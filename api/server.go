package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gonetwork"
)

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// Server wraps the blockchain and exposes it over HTTP.
// Authentication: Ed25519 challenge-response → short-lived JWT (15 min).
// All write endpoints require a valid JWT.
// Rate limiting: 100 req/min per IP for reads; 20 req/min for writes.
type Server struct {
	bc         *gonetwork.Blockchain
	jwtSecret  []byte // 32 random bytes at startup; not persisted
	listenAddr string

	challengeMu sync.Mutex
	challenges  map[string]challengeRecord // challenge hex → record

	// Optional: set to enable the operator KYC approval workflow.
	// When nil, POST /v1/admin/kyc/* and POST /v1/kyc/request return 501.
	OperatorRegistry *gonetwork.OperatorIdentityRegistry

	// Optional: set to enable Modulr webhook signature verification.
	// When nil, POST /v1/webhooks/payment accepts without verifying the HMAC.
	ModulrProvider *gonetwork.ModulrPaymentProvider

	// wsHub fans blockchain events out to all connected WebSocket clients.
	wsHub *hub

	// adminWalletKeys is the set of wallet public keys permitted to call /admin/* routes.
	// Loaded from GREENHOUSE_ADMIN_WALLET_KEYS (comma-separated base64 keys) at startup.
	// When empty, any authenticated wallet may call admin routes (single-operator dev mode).
	adminWalletKeys map[string]bool
}

type challengeRecord struct {
	expiresAt int64
}

// NewServer creates an API server for the given Blockchain.
// A fresh 32-byte JWT secret is generated at startup; restarting the server
// invalidates all issued tokens.
//
// Admin wallet keys are loaded from GREENHOUSE_ADMIN_WALLET_KEYS
// (comma-separated base64-encoded Ed25519 public keys). When the variable is
// not set, any authenticated wallet may call admin routes (single-operator
// development mode — restrict this before going to production).
func NewServer(bc *gonetwork.Blockchain, listenAddr string) *Server {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic("api: failed to generate JWT secret: " + err.Error())
	}

	adminKeys := make(map[string]bool)
	for _, k := range strings.Split(os.Getenv("GREENHOUSE_ADMIN_WALLET_KEYS"), ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			adminKeys[k] = true
		}
	}

	return &Server{
		bc:              bc,
		jwtSecret:       secret,
		listenAddr:      listenAddr,
		challenges:      make(map[string]challengeRecord),
		adminWalletKeys: adminKeys,
		wsHub:           newHub(),
	}
}

// Start registers all routes, starts background goroutines, and begins serving.
func (s *Server) Start() error {
	go s.startEventFan()
	go s.startPing()
	return http.ListenAndServe(s.listenAddr, s.Routes())
}

// Routes returns the fully configured HTTP handler with all middleware applied.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated
	mux.HandleFunc("POST /v1/auth/challenge", s.handleChallenge)
	mux.HandleFunc("POST /v1/auth/verify", s.handleVerify)
	mux.HandleFunc("GET /v1/blocks", s.handleListBlocks)
	mux.HandleFunc("GET /v1/health", s.handleHealth)

	// JWT-protected reads
	mux.Handle("GET /v1/assets", s.jwt(http.HandlerFunc(s.handleListAssets)))
	mux.Handle("GET /v1/assets/{id}", s.jwt(http.HandlerFunc(s.handleGetAsset)))
	mux.Handle("GET /v1/holdings/{walletKey}", s.jwt(http.HandlerFunc(s.handleGetHoldings)))
	mux.Handle("GET /v1/orderbook/{assetID}", s.jwt(http.HandlerFunc(s.handleGetOrderBook)))
	mux.Handle("GET /v1/trades", s.jwt(http.HandlerFunc(s.handleListTrades)))
	mux.Handle("GET /v1/deals", s.jwt(http.HandlerFunc(s.handleListDeals)))
	mux.Handle("GET /v1/reporting/holdings", s.jwt(http.HandlerFunc(s.handleReportHoldings)))
	mux.Handle("GET /v1/reporting/tax/{year}", s.jwt(http.HandlerFunc(s.handleReportTax)))

	// JWT-protected writes
	mux.Handle("POST /v1/assets", s.jwt(http.HandlerFunc(s.handleCreateAsset)))
	mux.Handle("POST /v1/orders", s.jwt(http.HandlerFunc(s.handlePlaceOrder)))
	mux.Handle("DELETE /v1/orders/{id}", s.jwt(http.HandlerFunc(s.handleCancelOrder)))
	mux.Handle("POST /v1/deals", s.jwt(http.HandlerFunc(s.handleCreateDeal)))
	mux.Handle("POST /v1/deals/{id}/anchor", s.jwt(http.HandlerFunc(s.handleAttachAnchor)))
	mux.Handle("POST /v1/deals/{id}/commit", s.jwt(http.HandlerFunc(s.handleAddCommitment)))

	// KYC: participant submits a request; operator approves it
	mux.Handle("GET /v1/kyc/status", s.jwt(http.HandlerFunc(s.handleKYCStatus)))
	mux.Handle("POST /v1/kyc/request", s.jwt(http.HandlerFunc(s.handleKYCRequest)))
	mux.Handle("GET /v1/admin/kyc/pending", s.jwtAdmin(http.HandlerFunc(s.handleAdminKYCList)))
	mux.Handle("POST /v1/admin/kyc/approve", s.jwtAdmin(http.HandlerFunc(s.handleAdminKYCApprove)))

	// Open orders for the authenticated wallet
	mux.Handle("GET /v1/orders", s.jwt(http.HandlerFunc(s.handleListOrders)))

	// Cap table for an asset
	mux.Handle("GET /v1/assets/{id}/captable", s.jwt(http.HandlerFunc(s.handleGetCapTable)))

	// Liquidity windows (issuer-facing)
	mux.Handle("GET /v1/liquidity/windows", s.jwt(http.HandlerFunc(s.handleListLiquidityWindows)))
	mux.Handle("POST /v1/liquidity/windows", s.jwtAdmin(http.HandlerFunc(s.handleScheduleLiquidityWindow)))

	// Corporate actions
	mux.Handle("GET /v1/corporate-actions", s.jwt(http.HandlerFunc(s.handleListCorporateActions)))
	mux.Handle("POST /v1/corporate-actions", s.jwtAdmin(http.HandlerFunc(s.handleProposeCorporateAction)))

	// Trade approvals (mobile co-signing)
	mux.Handle("GET /v1/trades/pending", s.jwt(http.HandlerFunc(s.handleListPendingTrades)))
	mux.Handle("POST /v1/trades/{id}/approve", s.jwt(http.HandlerFunc(s.handleApproveTrade)))

	// Payment webhook — no JWT; authenticated via HMAC signature from Modulr
	mux.HandleFunc("POST /v1/webhooks/payment", s.handlePaymentWebhook)

	// KYC webhook — no JWT; authenticated via HMAC from Onfido
	mux.HandleFunc("POST /v1/webhooks/kyc", s.handleKYCWebhook)

	// Real-time WebSocket event stream — JWT via ?token= or Authorization header
	mux.HandleFunc("GET /v1/stream", s.handleStream)

	return LoggingMiddleware(CORSMiddleware(RateLimitMiddleware(mux)))
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

type jwtClaims struct {
	Sub string `json:"sub"` // wallet public key (base64)
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) issueJWT(walletKey string) (string, error) {
	now := time.Now().UTC().Unix()
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	claims, err := json.Marshal(jwtClaims{Sub: walletKey, Iat: now, Exp: now + 900})
	if err != nil {
		return "", err
	}
	sigInput := b64url(header) + "." + b64url(claims)
	mac := hmac.New(sha256.New, s.jwtSecret)
	mac.Write([]byte(sigInput))
	return sigInput + "." + b64url(mac.Sum(nil)), nil
}

// verifyJWT validates the token and returns the wallet key (sub claim) or an error.
func (s *Server) verifyJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT")
	}
	sigInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, s.jwtSecret)
	mac.Write([]byte(sigInput))
	expectedSig := b64url(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return "", fmt.Errorf("invalid JWT signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("malformed JWT payload")
	}
	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("malformed JWT claims")
	}
	if time.Now().UTC().Unix() > claims.Exp {
		return "", fmt.Errorf("JWT has expired")
	}
	return claims.Sub, nil
}

// jwtAdmin wraps a handler requiring both a valid JWT and admin wallet status.
// When adminWalletKeys is empty (development mode) any authenticated wallet is
// considered an admin. In production, set GREENHOUSE_ADMIN_WALLET_KEYS.
func (s *Server) jwtAdmin(next http.Handler) http.Handler {
	return s.jwt(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.adminWalletKeys) > 0 {
			walletKey := walletFromCtx(r)
			if !s.adminWalletKeys[walletKey] {
				writeError(w, http.StatusForbidden, "admin access required")
				return
			}
		}
		next.ServeHTTP(w, r)
	}))
}

// jwt wraps a handler with JWT authentication. It sets the wallet key in the
// request context under walletKeyCtxKey.
func (s *Server) jwt(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok || token == "" {
			writeError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
			return
		}
		walletKey, err := s.verifyJWT(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), walletKeyCtxKey{}, walletKey)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// walletKeyCtxKey is the context key for the authenticated wallet's public key.
type walletKeyCtxKey struct{}

// walletFromCtx retrieves the authenticated wallet key from the request context.
func walletFromCtx(r *http.Request) string {
	v, _ := r.Context().Value(walletKeyCtxKey{}).(string)
	return v
}

// ---------------------------------------------------------------------------
// Challenge store helpers
// ---------------------------------------------------------------------------

func (s *Server) storeChallenge(ch string) {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	s.challenges[ch] = challengeRecord{expiresAt: time.Now().UTC().Unix() + 300}
	// Opportunistic cleanup of expired challenges
	now := time.Now().UTC().Unix()
	for k, v := range s.challenges {
		if v.expiresAt < now {
			delete(s.challenges, k)
		}
	}
}

func (s *Server) consumeChallenge(ch string) bool {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	rec, ok := s.challenges[ch]
	if !ok {
		return false
	}
	delete(s.challenges, ch)
	return time.Now().UTC().Unix() <= rec.expiresAt
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// newChallenge generates a random 32-byte challenge and returns its hex encoding.
func newChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
