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
// Authentication: Ed25519 challenge-response → short-lived access JWT (15 min)
//   - long-lived refresh token (7 days, rotated on each use).
//
// All write endpoints require a valid JWT.
// Rate limiting: 300 req/min per IP for reads; 100 req/min for writes.
type Server struct {
	bc         *gonetwork.Blockchain
	jwtSecret  []byte // 32 random bytes at startup; not persisted
	listenAddr string

	challengeMu sync.Mutex
	challenges  map[string]challengeRecord // challenge hex → record

	// Refresh token store.  Key = 64-hex-char random token.  Invalidated on use (rotation).
	refreshMu     sync.Mutex
	refreshTokens map[string]refreshTokenRecord

	// Optional: set to enable the operator KYC approval workflow.
	// When nil, POST /v1/admin/kyc/* and POST /v1/kyc/request return 501.
	OperatorRegistry *gonetwork.OperatorIdentityRegistry

	// RegistrationRegistry holds the full KYC/CDD onboarding records.
	// Always non-nil; initialised in NewServer.
	RegRegistry *gonetwork.RegistrationRegistry

	// EntityRegistry holds registered legal-entity identities (Phase 3:
	// institutional/vLEI-ready identity). Always non-nil; initialised in
	// NewServer.
	EntityRegistry *gonetwork.EntityRegistry

	// Optional: set to enable Modulr webhook signature verification.
	// When nil, POST /v1/webhooks/payment accepts without verifying the HMAC.
	ModulrProvider *gonetwork.ModulrPaymentProvider

	// Optional: set to enable the Pontes CeBM settlement webhook.
	PontesProvider *gonetwork.PontesPaymentProvider

	// Optional: set to enable the EURC on-chain settlement webhook.
	EURCProvider *gonetwork.EURCPaymentProvider

	// wsHub fans blockchain events out to all connected WebSocket clients.
	wsHub *hub

	// adminWalletKeys is the set of wallet public keys permitted to call /admin/* routes.
	adminWalletKeys map[string]bool

	allowedOrigins map[string]struct{}
}

type challengeRecord struct {
	expiresAt int64
}

type refreshTokenRecord struct {
	walletKey string
	expiresAt int64
}

// NewServer creates an API server for the given Blockchain.
//
// JWT secret is loaded from GREENHOUSE_JWT_SECRET (64 hex chars → 32 bytes).
// In production (GH_ENV=production) the variable must be set; in development
// an ephemeral random secret is generated with a warning.
//
// Admin wallet keys are loaded from GREENHOUSE_ADMIN_WALLET_KEYS
// (comma-separated base64-encoded Ed25519 public keys). In production the
// variable must be set; in development any authenticated wallet may call
// admin routes.
func NewServer(bc *gonetwork.Blockchain, listenAddr string) *Server {
	// JWT secret loading (H-4).
	var secret []byte
	if raw := os.Getenv("GREENHOUSE_JWT_SECRET"); raw != "" {
		decoded, err := hex.DecodeString(raw)
		if err != nil || len(decoded) != 32 {
			panic("GREENHOUSE_JWT_SECRET must be exactly 64 hex characters (32 bytes)")
		}
		secret = decoded
	} else if os.Getenv("GH_ENV") == "production" {
		panic("GREENHOUSE_JWT_SECRET must be set in production (H-4)")
	} else {
		fmt.Println("WARNING: GREENHOUSE_JWT_SECRET not set; using ephemeral secret (tokens invalidated on restart)")
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			panic("api: failed to generate JWT secret: " + err.Error())
		}
	}

	// Admin wallet key loading (H-3).
	adminKeys := make(map[string]bool)
	for _, k := range strings.Split(os.Getenv("GREENHOUSE_ADMIN_WALLET_KEYS"), ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			adminKeys[k] = true
		}
	}
	if len(adminKeys) == 0 && os.Getenv("GH_ENV") == "production" {
		panic("GREENHOUSE_ADMIN_WALLET_KEYS must be set in production (H-3)")
	}

	s := &Server{
		bc:              bc,
		jwtSecret:       secret,
		listenAddr:      listenAddr,
		challenges:      make(map[string]challengeRecord),
		refreshTokens:   make(map[string]refreshTokenRecord),
		RegRegistry:     gonetwork.NewRegistrationRegistry(),
		EntityRegistry:  gonetwork.NewEntityRegistry(),
		adminWalletKeys: adminKeys,
		wsHub:           newHub(),
	}
	// Wire the shared registry into the blockchain so Travel Rule lookups
	// can resolve investor PII from registration records.
	bc.RegistrationRegistry = s.RegRegistry
	return s
}

// Start registers all routes, starts background goroutines, and begins serving.
// In production (GH_ENV=production) it verifies that no mock provider is active.
func (s *Server) Start() error {
	// Production guards (H-1): fail loudly if mock providers are still wired in.
	if os.Getenv("GH_ENV") == "production" {
		switch s.bc.AMLScreener.(type) {
		case *gonetwork.MockAMLScreener:
			panic("production: MockAMLScreener is active — configure ComplyAdvantageScreener (H-1)")
		}
		switch s.bc.PaymentProvider.(type) {
		case *gonetwork.MockPaymentProvider:
			panic("production: MockPaymentProvider is active — configure Modulr/EURC/Pontes (H-1)")
		}
		switch s.bc.IdentityRegistry.(type) {
		case *gonetwork.MockIdentityRegistry:
			panic("production: MockIdentityRegistry is active — configure OnfidoIdentityRegistry (H-1)")
		}
		// F-2: Modulr rail must have a provider wired so webhook signatures are verified.
		_, fasterPayActive := s.bc.SettlementRouter[gonetwork.SettlementFasterPay]
		_, sepaActive := s.bc.SettlementRouter[gonetwork.SettlementSEPA]
		if (fasterPayActive || sepaActive) && s.ModulrProvider == nil {
			panic("production: Modulr rail is active but ModulrProvider is nil — webhook signatures cannot be verified (F-2)")
		}
	}
	go s.startEventFan()
	go s.startPing()
	go s.startSweep()
	return http.ListenAndServe(s.listenAddr, s.Routes())
}

// Routes returns the fully configured HTTP handler with all middleware applied.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.Handle("POST /v1/auth/challenge", AuthRateLimitMiddleware(http.HandlerFunc(s.handleChallenge)))
	mux.Handle("POST /v1/auth/verify", AuthRateLimitMiddleware(http.HandlerFunc(s.handleVerify)))
	mux.Handle("POST /v1/auth/refresh", AuthRateLimitMiddleware(http.HandlerFunc(s.handleRefreshToken)))
	mux.HandleFunc("GET /v1/register/status", s.handleGetRegistrationStatus)
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

	// Phase 2: claim-topic endpoints
	mux.Handle("GET /v1/claims/{walletKey}", s.jwt(http.HandlerFunc(s.handleListClaims)))
	mux.Handle("POST /v1/admin/claim-issuers", s.jwtAdmin(http.HandlerFunc(s.handleUpsertClaimIssuer)))

	// Phase 3: institutional/vLEI legal-entity identity endpoints
	mux.Handle("POST /v1/admin/entities", s.jwtAdmin(http.HandlerFunc(s.handleRegisterEntity)))
	mux.Handle("GET /v1/entities", s.jwt(http.HandlerFunc(s.handleListEntities)))
	mux.Handle("GET /v1/entities/{lei}", s.jwt(http.HandlerFunc(s.handleGetEntity)))
	mux.Handle("POST /v1/admin/entities/{lei}/role-claims", s.jwtAdmin(http.HandlerFunc(s.handleIssueEntityRoleClaim)))
	mux.Handle("POST /v1/admin/market-makers", s.jwtAdmin(http.HandlerFunc(s.handleCreateMarketMaker)))
	mux.Handle("GET /v1/market-makers/{assetID}", s.jwt(http.HandlerFunc(s.handleListMarketMakers)))
	mux.Handle("GET /v1/market-makers/{walletKey}/inventory", s.jwt(http.HandlerFunc(s.handleGetMarketMakerInventory)))
	mux.Handle("DELETE /v1/admin/market-makers/{id}", s.jwtAdmin(http.HandlerFunc(s.handleDeleteMarketMaker)))
	mux.Handle("POST /v1/kyc/request", s.jwt(http.HandlerFunc(s.handleKYCRequest)))
	mux.Handle("GET /v1/admin/kyc/pending", s.jwtAdmin(http.HandlerFunc(s.handleAdminKYCList)))
	mux.Handle("POST /v1/admin/kyc/approve", s.jwtAdmin(http.HandlerFunc(s.handleAdminKYCApprove)))

	// Registration: full CDD onboarding workflow
	mux.Handle("POST /v1/register", s.jwt(http.HandlerFunc(s.handleRegister)))
	mux.Handle("POST /v1/terms/accept", s.jwt(http.HandlerFunc(s.handleAcceptTerms)))
	mux.Handle("GET /v1/admin/registrations", s.jwtAdmin(http.HandlerFunc(s.handleAdminRegistrationList)))
	mux.Handle("POST /v1/admin/registrations/{key}/review", s.jwtAdmin(http.HandlerFunc(s.handleAdminRegistrationReview)))

	// Open orders for the authenticated wallet
	mux.Handle("GET /v1/orders", s.jwt(http.HandlerFunc(s.handleListOrders)))
	mux.Handle("POST /v1/rfq/requests", s.jwt(http.HandlerFunc(s.handleCreateRFQRequest)))
	mux.Handle("GET /v1/rfq/requests", s.jwt(http.HandlerFunc(s.handleListRFQRequests)))
	mux.Handle("POST /v1/rfq/requests/{id}/quotes", s.jwt(http.HandlerFunc(s.handleCreateRFQQuote)))
	mux.Handle("GET /v1/rfq/requests/{id}/quotes", s.jwt(http.HandlerFunc(s.handleListRFQQuotes)))
	mux.Handle("POST /v1/rfq/requests/{id}/accept", s.jwt(http.HandlerFunc(s.handleAcceptRFQQuote)))
	mux.Handle("DELETE /v1/rfq/requests/{id}", s.jwt(http.HandlerFunc(s.handleCancelRFQRequest)))
	mux.Handle("GET /v1/market-data/vwap/{assetID}", s.jwt(http.HandlerFunc(s.handleGetMarketDataVWAP)))

	// Issuer order management — see all bids on assets you issued, fill or reject
	mux.Handle("GET /v1/issuer/orders", s.jwt(http.HandlerFunc(s.handleIssuerListOrders)))
	mux.Handle("POST /v1/orders/{id}/fill", s.jwt(http.HandlerFunc(s.handleFillOrder)))
	mux.Handle("POST /v1/orders/{id}/reject", s.jwt(http.HandlerFunc(s.handleRejectOrder)))

	// Cap table for an asset
	mux.Handle("GET /v1/assets/{id}/captable", s.jwt(http.HandlerFunc(s.handleGetCapTable)))

	// Liquidity windows (issuer-facing)
	mux.Handle("GET /v1/liquidity/windows", s.jwt(http.HandlerFunc(s.handleListLiquidityWindows)))
	mux.Handle("POST /v1/liquidity/windows", s.jwtAdmin(http.HandlerFunc(s.handleScheduleLiquidityWindow)))

	// Corporate actions
	mux.Handle("GET /v1/corporate-actions", s.jwt(http.HandlerFunc(s.handleListCorporateActions)))
	mux.Handle("POST /v1/corporate-actions", s.jwtAdmin(http.HandlerFunc(s.handleProposeCorporateAction)))

	// SPV management
	mux.Handle("GET /v1/spv", s.jwt(http.HandlerFunc(s.handleListSPV)))
	mux.Handle("POST /v1/spv", s.jwt(http.HandlerFunc(s.handleCreateSPV)))
	mux.Handle("POST /v1/spv/{id}/nav", s.jwt(http.HandlerFunc(s.handleUpdateSPVNAV)))

	// Prospectus exemption registration (issuer-only write; any authenticated read)
	mux.Handle("POST /v1/assets/{id}/exemption", s.jwt(http.HandlerFunc(s.handleRegisterExemption)))
	mux.Handle("GET /v1/assets/{id}/exemption", s.jwt(http.HandlerFunc(s.handleGetExemption)))

	// MiFID II suitability assessments (admin write; any authenticated read)
	mux.Handle("POST /v1/suitability", s.jwtAdmin(http.HandlerFunc(s.handleSubmitSuitability)))
	mux.Handle("GET /v1/suitability/{walletKey}/{assetID}", s.jwt(http.HandlerFunc(s.handleGetSuitability)))

	// Legal document amendment trail (A-03)
	mux.Handle("POST /v1/assets/{id}/legal-doc", s.jwt(http.HandlerFunc(s.handleAddLegalDocAmendment)))
	mux.Handle("GET /v1/assets/{id}/legal-doc/history", s.jwt(http.HandlerFunc(s.handleGetLegalDocHistory)))

	// Participation note countersignature — SPV admin only (A-04)
	mux.Handle("POST /v1/assets/{id}/countersign", s.jwt(http.HandlerFunc(s.handleCounterSignAsset)))

	// Trade approvals (mobile co-signing)
	mux.Handle("GET /v1/trades/pending", s.jwt(http.HandlerFunc(s.handleListPendingTrades)))
	mux.Handle("POST /v1/trades/{id}/approve", s.jwt(http.HandlerFunc(s.handleApproveTrade)))

	// Settlement / payment instruction endpoints
	mux.Handle("GET /v1/payments/pending", s.jwt(http.HandlerFunc(s.handleListPendingPayments)))
	mux.Handle("GET /v1/payments/history", s.jwt(http.HandlerFunc(s.handleListPaymentHistory)))
	mux.Handle("POST /v1/payments/{tradeID}/register", s.jwtAdmin(http.HandlerFunc(s.handleRegisterCeBMSettlement)))

	// Payment webhook — no JWT; authenticated via HMAC signature from Modulr
	mux.HandleFunc("POST /v1/webhooks/payment", s.handlePaymentWebhook)
	mux.HandleFunc("POST /v1/webhooks/pontes", s.handlePontesWebhook)
	mux.HandleFunc("POST /v1/webhooks/eurc", s.handleEURCWebhook)

	// KYC webhook — no JWT; authenticated via HMAC from Onfido
	mux.HandleFunc("POST /v1/webhooks/kyc", s.handleKYCWebhook)

	// Real-time WebSocket event stream — JWT via ?token= or Authorization header
	mux.HandleFunc("GET /v1/stream", s.handleStream)

	// Dev-mode endpoints (disabled when GREENHOUSE_ADMIN_WALLET_KEYS is set)
	mux.HandleFunc("GET /v1/dev/state", s.handleDevState)
	mux.HandleFunc("GET /v1/dev/stream", s.handleDevStream)

	// G-09: SAR (Suspicious Activity Report) management — admin only
	mux.Handle("GET /v1/compliance/sar", s.jwtAdmin(http.HandlerFunc(s.handleListSARs)))
	mux.Handle("GET /v1/compliance/sar/closed", s.jwtAdmin(http.HandlerFunc(s.handleListClosedSARs)))
	mux.Handle("POST /v1/compliance/sar/{id}/resolve", s.jwtAdmin(http.HandlerFunc(s.handleResolveSAR)))

	// G-10: Regulatory report log — admin read; admin write for jurisdiction rules
	mux.Handle("GET /v1/compliance/reports", s.jwtAdmin(http.HandlerFunc(s.handleListRegulatoryReports)))
	mux.Handle("GET /v1/compliance/jurisdictions/{code}", s.jwt(http.HandlerFunc(s.handleGetJurisdictionRule)))
	mux.Handle("POST /v1/compliance/jurisdictions", s.jwtAdmin(http.HandlerFunc(s.handleUpsertJurisdictionRule)))

	// MAR Art 18: Insider list management
	mux.Handle("GET /v1/assets/{id}/insiders", s.jwt(http.HandlerFunc(s.handleListInsiders)))
	mux.Handle("POST /v1/assets/{id}/insiders", s.jwtAdmin(http.HandlerFunc(s.handleAddInsider)))
	mux.Handle("DELETE /v1/assets/{id}/insiders/{recordID}", s.jwtAdmin(http.HandlerFunc(s.handleRemoveInsider)))

	// MAR Art 16: STOR (Suspicious Transaction and Order Reports) management
	mux.Handle("GET /v1/compliance/stor", s.jwtAdmin(http.HandlerFunc(s.handleListSTORs)))
	mux.Handle("GET /v1/compliance/stor/closed", s.jwtAdmin(http.HandlerFunc(s.handleListClosedSTORs)))
	mux.Handle("POST /v1/compliance/stor/{id}/resolve", s.jwtAdmin(http.HandlerFunc(s.handleResolveSTOR)))

	// H-6: delegate vote registration — authenticated investors may assign their
	// voting power to another registered user (or themselves for self-delegation).
	mux.Handle("POST /v1/delegates/vote", s.jwt(http.HandlerFunc(s.handleRegisterDelegateVote)))

	// Block finality information — unauthenticated (public)
	mux.HandleFunc("GET /v1/blocks/{index}/finality", s.handleGetBlockFinality)

	return LoggingMiddleware(CORSMiddleware(RateLimitMiddleware(mux)))
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

// jwtClaims is the payload of a GreenHouse access token.
// Enhanced to include KYC and registration state so frontends can gate
// features without an extra API round-trip on every page load.
type jwtClaims struct {
	Sub                string `json:"sub"`
	Iat                int64  `json:"iat"`
	Exp                int64  `json:"exp"`
	Iss                string `json:"iss"`                           // token issuer — always "greenhouse-api"
	Aud                string `json:"aud"`                           // intended audience — always "greenhouse"
	InvestorClass      string `json:"investor_class,omitempty"`      // from KYC credential
	Jurisdiction       string `json:"jurisdiction,omitempty"`        // ISO 3166-1 alpha-2
	KYCStatus          string `json:"kyc_status,omitempty"`          // mirrors KYCStatus enum
	KYCExp             int64  `json:"kyc_exp,omitempty"`             // credential expiry
	RegistrationStatus string `json:"registration_status,omitempty"` // mirrors RegistrationStatus enum
	TermsAccepted      bool   `json:"terms_accepted"`
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateID returns a random prefixed identifier for use within the API package.
// Format: "<prefix>-<16 hex chars>" e.g. "INS-a3f7b2c19d4e5f6a".
func generateID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

func (s *Server) issueJWT(walletKey string) (string, error) {
	return s.issueJWTWithClaims(walletKey, "", "", "", 0, "", false)
}

// issueJWTWithClaims issues a 15-minute access token with full claims.
func (s *Server) issueJWTWithClaims(
	walletKey string,
	investorClass string,
	jurisdiction string,
	kycStatus string,
	kycExp int64,
	registrationStatus string,
	termsAccepted bool,
) (string, error) {
	now := time.Now().UTC().Unix()
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	claims, err := json.Marshal(jwtClaims{
		Sub:                walletKey,
		Iat:                now,
		Exp:                now + 900, // 15-minute access token
		Iss:                "greenhouse-api",
		Aud:                "greenhouse",
		InvestorClass:      investorClass,
		Jurisdiction:       jurisdiction,
		KYCStatus:          kycStatus,
		KYCExp:             kycExp,
		RegistrationStatus: registrationStatus,
		TermsAccepted:      termsAccepted,
	})
	if err != nil {
		return "", err
	}
	sigInput := b64url(header) + "." + b64url(claims)
	mac := hmac.New(sha256.New, s.jwtSecret)
	mac.Write([]byte(sigInput))
	return sigInput + "." + b64url(mac.Sum(nil)), nil
}

// issueRefreshToken generates a random 7-day refresh token bound to walletKey.
func (s *Server) issueRefreshToken(walletKey string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	// Evict expired tokens opportunistically.
	now := time.Now().UTC().Unix()
	for k, v := range s.refreshTokens {
		if v.expiresAt < now {
			delete(s.refreshTokens, k)
		}
	}
	s.refreshTokens[token] = refreshTokenRecord{
		walletKey: walletKey,
		expiresAt: now + 7*24*3600, // 7 days
	}
	return token, nil
}

// consumeRefreshToken validates and invalidates (rotates) a refresh token.
// Returns the wallet key on success.
func (s *Server) consumeRefreshToken(token string) (string, bool) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	rec, ok := s.refreshTokens[token]
	if !ok {
		return "", false
	}
	delete(s.refreshTokens, token) // single-use rotation
	if time.Now().UTC().Unix() > rec.expiresAt {
		return "", false
	}
	return rec.walletKey, true
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
	if claims.Iss != "greenhouse-api" {
		return "", fmt.Errorf("invalid token issuer")
	}
	if claims.Aud != "greenhouse" {
		return "", fmt.Errorf("invalid token audience")
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
	s.challenges[ch] = challengeRecord{expiresAt: time.Now().UTC().Unix() + 60}
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

// apiError pairs an HTTP status with a message so internal helpers (guard
// checks, compliance gates, etc.) can signal a specific HTTP response without
// writing to http.ResponseWriter themselves. Callers write the response via
// writeError(w, err.status, err.msg) once control returns to the handler.
type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

// newAPIError constructs an *apiError.
func newAPIError(status int, msg string) *apiError {
	return &apiError{status: status, msg: msg}
}

// newChallenge generates a random 32-byte challenge and returns its hex encoding.
func newChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
