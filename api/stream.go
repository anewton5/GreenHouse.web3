package api

// stream.go — WebSocket real-time event feed (GET /v1/stream) and Onfido
// KYC webhook handler (POST /v1/webhooks/kyc).
//
// # WebSocket stream
//
// Clients connect to GET /v1/stream with a valid JWT (via ?token= or
// Authorization: Bearer). After upgrade, the server pushes StreamEvent JSON
// messages for every event emitted by the blockchain:
//
//	order_placed, order_cancelled, trade_executed, block_finalised,
//	payment_confirmed, credential_issued
//
// Clients may optionally send a JSON subscription filter after connecting:
//
//	{"subscribe": ["trade_executed", "block_finalised"]}
//
// An empty or absent subscribe list means all event types are delivered.
//
// # KYC webhook
//
// Onfido (and any future KYC provider) posts to POST /v1/webhooks/kyc when a
// check completes. The payload is verified via the X-SHA2-Signature header
// using ONFIDO_WEBHOOK_SECRET. On a "completed"+"clear" check, the wallet's
// KYC request is auto-approved via OperatorRegistry.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"gonetwork"

	"github.com/gorilla/websocket"
)

// ---------------------------------------------------------------------------
// WebSocket hub — fan-out from bc.Events to all connected clients
// ---------------------------------------------------------------------------

var upgrader = websocket.Upgrader{
	HandshakeTimeout: 10 * time.Second,
	CheckOrigin: func(r *http.Request) bool {
		// In development accept all origins. Tighten for production.
		return true
	},
}

// wsClient represents a single connected WebSocket subscriber.
type wsClient struct {
	conn      *websocket.Conn
	send      chan []byte
	subscribe map[string]bool // nil = all events; otherwise filter set
}

// hub manages all connected WebSocket clients.
type hub struct {
	mu      sync.RWMutex
	clients map[*wsClient]struct{}
}

func newHub() *hub {
	return &hub{clients: make(map[*wsClient]struct{})}
}

func (h *hub) register(c *wsClient) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

func (h *hub) unregister(c *wsClient) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
	close(c.send)
}

// broadcast delivers an event to all clients whose subscription filter matches.
func (h *hub) broadcast(event gonetwork.StreamEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		if c.subscribe != nil && !c.subscribe[event.Type] {
			continue
		}
		select {
		case c.send <- data:
		default:
			// client too slow — skip this event for this client
		}
	}
}

// startEventFan reads from bc.Events and broadcasts to all WebSocket clients.
// It runs in a background goroutine started by Server.Start().
func (s *Server) startEventFan() {
	for event := range s.bc.Events {
		s.wsHub.broadcast(event)
	}
}

// ---------------------------------------------------------------------------
// handleStream — GET /v1/stream
// ---------------------------------------------------------------------------

// handleStream upgrades the HTTP connection to WebSocket and streams
// blockchain events to the client until the connection closes.
//
// Authentication: pass the JWT via the Authorization header or ?token= param.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	// Support token via query param for browser WebSocket clients that cannot
	// set custom headers.
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.Header.Get("Authorization")
		var ok bool
		if _, ok = cutPrefix(token, "Bearer "); ok {
			token, _ = cutPrefix(token, "Bearer ")
		}
	}

	walletKey, err := s.verifyJWT(token)
	if err != nil || walletKey == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws: upgrade failed: %v", err)
		return
	}

	client := &wsClient{
		conn: conn,
		send: make(chan []byte, 64),
	}
	s.wsHub.register(client)
	defer s.wsHub.unregister(client)

	// Writer goroutine — flushes the send channel to the WebSocket.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for msg := range client.send {
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		}
	}()

	// Reader — accepts subscription filter messages; detects close.
	conn.SetReadLimit(4096)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var sub struct {
			Subscribe []string `json:"subscribe"`
		}
		if json.Unmarshal(msg, &sub) == nil && len(sub.Subscribe) > 0 {
			filter := make(map[string]bool, len(sub.Subscribe))
			for _, t := range sub.Subscribe {
				filter[t] = true
			}
			client.subscribe = filter
		}
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	}
	<-done
}

// cutPrefix is a backport shim — strings.CutPrefix is available in Go 1.20+.
// The codebase targets 1.21+, but leave this as a helper for clarity.
func cutPrefix(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return s, false
}

// startPing runs a periodic ping to detect dead WebSocket connections.
func (s *Server) startPing() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.wsHub.mu.RLock()
		for c := range s.wsHub.clients {
			c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				// unregister will be called by the reader goroutine on next error
			}
		}
		s.wsHub.mu.RUnlock()
	}
}

// ---------------------------------------------------------------------------
// handleKYCWebhook — POST /v1/webhooks/kyc
// ---------------------------------------------------------------------------

// handleKYCWebhook processes Onfido check-completion webhook notifications.
//
// Onfido sends a JSON payload with a SHA-256 HMAC signature in the header:
//
//	X-SHA2-Signature: <hex digest>
//
// The secret is read from the ONFIDO_WEBHOOK_SECRET environment variable.
// When the variable is not set, signature verification is skipped (dev mode).
//
// On a "completed"+"clear" check, the wallet's pending KYC request is
// auto-approved via OperatorRegistry, and the resulting credential is written
// to bc.Credentials so it takes effect immediately.
func (s *Server) handleKYCWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	// Signature verification (skip only when ONFIDO_WEBHOOK_SECRET is not set).
	secret := os.Getenv("ONFIDO_WEBHOOK_SECRET")
	if secret != "" {
		provided := r.Header.Get("X-SHA2-Signature")
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		expected := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(expected), []byte(provided)) {
			writeError(w, http.StatusUnauthorized, "invalid webhook signature")
			return
		}
	}

	// Parse the Onfido webhook payload.
	// Onfido sends: {"payload": {"resource_type": "check", "action": "check.completed",
	//                             "object": {"href": "...", "status": "complete",
	//                                        "result": "clear", "tags": ["wallet:..."]}}}
	var payload struct {
		Payload struct {
			ResourceType string `json:"resource_type"`
			Action       string `json:"action"`
			Object       struct {
				Status string   `json:"status"`
				Result string   `json:"result"`
				Tags   []string `json:"tags"`
			} `json:"object"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook payload")
		return
	}

	// Only act on completed, clear checks.
	if payload.Payload.Action != "check.completed" ||
		payload.Payload.Object.Status != "complete" ||
		payload.Payload.Object.Result != "clear" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract the wallet key from the check tags (format "wallet:<base64key>").
	walletKey := ""
	for _, tag := range payload.Payload.Object.Tags {
		after, found := cutPrefix(tag, "wallet:")
		if found {
			walletKey = after
			break
		}
	}

	if walletKey == "" || s.OperatorRegistry == nil {
		// No wallet tag or no operator registry configured: acknowledge without processing.
		w.WriteHeader(http.StatusOK)
		return
	}

	att, err := s.OperatorRegistry.ApproveKYC(walletKey)
	if err != nil {
		// The wallet may not have a pending request (e.g. direct issuance path).
		// Log and acknowledge — do not return an error to Onfido.
		log.Printf("kyc webhook: ApproveKYC for %s: %v", walletKey, err)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Propagate to blockchain credentials so transfer eligibility checks pass.
	s.bc.Credentials[walletKey] = att

	// Emit a real-time event to all WebSocket subscribers.
	evPayload, _ := json.Marshal(map[string]any{
		"wallet_key":     walletKey,
		"investor_class": string(att.InvestorClass),
		"kyc_status":     att.KYCStatus,
		"expires_at":     att.ExpiresAt,
	})
	s.bc.Events <- gonetwork.StreamEvent{
		Type:      gonetwork.EventCredentialIssued,
		Timestamp: time.Now().UTC().Unix(),
		Payload:   json.RawMessage(evPayload),
	}

	log.Printf("kyc webhook: credential issued for wallet %s (class: %s)", walletKey, att.InvestorClass)
	w.WriteHeader(http.StatusOK)
}
