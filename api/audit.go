package api

// ---------------------------------------------------------------------------
// Audit logging — compliance-grade immutable event trail
//
// Regulatory basis:
//   FCA SYSC 9.1 / MiFID II Article 25(1) — transaction record-keeping
//   5AMLD / MLR 2017 reg.40              — AML audit trail (5 years)
//   UK GDPR Article 5(2)                 — accountability / demonstrability
//
// Design principles:
//   - Every entry is a single-line JSON object (NDJSON format).
//   - Wallet keys are NEVER stored in plain text; a truncated SHA3-256 prefix
//     is used for correlation without exposing full public keys.
//   - The log file is append-only and written with mode 0600.
//   - Log path is configurable via GREENHOUSE_AUDIT_LOG env var;
//     defaults to "audit.log" in the working directory.
//   - Writes are serialised through a mutex — safe for concurrent handlers.
//   - On file-open failure the logger falls back to stderr so startup is
//     never blocked; the ops team will notice the missing file.
// ---------------------------------------------------------------------------

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
)

// AuditAction identifies the category of auditable event.
type AuditAction string

const (
	AuditAuthChallenge         AuditAction = "auth.challenge"
	AuditAuthSuccess           AuditAction = "auth.success"
	AuditAuthFailure           AuditAction = "auth.failure"
	AuditTokenRefresh          AuditAction = "auth.token_refresh"
	AuditRegistrationSubmitted AuditAction = "registration.submitted"
	AuditRegistrationApproved  AuditAction = "registration.approved"
	AuditRegistrationRejected  AuditAction = "registration.rejected"
	AuditKYCRequested          AuditAction = "kyc.requested"
	AuditKYCApproved           AuditAction = "kyc.approved"
	AuditAdminAction           AuditAction = "admin.action"
)

// AuditEntry is a single immutable audit event record.
type AuditEntry struct {
	// Timestamp in Unix milliseconds for sub-second resolution.
	Timestamp int64 `json:"ts"`

	Action AuditAction `json:"action"`

	// ActorKey is a privacy-preserving fingerprint of the wallet that performed
	// the action. Full keys are never written to logs.
	ActorKey string `json:"actor_key,omitempty"`

	// SubjectKey is the fingerprint of the wallet the action was performed on
	// (e.g. the registration being approved). Omitted when actor == subject.
	SubjectKey string `json:"subject_key,omitempty"`

	// Outcome is "ok" on success or "fail" on failure.
	Outcome string `json:"outcome"`

	// IPAddress of the request originator. Sourced from RemoteAddr or
	// X-Forwarded-For when behind a trusted reverse proxy.
	IPAddress string `json:"ip,omitempty"`

	// Details carries action-specific key/value metadata (e.g. rejection reason,
	// investor class). Values must never contain raw PII.
	Details map[string]string `json:"details,omitempty"`
}

// auditKeyFingerprint returns a privacy-preserving representation of a wallet
// public key: the first 8 bytes of its SHA3-256 hash encoded as hex, followed
// by "…". This allows log correlation without exposing the full key.
func auditKeyFingerprint(key string) string {
	if key == "" {
		return ""
	}
	h := sha3.Sum256([]byte(key))
	return hex.EncodeToString(h[:8]) + "…"
}

// AuditLogger writes structured JSON audit entries to a dedicated append-only file.
type AuditLogger struct {
	mu     sync.Mutex
	logger *log.Logger
}

// newAuditLogger opens (or creates) the audit log file and returns a ready logger.
func newAuditLogger() *AuditLogger {
	path := os.Getenv("GREENHOUSE_AUDIT_LOG")
	if path == "" {
		path = "audit.log"
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		// Fall back to stderr — startup must not be blocked by a log file error.
		log.Printf("[WARN] audit: cannot open %q for writing (%v); falling back to stderr", path, err)
		return &AuditLogger{logger: log.New(os.Stderr, "[AUDIT] ", 0)}
	}
	// No prefix or flags — the JSON payload carries all metadata.
	return &AuditLogger{logger: log.New(f, "", 0)}
}

// globalAuditLogger is the package-wide audit logger, initialised once at startup.
var globalAuditLogger = newAuditLogger()

// Log serialises entry as a single JSON line and appends it to the audit log.
func (a *AuditLogger) Log(entry AuditEntry) {
	if entry.Timestamp == 0 {
		entry.Timestamp = time.Now().UnixMilli()
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logger.Println(string(data))
}

// auditLog is a package-level convenience wrapper.
func auditLog(entry AuditEntry) {
	globalAuditLogger.Log(entry)
}

// auditIP extracts a clean IP address string from an HTTP RemoteAddr value.
func auditIP(remoteAddr string) string {
	// RemoteAddr is "host:port"; strip the port.
	for i := len(remoteAddr) - 1; i >= 0; i-- {
		if remoteAddr[i] == ':' {
			return remoteAddr[:i]
		}
	}
	return remoteAddr
}
