package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// CORSMiddleware
// ---------------------------------------------------------------------------

// allowedOrigins returns the set of permitted CORS origins.
// Origins are read from the GREENHOUSE_ALLOWED_ORIGINS environment variable
// (comma-separated). When the variable is not set, localhost development
// origins are used. Set the variable to the exact production domain(s) before
// deploying to a public environment.
func allowedOrigins() map[string]struct{} {
	raw := os.Getenv("GREENHOUSE_ALLOWED_ORIGINS")
	if raw == "" {
		raw = "http://localhost:3000,http://localhost:3001"
	}
	set := make(map[string]struct{})
	for _, o := range strings.Split(raw, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			set[o] = struct{}{}
		}
	}
	return set
}

// corsOrigins is initialised once at package load time.
var corsOrigins = allowedOrigins()

// CORSMiddleware validates the request Origin against the allowlist and, when
// it matches, reflects the origin in the Access-Control-Allow-Origin header.
// Requests from unlisted origins receive no CORS header and are therefore
// blocked by the browser's same-origin policy.
//
// Security response headers (HSTS, X-Content-Type-Options, etc.) are added to
// every response regardless of origin.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers — applied unconditionally to every response.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")

		// CORS — only allow explicitly listed origins.
		origin := r.Header.Get("Origin")
		if _, ok := corsOrigins[origin]; ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// RateLimitMiddleware
// ---------------------------------------------------------------------------

// rateLimiter implements a simple per-IP sliding-window rate limiter.
type rateLimiter struct {
	mu       sync.Mutex
	windows  map[string][]int64 // IP → request timestamps (Unix seconds)
	readMax  int                // max requests per minute for read methods
	writeMax int                // max requests per minute for write methods
}

func newRateLimiter() *rateLimiter {
	readMax := 300
	writeMax := 100
	if v := os.Getenv("RATE_LIMIT_READ_PER_MIN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			readMax = n
		}
	}
	if v := os.Getenv("RATE_LIMIT_WRITE_PER_MIN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			writeMax = n
		}
	}
	return &rateLimiter{
		windows:  make(map[string][]int64),
		readMax:  readMax,
		writeMax: writeMax,
	}
}

// isWrite returns true for methods that mutate state.
func isWrite(method string) bool {
	return method == http.MethodPost || method == http.MethodPut ||
		method == http.MethodPatch || method == http.MethodDelete
}

// allow returns true if the request from ip is within the rate limit.
func (rl *rateLimiter) allow(ip, method string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().Unix()
	windowStart := now - 60 // 1-minute sliding window

	// Evict old timestamps
	ts := rl.windows[ip]
	kept := ts[:0]
	for _, t := range ts {
		if t >= windowStart {
			kept = append(kept, t)
		}
	}
	rl.windows[ip] = kept

	limit := rl.readMax
	if isWrite(method) {
		limit = rl.writeMax
	}
	if len(kept) >= limit {
		return false
	}
	rl.windows[ip] = append(rl.windows[ip], now)
	return true
}

// sweepOldEntries removes IPs whose last request was more than ttlSeconds ago.
// Called periodically by startSweep to prevent unbounded map growth (H-12).
func (rl *rateLimiter) sweepOldEntries(ttlSeconds int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Unix() - ttlSeconds
	for ip, ts := range rl.windows {
		if len(ts) == 0 || ts[len(ts)-1] < cutoff {
			delete(rl.windows, ip)
		}
	}
}

var globalRateLimiter = newRateLimiter()

// authRateLimiter is a stricter per-IP limiter applied only to authentication
// endpoints (challenge + verify). Limit: 10 requests/minute per IP.
// This is 10× tighter than the general write limit and provides the first
// layer of brute-force protection for Ed25519 challenge-response.
var authRateLimiter = &rateLimiter{
	windows:  make(map[string][]int64),
	readMax:  10,
	writeMax: 10,
}

// AuthRateLimitMiddleware wraps a single handler with the tighter auth rate limit.
func AuthRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !authRateLimiter.allow(ip, r.Method) {
			w.Header().Set("Retry-After", "60")
			writeErrorPlain(w, http.StatusTooManyRequests, "too many authentication attempts — try again in 60 seconds")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware enforces per-IP rate limits.
// Defaults: reads 300 req/min, writes 100 req/min.
// Override with RATE_LIMIT_READ_PER_MIN / RATE_LIMIT_WRITE_PER_MIN env vars.
func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !globalRateLimiter.allow(ip, r.Method) {
			w.Header().Set("Retry-After", "60")
			writeErrorPlain(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeErrorPlain is a standalone version of writeError (no import cycle).
func writeErrorPlain(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ---------------------------------------------------------------------------
// JWTMiddleware (standalone, for external use)
// ---------------------------------------------------------------------------

type jwtValidatorFunc func(token string) (string, error)

// JWTMiddleware returns a middleware that validates Bearer tokens using the
// provided validator function. The wallet key is stored in the context under
// walletKeyCtxKey{}.
func JWTMiddleware(validator jwtValidatorFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			token, ok := strings.CutPrefix(auth, "Bearer ")
			if !ok || token == "" {
				writeErrorPlain(w, http.StatusUnauthorized, "missing or malformed Authorization header")
				return
			}
			walletKey, err := validator(token)
			if err != nil {
				writeErrorPlain(w, http.StatusUnauthorized, err.Error())
				return
			}
			ctx := context.WithValue(r.Context(), walletKeyCtxKey{}, walletKey)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ---------------------------------------------------------------------------
// LoggingMiddleware
// ---------------------------------------------------------------------------

// responseRecorder captures the status code written by a handler.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}

// Hijack implements http.Hijacker so that WebSocket upgrades work through
// the logging middleware. Without this the gorilla upgrader returns 500.
func (rr *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := rr.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("logging middleware: ResponseWriter does not implement http.Hijacker")
	}
	return h.Hijack()
}

// LoggingMiddleware logs each request as structured JSON: method, path, status, duration.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf(`{"method":%q,"path":%q,"status":%d,"duration_ms":%d}`,
			r.Method, r.URL.Path, rec.statusCode, time.Since(start).Milliseconds())
	})
}
