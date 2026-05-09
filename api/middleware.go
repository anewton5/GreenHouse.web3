package api

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// CORSMiddleware
// ---------------------------------------------------------------------------

// CORSMiddleware sets appropriate CORS headers for the GreenHouse web client.
// All origins are allowed in development; tighten AllowedOrigins for production.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
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
	return &rateLimiter{
		windows:  make(map[string][]int64),
		readMax:  100,
		writeMax: 20,
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

var globalRateLimiter = newRateLimiter()

// RateLimitMiddleware enforces per-IP rate limits.
// Reads: 100 req/min. Writes: 20 req/min.
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
