# Payment System Audit — Production Readiness Review

**Scope:** `payment.go`, `payment_retry.go`, `pontes_payment.go`, `modulr_payment.go`, `eurc_payment.go`  
**Platform:** GreenHouse Private Placements (Web3 / DLT)  
**Target:** Enterprise-grade production readiness

---

## Executive Summary

The codebase is well above average for a prototype. The architecture is coherent, the crypto primitives are used correctly, interface abstractions are clean, and context propagation has been brought up to standard. However, there are **8 blocking issues** that must be resolved before any production traffic touches real money, and a further **14 significant issues** that represent enterprise-grade gaps. The most critical are: in-memory state (no persistence or crash recovery), missing idempotency enforcement, no amount validation on confirmations, and interface signature mismatches between providers.

**Verdict: Not production-ready as-is. Estimated gap to enterprise grade: medium — the foundation is strong, the missing pieces are well-defined.**

---

## Severity Classification

| Severity | Meaning |
|---|---|
| 🔴 BLOCKING | Will cause data loss, financial loss, or security breach in production |
| 🟠 HIGH | Significant reliability, compliance, or correctness gap |
| 🟡 MEDIUM | Enterprise-grade gap; acceptable for early pilot, must fix before scale |
| 🟢 LOW | Code quality, observability, or maintainability improvement |

---

## 🔴 BLOCKING Issues

### B-1: All state is in-memory — no persistence or crash recovery

**Files:** `pontes_payment.go`, `eurc_payment.go`

Both providers store all payment state in process memory:

```go
// pontes_payment.go
pending  map[string]string        // reference → Pontes transactionId
payments map[string]PaymentStatus // reference → status

// eurc_payment.go
accounts map[string]string        // walletID → on-chain address
payments map[string]PaymentStatus // reference → status
```

A process restart, OOM kill, or deployment wipes every in-flight settlement record. In a DVP system this means the asset leg may have already executed on-chain while the cash leg record is gone — irrecoverable without manual reconciliation.

**Required fix:** All payment state must be persisted to a durable store (Postgres, Redis with AOF, etc.) before any real money flows. The maps become a write-through cache at most.

---

### B-2: Interface signature mismatch — `PaymentProvider` is broken across providers

**Files:** `payment.go`, `modulr_payment.go`, `eurc_payment.go`

The `PaymentProvider` interface defines:

```go
CreateVirtualAccount(walletID string) (iban string, err error)
GetPaymentStatus(reference string) (PaymentStatus, error)
ConfirmPayment(reference string, amount float64, currency string) error
```

But `ModulrPaymentProvider` implements:

```go
func (m *ModulrPaymentProvider) CreateVirtualAccount(ctx context.Context, walletID string) (string, error)
func (m *ModulrPaymentProvider) GetPaymentStatus(ctx context.Context, reference string) (PaymentStatus, error)
func (m *ModulrPaymentProvider) ConfirmPayment(_ context.Context, _ string, _ float64, _ string) error
```

`ModulrPaymentProvider` does **not** satisfy `PaymentProvider`. This is a compile-time break. The interface needs a single canonical signature — the context-aware version is correct; the interface definition in `payment.go` is the one that needs updating.

**Required fix:** Update `PaymentProvider` (and `ContextualPaymentProvider`) to require `ctx context.Context` as the first parameter on all methods, consistently across all providers.

---

### B-3: No idempotency enforcement on `RegisterSettlement`

**File:** `pontes_payment.go`

The `SettlementRegistrar` interface doc says "Must be idempotent — the same instruction may be submitted more than once (retry path)." But the implementation has no idempotency check:

```go
func (p *PontesPaymentProvider) RegisterSettlementCtx(ctx context.Context, instruction *PaymentInstruction) (string, error) {
    // No check: has this reference already been registered?
    // Will POST /settlements again, creating a duplicate settlement
```

If the Pontes API does not enforce idempotency on its side (or uses a different key), a network timeout after the POST succeeds but before the response is received will cause a duplicate DVP settlement attempt — a critical financial error.

**Required fix:** Check `p.pending[instruction.Reference]` under the lock before making the API call, and return the cached `transactionID` if already registered. Also pass an idempotency key header to the Pontes API if the pilot spec supports it.

---

### B-4: Amount not validated on `ConfirmPayment`

**Files:** `pontes_payment.go`, `eurc_payment.go`

```go
func (p *PontesPaymentProvider) ConfirmPayment(reference string, amount float64, currency string) error {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.payments[reference] = PaymentStatusConfirmed  // amount and currency ignored entirely
    return nil
}
```

A webhook delivering the wrong amount (partial payment, fat-finger, or adversarial replay) is confirmed as though it were correct. In a securities settlement context this is a direct financial loss vector.

**Required fix:** Store the expected amount and currency from the `PaymentInstruction` at registration time, and validate them in `ConfirmPayment` before writing `PaymentStatusConfirmed`.

---

### B-5: Webhook signature verification not enforced at the call site

**Files:** `pontes_payment.go`, `modulr_payment.go`, `eurc_payment.go`

All three providers implement `VerifyWebhookSignature`, but it returns a `bool` and the enforcement is left entirely to the caller (the HTTP handler, not shown). There is no architectural guarantee that a webhook handler cannot accidentally call `ConfirmPayment` without first calling `VerifyWebhookSignature`. 

In `PontesPaymentProvider`, if `hmacSecret` is empty, `VerifyWebhookSignature` returns `false` — but an empty secret is a valid (if misconfigured) state that `NewPontesPaymentProvider` allows silently.

**Required fix:** 
1. `ConfirmPayment` should accept the raw payload and signature and verify internally, or the handler must be structured so verification is mandatory (e.g. middleware that returns 401 before the handler runs).
2. Warn loudly (log + return error) if `hmacSecret` is empty at construction time.

---

### B-6: `GetPaymentStatus` on Pontes has a TOCTOU race

**File:** `pontes_payment.go`

```go
func (p *PontesPaymentProvider) GetPaymentStatus(reference string) (PaymentStatus, error) {
    p.mu.Lock()
    if s, ok := p.payments[reference]; ok {
        p.mu.Unlock()
        return s, nil
    }
    transactionID, ok := p.pending[reference]
    p.mu.Unlock()   // ← lock released here
    if !ok {
        return PaymentStatusPending, nil
    }
    // ... HTTP call happens without the lock
    // Another goroutine may write p.payments[reference] concurrently
```

The subsequent write to `p.payments` under a second lock acquisition is guarded, but the HTTP call itself races with `ConfirmPayment` — a webhook could confirm between the status check returning "PENDING" from the API and this function returning. The status written here could then overwrite a `PaymentStatusConfirmed` already written by the webhook handler.

```go
// This guard exists but has a gap:
if existing, ok := p.payments[reference]; ok {
    p.mu.Unlock()
    return existing, nil   // good — but only checked after the HTTP call
}
p.payments[reference] = status   // could overwrite Confirmed with Pending
```

The `status == PaymentStatusConfirmed` guard means this only writes on confirmed — but if the Pontes API returns "PENDING" and then the webhook fires simultaneously, the webhook's `Confirmed` write happens first, and then this function returns `Pending` to the caller without overwriting (the second lock check prevents it). The read race is the real issue: a caller can get a stale `Pending` when `Confirmed` has already been written.

**Required fix:** Re-check `p.payments[reference]` after the HTTP call under the lock before returning any non-confirmed status.

---

### B-7: `retryHTTP` retries non-idempotent methods without awareness

**File:** `payment_retry.go`

`retryHTTP` retries all errors including plain network errors — but POST requests are not idempotent. If a POST to `/settlements` (Pontes) or `/wallets` (Circle) succeeds on the server but the response is lost in transit, retrying creates a duplicate resource. This is the server-side complement to B-3.

**Required fix:** Either (a) pass the HTTP method to `retryHTTP` and only auto-retry GET/PUT/DELETE, requiring explicit opt-in for POST, or (b) require all POST endpoints used with `retryHTTP` to support idempotency keys, and include them in the retry closure.

---

### B-8: `paymentRetryJitter` uses `math/rand` (not cryptographically seeded)

**File:** `payment_retry.go`

```go
paymentRetryJitter = func() float64 {
    return (rand.Float64()*0.2 - 0.1)
}
```

In Go 1.20+ the global `math/rand` source is automatically seeded, so this is not a security issue — but it is a predictability issue under load. If many goroutines retry simultaneously, their jitter windows can still cluster. This is minor for 3 attempts but worth noting.

**Required fix:** Use a per-call `rand.New(rand.NewSource(time.Now().UnixNano()))` or the newer `rand/v2` package, or accept the current behaviour as sufficient for the retry scale involved.

---

## 🟠 HIGH Issues

### H-1: No timeout on individual retry attempts — only on the whole HTTP client

**File:** `payment_retry.go`, all providers

The `http.Client` has a 30-second `Timeout`, but this is a per-request timeout. With 3 retry attempts each allowed 30 seconds, a single call to `RegisterSettlementCtx` can block for up to 90 seconds (plus backoff). There is no overall operation deadline.

**Recommended fix:** Accept an outer context with a deadline at the call site, or add a hard cap: `ctx, cancel := context.WithTimeout(ctx, 45*time.Second)`.

---

### H-2: `GetPaymentStatus` on Pontes returns `PaymentStatusPending` for unknown references — silently

**File:** `pontes_payment.go`

```go
transactionID, ok := p.pending[reference]
if !ok {
    return PaymentStatusPending, nil  // no error, no log
}
```

An unknown reference (typo, wrong environment, or a record lost after a restart per B-1) silently returns "pending" forever. The caller has no way to distinguish "genuinely pending" from "never registered". This can cause a trade to wait indefinitely for a settlement that was never initiated.

**Recommended fix:** Return a distinct `PaymentStatusUnknown` with an explanatory error, or at minimum log a warning.

---

### H-3: `sleepWithContext` is defined but never used

**File:** `payment_retry.go`

```go
var paymentRetrySleep = sleepWithContext
// ...
func sleepWithContext(ctx context.Context, d time.Duration) error { ... }
```

`paymentRetrySleep` is assigned but never called — `waitRetry` is used directly instead. This is dead code that exists as a testing seam but is disconnected from the actual implementation.

**Recommended fix:** Either wire `paymentRetrySleep` into `waitRetry` (making it the actual sleep function so tests can swap it), or remove it entirely.

---

### H-4: `EURCPaymentProvider.CreateVirtualAccount` error path leaks pending request

**File:** `eurc_payment.go`

```go
resp, err := retryHTTP(context.Background(), 3, func() (*http.Response, error) { ... })
if err != nil {
    return "", fmt.Errorf("eurc: wallet creation request failed: %w", err)
    // ← returns here without closing req.done or deleting from pendingAccount
```

Wait — looking more carefully, the error is caught and `req.err` is set, `req.done` is closed and `pendingAccount` entry is deleted further down, only in the success path near the end. But if `retryHTTP` returns an error, execution returns early before `close(req.done)` is called. Any concurrent goroutine waiting on `<-req.done` will block forever.

**Recommended fix:** Use `defer` to always close `req.done` and clean up `pendingAccount`:

```go
defer func() {
    e.mu.Lock()
    req.addr = addr
    req.err = err
    close(req.done)
    delete(e.pendingAccount, walletID)
    e.mu.Unlock()
}()
```

---

### H-5: Travel Rule threshold and payload population not enforced in the payment layer

**File:** `payment.go`

`TravelRuleThresholdEUR = 1_000.0` is defined and `TravelRule *TravelRulePayload` exists on `PaymentInstruction`, but there is no enforcement in any provider that a `TravelRulePayload` is present and non-nil when `TotalAmount >= 1000`. The comment says "Populated automatically in finalizeBlock" — but there is no validation at the payment layer to catch cases where it wasn't. EU TFR (Regulation 2023/1113) is a hard legal requirement, not a best-effort field.

**Recommended fix:** Add a validation step in `RegisterSettlementCtx` (and equivalent entry points) that returns an error if `instruction.TotalAmount >= TravelRuleThresholdEUR && instruction.TravelRule == nil`.

---

## 🟡 MEDIUM Issues

### M-1: `ContextualPaymentProvider` interface is incomplete and inconsistently applied

**File:** `payment.go`

`ContextualPaymentProvider` adds `CreateVirtualAccountCtx` and `GetPaymentStatusCtx` but omits `ConfirmPaymentCtx`. `ModulrPaymentProvider` implements `GetPaymentStatusCtx` as a trivial alias. `PontesPaymentProvider` implements `RegisterSettlementCtx` but this is on a separate `SettlementRegistrar` interface. The context-aware interface story is fragmented. 

**Recommended fix:** Collapse into a single `PaymentProvider` interface where all methods take `ctx` as the first argument. Eliminate the `-Ctx` suffix variants entirely — they only exist to paper over the mismatch.

---

### M-2: No structured logging or tracing

**Files:** All

Not a single log line, span, or metric exists across all five files. In a payment system processing real money, this means:

- No audit trail of which settlements were attempted, when, and with what result
- No alerting on retry storms or elevated failure rates
- No latency visibility per payment rail
- No correlation ID threading from HTTP request → payment → webhook

**Recommended fix:** Inject a `logger` (e.g. `*slog.Logger`) and a trace propagator into each provider at construction. Log at INFO on every settlement attempt/result, WARN on retries, ERROR on final failure. Add `slog.String("reference", ...)` to every log line.

---

### M-3: No circuit breaker on external payment APIs

**Files:** `pontes_payment.go`, `modulr_payment.go`, `eurc_payment.go`

If a payment provider's API goes down, every call will exhaust all retry attempts (with backoff) before failing. Under load this means a flood of blocked goroutines, each holding resources for up to 90 seconds (see H-1). There is no fast-fail mechanism.

**Recommended fix:** Wrap each provider's HTTP calls with a circuit breaker (e.g. `gobreaker` or `sony/gobreaker`). Open the circuit after N consecutive failures; half-open after a recovery interval.

---

### M-4: `modulr_payment.go` uses HMAC-SHA1 for request authentication

**File:** `modulr_payment.go`

```go
h := hmac.New(sha1.New, []byte(m.apiSecret))
```

SHA-1 is used because the Modulr API spec requires it. This is noted for awareness — it is correct per the spec, but SHA-1 is considered weak. If Modulr ever offers SHA-256 signatures, migrate. Document the constraint explicitly so a future reviewer does not "fix" it to SHA-256 and break production auth.

---

### M-5: `retryHTTP` backoff table has only 3 entries for up to 10 attempts

**File:** `payment_retry.go`

```go
var paymentRetryBackoffs = []time.Duration{0, 500 * time.Millisecond, 2 * time.Second}
```

`retryDelayForAttempt` caps at the last entry for any attempt beyond index 2. With `maxAttempts=10`, attempts 3–9 all wait exactly 2 seconds (± jitter). This is not true exponential backoff — it is a flat rate after the second retry. This may cause unnecessary load on a struggling upstream.

**Recommended fix:** Extend the backoff table (e.g. `{0, 500ms, 2s, 5s, 10s, 30s}`) or compute exponential backoff dynamically: `base * 2^attempt`.

---

### M-6: `PontesPaymentProvider` `baseURL` accepts empty string silently

**File:** `pontes_payment.go`

```go
func NewPontesPaymentProvider(apiKey, baseURL, dltOperator, hmacSecret string) (*PontesPaymentProvider, error) {
    // baseURL is not validated — if empty, all API calls go to "/settlements" etc.
```

An empty `baseURL` will cause all requests to fail with a URL parse error at runtime, rather than failing fast at construction.

**Recommended fix:** Validate `baseURL != ""` in `NewPontesPaymentProvider`, defaulting to `pontesPilotBaseURL` if empty (as `NewPontesPaymentProviderFromEnv` already does).

---

### M-7: No reconciliation mechanism

**Files:** All

There is no background job or API surface that reconciles expected settlements (from `pending`) against confirmed ones (in `payments`). If a webhook is missed (network blip, restart, double delivery), a settlement that completed on the provider's side will sit as "pending" in your system indefinitely.

**Recommended fix:** Implement a reconciliation loop that periodically polls `GetPaymentStatus` for all references in `pending` that are older than N minutes, and applies any confirmed statuses.

---

### M-8: `EURCPaymentProvider.CreateVirtualAccount` uses `context.Background()` 

**File:** `eurc_payment.go`

```go
resp, err := retryHTTP(context.Background(), 3, func() (*http.Response, error) {
```

Like the original `RegisterSettlement` issue that was fixed in this session, `CreateVirtualAccount` ignores the caller's context. A cancelled request will still fire the full retry sequence against the Circle API.

**Recommended fix:** Add a `CreateVirtualAccountCtx(ctx context.Context, walletID string)` method (same pattern as `RegisterSettlementCtx`) and have `CreateVirtualAccount` delegate to it with `context.Background()`.

---

## 🟢 LOW Issues

### L-1: `paymentRetryBackoffs[0]` is zero — first retry has no delay

**File:** `payment_retry.go`

```go
var paymentRetryBackoffs = []time.Duration{0, 500 * time.Millisecond, 2 * time.Second}
```

Attempt 0 (the first retry after the initial attempt) has zero backoff. `waitRetry` substitutes `1 * time.Nanosecond` for zero durations — effectively no delay. This may be intentional for responsiveness, but it means two attempts fire nearly back-to-back with no breathing room for transient failures.

---

### L-2: `pontesStatusToPaymentStatus` treats all unknown statuses as Pending

**File:** `pontes_payment.go`

```go
default:
    return PaymentStatusPending
```

An unknown status string (API version change, typo, new status added by Pontes) silently becomes "pending" rather than "unknown". This masks API changes.

**Recommended fix:** Return `PaymentStatusUnknown` from the default case and log the unrecognised status string.

---

### L-3: `modulrStatusToPaymentStatus` has the same issue as L-2

**File:** `modulr_payment.go`

Same pattern — unknown Modulr statuses silently become `PaymentStatusPending`.

---

### L-4: No `maxBodySize` limit on response reads

**Files:** All providers

```go
respBody, _ := io.ReadAll(resp.Body)
```

An unbounded `io.ReadAll` on an error response body is a memory exhaustion vector if the upstream returns an unexpectedly large response (or a misbehaving proxy injects one).

**Recommended fix:** Wrap with `io.LimitReader(resp.Body, 64*1024)` for error bodies.

---

### L-5: `ConfirmPayment` on `ModulrPaymentProvider` always returns an error

**File:** `modulr_payment.go`

```go
func (m *ModulrPaymentProvider) ConfirmPayment(_ context.Context, _ string, _ float64, _ string) error {
    return fmt.Errorf("modulr: ConfirmPayment must not be called directly...")
}
```

This satisfies the interface but creates a footgun — any code path that calls `ConfirmPayment` on a `PaymentProvider` interface value will silently fail if it holds a `ModulrPaymentProvider`. The error message is helpful but the failure mode is invisible unless the caller checks the error.

**Recommended fix:** Add a compile-time `// ConfirmPayment is intentionally unimplemented` comment and consider a `WebhookConfirmableProvider` interface that only providers supporting direct confirmation implement — making the contract explicit at the type level.

---

### L-6: `idempotencyKey` construction in EURC is subtly risky

**File:** `eurc_payment.go`

```go
idempotencyKey = "gh-" + hex.EncodeToString(h[:])[:33]
```

The hex string is truncated to 33 characters. SHA-256 hex is 64 characters, so collision probability is negligible in practice — but truncating a hash is not the same as using a full hash. If Circle's limit is 36 chars, `"gh-" + base64url(sha256[:18bytes])` (24 chars of base64url = 18 bytes = 144 bits of entropy) is cleaner and collision-proof at any realistic scale.

---

## Summary Table

| ID | Severity | File | Issue |
|---|---|---|---|
| B-1 | 🔴 BLOCKING | pontes, eurc | All state in-memory, no persistence |
| B-2 | 🔴 BLOCKING | payment, modulr | Interface signature mismatch |
| B-3 | 🔴 BLOCKING | pontes | No idempotency on RegisterSettlement |
| B-4 | 🔴 BLOCKING | pontes, eurc | Amount not validated on ConfirmPayment |
| B-5 | 🔴 BLOCKING | all | Webhook verification not architecturally enforced |
| B-6 | 🔴 BLOCKING | pontes | TOCTOU race in GetPaymentStatus |
| B-7 | 🔴 BLOCKING | payment_retry | Retrying non-idempotent POST requests |
| B-8 | 🔴 BLOCKING | payment_retry | math/rand for jitter (predictable under load) |
| H-1 | 🟠 HIGH | all | No overall operation timeout |
| H-2 | 🟠 HIGH | pontes | Unknown reference silently returns Pending |
| H-3 | 🟠 HIGH | payment_retry | sleepWithContext unused / disconnected |
| H-4 | 🟠 HIGH | eurc | Goroutine leak on CreateVirtualAccount error |
| H-5 | 🟠 HIGH | payment | Travel Rule not enforced at payment layer |
| M-1 | 🟡 MEDIUM | payment | ContextualPaymentProvider incomplete |
| M-2 | 🟡 MEDIUM | all | No structured logging or tracing |
| M-3 | 🟡 MEDIUM | all | No circuit breaker |
| M-4 | 🟡 MEDIUM | modulr | HMAC-SHA1 (spec-mandated, document it) |
| M-5 | 🟡 MEDIUM | payment_retry | Backoff table not truly exponential |
| M-6 | 🟡 MEDIUM | pontes | baseURL not validated at construction |
| M-7 | 🟡 MEDIUM | all | No reconciliation mechanism |
| M-8 | 🟡 MEDIUM | eurc | CreateVirtualAccount ignores caller context |
| L-1 | 🟢 LOW | payment_retry | First retry has zero delay |
| L-2 | 🟢 LOW | pontes | Unknown status → Pending silently |
| L-3 | 🟢 LOW | modulr | Unknown status → Pending silently |
| L-4 | 🟢 LOW | all | Unbounded io.ReadAll on error bodies |
| L-5 | 🟢 LOW | modulr | ConfirmPayment always errors — invisible footgun |
| L-6 | 🟢 LOW | eurc | Idempotency key truncation |

---

## Recommended Fix Priority Order

**Immediate (before any real-money testing):**
1. B-2 — Fix interface signatures (compiler break)
2. H-4 — Fix goroutine leak in EURC (will deadlock under any error)
3. B-3 — Add idempotency check to RegisterSettlement
4. B-4 — Validate amount/currency in ConfirmPayment
5. B-5 — Enforce webhook verification architecturally

**Before pilot launch:**
6. B-1 — Persist payment state to durable storage
7. B-6 — Fix TOCTOU race in GetPaymentStatus
8. B-7 — Make retryHTTP idempotency-aware
9. H-5 — Enforce Travel Rule at payment layer
10. M-7 — Implement reconciliation loop

**Before production scale:**
11. M-2 — Add structured logging and tracing
12. M-3 — Add circuit breakers
13. H-1 — Add overall operation timeouts
14. M-5 — Implement true exponential backoff
15. M-8 + H-2 + M-6 — Remaining context/validation gaps

---

## What Is Already Good

It is worth being explicit about what the codebase gets right, because these are not trivial:

- **HMAC webhook verification** is implemented correctly in all three providers using constant-time comparison (`hmac.Equal`) — a common mistake elsewhere.
- **Context propagation** is now correct in `RegisterSettlementCtx` and `ModulrPaymentProvider` after the fixes in this session.
- **retryHTTP** correctly handles pre-cancelled contexts, backoff interruption, and context error passthrough after the fixes applied.
- **Credential handling** is clean — no hardcoded keys, env var loading is validated, and secrets are stored in unexported fields.
- **The `SettlementRegistrar` interface** is a well-designed extension point that allows Pontes to be detected at runtime without polluting the base `PaymentProvider` interface.
- **Circle idempotency key construction** correctly identifies the collision risk of long wallet IDs and hashes them — this shows payment-level thinking.
- **`eurcAccountRequest` deduplication** (the pending channel pattern) correctly prevents thundering-herd duplicate wallet creation calls — a sophisticated pattern correctly applied.
- **`pontesStatusToPaymentStatus` and `modulrStatusToPaymentStatus`** are clean, exhaustive, and correctly handle the provider-specific status vocabulary.
- **DVP architecture and flow documentation** in the file comments is excellent — it will save significant onboarding time.
AUDIT_EOF
echo "Audit file written successfully"
wc -l /mnt/user-data/outputs/payment_audit.md