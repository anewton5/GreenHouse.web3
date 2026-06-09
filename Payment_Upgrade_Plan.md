# GreenHouse Payment System — Production Upgrade Plan

**Based on audit of:** `payment.go` · `payment_retry.go` · `pontes_payment.go` · `modulr_payment.go` · `eurc_payment.go`  
**Issues addressed:** B-1 through L-6 (27 total)  
**Format per issue:** Root cause · Specific fix · Code · Tests · Acceptance criteria

---

## How to read this document

Each issue section contains:

- **Root cause** — the exact lines and mechanism of the problem
- **Fix** — the complete corrected code for that issue
- **Tests** — copy-paste ready Go test functions
- **Acceptance criteria** — explicit pass/fail conditions for sign-off

Issues are ordered by the recommended fix sequence from the audit. Fix blocking issues first; they are prerequisites for correctness of everything else.

---

# BLOCKING ISSUES

---

## B-1 · All state is in-memory — no persistence or crash recovery

**Files:** `pontes_payment.go`, `eurc_payment.go`

### Root cause

Both providers store all operational state in process-local maps:

```go
// pontes_payment.go — wiped on any restart
pending  map[string]string        // reference → Pontes transactionId
payments map[string]PaymentStatus

// eurc_payment.go — wiped on any restart
accounts map[string]string        // walletID → on-chain address
payments map[string]PaymentStatus
```

A process crash, OOM kill, or rolling deployment between RegisterSettlement and the incoming webhook causes permanent loss of the `pending` map entry. The DVP asset leg may have already transferred on-chain, but there is no record to match the incoming webhook against — the trade is orphaned. Manual database reconciliation is the only recovery path, which is unacceptable for a regulated securities platform.

### Fix

Introduce a `PaymentStore` interface and inject it into each provider. The production implementation writes to PostgreSQL. The in-memory implementation is retained for tests only.

**`payment_store.go` (new file)**

```go
package gonetwork

import "context"

// PaymentStore is the durable backing store for all payment provider state.
// All writes must be synchronous and acknowledged before the provider
// returns success to the caller. Implementations must be safe for concurrent use.
type PaymentStore interface {
    // SetPending records that a settlement registration has been accepted by the
    // provider. reference is the platform trade reference; transactionID is the
    // provider-assigned ID. The expectedAmount and expectedCurrency are stored
    // for validation when ConfirmPayment is later called.
    SetPending(ctx context.Context, reference, transactionID string, expectedAmount float64, expectedCurrency string) error

    // GetPending retrieves the provider transactionID for a reference.
    // Returns ("", false, nil) when the reference is not registered.
    GetPending(ctx context.Context, reference string) (transactionID string, found bool, err error)

    // SetStatus persists a terminal or intermediate payment status.
    SetStatus(ctx context.Context, reference string, status PaymentStatus) error

    // GetStatus retrieves the last persisted status.
    // Returns (PaymentStatusUnknown, false, nil) when no record exists.
    GetStatus(ctx context.Context, reference string) (status PaymentStatus, found bool, err error)

    // GetExpected retrieves the expected amount and currency for a reference.
    // Returns (0, "", false, nil) when the reference is not registered.
    GetExpected(ctx context.Context, reference string) (amount float64, currency string, found bool, err error)

    // SetWalletAddress persists a provider-assigned on-chain address for a walletID.
    SetWalletAddress(ctx context.Context, walletID, address string) error

    // GetWalletAddress retrieves a previously stored on-chain address.
    // Returns ("", false, nil) when not found.
    GetWalletAddress(ctx context.Context, walletID string) (address string, found bool, err error)

    // PendingOlderThan returns all (reference, transactionID) pairs whose status
    // is not terminal and whose registration time is before the cutoff.
    // Used by the reconciliation loop (M-7).
    PendingOlderThan(ctx context.Context, cutoff time.Time) ([]PendingSettlement, error)
}

// PendingSettlement is a record returned by PaymentStore.PendingOlderThan.
type PendingSettlement struct {
    Reference     string
    TransactionID string
    RegisteredAt  time.Time
}
```

**`payment_store_memory.go` (new file — for tests)**

```go
package gonetwork

import (
    "context"
    "sync"
    "time"
)

// MemoryPaymentStore is a thread-safe in-memory PaymentStore used in tests.
// Do not use in production.
type MemoryPaymentStore struct {
    mu       sync.Mutex
    pending  map[string]pendingRecord  // reference → record
    statuses map[string]PaymentStatus
    wallets  map[string]string         // walletID → address
}

type pendingRecord struct {
    transactionID    string
    expectedAmount   float64
    expectedCurrency string
    registeredAt     time.Time
}

func NewMemoryPaymentStore() *MemoryPaymentStore {
    return &MemoryPaymentStore{
        pending:  make(map[string]pendingRecord),
        statuses: make(map[string]PaymentStatus),
        wallets:  make(map[string]string),
    }
}

func (s *MemoryPaymentStore) SetPending(_ context.Context, reference, transactionID string, amount float64, currency string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.pending[reference] = pendingRecord{
        transactionID:    transactionID,
        expectedAmount:   amount,
        expectedCurrency: currency,
        registeredAt:     time.Now(),
    }
    return nil
}

func (s *MemoryPaymentStore) GetPending(_ context.Context, reference string) (string, bool, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    r, ok := s.pending[reference]
    if !ok {
        return "", false, nil
    }
    return r.transactionID, true, nil
}

func (s *MemoryPaymentStore) SetStatus(_ context.Context, reference string, status PaymentStatus) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.statuses[reference] = status
    return nil
}

func (s *MemoryPaymentStore) GetStatus(_ context.Context, reference string) (PaymentStatus, bool, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    st, ok := s.statuses[reference]
    return st, ok, nil
}

func (s *MemoryPaymentStore) GetExpected(_ context.Context, reference string) (float64, string, bool, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    r, ok := s.pending[reference]
    if !ok {
        return 0, "", false, nil
    }
    return r.expectedAmount, r.expectedCurrency, true, nil
}

func (s *MemoryPaymentStore) SetWalletAddress(_ context.Context, walletID, address string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.wallets[walletID] = address
    return nil
}

func (s *MemoryPaymentStore) GetWalletAddress(_ context.Context, walletID string) (string, bool, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    addr, ok := s.wallets[walletID]
    return addr, ok, nil
}

func (s *MemoryPaymentStore) PendingOlderThan(_ context.Context, cutoff time.Time) ([]PendingSettlement, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    var results []PendingSettlement
    for ref, r := range s.pending {
        if r.registeredAt.Before(cutoff) {
            if _, terminated := s.statuses[ref]; !terminated {
                results = append(results, PendingSettlement{
                    Reference:     ref,
                    TransactionID: r.transactionID,
                    RegisteredAt:  r.registeredAt,
                })
            }
        }
    }
    return results, nil
}
```

**Update `PontesPaymentProvider` struct to accept `store PaymentStore`:**

```go
type PontesPaymentProvider struct {
    apiKey      string
    baseURL     string
    dltOperator string
    hmacSecret  string
    client      *http.Client
    store       PaymentStore  // ← injected; required

    mu sync.Mutex  // protects only the write-through cache below
    // In-memory caches. store is the source of truth.
    pendingCache  map[string]string
    paymentsCache map[string]PaymentStatus
}

func NewPontesPaymentProvider(apiKey, baseURL, dltOperator, hmacSecret string, store PaymentStore) (*PontesPaymentProvider, error) {
    if store == nil {
        return nil, fmt.Errorf("pontes: store must not be nil")
    }
    // ... rest of validation unchanged ...
}
```

### Tests

```go
func TestPaymentStore_SetAndGetPending(t *testing.T) {
    ctx := context.Background()
    store := NewMemoryPaymentStore()

    err := store.SetPending(ctx, "ref-001", "txn-abc", 1500.00, "EUR")
    require.NoError(t, err)

    txnID, found, err := store.GetPending(ctx, "ref-001")
    require.NoError(t, err)
    require.True(t, found)
    require.Equal(t, "txn-abc", txnID)
}

func TestPaymentStore_GetPending_NotFound(t *testing.T) {
    ctx := context.Background()
    store := NewMemoryPaymentStore()

    _, found, err := store.GetPending(ctx, "does-not-exist")
    require.NoError(t, err)
    require.False(t, found)
}

func TestPaymentStore_StatusSurvivesAcrossReads(t *testing.T) {
    ctx := context.Background()
    store := NewMemoryPaymentStore()

    require.NoError(t, store.SetStatus(ctx, "ref-001", PaymentStatusConfirmed))

    status, found, err := store.GetStatus(ctx, "ref-001")
    require.NoError(t, err)
    require.True(t, found)
    require.Equal(t, PaymentStatusConfirmed, status)
}

func TestPaymentStore_PendingOlderThan(t *testing.T) {
    ctx := context.Background()
    store := NewMemoryPaymentStore()

    require.NoError(t, store.SetPending(ctx, "ref-old", "txn-1", 100, "EUR"))
    time.Sleep(10 * time.Millisecond)
    cutoff := time.Now()
    require.NoError(t, store.SetPending(ctx, "ref-new", "txn-2", 200, "EUR"))

    results, err := store.PendingOlderThan(ctx, cutoff)
    require.NoError(t, err)
    require.Len(t, results, 1)
    require.Equal(t, "ref-old", results[0].Reference)
}
```

### Acceptance criteria

- All `PaymentStore` methods covered by unit tests passing with `MemoryPaymentStore`
- `PontesPaymentProvider` and `EURCPaymentProvider` constructors reject `nil` store with a descriptive error
- Integration test: simulate a process restart by constructing a new provider with the same `MemoryPaymentStore` instance; verify pending state is accessible
- PostgreSQL implementation passes the same test suite via a shared `PaymentStoreTestSuite` test helper

---

## B-2 · Interface signature mismatch — `PaymentProvider` broken across providers

**Files:** `payment.go`, `modulr_payment.go`, `eurc_payment.go`

### Root cause

`PaymentProvider` in `payment.go` defines context-free signatures:

```go
CreateVirtualAccount(walletID string) (iban string, err error)
GetPaymentStatus(reference string) (PaymentStatus, error)
ConfirmPayment(reference string, amount float64, currency string) error
```

But `ModulrPaymentProvider` implements context-aware signatures:

```go
func (m *ModulrPaymentProvider) CreateVirtualAccount(ctx context.Context, walletID string) (string, error)
func (m *ModulrPaymentProvider) GetPaymentStatus(ctx context.Context, reference string) (PaymentStatus, error)
func (m *ModulrPaymentProvider) ConfirmPayment(_ context.Context, _ string, _ float64, _ string) error
```

`ModulrPaymentProvider` does not satisfy `PaymentProvider`. This is a compile error. The `ContextualPaymentProvider` workaround is an anti-pattern that adds interface noise without solving the problem.

### Fix

Rewrite `PaymentProvider` with `context.Context` as the first argument on every method. Remove `ContextualPaymentProvider` entirely. Update `PontesPaymentProvider` and `EURCPaymentProvider` method signatures to match.

**`payment.go` — updated interface:**

```go
// PaymentProvider abstracts the fiat payment rail.
// All methods accept a context for cancellation, deadline propagation,
// and distributed tracing. Implementations must be safe for concurrent use.
type PaymentProvider interface {
    // CreateVirtualAccount returns a virtual IBAN or on-chain address for a
    // participant wallet. Must be idempotent — repeated calls for the same
    // walletID must return the same identifier without creating duplicates.
    CreateVirtualAccount(ctx context.Context, walletID string) (iban string, err error)

    // GetPaymentStatus returns the current status of a payment by reference.
    GetPaymentStatus(ctx context.Context, reference string) (PaymentStatus, error)

    // ConfirmPayment records that a payment has been received and validates
    // the amount and currency against what was expected at registration time.
    ConfirmPayment(ctx context.Context, reference string, amount float64, currency string) error
}
```

Remove `ContextualPaymentProvider` — it is now redundant.

**`pontes_payment.go` — update signatures:**

```go
func (p *PontesPaymentProvider) CreateVirtualAccount(ctx context.Context, walletID string) (string, error) {
    return "pontes-" + walletID, nil
}

func (p *PontesPaymentProvider) GetPaymentStatus(ctx context.Context, reference string) (PaymentStatus, error) {
    // ... (implementation updated per B-6 fix)
}

func (p *PontesPaymentProvider) ConfirmPayment(ctx context.Context, reference string, amount float64, currency string) error {
    // ... (implementation updated per B-4 fix)
}
```

**`eurc_payment.go` — update signatures:**

```go
func (e *EURCPaymentProvider) CreateVirtualAccount(ctx context.Context, walletID string) (string, error) {
    // ... (implementation updated per M-8 fix)
}

func (e *EURCPaymentProvider) GetPaymentStatus(ctx context.Context, reference string) (PaymentStatus, error) {
    // context unused for pure cache read — acceptable; retained for interface consistency
    e.mu.Lock()
    defer e.mu.Unlock()
    if s, ok := e.payments[reference]; ok {
        return s, nil
    }
    return PaymentStatusPending, nil
}

func (e *EURCPaymentProvider) ConfirmPayment(ctx context.Context, reference string, amount float64, currency string) error {
    // ... (implementation updated per B-4 fix)
}
```

### Tests

```go
// Compile-time interface conformance checks — these fail to build if signatures drift.
var _ PaymentProvider = (*PontesPaymentProvider)(nil)
var _ PaymentProvider = (*ModulrPaymentProvider)(nil)
var _ PaymentProvider = (*EURCPaymentProvider)(nil)

func TestPaymentProvider_InterfaceConformance(t *testing.T) {
    // If this test compiles, interface conformance is proven.
    // No runtime assertions needed — the value is the compile check above.
    t.Log("All PaymentProvider implementations satisfy the interface")
}
```

### Acceptance criteria

- `go build ./...` passes with zero errors after interface unification
- All three `var _ PaymentProvider = (*XProvider)(nil)` compile-time checks pass
- No remaining references to `ContextualPaymentProvider` or `-Ctx` suffix methods
- `go vet ./...` reports no issues

---

## B-3 · No idempotency enforcement on `RegisterSettlement`

**File:** `pontes_payment.go`

### Root cause

`RegisterSettlementCtx` makes a POST to `/settlements` on every call without checking whether the reference was already registered. A network timeout that occurs after the Pontes server accepts the request but before the response arrives will cause `retryHTTP` to retry — the retry POSTs again, potentially creating a duplicate settlement at the T2 level. This is a critical financial error in a DVP system.

```go
func (p *PontesPaymentProvider) RegisterSettlementCtx(ctx context.Context, instruction *PaymentInstruction) (string, error) {
    // ← No idempotency check here
    body, err := json.Marshal(...)
    resp, err := retryHTTP(ctx, 3, func() (*http.Response, error) {
        req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
        // ← No idempotency key header
        return p.client.Do(req)
    })
```

### Fix

Two complementary defences:

1. Check the store for an existing registration before making any API call
2. Send an idempotency key header with every POST so the Pontes API deduplicates on its side

```go
func (p *PontesPaymentProvider) RegisterSettlementCtx(ctx context.Context, instruction *PaymentInstruction) (string, error) {
    // Defence 1: check durable store before making any API call.
    if existingTxnID, found, err := p.store.GetPending(ctx, instruction.Reference); err != nil {
        return "", fmt.Errorf("pontes: store lookup failed for reference %s: %w", instruction.Reference, err)
    } else if found {
        // Already registered — restore in-place fields and return cached ID.
        instruction.PontesTransactionID = existingTxnID
        instruction.SettlementNetwork = "eurosystem-pontes"
        return existingTxnID, nil
    }

    // Travel Rule enforcement (see H-5).
    if instruction.TotalAmount >= TravelRuleThresholdEUR && instruction.TravelRule == nil {
        return "", fmt.Errorf("pontes: TravelRulePayload is required for amounts >= %.2f EUR (EU TFR Regulation 2023/1113)", TravelRuleThresholdEUR)
    }

    body, err := json.Marshal(pontesRegisterRequest{
        DLTOperator: p.dltOperator,
        Reference:   instruction.Reference,
        PayerBIC:    instruction.PayerWalletID,
        PayeeBIC:    instruction.PayeeWalletID,
        Amount:      instruction.TotalAmount,
        Currency:    instruction.Currency,
    })
    if err != nil {
        return "", fmt.Errorf("pontes: failed to marshal settlement request: %w", err)
    }

    // Defence 2: idempotency key — Pontes deduplicates on its side.
    // Key is derived deterministically from the reference so retries
    // within a single attempt window send the same key.
    idempotencyKey := "gh-settle-" + instruction.Reference

    endpoint := p.baseURL + "/settlements"
    resp, err := retryHTTP(ctx, 3, func() (*http.Response, error) {
        req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
        if err != nil {
            return nil, fmt.Errorf("pontes: failed to build settlement request: %w", err)
        }
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("Authorization", "Bearer "+p.apiKey)
        req.Header.Set("Idempotency-Key", idempotencyKey) // ← Defence 2
        return p.client.Do(req)
    })
    if err != nil {
        return "", fmt.Errorf("pontes: settlement registration request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        respBody, _ := io.LimitReader(resp.Body, 64*1024).(*io.LimitedReader).R.(io.Reader)
        b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
        return "", fmt.Errorf("pontes: settlement registration returned HTTP %d: %s", resp.StatusCode, string(b))
    }

    var result pontesRegisterResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return "", fmt.Errorf("pontes: failed to decode settlement response: %w", err)
    }
    if result.TransactionID == "" {
        return "", fmt.Errorf("pontes: settlement registration returned no transactionId")
    }

    // Persist to durable store before updating instruction fields.
    if err := p.store.SetPending(ctx, instruction.Reference, result.TransactionID, instruction.TotalAmount, instruction.Currency); err != nil {
        return "", fmt.Errorf("pontes: failed to persist pending settlement for reference %s: %w", instruction.Reference, err)
    }

    instruction.PontesTransactionID = result.TransactionID
    instruction.SettlementNetwork = "eurosystem-pontes"

    p.mu.Lock()
    p.pendingCache[instruction.Reference] = result.TransactionID
    p.mu.Unlock()

    return result.TransactionID, nil
}
```

### Tests

```go
func TestPontes_RegisterSettlement_Idempotent_SameReference(t *testing.T) {
    store := NewMemoryPaymentStore()
    p := newTestPontesProvider(t, store)

    callCount := 0
    p.client = httpClientReturning(t, func(req *http.Request) (*http.Response, error) {
        callCount++
        return jsonResponse(200, pontesRegisterResponse{TransactionID: "txn-001", Status: "PENDING"}), nil
    })

    instr := &PaymentInstruction{Reference: "ref-001", TotalAmount: 500.0, Currency: "EUR"}

    txn1, err := p.RegisterSettlementCtx(context.Background(), instr)
    require.NoError(t, err)
    require.Equal(t, "txn-001", txn1)
    require.Equal(t, 1, callCount)

    // Second call — must not hit the API again
    txn2, err := p.RegisterSettlementCtx(context.Background(), instr)
    require.NoError(t, err)
    require.Equal(t, "txn-001", txn2)
    require.Equal(t, 1, callCount, "API must not be called on repeated registration of same reference")
}

func TestPontes_RegisterSettlement_IdempotencyKeyHeader_IsSet(t *testing.T) {
    var capturedKey string
    p := newTestPontesProvider(t, NewMemoryPaymentStore())
    p.client = httpClientReturning(t, func(req *http.Request) (*http.Response, error) {
        capturedKey = req.Header.Get("Idempotency-Key")
        return jsonResponse(200, pontesRegisterResponse{TransactionID: "txn-002"}), nil
    })

    instr := &PaymentInstruction{Reference: "ref-002", TotalAmount: 100.0, Currency: "EUR"}
    _, err := p.RegisterSettlementCtx(context.Background(), instr)
    require.NoError(t, err)
    require.Equal(t, "gh-settle-ref-002", capturedKey)
}

func TestPontes_RegisterSettlement_StoreFailure_ReturnsError(t *testing.T) {
    p := newTestPontesProvider(t, &failingStore{setErr: errors.New("db down")})
    p.client = httpClientReturning(t, func(req *http.Request) (*http.Response, error) {
        return jsonResponse(200, pontesRegisterResponse{TransactionID: "txn-003"}), nil
    })

    instr := &PaymentInstruction{Reference: "ref-003", TotalAmount: 100.0, Currency: "EUR"}
    _, err := p.RegisterSettlementCtx(context.Background(), instr)
    require.Error(t, err)
    require.Contains(t, err.Error(), "failed to persist")
}
```

### Acceptance criteria

- `RegisterSettlementCtx` called twice with the same reference makes exactly one API call
- `Idempotency-Key: gh-settle-{reference}` header present on every POST to `/settlements`
- A store write failure after a successful API response returns an error (no silent loss)
- An API 500 followed by a retry reuses the same idempotency key header on all attempts

---

## B-4 · Amount not validated on `ConfirmPayment`

**Files:** `pontes_payment.go`, `eurc_payment.go`

### Root cause

`ConfirmPayment` ignores the `amount` and `currency` parameters entirely:

```go
// pontes — amount and currency parameters silently discarded
func (p *PontesPaymentProvider) ConfirmPayment(reference string, amount float64, currency string) error {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.payments[reference] = PaymentStatusConfirmed
    return nil
}
```

A webhook delivering a partial amount (e.g. EUR 400 against an expected EUR 1500) is confirmed as fully settled. This is a direct financial loss: the asset leg transfers in full while only a fraction of the cash leg was received.

### Fix

Retrieve the expected amount and currency from the store and validate before confirming.

```go
const amountTolerancePct = 0.001 // 0.1% — accounts for float rounding at provider boundary

func (p *PontesPaymentProvider) ConfirmPayment(ctx context.Context, reference string, amount float64, currency string) error {
    expectedAmount, expectedCurrency, found, err := p.store.GetExpected(ctx, reference)
    if err != nil {
        return fmt.Errorf("pontes: ConfirmPayment store lookup failed for reference %s: %w", reference, err)
    }
    if !found {
        return fmt.Errorf("pontes: ConfirmPayment called for unknown reference %q; no pending registration found", reference)
    }
    if currency != expectedCurrency {
        return fmt.Errorf("pontes: ConfirmPayment currency mismatch for reference %q: expected %s, got %s", reference, expectedCurrency, currency)
    }
    diff := amount - expectedAmount
    if diff < 0 {
        diff = -diff
    }
    if expectedAmount > 0 && diff/expectedAmount > amountTolerancePct {
        return fmt.Errorf("pontes: ConfirmPayment amount mismatch for reference %q: expected %.4f %s, got %.4f %s",
            reference, expectedAmount, expectedCurrency, amount, currency)
    }

    if err := p.store.SetStatus(ctx, reference, PaymentStatusConfirmed); err != nil {
        return fmt.Errorf("pontes: ConfirmPayment failed to persist confirmed status for reference %s: %w", reference, err)
    }

    p.mu.Lock()
    p.paymentsCache[reference] = PaymentStatusConfirmed
    p.mu.Unlock()
    return nil
}
```

Apply the identical pattern to `EURCPaymentProvider.ConfirmPayment`.

### Tests

```go
func TestPontes_ConfirmPayment_AmountMismatch_ReturnsError(t *testing.T) {
    ctx := context.Background()
    store := NewMemoryPaymentStore()
    require.NoError(t, store.SetPending(ctx, "ref-001", "txn-001", 1500.00, "EUR"))

    p := newTestPontesProvider(t, store)

    err := p.ConfirmPayment(ctx, "ref-001", 400.00, "EUR")
    require.Error(t, err)
    require.Contains(t, err.Error(), "amount mismatch")

    // Status must NOT be confirmed after a mismatch
    status, _, _ := store.GetStatus(ctx, "ref-001")
    require.NotEqual(t, PaymentStatusConfirmed, status)
}

func TestPontes_ConfirmPayment_CurrencyMismatch_ReturnsError(t *testing.T) {
    ctx := context.Background()
    store := NewMemoryPaymentStore()
    require.NoError(t, store.SetPending(ctx, "ref-002", "txn-002", 1000.00, "EUR"))

    p := newTestPontesProvider(t, store)

    err := p.ConfirmPayment(ctx, "ref-002", 1000.00, "GBP")
    require.Error(t, err)
    require.Contains(t, err.Error(), "currency mismatch")
}

func TestPontes_ConfirmPayment_UnknownReference_ReturnsError(t *testing.T) {
    ctx := context.Background()
    p := newTestPontesProvider(t, NewMemoryPaymentStore())

    err := p.ConfirmPayment(ctx, "never-registered", 1000.00, "EUR")
    require.Error(t, err)
    require.Contains(t, err.Error(), "unknown reference")
}

func TestPontes_ConfirmPayment_ValidAmount_Succeeds(t *testing.T) {
    ctx := context.Background()
    store := NewMemoryPaymentStore()
    require.NoError(t, store.SetPending(ctx, "ref-003", "txn-003", 1000.00, "EUR"))

    p := newTestPontesProvider(t, store)

    // Exact amount
    require.NoError(t, p.ConfirmPayment(ctx, "ref-003", 1000.00, "EUR"))

    status, found, _ := store.GetStatus(ctx, "ref-003")
    require.True(t, found)
    require.Equal(t, PaymentStatusConfirmed, status)
}

func TestPontes_ConfirmPayment_SmallFloatDifference_Succeeds(t *testing.T) {
    ctx := context.Background()
    store := NewMemoryPaymentStore()
    require.NoError(t, store.SetPending(ctx, "ref-004", "txn-004", 1000.00, "EUR"))

    p := newTestPontesProvider(t, store)

    // 0.05% difference — within tolerance
    require.NoError(t, p.ConfirmPayment(ctx, "ref-004", 1000.50, "EUR"))
}
```

### Acceptance criteria

- `ConfirmPayment` with an amount differing by > 0.1% returns an error and does not set `PaymentStatusConfirmed`
- `ConfirmPayment` with a currency mismatch returns an error
- `ConfirmPayment` for an unknown reference returns an error (not a silent no-op)
- Float rounding differences below 0.1% are accepted (prevents false rejection at provider boundaries)
- After a failed `ConfirmPayment`, `GetPaymentStatus` does not return `PaymentStatusConfirmed`

---

## B-5 · Webhook signature verification not architecturally enforced

**Files:** `pontes_payment.go`, `modulr_payment.go`, `eurc_payment.go`

### Root cause

`VerifyWebhookSignature` is a separate method that callers must remember to invoke. There is no compile-time or runtime enforcement that it is called before `ConfirmPayment`. A handler that skips verification (or is wired incorrectly) accepts any POST as a legitimate webhook.

Additionally, `NewPontesPaymentProvider` allows an empty `hmacSecret`, causing `VerifyWebhookSignature` to silently return `false` — rather than failing at construction with a clear error.

### Fix

**Part 1: Reject empty `hmacSecret` at construction for production providers.**

```go
func NewPontesPaymentProvider(apiKey, baseURL, dltOperator, hmacSecret string, store PaymentStore) (*PontesPaymentProvider, error) {
    if apiKey == "" {
        return nil, fmt.Errorf("pontes: apiKey must not be empty")
    }
    if dltOperator == "" {
        return nil, fmt.Errorf("pontes: dltOperator must not be empty")
    }
    if hmacSecret == "" {
        return nil, fmt.Errorf("pontes: hmacSecret must not be empty; webhook signature verification is required for production")
    }
    // ...
}
```

Apply the same guard to `NewEURCPaymentProvider` for `webhookSecret`.

**Part 2: Introduce `WebhookHandler` as the single enforced verification point.**

```go
// WebhookVerifier is implemented by providers that sign their webhook callbacks.
type WebhookVerifier interface {
    VerifyWebhookSignature(payload []byte, signature string) bool
}

// HandleWebhook is the single entry point for all provider webhook callbacks.
// It enforces signature verification before calling the action function,
// making it impossible to confirm a payment without passing a valid signature.
//
// Usage in HTTP handlers:
//
//   err := HandleWebhook(provider, rawBody, r.Header.Get("X-Pontes-Signature"),
//       func() error {
//           return provider.ConfirmPayment(ctx, reference, amount, currency)
//       })
func HandleWebhook(v WebhookVerifier, payload []byte, signature string, action func() error) error {
    if !v.VerifyWebhookSignature(payload, signature) {
        return fmt.Errorf("payment: webhook signature verification failed — request rejected")
    }
    return action()
}
```

### Tests

```go
func TestHandleWebhook_InvalidSignature_RejectsWithoutCallingAction(t *testing.T) {
    called := false
    provider := newTestPontesProvider(t, NewMemoryPaymentStore())

    err := HandleWebhook(provider, []byte(`{"event":"settlement.confirmed"}`), "bad-sig",
        func() error {
            called = true
            return nil
        })

    require.Error(t, err)
    require.Contains(t, err.Error(), "signature verification failed")
    require.False(t, called, "action must not be called when signature is invalid")
}

func TestHandleWebhook_ValidSignature_CallsAction(t *testing.T) {
    secret := "test-hmac-secret"
    payload := []byte(`{"event":"settlement.confirmed"}`)
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(payload)
    sig := hex.EncodeToString(mac.Sum(nil))

    p, _ := NewPontesPaymentProvider("key", "http://example", "op", secret, NewMemoryPaymentStore())

    called := false
    err := HandleWebhook(p, payload, sig, func() error {
        called = true
        return nil
    })

    require.NoError(t, err)
    require.True(t, called)
}

func TestNewPontesPaymentProvider_EmptyHmacSecret_ReturnsError(t *testing.T) {
    _, err := NewPontesPaymentProvider("key", "http://example", "op", "", NewMemoryPaymentStore())
    require.Error(t, err)
    require.Contains(t, err.Error(), "hmacSecret must not be empty")
}

func TestNewEURCPaymentProvider_EmptyWebhookSecret_ReturnsError(t *testing.T) {
    _, err := NewEURCPaymentProvider("key", "https://api.circle.com/v1", "ws-id", "")
    require.Error(t, err)
    require.Contains(t, err.Error(), "webhookSecret must not be empty")
}
```

### Acceptance criteria

- `HandleWebhook` with an invalid signature returns an error and never invokes `action`
- `HandleWebhook` with a valid signature calls `action` exactly once
- `NewPontesPaymentProvider` with empty `hmacSecret` returns an error
- `NewEURCPaymentProvider` with empty `webhookSecret` returns an error
- No code path in the webhook HTTP handler can reach `ConfirmPayment` without going through `HandleWebhook`

---

## B-6 · `GetPaymentStatus` TOCTOU race in Pontes

**File:** `pontes_payment.go`

### Root cause

The lock is released before the HTTP status poll. A concurrent `ConfirmPayment` (from a webhook) may write `PaymentStatusConfirmed` to the store while the HTTP call is in-flight. The poll then returns "PENDING" from the API (stale), and returns that stale status to the caller — even though confirmation has already been written.

```go
func (p *PontesPaymentProvider) GetPaymentStatus(reference string) (PaymentStatus, error) {
    p.mu.Lock()
    // ... check cache ...
    transactionID, ok := p.pending[reference]
    p.mu.Unlock()   // ← lock released

    // ... HTTP call (can take seconds) ...

    // A webhook may have confirmed during this window.
    // The re-check below only prevents overwriting confirmed with pending,
    // but the RETURNED value to the caller is still the stale "pending".
    status := pontesStatusToPaymentStatus(result.Status)
    if status == PaymentStatusConfirmed {
        p.mu.Lock()
        // ...
    }
    return status, nil  // ← may return stale Pending after confirmation was written
}
```

### Fix

After the HTTP call completes, re-read the store under the lock before returning any non-terminal status. The store is the source of truth.

```go
func (p *PontesPaymentProvider) GetPaymentStatus(ctx context.Context, reference string) (PaymentStatus, error) {
    // Fast path: check durable store for a terminal status first.
    if status, found, err := p.store.GetStatus(ctx, reference); err != nil {
        return PaymentStatusUnknown, fmt.Errorf("pontes: store status lookup failed for reference %s: %w", reference, err)
    } else if found {
        return status, nil
    }

    // Look up registered transactionID.
    transactionID, found, err := p.store.GetPending(ctx, reference)
    if err != nil {
        return PaymentStatusUnknown, fmt.Errorf("pontes: store pending lookup failed for reference %s: %w", reference, err)
    }
    if !found {
        // Not registered at all — return Unknown with an error (see H-2).
        return PaymentStatusUnknown, fmt.Errorf("pontes: reference %q has no registered settlement; may indicate data loss or incorrect reference", reference)
    }

    endpoint := p.baseURL + "/settlements/" + transactionID
    resp, err := retryHTTP(ctx, 3, func() (*http.Response, error) {
        req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
        if err != nil {
            return nil, fmt.Errorf("pontes: failed to build status request: %w", err)
        }
        req.Header.Set("Authorization", "Bearer "+p.apiKey)
        return p.client.Do(req)
    })
    if err != nil {
        return PaymentStatusUnknown, fmt.Errorf("pontes: status request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusNotFound {
        return PaymentStatusFailed, fmt.Errorf("pontes: transaction %s not found (404)", transactionID)
    }
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return PaymentStatusUnknown, fmt.Errorf("pontes: status check returned HTTP %d", resp.StatusCode)
    }

    var result struct {
        Status string `json:"status"`
    }
    if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&result); err != nil {
        return PaymentStatusUnknown, fmt.Errorf("pontes: failed to decode status response: %w", err)
    }

    apiStatus := pontesStatusToPaymentStatus(result.Status)

    // Re-read store AFTER the HTTP call — a webhook may have confirmed
    // during the network round-trip. Store is the authoritative source.
    if storeStatus, found, err := p.store.GetStatus(ctx, reference); err == nil && found {
        return storeStatus, nil
    }

    // If the API reports confirmed, persist it.
    if apiStatus == PaymentStatusConfirmed || apiStatus == PaymentStatusFailed || apiStatus == PaymentStatusExpired {
        _ = p.store.SetStatus(ctx, reference, apiStatus) // best-effort; non-fatal
    }

    return apiStatus, nil
}
```

### Tests

```go
func TestPontes_GetPaymentStatus_WebhookConfirms_DuringPoll_ReturnsConfirmed(t *testing.T) {
    ctx := context.Background()
    store := NewMemoryPaymentStore()
    require.NoError(t, store.SetPending(ctx, "ref-001", "txn-001", 1000.0, "EUR"))

    p := newTestPontesProvider(t, store)

    // Simulate: webhook fires while HTTP status poll is in-flight.
    p.client = httpClientReturning(t, func(req *http.Request) (*http.Response, error) {
        // Webhook writes confirmed to store concurrently
        _ = store.SetStatus(ctx, "ref-001", PaymentStatusConfirmed)
        // API returns PENDING (stale from network transit)
        return jsonResponse(200, map[string]string{"status": "PENDING"}), nil
    })

    status, err := p.GetPaymentStatus(ctx, "ref-001")
    require.NoError(t, err)
    require.Equal(t, PaymentStatusConfirmed, status, "store-confirmed status must win over stale API response")
}

func TestPontes_GetPaymentStatus_UnknownReference_ReturnsUnknownWithError(t *testing.T) {
    ctx := context.Background()
    p := newTestPontesProvider(t, NewMemoryPaymentStore())

    status, err := p.GetPaymentStatus(ctx, "never-registered")
    require.Error(t, err)
    require.Equal(t, PaymentStatusUnknown, status)
}
```

### Acceptance criteria

- When `ConfirmPayment` is called concurrently with `GetPaymentStatus`, the latter returns `PaymentStatusConfirmed` regardless of what the Pontes API says
- An unregistered reference returns `PaymentStatusUnknown` plus a descriptive error (not silent `PaymentStatusPending`)
- No data race detected by `go test -race ./...`

---

## B-7 · `retryHTTP` retries non-idempotent POST requests blindly

**File:** `payment_retry.go`

### Root cause

`retryHTTP` retries all errors equally regardless of HTTP method. POST to `/settlements` is not idempotent at the network level. If the server processes the request but the connection drops before the response arrives, the retry sends a second POST — potentially creating a duplicate settlement.

This is a systemic risk distinct from B-3 (which adds a pre-call store check). B-7 addresses the retry policy itself.

### Fix

Add an `httpMethod` field to the retry configuration. Only GET, PUT, DELETE, and HEAD are retried automatically. POST requests are retried only when an idempotency key is present in the request (confirming the caller has opted in to safe retry semantics).

```go
// retryConfig controls retry behaviour for a specific HTTP call.
type retryConfig struct {
    maxAttempts    int
    // safeToRetry explicitly marks a request as safe to retry even on POST.
    // Must only be set when the request carries an Idempotency-Key header,
    // ensuring the upstream deduplicates repeated requests.
    safeToRetry    bool
}

// retryHTTPWithConfig is the primary retry function. retryHTTP is a
// convenience wrapper that marks GET requests as safe and POST as unsafe.
func retryHTTPWithConfig(
    ctx context.Context,
    cfg retryConfig,
    fn func() (*http.Response, error),
) (*http.Response, error) {
    if cfg.maxAttempts <= 0 {
        cfg.maxAttempts = 1
    }

    var lastErr error
    for attempt := 0; attempt < cfg.maxAttempts; attempt++ {
        if err := ctx.Err(); err != nil {
            return nil, err
        }

        resp, err := fn()

        if err == nil {
            if resp.StatusCode < 500 {
                return resp, nil
            }
            if attempt == cfg.maxAttempts-1 {
                return resp, nil
            }
            if resp.Body != nil {
                _ = resp.Body.Close()
            }
        } else {
            lastErr = err
            if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
                return nil, err
            }
            if attempt == cfg.maxAttempts-1 {
                break
            }
            // For non-idempotent requests, do not retry on network errors —
            // the request may have been received and processed by the server.
            if !cfg.safeToRetry {
                break
            }
        }

        if err := waitRetry(ctx, retryDelayForAttempt(attempt)); err != nil {
            return nil, err
        }
    }
    return nil, lastErr
}
```

Update callers: GET calls use `safeToRetry: true`. POST calls with an idempotency key use `safeToRetry: true`. POST calls without one use `safeToRetry: false` and `maxAttempts: 1`.

### Tests

```go
func TestRetryHTTP_POST_NetworkError_NotRetried(t *testing.T) {
    attempts := 0
    _, err := retryHTTPWithConfig(context.Background(), retryConfig{maxAttempts: 3, safeToRetry: false},
        func() (*http.Response, error) {
            attempts++
            return nil, errors.New("connection reset")
        })

    require.Error(t, err)
    require.Equal(t, 1, attempts, "non-idempotent POST must not be retried on network error")
}

func TestRetryHTTP_POST_WithIdempotencyKey_IsRetried(t *testing.T) {
    attempts := 0
    _, err := retryHTTPWithConfig(context.Background(), retryConfig{maxAttempts: 3, safeToRetry: true},
        func() (*http.Response, error) {
            attempts++
            if attempts < 3 {
                return nil, errors.New("network error")
            }
            return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
        })

    require.NoError(t, err)
    require.Equal(t, 3, attempts)
}

func TestRetryHTTP_GET_IsAlwaysRetried(t *testing.T) {
    attempts := 0
    resp, err := retryHTTPWithConfig(context.Background(), retryConfig{maxAttempts: 3, safeToRetry: true},
        func() (*http.Response, error) {
            attempts++
            if attempts < 2 {
                return nil, errors.New("transient error")
            }
            return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
        })

    require.NoError(t, err)
    require.NotNil(t, resp)
    require.Equal(t, 2, attempts)
}
```

### Acceptance criteria

- Non-idempotent calls (`safeToRetry: false`) make exactly one attempt regardless of `maxAttempts`
- Idempotent calls (`safeToRetry: true`) retry up to `maxAttempts` on network errors
- All existing POST callers in `pontes_payment.go` updated to use `safeToRetry: true` (because they send `Idempotency-Key`)
- All GET callers updated to use `safeToRetry: true`

---

## B-8 · `paymentRetryJitter` uses `math/rand` — predictable under load

**File:** `payment_retry.go`

### Root cause

```go
paymentRetryJitter = func() float64 {
    return (rand.Float64()*0.2 - 0.1)
}
```

While Go 1.20+ auto-seeds the global source, using the global `math/rand` source is shared across all goroutines and creates contention under high concurrency. More critically, it is not the right tool — `math/rand/v2` is available and provides a per-instance source with no lock contention and a better PRNG (PCG).

### Fix

```go
import "math/rand/v2"

// jitterSource is a package-level PCG source. It is safe for concurrent use
// and produces higher-quality randomness than the global math/rand source.
var jitterSource = rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0))
var jitterMu sync.Mutex

paymentRetryJitter = func() float64 {
    jitterMu.Lock()
    v := jitterSource.Float64()*0.2 - 0.1
    jitterMu.Unlock()
    return v
}
```

If targeting Go < 1.22, use `rand.New(rand.NewSource(time.Now().UnixNano()))` with a mutex instead.

### Tests

```go
func TestRetryJitter_AlwaysWithinBounds(t *testing.T) {
    for i := 0; i < 10_000; i++ {
        j := paymentRetryJitter()
        require.GreaterOrEqual(t, j, -0.1, "jitter must be >= -10%%")
        require.LessOrEqual(t, j, 0.1, "jitter must be <= +10%%")
    }
}

func TestRetryJitter_Distribution_NotAllSame(t *testing.T) {
    seen := make(map[float64]bool)
    for i := 0; i < 100; i++ {
        seen[paymentRetryJitter()] = true
    }
    require.Greater(t, len(seen), 50, "jitter must produce varied values")
}
```

### Acceptance criteria

- 10,000 jitter samples all fall within [-0.1, +0.1]
- No lock contention under `go test -race` with 50 concurrent goroutines calling `retryDelayForAttempt`
- `paymentRetryJitter` is not the global `math/rand` source

---

# HIGH ISSUES

---

## H-1 · No overall operation timeout

**Files:** All providers

### Root cause

Each retry attempt is bounded by the `http.Client.Timeout` (30s), but with 3 attempts and backoff, a single call can block for ~94 seconds. There is no outer deadline that caps the total duration of a payment operation — a hung upstream can tie up a goroutine for the entire duration.

### Fix

Add an outer `operationTimeout` to each provider, applied inside every public method.

```go
const (
    pontesOperationTimeout = 45 * time.Second
    modulrOperationTimeout = 45 * time.Second
    eurcOperationTimeout   = 45 * time.Second
)

func (p *PontesPaymentProvider) RegisterSettlementCtx(ctx context.Context, instruction *PaymentInstruction) (string, error) {
    ctx, cancel := context.WithTimeout(ctx, pontesOperationTimeout)
    defer cancel()
    // ... rest of implementation
}
```

### Tests

```go
func TestPontes_RegisterSettlement_OverallTimeout_IsRespected(t *testing.T) {
    p := newTestPontesProvider(t, NewMemoryPaymentStore())
    p.client = httpClientReturning(t, func(req *http.Request) (*http.Response, error) {
        time.Sleep(10 * time.Second) // simulate slow upstream
        return nil, errors.New("timeout")
    })

    ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
    defer cancel()

    start := time.Now()
    _, err := p.RegisterSettlementCtx(ctx, &PaymentInstruction{Reference: "ref", Currency: "EUR", TotalAmount: 100})
    elapsed := time.Since(start)

    require.Error(t, err)
    require.Less(t, elapsed, 1*time.Second, "operation must abort before 1s when ctx deadline is 200ms")
}
```

### Acceptance criteria

- Any provider operation cancelled via context returns within 100ms of the cancellation
- No goroutine leak detectable after context cancellation (verified with `goleak`)
- Operation timeout is configurable at construction time, not hardcoded

---

## H-2 · Unknown reference silently returns `PaymentStatusPending`

**File:** `pontes_payment.go`

### Root cause

```go
transactionID, ok := p.pending[reference]
if !ok {
    return PaymentStatusPending, nil  // silent — indistinguishable from genuine pending
}
```

There is no way for the caller to distinguish between "registered but waiting for T2" and "never registered / data was lost". This causes indefinite polling for settlements that will never arrive.

### Fix

Already addressed in the B-6 fix above: return `PaymentStatusUnknown` with an explicit error for unknown references. See the B-6 fix for the full implementation.

### Tests

```go
func TestPontes_GetPaymentStatus_UnknownReference_NotSilent(t *testing.T) {
    p := newTestPontesProvider(t, NewMemoryPaymentStore())

    status, err := p.GetPaymentStatus(context.Background(), "unknown-ref")
    require.Error(t, err, "unknown reference must return an error, not a silent pending")
    require.Equal(t, PaymentStatusUnknown, status)
    require.Contains(t, err.Error(), "unknown-ref")
}
```

### Acceptance criteria

- `GetPaymentStatus` for an unknown reference returns `PaymentStatusUnknown` and a non-nil error
- The error message contains the reference for traceability
- Callers that previously treated `PaymentStatusPending` as "safe to wait" must be updated to handle `PaymentStatusUnknown` as a fatal condition

---

## H-3 · `sleepWithContext` declared but never used

**File:** `payment_retry.go`

### Root cause

```go
var paymentRetrySleep = sleepWithContext  // assigned
// ...
func sleepWithContext(...) error { ... }  // defined
```

`paymentRetrySleep` is never called in the implementation — `waitRetry` is used directly. This is dead code. It was likely intended as a test seam so tests could inject a controlled sleep. The seam is disconnected.

### Fix

Wire `paymentRetrySleep` into `waitRetry` so the seam is actually functional, enabling tests to zero out sleep durations:

```go
// waitRetry is the canonical internal sleep. Calls paymentRetrySleep so tests
// can override it to eliminate real delays.
func waitRetry(ctx context.Context, d time.Duration) error {
    return paymentRetrySleep(ctx, d)
}
```

Remove the separate `sleepWithContext` function — it is now identical to `waitRetry`. The `paymentRetrySleep` var is now the seam.

### Tests

```go
func TestRetryHTTP_SleepCanBeOverridden_ForFastTests(t *testing.T) {
    original := paymentRetrySleep
    defer func() { paymentRetrySleep = original }()

    // Override: zero-duration sleep for test speed
    paymentRetrySleep = func(ctx context.Context, d time.Duration) error {
        return ctx.Err() // still respect cancellation
    }

    attempts := 0
    _, _ = retryHTTPWithConfig(context.Background(), retryConfig{maxAttempts: 3, safeToRetry: true},
        func() (*http.Response, error) {
            attempts++
            return nil, errors.New("fail")
        })

    require.Equal(t, 3, attempts)
}
```

### Acceptance criteria

- `paymentRetrySleep` is the sole sleep function; `waitRetry` delegates to it
- Tests can override `paymentRetrySleep` to eliminate real backoff delays
- `go vet ./...` reports no unused variable warnings

---

## H-4 · Goroutine leak in `EURCPaymentProvider.CreateVirtualAccount` on error

**File:** `eurc_payment.go`

### Root cause

When `retryHTTP` returns an error, execution returns early before `close(req.done)` is called. Any goroutine waiting on `<-req.done` for the same `walletID` will block forever:

```go
resp, err := retryHTTP(context.Background(), 3, ...)
if err != nil {
    return "", fmt.Errorf("eurc: wallet creation request failed: %w", err)
    // ← close(req.done) is NEVER reached
}
```

Same leak exists if `resp.StatusCode` is not 2xx — that return also skips the cleanup block.

### Fix

Move cleanup to a `defer` that runs unconditionally:

```go
func (e *EURCPaymentProvider) CreateVirtualAccount(ctx context.Context, walletID string) (string, error) {
    e.mu.Lock()
    if addr, ok := e.accounts[walletID]; ok {
        e.mu.Unlock()
        return addr, nil
    }
    if existing, ok := e.pendingAccount[walletID]; ok {
        e.mu.Unlock()
        <-existing.done
        return existing.addr, existing.err
    }
    req := &eurcAccountRequest{done: make(chan struct{})}
    e.pendingAccount[walletID] = req
    e.mu.Unlock()

    // addr and err are named so the defer closure captures them.
    var addr string
    var err error

    defer func() {
        e.mu.Lock()
        req.addr = addr
        req.err = err
        close(req.done)
        delete(e.pendingAccount, walletID)
        if err == nil && addr != "" {
            if _, already := e.accounts[walletID]; !already {
                e.accounts[walletID] = addr
            }
        }
        e.mu.Unlock()
    }()

    // ... build idempotencyKey, marshal payload ...

    var resp *http.Response
    resp, err = retryHTTP(ctx, 3, func() (*http.Response, error) {
        r, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/wallets", bytes.NewReader(body))
        if reqErr != nil {
            return nil, fmt.Errorf("eurc: failed to build wallet request: %w", reqErr)
        }
        r.Header.Set("Content-Type", "application/json")
        r.Header.Set("Authorization", "Bearer "+e.apiKey)
        return e.client.Do(r)
    })
    if err != nil {
        err = fmt.Errorf("eurc: wallet creation request failed: %w", err)
        return "", err  // defer runs, closes req.done, propagates err
    }
    defer resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
        err = fmt.Errorf("eurc: wallet creation returned HTTP %d: %s", resp.StatusCode, string(b))
        return "", err  // defer runs
    }

    var result circleWalletResponse
    if decErr := json.NewDecoder(resp.Body).Decode(&result); decErr != nil {
        err = fmt.Errorf("eurc: failed to decode wallet response: %w", decErr)
        return "", err
    }
    addr = result.Data.Wallet.Address
    if addr == "" {
        err = fmt.Errorf("eurc: wallet creation returned no address")
        return "", err
    }

    return addr, nil  // defer runs with addr set, err nil
}
```

### Tests

```go
func TestEURC_CreateVirtualAccount_APIError_DoesNotLeakGoroutine(t *testing.T) {
    e, _ := NewEURCPaymentProvider("key", "https://api.circle.com/v1", "ws", "secret")
    e.client = httpClientReturning(t, func(req *http.Request) (*http.Response, error) {
        return nil, errors.New("connection refused")
    })

    var wg sync.WaitGroup
    const concurrency = 10
    wg.Add(concurrency)

    results := make([]error, concurrency)
    for i := 0; i < concurrency; i++ {
        i := i
        go func() {
            defer wg.Done()
            _, results[i] = e.CreateVirtualAccount(context.Background(), "wallet-A")
        }()
    }

    done := make(chan struct{})
    go func() {
        wg.Wait()
        close(done)
    }()

    select {
    case <-done:
        // All goroutines returned — no leak
    case <-time.After(5 * time.Second):
        t.Fatal("goroutine leak: concurrent CreateVirtualAccount calls did not all return within 5s")
    }
}

func TestEURC_CreateVirtualAccount_ConcurrentCalls_OnlyOneAPIRequest(t *testing.T) {
    callCount := int64(0)
    e, _ := NewEURCPaymentProvider("key", "https://api.circle.com/v1", "ws", "secret")
    e.client = httpClientReturning(t, func(req *http.Request) (*http.Response, error) {
        atomic.AddInt64(&callCount, 1)
        time.Sleep(50 * time.Millisecond) // simulate latency
        return jsonResponse(200, circleWalletResponse{...}), nil
    })

    var wg sync.WaitGroup
    for i := 0; i < 20; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            e.CreateVirtualAccount(context.Background(), "wallet-shared")
        }()
    }
    wg.Wait()

    require.Equal(t, int64(1), atomic.LoadInt64(&callCount), "exactly one API call for concurrent same-walletID requests")
}
```

### Acceptance criteria

- `go test -race ./...` reports no data races in `CreateVirtualAccount`
- `goleak.VerifyNone(t)` passes after any error path through `CreateVirtualAccount`
- 20 concurrent calls for the same `walletID` result in exactly one API request

---

## H-5 · Travel Rule not enforced at payment layer

**File:** `payment.go`, `pontes_payment.go`

### Root cause

The `TravelRulePayload` field exists but is populated only in `finalizeBlock` with no enforcement in the payment layer. If `finalizeBlock` forgets to attach it (bug, refactor, new code path), a high-value transfer is transmitted without the legally required FATF R16 / EU TFR data. This is a regulatory violation under Regulation 2023/1113, in force from 30 December 2024.

### Fix

Enforce at `RegisterSettlementCtx` and any other payment entry point that accepts a `PaymentInstruction`. Also validate that required fields within `TravelRulePayload` are non-empty.

```go
// validateTravelRule returns an error if Travel Rule requirements are not met.
func validateTravelRule(instruction *PaymentInstruction) error {
    if instruction.TotalAmount < TravelRuleThresholdEUR {
        return nil // below threshold — not required
    }
    if instruction.TravelRule == nil {
        return fmt.Errorf("payment: TravelRulePayload is required for %s %.2f >= threshold %.2f EUR (EU TFR 2023/1113)",
            instruction.Currency, instruction.TotalAmount, TravelRuleThresholdEUR)
    }
    tr := instruction.TravelRule
    if tr.OriginatorName == "" {
        return fmt.Errorf("payment: TravelRule.OriginatorName must not be empty")
    }
    if tr.OriginatorAccount == "" {
        return fmt.Errorf("payment: TravelRule.OriginatorAccount must not be empty")
    }
    if tr.BeneficiaryName == "" {
        return fmt.Errorf("payment: TravelRule.BeneficiaryName must not be empty")
    }
    return nil
}
```

Call `validateTravelRule(instruction)` at the top of `RegisterSettlementCtx` (and equivalent entry points for Modulr and EURC).

### Tests

```go
func TestValidateTravelRule_AboveThreshold_MissingPayload_ReturnsError(t *testing.T) {
    instr := &PaymentInstruction{
        TotalAmount: 1500.00,
        Currency:    "EUR",
        TravelRule:  nil,
    }
    err := validateTravelRule(instr)
    require.Error(t, err)
    require.Contains(t, err.Error(), "TravelRulePayload is required")
}

func TestValidateTravelRule_AboveThreshold_ValidPayload_NoError(t *testing.T) {
    instr := &PaymentInstruction{
        TotalAmount: 1500.00,
        Currency:    "EUR",
        TravelRule: &TravelRulePayload{
            OriginatorName:    "Alice Smith",
            OriginatorAccount: "GB29NWBK60161331926819",
            BeneficiaryName:   "Bob Jones",
        },
    }
    require.NoError(t, validateTravelRule(instr))
}

func TestValidateTravelRule_BelowThreshold_NoPayload_NoError(t *testing.T) {
    instr := &PaymentInstruction{
        TotalAmount: 999.99,
        Currency:    "EUR",
        TravelRule:  nil,
    }
    require.NoError(t, validateTravelRule(instr))
}

func TestPontes_RegisterSettlement_AboveThreshold_NoTravelRule_ReturnsError(t *testing.T) {
    p := newTestPontesProvider(t, NewMemoryPaymentStore())
    instr := &PaymentInstruction{
        Reference:   "ref-001",
        TotalAmount: 5000.00,
        Currency:    "EUR",
        TravelRule:  nil,
    }
    _, err := p.RegisterSettlementCtx(context.Background(), instr)
    require.Error(t, err)
    require.Contains(t, err.Error(), "TravelRulePayload is required")
}
```

### Acceptance criteria

- `RegisterSettlementCtx` for `TotalAmount >= 1000 EUR` with `TravelRule == nil` returns an error before any API call is made
- `validateTravelRule` validates required fields within the payload, not just nil-ness
- Below-threshold instructions are unaffected
- Travel Rule validation is applied consistently in all three provider `Register*` methods

---

# MEDIUM ISSUES

---

## M-1 · `ContextualPaymentProvider` incomplete and inconsistently applied

**File:** `payment.go`

### Root cause

`ContextualPaymentProvider` embeds `PaymentProvider` (context-free) and adds `-Ctx` suffix methods — a halfway measure that results in two interface tiers and dual implementations. Once B-2 is fixed (unified context-aware `PaymentProvider`), `ContextualPaymentProvider` is entirely redundant.

### Fix

Delete `ContextualPaymentProvider`. The unified `PaymentProvider` from B-2 replaces it. Remove all `-Ctx` suffix method aliases from all providers.

### Acceptance criteria

- `ContextualPaymentProvider` type does not exist in the codebase
- `GetPaymentStatusCtx` alias on `ModulrPaymentProvider` removed
- `go grep -r "ContextualPaymentProvider\|GetPaymentStatusCtx\|CreateVirtualAccountCtx" .` returns no results

---

## M-2 · No structured logging or tracing

**Files:** All

### Fix

Inject `*slog.Logger` into each provider at construction. Log at INFO on every significant state transition, WARN on retries, and ERROR on final failure. Add a `correlationID` field derived from context when available.

```go
type PontesPaymentProvider struct {
    // ...
    log *slog.Logger
}

func NewPontesPaymentProvider(..., log *slog.Logger) (*PontesPaymentProvider, error) {
    if log == nil {
        log = slog.Default()
    }
    // ...
}

// Inside RegisterSettlementCtx:
p.log.InfoContext(ctx, "pontes: registering settlement",
    slog.String("reference", instruction.Reference),
    slog.Float64("amount", instruction.TotalAmount),
    slog.String("currency", instruction.Currency),
)

// On success:
p.log.InfoContext(ctx, "pontes: settlement registered",
    slog.String("reference", instruction.Reference),
    slog.String("transactionID", result.TransactionID),
)

// On retry (inside retryHTTP):
p.log.WarnContext(ctx, "pontes: retrying settlement registration",
    slog.Int("attempt", attempt+1),
    slog.String("error", err.Error()),
)
```

### Tests

```go
func TestPontes_RegisterSettlement_LogsOnSuccess(t *testing.T) {
    var buf bytes.Buffer
    log := slog.New(slog.NewJSONHandler(&buf, nil))
    p := newTestPontesProviderWithLogger(t, NewMemoryPaymentStore(), log)
    // ... trigger registration ...

    require.Contains(t, buf.String(), "settlement registered")
    require.Contains(t, buf.String(), "ref-001")
}
```

### Acceptance criteria

- Every provider method logs at INFO on success with reference and amount
- Every retry logs at WARN with attempt number and error
- Every final failure logs at ERROR with full error chain
- Log output is valid JSON (`slog.NewJSONHandler`) for ingestion by Datadog/CloudWatch
- No credentials (API key, HMAC secret) appear in any log line

---

## M-3 · No circuit breaker on external payment APIs

**Files:** All providers

### Fix

Wrap each provider's HTTP transport with a per-provider circuit breaker using `github.com/sony/gobreaker`.

```go
import "github.com/sony/gobreaker"

type PontesPaymentProvider struct {
    // ...
    breaker *gobreaker.CircuitBreaker
}

func NewPontesPaymentProvider(...) (*PontesPaymentProvider, error) {
    // ...
    breaker := gobreaker.NewCircuitBreaker(gobreaker.Settings{
        Name:        "pontes",
        MaxRequests: 1,          // requests allowed in half-open state
        Interval:    60 * time.Second,
        Timeout:     30 * time.Second,
        ReadyToTrip: func(counts gobreaker.Counts) bool {
            return counts.ConsecutiveFailures >= 5
        },
        OnStateChange: func(name string, from, to gobreaker.State) {
            slog.Warn("pontes: circuit breaker state change",
                slog.String("from", from.String()),
                slog.String("to", to.String()),
            )
        },
    })
    // ...
}

// Wrap the HTTP call:
_, err = p.breaker.Execute(func() (any, error) {
    return retryHTTPWithConfig(ctx, cfg, fn)
})
```

### Tests

```go
func TestPontes_CircuitBreaker_OpensAfterConsecutiveFailures(t *testing.T) {
    p := newTestPontesProvider(t, NewMemoryPaymentStore())
    p.client = httpClientReturning(t, func(req *http.Request) (*http.Response, error) {
        return nil, errors.New("server error")
    })

    for i := 0; i < 5; i++ {
        _, _ = p.RegisterSettlementCtx(context.Background(),
            &PaymentInstruction{Reference: fmt.Sprintf("ref-%d", i), Currency: "EUR", TotalAmount: 100})
    }

    // Circuit should now be open — next call must fail fast
    start := time.Now()
    _, err := p.RegisterSettlementCtx(context.Background(),
        &PaymentInstruction{Reference: "ref-open", Currency: "EUR", TotalAmount: 100})
    elapsed := time.Since(start)

    require.Error(t, err)
    require.Less(t, elapsed, 50*time.Millisecond, "open circuit must fail fast without hitting the network")
}
```

### Acceptance criteria

- Circuit opens after 5 consecutive failures
- Open circuit returns immediately with a circuit-breaker error (< 50ms)
- Circuit transitions to half-open after 30 seconds and allows one probe request
- State changes are logged at WARN
- Each provider has its own independent circuit breaker

---

## M-4 · Modulr uses HMAC-SHA1 — document the constraint

**File:** `modulr_payment.go`

### Fix

The SHA-1 usage is spec-mandated. Add a prominent build-time comment and a `//nolint:gosec` annotation to prevent automated linters from flagging it as a vulnerability:

```go
// addAuthHeaders attaches the Modulr HMAC-SHA1 authentication headers to req.
//
// ⚠️  SHA-1 NOTICE: The Modulr HTTP Signature specification requires HMAC-SHA1.
// This is not a choice — using SHA-256 will cause all requests to be rejected
// with HTTP 401. SHA-1 is used only for the request signature; it is not used
// for any data confidentiality or certificate validation purpose.
// Reference: https://modulr.readme.io/docs/authentication
// Track: https://modulr.readme.io/changelog — upgrade if Modulr adds SHA-256 support.
func (m *ModulrPaymentProvider) addAuthHeaders(req *http.Request) error {
    // ...
    h := hmac.New(sha1.New, []byte(m.apiSecret)) //nolint:gosec // SHA-1 required by Modulr spec
```

### Acceptance criteria

- `gosec` and `staticcheck` run without flagging this as an unacknowledged vulnerability
- Comment references the Modulr documentation URL
- A TODO/track note exists for migration if Modulr adds SHA-256

---

## M-5 · Backoff table is not truly exponential beyond attempt 2

**File:** `payment_retry.go`

### Root cause

```go
var paymentRetryBackoffs = []time.Duration{0, 500 * time.Millisecond, 2 * time.Second}
```

Attempts 3 onwards all use 2 seconds flat. At 10 attempts this means attempts 3–9 hammering a struggling upstream every ~2 seconds — not exponential backoff.

### Fix

Replace the table with a computed exponential formula with a cap:

```go
const (
    retryBaseDelay = 500 * time.Millisecond
    retryMaxDelay  = 30 * time.Second
)

func retryDelayForAttempt(attempt int) time.Duration {
    if attempt <= 0 {
        return 0 // first retry: immediate
    }
    // Exponential: 500ms * 2^(attempt-1), capped at 30s
    delay := retryBaseDelay * (1 << uint(attempt-1))
    if delay > retryMaxDelay || delay < 0 { // overflow guard
        delay = retryMaxDelay
    }
    j := paymentRetryJitter()
    if j < -0.1 { j = -0.1 }
    if j > 0.1  { j = 0.1 }
    return time.Duration(float64(delay) * (1 + j))
}
```

This produces: attempt 0 → 0ms, attempt 1 → ~500ms, attempt 2 → ~1s, attempt 3 → ~2s, attempt 4 → ~4s, attempt 5 → ~8s, attempt 6+ → 30s (capped).

### Tests

```go
func TestRetryDelayForAttempt_Exponential(t *testing.T) {
    paymentRetryJitter = func() float64 { return 0 } // neutralise jitter

    require.Equal(t, time.Duration(0), retryDelayForAttempt(0))
    require.Equal(t, 500*time.Millisecond, retryDelayForAttempt(1))
    require.Equal(t, 1*time.Second, retryDelayForAttempt(2))
    require.Equal(t, 2*time.Second, retryDelayForAttempt(3))
    require.Equal(t, 4*time.Second, retryDelayForAttempt(4))
    require.Equal(t, 30*time.Second, retryDelayForAttempt(10)) // capped
    require.Equal(t, 30*time.Second, retryDelayForAttempt(100)) // no overflow
}
```

### Acceptance criteria

- Each attempt delay doubles the previous (before jitter)
- Delay never exceeds `retryMaxDelay` regardless of attempt count
- Negative input to `retryDelayForAttempt` returns 0 (no panic)
- Integer overflow is guarded (shift beyond 63 bits returns cap, not negative)

---

## M-6 · `PontesPaymentProvider` `baseURL` not validated at construction

**File:** `pontes_payment.go`

### Fix

```go
func NewPontesPaymentProvider(apiKey, baseURL, dltOperator, hmacSecret string, store PaymentStore) (*PontesPaymentProvider, error) {
    if apiKey == "" {
        return nil, fmt.Errorf("pontes: apiKey must not be empty")
    }
    if baseURL == "" {
        baseURL = pontesPilotBaseURL
    }
    // Validate it is a parseable URL
    if _, err := url.ParseRequestURI(baseURL); err != nil {
        return nil, fmt.Errorf("pontes: baseURL %q is not a valid URL: %w", baseURL, err)
    }
    // ...
}
```

### Tests

```go
func TestNewPontesPaymentProvider_InvalidBaseURL_ReturnsError(t *testing.T) {
    _, err := NewPontesPaymentProvider("key", "not a url", "op", "secret", NewMemoryPaymentStore())
    require.Error(t, err)
    require.Contains(t, err.Error(), "not a valid URL")
}

func TestNewPontesPaymentProvider_EmptyBaseURL_DefaultsToPilot(t *testing.T) {
    p, err := NewPontesPaymentProvider("key", "", "op", "secret", NewMemoryPaymentStore())
    require.NoError(t, err)
    require.Equal(t, pontesPilotBaseURL, p.baseURL)
}
```

### Acceptance criteria

- Invalid URL at construction returns an error with the offending URL quoted
- Empty URL defaults to `pontesPilotBaseURL` without error
- URL validation uses `url.ParseRequestURI` (requires scheme)

---

## M-7 · No reconciliation mechanism

**Files:** All providers

### Fix

Add a `ReconcileLoop` method to each provider that periodically polls `GetPaymentStatus` for all references in `pending` older than a configurable threshold.

```go
// StartReconciliation launches a background goroutine that polls for stale
// pending settlements and updates their status. It stops when ctx is cancelled.
// staleness is how long a pending settlement can remain unconfirmed before
// being polled (e.g. 5 minutes).
func (p *PontesPaymentProvider) StartReconciliation(ctx context.Context, interval, staleness time.Duration) {
    go func() {
        ticker := time.NewTicker(interval)
        defer ticker.Stop()
        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                p.reconcileOnce(ctx, staleness)
            }
        }
    }()
}

func (p *PontesPaymentProvider) reconcileOnce(ctx context.Context, staleness time.Duration) {
    cutoff := time.Now().Add(-staleness)
    pending, err := p.store.PendingOlderThan(ctx, cutoff)
    if err != nil {
        p.log.ErrorContext(ctx, "pontes: reconciliation store query failed", slog.String("error", err.Error()))
        return
    }
    for _, s := range pending {
        status, err := p.GetPaymentStatus(ctx, s.Reference)
        if err != nil {
            p.log.WarnContext(ctx, "pontes: reconciliation status poll failed",
                slog.String("reference", s.Reference),
                slog.String("error", err.Error()),
            )
            continue
        }
        p.log.InfoContext(ctx, "pontes: reconciliation updated status",
            slog.String("reference", s.Reference),
            slog.String("status", string(status)),
        )
    }
}
```

### Tests

```go
func TestPontes_ReconcileOnce_ConfirmsStaleSettlement(t *testing.T) {
    ctx := context.Background()
    store := NewMemoryPaymentStore()

    // Register a settlement that is older than the staleness window
    require.NoError(t, store.SetPending(ctx, "ref-001", "txn-001", 1000.0, "EUR"))

    p := newTestPontesProvider(t, store)
    p.client = httpClientReturning(t, func(req *http.Request) (*http.Response, error) {
        return jsonResponse(200, map[string]string{"status": "SETTLED"}), nil
    })

    p.reconcileOnce(ctx, -1*time.Second) // staleness = -1s means everything is stale

    status, found, _ := store.GetStatus(ctx, "ref-001")
    require.True(t, found)
    require.Equal(t, PaymentStatusConfirmed, status)
}
```

### Acceptance criteria

- `StartReconciliation` launches a goroutine that stops cleanly when context is cancelled
- `reconcileOnce` polls `GetPaymentStatus` for all references older than staleness threshold
- Confirmed or failed status from the API is persisted to the store
- No panic on empty pending set
- `go test -race` passes

---

## M-8 · `EURCPaymentProvider.CreateVirtualAccount` ignores caller context

**File:** `eurc_payment.go`

### Root cause

```go
resp, err := retryHTTP(context.Background(), 3, func() (*http.Response, error) {
    r, err := http.NewRequest(...)  // also no context
```

Both `retryHTTP` and `http.NewRequest` use `context.Background()`, so a cancelled caller context is ignored for the entire retry sequence.

### Fix

Already addressed in the H-4 fix above (the updated `CreateVirtualAccount` now accepts `ctx context.Context` per B-2, and passes it to both `retryHTTP` and `http.NewRequestWithContext`).

### Tests

```go
func TestEURC_CreateVirtualAccount_CancelledContext_NoRequest(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    cancel()

    called := false
    e, _ := NewEURCPaymentProvider("key", "https://api.circle.com/v1", "ws-id", "secret")
    e.client = httpClientReturning(t, func(req *http.Request) (*http.Response, error) {
        called = true
        return nil, errors.New("should not run")
    })

    _, err := e.CreateVirtualAccount(ctx, "wallet-id")
    require.ErrorIs(t, err, context.Canceled)
    require.False(t, called)
}
```

### Acceptance criteria

- Pre-cancelled context prevents any HTTP request from being made
- Context deadline propagates to all retry attempts
- `go test -race` passes

---

# LOW ISSUES

---

## L-1 · First retry delay is zero — two attempts fire back-to-back

**File:** `payment_retry.go`

### Fix

Already resolved by M-5: the new exponential formula produces 0 for attempt 0 (the initial call delay — correct, there is no delay before the first attempt) and 500ms for attempt 1 (the first *retry* — now has a delay). The `waitRetry` 1ns substitution for zero is no longer hit in the normal path.

### Acceptance criteria

- `retryDelayForAttempt(0)` returns 0 (no delay before first attempt — correct)
- `retryDelayForAttempt(1)` returns ~500ms (first retry has breathing room)
- `waitRetry` with a 0-duration input is covered by a test confirming it does not block indefinitely

---

## L-2 · `pontesStatusToPaymentStatus` silently maps unknown statuses to Pending

**File:** `pontes_payment.go`

### Fix

```go
func pontesStatusToPaymentStatus(s string) (PaymentStatus, bool) {
    switch s {
    case "SETTLED", "CONFIRMED":
        return PaymentStatusConfirmed, true
    case "FAILED", "REJECTED":
        return PaymentStatusFailed, true
    case "EXPIRED":
        return PaymentStatusExpired, true
    case "PENDING", "PROCESSING", "SUBMITTED":
        return PaymentStatusPending, true
    default:
        return PaymentStatusUnknown, false // unknown status — caller should log it
    }
}

// At the call site:
status, known := pontesStatusToPaymentStatus(result.Status)
if !known {
    p.log.WarnContext(ctx, "pontes: unrecognised status string from API",
        slog.String("raw_status", result.Status),
        slog.String("reference", reference),
    )
    status = PaymentStatusUnknown
}
```

### Tests

```go
func TestPontesStatusMapping_UnknownStatus_ReturnsUnknown(t *testing.T) {
    status, known := pontesStatusToPaymentStatus("SOME_NEW_STATUS")
    require.False(t, known)
    require.Equal(t, PaymentStatusUnknown, status)
}

func TestPontesStatusMapping_KnownStatuses(t *testing.T) {
    cases := []struct{ in string; want PaymentStatus }{
        {"SETTLED",    PaymentStatusConfirmed},
        {"CONFIRMED",  PaymentStatusConfirmed},
        {"FAILED",     PaymentStatusFailed},
        {"REJECTED",   PaymentStatusFailed},
        {"EXPIRED",    PaymentStatusExpired},
        {"PENDING",    PaymentStatusPending},
    }
    for _, c := range cases {
        t.Run(c.in, func(t *testing.T) {
            status, known := pontesStatusToPaymentStatus(c.in)
            require.True(t, known)
            require.Equal(t, c.want, status)
        })
    }
}
```

### Acceptance criteria

- Unknown status strings return `PaymentStatusUnknown` and `known=false`
- Unknown statuses are logged at WARN with the raw string included
- All currently known Pontes statuses are explicitly mapped (no implicit default)

---

## L-3 · `modulrStatusToPaymentStatus` same issue as L-2

**File:** `modulr_payment.go`

### Fix

Apply identical change as L-2 to `modulrStatusToPaymentStatus`. Return `(PaymentStatus, bool)` with `false` for unrecognised statuses.

### Acceptance criteria

- Identical to L-2 acceptance criteria, applied to Modulr status strings

---

## L-4 · Unbounded `io.ReadAll` on response bodies

**Files:** All providers

### Root cause

```go
respBody, _ := io.ReadAll(resp.Body)
```

No limit on error response body reads. A proxy returning a multi-megabyte HTML error page causes unbounded memory allocation.

### Fix

```go
const maxErrorBodyBytes = 64 * 1024 // 64 KB is sufficient for any API error message

b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
```

Apply to every `io.ReadAll(resp.Body)` call in all three provider files.

### Tests

```go
func TestPontes_ErrorResponse_LargeBody_DoesNotOOM(t *testing.T) {
    p := newTestPontesProvider(t, NewMemoryPaymentStore())
    largeBody := bytes.Repeat([]byte("x"), 10*1024*1024) // 10 MB
    p.client = httpClientReturning(t, func(req *http.Request) (*http.Response, error) {
        return &http.Response{
            StatusCode: 500,
            Body:       io.NopCloser(bytes.NewReader(largeBody)),
        }, nil
    })

    _, err := p.RegisterSettlementCtx(context.Background(),
        &PaymentInstruction{Reference: "ref", Currency: "EUR", TotalAmount: 100})
    require.Error(t, err)
    // Test passes if it completes without OOM — no assertion on memory, just liveness.
}
```

### Acceptance criteria

- All `io.ReadAll(resp.Body)` calls for error bodies are wrapped with `io.LimitReader(resp.Body, 64*1024)`
- Error messages still include the (truncated) body content for debuggability
- `go vet` and linter report no unbounded reads

---

## L-5 · `ConfirmPayment` on Modulr always errors — invisible footgun

**File:** `modulr_payment.go`

### Root cause

```go
func (m *ModulrPaymentProvider) ConfirmPayment(_ context.Context, _ string, _ float64, _ string) error {
    return fmt.Errorf("modulr: ConfirmPayment must not be called directly...")
}
```

Any code iterating over `[]PaymentProvider` and calling `ConfirmPayment` will silently fail for Modulr. The error is only visible if the caller checks it — and in a webhook flow, that check is often missing.

### Fix

Introduce a `DirectlyConfirmable` marker interface. Code that calls `ConfirmPayment` must type-assert against it first. Remove `ConfirmPayment` from `PaymentProvider` for webhook-only providers.

```go
// DirectlyConfirmable is implemented by providers where ConfirmPayment can be
// called programmatically (e.g. mock providers, EURC, Pontes via webhook handler).
// Providers that only accept confirmations via their own webhook infrastructure
// (Modulr) do NOT implement this interface.
type DirectlyConfirmable interface {
    ConfirmPayment(ctx context.Context, reference string, amount float64, currency string) error
}
```

Remove `ConfirmPayment` from `PaymentProvider`. `ModulrPaymentProvider` no longer implements it. `PontesPaymentProvider` and `EURCPaymentProvider` implement `DirectlyConfirmable`.

Callers (webhook handlers) use:

```go
if dc, ok := provider.(DirectlyConfirmable); ok {
    return dc.ConfirmPayment(ctx, reference, amount, currency)
}
return fmt.Errorf("provider does not support direct payment confirmation")
```

### Tests

```go
var _ DirectlyConfirmable = (*PontesPaymentProvider)(nil)
var _ DirectlyConfirmable = (*EURCPaymentProvider)(nil)

func TestModulr_DoesNotImplementDirectlyConfirmable(t *testing.T) {
    var m *ModulrPaymentProvider
    _, ok := any(m).(DirectlyConfirmable)
    require.False(t, ok, "ModulrPaymentProvider must not implement DirectlyConfirmable")
}
```

### Acceptance criteria

- `ModulrPaymentProvider` does not implement `DirectlyConfirmable`
- `PontesPaymentProvider` and `EURCPaymentProvider` implement `DirectlyConfirmable`
- No code path calls `ConfirmPayment` on a `PaymentProvider` interface without a type assertion
- Compile-time checks `var _ DirectlyConfirmable = (*XProvider)(nil)` pass for EURC and Pontes

---

## L-6 · EURC idempotency key truncation is subtly risky

**File:** `eurc_payment.go`

### Root cause

```go
idempotencyKey = "gh-" + hex.EncodeToString(h[:])[:33]
```

Hex-encoding SHA-256 produces 64 characters. Taking 33 hex characters = 16.5 bytes = 132 bits of entropy. While the collision probability is negligible in practice, truncating a hex string mid-byte index is semantically confusing and hard to audit.

### Fix

Use base64url encoding of the full 32-byte hash, truncated to a clean byte boundary that fits within Circle's 36-character limit:

```go
// Circle's idempotency key limit is 36 characters.
// "gh-" is 3 chars; we have 33 chars remaining.
// base64url of 24 bytes = 32 chars (no padding). Total: 3 + 32 = 35 chars.
idempotencyKey := "gh-" + walletID
if len(idempotencyKey) > 36 {
    h := sha256.Sum256([]byte(walletID))
    // Take first 24 bytes → 32 base64url chars. No padding needed.
    idempotencyKey = "gh-" + base64.RawURLEncoding.EncodeToString(h[:24])
}
// len("gh-" + 32 chars) == 35, always within Circle's 36-char limit.
```

### Tests

```go
func TestEURC_IdempotencyKey_AlwaysWithinLimit(t *testing.T) {
    cases := []string{
        "short",
        strings.Repeat("x", 33),  // exactly fills 36 with "gh-" prefix
        strings.Repeat("y", 100), // long wallet ID
        strings.Repeat("z", 256), // very long
    }
    for _, walletID := range cases {
        key := buildEURCIdempotencyKey(walletID) // extract key logic to testable func
        require.LessOrEqual(t, len(key), 36, "idempotency key must be <= 36 chars for walletID len=%d", len(walletID))
        require.Contains(t, key, "gh-")
    }
}

func TestEURC_IdempotencyKey_DifferentWalletIDs_DifferentKeys(t *testing.T) {
    k1 := buildEURCIdempotencyKey(strings.Repeat("a", 100))
    k2 := buildEURCIdempotencyKey(strings.Repeat("b", 100))
    require.NotEqual(t, k1, k2, "distinct wallet IDs must produce distinct idempotency keys")
}
```

### Acceptance criteria

- `buildEURCIdempotencyKey` (extracted function) for any input produces a key ≤ 36 characters
- Keys for distinct wallet IDs are distinct (no hash collision at this length is practically guaranteed)
- Key uses only URL-safe characters (base64url alphabet: `A-Z`, `a-z`, `0-9`, `-`, `_`)
- `len("gh-") + 32 = 35` for any wallet ID longer than 33 characters

---

# APPENDIX: Test Helper Utilities

The following helpers are referenced throughout the test sections above. Add them to `payment_test_helpers_test.go`:

```go
package gonetwork

import (
    "encoding/json"
    "io"
    "net/http"
    "testing"
)

type mockTransport struct {
    roundTrip func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    return m.roundTrip(req)
}

func httpClientReturning(t *testing.T, fn func(*http.Request) (*http.Response, error)) *http.Client {
    t.Helper()
    return &http.Client{Transport: &mockTransport{roundTrip: fn}}
}

func jsonResponse(statusCode int, body any) *http.Response {
    b, _ := json.Marshal(body)
    return &http.Response{
        StatusCode: statusCode,
        Body:       io.NopCloser(bytes.NewReader(b)),
        Header:     make(http.Header),
    }
}

func newTestPontesProvider(t *testing.T, store PaymentStore) *PontesPaymentProvider {
    t.Helper()
    p, err := NewPontesPaymentProvider("test-key", "http://test.pontes", "op-id", "test-hmac-secret-32chars", store)
    require.NoError(t, err)
    return p
}

// failingStore is a PaymentStore that returns errors for testing store failure paths.
type failingStore struct {
    *MemoryPaymentStore
    setErr error
}

func (f *failingStore) SetPending(ctx context.Context, ref, txn string, amt float64, cur string) error {
    if f.setErr != nil {
        return f.setErr
    }
    return f.MemoryPaymentStore.SetPending(ctx, ref, txn, amt, cur)
}
```

---

# APPENDIX: Fix Sequencing

Implement fixes in this order to avoid rework:

```
Phase 1 — Compile correctness (1–2 days)
  B-2  Interface unification
  M-1  Remove ContextualPaymentProvider
  L-5  DirectlyConfirmable interface

Phase 2 — Data safety (3–5 days)
  B-1  PaymentStore interface + MemoryPaymentStore
  B-3  Idempotency on RegisterSettlement
  B-4  Amount/currency validation in ConfirmPayment
  H-4  Goroutine leak fix in CreateVirtualAccount

Phase 3 — Security hardening (1–2 days)
  B-5  Webhook verification enforcement + empty secret rejection
  M-6  baseURL validation at construction
  L-4  Bounded io.ReadAll

Phase 4 — Retry correctness (1 day)
  B-7  POST retry safety
  B-8  math/rand/v2 jitter
  H-3  Wire paymentRetrySleep seam
  M-5  Exponential backoff formula
  L-1  (resolved by M-5)

Phase 5 — Resilience (2–3 days)
  B-6  TOCTOU fix in GetPaymentStatus
  H-1  Operation timeout
  H-2  (resolved by B-6)
  M-3  Circuit breaker
  M-7  Reconciliation loop
  M-8  (resolved by B-2 + H-4)

Phase 6 — Compliance & observability (2–3 days)
  H-5  Travel Rule enforcement
  M-2  Structured logging
  M-4  SHA-1 nolint annotation

Phase 7 — Code quality (1 day)
  L-2  Pontes status mapping
  L-3  Modulr status mapping
  L-6  EURC idempotency key

Total estimated effort: 11–17 engineering days
```
