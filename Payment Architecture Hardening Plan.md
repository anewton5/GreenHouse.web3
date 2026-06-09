# Payment Architecture Hardening Plan

Date: 1 June 2026 (updated)
Scope: Item 26 and adjacent payment lifecycle hardening in GreenHouse.web3
Status: Planning artifact for implementation execution — ready for review

## 1. Executive Summary

This plan documents the current payment architecture risk profile across GreenHouse's three live payment rails (Modulr, EURC, Pontes) and a staged upgrade program to harden security, correctness, observability, and operational resilience across:
- Settlement confirmation and DVP application paths
- Webhook authenticity, replay resistance, and callback semantics
- Provider retry, cancellation, and concurrency behavior
- Lifecycle consistency for pending, confirmed, settled, failed, and expired payments
- Pontes CeBM pilot readiness (ECB T2 bridge, September 2026)
- Cross-border European settlement via EURC, SEPA Instant, and Pontes

> **Critical discovery**: there is a blocking DVP bug affecting all webhook-driven providers today.
> When a Modulr, EURC, or Pontes webhook arrives and calls `ConfirmAndSettle`, it internally calls
> `provider.ConfirmPayment()` which webhook-only providers intentionally reject.
> `ConfirmAndSettle` returns an error; the webhook handler silently discards it with `_ =`.
> DVP is **never applied**. This is the highest-priority fix in the plan (F-1).

## 2. Current Architecture Snapshot

### 2.1 Core Components

| File | Responsibility |
|------|---------------|
| `payment.go` | Payment types, `SettlementMethod` constants, `DefaultSettlementMethod`, `PaymentProvider` interface |
| `blockchain.go` | `ConfirmAndSettle`, `confirmAndSettleLocked`, `ExpireStaleInstructions`, `applyBlockState` payment instruction issuance, `SettlementRouter` |
| `payment_retry.go` | Shared `retryHTTP` with backoff (0ms → 500ms → 2s), ±10% jitter, context cancellation |
| `modulr_payment.go` | Modulr Faster Payments (GBP), HMAC-SHA1 auth, webhook-only confirm, EUR virtual accounts |
| `eurc_payment.go` | Circle EURC on-chain (EUR), collision-safe idempotency key, HMAC-SHA256 webhook verify |
| `pontes_payment.go` | Eurosystem Pontes/T2 CeBM (EUR), `RegisterSettlement`, HMAC-SHA256 webhook verify |
| `mock_payment.go` | In-memory mock for tests, instant confirm semantics |
| `api/handlers.go` | Webhook ingestion (`/v1/webhooks/payment|pontes|eurc`), payment list endpoints |
| `api/server.go` | Provider wiring, production startup guards |

### 2.2 Primary Lifecycle Today

1. Trade match in `applyBlockState` creates `PaymentInstruction` and `PendingSettlement` entry.
2. `applyBlockState` calls `provider.ConfirmPayment()` directly — succeeds only for the mock.
3. For production providers: webhook arrives → handler calls `ConfirmAndSettle` → **fails silently** (see F-1).
4. Expiry sweep in `ExpireStaleInstructions` removes stale pending instructions on each block.

### 2.3 Settlement Rail Matrix

| Currency | Default Rail | Provider | Status |
|----------|-------------|----------|--------|
| GBP | `SettlementFasterPay` | `ModulrPaymentProvider` | Live — webhook-only confirm (DVP blocked by F-1) |
| EUR | `SettlementEURC` | `EURCPaymentProvider` | Live — webhook-only confirm (DVP blocked by F-1) |
| EUR (Q4 2026) | `SettlementCeBM` | `PontesPaymentProvider` | Pilot — registration not wired (F-4) |
| USD / CHF | `SettlementSWIFT` | None — falls back to mock | **Not implemented** (F-14) |
| Other | `SettlementSEPA` | None — falls back to mock | Stub only |

## 3. Findings (17 total, prioritized)

---

### F-1 — CRITICAL: DVP permanently blocked for all webhook-driven providers

**Severity**: Critical — live settlement blocker affecting GBP, EUR, and CeBM rails

**Location**: `blockchain.go:560` (`confirmAndSettleLocked`), `api/handlers.go:932,978,1028`

**Root cause**: `confirmAndSettleLocked` calls `provider.ConfirmPayment()` before recording any on-chain state. For Modulr (`modulr_payment.go:330`), `ConfirmPayment` intentionally returns `"must not be called directly"`. This error propagates as `"ConfirmAndSettle: provider confirm failed: ..."`. All three webhook handlers discard it with `_ = s.bc.ConfirmAndSettle(...)`. Result: webhook gets HTTP 200, DVP never applies, no event emitted, no log written.

**Fix notes**:
- Remove the `provider.ConfirmPayment()` call from `confirmAndSettleLocked` entirely. The blockchain is the authority; the webhook authentication is the trust anchor.
- The mock's synchronous confirm path in `applyBlockState` step 7 is the only legitimate direct-call site and is unaffected by this change.
- Change all three webhook handlers from `_ = s.bc.ConfirmAndSettle(...)` to:
  ```go
  if err := s.bc.ConfirmAndSettle(...); err != nil {
      log.Printf("ConfirmAndSettle failed ref=%s: %v", event.Reference, err)
      writeError(w, http.StatusInternalServerError, "settlement failed")
      return
  }
  ```
  HTTP 500 instructs providers to retry until the issue resolves (oracle outage, etc.).

**Tests required**:
- `TestConfirmAndSettle_ModulrWebhook_DVPApplied` — register `ModulrPaymentProvider` for `SettlementFasterPay`, add a pending instruction + settlement, call `ConfirmAndSettle`, assert `ConfirmedPayments` populated and `PendingSettlements` cleared
- `TestConfirmAndSettle_EURCWebhook_DVPApplied` — same for EURC
- `TestConfirmAndSettle_PontesWebhook_DVPApplied` — same for Pontes/CeBM
- `TestWebhookHandler_ModulrPaymentReceived_DVPApplied` (API) — POST a valid HMAC-signed webhook, assert holdings transferred within the same request

**Acceptance criteria**:
- [ ] `ConfirmAndSettle` returns `nil` for all three production providers on a valid callback
- [ ] Holdings are transferred in the same HTTP request that receives the webhook
- [ ] `ConfirmAndSettle` still returns `nil` for unknown references (no-op preserved)
- [ ] HTTP 500 returned when DVP fails internally (causes provider retry)

---

### F-2 — HIGH: Unsigned Modulr webhooks accepted when `ModulrProvider` is nil

**Severity**: High — authenticity bypass under misconfiguration

**Location**: `api/handlers.go:905`, `api/server.go:52`, `blockchain.go:1555`

**Root cause**: Signature verification is wrapped in `if s.ModulrProvider != nil`. When `ModulrProvider` is nil, any incoming request is processed as a valid payment event. The comment explicitly documents this as intentional for dev mode, but no production guard prevents this configuration from shipping.

**Fix notes**:
- Add to `productionReadinessError` in `blockchain.go`: require `MODULR_WEBHOOK_SECRET` env var when the Modulr rail is active.
- In `api/server.go` production start path, assert `ModulrProvider != nil` when `SettlementFasterPay` or `SettlementSEPA` is in the router.
- Default `handlePaymentWebhook` to return 401 (not process) when `ModulrProvider` is nil and the server is in production mode.

**Tests required**:
- `TestWebhookHandler_ModulrNilProvider_ProductionMode_Returns401`
- `TestProductionReadinessError_MissingModulrWebhookSecret`

**Acceptance criteria**:
- [ ] Unsigned Modulr webhooks are never processed in production mode
- [ ] Startup fails fast when Modulr rail is active but provider is not wired

---

### F-3 — HIGH: No amount/currency validation against instruction before DVP

**Severity**: High — financial integrity risk

**Location**: `blockchain.go:528` (`ConfirmAndSettle` signature), `blockchain.go:535–560` (`confirmAndSettleLocked`)

**Root cause**: `ConfirmAndSettle(reference, amount, currency)` accepts whatever the webhook claims. No comparison is made against `instruction.TotalAmount` or `instruction.Currency` before settlement proceeds. A malformed, manipulated, or accidentally redelivered callback with wrong values progresses all the way to DVP application.

**Fix notes**:
- In `confirmAndSettleLocked`, after finding the matching instruction, add:
  ```go
  if currency != instruction.Currency {
      return fmt.Errorf("ConfirmAndSettle: currency mismatch ref=%s got=%s want=%s",
          reference, currency, instruction.Currency)
  }
  if amount != instruction.TotalAmount {
      return fmt.Errorf("ConfirmAndSettle: amount mismatch ref=%s got=%.2f want=%.2f",
          reference, amount, instruction.TotalAmount)
  }
  ```
- Emit `EventPaymentConfirmationRejected` with fields: `reference`, `expected_amount`, `received_amount`, `expected_currency`, `received_currency`.
- Webhook handlers must return HTTP 422 (Unprocessable Entity) for a mismatch. HTTP 422 signals the provider that retrying is futile (unlike HTTP 500 which would prompt a retry).

**Tests required**:
- `TestConfirmAndSettle_WrongCurrency_Rejected` — assert error returned and no state mutation
- `TestConfirmAndSettle_WrongAmount_Rejected` — assert error returned and no state mutation
- `TestConfirmAndSettle_CorrectAmountCurrency_Settles` — baseline still works
- `TestWebhookHandler_AmountMismatch_Returns422` (API) — POST webhook with wrong amount, assert 422

**Acceptance criteria**:
- [ ] Callback with wrong currency returns error and emits rejection event; no state change
- [ ] Callback with wrong amount returns error and emits rejection event; no state change
- [ ] HTTP 422 returned to provider (stops retrying)
- [ ] `PendingSettlements` is never consumed on a rejected callback

---

### F-4 — HIGH: Pontes `RegisterSettlement` not wired into `applyBlockState`

**Severity**: High — Pontes pilot blocker; CeBM trades will never settle without this

**Location**: `blockchain.go:734` (instruction created), `pontes_payment.go:183` (`RegisterSettlement` doc)

**Root cause**: For `SettlementCeBM` instructions, `PontesPaymentProvider.RegisterSettlement()` must be called to register the DLT delivery leg with the Pontes bridge before any `settlement.confirmed` webhook can arrive. The function is documented as an "API layer call" but is never automatically invoked when a CeBM instruction is created in `applyBlockState`. The bridge never receives the registration and will never fire a callback.

**Fix notes**:
- Define a `SettlementRegistrar` interface in `payment.go`:
  ```go
  type SettlementRegistrar interface {
      RegisterSettlement(instruction *PaymentInstruction) (transactionID string, err error)
  }
  ```
- In `applyBlockState` step 6, after oracle-signing the instruction, check if the provider implements `SettlementRegistrar`. If so, launch an async goroutine with a bounded context (30s timeout) to call `RegisterSettlement`. Store `PontesTransactionID` back on the instruction on success.
- On failure: emit `EventPaymentRegistrationFailed` and leave instruction in pending state.
- Add `POST /v1/payments/{tradeID}/register` admin endpoint to retry failed registrations manually.

**Tests required**:
- `TestApplyBlockState_CeBMInstruction_RegisterSettlementCalled` — seal a block with an EUR trade when Pontes is registered, assert `RegisterSettlement` was called and `PontesTransactionID` is populated
- `TestApplyBlockState_CeBMRegistrationFailure_InstructionRemainsPending` — when `RegisterSettlement` errors, instruction is pending and `EventPaymentRegistrationFailed` emitted
- `TestRegistrationRetry_AdminEndpoint` — POST to `/v1/payments/{tradeID}/register`, assert transaction ID stored

**Acceptance criteria**:
- [ ] Every CeBM instruction has `PontesTransactionID` populated before its expiry
- [ ] Block application is not delayed by Pontes API latency (async registration)
- [ ] Failed registrations are observable and retryable

---

### F-5 — HIGH: EUR routing cannot auto-upgrade to CeBM when Pontes is registered

**Severity**: High — Pontes pilot functionality gap

**Location**: `payment.go:134` (`DefaultSettlementMethod`), `blockchain.go:706` (call site)

**Root cause**: `DefaultSettlementMethod` is a stateless package-level function with no access to `SettlementRouter`. When a `PontesPaymentProvider` is registered via `bc.RegisterSettlementProvider(SettlementCeBM, p)`, new EUR instructions should prefer CeBM over EURC — but the routing function always returns `SettlementEURC` for EUR. Manual cutover is required even after Pontes goes live.

**Fix notes**:
- Add `bc.PreferredSettlementMethod(currency string) SettlementMethod` to `Blockchain`:
  ```go
  func (bc *Blockchain) PreferredSettlementMethod(currency string) SettlementMethod {
      base := DefaultSettlementMethod(currency)
      upgrades := map[SettlementMethod]SettlementMethod{
          SettlementEURC: SettlementCeBM,
      }
      if upgraded, ok := upgrades[base]; ok {
          if _, registered := bc.SettlementRouter[upgraded]; registered {
              return upgraded
          }
      }
      return base
  }
  ```
- Replace the `DefaultSettlementMethod(trade.Currency)` call in `applyBlockState` with `bc.PreferredSettlementMethod(trade.Currency)`.

**Tests required**:
- `TestPreferredSettlementMethod_EUR_NoPontes_ReturnsEURC`
- `TestPreferredSettlementMethod_EUR_WithPontes_ReturnsCeBM`
- `TestPreferredSettlementMethod_GBP_AlwaysFasterPay` — GBP unaffected by router state

**Acceptance criteria**:
- [ ] Registering a Pontes provider automatically upgrades EUR routing without code change or restart
- [ ] No EUR instruction uses CeBM when Pontes is not registered

---

### F-6 — MEDIUM: `ExpireStaleInstructions` leaves orphaned `PendingSettlements`

**Severity**: Medium — reconciliation and memory integrity

**Location**: `blockchain.go:503` (`ExpireStaleInstructions`)

**Root cause**: `delete(bc.PendingInstructions, tradeID)` is called on expiry, but the corresponding `bc.PendingSettlements[tradeID]` entry is never removed. For Pontes instructions, the provider-side `p.pending[reference]` (transactionId cache) is also never cleaned. Both maps grow indefinitely on long-running nodes.

**Fix notes**:
- After `delete(bc.PendingInstructions, tradeID)`, add:
  ```go
  delete(bc.PendingSettlements, tradeID)
  ```
- Extend the emitted event payload to include `settlement_method` and `pontes_transaction_id` (if set) for compliance tooling and reconciliation audit trails.

**Tests required**:
- `TestExpireStaleInstructions_CleansLinkedSettlement` — expire an instruction that has a corresponding `PendingSettlements` entry, assert both maps are cleaned
- `TestExpireStaleInstructions_EventPayloadIncludesMethod` — assert emitted event includes `method` and `expired_at` fields

**Acceptance criteria**:
- [ ] After expiry, both `PendingInstructions[tradeID]` and `PendingSettlements[tradeID]` are absent
- [ ] No orphaned entries accumulate during soak testing

---

### F-7 — MEDIUM: `ConfirmedPayments` map grows unboundedly

**Severity**: Medium — memory and operational concern for long-running nodes

**Location**: `blockchain.go:573` (`confirmAndSettleLocked`)

**Root cause**: `bc.ConfirmedPayments[tradeID] = confirmation` is appended on every settlement and never pruned. The map is also not persisted to the block store, so a node restart loses idempotency history.

**Fix notes**:
- Persist `ConfirmedPayments` entries to bbolt alongside `SaveState` snapshots.
- Add a configurable 90-day retention window (aligns with EMIR/MiCA trade record retention). Prune entries older than `ConfirmedAt + retention` from in-memory state; they remain on disk.
- After pruning, late duplicate webhooks for the same reference fall back to the bbolt store as the idempotency gate.

**Tests required**:
- `TestConfirmedPayments_PersistenceRoundTrip` — save state, reload, assert `ConfirmedPayments` restored
- `TestConfirmedPayments_RetentionPrune` — inject old entries, run prune, assert removed from memory but idempotency preserved via store lookup

**Acceptance criteria**:
- [ ] `ConfirmedPayments` memory footprint is bounded in long-running node scenarios
- [ ] Idempotency guarantee is preserved after pruning

---

### F-8 — MEDIUM: Provider mutexes held during network I/O and retry backoffs

**Severity**: Medium — latency and concurrency under concurrent webhook/status traffic

**Location**: `eurc_payment.go:99` (lock acquired before HTTP call at line 136), `pontes_payment.go:126` (lock acquired before HTTP at line 145)

**Root cause**: `EURCPaymentProvider.CreateVirtualAccount` and `PontesPaymentProvider.GetPaymentStatus` hold their mutex across the entire HTTP call including retry backoffs. When retrying on a 503, the mutex is held for up to 6+ seconds (3 attempts × 2s), blocking all concurrent operations on the provider — including `ConfirmPayment` invocations from concurrently arriving webhooks.

**Fix notes**:
- Apply the double-check pattern:
  ```go
  p.mu.Lock()
  if cached, ok := p.map[key]; ok { p.mu.Unlock(); return cached, nil }
  p.mu.Unlock()
  // --- HTTP call outside lock ---
  resp, err := retryHTTP(...)
  // ---
  p.mu.Lock()
  if existing, ok := p.map[key]; ok { p.mu.Unlock(); return existing, nil } // double-check
  p.map[key] = result
  p.mu.Unlock()
  ```
- Circle's idempotency key makes concurrent wallet creation safe (last write wins, same result).

**Tests required**:
- `TestEURCCreateVirtualAccount_ConcurrentSameWallet_NoRace` — 10 goroutines, same `walletID`, assert no data race and single HTTP call
- `TestPontesGetPaymentStatus_ConcurrentPolling_NoDeadlock` — concurrent status polls with slow mock server, assert no deadlock

**Acceptance criteria**:
- [ ] `go test -race` passes under concurrent provider usage
- [ ] Lock is never held during an HTTP call or backoff sleep

---

### F-9 — MEDIUM: Pontes `GetPaymentStatus` silently degrades non-2xx and decode errors to pending

**Severity**: Medium — diagnostic clarity; hides outages and auth failures

**Location**: `pontes_payment.go:155–156`

**Root cause**: On HTTP response decode error (or non-2xx responses, which have no explicit status check), the function returns `PaymentStatusPending, nil`. A Pontes API 401 auth failure, 503 outage, or 404 unknown transaction are all indistinguishable from "not yet confirmed".

**Fix notes**:
- Add an HTTP status check immediately after `retryHTTP`:
  ```go
  if resp.StatusCode == http.StatusNotFound {
      return PaymentStatusFailed, fmt.Errorf("pontes: transaction %s not found (404)", transactionID)
  }
  if resp.StatusCode < 200 || resp.StatusCode >= 300 {
      return PaymentStatusPending, fmt.Errorf("pontes: status check returned HTTP %d", resp.StatusCode)
  }
  ```
- On decode error, return the error explicitly rather than silently degrading.
- 404 is terminal (the transactionID was never registered or expired at Pontes) — return `PaymentStatusFailed`.

**Tests required**:
- `TestPontesGetPaymentStatus_404_ReturnsFailed` — mock server returns 404, assert `PaymentStatusFailed` and non-nil error
- `TestPontesGetPaymentStatus_503_ReturnsPendingWithError` — mock server returns 503, assert non-nil error after retry exhaustion
- `TestPontesGetPaymentStatus_DecodeError_ReturnsError` — malformed JSON response, assert error returned

**Acceptance criteria**:
- [ ] `GetPaymentStatus` never returns `nil` error for any non-2xx response
- [ ] 404 is classified as terminal (failed), not transient

---

### F-10 — MEDIUM: All `retryHTTP` call sites use `context.Background()` — no shutdown cancellation

**Severity**: Medium — operational resilience

**Location**: `modulr_payment.go:189,251,295`, `pontes_payment.go:139,198`

**Root cause**: All `retryHTTP` calls pass `context.Background()`. During graceful shutdown, in-flight retries cannot be cancelled. Backoffs of up to 2s × 3 attempts can delay shutdown by up to 6 seconds per in-flight call.

**Fix notes**:
- Add a `ContextualPaymentProvider` interface (non-breaking — does not change existing `PaymentProvider`):
  ```go
  type ContextualPaymentProvider interface {
      PaymentProvider
      CreateVirtualAccountCtx(ctx context.Context, walletID string) (string, error)
      GetPaymentStatusCtx(ctx context.Context, reference string) (PaymentStatus, error)
  }
  ```
- Thread the request context from `r.Context()` in webhook handlers through to the provider calls.
- Pass the server lifecycle context (from `NewServer`) for background operations.

**Tests required**:
- `TestRetryHTTP_ContextCancellation_AbortsImmediately` — cancel context during first backoff sleep, assert immediate cancellation error
- `TestModulrCreateVirtualAccount_ContextCancelled_NoRetry` — pre-cancelled context, assert no HTTP call attempted

**Acceptance criteria**:
- [ ] Graceful shutdown cancels all in-flight payment provider requests within 100ms
- [ ] No retry is attempted after context cancellation

---

### F-11 — MEDIUM: Oracle signing error silently discarded on payment confirmation

**Severity**: Medium — cryptographic integrity

**Location**: `blockchain.go:568` (`confirmation, _ = bc.OracleService.SignConfirmation(confirmation)`)

**Root cause**: The error from `SignConfirmation` is discarded with `_`. If the oracle key provider fails (HSM unavailable, key rotated), an unsigned confirmation is stored in `ConfirmedPayments` and emitted on-chain. Downstream verifiers will reject it, and no retry will occur because no error is returned.

**Fix notes**:
- Replace `confirmation, _ = bc.OracleService.SignConfirmation(confirmation)` with:
  ```go
  confirmation, err = bc.OracleService.SignConfirmation(confirmation)
  if err != nil {
      return fmt.Errorf("ConfirmAndSettle: oracle signing failed: %w", err)
  }
  ```
- This causes `ConfirmAndSettle` to return an error → HTTP 500 → provider retries until the oracle recovers.
- Do NOT consume `PendingSettlements` before oracle signing succeeds — the entry must remain so the retry can apply DVP.
- Emit `EventOracleSigningFailed` for SOC alerting.

**Tests required**:
- `TestConfirmAndSettle_OracleSigningFails_ReturnsError` — inject a failing oracle, assert error returned and no `ConfirmedPayments` entry created
- `TestConfirmAndSettle_OracleSigningFails_NoPartialState` — assert `PendingSettlements` is NOT deleted when oracle signing fails

**Acceptance criteria**:
- [ ] Oracle signing failure returns a non-nil error from `ConfirmAndSettle`
- [ ] HTTP 500 returned to provider (causes retry until oracle recovers)
- [ ] `PendingSettlements` entry is not consumed on oracle signing failure

---

### F-12 — MEDIUM: `EventPaymentExpired` only fires during block application

**Severity**: Medium — operational and compliance monitoring accuracy

**Location**: `blockchain.go:608` (`bc.ExpireStaleInstructions()` called only inside `applyBlockState`)

**Root cause**: In low-activity periods where no blocks are sealed for minutes or hours, `EventPaymentExpired` is never emitted and observability systems (WebSocket stream, SOC monitors) receive no signal. The `/v1/payments/pending` API shows the correct expired status (calculated inline), but event-driven consumers miss it.

**Fix notes**:
- Add a background ticker goroutine in `NewBlockchain` (and start in `Server.Start()`):
  ```go
  go func() {
      ticker := time.NewTicker(expirySweepInterval) // default 60s
      defer ticker.Stop()
      for {
          select {
          case <-ticker.C:
              bc.Mu.Lock()
              bc.ExpireStaleInstructions()
              bc.Mu.Unlock()
          case <-ctx.Done():
              return
          }
      }
  }()
  ```
- Expose `GREENHOUSE_EXPIRY_SWEEP_INTERVAL` env var (default: `60s`).

**Tests required**:
- `TestExpirySweepTicker_EmitsEventWithoutBlock` — start a blockchain with a short interval (e.g. 50ms), add an already-expired instruction, assert `EventPaymentExpired` emitted within 2× the interval without sealing a block

**Acceptance criteria**:
- [ ] `EventPaymentExpired` fires within the configured sweep interval regardless of block activity
- [ ] The sweep goroutine exits cleanly on node shutdown

---

### F-13 — MEDIUM: No API-layer webhook test coverage

**Severity**: Medium — regression risk on security-critical paths

**Location**: `api/` package — only `api/metrics_test.go` exists

**Root cause**: All three webhook handlers have zero API-layer test coverage. Provider-level tests are strong but do not exercise full HTTP header parsing, event type filtering, HMAC verification in context, or HTTP response code semantics.

**Fix notes**: Create `api/payment_webhook_test.go`. Tests use `httptest.NewServer` wrapping a real `Server` backed by a test `Blockchain` with a `MockOracleService` and pre-registered providers.

**Tests required** (all in `api/payment_webhook_test.go`):
- `TestModulrWebhook_ValidSignature_Settles`
- `TestModulrWebhook_MissingSignatureHeader_Returns401`
- `TestModulrWebhook_InvalidSignature_Returns401`
- `TestModulrWebhook_WrongEventType_NoSettle_Returns200`
- `TestModulrWebhook_AmountMismatch_Returns422`
- `TestModulrWebhook_DuplicateDelivery_Idempotent`
- `TestPontesWebhook_ValidSignature_Settles`
- `TestPontesWebhook_NilProvider_Returns501`
- `TestEURCWebhook_ValidSignature_Settles`
- `TestEURCWebhook_NilProvider_Returns501`
- `TestListPendingPayments_FiltersToCallerWallet`
- `TestListPaymentHistory_IncludesSettlementFields`

**Acceptance criteria**:
- [ ] Full webhook test matrix passes under `go test ./api/...`
- [ ] Race tests pass under `go test -race ./api/...`

---

### F-14 — MEDIUM: No SWIFT provider stub — USD/CHF trades silently use mock

**Severity**: Medium — USD/CHF settlement gap

**Location**: `payment.go:23` (`SettlementSWIFT`), `payment.go:147`

**Root cause**: `DefaultSettlementMethod` routes USD and CHF to `SettlementSWIFT`, but no `SwiftPaymentProvider` exists. These trades fall back to `bc.PaymentProvider` (the mock in production until a real SWIFT provider is registered), meaning USD/CHF cross-border trades are silently settled via mock without real payment instructions.

**Fix notes**:
- Create `swift_payment.go` with a fail-closed stub:
  - Returns a clear `"SWIFT GPI not yet implemented"` error from `CreateVirtualAccount`.
  - Returns `PaymentStatusPending` from `GetPaymentStatus`.
  - Rejects direct `ConfirmPayment` calls (webhook-driven, same as Modulr).
  - Documents expected ISO 20022 pacs.008 message format in comments.
- Add `POST /v1/webhooks/swift` handler in `api/handlers.go`.
- Add to `productionReadinessError`: fail startup when USD/CHF trading is enabled without a real SWIFT provider registered.

**Tests required**:
- `TestSwiftProvider_ConfirmPayment_RejectsDirectCall`
- `TestSwiftProvider_CreateVirtualAccount_ReturnsNotImplementedError`

**Acceptance criteria**:
- [ ] USD/CHF trades never silently use the mock provider in production
- [ ] Startup fails fast when SWIFT rail is needed but not configured

---

### F-15 — LOW: TravelRule omitted when EUR valuation oracle is unavailable for non-EUR trades

**Severity**: Low — EU TFR 2023/1113 regulatory compliance edge case

**Location**: `blockchain.go:721–728`

**Root cause**: `eurAmount` defaults to `instruction.TotalAmount` (raw, no conversion) when `ValuationOracle` is nil or returns an error. A 900 USD trade (EUR equivalent ~830 EUR) has raw amount 900 — below `TravelRuleThresholdEUR` (1000) — so no TravelRule payload is attached. This misses the EU Transfer-of-Funds Regulation threshold.

**Fix notes**:
- When `ValuationOracle` is nil or errors for a non-EUR currency, log a warning and attach the TravelRule conservatively (assume EUR-equivalent ≥ 1000 when conversion is uncertain) rather than omitting it.
- In production, add `ValuationOracle != nil` to `productionReadinessError` when non-EUR assets are tradeable.

**Tests required**:
- `TestApplyBlockState_USDTrade_NoOracle_TravelRuleAttached` — USD trade at 900, nil oracle, assert TravelRule is attached
- `TestProductionReadinessError_NilValuationOracle_NonEURAssets_Fails`

**Acceptance criteria**:
- [ ] TravelRule is never omitted due to oracle unavailability for non-EUR currency trades

---

### F-16 — LOW: EURC wallet creation holds mutex across retry backoffs (up to 6s)

**Severity**: Low — variant of F-8 specific to wallet creation

**Location**: `eurc_payment.go:99`

**Root cause**: When `CreateVirtualAccount` retries on a 503, the mutex is held for the full backoff duration (up to 2.2s × 3 = 6.6s). This blocks all concurrent operations on the EURC provider — including `ConfirmPayment` calls from webhook handlers arriving in parallel. Covered by the F-8 double-check fix.

**Fix notes**: Apply the double-check unlock-HTTP-relock pattern from F-8. Circle's idempotency key makes concurrent creation safe (both callers will receive the same address).

---

### F-17 — LOW: No webhook event-ID replay cache

**Severity**: Low (partially mitigated by `ConfirmedPayments` idempotency)

**Location**: `api/handlers.go` — all three webhook handlers

**Root cause**: There is no event-ID deduplication cache at the handler level. If a provider retries a webhook (e.g. Modulr retries on timeout), `ConfirmAndSettle` is called again. While `ConfirmedPayments` prevents double DVP, each replay still acquires `bc.Mu`, iterates `PendingInstructions`, and may log noise. For Pontes pilot with ECB infrastructure, webhook retry windows may be long (up to 24h).

**Fix notes**:
- Add `webhookEventIDs map[string]int64` (event-id → received Unix timestamp) to `Server`.
- Extract provider-specific event IDs: `id` field (Modulr), `notificationId` (Circle), `eventId` (Pontes) and check the cache before calling `ConfirmAndSettle`.
- TTL: 48 hours (covers all three providers' retry windows).
- Prune stale entries on the existing sweep interval alongside the expiry ticker.

**Tests required**:
- `TestWebhookReplay_SameEventID_Returns200_NoDuplicateSettle` — send same event ID twice, assert second call returns 200 but `ConfirmAndSettle` not called a second time

**Acceptance criteria**:
- [ ] Duplicate delivery with same event ID is detected at handler level before blockchain lock acquisition

## 4. Target State

The hardened target state for GreenHouse's payment architecture:

1. DVP is correctly applied for every valid, authenticated webhook on all rails (Modulr, EURC, Pontes).
2. Strict callback-to-instruction integrity checks guard every settlement — wrong amount or currency is rejected with HTTP 422.
3. Unsigned, mismatched, and replayed callbacks are rejected with HTTP status codes that correctly control provider retry behavior (401 for auth failures, 422 for mismatches, 500 for transient internal failures).
4. Pontes CeBM pilot is fully wired: automatic `RegisterSettlement` on instruction creation, dynamic EUR routing preference, T2 business-hours awareness.
5. Payment lifecycle state is complete and consistent: `pending → confirmed → settled`, `pending → expired` (with full linked-state cleanup), `pending → failed`.
6. Provider HTTP I/O is lock-free; cancellation contexts flow from request/lifecycle through to retry calls.
7. Structured observability and audit trail satisfy MiCA, EU TFR 2023/1113, and ECB pilot compliance evidence requirements.
8. USD/CHF trades have a clearly defined fail-closed path rather than silently routing to the mock provider.

## 5. Pontes Pilot Readiness (September 2026)

The Pontes bridge pilot is approximately 3 months away. The following items must be completed before ECB pilot participation and are separate from (but dependent on) the F-series fixes above.

### P-1: Automatic settlement registration (see F-4)
Wire `RegisterSettlement` into `applyBlockState` for all `SettlementCeBM` instructions. Without this, no settlement request ever reaches the Pontes bridge and no callback will ever be received.

### P-2: Dynamic EUR routing upgrade (see F-5)
Implement `bc.PreferredSettlementMethod` so registering the Pontes provider automatically upgrades EUR instruction routing from EURC to CeBM without a code deployment.

### P-3: T2 business hours awareness
T2 RTGS operates on ECB business days (Monday–Friday, TARGET2 calendar). Pontes instructions submitted outside these windows will be queued or rejected by the bridge.

**Required work**:
- Add `T2BusinessDayChecker` utility using ECB's published TARGET2 holiday calendar.
- In `applyBlockState`, for `SettlementCeBM` instructions, set a `T2QueuedUntil` field when submitted outside T2 hours and log an operator warning.
- Extend `ExpiresAt` for CeBM instructions by the number of non-T2 hours between instruction creation and next T2 open, to prevent premature expiry.

### P-4: ISO 20022 reference fields
The Pontes bridge uses ISO 20022 message references for T2 cash leg instructions.

**Required additions to `PaymentInstruction`**:
```go
ISO20022MsgID   string `json:"iso20022_msg_id,omitempty"`   // pacs.009 message ID from Pontes
T2SettlementDate string `json:"t2_settlement_date,omitempty"` // intended T2 settlement date YYYY-MM-DD
```
Populate from the `RegisterSettlement` bridge response and store on-chain.

### P-5: Participant BIC validation
Pontes requires valid BIC-8 or BIC-11 identifiers for payer and payee. The current `PayerWalletID` / `PayeeWalletID` fields are Ed25519 public keys.

**Required additions to `PaymentInstruction`**:
```go
PayerBIC string `json:"payer_bic,omitempty"` // BIC-8 or BIC-11 for CeBM instructions
PayeeBIC string `json:"payee_bic,omitempty"`
```
Populate from the participant's `RegistrationRegistry` record at instruction creation time. Validate BIC format; reject CeBM instructions where BIC is missing.

### P-6: Pilot credentials, environment guards, and health endpoint
- Add `PONTES_API_KEY`, `PONTES_BASE_URL`, `PONTES_DLT_OPERATOR`, and `PONTES_HMAC_SECRET` to `productionReadinessError` when `SettlementCeBM` is in the router.
- Add `POST /v1/admin/pontes/health` endpoint that issues a lightweight Pontes API call to verify bridge connectivity.
- **Non-code deliverable**: submit ECB Market DLT Operator application. GreenHouse's permissioned dBFT network, KYC/compliance layer, and oracle-signed DVP directly satisfy ECB pilot eligibility criteria.

## 6. Cross-Border European Settlement

### EUR Settlement Architecture (Priority Order)

```
EUR trade
  │
  ├─ CeBM registered? ─────────► Pontes/T2 (Sept 2026+)   irreversible, central bank finality
  │   SettlementCeBM
  │
  ├─ EURC active? ─────────────► Circle EURC on-chain      ~12s finality, no bank credit risk
  │   SettlementEURC
  │
  └─ Fallback ─────────────────► Modulr SEPA Instant       ~10s, bank credit risk
      SettlementSEPA
```

This priority chain is implemented by `bc.PreferredSettlementMethod` (F-5). All three rails remain active simultaneously; the highest-confidence rail for the instruction is selected at creation time.

### GBP Settlement
Modulr Faster Payments is correctly wired. No routing change required. Add settlement latency monitoring (PSR 2023 mandates 10-second Faster Payments settlement).

### USD / CHF Settlement
SWIFT GPI stub (F-14) prevents silent mock fallback. For private placements, bilateral USD settlement can use Modulr's USD SWIFT rails as an interim measure. CHF via SIC/euroSIC is a future item; document as out of scope until Swiss pilot demand is confirmed.

### EURC Operational Notes
- The Circle idempotency key scheme should be reviewed when `walletSetID` rotates. The current hash-based key should include a version prefix to avoid key collisions across wallet set versions.
- EURC settlement is on Ethereum mainnet — expose on-chain `confirmations` depth in the payment status response so downstream systems can enforce a minimum confirmation depth before treating a transfer as final.
- Regulatory note: Circle's EURC is MiCA-compliant. GreenHouse's use of EURC for EUR settlement satisfies the ECB's acknowledged legitimate alternatives to CeBM for the pre-Pontes interim period.

## 7. Upgrade Roadmap

### Phase 0 — Baseline Lock *(do first, before any changes)*

| # | Work Item | File(s) |
|---|-----------|---------|
| 0.1 | Run and capture `go test -race -count=3` output as baseline evidence | — |
| 0.2 | Add `assertPaymentLifecycleInvariants` test helper documenting the expected state machine | `blockchain_extended_test.go` |
| 0.3 | Define `GREENHOUSE_PAYMENT_HARDENING=1` rollout flag to gate Phase 1 behavior changes | `blockchain.go`, `api/server.go` |

---

### Phase 1 — Critical DVP and Security Fixes *(blocking — must ship before Pontes pilot)*

| # | Finding | Work Item | File(s) |
|---|---------|-----------|---------|
| 1.1 | F-1 | Remove `provider.ConfirmPayment()` call from `confirmAndSettleLocked` | `blockchain.go:560` |
| 1.2 | F-1 | Wire `ConfirmAndSettle` errors to HTTP 500 in all three webhook handlers | `api/handlers.go:932,978,1028` |
| 1.3 | F-2 | Add Modulr provider + `MODULR_WEBHOOK_SECRET` guards to `productionReadinessError` | `blockchain.go:1555`, `api/server.go` |
| 1.4 | F-3 | Add amount + currency validation in `confirmAndSettleLocked`; return typed mismatch error | `blockchain.go:535–560` |
| 1.5 | F-3 | Return HTTP 422 from webhook handlers on amount/currency mismatch | `api/handlers.go` |
| 1.6 | F-11 | Propagate oracle signing error; return HTTP 500 so provider retries | `blockchain.go:568` |
| 1.7 | F-1, F-3 | Add `EventPaymentConfirmationRejected` event constant; emit on every rejection path | `blockchain.go` |

**Phase 1 Acceptance Criteria**:
- [ ] `TestConfirmAndSettle_ModulrWebhook_DVPApplied` passes
- [ ] `TestConfirmAndSettle_EURCWebhook_DVPApplied` passes
- [ ] `TestConfirmAndSettle_PontesWebhook_DVPApplied` passes
- [ ] `TestConfirmAndSettle_WrongCurrency_Rejected` passes
- [ ] `TestConfirmAndSettle_WrongAmount_Rejected` passes
- [ ] `TestConfirmAndSettle_OracleSigningFails_ReturnsError` passes
- [ ] `TestWebhookHandler_AmountMismatch_Returns422` passes
- [ ] `TestProductionReadinessError_MissingModulrWebhookSecret` passes
- [ ] `go test -race -count=3 -timeout=20m .` passes

---

### Phase 2 — Pontes Pilot Wiring *(target: complete by July 2026 — 8 weeks before pilot)*

| # | Finding | Work Item | File(s) |
|---|---------|-----------|---------|
| 2.1 | F-4 | Define `SettlementRegistrar` interface | `payment.go` |
| 2.2 | F-4 | Auto-invoke `RegisterSettlement` async from `applyBlockState` for CeBM instructions | `blockchain.go:734` |
| 2.3 | F-4 | Add `POST /v1/payments/{tradeID}/register` admin retry endpoint | `api/handlers.go` |
| 2.4 | F-5 | Implement `bc.PreferredSettlementMethod` with CeBM upgrade check | `blockchain.go` |
| 2.5 | P-1–P-6 | All Pontes pilot readiness items: BIC fields, ISO 20022 refs, T2 business hours, health endpoint, env guards, ECB application | `payment.go`, `pontes_payment.go`, `blockchain.go`, `api/handlers.go` |

**Phase 2 Acceptance Criteria**:
- [ ] `TestApplyBlockState_CeBMInstruction_RegisterSettlementCalled` passes
- [ ] `TestPreferredSettlementMethod_EUR_WithPontes_ReturnsCeBM` passes
- [ ] `TestPontesWebhook_ValidSignature_Settles` (API test) passes
- [ ] T2 business hours edge case test passes
- [ ] All `PONTES_*` env var guards present in `productionReadinessError`

---

### Phase 3 — Lifecycle Consistency and Data Integrity

| # | Finding | Work Item | File(s) |
|---|---------|-----------|---------|
| 3.1 | F-6 | Clean `PendingSettlements` on expiry alongside `PendingInstructions` | `blockchain.go:503` |
| 3.2 | F-7 | Persist `ConfirmedPayments` to bbolt; add 90-day retention prune | `persistence.go`, `blockchain.go` |
| 3.3 | F-12 | Add background expiry sweep ticker (default 60s, `GREENHOUSE_EXPIRY_SWEEP_INTERVAL`) | `blockchain.go` |
| 3.4 | F-9 | Fix Pontes status polling: HTTP status check, classify 404 as terminal | `pontes_payment.go:155` |
| 3.5 | F-15 | Conservative TravelRule attachment when EUR oracle unavailable | `blockchain.go:721` |

**Phase 3 Acceptance Criteria**:
- [ ] `TestExpireStaleInstructions_CleansLinkedSettlement` passes
- [ ] `TestConfirmedPayments_PersistenceRoundTrip` passes
- [ ] `TestExpirySweepTicker_EmitsEventWithoutBlock` passes
- [ ] `TestPontesGetPaymentStatus_404_ReturnsFailed` passes
- [ ] `TestApplyBlockState_USDTrade_NoOracle_TravelRuleAttached` passes

---

### Phase 4 — Concurrency, Context, and Resilience

| # | Finding | Work Item | File(s) |
|---|---------|-----------|---------|
| 4.1 | F-8, F-16 | Restructure EURC `CreateVirtualAccount` to use double-check pattern (unlock before HTTP) | `eurc_payment.go:99` |
| 4.2 | F-8 | Restructure Pontes `GetPaymentStatus` to unlock before HTTP | `pontes_payment.go:126` |
| 4.3 | F-10 | Add `ContextualPaymentProvider` interface with context-aware method variants | `payment.go` |
| 4.4 | F-10 | Pass `r.Context()` from webhook handlers to provider calls | `api/handlers.go` |
| 4.5 | — | Parameterize retry policy per provider/operation class via options struct | `payment_retry.go` |

**Phase 4 Acceptance Criteria**:
- [ ] `TestEURCCreateVirtualAccount_ConcurrentSameWallet_NoRace` passes
- [ ] `TestRetryHTTP_ContextCancellation_AbortsImmediately` passes
- [ ] `go test -race -count=3 -timeout=20m .` passes with concurrent provider tests

---

### Phase 5 — Observability, Test Hardening, and Operations

| # | Finding | Work Item | File(s) |
|---|---------|-----------|---------|
| 5.1 | F-13 | Create `api/payment_webhook_test.go` with full test matrix (12 tests) | `api/` |
| 5.2 | F-17 | Implement webhook event-ID replay cache in `Server` with 48h TTL | `api/server.go`, `api/handlers.go` |
| 5.3 | F-14 | Implement `swift_payment.go` fail-closed stub; add `POST /v1/webhooks/swift` | `swift_payment.go`, `api/handlers.go` |
| 5.4 | — | Add structured log fields to all payment events: `reference`, `method`, `provider`, `result` | `api/handlers.go`, `blockchain.go` |
| 5.5 | — | Add Prometheus counters: `payment_webhook_accepted_total`, `payment_webhook_rejected_total{reason}`, `payment_dvp_applied_total`, `payment_expiry_total`, `payment_retry_total{provider,attempt}` | `api/metrics.go` |
| 5.6 | — | Emit `EventPaymentConfirmationRejected` with reject reason for SOC tooling | `blockchain.go` |
| 5.7 | P-6 | Add `POST /v1/admin/pontes/health` endpoint | `api/handlers.go` |
| 5.8 | — | Add operator runbooks: provider outage, replay cache flush, reconciliation, TFR evidence export | `RUNBOOKS.md` |

**Phase 5 Acceptance Criteria**:
- [ ] `go test ./api/...` passes with full webhook test matrix
- [ ] `go test -race -count=3 -timeout=20m .` passes
- [ ] `go test -count=1 ./...` passes
- [ ] Replay protection test passes
- [ ] Prometheus counters appear in `/metrics` output after processing a test webhook

---

### Phase 6 — Rollout and Governance

| # | Work Item |
|---|-----------|
| 6.1 | Enable `GREENHOUSE_PAYMENT_HARDENING=1` in staging; run 48h soak with simulated webhook traffic |
| 6.2 | Capture settlement metrics baseline: DVP apply rate, expiry rate, webhook rejection rate |
| 6.3 | Canary 10% of production trades; compare metrics against baseline |
| 6.4 | Full production cutover when canary metrics stable for 24h |
| 6.5 | Remove `GREENHOUSE_PAYMENT_HARDENING` flag — behavior becomes unconditional |
| 6.6 | Update `PRODUCTION_READINESS_PLAN.md` with evidence, test outputs, and race results |
| 6.7 | Submit ECB Market DLT Operator application (non-code, parallel with Phase 2) |

**Rollback criteria**: DVP apply rate drops below 95% during canary, or any high-severity settlement incident within 24h of cutover.

## 8. Verification Matrix

### Security Verification

| Test scenario | Expected result |
|---------------|----------------|
| Unsigned Modulr webhook in production mode | HTTP 401, no state change |
| Invalid HMAC on Modulr webhook | HTTP 401, no state change |
| Unsigned Pontes webhook | HTTP 401, no state change |
| Unsigned EURC webhook | HTTP 401, no state change |
| Replay of already-processed event (same event-ID) | HTTP 200, no duplicate DVP |
| Payload/signature mismatch | HTTP 401, no state change |

### Correctness Verification

| Test scenario | Expected result |
|---------------|----------------|
| Valid Modulr webhook | DVP applied, `ConfirmedPayments` populated, `PendingSettlements` cleaned |
| Valid EURC webhook | Same |
| Valid Pontes/CeBM webhook | Same |
| Callback with wrong currency | HTTP 422, no state mutation, rejection event emitted |
| Callback with wrong amount | HTTP 422, no state mutation, rejection event emitted |
| Duplicate callback (same event ID) | HTTP 200, idempotent — no second DVP |
| Expired instruction callback | HTTP 200, no-op (instruction already removed) |
| Oracle signing failure | HTTP 500, provider retries, no partial state created |

### Pontes / CeBM Verification

| Test scenario | Expected result |
|---------------|----------------|
| EUR trade with Pontes registered | `SettlementCeBM` selected, `RegisterSettlement` called async |
| EUR trade without Pontes registered | `SettlementEURC` selected |
| CeBM instruction created outside T2 hours | `T2QueuedUntil` set, `ExpiresAt` extended, operator log warning |
| CeBM registration fails at Pontes | Instruction stays pending, `EventPaymentRegistrationFailed` emitted |
| Admin retry endpoint called | `RegisterSettlement` retried, `PontesTransactionID` populated |

### Resilience Verification

| Test scenario | Expected result |
|---------------|----------------|
| Provider returns 503 | Retried up to 3 times with 0ms / 500ms / 2s backoff |
| Provider returns 400 | No retry, immediate error returned |
| Context cancelled during retry sleep | Immediate abort, cancellation error |
| Pontes API returns 404 for transactionID | `PaymentStatusFailed` (terminal — no retry) |

### Regression Verification

| Command | Must pass |
|---------|-----------|
| `go test -run "TestMockPayment\|TestOracle\|TestConfirmAndSettle\|TestExpire\|TestModulr\|TestPontes\|TestEURC" -count=1 .` | All |
| `go test -race -count=3 -timeout=20m .` | All |
| `go test -count=1 ./...` | All |

## 9. Dependencies and Ordering

```
Phase 0 (baseline lock)
    │
    ▼
Phase 1 (DVP fix + auth)        ◄── BLOCKING for production and Pontes pilot
    │
    ├──► Phase 2 (Pontes wiring) ◄── target July 2026 (8 weeks before pilot)
    │
    ├──► Phase 3 (lifecycle)     ──► can begin when Phase 1 is stable in test
    │
    └──► Phase 4 (concurrency)   ──► can run in parallel with Phase 3
         │
         ▼
     Phase 5 (observability + tests)  ◄── requires Phases 1–4 stable
         │
         ▼
     Phase 6 (rollout)
```

Phase 1 is the only hard gate — it must be reviewed, merged, and stable before any subsequent phase begins. Phases 2, 3, and 4 may be developed in parallel branches after Phase 1 lands.

## 9. Open Decisions

**Decision 1 — Amount tolerance policy**
- **Option A (recommended)**: Strict exact match. Any deviation returns HTTP 422. Protects against rounding-induced double settlements.
- **Option B**: Provider-specific tolerance band (e.g. ±0.01 for Modulr fee rounding). More permissive; requires per-provider configuration and audit logging of all tolerance-matched payments.
- **Default**: Option A. Revisit if Modulr or Pontes settlement confirms demonstrate consistent sub-cent rounding.

**Decision 2 — Webhook replay cache persistence**
- **Option A (recommended)**: In-memory map with 48-hour TTL. Simple, covers all three providers' retry windows. Lost on restart (acceptable — providers will retry and `ConfirmedPayments` prevents double DVP).
- **Option B**: bbolt persistence. Survives node restart; adds I/O on every webhook. Required if event-driven consumers need strict exactly-once delivery guarantees after restart.
- **Default**: Option A. Upgrade to Option B if audit requirements demand post-restart idempotency proof.

**Decision 3 — `ContextualPaymentProvider` interface rollout**
- **Option A (recommended)**: New non-breaking interface with `*Ctx` method variants. Existing providers satisfy `PaymentProvider`; only providers that implement `ContextualPaymentProvider` receive request/lifecycle contexts.
- **Option B**: Change `PaymentProvider` interface signatures to accept `context.Context`. Breaking change — requires updating mock, all three production providers, and all tests simultaneously.
- **Default**: Option A preserves backward compatibility across the Pontes pilot timeline.

**Decision 4 — `ConfirmedPayments` retention and persistence**
- **Option A (recommended)**: Persist to bbolt alongside `SaveState`; prune in-memory entries older than 90 days (EMIR/MiCA retention minimum). Late-arriving replays fall back to bbolt lookup.
- **Option B**: Persist to bbolt indefinitely, no in-memory pruning. Correct but may impact startup time on long-running nodes.
- **Default**: Option A with 90-day window. Configurable via `GREENHOUSE_PAYMENT_RETENTION_DAYS`.

## 10. Execution Notes

- Webhook acceptance and DVP settlement are separable concerns — the DVP path should never depend on the provider's direct-call semantics. This is the root of F-1 and must guide all refactoring.
- Every rejection path needs a deterministic reason code (MiCA Article 80 incident reporting requires classifiable rejection reasons within 24h of incident).
- For the Pontes pilot: `PontesTransactionID`, `ISO20022MsgID`, and `T2SettlementDate` must be on-demand accessible for ECB audit. These fields must be persisted to the block store alongside the instruction.
- HTTP response codes are part of the provider protocol — returning 200 on a settlement failure silently suppresses provider retries. Use 500 for transient failures (oracle down, internal error), 422 for semantic mismatches (wrong amount/currency — provider should not retry), and 401/403 for authentication failures.
- The mock provider's `ConfirmPayment` is the only legitimate direct-call path. All production providers are webhook-driven. This distinction must be enforced by the type system (F-3 fix notes) rather than by convention.

## 11. Artifact Update Checklist

After implementation of each phase:

1. Update `PRODUCTION_READINESS_PLAN.md` Item 26 with phase completion dates, test evidence, and race test pass output.
2. Record `go test -race -count=3` output hash per phase as evidence artefact.
3. Record canary metrics at Phase 6 cutover (DVP apply rate, webhook rejection rate, expiry rate, retry rate) and attach to this document.
4. Record Pontes pilot ECB application submission date, applicant reference, and anticipated response date.
5. Create `RUNBOOKS.md` with the following runbooks:
   - Provider outage response (which rails degrade gracefully, escalation path)
   - Replay cache manual flush procedure (and when it is safe to do so)
   - Pontes registration retry procedure (`POST /v1/payments/{tradeID}/register`)
   - TFR 2023/1113 evidence export for regulatory inspection
   - `ConfirmedPayments` retention prune procedure and audit log generation
6. On completing Phase 2, submit ECB Market DLT Operator application and record submission in this checklist.
