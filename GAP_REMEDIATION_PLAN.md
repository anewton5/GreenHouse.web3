# GreenHouse — Gap Remediation Plan

> Last reviewed: May 2026  
> Scenario: UK startup tokenises Series A equity via Luxembourg SPV → raises from German / Luxembourg investors → quarterly secondary liquidity windows.

This document classifies every identified gap, details the root cause, the exact code or integration change required, the acceptance criteria, and the build order. Gaps are grouped into three tracks: **Code-Only** (can be closed in one session), **Integration** (requires third-party accounts / config), and **Regulatory / Architecture** (multi-week workstreams).

---

## Track 1 — Code-Only Gaps (Immediate)

---

### Gap 1 — Issuer Holds No Tokens After Tokenisation

**Severity:** Critical — the primary offering flow is broken at step 1.

**Root Cause:**  
`handleCreateAsset` creates the `Asset` record and calls `SealBlock` with an `AssetTxTypeIssue` transaction, but it does not create the corresponding `AssetHolding` for the issuer. `ApplyAssetTransaction` would create the holding if `at.Tx.Receiver` were set — but the issue transaction in `SealBlock` has an empty `Receiver` field.  

Result: the issuer wallet has zero tokens. `CirculatingSupply` stays 0. No secondary transfer is possible.

**Fix (file: `api/handlers.go` → `handleCreateAsset`):**

After `s.bc.Assets[assetID] = a`, insert:

```go
// Create issuer's initial holding at full supply.
holdingKey := gonetwork.HoldingKey(walletKey, assetID)
s.bc.Holdings[holdingKey] = &gonetwork.AssetHolding{
    AssetID:  assetID,
    HolderID: walletKey,
    Balance:  req.TotalSupply,
    // No lockup on the issuer's own allocation — they hold, not acquire via secondary.
}
a.CirculatingSupply = req.TotalSupply
```

**Acceptance Criteria:**
- `POST /v1/assets` returns the asset with `circulating_supply == total_supply`
- `GET /v1/holdings/{issuerWalletKey}` immediately shows the asset
- `POST /v1/orders` (ask) by the issuer succeeds on the first try
- Existing `assets_test.go` tests continue to pass

---

### Gap 2 — Lockup Not Applied on Holding Creation ✅ Already Fixed

**Status:** CLOSED. `ApplyAssetTransaction` in `assets.go` already contains the `lockupEnd()` closure that correctly sets `LockedUntil` for both `AssetTxTypeIssue` and `AssetTxTypeTransfer` cases. Validate step 7 enforces it.  
No further action needed.

---

### Gap 3 — ROFR Never Triggered in Transfer Pipeline

**Severity:** High — ROFR is a key differentiator (SCOPE doc) and a legal obligation for many shareholders' agreements. The feature is fully implemented in `corporate.go` but silently bypassed.

**Root Cause:**  
`AssetTransaction.Validate` in `assets.go` has 9 validation steps. Step 9 calls `CheckTransferEligibility` for credential checks. There is no call to `CheckROFR`. Since `Validate` is the sole gate before `ApplyAssetTransaction`, transfers on ROFR-enabled assets proceed without notifying existing holders.

**Fix (file: `assets.go` → `Validate`):**

`CheckROFR` requires the `pendingActions map[string]*CorporateAction`, which is not available inside `assets.go`'s `Validate` signature (it is a method on `AssetTransaction` taking only `assets`, `holdings`, `credentials`, and variadic `screener`). Two viable approaches:

**Approach A (recommended — minimal footprint):** Add a variadic fifth parameter `pendingActions ...map[string]*CorporateAction`. Existing 4-argument call sites compile unchanged.

```go
func (at *AssetTransaction) Validate(
    assets map[string]*Asset,
    holdings map[string]*AssetHolding,
    credentials map[string]*CredentialAttestation,
    screener ...AMLScreener,
) error { ... }
```

becomes a two-step change:

1. Rename the variadic to accept both the screener and pending actions via a new `ValidateOptions` struct — **or** — keep the screener variadic and add a separate `pendingActions` parameter before `screener`:

```go
func (at *AssetTransaction) Validate(
    assets map[string]*Asset,
    holdings map[string]*AssetHolding,
    credentials map[string]*CredentialAttestation,
    pendingActions map[string]*CorporateAction, // nil = skip ROFR check
    screener ...AMLScreener,
) error {
    ...
    // After step 8 (MaxHolders), before step 9 (credentials):
    if at.TxType == AssetTxTypeTransfer && pendingActions != nil {
        if triggered, _, err := CheckROFR(at, asset, holdings, pendingActions); triggered {
            return err // ErrROFRTriggered
        }
    }
    ...
}
```

2. Update all call sites in `dBFT.go`, `p2p.go`, and any tests to pass `bc.PendingCorporateActions` / `nil`.

**Impact on call sites:**
- `dBFT.go` line 247: `tx.Validate(bc.Assets, bc.Holdings, bc.Credentials, bc.PendingCorporateActions, bc.AMLScreener)`
- `p2p.go` line 551: same pattern
- All test files: pass `nil` for pendingActions (no behaviour change)

**Acceptance Criteria:**
- `NewAsset` with `HasROFR: true` + transfer attempt returns `ErrROFRTriggered`
- `bc.PendingCorporateActions` contains the created ROFR action
- Transfer with `HasROFR: false` passes unaffected
- Existing transfer tests (no ROFR) continue to pass unchanged

---

### Gap 4 — No API to Register Prospectus Exemption

**Severity:** High — the 149-retail-investor-per-jurisdiction cap (`CheckProspectusLimits`) is wired into `finalizeBlock` and `Validate`, but `bc.ProspectusExemptions` is always empty because there is no API endpoint to populate it. The compliance enforcement is fully built but unreachable from the UI.

**Fix (files: `api/handlers.go`, `api/server.go`):**

**New endpoint: `POST /v1/assets/{id}/exemption`**

```
Body:
{
  "basis": "prospectus_art1_4",          // or "qib_only" / "dlt_pilot"
  "max_retail_per_jurisdiction": 149,
  "max_ticket_size_eur": 100000,         // 0 = no limit
  "jurisdiction_coverage": ["DE","LU","IE","NL","FR"]  // empty = any EU
}
```

- Only the asset issuer (JWT wallet key == `asset.Issuer`) may register an exemption
- One exemption per asset (conflict → 409)
- Returns the created `ProspectusExemption` as JSON

**New endpoint: `GET /v1/assets/{id}/exemption`**

- Returns the current exemption including live `retail_holders_by_jurisdiction` counts
- Any authenticated wallet can read (needed for investor eligibility self-check)

**Acceptance Criteria:**
- `POST /v1/assets/{id}/exemption` by non-issuer → 403
- Duplicate POST → 409
- After registering exemption + 149 retail transfers in DE, the 150th returns an error in `Validate`
- `GET /v1/assets/{id}/exemption` returns live counts updated after each block

---

### Gap 5 — No API for MiFID II Suitability Assessment

**Severity:** Medium (only affects warrants and convertibles — `CheckSuitability` is called in `Validate` for these).

**Root Cause:**  
`bc.SuitabilityAssessments` is initialised but never populated. There is no endpoint to submit an assessment from a compliance officer or auto-generate one from KYC data. Warrants and convertibles are effectively blocked for all investors.

**Fix (files: `api/handlers.go`, `api/server.go`):**

**New endpoint: `POST /v1/suitability`**

```
Body (admin/compliance-officer call):
{
  "wallet_key": "<base64-ed25519-public-key>",
  "asset_id": "<asset-id>",
  "has_sufficient_knowledge": true,
  "has_sufficient_experience": true,
  "can_absorb_loss": true
}
```

- Requires `jwtAdmin` middleware (compliance officers only)
- Derives `Suitable = knowledge && experience && can_absorb_loss`
- `SuitabilityKey(walletKey, assetID)` → stored in `bc.SuitabilityAssessments`
- Returns the created `SuitabilityAssessment`

**New endpoint: `GET /v1/suitability/{walletKey}/{assetID}`**

- JWT-authenticated; any wallet can query its own assessment, admin can query any
- Returns 404 if no assessment exists (useful for investor portal pre-check)

**Acceptance Criteria:**
- Attempt to transfer a warrant without an assessment → `Validate` returns suitability error
- `POST /v1/suitability` with `suitable=true` → subsequent transfer succeeds
- `POST /v1/suitability` with `suitable=false` → transfer still blocked
- Non-admin call to `POST /v1/suitability` → 403

---

## Track 2 — Integration Gaps (Multi-day)

---

### Gap 6 — No Live Fiat Payment Provider

**Severity:** Critical for production — all trades confirm instantly via `MockPaymentProvider`.

**Provider options (comparison):**

| Provider | EUR support | Virtual IBAN | Webhook | Est. onboarding |
|---|---|---|---|---|
| Modulr | Yes (SEPA) | Yes | Yes (HMAC) | 2–4 weeks |
| Currencycloud (Visa) | Yes | Yes | Yes | 1–2 weeks |
| ClearBank | GBP-first | Yes | Yes | 4–8 weeks |
| EURC (Circle) | Native EUR stablecoin | No — on-chain | WebSocket | 1 week |

**Recommended path:** Modulr for EUR (SEPA Instant) + Faster Payments for GBP; EURC as a parallel rail for investors who prefer on-chain settlement.

**Implementation pattern:**
```go
// New file: modulr_payment.go
type ModulrPaymentProvider struct {
    apiKey    string
    apiSecret string
    baseURL   string
    client    *http.Client
}
// Implements PaymentProvider interface — CreateVirtualAccount, GetPaymentStatus, ConfirmPayment
// Production webhooks arrive at POST /v1/webhooks/payment (handler already exists)
// HMAC verification in handlePaymentWebhook already wired — needs live key in env
```

**Acceptance Criteria:**
- `CreateVirtualAccount` returns a real Modulr virtual IBAN
- Sandbox payment triggers `POST /v1/webhooks/payment` → `ConfirmPayment` → DVP transfer applied
- `PaymentStatusPending` → `PaymentStatusConfirmed` lifecycle visible in trade history

---

### Gap 7 — No Live AML Screening

**Severity:** Regulatory blocker.

**Provider options:**

| Provider | Sanctions | PEP | On-chain analytics | API |
|---|---|---|---|---|
| ComplyAdvantage | EU/UN/OFAC | Yes | No | REST |
| Elliptic | No | No | Yes (wallet scoring) | REST |
| Chainalysis | No | No | Yes | REST |
| Refinitiv World-Check | Yes | Yes | No | REST |

**Recommended path:** ComplyAdvantage for sanctions + PEP screening (covers both sender wallet key and underlying beneficial owner from KYC data), Elliptic for on-chain wallet risk scoring.

**Implementation pattern:**
```go
// New file: complyadv_aml.go
type ComplyAdvantageScreener struct {
    apiKey  string
    baseURL string
    client  *http.Client
}
// Implements AMLScreener interface — ScreenTransaction maps to /searches endpoint
// Cache results for 24h (watchlists don't change intra-day) to reduce API costs
```

**Acceptance Criteria:**
- OFAC SDN wallet key → `AMLSeverityBlock` → transfer rejected
- Clean wallet → nil alert → transfer proceeds
- Response cache hit < 1ms; API call < 500ms P95

---

### Gap 8 — No State Persistence

**Severity:** Production blocker — server restart loses all data.

**Recommended architecture:**

```
PostgreSQL (primary store)
  ├── assets            (asset registry)
  ├── holdings          (wallet balances)
  ├── orders + trades   (order book state + execution history)
  ├── credentials       (on-chain attestations)
  ├── blocks            (full block history — source of truth)
  ├── deals             (deal lifecycle)
  ├── spv_wrappers      (SPV registry)
  └── events            (append-only event log for FiDA / audit)
```

**Implementation pattern:**
```go
// New file: store/store.go
type StateStore interface {
    SaveAsset(a *Asset) error
    GetAsset(id string) (*Asset, error)
    SaveHolding(h *AssetHolding) error
    // ... one method per entity type
    SaveBlock(b *Block) error
    LoadState(bc *Blockchain) error  // called at startup to hydrate in-memory state
}

// New file: store/postgres.go
type PostgresStore struct { db *sql.DB }
// Implements StateStore; called from finalizeBlock after each block is committed
```

**Migration tooling:** `golang-migrate` or `goose` for schema migrations under `store/migrations/`.

**Acceptance Criteria:**
- Restart with populated database → state fully restored
- `go test ./store/...` with a test-container PostgreSQL passes
- No data loss for any entity type across restart

---

### Gap 9 — No Thread Safety on Blockchain Maps

**Severity:** High (data corruption under concurrent requests).

**Fix:**  
Add `sync.RWMutex` to `Blockchain` struct. Wrap all map reads with `RLock`/`RUnlock`, writes with `Lock`/`Unlock`.

```go
type Blockchain struct {
    mu sync.RWMutex   // guards Assets, Holdings, OrderBooks, Credentials, Trades, etc.
    ...
}
```

All HTTP handlers that read state: `bc.mu.RLock()` / defer `bc.mu.RUnlock()`.  
All handlers that write state: `bc.mu.Lock()` / defer `bc.mu.Unlock()`.  
`finalizeBlock` (called from consensus path): holds a write lock for its full duration.

Note: `MockAMLScreener` already has its own mutex — this is correct; do not use the blockchain mutex inside the screener.

---

### Gap 10 — FX Rates Always 1:1

**Severity:** Medium (affects tax report accuracy; not a functional blocker for primary raises).

**Fix:** ECB Daily Reference Rate feed or Open Exchange Rates API.

```go
// New file: ecb_oracle.go
type ECBValuationOracle struct {
    client        *http.Client
    cache         map[string]float64 // "EUR:GBP" → rate
    cacheExpiry   time.Time
}
// Fetches from https://data-api.ecb.europa.eu/service/data/EXR/ — free, no API key
// Cache for 24h (ECB publishes once per day at ~16:00 CET)
```

---

### Gap 11 — UK Jurisdiction Rules Not Configured

**Fix:** Pre-configure `JurisdictionRule` for `GB` in `NewBlockchain`:

```go
// In NewBlockchain, after JurisdictionRules initialisation:
bc.JurisdictionRules["GB"] = &JurisdictionRule{
    CountryCode:         "GB",
    MaxRetailHolders:    149,  // UK Prospectus Regulation equivalent
    RequiresSuitability: false,
    MinTicketSizeEUR:    0,
    MaxTicketSizeEUR:    0,
    // UK FCA Certified High Net Worth / Sophisticated Investor exemptions
    // are enforced via InvestorClass checks in AccreditedOnly, not ticket size
}
```

The investor onboarding flow needs a GB-specific credential path mapping to FCA Financial Promotions Order exemptions (CHNW / sophisticated investor certificate).

---

## Track 3 — Regulatory / Architecture Gaps

---

### Gap 12 — EU DLT Pilot Regime Authorisation

**Severity:** Existential for operating as an MTF (phase 2 target).

**Background:**  
EU Regulation 2022/858 creates a sandbox for DLT-based market infrastructures. It allows a single entity to operate as both a DLT Market Infrastructure (combining MTF + CSD roles), permitting atomic DVP settlement without a separate CSD intermediary — exactly what GreenHouse's architecture already implements.

**Process:**
1. Designate a home EU member state NCA (ESMA coordinates). Luxembourg (CSSF) or Ireland (CBI) are natural candidates given the SPV domicile.
2. Submit application under Article 8 (DLT MTF) with:
   - Technical documentation of the DLT network (consensus, finality, key management)
   - Rulebook (admission criteria, trading rules, default management)
   - Legal opinion on instrument classification
   - Capital requirements compliance (€730K minimum for MTF)
3. ESMA issues opinion within 3 months; NCA grants authorisation.
4. Phase 1 (until authorisation): operate as OTC matching service for professional investors only — no retail, no MTF licence required.

**Workstream owner:** Legal / Regulatory counsel  
**Timeline:** 6–12 months from application submission

---

### Gap 13 — Production Key Management

**Severity:** High (KMSKeyProvider stub is misleading).

**Current situation:** `keymanager.go` `KMSKeyProvider.Sign` is a no-op stub that records calls only. `kms_oracle.go` uses envelope encryption (correct) but only for the Oracle key.

**Recommended architecture for production:**
- **Wallet signing keys:** Client-side only (browser `SubtleCrypto` or hardware wallet). Private keys must never leave the client. ✅ Already the model in the portals.
- **Oracle / registry keys:** Google Cloud KMS (`EC_SIGN_ED25519` key spec) or HashiCorp Vault Transit (`ed25519` type). Replace `kms_oracle.go`'s envelope decrypt with a direct Cloud KMS sign call.
- **Bootstrap node key:** AWS Secrets Manager or GCP Secret Manager for the seed; loaded once at startup.

---

### Gap 14 — Multi-Node Production Deployment

**Severity:** Medium (consensus works; deployment is untested with multiple real nodes).

**Gaps identified:**
- `dBFT.go` delegate election uses in-memory `LockedWallets` — no network propagation
- Shard assignment is static (set at bootstrap); no dynamic resharding
- No slashing for byzantine delegates
- `P2PNode` uses libp2p with mDNS peer discovery — works on LAN, needs DHT bootstrap nodes for internet deployment

**Workstream:** DevOps / Protocol engineering (separate from application layer gaps)

---

## Build Order Summary

### Immediate (this session — code only)

| # | Gap | File(s) | Est. lines |
|---|---|---|---|
| 1 | Issuer initial holding | `api/handlers.go` | ~8 |
| 3 | Wire CheckROFR into Validate | `assets.go`, `dBFT.go`, `p2p.go` | ~20 |
| 4 | Prospectus exemption API | `api/handlers.go`, `api/server.go` | ~80 |
| 5 | Suitability assessment API | `api/handlers.go`, `api/server.go` | ~80 |

### Short-term (1–2 sprint)

| # | Gap | Owner | Effort |
|---|---|---|---|
| 9 | Thread safety (mutex) | Engineering | 1 day |
| 11 | UK jurisdiction rules | Engineering | 2h |
| 10 | FX rates oracle | Engineering | 1 day |
| 6 | Modulr payment integration | Engineering + Modulr onboarding | 3–5 days |
| 7 | ComplyAdvantage AML | Engineering + CA onboarding | 2–3 days |

### Medium-term (1–2 months)

| # | Gap | Owner | Effort |
|---|---|---|---|
| 8 | PostgreSQL persistence | Engineering | 1–2 weeks |
| 13 | Production KMS | Engineering + GCP/AWS setup | 3 days |
| 14 | Multi-node deployment | DevOps | 1–2 weeks |

### Long-term (regulatory track)

| # | Gap | Owner | Effort |
|---|---|---|---|
| 12 | DLT Pilot Regime authorisation | Legal / Regulatory | 6–12 months |

---

## Test Coverage Targets

Each code-only gap must ship with matching test cases:

| Gap | New test functions |
|---|---|
| 1 | `TestCreateAsset_IssuerHoldingCreated`, `TestCreateAsset_CirculatingSupplySet` |
| 3 | `TestValidate_ROFRTriggered`, `TestValidate_ROFRSkippedWhenFalse`, `TestValidate_ROFRNilPendingActions` |
| 4 | `TestProspectusExemption_CreateAndEnforce`, `TestProspectusExemption_NonIssuerForbidden`, `TestProspectusExemption_CapEnforced` |
| 5 | `TestSuitabilityAssessment_WarrantBlockedWithout`, `TestSuitabilityAssessment_WarrantAllowedWith`, `TestSuitabilityAssessment_EquityUnaffected` |
