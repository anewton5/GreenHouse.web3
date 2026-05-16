# GreenHouse — Technical Architecture Review & Development Plan

> **Reviewed:** May 2026  
> **Scope:** On-chain/off-chain asset consistency, capital issuance complexity, automated compliance and regulation, governance, and oracle infrastructure.  
> **Basis:** Full static review of the Go source tree (`assets.go`, `compliance.go`, `corporate.go`, `aml.go`, `identity.go`, `blockchain.go`, `kms_oracle.go`, `reporting.go`, `spv.go`, `liquidity.go`, `deal.go`, `payment.go`, `wallets.go`, `dBFT.go`, `orderbook.go`, `operator_identity.go`, `onfido_identity.go`, `keymanager.go`, `api/handlers.go`, and all `*_test.go` files).  
> **Cross-references:** Existing `GAP_REMEDIATION_PLAN.md` (Gaps 1–14) and `IMPLEMENTATION_PLAN.md` are preserved in full. This document extends them with the architectural review findings (Gaps G-01 through G-27) and consolidates both into a unified implementation plan.

---

## Executive Summary

The GreenHouse codebase is architecturally well-structured for a Phase 0 simulation. The core primitives are sound: Ed25519 signing is used consistently throughout; all critical objects (assets, orders, SPV wrappers, corporate actions, liquidity windows) carry issuer/proposer signatures; the dBFT consensus algorithm provides deterministic finality; and the compliance layer (`compliance.go`) already encodes MiFID II suitability, EU Prospectus Regulation exemption caps, and per-jurisdiction transfer rules at the logic level.

However, the review identified **27 gaps** across four domains that must be addressed before the platform can be considered production-ready or submitted to a regulator. These range from immediate code-only fixes (accessible in a single engineering session) to multi-week architectural workstreams.

The most critical findings are:

1. **The prospectus exemption 149-investor cap and MiFID II suitability checks are fully built but unreachable** — `bc.ProspectusExemptions` and `bc.SuitabilityAssessments` are always empty because no API endpoints exist to populate them. EU distribution is a regulatory blocker until Gaps G-01 and G-02 are closed.
2. **`CirculatingSupply` can diverge silently from the actual sum of holdings** — two independent write paths (`ApplyAssetTransaction` and `handleCreateAsset`) update it without reconciliation.
3. **The oracle is a single Ed25519 key** — a compromise invalidates all historical payment signatures. A threshold scheme is mandatory before DLT Pilot Regime authorisation.
4. **Drag-along, tag-along, and dividend execution are declared but not implemented** — their `CorporateActionType` constants exist but the execution functions that act on them do not.
5. **The `ValuationOracle` and FX rates always return `1.0` for unknown inputs** — every cross-currency compliance check and every FiDA holdings report is numerically wrong for any real asset.

---

## Part I — On-Chain / Off-Chain Asset Consistency

### Existing foundations

| Component | File | Status |
|---|---|---|
| `Asset` struct with `TotalSupply`, `CirculatingSupply`, `LegalDocHash` | `assets.go` | ✅ |
| `IssuerSignature` covering all asset fields at creation | `assets.go` | ✅ |
| `AssetHolding` map tracking per-wallet balances | `assets.go` | ✅ |
| `SPVWrapper` binding on-chain participation notes to SPV legal identity | `spv.go` | ✅ |
| `UpdateNAV` on `SPVWrapper` producing a signed `SPVTransaction` | `spv.go` | ✅ |
| `ApplyAssetTransaction` mutating holdings atomically with lockup enforcement | `assets.go` | ✅ |
| `VerifyIssuerSignature` on `Asset` | `assets.go` | ✅ (declared but never called in validation) |

---

### Gap G-01 — No proof that on-chain token supply matches off-chain share register

**Severity:** Critical  
**Regulatory impact:** Any regulator or auditor examining the chain can construct a token issuance that is not backed by real-world shares, with no cryptographic evidence to the contrary.

**Root cause:** `NewAsset` accepts any `TotalSupply` value asserted by the issuer. There is no co-signature from the SPV administrator or any other independent party confirming that exactly that number of shares have been reserved in the SPV's register or cap table. For `AssetTypeParticipationNote`, where the SPV is the legal vehicle, this is a direct legal risk.

**Current code path:**
```
POST /v1/assets
  → handleCreateAsset (api/handlers.go)
  → Asset{} created with Issuer = walletKey from JWT
  → SealBlock() — single-signature block commit
```

There is no step where `SPVWrapper.SPVAdminKey` is required to co-sign the issuance.

**Required change — Dual-authority issuance model:**

1. Introduce a `TwoPartyIssueRequest` struct in `assets.go`:

```go
type TwoPartyIssueRequest struct {
    AssetID         string  `json:"asset_id"`
    TotalSupply     float64 `json:"total_supply"`
    SPVID           string  `json:"spv_id"`
    IssuerKey       string  `json:"issuer_key"`
    AdminKey        string  `json:"admin_key"`
    IssuerSignature []byte  `json:"-"`
    AdminSignature  []byte  `json:"-"`
}
```

2. `AssetTransaction.Validate` must enforce `RequiredSigs = 2` for `AssetTxTypeIssue` when `asset.AssetType == AssetTypeParticipationNote`.

3. New API endpoint: `POST /v1/assets/{id}/countersign` — callable only by the wallet whose key matches `SPVWrapper.SPVAdminKey`. Sets `AdminSignature` and transitions the asset to `CirculatingSupply > 0`.

4. Until countersigned, `handlePlaceOrder` must reject ask orders from the issuer wallet on this asset.

**Acceptance criteria:**
- `POST /v1/assets` with `asset_class: "participation_note"` creates asset with `circulating_supply = 0`
- `POST /v1/orders` ask on an uncountersigned participation note → 409 "asset awaiting admin countersignature"
- `POST /v1/assets/{id}/countersign` by non-SPV-admin → 403
- After countersign → `circulating_supply == total_supply` and ask orders succeed

---

### Gap G-02 — `VerifyIssuerSignature` is never called in the validation pipeline

**Severity:** High  
**Root cause:** `VerifyIssuerSignature` is defined on `Asset` and used in tests, but it is never called from `AssetTransaction.Validate`, `ApplyAssetTransaction`, or any API handler. A tampered asset record (e.g., `TotalSupply` inflated after creation) would pass all validation checks undetected.

**Required change:**

In `AssetTransaction.Validate` (step 1, after confirming the asset exists), add:

```go
senderPub, err := PublicKeyFromString(asset.Issuer)
if err != nil {
    return fmt.Errorf("asset issuer key is malformed: %w", err)
}
if !asset.VerifyIssuerSignature(senderPub) {
    return fmt.Errorf("asset %s has an invalid issuer signature: record may have been tampered", asset.ID)
}
```

**Acceptance criteria:**
- Mutating `asset.TotalSupply` after creation → next transfer on that asset returns "invalid issuer signature"
- Normal transfer on unmodified asset → unaffected

---

### Gap G-03 — `LegalDocHash` is set-once with no amendment trail

**Severity:** High  
**Root cause:** `AssetMetadata.LegalDocHash` is committed at asset creation. There is no on-chain record of subsequent document amendments (e.g., amended shareholders' agreement, updated subscription terms). A stale or superseded hash is indistinguishable from a current one.

**Required change — `LegalDocAmendment` struct (new file: `legal_docs.go`):**

```go
type LegalDocAmendment struct {
    ID              string `json:"id"`
    AssetID         string `json:"asset_id"`
    PreviousDocHash string `json:"previous_doc_hash"`
    NewDocHash      string `json:"new_doc_hash"`
    AmendedAt       int64  `json:"amended_at"`
    IssuerSignature []byte `json:"-"`
    AdminSignature  []byte `json:"-"` // required for participation notes
}
```

- `Blockchain.LegalDocAmendments map[string][]*LegalDocAmendment` — assetID → chronological list.
- `CurrentLegalDocHash(assetID string) string` helper that walks the amendment log and returns the latest hash.
- `VerifyIssuerSignature` on `Asset` should be extended to also verify that the `LegalDocHash` matches the current amendment log tip.

**Acceptance criteria:**
- `GET /v1/assets/{id}` returns `current_legal_doc_hash` resolved from the amendment log
- Amendment by non-issuer or (for participation notes) without admin co-sig → 403
- Amendment log is included in the FiDA holdings report for audit purposes

---

### Gap G-04 — `CirculatingSupply` has two independent write paths that can diverge

**Severity:** Critical  
**Root cause:** `CirculatingSupply` is written in two places:
1. `ApplyAssetTransaction` in `assets.go` — increments on `AssetTxTypeIssue`, decrements on `AssetTxTypeRedeem`
2. `handleCreateAsset` in `api/handlers.go` — sets `a.CirculatingSupply = req.TotalSupply` directly, without going through `ApplyAssetTransaction`

These paths are not coordinated. Any future code that adds a third write path, or that calls only one of these, will silently diverge the supply figure. If `CirculatingSupply` is wrong, every subsequent compliance check that references it (prospectus cap, drag-along threshold, dividend calculation) produces an incorrect result.

**Required change — Supply reconciliation in `SealBlock`:**

```go
// In blockchain.go, called from SealBlock after every block:
func (bc *Blockchain) assertCirculatingSupplyConsistency() {
    for assetID, asset := range bc.Assets {
        var sum float64
        suffix := ":" + assetID
        for key, h := range bc.Holdings {
            if strings.HasSuffix(key, suffix) {
                sum += h.Balance
            }
        }
        if math.Abs(sum-asset.CirculatingSupply) > 1e-9 {
            // In development: panic
            // In production: emit a CRITICAL log event and alert the compliance stream
            log.Printf("CRITICAL: CirculatingSupply mismatch for asset %s: recorded=%.6f actual=%.6f",
                assetID, asset.CirculatingSupply, sum)
        }
    }
}
```

Remove the direct write in `handleCreateAsset` and route all supply updates through `ApplyAssetTransaction`.

**Acceptance criteria:**
- `POST /v1/assets` followed by a manual mutation of `CirculatingSupply` in tests → reconciliation detects drift
- Sum of all holdings for any asset always equals `CirculatingSupply` after every sealed block

---

### Gap G-05 — Capital issuance scenarios beyond single-event issuance are not modelled

**Severity:** Medium–High  
**Root cause:** The platform models a single issuance event at asset creation. Real private placements involve complex capital structures that the current code cannot represent.

| Scenario | Current state | Consequence of gap |
|---|---|---|
| Tranched / drawdown issuance | Not modelled — `TotalSupply` is fixed at creation | Startups cannot model committed-but-undrawn capital |
| Rights issue (existing holders buy pro-rata) | Not modelled | No pre-emption right for new issuances; dilution is unchecked |
| Secondary offering at a new price | Not modelled | No concept of offering price distinct from NAV in the issuance flow |
| Warrant exercise → new equity | `AssetTypeWarrant` declared | No conversion function exists; warrant holders cannot exercise |
| Convertible note conversion | `AssetTypeConvertible` declared | No conversion trigger, no conversion ratio field, no mechanics |
| Anti-dilution (broad-based weighted average) | Not modelled | Series A investors have no protection against down-rounds |
| Capital call on SPV participation notes | `SPVTxTypeCapitalCall` type declared in `spv.go` | No enforcement — holders are not debited, no escrow is created |

**Required changes — new file `instrument_lifecycle.go`:**

```go
// TrancheIssuanceRequest allows the issuer to draw down against an authorised
// TotalSupply in multiple tranches. Each tranche creates an AssetTxTypeIssue
// transaction for the tranche amount only.
type TrancheIssuanceRequest struct { ... }

// RightsIssueOffer creates a time-limited offer to existing holders to subscribe
// for new shares at a fixed price, pro-rata to their current holding.
type RightsIssueOffer struct { ... }

// WarrantExerciseRequest converts a warrant holding into the underlying equity
// at the strike price. Requires the underlying equity asset to exist on-chain.
type WarrantExerciseRequest struct {
    WarrantAssetID    string
    EquityAssetID     string  // target asset
    UnitsToExercise   float64
    StrikePrice       float64
    ExerciserKey      string
    ExerciserSignature []byte
}

// ConvertibleConversionRequest converts a convertible note into equity at the
// conversion ratio, triggered either by a qualifying financing event or maturity.
type ConvertibleConversionRequest struct { ... }

// AntiDilutionAdjustment calculates and applies broad-based weighted-average
// anti-dilution protection to existing preference shareholders.
func AntiDilutionAdjustment(
    asset *Asset,
    newSharesIssued float64,
    newIssuancePrice float64,
    holdings map[string]*AssetHolding,
) (adjustments map[string]float64, err error) { ... }
```

---

## Part II — Automated Compliance & Regulation

### Existing foundations

| Component | File | Status |
|---|---|---|
| `ProspectusExemption` with per-jurisdiction retail caps | `compliance.go` | ✅ Logic complete |
| `CheckProspectusLimits` enforcing Art 1(4) EU 2017/1129 | `compliance.go` | ✅ Logic complete |
| `UpdateRetailCounts` rebuilding jurisdiction counts per block | `compliance.go` | ✅ Logic complete |
| `SuitabilityAssessment` for MiFID II complex instruments | `compliance.go` | ✅ Logic complete |
| `CheckSuitability` gating warrants and convertibles | `compliance.go` | ✅ Called from `Validate` |
| `JurisdictionRule` with per-country asset-type blocks and ticket sizes | `compliance.go` | ✅ Logic complete |
| `ApplyJurisdictionRule` enforcing per-country limits | `compliance.go` | ✅ Logic complete |
| `AMLScreener` interface + `MockAMLScreener` | `aml.go` | ✅ Interface clean |
| `ProspectusWarning` at 90% retail cap | `aml.go` | ✅ Type declared |
| KYC credential lifecycle with `KYCStatusExpired` | `identity.go` | ✅ Types declared |
| `OperatorIdentityRegistry` manual KYC workflow | `operator_identity.go` | ✅ |
| `OnfidoIdentityRegistry` automated KYC | `onfido_identity.go` | ✅ |

---

### Gap G-06 — Prospectus exemption API does not exist; 149-investor cap is unreachable

**Severity:** Critical — regulatory blocker for any EU distribution  
**Cross-reference:** GAP_REMEDIATION_PLAN.md Gap 4  
**Root cause:** `bc.ProspectusExemptions` is initialised as an empty map and never populated. `CheckProspectusLimits` and `UpdateRetailCounts` are wired into the block finalisation path but cannot fire because the map is always empty. Every EU retail distribution since Phase 0 launch has operated without this cap being enforced.

**Required changes:**

**New endpoint: `POST /v1/assets/{id}/exemption`**
- JWT-authenticated; only callable by `asset.Issuer`
- Body: `{"basis":"prospectus_art1_4","max_retail_per_jurisdiction":149,"max_ticket_size_eur":100000,"jurisdiction_coverage":["DE","LU","IE","NL","FR"]}`
- Conflict (duplicate) → 409
- Stores result in `bc.ProspectusExemptions[assetID]`

**New endpoint: `GET /v1/assets/{id}/exemption`**
- Any authenticated wallet (needed for investor portal eligibility self-check)
- Returns `ProspectusExemption` including live `retail_holders_by_jurisdiction` counts

**`SealBlock` update (blockchain.go):**
- After each sealed block, call `gonetwork.UpdateRetailCounts(exemption, bc.Holdings, bc.Credentials)` for every asset that has a registered exemption

**Acceptance criteria:**
- `POST` by non-issuer → 403
- Duplicate `POST` → 409
- After registering exemption + 149 retail transfers in DE, the 150th `Validate` call returns the prospectus cap error
- `GET` live counts reflect state at every sealed block

---

### Gap G-07 — MiFID II suitability assessment API does not exist

**Severity:** High — product blocker for warrants and convertibles  
**Cross-reference:** GAP_REMEDIATION_PLAN.md Gap 5  
**Root cause:** `bc.SuitabilityAssessments` is initialised but never populated. `CheckSuitability` is correctly called in `Validate` for `AssetTypeWarrant` and `AssetTypeConvertible`, so every transfer attempt on those instruments is immediately rejected with "no assessment found". There is no API to submit or query an assessment.

**Required changes:**

**New endpoint: `POST /v1/suitability`**
- Requires `jwtAdmin` middleware (compliance officers only)
- Body: `{"wallet_key":"...","asset_id":"...","has_sufficient_knowledge":true,"has_sufficient_experience":true,"can_absorb_loss":true}`
- Derives `Suitable = knowledge && experience && can_absorb_loss`
- Stores in `bc.SuitabilityAssessments[SuitabilityKey(walletKey, assetID)]`

**New endpoint: `GET /v1/suitability/{walletKey}/{assetID}`**
- Any wallet can query its own assessment; admin can query any
- 404 if no assessment exists (investor portal pre-check)

**Automatic derivation rule:** If `credential.InvestorClass == InvestorClassProfessional` or `InvestorClassEligibleCP`, auto-derive `Suitable = true` with `HasSufficientKnowledge = true` (ESMA guidelines permit this). This should be applied when `IssueCredential` is called, not deferred to transfer time.

**Acceptance criteria:**
- Transfer a warrant without assessment → `Validate` returns suitability error
- `POST /v1/suitability` with `suitable=true` → subsequent transfer succeeds
- `POST /v1/suitability` with all false → transfer still blocked
- Non-admin POST → 403

---

### Gap G-08 — KYC credential expiry is not enforced at transfer time

**Severity:** High  
**Root cause:** `CredentialAttestation.ExpiresAt` and `KYCStatusExpired` are defined in `identity.go`, but `CheckTransferEligibility` in `assets.go` never checks whether the credential has expired. A credential issued with `validForDays=365` will pass eligibility checks indefinitely after expiry. This is a direct breach of ongoing AML/KYC obligations under 5AMLD/6AMLD.

**Current code in `CheckTransferEligibility` (assets.go):**
```go
cred, ok := credentials[receiverKey]
if !ok || cred.KYCStatus != KYCStatusVerified {
    return fmt.Errorf("receiver has no verified credential...")
}
// ExpiresAt is never checked here
```

**Required change — add expiry check:**
```go
if cred.ExpiresAt > 0 && time.Now().Unix() > cred.ExpiresAt {
    return fmt.Errorf(
        "receiver credential has expired (expired at unix %d): re-KYC required",
        cred.ExpiresAt,
    )
}
```

**Additional requirement — credential sweep:**  
A periodic sweep (or end-of-block hook) should downgrade `KYCStatus` to `KYCStatusExpired` for credentials past their `ExpiresAt` and emit an `EventCredentialExpired` stream event so the investor portal can surface the re-KYC requirement.

**Acceptance criteria:**
- Transfer to a wallet with expired credential → `Validate` returns expiry error
- Transfer to a wallet with `ExpiresAt = 0` (no expiry set) → passes
- `EventCredentialExpired` emitted for expired credentials on next block seal

---

### Gap G-09 — AML screening is entirely mocked; no live provider is integrated

**Severity:** Regulatory blocker for go-live  
**Cross-reference:** GAP_REMEDIATION_PLAN.md Gap 7  
**Root cause:** `bc.AMLScreener` defaults to `MockAMLScreener`, which passes all transactions except those explicitly added to `BlockedAddresses`. No real watchlist (OFAC SDN, EU Consolidated Sanctions, UN Consolidated List) is queried. The `ComplyAdvantageScreener` and `EllipticScreener` stubs referenced in the gap plan do not exist yet.

**Required changes:**

**New file: `complyadv_aml.go` — ComplyAdvantage live screener:**
```go
type ComplyAdvantageScreener struct {
    apiKey    string
    baseURL   string
    client    *http.Client
    cache     map[string]*cachedAMLResult  // 24h TTL cache
    mu        sync.RWMutex
}
// Implements AMLScreener.ScreenTransaction
// Maps to ComplyAdvantage /searches endpoint
// Returns AMLSeverityBlock for OFAC SDN / EU sanctions matches
// Returns AMLSeverityFlag for PEP matches
```

**New file: `elliptic_aml.go` — Elliptic on-chain analytics:**
```go
type EllipticScreener struct {
    apiKey  string
    client  *http.Client
}
// Implements AMLScreener for on-chain wallet risk scoring
// Scores wallet addresses against Elliptic Lens risk model
// Wallets above configurable risk threshold → AMLSeverityBlock
```

**New requirement — Behavioural transaction monitoring rules engine (`aml_rules.go`):**

Static watchlist matching is necessary but not sufficient. The following behavioural rules must be evaluated on each `ScreenTransaction` call:

| Rule ID | Description | Action |
|---|---|---|
| TM-01 | More than 5 transfers to distinct receivers within any 24h window | Flag |
| TM-02 | Cumulative 24h transfer volume > EUR 50,000 for retail investor | Flag |
| TM-03 | Cumulative 24h transfer volume > EUR 1,000,000 for professional investor | Flag |
| TM-04 | Transfer immediately after receiving tokens ("layering pattern") within same block | Flag |
| TM-05 | Transfer to wallet in `BlockedJurisdictions` of the asset | Block |
| TM-06 | Same wallet sending identical amounts to the same receiver within 10 minutes | Flag |

```go
type AMLRuleSet struct {
    Rules []AMLRule
}
type AMLRule struct {
    ID          string
    Description string
    Severity    AMLAlertSeverity
    Evaluate    func(ctx AMLRuleContext) bool
}
type AMLRuleContext struct {
    SenderKey   string
    ReceiverKey string
    AssetID     string
    Amount      float64
    Currency    string
    RecentTxs   []AMLCall  // last 24h for sender
}
```

**New requirement — SAR (Suspicious Activity Report) workflow:**

When `AMLSeverityFlag` is raised, the system must:
1. Create a `SARDraft` record (new struct in `aml.go`)
2. Store in `bc.PendingSARs map[string]*SARDraft`
3. Emit `EventSARCreated` on the stream
4. The compliance officer must resolve via `POST /v1/compliance/sar/{id}/resolve` within 72h
5. Unresolved SARs older than 72h must block further transactions from that wallet

**New requirement — FATF Travel Rule (transfers ≥ EUR 1,000):**

```go
// TravelRulePayload must be attached to AssetTransaction for transfers
// above the EUR 1,000 threshold (FATF Recommendation 16).
type TravelRulePayload struct {
    OriginatorName    string `json:"originator_name"`
    OriginatorAddress string `json:"originator_address"`
    OriginatorAccount string `json:"originator_account"`
    BeneficiaryName   string `json:"beneficiary_name"`
    BeneficiaryAccount string `json:"beneficiary_account"`
    TransferAmount    float64 `json:"transfer_amount"`
    Currency          string `json:"currency"`
}
```

`AssetTransaction.Validate` must reject transfers above EUR 1,000 that do not carry a `TravelRulePayload`.

**Acceptance criteria:**
- OFAC SDN address → `AMLSeverityBlock` → `Validate` rejects transfer
- Clean address → nil alert → transfer proceeds
- TM-02 rule fires after cumulative retail volume exceeds EUR 50k in 24h
- Transfer ≥ EUR 1,000 without `TravelRulePayload` → validation error
- `SARDraft` created on flag-severity AML alert
- ComplyAdvantage cache hit returns in < 1ms; live call returns in < 500ms P95

---

### Gap G-10 — No regulatory reporting pipeline

**Severity:** High — required for go-live in any EU or UK regulated capacity  
**Root cause:** No mechanism exists to generate the structured reports required by financial regulators. Every matched trade should trigger a regulatory report, but `finalizeBlock` / `SealBlock` contains no reporting hook.

**Applicable reporting obligations:**

| Obligation | Regulation | Trigger | Deadline |
|---|---|---|---|
| Transaction report | MiFIR Article 26 | Every matched trade | T+1 to competent authority (NCA) |
| Position report | EMIR | If leverage instruments added | Daily / monthly |
| AIF investor report | AIFMD Annex IV | If SPV qualifies as AIF | Semi-annual |
| CMAR | FCA SUP 17 | UK-domiciled trades | Monthly |
| FiDA data sharing | EU FiDA Regulation 2026 | Investor data access request | On-request (within 24h) |

**Required changes — new file `regulatory_reporting.go`:**

```go
type ReportType string

const (
    ReportTypeMiFIRTx   ReportType = "mifir_article26"
    ReportTypeCMAR      ReportType = "fca_cmar"
    ReportTypeAIFMDAnnex ReportType = "aifmd_annex_iv"
    ReportTypeFiDA      ReportType = "fida_data_share"
)

type RegulatoryReport struct {
    ID          string
    Type        ReportType
    AssetID     string
    TradeID     string
    GeneratedAt int64
    Payload     json.RawMessage  // schema-specific fields
    Submitted   bool
    SubmittedAt int64
}

type ReportingService interface {
    GenerateMiFIRReport(trade Trade, asset *Asset) (*RegulatoryReport, error)
    Submit(report *RegulatoryReport) error
}
```

The `ReportingService` must be wired into `SealBlock` — after every block containing `OrderTransactions`, `GenerateMiFIRReport` is called for each trade and the report is queued for submission.

---

### Gap G-11 — No UK-specific jurisdiction rule (`"GB"`)

**Severity:** Medium  
**Root cause:** `bc.JurisdictionRules` is empty. The platform targets UK companies and UK investors, but no `JurisdictionRule` for `"GB"` exists. Post-Brexit, UK distribution is governed by FSMA 2000 and the Financial Promotions Order (FPO), which differs materially from EU Prospectus Regulation.

**Key differences from EU rules:**
- No equivalent of Prospectus Regulation Art 1(4) 150-investor cap; instead, FPO Article 19 (high-net-worth) and Article 48 (sophisticated investor) exemptions apply
- FCA requires a "risk warning" statement to be seen and acknowledged before investment
- UK retail investors require FCA-regulated advisor involvement unless relying on an exemption
- No equivalent of MiFID II suitability for equity instruments distributed under FPO (but best-practice recommends it)

**Required change:**
```go
// In blockchain initialisation or a new config file:
bc.JurisdictionRules["GB"] = &gonetwork.JurisdictionRule{
    CountryCode:         "GB",
    MaxRetailHolders:    0,     // FPO uses exemptions, not a fixed cap
    RequiresSuitability: false, // equity; set true for warrants/convertibles
    BlockedAssetTypes:   nil,
    MinTicketSizeEUR:    0,
    MaxTicketSizeEUR:    0,
    // Additional FPO-specific fields will need extending JurisdictionRule
}
```

`JurisdictionRule` will need extended fields for FPO exemption type (`FPOArt19`, `FPOArt48`) and a flag requiring acknowledgement of a statutory risk warning.

---

## Part III — Governance & Regulation

### Existing foundations

| Component | File | Status |
|---|---|---|
| `CorporateActionType` constants: ROFR, DragAlong, TagAlong, Dividend | `corporate.go` | ✅ Types declared |
| `CorporateAction` struct with response tracking and threshold | `corporate.go` | ✅ |
| `CheckROFR` — triggers ROFR action on qualifying transfers | `corporate.go` | ✅ Wired into `Validate` |
| `TallyROFR` — balance-weighted response tally | `corporate.go` | ✅ |
| `RecordResponse` — signed holder exercise/waiver | `corporate.go` | ✅ |
| `NewCorporateActionResponse` | `corporate.go` | ✅ |
| `VotingRights bool` on `AssetMetadata` | `assets.go` | ✅ (flag only — no mechanics) |
| dBFT stake-weighted delegate election | `dBFT.go` | ✅ Working |

---

### Gap G-12 — Drag-along execution is declared but not implemented

**Severity:** High  
**Root cause:** `CorporateActionDragAlong` is a declared constant in `corporate.go` and `DragThreshold` is a field on `TransferRestrictions`, but no function exists that, once the threshold is crossed and the action reaches `CorporateActionApproved`, forcibly transfers minority holdings to the acquirer. `CorporateAction.Status` can be set to `CorporateActionApproved` but nothing is triggered.

**Required change — `ExecuteDragAlong` function in `corporate.go`:**

```go
// ExecuteDragAlong forcibly transfers all non-consenting minority holdings
// to the acquirer at action.PricePerUnit once the drag threshold is met.
// It must be called after TallyROFR confirms the threshold is crossed.
//
// For each non-consenting holder:
//   1. Creates a forced AssetTransaction (AssetTxTypeTransfer) to the acquirer
//   2. Creates a corresponding PaymentInstruction for the cash leg
//   3. Applies the holding change immediately (bypass Validate — this is an
//      involuntary corporate action, not a voluntary transfer)
//
// Returns the list of forced transfers and any errors.
func ExecuteDragAlong(
    action *CorporateAction,
    acquirerKey string,
    holdings map[string]*AssetHolding,
    assets map[string]*Asset,
    pendingInstructions map[string]*PaymentInstruction,
) ([]AssetTransaction, error) {
    if action.Type != CorporateActionDragAlong {
        return nil, fmt.Errorf("action %s is not a drag-along", action.ID)
    }
    if action.Status != CorporateActionApproved {
        return nil, fmt.Errorf("drag-along action %s is not yet approved (status: %s)",
            action.ID, action.Status)
    }
    // ... iterate holdings, create forced transfers for non-consenting holders
}
```

**Acceptance criteria:**
- Drag-along with threshold met + approved → all non-consenting holders' balances transferred to acquirer
- Drag-along with threshold not met → returns "threshold not met" error
- Each forced transfer creates a `PaymentInstruction` in `bc.PendingInstructions`
- `action.Status` set to `CorporateActionExecuted` after successful execution

---

### Gap G-13 — Tag-along exists only as a type constant; no mechanics

**Severity:** High  
**Root cause:** `CorporateActionTagAlong` is declared and `TagAlongRight bool` exists on `TransferRestrictions`, but `TagAlongRight` is never read in `Validate` or `ApplyAssetTransaction`. No `CheckTagAlong` function exists. Minority holders have no way to join a majority sale even when the right is contractually guaranteed.

**Required changes:**

1. **`CheckTagAlong` in `corporate.go`** — called from `Validate` when `asset.Restrictions.TagAlongRight == true` and the transfer quantity exceeds a majority threshold (configurable; default 50% of circulating supply):

```go
func CheckTagAlong(
    at *AssetTransaction,
    asset *Asset,
    holdings map[string]*AssetHolding,
    pendingActions map[string]*CorporateAction,
) (triggered bool, action *CorporateAction, err error) { ... }
```

Returns `ErrTagAlongTriggered` (new sentinel error in `corporate.go`) when triggered, analogous to `ErrROFRTriggered`.

2. **`ExecuteTagAlong` in `corporate.go`** — once minority holders who wished to join have responded within the notice window, executes their proportional transfer on identical terms (same `PricePerUnit` as the majority sale).

3. **Wire `CheckTagAlong` into `AssetTransaction.Validate`** — between the MaxHolders check and the ROFR check:

```go
if at.TxType == AssetTxTypeTransfer && pendingActions != nil {
    if triggered, _, err := CheckTagAlong(at, asset, holdings, pendingActions); triggered {
        return err // ErrTagAlongTriggered
    }
    if triggered, _, err := CheckROFR(at, asset, holdings, pendingActions); triggered {
        return err // ErrROFRTriggered
    }
}
```

**Acceptance criteria:**
- Transfer of 51%+ of circulating supply on a tag-along asset → `ErrTagAlongTriggered`
- Minority holder response within window → proportional transfer executed at same price
- Transfer below majority threshold → unaffected

---

### Gap G-14 — Dividend distribution is entirely unimplemented

**Severity:** High  
**Root cause:** `CorporateActionDividend` is declared and `DividendTerms` exists on `AssetMetadata`, but there is no function to distribute cash proportionally to all holders at a record date. Debt instruments and participating equity cannot pay returns.

**Required change — `ExecuteDividend` in `corporate.go`:**

```go
// ExecuteDividend distributes cash to all token holders proportional to their
// balance at action.DeadlineAt (the record date). For each holder, it creates
// a PaymentInstruction for (action.PricePerUnit * holding.Balance) in the
// asset's currency.
//
// A snapshot of holdings at the record date must be taken at block-sealing time
// when the record-date block is finalised. The snapshot prevents "dividend
// capture" by rapid transfers around the record date.
func ExecuteDividend(
    action *CorporateAction,
    snapshotHoldings map[string]*AssetHolding,  // holdings AT record date
    asset *Asset,
    pendingInstructions map[string]*PaymentInstruction,
    oracle OracleService,
) error { ... }
```

**Record-date snapshot requirement:** A `DividendHoldingSnapshot map[string]map[string]*AssetHolding` (actionID → holdings at record date) must be added to `Blockchain`. When `SealBlock` processes a block whose timestamp crosses `action.DeadlineAt`, it must take a snapshot of current holdings before applying further transfers.

**Acceptance criteria:**
- `ExecuteDividend` creates one `PaymentInstruction` per holder with balance > 0 at record date
- Total instructed amount == `action.PricePerUnit * asset.CirculatingSupply` (within floating-point tolerance)
- Holders who acquired tokens after the record-date snapshot do not receive the dividend
- `action.Status` set to `CorporateActionExecuted`

---

### Gap G-15 — On-chain shareholder voting exists only as a boolean flag

**Severity:** Medium  
**Root cause:** `AssetMetadata.VotingRights = true` indicates that token holders have voting rights, but there is no struct for proposing a resolution, no mechanism for holders to submit a signed vote, and no tally function. Shareholder meetings are entirely manual and off-chain, which is inconsistent with the platform's transparency proposition.

**Required changes — new file `governance.go`:**

```go
type VoteType string

const (
    VoteTypeOrdinaryResolution     VoteType = "ordinary"      // >50% required
    VoteTypeSpecialResolution      VoteType = "special"       // >75% required (e.g. amend articles)
    VoteTypeAdvisory               VoteType = "advisory"      // non-binding
)

// VoteProposal is an on-chain record of a shareholder vote proposal.
type VoteProposal struct {
    ID               string   `json:"id"`
    AssetID          string   `json:"asset_id"`
    ProposerKey      string   `json:"proposer_key"`
    ResolutionText   string   `json:"resolution_text"`   // hash of off-chain document recommended
    VoteType         VoteType `json:"vote_type"`
    RecordDate       int64    `json:"record_date"`        // snapshot date for voting rights
    DeadlineAt       int64    `json:"deadline_at"`
    QuorumFraction   float64  `json:"quorum_fraction"`   // minimum participation required
    ProposerSignature []byte  `json:"-"`
}

// VoteResponse is a signed ballot submitted by a token holder.
type VoteResponse struct {
    ProposalID  string `json:"proposal_id"`
    HolderKey   string `json:"holder_key"`
    InFavour    bool   `json:"in_favour"`
    VotingPower float64  // set by TallyVotes from snapshot; not submitted by holder
    Signature   []byte `json:"-"`
}

// VoteResult is the final tally produced after the deadline.
type VoteResult struct {
    ProposalID     string
    VotesFor       float64  // sum of voting power of in-favour responses
    VotesAgainst   float64
    QuorumReached  bool
    ResolutionPassed bool
    TalliedAt      int64
}

// TallyVotes tallies a VoteProposal using the holding snapshot at RecordDate.
func TallyVotes(
    proposal *VoteProposal,
    responses []*VoteResponse,
    snapshotHoldings map[string]*AssetHolding,
) (*VoteResult, error) { ... }
```

**Acceptance criteria:**
- `POST /v1/governance/votes` — issuer creates proposal; sealed in block
- `POST /v1/governance/votes/{id}/respond` — holder submits signed ballot
- `GET /v1/governance/votes/{id}/result` — returns `VoteResult` after deadline
- Holder with zero balance at record date cannot vote
- Duplicate ballot from same holder → 409

---

### Gap G-16 — Protocol governance is unilateral; no on-chain parameter change mechanism

**Severity:** Medium (longer-term — required for DLT Pilot Regime)  
**Root cause:** The dBFT delegate election provides decentralised block production, but all protocol parameters (jurisdiction rules, compliance rule sets, oracle key rotations) require a code deployment by GreenHouse. There is no on-chain mechanism for delegates to propose and ratify parameter changes. Under EU 2022/858 DLT Pilot Regime, Article 8 requires the operator to maintain documented governance procedures for changing the rules of the DLT system.

**Required changes — new file `protocol_governance.go`:**

```go
type ParameterChangeType string

const (
    ParamChangeJurisdictionRule   ParameterChangeType = "jurisdiction_rule"
    ParamChangeOracleKeyRotation  ParameterChangeType = "oracle_key_rotation"
    ParamChangeComplianceRuleSet  ParameterChangeType = "compliance_ruleset"
    ParamChangeAMLRuleSet         ParameterChangeType = "aml_ruleset"
)

// ProtocolProposal is a multi-sig ratified request to change a protocol parameter.
// It requires signatures from a threshold of current delegates before taking effect.
type ProtocolProposal struct {
    ID              string              `json:"id"`
    ChangeType      ParameterChangeType `json:"change_type"`
    Payload         json.RawMessage     `json:"payload"`       // the new parameter value
    ProposerKey     string              `json:"proposer_key"`
    RequiredSigs    int                 `json:"required_sigs"` // threshold of delegate sigs
    DelegateSigs    map[string][]byte   `json:"delegate_sigs"` // delegateKey → signature
    EffectiveAt     int64               `json:"effective_at"`  // Unix timestamp
    Status          string              `json:"status"`
}
```

**Acceptance criteria:**
- `POST /v1/protocol/proposals` — any delegate may propose
- `POST /v1/protocol/proposals/{id}/sign` — delegate sign; once threshold met → `status=ratified`
- Ratified proposal applied automatically at `EffectiveAt` during `SealBlock`
- Non-delegate attempt to propose → 403

---

## Part IV — Oracle Infrastructure

### Existing foundations

| Component | File | Status |
|---|---|---|
| `KMSOracleService` — AWS KMS envelope-encrypted Ed25519 key | `kms_oracle.go` | ✅ Working |
| `OracleService` interface (sign/verify instructions and confirmations) | `payment.go` | ✅ Clean interface |
| `ValuationOracle` interface + `MockValuationOracle` | `reporting.go` | ✅ Interface clean |
| `KMSOracleService.SignInstruction` / `VerifyInstruction` | `kms_oracle.go` | ✅ |
| `KMSOracleService.SignConfirmation` / `VerifyConfirmation` | `kms_oracle.go` | ✅ |
| `KeyProvider` interface with `LocalKeyProvider` and `KMSKeyProvider` stub | `keymanager.go` | ✅ Interface clean |

---

### Gap G-17 — Single oracle key is a single point of trust and failure

**Severity:** Critical — DLT Pilot Regime authorisation and institutional investor due diligence will reject a single-key model  
**Root cause:** `KMSOracleService` holds one Ed25519 key (decrypted from a single KMS-protected envelope at startup). Every `PaymentInstruction` and `PaymentConfirmation` carries a single oracle signature. A compromise of the KMS key or the running process invalidates all historical signatures retroactively. There is no key rotation mechanism that preserves historical verifiability.

**Required changes — new file `threshold_oracle.go`:**

A $t$-of-$n$ threshold oracle using a simple multi-party signature scheme. For the initial implementation, $n=3$, $t=2$ is sufficient:

| Oracle node | Key custody | Purpose |
|---|---|---|
| GreenHouse primary oracle | AWS KMS (existing) | Signs instructions during normal operation |
| SPV administrator oracle | HashiCorp Vault Transit on SPV admin infrastructure | Independent confirmation of cash receipt |
| Independent custodian oracle | GCP KMS on a separate GCP project | Provides a third key for deadlock breaking |

```go
// ThresholdOracleService implements OracleService with a t-of-n multi-sig.
// A PaymentInstruction is considered oracle-signed when at least t of the n
// configured oracle public keys have contributed a valid signature.
type ThresholdOracleService struct {
    threshold   int
    oracleKeys  []*OracleKeyHolder  // one per participating oracle node
    auditLog    *OracleAuditLog
}

type OracleKeyHolder struct {
    Name      string
    PublicKey *PublicKey
    Signer    KeyProvider  // LocalKeyProvider or KMSKeyProvider depending on custody
}

// SignInstruction collects signatures from all available oracle holders and
// returns the instruction with a ThresholdSignature payload.
// Returns an error if fewer than threshold holders are available.
func (t *ThresholdOracleService) SignInstruction(
    instruction *PaymentInstruction,
) (*PaymentInstruction, error) { ... }

// VerifyInstruction returns true if the instruction carries at least threshold
// valid oracle signatures.
func (t *ThresholdOracleService) VerifyInstruction(
    instruction *PaymentInstruction,
) bool { ... }
```

`PaymentInstruction.OracleSignature` must be extended from `[]byte` to a `ThresholdSignatureSet`:
```go
type ThresholdSignatureSet struct {
    Signatures map[string][]byte  // oracleName → Ed25519 sig
    Threshold  int
}
```

**Key rotation:** When a key is rotated, the new public key must be registered in a `OracleKeyRegistry` on-chain record, signed by all remaining current keys at the threshold. Historical instructions signed under the old key remain valid against the historical registry state.

**Acceptance criteria:**
- Instruction signed by only 1 of 3 oracles → `VerifyInstruction` returns false
- Instruction signed by 2 of 3 oracles → `VerifyInstruction` returns true
- Compromised single key cannot forge a new valid instruction without the second key
- Key rotation adds new key to on-chain registry; old key can be revoked

---

### Gap G-18 — `ValuationOracle` has no real data feed and no staleness guard

**Severity:** High  
**Root cause:** `MockValuationOracle.GetValuation` returns whatever was last set via `SetValuation`, or `1.0` (par) if nothing was set. There is no `ValidUntil` timestamp, no provider signature on the price, and no error when the price is stale. Every FiDA holdings report (`GenerateHoldingsReport`) and every unrealised P&L calculation is potentially based on an arbitrarily old or fabricated price.

**Required changes:**

**`SignedValuation` struct (in `reporting.go`):**
```go
type SignedValuation struct {
    AssetID         string  `json:"asset_id"`
    PricePerUnit    float64 `json:"price_per_unit"`
    Currency        string  `json:"currency"`
    Source          string  `json:"source"`           // e.g. "custodian_nav", "median_aggregate"
    ValidFrom       int64   `json:"valid_from"`
    ValidUntil      int64   `json:"valid_until"`
    OracleSignature []byte  `json:"-"`
}
```

**Updated `ValuationOracle` interface:**
```go
type ValuationOracle interface {
    GetSignedValuation(assetID string) (*SignedValuation, error)  // returns ErrStaleValuation if expired
    GetCurrencyRate(from, to string) (float64, error)
    PublishValuation(val *SignedValuation) error  // called by oracle node to push a new price
}
```

`GetSignedValuation` must return `ErrStaleValuation` if `time.Now().Unix() > val.ValidUntil`.

**External price adapters (new files):**

| Adapter | File | Data source |
|---|---|---|
| `NAVFeedAdapter` | `nav_feed.go` | Custodian bank NAV API (iCapital, Alter Domus, etc.) |
| `MarketDataAdapter` | `market_data.go` | Bloomberg B-PIPE / Refinitiv Elektron for listed comparables |
| `ECBRateAdapter` | `ecb_rate_oracle.go` | ECB XML daily FX rates (free, authoritative) |

**Acceptance criteria:**
- `GetSignedValuation` with expired `ValidUntil` → returns `ErrStaleValuation`
- `GenerateHoldingsReport` with a stale valuation → returns error, not silently bad data
- `ECBRateAdapter` fetches daily EUR/GBP, EUR/USD, EUR/CHF from ECB
- Prices carry `OracleSignature` verifiable by `ThresholdOracleService.OraclePublicKey()`

---

### Gap G-19 — FX rate oracle always returns `1.0`; cross-currency compliance is broken

**Severity:** High  
**Root cause:** `MockValuationOracle.GetCurrencyRate` returns `1.0` for any unknown pair. `ApplyJurisdictionRule` takes a `ticketValueEUR` parameter that the API layer must compute by converting the asset's native currency to EUR, but the only rate source available is the `MockValuationOracle` returning `1.0`. A GBP-denominated asset with a EUR 100k ticket-size limit is never correctly enforced — all GBP amounts are passed at `1:1` parity.

**Required change — `ECBRateAdapter` in `ecb_rate_oracle.go`:**

```go
// ECBRateAdapter fetches the ECB's published daily reference rates.
// Rates are fetched once per day and cached until the next ECB publication
// (typically 16:00 CET on TARGET2 business days).
// Each rate is signed by the oracle key to provide a tamper-evident audit trail.
type ECBRateAdapter struct {
    cache       map[string]*SignedFXRate  // "FROM:TO" → rate
    lastFetched int64
    oracleSvc   OracleService
    httpClient  *http.Client
}

type SignedFXRate struct {
    FromCurrency string  `json:"from"`
    ToCurrency   string  `json:"to"`
    Rate         float64 `json:"rate"`
    PublishedAt  int64   `json:"published_at"`  // ECB publication timestamp
    ValidUntil   int64   `json:"valid_until"`   // next_business_day 17:00 CET
    OracleSignature []byte `json:"-"`
}

func (e *ECBRateAdapter) GetCurrencyRate(from, to string) (float64, error) {
    rate, err := e.getSignedRate(from, to)
    if err != nil {
        return 0, err
    }
    if time.Now().Unix() > rate.ValidUntil {
        return 0, ErrStaleValuation
    }
    return rate.Rate, nil
}
```

The ECB provides daily rates at `https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml` (free, no API key, machine-readable XML).

**Acceptance criteria:**
- `GetCurrencyRate("GBP","EUR")` returns ECB daily rate within ±0.01%
- Rate expires at `ValidUntil`; subsequent call after expiry returns `ErrStaleValuation`
- Signed rate verifiable by oracle public key
- `ApplyJurisdictionRule` correctly enforces EUR ticket-size limits on GBP-denominated assets

---

### Gap G-20 — No audit log for oracle operations

**Severity:** High — mandatory for MiFIR and DORA (Digital Operational Resilience Act)  
**Root cause:** Every call to `SignInstruction` and `SignConfirmation` on `KMSOracleService` applies a signature and returns, with no append-only record of what was signed, when, or under which key. DORA Article 9 requires financial entities to maintain detailed logs of all critical operational functions, including signing operations on payment instructions.

**Required changes — new file `oracle_audit.go`:**

```go
// OracleAuditEntry is an immutable record of a single oracle signing operation.
// Each entry hashes the previous entry to form a tamper-evident chain.
type OracleAuditEntry struct {
    Sequence        int64   `json:"seq"`
    OperationType   string  `json:"op_type"`          // "sign_instruction", "sign_confirmation", "verify_*"
    ObjectID        string  `json:"object_id"`        // TradeID of the instruction/confirmation
    ObjectHash      string  `json:"object_hash"`      // SHA3-256 hex of the signed object
    SignerKey        string  `json:"signer_key"`       // fingerprint of the oracle public key used
    SignedAt         int64   `json:"signed_at"`
    PreviousEntryHash string `json:"prev_hash"`       // SHA3-256 of the previous entry's JSON
    EntryHash        string `json:"entry_hash"`        // SHA3-256 of this entry (excl. entry_hash)
}

// OracleAuditLog maintains an append-only, hash-chained log of all oracle operations.
// The chain ensures that any deletion or modification of a historical entry is detectable.
type OracleAuditLog struct {
    mu      sync.Mutex
    entries []*OracleAuditEntry
}

func (l *OracleAuditLog) Append(opType, objectID, objectHash, signerKey string) *OracleAuditEntry { ... }
func (l *OracleAuditLog) VerifyChain() error { ... }  // walks entire log, verifies hash chain
func (l *OracleAuditLog) ExportForAudit() []*OracleAuditEntry { ... }
```

Every `SignInstruction` and `SignConfirmation` call must append to the log before returning.

**Acceptance criteria:**
- Every signed instruction and confirmation has a corresponding audit entry
- Deleting an entry from the middle of the log → `VerifyChain()` returns an error
- `GET /v1/admin/oracle/audit` returns the full log (admin-only)
- Log survives server restart (must be persisted alongside other state — see Gap E-02)

---

### Gap G-21 — DVP settlement oracle is not decoupled from the token transfer trigger

**Severity:** High  
**Root cause:** The current DVP flow has a single oracle signing `PaymentInstruction` and `PaymentConfirmation`, and the same oracle process decides when `ApplyAssetTransaction` fires (i.e., when the token transfer is applied). If the oracle process is compromised, an attacker can trigger a token transfer without fiat actually having been received, or can block a legitimate settlement.

**Required change — independent settlement co-signature:**

The DVP path must require two independent oracle signatures before `ApplyAssetTransaction` fires:

1. **Payment confirmation oracle:** Signs the `PaymentConfirmation` attesting that fiat has been received by the payment provider (existing `KMSOracleService.SignConfirmation` role)
2. **Settlement authorisation oracle:** A second, independent oracle that co-signs the settlement trigger. This oracle verifies that a valid `PaymentConfirmation` exists and that it was signed by the payment confirmation oracle, then adds its own signature authorising the token transfer

```go
// In blockchain.go / finalizeBlock — DVP settlement path:
// Before calling ApplyAssetTransaction for a DVP trade:
if !bc.OracleService.VerifyConfirmation(conf) {
    return fmt.Errorf("payment confirmation oracle signature invalid")
}
if !bc.SettlementOracle.AuthoriseSettlement(trade.ID, conf) {
    return fmt.Errorf("settlement oracle authorisation required")
}
// Only then: ApplyAssetTransaction(...)
```

**Acceptance criteria:**
- Token transfer attempted with only payment confirmation signature but no settlement authorisation → rejected
- Both signatures present → DVP transfer applied
- Compromised payment oracle cannot unilaterally trigger token transfer without settlement oracle

---

## Part V — Consolidated Gap Severity Matrix

The following table consolidates all gaps from this review (G-01 through G-21) and the existing `GAP_REMEDIATION_PLAN.md` (Gaps 1–14, where not already subsumed).

| Gap ID | Title | Severity | Domain | Regulatory impact | Cross-ref |
|---|---|---|---|---|---|
| G-01 | Dual-authority issuance for participation notes | Critical | On-chain/off-chain | Legal validity of token supply | New |
| G-02 | `VerifyIssuerSignature` not called in validation | High | On-chain/off-chain | Tampered asset undetectable | New |
| G-03 | No `LegalDocAmendment` trail | High | On-chain/off-chain | Stale legal docs undetectable | New |
| G-04 | `CirculatingSupply` divergence — no reconciliation | Critical | On-chain/off-chain | All compliance checks using supply are wrong | New |
| G-05 | Missing capital issuance scenarios | High | On-chain/off-chain | Cannot model real private placements | New |
| G-06 | Prospectus exemption API unreachable | Critical | Compliance | EU distribution regulatory blocker | Extends Gap 4 |
| G-07 | MiFID II suitability API unreachable | High | Compliance | Warrants/convertibles blocked for all | Extends Gap 5 |
| G-08 | KYC expiry not enforced at transfer | High | Compliance | 5AMLD/6AMLD ongoing KYC breach | New |
| G-09 | AML entirely mocked; no live screening | Critical | Compliance | Regulatory blocker for go-live | Extends Gap 7 |
| G-10 | No regulatory reporting pipeline | High | Compliance | MiFIR Art 26, FCA CMAR breach | New |
| G-11 | No UK jurisdiction rule | Medium | Compliance | UK distribution without FPO compliance | New |
| G-12 | Drag-along execution not implemented | High | Governance | Shareholder agreement breach | New |
| G-13 | Tag-along has no mechanics | High | Governance | Shareholder agreement breach | New |
| G-14 | Dividend distribution not implemented | High | Governance | Debt instrument returns impossible | New |
| G-15 | On-chain voting is a flag only | Medium | Governance | Off-chain voting inconsistency | New |
| G-16 | No protocol governance mechanism | Medium | Governance | DLT Pilot Regime Art 8 gap | New |
| G-17 | Single oracle key — no threshold scheme | Critical | Oracle | Institutional investor / regulator red flag | New |
| G-18 | `ValuationOracle` returns `1.0`; no staleness guard | High | Oracle | FiDA reports numerically wrong | New |
| G-19 | FX rates always `1.0`; cross-currency compliance broken | High | Oracle | Ticket-size limits never correctly enforced | New |
| G-20 | No oracle audit log | High | Oracle | DORA Art 9 / MiFIR audit trail breach | New |
| G-21 | DVP oracle not decoupled from settlement trigger | High | Oracle | Single-point compromise enables theft | New |
| E-01 | Issuer holds no tokens after tokenisation | Critical | Foundations | Primary offering flow broken | Gap 1 ✅ Fixed |
| E-02 | Lockup not applied on holding creation | — | Foundations | — | Gap 2 ✅ Closed |
| E-03 | ROFR not wired into `Validate` | High | Foundations | ROFR silently bypassed | Gap 3 ✅ Fixed |
| E-04 | No state persistence | Critical | Foundations | All data lost on restart | Gap 8 |
| E-05 | No thread safety on `Blockchain` state | High | Foundations | Race conditions in concurrent requests | Gap 9 |
| E-06 | No live fiat payment provider | Critical | Foundations | All trades confirm via mock | Gap 6 |
| E-07 | `KMSKeyProvider` is a no-op stub | High | Foundations | Production signing impossible | Gap 13 |
| E-08 | Multi-node deployment untested | Medium | Foundations | Single-node production risk | Gap 14 |

---

## Part VI — Implementation Plan

### Track A — On-Chain / Off-Chain Integrity

**Goal:** Ensure that every token on-chain has a verifiable, tamper-evident connection to a real-world asset; that supply figures are always accurate; and that complex issuance scenarios are fully supported.

#### A-01 — `AssertCirculatingSupplyConsistency` (Gap G-04)
**Files:** `blockchain.go`  
**Effort:** 0.5 days  
**Dependencies:** None  
**Deliverable:** Function called at the end of every `SealBlock`. In development mode (`os.Getenv("GH_ENV") != "production"`), panics on divergence. In production, logs `CRITICAL` and emits a `EventSupplyMismatch` stream event. Removes the direct `CirculatingSupply` write in `api/handlers.go` and routes all issuances through `ApplyAssetTransaction`.

**Test cases:** `TestCirculatingSupply_ConsistencyAfterIssue`, `TestCirculatingSupply_ConsistencyAfterTransfer`, `TestCirculatingSupply_DetectsDivergence`

---

#### A-02 — `VerifyIssuerSignature` in `Validate` (Gap G-02)
**Files:** `assets.go`  
**Effort:** 2 hours  
**Dependencies:** A-01  
**Deliverable:** Added to `AssetTransaction.Validate` step 1.5 (between asset-exists check and quantity check).

**Test cases:** `TestValidate_TamperedAssetRejected`, `TestValidate_UntamperedAssetPasses`

---

#### A-03 — `LegalDocAmendment` log (Gap G-03)
**Files:** New `legal_docs.go`; `blockchain.go` (add `LegalDocAmendments` map); `api/handlers.go` (new endpoints)  
**Effort:** 2 days  
**Dependencies:** None  
**Deliverable:** `LegalDocAmendment` struct, `CurrentLegalDocHash()` helper, `POST /v1/assets/{id}/legal-doc` endpoint (issuer-only; participation notes require SPV admin co-sig), and `GET /v1/assets/{id}/legal-doc/history`.

**Test cases:** `TestLegalDoc_AmendmentChain`, `TestLegalDoc_NonIssuerRejected`, `TestLegalDoc_ParticipationNoteRequiresAdminSig`

---

#### A-04 — Dual-authority issuance for participation notes (Gap G-01)
**Files:** `assets.go`, `api/handlers.go`, `api/server.go`  
**Effort:** 3 days  
**Dependencies:** A-02  
**Deliverable:** `TwoPartyIssueRequest` struct; `POST /v1/assets/{id}/countersign` endpoint; `AssetTransaction.Validate` enforces `RequiredSigs = 2` for `AssetTypeParticipationNote`.

**Test cases:** `TestIssue_ParticipationNoteBlockedWithoutCountersig`, `TestIssue_ParticipationNoteReleasedAfterCountersig`, `TestIssue_DirectEquityUnaffected`

---

#### A-05 — Warrant exercise mechanics (Gap G-05)
**Files:** New `instrument_lifecycle.go`  
**Effort:** 1 week  
**Dependencies:** A-04  
**Deliverable:** `WarrantExerciseRequest`, `ProcessWarrantExercise()` that burns warrant tokens and issues equivalent equity tokens. API endpoint `POST /v1/instruments/warrant-exercise`.

**Test cases:** `TestWarrant_ExerciseReducesWarrantBalance`, `TestWarrant_ExerciseIncreasesEquityBalance`, `TestWarrant_ExerciseBeyondEntitlement`

---

#### A-06 — Convertible note conversion (Gap G-05)
**Files:** `instrument_lifecycle.go`  
**Effort:** 1 week  
**Dependencies:** A-05  
**Deliverable:** `ConvertibleConversionRequest`, conversion ratio field on `AssetMetadata`, conversion trigger (maturity date or qualifying financing event), `ProcessConvertibleConversion()`.

**Test cases:** `TestConvertible_ConversionAtMaturity`, `TestConvertible_ConversionOnQualifyingFinancing`, `TestConvertible_PrematureConversionRejected`

---

#### A-07 — Anti-dilution provisions (Gap G-05)
**Files:** `instrument_lifecycle.go`, `assets.go`  
**Effort:** 1 week  
**Dependencies:** A-06  
**Deliverable:** `AntiDilutionAdjustment()` implementing broad-based weighted-average formula. Called automatically when `AssetTxTypeIssue` creates new equity below the previous round price.

**Test cases:** `TestAntiDilution_DownRoundAdjustsConversionRatio`, `TestAntiDilution_UpRoundNoAdjustment`

---

#### A-08 — Capital call enforcement (Gap G-05)
**Files:** `spv.go`, `payment.go`  
**Effort:** 3 days  
**Dependencies:** A-04, G-14 (dividend infrastructure can be reused)  
**Deliverable:** `ProcessCapitalCall()` creating `PaymentInstruction` records for each note holder proportional to their balance. Note holders who fail to pay within the call window → holding marked `CapitalCallDefaulted` → transfer-restricted.

**Test cases:** `TestCapitalCall_InstructionCreatedPerHolder`, `TestCapitalCall_DefaulterRestricted`

---

### Track B — Compliance & Regulation

**Goal:** Make all built compliance logic accessible via API, add missing AML depth, enforce KYC expiry, implement the Travel Rule, and establish a regulatory reporting pipeline.

#### B-01 — Prospectus exemption API (Gap G-06)
**Files:** `api/handlers.go`, `api/server.go`  
**Effort:** 2 days  
**Dependencies:** None  
**Deliverable:** `POST /v1/assets/{id}/exemption`, `GET /v1/assets/{id}/exemption`. `UpdateRetailCounts` called in `SealBlock` for every asset with a registered exemption.

**Test cases:** As specified in GAP_REMEDIATION_PLAN.md Gap 4.

---

#### B-02 — MiFID II suitability assessment API (Gap G-07)
**Files:** `api/handlers.go`, `api/server.go`  
**Effort:** 2 days  
**Dependencies:** None  
**Deliverable:** `POST /v1/suitability`, `GET /v1/suitability/{walletKey}/{assetID}`. Auto-derive suitable for professional/eligible-CP investors.

**Test cases:** As specified in GAP_REMEDIATION_PLAN.md Gap 5.

---

#### B-03 — KYC expiry enforcement (Gap G-08)
**Files:** `assets.go`, `identity.go`, `blockchain.go`  
**Effort:** 1 day  
**Dependencies:** None  
**Deliverable:** Expiry check in `CheckTransferEligibility`. End-of-block credential sweep emitting `EventCredentialExpired`. `GET /v1/credentials/{walletKey}/status` returning live KYC status.

**Test cases:** `TestTransfer_ExpiredCredentialRejected`, `TestTransfer_NoExpiryPasses`, `TestCredentialSweep_EmitsExpiredEvent`

---

#### B-04 — UK jurisdiction rule (Gap G-11)
**Files:** `compliance.go` or new `jurisdiction_rules_gb.go`; `blockchain.go` init  
**Effort:** 1 day  
**Dependencies:** B-01  
**Deliverable:** `JurisdictionRule` for `"GB"` with FPO exemption type field. Pre-loaded in `Blockchain` initialisation.

**Test cases:** `TestJurisdiction_GBEquityAllowed`, `TestJurisdiction_GBWarrantRequiresSuitability`

---

#### B-05 — AML rules engine (Gap G-09)
**Files:** New `aml_rules.go`  
**Effort:** 1 week  
**Dependencies:** None  
**Deliverable:** `AMLRuleSet` with configurable rules TM-01 through TM-06. Rules evaluated in `MockAMLScreener.ScreenTransaction` and in the future `ComplyAdvantageScreener`.

**Test cases:** `TestAMLRule_TM01_FrequentTransfers`, `TestAMLRule_TM02_VolumeThreshold`, `TestAMLRule_TM04_LayeringPattern`

---

#### B-06 — SAR draft workflow (Gap G-09)
**Files:** `aml.go`, `api/handlers.go`, `api/server.go`  
**Effort:** 3 days  
**Dependencies:** B-05  
**Deliverable:** `SARDraft` struct; `bc.PendingSARs` map; `EventSARCreated` event; `POST /v1/compliance/sar/{id}/resolve` (admin-only). Unresolved SARs > 72h block further transactions from the flagged wallet.

**Test cases:** `TestSAR_CreatedOnFlagAlert`, `TestSAR_ResolveClearsBlock`, `TestSAR_UnresolvedBlocksWallet`

---

#### B-07 — FATF Travel Rule (Gap G-09)
**Files:** `assets.go`  
**Effort:** 3 days  
**Dependencies:** G-19 (FX rates needed for EUR threshold conversion)  
**Deliverable:** `TravelRulePayload` struct on `AssetTransaction`. `Validate` rejects transfers ≥ EUR 1,000 without payload. API updated to accept travel rule data on `POST /v1/orders` (or via `POST /v1/assets/transfer`).

**Test cases:** `TestTravelRule_BelowThresholdExempt`, `TestTravelRule_AboveThresholdRequiresPayload`, `TestTravelRule_MissingPayloadRejected`

---

#### B-08 — Live ComplyAdvantage AML screener (Gap G-09)
**Files:** New `complyadv_aml.go`  
**Effort:** 3 days + CA onboarding  
**Dependencies:** None  
**Deliverable:** `ComplyAdvantageScreener` implementing `AMLScreener`. 24h cache. Environment variables: `COMPLY_ADVANTAGE_API_KEY`, `COMPLY_ADVANTAGE_BASE_URL`.

**Test cases:** `TestComplyAdvantage_SDNMatch_Blocks`, `TestComplyAdvantage_PEPMatch_Flags`, `TestComplyAdvantage_CacheHit`

---

#### B-09 — Regulatory reporting pipeline (Gap G-10)
**Files:** New `regulatory_reporting.go`; `blockchain.go` (`SealBlock`)  
**Effort:** 2 weeks  
**Dependencies:** E-04 (persistence required for queued reports)  
**Deliverable:** `RegulatoryReport` struct; `ReportingService` interface; `MockReportingService`; `GenerateMiFIRReport` wired into `SealBlock` for every trade. `POST /v1/admin/reports/submit` to manually trigger submission of queued reports.

**Test cases:** `TestMiFIRReport_GeneratedForEveryTrade`, `TestMiFIRReport_FieldsCorrect`

---

### Track C — Governance

**Goal:** Implement execution logic for all declared corporate action types and establish on-chain shareholder voting.

#### C-01 — `ExecuteDragAlong` (Gap G-12)
**Files:** `corporate.go`  
**Effort:** 2 days  
**Dependencies:** None (ROFR infrastructure already present)  
**Deliverable:** `ExecuteDragAlong()` function. API endpoint `POST /v1/corporate-actions/{id}/execute` (issuer-only).

**Test cases:** `TestDragAlong_ForcesMinorityTransfer`, `TestDragAlong_ThresholdNotMet_Rejected`, `TestDragAlong_CreatesPaymentInstructions`

---

#### C-02 — `CheckTagAlong` + `ExecuteTagAlong` (Gap G-13)
**Files:** `corporate.go`, `assets.go`  
**Effort:** 2 days  
**Dependencies:** C-01 (shares the same action execution pattern)  
**Deliverable:** `ErrTagAlongTriggered` sentinel error; `CheckTagAlong()`; `ExecuteTagAlong()`; wired into `AssetTransaction.Validate` alongside `CheckROFR`.

**Test cases:** `TestTagAlong_Triggered_MajoritySale`, `TestTagAlong_NotTriggered_MinoritySale`, `TestTagAlong_ExecuteProportionalTransfer`

---

#### C-03 — `ExecuteDividend` (Gap G-14)
**Files:** `corporate.go`, `payment.go`, `blockchain.go`  
**Effort:** 2 days  
**Dependencies:** C-01 (payment instruction creation pattern)  
**Deliverable:** `ExecuteDividend()` with record-date snapshot. `DividendHoldingSnapshot` on `Blockchain`. `SealBlock` takes snapshot when record-date block is sealed.

**Test cases:** `TestDividend_ProportionalToBalance`, `TestDividend_RecordDateSnapshot_ExcludesLateAcquirers`, `TestDividend_TotalMatchesCirculatingSupply`

---

#### C-04 — On-chain shareholder voting (Gap G-15)
**Files:** New `governance.go`; `api/handlers.go`, `api/server.go`  
**Effort:** 1 week  
**Dependencies:** C-03 (record-date snapshot mechanism)  
**Deliverable:** `VoteProposal`, `VoteResponse`, `VoteResult`, `TallyVotes()`. API: `POST /v1/governance/votes`, `POST /v1/governance/votes/{id}/respond`, `GET /v1/governance/votes/{id}/result`.

**Test cases:** `TestVote_OrdinaryResolution_Passes`, `TestVote_SpecialResolution_Requires75Pct`, `TestVote_ZeroBalanceHolder_CannotVote`, `TestVote_DuplicateBallotRejected`

---

#### C-05 — Protocol governance (Gap G-16)
**Files:** New `protocol_governance.go`; `blockchain.go`; `api/handlers.go`  
**Effort:** 2 weeks  
**Dependencies:** C-04 (shares the voting/tally infrastructure)  
**Deliverable:** `ProtocolProposal` struct; delegate multi-sig ratification; `SealBlock` applies ratified proposals at `EffectiveAt`.

**Test cases:** `TestProtocolProposal_ThresholdSigsRequired`, `TestProtocolProposal_AppliedAtEffectiveAt`, `TestProtocolProposal_NonDelegateRejected`

---

### Track D — Oracle Infrastructure

**Goal:** Replace the single oracle key with a threshold scheme, add real data feeds, implement staleness guards and an audit log, and decouple DVP settlement.

#### D-01 — `SignedValuation` + staleness guard (Gap G-18)
**Files:** `reporting.go`  
**Effort:** 1 day  
**Dependencies:** None  
**Deliverable:** `SignedValuation` struct; updated `ValuationOracle` interface; `MockValuationOracle` updated to use `SignedValuation` with configurable TTL. `GenerateHoldingsReport` returns error on stale valuation.

**Test cases:** `TestValuation_StaleReturnsError`, `TestValuation_FreshPasses`, `TestHoldingsReport_StaleValuationPropagatesError`

---

#### D-02 — `OracleAuditLog` (Gap G-20)
**Files:** New `oracle_audit.go`; `kms_oracle.go`  
**Effort:** 2 days  
**Dependencies:** None  
**Deliverable:** `OracleAuditEntry` + `OracleAuditLog`; `KMSOracleService.SignInstruction` and `SignConfirmation` append to log; `VerifyChain()` validates the hash chain; `GET /v1/admin/oracle/audit` endpoint.

**Test cases:** `TestAuditLog_AppendAndVerify`, `TestAuditLog_TamperedEntryDetected`, `TestAuditLog_ChainIntegrityAfterRotation`

---

#### D-03 — `ECBRateAdapter` (Gap G-19)
**Files:** New `ecb_rate_oracle.go`; `reporting.go`  
**Effort:** 2 days  
**Dependencies:** D-01 (`SignedFXRate` uses the same signature infrastructure)  
**Deliverable:** `ECBRateAdapter` fetching daily ECB rates; 24h cache with `ValidUntil`; rates signed by oracle key. `MockValuationOracle.GetCurrencyRate` updated to proxy to `ECBRateAdapter` in tests where FX accuracy matters.

**Test cases:** `TestECBRate_FetchAndCache`, `TestECBRate_StaleRateReturnsError`, `TestECBRate_GBPEURWithinTolerance`

---

#### D-04 — `NAVFeedAdapter` interface + custodian stub (Gap G-18)
**Files:** New `nav_feed.go`  
**Effort:** 3 days  
**Dependencies:** D-01  
**Deliverable:** `NAVFeedAdapter` interface; `MockNAVFeedAdapter`; stub for iCapital/Alter Domus API format. The `Blockchain.ValuationOracle` uses `NAVFeedAdapter` for `AssetTypeParticipationNote` assets.

**Test cases:** `TestNAVFeed_LatestNAVServed`, `TestNAVFeed_StaleNAVRejected`

---

#### D-05 — Oracle price aggregation with median pricing (Gap G-18)
**Files:** New `oracle_aggregator.go`  
**Effort:** 1 week  
**Dependencies:** D-03, D-04  
**Deliverable:** `OracleAggregator` that queries multiple `NAVFeedAdapter` or `MarketDataAdapter` sources and produces a signed `SignedValuation` using the median price. Minimum 2 sources required; single-source failure does not block valuation.

**Test cases:** `TestAggregator_MedianOfThreeSources`, `TestAggregator_OneSourceFails_StillProducesMedian`, `TestAggregator_AllSourcesFail_ReturnsError`

---

#### D-06 — Independent settlement co-signature (Gap G-21)
**Files:** `payment.go`, `blockchain.go`  
**Effort:** 1 week  
**Dependencies:** D-02 (audit log must record both signatures)  
**Deliverable:** `SettlementOracle` interface; `SettlementAuthorisation` struct attached to `PaymentConfirmation`; `finalizeBlock` / DVP path checks both `OracleService.VerifyConfirmation` and `SettlementOracle.AuthoriseSettlement` before calling `ApplyAssetTransaction`.

**Test cases:** `TestDVP_SingleSignatureRejected`, `TestDVP_BothSignaturesAccepted`, `TestDVP_CompromisedPaymentOracle_CannotSettleAlone`

---

#### D-07 — `ThresholdOracleService` (Gap G-17)
**Files:** New `threshold_oracle.go`; `payment.go` (`ThresholdSignatureSet`); `kms_oracle.go` (key rotation hook)  
**Effort:** 2 weeks  
**Dependencies:** D-02, D-06  
**Deliverable:** `ThresholdOracleService` ($2$-of-$3$); `OracleKeyRegistry` on-chain record; `PaymentInstruction.OracleSignature` migrated to `ThresholdSignatureSet`; key rotation API `POST /v1/admin/oracle/rotate`.

**Test cases:** `TestThresholdOracle_TwoOfThreeValid`, `TestThresholdOracle_OneOfThreeRejected`, `TestThresholdOracle_KeyRotationPreservesHistory`

---

### Track E — Foundations (consolidated from `GAP_REMEDIATION_PLAN.md`)

| ID | Gap | Files | Effort | Status |
|---|---|---|---|---|
| E-01 | Issuer initial holding | `api/handlers.go` | ~8 lines | ✅ Fixed |
| E-02 | Lockup on holding creation | `assets.go` | — | ✅ Closed |
| E-03 | Wire CheckROFR into Validate | `assets.go`, `dBFT.go`, `p2p.go` | ~20 lines | ✅ Fixed |
| E-04 | PostgreSQL persistence | New `store/` package | 1–2 weeks | Open |
| E-05 | Thread safety — mutex on `Blockchain` | `blockchain.go` | 1 day | Open |
| E-06 | Modulr live payment provider | New `modulr_payment.go` | 3–5 days | Open |
| E-07 | `KMSKeyProvider` no-op stub | `keymanager.go` | 3 days | Open |
| E-08 | Multi-node deployment | `dBFT.go`, devops | 1–2 weeks | Open |

---

## Part VII — Sprint Sequencing

Sprints are two-week cycles. Dependencies are respected; no item begins before its listed dependencies are complete.

### Sprint 1 — Regulatory Unblocking & Data Integrity
**Primary goal:** Close all critical blockers that prevent a real distribution from going live.

| Item | Owner | Dependencies |
|---|---|---|
| B-01 — Prospectus exemption API | Engineering | — |
| B-02 — MiFID II suitability API | Engineering | — |
| B-03 — KYC expiry enforcement | Engineering | — |
| B-04 — UK jurisdiction rule | Engineering | B-01 |
| A-01 — Supply consistency reconciliation | Engineering | — |
| A-02 — `VerifyIssuerSignature` in Validate | Engineering | A-01 |
| E-05 — Thread safety (mutex) | Engineering | — |

**Sprint 1 exit criteria:** `go test ./...` passes; `POST /v1/assets/{id}/exemption` creates an enforced cap; warrants can be transferred after suitability registration; expired KYC credential blocks transfer; `CirculatingSupply` is reconciled on every sealed block.

---

### Sprint 2 — Governance Execution & Oracle Hardening
**Primary goal:** Implement the execution logic for all declared corporate actions; add valuation staleness and oracle audit.

| Item | Owner | Dependencies |
|---|---|---|
| C-01 — `ExecuteDragAlong` | Engineering | — |
| C-02 — `CheckTagAlong` + `ExecuteTagAlong` | Engineering | C-01 |
| C-03 — `ExecuteDividend` | Engineering | C-01 |
| D-01 — `SignedValuation` + staleness guard | Engineering | — |
| D-02 — `OracleAuditLog` | Engineering | — |
| D-03 — `ECBRateAdapter` | Engineering | D-01 |

**Sprint 2 exit criteria:** Drag-along execution test passes with forced minority transfer; dividends create proportional payment instructions; `GetValuation` returns `ErrStaleValuation` on expired price; every oracle signing operation has an audit entry.

---

### Sprint 3 — Issuance Integrity & AML Depth
**Primary goal:** Strengthen the on-chain/off-chain link; add behavioural AML.

| Item | Owner | Dependencies |
|---|---|---|
| A-03 — `LegalDocAmendment` log | Engineering | — |
| A-04 — Dual-authority issuance | Engineering | A-02 |
| B-05 — AML rules engine | Engineering | — |
| B-06 — SAR workflow | Engineering | B-05 |
| B-07 — FATF Travel Rule | Engineering | D-03 |

**Sprint 3 exit criteria:** Participation note issuance blocked without admin countersig; SAR created on behavioural flag; transfer ≥ EUR 1,000 without travel rule payload rejected.

---

### Sprint 4 — Instrument Lifecycle & Persistence
**Primary goal:** Enable warrants, convertibles, and capital calls; add state persistence.

| Item | Owner | Dependencies |
|---|---|---|
| A-05 — Warrant exercise | Engineering | A-04 |
| A-06 — Convertible conversion | Engineering | A-05 |
| D-04 — NAV feed adapter | Engineering | D-01 |
| D-05 — Oracle price aggregation | Engineering | D-03, D-04 |
| E-04 — PostgreSQL persistence | Engineering | — |
| E-06 — Modulr payment provider | Engineering + Modulr onboarding | E-04 |

**Sprint 4 exit criteria:** Warrant exercise reduces warrant balance and creates equity holding; NAV prices signed and served via aggregated oracle; state survives server restart; Modulr sandbox payment triggers DVP transfer.

---

### Sprint 5 — Voting, DVP Decoupling & Reporting
**Primary goal:** On-chain shareholder voting; independent settlement oracle; regulatory reporting hook.

| Item | Owner | Dependencies |
|---|---|---|
| C-04 — On-chain shareholder voting | Engineering | C-03 |
| D-06 — Independent settlement co-signature | Engineering | D-02 |
| A-07 — Anti-dilution provisions | Engineering | A-06 |
| A-08 — Capital call enforcement | Engineering | A-04, C-03 |
| B-09 — Regulatory reporting pipeline | Engineering | E-04 |

**Sprint 5 exit criteria:** Vote proposal created; holders can submit signed ballots; tally produces correct `VoteResult`; DVP transfer requires two independent oracle signatures; MiFIR report generated for every trade.

---

### Sprint 6 — Threshold Oracle, Protocol Governance & Live AML
**Primary goal:** Production-grade oracle, on-chain protocol governance, live sanctions screening.

| Item | Owner | Dependencies |
|---|---|---|
| D-07 — `ThresholdOracleService` | Engineering | D-02, D-06 |
| C-05 — Protocol governance | Engineering | C-04 |
| B-08 — Live ComplyAdvantage AML | Engineering + CA onboarding | B-05 |
| E-07 — Production KMS migration | Engineering + GCP/AWS | — |
| E-08 — Multi-node deployment | DevOps | E-04, E-07 |

**Sprint 6 exit criteria:** Single oracle key cannot sign a valid instruction without the second; protocol parameter change ratified by delegate threshold takes effect at scheduled block; OFAC SDN wallet blocked by ComplyAdvantage live call; nodes deployed across ≥ 3 separate machines with consensus verified.

---

## Part VIII — Test Coverage Targets

Every gap closed must ship with the test cases listed below. All tests must pass `go test ./... -race` (race detector enabled).

### Track A Tests

| Test function | Gap |
|---|---|
| `TestCirculatingSupply_ConsistencyAfterIssue` | A-01 |
| `TestCirculatingSupply_ConsistencyAfterTransfer` | A-01 |
| `TestCirculatingSupply_DetectsDivergence` | A-01 |
| `TestValidate_TamperedAssetRejected` | A-02 |
| `TestLegalDoc_AmendmentChain` | A-03 |
| `TestIssue_ParticipationNoteBlockedWithoutCountersig` | A-04 |
| `TestIssue_ParticipationNoteReleasedAfterCountersig` | A-04 |
| `TestWarrant_ExerciseReducesWarrantBalance` | A-05 |
| `TestWarrant_ExerciseIncreasesEquityBalance` | A-05 |
| `TestConvertible_ConversionAtMaturity` | A-06 |
| `TestAntiDilution_DownRoundAdjustsConversionRatio` | A-07 |
| `TestCapitalCall_InstructionCreatedPerHolder` | A-08 |

### Track B Tests

| Test function | Gap |
|---|---|
| `TestProspectusExemption_CreateAndEnforce` | B-01 |
| `TestProspectusExemption_NonIssuerForbidden` | B-01 |
| `TestProspectusExemption_CapEnforced_149thPasses_150thFails` | B-01 |
| `TestSuitabilityAssessment_WarrantBlockedWithout` | B-02 |
| `TestSuitabilityAssessment_WarrantAllowedWith` | B-02 |
| `TestSuitabilityAssessment_ProfessionalInvestorAutoPass` | B-02 |
| `TestTransfer_ExpiredCredentialRejected` | B-03 |
| `TestCredentialSweep_EmitsExpiredEvent` | B-03 |
| `TestJurisdiction_GBEquityAllowed` | B-04 |
| `TestAMLRule_TM02_VolumeThreshold` | B-05 |
| `TestAMLRule_TM04_LayeringPattern` | B-05 |
| `TestSAR_CreatedOnFlagAlert` | B-06 |
| `TestSAR_UnresolvedBlocksWallet` | B-06 |
| `TestTravelRule_AboveThresholdRequiresPayload` | B-07 |
| `TestComplyAdvantage_SDNMatch_Blocks` | B-08 |
| `TestMiFIRReport_GeneratedForEveryTrade` | B-09 |

### Track C Tests

| Test function | Gap |
|---|---|
| `TestDragAlong_ForcesMinorityTransfer` | C-01 |
| `TestDragAlong_ThresholdNotMet_Rejected` | C-01 |
| `TestTagAlong_Triggered_MajoritySale` | C-02 |
| `TestTagAlong_NotTriggered_MinoritySale` | C-02 |
| `TestDividend_ProportionalToBalance` | C-03 |
| `TestDividend_RecordDateSnapshot_ExcludesLateAcquirers` | C-03 |
| `TestVote_OrdinaryResolution_Passes` | C-04 |
| `TestVote_SpecialResolution_Requires75Pct` | C-04 |
| `TestVote_DuplicateBallotRejected` | C-04 |
| `TestProtocolProposal_ThresholdSigsRequired` | C-05 |

### Track D Tests

| Test function | Gap |
|---|---|
| `TestValuation_StaleReturnsError` | D-01 |
| `TestHoldingsReport_StaleValuationPropagatesError` | D-01 |
| `TestAuditLog_TamperedEntryDetected` | D-02 |
| `TestECBRate_GBPEURWithinTolerance` | D-03 |
| `TestECBRate_StaleRateReturnsError` | D-03 |
| `TestAggregator_MedianOfThreeSources` | D-05 |
| `TestDVP_SingleSignatureRejected` | D-06 |
| `TestDVP_BothSignaturesAccepted` | D-06 |
| `TestThresholdOracle_TwoOfThreeValid` | D-07 |
| `TestThresholdOracle_OneOfThreeRejected` | D-07 |
| `TestThresholdOracle_KeyRotationPreservesHistory` | D-07 |

---

## Part IX — Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Prospectus exemption live cap breached before B-01 is deployed | High | Regulatory sanction | Temporary hard-limit distribution to zero retail investors in any single jurisdiction until B-01 ships |
| `CirculatingSupply` divergence produces wrong FiDA reports sent to investors | Medium | Legal/reputational | Deploy A-01 as a hotfix (single function + test; can be merged in hours) |
| Single oracle key compromise → fraudulent payment instructions | Low | Critical / financial | Priority-escalate D-07; in the interim, implement manual operator review of all oracle-signed instructions above EUR 100k |
| NAV oracle stale → incorrect unrealised P&L in tax reports | High (mock returns 1.0 for all assets) | Reputational / legal | Block FiDA report generation for assets with `ValidUntil < now`; deploy D-01 before any investor-facing reporting |
| FATF Travel Rule breach on cross-border transfers | High (no Travel Rule payload exists) | Regulatory fine | Add `TravelRulePayload` validation to `Validate` before any cross-border transfers exceed EUR 1,000 |
| Dividend capture around record date via rapid token transfers | Medium | Reputational / financial | Record-date snapshot (C-03) must ship before first dividend distribution |
| ComplyAdvantage API outage blocks all transfers | Low-Medium | Operational | Implement circuit-breaker in `ComplyAdvantageScreener`: if API is unreachable, fall back to `MockAMLScreener` with enhanced behavioural rules + alert compliance team |
