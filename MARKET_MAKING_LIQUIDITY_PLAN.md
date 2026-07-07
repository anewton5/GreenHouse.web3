# Market-Making & Liquidity Provision — Execution Plan

> Companion to `VELA Markets Platform Strategy.md` (§4 — Research: Market-Making &
> Liquidity Provision), `COMPLIANCE_IDENTITY_LAYER_PLAN.md` (institutional identity
> layer this plan builds on — **COMPLETE**), `GAP_REMEDIATION_PLAN.md`, and
> `PRODUCTION_READINESS_PLAN.md`. This document does not duplicate items already
> tracked in those files — it covers RFQ, the Designated Market Maker Program, and
> market-data/risk feeds specifically.

**Status:** W1/W2/W3 implemented. W4 (AMM) removed by stakeholder decision. W5 implemented.

**Scope decisions (updated with stakeholder, 2026-07-07):**
- No AMM path is built in this plan (including opt-in, issuer-gated, or
  compliance-restricted variants). Secondary liquidity remains RFQ + existing CLOB/
  window mechanisms.
- RFQ quote acceptance is **manual**: a requester reviews received quotes and
  explicitly accepts one before expiry. No auto-best-price execution in this plan.
- The pre-existing dBFT gap where `AssetTransaction`/`OrderTransaction`/
  `CredentialTransaction` signatures are skipped during consensus voting
  (`PRODUCTION_READINESS_PLAN.md` lines 395, 512, 519) is **fixed now**, for all
  typed transactions, not only the new RFQ/MarketMaker types — because RFQ adds a
  new type through the exact same code path (`DefaultVotingStrategy.Vote` /
  `ValidateBlock`), so this is the natural moment to close it once for everything.
- RFQ remains the **default/primary** secondary-market mechanism for all private
  placement assets.
- The Market Maker Registry stays **centrally operator-gated** (`jwtAdmin`),
  consistent with the governance sequencing already documented in the strategy
  doc §6.4 (no decentralised governance at this stage).
- No parallel compliance engine is built for RFQ — it reuses the existing
  `AssetTransaction.Validate` gate, `CheckSuitability`, `CheckProspectusLimits`,
  `ApplyJurisdictionRule`, and the AML screener, exactly as the CLOB does today.

---

## 1. Current Architecture — Research Findings (baseline)

This section documents what already exists, established by direct code reading
before any implementation. Nothing here changes as part of this plan except
where explicitly noted.

### 1.1 Order matching (CLOB)
- `orderbook.go`: `Order`, `Trade`, `OrderBook`. Price-time-priority matching.
  `OrderBook.MatchOrders(assetID, currency)` returns `([]Trade, []*AssetTransaction, error)`.
  Produced `AssetTransaction`s are **unsigned** (`RequiredSigs: 1`, no signature) —
  in the Phase 0 simulation the simulation script signs them immediately; in
  production this is an off-chain signing request sent to the seller's client.
- `liquidity.go`: `WindowManager` / `LiquidityWindow` drive periodic-auction batch
  matching — `Tick(bc)` opens/closes windows and calls `MatchOrders` on close,
  then `applyDVP(bc, trade, atx)` runs the DVP settlement sequence (build
  `PaymentInstruction` → sign via `OracleService` → `PaymentProvider.ConfirmPayment`
  → `ApplyAssetTransaction`). **This `applyDVP` logic is the extraction target for
  Workstream W3** (see §4.4).

### 1.2 Blockchain state engine
- `blockchain.go`: `Blockchain.applyBlockState(block *Block)` is the single
  shared state-transition function called by both `SealBlock` (HTTP path) and
  `finalizeBlock` (dBFT consensus path). It currently processes, in order:
  asset transactions → credential transactions → claim/claim-issuer
  transactions → order transactions → order-book matching (continuous CLOB,
  skipping window-managed assets) → prospectus retail-count updates.
  **RFQ and Market Maker transactions must be added as new steps in this
  function** (§4.5, §2.4).
- Relevant `Blockchain` struct fields already present: `OrderBooks map[string]*OrderBook`,
  `Trades []Trade`, `PendingInstructions`, `PendingSettlements`,
  `SettlementRouter map[SettlementMethod]PaymentProvider`, `WindowManager`,
  `WindowResults []WindowResult`, `Claims map[string][]*Claim`, `TrustedIssuers`.
- `Block` / `blockHashInput` carry parallel slices per transaction family
  (`AssetTransactions`, `OrderTransactions`, `CredentialTransactions`,
  `ClaimTransactions`, `ClaimIssuerTransactions`) — **new `RFQTransactions` and
  `MarketMakerTransactions` slices follow the exact same pattern** (added to both
  `Block` and `blockHashInput` so they're covered by the signed payload hash).

### 1.3 Compliance gate (the ERC-3643-equivalent layer)
- `assets.go`: `AssetTransaction.Validate(bc, assets, holdings, credentials,
  pendingActions, screener...)` is **the** compliance gate: AML screening (block/flag
  severities, SAR draft creation), issuer-signature tamper check, MiFID II
  suitability, prospectus exemption caps (`CheckProspectusLimits`), jurisdiction
  rules (`ApplyJurisdictionRule`), lockups. `ApplyAssetTransaction` mutates
  `Holdings`/`CirculatingSupply` afterward.
- `api/handlers.go` `handleFillOrder` (issuer-as-dealer OTC fill, line ~2112) is
  the existing template for **defense-in-depth**: it replicates the compliance
  battery at the API layer (credential-expiry check, `CheckSuitability`,
  `CheckProspectusLimits`, `ApplyJurisdictionRule`, FATF Travel Rule derivation)
  *before* the resulting `AssetTransaction` is even built, in addition to the
  same checks running again inside `Validate` at block-apply time. **RFQ accept
  handlers must replicate this exact pattern** — do not invent new
  compliance logic.

### 1.4 Institutional identity / claims layer (COMPLETE, per `COMPLIANCE_IDENTITY_LAYER_PLAN.md`)
- `claims.go`: `ClaimTopic` enum (`kyc`, `aml_clear`, `accredited`,
  `jurisdiction_resident`, `pep_clear`, `suitability`, `institutional_role`,
  `custom`). `TrustedIssuersRegistry`, `ClaimTransaction`, `ClaimIssuerTransaction`.
- `entity_identity.go`: `LegalEntityIdentity` (LEI, jurisdiction, `did:webs`),
  `EntityRole` enum — currently `authorised_signatory`, `ubo`, `director`,
  `spv_admin`. **No `EntityRoleMarketMaker` yet — added in W1.** Roles are
  modelled as `ClaimTopicInstitutionalRole` claims (`"<LEI>:<role>"` payload via
  `EntityRoleClaimData`/`ParseEntityRoleClaim`/`HasEntityRole`), issued through
  the existing `IdentityRegistry.IssueClaim` + `SealClaimBlock` path.
- `api/server.go` / `api/handlers.go`: `POST /v1/admin/entities`,
  `GET /v1/entities`, `GET /v1/entities/{lei}`,
  `POST /v1/admin/entities/{lei}/role-claims` — the exact endpoint pattern W1
  reuses for granting the market-maker role.

### 1.5 Settlement / DVP
- `payment.go`: `PaymentInstruction`, `PaymentConfirmation`, `PaymentProvider`,
  `SettlementRegistrar`, `OracleService` interfaces. `SettlementMethod` enum
  (`sepa_instant`, `faster_payments`, `swift_gpi`, `eurc_on_chain`, `pontes_cbm`).
  `DefaultSettlementMethod(currency)` / `Blockchain.PreferredSettlementMethod(currency)`
  auto-upgrade EUR trades to CeBM/Pontes when registered.
- DVP settlement is currently duplicated in two places: inline in
  `applyBlockState` (continuous CLOB path) and in `WindowManager.applyDVP`
  (periodic-auction path). **W3 extracts a single shared
  `Blockchain.executeTradeDVP(trade Trade, atx *AssetTransaction)` helper** so
  RFQ and both existing CLOB paths call one settlement primitive.

### 1.6 Regulatory reporting
- `regulatory_reporting.go`: `GenerateMiFIRReport(bc, trade, blockIndex)` and
  `GenerateAIFMDReport(bc, trade, blockIndex)` are generic on the `Trade`
  struct — directly reusable for RFQ- and CLOB-executed trades with no interface
  changes.

### 1.7 P2P / consensus
- `p2p.go`: `MessageType*` string constants per transaction family, used for
  gossip. New constants needed: `MessageTypeRFQRequest`, `MessageTypeRFQQuote`,
  `MessageTypeRFQAccept`, `MessageTypeMarketMakerTransaction`.
- **Known gap** (`PRODUCTION_READINESS_PLAN.md` lines 395, 512, 519):
  `DefaultVotingStrategy.Vote` and `Blockchain.ValidateBlock` verify signatures
  on base `Transaction` only. `AssetTransaction`, `OrderTransaction`, and
  `CredentialTransaction` signatures are **not currently checked during dBFT
  consensus voting** (only `ValidateBlock`'s Item 11 checks cover them, and that
  function is one of potentially several validation paths — the dBFT voting
  strategy itself trusts them unverified). Confirmed with the user: **fixed in
  this plan for all typed transactions** (§3).
- `dbft_validate_typed_test.go` already documents/tests the target behaviour for
  `OrderTransaction`/`CredentialTransaction`/`AssetTransaction` signature
  acceptance/rejection at the `ValidateBlock` layer — this is the template to
  extend for `RFQTransaction`/`MarketMakerTransaction` and to audit against the
  `DefaultVotingStrategy.Vote` gap specifically.

### 1.8 Persistence
- `persistence.go`: `stateSnapshot` currently covers Assets/Holdings/
  Credentials/WalletSequences/ConfirmedPayments (per `COMPLIANCE_IDENTITY_LAYER_PLAN.md`
  bug #3, since expanded). **Any new state map introduced by this plan
  (`MarketMakerRegistry`, `RFQRequests`, `RFQQuotes`) must be
  added to `stateSnapshot` in the same change that introduces the map** — this
  exact bug class (new state silently not persisted) has already bitten this
  codebase once.

### 1.9 REST API conventions
- `api/server.go`: `mux.Handle("METHOD /v1/path", s.jwt(http.HandlerFunc(...)))`
  for authenticated routes, `s.jwtAdmin(...)` for operator-only routes,
  unauthenticated routes via plain `mux.HandleFunc`.
- Handlers decode a small anonymous request `struct` via `json.NewDecoder`,
  validate field-by-field with `writeError(w, http.StatusXXX, "...")`, and
  respond via `writeJSON(w, http.StatusOK, ...)`.

---

## 2. Workstream W1 — Designated Market Maker Program

**Depends on:** nothing (foundation). **Feeds into:** W3 (dealer eligibility gate),
W2 (new tx type to verify), W5 (position-limit fields).

### 2.1 Identity: new `EntityRole`
- [x] `entity_identity.go`: add `EntityRoleMarketMaker EntityRole = "market_maker"`
  to the existing `EntityRole` const block, alongside `AuthorisedSignatory`,
  `UBO`, `Director`, `SPVAdmin`. No other changes to `entity_identity.go` — the
  existing `EntityRoleClaimData`/`ParseEntityRoleClaim`/`HasEntityRole` machinery
  already supports an arbitrary role string.

### 2.2 New file `market_makers.go`
- [x] `MarketMakerAgreement` struct:
  ```go
  type MarketMakerAgreement struct {
      ID                     string  `json:"id"`
      AssetID                string  `json:"asset_id"`
      DealerKey              string  `json:"dealer_key"`   // base64-encoded Ed25519 public key
      DealerLEI              string  `json:"dealer_lei,omitempty"`
      FeeRebateBps           int     `json:"fee_rebate_bps"`
      MaxSpreadBps           int     `json:"max_spread_bps"`
      MinQuoteSize           float64 `json:"min_quote_size"`
      PriorityAllocationPct  float64 `json:"priority_allocation_pct"`
      MaxPositionUnits       float64 `json:"max_position_units,omitempty"`   // 0 = unlimited (used by W5)
      MaxPositionValue       float64 `json:"max_position_value,omitempty"`   // 0 = unlimited (used by W5)
      EffectiveFrom          int64   `json:"effective_from"`
      EffectiveTo            int64   `json:"effective_to,omitempty"` // 0 = open-ended
      Status                 MarketMakerStatus `json:"status"`
      CreatedAt              int64   `json:"created_at"`
      OperatorSignature      []byte  `json:"-"`
  }

  type MarketMakerStatus string
  const (
      MarketMakerStatusActive  MarketMakerStatus = "active"
      MarketMakerStatusRevoked MarketMakerStatus = "revoked"
      MarketMakerStatusExpired MarketMakerStatus = "expired"
  )
  ```
- [x] `NewMarketMakerAgreement(operatorKey *PrivateKey, assetID, dealerKey string,
  ...) (*MarketMakerAgreement, error)` — signs with the operator key, mirroring
  the `ClaimIssuerTransaction`/`NewOrder` signing pattern (marshal with
  `OperatorSignature: nil`, `sha3.Sum256`, sign).
- [x] `MarketMakerRegistry` struct + methods:
  ```go
  type MarketMakerRegistry struct {
      ByAsset map[string][]*MarketMakerAgreement // assetID -> agreements
  }

  func NewMarketMakerRegistry() *MarketMakerRegistry
  func (r *MarketMakerRegistry) RegisterMarketMaker(a *MarketMakerAgreement) error
  func (r *MarketMakerRegistry) RevokeMarketMaker(id string) error
  func (r *MarketMakerRegistry) IsDesignatedMarketMaker(assetID, walletKey string) bool
  func (r *MarketMakerRegistry) ActiveAgreementsFor(assetID string) []*MarketMakerAgreement
  func (r *MarketMakerRegistry) AgreementFor(assetID, walletKey string) *MarketMakerAgreement // used by W5 for position limits
  ```
  `IsDesignatedMarketMaker` must check `Status == MarketMakerStatusActive`,
  `EffectiveFrom <= now`, and (`EffectiveTo == 0 || now <= EffectiveTo`).
- [x] Registration precondition: the dealer wallet must already hold a valid
  `EntityRoleMarketMaker` claim (via `HasEntityRole` against `bc.Claims`) before
  `RegisterMarketMaker` succeeds — reuse, don't duplicate, the Phase 3 identity
  check.
- [x] New `MarketMakerTransaction` type for consensus propagation:
  ```go
  type MarketMakerTransactionAction string
  const (
      MarketMakerActionRegister MarketMakerTransactionAction = "register"
      MarketMakerActionRevoke   MarketMakerTransactionAction = "revoke"
  )

  type MarketMakerTransaction struct {
      Tx         Transaction // Tx.Sender = operator key (signs base Tx too, for uniform typed-tx verification — see W2)
      Agreement  MarketMakerAgreement
      Action     MarketMakerTransactionAction
      RevokeID   string `json:",omitempty"` // set when Action == revoke
  }
  ```

### 2.3 Blockchain wiring
- [x] `blockchain.go`: add `MarketMakerRegistry *MarketMakerRegistry` field to
  `Blockchain`; initialise in `NewBlockchain` via `NewMarketMakerRegistry()`.
- [x] `blockchain.go`: add `[]MarketMakerTransaction` to `Block` and
  `blockHashInput` (`MarketMakerTransactions`), following the exact pattern of
  `ClaimIssuerTransactions`.
- [x] `applyBlockState`: add a processing step for `block.MarketMakerTransactions`
  (register → `RegisterMarketMaker`; revoke → `RevokeMarketMaker`), emitting a
  new `EventMarketMakerRegistered` / `EventMarketMakerRevoked` stream event.
- [x] `persistence.go`: add `MarketMakerRegistry` to `stateSnapshot` in the same
  commit that introduces the field (see §1.8).

### 2.4 API endpoints
- [x] `POST /v1/admin/market-makers` (`jwtAdmin`) — body: `{asset_id, dealer_key,
  dealer_lei, fee_rebate_bps, max_spread_bps, min_quote_size,
  priority_allocation_pct, max_position_units, max_position_value,
  effective_from, effective_to}`. Verifies the dealer already holds
  `EntityRoleMarketMaker` (reject with 409 if not — direct the caller to
  `POST /v1/admin/entities/{lei}/role-claims` first); builds and commits a
  `MarketMakerTransaction` via a new `SealMarketMakerBlock` (mirrors
  `SealClaimBlock`'s pattern of a dedicated Seal function reusing
  `applyBlockState`, to avoid changing `SealBlock`'s signature).
- [x] `GET /v1/market-makers/{assetID}` (`jwt`) — list active agreements for an asset.
- [x] `DELETE /v1/admin/market-makers/{id}` (`jwtAdmin`) — revoke.

### 2.5 Tests
- [x] `market_makers_test.go`: agreement sign/verify, `IsDesignatedMarketMaker`
  time-window edge cases (not-yet-effective, expired, revoked), registration
  rejected without a prior `EntityRoleMarketMaker` claim, registry persistence
  round-trip.
- [x] API-level test in `api/` mirroring `corporate_actions_test.go` conventions
  for the three new endpoints (admin-only enforcement, dealer-role precondition).

---

## 3. Workstream W2 — dBFT Typed-Transaction Signature Hardening

**Depends on:** tx-type definitions from W1 (`MarketMakerTransaction`) and W3
(`RFQTransaction`) existing (can be stubbed early and developed in parallel;
verification logic lands once both types are defined). **Blocks:** W3/W4 going
live in consensus mode (`dbft`) — RFQ must not repeat the unverified-signature
gap on day one.

- [x] Audit `dBFT.go`'s `DefaultVotingStrategy.Vote` (and any other pre-vote
  validation path distinct from `Blockchain.ValidateBlock`) to confirm exactly
  which typed-transaction signature checks are missing at the *voting* stage
  versus already covered at the *validate-block* stage. Audit result: `Vote`
  duplicated a partial subset of typed checks (base/asset/order, plus the W2
  market-maker base-tx stub) and did **not** call `ValidateBlock`; RFQ and
  market-maker payload checks were also missing from `ValidateBlock` itself.
- [x] Extend whichever function(s) are found to be missing checks so that,
  for every block a delegate is asked to vote on, the delegate verifies:
  - `AssetTransaction.Tx` sender signature (skip when `RequiredSigs == 0`,
    matching the existing `ValidateBlock` Item 11 Step A carve-out for
    genesis/internal issuances).
  - `OrderTransaction.Order` signature (skip for cancellations, matching Item 11
    Step B).
  - `CredentialTransaction.Attestation` registry signature (skip when
    `bc.IdentityRegistry == nil`, matching Item 11 Step C).
  - **New:** `RFQTransaction` — verify the requester's signature on
    `RFQRequest` and, for quote/accept sub-actions, the dealer's/requester's
    signature respectively (§4.2).
  - **New:** `MarketMakerTransaction` — verify the operator signature via
    `bc.OperatorKeyProvider.Verify` (mirrors the existing
    `ClaimIssuerTransaction` admin-signature check in `ValidateBlock`).
- [x] Ensure the fix does not change `dbft` mode's finality/liveness properties
  — a block a delegate rejects for a bad typed-tx signature must trigger the
  existing view-change path exactly as a bad base-`Transaction` signature
  would today, not a panic or silent skip.
- [x] Extend `dbft_validate_typed_test.go` with reject/accept cases for **all
  five** typed-transaction families (`AssetTransaction`, `OrderTransaction`,
  `CredentialTransaction`, `RFQTransaction`, `MarketMakerTransaction`),
  following the file's existing structure (see its header comment listing
  current coverage) — including a case that specifically exercises
  `DefaultVotingStrategy.Vote` (not just `ValidateBlock`) for each family, since
  that is the gap the user asked to close.

---

## 4. Workstream W3 — RFQ Engine

**Depends on:** W1 (dealer eligibility gate via `MarketMakerRegistry.IsDesignatedMarketMaker`).
**Produces:** `Blockchain.executeTradeDVP`, shared by RFQ + existing CLOB/window settlement paths.

### 4.1 New file `rfq.go` — types

```go
type RFQRequestStatus string
const (
    RFQRequestStatusOpen      RFQRequestStatus = "open"
    RFQRequestStatusQuoted    RFQRequestStatus = "quoted"    // >=1 active quote received
    RFQRequestStatusAccepted  RFQRequestStatus = "accepted"
    RFQRequestStatusExpired   RFQRequestStatus = "expired"
    RFQRequestStatusCancelled RFQRequestStatus = "cancelled"
)

// RFQRequest is signed by the requester, mirroring Order's signing pattern.
type RFQRequest struct {
    ID           string           `json:"id"`
    AssetID      string           `json:"asset_id"`
    RequesterKey string           `json:"requester_key"`
    Side         OrderSide        `json:"side"` // reuse OrderSideBid/OrderSideAsk
    Quantity     float64          `json:"quantity"`
    LimitPrice   float64          `json:"limit_price,omitempty"` // 0 = no limit; still uses currency-precision compliance checks
    ExpiresAt    int64            `json:"expires_at"`            // Unix seconds
    Status       RFQRequestStatus `json:"status"`
    CreatedAt    int64            `json:"created_at"`
    Signature    []byte           `json:"-"`
}

type RFQQuoteStatus string
const (
    RFQQuoteStatusActive   RFQQuoteStatus = "active"
    RFQQuoteStatusAccepted RFQQuoteStatus = "accepted"
    RFQQuoteStatusRejected RFQQuoteStatus = "rejected"
    RFQQuoteStatusExpired  RFQQuoteStatus = "expired"
)

// RFQQuote is signed by the quoting dealer.
type RFQQuote struct {
    ID        string         `json:"id"`
    RequestID string         `json:"request_id"`
    DealerKey string         `json:"dealer_key"`
    Price     float64        `json:"price"`
    Quantity  float64        `json:"quantity"` // dealer may quote less than the full requested size
    ExpiresAt int64          `json:"expires_at"` // short TTL, e.g. 30s-5min
    Status    RFQQuoteStatus `json:"status"`
    CreatedAt int64          `json:"created_at"`
    Signature []byte         `json:"-"`
}

type RFQTransactionAction string
const (
    RFQActionRequest RFQTransactionAction = "request"
    RFQActionQuote   RFQTransactionAction = "quote"
    RFQActionAccept  RFQTransactionAction = "accept"
    RFQActionCancel  RFQTransactionAction = "cancel"
)

// RFQTransaction is broadcast via P2P / included in blocks, mirroring OrderTransaction.
type RFQTransaction struct {
    Tx        Transaction          // Tx.Sender = requester (request/accept/cancel) or dealer (quote)
    Action    RFQTransactionAction
    Request   RFQRequest `json:",omitempty"`
    Quote     RFQQuote   `json:",omitempty"`
    AcceptID  string     `json:",omitempty"` // quote ID being accepted, set when Action == accept
}
```

- [x] `NewRFQRequest(requesterKey *PrivateKey, assetID string, side OrderSide,
  quantity, limitPrice float64, expiresAt int64) (*RFQRequest, error)` — same
  sign pattern as `NewOrder`.
- [x] `NewRFQQuote(dealerKey *PrivateKey, requestID string, price, quantity
  float64, expiresAt int64) (*RFQQuote, error)`.
- [x] `(*RFQRequest).VerifySignature(pub *PublicKey) bool`,
  `(*RFQQuote).VerifySignature(pub *PublicKey) bool` — same
  marshal-with-nil-sig-then-hash pattern as `Order.VerifySignature`.
- [x] `(*RFQRequest).IsExpired() bool`, `(*RFQQuote).IsExpired() bool`.

### 4.2 `RFQEngine` (or `Blockchain` methods directly — decide during implementation
based on how much state needs to be threaded; leaning toward methods on
`Blockchain` for consistency with `WindowManager` being a field, not a
free-floating engine)

- [x] `Blockchain.RFQRequests map[string]*RFQRequest`,
  `Blockchain.RFQQuotes map[string][]*RFQQuote` (keyed by `RequestID`) —
  new fields on `Blockchain`, initialised in `NewBlockchain`.
- [x] Request creation: any registered/KYC'd wallet may create a request (no
  market-maker gate on the requester side — only quoting dealers are gated).
- [x] Quote submission: **gate** — `bc.MarketMakerRegistry.IsDesignatedMarketMaker(
  request.AssetID, quote.DealerKey)` must be true, else reject with a clear
  error (`"wallet is not a designated market maker for this asset"`).
- [x] Accept (manual, per confirmed decision #2): the **requester** — and only
  the requester (`quote.RequestID` request's `RequesterKey == caller`) — selects
  exactly one active, non-expired quote. On accept:
  1. Re-run the **same compliance battery `handleFillOrder` runs**: credential
     expiry check, `CheckSuitability`, `CheckProspectusLimits`,
     `ApplyJurisdictionRule`, `AutoTravelRule` — at the API layer, before
     building any transaction (defense-in-depth, matching §1.3).
  2. Build a `Trade` (reuse the existing `Trade` struct): `BidOrderID`/
     `AskOrderID` set to synthetic values — e.g. `"rfq:" + request.ID` /
     `"rfq:" + quote.ID` — so RFQ trades are visually distinguishable from CLOB
     trades in `bc.Trades` and in `GET /v1/trades` without a schema change.
     `BuyerID`/`SellerID` derived from `request.Side` (bid → requester is buyer,
     dealer is seller; ask → reverse).
  3. Build an unsigned `AssetTransaction` exactly as `MatchOrders` does
     (`RequiredSigs: 1`, empty signature — same production caveat: off-chain
     signing request to the seller in a live deployment).
  4. Settle via `bc.executeTradeDVP(trade, atx)` (§4.4).
  5. Mark the accepted quote `RFQQuoteStatusAccepted`, all other active quotes
     for that request `RFQQuoteStatusRejected`, and the request
     `RFQRequestStatusAccepted`.
  6. Call `GenerateMiFIRReport(bc, trade, blockIndex)` /
     `GenerateAIFMDReport(bc, trade, blockIndex)` — same as CLOB trades (§1.6).
- [x] Expiry sweep: an `ExpireRFQRequests()`/`ExpireRFQQuotes()` pair, called at
  the top of `applyBlockState` alongside the existing `ExpireStaleInstructions()`
  call, marking past-TTL requests/quotes `RFQRequestStatusExpired`/
  `RFQQuoteStatusExpired`.

### 4.3 P2P / consensus wiring
- [x] `p2p.go`: add `MessageTypeRFQRequest = "rfq_request"`,
  `MessageTypeRFQQuote = "rfq_quote"`, `MessageTypeRFQAccept = "rfq_accept"`.
- [x] `blockchain.go`: add `RFQTransactions []RFQTransaction` to `Block` and
  `blockHashInput`.
- [x] `applyBlockState`: new processing step for `block.RFQTransactions`,
  dispatching on `Action` (request/quote/accept/cancel) into the `RFQRequests`/
  `RFQQuotes` maps, following the exact structural pattern already used for
  `block.OrderTransactions` (step 4 in the current `applyBlockState`).
- [x] New stream events: `EventRFQRequestCreated`, `EventRFQQuoteSubmitted`,
  `EventRFQAccepted`, `EventRFQExpired` — mirroring `EventOrderPlaced`/
  `EventOrderCancelled`'s existing shape.
- [x] `persistence.go`: add `RFQRequests`, `RFQQuotes` to `stateSnapshot`.
- [x] W2 must cover `RFQTransaction` signature verification before this ships in
  `dbft` consensus mode (see §3).

### 4.4 Settlement refactor — `Blockchain.executeTradeDVP`
- [x] Extract the body of `WindowManager.applyDVP` (build `PaymentInstruction` →
  `OracleService.SignInstruction` → `PaymentProvider.ConfirmPayment` →
  `GetPaymentStatus` → `OracleService.SignConfirmation` →
  `cacheConfirmedPaymentLocked`/`persistConfirmedPaymentLocked` →
  `ApplyAssetTransaction`) into a new `Blockchain` method:
  ```go
  // executeTradeDVP settles trade by issuing a PaymentInstruction, confirming
  // it through the preferred settlement provider, and applying the resulting
  // AssetTransaction. Used by the continuous CLOB path, WindowManager, RFQ
  // acceptance so all three share one settlement primitive.
  // bc.Mu must be held by the caller.
  func (bc *Blockchain) executeTradeDVP(trade Trade, atx *AssetTransaction) error
  ```
- [x] Update `WindowManager.applyDVP` to call `bc.executeTradeDVP` instead of
  inlining the sequence (keeps `liquidity.go` unchanged in behaviour, removes
  duplication).
- [x] Route the continuous-CLOB settlement block in `applyBlockState` through
  `executeTradeDVP` as the planned low-risk cleanup, so matching, RFQ, and
  liquidity-window paths now share one settlement primitive.

### 4.5 API endpoints
- [x] `POST /v1/rfq/requests` (`jwt`) — body: `{asset_id, side, quantity,
  limit_price?, ttl_seconds}`. Same registration-approval precondition as
  `handlePlaceOrder` (`RegRegistry.Get(walletKey).Status ==
  RegistrationStatusApproved`).
- [x] `GET /v1/rfq/requests?assetID=` (`jwt`) — dealer view: only requests for
  assets where `bc.MarketMakerRegistry.IsDesignatedMarketMaker(assetID,
  callerKey)` is true, plus the requester's own requests regardless of role.
- [x] `POST /v1/rfq/requests/{id}/quotes` (`jwt`) — dealer submits a quote;
  403 if not a designated market maker for the request's asset.
- [x] `GET /v1/rfq/requests/{id}/quotes` (`jwt`) — requester views received
  quotes (403 for anyone but the requester).
- [x] `POST /v1/rfq/requests/{id}/accept` (`jwt`) — body: `{quote_id}`.
  Requester-only; runs the full compliance battery (§4.2 step 1) before
  committing.
- [x] `DELETE /v1/rfq/requests/{id}` (`jwt`) — requester cancels an open request.

### 4.6 Tests
- [x] `rfq_test.go`: request/quote sign-verify-tamper, dealer-gate rejection
  (non-designated wallet can't quote), manual-accept happy path (Trade + DVP +
  regulatory report all produced), expiry sweep, double-accept rejection,
  cancellation.
- [x] API-level tests in `api/` for all six endpoints above (auth, role gates,
  compliance-battery rejection paths — expired credential, suitability
  failure, prospectus cap breach, jurisdiction rule breach — mirroring the
  existing `handleFillOrder` test coverage style).

---

## 5. Workstream W4 — Removed (No AMM Path)

**Status:** Removed from this execution plan per stakeholder direction (2026-07-07).

All AMM design/engineering work items are explicitly dropped from this plan.
No `AmmEligible` asset flag, AMM pools, AMM endpoints, or AMM-specific events
will be implemented under this execution track.

---

## 6. Workstream W5 — Market-Maker Data & Risk Feeds

**Depends on:** `Trades` (exists today). **Position-limit enforcement** depends on
W1's `MarketMakerAgreement.MaxPositionUnits`/`MaxPositionValue` fields and W3's
RFQ-accept path existing. Otherwise independent — can be developed in parallel
with W1–W3.

### 6.1 New file `market_data.go`
- [x] `VWAP(trades []Trade, assetID string, window time.Duration) float64` —
  volume-weighted average price over trades within `window` of `time.Now()`,
  reusing the same sum(P×Q)/sum(Q) approach already used internally by
  `Blockchain.storAssetVWAP` (blockchain.go) for STOR pattern detection —
  **factor `storAssetVWAP`'s core math out into this shared helper** rather
  than writing a second implementation, and have `storAssetVWAP` call it.
- [x] `InventoryReport` struct + `InventorySnapshot(walletKey string, bc
  *Blockchain) InventoryReport` — aggregates current `Holdings` balance across
  all assets plus open exposure from `OrderBooks` (resting orders),
  `RFQQuotes` (active quotes not yet accepted/expired).
  ```go
  type InventoryReport struct {
      WalletKey        string             `json:"wallet_key"`
      Holdings         map[string]float64 `json:"holdings"`          // assetID -> balance
      OpenOrderExposure map[string]float64 `json:"open_order_exposure"` // assetID -> resting order quantity
      OpenQuoteExposure map[string]float64 `json:"open_quote_exposure"` // assetID -> active RFQ quote quantity
      GeneratedAt        int64              `json:"generated_at"`
  }
  ```
- [x] Position-limit enforcement: a new `CheckMarketMakerPositionLimit(bc
  *Blockchain, dealerKey, assetID string, additionalQuantity float64) error`
  helper, called from RFQ-accept (when the accepted counterparty is a
  designated market maker), comparing projected exposure
  against `MarketMakerAgreement.MaxPositionUnits`/`MaxPositionValue` (0 = no
  limit). This is an **additional** check layered on top of the existing
  compliance battery, not a replacement for any of it.

### 6.2 API endpoints
- [x] `GET /v1/market-data/vwap/{assetID}?window=1h` (`jwt`) — parses `window`
  as a `time.Duration` string (default `24h` if omitted).
- [x] `GET /v1/market-makers/{walletKey}/inventory` (`jwt` — caller must be
  `walletKey` itself, or `jwtAdmin`).

### 6.3 Tests
- [x] `market_data_test.go`: VWAP correctness against hand-computed fixtures
  (including the refactor of `storAssetVWAP` — confirm STOR detection tests
  still pass unchanged after the extraction), inventory snapshot aggregation
  across holdings + orders + quotes, position-limit rejection at
  and under the configured cap.

---

## 7. Dependency Graph & Sequencing

```
W1 (Market Maker Program) ──┬──> W3 (RFQ Engine)
             │
             └──> W5 (position-limit fields + VWAP/inventory)

W2 (dBFT signature hardening) ── stubs land alongside W1/W3 tx-type definitions,
               full verification lands before W3 ships in
                                   `dbft` consensus mode.
```

Recommended build order:
1. **W1** (foundation — no blocking dependencies).
2. **W2 tx-type stubs** for `MarketMakerTransaction` (from W1) land together with W1. Completed: `DefaultVotingStrategy.Vote` now recognises market-maker-only blocks and verifies the embedded base `Transaction` signature; the full operator-payload verification remains in W2 step 4 once `RFQTransaction` exists.
3. **W3** (RFQ), including the `executeTradeDVP` extraction and its own
   `RFQTransaction` stub for W2.
4. **W2 full verification pass** once both new tx types exist — close the gap
  for all five typed-transaction families in one focused change. Completed:
  `DefaultVotingStrategy.Vote` now reuses the shared typed-transaction verifier
  with blockchain context, and `ValidateBlock` now enforces RFQ and full
  market-maker payload signatures alongside the existing asset/order/credential
  checks.
5. **W5** (data/risk feeds) — VWAP/inventory can start any time after step 1;
   position-limit enforcement wiring lands after W1 (agreement fields) and W3
   (RFQ-accept call site) exist.

---

## 8. New / Modified Files Summary

| File | Status | Workstream |
|---|---|---|
| `entity_identity.go` | modified (add `EntityRoleMarketMaker`) | W1 |
| `market_makers.go` + `market_makers_test.go` | new | W1 |
| `dBFT.go` | modified | W2 |
| `dbft_validate_typed_test.go` | modified | W2 |
| `rfq.go` + `rfq_test.go` | new | W3 |
| `p2p.go` | modified (new `MessageType*` constants) | W3, W1 |
| `blockchain.go` | modified (new fields, `applyBlockState` steps, `executeTradeDVP`, `Block`/`blockHashInput` slices) | W1, W3 |
| `liquidity.go` | modified (`applyDVP` calls `executeTradeDVP`) | W3 |
| `market_data.go` + `market_data_test.go` | new | W5 |
| `persistence.go` | modified (new `stateSnapshot` entries) | W1, W3 |
| `api/server.go`, `api/handlers.go`, `api/market_data_test.go` | modified/new (W5 routes + handlers + API tests) | W1, W3, W5 |
| `regulatory_reporting.go` | unchanged — reused as-is | W3 |

The continuous-CLOB settlement path now also routes through
`executeTradeDVP`, eliminating the remaining DVP duplication between the CLOB,
RFQ, and liquidity-window paths.

---

## 9. Persistence Checklist

Every new `Blockchain` map introduced by this plan must be added to
`persistence.go`'s `stateSnapshot` (and its corresponding load path) **in the
same commit** that introduces the field — this exact bug class (new state
silently lost on restart) was previously identified and fixed for
SAR/STOR/regulatory-report state in `COMPLIANCE_IDENTITY_LAYER_PLAN.md` bug #3.

- [x] `MarketMakerRegistry` (W1)
- [x] `RFQRequests`, `RFQQuotes` (W3)

Add a regression test per map confirming a save → reload round-trip preserves
all fields (mirrors the verification approach already used for
`ConfirmedPayments`/`Credentials` elsewhere in the test suite).

---

## 10. API Surface Summary

| Method | Path | Auth | Workstream |
|---|---|---|---|
| POST | `/v1/admin/market-makers` | jwtAdmin | W1 |
| GET | `/v1/market-makers/{assetID}` | jwt | W1 |
| DELETE | `/v1/admin/market-makers/{id}` | jwtAdmin | W1 |
| POST | `/v1/rfq/requests` | jwt | W3 |
| GET | `/v1/rfq/requests?assetID=` | jwt | W3 |
| GET | `/v1/rfq/requests/{id}/quotes` | jwt | W3 |
| POST | `/v1/rfq/requests/{id}/quotes` | jwt | W3 |
| POST | `/v1/rfq/requests/{id}/accept` | jwt | W3 |
| DELETE | `/v1/rfq/requests/{id}` | jwt | W3 |
| GET | `/v1/market-data/vwap/{assetID}` | jwt | W5 |
| GET | `/v1/market-makers/{walletKey}/inventory` | jwt (self or admin) | W5 |

---

## 11. Verification Plan

1. `make test` (= `go test -v ./...`) must pass clean after each workstream —
   do not move to the next workstream with a red test suite.
2. `go build ./...` and `go vet ./...` clean, matching the verification bar set
   in `COMPLIANCE_IDENTITY_LAYER_PLAN.md`.
3. New unit test files per workstream (§2.5, §4.6, §6.3) plus the W2
   `dbft_validate_typed_test.go` extension.
4. **Manual/integration walkthroughs** (can be scripted as additional `_test.go`
   integration-style tests, following `integration_placement_test.go`'s
   convention):
   - Full RFQ round-trip: request → quote (rejected from a non-designated
     wallet, accepted from a designated one) → manual accept → `Trade` appears
     in `bc.Trades` → a `RegulatoryReport` is generated → holdings update on
     both sides.
   - A forged signature on each of `RFQTransaction` and `MarketMakerTransaction`
     is rejected by `DefaultVotingStrategy.Vote` (not just `ValidateBlock`).
  - Restart-persistence: `MarketMakerRegistry` and `RFQRequests`/`RFQQuotes`
    survive a `BlockStore.SaveState`/`LoadState` cycle.
5. `go test -race ./...` — this codebase's existing convention
   (`COMPLIANCE_IDENTITY_LAYER_PLAN.md` verification section) for catching
   concurrency issues, particularly relevant here since `executeTradeDVP` and
   the new RFQ maps are read/written under `bc.Mu` from multiple call
   sites (API handlers, `applyBlockState`, background settlement-registration
   goroutines).

---

## 12. Scope Boundaries (explicit)

**In scope:**
- RFQ engine (manual quote acceptance) as the primary secondary-market
  mechanism.
- Designated Market Maker registry with incentive-structure fields (fee
  rebate, priority allocation, position limits) — agreement data model only.
- VWAP / inventory / position-limit market-data and risk feeds.
- dBFT signature-verification hardening for **all** typed transactions.

**Out of scope (explicitly deferred, per strategy doc's later-phase roadmap):**
- Cross-platform/cross-chain secondary liquidity (Tokeny DvD-style shared
  order books) — strategy doc Phase 4 (30+ months).
- Changing the existing continuous-CLOB/periodic-window matching behaviour —
  kept exactly as-is; RFQ is additive alongside it.
- Actual fee-rebate **payout automation**/reconciliation ledger — this plan
  only introduces the agreement *terms* (`FeeRebateBps` etc.); computing and
  disbursing real rebate payments is a separate follow-on piece of work.
- Any AMM mechanism (including opt-in, issuer-gated, compliance-restricted, or
  single-pool variants).
- GLEIF QVI live integration — already explicitly deferred by
  `COMPLIANCE_IDENTITY_LAYER_PLAN.md`.
- ZK-KYC — already explicitly deferred by `COMPLIANCE_IDENTITY_LAYER_PLAN.md`
  (hooks-only groundwork already in place via `zk_claims.go`).
- Auto-best-price RFQ execution (explicitly decided against — manual only).

---

## 13. Open Questions / Further Considerations (non-blocking)

1. Whether `RFQRequest.LimitPrice == 0` (no limit) should still bound accepted
   quotes via some sanity check (e.g. reject wildly off-market quotes) — v1
   leaves this entirely to the requester's manual judgement, consistent with
   the negotiated-OTC nature of RFQ; revisit if abuse patterns emerge.
2. Whether the optional low-risk cleanup noted in §8 (routing the continuous
   CLOB path through `executeTradeDVP` too) should be scheduled as its own
   small follow-up once W3 has proven the extraction is behaviourally
   identical in production.

---

## 14. Audit Findings (2026-07-07)

Full-codebase audit of the implemented W1/W2/W3/W5 work (W4 confirmed absent).
Verification basis: direct code reading of `blockchain.go`, `dBFT.go`, `p2p.go`,
`persistence.go`, `market_makers.go`, `rfq.go`, `market_data.go`,
`entity_identity.go`, `api/server.go`, `api/handlers.go`, all associated test
files, plus `go build ./...`, `go vet ./...` (both clean), and a scoped
`go test -race` pass over the new W1/W3/W5 tests (clean).

### 14.1 Confirmed correct
- W1: `EntityRoleMarketMaker` present; **true defense-in-depth** — the
  `MarketMakerRegistry.verifier` closure (wired in `initMarketMakerRegistry`)
  independently re-checks `HasEntityRole` at `applyBlockState`/`catchUpBlock`
  time, in addition to the API-layer 409 check. Persistence round-trip tested.
- W2: All five typed-transaction families verified at both `ValidateBlock` and
  `DefaultVotingStrategy.Vote` via the shared `validateTypedTransactions`.
  `dbft_validate_typed_test.go` exercises RFQ (request/quote/accept) and
  MarketMaker (valid/invalid operator sig) at both layers.
- W4: Clean removal — no `AmmEligible`/`LiquidityPool`/`/v1/amm/*` remnants.
- W5: `VWAP`, `InventoryReport`/`InventorySnapshot`,
  `CheckMarketMakerPositionLimit`, both endpoints, and the `storAssetVWAP`
  shared-math refactor are correctly implemented and tested.
- Persistence: `MarketMakerRegistry`/`RFQRequests`/`RFQQuotes` are in
  `stateSnapshot` with passing round-trip tests; `blockTransactionHashKeys`
  gives both new families distinct hash prefixes for replay protection.

### 14.2 Gaps / weaknesses (new, introduced by this plan)

1. **RFQ-accept compliance battery is single-layer, not defense-in-depth**
   (Medium). `applyBlockState`'s RFQ `accept` branch (blockchain.go) only
   checks status/expiry/limit-price before calling `executeTradeDVP` — it does
   **not** re-run `CheckSuitability`/`CheckProspectusLimits`/
   `ApplyJurisdictionRule`/AML/Travel Rule. Those checks exist only in
   `api/handlers.go`'s `handleAcceptRFQQuote` →
   `validateRFQBuyerCompliance`. Contrast with W1, where the registry itself
   re-checks the role claim. Practical impact today is low (the only producer
   of RFQ blocks is `SealRFQBlock`, called exclusively from the API handler
   that already ran the checks), but the block-apply layer alone provides no
   protection if RFQ transactions ever reach `applyBlockState` via another
   path (P2P-gossip single-tx handling, or a future dBFT block).
   *Note: continuous-CLOB matched trades have this same characteristic
   (no `AssetTransaction.Validate` at match time) — RFQ is consistent with
   existing architecture, not a regression, but the plan's own "defense in
   depth" framing (§1.3) doesn't fully hold for RFQ.*

2. **`CheckMarketMakerPositionLimit` — API-only enforcement + TOCTOU race +
   value-cap edge case** (Low-Medium).
   - Called only from `handleAcceptRFQQuote`, not from `applyBlockState` — same
     single-layer characteristic as finding 1.
   - The check (`InventorySnapshot` under a separate `RLock`) and the
     subsequent state mutation (`SealRFQBlock`, its own `Lock`) are not atomic;
     two concurrent RFQ accepts against the same dealer could each pass the
     check before either commits, allowing the position cap to be exceeded
     under concurrent load.
   - `MaxPositionValue` silently isn't enforced for the very first trade ever
     recorded against an asset, because `latestAssetMarkPrice` returns 0 with
     no prior trade history (the `if mark > 0` guard skips the value check
     entirely). `MaxPositionUnits`, if also set, still applies independently.
   - Position limits only bound the dealer's *long* accumulation (when the
     dealer is buyer); no equivalent bound exists for short/selling exposure —
     likely intentional, but not explicitly documented as a scope boundary
     until now.

### 14.3 Pre-existing architectural characteristics (not introduced by this
plan, but directly relevant to it — surfaced during this audit)

3. **P2P block gossip does not replicate state** (Medium, systemic). In
   `p2p.go`'s `HandleMessages`, the `case MessageTypeBlock:` handler validates
   and appends a received block to the local `Blocks` slice but never calls
   `applyBlockState` on it. `SealRFQBlock`/`SealMarketMakerBlock` (like
   `SealBlock`/`SealClaimBlock`) broadcast via `BroadcastBlock` (whole-block),
   not a per-transaction message. Net effect: a peer node receiving an
   RFQ/MarketMaker (or Asset/Order/Credential/Claim) block over gossip does
   **not** update its own `RFQRequests`/`RFQQuotes`/`MarketMakerRegistry`/
   `Holdings`/`Trades` — only the sealing node's in-memory state reflects the
   change. This affects every typed-transaction family equally and pre-dates
   this plan, but means the new RFQ/Market-Maker features do not currently
   replicate correctly in a multi-node deployment.
4. **Dead code**: `BroadcastRFQTransaction` and the
   `case MessageTypeRFQRequest, MessageTypeRFQQuote, MessageTypeRFQAccept:`
   handler in `HandleMessages` are never invoked by any production call site
   (RFQ actions go straight through `SealRFQBlock`'s whole-block broadcast).
   `MessageTypeMarketMakerTransaction` (called for in plan §1.7) was never
   added — functionally moot given finding 3, but the plan item is technically
   incomplete.
5. **`catchUpBlock` narrow-crash-window replay is state-only for RFQ**: on
   replay, an `RFQActionAccept` only sets `RFQRequestStatusAccepted` — it does
   not reconstruct the `Trade`, re-run `executeTradeDVP`, or update quote
   statuses, because the underlying trade/settlement was never persisted back
   into `block.RFQTransactions`/`block.AssetTransactions` in the first place.
   This mirrors identical pre-existing behaviour for CLOB-matched trades
   (also never round-tripped through the block payload), so it's consistent
   with existing design, not a new regression — but worth documenting as a
   known limitation of the crash-recovery path for both mechanisms.

### 14.4 Recommended follow-ups (not yet scheduled)
- Add a second compliance/position-limit check inside `applyBlockState`'s RFQ
  `accept` branch (or explicitly document that HTTP-mode API-layer checks are
  the sole enforcement point, matching CLOB's existing posture, so this is a
  documented design decision rather than an implicit gap).
- Consider holding `bc.Mu` across the position-limit check + seal for RFQ
  accept to close the TOCTOU window, or accept the race as consistent with
  `handleFillOrder`'s existing pattern and document it explicitly.
- If multi-node P2P replication of typed-transaction state is ever required,
  extend `HandleMessages`'s `MessageTypeBlock` case to call `applyBlockState`
  on validated inbound blocks (systemic fix, not RFQ/MM-specific).

### 14.5 Resolution (2026-07-07)

All findings in §14.2 and §14.3 have been addressed:

1. **RFQ-accept compliance battery** — extracted into a single shared method,
   `Blockchain.ValidateRFQAcceptCompliance` (`rfq.go`), containing the exact
   compliance battery previously duplicated in `api/handlers.go`. It is now
   called from **both** `handleAcceptRFQQuote` (API layer, before sealing) and
   `applyBlockState`'s RFQ `accept` branch (block-apply layer, before
   executing the trade) — true defense-in-depth, matching W1's pattern.
   `api/handlers.go`'s `validateRFQBuyerCompliance` wrapper was removed; the
   handler now calls `s.bc.ValidateRFQAcceptCompliance(...)` directly.
2. **`CheckMarketMakerPositionLimit`** — split into self-locking exported
   functions (`InventorySnapshot`, `CheckMarketMakerPositionLimit`,
   `latestAssetMarkPrice`) and lock-free internal variants
   (`inventorySnapshotLocked`, `checkMarketMakerPositionLimitLocked`,
   `latestAssetMarkPriceLocked`) in `market_data.go`. `applyBlockState`'s RFQ
   `accept` branch now calls `checkMarketMakerPositionLimitLocked` directly
   (bc.Mu is already write-locked by the caller — calling the self-locking
   exported function from there would deadlock, since `sync.RWMutex` is not
   re-entrant). The TOCTOU race and value-cap first-trade edge case are
   unchanged (documented, not code-level fixes — see below) but are no longer
   API-only: the block-apply layer now enforces the same cap independently.
3. **P2P block gossip not replicating state** — `p2p.go`'s
   `HandleMessages`/`MessageTypeBlock` case now calls `markCommittedTxHashes`,
   `applyBlockState`, and (when `BlockStore` is configured) `SaveBlock`/
   `SaveState` on every validated inbound block, so receiving peers now
   correctly replicate order books, holdings, RFQ/market-maker registries,
   trades, etc. — not just the block shell. This is a systemic fix covering
   all typed-transaction families, not RFQ/MM-specific.
4. **Dead code** — `BroadcastRFQTransaction`, the
   `MessageTypeRFQRequest`/`MessageTypeRFQQuote`/`MessageTypeRFQAccept`
   constants, and the corresponding `HandleMessages` case were removed
   entirely. They were unused by any production call site and, if ever wired
   up, would have double-applied state (e.g. duplicate RFQ quotes) alongside
   the now-fixed whole-block gossip path in finding 3. `SealRFQBlock`/
   `SealMarketMakerBlock` continue to broadcast via whole-block `BroadcastBlock`
   only, which is now sufficient on its own.
5. **`catchUpBlock` narrow-crash-window replay** — left intentionally
   unchanged (no code fix) and instead explicitly documented in-line: fully
   replaying RFQ-accept trades here would re-invoke the external
   `PaymentProvider.ConfirmPayment` for a payment reference that may already
   have real-world side effects, which is unsafe during crash recovery. This
   is the same reason CLOB-matched trades are never round-tripped through the
   block payload either — now stated explicitly as a deliberate design
   decision rather than an implicit gap.

Verification: `go build ./...` and `go vet ./...` clean; full `go test ./...`
green; scoped `go test -race` over RFQ/market-maker/dBFT-typed-tx/market-data
tests green (no deadlocks from the lock-free refactor, no data races).
