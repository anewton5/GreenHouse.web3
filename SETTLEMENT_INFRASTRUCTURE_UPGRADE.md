
---

## Plan: Settlement Infrastructure Upgrade — CeBM + Interim Fallbacks

**TL;DR**: GreenHouse's `PaymentProvider` interface is already the right abstraction. The plan adds a Pontes CeBM adapter (for the ECB's Q3 2026 pilot), implements the existing but empty `SettlementEURC` constant as a MiCA-compliant euro stablecoin bridge, extends Modulr for EUR SEPA, and introduces a settlement router so the blockchain automatically dispatches to the best available rail per trade currency. All interim rails stay live as fallbacks once CeBM goes live.

---

### The Opportunity — What Appia + Pontes Actually Are

The ECB is running two parallel initiatives (both confirmed as of March/April 2026):

**Pontes** — the *operational* product. Launching pilot **September 2026**. It acts as a bridge between market DLT platforms (like GreenHouse) and T2 (the Eurosystem's RTGS). It supports a **dual-settlement model**: either native cash tokens on a Eurosystem DLT platform, or final settlement routed through T2. DVP is natively supported. The ECB is finalising eligibility criteria for "market DLT operators" now.

**Appia** — the *blueprint* initiative. Launched 2025, publishing findings by 2028. It's determining what standards, governance models and interoperability patterns the European tokenised ecosystem will use. Public consultation is currently open. Getting GreenHouse's architecture into the consultation shapes future standards in GreenHouse's favour.

The ECB's stated problem GreenHouse is solving: *"without that [CeBM] anchor, innovative private solutions will not be able to scale with confidence, leaving markets to depend on settlement assets that present liquidity and credit risk — many of which may be issued in foreign currency, on non-European platforms."*

---

### Phases + Steps

**Phase 0: Architectural Prerequisite** *(no new feature surface; unblocks all phases)*

1. Add `SettlementRouter` to `Blockchain` struct in blockchain.go — a `map[SettlementMethod]PaymentProvider` that dispatches `PaymentInstruction` to the correct provider. `finalizeBlock` uses this instead of directly calling `bc.PaymentProvider`. The existing single `PaymentProvider` field becomes the default fallback.

2. Add expiry enforcement in `finalizeBlock` (or a ticker-driven goroutine) in dBFT.go: iterate `PendingInstructions`, revert any with `ExpiresAt < time.Now().Unix()` — emit a new `EventPaymentExpired` and reverse the matched order state. Currently the `ExpiresAt` field exists but nothing acts on it.

---

**Phase 1: Interim Settlement Fallbacks** *(deployable now, before Pontes)*

3. **EURC on-chain (highest priority interim rail)** — New file `eurc_payment.go`. Implement `EURCPaymentProvider` satisfying `PaymentProvider`. Uses Circle's EURC contract (MiCA-compliant, euro-denominated, EU-governed). Confirmation arrives via on-chain event monitoring rather than a webhook. Enables instant atomic settlement with no bank credit risk. This is the most credible interim alternative to CeBM — it's what the ECB's own strategy acknowledges as legitimate *("tokenised deposits or euro-denominated stablecoins issued in Europe")*. Wire up the already-defined `SettlementEURC = "eurc_on_chain"` constant to this implementation.

4. **SEPA Instant EUR extension** — Extend `ModulrPaymentProvider` in modulr_payment.go to open EUR virtual accounts (`Currency: "EUR"`) alongside the existing GBP accounts. The Modulr API supports this; only the account creation call and currency routing logic need updating.

5. **SWIFT GPI adapter** — New `SwiftPaymentProvider` implementing `PaymentProvider`, for USD/CHF cross-border trades. Wires up the existing `SettlementSWIFT = "swift_gpi"` constant. SWIFT GPI provides end-to-end tracking and ~24h finality with confirmed status callbacks. Can start with a mock, with real SWIFT API integration as a follow-on.

6. **Currency-to-method routing** — Add `DefaultSettlementMethod(currency string) SettlementMethod` logic: EUR → `SettlementEURC` (then SEPA Instant fallback), GBP → `SettlementFasterPay`, USD/CHF → `SettlementSWIFT`. `PaymentInstruction.Method` is set at instruction creation time in `finalizeBlock`.

---

**Phase 2: Pontes CeBM Integration** *(target Q3 2026 pilot participation)*

7. **New `SettlementMethod` constant** in payment.go: `SettlementCeBM = "pontes_cbm"`. Add `PontesTransactionID string` and `SettlementNetwork string` fields to `PaymentInstruction`.

8. **`PontesPaymentProvider`** — New file `pontes_payment.go`. Implements `PaymentProvider`. Calls the Pontes pilot API to:
   - Register the trade's asset delivery leg (DLT-side) with the Pontes bridge
   - Receive confirmation that T2 has settled the cash leg
   - `ConfirmPayment` is called when Pontes delivers the T2 settlement confirmation
   The interface is already perfectly shaped for this — `CreateVirtualAccount` maps to participant registration, `GetPaymentStatus` maps to polling Pontes for T2 confirmation, `ConfirmPayment` is called by the webhook.

9. **Pontes webhook handler** in api/handlers.go: `POST /v1/webhooks/pontes`. Similar structure to the existing Modulr webhook. Authenticates the Pontes callback (HMAC or mTLS, per ECB spec), maps to `PaymentStatusConfirmed`, triggers DVP.

10. **DVP finality upgrade** in dBFT.go: for `SettlementCeBM`, the DVP asset transfer in `finalizeBlock` step 8 must only trigger after the Pontes callback — not after a mock instant confirm. The `SettlementRouter` handles this naturally by routing CeBM instructions to `PontesPaymentProvider`.

11. **Market DLT Operator registration** — Non-code deliverable: apply to ECB's eligibility process for Pontes pilot participation. The ECB is currently finalising criteria (see Focus Session from July 2025). GreenHouse's permissioned network, dBFT finality, and identity/compliance layer are directly aligned with their requirements.

---

**Phase 3: Appia Ecosystem Positioning** *(2026–2028, parallel with Phase 2)*

12. **Respond to Appia public consultation** — Submit GreenHouse's architecture as a case study for a "market DLT platform" under the Appia blueprint. Key positions to stake: Ed25519 identity layer ↔ ONCHAINID compatibility; on-chain compliance ↔ Appia common standards; DVP + oracle architecture ↔ Appia settlement finality model.

13. **Appia standards adapter** (stub now, implement as specs emerge) — add `AppiaComplianceAdapter` interface stub in a new `appia.go` file so that as Appia publishes technical standards (expected 2027–2028), GreenHouse can implement them without touching core settlement logic.

---

### Relevant Files

- payment.go — add `SettlementCeBM` constant; extend `PaymentInstruction` with `PontesTransactionID`, `SettlementNetwork`
- modulr_payment.go — extend `CreateVirtualAccount` for EUR currency
- blockchain.go — add `SettlementRouter map[SettlementMethod]PaymentProvider`; `DefaultSettlementMethod()` helper
- dBFT.go — `finalizeBlock`: route via `SettlementRouter`; add expiry enforcement
- handlers.go — new `POST /v1/webhooks/pontes` handler
- NEW: `GreenHouse.web3/eurc_payment.go` — `EURCPaymentProvider`
- NEW: `GreenHouse.web3/pontes_payment.go` — `PontesPaymentProvider`
- NEW: `GreenHouse.web3/appia.go` — `AppiaComplianceAdapter` interface stub

---

### Verification

1. Unit test `SettlementRouter` dispatches `PaymentInstruction` to the correct provider by `SettlementMethod`
2. Unit test expiry enforcement: insert a `PendingInstruction` with `ExpiresAt = time.Now().Unix() - 1`, run `finalizeBlock`, confirm `EventPaymentExpired` is emitted and order state is reverted
3. Test `EURCPaymentProvider` mock: confirm a EUR trade, assert DVP applies asset transfer
4. Test Modulr EUR extension: `CreateVirtualAccount` with EUR currency returns a valid IBAN
5. Integration test: full trade lifecycle (EUR) via EURC → SEPA Instant fallback
6. Stub test for `PontesPaymentProvider`: confirm Pontes webhook handler returns `200`, calls `ConfirmPayment`, triggers DVP

---

### Decisions / Scope Boundaries

- **EURC over tokenised deposits for Phase 1**: Circle's EURC is MiCA-regulated, EUR-denominated, EU-issued — the ECB's own strategy endorses this class of asset. Tokenised deposits (e.g. Fnality) have less tooling available right now.
- **Pontes before Digital Euro**: Pontes is wholesale infrastructure available Q3 2026. The retail Digital Euro (2029) is irrelevant to institutional settlement.
- **`PaymentProvider` interface unchanged**: all new providers implement the existing interface — no breaking changes to `finalizeBlock` or DVP logic.
- **Out of scope**: cross-chain bridges to non-European DLT networks; USD CeBM (Fed not running equivalent).

---

### Further Considerations

1. **Pontes eligibility criteria**: The ECB is finalising who qualifies as a "market DLT operator." GreenHouse likely qualifies (permissioned network, dBFT finality, regulated participants), but this should be confirmed by reviewing the ECB's [Focus Session materials from July 2025](https://www.ecb.europa.eu/press/intro/events/html/fs_20250715.en.html) before committing to Phase 2 scope.

2. **EURC vs. EURR**: Circle's EURC and Societe Generale's EUR CoinVertible (EURCV) are both MiCA-compliant candidates. The choice affects which chain/API GreenHouse integrates with. EURC is more liquid and has better tooling; EURCV has stronger institutional backing in European capital markets.

3. **Appia consultation deadline**: The ECB's public consultation is currently open (launched alongside the March 2026 roadmap). Submitting GreenHouse's architecture now — before the consultation closes — is a low-cost, high-leverage step to influence Appia standards in GreenHouse's favour.