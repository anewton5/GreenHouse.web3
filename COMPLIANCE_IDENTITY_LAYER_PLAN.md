# Compliance & Identity Layer — Hardening + VELA Claims Architecture

> Companion to `VELA Markets Platform Strategy.md`, `GAP_REMEDIATION_PLAN.md`, and
> `PRODUCTION_READINESS_PLAN.md`. This document does not duplicate items already
> tracked in those files — it focuses on the compliance/identity layer specifically,
> informed by VELA's target architecture (ISO 24165 DTI, GLEIF vLEI, ERC-3643/ONCHAINID,
> ZK-KYC).

**Scope decisions (confirmed with stakeholder):**
- Harden existing bugs/gaps **first**, then build the new claims/DTI/vLEI architecture.
- ZK-KYC: interface/hook groundwork only — no real proof system in this plan.
- vLEI: internal data model only (LEI field, legal-entity type, role claims) — GLEIF QVI
  integration explicitly deferred to a future track.

---

## Confirmed Bugs (fix before Phase 1 proper)

These were discovered during codebase analysis and are not documented in any prior
planning doc. They are being remediated immediately, ahead of the rest of Phase 1.

| # | Bug | Files | Status |
|---|-----|-------|--------|
| 1 | `handleAdminRegistrationReview` issues `InvestorClass` values (`elective_professional`, `eligible_counterparty`) that don't match on-chain constants (`professional`, `eligible_cp`), silently breaking the G-07 auto-suitability grant. It also sometimes bypasses `SealBlock`, producing a credential with empty `CredentialHash`/`RegistrySignature`. | `identity.go`, `api/handlers.go` | Fixing now |
| 2 | `handleResolveSAR`/`handleResolveSTOR`/`handleAddInsider`/`handleRemoveInsider` mutate blockchain state without `bc.Mu` — a race against `detectSTORs` (which runs under `bc.Mu` inside `applyBlockState`). | `api/handlers.go` | Fixing now |
| 3 | `SARDraft`/`STORDraft`/`InsiderList`/`RegulatoryReport`/`ProspectusExemption`/`SuitabilityAssessment`/`JurisdictionRule`/`LegalDocAmendment` state is never persisted — `stateSnapshot` in `persistence.go` only covers Assets/Holdings/Credentials/WalletSequences/ConfirmedPayments. All lost on restart. | `persistence.go` | Fixing now |
| 4 | `ComplyAdvantageScreener`/`EllipticScreener` are fully implemented (real HTTP, response parsing, 24h cache) but never instantiated in `cmd/api/main.go` — `bc.AMLScreener` silently defaults to `MockAMLScreener`. The production guard against Mock types already exists (`productionReadinessError` in `blockchain.go`), but nothing supplies a real screener. | `cmd/api/main.go` | Fixing now |
| 5 | PEP rescreening scheduler (`StartPEPRescreeningScheduler`) already accepts a `context.Context` (no goroutine leak — this part was already fixed), but is **never called** from `cmd/api/main.go`, so periodic re-screening never actually runs in production. | `cmd/api/main.go` | Fixing now |

### Fix approach

1. **Bug 1** — Add `NormalizeInvestorClass()` in `identity.go`, called inside
   `NewIdentityCredential` (the single choke point all three `IdentityRegistry`
   implementations funnel through), so every `CredentialAttestation` carries a
   canonical class regardless of which MiFID II vocabulary the caller used.
   Refactor `handleAdminKYCApprove` and `handleAdminRegistrationReview` to share a
   new `commitIssuedCredential`/`autoGrantSuitability` helper pair, removing the
   hand-built, unsigned `CredentialAttestation` literal entirely — every issuance
   path now goes through `IssueCredential`/`ApproveKYC` → `SealBlock`.
2. **Bug 2** — Wrap the read-modify-write in each handler with `bc.Mu.Lock()`
   (and the paired list/read handlers with `bc.Mu.RLock()`), scoping the critical
   section tightly around the map access only (not JSON encode/decode or HTTP I/O).
3. **Bug 3** — Extend `stateSnapshot`, `SaveState`, and `LoadState` in
   `persistence.go` to include the eight missing fields.
4. **Bug 4** — Add a `loadAMLScreener()` helper in `main.go`, selected via
   `GREENHOUSE_AML_PROVIDER` (`complyadvantage` | `elliptic` | unset/`mock`).
5. **Bug 5** — Call `gn.StartPEPRescreeningScheduler(ctx, bc, interval)` from
   `main.go`, reusing the existing shutdown `ctx`, with interval configurable via
   `GREENHOUSE_PEP_RESCREEN_INTERVAL`.

---

## Phase 1 — Correctness & Security Hardening (remaining items) — COMPLETE

Beyond the confirmed bugs above:

1.6. **Done.** Added `retryHTTP`-based retry/backoff (3 attempts, ~30s cap, reusing
   the existing shared helper from `payment_retry.go`) to both
   `ComplyAdvantageScreener.callAPI` and `EllipticScreener.callAPI`. Added a new
   `AuditedAMLScreener` wrapper (`aml.go`) that persists every screening decision
   to a durable `aml_screening_log` bbolt bucket (`persistence.go`); wired in
   `cmd/api/main.go` around any live provider selected via `GREENHOUSE_AML_PROVIDER`.
1.7. **Done.** Added `CountJurisdictionRetailHolders(assetID, jurisdiction, holdings,
   credentials)` in `compliance.go` as the single canonical live counter. Discovered
   and fixed a real bug in the process: `handleFillOrder`'s G-11 block was counting
   ALL retail credential holders platform-wide (ignoring asset and jurisdiction),
   while `AssetTransaction.Validate` correctly scoped the count — both call sites
   now share the same correct, asset+jurisdiction-scoped implementation.
1.8. **Done.** Resolved SAR/STOR drafts are now archived to durable `closed_sars`/
   `closed_stors` bbolt buckets (`BlockStore.SaveClosedSAR`/`SaveClosedSTOR`) and
   removed from the live `PendingSARs`/`PendingSTORs` maps when a `BlockStore` is
   configured (left in place with updated status on dev/test nodes with no
   `BlockStore`, so nothing is silently lost). New read endpoints:
   `GET /v1/compliance/sar/closed` and `GET /v1/compliance/stor/closed`.

---

## Phase 2 — Claim-Topic / Trusted-Issuer Registry (ERC-3643/ONCHAINID-style) — COMPLETE

*New file `claims.go` + `claims_test.go`.*

1. **Done.** `ClaimTopic` enum: KYC, AML_CLEAR, ACCREDITED, JURISDICTION_RESIDENT,
   PEP_CLEAR, SUITABILITY, INSTITUTIONAL_ROLE (+ `ClaimTopicCustom` escape hatch).
2. **Done.** `Claim` struct + `NewClaim`/`VerifySignature`/`IsExpired`/`IsValid`,
   mirroring `IdentityCredential`'s `sha3.Sum256` + Ed25519 pattern exactly.
3. **Done.** `TrustedIssuersRegistry` (topic → authorized issuer pubkeys) +
   `ClaimIssuerTransaction`. **Scope decision:** rather than a new admin-key
   concept, `ClaimIssuerTransaction.AdminSignature` is verified against
   `bc.OperatorKeyProvider` — the same key that already signs every sealed
   block. This matches VELA's own roadmap (Section 6.4: "start as a
   centrally-operated, licensed regulated entity"); a multi-institution
   trusted-issuer governance body is a later-stage concern, not a Phase 2 one.
4. **Done.** Added `bc.Claims`/`bc.TrustedIssuers` to `Blockchain`; wired into
   `NewBlockchain`, `ValidateBlock` (issuer signature + trust check for
   `ClaimTransaction`; operator-signature check for `ClaimIssuerTransaction`),
   `applyBlockState`, `catchUpBlock`, and `persistence.go`'s `stateSnapshot`.
   **Scope decision:** rather than adding two new parameters to `SealBlock`
   (which would require updating every existing call site across the
   codebase), added a dedicated `SealClaimBlock(claimTxs, issuerTxs)` method
   that reuses the same `applyBlockState` engine. Zero changes to `SealBlock`'s
   signature or any existing call site.
5. **Done.** Backward-compatible adapter: `SynthesizeClaimsFromAttestation`
   derives KYC / jurisdiction-resident / accredited claims from a legacy
   `CredentialAttestation` so every existing credential holder already
   satisfies the equivalent claim topics.
6. **Done (as a new additive entry point, not a forced rewrite).**
   `EvaluateComplianceRequirements(bc, walletKey, requiredTopics)` is the new
   canonical, claim-topic-based check (via `EffectiveClaims` = real claims +
   adapter fallback). **Scope decision:** `CheckTransferEligibility`,
   `ApplyJurisdictionRule`, `CheckSuitability`, and `CheckProspectusLimits` take
   narrower parameters (a `credentials` map, not `bc`) and are called from
   multiple sites (`assets.go` `Validate`, `api/handlers.go` `handleFillOrder`).
   Forcing them to accept `bc` so they could see real `bc.Claims` entries would
   require a signature change propagated through every call site and test —
   a much larger, riskier change than Phase 2's stated backward-compatibility
   goal justifies. They remain unchanged and continue to be the enforcement
   path for existing callers; `EvaluateComplianceRequirements` is available for
   new integrations that have `bc` in scope.
7. **Done.** `IdentityRegistry` interface gained `IssueClaim(walletKey, topic,
   data, validForDays)`, implemented by `MockIdentityRegistry`,
   `OperatorIdentityRegistry`, and `OnfidoIdentityRegistry` (each simply calls
   `NewClaim` with its existing registry key — the same key that already
   signs `CredentialAttestation`s). `commitIssuedCredential` (api/handlers.go)
   now also issues and commits a `ClaimTopicKYC` claim via `SealClaimBlock`
   whenever it commits a `CredentialAttestation`, for every credential-issuing
   endpoint (`handleAdminKYCApprove`, `handleAdminRegistrationReview`).

**New HTTP endpoints:**
- `GET /v1/claims/{walletKey}` — effective claims (real + adapter-synthesized).
- `POST /v1/admin/claim-issuers` — add/remove a trusted issuer for a topic
  (signed by the node operator key, committed via `SealClaimBlock`).

---

## Phase 3 — Institutional / vLEI-Ready Identity Model — **COMPLETE**

*Depends on Phase 2. New file `entity_identity.go` + `entity_identity_test.go`. Internal model only.*

1. **Done.** `LegalEntityIdentity` (LEI, legal name, jurisdiction, `did:webs`-ready
   `DIDWebs` field, `RegisteredAddressHash`, status, timestamps) +
   `ValidateLEI` (ISO 17442: 20-char structural check + ISO/IEC 7064 MOD 97-10
   checksum, mirroring `ValidateISIN`'s existing pattern in `assets.go`; empty
   string accepted since LEI remains optional pending full institutional
   rollout). Unexported `leiMod97`/`leiCheckDigits` helpers do the checksum
   arithmetic and let tests construct self-consistent test LEIs without a real
   GLEIF-issued identifier.
2. **Done.** `EntityRole` (`authorised_signatory`, `ubo`, `director`,
   `spv_admin`) modeled as a `ClaimTopicInstitutionalRole` claim — reuses
   Phase 2 claim infrastructure with no parallel signing/storage path.
   `EntityRoleClaimData(lei, role)` builds the `Claim.Data` payload
   (`"<LEI>:<role>"`); `ParseEntityRoleClaim` reads it back; `HasEntityRole`
   checks `EffectiveClaims` for a live match. Claims are issued via the
   existing `IdentityRegistry.IssueClaim` + `SealClaimBlock` path (no new
   signing code).
3. **Done.** Wired the previously dead-code `CorporateDocuments`
   (`registration.go`) into `RegistrationRecord` as the institutional
   onboarding path: added `Corporate *CorporateDocuments` and `EntityLEI
   string` fields. `validation.go`'s `Validate()` gained a corporate block
   (only enforced when `Corporate != nil`) requiring a structurally valid
   `EntityLEI` and `IncorporationDocumentHash`/`RegisteredAddressHash`, with
   `ArticlesOfAssociationHash`/`CompaniesHouseExtractHash` validated only if
   present.
4. **Done.** `EntityRegistry` (mutex-protected, keyed by LEI) implementing the
   `EntityIdentityProvider` interface (`RegisterEntity`, `GetEntity`,
   `ListEntities`, `UpdateEntityStatus`) — manual/self-declared entry today,
   swappable for a real GLEIF QVI provider later without changing call sites.
   **Scope decision:** placed on the API `Server` (`s.EntityRegistry`,
   mirroring `s.RegRegistry`'s existing placement) rather than on
   `Blockchain`, since institutional-role enforcement resolves entirely
   through `bc.Claims` (via `EffectiveClaims`/`HasEntityRole`) — the registry
   itself is reference data for the HTTP admin API, not consensus-critical
   on-chain state.
5. **Done.** `SPVAdminHasRoleClaim(bc, spv, entityLEI)` cross-checks
   `SPVWrapper.SPVAdminKey` against a valid `spv_admin` role claim for
   `entityLEI`. Added optional `SPVWrapper.EntityLEI` field. **Scope
   decision:** additive only — NOT wired into the enforcement path in
   `handleUpdateSPVNAV`/`handleCounterSignAsset`, since existing SPV
   authorisation (`SPVAdminKey == caller`) remains the primary gate and no
   existing SPV yet has a role claim issued; wiring it in now would break
   every existing SPV test. Available for audit/reporting use and future
   enforcement once role claims are backfilled.
6. **Done.** Added optional `BuyerLEI`/`SellerLEI` fields to `RegulatoryReport`
   (MiFIR RTS 22 counterparty-LEI field). **Scope decision:**
   `ReportingService.GenerateReport(reportType, trade, asset, blockIndex)`
   does not receive `bc`, so populating the LEI fields there would require
   changing the interface (affecting `NCAReportingService` too). Instead,
   `GenerateMiFIRReport`/`GenerateAIFMDReport` (which already take `bc`)
   populate `BuyerLEI`/`SellerLEI` as a post-processing step via a new
   `lookupCounterpartyLEI(bc, walletKey)` helper (first valid
   `ClaimTopicInstitutionalRole` claim found via `EffectiveClaims`), leaving
   both empty for non-institutional (retail) counterparties.

**New HTTP endpoints:**
- `POST /v1/admin/entities` — register a `LegalEntityIdentity` (admin only).
- `GET /v1/entities` / `GET /v1/entities/{lei}` — list / fetch registered entities.
- `POST /v1/admin/entities/{lei}/role-claims` — issue an `EntityRole` claim to a
  wallet for a registered entity (admin only; reuses `IdentityRegistry.IssueClaim`
  + `SealClaimBlock`, the same pattern `commitIssuedCredential` uses for KYC claims).

**Verification:** `go build ./...`, `go vet ./...`, `go test ./...`, and
`go test -race ./...` all pass clean (14 new tests in `entity_identity_test.go`
covering `ValidateLEI` checksum validation, `EntityRegistry` CRUD, the
`EntityRoleClaimData`/`ParseEntityRoleClaim` round trip, `HasEntityRole`, and
`SPVAdminHasRoleClaim`).

---

## Phase 4 — DTI / Asset Identifier Layer (ISO 24165) — **COMPLETE**

*Independent of Phase 3; implemented additively with no breaking API changes.*

1. **Done.** Added `DTI`/`DLI` fields to `AssetMetadata` (`assets.go`) plus a
   new `ValidateDTI(dti string) error` structural validator (9-char uppercase
   alphanumeric; empty accepted so DTI remains optional).
2. **Done.** Surfaced `dti`/`dli` as optional, manually-entered metadata on
   `handleCreateAsset` (`api/handlers.go`). The handler now validates:
   - `isin` via existing `ValidateISIN`
   - `dti` via `ValidateDTI`
   - `dli` via the same structural rule as `ValidateDTI`
   GreenHouse still does not mint DTIs; it stores externally assigned values.
3. **Done.** Threaded DTI into reporting and NCA submissions:
   - `RegulatoryReport` now includes `DTI string \`json:"dti,omitempty"\``
   - `DefaultReportingService.GenerateReport` copies `asset.Metadata.DTI`
   - `NCAReportingService` automatically transmits DTI because it posts the
     marshaled `RegulatoryReport` payload to the configured endpoint.

**Scalability/architecture notes:**
- Kept reporting-service interface stable (`GenerateReport(reportType, trade, asset, blockIndex)` unchanged), so custom reporting backends and NCA wiring require no migration.
- DTI support is additive and optional, preserving backward compatibility for all existing asset issuance flows and historical assets with no DTI.
- DLI was modeled in asset metadata now so future reporting standards can include it without another asset-schema migration.

---

## Phase 5 — ZK-KYC Interface Groundwork (hooks only) — **COMPLETE**

*Depends on Phase 2. New file `zk_claims.go` + `zk_claims_test.go`. Hooks only; no
real proof system yet.*

1. **Done.** Added `ZKClaimProof` as a placeholder proof envelope plus the
   `ZKClaimVerifier` interface for future Groth16/PLONK-style selective
   disclosure back-ends. The shape is intentionally generic so later proof
   systems can map into the same API surface without another compliance-layer
   refactor.
2. **Done.** Added `StubZKVerifier` with fail-closed behavior by default. It
   returns false unless a topic is explicitly allow-listed, making the hook
   safe for tests and proving that nothing silently becomes accepted when no
   verifier is configured.
3. **Done.** Wired the hook additively into `EvaluateComplianceRequirements`
   via an optional variadic proof parameter. Existing call sites are unchanged;
   callers that do not supply proofs continue to use the legacy claim path only.
   When a `Blockchain.ZKVerifier` is configured and a proof is supplied for a
   required topic, the verifier is consulted as an alternative satisfaction
   path. The default nil verifier preserves zero behavior change.
4. **Done.** Documented the selective-disclosure target in code comments as the
   future predicate-style goal (e.g. proving a wallet satisfies a topic without
   revealing the underlying issuer/class/jurisdiction detail). This is a hook
   only, not a cryptography implementation.

**Scalability/architecture notes:**
- Kept the hook optional and additive so current compliance flows remain
  unchanged and no existing tests or call sites needed refactoring.
- Stored the verifier on `Blockchain` as an injectable service hook, matching
  the existing service-injection pattern used for reporting and identity.
- Fail-closed default ensures unconfigured deployments cannot accidentally
  accept unverified ZK inputs.

**Verification:** `go build ./...`, `go vet ./...`, `go test ./...`, and
`go test -race ./...` all pass clean (new tests in `zk_claims_test.go` cover
fail-closed default behavior, allow-listed success, nil-verifier rejection, and
erroring-verifier rejection).

---

## Relevant Files

- `identity.go`, `operator_identity.go`, `onfido_identity.go`
- `registration.go`, `validation.go`
- `api/handlers.go`, `api/server.go`
- `blockchain.go`, `persistence.go`
- `compliance.go`, `aml.go`, `aml_rules.go`, `complyadv_aml.go`, `elliptic_aml.go`
- `assets.go`, `spv.go`
- `regulatory_reporting.go`, `nca_reporting.go`
- `cmd/api/main.go`
- `claims.go`, `claims_test.go` (Phase 2, complete)
- `entity_identity.go`, `entity_identity_test.go` (Phase 3, complete)
- `zk_claims.go`, `zk_claims_test.go` (Phase 5, complete)

## Verification

- `go build ./...`, `go vet ./...`, `go test ./...`, and `go test -race ./...` all
   pass clean as of Phase 5 completion (2026-07-05).
- `claims_test.go` covers: Claim sign/verify/tamper-detection/expiry,
  TrustedIssuersRegistry add/remove/nil-safety, ClaimIssuerTransaction
  sign/verify via KeyProvider, SynthesizeClaimsFromAttestation for retail vs.
  accredited investors (and nil/expired inputs), EvaluateComplianceRequirements
  (adapter fallback, real-claim precedence, unknown wallet), and IssueClaim on
  both MockIdentityRegistry and OperatorIdentityRegistry.
- LEI/DTI checksum validator test vectors (Phases 3/4).
- Fail-closed and no-op-when-unconfigured tests for `StubZKVerifier` plus
  optional-proof path coverage in `EvaluateComplianceRequirements`
  (Phase 5).

## Further Considerations (open, not blocking)

1. Claim topics as a fixed Go enum vs. fully dynamic on-chain registry — leaning
   fixed enum + custom-string escape hatch for now.
2. Add a distinct `InvestorClassElectiveProfessional` on-chain constant
   (regulatory accuracy) vs. normalizing to `InvestorClassProfessional` (current
   bug-fix approach) — revisit as part of Phase 2's claims model.
3. Making SAR/STOR resolution its own block-committed transaction type (true
   immutable audit trail) — candidate for a future session, not in this plan.
