# GreenHouse Systematic Review

Date: 2026-07-05
Reviewer: GitHub Copilot (GPT-5.3-Codex)

## Objective

Perform a systematic review of:

- Backend handlers, endpoint wiring, middleware, and security/control flow in `GreenHouse.web3/api`
- Client-side API layers for issuer and investor portals:
  - `greenhouse-issuer/src/lib/api.ts`
  - `greenhouse-investor/src/lib/api.ts`

The focus of this review is consistency after major upgrades in Payment, Registration, Compliance, and Identity architecture.

---

## Scope and Method

### In scope

- Route registration and auth model (`jwt`, `jwtAdmin`, unauthenticated)
- Handler request/response contract behavior
- Payment and webhook handling paths
- Registration/KYC and identity/claims/entity endpoint exposure
- Client endpoint coverage and shape compatibility
- Critical middleware behavior (CORS, rate limiting, security headers)

### Out of scope

- Frontend page/component rendering and UX behavior beyond API contract assumptions
- Performance benchmarking and load testing
- Full business logic correctness of blockchain/domain internals outside endpoint interaction

### Files reviewed

- Backend:
  - `GreenHouse.web3/api/server.go`
  - `GreenHouse.web3/api/handlers.go`
  - `GreenHouse.web3/api/middleware.go`
  - `GreenHouse.web3/api/stream.go`
  - `GreenHouse.web3/pontes_payment.go`
  - `GreenHouse.web3/deal.go`
  - `GreenHouse.web3/corporate.go`
  - `GreenHouse.web3/regulatory_reporting.go`
- Portals:
  - `greenhouse-investor/src/lib/api.ts`
  - `greenhouse-issuer/src/lib/api.ts`

---

## Executive Summary

The backend has incorporated major architecture upgrades and exposes many new capabilities (claims, entities, settlement recovery, compliance archives). However, the issuer and investor client API layers are only partially aligned.

Most significant risks identified:

1. Issuer fill-order flow cannot satisfy mandatory Travel Rule payload requirements for larger trades.
2. Investor client calls an admin-only regulatory endpoint.
3. New Identity/Claims/Entity backend capabilities are largely unexposed in both portal API layers.

Additional issues include response-shape drift, semantic mismatches, and a missing structural webhook verification wrapper usage in API handlers.

---

## Findings (Severity Ordered)

## 1) HIGH - Issuer fill flow is incompatible with Travel Rule requirement

### Evidence

- Backend rejects fills >= EUR 1,000 if `travel_rule_data` is absent:
  - `GreenHouse.web3/api/handlers.go` (`handleFillOrder`)
- Issuer portal always posts `{}` on fill:
  - `greenhouse-issuer/src/lib/api.ts` (`fillOrder`)

### Risk

Large fills fail at runtime with HTTP 422 despite valid business intent.

### Required upgrade

- Extend issuer API client `fillOrder` to accept optional/required `travel_rule_data` input.
- Add server/client contract docs for when `travel_rule_data` becomes mandatory.
- Ensure issuer UI workflow can capture and submit Travel Rule payload for qualifying trades.

---

## 2) HIGH - Investor client calls admin-only regulatory reports endpoint

### Evidence

- Investor API client calls `/v1/compliance/reports`:
  - `greenhouse-investor/src/lib/api.ts` (`listRegulatoryReports`)
- Backend route is admin-protected via `jwtAdmin`:
  - `GreenHouse.web3/api/server.go` (`GET /v1/compliance/reports`)

### Risk

Unauthorized failures for investor users; confusing UX and potential dead code paths.

### Required upgrade

- Either remove/hide this call from investor client, or
- Add a user-scoped backend reporting endpoint and migrate investor client to it.

---

## 3) HIGH - Major identity architecture endpoints are not exposed in portal API layers

### Evidence

Backend exposes:

- `GET /v1/claims/{walletKey}`
- `POST /v1/admin/claim-issuers`
- `POST /v1/admin/entities`
- `GET /v1/entities`
- `GET /v1/entities/{lei}`
- `POST /v1/admin/entities/{lei}/role-claims`

No corresponding endpoint bindings were found in:

- `greenhouse-investor/src/lib/api.ts`
- `greenhouse-issuer/src/lib/api.ts`

### Risk

Core upgraded functionality cannot be used by portal teams without ad hoc HTTP calls.

### Required upgrade

- Add typed client bindings for claims/entity endpoints.
- Decide explicit role split:
  - Investor: read-only claims/entity visibility (if intended)
  - Issuer/Admin: issuer registry and role-claim management

---

## 4) MEDIUM - Manual CeBM settlement recovery endpoint missing in portal clients

### Evidence

- Backend route present:
  - `POST /v1/payments/{tradeID}/register` in `GreenHouse.web3/api/server.go`
- No matching issuer/investor API binding found.

### Risk

Operational recovery path (failed async registration retry) unavailable from portal workflows.

### Required upgrade

- Add issuer/admin API function for manual settlement re-registration.
- Add corresponding UI operation in issuer ops/compliance panel.

---

## 5) MEDIUM - Issuer pending-payments contract wording does not match backend behavior

### Evidence

- Issuer client says pending payments are across all participants (issuer view):
  - `greenhouse-issuer/src/lib/api.ts` comment on `listPendingPayments`
- Backend `handleListPendingPayments` filters by payer wallet (`instr.PayerWalletID == wallet`):
  - `GreenHouse.web3/api/handlers.go`

### Risk

Issuer may receive partial/empty data and infer missing records.

### Required upgrade

Choose one and align both sides:

- Add issuer-scoped backend view (trades for issued assets), or
- Correct client comments and downstream expectations to payer-only scope.

---

## 6) MEDIUM - Deal anchor payload mismatch between issuer client and backend model

### Evidence

- Issuer `anchorDeal` sends fields like `document_hash`, `document_url`, `anchor_type`.
- Backend decodes `DealAnchor` and validates signature/key fields expected by domain model (`anchor_wallet_key`, `commitment_amount`, etc.) in:
  - `GreenHouse.web3/api/handlers.go` (`handleAttachAnchor`)
  - `GreenHouse.web3/deal.go` (`DealAnchor`)

### Risk

Anchor endpoint requests likely fail validation/signature checks or cannot satisfy intended business flow.

### Required upgrade

- Normalize client request DTO to backend `DealAnchor` schema.
- Confirm expected signing payload and required signature fields.
- Add compatibility tests covering issuer-client payload against backend handler.

---

## 7) MEDIUM - Corporate action response shape/model drift

### Evidence

- Issuer client expects `record_date`, `parameters`, `created_at` in `CorporateAction`.
- Backend `CorporateAction` has `record_date` but not `created_at` and no persisted `parameters` field:
  - `GreenHouse.web3/corporate.go`
- Handler accepts `parameters` in request but does not persist them to `CorporateAction`:
  - `GreenHouse.web3/api/handlers.go` (`handleProposeCorporateAction`)

### Risk

Client relies on fields not stored/returned consistently; data loss of request parameters.

### Required upgrade

- Either persist and return `parameters` and `created_at`, or
- Remove/adjust client shape and API docs to reflect authoritative backend schema.

---

## 8) MEDIUM - KYC status shape inconsistency between investor and issuer clients

### Evidence

- Backend `handleKYCStatus` returns `kyc_status: not_found` without `expires_at`.
- Issuer client models `expires_at` as optional.
- Investor client models `expires_at` as required.

### Risk

Investor side can mis-handle no-credential responses.

### Required upgrade

- Make investor `KYCStatus.expires_at` optional, or
- Standardize backend to always return `expires_at` with explicit sentinel.

---

## 9) MEDIUM - Webhook verification helper exists but is not used in API handlers

### Evidence

- Central helper exists in `GreenHouse.web3/pontes_payment.go`:
  - `HandleWebhook(v, payload, signature, action)`
- Payment handlers in `GreenHouse.web3/api/handlers.go` perform inline verification and do not call helper.

### Risk

Security behavior remains correct today but is not architecturally centralized; future drift risk.

### Required upgrade

- Refactor payment webhook handlers to use central `HandleWebhook` wrapper.
- Keep provider-specific parsing but enforce common signature gate through wrapper.

---

## 10) LOW - Report type enum mismatch in issuer portal

### Evidence

- Issuer client `RegulatoryReport.report_type` allows `"fca_cmar"`.
- Backend report type constant is `"cmar"`:
  - `GreenHouse.web3/regulatory_reporting.go`

### Risk

Filter/type errors or brittle report-type logic.

### Required upgrade

- Update issuer enum to backend canonical values: `mifir`, `cmar`, `aifmd`.

---

## 11) LOW - Client report models lag backend fields (DTI/LEI/counterparties)

### Evidence

Backend `RegulatoryReport` includes fields such as:

- `isin`, `dti`, `buyer_id`, `seller_id`, `buyer_lei`, `seller_lei`

Client interfaces in issuer/investor API files omit these.

### Risk

Upgraded compliance/identity data not consumable in portals.

### Required upgrade

- Extend both client interfaces to include new report fields.
- Update reporting views to display relevant new attributes.

---

## Endpoint Coverage Delta Matrix

Legend:

- Present: endpoint binding exists in portal API layer
- Missing: no binding found in portal API layer
- Mismatch: binding exists but contract/auth/semantics mismatch

| Capability | Backend route | Issuer API | Investor API | Status |
|---|---|---|---|---|
| Claims listing | GET /v1/claims/{walletKey} | Missing | Missing | Missing |
| Claim issuer upsert | POST /v1/admin/claim-issuers | Missing | Missing | Missing |
| Entity register | POST /v1/admin/entities | Missing | Missing | Missing |
| Entity list/get | GET /v1/entities, GET /v1/entities/{lei} | Missing | Missing | Missing |
| Entity role claim | POST /v1/admin/entities/{lei}/role-claims | Missing | Missing | Missing |
| Manual payment register retry | POST /v1/payments/{tradeID}/register | Missing | Missing | Missing |
| Closed SAR archive | GET /v1/compliance/sar/closed | Missing | Missing | Missing |
| Closed STOR archive | GET /v1/compliance/stor/closed | Missing | Missing | Missing |
| Payment pending list | GET /v1/payments/pending | Present | Present | Mismatch (issuer semantics) |
| Regulatory reports | GET /v1/compliance/reports (admin) | Present | Present | Mismatch (investor auth) |
| Fill order payload | POST /v1/orders/{id}/fill | Present | N/A | Mismatch (Travel Rule) |
| Deal anchor payload | POST /v1/deals/{id}/anchor | Present | N/A | Mismatch (schema) |

---

## Middleware and Control-Path Notes

### Positive observations

- CORS allow-list with explicit origin reflection and security headers is implemented.
- Rate limiting differentiates read vs write and has auth-specific tighter limits.
- Sweep job removes expired challenge/refresh records and stale rate-limiter entries.
- Production guards for mock providers and critical provider presence are present in server startup.

### Improvement opportunity

- Centralized webhook enforcement helper should be adopted in HTTP handlers to reduce future drift risk.

---

## Recommended Upgrade Sequence

## Phase A - Immediate contract break fixes

1. Fix issuer `fillOrder` to support `travel_rule_data` for >= EUR 1,000.
2. Remove or replace investor use of admin-only `/v1/compliance/reports`.
3. Align deal anchor DTO/schema and signature requirements.
4. Resolve corporate action field drift (`parameters`, `created_at`).

## Phase B - Architecture coverage completion

5. Add client bindings for claims/entity/role-claim endpoints.
6. Add issuer/admin binding for manual payment registration retry.
7. Add closed SAR/STOR archive endpoint bindings where needed.
8. Align issuer pending-payments semantics with backend behavior.

## Phase C - Model harmonization

9. Normalize report type enums (`cmar` vs `fca_cmar`).
10. Expand regulatory report client interfaces to include DTI/LEI/counterparty fields.
11. Unify KYC status typing around `expires_at` optionality.

## Phase D - Security hardening consistency

12. Refactor webhook handlers to route signature verification via shared `HandleWebhook`.

---

## Suggested Validation Checklist After Upgrades

- `go build ./...` and `go test ./...` pass in `GreenHouse.web3`.
- Issuer and investor TypeScript compile passes after API typing updates.
- End-to-end tests:
  - Fill order >= EUR 1,000 succeeds with valid Travel Rule payload.
  - Investor no longer calls admin-only report endpoint, or can access new user-scoped endpoint.
  - Claims/entity endpoints are callable from intended portal role flows.
  - Manual payment re-registration can be invoked by admin issuer flow.
- Contract tests assert client DTOs against backend handler decode structs for:
  - deal anchor
  - corporate action proposal
  - payment pending/history responses

---

## Final Note

This document captures the current mismatch profile between upgraded backend architecture and portal API layers. The backend is substantially ahead of the clients in identity/compliance/payment operations exposure; the fastest risk reduction comes from closing the three high-severity issues first, then finishing endpoint coverage parity.
