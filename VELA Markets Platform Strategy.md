# VELA Markets: Building the Complete Private Markets Platform
### Research & Strategic Development Plan — June 2026

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Research: Legal Recognition of Tokenised Ownership](#2-research-legal-recognition-of-tokenised-ownership)
3. [Research: Interoperability Standards](#3-research-interoperability-standards)
4. [Research: Market-Making & Liquidity Provision](#4-research-market-making--liquidity-provision)
5. [Research: Privacy-Preserving Technology](#5-research-privacy-preserving-technology)
6. [Research: Governance Models](#6-research-governance-models)
7. [Synthesis: What This Means for VELA](#7-synthesis-what-this-means-for-vela)
8. [Strategic Build Plan](#8-strategic-build-plan)
9. [Technical Architecture Recommendations](#9-technical-architecture-recommendations)
10. [Regulatory Pathway](#10-regulatory-pathway)
11. [Partnership & Dependency Map](#11-partnership--dependency-map)
12. [Risk Register](#12-risk-register)

---

## 1. Executive Summary

The shared document that prompted this research makes a sharp point: the biggest value in a native Layer 1 for private markets doesn't come from tokenisation itself — it comes from **collapsing five non-technical hurdles** that currently sit outside any codebase: legal recognition, interoperability, market-making, privacy, and governance. These are the actual gating factors, not smart contract design.

This report researches each of the five in depth, then translates the findings into a phased build plan for VELA Markets — one that plays to what's already built (the Go payment engine, the Pontes and EURC integrations, the EU DLT Pilot Regime target) rather than starting from a blank page.

**Headline findings:**

- **Legal recognition** is moving faster than expected. The European Commission's December 2025 Market Integration Package proposes raising the DLT Pilot Regime's issuance cap from €6bn to **€100bn** and amending the Financial Collateral Directive to explicitly cover tokenised assets — with a realistic adoption timeline of **late 2026**. This is the single most important regulatory tailwind for VELA's EU strategy.
- **Interoperability** is converging around a small stack: ISO 24165 (token identity), GLEIF vLEI (institutional identity), and ERC-3643/ONCHAINID (compliance-embedded transfer restrictions). A platform that speaks all three from day one avoids being an island.
- **Market-making** for tokenised private assets is an unsolved distribution problem, not a technology problem. The industry consensus is now explicit: *"plan for market making from day one... a tokenized asset without active market makers is an illiquid asset with extra technology cost."*
- **Privacy** has a production-ready answer: ZK-proof-based selective disclosure (ZK-KYC, confidential balances) is moving from pilot to institutional deployment across Goldman Sachs, Deutsche Bank, and JPMorgan in 2025–2026.
- **Governance** has two working templates worth studying closely: Canton's Global Synchronizer Foundation (open, Linux Foundation-hosted, BFT supermajority voting among vetted Super Validators) and Polymesh's Governing Council (smaller, more centralised). VELA doesn't need to invent a third model — it needs to pick the right one for its trust profile and jurisdiction mix.

---

## 2. Research: Legal Recognition of Tokenised Ownership

### 2.1 The EU DLT Pilot Regime — Current State and the Critical 2026 Inflection

The DLT Pilot Regime has applied since 23 March 2023, giving authorised firms exemptions from parts of MiFID II and CSDR to operate a DLT Multilateral Trading Facility (DLT MTF), DLT Settlement System (DLT SS), or combined DLT Trading and Settlement System (DLT TSS).

**Where it stands today:**
- Six DLT Market Infrastructures are now authorised across the EU, following a slow start in 2023–2024.
- 21X AG became the first licensed DLT Trading and Settlement System (DLT TSS) in Europe, authorised in April 2025, and has already implemented ISO 24165 for both its tokenised financial instruments and its cash-side tokens.
- CSD Prague and 21X currently have no live connectivity with traditional CSDs (Clearstream, Euroclear), CCPs (Eurex Clearing, LCH), or RTGS systems such as TARGET2 — meaning DLT-based transactions remain siloed from the mainstream plumbing.

**Why 2026 matters more than any prior year:**

Three structural fixes are moving through the legislative process simultaneously:

1. **Threshold increase.** The European Commission's Market Integration Package proposes raising the DLT Pilot's aggregate issuance cap from €6bn to €100bn — the size cap was the single biggest deterrent to institutional participation, since firms couldn't generate a meaningful return on infrastructure investment within a €6bn ceiling.
2. **Cash settlement fix.** The current regime only permits e-money token settlement where the token is issued by a credit institution (not an e-money institution) — a restriction ESMA flagged as a major blocker. The Market Integration Package proposes a new framework enabling settlement of the cash leg with specific MiCAR-authorised e-money tokens more broadly.
3. **Collateral law fix.** The proposal amends the Financial Collateral Directive to expressly bring tokenised assets within scope, with a conflict-of-laws rule that ties a collateral taker's rights to the law of the Member State where the DLT system is located. Realistic adoption: late 2026.

Separately, the small-offering prospectus threshold under EU rules is rising to **€12m** as of 5 June 2026 (with member states able to set a lower €5m floor) — directly relevant to VELA's smaller private placement issuances, which may qualify for lighter-touch treatment.

**Duration risk has also been substantially de-risked.** ESMA has explicitly called on the Commission to confirm the regime will extend for a further three years from 2026, and the Commission's official communications have already pushed back against the earlier (and damaging) market belief that the regime automatically expires in 2026 — in fact, the authorisation itself is not time-bound absent a specific legislative change.

### 2.2 UK: The Digital Securities Sandbox

The UK's parallel structure, run jointly by the Bank of England and FCA:
- Opened 30 September 2024, running through a series of "gates" with increasing permitted activity, up to and including full DLT-based issuance, trading, and settlement of digital securities (equities, corporate/government bonds, money market instruments, fund units, emissions allowances).
- By end-November 2025 the DSS had attracted 16 participants.
- A March 2026 FCA sandbox cohort is separately testing stablecoin settlement assets specifically designed to interoperate with the DSS, including for cross-border issuance and settlement of digital securities.
- The DSS is scheduled to run until January 2029, with an intended transition to a permanent regime once lessons are absorbed.
- A notable gap: **UK branches of foreign firms are not eligible to enter the DSS** — only UK-established legal entities.
- There is active UK-US dialogue (SEC Commissioner Peirce has publicly discussed a transatlantic sandbox/mutual recognition regime) — worth monitoring for VELA's North America expansion plans.

### 2.3 What This Means Structurally

Both regimes are explicitly **sandbox-to-permanent-regime** structures — meaning early, well-documented participation now builds the regulatory relationship and operational track record that determines standing when the permanent frameworks crystallise. This is the same dynamic 21X and the DSS's 16 participants are already capturing.

---

## 3. Research: Interoperability Standards

Three standards are converging into what is becoming the *de facto* interoperability stack for regulated tokenised finance. A platform not speaking all three is building a private dialect.

### 3.1 ISO 24165 — Digital Token Identifier (DTI)

- A global standard (ISO subcommittee SC8) providing a unique nine-character alphanumeric identifier for any fungible digital token, agnostic to the underlying ledger (public or private).
- The 2025 update (ISO 24165-1:2025 / -2:2025) extended scope to include NFTs and separated the token identifier (DTI) from the ledger identifier (DLI).
- **Regulatory pull, not just voluntary adoption:** ESMA mandated DTI use under MiCA in July 2024 for CASP transaction and holdings reporting; the FCA is separately building DTI into its DLT financial instrument reporting framework.
- 21X's implementation is instructive: they use DTI for **both sides of a trade** — the tokenised security and the cash-side stablecoin — giving a single consistent identifier scheme across the whole settlement flow.

**Implication for VELA:** register DTIs for every asset class VELA issues from day one. This is now a reporting *requirement* in the EU, not an optional nicety, and retrofitting identifiers after the fact is far more painful than issuing with them built in.

### 3.2 GLEIF vLEI — Verifiable Institutional Identity

- The vLEI is the cryptographically verifiable digital counterpart to the 20-character LEI code that over two million legal entities already hold globally — now usable directly in on-chain interactions.
- Built on KERI (Key Event Receipt Infrastructure), an IETF draft spec, using a chained credential model (ACDC) rather than a single static certificate — meaning revocation and role changes propagate correctly, unlike traditional PKI certificates.
- Crucially, vLEI issuance and verification **does not require a specific blockchain** — GLEIF designed it to connect to any DLT or cloud infrastructure without custom integration, using the `did:webs` method for discoverability.
- GLEIF has an active strategic partnership with Chainlink (Cross-Chain Identity + Automated Compliance Engine) to embed vLEI-verified organisational identity directly into on-chain wallets, smart contracts, and tokenised assets — allowing a smart contract to know not just *that* a wallet passed KYC, but cryptographically *which legal entity* stands behind it and *what role* the signer holds within that entity.
- GLEIF's own framing captures the point precisely: this closes the biggest institutional adoption barrier — **the lack of a trusted identity on-chain** — while preserving privacy (a vLEI can attest that a wallet is KYC'd and has passed source-of-funds checks without revealing the underlying identity to the public chain).

**Implication for VELA:** vLEI is the natural counterpart identity layer for VELA's institutional issuers and larger investors (family offices, funds, asset managers) — it's globally recognised, regulator-endorsed, and chain-agnostic, meaning it survives any future decision VELA makes about which underlying ledger(s) to settle on.

### 3.3 ERC-3643 / ONCHAINID — Compliance-Embedded Transfer Standard

Already covered in depth in prior research (see companion document on payment/settlement systems) — but worth restating as the third pillar: ERC-3643 is the only token standard formally accepted as an ERC standard specifically for regulated securities, with $32bn+ tokenised through it and adoption across DTCC, Apex Group, Invesco, and Franklin Templeton, and direct use in MAS Project Guardian.

### 3.4 The Interoperability Gap That Remains

Even with these three standards converging, **cross-platform secondary liquidity is still fragmented** — a tokenised asset issued and compliance-gated on one platform doesn't automatically trade on another. Tokeny's Delivery-vs-Delivery shared order book model (covered in the prior settlement research) is the most credible attempt to solve this today, but it's still early and limited to Tokeny's own network of partners.

---

## 4. Research: Market-Making & Liquidity Provision

This is the least technically solved of the five challenges, and industry commentary in 2026 is unusually blunt about it.

### 4.1 The Core Diagnosis

The RWA tokenisation industry has solved the *issuance* problem — dozens of platforms can create a compliant token. What it has not solved, and what represents the single largest barrier to institutional adoption, is **secondary market liquidity**. A tokenised asset without active market makers is simply an illiquid asset with extra technology cost bolted on.

This directly echoes the shared document's own framing: fractional ownership expands the *potential* buyer pool but "does not automatically create liquidity" — market-making is a separate, deliberate function that has to be designed in, not assumed.

### 4.2 Three Market Structure Models, and When Each Applies

**A. Request-for-Quote (RFQ)**
- The dominant model in institutional bond and illiquid-derivative markets today. A requester asks a curated set of dealers for an executable price on a specific size; competition happens *after* trading interest appears, not continuously in a public book.
- Best suited to: large blocks, long-tail/bespoke assets, and situations where broadcasting trading intent would move the price against the requester — which describes almost every private placement secondary transfer.
- Structural strength for VELA's use case: an issuer or platform doesn't need to bootstrap a full two-sided public order book for every single-asset private fund — RFQ lets designated dealers quote on demand.

**B. Central Limit Order Book (CLOB)**
- Continuous, transparent, composable — but requires enough resting liquidity and participant density to function. The emerging DeFi consensus is explicit: "the natural hierarchy is CLOB first, RFQ as a later overlay" — but only once there's enough depth that CLOB doesn't just display an empty book. Building CLOB-first for a genuinely illiquid, low-frequency asset class like private placements risks an empty, discouraging venue.

**C. Compliant AMM (Automated Market Maker)**
- Emerging model: platforms like IXS combine an AMM/DEX specifically adapted for security tokens, giving fund managers a compliant mechanism to bootstrap liquidity without waiting for a critical mass of active dealers.
- The trade-off: AMMs price via a bonding curve, which works well for fungible, price-continuous assets but is a poor fit for genuinely heterogeneous private placements (each deal has different terms, lock-ups, and risk).

**Recommended model for VELA:** RFQ as the primary secondary mechanism (matches the actual trading pattern of private placements — infrequent, large, negotiated), with a compliant AMM layer reserved for more standardised, fungible instruments (e.g., feeder fund interests in an open-ended vehicle) where continuous pricing genuinely helps.

### 4.3 What "Building Market-Making From Day One" Actually Requires

Concrete guidance now circulating among institutional RWA infrastructure providers:
1. **Select infrastructure with secondary capability, not just issuance** — evaluate any partner or internally-built system on matching engine quality, compliance automation depth, and DvP settlement quality, not just token minting.
2. **Identify designated market makers before launch**, and structure explicit incentive programmes (rebates, priority allocation, fee sharing) — a tokenised asset does not attract market makers organically the way a listed equity does.
3. **Build the investor pipeline before the token exists.** Tokenisation doesn't create demand; VELA's distribution relationships (wealth channels, family offices, institutional LPs) are the actual liquidity source, and the token is just the settlement rail.
4. **Design order types and data feeds professional market makers actually need** — VWAP benchmarks, inventory reporting, position limits — not a simplified retail-style interface.

### 4.4 Empirical Reality Check

Recent academic work tracking tokenised RWAs (Dec 2025–May 2026, across Treasury, gold, and private-credit-linked tokens) found that a large tokenised market can remain functionally illiquid if activity concentrates in minting/redemption flows rather than genuine secondary trading, and if the holder base stays narrow. Tokenised real estate studies show properties changing hands roughly once per year on average — tokenisation alone doesn't change the underlying trading frequency of the asset class. **This is an important expectation-setting point for VELA's own roadmap and investor communications:** the technology removes friction, but genuine liquidity still has to be built deliberately, asset class by asset class.

---

## 5. Research: Privacy-Preserving Technology

### 5.1 Zero-Knowledge Proofs Have Moved From Theoretical to Institutional in 2025–2026

Financial institutions are now piloting ZKPs specifically for KYC/AML — verifying client eligibility or solvency without directly accessing or storing private financial records. Adoption has expanded from an initial cluster of scaling use cases (zk-Rollups) into enterprise compliance, supply chain verification, and confidential multi-party computation.

Institutional names now actively using ZK-based solutions include Goldman Sachs, Deutsche Bank, and JPMorgan, across confidential transactions and compliance workflows.

### 5.2 ZK-KYC — The Specific Mechanism Relevant to VELA

**How it works:** rather than a "reveal-and-store" identity model (submit passport → provider stores it), ZK-KYC lets an investor cryptographically prove a specific eligibility fact — e.g., "I am an accredited investor," "I am EU-resident and over 18," "I am not on a sanctions list" — without disclosing the underlying documents.

The most concrete real-world validation: an EU Crypto-Asset Service Provider onboarding a citizen can request a ZK proof that satisfies MiCA Article 70's identity verification requirement while **never seeing the underlying identity document** — and this is explicitly framed as the *regulator-blessed path* for ZKP-based compliance, inheriting institutional trust from the EU's own eIDAS digital identity wallet infrastructure.

**Honest technical constraints to plan around:**
- Some ZK proof systems (Groth16) require a one-time "trusted setup" ceremony per circuit — a compromised ceremony can produce flawed proofs. Newer systems (PLONK, zk-STARKs) avoid this at the cost of larger proof sizes or different performance profiles — a real architecture decision, not a footnote.
- Proof generation remains computationally nontrivial at scale — this affects UX and infrastructure cost, particularly for anything mobile-first.
- Bridging off-chain identity data (government databases, bank APIs) to an on-chain verifiable proof is itself an unsolved integration problem — smart contracts can't natively reach into external data sources, which is why oracle-based approaches (e.g., Chainlink DECO) exist specifically to prove authenticity of an HTTPS/TLS data session without revealing its contents.

### 5.3 The Institutional Custody Angle

A parallel and directly relevant pattern: institutional custody providers are adding privacy layers so they can settle on **public** blockchains without exposing client identities or positions — using shielded smart contracts or commit-and-reveal schemes so only the regulator or custodian can link an address to a client. This is architecturally the same problem VELA faces: wanting the auditability and network effects of a more open ledger, without broadcasting every counterparty's position to the world.

### 5.4 Strategic Read: Privacy as a Liquidity Moat, Not Just a Compliance Feature

One emerging thesis worth taking seriously for VELA's architecture decisions: privacy-driven infrastructure may produce winner-take-most dynamics. If liquidity coalesces on the platforms that achieve robust default privacy *alongside* broad functionality, transparent-by-default competitors face a structural disadvantage for genuinely sensitive institutional flow — because large directional positions that leak into a public book move the market against the holder before they can trade. Secret-asset bridges between chains remain rudimentary today, which means liquidity tends to stay wherever it can remain confidential. **This reframes privacy from a defensive compliance checkbox to a genuine competitive moat for VELA if built early and well.**

---

## 6. Research: Governance Models

Two working institutional templates exist today, and they represent genuinely different trust philosophies. VELA should study both rather than defaulting to either.

### 6.1 Canton Network's Global Synchronizer Foundation — The Open Consortium Model

- Governed by BFT (Byzantine Fault Tolerant) supermajority voting — specifically a two-thirds threshold — among **Super Validators**: vetted, identifiable legal entities (not anonymous stake-weighted actors) admitted only through a supermajority governance vote of existing Super Validators.
- As of March 2026, 13 Super Validators hold **equal voting power** regardless of size or stake — a deliberate design choice: if one Super Validator had more governance weight, competing institutions would be reluctant to rely on infrastructure a rival could influence. Equal voting makes the network's neutrality structural rather than merely promised.
- Governance is hosted by the **Global Synchronizer Foundation (GSF)**, created in partnership with the **Linux Foundation** specifically to provide organisational neutrality — a recognisable, independent umbrella rather than a single company controlling the protocol. GSF membership has grown past 30 organisations, including Goldman Sachs, Broadridge, Tradeweb, and Moody's Ratings.
- Below the Super Validator layer, the broader validator set is open — over 780 active validators as of May 2026 — meaning participation scales without every participant needing governance rights.
- Anyone can submit a Canton Improvement Proposal (CIP); Super Validators vote on adoption. Recent CIPs (e.g., CIP-0104, CIP-0105) show the mechanism actively used for both economic parameter changes and validator-locking requirements — a live, functioning process, not a paper framework.

### 6.2 Polymesh's Governing Council — The Curated Committee Model

(Building on the earlier research in this conversation thread.) A smaller Governing Council with committees of up to 20 members holds final vote on protocol improvement proposals — a more centralised structure than Canton's, trading breadth of legitimacy for decision-making speed and simplicity. Reasonable for a smaller, more tightly-scoped network; less credible as neutral infrastructure once a network needs to host genuinely competing institutions who each want assurance no rival controls the rules.

### 6.3 What Regulators Actually Want to See

Threading through both the EU and UK sandbox frameworks discussed above, and through GLEIF's own regulatory engagement, a consistent regulatory expectation emerges:
- **Identifiable, accountable governance participants** — not anonymous validators. Both Canton (Super Validators must be identifiable legal entities complying with applicable regulation) and Polymesh (licensed financial entities only) enforce this.
- **Independent neutrality signalling** — Canton's use of the Linux Foundation as a credible, non-commercial governance host is a deliberate trust-building move that a single-company-controlled network cannot replicate.
- **A functioning, demonstrable amendment process** — regulators want to see that rules can change in response to new law without a hard fork or ungoverned chaos; ESMA's own DLT Pilot Regime report explicitly asks DLT market infrastructures to demonstrate operational and legal performance, including how they've handled rule changes.

### 6.4 Implication for VELA

At VELA's current stage (single founder, pre-network), the honest answer is that **full decentralised governance is premature** — there's no consortium yet to decentralise power *among*. The right sequencing, following both templates' actual histories, is:
1. Start as a centrally-operated, licensed regulated entity (matches Polymesh's and Securitize's early posture, and is what EU/UK regulators expect from a sandbox entrant in any case).
2. As institutional participants join (custodians, market makers, other issuers), formalise a foundation-style governance body — ideally hosted under a recognised neutral umbrella — with clear, published criteria for admission as a governance participant.
3. Only decentralise validator/governance participation once there is a genuine multi-institution network to decentralise — mirroring Canton's actual sequence (private deployments first, public Global Synchronizer only once the ecosystem was ready).

---

## 7. Synthesis: What This Means for VELA

Mapping the five researched challenges against what's already been built (per prior sessions: the Go payment engine with Pontes and EURC integrations, the seven-phase payment upgrade plan, the comparative DLT platform analysis, and the EU DLT Pilot Regime target):

| Challenge | Industry State | VELA's Position Today | Gap to Close |
|---|---|---|---|
| **Legal recognition** | EU Pilot Regime cap rising to €100bn (late 2026); UK DSS open with 16 participants | Not yet an authorised DLT market infrastructure under either regime | Formal DLT Pilot Regime / DSS application is the critical path-defining action |
| **Interoperability** | ISO 24165 + GLEIF vLEI + ERC-3643 converging as the de facto stack | Payment layer built (Pontes/EURC/Modulr); no confirmed token identity or institutional identity standard yet adopted | Adopt DTI + vLEI + ERC-3643 (or Polymesh-equivalent) before first issuance, not after |
| **Market-making** | Universally recognised as the biggest unsolved liquidity problem; RFQ is the dominant model for illiquid institutional assets | No secondary market infrastructure yet built or partnered | Design RFQ-based secondary market and designated market-maker programme as a first-class roadmap item, not a "phase 3 nice-to-have" |
| **Privacy** | ZK-KYC now regulator-endorsed under MiCA/eIDAS; institutional ZK adoption accelerating | ZKP authentication previously explored but not implemented | Prioritise ZK-KYC pilot ahead of full Confidential Assets-style transaction privacy |
| **Governance** | Two working templates (Canton open consortium vs. Polymesh curated council) | Solo-founder stage; governance question not yet urgent | Defer formal governance design, but document the intended sequencing now so early legal/technical architecture doesn't foreclose it later |

**The single most important structural insight from the shared document, validated by this research:** VELA's biggest source of defensible value isn't tokenisation itself — every competitor can tokenise an asset. It's **collapsing the intermediary chain** (Seller → Broker → Buyer → Lawyers → GP → Administrator → Custodian → Bank) into something closer to Seller → VELA → Buyer, with compliance, identity, and settlement enforced automatically. That collapse is what the five researched challenges are actually gating — and it's also precisely where VELA's existing payment-engine work (Pontes settlement, EURC, retry/reconciliation logic) already gives a head start that most tokenisation-first competitors don't have.

---

## 8. Strategic Build Plan

### Phase 0 — Foundation Confirmation (Now – 3 months)

**Goal: Lock the architecture decisions that are expensive to reverse later.**

- [ ] Formal decision: native compliance-first chain (Polymesh-style) vs. EVM-based ERC-3643 issuance vs. hybrid. Given VELA's existing Go/TypeScript/Rust stack and EU focus, an **ERC-3643-compatible, EVM-anchored approach with a Polymesh-style compliance module ported into VELA's own Go services** is the pragmatic middle path — it keeps optionality on which base chain(s) VELA ultimately settles to, while inheriting the regulator-recognised compliance standard.
- [ ] Register for ISO 24165 DTIs for the asset classes VELA plans to issue first (mirrors 21X's approach of covering both the security token and the cash-side token).
- [ ] Scope a GLEIF vLEI integration for institutional issuer and investor onboarding — this can sit alongside, not replace, the KYC/AML workflow already implied by the payment engine work.
- [ ] Document the intended governance sequencing (see Section 6.4) in VELA's internal architecture docs, so early legal structuring (e.g., the entity registration format previously settled on — VELA Markets Ltd) doesn't foreclose a future foundation-style governance transition.

### Phase 1 — Regulatory Entry Point (3 – 9 months)

**Goal: Get inside a sandbox before building further, not after.**

- [ ] Prepare and submit a **DLT Pilot Regime application** (DLT MTF or combined DLT TSS, depending on final scope) — the €100bn threshold increase and cash-settlement fix due in late 2026 make this dramatically more attractive than it was even 12 months ago.
- [ ] In parallel, evaluate a **UK Digital Securities Sandbox** application if VELA intends UK-domiciled activity — note the requirement that the applying entity be UK-established, which affects legal structuring decisions now.
- [ ] Engage early and often with the relevant regulator(s) before submitting — both ESMA's own guidance and general market practice stress this; regulators are described as broadly supportive of well-prepared tokenisation projects, but expect proactive engagement rather than a cold application.

### Phase 2 — Compliance & Identity Layer (6 – 18 months, overlapping Phase 1)

**Goal: Build the layer that makes every later feature (secondary trading, cross-border access) possible without rework.**

- [ ] Implement ERC-3643 / ONCHAINID-equivalent compliance-gated transfer logic in VELA's asset issuance module — identity checks and jurisdictional/holding-limit rules enforced at the protocol/contract layer, not as an application-level bolt-on.
- [ ] Pilot ZK-KYC for investor onboarding — starting narrow (e.g., proving accreditation status and EU residency without storing the underlying documents) rather than attempting full confidential-transaction privacy in one step. This also directly de-risks GDPR exposure, since VELA never stores the raw identity data being proven against.
- [ ] Integrate GLEIF vLEI for institutional counterparties (issuers, custodians, market makers) so that every institutional wallet interacting with VELA carries a cryptographically verifiable, regulator-recognised legal entity identity.

### Phase 3 — Secondary Market & Liquidity (18 – 30 months)

**Goal: Solve the industry's single biggest unsolved problem, deliberately and early rather than as an afterthought.**

- [ ] Build the **RFQ-based secondary market** as the primary transfer mechanism for private placement interests — matches the actual trading pattern of the asset class (infrequent, large, negotiated) far better than a public order book would.
- [ ] Recruit and formally incentivise **2–3 designated market makers** before the first secondary-eligible asset launches — not after liquidity fails to appear organically. Structure explicit incentives (fee rebates, priority allocation).
- [ ] Reserve a compliant-AMM secondary mechanism for more standardised, fungible instruments only (e.g., feeder fund units in an open-ended structure) where continuous pricing genuinely adds value.
- [ ] Extend the atomic DvP settlement already implicit in the Pontes/EURC payment work to the secondary leg — this is where VELA's existing payment engine work becomes a genuine differentiator versus tokenisation-only competitors who still depend on traditional rails for the cash leg.

### Phase 4 — Cross-Border & Governance Maturity (30+ months)

**Goal: Scale beyond a single-jurisdiction pilot without losing the trust properties that got VELA there.**

- [ ] Formalise a foundation-style governance body once genuine multi-institution participation exists (custodians, market makers, other issuers) — following the Canton sequencing rather than attempting to decentralise prematurely.
- [ ] Pursue UK DSS and/or US sandbox pathways in parallel, monitoring the SEC-FCA transatlantic sandbox dialogue for a potential mutual-recognition shortcut.
- [ ] Extend interoperability toward genuine cross-platform secondary liquidity (Tokeny's DvD shared order book model is the closest working precedent) — this is the point at which VELA's earlier standards choices (DTI, vLEI, ERC-3643) pay off, since a platform that spoke a private dialect from the start cannot retrofit this cheaply.

---

## 9. Technical Architecture Recommendations

Building on the previously-established language stack (Go for core payment/settlement services, TypeScript for smart contract tooling, Rust as the natural progression for custom node infrastructure or ZK systems):

| Layer | Recommendation | Rationale |
|---|---|---|
| **Compliance engine** | Port Polymesh-style protocol-level compliance rules into VELA's Go services, expressed as composable rule sets (jurisdiction, accreditation, holding limits, lock-ups) | Matches the "rules that follow the asset" principle from the shared document; keeps compliance logic in a language the existing team already owns |
| **Token standard** | ERC-3643-compatible issuance layer (TypeScript/Solidity tooling) | Inherits the only ERC standard formally recognised for regulated securities; keeps multi-chain optionality |
| **Identity** | GLEIF vLEI for institutions + ZK-KYC (Rust, given the ZK tooling ecosystem) for individual investor eligibility proofs | Regulator-endorsed under MiCA Article 70; avoids storing raw identity documents |
| **Token/asset identifiers** | ISO 24165 DTI registration for every issued asset class, including the cash-side settlement token | Now a MiCA/FCA reporting expectation, not optional |
| **Settlement/cash leg** | Extend existing Pontes + EURC integration as VELA's primary cash rail; treat this as a structural advantage over tokenisation-only competitors | This is genuinely ahead of most competitors researched — most rely entirely on third-party stablecoins or traditional wires |
| **Secondary market matching** | RFQ engine (Go, given latency/reliability requirements match the existing payment-retry work) with compliant-AMM as a secondary option for fungible instruments only | Matches actual private-placement trading patterns; avoids an empty, discouraging public order book |
| **Privacy** | ZK proof system choice: evaluate PLONK/zk-STARKs over Groth16 specifically to avoid trusted-setup ceremony risk, given the reputational stakes of a compromised setup in a regulated-securities context | Direct finding from this research; a real architecture decision with institutional trust implications |

---

## 10. Regulatory Pathway

```
Now ─────────────────────────────────────────────────────────────► 30+ months

[Entity structuring]     [DLT Pilot Regime      [Live issuance under    [Foundation-style
 already underway          application prep]      sandbox exemptions]     governance body,
 (VELA Markets Ltd)                                                       multi-jurisdiction]
        │                        │                        │                      │
        ▼                        ▼                        ▼                      ▼
 Confirm architecture    Engage ESMA/NCA early    First tokenised        UK DSS + potential
 decisions that are      per ESMA guidance;       private placement      US sandbox pathway;
 expensive to reverse    parallel UK DSS          issued under Pilot     cross-platform
 (compliance standard,   evaluation if UK          Regime exemptions;     secondary liquidity
 identity stack, DTI)    entity structuring        RFQ secondary market   via DvD-style model
                          is in scope               live
```

**Key regulatory dates to track:**
- **Late 2026** — realistic adoption window for the EU Market Integration Package (€100bn threshold, cash-settlement fix, Financial Collateral Directive amendment)
- **5 June 2026** — small-offering prospectus threshold rises to €12m EU baseline (already in effect; relevant to near-term issuance sizing)
- **January 2029** — current scheduled end of the UK DSS (extendable)
- Ongoing — ESMA annual DLT Pilot Regime implementation reports, which directly signal where the regime is heading

---

## 11. Partnership & Dependency Map

| Function | Build In-House | Partner | Notes |
|---|---|---|---|
| Compliance rule engine | ✅ | | Core IP; matches existing Go investment |
| Token identity (DTI) | | ✅ DTI Foundation | Registration process, not a build |
| Institutional identity (vLEI) | | ✅ GLEIF-accredited QVI | Issuance via a Qualified vLEI Issuer, not built internally |
| Cash settlement (EUR) | ✅ | | Existing Pontes/EURC/Modulr integration is a genuine asset — extend, don't replace |
| Designated market making | | ✅ 2–3 recruited firms | Cannot be self-provided credibly; needs independent market makers |
| Custody | | ✅ Licensed custodian partner | Required for regulatory credibility; not a near-term build priority |
| ZK proof infrastructure | ✅ (Rust) | Consider Chainlink DECO/ACE as a bridge for off-chain data verification | Build the proof logic; consider partnering for the oracle/data-bridging layer |
| Legal/regulatory application | | ✅ Specialist DLT Pilot Regime counsel | High-stakes, one-shot process; not a DIY exercise given the competitive advantage of getting it right first time |

---

## 12. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| EU Market Integration Package delayed beyond late 2026 | Moderate | High — affects issuance scale planning | Design for compliance under *current* €6bn cap first; treat the €100bn increase as upside, not a dependency |
| Secondary market fails to attract genuine market-maker interest | High if unaddressed | Critical — recreates the "illiquid asset with extra technology cost" failure mode explicitly flagged in research | Recruit and incentivise market makers *before* first secondary-eligible issuance, per Phase 3 |
| Standards fragmentation (a competing token/identity standard displaces ERC-3643 or DTI) | Low-moderate | Moderate | Architecture choice already favours the standard with the broadest current regulatory endorsement; monitor ISO/ESMA guidance for shifts |
| ZK trusted-setup compromise (if Groth16-family proofs chosen) | Low | High (reputational, in a regulated-securities context) | Prefer PLONK/zk-STARK-family systems where proof-size trade-off is acceptable |
| Governance centralisation becomes a regulatory objection as VELA scales | Low near-term, rising over time | Moderate | Document intended foundation-style transition now (Section 6.4) so it isn't a scramble later |
| Cross-border identity/KYC portability gap (flagged in prior settlement research) undermines EU-first strategy when expanding to UK/Asia | Moderate | Moderate | vLEI's chain-agnostic, jurisdiction-agnostic design directly mitigates this if adopted early |

---

## Closing Note

The shared framing document's most important line is arguably this one: *"the innovation would be less about 'putting assets on a blockchain' and more about creating a programmable financial market infrastructure."* Everything researched here confirms that the actual competitive battlefield in 2026 is not tokenisation — every serious platform can already do that — it's who solves legal recognition, interoperability, market-making, privacy, and governance **together**, as one coherent system, rather than as five separate bolt-ons. VELA's existing payment-engine work already gives it a genuine head start on the piece almost everyone else treats as an afterthought — the cash leg. The plan above is designed to extend that advantage across the other four, deliberately and in the right order, rather than letting any one of them become the blocker the way it has for competitors researched in this and prior sessions.

---

*Research compiled from ESMA, European Commission, Bank of England, FCA, GLEIF, DTI Foundation, Canton Network/Global Synchronizer Foundation, and industry sources (PwC, William Fry, CMS, Chainlink, Fireblocks, Metamask/Consensys research). Current as of June 2026.*
