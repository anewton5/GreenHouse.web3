# Addendum: UK Company Registration & Cross-Border Access
## Supplement to EU Private Placements DLT Platform Regulatory Review — May 2026

---

> **Questions addressed:**
> 1. Can you register your company in the UK — at all, or alongside Germany/Luxembourg?
> 2. Can your EU-authorised DLT platform serve UK and other non-EU investors and issuers?
> 3. How do you structure a genuinely pan-European (EU + non-EU) private placements platform?

---

## PART 1 — THE UK REGISTRATION QUESTION

### 1.1 Short Answer

**Yes, absolutely — and you probably should have a UK entity.** But the architecture matters enormously. The UK cannot be your *regulated operating entity* for EU DLT Pilot Regime purposes — that must sit in an EU Member State. However, the UK is an excellent location for a **holding company, IP entity, or technology subsidiary**, and increasingly also for a parallel UK-regulated operating entity under the UK's own Digital Securities Sandbox (DSS).

The optimal structure for your ambitions is a **dual-jurisdiction group** with:
- An **EU regulated OpCo** (Germany or Luxembourg) — holds DLT TSS permission, MiFID II authorisation, EU passporting rights
- A **UK entity** — holding company and/or DSS sandbox participant for UK market access

### 1.2 Why the UK Cannot Be Your Primary EU-Regulated Entity

Post-Brexit, the UK is a **third country** under EU law. This has concrete consequences:

| EU Framework | Impact on UK-Registered Firms |
|-------------|-------------------------------|
| DLT Pilot Regime (2022/858) | **No.** Only EU-authorised investment firms, market operators, or CSDs can apply. UK entities cannot apply directly. |
| MiFID II | UK firms lost passporting rights on 31 December 2020. A UK-registered investment firm cannot operate across the EU without a separate EU authorisation. |
| MiCA | UK is a third country. CASP authorisation requires EU legal establishment. UK firms cannot passport into EU under MiCA. |
| DORA | Applies to EU-regulated entities; UK ICT providers serving EU firms face contractual DORA obligations but are not directly in-scope. |
| EU Prospectus Regulation | UK issuers are treated as third-country issuers and must comply with EU prospectus rules for EU public offers. |

> **Bottom line:** A UK company *alone* cannot hold DLT Pilot Regime permission, MiFID II investment firm authorisation, or MiCA CASP authorisation. You need a separate EU entity for the regulated EU operations.

### 1.3 What the UK *Can* Do for Your Structure

| Role | UK Entity Suitability | Notes |
|------|----------------------|-------|
| **Holding company** | ✅ Excellent | UK has no withholding tax on dividends paid outward; extensive tax treaty network; strong legal system |
| **IP / Technology entity** | ✅ Strong | License technology (blockchain protocol, smart contracts) to EU OpCo; UK R&D tax credits available |
| **DSS participant** (UK market) | ✅ Now open | UK Digital Securities Sandbox operates independently of EU DLT Pilot Regime |
| **FCA-regulated entity** | ✅ For UK market | Obtain FCA authorisation separately for UK investors and UK issuers |
| **Founder / parent entity** | ✅ Practical | Many EU DLT startups are founded by UK-based entrepreneurs — perfectly fine |
| **EU regulated OpCo** | ❌ Not permitted | Must be incorporated in an EU Member State |

### 1.4 The UK Digital Securities Sandbox (DSS) — Your UK Parallel Track

The UK's DSS is the direct equivalent of the EU DLT Pilot Regime. Launched September 2024 by the FCA and Bank of England jointly, it is currently open for applications (window expected to close around March 2027).

**What the DSS allows:**
- Test issuance, trading, and settlement of tokenised securities under a modified regulatory framework
- Combine notary/maintenance/settlement functions (traditionally CSD-only) with operation of a trading venue — the same structural innovation as the EU DLT TSS
- Non-GBP denominated assets are permitted
- Path to full permanent authorisation if the sandbox is successful

**Key DSS features vs. EU DLT Pilot Regime:**

| Feature | EU DLT Pilot Regime | UK Digital Securities Sandbox |
|---------|--------------------|-----------------------------|
| Launch | March 2023 | September 2024 |
| Regulator | NCA (e.g., BaFin, CSSF) + ESMA coordination | FCA + Bank of England jointly |
| Duration | Until regime is made permanent or terminated; currently open-ended | Until December 2028 (extendable) |
| Passporting | EU-wide via MiFID II passporting | UK-only; no passporting |
| Settlement currency | EUR, commercial bank money, EMTs; Pontes for central bank money | GBP, potential sterling stablecoins |
| CSD exemptions | Yes, under Articles 4–6 of Regulation 2022/858 | Yes, under modified UK CSD regime |
| Natural person access | Possible with exemptions | Possible |
| Firm types eligible | Investment firms, market operators, CSDs, new entrants | Existing authorised firms or new entrants |
| Capital minimum | Based on IFR/MiFID II | Reduced minimum; flexible limits introduced at Gate 2 (2025) |

**Timeline:** In April 2026, the FCA advanced tokenisation policy via Policy Statement PS 26/7. A comprehensive cross-authority roadmap for wholesale market digitalisation is expected later in 2026. The FCA's full crypto authorisation gateway is expected to open September 2026, with the regime going live October 2027.

**Current DSS status (May 2026):** 16 companies have successfully completed initial evaluation and are progressing toward full operational deployment, including the DIGIT pilot (UK's first digital gilt, issued by HSBC's Orion platform for HM Treasury).

### 1.5 Recommended UK Corporate Structure

```
┌──────────────────────────────────────────────────────┐
│             UK HOLDING COMPANY (Ltd/Plc)              │
│         (Incorporated in England & Wales)             │
│                                                       │
│  • No financial services regulation required          │
│  • Holds shares in all subsidiaries                   │
│  • UK Asset Holding Company regime (if applicable)    │
│  • R&D tax credits on tech development costs          │
│  • No withholding tax on dividends paid out           │
│  • English law — world's preferred governing law      │
└─────────────┬──────────────────┬─────────────────────┘
              │                  │
┌─────────────▼──────┐  ┌────────▼───────────────────┐
│  EU REGULATED       │  │  UK REGULATED ENTITY        │
│  OPCO               │  │  (FCA-authorised)           │
│  (Germany/Lux)      │  │                             │
│                     │  │  • FCA investment firm      │
│  • DLT TSS          │  │  • DSS sandbox participant  │
│    permission       │  │  • UK private placements    │
│  • MiFID II auth    │  │  • UK investor/issuer       │
│  • EU passporting   │  │    access                   │
│  • Pontes eligible  │  │  • Path to permanent UK     │
│  • CASP (if needed) │  │    DLT authorisation        │
└─────────────────────┘  └────────────────────────────┘
```

### 1.6 UK Holding Company — Tax Considerations

The UK remains an attractive holding company jurisdiction post-Brexit:

**Advantages:**
- **Substantial Shareholding Exemption (SSE):** Gains on disposal of qualifying subsidiaries are generally tax-exempt
- **Dividend exemption:** Most dividends received from subsidiaries are exempt from UK corporation tax
- **No withholding tax** on dividends paid by UK holding companies to shareholders
- **Extensive tax treaty network:** UK has treaties with most EU Member States; withholding taxes on interest/royalties from EU subsidiaries to UK parent are typically reduced or eliminated (check Germany specifically — 5% WHT applies)
- **UK R&D tax credits:** Generous regime for technology development costs

**Watch points:**
- The **EU Interest and Royalties Directive** no longer applies between the UK and EU Member States — royalty payments from your EU OpCo to a UK IP entity attract withholding tax (reduced by treaty but not eliminated in all jurisdictions)
- **Transfer pricing:** Intragroup IP licensing and service fees must be at arm's length; document carefully
- **Substance requirements:** UK holding company must have genuine substance, not be a letterbox; the EU/ESMA are active in challenging substance-less structures

---

## PART 2 — UK AND NON-EU INVESTORS ACCESSING YOUR EU PLATFORM

### 2.1 The Core Rule: Where Is the Service Being Provided?

The EU's approach to cross-border financial services is **where the service is provided**, not where the investor is located. If your EU DLT TSS is providing services *into* the EU, EU rules apply. But EU rules do not *prevent* UK or other non-EU investors from accessing EU-authorised platforms — they govern how.

### 2.2 UK Investors on Your EU DLT TSS Platform

**Short answer: Yes, UK investors can access your EU-authorised platform.** There is no EU law prohibition on UK persons investing through an EU-regulated platform. The regulatory requirements fall on the *platform* (your EU OpCo), not on the nationality of investors.

**What this means in practice:**

| Scenario | Permissible? | Requirements |
|----------|-------------|--------------|
| UK professional investor accesses your EU DLT TSS and invests in an EU startup's tokenised shares | ✅ Yes | KYC/AML as normal; categorise as professional investor under MiFID II criteria |
| UK retail investor accesses your platform | ⚠️ Caution | MiFID II conduct obligations apply based on the investor's category, not their country; retail protections (appropriateness, disclosures) must be met |
| Your EU platform actively markets to UK investors | ✅ Yes from EU side; UK financial promotions rules apply | Marketing to UK persons triggers UK FCA financial promotions regime; must be communicated by or approved by an FCA-authorised firm |
| UK-based startup tokenises shares on your EU platform | ✅ Yes | The issuer is a UK company listing DLT financial instruments on an EU-authorised DLT TSS; EU Prospectus Regulation / exemptions apply; company law of UK governs the shares themselves |

### 2.3 UK Financial Promotions — A Critical Compliance Point

If your platform markets to UK-based persons (investors or issuers), UK financial promotions law applies regardless of where your EU entity is based.

**Key requirements:**
- Financial promotions communicated to UK persons must be approved by an FCA-authorised firm (unless the communicator is itself FCA-authorised)
- Your UK FCA-authorised subsidiary can approve financial promotions for UK audiences — this is a key reason to have the UK entity
- Unapproved financial promotions to UK persons carry criminal penalties
- The FCA has been very active in enforcement in this area

**Practical solution:** Your UK FCA-authorised entity (whether DSS participant or standard investment firm) approves and distributes all financial promotions directed at UK persons. Your EU OpCo does the same for EU persons.

### 2.4 UK Issuers on Your EU Platform — Company Law Dimension

When a UK company tokenises its shares on your EU DLT TSS, the **company law governing those shares remains UK law** (Companies Act 2006). This creates a cross-border legal interface that needs careful planning:

| Issue | UK Law | EU DLT Platform Implication |
|-------|--------|---------------------------|
| Share register | UK Companies Act requires a register of members | DLT ledger must serve as or interface with the statutory register; UK law reform may be needed (Law Commission has reviewed this) |
| Transfer of shares | UK law governs what constitutes a valid transfer | Smart contract transfer must be legally valid under UK law |
| Shareholder rights | UK Corporate Governance Code | Dividend payment, voting rights must comply with UK company law |
| FCA Listing Rules | If UK-listed, FCA rules apply additionally | Private companies are not subject to Listing Rules |
| Tax | UK Stamp Duty Reserve Tax (SDRT) | 0.5% SDRT may apply on share transfers; DLT transfers are not currently SDRT-exempt in UK — watch for reform |

> **UK Law Commission note:** The Law Commission of England and Wales has been examining digital assets and their legal status. While significant progress has been made (the Property (Digital Assets etc) Bill was introduced and passed), the framework for company shares on DLT is still evolving. Obtain a legal opinion on the validity of DLT-based share transfers for UK companies before onboarding UK issuers.

### 2.5 Non-EU, Non-UK Investors (Switzerland, Norway, EEA, Rest of World)

**EEA countries (Norway, Iceland, Liechtenstein):**
- EEA countries have largely adopted MiFID II and related EU financial legislation through the EEA Agreement
- Investors from EEA countries are treated similarly to EU investors for most purposes
- Your EU passporting may extend to EEA — verify for each jurisdiction

**Switzerland:**
- Switzerland is neither EU nor EEA
- Swiss investors can access your EU platform subject to the same rules as UK investors
- Switzerland has its own DLT Act (2021) and is developing its tokenised securities ecosystem independently
- Marketing to Swiss investors triggers Swiss FinSA (Financial Services Act) requirements — consider a local Swiss marketing arrangement

**United States:**
- US investors accessing EU tokenised securities platforms trigger potential SEC and CFTC oversight
- Regulation S / Rule 144A exemptions may need to be structured if US persons are involved
- Strongly recommended: **exclude US persons** from initial platform access; add them later with bespoke US legal structuring
- US persons should be identified at KYC stage and access blocked pending US legal framework

**Other jurisdictions:**
- Assess each non-EU/non-UK jurisdiction on a case-by-case basis
- FATF member jurisdictions with adequate AML frameworks: generally serviceable with enhanced KYC
- FATF blacklist/greylist countries: EDD required; many will be restricted entirely
- Third-country equivalent regimes: some jurisdictions (e.g., Australia, Canada, Japan, Singapore) have MiFID II-equivalent regimes which may facilitate easier access

### 2.6 Reverse Solicitation — A Limited Tool for Third-Country Access

If a non-EU investor approaches your EU platform entirely on their *own initiative* (no marketing, no advertising, no website targeting), this is "reverse solicitation" — and the EU's licensing requirements do not apply to that specific transaction. However:

- **ESMA is very strict** on this: any form of targeted marketing, online advertising, geo-targeted content, or local language website *disqualifies* the exemption
- The exemption applies only to the **specific service or product requested** — it cannot be used to build a broader relationship
- **Do not rely on reverse solicitation as a business model.** It is a narrow safety valve, not a distribution strategy
- Contractual disclaimers claiming "all business is reverse solicitation" are specifically called out by ESMA as ineffective

---

## PART 3 — THE TRANSATLANTIC DIMENSION: UK-US COOPERATION

A significant development relevant to your long-term strategy: in September 2025, HM Treasury and the US Treasury launched the **Transatlantic Taskforce for Markets of the Future**, co-chaired with participation from the FCA, SEC, CFTC, and Bank of England. Its mandate covers digital asset collaboration and cross-border capital markets access, with a report expected summer 2026.

This Taskforce signals genuine regulatory convergence ambitions between the UK and US on digital assets. If you have a UK entity in the group, you are better positioned to benefit from any regulatory bridge or mutual recognition arrangement that emerges from this process.

Similarly, at the EU-UK Summit (19 May 2025), financial services cooperation was on the agenda, with calls to make finance part of the post-Brexit reset. While no specific equivalence deal has been struck, the political temperature is warming — and the EU's clearinghouse equivalence for the UK has been extended to June 2028. Your dual UK-EU structure positions you to benefit from any further equivalence arrangements that may emerge.

---

## PART 4 — RECOMMENDED DUAL-JURISDICTION STRUCTURE IN FULL

```
┌─────────────────────────────────────────────────────────────┐
│                   UK HOLDING COMPANY                         │
│              (England & Wales — Private Ltd or Plc)          │
│                                                             │
│  Functions: Group HQ, IP ownership, shareholder vehicle     │
│  Regulation: None required at holding level                 │
│  Tax: SSE, dividend exemption, extensive treaty network     │
└──────┬──────────────────────────────────────┬───────────────┘
       │                                      │
┌──────▼───────────────────┐  ┌───────────────▼───────────────┐
│  EU REGULATED OPCO        │  │  UK ENTITY (FCA-authorised)   │
│  (Germany or Luxembourg)  │  │                               │
│                           │  │  Activities:                  │
│  Licences:                │  │  · FCA Investment Firm auth   │
│  · MiFID II investment    │  │  · DSS sandbox participant    │
│    firm / market operator │  │  · UK financial promotions    │
│  · DLT TSS specific       │  │    approver                   │
│    permission (EU 2022/   │  │  · UK investor/issuer KYC     │
│    858)                   │  │  · Future: full UK DLT auth   │
│  · CASP (MiCA) if needed  │  │    when regime permanent      │
│  · Pontes registered      │  │                               │
│    Market DLT Operator    │  │  Clients:                     │
│                           │  │  · UK investors               │
│  Clients:                 │  │  · UK issuers                 │
│  · All EU/EEA investors   │  │  · Rest of world (ex-US)      │
│  · UK professional        │  │    where permitted            │
│    investors (via EU      │  │                               │
│    platform)              │  │  Settlement:                  │
│  · Swiss, RoW investors   │  │  · GBP settlement             │
│    (assessed per jur.)    │  │  · Sterling stablecoin        │
│                           │  │    (when regime finalised)    │
│  Settlement:              │  │  · RTGS/CHAPS                 │
│  · EUR via Pontes         │  └───────────────────────────────┘
│    (central bank money)   │
│  · Commercial bank EUR    │  ┌───────────────────────────────┐
│  · EMTs                   │  │  TECHNOLOGY / IP ENTITY       │
└───────────────────────────┘  │  (can be UK or EU)            │
                               │                               │
                               │  Owns: dBFT blockchain        │
                               │         protocol, smart        │
                               │         contracts, platform    │
                               │         software              │
                               │  Licenses to: both OpCos      │
                               │  Benefits: R&D tax credits    │
                               └───────────────────────────────┘
```

---

## PART 5 — STEP-BY-STEP: ADDING UK TO YOUR ROADMAP

### Phase A: Establish UK Holding Company (Month 1)
- Incorporate UK Ltd or Plc at Companies House (1–3 days)
- Appoint directors (can be same as EU OpCo founders initially)
- Set up as 100% owner of EU OpCo and future UK OpCo
- Register for Corporation Tax with HMRC
- Consider whether UK Asset Holding Company (AHC) regime applies if you raise fund capital

### Phase B: UK Technology Entity (Month 1–3)
- Incorporate UK Ltd as IP/technology subsidiary
- Assign or license all blockchain protocol IP to this entity
- Register for UK R&D tax credits (up to 20% cash credit on qualifying costs)
- Document intragroup IP licensing agreements at arm's length

### Phase C: FCA Authorisation Application (Months 3–12)
- Apply for FCA authorisation as an investment firm (for UK investor-facing services)
- Required licences: arranging deals in investments; operating a multilateral trading facility (UK equivalent)
- FCA authorisation timeline: typically 6–12 months for a new applicant
- Senior Managers and Certification Regime (SMCR) applies — identify all Senior Management Functions
- Simultaneously apply for DSS sandbox entry if you wish to test UK DLT infrastructure

### Phase D: DSS Application (Months 6–18)
- Apply to FCA/Bank of England for DSS entry via online application
- DSS is divided into gates:
  - **Gate 1:** Proof-of-concept testing, limited activity
  - **Gate 2:** Growing the business under Bank and FCA rules (flexible limits introduced 2025); FCA requirements for operators of trading venues
  - **Gate 3:** Full authorisation path; revised CSD regime reflecting sandbox learnings
- DSS operational until December 2028 (extendable)
- Application window expected to close around March 2027 — **do not delay**

### Phase E: UK Financial Promotions Regime (Ongoing from launch)
- All marketing to UK persons must be approved by FCA-authorised person
- Your UK FCA entity performs this role for the group
- Document approval process and maintain approvals register
- Do not allow EU OpCo to market directly to UK persons without UK entity sign-off

### Phase F: UK Issuer Onboarding (Ongoing)
- Legal opinion on validity of DLT-based share registers under Companies Act 2006
- UK SDRT analysis for each share transfer (potential 0.5% tax)
- Monitor Property (Digital Assets etc) Bill and any Companies Act reform affecting digital shares
- Separate terms of service for UK-incorporated issuers vs. EU-incorporated issuers

---

## PART 6 — REGULATORY DIVERGENCE RISK

The UK is deliberately diverging from EU financial regulation post-Brexit. This creates both opportunity and risk for a dual-jurisdiction platform:

| Area | UK Direction | EU Direction | Divergence Risk |
|------|-------------|-------------|-----------------|
| Crypto/DLT regulation | Lighter touch, innovation-focused; full regime October 2027 | MiCA/DLT Pilot — prescriptive but comprehensive, now in force | Medium — different licensing timelines |
| AIFMD equivalent | UK reviewing; new 3-tier categorisation proposed | AIFMD II in force | Medium |
| Short selling | UK Short Selling Regulations 2025 (diverging from EU SSR) | EU SSR | Low for your model |
| AML | UK aligned with FATF but not EU AMLR directly | EU AMLR + AMLA from 2025 | Low — both FATF-based |
| Operational resilience | UK PRA SS1/21 + FCA PS21/3 (not DORA) | DORA (January 2025) | High — different standards |
| Settlement finality | UK settlement finality law (aligned) | EU Settlement Finality Directive | Low |
| Data protection | UK GDPR (currently aligned) | EU GDPR | Low currently; watch for future UK divergence |

**Key risk:** Your EU OpCo must comply with DORA. Your UK OpCo must comply with UK operational resilience rules. These are substantively similar but not identical — build a common baseline ICT framework (e.g., ISO 27001) and layer each jurisdiction's specific requirements on top to avoid duplicating compliance work.

---

## SUMMARY: ANSWERS TO YOUR QUESTIONS

### Can you register in the UK?
**Yes — and you should.** Register the UK holding company immediately (it is simple and cheap). Register a UK operating entity for the FCA authorisation and DSS application in parallel with your EU authorisation journey. You cannot use a UK entity alone for the EU DLT Pilot Regime — that requires an EU-incorporated entity.

### Can your EU platform serve UK investors and issuers?
**Yes.** UK and other non-EU investors can access your EU-authorised DLT TSS platform. The constraints are:
- Financial promotions to UK persons require FCA-authorised approval
- UK corporate issuers face additional company law considerations (UK share register requirements, potential SDRT)
- US persons should be excluded initially and addressed separately with US legal counsel

### Can your platform be truly pan-European (EU + UK + beyond)?
**Yes, with the right group structure.** The dual-entity group (EU OpCo + UK OpCo + UK Holding Co) gives you:
- **EU DLT Pilot Regime permission** — for EU/EEA investors and issuers, with EUR settlement via Pontes
- **UK DSS participation** — for UK investors and issuers, with GBP settlement
- **Pan-European reach** — Switzerland, Norway, and other non-EU European markets accessible through both entities with appropriate local arrangements
- **Unified technology layer** — single dBFT blockchain running both jurisdictions' regulated operations
- **Future optionality** — positioned to benefit from any UK-EU regulatory convergence or equivalence arrangement

---

*This addendum should be read alongside the main regulatory review document. All content reflects the regulatory position as of May 2026 and should be verified with qualified UK and EU regulatory counsel. The UK regulatory landscape for digital assets is in active development — specific rules and timelines are subject to change.*
