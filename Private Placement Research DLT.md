# DLT & Private Placement Platforms: Research Report
> Compiled: May 2026

---

## Table of Contents

1. [What Are Private Placement Platforms?](#1-what-are-private-placement-platforms)
2. [Where the Industry Stands Today](#2-where-the-industry-stands-today)
3. [How DLT Is Disrupting the Industry](#3-how-dlt-is-disrupting-the-industry)
4. [Major DLT Private Placement Players](#4-major-dlt-private-placement-players)
5. [Polymesh: Operations, Gaps & Weaknesses](#5-polymesh-operations-gaps--weaknesses)
6. [What a Stronger DLT Platform Would Look Like](#6-what-a-stronger-dlt-platform-would-look-like)
7. [P2P Networking & Consensus Architecture](#7-p2p-networking--consensus-architecture)

---

## 1. What Are Private Placement Platforms?

Private placement platforms are digital marketplaces or intermediary systems that facilitate the sale of securities — equity, debt, funds, or alternative assets — directly to a select group of investors (typically accredited or institutional) without a public offering. They bypass the traditional IPO or public exchange route, operating under regulatory exemptions (like Reg D in the US or equivalent frameworks globally).

They serve multiple roles:
- Deal origination
- Investor onboarding (KYC/AML)
- Subscription processing
- Compliance
- Post-investment reporting

Key players today include **iCapital**, **Opto Investments**, **UpMarket**, **Willow Wealth**, and emerging niche platforms.

---

## 2. Where the Industry Stands Today

### Scale & Momentum

Private markets are projected to exceed $15 trillion by 2025 and surpass $18 trillion by 2027, with strong growth in private credit/debt, real assets, and secondary markets expected to continue.

### Democratisation Is the Defining Theme

Retail investors' appetite for alternative assets and the availability of vehicles enabling private market access have grown even more rapidly than anticipated. A State Street survey found that 55% of senior executives at top buy-side firms believe that within one to two years, half of all private market fundraising will come from retail investors.

In August 2025, the US administration issued an executive order calling for expanded access to private equity and other alternative investments for 401(k) retirement plans, accelerating this democratisation trend. Firms like Ares are targeting $125 billion in wealth assets for their platforms by 2028.

### Semi-Liquid Structures Are Booming

The 'semi-liquid' NAV stood at $426 billion in Q3 2025, following a 40% CAGR since 2021. Private wealth vehicles that package illiquid assets into interval funds or semi-liquid funds are becoming an integral part of the asset allocation toolkit — signalling that private markets are becoming part of household balance sheets, not just institutional portfolios.

### 2026 Market Conditions

Private markets enter 2026 on firmer footing, with deal activity rebounding alongside a more supportive rate environment.

---

## 3. How DLT Is Disrupting the Industry

Distributed Ledger Technology (blockchain) is arguably the most structurally significant force reshaping private placements, across several dimensions:

### 3.1 Tokenisation of Private Assets

Tokenisation converts real-world assets — stocks, bonds, real estate — into digital tokens. Private fund transactions that take weeks today could happen in minutes. It enables real-time fractional ownership of previously illiquid assets, greater liquidity, and broader investor access. Assets can be transferred directly between parties without a central intermediary, reducing transaction costs while increasing speed.

### 3.2 Full Lifecycle Transformation

DLT is transforming the entire lifecycle of securities, from issuance to post-trading:
- **Primary markets:** Faster issuance through shared data and process automation
- **Secondary markets:** Enhanced liquidity through fractionalisation, extended trading hours, and broader access to asset classes

### 3.3 Smart Contracts Automating Compliance

Smart contracts introduce self-executing agreements coded into blockchain networks, automating workflows, compliance checks, and real-time reporting — together representing a paradigm shift toward financial systems that can operate continuously and securely at a fraction of today's cost.

### 3.4 Regulatory Milestones

In December 2025, the SEC Trading and Markets Division outlined how broker-dealers can custody tokenised stocks and bonds under existing rules, and issued a no-action letter clearing the way for the DTCC's Depository Trust Company to launch a tokenised securities service. In January 2026, the NYSE announced it is developing a platform to trade tokenised stocks and ETFs, supporting 24/7 trading and near-instant settlement.

### 3.5 Institutional Adoption Maturing

A Value Exchange study found that 72% of organisations — including banks, investors, and market operators — had issued a digital asset in the last 12 months, while 60% are providing digital asset custody solutions. Over the next 12 months, 56% said they would pledge tokenised securities as collateral.

### 3.6 European Regulatory Framework

The EU's Markets in Crypto-Assets Regulation (MiCA), fully applicable since December 2024, establishes a harmonised framework for crypto-asset service providers and issuers. DLT is increasingly intersecting with mainstream financial services, reducing payment and settlement frictions, improving liquidity management, enabling programmability, and streamlining reconciliation.

---

## 4. Major DLT Private Placement Players

The landscape falls into three tiers: purpose-built native blockchains, full-stack application platforms, and institutional infrastructure rails.

### Tier 1: Native Blockchain Engines

#### Polymesh / Polymath

The clearest case of a purpose-built chain where compliance is in the protocol itself:

- A public permissioned blockchain purpose-built for regulated assets and capital markets
- Addresses key challenges around governance, identity, compliance, confidentiality, and settlement — built from the ground up for regulated securities
- Every participant must have a verified on-chain identity; assets are first-class citizens at the protocol level
- Does not rely on traditional token standards like ERC-20 or ERC-1400 — token functionality is incorporated into the chain at the protocol layer
- In May 2026, launched Confidential Assets — a native protocol-layer privacy feature using zero-knowledge proof technology allowing institutions to transact on a public blockchain while keeping positions, balances, and counterparty details private

### Tier 2: Full-Stack Application Platforms

#### Securitize

The regulated infrastructure market leader:
- DS Protocol automates token issuance, transfer agent functions, and secondary trading on a regulated ATS
- Fund Services platform offers full tokenised fund administration
- $47 million led by BlackRock; over $1 billion in on-chain assets
- Received authorisation under the EU's DLT Pilot Regime — the only firm with licensed tokenisation infrastructure in both the US and EU
- In May 2026, launched fully regulated on-chain trading for tokenised equities with Jump Trading and Jupiter, running on Solana

#### Tokeny (now part of Apex Group)

The standard-setter:
- Enables financial institutions to issue, manage, and distribute tokenised securities using the ERC-3643 standard (formerly T-REX)
- $28 billion worth of assets tokenised through ERC-3643
- ERC-3643 is the only token standard officially accepted as an ERC standard for regulated securities
- 1,000+ features built on ERC-3643; indexed over 3 billion blockchain events

### Tier 3: Institutional Rails & Infrastructure

#### Broadridge DLR + HQLAX + Canton Network

- Broadridge's Distributed Ledger Repo (DLR) settles approximately $354 billion per day in tokenised real assets
- HQLAX secured strategic investments from Broadridge and Digital Asset, with plans to migrate to the Canton Network
- Canton Network (built by Digital Asset using DAML smart contracts) is the permissioned interoperability layer used by Goldman Sachs, JPMorgan, and others

#### LSEG Digital Markets Infrastructure (DMI)

- Covers fund issuance, tokenisation and registry, distribution, and post-trade settlement and servicing
- Apex Group announced as first fund services provider connected to DMI in early 2026

#### DTCC

- Bridge-first approach: tokenisation services convert traditional book-entry securities held at DTC into tokenised representations while preserving ownership rights
- Not a native DLT play but the incumbent clearinghouse wrapping itself in DLT rails

### Player Comparison Table

| Platform | Native Chain? | Settlement Native? | Compliance Native? | Regulation Licensed? | Privacy/Security |
|---|---|---|---|---|---|
| **Polymesh** | ✅ Yes | ✅ Protocol-level | ✅ Protocol-level | Partial | ✅ ZK-proofs (2026) |
| **Securitize** | ❌ Multi-chain | ✅ Near-instant | ✅ Smart contract | ✅ US + EU licensed | Moderate |
| **Tokeny/ERC-3643** | ❌ EVM chains | ✅ On-chain | ✅ Smart contract | ✅ Via Apex Group | Moderate |
| **Broadridge DLR** | ❌ Permissioned | ✅ $354B/day | Partial | ✅ Institutional | High |
| **LSEG DMI** | ❌ Hybrid | ✅ Post-trade | Partial | ✅ Regulatory body | High |
| **DTCC** | ❌ Bridge model | ✅ Legacy + token | Partial | ✅ Incumbent | High |

---

## 5. Polymesh: Operations, Gaps & Weaknesses

### 5.1 Where Polymesh Operates

**Headquarters & Governance:** Polymesh is governed by Polymesh Labs Ltd., a Cayman Islands-based subsidiary of Polymath, headquartered in Toronto, Canada.

**Geographic Footprint:**

| Region | Status | Key Partners |
|---|---|---|
| North America | Primary home | tZERO (broker-dealer), BitGo, Paysafe |
| Europe | Growing | Black Manta (BaFin-regulated), Luxembourg/Munich/Vienna/Cork |
| Asia | Early-stage | BDACS (South Korea, licensed custodian), Galaxy/GK8 |

**Network Scale (as of 2026):**
- 100+ million blocks validated
- 62 certified nodes
- 7,000+ user accounts
- 5,000+ POLYX holders

**Node Operator Model:** Only licensed and regulated financial entities can run validator nodes, introducing real-world accountability bolstered by mandatory on-chain identity verification.

### 5.2 Gaps & Weaknesses

#### 1. Tiny Ecosystem Scale

Less than one-eighth of the projected $16 trillion in tokenised assets expected by 2030 are currently on-chain in 2025. Polymesh's 7,000 accounts and 62 nodes are a fraction of what Ethereum, Solana, or Avalanche host. The network effect moat simply isn't there yet.

#### 2. No Native Secondary Market Liquidity

Polymesh has significantly limited secondary market infrastructure and reduced DeFi composability. Tokenising an asset on Polymesh doesn't automatically give it a buyer. The platform depends entirely on partner ATSs (like tZERO) for secondary trading — meaning liquidity is borrowed, not native.

#### 3. Developer Lock-In & Flexibility Limits

Polymesh is built using the Substrate framework, and developers interact via the Polymesh SDK rather than deploying custom smart contracts. Developers accustomed to writing Solidity for the EVM face a significant paradigm shift. This limits flexibility for teams wanting highly customised financial logic.

#### 4. Not a Registered Regulated Entity

Polymath is explicitly not a registered broker-dealer, investment adviser, or financial advisor, and is not registered with any regulatory agency. It must always rely on licensed third parties for execution, custody, and compliance counterparty functions — creating dependency and friction.

#### 5. Confidential Assets Still Maturing

Confidential Assets only launched on DevNet in December 2025. Its progression to testnet and then mainnet has no confirmed public timeline. Institutions face uncertainty about when this critical production privacy feature will be available.

#### 6. POLYX Token as a Friction Layer

Requiring POLYX to pay transaction fees introduces operational complexity and crypto market volatility risk. Unlike stablecoin-denominated fee models, POLYX pricing fluctuates — a real friction point for treasury management at banks and asset managers.

#### 7. Patchy Jurisdictional Coverage

Despite partnerships in Europe (via Black Manta/BaFin) and South Korea (BDACS), Polymesh has no significant licensed presence in the UK (FCA), Singapore (MAS), UAE (DFSA/ADGM), Japan (FSA), or Australia (ASIC).

#### 8. Governance Concentration Risk

The Polymesh Governing Council has final vote on all protocol improvement proposals, with committees of up to 20 members. For institutions requiring regulatory certainty about who controls the underlying infrastructure, a council of 20 is uncomfortably centralised.

---

## 6. What a Stronger DLT Platform Would Look Like

Building on Polymesh's architectural strengths but closing its gaps, the ideal platform would combine seven integrated layers:

### Layer 1 — The Chain: Compliance-Native but EVM-Compatible

A purpose-built L1 (like Polymesh) but with EVM compatibility or a WASM VM alongside its native compliance engine — so Solidity developers and the broader DeFi toolchain can plug in without rewriting everything. Think Polymesh's protocol-level compliance with Avalanche's subnet flexibility or Cosmos's IBC interoperability built in from day one.

### Layer 2 — Identity: Universal, Portable, Cross-Jurisdiction

The identity layer should be portable across jurisdictions and chains — not siloed to one network. A ONCHAINID-style system (like ERC-3643 uses) but with formal regulatory recognition in the US (SEC/FINRA), EU (MiCA/MiFID II), UK (FCA), Singapore (MAS), and UAE (DFSA) simultaneously. Real-time identity updates should cascade automatically as investor accreditation status changes.

### Layer 3 — Compliance Engine: Rules That Follow the Asset

An AI-assisted dynamic compliance layer that monitors regulatory changes across all covered jurisdictions and proposes rule updates to issuers automatically, rather than waiting for them to notice and manually amend. Rules embedded in assets should be updatable without reissuance.

### Layer 4 — Settlement: Atomic, Multi-Asset, CBDC-Ready

Native Delivery-vs-Payment (DvP) settlement where cash leg and securities leg settle atomically and simultaneously. The cash leg should support multiple settlement rails: stablecoins (USDC, EURC), tokenised bank deposits, and CBDC connections as central banks roll those out. Canada's Project Samara in March 2026 demonstrated bond issuance with payments settled in wholesale central bank deposits — that CBDC integration is where institutional settlement is heading.

### Layer 5 — Liquidity: Native Secondary Market, Not Borrowed

A native regulated ATS or MTF embedded in the protocol — not a partnership dependency — so primary issuance connects directly to a compliant secondary market with built-in market-making incentives. Fractional secondary trading should be possible on day one of any issuance.

### Layer 6 — Privacy: Selective Disclosure at Production Grade

ZK-proof-based confidential transactions live at mainnet from launch, with granular disclosure control: regulators can see everything, counterparties see only what's needed for the trade, the market sees nothing sensitive. The key design insight: institutions face an uncomfortable binary between full public blockchain transparency and fully private permissioned chains. ZK solves that binary.

### Layer 7 — Licensing: The Platform Itself Is the Regulated Entity

The single biggest structural leap beyond what exists today. Rather than being a technology provider relying on third-party broker-dealers and transfer agents, a fully integrated platform would hold its own:
- Broker-dealer license (US)
- Investment firm license (EU)
- MTF authorisation (UK)
- CMS license (Singapore)

Operating as the regulated counterparty across jurisdictions, not just the rails underneath. Securitize is closest to this today with its US and EU licenses, but no one has it across all major financial jurisdictions simultaneously.

### Ideal Platform vs Polymesh Today

| Capability | Polymesh Today | Ideal Platform |
|---|---|---|
| Compliance at protocol layer | ✅ | ✅ + AI-assisted updates |
| Native chain | ✅ | ✅ + EVM compatible |
| Identity | ✅ On-chain | ✅ + Cross-jurisdictional portability |
| Settlement finality | ✅ Near-instant | ✅ + DvP + CBDC rails |
| Secondary market liquidity | ❌ Partner-dependent | ✅ Native ATS/MTF |
| Privacy/Confidentiality | 🟡 DevNet only | ✅ ZK at mainnet |
| Regulated entity status | ❌ Technology only | ✅ Multi-jurisdiction licensed |
| Developer ecosystem | ❌ Substrate/SDK only | ✅ EVM + native SDK |
| Geographic coverage | 🟡 NA + Europe + Korea | ✅ US, EU, UK, SG, UAE, JP |
| Fee currency stability | ❌ POLYX volatile | ✅ Stablecoin or fiat fees |

---

## 7. P2P Networking & Consensus Architecture

### 7.1 Polymesh — Substrate/libp2p/GRANDPA+BABE Stack

#### The P2P Foundation: libp2p

Polymesh is built on the Substrate framework, which builds on libp2p — a modular networking stack that handles everything below the consensus layer.

**Transport Layer:**
- TCP as the mandatory transport (QUIC/UDP optional)
- Yamux or mplex as stream multiplexer — allowing multiple logical streams over a single TCP connection between two nodes

**Peer Discovery:**
- Kademlia DHT (Distributed Hash Table) for finding other nodes
- mDNS for local network discovery

**Message Propagation — GossipSub:**
GossipSub is a scalable and resilient gossip protocol that propagates messages by having peers gossip with a random subset of their neighbours. Peers establish two types of connections:
- **Full-message (mesh) peers:** Transmit entire messages; each node connects to D=6 mesh peers (acceptable range 4–12)
- **Metadata-only peers:** Exchange control messages only (IHAVE, IWANT, GRAFT, PRUNE)

This design balances speed, reliability, resilience, and bandwidth efficiency.

**Security:**
- Noise protocol for encrypted peer connections
- All peer connections are authenticated and encrypted at the transport layer

#### The Two-Layer Consensus Architecture: BABE + GRANDPA

Polymesh runs two consensus protocols simultaneously — one for block *production*, one for block *finality*:

**BABE (Blind Assignment for Blockchain Extension) — Block Production:**
- Slot-based mechanism using a Verifiable Random Function (VRF) for slot allocation
- Each slot, all authorities generate a VRF random number — if below a threshold proportional to their stake weight, they have the right to produce a block
- VRF proof is included in the block header so peers can validate the slot claim
- Time divided into **epochs** (fixed slot windows)
- Occasionally two validators win the same slot, creating temporary forks — this is by design and resolved by GRANDPA

**GRANDPA (GHOST-based Recursive ANcestor Deriving Prefix Agreement) — Finality:**
- Does not author blocks — listens to gossip about blocks produced by BABE and runs as a separate service
- Validators vote on **chains**, not individual blocks — votes apply transitively to all ancestor blocks
- Once two-thirds of GRANDPA authorities vote for a particular block, it is considered final and irreversible
- Reaches agreement on chains rather than blocks, greatly speeding up finalization — multiple blocks can be finalized in a single round

#### How a Polymesh Transaction Flows

```
1. SUBMISSION
   User submits signed transaction via RPC to any node's transaction pool

2. IDENTITY CHECK (Polymesh-specific)
   Protocol verifies on-chain identity — compliance gate at protocol layer,
   not a smart contract overlay

3. MEMPOOL GOSSIP
   Node validates transaction format and fee, gossips via libp2p GossipSub
   to mesh peers who forward it onward — propagating across the network
   within milliseconds

4. BLOCK AUTHORING
   BABE-selected validator for that slot bundles transactions into a block
   with a VRF proof header and broadcasts it via libp2p

5. BLOCK GOSSIP
   Block propagates through the GossipSub mesh — peers validate VRF proof
   before forwarding

6. GRANDPA VOTING
   Validators exchange pre-vote and pre-commit messages across two voting
   rounds via libp2p gossip. ⅔ supermajority → block finalized

7. ATOMIC SETTLEMENT
   Native settlement engine confirms the transfer only once both legs of a
   DvP transaction are signed — the two-way affirmation model prevents
   unwanted airdrops
```

---

### 7.2 Canton Network — Proof-of-Stakeholder Architecture

#### The Core Principle: Subgroup Consensus

Canton employs "Proof-of-Stakeholder" consensus — in each transaction, only the validators involved in the transaction (the stakeholders to that leg) are able to and responsible for validating it. There is **no global broadcast** of transaction data.

**Transaction Flow:**

```
1. INITIATION
   A party on a participant node initiates a transaction by exercising a
   choice on a DAML contract

2. STAKEHOLDER DEFINITION
   The DAML template's signatories and observers implicitly define the
   transaction's stakeholders — the only parties involved in validation

3. ENCRYPTION & SUBMISSION
   The initiating node encrypts the transaction details for the defined
   stakeholder set and submits the encrypted payload to a mutually
   agreed-upon sync domain

4. SEQUENCING
   The sync domain sequences the transaction and broadcasts it to
   participant nodes of all stakeholders ONLY

5. VALIDATION
   Each stakeholder's participant node decrypts it and independently
   validates it against its local view of the ledger
```

#### The Sync Domain: Ordering Without Validation

The Canton synchronizer provides a **routing and ordering service** for messages passing between validators — it is not responsible for validating transactions itself. All messages within a sync domain are exchanged over the sequencer, which ensures total order between all messages.

**Three-Layer Network Topology:**

| Layer | Role |
|---|---|
| Participant Nodes | Where parties and DAML contracts live; expose APIs to users |
| Sync Domain (Sequencer + Mediator + Topology Manager) | Ordering and coordination layer |
| Super-Validators | Global Synchronizer; enable cross-domain atomic settlement |

**Key Scalability Advantage:** Canton decouples transaction validation from transaction ordering. In traditional blockchains, all validators must validate all transactions — throughput is limited by the slowest validator. Canton's stakeholder-scoped validation eliminates this bottleneck.

---

### 7.3 Hyperledger Fabric — Three-Phase Separation Architecture

#### The Unique Structural Choice: Execute-Order-Validate

Fabric separates transaction processing into three distinct phases:

```
Phase 1: ENDORSEMENT (Execute)
  Client sends transaction proposal to endorsing peers
  Each endorsing peer executes the chaincode and signs the result
  Client collects signed endorsements from required organisations

Phase 2: ORDERING
  Client submits endorsed transaction to ordering service (Raft cluster)
  Ordering service sequences transactions into blocks
  Blocks are broadcast to all channel peers

Phase 3: VALIDATION & COMMIT
  Each peer independently validates each transaction:
    - Correct endorsements per policy
    - No double-spend (MVCC check)
  Valid transactions committed to ledger
  Invalid transactions marked (not reverted — immutably recorded)
```

#### P2P Gossip in Fabric

Fabric implements gossip for scalable, reliable ledger data dissemination. Gossip messaging is continuous — each peer on a channel is constantly receiving current and consistent ledger data from multiple peers.

Not every peer needs to connect directly to an orderer — peers can cascade blocks to other peers using gossip, though direct connection to the ordering service is recommended for performance.

#### The Ordering Service

Unlike Polymesh where ordering is distributed among validators via BABE, Fabric centralises ordering in a dedicated Raft cluster which then **pushes** blocks out to peers. Gossip is used for secondary distribution and peer catch-up, not as the primary ordering mechanism.

---

### 7.4 Architectural Comparison

| Dimension | Polymesh (Substrate) | Canton Network | Hyperledger Fabric |
|---|---|---|---|
| **P2P Stack** | libp2p (GossipSub) | Custom sync domain messaging | Custom gossip protocol |
| **Transaction Broadcast** | Flood via gossip mesh | Encrypted, stakeholder-scoped only | Three-phase: endorse → order → validate |
| **Consensus Type** | BABE (production) + GRANDPA (finality) | Proof-of-Stakeholder (subgroup BFT) | Raft/BFT in orderer cluster |
| **Finality** | Deterministic, ~6 seconds | Immediate per sync domain sequencing | Block-by-block per orderer |
| **Data Visibility** | All validators see all transactions | Only stakeholders see transaction data | Channel-scoped visibility |
| **Privacy Model** | ZK-proofs (Confidential Assets, 2026) | Encryption at P2P layer natively | Private data collections |
| **Node Entry** | Licensed financial entities only | Permissioned validator set | MSP certificate-based |
| **Scalability Limit** | Validator set size (62 nodes today) | Horizontal (stakeholder subgroups) | Orderer cluster throughput |

### 7.5 The Core Trade-offs

**Polymesh — Broadcast-then-Filter:**
Transactions propagate broadly across the libp2p gossip mesh and compliance rules filter what's valid. Simpler to implement, easier to audit, but every node sees every transaction's metadata (until Confidential Assets reaches mainnet).

**Canton — Encrypt-then-Route:**
Only the parties relevant to a transaction ever receive it. Architecturally superior for institutional privacy but introduces the sync domain as a potential coordination bottleneck and requires a more complex trust model.

**Fabric — Role-Segregation:**
Specialist nodes (endorsers, orderers, committers) each do a single job. Maximises throughput for high-volume known workflows but introduces tight coupling between the ordering service and overall network health.

---

## Outlook

The convergence of platform technology, regulatory clarity, and DLT is accelerating a structural shift:

- **Access is widening** — from institutions-only to accredited retail, and eventually broader audiences via tokenised fractions
- **Liquidity is improving** — secondary markets for private assets are deepening, a historically intractable problem
- **Settlement is compressing** — from T+2 days to near-instant via blockchain rails
- **Intermediary layers are thinning** — smart contracts automate what lawyers, transfer agents, and custodians previously handled manually
- **The P2P layer is the battlefield** — the architecture underneath each platform will determine which can scale to institutional volumes without compromising compliance and privacy

The next stage of evolution across all these networks centres on collateral mobility, cross-chain margining, and the unification of liquidity across execution environments. The winners will be those that can deliver seamless collateral portability, low-latency settlement, and deep liquidity without sacrificing trust minimisation.

The key near-term risk is regulatory fragmentation — EU tokenisation companies have warned that structural inertia in European regulation could delay effective application until at least 2030, creating a critical strategic vulnerability as global liquidity won't wait.

---

*Research compiled from publicly available sources including Polymath/Polymesh publications, Parity Technologies documentation, Digital Asset/Canton Network technical primers, Hyperledger Foundation documentation, and market data providers. Current as of May 2026.*
