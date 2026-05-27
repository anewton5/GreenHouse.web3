# P2P Networking & Consensus Algorithm
## Architecture Reference and Implementation Review Checklist
### DLT Private Placements Platform — May 2026

---

> **Purpose of this document:** Two things simultaneously. First, a reference architecture describing how P2P networking and dBFT consensus should be designed for a regulated, permissioned DLT private placements platform. Second, a structured implementation review checklist — work through every section against your existing codebase to identify gaps, misconfigurations, or areas requiring hardening before regulatory submission and production launch.
>
> Sections marked **[CHECKLIST]** contain specific items to verify in your implementation. Mark each ✅ (implemented correctly), ⚠️ (partially implemented or needs review), or ❌ (not implemented / incorrect).

---

## Table of Contents

1. [Is P2P Required? The Fundamental Question](#1-is-p2p-required)
2. [Permissioned vs Open P2P — The Critical Distinction](#2-permissioned-vs-open-p2p)
3. [Four-Layer Platform Architecture](#3-four-layer-platform-architecture)
4. [Layer 1 — The Permissioned P2P Network](#4-layer-1--the-permissioned-p2p-network)
5. [Node Types and Topology](#5-node-types-and-topology)
6. [P2P Protocol Implementation](#6-p2p-protocol-implementation)
7. [P2P Implementation Review Checklist](#7-p2p-implementation-review-checklist)
8. [dBFT Consensus — Architecture Reference](#8-dbft-consensus--architecture-reference)
9. [dBFT Implementation Review Checklist](#9-dbft-implementation-review-checklist)
10. [Security Hardening Checklist](#10-security-hardening-checklist)
11. [DORA Resilience Checklist](#11-dora-resilience-checklist)
12. [Regulatory Documentation Checklist](#12-regulatory-documentation-checklist)
13. [Integration Points — Pontes and External Systems](#13-integration-points--pontes-and-external-systems)
14. [Known Attack Vectors and Mitigations](#14-known-attack-vectors-and-mitigations)

---

## 1. Is P2P Required?

Yes — P2P networking is required, and it is required specifically because of the dBFT consensus mechanism. dBFT validators must exchange messages directly with each other across multiple rounds to reach agreement. This cannot be achieved with a pure client-server model, which would:

- Create a single point of failure (violating DORA resilience requirements)
- Destroy Byzantine fault tolerance (a central server can be compromised or fail)
- Introduce latency that makes consensus impractical at scale

However, the critical understanding is that **"P2P" on a regulated permissioned platform is architecturally and behaviourally different from public blockchain P2P.** Public blockchains (Bitcoin, Ethereum) use open gossip protocols where any node on the internet can connect. Your regulatory obligations make this impossible and illegal.

The DLT Pilot Regime (Regulation EU 2022/858), DORA (Regulation EU 2022/2554), and your AML obligations collectively require that you know the identity of every node, control who can join the network, and maintain documented contracts with every node operator. This produces a **permissioned P2P network** — structurally peer-to-peer, but access-controlled, authenticated, and fully governed.

---

## 2. Permissioned vs Open P2P — The Critical Distinction

| Property | Open P2P (Bitcoin/Ethereum) | Your Permissioned P2P |
|---|---|---|
| Node discovery | Open — any node on the internet | Permissioned — static approved peer list only |
| Identity | Pseudonymous cryptographic address | Fully identified, KYC'd, fit-and-proper assessed |
| Who can join | Anyone with internet access | Explicitly approved entities only |
| Governance of additions | None — open protocol | Documented admission procedure, NCA-notifiable for material changes |
| Message authentication | Cryptographic signature | Cryptographic signature + identity binding to legal entity |
| Network topology | Dynamic, constantly changing | Static or slowly changing, fully documented |
| Regulatory classification | Not applicable | Every node operator = ICT third-party provider under DORA |
| Sybil resistance | Proof of Work / Proof of Stake | Admission control — only approved nodes receive valid certificates |
| Network visibility | Public | Disclosed to NCA; commercially confidential |

**Regulatory consequence of getting this wrong:** If your P2P layer allows unapproved nodes to connect, you are operating an uncontrolled network — a material deficiency that will cause your DLT TSS application to fail. The NCA must be able to see a closed, governed network with a documented peer set.

---

## 3. Four-Layer Platform Architecture

Your platform separates into four layers. P2P operates entirely in Layer 1. Understanding the boundary between layers is important for both security and regulatory clarity.

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 4 — CLIENT INTERFACE                                      │
│                                                                  │
│  · REST APIs for investor/issuer portal                          │
│  · WebSocket for real-time order book and settlement updates     │
│  · Pontes EII Adapter (REST calls to ECB's Extended             │
│    Interoperability Interface for central bank settlement)       │
│  · KYC provider webhooks (Sumsub/Onfido callbacks)              │
│  · Admin portal and reporting interfaces                         │
│                                                                  │
│  Architecture: pure client-server / API — NO P2P at this layer  │
│  Security boundary: TLS 1.3, API key / OAuth2, rate limiting    │
└─────────────────────────────┬───────────────────────────────────┘
                              │ Authenticated API calls
┌─────────────────────────────▼───────────────────────────────────┐
│  LAYER 3 — APPLICATION / SMART CONTRACT                          │
│                                                                  │
│  · Token Registry — tokenised shares, ISIN mapping,             │
│    transfer restrictions, holder count tracking                  │
│  · Compliance Engine — KYC status registry, investor            │
│    categorisation, jurisdiction restrictions, transfer locks     │
│  · DvP Settlement Module — atomic delivery vs payment,          │
│    Pontes cash token integration, escrow and revert logic        │
│  · Corporate Actions — dividend distribution, voting rights,     │
│    capital events (splits, consolidations, rights issues)        │
│  · Regulatory Reporting — immutable transaction log,            │
│    position snapshots, ESMA reporting format generation          │
│                                                                  │
│  Architecture: smart contracts / chaincode executed ON the       │
│  blockchain; state is verified by consensus before commitment    │
│  Security boundary: smart contract audit, formal verification    │
└─────────────────────────────┬───────────────────────────────────┘
                              │ Block production / state transitions
┌─────────────────────────────▼───────────────────────────────────┐
│  LAYER 2 — CONSENSUS (dBFT)                                      │
│                                                                  │
│  · Speaker (primary) selection — deterministic, round-robin     │
│    or stake-weighted                                             │
│  · Block proposal message (Speaker → all Delegates)             │
│  · Prepare phase — delegates validate and broadcast PrepareReq  │
│  · Commit phase — delegates broadcast Commit messages           │
│  · Block finalisation — ≥2/3 commits received, block added      │
│  · View change — fallback if Speaker fails or is Byzantine      │
│                                                                  │
│  THIS IS WHERE P2P IS CRITICAL — consensus nodes must maintain  │
│  direct authenticated connections to all other consensus nodes   │
│  Settlement finality is achieved at block confirmation          │
└─────────────────────────────┬───────────────────────────────────┘
                              │ Authenticated encrypted peer connections
┌─────────────────────────────▼───────────────────────────────────┐
│  LAYER 1 — PERMISSIONED P2P NETWORK                              │
│                                                                  │
│  · Transport: TLS 1.3 with mutual certificate authentication     │
│  · Peer identity: cryptographic public key / X.509 certificate  │
│  · Peer discovery: DISABLED (static approved peer list only)    │
│  · Consensus sub-network: full mesh between all delegate nodes  │
│  · General sub-network: gossip for transaction / block propagation│
│  · Admission control: certificate validation at handshake stage  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Layer 1 — The Permissioned P2P Network

### 4.1 Two Sub-Networks Within Layer 1

Your P2P layer contains two structurally different sub-networks that serve different purposes:

#### Sub-network A — Consensus Node Full Mesh

dBFT delegates must all communicate directly with each other. This is a **full mesh topology** — every consensus node maintains a persistent, authenticated connection to every other consensus node.

**Why full mesh is required for consensus:**
- dBFT requires every delegate to receive messages from every other delegate within each consensus round
- Routing consensus messages through intermediate nodes introduces uncertainty about message provenance and timing
- Byzantine fault tolerance requires direct knowledge of which nodes are responding — intermediary routing obscures this
- A single missed message from one delegate can stall a consensus round

For N consensus nodes, the number of direct connections is N(N-1)/2:

| Consensus Nodes (N) | Connections | Byzantine Tolerance | Minimum honest nodes |
|---|---|---|---|
| 4 | 6 | 1 | 3 |
| 7 | 21 | 2 | 5 |
| 10 | 45 | 3 | 7 |
| 13 | 78 | 4 | 9 |
| 21 | 210 | 6 | 15 |

**Recommended starting configuration:** 4 consensus nodes (tolerates 1 failure). Expand to 7 as institutional node operators join. All connections are persistent, long-running TCP sessions over TLS 1.3 that reconnect automatically on failure.

#### Sub-network B — General Node Gossip Network

Full nodes (non-consensus) propagate transactions and blocks via a **gossip protocol**. They do not need connections to every other node — each full node maintains connections to a subset of approved peers (typically 4–8).

On your permissioned network, gossip uses a **static peer list** — each node has a configured list of approved peer IDs or certificate fingerprints it is allowed to connect to. Dynamic peer discovery is disabled entirely. This maintains the permissioned property: a node cannot discover or connect to unapproved peers.

### 4.2 Message Flow Through the P2P Layer

```
CLIENT SUBMITS TRANSACTION
         │
         ▼
API Gateway Node (Layer 4)
· Validates format and signature
· Checks nonce / replay protection
· Injects into P2P network
         │
         ▼ gossip propagation
Full Nodes relay transaction
         │
         ▼ direct connection
Consensus Nodes (all delegates receive transaction)
         │
         ▼ dBFT consensus rounds
Block proposed → Prepared → Committed → Finalised
         │
         ▼ gossip propagation
Full Nodes receive and validate new block
         │
         ▼
API Gateway Nodes detect new block via subscription
         │
         ▼
WebSocket push to connected clients
Settlement confirmed, Pontes EII Adapter notified
```

---

## 5. Node Types and Topology

### 5.1 Node Type Definitions

**Consensus Nodes (Delegates / Validators)**
- Participate in dBFT consensus rounds
- Propose and vote on blocks
- Maintain full mesh connections to all other consensus nodes
- Operated by: your platform initially; regulated institutional participants as the network grows
- Hardware: dedicated servers or bare-metal cloud instances; HSM or secure enclave for signing keys
- DORA classification: critical — highest resilience requirements (RTO < 4 hours)
- Regulatory requirement: node operators must pass fit-and-proper assessment; DORA-compliant contracts required

**Full Nodes (Observer / Relay)**
- Store full blockchain history
- Validate all transactions and blocks independently
- Relay transactions and blocks via gossip
- Serve as connection targets for API gateway nodes
- Do not participate in consensus
- Operated by: your platform, regulated participants (banks, CSDs), potentially large issuers

**API Gateway Nodes**
- Bridge Layer 4 (client interface) to Layer 1 (P2P network)
- Receive REST/WebSocket requests from external clients
- Validate and inject transactions into the P2P network
- Subscribe to new blocks and push updates to connected clients
- Are NOT peers in the consensus network — they connect to full nodes only
- Horizontally scalable — run multiple behind a load balancer

**Light Clients (Optional)**
- Browser-based or mobile connections from end investors
- Never connect directly to the P2P network
- Connect only to API gateway nodes via HTTPS/WebSocket
- Verify transaction inclusion via Merkle proofs if required

### 5.2 Network Topology Diagram

```
                    ┌─────────────────────────────┐
                    │   CONSENSUS NODE FULL MESH   │
                    │                             │
                    │  [CN1]───────────[CN2]      │
                    │    │  ╲         ╱  │         │
                    │    │    ╲     ╱    │         │
                    │    │      [CN3]    │         │
                    │    │    ╱     ╲    │         │
                    │    │  ╱         ╲  │         │
                    │  [CN4]───────────╌──         │
                    │                             │
                    │  Each line = persistent     │
                    │  TLS 1.3 mutual-auth conn   │
                    └──────────┬──────────────────┘
                               │ gossip
              ┌────────────────┼────────────────┐
              │                │                │
           [FN1]            [FN2]            [FN3]
       Full Node         Full Node        Full Node
              │                │                │
              └────────┬───────┘                │
                       │                        │
                  [GW1]│                    [GW2]│
              API Gateway                API Gateway
              (Load Balanced)            (Load Balanced)
                    │                        │
            ┌───────┴──────┐        ┌───────┴──────┐
         REST/WS         REST/WS  REST/WS        REST/WS
            │                │        │                │
        [Investor]      [Issuer]  [Bank Node]   [Admin Portal]
         Portal          Portal
```

---

## 6. P2P Protocol Implementation

### 6.1 Protocol Options

**Option 1 — libp2p (Recommended)**

libp2p is the modular P2P networking library used by Ethereum 2.0, IPFS, Polkadot, and Filecoin. Available in Go, Rust, JavaScript, Python, and Java.

Relevant modules for your implementation:

| libp2p Module | Purpose | Your Configuration |
|---|---|---|
| `transport/tcp` | TCP transport | Enabled |
| `security/noise` or `security/tls` | Authenticated encryption | TLS 1.3 preferred for regulatory familiarity |
| `muxer/yamux` | Stream multiplexing | Enabled — allows multiple logical streams per connection |
| `discovery/mdns` | Local network discovery | **DISABLED** — permissioned network only |
| `discovery/dht` (Kademlia) | Distributed peer discovery | **DISABLED** — permissioned network only |
| `pubsub/gossipsub` | Gossip message propagation | Enabled for transaction and block propagation |
| `peerstore` | Peer identity and address management | Configured with static approved peer list |
| `connmgr` | Connection limits and lifecycle | Configured with max peers = approved peer list size |

Critical permissioned configuration:

```go
// Pseudocode — adapt to your implementation language

// 1. Static peer list — load approved peers from config
approvedPeers := loadApprovedPeerList("peers.json")
// peers.json contains: [{peerID: "12D3K...", addr: "/ip4/x.x.x.x/tcp/9000", cert: "..."}]

// 2. Connection gating — reject unapproved peers at handshake
type PermissionedGater struct {
    approvedPeers map[peer.ID]bool
}

func (g *PermissionedGater) InterceptPeerDial(p peer.ID) bool {
    return g.approvedPeers[p]  // reject if not in approved list
}

func (g *PermissionedGater) InterceptSecured(dir network.Direction, p peer.ID, conn network.ConnMultiaddrs) bool {
    return g.approvedPeers[p]  // reject after handshake if not approved
}

// 3. Build host with gater
host, _ := libp2p.New(
    libp2p.Transport(tcp.NewTCPTransport),
    libp2p.Security(tls.ID, tls.New),  // TLS 1.3
    libp2p.Muxer(yamux.ID, yamux.DefaultTransport),
    libp2p.ConnectionGater(&PermissionedGater{approvedPeers}),
    libp2p.DisableRelay(),              // no circuit relays
    libp2p.NoListenAddrs,               // explicit listen address only
)
```

**Option 2 — Custom TLS Mesh**

Build peer connections directly over TLS 1.3 sockets with X.509 mutual authentication. Each node has a certificate issued by your internal Certificate Authority (CA). Only certificates signed by your CA are accepted.

Advantages: simpler to explain to regulators (TLS and X.509 are universally understood), no external library dependency.
Disadvantages: you rebuild a lot of libp2p's functionality (reconnection, multiplexing, message framing, backpressure) from scratch.

**Option 3 — Existing DLT Framework P2P**

If your dBFT runs on an existing framework (Neo, CometBFT/Tendermint, Hyperledger Besu, or similar), use that framework's built-in P2P layer with permissioning enabled.

- **Neo:** Built-in P2P with seed nodes — configure seed nodes to be your approved consensus nodes only; disable open peer discovery
- **CometBFT:** `persistent_peers` configuration and `private_peer_ids` to restrict peer connections
- **Hyperledger Fabric:** Channel membership service (MSP) enforces permissioned peer identity natively

### 6.2 Gossip Protocol Configuration

For transaction and block propagation between full nodes:

**GossipSub parameters (if using libp2p GossipSub):**

| Parameter | Recommended Value | Purpose |
|---|---|---|
| `D` (degree) | 6 | Target peer count per topic |
| `Dlo` | 4 | Low watermark — connect more peers if below |
| `Dhi` | 12 | High watermark — prune peers if above |
| `HeartbeatInterval` | 700ms | Gossip heartbeat frequency |
| `HistoryLength` | 5 | Gossip history windows to maintain |
| `HistoryGossip` | 3 | History windows to include in gossip |
| `SeenMessagesTTL` | 2 minutes | Duplicate message detection window |

**Topics to define:**

```
/platform/mainnet/tx/1.0.0         — new transaction announcements
/platform/mainnet/block/1.0.0      — new block announcements  
/platform/mainnet/consensus/1.0.0  — consensus messages (delegates only)
/platform/mainnet/status/1.0.0     — node health/status broadcasts
```

Restrict the `/consensus/` topic to consensus node peer IDs only — full nodes should not subscribe to or receive raw consensus messages.

---

## 7. P2P Implementation Review Checklist

Work through every item below against your current implementation. The goal is to identify any gaps before your NCA regulatory submission and before onboarding real participants.

---

### 7.1 Peer Discovery and Admission Control

- [ ] **No open peer discovery:** Confirm that mDNS, Kademlia DHT, or any other automatic peer discovery mechanism is completely disabled. A new node should never be able to connect to the network unless its identity is in the approved peer list.
- [ ] **Static approved peer list:** Is there a managed list of approved peer IDs (or certificate fingerprints)? Is it stored in version-controlled configuration, not hardcoded in source?
- [ ] **Peer ID binding to legal entity:** Is each peer ID or certificate uniquely associated with a known legal entity (company name, registration number)? Can you produce this mapping for an NCA?
- [ ] **Admission procedure documented:** Is there a written procedure describing how a new node is approved, what criteria it must meet, and who has authority to add it to the approved list?
- [ ] **Removal procedure documented:** Can you remove a node from the network immediately if its operator is compromised, sanctioned, or loses regulatory approval? Is removal tested?
- [ ] **Connection gating at handshake:** Is peer identity verified cryptographically at the TLS/Noise handshake stage, before any application data is exchanged? Connections from unapproved peers should be rejected at the transport layer, not the application layer.
- [ ] **No circuit relays or proxy connections:** Confirm there are no relay mechanisms (libp2p circuit relay, TURN servers, SOCKS proxies) that would allow a non-approved node to appear as an approved one.
- [ ] **Peer list change governance:** Is there a change management procedure for modifying the approved peer list? Is it logged with timestamp, reason, and authoriser?

---

### 7.2 Transport Security

- [ ] **TLS version:** Confirm TLS 1.3 is the minimum version. TLS 1.2 should be disabled. TLS 1.0 and 1.1 must not be negotiable under any circumstances.
- [ ] **Cipher suites:** Only allow AEAD cipher suites. Recommended: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`. Disable: RC4, 3DES, all NULL cipher suites, all export-grade suites.
- [ ] **Mutual TLS (mTLS):** Is mutual authentication enforced? Both sides must present and verify certificates — not just the server presenting to the client (one-way TLS is insufficient for a P2P node network).
- [ ] **Certificate validation:** Are certificate chain validation, expiry checking, and revocation checking (CRL or OCSP) all performed on every connection? Test what happens when an expired or revoked certificate connects.
- [ ] **Certificate Authority:** Is there a dedicated internal CA for issuing node certificates? Is the CA private key stored in an HSM or equivalent secure storage? Who has authority to issue new certificates?
- [ ] **Certificate rotation:** Is there a procedure for rotating node certificates before expiry? What is the rotation period? Is it automated or manual?
- [ ] **Perfect Forward Secrecy:** Confirm all cipher suites provide PFS (ephemeral key exchange — ECDHE). Static RSA key exchange must not be used.
- [ ] **Certificate pinning (optional but recommended):** Do nodes pin the expected certificate fingerprint of their configured peers, in addition to standard chain validation? This prevents a compromised CA from issuing fraudulent certificates for peer nodes.

---

### 7.3 Network Topology

- [ ] **Consensus node full mesh:** Do all consensus nodes maintain persistent direct connections to all other consensus nodes? Test this by checking the active connection list on each node — it should show N-1 connections where N is the total number of consensus nodes.
- [ ] **Connection persistence and reconnection:** Do consensus node connections automatically reconnect within a defined timeout after a network interruption? What is the reconnection backoff policy? Is there a maximum retry limit or does it retry indefinitely?
- [ ] **Full node peer count:** Do full nodes maintain the configured number of approved peer connections (recommend 4–8)? Is there a minimum peer count below which the node raises an alert?
- [ ] **API gateway isolation:** Are API gateway nodes connecting only to full nodes, never directly to consensus nodes? Consensus nodes should not accept connections from untrusted API-facing infrastructure.
- [ ] **Network segmentation:** Are consensus nodes on a separate network segment (VPC, VLAN, or security group) from API gateway nodes? Can an attacker who compromises an API gateway node directly reach a consensus node at the network layer?
- [ ] **Topology documentation:** Is there an up-to-date network topology diagram that reflects the current production configuration? Is it version-controlled and dated?

---

### 7.4 Message Handling and Propagation

- [ ] **Transaction validation before propagation:** Do nodes validate the basic structure, signature, and format of a transaction before gossiping it to peers? Propagating invalid transactions wastes bandwidth and creates DoS risk.
- [ ] **Duplicate message detection:** Is there a mechanism to detect and discard duplicate messages (same transaction or block received from multiple peers)? Without this, gossip can amplify and flood the network.
- [ ] **Message size limits:** Is there a maximum message size enforced at the P2P layer? Oversized messages can be used for DoS attacks. Recommended: reject any message above your defined maximum block size.
- [ ] **Rate limiting per peer:** Is there a rate limit on messages received per peer per time window? A malicious or malfunctioning node should not be able to flood the network.
- [ ] **Mempool limits:** Is there a maximum mempool size? When the mempool is full, what happens to new incoming transactions — dropped, queued, or rejected with an error?
- [ ] **Transaction replay protection:** Does each transaction include a nonce or equivalent mechanism preventing replay attacks (resubmitting a valid past transaction)?
- [ ] **Block propagation timing:** After a block is finalised, how long does it take to reach all full nodes? Measure this in your test environment and document it.

---

### 7.5 Node Identity and Key Management

- [ ] **Unique identity per node:** Does each node have a unique cryptographic identity (public/private keypair) that is stable across restarts? Node identity should not change unless explicitly rotated.
- [ ] **Private key storage:** Is the node's private key stored securely? For consensus nodes, an HSM (FIPS 140-2 Level 3 or higher) or equivalent secure enclave should be used. For full nodes, at minimum encrypted key storage with access controls.
- [ ] **Key backup and recovery:** Is there a secure backup of node private keys? What is the recovery procedure if a node's key is lost? Is the backup tested?
- [ ] **Key rotation procedure:** Is there a documented procedure for rotating a node's keypair? Does key rotation require updating the approved peer list? Is this tested?
- [ ] **Separation of node identity and consensus signing key:** For consensus nodes, the P2P identity key (used for peer authentication) should ideally be separate from the consensus signing key (used to sign blocks and votes). Compromise of one should not compromise the other.

---

### 7.6 Logging, Monitoring, and Alerting

- [ ] **Peer connection events logged:** Every peer connection and disconnection is logged with timestamp, peer ID, direction (inbound/outbound), and reason for disconnection.
- [ ] **Rejected connection attempts logged:** Failed connection attempts (from unapproved peers or with invalid certificates) are logged with the presented identity if available. These are potential intrusion attempts.
- [ ] **Message rate anomaly detection:** Is there monitoring that alerts when any peer is sending messages at an abnormal rate?
- [ ] **Peer count monitoring:** Is there an alert when any node's active peer count drops below the minimum threshold? A consensus node losing peers could impair consensus.
- [ ] **Network partition detection:** Is there a mechanism to detect if the consensus node set has been partitioned (i.e., some consensus nodes cannot reach others)?
- [ ] **Structured log format:** Are P2P logs in a structured format (JSON) suitable for ingestion into a SIEM? DORA requires security event monitoring with audit trails.
- [ ] **Log retention:** Are P2P logs retained for the period required by regulation (minimum 5 years for financial records; check your NCA's specific requirements)?

---

## 8. dBFT Consensus — Architecture Reference

### 8.1 What dBFT Is

Delegated Byzantine Fault Tolerant (dBFT) consensus is a Practical Byzantine Fault Tolerant (pBFT) variant in which a subset of nodes (delegates or validators) participates in consensus on behalf of the wider network. It achieves:

- **Immediate finality:** Transactions are final the moment a block is committed — there are no forks and no probabilistic finality. This is critical for settlement finality under Directive 98/26/EC.
- **High throughput:** No mining or staking computation — consensus is pure message passing.
- **Deterministic liveness:** Under normal conditions (< f Byzantine nodes), consensus completes in a bounded number of message rounds.
- **Byzantine tolerance:** The network continues to reach correct consensus as long as fewer than ⌊(N-1)/3⌋ delegates are Byzantine (malicious or faulty).

### 8.2 The Consensus Rounds — Detailed Flow

```
ROUND START
│
├─ Speaker Selection
│  · Deterministic: speaker = delegates[block_height % N]
│  · Or: stake-weighted selection
│  · All delegates know who the current speaker is without communication
│
├─ PHASE 1: Block Proposal (Speaker → All Delegates)
│  Speaker collects transactions from mempool
│  Speaker creates block proposal:
│    - Block header (height, previous hash, timestamp, speaker ID)
│    - Transaction list (ordered by priority/fee)
│    - Speaker signature
│  Speaker broadcasts PrepareRequest to all delegates
│
├─ PHASE 2: Prepare (All Delegates → All Delegates)
│  Each delegate receives PrepareRequest
│  Validates: block format, speaker legitimacy, transaction validity
│  If valid: broadcasts PrepareResponse (signed) to all other delegates
│  If invalid: triggers view change (see below)
│
├─ PHASE 3: Commit (All Delegates → All Delegates)
│  Each delegate waits to receive M = ⌈(2N/3)⌉ PrepareResponse messages
│  Once threshold reached: broadcasts Commit message (signed) to all delegates
│  Commit includes: delegate's signature share of the block
│
├─ BLOCK FINALISATION
│  Each delegate waits to receive M = ⌈(2N/3)⌉ Commit messages
│  Once threshold reached: block is final
│  Block added to local chain
│  Block broadcast to full nodes via gossip
│  Settlement finality achieved — irreversible
│
└─ VIEW CHANGE (Fallback)
   Triggered when: timer expires before threshold reached,
   or delegates detect Speaker is Byzantine
   · Delegates broadcast ChangeView message with new view number
   · New Speaker = delegates[(block_height + view_number) % N]
   · Consensus restarts with new Speaker
   · Maximum view changes before block is skipped: configurable
```

### 8.3 Finality and Settlement

dBFT's immediate finality is a **regulatory asset.** Under the EU Settlement Finality Directive (Directive 98/26/EC) and CSDR, settlement finality is a legal concept — a transfer order entered into a settlement system is final and irrevocable from a defined moment. dBFT's single-round finality (once ≥2/3 Commits are received, the block cannot be rolled back) maps cleanly to this legal concept in a way that probabilistic finality (Bitcoin, pre-Merge Ethereum) does not.

Your legal opinion on settlement finality (required for the DLT TSS application) should reference the specific block commitment threshold and the impossibility of fork under dBFT with < f Byzantine nodes.

### 8.4 Byzantine Fault Tolerance Thresholds

| Total Delegates (N) | Max Byzantine (f) | Min Honest Required | Commit Threshold (⌈2N/3⌉) |
|---|---|---|---|
| 4 | 1 | 3 | 3 |
| 7 | 2 | 5 | 5 |
| 10 | 3 | 7 | 7 |
| 13 | 4 | 9 | 9 |
| 21 | 6 | 15 | 14 |

**Recommended minimum for production:** 4 delegates (tolerates 1 Byzantine or failed node). Expand to 7 as institutional node operators join.

### 8.5 View Change — The Liveness Mechanism

If the current Speaker fails to produce a valid block proposal within a timeout period, or if delegates detect that the Speaker is Byzantine (e.g., proposing conflicting blocks to different delegates), dBFT enters a **view change**.

View change is dBFT's liveness guarantee — it ensures the network continues making progress even if the current Speaker is unavailable or malicious.

The view change timeout must be carefully calibrated:
- **Too short:** Network churn and normal latency spikes trigger unnecessary view changes, degrading throughput
- **Too long:** A failed Speaker causes extended settlement delays

Recommended starting values (adjust based on your network latency measurements):
- Initial timeout: 15–30 seconds
- Timeout growth: double on each successive view change (exponential backoff)
- Maximum view changes before logging a critical alert: 3

---

## 9. dBFT Implementation Review Checklist

### 9.1 Consensus Correctness

- [ ] **Byzantine fault threshold correctly implemented:** Verify that the commit threshold is exactly ⌈(2N/3)⌉ where N is the total number of delegates. A threshold that is too low (e.g., simple majority ⌈N/2⌉) breaks Byzantine fault tolerance — a Byzantine minority could force an incorrect block.
- [ ] **Threshold computed dynamically:** If delegates can join or leave (even between consensus rounds), is the threshold recomputed based on the current active delegate count? A stale threshold from an earlier delegate set is a correctness bug.
- [ ] **No double-voting protection:** Does the implementation reject a second PrepareResponse or Commit message from the same delegate in the same round? A Byzantine delegate could try to vote twice.
- [ ] **Block hash in votes:** Do PrepareResponse and Commit messages include the hash of the block being voted on? Without this, votes could be replayed across different block proposals.
- [ ] **Speaker legitimacy check:** Do delegates verify that the PrepareRequest is from the expected Speaker (based on block height and view number)? Proposals from unexpected sources should be rejected.
- [ ] **Transaction validity at proposal time:** Does the Speaker validate every transaction in the proposed block before including it? Does each delegate re-validate all transactions upon receiving the PrepareRequest?
- [ ] **Ordered transaction execution:** Is the order of transactions within a block deterministic and consistent across all nodes? Non-deterministic ordering would cause state divergence.
- [ ] **State root in block header:** Does the block header include the Merkle root of the post-execution state? This allows any node to verify that executing the block's transactions produces the claimed state.
- [ ] **Previous block hash in header:** Does each block include the hash of the previous block, forming the chain? Verify the chain linkage is checked during block validation.

---

### 9.2 View Change Correctness

- [ ] **View change threshold:** Is a view change triggered when ⌈(2N/3)⌉ ChangeView messages with the same new view number are received? The same Byzantine fault threshold should apply.
- [ ] **View number monotonicity:** Can view numbers only increase? A ChangeView message with a lower view number than the current view should be rejected.
- [ ] **New Speaker derivation:** Is the new Speaker deterministically derived as `delegates[(block_height + view_number) % N]`? Verify this is consistent across all nodes.
- [ ] **State reset on view change:** On entering a new view, is the consensus state cleanly reset? Votes from the previous view should not be carried into the new view.
- [ ] **Timeout calibration:** What is the current view change timeout? Has it been measured against actual network latency and found to be appropriate? Document the basis for the chosen value.
- [ ] **Exponential backoff:** Does the timeout increase on successive view changes? Without backoff, a network under stress can thrash between view changes continuously.
- [ ] **Maximum view changes per block:** Is there a limit on how many view changes can occur before a block height is abandoned? What happens when this limit is reached?
- [ ] **View change message forwarding:** If a delegate receives a ChangeView for a view it has not yet reached, does it buffer or discard it? Discarding can cause liveness issues if messages arrive out of order.

---

### 9.3 Timing and Liveness

- [ ] **Block time measurement:** What is the average observed block time in your test network? What is the 99th percentile? Both should be measured and documented.
- [ ] **Consensus timeout vs network latency:** Is the view change timeout at least 5× the observed 99th percentile round-trip time between consensus nodes? If the timeout is shorter than realistic network latency, view changes will trigger incorrectly.
- [ ] **Clock synchronisation:** Are all consensus nodes synchronised to an accurate time source (NTP with GPS or similar)? Timestamp-based logic in block headers or timeouts can malfunction with clock skew > a few hundred milliseconds.
- [ ] **Mempool transaction ordering:** Is there a defined priority ordering for transactions in the mempool (e.g., by fee, timestamp, or type)? Is this ordering deterministic — would all delegates independently arrive at the same ordered transaction list?
- [ ] **Empty block policy:** What happens when the mempool is empty? Does the Speaker propose an empty block (maintaining liveness) or wait for transactions (risking timeout)? Document and test this edge case.
- [ ] **Block size limit:** Is there a maximum block size (in transactions or bytes)? What happens when the mempool has more transactions than fit in a single block?

---

### 9.4 Delegate Set Management

- [ ] **Delegate set configuration:** How is the current delegate set determined? Is it hardcoded in genesis, governable on-chain, or configured externally? What is the procedure for adding or removing a delegate?
- [ ] **Delegate set change governance:** Is there a documented governance procedure for changing the delegate set? Who has authority to propose changes? How are changes enacted (on-chain vote, off-chain agreement, emergency procedure)?
- [ ] **NCA notification on delegate changes:** Your DLT TSS application will list the delegate set. Material changes to the delegate set may need to be notified to your NCA. Is there a procedure for this?
- [ ] **Delegate set stored on-chain:** Is the current authoritative delegate set recorded on the blockchain itself (not just in configuration files)? On-chain storage makes the delegate set auditable and tamper-evident.
- [ ] **Minimum delegate count enforcement:** Is there a check preventing the delegate count from falling below the minimum required for Byzantine fault tolerance? E.g., prevent removing a delegate that would leave only 3 total (tolerance = 1, which may be insufficient for production).
- [ ] **Delegation and identity binding:** Is each delegate's consensus identity (signing key) cryptographically bound to their network identity (P2P peer ID) and their legal entity identity? All three should be provably linked.

---

### 9.5 Block Structure and Validation

- [ ] **Block header fields:** Verify your block header includes at minimum: block height, timestamp, previous block hash, transactions Merkle root, state root, delegate set hash, Speaker ID and signature.
- [ ] **Signature verification on receipt:** Do all nodes verify the Speaker's signature on a block proposal before processing it? Do all nodes verify delegate signatures on PrepareResponse and Commit messages?
- [ ] **Signature aggregation (optional but recommended):** For efficiency, do Commit messages use signature aggregation (e.g., BLS threshold signatures)? This reduces the data stored per block to prove ≥2/3 agreement.
- [ ] **Block serialisation determinism:** Is block serialisation (the process of converting a block to bytes for hashing) deterministic across all programming language implementations and platforms? Non-deterministic serialisation (e.g., JSON with varying field order) causes hash mismatches.
- [ ] **Genesis block configuration:** Is the genesis block hardcoded and verified on startup? Does it establish the initial delegate set, initial token allocations, and initial compliance engine state?
- [ ] **Block storage and retrieval:** Can any block be retrieved by height and by hash? Is there an index? What is the expected chain growth rate over 5 years, and does your storage architecture accommodate it?

---

### 9.6 Smart Contract / Chaincode Execution

- [ ] **Deterministic execution:** Are smart contract operations deterministic — does executing the same transaction against the same state always produce the same result on every node? Non-determinism (random numbers, current timestamp as primary logic input, floating-point arithmetic) will cause state divergence.
- [ ] **Execution sandboxing:** Are smart contracts executed in a sandboxed environment that prevents access to the underlying OS, filesystem, or network? An unconstrained smart contract is a critical security vulnerability.
- [ ] **Gas / resource limits:** Is there a computational resource limit per transaction (analogous to gas in Ethereum)? Without limits, a single transaction can halt the network by consuming all available CPU.
- [ ] **Re-entrancy protection:** Are your smart contracts protected against re-entrancy attacks? The pattern where Contract A calls Contract B which calls back into Contract A before A's state is settled is a well-known and repeatedly exploited vulnerability.
- [ ] **Integer overflow/underflow:** Are arithmetic operations in smart contracts protected against overflow and underflow? Use safe math libraries or a language with built-in overflow checking.
- [ ] **Access control on privileged functions:** Are administrative functions (minting tokens, modifying the delegate set, pausing the contract) protected by multi-signature requirements and role-based access control?
- [ ] **Upgrade mechanism:** Is there a procedure for upgrading smart contracts? If contracts are immutable (no upgrade mechanism), how are bugs fixed? If upgradeable, is the upgrade mechanism itself secure (multi-sig, timelock)?

---

## 10. Security Hardening Checklist

### 10.1 Cryptographic Implementation

- [ ] **Signature algorithm:** What signature algorithm is used for consensus messages and transactions? Recommended: Ed25519 (EdDSA) for performance, or ECDSA with P-256 (secp256r1) for broader regulatory familiarity. Document and justify your choice.
- [ ] **Hash function:** SHA-256 or SHA-3 (Keccak-256) for block and transaction hashing. No MD5, SHA-1, or non-standard hash functions.
- [ ] **Random number generation:** Is all randomness (key generation, nonces, etc.) sourced from a cryptographically secure random number generator (CSPRNG)? On Linux: `/dev/urandom` or `getrandom()`. Never use `Math.random()` or language-level `rand()`.
- [ ] **No hardcoded secrets:** Confirm that no private keys, API keys, passwords, or other secrets are hardcoded in source code or committed to version control. Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).
- [ ] **Post-quantum readiness plan:** DORA requires future-proofing. Do you have a documented plan for migrating to post-quantum cryptographic algorithms (NIST PQC standards: CRYSTALS-Dilithium for signatures, CRYSTALS-Kyber for key encapsulation) when the timeline becomes clear?

### 10.2 Network-Level Security

- [ ] **DDoS mitigation for API gateway:** API gateway nodes are internet-facing and vulnerable to DDoS. Is there rate limiting, IP reputation filtering, or a DDoS mitigation service (AWS Shield, Cloudflare) in place?
- [ ] **No direct internet exposure of consensus nodes:** Consensus nodes should not have public IP addresses. They should be accessible only within your private network, reachable only by approved full nodes.
- [ ] **Firewall rules:** Are firewall rules tightly scoped? Consensus nodes should only accept inbound connections on the P2P port from the IP addresses of other approved consensus nodes — nothing else.
- [ ] **Port minimisation:** Are all unnecessary ports closed on all node types? Document which ports are open on each node type and why.
- [ ] **Node software versions pinned:** Are the versions of all P2P and consensus software components pinned and verified against known-good checksums? Automatic updates of consensus-critical software without review is a significant risk.

### 10.3 Operational Security

- [ ] **Multi-signature for administrative operations:** Any operation that changes the delegate set, pauses the network, or modifies smart contract logic should require signatures from multiple authorised individuals — no single-person authority over critical operations.
- [ ] **HSM for consensus node signing keys:** Consensus nodes sign blocks and votes with their private key. This key must be stored in an HSM (FIPS 140-2 Level 3 minimum) or equivalent secure enclave. A compromised signing key allows an attacker to impersonate that consensus node and submit Byzantine votes.
- [ ] **Privileged access management (PAM):** All administrative access to consensus node servers is logged, session-recorded, and requires MFA. No shared passwords. DORA mandates this for critical ICT systems.
- [ ] **Dependency audit:** Have all third-party libraries used in the P2P and consensus implementation been audited? Are they from reputable sources? Are they monitored for new CVEs?
- [ ] **External security audit:** Has an independent security firm conducted a code-level audit of the P2P and consensus implementation? This is expected by NCAs reviewing a DLT TSS application. Budget for this during seed stage.

---

## 11. DORA Resilience Checklist

DORA (Regulation EU 2022/2554) applies from the moment you receive regulatory authorisation. These requirements should be designed into the architecture now, not retrofitted later.

### 11.1 ICT Risk Management

- [ ] **RTO defined per node type:** What is the Recovery Time Objective for each node type if it fails? Consensus nodes: recommend RTO < 4 hours. Full nodes: RTO < 24 hours. Document these formally.
- [ ] **RPO defined:** What is the Recovery Point Objective? How much blockchain data could be lost in a worst-case recovery scenario? For a blockchain with immutable history, RPO should be zero — all committed blocks are recoverable from any surviving full node.
- [ ] **Minimum viable consensus set:** What is the minimum number of consensus nodes that must be operational for the network to function? This is your Byzantine fault threshold in practice. Document it.
- [ ] **Node redundancy:** For each consensus node, is there a hot standby or rapid-replacement procedure if the primary fails? The replacement must be able to join consensus within your RTO.
- [ ] **Geographic distribution:** Are consensus nodes distributed across multiple geographic locations (at minimum, multiple availability zones; ideally multiple EU data centres in different cities)? A single data centre failure should not halt consensus.
- [ ] **Cloud provider concentration risk:** If all nodes run on the same cloud provider (e.g., all on AWS), a cloud provider outage is a single point of failure. Consider a multi-cloud or hybrid strategy for consensus nodes.

### 11.2 Incident Classification for Blockchain-Specific Events

DORA requires you to classify ICT incidents and report major ones to your NCA. Define what constitutes a major incident in your DLT context:

- [ ] **Consensus halt:** All consensus has stopped (no new blocks for > X minutes). Classify as major if duration exceeds your SLA.
- [ ] **Network partition:** Consensus node set is partitioned — some nodes cannot reach others. Potential safety risk if the partition persists.
- [ ] **Byzantine node detected:** Evidence that a consensus node is sending conflicting messages (equivocation). Immediate major incident regardless of duration.
- [ ] **Settlement failure:** A transaction that should have settled has not settled within expected timeframe. Major incident if client funds or securities are at risk.
- [ ] **Smart contract exploit:** Any evidence of unexpected state changes not caused by legitimate transactions.
- [ ] **Governance attack:** Unauthorised change to the delegate set or administrative parameters.
- [ ] **Key compromise:** Actual or suspected compromise of any consensus node signing key.

For each incident type above, document: detection mechanism, response procedure, escalation path, NCA reporting trigger (DORA: initial notification within 4 hours of classification as major).

### 11.3 Testing Requirements

- [ ] **Consensus node failure simulation:** Regularly test (at minimum quarterly) that taking one consensus node offline does not halt consensus. The network should continue operating with N-1 delegates.
- [ ] **Byzantine node simulation:** Test that a consensus node sending malformed or conflicting messages does not cause incorrect blocks to be finalised.
- [ ] **Network partition simulation:** Test that a partition of the consensus network (some nodes cannot reach others) is detected and handled correctly (the minority partition should halt rather than produce conflicting blocks).
- [ ] **Full recovery test:** Periodically test the complete recovery procedure: take a consensus node offline, perform recovery from backup, rejoin the network, and verify that the recovered node correctly syncs the missed blocks.
- [ ] **View change testing:** Confirm that view change works correctly by simulating a Speaker failure (kill the Speaker process mid-round). Measure how long consensus resumes and whether any blocks are skipped.

---

## 12. Regulatory Documentation Checklist

For your DLT TSS application, your NCA will review the P2P and consensus implementation. Prepare the following documents:

- [ ] **Network topology diagram:** Every node type, connection types, protocols, who operates each node. Version-controlled, dated, with a change history.
- [ ] **Node operator register:** Legal entity name, registration number, jurisdiction, and fit-and-proper assessment status for every consensus node operator.
- [ ] **Byzantine fault tolerance proof:** Mathematical demonstration that your consensus mechanism tolerates ⌊(N-1)/3⌋ Byzantine nodes. Reference the academic literature (Castro & Liskov 1999 for pBFT; relevant dBFT papers for your specific variant).
- [ ] **Settlement finality legal opinion:** External legal opinion confirming that block commitment under dBFT constitutes legally final and irrevocable settlement under applicable law, mapping to Directive 98/26/EC concepts.
- [ ] **ICT third-party register:** Every node operator is an ICT third-party provider under DORA. Maintain a register with contract references, service descriptions, criticality classification, and last review date.
- [ ] **Cryptographic algorithm justification:** Document why each cryptographic algorithm was chosen, its security level (bit strength), and its compliance with ENISA's current recommendations.
- [ ] **Key management policy:** How consensus signing keys are generated, stored, backed up, rotated, and revoked. Who has access. What happens on compromise.
- [ ] **Change management procedure:** How software updates to P2P or consensus components are tested, approved, and deployed. NCA may need to be notified of material changes.
- [ ] **Incident response plan:** Specific to blockchain/consensus events (see DORA checklist above). Tested at least annually.
- [ ] **Smart contract audit reports:** External audit reports from reputable security firms for all production smart contracts. Findings and remediations documented.

---

## 13. Integration Points — Pontes and External Systems

### 13.1 Pontes EII Integration

The Pontes integration does not extend into the P2P layer — the Extended Interoperability Interface (EII) is a REST API called from your Layer 4 application layer. However, the P2P layer must handle the on-chain consequences of settlement:

```
SETTLEMENT FLOW WITH PONTES:

1. Trade matched on your platform
   → Settlement instruction written to blockchain via P2P/consensus

2. Smart contract (Layer 3) locks security tokens in escrow

3. Pontes EII Adapter (Layer 4) calls ECB EII REST API:
   POST /settlement/initiate
   Body: {tradeId, securityISIN, quantity, buyerDCW, sellerDCW, amount}

4. ECB ESY DLT locks cash tokens in buyer's DCW

5. Atomic exchange:
   ECB ESY DLT: transfers cash tokens seller→buyer
   Your smart contract: releases security tokens escrow→buyer

6. Pontes EII Adapter receives settlement confirmation
   → Writes settlement confirmation transaction to your blockchain
   → Transaction propagates via P2P to all nodes
   → Block finalised by consensus
   → Settlement finality recorded on-chain (immutable)

7. If either leg fails: both revert
   → Pontes returns failure response
   → Smart contract releases escrow back to seller
   → Failure event written to blockchain
```

- [ ] **Settlement atomicity:** Is the DvP mechanism genuinely atomic — either both legs complete or both revert? There must be no state where security tokens have transferred but cash has not (or vice versa).
- [ ] **Revert handling:** What happens if the Pontes EII call fails or times out? Is the security token escrow automatically released after a timeout? Is the timeout period documented and tested?
- [ ] **Settlement confirmation on-chain:** Is the Pontes settlement confirmation (or failure) written as an immutable transaction to your blockchain? This creates the audit trail required for regulatory reporting.
- [ ] **EII API credentials:** How are your EII API credentials (certificates or tokens) stored and managed? They must be stored with the same security standards as consensus signing keys.

### 13.2 KYC Provider Integration

- [ ] **Off-chain KYC data:** Confirm that personal KYC data (name, ID document images, address) is stored exclusively off-chain in your KYC provider's infrastructure or your own encrypted database. Only a pseudonymous KYC verification hash or status flag is stored on-chain.
- [ ] **On-chain KYC status:** The on-chain compliance engine references investor addresses mapped to a KYC status (verified/not verified/suspended) — not the underlying personal data. Confirm this architecture.
- [ ] **KYC status update propagation:** When a KYC status changes (e.g., investor fails re-screening), the update must propagate to the on-chain compliance engine via a transaction. Is this flow automated or manual?
- [ ] **Transfer restriction enforcement:** Confirm that the on-chain compliance engine's transfer restriction checks are enforced at the smart contract level — they cannot be bypassed by a malicious API call. The restriction logic must be in the consensus-validated contract, not in the API layer alone.

---

## 14. Known Attack Vectors and Mitigations

Document your response to each attack vector as part of your NCA submission:

| Attack | Description | Your Mitigation |
|---|---|---|
| **Sybil attack** | Attacker adds many fake nodes to gain network influence | Admission control — only approved nodes with verified identity can join |
| **Eclipse attack** | Attacker surrounds a victim node with malicious peers, controlling its view of the network | Static peer list — nodes only connect to pre-approved peers; attacker cannot insert themselves |
| **Byzantine delegate** | A consensus node sends conflicting messages to different delegates (equivocation) | dBFT detects equivocation; equivocating node's messages are rejected after detection; view change removes the Byzantine speaker |
| **Long-range attack** | Attacker rewrites historical blocks from an old key | dBFT has immediate finality — historical blocks cannot be rewritten; no fork possible |
| **Network partition** | Network splits into two groups; each group might produce blocks | dBFT's BFT property: only the partition with ≥ ⌈2N/3⌉ nodes can reach the commit threshold; the minority partition halts |
| **Replay attack** | Attacker resubmits a valid past transaction | Transaction nonce / unique ID prevents replay; already-executed transactions are rejected |
| **Smart contract exploit** | Malicious transaction triggers unintended smart contract behaviour | External audit; formal verification; access controls; upgrade mechanism with multi-sig |
| **Key compromise** | Consensus node signing key stolen | HSM storage; key rotation procedure; multi-sig for critical operations; monitor for unexpected signatures |
| **Denial of Service on consensus nodes** | Flood consensus nodes with traffic to halt consensus | Consensus nodes not internet-exposed; only accessible from approved peers; rate limiting at P2P layer |
| **Governance attack** | Attacker gains enough delegate positions to control consensus | Fit-and-proper assessment for all delegate operators; on-chain delegate set with change governance; monitor for unusual delegate set change proposals |

---

## Summary — Priority Review Order

When reviewing your existing implementation against this document, work in this order:

1. **Security first:** Transport security (TLS 1.3, mTLS), peer admission control, and key management. A vulnerability here undermines everything else.
2. **Consensus correctness:** BFT threshold, double-vote protection, view change. An incorrect consensus implementation produces incorrect state — the most serious possible bug.
3. **Finality:** Confirm that block commitment is genuinely irreversible and maps cleanly to the legal concept of settlement finality.
4. **Resilience:** Node redundancy, geographic distribution, failure recovery. Required by DORA from day one of authorisation.
5. **Observability:** Logging, monitoring, alerting. You cannot operate or demonstrate regulatory compliance without comprehensive visibility.
6. **Documentation:** NCA submission quality documentation for all of the above. Technical correctness alone is not sufficient — regulators must be able to understand and verify what you have built.

---

*This document reflects the regulatory and technical requirements as of May 2026. Cryptographic standards, DORA technical specifications, and DLT Pilot Regime technical guidance are subject to update — verify against the latest ENISA, ESMA, and ECB publications before filing regulatory submissions. This document does not constitute legal advice.*
