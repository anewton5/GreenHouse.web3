# GreenHouse — Private Placement Platform Roadmap

## Strategic Vision

GreenHouse will be built as a **decentralised private placement platform** targeting the sub-institutional layer of European capital markets: Series A/B companies seeking growth capital, smaller fund managers, family offices, and high-net-worth individuals (HNWIs) who currently lack efficient access to cross-border European private markets.

The platform solves a concrete problem: private market transactions in Europe are fragmented across jurisdictions, slow to settle, expensive in legal overhead, and largely inaccessible below institutional ticket sizes. GreenHouse replaces the opaque, intermediary-heavy private placement process with a transparent, cryptographically enforced, permissioned blockchain network.

**Initial scope**: Private placements to verified accredited investors only. This is the lowest regulatory burden while proving the core model, before pursuing DLT Pilot Regime authorisation for broader market access.

---

## Current Technical Foundation

The existing codebase provides a working base:

| Component | Status | Relevance |
|---|---|---|
| Ed25519 signing + multi-sig | ✅ Working | Binding transaction execution, co-signing |
| `Transaction` struct | ✅ Working | Base for asset transfer |
| `Block` + `Blockchain` | ✅ Working | Immutable settlement record |
| dBFT consensus | ✅ Working | Deterministic finality — critical for settlement |
| Wallet + locking/staking | ✅ Working | Escrow, capital lockup periods |
| Sharding | ✅ Working | Parallel processing of high-volume transactions |
| P2P network (libp2p) | ✅ Working | Permissioned node network for participants |
| GossipSub messaging | ✅ Working | Order/block propagation to all participants |

The blockchain's dBFT consensus is a strong architectural choice for a capital market: it provides **deterministic, immediate finality** (no forks, no probabilistic confirmation) — a hard requirement for regulated settlement infrastructure.

---

## Technology Plan

### 1. Asset Tokenization Layer

**Purpose**: Represent real-world financial instruments (equity stakes, convertible notes, fund units, warrants) as on-chain assets that can be transferred, held, and queried.

#### The Problem with the Current Model

The current `Transaction` struct moves a generic `Amount float64` of a single native token. A capital market requires multiple distinct instruments, each with its own rules, supply, and legal metadata.

#### Target Data Model

```go
// New file: assets.go

type AssetType string

const (
    AssetTypeEquity      AssetType = "equity"       // ordinary/preference shares
    AssetTypeDebt        AssetType = "debt"          // bonds, loan notes
    AssetTypeFundUnit    AssetType = "fund_unit"     // LP interests, fund shares
    AssetTypeWarrant     AssetType = "warrant"       // option to purchase equity
    AssetTypeConvertible AssetType = "convertible"   // convertible loan note
)

type TransferRestrictions struct {
    LockupPeriodDays    int      // e.g. 365 for a 12-month lockup
    AccreditedOnly      bool     // restrict to verified accredited investors
    MaxHolders          int      // e.g. 249 to stay under certain exemption limits
    AllowedJurisdictions []string // ISO 3166-1 alpha-2 country codes
    BlockedJurisdictions []string // explicit exclusion list
}

type AssetMetadata struct {
    CompanyName     string
    Jurisdiction    string    // ISO country code of incorporation
    ISIN            string    // International Securities Identification Number (if assigned)
    VotingRights    bool
    DividendTerms   string    // plain text or reference to legal document hash
    LegalDocHash    string    // SHA3-256 of the subscription agreement / term sheet
}

type Asset struct {
    ID               string               // UUID, unique per issuance
    Issuer           string               // public key hex of issuing entity
    AssetType        AssetType
    TotalSupply      float64              // total units issued
    CirculatingSupply float64             // outstanding (total - burned/redeemed)
    Metadata         AssetMetadata
    Restrictions     TransferRestrictions
    CreatedAt        int64                // Unix timestamp
    IssuerSignature  []byte               // issuer's Ed25519 signature over this struct
}

// AssetHolding records how much of a given asset a wallet holds
type AssetHolding struct {
    AssetID   string
    HolderID  string  // public key hex
    Balance   float64
    LockedUntil int64 // Unix timestamp, 0 = no lockup
}

// AssetTransaction extends the existing Transaction with asset context
type AssetTransaction struct {
    Transaction             // embedded: Sender, Receiver, Amount, Signatures
    AssetID     string      // which asset is being transferred
    TxType      AssetTxType // issue, transfer, redeem
}

type AssetTxType string

const (
    AssetTxTypeIssue    AssetTxType = "issue"    // new tokens created by issuer
    AssetTxTypeTransfer AssetTxType = "transfer" // holder-to-holder transfer
    AssetTxTypeRedeem   AssetTxType = "redeem"   // tokens burned/returned to issuer
)
```

#### Registry

The blockchain state needs to maintain a registry of all issued assets and all holdings:

```go
// To be added to the Blockchain struct in blockchain.go
type Blockchain struct {
    // ... existing fields ...
    Assets   map[string]*Asset        // assetID → Asset
    Holdings map[string]*AssetHolding // holderID+assetID → AssetHolding
}
```

#### Transfer Validation Rules

Before any `AssetTransaction` is accepted into the `TransactionPool`, it must pass:

1. **Asset exists** — the `AssetID` resolves to a known asset in the registry
2. **Sender holds sufficient balance** — `Holdings[sender+assetID].Balance >= Amount`
3. **Lockup not active** — `LockedUntil < time.Now().Unix()`
4. **Receiver is accredited** (if `AccreditedOnly`) — receiver's wallet has a valid credential attestation
5. **Jurisdiction check** — receiver's jurisdiction is not in `BlockedJurisdictions`
6. **Multi-sig threshold met** — existing `VerifyMultiSignature` handles this
7. **Max holders not exceeded** — count of unique holders of this asset stays within `MaxHolders`

#### Priority Build Order

- [ ] `assets.go` — `Asset`, `AssetHolding`, `AssetTransaction` structs + validation logic
- [ ] `assets_test.go` — issuance, transfer, restriction enforcement tests
- [ ] Extend `Blockchain.ValidateBlock` to handle `AssetTransaction` alongside `Transaction`
- [ ] Extend `blockchain.go` `AddBlock` to update `Holdings` state on confirmed blocks
- [ ] Extend `BroadcastTransaction` / `HandleMessages` in `p2p.go` to handle `AssetTransaction` message type

---

### 2. Order Book / Matching Engine

**Purpose**: Allow participants to post bids (buy orders) and asks (sell orders) for assets, and match them to execute trades — producing `AssetTransaction`s that then go through normal consensus and settlement.

#### Architecture Decision: On-Chain Order Book

For a private placement platform with lower-frequency trading (secondary transfers of private equity are infrequent relative to public markets), an **on-chain order book** is the right choice:

- Every order is a signed message on the chain — fully auditable
- No off-chain component to trust or that can be manipulated
- Matching is deterministic — all nodes compute the same matches from the same state
- Simpler operational model for a regulated environment

An off-chain matching engine (like a CEX) introduces a centralised point that requires its own regulatory approval and creates trust assumptions that conflict with the platform's decentralised premise.

#### Data Model

```go
// New file: orderbook.go

type OrderSide string

const (
    OrderSideBid OrderSide = "bid" // buyer — wants to acquire asset
    OrderSideAsk OrderSide = "ask" // seller — wants to sell asset
)

type OrderStatus string

const (
    OrderStatusOpen      OrderStatus = "open"
    OrderStatusPartial   OrderStatus = "partial"
    OrderStatusFilled    OrderStatus = "filled"
    OrderStatusCancelled OrderStatus = "cancelled"
)

type Order struct {
    ID          string      // UUID
    AssetID     string      // which asset
    Side        OrderSide
    Price       float64     // price per unit in platform currency
    Quantity    float64     // units of the asset
    Filled      float64     // how much has been matched so far
    PlacedBy    string      // public key hex of order placer
    PlacedAt    int64       // Unix timestamp
    ExpiresAt   int64       // 0 = GTC (good till cancelled)
    Status      OrderStatus
    Signature   []byte      // Ed25519 signature from PlacedBy over this order
}

type Trade struct {
    ID          string
    AssetID     string
    BidOrderID  string
    AskOrderID  string
    Price       float64     // agreed execution price
    Quantity    float64     // units transferred
    ExecutedAt  int64
}
```

#### Matching Logic

Orders are stored in the blockchain state per asset. When a new block is confirmed, the matching engine runs over open orders for each asset:

```
For each asset:
  Sort asks ascending by price (cheapest seller first)
  Sort bids descending by price (highest bidder first)
  While best_bid.price >= best_ask.price:
    Match at ask price (price-time priority)
    Create Trade record
    Create AssetTransaction (ask.PlacedBy → bid.PlacedBy, quantity, price)
    Update Order.Filled, Order.Status
```

This is **price-time priority** (the same rule used by most equity exchanges), implemented deterministically so every node produces the same matches.

#### Integration with Consensus

Matching runs as part of block finalisation in `finalizeBlock`:

1. New `Order` transactions arrive in `TransactionPool` via P2P
2. Speaker packages them into a `Block` alongside `AssetTransaction`s
3. dBFT consensus approves the block
4. On `finalizeBlock`:
   - Orders are added to the order book state
   - Matching engine runs — produces `Trade` records and `AssetTransaction`s
   - Holdings are updated atomically

#### Priority Build Order

- [ ] `orderbook.go` — `Order`, `Trade` structs + `MatchOrders(assetID string)` function
- [ ] `orderbook_test.go` — partial fill, full fill, price priority, expiry tests
- [ ] Extend `Blockchain` state to hold `Orders map[string]*Order` and `Trades []Trade`
- [ ] Add `OrderTransaction` message type to `p2p.go` handler
- [ ] Extend `finalizeBlock` in `dBFT.go` to call the matching engine
- [ ] Add order cancellation: signed cancel instruction, removes from open order book

---

### 3. Identity and Compliance Layer

**Purpose**: Ensure only verified, eligible participants can hold or trade assets — meeting KYC/AML requirements and investor classification rules — without storing personal data on the immutable chain.

#### The Core Design Principle

Personal data **must not** live on the blockchain. GDPR's right to erasure is incompatible with an immutable ledger. The solution is:

- **Off-chain**: A compliant identity registry stores personal data (name, passport, address)
- **On-chain**: Wallets carry a **credential attestation** — a signed certificate issued by the registry, containing only non-personal claims

This is architecturally similar to a verifiable credential (W3C VC standard), adapted to the existing Ed25519 key infrastructure.

#### Credential Model

```go
// New file: identity.go

type InvestorClass string

const (
    InvestorClassRetail        InvestorClass = "retail"
    InvestorClassProfessional  InvestorClass = "professional"   // MiFID II Article 30
    InvestorClassEligibleCP    InvestorClass = "eligible_cp"    // MiFID II Article 30
    InvestorClassAccredited    InvestorClass = "accredited"     // private placement eligible
)

type KYCStatus string

const (
    KYCStatusNone     KYCStatus = "none"
    KYCStatusPending  KYCStatus = "pending"
    KYCStatusVerified KYCStatus = "verified"
    KYCStatusRejected KYCStatus = "rejected"
    KYCStatusExpired  KYCStatus = "expired"
)

// IdentityCredential is issued by the Identity Registry and attached to a wallet.
// It contains NO personal data — only verifiable claims.
type IdentityCredential struct {
    WalletPublicKey  string        // the wallet this credential belongs to
    InvestorClass    InvestorClass
    KYCStatus        KYCStatus
    Jurisdiction     string        // ISO 3166-1 alpha-2 — country of residence
    IssuedAt         int64         // Unix timestamp
    ExpiresAt        int64         // credentials must be renewed (e.g. annually)
    RegistryID       string        // identifier of the issuing registry node
    RegistrySignature []byte       // Ed25519 signature from the registry's key
}

// CredentialAttestation is the lightweight on-chain record —
// just a hash of the IdentityCredential plus the registry's signature.
// The full credential is held off-chain by the wallet owner.
type CredentialAttestation struct {
    WalletPublicKey   string
    CredentialHash    string  // SHA3-256 of the IdentityCredential JSON
    ExpiresAt         int64
    RegistrySignature []byte
}
```

#### Identity Registry Node

A trusted registry node (operated by GreenHouse or a regulated KYC partner) holds a special role in the permissioned network:

- It runs a standard GreenHouse node
- Its public key is known to all participants (hardcoded or distributed via a genesis configuration)
- It issues `CredentialAttestation`s after completing off-chain KYC
- On-chain, any node can verify that a credential was issued by the registry by checking the `RegistrySignature` against the registry's public key

The registry does **not** need to be online for every transaction — credential attestations are stored in the blockchain state, verified at transfer time.

#### Verification Flow

```
New participant wants to invest:

1. Participant generates a wallet (GeneratePrivateKey / NewWallet)
2. Participant submits KYC documents to GreenHouse off-chain portal
3. GreenHouse (or KYC partner) verifies identity, determines InvestorClass
4. Registry node creates IdentityCredential, signs it, issues CredentialAttestation
5. CredentialAttestation is broadcast as an on-chain transaction and included in a block
6. Participant's wallet is now verified on-chain

Transfer validation now checks:
    receiver_wallet.Credential.KYCStatus == KYCStatusVerified
    receiver_wallet.Credential.InvestorClass == AccreditedOnly (if asset requires it)
    receiver_wallet.Credential.Jurisdiction not in asset.BlockedJurisdictions
    receiver_wallet.Credential.ExpiresAt > time.Now().Unix()
```

#### Blockchain State Extension

```go
// To be added to the Blockchain struct
type Blockchain struct {
    // ... existing fields ...
    Credentials map[string]*CredentialAttestation // walletPublicKey → credential
}
```

#### Permissioned Node Access

Beyond wallet-level credentials, the P2P network itself should be permissioned — only nodes run by verified participants or operators should be able to join. The mechanism:

- Bootstrap nodes maintain an allowlist of permitted peer IDs
- On connection, peers present a signed challenge proving control of their key
- Unapproved peer IDs are disconnected after the handshake

This is achievable with libp2p's `ConnectionGater` interface, which already exists in go-libp2p.

#### Priority Build Order

- [ ] `identity.go` — `IdentityCredential`, `CredentialAttestation` structs + `VerifyCredential(walletKey string, asset Asset)` function
- [ ] `identity_test.go` — credential issuance, expiry, jurisdiction check, accreditation check tests
- [ ] Extend `Blockchain` state to hold `Credentials` map
- [ ] Add `CredentialTransaction` message type — used by registry to publish attestations
- [ ] Extend `ValidateBlock` and asset transfer validation to check credentials
- [ ] Implement `ConnectionGater` in `p2p.go` for permissioned network access
- [ ] Off-chain: design KYC intake portal (out of scope for initial blockchain build, but API contract should be defined)

---

## Build Sequence

The three layers have dependencies. Build in this order:

```
Phase 1 — Asset Tokenization (no dependency on other new layers)
  └── assets.go + assets_test.go
  └── Extend blockchain.go: Holdings state, ValidateBlock for AssetTransaction
  └── Extend p2p.go: AssetTransaction message type

Phase 2 — Identity Layer (needed before order book — transfers require credential checks)
  └── identity.go + identity_test.go
  └── Extend blockchain.go: Credentials state, CredentialTransaction
  └── Extend asset transfer validation to call VerifyCredential
  └── ConnectionGater in p2p.go

Phase 3 — Order Book (depends on both assets and identity)
  └── orderbook.go + orderbook_test.go
  └── Extend blockchain.go: Orders + Trades state
  └── Extend finalizeBlock in dBFT.go: run MatchOrders after block commit
  └── Extend p2p.go: OrderTransaction message type
```

---

## Regulatory Position

**Operating model**: Private placements to accredited investors only.

This keeps GreenHouse outside the scope of the Prospectus Regulation (below the €8m threshold for a 12-month period per issuer, or restricted to qualified investors) and MiFID II's full MTF/OTF licence requirements.

**Applicable frameworks**:

| Framework | Relevance | Position |
|---|---|---|
| EU Prospectus Regulation | Public offerings | Avoided — private placement to accredited investors only |
| MiFID II | Trading venue rules | Avoided initially — bilateral private transactions, not a trading venue |
| AIFMD | Fund manager rules | Applies to fund issuers using the platform — their responsibility |
| GDPR | Personal data | Handled by off-chain identity registry; chain holds only credential hashes |
| AML4/5 Directive | KYC/AML obligations | Handled by identity registry KYC process |
| DLT Pilot Regime (EU 2022/858) | DLT market infrastructure sandbox | Future pathway to full MTF authorisation |

**Future milestone**: Once transaction volume and participant base are established, apply for DLT Pilot Regime authorisation from a national competent authority (FCA, AMF, or BaFin are the most active). This unlocks the ability to serve retail investors and list on a regulated MTF.

---

## Open Questions to Resolve

1. **Platform currency**: What currency do orders price in? Options:
   - EUR stablecoin (simplest for European participants)
   - Native GreenHouse token (requires token economics design)
   - Off-chain cash settlement with on-chain delivery-versus-payment (DVP) flag

2. **KYC partner**: Will GreenHouse operate its own KYC registry, or integrate with a third-party provider (Onfido, Jumio, Veriff)? The registry node design above supports either.

3. **Issuer onboarding**: What is the process for a company to issue an asset on the platform? This needs a legal wrapper (subscription agreement template, cap table integration).

4. **Secondary market liquidity**: Private equity is inherently illiquid. The order book helps, but liquidity provision strategy (e.g., curated market makers, matched auction windows rather than continuous trading) needs to be defined.

5. **Node operators**: Who runs nodes beyond GreenHouse? Institutional participants (custodians, fund admins) running their own nodes increases network resilience and decentralisation.
