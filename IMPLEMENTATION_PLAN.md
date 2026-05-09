# GreenHouse — Phase 0 Implementation Plan

## Overview

This plan covers the complete Phase 0 simulation build: eight weeks of focused engineering
to produce a fully demonstrable private placement platform running on the existing GreenHouse
P2P blockchain — with zero external service dependencies, zero licensing cost, and all real
logic in place so that integrating a live payment provider or KYC partner is a single-file
swap.

**Output at the end of Week 8**: A running multi-node network that issues tokenised assets,
enforces investor credentials, matches orders, and settles trades atomically (DVP) — all
verifiable by running `go test ./...` and `go run simulation/main.go`.

---

## Codebase Conventions (existing patterns to follow)

| Convention | Detail |
|---|---|
| Package | `package gonetwork` — all new files join this package |
| Signing | Ed25519 via existing `PrivateKey.Sign()` + `PublicKey` — do not introduce new crypto |
| Hashing | `sha3.Sum256` from `golang.org/x/crypto/sha3` — already imported |
| JSON | `encoding/json` — all serialisation for P2P messages |
| Testing | `github.com/stretchr/testify/assert` + `require` — already in `go.mod` |
| P2P messages | `P2PMessage{Type, Payload}` — add new `MessageType*` constants, handle in `HandleMessages` |
| Block storage | `Block.Transactions []Transaction` — asset transactions embed `Transaction` |
| Errors | Return `error` as last value; use `fmt.Errorf("context: %w", err)` |

---

## Week 1–2: Asset Tokenization Layer

### Files to create
- `assets.go`
- `assets_test.go`

### What these files must NOT do
- Touch `blockchain.go`, `p2p.go`, or any existing file yet
- Introduce any external dependency
- Handle payments or identity (those come later)

---

### `assets.go` — Complete Specification

#### Types

```go
package gonetwork

import (
    "encoding/json"
    "fmt"
    "time"
    "golang.org/x/crypto/sha3"
    "encoding/hex"
)

type AssetType string

const (
    AssetTypeEquity      AssetType = "equity"
    AssetTypeDebt        AssetType = "debt"
    AssetTypeFundUnit    AssetType = "fund_unit"
    AssetTypeWarrant     AssetType = "warrant"
    AssetTypeConvertible AssetType = "convertible"
)

type AssetTxType string

const (
    AssetTxTypeIssue    AssetTxType = "issue"
    AssetTxTypeTransfer AssetTxType = "transfer"
    AssetTxTypeRedeem   AssetTxType = "redeem"
)

type TransferRestrictions struct {
    LockupPeriodDays     int
    AccreditedOnly       bool
    MaxHolders           int      // 0 = unlimited
    AllowedJurisdictions []string // empty = all allowed
    BlockedJurisdictions []string
}

type AssetMetadata struct {
    CompanyName   string
    Jurisdiction  string // ISO 3166-1 alpha-2
    ISIN          string // optional, assigned by issuer
    VotingRights  bool
    DividendTerms string
    LegalDocHash  string // SHA3-256 hex of subscription agreement PDF
}

type Asset struct {
    ID                string
    Issuer            string // PublicKey.String() of issuing wallet
    AssetType         AssetType
    TotalSupply       float64
    CirculatingSupply float64
    Currency          string // "GBP", "EUR", "USD", "CHF"
    Metadata          AssetMetadata
    Restrictions      TransferRestrictions
    CreatedAt         int64  // Unix timestamp
    IssuerSignature   []byte // Sign(SHA3-256(Asset with IssuerSignature=nil))
}

// AssetHolding records one wallet's balance of one asset
type AssetHolding struct {
    AssetID     string
    HolderID    string  // PublicKey.String()
    Balance     float64
    LockedUntil int64   // Unix timestamp; 0 = no lockup
}

// AssetTransaction is the payload broadcast via P2P for asset-layer transfers.
// It embeds the existing Transaction (which carries Sender, Receiver, Amount,
// Signatures, RequiredSigs, Nonce) and adds asset-specific fields.
// The embedded Transaction.Amount == the number of asset units being transferred.
type AssetTransaction struct {
    Tx      Transaction
    AssetID string
    TxType  AssetTxType
}
```

#### Functions to implement

```go
// Asset

func NewAsset(
    issuerKey *PrivateKey,
    assetType AssetType,
    totalSupply float64,
    currency string,
    metadata AssetMetadata,
    restrictions TransferRestrictions,
) (*Asset, error)
// - generates UUID for ID (use fmt.Sprintf("%x", sha3.Sum256(...timestamp+issuer...)))
// - sets CreatedAt = time.Now().Unix()
// - sets CirculatingSupply = totalSupply on issuance
// - signs the asset: marshal to JSON with IssuerSignature=nil, sha3.Sum256, Sign
// - returns error if issuerKey nil or totalSupply <= 0

func (a *Asset) VerifyIssuerSignature(issuerPubKey *PublicKey) bool
// - marshal Asset with IssuerSignature=nil, sha3.Sum256, verify against IssuerSignature

func (a *Asset) CalculateHash() string
// - sha3.Sum256(json.Marshal(a)), return hex string
// - used as the canonical identifier when storing in Blockchain.Assets

// AssetTransaction

func NewAssetTransaction(
    senderKey *PrivateKey,
    receiverPubKey *PublicKey,
    assetID string,
    quantity float64,
    txType AssetTxType,
) (*AssetTransaction, error)
// - creates embedded Transaction{Sender: senderKey.Public().String(),
//   Receiver: receiverPubKey.String(), Amount: quantity, RequiredSigs: 1}
// - calls tx.GenerateNonce()
// - calls tx.SignTransaction(senderKey)
// - returns AssetTransaction{Tx: tx, AssetID: assetID, TxType: txType}

func (at *AssetTransaction) Validate(
    assets map[string]*Asset,
    holdings map[string]*AssetHolding,
    credentials map[string]*CredentialAttestation, // may be nil in Week 1
) error
// Validation rules (in order):
// 1. Asset exists in assets map
// 2. Quantity > 0
// 3. Sender and Receiver not empty
// 4. Tx signature valid (reuse existing VerifyTransaction)
// 5. TxType == "issue": sender must be asset.Issuer — enforce issuer-only issuance
// 6. TxType == "transfer" or "redeem": sender holding exists and Balance >= Quantity
// 7. Lockup: holding.LockedUntil == 0 || holding.LockedUntil <= time.Now().Unix()
// 8. MaxHolders: if asset.Restrictions.MaxHolders > 0, count distinct holders < max
// 9. BlockedJurisdictions: if credentials != nil, check receiver not blocked
// 10. AccreditedOnly: if credentials != nil, check receiver is accredited
// Returns nil if all checks pass, descriptive error otherwise

// Blockchain state mutations (to be called from finalizeBlock)

func ApplyAssetTransaction(
    at *AssetTransaction,
    assets map[string]*Asset,
    holdings map[string]*AssetHolding,
) error
// Updates holdings atomically:
// issue:    create/increment receiver holding, increment CirculatingSupply
// transfer: decrement sender, increment receiver
// redeem:   decrement sender, decrement CirculatingSupply
// Sets LockedUntil on new holdings based on asset.Restrictions.LockupPeriodDays
// Returns error if preconditions fail (should not happen if Validate was called first)

func HoldingKey(holderID, assetID string) string
// Returns "holderID:assetID" — canonical key for the holdings map
```

#### P2P message type (to add to `p2p.go` later — flag for Week 5)

```go
const MessageTypeAssetTransaction = "asset_transaction"
```

---

### `assets_test.go` — Required Test Cases

Each test must be independent (no shared state between tests). Use `testify/require` for
fatal assertions and `testify/assert` for non-fatal ones.

| Test name | What it tests |
|---|---|
| `TestNewAsset_Valid` | Creates equity asset, verifies issuer signature, checks all fields set |
| `TestNewAsset_InvalidSupply` | Rejects totalSupply <= 0 |
| `TestNewAsset_NilKey` | Rejects nil issuerKey |
| `TestAssetIssueTransaction` | Issues tokens: sender holding is created with correct balance |
| `TestAssetTransfer_Valid` | Transfers between two wallets: balances update correctly |
| `TestAssetTransfer_InsufficientBalance` | Rejects transfer where sender balance < quantity |
| `TestAssetTransfer_InvalidSignature` | Rejects transaction signed by wrong key |
| `TestAssetTransfer_LockupActive` | Rejects transfer during lockup period |
| `TestAssetTransfer_LockupExpired` | Accepts transfer after lockup period has passed |
| `TestAssetRedeem` | Redeems tokens: sender balance decrements, CirculatingSupply decrements |
| `TestAssetMaxHolders` | Rejects transfer that would exceed MaxHolders limit |
| `TestAssetBlockedJurisdiction` | Rejects transfer to receiver in blocked jurisdiction (credential stub) |
| `TestAssetIssuerOnlyIssuance` | Rejects issue transaction from non-issuer wallet |
| `TestHoldingKey` | Verifies HoldingKey returns consistent canonical form |
| `TestApplyAssetTransaction_Idempotent` | Applying same transaction twice is an error |

**Test helper to define in `assets_test.go`**:
```go
func makeTestAsset(t *testing.T) (*Asset, *PrivateKey) {
    // Creates a standard equity asset for reuse across tests
}

func makeTestWallet(t *testing.T) (*PrivateKey, string) {
    // Generates key, returns (key, publicKeyString)
}
```

---

## Week 2–3: Identity and Compliance Layer

### Files to create
- `identity.go`
- `identity_test.go`

### Why before the order book
Asset transfer validation needs to check investor credentials. The `Validate` function in
`assets.go` accepts `credentials map[string]*CredentialAttestation` — this map is populated
by the identity layer. Building identity before the order book means asset validation is
complete when order matching produces `AssetTransaction`s in Week 4.

---

### `identity.go` — Complete Specification

#### Types

```go
package gonetwork

type InvestorClass string

const (
    InvestorClassRetail       InvestorClass = "retail"
    InvestorClassProfessional InvestorClass = "professional"
    InvestorClassEligibleCP   InvestorClass = "eligible_cp"
    InvestorClassAccredited   InvestorClass = "accredited"
)

type KYCStatus string

const (
    KYCStatusNone     KYCStatus = "none"
    KYCStatusPending  KYCStatus = "pending"
    KYCStatusVerified KYCStatus = "verified"
    KYCStatusRejected KYCStatus = "rejected"
    KYCStatusExpired  KYCStatus = "expired"
)

// IdentityCredential is held off-chain by the wallet owner and the registry.
// It contains NO personal data — only verifiable claims.
// The registry signs it; the wallet owner presents it when challenged.
type IdentityCredential struct {
    WalletPublicKey   string
    InvestorClass     InvestorClass
    KYCStatus         KYCStatus
    Jurisdiction      string    // ISO 3166-1 alpha-2
    IssuedAt          int64
    ExpiresAt         int64
    RegistryID        string    // PublicKey.String() of the registry node
    RegistrySignature []byte    // Sign(SHA3-256(credential with Signature=nil))
}

// CredentialAttestation is the on-chain record.
// Only the hash and signature live on chain — no personal data.
type CredentialAttestation struct {
    WalletPublicKey   string
    CredentialHash    string // SHA3-256 hex of the IdentityCredential JSON
    InvestorClass     InvestorClass  // duplicated for fast on-chain checking
    KYCStatus         KYCStatus      // duplicated for fast on-chain checking
    Jurisdiction      string         // duplicated for fast on-chain checking
    ExpiresAt         int64
    RegistrySignature []byte
}

// CredentialTransaction is broadcast via P2P when the registry issues an attestation.
// It is included in a block, committing the credential on-chain.
type CredentialTransaction struct {
    Attestation CredentialAttestation
}
```

#### Interface — the key abstraction

```go
// IdentityRegistry is the interface both the mock and any future live KYC
// provider must implement. All identity checks in assets.go and orderbook.go
// use this interface — never a concrete type.
type IdentityRegistry interface {
    // IssueCredential creates and signs an attestation for a wallet.
    // In production this is called by the registry operator after off-chain KYC.
    // In the mock it is called immediately with no checks.
    IssueCredential(
        walletKey string,
        class InvestorClass,
        jurisdiction string,
        validForDays int,
    ) (*CredentialAttestation, error)

    // VerifyCredential checks that a wallet has a valid, non-expired credential.
    VerifyCredential(walletKey string) (*CredentialAttestation, error)

    // RegistryPublicKey returns the registry's public key for signature verification.
    RegistryPublicKey() *PublicKey
}
```

#### Functions to implement

```go
// IdentityCredential

func NewIdentityCredential(
    walletKey string,
    class InvestorClass,
    jurisdiction string,
    validForDays int,
    registryKey *PrivateKey,
) (*IdentityCredential, error)
// - validates walletKey not empty, class and jurisdiction valid
// - sets IssuedAt = time.Now().Unix()
// - sets ExpiresAt = IssuedAt + int64(validForDays*86400)
// - sets RegistryID = registryKey.Public().String()
// - signs: marshal with RegistrySignature=nil, sha3.Sum256, Sign(registryKey)

func (c *IdentityCredential) VerifySignature(registryPubKey *PublicKey) bool
// - marshal with RegistrySignature=nil, sha3.Sum256, ed25519.Verify

func (c *IdentityCredential) IsExpired() bool
// - return time.Now().Unix() > c.ExpiresAt

func (c *IdentityCredential) ToAttestation() *CredentialAttestation
// - marshals credential to JSON, sha3.Sum256 → CredentialHash
// - copies InvestorClass, KYCStatus, Jurisdiction, ExpiresAt, RegistrySignature
// - does NOT copy personal fields (none exist in this struct, by design)

// CredentialAttestation

func (a *CredentialAttestation) IsValid() bool
// - KYCStatus == KYCStatusVerified AND time.Now().Unix() <= ExpiresAt

func (a *CredentialAttestation) IsAccredited() bool
// - IsValid() AND InvestorClass != InvestorClassRetail

// Blockchain state helper

func CheckTransferEligibility(
    receiverKey string,
    asset *Asset,
    credentials map[string]*CredentialAttestation,
) error
// Called from AssetTransaction.Validate when credentials map is non-nil.
// Returns nil if:
//   - asset.Restrictions.AccreditedOnly == false, OR credential exists and IsAccredited()
//   - receiver jurisdiction not in asset.Restrictions.BlockedJurisdictions
//   - credential exists and IsValid()
// Returns descriptive error otherwise.
```

#### P2P message type constant (for Week 5)

```go
const MessageTypeCredential = "credential"
```

---

### `identity_test.go` — Required Test Cases

| Test name | What it tests |
|---|---|
| `TestNewCredential_Valid` | Issues credential, verifies registry signature, checks all fields |
| `TestNewCredential_InvalidJurisdiction` | Rejects empty jurisdiction |
| `TestCredentialExpiry` | `IsExpired()` returns false immediately, true after expiry timestamp |
| `TestCredentialToAttestation` | Hash is deterministic; no personal data in attestation |
| `TestAttestationIsValid` | Valid + not expired = true; expired = false; rejected = false |
| `TestAttestationIsAccredited` | Professional/eligible_cp/accredited = true; retail = false |
| `TestCheckTransferEligibility_Accredited` | AccreditedOnly asset: accredited investor passes |
| `TestCheckTransferEligibility_RetailBlocked` | AccreditedOnly asset: retail investor rejected |
| `TestCheckTransferEligibility_JurisdictionBlocked` | Receiver in blocked jurisdiction rejected |
| `TestCheckTransferEligibility_NoRestrictions` | Asset with no restrictions: no credential required |
| `TestCredentialSignatureTampering` | Mutated credential fails VerifySignature |
| `TestAssetValidationWithCredentials` | Full integration: AssetTransaction.Validate with credentials map |

---

## Week 3–4: Payment Interfaces and Mocks

### Files to create
- `payment.go`
- `mock_payment.go`
- `mock_identity.go`

### Purpose
Define the contracts for all external integrations. Build mocks that make the simulation
run at full speed (instant confirmation, instant KYC). These mocks are also the test doubles
used in all future tests — no real network calls ever happen in `go test`.

---

### `payment.go` — Complete Specification

#### Types

```go
package gonetwork

type PaymentStatus string

const (
    PaymentStatusPending   PaymentStatus = "pending"
    PaymentStatusConfirmed PaymentStatus = "confirmed"
    PaymentStatusFailed    PaymentStatus = "failed"
    PaymentStatusExpired   PaymentStatus = "expired"
)

type SettlementMethod string

const (
    SettlementSEPA      SettlementMethod = "sepa_instant"
    SettlementFasterPay SettlementMethod = "faster_payments"
    SettlementSWIFT     SettlementMethod = "swift_gpi"
    SettlementEURC      SettlementMethod = "eurc_on_chain"
)

// PaymentInstruction is created on-chain when an order is matched.
// It instructs the buyer to make a specific payment.
// It is signed by the registry oracle to prevent forgery.
type PaymentInstruction struct {
    TradeID         string
    AssetID         string
    Quantity        float64
    PricePerUnit    float64
    TotalAmount     float64  // Quantity * PricePerUnit
    Currency        string
    Method          SettlementMethod
    PayerWalletID   string   // buyer's PublicKey.String()
    PayeeWalletID   string   // seller's PublicKey.String()
    PayerVirtualIBAN string  // virtual IBAN assigned to buyer by payment provider
    Reference       string   // unique reference for payment matching
    ExpiresAt       int64    // Unix timestamp — trade reverts if payment not confirmed
    OracleSignature []byte   // registry signs this instruction
}

// PaymentConfirmation is broadcast on-chain when payment is confirmed.
// In production: triggered by a Modulr webhook received by the oracle service.
// In simulation: triggered immediately by MockPaymentProvider.
type PaymentConfirmation struct {
    InstructionID   string   // TradeID
    Reference       string
    ConfirmedAmount float64
    Currency        string
    ConfirmedAt     int64
    OracleSignature []byte   // registry signs this confirmation
}
```

#### Interfaces

```go
// PaymentProvider abstracts the payment rail (Modulr, Stripe, etc.).
// The mock implements this for simulation; a live implementation will be
// a single new file when Modulr onboarding is complete.
type PaymentProvider interface {
    // CreateVirtualAccount returns a virtual IBAN for a participant wallet.
    // This is called once per wallet during participant onboarding.
    CreateVirtualAccount(walletID string) (iban string, err error)

    // GetPaymentStatus polls for the status of a payment by reference.
    GetPaymentStatus(reference string) (PaymentStatus, error)

    // ConfirmPayment simulates or receives confirmation of a payment.
    // In production this is triggered by a webhook; the interface allows
    // the mock to call it directly in tests.
    ConfirmPayment(reference string, amount float64, currency string) error
}

// OracleService signs PaymentInstructions and PaymentConfirmations.
// In Phase 1 this is operated by GreenHouse (self-signed via registry key).
// In Phase 2 it becomes multi-sig.
type OracleService interface {
    // SignInstruction signs a PaymentInstruction and returns it with OracleSignature set.
    SignInstruction(instruction *PaymentInstruction) (*PaymentInstruction, error)

    // SignConfirmation signs a PaymentConfirmation and returns it with OracleSignature set.
    SignConfirmation(confirmation *PaymentConfirmation) (*PaymentConfirmation, error)

    // VerifyInstruction verifies the oracle signature on a PaymentInstruction.
    VerifyInstruction(instruction *PaymentInstruction) bool

    // VerifyConfirmation verifies the oracle signature on a PaymentConfirmation.
    VerifyConfirmation(confirmation *PaymentConfirmation) bool
}
```

#### P2P message type constants (for Week 5)

```go
const MessageTypePaymentInstruction = "payment_instruction"
const MessageTypePaymentConfirmation = "payment_confirmation"
```

---

### `mock_payment.go` — Complete Specification

```go
package gonetwork

// MockPaymentProvider confirms payments instantly. It records all virtual
// accounts and payment references for assertion in tests.
type MockPaymentProvider struct {
    VirtualAccounts map[string]string        // walletID → IBAN
    Payments        map[string]PaymentStatus // reference → status
    counter         int64
}

func NewMockPaymentProvider() *MockPaymentProvider
// Initialises both maps

func (m *MockPaymentProvider) CreateVirtualAccount(walletID string) (string, error)
// Generates deterministic IBAN: fmt.Sprintf("GB%02dMOCK%016X", counter, hash(walletID))
// Stores in VirtualAccounts, increments counter

func (m *MockPaymentProvider) GetPaymentStatus(reference string) (PaymentStatus, error)
// Returns Payments[reference], or PaymentStatusPending if not found

func (m *MockPaymentProvider) ConfirmPayment(reference string, amount float64, currency string) error
// Sets Payments[reference] = PaymentStatusConfirmed
// In simulation this is called immediately after instruction is issued
```

#### `MockOracleService`

```go
// MockOracleService uses the registry node's real Ed25519 key but runs locally.
// This is functionally identical to the production oracle — the only difference
// in production is that the key is held in AWS KMS instead of memory.
type MockOracleService struct {
    RegistryKey    *PrivateKey
    RegistryPubKey *PublicKey
}

func NewMockOracleService() (*MockOracleService, error)
// Generates a fresh Ed25519 key for the registry

func (o *MockOracleService) SignInstruction(instruction *PaymentInstruction) (*PaymentInstruction, error)
// Marshal instruction with OracleSignature=nil, sha3.Sum256, Sign(RegistryKey)
// Returns copy with OracleSignature set

func (o *MockOracleService) SignConfirmation(confirmation *PaymentConfirmation) (*PaymentConfirmation, error)
// Same pattern as SignInstruction

func (o *MockOracleService) VerifyInstruction(instruction *PaymentInstruction) bool
// Marshal with OracleSignature=nil, sha3.Sum256, ed25519.Verify(RegistryPubKey)

func (o *MockOracleService) VerifyConfirmation(confirmation *PaymentConfirmation) bool
// Same pattern as VerifyInstruction
```

---

### `mock_identity.go` — Complete Specification

```go
package gonetwork

// MockIdentityRegistry issues credentials instantly with no real KYC.
// It uses a real Ed25519 key and real signatures — only the verification
// process (which in production involves a human reviewing documents) is bypassed.
type MockIdentityRegistry struct {
    registryKey  *PrivateKey
    registryPub  *PublicKey
    credentials  map[string]*CredentialAttestation // walletKey → attestation
}

func NewMockIdentityRegistry() (*MockIdentityRegistry, error)
// Generates registry Ed25519 key

func (r *MockIdentityRegistry) IssueCredential(
    walletKey string,
    class InvestorClass,
    jurisdiction string,
    validForDays int,
) (*CredentialAttestation, error)
// Creates IdentityCredential via NewIdentityCredential
// Calls ToAttestation()
// Stores in r.credentials
// Returns attestation

func (r *MockIdentityRegistry) VerifyCredential(walletKey string) (*CredentialAttestation, error)
// Returns r.credentials[walletKey] or error if not found

func (r *MockIdentityRegistry) RegistryPublicKey() *PublicKey
// Returns r.registryPub
```

---

## Week 4–5: Order Book and Matching Engine

### Files to create
- `orderbook.go`
- `orderbook_test.go`

---

### `orderbook.go` — Complete Specification

#### Types

```go
package gonetwork

type OrderSide string

const (
    OrderSideBid OrderSide = "bid"
    OrderSideAsk OrderSide = "ask"
)

type OrderStatus string

const (
    OrderStatusOpen      OrderStatus = "open"
    OrderStatusPartial   OrderStatus = "partial"
    OrderStatusFilled    OrderStatus = "filled"
    OrderStatusCancelled OrderStatus = "cancelled"
    OrderStatusExpired   OrderStatus = "expired"
)

type Order struct {
    ID          string
    AssetID     string
    Side        OrderSide
    Price       float64     // price per unit in asset's Currency
    Quantity    float64     // total units requested
    Filled      float64     // units matched so far
    PlacedBy    string      // PublicKey.String() of order placer
    PlacedAt    int64       // Unix timestamp
    ExpiresAt   int64       // 0 = GTC (good till cancelled)
    Status      OrderStatus
    Signature   []byte      // Sign(SHA3-256(Order with Signature=nil))
}

type Trade struct {
    ID          string
    AssetID     string
    BidOrderID  string
    AskOrderID  string
    BuyerID     string  // PublicKey.String()
    SellerID    string
    Price       float64
    Quantity    float64
    Currency    string
    ExecutedAt  int64
}

// OrderBook holds all open orders for a single asset.
// One OrderBook exists per asset in Blockchain.OrderBooks.
type OrderBook struct {
    AssetID string
    Bids    []*Order // maintained sorted: highest price first
    Asks    []*Order // maintained sorted: lowest price first
}

// OrderTransaction is broadcast via P2P to place or cancel an order.
type OrderTransaction struct {
    Tx        Transaction // Sender = order placer; Amount = 0 (not a value transfer)
    Order     Order
    IsCancellation bool  // true = cancel OrderID, false = place new order
}
```

#### Functions to implement

```go
func NewOrder(
    placerKey *PrivateKey,
    assetID string,
    side OrderSide,
    price float64,
    quantity float64,
    expiresAt int64,
) (*Order, error)
// - validates: price > 0, quantity > 0, assetID not empty
// - generates ID: hex(sha3.Sum256(placerKey+assetID+timestamp))
// - sets PlacedAt = time.Now().Unix(), Status = OrderStatusOpen
// - signs: marshal with Signature=nil, sha3.Sum256, Sign(placerKey)

func (o *Order) Remaining() float64
// return o.Quantity - o.Filled

func (o *Order) IsExpired() bool
// return o.ExpiresAt > 0 && time.Now().Unix() > o.ExpiresAt

func (o *Order) VerifySignature(placerPubKey *PublicKey) bool
// marshal with Signature=nil, sha3.Sum256, ed25519.Verify

func NewOrderBook(assetID string) *OrderBook

func (ob *OrderBook) AddOrder(order *Order) error
// Validates order signature (needs pubkey — accept *PublicKey parameter)
// Inserts into Bids or Asks, maintaining sort order:
//   Bids: sorted descending by Price (highest first)
//   Asks: sorted ascending by Price (lowest first)
// Same price: sort ascending by PlacedAt (time priority — earlier orders matched first)

func (ob *OrderBook) CancelOrder(orderID string, cancellerKey string) error
// Finds order by ID, verifies canceller == order.PlacedBy
// Sets Status = OrderStatusCancelled, removes from slice

func (ob *OrderBook) ExpireOrders()
// Iterates all open orders; sets expired ones to OrderStatusExpired; removes from slices
// Called at start of each MatchOrders run

func (ob *OrderBook) MatchOrders(assetID string, currency string) ([]Trade, []*AssetTransaction, error)
// Core matching algorithm — price-time priority:
//
//   ob.ExpireOrders()
//   trades := []Trade{}
//   assetTxs := []*AssetTransaction{}
//
//   for len(ob.Bids) > 0 && len(ob.Asks) > 0 {
//       bestBid = ob.Bids[0]
//       bestAsk = ob.Asks[0]
//       if bestBid.Price < bestAsk.Price { break } // no match
//
//       qty = min(bestBid.Remaining(), bestAsk.Remaining())
//       price = bestAsk.Price // price-time: execute at ask price
//
//       trade = Trade{...}
//       trades = append(trades, trade)
//
//       assetTx = NewAssetTransaction(... seller→buyer, qty ...)
//       assetTxs = append(assetTxs, assetTx)
//
//       update bestBid.Filled, bestAsk.Filled, statuses
//       remove fully filled orders from slices
//   }
//
//   return trades, assetTxs, nil
//
// Note: MatchOrders does NOT call ApplyAssetTransaction — that happens
// in finalizeBlock after consensus. MatchOrders only produces the
// transactions and trade records.
```

**Critical design note**: `MatchOrders` produces `AssetTransaction`s but does NOT sign
them — the system cannot sign on behalf of sellers without their private key. Instead:

- The `AssetTransaction.Tx.Sender` is set to the seller's public key
- The `AssetTransaction.Tx.Signatures` is left empty
- A separate **settlement signature flow** is required: the seller must co-sign the
  generated `AssetTransaction` before it can be committed

For the simulation (Phase 0), this is handled by the simulation script holding all private
keys in memory and auto-signing. In production, this is an off-chain signing request sent to
the seller's client. Document this clearly in code comments.

---

### `orderbook_test.go` — Required Test Cases

| Test name | What it tests |
|---|---|
| `TestNewOrder_Valid` | Creates order, verifies signature, checks all fields |
| `TestNewOrder_InvalidPrice` | Rejects price <= 0 |
| `TestNewOrder_InvalidQuantity` | Rejects quantity <= 0 |
| `TestOrderBookAddBid` | Bids sorted highest-price first |
| `TestOrderBookAddAsk` | Asks sorted lowest-price first |
| `TestOrderBookTimePriority` | Two bids at same price: earlier one matched first |
| `TestMatchOrders_FullFill` | Matching bid and ask, same quantity: both filled |
| `TestMatchOrders_PartialFill` | Bid quantity > ask quantity: bid partially filled, ask fully filled |
| `TestMatchOrders_NoMatch` | Bid price < ask price: no trade produced |
| `TestMatchOrders_MultipleMatches` | Three asks against one large bid: multiple trades produced |
| `TestMatchOrders_ExecuteAtAskPrice` | Execution price equals ask price, not bid price |
| `TestOrderExpiry` | Expired order is removed before matching; no trade produced |
| `TestCancelOrder` | Order cancelled by placer: removed from book |
| `TestCancelOrder_WrongCanceller` | Cancellation rejected if canceller != placer |
| `TestMatchOrders_ProducesAssetTransactions` | Each trade produces exactly one AssetTransaction |
| `TestOrderBookEmptyAfterFill` | Both sides empty after complete fill |

---

## Week 5–6: DVP Integration

### Files to modify
- `blockchain.go` — extend `Blockchain` struct and `finalizeBlock`
- `dBFT.go` — extend `createBlock` to collect order and asset transactions
- `p2p.go` — add new message type handlers

### No new files — this week is integration only.

---

### Changes to `blockchain.go`

#### Extend the `Blockchain` struct

Add the following fields:

```go
type Blockchain struct {
    // ... all existing fields ...

    // Asset layer
    Assets   map[string]*Asset          // assetID → Asset
    Holdings map[string]*AssetHolding   // HoldingKey(holderID, assetID) → AssetHolding

    // Order book layer
    OrderBooks map[string]*OrderBook    // assetID → OrderBook
    Trades     []Trade                  // append-only trade history

    // Identity layer
    Credentials map[string]*CredentialAttestation // walletKey → attestation

    // Payment layer
    PendingInstructions map[string]*PaymentInstruction  // tradeID → instruction
    ConfirmedPayments   map[string]*PaymentConfirmation // tradeID → confirmation

    // Services (interfaces — swappable for live implementations)
    PaymentProvider  PaymentProvider
    IdentityRegistry IdentityRegistry
    OracleService    OracleService
}
```

#### Extend `NewBlockchain`

After the genesis block is added, initialise the new maps:

```go
bc.Assets      = make(map[string]*Asset)
bc.Holdings    = make(map[string]*AssetHolding)
bc.OrderBooks  = make(map[string]*OrderBook)
bc.Trades      = []Trade{}
bc.Credentials = make(map[string]*CredentialAttestation)
bc.PendingInstructions = make(map[string]*PaymentInstruction)
bc.ConfirmedPayments   = make(map[string]*PaymentConfirmation)
```

If `PaymentProvider`, `IdentityRegistry`, and `OracleService` are nil (not set by caller),
`NewBlockchain` sets them to mock implementations by default:

```go
if bc.PaymentProvider == nil {
    bc.PaymentProvider = NewMockPaymentProvider()
}
if bc.IdentityRegistry == nil {
    bc.IdentityRegistry, _ = NewMockIdentityRegistry()
}
if bc.OracleService == nil {
    bc.OracleService, _ = NewMockOracleService()
}
```

This ensures all existing tests continue passing without modification.

#### Extend `finalizeBlock` in `dBFT.go`

After `bc.Blocks = append(bc.Blocks, block)`, add the following sequence:

```go
func (bc *Blockchain) finalizeBlock(block Block) {
    // 1. Existing: append to chain
    bc.Blocks = append(bc.Blocks, block)

    // 2. Apply asset transactions from this block
    for _, tx := range block.AssetTransactions {
        if err := tx.Validate(bc.Assets, bc.Holdings, bc.Credentials); err != nil {
            fmt.Printf("Skipping invalid asset tx: %v\n", err)
            continue
        }
        if err := ApplyAssetTransaction(&tx, bc.Assets, bc.Holdings); err != nil {
            fmt.Printf("Failed to apply asset tx: %v\n", err)
        }
    }

    // 3. Apply credential transactions
    for _, ct := range block.CredentialTransactions {
        bc.Credentials[ct.Attestation.WalletPublicKey] = &ct.Attestation
    }

    // 4. Apply new orders to order books
    for _, ot := range block.OrderTransactions {
        if ot.IsCancellation {
            if ob, ok := bc.OrderBooks[ot.Order.AssetID]; ok {
                ob.CancelOrder(ot.Order.ID, ot.Tx.Sender)
            }
            continue
        }
        if _, ok := bc.OrderBooks[ot.Order.AssetID]; !ok {
            bc.OrderBooks[ot.Order.AssetID] = NewOrderBook(ot.Order.AssetID)
        }
        // Retrieve placer's public key from sender string
        pubKey, err := PublicKeyFromString(ot.Tx.Sender)
        if err != nil { continue }
        bc.OrderBooks[ot.Order.AssetID].AddOrder(&ot.Order, pubKey)
    }

    // 5. Run matching engine for all order books that have new orders
    for assetID, ob := range bc.OrderBooks {
        asset, ok := bc.Assets[assetID]
        if !ok { continue }
        trades, assetTxs, err := ob.MatchOrders(assetID, asset.Currency)
        if err != nil { continue }

        for i, trade := range trades {
            bc.Trades = append(bc.Trades, trade)

            // 6. Issue PaymentInstruction for each trade
            instruction := &PaymentInstruction{
                TradeID:      trade.ID,
                AssetID:      trade.AssetID,
                Quantity:     trade.Quantity,
                PricePerUnit: trade.Price,
                TotalAmount:  trade.Price * trade.Quantity,
                Currency:     trade.Currency,
                Method:       SettlementSEPA, // default; participant may override
                PayerWalletID:  trade.BuyerID,
                PayeeWalletID:  trade.SellerID,
                Reference:    fmt.Sprintf("GH-%s", trade.ID[:8]),
                ExpiresAt:    time.Now().Unix() + 86400, // 24h to pay
            }
            instruction, _ = bc.OracleService.SignInstruction(instruction)
            bc.PendingInstructions[trade.ID] = instruction

            // 7. Simulate payment confirmation (MockPaymentProvider confirms instantly)
            _ = bc.PaymentProvider.ConfirmPayment(
                instruction.Reference,
                instruction.TotalAmount,
                instruction.Currency,
            )
            status, _ := bc.PaymentProvider.GetPaymentStatus(instruction.Reference)
            if status == PaymentStatusConfirmed {
                confirmation := &PaymentConfirmation{
                    InstructionID:   trade.ID,
                    Reference:       instruction.Reference,
                    ConfirmedAmount: instruction.TotalAmount,
                    Currency:        instruction.Currency,
                    ConfirmedAt:     time.Now().Unix(),
                }
                confirmation, _ = bc.OracleService.SignConfirmation(confirmation)
                bc.ConfirmedPayments[trade.ID] = confirmation

                // 8. DVP: apply asset transaction now that payment is confirmed
                atx := assetTxs[i]
                _ = ApplyAssetTransaction(atx, bc.Assets, bc.Holdings)
            }
        }
    }
}
```

**Note on Block struct extension**: The current `Block` struct holds only `[]Transaction`.
To carry the new transaction types, add optional slice fields:

```go
type Block struct {
    Transactions           []Transaction            // existing — native token transfers
    AssetTransactions      []AssetTransaction       // new
    OrderTransactions      []OrderTransaction       // new
    CredentialTransactions []CredentialTransaction  // new
    PrevHash               string
    Nonce                  int
    Signatures             [][]byte
}
```

These fields are `omitempty` in JSON — existing blocks with nil slices serialise identically
to the current format, preserving backward compatibility.

---

### Changes to `p2p.go`

In `HandleMessages`, extend the message type dispatch:

```go
case MessageTypeAssetTransaction:
    var at AssetTransaction
    if err := json.Unmarshal(msg.Payload, &at); err != nil { continue }
    // validate and add to pending pool (not yet in a block)
    if err := at.Validate(node.Blockchain.Assets, node.Blockchain.Holdings, node.Blockchain.Credentials); err == nil {
        node.Blockchain.PendingAssetTransactions = append(node.Blockchain.PendingAssetTransactions, at)
    }

case MessageTypeCredential:
    var ct CredentialTransaction
    if err := json.Unmarshal(msg.Payload, &ct); err != nil { continue }
    // apply directly — credentials are trusted (registry-signed)
    if ct.Attestation.IsValid() {
        node.Blockchain.Credentials[ct.Attestation.WalletPublicKey] = &ct.Attestation
    }

case MessageTypePaymentConfirmation:
    var pc PaymentConfirmation
    if err := json.Unmarshal(msg.Payload, &pc); err != nil { continue }
    if node.Blockchain.OracleService.VerifyConfirmation(&pc) {
        node.Blockchain.ConfirmedPayments[pc.InstructionID] = &pc
    }
```

Also add broadcast helper methods to `P2PNode`:

```go
func (n *P2PNode) BroadcastAssetTransaction(at AssetTransaction) error
func (n *P2PNode) BroadcastCredential(ct CredentialTransaction) error
func (n *P2PNode) BroadcastPaymentConfirmation(pc PaymentConfirmation) error
```

Each follows the exact same pattern as the existing `BroadcastTransaction`:
JSON-encode into `P2PMessage{Type: ..., Payload: ...}`, publish to topic.

---

## Week 6–8: End-to-End Simulation

### Files to create
- `simulation/main.go`

This is a runnable Go program (`go run simulation/main.go`) that demonstrates the full
platform lifecycle from start to finish, printing a clear narrative log of every step.

### `simulation/main.go` — Required Scenario

```
Step 1:  Create blockchain + P2P node (two-node local network if run with -multi flag)
Step 2:  Issue credentials for four participants:
           Alice   — Accredited / GB / Professional
           Bob     — Accredited / DE / Professional
           Charlie — Accredited / FR / Eligible CP
           Diana   — Retail / GB (used to test rejection)
Step 3:  Issue an asset:
           "Acme Series B"  — 1,000,000 equity shares @ GBP
           LockupPeriodDays: 365, AccreditedOnly: true
Step 4:  Issuer allocates initial holdings:
           Alice:   400,000 shares (issue transaction)
           Bob:     300,000 shares (issue transaction)
           Charlie: 300,000 shares (issue transaction)
Step 5:  Place orders:
           Alice bids 50,000 shares @ £6.00  (buying more)
           Bob   asks 50,000 shares @ £5.50  (selling some)
           Charlie asks 25,000 shares @ £6.50 (no match — price too high)
Step 6:  Run consensus — block proposed, delegates vote, block finalised
Step 7:  Matching engine runs:
           Alice bid £6.00 >= Bob ask £5.50 → MATCH
           Quantity: 50,000 @ £5.50 = £275,000
           Charlie ask £6.50 > Alice bid £6.00 → NO MATCH
Step 8:  PaymentInstruction issued: Alice → Bob £275,000 GBP
Step 9:  MockPaymentProvider confirms instantly
Step 10: DVP settlement:
           Bob:   -50,000 shares / +£275,000 (simulated)
           Alice: +50,000 shares / -£275,000 (simulated)
Step 11: Attempt: Diana (retail) tries to buy from Charlie → REJECTED (AccreditedOnly)
Step 12: Print final chain state:
           Block count, all holdings, all trades, all credentials
```

### Expected terminal output (sample)

```
=== GreenHouse Private Placement Simulation ===

[INIT]    Genesis block added
[INIT]    P2P node started (mock mode)
[INIT]    Services: MockIdentityRegistry | MockPaymentProvider | MockOracleService

[KYC]     Credential issued: Alice   — Accredited / GB / Professional
[KYC]     Credential issued: Bob     — Accredited / DE / Professional
[KYC]     Credential issued: Charlie — Accredited / FR / EligibleCP
[KYC]     Credential issued: Diana   — Retail / GB
          (Diana flagged: retail investor, cannot hold AccreditedOnly assets)

[ASSET]   Issued: Acme Series B — 1,000,000 shares — GBP — AccreditedOnly
[ASSET]   Lockup: 365 days from issuance

[ALLOC]   Alice   receives 400,000 shares (LockedUntil: 2027-04-30)
[ALLOC]   Bob     receives 300,000 shares (LockedUntil: 2027-04-30)
[ALLOC]   Charlie receives 300,000 shares (LockedUntil: 2027-04-30)

[ORDER]   Alice   BID  50,000 shares @ £6.00 — ID: a1b2...
[ORDER]   Bob     ASK  50,000 shares @ £5.50 — ID: c3d4...
[ORDER]   Charlie ASK  25,000 shares @ £6.50 — ID: e5f6...

[CONSENSUS] Block #1 proposed — 3 orders, 3 alloc txs
[CONSENSUS] Delegates voted: 3/3 yes
[CONSENSUS] Block #1 finalised — hash: 3fa2...

[MATCH]   BID £6.00 >= ASK £5.50 → TRADE
[MATCH]   Quantity: 50,000 @ £5.50 = £275,000.00 GBP
[MATCH]   Trade ID: t7g8... | Buyer: Alice | Seller: Bob
[MATCH]   Charlie ASK £6.50 — no matching bid

[DVP]     PaymentInstruction: Alice → Bob  £275,000.00 GBP  Ref: GH-t7g8
[DVP]     MockPaymentProvider: confirmed instantly
[DVP]     OracleService: PaymentConfirmation signed
[DVP]     Asset delivery: Bob -50,000 / Alice +50,000
[DVP]     Settlement complete ✓

[REJECT]  Diana attempts to buy from Charlie
[REJECT]  Reason: AccreditedOnly asset — Diana is InvestorClassRetail
[REJECT]  Order rejected before reaching order book ✓

=== Final State ===
Chain:    4 blocks
Assets:   1 (Acme Series B — 1,000,000 shares in circulation)
Holdings: Alice 450,000 | Bob 250,000 | Charlie 300,000 | Diana 0
Trades:   1 (£275,000 settled)
Pending:  0 payment instructions
```

---

## Test Coverage Targets

Before Week 8 deployment, all tests must pass:

```bash
go test ./... -count=1
```

Expected coverage per file:

| File | Target coverage |
|---|---|
| `assets.go` | ≥ 90% |
| `identity.go` | ≥ 90% |
| `payment.go` (mock) | ≥ 85% |
| `orderbook.go` | ≥ 90% |
| `blockchain.go` (new code) | ≥ 80% |
| All existing files | Must not regress |

Run coverage report:

```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
open coverage.html
```

---

## Integration Checklist (end of Week 8)

- [ ] `go build ./...` — clean, zero warnings
- [ ] `go test ./...` — all tests pass (including all pre-existing tests)
- [ ] `go vet ./...` — zero issues
- [ ] `go run simulation/main.go` — prints full scenario, exits 0
- [ ] Simulation runs correctly with `MockPaymentProvider` instant confirmation
- [ ] Asset transfer correctly blocked for retail investor
- [ ] Asset transfer correctly blocked during lockup period
- [ ] Order matching produces correct trades (price-time priority)
- [ ] DVP: asset delivery only happens after payment confirmation
- [ ] All new `PaymentInstruction` / `PaymentConfirmation` messages are oracle-signed
- [ ] All existing 39 passing tests still pass

---

## What Remains Stubbed (Intentionally)

These are the integration points that are mocked now and swapped for real implementations
when external onboarding is complete:

| Stub | Production replacement | When needed |
|---|---|---|
| `MockPaymentProvider` | `ModulrPaymentProvider` implementing `PaymentProvider` | After Modulr onboarding |
| `MockIdentityRegistry` | `OnfidoIdentityRegistry` or `GreenHouseRegistryService` | Before first real user |
| `MockOracleService` | Oracle service backed by AWS KMS | Before real money moves |
| Local Ed25519 key | AWS KMS asymmetric key | Same as above |
| `SettlementSEPA` hardcoded | Participant-selected method | UX layer build |
| Simulation auto-signing | Off-chain seller co-signing flow | Mobile/web client build |

---

# GreenHouse — Phase 2 Implementation Plan

## Strategic Context

Phase 0 delivered the core private placement engine: tokenised assets, KYC credentials,
price-time priority order matching, and atomic DVP settlement. Phase 2 extends this
foundation to meet the specific demands of the **European Capital Market Union** agenda.

The European Commission's 2026 consultations on Intermittent Multilateral Trading Platforms,
the DLT Pilot Regime (Regulation EU 2022/858), and the Financial Data Access (FiDA)
Regulation collectively define the regulatory envelope GreenHouse must operate within and
can exploit as a structural advantage over legacy incumbents.

Five strategic themes drive Phase 2:

| Theme | Problem solved | Regulatory hook |
|---|---|---|
| Intermittent Liquidity Windows | Founders want controlled liquidity, not 24/7 price discovery | IMTP consultation |
| SPV / Participation Notes | German notary bottleneck blocks cross-border equity transfers | Prospectus Regulation Art 1(4) |
| Corporate Actions Engine | ROFR, drag-along, tag-along are manual legal nightmares | Company law automation |
| FiDA Reporting Layer | Family offices hold 15+ placements with no unified view | FiDA open finance mandate |
| API Gateway + KMS | Production keys, client auth, WebSocket feeds | DLT Pilot Regime pre-authorisation |

---

## Codebase Conventions — Phase 2 additions

All Phase 0 conventions continue unchanged. Additional conventions for Phase 2:

| Convention | Detail |
|---|---|
| New packages | `liquidity`, `corporate`, `reporting`, `api` — separate packages under module root |
| Time windows | All window boundaries are Unix timestamps; `time.Now().UTC()` throughout |
| Corporate actions | All proposals signed by proposer; execution requires threshold signatures |
| Reporting | All report types are JSON-serialisable and schema-versioned with `SchemaVersion string` |
| API auth | Ed25519 challenge-response; JWT issued post-auth; short-lived (15 min) |
| KMS interface | New `KeyProvider` interface in `keys.go`; local `LocalKeyProvider` + stub `KMSKeyProvider` |

---

## Week 1–2: Liquidity Windows

### Purpose

Replace the always-on order book with time-gated **Liquidity Windows** — quarterly
trading periods during which the order book opens, matches, and then closes. Between
windows, orders can be submitted but not matched. This is precisely the Intermittent
Multilateral Trading Platform model being consulted on by the European Commission.

### Files to create
- `liquidity.go`
- `liquidity_test.go`

---

### `liquidity.go` — Complete Specification

#### Types

```go
package gonetwork

type WindowStatus string

const (
    WindowStatusScheduled WindowStatus = "scheduled" // defined, not yet open
    WindowStatusOpen      WindowStatus = "open"       // accepting and matching orders
    WindowStatusClosed    WindowStatus = "closed"     // matching complete, book frozen
    WindowStatusCancelled WindowStatus = "cancelled"  // cancelled before open
)

// LiquidityWindow defines a time-bounded trading period for a single asset.
// Outside a window the order book accepts submissions but MatchOrders is a no-op.
type LiquidityWindow struct {
    ID          string
    AssetID     string
    OpenAt      int64        // Unix timestamp — window opens
    CloseAt     int64        // Unix timestamp — window closes; matching runs at CloseAt
    MaxVolume   float64      // 0 = unlimited volume in this window
    Currency    string
    Status      WindowStatus
    ProposerKey string       // issuer or platform operator public key
    Signature   []byte       // Sign(SHA3-256(window with Signature=nil))
}

// WindowResult is the settlement output of a completed Liquidity Window.
// It is committed to a block as part of window finalisation.
type WindowResult struct {
    WindowID       string
    AssetID        string
    TotalVolume    float64
    TotalValue     float64
    TradeCount     int
    ClearingPrice  float64  // volume-weighted average price across all matched trades
    ClosedAt       int64
}
```

#### Functions

```go
func NewLiquidityWindow(
    proposerKey *PrivateKey,
    assetID string,
    openAt, closeAt int64,
    maxVolume float64,
    currency string,
) (*LiquidityWindow, error)
// - validates: assetID not empty, openAt < closeAt, openAt > time.Now().Unix()
// - generates ID: hex(sha3.Sum256(proposerKey+assetID+openAt))
// - signs: marshal with Signature=nil, sha3.Sum256, Sign(proposerKey)

func (w *LiquidityWindow) IsOpen() bool
// - w.Status == WindowStatusOpen

func (w *LiquidityWindow) ShouldOpen() bool
// - w.Status == WindowStatusScheduled && time.Now().Unix() >= w.OpenAt

func (w *LiquidityWindow) ShouldClose() bool
// - w.Status == WindowStatusOpen && time.Now().Unix() >= w.CloseAt

func (w *LiquidityWindow) VerifySignature(proposerPubKey *PublicKey) bool
// - standard: marshal with Signature=nil, sha3.Sum256, verify

// WindowManager manages all windows for all assets on this blockchain.
// It is embedded in Blockchain in Week 1-2 integration.

type WindowManager struct {
    Windows  map[string]*LiquidityWindow  // windowID → window
    Schedule map[string][]*LiquidityWindow // assetID → ordered list of upcoming windows
}

func NewWindowManager() *WindowManager

func (wm *WindowManager) ScheduleWindow(w *LiquidityWindow) error
// - validates no overlapping window exists for the same asset
// - adds to Windows and Schedule

func (wm *WindowManager) Tick(bc *Blockchain) []WindowResult
// Called at the start of each finalizeBlock pass.
// - Transitions ShouldOpen windows → WindowStatusOpen
// - Transitions ShouldClose windows → WindowStatusClosed; runs MatchOrders for that asset
// - Returns WindowResult for each window just closed
// - Outside an open window, MatchOrders is suppressed for that asset in finalizeBlock
```

#### Integration with `Blockchain`

Add to `Blockchain` struct in `blockchain.go`:

```go
WindowManager *WindowManager
```

Initialise in `NewBlockchain`:

```go
bc.WindowManager = NewWindowManager()
```

Modify `finalizeBlock` step 5 (MatchOrders loop): before calling `ob.MatchOrders`,
check that the asset has an open window via `bc.WindowManager`. If no open window
exists for that asset, skip matching. The match runs only when the window closes.

#### P2P message type constant

```go
const MessageTypeLiquidityWindow = "liquidity_window"
```

---

### `liquidity_test.go` — Required Test Cases

| Test name | What it tests |
|---|---|
| `TestNewLiquidityWindow_Valid` | Creates window, verifies signature, fields correct |
| `TestNewLiquidityWindow_InvalidDates` | Rejects openAt >= closeAt |
| `TestNewLiquidityWindow_PastOpen` | Rejects openAt in the past |
| `TestWindowManager_ScheduleWindow` | Window scheduled, appears in asset schedule |
| `TestWindowManager_NoOverlap` | Rejects window overlapping existing scheduled window |
| `TestWindowManager_Tick_Opens` | Tick transitions scheduled → open when time reached |
| `TestWindowManager_Tick_Closes` | Tick transitions open → closed, returns WindowResult |
| `TestMatchingSuppressedOutsideWindow` | Orders submitted outside window are not matched |
| `TestMatchingRunsOnWindowClose` | Matching runs exactly when window closes |
| `TestWindowResult_VWAP` | ClearingPrice is volume-weighted average across all trades |
| `TestMultipleAssets_IndependentWindows` | Windows for different assets are independent |

---

## Week 2–3: SPV / Participation Notes

### Purpose

The German notary bottleneck makes direct equity token transfers legally impossible for
GmbH shares without a notarial act. Luxembourg RAIFs and Irish ICAVs provide a
well-established SPV wrapper: the SPV holds the underlying legal shares; investors hold
**Participation Notes** — on-chain instruments representing a proportional economic claim
on the SPV. This structure is cross-border clean, avoids notary requirements, and is
familiar to European family offices and institutional investors.

### Files to create
- `spv.go`
- `spv_test.go`

---

### `spv.go` — Complete Specification

#### Types

```go
package gonetwork

type SPVJurisdiction string

const (
    SPVJurisdictionLuxembourg SPVJurisdiction = "LU" // RAIF / SCSp
    SPVJurisdictionIreland    SPVJurisdiction = "IE" // ICAV / DAC
    SPVJurisdictionNetherlands SPVJurisdiction = "NL" // BV / Coöperatie
    SPVJurisdictionCayman     SPVJurisdiction = "KY" // used for APAC / US investors
)

// SPVWrapper represents the legal vehicle that holds underlying company shares.
// The SPV admin key is held by the fund administrator (e.g., Aztec Group, Intertrust).
type SPVWrapper struct {
    ID                      string
    Name                    string
    Jurisdiction            SPVJurisdiction
    UnderlyingCompanyID     string  // the company whose shares the SPV holds
    UnderlyingShareClass    string  // e.g. "Series B Preferred"
    SPVAdminKey             string  // public key of the licensed fund administrator
    NAV                     float64 // Net Asset Value per unit — updated by oracle
    NAVUpdatedAt            int64
    LegalDocHash            string  // SHA3-256 of SPV formation document
    Signature               []byte  // signed by SPVAdminKey
}

// ParticipationNote is an AssetType extension.
// When AssetType == AssetTypeParticipationNote, Asset.Metadata.ISIN
// holds the SPV's ISIN and the asset maps 1:1 to an SPVWrapper.ID.
// Add to AssetType constants:
const AssetTypeParticipationNote AssetType = "participation_note"
const AssetTypeDepositoryReceipt AssetType = "depositary_receipt"

// SPVTransaction records a corporate event at the SPV level that affects
// all note holders proportionally (e.g., a dividend from the underlying company).
type SPVTransaction struct {
    ID          string
    SPVID       string
    Type        SPVTxType
    AmountPerUnit float64
    Currency    string
    EffectiveAt int64
    AdminKey    string  // SPV admin who authorised this
    Signature   []byte
}

type SPVTxType string

const (
    SPVTxTypeDividendDistribution SPVTxType = "dividend"
    SPVTxTypeNAVUpdate            SPVTxType = "nav_update"
    SPVTxTypeCapitalCall          SPVTxType = "capital_call"
    SPVTxTypeWindingUp            SPVTxType = "winding_up"
)
```

#### Functions

```go
func NewSPVWrapper(
    adminKey *PrivateKey,
    name string,
    jurisdiction SPVJurisdiction,
    underlyingCompanyID string,
    underlyingShareClass string,
    legalDocHash string,
) (*SPVWrapper, error)
// - validates all required fields non-empty
// - generates ID: hex(sha3.Sum256(adminKey+name+jurisdiction+underlyingCompanyID))
// - signs the wrapper

func (s *SPVWrapper) VerifySignature(adminPubKey *PublicKey) bool

func (s *SPVWrapper) UpdateNAV(
    newNAV float64,
    adminKey *PrivateKey,
) (*SPVTransaction, error)
// - creates an SPVTransaction of type NAVUpdate
// - updates s.NAV and s.NAVUpdatedAt
// - returns signed SPVTransaction for broadcast

func NewSPVTransaction(
    adminKey *PrivateKey,
    spvID string,
    txType SPVTxType,
    amountPerUnit float64,
    currency string,
    effectiveAt int64,
) (*SPVTransaction, error)

// ApplySPVTransaction distributes a dividend or capital call across all
// note holders proportionally, creating AssetTransactions for each holder.
func ApplySPVTransaction(
    spvTx *SPVTransaction,
    spv *SPVWrapper,
    asset *Asset,
    holdings map[string]*AssetHolding,
    paymentProvider PaymentProvider,
) ([]PaymentInstruction, error)
// For SPVTxTypeDividendDistribution:
//   For each holder: instruction = PaymentInstruction{
//     TotalAmount: holding.Balance * spvTx.AmountPerUnit,
//     PayeeWalletID: holderID,
//     PayerWalletID: spv.SPVAdminKey,
//   }
// Returns all instructions for signing by oracle before broadcast.
```

#### Integration with `Blockchain`

Add to `Blockchain` struct:

```go
SPVs map[string]*SPVWrapper  // spvID → SPVWrapper
```

Initialise in `NewBlockchain`: `bc.SPVs = make(map[string]*SPVWrapper)`

#### P2P message type constants

```go
const MessageTypeSPVTransaction = "spv_transaction"
```

---

### `spv_test.go` — Required Test Cases

| Test name | What it tests |
|---|---|
| `TestNewSPVWrapper_Valid` | Creates SPV, verifies admin signature |
| `TestNewSPVWrapper_MissingFields` | Rejects empty required fields |
| `TestSPVWrapper_UpdateNAV` | NAV and timestamp update; returns signed SPVTransaction |
| `TestApplySPVTransaction_Dividend` | Three note holders, correct proportional instructions |
| `TestApplySPVTransaction_ZeroBalance` | Holders with zero balance receive no instruction |
| `TestSPVAssetLink` | ParticipationNote asset correctly references SPV ID via ISIN |
| `TestSPVSignatureTampering` | Mutated SPVWrapper fails VerifySignature |

---

## Week 3–4: Corporate Actions Engine

### Purpose

Right of First Refusal, drag-along, and tag-along rights are the three most common
contractual constraints on private company share transfers. Today these are enforced via
manual legal processes taking weeks and costing thousands in legal fees. GreenHouse encodes
them as on-chain rules: any transfer that triggers a ROFR is automatically paused,
existing holders are notified (via P2P broadcast), and their response is recorded
on-chain with a deadline enforced by block timestamp.

### Files to create
- `corporate.go`
- `corporate_test.go`

---

### `corporate.go` — Complete Specification

#### Types

```go
package gonetwork

type CorporateActionType string

const (
    CorporateActionROFR      CorporateActionType = "rofr"       // right of first refusal
    CorporateActionDragAlong CorporateActionType = "drag_along" // majority forces minority to sell
    CorporateActionTagAlong  CorporateActionType = "tag_along"  // minority joins majority sale
    CorporateActionDividend  CorporateActionType = "dividend"   // cash distribution to holders
)

type CorporateActionStatus string

const (
    CorporateActionPending   CorporateActionStatus = "pending"   // awaiting responses
    CorporateActionApproved  CorporateActionStatus = "approved"  // threshold met
    CorporateActionRejected  CorporateActionStatus = "rejected"  // threshold not met or lapsed
    CorporateActionExecuted  CorporateActionStatus = "executed"  // transfer completed
    CorporateActionLapsed    CorporateActionStatus = "lapsed"    // deadline passed without action
)

// CorporateAction is created automatically when a transfer triggers a ROFR
// or when an issuer initiates a drag-along/tag-along event.
type CorporateAction struct {
    ID              string
    AssetID         string
    Type            CorporateActionType
    Status          CorporateActionStatus
    ProposerKey     string   // wallet initiating the action
    TargetTransfer  *AssetTransaction // the transfer being evaluated (nil for drag/tag)
    PricePerUnit    float64
    TotalUnits      float64
    DeadlineAt      int64   // Unix timestamp — action lapses after this
    Responses       map[string]bool // holderKey → exercised (true) / waived (false)
    RequiredThreshold float64       // 0-1 fraction of circulating supply needed
    ProposerSignature []byte
}

// CorporateActionResponse is broadcast by a holder exercising or waiving a right.
type CorporateActionResponse struct {
    ActionID    string
    HolderKey   string
    Exercised   bool    // true = exercising right; false = waiving
    Signature   []byte  // Sign(SHA3-256(ActionID+HolderKey+Exercised))
}
```

#### Functions

```go
func NewCorporateAction(
    proposerKey *PrivateKey,
    assetID string,
    actionType CorporateActionType,
    targetTransfer *AssetTransaction,
    pricePerUnit float64,
    totalUnits float64,
    deadlineDays int,
    requiredThreshold float64,
) (*CorporateAction, error)
// - generates ID from sha3 of proposerKey+assetID+actionType+time
// - sets DeadlineAt = time.Now().Unix() + int64(deadlineDays*86400)
// - initialises Responses as empty map
// - signs with proposerKey

func (ca *CorporateAction) RecordResponse(
    resp *CorporateActionResponse,
    holderPubKey *PublicKey,
) error
// - verifies resp.Signature
// - verifies resp.HolderKey matches holderPubKey
// - records in ca.Responses[resp.HolderKey]
// - returns error if action is not Pending or if deadline has passed

func (ca *CorporateAction) IsLapsed() bool
// return time.Now().Unix() > ca.DeadlineAt

func (ca *CorporateAction) TallyROFR(
    holdings map[string]*AssetHolding,
) (exercisedFraction float64, totalCirculating float64)
// Sums Balance of all holders who Exercised == true
// Returns that sum as a fraction of totalCirculating supply

// CheckROFR is called from AssetTransaction.Validate before allowing a transfer.
// If the asset has ROFR terms (TransferRestrictions.HasROFR — add this field to
// TransferRestrictions in assets.go), it creates a CorporateAction and returns
// a sentinel error ErrROFRTriggered. The transfer is suspended until the action
// resolves. If all holders waive or the deadline lapses, the transfer proceeds.
func CheckROFR(
    at *AssetTransaction,
    asset *Asset,
    holdings map[string]*AssetHolding,
    pendingActions map[string]*CorporateAction,
) (triggered bool, action *CorporateAction, err error)

// ExecuteDragAlong is called by the issuer when threshold holders have agreed to sell.
// It generates AssetTransactions for all minority holders on the same terms.
func ExecuteDragAlong(
    action *CorporateAction,
    holdings map[string]*AssetHolding,
    buyerKey string,
) ([]*AssetTransaction, error)
```

#### Add to `TransferRestrictions` in `assets.go`

```go
HasROFR       bool    // triggers CorporateAction on every transfer
ROFRDays      int     // notice period in days (default 30)
DragThreshold float64 // 0-1 fraction required to trigger drag-along (0 = disabled)
TagAlongRight bool    // minority holders may join any majority sale on same terms
```

#### Add to `Blockchain` struct

```go
PendingCorporateActions map[string]*CorporateAction // actionID → action
```

#### P2P message type constants

```go
const MessageTypeCorporateAction         = "corporate_action"
const MessageTypeCorporateActionResponse = "corporate_action_response"
```

---

### `corporate_test.go` — Required Test Cases

| Test name | What it tests |
|---|---|
| `TestNewCorporateAction_Valid` | Creates ROFR action, signature valid |
| `TestRecordResponse_Exercise` | Holder exercises ROFR; recorded correctly |
| `TestRecordResponse_Waive` | Holder waives ROFR; recorded correctly |
| `TestRecordResponse_Expired` | Response after deadline rejected |
| `TestTallyROFR_AllWaive` | All holders waive; exercisedFraction = 0 |
| `TestTallyROFR_Partial` | Some holders exercise; fraction calculated correctly |
| `TestCheckROFR_Triggered` | Transfer on ROFR-flagged asset returns ErrROFRTriggered |
| `TestCheckROFR_NotApplicable` | Transfer on non-ROFR asset proceeds normally |
| `TestExecuteDragAlong_ProducesTransactions` | Minority holders get AssetTransactions on drag terms |
| `TestCorporateAction_Lapsed` | IsLapsed returns true after DeadlineAt |
| `TestTagAlong_MinorityJoins` | Tag-along holder can attach to majority sale |

---

## Week 4–5: Multi-Jurisdiction Compliance Engine

### Purpose

The Prospectus Regulation (EU 2017/1129) Art 1(4) exempts placements to fewer than
150 non-professional investors per EU member state. GreenHouse must track this per-asset,
per-jurisdiction at all times. Additionally, MiFID II Article 25 requires suitability
assessments for complex instruments. This week encodes these rules as on-chain enforcement,
replacing the current single-level AccreditedOnly flag with a full jurisdictional rule engine.

### Files to create
- `compliance.go`
- `compliance_test.go`

---

### `compliance.go` — Complete Specification

#### Types

```go
package gonetwork

// ProspectusExemption tracks the regulatory basis for a placement
// and enforces its limits automatically.
type ProspectusExemption struct {
    AssetID           string
    Basis             ExemptionBasis
    MaxRetailPerJurisdiction int  // typically 149 (i.e., < 150)
    MaxTicketSizeEUR  float64     // 0 = no limit
    JurisdictionCoverage []string // ISO codes of target jurisdictions; empty = EU-wide
    // Live holder counts — maintained by finalizeBlock
    RetailHoldersByJurisdiction map[string]int // jurisdictionCode → count
}

type ExemptionBasis string

const (
    ExemptionProspectusArt1_4 ExemptionBasis = "prospectus_art1_4" // < 150 retail / state
    ExemptionQIBOnly          ExemptionBasis = "qib_only"           // qualified investors only
    ExemptionPilotRegime      ExemptionBasis = "dlt_pilot"          // EU DLT Pilot Regime
)

// SuitabilityAssessment is the MiFID II Article 25 record.
// For complex instruments (warrants, convertibles) a suitability check is mandatory.
type SuitabilityAssessment struct {
    WalletPublicKey   string
    AssetID           string
    InstrumentClass   AssetType
    AssessedAt        int64
    // Suitability flags — set by the onboarding flow or assessment tool
    HasSufficientKnowledge  bool
    HasSufficientExperience bool
    CanAbsorbLoss           bool
    Suitable                bool  // final determination
    RegistrySignature       []byte // signed by IdentityRegistry
}

// JurisdictionRule encodes country-specific transfer constraints that are
// layered on top of the global AccreditedOnly / MaxHolders rules.
type JurisdictionRule struct {
    CountryCode        string
    MaxRetailHolders   int      // 0 = unlimited
    RequiresSuitability bool    // true for MiFID II complex instruments
    BlockedAssetTypes  []AssetType
    MinTicketSizeEUR   float64
    MaxTicketSizeEUR   float64  // 0 = no limit
}
```

#### Functions

```go
func NewProspectusExemption(
    assetID string,
    basis ExemptionBasis,
    maxRetailPerJurisdiction int,
    jurisdictions []string,
) *ProspectusExemption

// CheckProspectusLimits is called from CheckTransferEligibility when
// asset.Exemption is set. Returns an error if adding this holder would
// breach the per-jurisdiction retail cap.
func CheckProspectusLimits(
    receiverCredential *CredentialAttestation,
    exemption *ProspectusExemption,
) error

// CheckSuitability returns an error if the instrument requires a suitability
// assessment and none exists for this wallet, or if the assessment is negative.
func CheckSuitability(
    walletKey string,
    asset *Asset,
    assessments map[string]*SuitabilityAssessment,
) error

// ApplyJurisdictionRule checks a JurisdictionRule against a proposed transfer.
func ApplyJurisdictionRule(
    rule *JurisdictionRule,
    senderCredential *CredentialAttestation,
    receiverCredential *CredentialAttestation,
    ticketValueEUR float64,
) error

// UpdateRetailCounts rebuilds RetailHoldersByJurisdiction from the current holdings
// and credentials maps. Called at the end of finalizeBlock.
func UpdateRetailCounts(
    exemption *ProspectusExemption,
    holdings map[string]*AssetHolding,
    credentials map[string]*CredentialAttestation,
)
```

#### Integration with `Blockchain`

Add to `Blockchain` struct:

```go
ProspectusExemptions  map[string]*ProspectusExemption    // assetID → exemption
SuitabilityAssessments map[string]*SuitabilityAssessment // walletKey:assetID → assessment
JurisdictionRules     map[string]*JurisdictionRule       // countryCode → rule
```

---

### `compliance_test.go` — Required Test Cases

| Test name | What it tests |
|---|---|
| `TestProspectusLimit_UnderCap` | 148 retail holders → 149th transfer allowed |
| `TestProspectusLimit_AtCap` | 149 retail holders → 150th transfer blocked |
| `TestProspectusLimit_ProfessionalExcluded` | Professional investors do not count toward cap |
| `TestProspectusLimit_PerJurisdiction` | GB at cap does not block DE transfer |
| `TestSuitability_Pass` | Suitable assessment → transfer allowed |
| `TestSuitability_Fail` | Negative assessment → complex instrument blocked |
| `TestSuitability_Missing` | No assessment → complex instrument blocked |
| `TestSuitability_NotRequired` | Standard equity → suitability not checked |
| `TestJurisdictionRule_MinTicket` | Transfer below MinTicketSizeEUR blocked |
| `TestJurisdictionRule_BlockedAssetType` | Asset type blocked in jurisdiction |
| `TestUpdateRetailCounts_Accurate` | Counts match actual retail holders by jurisdiction |

---

## Week 5–6: FiDA Reporting Layer

### Purpose

Under the Financial Data Access (FiDA) Regulation coming into force in 2026–2027, financial
institutions must provide machine-readable data to authorised third-party data aggregators on
participant request. GreenHouse must produce standardised holdings reports and tax-event
records per EU jurisdiction. This is also the primary value proposition to family offices:
a single, auditable view of all private market holdings with tax-ready output.

### Files to create
- `reporting.go`
- `reporting_test.go`

---

### `reporting.go` — Complete Specification

#### Types

```go
package gonetwork

// HoldingsReport is a FiDA-compliant snapshot of a wallet's holdings at a point in time.
type HoldingsReport struct {
    SchemaVersion   string  // "1.0"
    WalletPublicKey string
    GeneratedAt     int64
    Holdings        []HoldingSnapshot
}

type HoldingSnapshot struct {
    AssetID        string
    AssetName      string
    AssetType      AssetType
    ISIN           string
    Balance        float64
    Currency       string
    NAVPerUnit     float64  // from SPV oracle or last known price
    TotalValue     float64  // Balance * NAVPerUnit
    AcquisitionCost float64 // total cost basis (sum of purchase prices)
    UnrealisedPnL  float64  // TotalValue - AcquisitionCost
    LockedUntil    int64   // 0 = freely transferable
}

// TaxReport contains taxable events for a wallet in a given tax year,
// formatted to cover major EU jurisdiction requirements (UK CGT, German KeSt,
// French PFU, Dutch Box 3).
type TaxReport struct {
    SchemaVersion   string
    WalletPublicKey string
    TaxYear         int
    Jurisdiction    string // ISO 3166-1 alpha-2
    Currency        string // reporting currency
    Events          []TaxableEvent
    TotalGain       float64
    TotalLoss       float64
    NetGainLoss     float64
}

type TaxableEventType string

const (
    TaxEventAcquisition  TaxableEventType = "acquisition"
    TaxEventDisposal     TaxableEventType = "disposal"
    TaxEventDividend     TaxableEventType = "dividend"
    TaxEventCapitalCall  TaxableEventType = "capital_call"
)

type TaxableEvent struct {
    Date        int64
    AssetID     string
    Type        TaxableEventType
    Units       float64
    UnitPrice   float64
    Proceeds    float64  // Units * UnitPrice (for disposal)
    CostBasis   float64  // original acquisition cost (for disposal)
    GainLoss    float64  // Proceeds - CostBasis (for disposal)
    Currency    string
    TradeID     string  // links back to the Trade record
}

// ValuationOracle provides current NAV or price per unit for an asset.
// MockValuationOracle returns the last trade price or par value.
type ValuationOracle interface {
    GetValuation(assetID string) (float64, error)
    GetCurrencyRate(from, to string) (float64, error)  // for FX conversion
}

// CostBasisTracker maintains a per-wallet, per-asset acquisition cost record
// using FIFO matching (standard for EU CGT purposes).
type CostBasisTracker struct {
    // walletKey:assetID → ordered acquisition lots
    Lots map[string][]AcquisitionLot
}

type AcquisitionLot struct {
    AcquiredAt  int64
    Units       float64
    UnitCost    float64
    TradeID     string
}
```

#### Functions

```go
func GenerateHoldingsReport(
    walletKey string,
    holdings map[string]*AssetHolding,
    assets map[string]*Asset,
    valuation ValuationOracle,
    tracker *CostBasisTracker,
) (*HoldingsReport, error)
// Iterates all holdings for walletKey, populates HoldingSnapshot for each,
// calls valuation.GetValuation for NAV, calculates UnrealisedPnL.

func GenerateTaxReport(
    walletKey string,
    taxYear int,
    jurisdiction string,
    reportCurrency string,
    trades []Trade,
    assets map[string]*Asset,
    tracker *CostBasisTracker,
    valuation ValuationOracle,
) (*TaxReport, error)
// Filters trades for walletKey in taxYear.
// For each disposal: matches against FIFO cost lots, calculates GainLoss.
// Converts to reportCurrency via valuation.GetCurrencyRate.
// Applies jurisdiction-specific rules:
//   GB:  CGT — annual exempt amount applied (£3,000 in 2026)
//   DE:  Kapitalertragsteuer — 25% flat; no annual exempt for disposals
//   FR:  PFU (Flat Tax) — 30% on net gain
//   NL:  Box 3 — assets valued at 1 Jan; no CGT on individual trades

func (t *CostBasisTracker) RecordAcquisition(
    walletKey, assetID string,
    lot AcquisitionLot,
)

func (t *CostBasisTracker) ConsumeForDisposal(
    walletKey, assetID string,
    units float64,
    disposalDate int64,
) (costBasis float64, lotsConsumed []AcquisitionLot, err error)
// FIFO: consumes earliest lots first. Returns total cost basis for the units disposed.

// MarshalFiDA returns the report as a FiDA-compliant JSON byte slice.
func (r *HoldingsReport) MarshalFiDA() ([]byte, error)
func (r *TaxReport) MarshalFiDA() ([]byte, error)
```

#### Integration with `Blockchain`

Add to `Blockchain` struct:

```go
CostBasisTracker  *CostBasisTracker
ValuationOracle   ValuationOracle
```

`NewBlockchain`: initialise with `MockValuationOracle` (returns last trade price or par).

In `finalizeBlock`, after applying asset transactions, call
`bc.CostBasisTracker.RecordAcquisition` for each new holding created.

---

### `reporting_test.go` — Required Test Cases

| Test name | What it tests |
|---|---|
| `TestGenerateHoldingsReport_SingleAsset` | One holding, correct value and PnL |
| `TestGenerateHoldingsReport_MultiAsset` | Multiple holdings across different assets |
| `TestGenerateHoldingsReport_EmptyWallet` | Returns empty report, no error |
| `TestCostBasisTracker_FIFO` | Disposal consumes oldest lots first |
| `TestCostBasisTracker_PartialLot` | Disposal consuming part of a lot |
| `TestCostBasisTracker_InsufficientUnits` | Returns error if disposal exceeds held units |
| `TestGenerateTaxReport_Gain` | Disposal at profit produces positive GainLoss |
| `TestGenerateTaxReport_Loss` | Disposal at loss produces negative GainLoss |
| `TestGenerateTaxReport_GBExemptAmount` | UK £3,000 annual CGT exempt amount applied |
| `TestGenerateTaxReport_FXConversion` | EUR-denominated trade converted to GBP correctly |
| `TestGenerateTaxReport_FiltersByYear` | Only events in taxYear included |
| `TestMarshalFiDA_HoldingsReport` | Output is valid JSON with SchemaVersion field |

---

## Week 6–7: Lead Investor / Deal Anchoring

### Purpose

Unlike retail crowdfunding platforms, GreenHouse targets professional and family office
investors. The **Lead Investor** model requires a reputable anchor (a named VC or Family
Office) to commit a minimum stake before a placement opens to other participants. This
signals quality, reduces adverse selection, and creates the social proof required by
co-investors. The entire anchor commitment and co-investment process is on-chain and
cryptographically verifiable.

### Files to create
- `deal.go`
- `deal_test.go`

---

### `deal.go` — Complete Specification

#### Types

```go
package gonetwork

type DealStatus string

const (
    DealStatusDraft     DealStatus = "draft"      // created, no anchor yet
    DealStatusAnchoring DealStatus = "anchoring"  // anchor invited, awaiting commitment
    DealStatusAnchored  DealStatus = "anchored"   // anchor committed; open to co-investors
    DealStatusLive      DealStatus = "live"        // liquidity window open
    DealStatusClosed    DealStatus = "closed"      // fully subscribed or window closed
    DealStatusFailed    DealStatus = "failed"      // anchor did not commit by deadline
)

// Deal is the top-level record for a private placement.
// It ties together an Asset, a ProspectusExemption, an optional SPVWrapper,
// a LiquidityWindow, and the anchor commitment.
type Deal struct {
    ID                  string
    AssetID             string
    SPVID               string       // empty if asset issued directly (non-SPV)
    IssuerKey           string
    Status              DealStatus
    TargetRaiseAmount   float64
    MinAnchorFraction   float64      // minimum anchor as fraction of TargetRaiseAmount (e.g. 0.20)
    AnchorDeadlineAt    int64
    Anchor              *DealAnchor  // nil until an anchor commits
    CoInvestors         []*DealCommitment
    LiquidityWindowID   string
    CreatedAt           int64
    IssuerSignature     []byte
}

// DealAnchor is the commitment record of the lead investor.
type DealAnchor struct {
    DealID               string
    AnchorWalletKey      string
    CommitmentAmount     float64
    Currency             string
    CommittedAt          int64
    CredentialAttestation *CredentialAttestation // must be accredited + valid
    AnchorSignature      []byte  // Sign(SHA3-256(DealID+AnchorWalletKey+CommitmentAmount))
}

// DealCommitment is an individual co-investor's subscription intent.
// It becomes binding once the deal moves to DealStatusLive.
type DealCommitment struct {
    DealID          string
    InvestorKey     string
    CommitmentAmount float64
    Currency        string
    CommittedAt     int64
    Signature       []byte
}
```

#### Functions

```go
func NewDeal(
    issuerKey *PrivateKey,
    assetID string,
    spvID string,
    targetRaiseAmount float64,
    minAnchorFraction float64,
    anchorDeadlineDays int,
) (*Deal, error)
// - validates targetRaiseAmount > 0, minAnchorFraction in (0, 1]
// - sets AnchorDeadlineAt = time.Now().Unix() + int64(anchorDeadlineDays*86400)
// - signs with issuerKey

func (d *Deal) AttachAnchor(
    anchor *DealAnchor,
    anchorPubKey *PublicKey,
    credentials map[string]*CredentialAttestation,
) error
// - verifies AnchorSignature
// - verifies anchor's credential IsAccredited()
// - verifies CommitmentAmount >= d.TargetRaiseAmount * d.MinAnchorFraction
// - transitions d.Status DealStatusAnchoring → DealStatusAnchored

func (d *Deal) AddCoInvestor(
    commitment *DealCommitment,
    investorPubKey *PublicKey,
    credentials map[string]*CredentialAttestation,
) error
// - verifies Signature
// - verifies investor credential IsValid()
// - allowed only when d.Status == DealStatusAnchored or DealStatusLive
// - appends to d.CoInvestors

func (d *Deal) TotalCommitted() float64
// returns Anchor.CommitmentAmount + sum(CoInvestors.CommitmentAmount)

func (d *Deal) IsOversubscribed() bool
// return d.TotalCommitted() >= d.TargetRaiseAmount

func (d *Deal) CheckAnchorDeadline() bool
// if now > AnchorDeadlineAt && d.Anchor == nil → set Status = Failed, return true
// returns true if deal was failed by this call

// P2P message type constant
const MessageTypeDealAnchor     = "deal_anchor"
const MessageTypeDealCommitment = "deal_commitment"
```

#### Integration with `Blockchain`

Add to `Blockchain` struct:

```go
Deals map[string]*Deal  // dealID → Deal
```

---

### `deal_test.go` — Required Test Cases

| Test name | What it tests |
|---|---|
| `TestNewDeal_Valid` | Deal created, issuer signature valid |
| `TestNewDeal_InvalidFraction` | minAnchorFraction outside (0,1] rejected |
| `TestAttachAnchor_Valid` | Anchor commitment meets minimum; status → Anchored |
| `TestAttachAnchor_BelowMinimum` | Commitment below min fraction rejected |
| `TestAttachAnchor_RetailInvestor` | Retail anchor credential rejected |
| `TestAttachAnchor_ExpiredCredential` | Expired credential rejected |
| `TestAddCoInvestor_Valid` | Co-investor added when deal is Anchored |
| `TestAddCoInvestor_DealNotAnchored` | Co-investor rejected when deal is Draft |
| `TestTotalCommitted_SumCorrect` | Anchor + co-investors summed correctly |
| `TestIsOversubscribed_True` | Total >= target → true |
| `TestCheckAnchorDeadline_Fails` | Deadline passed, no anchor → DealStatusFailed |
| `TestCheckAnchorDeadline_NotYet` | Deadline not passed → no state change |

---

## Week 7–8: API Gateway + Production Key Management

### Purpose

Phase 2 concludes by exposing the blockchain operations through an authenticated REST API,
enabling web and mobile clients to interact with the platform without running a full node.
Simultaneously, the local Ed25519 key model is replaced with a `KeyProvider` interface
that can be backed by AWS KMS or HashiCorp Vault, eliminating the critical security risk
of keys in process memory.

### Files to create
- `keymanager.go`
- `keymanager_test.go`
- `api/server.go`
- `api/handlers.go`
- `api/middleware.go`

---

### `keymanager.go` — Complete Specification

```go
package gonetwork

// KeyProvider abstracts key storage and signing.
// LocalKeyProvider uses the existing in-memory PrivateKey.
// KMSKeyProvider (stub) signs via AWS KMS API calls.
type KeyProvider interface {
    // PublicKey returns the provider's public key for identity purposes.
    PublicKeyString() string

    // Sign returns an Ed25519 signature over msg.
    // For KMSKeyProvider this makes an AWS KMS Sign API call.
    Sign(msg []byte) ([]byte, error)

    // Verify verifies a signature.
    Verify(msg, sig []byte) bool
}

type LocalKeyProvider struct {
    key *PrivateKey
}

func NewLocalKeyProvider(key *PrivateKey) *LocalKeyProvider

func (p *LocalKeyProvider) PublicKeyString() string
func (p *LocalKeyProvider) Sign(msg []byte) ([]byte, error)
func (p *LocalKeyProvider) Verify(msg, sig []byte) bool

// KMSKeyProvider is a stub that records intended API calls.
// Replace with real AWS SDK calls when KMS onboarding is complete.
type KMSKeyProvider struct {
    KeyARN    string
    KeyID     string
    PublicKey string // cached from KMS DescribeKey
    // Calls records all invocations for test assertion.
    Calls     []string
}

func NewKMSKeyProvider(keyARN string) *KMSKeyProvider

func (p *KMSKeyProvider) PublicKeyString() string
func (p *KMSKeyProvider) Sign(msg []byte) ([]byte, error)
// Stub: appends "Sign" to p.Calls, returns nil sig and nil error.
// Production: calls kms.Sign(keyARN, msg, "ECDSA_SHA_256")
func (p *KMSKeyProvider) Verify(msg, sig []byte) bool
// Stub: appends "Verify" to p.Calls, returns true.
```

---

### `api/server.go` — Complete Specification

```go
package api

// Server wraps the blockchain and exposes it over HTTP.
// Authentication: Ed25519 challenge-response → short-lived JWT (15 min).
// All write endpoints require a valid JWT.
// Rate limiting: 100 req/min per IP for reads; 20 req/min for writes.

type Server struct {
    bc         *gonetwork.Blockchain
    jwtSecret  []byte  // random 32 bytes at startup; not persisted (restart invalidates tokens)
    listenAddr string
}

func NewServer(bc *gonetwork.Blockchain, listenAddr string) *Server

func (s *Server) Start() error
// Registers all routes and starts http.ListenAndServe

func (s *Server) Routes() http.Handler
// Returns the fully configured router with all middleware applied
```

#### Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/auth/challenge` | None | Returns a random challenge nonce |
| `POST` | `/v1/auth/verify` | None | Verify Ed25519 sig over challenge; returns JWT |
| `GET` | `/v1/assets` | JWT | List all assets |
| `POST` | `/v1/assets` | JWT | Issue a new asset (issuer role) |
| `GET` | `/v1/assets/{id}` | JWT | Get asset details |
| `GET` | `/v1/holdings/{walletKey}` | JWT | Holdings report for a wallet |
| `POST` | `/v1/orders` | JWT | Place an order |
| `DELETE` | `/v1/orders/{id}` | JWT | Cancel an order |
| `GET` | `/v1/orderbook/{assetID}` | JWT | Current order book state |
| `GET` | `/v1/trades` | JWT | Trade history (filterable by assetID, walletKey) |
| `GET` | `/v1/deals` | JWT | List all deals |
| `POST` | `/v1/deals` | JWT | Create a new deal (issuer role) |
| `POST` | `/v1/deals/{id}/anchor` | JWT | Attach anchor commitment |
| `POST` | `/v1/deals/{id}/commit` | JWT | Add co-investor commitment |
| `GET` | `/v1/reporting/holdings` | JWT | FiDA holdings report (JSON) |
| `GET` | `/v1/reporting/tax/{year}` | JWT | Tax report for year and jurisdiction |
| `GET` | `/v1/blocks` | None | Recent blocks (last 50) |
| `GET` | `/v1/health` | None | Service health and version |

#### `api/middleware.go`

```go
// JWTMiddleware validates the Bearer token on all protected routes.
// CORSMiddleware sets appropriate CORS headers for the web client.
// RateLimitMiddleware enforces per-IP rate limits using a sliding window.
// LoggingMiddleware logs method, path, status, duration in structured JSON.
```

---

### `keymanager_test.go` — Required Test Cases

| Test name | What it tests |
|---|---|
| `TestLocalKeyProvider_SignVerify` | Sign then verify with same provider |
| `TestLocalKeyProvider_CrossVerify` | Signature verifiable by raw PublicKey |
| `TestKMSKeyProvider_SignRecordsCall` | Stub records Sign call in Calls slice |
| `TestKMSKeyProvider_VerifyRecordsCall` | Stub records Verify call |
| `TestKeyProvider_Interface` | LocalKeyProvider satisfies KeyProvider interface |

---

## Phase 2 Integration Checklist

At the end of Phase 2, all of the following must pass:

- [ ] `go build ./...` — clean
- [ ] `go test ./...` — all Phase 1 and Phase 2 tests pass
- [ ] `go vet ./...` — zero issues
- [ ] Liquidity Window: orders submitted outside window are not matched
- [ ] Liquidity Window: matching runs on window close, VWAP calculated
- [ ] SPV: Participation Note issuance with admin signature verified
- [ ] SPV: Dividend distribution creates correct per-holder payment instructions
- [ ] ROFR: transfer on flagged asset pauses and broadcasts CorporateAction
- [ ] Drag-along: ExecuteDragAlong produces signed AssetTransactions for all minority holders
- [ ] Prospectus limit: 150th retail investor blocked per jurisdiction
- [ ] Suitability: complex instrument blocked without positive assessment
- [ ] Holdings report: FiDA-compliant JSON with correct valuations and PnL
- [ ] Tax report: FIFO cost basis correct; GBP, EUR, DE jurisdictions tested
- [ ] Deal anchoring: deal moves to Anchored only when minimum fraction committed
- [ ] API: JWT auth flow (challenge → verify → protected endpoint) end-to-end
- [ ] API: rate limiter blocks excessive requests
- [ ] KMS stub: LocalKeyProvider and KMSKeyProvider both satisfy KeyProvider interface
- [ ] All Phase 0 tests still pass (zero regressions)

---

## What Remains Stubbed After Phase 2 (Intentionally)

| Stub | Production replacement | When needed |
|---|---|---|
| `MockValuationOracle` | Live price feed (Bloomberg / Refinitiv) or SPV NAV oracle | Before reporting goes live |
| `KMSKeyProvider` (stub) | Real AWS KMS `Sign` + `DescribeKey` API calls | Before real money moves |
| `GetCurrencyRate` stub | ECB FX rate feed | Before multi-currency reporting |
| `JurisdictionRule` static config | Regulatory rules database with update mechanism | Before expanding to new jurisdictions |
| Tax calculation stubs (DE, FR, NL) | Jurisdiction-specific accountant review + legal sign-off | Before tax reports sent to users |
| `api/server.go` HTTP layer | TLS termination via reverse proxy (nginx / AWS ALB) | Before public access |
| Anchor commitment (off-chain legal) | Legal commitment deed linked via `LegalDocHash` | Before accepting real anchor capital |
