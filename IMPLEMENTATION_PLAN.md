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
