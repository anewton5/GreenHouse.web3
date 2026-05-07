package gonetwork

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// Asset types
// ---------------------------------------------------------------------------

// AssetType classifies the financial instrument being tokenised.
type AssetType string

const (
	AssetTypeEquity      AssetType = "equity"
	AssetTypeDebt        AssetType = "debt"
	AssetTypeFundUnit    AssetType = "fund_unit"
	AssetTypeWarrant     AssetType = "warrant"
	AssetTypeConvertible AssetType = "convertible"
)

// AssetTxType classifies an asset-layer transaction operation.
type AssetTxType string

const (
	// AssetTxTypeIssue creates new tokens. Only the asset issuer may use this.
	AssetTxTypeIssue AssetTxType = "issue"
	// AssetTxTypeTransfer moves tokens between two participant wallets.
	AssetTxTypeTransfer AssetTxType = "transfer"
	// AssetTxTypeRedeem burns tokens, returning them to the issuer.
	AssetTxTypeRedeem AssetTxType = "redeem"
)

// TransferRestrictions encodes the eligibility and lockup rules for an asset.
// All fields are optional; zero values mean no restriction.
type TransferRestrictions struct {
	// LockupPeriodDays sets how long a newly acquired holding is non-transferable.
	LockupPeriodDays int
	// AccreditedOnly restricts transfers to wallets with a non-retail credential.
	AccreditedOnly bool
	// MaxHolders limits the total number of distinct holders. 0 = unlimited.
	MaxHolders int
	// AllowedJurisdictions restricts holders to listed ISO country codes. Empty = all allowed.
	AllowedJurisdictions []string
	// BlockedJurisdictions explicitly excludes listed ISO country codes.
	BlockedJurisdictions []string
}

// AssetMetadata holds legal and descriptive information about an asset.
type AssetMetadata struct {
	CompanyName   string
	Jurisdiction  string // ISO 3166-1 alpha-2 country code of incorporation
	ISIN          string // optional — assigned by issuer or registration authority
	VotingRights  bool
	DividendTerms string
	// LegalDocHash is the SHA3-256 hex of the subscription agreement or term sheet.
	// Committing this hash on-chain binds the on-chain issuance to the legal document.
	LegalDocHash string
}

// Asset represents a tokenised financial instrument on the GreenHouse network.
// It is created by an issuer wallet and governs all subsequent transfer rules.
type Asset struct {
	ID                string
	Issuer            string // base64-encoded Ed25519 public key of the issuing wallet
	AssetType         AssetType
	TotalSupply       float64
	CirculatingSupply float64 // increments on issue, decrements on redeem
	Currency          string  // "GBP", "EUR", "USD", "CHF"
	Metadata          AssetMetadata
	Restrictions      TransferRestrictions
	CreatedAt         int64  // Unix timestamp
	IssuerSignature   []byte // Ed25519 sig over all fields (with IssuerSignature=nil)
}

// AssetHolding records a wallet's balance of a specific asset.
type AssetHolding struct {
	AssetID     string
	HolderID    string // base64-encoded Ed25519 public key
	Balance     float64
	LockedUntil int64 // Unix timestamp; 0 = no lockup active
}

// AssetTransaction is the payload for an asset-layer operation broadcast via P2P.
// The embedded Tx fields map as follows:
//
//	Tx.Sender   = issuer or seller's base64-encoded public key
//	Tx.Receiver = recipient's base64-encoded public key
//	Tx.Amount   = quantity of asset units
type AssetTransaction struct {
	Tx      Transaction
	AssetID string
	TxType  AssetTxType
}

// P2P message type constant for asset transactions (used in p2p.go Week 5).
const MessageTypeAssetTransaction = "asset_transaction"

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

// HoldingKey returns the canonical map key for a participant's holding of an asset.
// Format: "<holderID>:<assetID>"
func HoldingKey(holderID, assetID string) string {
	return holderID + ":" + assetID
}

// NewAsset creates and cryptographically signs a new asset on behalf of the issuer.
// The IssuerSignature covers all fields — any mutation of the asset is detectable.
// CirculatingSupply starts at 0; it grows as issue transactions are applied.
func NewAsset(
	issuerKey *PrivateKey,
	assetType AssetType,
	totalSupply float64,
	currency string,
	metadata AssetMetadata,
	restrictions TransferRestrictions,
) (*Asset, error) {
	if issuerKey == nil {
		return nil, fmt.Errorf("issuer key must not be nil")
	}
	if totalSupply <= 0 {
		return nil, fmt.Errorf("total supply must be greater than zero")
	}
	if currency == "" {
		return nil, fmt.Errorf("currency must not be empty")
	}

	issuerKeyStr := base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes())

	// Derive a unique, deterministic ID from the issuer key and current nanosecond.
	idSrc := fmt.Sprintf("%s:%d", issuerKeyStr, time.Now().UnixNano())
	idHash := sha3.Sum256([]byte(idSrc))

	a := &Asset{
		ID:                hex.EncodeToString(idHash[:]),
		Issuer:            issuerKeyStr,
		AssetType:         assetType,
		TotalSupply:       totalSupply,
		CirculatingSupply: 0,
		Currency:          currency,
		Metadata:          metadata,
		Restrictions:      restrictions,
		CreatedAt:         time.Now().Unix(),
		IssuerSignature:   nil, // must be nil during signing
	}

	data, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal asset for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	a.IssuerSignature = issuerKey.Sign(hash[:]).Bytes()

	return a, nil
}

// VerifyIssuerSignature checks the issuer's Ed25519 signature against the asset's
// current field values. Returns false if the asset has been tampered with.
func (a *Asset) VerifyIssuerSignature(issuerPubKey *PublicKey) bool {
	assetCopy := *a
	assetCopy.IssuerSignature = nil
	data, err := json.Marshal(assetCopy)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: a.IssuerSignature}
	return sig.Verify(issuerPubKey, hash[:])
}

// CalculateHash returns the SHA3-256 hex hash of the asset's full JSON representation.
// Used as a canonical identifier when storing assets in the blockchain state.
func (a *Asset) CalculateHash() string {
	data, _ := json.Marshal(a)
	hash := sha3.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// NewAssetTransaction creates a signed AssetTransaction.
// The embedded Transaction is signed by senderKey with RequiredSigs=1.
func NewAssetTransaction(
	senderKey *PrivateKey,
	receiverPubKey *PublicKey,
	assetID string,
	quantity float64,
	txType AssetTxType,
) (*AssetTransaction, error) {
	if senderKey == nil {
		return nil, fmt.Errorf("sender key must not be nil")
	}
	if receiverPubKey == nil {
		return nil, fmt.Errorf("receiver public key must not be nil")
	}
	if assetID == "" {
		return nil, fmt.Errorf("asset ID must not be empty")
	}
	if quantity <= 0 {
		return nil, fmt.Errorf("quantity must be greater than zero")
	}

	tx := Transaction{
		Sender:       base64.StdEncoding.EncodeToString(senderKey.Public().Bytes()),
		Receiver:     base64.StdEncoding.EncodeToString(receiverPubKey.Bytes()),
		Amount:       quantity,
		RequiredSigs: 1,
	}
	tx.GenerateNonce()

	if err := tx.SignTransaction(senderKey); err != nil {
		return nil, fmt.Errorf("failed to sign asset transaction: %w", err)
	}

	return &AssetTransaction{
		Tx:      tx,
		AssetID: assetID,
		TxType:  txType,
	}, nil
}

// Validate checks an AssetTransaction against current chain state.
// credentials may be nil; if nil, AccreditedOnly and BlockedJurisdictions checks
// are skipped. This allows Week 1 assets to be tested before identity.go exists.
//
// Validation order:
//  1. Asset exists
//  2. Quantity > 0
//  3. Sender and Receiver are non-empty
//  4. Transaction signature is valid
//  5. Issue: sender must be asset.Issuer
//  6. Transfer/Redeem: sender holds sufficient balance
//  7. Transfer/Redeem: holding lockup period is not active
//  8. Transfer: MaxHolders limit is not exceeded by adding a new holder
//  9. Credential checks (AccreditedOnly, BlockedJurisdictions) if credentials != nil
func (at *AssetTransaction) Validate(
	assets map[string]*Asset,
	holdings map[string]*AssetHolding,
	credentials map[string]*CredentialAttestation,
) error {
	// 1. Asset must exist in the registry.
	asset, ok := assets[at.AssetID]
	if !ok {
		return fmt.Errorf("unknown asset ID: %s", at.AssetID)
	}

	// 2. Quantity must be positive (also enforced by VerifyTransaction, but checked
	// here first to give a cleaner error message in asset context).
	if at.Tx.Amount <= 0 {
		return fmt.Errorf("quantity must be greater than zero, got %g", at.Tx.Amount)
	}

	// 3. Sender and receiver must be present.
	if at.Tx.Sender == "" {
		return fmt.Errorf("sender must not be empty")
	}
	if at.Tx.Receiver == "" {
		return fmt.Errorf("receiver must not be empty")
	}

	// 4. Signature must be valid. Decodes sender's public key from the Sender field
	// and verifies the embedded Transaction signature.
	senderPubKey, err := PublicKeyFromString(at.Tx.Sender)
	if err != nil {
		return fmt.Errorf("invalid sender public key: %w", err)
	}
	if valid, err := at.Tx.VerifyTransaction([]*PublicKey{senderPubKey}); !valid {
		return fmt.Errorf("invalid transaction signature: %w", err)
	}

	switch at.TxType {
	case AssetTxTypeIssue:
		// 5. Only the asset issuer may issue new tokens.
		if at.Tx.Sender != asset.Issuer {
			return fmt.Errorf("only the asset issuer may issue tokens: sender %s is not issuer %s",
				at.Tx.Sender, asset.Issuer)
		}

	case AssetTxTypeTransfer, AssetTxTypeRedeem:
		// 6. Sender must hold enough tokens to cover the transaction.
		holdingKey := HoldingKey(at.Tx.Sender, at.AssetID)
		holding, exists := holdings[holdingKey]
		available := 0.0
		if exists {
			available = holding.Balance
		}
		if !exists || holding.Balance < at.Tx.Amount {
			return fmt.Errorf("insufficient balance: required %g, available %g",
				at.Tx.Amount, available)
		}

		// 7. Holding must not be within an active lockup period.
		if holding.LockedUntil > 0 && time.Now().Unix() < holding.LockedUntil {
			return fmt.Errorf("holding is locked until unix %d (%.0f seconds remaining)",
				holding.LockedUntil, float64(holding.LockedUntil-time.Now().Unix()))
		}

	default:
		return fmt.Errorf("unknown asset transaction type: %q", at.TxType)
	}

	// 8. MaxHolders: if a transfer would introduce a new holder, check the limit.
	if at.TxType == AssetTxTypeTransfer && asset.Restrictions.MaxHolders > 0 {
		receiverHoldingKey := HoldingKey(at.Tx.Receiver, at.AssetID)
		if _, receiverExists := holdings[receiverHoldingKey]; !receiverExists {
			// Count distinct current holders of this asset.
			holderCount := 0
			suffix := ":" + at.AssetID
			for key := range holdings {
				if strings.HasSuffix(key, suffix) {
					holderCount++
				}
			}
			if holderCount >= asset.Restrictions.MaxHolders {
				return fmt.Errorf("max holders reached: limit is %d, currently %d",
					asset.Restrictions.MaxHolders, holderCount)
			}
		}
	}

	// 9 & 10. Credential-based checks: AccreditedOnly and BlockedJurisdictions.
	// Skipped entirely when credentials map is nil (e.g., Week 1 tests, dev mode).
	if credentials != nil {
		if err := CheckTransferEligibility(at.Tx.Receiver, asset, credentials); err != nil {
			return err
		}
	}

	return nil
}

// CheckTransferEligibility verifies that a receiver wallet is eligible to hold
// a given asset based on the asset's transfer restrictions and the receiver's
// on-chain credential. Called from Validate when credentials are present.
//
// If no restrictions require credential verification, the check passes immediately.
// If AccreditedOnly is set but no valid credential exists, the transfer is rejected.
func CheckTransferEligibility(
	receiverKey string,
	asset *Asset,
	credentials map[string]*CredentialAttestation,
) error {
	// Fast path: no credential-dependent restrictions.
	if !asset.Restrictions.AccreditedOnly && len(asset.Restrictions.BlockedJurisdictions) == 0 {
		return nil
	}

	cred, exists := credentials[receiverKey]

	// If AccreditedOnly is set, a valid credential is mandatory.
	if asset.Restrictions.AccreditedOnly {
		if !exists || !cred.IsValid() {
			return fmt.Errorf("asset requires accreditation: receiver %s has no valid credential",
				receiverKey)
		}
		if !cred.IsAccredited() {
			return fmt.Errorf("asset requires accredited investor: receiver holds class %q",
				cred.InvestorClass)
		}
	}

	// Jurisdiction block check: only applies if we have a credential to inspect.
	if exists && cred.IsValid() {
		for _, blocked := range asset.Restrictions.BlockedJurisdictions {
			if cred.Jurisdiction == blocked {
				return fmt.Errorf("receiver jurisdiction %q is blocked for asset %s",
					cred.Jurisdiction, asset.ID)
			}
		}
	}

	return nil
}

// ApplyAssetTransaction mutates the holdings map and asset CirculatingSupply
// to reflect a committed AssetTransaction. Must only be called after Validate
// has returned nil — this function does not re-validate.
//
// Issue:    creates/increments receiver holding; increments CirculatingSupply.
// Transfer: decrements sender holding; creates/increments receiver holding.
// Redeem:   decrements sender holding; decrements CirculatingSupply.
//
// Newly created holdings have LockedUntil set per asset.Restrictions.LockupPeriodDays.
// A holding with Balance == 0 is removed from the map.
func ApplyAssetTransaction(
	at *AssetTransaction,
	assets map[string]*Asset,
	holdings map[string]*AssetHolding,
) error {
	asset, ok := assets[at.AssetID]
	if !ok {
		return fmt.Errorf("unknown asset ID: %s", at.AssetID)
	}

	senderKey := HoldingKey(at.Tx.Sender, at.AssetID)
	receiverKey := HoldingKey(at.Tx.Receiver, at.AssetID)

	// lockupEnd calculates the lockup expiry for a newly created holding.
	lockupEnd := func() int64 {
		if asset.Restrictions.LockupPeriodDays > 0 {
			return time.Now().Unix() + int64(asset.Restrictions.LockupPeriodDays)*86400
		}
		return 0
	}

	switch at.TxType {
	case AssetTxTypeIssue:
		if h, exists := holdings[receiverKey]; exists {
			h.Balance += at.Tx.Amount
		} else {
			holdings[receiverKey] = &AssetHolding{
				AssetID:     at.AssetID,
				HolderID:    at.Tx.Receiver,
				Balance:     at.Tx.Amount,
				LockedUntil: lockupEnd(),
			}
		}
		asset.CirculatingSupply += at.Tx.Amount

	case AssetTxTypeTransfer:
		senderHolding, exists := holdings[senderKey]
		if !exists || senderHolding.Balance < at.Tx.Amount {
			return fmt.Errorf("insufficient balance for transfer: required %g, available %g",
				at.Tx.Amount, func() float64 {
					if exists {
						return senderHolding.Balance
					}
					return 0
				}())
		}
		senderHolding.Balance -= at.Tx.Amount
		if senderHolding.Balance == 0 {
			delete(holdings, senderKey)
		}
		if h, exists := holdings[receiverKey]; exists {
			h.Balance += at.Tx.Amount
		} else {
			holdings[receiverKey] = &AssetHolding{
				AssetID:     at.AssetID,
				HolderID:    at.Tx.Receiver,
				Balance:     at.Tx.Amount,
				LockedUntil: lockupEnd(),
			}
		}

	case AssetTxTypeRedeem:
		senderHolding, exists := holdings[senderKey]
		if !exists || senderHolding.Balance < at.Tx.Amount {
			return fmt.Errorf("insufficient balance for redemption: required %g, available %g",
				at.Tx.Amount, func() float64 {
					if exists {
						return senderHolding.Balance
					}
					return 0
				}())
		}
		senderHolding.Balance -= at.Tx.Amount
		if senderHolding.Balance == 0 {
			delete(holdings, senderKey)
		}
		asset.CirculatingSupply -= at.Tx.Amount

	default:
		return fmt.Errorf("unknown asset transaction type: %q", at.TxType)
	}

	return nil
}
