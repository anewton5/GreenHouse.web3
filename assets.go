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
	AssetTypeEquity            AssetType = "equity"
	AssetTypeDebt              AssetType = "debt"
	AssetTypeFundUnit          AssetType = "fund_unit"
	AssetTypeWarrant           AssetType = "warrant"
	AssetTypeConvertible       AssetType = "convertible"
	AssetTypeParticipationNote AssetType = "participation_note" // SPV-backed; ISIN = SPV ISIN
	AssetTypeDepositaryReceipt AssetType = "depositary_receipt" // cross-listing wrapper
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
	LockupPeriodDays int `json:"lockup_period_days,omitempty"`
	// AccreditedOnly restricts transfers to wallets with a non-retail credential.
	AccreditedOnly bool `json:"accredited_only,omitempty"`
	// MaxHolders limits the total number of distinct holders. 0 = unlimited.
	MaxHolders int `json:"max_holders,omitempty"`
	// AllowedJurisdictions restricts holders to listed ISO country codes. Empty = all allowed.
	AllowedJurisdictions []string `json:"allowed_jurisdictions,omitempty"`
	// BlockedJurisdictions explicitly excludes listed ISO country codes.
	BlockedJurisdictions []string `json:"blocked_jurisdictions,omitempty"`

	// Corporate-action rights (Phase 2 Week 3-4)

	// HasROFR triggers a CorporateAction on every transfer, giving existing holders
	// the right to purchase on the same terms before the transfer proceeds.
	HasROFR bool `json:"has_rofr,omitempty"`
	// ROFRDays is the notice period during which holders may exercise the ROFR (default 30).
	ROFRDays int `json:"rofr_days,omitempty"`
	// DragThreshold is the minimum fraction (0-1) of circulating supply that must consent
	// before a drag-along can be triggered. 0 disables drag-along rights.
	DragThreshold float64 `json:"drag_threshold,omitempty"`
	// TagAlongRight allows minority holders to join any majority sale on identical terms.
	TagAlongRight bool `json:"tag_along_right,omitempty"`
}

// AssetMetadata holds legal and descriptive information about an asset.
type AssetMetadata struct {
	CompanyName   string `json:"company_name,omitempty"`
	Jurisdiction  string `json:"jurisdiction,omitempty"` // ISO 3166-1 alpha-2 country code of incorporation
	ISIN          string `json:"isin,omitempty"`         // optional — assigned by issuer or registration authority
	VotingRights  bool   `json:"voting_rights,omitempty"`
	DividendTerms string `json:"dividend_terms,omitempty"`
	// LegalDocHash is the SHA3-256 hex of the subscription agreement or term sheet.
	// Committing this hash on-chain binds the on-chain issuance to the legal document.
	LegalDocHash string `json:"legal_doc_hash,omitempty"`
}

// Asset represents a tokenised financial instrument on the GreenHouse network.
// It is created by an issuer wallet and governs all subsequent transfer rules.
type Asset struct {
	ID                string               `json:"id"`
	Name              string               `json:"name,omitempty"`
	Symbol            string               `json:"symbol,omitempty"`
	Issuer            string               `json:"issuer"` // base64-encoded Ed25519 public key of the issuing wallet
	AssetType         AssetType            `json:"asset_class"`
	TotalSupply       float64              `json:"total_supply"`
	CirculatingSupply float64              `json:"circulating_supply"` // increments on issue, decrements on redeem
	Currency          string               `json:"currency"`           // "GBP", "EUR", "USD", "CHF"
	Metadata          AssetMetadata        `json:"metadata"`
	Restrictions      TransferRestrictions `json:"restrictions,omitempty"`
	CreatedAt         int64                `json:"created_at"` // Unix timestamp
	IssuerSignature   []byte               `json:"-"`          // Ed25519 sig — not exposed via API
}

// AssetHolding records a wallet's balance of a specific asset.
type AssetHolding struct {
	AssetID     string  `json:"asset_id"`
	HolderID    string  `json:"holder_id"` // base64-encoded Ed25519 public key
	Balance     float64 `json:"balance"`
	LockedUntil int64   `json:"locked_until,omitempty"` // Unix timestamp; 0 = no lockup active
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
	// TravelRuleData carries FATF Travel Rule originator/beneficiary information.
	// Required (non-nil) when the transfer value is EUR 1,000 or above.
	TravelRuleData *TravelRulePayload `json:"travel_rule_data,omitempty"`
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

// HoldingKey returns the canonical map key for a participant's holding of an asset.
// Format: "<holderID>:<assetID>"
func HoldingKey(holderID, assetID string) string {
	return holderID + ":" + assetID
}

// ValidateISIN returns an error if isin does not conform to ISO 6166.
// An empty string is accepted (ISIN is optional on GreenHouse assets).
// The check covers structure only (length, character set); Luhn-style checksum
// verification is deferred to integration with an ANNA/NNA database lookup.
func ValidateISIN(isin string) error {
	if isin == "" {
		return nil
	}
	if len(isin) != 12 {
		return fmt.Errorf("ISIN must be exactly 12 characters (ISO 6166); got %d", len(isin))
	}
	for i, c := range isin {
		switch {
		case i < 2: // country code — uppercase alpha only
			if c < 'A' || c > 'Z' {
				return fmt.Errorf("ISIN country code (first 2 chars) must be uppercase alpha; position %d got %q", i, c)
			}
		default: // alphanumeric (uppercase)
			if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				return fmt.Errorf("ISIN position %d must be uppercase alphanumeric; got %q", i, c)
			}
		}
	}
	return nil
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
// immutable creation fields. Returns false if any tamper-sensitive field has been
// modified since the asset was signed.
//
// CirculatingSupply is intentionally excluded from the hash: it is mutable state
// that legitimately changes as issue/redeem transactions are applied, and was 0
// at the time NewAsset() produced the signature. Tamper-proof coverage extends to
// the fields that define the instrument: ID, Issuer, AssetType, TotalSupply,
// Currency, Metadata, Restrictions, and CreatedAt.
func (a *Asset) VerifyIssuerSignature(issuerPubKey *PublicKey) bool {
	assetCopy := *a
	assetCopy.IssuerSignature = nil
	assetCopy.CirculatingSupply = 0 // mutable — excluded from the creation signature
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
//  0. AML screening (sender + receiver) — optional; pass a non-nil AMLScreener
//  1. Asset exists
//  2. Quantity > 0
//  3. Sender and Receiver are non-empty
//  4. Transaction signature is valid
//  5. Issue: sender must be asset.Issuer
//  6. Transfer/Redeem: sender holds sufficient balance
//  7. Transfer/Redeem: holding lockup period is not active
//  8. Transfer: MaxHolders limit is not exceeded by adding a new holder
//     8b. Transfer: ROFR check (if pendingActions != nil and asset has HasROFR set)
//  9. Credential checks (AccreditedOnly, BlockedJurisdictions) if credentials != nil
//
// pendingActions is the blockchain's PendingCorporateActions map. Pass nil to skip
// the ROFR check (e.g. in tests that don't exercise ROFR logic).
// AML screening is optional: pass an AMLScreener as the 5th variadic argument.
func (at *AssetTransaction) Validate(
	assets map[string]*Asset,
	holdings map[string]*AssetHolding,
	credentials map[string]*CredentialAttestation,
	pendingActions map[string]*CorporateAction,
	screener ...AMLScreener,
) error {
	// 0. AML screening — runs before any other check so blocked parties are
	// rejected immediately rather than after expensive validation work.
	if len(screener) > 0 && screener[0] != nil {
		asset0, ok0 := assets[at.AssetID]
		currency := ""
		if ok0 {
			currency = asset0.Currency
		}
		alert, err := screener[0].ScreenTransaction(
			at.Tx.Sender, at.Tx.Receiver, at.AssetID, at.Tx.Amount, currency,
		)
		if err != nil {
			return fmt.Errorf("aml screening error: %w", err)
		}
		if alert != nil && alert.Severity == AMLSeverityBlock {
			return fmt.Errorf("transaction blocked by AML screening: %s (list: %s)",
				alert.Reason, alert.MatchedList)
		}
		// AMLSeverityFlag: log and continue — the event is already recorded in
		// the screener's Calls slice for compliance audit purposes.
	}

	// 1. Asset must exist in the registry.
	asset, ok := assets[at.AssetID]
	if !ok {
		return fmt.Errorf("unknown asset ID: %s", at.AssetID)
	}

	// 1b. Issuer signature must be intact — detects any post-creation tampering of
	// asset fields (e.g. TotalSupply inflation, metadata mutation).
	// Assets created via NewAsset() carry a signature; assets built directly in
	// the API handler (no private key available) have IssuerSignature == nil and
	// skip this check, relying on JWT authentication as the identity anchor.
	if len(asset.IssuerSignature) > 0 {
		issuerPub, keyErr := PublicKeyFromString(asset.Issuer)
		if keyErr != nil {
			return fmt.Errorf("asset %s has a malformed issuer key: %w", asset.ID, keyErr)
		}
		if !asset.VerifyIssuerSignature(issuerPub) {
			return fmt.Errorf("asset %s has an invalid issuer signature: record may have been tampered", asset.ID)
		}
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
		// 5b. Participation notes require SPV admin countersignature before any tokens
		// may be issued. CirculatingSupply starts at 0 and is only released by the
		// handleCounterSignAsset endpoint once the SPV administrator countersigns.
		if asset.AssetType == AssetTypeParticipationNote && asset.CirculatingSupply == 0 {
			return fmt.Errorf(
				"asset %s is a participation note awaiting SPV admin countersignature: issue transactions are blocked until supply is released",
				asset.ID,
			)
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

	// 8b. ROFR: if the asset has a right-of-first-refusal, suspend the transfer
	// so existing holders can exercise their pre-emption right. A CorporateAction
	// is created in pendingActions and ErrROFRTriggered is returned. The transfer
	// may proceed once the action resolves (caller's responsibility).
	if at.TxType == AssetTxTypeTransfer && pendingActions != nil {
		if triggered, _, err := CheckROFR(at, asset, holdings, pendingActions); triggered {
			return err // ErrROFRTriggered
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
// If no restrictions require credential verification, the check passes immediately
// unless the receiver's credential is expired (G-08: any expired credential blocks
// transfers regardless of asset type).
//
// If AccreditedOnly is set but no valid credential exists, the transfer is rejected.
func CheckTransferEligibility(
	receiverKey string,
	asset *Asset,
	credentials map[string]*CredentialAttestation,
) error {
	cred, exists := credentials[receiverKey]

	// G-08: block transfers to wallets with an expired credential, regardless of
	// asset type.  Re-KYC must be completed before the wallet can receive further
	// regulated-security transfers.
	if exists && cred.ExpiresAt > 0 && time.Now().Unix() > cred.ExpiresAt {
		return fmt.Errorf(
			"receiver KYC credential has expired (expired at unix %d): re-KYC required",
			cred.ExpiresAt,
		)
	}

	// Fast path: no credential-dependent restrictions beyond the expiry check above.
	if !asset.Restrictions.AccreditedOnly && len(asset.Restrictions.BlockedJurisdictions) == 0 {
		return nil
	}

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
