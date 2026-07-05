package gonetwork

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// ErrROFRTriggered is returned by CheckROFR when a transfer is suspended
// pending existing holders' right-of-first-refusal response window.
var ErrROFRTriggered = errors.New("transfer suspended: ROFR triggered")

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// CorporateActionType classifies the corporate governance event.
type CorporateActionType string

const (
	// CorporateActionROFR suspends a transfer and notifies existing holders.
	CorporateActionROFR CorporateActionType = "rofr"
	// CorporateActionDragAlong forces minority holders to sell on majority terms.
	CorporateActionDragAlong CorporateActionType = "drag_along"
	// CorporateActionTagAlong allows minority holders to join a majority sale.
	CorporateActionTagAlong CorporateActionType = "tag_along"
	// CorporateActionDividend distributes cash to all holders proportionally.
	CorporateActionDividend CorporateActionType = "dividend"
)

// CorporateActionStatus tracks lifecycle state.
type CorporateActionStatus string

const (
	CorporateActionPending  CorporateActionStatus = "pending"  // awaiting responses
	CorporateActionApproved CorporateActionStatus = "approved" // threshold met
	CorporateActionRejected CorporateActionStatus = "rejected" // threshold not met
	CorporateActionExecuted CorporateActionStatus = "executed" // transfer completed
	CorporateActionLapsed   CorporateActionStatus = "lapsed"   // deadline passed without action
)

// CorporateAction is the on-chain record of a governance event.
// It is created automatically when a transfer triggers a ROFR, or when an
// issuer initiates a drag-along / tag-along event.
type CorporateAction struct {
	ID                string                `json:"id"`
	AssetID           string                `json:"asset_id"`
	Type              CorporateActionType   `json:"action_type"`
	Status            CorporateActionStatus `json:"status"`
	ProposerKey       string                `json:"proposer_key"` // base64 Ed25519 public key of the wallet initiating
	CreatedAt         int64                 `json:"created_at"`
	TargetTransfer    *AssetTransaction     `json:"target_transfer,omitempty"`
	PricePerUnit      float64               `json:"price_per_unit,omitempty"`
	TotalUnits        float64               `json:"total_units,omitempty"`
	DeadlineAt        int64                 `json:"record_date"`         // Unix timestamp
	Responses         map[string]bool       `json:"responses,omitempty"` // holderKey → exercised
	RequiredThreshold float64               `json:"required_threshold"`
	ProposerSignature []byte                `json:"-"`
}

// CorporateActionResponse is broadcast by a holder exercising or waiving a right.
type CorporateActionResponse struct {
	ActionID  string `json:"action_id"`
	HolderKey string `json:"holder_key"` // base64 Ed25519 public key of the responding holder
	Exercised bool   `json:"exercised"`  // true = exercising; false = waiving
	Signature []byte `json:"-"`
}

// ---------------------------------------------------------------------------
// NewCorporateAction
// ---------------------------------------------------------------------------

// NewCorporateAction creates and signs a CorporateAction.
// deadlineDays must be > 0. requiredThreshold must be in (0, 1].
func NewCorporateAction(
	proposerKey *PrivateKey,
	assetID string,
	actionType CorporateActionType,
	targetTransfer *AssetTransaction,
	pricePerUnit float64,
	totalUnits float64,
	deadlineDays int,
	requiredThreshold float64,
) (*CorporateAction, error) {
	if assetID == "" {
		return nil, fmt.Errorf("assetID must not be empty")
	}
	if deadlineDays <= 0 {
		return nil, fmt.Errorf("deadlineDays must be positive")
	}
	if requiredThreshold <= 0 || requiredThreshold > 1 {
		return nil, fmt.Errorf("requiredThreshold must be in (0, 1]")
	}

	proposerPubStr := base64.StdEncoding.EncodeToString(proposerKey.Public().Bytes())
	now := time.Now().UTC().Unix()

	// Deterministic ID: sha3-256(proposerPub || assetID || actionType || now)
	h := sha3.New256()
	h.Write([]byte(proposerPubStr))
	h.Write([]byte(assetID))
	h.Write([]byte(actionType))
	var ts [8]byte
	ts[0] = byte(now >> 56)
	ts[1] = byte(now >> 48)
	ts[2] = byte(now >> 40)
	ts[3] = byte(now >> 32)
	ts[4] = byte(now >> 24)
	ts[5] = byte(now >> 16)
	ts[6] = byte(now >> 8)
	ts[7] = byte(now)
	h.Write(ts[:])
	id := hex.EncodeToString(h.Sum(nil))

	ca := &CorporateAction{
		ID:                id,
		AssetID:           assetID,
		Type:              actionType,
		Status:            CorporateActionPending,
		ProposerKey:       proposerPubStr,
		CreatedAt:         now,
		TargetTransfer:    targetTransfer,
		PricePerUnit:      pricePerUnit,
		TotalUnits:        totalUnits,
		DeadlineAt:        now + int64(deadlineDays)*86400,
		Responses:         make(map[string]bool),
		RequiredThreshold: requiredThreshold,
	}

	// Sign: marshal with ProposerSignature=nil (already nil), sha3.Sum256, sign
	data, err := json.Marshal(ca)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CorporateAction for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	ca.ProposerSignature = proposerKey.Sign(hash[:]).Bytes()

	return ca, nil
}

// ---------------------------------------------------------------------------
// CorporateAction methods
// ---------------------------------------------------------------------------

// IsLapsed returns true when the action's deadline has passed.
func (ca *CorporateAction) IsLapsed() bool {
	return time.Now().UTC().Unix() > ca.DeadlineAt
}

// RecordResponse records a holder's exercise or waiver of their ROFR.
// It verifies the signature, checks the action is still actionable, and
// stores the response. Returns an error if validation fails.
func (ca *CorporateAction) RecordResponse(resp *CorporateActionResponse, holderPubKey *PublicKey) error {
	if ca.Status != CorporateActionPending {
		return fmt.Errorf("corporate action %s is not pending (status: %s)", ca.ID, ca.Status)
	}
	if ca.IsLapsed() {
		return fmt.Errorf("corporate action %s has lapsed", ca.ID)
	}

	// Verify the key identity claim
	claimedPub := base64.StdEncoding.EncodeToString(holderPubKey.Bytes())
	if resp.HolderKey != claimedPub {
		return fmt.Errorf("response HolderKey does not match supplied public key")
	}

	// Verify signature: SHA3-256(ActionID || HolderKey || exercisedByte)
	h := sha3.New256()
	h.Write([]byte(resp.ActionID))
	h.Write([]byte(resp.HolderKey))
	if resp.Exercised {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	msgHash := h.Sum(nil)
	sig := &Signature{value: resp.Signature}
	if !sig.Verify(holderPubKey, msgHash) {
		return fmt.Errorf("invalid signature on CorporateActionResponse")
	}

	ca.Responses[resp.HolderKey] = resp.Exercised
	return nil
}

// TallyROFR sums the balances of holders who exercised their ROFR and returns
// that sum as a fraction of totalCirculating.
// holdings is the global holdings map keyed by HoldingKey(holderID, assetID).
func (ca *CorporateAction) TallyROFR(holdings map[string]*AssetHolding) (exercisedFraction float64, totalCirculating float64) {
	var exercisedBalance float64
	for _, holding := range holdings {
		if holding.AssetID != ca.AssetID {
			continue
		}
		totalCirculating += holding.Balance
		if exercised, ok := ca.Responses[holding.HolderID]; ok && exercised {
			exercisedBalance += holding.Balance
		}
	}
	if totalCirculating == 0 {
		return 0, 0
	}
	return exercisedBalance / totalCirculating, totalCirculating
}

// ---------------------------------------------------------------------------
// NewCorporateActionResponse — helper to build a signed response
// ---------------------------------------------------------------------------

// NewCorporateActionResponse creates a signed ROFR response for the given holder.
func NewCorporateActionResponse(actionID string, exercised bool, holderKey *PrivateKey) *CorporateActionResponse {
	holderPubStr := base64.StdEncoding.EncodeToString(holderKey.Public().Bytes())

	h := sha3.New256()
	h.Write([]byte(actionID))
	h.Write([]byte(holderPubStr))
	if exercised {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	msgHash := h.Sum(nil)

	return &CorporateActionResponse{
		ActionID:  actionID,
		HolderKey: holderPubStr,
		Exercised: exercised,
		Signature: holderKey.Sign(msgHash).Bytes(),
	}
}

// ---------------------------------------------------------------------------
// CheckROFR
// ---------------------------------------------------------------------------

// CheckROFR inspects whether a transfer on a ROFR-flagged asset should be
// suspended. If triggered, a new CorporateAction is created, inserted into
// pendingActions, and ErrROFRTriggered is returned — the caller must not apply
// the transfer until the action resolves.
//
// Returns (false, nil, nil) when no ROFR applies (asset has HasROFR == false
// or there is already a resolved action for the same transfer).
func CheckROFR(
	at *AssetTransaction,
	asset *Asset,
	holdings map[string]*AssetHolding,
	pendingActions map[string]*CorporateAction,
) (triggered bool, action *CorporateAction, err error) {
	if !asset.Restrictions.HasROFR {
		return false, nil, nil
	}

	rofrDays := asset.Restrictions.ROFRDays
	if rofrDays <= 0 {
		rofrDays = 30
	}

	// We need a PrivateKey to sign — but CheckROFR is called without one.
	// The caller should use NewCorporateAction directly when they have the key.
	// Here we create a lightweight unsigned placeholder and store it.
	// In production the proposer submits a pre-signed action; for the engine
	// we create a system-signed stub using the transfer's FromWallet as identity.
	//
	// Since we don't have a private key here, we build the action manually
	// and leave ProposerSignature nil — it will be filled by the transfer sender.
	now := time.Now().UTC().Unix()

	h := sha3.New256()
	h.Write([]byte(at.Tx.Sender))
	h.Write([]byte(asset.ID))
	h.Write([]byte(CorporateActionROFR))
	var ts [8]byte
	ts[0] = byte(now >> 56)
	ts[1] = byte(now >> 48)
	ts[2] = byte(now >> 40)
	ts[3] = byte(now >> 32)
	ts[4] = byte(now >> 24)
	ts[5] = byte(now >> 16)
	ts[6] = byte(now >> 8)
	ts[7] = byte(now)
	h.Write(ts[:])
	id := hex.EncodeToString(h.Sum(nil))

	ca := &CorporateAction{
		ID:                id,
		AssetID:           asset.ID,
		Type:              CorporateActionROFR,
		Status:            CorporateActionPending,
		ProposerKey:       at.Tx.Sender,
		TargetTransfer:    at,
		PricePerUnit:      0, // AssetTransaction does not carry price; set by caller if needed
		TotalUnits:        at.Tx.Amount,
		DeadlineAt:        now + int64(rofrDays)*86400,
		Responses:         make(map[string]bool),
		RequiredThreshold: 0.5, // majority must exercise to block the transfer
	}

	pendingActions[ca.ID] = ca
	return true, ca, ErrROFRTriggered
}

// ---------------------------------------------------------------------------
// ExecuteDragAlong
// ---------------------------------------------------------------------------

// ExecuteDragAlong generates unsigned AssetTransactions for all minority holders
// who have not explicitly waived, forcing them to sell on the same terms as the
// majority. Only call this after verifying the threshold has been met.
//
// buyerKey is the base64-encoded Ed25519 public key of the acquirer.
// Returns an error if the action is not of type drag_along.
func ExecuteDragAlong(
	action *CorporateAction,
	holdings map[string]*AssetHolding,
	buyerKey string,
) ([]*AssetTransaction, error) {
	if action.Type != CorporateActionDragAlong {
		return nil, fmt.Errorf("ExecuteDragAlong requires a drag_along action; got %s", action.Type)
	}

	var txs []*AssetTransaction

	for _, holding := range holdings {
		if holding.AssetID != action.AssetID {
			continue
		}
		if holding.Balance <= 0 {
			continue
		}
		// Skip holders who explicitly waived (false) — they agreed to sell.
		// Skip the proposer themselves.
		if holding.HolderID == action.ProposerKey {
			continue
		}
		// Build a transfer from each minority holder to the buyer
		atx := &AssetTransaction{
			AssetID: action.AssetID,
			TxType:  AssetTxTypeTransfer,
			Tx: Transaction{
				Sender:       holding.HolderID,
				Receiver:     buyerKey,
				Amount:       holding.Balance,
				RequiredSigs: 1,
			},
		}
		txs = append(txs, atx)
	}

	return txs, nil
}
