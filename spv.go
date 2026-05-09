package gonetwork

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// SPVJurisdiction is the ISO 3166-1 alpha-2 country code of the SPV's legal domicile.
type SPVJurisdiction string

const (
	SPVJurisdictionLuxembourg  SPVJurisdiction = "LU" // RAIF / SCSp
	SPVJurisdictionIreland     SPVJurisdiction = "IE" // ICAV / DAC
	SPVJurisdictionNetherlands SPVJurisdiction = "NL" // BV / Coöperatie
	SPVJurisdictionCayman      SPVJurisdiction = "KY" // used for APAC / US investors
)

// SPVWrapper represents the legal vehicle that holds underlying company shares.
// The on-chain record binds the SPV's identity to a specific fund administrator
// (SPVAdminKey) and to the underlying company and share class it holds.
//
// Investors hold AssetTypeParticipationNote assets whose Metadata.ISIN equals
// the SPV's ISIN. All economic rights flow through the SPV.
type SPVWrapper struct {
	ID                   string          `json:"ID"`
	Name                 string          `json:"Name"`
	Jurisdiction         SPVJurisdiction `json:"Jurisdiction"`
	UnderlyingCompanyID  string          `json:"UnderlyingCompanyID"`  // e.g. "acme-ltd"
	UnderlyingShareClass string          `json:"UnderlyingShareClass"` // e.g. "Series B Preferred"
	SPVAdminKey          string          `json:"SPVAdminKey"`          // base64 Ed25519 public key of fund admin
	NAV                  float64         `json:"NAV"`                  // Net Asset Value per unit
	NAVUpdatedAt         int64           `json:"NAVUpdatedAt"`         // Unix seconds
	LegalDocHash         string          `json:"LegalDocHash"`         // SHA3-256 hex of SPV formation document
	Signature            []byte          `json:"Signature,omitempty"`  // Ed25519 sig by SPVAdminKey
}

// SPVTxType classifies a corporate event at the SPV level.
type SPVTxType string

const (
	SPVTxTypeDividendDistribution SPVTxType = "dividend"     // cash paid to note holders
	SPVTxTypeNAVUpdate            SPVTxType = "nav_update"   // updated valuation
	SPVTxTypeCapitalCall          SPVTxType = "capital_call" // holders must contribute additional cash
	SPVTxTypeWindingUp            SPVTxType = "winding_up"   // SPV is being dissolved
)

// SPVTransaction records a corporate event at the SPV level that affects
// all participation note holders proportionally.
type SPVTransaction struct {
	ID            string    `json:"ID"`
	SPVID         string    `json:"SPVID"`
	Type          SPVTxType `json:"Type"`
	AmountPerUnit float64   `json:"AmountPerUnit"`    // per note unit (0 for nav_update)
	NewNAV        float64   `json:"NewNAV,omitempty"` // set for nav_update
	Currency      string    `json:"Currency"`
	EffectiveAt   int64     `json:"EffectiveAt"` // Unix seconds
	AdminKey      string    `json:"AdminKey"`    // base64 public key of authorising admin
	Signature     []byte    `json:"Signature,omitempty"`
}

// ---------------------------------------------------------------------------
// SPVWrapper constructor and methods
// ---------------------------------------------------------------------------

// NewSPVWrapper creates and signs an SPVWrapper.
// All string fields are required (non-empty).
func NewSPVWrapper(
	adminKey *PrivateKey,
	name string,
	jurisdiction SPVJurisdiction,
	underlyingCompanyID string,
	underlyingShareClass string,
	legalDocHash string,
) (*SPVWrapper, error) {
	if name == "" {
		return nil, fmt.Errorf("SPV name must not be empty")
	}
	if string(jurisdiction) == "" {
		return nil, fmt.Errorf("SPV jurisdiction must not be empty")
	}
	if underlyingCompanyID == "" {
		return nil, fmt.Errorf("underlyingCompanyID must not be empty")
	}
	if underlyingShareClass == "" {
		return nil, fmt.Errorf("underlyingShareClass must not be empty")
	}
	if legalDocHash == "" {
		return nil, fmt.Errorf("legalDocHash must not be empty")
	}

	adminPubStr := base64.StdEncoding.EncodeToString(adminKey.Public().Bytes())

	// Deterministic ID: sha3-256(adminPubKey || name || jurisdiction || underlyingCompanyID)
	h := sha3.New256()
	h.Write([]byte(adminPubStr))
	h.Write([]byte(name))
	h.Write([]byte(jurisdiction))
	h.Write([]byte(underlyingCompanyID))
	id := hex.EncodeToString(h.Sum(nil))

	s := &SPVWrapper{
		ID:                   id,
		Name:                 name,
		Jurisdiction:         jurisdiction,
		UnderlyingCompanyID:  underlyingCompanyID,
		UnderlyingShareClass: underlyingShareClass,
		SPVAdminKey:          adminPubStr,
		LegalDocHash:         legalDocHash,
		NAVUpdatedAt:         time.Now().UTC().Unix(),
	}

	// Sign: marshal with Signature=nil (already nil), sha3.Sum256, sign
	data, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SPV for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	s.Signature = adminKey.Sign(hash[:]).Bytes()

	return s, nil
}

// VerifySignature checks the SPV admin's Ed25519 signature over the wrapper's fields.
func (s *SPVWrapper) VerifySignature(adminPubKey *PublicKey) bool {
	sCopy := *s
	sCopy.Signature = nil
	data, err := json.Marshal(sCopy)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: s.Signature}
	return sig.Verify(adminPubKey, hash[:])
}

// UpdateNAV updates the wrapper's NAV and returns a signed SPVTransaction of type NAVUpdate.
// The wrapper's own Signature is NOT refreshed — NAV is a live oracle field and the
// original formation signature remains the identity anchor. Only the SPVTransaction
// carries the admin's authorisation for this update.
func (s *SPVWrapper) UpdateNAV(newNAV float64, adminKey *PrivateKey) (*SPVTransaction, error) {
	if newNAV < 0 {
		return nil, fmt.Errorf("NAV must be non-negative")
	}
	s.NAV = newNAV
	s.NAVUpdatedAt = time.Now().UTC().Unix()

	return NewSPVTransaction(adminKey, s.ID, SPVTxTypeNAVUpdate, 0, "", time.Now().UTC().Unix())
}

// ---------------------------------------------------------------------------
// SPVTransaction constructor
// ---------------------------------------------------------------------------

// NewSPVTransaction creates and signs an SPVTransaction.
// currency may be empty for SPVTxTypeNAVUpdate (no cash changes hands).
func NewSPVTransaction(
	adminKey *PrivateKey,
	spvID string,
	txType SPVTxType,
	amountPerUnit float64,
	currency string,
	effectiveAt int64,
) (*SPVTransaction, error) {
	if spvID == "" {
		return nil, fmt.Errorf("spvID must not be empty")
	}
	if txType != SPVTxTypeNAVUpdate && currency == "" {
		return nil, fmt.Errorf("currency must not be empty for %s transactions", txType)
	}
	if txType != SPVTxTypeNAVUpdate && amountPerUnit < 0 {
		return nil, fmt.Errorf("amountPerUnit must be non-negative")
	}

	adminPubStr := base64.StdEncoding.EncodeToString(adminKey.Public().Bytes())

	// Deterministic ID: sha3-256(spvID || type || adminPub || effectiveAt)
	h := sha3.New256()
	h.Write([]byte(spvID))
	h.Write([]byte(txType))
	h.Write([]byte(adminPubStr))
	var buf [8]byte
	buf[0] = byte(effectiveAt >> 56)
	buf[1] = byte(effectiveAt >> 48)
	buf[2] = byte(effectiveAt >> 40)
	buf[3] = byte(effectiveAt >> 32)
	buf[4] = byte(effectiveAt >> 24)
	buf[5] = byte(effectiveAt >> 16)
	buf[6] = byte(effectiveAt >> 8)
	buf[7] = byte(effectiveAt)
	h.Write(buf[:])
	id := hex.EncodeToString(h.Sum(nil))

	tx := &SPVTransaction{
		ID:            id,
		SPVID:         spvID,
		Type:          txType,
		AmountPerUnit: amountPerUnit,
		Currency:      currency,
		EffectiveAt:   effectiveAt,
		AdminKey:      adminPubStr,
	}

	data, err := json.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SPVTransaction for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	tx.Signature = adminKey.Sign(hash[:]).Bytes()

	return tx, nil
}

// VerifySignature checks the admin's Ed25519 signature on this SPVTransaction.
func (tx *SPVTransaction) VerifySignature(adminPubKey *PublicKey) bool {
	txCopy := *tx
	txCopy.Signature = nil
	data, err := json.Marshal(txCopy)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: tx.Signature}
	return sig.Verify(adminPubKey, hash[:])
}

// ---------------------------------------------------------------------------
// ApplySPVTransaction
// ---------------------------------------------------------------------------

// ApplySPVTransaction processes a dividend or capital call SPV event, generating
// one PaymentInstruction per note holder proportional to their balance.
//
// For SPVTxTypeDividendDistribution the SPV admin pays each holder:
//
//	instruction.TotalAmount = holder.Balance * spvTx.AmountPerUnit
//
// For SPVTxTypeCapitalCall each holder owes the SPV admin:
//
//	instruction.TotalAmount = holder.Balance * spvTx.AmountPerUnit
//	(PayerWalletID and PayeeWalletID are swapped vs dividend)
//
// Holders with zero balance produce no instruction.
// The instructions are unsigned — callers must pass them through OracleService.SignInstruction.
//
// Only holders whose HoldingKey matches the SPV's asset ID are included.
func ApplySPVTransaction(
	spvTx *SPVTransaction,
	spv *SPVWrapper,
	asset *Asset,
	holdings map[string]*AssetHolding,
	_ PaymentProvider, // reserved for future virtual-account lookup
) ([]PaymentInstruction, error) {
	if spvTx.Type != SPVTxTypeDividendDistribution && spvTx.Type != SPVTxTypeCapitalCall {
		return nil, fmt.Errorf("ApplySPVTransaction only handles dividend and capital_call; got %s", spvTx.Type)
	}
	if asset == nil {
		return nil, fmt.Errorf("asset must not be nil")
	}

	var instructions []PaymentInstruction

	for key, holding := range holdings {
		if holding.AssetID != asset.ID {
			continue
		}
		if holding.Balance <= 0 {
			continue
		}
		// Verify the holding key matches — guard against map corruption
		if key != HoldingKey(holding.HolderID, holding.AssetID) {
			continue
		}

		amount := holding.Balance * spvTx.AmountPerUnit

		// Deterministic reference: sha3(txID || holderID)[:8]
		refH := sha3.New256()
		refH.Write([]byte(spvTx.ID))
		refH.Write([]byte(holding.HolderID))
		refBytes := refH.Sum(nil)
		ref := fmt.Sprintf("SPV-%s", hex.EncodeToString(refBytes[:8]))

		var payerID, payeeID string
		switch spvTx.Type {
		case SPVTxTypeDividendDistribution:
			payerID = spv.SPVAdminKey // SPV pays holder
			payeeID = holding.HolderID
		case SPVTxTypeCapitalCall:
			payerID = holding.HolderID // holder pays SPV
			payeeID = spv.SPVAdminKey
		}

		instructions = append(instructions, PaymentInstruction{
			TradeID:       spvTx.ID,
			AssetID:       asset.ID,
			TotalAmount:   amount,
			Currency:      spvTx.Currency,
			Method:        SettlementSEPA,
			PayerWalletID: payerID,
			PayeeWalletID: payeeID,
			Reference:     ref,
			ExpiresAt:     spvTx.EffectiveAt + 7*86400, // 7-day payment window
		})
	}

	return instructions, nil
}
