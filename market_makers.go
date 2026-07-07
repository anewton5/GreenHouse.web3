package gonetwork

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
)

type MarketMakerStatus string

const (
	MarketMakerStatusActive  MarketMakerStatus = "active"
	MarketMakerStatusRevoked MarketMakerStatus = "revoked"
	MarketMakerStatusExpired MarketMakerStatus = "expired"
)

type MarketMakerAgreement struct {
	ID                    string            `json:"id"`
	AssetID               string            `json:"asset_id"`
	DealerKey             string            `json:"dealer_key"`
	DealerLEI             string            `json:"dealer_lei,omitempty"`
	FeeRebateBps          int               `json:"fee_rebate_bps"`
	MaxSpreadBps          int               `json:"max_spread_bps"`
	MinQuoteSize          float64           `json:"min_quote_size"`
	PriorityAllocationPct float64           `json:"priority_allocation_pct"`
	MaxPositionUnits      float64           `json:"max_position_units,omitempty"`
	MaxPositionValue      float64           `json:"max_position_value,omitempty"`
	EffectiveFrom         int64             `json:"effective_from"`
	EffectiveTo           int64             `json:"effective_to,omitempty"`
	Status                MarketMakerStatus `json:"status"`
	CreatedAt             int64             `json:"created_at"`
	OperatorSignature     []byte            `json:"-"`
}

func (a *MarketMakerAgreement) SigningHash() []byte {
	cp := *a
	cp.OperatorSignature = nil
	data, _ := json.Marshal(cp)
	hash := sha3.Sum256(data)
	return hash[:]
}

func (a *MarketMakerAgreement) VerifyOperatorSignature(pub *PublicKey) bool {
	if a == nil || pub == nil || len(a.OperatorSignature) == 0 {
		return false
	}
	sig := &Signature{value: a.OperatorSignature}
	return sig.Verify(pub, a.SigningHash())
}

func (a *MarketMakerAgreement) IsActiveAt(now int64) bool {
	if a == nil {
		return false
	}
	if a.Status != MarketMakerStatusActive {
		return false
	}
	if now < a.EffectiveFrom {
		return false
	}
	return a.EffectiveTo == 0 || now <= a.EffectiveTo
}

func NewMarketMakerAgreement(
	operatorKey *PrivateKey,
	assetID, dealerKey, dealerLEI string,
	feeRebateBps, maxSpreadBps int,
	minQuoteSize, priorityAllocationPct, maxPositionUnits, maxPositionValue float64,
	effectiveFrom, effectiveTo int64,
) (*MarketMakerAgreement, error) {
	if operatorKey == nil {
		return nil, fmt.Errorf("operator key must not be nil")
	}
	return NewMarketMakerAgreementWithProvider(
		NewLocalKeyProvider(operatorKey),
		assetID,
		dealerKey,
		dealerLEI,
		feeRebateBps,
		maxSpreadBps,
		minQuoteSize,
		priorityAllocationPct,
		maxPositionUnits,
		maxPositionValue,
		effectiveFrom,
		effectiveTo,
	)
}

func NewMarketMakerAgreementWithProvider(
	operatorKey KeyProvider,
	assetID, dealerKey, dealerLEI string,
	feeRebateBps, maxSpreadBps int,
	minQuoteSize, priorityAllocationPct, maxPositionUnits, maxPositionValue float64,
	effectiveFrom, effectiveTo int64,
) (*MarketMakerAgreement, error) {
	if operatorKey == nil {
		return nil, fmt.Errorf("operator key provider must not be nil")
	}
	if assetID == "" {
		return nil, fmt.Errorf("asset ID must not be empty")
	}
	if dealerKey == "" {
		return nil, fmt.Errorf("dealer key must not be empty")
	}
	if dealerLEI == "" {
		return nil, fmt.Errorf("dealer LEI must not be empty")
	}
	if _, err := PublicKeyFromString(dealerKey); err != nil {
		return nil, fmt.Errorf("dealer key is not a valid Ed25519 public key: %w", err)
	}
	if feeRebateBps < 0 {
		return nil, fmt.Errorf("fee rebate bps must be >= 0")
	}
	if maxSpreadBps < 0 {
		return nil, fmt.Errorf("max spread bps must be >= 0")
	}
	if minQuoteSize <= 0 {
		return nil, fmt.Errorf("min quote size must be greater than zero")
	}
	if priorityAllocationPct < 0 {
		return nil, fmt.Errorf("priority allocation pct must be >= 0")
	}
	if effectiveFrom <= 0 {
		effectiveFrom = time.Now().Unix()
	}
	if effectiveTo != 0 && effectiveTo < effectiveFrom {
		return nil, fmt.Errorf("effective_to must be zero or greater than/equal to effective_from")
	}

	createdAt := time.Now().Unix()
	idHash := sha3.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%d", assetID, dealerKey, dealerLEI, createdAt)))
	agreement := &MarketMakerAgreement{
		ID:                    hex.EncodeToString(idHash[:]),
		AssetID:               assetID,
		DealerKey:             dealerKey,
		DealerLEI:             dealerLEI,
		FeeRebateBps:          feeRebateBps,
		MaxSpreadBps:          maxSpreadBps,
		MinQuoteSize:          minQuoteSize,
		PriorityAllocationPct: priorityAllocationPct,
		MaxPositionUnits:      maxPositionUnits,
		MaxPositionValue:      maxPositionValue,
		EffectiveFrom:         effectiveFrom,
		EffectiveTo:           effectiveTo,
		Status:                MarketMakerStatusActive,
		CreatedAt:             createdAt,
	}
	sig, err := operatorKey.Sign(agreement.SigningHash())
	if err != nil {
		return nil, fmt.Errorf("failed to sign market maker agreement: %w", err)
	}
	agreement.OperatorSignature = sig
	return agreement, nil
}

type MarketMakerRegistry struct {
	ByAsset  map[string][]*MarketMakerAgreement `json:"by_asset"`
	verifier func(*MarketMakerAgreement) error  `json:"-"`
}

func NewMarketMakerRegistry() *MarketMakerRegistry {
	return &MarketMakerRegistry{ByAsset: make(map[string][]*MarketMakerAgreement)}
}

func (r *MarketMakerRegistry) RegisterMarketMaker(a *MarketMakerAgreement) error {
	if r == nil {
		return fmt.Errorf("market maker registry is nil")
	}
	if a == nil {
		return fmt.Errorf("market maker agreement is nil")
	}
	if a.AssetID == "" || a.DealerKey == "" {
		return fmt.Errorf("market maker agreement must include asset_id and dealer_key")
	}
	if r.verifier != nil {
		if err := r.verifier(a); err != nil {
			return err
		}
	}
	if r.ByAsset == nil {
		r.ByAsset = make(map[string][]*MarketMakerAgreement)
	}
	for _, existing := range r.ByAsset[a.AssetID] {
		if existing == nil {
			continue
		}
		if existing.ID == a.ID {
			return fmt.Errorf("market maker agreement %s already exists", a.ID)
		}
		if existing.DealerKey == a.DealerKey && existing.IsActiveAt(time.Now().Unix()) {
			return fmt.Errorf("dealer already has an active market maker agreement for asset %s", a.AssetID)
		}
	}
	cp := *a
	r.ByAsset[a.AssetID] = append(r.ByAsset[a.AssetID], &cp)
	return nil
}

func (r *MarketMakerRegistry) RevokeMarketMaker(id string) error {
	if r == nil {
		return fmt.Errorf("market maker registry is nil")
	}
	for _, agreements := range r.ByAsset {
		for _, agreement := range agreements {
			if agreement != nil && agreement.ID == id {
				agreement.Status = MarketMakerStatusRevoked
				return nil
			}
		}
	}
	return fmt.Errorf("market maker agreement %s not found", id)
}

func (r *MarketMakerRegistry) IsDesignatedMarketMaker(assetID, walletKey string) bool {
	return r.AgreementFor(assetID, walletKey) != nil
}

func (r *MarketMakerRegistry) ActiveAgreementsFor(assetID string) []*MarketMakerAgreement {
	if r == nil {
		return nil
	}
	now := time.Now().Unix()
	var out []*MarketMakerAgreement
	for _, agreement := range r.ByAsset[assetID] {
		if agreement != nil && agreement.IsActiveAt(now) {
			out = append(out, agreement)
		}
	}
	return out
}

func (r *MarketMakerRegistry) AgreementFor(assetID, walletKey string) *MarketMakerAgreement {
	if r == nil {
		return nil
	}
	now := time.Now().Unix()
	for _, agreement := range r.ByAsset[assetID] {
		if agreement != nil && agreement.DealerKey == walletKey && agreement.IsActiveAt(now) {
			return agreement
		}
	}
	return nil
}

func (r *MarketMakerRegistry) AgreementByID(id string) *MarketMakerAgreement {
	if r == nil {
		return nil
	}
	for _, agreements := range r.ByAsset {
		for _, agreement := range agreements {
			if agreement != nil && agreement.ID == id {
				return agreement
			}
		}
	}
	return nil
}

type MarketMakerTransactionAction string

const (
	MarketMakerActionRegister MarketMakerTransactionAction = "register"
	MarketMakerActionRevoke   MarketMakerTransactionAction = "revoke"
)

type MarketMakerTransaction struct {
	Tx        Transaction
	Agreement MarketMakerAgreement
	Action    MarketMakerTransactionAction
	RevokeID  string `json:",omitempty"`
}

func NewMarketMakerTransaction(provider KeyProvider, agreement MarketMakerAgreement, action MarketMakerTransactionAction, revokeID string) (MarketMakerTransaction, error) {
	if provider == nil {
		return MarketMakerTransaction{}, fmt.Errorf("operator key provider must not be nil")
	}
	receiver := agreement.DealerKey
	if action == MarketMakerActionRevoke {
		receiver = revokeID
	}
	tx := Transaction{
		Sender:       provider.PublicKeyString(),
		Receiver:     receiver,
		Amount:       0,
		RequiredSigs: 1,
		Nonce:        time.Now().UnixNano(),
	}
	sig, err := provider.Sign(tx.hash())
	if err != nil {
		return MarketMakerTransaction{}, fmt.Errorf("failed to sign market maker transaction: %w", err)
	}
	tx.AddSignature(sig)
	return MarketMakerTransaction{
		Tx:        tx,
		Agreement: agreement,
		Action:    action,
		RevokeID:  revokeID,
	}, nil
}
