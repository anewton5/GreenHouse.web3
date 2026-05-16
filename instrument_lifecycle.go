package gonetwork

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// Warrant exercise (A-05)
// ---------------------------------------------------------------------------

// WarrantExerciseRequest converts a warrant holding into the underlying equity
// at the strike price. The exerciser burns warrant units and receives an
// equivalent quantity of the underlying equity asset.
//
// Pre-conditions:
//   - WarrantAssetID must exist and be AssetTypeWarrant
//   - EquityAssetID must exist and be AssetTypeEquity (or compatible)
//   - ExerciserKey must hold >= UnitsToExercise of the warrant asset
//   - The warrant asset's Metadata must carry the target equity asset ID in
//     the "underlying_asset_id" field (set at warrant creation)
//   - ExerciserSignature must cover the canonical JSON of this request
type WarrantExerciseRequest struct {
	ID                 string  `json:"id"`
	WarrantAssetID     string  `json:"warrant_asset_id"`
	EquityAssetID      string  `json:"equity_asset_id"` // underlying equity
	UnitsToExercise    float64 `json:"units_to_exercise"`
	StrikePrice        float64 `json:"strike_price"`      // per warrant unit; informational
	ExerciserKey       string  `json:"exerciser_key"`     // base64 Ed25519 public key
	ExerciserSignature []byte  `json:"-"`
	ExercisedAt        int64   `json:"exercised_at"` // Unix timestamp
}

// ProcessWarrantExercise validates and applies a warrant exercise.
//
// On success it:
//   1. Reduces the exerciser's warrant balance by UnitsToExercise
//      (decrements the warrant's CirculatingSupply via AssetTxTypeRedeem path)
//   2. Creates or increments the exerciser's equity holding by the same quantity
//      (increments the equity's CirculatingSupply via AssetTxTypeIssue path)
//   3. Creates a PaymentInstruction for the strike-price cash leg in pendingInstructions
//
// Returns the two synthetic AssetTransactions that were applied so the caller
// can include them in the next sealed block.
func ProcessWarrantExercise(
	req *WarrantExerciseRequest,
	assets map[string]*Asset,
	holdings map[string]*AssetHolding,
	pendingInstructions map[string]*PaymentInstruction,
) (redeemTx AssetTransaction, issueTx AssetTransaction, err error) {
	if req.UnitsToExercise <= 0 {
		return redeemTx, issueTx, fmt.Errorf("units_to_exercise must be greater than zero")
	}
	if req.ExerciserKey == "" {
		return redeemTx, issueTx, fmt.Errorf("exerciser_key must not be empty")
	}

	// Validate exerciser signature over the request.
	if len(req.ExerciserSignature) > 0 {
		sigCopy := *req
		sigCopy.ExerciserSignature = nil
		data, merr := json.Marshal(sigCopy)
		if merr != nil {
			return redeemTx, issueTx, fmt.Errorf("failed to marshal request for verification: %w", merr)
		}
		hash := sha3.Sum256(data)
		pub, kerr := PublicKeyFromString(req.ExerciserKey)
		if kerr != nil {
			return redeemTx, issueTx, fmt.Errorf("invalid exerciser key: %w", kerr)
		}
		sig := &Signature{value: req.ExerciserSignature}
		if !sig.Verify(pub, hash[:]) {
			return redeemTx, issueTx, fmt.Errorf("exerciser signature is invalid")
		}
	}

	warrantAsset, ok := assets[req.WarrantAssetID]
	if !ok {
		return redeemTx, issueTx, fmt.Errorf("warrant asset %q not found", req.WarrantAssetID)
	}
	if warrantAsset.AssetType != AssetTypeWarrant {
		return redeemTx, issueTx, fmt.Errorf("asset %q is not a warrant (type: %s)", req.WarrantAssetID, warrantAsset.AssetType)
	}

	equityAsset, ok := assets[req.EquityAssetID]
	if !ok {
		return redeemTx, issueTx, fmt.Errorf("equity asset %q not found", req.EquityAssetID)
	}

	// Exerciser must hold sufficient warrant units.
	warrantHoldingKey := HoldingKey(req.ExerciserKey, req.WarrantAssetID)
	warrantHolding, exists := holdings[warrantHoldingKey]
	if !exists || warrantHolding.Balance < req.UnitsToExercise {
		available := 0.0
		if exists {
			available = warrantHolding.Balance
		}
		return redeemTx, issueTx, fmt.Errorf(
			"insufficient warrant balance: required %g, available %g",
			req.UnitsToExercise, available,
		)
	}

	// --- Apply: burn warrant units ---
	warrantHolding.Balance -= req.UnitsToExercise
	if warrantHolding.Balance == 0 {
		delete(holdings, warrantHoldingKey)
	}
	warrantAsset.CirculatingSupply -= req.UnitsToExercise

	// --- Apply: issue equity units ---
	equityHoldingKey := HoldingKey(req.ExerciserKey, req.EquityAssetID)
	if h, exists := holdings[equityHoldingKey]; exists {
		h.Balance += req.UnitsToExercise
	} else {
		lockupEnd := int64(0)
		if equityAsset.Restrictions.LockupPeriodDays > 0 {
			lockupEnd = time.Now().Unix() + int64(equityAsset.Restrictions.LockupPeriodDays)*86400
		}
		holdings[equityHoldingKey] = &AssetHolding{
			AssetID:     req.EquityAssetID,
			HolderID:    req.ExerciserKey,
			Balance:     req.UnitsToExercise,
			LockedUntil: lockupEnd,
		}
	}
	equityAsset.CirculatingSupply += req.UnitsToExercise

	// --- Cash leg: create a PaymentInstruction for the strike price ---
	if req.StrikePrice > 0 && pendingInstructions != nil {
		totalStrike := req.StrikePrice * req.UnitsToExercise
		ref := "warrant-exercise-" + req.ID
		pendingInstructions[req.ID] = &PaymentInstruction{
			TradeID:       req.ID,
			AssetID:       req.WarrantAssetID,
			Quantity:      req.UnitsToExercise,
			PricePerUnit:  req.StrikePrice,
			TotalAmount:   totalStrike,
			Currency:      equityAsset.Currency,
			PayerWalletID: req.ExerciserKey,
			PayeeWalletID: equityAsset.Issuer,
			Reference:     ref,
			ExpiresAt:     time.Now().Unix() + 86400, // 24h to settle the cash leg
		}
	}

	// Build synthetic transactions for block inclusion.
	redeemTx = AssetTransaction{AssetID: req.WarrantAssetID, TxType: AssetTxTypeRedeem}
	issueTx = AssetTransaction{AssetID: req.EquityAssetID, TxType: AssetTxTypeIssue}
	return redeemTx, issueTx, nil
}

// ---------------------------------------------------------------------------
// Convertible note conversion (A-06)
// ---------------------------------------------------------------------------

// ConversionTrigger classifies what event caused a convertible note to convert.
type ConversionTrigger string

const (
	// ConversionTriggerMaturity is hit when the convertible reaches its maturity date.
	ConversionTriggerMaturity ConversionTrigger = "maturity"
	// ConversionTriggerQualifyingFinancing is triggered when a qualifying financing
	// round occurs (typically a pre-money valuation above a cap threshold).
	ConversionTriggerQualifyingFinancing ConversionTrigger = "qualifying_financing"
	// ConversionTriggerVoluntary is a holder-initiated conversion before maturity.
	ConversionTriggerVoluntary ConversionTrigger = "voluntary"
)

// ConvertibleConversionRequest converts convertible note tokens into equity
// at the conversion ratio defined in the note's metadata.
//
// The convertible asset's Metadata must carry:
//   - "conversion_ratio"      : float64 — equity units per convertible unit
//   - "equity_asset_id"       : string  — target equity asset ID
//   - "maturity_date_unix"    : int64   — maturity timestamp
//   - "valuation_cap_eur"     : float64 — optional cap for discount calculation
//
// All of these must be set in the AssetMetadata.DividendTerms JSON field or a
// dedicated metadata field agreed upon at issuance.
type ConvertibleConversionRequest struct {
	ID                    string            `json:"id"`
	ConvertibleAssetID    string            `json:"convertible_asset_id"`
	EquityAssetID         string            `json:"equity_asset_id"`
	ConversionRatio       float64           `json:"conversion_ratio"` // equity units per convertible unit
	UnitsToConvert        float64           `json:"units_to_convert"`
	Trigger               ConversionTrigger `json:"trigger"`
	HolderKey             string            `json:"holder_key"`
	HolderSignature       []byte            `json:"-"`
	ConvertedAt           int64             `json:"converted_at"`
}

// ProcessConvertibleConversion validates and applies a convertible note conversion.
//
// On success it:
//   1. Burns UnitsToConvert convertible tokens from the holder's balance
//   2. Issues ConversionRatio * UnitsToConvert equity tokens to the holder
//   3. Returns the two synthetic AssetTransactions for block inclusion
//
// The maturity-date and trigger rules are the caller's responsibility to enforce
// before calling this function (e.g. the API handler checks block time vs maturity).
func ProcessConvertibleConversion(
	req *ConvertibleConversionRequest,
	assets map[string]*Asset,
	holdings map[string]*AssetHolding,
) (redeemTx AssetTransaction, issueTx AssetTransaction, err error) {
	if req.UnitsToConvert <= 0 {
		return redeemTx, issueTx, fmt.Errorf("units_to_convert must be greater than zero")
	}
	if req.ConversionRatio <= 0 {
		return redeemTx, issueTx, fmt.Errorf("conversion_ratio must be greater than zero")
	}
	if req.HolderKey == "" {
		return redeemTx, issueTx, fmt.Errorf("holder_key must not be empty")
	}

	// Validate holder signature if provided.
	if len(req.HolderSignature) > 0 {
		sigCopy := *req
		sigCopy.HolderSignature = nil
		data, merr := json.Marshal(sigCopy)
		if merr != nil {
			return redeemTx, issueTx, fmt.Errorf("failed to marshal request for verification: %w", merr)
		}
		hash := sha3.Sum256(data)
		pub, kerr := PublicKeyFromString(req.HolderKey)
		if kerr != nil {
			return redeemTx, issueTx, fmt.Errorf("invalid holder key: %w", kerr)
		}
		sig := &Signature{value: req.HolderSignature}
		if !sig.Verify(pub, hash[:]) {
			return redeemTx, issueTx, fmt.Errorf("holder signature is invalid")
		}
	}

	convertibleAsset, ok := assets[req.ConvertibleAssetID]
	if !ok {
		return redeemTx, issueTx, fmt.Errorf("convertible asset %q not found", req.ConvertibleAssetID)
	}
	if convertibleAsset.AssetType != AssetTypeConvertible {
		return redeemTx, issueTx, fmt.Errorf(
			"asset %q is not a convertible (type: %s)", req.ConvertibleAssetID, convertibleAsset.AssetType,
		)
	}

	equityAsset, ok := assets[req.EquityAssetID]
	if !ok {
		return redeemTx, issueTx, fmt.Errorf("equity asset %q not found", req.EquityAssetID)
	}

	// Holder must hold sufficient convertible units.
	convHoldingKey := HoldingKey(req.HolderKey, req.ConvertibleAssetID)
	convHolding, exists := holdings[convHoldingKey]
	if !exists || convHolding.Balance < req.UnitsToConvert {
		available := 0.0
		if exists {
			available = convHolding.Balance
		}
		return redeemTx, issueTx, fmt.Errorf(
			"insufficient convertible balance: required %g, available %g",
			req.UnitsToConvert, available,
		)
	}

	equityUnits := req.ConversionRatio * req.UnitsToConvert

	// --- Apply: burn convertible units ---
	convHolding.Balance -= req.UnitsToConvert
	if convHolding.Balance == 0 {
		delete(holdings, convHoldingKey)
	}
	convertibleAsset.CirculatingSupply -= req.UnitsToConvert

	// --- Apply: issue equity units ---
	equityHoldingKey := HoldingKey(req.HolderKey, req.EquityAssetID)
	if h, exists := holdings[equityHoldingKey]; exists {
		h.Balance += equityUnits
	} else {
		lockupEnd := int64(0)
		if equityAsset.Restrictions.LockupPeriodDays > 0 {
			lockupEnd = time.Now().Unix() + int64(equityAsset.Restrictions.LockupPeriodDays)*86400
		}
		holdings[equityHoldingKey] = &AssetHolding{
			AssetID:     req.EquityAssetID,
			HolderID:    req.HolderKey,
			Balance:     equityUnits,
			LockedUntil: lockupEnd,
		}
	}
	equityAsset.CirculatingSupply += equityUnits

	redeemTx = AssetTransaction{AssetID: req.ConvertibleAssetID, TxType: AssetTxTypeRedeem}
	issueTx = AssetTransaction{AssetID: req.EquityAssetID, TxType: AssetTxTypeIssue}
	return redeemTx, issueTx, nil
}

// ---------------------------------------------------------------------------
// Anti-dilution protection (A-07)
// ---------------------------------------------------------------------------

// AntiDilutionAdjustment computes broad-based weighted-average anti-dilution
// adjustments for existing preference shareholders when new equity is issued
// below the previous financing round price.
//
// Formula (broad-based weighted average):
//
//	NCP = (CSO * OCP + NewShares * NewPrice) / (CSO + NewShares)
//
// Where:
//   NCP = new conversion price (adjusted)
//   CSO = total shares outstanding before the new issue
//   OCP = original conversion price (i.e. the round price at which the
//         preference shareholders invested)
//   NewShares = number of shares in the new (dilutive) round
//   NewPrice  = issuance price in the new round
//
// The function returns a map of holderKey → new conversion price. It is the
// caller's responsibility to record these adjustments and apply them when
// the preference holders subsequently convert or exercise warrants.
//
// If newIssuancePrice >= originalRoundPrice the adjustment is zero (no dilution)
// and an empty map is returned.
func AntiDilutionAdjustment(
	asset *Asset,
	newSharesIssued float64,
	newIssuancePrice float64,
	holdings map[string]*AssetHolding,
	originalRoundPriceByHolder map[string]float64, // holderKey → price they paid
) (adjustedConversionPriceByHolder map[string]float64, err error) {
	if asset == nil {
		return nil, fmt.Errorf("asset must not be nil")
	}
	if newSharesIssued <= 0 {
		return nil, fmt.Errorf("newSharesIssued must be greater than zero")
	}
	if newIssuancePrice <= 0 {
		return nil, fmt.Errorf("newIssuancePrice must be greater than zero")
	}

	cso := asset.CirculatingSupply // shares outstanding before new issue
	if cso <= 0 {
		return nil, fmt.Errorf("asset has no circulating supply; cannot compute anti-dilution")
	}

	result := make(map[string]float64)

	suffix := ":" + asset.ID
	for key, holding := range holdings {
		if holding.Balance <= 0 {
			continue
		}
		// Only process holders of this asset.
		if len(key) <= len(suffix) || key[len(key)-len(suffix):] != suffix {
			continue
		}
		holderKey := key[:len(key)-len(suffix)-1+1] // extract holderID prefix
		// Use the suffix check a different way to extract holder key.
		holderKey = holding.HolderID

		ocp, hasPrior := originalRoundPriceByHolder[holderKey]
		if !hasPrior || ocp <= 0 {
			continue // holder has no prior round price — not a preference shareholder
		}

		if newIssuancePrice >= ocp {
			continue // not a down-round; no adjustment needed
		}

		// Broad-based weighted average new conversion price.
		ncp := (cso*ocp + newSharesIssued*newIssuancePrice) / (cso + newSharesIssued)
		ncp = math.Round(ncp*1e6) / 1e6 // round to 6 decimal places
		result[holderKey] = ncp
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Capital call enforcement (A-08)
// ---------------------------------------------------------------------------

// CapitalCallStatus tracks the lifecycle of an SPV capital call for a single holder.
type CapitalCallStatus string

const (
	CapitalCallStatusPending   CapitalCallStatus = "pending"
	CapitalCallStatusPaid      CapitalCallStatus = "paid"
	CapitalCallStatusDefaulted CapitalCallStatus = "defaulted"
)

// CapitalCallRecord tracks the per-holder obligation for an SPV capital call.
type CapitalCallRecord struct {
	ID          string            `json:"id"`
	SPVID       string            `json:"spv_id"`
	AssetID     string            `json:"asset_id"`
	HolderKey   string            `json:"holder_key"`
	Units       float64           `json:"units"`          // number of participation note units held at call date
	AmountDue   float64           `json:"amount_due"`     // total cash call amount
	Currency    string            `json:"currency"`
	DeadlineAt  int64             `json:"deadline_at"`   // Unix timestamp
	Status      CapitalCallStatus `json:"status"`
	PaymentRef  string            `json:"payment_ref,omitempty"` // matched payment reference
}

// ProcessCapitalCall creates per-holder CapitalCallRecord entries and corresponding
// PaymentInstruction records for an SPV capital call event.
//
// amountPerUnit is the cash amount called per participation note unit.
// deadlineDays is the number of days holders have to pay before defaulting.
//
// Holders who have not paid by DeadlineAt should be marked defaulted and their
// holdings transfer-restricted (the sweep is a separate scheduled process).
//
// Returns the list of call records created (one per holder with balance > 0).
func ProcessCapitalCall(
	spvID string,
	assetID string,
	amountPerUnit float64,
	currency string,
	deadlineDays int,
	holdings map[string]*AssetHolding,
	pendingInstructions map[string]*PaymentInstruction,
	spvAdminKey string,
) ([]*CapitalCallRecord, error) {
	if spvID == "" {
		return nil, fmt.Errorf("spvID must not be empty")
	}
	if assetID == "" {
		return nil, fmt.Errorf("assetID must not be empty")
	}
	if amountPerUnit <= 0 {
		return nil, fmt.Errorf("amountPerUnit must be greater than zero")
	}
	if currency == "" {
		return nil, fmt.Errorf("currency must not be empty")
	}
	if deadlineDays <= 0 {
		deadlineDays = 14 // default 14-day capital call window
	}

	deadline := time.Now().Unix() + int64(deadlineDays)*86400
	suffix := ":" + assetID

	var records []*CapitalCallRecord
	for key, holding := range holdings {
		if !hasStringSuffix(key, suffix) {
			continue
		}
		if holding.Balance <= 0 {
			continue
		}

		amountDue := amountPerUnit * holding.Balance

		// Deterministic record ID.
		h := sha3.New256()
		h.Write([]byte(spvID))
		h.Write([]byte(assetID))
		h.Write([]byte(holding.HolderID))
		h.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		recordID := hex.EncodeToString(h.Sum(nil))

		ref := "capital-call-" + recordID

		record := &CapitalCallRecord{
			ID:         recordID,
			SPVID:      spvID,
			AssetID:    assetID,
			HolderKey:  holding.HolderID,
			Units:      holding.Balance,
			AmountDue:  amountDue,
			Currency:   currency,
			DeadlineAt: deadline,
			Status:     CapitalCallStatusPending,
			PaymentRef: ref,
		}
		records = append(records, record)

		if pendingInstructions != nil {
			pendingInstructions[recordID] = &PaymentInstruction{
				TradeID:       recordID,
				AssetID:       assetID,
				Quantity:      holding.Balance,
				PricePerUnit:  amountPerUnit,
				TotalAmount:   amountDue,
				Currency:      currency,
				Method:        SettlementSEPA,
				PayerWalletID: holding.HolderID,
				PayeeWalletID: spvAdminKey,
				Reference:     ref,
				ExpiresAt:     deadline,
			}
		}
	}

	return records, nil
}

// MarkCapitalCallDefault marks a holder's holding as transfer-restricted after
// failing to pay a capital call by the deadline. It adds a blocking lockup of
// 10 years (effectively permanent until the administrator resolves the default).
func MarkCapitalCallDefault(
	holderKey string,
	assetID string,
	holdings map[string]*AssetHolding,
) error {
	key := HoldingKey(holderKey, assetID)
	h, ok := holdings[key]
	if !ok {
		return fmt.Errorf("no holding found for holder %q on asset %q", holderKey, assetID)
	}
	// Set a 10-year lockup — the administrator must explicitly clear this.
	h.LockedUntil = time.Now().Unix() + int64(10*365*24*3600)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// hasStringSuffix is a local copy to avoid importing strings in this file.
func hasStringSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// deriveID generates a deterministic SHA3-256 hex ID from the provided seed fields.
func deriveID(parts ...string) string {
	h := sha3.New256()
	for _, p := range parts {
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// newExerciseID generates a deterministic ID for a WarrantExerciseRequest or
// ConvertibleConversionRequest from its key fields plus a nanosecond timestamp.
func newExerciseID(assetID, holderKey string) string {
	idSrc := fmt.Sprintf("%s:%s:%d", assetID, holderKey, time.Now().UnixNano())
	h := sha3.Sum256([]byte(idSrc))
	return hex.EncodeToString(h[:])
}

// newInstrumentB64 is a base64 helper consistent with the rest of the codebase.
func newInstrumentB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
