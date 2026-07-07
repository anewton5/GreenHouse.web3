package gonetwork

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
)

type RFQRequestStatus string

const (
	RFQRequestStatusOpen      RFQRequestStatus = "open"
	RFQRequestStatusQuoted    RFQRequestStatus = "quoted"
	RFQRequestStatusAccepted  RFQRequestStatus = "accepted"
	RFQRequestStatusExpired   RFQRequestStatus = "expired"
	RFQRequestStatusCancelled RFQRequestStatus = "cancelled"
)

type RFQRequest struct {
	ID           string           `json:"id"`
	AssetID      string           `json:"asset_id"`
	RequesterKey string           `json:"requester_key"`
	Side         OrderSide        `json:"side"`
	Quantity     float64          `json:"quantity"`
	LimitPrice   float64          `json:"limit_price,omitempty"`
	ExpiresAt    int64            `json:"expires_at"`
	Status       RFQRequestStatus `json:"status"`
	CreatedAt    int64            `json:"created_at"`
	Signature    []byte           `json:"-"`
}

type RFQQuoteStatus string

const (
	RFQQuoteStatusActive   RFQQuoteStatus = "active"
	RFQQuoteStatusAccepted RFQQuoteStatus = "accepted"
	RFQQuoteStatusRejected RFQQuoteStatus = "rejected"
	RFQQuoteStatusExpired  RFQQuoteStatus = "expired"
)

type RFQQuote struct {
	ID        string         `json:"id"`
	RequestID string         `json:"request_id"`
	DealerKey string         `json:"dealer_key"`
	Price     float64        `json:"price"`
	Quantity  float64        `json:"quantity"`
	ExpiresAt int64          `json:"expires_at"`
	Status    RFQQuoteStatus `json:"status"`
	CreatedAt int64          `json:"created_at"`
	Signature []byte         `json:"-"`
}

type RFQTransactionAction string

const (
	RFQActionRequest RFQTransactionAction = "request"
	RFQActionQuote   RFQTransactionAction = "quote"
	RFQActionAccept  RFQTransactionAction = "accept"
	RFQActionCancel  RFQTransactionAction = "cancel"
)

type RFQTransaction struct {
	Tx       Transaction
	Action   RFQTransactionAction
	Request  RFQRequest `json:",omitempty"`
	Quote    RFQQuote   `json:",omitempty"`
	AcceptID string     `json:",omitempty"`
}

func NewRFQRequest(
	requesterKey *PrivateKey,
	assetID string,
	side OrderSide,
	quantity, limitPrice float64,
	expiresAt int64,
) (*RFQRequest, error) {
	if requesterKey == nil {
		return nil, fmt.Errorf("requester key must not be nil")
	}
	if assetID == "" {
		return nil, fmt.Errorf("asset ID must not be empty")
	}
	if quantity <= 0 {
		return nil, fmt.Errorf("quantity must be greater than zero")
	}
	if limitPrice < 0 {
		return nil, fmt.Errorf("limit price must be >= 0")
	}
	if expiresAt <= time.Now().Unix() {
		return nil, fmt.Errorf("expiresAt must be in the future")
	}

	createdAt := time.Now().Unix()
	idHash := sha3.Sum256([]byte(fmt.Sprintf("%x:%s:%d", requesterKey.Public().Bytes(), assetID, time.Now().UnixNano())))
	req := &RFQRequest{
		ID:           hex.EncodeToString(idHash[:]),
		AssetID:      assetID,
		RequesterKey: encodeStdBase64(requesterKey.Public().Bytes()),
		Side:         side,
		Quantity:     quantity,
		LimitPrice:   limitPrice,
		ExpiresAt:    expiresAt,
		Status:       RFQRequestStatusOpen,
		CreatedAt:    createdAt,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RFQ request for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	req.Signature = requesterKey.Sign(hash[:]).Bytes()
	return req, nil
}

func NewRFQQuote(
	dealerKey *PrivateKey,
	requestID string,
	price, quantity float64,
	expiresAt int64,
) (*RFQQuote, error) {
	if dealerKey == nil {
		return nil, fmt.Errorf("dealer key must not be nil")
	}
	if requestID == "" {
		return nil, fmt.Errorf("request ID must not be empty")
	}
	if price <= 0 {
		return nil, fmt.Errorf("price must be greater than zero")
	}
	if quantity <= 0 {
		return nil, fmt.Errorf("quantity must be greater than zero")
	}
	if expiresAt <= time.Now().Unix() {
		return nil, fmt.Errorf("expiresAt must be in the future")
	}

	createdAt := time.Now().Unix()
	idHash := sha3.Sum256([]byte(fmt.Sprintf("%x:%s:%d", dealerKey.Public().Bytes(), requestID, time.Now().UnixNano())))
	quote := &RFQQuote{
		ID:        hex.EncodeToString(idHash[:]),
		RequestID: requestID,
		DealerKey: encodeStdBase64(dealerKey.Public().Bytes()),
		Price:     price,
		Quantity:  quantity,
		ExpiresAt: expiresAt,
		Status:    RFQQuoteStatusActive,
		CreatedAt: createdAt,
	}
	data, err := json.Marshal(quote)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RFQ quote for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	quote.Signature = dealerKey.Sign(hash[:]).Bytes()
	return quote, nil
}

func (r *RFQRequest) VerifySignature(pub *PublicKey) bool {
	if r == nil || pub == nil || len(r.Signature) == 0 {
		return false
	}
	cp := *r
	cp.Signature = nil
	data, err := json.Marshal(cp)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: r.Signature}
	return sig.Verify(pub, hash[:])
}

func (q *RFQQuote) VerifySignature(pub *PublicKey) bool {
	if q == nil || pub == nil || len(q.Signature) == 0 {
		return false
	}
	cp := *q
	cp.Signature = nil
	data, err := json.Marshal(cp)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: q.Signature}
	return sig.Verify(pub, hash[:])
}

func (r *RFQRequest) IsExpired() bool {
	return r != nil && r.ExpiresAt > 0 && time.Now().Unix() > r.ExpiresAt
}

func (q *RFQQuote) IsExpired() bool {
	return q != nil && q.ExpiresAt > 0 && time.Now().Unix() > q.ExpiresAt
}

// ValidateRFQAcceptCompliance runs the same compliance battery handleFillOrder
// runs for issuer-as-dealer OTC fills: credential-expiry check, MiFID II
// suitability, prospectus exemption caps, jurisdiction rules, FATF Travel Rule
// derivation, and AML screening. transferRef is used as the Travel Rule
// reference and should uniquely identify the trade (e.g. "rfq:<quoteID>").
//
// This is the single source of truth for RFQ-accept compliance — both the API
// handler (before building the transaction) and applyBlockState's RFQ accept
// branch (before executing the trade) call this same method, so the checks
// are enforced regardless of which path an RFQ accept transaction reaches
// applyBlockState through (defense-in-depth, matching the AssetTransaction.Validate
// pattern used by the compliance gate elsewhere).
//
// Like executeTradeDVP, this method assumes any necessary locking has already
// been handled by the caller — it does not acquire bc.Mu itself.
func (bc *Blockchain) ValidateRFQAcceptCompliance(buyerKey, sellerKey string, asset *Asset, quantity, price float64, transferRef string) error {
	if bc == nil {
		return fmt.Errorf("blockchain is nil")
	}
	if asset == nil {
		return fmt.Errorf("asset is nil")
	}
	buyerCred := bc.Credentials[buyerKey]
	if buyerCred != nil && buyerCred.ExpiresAt > 0 && time.Now().Unix() > buyerCred.ExpiresAt {
		return fmt.Errorf("buyer KYC credential has expired (expired at unix %d): re-KYC required", buyerCred.ExpiresAt)
	}
	if err := CheckSuitability(buyerKey, asset, bc.SuitabilityAssessments); err != nil {
		return err
	}
	if exemption, hasExemption := bc.ProspectusExemptions[asset.ID]; hasExemption {
		if err := CheckProspectusLimits(buyerCred, exemption); err != nil {
			return err
		}
	}
	if buyerCred != nil {
		if rule, hasRule := bc.JurisdictionRules[buyerCred.Jurisdiction]; hasRule {
			currentRetailCount := CountJurisdictionRetailHolders(asset.ID, buyerCred.Jurisdiction, bc.Holdings, bc.Credentials)
			if err := ApplyJurisdictionRule(rule, nil, buyerCred, asset, 0, currentRetailCount); err != nil {
				return err
			}
		}
	}
	if _, err := bc.AutoTravelRule(buyerKey, sellerKey, transferRef, quantity*price, asset.Currency); err != nil {
		return fmt.Errorf("FATF Travel Rule: %w", err)
	}
	if bc.AMLScreener != nil {
		alert, err := bc.AMLScreener.ScreenTransaction(sellerKey, buyerKey, asset.ID, quantity, asset.Currency)
		if err != nil {
			return fmt.Errorf("AML screening failed: %w", err)
		}
		if alert != nil && alert.Severity == AMLSeverityBlock {
			return fmt.Errorf("transfer blocked by AML screening: %s", alert.Reason)
		}
		if alert != nil && alert.Severity == AMLSeverityFlag {
			if bc.PendingSARs != nil {
				sarID := fmt.Sprintf("sar-rfq-%s-%d", asset.ID, time.Now().UnixNano())
				bc.PendingSARs[sarID] = &SARDraft{
					ID:          sarID,
					SenderKey:   sellerKey,
					ReceiverKey: buyerKey,
					AssetID:     asset.ID,
					Amount:      quantity,
					Reason:      alert.Reason,
					CreatedAt:   time.Now().Unix(),
					Status:      SARStatusPending,
				}
			}
		}
	}
	return nil
}

func encodeStdBase64(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}
