package gonetwork

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// DealStatus
// ---------------------------------------------------------------------------

// DealStatus represents the lifecycle state of a private placement deal.
type DealStatus string

const (
	DealStatusDraft     DealStatus = "draft"     // created, no anchor yet
	DealStatusAnchoring DealStatus = "anchoring" // anchor invited, awaiting commitment
	DealStatusAnchored  DealStatus = "anchored"  // anchor committed; open to co-investors
	DealStatusLive      DealStatus = "live"      // liquidity window open
	DealStatusClosed    DealStatus = "closed"    // fully subscribed or window closed
	DealStatusFailed    DealStatus = "failed"    // anchor did not commit by deadline
)

// ---------------------------------------------------------------------------
// Deal types
// ---------------------------------------------------------------------------

// Deal is the top-level record for a private placement.
// It ties together an Asset, an optional SPVWrapper, a LiquidityWindow, and
// the anchor commitment. Only moves forward through its lifecycle; it cannot
// revert to an earlier status.
type Deal struct {
	ID                string            `json:"id"`
	AssetID           string            `json:"asset_id"`
	SPVID             string            `json:"spv_id,omitempty"` // empty if asset issued directly (non-SPV)
	IssuerKey         string            `json:"issuer_key"`       // base64-encoded public key of the issuer
	Status            DealStatus        `json:"status"`
	TargetRaiseAmount float64           `json:"target_amount"`
	MinAnchorFraction float64           `json:"min_anchor_fraction"`
	AnchorDeadlineAt  int64             `json:"closes_at"` // Unix timestamp after which the deal can be failed
	Anchor            *DealAnchor       `json:"anchor,omitempty"`
	CoInvestors       []*DealCommitment `json:"co_investors,omitempty"`
	LiquidityWindowID string            `json:"liquidity_window_id,omitempty"`
	CreatedAt         int64             `json:"created_at"`
	IssuerSignature   []byte            `json:"-"`
}

// DealAnchor is the commitment record of the lead investor.
type DealAnchor struct {
	DealID                string                 `json:"deal_id"`
	AnchorWalletKey       string                 `json:"anchor_wallet_key"`
	CommitmentAmount      float64                `json:"commitment_amount"`
	Currency              string                 `json:"currency"`
	CommittedAt           int64                  `json:"committed_at"`
	CredentialAttestation *CredentialAttestation `json:"credential_attestation,omitempty"`
	AnchorSignature       []byte                 `json:"-"`
}

// DealCommitment is an individual co-investor's subscription intent.
// It becomes binding once the deal moves to DealStatusLive.
type DealCommitment struct {
	DealID           string  `json:"deal_id"`
	InvestorKey      string  `json:"investor_key"`
	CommitmentAmount float64 `json:"commitment_amount"`
	Currency         string  `json:"currency"`
	CommittedAt      int64   `json:"committed_at"`
	Signature        []byte  `json:"-"`
}

// ---------------------------------------------------------------------------
// Deal constructors
// ---------------------------------------------------------------------------

// NewDeal creates a new private placement deal in DealStatusDraft and signs it
// with the issuer's key. anchorDeadlineDays specifies how many days from now the
// anchor must commit before the deal can be failed.
func NewDeal(
	issuerKey *PrivateKey,
	assetID string,
	spvID string,
	targetRaiseAmount float64,
	minAnchorFraction float64,
	anchorDeadlineDays int,
) (*Deal, error) {
	if issuerKey == nil {
		return nil, fmt.Errorf("issuer key must not be nil")
	}
	if targetRaiseAmount <= 0 {
		return nil, fmt.Errorf("targetRaiseAmount must be greater than zero")
	}
	if minAnchorFraction <= 0 || minAnchorFraction > 1 {
		return nil, fmt.Errorf("minAnchorFraction must be in (0, 1]")
	}
	if anchorDeadlineDays <= 0 {
		return nil, fmt.Errorf("anchorDeadlineDays must be greater than zero")
	}

	issuerKeyStr := base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes())
	now := time.Now().UTC().Unix()

	d := &Deal{
		IssuerKey:         issuerKeyStr,
		AssetID:           assetID,
		SPVID:             spvID,
		Status:            DealStatusDraft,
		TargetRaiseAmount: targetRaiseAmount,
		MinAnchorFraction: minAnchorFraction,
		AnchorDeadlineAt:  now + int64(anchorDeadlineDays*86400),
		CreatedAt:         now,
		IssuerSignature:   nil,
	}

	// Derive a deterministic ID from the deal content before signing
	idData, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal deal for ID: %w", err)
	}
	idHash := sha3.Sum256(idData)
	d.ID = fmt.Sprintf("%x", idHash[:8]) // first 8 bytes as hex = 16-char ID

	// Sign (ID is now set; IssuerSignature stays nil during sign)
	data, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal deal for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	d.IssuerSignature = issuerKey.Sign(hash[:]).Bytes()

	return d, nil
}

// verifyIssuerSignature checks the issuer's Ed25519 signature on the deal.
func (d *Deal) verifyIssuerSignature(issuerPubKey *PublicKey) bool {
	copy := *d
	copy.IssuerSignature = nil
	data, err := json.Marshal(copy)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: d.IssuerSignature}
	return sig.Verify(issuerPubKey, hash[:])
}

// ---------------------------------------------------------------------------
// NewDealAnchor creates and signs an anchor commitment.
// The caller must supply their private key so the commitment can be verified
// on-chain without the private key being stored.
func NewDealAnchor(
	anchorKey *PrivateKey,
	dealID string,
	commitmentAmount float64,
	currency string,
	credential *CredentialAttestation,
) (*DealAnchor, error) {
	if anchorKey == nil {
		return nil, fmt.Errorf("anchor key must not be nil")
	}
	if commitmentAmount <= 0 {
		return nil, fmt.Errorf("commitment amount must be greater than zero")
	}

	walletKey := base64.StdEncoding.EncodeToString(anchorKey.Public().Bytes())

	// Sign over DealID + AnchorWalletKey + CommitmentAmount (as specified)
	sigPayload := fmt.Sprintf("%s%s%.18f", dealID, walletKey, commitmentAmount)
	hash := sha3.Sum256([]byte(sigPayload))
	sig := anchorKey.Sign(hash[:]).Bytes()

	return &DealAnchor{
		DealID:                dealID,
		AnchorWalletKey:       walletKey,
		CommitmentAmount:      commitmentAmount,
		Currency:              currency,
		CommittedAt:           time.Now().UTC().Unix(),
		CredentialAttestation: credential,
		AnchorSignature:       sig,
	}, nil
}

// verifyAnchorSignature checks the anchor's Ed25519 signature.
func (a *DealAnchor) verifyAnchorSignature(pubKey *PublicKey) bool {
	sigPayload := fmt.Sprintf("%s%s%.18f", a.DealID, a.AnchorWalletKey, a.CommitmentAmount)
	hash := sha3.Sum256([]byte(sigPayload))
	sig := &Signature{value: a.AnchorSignature}
	return sig.Verify(pubKey, hash[:])
}

// ---------------------------------------------------------------------------
// NewDealCommitment creates and signs a co-investor commitment.
func NewDealCommitment(
	investorKey *PrivateKey,
	dealID string,
	commitmentAmount float64,
	currency string,
) (*DealCommitment, error) {
	if investorKey == nil {
		return nil, fmt.Errorf("investor key must not be nil")
	}
	if commitmentAmount <= 0 {
		return nil, fmt.Errorf("commitment amount must be greater than zero")
	}

	c := &DealCommitment{
		DealID:           dealID,
		InvestorKey:      base64.StdEncoding.EncodeToString(investorKey.Public().Bytes()),
		CommitmentAmount: commitmentAmount,
		Currency:         currency,
		CommittedAt:      time.Now().UTC().Unix(),
		Signature:        nil,
	}

	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal commitment for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	c.Signature = investorKey.Sign(hash[:]).Bytes()
	return c, nil
}

// verifyCommitmentSignature checks the investor's Ed25519 signature on the commitment.
func (c *DealCommitment) verifyCommitmentSignature(pubKey *PublicKey) bool {
	copy := *c
	copy.Signature = nil
	data, err := json.Marshal(copy)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: c.Signature}
	return sig.Verify(pubKey, hash[:])
}

// ---------------------------------------------------------------------------
// Deal lifecycle methods
// ---------------------------------------------------------------------------

// AttachAnchor validates and attaches a lead investor commitment to the deal.
// It transitions the deal from DealStatusAnchoring → DealStatusAnchored.
// Preconditions:
//   - deal status must be DealStatusDraft or DealStatusAnchoring
//   - anchor signature must be valid
//   - anchor credential must be accredited (not retail) and valid (not expired)
//   - commitment amount must be >= TargetRaiseAmount × MinAnchorFraction
func (d *Deal) AttachAnchor(
	anchor *DealAnchor,
	anchorPubKey *PublicKey,
	_ map[string]*CredentialAttestation, // reserved for future registry lookup
) error {
	if d.Status != DealStatusDraft && d.Status != DealStatusAnchoring {
		return fmt.Errorf("cannot attach anchor: deal is %s", d.Status)
	}
	if anchor == nil {
		return fmt.Errorf("anchor must not be nil")
	}
	if !anchor.verifyAnchorSignature(anchorPubKey) {
		return fmt.Errorf("anchor signature is invalid")
	}
	cred := anchor.CredentialAttestation
	if cred == nil {
		return fmt.Errorf("anchor credential is missing")
	}
	if !cred.IsValid() {
		return fmt.Errorf("anchor credential has expired or is not verified")
	}
	if !cred.IsAccredited() {
		return fmt.Errorf("anchor investor class %q does not meet accredited requirement", cred.InvestorClass)
	}

	minCommitment := d.TargetRaiseAmount * d.MinAnchorFraction
	if anchor.CommitmentAmount < minCommitment {
		return fmt.Errorf(
			"anchor commitment %.2f is below minimum required %.2f (%.0f%% of %.2f)",
			anchor.CommitmentAmount, minCommitment,
			d.MinAnchorFraction*100, d.TargetRaiseAmount,
		)
	}

	d.Anchor = anchor
	d.Status = DealStatusAnchored
	return nil
}

// AddCoInvestor validates and appends a co-investor commitment.
// Allowed when deal status is DealStatusAnchored or DealStatusLive.
func (d *Deal) AddCoInvestor(
	commitment *DealCommitment,
	investorPubKey *PublicKey,
	_ map[string]*CredentialAttestation, // reserved
) error {
	if d.Status != DealStatusAnchored && d.Status != DealStatusLive {
		return fmt.Errorf("co-investors may not commit when deal is %s", d.Status)
	}
	if commitment == nil {
		return fmt.Errorf("commitment must not be nil")
	}
	if !commitment.verifyCommitmentSignature(investorPubKey) {
		return fmt.Errorf("co-investor commitment signature is invalid")
	}
	if commitment.DealID != d.ID {
		return fmt.Errorf("commitment deal ID %q does not match deal %q", commitment.DealID, d.ID)
	}

	d.CoInvestors = append(d.CoInvestors, commitment)
	return nil
}

// TotalCommitted returns the sum of all committed capital (anchor + co-investors).
func (d *Deal) TotalCommitted() float64 {
	total := 0.0
	if d.Anchor != nil {
		total += d.Anchor.CommitmentAmount
	}
	for _, c := range d.CoInvestors {
		total += c.CommitmentAmount
	}
	return total
}

// IsOversubscribed returns true when total committed capital meets or exceeds
// the TargetRaiseAmount.
func (d *Deal) IsOversubscribed() bool {
	return d.TotalCommitted() >= d.TargetRaiseAmount
}

// CheckAnchorDeadline evaluates whether the anchor deadline has passed without
// an anchor commitment. If so, it sets the deal status to DealStatusFailed and
// returns true. Returns false if the deadline has not passed or an anchor already
// exists.
func (d *Deal) CheckAnchorDeadline() bool {
	if d.Anchor != nil {
		return false
	}
	if time.Now().UTC().Unix() > d.AnchorDeadlineAt {
		d.Status = DealStatusFailed
		return true
	}
	return false
}
