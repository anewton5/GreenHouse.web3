package gonetwork

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pubKeyB64 returns the base64-encoded public key string for a PrivateKey.
func pubKeyB64(k *PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Public().Bytes())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// dealTestKey generates a fresh Ed25519 key and fails the test on error.
func dealTestKey(t *testing.T) *PrivateKey {
	t.Helper()
	k, err := GeneratePrivateKey()
	require.NoError(t, err)
	return k
}

// dealTestRegistry creates a MockIdentityRegistry backed by a fresh key.
func dealTestRegistry(t *testing.T) *MockIdentityRegistry {
	t.Helper()
	reg, err := NewMockIdentityRegistry()
	require.NoError(t, err)
	return reg
}

// issueCredential is a shorthand for issuing an on-chain CredentialAttestation.
func issueCredential(
	t *testing.T,
	reg *MockIdentityRegistry,
	walletKey string,
	class InvestorClass,
	validDays int,
) *CredentialAttestation {
	t.Helper()
	cred, err := reg.IssueCredential(walletKey, class, "DE", validDays)
	require.NoError(t, err)
	return cred
}

func makeDeal(t *testing.T, issuer *PrivateKey, target, minFraction float64, deadlineDays int) *Deal {
	t.Helper()
	d, err := NewDeal(issuer, "ASSET-1", "", target, minFraction, deadlineDays)
	require.NoError(t, err)
	return d
}

// ---------------------------------------------------------------------------
// TestNewDeal_Valid
// ---------------------------------------------------------------------------

func TestNewDeal_Valid(t *testing.T) {
	issuer := dealTestKey(t)
	d, err := NewDeal(issuer, "ASSET-1", "", 1_000_000, 0.20, 30)
	require.NoError(t, err)
	require.NotNil(t, d)

	assert.NotEmpty(t, d.ID)
	assert.Equal(t, DealStatusDraft, d.Status)
	assert.Equal(t, 1_000_000.0, d.TargetRaiseAmount)
	assert.Equal(t, 0.20, d.MinAnchorFraction)
	assert.NotEmpty(t, d.IssuerSignature)

	// Verify signature round-trip
	pub := issuer.Public()
	assert.True(t, d.verifyIssuerSignature(pub))
}

// ---------------------------------------------------------------------------
// TestNewDeal_InvalidFraction
// ---------------------------------------------------------------------------

func TestNewDeal_InvalidFraction(t *testing.T) {
	issuer := dealTestKey(t)

	_, err := NewDeal(issuer, "A", "", 100_000, 0.0, 30)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "minAnchorFraction")

	_, err = NewDeal(issuer, "A", "", 100_000, 1.1, 30)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "minAnchorFraction")

	// Exactly 1.0 should be valid
	_, err = NewDeal(issuer, "A", "", 100_000, 1.0, 30)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// TestAttachAnchor_Valid
// ---------------------------------------------------------------------------

func TestAttachAnchor_Valid(t *testing.T) {
	issuer := dealTestKey(t)
	anchorKey := dealTestKey(t)
	reg := dealTestRegistry(t)

	d := makeDeal(t, issuer, 500_000, 0.20, 30) // min anchor = 100_000

	anchorWalletKey := pubKeyB64(anchorKey)
	cred := issueCredential(t, reg, anchorWalletKey, InvestorClassProfessional, 365)

	anchor, err := NewDealAnchor(anchorKey, d.ID, 100_000, "EUR", cred)
	require.NoError(t, err)

	err = d.AttachAnchor(anchor, anchorKey.Public(), nil)
	require.NoError(t, err)
	assert.Equal(t, DealStatusAnchored, d.Status)
	assert.NotNil(t, d.Anchor)
}

// ---------------------------------------------------------------------------
// TestAttachAnchor_BelowMinimum
// ---------------------------------------------------------------------------

func TestAttachAnchor_BelowMinimum(t *testing.T) {
	issuer := dealTestKey(t)
	anchorKey := dealTestKey(t)
	reg := dealTestRegistry(t)

	d := makeDeal(t, issuer, 500_000, 0.20, 30) // min = 100_000

	anchorWalletKey := pubKeyB64(anchorKey)
	cred := issueCredential(t, reg, anchorWalletKey, InvestorClassProfessional, 365)

	anchor, err := NewDealAnchor(anchorKey, d.ID, 50_000, "EUR", cred) // below min
	require.NoError(t, err)

	err = d.AttachAnchor(anchor, anchorKey.Public(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

// ---------------------------------------------------------------------------
// TestAttachAnchor_RetailInvestor
// ---------------------------------------------------------------------------

func TestAttachAnchor_RetailInvestor(t *testing.T) {
	issuer := dealTestKey(t)
	anchorKey := dealTestKey(t)
	reg := dealTestRegistry(t)

	d := makeDeal(t, issuer, 100_000, 0.20, 30)

	anchorWalletKey := pubKeyB64(anchorKey)
	// Retail class — not accredited
	cred := issueCredential(t, reg, anchorWalletKey, InvestorClassRetail, 365)

	anchor, err := NewDealAnchor(anchorKey, d.ID, 20_001, "EUR", cred)
	require.NoError(t, err)

	err = d.AttachAnchor(anchor, anchorKey.Public(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accredited")
}

// ---------------------------------------------------------------------------
// TestAttachAnchor_ExpiredCredential
// ---------------------------------------------------------------------------

func TestAttachAnchor_ExpiredCredential(t *testing.T) {
	issuer := dealTestKey(t)
	anchorKey := dealTestKey(t)

	d := makeDeal(t, issuer, 100_000, 0.20, 30)

	anchorWalletKey := pubKeyB64(anchorKey)

	// Build an expired credential manually
	expiredCred := &CredentialAttestation{
		WalletPublicKey: anchorWalletKey,
		InvestorClass:   InvestorClassProfessional,
		KYCStatus:       KYCStatusVerified,
		Jurisdiction:    "DE",
		ExpiresAt:       time.Now().Add(-24 * time.Hour).Unix(), // expired yesterday
	}

	anchor, err := NewDealAnchor(anchorKey, d.ID, 20_001, "EUR", expiredCred)
	require.NoError(t, err)

	err = d.AttachAnchor(anchor, anchorKey.Public(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

// ---------------------------------------------------------------------------
// TestAddCoInvestor_Valid
// ---------------------------------------------------------------------------

func TestAddCoInvestor_Valid(t *testing.T) {
	issuer := dealTestKey(t)
	anchorKey := dealTestKey(t)
	investorKey := dealTestKey(t)
	reg := dealTestRegistry(t)

	d := makeDeal(t, issuer, 500_000, 0.20, 30)
	anchorWalletKey := pubKeyB64(anchorKey)
	cred := issueCredential(t, reg, anchorWalletKey, InvestorClassProfessional, 365)
	anchor, err := NewDealAnchor(anchorKey, d.ID, 100_000, "EUR", cred)
	require.NoError(t, err)
	require.NoError(t, d.AttachAnchor(anchor, anchorKey.Public(), nil))

	// Now add a co-investor
	commitment, err := NewDealCommitment(investorKey, d.ID, 50_000, "EUR")
	require.NoError(t, err)

	err = d.AddCoInvestor(commitment, investorKey.Public(), nil)
	require.NoError(t, err)
	assert.Len(t, d.CoInvestors, 1)
}

// ---------------------------------------------------------------------------
// TestAddCoInvestor_DealNotAnchored
// ---------------------------------------------------------------------------

func TestAddCoInvestor_DealNotAnchored(t *testing.T) {
	issuer := dealTestKey(t)
	investorKey := dealTestKey(t)

	d := makeDeal(t, issuer, 500_000, 0.20, 30) // still Draft

	commitment, err := NewDealCommitment(investorKey, d.ID, 50_000, "EUR")
	require.NoError(t, err)

	err = d.AddCoInvestor(commitment, investorKey.Public(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "draft")
}

// ---------------------------------------------------------------------------
// TestTotalCommitted_SumCorrect
// ---------------------------------------------------------------------------

func TestTotalCommitted_SumCorrect(t *testing.T) {
	issuer := dealTestKey(t)
	anchorKey := dealTestKey(t)
	reg := dealTestRegistry(t)

	d := makeDeal(t, issuer, 1_000_000, 0.20, 30)
	anchorWalletKey := pubKeyB64(anchorKey)
	cred := issueCredential(t, reg, anchorWalletKey, InvestorClassAccredited, 365)
	anchor, err := NewDealAnchor(anchorKey, d.ID, 200_000, "EUR", cred)
	require.NoError(t, err)
	require.NoError(t, d.AttachAnchor(anchor, anchorKey.Public(), nil))

	for i := 0; i < 3; i++ {
		inv := dealTestKey(t)
		c, err := NewDealCommitment(inv, d.ID, 100_000, "EUR")
		require.NoError(t, err)
		require.NoError(t, d.AddCoInvestor(c, inv.Public(), nil))
	}

	// 200_000 anchor + 3×100_000 co-investors = 500_000
	assert.InDelta(t, 500_000.0, d.TotalCommitted(), 1e-6)
}

// ---------------------------------------------------------------------------
// TestIsOversubscribed_True
// ---------------------------------------------------------------------------

func TestIsOversubscribed_True(t *testing.T) {
	issuer := dealTestKey(t)
	anchorKey := dealTestKey(t)
	reg := dealTestRegistry(t)

	d := makeDeal(t, issuer, 300_000, 0.20, 30)
	anchorWalletKey := pubKeyB64(anchorKey)
	cred := issueCredential(t, reg, anchorWalletKey, InvestorClassAccredited, 365)
	anchor, err := NewDealAnchor(anchorKey, d.ID, 60_000, "EUR", cred)
	require.NoError(t, err)
	require.NoError(t, d.AttachAnchor(anchor, anchorKey.Public(), nil))

	assert.False(t, d.IsOversubscribed())

	// Add enough to hit target
	for i := 0; i < 3; i++ {
		inv := dealTestKey(t)
		c, err := NewDealCommitment(inv, d.ID, 80_000, "EUR")
		require.NoError(t, err)
		require.NoError(t, d.AddCoInvestor(c, inv.Public(), nil))
	}
	// 60_000 + 240_000 = 300_000 ≥ target
	assert.True(t, d.IsOversubscribed())
}

// ---------------------------------------------------------------------------
// TestCheckAnchorDeadline_Fails
// ---------------------------------------------------------------------------

func TestCheckAnchorDeadline_Fails(t *testing.T) {
	issuer := dealTestKey(t)
	d, err := NewDeal(issuer, "ASSET-1", "", 100_000, 0.20, 1) // 1 day deadline
	require.NoError(t, err)

	// Set deadline to the past
	d.AnchorDeadlineAt = time.Now().Add(-1 * time.Second).Unix()

	failed := d.CheckAnchorDeadline()
	assert.True(t, failed)
	assert.Equal(t, DealStatusFailed, d.Status)
}

// ---------------------------------------------------------------------------
// TestCheckAnchorDeadline_NotYet
// ---------------------------------------------------------------------------

func TestCheckAnchorDeadline_NotYet(t *testing.T) {
	issuer := dealTestKey(t)
	d := makeDeal(t, issuer, 100_000, 0.20, 30) // 30 days — deadline is in the future

	failed := d.CheckAnchorDeadline()
	assert.False(t, failed)
	assert.Equal(t, DealStatusDraft, d.Status)
}
