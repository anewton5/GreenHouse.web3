package gonetwork

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeRegistry creates a fresh MockIdentityRegistry for use within a single test.
func makeRegistry(t *testing.T) *MockIdentityRegistry {
	t.Helper()
	reg, err := NewMockIdentityRegistry()
	require.NoError(t, err)
	return reg
}

// makeCredential issues a verified professional credential for walletKey.
func makeCredential(t *testing.T, reg *MockIdentityRegistry, walletKey string) *CredentialAttestation {
	t.Helper()
	att, err := reg.IssueCredential(walletKey, InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)
	return att
}

// ---------------------------------------------------------------------------
// IdentityCredential tests
// ---------------------------------------------------------------------------

func TestNewCredential_Valid(t *testing.T) {
	reg := makeRegistry(t)
	walletKey := "testwalletkey"

	cred, err := NewIdentityCredential(walletKey, InvestorClassProfessional, "GB", 365, reg.registryKey)
	require.NoError(t, err)

	assert.Equal(t, walletKey, cred.WalletPublicKey)
	assert.Equal(t, InvestorClassProfessional, cred.InvestorClass)
	assert.Equal(t, KYCStatusVerified, cred.KYCStatus)
	assert.Equal(t, "GB", cred.Jurisdiction)
	assert.Greater(t, cred.ExpiresAt, cred.IssuedAt)
	assert.NotEmpty(t, cred.RegistrySignature)
	assert.NotEmpty(t, cred.RegistryID)

	// Verify the registry signature is valid.
	assert.True(t, cred.VerifySignature(reg.registryPub))
}

func TestNewCredential_InvalidJurisdiction(t *testing.T) {
	reg := makeRegistry(t)
	_, err := NewIdentityCredential("walletkey", InvestorClassRetail, "", 365, reg.registryKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jurisdiction")
}

func TestNewCredential_EmptyWalletKey(t *testing.T) {
	reg := makeRegistry(t)
	_, err := NewIdentityCredential("", InvestorClassRetail, "DE", 365, reg.registryKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet key")
}

func TestNewCredential_NilRegistryKey(t *testing.T) {
	_, err := NewIdentityCredential("walletkey", InvestorClassRetail, "DE", 365, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry key")
}

func TestNewCredential_InvalidDays(t *testing.T) {
	reg := makeRegistry(t)
	_, err := NewIdentityCredential("walletkey", InvestorClassRetail, "DE", 0, reg.registryKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validForDays")
}

func TestCredentialExpiry(t *testing.T) {
	reg := makeRegistry(t)
	cred, err := NewIdentityCredential("walletkey", InvestorClassProfessional, "GB", 365, reg.registryKey)
	require.NoError(t, err)

	// Not expired immediately after issuance.
	assert.False(t, cred.IsExpired())

	// Simulate past expiry by mutating ExpiresAt.
	cred.ExpiresAt = time.Now().Unix() - 1
	assert.True(t, cred.IsExpired())
}

func TestCredentialToAttestation(t *testing.T) {
	reg := makeRegistry(t)
	cred, err := NewIdentityCredential("walletkey", InvestorClassProfessional, "GB", 365, reg.registryKey)
	require.NoError(t, err)

	att := cred.ToAttestation()

	assert.Equal(t, cred.WalletPublicKey, att.WalletPublicKey)
	assert.Equal(t, cred.InvestorClass, att.InvestorClass)
	assert.Equal(t, cred.KYCStatus, att.KYCStatus)
	assert.Equal(t, cred.Jurisdiction, att.Jurisdiction)
	assert.Equal(t, cred.ExpiresAt, att.ExpiresAt)
	assert.Equal(t, cred.RegistrySignature, att.RegistrySignature)
	assert.NotEmpty(t, att.CredentialHash)

	// Hash must be deterministic.
	att2 := cred.ToAttestation()
	assert.Equal(t, att.CredentialHash, att2.CredentialHash)
}

func TestCredentialSignatureTampering(t *testing.T) {
	reg := makeRegistry(t)
	cred, err := NewIdentityCredential("walletkey", InvestorClassProfessional, "GB", 365, reg.registryKey)
	require.NoError(t, err)

	// Signature passes before tampering.
	assert.True(t, cred.VerifySignature(reg.registryPub))

	// Elevate investor class without re-signing.
	cred.InvestorClass = InvestorClassAccredited
	assert.False(t, cred.VerifySignature(reg.registryPub))
}

func TestCredentialVerifySignature_WrongKey(t *testing.T) {
	reg := makeRegistry(t)
	otherReg := makeRegistry(t)

	cred, err := NewIdentityCredential("walletkey", InvestorClassProfessional, "GB", 365, reg.registryKey)
	require.NoError(t, err)

	// Signed by reg, verified against otherReg — must fail.
	assert.False(t, cred.VerifySignature(otherReg.registryPub))
}

// ---------------------------------------------------------------------------
// CredentialAttestation tests
// ---------------------------------------------------------------------------

func TestAttestationIsValid(t *testing.T) {
	reg := makeRegistry(t)
	walletKey := "walletkey"
	att := makeCredential(t, reg, walletKey)

	assert.True(t, att.IsValid())

	// Expired credential is invalid.
	expired := *att
	expired.ExpiresAt = time.Now().Unix() - 1
	assert.False(t, expired.IsValid())

	// Rejected credential is invalid regardless of expiry.
	rejected := *att
	rejected.KYCStatus = KYCStatusRejected
	assert.False(t, rejected.IsValid())
}

func TestAttestationIsAccredited(t *testing.T) {
	reg := makeRegistry(t)
	walletKey := "walletkey"

	professional, err := reg.IssueCredential(walletKey, InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)
	assert.True(t, professional.IsAccredited())

	eligibleCP, err := reg.IssueCredential(walletKey, InvestorClassEligibleCP, "GB", 365)
	require.NoError(t, err)
	assert.True(t, eligibleCP.IsAccredited())

	accredited, err := reg.IssueCredential(walletKey, InvestorClassAccredited, "GB", 365)
	require.NoError(t, err)
	assert.True(t, accredited.IsAccredited())

	retail, err := reg.IssueCredential(walletKey, InvestorClassRetail, "GB", 365)
	require.NoError(t, err)
	assert.False(t, retail.IsAccredited())
}

// ---------------------------------------------------------------------------
// MockIdentityRegistry tests
// ---------------------------------------------------------------------------

func TestMockRegistry_IssueAndVerify(t *testing.T) {
	reg := makeRegistry(t)
	walletKey := "walletkey"

	att, err := reg.IssueCredential(walletKey, InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)
	assert.NotNil(t, att)

	retrieved, err := reg.VerifyCredential(walletKey)
	require.NoError(t, err)
	assert.Equal(t, att.CredentialHash, retrieved.CredentialHash)
}

func TestMockRegistry_VerifyUnknownWallet(t *testing.T) {
	reg := makeRegistry(t)
	_, err := reg.VerifyCredential("nobody")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credential found")
}

func TestMockRegistry_RegistryPublicKey(t *testing.T) {
	reg := makeRegistry(t)
	pub := reg.RegistryPublicKey()
	require.NotNil(t, pub)

	// Confirm it matches the key used to sign credentials.
	cred, err := NewIdentityCredential("walletkey", InvestorClassProfessional, "GB", 365, reg.registryKey)
	require.NoError(t, err)
	assert.True(t, cred.VerifySignature(pub))
}

// ---------------------------------------------------------------------------
// CheckTransferEligibility tests
// ---------------------------------------------------------------------------

func TestCheckTransferEligibility_NoRestrictions(t *testing.T) {
	asset, _ := makeTestAsset(t) // no AccreditedOnly, no BlockedJurisdictions
	_, receiverStr := makeTestWallet(t)

	// No credentials map — fast path, must pass.
	err := CheckTransferEligibility(receiverStr, asset, nil)
	assert.NoError(t, err)

	// Empty credentials map — fast path (no credential restrictions set), must pass.
	err = CheckTransferEligibility(receiverStr, asset, map[string]*CredentialAttestation{})
	assert.NoError(t, err)
}

func TestCheckTransferEligibility_Accredited(t *testing.T) {
	asset, _ := makeTestAsset(t)
	asset.Restrictions.AccreditedOnly = true

	_, receiverStr := makeTestWallet(t)
	reg := makeRegistry(t)

	att, err := reg.IssueCredential(receiverStr, InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)

	creds := map[string]*CredentialAttestation{receiverStr: att}
	err = CheckTransferEligibility(receiverStr, asset, creds)
	assert.NoError(t, err)
}

func TestCheckTransferEligibility_RetailBlocked(t *testing.T) {
	asset, _ := makeTestAsset(t)
	asset.Restrictions.AccreditedOnly = true

	_, receiverStr := makeTestWallet(t)
	reg := makeRegistry(t)

	att, err := reg.IssueCredential(receiverStr, InvestorClassRetail, "GB", 365)
	require.NoError(t, err)

	creds := map[string]*CredentialAttestation{receiverStr: att}
	err = CheckTransferEligibility(receiverStr, asset, creds)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accredited")
}

func TestCheckTransferEligibility_JurisdictionBlocked(t *testing.T) {
	asset, _ := makeTestAsset(t)
	asset.Restrictions.BlockedJurisdictions = []string{"RU", "KP"}

	_, receiverStr := makeTestWallet(t)
	reg := makeRegistry(t)

	att, err := reg.IssueCredential(receiverStr, InvestorClassProfessional, "RU", 365)
	require.NoError(t, err)

	creds := map[string]*CredentialAttestation{receiverStr: att}
	err = CheckTransferEligibility(receiverStr, asset, creds)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func TestCheckTransferEligibility_NoCredentialForAccreditedAsset(t *testing.T) {
	asset, _ := makeTestAsset(t)
	asset.Restrictions.AccreditedOnly = true

	_, receiverStr := makeTestWallet(t)

	// Non-nil but empty credentials map — no credential exists for receiver.
	err := CheckTransferEligibility(receiverStr, asset, map[string]*CredentialAttestation{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid credential")
}

// ---------------------------------------------------------------------------
// Integration: AssetTransaction.Validate with a real credentials map
// ---------------------------------------------------------------------------

func TestAssetValidationWithCredentials(t *testing.T) {
	issuerKey, issuerStr := makeTestWallet(t)
	_, receiverStr := makeTestWallet(t)

	reg := makeRegistry(t)

	// Issue credentials for both parties.
	_, err := reg.IssueCredential(issuerStr, InvestorClassAccredited, "GB", 365)
	require.NoError(t, err)
	att, err := reg.IssueCredential(receiverStr, InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)

	// Create an accredited-only asset.
	asset, err := NewAsset(
		issuerKey,
		AssetTypeEquity,
		1000,
		"GBP",
		AssetMetadata{CompanyName: "CredTest Ltd", Jurisdiction: "GB"},
		TransferRestrictions{AccreditedOnly: true},
	)
	require.NoError(t, err)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}
	creds := map[string]*CredentialAttestation{receiverStr: att}

	// Issue tokens to the receiver (as issuer).
	receiverPub, err := PublicKeyFromString(receiverStr)
	require.NoError(t, err)
	at, err := NewAssetTransaction(issuerKey, receiverPub, asset.ID, 100, AssetTxTypeIssue)
	require.NoError(t, err)

	// Validate must pass with valid credentials.
	err = at.Validate(assets, holdings, creds, nil)
	require.NoError(t, err)

	// Apply the issuance.
	err = ApplyAssetTransaction(at, assets, holdings)
	require.NoError(t, err)

	// Now try a transfer from receiver to an unaccredited wallet.
	_, thirdStr := makeTestWallet(t)
	thirdPub, err := PublicKeyFromString(thirdStr)
	require.NoError(t, err)

	// Issue credential for receiver so they can sign the transfer.
	receiverPrivKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	actualReceiverStr := base64.StdEncoding.EncodeToString(receiverPrivKey.Public().Bytes())
	_, err = reg.IssueCredential(actualReceiverStr, InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)

	// Force the holding to be owned by receiverPrivKey's address for transfer test.
	holdings[HoldingKey(actualReceiverStr, asset.ID)] = &AssetHolding{
		AssetID:  asset.ID,
		HolderID: actualReceiverStr,
		Balance:  100,
	}

	transferAt, err := NewAssetTransaction(receiverPrivKey, thirdPub, asset.ID, 50, AssetTxTypeTransfer)
	require.NoError(t, err)

	// Third wallet has no credential — transfer must fail.
	retailCred, err := reg.IssueCredential(thirdStr, InvestorClassRetail, "GB", 365)
	require.NoError(t, err)
	creds[thirdStr] = retailCred

	err = transferAt.Validate(assets, holdings, creds, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accredited")
}
