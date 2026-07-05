package gonetwork

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

func TestNewClaim_ValidAndVerifiable(t *testing.T) {
	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	subjectKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	subject := base64.StdEncoding.EncodeToString(subjectKey.Public().Bytes())

	claim, err := NewClaim(ClaimTopicKYC, "", subject, "professional", 30, issuerKey)
	require.NoError(t, err)
	assert.Equal(t, ClaimTopicKYC, claim.Topic)
	assert.Equal(t, subject, claim.Subject)
	assert.Equal(t, "professional", claim.Data)
	assert.True(t, claim.IsValid())
	assert.False(t, claim.IsExpired())
	assert.True(t, claim.VerifySignature(issuerKey.Public()))
}

func TestNewClaim_RejectsInvalidInput(t *testing.T) {
	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	_, err = NewClaim(ClaimTopicKYC, "", "", "data", 30, issuerKey)
	assert.Error(t, err, "empty subject should be rejected")

	_, err = NewClaim(ClaimTopicKYC, "", "subject", "data", 30, nil)
	assert.Error(t, err, "nil issuer key should be rejected")

	_, err = NewClaim(ClaimTopicKYC, "", "subject", "data", 0, issuerKey)
	assert.Error(t, err, "non-positive validForDays should be rejected")

	_, err = NewClaim(ClaimTopicCustom, "", "subject", "data", 30, issuerKey)
	assert.Error(t, err, "ClaimTopicCustom without CustomTopic should be rejected")
}

func TestClaim_VerifySignature_DetectsTampering(t *testing.T) {
	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	claim, err := NewClaim(ClaimTopicAccredited, "", "subject-key", "accredited", 30, issuerKey)
	require.NoError(t, err)
	require.True(t, claim.VerifySignature(issuerKey.Public()))

	claim.Data = "tampered"
	assert.False(t, claim.VerifySignature(issuerKey.Public()), "signature must fail after mutation")
}

func TestClaim_IsExpired(t *testing.T) {
	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	claim, err := NewClaim(ClaimTopicKYC, "", "subject-key", "", 30, issuerKey)
	require.NoError(t, err)
	assert.False(t, claim.IsExpired())

	claim.ExpiresAt = time.Now().Unix() - 1
	assert.True(t, claim.IsExpired())
	assert.False(t, claim.IsValid(), "an expired claim must not be valid even with a signature present")
}

// ---------------------------------------------------------------------------
// TrustedIssuersRegistry
// ---------------------------------------------------------------------------

func TestTrustedIssuersRegistry_AddRemoveIsTrusted(t *testing.T) {
	reg := NewTrustedIssuersRegistry()
	assert.False(t, reg.IsTrusted(ClaimTopicKYC, "issuer-a"))

	reg.AddIssuer(ClaimTopicKYC, "issuer-a")
	assert.True(t, reg.IsTrusted(ClaimTopicKYC, "issuer-a"))
	assert.False(t, reg.IsTrusted(ClaimTopicAMLClear, "issuer-a"), "trust is scoped per topic")

	reg.RemoveIssuer(ClaimTopicKYC, "issuer-a")
	assert.False(t, reg.IsTrusted(ClaimTopicKYC, "issuer-a"))
}

func TestTrustedIssuersRegistry_NilSafe(t *testing.T) {
	var reg *TrustedIssuersRegistry
	assert.False(t, reg.IsTrusted(ClaimTopicKYC, "issuer-a"))
}

// ---------------------------------------------------------------------------
// ClaimIssuerTransaction
// ---------------------------------------------------------------------------

func TestClaimIssuerTransaction_SignAndVerifyViaKeyProvider(t *testing.T) {
	operatorKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	provider := NewLocalKeyProvider(operatorKey)

	cit := ClaimIssuerTransaction{
		Topic:      ClaimTopicKYC,
		IssuerKey:  "some-issuer-pubkey",
		Action:     ClaimIssuerActionAdd,
		RecordedAt: time.Now().Unix(),
	}
	sig, err := provider.Sign(cit.SigningHash())
	require.NoError(t, err)
	cit.AdminSignature = sig

	assert.True(t, provider.Verify(cit.SigningHash(), cit.AdminSignature))

	// Tampering with any signed field must invalidate the signature.
	tampered := cit
	tampered.Action = ClaimIssuerActionRemove
	assert.False(t, provider.Verify(tampered.SigningHash(), tampered.AdminSignature))
}

// ---------------------------------------------------------------------------
// SynthesizeClaimsFromAttestation (backward-compatible adapter)
// ---------------------------------------------------------------------------

func TestSynthesizeClaimsFromAttestation_NilAndInvalid(t *testing.T) {
	assert.Nil(t, SynthesizeClaimsFromAttestation(nil))

	expired := &CredentialAttestation{
		WalletPublicKey: "wallet-1",
		KYCStatus:       KYCStatusVerified,
		ExpiresAt:       time.Now().Unix() - 1,
	}
	assert.Nil(t, SynthesizeClaimsFromAttestation(expired), "expired attestation must not synthesize claims")
}

func TestSynthesizeClaimsFromAttestation_RetailInvestor(t *testing.T) {
	att := &CredentialAttestation{
		WalletPublicKey: "wallet-1",
		InvestorClass:   InvestorClassRetail,
		KYCStatus:       KYCStatusVerified,
		Jurisdiction:    "DE",
		ExpiresAt:       time.Now().Unix() + 86400,
	}
	claims := SynthesizeClaimsFromAttestation(att)
	require.Len(t, claims, 2, "retail investors get KYC + jurisdiction claims but not an accredited claim")

	topics := map[ClaimTopic]bool{}
	for _, c := range claims {
		topics[c.Topic] = true
		assert.True(t, c.IsValid())
		assert.Equal(t, legacyClaimIssuer, c.Issuer)
	}
	assert.True(t, topics[ClaimTopicKYC])
	assert.True(t, topics[ClaimTopicJurisdictionResident])
	assert.False(t, topics[ClaimTopicAccredited])
}

func TestSynthesizeClaimsFromAttestation_ProfessionalInvestor(t *testing.T) {
	att := &CredentialAttestation{
		WalletPublicKey: "wallet-2",
		InvestorClass:   InvestorClassProfessional,
		KYCStatus:       KYCStatusVerified,
		Jurisdiction:    "LU",
		ExpiresAt:       time.Now().Unix() + 86400,
	}
	claims := SynthesizeClaimsFromAttestation(att)
	require.Len(t, claims, 3, "accredited (non-retail) investors also get an accredited claim")

	var accreditedClaim *Claim
	for _, c := range claims {
		if c.Topic == ClaimTopicAccredited {
			accreditedClaim = c
		}
	}
	require.NotNil(t, accreditedClaim)
	assert.Equal(t, string(InvestorClassProfessional), accreditedClaim.Data)
}

// ---------------------------------------------------------------------------
// EffectiveClaims / EvaluateComplianceRequirements
// ---------------------------------------------------------------------------

func newClaimsTestBlockchain(t *testing.T) *Blockchain {
	t.Helper()
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", ConsensusModeHTTP)
	return NewBlockchain(t.Context(), "claims-test")
}

func TestEvaluateComplianceRequirements_FallsBackToLegacyAttestation(t *testing.T) {
	bc := newClaimsTestBlockchain(t)
	walletKey := "wallet-legacy"
	bc.Credentials[walletKey] = &CredentialAttestation{
		WalletPublicKey: walletKey,
		InvestorClass:   InvestorClassAccredited,
		KYCStatus:       KYCStatusVerified,
		Jurisdiction:    "GB",
		ExpiresAt:       time.Now().Unix() + 86400,
	}

	err := EvaluateComplianceRequirements(bc, walletKey, []ClaimTopic{ClaimTopicKYC, ClaimTopicAccredited, ClaimTopicJurisdictionResident})
	assert.NoError(t, err, "a wallet with only a legacy attestation should satisfy topics via the adapter")

	err = EvaluateComplianceRequirements(bc, walletKey, []ClaimTopic{ClaimTopicSuitability})
	assert.Error(t, err, "topics not implied by the legacy attestation must fail")
}

func TestEvaluateComplianceRequirements_RealClaimTakesPrecedence(t *testing.T) {
	bc := newClaimsTestBlockchain(t)
	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	walletKey := "wallet-real-claim"

	claim, err := NewClaim(ClaimTopicSuitability, "", walletKey, "suitable", 30, issuerKey)
	require.NoError(t, err)
	bc.Claims[walletKey] = []*Claim{claim}

	assert.NoError(t, EvaluateComplianceRequirements(bc, walletKey, []ClaimTopic{ClaimTopicSuitability}))
	assert.Error(t, EvaluateComplianceRequirements(bc, walletKey, []ClaimTopic{ClaimTopicKYC}),
		"a real claim for one topic must not satisfy an unrelated required topic")
}

func TestEvaluateComplianceRequirements_UnknownWallet(t *testing.T) {
	bc := newClaimsTestBlockchain(t)
	err := EvaluateComplianceRequirements(bc, "never-onboarded", []ClaimTopic{ClaimTopicKYC})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// IdentityRegistry.IssueClaim implementations
// ---------------------------------------------------------------------------

func TestMockIdentityRegistry_IssueClaim(t *testing.T) {
	reg, err := NewMockIdentityRegistry()
	require.NoError(t, err)

	claim, err := reg.IssueClaim("wallet-1", ClaimTopicKYC, "professional", 30)
	require.NoError(t, err)
	assert.Equal(t, ClaimTopicKYC, claim.Topic)
	assert.True(t, claim.VerifySignature(reg.RegistryPublicKey()))
}

func TestOperatorIdentityRegistry_IssueClaim(t *testing.T) {
	registryKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	reg, err := NewOperatorIdentityRegistry(registryKey)
	require.NoError(t, err)

	claim, err := reg.IssueClaim("wallet-1", ClaimTopicAMLClear, "", 30)
	require.NoError(t, err)
	assert.Equal(t, ClaimTopicAMLClear, claim.Topic)
	assert.True(t, claim.VerifySignature(reg.RegistryPublicKey()))
}
