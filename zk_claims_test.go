package gonetwork

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStubZKVerifier_FailClosedByDefault(t *testing.T) {
	v := NewStubZKVerifier()
	ok, err := v.VerifyProof(ZKClaimProof{ProofSystem: "stub", ClaimTopic: ClaimTopicKYC}, ClaimTopicKYC)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestStubZKVerifier_AllowedTopicPasses(t *testing.T) {
	v := NewStubZKVerifier()
	v.AllowedTopics[ClaimTopicSuitability] = true

	ok, err := v.VerifyProof(ZKClaimProof{ProofSystem: "stub", ClaimTopic: ClaimTopicSuitability}, ClaimTopicSuitability)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestEvaluateComplianceRequirements_ZKHook_NoVerifierConfigured(t *testing.T) {
	bc := newClaimsTestBlockchain(t)
	err := EvaluateComplianceRequirements(
		bc,
		"wallet-zk-no-verifier",
		[]ClaimTopic{ClaimTopicSuitability},
		ZKClaimProof{ProofSystem: "stub", ClaimTopic: ClaimTopicSuitability},
	)
	assert.Error(t, err, "proofs must be ignored when no verifier is configured")
}

func TestEvaluateComplianceRequirements_ZKHook_VerifierAllowsTopic(t *testing.T) {
	bc := newClaimsTestBlockchain(t)
	verifier := NewStubZKVerifier()
	verifier.AllowedTopics[ClaimTopicSuitability] = true
	bc.ZKVerifier = verifier

	err := EvaluateComplianceRequirements(
		bc,
		"wallet-zk-allowed",
		[]ClaimTopic{ClaimTopicSuitability},
		ZKClaimProof{ProofSystem: "stub", ClaimTopic: ClaimTopicSuitability},
	)
	assert.NoError(t, err)
}

func TestEvaluateComplianceRequirements_ZKHook_FailClosedWhenVerifierRejects(t *testing.T) {
	bc := newClaimsTestBlockchain(t)
	bc.ZKVerifier = NewStubZKVerifier() // no allowed topics

	err := EvaluateComplianceRequirements(
		bc,
		"wallet-zk-rejected",
		[]ClaimTopic{ClaimTopicSuitability},
		ZKClaimProof{ProofSystem: "stub", ClaimTopic: ClaimTopicSuitability},
	)
	assert.Error(t, err)
}

type erroringZKVerifier struct{}

func (erroringZKVerifier) VerifyProof(ZKClaimProof, ClaimTopic) (bool, error) {
	return false, errors.New("verifier backend unavailable")
}

func TestEvaluateComplianceRequirements_ZKHook_FailClosedOnVerifierError(t *testing.T) {
	bc := newClaimsTestBlockchain(t)
	bc.ZKVerifier = erroringZKVerifier{}

	err := EvaluateComplianceRequirements(
		bc,
		"wallet-zk-error",
		[]ClaimTopic{ClaimTopicSuitability},
		ZKClaimProof{ProofSystem: "stub", ClaimTopic: ClaimTopicSuitability},
	)
	assert.Error(t, err)
}
