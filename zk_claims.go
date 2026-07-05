package gonetwork

// ---------------------------------------------------------------------------
// Phase 5 — ZK-KYC interface groundwork (hooks only)
//
// This file defines additive interfaces and placeholder data structures for
// future selective-disclosure claim proofs. No production ZK system is
// implemented here: StubZKVerifier is deliberately fail-closed by default and
// only returns true for explicitly allow-listed topics in tests.
// ---------------------------------------------------------------------------

// ZKClaimProof is a placeholder envelope for zero-knowledge attestations about
// a claim topic. It is intentionally generic so future Groth16/PLONK back-ends
// can map their wire formats into one API surface.
type ZKClaimProof struct {
	ProofSystem string `json:"proof_system"` // e.g. "groth16", "plonk", "stub"
	ClaimTopic  ClaimTopic
	// CustomTopic is required when ClaimTopic == ClaimTopicCustom.
	CustomTopic string `json:"custom_topic,omitempty"`
	// PublicInputs are verifier-visible commitments/inputs (opaque bytes here).
	PublicInputs []byte `json:"public_inputs,omitempty"`
	// ProofBytes are the serialized proof payload (opaque bytes here).
	ProofBytes []byte `json:"proof_bytes,omitempty"`
	// CommitmentHash is an optional digest binding the proof to an external
	// commitment object (off-chain statement, merkle leaf, etc.).
	CommitmentHash string `json:"commitment_hash,omitempty"`
}

// ZKClaimVerifier verifies whether proof satisfies topic without revealing the
// underlying sensitive claim payload.
type ZKClaimVerifier interface {
	VerifyProof(proof ZKClaimProof, topic ClaimTopic) (bool, error)
}

// StubZKVerifier is a test/development verifier that fails closed by default.
// It only approves proofs for topics explicitly enabled via AllowedTopics.
type StubZKVerifier struct {
	AllowedTopics map[ClaimTopic]bool
}

// NewStubZKVerifier returns a fail-closed verifier (nothing allowed).
func NewStubZKVerifier() *StubZKVerifier {
	return &StubZKVerifier{AllowedTopics: make(map[ClaimTopic]bool)}
}

// VerifyProof implements ZKClaimVerifier. Returns true only when all of these
// hold:
//  1. proof.ClaimTopic matches topic
//  2. topic is explicitly allow-listed in AllowedTopics
//
// Otherwise it returns false with no error (fail closed).
func (v *StubZKVerifier) VerifyProof(proof ZKClaimProof, topic ClaimTopic) (bool, error) {
	if v == nil {
		return false, nil
	}
	if proof.ClaimTopic != topic {
		return false, nil
	}
	return v.AllowedTopics[topic], nil
}
