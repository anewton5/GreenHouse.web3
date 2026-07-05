package gonetwork

// ---------------------------------------------------------------------------
// Phase 2 — Claim-Topic / Trusted-Issuer Registry (ERC-3643/ONCHAINID-style)
//
// This generalises the flat, single-issuer CredentialAttestation model
// (identity.go) into independently issued, expired, and revoked per-topic
// Claims, each signed by whichever issuer TrustedIssuersRegistry authorises
// for that specific topic — mirroring ERC-3643's ITrustedIssuersRegistry +
// IClaimTopicsRegistry pattern, collapsed into one registry since a fixed
// ClaimTopic enum makes a separate topics registry unnecessary for now.
//
// This layer is purely additive: SynthesizeClaimsFromAttestation lets every
// wallet with a legacy CredentialAttestation satisfy claim-topic checks via
// EvaluateComplianceRequirements without being re-onboarded, and none of the
// existing identity/compliance code paths are modified by this file.
// ---------------------------------------------------------------------------

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// ClaimTopic
// ---------------------------------------------------------------------------

// ClaimTopic identifies the kind of eligibility fact a Claim attests to.
// Kept as a fixed enum (+ a custom escape hatch) rather than a fully dynamic
// on-chain topic registry, to avoid unnecessary complexity at this stage.
type ClaimTopic string

const (
	ClaimTopicKYC                  ClaimTopic = "kyc"
	ClaimTopicAMLClear             ClaimTopic = "aml_clear"
	ClaimTopicAccredited           ClaimTopic = "accredited"
	ClaimTopicJurisdictionResident ClaimTopic = "jurisdiction_resident"
	ClaimTopicPEPClear             ClaimTopic = "pep_clear"
	ClaimTopicSuitability          ClaimTopic = "suitability"
	ClaimTopicInstitutionalRole    ClaimTopic = "institutional_role"
	// ClaimTopicCustom is an escape hatch for topics not yet in the fixed enum
	// above; use Claim.CustomTopic to name the specific topic when this
	// constant is used.
	ClaimTopicCustom ClaimTopic = "custom"
)

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

// Claim is a single, independently issued and independently revocable
// eligibility attestation about a wallet, scoped to one ClaimTopic. A wallet
// may hold multiple claims across different topics, each signed by whichever
// issuer is trusted for that topic (see TrustedIssuersRegistry) — unlike
// CredentialAttestation, which bundles KYC status, investor class, and
// jurisdiction into a single all-or-nothing record signed by exactly one
// registry.
type Claim struct {
	Topic ClaimTopic `json:"topic"`
	// CustomTopic is set only when Topic == ClaimTopicCustom.
	CustomTopic string `json:"custom_topic,omitempty"`
	// Subject is the base64-encoded Ed25519 public key of the wallet the
	// claim is about.
	Subject string `json:"subject"`
	// Issuer is the base64-encoded Ed25519 public key of the issuing
	// authority. For claims synthesized from a legacy CredentialAttestation
	// (see SynthesizeClaimsFromAttestation) this is the sentinel string
	// "legacy:credential_attestation" rather than a real key.
	Issuer string `json:"issuer"`
	// Data carries topic-specific payload as a plain string, e.g. the
	// jurisdiction code for ClaimTopicJurisdictionResident, or the investor
	// class for ClaimTopicAccredited.
	Data      string `json:"data,omitempty"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
	// Signature is the Ed25519 signature by Issuer over the claim's JSON
	// representation with Signature set to nil.
	Signature []byte `json:"signature"`
}

// NewClaim creates and signs a new Claim. issuerKey signs the claim; any
// mutation of the claim after issuance is detectable via VerifySignature.
func NewClaim(
	topic ClaimTopic,
	customTopic string,
	subject string,
	data string,
	validForDays int,
	issuerKey *PrivateKey,
) (*Claim, error) {
	if subject == "" {
		return nil, fmt.Errorf("claim subject must not be empty")
	}
	if issuerKey == nil {
		return nil, fmt.Errorf("issuer key must not be nil")
	}
	if validForDays <= 0 {
		return nil, fmt.Errorf("validForDays must be greater than zero")
	}
	if topic == ClaimTopicCustom && customTopic == "" {
		return nil, fmt.Errorf("custom_topic must be set when topic is %q", ClaimTopicCustom)
	}

	now := time.Now().Unix()
	c := &Claim{
		Topic:       topic,
		CustomTopic: customTopic,
		Subject:     subject,
		Issuer:      base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes()),
		Data:        data,
		IssuedAt:    now,
		ExpiresAt:   now + int64(validForDays)*86400,
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claim for signing: %w", err)
	}
	hash := sha3.Sum256(payload)
	c.Signature = issuerKey.Sign(hash[:]).Bytes()
	return c, nil
}

// VerifySignature checks issuerPubKey's Ed25519 signature on the claim.
// Returns false if the claim has been tampered with since it was signed.
func (c *Claim) VerifySignature(issuerPubKey *PublicKey) bool {
	claimCopy := *c
	claimCopy.Signature = nil
	payload, err := json.Marshal(claimCopy)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(payload)
	sig := &Signature{value: c.Signature}
	return sig.Verify(issuerPubKey, hash[:])
}

// IsExpired returns true if the claim has passed its expiry timestamp.
func (c *Claim) IsExpired() bool {
	return time.Now().Unix() > c.ExpiresAt
}

// IsValid returns true if the claim carries a signature and has not expired.
// Note this checks presence of a signature only — cryptographic validity
// against a specific issuer key is checked separately via VerifySignature
// (real claims) or is not applicable (synthesized claims; see
// SynthesizeClaimsFromAttestation).
func (c *Claim) IsValid() bool {
	return len(c.Signature) > 0 && !c.IsExpired()
}

// ---------------------------------------------------------------------------
// TrustedIssuersRegistry
// ---------------------------------------------------------------------------

// TrustedIssuersRegistry maps each ClaimTopic to the set of issuer public
// keys (base64-encoded) authorised to issue claims for that topic. Mirrors
// ERC-3643's ITrustedIssuersRegistry + IClaimTopicsRegistry pattern.
type TrustedIssuersRegistry struct {
	// Issuers maps topic -> set of trusted issuer public keys (base64).
	Issuers map[ClaimTopic]map[string]bool `json:"issuers"`
}

// NewTrustedIssuersRegistry returns an empty registry (no issuer trusted for
// any topic). Trust must be granted explicitly via AddIssuer.
func NewTrustedIssuersRegistry() *TrustedIssuersRegistry {
	return &TrustedIssuersRegistry{Issuers: make(map[ClaimTopic]map[string]bool)}
}

// IsTrusted returns true if issuerKey is authorised to issue claims for topic.
func (r *TrustedIssuersRegistry) IsTrusted(topic ClaimTopic, issuerKey string) bool {
	if r == nil || r.Issuers == nil {
		return false
	}
	set, ok := r.Issuers[topic]
	if !ok {
		return false
	}
	return set[issuerKey]
}

// AddIssuer authorises issuerKey to issue claims for topic. Idempotent.
func (r *TrustedIssuersRegistry) AddIssuer(topic ClaimTopic, issuerKey string) {
	if r.Issuers == nil {
		r.Issuers = make(map[ClaimTopic]map[string]bool)
	}
	if r.Issuers[topic] == nil {
		r.Issuers[topic] = make(map[string]bool)
	}
	r.Issuers[topic][issuerKey] = true
}

// RemoveIssuer revokes issuerKey's authorisation to issue claims for topic.
func (r *TrustedIssuersRegistry) RemoveIssuer(topic ClaimTopic, issuerKey string) {
	if r.Issuers == nil || r.Issuers[topic] == nil {
		return
	}
	delete(r.Issuers[topic], issuerKey)
}

// ---------------------------------------------------------------------------
// On-chain transactions
// ---------------------------------------------------------------------------

// ClaimTransaction is broadcast/committed when an issuer issues a Claim to a
// wallet. Included in a block via SealClaimBlock, mirroring how
// CredentialTransaction commits a CredentialAttestation.
type ClaimTransaction struct {
	Claim Claim `json:"claim"`
}

// ClaimIssuerAction distinguishes an add vs. remove operation in a
// ClaimIssuerTransaction.
type ClaimIssuerAction string

const (
	ClaimIssuerActionAdd    ClaimIssuerAction = "add"
	ClaimIssuerActionRemove ClaimIssuerAction = "remove"
)

// ClaimIssuerTransaction records a governance action authorising or revoking
// an issuer's trust for a specific ClaimTopic. Committed on-chain (via
// SealClaimBlock) so trusted-issuer changes are auditable.
//
// At this stage (single-operator governance — see VELA roadmap Section 6.4)
// the transaction must be signed by the node's own OperatorKeyProvider, the
// same key that already signs every sealed block. This avoids inventing a
// new admin-key concept and matches the "centrally-operated, licensed
// regulated entity" posture appropriate before a genuine multi-institution
// governance body exists.
type ClaimIssuerTransaction struct {
	Topic          ClaimTopic        `json:"topic"`
	IssuerKey      string            `json:"issuer_key"` // base64 Ed25519 public key being added/removed
	Action         ClaimIssuerAction `json:"action"`
	RecordedAt     int64             `json:"recorded_at"`
	AdminSignature []byte            `json:"admin_signature"`
}

// SigningHash returns the deterministic pre-signature hash that
// AdminSignature covers (all fields except AdminSignature itself).
func (t *ClaimIssuerTransaction) SigningHash() []byte {
	cp := *t
	cp.AdminSignature = nil
	data, _ := json.Marshal(cp)
	hash := sha3.Sum256(data)
	return hash[:]
}

// ---------------------------------------------------------------------------
// Backward-compatible adapter
// ---------------------------------------------------------------------------

// legacyClaimIssuer is the sentinel Issuer value on claims synthesized from a
// legacy CredentialAttestation, so callers can distinguish real, independently
// verifiable claims from ones derived for backward compatibility.
const legacyClaimIssuer = "legacy:credential_attestation"

// synthesizedClaimSignature is a non-empty placeholder so IsValid()'s
// signature-presence check passes for synthesized claims. Synthesized claims
// are not independently signed — their validity rests entirely on the
// legacy CredentialAttestation.IsValid() check performed before synthesis.
var synthesizedClaimSignature = []byte("synthesized")

// SynthesizeClaimsFromAttestation derives the set of topic claims implied by
// a legacy CredentialAttestation, without requiring the wallet to have any
// real on-chain Claim. This lets EvaluateComplianceRequirements treat every
// existing credential holder as already satisfying the equivalent claim
// topics, so introducing the Phase 2 claims model does not break eligibility
// for any wallet onboarded before this feature existed. Returns nil if att is
// nil or not currently valid.
func SynthesizeClaimsFromAttestation(att *CredentialAttestation) []*Claim {
	if att == nil || !att.IsValid() {
		return nil
	}
	base := Claim{
		Subject:   att.WalletPublicKey,
		Issuer:    legacyClaimIssuer,
		ExpiresAt: att.ExpiresAt,
		Signature: synthesizedClaimSignature,
	}

	kyc := base
	kyc.Topic = ClaimTopicKYC
	claims := []*Claim{&kyc}

	jur := base
	jur.Topic = ClaimTopicJurisdictionResident
	jur.Data = att.Jurisdiction
	claims = append(claims, &jur)

	if att.IsAccredited() {
		acc := base
		acc.Topic = ClaimTopicAccredited
		acc.Data = string(att.InvestorClass)
		claims = append(claims, &acc)
	}

	return claims
}

// ---------------------------------------------------------------------------
// Unified compliance entry point
// ---------------------------------------------------------------------------

// EffectiveClaims returns the union of real on-chain claims for walletKey
// (bc.Claims) and claims synthesized from the legacy CredentialAttestation
// (bc.Credentials) for topics not already covered by a real claim. Real
// claims take precedence over synthesized ones for the same topic.
func EffectiveClaims(bc *Blockchain, walletKey string) []*Claim {
	if bc == nil {
		return nil
	}
	var out []*Claim
	covered := make(map[ClaimTopic]bool)
	for _, c := range bc.Claims[walletKey] {
		if c.IsValid() {
			out = append(out, c)
			covered[c.Topic] = true
		}
	}
	if att, ok := bc.Credentials[walletKey]; ok && att != nil {
		for _, c := range SynthesizeClaimsFromAttestation(att) {
			if !covered[c.Topic] {
				out = append(out, c)
			}
		}
	}
	return out
}

// hasValidClaimForTopic returns true if claims contains a valid claim (or
// custom claim matching customTopic, when topic == ClaimTopicCustom) for topic.
func hasValidClaimForTopic(claims []*Claim, topic ClaimTopic, customTopic string) bool {
	for _, c := range claims {
		if !c.IsValid() || c.Topic != topic {
			continue
		}
		if topic == ClaimTopicCustom && c.CustomTopic != customTopic {
			continue
		}
		return true
	}
	return false
}

// hasVerifiedProofForTopic returns true when proofs contains at least one proof
// for topic that verifier accepts. verifier nil => false (fail closed).
func hasVerifiedProofForTopic(verifier ZKClaimVerifier, topic ClaimTopic, proofs []ZKClaimProof) bool {
	if verifier == nil {
		return false
	}
	for _, p := range proofs {
		if p.ClaimTopic != topic {
			continue
		}
		ok, err := verifier.VerifyProof(p, topic)
		if err != nil {
			continue
		}
		if ok {
			return true
		}
	}
	return false
}

// EvaluateComplianceRequirements checks that walletKey satisfies every topic
// in requiredTopics, consulting EffectiveClaims (real claims first, falling
// back to claims synthesized from the legacy CredentialAttestation).
//
// This is the canonical, claim-topic-based compliance check introduced in
// Phase 2. It is additive: CheckTransferEligibility, ApplyJurisdictionRule,
// CheckSuitability, and CheckProspectusLimits remain the primary enforcement
// path for existing callers (their signatures take narrower parameters than
// bc and are unchanged); new integrations should prefer this function.
func EvaluateComplianceRequirements(bc *Blockchain, walletKey string, requiredTopics []ClaimTopic, proofs ...ZKClaimProof) error {
	claims := EffectiveClaims(bc, walletKey)
	for _, topic := range requiredTopics {
		if hasValidClaimForTopic(claims, topic, "") {
			continue
		}
		if bc != nil && hasVerifiedProofForTopic(bc.ZKVerifier, topic, proofs) {
			continue
		}
		if !hasValidClaimForTopic(claims, topic, "") {
			return fmt.Errorf("wallet %s is missing a valid claim for required topic %q", walletKey, topic)
		}
	}
	return nil
}
