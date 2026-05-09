package gonetwork

import "encoding/base64"

// ---------------------------------------------------------------------------
// KeyProvider interface
// ---------------------------------------------------------------------------

// KeyProvider abstracts key storage and signing operations.
// LocalKeyProvider uses the existing in-memory PrivateKey.
// KMSKeyProvider is a stub that records intended API calls; replace the body
// of Sign / Verify with real AWS KMS SDK calls when KMS onboarding is complete.
type KeyProvider interface {
	// PublicKeyString returns the base64-encoded Ed25519 public key.
	PublicKeyString() string

	// Sign returns an Ed25519 signature over msg.
	// For KMSKeyProvider this will invoke the AWS KMS Sign API.
	Sign(msg []byte) ([]byte, error)

	// Verify returns true if sig is a valid Ed25519 signature of msg under
	// this provider's key.
	Verify(msg, sig []byte) bool
}

// ---------------------------------------------------------------------------
// LocalKeyProvider
// ---------------------------------------------------------------------------

// LocalKeyProvider implements KeyProvider using an in-memory Ed25519 PrivateKey.
type LocalKeyProvider struct {
	key *PrivateKey
}

// NewLocalKeyProvider wraps an existing PrivateKey in a LocalKeyProvider.
func NewLocalKeyProvider(key *PrivateKey) *LocalKeyProvider {
	return &LocalKeyProvider{key: key}
}

// PublicKeyString returns the base64-encoded public key string.
func (p *LocalKeyProvider) PublicKeyString() string {
	return base64.StdEncoding.EncodeToString(p.key.Public().Bytes())
}

// Sign signs msg with the in-memory private key and returns the raw signature bytes.
func (p *LocalKeyProvider) Sign(msg []byte) ([]byte, error) {
	return p.key.Sign(msg).Bytes(), nil
}

// Verify checks whether sig is a valid Ed25519 signature of msg under this
// provider's key.
func (p *LocalKeyProvider) Verify(msg, sig []byte) bool {
	s := &Signature{value: sig}
	return s.Verify(p.key.Public(), msg)
}

// ---------------------------------------------------------------------------
// KMSKeyProvider (stub)
// ---------------------------------------------------------------------------

// KMSKeyProvider is a production stub for AWS KMS-backed signing.
// In production, replace Sign and Verify bodies with real KMS SDK calls.
// Calls records all method invocations for test assertion and audit.
type KMSKeyProvider struct {
	KeyARN    string
	KeyID     string
	PublicKey string // cached from KMS DescribeKey; empty until populated
	Calls     []string
}

// NewKMSKeyProvider creates a KMSKeyProvider for the given AWS KMS key ARN.
func NewKMSKeyProvider(keyARN string) *KMSKeyProvider {
	return &KMSKeyProvider{
		KeyARN: keyARN,
		KeyID:  keyARN,
	}
}

// PublicKeyString returns the cached public key string (populated on first use in production).
func (p *KMSKeyProvider) PublicKeyString() string {
	return p.PublicKey
}

// Sign records the call and returns nil, nil.
// Production replacement: call kms.Sign(p.KeyARN, msg, "ECDSA_SHA_256").
func (p *KMSKeyProvider) Sign(msg []byte) ([]byte, error) {
	p.Calls = append(p.Calls, "Sign")
	return nil, nil
}

// Verify records the call and returns true.
// Production replacement: verify signature via kms.GetPublicKey + local Ed25519 verify.
func (p *KMSKeyProvider) Verify(msg, sig []byte) bool {
	p.Calls = append(p.Calls, "Verify")
	return true
}

// ---------------------------------------------------------------------------
// Package-level helper
// ---------------------------------------------------------------------------

// VerifySignatureBytes verifies an Ed25519 signature against a message using
// the given public key. Exported for use by sub-packages (e.g. api) that
// cannot construct the unexported Signature type directly.
func VerifySignatureBytes(pub *PublicKey, msg, sig []byte) bool {
	s := &Signature{value: sig}
	return s.Verify(pub, msg)
}
