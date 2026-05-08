package gonetwork

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// InvestorClass classifies a participant for regulatory eligibility checks.
type InvestorClass string

const (
	InvestorClassRetail       InvestorClass = "retail"
	InvestorClassProfessional InvestorClass = "professional"
	InvestorClassEligibleCP   InvestorClass = "eligible_cp"
	InvestorClassAccredited   InvestorClass = "accredited"
)

// KYCStatus tracks the KYC verification state of a participant wallet.
type KYCStatus string

const (
	KYCStatusNone     KYCStatus = "none"
	KYCStatusPending  KYCStatus = "pending"
	KYCStatusVerified KYCStatus = "verified"
	KYCStatusRejected KYCStatus = "rejected"
	KYCStatusExpired  KYCStatus = "expired"
)

// IdentityCredential is held off-chain by the wallet owner and the registry.
// It contains NO personal data — only verifiable claims (class, jurisdiction, expiry).
// The registry signs it; the wallet owner presents it when challenged.
type IdentityCredential struct {
	WalletPublicKey   string
	InvestorClass     InvestorClass
	KYCStatus         KYCStatus
	Jurisdiction      string // ISO 3166-1 alpha-2
	IssuedAt          int64
	ExpiresAt         int64
	RegistryID        string // base64-encoded public key of the issuing registry node
	RegistrySignature []byte // Ed25519 sig over all fields (with RegistrySignature=nil)
}

// CredentialAttestation is the on-chain record of a participant's verified identity.
// Only the credential hash and a duplication of the eligibility fields live on-chain —
// no personal data is committed to the blockchain.
type CredentialAttestation struct {
	WalletPublicKey   string
	CredentialHash    string        // SHA3-256 hex of the IdentityCredential JSON
	InvestorClass     InvestorClass // duplicated for fast on-chain eligibility checks
	KYCStatus         KYCStatus     // duplicated for fast on-chain eligibility checks
	Jurisdiction      string        // duplicated for fast on-chain eligibility checks
	ExpiresAt         int64
	RegistrySignature []byte // same signature as on the parent IdentityCredential
}

// CredentialTransaction is broadcast via P2P when the registry issues an attestation.
// It is included in a block, committing the credential on-chain.
type CredentialTransaction struct {
	Attestation CredentialAttestation
}

// ---------------------------------------------------------------------------
// IdentityRegistry interface
// ---------------------------------------------------------------------------

// IdentityRegistry is the interface both the mock and any future live KYC provider
// must implement. All identity checks in assets.go and orderbook.go use this
// interface — never a concrete type.
type IdentityRegistry interface {
	// IssueCredential creates and signs an attestation for a wallet.
	// In production this is called by the registry operator after off-chain KYC.
	// In the mock it is called immediately with no checks.
	IssueCredential(
		walletKey string,
		class InvestorClass,
		jurisdiction string,
		validForDays int,
	) (*CredentialAttestation, error)

	// VerifyCredential checks that a wallet has a valid, non-expired credential.
	VerifyCredential(walletKey string) (*CredentialAttestation, error)

	// RegistryPublicKey returns the registry's public key for signature verification.
	RegistryPublicKey() *PublicKey
}

// ---------------------------------------------------------------------------
// IdentityCredential functions
// ---------------------------------------------------------------------------

// NewIdentityCredential creates and signs a new identity credential.
// The credential is signed by the registry key; any mutation is detectable.
func NewIdentityCredential(
	walletKey string,
	class InvestorClass,
	jurisdiction string,
	validForDays int,
	registryKey *PrivateKey,
) (*IdentityCredential, error) {
	if walletKey == "" {
		return nil, fmt.Errorf("wallet key must not be empty")
	}
	if jurisdiction == "" {
		return nil, fmt.Errorf("jurisdiction must not be empty")
	}
	if registryKey == nil {
		return nil, fmt.Errorf("registry key must not be nil")
	}
	if validForDays <= 0 {
		return nil, fmt.Errorf("validForDays must be greater than zero")
	}

	now := time.Now().Unix()
	registryID := base64.StdEncoding.EncodeToString(registryKey.Public().Bytes())

	c := &IdentityCredential{
		WalletPublicKey:   walletKey,
		InvestorClass:     class,
		KYCStatus:         KYCStatusVerified,
		Jurisdiction:      jurisdiction,
		IssuedAt:          now,
		ExpiresAt:         now + int64(validForDays)*86400,
		RegistryID:        registryID,
		RegistrySignature: nil, // must be nil during signing
	}

	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	c.RegistrySignature = registryKey.Sign(hash[:]).Bytes()

	return c, nil
}

// VerifySignature checks the registry's Ed25519 signature on the credential.
// Returns false if the credential has been tampered with.
func (c *IdentityCredential) VerifySignature(registryPubKey *PublicKey) bool {
	credCopy := *c
	credCopy.RegistrySignature = nil
	data, err := json.Marshal(credCopy)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: c.RegistrySignature}
	return sig.Verify(registryPubKey, hash[:])
}

// IsExpired returns true if the credential has passed its expiry timestamp.
func (c *IdentityCredential) IsExpired() bool {
	return time.Now().Unix() > c.ExpiresAt
}

// ToAttestation converts an IdentityCredential into an on-chain CredentialAttestation.
// The hash commits the full credential; the eligibility fields are duplicated for
// fast checking without re-reading the off-chain credential.
func (c *IdentityCredential) ToAttestation() *CredentialAttestation {
	data, _ := json.Marshal(c)
	hash := sha3.Sum256(data)

	return &CredentialAttestation{
		WalletPublicKey:   c.WalletPublicKey,
		CredentialHash:    hex.EncodeToString(hash[:]),
		InvestorClass:     c.InvestorClass,
		KYCStatus:         c.KYCStatus,
		Jurisdiction:      c.Jurisdiction,
		ExpiresAt:         c.ExpiresAt,
		RegistrySignature: c.RegistrySignature,
	}
}

// ---------------------------------------------------------------------------
// CredentialAttestation functions
// ---------------------------------------------------------------------------

// IsValid returns true if the credential is verified and has not expired.
func (a *CredentialAttestation) IsValid() bool {
	return a.KYCStatus == KYCStatusVerified && time.Now().Unix() <= a.ExpiresAt
}

// IsAccredited returns true if the credential is valid and the investor class
// is above retail (professional, eligible counterparty, or accredited).
func (a *CredentialAttestation) IsAccredited() bool {
	return a.IsValid() && a.InvestorClass != InvestorClassRetail
}

// ---------------------------------------------------------------------------
// MockIdentityRegistry
// ---------------------------------------------------------------------------

// MockIdentityRegistry implements IdentityRegistry using real Ed25519 keys.
// Credentials are issued instantly with no off-chain checks.
// It is the test double used in all tests that involve identity.
type MockIdentityRegistry struct {
	registryKey *PrivateKey
	registryPub *PublicKey
	credentials map[string]*CredentialAttestation
}

// NewMockIdentityRegistry generates a fresh Ed25519 registry key and returns
// a ready-to-use MockIdentityRegistry.
func NewMockIdentityRegistry() (*MockIdentityRegistry, error) {
	key, err := GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate registry key: %w", err)
	}
	pub := key.Public()
	return &MockIdentityRegistry{
		registryKey: key,
		registryPub: pub,
		credentials: make(map[string]*CredentialAttestation),
	}, nil
}

// IssueCredential creates and stores an attestation for walletKey.
func (r *MockIdentityRegistry) IssueCredential(
	walletKey string,
	class InvestorClass,
	jurisdiction string,
	validForDays int,
) (*CredentialAttestation, error) {
	cred, err := NewIdentityCredential(walletKey, class, jurisdiction, validForDays, r.registryKey)
	if err != nil {
		return nil, err
	}
	attestation := cred.ToAttestation()
	r.credentials[walletKey] = attestation
	return attestation, nil
}

// VerifyCredential returns the stored attestation for walletKey, or an error
// if no credential has been issued.
func (r *MockIdentityRegistry) VerifyCredential(walletKey string) (*CredentialAttestation, error) {
	a, ok := r.credentials[walletKey]
	if !ok {
		return nil, fmt.Errorf("no credential found for wallet %s", walletKey)
	}
	return a, nil
}

// RegistryPublicKey returns the registry's public key for signature verification.
func (r *MockIdentityRegistry) RegistryPublicKey() *PublicKey {
	return r.registryPub
}
