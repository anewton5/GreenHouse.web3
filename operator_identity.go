package gonetwork

import (
	"fmt"
	"sync"
	"time"
)

// PendingKYCRequest holds a KYC approval request submitted by a participant
// and awaiting review by a GreenHouse operator.
type PendingKYCRequest struct {
	WalletKey    string        `json:"wallet_key"`
	Class        InvestorClass `json:"class"`
	Jurisdiction string        `json:"jurisdiction"`
	ValidForDays int           `json:"valid_for_days"`
	RequestedAt  int64         `json:"requested_at"` // Unix timestamp
}

// OperatorIdentityRegistry implements IdentityRegistry with a manual
// operator-review approval workflow.
//
// Participants submit KYC requests via POST /v1/kyc/request. These requests
// appear in the admin queue, which a GreenHouse operator reviews after
// examining off-chain documents (passport scans, proof of address, etc.).
// The operator approves via POST /v1/admin/kyc/approve, which calls
// IssueCredential internally.
//
// This is the zero-external-cost KYC path for early-stage development and
// first pilot users. Replace with an automated provider (Sumsub, Persona,
// Onfido) when the volume of applications makes manual review impractical.
type OperatorIdentityRegistry struct {
	mu          sync.RWMutex
	registryKey *PrivateKey
	registryPub *PublicKey
	credentials map[string]*CredentialAttestation
	pending     map[string]*PendingKYCRequest
}

// NewOperatorIdentityRegistry creates a new OperatorIdentityRegistry bound to
// the provided registry key. The registry key should be kept in secure storage
// (e.g. a key file readable only by the node process, or KMS in production).
func NewOperatorIdentityRegistry(registryKey *PrivateKey) (*OperatorIdentityRegistry, error) {
	if registryKey == nil {
		return nil, fmt.Errorf("operator registry: registry key must not be nil")
	}
	return &OperatorIdentityRegistry{
		registryKey: registryKey,
		registryPub: registryKey.Public(),
		credentials: make(map[string]*CredentialAttestation),
		pending:     make(map[string]*PendingKYCRequest),
	}, nil
}

// RequestKYC adds a KYC approval request to the pending queue.
// Called by participants before they can trade. A duplicate request for the
// same wallet key overwrites the previous one (allowing resubmission after
// an operator asks for corrections).
func (o *OperatorIdentityRegistry) RequestKYC(
	walletKey string,
	class InvestorClass,
	jurisdiction string,
	validForDays int,
) error {
	if walletKey == "" {
		return fmt.Errorf("operator registry: wallet key must not be empty")
	}
	if jurisdiction == "" {
		return fmt.Errorf("operator registry: jurisdiction must not be empty")
	}
	if validForDays <= 0 {
		return fmt.Errorf("operator registry: validForDays must be greater than zero")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pending[walletKey] = &PendingKYCRequest{
		WalletKey:    walletKey,
		Class:        class,
		Jurisdiction: jurisdiction,
		ValidForDays: validForDays,
		RequestedAt:  time.Now().Unix(),
	}
	return nil
}

// ApproveKYC issues a credential for a wallet that has a pending request.
// Must be called by an authorised operator. The pending request is removed
// from the queue whether or not credential issuance succeeds.
func (o *OperatorIdentityRegistry) ApproveKYC(walletKey string) (*CredentialAttestation, error) {
	o.mu.Lock()
	req, ok := o.pending[walletKey]
	if !ok {
		o.mu.Unlock()
		return nil, fmt.Errorf("operator registry: no pending KYC request for wallet %s", walletKey)
	}
	delete(o.pending, walletKey)
	o.mu.Unlock()

	return o.IssueCredential(req.WalletKey, req.Class, req.Jurisdiction, req.ValidForDays)
}

// IssueCredential creates and signs an attestation for walletKey.
// Implements IdentityRegistry. Can be called directly by an operator without
// a prior RequestKYC (e.g. for bulk onboarding or pilot participants).
func (o *OperatorIdentityRegistry) IssueCredential(
	walletKey string,
	class InvestorClass,
	jurisdiction string,
	validForDays int,
) (*CredentialAttestation, error) {
	cred, err := NewIdentityCredential(walletKey, class, jurisdiction, validForDays, o.registryKey)
	if err != nil {
		return nil, err
	}
	attestation := cred.ToAttestation()
	o.mu.Lock()
	o.credentials[walletKey] = attestation
	o.mu.Unlock()
	return attestation, nil
}

// VerifyCredential returns the stored attestation for walletKey.
// Returns an error if no credential has been issued for the wallet.
func (o *OperatorIdentityRegistry) VerifyCredential(walletKey string) (*CredentialAttestation, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	a, ok := o.credentials[walletKey]
	if !ok {
		return nil, fmt.Errorf("operator registry: no credential found for wallet %s", walletKey)
	}
	return a, nil
}

// RegistryPublicKey returns the registry's public key for signature verification.
func (o *OperatorIdentityRegistry) RegistryPublicKey() *PublicKey {
	return o.registryPub
}

// IssueClaim creates and signs a topic-scoped Claim for walletKey, using the
// same registry key that signs CredentialAttestations via IssueCredential.
func (o *OperatorIdentityRegistry) IssueClaim(walletKey string, topic ClaimTopic, data string, validForDays int) (*Claim, error) {
	return NewClaim(topic, "", walletKey, data, validForDays, o.registryKey)
}

// ListPendingRequests returns all pending KYC requests.
// Called by GET /v1/admin/kyc/pending to populate the operator approval queue.
func (o *OperatorIdentityRegistry) ListPendingRequests() []*PendingKYCRequest {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]*PendingKYCRequest, 0, len(o.pending))
	for _, r := range o.pending {
		out = append(out, r)
	}
	return out
}

// PendingCount returns the number of wallets currently awaiting KYC approval.
func (o *OperatorIdentityRegistry) PendingCount() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.pending)
}
