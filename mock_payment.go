package gonetwork

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// MockPaymentProvider
// ---------------------------------------------------------------------------

// MockPaymentProvider confirms payments instantly with no real banking integration.
// It records all virtual accounts and payment references for test assertions.
// Thread-safe for concurrent use via atomic counter and map access patterns typical
// in single-goroutine test scenarios.
type MockPaymentProvider struct {
	VirtualAccounts map[string]string        // walletID → IBAN
	Payments        map[string]PaymentStatus // reference → status
	counter         int64
}

// NewMockPaymentProvider returns an initialised MockPaymentProvider.
func NewMockPaymentProvider() *MockPaymentProvider {
	return &MockPaymentProvider{
		VirtualAccounts: make(map[string]string),
		Payments:        make(map[string]PaymentStatus),
	}
}

// CreateVirtualAccount generates and stores a deterministic mock IBAN for walletID.
// Format: GB<counter>MOCK<hash(walletID)[0:8]>
func (m *MockPaymentProvider) CreateVirtualAccount(ctx context.Context, walletID string) (string, error) {
	if walletID == "" {
		return "", fmt.Errorf("walletID must not be empty")
	}
	if existing, ok := m.VirtualAccounts[walletID]; ok {
		return existing, nil
	}
	counter := atomic.AddInt64(&m.counter, 1)
	hash := sha3.Sum256([]byte(walletID))
	iban := fmt.Sprintf("GB%02dMOCK%016X", counter%100, hash[:8])
	m.VirtualAccounts[walletID] = iban
	return iban, nil
}

// GetPaymentStatus returns the current status of a payment reference.
// Returns PaymentStatusPending if the reference is unknown.
func (m *MockPaymentProvider) GetPaymentStatus(ctx context.Context, reference string) (PaymentStatus, error) {
	if status, ok := m.Payments[reference]; ok {
		return status, nil
	}
	return PaymentStatusPending, nil
}

// ConfirmPayment records a payment reference as confirmed.
// In simulation this is called immediately after a PaymentInstruction is issued.
func (m *MockPaymentProvider) ConfirmPayment(ctx context.Context, reference string, amount float64, currency string) error {
	if reference == "" {
		return fmt.Errorf("reference must not be empty")
	}
	if amount <= 0 {
		return fmt.Errorf("amount must be greater than zero")
	}
	m.Payments[reference] = PaymentStatusConfirmed
	return nil
}

// ---------------------------------------------------------------------------
// MockOracleService
// ---------------------------------------------------------------------------

// MockOracleService uses a real Ed25519 key and real signatures but runs locally.
// This is functionally identical to the production oracle — the only difference
// in production is that the key is held in a hardware security module (e.g. AWS KMS)
// rather than in memory.
type MockOracleService struct {
	oracleKey *PrivateKey
	oraclePub *PublicKey
}

// NewMockOracleService generates a fresh Ed25519 key pair for the oracle and
// returns a ready-to-use MockOracleService.
func NewMockOracleService() (*MockOracleService, error) {
	key, err := GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate oracle key: %w", err)
	}
	pub := key.Public()
	return &MockOracleService{
		oracleKey: key,
		oraclePub: pub,
	}, nil
}

// OraclePublicKey returns the oracle's public key for external verification.
func (o *MockOracleService) OraclePublicKey() *PublicKey {
	return o.oraclePub
}

// SignInstruction signs a PaymentInstruction and returns a copy with OracleSignature set.
// The signature covers all fields with OracleSignature=nil.
func (o *MockOracleService) SignInstruction(instruction *PaymentInstruction) (*PaymentInstruction, error) {
	if instruction == nil {
		return nil, fmt.Errorf("instruction must not be nil")
	}
	copy := *instruction
	copy.OracleSignature = nil
	data, err := json.Marshal(copy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal instruction for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	signed := *instruction
	signed.OracleSignature = o.oracleKey.Sign(hash[:]).Bytes()
	return &signed, nil
}

// SignConfirmation signs a PaymentConfirmation and returns a copy with OracleSignature set.
func (o *MockOracleService) SignConfirmation(confirmation *PaymentConfirmation) (*PaymentConfirmation, error) {
	if confirmation == nil {
		return nil, fmt.Errorf("confirmation must not be nil")
	}
	copy := *confirmation
	copy.OracleSignature = nil
	data, err := json.Marshal(copy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal confirmation for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	signed := *confirmation
	signed.OracleSignature = o.oracleKey.Sign(hash[:]).Bytes()
	return &signed, nil
}

// VerifyInstruction checks the oracle signature on a PaymentInstruction.
// Returns false if the instruction has been tampered with or the signature is missing.
func (o *MockOracleService) VerifyInstruction(instruction *PaymentInstruction) bool {
	if instruction == nil || len(instruction.OracleSignature) == 0 {
		return false
	}
	copy := *instruction
	copy.OracleSignature = nil
	data, err := json.Marshal(copy)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: instruction.OracleSignature}
	return sig.Verify(o.oraclePub, hash[:])
}

// VerifyConfirmation checks the oracle signature on a PaymentConfirmation.
// Returns false if the confirmation has been tampered with or the signature is missing.
func (o *MockOracleService) VerifyConfirmation(confirmation *PaymentConfirmation) bool {
	if confirmation == nil || len(confirmation.OracleSignature) == 0 {
		return false
	}
	copy := *confirmation
	copy.OracleSignature = nil
	data, err := json.Marshal(copy)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: confirmation.OracleSignature}
	return sig.Verify(o.oraclePub, hash[:])
}
