package gonetwork

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestOperatorRegistry(t *testing.T) *OperatorIdentityRegistry {
	t.Helper()
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	reg, err := NewOperatorIdentityRegistry(key)
	require.NoError(t, err)
	return reg
}

// TestOperatorRegistry_ImplementsInterface is a compile-time assertion that
// *OperatorIdentityRegistry satisfies the IdentityRegistry interface.
func TestOperatorRegistry_ImplementsInterface(t *testing.T) {
	reg := newTestOperatorRegistry(t)
	var _ IdentityRegistry = reg
}

// TestOperatorRegistry_NilRegistryKey verifies that construction fails when
// no registry key is provided.
func TestOperatorRegistry_NilRegistryKey(t *testing.T) {
	_, err := NewOperatorIdentityRegistry(nil)
	assert.Error(t, err)
}

// TestOperatorRegistry_RequestKYC checks that a submitted request appears in
// the pending queue.
func TestOperatorRegistry_RequestKYC(t *testing.T) {
	reg := newTestOperatorRegistry(t)

	err := reg.RequestKYC("wallet-abc", InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)
	assert.Equal(t, 1, reg.PendingCount())
}

// TestOperatorRegistry_ApproveKYC verifies the full request→approve flow:
// the pending queue empties and a valid credential is issued.
func TestOperatorRegistry_ApproveKYC(t *testing.T) {
	reg := newTestOperatorRegistry(t)
	require.NoError(t, reg.RequestKYC("wallet-abc", InvestorClassProfessional, "GB", 365))

	att, err := reg.ApproveKYC("wallet-abc")
	require.NoError(t, err)
	assert.NotNil(t, att)
	assert.Equal(t, KYCStatusVerified, att.KYCStatus)
	assert.Equal(t, InvestorClassProfessional, att.InvestorClass)
	assert.Equal(t, "GB", att.Jurisdiction)
	assert.Equal(t, 0, reg.PendingCount(), "pending queue should be empty after approval")
}

// TestOperatorRegistry_ApproveKYC_NoPending verifies that approving a wallet
// with no pending request returns an error.
func TestOperatorRegistry_ApproveKYC_NoPending(t *testing.T) {
	reg := newTestOperatorRegistry(t)
	_, err := reg.ApproveKYC("wallet-unknown")
	assert.Error(t, err, "approving a non-existent request should fail")
}

// TestOperatorRegistry_IssueCredential_DirectIssuance verifies that an operator
// can issue a credential directly without a prior RequestKYC.
func TestOperatorRegistry_IssueCredential_DirectIssuance(t *testing.T) {
	reg := newTestOperatorRegistry(t)

	att, err := reg.IssueCredential("wallet-direct", InvestorClassRetail, "DE", 180)
	require.NoError(t, err)
	assert.Equal(t, KYCStatusVerified, att.KYCStatus)
	assert.Equal(t, InvestorClassRetail, att.InvestorClass)
}

// TestOperatorRegistry_VerifyCredential checks that a credential issued via
// ApproveKYC can be retrieved and is valid.
func TestOperatorRegistry_VerifyCredential(t *testing.T) {
	reg := newTestOperatorRegistry(t)
	require.NoError(t, reg.RequestKYC("wallet-xyz", InvestorClassAccredited, "US", 365))
	_, err := reg.ApproveKYC("wallet-xyz")
	require.NoError(t, err)

	att, err := reg.VerifyCredential("wallet-xyz")
	require.NoError(t, err)
	assert.True(t, att.IsValid())
	assert.True(t, att.IsAccredited())
}

// TestOperatorRegistry_VerifyCredential_Unknown verifies that looking up a
// wallet with no credential returns an error.
func TestOperatorRegistry_VerifyCredential_Unknown(t *testing.T) {
	reg := newTestOperatorRegistry(t)
	_, err := reg.VerifyCredential("wallet-none")
	assert.Error(t, err, "unknown wallet should return an error")
}

// TestOperatorRegistry_ListPendingRequests checks that multiple requests all
// appear in the pending list.
func TestOperatorRegistry_ListPendingRequests(t *testing.T) {
	reg := newTestOperatorRegistry(t)
	require.NoError(t, reg.RequestKYC("wallet-1", InvestorClassRetail, "GB", 365))
	require.NoError(t, reg.RequestKYC("wallet-2", InvestorClassProfessional, "DE", 365))

	pending := reg.ListPendingRequests()
	assert.Len(t, pending, 2)
}

// TestOperatorRegistry_DuplicateRequest_Overwrites verifies that a second
// RequestKYC for the same wallet replaces the first entry rather than
// creating a duplicate.
func TestOperatorRegistry_DuplicateRequest_Overwrites(t *testing.T) {
	reg := newTestOperatorRegistry(t)
	require.NoError(t, reg.RequestKYC("wallet-dup", InvestorClassRetail, "GB", 365))
	require.NoError(t, reg.RequestKYC("wallet-dup", InvestorClassProfessional, "DE", 730))

	pending := reg.ListPendingRequests()
	require.Len(t, pending, 1, "duplicate should overwrite, not append")
	assert.Equal(t, InvestorClassProfessional, pending[0].Class)
	assert.Equal(t, "DE", pending[0].Jurisdiction)
	assert.Equal(t, 730, pending[0].ValidForDays)
}

// TestOperatorRegistry_RequestKYC_InvalidInputs checks that malformed requests
// are rejected before entering the queue.
func TestOperatorRegistry_RequestKYC_InvalidInputs(t *testing.T) {
	reg := newTestOperatorRegistry(t)

	assert.Error(t, reg.RequestKYC("", InvestorClassRetail, "GB", 365), "empty wallet key")
	assert.Error(t, reg.RequestKYC("wallet", InvestorClassRetail, "", 365), "empty jurisdiction")
	assert.Error(t, reg.RequestKYC("wallet", InvestorClassRetail, "GB", 0), "zero validForDays")
	assert.Error(t, reg.RequestKYC("wallet", InvestorClassRetail, "GB", -1), "negative validForDays")
	assert.Equal(t, 0, reg.PendingCount(), "no invalid requests should be queued")
}
