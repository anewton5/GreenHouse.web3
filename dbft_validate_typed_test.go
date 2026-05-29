package gonetwork

// ---------------------------------------------------------------------------
// Item 11: ValidateBlock typed-transaction verification tests.
//
// Covers:
//   - AssetTransaction sender signature accepted / rejected
//   - OrderTransaction order signature accepted / rejected
//   - CredentialTransaction registry signature accepted / rejected
//   - DefaultVotingStrategy.Vote rejects invalid OrderTransaction signatures
// ---------------------------------------------------------------------------

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// minimalBC returns a Blockchain with no delegates (single-operator mode) so
// the BFT supermajority check is skipped and we can focus on typed-tx checks.
func minimalBC(t *testing.T) *Blockchain {
	t.Helper()
	return newTestBlockchain(t)
}

// makeSignedAssetTx produces a valid AssetTransaction signed by senderKey.
// receiverKey may be the same key (self-transfer is OK for signature tests).
func makeSignedAssetTx(t *testing.T, senderKey *PrivateKey, receiverKey *PublicKey) AssetTransaction {
	t.Helper()
	at, err := NewAssetTransaction(senderKey, receiverKey, "ASSET-001", 100, AssetTxTypeIssue)
	require.NoError(t, err)
	return *at
}

// makeSignedOrder produces a new Order signed by placerKey.
func makeSignedOrder(t *testing.T, placerKey *PrivateKey) Order {
	t.Helper()
	order, err := NewOrder(placerKey, "ASSET-001", OrderSideBid, 10.0, 5.0, 0)
	require.NoError(t, err)
	return *order
}

// ---------------------------------------------------------------------------
// AssetTransaction signature tests
// ---------------------------------------------------------------------------

func TestValidateBlock_AssetTx_ValidSenderSig_ReturnsTrue(t *testing.T) {
	bc := minimalBC(t)
	senderKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	at := makeSignedAssetTx(t, senderKey, senderKey.Public())
	block := Block{
		PrevHash:          bc.GetLastBlockHash(),
		AssetTransactions: []AssetTransaction{at},
	}

	assert.True(t, bc.ValidateBlock(block))
}

func TestValidateBlock_AssetTx_InvalidSenderSig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	senderKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	at := makeSignedAssetTx(t, senderKey, senderKey.Public())
	// Tamper the signature.
	at.Tx.Signatures[0][0] ^= 0xFF
	block := Block{
		PrevHash:          bc.GetLastBlockHash(),
		AssetTransactions: []AssetTransaction{at},
	}

	assert.False(t, bc.ValidateBlock(block))
}

func TestValidateBlock_AssetTx_RequiredSigsZero_SkipsCheck(t *testing.T) {
	bc := minimalBC(t)
	// RequiredSigs == 0 → internal/genesis entry, no signature required.
	block := Block{
		PrevHash: bc.GetLastBlockHash(),
		AssetTransactions: []AssetTransaction{
			{Tx: Transaction{RequiredSigs: 0}, AssetID: "GENESIS", TxType: AssetTxTypeIssue},
		},
	}
	assert.True(t, bc.ValidateBlock(block))
}

// ---------------------------------------------------------------------------
// OrderTransaction signature tests
// ---------------------------------------------------------------------------

func TestValidateBlock_OrderTx_ValidOrderSig_ReturnsTrue(t *testing.T) {
	bc := minimalBC(t)
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	order := makeSignedOrder(t, placerKey)
	block := Block{
		PrevHash: bc.GetLastBlockHash(),
		OrderTransactions: []OrderTransaction{
			{Order: order, IsCancellation: false},
		},
	}

	assert.True(t, bc.ValidateBlock(block))
}

func TestValidateBlock_OrderTx_InvalidOrderSig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	order := makeSignedOrder(t, placerKey)
	// Tamper the order signature.
	order.Signature[0] ^= 0xFF
	block := Block{
		PrevHash: bc.GetLastBlockHash(),
		OrderTransactions: []OrderTransaction{
			{Order: order, IsCancellation: false},
		},
	}

	assert.False(t, bc.ValidateBlock(block))
}

func TestValidateBlock_OrderTx_Cancellation_SkipsOrderSigCheck(t *testing.T) {
	bc := minimalBC(t)
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	order := makeSignedOrder(t, placerKey)
	// Tamper the order signature — should be ignored for cancellations.
	order.Signature[0] ^= 0xFF
	block := Block{
		PrevHash: bc.GetLastBlockHash(),
		OrderTransactions: []OrderTransaction{
			{Order: order, IsCancellation: true},
		},
	}

	assert.True(t, bc.ValidateBlock(block))
}

// ---------------------------------------------------------------------------
// CredentialTransaction registry-signature tests
// ---------------------------------------------------------------------------

// newCredentialBlock issues a real credential via MockIdentityRegistry, wraps
// it in a Block, and returns both the block and the registry.
// prevHash is set from the caller's blockchain so the chain-linkage check passes.
func newCredentialBlock(t *testing.T, prevHash string) (Block, *MockIdentityRegistry) {
	t.Helper()
	reg, err := NewMockIdentityRegistry()
	require.NoError(t, err)

	att, err := reg.IssueCredential("wallet-alice", InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)

	block := Block{
		PrevHash: prevHash,
		CredentialTransactions: []CredentialTransaction{
			{Attestation: *att},
		},
	}
	return block, reg
}

func TestValidateBlock_CredentialTx_ValidRegistrySig_ReturnsTrue(t *testing.T) {
	bc := minimalBC(t)
	block, reg := newCredentialBlock(t, bc.GetLastBlockHash())
	bc.IdentityRegistry = reg

	assert.True(t, bc.ValidateBlock(block))
}

func TestValidateBlock_CredentialTx_InvalidRegistrySig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	block, reg := newCredentialBlock(t, bc.GetLastBlockHash())
	bc.IdentityRegistry = reg

	// Tamper the registry signature on the embedded attestation.
	block.CredentialTransactions[0].Attestation.RegistrySignature[0] ^= 0xFF

	assert.False(t, bc.ValidateBlock(block))
}

func TestValidateBlock_CredentialTx_NoRegistrySignature_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	reg, err := NewMockIdentityRegistry()
	require.NoError(t, err)
	bc.IdentityRegistry = reg

	// Build an attestation with no RegistrySignature.
	att := CredentialAttestation{
		WalletPublicKey: "wallet-alice",
		CredentialHash:  "aabbcc",
		InvestorClass:   InvestorClassProfessional,
		KYCStatus:       KYCStatusVerified,
		Jurisdiction:    "GB",
	}
	block := Block{
		PrevHash:               bc.GetLastBlockHash(),
		CredentialTransactions: []CredentialTransaction{{Attestation: att}},
	}

	assert.False(t, bc.ValidateBlock(block))
}

func TestValidateBlock_CredentialTx_NoRegistry_Skipped(t *testing.T) {
	// bc.IdentityRegistry == nil → registry-signature check is skipped.
	bc := minimalBC(t)
	bc.IdentityRegistry = nil

	att := CredentialAttestation{
		WalletPublicKey:   "wallet-alice",
		CredentialHash:    "aabbcc",
		RegistrySignature: []byte("definitely-invalid"),
	}
	block := Block{
		PrevHash:               bc.GetLastBlockHash(),
		CredentialTransactions: []CredentialTransaction{{Attestation: att}},
	}

	assert.True(t, bc.ValidateBlock(block))
}

// ---------------------------------------------------------------------------
// DefaultVotingStrategy.Vote — OrderTransaction tests
// ---------------------------------------------------------------------------

func TestDefaultVotingStrategy_Vote_ValidOrderTx_ReturnsTrue(t *testing.T) {
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	order := makeSignedOrder(t, placerKey)
	block := Block{
		OrderTransactions: []OrderTransaction{
			{Order: order, IsCancellation: false},
		},
	}

	d := &DefaultVotingStrategy{}
	assert.True(t, d.Vote(block))
}

func TestDefaultVotingStrategy_Vote_InvalidOrderSig_ReturnsFalse(t *testing.T) {
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	order := makeSignedOrder(t, placerKey)
	order.Signature[0] ^= 0xFF
	block := Block{
		OrderTransactions: []OrderTransaction{
			{Order: order, IsCancellation: false},
		},
	}

	d := &DefaultVotingStrategy{}
	assert.False(t, d.Vote(block))
}

func TestDefaultVotingStrategy_Vote_CancellationWithTamperedSig_ReturnsTrue(t *testing.T) {
	// Cancellations skip the Order signature check in Vote.
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	order := makeSignedOrder(t, placerKey)
	order.Signature[0] ^= 0xFF
	block := Block{
		OrderTransactions: []OrderTransaction{
			{Order: order, IsCancellation: true},
		},
	}

	d := &DefaultVotingStrategy{}
	assert.True(t, d.Vote(block))
}

// ---------------------------------------------------------------------------
// AssetTransaction wrong-key test (singer != Tx.Sender)
// ---------------------------------------------------------------------------

func TestValidateBlock_AssetTx_WrongKey_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	senderKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	otherKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	at := makeSignedAssetTx(t, senderKey, senderKey.Public())
	// Replace Tx.Sender with a different (wrong) key so the embedded sig won't verify.
	at.Tx.Sender = base64.StdEncoding.EncodeToString(otherKey.Public().Bytes())
	block := Block{
		PrevHash:          bc.GetLastBlockHash(),
		AssetTransactions: []AssetTransaction{at},
	}

	assert.False(t, bc.ValidateBlock(block))
}
