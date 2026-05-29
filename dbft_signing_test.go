package gonetwork

// ---------------------------------------------------------------------------
// dbft_signing_test.go — Item 8: dBFT real Ed25519 delegate block signing
//
// Covers:
//   Step A — createBlock pre-computes PayloadHash; AchieveConsensus collects
//             real Ed25519 signatures from delegates that voted yes.
//   Step B — DefaultVotingStrategy.Vote rejects AssetTransactions with an
//             invalid sender signature.
//   Step C — ValidateBlock rejects a block whose delegate signatures have been
//             tampered with.
// ---------------------------------------------------------------------------

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeDelegateWithKey returns a delegate Node backed by a freshly-generated
// Ed25519 key pair. The Node.PrivateKey / PublicKey fields are the raw
// ed25519 types used by AchieveConsensus and ValidateBlock.
func makeDelegateWithKey(t *testing.T, id string, bc *Blockchain, strategy VotingStrategy) Node {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	n := Node{
		ID:             id,
		IsDelegate:     true,
		PrivateKey:     priv,
		PublicKey:      pub,
		Inbox:          make(chan Message, 1000),
		VotingStrategy: strategy,
		Blockchain:     bc,
	}
	return n
}

// ---------------------------------------------------------------------------
// Step A: AchieveConsensus collects real Ed25519 signatures
// ---------------------------------------------------------------------------

// TestAchieveConsensus_WithKeyedDelegates_SignaturesVerifiable verifies that
// when delegates hold real Ed25519 keys and vote yes, the finalised block
// carries signatures that are verifiable against the delegate public keys.
func TestAchieveConsensus_WithKeyedDelegates_SignaturesVerifiable(t *testing.T) {
	bc := newTestBlockchain(t)

	alwaysYes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}
	d1 := makeDelegateWithKey(t, "d1", bc, alwaysYes)
	d2 := makeDelegateWithKey(t, "d2", bc, alwaysYes)
	d3 := makeDelegateWithKey(t, "d3", bc, alwaysYes)
	bc.Delegates = []Node{d1, d2, d3}

	b := blockWithSignedTx(t)
	// Pre-compute the chain-linking fields so PayloadHash is stable before
	// delegates sign (mirrors what createBlock does).
	b.Index = len(bc.Blocks)
	b.Nonce = bc.Nonce
	b.PrevHash = bc.GetLastBlockHash()
	b.SetPayloadHash()
	require.NotEmpty(t, b.PayloadHash)

	ok := bc.AchieveConsensus(b)
	require.True(t, ok, "supermajority of keyed delegates should reach consensus")

	// The finalised block is the last in the chain (genesis + 1).
	require.Len(t, bc.Blocks, 2)
	finalised := bc.Blocks[1]

	// Block must carry at least ⌈2×3/3⌉ = 2 signatures.
	require.GreaterOrEqual(t, len(finalised.Signatures), 2,
		"finalized block should carry delegate signatures")

	// Every signature must verify against one of the delegate public keys.
	payloadHashBytes, err := hex.DecodeString(finalised.PayloadHash)
	require.NoError(t, err)

	delegates := []Node{d1, d2, d3}
	for _, sig := range finalised.Signatures {
		verified := false
		for _, d := range delegates {
			if ed25519.Verify(d.PublicKey, payloadHashBytes, sig) {
				verified = true
				break
			}
		}
		assert.True(t, verified, "signature %x could not be verified against any delegate key", sig)
	}
}

// TestAchieveConsensus_DelegatesWithoutKeys_NoSignatures checks that the
// existing behaviour is preserved: delegates that have no PrivateKey produce
// a block with an empty Signatures slice (no panic, no invalid sigs).
func TestAchieveConsensus_DelegatesWithoutKeys_NoSignatures(t *testing.T) {
	bc := newTestBlockchain(t)

	alwaysYes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}
	bc.Delegates = []Node{
		makeDelegate("d1", bc, alwaysYes),
		makeDelegate("d2", bc, alwaysYes),
		makeDelegate("d3", bc, alwaysYes),
	}

	b := blockWithSignedTx(t)
	ok := bc.AchieveConsensus(b)
	require.True(t, ok)

	finalised := bc.Blocks[len(bc.Blocks)-1]
	assert.Empty(t, finalised.Signatures,
		"delegates without private keys should produce no signatures")
}

// ---------------------------------------------------------------------------
// Step A (integration): createBlock sets PayloadHash before delegates sign
// ---------------------------------------------------------------------------

// TestCreateBlock_SignaturesMatchPayloadHash verifies the end-to-end flow of
// createBlock → AchieveConsensus → finalizeBlock:
//  1. The block's PayloadHash survives through finalization unchanged.
//  2. The collected delegate signatures verify against the finalized hash.
func TestCreateBlock_SignaturesMatchPayloadHash(t *testing.T) {
	bc := newTestBlockchain(t)

	alwaysYes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}
	d1 := makeDelegateWithKey(t, "d1", bc, alwaysYes)
	d2 := makeDelegateWithKey(t, "d2", bc, alwaysYes)
	d3 := makeDelegateWithKey(t, "d3", bc, alwaysYes)
	bc.Delegates = []Node{d1, d2, d3}

	// Seed the shard pool (createBlock reads from Shards).
	bc.InitializeShards(1)
	bc.Shards[0].TransactionPool = []Transaction{
		{Sender: "sender1", Receiver: "receiver1", Amount: 10, RequiredSigs: 0},
	}

	bc.createBlock(nil /* P2PNode — not needed for this in-process test */)

	// Genesis + the newly created block.
	require.Len(t, bc.Blocks, 2, "createBlock should have appended one block")
	finalised := bc.Blocks[1]

	require.NotEmpty(t, finalised.PayloadHash)
	require.NotEmpty(t, finalised.Signatures,
		"createBlock with keyed delegates should produce non-empty Signatures")

	payloadHashBytes, err := hex.DecodeString(finalised.PayloadHash)
	require.NoError(t, err)

	delegates := []Node{d1, d2, d3}
	for _, sig := range finalised.Signatures {
		verified := false
		for _, d := range delegates {
			if ed25519.Verify(d.PublicKey, payloadHashBytes, sig) {
				verified = true
				break
			}
		}
		assert.True(t, verified, "signature %x should verify against a delegate key", sig)
	}
}

// makeSenderSignedTx returns a Transaction signed by key with RequiredSigs=1.
func makeSenderSignedTx(t *testing.T, key *PrivateKey) Transaction {
	t.Helper()
	senderPub := base64.StdEncoding.EncodeToString(key.Public().Bytes())
	tx := Transaction{
		Sender:       senderPub,
		Receiver:     "recv",
		Amount:       10,
		RequiredSigs: 1,
	}
	tx.GenerateNonce()
	require.NoError(t, tx.SignTransaction(key))
	return tx
}

// ---------------------------------------------------------------------------
// Step B: DefaultVotingStrategy.Vote rejects invalid AssetTx sender sigs
// ---------------------------------------------------------------------------

// TestDefaultVotingStrategy_AssetTxInvalidSenderSig_ReturnsFalse verifies that
// a block containing an AssetTransaction with RequiredSigs > 0 but an invalid
// sender signature is rejected by the DefaultVotingStrategy.
func TestDefaultVotingStrategy_AssetTxInvalidSenderSig_ReturnsFalse(t *testing.T) {
	s := &DefaultVotingStrategy{}

	// Build an AssetTransaction whose embedded Tx is signed by one key but
	// whose Sender field is a DIFFERENT key → signature verification must fail.
	senderKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	wrongKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	tx := Transaction{
		Sender:       base64.StdEncoding.EncodeToString(wrongKey.Public().Bytes()), // mismatched sender public key
		Receiver:     "recv",
		Amount:       5,
		RequiredSigs: 1,
	}
	tx.GenerateNonce()
	require.NoError(t, tx.SignTransaction(senderKey)) // signed by senderKey, not wrongKey

	b := Block{AssetTransactions: []AssetTransaction{{Tx: tx, AssetID: "asset-1"}}}
	assert.False(t, s.Vote(b),
		"DefaultVotingStrategy should reject block with invalid AssetTx sender signature")
}

// TestDefaultVotingStrategy_AssetTxValidSenderSig_ReturnsTrue verifies that a
// properly signed AssetTransaction is accepted.
func TestDefaultVotingStrategy_AssetTxValidSenderSig_ReturnsTrue(t *testing.T) {
	s := &DefaultVotingStrategy{}

	senderKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	tx := Transaction{
		Sender:       base64.StdEncoding.EncodeToString(senderKey.Public().Bytes()),
		Receiver:     "recv",
		Amount:       5,
		RequiredSigs: 1,
	}
	tx.GenerateNonce()
	require.NoError(t, tx.SignTransaction(senderKey))

	b := Block{AssetTransactions: []AssetTransaction{{Tx: tx, AssetID: "asset-1"}}}
	assert.True(t, s.Vote(b),
		"DefaultVotingStrategy should accept block with valid AssetTx sender signature")
}

// TestDefaultVotingStrategy_AssetTxRequiredSigsZero_Skipped verifies that
// AssetTransactions with RequiredSigs == 0 are not signature-checked (existing
// behaviour preserved for internal / genesis issuance transactions).
func TestDefaultVotingStrategy_AssetTxRequiredSigsZero_Skipped(t *testing.T) {
	s := &DefaultVotingStrategy{}
	// No Sender / Signatures — would fail if checked, but RequiredSigs == 0.
	b := Block{AssetTransactions: []AssetTransaction{{AssetID: "asset-1"}}}
	assert.True(t, s.Vote(b))
}

// ---------------------------------------------------------------------------
// Step C: ValidateBlock rejects tampered delegate signatures
// ---------------------------------------------------------------------------

// signBlockWithDelegates signs block.PayloadHash with each delegate's
// private key and appends the signatures to block.Signatures.
func signBlockWithDelegates(t *testing.T, b *Block, delegates []Node) {
	t.Helper()
	payloadHashBytes, err := hex.DecodeString(b.PayloadHash)
	require.NoError(t, err)
	for _, d := range delegates {
		if len(d.PrivateKey) > 0 {
			b.Signatures = append(b.Signatures, ed25519.Sign(d.PrivateKey, payloadHashBytes))
		}
	}
}

// TestValidateBlock_TamperedDelegateSig_ReturnsFalse verifies that altering
// any byte of a delegate signature invalidates the block.
func TestValidateBlock_TamperedDelegateSig_ReturnsFalse(t *testing.T) {
	bc := newTestBlockchain(t)

	alwaysYes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}
	d1 := makeDelegateWithKey(t, "d1", bc, alwaysYes)
	d2 := makeDelegateWithKey(t, "d2", bc, alwaysYes)
	d3 := makeDelegateWithKey(t, "d3", bc, alwaysYes)
	bc.Delegates = []Node{d1, d2, d3}

	b := blockWithSignedTx(t)
	b.Index = len(bc.Blocks)
	b.Nonce = bc.Nonce
	b.PrevHash = bc.GetLastBlockHash()
	b.SetPayloadHash()
	signBlockWithDelegates(t, &b, []Node{d1, d2, d3})
	require.NotEmpty(t, b.Signatures, "need signatures to tamper")

	// Tamper every signature so zero verify — dropping below the ⌈2n/3⌉ threshold.
	for i := range b.Signatures {
		tampered := make([]byte, len(b.Signatures[i]))
		copy(tampered, b.Signatures[i])
		tampered[0] ^= 0xFF
		b.Signatures[i] = tampered
	}

	assert.False(t, bc.ValidateBlock(b),
		"ValidateBlock must reject a block with a tampered delegate signature")
}

// TestValidateBlock_ValidDelegateSigs_ReturnsTrue checks that a block with
// valid Ed25519 delegate signatures passes ValidateBlock.
func TestValidateBlock_ValidDelegateSigs_ReturnsTrue(t *testing.T) {
	bc := newTestBlockchain(t)

	alwaysYes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}
	d1 := makeDelegateWithKey(t, "d1", bc, alwaysYes)
	d2 := makeDelegateWithKey(t, "d2", bc, alwaysYes)
	d3 := makeDelegateWithKey(t, "d3", bc, alwaysYes)
	bc.Delegates = []Node{d1, d2, d3}

	b := blockWithSignedTx(t)
	b.Index = len(bc.Blocks)
	b.Nonce = bc.Nonce
	b.PrevHash = bc.GetLastBlockHash()
	b.SetPayloadHash()
	signBlockWithDelegates(t, &b, []Node{d1, d2, d3})

	assert.True(t, bc.ValidateBlock(b),
		"ValidateBlock must accept a block with valid Ed25519 delegate signatures")
}
