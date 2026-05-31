package gonetwork

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveConsensusMode_RequiresExplicitModeOutsideTests(t *testing.T) {
	t.Setenv("GONETWORK_ALLOW_TEST_CONSENSUS_HYBRID", "")
	_, err := resolveConsensusMode("", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GREENHOUSE_CONSENSUS_MODE")
}

func TestResolveConsensusMode_TestOverride_AllowsHybrid(t *testing.T) {
	t.Setenv("GONETWORK_ALLOW_TEST_CONSENSUS_HYBRID", "1")
	mode, err := resolveConsensusMode("", false)
	require.NoError(t, err)
	assert.Equal(t, consensusModeHybrid, mode)
}

func TestResolveConsensusMode_ProductionRequiresExplicitMode(t *testing.T) {
	t.Setenv("GONETWORK_ALLOW_TEST_CONSENSUS_HYBRID", "1")
	_, err := resolveConsensusMode("", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GREENHOUSE_CONSENSUS_MODE")
}

func TestResolveConsensusMode_HybridRejectedWithoutTestOverride(t *testing.T) {
	t.Setenv("GONETWORK_ALLOW_TEST_CONSENSUS_HYBRID", "")
	_, err := resolveConsensusMode(consensusModeHybrid, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only allowed in unit tests")
}

func TestResolveConsensusMode_RejectsInvalidMode(t *testing.T) {
	_, err := resolveConsensusMode("invalid", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid GREENHOUSE_CONSENSUS_MODE")
}

func TestSealBlock_DBFTMode_DoesNotAppendBlock(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.ConsensusMode = ConsensusModeDBFT

	before := len(bc.Blocks)
	bc.SealBlock(nil, nil, nil)
	assert.Equal(t, before, len(bc.Blocks))
	assert.Equal(t, uint64(1), bc.ConsensusModeRejectCount())
	assert.Equal(t, uint64(1), bc.ConsensusModeRejectByPathSnapshot()["SealBlock"])
}

func TestStartConsensus_HTTPMode_ReturnsEarly(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.ConsensusMode = ConsensusModeHTTP
	bc.currentView = View{Number: 7}

	// startConsensus should return before touching consensus state in HTTP mode.
	bc.startConsensus(nil)
	assert.Equal(t, 7, bc.currentView.Number)
	assert.Equal(t, uint64(1), bc.ConsensusModeRejectCount())
	assert.Equal(t, uint64(1), bc.ConsensusModeRejectByPathSnapshot()["startConsensus"])
}

func TestCreateBlock_HTTPMode_ReturnsEarlyAndCountsReject(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.ConsensusMode = ConsensusModeHTTP

	bc.createBlock(nil)
	assert.Equal(t, uint64(1), bc.ConsensusModeRejectCount())
	assert.Equal(t, uint64(1), bc.ConsensusModeRejectByPathSnapshot()["createBlock"])
}

func TestFinalizeBlock_AppendsOperatorSignature(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.ConsensusMode = ConsensusModeDBFT

	operatorKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bc.OperatorKeyProvider = NewLocalKeyProvider(operatorKey)

	alwaysYes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}
	d1 := makeDelegateWithKey(t, "d1", bc, alwaysYes)
	d2 := makeDelegateWithKey(t, "d2", bc, alwaysYes)
	d3 := makeDelegateWithKey(t, "d3", bc, alwaysYes)
	bc.Delegates = []Node{d1, d2, d3}

	tx := Transaction{Sender: "sender1", Receiver: "receiver1", Amount: 1, RequiredSigs: 0, Nonce: 1}
	b := Block{Transactions: []Transaction{tx}}
	b.Index = len(bc.Blocks)
	b.Nonce = bc.Nonce
	b.PrevHash = bc.GetLastBlockHash()
	b.SealedAt = 1
	b.SetPayloadHash()

	require.True(t, bc.AchieveConsensus(b))
	require.Len(t, bc.Blocks, 2)
	finalized := bc.Blocks[1]

	payloadHashBytes, err := hex.DecodeString(finalized.PayloadHash)
	require.NoError(t, err)

	hasOperatorSig := false
	for _, sig := range finalized.Signatures {
		if ed25519.Verify(operatorKey.Public().key, payloadHashBytes, sig) {
			hasOperatorSig = true
			break
		}
	}
	assert.True(t, hasOperatorSig, "finalized block should include an operator signature")
}

func TestValidateBlock_RejectsAlreadyCommittedTransactionHash(t *testing.T) {
	bc := newTestBlockchain(t)

	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	sender := base64.StdEncoding.EncodeToString(key.Public().Bytes())

	tx := Transaction{Sender: sender, Receiver: "recv", Amount: 10, RequiredSigs: 0, Nonce: 1}
	bc.AddBlock(Block{Transactions: []Transaction{tx}})

	candidate := Block{
		Transactions: []Transaction{tx},
		PrevHash:     bc.GetLastBlockHash(),
	}

	assert.False(t, bc.ValidateBlock(candidate), "replayed committed transaction hash must be rejected")
	assert.Equal(t, uint64(1), bc.DuplicateTxHashRejectCount())
	assert.Equal(t, uint64(1), bc.DuplicateTxRejectByReasonSnapshot()["already_committed"])
}

func TestRebuildCommittedTxHashes_RehydratesFromBlocks(t *testing.T) {
	bc := newTestBlockchain(t)
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	sender := base64.StdEncoding.EncodeToString(key.Public().Bytes())

	tx := Transaction{Sender: sender, Receiver: "recv", Amount: 5, RequiredSigs: 0, Nonce: 99}
	bc.AddBlock(Block{Transactions: []Transaction{tx}})

	bc.CommittedTxHashes = nil
	bc.rebuildCommittedTxHashes()

	_, exists := bc.CommittedTxHashes[transactionHashKey(tx)]
	assert.True(t, exists)
}

func TestStartupInvariant_RejectsConflictingServiceFlags(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.ConsensusMode = ConsensusModeHTTP
	t.Setenv("GREENHOUSE_ENABLE_HTTP_SEAL", "true")
	t.Setenv("GREENHOUSE_ENABLE_DBFT_CONSENSUS", "true")

	err := bc.enforceConsensusStartupInvariant()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicting services enabled")
}

func TestStartupInvariant_EmitsModeEventOnSuccess(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.ConsensusMode = ConsensusModeDBFT
	t.Setenv("GREENHOUSE_ENABLE_HTTP_SEAL", "false")
	t.Setenv("GREENHOUSE_ENABLE_DBFT_CONSENSUS", "true")

	require.NoError(t, bc.enforceConsensusStartupInvariant())

	select {
	case ev := <-bc.Events:
		assert.Equal(t, EventConsensusModeInvariant, ev.Type)
	default:
		t.Fatal("expected consensus mode invariant event")
	}
}
