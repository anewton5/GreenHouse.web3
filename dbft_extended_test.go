package gonetwork

// ---------------------------------------------------------------------------
// dbft_extended_test.go — dBFT consensus engine (Node, voting, consensus)
//
// Covers:
//   DefaultVotingStrategy.Vote     — empty block rejects, tx block accepts,
//                                    RequiredSigs==0 skips sig verification
//   AchieveConsensus               — no delegates, supermajority, Byzantine
//                                    failure (>1/3 traitors), timeout
//   Node.SyncBlockchain            — node copies peer blockchain
//   Node.HandleFork                — longer chain replaces shorter
//   Node.ProcessMessages           — Transaction message calls AddTransaction
//   NewNode                        — constructs node with inbox channel
//   FuncVotingStrategy.Vote        — custom strategy invoked
// ---------------------------------------------------------------------------

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// makeNode creates a Node wired to a Blockchain.
func makeNode(t *testing.T, id string, bc *Blockchain) *Node {
	t.Helper()
	return NewNode(id, bc)
}

// makeDelegate builds a delegate Node with a given VotingStrategy.
func makeDelegate(id string, bc *Blockchain, strategy VotingStrategy) Node {
	n := Node{
		ID:             id,
		IsDelegate:     true,
		Inbox:          make(chan Message, 10),
		VotingStrategy: strategy,
		Blockchain:     bc,
	}
	return n
}

// blockWithSignedTx returns a Block with one properly-signed transaction.
func blockWithSignedTx(t *testing.T) Block {
	t.Helper()
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	senderPub := base64.StdEncoding.EncodeToString(key.Public().Bytes())

	tx := Transaction{
		Sender:       senderPub,
		Receiver:     "recv",
		Amount:       10,
		RequiredSigs: 1,
	}
	tx.GenerateNonce()
	require.NoError(t, tx.SignTransaction(key))

	b := Block{Transactions: []Transaction{tx}}
	b.SetPayloadHash()
	return b
}

// ---------------------------------------------------------------------------
// DefaultVotingStrategy.Vote
// ---------------------------------------------------------------------------

func TestDefaultVotingStrategy_EmptyBlock_ReturnsFalse(t *testing.T) {
	s := &DefaultVotingStrategy{}
	assert.False(t, s.Vote(Block{}))
}

func TestDefaultVotingStrategy_BlockWithAssetTx_ReturnsTrue(t *testing.T) {
	s := &DefaultVotingStrategy{}
	b := Block{AssetTransactions: []AssetTransaction{{AssetID: "asset-1"}}}
	assert.True(t, s.Vote(b))
}

func TestDefaultVotingStrategy_BlockWithOrderTx_ReturnsTrue(t *testing.T) {
	s := &DefaultVotingStrategy{}
	// Item 11: Vote now verifies Order.PlacedBy signature; use a properly signed order.
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	order, err := NewOrder(placerKey, "asset-1", OrderSideBid, 10.0, 5.0, 0)
	require.NoError(t, err)
	b := Block{OrderTransactions: []OrderTransaction{{Order: *order}}}
	assert.True(t, s.Vote(b))
}

func TestDefaultVotingStrategy_SignedBaseTx_ReturnsTrue(t *testing.T) {
	s := &DefaultVotingStrategy{}
	b := blockWithSignedTx(t)
	assert.True(t, s.Vote(b))
}

func TestDefaultVotingStrategy_TxWithRequiredSigsZero_SkipsSigCheck(t *testing.T) {
	// RequiredSigs == 0 must not fail even though Sender is not a valid public key.
	s := &DefaultVotingStrategy{}
	b := Block{
		Transactions: []Transaction{
			{Sender: "not-a-pubkey", Receiver: "B", Amount: 1, RequiredSigs: 0},
		},
	}
	assert.True(t, s.Vote(b))
}

func TestDefaultVotingStrategy_InvalidSenderKey_ReturnsFalse(t *testing.T) {
	s := &DefaultVotingStrategy{}
	b := Block{
		Transactions: []Transaction{
			{Sender: "not-a-valid-key", Receiver: "B", Amount: 1, RequiredSigs: 1},
		},
	}
	assert.False(t, s.Vote(b))
}

// ---------------------------------------------------------------------------
// FuncVotingStrategy
// ---------------------------------------------------------------------------

func TestFuncVotingStrategy_InvokesFunc(t *testing.T) {
	called := false
	s := &FuncVotingStrategy{VoteFunc: func(block Block) bool {
		called = true
		return true
	}}
	result := s.Vote(Block{})
	assert.True(t, called)
	assert.True(t, result)
}

// ---------------------------------------------------------------------------
// Node.VoteOnBlock
// ---------------------------------------------------------------------------

func TestNode_VoteOnBlock_NilStrategy_DefaultsTrue(t *testing.T) {
	bc := newTestBlockchain(t)
	n := makeNode(t, "node-1", bc)
	// No VotingStrategy set — defaults to true
	assert.True(t, n.VoteOnBlock(Block{}))
}

func TestNode_VoteOnBlock_WithStrategy(t *testing.T) {
	bc := newTestBlockchain(t)
	n := makeNode(t, "node-1", bc)
	n.VotingStrategy = &FuncVotingStrategy{VoteFunc: func(b Block) bool { return false }}
	assert.False(t, n.VoteOnBlock(Block{}))
}

// ---------------------------------------------------------------------------
// AchieveConsensus
// ---------------------------------------------------------------------------

func TestAchieveConsensus_NoDelegates_ReturnsFalse(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Delegates = nil
	assert.False(t, bc.AchieveConsensus(Block{}))
}

func TestAchieveConsensus_SupermajorityApproves_ReturnsTrue(t *testing.T) {
	bc := newTestBlockchain(t)

	b := blockWithSignedTx(t)

	// 3 delegates all vote yes (strategy: true)
	alwaysYes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}
	bc.Delegates = []Node{
		makeDelegate("d1", bc, alwaysYes),
		makeDelegate("d2", bc, alwaysYes),
		makeDelegate("d3", bc, alwaysYes),
	}

	ok := bc.AchieveConsensus(b)
	assert.True(t, ok)
}

func TestAchieveConsensus_ByzantineOneThird_StillReachesConsensus(t *testing.T) {
	// 4 delegates: 3 yes, 1 no → threshold = ceil(8/3) = 3 → passes
	bc := newTestBlockchain(t)
	b := blockWithSignedTx(t)

	yes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}
	no := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return false }}

	bc.Delegates = []Node{
		makeDelegate("d1", bc, yes),
		makeDelegate("d2", bc, yes),
		makeDelegate("d3", bc, yes),
		makeDelegate("d4", bc, no),
	}

	ok := bc.AchieveConsensus(b)
	assert.True(t, ok)
}

func TestAchieveConsensus_ByzantineOverOneThird_FailsConsensus(t *testing.T) {
	// 3 delegates: 1 yes, 2 no → threshold = ceil(6/3) = 2 → fails
	bc := newTestBlockchain(t)
	b := blockWithSignedTx(t)

	yes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}
	no := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return false }}

	bc.Delegates = []Node{
		makeDelegate("d1", bc, yes),
		makeDelegate("d2", bc, no),
		makeDelegate("d3", bc, no),
	}

	ok := bc.AchieveConsensus(b)
	assert.False(t, ok)
}

func TestAchieveConsensus_Timeout_ReturnsFalse(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.ConsensusTimeout = 50 * time.Millisecond // Very short timeout

	b := blockWithSignedTx(t)

	// Delegates that vote very slowly (simulate delay)
	slow := &FuncVotingStrategy{VoteFunc: func(_ Block) bool {
		time.Sleep(500 * time.Millisecond)
		return true
	}}
	bc.Delegates = []Node{
		makeDelegate("d1", bc, slow),
		makeDelegate("d2", bc, slow),
		makeDelegate("d3", bc, slow),
	}

	ok := bc.AchieveConsensus(b)
	assert.False(t, ok, "timeout must force false result")
}

func TestAchieveConsensus_ZeroTimeout_NoDeadline(t *testing.T) {
	// ConsensusTimeout == 0 means no deadline — consensus should succeed normally
	bc := newTestBlockchain(t)
	bc.ConsensusTimeout = 0

	b := blockWithSignedTx(t)
	yes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}
	bc.Delegates = []Node{
		makeDelegate("d1", bc, yes),
		makeDelegate("d2", bc, yes),
		makeDelegate("d3", bc, yes),
	}

	ok := bc.AchieveConsensus(b)
	assert.True(t, ok)
}

// ---------------------------------------------------------------------------
// Node.SyncBlockchain
// ---------------------------------------------------------------------------

func TestNode_SyncBlockchain_CopiesPeerChain(t *testing.T) {
	bc1 := newTestBlockchain(t)
	bc2 := newTestBlockchain(t)

	// Add extra blocks to bc2
	bc2.AddBlock(Block{Transactions: []Transaction{{Sender: "A", Receiver: "B", Amount: 1}}})
	bc2.AddBlock(Block{Transactions: []Transaction{{Sender: "C", Receiver: "D", Amount: 2}}})

	n1 := makeNode(t, "n1", bc1)
	n2 := makeNode(t, "n2", bc2)

	n1.SyncBlockchain(n2)

	// After sync, n1 should reference bc2's blockchain
	assert.Equal(t, bc2, n1.Blockchain)
	assert.Equal(t, len(bc2.Blocks), len(n1.Blockchain.Blocks))
}

// ---------------------------------------------------------------------------
// Node.HandleFork
// ---------------------------------------------------------------------------

// Item 12: HandleFork no longer replaces the local chain even when the peer is
// longer. dBFT provides single-path irreversible finality; use SyncBlockchain
// for legitimate catch-up.
func TestNode_HandleFork_LongerChain_LocalChainUnchanged(t *testing.T) {
	bc1 := newTestBlockchain(t)
	bc2 := newTestBlockchain(t)

	bc2.AddBlock(Block{Transactions: []Transaction{{Sender: "A", Receiver: "B", Amount: 1}}})
	bc2.AddBlock(Block{Transactions: []Transaction{{Sender: "A", Receiver: "B", Amount: 2}}})

	n1 := makeNode(t, "n1", bc1)
	n2 := makeNode(t, "n2", bc2)

	wantLen := len(n1.Blockchain.Blocks)
	n1.HandleFork(n2)

	assert.Equal(t, wantLen, len(n1.Blockchain.Blocks),
		"HandleFork must not replace the local chain (dBFT single-path finality)")
}

func TestNode_HandleFork_ShorterChain_NoChange(t *testing.T) {
	bc1 := newTestBlockchain(t)
	bc2 := newTestBlockchain(t)

	bc1.AddBlock(Block{Transactions: []Transaction{{Sender: "A", Receiver: "B", Amount: 1}}})
	bc1.AddBlock(Block{Transactions: []Transaction{{Sender: "A", Receiver: "B", Amount: 2}}})

	n1 := makeNode(t, "n1", bc1)
	n2 := makeNode(t, "n2", bc2)

	originalLen := len(n1.Blockchain.Blocks)
	n1.HandleFork(n2) // n2 has shorter chain — no change expected
	assert.Equal(t, originalLen, len(n1.Blockchain.Blocks))
}

// ---------------------------------------------------------------------------
// Node.ProcessMessages — Transaction message
// ---------------------------------------------------------------------------

func TestNode_ProcessMessages_TransactionMessage_AddsToPool(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.InitializeShards(1)
	n := makeNode(t, "n1", bc)

	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	senderPub := base64.StdEncoding.EncodeToString(key.Public().Bytes())

	tx := Transaction{
		Sender:       senderPub,
		Receiver:     "recv",
		Amount:       5,
		RequiredSigs: 1,
	}
	tx.GenerateNonce()
	require.NoError(t, tx.SignTransaction(key))

	// ProcessMessages runs until n.Inbox is closed — close it when the test ends.
	t.Cleanup(func() { close(n.Inbox) })
	go n.ProcessMessages()

	n.Inbox <- Message{Type: "Transaction", Payload: tx}

	// Give ProcessMessages time to handle the tx
	time.Sleep(100 * time.Millisecond)

	assert.Greater(t, transactionPoolLength(bc), 0, "transaction should appear in a shard pool")
}

// ---------------------------------------------------------------------------
// NewNode
// ---------------------------------------------------------------------------

func TestNewNode_FieldsInitialised(t *testing.T) {
	bc := newTestBlockchain(t)
	n := NewNode("node-abc", bc)

	require.NotNil(t, n)
	assert.Equal(t, "node-abc", n.ID)
	assert.Equal(t, bc, n.Blockchain)
	require.NotNil(t, n.Inbox, "Inbox channel must be initialised")
	assert.Equal(t, 1000, cap(n.Inbox), "Item 23: inbox capacity must absorb consensus bursts")
}
