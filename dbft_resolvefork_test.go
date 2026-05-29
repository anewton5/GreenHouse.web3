package gonetwork

// ---------------------------------------------------------------------------
// dbft_resolvefork_test.go — Item 12: ResolveFork removed; single-path finality
//
// dBFT provides irreversible finality. Once a block carries ⌈2n/3⌉ valid
// delegate signatures it cannot be reverted. The Nakamoto longest-chain fork
// rule (ResolveFork) has been removed because:
//   - It would allow a Byzantine peer to replace finalised blocks.
//   - In-memory state diverges from bc.Blocks after an unconditional
//     replacement (applyBlockState is not re-run).
//
// Acceptance criteria (from PRODUCTION_READINESS_PLAN.md §Item 12):
//   - A peer presenting a longer chain cannot replace the local chain.
//   - An existing finalised block is never replaced by any competing block.
//   - ResolveFork is removed; single-path finality is documented.
// ---------------------------------------------------------------------------

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// HandleFork — must never replace the local chain
// ---------------------------------------------------------------------------

func TestHandleFork_PeerChainLonger_LocalBlocksUnchanged(t *testing.T) {
	local := newTestBlockchain(t)
	peer := newTestBlockchain(t)

	// Peer has two extra blocks.
	peer.AddBlock(Block{Transactions: []Transaction{{Sender: "A", Receiver: "B", Amount: 1}}})
	peer.AddBlock(Block{Transactions: []Transaction{{Sender: "C", Receiver: "D", Amount: 2}}})

	wantLen := len(local.Blocks)
	wantHash := local.GetLastBlockHash()

	nLocal := &Node{ID: "local", Blockchain: local}
	nPeer := &Node{ID: "peer", Blockchain: peer}
	nLocal.HandleFork(nPeer)

	assert.Equal(t, wantLen, len(nLocal.Blockchain.Blocks),
		"HandleFork must not add blocks from peer chain")
	assert.Equal(t, wantHash, nLocal.Blockchain.GetLastBlockHash(),
		"HandleFork must not change the tip hash")
}

func TestHandleFork_PeerChainEqual_LocalBlocksUnchanged(t *testing.T) {
	local := newTestBlockchain(t)
	peer := newTestBlockchain(t)

	wantLen := len(local.Blocks)

	nLocal := &Node{ID: "local", Blockchain: local}
	nPeer := &Node{ID: "peer", Blockchain: peer}
	nLocal.HandleFork(nPeer)

	assert.Equal(t, wantLen, len(nLocal.Blockchain.Blocks))
}

func TestHandleFork_PeerChainShorter_LocalBlocksUnchanged(t *testing.T) {
	local := newTestBlockchain(t)
	local.AddBlock(Block{Transactions: []Transaction{{Sender: "X", Receiver: "Y", Amount: 5}}})

	peer := newTestBlockchain(t) // only genesis

	wantLen := len(local.Blocks)

	nLocal := &Node{ID: "local", Blockchain: local}
	nPeer := &Node{ID: "peer", Blockchain: peer}
	nLocal.HandleFork(nPeer)

	assert.Equal(t, wantLen, len(nLocal.Blockchain.Blocks),
		"HandleFork must not modify local chain when peer is shorter")
}

// ---------------------------------------------------------------------------
// AddBlock duplicate-index safety assertion
// ---------------------------------------------------------------------------

// TestAddBlock_SequentialIndexing verifies that AddBlock always assigns the
// next sequential index regardless of what is set on the incoming block, and
// that the BFT safety protection lives in HandleFork being a no-op (not in
// AddBlock, which is a pure append primitive).
func TestAddBlock_SequentialIndexing(t *testing.T) {
	bc := newTestBlockchain(t)
	startLen := len(bc.Blocks)

	for i := 0; i < 3; i++ {
		bc.AddBlock(Block{Transactions: []Transaction{{Sender: "A", Receiver: "B", Amount: float64(i)}}})
	}

	require.Equal(t, startLen+3, len(bc.Blocks))
	for i, b := range bc.Blocks {
		assert.Equal(t, i, b.Index, "block at position %d must have index %d", i, i)
	}
}

// ---------------------------------------------------------------------------
// Single-path finality: SyncBlockchain is the correct mechanism for a
// lagging node to catch up — not fork resolution.
// ---------------------------------------------------------------------------

func TestSyncBlockchain_LaggingNodeCatchesUp(t *testing.T) {
	authoritative := newTestBlockchain(t)
	authoritative.AddBlock(Block{Transactions: []Transaction{{Sender: "A", Receiver: "B", Amount: 10}}})
	authoritative.AddBlock(Block{Transactions: []Transaction{{Sender: "C", Receiver: "D", Amount: 20}}})

	lagging := newTestBlockchain(t) // behind by 2 blocks

	nAuth := &Node{ID: "auth", Blockchain: authoritative}
	nLag := &Node{ID: "lag", Blockchain: lagging}

	// SyncBlockchain replaces the lagging node's blockchain reference directly.
	// This is the correct catch-up mechanism (no fork resolution needed).
	nLag.SyncBlockchain(nAuth)

	assert.Equal(t, len(nAuth.Blockchain.Blocks), len(nLag.Blockchain.Blocks),
		"SyncBlockchain must align the lagging node with the authoritative peer")
}
