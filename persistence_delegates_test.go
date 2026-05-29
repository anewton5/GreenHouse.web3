package gonetwork

// ---------------------------------------------------------------------------
// persistence_delegates_test.go — Item 10: delegate-set persistence
//
// Covers:
//   SaveDelegates / LoadDelegates  — round-trip (identity, keys, re-init fields)
//   Survives close + reopen        — delegates bucket persists across restarts
//   VoteForDelegates integration   — SaveDelegates called when BlockStore is set
//   NewBlockchain startup load     — LoadDelegates called via GREENHOUSE_DB_PATH
//   WalletSequences end-to-end     — persisted via SaveState; rebuilt on replay
// ---------------------------------------------------------------------------

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeTestDelegate constructs a Node with freshly generated Ed25519 keys for
// use in persistence tests. The Inbox, Blockchain, and viewChangeRequests
// fields are populated so the node is ready for in-process use.
func makeTestDelegate(t *testing.T, id string, bc *Blockchain) Node {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return Node{
		ID:                 id,
		IsDelegate:         true,
		Stake:              100,
		Votes:              50,
		PublicKey:          pub,
		PrivateKey:         priv,
		Inbox:              make(chan Message, 100),
		Blockchain:         bc,
		viewChangeRequests: make(map[int]int),
	}
}

// ---------------------------------------------------------------------------
// SaveDelegates / LoadDelegates — low-level round-trip
// ---------------------------------------------------------------------------

func TestSaveDelegates_LoadDelegates_Roundtrip(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	bc := newTestBlockchain(t)
	d1 := makeTestDelegate(t, "delegate-1", bc)
	d2 := makeTestDelegate(t, "delegate-2", bc)
	bc.Delegates = []Node{d1, d2}

	require.NoError(t, bs.SaveDelegates(bc.Delegates))

	// Load into a fresh blockchain.
	bc2 := newTestBlockchain(t)
	bc2.Delegates = nil
	require.NoError(t, bs.LoadDelegates(bc2))

	require.Len(t, bc2.Delegates, 2)
	assert.Equal(t, "delegate-1", bc2.Delegates[0].ID)
	assert.Equal(t, "delegate-2", bc2.Delegates[1].ID)
	assert.True(t, bc2.Delegates[0].IsDelegate)
	assert.Equal(t, 100, bc2.Delegates[0].Stake)
	assert.Equal(t, 50, bc2.Delegates[0].Votes)
	assert.Equal(t, d1.PublicKey, bc2.Delegates[0].PublicKey)
	assert.Equal(t, d1.PrivateKey, bc2.Delegates[0].PrivateKey)
}

func TestSaveDelegates_RuntimeFields_ReInitialisedOnLoad(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	bc := newTestBlockchain(t)
	d1 := makeTestDelegate(t, "d1", bc)
	bc.Delegates = []Node{d1}
	require.NoError(t, bs.SaveDelegates(bc.Delegates))

	bc2 := newTestBlockchain(t)
	require.NoError(t, bs.LoadDelegates(bc2))
	require.Len(t, bc2.Delegates, 1)

	// Inbox must be a usable channel (not nil).
	loaded := bc2.Delegates[0]
	require.NotNil(t, loaded.Inbox, "Inbox must be re-initialised after load")
	select {
	case loaded.Inbox <- Message{}:
	default:
		t.Fatal("Inbox channel is full — expected a buffered channel with capacity")
	}

	// Blockchain pointer must point to bc2.
	assert.Equal(t, bc2, loaded.Blockchain)
}

func TestSaveDelegates_EmptySet_Roundtrip(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	bc := newTestBlockchain(t)
	bc.Delegates = []Node{}

	require.NoError(t, bs.SaveDelegates(bc.Delegates))

	bc2 := newTestBlockchain(t)
	require.NoError(t, bs.LoadDelegates(bc2))
	// After an explicit empty save, delegates should be an empty (not nil) slice.
	assert.Empty(t, bc2.Delegates)
}

func TestLoadDelegates_EmptyStore_NoChange(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	bc := newTestBlockchain(t)
	bc.Delegates = nil

	require.NoError(t, bs.LoadDelegates(bc))
	assert.Nil(t, bc.Delegates, "fresh store should leave Delegates untouched")
}

// ---------------------------------------------------------------------------
// Persistence survives close + reopen
// ---------------------------------------------------------------------------

func TestSaveDelegates_SurvivesReopen(t *testing.T) {
	path := tempDBPath(t)

	// Write two delegates and close.
	func() {
		bs, err := OpenBlockStore(path)
		require.NoError(t, err)
		defer bs.Close()

		bc := newTestBlockchain(t)
		d1 := makeTestDelegate(t, "alpha", bc)
		d2 := makeTestDelegate(t, "beta", bc)
		bc.Delegates = []Node{d1, d2}
		require.NoError(t, bs.SaveDelegates(bc.Delegates))
	}()

	// Reopen and verify.
	bs2, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs2.Close()

	bc2 := newTestBlockchain(t)
	require.NoError(t, bs2.LoadDelegates(bc2))
	require.Len(t, bc2.Delegates, 2)
	assert.Equal(t, "alpha", bc2.Delegates[0].ID)
	assert.Equal(t, "beta", bc2.Delegates[1].ID)
}

func TestSaveDelegates_OverwritesPreviousSave(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	bc := newTestBlockchain(t)
	d1 := makeTestDelegate(t, "first", bc)
	bc.Delegates = []Node{d1}
	require.NoError(t, bs.SaveDelegates(bc.Delegates))

	// Save a different set — should overwrite.
	d2 := makeTestDelegate(t, "second", bc)
	d3 := makeTestDelegate(t, "third", bc)
	bc.Delegates = []Node{d2, d3}
	require.NoError(t, bs.SaveDelegates(bc.Delegates))

	bc2 := newTestBlockchain(t)
	require.NoError(t, bs.LoadDelegates(bc2))
	require.Len(t, bc2.Delegates, 2)
	assert.Equal(t, "second", bc2.Delegates[0].ID)
	assert.Equal(t, "third", bc2.Delegates[1].ID)
}

// ---------------------------------------------------------------------------
// VoteForDelegates integration — SaveDelegates called when BlockStore is set
// ---------------------------------------------------------------------------

func TestVoteForDelegates_WithBlockStore_PersistsDelegates(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	bc := newTestBlockchain(t)
	bc.BlockStore = bs

	// Wire up the minimal staking data needed for VoteForDelegates to elect one
	// delegate:
	//   lockedWallet.OwnerPublicKey → voterID → delegateID → bc.Nodes[0]
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	var ownerKey [32]byte
	copy(ownerKey[:], pub)
	pubStr := base64.StdEncoding.EncodeToString(ownerKey[:])

	const voterID = "voter-1"
	const delegateID = "delegate-A"

	bc.PublicKeyToID[pubStr] = voterID
	bc.UserIDToDelegateID[voterID] = delegateID

	delegateNode := Node{
		ID:         delegateID,
		PublicKey:  pub,
		PrivateKey: priv,
		Inbox:      make(chan Message, 100),
		Blockchain: bc,
	}
	bc.Nodes = []Node{delegateNode}

	lw := &LockedWallet{OwnerPublicKey: ownerKey, Balance: 500}
	bc.LockedWallets[ownerKey] = lw

	// VoteForDelegates elects delegate-A and calls SaveDelegates via BlockStore.
	bc.VoteForDelegates(nil) // nil p2pNode — startConsensus exits early (empty pool)

	// Verify the delegate was persisted to BBolt.
	bc2 := newTestBlockchain(t)
	bc2.Delegates = nil
	require.NoError(t, bs.LoadDelegates(bc2))
	require.Len(t, bc2.Delegates, 1, "VoteForDelegates should have persisted the elected delegate")
	assert.Equal(t, delegateID, bc2.Delegates[0].ID)
}

func TestVoteForDelegates_NoBlockStore_NoPanic(t *testing.T) {
	bc := newTestBlockchain(t)
	// BlockStore is nil by default — SaveDelegates should be skipped without panic.
	bc.VoteForDelegates(nil)
}

// ---------------------------------------------------------------------------
// NewBlockchain startup load — delegates restored via GREENHOUSE_DB_PATH
// ---------------------------------------------------------------------------

func TestNewBlockchain_LoadsDelegatesFromStore_OnStartup(t *testing.T) {
	path := tempDBPath(t)

	// Pre-populate the store with a saved delegate set.
	func() {
		bs, err := OpenBlockStore(path)
		require.NoError(t, err)
		defer bs.Close()

		bc := newTestBlockchain(t)
		d := makeTestDelegate(t, "startup-delegate", bc)
		bc.Delegates = []Node{d}
		require.NoError(t, bs.SaveDelegates(bc.Delegates))
	}()

	// Start a fresh blockchain pointed at the same file.
	t.Setenv("GREENHOUSE_DB_PATH", path)
	bc := NewBlockchain(context.Background(), "test-startup")
	require.NotNil(t, bc.BlockStore)

	bc.Mu.RLock()
	delegates := make([]Node, len(bc.Delegates))
	copy(delegates, bc.Delegates)
	bc.Mu.RUnlock()

	require.Len(t, delegates, 1, "delegates should be restored from store on startup")
	assert.Equal(t, "startup-delegate", delegates[0].ID)
	assert.NotNil(t, delegates[0].Inbox, "Inbox must be re-initialised on load")
	assert.Equal(t, bc, delegates[0].Blockchain, "Blockchain pointer must be wired to the running chain")
}

// ---------------------------------------------------------------------------
// WalletSequences end-to-end — persisted via SaveState, rebuilt on replay
// Acceptance criterion: bc.WalletSequences after restart reflects the highest
// observed nonce per sender across all replayed blocks.
// ---------------------------------------------------------------------------

func TestWalletSequences_RestoredAfterRestart(t *testing.T) {
	path := tempDBPath(t)

	// Run 1: create blockchain, add a transaction (to populate WalletSequences),
	// seal a block (calls SaveState internally), then close the store.
	aliceKey := "alice-sender-public-key"
	func() {
		bs, err := OpenBlockStore(path)
		require.NoError(t, err)

		bc := newTestBlockchain(t)
		bc.BlockStore = bs

		tx := Transaction{
			Sender:   aliceKey,
			Receiver: "bob",
			Amount:   1,
			Nonce:    42,
		}
		bc.Mu.Lock()
		bc.WalletSequences[aliceKey] = tx.Nonce
		bc.TransactionPool = append(bc.TransactionPool, tx)
		bc.Mu.Unlock()

		// SealBlock writes the block and calls SaveState (which includes WalletSequences).
		bc.SealBlock(nil, nil, nil)
		bs.Close()
	}()

	// Run 2: open a brand-new blockchain from the same db path.
	// SaveState already recorded WalletSequences = {aliceKey: 42}.
	bs2, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs2.Close()

	bc2 := newTestBlockchain(t)
	bc2.WalletSequences = make(map[string]int64)

	_, err = bs2.LoadState(bc2)
	require.NoError(t, err)

	assert.Equal(t, int64(42), bc2.WalletSequences[aliceKey],
		"WalletSequences must reflect the highest nonce sealed before restart")
}

func TestWalletSequences_CatchUpFromBlocks_AfterMissingSnapshot(t *testing.T) {
	// Simulate the crash-window scenario: blocks were saved but SaveState was
	// never called (e.g., crash between SaveBlock and SaveState).
	// catchUpBlock (called by NewBlockchain during startup) must rebuild
	// WalletSequences from the raw block data.
	path := tempDBPath(t)

	var bobKey string
	func() {
		bs, err := OpenBlockStore(path)
		require.NoError(t, err)
		defer bs.Close()

		bobKey = "bob-wallet-key"
		b := Block{
			Index: 1,
			Transactions: []Transaction{
				{Sender: bobKey, Receiver: "alice", Amount: 5, Nonce: 99},
			},
		}
		b.SetPayloadHash()
		require.NoError(t, bs.SaveBlock(&b))
		// Deliberately do NOT call SaveState — simulating a crash before snapshot.
	}()

	// Open the store and replay manually, as NewBlockchain would.
	bs2, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs2.Close()

	bc2 := newTestBlockchain(t)
	bc2.Blocks = []Block{}
	bc2.WalletSequences = make(map[string]int64)

	require.NoError(t, bs2.LoadBlocks(bc2))
	// LoadState returns -1 (no snapshot) → catchUpBlock is called for all blocks.
	lastApplied, err := bs2.LoadState(bc2)
	require.NoError(t, err)
	assert.Equal(t, -1, lastApplied)

	for i := lastApplied + 1; i < len(bc2.Blocks); i++ {
		bc2.catchUpBlock(&bc2.Blocks[i])
	}

	assert.Equal(t, int64(99), bc2.WalletSequences[bobKey],
		"catchUpBlock must rebuild WalletSequences from raw block transactions")
}
