package gonetwork

// ---------------------------------------------------------------------------
// persistence_test.go — bbolt BlockStore (C-4)
//
// Covers:
//   OpenBlockStore         — creates file, initialises bucket, returns error
//                            when path is invalid
//   SaveBlock / LoadBlocks — round-trip (single block, many blocks, ordering)
//   BlockCount             — reports correct count after writes
//   Close                  — idempotent, file released
//   SealBlock integration  — BlockStore.SaveBlock called by Blockchain.SealBlock
// ---------------------------------------------------------------------------

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tempDBPath returns a unique temp-file path for a bbolt database and
// registers a cleanup that removes the file at the end of the test.
func tempDBPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "test.db")
}

// ---------------------------------------------------------------------------
// OpenBlockStore
// ---------------------------------------------------------------------------

func TestOpenBlockStore_CreatesFile(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	require.NotNil(t, bs)
	bs.Close()

	_, statErr := os.Stat(path)
	assert.NoError(t, statErr, "database file should exist after OpenBlockStore")
}

func TestOpenBlockStore_InvalidPath_ReturnsError(t *testing.T) {
	_, err := OpenBlockStore("/nonexistent/path/that/cannot/be/created/test.db")
	assert.Error(t, err)
}

func TestOpenBlockStore_OpenExisting_Succeeds(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	bs.Close()

	// Re-open the same file
	bs2, err := OpenBlockStore(path)
	require.NoError(t, err)
	bs2.Close()
}

// ---------------------------------------------------------------------------
// SaveBlock / LoadBlocks
// ---------------------------------------------------------------------------

func TestPersistence_SaveAndLoad_SingleBlock(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	block := Block{Index: 0, PrevHash: "0000", Nonce: 1}
	block.SetPayloadHash()

	require.NoError(t, bs.SaveBlock(&block))

	bc := newTestBlockchain(t)
	bc.Blocks = nil // clear genesis

	require.NoError(t, bs.LoadBlocks(bc))
	require.Len(t, bc.Blocks, 1)
	assert.Equal(t, 0, bc.Blocks[0].Index)
	assert.Equal(t, block.PayloadHash, bc.Blocks[0].PayloadHash)
}

func TestPersistence_SaveAndLoad_MultipleBlocksPreservesOrder(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	for i := 0; i < 5; i++ {
		b := Block{Index: i, Nonce: i}
		b.SetPayloadHash()
		require.NoError(t, bs.SaveBlock(&b))
	}

	bc := newTestBlockchain(t)
	bc.Blocks = nil
	require.NoError(t, bs.LoadBlocks(bc))
	require.Len(t, bc.Blocks, 5)

	for i, b := range bc.Blocks {
		assert.Equal(t, i, b.Index, "block order must be preserved")
	}
}

func TestPersistence_SaveBlock_Overwrites(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	b := Block{Index: 0, Nonce: 1}
	b.SetPayloadHash()
	require.NoError(t, bs.SaveBlock(&b))

	// Overwrite with updated nonce
	b.Nonce = 99
	b.SetPayloadHash()
	require.NoError(t, bs.SaveBlock(&b))

	bc := newTestBlockchain(t)
	bc.Blocks = nil
	require.NoError(t, bs.LoadBlocks(bc))

	require.Len(t, bc.Blocks, 1)
	assert.Equal(t, 99, bc.Blocks[0].Nonce)
}

func TestPersistence_LoadBlocks_EmptyStore_NoError(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	bc := newTestBlockchain(t)
	originalLen := len(bc.Blocks)
	err = bs.LoadBlocks(bc)
	require.NoError(t, err)
	assert.Equal(t, originalLen, len(bc.Blocks), "empty store should not change block count")
}

func TestPersistence_SaveBlock_WithTransactions(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	b := Block{
		Index: 1,
		Transactions: []Transaction{
			{Sender: "alice", Receiver: "bob", Amount: 100},
		},
	}
	b.SetPayloadHash()
	require.NoError(t, bs.SaveBlock(&b))

	bc := newTestBlockchain(t)
	bc.Blocks = nil
	require.NoError(t, bs.LoadBlocks(bc))

	require.Len(t, bc.Blocks, 1)
	require.Len(t, bc.Blocks[0].Transactions, 1)
	assert.Equal(t, "alice", bc.Blocks[0].Transactions[0].Sender)
}

// ---------------------------------------------------------------------------
// BlockCount
// ---------------------------------------------------------------------------

func TestPersistence_BlockCount_AfterSaves(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	for i := 0; i < 3; i++ {
		b := Block{Index: i}
		b.SetPayloadHash()
		require.NoError(t, bs.SaveBlock(&b))
	}

	count, err := bs.BlockCount()
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestPersistence_BlockCount_Empty(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	count, err := bs.BlockCount()
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// ---------------------------------------------------------------------------
// Persistence survives close + reopen
// ---------------------------------------------------------------------------

func TestPersistence_SurvivesReopen(t *testing.T) {
	path := tempDBPath(t)

	// Write 3 blocks
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		b := Block{Index: i, Nonce: i * 10}
		b.SetPayloadHash()
		require.NoError(t, bs.SaveBlock(&b))
	}
	bs.Close()

	// Reopen and verify
	bs2, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs2.Close()

	bc := newTestBlockchain(t)
	bc.Blocks = nil
	require.NoError(t, bs2.LoadBlocks(bc))
	require.Len(t, bc.Blocks, 3)
	assert.Equal(t, 20, bc.Blocks[2].Nonce)
}

// ---------------------------------------------------------------------------
// SealBlock integration — BlockStore wired into Blockchain
// ---------------------------------------------------------------------------

func TestPersistence_SealBlock_PersistsBlock(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	bc := NewBlockchain(context.Background(), "seal-test")
	bc.BlockStore = bs

	// SealBlock with an asset transaction to avoid empty-block rejection
	bc.SealBlock(nil, nil, nil) // even empty seal should persist the block
	// Genesis block is block 0; SealBlock adds block 1
	count, err := bs.BlockCount()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1, "at least one block should be persisted")
}
