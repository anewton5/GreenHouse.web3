package gonetwork

// ---------------------------------------------------------------------------
// C-4: bbolt block store — durable block persistence
//
// BlockStore wraps a bbolt (BoltDB) database and provides two operations:
//
//   - SaveBlock(b *Block)               — appends or overwrites a block by index.
//   - LoadBlocks(bc *Blockchain) error  — reads all stored blocks into bc.Blocks,
//                                         preserving their original order.
//
// The database uses a single bucket ("blocks") keyed by the block index encoded
// as a zero-padded 10-digit decimal string so that BoltDB's byte-sorted iteration
// yields blocks in chain order.
//
// Usage (in cmd/api/main.go):
//
//	store, err := gonetwork.OpenBlockStore("greenhouse.db")
//	if err != nil { log.Fatal(err) }
//	defer store.Close()
//	if err := store.LoadBlocks(bc); err != nil { log.Printf("load: %v", err) }
//	bc.BlockStore = store  // SealBlock calls store.SaveBlock after every seal
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"

	bolt "go.etcd.io/bbolt"
)

const blocksBucket = "blocks"

// BlockStore wraps a bbolt database for block persistence.
type BlockStore struct {
	db *bolt.DB
}

// OpenBlockStore opens (or creates) a bbolt database at the given file path and
// ensures the "blocks" bucket exists.
func OpenBlockStore(path string) (*BlockStore, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("OpenBlockStore: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(blocksBucket))
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("OpenBlockStore: bucket init: %w", err)
	}
	return &BlockStore{db: db}, nil
}

// Close cleanly shuts down the bbolt database.
func (bs *BlockStore) Close() error {
	return bs.db.Close()
}

// SaveBlock serialises b as JSON and writes it to the "blocks" bucket under the
// key fmt.Sprintf("%010d", b.Index). Overwrites any existing entry at that index.
func (bs *BlockStore) SaveBlock(b *Block) error {
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("BlockStore.SaveBlock: marshal: %w", err)
	}
	key := []byte(fmt.Sprintf("%010d", b.Index))
	return bs.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(blocksBucket)).Put(key, data)
	})
}

// LoadBlocks reads all blocks from the database in index order and appends them
// to bc.Blocks. It does NOT acquire bc.Mu — callers must ensure exclusive access
// (e.g. call only from Start() before serving requests).
func (bs *BlockStore) LoadBlocks(bc *Blockchain) error {
	return bs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		if b == nil {
			return nil // empty store — first start
		}
		return b.ForEach(func(k, v []byte) error {
			var blk Block
			if err := json.Unmarshal(v, &blk); err != nil {
				log.Printf("BlockStore.LoadBlocks: skipping malformed block key=%s: %v", k, err)
				return nil
			}
			bc.Blocks = append(bc.Blocks, blk)
			return nil
		})
	})
}

// BlockCount returns the number of blocks currently stored.
func (bs *BlockStore) BlockCount() (int, error) {
	var n int
	err := bs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		if b != nil {
			n = b.Stats().KeyN
		}
		return nil
	})
	return n, err
}

// keyForIndex returns the zero-padded decimal key string for a block index.
// Exported for testing.
func keyForIndex(index int) string {
	return strconv.FormatInt(int64(index), 10)
}
