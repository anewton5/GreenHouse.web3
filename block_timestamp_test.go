package gonetwork

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestBlockTimestamp_NonZeroAfterSeal verifies that AddBlock stamps every block
// with a non-zero SealedAt value before returning.
func TestBlockTimestamp_NonZeroAfterSeal(t *testing.T) {
	bc := NewBlockchain(context.Background(), "timestamp-test")

	before := time.Now().UnixMicro()
	tx := Transaction{Sender: "alice", Receiver: "bob", Amount: 1}
	bc.AddBlock(Block{Transactions: []Transaction{tx}})
	after := time.Now().UnixMicro()

	if len(bc.Blocks) < 2 {
		t.Fatal("expected at least genesis + 1 block")
	}
	sealed := bc.Blocks[len(bc.Blocks)-1]
	if sealed.SealedAt == 0 {
		t.Fatal("SealedAt must be non-zero after AddBlock")
	}
	if sealed.SealedAt < before || sealed.SealedAt > after {
		t.Errorf("SealedAt %d outside expected range [%d, %d]", sealed.SealedAt, before, after)
	}
}

// TestBlockTimestamp_IncludedInPayloadHash verifies that two otherwise identical
// blocks produce different PayloadHash values when SealedAt differs.
func TestBlockTimestamp_IncludedInPayloadHash(t *testing.T) {
	tx := Transaction{Sender: "alice", Receiver: "bob", Amount: 1}

	b1 := Block{
		Index:        1,
		SealedAt:     1_000_000,
		Transactions: []Transaction{tx},
		PrevHash:     "0000",
		Nonce:        1,
	}
	b1.SetPayloadHash()
	h1 := b1.PayloadHash

	b2 := Block{
		Index:        1,
		SealedAt:     1_000_001, // one microsecond later
		Transactions: []Transaction{tx},
		PrevHash:     "0000",
		Nonce:        1,
	}
	b2.SetPayloadHash()
	h2 := b2.PayloadHash

	if h1 == h2 {
		t.Error("different SealedAt values must produce different PayloadHash values")
	}
}

// TestBlockTimestamp_JSONSerialisation verifies that the sealed_at field is
// present in the JSON output and round-trips correctly.
func TestBlockTimestamp_JSONSerialisation(t *testing.T) {
	bc := NewBlockchain(context.Background(), "timestamp-test")
	tx := Transaction{Sender: "alice", Receiver: "bob", Amount: 1}
	bc.AddBlock(Block{Transactions: []Transaction{tx}})

	sealed := bc.Blocks[len(bc.Blocks)-1]
	data, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	// Verify the key is present in the JSON blob.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := raw["sealed_at"]; !ok {
		t.Error("JSON output must contain the \"sealed_at\" key")
	}

	// Round-trip.
	var roundTrip Block
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if roundTrip.SealedAt != sealed.SealedAt {
		t.Errorf("SealedAt mismatch after round-trip: got %d, want %d", roundTrip.SealedAt, sealed.SealedAt)
	}
}

// TestBlockTimestamp_GenesisHasSealedAtZero verifies that the genesis block
// (created outside AddBlock) has SealedAt == 0, which is acceptable.
func TestBlockTimestamp_GenesisHasSealedAtZero(t *testing.T) {
	bc := NewBlockchain(context.Background(), "timestamp-test")
	genesis := bc.Blocks[0]
	if genesis.SealedAt != 0 {
		t.Errorf("genesis block SealedAt must be 0, got %d", genesis.SealedAt)
	}
}

// TestBlockTimestamp_TamperedSealedAtFailsValidation verifies that altering
// SealedAt after sealing is detected by ValidateBlock (acceptance criterion
// "Replaying a block with a different SealedAt fails ValidateBlock").
func TestBlockTimestamp_TamperedSealedAtFailsValidation(t *testing.T) {
	bc := NewBlockchain(context.Background(), "timestamp-test")

	// Build a candidate block manually so it points to genesis as its predecessor.
	// Use AssetTransactions to avoid base-transaction signature validation, which
	// is not the subject of this test.
	block := Block{
		Index:             1,
		SealedAt:          time.Now().UnixMicro(),
		AssetTransactions: []AssetTransaction{{AssetID: "ISIN123", TxType: "issue"}},
		PrevHash:          bc.Blocks[0].CalculateHash(),
		Nonce:             0,
	}
	block.SetPayloadHash()

	// Tamper: shift SealedAt by one microsecond after the hash was computed.
	block.SealedAt += 1

	if bc.ValidateBlock(block) {
		t.Error("ValidateBlock must return false for a block with a tampered SealedAt")
	}
}

// TestBlockTimestamp_UntamperedBlockPassesValidation confirms that a legitimately
// sealed block passes ValidateBlock so the content-integrity check does not
// produce false positives.
func TestBlockTimestamp_UntamperedBlockPassesValidation(t *testing.T) {
	bc := NewBlockchain(context.Background(), "timestamp-test")

	// Build a candidate block manually pointing to genesis. Using AssetTransactions
	// avoids the base-transaction signature validation path (not the focus here).
	block := Block{
		Index:             1,
		SealedAt:          time.Now().UnixMicro(),
		AssetTransactions: []AssetTransaction{{AssetID: "ISIN123", TxType: "issue"}},
		PrevHash:          bc.Blocks[0].CalculateHash(),
		Nonce:             0,
	}
	block.SetPayloadHash()

	if !bc.ValidateBlock(block) {
		t.Error("ValidateBlock must return true for an untampered sealed block")
	}
}
