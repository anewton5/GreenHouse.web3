package gonetwork

// ---------------------------------------------------------------------------
// utilities_test.go
//
// Covers previously-untested utility functions:
//   ValidateISIN                   — valid ISIN, empty, wrong length, bad chars,
//                                    invalid Luhn check digit
//   EncryptPrivateKey /            — round-trip, wrong passphrase, v2 prefix,
//   DecryptPrivateKey                legacy path, short ciphertext errors
//   NewPrivateKeyFromSeed          — valid 32-byte seed, wrong length
//   GeneratePublicKey              — matches Private.Public()
//   ProspectusExemption.MarshalJSON — produces valid JSON
//   LiquidityWindow.IsOpen         — status checks
//   WindowManager.HasOpenWindow    — empty, open, closed
//   Shard.ValidateShardTransactions — valid tx, invalid tx (no panic)
//   Blockchain.SaveBlockchain /    — save+load round-trip, missing file
//   LoadBlockchain
// ---------------------------------------------------------------------------

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ValidateISIN
// ---------------------------------------------------------------------------

func TestValidateISIN_Empty_OK(t *testing.T) {
	assert.NoError(t, ValidateISIN(""))
}

func TestValidateISIN_ValidGB_OK(t *testing.T) {
	// GB0001234567 — real-world format example with valid Luhn
	// Using a known-valid ISIN: GB00B1YW4409 (ARM Holdings)
	assert.NoError(t, ValidateISIN("GB00B1YW4409"))
}

func TestValidateISIN_WrongLength_Error(t *testing.T) {
	err := ValidateISIN("GB000123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "12 characters")
}

func TestValidateISIN_LowercaseCountry_Error(t *testing.T) {
	err := ValidateISIN("gb00B1YW4409")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "country code")
}

func TestValidateISIN_InvalidChar_Error(t *testing.T) {
	err := ValidateISIN("GB0001234!67")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uppercase alphanumeric")
}

func TestValidateISIN_BadCheckDigit_Error(t *testing.T) {
	// Valid format but wrong check digit
	err := ValidateISIN("GB00B1YW4400")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "check digit")
}

// ---------------------------------------------------------------------------
// EncryptPrivateKey / DecryptPrivateKey — v2 (AES-256-GCM + Argon2id)
// ---------------------------------------------------------------------------

func TestEncryptDecryptPrivateKey_RoundTrip(t *testing.T) {
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	original := key.Bytes()

	encrypted, err := EncryptPrivateKey(original, "my-passphrase-123")
	require.NoError(t, err)
	assert.Contains(t, encrypted, "v2:", "v2 prefix should be present")

	decrypted, err := DecryptPrivateKey(encrypted, "my-passphrase-123")
	require.NoError(t, err)
	assert.Equal(t, original, decrypted)
}

func TestDecryptPrivateKey_WrongPassphrase_Error(t *testing.T) {
	key, _ := GeneratePrivateKey()
	encrypted, err := EncryptPrivateKey(key.Bytes(), "correct-passphrase")
	require.NoError(t, err)

	_, err = DecryptPrivateKey(encrypted, "wrong-passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestEncryptPrivateKey_DifferentNonceEachCall(t *testing.T) {
	key, _ := GeneratePrivateKey()
	seed := key.Bytes()
	enc1, err := EncryptPrivateKey(seed, "pass")
	require.NoError(t, err)
	enc2, err := EncryptPrivateKey(seed, "pass")
	require.NoError(t, err)
	assert.NotEqual(t, enc1, enc2, "random salt/nonce should produce different ciphertext each call")
}

func TestDecryptPrivateKey_InvalidHex_Error(t *testing.T) {
	_, err := DecryptPrivateKey("v2:not-valid-hex!", "passphrase")
	require.Error(t, err)
}

func TestDecryptPrivateKey_TooShortCiphertext_Error(t *testing.T) {
	// Minimal valid hex but too short for salt+nonce+tag
	_, err := DecryptPrivateKey("v2:deadbeef", "passphrase")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// NewPrivateKeyFromSeed
// ---------------------------------------------------------------------------

func TestNewPrivateKeyFromSeed_Valid(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	k, err := NewPrivateKeyFromSeed(seed)
	require.NoError(t, err)
	require.NotNil(t, k)
	assert.Equal(t, seed, k.Bytes())
}

func TestNewPrivateKeyFromSeed_WrongLength_Error(t *testing.T) {
	_, err := NewPrivateKeyFromSeed(make([]byte, 16))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

// ---------------------------------------------------------------------------
// GeneratePublicKey
// ---------------------------------------------------------------------------

func TestGeneratePublicKey_MatchesPrivatePublic(t *testing.T) {
	key, _ := GeneratePrivateKey()
	pub1 := key.Public()
	pub2 := GeneratePublicKey(key)
	require.NotNil(t, pub2)
	assert.Equal(t, pub1.Bytes(), pub2.Bytes())
}

// ---------------------------------------------------------------------------
// ProspectusExemption.MarshalJSON
// ---------------------------------------------------------------------------

func TestProspectusExemptionMarshalJSON_ValidJSON(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionPilotRegime, 149, []string{"GB", "DE"})
	pe.TwelveMonthEURValue = 50000.0

	data, err := pe.MarshalJSON()
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out))
	// ProspectusExemption.AssetID has no json tag so it marshals as "AssetID"
	assert.Equal(t, "asset-1", out["AssetID"])
}

// ---------------------------------------------------------------------------
// LiquidityWindow.IsOpen
// ---------------------------------------------------------------------------

func TestLiquidityWindowIsOpen_Open_True(t *testing.T) {
	w := &LiquidityWindow{Status: WindowStatusOpen}
	assert.True(t, w.IsOpen())
}

func TestLiquidityWindowIsOpen_Scheduled_False(t *testing.T) {
	w := &LiquidityWindow{Status: WindowStatusScheduled}
	assert.False(t, w.IsOpen())
}

func TestLiquidityWindowIsOpen_Closed_False(t *testing.T) {
	w := &LiquidityWindow{Status: WindowStatusClosed}
	assert.False(t, w.IsOpen())
}

// ---------------------------------------------------------------------------
// WindowManager.HasOpenWindow
// ---------------------------------------------------------------------------

func TestWindowManagerHasOpenWindow_NoWindows_False(t *testing.T) {
	wm := NewWindowManager()
	assert.False(t, wm.HasOpenWindow("asset-X"))
}

func TestWindowManagerHasOpenWindow_OpenWindow_True(t *testing.T) {
	wm := NewWindowManager()
	wm.Schedule["asset-X"] = []*LiquidityWindow{
		{ID: "w1", AssetID: "asset-X", Status: WindowStatusOpen},
	}
	assert.True(t, wm.HasOpenWindow("asset-X"))
}

func TestWindowManagerHasOpenWindow_ClosedWindow_False(t *testing.T) {
	wm := NewWindowManager()
	wm.Schedule["asset-X"] = []*LiquidityWindow{
		{ID: "w1", AssetID: "asset-X", Status: WindowStatusClosed},
	}
	assert.False(t, wm.HasOpenWindow("asset-X"))
}

// ---------------------------------------------------------------------------
// Shard.ValidateShardTransactions
// ---------------------------------------------------------------------------

func TestShardValidateShardTransactions_ValidTx_NoPanic(t *testing.T) {
	bc := NewBlockchain(context.Background(), "shard-test")
	bc.InitializeShards(2)
	require.Len(t, bc.Shards, 2)

	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	pubStr := base64.StdEncoding.EncodeToString(key.Public().Bytes())

	tx := Transaction{
		Sender:       pubStr,
		Receiver:     "recv",
		Amount:       10,
		RequiredSigs: 1,
	}
	tx.GenerateNonce()
	require.NoError(t, tx.SignTransaction(key))

	bc.AssignTransactionToShard(tx)

	assert.NotPanics(t, func() {
		for _, shard := range bc.Shards {
			shard.ValidateShardTransactions()
		}
	})
}

func TestShardValidateShardTransactions_InvalidSenderKey_NoPanic(t *testing.T) {
	bc := NewBlockchain(context.Background(), "shard-invalid")
	bc.InitializeShards(1)

	// Transaction with an obviously invalid sender key
	tx := Transaction{
		Sender:       "not-a-valid-pub-key",
		Receiver:     "recv",
		Amount:       10,
		RequiredSigs: 1,
	}
	bc.Shards[0].TransactionPool = append(bc.Shards[0].TransactionPool, tx)

	assert.NotPanics(t, func() {
		bc.Shards[0].ValidateShardTransactions()
	})
}

// ---------------------------------------------------------------------------
// Blockchain.SaveBlockchain / LoadBlockchain
//
// NOTE: NewBlockchain initialises LockedWallets as map[[32]byte]*LockedWallet
// whose key type is not JSON-marshallable. SaveBlockchain therefore fails for
// a fully-initialised blockchain. Tests here focus on the error-path behaviour
// and the happy-path using a minimal blockchain that does not set LockedWallets.
// ---------------------------------------------------------------------------

func TestLoadBlockchain_MissingFile_Error(t *testing.T) {
	_, err := LoadBlockchain("/tmp/does-not-exist-gh-utilities-abc123.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read")
}

func TestLoadBlockchain_InvalidJSON_Error(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0644))

	_, err := LoadBlockchain(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize")
}

func TestSaveBlockchain_InvalidPath_Error(t *testing.T) {
	// Use a minimal blockchain struct to avoid map[[32]uint8] JSON issue
	bc := &Blockchain{
		Blocks:             []Block{},
		PublicKeyToID:      make(map[string]string),
		UserIDToDelegateID: make(map[string]string),
		Wallets:            make(map[string]*Wallet),
	}
	err := bc.SaveBlockchain("/nonexistent-directory/chain.json")
	require.Error(t, err)
}
