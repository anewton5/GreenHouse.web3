package gonetwork

// ---------------------------------------------------------------------------
// allowlist_manifest_test.go — Item 4: AllowlistGater make functional
//
// Covers:
//   PublicKeyFromHex     — valid / invalid hex / wrong-length decoding
//   LoadPeerManifest     — happy path, missing file, invalid JSON,
//                          invalid signature (skipped with warning),
//                          registry key not configured
//   NetworkRegistryKey   — loaded from GREENHOUSE_REGISTRY_PUBKEY in
//                          NewBlockchain; absent key leaves field nil
// ---------------------------------------------------------------------------

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/sha3"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// realPeerID generates a real libp2p Ed25519 peer ID suitable for use in
// manifest entries (peer.Decode can round-trip these).
func realPeerID(t *testing.T) peer.ID {
	t.Helper()
	priv, _, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	id, err := peer.IDFromPrivateKey(priv)
	require.NoError(t, err)
	return id
}

// ---------------------------------------------------------------------------
// PublicKeyFromHex
// ---------------------------------------------------------------------------

// TestPublicKeyFromHex_Valid verifies that a 64-char lowercase hex string
// round-trips through PublicKeyFromHex correctly.
func TestPublicKeyFromHex_Valid(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	hexStr := hex.EncodeToString(privKey.Public().Bytes())
	got, err := PublicKeyFromHex(hexStr)
	require.NoError(t, err)
	assert.Equal(t, privKey.Public().Bytes(), got.Bytes())
}

// TestPublicKeyFromHex_InvalidHex verifies that non-hex input is rejected.
func TestPublicKeyFromHex_InvalidHex(t *testing.T) {
	_, err := PublicKeyFromHex("not-valid-hex!!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hex-encoded public key")
}

// TestPublicKeyFromHex_WrongLength verifies that a hex string whose decoded
// length is not 32 bytes is rejected.
func TestPublicKeyFromHex_WrongLength(t *testing.T) {
	// 16 bytes = 32 hex chars — too short for an Ed25519 key
	_, err := PublicKeyFromHex(hex.EncodeToString(make([]byte, 16)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key length")
}

// ---------------------------------------------------------------------------
// LoadPeerManifest
// ---------------------------------------------------------------------------

// writeTempManifest serialises entries to a temp file and returns its path.
func writeTempManifest(t *testing.T, entries interface{}) string {
	t.Helper()
	data, err := json.Marshal(entries)
	require.NoError(t, err)
	f, err := os.CreateTemp(t.TempDir(), "peers-*.json")
	require.NoError(t, err)
	_, err = f.Write(data)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// signedEntry returns a manifest entry whose signature is valid for registryKey.
func signedEntry(t *testing.T, registryKey *PrivateKey, id peer.ID) map[string]string {
	t.Helper()
	hash := sha3.Sum256([]byte(id))
	sig := registryKey.Sign(hash[:]).Bytes()
	return map[string]string{
		"peer_id":   id.String(),
		"signature": hex.EncodeToString(sig),
	}
}

// TestLoadPeerManifest_Valid verifies that a correctly signed manifest
// pre-populates the gater and listed peers are admitted.
func TestLoadPeerManifest_Valid(t *testing.T) {
	registryKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	gater := NewAllowlistGater(registryKey.Public())

	peerA := realPeerID(t)
	peerB := realPeerID(t)

	entries := []map[string]string{
		signedEntry(t, registryKey, peerA),
		signedEntry(t, registryKey, peerB),
	}
	path := writeTempManifest(t, entries)

	require.NoError(t, LoadPeerManifest(path, gater))

	// Both peers must be admitted; the gater is now in permissioned mode.
	assert.True(t, gater.InterceptPeerDial(peerA), "peerA should be admitted")
	assert.True(t, gater.InterceptPeerDial(peerB), "peerB should be admitted")

	// An unlisted peer must be rejected.
	unlisted := realPeerID(t)
	assert.False(t, gater.InterceptPeerDial(unlisted), "unlisted peer should be blocked")
}

// TestLoadPeerManifest_MissingFile verifies that a non-existent path returns
// an error (not a panic).
func TestLoadPeerManifest_MissingFile(t *testing.T) {
	gater := NewAllowlistGater(nil)
	err := LoadPeerManifest(filepath.Join(t.TempDir(), "no-such-file.json"), gater)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot open")
}

// TestLoadPeerManifest_InvalidJSON verifies that a file with malformed JSON
// returns a parse error.
func TestLoadPeerManifest_InvalidJSON(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bad-*.json")
	require.NoError(t, err)
	_, err = f.WriteString("{not valid json}")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	gater := NewAllowlistGater(nil)
	err = LoadPeerManifest(f.Name(), gater)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot parse")
}

// TestLoadPeerManifest_SkipsInvalidSig verifies that an entry with a wrong
// signature is skipped (warning logged) and the valid entry is still admitted.
func TestLoadPeerManifest_SkipsInvalidSig(t *testing.T) {
	registryKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	attackerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	gater := NewAllowlistGater(registryKey.Public())

	goodPeer := realPeerID(t)
	badPeer := realPeerID(t)

	badHash := sha3.Sum256([]byte(badPeer))
	badSig := attackerKey.Sign(badHash[:]).Bytes() // wrong key

	entries := []map[string]string{
		signedEntry(t, registryKey, goodPeer),
		{"peer_id": badPeer.String(), "signature": hex.EncodeToString(badSig)},
	}
	path := writeTempManifest(t, entries)

	// LoadPeerManifest must succeed (file and JSON are valid).
	require.NoError(t, LoadPeerManifest(path, gater))

	assert.True(t, gater.InterceptPeerDial(goodPeer), "valid peer should be admitted")
	assert.False(t, gater.InterceptPeerDial(badPeer), "bad-sig peer should not be admitted")
}

// TestLoadPeerManifest_NoRegistryKey verifies that entries are skipped when
// the gater has no registry key (open-mode gater), but the file parse still
// succeeds (no error returned — open mode means no signing required but
// AllowPeer returns an error which LoadPeerManifest logs and skips).
func TestLoadPeerManifest_NoRegistryKey(t *testing.T) {
	registryKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	// Open-mode gater (nil registry key) cannot verify signatures.
	gater := NewAllowlistGater(nil)

	peerA := realPeerID(t)
	entries := []map[string]string{signedEntry(t, registryKey, peerA)}
	path := writeTempManifest(t, entries)

	// Should not error — invalid entries are skipped with a warning.
	require.NoError(t, LoadPeerManifest(path, gater))

	// Open-mode gater (no entries admitted) must remain open.
	assert.True(t, gater.InterceptPeerDial(peerA), "open-mode gater permits all peers")
}

// ---------------------------------------------------------------------------
// NetworkRegistryKey loaded by NewBlockchain
// ---------------------------------------------------------------------------

// TestNetworkRegistryKey_LoadedFromEnv verifies that NewBlockchain reads
// GREENHOUSE_REGISTRY_PUBKEY and populates bc.NetworkRegistryKey.
func TestNetworkRegistryKey_LoadedFromEnv(t *testing.T) {
	regKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	t.Setenv("GREENHOUSE_REGISTRY_PUBKEY", hex.EncodeToString(regKey.Public().Bytes()))

	bc := newTestBlockchain(t)
	require.NotNil(t, bc.NetworkRegistryKey, "NetworkRegistryKey must be populated from env")
	assert.Equal(t, regKey.Public().Bytes(), bc.NetworkRegistryKey.Bytes())
}

// TestNetworkRegistryKey_AbsentEnvIsNil verifies that an unset
// GREENHOUSE_REGISTRY_PUBKEY leaves NetworkRegistryKey nil (open mode).
func TestNetworkRegistryKey_AbsentEnvIsNil(t *testing.T) {
	t.Setenv("GREENHOUSE_REGISTRY_PUBKEY", "")
	bc := newTestBlockchain(t)
	assert.Nil(t, bc.NetworkRegistryKey, "no env var → open mode → nil key")
}
