package gonetwork

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TestLocalKeyProvider_SignVerify
// ---------------------------------------------------------------------------

func TestLocalKeyProvider_SignVerify(t *testing.T) {
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	provider := NewLocalKeyProvider(key)

	msg := []byte("test message for GreenHouse signing")
	sig, err := provider.Sign(msg)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	assert.True(t, provider.Verify(msg, sig), "signature over original message must verify")
	assert.False(t, provider.Verify([]byte("tampered"), sig), "signature must not verify against different message")
}

// ---------------------------------------------------------------------------
// TestLocalKeyProvider_CrossVerify
// ---------------------------------------------------------------------------

// TestLocalKeyProvider_CrossVerify ensures that a signature produced by
// LocalKeyProvider can be verified directly through VerifySignatureBytes,
// confirming interoperability with the raw public key.
func TestLocalKeyProvider_CrossVerify(t *testing.T) {
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	provider := NewLocalKeyProvider(key)

	msg := []byte("cross-verification test payload")
	sig, err := provider.Sign(msg)
	require.NoError(t, err)

	// Verify using the package-level helper (exported for api sub-package)
	assert.True(t, VerifySignatureBytes(key.Public(), msg, sig))

	// Different key must not verify
	other, err := GeneratePrivateKey()
	require.NoError(t, err)
	assert.False(t, VerifySignatureBytes(other.Public(), msg, sig))
}

// ---------------------------------------------------------------------------
// TestKMSKeyProvider_SignRecordsCall
// ---------------------------------------------------------------------------

func TestKMSKeyProvider_SignRecordsCall(t *testing.T) {
	p := NewKMSKeyProvider("arn:aws:kms:eu-west-1:123456789012:key/test-key-id")

	sig, err := p.Sign([]byte("payload"))
	require.Error(t, err) // H-2: stub returns explicit error to fail loudly
	assert.Nil(t, sig)    // stub returns nil signature
	assert.Contains(t, p.Calls, "Sign")
	assert.Len(t, p.Calls, 1)
}

// ---------------------------------------------------------------------------
// TestKMSKeyProvider_VerifyRecordsCall
// ---------------------------------------------------------------------------

func TestKMSKeyProvider_VerifyRecordsCall(t *testing.T) {
	p := NewKMSKeyProvider("arn:aws:kms:eu-west-1:123456789012:key/test-key-id")

	result := p.Verify([]byte("message"), nil)
	assert.False(t, result) // H-2: stub rejects signatures to prevent silent acceptance
	assert.Contains(t, p.Calls, "Verify")
	assert.Len(t, p.Calls, 1)
}

// ---------------------------------------------------------------------------
// TestKeyProvider_Interface
// ---------------------------------------------------------------------------

// TestKeyProvider_Interface ensures LocalKeyProvider satisfies the KeyProvider
// interface at compile time and that all interface methods work correctly.
func TestKeyProvider_Interface(t *testing.T) {
	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	// Assign concrete type to interface — compile-time check
	var provider KeyProvider = NewLocalKeyProvider(key)

	pubKey := provider.PublicKeyString()
	assert.NotEmpty(t, pubKey, "PublicKeyString must not be empty")

	msg := []byte("interface compliance test")
	sig, err := provider.Sign(msg)
	require.NoError(t, err)
	assert.True(t, provider.Verify(msg, sig))
}

// ---------------------------------------------------------------------------
// VaultKeyProvider helpers
// ---------------------------------------------------------------------------

// vaultMockServer starts an httptest.Server that handles Vault Transit API
// requests for the given keyName using a real in-process Ed25519 keypair.
// It returns the server and the public key so callers can verify signatures.
func vaultMockServer(t *testing.T, keyName string) (*httptest.Server, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/sign/"+keyName):
			var body struct {
				Input string `json:"input"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			msg, _ := base64.StdEncoding.DecodeString(body.Input)
			sig := ed25519.Sign(priv, msg)
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig),
				},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(path, "/verify/"+keyName):
			var body struct {
				Input     string `json:"input"`
				Signature string `json:"signature"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			msg, _ := base64.StdEncoding.DecodeString(body.Input)
			var valid bool
			parts := strings.SplitN(body.Signature, ":", 3)
			if len(parts) == 3 {
				sigBytes, _ := base64.StdEncoding.DecodeString(parts[2])
				valid = ed25519.Verify(pub, msg, sigBytes)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"valid": valid},
			})

		case r.Method == http.MethodGet && strings.HasSuffix(path, "/keys/"+keyName):
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"type": "ed25519",
					"keys": map[string]any{
						"1": map[string]any{"public_key": pubPEM},
					},
				},
			})

		default:
			http.NotFound(w, r)
		}
	}))
	return srv, pub
}

// ---------------------------------------------------------------------------
// TestVaultKeyProvider_New
// ---------------------------------------------------------------------------

func TestVaultKeyProvider_New_InvalidParams(t *testing.T) {
	_, err := NewVaultKeyProvider("", "token", "key")
	assert.Error(t, err, "empty address must be rejected")

	_, err = NewVaultKeyProvider("http://vault:8200", "", "key")
	assert.Error(t, err, "empty token must be rejected")

	_, err = NewVaultKeyProvider("http://vault:8200", "token", "")
	assert.Error(t, err, "empty keyName must be rejected")
}

func TestVaultKeyProvider_NewFromEnv_MissingCreds(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")
	_, err := NewVaultKeyProviderFromEnv("greenhouse-node")
	assert.Error(t, err)
}

func TestVaultKeyProvider_NewFromEnv_Valid(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	t.Setenv("VAULT_TOKEN", "test-token")
	p, err := NewVaultKeyProviderFromEnv("greenhouse-node")
	require.NoError(t, err)
	assert.NotNil(t, p)
}

// ---------------------------------------------------------------------------
// TestVaultKeyProvider_Sign
// ---------------------------------------------------------------------------

func TestVaultKeyProvider_Sign(t *testing.T) {
	srv, pub := vaultMockServer(t, "greenhouse-node")
	defer srv.Close()

	p, err := NewVaultKeyProvider(srv.URL, "test-token", "greenhouse-node")
	require.NoError(t, err)

	msg := []byte("hello GreenHouse")
	sig, err := p.Sign(msg)
	require.NoError(t, err)
	assert.Len(t, sig, ed25519.SignatureSize, "Ed25519 signature must be 64 bytes")
	assert.True(t, ed25519.Verify(pub, msg, sig), "signature must verify locally against the real public key")
}

func TestVaultKeyProvider_Sign_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"errors":["internal server error"]}`))
	}))
	defer srv.Close()

	p, err := NewVaultKeyProvider(srv.URL, "test-token", "greenhouse-node")
	require.NoError(t, err)

	_, err = p.Sign([]byte("payload"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestVaultKeyProvider_Sign_BadSignatureFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"signature": "malformed"},
		})
	}))
	defer srv.Close()

	p, err := NewVaultKeyProvider(srv.URL, "test-token", "greenhouse-node")
	require.NoError(t, err)

	_, err = p.Sign([]byte("payload"))
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// TestVaultKeyProvider_Verify
// ---------------------------------------------------------------------------

func TestVaultKeyProvider_Verify_Valid(t *testing.T) {
	srv, _ := vaultMockServer(t, "greenhouse-node")
	defer srv.Close()

	p, err := NewVaultKeyProvider(srv.URL, "test-token", "greenhouse-node")
	require.NoError(t, err)

	msg := []byte("valid signature test")
	sig, err := p.Sign(msg)
	require.NoError(t, err)

	assert.True(t, p.Verify(msg, sig), "freshly produced signature must verify")
}

func TestVaultKeyProvider_Verify_Invalid(t *testing.T) {
	srv, _ := vaultMockServer(t, "greenhouse-node")
	defer srv.Close()

	p, err := NewVaultKeyProvider(srv.URL, "test-token", "greenhouse-node")
	require.NoError(t, err)

	msg := []byte("original message")
	sig, err := p.Sign(msg)
	require.NoError(t, err)

	assert.False(t, p.Verify([]byte("tampered message"), sig), "signature must not verify against a different message")
}

func TestVaultKeyProvider_Verify_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	defer srv.Close()

	p, err := NewVaultKeyProvider(srv.URL, "test-token", "greenhouse-node")
	require.NoError(t, err)

	assert.False(t, p.Verify([]byte("msg"), make([]byte, 64)), "HTTP error must return false, not panic")
}

// ---------------------------------------------------------------------------
// TestVaultKeyProvider_PublicKeyString
// ---------------------------------------------------------------------------

func TestVaultKeyProvider_PublicKeyString(t *testing.T) {
	srv, pub := vaultMockServer(t, "greenhouse-node")
	defer srv.Close()

	p, err := NewVaultKeyProvider(srv.URL, "test-token", "greenhouse-node")
	require.NoError(t, err)

	pubStr := p.PublicKeyString()
	require.NotEmpty(t, pubStr)

	pubBytes, err := base64.StdEncoding.DecodeString(pubStr)
	require.NoError(t, err)
	assert.Equal(t, []byte(pub), pubBytes, "decoded public key bytes must match the mock server key")

	// Second call must use cache (same result, no additional HTTP requests)
	assert.Equal(t, pubStr, p.PublicKeyString(), "cached public key must be identical on repeated calls")
}

func TestVaultKeyProvider_PublicKeyString_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p, err := NewVaultKeyProvider(srv.URL, "test-token", "no-such-key")
	require.NoError(t, err)

	assert.Empty(t, p.PublicKeyString(), "HTTP error fetching key should return empty string")
}

// ---------------------------------------------------------------------------
// TestVaultKeyProvider_ImplementsKeyProvider
// ---------------------------------------------------------------------------

func TestVaultKeyProvider_ImplementsKeyProvider(t *testing.T) {
	srv, _ := vaultMockServer(t, "greenhouse-node")
	defer srv.Close()

	// Compile-time interface satisfaction check
	var _ KeyProvider = &VaultKeyProvider{}

	p, err := NewVaultKeyProvider(srv.URL, "test-token", "greenhouse-node")
	require.NoError(t, err)

	// Exercise all interface methods through the interface type
	var provider KeyProvider = p
	msg := []byte("vault interface roundtrip test")
	sig, err := provider.Sign(msg)
	require.NoError(t, err)
	assert.Len(t, sig, ed25519.SignatureSize)
	assert.True(t, provider.Verify(msg, sig))
	assert.NotEmpty(t, provider.PublicKeyString())
}

// ---------------------------------------------------------------------------
// TestNewLocalKeyProviderFromEncryptedFile
// ---------------------------------------------------------------------------

// TestNewLocalKeyProviderFromEncryptedFile_Roundtrip verifies the full
// encrypt→write→read→sign→verify lifecycle for file-based key storage.
func TestNewLocalKeyProviderFromEncryptedFile_Roundtrip(t *testing.T) {
	// Generate a fresh Ed25519 keypair.
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Wrap in our PrivateKey type and encrypt.
	privKey, err := NewPrivateKeyFromSeed(priv.Seed())
	require.NoError(t, err)

	const passphrase = "correct-horse-battery-staple"
	encrypted, err := EncryptPrivateKey(priv.Seed(), passphrase)
	require.NoError(t, err)

	// Write the ciphertext to a temp file.
	tmpFile := t.TempDir() + "/operator.key"
	err = os.WriteFile(tmpFile, []byte(encrypted), 0600)
	require.NoError(t, err)

	// Load via the new helper.
	provider, err := NewLocalKeyProviderFromEncryptedFile(tmpFile, passphrase)
	require.NoError(t, err)
	require.NotNil(t, provider)

	// Public key must match.
	origPubB64 := NewLocalKeyProvider(privKey).PublicKeyString()
	assert.Equal(t, origPubB64, provider.PublicKeyString(), "loaded public key must match original")

	// Sign and verify.
	msg := []byte("greenhouse operator roundtrip message")
	sig, err := provider.Sign(msg)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(pub, msg, sig), "signature must verify with original ed25519 public key")
	assert.True(t, provider.Verify(msg, sig), "provider.Verify must also return true")
}

// TestNewLocalKeyProviderFromEncryptedFile_WrongPassphrase verifies that an
// incorrect passphrase produces an error rather than a silently wrong key.
func TestNewLocalKeyProviderFromEncryptedFile_WrongPassphrase(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	encrypted, err := EncryptPrivateKey(priv.Seed(), "right-passphrase")
	require.NoError(t, err)

	tmpFile := t.TempDir() + "/operator.key"
	require.NoError(t, os.WriteFile(tmpFile, []byte(encrypted), 0600))

	_, err = NewLocalKeyProviderFromEncryptedFile(tmpFile, "wrong-passphrase")
	assert.Error(t, err, "wrong passphrase must be rejected")
	assert.Contains(t, err.Error(), "decryption failed")
}

// TestNewLocalKeyProviderFromEncryptedFile_MissingFile verifies that a clear
// error is returned when the key file does not exist.
func TestNewLocalKeyProviderFromEncryptedFile_MissingFile(t *testing.T) {
	_, err := NewLocalKeyProviderFromEncryptedFile("/nonexistent/path/operator.key", "passphrase")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot read")
}

// TestNewLocalKeyProviderFromEncryptedFile_FileWithTrailingNewline ensures that
// trailing whitespace in the key file is handled correctly.
func TestNewLocalKeyProviderFromEncryptedFile_FileWithTrailingNewline(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	encrypted, err := EncryptPrivateKey(priv.Seed(), "pass")
	require.NoError(t, err)

	tmpFile := t.TempDir() + "/operator.key"
	// Write with trailing newline as a text editor would.
	require.NoError(t, os.WriteFile(tmpFile, []byte(encrypted+"\n"), 0600))

	provider, err := NewLocalKeyProviderFromEncryptedFile(tmpFile, "pass")
	require.NoError(t, err, "trailing newline must not cause an error")
	assert.NotEmpty(t, provider.PublicKeyString())
}

// ---------------------------------------------------------------------------
// TestBlock_KeyVersionInPayloadHash
// ---------------------------------------------------------------------------

// TestBlock_KeyVersionInPayloadHash verifies that the KeyVersion field is
// included in the PayloadHash so that substituting the operator key after
// signing invalidates the hash.
func TestBlock_KeyVersionInPayloadHash(t *testing.T) {
	_, privA, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, privB, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	keyA, err := NewPrivateKeyFromSeed(privA.Seed())
	require.NoError(t, err)
	keyB, err := NewPrivateKeyFromSeed(privB.Seed())
	require.NoError(t, err)

	providerA := NewLocalKeyProvider(keyA)
	providerB := NewLocalKeyProvider(keyB)

	bc := NewBlockchain(context.Background(), "test")
	bc.OperatorKeyProvider = providerA

	bc.AddBlock(Block{Transactions: []Transaction{}})
	require.Len(t, bc.Blocks, 2) // index 0 = genesis, index 1 = our block

	blockWithA := bc.Blocks[1]
	assert.Equal(t, providerA.PublicKeyString(), blockWithA.KeyVersion,
		"KeyVersion must match the operator public key used at seal time")
	assert.NotEmpty(t, blockWithA.PayloadHash)

	// Build an equivalent block with keyB as the operator and confirm
	// the PayloadHash differs — KeyVersion is part of the signed payload.
	bc2 := NewBlockchain(context.Background(), "test2")
	bc2.OperatorKeyProvider = providerB
	bc2.AddBlock(Block{Transactions: []Transaction{}})
	require.Len(t, bc2.Blocks, 2)

	blockWithB := bc2.Blocks[1]
	assert.Equal(t, providerB.PublicKeyString(), blockWithB.KeyVersion)
	assert.NotEqual(t, blockWithA.PayloadHash, blockWithB.PayloadHash,
		"blocks sealed by different operators must have distinct PayloadHashes")
}
