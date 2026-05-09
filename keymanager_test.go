package gonetwork

import (
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
	require.NoError(t, err)    // stub returns no error
	assert.Nil(t, sig)         // stub returns nil signature
	assert.Contains(t, p.Calls, "Sign")
	assert.Len(t, p.Calls, 1)
}

// ---------------------------------------------------------------------------
// TestKMSKeyProvider_VerifyRecordsCall
// ---------------------------------------------------------------------------

func TestKMSKeyProvider_VerifyRecordsCall(t *testing.T) {
	p := NewKMSKeyProvider("arn:aws:kms:eu-west-1:123456789012:key/test-key-id")

	result := p.Verify([]byte("message"), nil)
	assert.True(t, result) // stub returns true
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
