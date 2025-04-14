package gonetwork

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	assert.NoError(t, err)
	assert.Equal(t, len(privKey.Bytes()), seedLen)
	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestPrivateKeySign(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	assert.NoError(t, err)
	msg := []byte("foo bar baz")
	sig := privKey.Sign(msg)
	assert.True(t, sig.Verify(privKey.Public(), msg))
}

func TestPublicKeyFromString(t *testing.T) {
	// Generate a valid key pair
	privateKey, _ := GeneratePrivateKey()
	publicKey := privateKey.Public()
	pubKeyStr := base64.StdEncoding.EncodeToString(publicKey.Bytes())

	// Test valid public key
	pubKey, err := PublicKeyFromString(pubKeyStr)
	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
	assert.Equal(t, publicKey.Bytes(), pubKey.Bytes())

	// Test invalid base64 string
	_, err = PublicKeyFromString("invalid_base64")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode public key from base64")

	// Test incorrect key length
	invalidKey := base64.StdEncoding.EncodeToString([]byte("short_key"))
	_, err = PublicKeyFromString(invalidKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key length")

	// Test invalid public key (32 bytes but not a valid ed25519 key)
	invalidPubKey := base64.StdEncoding.EncodeToString(make([]byte, pubKeyLen))
	_, err = PublicKeyFromString(invalidPubKey)
	assert.NoError(t, err) // This will pass because ed25519 keys are just byte slices of length 32
}
