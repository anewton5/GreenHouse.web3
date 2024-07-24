package gonetwork

import (
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
