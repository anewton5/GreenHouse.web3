package gonetwork

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	privKeyLen = 64
	pubKeyLen  = 32
	seedLen    = 32
)

type PrivateKey struct {
	key ed25519.PrivateKey
}

func GeneratePrivateKey() (*PrivateKey, error) {
	seed := make([]byte, seedLen)
	_, err := io.ReadFull(rand.Reader, seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key seed: %w", err)
	}
	return &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}, nil
}

func (p *PrivateKey) Bytes() []byte {
	return p.key.Seed()
}

func (p *PrivateKey) Sign(msg []byte) *Signature {
	return &Signature{
		value: ed25519.Sign(p.key, msg),
	}
}

type PublicKey struct {
	key ed25519.PublicKey
}

type Signature struct {
	value []byte
}

func (p *PrivateKey) Public() *PublicKey {
	return &PublicKey{
		key: p.key.Public().(ed25519.PublicKey),
	}
}

func (p *PublicKey) Bytes() []byte {
	return p.key
}

func (s *Signature) Bytes() []byte {
	return s.value
}

func (s *Signature) Verify(pubKey *PublicKey, msg []byte) bool {
	return ed25519.Verify(pubKey.key, msg, s.value)
}

func PublicKeyFromString(pubKeyStr string) (*PublicKey, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key from base64: %w", err)
	}
	if len(pubKeyBytes) != pubKeyLen {
		return nil, fmt.Errorf("invalid public key length: expected %d bytes, got %d bytes", pubKeyLen, len(pubKeyBytes))
	}
	return &PublicKey{key: ed25519.PublicKey(pubKeyBytes)}, nil
}
