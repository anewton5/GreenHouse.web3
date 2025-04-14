package gonetwork

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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
func GeneratePublicKey(privateKey *PrivateKey) *PublicKey {
	pubKey := privateKey.key.Public()
	if pubKey == nil {
		return nil
	}
	return &PublicKey{key: pubKey.(ed25519.PublicKey)}
}

func EncryptPrivateKey(key []byte, passphrase string) (string, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(key))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], key)

	return hex.EncodeToString(ciphertext), nil
}

func DecryptPrivateKey(encryptedKey string, passphrase string) ([]byte, error) {
	ciphertext, _ := hex.DecodeString(encryptedKey)
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}
