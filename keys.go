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
	"strings"

	"golang.org/x/crypto/argon2"
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

// NewPrivateKeyFromSeed creates a PrivateKey from a 32-byte seed.
func NewPrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) != seedLen {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", seedLen, len(seed))
	}
	return &PrivateKey{key: ed25519.NewKeyFromSeed(seed)}, nil
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
	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(pubKeyStr)
	if err != nil {
		// fall back to standard base64 for backwards compatibility
		pubKeyBytes, err = base64.StdEncoding.DecodeString(pubKeyStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key from base64: %w", err)
		}
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

// keyEncryptionVersion prefixes ciphertext produced by the current scheme
// (AES-256-GCM + Argon2id KDF) so that DecryptPrivateKey can detect and
// gracefully fall back to the legacy AES-128-CFB scheme for old keys.
const keyEncryptionVersion = "v2:"

// argon2id parameters — tuned for interactive use (OWASP recommendation):
// time=3 iterations, memory=65536 KiB (64 MiB), parallelism=4, output=32 B.
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MiB in KiB
	argon2Threads = 4
	argon2KeyLen  = 32
	saltLen       = 16
)

// EncryptPrivateKey encrypts a private key seed using AES-256-GCM with an
// Argon2id-derived key. The output is a version-prefixed hex string:
//
//	"v2:" + hex( salt(16B) || nonce(12B) || ciphertext+tag )
//
// The passphrase is passed through Argon2id before being used as an AES key,
// so there is no requirement on passphrase length or entropy level.
func EncryptPrivateKey(key []byte, passphrase string) (string, error) {
	// Generate a random 16-byte salt for Argon2id.
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("EncryptPrivateKey: failed to generate salt: %w", err)
	}

	// Derive a 256-bit AES key from the passphrase.
	aesKey := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Encrypt with AES-256-GCM (provides confidentiality + integrity).
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("EncryptPrivateKey: cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("EncryptPrivateKey: GCM init: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("EncryptPrivateKey: failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, key, nil)

	// Encode as: "v2:" + hex(salt || nonce || ciphertext+tag)
	blob := append(append(salt, nonce...), ciphertext...)
	return keyEncryptionVersion + hex.EncodeToString(blob), nil
}

// DecryptPrivateKey decrypts a private key seed produced by EncryptPrivateKey.
// It detects the key format by the "v2:" prefix and falls back to the legacy
// AES-128-CFB scheme for keys encrypted by older versions of the software.
func DecryptPrivateKey(encryptedKey string, passphrase string) ([]byte, error) {
	if strings.HasPrefix(encryptedKey, keyEncryptionVersion) {
		return decryptPrivateKeyV2(encryptedKey[len(keyEncryptionVersion):], passphrase)
	}
	// Legacy path: AES-128-CFB without KDF (deprecated; kept for migration only).
	return decryptPrivateKeyLegacy(encryptedKey, passphrase)
}

// decryptPrivateKeyV2 decrypts a v2-format key (AES-256-GCM + Argon2id).
func decryptPrivateKeyV2(hexBlob string, passphrase string) ([]byte, error) {
	blob, err := hex.DecodeString(hexBlob)
	if err != nil {
		return nil, fmt.Errorf("DecryptPrivateKey(v2): invalid hex encoding: %w", err)
	}

	const nonceLen = 12 // GCM standard nonce size
	if len(blob) < saltLen+nonceLen {
		return nil, fmt.Errorf("DecryptPrivateKey(v2): ciphertext too short")
	}

	salt := blob[:saltLen]
	nonce := blob[saltLen : saltLen+nonceLen]
	ciphertext := blob[saltLen+nonceLen:]

	aesKey := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("DecryptPrivateKey(v2): cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("DecryptPrivateKey(v2): GCM init: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("DecryptPrivateKey(v2): authentication failed (wrong passphrase?): %w", err)
	}
	return plaintext, nil
}

// decryptPrivateKeyLegacy decrypts a key encrypted with the old AES-128-CFB
// scheme (no KDF). Kept only for migrating existing encrypted keys.
func decryptPrivateKeyLegacy(encryptedKey string, passphrase string) ([]byte, error) {
	ciphertext, err := hex.DecodeString(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("DecryptPrivateKey(legacy): invalid hex: %w", err)
	}
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("DecryptPrivateKey(legacy): ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}
