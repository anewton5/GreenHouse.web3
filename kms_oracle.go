package gonetwork

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// KMSOracleService
// ---------------------------------------------------------------------------

// KMSOracleService implements OracleService using AWS KMS envelope encryption.
//
// Design: the Ed25519 oracle private key seed is stored encrypted by a KMS CMK.
// At startup the seed is decrypted once and held in memory. All signing operations
// use the in-memory Ed25519 key — no KMS round-trip per signature (which would add
// ~30 ms latency per trade). The KMS CMK is used only to protect the seed at rest.
//
// Environment variables:
//
//	AWS_KMS_KEY_ARN               — ARN of the KMS Customer Master Key  (required)
//	AWS_KMS_ORACLE_KEY_B64        — base64(KMS-encrypted 32-byte Ed25519 seed) (required)
//	AWS_REGION                    — AWS region (optional; falls back to SDK default)
//
// Initial setup:
//  1. Generate a 32-byte random seed.
//  2. Call kms:Encrypt with the CMK ARN and the seed as plaintext.
//  3. base64-encode the ciphertext blob and set AWS_KMS_ORACLE_KEY_B64.
//
// Key rotation:
//
//	Repeat the initial setup with a new seed and restart the node. The old seed is
//	discarded — the new key signs all subsequent instructions.
type KMSOracleService struct {
	oracleKey *PrivateKey
	oraclePub *PublicKey
	keyARN    string
}

// NewKMSOracleService decrypts the oracle key seed from AWS KMS and returns a
// ready-to-use KMSOracleService. ctx is used only for the startup KMS call.
func NewKMSOracleService(ctx context.Context) (*KMSOracleService, error) {
	keyARN := os.Getenv("AWS_KMS_KEY_ARN")
	if keyARN == "" {
		return nil, fmt.Errorf("kms oracle: AWS_KMS_KEY_ARN environment variable is not set")
	}
	encryptedB64 := os.Getenv("AWS_KMS_ORACLE_KEY_B64")
	if encryptedB64 == "" {
		return nil, fmt.Errorf("kms oracle: AWS_KMS_ORACLE_KEY_B64 environment variable is not set")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return nil, fmt.Errorf("kms oracle: decode AWS_KMS_ORACLE_KEY_B64: %w", err)
	}

	// Load default AWS config (respects AWS_REGION, AWS_PROFILE, instance role, etc.)
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms oracle: load AWS config: %w", err)
	}

	client := kms.NewFromConfig(cfg)
	resp, err := client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: ciphertext,
		KeyId:          aws.String(keyARN),
	})
	if err != nil {
		return nil, fmt.Errorf("kms oracle: decrypt oracle key: %w", err)
	}

	if len(resp.Plaintext) != 32 {
		return nil, fmt.Errorf("kms oracle: expected 32-byte seed, got %d bytes", len(resp.Plaintext))
	}

	privKey, err := NewPrivateKeyFromSeed(resp.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("kms oracle: reconstruct private key: %w", err)
	}

	return &KMSOracleService{
		oracleKey: privKey,
		oraclePub: privKey.Public(),
		keyARN:    keyARN,
	}, nil
}

// OraclePublicKey returns the oracle's public key for external signature verification.
func (k *KMSOracleService) OraclePublicKey() *PublicKey {
	return k.oraclePub
}

// SignInstruction signs a PaymentInstruction and returns a copy with OracleSignature set.
// The signature covers all fields with OracleSignature set to nil.
func (k *KMSOracleService) SignInstruction(instruction *PaymentInstruction) (*PaymentInstruction, error) {
	if instruction == nil {
		return nil, fmt.Errorf("kms oracle: instruction must not be nil")
	}
	cp := *instruction
	cp.OracleSignature = nil
	data, err := json.Marshal(cp)
	if err != nil {
		return nil, fmt.Errorf("kms oracle: marshal instruction: %w", err)
	}
	hash := sha3.Sum256(data)
	signed := *instruction
	signed.OracleSignature = k.oracleKey.Sign(hash[:]).Bytes()
	return &signed, nil
}

// SignConfirmation signs a PaymentConfirmation and returns a copy with OracleSignature set.
func (k *KMSOracleService) SignConfirmation(confirmation *PaymentConfirmation) (*PaymentConfirmation, error) {
	if confirmation == nil {
		return nil, fmt.Errorf("kms oracle: confirmation must not be nil")
	}
	cp := *confirmation
	cp.OracleSignature = nil
	data, err := json.Marshal(cp)
	if err != nil {
		return nil, fmt.Errorf("kms oracle: marshal confirmation: %w", err)
	}
	hash := sha3.Sum256(data)
	signed := *confirmation
	signed.OracleSignature = k.oracleKey.Sign(hash[:]).Bytes()
	return &signed, nil
}

// VerifyInstruction verifies the oracle signature on a PaymentInstruction.
// Returns false if the instruction has been tampered with or the signature is missing.
func (k *KMSOracleService) VerifyInstruction(instruction *PaymentInstruction) bool {
	if instruction == nil || len(instruction.OracleSignature) == 0 {
		return false
	}
	cp := *instruction
	cp.OracleSignature = nil
	data, err := json.Marshal(cp)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: instruction.OracleSignature}
	return sig.Verify(k.oraclePub, hash[:])
}

// VerifyConfirmation verifies the oracle signature on a PaymentConfirmation.
// Returns false if the confirmation has been tampered with or the signature is missing.
func (k *KMSOracleService) VerifyConfirmation(confirmation *PaymentConfirmation) bool {
	if confirmation == nil || len(confirmation.OracleSignature) == 0 {
		return false
	}
	cp := *confirmation
	cp.OracleSignature = nil
	data, err := json.Marshal(cp)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: confirmation.OracleSignature}
	return sig.Verify(k.oraclePub, hash[:])
}
