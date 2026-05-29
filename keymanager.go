package gonetwork

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// KeyProvider interface
// ---------------------------------------------------------------------------

// KeyProvider abstracts key storage and signing operations.
// LocalKeyProvider uses the existing in-memory PrivateKey.
// KMSKeyProvider is a stub that records intended API calls; replace the body
// of Sign / Verify with real AWS KMS SDK calls when KMS onboarding is complete.
type KeyProvider interface {
	// PublicKeyString returns the base64-encoded Ed25519 public key.
	PublicKeyString() string

	// Sign returns an Ed25519 signature over msg.
	// For KMSKeyProvider this will invoke the AWS KMS Sign API.
	Sign(msg []byte) ([]byte, error)

	// Verify returns true if sig is a valid Ed25519 signature of msg under
	// this provider's key.
	Verify(msg, sig []byte) bool
}

// ---------------------------------------------------------------------------
// LocalKeyProvider
// ---------------------------------------------------------------------------

// LocalKeyProvider implements KeyProvider using an in-memory Ed25519 PrivateKey.
type LocalKeyProvider struct {
	key *PrivateKey
}

// NewLocalKeyProvider wraps an existing PrivateKey in a LocalKeyProvider.
func NewLocalKeyProvider(key *PrivateKey) *LocalKeyProvider {
	return &LocalKeyProvider{key: key}
}

// PublicKeyString returns the base64-encoded public key string.
func (p *LocalKeyProvider) PublicKeyString() string {
	return base64.StdEncoding.EncodeToString(p.key.Public().Bytes())
}

// Sign signs msg with the in-memory private key and returns the raw signature bytes.
func (p *LocalKeyProvider) Sign(msg []byte) ([]byte, error) {
	return p.key.Sign(msg).Bytes(), nil
}

// Verify checks whether sig is a valid Ed25519 signature of msg under this
// provider's key.
func (p *LocalKeyProvider) Verify(msg, sig []byte) bool {
	s := &Signature{value: sig}
	return s.Verify(p.key.Public(), msg)
}

// ---------------------------------------------------------------------------
// KMSKeyProvider (stub)
// ---------------------------------------------------------------------------

// KMSKeyProvider is a production stub for managed key storage and signing.
//
// Deprecated: AWS KMS does not support raw Ed25519 signing. Use VaultKeyProvider
// (HashiCorp Vault Transit / Google Cloud KMS with EC_SIGN_ED25519) or
// NewLocalKeyProviderFromEncryptedFile for file-based key storage instead.
// This type is retained to avoid breaking existing configurations; its Sign
// method always returns an error rather than silently producing a nil signature.
//
// AWS KMS does NOT support Ed25519. If you choose AWS, you must migrate the
// signing scheme to ECDSA P-256 throughout the codebase — a significant change.
//
// Recommended production paths that preserve Ed25519:
//
//   - HashiCorp Vault Transit secrets engine (free, self-hosted alongside the
//     bootstrap node, native Ed25519 support via the "ed25519" key type).
//   - Google Cloud KMS (managed service, ~$0.006/key/month, native Ed25519
//     support via the "EC_SIGN_ED25519" key spec).
//
// To implement: replace the Sign and Verify bodies below with the corresponding
// SDK calls for your chosen provider. The interface and call sites remain unchanged.
type KMSKeyProvider struct {
	KeyARN    string
	KeyID     string
	PublicKey string // cached from KMS DescribeKey; empty until populated
	Calls     []string
}

// NewKMSKeyProvider creates a KMSKeyProvider for the given AWS KMS key ARN.
func NewKMSKeyProvider(keyARN string) *KMSKeyProvider {
	return &KMSKeyProvider{
		KeyARN: keyARN,
		KeyID:  keyARN,
	}
}

// PublicKeyString returns the cached public key string (populated on first use in production).
func (p *KMSKeyProvider) PublicKeyString() string {
	return p.PublicKey
}

// Sign returns an explicit error so callers fail loudly instead of silently
// propagating nil signatures. Production code must swap KMSKeyProvider for
// VaultKeyProvider or LocalKeyProvider before enabling signing paths.
func (p *KMSKeyProvider) Sign(msg []byte) ([]byte, error) {
	p.Calls = append(p.Calls, "Sign")
	return nil, fmt.Errorf("KMSKeyProvider.Sign is not implemented: configure VaultKeyProvider or LocalKeyProvider for signing (H-2)")
}

// Verify returns false so callers reject signatures from the stub rather than
// accepting them silently.
func (p *KMSKeyProvider) Verify(msg, sig []byte) bool {
	p.Calls = append(p.Calls, "Verify")
	return false
}

// ---------------------------------------------------------------------------
// VaultKeyProvider
// ---------------------------------------------------------------------------

// VaultKeyProvider implements KeyProvider using the HashiCorp Vault Transit
// secrets engine with an Ed25519 key. All signing and verification operations
// are delegated to Vault; the private key never leaves the server.
//
// One-time Vault setup:
//
//	vault secrets enable transit
//	vault write transit/keys/greenhouse-node type=ed25519
//
// Required Vault policy:
//
//	path "transit/sign/greenhouse-node"   { capabilities = ["update"] }
//	path "transit/verify/greenhouse-node" { capabilities = ["update"] }
//	path "transit/keys/greenhouse-node"   { capabilities = ["read"]   }
//
// Environment variables read by NewVaultKeyProviderFromEnv:
//
//	VAULT_ADDR  — Vault server address (e.g. "http://127.0.0.1:8200")
//	VAULT_TOKEN — Vault token with the policy above
type VaultKeyProvider struct {
	address   string // Vault server base URL, e.g. "http://127.0.0.1:8200"
	token     string // Vault auth token
	keyName   string // Transit key name, e.g. "greenhouse-node"
	mountPath string // Transit mount path; defaults to "transit"
	cachedPub string // lazily populated base64-encoded public key (32 raw bytes)
	client    *http.Client
}

// NewVaultKeyProviderFromEnv creates a VaultKeyProvider from the VAULT_ADDR and
// VAULT_TOKEN environment variables. keyName is the Transit key name to use.
func NewVaultKeyProviderFromEnv(keyName string) (*VaultKeyProvider, error) {
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		return nil, fmt.Errorf("vault: VAULT_ADDR and VAULT_TOKEN must be set")
	}
	return NewVaultKeyProvider(addr, token, keyName)
}

// NewVaultKeyProvider creates a VaultKeyProvider with explicit credentials.
// mountPath defaults to "transit". address must not have a trailing slash.
func NewVaultKeyProvider(address, token, keyName string) (*VaultKeyProvider, error) {
	if address == "" {
		return nil, fmt.Errorf("vault: address must not be empty")
	}
	if token == "" {
		return nil, fmt.Errorf("vault: token must not be empty")
	}
	if keyName == "" {
		return nil, fmt.Errorf("vault: keyName must not be empty")
	}
	return &VaultKeyProvider{
		address:   strings.TrimRight(address, "/"),
		token:     token,
		keyName:   keyName,
		mountPath: "transit",
		client:    &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// PublicKeyString returns the base64-encoded raw Ed25519 public key (32 bytes).
// The result is fetched from Vault on first call and cached for subsequent calls.
func (v *VaultKeyProvider) PublicKeyString() string {
	if v.cachedPub != "" {
		return v.cachedPub
	}
	pub, err := v.fetchPublicKey()
	if err != nil {
		return ""
	}
	v.cachedPub = pub
	return v.cachedPub
}

// Sign asks Vault Transit to sign msg and returns the raw 64-byte Ed25519
// signature. The private key never leaves Vault.
func (v *VaultKeyProvider) Sign(msg []byte) ([]byte, error) {
	body, _ := json.Marshal(map[string]any{
		"input": base64.StdEncoding.EncodeToString(msg),
	})
	endpoint := fmt.Sprintf("%s/v1/%s/sign/%s", v.address, v.mountPath, v.keyName)
	data, err := v.vaultPost(endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("vault: sign request failed: %w", err)
	}
	sigStr, ok := data["signature"].(string)
	if !ok || sigStr == "" {
		return nil, fmt.Errorf("vault: sign response missing signature field")
	}
	// Vault Transit signature format: "vault:v1:<base64>"
	parts := strings.SplitN(sigStr, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("vault: unexpected signature format: %s", sigStr)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("vault: failed to decode signature bytes: %w", err)
	}
	return raw, nil
}

// Verify asks Vault Transit to verify sig over msg. sig must be the raw 64-byte
// Ed25519 signature as returned by Sign.
func (v *VaultKeyProvider) Verify(msg, sig []byte) bool {
	body, _ := json.Marshal(map[string]any{
		"input":     base64.StdEncoding.EncodeToString(msg),
		"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig),
	})
	endpoint := fmt.Sprintf("%s/v1/%s/verify/%s", v.address, v.mountPath, v.keyName)
	data, err := v.vaultPost(endpoint, body)
	if err != nil {
		return false
	}
	valid, _ := data["valid"].(bool)
	return valid
}

// vaultPost sends a POST request to endpoint with a JSON body, attaches the
// Vault token header, and returns the parsed data map from the response envelope.
func (v *VaultKeyProvider) vaultPost(endpoint string, body []byte) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")

	res, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("vault: API returned %d: %s", res.StatusCode, string(b))
	}
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("vault: failed to decode response: %w", err)
	}
	return envelope.Data, nil
}

// fetchPublicKey retrieves the Ed25519 public key from the Vault Transit keys
// endpoint, parses the PEM SubjectPublicKeyInfo, and returns the raw 32-byte
// key as a standard base64 string.
func (v *VaultKeyProvider) fetchPublicKey() (string, error) {
	endpoint := fmt.Sprintf("%s/v1/%s/keys/%s", v.address, v.mountPath, v.keyName)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", v.token)

	res, err := v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault: fetch key request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		return "", fmt.Errorf("vault: fetch key returned %d: %s", res.StatusCode, string(b))
	}
	var envelope struct {
		Data struct {
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&envelope); err != nil {
		return "", fmt.Errorf("vault: failed to decode key response: %w", err)
	}
	var pemStr string
	for _, kv := range envelope.Data.Keys {
		if kv.PublicKey != "" {
			pemStr = kv.PublicKey
			break
		}
	}
	if pemStr == "" {
		return "", fmt.Errorf("vault: no public key found for key %s", v.keyName)
	}
	// Vault returns a PEM-encoded SubjectPublicKeyInfo block for Ed25519 keys.
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "", fmt.Errorf("vault: failed to decode PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("vault: failed to parse PKIX public key: %w", err)
	}
	ed25519Pub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("vault: key is not Ed25519")
	}
	return base64.StdEncoding.EncodeToString([]byte(ed25519Pub)), nil
}

// ---------------------------------------------------------------------------
// Package-level helper
// ---------------------------------------------------------------------------

// VerifySignatureBytes verifies an Ed25519 signature against a message using
// the given public key. Exported for use by sub-packages (e.g. api) that
// cannot construct the unexported Signature type directly.
func VerifySignatureBytes(pub *PublicKey, msg, sig []byte) bool {
	s := &Signature{value: sig}
	return s.Verify(pub, msg)
}

// NewLocalKeyProviderFromEncryptedFile reads an AES-256-GCM encrypted Ed25519
// private key from path and returns a LocalKeyProvider ready for signing.
// The file must contain the output of EncryptPrivateKey — a "v2:"-prefixed
// hex string produced by the Argon2id + AES-256-GCM scheme in keys.go.
//
// Typical operator workflow:
//
//	// One-time: encrypt and persist the key
//	encrypted, err := gonetwork.EncryptPrivateKey(privKey.Bytes(), passphrase)
//	os.WriteFile("/etc/greenhouse/operator.key", []byte(encrypted), 0600)
//
//	// At node startup:
//	provider, err := gonetwork.NewLocalKeyProviderFromEncryptedFile(
//	    "/etc/greenhouse/operator.key", os.Getenv("GH_OPERATOR_PASSPHRASE"))
//	bc.OperatorKeyProvider = provider
func NewLocalKeyProviderFromEncryptedFile(path, passphrase string) (*LocalKeyProvider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("NewLocalKeyProviderFromEncryptedFile: cannot read %s: %w", path, err)
	}
	encryptedKey := strings.TrimSpace(string(data))
	seed, err := DecryptPrivateKey(encryptedKey, passphrase)
	if err != nil {
		return nil, fmt.Errorf("NewLocalKeyProviderFromEncryptedFile: decryption failed: %w", err)
	}
	privKey, err := NewPrivateKeyFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("NewLocalKeyProviderFromEncryptedFile: invalid key seed (expected %d bytes): %w", seedLen, err)
	}
	return NewLocalKeyProvider(privKey), nil
}
