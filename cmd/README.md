# GreenHouse Node — Operator Key Management

This directory contains the runnable binaries that form a GreenHouse node.

```
cmd/
├── api/        HTTP/WebSocket API gateway
├── bootstrap/  Bootstrap peer that seeds the P2P overlay
├── node/       Full consensus + persistence node
└── operator/   CLI tool for key generation and key rotation
```

---

## Wiring an OperatorKeyProvider

Every production node **must** set `bc.OperatorKeyProvider` before calling
`productionReadinessError` (called automatically at startup). Three options are
supported; choose the one that matches your deployment:

---

### Option 1 — File-based key (`NewLocalKeyProviderFromEncryptedFile`)

Best for: single-node pilots, CI/CD pipelines, and air-gapped deployments.

**Encrypt and persist the operator key once:**

```go
import "github.com/greenhouse/gonetwork"

// Generate a fresh Ed25519 keypair
privKey, err := gonetwork.GeneratePrivateKey()

// Encrypt with Argon2id + AES-256-GCM
encrypted, err := gonetwork.EncryptPrivateKey(privKey.Seed(), os.Getenv("GH_OPERATOR_PASSPHRASE"))

// Write to a file readable only by the node process (0600)
os.WriteFile("/etc/greenhouse/operator.key", []byte(encrypted), 0600)
```

**At node startup:**

```go
provider, err := gonetwork.NewLocalKeyProviderFromEncryptedFile(
    "/etc/greenhouse/operator.key",
    os.Getenv("GH_OPERATOR_PASSPHRASE"),
)
if err != nil {
    log.Fatalf("failed to load operator key: %v", err)
}
bc.OperatorKeyProvider = provider
```

**Security checklist:**
- Store `GH_OPERATOR_PASSPHRASE` in your secrets manager (Vault, AWS SSM, etc.),
  not in a `.env` file committed to version control.
- Restrict the key file: `chown greenhouse:greenhouse /etc/greenhouse/operator.key && chmod 600 ...`
- Rotate by re-running the encrypt step with a new keypair and restarting the node.

---

### Option 2 — HashiCorp Vault Transit (`VaultKeyProvider`)

Best for: multi-node production clusters requiring HSM-grade key isolation.

Vault Transit stores the private key inside Vault and performs signing server-side.
The node process never sees the raw private key bytes.

**Vault setup (one-time):**

```sh
# Enable the transit secrets engine
vault secrets enable transit

# Create an Ed25519 signing key named "greenhouse-node"
vault write -f transit/keys/greenhouse-node type=ed25519

# Create a policy that allows sign + verify but not export
vault policy write greenhouse-node - <<EOF
path "transit/sign/greenhouse-node"   { capabilities = ["update"] }
path "transit/verify/greenhouse-node" { capabilities = ["update"] }
path "transit/keys/greenhouse-node"   { capabilities = ["read"]   }
EOF

# Issue a token for the node
vault token create -policy=greenhouse-node -ttl=24h -renewable=true
```

**At node startup:**

```go
// Reads VAULT_ADDR and VAULT_TOKEN from environment
provider, err := gonetwork.NewVaultKeyProviderFromEnv("greenhouse-node")
if err != nil {
    log.Fatalf("vault key provider: %v", err)
}
bc.OperatorKeyProvider = provider
```

Or, with explicit values:

```go
provider, err := gonetwork.NewVaultKeyProvider(
    os.Getenv("VAULT_ADDR"),   // e.g. "https://vault.internal:8200"
    os.Getenv("VAULT_TOKEN"),  // short-lived, renewable token
    "greenhouse-node",         // key name in Vault Transit
)
```

**Security checklist:**
- Use AppRole or Kubernetes auth instead of token auth in production.
- Enable Vault audit logging for all signing operations.
- Set key `min_encryption_version` and `min_decryption_version` to enforce rotation.

---

### Option 3 — Google Cloud KMS (`EC_SIGN_ED25519`)

Best for: GCP-hosted deployments that prefer a managed service.

Create a key ring and a key version:

```sh
gcloud kms keyrings create greenhouse --location=global
gcloud kms keys create operator-node \
  --location=global \
  --keyring=greenhouse \
  --purpose=asymmetric-signing \
  --default-algorithm=ec-sign-ed25519
```

Implement `KeyProvider` using the [Cloud KMS Go client library][gcp-kms]:

```go
type GCPKMSKeyProvider struct { /* ... */ }
func (p *GCPKMSKeyProvider) Sign(msg []byte) ([]byte, error)   { /* call kmsClient.AsymmetricSign */ }
func (p *GCPKMSKeyProvider) Verify(msg, sig []byte) bool       { /* call kmsClient.GetPublicKey */ }
func (p *GCPKMSKeyProvider) PublicKeyString() string           { /* return cached base64 pubkey */ }
```

[gcp-kms]: https://pkg.go.dev/cloud.google.com/go/kms/apiv1

---

### Deprecated: `KMSKeyProvider` (AWS KMS)

`KMSKeyProvider` is **deprecated** and its `Sign` method always returns an error.
AWS KMS does not support raw Ed25519 signing. Use one of the three options above.

---

## Key Rotation

1. Generate a new keypair / Vault key version.
2. Update the node config (new file path or new Vault key version).
3. Restart the node. The next block produced will carry the new `KeyVersion`
   in its `PayloadHash`, preventing post-hoc key substitution.
4. Retain the old key for verifying historical blocks until the chain has
   sufficient depth beyond the rotation point.
