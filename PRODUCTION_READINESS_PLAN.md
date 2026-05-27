# GreenHouse — Production Readiness Plan

> **Version:** 1.0
> **Date:** 26 May 2026
> **Scope:** `GreenHouse.web3` — the Go DLT engine
> **Status:** Pre-implementation — all items open
> **Author:** Architecture Review (AI-assisted four-domain audit)

This document records every production-readiness gap discovered during the May 2026 architecture audit of the GreenHouse private-markets DLT platform. It is the authoritative backlog for upgrading the implementation from a functional prototype to a production-grade deployment.

Gaps are organised into three phases ordered by severity and dependency. **Phase 1** must be completed before any production peer connects or any live trade is placed. **Phase 2** items will be inspected by the NCA during DLT TSS authorisation review. **Phase 3** items are hardening work that prevents degraded operation under adversarial or fault conditions.

Each item records: the gap identifier used in code comments, severity, root cause, the exact file and line(s) to change, the fix description, and the acceptance criteria.

---

## Summary Table

| #  | Phase | Area                                              | Severity     | Status |
|----|-------|---------------------------------------------------|--------------|--------|
| 1  | 1     | Persistence — state replay on startup             | **Critical** | Open   |
| 2  | 1     | Production guard — refuse mock services           | **Critical** | Open   |
| 3  | 1     | ConfirmAndSettle data race (webhook path)         | **Critical** | Open   |
| 4  | 1     | AllowlistGater — make functional                  | **Critical** | Open   |
| 5  | 1     | GossipSub topic validator                         | **Critical** | Open   |
| 6  | 1     | Block timestamp field                             | **High**     | Open   |
| 7  | 1     | Key management — require OperatorKeyProvider      | **Critical** | Open   |
| 8  | 2     | dBFT — real delegate Ed25519 signing              | **Critical** | Open   |
| 9  | 2     | dBFT — distributed view-change protocol           | **Critical** | Open   |
| 10 | 2     | dBFT — persist delegate set and WalletSequences   | **High**     | Open   |
| 11 | 2     | ValidateBlock — typed transaction verification    | **High**     | Open   |
| 12 | 2     | ResolveFork — require BFT supermajority proof     | **Critical** | Open   |
| 13 | 2     | Wire AML, Suitability, Jurisdiction into Validate | **High**     | Open   |
| 14 | 2     | Wire NCAReportingService into SealBlock           | **High**     | Open   |
| 15 | 2     | Fix PEP rescreening — mutex safety and context    | **High**     | Open   |
| 16 | 2     | STOR auto-creation in applyBlockState             | **High**     | Open   |
| 17 | 2     | P2P — disable DHT discovery in production         | **High**     | Open   |
| 18 | 2     | P2P — connection manager and GossipSub tuning     | **High**     | Open   |
| 19 | 2     | P2P — peer reconnect and full-mesh delegates      | **High**     | Open   |
| 20 | 2     | Explicit TLS/Noise transport enforcement          | **Medium**   | Open   |
| 21 | 3     | Shutdown safety — WaitGroup for DHT goroutine     | **Medium**   | Open   |
| 22 | 3     | Broadcast* use node lifecycle context             | **Medium**   | Open   |
| 23 | 3     | dBFT inbox capacity and dropped-message metrics   | **Medium**   | Open   |
| 24 | 3     | Unify block production paths                      | **Medium**   | Open   |
| 25 | 3     | BBolt key format fix and hot-backup               | **Medium**   | Open   |
| 26 | 3     | Payment provider retry and backoff                | **Medium**   | Open   |
| 27 | 3     | Settlement reversal mechanism                     | **Medium**   | Open   |
| 28 | 3     | Block signing peer verification                   | **High**     | Open   |
| 29 | 3     | DORA minimum viable implementation                | **Critical** | Open   |
| 30 | 3     | Compliance completeness (medium-priority items)   | **Medium**   | Open   |

---

## Phase 1 — Pre-Traffic Blockers

> These items must be completed before any production node accepts a live connection or any real asset transfer is placed. Each represents either a data-loss vector, a security bypass, or a financial integrity failure.

---

### Item 1 — Persistence: State Replay on Startup

**Gap IDs:** P-01, P-02, P-03
**Severity:** Critical
**Files:** `persistence.go`, `blockchain.go:1110`

#### Root Cause

`BlockStore` (BBolt) exists and `SaveBlock` is called in `SealBlock`, but it is never opened or wired in `NewBlockchain` (`blockchain.go:1110`). The `NewBlockchain` function leaves `bc.BlockStore = nil`. Consequently:

- Every node restart begins from genesis — zero blocks, zero holdings, zero assets, zero credentials.
- `WalletSequences` (the per-sender monotone nonce that prevents replay attacks) is reset to zero on every restart. An attacker who observed a signed transaction before a restart can resubmit it successfully.
- The BBolt `keyForIndex` key format may be inconsistent with `SaveBlock`'s format, so even if wired, iteration would not return blocks in correct chain order.

#### Fix

**Step A — Open BlockStore in NewBlockchain:**
In `NewBlockchain` (`blockchain.go:1110`), read the env var `GREENHOUSE_DB_PATH`. If set (and `GH_ENV=production`), call `OpenBlockStore(path)` and assign to `bc.BlockStore`. Fail with `log.Fatal` if the path is set but the file cannot be opened.

**Step B — State replay after load:**
After `store.LoadBlocks(bc)` populates `bc.Blocks`, iterate every block in ascending index order and call `applyBlockState(&block)` for each one. This reconstructs `bc.Holdings`, `bc.Assets`, `bc.Credentials`, `bc.Trades`, `bc.Delegates`, `bc.WalletSequences`, `bc.PendingSettlements`, and all other derived state from the immutable block log.

**Step C — Fix BBolt key format:**
In `persistence.go`, ensure `keyForIndex` uses `fmt.Sprintf("%010d", index)` — a zero-padded ten-digit decimal string — so BBolt's byte-ordered bucket iteration yields blocks in ascending chain order. Verify this matches the `SaveBlock` key format exactly.

**Step D — Rebuild WalletSequences during replay:**
As each block is replayed in Step B, for every `Transaction` in the block, set:
```go
bc.WalletSequences[tx.Sender] = max(bc.WalletSequences[tx.Sender], tx.Nonce)
```
This closes the post-restart replay window.

#### Acceptance Criteria

- Start a node, seal five blocks, shut down. Restart — the node loads all five blocks and `len(bc.Blocks) == 5`.
- `bc.Holdings`, `bc.Assets`, and `bc.Credentials` are fully populated immediately after `NewBlockchain` returns (no transactions needed to re-populate them).
- `bc.WalletSequences` contains the highest nonce per sender seen across all replayed blocks.
- Attempting to submit a transaction with a nonce ≤ the replayed value is rejected with `sequence number too low`.
- `go test -race ./...` continues to pass.

#### Dependencies

None. This is the foundation for Items 10, 12, and 24.

---

### Item 2 — Production Guard: Refuse Mock Services at Startup

**Gap IDs:** GAP-AML-01, GAP-KYC-01, PAY-01, KM-01
**Severity:** Critical
**Files:** `blockchain.go:1195–1209`, `onfido_identity.go:203`

#### Root Cause

`NewBlockchain` (`blockchain.go:1195–1209`) assigns `MockAMLScreener`, `MockPaymentProvider`, and `MockIdentityRegistry` unconditionally — there is no check for `GH_ENV`. A misconfigured production node will silently accept all AML checks (mock always returns `AMLSeverityClear`), process no real payments, and issue credentials against a non-persistent registry.

Additionally, `OnfidoIdentityRegistry.HandleWebhook` makes the HMAC verification of Onfido webhook events optional — if `ONFIDO_WEBHOOK_SECRET` is not set, it skips the HMAC check entirely (`onfido_identity.go:203`), allowing spoofed KYC approval webhooks.

#### Fix

**Step A — Startup guard in NewBlockchain:**
After the existing mock-assignment block (`blockchain.go:1195–1209`), add:

```go
if os.Getenv("GH_ENV") == "production" {
    if _, ok := bc.AMLScreener.(*MockAMLScreener); ok {
        log.Fatal("production: AMLScreener is MockAMLScreener — set a real screener before startup")
    }
    if _, ok := bc.PaymentProvider.(*MockPaymentProvider); ok {
        log.Fatal("production: PaymentProvider is MockPaymentProvider — set a real provider before startup")
    }
    if _, ok := bc.IdentityRegistry.(*MockIdentityRegistry); ok {
        log.Fatal("production: IdentityRegistry is MockIdentityRegistry — set a real registry before startup")
    }
    if bc.OperatorKeyProvider == nil {
        log.Fatal("production: OperatorKeyProvider is nil — set a key provider before startup")
    }
    if os.Getenv("ONFIDO_WEBHOOK_SECRET") == "" {
        log.Fatal("production: ONFIDO_WEBHOOK_SECRET is not set")
    }
}
```

**Step B — Enforce HMAC in OnfidoIdentityRegistry:**
In `onfido_identity.go:203`, change the HMAC check from `if secret != ""` (optional) to always performing the verification when the handler is invoked in production. Return HTTP 401 and do not process the event if the signature is absent or invalid.

#### Acceptance Criteria

- Running `GH_ENV=production` with default (mock) providers causes `log.Fatal` at startup with a clear message identifying which service is mocked.
- Running with all real providers and a valid `ONFIDO_WEBHOOK_SECRET` starts cleanly.
- An Onfido webhook with a missing or incorrect `X-SHA2-Signature` header returns HTTP 401 and does not create a credential.
- `go test -race ./...` continues to pass (tests use `GONETWORK_NO_P2P=1` and mocks via `newTestBlockchain(t)`; this guard only fires when `GH_ENV=production`).

#### Dependencies

Depends on Item 7 (the `OperatorKeyProvider` check references the interface set up there).

---

### Item 3 — ConfirmAndSettle Data Race (Webhook Path)

**Gap IDs:** PAY-02, PAY-03
**Severity:** Critical
**Files:** `blockchain.go:436`, `api/handlers.go:865,911,961`

#### Root Cause

`ConfirmAndSettle` (`blockchain.go:436`) is documented as "caller must hold `bc.Mu`" (`blockchain.go:154`). However, every webhook handler that calls it — Modulr (`api/handlers.go:865`), EURC (`api/handlers.go:911`), and Pontes (`api/handlers.go:961`) — calls it without acquiring the lock.

Two concurrent webhook deliveries for the same payment reference will both read `bc.PendingSettlements[reference]` before either has removed it, pass the idempotency check, and both apply the DVP asset transfer — doubling the buyer's holding and halving the seller's balance twice.

This is also a data race under the Go race detector: concurrent unsynchronised read/write of `bc.PendingSettlements`.

#### Fix

Remove the "caller must hold lock" contract from `ConfirmAndSettle`. Move `bc.Mu.Lock()/Unlock()` inside the function itself at `blockchain.go:436`:

```go
func (bc *Blockchain) ConfirmAndSettle(reference string, amount float64, currency string) error {
    bc.Mu.Lock()
    defer bc.Mu.Unlock()
    // ... existing body unchanged ...
}
```

Update the comment at `blockchain.go:154` to reflect the new contract. Remove any existing lock calls from the three webhook handlers in `api/handlers.go`.

The idempotency check (`if settlement.Status == "settled"`) already exists inside the function; acquiring the lock internally makes it atomic with respect to concurrent webhooks.

#### Acceptance Criteria

- Two goroutines calling `ConfirmAndSettle` with the same reference concurrently: only one applies the DVP transfer; the second returns `nil` (idempotent).
- `go test -race -count=3 ./...` produces no data-race report on `ConfirmAndSettle` or `bc.PendingSettlements`.
- Existing `ConfirmAndSettle` tests in `blockchain_extended_test.go` continue to pass.

#### Dependencies

None.

---

### Item 4 — AllowlistGater: Make Functional

**Gap IDs:** P2P GAP-01, P2P GAP-06
**Severity:** Critical
**Files:** `p2p.go`, `blockchain.go`

#### Root Cause

`NewAllowlistGater(nil)` is called in `NewP2PNode` because `NewBlockchain` does not pass a registry key. With `registryKey == nil`:

- `AllowPeer` always returns `"allowlist: registry key not configured"` — the allowlist can never be populated.
- `InterceptSecured` falls into the `len(g.allowed) == 0` branch and returns `true` — every peer on the internet is permanently admitted.
- The `MessageTypeAllowlistAdd` / `MessageTypeAllowlistRevoke` gossip path is structurally correct but permanently non-functional.

The result: the GreenHouse network has no access control at the P2P layer whatsoever. There is also no mechanism to pre-populate the allowlist from a static manifest at startup.

#### Fix

**Step A — Registry key:**
Add a `NetworkRegistryKey *PublicKey` field to `Blockchain`. Populate it from `GREENHOUSE_REGISTRY_PUBKEY` (hex-encoded) in `NewBlockchain`. Pass it to `NewAllowlistGater` when constructing `NewP2PNode`.

**Step B — Static peer manifest:**
Create a `LoadPeerManifest(path string, gater *AllowlistGater) error` function. The manifest is a JSON file:
```json
[
  {"peer_id": "12D3KooW...", "signature": "<hex>"},
  ...
]
```
Each entry's signature is `Sign(SHA3-256([]byte(peer_id)))` produced by the network registry private key. Call `gater.AllowPeer(peerID, sig)` for each entry. Invoke this in `NewP2PNode` if `GREENHOUSE_PEER_MANIFEST` env var is set.

**Step C — Fail-fast in production:**
In the production guard (Item 2), add: if `GREENHOUSE_REGISTRY_PUBKEY` is not set, `log.Fatal`.

#### Acceptance Criteria

- A node configured with `GREENHOUSE_REGISTRY_PUBKEY` and a valid `peers.json`: only peers listed in the manifest can complete the TLS/Noise handshake. An unlisted test peer is rejected at `InterceptSecured`.
- An `AllowlistAdd` gossip message from a non-registry key is rejected.
- Development/test nodes (no `GREENHOUSE_REGISTRY_PUBKEY`) continue to work in open mode.

#### Dependencies

Depends on Item 7 (key infrastructure must exist before a production registry key can be loaded).

---

### Item 5 — GossipSub Topic Validator

**Gap IDs:** P2P GAP-02, P2P GAP-03
**Severity:** Critical
**Files:** `p2p.go`

#### Root Cause

`pubsub.NewGossipSub` is called with no topic validators registered. Any peer — whether in the allowlist or not — can publish arbitrary bytes to any GossipSub topic. The `AllowlistGater` controls connections but not message publication; a peer admitted to the network can send malicious `MessageTypeBlock` payloads to all validators without restriction.

Additionally, `HandleMessages` processes messages in a tight loop that skips messages from `h.ID()` (self) but never checks whether `msg.ReceivedFrom` is in the allowlist — a peer that obtained a connection (e.g. before being revoked) can continue to inject messages until it is disconnected.

#### Fix

**Step A — Register topic validator:**
After `ps.Join(topicName)`, call:
```go
ps.RegisterTopicValidator(topicName, func(ctx context.Context, pid peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
    if !gater.InterceptPeerDial(pid) {
        return pubsub.ValidationReject
    }
    return pubsub.ValidationAccept
})
```

**Step B — Sender check in HandleMessages:**
At the top of the `HandleMessages` receive loop, after the self-skip, add:
```go
if !gater.InterceptPeerDial(msg.ReceivedFrom) {
    continue // silently drop; peer has been revoked
}
```

#### Acceptance Criteria

- A peer not in the allowlist that somehow obtains a connection cannot inject a message that reaches `HandleMessages`.
- A revoked peer's in-flight messages are dropped before being decoded.
- `go test -race ./...` continues to pass.

#### Dependencies

Depends on Item 4 (gater must be functional for the validator to work correctly).

---

### Item 6 — Block Timestamp Field

**Gap ID:** GAP-LOG-01
**Severity:** High
**Files:** `blockchain.go:97,109`

#### Root Cause

The `Block` struct (`blockchain.go:97`) and `blockHashInput` (`blockchain.go:109`) contain no timestamp field. Blocks are undated from the perspective of on-chain state. `SealBlock` (`blockchain.go:664`) never sets a time when constructing `Block{}`.

This is a regulatory breach: MiFIR RTS 22 requires trade timestamps to microsecond precision; MAR requires timestamps on all market activity records; CSDR requires settlement timestamps. Currently the only timestamps in the system are ephemeral `StreamEvent` fields and per-trade `ExecutedAt` fields — both discarded on restart.

#### Fix

**Step A:** Add `SealedAt int64 \`json:"sealed_at"\`` to `Block` at `blockchain.go:97`.

**Step B:** Add `SealedAt int64 \`json:"sealed_at"\`` to `blockHashInput` at `blockchain.go:109`. This makes the timestamp part of the signed payload hash — a block's timestamp cannot be altered post-hoc without invalidating all delegate signatures.

**Step C:** In `AddBlock`, set `block.SealedAt = time.Now().UnixMicro()` before `block.SetPayloadHash()`.

#### Acceptance Criteria

- Every block in `bc.Blocks` has a non-zero `SealedAt` value after sealing.
- `block.PayloadHash` changes if `SealedAt` changes (timestamp is included in the hash input).
- `Block` JSON serialisation includes `"sealed_at"` with a Unix microsecond integer.
- Replaying a block with a different `SealedAt` fails `ValidateBlock`.

#### Dependencies

None, but implement before Item 8 (delegate signing depends on `blockHashInput` being stable).

---

### Item 7 — Key Management: Require OperatorKeyProvider

**Gap IDs:** KM-01, KM-02, KM-04, KM-05
**Severity:** Critical
**Files:** `keymanager.go:88`, `blockchain.go:286,692`

#### Root Cause

`bc.OperatorKeyProvider` is `nil` by default (`blockchain.go:286`). `SealBlock` only signs the block if `OperatorKeyProvider != nil` (`blockchain.go:692`) — so in a default deployment, no block is ever signed by the operator node. This means:

- Receiving peers cannot verify block authenticity.
- The dBFT `createBlock` path never signs at all.
- `KMSKeyProvider.Sign` (`keymanager.go:88`) always returns an error because AWS KMS does not support raw Ed25519 — it is a non-functional stub.

There is also no mechanism to load a key from an encrypted file at startup.

#### Fix

**Step A:** Include `OperatorKeyProvider == nil` check in Item 2's production `log.Fatal` guard (already included there).

**Step B — Implement NewLocalKeyProviderFromEncryptedFile:**
Add to `keymanager.go`:
```go
// NewLocalKeyProviderFromEncryptedFile decrypts an AES-256-GCM encrypted Ed25519
// private key file and returns a LocalKeyProvider. File format:
// [32-byte PBKDF2 salt][12-byte nonce][AES-256-GCM ciphertext of Ed25519 private key].
// Key is derived from passphrase using PBKDF2-SHA256 with 600,000 iterations.
func NewLocalKeyProviderFromEncryptedFile(path, passphrase string) (*LocalKeyProvider, error)
```

**Step C — Document VaultKeyProvider wiring:**
Add a `cmd/README.md` section documenting how to wire `VaultKeyProvider` as the `OperatorKeyProvider` at startup, including the required Vault policy and `VAULT_ADDR` / `VAULT_TOKEN` / `VAULT_KEY_PATH` environment variables.

**Step D — Deprecate KMSKeyProvider:**
Add a `// Deprecated: AWS KMS does not support raw Ed25519 signing. Use VaultKeyProvider or LocalKeyProvider.` comment to `KMSKeyProvider` at `keymanager.go:88`. Do not remove it (breaking change).

**Step E — Key rotation support:**
Add a `KeyVersion string` field to `Block` (and `blockHashInput`). Set it to `OperatorKeyProvider.PublicKeyString()` in `AddBlock`. This allows receiving nodes to look up the correct public key when keys are rotated.

#### Acceptance Criteria

- A node with no `OperatorKeyProvider` and `GH_ENV=production` fails at startup.
- `NewLocalKeyProviderFromEncryptedFile` roundtrips: encrypt a key, write to file, reload, sign a message, verify with the original public key.
- Blocks produced by `SealBlock` carry a non-empty `Signatures` slice when `OperatorKeyProvider` is set.
- `KMSKeyProvider` is clearly marked deprecated in code.

#### Dependencies

None. Items 4 and 8 depend on this.

---

## Phase 2 — Required Before Regulatory Submission

> These items will be reviewed by the NCA (or equivalent national competent authority) during the DLT TSS authorisation process under MiCA / UK FSMA 2023 amendments. Each represents a failure mode that a regulator would classify as a critical control gap.

---

### Item 8 — dBFT: Real Delegate Ed25519 Block Signing

**Gap IDs:** dBFT GAP-03, GAP-13, BS-02
**Severity:** Critical
**Files:** `dBFT.go`, `blockchain.go`

#### Root Cause

`createBlock` (called from within the dBFT consensus path) populates `Signatures` with `[]byte(delegate.ID)` — a literal byte encoding of the delegate's human-readable ID string, not an Ed25519 signature. This means:

- `ValidateBlock`'s signature-verification loop accepts any string as a "signature" for delegates with a public key, as long as the count meets the supermajority threshold.
- `DefaultVotingStrategy.Vote` verifies signatures for base `Transaction` types only — `AssetTransactions`, `OrderTransactions`, and `CredentialTransactions` are entirely skipped.
- Blocks produced by the dBFT path carry no cryptographic proof that any specific delegate approved them.

#### Fix

**Step A — Real signatures in createBlock:**
Each delegate that votes `true` must sign `block.PayloadHash` bytes using its `PrivateKey` (already a field on the `Node` struct). Replace the `[]byte(delegate.ID)` stub with a real Ed25519 signature and append it to `block.Signatures`.

**Step B — Extend DefaultVotingStrategy.Vote:**
For `AssetTransaction`: verify the `Tx.Sender` signature over the asset transaction hash using the sender's registered public key (from `bc.Credentials`). For `CredentialTransaction`: verify the issuer's Ed25519 signature. Return `false` (reject) if verification fails.

**Step C:** Remove the `len(delegate.PublicKey) == 0` bypass in `ValidateBlock` once all delegates have keys.

#### Acceptance Criteria

- A block produced by `AchieveConsensus` carries Ed25519 signatures verifiable against the delegate public keys stored in `bc.Delegates`.
- `ValidateBlock` rejects a block where any delegate signature has been tampered with.
- `DefaultVotingStrategy.Vote` returns `false` for an `AssetTransaction` with an invalid sender signature.

#### Dependencies

Depends on Items 6 (blockHashInput must be stable before signing) and 7 (keys must be loaded).

---

### Item 9 — dBFT: Distributed View-Change Protocol

**Gap IDs:** dBFT GAP-01, GAP-02
**Severity:** Critical
**Files:** `dBFT.go`

#### Root Cause

`startConsensus` calls `AchieveConsensus` (`dBFT.go:187`) once and returns. If the elected speaker is Byzantine (crashes, equivocates, or is unavailable), consensus is permanently stalled — there is no view-change mechanism. dBFT's liveness guarantee depends on `O(n²)` view-change messages that cycle to a new speaker when the current one fails.

#### Fix

**Step A:** Add constants `MessageTypeViewChangeRequest = "view_change_request"` and `MessageTypeViewChangeResponse = "view_change_response"`. Add a `ViewChangeRequest{View int, NodeID string, Reason string}` struct.

**Step B:** When `AchieveConsensus` returns `false` (timeout or insufficient votes), broadcast a `ViewChangeRequest{View: currentView + 1, NodeID: self, Reason: "timeout"}` to all delegates.

**Step C:** Add a `ViewChangeRequest` case to `ProcessMessages`. When `f+1` view-change requests for the same new view are accumulated (where `f = (len(bc.Delegates) - 1) / 3`), increment the view counter and re-run `selectSpeaker` with the new view.

**Step D:** Wrap the `AchieveConsensus` call in a retry loop limited to `len(bc.Delegates)` attempts (one full rotation of potential speakers). If all attempts are exhausted, emit an error event and return without sealing.

#### Acceptance Criteria

- With one Byzantine (non-responding) delegate out of four, consensus completes in the second view after view-change messages are exchanged.
- With two Byzantine delegates out of seven (`f=2`), consensus completes after at most two view changes.
- `startConsensus` never blocks indefinitely — it returns after at most `len(bc.Delegates) * ConsensusTimeout`.

#### Dependencies

Depends on Item 19 (delegates need network connectivity to exchange view-change messages over P2P).

---

### Item 10 — dBFT: Persist Delegate Set and WalletSequences

**Gap IDs:** dBFT GAP-05, dBFT GAP-11
**Severity:** High
**Files:** `dBFT.go`, `persistence.go`, `blockchain.go`

#### Root Cause

The active delegate set (`bc.Delegates`) is assembled in-memory during `VoteForDelegates` and lost entirely on node restart. On startup with an empty `bc.Delegates` slice, `AchieveConsensus` succeeds vacuously (zero required votes) — the first restart after election causes the BFT threshold to drop to zero.

#### Fix

**Step A:** In `BlockStore` (BBolt), create a second bucket `"delegates"`. After every successful `VoteForDelegates` result, serialise the active `[]Node` slice to JSON and write to key `"active"` in this bucket.

**Step B:** In the startup replay sequence (Item 1, Step B), after replaying all blocks, read `"delegates"/"active"` from BBolt. If present, unmarshal and assign to `bc.Delegates`.

**Step C:** If after state replay `bc.Delegates` is still empty but staking/credential data exists, automatically call `VoteForDelegates` to re-elect from the reconstructed state.

#### Acceptance Criteria

- Seal a block, elect delegates, restart. The restarted node has `len(bc.Delegates) > 0` before receiving any new transactions.
- `AchieveConsensus` after restart requires the same supermajority threshold as before restart.
- `bc.WalletSequences` after restart reflects the highest observed nonce per sender across all replayed blocks.

#### Dependencies

Depends on Item 1 (BBolt must be wired first).

---

### Item 11 — ValidateBlock: Typed Transaction Verification

**Gap IDs:** dBFT GAP-04, dBFT GAP-13
**Severity:** High
**Files:** `blockchain.go`, `dBFT.go`

#### Root Cause

`ValidateBlock` and `DefaultVotingStrategy.Vote` perform signature and sequence-number checks only on base `Transaction` types. `AssetTransactions`, `OrderTransactions`, and `CredentialTransactions` embedded in a block are trusted without verification during the consensus voting phase — a Byzantine delegate can inject unsigned asset transfers into a proposed block and have them accepted by honest delegates.

#### Fix

In `ValidateBlock`:
- For each `AssetTransaction` in `block.AssetTransactions`: call `at.Validate(bc)`. Return an error if any fail.
- For each `CredentialTransaction`: verify the issuer's Ed25519 signature over the credential hash using the issuer's public key from `bc.IdentityRegistry`.
- For each `OrderTransaction`: verify the `Tx.Sender` signature over the order hash.

In `DefaultVotingStrategy.Vote`: move the typed transaction checks out of the skipped path and into explicit signature-verification blocks (see also Item 8, Step B).

#### Acceptance Criteria

- A block containing an `AssetTransaction` with an invalid sender signature is rejected by `ValidateBlock`.
- A block containing an `AssetTransaction` that fails the jurisdiction rule is rejected.
- `go test -race ./...` continues to pass.

#### Dependencies

Depends on Item 13 (jurisdiction/suitability wiring must exist before `at.Validate(bc)` can enforce them).

---

### Item 12 — ResolveFork: Require BFT Supermajority Proof

**Gap ID:** dBFT GAP-07
**Severity:** Critical
**Files:** `dBFT.go:445`, `blockchain.go`

#### Root Cause

`ResolveFork` (`dBFT.go:445`) replaces `bc.Blocks` with a peer's block slice if the peer's chain is longer. This is a longest-chain (Nakamoto) fork resolution rule — it is fundamentally incompatible with dBFT:

- dBFT provides **irreversible finality** — once a block has `⌈2n/3⌉` valid delegate signatures, it cannot be reverted. No competing chain is valid.
- `ResolveFork` can be exploited to replace finalized blocks with attacker-controlled content.
- There is no re-application of `applyBlockState` after replacement — the in-memory state diverges from the replaced `bc.Blocks`.

#### Fix

**Option A (Recommended) — Remove ResolveFork entirely:**
In a pure dBFT deployment, fork resolution is never needed. Add an assertion in `AddBlock`: if a block with the same index already exists with a different `PayloadHash`, `log.Fatal` (this indicates a catastrophic consensus failure requiring human intervention, not automatic resolution).

**Option B — Require BFT proof:**
If fork resolution is kept for hybrid deployments, each block in the competing chain must carry valid `⌈2n/3⌉` delegate signatures verifiable against `bc.Delegates`. Reject the fork entirely if any block fails this check. After accepting the fork, replay state from block 0.

#### Acceptance Criteria

- A peer presenting a longer chain without valid delegate signatures cannot replace the local chain.
- An existing finalized block (one with `⌈2n/3⌉` valid sigs) is never replaced by any competing block.
- If Option A is chosen: `ResolveFork` is removed and the dBFT README notes that the network uses single-path finality.

#### Dependencies

Depends on Item 8 (delegate signatures must be real before they can be verified here) and Item 1 (state replay is needed if Option B is used).

---

### Item 13 — Wire AML, Suitability, and Jurisdiction into AssetTransaction.Validate

**Gap IDs:** GAP-KYC-02, GAP-REG-01, GAP-REG-02, GAP-AML-03
**Severity:** High
**Files:** `assets.go`, `compliance.go`, `blockchain.go`

#### Root Cause

`AssetTransaction.Validate` does not call:

- `CheckSuitability` — MiFID II requires suitability assessment for complex instruments before any transfer. The function exists in `compliance.go` but is never wired in.
- `ApplyJurisdictionRule` — jurisdiction-specific transfer restrictions are never enforced. `NewBlockchain` only seeds `JurisdictionRules` for GB; DE, LU, FR, and NL rules are absent.
- `CheckProspectusLimits` / `CheckProspectusValueThreshold` — the EUR 8M prospectus threshold and per-investor offer limits exist in `compliance.go` but are not called pre-trade.

Additionally, when `AMLScreener.ScreenTransaction` returns `AMLSeverityFlag` in `Validate`, the result is logged or discarded but no SAR is created.

#### Fix

In `AssetTransaction.Validate(bc *Blockchain)`, add four new steps:

1. For `AMLSeverityFlag` results: call `bc.PendingSARs = append(...)` with `NewSARDraft(...)` and emit `EventAMLFlagAlert` on `bc.Events`. Do not block the transaction (flag ≠ block) but ensure the alert is durable.

2. After the balance check, call `ApplyJurisdictionRule(receiverCredential.Jurisdiction, asset, bc.JurisdictionRules)`. Return an error if the receiver's jurisdiction disallows the transfer.

3. For complex instruments (check `asset.InstrumentType`): call `CheckSuitability(receiver, asset, bc.SuitabilityAssessments)`. Return an error if unsuitability is found.

4. Before order matching: call `CheckProspectusLimits(asset, bc.RetailCounts)` and `CheckProspectusValueThreshold(asset, transferAmount)`. Return an error if either threshold is breached.

Also seed DE, LU, FR, and NL jurisdiction rules in `NewBlockchain` (`blockchain.go:1173`) reflecting the key restrictions from `EU_Private_Placements_Regulatory_Review.md`.

#### Acceptance Criteria

- A transfer to an investor in a jurisdiction not covered by the asset's offering document fails `Validate` with `"jurisdiction rule: transfer not permitted"`.
- A complex-instrument transfer to an investor with no `SuitabilityAssessment` fails with `"suitability check failed"`.
- A transfer exceeding the EUR 8M prospectus threshold fails with `"prospectus threshold exceeded"`.
- An AML `SeverityFlag` result results in a `SARDraft` in `bc.PendingSARs` with status `Draft`.

#### Dependencies

None, but must be completed before Item 11 (which calls `at.Validate(bc)` from `ValidateBlock`).

---

### Item 14 — Wire NCAReportingService into SealBlock

**Gap ID:** GAP-REG-04
**Severity:** High
**Files:** `blockchain.go`, `nca_reporting.go`

#### Root Cause

`NCAReportingService` (`nca_reporting.go`) is fully implemented with `GenerateMiFIRReport`, `GenerateAIFMDReport`, and `SubmitToNCA` methods. However, it is never instantiated or wired into `SealBlock`. The `ReportingService` field on `Blockchain` is assigned `DefaultReportingService` (`regulatory_reporting.go:120`) which is a no-op. MiFIR transaction reporting is a T+1 obligation.

#### Fix

**Step A:** In `NewBlockchain`, when `GH_ENV=production` and `NCA_REPORTING_ENDPOINT` is set, instantiate `NCAReportingService` and assign to `bc.ReportingService`.

**Step B:** After `applyBlockState` in `SealBlock`, for every trade in the sealed block, call `bc.ReportingService.GenerateMiFIRReport(trade)` and `bc.ReportingService.SubmitToNCA(report)`.

**Step C:** If `SubmitToNCA` returns an error, write the serialised report to a BBolt bucket `"reporting_outbox"` keyed by `report.ID`. Add a background goroutine that retries failed outbox entries with exponential backoff and deletes them on success.

#### Acceptance Criteria

- In production mode, a sealed block containing trades triggers `GenerateMiFIRReport` for each trade.
- A simulated NCA endpoint outage: reports are written to the BBolt outbox and retried on reconnect.
- `DefaultReportingService` continues to be used in development/test mode.

#### Dependencies

Depends on Item 1 (BBolt must be wired for the outbox).

---

### Item 15 — Fix PEP Rescreening: Mutex Safety and Context

**Gap IDs:** GAP-AML-02, GAP-REG-07
**Severity:** High
**Files:** `aml_rules.go:308,319`

#### Root Cause

`rescreenAllWallets` (`aml_rules.go:319`) acquires `bc.Mu.Lock()` before calling `bc.AMLScreener.ScreenTransaction` in a loop. `ComplyAdvantageScreener` has a 10-second HTTP timeout per call (`complyadv_aml.go:51`). With 1,000 credentials and a degraded screener, this holds the blockchain write-lock for up to ~2.8 hours, freezing all `SealBlock`, order, and credential operations.

Additionally, `StartPEPRescreeningScheduler` launches a goroutine with no `context.Context` — the goroutine cannot be stopped during `Shutdown`, causing a goroutine leak.

#### Fix

**Step A:** Change signature to `StartPEPRescreeningScheduler(bc *Blockchain, interval time.Duration, ctx context.Context)`. Stop the goroutine when `ctx.Done()` fires.

**Step B — Snapshot outside lock, screen outside lock, write inside lock:**
```go
// Snapshot wallet keys under RLock
bc.Mu.RLock()
wallets := make([]string, 0, len(bc.Credentials))
for k := range bc.Credentials { wallets = append(wallets, k) }
bc.Mu.RUnlock()

// Screen each wallet WITHOUT holding the lock
for _, key := range wallets {
    ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
    alert, err := bc.AMLScreener.ScreenTransaction(ctx2, ...)
    cancel()
    if err != nil { log.Printf("rescreen error: %v", err); continue }
    if alert.Severity == AMLSeverityBlock || alert.Severity == AMLSeverityFlag {
        bc.Mu.Lock()
        bc.PendingSARs[sarID] = NewSARDraft(...)
        bc.Mu.Unlock()
    }
}
```

#### Acceptance Criteria

- `rescreenAllWallets` with 1,000 wallets does not hold `bc.Mu` for more than a few microseconds (snapshot + individual SAR writes).
- `StartPEPRescreeningScheduler` goroutine exits within one tick interval of the context being cancelled.
- `go test -race ./...` continues to pass including `TestStartPEPRescreeningScheduler_FiresWithinInterval`.

#### Dependencies

None.

---

### Item 16 — STOR Auto-Creation in applyBlockState

**Gap ID:** GAP-AML-04
**Severity:** High
**Files:** `blockchain.go`, `aml_rules.go`

#### Root Cause

`bc.PendingSTORs` (Suspicious Transaction Order Reports) is defined in `Blockchain` (`blockchain.go:251`) but `NewSTORDraft` is never called in any code path. Under MAR Article 16, firms must submit STORs to the NCA when they reasonably suspect market manipulation. Self-transfers, wash trades, and unusual price deviations are all detectable from `applyBlockState`.

#### Fix

After `MatchOrders` in `applyBlockState`, detect three patterns:

**Pattern 1 — Self-transfer:** If `trade.BuyerID == trade.SellerID`, call `NewSTORDraft(bc, trade, "self-transfer")`.

**Pattern 2 — Wash trade:** Maintain a rolling `bc.RecentCounterpartyTrades` map (keyed by sorted `"buyerID:sellerID"`, retaining only trades in the last 30 days). If the same counterparty pair has traded the same asset more than 3 times in the window, call `NewSTORDraft(bc, trade, "wash-trade-pattern")`.

**Pattern 3 — Price deviation:** If the trade price deviates from the asset's last 10-trade VWAP by more than 20%, call `NewSTORDraft(bc, trade, "price-deviation")`.

Emit `EventSTORCreated` on `bc.Events` for each new STOR draft.

#### Acceptance Criteria

- A self-transfer `AssetTransaction` results in `len(bc.PendingSTORs) == 1` with reason `"self-transfer"`.
- Four trades between the same buyer/seller on the same asset within a 30-day window triggers a STOR.
- An `EventSTORCreated` event is emitted on `bc.Events` for each new STOR.

#### Dependencies

Depends on Item 6 (block timestamps are needed to implement the 30-day rolling window).

---

### Item 17 — P2P: Disable DHT Discovery in Production

**Gap IDs:** P2P GAP-04, P2P GAP-05
**Severity:** High
**Files:** `p2p.go`

#### Root Cause

The Kademlia DHT (`dht.New` / `dht.Bootstrap`) runs unconditionally in `NewP2PNode`. In production, DHT enables any node in the libp2p network to discover and connect to GreenHouse validators — bypassing the `AllowlistGater` for initial connection brokering. mDNS discovery is already correctly gated behind `if os.Getenv("GH_ENV") != "production"` — DHT should follow the same pattern.

Additionally, `GREENHOUSE_BOOTSTRAP_PEERS` defaults to an empty slice with no startup warning when empty in production.

#### Fix

**Step A:** Wrap the entire DHT initialisation block in `if os.Getenv("GH_ENV") != "production"`. In production, rely solely on the static peer manifest loaded by `LoadPeerManifest` (Item 4).

**Step B:** In the production guard (Item 2), add: if `GH_ENV=production` and no peer manifest is loaded, `log.Fatal("production: no peer manifest or bootstrap peers configured")`.

#### Acceptance Criteria

- `GH_ENV=production`: no `dht.New` call is made; no DHT goroutine is launched.
- `GH_ENV=production` with no peer manifest: startup fails with a clear error.
- Development/test mode: DHT behaviour is unchanged.

#### Dependencies

Depends on Item 4 (static peer manifest must replace DHT before DHT is disabled).

---

### Item 18 — P2P: Connection Manager and GossipSub Tuning

**Gap IDs:** P2P GAP-07, P2P GAP-11, P2P GAP-12
**Severity:** High
**Files:** `p2p.go`, `go.mod`

#### Root Cause

`libp2p.New` is called with only `libp2p.ConnectionGater(gater)`. No connection manager is configured — the default is unlimited connections. A single malicious peer can exhaust file descriptors by opening thousands of connections.

`pubsub.NewGossipSub(ctx, h)` uses all defaults: `D=6, Dlo=5, Dhi=12`. For a validator network of 5–21 nodes, `D=6` may exceed the peer count causing continuous `"not enough peers in mesh"` warnings. No peer scoring, FloodPublish, or message size cap is configured. `BroadcastBlock` and `BroadcastTransaction` have no application-level rate limiter.

#### Fix

**Step A — Connection manager:**
```go
libp2p.ConnectionManager(connmgr.NewConnManager(20, 40, connmgr.WithGracePeriod(time.Minute)))
```
Import `github.com/libp2p/go-libp2p/p2p/net/connmgr`.

**Step B — GossipSub params tuned for validator network:**
Replace `pubsub.NewGossipSub(ctx, h)` with options:
- `pubsub.WithMaxMessageSize(256 * 1024)` — 256 KB max block size
- `pubsub.WithFloodPublish(true)` — ensure all validators receive messages
- `pubsub.WithGossipSubParams(...)` with `D`, `Dlo`, `Dhi` derived from validator count; `HeartbeatInterval: 500 * time.Millisecond`

**Step C — Rate limiter:**
Add a `rate.Limiter` field to `P2PNode` (e.g. `rate.NewLimiter(rate.Every(100*time.Millisecond), 10)` — max 10 blocks/second). Call `n.limiter.Wait(ctx)` at the start of `BroadcastBlock` and `BroadcastTransaction`.

#### Acceptance Criteria

- With 50 concurrent peers attempting to connect, only 40 connections are maintained; surplus connections are closed.
- GossipSub does not emit `"not enough peers in mesh"` warnings with 5 validators.
- `BroadcastBlock` called 100 times/second is throttled to ~10/second by the rate limiter.

#### Dependencies

None.

---

### Item 19 — P2P: Peer Reconnect and Full-Mesh Delegates

**Gap IDs:** P2P GAP-08, P2P GAP-09
**Severity:** High
**Files:** `p2p.go`, `network.go`, `dBFT.go`

#### Root Cause

No `network.Notifee` is registered on `h.Network()`. If a connected peer (or delegate) disconnects mid-consensus, there is no automatic reconnect attempt. The DHT retry loop only runs at startup.

Delegates are Go structs in-process — there is no mapping between `bc.Delegates` entries and libp2p peer IDs. A network partition silently degrades to in-process-only consensus with no error.

#### Fix

**Step A — network.Notifee for reconnect:**
Implement `type peerReconnectNotifee struct { node *P2PNode }` with a `Disconnected` handler. For peers in `gater.allowed`, launch a goroutine with exponential-backoff reconnect (100ms → 200ms → 400ms → ... → 30s max, 10 attempts).

**Step B:** Register via `h.Network().Notify(reconnectNotifee)`.

**Step C — Delegate libp2p peer ID field:**
Add `P2PPeerID string` to the `Node` (delegate) struct. In `startConsensus`, dial all delegates by their `P2PPeerID` before beginning the round.

**Step D — Consensus sub-topic:**
Create a separate topic `topicName + "/consensus"` for `BlockProposal`, `Vote`, `ViewChangeRequest`, and `ViewChangeResponse` messages. Subscribe to this topic in addition to the main topic.

**Step E — Full-mesh assertion at startup:**
Before the first `startConsensus` call, verify that all delegates with a non-empty `P2PPeerID` are connected. If any are unreachable after 3 attempts, emit `EventDelegateUnreachable` (warning, not fatal).

#### Acceptance Criteria

- A disconnected allowlisted peer reconnects within 30 seconds with exponential backoff.
- A `ViewChangeRequest` broadcast on the consensus topic reaches all connected delegates within two GossipSub heartbeat intervals.
- `startConsensus` does not proceed until all delegates are confirmed reachable (or `EventDelegateUnreachable` is emitted).

#### Dependencies

Depends on Item 9 (view-change messages need the consensus topic established in Step D).

---

### Item 20 — Explicit TLS/Noise Transport Enforcement

**Gap ID:** P2P GAP-13
**Severity:** Medium
**Files:** `p2p.go`, `go.mod`

#### Root Cause

`libp2p.New` in `p2p.go` specifies no security transport. The libp2p default (Noise + TLS 1.3, protocol-negotiated) is safe today, but it is not explicitly documented or enforced. A future libp2p version change or misconfigured build could silently remove security without a compilation error. For financial infrastructure, the security transport should be explicit and auditable.

#### Fix

Add to the `libp2p.New` options list:
```go
libp2p.Security(noise.ID, noise.New)
```
Import `github.com/libp2p/go-libp2p/p2p/security/noise`. Noise XX provides mutual authentication — appropriate for a permissioned validator network where both parties must prove their identity.

Add a startup log line: `log.Printf("P2P: using Noise XX security transport (mutual auth)")`.

#### Acceptance Criteria

- Build succeeds with the explicit Noise import.
- Two nodes connect and exchange a test message successfully.
- The security transport choice is visible in startup logs.

#### Dependencies

None.

---

## Phase 3 — Production Hardening

> Phase 3 items prevent degraded operation under adversarial conditions, improve observability, and close medium/low-severity gaps. They can be implemented in any order and do not block regulatory submission, but should be completed before the first production liquidity window.

---

### Item 21 — Shutdown Safety: WaitGroup for DHT Goroutine

**Gap ID:** P2P GAP-10
**Severity:** Medium
**Files:** `p2p.go`

#### Root Cause

`Shutdown` calls `n.cancelBackground()` then immediately `n.Host.Close()` without waiting for the background DHT goroutine to exit. The DHT goroutine may be mid-`h.Connect(bgCtx, p)` when the host closes, producing a panic or data race on the closed host.

#### Fix

Add `bgWg sync.WaitGroup` to `P2PNode`. Before launching the DHT goroutine, call `n.bgWg.Add(1)`. Add `defer n.bgWg.Done()` as the first statement inside the goroutine. In `Shutdown`, after `cancelBackground()`, call `n.bgWg.Wait()` before `n.Host.Close()`.

#### Acceptance Criteria

- `go test -race -count=5 ./...` produces no data-race report involving `h.Connect` and `Host.Close`.
- Node shutdown completes cleanly without panic in a test that triggers the DHT goroutine.

#### Dependencies

None.

---

### Item 22 — Broadcast* Use Node Lifecycle Context

**Gap IDs:** P2P GAP-14, P2P GAP-15
**Severity:** Medium
**Files:** `p2p.go`

#### Root Cause

`BroadcastTransaction`, `BroadcastBlock`, `BroadcastAllowlistTransaction`, `SendPing`, `SendAck`, `BroadcastAssetTransaction`, and `mdnsNotifee.HandlePeerFound` all use `context.Background()`. If a caller holds a `P2PNode` reference and calls `BroadcastBlock` concurrently with `Shutdown`, `Topic.Publish` races against `Topic.Close()`.

#### Fix

**Step A:** Store `bgCtx context.Context` on `P2PNode` (already created for the DHT goroutine). Use it in all `Topic.Publish` and `host.Connect` calls.

**Step B:** Add `closed int32` atomic to `P2PNode`. Set to `1` at the beginning of `Shutdown`. All `Broadcast*` methods check `atomic.LoadInt32(&n.closed) == 1` at entry and return `ErrNodeShutdown` immediately if set.

**Step C:** Pass `bgCtx` to `mdnsNotifee` and use it in `host.Connect`.

#### Acceptance Criteria

- Calling `BroadcastBlock` after `Shutdown` returns `ErrNodeShutdown`, not a panic.
- `go test -race -count=5 ./...` produces no data-race report on `Topic.Publish` vs `Topic.Close`.

#### Dependencies

None.

---

### Item 23 — dBFT Inbox Capacity and Dropped-Message Metrics

**Gap ID:** dBFT GAP-08
**Severity:** Medium
**Files:** `dBFT.go`

#### Root Cause

`Node.Inbox` is created with capacity 10. In a 7-validator network, a single consensus round can generate: 1 `BlockProposal` + 7 `PrepareResponse` + 7 `Commit` = 15+ messages. The inbox overflows and `ReceiveMessage` silently drops messages, meaning consensus rounds may not collect enough votes even when all validators are honest.

#### Fix

**Step A:** Change the inbox channel creation to `make(chan P2PMessage, 1000)`.

**Step B:** Add `droppedMessages atomic.Uint64` to `Node`. In the `ReceiveMessage` default case (drop path), call `n.droppedMessages.Add(1)` and emit a log warning.

**Step C (optional):** Expose `droppedMessages` as a Prometheus gauge counter, registered in `cmd/api/main.go` if a metrics endpoint is configured.

#### Acceptance Criteria

- A 21-validator consensus round with 50 messages per round does not drop any messages.
- `droppedMessages` counter is incremented when the inbox is at capacity.
- Existing `TestNode_ProcessMessages_*` tests continue to pass.

#### Dependencies

None.

---

### Item 24 — Unify Block Production Paths

**Gap IDs:** BS-03, dBFT GAP-14
**Severity:** Medium
**Files:** `blockchain.go`, `dBFT.go`

#### Root Cause

There are two distinct block-sealing code paths:

1. **HTTP API path:** `SealBlock` (`blockchain.go:664`) — operator-signed, triggers `applyBlockState`, persists to BBolt, broadcasts over P2P.
2. **dBFT path:** `createBlock` → `AchieveConsensus` → `finalizeBlock` — delegate-signed, calls `AddBlock` directly without operator signing.

These paths produce blocks with incompatible structures. `ValidateBlock` cannot verify both types consistently. There is also no cross-block transaction deduplication — the same transaction hash can appear in two different blocks.

#### Fix

**Step A:** Add `ConsensusMode string` to `Blockchain`, read from `GREENHOUSE_CONSENSUS_MODE` env var (`"http"` or `"dbft"`). Fail at startup (`log.Fatal`) if `GH_ENV=production` and `ConsensusMode` is empty.

**Step B — Enforce mutual exclusion:**
In `SealBlock`, if `bc.ConsensusMode == "dbft"`, return an error: `"SealBlock is disabled in dBFT mode"`.
In `startConsensus`, if `bc.ConsensusMode == "http"`, return an error: `"dBFT consensus is disabled in http mode"`.

**Step C:** In `finalizeBlock`, after delegate signatures are collected, also call `OperatorKeyProvider.Sign` to add an operator signature (same logic as `SealBlock:692`). This makes dBFT-produced blocks carry both delegate and operator signatures.

**Step D — Cross-block transaction deduplication:**
Add `bc.CommittedTxHashes map[string]struct{}`. Populate in `applyBlockState` (every transaction hash added). In `ValidateBlock`, reject any block containing a transaction hash already in `CommittedTxHashes`. Rebuild from replayed blocks at startup.

#### Acceptance Criteria

- `GREENHOUSE_CONSENSUS_MODE=dbft`: `SealBlock` returns an error.
- `GREENHOUSE_CONSENSUS_MODE=http`: `startConsensus` returns an error.
- A dBFT-produced block carries both delegate and operator signatures.
- A duplicate transaction hash in a second block is rejected by `ValidateBlock`.

#### Dependencies

Depends on Items 1, 7, and 8.

---

### Item 25 — BBolt Key Format Fix and Hot-Backup

**Gap IDs:** P-03, P-04
**Severity:** Medium
**Files:** `persistence.go`

#### Root Cause

`keyForIndex` and `SaveBlock` must produce identical key formats for BBolt's byte-sorted iteration to yield blocks in correct chain order. Any mismatch causes `LoadBlocks` to return blocks in lexicographic rather than chain order (e.g. block 10 sorts before block 2 without zero-padding). Additionally, there is no hot-backup mechanism — a corrupted or lost BBolt file destroys the entire chain history.

#### Fix

**Step A:** Verify and align both `SaveBlock` and `keyForIndex` to use `fmt.Sprintf("%010d", index)`. Add a unit test that saves 10 blocks and verifies `LoadBlocks` returns them in exact index order `[0, 1, 2, ..., 9]`.

**Step B — Implement BlockStore.Backup:**
```go
// Backup writes a consistent BBolt snapshot to w. Safe to call concurrently
// with SaveBlock — uses a read-only BBolt transaction.
func (s *BlockStore) Backup(w io.Writer) error {
    return s.db.View(func(tx *bolt.Tx) error {
        _, err := tx.WriteTo(w)
        return err
    })
}
```

**Step C:** Add optional `GREENHOUSE_BACKUP_DIR` env var. If set, launch a goroutine that calls `store.Backup` every 24 hours and writes a timestamped `.bak` file to the directory. The goroutine exits on node shutdown.

#### Acceptance Criteria

- `LoadBlocks` after saving blocks 0–9 returns them in order `[0, 1, 2, ..., 9]`.
- `Backup` produces a file that can be opened with `bolt.Open` and yields identical block data.
- The backup goroutine exits on node shutdown.

#### Dependencies

Depends on Item 1 (BBolt must be wired first).

---

### Item 26 — Payment Provider Retry and Backoff

**Gap ID:** PAY-05
**Severity:** Medium
**Files:** `modulr_payment.go`, `eurc_payment.go`, `pontes_payment.go`

#### Root Cause

All three payment provider HTTP clients make a single HTTP call and return an error on failure. There is no retry logic — a transient 500 or network timeout causes settlement to fail permanently. CSDR Article 7 requires best-effort settlement. Additionally, `ConfirmPayment` errors in `applyBlockState` (`blockchain.go:636`) are silently discarded with `_ = provider.ConfirmPayment(...)`.

#### Fix

Add a shared `retryHTTP(ctx context.Context, maxAttempts int, fn func() (*http.Response, error)) (*http.Response, error)` helper in a new file `payment_retry.go`:

- Up to 3 attempts for `5xx` responses and `net.Error` (timeouts, connection refused).
- No retry for `4xx` responses (client errors are definitive).
- Backoff: 0ms, 500ms, 2000ms with ±10% jitter.
- Respect the passed `context.Context` — if cancelled, stop immediately.

Wire into `ModulrPaymentProvider.InitiatePayment`, `EURCPaymentProvider.InitiatePayment`, and `PontesPaymentProvider.InitiatePayment`.

Change the `ConfirmPayment` silent discard in `applyBlockState` from:
```go
_ = provider.ConfirmPayment(...)
```
to:
```go
if err := provider.ConfirmPayment(...); err != nil {
    log.Printf("ConfirmPayment error for trade %s: %v", trade.ID, err)
}
```
Do not fail the block on `ConfirmPayment` error (the trade is already settled on-chain) but log for operational visibility.

#### Acceptance Criteria

- A simulated Modulr 503 response retries three times before returning an error.
- A simulated Modulr 400 response does not retry.
- `ConfirmPayment` errors are logged, not silently discarded.

#### Dependencies

None.

---

### Item 27 — Settlement Reversal Mechanism

**Gap ID:** SF-01
**Severity:** Medium
**Files:** `blockchain.go`, `payment.go`

#### Root Cause

There is no mechanism to reverse a settled trade. CSDR and MiFIR require that settlement failures are reportable and in some cases trades must be reversible with regulator approval (e.g. due to data errors, court orders, or regulatory intervention). There is currently no path to unwind holding changes on-chain.

#### Fix

**Step A — ReverseSettlement function:**
```go
// ReverseSettlement reverses a previously settled trade. It requires multi-sig
// authorisation from at least 2 operator keys. The reversal is recorded as an
// on-chain ReversalTransaction, not a direct state mutation.
func (bc *Blockchain) ReverseSettlement(tradeID string, authorisedBy []AuthorisedSignature) error
```
This function:
1. Verifies that `len(authorisedBy) >= 2` and all signatures are valid against registered operator keys.
2. Creates an inverse `AssetTransaction` (tokens and payment returned to respective parties).
3. Creates a `ReversalRecord` with the trade ID, reason, authorising operator keys, and timestamp.
4. Calls `SealBlock` with the inverse transaction to create an on-chain record.

**Step B — ReversalRecord type:**
```go
type ReversalRecord struct {
    TradeID      string
    Reason       string
    AuthorisedBy []string // operator public keys
    ReversedAt   int64
    BlockIndex   int      // block in which the reversal was recorded
}
```
Store in `bc.ReversalRecords []*ReversalRecord`.

#### Acceptance Criteria

- Valid trade ID + two valid operator signatures: creates a `ReversalRecord`, buyer's holding is decremented, seller's holding is restored.
- One authorising signature returns `"insufficient authorisation: require 2 signatures"`.
- The reversal is recorded as an on-chain block visible in `bc.Blocks`.

#### Dependencies

Depends on Item 7 (operator keys are needed for multi-sig authorisation).

---

### Item 28 — Block Signing: Peer Verification

**Gap ID:** BS-01
**Severity:** High
**Files:** `p2p.go`, `blockchain.go`

#### Root Cause

When a `MessageTypeBlock` is received in `HandleMessages`, the block is decoded and passed to `bc.ValidateBlock`. `ValidateBlock` checks delegate signatures against `bc.Delegates`, but it does not verify the operator signature — the sender's operator public key is not distributed to peers and is not included in the block. An attacker who can inject a `MessageTypeBlock` gossip message can present a block with fabricated content.

#### Fix

**Step A:** Add `OperatorPublicKey string \`json:"operator_pk"\`` to `Block` and `blockHashInput`. Set it to `bc.OperatorKeyProvider.PublicKeyString()` in `AddBlock`.

**Step B:** After decoding an incoming block in `HandleMessages`, verify the operator signature against `block.OperatorPublicKey`. Reject the block (log and drop) if verification fails.

**Step C:** Include `OperatorPublicKey` in the `peers.json` manifest entries (alongside `peer_id` and `signature`). When a peer is admitted, store its operator public key in `bc.PeerOperatorKeys map[peer.ID]string`.

#### Acceptance Criteria

- A block received with a tampered operator signature is rejected.
- A block from a valid peer with a valid operator signature is accepted.
- `OperatorPublicKey` is included in all blocks produced by `SealBlock` and `finalizeBlock`.

#### Dependencies

Depends on Items 4 (peer manifest), 5 (topic validator), and 7 (operator key loaded).

---

### Item 29 — DORA Minimum Viable Implementation

**Gap ID:** GAP-DORA-01
**Severity:** Critical
**Files:** New file `dora.go`, `appia.go`, new documents `BCP.md`, `TLPT_PLAN.md`

#### Root Cause

The Digital Operational Resilience Act (DORA) — effective 17 January 2025 — requires all financial entities (including DLT-based platforms) to implement: an ICT risk management framework, an ICT third-party register, an ICT-related incident classification and reporting workflow, resilience testing, and a business continuity plan. GreenHouse has zero DORA implementation. This is a regulatory breach for any EU deployment under MiCA.

#### Fix

**Step A — ICT Third-Party Register (`dora.go`):**
```go
type ICTProvider struct {
    Name         string
    Services     []string // e.g. ["identity-verification", "aml-screening"]
    SLAUptimePct float64
    DORACategory string   // "critical" or "important"
    ContractRef  string
}
type ICTThirdPartyRegister struct {
    Providers []*ICTProvider
}
```
Seed with: Onfido (identity verification, critical), ComplyAdvantage (AML screening, critical), Elliptic (blockchain AML, important), Modulr (payment rail, critical), AWS/GCP (infrastructure, critical).

**Step B — ICT Incident Log (`dora.go`):**
```go
type ICTIncident struct {
    ID                 string
    Severity           string   // "minor", "major", "critical"
    Classification     string   // "cyber", "operational", "third-party"
    DetectedAt         int64
    ResolvedAt         int64
    NCANotified        bool
    NCANotificationDue int64    // DetectedAt + 4h for critical, 72h for major
    Description        string
    AffectedServices   []string
}
type ICTIncidentLog struct {
    Incidents []*ICTIncident
}
```
Expose `POST /v1/incidents` and `GET /v1/incidents` in the API.

**Step C — NodeOperatorRegistry:**
Extend the existing partial implementation in `appia.go` with DORA-required fields: jurisdiction, ICT risk category, last TLPT date, incident history reference.

**Step D — BCP/DR Runbook:**
Create `BCP.md` in the repository root containing: RTO/RPO targets, failover procedure, BBolt backup restore steps, key recovery procedure, NCA notification contacts, and communication chain. Reference from `README.md`.

**Step E — Annual TLPT Plan:**
Create `TLPT_PLAN.md` covering: scope, threat scenarios (enumerated), test schedule, success criteria, and NCA engagement procedure.

#### Acceptance Criteria

- `GET /v1/ict-register` returns the seeded list of ICT providers in JSON.
- `POST /v1/incidents` creates an `ICTIncident` with correct `NCANotificationDue` computed from severity.
- `BCP.md` exists and covers all five mandatory areas (RTO/RPO, failover, backup restore, key recovery, NCA contacts).

#### Dependencies

None.

---

### Item 30 — Compliance Completeness (Medium-Priority Items)

**Gap IDs:** GAP-REG-03, GAP-REG-05, GAP-REG-06, GAP-KYC-03, GAP-LOG-02
**Severity:** Medium
**Files:** `blockchain.go`, `operator_identity.go:100`, `assets.go`, `aml_rules.go`, `registration.go`

#### Root Cause

Five medium-priority compliance gaps remain after the high-priority items above are addressed:

1. **Travel Rule (GAP-REG-03):** `TravelRulePayload` builder produces an incomplete payload when `RegistrationRegistry == nil`. There is no VASP-to-VASP transmission mechanism.
2. **Insider Lists (GAP-REG-05):** `bc.InsiderLists` is defined but entries are never auto-created when a new asset is admitted. MAR Article 18 requires insider lists from the moment a transaction is considered.
3. **FATCA/CRS (GAP-REG-06):** TIN data is collected at registration (`registration.go:66`) but there is no annual reporting pipeline.
4. **Operator KYC audit trail (GAP-KYC-03):** `OperatorIdentityRegistry.IssueCredential` (`operator_identity.go:100`) can be called directly, bypassing `RequestKYC → ApproveKYC`. No approval record is retained. Under 5AMLD / UK MLR 2017, the CDD approval decision and evidence must be retained for 5 years.
5. **AML alert history (GAP-LOG-02):** Flag-severity AML alerts produce no durable record in `bc.AMLAlerts`.

#### Fix

**Travel Rule:**
Require `RegistrationRegistry` non-nil in production (add to startup guard in Item 2). Implement a `"travel_rule_outbox"` BBolt bucket and a background goroutine that dispatches payloads to registered counterparty VASPs via HTTP POST to `VASP_ENDPOINT`.

**Insider Lists:**
In `applyBlockState`, when an `AssetTransaction` of type `AssetTxTypeIssue` is applied, initialise:
```go
bc.InsiderLists[asset.ID] = &InsiderList{
    AssetID:   asset.ID,
    CreatedAt: time.Now().Unix(),
    Members:   []string{},
}
```

**FATCA/CRS:**
Add `TaxReportingExport(year int) ([]FATCARecord, []CRSRecord, error)` to `Blockchain`. Iterate `bc.Credentials`, filter by US persons (FATCA) and non-resident aliens (CRS), aggregate income/holdings from `bc.Holdings`, produce structured records. Wire to `GET /v1/tax-reporting/{year}`.

**Operator KYC audit trail:**
In `IssueCredential` (`operator_identity.go:100`), require an `ApprovalRecord{ApprovedBy, ApprovedAt, DocumentRefs}` parameter. Append to `bc.ApprovalLog`. Emit `EventCredentialIssued` with the `ApprovalRecord` payload. In production mode, return an error if `ApprovalRecord` is not provided.

**AML alert history:**
Add `AMLAlerts []*AMLAlert` to `Blockchain`. Append to `bc.AMLAlerts` in all code paths that receive a non-clear AML result (screener calls, rescreening, flag alerts). Expose via `GET /v1/compliance/alerts`.

#### Acceptance Criteria

- Issuing an asset automatically creates an `InsiderList` entry in `bc.InsiderLists`.
- `TaxReportingExport(2025)` returns records for all investors with TIN data.
- `IssueCredential` without an `ApprovalRecord` returns an error in production mode.
- `bc.AMLAlerts` is populated after any non-clear AML screening result.

#### Dependencies

Depends on Item 6 (timestamps for audit trail dating) and Item 1 (AMLAlerts must survive restart via state replay).

---

## Excluded from This Plan

The following items were considered during the audit but are excluded for the stated reasons:

| Item | Reason for Exclusion |
|------|---------------------|
| FATCA/CRS full SaaS integration | Separate workstream requiring OECD Common Reporting Schema integration; outside the scope of the DLT engine |
| Pontes API full production integration | Pilot launch scheduled Q3 2026; Pontes integration is in active development by the payments team |
| Formal TLPT scenario execution | Requires a licensed TLPT provider and NCA engagement; `TLPT_PLAN.md` (Item 29 Step E) covers the plan document only |
| Multi-region BBolt replication | Requires a distributed storage layer (e.g. etcd or TiKV); out of scope for current single-node architecture |
| Cross-chain bridge integration | Not part of the current product roadmap |

---

## Implementation Order and Dependencies

```
Phase 1 (Items 1–7) must be completed as a unit before Phase 2 begins.

Within Phase 1:
  Item 7  → Item 4  (registry key needed by AllowlistGater)
  Item 7  → Item 2  (OperatorKeyProvider check in production guard)
  Item 1:   independent — complete first (foundation for Items 10, 12, 24)
  Item 6:   independent — complete before Item 8 (blockHashInput must be stable)
  Items 2, 3, 5: independent of each other

Phase 2 dependencies:
  Item 8  depends on Items 6, 7
  Item 9  depends on Item 19
  Item 10 depends on Item 1
  Item 11 depends on Item 13
  Item 12 depends on Items 1, 8
  Item 14 depends on Item 1
  Items 13, 15, 16, 17, 18, 20: independent of each other

Phase 3 dependencies:
  Item 24 depends on Items 1, 7, 8
  Item 25 depends on Item 1
  Item 27 depends on Item 7
  Item 28 depends on Items 4, 5, 7
  Item 30 depends on Items 1, 6
  Items 21, 22, 23, 26, 29: independent
```

---

## Test Coverage Expectations

Every item should ship with tests that:

1. Verify the happy path in the production configuration.
2. Verify the fail-fast behaviour at startup (where applicable).
3. Verify the rejection path for the attack or failure scenario the item addresses.
4. Pass under `go test -race -count=3 ./...` without introducing new goroutine leaks.

The current baseline is `ok gonetwork 169.296s` with zero failures and zero race reports. This must be maintained throughout the implementation.

---

*End of document. For the gap audit reports that informed this plan, see the session research artefacts dated May 2026.*
