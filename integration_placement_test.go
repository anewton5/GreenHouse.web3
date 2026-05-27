package gonetwork

// ---------------------------------------------------------------------------
// integration_placement_test.go — end-to-end private placement flow tests.
//
// These tests exercise the full on-chain path via CommitBlock:
//   1. Credential issuance → credential appears in bc.Credentials
//   2. Asset issuance → asset appears in bc.Assets, holding created
//   3. Asset transfer → holding moves between wallets
//   4. Credential + asset + transfer in one block
//   5. AML screener blocks a transfer via Validate
//   6. Events are emitted for credential issuance
// ---------------------------------------------------------------------------

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helper — build a minimal valid Asset registered in the blockchain state.
// ---------------------------------------------------------------------------

func integrationAsset(t *testing.T, issuerKey *PrivateKey) *Asset {
	t.Helper()
	asset, err := NewAsset(
		issuerKey,
		AssetTypeEquity,
		1_000_000,
		"GBP",
		AssetMetadata{
			CompanyName:  "Integration Corp",
			Jurisdiction: "GB",
		},
		TransferRestrictions{},
	)
	require.NoError(t, err)
	return asset
}

// pubStr returns the base64-encoded Ed25519 public key string for a wallet.
func pubStr(key *PrivateKey) string {
	return base64.StdEncoding.EncodeToString(key.Public().Bytes())
}

// ---------------------------------------------------------------------------
// 1. Credential issuance via CommitBlock
// ---------------------------------------------------------------------------

func TestIntegration_CredentialTransaction_AppearsInCredentials(t *testing.T) {
	bc := newTestBlockchain(t)

	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	att, err := bc.IdentityRegistry.IssueCredential(pubStr(issuerKey), InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)

	block := Block{
		Index: 1,
		CredentialTransactions: []CredentialTransaction{
			{Attestation: *att},
		},
	}
	bc.CommitBlock(block)

	bc.Mu.RLock()
	defer bc.Mu.RUnlock()
	stored, ok := bc.Credentials[att.WalletPublicKey]
	assert.True(t, ok, "credential must be stored after CommitBlock")
	assert.Equal(t, InvestorClassProfessional, stored.InvestorClass)
}

// ---------------------------------------------------------------------------
// 2. Asset issuance via CommitBlock
// ---------------------------------------------------------------------------

func TestIntegration_AssetIssue_CreatesHolding(t *testing.T) {
	bc := newTestBlockchain(t)

	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	asset := integrationAsset(t, issuerKey)
	// Register asset in blockchain state so Validate passes.
	bc.Assets[asset.ID] = asset

	investorKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	at, err := NewAssetTransaction(issuerKey, investorKey.Public(), asset.ID, 10_000, AssetTxTypeIssue)
	require.NoError(t, err)

	block := Block{
		Index:             1,
		AssetTransactions: []AssetTransaction{*at},
	}
	bc.CommitBlock(block)

	bc.Mu.RLock()
	defer bc.Mu.RUnlock()
	hk := HoldingKey(pubStr(investorKey), asset.ID)
	holding, ok := bc.Holdings[hk]
	require.True(t, ok, "holding must exist after issuance block")
	assert.Equal(t, 10_000.0, holding.Balance)
}

// ---------------------------------------------------------------------------
// 3. Asset transfer via CommitBlock
// ---------------------------------------------------------------------------

func TestIntegration_AssetTransfer_MovesHolding(t *testing.T) {
	bc := newTestBlockchain(t)

	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	asset := integrationAsset(t, issuerKey)
	bc.Assets[asset.ID] = asset

	aliceKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bobKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	// Seed Alice with tokens via direct apply (bypass P2P / block path).
	issueAt, err := NewAssetTransaction(issuerKey, aliceKey.Public(), asset.ID, 500, AssetTxTypeIssue)
	require.NoError(t, err)
	require.NoError(t, ApplyAssetTransaction(issueAt, bc.Assets, bc.Holdings))

	// Now transfer 200 from Alice → Bob via CommitBlock.
	transferAt, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 200, AssetTxTypeTransfer)
	require.NoError(t, err)

	block := Block{
		Index:             1,
		AssetTransactions: []AssetTransaction{*transferAt},
	}
	bc.CommitBlock(block)

	bc.Mu.RLock()
	defer bc.Mu.RUnlock()

	aliceHK := HoldingKey(pubStr(aliceKey), asset.ID)
	bobHK := HoldingKey(pubStr(bobKey), asset.ID)

	aliceH, aliceOK := bc.Holdings[aliceHK]
	bobH, bobOK := bc.Holdings[bobHK]

	require.True(t, aliceOK)
	require.True(t, bobOK)
	assert.Equal(t, 300.0, aliceH.Balance, "Alice should have 300 after sending 200")
	assert.Equal(t, 200.0, bobH.Balance, "Bob should have 200 after receiving")
}

// ---------------------------------------------------------------------------
// 4. Combined block: credential + asset issue
// ---------------------------------------------------------------------------

func TestIntegration_CombinedBlock_CredentialAndAsset(t *testing.T) {
	bc := newTestBlockchain(t)

	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	asset := integrationAsset(t, issuerKey)
	bc.Assets[asset.ID] = asset

	investorKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	att, err := bc.IdentityRegistry.IssueCredential(pubStr(investorKey), InvestorClassRetail, "DE", 365)
	require.NoError(t, err)

	at, err := NewAssetTransaction(issuerKey, investorKey.Public(), asset.ID, 5_000, AssetTxTypeIssue)
	require.NoError(t, err)

	block := Block{
		Index:                  1,
		CredentialTransactions: []CredentialTransaction{{Attestation: *att}},
		AssetTransactions:      []AssetTransaction{*at},
	}
	bc.CommitBlock(block)

	bc.Mu.RLock()
	defer bc.Mu.RUnlock()

	_, credOK := bc.Credentials[att.WalletPublicKey]
	assert.True(t, credOK, "credential must be stored")

	hk := HoldingKey(pubStr(investorKey), asset.ID)
	_, holdingOK := bc.Holdings[hk]
	assert.True(t, holdingOK, "holding must be created")
}

// ---------------------------------------------------------------------------
// 5. Events emitted for credential issuance
// ---------------------------------------------------------------------------

func TestIntegration_CredentialBlock_EmitsEvent(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Events = make(chan StreamEvent, 10)

	investorKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	att, err := bc.IdentityRegistry.IssueCredential(pubStr(investorKey), InvestorClassRetail, "GB", 365)
	require.NoError(t, err)

	block := Block{
		Index:                  1,
		CredentialTransactions: []CredentialTransaction{{Attestation: *att}},
	}
	bc.CommitBlock(block)

	assert.Greater(t, len(bc.Events), 0, "at least one event must be emitted")
	// Drain events until we find credential_issued (block_finalised may arrive first).
	found := false
	for len(bc.Events) > 0 {
		evt := <-bc.Events
		if evt.Type == EventCredentialIssued {
			found = true
			break
		}
	}
	assert.True(t, found, "expected a credential_issued event")
}

// ---------------------------------------------------------------------------
// 6. AML-blocked transfer is skipped without corrupting state
// ---------------------------------------------------------------------------

func TestIntegration_AMLBlockedTransfer_IsSkipped(t *testing.T) {
	bc := newTestBlockchain(t)

	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	asset := integrationAsset(t, issuerKey)
	bc.Assets[asset.ID] = asset

	aliceKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bobKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	// Seed Alice.
	issueAt, err := NewAssetTransaction(issuerKey, aliceKey.Public(), asset.ID, 1_000, AssetTxTypeIssue)
	require.NoError(t, err)
	require.NoError(t, ApplyAssetTransaction(issueAt, bc.Assets, bc.Holdings))

	// Block Alice via AML screener.
	mockScreener := NewMockAMLScreener()
	mockScreener.BlockAddress(pubStr(aliceKey), "OFAC-SDN")
	bc.AMLScreener = mockScreener

	transferAt, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 500, AssetTxTypeTransfer)
	require.NoError(t, err)

	block := Block{
		Index:             1,
		AssetTransactions: []AssetTransaction{*transferAt},
	}
	bc.CommitBlock(block) // should skip the blocked tx without panicking

	bc.Mu.RLock()
	defer bc.Mu.RUnlock()

	// Alice's balance should be unchanged.
	aliceHK := HoldingKey(pubStr(aliceKey), asset.ID)
	aliceH, ok := bc.Holdings[aliceHK]
	require.True(t, ok)
	assert.Equal(t, 1_000.0, aliceH.Balance, "blocked transfer must not move Alice's tokens")

	// Bob should have no holding.
	bobHK := HoldingKey(pubStr(bobKey), asset.ID)
	_, bobOK := bc.Holdings[bobHK]
	assert.False(t, bobOK, "Bob must not receive tokens from a blocked sender")
}
