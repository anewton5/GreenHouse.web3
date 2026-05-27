package gonetwork

// ---------------------------------------------------------------------------
// legal_docs_test.go — LegalDocAmendment lifecycle and ApplyAmendment
//
// Covers:
//   NewLegalDocAmendment        — valid creation, nil key, same hash, empty fields
//   SetAdminSignature           — valid, nil key
//   VerifyIssuerSignature       — valid, no sig, wrong sig
//   VerifyAdminSignature        — valid, no sig/key, wrong sig
//   ApplyAmendment              — success, unknown asset, broken chain, wrong
//                                 issuer key, invalid issuer sig, participation
//                                 note requires admin sig
//   CurrentLegalDocHash         — no amendments (falls back to metadata),
//                                 after amendments (returns latest)
// ---------------------------------------------------------------------------

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func makeIssuerKey(t *testing.T) *PrivateKey {
	t.Helper()
	k, err := GeneratePrivateKey()
	require.NoError(t, err)
	return k
}

func makeAmendment(t *testing.T, assetID, prevHash, newHash string, issuerKey *PrivateKey) *LegalDocAmendment {
	t.Helper()
	a, err := NewLegalDocAmendment(assetID, prevHash, newHash, issuerKey)
	require.NoError(t, err)
	return a
}

// simpleAssets returns a minimal assets map with one equity asset.
func simpleAssets(assetID, issuerPub, currentHash string) map[string]*Asset {
	return map[string]*Asset{
		assetID: {
			ID:        assetID,
			AssetType: AssetTypeEquity,
			Issuer:    issuerPub,
			Metadata:  AssetMetadata{LegalDocHash: currentHash},
		},
	}
}

// ---------------------------------------------------------------------------
// NewLegalDocAmendment
// ---------------------------------------------------------------------------

func TestNewLegalDocAmendment_Valid(t *testing.T) {
	key := makeIssuerKey(t)
	a, err := NewLegalDocAmendment("asset-1", "hash-prev", "hash-new", key)
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.Equal(t, "asset-1", a.AssetID)
	assert.Equal(t, "hash-prev", a.PreviousDocHash)
	assert.Equal(t, "hash-new", a.NewDocHash)
	assert.NotEmpty(t, a.IssuerSignature)
	assert.NotEmpty(t, a.IssuerKey)
	assert.Greater(t, a.AmendedAt, int64(0))
}

func TestNewLegalDocAmendment_EmptyAssetID_Error(t *testing.T) {
	key := makeIssuerKey(t)
	_, err := NewLegalDocAmendment("", "prev", "new", key)
	require.Error(t, err)
}

func TestNewLegalDocAmendment_EmptyPrevHash_Error(t *testing.T) {
	key := makeIssuerKey(t)
	_, err := NewLegalDocAmendment("asset", "", "new", key)
	require.Error(t, err)
}

func TestNewLegalDocAmendment_EmptyNewHash_Error(t *testing.T) {
	key := makeIssuerKey(t)
	_, err := NewLegalDocAmendment("asset", "prev", "", key)
	require.Error(t, err)
}

func TestNewLegalDocAmendment_SameHash_Error(t *testing.T) {
	key := makeIssuerKey(t)
	_, err := NewLegalDocAmendment("asset", "same", "same", key)
	require.Error(t, err)
}

func TestNewLegalDocAmendment_NilKey_Error(t *testing.T) {
	_, err := NewLegalDocAmendment("asset", "prev", "new", nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// SetAdminSignature
// ---------------------------------------------------------------------------

func TestSetAdminSignature_Valid(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	adminKey := makeIssuerKey(t)
	a := makeAmendment(t, "asset-1", "prev-hash", "new-hash", issuerKey)

	err := a.SetAdminSignature(adminKey)
	require.NoError(t, err)
	assert.NotEmpty(t, a.AdminSignature)
	assert.Equal(t, base64.StdEncoding.EncodeToString(adminKey.Public().Bytes()), a.AdminKey)
}

func TestSetAdminSignature_NilKey_Error(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	a := makeAmendment(t, "asset-1", "prev", "new", issuerKey)
	err := a.SetAdminSignature(nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// VerifyIssuerSignature
// ---------------------------------------------------------------------------

func TestVerifyIssuerSignature_Valid(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	a := makeAmendment(t, "asset-1", "prev", "new", issuerKey)
	assert.True(t, a.VerifyIssuerSignature())
}

func TestVerifyIssuerSignature_NoSignature_False(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	a := makeAmendment(t, "asset-1", "prev", "new", issuerKey)
	a.IssuerSignature = nil
	assert.False(t, a.VerifyIssuerSignature())
}

func TestVerifyIssuerSignature_TamperedData_False(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	a := makeAmendment(t, "asset-1", "prev", "new", issuerKey)
	a.NewDocHash = "tampered-hash" // mutate after signing
	assert.False(t, a.VerifyIssuerSignature())
}

// ---------------------------------------------------------------------------
// VerifyAdminSignature
// ---------------------------------------------------------------------------

func TestVerifyAdminSignature_Valid(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	adminKey := makeIssuerKey(t)
	a := makeAmendment(t, "asset-1", "prev", "new", issuerKey)
	require.NoError(t, a.SetAdminSignature(adminKey))
	assert.True(t, a.VerifyAdminSignature())
}

func TestVerifyAdminSignature_NoSig_False(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	a := makeAmendment(t, "asset-1", "prev", "new", issuerKey)
	// No admin signature set
	assert.False(t, a.VerifyAdminSignature())
}

func TestVerifyAdminSignature_TamperedData_False(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	adminKey := makeIssuerKey(t)
	a := makeAmendment(t, "asset-1", "prev", "new", issuerKey)
	require.NoError(t, a.SetAdminSignature(adminKey))
	a.NewDocHash = "tampered"
	assert.False(t, a.VerifyAdminSignature())
}

// ---------------------------------------------------------------------------
// CurrentLegalDocHash
// ---------------------------------------------------------------------------

func TestCurrentLegalDocHash_NoAmendments_ReturnsMetadataHash(t *testing.T) {
	asset := &Asset{ID: "a1", Metadata: AssetMetadata{LegalDocHash: "genesis-hash"}}
	log := make(map[string][]*LegalDocAmendment)
	hash := CurrentLegalDocHash("a1", asset, log)
	assert.Equal(t, "genesis-hash", hash)
}

func TestCurrentLegalDocHash_AfterAmendments_ReturnsLatest(t *testing.T) {
	asset := &Asset{ID: "a1", Metadata: AssetMetadata{LegalDocHash: "genesis-hash"}}
	log := map[string][]*LegalDocAmendment{
		"a1": {
			{NewDocHash: "v1"},
			{NewDocHash: "v2"},
		},
	}
	hash := CurrentLegalDocHash("a1", asset, log)
	assert.Equal(t, "v2", hash)
}

// ---------------------------------------------------------------------------
// ApplyAmendment
// ---------------------------------------------------------------------------

func TestApplyAmendment_Success(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	issuerPub := base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes())

	assets := simpleAssets("asset-1", issuerPub, "genesis")
	log := make(map[string][]*LegalDocAmendment)

	a := makeAmendment(t, "asset-1", "genesis", "v1", issuerKey)
	err := ApplyAmendment(a, assets, nil, log)
	require.NoError(t, err)

	assert.Len(t, log["asset-1"], 1)
	assert.Equal(t, "v1", assets["asset-1"].Metadata.LegalDocHash)
}

func TestApplyAmendment_ChainMultipleAmendments(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	issuerPub := base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes())
	assets := simpleAssets("asset-1", issuerPub, "genesis")
	log := make(map[string][]*LegalDocAmendment)

	a1 := makeAmendment(t, "asset-1", "genesis", "v1", issuerKey)
	require.NoError(t, ApplyAmendment(a1, assets, nil, log))

	a2 := makeAmendment(t, "asset-1", "v1", "v2", issuerKey)
	require.NoError(t, ApplyAmendment(a2, assets, nil, log))

	assert.Equal(t, "v2", assets["asset-1"].Metadata.LegalDocHash)
	assert.Len(t, log["asset-1"], 2)
}

func TestApplyAmendment_UnknownAsset_Error(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	a := makeAmendment(t, "missing-asset", "prev", "new", issuerKey)
	err := ApplyAmendment(a, map[string]*Asset{}, nil, make(map[string][]*LegalDocAmendment))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown asset")
}

func TestApplyAmendment_BrokenChain_Error(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	issuerPub := base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes())
	assets := simpleAssets("asset-1", issuerPub, "genesis")
	log := make(map[string][]*LegalDocAmendment)

	// PreviousDocHash is wrong — should be "genesis"
	a := makeAmendment(t, "asset-1", "wrong-prev", "v1", issuerKey)
	err := ApplyAmendment(a, assets, nil, log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "amendment chain broken")
}

func TestApplyAmendment_WrongIssuerKey_Error(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	otherKey := makeIssuerKey(t)
	issuerPub := base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes())
	assets := simpleAssets("asset-1", issuerPub, "genesis")
	log := make(map[string][]*LegalDocAmendment)

	// Amendment signed by a different key than the asset issuer
	a := makeAmendment(t, "asset-1", "genesis", "v1", otherKey)
	err := ApplyAmendment(a, assets, nil, log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match asset issuer")
}

func TestApplyAmendment_InvalidIssuerSig_Error(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	issuerPub := base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes())
	assets := simpleAssets("asset-1", issuerPub, "genesis")
	log := make(map[string][]*LegalDocAmendment)

	a := makeAmendment(t, "asset-1", "genesis", "v1", issuerKey)
	a.IssuerSignature = []byte("corrupted-signature-bytes-padding00000000000000000000000000000000")
	err := ApplyAmendment(a, assets, nil, log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid issuer signature")
}

func TestApplyAmendment_ParticipationNote_RequiresAdminSig(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	issuerPub := base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes())

	assets := map[string]*Asset{
		"pn-asset": {
			ID:        "pn-asset",
			AssetType: AssetTypeParticipationNote,
			Issuer:    issuerPub,
			Metadata:  AssetMetadata{LegalDocHash: "genesis"},
		},
	}
	log := make(map[string][]*LegalDocAmendment)

	// Amendment without admin signature — must fail
	a := makeAmendment(t, "pn-asset", "genesis", "v1", issuerKey)
	err := ApplyAmendment(a, assets, map[string]*SPVWrapper{}, log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin co-signature")
}

func TestApplyAmendment_ParticipationNote_WithAdminSig_Succeeds(t *testing.T) {
	issuerKey := makeIssuerKey(t)
	adminKey := makeIssuerKey(t)
	issuerPub := base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes())

	assets := map[string]*Asset{
		"pn-asset": {
			ID:        "pn-asset",
			AssetType: AssetTypeParticipationNote,
			Issuer:    issuerPub,
			Metadata:  AssetMetadata{LegalDocHash: "genesis"},
		},
	}
	log := make(map[string][]*LegalDocAmendment)

	a := makeAmendment(t, "pn-asset", "genesis", "v1", issuerKey)
	require.NoError(t, a.SetAdminSignature(adminKey))

	err := ApplyAmendment(a, assets, map[string]*SPVWrapper{}, log)
	require.NoError(t, err)
	assert.Equal(t, "v1", assets["pn-asset"].Metadata.LegalDocHash)
}
