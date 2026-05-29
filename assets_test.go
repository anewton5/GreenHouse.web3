package gonetwork

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// makeTestAsset creates a standard unlocked equity asset for reuse across tests.
// Returns the asset and the issuer's private key.
func makeTestAsset(t *testing.T) (*Asset, *PrivateKey) {
	t.Helper()
	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	asset, err := NewAsset(
		key,
		AssetTypeEquity,
		1_000_000,
		"GBP",
		AssetMetadata{
			CompanyName:  "Acme Corp",
			Jurisdiction: "GB",
			VotingRights: true,
		},
		TransferRestrictions{
			LockupPeriodDays: 0,
			AccreditedOnly:   false,
			MaxHolders:       0,
		},
	)
	require.NoError(t, err)
	return asset, key
}

// makeTestWallet generates a new Ed25519 key pair and returns the private key
// along with the base64-encoded public key string (used as wallet address).
func makeTestWallet(t *testing.T) (*PrivateKey, string) {
	t.Helper()
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	pubKeyStr := base64.StdEncoding.EncodeToString(key.Public().Bytes())
	return key, pubKeyStr
}

// issueTokens is a test helper that creates and applies an issue transaction,
// giving `quantity` tokens of `asset` to `recipientKey`.
func issueTokens(
	t *testing.T,
	issuerKey *PrivateKey,
	recipientKey *PrivateKey,
	asset *Asset,
	assets map[string]*Asset,
	holdings map[string]*AssetHolding,
	quantity float64,
) {
	t.Helper()
	at, err := NewAssetTransaction(issuerKey, recipientKey.Public(), asset.ID, quantity, AssetTxTypeIssue)
	require.NoError(t, err)
	require.NoError(t, at.Validate(nil, assets, holdings, nil, nil))
	require.NoError(t, ApplyAssetTransaction(at, assets, holdings))
}

// ---------------------------------------------------------------------------
// NewAsset
// ---------------------------------------------------------------------------

func TestNewAsset_Valid(t *testing.T) {
	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	asset, err := NewAsset(
		key,
		AssetTypeEquity,
		500_000,
		"EUR",
		AssetMetadata{
			CompanyName:  "TestCo",
			Jurisdiction: "DE",
		},
		TransferRestrictions{},
	)

	require.NoError(t, err)
	assert.NotEmpty(t, asset.ID)
	assert.Equal(t, AssetTypeEquity, asset.AssetType)
	assert.Equal(t, float64(500_000), asset.TotalSupply)
	assert.Equal(t, float64(0), asset.CirculatingSupply)
	assert.Equal(t, "EUR", asset.Currency)
	assert.Equal(t, "TestCo", asset.Metadata.CompanyName)
	assert.Equal(t, "DE", asset.Metadata.Jurisdiction)
	assert.NotEmpty(t, asset.IssuerSignature)
	assert.Greater(t, asset.CreatedAt, int64(0))

	// Issuer field must equal the base64 public key of the key used.
	expectedIssuer := base64.StdEncoding.EncodeToString(key.Public().Bytes())
	assert.Equal(t, expectedIssuer, asset.Issuer)

	// Signature must verify against the issuer's public key.
	assert.True(t, asset.VerifyIssuerSignature(key.Public()))
}

func TestNewAsset_InvalidSupply(t *testing.T) {
	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	_, err = NewAsset(key, AssetTypeEquity, 0, "GBP", AssetMetadata{}, TransferRestrictions{})
	assert.ErrorContains(t, err, "total supply must be greater than zero")

	_, err = NewAsset(key, AssetTypeEquity, -100, "GBP", AssetMetadata{}, TransferRestrictions{})
	assert.ErrorContains(t, err, "total supply must be greater than zero")
}

func TestNewAsset_NilKey(t *testing.T) {
	_, err := NewAsset(nil, AssetTypeEquity, 100, "GBP", AssetMetadata{}, TransferRestrictions{})
	assert.ErrorContains(t, err, "issuer key must not be nil")
}

func TestNewAsset_EmptyCurrency(t *testing.T) {
	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	_, err = NewAsset(key, AssetTypeEquity, 100, "", AssetMetadata{}, TransferRestrictions{})
	assert.ErrorContains(t, err, "currency must not be empty")
}

func TestAssetIssuerSignatureTampering(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)

	// Verify the untampered signature passes.
	assert.True(t, asset.VerifyIssuerSignature(issuerKey.Public()))

	// Mutate a field — signature should no longer verify.
	asset.TotalSupply = 9_999_999
	assert.False(t, asset.VerifyIssuerSignature(issuerKey.Public()))
}

func TestAssetCalculateHash_Deterministic(t *testing.T) {
	asset, _ := makeTestAsset(t)
	h1 := asset.CalculateHash()
	h2 := asset.CalculateHash()
	assert.Equal(t, h1, h2)
	assert.NotEmpty(t, h1)
}

// ---------------------------------------------------------------------------
// HoldingKey
// ---------------------------------------------------------------------------

func TestHoldingKey(t *testing.T) {
	k := HoldingKey("alice", "asset1")
	assert.Equal(t, "alice:asset1", k)

	// Key must be stable and consistent.
	assert.Equal(t, HoldingKey("alice", "asset1"), HoldingKey("alice", "asset1"))

	// Different inputs must produce different keys.
	assert.NotEqual(t, HoldingKey("alice", "asset1"), HoldingKey("bob", "asset1"))
	assert.NotEqual(t, HoldingKey("alice", "asset1"), HoldingKey("alice", "asset2"))
}

// ---------------------------------------------------------------------------
// NewAssetTransaction
// ---------------------------------------------------------------------------

func TestNewAssetTransaction_Valid(t *testing.T) {
	_, issuerKeyStr := makeTestWallet(t)
	_ = issuerKeyStr // not used directly here
	senderKey, _ := makeTestWallet(t)
	receiverKey, _ := makeTestWallet(t)

	at, err := NewAssetTransaction(senderKey, receiverKey.Public(), "asset-id-123", 100, AssetTxTypeTransfer)

	require.NoError(t, err)
	assert.Equal(t, float64(100), at.Tx.Amount)
	assert.Equal(t, "asset-id-123", at.AssetID)
	assert.Equal(t, AssetTxTypeTransfer, at.TxType)
	assert.Len(t, at.Tx.Signatures, 1)
	assert.NotZero(t, at.Tx.Nonce)
}

func TestNewAssetTransaction_NilSenderKey(t *testing.T) {
	_, receiverKeyStr := makeTestWallet(t)
	receiverPubKey, err := PublicKeyFromString(receiverKeyStr)
	require.NoError(t, err)

	_, err = NewAssetTransaction(nil, receiverPubKey, "asset-id", 100, AssetTxTypeTransfer)
	assert.ErrorContains(t, err, "sender key must not be nil")
}

func TestNewAssetTransaction_NilReceiverKey(t *testing.T) {
	senderKey, _ := makeTestWallet(t)

	_, err := NewAssetTransaction(senderKey, nil, "asset-id", 100, AssetTxTypeTransfer)
	assert.ErrorContains(t, err, "receiver public key must not be nil")
}

func TestNewAssetTransaction_ZeroQuantity(t *testing.T) {
	senderKey, _ := makeTestWallet(t)
	receiverKey, _ := makeTestWallet(t)

	_, err := NewAssetTransaction(senderKey, receiverKey.Public(), "asset-id", 0, AssetTxTypeTransfer)
	assert.ErrorContains(t, err, "quantity must be greater than zero")
}

// ---------------------------------------------------------------------------
// Issue
// ---------------------------------------------------------------------------

func TestAssetIssueTransaction(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	_, recipientKeyStr := makeTestWallet(t)
	recipientKey, err := PublicKeyFromString(recipientKeyStr)
	require.NoError(t, err)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	at, err := NewAssetTransaction(issuerKey, recipientKey, asset.ID, 250_000, AssetTxTypeIssue)
	require.NoError(t, err)

	require.NoError(t, at.Validate(nil, assets, holdings, nil, nil))
	require.NoError(t, ApplyAssetTransaction(at, assets, holdings))

	holdingKey := HoldingKey(recipientKeyStr, asset.ID)
	holding, exists := holdings[holdingKey]
	require.True(t, exists)
	assert.Equal(t, float64(250_000), holding.Balance)
	assert.Equal(t, float64(250_000), asset.CirculatingSupply)
}

func TestAssetIssuerOnlyIssuance(t *testing.T) {
	asset, _ := makeTestAsset(t)
	_, receiverKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	// Create issue transaction signed by a non-issuer wallet.
	nonIssuerPrivKey, _ := GeneratePrivateKey()
	receiverPubKey, err := PublicKeyFromString(receiverKeyStr)
	require.NoError(t, err)

	at, err := NewAssetTransaction(nonIssuerPrivKey, receiverPubKey, asset.ID, 100, AssetTxTypeIssue)
	require.NoError(t, err)

	err = at.Validate(nil, assets, holdings, nil, nil)
	assert.ErrorContains(t, err, "only the asset issuer may issue tokens")
}

// ---------------------------------------------------------------------------
// Transfer
// ---------------------------------------------------------------------------

func TestAssetTransfer_Valid(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	aliceKey, aliceKeyStr := makeTestWallet(t)
	bobKey, bobKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	// Issue 500 tokens to Alice.
	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 500)

	// Transfer 200 from Alice to Bob.
	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 200, AssetTxTypeTransfer)
	require.NoError(t, err)
	require.NoError(t, at.Validate(nil, assets, holdings, nil, nil))
	require.NoError(t, ApplyAssetTransaction(at, assets, holdings))

	aliceHolding := holdings[HoldingKey(aliceKeyStr, asset.ID)]
	bobHolding := holdings[HoldingKey(bobKeyStr, asset.ID)]

	require.NotNil(t, aliceHolding)
	require.NotNil(t, bobHolding)
	assert.Equal(t, float64(300), aliceHolding.Balance)
	assert.Equal(t, float64(200), bobHolding.Balance)
	// CirculatingSupply unchanged by transfers.
	assert.Equal(t, float64(500), asset.CirculatingSupply)
}

func TestAssetTransfer_InsufficientBalance(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	aliceKey, _ := makeTestWallet(t)
	bobKey, _ := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	// Issue only 50 tokens to Alice.
	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 50)

	// Attempt to transfer 100 — more than Alice holds.
	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 100, AssetTxTypeTransfer)
	require.NoError(t, err)

	err = at.Validate(nil, assets, holdings, nil, nil)
	assert.ErrorContains(t, err, "insufficient balance")
}

func TestAssetTransfer_NoHolding(t *testing.T) {
	asset, _ := makeTestAsset(t)
	aliceKey, _ := makeTestWallet(t)
	bobKey, _ := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{} // Alice has no holding at all.

	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 10, AssetTxTypeTransfer)
	require.NoError(t, err)

	err = at.Validate(nil, assets, holdings, nil, nil)
	assert.ErrorContains(t, err, "insufficient balance")
}

func TestAssetTransfer_InvalidSignature(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	aliceKey, _ := makeTestWallet(t)
	bobKey, _ := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 100)

	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 50, AssetTxTypeTransfer)
	require.NoError(t, err)

	// Corrupt the first byte of the signature.
	at.Tx.Signatures[0][0] ^= 0xff

	err = at.Validate(nil, assets, holdings, nil, nil)
	assert.ErrorContains(t, err, "invalid transaction signature")
}

func TestAssetTransfer_LockupActive(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	aliceKey, aliceKeyStr := makeTestWallet(t)
	bobKey, _ := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 100)

	// Manually activate a 365-day lockup on Alice's holding.
	holdingKey := HoldingKey(aliceKeyStr, asset.ID)
	holdings[holdingKey].LockedUntil = time.Now().Unix() + 365*86400

	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 50, AssetTxTypeTransfer)
	require.NoError(t, err)

	err = at.Validate(nil, assets, holdings, nil, nil)
	assert.ErrorContains(t, err, "holding is locked until")
}

func TestAssetTransfer_LockupExpired(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	aliceKey, aliceKeyStr := makeTestWallet(t)
	bobKey, _ := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 100)

	// Set lockup 1 second in the past — should be treated as expired.
	holdingKey := HoldingKey(aliceKeyStr, asset.ID)
	holdings[holdingKey].LockedUntil = time.Now().Unix() - 1

	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 50, AssetTxTypeTransfer)
	require.NoError(t, err)

	// Validate should pass — lockup is expired.
	assert.NoError(t, at.Validate(nil, assets, holdings, nil, nil))
}

// ---------------------------------------------------------------------------
// Redeem
// ---------------------------------------------------------------------------

func TestAssetRedeem(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	aliceKey, aliceKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	// Issue 200 tokens to Alice.
	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 200)
	assert.Equal(t, float64(200), asset.CirculatingSupply)

	// Alice redeems 75 tokens back to the issuer.
	issuerPubKey := issuerKey.Public()
	at, err := NewAssetTransaction(aliceKey, issuerPubKey, asset.ID, 75, AssetTxTypeRedeem)
	require.NoError(t, err)
	require.NoError(t, at.Validate(nil, assets, holdings, nil, nil))
	require.NoError(t, ApplyAssetTransaction(at, assets, holdings))

	aliceHolding := holdings[HoldingKey(aliceKeyStr, asset.ID)]
	require.NotNil(t, aliceHolding)
	assert.Equal(t, float64(125), aliceHolding.Balance)
	assert.Equal(t, float64(125), asset.CirculatingSupply)
}

func TestAssetRedeem_FullBalance(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	aliceKey, aliceKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 100)

	// Redeem entire balance — holding should be removed from the map.
	at, err := NewAssetTransaction(aliceKey, issuerKey.Public(), asset.ID, 100, AssetTxTypeRedeem)
	require.NoError(t, err)
	require.NoError(t, at.Validate(nil, assets, holdings, nil, nil))
	require.NoError(t, ApplyAssetTransaction(at, assets, holdings))

	_, exists := holdings[HoldingKey(aliceKeyStr, asset.ID)]
	assert.False(t, exists, "holding with zero balance should be removed from the map")
	assert.Equal(t, float64(0), asset.CirculatingSupply)
}

// ---------------------------------------------------------------------------
// MaxHolders
// ---------------------------------------------------------------------------

func TestAssetMaxHolders(t *testing.T) {
	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	// Create an asset with a max of 2 holders.
	asset, err := NewAsset(
		key,
		AssetTypeEquity,
		1_000_000,
		"GBP",
		AssetMetadata{CompanyName: "MaxTest"},
		TransferRestrictions{MaxHolders: 2},
	)
	require.NoError(t, err)

	aliceKey, aliceKeyStr := makeTestWallet(t)
	bobKey, _ := makeTestWallet(t)
	charlieKey, _ := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	// Issue to Alice and Bob (reaches the limit of 2).
	issueTokens(t, key, aliceKey, asset, assets, holdings, 100)
	issueTokens(t, key, bobKey, asset, assets, holdings, 100)
	assert.Len(t, holdings, 2)

	// Transfer from Alice to Charlie (would create a 3rd holder) — must fail.
	at, err := NewAssetTransaction(aliceKey, charlieKey.Public(), asset.ID, 10, AssetTxTypeTransfer)
	require.NoError(t, err)
	err = at.Validate(nil, assets, holdings, nil, nil)
	assert.ErrorContains(t, err, "max holders reached")

	// Transfer from Alice to Bob (Bob already holds — no new holder) — must pass.
	at2, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 10, AssetTxTypeTransfer)
	require.NoError(t, err)
	assert.NoError(t, at2.Validate(nil, assets, holdings, nil, nil))

	_ = aliceKeyStr // used implicitly via HoldingKey in holdings map
}

// ---------------------------------------------------------------------------
// Credential checks
// ---------------------------------------------------------------------------

func TestAssetBlockedJurisdiction(t *testing.T) {
	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	asset, err := NewAsset(
		key,
		AssetTypeEquity,
		1_000_000,
		"GBP",
		AssetMetadata{CompanyName: "GeoTest"},
		TransferRestrictions{BlockedJurisdictions: []string{"DE", "FR"}},
	)
	require.NoError(t, err)

	aliceKey, _ := makeTestWallet(t)
	germanWalletKey, germanKeyStr := makeTestWallet(t)
	germanPubKey, err := PublicKeyFromString(germanKeyStr)
	require.NoError(t, err)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, key, aliceKey, asset, assets, holdings, 200)

	// Create a credential for the German wallet.
	credentials := map[string]*CredentialAttestation{
		germanKeyStr: {
			WalletPublicKey: germanKeyStr,
			InvestorClass:   InvestorClassProfessional,
			KYCStatus:       KYCStatusVerified,
			Jurisdiction:    "DE",
			ExpiresAt:       time.Now().Unix() + 86400,
		},
	}

	// Transfer to German wallet — should fail (DE is blocked).
	at, err := NewAssetTransaction(aliceKey, germanPubKey, asset.ID, 50, AssetTxTypeTransfer)
	require.NoError(t, err)
	err = at.Validate(nil, assets, holdings, credentials, nil)
	assert.ErrorContains(t, err, "jurisdiction")
	assert.ErrorContains(t, err, "DE")

	_ = germanWalletKey
}

func TestAssetAccreditedOnly_Accredited(t *testing.T) {
	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	asset, err := NewAsset(
		key,
		AssetTypeEquity,
		1_000_000,
		"GBP",
		AssetMetadata{CompanyName: "PrivateTest"},
		TransferRestrictions{AccreditedOnly: true},
	)
	require.NoError(t, err)

	aliceKey, _ := makeTestWallet(t)
	bobKey, bobKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, key, aliceKey, asset, assets, holdings, 200)

	// Bob has a valid accredited credential.
	credentials := map[string]*CredentialAttestation{
		bobKeyStr: {
			WalletPublicKey: bobKeyStr,
			InvestorClass:   InvestorClassAccredited,
			KYCStatus:       KYCStatusVerified,
			Jurisdiction:    "GB",
			ExpiresAt:       time.Now().Unix() + 86400,
		},
	}

	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 50, AssetTxTypeTransfer)
	require.NoError(t, err)
	assert.NoError(t, at.Validate(nil, assets, holdings, credentials, nil))
}

func TestAssetAccreditedOnly_RetailBlocked(t *testing.T) {
	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	asset, err := NewAsset(
		key,
		AssetTypeEquity,
		1_000_000,
		"GBP",
		AssetMetadata{CompanyName: "PrivateTest"},
		TransferRestrictions{AccreditedOnly: true},
	)
	require.NoError(t, err)

	aliceKey, _ := makeTestWallet(t)
	retailKey, retailKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, key, aliceKey, asset, assets, holdings, 200)

	// Retail investor credential.
	credentials := map[string]*CredentialAttestation{
		retailKeyStr: {
			WalletPublicKey: retailKeyStr,
			InvestorClass:   InvestorClassRetail,
			KYCStatus:       KYCStatusVerified,
			Jurisdiction:    "GB",
			ExpiresAt:       time.Now().Unix() + 86400,
		},
	}

	at, err := NewAssetTransaction(aliceKey, retailKey.Public(), asset.ID, 50, AssetTxTypeTransfer)
	require.NoError(t, err)
	err = at.Validate(nil, assets, holdings, credentials, nil)
	assert.ErrorContains(t, err, "retail")
}

func TestAssetAccreditedOnly_NoCredential(t *testing.T) {
	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	asset, err := NewAsset(
		key,
		AssetTypeEquity,
		1_000_000,
		"GBP",
		AssetMetadata{CompanyName: "PrivateTest"},
		TransferRestrictions{AccreditedOnly: true},
	)
	require.NoError(t, err)

	aliceKey, _ := makeTestWallet(t)
	bobKey, _ := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, key, aliceKey, asset, assets, holdings, 200)

	// Empty credentials map — Bob has no credential at all.
	credentials := map[string]*CredentialAttestation{}

	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 50, AssetTxTypeTransfer)
	require.NoError(t, err)
	err = at.Validate(nil, assets, holdings, credentials, nil)
	assert.ErrorContains(t, err, "accreditation")
}

func TestAssetNoRestrictions_NoCredentialRequired(t *testing.T) {
	asset, issuerKey := makeTestAsset(t) // no restrictions
	aliceKey, _ := makeTestWallet(t)
	bobKey, _ := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 100)

	// Non-nil but empty credentials — still passes because asset has no restrictions.
	credentials := map[string]*CredentialAttestation{}

	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 50, AssetTxTypeTransfer)
	require.NoError(t, err)
	assert.NoError(t, at.Validate(nil, assets, holdings, credentials, nil))
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

func TestApplyAssetTransaction_Idempotent(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	aliceKey, _ := makeTestWallet(t)
	bobKey, _ := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 100)

	// Create a transfer of Alice's full balance to Bob.
	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 100, AssetTxTypeTransfer)
	require.NoError(t, err)

	// First application: should succeed.
	require.NoError(t, at.Validate(nil, assets, holdings, nil, nil))
	require.NoError(t, ApplyAssetTransaction(at, assets, holdings))

	// Second application: Alice's balance is now 0 — must fail.
	err = ApplyAssetTransaction(at, assets, holdings)
	assert.ErrorContains(t, err, "insufficient balance")
}

// ---------------------------------------------------------------------------
// Unknown asset
// ---------------------------------------------------------------------------

func TestValidate_UnknownAsset(t *testing.T) {
	aliceKey, _ := makeTestWallet(t)
	bobKey, _ := makeTestWallet(t)

	assets := map[string]*Asset{} // empty registry
	holdings := map[string]*AssetHolding{}

	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), "nonexistent-asset-id", 10, AssetTxTypeTransfer)
	require.NoError(t, err)

	err = at.Validate(nil, assets, holdings, nil, nil)
	assert.ErrorContains(t, err, "unknown asset ID")
}

// ---------------------------------------------------------------------------
// Lockup applied on new holdings
// ---------------------------------------------------------------------------

func TestAssetLockupAppliedOnIssue(t *testing.T) {
	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	asset, err := NewAsset(
		key,
		AssetTypeEquity,
		1_000_000,
		"GBP",
		AssetMetadata{CompanyName: "LockTest"},
		TransferRestrictions{LockupPeriodDays: 365},
	)
	require.NoError(t, err)

	aliceKey, aliceKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	issueTokens(t, key, aliceKey, asset, assets, holdings, 100)

	holdingKey := HoldingKey(aliceKeyStr, asset.ID)
	holding := holdings[holdingKey]
	require.NotNil(t, holding)

	// LockedUntil must be approximately 365 days from now.
	expectedLockout := time.Now().Unix() + 365*86400
	assert.InDelta(t, expectedLockout, holding.LockedUntil, 5, // 5-second tolerance
		"lockup expiry should be ~365 days from now")
}
