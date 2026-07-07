package gonetwork

import (
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMarketMakerAgreement_SignAndVerify(t *testing.T) {
	operatorKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	dealerKeyStr := base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes())

	agreement, err := NewMarketMakerAgreement(
		operatorKey,
		"ASSET-1",
		dealerKeyStr,
		"549300ACMECORP0008",
		25,
		150,
		10,
		20,
		0,
		0,
		time.Now().Unix(),
		0,
	)
	require.NoError(t, err)
	assert.True(t, agreement.VerifyOperatorSignature(operatorKey.Public()))

	tampered := *agreement
	tampered.AssetID = "ASSET-2"
	assert.False(t, tampered.VerifyOperatorSignature(operatorKey.Public()))
}

func TestMarketMakerRegistry_IsDesignatedMarketMaker_TimeWindows(t *testing.T) {
	now := time.Now().Unix()
	registry := NewMarketMakerRegistry()
	registry.ByAsset["ASSET-1"] = []*MarketMakerAgreement{
		{
			ID:            "active",
			AssetID:       "ASSET-1",
			DealerKey:     "dealer-active",
			EffectiveFrom: now - 60,
			Status:        MarketMakerStatusActive,
		},
		{
			ID:            "future",
			AssetID:       "ASSET-1",
			DealerKey:     "dealer-future",
			EffectiveFrom: now + 60,
			Status:        MarketMakerStatusActive,
		},
		{
			ID:            "expired",
			AssetID:       "ASSET-1",
			DealerKey:     "dealer-expired",
			EffectiveFrom: now - 120,
			EffectiveTo:   now - 1,
			Status:        MarketMakerStatusActive,
		},
		{
			ID:            "revoked",
			AssetID:       "ASSET-1",
			DealerKey:     "dealer-revoked",
			EffectiveFrom: now - 60,
			Status:        MarketMakerStatusRevoked,
		},
	}

	assert.True(t, registry.IsDesignatedMarketMaker("ASSET-1", "dealer-active"))
	assert.False(t, registry.IsDesignatedMarketMaker("ASSET-1", "dealer-future"))
	assert.False(t, registry.IsDesignatedMarketMaker("ASSET-1", "dealer-expired"))
	assert.False(t, registry.IsDesignatedMarketMaker("ASSET-1", "dealer-revoked"))

	active := registry.ActiveAgreementsFor("ASSET-1")
	require.Len(t, active, 1)
	assert.Equal(t, "active", active[0].ID)
}

func TestMarketMakerRegistry_RegisterMarketMaker_RequiresRoleClaim(t *testing.T) {
	bc := newClaimsTestBlockchain(t)
	operatorKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	dealerKeyStr := base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes())
	lei := newTestLEI(t, "549300ACMECORP0009")
	agreement, err := NewMarketMakerAgreement(
		operatorKey,
		"ASSET-1",
		dealerKeyStr,
		lei,
		10,
		100,
		1,
		10,
		0,
		0,
		time.Now().Unix(),
		0,
	)
	require.NoError(t, err)

	err = bc.MarketMakerRegistry.RegisterMarketMaker(agreement)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "market_maker")

	claim, err := NewClaim(ClaimTopicInstitutionalRole, "", dealerKeyStr, EntityRoleClaimData(lei, EntityRoleMarketMaker), 30, issuerKey)
	require.NoError(t, err)
	bc.Claims[dealerKeyStr] = []*Claim{claim}

	require.NoError(t, bc.MarketMakerRegistry.RegisterMarketMaker(agreement))
	assert.True(t, bc.MarketMakerRegistry.IsDesignatedMarketMaker("ASSET-1", dealerKeyStr))
}

func TestPersistence_SaveAndLoadState_RoundTripMarketMakerRegistry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "market-makers.db")
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	bc := newClaimsTestBlockchain(t)
	operatorKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	dealerKeyStr := base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes())
	lei := newTestLEI(t, "549300ACMECORP0010")
	claim, err := NewClaim(ClaimTopicInstitutionalRole, "", dealerKeyStr, EntityRoleClaimData(lei, EntityRoleMarketMaker), 30, issuerKey)
	require.NoError(t, err)
	bc.Claims[dealerKeyStr] = []*Claim{claim}

	agreement, err := NewMarketMakerAgreement(
		operatorKey,
		"ASSET-99",
		dealerKeyStr,
		lei,
		5,
		75,
		3,
		15,
		250,
		100000,
		time.Now().Unix(),
		0,
	)
	require.NoError(t, err)
	require.NoError(t, bc.MarketMakerRegistry.RegisterMarketMaker(agreement))

	require.NoError(t, bs.SaveState(bc, 4))

	bc2 := newClaimsTestBlockchain(t)
	lastApplied, err := bs.LoadState(bc2)
	require.NoError(t, err)
	assert.Equal(t, 4, lastApplied)

	restored := bc2.MarketMakerRegistry.AgreementFor("ASSET-99", dealerKeyStr)
	require.NotNil(t, restored)
	assert.Equal(t, agreement.ID, restored.ID)
	assert.Equal(t, agreement.DealerLEI, restored.DealerLEI)
	assert.Equal(t, agreement.FeeRebateBps, restored.FeeRebateBps)
	assert.Equal(t, agreement.MaxSpreadBps, restored.MaxSpreadBps)
	assert.InDelta(t, agreement.MinQuoteSize, restored.MinQuoteSize, 1e-9)
	assert.InDelta(t, agreement.PriorityAllocationPct, restored.PriorityAllocationPct, 1e-9)
}
