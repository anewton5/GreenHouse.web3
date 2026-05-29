package gonetwork

// ---------------------------------------------------------------------------
// instrument_lifecycle_test.go
//
// Covers:
//   ProcessConvertibleConversion — success, burns convertible, issues equity,
//                                  insufficient balance, wrong asset type,
//                                  missing assets, invalid params, existing
//                                  equity holding incremented
//   ValidateBlock                — empty block, prev-hash mismatch, valid asset
//                                  tx block, invalid sender key, bad amount
// ---------------------------------------------------------------------------

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers for convertible conversion tests
// ---------------------------------------------------------------------------

func makeConversionAssets(convertibleID, equityID string) (map[string]*Asset, map[string]*AssetHolding) {
	assets := map[string]*Asset{
		convertibleID: {
			ID:                convertibleID,
			AssetType:         AssetTypeConvertible,
			CirculatingSupply: 1000,
		},
		equityID: {
			ID:                equityID,
			AssetType:         AssetTypeEquity,
			CirculatingSupply: 5000,
		},
	}
	return assets, make(map[string]*AssetHolding)
}

func conversionReq(convertibleID, equityID, holderKey string, units, ratio float64) *ConvertibleConversionRequest {
	return &ConvertibleConversionRequest{
		ID:                 "req-001",
		ConvertibleAssetID: convertibleID,
		EquityAssetID:      equityID,
		ConversionRatio:    ratio,
		UnitsToConvert:     units,
		Trigger:            ConversionTriggerVoluntary,
		HolderKey:          holderKey,
	}
}

// ---------------------------------------------------------------------------
// ProcessConvertibleConversion — success path
// ---------------------------------------------------------------------------

func TestProcessConvertibleConversion_Success(t *testing.T) {
	assets, holdings := makeConversionAssets("conv-001", "equity-001")
	holder := "wallet-holder"

	// Seed holder's convertible balance
	holdings[HoldingKey(holder, "conv-001")] = &AssetHolding{
		AssetID:  "conv-001",
		HolderID: holder,
		Balance:  100,
	}

	req := conversionReq("conv-001", "equity-001", holder, 100, 2.5)
	redeemTx, issueTx, err := ProcessConvertibleConversion(req, assets, holdings)

	require.NoError(t, err)
	assert.Equal(t, AssetTxTypeRedeem, redeemTx.TxType)
	assert.Equal(t, "conv-001", redeemTx.AssetID)
	assert.Equal(t, AssetTxTypeIssue, issueTx.TxType)
	assert.Equal(t, "equity-001", issueTx.AssetID)

	// Convertible balance burned
	assert.NotContains(t, holdings, HoldingKey(holder, "conv-001"),
		"zero-balance convertible holding should be removed")

	// Equity issued (100 × 2.5 = 250)
	equityHolding := holdings[HoldingKey(holder, "equity-001")]
	require.NotNil(t, equityHolding)
	assert.InDelta(t, 250.0, equityHolding.Balance, 0.001)

	// Supply counters updated
	assert.InDelta(t, 900.0, assets["conv-001"].CirculatingSupply, 0.001)
	assert.InDelta(t, 5250.0, assets["equity-001"].CirculatingSupply, 0.001)
}

func TestProcessConvertibleConversion_ExistingEquityHolding_Incremented(t *testing.T) {
	assets, holdings := makeConversionAssets("conv-002", "equity-002")
	holder := "wallet-existing"

	holdings[HoldingKey(holder, "conv-002")] = &AssetHolding{
		AssetID: "conv-002", HolderID: holder, Balance: 50,
	}
	// Pre-existing equity holding
	holdings[HoldingKey(holder, "equity-002")] = &AssetHolding{
		AssetID: "equity-002", HolderID: holder, Balance: 1000,
	}

	req := conversionReq("conv-002", "equity-002", holder, 50, 1.0)
	_, _, err := ProcessConvertibleConversion(req, assets, holdings)
	require.NoError(t, err)

	assert.InDelta(t, 1050.0, holdings[HoldingKey(holder, "equity-002")].Balance, 0.001)
}

// ---------------------------------------------------------------------------
// ProcessConvertibleConversion — error paths
// ---------------------------------------------------------------------------

func TestProcessConvertibleConversion_ZeroUnits_Error(t *testing.T) {
	assets, holdings := makeConversionAssets("conv", "equity")
	req := conversionReq("conv", "equity", "holder", 0, 1.0)
	_, _, err := ProcessConvertibleConversion(req, assets, holdings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "units_to_convert")
}

func TestProcessConvertibleConversion_ZeroRatio_Error(t *testing.T) {
	assets, holdings := makeConversionAssets("conv", "equity")
	req := conversionReq("conv", "equity", "holder", 10, 0)
	_, _, err := ProcessConvertibleConversion(req, assets, holdings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conversion_ratio")
}

func TestProcessConvertibleConversion_EmptyHolderKey_Error(t *testing.T) {
	assets, holdings := makeConversionAssets("conv", "equity")
	req := conversionReq("conv", "equity", "", 10, 1.0)
	_, _, err := ProcessConvertibleConversion(req, assets, holdings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "holder_key")
}

func TestProcessConvertibleConversion_MissingConvertibleAsset_Error(t *testing.T) {
	assets := map[string]*Asset{
		"equity": {ID: "equity", AssetType: AssetTypeEquity},
	}
	_, _, err := ProcessConvertibleConversion(
		conversionReq("missing-conv", "equity", "holder", 10, 1.0),
		assets, make(map[string]*AssetHolding),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestProcessConvertibleConversion_WrongAssetType_Error(t *testing.T) {
	assets := map[string]*Asset{
		"not-conv": {ID: "not-conv", AssetType: AssetTypeEquity},
		"equity":   {ID: "equity", AssetType: AssetTypeEquity},
	}
	_, _, err := ProcessConvertibleConversion(
		conversionReq("not-conv", "equity", "holder", 10, 1.0),
		assets, make(map[string]*AssetHolding),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a convertible")
}

func TestProcessConvertibleConversion_InsufficientBalance_Error(t *testing.T) {
	assets, holdings := makeConversionAssets("conv", "equity")
	holder := "wallet-poor"
	holdings[HoldingKey(holder, "conv")] = &AssetHolding{
		AssetID: "conv", HolderID: holder, Balance: 5,
	}
	_, _, err := ProcessConvertibleConversion(
		conversionReq("conv", "equity", holder, 100, 1.0),
		assets, holdings,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient convertible balance")
}

func TestProcessConvertibleConversion_NoHolding_Error(t *testing.T) {
	assets, holdings := makeConversionAssets("conv", "equity")
	_, _, err := ProcessConvertibleConversion(
		conversionReq("conv", "equity", "wallet-no-holding", 10, 1.0),
		assets, holdings,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient convertible balance")
}

func TestProcessConvertibleConversion_MissingEquityAsset_Error(t *testing.T) {
	holder := "wallet-holder"
	assets := map[string]*Asset{
		"conv": {ID: "conv", AssetType: AssetTypeConvertible, CirculatingSupply: 100},
	}
	holdings := map[string]*AssetHolding{
		HoldingKey(holder, "conv"): {AssetID: "conv", HolderID: holder, Balance: 50},
	}
	_, _, err := ProcessConvertibleConversion(
		conversionReq("conv", "missing-equity", holder, 10, 1.0),
		assets, holdings,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "equity asset")
}

// ---------------------------------------------------------------------------
// ValidateBlock
// ---------------------------------------------------------------------------

func TestValidateBlock_EmptyBlock_ReturnsFalse(t *testing.T) {
	bc := NewBlockchain(context.Background(), "validate-empty")
	assert.False(t, bc.ValidateBlock(Block{}))
}

func TestValidateBlock_BlockWithAssetTx_ReturnsTrue(t *testing.T) {
	bc := NewBlockchain(context.Background(), "validate-asset")
	b := Block{
		PrevHash:          bc.Blocks[len(bc.Blocks)-1].CalculateHash(),
		AssetTransactions: []AssetTransaction{{AssetID: "a1"}},
	}
	b.SetPayloadHash()
	assert.True(t, bc.ValidateBlock(b))
}

func TestValidateBlock_BlockWithOrderTx_ReturnsTrue(t *testing.T) {
	bc := NewBlockchain(context.Background(), "validate-order")

	// Item 11: orders now require a valid placer signature.
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	order, err := NewOrder(placerKey, "a1", OrderSideBid, 10.0, 5.0, 0)
	require.NoError(t, err)

	b := Block{
		PrevHash:          bc.Blocks[len(bc.Blocks)-1].CalculateHash(),
		OrderTransactions: []OrderTransaction{{Order: *order}},
	}
	b.SetPayloadHash()
	assert.True(t, bc.ValidateBlock(b))
}

func TestValidateBlock_WrongPrevHash_ReturnsFalse(t *testing.T) {
	bc := NewBlockchain(context.Background(), "validate-prev")
	b := Block{
		PrevHash:          "wrong-hash",
		AssetTransactions: []AssetTransaction{{AssetID: "a1"}},
	}
	assert.False(t, bc.ValidateBlock(b))
}

func TestValidateBlock_SignedTxValid_ReturnsTrue(t *testing.T) {
	bc := NewBlockchain(context.Background(), "validate-signed")
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	senderPub := base64.StdEncoding.EncodeToString(key.Public().Bytes())

	tx := Transaction{
		Sender:       senderPub,
		Receiver:     "recv",
		Amount:       10,
		RequiredSigs: 1,
	}
	tx.GenerateNonce()
	require.NoError(t, tx.SignTransaction(key))

	b := Block{
		PrevHash:     bc.Blocks[len(bc.Blocks)-1].CalculateHash(),
		Transactions: []Transaction{tx},
	}
	b.SetPayloadHash()
	assert.True(t, bc.ValidateBlock(b))
}

func TestValidateBlock_InvalidSenderKey_ReturnsFalse(t *testing.T) {
	bc := NewBlockchain(context.Background(), "validate-bad-key")
	b := Block{
		PrevHash: bc.Blocks[len(bc.Blocks)-1].CalculateHash(),
		Transactions: []Transaction{
			{Sender: "not-a-valid-pub-key", Receiver: "recv", Amount: 1, RequiredSigs: 1},
		},
	}
	assert.False(t, bc.ValidateBlock(b))
}

func TestValidateBlock_ZeroAmount_ReturnsFalse(t *testing.T) {
	bc := NewBlockchain(context.Background(), "validate-zero-amount")
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	senderPub := base64.StdEncoding.EncodeToString(key.Public().Bytes())

	tx := Transaction{
		Sender:       senderPub,
		Receiver:     "recv",
		Amount:       0,
		RequiredSigs: 1,
	}
	tx.GenerateNonce()
	require.NoError(t, tx.SignTransaction(key))

	b := Block{
		PrevHash:     bc.Blocks[len(bc.Blocks)-1].CalculateHash(),
		Transactions: []Transaction{tx},
	}
	assert.False(t, bc.ValidateBlock(b))
}

func TestValidateBlock_EmptyChain_NoPrevHashCheck(t *testing.T) {
	bc := &Blockchain{
		Blocks:    nil,
		Delegates: nil,
	}
	// With no prior blocks the prev-hash check is skipped
	b := Block{AssetTransactions: []AssetTransaction{{AssetID: "a1"}}}
	assert.True(t, bc.ValidateBlock(b))
}
