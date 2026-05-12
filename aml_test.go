package gonetwork

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// MockAMLScreener unit tests
// ---------------------------------------------------------------------------

// TestAMLScreener_PassesClean verifies that ScreenTransaction returns nil (no alert)
// for addresses that are not in any block or flag list.
func TestAMLScreener_PassesClean(t *testing.T) {
	screener := NewMockAMLScreener()

	_, senderKey := makeTestWallet(t)
	_, receiverKey := makeTestWallet(t)

	alert, err := screener.ScreenTransaction(senderKey, receiverKey, "asset-1", 100.0, "GBP")
	require.NoError(t, err)
	assert.Nil(t, alert, "clean addresses should return no alert")
	assert.Len(t, screener.Calls, 1)
}

// TestAMLScreener_BlocksAddress verifies that a blocked sender triggers a
// block-severity alert.
func TestAMLScreener_BlocksSender(t *testing.T) {
	screener := NewMockAMLScreener()

	_, senderKey := makeTestWallet(t)
	_, receiverKey := makeTestWallet(t)

	screener.BlockAddress(senderKey, "OFAC SDN")

	alert, err := screener.ScreenTransaction(senderKey, receiverKey, "asset-1", 500.0, "USD")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, AMLSeverityBlock, alert.Severity)
	assert.Equal(t, "OFAC SDN", alert.MatchedList)
	assert.NotZero(t, alert.ScreenedAt)
}

// TestAMLScreener_BlocksReceiver verifies that a blocked receiver also triggers a
// block-severity alert (transactions to sanctioned parties must be rejected).
func TestAMLScreener_BlocksReceiver(t *testing.T) {
	screener := NewMockAMLScreener()

	_, senderKey := makeTestWallet(t)
	_, receiverKey := makeTestWallet(t)

	screener.BlockAddress(receiverKey, "EU Consolidated Sanctions")

	alert, err := screener.ScreenTransaction(senderKey, receiverKey, "asset-1", 1000.0, "EUR")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, AMLSeverityBlock, alert.Severity)
	assert.Equal(t, "EU Consolidated Sanctions", alert.MatchedList)
}

// TestAMLScreener_FlagsSender verifies that a flagged (PEP) sender triggers a
// flag-severity alert but does not block.
func TestAMLScreener_FlagsSender(t *testing.T) {
	screener := NewMockAMLScreener()

	_, senderKey := makeTestWallet(t)
	_, receiverKey := makeTestWallet(t)

	screener.FlagAddress(senderKey, "PEP")

	alert, err := screener.ScreenTransaction(senderKey, receiverKey, "asset-1", 200.0, "GBP")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, AMLSeverityFlag, alert.Severity)
	assert.Equal(t, "PEP", alert.MatchedList)
}

// TestAMLScreener_FlagsReceiver verifies that a flagged receiver triggers a
// flag-severity alert.
func TestAMLScreener_FlagsReceiver(t *testing.T) {
	screener := NewMockAMLScreener()

	_, senderKey := makeTestWallet(t)
	_, receiverKey := makeTestWallet(t)

	screener.FlagAddress(receiverKey, "UN Sanctions Watch")

	alert, err := screener.ScreenTransaction(senderKey, receiverKey, "asset-1", 50.0, "GBP")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, AMLSeverityFlag, alert.Severity)
}

// TestAMLScreener_BlockTakesPrecedenceOverFlag verifies that when a wallet appears
// in both the block and flag list, the block takes precedence.
func TestAMLScreener_BlockTakesPrecedenceOverFlag(t *testing.T) {
	screener := NewMockAMLScreener()

	_, senderKey := makeTestWallet(t)
	_, receiverKey := makeTestWallet(t)

	screener.BlockAddress(senderKey, "OFAC SDN")
	screener.FlagAddress(senderKey, "PEP") // also flagged — block must win

	alert, err := screener.ScreenTransaction(senderKey, receiverKey, "asset-1", 100.0, "GBP")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, AMLSeverityBlock, alert.Severity)
}

// TestAMLScreener_RecordsCallHistory verifies that every ScreenTransaction call
// is recorded in the Calls slice for audit / test-assertion purposes.
func TestAMLScreener_RecordsCallHistory(t *testing.T) {
	screener := NewMockAMLScreener()

	_, k1 := makeTestWallet(t)
	_, k2 := makeTestWallet(t)
	_, k3 := makeTestWallet(t)

	_, _ = screener.ScreenTransaction(k1, k2, "a1", 100, "GBP")
	_, _ = screener.ScreenTransaction(k2, k3, "a2", 200, "EUR")

	assert.Len(t, screener.Calls, 2)
	assert.Equal(t, k1, screener.Calls[0].SenderKey)
	assert.Equal(t, k2, screener.Calls[1].SenderKey)
	assert.NotZero(t, screener.Calls[0].CalledAt)
}

// ---------------------------------------------------------------------------
// AML wired into AssetTransaction.Validate
// ---------------------------------------------------------------------------

// TestAMLScreener_WiredIntoValidate_BlocksTransfer verifies that AssetTransaction.Validate
// returns an error when the AML screener blocks the sender.
func TestAMLScreener_WiredIntoValidate_BlocksTransfer(t *testing.T) {
	// Build assets/holdings maps with an issued balance.
	asset, issuerKey := makeTestAsset(t)
	assets := map[string]*Asset{asset.ID: asset}
	holdings := make(map[string]*AssetHolding)

	senderPrivKey, senderKey := makeTestWallet(t)
	_, receiverKey := makeTestWallet(t)

	// Issue tokens to sender.
	issueTokens(t, issuerKey, senderPrivKey, asset, assets, holdings, 1000)

	// Build a transfer from sender to receiver.
	receiverPub, err := PublicKeyFromString(receiverKey)
	require.NoError(t, err)
	at, err := NewAssetTransaction(senderPrivKey, receiverPub, asset.ID, 100, AssetTxTypeTransfer)
	require.NoError(t, err)

	// Without screener — must pass.
	require.NoError(t, at.Validate(assets, holdings, nil, nil))

	// Block sender and pass screener — must fail.
	screener := NewMockAMLScreener()
	screener.BlockAddress(senderKey, "TEST_LIST")

	err = at.Validate(assets, holdings, nil, nil, screener)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked by AML screening")
}

// TestAMLScreener_WiredIntoValidate_AllowsClean verifies that a clean screener
// does not interfere with a legitimate transfer.
func TestAMLScreener_WiredIntoValidate_AllowsClean(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	assets := map[string]*Asset{asset.ID: asset}
	holdings := make(map[string]*AssetHolding)

	senderPrivKey, _ := makeTestWallet(t)
	_, receiverKey := makeTestWallet(t)

	issueTokens(t, issuerKey, senderPrivKey, asset, assets, holdings, 1000)

	receiverPub, err := PublicKeyFromString(receiverKey)
	require.NoError(t, err)
	at, err := NewAssetTransaction(senderPrivKey, receiverPub, asset.ID, 100, AssetTxTypeTransfer)
	require.NoError(t, err)

	screener := NewMockAMLScreener() // no blocked addresses
	assert.NoError(t, at.Validate(assets, holdings, nil, nil, screener))
}

// TestAMLScreener_WiredIntoValidate_FlagDoesNotBlock verifies that a flag-severity
// alert allows the transaction through (compliance notification only).
func TestAMLScreener_WiredIntoValidate_FlagDoesNotBlock(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	assets := map[string]*Asset{asset.ID: asset}
	holdings := make(map[string]*AssetHolding)

	senderPrivKey, senderKey := makeTestWallet(t)
	_, receiverKey := makeTestWallet(t)

	issueTokens(t, issuerKey, senderPrivKey, asset, assets, holdings, 1000)

	receiverPub, err := PublicKeyFromString(receiverKey)
	require.NoError(t, err)
	at, err := NewAssetTransaction(senderPrivKey, receiverPub, asset.ID, 100, AssetTxTypeTransfer)
	require.NoError(t, err)

	screener := NewMockAMLScreener()
	screener.FlagAddress(senderKey, "PEP") // flagged but not blocked

	// Must pass Validate (flag does not block).
	assert.NoError(t, at.Validate(assets, holdings, nil, nil, screener))
	// Screener must have recorded the call.
	assert.Len(t, screener.Calls, 1)
}

// ---------------------------------------------------------------------------
// ProspectusWarning threshold tests
// ---------------------------------------------------------------------------

// TestProspectusWarning_ThresholdConstant verifies the threshold constant is 90%.
func TestProspectusWarning_ThresholdConstant(t *testing.T) {
	assert.Equal(t, 0.90, ProspectusWarningThreshold)
}

// TestCheckProspectusThresholds_EmitsWarning verifies that a blockchain events
// channel receives a prospectus_warning event when a jurisdiction is at or above 90%.
func TestCheckProspectusThresholds_EmitsWarning(t *testing.T) {
	bc := &Blockchain{
		Events: make(chan StreamEvent, 16),
		ProspectusExemptions: map[string]*ProspectusExemption{
			"asset-1": {
				AssetID:                     "asset-1",
				Basis:                       ExemptionProspectusArt1_4,
				MaxRetailPerJurisdiction:    10,
				RetailHoldersByJurisdiction: map[string]int{"GB": 9}, // 90% exactly
			},
		},
	}

	CheckProspectusThresholds(bc, bc.ProspectusExemptions)

	require.Len(t, bc.Events, 1)
	evt := <-bc.Events
	assert.Equal(t, EventProspectusWarning, evt.Type)
}

// TestCheckProspectusThresholds_NoWarningBeforeThreshold verifies that a jurisdiction
// below the 90% threshold does not emit a warning.
func TestCheckProspectusThresholds_NoWarningBeforeThreshold(t *testing.T) {
	bc := &Blockchain{
		Events: make(chan StreamEvent, 16),
		ProspectusExemptions: map[string]*ProspectusExemption{
			"asset-1": {
				AssetID:                     "asset-1",
				MaxRetailPerJurisdiction:    10,
				RetailHoldersByJurisdiction: map[string]int{"GB": 8}, // 80% — below threshold
			},
		},
	}

	CheckProspectusThresholds(bc, bc.ProspectusExemptions)

	assert.Empty(t, bc.Events)
}
