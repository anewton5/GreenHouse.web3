package gonetwork

// ---------------------------------------------------------------------------
// pep_rescreening_test.go — PEP/sanctions periodic re-screening tests
//
// Covers:
//   rescreenAllWallets     — flag alert → SAR created
//                          — block alert → SAR created
//                          — clean wallet → no SAR
//                          — SAR ID collision (duplicate) → skipped
//   StartPEPRescreeningScheduler — goroutine fires within interval
//   CrossBorderHighRiskCheck     — high-risk jurisdiction + amount > €5,000 → Block
//                                — high-risk jurisdiction + amount < €5,000 → Flag
//                                — nil credential → nil
//                                — non-high-risk jurisdiction → nil
// ---------------------------------------------------------------------------

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// controlledScreener: an AMLScreener that returns a preset alert and counts calls.
// ---------------------------------------------------------------------------

type controlledScreener struct {
	alert     *AMLAlert
	callCount int32
}

func (c *controlledScreener) ScreenTransaction(_, _ string, _ string, _ float64, _ string) (*AMLAlert, error) {
	atomic.AddInt32(&c.callCount, 1)
	return c.alert, nil
}

// ---------------------------------------------------------------------------
// rescreenAllWallets
// ---------------------------------------------------------------------------

func TestRescreenAllWallets_FlagAlert_CreatesSAR(t *testing.T) {
	bc := newTestBlockchain(t)

	// Issue a credential so the wallet appears in bc.Credentials.
	_, err := bc.IdentityRegistry.IssueCredential("wallet-pep", InvestorClassRetail, "GB", 365)
	require.NoError(t, err)

	// Register credential in bc.Credentials directly (SealBlock / CredentialTransaction path).

	att, _ := bc.IdentityRegistry.VerifyCredential("wallet-pep")
	bc.Credentials["wallet-pep"] = att

	// Install a screener that always flags.
	screener := &controlledScreener{
		alert: &AMLAlert{
			Severity:    AMLSeverityFlag,
			Reason:      "PEP hit",
			MatchedList: "PEP-LIST",
		},
	}
	bc.AMLScreener = screener

	rescreenAllWallets(bc)

	assert.Equal(t, int32(1), atomic.LoadInt32(&screener.callCount), "screener must be called once per wallet")
	assert.Len(t, bc.PendingSARs, 1, "a SAR must be created for the flagged wallet")
	for _, sar := range bc.PendingSARs {
		assert.Equal(t, "wallet-pep", sar.SenderKey)
		assert.Equal(t, SARStatusPending, sar.Status)
	}
}

func TestRescreenAllWallets_BlockAlert_CreatesSAR(t *testing.T) {
	bc := newTestBlockchain(t)

	att, err := bc.IdentityRegistry.IssueCredential("wallet-sanctioned", InvestorClassRetail, "IR", 365)
	require.NoError(t, err)
	bc.Credentials["wallet-sanctioned"] = att

	screener := &controlledScreener{
		alert: &AMLAlert{
			Severity:    AMLSeverityBlock,
			Reason:      "OFAC SDN match",
			MatchedList: "OFAC-SDN",
		},
	}
	bc.AMLScreener = screener

	rescreenAllWallets(bc)

	assert.Len(t, bc.PendingSARs, 1)
	for _, sar := range bc.PendingSARs {
		assert.Contains(t, sar.Reason, "OFAC SDN match")
	}
}

func TestRescreenAllWallets_CleanWallet_NoSAR(t *testing.T) {
	bc := newTestBlockchain(t)

	att, err := bc.IdentityRegistry.IssueCredential("wallet-clean", InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)
	bc.Credentials["wallet-clean"] = att

	// Screener returns nil (clean).
	bc.AMLScreener = &controlledScreener{alert: nil}

	rescreenAllWallets(bc)

	assert.Empty(t, bc.PendingSARs)
}

func TestRescreenAllWallets_MultipleWallets_OnlyFlaggedGetSAR(t *testing.T) {
	bc := newTestBlockchain(t)

	for i, wallet := range []string{"wallet-1", "wallet-2", "wallet-3"} {
		att, err := bc.IdentityRegistry.IssueCredential(wallet, InvestorClassRetail, "GB", 365)
		require.NoError(t, err)
		bc.Credentials[wallet] = att
		_ = i
	}

	// Use MockAMLScreener from aml.go — flag wallet-2 only.
	mockScreener := NewMockAMLScreener()
	mockScreener.FlagAddress("wallet-2", "PEP-LIST")
	bc.AMLScreener = mockScreener

	rescreenAllWallets(bc)

	assert.Len(t, bc.PendingSARs, 1)
	for _, sar := range bc.PendingSARs {
		assert.Equal(t, "wallet-2", sar.SenderKey)
	}
}

func TestRescreenAllWallets_EmptyCredentials_NoSAR(t *testing.T) {
	bc := newTestBlockchain(t)
	// No credentials registered.
	bc.AMLScreener = &controlledScreener{alert: &AMLAlert{Severity: AMLSeverityFlag}}
	rescreenAllWallets(bc)
	assert.Empty(t, bc.PendingSARs)
}

// ---------------------------------------------------------------------------
// StartPEPRescreeningScheduler
// ---------------------------------------------------------------------------

func TestStartPEPRescreeningScheduler_FiresWithinInterval(t *testing.T) {
	bc := newTestBlockchain(t)

	att, err := bc.IdentityRegistry.IssueCredential("wallet-sched", InvestorClassRetail, "GB", 365)
	require.NoError(t, err)
	bc.Credentials["wallet-sched"] = att

	screener := &controlledScreener{alert: nil} // clean — just counting calls
	bc.AMLScreener = screener

	// Use a short interval. Under the race detector with a loaded suite the OS
	// scheduler can delay goroutines by tens of milliseconds, so we keep a
	// generous 25x margin between the interval and the observation window.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // stop the goroutine when the test ends
	StartPEPRescreeningScheduler(ctx, bc, 20*time.Millisecond)

	// Wait long enough for at least 2 ticks even under heavy goroutine load.
	time.Sleep(500 * time.Millisecond)

	called := atomic.LoadInt32(&screener.callCount)
	assert.GreaterOrEqual(t, called, int32(2), "scheduler must trigger rescreening at least twice")
}

func TestStartPEPRescreeningScheduler_StopsOnContextCancel(t *testing.T) {
	bc := newTestBlockchain(t)
	screener := &controlledScreener{alert: nil}
	bc.AMLScreener = screener

	ctx, cancel := context.WithCancel(context.Background())

	interval := 50 * time.Millisecond
	StartPEPRescreeningScheduler(ctx, bc, interval)

	// Let it fire at least once.
	time.Sleep(80 * time.Millisecond)

	// Cancel and capture the call count.
	cancel()
	time.Sleep(interval + 50*time.Millisecond) // one extra tick window

	countAfterCancel := atomic.LoadInt32(&screener.callCount)

	// Wait another full interval — count must not increase after cancellation.
	time.Sleep(interval + 50*time.Millisecond)
	countFinal := atomic.LoadInt32(&screener.callCount)

	assert.Equal(t, countAfterCancel, countFinal, "scheduler must not fire after context is cancelled")
}

// ---------------------------------------------------------------------------
// CrossBorderHighRiskCheck
// ---------------------------------------------------------------------------

func TestCrossBorderHighRiskCheck_NilCredential_ReturnsNil(t *testing.T) {
	result := CrossBorderHighRiskCheck(nil, 10_000)
	assert.Nil(t, result)
}

func TestCrossBorderHighRiskCheck_LowRiskJurisdiction_ReturnsNil(t *testing.T) {
	cred := &CredentialAttestation{WalletPublicKey: "w", Jurisdiction: "GB"}
	result := CrossBorderHighRiskCheck(cred, 10_000)
	assert.Nil(t, result)
}

func TestCrossBorderHighRiskCheck_HighRiskJurisdiction_BelowThreshold_Flag(t *testing.T) {
	// amount < EUR 5,000 → Flag (not block)
	cred := &CredentialAttestation{WalletPublicKey: "w", Jurisdiction: "IR"} // Iran
	result := CrossBorderHighRiskCheck(cred, 4_999)
	require.NotNil(t, result)
	assert.Equal(t, AMLSeverityFlag, result.Severity)
}

func TestCrossBorderHighRiskCheck_HighRiskJurisdiction_AboveThreshold_Block(t *testing.T) {
	// amount ≥ EUR 5,000 → Block
	cred := &CredentialAttestation{WalletPublicKey: "w", Jurisdiction: "KP"} // North Korea
	result := CrossBorderHighRiskCheck(cred, 5_000)
	require.NotNil(t, result)
	assert.Equal(t, AMLSeverityBlock, result.Severity)
}

func TestCrossBorderHighRiskCheck_Russia_AboveThreshold_Block(t *testing.T) {
	cred := &CredentialAttestation{WalletPublicKey: "w", Jurisdiction: "RU"}
	result := CrossBorderHighRiskCheck(cred, 100_000)
	require.NotNil(t, result)
	assert.Equal(t, AMLSeverityBlock, result.Severity)
	assert.Contains(t, result.MatchedList, "TM-06-FATF")
}

// ---------------------------------------------------------------------------
// ApplyJurisdictionRule — MaxRetailHolders enforcement (new parameter, Fix 1d)
// ---------------------------------------------------------------------------

func TestApplyJurisdictionRule_MaxRetailHolders_CapReached_Error(t *testing.T) {
	rule := &JurisdictionRule{
		CountryCode:      "GB",
		MaxRetailHolders: 5,
	}
	asset := &Asset{ID: "asset-1", AssetType: AssetTypeEquity}
	retailCred := &CredentialAttestation{InvestorClass: InvestorClassRetail}

	// currentRetailCount == MaxRetailHolders → cap reached.
	err := ApplyJurisdictionRule(rule, nil, retailCred, asset, 10_000, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "retail holder cap")
}

func TestApplyJurisdictionRule_MaxRetailHolders_BelowCap_NoError(t *testing.T) {
	rule := &JurisdictionRule{
		CountryCode:      "GB",
		MaxRetailHolders: 10,
	}
	asset := &Asset{ID: "asset-2", AssetType: AssetTypeEquity}
	retailCred := &CredentialAttestation{InvestorClass: InvestorClassRetail}

	// currentRetailCount < MaxRetailHolders → allowed.
	err := ApplyJurisdictionRule(rule, nil, retailCred, asset, 10_000, 4)
	assert.NoError(t, err)
}

func TestApplyJurisdictionRule_MaxRetailHolders_ProfessionalReceiver_NotCounted(t *testing.T) {
	rule := &JurisdictionRule{
		CountryCode:      "DE",
		MaxRetailHolders: 2,
	}
	asset := &Asset{ID: "asset-3", AssetType: AssetTypeDebt}
	// Professional investor — cap does not apply.
	profCred := &CredentialAttestation{InvestorClass: InvestorClassProfessional}

	// currentRetailCount is already at cap, but receiver is professional → pass.
	err := ApplyJurisdictionRule(rule, nil, profCred, asset, 50_000, 2)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// keep context.Background import used in dbft tests
// ---------------------------------------------------------------------------

var _ = context.Background
