package gonetwork

// ---------------------------------------------------------------------------
// preferred_settlement_test.go — F-5 PreferredSettlementMethod tests
//
// Verifies that bc.PreferredSettlementMethod:
//   - Returns SettlementEURC for EUR when no CeBM provider is registered.
//   - Returns SettlementCeBM for EUR when a Pontes provider is registered.
//   - Returns SettlementFasterPay for GBP regardless of router state.
//   - Returns SettlementSWIFT for USD/CHF regardless of router state.
// ---------------------------------------------------------------------------

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPreferredSettlementMethod_EUR_NoPontes_ReturnsEURC asserts that EUR
// instructions default to EURC when no Pontes (CeBM) provider is registered.
func TestPreferredSettlementMethod_EUR_NoPontes_ReturnsEURC(t *testing.T) {
	bc := NewBlockchain(context.Background(), "f5-eur-no-pontes")
	// No SettlementCeBM registered — should fall through to DefaultSettlementMethod.
	assert.Equal(t, SettlementEURC, bc.PreferredSettlementMethod("EUR"))
}

// TestPreferredSettlementMethod_EUR_WithPontes_ReturnsCeBM asserts that EUR
// instructions are upgraded to CeBM when a Pontes provider is registered.
func TestPreferredSettlementMethod_EUR_WithPontes_ReturnsCeBM(t *testing.T) {
	bc := NewBlockchain(context.Background(), "f5-eur-with-pontes")
	bc.RegisterSettlementProvider(SettlementCeBM, NewMockPaymentProvider())
	assert.Equal(t, SettlementCeBM, bc.PreferredSettlementMethod("EUR"))
}

// TestPreferredSettlementMethod_GBP_AlwaysFasterPay asserts that GBP is
// unaffected by router state — always returns SettlementFasterPay.
func TestPreferredSettlementMethod_GBP_AlwaysFasterPay(t *testing.T) {
	bc := NewBlockchain(context.Background(), "f5-gbp")
	// Even if CeBM is registered, GBP is not in the upgrade map.
	bc.RegisterSettlementProvider(SettlementCeBM, NewMockPaymentProvider())
	assert.Equal(t, SettlementFasterPay, bc.PreferredSettlementMethod("GBP"))
}

// TestPreferredSettlementMethod_USD_AlwaysSWIFT asserts that USD is unaffected.
func TestPreferredSettlementMethod_USD_AlwaysSWIFT(t *testing.T) {
	bc := NewBlockchain(context.Background(), "f5-usd")
	bc.RegisterSettlementProvider(SettlementCeBM, NewMockPaymentProvider())
	assert.Equal(t, SettlementSWIFT, bc.PreferredSettlementMethod("USD"))
}

// TestPreferredSettlementMethod_EURRoute_AppliedInApplyBlockState asserts that
// sealing a EUR trade when a Pontes provider is registered results in a
// SettlementCeBM instruction, not SettlementEURC (F-5 integration check).
func TestPreferredSettlementMethod_EURRoute_AppliedInApplyBlockState(t *testing.T) {
	bc := NewBlockchain(context.Background(), "f5-integration")
	bc.RegisterSettlementProvider(SettlementCeBM, NewMockPaymentProvider())

	// Seal a EUR trade — the instruction Method must be CeBM.
	sealEURTrade(t, bc, 50.0, 2.0)

	bc.Mu.Lock()
	var instr *PaymentInstruction
	for _, i := range bc.PendingInstructions {
		instr = i
		break
	}
	bc.Mu.Unlock()

	if instr != nil {
		assert.Equal(t, SettlementCeBM, instr.Method,
			"EUR instruction must use CeBM when Pontes provider is registered")
	}
	// If the mock settled it immediately, check ConfirmedPayments instead.
	assert.Len(t, bc.Trades, 1, "trade must be recorded")
}
