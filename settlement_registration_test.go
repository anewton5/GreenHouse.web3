package gonetwork

// ---------------------------------------------------------------------------
// settlement_registration_test.go — F-4 SettlementRegistrar wiring tests
//
// Verifies that applyBlockState:
//   - Detects providers implementing SettlementRegistrar and calls
//     RegisterSettlement asynchronously after oracle-signing (F-4).
//   - Writes PontesTransactionID and SettlementNetwork back to the live
//     instruction on success.
//   - Emits EventPaymentRegistrationFailed and leaves instruction pending
//     when RegisterSettlement returns an error.
// ---------------------------------------------------------------------------

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

// mockRegistrarProvider is a PaymentProvider that also implements
// SettlementRegistrar. RegisterSettlement signals registeredCh and returns
// txID / err as configured.
type mockRegistrarProvider struct {
	MockPaymentProvider
	txID         string
	regErr       error
	registeredCh chan struct{}
}

func newMockRegistrar(txID string, regErr error) *mockRegistrarProvider {
	return &mockRegistrarProvider{
		MockPaymentProvider: *NewMockPaymentProvider(),
		txID:                txID,
		regErr:              regErr,
		registeredCh:        make(chan struct{}, 1),
	}
}

func (m *mockRegistrarProvider) RegisterSettlement(instruction *PaymentInstruction) (string, error) {
	m.registeredCh <- struct{}{}
	if m.regErr != nil {
		return "", m.regErr
	}
	return m.txID, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// sealEURTrade seeds an EUR equity asset + buyer/seller holdings and seals a
// single block so that a trade is executed and a payment instruction is
// created. Returns the trade ID.
func sealEURTrade(t *testing.T, bc *Blockchain, price, qty float64) string {
	t.Helper()
	assetID := "eu-bond-f4"
	seedAsset(bc, assetID, "EUR")

	buyerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	sellerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	sellerPub := base64.StdEncoding.EncodeToString(sellerKey.Public().Bytes())
	seedHolding(bc, sellerPub, assetID, qty)

	buyTx := placeOrderTx(t, buyerKey, assetID, OrderSideBid, price, qty)
	sellTx := placeOrderTx(t, sellerKey, assetID, OrderSideAsk, price, qty)
	bc.SealBlock(nil, []OrderTransaction{buyTx, sellTx}, nil)

	require.Len(t, bc.Trades, 1, "expected exactly one trade")
	return bc.Trades[0].ID
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestApplyBlockState_CeBMInstruction_RegisterSettlementCalled asserts that
// when a SettlementRegistrar is registered for SettlementEURC (the method
// assigned to EUR trades by DefaultSettlementMethod), applyBlockState calls
// RegisterSettlement asynchronously after sealing the block and writes the
// returned transactionID back to the live instruction (F-4).
func TestApplyBlockState_CeBMInstruction_RegisterSettlementCalled(t *testing.T) {
	bc := NewBlockchain(context.Background(), "f4-register")

	// EUR trades use SettlementEURC by default (F-5 will auto-upgrade to CeBM).
	// We register the mock for SettlementEURC so the type assertion fires.
	mock := newMockRegistrar("pontes-tx-001", nil)
	bc.RegisterSettlementProvider(SettlementEURC, mock)

	// Seal a EUR trade so applyBlockState creates a CeBM instruction.
	tradeID := sealEURTrade(t, bc, 100.0, 5.0)

	// Wait for the async goroutine to complete (up to 2 seconds).
	select {
	case <-mock.registeredCh:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("RegisterSettlement was not called within 2 seconds")
	}

	// Give the goroutine time to acquire bc.Mu and write back txID.
	time.Sleep(10 * time.Millisecond)

	bc.Mu.Lock()
	instr := bc.PendingInstructions[tradeID]
	bc.Mu.Unlock()

	require.NotNil(t, instr, "instruction must remain in PendingInstructions")
	assert.Equal(t, "pontes-tx-001", instr.PontesTransactionID, "PontesTransactionID must be written back")
	assert.Equal(t, "eurosystem-pontes", instr.SettlementNetwork, "SettlementNetwork must be set")
}

// TestApplyBlockState_CeBMRegistrationFailure_EventEmitted asserts that when
// RegisterSettlement returns an error, EventPaymentRegistrationFailed is emitted
// and the instruction remains in PendingInstructions so the operator can retry
// via the admin endpoint (F-4).
func TestApplyBlockState_CeBMRegistrationFailure_EventEmitted(t *testing.T) {
	bc := NewBlockchain(context.Background(), "f4-failure")
	bc.Events = make(chan StreamEvent, 64)

	mock := newMockRegistrar("", fmt.Errorf("pontes: 503 service unavailable"))
	bc.RegisterSettlementProvider(SettlementEURC, mock)

	tradeID := sealEURTrade(t, bc, 50.0, 2.0)

	// Wait for the goroutine to call RegisterSettlement.
	select {
	case <-mock.registeredCh:
	case <-time.After(2 * time.Second):
		t.Fatal("RegisterSettlement was not called within 2 seconds")
	}

	// Allow the goroutine to emit the event.
	time.Sleep(20 * time.Millisecond)

	// Drain events looking for EventPaymentRegistrationFailed.
	var found bool
draining:
	for {
		select {
		case evt := <-bc.Events:
			if evt.Type == EventPaymentRegistrationFailed {
				found = true
				break draining
			}
		default:
			break draining
		}
	}
	assert.True(t, found, "EventPaymentRegistrationFailed must be emitted on registration error")

	// Instruction must still be pending so the operator can retry.
	bc.Mu.Lock()
	_, pending := bc.PendingInstructions[tradeID]
	bc.Mu.Unlock()
	assert.True(t, pending, "instruction must remain in PendingInstructions after failed registration")
}

// TestSettlementRegistrar_NonCeBMProvider_NotCalled asserts that providers
// that do not implement SettlementRegistrar (e.g. the default MockPaymentProvider)
// do not trigger a registration call — existing GBP/EURC flows are unaffected.
func TestSettlementRegistrar_NonCeBMProvider_NotCalled(t *testing.T) {
	// Default MockPaymentProvider does not implement SettlementRegistrar.
	bc := NewBlockchain(context.Background(), "f4-no-register")
	// No explicit SettlementCeBM registration — falls back to MockPaymentProvider.

	seedAsset(bc, "gbp-bond", "GBP")
	buyerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	sellerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	sellerPub := base64.StdEncoding.EncodeToString(sellerKey.Public().Bytes())
	seedHolding(bc, sellerPub, "gbp-bond", 10)

	buyTx := placeOrderTx(t, buyerKey, "gbp-bond", OrderSideBid, 10.0, 10)
	sellTx := placeOrderTx(t, sellerKey, "gbp-bond", OrderSideAsk, 10.0, 10)

	// Should complete without panic or hang — no goroutine is launched.
	bc.SealBlock(nil, []OrderTransaction{buyTx, sellTx}, nil)
	assert.Len(t, bc.Trades, 1, "trade must still be recorded")
}
