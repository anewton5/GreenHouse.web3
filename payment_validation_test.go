package gonetwork

// ---------------------------------------------------------------------------
// payment_validation_test.go — F-3 amount/currency validation tests
//
// Verifies that confirmAndSettleLocked rejects callbacks whose amount or
// currency does not match the on-chain instruction, emits
// EventPaymentConfirmationRejected, leaves all state unmodified, and wraps
// ErrPaymentMismatch so callers can map the error to HTTP 422.
// ---------------------------------------------------------------------------

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pendingInstruction is a helper that creates a minimal PaymentInstruction and
// registers it in bc.PendingInstructions under tradeID.
func pendingInstruction(bc *Blockchain, tradeID, reference, currency string, amount float64) {
	bc.PendingInstructions[tradeID] = &PaymentInstruction{
		Reference:   reference,
		TotalAmount: amount,
		Currency:    currency,
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}
}

// TestConfirmAndSettle_WrongCurrency_Rejected asserts that a callback with the
// correct amount but wrong currency is rejected with ErrPaymentMismatch, no
// confirmation is stored, and the pending instruction is not consumed (F-3).
func TestConfirmAndSettle_WrongCurrency_Rejected(t *testing.T) {
	bc := newTestBlockchain(t)
	pendingInstruction(bc, "trade-f3-001", "ref-f3-001", "GBP", 1000)
	bc.PendingSettlements["trade-f3-001"] = &AssetTransaction{AssetID: "bond-1"}

	err := bc.ConfirmAndSettle("ref-f3-001", 1000, "EUR") // right amount, wrong currency
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPaymentMismatch), "must wrap ErrPaymentMismatch")
	assert.Contains(t, err.Error(), "currency mismatch")

	// No state mutation on rejection.
	assert.Empty(t, bc.ConfirmedPayments, "no confirmation must be recorded")
	assert.Contains(t, bc.PendingInstructions, "trade-f3-001", "instruction must remain pending")
	assert.Contains(t, bc.PendingSettlements, "trade-f3-001", "settlement must not be consumed")
}

// TestConfirmAndSettle_WrongAmount_Rejected asserts that a callback with the
// correct currency but wrong amount is rejected with ErrPaymentMismatch, no
// confirmation is stored, and the pending instruction is not consumed (F-3).
func TestConfirmAndSettle_WrongAmount_Rejected(t *testing.T) {
	bc := newTestBlockchain(t)
	pendingInstruction(bc, "trade-f3-002", "ref-f3-002", "GBP", 1000)
	bc.PendingSettlements["trade-f3-002"] = &AssetTransaction{AssetID: "bond-2"}

	err := bc.ConfirmAndSettle("ref-f3-002", 500, "GBP") // right currency, wrong amount
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPaymentMismatch), "must wrap ErrPaymentMismatch")
	assert.Contains(t, err.Error(), "amount mismatch")

	// No state mutation on rejection.
	assert.Empty(t, bc.ConfirmedPayments, "no confirmation must be recorded")
	assert.Contains(t, bc.PendingInstructions, "trade-f3-002", "instruction must remain pending")
	assert.Contains(t, bc.PendingSettlements, "trade-f3-002", "settlement must not be consumed")
}

// TestConfirmAndSettle_CorrectAmountCurrency_Settles is the baseline: a
// callback whose amount and currency both match the instruction must settle
// without error (F-3 acceptance criterion — existing behaviour preserved).
func TestConfirmAndSettle_CorrectAmountCurrency_Settles(t *testing.T) {
	bc := newTestBlockchain(t)
	pendingInstruction(bc, "trade-f3-003", "ref-f3-003", "GBP", 1000)

	err := bc.ConfirmAndSettle("ref-f3-003", 1000, "GBP")
	require.NoError(t, err)
	assert.Contains(t, bc.ConfirmedPayments, "trade-f3-003")
}

// TestConfirmAndSettle_MismatchEventEmitted verifies that
// EventPaymentConfirmationRejected is emitted on a currency mismatch and
// carries the expected_currency / received_currency fields (F-3).
func TestConfirmAndSettle_MismatchEventEmitted(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Events = make(chan StreamEvent, 8)
	pendingInstruction(bc, "trade-f3-004", "ref-f3-004", "GBP", 1000)

	_ = bc.ConfirmAndSettle("ref-f3-004", 1000, "EUR")

	require.Len(t, bc.Events, 1)
	evt := <-bc.Events
	assert.Equal(t, EventPaymentConfirmationRejected, evt.Type)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(evt.Payload, &payload))
	assert.Equal(t, "ref-f3-004", payload["reference"])
	assert.Equal(t, "GBP", payload["expected_currency"])
	assert.Equal(t, "EUR", payload["received_currency"])
}

func TestConfirmPayment_UnknownReference_Error(t *testing.T) {
	store := NewMemoryPaymentStore()

	p, _ := NewPontesPaymentProvider(
		"k",
		"https://example.com",
		"OP",
		"test-hmac-secret",
		store,
	)

	err := p.ConfirmPayment(
		context.Background(),
		"unknown-ref",
		100,
		"EUR",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown reference")
}

func TestConfirmPayment_AmountMismatch_Error(t *testing.T) {
	store := NewMemoryPaymentStore()

	require.NoError(t, store.SetPending(
		context.Background(),
		"ref-mismatch",
		"txn-123",
		1000,
		"EUR",
	))

	p, err := NewPontesPaymentProvider(
		"k",
		"https://example.com",
		"OP",
		"test-hmac-secret",
		store,
	)
	require.NoError(t, err)
	require.NotNil(t, p)

	err = p.ConfirmPayment(
		context.Background(),
		"ref-mismatch",
		400, // ❌ wrong amount
		"EUR",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "amount mismatch")
}

func TestHandleWebhook_InvalidSignature_RejectsWithoutCallingAction(t *testing.T) {
	called := false
	provider := newTestPontesProvider(t, NewMemoryPaymentStore())

	err := HandleWebhook(provider, []byte(`{"event":"settlement.confirmed"}`), "bad-sig",
		func() error {
			called = true
			return nil
		})

	require.Error(t, err)
	require.Contains(t, err.Error(), "signature verification failed")
	require.False(t, called, "action must not be called when signature is invalid")
}

func TestHandleWebhook_ValidSignature_CallsAction(t *testing.T) {
	secret := "test-hmac-secret"
	payload := []byte(`{"event":"settlement.confirmed"}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	sig := hex.EncodeToString(mac.Sum(nil))

	p, _ := NewPontesPaymentProvider("key", "http://example", "op", secret, NewMemoryPaymentStore())

	called := false
	err := HandleWebhook(p, payload, sig, func() error {
		called = true
		return nil
	})

	require.NoError(t, err)
	require.True(t, called)
}

func TestNewEURCPaymentProvider_EmptyWebhookSecret_ReturnsError(t *testing.T) {
	_, err := NewEURCPaymentProvider("key", "https://api.circle.com/v1", "ws-id", "", NewMemoryPaymentStore())
	require.Error(t, err)
	require.Contains(t, err.Error(), "webhookSecret must not be empty")
}
