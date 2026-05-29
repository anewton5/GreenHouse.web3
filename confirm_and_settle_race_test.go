package gonetwork

// ---------------------------------------------------------------------------
// confirm_and_settle_race_test.go — Item 3 concurrency and idempotency tests
//
// Acceptance criteria from PRODUCTION_READINESS_PLAN.md Item 3:
//   - Two goroutines calling ConfirmAndSettle with the same reference
//     concurrently: only one applies the DVP transfer; the second returns nil
//     (idempotent).
//   - go test -race -count=3 ./... produces no data-race report on
//     ConfirmAndSettle or bc.PendingSettlements.
//   - Existing ConfirmAndSettle tests in blockchain_extended_test.go continue
//     to pass.
// ---------------------------------------------------------------------------

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfirmAndSettle_ConcurrentSameReference verifies that two goroutines
// racing on an identical reference produce exactly one confirmation — the
// idempotency check inside bc.Mu makes the second call a no-op.
func TestConfirmAndSettle_ConcurrentSameReference(t *testing.T) {
	bc := newTestBlockchain(t)
	mock := NewMockPaymentProvider()
	bc.PaymentProvider = mock

	instr := &PaymentInstruction{
		Reference:   "REF-RACE-001",
		Method:      SettlementSEPA,
		TotalAmount: 10000,
		Currency:    "EUR",
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}
	bc.PendingInstructions["trade-race-001"] = instr

	var wg sync.WaitGroup
	errs := make([]error, 2)

	for i := 0; i < 2; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = bc.ConfirmAndSettle("REF-RACE-001", 10000, "EUR")
		}()
	}
	wg.Wait()

	assert.NoError(t, errs[0], "first racer must not error")
	assert.NoError(t, errs[1], "second racer must not error (idempotent)")
	assert.Len(t, bc.ConfirmedPayments, 1, "exactly one confirmation must be recorded")
}

// TestConfirmAndSettle_ConcurrentManyGoroutines stress-tests the mutex under
// high concurrency: 50 goroutines all fire the same reference simultaneously.
// Only one confirmation must be recorded and the race detector must be silent.
func TestConfirmAndSettle_ConcurrentManyGoroutines(t *testing.T) {
	const numGoroutines = 50

	bc := newTestBlockchain(t)
	mock := NewMockPaymentProvider()
	bc.PaymentProvider = mock

	instr := &PaymentInstruction{
		Reference:   "REF-STRESS-001",
		Method:      SettlementSEPA,
		TotalAmount: 5000,
		Currency:    "EUR",
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}
	bc.PendingInstructions["trade-stress-001"] = instr

	var wg sync.WaitGroup
	errs := make([]error, numGoroutines)

	start := make(chan struct{}) // synchronise all goroutines to start together
	for i := 0; i < numGoroutines; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = bc.ConfirmAndSettle("REF-STRESS-001", 5000, "EUR")
		}()
	}
	close(start) // release all goroutines simultaneously
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d must not error", i)
	}
	assert.Len(t, bc.ConfirmedPayments, 1, "exactly one confirmation must be recorded regardless of concurrency")
}

// TestConfirmAndSettle_ConcurrentDifferentReferences verifies that concurrent
// calls for distinct references both succeed and each records its own
// confirmation independently.
func TestConfirmAndSettle_ConcurrentDifferentReferences(t *testing.T) {
	bc := newTestBlockchain(t)
	mock := NewMockPaymentProvider()
	bc.PaymentProvider = mock

	for i, ref := range []string{"REF-A", "REF-B"} {
		id := string(rune('A'+i)) + "-trade"
		bc.PendingInstructions[id] = &PaymentInstruction{
			Reference:   ref,
			Method:      SettlementSEPA,
			TotalAmount: 1000,
			Currency:    "EUR",
			ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
		}
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	refs := []string{"REF-A", "REF-B"}
	for i := 0; i < 2; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = bc.ConfirmAndSettle(refs[i], 1000, "EUR")
		}()
	}
	wg.Wait()

	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	assert.Len(t, bc.ConfirmedPayments, 2, "both distinct references must be confirmed")
}

// TestConfirmAndSettle_DVP_AppliedExactlyOnce_Concurrent verifies that when a
// pending settlement (DVP asset transfer) is present, concurrent webhooks only
// apply the asset transfer once.
func TestConfirmAndSettle_DVP_AppliedExactlyOnce_Concurrent(t *testing.T) {
	bc := newTestBlockchain(t)
	mock := NewMockPaymentProvider()
	bc.PaymentProvider = mock

	const assetID = "asset-dvp-race"
	const buyer = "buyer-dvp"
	const seller = "seller-dvp"

	// Seed minimal asset and holdings using the correct key format.
	bc.Assets[assetID] = &Asset{ID: assetID, TotalSupply: 100, Currency: "EUR"}
	bc.Holdings[HoldingKey(seller, assetID)] = &AssetHolding{
		AssetID:  assetID,
		HolderID: seller,
		Balance:  10,
	}

	instr := &PaymentInstruction{
		Reference:   "REF-DVP-RACE",
		Method:      SettlementSEPA,
		TotalAmount: 500,
		Currency:    "EUR",
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}
	bc.PendingInstructions["dvp-trade"] = instr
	bc.PendingSettlements["dvp-trade"] = &AssetTransaction{
		AssetID: assetID,
		TxType:  AssetTxTypeTransfer,
		Tx: Transaction{
			Sender:   seller,
			Receiver: buyer,
			Amount:   5,
		},
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = bc.ConfirmAndSettle("REF-DVP-RACE", 500, "EUR")
		}()
	}
	close(start)
	wg.Wait()

	// Exactly one transfer must have occurred.
	sellerHolding := bc.Holdings[HoldingKey(seller, assetID)]
	buyerHolding := bc.Holdings[HoldingKey(buyer, assetID)]
	if sellerHolding != nil {
		assert.Equal(t, 5.0, sellerHolding.Balance, "seller must have exactly 5 units remaining")
	} else {
		assert.Fail(t, "seller holding must exist after partial transfer")
	}
	require.NotNil(t, buyerHolding, "buyer holding must exist after DVP transfer")
	assert.Equal(t, 5.0, buyerHolding.Balance, "buyer must have exactly 5 units")
	assert.Empty(t, bc.PendingSettlements, "pending settlement must be cleared exactly once")
}
