package gonetwork

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPaymentStore_SetAndGetPending(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPaymentStore()

	err := store.SetPending(ctx, "ref-001", "txn-abc", 1500.00, "EUR")
	require.NoError(t, err)

	txnID, found, err := store.GetPending(ctx, "ref-001")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "txn-abc", txnID)
}

func TestPaymentStore_GetPending_NotFound(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPaymentStore()

	_, found, err := store.GetPending(ctx, "does-not-exist")
	require.NoError(t, err)
	require.False(t, found)
}

func TestPaymentStore_StatusSurvivesAcrossReads(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPaymentStore()

	require.NoError(t, store.SetStatus(ctx, "ref-001", PaymentStatusConfirmed))

	status, found, err := store.GetStatus(ctx, "ref-001")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, PaymentStatusConfirmed, status)
}

func TestPaymentStore_PendingOlderThan(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPaymentStore()

	require.NoError(t, store.SetPending(ctx, "ref-old", "txn-1", 100, "EUR"))
	time.Sleep(10 * time.Millisecond)
	cutoff := time.Now()
	require.NoError(t, store.SetPending(ctx, "ref-new", "txn-2", 200, "EUR"))

	results, err := store.PendingOlderThan(ctx, cutoff)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, "ref-old", results[0].Reference)
}

var _ PaymentProvider = (*PontesPaymentProvider)(nil)
var _ PaymentProvider = (*ModulrPaymentProvider)(nil)
var _ PaymentProvider = (*EURCPaymentProvider)(nil)

func TestPaymentProvider_InterfaceConformance(t *testing.T) {
	// If this test compiles, interface conformance is proven.
	// No runtime assertions needed — the value is the compile check above.
	t.Log("All PaymentProvider implementations satisfy the interface")
}
