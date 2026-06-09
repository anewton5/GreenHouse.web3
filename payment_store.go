package gonetwork

import (
	"context"
	"time"
)

// PaymentStore is the durable backing store for all payment provider state.
// All writes must be synchronous and acknowledged before the provider
// returns success to the caller. Implementations must be safe for concurrent use.
type PaymentStore interface {
	// SetPending records that a settlement registration has been accepted by the
	// provider. reference is the platform trade reference; transactionID is the
	// provider-assigned ID. The expectedAmount and expectedCurrency are stored
	// for validation when ConfirmPayment is later called.
	SetPending(ctx context.Context, reference, transactionID string, expectedAmount float64, expectedCurrency string) error

	// GetPending retrieves the provider transactionID for a reference.
	// Returns ("", false, nil) when the reference is not registered.
	GetPending(ctx context.Context, reference string) (transactionID string, found bool, err error)

	// SetStatus persists a terminal or intermediate payment status.
	SetStatus(ctx context.Context, reference string, status PaymentStatus) error

	// GetStatus retrieves the last persisted status.
	// Returns (PaymentStatusUnknown, false, nil) when no record exists.
	GetStatus(ctx context.Context, reference string) (status PaymentStatus, found bool, err error)

	// GetExpected retrieves the expected amount and currency for a reference.
	// Returns (0, "", false, nil) when the reference is not registered.
	GetExpected(ctx context.Context, reference string) (amount float64, currency string, found bool, err error)

	// SetWalletAddress persists a provider-assigned on-chain address for a walletID.
	SetWalletAddress(ctx context.Context, walletID, address string) error

	// GetWalletAddress retrieves a previously stored on-chain address.
	// Returns ("", false, nil) when not found.
	GetWalletAddress(ctx context.Context, walletID string) (address string, found bool, err error)

	// PendingOlderThan returns all (reference, transactionID) pairs whose status
	// is not terminal and whose registration time is before the cutoff.
	// Used by the reconciliation loop (M-7).
	PendingOlderThan(ctx context.Context, cutoff time.Time) ([]PendingSettlement, error)
}

// PendingSettlement is a record returned by PaymentStore.PendingOlderThan.
type PendingSettlement struct {
	Reference     string
	TransactionID string
	RegisteredAt  time.Time
}
