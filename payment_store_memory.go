package gonetwork

import (
	"context"
	"sync"
	"time"
)

// MemoryPaymentStore is a thread-safe in-memory PaymentStore used in tests.
// Do not use in production.
type MemoryPaymentStore struct {
	mu       sync.Mutex
	pending  map[string]pendingRecord // reference → record
	statuses map[string]PaymentStatus
	wallets  map[string]string // walletID → address
}

type pendingRecord struct {
	transactionID    string
	expectedAmount   float64
	expectedCurrency string
	registeredAt     time.Time
}

func NewMemoryPaymentStore() *MemoryPaymentStore {
	return &MemoryPaymentStore{
		pending:  make(map[string]pendingRecord),
		statuses: make(map[string]PaymentStatus),
		wallets:  make(map[string]string),
	}
}

func (s *MemoryPaymentStore) SetPending(_ context.Context, reference, transactionID string, amount float64, currency string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[reference] = pendingRecord{
		transactionID:    transactionID,
		expectedAmount:   amount,
		expectedCurrency: currency,
		registeredAt:     time.Now(),
	}
	return nil
}

func (s *MemoryPaymentStore) GetPending(_ context.Context, reference string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.pending[reference]
	if !ok {
		return "", false, nil
	}
	return r.transactionID, true, nil
}

func (s *MemoryPaymentStore) SetStatus(_ context.Context, reference string, status PaymentStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses[reference] = status
	return nil
}

func (s *MemoryPaymentStore) GetStatus(_ context.Context, reference string) (PaymentStatus, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.statuses[reference]
	if !ok {
		return PaymentStatusUnknown, false, nil
	}

	return st, true, nil
}

func (s *MemoryPaymentStore) GetExpected(_ context.Context, reference string) (float64, string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.pending[reference]
	if !ok {
		return 0, "", false, nil
	}
	return r.expectedAmount, r.expectedCurrency, true, nil
}

func (s *MemoryPaymentStore) SetWalletAddress(_ context.Context, walletID, address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wallets[walletID] = address
	return nil
}

func (s *MemoryPaymentStore) GetWalletAddress(_ context.Context, walletID string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	addr, ok := s.wallets[walletID]
	return addr, ok, nil
}

func (s *MemoryPaymentStore) PendingOlderThan(_ context.Context, cutoff time.Time) ([]PendingSettlement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var results []PendingSettlement
	for ref, r := range s.pending {
		if r.registeredAt.Before(cutoff) {
			if _, terminated := s.statuses[ref]; !terminated {
				results = append(results, PendingSettlement{
					Reference:     ref,
					TransactionID: r.transactionID,
					RegisteredAt:  r.registeredAt,
				})
			}
		}
	}
	return results, nil
}
