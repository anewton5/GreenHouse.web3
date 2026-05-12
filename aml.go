package gonetwork

import (
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// AML interface + types
// ---------------------------------------------------------------------------

// AMLAlertSeverity classifies the urgency of an AML screening match.
type AMLAlertSeverity string

const (
	// AMLSeverityFlag means log the alert and notify compliance, but let the
	// transaction proceed (used for PEP matches that are not sanctioned).
	AMLSeverityFlag AMLAlertSeverity = "flag"

	// AMLSeverityBlock means reject the transaction and record the refusal.
	// Used for OFAC SDN, EU/UN sanctions list matches.
	AMLSeverityBlock AMLAlertSeverity = "block"
)

// AMLAlert is returned by AMLScreener when a match is found.
type AMLAlert struct {
	// Severity determines whether the transaction is blocked or flagged.
	Severity AMLAlertSeverity `json:"severity"`
	// Reason is a human-readable description of the match.
	Reason string `json:"reason"`
	// MatchedList is the name of the watchlist that triggered the alert
	// (e.g. "OFAC SDN", "EU Consolidated Sanctions", "PEP").
	MatchedList string `json:"matched_list"`
	// ScreenedAt is the Unix timestamp of the screening call.
	ScreenedAt int64 `json:"screened_at"`
}

// AMLScreener checks a proposed asset transaction against AML watchlists and
// behavioural risk models before allowing it into the validation pipeline.
//
// Implementations:
//   - MockAMLScreener  — passes all transactions except explicitly blocked addresses
//   - (future) ComplyAdvantageScreener — calls ComplyAdvantage API in real time
//   - (future) EllipticScreener        — uses Elliptic on-chain analytics
type AMLScreener interface {
	// ScreenTransaction returns nil if the transaction is clean, or an AMLAlert
	// describing the match. A block-severity alert causes Validate to return an error.
	ScreenTransaction(
		senderKey string,
		receiverKey string,
		assetID string,
		amount float64,
		currency string,
	) (*AMLAlert, error)
}

// ---------------------------------------------------------------------------
// MockAMLScreener
// ---------------------------------------------------------------------------

// MockAMLScreener passes all transactions except those explicitly blocked via
// BlockedAddresses. It uses a real Ed25519 key for registry operations and
// records every screening call for assertion in tests.
//
// In production this is replaced with a live provider (ComplyAdvantage,
// Elliptic, or Chainalysis) without any change to the call sites.
type MockAMLScreener struct {
	mu sync.RWMutex

	// BlockedAddresses maps wallet public key strings to the list that triggered
	// the block (e.g. "OFAC SDN"). Addresses in this map return a block-severity alert.
	BlockedAddresses map[string]string

	// FlaggedAddresses maps wallet public key strings to the list that flags them
	// (e.g. "PEP"). Transactions proceed but a flag-severity alert is returned.
	FlaggedAddresses map[string]string

	// Calls records every ScreenTransaction invocation for test assertions.
	Calls []AMLCall
}

// AMLCall records the arguments of a single ScreenTransaction invocation.
type AMLCall struct {
	SenderKey   string
	ReceiverKey string
	AssetID     string
	Amount      float64
	Currency    string
	CalledAt    int64
}

// NewMockAMLScreener returns an open screener with empty block/flag lists.
func NewMockAMLScreener() *MockAMLScreener {
	return &MockAMLScreener{
		BlockedAddresses: make(map[string]string),
		FlaggedAddresses: make(map[string]string),
	}
}

// BlockAddress adds a wallet key to the block list under a named watchlist.
func (m *MockAMLScreener) BlockAddress(walletKey, watchlist string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BlockedAddresses[walletKey] = watchlist
}

// FlagAddress adds a wallet key to the flag list under a named watchlist.
func (m *MockAMLScreener) FlagAddress(walletKey, watchlist string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FlaggedAddresses[walletKey] = watchlist
}

// ScreenTransaction implements AMLScreener. It checks both sender and receiver
// against the block and flag lists. A block on either party blocks the transaction.
func (m *MockAMLScreener) ScreenTransaction(
	senderKey string,
	receiverKey string,
	assetID string,
	amount float64,
	currency string,
) (*AMLAlert, error) {
	m.mu.Lock()
	m.Calls = append(m.Calls, AMLCall{
		SenderKey:   senderKey,
		ReceiverKey: receiverKey,
		AssetID:     assetID,
		Amount:      amount,
		Currency:    currency,
		CalledAt:    time.Now().Unix(),
	})
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check sender block list.
	if list, blocked := m.BlockedAddresses[senderKey]; blocked {
		return &AMLAlert{
			Severity:    AMLSeverityBlock,
			Reason:      fmt.Sprintf("sender matched sanctions list: %s", list),
			MatchedList: list,
			ScreenedAt:  time.Now().Unix(),
		}, nil
	}

	// Check receiver block list.
	if list, blocked := m.BlockedAddresses[receiverKey]; blocked {
		return &AMLAlert{
			Severity:    AMLSeverityBlock,
			Reason:      fmt.Sprintf("receiver matched sanctions list: %s", list),
			MatchedList: list,
			ScreenedAt:  time.Now().Unix(),
		}, nil
	}

	// Check sender flag list.
	if list, flagged := m.FlaggedAddresses[senderKey]; flagged {
		return &AMLAlert{
			Severity:    AMLSeverityFlag,
			Reason:      fmt.Sprintf("sender flagged as PEP or monitored entity: %s", list),
			MatchedList: list,
			ScreenedAt:  time.Now().Unix(),
		}, nil
	}

	// Check receiver flag list.
	if list, flagged := m.FlaggedAddresses[receiverKey]; flagged {
		return &AMLAlert{
			Severity:    AMLSeverityFlag,
			Reason:      fmt.Sprintf("receiver flagged as PEP or monitored entity: %s", list),
			MatchedList: list,
			ScreenedAt:  time.Now().Unix(),
		}, nil
	}

	return nil, nil
}

// ---------------------------------------------------------------------------
// ProspectusWarning
// ---------------------------------------------------------------------------

// ProspectusWarningThreshold is the fraction of the retail investor cap at which
// a warning event is emitted. At 90% of the limit the issuer portal surfaces a
// prominent alert so the issuer can decide whether to restrict further issuances
// before the hard cap is breached.
const ProspectusWarningThreshold = 0.90

// ProspectusWarning is emitted as a blockchain event (EventProspectusWarning) when
// a jurisdiction's retail holder count crosses the warning threshold for an asset.
// It is attached to blocks as a CredentialTransaction-style record and surfaced by
// the API in the compliance events feed.
type ProspectusWarning struct {
	AssetID           string  `json:"asset_id"`
	Jurisdiction      string  `json:"jurisdiction"`
	CurrentCount      int     `json:"current_count"`
	Limit             int     `json:"limit"`
	ThresholdFraction float64 `json:"threshold_fraction"`
	WarnedAt          int64   `json:"warned_at"`
}

// EventProspectusWarning is the stream event type for prospectus threshold alerts.
const EventProspectusWarning = "prospectus_warning"

// CheckProspectusThresholds inspects every asset's ProspectusExemption after
// UpdateRetailCounts has run and emits an EventProspectusWarning onto bc.Events
// for any jurisdiction that has crossed the warning threshold since last check.
//
// It is called from finalizeBlock immediately after UpdateRetailCounts.
func CheckProspectusThresholds(
	bc *Blockchain,
	exemptions map[string]*ProspectusExemption,
) {
	for _, pe := range exemptions {
		if pe.MaxRetailPerJurisdiction <= 0 {
			continue
		}
		for jurisdiction, count := range pe.RetailHoldersByJurisdiction {
			limit := pe.MaxRetailPerJurisdiction
			if count == 0 {
				continue
			}
			fraction := float64(count) / float64(limit)
			if fraction >= ProspectusWarningThreshold {
				bc.EmitEvent(EventProspectusWarning, ProspectusWarning{
					AssetID:           pe.AssetID,
					Jurisdiction:      jurisdiction,
					CurrentCount:      count,
					Limit:             limit,
					ThresholdFraction: fraction,
					WarnedAt:          time.Now().Unix(),
				})
			}
		}
	}
}
