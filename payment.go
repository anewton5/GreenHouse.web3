package gonetwork

import "context"

// ---------------------------------------------------------------------------
// Payment status and settlement types
// ---------------------------------------------------------------------------

// PaymentStatus tracks the lifecycle of a fiat payment leg in a DVP trade.
type PaymentStatus string

const (
	// PaymentStatusUnknown indicates the provider call failed and no reliable
	// business status could be determined from the response.
	PaymentStatusUnknown   PaymentStatus = "unknown"
	PaymentStatusPending   PaymentStatus = "pending"
	PaymentStatusConfirmed PaymentStatus = "confirmed"
	PaymentStatusFailed    PaymentStatus = "failed"
	PaymentStatusExpired   PaymentStatus = "expired"
)

// SettlementMethod identifies the payment rail used for the fiat leg of a trade.
type SettlementMethod string

const (
	SettlementSEPA      SettlementMethod = "sepa_instant"
	SettlementFasterPay SettlementMethod = "faster_payments"
	SettlementSWIFT     SettlementMethod = "swift_gpi"
	SettlementEURC      SettlementMethod = "eurc_on_chain"
	// SettlementCeBM uses the Eurosystem Pontes bridge to settle trades in
	// tokenised Central Bank Money (CeBM) via T2 (wholesale RTGS). This is the
	// primary EUR rail once the Pontes pilot launches (Q3 2026). Register a
	// PontesPaymentProvider for this method via Blockchain.RegisterSettlementProvider.
	SettlementCeBM SettlementMethod = "pontes_cbm"
)

// ---------------------------------------------------------------------------
// Payment instruction and confirmation
// ---------------------------------------------------------------------------

// PaymentInstruction is created on-chain when an order is matched.
// It instructs the buyer to transfer a specific fiat amount.
// The oracle signs it to prevent forgery; any mutation is detectable.
type PaymentInstruction struct {
	TradeID          string // matches Trade.ID
	AssetID          string
	Quantity         float64
	PricePerUnit     float64
	TotalAmount      float64 // Quantity * PricePerUnit
	Currency         string  // "GBP", "EUR", "USD", "CHF"
	Method           SettlementMethod
	PayerWalletID    string // buyer's base64-encoded public key
	PayeeWalletID    string // seller's base64-encoded public key
	PayerVirtualIBAN string // virtual IBAN assigned to buyer by payment provider
	Reference        string // unique reference for payment matching
	ExpiresAt        int64  // Unix timestamp — trade reverts if unpaid
	OracleSignature  []byte // Ed25519 sig from OracleService

	// TravelRule carries the FATF Recommendation 16 / EU Transfer-of-Funds Regulation
	// (TFR, Regulation 2023/1113) originator and beneficiary information.
	// Populated automatically in finalizeBlock when TotalAmount >= TravelRuleThresholdEUR.
	// Transmitted to the receiving payment provider alongside the instruction.
	TravelRule *TravelRulePayload `json:"travel_rule,omitempty"`

	// CeBM / Pontes fields — populated when Method == SettlementCeBM.
	// PontesTransactionID is the identifier returned by the Pontes bridge when
	// the DLT delivery leg is registered via PontesPaymentProvider.RegisterSettlement.
	PontesTransactionID string `json:"pontes_transaction_id,omitempty"`
	// SettlementNetwork identifies the DLT network on which the asset delivery leg
	// is settled. Set to "eurosystem-pontes" for CeBM and "ethereum" for EURC.
	SettlementNetwork string `json:"settlement_network,omitempty"`
}

// PaymentConfirmation is broadcast on-chain when fiat payment is confirmed.
// In production this is triggered by a payment provider webhook received by
// the oracle service. In simulation it is emitted immediately by MockPaymentProvider.
type PaymentConfirmation struct {
	InstructionID   string // matches PaymentInstruction.TradeID
	Reference       string
	ConfirmedAmount float64
	Currency        string
	ConfirmedAt     int64  // Unix timestamp
	OracleSignature []byte // Ed25519 sig from OracleService
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

// PaymentProvider abstracts the fiat payment rail.
// The mock implements this for simulation; a live implementation is a single
// new file when Modulr (or equivalent) onboarding is complete.
type PaymentProvider interface {
	// CreateVirtualAccount returns a virtual IBAN for a participant wallet.
	// Called once per wallet during participant onboarding.
	CreateVirtualAccount(ctx context.Context, walletID string) (iban string, err error)

	// GetPaymentStatus returns the current status of a payment by reference.
	GetPaymentStatus(ctx context.Context, reference string) (PaymentStatus, error)

	// ConfirmPayment records that a payment has been received.
	// In production this is triggered by a webhook; the interface allows
	// the mock to call it directly in tests.
	ConfirmPayment(ctx context.Context, reference string, amount float64, currency string) error
}

// SettlementRegistrar is an optional extension of PaymentProvider for rails
// that require an explicit registration step before a webhook callback can
// arrive. PontesPaymentProvider implements this interface; Modulr and EURC do
// not (their callbacks are triggered by the payer, not by a registration call).
//
// Providers that implement SettlementRegistrar are detected automatically by
// applyBlockState via a type assertion, and RegisterSettlement is called
// asynchronously for each matching PaymentInstruction (F-4).
type SettlementRegistrar interface {
	// RegisterSettlement submits the DLT delivery leg to the provider and
	// returns the provider-assigned transactionID. Must be idempotent — the
	// same instruction may be submitted more than once (retry path).
	RegisterSettlement(instruction *PaymentInstruction) (transactionID string, err error)
}

// OracleService signs and verifies PaymentInstructions and PaymentConfirmations.
// In Phase 1 this is operated by GreenHouse using its registry Ed25519 key.
// In Phase 2 it becomes a multi-sig threshold scheme.
type OracleService interface {
	// SignInstruction signs a PaymentInstruction and returns it with OracleSignature set.
	SignInstruction(instruction *PaymentInstruction) (*PaymentInstruction, error)

	// SignConfirmation signs a PaymentConfirmation and returns it with OracleSignature set.
	SignConfirmation(confirmation *PaymentConfirmation) (*PaymentConfirmation, error)

	// VerifyInstruction checks the oracle signature on a PaymentInstruction.
	VerifyInstruction(instruction *PaymentInstruction) bool

	// VerifyConfirmation checks the oracle signature on a PaymentConfirmation.
	VerifyConfirmation(confirmation *PaymentConfirmation) bool

	// OraclePublicKey returns the oracle's public key for external verification.
	OraclePublicKey() *PublicKey
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// TravelRuleThresholdEUR is the minimum total transfer value (EUR-equivalent) at
// which a TravelRulePayload must be attached to a PaymentInstruction.
// Source: FATF Recommendation 16; EU TFR (Regulation 2023/1113), in force 30 Dec 2024.
const TravelRuleThresholdEUR = 1_000.0

// DefaultSettlementMethod returns the preferred payment rail for the given
// trade currency. The returned method is used as the default when creating a
// PaymentInstruction unless overridden by the caller.
//
//   - GBP  → SettlementFasterPay (Faster Payments via Modulr)
//   - EUR  → SettlementEURC      (Circle EURC stablecoin; upgrade to SettlementCeBM
//     once a PontesPaymentProvider is registered via Blockchain.RegisterSettlementProvider)
//   - USD, CHF → SettlementSWIFT (SWIFT GPI)
//   - default   → SettlementSEPA
func DefaultSettlementMethod(currency string) SettlementMethod {
	switch currency {
	case "GBP":
		return SettlementFasterPay
	case "EUR":
		return SettlementEURC
	case "USD", "CHF":
		return SettlementSWIFT
	default:
		return SettlementSEPA
	}
}

// ---------------------------------------------------------------------------
