package gonetwork

// ---------------------------------------------------------------------------
// Payment status and settlement types
// ---------------------------------------------------------------------------

// PaymentStatus tracks the lifecycle of a fiat payment leg in a DVP trade.
type PaymentStatus string

const (
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
)

// ---------------------------------------------------------------------------
// Payment instruction and confirmation
// ---------------------------------------------------------------------------

// PaymentInstruction is created on-chain when an order is matched.
// It instructs the buyer to transfer a specific fiat amount.
// The oracle signs it to prevent forgery; any mutation is detectable.
type PaymentInstruction struct {
	TradeID          string           // matches Trade.ID
	AssetID          string
	Quantity         float64
	PricePerUnit     float64
	TotalAmount      float64          // Quantity * PricePerUnit
	Currency         string           // "GBP", "EUR", "USD", "CHF"
	Method           SettlementMethod
	PayerWalletID    string           // buyer's base64-encoded public key
	PayeeWalletID    string           // seller's base64-encoded public key
	PayerVirtualIBAN string           // virtual IBAN assigned to buyer by payment provider
	Reference        string           // unique reference for payment matching
	ExpiresAt        int64            // Unix timestamp — trade reverts if unpaid
	OracleSignature  []byte           // Ed25519 sig from OracleService
}

// PaymentConfirmation is broadcast on-chain when fiat payment is confirmed.
// In production this is triggered by a payment provider webhook received by
// the oracle service. In simulation it is emitted immediately by MockPaymentProvider.
type PaymentConfirmation struct {
	InstructionID   string  // matches PaymentInstruction.TradeID
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
	CreateVirtualAccount(walletID string) (iban string, err error)

	// GetPaymentStatus returns the current status of a payment by reference.
	GetPaymentStatus(reference string) (PaymentStatus, error)

	// ConfirmPayment records that a payment has been received.
	// In production this is triggered by a webhook; the interface allows
	// the mock to call it directly in tests.
	ConfirmPayment(reference string, amount float64, currency string) error
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
// P2P message type constants (used in p2p.go Week 5)
// ---------------------------------------------------------------------------

const MessageTypePaymentInstruction = "payment_instruction"
const MessageTypePaymentConfirmation = "payment_confirmation"
