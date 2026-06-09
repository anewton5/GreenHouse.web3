package gonetwork

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeOracle(t *testing.T) *MockOracleService {
	t.Helper()
	oracle, err := NewMockOracleService()
	require.NoError(t, err)
	return oracle
}

func makeInstruction(tradeID string) *PaymentInstruction {
	return &PaymentInstruction{
		TradeID:          tradeID,
		AssetID:          "asset-001",
		Quantity:         100,
		PricePerUnit:     10.50,
		TotalAmount:      1050.00,
		Currency:         "GBP",
		Method:           SettlementFasterPay,
		PayerWalletID:    "buyer-wallet-key",
		PayeeWalletID:    "seller-wallet-key",
		PayerVirtualIBAN: "GB01MOCK0000000000001234",
		Reference:        "GH-" + tradeID[:8],
		ExpiresAt:        time.Now().Add(24 * time.Hour).Unix(),
	}
}

func makeConfirmation(tradeID, reference string) *PaymentConfirmation {
	return &PaymentConfirmation{
		InstructionID:   tradeID,
		Reference:       reference,
		ConfirmedAmount: 1050.00,
		Currency:        "GBP",
		ConfirmedAt:     time.Now().Unix(),
	}
}

// ---------------------------------------------------------------------------
// MockPaymentProvider tests
// ---------------------------------------------------------------------------

func TestMockPaymentProvider_CreateVirtualAccount(t *testing.T) {
	p := NewMockPaymentProvider()
	iban, err := p.CreateVirtualAccount(context.Background(), "wallet-alice")
	require.NoError(t, err)
	assert.NotEmpty(t, iban)
	assert.Contains(t, iban, "GB")
	assert.Contains(t, iban, "MOCK")
}

func TestMockPaymentProvider_CreateVirtualAccount_Idempotent(t *testing.T) {
	p := NewMockPaymentProvider()
	iban1, err := p.CreateVirtualAccount(context.Background(), "wallet-alice")
	require.NoError(t, err)
	iban2, err := p.CreateVirtualAccount(context.Background(), "wallet-alice")
	require.NoError(t, err)
	// Same wallet always gets same IBAN.
	assert.Equal(t, iban1, iban2)
}

func TestMockPaymentProvider_CreateVirtualAccount_DifferentWallets(t *testing.T) {
	p := NewMockPaymentProvider()
	iban1, err := p.CreateVirtualAccount(context.Background(), "wallet-alice")
	require.NoError(t, err)
	iban2, err := p.CreateVirtualAccount(context.Background(), "wallet-bob")
	require.NoError(t, err)
	assert.NotEqual(t, iban1, iban2)
}

func TestMockPaymentProvider_CreateVirtualAccount_EmptyWallet(t *testing.T) {
	p := NewMockPaymentProvider()
	_, err := p.CreateVirtualAccount(context.Background(), "")
	require.Error(t, err)
}

func TestMockPaymentProvider_GetPaymentStatus_Unknown(t *testing.T) {
	p := NewMockPaymentProvider()
	status, err := p.GetPaymentStatus(context.Background(), "ref-unknown")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusPending, status)
}

func TestMockPaymentProvider_ConfirmPayment(t *testing.T) {
	p := NewMockPaymentProvider()
	err := p.ConfirmPayment(context.Background(), "ref-001", 1050.00, "GBP")
	require.NoError(t, err)

	status, err := p.GetPaymentStatus(context.Background(), "ref-001")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusConfirmed, status)
}

func TestMockPaymentProvider_ConfirmPayment_ZeroAmount(t *testing.T) {
	p := NewMockPaymentProvider()
	err := p.ConfirmPayment(context.Background(), "ref-001", 0, "GBP")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "amount")
}

func TestMockPaymentProvider_ConfirmPayment_EmptyReference(t *testing.T) {
	p := NewMockPaymentProvider()
	err := p.ConfirmPayment(context.Background(), "", 100, "GBP")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reference")
}

// ---------------------------------------------------------------------------
// MockOracleService — instruction signing tests
// ---------------------------------------------------------------------------

func TestMockOracleService_SignInstruction(t *testing.T) {
	oracle := makeOracle(t)
	instr := makeInstruction("trade-abc123de")

	signed, err := oracle.SignInstruction(instr)
	require.NoError(t, err)
	assert.NotEmpty(t, signed.OracleSignature)
	// Original must be unchanged.
	assert.Empty(t, instr.OracleSignature)
}

func TestMockOracleService_VerifyInstruction_Valid(t *testing.T) {
	oracle := makeOracle(t)
	instr := makeInstruction("trade-abc123de")

	signed, err := oracle.SignInstruction(instr)
	require.NoError(t, err)
	assert.True(t, oracle.VerifyInstruction(signed))
}

func TestMockOracleService_VerifyInstruction_Tampered(t *testing.T) {
	oracle := makeOracle(t)
	instr := makeInstruction("trade-abc123de")

	signed, err := oracle.SignInstruction(instr)
	require.NoError(t, err)

	// Mutate total amount after signing.
	signed.TotalAmount = 9999.99
	assert.False(t, oracle.VerifyInstruction(signed))
}

func TestMockOracleService_VerifyInstruction_NoSignature(t *testing.T) {
	oracle := makeOracle(t)
	instr := makeInstruction("trade-abc123de")
	assert.False(t, oracle.VerifyInstruction(instr))
}

func TestMockOracleService_VerifyInstruction_NilInstruction(t *testing.T) {
	oracle := makeOracle(t)
	assert.False(t, oracle.VerifyInstruction(nil))
}

func TestMockOracleService_VerifyInstruction_WrongOracle(t *testing.T) {
	oracle1 := makeOracle(t)
	oracle2 := makeOracle(t)
	instr := makeInstruction("trade-abc123de")

	signed, err := oracle1.SignInstruction(instr)
	require.NoError(t, err)
	// Signed by oracle1, verified by oracle2 — must fail.
	assert.False(t, oracle2.VerifyInstruction(signed))
}

// ---------------------------------------------------------------------------
// MockOracleService — confirmation signing tests
// ---------------------------------------------------------------------------

func TestMockOracleService_SignConfirmation(t *testing.T) {
	oracle := makeOracle(t)
	conf := makeConfirmation("trade-abc123de", "GH-trade-ab")

	signed, err := oracle.SignConfirmation(conf)
	require.NoError(t, err)
	assert.NotEmpty(t, signed.OracleSignature)
	assert.Empty(t, conf.OracleSignature)
}

func TestMockOracleService_VerifyConfirmation_Valid(t *testing.T) {
	oracle := makeOracle(t)
	conf := makeConfirmation("trade-abc123de", "GH-trade-ab")

	signed, err := oracle.SignConfirmation(conf)
	require.NoError(t, err)
	assert.True(t, oracle.VerifyConfirmation(signed))
}

func TestMockOracleService_VerifyConfirmation_Tampered(t *testing.T) {
	oracle := makeOracle(t)
	conf := makeConfirmation("trade-abc123de", "GH-trade-ab")

	signed, err := oracle.SignConfirmation(conf)
	require.NoError(t, err)

	signed.ConfirmedAmount = 0.01
	assert.False(t, oracle.VerifyConfirmation(signed))
}

func TestMockOracleService_VerifyConfirmation_NilConfirmation(t *testing.T) {
	oracle := makeOracle(t)
	assert.False(t, oracle.VerifyConfirmation(nil))
}

func TestMockOracleService_OraclePublicKey(t *testing.T) {
	oracle := makeOracle(t)
	pub := oracle.OraclePublicKey()
	require.NotNil(t, pub)

	// Signing and verifying with the returned key must round-trip correctly.
	instr := makeInstruction("trade-abc123de")
	signed, err := oracle.SignInstruction(instr)
	require.NoError(t, err)
	assert.True(t, oracle.VerifyInstruction(signed))
}

// ---------------------------------------------------------------------------
// Integration: full DVP payment flow
// ---------------------------------------------------------------------------

func TestPaymentFlow_InstructionToConfirmation(t *testing.T) {
	provider := NewMockPaymentProvider()
	oracle := makeOracle(t)

	// Onboard buyer — create virtual account.
	buyerID := "buyer-wallet-key"
	iban, err := provider.CreateVirtualAccount(context.Background(), buyerID)
	require.NoError(t, err)
	assert.NotEmpty(t, iban)

	tradeID := "trade-abc123de-f012"

	// Oracle issues a payment instruction.
	instr := &PaymentInstruction{
		TradeID:          tradeID,
		AssetID:          "asset-001",
		Quantity:         50,
		PricePerUnit:     20.00,
		TotalAmount:      1000.00,
		Currency:         "GBP",
		Method:           SettlementFasterPay,
		PayerWalletID:    buyerID,
		PayeeWalletID:    "seller-wallet-key",
		PayerVirtualIBAN: iban,
		Reference:        "GH-trade-ab",
		ExpiresAt:        time.Now().Add(24 * time.Hour).Unix(),
	}
	signed, err := oracle.SignInstruction(instr)
	require.NoError(t, err)
	assert.True(t, oracle.VerifyInstruction(signed))

	// Simulate buyer payment.
	err = provider.ConfirmPayment(context.Background(), signed.Reference, signed.TotalAmount, signed.Currency)
	require.NoError(t, err)

	status, err := provider.GetPaymentStatus(context.Background(), signed.Reference)
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusConfirmed, status)

	// Oracle issues confirmation.
	conf := &PaymentConfirmation{
		InstructionID:   tradeID,
		Reference:       signed.Reference,
		ConfirmedAmount: signed.TotalAmount,
		Currency:        signed.Currency,
		ConfirmedAt:     time.Now().Unix(),
	}
	signedConf, err := oracle.SignConfirmation(conf)
	require.NoError(t, err)
	assert.True(t, oracle.VerifyConfirmation(signedConf))
}
