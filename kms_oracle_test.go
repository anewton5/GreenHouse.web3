package gonetwork

// ---------------------------------------------------------------------------
// kms_oracle_test.go
//
// Tests KMSOracleService signing and verification without AWS KMS.
// Since tests run in the same package, we can construct the struct directly
// using unexported fields (in-process key — no AWS round-trip needed).
// ---------------------------------------------------------------------------

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestOracle constructs a KMSOracleService using a freshly generated key
// without calling AWS KMS. Safe for unit tests.
func newTestOracle(t *testing.T) *KMSOracleService {
	t.Helper()
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	return &KMSOracleService{
		oracleKey: key,
		oraclePub: key.Public(),
		keyARN:    "arn:aws:kms:eu-west-1:123456789012:key/test-key",
	}
}

// ---------------------------------------------------------------------------
// NewKMSOracleService — env-var validation (no AWS call needed)
// ---------------------------------------------------------------------------

func TestNewKMSOracleService_MissingKeyARN_Error(t *testing.T) {
	t.Setenv("AWS_KMS_KEY_ARN", "")
	t.Setenv("AWS_KMS_ORACLE_KEY_B64", "")
	ctx := t.Context()
	_, err := NewKMSOracleService(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AWS_KMS_KEY_ARN")
}

func TestNewKMSOracleService_MissingOracleKeyB64_Error(t *testing.T) {
	t.Setenv("AWS_KMS_KEY_ARN", "arn:aws:kms:eu-west-1:123:key/k1")
	t.Setenv("AWS_KMS_ORACLE_KEY_B64", "")
	ctx := t.Context()
	_, err := NewKMSOracleService(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AWS_KMS_ORACLE_KEY_B64")
}

func TestNewKMSOracleService_InvalidBase64_Error(t *testing.T) {
	t.Setenv("AWS_KMS_KEY_ARN", "arn:aws:kms:eu-west-1:123:key/k1")
	t.Setenv("AWS_KMS_ORACLE_KEY_B64", "not!!valid-base64")
	ctx := t.Context()
	_, err := NewKMSOracleService(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

// ---------------------------------------------------------------------------
// OraclePublicKey
// ---------------------------------------------------------------------------

func TestKMSOraclePublicKey_ReturnsCorrectKey(t *testing.T) {
	oracle := newTestOracle(t)
	pub := oracle.OraclePublicKey()
	require.NotNil(t, pub)
	assert.Equal(t, oracle.oraclePub.Bytes(), pub.Bytes())
}

// ---------------------------------------------------------------------------
// SignInstruction / VerifyInstruction
// ---------------------------------------------------------------------------

func TestKMSOracleSignInstruction_Valid(t *testing.T) {
	oracle := newTestOracle(t)
	instr := &PaymentInstruction{
		TradeID:     "trade-001",
		AssetID:     "equity-A",
		TotalAmount: 10_000.0,
		Currency:    "EUR",
		Reference:   "ref-001",
	}

	signed, err := oracle.SignInstruction(instr)
	require.NoError(t, err)
	require.NotNil(t, signed)
	assert.NotEmpty(t, signed.OracleSignature)
	// Original must not be mutated
	assert.Nil(t, instr.OracleSignature)
}

func TestKMSOracleSignInstruction_NilInput_Error(t *testing.T) {
	oracle := newTestOracle(t)
	_, err := oracle.SignInstruction(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestKMSOracleVerifyInstruction_Valid(t *testing.T) {
	oracle := newTestOracle(t)
	instr := &PaymentInstruction{
		TradeID:     "trade-002",
		TotalAmount: 5_000.0,
		Currency:    "GBP",
		Reference:   "ref-002",
	}

	signed, err := oracle.SignInstruction(instr)
	require.NoError(t, err)
	assert.True(t, oracle.VerifyInstruction(signed))
}

func TestKMSOracleVerifyInstruction_Nil_False(t *testing.T) {
	oracle := newTestOracle(t)
	assert.False(t, oracle.VerifyInstruction(nil))
}

func TestKMSOracleVerifyInstruction_NoSignature_False(t *testing.T) {
	oracle := newTestOracle(t)
	instr := &PaymentInstruction{TradeID: "trade-003"}
	assert.False(t, oracle.VerifyInstruction(instr))
}

func TestKMSOracleVerifyInstruction_TamperedAmount_False(t *testing.T) {
	oracle := newTestOracle(t)
	instr := &PaymentInstruction{
		TradeID:     "trade-004",
		TotalAmount: 10_000.0,
		Currency:    "EUR",
	}
	signed, _ := oracle.SignInstruction(instr)
	// Tamper the total
	signed.TotalAmount = 99_999.0
	assert.False(t, oracle.VerifyInstruction(signed))
}

func TestKMSOracleVerifyInstruction_WrongKey_False(t *testing.T) {
	oracle1 := newTestOracle(t)
	oracle2 := newTestOracle(t)
	instr := &PaymentInstruction{TradeID: "trade-005", Currency: "EUR", TotalAmount: 1000}
	signed, _ := oracle1.SignInstruction(instr)
	// oracle2 has a different key — should reject
	assert.False(t, oracle2.VerifyInstruction(signed))
}

// ---------------------------------------------------------------------------
// SignConfirmation / VerifyConfirmation
// ---------------------------------------------------------------------------

func TestKMSOracleSignConfirmation_Valid(t *testing.T) {
	oracle := newTestOracle(t)
	conf := &PaymentConfirmation{
		InstructionID:   "trade-006",
		Reference:       "ref-006",
		ConfirmedAmount: 1_500.0,
		Currency:        "EUR",
	}

	signed, err := oracle.SignConfirmation(conf)
	require.NoError(t, err)
	require.NotNil(t, signed)
	assert.NotEmpty(t, signed.OracleSignature)
	// Original not mutated
	assert.Nil(t, conf.OracleSignature)
}

func TestKMSOracleSignConfirmation_NilInput_Error(t *testing.T) {
	oracle := newTestOracle(t)
	_, err := oracle.SignConfirmation(nil)
	require.Error(t, err)
}

func TestKMSOracleVerifyConfirmation_Valid(t *testing.T) {
	oracle := newTestOracle(t)
	conf := &PaymentConfirmation{
		InstructionID:   "trade-007",
		ConfirmedAmount: 2_000.0,
		Currency:        "GBP",
	}

	signed, err := oracle.SignConfirmation(conf)
	require.NoError(t, err)
	assert.True(t, oracle.VerifyConfirmation(signed))
}

func TestKMSOracleVerifyConfirmation_Nil_False(t *testing.T) {
	oracle := newTestOracle(t)
	assert.False(t, oracle.VerifyConfirmation(nil))
}

func TestKMSOracleVerifyConfirmation_NoSignature_False(t *testing.T) {
	oracle := newTestOracle(t)
	conf := &PaymentConfirmation{InstructionID: "trade-008"}
	assert.False(t, oracle.VerifyConfirmation(conf))
}

func TestKMSOracleVerifyConfirmation_TamperedCurrency_False(t *testing.T) {
	oracle := newTestOracle(t)
	conf := &PaymentConfirmation{
		InstructionID:   "trade-009",
		ConfirmedAmount: 1_000.0,
		Currency:        "EUR",
	}
	signed, _ := oracle.SignConfirmation(conf)
	signed.Currency = "GBP" // tamper
	assert.False(t, oracle.VerifyConfirmation(signed))
}

func TestKMSOracleVerifyConfirmation_WrongKey_False(t *testing.T) {
	oracle1 := newTestOracle(t)
	oracle2 := newTestOracle(t)
	conf := &PaymentConfirmation{InstructionID: "trade-010", Currency: "EUR", ConfirmedAmount: 500}
	signed, _ := oracle1.SignConfirmation(conf)
	assert.False(t, oracle2.VerifyConfirmation(signed))
}

// ---------------------------------------------------------------------------
// Idempotency: signing a pre-signed instruction produces a fresh valid sig
// ---------------------------------------------------------------------------

func TestKMSOracleSignInstruction_Idempotent_OverwritesSig(t *testing.T) {
	oracle := newTestOracle(t)
	instr := &PaymentInstruction{TradeID: "trade-011", TotalAmount: 500, Currency: "GBP"}

	signed1, err := oracle.SignInstruction(instr)
	require.NoError(t, err)
	signed2, err := oracle.SignInstruction(signed1)
	require.NoError(t, err)

	// Both should verify correctly
	assert.True(t, oracle.VerifyInstruction(signed1))
	assert.True(t, oracle.VerifyInstruction(signed2))
}

// ---------------------------------------------------------------------------
// KMSKeyProvider (keymanager.go stub)
// ---------------------------------------------------------------------------

func TestKMSKeyProvider_PublicKeyString_Empty(t *testing.T) {
	p := NewKMSKeyProvider("arn:test")
	assert.Equal(t, "", p.PublicKeyString())
}

func TestKMSKeyProvider_PublicKeyString_Set(t *testing.T) {
	p := NewKMSKeyProvider("arn:test")
	p.PublicKey = "base64encodedpubkey"
	assert.Equal(t, "base64encodedpubkey", p.PublicKeyString())
}

func TestKMSKeyProvider_Sign_ReturnsError(t *testing.T) {
	p := NewKMSKeyProvider("arn:test")
	_, err := p.Sign([]byte("msg"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "H-2")
	assert.Contains(t, p.Calls, "Sign")
}

func TestKMSKeyProvider_Verify_ReturnsFalse(t *testing.T) {
	p := NewKMSKeyProvider("arn:test")
	assert.False(t, p.Verify([]byte("msg"), []byte("sig")))
	assert.Contains(t, p.Calls, "Verify")
}
