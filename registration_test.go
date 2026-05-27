package gonetwork

// ---------------------------------------------------------------------------
// registration_test.go — RegistrationRegistry (PII encryption, lifecycle)
//
// Covers:
//   NewRegistrationRegistry       — default construction, bad key panic
//   Upsert / Get                  — round-trip, timestamps, nil key result
//   ListPending                   — filter + sort by SubmittedAt
//   UpdateStatus                  — lifecycle transitions, error on missing
//   All                           — returns all records
//   PII encryption (M-7)          — encrypted fields not equal to plaintext in
//                                   stored map; decrypted output matches input
//   RedactPII                     — sensitive fields blanked
//   Validate integration          — Validate() errors on incomplete record
// ---------------------------------------------------------------------------

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// NewRegistrationRegistry — basic construction
// ---------------------------------------------------------------------------

func TestNewRegistrationRegistry_Default_NoPIIKey(t *testing.T) {
	os.Unsetenv("GREENHOUSE_PII_KEY")
	rr := NewRegistrationRegistry()
	require.NotNil(t, rr)
	assert.False(t, rr.hasPIIKey, "should not have PII key when env var absent")
}

func TestNewRegistrationRegistry_ValidKey(t *testing.T) {
	key := hex.EncodeToString(make([]byte, 32)) // 64 zeroes — valid
	t.Setenv("GREENHOUSE_PII_KEY", key)
	rr := NewRegistrationRegistry()
	require.NotNil(t, rr)
	assert.True(t, rr.hasPIIKey)
}

func TestNewRegistrationRegistry_ShortKey_Panics(t *testing.T) {
	t.Setenv("GREENHOUSE_PII_KEY", "tooshort")
	assert.Panics(t, func() { NewRegistrationRegistry() })
}

func TestNewRegistrationRegistry_NonHexKey_Panics(t *testing.T) {
	t.Setenv("GREENHOUSE_PII_KEY", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	assert.Panics(t, func() { NewRegistrationRegistry() })
}

// ---------------------------------------------------------------------------
// Upsert / Get — basic round-trip
// ---------------------------------------------------------------------------

func TestRegistrationRegistry_Upsert_Get_RoundTrip(t *testing.T) {
	os.Unsetenv("GREENHOUSE_PII_KEY")
	rr := NewRegistrationRegistry()
	rec := validRegistrationRecord("wallet-a")

	rr.Upsert(rec)
	got := rr.Get("wallet-a")

	require.NotNil(t, got)
	assert.Equal(t, "wallet-a", got.WalletKey)
	assert.Equal(t, "Alice Olivia Smith", got.Personal.FullLegalName)
	assert.Equal(t, "1 City Road", got.Address.Line1)
}

func TestRegistrationRegistry_Get_UnknownWallet_ReturnsNil(t *testing.T) {
	os.Unsetenv("GREENHOUSE_PII_KEY")
	rr := NewRegistrationRegistry()
	assert.Nil(t, rr.Get("does-not-exist"))
}

func TestRegistrationRegistry_Upsert_SetsCreatedAt(t *testing.T) {
	os.Unsetenv("GREENHOUSE_PII_KEY")
	rr := NewRegistrationRegistry()
	rec := validRegistrationRecord("wallet-b")
	rec.CreatedAt = 0

	rr.Upsert(rec)
	got := rr.Get("wallet-b")
	assert.Greater(t, got.CreatedAt, int64(0))
}

func TestRegistrationRegistry_Upsert_SetsUpdatedAt(t *testing.T) {
	os.Unsetenv("GREENHOUSE_PII_KEY")
	rr := NewRegistrationRegistry()
	rec := validRegistrationRecord("wallet-c")
	rr.Upsert(rec)
	first := rr.Get("wallet-c").UpdatedAt

	rr.Upsert(rec)
	second := rr.Get("wallet-c").UpdatedAt
	assert.GreaterOrEqual(t, second, first)
}

func TestRegistrationRegistry_Upsert_PreservesExistingCreatedAt(t *testing.T) {
	os.Unsetenv("GREENHOUSE_PII_KEY")
	rr := NewRegistrationRegistry()
	rec := validRegistrationRecord("wallet-d")
	rec.CreatedAt = 1000 // explicitly set

	rr.Upsert(rec)
	got := rr.Get("wallet-d")
	assert.Equal(t, int64(1000), got.CreatedAt)
}

// ---------------------------------------------------------------------------
// ListPending — filter and sort
// ---------------------------------------------------------------------------

func TestRegistrationRegistry_ListPending_SortedBySubmittedAt(t *testing.T) {
	os.Unsetenv("GREENHOUSE_PII_KEY")
	rr := NewRegistrationRegistry()

	r1 := validRegistrationRecord("w1")
	r1.Status = RegistrationStatusPendingReview
	r1.SubmittedAt = 1000

	r2 := validRegistrationRecord("w2")
	r2.Status = RegistrationStatusPendingReview
	r2.SubmittedAt = 500

	r3 := validRegistrationRecord("w3")
	r3.Status = RegistrationStatusApproved // not pending
	r3.SubmittedAt = 100

	rr.Upsert(r1)
	rr.Upsert(r2)
	rr.Upsert(r3)

	pending := rr.ListPending()
	require.Len(t, pending, 2)
	assert.Equal(t, "w2", pending[0].WalletKey, "oldest first")
	assert.Equal(t, "w1", pending[1].WalletKey)
}

func TestRegistrationRegistry_ListPending_EmptyWhenNonePending(t *testing.T) {
	os.Unsetenv("GREENHOUSE_PII_KEY")
	rr := NewRegistrationRegistry()
	r := validRegistrationRecord("w1")
	r.Status = RegistrationStatusApproved
	rr.Upsert(r)
	assert.Empty(t, rr.ListPending())
}

// ---------------------------------------------------------------------------
// UpdateStatus
// ---------------------------------------------------------------------------

func TestRegistrationRegistry_UpdateStatus_Success(t *testing.T) {
	os.Unsetenv("GREENHOUSE_PII_KEY")
	rr := NewRegistrationRegistry()
	rec := validRegistrationRecord("wallet-e")
	rec.Status = RegistrationStatusPendingReview
	rr.Upsert(rec)

	err := rr.UpdateStatus("wallet-e", RegistrationStatusApproved, "admin-wallet", "")
	require.NoError(t, err)

	got := rr.Get("wallet-e")
	assert.Equal(t, RegistrationStatusApproved, got.Status)
	assert.Equal(t, "admin-wallet", got.ReviewedBy)
	assert.Greater(t, got.ReviewedAt, int64(0))
}

func TestRegistrationRegistry_UpdateStatus_Rejected_WithReason(t *testing.T) {
	os.Unsetenv("GREENHOUSE_PII_KEY")
	rr := NewRegistrationRegistry()
	rec := validRegistrationRecord("wallet-f")
	rr.Upsert(rec)

	err := rr.UpdateStatus("wallet-f", RegistrationStatusRejected, "admin", "Document expired")
	require.NoError(t, err)

	got := rr.Get("wallet-f")
	assert.Equal(t, RegistrationStatusRejected, got.Status)
	assert.Equal(t, "Document expired", got.RejectionReason)
}

func TestRegistrationRegistry_UpdateStatus_UnknownWallet_ReturnsError(t *testing.T) {
	os.Unsetenv("GREENHOUSE_PII_KEY")
	rr := NewRegistrationRegistry()
	err := rr.UpdateStatus("ghost-wallet", RegistrationStatusApproved, "admin", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ghost-wallet")
}

// ---------------------------------------------------------------------------
// All
// ---------------------------------------------------------------------------

func TestRegistrationRegistry_All_ReturnsAllRecords(t *testing.T) {
	os.Unsetenv("GREENHOUSE_PII_KEY")
	rr := NewRegistrationRegistry()
	rr.Upsert(validRegistrationRecord("w1"))
	rr.Upsert(validRegistrationRecord("w2"))
	rr.Upsert(validRegistrationRecord("w3"))

	all := rr.All()
	assert.Len(t, all, 3)
}

func TestRegistrationRegistry_All_EmptyRegistry(t *testing.T) {
	os.Unsetenv("GREENHOUSE_PII_KEY")
	rr := NewRegistrationRegistry()
	assert.Empty(t, rr.All())
}

// ---------------------------------------------------------------------------
// PII encryption (M-7)
// ---------------------------------------------------------------------------

func registryWithPIIKey(t *testing.T) *RegistrationRegistry {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	t.Setenv("GREENHOUSE_PII_KEY", hex.EncodeToString(key))
	return NewRegistrationRegistry()
}

func TestRegistrationRegistry_PIIEncryption_GetReturnsPlaintext(t *testing.T) {
	rr := registryWithPIIKey(t)
	rec := validRegistrationRecord("pii-wallet")

	rr.Upsert(rec)
	got := rr.Get("pii-wallet")

	require.NotNil(t, got)
	// Caller always receives plaintext regardless of encryption status
	assert.Equal(t, "Alice Olivia Smith", got.Personal.FullLegalName)
	assert.Equal(t, "1 City Road", got.Address.Line1)
	assert.Equal(t, "London", got.Address.City)
}

func TestRegistrationRegistry_PIIEncryption_StoredFieldsAreEncrypted(t *testing.T) {
	rr := registryWithPIIKey(t)
	rec := validRegistrationRecord("pii-wallet2")
	rr.Upsert(rec)

	// Access the raw stored record without decryption
	rr.mu.RLock()
	raw := rr.records["pii-wallet2"]
	rr.mu.RUnlock()

	require.NotNil(t, raw)
	// Stored value must NOT be the original plaintext — it should have "enc:" prefix
	assert.NotEqual(t, "Alice Olivia Smith", raw.Personal.FullLegalName,
		"stored name must be encrypted, not plaintext")
	assert.True(t, len(raw.Personal.FullLegalName) > 4 &&
		raw.Personal.FullLegalName[:4] == "enc:",
		"stored name should have enc: prefix")
}

func TestRegistrationRegistry_PIIEncryption_EmptyFieldNotEncrypted(t *testing.T) {
	rr := registryWithPIIKey(t)
	rec := validRegistrationRecord("pii-wallet3")
	rec.Personal.TaxIDNumber = ""
	rr.Upsert(rec)

	rr.mu.RLock()
	raw := rr.records["pii-wallet3"]
	rr.mu.RUnlock()

	// Empty string should remain empty (not "enc:...")
	assert.Equal(t, "", raw.Personal.TaxIDNumber)
}

func TestRegistrationRegistry_PIIEncryption_ListPendingDecrypts(t *testing.T) {
	rr := registryWithPIIKey(t)
	rec := validRegistrationRecord("pii-pending")
	rec.Status = RegistrationStatusPendingReview
	rr.Upsert(rec)

	pending := rr.ListPending()
	require.Len(t, pending, 1)
	assert.Equal(t, "Alice Olivia Smith", pending[0].Personal.FullLegalName)
}

func TestRegistrationRegistry_PIIEncryption_AllDecrypts(t *testing.T) {
	rr := registryWithPIIKey(t)
	rec := validRegistrationRecord("pii-all")
	rr.Upsert(rec)

	all := rr.All()
	require.Len(t, all, 1)
	assert.Equal(t, "Alice Olivia Smith", all[0].Personal.FullLegalName)
}

func TestRegistrationRegistry_PIIEncryption_DifferentCiphertextEachUpsert(t *testing.T) {
	// AES-GCM uses a random nonce so the same plaintext must produce different ciphertext
	rr := registryWithPIIKey(t)
	rec := validRegistrationRecord("pii-nonce")
	rr.Upsert(rec)

	rr.mu.RLock()
	first := rr.records["pii-nonce"].Personal.FullLegalName
	rr.mu.RUnlock()

	rr.Upsert(rec)

	rr.mu.RLock()
	second := rr.records["pii-nonce"].Personal.FullLegalName
	rr.mu.RUnlock()

	assert.NotEqual(t, first, second, "nonce must be random — ciphertext must differ per encryption")
}

func TestRegistrationRegistry_PIIEncryption_AllTenFieldsEncrypted(t *testing.T) {
	rr := registryWithPIIKey(t)
	sof := "Employment income from senior engineering position at technology company. " // >50 chars
	sow := "Accumulated savings from 10 years of employment in the technology sector.  "
	rec := validRegistrationRecord("pii-all-fields")
	rec.Personal.TaxIDNumber = "AB123456C"
	rec.Address.Line2 = "Flat 4B"
	rec.Consents.SourceOfFundsDeclaration = sof
	rec.Consents.SourceOfWealthDeclaration = sow
	rr.Upsert(rec)

	rr.mu.RLock()
	raw := rr.records["pii-all-fields"]
	rr.mu.RUnlock()

	for field, value := range map[string]string{
		"FullLegalName":             raw.Personal.FullLegalName,
		"DateOfBirth":               raw.Personal.DateOfBirth,
		"Nationality":               raw.Personal.Nationality,
		"TaxResidency":              raw.Personal.TaxResidency,
		"TaxIDNumber":               raw.Personal.TaxIDNumber,
		"Address.Line1":             raw.Address.Line1,
		"Address.Line2":             raw.Address.Line2,
		"Address.City":              raw.Address.City,
		"Address.PostCode":          raw.Address.PostCode,
		"SourceOfFundsDeclaration":  raw.Consents.SourceOfFundsDeclaration,
		"SourceOfWealthDeclaration": raw.Consents.SourceOfWealthDeclaration,
	} {
		assert.Truef(t, len(value) >= 4 && value[:4] == "enc:",
			"field %s should be encrypted (have %q)", field, value)
	}
}

// ---------------------------------------------------------------------------
// RedactPII
// ---------------------------------------------------------------------------

func TestRedactPII_SensitiveFieldsBlanked(t *testing.T) {
	r := validRegistrationRecord("wallet-r")
	redacted := r.RedactPII()

	assert.Equal(t, "[redacted]", redacted.Personal.TaxIDNumber)
	assert.Equal(t, "[redacted]", redacted.Document.DocumentHash)
	assert.Equal(t, "[redacted]", redacted.Document.ProofOfAddressHash)
	assert.Equal(t, "[redacted]", redacted.Consents.SourceOfFundsDeclaration)
	assert.Equal(t, "[redacted]", redacted.Consents.SourceOfWealthDeclaration)
}

func TestRedactPII_NonSensitiveFieldsPreserved(t *testing.T) {
	r := validRegistrationRecord("wallet-r")
	redacted := r.RedactPII()

	assert.Equal(t, "wallet-r", redacted.WalletKey)
	assert.Equal(t, "Alice Olivia Smith", redacted.Personal.FullLegalName)
	assert.Equal(t, "London", redacted.Address.City)
}

func TestRedactPII_DoesNotMutateOriginal(t *testing.T) {
	r := validRegistrationRecord("wallet-r")
	origHash := r.Document.DocumentHash
	_ = r.RedactPII()
	assert.Equal(t, origHash, r.Document.DocumentHash, "RedactPII must not mutate the original")
}

// ---------------------------------------------------------------------------
// IsComplete (deprecated but tested for backwards compat)
// ---------------------------------------------------------------------------

func TestIsComplete_ValidRecord(t *testing.T) {
	r := validRegistrationRecord("wallet-complete")
	assert.True(t, r.IsComplete())
}

func TestIsComplete_EmptyRecord(t *testing.T) {
	r := &RegistrationRecord{}
	assert.False(t, r.IsComplete())
}
