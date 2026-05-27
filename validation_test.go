package gonetwork

// ---------------------------------------------------------------------------
// validation_test.go — comprehensive coverage of RegistrationRecord.Validate()
//
// Each test isolates a single field rule to ensure the error message
// references the correct field name and the validation reason is correct.
// ---------------------------------------------------------------------------

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

func TestValidate_ValidRecord_NoErrors(t *testing.T) {
	r := validRegistrationRecord("wallet-alice")
	errs := r.Validate()
	assert.Empty(t, errs, "valid record should produce no errors")
}

// ---------------------------------------------------------------------------
// personal.full_legal_name
// ---------------------------------------------------------------------------

func TestValidate_FullLegalName_TooShort(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.FullLegalName = "A"
	errs := r.Validate()
	requireFieldError(t, errs, "personal.full_legal_name")
}

func TestValidate_FullLegalName_TooLong(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.FullLegalName = strings.Repeat("X", 151)
	errs := r.Validate()
	requireFieldError(t, errs, "personal.full_legal_name")
}

func TestValidate_FullLegalName_Empty(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.FullLegalName = ""
	errs := r.Validate()
	requireFieldError(t, errs, "personal.full_legal_name")
}

func TestValidate_FullLegalName_NonPrintable(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.FullLegalName = "Alice\x00Smith"
	errs := r.Validate()
	requireFieldError(t, errs, "personal.full_legal_name")
}

func TestValidate_FullLegalName_Boundary_TwoChars(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.FullLegalName = "AB"
	errs := r.Validate()
	assertNoFieldError(t, errs, "personal.full_legal_name")
}

func TestValidate_FullLegalName_Boundary_150Chars(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.FullLegalName = strings.Repeat("A", 150)
	errs := r.Validate()
	assertNoFieldError(t, errs, "personal.full_legal_name")
}

// ---------------------------------------------------------------------------
// personal.date_of_birth
// ---------------------------------------------------------------------------

func TestValidate_DOB_Missing(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.DateOfBirth = ""
	errs := r.Validate()
	requireFieldError(t, errs, "personal.date_of_birth")
}

func TestValidate_DOB_InvalidFormat(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.DateOfBirth = "01/01/1990"
	errs := r.Validate()
	requireFieldError(t, errs, "personal.date_of_birth")
}

func TestValidate_DOB_Under18(t *testing.T) {
	r := validRegistrationRecord("w1")
	// 17 years old
	r.Personal.DateOfBirth = time.Now().UTC().AddDate(-17, 0, 1).Format("2006-01-02")
	errs := r.Validate()
	requireFieldError(t, errs, "personal.date_of_birth")
}

func TestValidate_DOB_Exactly18_IsValid(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.DateOfBirth = time.Now().UTC().AddDate(-18, 0, -1).Format("2006-01-02")
	errs := r.Validate()
	assertNoFieldError(t, errs, "personal.date_of_birth")
}

// ---------------------------------------------------------------------------
// personal.nationality / personal.tax_residency
// ---------------------------------------------------------------------------

func TestValidate_Nationality_Empty(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.Nationality = ""
	errs := r.Validate()
	requireFieldError(t, errs, "personal.nationality")
}

func TestValidate_Nationality_InvalidCode(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.Nationality = "XX"
	errs := r.Validate()
	requireFieldError(t, errs, "personal.nationality")
}

func TestValidate_TaxResidency_InvalidCode(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.TaxResidency = "ZZ"
	errs := r.Validate()
	requireFieldError(t, errs, "personal.tax_residency")
}

// ---------------------------------------------------------------------------
// personal.tax_id_number (optional but constrained when present)
// ---------------------------------------------------------------------------

func TestValidate_TaxIDNumber_TooShort(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.TaxIDNumber = "AB"
	errs := r.Validate()
	requireFieldError(t, errs, "personal.tax_id_number")
}

func TestValidate_TaxIDNumber_TooLong(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.TaxIDNumber = strings.Repeat("X", 51)
	errs := r.Validate()
	requireFieldError(t, errs, "personal.tax_id_number")
}

func TestValidate_TaxIDNumber_Absent_IsValid(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Personal.TaxIDNumber = ""
	errs := r.Validate()
	assertNoFieldError(t, errs, "personal.tax_id_number")
}

// ---------------------------------------------------------------------------
// address fields
// ---------------------------------------------------------------------------

func TestValidate_Address_Line1_Empty(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Address.Line1 = ""
	errs := r.Validate()
	requireFieldError(t, errs, "address.line1")
}

func TestValidate_Address_Line1_TooLong(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Address.Line1 = strings.Repeat("A", 201)
	errs := r.Validate()
	requireFieldError(t, errs, "address.line1")
}

func TestValidate_Address_City_Empty(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Address.City = ""
	errs := r.Validate()
	requireFieldError(t, errs, "address.city")
}

func TestValidate_Address_City_TooLong(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Address.City = strings.Repeat("A", 101)
	errs := r.Validate()
	requireFieldError(t, errs, "address.city")
}

func TestValidate_Address_PostCode_Empty(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Address.PostCode = ""
	errs := r.Validate()
	requireFieldError(t, errs, "address.post_code")
}

func TestValidate_Address_PostCode_TooLong(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Address.PostCode = strings.Repeat("A", 21)
	errs := r.Validate()
	requireFieldError(t, errs, "address.post_code")
}

func TestValidate_Address_Country_Invalid(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Address.Country = "XX"
	errs := r.Validate()
	requireFieldError(t, errs, "address.country")
}

// ---------------------------------------------------------------------------
// document fields
// ---------------------------------------------------------------------------

func TestValidate_Document_Type_Missing(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Document.Type = ""
	errs := r.Validate()
	requireFieldError(t, errs, "document.type")
}

func TestValidate_Document_Type_Unrecognised(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Document.Type = "selfie"
	errs := r.Validate()
	requireFieldError(t, errs, "document.type")
}

func TestValidate_Document_Type_AllAccepted(t *testing.T) {
	for _, dt := range []string{"passport", "national_id", "driving_licence", "residence_permit"} {
		r := validRegistrationRecord("w1")
		r.Document.Type = dt
		errs := r.Validate()
		assertNoFieldError(t, errs, "document.type")
	}
}

func TestValidate_Document_IssuingCountry_Invalid(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Document.IssuingCountry = "INVALID"
	errs := r.Validate()
	requireFieldError(t, errs, "document.issuing_country")
}

func TestValidate_Document_Expiry_Missing(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Document.ExpiryDate = ""
	errs := r.Validate()
	requireFieldError(t, errs, "document.expiry_date")
}

func TestValidate_Document_Expiry_InvalidFormat(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Document.ExpiryDate = "31-12-2030"
	errs := r.Validate()
	requireFieldError(t, errs, "document.expiry_date")
}

func TestValidate_Document_Expiry_InThePast(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Document.ExpiryDate = time.Now().UTC().AddDate(-1, 0, 0).Format("2006-01-02")
	errs := r.Validate()
	requireFieldError(t, errs, "document.expiry_date")
}

func TestValidate_Document_Hash_Empty(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Document.DocumentHash = ""
	errs := r.Validate()
	requireFieldError(t, errs, "document.document_hash")
}

func TestValidate_Document_Hash_TooShort(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Document.DocumentHash = strings.Repeat("a", 32)
	errs := r.Validate()
	requireFieldError(t, errs, "document.document_hash")
}

func TestValidate_Document_Hash_UpperCase(t *testing.T) {
	r := validRegistrationRecord("w1")
	// SHA-256 must be lowercase hex
	r.Document.DocumentHash = strings.Repeat("A", 64)
	errs := r.Validate()
	requireFieldError(t, errs, "document.document_hash")
}

func TestValidate_Document_POAHash_Invalid(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Document.ProofOfAddressHash = "not-a-hash"
	errs := r.Validate()
	requireFieldError(t, errs, "document.proof_of_address_hash")
}

// ---------------------------------------------------------------------------
// consent fields
// ---------------------------------------------------------------------------

func TestValidate_Consents_TOS_Missing(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Consents.TermsOfServiceAcceptedAt = 0
	errs := r.Validate()
	requireFieldError(t, errs, "consents.terms_of_service_accepted_at")
}

func TestValidate_Consents_Privacy_Missing(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Consents.PrivacyPolicyAcceptedAt = 0
	errs := r.Validate()
	requireFieldError(t, errs, "consents.privacy_policy_accepted_at")
}

func TestValidate_Consents_RiskWarnings_Missing(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Consents.RiskWarningsAcceptedAt = 0
	errs := r.Validate()
	requireFieldError(t, errs, "consents.risk_warnings_accepted_at")
}

func TestValidate_Consents_SOF_TooShort(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Consents.SourceOfFundsDeclaration = "short"
	errs := r.Validate()
	requireFieldError(t, errs, "consents.source_of_funds_declaration")
}

func TestValidate_Consents_SOW_TooShortWhenProvided(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Consents.SourceOfWealthDeclaration = "too short"
	errs := r.Validate()
	requireFieldError(t, errs, "consents.source_of_wealth_declaration")
}

func TestValidate_Consents_SOW_Absent_IsValid(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Consents.SourceOfWealthDeclaration = ""
	errs := r.Validate()
	assertNoFieldError(t, errs, "consents.source_of_wealth_declaration")
}

func TestValidate_Consents_PEP_NotConfirmed(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Consents.NotPEP = false
	errs := r.Validate()
	requireFieldError(t, errs, "consents.not_pep")
}

func TestValidate_Consents_Sanctions_NotConfirmed(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Consents.NotSanctioned = false
	errs := r.Validate()
	requireFieldError(t, errs, "consents.not_sanctioned")
}

// ---------------------------------------------------------------------------
// jurisdiction
// ---------------------------------------------------------------------------

func TestValidate_Jurisdiction_Empty(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Jurisdiction = ""
	errs := r.Validate()
	requireFieldError(t, errs, "jurisdiction")
}

func TestValidate_Jurisdiction_Invalid(t *testing.T) {
	r := validRegistrationRecord("w1")
	r.Jurisdiction = "EU" // not a valid alpha-2 country code
	errs := r.Validate()
	requireFieldError(t, errs, "jurisdiction")
}

// ---------------------------------------------------------------------------
// Multiple errors in one record
// ---------------------------------------------------------------------------

func TestValidate_MultipleErrors_AllReported(t *testing.T) {
	r := &RegistrationRecord{}
	errs := r.Validate()
	// A completely empty record should trigger many field errors
	require.Greater(t, len(errs), 5, "completely empty record should yield many errors")
}

// ---------------------------------------------------------------------------
// IsValidISO3166
// ---------------------------------------------------------------------------

func TestIsValidISO3166_KnownCodes(t *testing.T) {
	for _, code := range []string{"GB", "DE", "FR", "US", "JP", "AU"} {
		assert.True(t, IsValidISO3166(code), "%s should be valid", code)
	}
}

func TestIsValidISO3166_LowercaseAccepted(t *testing.T) {
	assert.True(t, IsValidISO3166("gb"), "lowercase should be accepted")
}

func TestIsValidISO3166_InvalidCodes(t *testing.T) {
	for _, code := range []string{"XX", "EU", "ZZ", "UK", "ENG"} {
		assert.False(t, IsValidISO3166(code), "%s should be invalid", code)
	}
}

// ---------------------------------------------------------------------------
// ValidationError.Error()
// ---------------------------------------------------------------------------

func TestValidationError_Error(t *testing.T) {
	ve := ValidationError{Field: "personal.full_legal_name", Message: "is required"}
	assert.Equal(t, "personal.full_legal_name: is required", ve.Error())
}

// ---------------------------------------------------------------------------
// Helper assertions
// ---------------------------------------------------------------------------

// requireFieldError asserts that at least one ValidationError references the given field.
func requireFieldError(t *testing.T, errs []ValidationError, field string) {
	t.Helper()
	for _, e := range errs {
		if e.Field == field {
			return
		}
	}
	t.Errorf("expected a ValidationError for field %q but none was found; got: %+v", field, errs)
}

// assertNoFieldError asserts there is no ValidationError for the given field.
func assertNoFieldError(t *testing.T, errs []ValidationError, field string) {
	t.Helper()
	for _, e := range errs {
		if e.Field == field {
			t.Errorf("unexpected ValidationError for field %q: %s", field, e.Message)
			return
		}
	}
}
