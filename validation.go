package gonetwork

// ---------------------------------------------------------------------------
// Validation — production-grade input validation for registration records
//
// Implements semantic validation beyond empty-string checks:
//   - ISO 3166-1 alpha-2 country codes for all country/jurisdiction fields
//   - YYYY-MM-DD date format and age ≥ 18 check for date of birth
//   - SHA-256 hex format for document hashes (64 lowercase hex chars)
//   - Document type whitelist and future-dated expiry enforcement
//   - Minimum length for source-of-funds / source-of-wealth declarations
//   - Character set enforcement for legal names
//
// Usage:
//
//	if errs := record.Validate(); len(errs) > 0 {
//	    // handle field-level errors
//	}
// ---------------------------------------------------------------------------

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// ValidationError describes a single field-level validation failure.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// docHashRE matches a lowercase SHA-256 hex string (exactly 64 characters).
var docHashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// validDocumentTypes is the exhaustive set of accepted identity document type codes.
// Acceptable per MLD5 Article 13 / MLR 2017 regulation 28.
var validDocumentTypes = map[string]bool{
	"passport":         true,
	"national_id":      true,
	"driving_licence":  true,
	"residence_permit": true,
}

// iso3166Alpha2 is the complete ISO 3166-1 alpha-2 country code set (2024 edition).
// Stored as a map for O(1) lookups. Lookup is case-insensitive via ToUpper normalisation.
var iso3166Alpha2 = map[string]struct{}{
	"AF": {}, "AX": {}, "AL": {}, "DZ": {}, "AS": {}, "AD": {}, "AO": {}, "AI": {},
	"AQ": {}, "AG": {}, "AR": {}, "AM": {}, "AW": {}, "AU": {}, "AT": {}, "AZ": {},
	"BS": {}, "BH": {}, "BD": {}, "BB": {}, "BY": {}, "BE": {}, "BZ": {}, "BJ": {},
	"BM": {}, "BT": {}, "BO": {}, "BQ": {}, "BA": {}, "BW": {}, "BV": {}, "BR": {},
	"IO": {}, "BN": {}, "BG": {}, "BF": {}, "BI": {}, "CV": {}, "KH": {}, "CM": {},
	"CA": {}, "KY": {}, "CF": {}, "TD": {}, "CL": {}, "CN": {}, "CX": {}, "CC": {},
	"CO": {}, "KM": {}, "CG": {}, "CD": {}, "CK": {}, "CR": {}, "CI": {}, "HR": {},
	"CU": {}, "CW": {}, "CY": {}, "CZ": {}, "DK": {}, "DJ": {}, "DM": {}, "DO": {},
	"EC": {}, "EG": {}, "SV": {}, "GQ": {}, "ER": {}, "EE": {}, "SZ": {}, "ET": {},
	"FK": {}, "FO": {}, "FJ": {}, "FI": {}, "FR": {}, "GF": {}, "PF": {}, "TF": {},
	"GA": {}, "GM": {}, "GE": {}, "DE": {}, "GH": {}, "GI": {}, "GR": {}, "GL": {},
	"GD": {}, "GP": {}, "GU": {}, "GT": {}, "GG": {}, "GN": {}, "GW": {}, "GY": {},
	"HT": {}, "HM": {}, "VA": {}, "HN": {}, "HK": {}, "HU": {}, "IS": {}, "IN": {},
	"ID": {}, "IR": {}, "IQ": {}, "IE": {}, "IM": {}, "IL": {}, "IT": {}, "JM": {},
	"JP": {}, "JE": {}, "JO": {}, "KZ": {}, "KE": {}, "KI": {}, "KP": {}, "KR": {},
	"KW": {}, "KG": {}, "LA": {}, "LV": {}, "LB": {}, "LS": {}, "LR": {}, "LY": {},
	"LI": {}, "LT": {}, "LU": {}, "MO": {}, "MG": {}, "MW": {}, "MY": {}, "MV": {},
	"ML": {}, "MT": {}, "MH": {}, "MQ": {}, "MR": {}, "MU": {}, "YT": {}, "MX": {},
	"FM": {}, "MD": {}, "MC": {}, "MN": {}, "ME": {}, "MS": {}, "MA": {}, "MZ": {},
	"MM": {}, "NA": {}, "NR": {}, "NP": {}, "NL": {}, "NC": {}, "NZ": {}, "NI": {},
	"NE": {}, "NG": {}, "NU": {}, "NF": {}, "MK": {}, "MP": {}, "NO": {}, "OM": {},
	"PK": {}, "PW": {}, "PS": {}, "PA": {}, "PG": {}, "PY": {}, "PE": {}, "PH": {},
	"PN": {}, "PL": {}, "PT": {}, "PR": {}, "QA": {}, "RE": {}, "RO": {}, "RU": {},
	"RW": {}, "BL": {}, "SH": {}, "KN": {}, "LC": {}, "MF": {}, "PM": {}, "VC": {},
	"WS": {}, "SM": {}, "ST": {}, "SA": {}, "SN": {}, "RS": {}, "SC": {}, "SL": {},
	"SG": {}, "SX": {}, "SK": {}, "SI": {}, "SB": {}, "SO": {}, "ZA": {}, "GS": {},
	"SS": {}, "ES": {}, "LK": {}, "SD": {}, "SR": {}, "SJ": {}, "SE": {}, "CH": {},
	"SY": {}, "TW": {}, "TJ": {}, "TZ": {}, "TH": {}, "TL": {}, "TG": {}, "TK": {},
	"TO": {}, "TT": {}, "TN": {}, "TR": {}, "TM": {}, "TC": {}, "TV": {}, "UG": {},
	"UA": {}, "AE": {}, "GB": {}, "US": {}, "UM": {}, "UY": {}, "UZ": {}, "VU": {},
	"VE": {}, "VN": {}, "VG": {}, "VI": {}, "WF": {}, "EH": {}, "YE": {}, "ZM": {},
	"ZW": {},
}

// IsValidISO3166 returns true if code is a recognised ISO 3166-1 alpha-2 code.
// The lookup is case-insensitive.
func IsValidISO3166(code string) bool {
	_, ok := iso3166Alpha2[strings.ToUpper(code)]
	return ok
}

// isValidDocHash returns true if s is a 64-character lowercase hexadecimal string.
func isValidDocHash(s string) bool {
	return docHashRE.MatchString(s)
}

// isPrintableName returns true if every rune in s is printable (no control characters).
func isPrintableName(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// Validate performs comprehensive field-level validation on the RegistrationRecord
// and returns a slice of ValidationErrors. An empty slice means the record is valid
// and ready to be transitioned to pending_review.
//
// This replaces the legacy IsComplete() empty-string check with full semantic
// validation required for AML/KYC compliance under 5AMLD, MLR 2017, and MiFID II.
//
// Validation is delegated to one section-scoped helper per part of the record,
// invoked in the same order as this doc comment lists them. Each helper is
// independently testable and self-contained (no cross-section dependencies).
func (r *RegistrationRecord) Validate() []ValidationError {
	var errs []ValidationError
	errs = append(errs, r.personalInfoErrors()...)
	errs = append(errs, r.addressErrors()...)
	errs = append(errs, r.documentErrors()...)
	errs = append(errs, r.consentErrors()...)
	// Corporate/institutional checks only apply when Corporate is present —
	// individual investors leave this nil and are unaffected.
	if r.Corporate != nil {
		errs = append(errs, r.corporateErrors()...)
	}
	errs = append(errs, r.jurisdictionErrors()...)
	return errs
}

// personalInfoErrors validates full legal name, date of birth (incl. age ≥ 18),
// nationality, tax residency, and optional tax ID number.
func (r *RegistrationRecord) personalInfoErrors() []ValidationError {
	var errs []ValidationError
	add := func(field, msg string) {
		errs = append(errs, ValidationError{Field: field, Message: msg})
	}

	name := strings.TrimSpace(r.Personal.FullLegalName)
	switch {
	case len(name) < 2:
		add("personal.full_legal_name", "must be at least 2 characters")
	case len(name) > 150:
		add("personal.full_legal_name", "must not exceed 150 characters")
	case !isPrintableName(name):
		add("personal.full_legal_name", "must contain only printable characters")
	}

	if r.Personal.DateOfBirth == "" {
		add("personal.date_of_birth", "is required")
	} else {
		dob, err := time.Parse("2006-01-02", r.Personal.DateOfBirth)
		if err != nil {
			add("personal.date_of_birth", "must be in YYYY-MM-DD format")
		} else {
			// Age gate: applicant must be at least 18 years old on the current date.
			if dob.After(time.Now().UTC().AddDate(-18, 0, 0)) {
				add("personal.date_of_birth", "applicant must be at least 18 years old")
			}
		}
	}

	if r.Personal.Nationality == "" {
		add("personal.nationality", "is required")
	} else if !IsValidISO3166(r.Personal.Nationality) {
		add("personal.nationality", fmt.Sprintf("%q is not a valid ISO 3166-1 alpha-2 country code", r.Personal.Nationality))
	}

	if r.Personal.TaxResidency == "" {
		add("personal.tax_residency", "is required")
	} else if !IsValidISO3166(r.Personal.TaxResidency) {
		add("personal.tax_residency", fmt.Sprintf("%q is not a valid ISO 3166-1 alpha-2 country code", r.Personal.TaxResidency))
	}

	tin := strings.TrimSpace(r.Personal.TaxIDNumber)
	// TIN is optional; when provided it must satisfy minimum length for meaningful content.
	if tin != "" && (len(tin) < 4 || len(tin) > 50) {
		add("personal.tax_id_number", "if provided, must be between 4 and 50 characters")
	}

	return errs
}

// addressErrors validates the residential address block.
func (r *RegistrationRecord) addressErrors() []ValidationError {
	var errs []ValidationError
	add := func(field, msg string) {
		errs = append(errs, ValidationError{Field: field, Message: msg})
	}

	if strings.TrimSpace(r.Address.Line1) == "" {
		add("address.line1", "is required")
	} else if len(r.Address.Line1) > 200 {
		add("address.line1", "must not exceed 200 characters")
	}

	if strings.TrimSpace(r.Address.City) == "" {
		add("address.city", "is required")
	} else if len(r.Address.City) > 100 {
		add("address.city", "must not exceed 100 characters")
	}

	if strings.TrimSpace(r.Address.PostCode) == "" {
		add("address.post_code", "is required")
	} else if len(r.Address.PostCode) > 20 {
		add("address.post_code", "must not exceed 20 characters")
	}

	if r.Address.Country == "" {
		add("address.country", "is required")
	} else if !IsValidISO3166(r.Address.Country) {
		add("address.country", fmt.Sprintf("%q is not a valid ISO 3166-1 alpha-2 country code", r.Address.Country))
	}

	return errs
}

// documentErrors validates the identity document block (type, issuing country,
// expiry, document hash, proof-of-address hash).
func (r *RegistrationRecord) documentErrors() []ValidationError {
	var errs []ValidationError
	add := func(field, msg string) {
		errs = append(errs, ValidationError{Field: field, Message: msg})
	}

	if r.Document.Type == "" {
		add("document.type", "is required")
	} else if !validDocumentTypes[r.Document.Type] {
		add("document.type", fmt.Sprintf("%q is not a recognised document type; accepted values: passport, national_id, driving_licence, residence_permit", r.Document.Type))
	}

	if r.Document.IssuingCountry == "" {
		add("document.issuing_country", "is required")
	} else if !IsValidISO3166(r.Document.IssuingCountry) {
		add("document.issuing_country", fmt.Sprintf("%q is not a valid ISO 3166-1 alpha-2 country code", r.Document.IssuingCountry))
	}

	if r.Document.ExpiryDate == "" {
		add("document.expiry_date", "is required")
	} else {
		expiry, err := time.Parse("2006-01-02", r.Document.ExpiryDate)
		if err != nil {
			add("document.expiry_date", "must be in YYYY-MM-DD format")
		} else if !expiry.After(time.Now().UTC()) {
			add("document.expiry_date", "document has expired and cannot be accepted")
		}
	}

	if r.Document.DocumentHash == "" {
		add("document.document_hash", "is required")
	} else if !isValidDocHash(r.Document.DocumentHash) {
		add("document.document_hash", "must be a 64-character lowercase hexadecimal SHA-256 hash")
	}

	if r.Document.ProofOfAddressHash == "" {
		add("document.proof_of_address_hash", "is required")
	} else if !isValidDocHash(r.Document.ProofOfAddressHash) {
		add("document.proof_of_address_hash", "must be a 64-character lowercase hexadecimal SHA-256 hash")
	}

	return errs
}

// consentErrors validates T&C/privacy/risk-warning acceptance timestamps,
// source-of-funds/wealth declarations, and PEP/sanctions self-certification.
func (r *RegistrationRecord) consentErrors() []ValidationError {
	var errs []ValidationError
	add := func(field, msg string) {
		errs = append(errs, ValidationError{Field: field, Message: msg})
	}

	if r.Consents.TermsOfServiceAcceptedAt <= 0 {
		add("consents.terms_of_service_accepted_at", "terms of service must be accepted before submitting")
	}
	if r.Consents.PrivacyPolicyAcceptedAt <= 0 {
		add("consents.privacy_policy_accepted_at", "privacy policy must be accepted before submitting")
	}
	if r.Consents.RiskWarningsAcceptedAt <= 0 {
		add("consents.risk_warnings_accepted_at", "risk warnings must be accepted before submitting")
	}

	if len(strings.TrimSpace(r.Consents.SourceOfFundsDeclaration)) < 50 {
		add("consents.source_of_funds_declaration", "must be at least 50 characters describing the source of funds")
	}

	// Source of wealth is required for EDD (enhanced due diligence) classifications;
	// if provided by any applicant it must also meet the minimum length threshold.
	if sow := strings.TrimSpace(r.Consents.SourceOfWealthDeclaration); len(sow) > 0 && len(sow) < 50 {
		add("consents.source_of_wealth_declaration", "if provided, must be at least 50 characters")
	}

	if !r.Consents.NotPEP {
		add("consents.not_pep", "applicant must confirm they are not a politically exposed person")
	}
	if !r.Consents.NotSanctioned {
		add("consents.not_sanctioned", "applicant must confirm they are not subject to financial sanctions")
	}

	return errs
}

// corporateErrors validates the corporate/institutional onboarding block
// (Phase 3). Callers must only invoke this when r.Corporate != nil.
func (r *RegistrationRecord) corporateErrors() []ValidationError {
	var errs []ValidationError
	add := func(field, msg string) {
		errs = append(errs, ValidationError{Field: field, Message: msg})
	}

	if r.EntityLEI == "" {
		add("entity_lei", "is required when registering as a corporate entity")
	} else if err := ValidateLEI(r.EntityLEI); err != nil {
		add("entity_lei", err.Error())
	}
	if r.Corporate.IncorporationDocumentHash == "" {
		add("corporate.incorporation_document_hash", "is required")
	} else if !isValidDocHash(r.Corporate.IncorporationDocumentHash) {
		add("corporate.incorporation_document_hash", "must be a 64-character lowercase hexadecimal SHA-256 hash")
	}
	if r.Corporate.RegisteredAddressHash == "" {
		add("corporate.registered_address_hash", "is required")
	} else if !isValidDocHash(r.Corporate.RegisteredAddressHash) {
		add("corporate.registered_address_hash", "must be a 64-character lowercase hexadecimal SHA-256 hash")
	}
	if h := r.Corporate.ArticlesOfAssociationHash; h != "" && !isValidDocHash(h) {
		add("corporate.articles_of_association_hash", "if provided, must be a 64-character lowercase hexadecimal SHA-256 hash")
	}
	if h := r.Corporate.CompaniesHouseExtractHash; h != "" && !isValidDocHash(h) {
		add("corporate.companies_house_extract_hash", "if provided, must be a 64-character lowercase hexadecimal SHA-256 hash")
	}

	return errs
}

// jurisdictionErrors validates the top-level jurisdiction field.
func (r *RegistrationRecord) jurisdictionErrors() []ValidationError {
	var errs []ValidationError
	if r.Jurisdiction == "" {
		errs = append(errs, ValidationError{Field: "jurisdiction", Message: "is required"})
	} else if !IsValidISO3166(r.Jurisdiction) {
		errs = append(errs, ValidationError{
			Field:   "jurisdiction",
			Message: fmt.Sprintf("%q is not a valid ISO 3166-1 alpha-2 country code", r.Jurisdiction),
		})
	}
	return errs
}
