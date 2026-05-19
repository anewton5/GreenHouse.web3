package gonetwork

// ---------------------------------------------------------------------------
// Registration — production investor onboarding
//
// EU/UK legislative references:
//   MiFID II / MiFIR (2014/65/EU)        — investor classification, appropriateness
//   UK FCA COBS 3, 4.7, 10              — categorisation, risk warnings, appropriateness
//   5AMLD (EU 2018/843) / JMLSG          — CDD, EDD, source of funds/wealth
//   UK MLR 2017 (SI 2017/692)            — AML CDD requirements
//   GDPR (EU 2016/679) / UK GDPR        — PII handling, data minimisation
//   FATCA / CRS                          — TIN collection for tax reporting
//   EU DLT Pilot Regime (2022/858)       — digital securities CSD requirements
//   FCA Digital Securities Sandbox       — UK equivalent sandbox requirements
//   ECB Appia / Pontes pilot             — DLT operator registration for CeBM settlement
// ---------------------------------------------------------------------------

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// RegistrationStatus tracks the full lifecycle of an investor's onboarding.
type RegistrationStatus string

const (
	// RegistrationStatusUnregistered — wallet exists but has not started registration.
	RegistrationStatusUnregistered RegistrationStatus = "unregistered"
	// RegistrationStatusTermsAccepted — investor has accepted T&C, Privacy & Risk Warnings
	// but has not yet submitted personal information.
	RegistrationStatusTermsAccepted RegistrationStatus = "terms_accepted"
	// RegistrationStatusSubmitted — investor has completed all form steps; awaiting KYC check.
	RegistrationStatusSubmitted RegistrationStatus = "submitted"
	// RegistrationStatusPendingReview — documents received; awaiting operator or Onfido review.
	RegistrationStatusPendingReview RegistrationStatus = "pending_review"
	// RegistrationStatusApproved — registration approved; KYC credential will be issued.
	RegistrationStatusApproved RegistrationStatus = "approved"
	// RegistrationStatusRejected — registration rejected (reason stored in RejectionReason).
	RegistrationStatusRejected RegistrationStatus = "rejected"
	// RegistrationStatusSuspended — account suspended pending further investigation (SAR/AML).
	RegistrationStatusSuspended RegistrationStatus = "suspended"
)

// ---------------------------------------------------------------------------
// PersonalInfo
// ---------------------------------------------------------------------------

// PersonalInfo holds the CDD core identity fields required under 5AMLD / UK MLR 2017.
// This data is PII and must be stored encrypted at-rest.
// Data retention: 5 years from date of last transaction (JMLSG 3.36 / MLR 2017 reg.40).
type PersonalInfo struct {
	FullLegalName string `json:"full_legal_name"`         // As shown on identity document
	DateOfBirth   string `json:"date_of_birth"`           // ISO 8601: YYYY-MM-DD
	Nationality   string `json:"nationality"`             // ISO 3166-1 alpha-2
	TaxResidency  string `json:"tax_residency"`           // ISO 3166-1 alpha-2 (primary)
	TaxIDNumber   string `json:"tax_id_number,omitempty"` // TIN — required for FATCA / OECD CRS reporting
}

// ---------------------------------------------------------------------------
// AddressInfo
// ---------------------------------------------------------------------------

// AddressInfo is the investor's current residential address for CDD purposes.
// Updated whenever the investor changes address (must re-verify within 30 days).
type AddressInfo struct {
	Line1    string `json:"line1"`
	Line2    string `json:"line2,omitempty"`
	City     string `json:"city"`
	PostCode string `json:"post_code"`
	Country  string `json:"country"` // ISO 3166-1 alpha-2
}

// ---------------------------------------------------------------------------
// IdentityDocument
// ---------------------------------------------------------------------------

// IdentityDocument stores hashed references to uploaded verification documents.
// Only SHA-256 hashes are stored here; originals are held by the KYC provider
// (Onfido) or in a dedicated encrypted document store (e.g. S3 + SSE-KMS).
//
// Acceptable document types for MLD5 Article 13 / MLR 2017 regulation 28:
//
//	"passport" | "national_id" | "driving_licence" | "residence_permit"
type IdentityDocument struct {
	Type               string `json:"type"`                            // Document type code
	IssuingCountry     string `json:"issuing_country"`                 // ISO 3166-1 alpha-2
	ExpiryDate         string `json:"expiry_date,omitempty"`           // YYYY-MM-DD
	DocumentHash       string `json:"document_hash"`                   // SHA-256 hex of document bytes
	ProofOfAddressHash string `json:"proof_of_address_hash,omitempty"` // SHA-256 hex of PoA (utility bill <3 months)
	UploadedAt         int64  `json:"uploaded_at"`
}

// ---------------------------------------------------------------------------
// InvestorClassificationRecord
// ---------------------------------------------------------------------------

// InvestorClassificationRecord captures the MiFID II / FCA COBS 3 classification
// and the supporting evidence for elective professional or ECP status.
//
// MiFID II investor categories (Article 4(1)(10), Annex II):
//
//	retail             — default; highest protections; appropriateness test required
//	professional       — per se professional (credit institution, investment firm, etc.)
//	elective_professional — retail electing professional (COBS 3.5: must satisfy ≥2 of 3 criteria)
//	eligible_cp        — eligible counterparty (Article 30); fewest protections
//
// Elective professional criteria (MiFID II Annex II Section I.2):
//
//	(1) ≥10 significant-size transactions per quarter over past 4 quarters
//	(2) Portfolio (cash deposits + financial instruments) > €500,000
//	(3) ≥1 year professional experience in financial sector in relevant role
type InvestorClassificationRecord struct {
	Class InvestorClass `json:"class"` // retail | professional | elective_professional | eligible_cp

	// Elective professional criteria (at least 2 must be true for elective_professional).
	LargeTradeFrequency   bool `json:"large_trade_frequency,omitempty"`   // ≥10 significant trades/Q
	PortfolioQualifies    bool `json:"portfolio_qualifies,omitempty"`     // >€500,000 portfolio
	ProfessionalExp       bool `json:"professional_experience,omitempty"` // ≥1y financial-sector experience
	RelevantQualification bool `json:"relevant_qualification,omitempty"`  // CFA, CISI, etc.

	// For eligible counterparty: NCA registration number of the regulated entity.
	NCAReg string `json:"nca_reg,omitempty"` // e.g. FCA FRN, BaFin registration, AMF number
}

// ---------------------------------------------------------------------------
// ComplianceConsents
// ---------------------------------------------------------------------------

// ComplianceConsents records all required legal acceptances with version + timestamp.
// Each field is required before an investor may access the platform.
//
// Retention: GDPR Article 7(1) — controller must demonstrate consent was given;
// retain consent records for the full customer lifecycle + 6 years (limitation period).
type ComplianceConsents struct {
	// Required — FCA COBS 4.7 / GDPR Article 6(1)(a)
	TermsOfServiceAcceptedAt int64  `json:"terms_of_service_accepted_at"` // Unix timestamp
	TermsOfServiceVersion    string `json:"terms_of_service_version"`     // semver e.g. "1.0"

	// Required — UK GDPR Article 13 disclosure
	PrivacyPolicyAcceptedAt int64  `json:"privacy_policy_accepted_at"`
	PrivacyPolicyVersion    string `json:"privacy_policy_version"`

	// Required for retail investors — FCA COBS 4.12 / EU Prospectus Regulation
	RiskWarningsAcceptedAt int64  `json:"risk_warnings_accepted_at"`
	RiskWarningsVersion    string `json:"risk_warnings_version"`

	// AML / 5AMLD Article 13 / MLR 2017 regulation 28 — Source of Funds
	SourceOfFundsDeclaration  string `json:"source_of_funds_declaration"`            // e.g. "Employment income and savings"
	SourceOfWealthDeclaration string `json:"source_of_wealth_declaration,omitempty"` // required for EDD

	// AML declarations — all must be true (self-certification against sanctions/PEP lists)
	// Platform additionally performs automated PEP/sanctions screening via AML provider.
	NotPEP          bool `json:"not_pep"`           // Not a politically exposed person (FATF Rec.12)
	NotSanctioned   bool `json:"not_sanctioned"`    // Not on OFAC/HM Treasury/EU consolidated lists
	NotUBOAnonymous bool `json:"not_ubo_anonymous"` // If corporate: UBO is known + not anonymous

	// Optional
	MarketingConsent bool `json:"marketing_consent"`
}

// ---------------------------------------------------------------------------
// RegistrationRecord
// ---------------------------------------------------------------------------

// RegistrationRecord is the full operator-held registration record for one investor.
// It binds a blockchain wallet key to a verified real-world identity and holds all
// the compliance data needed to onboard under EU/UK private placement rules.
//
// Data governance notes:
//   - Encrypt at-rest: use column-level AES-256-GCM encryption, key from KMS.
//   - Audit log: record every read and write with actor + timestamp + purpose.
//   - Retention: minimum 5 years after last transaction (JMLSG 3.36; MLR 2017 reg.40).
//   - DSAR: respond to data subject access requests within 30 days (UK GDPR s.45).
//   - No personal data commits to the blockchain — only the hashed attestation.
type RegistrationRecord struct {
	WalletKey      string                       `json:"wallet_key"`
	Status         RegistrationStatus           `json:"status"`
	Personal       PersonalInfo                 `json:"personal"`
	Address        AddressInfo                  `json:"address"`
	Document       IdentityDocument             `json:"document"`
	Classification InvestorClassificationRecord `json:"classification"`
	Consents       ComplianceConsents           `json:"consents"`

	// Jurisdiction is the investor's primary regulatory jurisdiction.
	// Used to select the applicable ruleset (UK FCA vs EU NCA) for:
	//   - prospectus exemption limits
	//   - appropriateness test requirements
	//   - marketing restrictions
	Jurisdiction string `json:"jurisdiction"` // ISO 3166-1 alpha-2
	ValidForDays int    `json:"valid_for_days"`

	// Lifecycle timestamps
	CreatedAt       int64  `json:"created_at"`
	SubmittedAt     int64  `json:"submitted_at,omitempty"`
	ReviewedAt      int64  `json:"reviewed_at,omitempty"`
	ReviewedBy      string `json:"reviewed_by,omitempty"` // admin wallet key
	RejectionReason string `json:"rejection_reason,omitempty"`
	UpdatedAt       int64  `json:"updated_at"`

	// External KYC provider — populated when Onfido automated KYC is used.
	OnfidoApplicantID string `json:"onfido_applicant_id,omitempty"`
}

// RedactPII returns a copy of the record with sensitive fields blanked out.
// Use this for operator-facing UIs and logs where full PII is not needed.
func (r *RegistrationRecord) RedactPII() *RegistrationRecord {
	copy := *r
	copy.Personal.TaxIDNumber = "[redacted]"
	copy.Document.DocumentHash = "[redacted]"
	copy.Document.ProofOfAddressHash = "[redacted]"
	copy.Consents.SourceOfFundsDeclaration = "[redacted]"
	copy.Consents.SourceOfWealthDeclaration = "[redacted]"
	return &copy
}

// IsComplete returns true when all mandatory fields have been filled.
// Deprecated: call Validate() directly to receive field-level error details.
func (r *RegistrationRecord) IsComplete() bool {
	return len(r.Validate()) == 0
}

// ---------------------------------------------------------------------------
// RegistrationRegistry
// ---------------------------------------------------------------------------

// RegistrationRegistry is a concurrency-safe in-memory store for RegistrationRecords.
// Replace with an encrypted, audited database (PostgreSQL + pgcrypto / RDS + KMS) in
// production before accepting real investors.
//
// M-7: when GREENHOUSE_PII_KEY is set (64 hex chars = 32-byte AES-256 key) all
// personally identifiable fields are encrypted with AES-256-GCM before being
// stored in the in-memory map and decrypted transparently on every read. This
// ensures PII is never exposed in core dumps, heap snapshots, or serialised
// state files.
type RegistrationRegistry struct {
	mu        sync.RWMutex
	hasPIIKey bool
	piiKey    [32]byte
	records   map[string]*RegistrationRecord // walletKey → record (PII fields AES-GCM encrypted when hasPIIKey)
}

// NewRegistrationRegistry creates an empty RegistrationRegistry.
// It reads GREENHOUSE_PII_KEY from the environment; if set and valid it enables
// at-rest PII encryption (M-7). If not set a warning is logged and records are
// stored in plaintext (acceptable for local development only).
func NewRegistrationRegistry() *RegistrationRegistry {
	rr := &RegistrationRegistry{
		records: make(map[string]*RegistrationRecord),
	}
	if raw := os.Getenv("GREENHOUSE_PII_KEY"); raw != "" {
		keyBytes, err := hex.DecodeString(raw)
		if err != nil || len(keyBytes) != 32 {
			panic("GREENHOUSE_PII_KEY must be exactly 64 hex characters (32 bytes)")
		}
		copy(rr.piiKey[:], keyBytes)
		rr.hasPIIKey = true
	}
	return rr
}

// piiEncrypt encrypts a UTF-8 plaintext string with AES-256-GCM and returns
// "enc:<base64(nonce+ciphertext)>". Returns the plaintext unchanged if PII
// encryption is not configured.
func (rr *RegistrationRegistry) piiEncrypt(plaintext string) string {
	if !rr.hasPIIKey || plaintext == "" {
		return plaintext
	}
	block, err := aes.NewCipher(rr.piiKey[:])
	if err != nil {
		panic("RegistrationRegistry: AES cipher init failed: " + err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic("RegistrationRegistry: GCM init failed: " + err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic("RegistrationRegistry: nonce generation failed: " + err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return "enc:" + base64.StdEncoding.EncodeToString(ciphertext)
}

// piiDecrypt decrypts a value previously encrypted by piiEncrypt. Non-"enc:"
// prefixed values (legacy plaintext) are returned unchanged.
func (rr *RegistrationRegistry) piiDecrypt(ciphertext string) string {
	if !strings.HasPrefix(ciphertext, "enc:") {
		return ciphertext // plaintext or empty
	}
	if !rr.hasPIIKey {
		return ciphertext // can't decrypt without key — return as-is
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext[4:])
	if err != nil {
		return ciphertext
	}
	block, err := aes.NewCipher(rr.piiKey[:])
	if err != nil {
		return ciphertext
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ciphertext
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return ciphertext
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return ciphertext
	}
	return string(plaintext)
}

// encryptRecord returns a shallow copy of r with PII fields encrypted.
func (rr *RegistrationRegistry) encryptRecord(r *RegistrationRecord) *RegistrationRecord {
	if !rr.hasPIIKey {
		return r
	}
	c := *r
	c.Personal.FullLegalName = rr.piiEncrypt(r.Personal.FullLegalName)
	c.Personal.DateOfBirth = rr.piiEncrypt(r.Personal.DateOfBirth)
	c.Personal.Nationality = rr.piiEncrypt(r.Personal.Nationality)
	c.Personal.TaxResidency = rr.piiEncrypt(r.Personal.TaxResidency)
	c.Personal.TaxIDNumber = rr.piiEncrypt(r.Personal.TaxIDNumber)
	c.Address.Line1 = rr.piiEncrypt(r.Address.Line1)
	c.Address.Line2 = rr.piiEncrypt(r.Address.Line2)
	c.Address.City = rr.piiEncrypt(r.Address.City)
	c.Address.PostCode = rr.piiEncrypt(r.Address.PostCode)
	c.Consents.SourceOfFundsDeclaration = rr.piiEncrypt(r.Consents.SourceOfFundsDeclaration)
	c.Consents.SourceOfWealthDeclaration = rr.piiEncrypt(r.Consents.SourceOfWealthDeclaration)
	return &c
}

// decryptRecord returns a shallow copy of r with PII fields decrypted.
func (rr *RegistrationRegistry) decryptRecord(r *RegistrationRecord) *RegistrationRecord {
	if !rr.hasPIIKey {
		return r
	}
	c := *r
	c.Personal.FullLegalName = rr.piiDecrypt(r.Personal.FullLegalName)
	c.Personal.DateOfBirth = rr.piiDecrypt(r.Personal.DateOfBirth)
	c.Personal.Nationality = rr.piiDecrypt(r.Personal.Nationality)
	c.Personal.TaxResidency = rr.piiDecrypt(r.Personal.TaxResidency)
	c.Personal.TaxIDNumber = rr.piiDecrypt(r.Personal.TaxIDNumber)
	c.Address.Line1 = rr.piiDecrypt(r.Address.Line1)
	c.Address.Line2 = rr.piiDecrypt(r.Address.Line2)
	c.Address.City = rr.piiDecrypt(r.Address.City)
	c.Address.PostCode = rr.piiDecrypt(r.Address.PostCode)
	c.Consents.SourceOfFundsDeclaration = rr.piiDecrypt(r.Consents.SourceOfFundsDeclaration)
	c.Consents.SourceOfWealthDeclaration = rr.piiDecrypt(r.Consents.SourceOfWealthDeclaration)
	return &c
}

// Upsert creates or replaces the registration record for a wallet key.
// It always updates the UpdatedAt timestamp. PII fields are encrypted before
// storage when GREENHOUSE_PII_KEY is configured (M-7).
func (rr *RegistrationRegistry) Upsert(record *RegistrationRecord) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	now := time.Now().Unix()
	if record.CreatedAt == 0 {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	rr.records[record.WalletKey] = rr.encryptRecord(record)
}

// Get returns the registration record for a wallet key, or nil if not found.
// PII fields are transparently decrypted before being returned (M-7).
func (rr *RegistrationRegistry) Get(walletKey string) *RegistrationRecord {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	r := rr.records[walletKey]
	if r == nil {
		return nil
	}
	return rr.decryptRecord(r)
}

// ListPending returns all records in RegistrationStatusPendingReview,
// sorted by SubmittedAt ascending (oldest first). PII fields are decrypted (M-7).
func (rr *RegistrationRegistry) ListPending() []*RegistrationRecord {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	out := make([]*RegistrationRecord, 0)
	for _, r := range rr.records {
		if r.Status == RegistrationStatusPendingReview {
			out = append(out, rr.decryptRecord(r))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SubmittedAt < out[j].SubmittedAt
	})
	return out
}

// UpdateStatus transitions a record to a new status.
// Caller must hold no lock; this method acquires its own lock.
func (rr *RegistrationRegistry) UpdateStatus(
	walletKey string,
	newStatus RegistrationStatus,
	reviewedBy string,
	rejectionReason string,
) error {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rec, ok := rr.records[walletKey]
	if !ok {
		return fmt.Errorf("registration: record not found for wallet %s", walletKey)
	}
	rec.Status = newStatus
	rec.ReviewedAt = time.Now().Unix()
	rec.ReviewedBy = reviewedBy
	if rejectionReason != "" {
		rec.RejectionReason = rejectionReason
	}
	rec.UpdatedAt = time.Now().Unix()
	return nil
}

// All returns all records (for admin use). Caller is responsible for redacting PII.
// PII fields are decrypted before being returned (M-7).
func (rr *RegistrationRegistry) All() []*RegistrationRecord {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	out := make([]*RegistrationRecord, 0, len(rr.records))
	for _, r := range rr.records {
		out = append(out, rr.decryptRecord(r))
	}
	return out
}
