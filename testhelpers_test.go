package gonetwork

// ---------------------------------------------------------------------------
// Shared test helpers used across multiple test files.
// ---------------------------------------------------------------------------

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newTestBlockchain returns a fully-initialised Blockchain suitable for unit
// tests.  It uses NewBlockchain so all maps and default settings are populated.
// GONETWORK_NO_P2P=1 suppresses libp2p/mDNS/GossipSub startup so that the
// ~95 test blockchain instances do not each create a real network host
// (which would add >100 s of mDNS teardown overhead for the full suite).
func newTestBlockchain(t *testing.T) *Blockchain {
	t.Helper()
	t.Setenv("GONETWORK_NO_P2P", "1")
	return NewBlockchain(context.Background(), "test-chain")
}

// validRegistrationRecord builds a RegistrationRecord that passes Validate().
// It uses a date of birth 30 years ago to pass the age gate.
func validRegistrationRecord(walletKey string) *RegistrationRecord {
	dob := time.Now().UTC().AddDate(-30, 0, 0).Format("2006-01-02")
	expiry := time.Now().UTC().AddDate(5, 0, 0).Format("2006-01-02")
	soFunds := strings.Repeat("Employment income from software engineering role. ", 2) // >50 chars
	return &RegistrationRecord{
		WalletKey: walletKey,
		Personal: PersonalInfo{
			FullLegalName: "Alice Olivia Smith",
			DateOfBirth:   dob,
			Nationality:   "GB",
			TaxResidency:  "GB",
			TaxIDNumber:   "AB123456C",
		},
		Address: AddressInfo{
			Line1:    "1 City Road",
			City:     "London",
			PostCode: "EC1A 1AA",
			Country:  "GB",
		},
		Document: IdentityDocument{
			Type:               "passport",
			IssuingCountry:     "GB",
			ExpiryDate:         expiry,
			DocumentHash:       strings.Repeat("a", 64),
			ProofOfAddressHash: strings.Repeat("b", 64),
		},
		Consents: ComplianceConsents{
			TermsOfServiceAcceptedAt: time.Now().Unix(),
			TermsOfServiceVersion:    "1.0",
			PrivacyPolicyAcceptedAt:  time.Now().Unix(),
			PrivacyPolicyVersion:     "1.0",
			RiskWarningsAcceptedAt:   time.Now().Unix(),
			RiskWarningsVersion:      "1.0",
			SourceOfFundsDeclaration: soFunds,
			NotPEP:                   true,
			NotSanctioned:            true,
		},
		Jurisdiction: "GB",
		ValidForDays: 365,
	}
}

func newTestPontesProvider(
	t *testing.T,
	store PaymentStore,
) *PontesPaymentProvider {

	t.Helper()

	p, err := NewPontesPaymentProvider(
		"test-api-key",
		"http://pontes.test",
		"GH-DLT",
		"test-secret",
		store,
	)

	require.NoError(t, err)

	return p
}
