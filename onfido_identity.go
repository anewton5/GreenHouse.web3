package gonetwork

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// OnfidoIdentityRegistry
// ---------------------------------------------------------------------------

// OnfidoIdentityRegistry implements IdentityRegistry backed by the Onfido
// identity-verification API. It is the production replacement for
// OperatorIdentityRegistry when automated KYC is required.
//
// Usage:
//  1. Create an applicant via InitiateKYC — this returns an Onfido applicant ID
//     and SDK token the investor portal embeds in the Onfido Web SDK.
//  2. Onfido runs checks and posts a webhook on completion.
//  3. HandleWebhook processes the webhook, verifies the HMAC, and automatically
//     calls IssueCredential for clear checks.
//
// Environment variables:
//
//	ONFIDO_API_TOKEN       — Onfido API live/sandbox key (required)
//	ONFIDO_WEBHOOK_SECRET  — HMAC secret for webhook verification (required in prod)
//
// The registry key is injected at construction time. In production it should be
// loaded from AWS KMS or HashiCorp Vault, not from disk.
type OnfidoIdentityRegistry struct {
	mu          sync.RWMutex
	registryKey *PrivateKey
	registryPub *PublicKey
	credentials map[string]*CredentialAttestation // walletKey → attestation
	applicants  map[string]string                 // walletKey → onfido applicantID
	apiToken    string
	baseURL     string // override for testing; defaults to https://api.eu.onfido.com/v3.6
	httpClient  *http.Client
}

// NewOnfidoIdentityRegistry constructs an OnfidoIdentityRegistry.
// registryKey must not be nil; it is used to sign credentials.
// The Onfido API token is read from the ONFIDO_API_TOKEN environment variable.
func NewOnfidoIdentityRegistry(registryKey *PrivateKey) (*OnfidoIdentityRegistry, error) {
	if registryKey == nil {
		return nil, fmt.Errorf("onfido registry: registry key must not be nil")
	}
	token := os.Getenv("ONFIDO_API_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("onfido registry: ONFIDO_API_TOKEN environment variable is not set")
	}
	return &OnfidoIdentityRegistry{
		registryKey: registryKey,
		registryPub: registryKey.Public(),
		credentials: make(map[string]*CredentialAttestation),
		applicants:  make(map[string]string),
		apiToken:    token,
		baseURL:     "https://api.eu.onfido.com/v3.6",
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// ---------------------------------------------------------------------------
// IdentityRegistry interface implementation
// ---------------------------------------------------------------------------

// IssueCredential creates, signs, and stores an attestation for walletKey.
// In production this should only be called after a successful Onfido check
// (via HandleWebhook). Calling it directly bypasses the Onfido verification
// and should only be done by authorised operators after manual review.
func (o *OnfidoIdentityRegistry) IssueCredential(
	walletKey string,
	class InvestorClass,
	jurisdiction string,
	validForDays int,
) (*CredentialAttestation, error) {
	cred, err := NewIdentityCredential(walletKey, class, jurisdiction, validForDays, o.registryKey)
	if err != nil {
		return nil, err
	}
	attestation := cred.ToAttestation()
	o.mu.Lock()
	o.credentials[walletKey] = attestation
	o.mu.Unlock()
	return attestation, nil
}

// VerifyCredential returns the stored attestation for walletKey.
func (o *OnfidoIdentityRegistry) VerifyCredential(walletKey string) (*CredentialAttestation, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	a, ok := o.credentials[walletKey]
	if !ok {
		return nil, fmt.Errorf("onfido registry: no credential found for wallet %s", walletKey)
	}
	return a, nil
}

// RegistryPublicKey returns the registry's public key for signature verification.
func (o *OnfidoIdentityRegistry) RegistryPublicKey() *PublicKey {
	return o.registryPub
}

// IssueClaim creates and signs a topic-scoped Claim for walletKey, using the
// same registry key that signs CredentialAttestations via IssueCredential.
func (o *OnfidoIdentityRegistry) IssueClaim(walletKey string, topic ClaimTopic, data string, validForDays int) (*Claim, error) {
	return NewClaim(topic, "", walletKey, data, validForDays, o.registryKey)
}

// ---------------------------------------------------------------------------
// Onfido API integration
// ---------------------------------------------------------------------------

// onfidoApplicantRequest is the JSON body for creating an Onfido applicant.
type onfidoApplicantRequest struct {
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	CustomData string `json:"custom_data,omitempty"` // we embed walletKey here
}

type onfidoApplicantResponse struct {
	ID string `json:"id"`
}

type onfidoCheckRequest struct {
	ApplicantID string   `json:"applicant_id"`
	ReportNames []string `json:"report_names"`
	Tags        []string `json:"tags"` // we embed wallet:<key> here
}

type onfidoCheckResponse struct {
	ID string `json:"id"`
}

// InitiateKYC creates an Onfido applicant and starts a document + facial
// similarity check. It returns the Onfido applicant ID which the frontend
// uses to initialise the Onfido Web SDK.
//
// The wallet key is attached as a tag in the format "wallet:<base64key>" so
// HandleWebhook can resolve it back to the investor's wallet on completion.
func (o *OnfidoIdentityRegistry) InitiateKYC(
	ctx context.Context,
	walletKey string,
	firstName string,
	lastName string,
) (applicantID string, err error) {
	if walletKey == "" {
		return "", fmt.Errorf("onfido registry: wallet key must not be empty")
	}

	// 1. Create applicant.
	appBody, err := json.Marshal(onfidoApplicantRequest{
		FirstName:  firstName,
		LastName:   lastName,
		CustomData: walletKey,
	})
	if err != nil {
		return "", fmt.Errorf("onfido registry: marshal applicant: %w", err)
	}
	var appResp onfidoApplicantResponse
	if err := o.onfidoPost(ctx, "/applicants", appBody, &appResp); err != nil {
		return "", fmt.Errorf("onfido registry: create applicant: %w", err)
	}

	// 2. Start check with document + facial similarity reports.
	checkBody, err := json.Marshal(onfidoCheckRequest{
		ApplicantID: appResp.ID,
		ReportNames: []string{"document", "facial_similarity_photo"},
		Tags:        []string{fmt.Sprintf("wallet:%s", walletKey)},
	})
	if err != nil {
		return "", fmt.Errorf("onfido registry: marshal check: %w", err)
	}
	var checkResp onfidoCheckResponse
	if err := o.onfidoPost(ctx, "/checks", checkBody, &checkResp); err != nil {
		return "", fmt.Errorf("onfido registry: create check: %w", err)
	}

	o.mu.Lock()
	o.applicants[walletKey] = appResp.ID
	o.mu.Unlock()

	return appResp.ID, nil
}

// HandleWebhook processes an Onfido webhook notification. It verifies the
// X-SHA2-Signature HMAC, extracts the wallet key from the check tags, and
// automatically issues a credential for clear checks.
//
// The HMAC secret is read from the ONFIDO_WEBHOOK_SECRET environment variable.
// If the variable is not set, signature verification is skipped (dev/test mode).
//
// Returns the issued credential (or nil if the check was not clear), plus any error.
func (o *OnfidoIdentityRegistry) HandleWebhook(
	body []byte,
	providedSig string,
	defaultClass InvestorClass,
	defaultJurisdiction string,
	validForDays int,
) (*CredentialAttestation, error) {
	// Verify HMAC signature.
	// In production (GH_ENV=production) HMAC is mandatory — a missing or
	// incorrect signature returns an error and the webhook is not processed.
	// In non-production environments the check is skipped only when
	// ONFIDO_WEBHOOK_SECRET is empty (dev / test mode).
	secret := os.Getenv("ONFIDO_WEBHOOK_SECRET")
	if os.Getenv("GH_ENV") == "production" || secret != "" {
		if secret == "" {
			return nil, fmt.Errorf("onfido webhook: ONFIDO_WEBHOOK_SECRET not configured — cannot verify signature")
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		expected := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(expected), []byte(providedSig)) {
			return nil, fmt.Errorf("onfido webhook: invalid HMAC signature")
		}
	}

	// Parse Onfido webhook envelope.
	var payload struct {
		Payload struct {
			ResourceType string `json:"resource_type"`
			Action       string `json:"action"`
			Object       struct {
				Status string   `json:"status"`
				Result string   `json:"result"`
				Tags   []string `json:"tags"`
			} `json:"object"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("onfido webhook: parse payload: %w", err)
	}

	// Only act on completed, clear checks.
	if payload.Payload.Action != "check.completed" ||
		payload.Payload.Object.Status != "complete" ||
		payload.Payload.Object.Result != "clear" {
		return nil, nil // acknowledged but no action needed
	}

	// Extract wallet key from tags.
	walletKey := ""
	for _, tag := range payload.Payload.Object.Tags {
		if after, found := strings.CutPrefix(tag, "wallet:"); found {
			walletKey = after
			break
		}
	}
	if walletKey == "" {
		return nil, fmt.Errorf("onfido webhook: no wallet tag found in check tags")
	}

	return o.IssueCredential(walletKey, defaultClass, defaultJurisdiction, validForDays)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (o *OnfidoIdentityRegistry) onfidoPost(
	ctx context.Context,
	path string,
	body []byte,
	out any,
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token token="+o.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("onfido API error %d: %s", resp.StatusCode, string(respBody))
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
