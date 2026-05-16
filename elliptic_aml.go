package gonetwork

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// EllipticScreener
// ---------------------------------------------------------------------------

// EllipticScreener implements AMLScreener using the Elliptic Lens API for
// blockchain analytics. It is designed for networks where wallet addresses
// (public keys) can be scored for risk based on on-chain transaction history.
//
// Reference: https://developers.elliptic.co/docs
//
// Configuration:
//
//	screener := gonetwork.NewEllipticScreener(
//	    os.Getenv("ELLIPTIC_API_KEY"),
//	    os.Getenv("ELLIPTIC_API_SECRET"),
//	    "https://aml-api.elliptic.co",
//	)
type EllipticScreener struct {
	apiKey    string
	apiSecret string
	baseURL   string
	client    *http.Client

	mu    sync.Mutex
	cache map[string]*ellipticEntry
}

// ellipticEntry caches a single Elliptic wallet risk result.
type ellipticEntry struct {
	alert     *AMLAlert
	fetchedAt int64
}

const ellipticCacheTTL = 24 * 60 * 60 // 24 hours

// ellipticRiskThresholdBlock is the Elliptic risk score (0-10) above which a
// transfer is blocked.  Scores above 8 indicate a strong sanctions/darknet link.
const ellipticRiskThresholdBlock = 8.0

// ellipticRiskThresholdFlag is the score above which a transfer is flagged for
// compliance review but is permitted to proceed.
const ellipticRiskThresholdFlag = 5.0

// NewEllipticScreener returns an EllipticScreener ready to use.
// apiKey and apiSecret are loaded from environment variables; never hard-code them.
func NewEllipticScreener(apiKey, apiSecret, baseURL string) *EllipticScreener {
	return &EllipticScreener{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		baseURL:   baseURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache: make(map[string]*ellipticEntry),
	}
}

// ScreenTransaction implements AMLScreener. Both sender and receiver are scored.
func (s *EllipticScreener) ScreenTransaction(
	senderKey string,
	receiverKey string,
	_ string, // assetID — not used by Elliptic
	_ float64, // amount — not used by Elliptic
	_ string, // currency — not used by Elliptic
) (*AMLAlert, error) {
	senderAlert, err := s.scoreWallet(senderKey)
	if err != nil {
		return nil, fmt.Errorf("Elliptic sender score failed: %w", err)
	}
	if senderAlert != nil && senderAlert.Severity == AMLSeverityBlock {
		return senderAlert, nil
	}

	receiverAlert, err := s.scoreWallet(receiverKey)
	if err != nil {
		return nil, fmt.Errorf("Elliptic receiver score failed: %w", err)
	}
	if receiverAlert != nil && receiverAlert.Severity == AMLSeverityBlock {
		return receiverAlert, nil
	}

	if senderAlert != nil {
		return senderAlert, nil
	}
	return receiverAlert, nil
}

// scoreWallet returns an AMLAlert based on the Elliptic risk score for walletKey,
// using cached results when available.
func (s *EllipticScreener) scoreWallet(walletKey string) (*AMLAlert, error) {
	s.mu.Lock()
	if entry, ok := s.cache[walletKey]; ok {
		if time.Now().Unix()-entry.fetchedAt < ellipticCacheTTL {
			s.mu.Unlock()
			return entry.alert, nil
		}
	}
	s.mu.Unlock()

	alert, err := s.callAPI(walletKey)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.cache[walletKey] = &ellipticEntry{alert: alert, fetchedAt: time.Now().Unix()}
	s.mu.Unlock()

	return alert, nil
}

// ellipticWalletRiskRequest is the body sent to POST /v2/wallet/synchronous.
type ellipticWalletRiskRequest struct {
	Subject struct {
		Asset string `json:"asset"`
		Type  string `json:"type"`
		Hash  string `json:"hash"`
	} `json:"subject"`
	Type string `json:"type"`
}

// ellipticWalletRiskResponse captures the relevant fields from the Elliptic API.
type ellipticWalletRiskResponse struct {
	RiskScore      float64 `json:"risk_score"` // 0–10; higher is riskier
	RiskReason     string  `json:"risk_reason"`
	BlockchainInfo struct {
		Cluster string `json:"cluster"`
	} `json:"blockchain_info"`
}

// callAPI performs a real HTTP request to the Elliptic Wallet Screening endpoint.
func (s *EllipticScreener) callAPI(walletKey string) (*AMLAlert, error) {
	var reqBody ellipticWalletRiskRequest
	reqBody.Subject.Asset = "holistic" // score all assets
	reqBody.Subject.Type = "address"
	reqBody.Subject.Hash = walletKey
	reqBody.Type = "wallet_exposure"

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Elliptic request: %w", err)
	}

	url := s.baseURL + "/v2/wallet/synchronous"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to build Elliptic request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-access-key", s.apiKey)
	req.Header.Set("x-access-secret", s.apiSecret)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Elliptic API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("Elliptic API: invalid credentials (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Elliptic API: unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read Elliptic response: %w", err)
	}

	var result ellipticWalletRiskResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse Elliptic response: %w", err)
	}

	switch {
	case result.RiskScore >= ellipticRiskThresholdBlock:
		return &AMLAlert{
			Severity:    AMLSeverityBlock,
			Reason:      fmt.Sprintf("Elliptic: wallet risk score %.1f/10 exceeds block threshold (%.1f): %s", result.RiskScore, ellipticRiskThresholdBlock, result.RiskReason),
			MatchedList: "ELLIPTIC-HIGH",
			ScreenedAt:  time.Now().Unix(),
		}, nil
	case result.RiskScore >= ellipticRiskThresholdFlag:
		return &AMLAlert{
			Severity:    AMLSeverityFlag,
			Reason:      fmt.Sprintf("Elliptic: wallet risk score %.1f/10 exceeds flag threshold (%.1f): %s", result.RiskScore, ellipticRiskThresholdFlag, result.RiskReason),
			MatchedList: "ELLIPTIC-MED",
			ScreenedAt:  time.Now().Unix(),
		}, nil
	}
	return nil, nil // clean
}
