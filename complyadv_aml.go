package gonetwork

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// ComplyAdvantageScreener
// ---------------------------------------------------------------------------

// ComplyAdvantageScreener implements AMLScreener by calling the ComplyAdvantage
// "Search" API in real time. Results are cached for 24 hours per wallet key to
// avoid redundant API calls on repeated transfers from the same participant.
//
// Reference: https://docs.complyadvantage.com/api-docs/
//
// Configuration is provided at construction time; secrets must be loaded from
// environment variables — never hard-coded.
//
//	screener := gonetwork.NewComplyAdvantageScreener(
//	    os.Getenv("COMPLYADVANTAGE_API_KEY"),
//	    "https://api.complyadvantage.com",
//	)
type ComplyAdvantageScreener struct {
	apiKey  string
	baseURL string
	client  *http.Client

	mu    sync.Mutex
	cache map[string]*caEntry // walletKey → cached result
}

// caEntry is a single cached ComplyAdvantage result.
type caEntry struct {
	alert     *AMLAlert
	fetchedAt int64
}

const caDefaultCacheTTL = 24 * 60 * 60 // 24 hours in seconds

// NewComplyAdvantageScreener returns a ComplyAdvantageScreener ready to use.
// apiKey must be the ComplyAdvantage API key from the GreenHouse secrets store.
// baseURL should be "https://api.complyadvantage.com" for production.
func NewComplyAdvantageScreener(apiKey, baseURL string) *ComplyAdvantageScreener {
	return &ComplyAdvantageScreener{
		apiKey:  apiKey,
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache: make(map[string]*caEntry),
	}
}

// ScreenTransaction implements AMLScreener. It searches both sender and receiver
// keys against the ComplyAdvantage entity database.  Results are cached for 24 h.
func (s *ComplyAdvantageScreener) ScreenTransaction(
	senderKey string,
	receiverKey string,
	assetID string,
	amount float64,
	currency string,
) (*AMLAlert, error) {
	// Screen sender.
	senderAlert, err := s.screenEntity(senderKey)
	if err != nil {
		return nil, fmt.Errorf("ComplyAdvantage sender screen failed: %w", err)
	}
	if senderAlert != nil && senderAlert.Severity == AMLSeverityBlock {
		return senderAlert, nil
	}

	// Screen receiver.
	receiverAlert, err := s.screenEntity(receiverKey)
	if err != nil {
		return nil, fmt.Errorf("ComplyAdvantage receiver screen failed: %w", err)
	}
	if receiverAlert != nil && receiverAlert.Severity == AMLSeverityBlock {
		return receiverAlert, nil
	}

	// Return any flag-severity hit.
	if senderAlert != nil {
		return senderAlert, nil
	}
	return receiverAlert, nil
}

// screenEntity searches a single wallet key against ComplyAdvantage.
// Results are cached per-key for caDefaultCacheTTL seconds.
func (s *ComplyAdvantageScreener) screenEntity(walletKey string) (*AMLAlert, error) {
	s.mu.Lock()
	if entry, ok := s.cache[walletKey]; ok {
		if time.Now().Unix()-entry.fetchedAt < caDefaultCacheTTL {
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
	s.cache[walletKey] = &caEntry{alert: alert, fetchedAt: time.Now().Unix()}
	s.mu.Unlock()

	return alert, nil
}

// complyAdvantageSearchRequest is the JSON body sent to /v2/searches.
type complyAdvantageSearchRequest struct {
	SearchTerm string   `json:"search_term"`
	Fuzziness  float64  `json:"fuzziness"`
	Filters    caFilter `json:"filters"`
}

type caFilter struct {
	Types []string `json:"types"` // e.g. ["sanction","warning","pep"]
}

// complyAdvantageSearchResponse captures the relevant subset of the API response.
type complyAdvantageSearchResponse struct {
	Content struct {
		Data struct {
			Hits []struct {
				Score float64 `json:"doc_score"`
				Doc   struct {
					Types []string `json:"types"`
					Name  string   `json:"name"`
				} `json:"doc"`
			} `json:"hits"`
		} `json:"data"`
	} `json:"content"`
}

// callAPI performs a real HTTP call to the ComplyAdvantage Search API,
// retrying transient failures (network errors, 5xx responses) with bounded
// exponential backoff via the shared retryHTTP helper (up to 3 attempts,
// ~30s overall cap).
func (s *ComplyAdvantageScreener) callAPI(walletKey string) (*AMLAlert, error) {
	reqBody := complyAdvantageSearchRequest{
		SearchTerm: walletKey,
		Fuzziness:  0.6,
		Filters: caFilter{
			Types: []string{"sanction", "warning", "pep", "adverse-media"},
		},
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ComplyAdvantage request: %w", err)
	}

	url := s.baseURL + "/v2/searches"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := retryHTTP(ctx, retryConfig{maxAttempts: 3, safeToRetry: true}, func(ctx context.Context) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Token "+s.apiKey)
		return s.client.Do(req)
	})
	if err != nil {
		return nil, fmt.Errorf("ComplyAdvantage API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("ComplyAdvantage API: invalid API key")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("ComplyAdvantage API: unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read ComplyAdvantage response: %w", err)
	}

	var result complyAdvantageSearchResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse ComplyAdvantage response: %w", err)
	}

	for _, hit := range result.Content.Data.Hits {
		if hit.Score < 0.9 {
			continue // low-confidence match — ignore
		}
		for _, t := range hit.Doc.Types {
			switch t {
			case "sanction":
				return &AMLAlert{
					Severity:    AMLSeverityBlock,
					Reason:      fmt.Sprintf("ComplyAdvantage: entity %q matched sanctions list", hit.Doc.Name),
					MatchedList: "CA-SANCTION",
					ScreenedAt:  time.Now().Unix(),
				}, nil
			case "pep":
				return &AMLAlert{
					Severity:    AMLSeverityFlag,
					Reason:      fmt.Sprintf("ComplyAdvantage: entity %q identified as PEP", hit.Doc.Name),
					MatchedList: "CA-PEP",
					ScreenedAt:  time.Now().Unix(),
				}, nil
			case "warning":
				return &AMLAlert{
					Severity:    AMLSeverityFlag,
					Reason:      fmt.Sprintf("ComplyAdvantage: entity %q matched warning list", hit.Doc.Name),
					MatchedList: "CA-WARNING",
					ScreenedAt:  time.Now().Unix(),
				}, nil
			}
		}
	}

	return nil, nil // clean
}
