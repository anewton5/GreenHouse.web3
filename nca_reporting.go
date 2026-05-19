package gonetwork

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// ---------------------------------------------------------------------------
// NCA Reporting Service
// ---------------------------------------------------------------------------

// NCAReportingService wraps DefaultReportingService and additionally submits
// each generated report to the configured National Competent Authority (NCA) or
// Approved Reporting Mechanism (ARM) endpoint.
//
// Configuration (environment variables):
//
//	GREENHOUSE_NCA_REPORTING_ENDPOINT  — base URL of the NCA/ARM HTTP endpoint
//	GREENHOUSE_ARM_API_KEY             — Bearer token for the NCA/ARM API
//
// When GREENHOUSE_NCA_REPORTING_ENDPOINT is empty the service operates in
// stub mode: reports are generated and stored on-chain but not transmitted.
// This makes it safe to use NCAReportingService in all environments without
// conditional logic in callers.
type NCAReportingService struct {
	inner      *DefaultReportingService
	endpoint   string
	apiKey     string
	httpClient *http.Client
}

// NewNCAReportingService creates an NCAReportingService using env-var configuration.
func NewNCAReportingService() *NCAReportingService {
	return &NCAReportingService{
		inner:    &DefaultReportingService{},
		endpoint: os.Getenv("GREENHOUSE_NCA_REPORTING_ENDPOINT"),
		apiKey:   os.Getenv("GREENHOUSE_ARM_API_KEY"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GenerateReport implements ReportingService.  It generates the report via the
// inner DefaultReportingService and — when an endpoint is configured — submits
// the report to the NCA/ARM over HTTPS.  If submission fails the error is
// logged but the report is still returned so on-chain storage succeeds.
func (s *NCAReportingService) GenerateReport(
	reportType ReportType,
	trade Trade,
	asset *Asset,
	blockIndex int,
) (*RegulatoryReport, error) {
	report, err := s.inner.GenerateReport(reportType, trade, asset, blockIndex)
	if err != nil {
		return nil, err
	}
	if s.endpoint != "" {
		if submitErr := s.submitToNCA(report); submitErr != nil {
			// Non-fatal: log and continue — on-chain record is authoritative.
			fmt.Printf("NCAReportingService: submission warning for report %s: %v\n", report.ID, submitErr)
		}
	}
	return report, nil
}

// submitToNCA POSTs a single RegulatoryReport to the configured NCA/ARM endpoint.
func (s *NCAReportingService) submitToNCA(report *RegulatoryReport) error {
	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, s.endpoint+"/reports", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("NCA endpoint returned %d", resp.StatusCode)
	}
	return nil
}
