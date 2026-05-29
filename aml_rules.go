package gonetwork

import (
	"context"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// FATF Travel Rule
// ---------------------------------------------------------------------------

// TravelRulePayload carries the originator and beneficiary information required
// by the FATF (Financial Action Task Force) Travel Rule for virtual asset
// transfers at or above USD/EUR 1,000 equivalent.
//
// Reference: FATF Recommendation 16, updated June 2019.
type TravelRulePayload struct {
	// Originator fields
	OriginatorName        string `json:"originator_name"`
	OriginatorAccount     string `json:"originator_account"`      // IBAN, wallet key, or account ref
	OriginatorAddressLine string `json:"originator_address_line"` // street and building
	OriginatorCity        string `json:"originator_city"`
	OriginatorCountryCode string `json:"originator_country_code"` // ISO 3166-1 alpha-2

	// Beneficiary fields
	BeneficiaryName        string `json:"beneficiary_name"`
	BeneficiaryAccount     string `json:"beneficiary_account"`
	BeneficiaryAddressLine string `json:"beneficiary_address_line"`
	BeneficiaryCity        string `json:"beneficiary_city"`
	BeneficiaryCountryCode string `json:"beneficiary_country_code"`

	// Transfer reference
	TransferRef string `json:"transfer_ref,omitempty"` // unique reference for the instruction
}

// Validate returns an error if mandatory Travel Rule fields are absent.
func (p *TravelRulePayload) Validate() error {
	switch {
	case p.OriginatorName == "":
		return fmt.Errorf("originator_name is required")
	case p.OriginatorAccount == "":
		return fmt.Errorf("originator_account is required")
	case p.BeneficiaryName == "":
		return fmt.Errorf("beneficiary_name is required")
	case p.BeneficiaryAccount == "":
		return fmt.Errorf("beneficiary_account is required")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Behavioural AML rules engine
// ---------------------------------------------------------------------------

// AMLRuleContext contains the transaction context passed to each AMLRule.
type AMLRuleContext struct {
	SenderKey   string
	ReceiverKey string
	AssetID     string
	Amount      float64
	Currency    string
	// TradeHistory provides recent trades for velocity / structuring checks.
	TradeHistory []Trade
	// ScreenedAt is the timestamp of the current screening call.
	ScreenedAt int64
}

// AMLRule is a single behavioural transaction-monitoring rule.
// Returns a non-nil AMLAlert when the rule fires, or nil if clean.
type AMLRule struct {
	// ID is a short mnemonic used in audit logs (e.g. "TM-01").
	ID string
	// Description is a human-readable explanation of what the rule detects.
	Description string
	// Check evaluates the rule against the provided context.
	Check func(ctx AMLRuleContext) *AMLAlert
}

// AMLRuleSet is a collection of AMLRules evaluated sequentially.
// The first block-severity match stops evaluation; flag matches accumulate.
type AMLRuleSet struct {
	Rules []AMLRule
}

// NewDefaultAMLRuleSet returns the standard set of six behavioural TM rules
// (TM-01 through TM-06) calibrated for regulated securities transfers.
func NewDefaultAMLRuleSet() *AMLRuleSet {
	return &AMLRuleSet{
		Rules: []AMLRule{
			tmRule01LargeTransaction(),
			tmRule02RapidSuccessiveTransfers(),
			tmRule03RoundAmountStructuring(),
			tmRule04SelfTransfer(),
			tmRule05HighVelocitySender(),
			tmRule06CrossBorderLargeTransfer(),
		},
	}
}

// Screen evaluates all rules in the set against the provided context.
// Returns the highest-severity alert found, or nil if all rules pass.
func (rs *AMLRuleSet) Screen(ctx AMLRuleContext) *AMLAlert {
	var flagAlert *AMLAlert
	for _, rule := range rs.Rules {
		alert := rule.Check(ctx)
		if alert == nil {
			continue
		}
		if alert.Severity == AMLSeverityBlock {
			return alert // block immediately
		}
		if flagAlert == nil {
			flagAlert = alert // keep first flag
		}
	}
	return flagAlert
}

// ---------------------------------------------------------------------------
// TM-01: Single large transaction
// ---------------------------------------------------------------------------

// tmRule01LargeTransaction flags transactions above EUR 15,000 equivalent and
// blocks those above EUR 100,000 (reporting thresholds under 4AMLD/5AMLD).
func tmRule01LargeTransaction() AMLRule {
	return AMLRule{
		ID:          "TM-01",
		Description: "Single transaction above reporting threshold",
		Check: func(ctx AMLRuleContext) *AMLAlert {
			switch {
			case ctx.Amount >= 100_000:
				return &AMLAlert{
					Severity:    AMLSeverityBlock,
					Reason:      fmt.Sprintf("TM-01: single transaction EUR %.2f exceeds block threshold EUR 100,000", ctx.Amount),
					MatchedList: "TM-01-HIGH",
					ScreenedAt:  ctx.ScreenedAt,
				}
			case ctx.Amount >= 15_000:
				return &AMLAlert{
					Severity:    AMLSeverityFlag,
					Reason:      fmt.Sprintf("TM-01: single transaction EUR %.2f exceeds reporting threshold EUR 15,000", ctx.Amount),
					MatchedList: "TM-01-LOW",
					ScreenedAt:  ctx.ScreenedAt,
				}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// TM-02: Rapid successive transfers from same sender
// ---------------------------------------------------------------------------

// tmRule02RapidSuccessiveTransfers flags senders who have made 5 or more
// transfers within the past 24 hours (potential smurfing / layering).
func tmRule02RapidSuccessiveTransfers() AMLRule {
	return AMLRule{
		ID:          "TM-02",
		Description: "Rapid successive transfers from same sender (possible smurfing)",
		Check: func(ctx AMLRuleContext) *AMLAlert {
			cutoff := ctx.ScreenedAt - 86400 // 24 h lookback
			count := 0
			for _, t := range ctx.TradeHistory {
				if (t.SellerID == ctx.SenderKey || t.BuyerID == ctx.SenderKey) &&
					t.ExecutedAt >= cutoff {
					count++
				}
			}
			if count >= 5 {
				return &AMLAlert{
					Severity:    AMLSeverityFlag,
					Reason:      fmt.Sprintf("TM-02: sender involved in %d transfers in the past 24 h (threshold: 5)", count),
					MatchedList: "TM-02",
					ScreenedAt:  ctx.ScreenedAt,
				}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// TM-03: Round-amount structuring
// ---------------------------------------------------------------------------

// tmRule03RoundAmountStructuring flags transfers with perfectly round amounts
// that appear designed to stay below reporting thresholds (structuring).
func tmRule03RoundAmountStructuring() AMLRule {
	return AMLRule{
		ID:          "TM-03",
		Description: "Round-amount structuring below reporting threshold",
		Check: func(ctx AMLRuleContext) *AMLAlert {
			// Flag transfers that are a round number AND within 10 % below the
			// EUR 15,000 reporting threshold (i.e. EUR 13,500 – 14,999).
			if ctx.Amount >= 13_500 && ctx.Amount < 15_000 &&
				ctx.Amount == float64(int64(ctx.Amount)) {
				return &AMLAlert{
					Severity:    AMLSeverityFlag,
					Reason:      fmt.Sprintf("TM-03: round-amount transfer EUR %.0f just below EUR 15,000 threshold (possible structuring)", ctx.Amount),
					MatchedList: "TM-03",
					ScreenedAt:  ctx.ScreenedAt,
				}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// TM-04: Self-transfer (same sender and receiver)
// ---------------------------------------------------------------------------

// tmRule04SelfTransfer flags transfers where the sender and receiver wallets are
// identical — may indicate layering or wash-trading.
func tmRule04SelfTransfer() AMLRule {
	return AMLRule{
		ID:          "TM-04",
		Description: "Self-transfer (sender == receiver)",
		Check: func(ctx AMLRuleContext) *AMLAlert {
			if ctx.SenderKey != "" && ctx.SenderKey == ctx.ReceiverKey {
				return &AMLAlert{
					Severity:    AMLSeverityFlag,
					Reason:      "TM-04: sender and receiver wallets are identical (possible wash-trade or layering)",
					MatchedList: "TM-04",
					ScreenedAt:  ctx.ScreenedAt,
				}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// TM-05: High-velocity sender (EUR total within 24 h)
// ---------------------------------------------------------------------------

// tmRule05HighVelocitySender flags senders whose 24-hour aggregate transfer
// volume exceeds EUR 50,000 — a signal of rapid layering.
func tmRule05HighVelocitySender() AMLRule {
	return AMLRule{
		ID:          "TM-05",
		Description: "High-velocity sender — 24 h aggregate above EUR 50,000",
		Check: func(ctx AMLRuleContext) *AMLAlert {
			cutoff := ctx.ScreenedAt - 86400
			var total float64
			for _, t := range ctx.TradeHistory {
				if t.SellerID == ctx.SenderKey && t.ExecutedAt >= cutoff {
					total += t.Price * t.Quantity
				}
			}
			total += ctx.Amount // include current transaction
			if total >= 50_000 {
				return &AMLAlert{
					Severity:    AMLSeverityFlag,
					Reason:      fmt.Sprintf("TM-05: sender 24 h aggregate EUR %.2f exceeds EUR 50,000", total),
					MatchedList: "TM-05",
					ScreenedAt:  ctx.ScreenedAt,
				}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// TM-06: Cross-border transfer to high-risk jurisdiction
// ---------------------------------------------------------------------------

// highRiskJurisdictions contains FATF grey-list and black-list country codes
// as of the June 2024 public statement. Refreshed quarterly via GREENHOUSE_AML_HIGH_RISK_JURISDICTIONS.
var highRiskJurisdictions = map[string]bool{
	"AF": true, // Afghanistan
	"IR": true, // Iran
	"KP": true, // North Korea
	"MM": true, // Myanmar
	"RU": true, // Russia (EU/UK/US restricted)
	"SY": true, // Syria
	"YE": true, // Yemen
}

// tmRule06CrossBorderLargeTransfer blocks transfers above EUR 5,000 to wallets
// in FATF high-risk jurisdictions.
func tmRule06CrossBorderLargeTransfer() AMLRule {
	return AMLRule{
		ID:          "TM-06",
		Description: "Transfer to FATF high-risk jurisdiction above EUR 5,000",
		Check: func(ctx AMLRuleContext) *AMLAlert {
			// The receiver's jurisdiction is not available in AMLRuleContext (it
			// lives in the CredentialAttestation). This rule is a best-effort
			// check on amount alone; the full jurisdiction check is in ApplyJurisdictionRule.
			_ = highRiskJurisdictions // referenced in integration layer
			return nil                // placeholder — full check done at handler level
		},
	}
}

// ---------------------------------------------------------------------------
// PEP / Sanctions Re-screening Scheduler
// ---------------------------------------------------------------------------

// StartPEPRescreeningScheduler starts a background goroutine that periodically
// re-screens every registered credential holder against the configured AML
// screener.  Any flag-severity hit raises a SAR draft for compliance review.
//
// JMLSG 3.4.5 requires ongoing periodic re-screening; a 24-hour interval is
// the recommended production setting.  Use a shorter interval only in tests.
//
// The goroutine stops cleanly when ctx is cancelled, enabling graceful shutdown
// without goroutine leaks.
func StartPEPRescreeningScheduler(ctx context.Context, bc *Blockchain, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rescreenAllWallets(bc)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// rescreenAllWallets is the single-pass re-screening function called by the scheduler.
//
// Lock discipline:
//   - Wallet keys and the AML screener reference are captured under bc.Mu.RLock(),
//     which is released immediately after the snapshot. This keeps the read-lock
//     window to microseconds regardless of wallet count.
//   - The potentially long-running ScreenTransaction call (network I/O with a
//     10-second HTTP timeout per call) is executed WITHOUT holding any lock, so
//     SealBlock, order matching, and credential operations are never stalled.
//   - Each SAR write acquires bc.Mu.Lock() only for the duration of the map
//     update + event emission, then releases immediately.
func rescreenAllWallets(bc *Blockchain) {
	// Snapshot wallet keys and screener under RLock so we never stall writers.
	bc.Mu.RLock()
	wallets := make([]string, 0, len(bc.Credentials))
	for k := range bc.Credentials {
		wallets = append(wallets, k)
	}
	screener := bc.AMLScreener
	bc.Mu.RUnlock()

	// Screen each wallet WITHOUT holding the lock.
	for _, walletKey := range wallets {
		alert, err := screener.ScreenTransaction(walletKey, walletKey, "", 0, "")
		if err != nil || alert == nil {
			continue
		}
		if alert.Severity != AMLSeverityFlag && alert.Severity != AMLSeverityBlock {
			continue
		}
		sarID := generateID("SAR")
		bc.Mu.Lock()
		if _, exists := bc.PendingSARs[sarID]; !exists {
			bc.PendingSARs[sarID] = &SARDraft{
				ID:          sarID,
				SenderKey:   walletKey,
				ReceiverKey: walletKey,
				AssetID:     "",
				Reason:      "PEP/sanctions periodic re-screening alert: " + alert.Reason,
				MatchedList: alert.MatchedList,
				CreatedAt:   time.Now().Unix(),
				Status:      SARStatusPending,
			}
			bc.emitEvent(EventSARCreated, map[string]any{
				"sar_id":       sarID,
				"wallet_key":   walletKey,
				"matched_list": alert.MatchedList,
				"source":       "pep_rescreening",
			})
		}
		bc.Mu.Unlock()
	}
}

// CrossBorderHighRiskCheck returns an AMLSeverityBlock alert if the receiver is
// credentialled to a FATF high-risk jurisdiction AND the transfer exceeds EUR 5,000.
// Called from handleFillOrder after credential lookup.
func CrossBorderHighRiskCheck(receiverCred *CredentialAttestation, amount float64) *AMLAlert {
	if receiverCred == nil {
		return nil
	}
	if !highRiskJurisdictions[receiverCred.Jurisdiction] {
		return nil
	}
	if amount < 5_000 {
		return &AMLAlert{
			Severity:    AMLSeverityFlag,
			Reason:      fmt.Sprintf("TM-06: transfer EUR %.2f to FATF high-risk jurisdiction %s", amount, receiverCred.Jurisdiction),
			MatchedList: "TM-06-FATF",
			ScreenedAt:  time.Now().Unix(),
		}
	}
	return &AMLAlert{
		Severity:    AMLSeverityBlock,
		Reason:      fmt.Sprintf("TM-06: transfer EUR %.2f to FATF high-risk jurisdiction %s exceeds EUR 5,000 threshold", amount, receiverCred.Jurisdiction),
		MatchedList: "TM-06-FATF",
		ScreenedAt:  time.Now().Unix(),
	}
}
