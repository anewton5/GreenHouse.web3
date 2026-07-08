package api

// dev.go — Development-only endpoints for the GreenHouse dev dashboard.
//
// These endpoints expose raw blockchain state and an unauthenticated WebSocket
// stream to make it easy to observe the platform during local development.
//
// Security: all handlers call isDevMode() first and return 403 when any
// GREENHOUSE_ADMIN_WALLET_KEYS are configured, ensuring these endpoints are
// unreachable in production.
//
//   GET /v1/dev/state  — full blockchain state snapshot (JSON)
//   GET /v1/dev/stream — unauthenticated WebSocket event feed

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"gonetwork"
)

// isDevMode reports whether the server is running without configured admin
// wallet keys, which is the signal for "local development" mode.
// Dev endpoints are blocked whenever admin keys are set.
func (s *Server) isDevMode() bool {
	return len(s.adminWalletKeys) == 0
}

// ---------------------------------------------------------------------------
// GET /v1/dev/state
// ---------------------------------------------------------------------------

type devBlockSummary struct {
	Index             int    `json:"index"`
	Hash              string `json:"hash"`
	PrevHash          string `json:"prev_hash"`
	TxCount           int    `json:"tx_count"`
	AssetTxCount      int    `json:"asset_tx_count"`
	OrderTxCount      int    `json:"order_tx_count"`
	CredentialTxCount int    `json:"credential_tx_count"`
}

// handleDevState returns a comprehensive snapshot of the current blockchain
// state without authentication.
// GET /v1/dev/state
//
// Each dashboard section is built by a dedicated snapshot function so this
// handler stays a thin assembler; see devBlockSummaries, devAssetSnapshot,
// etc. below.
func (s *Server) handleDevState(w http.ResponseWriter, r *http.Request) {
	if !s.isDevMode() {
		writeError(w, http.StatusForbidden, "dev endpoints are disabled when admin keys are configured")
		return
	}

	orderBookSnapshot, openBids, openAsks := devOrderBookSnapshot(s.bc)
	amendmentList, totalAmendments := devAmendmentSnapshot(s.bc)
	recentReports, totalReports := devRecentReports(s.bc)
	pendingSARs := devPendingSARSnapshot(s.bc)

	writeJSON(w, http.StatusOK, map[string]any{
		"timestamp":                 time.Now().UTC().Unix(),
		"block_count":               len(s.bc.Blocks),
		"blocks":                    devBlockSummaries(s.bc),
		"asset_count":               len(s.bc.Assets),
		"assets":                    devAssetSnapshot(s.bc),
		"trade_count":               len(s.bc.Trades),
		"trades":                    s.bc.Trades,
		"open_bid_count":            openBids,
		"open_ask_count":            openAsks,
		"order_books":               orderBookSnapshot,
		"credential_count":          len(s.bc.Credentials),
		"credentials":               devCredentialSnapshot(s.bc),
		"deal_count":                len(s.bc.Deals),
		"deals":                     devDealSnapshot(s.bc),
		"corporate_actions":         devCorporateActionSnapshot(s.bc),
		"liquidity_windows":         devLiquidityWindowSnapshot(s.bc),
		"pending_payments":          devPendingPaymentSnapshot(s.bc),
		"spvs":                      devSPVSnapshot(s.bc),
		"pending_countersign_count": devPendingCountersignCount(s.bc),
		"amendment_count":           totalAmendments,
		"amendments":                amendmentList,
		// Part II compliance
		"pending_sar_count":       len(pendingSARs),
		"pending_sars":            pendingSARs,
		"regulatory_report_count": totalReports,
		"regulatory_reports":      recentReports,
		"jurisdiction_rules":      devJurisdictionSnapshot(s.bc),
	})
}

// devBlockSummaries builds the lightweight per-block summary list.
func devBlockSummaries(bc *gonetwork.Blockchain) []devBlockSummary {
	blocks := make([]devBlockSummary, 0, len(bc.Blocks))
	for i, b := range bc.Blocks {
		blocks = append(blocks, devBlockSummary{
			Index:             i,
			Hash:              b.CalculateHash(),
			PrevHash:          b.PrevHash,
			TxCount:           len(b.Transactions),
			AssetTxCount:      len(b.AssetTransactions),
			OrderTxCount:      len(b.OrderTransactions),
			CredentialTxCount: len(b.CredentialTransactions),
		})
	}
	return blocks
}

// devAssetSnapshot returns every registered asset.
func devAssetSnapshot(bc *gonetwork.Blockchain) []any {
	assets := make([]any, 0, len(bc.Assets))
	for _, a := range bc.Assets {
		assets = append(assets, a)
	}
	return assets
}

// devOrderBookSnapshot returns a per-asset order book summary along with the
// total count of open bids/asks across all order books.
func devOrderBookSnapshot(bc *gonetwork.Blockchain) (snapshot []any, openBids int, openAsks int) {
	snapshot = make([]any, 0, len(bc.OrderBooks))
	for assetID, ob := range bc.OrderBooks {
		bidCount, askCount := 0, 0
		for _, o := range ob.Bids {
			if string(o.Status) == "open" {
				bidCount++
				openBids++
			}
		}
		for _, o := range ob.Asks {
			if string(o.Status) == "open" {
				askCount++
				openAsks++
			}
		}
		snapshot = append(snapshot, map[string]any{
			"asset_id":  assetID,
			"bid_count": bidCount,
			"ask_count": askCount,
			"bids":      ob.Bids,
			"asks":      ob.Asks,
		})
	}
	return snapshot, openBids, openAsks
}

// devCredentialSnapshot returns every issued KYC credential.
func devCredentialSnapshot(bc *gonetwork.Blockchain) []any {
	credentials := make([]any, 0, len(bc.Credentials))
	for _, c := range bc.Credentials {
		credentials = append(credentials, c)
	}
	return credentials
}

// devDealSnapshot returns every registered deal.
func devDealSnapshot(bc *gonetwork.Blockchain) []any {
	deals := make([]any, 0, len(bc.Deals))
	for _, d := range bc.Deals {
		deals = append(deals, d)
	}
	return deals
}

// devCorporateActionSnapshot returns every pending corporate action.
func devCorporateActionSnapshot(bc *gonetwork.Blockchain) []any {
	corpActions := make([]any, 0, len(bc.PendingCorporateActions))
	for _, ca := range bc.PendingCorporateActions {
		corpActions = append(corpActions, ca)
	}
	return corpActions
}

// devLiquidityWindowSnapshot returns every scheduled/open/closed liquidity window.
func devLiquidityWindowSnapshot(bc *gonetwork.Blockchain) []any {
	liquidityWindows := make([]any, 0)
	if bc.WindowManager != nil {
		for _, win := range bc.WindowManager.Windows {
			liquidityWindows = append(liquidityWindows, win)
		}
	}
	return liquidityWindows
}

// devPendingPaymentSnapshot returns every pending payment instruction.
func devPendingPaymentSnapshot(bc *gonetwork.Blockchain) []any {
	pendingPayments := make([]any, 0, len(bc.PendingInstructions))
	for _, p := range bc.PendingInstructions {
		pendingPayments = append(pendingPayments, p)
	}
	return pendingPayments
}

// devSPVSnapshot returns every registered SPV (A-04).
func devSPVSnapshot(bc *gonetwork.Blockchain) []any {
	spvList := make([]any, 0, len(bc.SPVs))
	for _, spv := range bc.SPVs {
		spvList = append(spvList, spv)
	}
	return spvList
}

// devPendingCountersignCount counts participation notes still awaiting SPV
// admin countersignature (A-04).
func devPendingCountersignCount(bc *gonetwork.Blockchain) int {
	count := 0
	for _, a := range bc.Assets {
		if a.AssetType == gonetwork.AssetTypeParticipationNote && a.CirculatingSupply == 0 {
			count++
		}
	}
	return count
}

// devAmendmentSnapshot flattens the legal document amendment log (A-03)
// across all assets (most recent first across all assets) and returns the
// total amendment count.
func devAmendmentSnapshot(bc *gonetwork.Blockchain) (list []any, total int) {
	for _, l := range bc.LegalDocAmendments {
		total += len(l)
	}
	list = make([]any, 0, total)
	for assetID, l := range bc.LegalDocAmendments {
		for _, am := range l {
			list = append(list, map[string]any{
				"id":                am.ID,
				"asset_id":          assetID,
				"previous_doc_hash": am.PreviousDocHash,
				"new_doc_hash":      am.NewDocHash,
				"amended_at":        am.AmendedAt,
				"issuer_key":        am.IssuerKey,
				"admin_key":         am.AdminKey,
			})
		}
	}
	return list, total
}

// devPendingSARSnapshot returns pending Suspicious Activity Report drafts (G-09).
func devPendingSARSnapshot(bc *gonetwork.Blockchain) []any {
	pendingSARs := make([]any, 0, len(bc.PendingSARs))
	for _, sar := range bc.PendingSARs {
		if sar.Status == gonetwork.SARStatusPending {
			pendingSARs = append(pendingSARs, sar)
		}
	}
	return pendingSARs
}

// devRecentReports returns the most recent 50 regulatory reports (G-10) and
// the total report count.
func devRecentReports(bc *gonetwork.Blockchain) (recent []any, total int) {
	allReports := bc.RegulatoryReports
	total = len(allReports)
	reportStart := 0
	if total > 50 {
		reportStart = total - 50
	}
	recent = make([]any, 0, total-reportStart)
	for _, rep := range allReports[reportStart:] {
		recent = append(recent, rep)
	}
	return recent, total
}

// devJurisdictionSnapshot returns the jurisdiction rules table (G-11).
func devJurisdictionSnapshot(bc *gonetwork.Blockchain) map[string]any {
	jurisdictions := make(map[string]any, len(bc.JurisdictionRules))
	for code, rule := range bc.JurisdictionRules {
		jurisdictions[code] = rule
	}
	return jurisdictions
}

// ---------------------------------------------------------------------------
// GET /v1/dev/stream
// ---------------------------------------------------------------------------

// handleDevStream upgrades the connection to WebSocket and fans out all
// blockchain events without requiring JWT authentication.
// GET /v1/dev/stream — dev mode only.
func (s *Server) handleDevStream(w http.ResponseWriter, r *http.Request) {
	if !s.isDevMode() {
		writeError(w, http.StatusForbidden, "dev endpoints are disabled when admin keys are configured")
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	client := &wsClient{
		conn: conn,
		send: make(chan []byte, 256),
	}
	s.wsHub.register(client)
	defer s.wsHub.unregister(client)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for msg := range client.send {
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		}
	}()

	conn.SetReadLimit(4096)
	conn.SetReadDeadline(time.Now().Add(300 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(300 * time.Second))
		return nil
	})

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		// Accept optional subscription filter: {"subscribe": ["trade_executed", ...]}
		var sub struct {
			Subscribe []string `json:"subscribe"`
		}
		if json.Unmarshal(msg, &sub) == nil && len(sub.Subscribe) > 0 {
			filter := make(map[string]bool, len(sub.Subscribe))
			for _, t := range sub.Subscribe {
				filter[t] = true
			}
			client.subscribe = filter
		}
		conn.SetReadDeadline(time.Now().Add(300 * time.Second))
	}
	<-done
}
