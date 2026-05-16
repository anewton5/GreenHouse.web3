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
func (s *Server) handleDevState(w http.ResponseWriter, r *http.Request) {
	if !s.isDevMode() {
		writeError(w, http.StatusForbidden, "dev endpoints are disabled when admin keys are configured")
		return
	}

	// Block summaries
	blocks := make([]devBlockSummary, 0, len(s.bc.Blocks))
	for i, b := range s.bc.Blocks {
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

	// Assets
	assets := make([]any, 0, len(s.bc.Assets))
	for _, a := range s.bc.Assets {
		assets = append(assets, a)
	}

	// Open order count across all order books
	openBids, openAsks := 0, 0
	orderBookSnapshot := make([]any, 0, len(s.bc.OrderBooks))
	for assetID, ob := range s.bc.OrderBooks {
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
		orderBookSnapshot = append(orderBookSnapshot, map[string]any{
			"asset_id":  assetID,
			"bid_count": bidCount,
			"ask_count": askCount,
			"bids":      ob.Bids,
			"asks":      ob.Asks,
		})
	}

	// Credentials
	credentials := make([]any, 0, len(s.bc.Credentials))
	for _, c := range s.bc.Credentials {
		credentials = append(credentials, c)
	}

	// Deals
	deals := make([]any, 0, len(s.bc.Deals))
	for _, d := range s.bc.Deals {
		deals = append(deals, d)
	}

	// Corporate actions
	corpActions := make([]any, 0, len(s.bc.PendingCorporateActions))
	for _, ca := range s.bc.PendingCorporateActions {
		corpActions = append(corpActions, ca)
	}

	// Liquidity windows
	liquidityWindows := make([]any, 0)
	if s.bc.WindowManager != nil {
		for _, win := range s.bc.WindowManager.Windows {
			liquidityWindows = append(liquidityWindows, win)
		}
	}

	// Pending payment instructions
	pendingPayments := make([]any, 0, len(s.bc.PendingInstructions))
	for _, p := range s.bc.PendingInstructions {
		pendingPayments = append(pendingPayments, p)
	}

	// SPVs (A-04)
	spvList := make([]any, 0, len(s.bc.SPVs))
	for _, spv := range s.bc.SPVs {
		spvList = append(spvList, spv)
	}

	// Participation notes awaiting SPV admin countersignature (A-04)
	pendingCountersign := 0
	for _, a := range s.bc.Assets {
		if a.AssetType == gonetwork.AssetTypeParticipationNote && a.CirculatingSupply == 0 {
			pendingCountersign++
		}
	}

	// Legal document amendment log (A-03)
	totalAmendments := 0
	for _, list := range s.bc.LegalDocAmendments {
		totalAmendments += len(list)
	}

	// Flatten amendment list for the dashboard (most recent first across all assets)
	amendmentList := make([]any, 0, totalAmendments)
	for assetID, list := range s.bc.LegalDocAmendments {
		for _, am := range list {
			amendmentList = append(amendmentList, map[string]any{
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

	// ── Part II compliance state ─────────────────────────────────────────

	// Pending SARs (G-09)
	pendingSARs := make([]any, 0, len(s.bc.PendingSARs))
	for _, sar := range s.bc.PendingSARs {
		if sar.Status == gonetwork.SARStatusPending {
			pendingSARs = append(pendingSARs, sar)
		}
	}

	// Recent regulatory reports — last 50 (G-10)
	allReports := s.bc.RegulatoryReports
	reportStart := 0
	if len(allReports) > 50 {
		reportStart = len(allReports) - 50
	}
	recentReports := make([]any, 0, len(allReports)-reportStart)
	for _, rep := range allReports[reportStart:] {
		recentReports = append(recentReports, rep)
	}

	// Jurisdiction rules snapshot (G-11)
	jurisdictions := make(map[string]any, len(s.bc.JurisdictionRules))
	for code, rule := range s.bc.JurisdictionRules {
		jurisdictions[code] = rule
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"timestamp":                 time.Now().UTC().Unix(),
		"block_count":               len(s.bc.Blocks),
		"blocks":                    blocks,
		"asset_count":               len(s.bc.Assets),
		"assets":                    assets,
		"trade_count":               len(s.bc.Trades),
		"trades":                    s.bc.Trades,
		"open_bid_count":            openBids,
		"open_ask_count":            openAsks,
		"order_books":               orderBookSnapshot,
		"credential_count":          len(s.bc.Credentials),
		"credentials":               credentials,
		"deal_count":                len(s.bc.Deals),
		"deals":                     deals,
		"corporate_actions":         corpActions,
		"liquidity_windows":         liquidityWindows,
		"pending_payments":          pendingPayments,
		"spvs":                      spvList,
		"pending_countersign_count": pendingCountersign,
		"amendment_count":           totalAmendments,
		"amendments":                amendmentList,
		// Part II compliance
		"pending_sar_count":       len(pendingSARs),
		"pending_sars":            pendingSARs,
		"regulatory_report_count": len(allReports),
		"regulatory_reports":      recentReports,
		"jurisdiction_rules":      jurisdictions,
	})
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
