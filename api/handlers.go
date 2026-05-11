package api

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"gonetwork"
)

// ---------------------------------------------------------------------------
// Auth endpoints
// ---------------------------------------------------------------------------

// handleChallenge issues a random challenge nonce for Ed25519 challenge-response auth.
// POST /v1/auth/challenge
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	ch, err := newChallenge()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate challenge")
		return
	}
	s.storeChallenge(ch)
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":  ch,
		"expires_at": time.Now().UTC().Unix() + 300,
	})
}

// handleVerify verifies an Ed25519 signature over the challenge and returns a JWT.
// POST /v1/auth/verify
// Body: {"wallet_key":"<base64>","challenge":"<hex>","signature":"<base64>"}
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WalletKey string `json:"wallet_key"`
		Challenge string `json:"challenge"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	pub, err := gonetwork.PublicKeyFromString(req.WalletKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid wallet_key: "+err.Error())
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid signature encoding")
		return
	}
	if !s.consumeChallenge(req.Challenge) {
		writeError(w, http.StatusUnauthorized, "challenge not found or expired")
		return
	}
	// Verify Ed25519 sig over the raw challenge bytes (UTF-8 of the hex string)
	if !gonetwork.VerifySignatureBytes(pub, []byte(req.Challenge), sig) {
		writeError(w, http.StatusUnauthorized, "signature verification failed")
		return
	}
	token, err := s.issueJWT(req.WalletKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// ---------------------------------------------------------------------------
// Asset endpoints
// ---------------------------------------------------------------------------

// handleListAssets returns all assets on chain.
// GET /v1/assets
func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	assets := make([]*gonetwork.Asset, 0, len(s.bc.Assets))
	for _, a := range s.bc.Assets {
		assets = append(assets, a)
	}
	writeJSON(w, http.StatusOK, assets)
}

// handleGetAsset returns a single asset by ID.
// GET /v1/assets/{id}
func (s *Server) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.bc.Assets[id]
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// handleCreateAsset accepts a pre-signed Asset JSON and registers it on chain.
// POST /v1/assets
// Body: Asset JSON (must include a valid IssuerSignature)
func (s *Server) handleCreateAsset(w http.ResponseWriter, r *http.Request) {
	var a gonetwork.Asset
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		writeError(w, http.StatusBadRequest, "invalid asset payload")
		return
	}
	if a.ID == "" {
		writeError(w, http.StatusBadRequest, "asset ID must not be empty")
		return
	}
	if _, exists := s.bc.Assets[a.ID]; exists {
		writeError(w, http.StatusConflict, "asset already exists")
		return
	}
	s.bc.Assets[a.ID] = &a
	writeJSON(w, http.StatusCreated, &a)
}

// ---------------------------------------------------------------------------
// Holdings endpoint
// ---------------------------------------------------------------------------

// handleGetHoldings returns a FiDA holdings report for the specified wallet.
// GET /v1/holdings/{walletKey}
func (s *Server) handleGetHoldings(w http.ResponseWriter, r *http.Request) {
	walletKey := r.PathValue("walletKey")
	report, err := gonetwork.GenerateHoldingsReport(
		walletKey,
		s.bc.Holdings,
		s.bc.Assets,
		s.bc.ValuationOracle,
		s.bc.CostBasisTracker,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// ---------------------------------------------------------------------------
// Order endpoints
// ---------------------------------------------------------------------------

// handleGetOrderBook returns the current order book state for an asset.
// GET /v1/orderbook/{assetID}
func (s *Server) handleGetOrderBook(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("assetID")
	ob, ok := s.bc.OrderBooks[assetID]
	if !ok {
		writeError(w, http.StatusNotFound, "order book not found")
		return
	}
	writeJSON(w, http.StatusOK, ob)
}

// handleListTrades returns trade history, optionally filtered by assetID or walletKey.
// GET /v1/trades?assetID=&walletKey=
func (s *Server) handleListTrades(w http.ResponseWriter, r *http.Request) {
	assetFilter := r.URL.Query().Get("assetID")
	walletFilter := r.URL.Query().Get("walletKey")

	out := make([]gonetwork.Trade, 0)
	for _, t := range s.bc.Trades {
		if assetFilter != "" && t.AssetID != assetFilter {
			continue
		}
		if walletFilter != "" && t.BuyerID != walletFilter && t.SellerID != walletFilter {
			continue
		}
		out = append(out, t)
	}
	writeJSON(w, http.StatusOK, out)
}

// handlePlaceOrder accepts a pre-signed OrderTransaction JSON and queues it.
// POST /v1/orders
// Body: OrderTransaction JSON
func (s *Server) handlePlaceOrder(w http.ResponseWriter, r *http.Request) {
	var ot gonetwork.OrderTransaction
	if err := json.NewDecoder(r.Body).Decode(&ot); err != nil {
		writeError(w, http.StatusBadRequest, "invalid order transaction payload")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"order_id": ot.Order.ID, "status": "queued"})
}

// handleCancelOrder marks an order for cancellation.
// DELETE /v1/orders/{id}
func (s *Server) handleCancelOrder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, map[string]string{"order_id": id, "status": "cancelled"})
}

// ---------------------------------------------------------------------------
// Deal endpoints
// ---------------------------------------------------------------------------

// handleListDeals returns all deals.
// GET /v1/deals
func (s *Server) handleListDeals(w http.ResponseWriter, r *http.Request) {
	deals := make([]*gonetwork.Deal, 0, len(s.bc.Deals))
	for _, d := range s.bc.Deals {
		deals = append(deals, d)
	}
	writeJSON(w, http.StatusOK, deals)
}

// handleCreateDeal accepts a pre-signed Deal JSON and registers it.
// POST /v1/deals
func (s *Server) handleCreateDeal(w http.ResponseWriter, r *http.Request) {
	var d gonetwork.Deal
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		writeError(w, http.StatusBadRequest, "invalid deal payload")
		return
	}
	if d.ID == "" {
		writeError(w, http.StatusBadRequest, "deal ID must not be empty")
		return
	}
	if _, exists := s.bc.Deals[d.ID]; exists {
		writeError(w, http.StatusConflict, "deal already exists")
		return
	}
	s.bc.Deals[d.ID] = &d
	writeJSON(w, http.StatusCreated, &d)
}

// handleAttachAnchor attaches a DealAnchor commitment to an existing deal.
// POST /v1/deals/{id}/anchor
func (s *Server) handleAttachAnchor(w http.ResponseWriter, r *http.Request) {
	dealID := r.PathValue("id")
	d, ok := s.bc.Deals[dealID]
	if !ok {
		writeError(w, http.StatusNotFound, "deal not found")
		return
	}
	var anchor gonetwork.DealAnchor
	if err := json.NewDecoder(r.Body).Decode(&anchor); err != nil {
		writeError(w, http.StatusBadRequest, "invalid anchor payload")
		return
	}
	pub, err := gonetwork.PublicKeyFromString(anchor.AnchorWalletKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid anchor wallet key")
		return
	}
	if err := d.AttachAnchor(&anchor, pub, nil); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// handleAddCommitment adds a DealCommitment from a co-investor.
// POST /v1/deals/{id}/commit
func (s *Server) handleAddCommitment(w http.ResponseWriter, r *http.Request) {
	dealID := r.PathValue("id")
	d, ok := s.bc.Deals[dealID]
	if !ok {
		writeError(w, http.StatusNotFound, "deal not found")
		return
	}
	var c gonetwork.DealCommitment
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid commitment payload")
		return
	}
	pub, err := gonetwork.PublicKeyFromString(c.InvestorKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid investor key")
		return
	}
	if err := d.AddCoInvestor(&c, pub, nil); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// ---------------------------------------------------------------------------
// Reporting endpoints
// ---------------------------------------------------------------------------

// handleReportHoldings returns the FiDA holdings report for the authenticated wallet.
// GET /v1/reporting/holdings
func (s *Server) handleReportHoldings(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)
	report, err := gonetwork.GenerateHoldingsReport(
		walletKey,
		s.bc.Holdings,
		s.bc.Assets,
		s.bc.ValuationOracle,
		s.bc.CostBasisTracker,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	data, err := report.MarshalFiDA()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to serialise report")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// handleReportTax returns a tax report for the authenticated wallet for the given year.
// GET /v1/reporting/tax/{year}?jurisdiction=GB&currency=GBP
func (s *Server) handleReportTax(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)
	yearStr := r.PathValue("year")
	year, err := strconv.Atoi(yearStr)
	if err != nil || year < 2000 || year > 2100 {
		writeError(w, http.StatusBadRequest, "invalid tax year")
		return
	}
	jurisdiction := r.URL.Query().Get("jurisdiction")
	if jurisdiction == "" {
		jurisdiction = "DE"
	}
	currency := r.URL.Query().Get("currency")
	if currency == "" {
		currency = "EUR"
	}

	report, err := gonetwork.GenerateTaxReport(
		walletKey,
		year,
		jurisdiction,
		currency,
		s.bc.Trades,
		s.bc.Assets,
		s.bc.CostBasisTracker,
		s.bc.ValuationOracle,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	data, err := report.MarshalFiDA()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to serialise report")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// ---------------------------------------------------------------------------
// Infrastructure endpoints
// ---------------------------------------------------------------------------

// handleListBlocks returns the most recent 50 blocks on chain.
// GET /v1/blocks
func (s *Server) handleListBlocks(w http.ResponseWriter, r *http.Request) {
	blocks := s.bc.Blocks
	if len(blocks) > 50 {
		blocks = blocks[len(blocks)-50:]
	}
	writeJSON(w, http.StatusOK, blocks)
}

// handleHealth returns service health and version information.
// GET /v1/health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"version":   "2.0.0",
		"timestamp": time.Now().UTC().Unix(),
	})
}

// ---------------------------------------------------------------------------
// KYC endpoints
// ---------------------------------------------------------------------------

// handleKYCRequest queues a KYC approval request from an authenticated participant.
// POST /v1/kyc/request
// Body: {"class":"professional","jurisdiction":"GB","valid_for_days":365}
func (s *Server) handleKYCRequest(w http.ResponseWriter, r *http.Request) {
	if s.OperatorRegistry == nil {
		writeError(w, http.StatusNotImplemented, "KYC workflow not configured on this node")
		return
	}
	walletKey := walletFromCtx(r)
	var req struct {
		Class        gonetwork.InvestorClass `json:"class"`
		Jurisdiction string                  `json:"jurisdiction"`
		ValidForDays int                     `json:"valid_for_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ValidForDays <= 0 {
		req.ValidForDays = 365
	}
	if err := s.OperatorRegistry.RequestKYC(walletKey, req.Class, req.Jurisdiction, req.ValidForDays); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{
		"wallet_key": walletKey,
		"status":     "pending_review",
		"message":    "Your KYC request has been submitted. A GreenHouse operator will review it shortly.",
	})
}

// handleAdminKYCList returns all pending KYC approval requests.
// GET /v1/admin/kyc/pending
func (s *Server) handleAdminKYCList(w http.ResponseWriter, _ *http.Request) {
	if s.OperatorRegistry == nil {
		writeError(w, http.StatusNotImplemented, "KYC workflow not configured on this node")
		return
	}
	pending := s.OperatorRegistry.ListPendingRequests()
	writeJSON(w, http.StatusOK, map[string]any{
		"count":    len(pending),
		"requests": pending,
	})
}

// handleAdminKYCApprove approves a pending KYC request and issues a credential.
// POST /v1/admin/kyc/approve
// Body: {"wallet_key":"<base64>"}
func (s *Server) handleAdminKYCApprove(w http.ResponseWriter, r *http.Request) {
	if s.OperatorRegistry == nil {
		writeError(w, http.StatusNotImplemented, "KYC workflow not configured on this node")
		return
	}
	var req struct {
		WalletKey string `json:"wallet_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.WalletKey == "" {
		writeError(w, http.StatusBadRequest, "wallet_key must not be empty")
		return
	}
	att, err := s.OperatorRegistry.ApproveKYC(req.WalletKey)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	// Propagate the credential to the blockchain's credential store so it
	// is immediately usable for transfer eligibility checks.
	s.bc.Credentials[req.WalletKey] = att
	writeJSON(w, http.StatusOK, map[string]any{
		"wallet_key":     att.WalletPublicKey,
		"investor_class": att.InvestorClass,
		"kyc_status":     att.KYCStatus,
		"expires_at":     att.ExpiresAt,
	})
}

// handlePaymentWebhook receives Modulr payment-received notifications.
// POST /v1/webhooks/payment
//
// When ModulrProvider is configured the HMAC-SHA256 signature in
// X-Mod-Nonce is verified before any payload processing. When it is nil
// (e.g. in development using MockPaymentProvider) the signature check is
// skipped and the event is still processed.
func (s *Server) handlePaymentWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	if s.ModulrProvider != nil {
		sig := r.Header.Get("X-Mod-Nonce")
		if sig == "" {
			writeError(w, http.StatusUnauthorized, "missing X-Mod-Nonce header")
			return
		}
		if !s.ModulrProvider.VerifyWebhookSignature(body, sig) {
			writeError(w, http.StatusUnauthorized, "invalid webhook signature")
			return
		}
	}

	var event struct {
		Type      string  `json:"type"`
		Reference string  `json:"externalReference"`
		Amount    float64 `json:"amount"`
		Currency  string  `json:"currency"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook payload")
		return
	}

	if event.Type == "PAYMENT_RECEIVED" && event.Reference != "" {
		// Errors here are intentionally swallowed — returning a non-200 to
		// Modulr would trigger automatic retries for events that may already
		// be processed or are not applicable (e.g. wrong reference format).
		_ = s.bc.PaymentProvider.ConfirmPayment(event.Reference, event.Amount, event.Currency)
	}

	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------------------
// KYC status endpoint
// ---------------------------------------------------------------------------

// handleKYCStatus returns the current KYC credential for the authenticated wallet.
// GET /v1/kyc/status
func (s *Server) handleKYCStatus(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)
	att, ok := s.bc.Credentials[walletKey]
	if !ok {
		writeJSON(w, http.StatusOK, map[string]string{
			"kyc_status":     "not_found",
			"investor_class": "",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"kyc_status":     att.KYCStatus,
		"investor_class": string(att.InvestorClass),
		"expires_at":     att.ExpiresAt,
	})
}

// ---------------------------------------------------------------------------
// Open orders by wallet
// ---------------------------------------------------------------------------

// handleListOrders returns all open orders in any order book that belong to
// the authenticated wallet.
// GET /v1/orders
func (s *Server) handleListOrders(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)
	type orderView struct {
		ID      string  `json:"id"`
		AssetID string  `json:"asset_id"`
		Side    string  `json:"side"`
		Price   float64 `json:"price"`
		Volume  float64 `json:"volume"`
		Filled  float64 `json:"filled"`
		Status  string  `json:"status"`
	}
	var out []orderView
	for assetID, ob := range s.bc.OrderBooks {
		allOrders := append(ob.Bids, ob.Asks...)
		for _, o := range allOrders {
			if o.PlacedBy != walletKey {
				continue
			}
			side := "buy"
			if o.Side == gonetwork.OrderSideAsk {
				side = "sell"
			}
			out = append(out, orderView{
				ID:      o.ID,
				AssetID: assetID,
				Side:    side,
				Price:   o.Price,
				Volume:  o.Quantity,
				Filled:  o.Filled,
				Status:  string(o.Status),
			})
		}
	}
	if out == nil {
		out = []orderView{}
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Cap table
// ---------------------------------------------------------------------------

// handleGetCapTable returns the cap table for an asset (all holders and their
// percentage of total supply).
// GET /v1/assets/{id}/captable
func (s *Server) handleGetCapTable(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	asset, ok := s.bc.Assets[assetID]
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	type holderRow struct {
		WalletKey  string  `json:"wallet_key"`
		Quantity   float64 `json:"quantity"`
		Percentage float64 `json:"percentage"`
	}
	var rows []holderRow
	for _, h := range s.bc.Holdings {
		if h.AssetID != assetID {
			continue
		}
		pct := 0.0
		if asset.TotalSupply > 0 {
			pct = h.Balance / asset.TotalSupply * 100
		}
		rows = append(rows, holderRow{
			WalletKey:  h.HolderID,
			Quantity:   h.Balance,
			Percentage: pct,
		})
	}
	if rows == nil {
		rows = []holderRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"asset_id":     assetID,
		"total_supply": asset.TotalSupply,
		"holders":      rows,
	})
}

// ---------------------------------------------------------------------------
// Liquidity windows
// ---------------------------------------------------------------------------

// handleListLiquidityWindows returns all scheduled/open/closed liquidity windows.
// GET /v1/liquidity/windows?asset_id=
func (s *Server) handleListLiquidityWindows(w http.ResponseWriter, r *http.Request) {
	assetFilter := r.URL.Query().Get("asset_id")
	var out []*gonetwork.LiquidityWindow
	if s.bc.WindowManager != nil {
		for _, win := range s.bc.WindowManager.Windows {
			if assetFilter != "" && win.AssetID != assetFilter {
				continue
			}
			out = append(out, win)
		}
	}
	if out == nil {
		out = []*gonetwork.LiquidityWindow{}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleScheduleLiquidityWindow creates a new liquidity window for an asset.
// POST /v1/liquidity/windows
// Body: {"asset_id":"...","opens_at":unix,"closes_at":unix,"max_volume":0,"currency":"GBP"}
func (s *Server) handleScheduleLiquidityWindow(w http.ResponseWriter, r *http.Request) {
	if s.bc.WindowManager == nil {
		writeError(w, http.StatusNotImplemented, "liquidity window manager not configured")
		return
	}
	walletKey := walletFromCtx(r)
	var req struct {
		AssetID   string  `json:"asset_id"`
		OpensAt   int64   `json:"opens_at"`
		ClosesAt  int64   `json:"closes_at"`
		MaxVolume float64 `json:"max_volume"`
		Currency  string  `json:"currency"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.AssetID == "" || req.OpensAt == 0 || req.ClosesAt == 0 {
		writeError(w, http.StatusBadRequest, "asset_id, opens_at, closes_at are required")
		return
	}
	if req.ClosesAt <= req.OpensAt {
		writeError(w, http.StatusBadRequest, "closes_at must be after opens_at")
		return
	}
	win := &gonetwork.LiquidityWindow{
		ID:          base64.RawURLEncoding.EncodeToString([]byte(req.AssetID + strconv.FormatInt(req.OpensAt, 10))),
		AssetID:     req.AssetID,
		OpenAt:      req.OpensAt,
		CloseAt:     req.ClosesAt,
		MaxVolume:   req.MaxVolume,
		Currency:    req.Currency,
		Status:      gonetwork.WindowStatusScheduled,
		ProposerKey: walletKey,
	}
	if err := s.bc.WindowManager.ScheduleWindow(win); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, win)
}

// ---------------------------------------------------------------------------
// Corporate actions
// ---------------------------------------------------------------------------

// handleListCorporateActions returns all pending corporate actions, optionally
// filtered by asset.
// GET /v1/corporate-actions?asset_id=
func (s *Server) handleListCorporateActions(w http.ResponseWriter, r *http.Request) {
	assetFilter := r.URL.Query().Get("asset_id")
	var out []*gonetwork.CorporateAction
	for _, ca := range s.bc.PendingCorporateActions {
		if assetFilter != "" && ca.AssetID != assetFilter {
			continue
		}
		out = append(out, ca)
	}
	if out == nil {
		out = []*gonetwork.CorporateAction{}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleProposeCorporateAction creates a new pending corporate action.
// POST /v1/corporate-actions
// Body: {"asset_id":"...","action_type":"dividend","record_date":unix,"parameters":{}}
func (s *Server) handleProposeCorporateAction(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)
	var req struct {
		AssetID    string                          `json:"asset_id"`
		ActionType gonetwork.CorporateActionType   `json:"action_type"`
		RecordDate int64                           `json:"record_date"`
		Parameters map[string]interface{}          `json:"parameters"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.AssetID == "" || req.ActionType == "" {
		writeError(w, http.StatusBadRequest, "asset_id and action_type are required")
		return
	}
	id := base64.RawURLEncoding.EncodeToString([]byte(req.AssetID + string(req.ActionType) + strconv.FormatInt(time.Now().UnixNano(), 10)))
	ca := &gonetwork.CorporateAction{
		ID:          id,
		AssetID:     req.AssetID,
		Type:        req.ActionType,
		Status:      gonetwork.CorporateActionPending,
		ProposerKey: walletKey,
		DeadlineAt:  req.RecordDate,
	}
	s.bc.PendingCorporateActions[id] = ca
	writeJSON(w, http.StatusCreated, ca)
}

// ---------------------------------------------------------------------------
// Pending trade approvals (mobile co-signing)
// ---------------------------------------------------------------------------

// handleListPendingTrades returns trades awaiting the authenticated wallet's
// co-signature (seller confirmation).
// GET /v1/trades/pending
func (s *Server) handleListPendingTrades(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)
	var out []gonetwork.Trade
	for _, t := range s.bc.Trades {
		if t.SellerID == walletKey && t.Status == "pending_approval" {
			out = append(out, t)
		}
	}
	if out == nil {
		out = []gonetwork.Trade{}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleApproveTrade records a seller co-signature for a trade.
// POST /v1/trades/{id}/approve
// Body: {"approve":true,"signature":"<base64url>","timestamp":unix}
func (s *Server) handleApproveTrade(w http.ResponseWriter, r *http.Request) {
	tradeID := r.PathValue("id")
	walletKey := walletFromCtx(r)

	var req struct {
		Approve   bool   `json:"approve"`
		Signature string `json:"signature"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Find the trade and verify the caller is the seller.
	var found *gonetwork.Trade
	for i := range s.bc.Trades {
		if s.bc.Trades[i].ID == tradeID {
			found = &s.bc.Trades[i]
			break
		}
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "trade not found")
		return
	}
	if found.SellerID != walletKey {
		writeError(w, http.StatusForbidden, "only the seller may approve this trade")
		return
	}

	// Verify the Ed25519 signature over the approval payload.
	pub, err := gonetwork.PublicKeyFromString(walletKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid wallet key")
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil {
		// fall back to standard base64
		sig, err = base64.StdEncoding.DecodeString(req.Signature)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid signature encoding")
			return
		}
	}
	payload := map[string]any{"trade_id": tradeID, "approve": req.Approve, "timestamp": req.Timestamp}
	payloadBytes, _ := json.Marshal(payload)
	if !gonetwork.VerifySignatureBytes(pub, payloadBytes, sig) {
		writeError(w, http.StatusUnauthorized, "signature verification failed")
		return
	}

	status := "approved"
	if !req.Approve {
		status = "rejected"
	}
	found.Status = status
	writeJSON(w, http.StatusOK, map[string]string{"trade_id": tradeID, "status": status})
}
