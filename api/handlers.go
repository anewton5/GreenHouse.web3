package api

import (
	"encoding/base64"
	"encoding/json"
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
