package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/sha3"

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
		"expires_at": time.Now().UTC().Unix() + 60,
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
	sig, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil {
		// fall back to standard base64
		sig, err = base64.StdEncoding.DecodeString(req.Signature)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid signature encoding")
			return
		}
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

// handleCreateAsset creates a new tokenised asset.
// POST /v1/assets
// Body: {"name":"...","symbol":"...","asset_class":"equity","total_supply":1000000,"currency":"GBP","metadata":{}}
func (s *Server) handleCreateAsset(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)

	var req struct {
		Name        string            `json:"name"`
		Symbol      string            `json:"symbol"`
		AssetClass  string            `json:"asset_class"`
		TotalSupply float64           `json:"total_supply"`
		Currency    string            `json:"currency"`
		Metadata    map[string]string `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid asset payload")
		return
	}
	if req.Name == "" || req.Symbol == "" {
		writeError(w, http.StatusBadRequest, "name and symbol are required")
		return
	}
	if req.TotalSupply <= 0 {
		writeError(w, http.StatusBadRequest, "total_supply must be greater than zero")
		return
	}
	if req.Currency == "" {
		writeError(w, http.StatusBadRequest, "currency is required")
		return
	}

	// Derive a unique, collision-resistant ID from issuer wallet + symbol + timestamp.
	idSrc := fmt.Sprintf("%s:%s:%d", walletKey, req.Symbol, time.Now().UnixNano())
	idHash := sha3.Sum256([]byte(idSrc))
	assetID := hex.EncodeToString(idHash[:])

	// Build AssetMetadata from the optional metadata map.
	meta := gonetwork.AssetMetadata{}
	if req.Metadata != nil {
		meta.ISIN = req.Metadata["isin"]
		meta.Jurisdiction = req.Metadata["jurisdiction"]
		meta.CompanyName = req.Metadata["company_name"]
		meta.DividendTerms = req.Metadata["dividend_terms"]
		meta.LegalDocHash = req.Metadata["legal_doc_hash"]
	}

	// Map asset_class string to AssetType.
	classMap := map[string]gonetwork.AssetType{
		"equity":      gonetwork.AssetTypeEquity,
		"bond":        gonetwork.AssetTypeDebt,
		"fund":        gonetwork.AssetTypeFundUnit,
		"real_estate": gonetwork.AssetTypeEquity,
		"commodity":   gonetwork.AssetTypeEquity,
		"other":       gonetwork.AssetTypeEquity,
	}
	assetType, ok := classMap[req.AssetClass]
	if !ok {
		assetType = gonetwork.AssetTypeEquity
	}

	a := &gonetwork.Asset{
		ID:          assetID,
		Name:        req.Name,
		Symbol:      req.Symbol,
		Issuer:      walletKey,
		AssetType:   assetType,
		TotalSupply: req.TotalSupply,
		Currency:    req.Currency,
		Metadata:    meta,
		CreatedAt:   time.Now().Unix(),
	}
	if a.Metadata.CompanyName == "" {
		a.Metadata.CompanyName = req.Name
	}

	if _, exists := s.bc.Assets[assetID]; exists {
		writeError(w, http.StatusConflict, "asset already exists")
		return
	}
	s.bc.Assets[assetID] = a

	// Create the issuer's initial holding at full supply so they can immediately
	// place ask orders and initiate transfers to investors.
	issuerHoldingKey := gonetwork.HoldingKey(walletKey, assetID)
	s.bc.Holdings[issuerHoldingKey] = &gonetwork.AssetHolding{
		AssetID:  assetID,
		HolderID: walletKey,
		Balance:  req.TotalSupply,
	}
	a.CirculatingSupply = req.TotalSupply

	s.bc.SealBlock(
		[]gonetwork.AssetTransaction{{AssetID: assetID, TxType: gonetwork.AssetTxTypeIssue}},
		nil, nil,
	)
	writeJSON(w, http.StatusCreated, a)
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

// handlePlaceOrder creates and stores a new order on behalf of the authenticated wallet.
// POST /v1/orders
// Body: {"asset_id":"...","side":"buy","type":"limit","price":10.50,"quantity":100}
func (s *Server) handlePlaceOrder(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)

	var req struct {
		AssetID  string  `json:"asset_id"`
		Side     string  `json:"side"` // "buy" or "sell"
		Type     string  `json:"type"` // "limit" or "market"
		Price    float64 `json:"price"`
		Quantity float64 `json:"quantity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid order payload")
		return
	}
	if req.AssetID == "" {
		writeError(w, http.StatusBadRequest, "asset_id is required")
		return
	}
	if _, ok := s.bc.Assets[req.AssetID]; !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if req.Quantity <= 0 {
		writeError(w, http.StatusBadRequest, "quantity must be greater than zero")
		return
	}
	if req.Type == "limit" && req.Price <= 0 {
		writeError(w, http.StatusBadRequest, "price must be greater than zero for limit orders")
		return
	}

	// Map "buy"/"sell" → OrderSide constants.
	var side gonetwork.OrderSide
	switch req.Side {
	case "buy":
		side = gonetwork.OrderSideBid
	case "sell":
		side = gonetwork.OrderSideAsk
	default:
		writeError(w, http.StatusBadRequest, "side must be \"buy\" or \"sell\"")
		return
	}

	// For market orders use a highly aggressive price to ensure immediate matching.
	price := req.Price
	if req.Type == "market" {
		if side == gonetwork.OrderSideBid {
			price = 1e15 // will match any ask
		} else {
			price = 0.0001 // will match any bid
		}
	}

	now := time.Now()
	idSrc := fmt.Sprintf("%s:%s:%d", walletKey, req.AssetID, now.UnixNano())
	idHash := sha3.Sum256([]byte(idSrc))
	orderID := hex.EncodeToString(idHash[:])

	order := &gonetwork.Order{
		ID:       orderID,
		AssetID:  req.AssetID,
		Side:     side,
		Type:     req.Type,
		Price:    price,
		Quantity: req.Quantity,
		Filled:   0,
		PlacedBy: walletKey,
		PlacedAt: now.UnixNano(),
		Status:   gonetwork.OrderStatusOpen,
	}

	// Get or create the order book for this asset.
	ob, ok := s.bc.OrderBooks[req.AssetID]
	if !ok {
		ob = gonetwork.NewOrderBook(req.AssetID)
		s.bc.OrderBooks[req.AssetID] = ob
	}

	// Insert directly (JWT authentication already validates the caller).
	if side == gonetwork.OrderSideBid {
		ob.Bids = append(ob.Bids, order)
	} else {
		ob.Asks = append(ob.Asks, order)
	}

	s.bc.EmitEvent(gonetwork.EventOrderPlaced, map[string]any{
		"order_id":  order.ID,
		"asset_id":  order.AssetID,
		"side":      req.Side,
		"price":     req.Price,
		"quantity":  order.Quantity,
		"placed_by": walletKey,
	})
	s.bc.SealBlock(nil, []gonetwork.OrderTransaction{{Order: *order}}, nil)

	// Return the order using the same shape as handleListOrders.
	respSide := req.Side // already "buy" or "sell"
	orderType := req.Type
	if orderType == "" {
		orderType = "limit"
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         order.ID,
		"asset_id":   order.AssetID,
		"side":       respSide,
		"type":       orderType,
		"price":      req.Price, // return original price, not market sentinel
		"quantity":   order.Quantity,
		"filled":     order.Filled,
		"status":     string(order.Status),
		"created_at": now.Unix(),
	})
}

// handleCancelOrder marks an order for cancellation.
// DELETE /v1/orders/{id}
func (s *Server) handleCancelOrder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	walletKey := walletFromCtx(r)

	var found *gonetwork.Order
	for _, book := range s.bc.OrderBooks {
		for _, o := range append(book.Bids, book.Asks...) {
			if o.ID == id {
				found = o
				break
			}
		}
		if found != nil {
			break
		}
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "order not found")
		return
	}
	if found.PlacedBy != walletKey {
		writeError(w, http.StatusForbidden, "only the order placer may cancel it")
		return
	}
	if found.Status != gonetwork.OrderStatusOpen {
		writeError(w, http.StatusConflict, "order is not open")
		return
	}
	found.Status = gonetwork.OrderStatusCancelled

	s.bc.EmitEvent(gonetwork.EventOrderCancelled, map[string]any{
		"order_id": id,
		"asset_id": found.AssetID,
		"reason":   "cancelled_by_placer",
	})
	s.bc.SealBlock(nil, []gonetwork.OrderTransaction{{Order: *found, IsCancellation: true}}, nil)

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
	// Ensure holdings is always a JSON array, never null.
	if report.Holdings == nil {
		report.Holdings = []gonetwork.HoldingSnapshot{}
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
	// Validate investor class
	validClasses := map[gonetwork.InvestorClass]bool{
		"retail": true, "professional": true,
		"elective_professional": true, "eligible_counterparty": true,
	}
	if !validClasses[req.Class] {
		writeError(w, http.StatusBadRequest, "invalid investor class")
		return
	}
	// Validate jurisdiction is a 2-letter ISO 3166-1 alpha-2 code
	if len(req.Jurisdiction) != 2 {
		writeError(w, http.StatusBadRequest, "jurisdiction must be a 2-letter ISO country code")
		return
	}
	// Validate valid_for_days is in an acceptable range
	if req.ValidForDays <= 0 || req.ValidForDays > 730 {
		writeError(w, http.StatusBadRequest, "valid_for_days must be between 1 and 730")
		return
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

	s.bc.EmitEvent(gonetwork.EventCredentialIssued, map[string]any{
		"wallet_key":     att.WalletPublicKey,
		"investor_class": att.InvestorClass,
		"kyc_status":     att.KYCStatus,
		"jurisdiction":   att.Jurisdiction,
		"expires_at":     att.ExpiresAt,
	})
	s.bc.SealBlock(nil, nil, []gonetwork.CredentialTransaction{{Attestation: *att}})

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
		ID        string  `json:"id"`
		AssetID   string  `json:"asset_id"`
		Side      string  `json:"side"`
		Type      string  `json:"type"`
		Price     float64 `json:"price"`
		Quantity  float64 `json:"quantity"`
		Filled    float64 `json:"filled"`
		Status    string  `json:"status"`
		CreatedAt int64   `json:"created_at"`
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
			orderType := o.Type
			if orderType == "" {
				orderType = "limit"
			}
			out = append(out, orderView{
				ID:        o.ID,
				AssetID:   assetID,
				Side:      side,
				Type:      orderType,
				Price:     o.Price,
				Quantity:  o.Quantity,
				Filled:    o.Filled,
				Status:    string(o.Status),
				CreatedAt: o.PlacedAt / 1e9, // nanoseconds → seconds
			})
		}
	}
	if out == nil {
		out = []orderView{}
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Issuer order management
// ---------------------------------------------------------------------------

// handleIssuerListOrders returns all open buy (bid) orders for assets issued
// by the authenticated wallet, so the issuer can review and fill/reject them.
// GET /v1/issuer/orders
func (s *Server) handleIssuerListOrders(w http.ResponseWriter, r *http.Request) {
	issuerKey := walletFromCtx(r)

	type issuerOrderView struct {
		ID        string  `json:"id"`
		AssetID   string  `json:"asset_id"`
		AssetName string  `json:"asset_name"`
		Side      string  `json:"side"`
		Type      string  `json:"type"`
		Price     float64 `json:"price"`
		Quantity  float64 `json:"quantity"`
		Filled    float64 `json:"filled"`
		Status    string  `json:"status"`
		PlacedBy  string  `json:"placed_by"`
		CreatedAt int64   `json:"created_at"`
	}

	var out []issuerOrderView
	for assetID, ob := range s.bc.OrderBooks {
		asset, ok := s.bc.Assets[assetID]
		if !ok || asset.Issuer != issuerKey {
			continue
		}
		assetName := asset.Name
		if assetName == "" {
			assetName = asset.Symbol
		}
		allOrders := append(ob.Bids, ob.Asks...)
		for _, o := range allOrders {
			if o.Status != gonetwork.OrderStatusOpen {
				continue
			}
			side := "buy"
			if o.Side == gonetwork.OrderSideAsk {
				side = "sell"
			}
			orderType := o.Type
			if orderType == "" {
				orderType = "limit"
			}
			out = append(out, issuerOrderView{
				ID:        o.ID,
				AssetID:   assetID,
				AssetName: assetName,
				Side:      side,
				Type:      orderType,
				Price:     o.Price,
				Quantity:  o.Quantity,
				Filled:    o.Filled,
				Status:    string(o.Status),
				PlacedBy:  o.PlacedBy,
				CreatedAt: o.PlacedAt / 1e9,
			})
		}
	}
	if out == nil {
		out = []issuerOrderView{}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleFillOrder marks an order as filled and credits the buyer's holding.
// The issuer must own the asset. Filling allocates tokens from the issuer's
// holding (or directly from circulating supply if the issuer has no holding yet).
// POST /v1/orders/{id}/fill
func (s *Server) handleFillOrder(w http.ResponseWriter, r *http.Request) {
	orderID := r.PathValue("id")
	issuerKey := walletFromCtx(r)

	// Find the order across all books.
	var found *gonetwork.Order
	for _, book := range s.bc.OrderBooks {
		for _, o := range append(book.Bids, book.Asks...) {
			if o.ID == orderID {
				found = o
				break
			}
		}
		if found != nil {
			break
		}
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "order not found")
		return
	}

	// Verify the caller issued the asset.
	asset, ok := s.bc.Assets[found.AssetID]
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if asset.Issuer != issuerKey {
		writeError(w, http.StatusForbidden, "only the asset issuer may fill orders")
		return
	}
	if found.Status != gonetwork.OrderStatusOpen {
		writeError(w, http.StatusConflict, "order is not open")
		return
	}

	fillQty := found.Quantity - found.Filled

	// Credit the buyer's holding.
	buyerKey := gonetwork.HoldingKey(found.PlacedBy, found.AssetID)
	if h, exists := s.bc.Holdings[buyerKey]; exists {
		h.Balance += fillQty
	} else {
		s.bc.Holdings[buyerKey] = &gonetwork.AssetHolding{
			HolderID: found.PlacedBy,
			AssetID:  found.AssetID,
			Balance:  fillQty,
		}
	}

	// Deduct from issuer holding if it exists.
	issuerHoldingKey := gonetwork.HoldingKey(issuerKey, found.AssetID)
	if ih, exists := s.bc.Holdings[issuerHoldingKey]; exists && ih.Balance >= fillQty {
		ih.Balance -= fillQty
	}

	// Mark filled and update asset circulating supply.
	found.Filled = found.Quantity
	found.Status = gonetwork.OrderStatusFilled
	asset.CirculatingSupply += fillQty

	// Record the trade.
	tradeID := fmt.Sprintf("trade-%s", orderID[:8])
	s.bc.Trades = append(s.bc.Trades, gonetwork.Trade{
		ID:         tradeID,
		AssetID:    found.AssetID,
		BuyerID:    found.PlacedBy,
		SellerID:   issuerKey,
		Quantity:   fillQty,
		Price:      found.Price,
		ExecutedAt: time.Now().Unix(),
		Status:     "settled",
	})

	s.bc.EmitEvent(gonetwork.EventTradeExecuted, map[string]any{
		"trade_id":  tradeID,
		"asset_id":  found.AssetID,
		"buyer_id":  found.PlacedBy,
		"seller_id": issuerKey,
		"quantity":  fillQty,
		"price":     found.Price,
	})
	s.bc.SealBlock(nil, []gonetwork.OrderTransaction{{Order: *found}}, nil)

	writeJSON(w, http.StatusOK, map[string]any{
		"order_id":   orderID,
		"trade_id":   tradeID,
		"status":     "filled",
		"filled_qty": fillQty,
		"buyer":      found.PlacedBy,
		"asset_id":   found.AssetID,
		"settled_at": time.Now().Unix(),
	})
}

// handleRejectOrder marks an order as cancelled by the issuer.
// POST /v1/orders/{id}/reject
func (s *Server) handleRejectOrder(w http.ResponseWriter, r *http.Request) {
	orderID := r.PathValue("id")
	issuerKey := walletFromCtx(r)

	var found *gonetwork.Order
	for _, book := range s.bc.OrderBooks {
		for _, o := range append(book.Bids, book.Asks...) {
			if o.ID == orderID {
				found = o
				break
			}
		}
		if found != nil {
			break
		}
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "order not found")
		return
	}

	asset, ok := s.bc.Assets[found.AssetID]
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if asset.Issuer != issuerKey {
		writeError(w, http.StatusForbidden, "only the asset issuer may reject orders")
		return
	}
	if found.Status != gonetwork.OrderStatusOpen {
		writeError(w, http.StatusConflict, "order is not open")
		return
	}

	found.Status = gonetwork.OrderStatusCancelled

	s.bc.EmitEvent(gonetwork.EventOrderCancelled, map[string]any{
		"order_id": orderID,
		"asset_id": found.AssetID,
		"reason":   "rejected_by_issuer",
	})
	s.bc.SealBlock(nil, []gonetwork.OrderTransaction{{Order: *found, IsCancellation: true}}, nil)

	writeJSON(w, http.StatusOK, map[string]string{
		"order_id": orderID,
		"status":   "rejected",
	})
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
		AssetID    string                        `json:"asset_id"`
		ActionType gonetwork.CorporateActionType `json:"action_type"`
		RecordDate int64                         `json:"record_date"`
		Parameters map[string]interface{}        `json:"parameters"`
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

// ---------------------------------------------------------------------------
// SPV management
// ---------------------------------------------------------------------------

// handleListSPV returns all SPVs that the authenticated wallet administers.
// GET /v1/spv
func (s *Server) handleListSPV(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)
	out := make([]*gonetwork.SPVWrapper, 0)
	for _, spv := range s.bc.SPVs {
		if spv.SPVAdminKey == walletKey {
			out = append(out, spv)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCreateSPV creates a new SPVWrapper signed by the authenticated wallet.
// POST /v1/spv
// Body: { signed_spv: <SPVWrapper> }
func (s *Server) handleCreateSPV(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SignedSPV *gonetwork.SPVWrapper `json:"signed_spv"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.SignedSPV == nil {
		writeError(w, http.StatusBadRequest, "signed_spv is required")
		return
	}

	pubKey, err := gonetwork.PublicKeyFromString(req.SignedSPV.SPVAdminKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid SPVAdminKey in signed_spv")
		return
	}
	if !req.SignedSPV.VerifySignature(pubKey) {
		writeError(w, http.StatusUnauthorized, "signed_spv signature verification failed")
		return
	}

	if _, exists := s.bc.SPVs[req.SignedSPV.ID]; exists {
		writeError(w, http.StatusConflict, "SPV with this ID already exists")
		return
	}
	s.bc.SPVs[req.SignedSPV.ID] = req.SignedSPV
	writeJSON(w, http.StatusCreated, req.SignedSPV)
}

// handleUpdateSPVNAV updates the NAV of an SPV the authenticated wallet administers.
// POST /v1/spv/{id}/nav
// Body: { signed_tx: <SPVTransaction> }
func (s *Server) handleUpdateSPVNAV(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)
	spvID := r.PathValue("id")

	var req struct {
		SignedTx *gonetwork.SPVTransaction `json:"signed_tx"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.SignedTx == nil {
		writeError(w, http.StatusBadRequest, "signed_tx is required")
		return
	}

	spv, ok := s.bc.SPVs[spvID]
	if !ok {
		writeError(w, http.StatusNotFound, "SPV not found")
		return
	}
	if spv.SPVAdminKey != walletKey {
		writeError(w, http.StatusForbidden, "only the SPV admin may update NAV")
		return
	}

	pubKey, err := gonetwork.PublicKeyFromString(spv.SPVAdminKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SPV has invalid admin key")
		return
	}
	if !req.SignedTx.VerifySignature(pubKey) {
		writeError(w, http.StatusUnauthorized, "signed_tx signature verification failed")
		return
	}
	if req.SignedTx.Type != gonetwork.SPVTxTypeNAVUpdate {
		writeError(w, http.StatusBadRequest, "signed_tx must be nav_update type")
		return
	}

	spv.NAV = req.SignedTx.NewNAV
	spv.NAVUpdatedAt = req.SignedTx.EffectiveAt
	writeJSON(w, http.StatusOK, spv)
}

// ---------------------------------------------------------------------------
// Prospectus Exemption endpoints
// ---------------------------------------------------------------------------

// handleRegisterExemption creates a ProspectusExemption for an asset, enabling
// the 149-retail-investor-per-jurisdiction cap to be enforced in Validate.
// Only the asset issuer may register an exemption; only one exemption is allowed
// per asset (attempt to overwrite returns 409).
//
// POST /v1/assets/{id}/exemption
func (s *Server) handleRegisterExemption(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)
	assetID := r.PathValue("id")

	asset, ok := s.bc.Assets[assetID]
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if asset.Issuer != walletKey {
		writeError(w, http.StatusForbidden, "only the asset issuer may register an exemption")
		return
	}
	if _, exists := s.bc.ProspectusExemptions[assetID]; exists {
		writeError(w, http.StatusConflict, "exemption already registered for this asset")
		return
	}

	var req struct {
		Basis                    string   `json:"basis"`
		MaxRetailPerJurisdiction int      `json:"max_retail_per_jurisdiction"`
		MaxTicketSizeEUR         float64  `json:"max_ticket_size_eur"`
		JurisdictionCoverage     []string `json:"jurisdiction_coverage"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid exemption payload")
		return
	}
	if req.Basis == "" {
		writeError(w, http.StatusBadRequest, "basis is required")
		return
	}
	if req.MaxRetailPerJurisdiction <= 0 {
		req.MaxRetailPerJurisdiction = 149 // EU Prospectus Regulation default
	}

	pe := gonetwork.NewProspectusExemption(
		assetID,
		gonetwork.ExemptionBasis(req.Basis),
		req.MaxRetailPerJurisdiction,
		req.JurisdictionCoverage,
	)
	s.bc.ProspectusExemptions[assetID] = pe
	writeJSON(w, http.StatusCreated, pe)
}

// handleGetExemption returns the ProspectusExemption for an asset, including
// live retail_holders_by_jurisdiction counts rebuilt at the end of each block.
//
// GET /v1/assets/{id}/exemption
func (s *Server) handleGetExemption(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	pe, ok := s.bc.ProspectusExemptions[assetID]
	if !ok {
		writeError(w, http.StatusNotFound, "no exemption registered for this asset")
		return
	}
	writeJSON(w, http.StatusOK, pe)
}

// ---------------------------------------------------------------------------
// Suitability Assessment endpoints
// ---------------------------------------------------------------------------

// handleSubmitSuitability records a MiFID II suitability assessment for a
// (wallet, asset) pair. Only compliance officers (jwtAdmin middleware) should
// call this endpoint after completing the required investor questionnaire.
//
// POST /v1/suitability
func (s *Server) handleSubmitSuitability(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WalletKey               string `json:"wallet_key"`
		AssetID                 string `json:"asset_id"`
		HasSufficientKnowledge  bool   `json:"has_sufficient_knowledge"`
		HasSufficientExperience bool   `json:"has_sufficient_experience"`
		CanAbsorbLoss           bool   `json:"can_absorb_loss"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid suitability payload")
		return
	}
	if req.WalletKey == "" || req.AssetID == "" {
		writeError(w, http.StatusBadRequest, "wallet_key and asset_id are required")
		return
	}

	suitable := req.HasSufficientKnowledge && req.HasSufficientExperience && req.CanAbsorbLoss

	sa := &gonetwork.SuitabilityAssessment{
		WalletPublicKey:         req.WalletKey,
		AssetID:                 req.AssetID,
		HasSufficientKnowledge:  req.HasSufficientKnowledge,
		HasSufficientExperience: req.HasSufficientExperience,
		CanAbsorbLoss:           req.CanAbsorbLoss,
		Suitable:                suitable,
		AssessedAt:              time.Now().Unix(),
	}

	key := gonetwork.SuitabilityKey(req.WalletKey, req.AssetID)
	s.bc.SuitabilityAssessments[key] = sa
	writeJSON(w, http.StatusCreated, sa)
}

// handleGetSuitability returns the suitability assessment for a given
// (walletKey, assetID) pair. Returns 404 if no assessment has been submitted.
//
// GET /v1/suitability/{walletKey}/{assetID}
func (s *Server) handleGetSuitability(w http.ResponseWriter, r *http.Request) {
	walletKey := r.PathValue("walletKey")
	assetID := r.PathValue("assetID")
	key := gonetwork.SuitabilityKey(walletKey, assetID)
	sa, ok := s.bc.SuitabilityAssessments[key]
	if !ok {
		writeError(w, http.StatusNotFound, "no suitability assessment found")
		return
	}
	writeJSON(w, http.StatusOK, sa)
}
