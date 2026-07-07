package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
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
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024) // 4 KB — prevents DoS via oversized payloads
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
		auditLog(AuditEntry{
			Action:    AuditAuthFailure,
			ActorKey:  auditKeyFingerprint(req.WalletKey),
			Outcome:   "fail",
			IPAddress: auditIP(r.RemoteAddr),
			Details:   map[string]string{"reason": "challenge not found or expired"},
		})
		writeError(w, http.StatusUnauthorized, "challenge not found or expired")
		return
	}
	if !gonetwork.VerifySignatureBytes(pub, []byte(req.Challenge), sig) {
		auditLog(AuditEntry{
			Action:    AuditAuthFailure,
			ActorKey:  auditKeyFingerprint(req.WalletKey),
			Outcome:   "fail",
			IPAddress: auditIP(r.RemoteAddr),
			Details:   map[string]string{"reason": "signature verification failed"},
		})
		writeError(w, http.StatusUnauthorized, "signature verification failed")
		return
	}

	// Enrich the access token with KYC and registration context.
	var investorClass, jurisdiction, kycStatus, regStatus string
	var kycExp int64
	termsAccepted := false

	if att, ok := s.bc.Credentials[req.WalletKey]; ok {
		investorClass = string(att.InvestorClass)
		jurisdiction = att.Jurisdiction
		kycStatus = string(att.KYCStatus)
		kycExp = att.ExpiresAt
	}
	if rec := s.RegRegistry.Get(req.WalletKey); rec != nil {
		regStatus = string(rec.Status)
		termsAccepted = rec.Consents.TermsOfServiceAcceptedAt > 0
		if jurisdiction == "" {
			jurisdiction = rec.Jurisdiction
		}
	}

	token, err := s.issueJWTWithClaims(req.WalletKey, investorClass, jurisdiction,
		kycStatus, kycExp, regStatus, termsAccepted)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}
	refreshToken, err := s.issueRefreshToken(req.WalletKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue refresh token")
		return
	}
	auditLog(AuditEntry{
		Action:    AuditAuthSuccess,
		ActorKey:  auditKeyFingerprint(req.WalletKey),
		Outcome:   "ok",
		IPAddress: auditIP(r.RemoteAddr),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"token":         token,
		"refresh_token": refreshToken,
		"expires_in":    900,
	})
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
		meta.DTI = req.Metadata["dti"]
		meta.DLI = req.Metadata["dli"]
		meta.Jurisdiction = req.Metadata["jurisdiction"]
		meta.CompanyName = req.Metadata["company_name"]
		meta.DividendTerms = req.Metadata["dividend_terms"]
		meta.LegalDocHash = req.Metadata["legal_doc_hash"]
	}
	// ISO 6166 structural validation — rejects malformed ISINs at creation time.
	if err := gonetwork.ValidateISIN(meta.ISIN); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// ISO 24165 structural validation for optional DTI/DLI metadata.
	if err := gonetwork.ValidateDTI(meta.DTI); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := gonetwork.ValidateDTI(meta.DLI); err != nil {
		writeError(w, http.StatusBadRequest, "invalid DLI: "+err.Error())
		return
	}

	// Map asset_class string to AssetType.
	classMap := map[string]gonetwork.AssetType{
		"equity":             gonetwork.AssetTypeEquity,
		"bond":               gonetwork.AssetTypeDebt,
		"debt":               gonetwork.AssetTypeDebt,
		"fund":               gonetwork.AssetTypeFundUnit,
		"fund_unit":          gonetwork.AssetTypeFundUnit,
		"warrant":            gonetwork.AssetTypeWarrant,
		"convertible":        gonetwork.AssetTypeConvertible,
		"participation_note": gonetwork.AssetTypeParticipationNote,
		"depositary_receipt": gonetwork.AssetTypeDepositaryReceipt,
		"real_estate":        gonetwork.AssetTypeEquity,
		"commodity":          gonetwork.AssetTypeEquity,
		"other":              gonetwork.AssetTypeEquity,
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

	// A-04: Participation notes require SPV admin countersignature before supply
	// is released. Leave CirculatingSupply = 0 and create no issuer holding.
	// The POST /v1/assets/{id}/countersign endpoint releases supply.
	if assetType != gonetwork.AssetTypeParticipationNote {
		// For all other asset types, create the issuer's initial holding at full
		// supply so they can immediately place ask orders and initiate transfers.
		issuerHoldingKey := gonetwork.HoldingKey(walletKey, assetID)
		s.bc.Holdings[issuerHoldingKey] = &gonetwork.AssetHolding{
			AssetID:  assetID,
			HolderID: walletKey,
			Balance:  req.TotalSupply,
		}
		a.CirculatingSupply = req.TotalSupply
	}

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

func parseRFQSide(raw string) (gonetwork.OrderSide, error) {
	switch raw {
	case "buy":
		return gonetwork.OrderSideBid, nil
	case "sell":
		return gonetwork.OrderSideAsk, nil
	default:
		return "", fmt.Errorf("side must be \"buy\" or \"sell\"")
	}
}

// handleCreateRFQRequest creates a new RFQ request on behalf of the authenticated wallet.
// POST /v1/rfq/requests
func (s *Server) handleCreateRFQRequest(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)
	if reg := s.RegRegistry.Get(walletKey); reg == nil || reg.Status != gonetwork.RegistrationStatusApproved {
		writeError(w, http.StatusForbidden, "registration approval required to create RFQ requests")
		return
	}
	var req struct {
		AssetID    string  `json:"asset_id"`
		Side       string  `json:"side"`
		Quantity   float64 `json:"quantity"`
		LimitPrice float64 `json:"limit_price"`
		TTLSeconds int64   `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
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
	side, err := parseRFQSide(req.Side)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Quantity <= 0 {
		writeError(w, http.StatusBadRequest, "quantity must be greater than zero")
		return
	}
	if req.LimitPrice < 0 {
		writeError(w, http.StatusBadRequest, "limit_price must be greater than or equal to zero")
		return
	}
	if req.TTLSeconds <= 0 {
		writeError(w, http.StatusBadRequest, "ttl_seconds must be greater than zero")
		return
	}
	now := time.Now()
	idHash := sha3.Sum256([]byte(fmt.Sprintf("%s:%s:%d", walletKey, req.AssetID, now.UnixNano())))
	rfqReq := gonetwork.RFQRequest{
		ID:           hex.EncodeToString(idHash[:]),
		AssetID:      req.AssetID,
		RequesterKey: walletKey,
		Side:         side,
		Quantity:     req.Quantity,
		LimitPrice:   req.LimitPrice,
		ExpiresAt:    now.Unix() + req.TTLSeconds,
		Status:       gonetwork.RFQRequestStatusOpen,
		CreatedAt:    now.Unix(),
	}
	rfqTx := gonetwork.RFQTransaction{
		Tx:      gonetwork.Transaction{Sender: walletKey, Receiver: req.AssetID, RequiredSigs: 0, Nonce: now.UnixNano()},
		Action:  gonetwork.RFQActionRequest,
		Request: rfqReq,
	}
	s.bc.SealRFQBlock([]gonetwork.RFQTransaction{rfqTx})
	writeJSON(w, http.StatusCreated, rfqReq)
}

// handleListRFQRequests lists requests visible to the caller.
// GET /v1/rfq/requests?assetID=
func (s *Server) handleListRFQRequests(w http.ResponseWriter, r *http.Request) {
	callerKey := walletFromCtx(r)
	assetFilter := r.URL.Query().Get("assetID")
	out := make([]gonetwork.RFQRequest, 0)
	for _, req := range s.bc.RFQRequests {
		if req == nil {
			continue
		}
		if assetFilter != "" && req.AssetID != assetFilter {
			continue
		}
		if req.RequesterKey == callerKey || s.bc.MarketMakerRegistry.IsDesignatedMarketMaker(req.AssetID, callerKey) {
			out = append(out, *req)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

// handleCreateRFQQuote records a dealer quote against an RFQ request.
// POST /v1/rfq/requests/{id}/quotes
func (s *Server) handleCreateRFQQuote(w http.ResponseWriter, r *http.Request) {
	callerKey := walletFromCtx(r)
	if reg := s.RegRegistry.Get(callerKey); reg == nil || reg.Status != gonetwork.RegistrationStatusApproved {
		writeError(w, http.StatusForbidden, "registration approval required to submit RFQ quotes")
		return
	}
	requestID := r.PathValue("id")
	rfqReq := s.bc.RFQRequests[requestID]
	if rfqReq == nil {
		writeError(w, http.StatusNotFound, "RFQ request not found")
		return
	}
	if !s.bc.MarketMakerRegistry.IsDesignatedMarketMaker(rfqReq.AssetID, callerKey) {
		writeError(w, http.StatusForbidden, "wallet is not a designated market maker for this asset")
		return
	}
	var req struct {
		Price      float64 `json:"price"`
		Quantity   float64 `json:"quantity"`
		TTLSeconds int64   `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Price <= 0 || req.Quantity <= 0 || req.TTLSeconds <= 0 {
		writeError(w, http.StatusBadRequest, "price, quantity, and ttl_seconds must be greater than zero")
		return
	}
	now := time.Now()
	idHash := sha3.Sum256([]byte(fmt.Sprintf("%s:%s:%d", callerKey, requestID, now.UnixNano())))
	quote := gonetwork.RFQQuote{
		ID:        hex.EncodeToString(idHash[:]),
		RequestID: requestID,
		DealerKey: callerKey,
		Price:     req.Price,
		Quantity:  req.Quantity,
		ExpiresAt: now.Unix() + req.TTLSeconds,
		Status:    gonetwork.RFQQuoteStatusActive,
		CreatedAt: now.Unix(),
	}
	rfqTx := gonetwork.RFQTransaction{
		Tx:     gonetwork.Transaction{Sender: callerKey, Receiver: requestID, RequiredSigs: 0, Nonce: now.UnixNano()},
		Action: gonetwork.RFQActionQuote,
		Quote:  quote,
	}
	s.bc.SealRFQBlock([]gonetwork.RFQTransaction{rfqTx})
	writeJSON(w, http.StatusCreated, quote)
}

// handleListRFQQuotes lists quotes for an RFQ request; requester only.
// GET /v1/rfq/requests/{id}/quotes
func (s *Server) handleListRFQQuotes(w http.ResponseWriter, r *http.Request) {
	callerKey := walletFromCtx(r)
	requestID := r.PathValue("id")
	rfqReq := s.bc.RFQRequests[requestID]
	if rfqReq == nil {
		writeError(w, http.StatusNotFound, "RFQ request not found")
		return
	}
	if rfqReq.RequesterKey != callerKey {
		writeError(w, http.StatusForbidden, "only the requester may view RFQ quotes")
		return
	}
	out := make([]gonetwork.RFQQuote, 0, len(s.bc.RFQQuotes[requestID]))
	for _, quote := range s.bc.RFQQuotes[requestID] {
		if quote != nil {
			out = append(out, *quote)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"request_id": requestID, "quotes": out})
}

// handleAcceptRFQQuote accepts a quote for an RFQ request; requester only.
// POST /v1/rfq/requests/{id}/accept
func (s *Server) handleAcceptRFQQuote(w http.ResponseWriter, r *http.Request) {
	callerKey := walletFromCtx(r)
	requestID := r.PathValue("id")
	rfqReq := s.bc.RFQRequests[requestID]
	if rfqReq == nil {
		writeError(w, http.StatusNotFound, "RFQ request not found")
		return
	}
	if rfqReq.RequesterKey != callerKey {
		writeError(w, http.StatusForbidden, "only the requester may accept RFQ quotes")
		return
	}
	if rfqReq.Status == gonetwork.RFQRequestStatusAccepted {
		writeError(w, http.StatusConflict, "RFQ request has already been accepted")
		return
	}
	if rfqReq.Status == gonetwork.RFQRequestStatusCancelled || rfqReq.Status == gonetwork.RFQRequestStatusExpired {
		writeError(w, http.StatusConflict, "RFQ request is not open")
		return
	}
	var req struct {
		QuoteID string `json:"quote_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.QuoteID == "" {
		writeError(w, http.StatusBadRequest, "quote_id is required")
		return
	}
	var acceptedQuote *gonetwork.RFQQuote
	for _, quote := range s.bc.RFQQuotes[requestID] {
		if quote != nil && quote.ID == req.QuoteID {
			acceptedQuote = quote
			break
		}
	}
	if acceptedQuote == nil {
		writeError(w, http.StatusNotFound, "RFQ quote not found")
		return
	}
	if acceptedQuote.Status != gonetwork.RFQQuoteStatusActive || acceptedQuote.IsExpired() {
		writeError(w, http.StatusConflict, "RFQ quote is not active")
		return
	}
	asset, ok := s.bc.Assets[rfqReq.AssetID]
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	quantity := rfqReq.Quantity
	if acceptedQuote.Quantity < quantity {
		quantity = acceptedQuote.Quantity
	}
	buyerKey := rfqReq.RequesterKey
	sellerKey := acceptedQuote.DealerKey
	if rfqReq.Side == gonetwork.OrderSideAsk {
		buyerKey = acceptedQuote.DealerKey
		sellerKey = rfqReq.RequesterKey
	}
	if buyerKey == acceptedQuote.DealerKey {
		if err := gonetwork.CheckMarketMakerPositionLimit(s.bc, acceptedQuote.DealerKey, asset.ID, quantity); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
	}
	if err := s.bc.ValidateRFQAcceptCompliance(buyerKey, sellerKey, asset, quantity, acceptedQuote.Price, "rfq:"+acceptedQuote.ID); err != nil {
		status := http.StatusForbidden
		if strings.HasPrefix(err.Error(), "FATF Travel Rule:") {
			status = http.StatusUnprocessableEntity
		}
		if strings.HasPrefix(err.Error(), "AML screening failed:") {
			status = http.StatusInternalServerError
		}
		writeError(w, status, err.Error())
		return
	}
	now := time.Now()
	rfqTx := gonetwork.RFQTransaction{
		Tx:       gonetwork.Transaction{Sender: callerKey, Receiver: acceptedQuote.DealerKey, RequiredSigs: 0, Nonce: now.UnixNano()},
		Action:   gonetwork.RFQActionAccept,
		Request:  *rfqReq,
		AcceptID: acceptedQuote.ID,
	}
	s.bc.SealRFQBlock([]gonetwork.RFQTransaction{rfqTx})
	writeJSON(w, http.StatusOK, map[string]any{"request_id": requestID, "quote_id": acceptedQuote.ID, "status": "accepted"})
}

// handleCancelRFQRequest cancels an open RFQ request; requester only.
// DELETE /v1/rfq/requests/{id}
func (s *Server) handleCancelRFQRequest(w http.ResponseWriter, r *http.Request) {
	callerKey := walletFromCtx(r)
	requestID := r.PathValue("id")
	rfqReq := s.bc.RFQRequests[requestID]
	if rfqReq == nil {
		writeError(w, http.StatusNotFound, "RFQ request not found")
		return
	}
	if rfqReq.RequesterKey != callerKey {
		writeError(w, http.StatusForbidden, "only the requester may cancel an RFQ request")
		return
	}
	if rfqReq.Status == gonetwork.RFQRequestStatusAccepted || rfqReq.Status == gonetwork.RFQRequestStatusExpired {
		writeError(w, http.StatusConflict, "RFQ request is not open")
		return
	}
	now := time.Now()
	rfqTx := gonetwork.RFQTransaction{
		Tx:      gonetwork.Transaction{Sender: callerKey, Receiver: requestID, RequiredSigs: 0, Nonce: now.UnixNano()},
		Action:  gonetwork.RFQActionCancel,
		Request: *rfqReq,
	}
	s.bc.SealRFQBlock([]gonetwork.RFQTransaction{rfqTx})
	writeJSON(w, http.StatusOK, map[string]any{"request_id": requestID, "status": "cancelled"})
}

// handlePlaceOrder creates and stores a new order on behalf of the authenticated wallet.
// POST /v1/orders
// Body: {"asset_id":"...","side":"buy","type":"limit","price":10.50,"quantity":100}
func (s *Server) handlePlaceOrder(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)

	// Require approved registration before any order can be placed.
	if reg := s.RegRegistry.Get(walletKey); reg == nil || reg.Status != gonetwork.RegistrationStatusApproved {
		writeError(w, http.StatusForbidden, "registration approval required to place orders")
		return
	}

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
	asset, ok := s.bc.Assets[req.AssetID]
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	// A-04: Block ask orders on participation notes that have not yet been
	// countersigned by the SPV administrator.
	if asset.AssetType == gonetwork.AssetTypeParticipationNote && asset.CirculatingSupply == 0 && req.Side == "sell" {
		writeError(w, http.StatusConflict, "asset awaiting SPV admin countersignature: ask orders not permitted until supply is released")
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
	var req struct {
		DealID                string                           `json:"deal_id,omitempty"`
		AnchorWalletKey       string                           `json:"anchor_wallet_key"`
		CommitmentAmount      float64                          `json:"commitment_amount"`
		Currency              string                           `json:"currency"`
		CommittedAt           int64                            `json:"committed_at,omitempty"`
		AnchorSignature       string                           `json:"anchor_signature"`
		CredentialAttestation *gonetwork.CredentialAttestation `json:"credential_attestation,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid anchor payload")
		return
	}
	if req.AnchorWalletKey == "" || req.CommitmentAmount <= 0 || req.AnchorSignature == "" {
		writeError(w, http.StatusBadRequest, "anchor_wallet_key, commitment_amount and anchor_signature are required")
		return
	}
	if req.DealID != "" && req.DealID != dealID {
		writeError(w, http.StatusBadRequest, "deal_id must match path parameter")
		return
	}

	anchorSig, err := base64.StdEncoding.DecodeString(req.AnchorSignature)
	if err != nil {
		anchorSig, err = base64.RawURLEncoding.DecodeString(req.AnchorSignature)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid anchor_signature encoding")
			return
		}
	}

	anchor := &gonetwork.DealAnchor{
		DealID:                dealID,
		AnchorWalletKey:       req.AnchorWalletKey,
		CommitmentAmount:      req.CommitmentAmount,
		Currency:              req.Currency,
		CommittedAt:           req.CommittedAt,
		CredentialAttestation: req.CredentialAttestation,
		AnchorSignature:       anchorSig,
	}
	pub, err := gonetwork.PublicKeyFromString(anchor.AnchorWalletKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid anchor wallet key")
		return
	}
	if err := d.AttachAnchor(anchor, pub, nil); err != nil {
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

func prometheusEscapeLabelValue(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}

// handleMetrics exports Prometheus text metrics for operational monitoring.
// GET /metrics
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	modeRejectByPath := s.bc.ConsensusModeRejectByPathSnapshot()
	duplicateRejectByReason := s.bc.DuplicateTxRejectByReasonSnapshot()

	pathLabels := make([]string, 0, len(modeRejectByPath))
	for path := range modeRejectByPath {
		pathLabels = append(pathLabels, path)
	}
	sort.Strings(pathLabels)

	reasonLabels := make([]string, 0, len(duplicateRejectByReason))
	for reason := range duplicateRejectByReason {
		reasonLabels = append(reasonLabels, reason)
	}
	sort.Strings(reasonLabels)

	var out strings.Builder
	out.WriteString("# HELP gonetwork_consensus_mode_rejections_total Number of consensus mode path rejections.\n")
	out.WriteString("# TYPE gonetwork_consensus_mode_rejections_total counter\n")
	out.WriteString(fmt.Sprintf("gonetwork_consensus_mode_rejections_total %d\n", s.bc.ConsensusModeRejectCount()))

	out.WriteString("# HELP gonetwork_consensus_mode_rejections_by_path_total Number of consensus mode path rejections by path label.\n")
	out.WriteString("# TYPE gonetwork_consensus_mode_rejections_by_path_total counter\n")
	for _, path := range pathLabels {
		out.WriteString(fmt.Sprintf(
			"gonetwork_consensus_mode_rejections_by_path_total{path=\"%s\"} %d\n",
			prometheusEscapeLabelValue(path),
			modeRejectByPath[path],
		))
	}

	out.WriteString("# HELP gonetwork_duplicate_transaction_rejections_total Number of rejected duplicate transaction hashes.\n")
	out.WriteString("# TYPE gonetwork_duplicate_transaction_rejections_total counter\n")
	out.WriteString(fmt.Sprintf("gonetwork_duplicate_transaction_rejections_total %d\n", s.bc.DuplicateTxHashRejectCount()))

	out.WriteString("# HELP gonetwork_duplicate_transaction_rejections_by_reason_total Number of rejected duplicate transaction hashes by reason label.\n")
	out.WriteString("# TYPE gonetwork_duplicate_transaction_rejections_by_reason_total counter\n")
	for _, reason := range reasonLabels {
		out.WriteString(fmt.Sprintf(
			"gonetwork_duplicate_transaction_rejections_by_reason_total{reason=\"%s\"} %d\n",
			prometheusEscapeLabelValue(reason),
			duplicateRejectByReason[reason],
		))
	}

	out.WriteString("# HELP gonetwork_consensus_mode_active Active consensus mode gauge (one-hot).\n")
	out.WriteString("# TYPE gonetwork_consensus_mode_active gauge\n")
	out.WriteString(fmt.Sprintf(
		"gonetwork_consensus_mode_active{mode=\"%s\"} 1\n",
		prometheusEscapeLabelValue(s.bc.ConsensusMode),
	))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(out.String()))
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
	s.commitIssuedCredential(att)

	writeJSON(w, http.StatusOK, map[string]any{
		"wallet_key":     att.WalletPublicKey,
		"investor_class": att.InvestorClass,
		"kyc_status":     att.KYCStatus,
		"expires_at":     att.ExpiresAt,
	})
}

// commitIssuedCredential propagates a freshly issued CredentialAttestation to
// the blockchain's credential store, auto-derives MiFID II suitability for
// professional / eligible-counterparty investors on existing complex
// instruments (G-07), emits EventCredentialIssued, and commits the credential
// on-chain via SealBlock. Every credential-issuing endpoint (KYC approval,
// registration review, future automated KYC) must call this so every
// CredentialAttestation carries a valid CredentialHash + RegistrySignature and
// is auditable as a CredentialTransaction, instead of only some paths doing so.
func (s *Server) commitIssuedCredential(att *gonetwork.CredentialAttestation) {
	s.bc.Credentials[att.WalletPublicKey] = att
	s.autoGrantSuitability(att)

	s.bc.EmitEvent(gonetwork.EventCredentialIssued, map[string]any{
		"wallet_key":     att.WalletPublicKey,
		"investor_class": att.InvestorClass,
		"kyc_status":     att.KYCStatus,
		"jurisdiction":   att.Jurisdiction,
		"expires_at":     att.ExpiresAt,
	})
	s.bc.SealBlock(nil, nil, []gonetwork.CredentialTransaction{{Attestation: *att}})

	// Phase 2: also emit a topic-scoped KYC claim via the same identity
	// registry, so this wallet is represented in the new claims model
	// immediately rather than only via the SynthesizeClaimsFromAttestation
	// adapter. Non-fatal on failure — the legacy attestation above is already
	// committed and remains fully sufficient for existing eligibility checks.
	if s.bc.IdentityRegistry != nil {
		validDays := int((att.ExpiresAt - time.Now().Unix()) / 86400)
		if validDays <= 0 {
			validDays = 1
		}
		claim, err := s.bc.IdentityRegistry.IssueClaim(
			att.WalletPublicKey, gonetwork.ClaimTopicKYC, string(att.InvestorClass), validDays,
		)
		if err != nil {
			log.Printf("commitIssuedCredential: failed to issue KYC claim for %s: %v", att.WalletPublicKey, err)
		} else {
			s.bc.SealClaimBlock([]gonetwork.ClaimTransaction{{Claim: *claim}}, nil)
		}
	}
}

// autoGrantSuitability implements G-07: for professional and
// eligible-counterparty investors, auto-derive a positive MiFID II
// suitability assessment for all existing complex instruments (warrants,
// convertibles) so they are not blocked at the transfer gate. Existing
// assessments are never overwritten.
func (s *Server) autoGrantSuitability(att *gonetwork.CredentialAttestation) {
	if att.InvestorClass != gonetwork.InvestorClassProfessional &&
		att.InvestorClass != gonetwork.InvestorClassEligibleCP {
		return
	}
	for assetID, asset := range s.bc.Assets {
		if asset.AssetType != gonetwork.AssetTypeWarrant && asset.AssetType != gonetwork.AssetTypeConvertible {
			continue
		}
		key := gonetwork.SuitabilityKey(att.WalletPublicKey, assetID)
		if _, exists := s.bc.SuitabilityAssessments[key]; exists {
			continue
		}
		s.bc.SuitabilityAssessments[key] = &gonetwork.SuitabilityAssessment{
			WalletPublicKey:         att.WalletPublicKey,
			AssetID:                 assetID,
			InstrumentClass:         asset.AssetType,
			HasSufficientKnowledge:  true,
			HasSufficientExperience: true,
			CanAbsorbLoss:           true,
			Suitable:                true,
			AssessedAt:              time.Now().Unix(),
		}
	}
}

// handlePaymentWebhook receives Modulr payment-received notifications.
// POST /v1/webhooks/payment
//
// In production (GH_ENV=production) ModulrProvider must be set and the
// HMAC-SHA256 signature in X-Mod-Nonce is always verified. When ModulrProvider
// is nil in production the request is rejected with 401 (F-2). In development
// the signature check is skipped when ModulrProvider is nil.
func (s *Server) handlePaymentWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	// F-2: In production, reject any request when ModulrProvider is nil —
	// there is no key material available to verify the signature.
	if s.ModulrProvider == nil && os.Getenv("GH_ENV") == "production" {
		writeError(w, http.StatusUnauthorized, "Modulr provider not configured")
		return
	}

	if s.ModulrProvider != nil {
		sig := r.Header.Get("X-Mod-Nonce")
		if sig == "" {
			writeError(w, http.StatusUnauthorized, "missing X-Mod-Nonce header")
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
		if s.ModulrProvider != nil {
			err = gonetwork.HandleWebhook(
				s.ModulrProvider,
				body,
				r.Header.Get("X-Mod-Nonce"),
				func() error {
					// ConfirmAndSettle confirms the payment and applies the DVP asset transfer.
					// HTTP 422 on mismatch tells Modulr this callback is permanently rejected.
					// HTTP 500 on other errors instructs Modulr to retry until the issue resolves.
					// HTTP 200 on nil error (unknown reference) prevents unnecessary retries.
					return s.bc.ConfirmAndSettle(event.Reference, event.Amount, event.Currency)
				},
			)
		} else {
			err = s.bc.ConfirmAndSettle(event.Reference, event.Amount, event.Currency)
		}
		if err != nil {
			if errors.Is(err, gonetwork.ErrInvalidWebhookSignature) {
				writeError(w, http.StatusUnauthorized, "invalid webhook signature")
				return
			}
			if errors.Is(err, gonetwork.ErrPaymentMismatch) {
				log.Printf("[payment] mismatch ref=%s: %v", event.Reference, err)
				writeError(w, http.StatusUnprocessableEntity, "payment mismatch")
				return
			}
			log.Printf("[payment] ConfirmAndSettle failed ref=%s: %v", event.Reference, err)
			writeError(w, http.StatusInternalServerError, "settlement failed")
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

// handlePontesWebhook receives Eurosystem Pontes CeBM settlement confirmations.
// POST /v1/webhooks/pontes
//
// The Pontes bridge signs each callback with HMAC-SHA256; the signature is in
// the X-Pontes-Signature header. When PontesProvider is nil this endpoint
// returns 501.
func (s *Server) handlePontesWebhook(w http.ResponseWriter, r *http.Request) {
	if s.PontesProvider == nil {
		writeError(w, http.StatusNotImplemented, "Pontes CeBM provider not configured")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	sig := r.Header.Get("X-Pontes-Signature")
	if sig == "" {
		writeError(w, http.StatusUnauthorized, "missing X-Pontes-Signature header")
		return
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

	if event.Type == "settlement.confirmed" && event.Reference != "" {
		err = gonetwork.HandleWebhook(
			s.PontesProvider,
			body,
			sig,
			func() error {
				// HTTP 422 on mismatch tells the Pontes bridge this callback is permanently rejected.
				// HTTP 500 on other errors instructs the Pontes bridge to retry.
				return s.bc.ConfirmAndSettle(event.Reference, event.Amount, event.Currency)
			},
		)
		if err != nil {
			if errors.Is(err, gonetwork.ErrInvalidWebhookSignature) {
				writeError(w, http.StatusUnauthorized, "invalid Pontes webhook signature")
				return
			}
			if errors.Is(err, gonetwork.ErrPaymentMismatch) {
				log.Printf("[pontes] mismatch ref=%s: %v", event.Reference, err)
				writeError(w, http.StatusUnprocessableEntity, "payment mismatch")
				return
			}
			log.Printf("[pontes] ConfirmAndSettle failed ref=%s: %v", event.Reference, err)
			writeError(w, http.StatusInternalServerError, "settlement failed")
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

// handleEURCWebhook receives Circle EURC on-chain transfer confirmations.
// POST /v1/webhooks/eurc
//
// Circle signs each notification with HMAC-SHA256; the signature is in the
// Circle-Signature header. When EURCProvider is nil this endpoint returns 501.
func (s *Server) handleEURCWebhook(w http.ResponseWriter, r *http.Request) {
	if s.EURCProvider == nil {
		writeError(w, http.StatusNotImplemented, "EURC provider not configured")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	sig := r.Header.Get("Circle-Signature")
	if sig == "" {
		writeError(w, http.StatusUnauthorized, "missing Circle-Signature header")
		return
	}

	// Circle uses a notifications envelope; extract the transfer event.
	var envelope struct {
		NotificationType string `json:"notificationType"`
		Transfer         *struct {
			ExternalRef string  `json:"externalRef"`
			Amount      float64 `json:"amount,string"`
			Currency    string  `json:"currency"`
		} `json:"transfer"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook payload")
		return
	}

	if envelope.NotificationType == "transfer.complete" &&
		envelope.Transfer != nil &&
		envelope.Transfer.ExternalRef != "" {
		err = gonetwork.HandleWebhook(
			s.EURCProvider,
			body,
			sig,
			func() error {
				// HTTP 422 on mismatch tells Circle this callback is permanently rejected.
				// HTTP 500 on other errors instructs Circle to retry.
				return s.bc.ConfirmAndSettle(
					envelope.Transfer.ExternalRef,
					envelope.Transfer.Amount,
					envelope.Transfer.Currency,
				)
			},
		)
		if err != nil {
			if errors.Is(err, gonetwork.ErrInvalidWebhookSignature) {
				writeError(w, http.StatusUnauthorized, "invalid EURC webhook signature")
				return
			}
			if errors.Is(err, gonetwork.ErrPaymentMismatch) {
				log.Printf("[eurc] mismatch ref=%s: %v", envelope.Transfer.ExternalRef, err)
				writeError(w, http.StatusUnprocessableEntity, "payment mismatch")
				return
			}
			log.Printf("[eurc] ConfirmAndSettle failed ref=%s: %v", envelope.Transfer.ExternalRef, err)
			writeError(w, http.StatusInternalServerError, "settlement failed")
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------------------
// Registration endpoints
// ---------------------------------------------------------------------------

// handleRefreshToken exchanges a valid refresh token for a new access token
// and a rotated refresh token (single-use rotation).
//
// POST /v1/auth/refresh
// Body: {"refresh_token":"<hex>"}
func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1*1024) // 1 KB — refresh token is a 64-char hex string
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token required")
		return
	}
	walletKey, ok := s.consumeRefreshToken(req.RefreshToken)
	if !ok {
		writeError(w, http.StatusUnauthorized, "refresh token invalid or expired")
		return
	}
	// Enrich with latest KYC / registration state.
	var investorClass, jurisdiction, kycStatus, regStatus string
	var kycExp int64
	termsAccepted := false

	if att, exists := s.bc.Credentials[walletKey]; exists {
		investorClass = string(att.InvestorClass)
		jurisdiction = att.Jurisdiction
		kycStatus = string(att.KYCStatus)
		kycExp = att.ExpiresAt
	}
	if rec := s.RegRegistry.Get(walletKey); rec != nil {
		regStatus = string(rec.Status)
		termsAccepted = rec.Consents.TermsOfServiceAcceptedAt > 0
		if jurisdiction == "" {
			jurisdiction = rec.Jurisdiction
		}
	}
	token, err := s.issueJWTWithClaims(walletKey, investorClass, jurisdiction,
		kycStatus, kycExp, regStatus, termsAccepted)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}
	newRefresh, err := s.issueRefreshToken(walletKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to rotate refresh token")
		return
	}
	auditLog(AuditEntry{
		Action:    AuditTokenRefresh,
		ActorKey:  auditKeyFingerprint(walletKey),
		Outcome:   "ok",
		IPAddress: auditIP(r.RemoteAddr),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"token":         token,
		"refresh_token": newRefresh,
		"expires_in":    900,
	})
}

// handleGetRegistrationStatus returns the registration state for any wallet
// without requiring a JWT.  Used by the frontend before login to decide
// whether to show the registration wizard.
//
// GET /v1/register/status?wallet_key=<base64>
func (s *Server) handleGetRegistrationStatus(w http.ResponseWriter, r *http.Request) {
	walletKey := r.URL.Query().Get("wallet_key")
	if walletKey == "" {
		writeError(w, http.StatusBadRequest, "wallet_key query parameter required")
		return
	}
	rec := s.RegRegistry.Get(walletKey)
	if rec == nil {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": string(gonetwork.RegistrationStatusUnregistered),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       string(rec.Status),
		"jurisdiction": rec.Jurisdiction,
		"terms_accepted": rec.Consents.TermsOfServiceAcceptedAt > 0 &&
			rec.Consents.PrivacyPolicyAcceptedAt > 0 &&
			rec.Consents.RiskWarningsAcceptedAt > 0,
		"submitted_at": rec.SubmittedAt,
		"reviewed_at":  rec.ReviewedAt,
	})
}

// handleAcceptTerms records T&C, Privacy Policy, and Risk Warning acceptances
// for the authenticated wallet.  Must be called before submitting a full
// registration.  May be called independently when new document versions are
// released.
//
// POST /v1/terms/accept
// Body: {"tos_version":"1.0","privacy_version":"1.0","risk_version":"1.0","marketing_consent":false}
func (s *Server) handleAcceptTerms(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)
	var req struct {
		TOSVersion       string `json:"tos_version"`
		PrivacyVersion   string `json:"privacy_version"`
		RiskVersion      string `json:"risk_version"`
		MarketingConsent bool   `json:"marketing_consent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TOSVersion == "" || req.PrivacyVersion == "" || req.RiskVersion == "" {
		writeError(w, http.StatusBadRequest, "tos_version, privacy_version and risk_version are required")
		return
	}
	rec := s.RegRegistry.Get(walletKey)
	if rec == nil {
		rec = &gonetwork.RegistrationRecord{
			WalletKey: walletKey,
			Status:    gonetwork.RegistrationStatusUnregistered,
		}
	}
	now := time.Now().Unix()
	rec.Consents.TermsOfServiceAcceptedAt = now
	rec.Consents.TermsOfServiceVersion = req.TOSVersion
	rec.Consents.PrivacyPolicyAcceptedAt = now
	rec.Consents.PrivacyPolicyVersion = req.PrivacyVersion
	rec.Consents.RiskWarningsAcceptedAt = now
	rec.Consents.RiskWarningsVersion = req.RiskVersion
	rec.Consents.MarketingConsent = req.MarketingConsent
	if rec.Status == gonetwork.RegistrationStatusUnregistered {
		rec.Status = gonetwork.RegistrationStatusTermsAccepted
	}
	s.RegRegistry.Upsert(rec)
	writeJSON(w, http.StatusOK, map[string]string{"status": string(rec.Status)})
}

// handleRegister submits or updates the full registration record for the
// authenticated wallet.  All fields required by Validate() must be present.
// On success the record moves to RegistrationStatusPendingReview and, if Onfido
// is configured, automatically initiates the KYC check.
//
// POST /v1/register
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64 KB — prevents DoS via oversized payloads
	walletKey := walletFromCtx(r)

	// Existing record preserved (allows partial updates / resubmission after rejection).
	rec := s.RegRegistry.Get(walletKey)
	if rec == nil {
		rec = &gonetwork.RegistrationRecord{
			WalletKey: walletKey,
			Status:    gonetwork.RegistrationStatusUnregistered,
		}
	}
	// Block resubmission of already-approved or suspended accounts.
	if rec.Status == gonetwork.RegistrationStatusApproved {
		writeError(w, http.StatusConflict, "registration already approved")
		return
	}
	if rec.Status == gonetwork.RegistrationStatusSuspended {
		writeError(w, http.StatusForbidden, "account suspended — contact compliance")
		return
	}

	var body struct {
		Personal struct {
			FullLegalName string `json:"full_legal_name"`
			DateOfBirth   string `json:"date_of_birth"`
			Nationality   string `json:"nationality"`
			TaxResidency  string `json:"tax_residency"`
			TaxIDNumber   string `json:"tax_id_number"`
		} `json:"personal"`
		Address struct {
			Line1    string `json:"line1"`
			Line2    string `json:"line2"`
			City     string `json:"city"`
			PostCode string `json:"post_code"`
			Country  string `json:"country"`
		} `json:"address"`
		Document struct {
			Type               string `json:"type"`
			IssuingCountry     string `json:"issuing_country"`
			ExpiryDate         string `json:"expiry_date"`
			DocumentHash       string `json:"document_hash"`
			ProofOfAddressHash string `json:"proof_of_address_hash"`
		} `json:"document"`
		Classification struct {
			Class                 string `json:"class"`
			LargeTradeFrequency   bool   `json:"large_trade_frequency"`
			PortfolioQualifies    bool   `json:"portfolio_qualifies"`
			ProfessionalExp       bool   `json:"professional_experience"`
			RelevantQualification bool   `json:"relevant_qualification"`
			NCAReg                string `json:"nca_reg"`
		} `json:"classification"`
		Consents struct {
			SourceOfFunds   string `json:"source_of_funds"`
			SourceOfWealth  string `json:"source_of_wealth"`
			NotPEP          bool   `json:"not_pep"`
			NotSanctioned   bool   `json:"not_sanctioned"`
			NotUBOAnonymous bool   `json:"not_ubo_anonymous"`
		} `json:"consents"`
		Jurisdiction string `json:"jurisdiction"`
		ValidForDays int    `json:"valid_for_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Populate record fields.
	rec.Personal = gonetwork.PersonalInfo{
		FullLegalName: body.Personal.FullLegalName,
		DateOfBirth:   body.Personal.DateOfBirth,
		Nationality:   body.Personal.Nationality,
		TaxResidency:  body.Personal.TaxResidency,
		TaxIDNumber:   body.Personal.TaxIDNumber,
	}
	rec.Address = gonetwork.AddressInfo{
		Line1:    body.Address.Line1,
		Line2:    body.Address.Line2,
		City:     body.Address.City,
		PostCode: body.Address.PostCode,
		Country:  body.Address.Country,
	}
	rec.Document = gonetwork.IdentityDocument{
		Type:               body.Document.Type,
		IssuingCountry:     body.Document.IssuingCountry,
		ExpiryDate:         body.Document.ExpiryDate,
		DocumentHash:       body.Document.DocumentHash,
		ProofOfAddressHash: body.Document.ProofOfAddressHash,
		UploadedAt:         time.Now().Unix(),
	}
	rec.Classification = gonetwork.InvestorClassificationRecord{
		Class:                 gonetwork.InvestorClass(body.Classification.Class),
		LargeTradeFrequency:   body.Classification.LargeTradeFrequency,
		PortfolioQualifies:    body.Classification.PortfolioQualifies,
		ProfessionalExp:       body.Classification.ProfessionalExp,
		RelevantQualification: body.Classification.RelevantQualification,
		NCAReg:                body.Classification.NCAReg,
	}
	// Merge AML consents (T&C timestamps already stored via /terms/accept).
	rec.Consents.SourceOfFundsDeclaration = body.Consents.SourceOfFunds
	rec.Consents.SourceOfWealthDeclaration = body.Consents.SourceOfWealth
	rec.Consents.NotPEP = body.Consents.NotPEP
	rec.Consents.NotSanctioned = body.Consents.NotSanctioned
	rec.Consents.NotUBOAnonymous = body.Consents.NotUBOAnonymous
	rec.Jurisdiction = body.Jurisdiction
	if body.ValidForDays > 0 {
		rec.ValidForDays = body.ValidForDays
	} else {
		rec.ValidForDays = 365
	}

	if errs := rec.Validate(); len(errs) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":  "validation failed",
			"fields": errs,
		})
		return
	}

	// Reject duplicate document submissions — the same document hash must not appear
	// on more than one registration record. Prevents identity document reuse / fraud.
	if docHash := rec.Document.DocumentHash; docHash != "" {
		for _, existing := range s.RegRegistry.All() {
			if existing.WalletKey != walletKey && existing.Document.DocumentHash == docHash {
				writeError(w, http.StatusConflict, "document hash already registered to another account")
				return
			}
		}
	}

	rec.Status = gonetwork.RegistrationStatusPendingReview
	rec.SubmittedAt = time.Now().Unix()
	s.RegRegistry.Upsert(rec)

	// If the OperatorRegistry is configured and T&C timestamps are set,
	// also enqueue a KYC request so the operator sees it in the KYC queue.
	if s.OperatorRegistry != nil {
		_ = s.OperatorRegistry.RequestKYC(
			walletKey,
			rec.Classification.Class,
			rec.Jurisdiction,
			rec.ValidForDays,
		)
	}

	auditLog(AuditEntry{
		Action:    AuditRegistrationSubmitted,
		ActorKey:  auditKeyFingerprint(walletKey),
		Outcome:   "ok",
		IPAddress: auditIP(r.RemoteAddr),
		Details:   map[string]string{"jurisdiction": rec.Jurisdiction},
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"status":       string(rec.Status),
		"submitted_at": rec.SubmittedAt,
		"message":      "Registration submitted and under review.",
	})
}

// handleAdminRegistrationList returns all pending registrations for operator review.
//
// GET /v1/admin/registrations
func (s *Server) handleAdminRegistrationList(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("status")
	var records []*gonetwork.RegistrationRecord
	if filter == "" || filter == "pending_review" {
		records = s.RegRegistry.ListPending()
	} else {
		all := s.RegRegistry.All()
		for _, rec := range all {
			if string(rec.Status) == filter {
				records = append(records, rec)
			}
		}
	}
	// Redact PII before sending to admin UI — operator sees names and status but not doc hashes / TINs.
	redacted := make([]*gonetwork.RegistrationRecord, len(records))
	for i, r := range records {
		redacted[i] = r.RedactPII()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(redacted),
		"records": redacted,
	})
}

// handleAdminRegistrationReview approves or rejects a registration record.
// On approval, the KYC credential is also issued if OperatorRegistry is set.
//
// POST /v1/admin/registrations/{key}/review
// Body: {"action":"approve"|"reject","rejection_reason":"..."}
func (s *Server) handleAdminRegistrationReview(w http.ResponseWriter, r *http.Request) {
	targetKey := r.PathValue("key")
	adminKey := walletFromCtx(r)

	var req struct {
		Action          string `json:"action"`           // "approve" | "reject"
		RejectionReason string `json:"rejection_reason"` // required when action == "reject"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Action != "approve" && req.Action != "reject" {
		writeError(w, http.StatusBadRequest, "action must be 'approve' or 'reject'")
		return
	}
	if req.Action == "reject" && req.RejectionReason == "" {
		writeError(w, http.StatusBadRequest, "rejection_reason is required when rejecting")
		return
	}

	rec := s.RegRegistry.Get(targetKey)
	if rec == nil {
		writeError(w, http.StatusNotFound, "registration record not found")
		return
	}

	if req.Action == "approve" {
		if err := s.RegRegistry.UpdateStatus(targetKey,
			gonetwork.RegistrationStatusApproved, adminKey, ""); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Issue the on-chain KYC credential through the canonical signing path
		// (NewIdentityCredential -> ToAttestation), never by constructing a
		// CredentialAttestation literal directly — a hand-built attestation has
		// no CredentialHash/RegistrySignature and would fail ValidateBlock's
		// registry-signature check if ever gossiped or replayed.
		validDays := rec.ValidForDays
		if validDays <= 0 {
			validDays = 365
		}
		var att *gonetwork.CredentialAttestation
		var credErr error
		switch {
		case s.OperatorRegistry != nil:
			// Prefer ApproveKYC so any queued /v1/kyc/request entry is cleared
			// from the admin pending-review queue. Fall back to direct issuance
			// if no matching pending request exists (e.g. the registration was
			// submitted before OperatorRegistry was configured on this node).
			att, credErr = s.OperatorRegistry.ApproveKYC(targetKey)
			if credErr != nil {
				att, credErr = s.OperatorRegistry.IssueCredential(targetKey, rec.Classification.Class, rec.Jurisdiction, validDays)
			}
		case s.bc.IdentityRegistry != nil:
			att, credErr = s.bc.IdentityRegistry.IssueCredential(targetKey, rec.Classification.Class, rec.Jurisdiction, validDays)
		default:
			credErr = fmt.Errorf("no identity registry configured on this node")
		}
		if credErr != nil {
			// Non-fatal: registration is approved even if credential issuance fails.
			// Retry via /v1/admin/kyc/approve once an identity registry is available.
			writeJSON(w, http.StatusOK, map[string]string{
				"status":  "approved",
				"warning": "registration approved but credential issuance failed: " + credErr.Error(),
			})
			return
		}
		s.commitIssuedCredential(att)
		auditLog(AuditEntry{
			Action:     AuditRegistrationApproved,
			ActorKey:   auditKeyFingerprint(adminKey),
			SubjectKey: auditKeyFingerprint(targetKey),
			Outcome:    "ok",
			IPAddress:  auditIP(r.RemoteAddr),
		})
		writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
	} else {
		if err := s.RegRegistry.UpdateStatus(targetKey,
			gonetwork.RegistrationStatusRejected, adminKey, req.RejectionReason); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		auditLog(AuditEntry{
			Action:     AuditRegistrationRejected,
			ActorKey:   auditKeyFingerprint(adminKey),
			SubjectKey: auditKeyFingerprint(targetKey),
			Outcome:    "ok",
			IPAddress:  auditIP(r.RemoteAddr),
			Details:    map[string]string{"reason": req.RejectionReason},
		})
		writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
	}
}

// ---------------------------------------------------------------------------
// Settlement / payment instruction endpoints
// ---------------------------------------------------------------------------

// pendingPaymentResponse is the per-instruction shape returned by
// GET /v1/payments/pending.
type pendingPaymentResponse struct {
	TradeID             string  `json:"trade_id"`
	AssetID             string  `json:"asset_id"`
	Reference           string  `json:"reference"`
	Amount              float64 `json:"amount"`
	Currency            string  `json:"currency"`
	Method              string  `json:"method"`
	SettlementNetwork   string  `json:"settlement_network,omitempty"`
	PontesTransactionID string  `json:"pontes_transaction_id,omitempty"`
	ExpiresAt           int64   `json:"expires_at"`
	Status              string  `json:"status"`
}

// handleListPendingPayments returns all pending PaymentInstructions for the
// authenticated wallet in their role as payer (buyer). Includes instructions
// that are already confirmed so the UI can show a complete picture.
//
// GET /v1/payments/pending
func (s *Server) handleListPendingPayments(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)
	now := time.Now().Unix()

	out := make([]pendingPaymentResponse, 0)
	for tradeID, instr := range s.bc.PendingInstructions {
		if instr.PayerWalletID != walletKey {
			continue
		}
		status := "pending"
		if _, settled := s.bc.ConfirmedPayments[tradeID]; settled {
			status = "confirmed"
		} else if instr.ExpiresAt > 0 && now > instr.ExpiresAt {
			status = "expired"
		}
		out = append(out, pendingPaymentResponse{
			TradeID:             tradeID,
			AssetID:             instr.AssetID,
			Reference:           instr.Reference,
			Amount:              instr.TotalAmount,
			Currency:            instr.Currency,
			Method:              string(instr.Method),
			SettlementNetwork:   instr.SettlementNetwork,
			PontesTransactionID: instr.PontesTransactionID,
			ExpiresAt:           instr.ExpiresAt,
			Status:              status,
		})
	}
	// Sort by status priority (pending first) then ExpiresAt ascending.
	sort.Slice(out, func(i, j int) bool {
		si, sj := out[i].Status, out[j].Status
		if si != sj {
			order := map[string]int{"pending": 0, "expired": 1, "confirmed": 2}
			return order[si] < order[sj]
		}
		return out[i].ExpiresAt < out[j].ExpiresAt
	})
	writeJSON(w, http.StatusOK, out)
}

// settledTradeResponse is the per-trade shape returned by
// GET /v1/payments/history.
type settledTradeResponse struct {
	gonetwork.Trade
	SettlementMethod    string `json:"settlement_method"`
	SettlementStatus    string `json:"settlement_status"`
	SettlementReference string `json:"settlement_reference,omitempty"`
	SettlementNetwork   string `json:"settlement_network,omitempty"`
	ConfirmedAt         int64  `json:"confirmed_at,omitempty"`
}

// handleListPaymentHistory returns all trades for the authenticated wallet
// enriched with settlement method and confirmation status. Useful for the
// settlement history view and for reconciliation.
//
// GET /v1/payments/history
func (s *Server) handleListPaymentHistory(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)

	out := make([]settledTradeResponse, 0)
	for _, trade := range s.bc.Trades {
		if trade.BuyerID != walletKey && trade.SellerID != walletKey {
			continue
		}
		row := settledTradeResponse{Trade: trade, SettlementStatus: "pending"}
		if instr, ok := s.bc.PendingInstructions[trade.ID]; ok {
			row.SettlementMethod = string(instr.Method)
			row.SettlementReference = instr.Reference
			row.SettlementNetwork = instr.SettlementNetwork
		}
		if conf, ok := s.bc.ConfirmedPayments[trade.ID]; ok {
			row.SettlementStatus = "confirmed"
			row.ConfirmedAt = conf.ConfirmedAt
		}
		out = append(out, row)
	}
	// Most recent trades first.
	sort.Slice(out, func(i, j int) bool {
		return out[i].ExecutedAt > out[j].ExecutedAt
	})
	writeJSON(w, http.StatusOK, out)
}

// handleRegisterCeBMSettlement is an admin endpoint that triggers a
// SettlementRegistrar.RegisterSettlement call for a pending instruction whose
// automatic async registration failed (F-4). This allows operators to retry
// Pontes CeBM registrations without re-sealing a block.
//
// POST /v1/payments/{tradeID}/register
// Requires admin JWT.
//
// Responses:
//
//	200 — registration succeeded; body contains pontes_transaction_id.
//	404 — no pending instruction for tradeID.
//	409 — provider does not implement SettlementRegistrar.
//	502 — provider returned an error.
func (s *Server) handleRegisterCeBMSettlement(w http.ResponseWriter, r *http.Request) {
	tradeID := r.PathValue("tradeID")

	s.bc.Mu.Lock()
	instr, ok := s.bc.PendingInstructions[tradeID]
	s.bc.Mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "trade not found")
		return
	}

	provider := s.bc.ProviderForMethod(instr.Method)
	registrar, ok := provider.(gonetwork.SettlementRegistrar)
	if !ok {
		writeError(w, http.StatusConflict, "provider does not support registration")
		return
	}

	txID, err := registrar.RegisterSettlement(instr)
	if err != nil {
		log.Printf("[settlement] manual register failed trade=%s ref=%s: %v", tradeID, instr.Reference, err)
		writeError(w, http.StatusBadGateway, "registration failed")
		return
	}

	// Write back the transaction ID under lock, as with the async goroutine path.
	s.bc.Mu.Lock()
	if live, exists := s.bc.PendingInstructions[tradeID]; exists {
		live.PontesTransactionID = txID
		live.SettlementNetwork = "eurosystem-pontes"
	}
	s.bc.Mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"pontes_transaction_id": txID})
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
// Phase 2 — Claim-topic endpoints
// ---------------------------------------------------------------------------

// handleListClaims returns the effective set of claim-topic attestations for
// a wallet — both real on-chain Claims and claims synthesized from the
// legacy CredentialAttestation (the Phase 2 backward-compatible adapter).
// GET /v1/claims/{walletKey}
func (s *Server) handleListClaims(w http.ResponseWriter, r *http.Request) {
	walletKey := r.PathValue("walletKey")
	claims := gonetwork.EffectiveClaims(s.bc, walletKey)
	writeJSON(w, http.StatusOK, map[string]any{
		"wallet_key": walletKey,
		"count":      len(claims),
		"claims":     claims,
	})
}

// handleUpsertClaimIssuer adds or removes a trusted issuer for a claim topic.
// Signed by the node operator key (single-authority governance at this stage
// — see VELA roadmap Section 6.4) and committed on-chain via SealClaimBlock
// for auditability.
// POST /v1/admin/claim-issuers
// Body: {"topic":"kyc","issuer_key":"<base64>","action":"add"|"remove"}
func (s *Server) handleUpsertClaimIssuer(w http.ResponseWriter, r *http.Request) {
	if s.bc.OperatorKeyProvider == nil {
		writeError(w, http.StatusNotImplemented, "operator key provider not configured on this node")
		return
	}
	var req struct {
		Topic     string `json:"topic"`
		IssuerKey string `json:"issuer_key"`
		Action    string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Topic == "" || req.IssuerKey == "" {
		writeError(w, http.StatusBadRequest, "topic and issuer_key are required")
		return
	}
	action := gonetwork.ClaimIssuerAction(req.Action)
	if action != gonetwork.ClaimIssuerActionAdd && action != gonetwork.ClaimIssuerActionRemove {
		writeError(w, http.StatusBadRequest, `action must be "add" or "remove"`)
		return
	}
	if _, err := gonetwork.PublicKeyFromString(req.IssuerKey); err != nil {
		writeError(w, http.StatusBadRequest, "issuer_key is not a valid Ed25519 public key: "+err.Error())
		return
	}

	cit := gonetwork.ClaimIssuerTransaction{
		Topic:      gonetwork.ClaimTopic(req.Topic),
		IssuerKey:  req.IssuerKey,
		Action:     action,
		RecordedAt: time.Now().Unix(),
	}
	sig, err := s.bc.OperatorKeyProvider.Sign(cit.SigningHash())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign claim-issuer transaction")
		return
	}
	cit.AdminSignature = sig

	s.bc.SealClaimBlock(nil, []gonetwork.ClaimIssuerTransaction{cit})

	writeJSON(w, http.StatusOK, map[string]any{
		"topic":      cit.Topic,
		"issuer_key": cit.IssuerKey,
		"action":     cit.Action,
	})
}

// ---------------------------------------------------------------------------
// Phase 3 — Institutional / vLEI legal-entity identity endpoints
// ---------------------------------------------------------------------------

// handleRegisterEntity registers a new legal entity (LEI + legal name +
// jurisdiction) for institutional onboarding. The entity starts in "pending"
// status.
// POST /v1/admin/entities
// Body: {"lei":"...", "legal_name":"...", "jurisdiction":"GB", "did_webs":"...", "registered_address_hash":"..."}
func (s *Server) handleRegisterEntity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LEI                   string `json:"lei"`
		LegalName             string `json:"legal_name"`
		Jurisdiction          string `json:"jurisdiction"`
		DIDWebs               string `json:"did_webs"`
		RegisteredAddressHash string `json:"registered_address_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	entity := &gonetwork.LegalEntityIdentity{
		LEI:                   req.LEI,
		LegalName:             req.LegalName,
		Jurisdiction:          req.Jurisdiction,
		DIDWebs:               req.DIDWebs,
		RegisteredAddressHash: req.RegisteredAddressHash,
		RegisteredBy:          walletFromCtx(r),
	}
	if err := s.EntityRegistry.RegisterEntity(entity); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, entity)
}

// handleGetEntity returns a single registered legal entity by LEI.
// GET /v1/entities/{lei}
func (s *Server) handleGetEntity(w http.ResponseWriter, r *http.Request) {
	entity, err := s.EntityRegistry.GetEntity(r.PathValue("lei"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entity)
}

// handleListEntities returns all registered legal entities.
// GET /v1/entities
func (s *Server) handleListEntities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"entities": s.EntityRegistry.ListEntities(),
	})
}

// handleIssueEntityRoleClaim issues a ClaimTopicInstitutionalRole claim
// binding a wallet to a role (authorised_signatory, ubo, director, spv_admin,
// market_maker)
// within a registered legal entity, reusing the Phase 2 claim-issuance
// machinery (IdentityRegistry.IssueClaim + SealClaimBlock) exactly as
// commitIssuedCredential does for KYC claims.
// POST /v1/admin/entities/{lei}/role-claims
// Body: {"wallet_key":"...", "role":"spv_admin", "valid_for_days":365}
func (s *Server) handleIssueEntityRoleClaim(w http.ResponseWriter, r *http.Request) {
	lei := r.PathValue("lei")
	if _, err := s.EntityRegistry.GetEntity(lei); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if s.bc.IdentityRegistry == nil {
		writeError(w, http.StatusNotImplemented, "identity registry not configured on this node")
		return
	}
	var req struct {
		WalletKey    string `json:"wallet_key"`
		Role         string `json:"role"`
		ValidForDays int    `json:"valid_for_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.WalletKey == "" {
		writeError(w, http.StatusBadRequest, "wallet_key is required")
		return
	}
	role := gonetwork.EntityRole(req.Role)
	switch role {
	case gonetwork.EntityRoleAuthorisedSignatory, gonetwork.EntityRoleUBO, gonetwork.EntityRoleDirector, gonetwork.EntityRoleSPVAdmin, gonetwork.EntityRoleMarketMaker:
	default:
		writeError(w, http.StatusBadRequest, "role must be one of authorised_signatory, ubo, director, spv_admin, market_maker")
		return
	}
	validDays := req.ValidForDays
	if validDays <= 0 {
		validDays = 365
	}

	claim, err := s.bc.IdentityRegistry.IssueClaim(
		req.WalletKey, gonetwork.ClaimTopicInstitutionalRole, gonetwork.EntityRoleClaimData(lei, role), validDays,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue role claim: "+err.Error())
		return
	}
	s.bc.SealClaimBlock([]gonetwork.ClaimTransaction{{Claim: *claim}}, nil)

	writeJSON(w, http.StatusOK, claim)
}

// handleCreateMarketMaker registers a designated market maker agreement for an asset.
// POST /v1/admin/market-makers
func (s *Server) handleCreateMarketMaker(w http.ResponseWriter, r *http.Request) {
	if s.bc.OperatorKeyProvider == nil {
		writeError(w, http.StatusNotImplemented, "operator key provider not configured on this node")
		return
	}
	var req struct {
		AssetID               string  `json:"asset_id"`
		DealerKey             string  `json:"dealer_key"`
		DealerLEI             string  `json:"dealer_lei"`
		FeeRebateBps          int     `json:"fee_rebate_bps"`
		MaxSpreadBps          int     `json:"max_spread_bps"`
		MinQuoteSize          float64 `json:"min_quote_size"`
		PriorityAllocationPct float64 `json:"priority_allocation_pct"`
		MaxPositionUnits      float64 `json:"max_position_units"`
		MaxPositionValue      float64 `json:"max_position_value"`
		EffectiveFrom         int64   `json:"effective_from"`
		EffectiveTo           int64   `json:"effective_to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.AssetID == "" || req.DealerKey == "" || req.DealerLEI == "" {
		writeError(w, http.StatusBadRequest, "asset_id, dealer_key, and dealer_lei are required")
		return
	}
	if _, err := gonetwork.PublicKeyFromString(req.DealerKey); err != nil {
		writeError(w, http.StatusBadRequest, "dealer_key is not a valid Ed25519 public key: "+err.Error())
		return
	}
	if !gonetwork.HasEntityRole(s.bc, req.DealerKey, req.DealerLEI, gonetwork.EntityRoleMarketMaker) {
		writeError(w, http.StatusConflict, "dealer wallet does not hold a market_maker role claim for the supplied dealer_lei")
		return
	}
	agreement, err := gonetwork.NewMarketMakerAgreementWithProvider(
		s.bc.OperatorKeyProvider,
		req.AssetID,
		req.DealerKey,
		req.DealerLEI,
		req.FeeRebateBps,
		req.MaxSpreadBps,
		req.MinQuoteSize,
		req.PriorityAllocationPct,
		req.MaxPositionUnits,
		req.MaxPositionValue,
		req.EffectiveFrom,
		req.EffectiveTo,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	mtx, err := gonetwork.NewMarketMakerTransaction(s.bc.OperatorKeyProvider, *agreement, gonetwork.MarketMakerActionRegister, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign market maker transaction")
		return
	}

	s.bc.SealMarketMakerBlock([]gonetwork.MarketMakerTransaction{mtx})
	writeJSON(w, http.StatusCreated, agreement)
}

// handleListMarketMakers returns all currently-active market maker agreements for an asset.
// GET /v1/market-makers/{assetID}
func (s *Server) handleListMarketMakers(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("assetID")
	if assetID == "" {
		writeError(w, http.StatusBadRequest, "assetID is required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"asset_id":   assetID,
		"agreements": s.bc.MarketMakerRegistry.ActiveAgreementsFor(assetID),
	})
}

// handleGetMarketMakerInventory returns inventory/open exposure for one wallet.
// GET /v1/market-makers/{walletKey}/inventory
func (s *Server) handleGetMarketMakerInventory(w http.ResponseWriter, r *http.Request) {
	targetWallet := r.PathValue("walletKey")
	if targetWallet == "" {
		writeError(w, http.StatusBadRequest, "walletKey is required")
		return
	}
	caller := walletFromCtx(r)
	if caller != targetWallet {
		if len(s.adminWalletKeys) > 0 && !s.adminWalletKeys[caller] {
			writeError(w, http.StatusForbidden, "caller must be the wallet owner or an admin")
			return
		}
	}
	report := gonetwork.InventorySnapshot(targetWallet, s.bc)
	writeJSON(w, http.StatusOK, report)
}

// handleGetMarketDataVWAP returns a windowed VWAP for an asset.
// GET /v1/market-data/vwap/{assetID}?window=1h
func (s *Server) handleGetMarketDataVWAP(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("assetID")
	if assetID == "" {
		writeError(w, http.StatusBadRequest, "assetID is required")
		return
	}
	if _, ok := s.bc.Assets[assetID]; !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	windowStr := strings.TrimSpace(r.URL.Query().Get("window"))
	if windowStr == "" {
		windowStr = "24h"
	}
	window, err := time.ParseDuration(windowStr)
	if err != nil || window <= 0 {
		writeError(w, http.StatusBadRequest, "window must be a positive time.Duration (for example 1h, 24h, 30m)")
		return
	}
	vwap := gonetwork.VWAP(s.bc.Trades, assetID, window)
	cutoff := time.Now().Add(-window).Unix()
	tradeCount := 0
	for _, tr := range s.bc.Trades {
		if tr.AssetID != assetID {
			continue
		}
		if tr.ExecutedAt != 0 && tr.ExecutedAt < cutoff {
			continue
		}
		tradeCount++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"asset_id":    assetID,
		"window":      window.String(),
		"vwap":        vwap,
		"trade_count": tradeCount,
		"as_of":       time.Now().Unix(),
	})
}

// handleDeleteMarketMaker revokes an existing designated market maker agreement.
// DELETE /v1/admin/market-makers/{id}
func (s *Server) handleDeleteMarketMaker(w http.ResponseWriter, r *http.Request) {
	if s.bc.OperatorKeyProvider == nil {
		writeError(w, http.StatusNotImplemented, "operator key provider not configured on this node")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	agreement := s.bc.MarketMakerRegistry.AgreementByID(id)
	if agreement == nil {
		writeError(w, http.StatusNotFound, "market maker agreement not found")
		return
	}
	mtx, err := gonetwork.NewMarketMakerTransaction(s.bc.OperatorKeyProvider, *agreement, gonetwork.MarketMakerActionRevoke, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign market maker transaction")
		return
	}

	s.bc.SealMarketMakerBlock([]gonetwork.MarketMakerTransaction{mtx})
	writeJSON(w, http.StatusOK, map[string]any{
		"agreement_id": id,
		"status":       gonetwork.MarketMakerStatusRevoked,
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

	// ---------------------------------------------------------------------------
	// Part II compliance gate (G-06, G-07, G-08, G-09, G-11)
	// ---------------------------------------------------------------------------

	// Look up the buyer's credential (may be nil for uncredentialled wallets).
	buyerCred := s.bc.Credentials[found.PlacedBy]

	// G-08: reject transfers to wallets with an expired credential.
	if buyerCred != nil && buyerCred.ExpiresAt > 0 && time.Now().Unix() > buyerCred.ExpiresAt {
		writeError(w, http.StatusForbidden, fmt.Sprintf(
			"buyer KYC credential has expired (expired at unix %d): re-KYC required",
			buyerCred.ExpiresAt,
		))
		return
	}

	// G-07: MiFID II suitability check for complex instruments (warrants, convertibles).
	if err := gonetwork.CheckSuitability(found.PlacedBy, asset, s.bc.SuitabilityAssessments); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	// G-06: prospectus exemption cap — reject if the buyer would breach the
	// per-jurisdiction retail holder limit.
	if exemption, hasExemption := s.bc.ProspectusExemptions[found.AssetID]; hasExemption {
		if err := gonetwork.CheckProspectusLimits(buyerCred, exemption); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	// G-11: jurisdiction-specific rules.
	if buyerCred != nil {
		if rule, hasRule := s.bc.JurisdictionRules[buyerCred.Jurisdiction]; hasRule {
			// Live count scoped to this asset + jurisdiction (previously this
			// counted ALL retail credential holders platform-wide, which could
			// incorrectly block a buyer once any single jurisdiction's cap was
			// reached anywhere on the platform).
			currentRetailCount := gonetwork.CountJurisdictionRetailHolders(found.AssetID, buyerCred.Jurisdiction, s.bc.Holdings, s.bc.Credentials)
			if err := gonetwork.ApplyJurisdictionRule(rule, nil, buyerCred, asset, 0, currentRetailCount); err != nil {
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
		}
	}

	// G-09: FATF Travel Rule — derive originator/beneficiary information from
	// registration records when EUR-equivalent value is >= TravelRuleThresholdEUR.
	// This keeps the issuer fill API stateless and avoids trusting caller-supplied
	// PII payloads for regulatory controls.
	tradeID := fmt.Sprintf("trade-%s", orderID[:8])
	tradeValue := fillQty * found.Price
	if _, err := s.bc.AutoTravelRule(found.PlacedBy, issuerKey, tradeID, tradeValue, asset.Currency); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "FATF Travel Rule: "+err.Error())
		return
	}

	// G-09: AML screening via the configured screener.
	if s.bc.AMLScreener != nil {
		alert, err := s.bc.AMLScreener.ScreenTransaction(
			issuerKey, found.PlacedBy, found.AssetID, fillQty, asset.Currency,
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "AML screening failed: "+err.Error())
			return
		}
		if alert != nil && alert.Severity == gonetwork.AMLSeverityBlock {
			writeError(w, http.StatusForbidden, "transfer blocked by AML screening: "+alert.Reason)
			return
		}
		if alert != nil && alert.Severity == gonetwork.AMLSeverityFlag {
			// Create a SAR draft for compliance review; transfer is permitted.
			sarID := fmt.Sprintf("sar-%s-%d", orderID[:8], time.Now().UnixNano())
			s.bc.PendingSARs[sarID] = &gonetwork.SARDraft{
				ID:          sarID,
				SenderKey:   issuerKey,
				ReceiverKey: found.PlacedBy,
				AssetID:     found.AssetID,
				Amount:      fillQty,
				Currency:    asset.Currency,
				Reason:      alert.Reason,
				MatchedList: alert.MatchedList,
				CreatedAt:   time.Now().Unix(),
				Status:      gonetwork.SARStatusPending,
			}
			s.bc.EmitEvent(gonetwork.EventSARCreated, map[string]any{
				"sar_id":       sarID,
				"order_id":     orderID,
				"asset_id":     found.AssetID,
				"matched_list": alert.MatchedList,
				"reason":       alert.Reason,
			})
		}
	}

	// ---------------------------------------------------------------------------
	// End compliance gate
	// ---------------------------------------------------------------------------

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
// Body: {"asset_id":"...","action_type":"dividend","record_date":unix,"price_per_unit":1.23,"total_units":1000,"required_threshold":0.5}
func (s *Server) handleProposeCorporateAction(w http.ResponseWriter, r *http.Request) {
	walletKey := walletFromCtx(r)
	var req struct {
		AssetID           string                        `json:"asset_id"`
		ActionType        gonetwork.CorporateActionType `json:"action_type"`
		RecordDate        int64                         `json:"record_date"`
		PricePerUnit      float64                       `json:"price_per_unit"`
		TotalUnits        float64                       `json:"total_units"`
		RequiredThreshold float64                       `json:"required_threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.AssetID == "" || req.ActionType == "" || req.RecordDate <= 0 {
		writeError(w, http.StatusBadRequest, "asset_id, action_type and record_date are required")
		return
	}
	if req.RequiredThreshold == 0 {
		req.RequiredThreshold = 0.5
	}
	if req.RequiredThreshold <= 0 || req.RequiredThreshold > 1 {
		writeError(w, http.StatusBadRequest, "required_threshold must be in (0,1]")
		return
	}
	now := time.Now().Unix()
	id := base64.RawURLEncoding.EncodeToString([]byte(req.AssetID + string(req.ActionType) + strconv.FormatInt(time.Now().UnixNano(), 10)))
	ca := &gonetwork.CorporateAction{
		ID:                id,
		AssetID:           req.AssetID,
		Type:              req.ActionType,
		Status:            gonetwork.CorporateActionPending,
		ProposerKey:       walletKey,
		CreatedAt:         now,
		PricePerUnit:      req.PricePerUnit,
		TotalUnits:        req.TotalUnits,
		DeadlineAt:        req.RecordDate,
		RequiredThreshold: req.RequiredThreshold,
		Responses:         make(map[string]bool),
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
	walletKey := walletFromCtx(r)

	// Accept two body shapes:
	//   (a) { "signed_spv": <SPVWrapper> }  — pre-signed by the caller (legacy / SDK)
	//   (b) { "name": "...", "jurisdiction": "LU", "underlying_company_id": "...",
	//          "underlying_share_class": "...", "legal_doc_hash": "..." }
	//       — unsigned; SPVAdminKey is derived from the JWT wallet claim.
	var raw map[string]json.RawMessage
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var spv *gonetwork.SPVWrapper

	if _, hasSignedSPV := raw["signed_spv"]; hasSignedSPV {
		// Path (a): full signed wrapper supplied by caller
		var req struct {
			SignedSPV *gonetwork.SPVWrapper `json:"signed_spv"`
		}
		if err := json.Unmarshal(body, &req); err != nil || req.SignedSPV == nil {
			writeError(w, http.StatusBadRequest, "invalid signed_spv")
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
		spv = req.SignedSPV
	} else {
		// Path (b): plain fields — build the wrapper server-side, ownership proven by JWT
		var fields struct {
			Name                 string `json:"name"`
			Jurisdiction         string `json:"jurisdiction"`
			UnderlyingCompanyID  string `json:"underlying_company_id"`
			UnderlyingShareClass string `json:"underlying_share_class"`
			LegalDocHash         string `json:"legal_doc_hash"`
		}
		if err := json.Unmarshal(body, &fields); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON fields")
			return
		}
		if fields.Name == "" || fields.Jurisdiction == "" ||
			fields.UnderlyingCompanyID == "" || fields.UnderlyingShareClass == "" ||
			fields.LegalDocHash == "" {
			writeError(w, http.StatusBadRequest, "name, jurisdiction, underlying_company_id, underlying_share_class and legal_doc_hash are required")
			return
		}
		spv = &gonetwork.SPVWrapper{
			Name:                 fields.Name,
			Jurisdiction:         gonetwork.SPVJurisdiction(fields.Jurisdiction),
			UnderlyingCompanyID:  fields.UnderlyingCompanyID,
			UnderlyingShareClass: fields.UnderlyingShareClass,
			SPVAdminKey:          walletKey,
			LegalDocHash:         fields.LegalDocHash,
			NAVUpdatedAt:         0,
		}
		// Deterministic ID: sha3-256(adminKey || name || jurisdiction || companyID)
		spv.ID = gonetwork.SPVDeterministicID(walletKey, fields.Name, fields.Jurisdiction, fields.UnderlyingCompanyID)
	}

	if _, exists := s.bc.SPVs[spv.ID]; exists {
		writeError(w, http.StatusConflict, "SPV with this ID already exists")
		return
	}
	s.bc.SPVs[spv.ID] = spv
	writeJSON(w, http.StatusCreated, spv)
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

// ---------------------------------------------------------------------------
// Legal document amendment endpoints (A-03)
// ---------------------------------------------------------------------------

// handleAddLegalDocAmendment appends a signed legal document amendment to the
// on-chain amendment log for an asset.
// POST /v1/assets/{id}/legal-doc
// Body: {"previous_doc_hash":"<hex>","new_doc_hash":"<hex>","issuer_signature":"<base64>"}
//
// For AssetTypeParticipationNote the body must also include:
//
//	{"admin_key":"<base64>","admin_signature":"<base64>"}
func (s *Server) handleAddLegalDocAmendment(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	walletKey := walletFromCtx(r)

	asset, ok := s.bc.Assets[assetID]
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if asset.Issuer != walletKey {
		writeError(w, http.StatusForbidden, "only the asset issuer may amend the legal document")
		return
	}

	var req struct {
		PreviousDocHash string `json:"previous_doc_hash"`
		NewDocHash      string `json:"new_doc_hash"`
		IssuerSignature string `json:"issuer_signature"` // base64
		AdminKey        string `json:"admin_key,omitempty"`
		AdminSignature  string `json:"admin_signature,omitempty"` // base64
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.PreviousDocHash == "" || req.NewDocHash == "" {
		writeError(w, http.StatusBadRequest, "previous_doc_hash and new_doc_hash are required")
		return
	}
	if req.PreviousDocHash == req.NewDocHash {
		writeError(w, http.StatusBadRequest, "new_doc_hash must differ from previous_doc_hash")
		return
	}
	if req.IssuerSignature == "" {
		writeError(w, http.StatusBadRequest, "issuer_signature is required")
		return
	}

	issuerSig, err := base64.StdEncoding.DecodeString(req.IssuerSignature)
	if err != nil {
		issuerSig, err = base64.RawURLEncoding.DecodeString(req.IssuerSignature)
		if err != nil {
			writeError(w, http.StatusBadRequest, "issuer_signature is not valid base64")
			return
		}
	}

	// Derive a deterministic ID (mirrors NewLegalDocAmendment logic without a private key).
	h := sha3.New256()
	h.Write([]byte(assetID))
	h.Write([]byte(req.PreviousDocHash))
	h.Write([]byte(req.NewDocHash))
	h.Write([]byte(walletKey))
	amendID := hex.EncodeToString(h.Sum(nil))

	amendment := &gonetwork.LegalDocAmendment{
		ID:              amendID,
		AssetID:         assetID,
		PreviousDocHash: req.PreviousDocHash,
		NewDocHash:      req.NewDocHash,
		AmendedAt:       time.Now().UTC().Unix(),
		IssuerKey:       walletKey,
		IssuerSignature: issuerSig,
	}

	if req.AdminKey != "" && req.AdminSignature != "" {
		adminSig, err := base64.StdEncoding.DecodeString(req.AdminSignature)
		if err != nil {
			adminSig, err = base64.RawURLEncoding.DecodeString(req.AdminSignature)
			if err != nil {
				writeError(w, http.StatusBadRequest, "admin_signature is not valid base64")
				return
			}
		}
		amendment.AdminKey = req.AdminKey
		amendment.AdminSignature = adminSig
	}

	if err := gonetwork.ApplyAmendment(
		amendment,
		s.bc.Assets,
		s.bc.SPVs,
		s.bc.LegalDocAmendments,
	); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	s.bc.EmitEvent(gonetwork.EventLegalDocAmended, map[string]any{
		"asset_id":          assetID,
		"amendment_id":      amendment.ID,
		"previous_doc_hash": amendment.PreviousDocHash,
		"new_doc_hash":      amendment.NewDocHash,
	})
	s.bc.SealBlock(nil, nil, nil)

	writeJSON(w, http.StatusCreated, amendment)
}

// handleGetLegalDocHistory returns the full amendment history for an asset's
// legal document, along with the resolved current hash.
// GET /v1/assets/{id}/legal-doc/history
func (s *Server) handleGetLegalDocHistory(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")

	asset, ok := s.bc.Assets[assetID]
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}

	amendments := s.bc.LegalDocAmendments[assetID]
	if amendments == nil {
		amendments = []*gonetwork.LegalDocAmendment{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"asset_id":         assetID,
		"current_doc_hash": gonetwork.CurrentLegalDocHash(assetID, asset, s.bc.LegalDocAmendments),
		"genesis_doc_hash": asset.Metadata.LegalDocHash,
		"amendment_count":  len(amendments),
		"amendments":       amendments,
	})
}

// ---------------------------------------------------------------------------
// Participation note countersignature endpoint (A-04)
// ---------------------------------------------------------------------------

// handleCounterSignAsset is called by the SPV administrator to countersign a
// participation note asset, releasing its supply from 0 to TotalSupply.
//
// Until this endpoint is called:
//   - CirculatingSupply == 0
//   - Sell orders on the asset are rejected with 409
//
// POST /v1/assets/{id}/countersign
// Body: {"spv_id":"...","admin_signature":"<base64>"}
func (s *Server) handleCounterSignAsset(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	walletKey := walletFromCtx(r)

	asset, ok := s.bc.Assets[assetID]
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if asset.AssetType != gonetwork.AssetTypeParticipationNote {
		writeError(w, http.StatusBadRequest, "countersignature only applies to participation_note assets")
		return
	}
	if asset.CirculatingSupply > 0 {
		writeError(w, http.StatusConflict, "asset has already been countersigned")
		return
	}

	var req struct {
		SPVID          string `json:"spv_id"`
		AdminSignature string `json:"admin_signature"` // base64
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.SPVID == "" {
		writeError(w, http.StatusBadRequest, "spv_id is required")
		return
	}
	if req.AdminSignature == "" {
		writeError(w, http.StatusBadRequest, "admin_signature is required")
		return
	}

	spv, ok := s.bc.SPVs[req.SPVID]
	if !ok {
		writeError(w, http.StatusNotFound, "SPV not found")
		return
	}
	if spv.SPVAdminKey != walletKey {
		writeError(w, http.StatusForbidden, "only the SPV administrator may countersign")
		return
	}

	adminSig, err := base64.StdEncoding.DecodeString(req.AdminSignature)
	if err != nil {
		adminSig, err = base64.RawURLEncoding.DecodeString(req.AdminSignature)
		if err != nil {
			writeError(w, http.StatusBadRequest, "admin_signature is not valid base64")
			return
		}
	}

	// Verify the admin signature covers the asset ID (proving intentional countersign).
	adminPub, err := gonetwork.PublicKeyFromString(spv.SPVAdminKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SPV has an invalid admin key")
		return
	}
	if !gonetwork.VerifySignatureBytes(adminPub, []byte(assetID), adminSig) {
		writeError(w, http.StatusUnauthorized, "admin_signature is not valid over asset ID")
		return
	}

	// Release supply: create issuer holding and set CirculatingSupply.
	issuerHoldingKey := gonetwork.HoldingKey(asset.Issuer, assetID)
	s.bc.Holdings[issuerHoldingKey] = &gonetwork.AssetHolding{
		AssetID:  assetID,
		HolderID: asset.Issuer,
		Balance:  asset.TotalSupply,
	}
	asset.CirculatingSupply = asset.TotalSupply
	asset.Metadata.ISIN = spv.ID // bind asset to the SPV

	s.bc.SealBlock(
		[]gonetwork.AssetTransaction{{AssetID: assetID, TxType: gonetwork.AssetTxTypeIssue}},
		nil, nil,
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"asset_id":           assetID,
		"spv_id":             req.SPVID,
		"circulating_supply": asset.CirculatingSupply,
		"status":             "countersigned",
	})
}

// ---------------------------------------------------------------------------
// SAR (Suspicious Activity Report) endpoints   (G-09)
// ---------------------------------------------------------------------------

// handleListSARs returns all pending Suspicious Activity Report drafts.
// Only compliance officers (jwtAdmin) may access this list.
// GET /v1/compliance/sar
func (s *Server) handleListSARs(w http.ResponseWriter, _ *http.Request) {
	s.bc.Mu.RLock()
	out := make([]*gonetwork.SARDraft, 0, len(s.bc.PendingSARs))
	for _, sar := range s.bc.PendingSARs {
		out = append(out, sar)
	}
	s.bc.Mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(out),
		"sars":  out,
	})
}

// handleListClosedSARs returns resolved (filed or dismissed) SAR drafts from
// the durable archive bucket. Returns an empty list when no BlockStore is
// configured (dev/test nodes) rather than erroring.
// GET /v1/compliance/sar/closed
func (s *Server) handleListClosedSARs(w http.ResponseWriter, _ *http.Request) {
	if s.bc.BlockStore == nil {
		writeJSON(w, http.StatusOK, map[string]any{"count": 0, "sars": []any{}})
		return
	}
	closed, err := s.bc.BlockStore.LoadClosedSARs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load closed SAR archive")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(closed), "sars": closed})
}

// handleResolveSAR allows a compliance officer to file or dismiss a SAR draft.
// Resolved drafts are archived to the durable "closed_sars" bucket (when a
// BlockStore is configured) and removed from the live PendingSARs map, so SAR
// retention no longer depends on the process staying alive.
// POST /v1/compliance/sar/{id}/resolve
// Body: {"action":"file"|"dismiss","notes":"optional explanation"}
func (s *Server) handleResolveSAR(w http.ResponseWriter, r *http.Request) {
	sarID := r.PathValue("id")
	resolverKey := walletFromCtx(r)

	var req struct {
		Action string `json:"action"` // "file" or "dismiss"
		Notes  string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Action != "file" && req.Action != "dismiss" {
		writeError(w, http.StatusBadRequest, `action must be "file" or "dismiss"`)
		return
	}

	// Mutates bc.PendingSARs, which is also read/written by detectSTORs inside
	// applyBlockState — bc.Mu must be held for the whole read-modify-write.
	s.bc.Mu.Lock()
	sar, ok := s.bc.PendingSARs[sarID]
	if !ok {
		s.bc.Mu.Unlock()
		writeError(w, http.StatusNotFound, "SAR not found")
		return
	}
	if sar.Status != gonetwork.SARStatusPending {
		status := sar.Status
		s.bc.Mu.Unlock()
		writeError(w, http.StatusConflict, fmt.Sprintf("SAR is already %s", status))
		return
	}
	if req.Action == "file" {
		sar.Status = gonetwork.SARStatusFiled
	} else {
		sar.Status = gonetwork.SARStatusDismissed
	}
	sar.ResolvedAt = time.Now().Unix()
	sar.ResolvedBy = resolverKey
	sar.Notes = req.Notes
	sarCopy := *sar
	// Only remove from the live map once we know the resolved record has
	// somewhere durable to go; otherwise leave it in PendingSARs (with its
	// updated Status) so the record isn't lost entirely on a dev/test node
	// with no BlockStore configured.
	archiving := s.bc.BlockStore != nil
	if archiving {
		delete(s.bc.PendingSARs, sarID)
	}
	s.bc.Mu.Unlock()

	if archiving {
		if err := s.bc.BlockStore.SaveClosedSAR(&sarCopy); err != nil {
			log.Printf("handleResolveSAR: failed to archive resolved SAR %s: %v", sarID, err)
		}
	}

	writeJSON(w, http.StatusOK, &sarCopy)
}

// ---------------------------------------------------------------------------
// Regulatory reporting endpoints   (G-10)
// ---------------------------------------------------------------------------

// handleListRegulatoryReports returns generated regulatory reports, optionally
// filtered by report_type or trade_id query parameters.
// GET /v1/compliance/reports?report_type=mifir&trade_id=
func (s *Server) handleListRegulatoryReports(w http.ResponseWriter, r *http.Request) {
	typeFilter := r.URL.Query().Get("report_type")
	tradeFilter := r.URL.Query().Get("trade_id")

	var out []*gonetwork.RegulatoryReport
	for _, rep := range s.bc.RegulatoryReports {
		if typeFilter != "" && string(rep.ReportType) != typeFilter {
			continue
		}
		if tradeFilter != "" && rep.TradeID != tradeFilter {
			continue
		}
		out = append(out, rep)
	}
	if out == nil {
		out = []*gonetwork.RegulatoryReport{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(out),
		"reports": out,
	})
}

// handleGetJurisdictionRule returns the jurisdiction rule for a given country code.
// GET /v1/compliance/jurisdictions/{code}
func (s *Server) handleGetJurisdictionRule(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	rule, ok := s.bc.JurisdictionRules[code]
	if !ok {
		writeError(w, http.StatusNotFound, "no jurisdiction rule found for "+code)
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

// handleUpsertJurisdictionRule creates or replaces a JurisdictionRule.
// POST /v1/compliance/jurisdictions
func (s *Server) handleUpsertJurisdictionRule(w http.ResponseWriter, r *http.Request) {
	var rule gonetwork.JurisdictionRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid jurisdiction rule payload")
		return
	}
	if len(rule.CountryCode) != 2 {
		writeError(w, http.StatusBadRequest, "country_code must be a 2-letter ISO 3166-1 alpha-2 code")
		return
	}
	s.bc.JurisdictionRules[rule.CountryCode] = &rule
	writeJSON(w, http.StatusOK, &rule)
}

// ---------------------------------------------------------------------------
// MAR Article 18 — Insider List endpoints
// ---------------------------------------------------------------------------

// handleListInsiders returns the insider list for an asset.
// Compliance officers and the NCA may request this list at any time (MAR Art 18(7)).
// GET /v1/assets/{id}/insiders
func (s *Server) handleListInsiders(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	s.bc.Mu.RLock()
	_, assetExists := s.bc.Assets[assetID]
	list := s.bc.InsiderLists[assetID]
	var active []*gonetwork.InsiderRecord
	if list != nil {
		active = list.Active()
	}
	s.bc.Mu.RUnlock()
	if !assetExists {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if list == nil {
		writeJSON(w, http.StatusOK, map[string]any{"asset_id": assetID, "count": 0, "records": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"asset_id": assetID,
		"count":    len(active),
		"records":  active,
	})
}

// handleAddInsider adds a person to the MAR Article 18 insider list for an asset.
// Only compliance officers (jwtAdmin) may add entries.
// POST /v1/assets/{id}/insiders
// Body: {"full_name":"...","role":"...","organisation":"...","reason":"..."}
func (s *Server) handleAddInsider(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	addedBy := walletFromCtx(r)

	s.bc.Mu.RLock()
	_, assetExists := s.bc.Assets[assetID]
	s.bc.Mu.RUnlock()
	if !assetExists {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}

	var req struct {
		FullName     string `json:"full_name"`
		Role         string `json:"role"`
		Organisation string `json:"organisation"`
		Reason       string `json:"reason"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.FullName == "" || req.Role == "" {
		writeError(w, http.StatusBadRequest, "full_name and role are required")
		return
	}
	if req.Reason == "" {
		writeError(w, http.StatusBadRequest, "reason is required (describe the insider's access to inside information)")
		return
	}

	record := &gonetwork.InsiderRecord{
		ID:            generateID("INS"),
		AssetID:       assetID,
		FullName:      req.FullName,
		Role:          req.Role,
		Organisation:  req.Organisation,
		Reason:        req.Reason,
		AddedAt:       time.Now().Unix(),
		AddedByWallet: addedBy,
	}

	// Mutates bc.InsiderLists under bc.Mu — this map is also read by
	// handleListInsiders and (in a future block-sealing check) applyBlockState
	// under the same lock.
	s.bc.Mu.Lock()
	list := s.bc.InsiderLists[assetID]
	if list == nil {
		list = &gonetwork.InsiderList{AssetID: assetID}
		s.bc.InsiderLists[assetID] = list
	}
	list.Add(record)
	s.bc.Mu.Unlock()

	writeJSON(w, http.StatusCreated, record)
}

// handleRemoveInsider soft-deletes an insider record (MAR Art 18: records must be
// retained for 5 years and must show the date they were removed).
// DELETE /v1/assets/{id}/insiders/{recordID}
func (s *Server) handleRemoveInsider(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	recordID := r.PathValue("recordID")

	s.bc.Mu.Lock()
	list := s.bc.InsiderLists[assetID]
	if list == nil {
		s.bc.Mu.Unlock()
		writeError(w, http.StatusNotFound, "insider list not found for asset")
		return
	}
	removed := list.Remove(recordID, time.Now().Unix())
	s.bc.Mu.Unlock()
	if !removed {
		writeError(w, http.StatusNotFound, "insider record not found or already removed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "record_id": recordID})
}

// ---------------------------------------------------------------------------
// MAR Article 16 — STOR endpoints
// ---------------------------------------------------------------------------

// handleListSTORs returns all STOR drafts, optionally filtered by resolution.
// Only compliance officers (jwtAdmin) may access this list.
// GET /v1/compliance/stor?resolution=pending_review
func (s *Server) handleListSTORs(w http.ResponseWriter, _ *http.Request) {
	s.bc.Mu.RLock()
	out := make([]*gonetwork.STORDraft, 0, len(s.bc.PendingSTORs))
	for _, stor := range s.bc.PendingSTORs {
		out = append(out, stor)
	}
	s.bc.Mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(out),
		"stors": out,
	})
}

// handleListClosedSTORs returns resolved STOR drafts from the durable archive
// bucket. Returns an empty list when no BlockStore is configured.
// GET /v1/compliance/stor/closed
func (s *Server) handleListClosedSTORs(w http.ResponseWriter, _ *http.Request) {
	if s.bc.BlockStore == nil {
		writeJSON(w, http.StatusOK, map[string]any{"count": 0, "stors": []any{}})
		return
	}
	closed, err := s.bc.BlockStore.LoadClosedSTORs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load closed STOR archive")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(closed), "stors": closed})
}

// handleResolveSTOR allows a compliance officer to file or dismiss a STOR draft.
// MAR Article 16(1) requires the report to be filed with the NCA "without delay".
// Resolved drafts are archived to the durable "closed_stors" bucket (when a
// BlockStore is configured) and removed from the live PendingSTORs map.
// POST /v1/compliance/stor/{id}/resolve
// Body: {"action":"file"|"dismiss","nca_ref":"optional ref","notes":"optional"}
func (s *Server) handleResolveSTOR(w http.ResponseWriter, r *http.Request) {
	storID := r.PathValue("id")
	resolverKey := walletFromCtx(r)

	var req struct {
		Action string `json:"action"` // "file" or "dismiss"
		NCARef string `json:"nca_ref,omitempty"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Action != "file" && req.Action != "dismiss" {
		writeError(w, http.StatusBadRequest, `action must be "file" or "dismiss"`)
		return
	}

	// Mutates bc.PendingSTORs, which is also read/written by detectSTORs inside
	// applyBlockState — bc.Mu must be held for the whole read-modify-write.
	s.bc.Mu.Lock()
	stor, ok := s.bc.PendingSTORs[storID]
	if !ok {
		s.bc.Mu.Unlock()
		writeError(w, http.StatusNotFound, "STOR not found")
		return
	}
	if stor.Resolution != gonetwork.STORResolutionPendingReview {
		resolution := stor.Resolution
		s.bc.Mu.Unlock()
		writeError(w, http.StatusConflict, fmt.Sprintf("STOR is already %s", resolution))
		return
	}
	if req.Action == "file" {
		stor.Resolution = gonetwork.STORResolutionFiledWithNCA
		stor.NCARef = req.NCARef
	} else {
		stor.Resolution = gonetwork.STORResolutionDismissed
	}
	stor.ResolvedAt = time.Now().Unix()
	stor.ResolvedBy = resolverKey
	storCopy := *stor
	// Only remove from the live map once we know the resolved record has
	// somewhere durable to go; see handleResolveSAR for the same rationale.
	archiving := s.bc.BlockStore != nil
	if archiving {
		delete(s.bc.PendingSTORs, storID)
	}
	s.bc.Mu.Unlock()

	if archiving {
		if err := s.bc.BlockStore.SaveClosedSTOR(&storCopy); err != nil {
			log.Printf("handleResolveSTOR: failed to archive resolved STOR %s: %v", storID, err)
		}
	}

	writeJSON(w, http.StatusOK, &storCopy)
}

// ---------------------------------------------------------------------------
// Settlement finality certificate
// ---------------------------------------------------------------------------

// handleGetBlockFinality returns a finality certificate for the block at the
// specified index. This gives external parties (custodians, transfer agents) a
// machine-readable proof that settlement has reached dBFT finality.
// GET /v1/blocks/{index}/finality
func (s *Server) handleGetBlockFinality(w http.ResponseWriter, r *http.Request) {
	indexStr := r.PathValue("index")
	idx, err := strconv.Atoi(indexStr)
	if err != nil || idx < 0 {
		writeError(w, http.StatusBadRequest, "invalid block index")
		return
	}

	blocks := s.bc.Blocks
	if idx >= len(blocks) {
		writeError(w, http.StatusNotFound, "block not found")
		return
	}
	blk := blocks[idx]

	writeJSON(w, http.StatusOK, map[string]any{
		"block_index": idx,
		"block_hash":  blk.CalculateHash(),
		"prev_hash":   blk.PrevHash,
		"tx_count":    len(blk.Transactions),
		"finality":    "dbft", // deterministic finality — no forks possible
		"queried_at":  time.Now().UTC().Unix(),
	})
}

// handleRegisterDelegateVote lets an authenticated investor assign their
// consensus voting power to another registered user (or themselves).
// H-6: populates UserIDToDelegateID so that getDelegateID returns a real entry.
//
// POST /v1/delegates/vote
// Body: { "delegate_id": "<wallet-key or user-id>" }
// Omitting delegate_id or setting it to the caller's own wallet key = self-delegation.
func (s *Server) handleRegisterDelegateVote(w http.ResponseWriter, r *http.Request) {
	callerKey := walletFromCtx(r)
	if callerKey == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body struct {
		DelegateID string `json:"delegate_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.DelegateID == "" {
		body.DelegateID = callerKey // default: self-delegation
	}

	s.bc.RegisterDelegateVote(callerKey, body.DelegateID)
	writeJSON(w, http.StatusOK, map[string]any{
		"voter_id":    callerKey,
		"delegate_id": body.DelegateID,
	})
}
