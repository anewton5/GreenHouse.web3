package gonetwork

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// WindowStatus tracks the lifecycle of a LiquidityWindow.
type WindowStatus string

const (
	WindowStatusScheduled WindowStatus = "scheduled" // defined, not yet open
	WindowStatusOpen      WindowStatus = "open"      // order matching active
	WindowStatusClosed    WindowStatus = "closed"    // matching complete, book frozen
	WindowStatusCancelled WindowStatus = "cancelled" // cancelled before open
)

// LiquidityWindow defines a time-bounded trading period for a single asset.
// Outside an open window, orders may be submitted to the book but MatchOrders
// is suppressed — no trades are generated until the window closes.
type LiquidityWindow struct {
	ID          string       `json:"id"`
	AssetID     string       `json:"asset_id"`
	OpenAt      int64        `json:"opens_at"`   // Unix seconds — window opens
	CloseAt     int64        `json:"closes_at"`  // Unix seconds — matching fires at close
	MaxVolume   float64      `json:"max_volume"` // 0 = unlimited
	Currency    string       `json:"currency"`
	Status      WindowStatus `json:"status"`
	ProposerKey string       `json:"proposer_key"` // base64-encoded Ed25519 public key
	Signature   []byte       `json:"-"`
}

// WindowResult is the settlement summary produced when a LiquidityWindow closes.
// It is appended to Blockchain.WindowResults for auditability.
type WindowResult struct {
	WindowID      string  `json:"window_id"`
	AssetID       string  `json:"asset_id"`
	TotalVolume   float64 `json:"total_volume"` // total units matched
	TotalValue    float64 `json:"total_value"`  // total cash value of matched trades
	TradeCount    int     `json:"trade_count"`
	ClearingPrice float64 `json:"clearing_price"` // volume-weighted average price (VWAP)
	ClosedAt      int64   `json:"closed_at"`
}

// ---------------------------------------------------------------------------
// LiquidityWindow constructor and methods
// ---------------------------------------------------------------------------

// NewLiquidityWindow creates and signs a LiquidityWindow.
// openAt must be strictly in the future and strictly before closeAt.
func NewLiquidityWindow(
	proposerKey *PrivateKey,
	assetID string,
	openAt, closeAt int64,
	maxVolume float64,
	currency string,
) (*LiquidityWindow, error) {
	if assetID == "" {
		return nil, fmt.Errorf("assetID must not be empty")
	}
	if currency == "" {
		return nil, fmt.Errorf("currency must not be empty")
	}
	if openAt >= closeAt {
		return nil, fmt.Errorf("openAt (%d) must be before closeAt (%d)", openAt, closeAt)
	}
	if openAt <= time.Now().UTC().Unix() {
		return nil, fmt.Errorf("openAt must be in the future")
	}

	pubKeyStr := base64.StdEncoding.EncodeToString(proposerKey.Public().Bytes())

	// Deterministic ID: sha3-256(proposerPubKey || assetID || openAt big-endian)
	h := sha3.New256()
	h.Write([]byte(pubKeyStr))
	h.Write([]byte(assetID))
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(openAt))
	h.Write(buf)
	id := hex.EncodeToString(h.Sum(nil))

	w := &LiquidityWindow{
		ID:          id,
		AssetID:     assetID,
		OpenAt:      openAt,
		CloseAt:     closeAt,
		MaxVolume:   maxVolume,
		Currency:    currency,
		Status:      WindowStatusScheduled,
		ProposerKey: pubKeyStr,
	}

	// Sign: marshal with Signature=nil (already nil on new struct), sha3.Sum256, sign
	data, err := json.Marshal(w)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal window for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	w.Signature = proposerKey.Sign(hash[:]).Bytes()

	return w, nil
}

// IsOpen returns true when the window is currently in WindowStatusOpen.
func (w *LiquidityWindow) IsOpen() bool {
	return w.Status == WindowStatusOpen
}

// ShouldOpen returns true when the window is scheduled and its open time has arrived.
func (w *LiquidityWindow) ShouldOpen() bool {
	return w.Status == WindowStatusScheduled && time.Now().UTC().Unix() >= w.OpenAt
}

// ShouldClose returns true when the window is open and its close time has arrived.
func (w *LiquidityWindow) ShouldClose() bool {
	return w.Status == WindowStatusOpen && time.Now().UTC().Unix() >= w.CloseAt
}

// VerifySignature verifies the proposer's Ed25519 signature over this window's fields.
func (w *LiquidityWindow) VerifySignature(proposerPubKey *PublicKey) bool {
	wCopy := *w
	wCopy.Signature = nil
	data, err := json.Marshal(wCopy)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: w.Signature}
	return sig.Verify(proposerPubKey, hash[:])
}

// ---------------------------------------------------------------------------
// WindowManager
// ---------------------------------------------------------------------------

// WindowManager tracks all LiquidityWindows across all assets and drives their
// lifecycle transitions on every call to Tick.
type WindowManager struct {
	Windows  map[string]*LiquidityWindow   // windowID → window
	Schedule map[string][]*LiquidityWindow // assetID → chronologically ordered windows
}

// NewWindowManager returns an initialised, empty WindowManager.
func NewWindowManager() *WindowManager {
	return &WindowManager{
		Windows:  make(map[string]*LiquidityWindow),
		Schedule: make(map[string][]*LiquidityWindow),
	}
}

// ScheduleWindow registers w with the manager.
// Returns an error if w overlaps any existing non-cancelled window for the same asset.
func (wm *WindowManager) ScheduleWindow(w *LiquidityWindow) error {
	for _, existing := range wm.Schedule[w.AssetID] {
		if existing.Status == WindowStatusCancelled {
			continue
		}
		// Overlap: ranges intersect when neither is entirely before or after the other
		if w.OpenAt < existing.CloseAt && w.CloseAt > existing.OpenAt {
			return fmt.Errorf(
				"window %s overlaps existing window %s for asset %s",
				w.ID, existing.ID, w.AssetID,
			)
		}
	}
	wm.Windows[w.ID] = w
	wm.Schedule[w.AssetID] = append(wm.Schedule[w.AssetID], w)
	return nil
}

// HasOpenWindow returns true if there is a currently open LiquidityWindow for assetID.
func (wm *WindowManager) HasOpenWindow(assetID string) bool {
	for _, w := range wm.Schedule[assetID] {
		if w.IsOpen() {
			return true
		}
	}
	return false
}

// IsManaged returns true if the WindowManager has at least one registered window
// (in any state) for assetID. Unmanaged assets are not subject to window gating —
// their order books match on every block as in Phase 0.
func (wm *WindowManager) IsManaged(assetID string) bool {
	return len(wm.Schedule[assetID]) > 0
}

// Tick is called at the start of each finalizeBlock pass.
// It opens scheduled windows whose time has arrived, closes open windows whose
// close time has arrived (running MatchOrders + DVP for each), and returns a
// WindowResult for every window that was just closed.
func (wm *WindowManager) Tick(bc *Blockchain) []WindowResult {
	var results []WindowResult

	for _, w := range wm.Windows {
		if w.ShouldOpen() {
			w.Status = WindowStatusOpen
			continue
		}

		if !w.ShouldClose() {
			continue
		}

		w.Status = WindowStatusClosed

		result := WindowResult{
			WindowID: w.ID,
			AssetID:  w.AssetID,
			ClosedAt: time.Now().UTC().Unix(),
		}

		ob, hasBook := bc.OrderBooks[w.AssetID]
		asset, hasAsset := bc.Assets[w.AssetID]
		if !hasBook || !hasAsset {
			results = append(results, result)
			continue
		}

		trades, assetTxs, err := ob.MatchOrders(w.AssetID, asset.Currency)
		if err != nil {
			fmt.Printf("WindowManager: MatchOrders error for window %s: %v\n", w.ID, err)
			results = append(results, result)
			continue
		}

		var totalVolume, totalValue float64
		for i, trade := range trades {
			// Honour MaxVolume cap if set
			if w.MaxVolume > 0 && totalVolume+trade.Quantity > w.MaxVolume {
				break
			}
			totalVolume += trade.Quantity
			totalValue += trade.Price * trade.Quantity

			bc.Trades = append(bc.Trades, trade)
			wm.applyDVP(bc, trade, assetTxs[i])
		}

		result.TotalVolume = totalVolume
		result.TotalValue = totalValue
		result.TradeCount = len(trades)
		if totalVolume > 0 {
			result.ClearingPrice = totalValue / totalVolume
		}

		results = append(results, result)
	}

	return results
}

// applyDVP mirrors the DVP flow from finalizeBlock: issue PaymentInstruction,
// confirm via PaymentProvider, sign PaymentConfirmation, apply asset transfer.
func (wm *WindowManager) applyDVP(bc *Blockchain, trade Trade, atx *AssetTransaction) {
	instruction := &PaymentInstruction{
		TradeID:       trade.ID,
		AssetID:       trade.AssetID,
		Quantity:      trade.Quantity,
		PricePerUnit:  trade.Price,
		TotalAmount:   trade.Price * trade.Quantity,
		Currency:      trade.Currency,
		Method:        SettlementSEPA,
		PayerWalletID: trade.BuyerID,
		PayeeWalletID: trade.SellerID,
		Reference:     fmt.Sprintf("GH-%s", trade.ID[:8]),
		ExpiresAt:     time.Now().UTC().Unix() + 86400,
	}
	instruction, _ = bc.OracleService.SignInstruction(instruction)
	bc.PendingInstructions[trade.ID] = instruction

	_ = bc.PaymentProvider.ConfirmPayment(
		instruction.Reference,
		instruction.TotalAmount,
		instruction.Currency,
	)
	status, _ := bc.PaymentProvider.GetPaymentStatus(instruction.Reference)
	if status != PaymentStatusConfirmed {
		return
	}

	confirmation := &PaymentConfirmation{
		InstructionID:   trade.ID,
		Reference:       instruction.Reference,
		ConfirmedAmount: instruction.TotalAmount,
		Currency:        instruction.Currency,
		ConfirmedAt:     time.Now().UTC().Unix(),
	}
	confirmation, _ = bc.OracleService.SignConfirmation(confirmation)
	bc.ConfirmedPayments[trade.ID] = confirmation

	if err := ApplyAssetTransaction(atx, bc.Assets, bc.Holdings); err != nil {
		fmt.Printf("DVP apply failed for window trade %s: %v\n", trade.ID, err)
	}
}
