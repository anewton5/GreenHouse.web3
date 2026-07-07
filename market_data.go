package gonetwork

import (
	"fmt"
	"math"
	"time"
)

// InventoryReport summarises a wallet's current and open trading exposure.
type InventoryReport struct {
	WalletKey         string             `json:"wallet_key"`
	Holdings          map[string]float64 `json:"holdings"`
	OpenOrderExposure map[string]float64 `json:"open_order_exposure"`
	OpenQuoteExposure map[string]float64 `json:"open_quote_exposure"`
	GeneratedAt       int64              `json:"generated_at"`
}

// VWAP computes a time-windowed volume-weighted average price for one asset.
// Returns 0 when the window has no eligible trades or when total quantity is 0.
func VWAP(trades []Trade, assetID string, window time.Duration) float64 {
	if assetID == "" || window <= 0 {
		return 0
	}
	cutoff := time.Now().Add(-window).Unix()
	relevant := make([]Trade, 0)
	for _, tr := range trades {
		if tr.AssetID != assetID {
			continue
		}
		if tr.ExecutedAt != 0 && tr.ExecutedAt < cutoff {
			continue
		}
		relevant = append(relevant, tr)
	}
	vwap, _ := vwapFromTrades(relevant)
	return vwap
}

// InventorySnapshot aggregates holdings and open order/quote exposures for walletKey.
func InventorySnapshot(walletKey string, bc *Blockchain) InventoryReport {
	if bc == nil || walletKey == "" {
		return InventoryReport{
			WalletKey:         walletKey,
			Holdings:          map[string]float64{},
			OpenOrderExposure: map[string]float64{},
			OpenQuoteExposure: map[string]float64{},
			GeneratedAt:       time.Now().Unix(),
		}
	}
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()
	return inventorySnapshotLocked(walletKey, bc)
}

// inventorySnapshotLocked is the lock-free body of InventorySnapshot. bc.Mu must
// already be held (read or write) by the caller. Used internally by
// applyBlockState, which holds the write lock — calling the exported,
// self-locking InventorySnapshot from there would deadlock (sync.RWMutex is
// not re-entrant).
func inventorySnapshotLocked(walletKey string, bc *Blockchain) InventoryReport {
	report := InventoryReport{
		WalletKey:         walletKey,
		Holdings:          map[string]float64{},
		OpenOrderExposure: map[string]float64{},
		OpenQuoteExposure: map[string]float64{},
		GeneratedAt:       time.Now().Unix(),
	}
	if bc == nil || walletKey == "" {
		return report
	}

	for _, h := range bc.Holdings {
		if h == nil || h.HolderID != walletKey || h.AssetID == "" {
			continue
		}
		report.Holdings[h.AssetID] += h.Balance
	}

	for assetID, ob := range bc.OrderBooks {
		if ob == nil {
			continue
		}
		for _, o := range append(ob.Bids, ob.Asks...) {
			if o == nil || o.PlacedBy != walletKey {
				continue
			}
			if o.Status != OrderStatusOpen && o.Status != OrderStatusPartial {
				continue
			}
			remaining := o.Remaining()
			if remaining > 0 {
				report.OpenOrderExposure[assetID] += remaining
			}
		}
	}

	for requestID, quotes := range bc.RFQQuotes {
		req := bc.RFQRequests[requestID]
		if req == nil || req.AssetID == "" {
			continue
		}
		for _, q := range quotes {
			if q == nil || q.DealerKey != walletKey {
				continue
			}
			if q.Status != RFQQuoteStatusActive || q.IsExpired() {
				continue
			}
			if q.Quantity > 0 {
				report.OpenQuoteExposure[req.AssetID] += q.Quantity
			}
		}
	}

	return report
}

// CheckMarketMakerPositionLimit enforces optional position caps on designated market makers.
// additionalQuantity should be the incremental units that would increase the dealer's position.
func CheckMarketMakerPositionLimit(bc *Blockchain, dealerKey, assetID string, additionalQuantity float64) error {
	if bc == nil {
		return fmt.Errorf("blockchain is nil")
	}
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()
	return checkMarketMakerPositionLimitLocked(bc, dealerKey, assetID, additionalQuantity)
}

// checkMarketMakerPositionLimitLocked is the lock-free body of
// CheckMarketMakerPositionLimit. bc.Mu must already be held (read or write) by
// the caller — used internally by applyBlockState for the same re-entrancy
// reason as inventorySnapshotLocked.
func checkMarketMakerPositionLimitLocked(bc *Blockchain, dealerKey, assetID string, additionalQuantity float64) error {
	if bc == nil {
		return fmt.Errorf("blockchain is nil")
	}
	if dealerKey == "" {
		return fmt.Errorf("dealer key is required")
	}
	if assetID == "" {
		return fmt.Errorf("asset ID is required")
	}
	if additionalQuantity < 0 {
		return fmt.Errorf("additional quantity must be >= 0")
	}

	agreement := bc.MarketMakerRegistry.AgreementFor(assetID, dealerKey)
	if agreement == nil {
		return nil
	}

	report := inventorySnapshotLocked(dealerKey, bc)
	currentUnits := report.Holdings[assetID] + report.OpenOrderExposure[assetID] + report.OpenQuoteExposure[assetID]
	projectedUnits := currentUnits + additionalQuantity

	if agreement.MaxPositionUnits > 0 && projectedUnits > agreement.MaxPositionUnits+1e-9 {
		return fmt.Errorf(
			"projected position %.6f exceeds max_position_units %.6f for asset %s",
			projectedUnits,
			agreement.MaxPositionUnits,
			assetID,
		)
	}

	if agreement.MaxPositionValue > 0 {
		mark := latestAssetMarkPriceLocked(bc, assetID)
		if mark > 0 {
			projectedValue := projectedUnits * mark
			if projectedValue > agreement.MaxPositionValue+1e-9 {
				return fmt.Errorf(
					"projected position value %.6f exceeds max_position_value %.6f for asset %s",
					projectedValue,
					agreement.MaxPositionValue,
					assetID,
				)
			}
		}
	}

	return nil
}

// vwapFromTrades centralises VWAP core math for STOR detection and market data APIs.
func vwapFromTrades(trades []Trade) (float64, int) {
	if len(trades) == 0 {
		return 0, 0
	}
	var sumPQ, sumQ float64
	count := 0
	for _, tr := range trades {
		if tr.Quantity <= 0 {
			continue
		}
		sumPQ += tr.Price * tr.Quantity
		sumQ += tr.Quantity
		count++
	}
	if sumQ == 0 {
		return 0, 0
	}
	return sumPQ / sumQ, count
}

func latestAssetMarkPrice(bc *Blockchain, assetID string) float64 {
	if bc == nil || assetID == "" {
		return 0
	}
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()
	return latestAssetMarkPriceLocked(bc, assetID)
}

// latestAssetMarkPriceLocked is the lock-free body of latestAssetMarkPrice.
// bc.Mu must already be held (read or write) by the caller.
func latestAssetMarkPriceLocked(bc *Blockchain, assetID string) float64 {
	if bc == nil || assetID == "" {
		return 0
	}
	for i := len(bc.Trades) - 1; i >= 0; i-- {
		tr := bc.Trades[i]
		if tr.AssetID == assetID && tr.Price > 0 && !math.IsNaN(tr.Price) && !math.IsInf(tr.Price, 0) {
			return tr.Price
		}
	}
	return 0
}
