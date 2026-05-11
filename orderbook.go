package gonetwork

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// OrderSide indicates whether an order is a buy (bid) or sell (ask).
type OrderSide string

const (
	OrderSideBid OrderSide = "bid"
	OrderSideAsk OrderSide = "ask"
)

// OrderStatus tracks the lifecycle of an order in the book.
type OrderStatus string

const (
	OrderStatusOpen      OrderStatus = "open"
	OrderStatusPartial   OrderStatus = "partial"
	OrderStatusFilled    OrderStatus = "filled"
	OrderStatusCancelled OrderStatus = "cancelled"
	OrderStatusExpired   OrderStatus = "expired"
)

// Order represents a single buy or sell order placed by a participant.
// Orders are signed by the placer — any mutation is detectable.
type Order struct {
	ID        string
	AssetID   string
	Side      OrderSide
	Price     float64 // price per unit in the asset's currency
	Quantity  float64 // total units requested
	Filled    float64 // units matched so far
	PlacedBy  string  // base64-encoded Ed25519 public key of the order placer
	PlacedAt  int64   // Unix nanosecond timestamp — used for time-priority ordering
	ExpiresAt int64   // Unix timestamp (seconds); 0 = GTC (good till cancelled)
	Status    OrderStatus
	Signature []byte // Ed25519 sig over all fields (with Signature=nil)
}

// Trade is the immutable record of a matched execution.
// One Trade is produced per matched bid/ask pair.
type Trade struct {
	ID         string
	AssetID    string
	BidOrderID string
	AskOrderID string
	BuyerID    string  // base64-encoded public key of the buyer
	SellerID   string  // base64-encoded public key of the seller
	Price      float64 // execution price (= ask price — price-time priority)
	Quantity   float64
	Currency   string
	ExecutedAt int64  // Unix timestamp
	Status     string `json:"status,omitempty"` // "" = settled; "pending_approval" = awaiting seller co-sig
}

// OrderBook holds all open orders for a single asset.
// Bids are sorted highest-price first; Asks are sorted lowest-price first.
// Within the same price level, orders are sorted by PlacedAt ascending (time priority).
type OrderBook struct {
	AssetID string
	Bids    []*Order // sorted: highest price first
	Asks    []*Order // sorted: lowest price first
}

// OrderTransaction is broadcast via P2P to place or cancel an order.
// Tx.Sender = order placer's public key; Tx.Amount = 0 (not a value transfer).
type OrderTransaction struct {
	Tx             Transaction
	Order          Order
	IsCancellation bool // if true, cancel Order.ID; if false, place new order
}

// ---------------------------------------------------------------------------
// Order functions
// ---------------------------------------------------------------------------

// NewOrder creates and signs a new order on behalf of the placer.
// The Signature covers all fields — any mutation is detectable via VerifySignature.
func NewOrder(
	placerKey *PrivateKey,
	assetID string,
	side OrderSide,
	price float64,
	quantity float64,
	expiresAt int64,
) (*Order, error) {
	if placerKey == nil {
		return nil, fmt.Errorf("placer key must not be nil")
	}
	if assetID == "" {
		return nil, fmt.Errorf("asset ID must not be empty")
	}
	if price <= 0 {
		return nil, fmt.Errorf("price must be greater than zero, got %g", price)
	}
	if quantity <= 0 {
		return nil, fmt.Errorf("quantity must be greater than zero, got %g", quantity)
	}

	placerKeyStr := base64.StdEncoding.EncodeToString(placerKey.Public().Bytes())
	nowNano := time.Now().UnixNano()

	// Derive a unique ID from the placer key, asset, and nanosecond timestamp.
	idSrc := fmt.Sprintf("%s:%s:%d", placerKeyStr, assetID, nowNano)
	idHash := sha3.Sum256([]byte(idSrc))

	o := &Order{
		ID:        hex.EncodeToString(idHash[:]),
		AssetID:   assetID,
		Side:      side,
		Price:     price,
		Quantity:  quantity,
		Filled:    0,
		PlacedBy:  placerKeyStr,
		PlacedAt:  nowNano,
		ExpiresAt: expiresAt,
		Status:    OrderStatusOpen,
		Signature: nil, // must be nil during signing
	}

	data, err := json.Marshal(o)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal order for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	o.Signature = placerKey.Sign(hash[:]).Bytes()

	return o, nil
}

// Remaining returns the unmatched quantity still outstanding on the order.
func (o *Order) Remaining() float64 {
	return o.Quantity - o.Filled
}

// IsExpired returns true if the order has passed its expiry time.
// Orders with ExpiresAt == 0 (GTC — good till cancelled) never expire.
func (o *Order) IsExpired() bool {
	return o.ExpiresAt > 0 && time.Now().Unix() > o.ExpiresAt
}

// VerifySignature checks the placer's Ed25519 signature on the order.
// Returns false if the order has been tampered with or the signature is missing.
func (o *Order) VerifySignature(placerPubKey *PublicKey) bool {
	if placerPubKey == nil || len(o.Signature) == 0 {
		return false
	}
	orderCopy := *o
	orderCopy.Signature = nil
	data, err := json.Marshal(orderCopy)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: o.Signature}
	return sig.Verify(placerPubKey, hash[:])
}

// ---------------------------------------------------------------------------
// OrderBook functions
// ---------------------------------------------------------------------------

// NewOrderBook creates an empty order book for the given asset.
func NewOrderBook(assetID string) *OrderBook {
	return &OrderBook{
		AssetID: assetID,
		Bids:    []*Order{},
		Asks:    []*Order{},
	}
}

// AddOrder validates and inserts an order into the book, maintaining sort order.
// The order signature is verified against placerPubKey before insertion.
// Bids: sorted highest-price first, then earliest PlacedAt first at equal price.
// Asks: sorted lowest-price first, then earliest PlacedAt first at equal price.
func (ob *OrderBook) AddOrder(order *Order, placerPubKey *PublicKey) error {
	if order == nil {
		return fmt.Errorf("order must not be nil")
	}
	if placerPubKey == nil {
		return fmt.Errorf("placer public key must not be nil")
	}
	if !order.VerifySignature(placerPubKey) {
		return fmt.Errorf("invalid order signature")
	}
	if order.IsExpired() {
		return fmt.Errorf("cannot add expired order")
	}

	switch order.Side {
	case OrderSideBid:
		ob.Bids = append(ob.Bids, order)
		sort.Slice(ob.Bids, func(i, j int) bool {
			if ob.Bids[i].Price != ob.Bids[j].Price {
				return ob.Bids[i].Price > ob.Bids[j].Price // descending: highest bid first
			}
			return ob.Bids[i].PlacedAt < ob.Bids[j].PlacedAt // ascending: earlier order first
		})
	case OrderSideAsk:
		ob.Asks = append(ob.Asks, order)
		sort.Slice(ob.Asks, func(i, j int) bool {
			if ob.Asks[i].Price != ob.Asks[j].Price {
				return ob.Asks[i].Price < ob.Asks[j].Price // ascending: lowest ask first
			}
			return ob.Asks[i].PlacedAt < ob.Asks[j].PlacedAt // ascending: earlier order first
		})
	default:
		return fmt.Errorf("unknown order side: %q", order.Side)
	}

	return nil
}

// CancelOrder removes an order from the book and marks it cancelled.
// Only the original placer (identified by their public key string) may cancel.
func (ob *OrderBook) CancelOrder(orderID string, cancellerKey string) error {
	for i, o := range ob.Bids {
		if o.ID == orderID {
			if o.PlacedBy != cancellerKey {
				return fmt.Errorf("cancellation rejected: %s did not place order %s", cancellerKey, orderID)
			}
			o.Status = OrderStatusCancelled
			ob.Bids = append(ob.Bids[:i], ob.Bids[i+1:]...)
			return nil
		}
	}
	for i, o := range ob.Asks {
		if o.ID == orderID {
			if o.PlacedBy != cancellerKey {
				return fmt.Errorf("cancellation rejected: %s did not place order %s", cancellerKey, orderID)
			}
			o.Status = OrderStatusCancelled
			ob.Asks = append(ob.Asks[:i], ob.Asks[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("order not found: %s", orderID)
}

// ExpireOrders removes all orders past their ExpiresAt timestamp from the book.
// Called at the start of each MatchOrders run.
func (ob *OrderBook) ExpireOrders() {
	now := time.Now().Unix()

	var activeBids []*Order
	for _, o := range ob.Bids {
		if o.ExpiresAt > 0 && now > o.ExpiresAt {
			o.Status = OrderStatusExpired
		} else {
			activeBids = append(activeBids, o)
		}
	}
	ob.Bids = activeBids

	var activeAsks []*Order
	for _, o := range ob.Asks {
		if o.ExpiresAt > 0 && now > o.ExpiresAt {
			o.Status = OrderStatusExpired
		} else {
			activeAsks = append(activeAsks, o)
		}
	}
	ob.Asks = activeAsks
}

// MatchOrders runs the price-time priority matching algorithm and returns all
// trades and corresponding asset transactions for this matching cycle.
//
// Execution rules:
//   - Bids and asks are matched if bestBid.Price >= bestAsk.Price.
//   - Execution price is always the ask price (price-time priority).
//   - Matched quantity is min(bestBid.Remaining(), bestAsk.Remaining()).
//   - Expired orders are removed before matching begins.
//
// IMPORTANT — unsigned transactions:
// The returned AssetTransactions have empty Signatures (RequiredSigs=1, Signatures=nil).
// They cannot pass the normal Validate signature check. In the Phase 0 simulation,
// the simulation script holds all private keys and signs them immediately. In production,
// this is an off-chain signing request sent to the seller's client software.
//
// MatchOrders does NOT call ApplyAssetTransaction — DVP settlement happens in
// finalizeBlock after payment confirmation.
func (ob *OrderBook) MatchOrders(assetID string, currency string) ([]Trade, []*AssetTransaction, error) {
	ob.ExpireOrders()

	var trades []Trade
	var assetTxs []*AssetTransaction

	for len(ob.Bids) > 0 && len(ob.Asks) > 0 {
		bestBid := ob.Bids[0]
		bestAsk := ob.Asks[0]

		if bestBid.Price < bestAsk.Price {
			break // spread: no match possible
		}

		// Matched quantity is the smaller of the two remaining amounts.
		qty := bestBid.Remaining()
		if bestAsk.Remaining() < qty {
			qty = bestAsk.Remaining()
		}
		price := bestAsk.Price // execute at ask price

		// Generate a deterministic trade ID from order IDs and nanosecond timestamp.
		idSrc := fmt.Sprintf("%s:%s:%d", bestBid.ID, bestAsk.ID, time.Now().UnixNano())
		idHash := sha3.Sum256([]byte(idSrc))

		trade := Trade{
			ID:         hex.EncodeToString(idHash[:]),
			AssetID:    assetID,
			BidOrderID: bestBid.ID,
			AskOrderID: bestAsk.ID,
			BuyerID:    bestBid.PlacedBy,
			SellerID:   bestAsk.PlacedBy,
			Price:      price,
			Quantity:   qty,
			Currency:   currency,
			ExecutedAt: time.Now().Unix(),
		}
		trades = append(trades, trade)

		// Build unsigned AssetTransaction: seller transfers qty units to buyer.
		// Signatures intentionally empty — see function comment above.
		at := &AssetTransaction{
			Tx: Transaction{
				Sender:       bestAsk.PlacedBy, // seller
				Receiver:     bestBid.PlacedBy, // buyer
				Amount:       qty,
				RequiredSigs: 1,
				Nonce:        time.Now().UnixNano(),
			},
			AssetID: assetID,
			TxType:  AssetTxTypeTransfer,
		}
		assetTxs = append(assetTxs, at)

		// Update fill state and remove fully filled orders.
		bestBid.Filled += qty
		bestAsk.Filled += qty

		if bestBid.Remaining() <= 0 {
			bestBid.Status = OrderStatusFilled
			ob.Bids = ob.Bids[1:]
		} else {
			bestBid.Status = OrderStatusPartial
		}

		if bestAsk.Remaining() <= 0 {
			bestAsk.Status = OrderStatusFilled
			ob.Asks = ob.Asks[1:]
		} else {
			bestAsk.Status = OrderStatusPartial
		}
	}

	return trades, assetTxs, nil
}
