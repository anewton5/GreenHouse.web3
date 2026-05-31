package gonetwork

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"
)

type Transaction struct {
	Sender       string
	Receiver     string
	Amount       float64
	Signatures   [][]byte
	RequiredSigs int
	Nonce        int64
}

func (t *Transaction) GenerateNonce() {
	t.Nonce = time.Now().UnixNano()
}

func (t *Transaction) AddSignature(signature []byte) {
	t.Signatures = append(t.Signatures, signature)
}

func (t *Transaction) VerifyMultiSignature(pubKeys []*PublicKey) bool {
	// Ensure the number of signatures meets the required threshold
	if len(t.Signatures) < t.RequiredSigs {
		return false
	}

	validSigs := 0
	txHash := t.hash()

	// Verify each signature against the corresponding public key
	for i, sig := range t.Signatures {
		if i >= len(pubKeys) {
			break
		}
		if ed25519.Verify(pubKeys[i].key, txHash, sig) {
			validSigs++
		}
	}

	// Check if the number of valid signatures meets the required threshold
	return validSigs >= t.RequiredSigs
}

// Verifies the transaction by checking the signature against the sender's public key
func (t *Transaction) VerifyTransaction(pubKeys []*PublicKey) (bool, error) {
	// Validate transaction fields
	if t.Amount <= 0 {
		return false, fmt.Errorf("invalid transaction: amount must be greater than zero")
	}

	if t.Sender == "" || t.Receiver == "" {
		return false, fmt.Errorf("invalid transaction: sender and receiver must not be empty")
	}

	// Ensure the number of signatures meets the required threshold
	if len(t.Signatures) < t.RequiredSigs {
		return false, fmt.Errorf("insufficient signatures: required %d, got %d", t.RequiredSigs, len(t.Signatures))
	}

	// Calculate the transaction hash
	txHash := t.hash()

	// Verify each signature against the corresponding public key
	validSigs := 0
	for i, sig := range t.Signatures {
		if i >= len(pubKeys) {
			break
		}
		if ed25519.Verify(pubKeys[i].key, txHash, sig) {
			validSigs++
		}
	}

	// Check if the number of valid signatures meets the required threshold
	if validSigs < t.RequiredSigs {
		return false, fmt.Errorf("insufficient valid signatures: required %d, got %d", t.RequiredSigs, validSigs)
	}

	return true, nil
}

type Block struct {
	Index       int    `json:"index"`
	PayloadHash string `json:"payload_hash,omitempty"`
	// SealedAt is the Unix microsecond timestamp set by AddBlock immediately
	// before SetPayloadHash is called. It is included in the signed payload
	// hash so it cannot be altered without invalidating all delegate signatures.
	// Required for MiFIR RTS 22 / MAR / CSDR regulatory timestamp obligations.
	SealedAt int64 `json:"sealed_at"`
	// KeyVersion is the base64-encoded Ed25519 public key of the operator that
	// sealed this block, set to OperatorKeyProvider.PublicKeyString() in AddBlock.
	// Receiving nodes use it to verify the operator signature and to look up the
	// correct key after a rotation. Included in blockHashInput so it cannot be
	// substituted post-hoc without invalidating all delegate signatures.
	KeyVersion             string                  `json:"key_version,omitempty"`
	Transactions           []Transaction           `json:"Transactions"`
	AssetTransactions      []AssetTransaction      `json:"AssetTransactions,omitempty"`
	OrderTransactions      []OrderTransaction      `json:"OrderTransactions,omitempty"`
	CredentialTransactions []CredentialTransaction `json:"CredentialTransactions,omitempty"`
	PrevHash               string
	Nonce                  int
	Signatures             [][]byte
}

// blockHashInput is the deterministic pre-signature representation of a block
// used as the payload that delegates sign. It excludes Signatures so the hash
// is stable regardless of how many signatures are collected.
type blockHashInput struct {
	Index                  int                     `json:"index"`
	SealedAt               int64                   `json:"sealed_at"`
	KeyVersion             string                  `json:"key_version,omitempty"`
	Transactions           []Transaction           `json:"transactions"`
	AssetTransactions      []AssetTransaction      `json:"asset_transactions,omitempty"`
	OrderTransactions      []OrderTransaction      `json:"order_transactions,omitempty"`
	CredentialTransactions []CredentialTransaction `json:"credential_transactions,omitempty"`
	PrevHash               string                  `json:"prev_hash"`
	Nonce                  int                     `json:"nonce"`
}

// SetPayloadHash computes and stores the pre-signature block hash. Must be
// called after all transaction fields are populated and before any signatures
// are added. Delegates sign PayloadHash; CalculateHash includes signatures
// and is used for chain-linking (PrevHash references).
func (b *Block) SetPayloadHash() {
	input := blockHashInput{
		Index:                  b.Index,
		SealedAt:               b.SealedAt,
		KeyVersion:             b.KeyVersion,
		Transactions:           b.Transactions,
		AssetTransactions:      b.AssetTransactions,
		OrderTransactions:      b.OrderTransactions,
		CredentialTransactions: b.CredentialTransactions,
		PrevHash:               b.PrevHash,
		Nonce:                  b.Nonce,
	}
	data, _ := json.Marshal(input)
	hash := sha3.Sum256(data)
	b.PayloadHash = hex.EncodeToString(hash[:])
}

func (b *Block) CalculateHash() string {
	blockData, _ := json.Marshal(b)
	hash := sha3.Sum256(blockData)
	return hex.EncodeToString(hash[:])
}

type View struct {
	Number int
}

const (
	ConsensusModeHTTP   = "http"
	ConsensusModeDBFT   = "dbft"
	consensusModeHybrid = "hybrid"
)

type Blockchain struct {
	// Mu guards all mutable state on this struct. Callers must hold Mu.RLock()
	// for reads and Mu.Lock() for writes. Internal helpers (applyBlockState,
	// confirmAndSettleLocked, etc.) assume the caller already holds the
	// appropriate lock — they do not acquire it themselves.
	// ConfirmAndSettle (the public method) is self-locking and safe to call
	// concurrently from multiple goroutines (e.g. concurrent webhook deliveries).
	Mu sync.RWMutex `json:"-"`

	Blocks             []Block
	Nodes              []Node
	LockedWallets      map[[32]byte]*LockedWallet `json:"-"`
	Delegates          []Node
	PublicKeyToID      map[string]string
	UserIDToDelegateID map[string]string
	currentView        View
	currentSpeaker     int
	Wallets            map[string]*Wallet
	Nonce              int
	TransactionPool    []Transaction
	Shards             []*Shard
	P2PNode            *P2PNode `json:"-"`

	// Asset layer
	Assets   map[string]*Asset        // assetID → Asset
	Holdings map[string]*AssetHolding // HoldingKey(holderID, assetID) → AssetHolding

	// Order book layer
	OrderBooks map[string]*OrderBook // assetID → OrderBook
	Trades     []Trade               // append-only trade history

	// Identity layer
	Credentials map[string]*CredentialAttestation // walletKey → attestation

	// Payment layer
	PendingInstructions      map[string]*PaymentInstruction  // tradeID → instruction
	ConfirmedPayments        map[string]*PaymentConfirmation // tradeID → confirmation
	PendingSettlements       map[string]*AssetTransaction    // tradeID → DVP asset tx awaiting payment
	PendingAssetTransactions []AssetTransaction              // received via P2P, awaiting block inclusion

	// Services (interfaces — swappable for live implementations)
	PaymentProvider  PaymentProvider  `json:"-"`
	IdentityRegistry IdentityRegistry `json:"-"`
	OracleService    OracleService    `json:"-"`

	// SettlementRouter dispatches PaymentInstructions to per-method providers.
	// Register providers via RegisterSettlementProvider. Falls back to
	// PaymentProvider when no entry exists for a given SettlementMethod.
	// Example: register a PontesPaymentProvider for SettlementCeBM once the
	// ECB Pontes pilot launches (Q3 2026).
	SettlementRouter map[SettlementMethod]PaymentProvider `json:"-"`

	// Phase 2: Liquidity Windows
	WindowManager *WindowManager
	WindowResults []WindowResult

	// Phase 2: SPV / Participation Notes
	SPVs map[string]*SPVWrapper // spvID → SPVWrapper

	// Phase 2: Corporate Actions
	PendingCorporateActions map[string]*CorporateAction // actionID → action

	// Phase 2: Multi-Jurisdiction Compliance
	ProspectusExemptions   map[string]*ProspectusExemption   // assetID → exemption
	SuitabilityAssessments map[string]*SuitabilityAssessment // walletKey:assetID → assessment
	JurisdictionRules      map[string]*JurisdictionRule      // countryCode → rule

	// Phase 2: FiDA Reporting
	CostBasisTracker *CostBasisTracker
	ValuationOracle  ValuationOracle

	// Phase 2: Deal Anchoring
	Deals map[string]*Deal // dealID → Deal

	// Part I: Legal doc amendment log — assetID → ordered list of amendments.
	// Use CurrentLegalDocHash(assetID) to resolve the current document hash.
	LegalDocAmendments map[string][]*LegalDocAmendment

	// Part III: Dividend holding snapshots — actionID → holdings frozen at record date.
	DividendHoldingSnapshots map[string]map[string]*AssetHolding

	// Phase 3 / Track 5: AML screening — called from AssetTransaction.Validate
	// before any other check. Defaults to MockAMLScreener (passes everything).
	// Replace with ComplyAdvantageScreener / EllipticScreener before going live.
	AMLScreener AMLScreener `json:"-"`

	// G-09: Suspicious Activity Report drafts — keyed by SAR ID.
	// Created automatically when the AML screener returns a flag-severity alert.
	// Compliance officers resolve them via POST /v1/compliance/sar/{id}/resolve.
	PendingSARs map[string]*SARDraft

	// G-10: Regulatory report log — append-only list of MiFIR/CMAR/AIFMD reports.
	// A new entry is created by SealBlock for every trade in a block that has a
	// reporting obligation.  In production, a reporter goroutine tails this list
	// and submits reports to the relevant NCA/ARM.
	RegulatoryReports []*RegulatoryReport

	// MAR Article 18: insider lists — keyed by assetID.
	// A list is created automatically when a new asset is admitted to trading.
	// Compliance officers maintain them; the NCA may request them at any time.
	InsiderLists map[string]*InsiderList

	// MAR Article 16: Suspicious Transaction and Order Report drafts — keyed by STOR ID.
	// Auto-created by order/trade pattern detection; resolved by compliance officers
	// via POST /v1/compliance/stor/{id}/resolve.
	PendingSTORs map[string]*STORDraft

	// MAR Article 16: rolling 30-day counterparty trade window for wash-trade detection.
	// Key: canonical sorted "buyerID:sellerID" pair. Value: trades within the last 30 days.
	// Pruned lazily on each detectSTORs call to avoid unbounded growth.
	RecentCounterpartyTrades map[string][]Trade

	// RegistrationRegistry provides KYC-verified investor PII for FATF Travel Rule
	// payload population. Set to the same registry used by the API server so that
	// finalizeBlock can look up buyer/seller names and addresses inline.
	// If nil, Travel Rule payloads are constructed with wallet keys only.
	RegistrationRegistry *RegistrationRegistry

	// Track 4: Real-time event stream
	// Events is a buffered channel onto which the blockchain emits StreamEvents
	// whenever significant state changes occur (blocks, trades, payments, credentials).
	// The API server reads from this channel and fans the events out to WebSocket clients.
	// Senders use bc.emitEvent() which never blocks — events are dropped when the
	// buffer is full rather than blocking the consensus path.
	Events chan StreamEvent `json:"-"`

	// WalletSequences tracks the last accepted nonce per sender public key.
	// Any transaction with nonce ≤ WalletSequences[sender] is rejected as a
	// replay. Time-based nonces (UnixNano) are monotonically increasing in
	// normal operation; this guard closes the replay window that opens when a
	// shard pool is cleared after a block is sealed.
	WalletSequences map[string]int64

	// ConsensusTimeout is the maximum time AchieveConsensus will wait for all
	// delegate votes before declaring a view-change (M-2). Defaults to 30s.
	// Set to 0 to disable the timeout (not recommended for production).
	ConsensusTimeout time.Duration

	// ConsensusMode controls which block production path is enabled.
	// "http" enables SealBlock and disables dBFT startConsensus.
	// "dbft" enables dBFT startConsensus and disables SealBlock.
	// "hybrid" (dev/test default) permits both paths for compatibility.
	ConsensusMode string

	// CommittedTxHashes stores hashes for all committed block transactions,
	// across base/asset/order/credential transaction families, to prevent
	// replaying already-committed entries in subsequently validated blocks.
	CommittedTxHashes map[string]struct{}

	// observability counters for enterprise monitoring and alerting.
	consensusModeRejects      uint64
	duplicateTxHashRejections uint64

	metricsMu                 sync.RWMutex
	consensusModeRejectByPath map[string]uint64
	duplicateTxRejectByReason map[string]uint64

	// OperatorKeyProvider is the node-operator's signing key used to add an
	// operator Ed25519 signature to every sealed block (C-2). When nil (default
	// in dev/test mode) the signing step is skipped. Set to a LocalKeyProvider
	// or VaultKeyProvider before starting a production node.
	OperatorKeyProvider KeyProvider `json:"-"`

	// BlockStore is an optional bbolt-backed persistent block store (C-4).
	// When non-nil, SealBlock writes each sealed block to disk so the chain
	// survives process restarts. Populate via OpenBlockStore() and call
	// LoadBlocks() before serving requests.
	BlockStore *BlockStore `json:"-"`

	// ReportingService is the regulatory reporting back-end used by SealBlock
	// to generate MiFIR/AIFMD reports for every trade in a sealed block.
	// Defaults to DefaultReportingService (on-chain record only). In production,
	// NewBlockchain replaces this with NCAReportingService so that reports are
	// also transmitted to the NCA/ARM and persisted to the outbox on failure.
	ReportingService ReportingService `json:"-"`

	// NetworkRegistryKey is the Ed25519 public key of the network registry.
	// Loaded from GREENHOUSE_REGISTRY_PUBKEY (64-char hex) at startup.
	// When set, the AllowlistGater enforces that every incoming P2P peer carries
	// a valid registry signature. When nil the gater operates in open mode
	// (development/test). Required in production (enforced by productionReadinessError).
	NetworkRegistryKey *PublicKey `json:"-"`
}

// ---------------------------------------------------------------------------
// StreamEvent — real-time event type
// ---------------------------------------------------------------------------

// StreamEvent is emitted by the blockchain onto the Events channel when
// significant state changes occur. The API server fans these out to all
// connected WebSocket clients.
type StreamEvent struct {
	Type      string          `json:"type"`
	Timestamp int64           `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
}

// Stream event type constants.
const (
	EventBlockFinalised    = "block_finalised"
	EventOrderPlaced       = "order_placed"
	EventOrderCancelled    = "order_cancelled"
	EventTradeExecuted     = "trade_executed"
	EventPaymentConfirmed  = "payment_confirmed"
	EventCredentialIssued  = "credential_issued"
	EventCredentialExpired = "credential_expired"
	EventSupplyMismatch    = "supply_mismatch"
	EventLegalDocAmended   = "legal_doc_amended"
	// G-10: emitted when a regulatory report (MiFIR, AIFMD, etc.) is generated.
	EventRegulatoryReport = "regulatory_report"
	// EventPaymentExpired is emitted when a PaymentInstruction passes its
	// ExpiresAt deadline without a confirmed payment. The DVP asset transfer
	// is not applied; the trade remains in a failed-settlement state.
	EventPaymentExpired = "payment_expired"
	// EventConsensusFailure is emitted by createBlock when all view-change
	// retries are exhausted without sealing a block (Item 9 Step D).
	EventConsensusFailure = "consensus_failure"
	// EventDelegateUnreachable is emitted by startConsensus when a delegate with
	// configured P2P peer ID cannot be reached after pre-consensus dial checks.
	EventDelegateUnreachable = "delegate_unreachable"
	// EventSTORCreated is emitted when a pattern-detection rule in applyBlockState
	// creates a new STORDraft (MAR Article 16 — market manipulation suspicion).
	EventSTORCreated = "stor_created"
	// EventConsensusModeInvariant records the resolved startup mode and enabled
	// block-production services after invariant evaluation.
	EventConsensusModeInvariant = "consensus_mode_invariant"
	// EventConsensusModeRejected is emitted when a mode-gated path is invoked.
	EventConsensusModeRejected = "consensus_mode_rejected"
	// EventDuplicateTransactionRejected is emitted when ValidateBlock rejects a
	// duplicate transaction hash (already committed or duplicated in-block).
	EventDuplicateTransactionRejected = "duplicate_transaction_rejected"
)

// EmitEvent is the exported entry point for emitEvent, allowing external
// packages (e.g. the API layer) to push events onto the stream channel.
func (bc *Blockchain) EmitEvent(eventType string, payload any) {
	bc.emitEvent(eventType, payload)
}

// ---------------------------------------------------------------------------
// FATF Travel Rule helper
// ---------------------------------------------------------------------------

// buildTravelRule constructs a TravelRulePayload for a payment above the FATF
// Recommendation 16 threshold. It tries to resolve originator and beneficiary
// names and addresses from the RegistrationRegistry; if the registry is not set
// or a record is absent, the wallet key is used as the account identifier only.
//
// The caller (finalizeBlock) is responsible for checking the EUR-equivalent amount
// against TravelRuleThresholdEUR before calling this function.
func (bc *Blockchain) buildTravelRule(payerKey, payeeKey, transferRef string) *TravelRulePayload {
	p := &TravelRulePayload{
		OriginatorAccount:  payerKey,
		BeneficiaryAccount: payeeKey,
		TransferRef:        transferRef,
	}
	if bc.RegistrationRegistry != nil {
		if rec := bc.RegistrationRegistry.Get(payerKey); rec != nil {
			p.OriginatorName = rec.Personal.FullLegalName
			p.OriginatorAddressLine = rec.Address.Line1
			p.OriginatorCity = rec.Address.City
			p.OriginatorCountryCode = rec.Address.Country
		}
		if rec := bc.RegistrationRegistry.Get(payeeKey); rec != nil {
			p.BeneficiaryName = rec.Personal.FullLegalName
			p.BeneficiaryAddressLine = rec.Address.Line1
			p.BeneficiaryCity = rec.Address.City
			p.BeneficiaryCountryCode = rec.Address.Country
		}
	}
	return p
}

// ---------------------------------------------------------------------------
// Settlement router helpers
// ---------------------------------------------------------------------------

// RegisterSettlementProvider registers a PaymentProvider for a specific
// SettlementMethod. The provider will be used for all PaymentInstructions
// whose Method matches. Call this after NewBlockchain and before the first
// block is finalised.
//
// Example — enable CeBM settlement once the Pontes pilot is live:
//
//	pontes, _ := gonetwork.NewPontesPaymentProviderFromEnv()
//	bc.RegisterSettlementProvider(gonetwork.SettlementCeBM, pontes)
func (bc *Blockchain) RegisterSettlementProvider(method SettlementMethod, p PaymentProvider) {
	bc.SettlementRouter[method] = p
}

// ProviderForMethod returns the PaymentProvider registered for the given
// SettlementMethod. Falls back to bc.PaymentProvider when none is registered.
func (bc *Blockchain) ProviderForMethod(method SettlementMethod) PaymentProvider {
	if p, ok := bc.SettlementRouter[method]; ok {
		return p
	}
	return bc.PaymentProvider
}

// ExpireStaleInstructions removes PendingInstructions whose ExpiresAt deadline
// has passed without a confirmed payment. An EventPaymentExpired is emitted for
// each expired instruction. The DVP asset transfer is not applied — the trade
// remains in a failed-settlement state until the issuer manually resolves it.
//
// This is called at the start of each finalizeBlock to ensure no stale
// instruction is left open indefinitely.
func (bc *Blockchain) ExpireStaleInstructions() {
	now := time.Now().Unix()
	for tradeID, instr := range bc.PendingInstructions {
		if instr.ExpiresAt <= 0 {
			continue
		}
		if now <= instr.ExpiresAt {
			continue
		}
		// Skip instructions that have already been settled (webhook may have
		// arrived before the expiry sweep runs).
		if _, settled := bc.ConfirmedPayments[tradeID]; settled {
			continue
		}
		delete(bc.PendingInstructions, tradeID)
		bc.emitEvent(EventPaymentExpired, map[string]any{
			"trade_id":   tradeID,
			"asset_id":   instr.AssetID,
			"payer":      instr.PayerWalletID,
			"payee":      instr.PayeeWalletID,
			"amount":     instr.TotalAmount,
			"currency":   instr.Currency,
			"method":     string(instr.Method),
			"expired_at": instr.ExpiresAt,
		})
	}
}

// ConfirmAndSettle marks a payment as confirmed and, if the corresponding
// PaymentInstruction exists and has not already been settled, applies the DVP
// asset transfer. It is the canonical entry point for payment confirmations
// arriving via webhook (Modulr, Pontes, EURC) and replaces direct calls to
// bc.PaymentProvider.ConfirmPayment from the webhook handlers.
//
// ConfirmAndSettle is safe to call concurrently from multiple goroutines. It
// acquires bc.Mu internally — callers must NOT hold the lock when calling this.
//
// Returns nil if the reference is unknown (no-op is intentional — webhook
// providers must not retry on unknown references).
func (bc *Blockchain) ConfirmAndSettle(reference string, amount float64, currency string) error {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()
	return bc.confirmAndSettleLocked(reference, amount, currency)
}

// confirmAndSettleLocked is the lock-free body of ConfirmAndSettle.
// bc.Mu must be held by the caller (e.g. applyBlockState).
func (bc *Blockchain) confirmAndSettleLocked(reference string, amount float64, currency string) error {
	// Find the matching instruction by reference.
	var instruction *PaymentInstruction
	var tradeID string
	for id, instr := range bc.PendingInstructions {
		if instr.Reference == reference {
			instruction = instr
			tradeID = id
			break
		}
	}
	if instruction == nil {
		// Unknown reference — not an error; the webhook may fire for a trade
		// already settled or not yet registered.
		return nil
	}

	// Idempotency: skip if already settled.
	if _, settled := bc.ConfirmedPayments[tradeID]; settled {
		return nil
	}

	// Record the confirmation via the registered provider.
	provider := bc.ProviderForMethod(instruction.Method)
	if err := provider.ConfirmPayment(reference, amount, currency); err != nil {
		return fmt.Errorf("ConfirmAndSettle: provider confirm failed: %w", err)
	}

	// Build and oracle-sign the on-chain confirmation.
	confirmation := &PaymentConfirmation{
		InstructionID:   tradeID,
		Reference:       reference,
		ConfirmedAmount: amount,
		Currency:        currency,
		ConfirmedAt:     time.Now().Unix(),
	}
	confirmation, _ = bc.OracleService.SignConfirmation(confirmation)
	bc.ConfirmedPayments[tradeID] = confirmation

	bc.emitEvent(EventPaymentConfirmed, map[string]any{
		"trade_id":  tradeID,
		"reference": reference,
		"amount":    amount,
		"currency":  currency,
	})

	// DVP: apply the asset transfer now that payment is confirmed.
	// The AssetTransaction was stored alongside the PaymentInstruction in
	// bc.PendingSettlements when the order was matched. If no pending
	// settlement exists we fall back to a direct holdings adjustment so
	// that legacy paths (e.g. finalizeBlock mock flow) still work correctly.
	if bc.PendingSettlements != nil {
		if atx, ok := bc.PendingSettlements[tradeID]; ok {
			if err := ApplyAssetTransaction(atx, bc.Assets, bc.Holdings); err != nil {
				return fmt.Errorf("ConfirmAndSettle: DVP apply failed for trade %s: %w", tradeID, err)
			}
			delete(bc.PendingSettlements, tradeID)
		}
	}

	return nil
}

// applyBlockState processes all transactions contained in a block and updates
// the live chain state: order books, holdings, credentials, trades, payment
// instructions, and prospectus counters. It is the shared engine called by
// both SealBlock (HTTP API path) and finalizeBlock (dBFT consensus path) so
// that identical state transitions occur regardless of how a block was produced.
//
// applyBlockState must only be called while bc.Mu is held by the caller.
func (bc *Blockchain) applyBlockState(block *Block) {
	// 1. Expire stale payment instructions before running the matching engine.
	bc.ExpireStaleInstructions()

	// 2. Apply asset transactions.
	for _, tx := range block.AssetTransactions {
		if err := tx.Validate(bc, bc.Assets, bc.Holdings, bc.Credentials, bc.PendingCorporateActions, bc.AMLScreener); err != nil {
			fmt.Printf("Skipping invalid asset tx: %v\n", err)
			continue
		}
		if err := ApplyAssetTransaction(&tx, bc.Assets, bc.Holdings); err != nil {
			fmt.Printf("Failed to apply asset tx: %v\n", err)
		}
	}

	// 3. Apply credential transactions.
	for _, ct := range block.CredentialTransactions {
		bc.Credentials[ct.Attestation.WalletPublicKey] = &ct.Attestation
		bc.emitEvent(EventCredentialIssued, map[string]any{
			"wallet_key":     ct.Attestation.WalletPublicKey,
			"investor_class": ct.Attestation.InvestorClass,
			"kyc_status":     ct.Attestation.KYCStatus,
			"expires_at":     ct.Attestation.ExpiresAt,
		})
	}

	// 4. Apply order transactions (add new orders / process cancellations).
	for _, ot := range block.OrderTransactions {
		if ot.IsCancellation {
			if ob, ok := bc.OrderBooks[ot.Order.AssetID]; ok {
				if err := ob.CancelOrder(ot.Order.ID, ot.Tx.Sender); err != nil {
					fmt.Printf("Failed to cancel order %s: %v\n", ot.Order.ID, err)
				}
			}
			bc.emitEvent(EventOrderCancelled, map[string]any{
				"order_id": ot.Order.ID,
				"asset_id": ot.Order.AssetID,
			})
			continue
		}
		if _, ok := bc.OrderBooks[ot.Order.AssetID]; !ok {
			bc.OrderBooks[ot.Order.AssetID] = NewOrderBook(ot.Order.AssetID)
		}
		pubKey, err := PublicKeyFromString(ot.Tx.Sender)
		if err != nil {
			fmt.Printf("Failed to decode order placer key: %v\n", err)
			continue
		}
		if err := bc.OrderBooks[ot.Order.AssetID].AddOrder(&ot.Order, pubKey); err != nil {
			fmt.Printf("Failed to add order to book: %v\n", err)
		} else {
			bc.emitEvent(EventOrderPlaced, map[string]any{
				"order_id": ot.Order.ID,
				"asset_id": ot.Order.AssetID,
				"side":     ot.Order.Side,
				"price":    ot.Order.Price,
				"quantity": ot.Order.Quantity,
			})
		}
	}

	// 5. Run the matching engine for all order books.
	// Window-managed assets are matched by Tick() on window close; skip them here.
	if bc.WindowManager != nil {
		windowResults := bc.WindowManager.Tick(bc)
		bc.WindowResults = append(bc.WindowResults, windowResults...)
	}

	for assetID, ob := range bc.OrderBooks {
		if bc.WindowManager != nil && bc.WindowManager.IsManaged(assetID) {
			continue
		}
		asset, ok := bc.Assets[assetID]
		if !ok {
			continue
		}
		trades, assetTxs, err := ob.MatchOrders(assetID, asset.Currency)
		if err != nil {
			fmt.Printf("MatchOrders error for asset %s: %v\n", assetID, err)
			continue
		}

		for i, trade := range trades {
			bc.Trades = append(bc.Trades, trade)
			bc.emitEvent(EventTradeExecuted, map[string]any{
				"trade_id":  trade.ID,
				"asset_id":  trade.AssetID,
				"quantity":  trade.Quantity,
				"price":     trade.Price,
				"currency":  trade.Currency,
				"buyer_id":  trade.BuyerID,
				"seller_id": trade.SellerID,
			})

			// MAR Article 16: detect market-manipulation patterns on every trade.
			bc.detectSTORs(trade)

			// 6. Issue a PaymentInstruction for each matched trade.
			instruction := &PaymentInstruction{
				TradeID:       trade.ID,
				AssetID:       trade.AssetID,
				Quantity:      trade.Quantity,
				PricePerUnit:  trade.Price,
				TotalAmount:   trade.Price * trade.Quantity,
				Currency:      trade.Currency,
				Method:        DefaultSettlementMethod(trade.Currency),
				PayerWalletID: trade.BuyerID,
				PayeeWalletID: trade.SellerID,
				Reference:     fmt.Sprintf("GH-%s", trade.ID[:8]),
				ExpiresAt:     time.Now().Unix() + 86400, // 24 h to pay
			}

			// FATF Recommendation 16 / EU TFR 2023/1113: attach originator and
			// beneficiary data when the EUR-equivalent value >= €1,000.
			// Convert to EUR via the ValuationOracle when the trade currency differs.
			eurAmount := instruction.TotalAmount
			if bc.ValuationOracle != nil && instruction.Currency != "EUR" {
				if rate, err := bc.ValuationOracle.GetCurrencyRate(instruction.Currency, "EUR"); err == nil && rate > 0 {
					eurAmount = instruction.TotalAmount * rate
				}
			}
			if eurAmount >= TravelRuleThresholdEUR {
				instruction.TravelRule = bc.buildTravelRule(
					trade.BuyerID, trade.SellerID, instruction.Reference,
				)
			}

			instruction, _ = bc.OracleService.SignInstruction(instruction)
			bc.PendingInstructions[trade.ID] = instruction
			bc.PendingSettlements[trade.ID] = assetTxs[i]

			// 7. Attempt immediate synchronous confirmation (mock / local providers).
			// Production providers (Modulr, EURC, Pontes) leave status pending and
			// call ConfirmAndSettle via their webhook handler when payment arrives.
			provider := bc.ProviderForMethod(instruction.Method)
			_ = provider.ConfirmPayment(
				instruction.Reference,
				instruction.TotalAmount,
				instruction.Currency,
			)
			status, _ := provider.GetPaymentStatus(instruction.Reference)
			if status == PaymentStatusConfirmed {
				// 8. DVP: apply the asset transfer now that payment is confirmed.
				// applyBlockState already holds bc.Mu, so use the lock-free variant.
				if err := bc.confirmAndSettleLocked(instruction.Reference, instruction.TotalAmount, instruction.Currency); err != nil {
					fmt.Printf("DVP settle failed for trade %s: %v\n", trade.ID, err)
				} else {
					if pe, ok := bc.ProspectusExemptions[trade.AssetID]; ok {
						pe.RecordSettlement(trade.ID, instruction.TotalAmount)
					}
				}
			}
		}
	}

	// 9. Update prospectus retail-holder counts and emit threshold warnings.
	for _, pe := range bc.ProspectusExemptions {
		UpdateRetailCounts(pe, bc.Holdings, bc.Credentials)
	}
	CheckProspectusThresholds(bc, bc.ProspectusExemptions)
}

// SealBlock constructs and commits a block from the provided transaction slices,
// applies its state (order matching, DVP settlement, credential expiry, compliance
// checks), and emits EventBlockFinalised. It is the canonical write path for the
// HTTP API; all state-mutating handlers call SealBlock after building their
// transaction list.
//
// SealBlock acquires bc.Mu for its entire duration. Callers must not hold bc.Mu.
// BroadcastBlock is called AFTER bc.Mu is released so network I/O does not
// stall other readers/writers waiting on the mutex.
func (bc *Blockchain) SealBlock(assetTxs []AssetTransaction, orderTxs []OrderTransaction, credTxs []CredentialTransaction) {
	if bc.ConsensusMode == ConsensusModeDBFT {
		bc.recordConsensusModeReject("SealBlock", ConsensusModeHTTP)
		log.Printf("SealBlock: disabled in %q consensus mode", ConsensusModeDBFT)
		return
	}

	var sealedBlock Block

	func() {
		bc.Mu.Lock()
		defer bc.Mu.Unlock()

		// Build the complete block before appending or broadcasting. AddBlock sets
		// Index, PrevHash, Nonce, and PayloadHash; all content is present at broadcast.
		block := Block{
			AssetTransactions:      assetTxs,
			OrderTransactions:      orderTxs,
			CredentialTransactions: credTxs,
		}
		bc.AddBlock(block)
		idx := len(bc.Blocks) - 1

		// C-2: operator signs PayloadHash so that external verifiers can confirm
		// which node produced the block. Skip when no key is configured (dev mode).
		if bc.OperatorKeyProvider != nil {
			payloadBytes, err := hex.DecodeString(bc.Blocks[idx].PayloadHash)
			if err == nil {
				sig, err := bc.OperatorKeyProvider.Sign(payloadBytes)
				if err == nil {
					bc.Blocks[idx].Signatures = append(bc.Blocks[idx].Signatures, sig)
				} else {
					log.Printf("SealBlock: operator signing failed: %v", err)
				}
			}
		}

		// C-4: persist sealed block to bbolt so the chain survives restarts.
		if bc.BlockStore != nil {
			if err := bc.BlockStore.SaveBlock(&bc.Blocks[idx]); err != nil {
				log.Printf("SealBlock: persistence write failed: %v", err)
			}
		}

		// Apply all block state: order matching, DVP settlement, credential application.
		bc.applyBlockState(&bc.Blocks[idx])

		// C-4: persist state snapshot so chain state survives restarts.
		if bc.BlockStore != nil {
			if err := bc.BlockStore.SaveState(bc, idx); err != nil {
				log.Printf("SealBlock: state snapshot failed: %v", err)
			}
		}

		blk := bc.Blocks[idx]
		sealedBlock = blk // capture for broadcast after the lock releases

		// G-08: sweep credentials past their expiry date.
		now := time.Now().Unix()
		for walletKey, cred := range bc.Credentials {
			if cred.KYCStatus == KYCStatusVerified && cred.ExpiresAt > 0 && now > cred.ExpiresAt {
				cred.KYCStatus = KYCStatusExpired
				bc.emitEvent(EventCredentialExpired, map[string]any{
					"wallet_key":     walletKey,
					"expired_at":     cred.ExpiresAt,
					"investor_class": string(cred.InvestorClass),
				})
			}
		}

		// G-10: MiFIR / AIFMD reports for trades matched in this block.
		// Look up the actual Trade from bc.Trades by matching order IDs so the
		// report carries the canonical trade ID rather than a synthetic one.
		for _, otx := range orderTxs {
			if otx.IsCancellation || otx.Order.Status != OrderStatusFilled {
				continue
			}
			for i := len(bc.Trades) - 1; i >= 0; i-- {
				t := bc.Trades[i]
				if t.BidOrderID == otx.Order.ID || t.AskOrderID == otx.Order.ID {
					GenerateMiFIRReport(bc, t, idx)
					GenerateAIFMDReport(bc, t, idx)
					break
				}
			}
		}

		// A-01: verify CirculatingSupply is consistent with the sum of all holdings.
		bc.assertCirculatingSupplyConsistency()

		bc.emitEvent(EventBlockFinalised, map[string]any{
			"block_index":         idx,
			"hash":                blk.CalculateHash(),
			"tx_count":            0,
			"asset_tx_count":      len(assetTxs),
			"order_tx_count":      len(orderTxs),
			"credential_tx_count": len(credTxs),
		})
	}()

	// Broadcast outside bc.Mu so network I/O does not stall mutex waiters.
	if bc.P2PNode != nil {
		if err := bc.P2PNode.BroadcastBlock(sealedBlock); err != nil {
			log.Printf("SealBlock: broadcast failed: %v", err)
		}
	}
}

// assertCirculatingSupplyConsistency verifies that each asset's CirculatingSupply
// equals the arithmetic sum of all holdings for that asset. Called from SealBlock
// after every block is finalised.
//
// In development mode (GH_ENV != "production") any divergence panics so it is
// caught immediately in testing. In production it emits EventSupplyMismatch and
// logs a CRITICAL message rather than crashing a live node.
func (bc *Blockchain) assertCirculatingSupplyConsistency() {
	for assetID, asset := range bc.Assets {
		var sum float64
		suffix := ":" + assetID
		for key, h := range bc.Holdings {
			if strings.HasSuffix(key, suffix) {
				sum += h.Balance
			}
		}
		if math.Abs(sum-asset.CirculatingSupply) > 1e-9 {
			msg := fmt.Sprintf(
				"CRITICAL: CirculatingSupply mismatch for asset %s: recorded=%.9f actual=%.9f delta=%.9e",
				assetID, asset.CirculatingSupply, sum, math.Abs(sum-asset.CirculatingSupply),
			)
			if os.Getenv("GH_ENV") != "production" {
				panic(msg)
			}
			log.Println(msg)
			bc.emitEvent(EventSupplyMismatch, map[string]any{
				"asset_id":            assetID,
				"recorded_supply":     asset.CirculatingSupply,
				"actual_holdings_sum": sum,
				"delta":               math.Abs(sum - asset.CirculatingSupply),
			})
		}
	}
}

// ---------------------------------------------------------------------------
// MAR Article 16 — STOR pattern detection
// ---------------------------------------------------------------------------

// detectSTORs checks a newly-matched trade for three MAR Article 16 market-
// manipulation patterns and creates a STORDraft in bc.PendingSTORs for each
// hit.  An EventSTORCreated is emitted for every new draft.
//
// bc.Mu must be held by the caller (detectSTORs is called from applyBlockState).
func (bc *Blockchain) detectSTORs(trade Trade) {
	// Pattern 1 — Self-transfer: buyer and seller are the same wallet.
	if trade.BuyerID == trade.SellerID && trade.BuyerID != "" {
		stor := NewSTORDraft(STORWashTrading, trade.AssetID, "", trade.ID, trade.BuyerID,
			"self-transfer: buyer and seller are the same wallet")
		bc.PendingSTORs[stor.ID] = stor
		bc.emitEvent(EventSTORCreated, map[string]any{
			"stor_id":  stor.ID,
			"category": stor.Category,
			"asset_id": trade.AssetID,
			"trade_id": trade.ID,
			"reason":   "self-transfer",
		})
	}

	// Pattern 2 — Wash trade: same counterparty pair traded the same asset
	// more than 3 times within the last 30 days.
	cpKey := storCounterpartyKey(trade.BuyerID, trade.SellerID)
	cutoff := time.Now().Unix() - 30*24*3600
	prev := bc.RecentCounterpartyTrades[cpKey]
	pruned := prev[:0]
	for _, t := range prev {
		if t.ExecutedAt >= cutoff {
			pruned = append(pruned, t)
		}
	}
	bc.RecentCounterpartyTrades[cpKey] = append(pruned, trade)
	assetTradeCount := 0
	for _, t := range bc.RecentCounterpartyTrades[cpKey] {
		if t.AssetID == trade.AssetID {
			assetTradeCount++
		}
	}
	if assetTradeCount > 3 {
		stor := NewSTORDraft(STORWashTrading, trade.AssetID, "", trade.ID, trade.BuyerID,
			fmt.Sprintf("wash-trade-pattern: counterparty pair traded asset %s %d times within 30 days",
				trade.AssetID, assetTradeCount))
		bc.PendingSTORs[stor.ID] = stor
		bc.emitEvent(EventSTORCreated, map[string]any{
			"stor_id":  stor.ID,
			"category": stor.Category,
			"asset_id": trade.AssetID,
			"trade_id": trade.ID,
			"reason":   "wash-trade-pattern",
		})
	}

	// Pattern 3 — Price deviation: trade price deviates more than 20% from the
	// last-10-trade VWAP for this asset.
	vwap, n := bc.storAssetVWAP(trade.AssetID, trade.ID, 10)
	if n >= 2 && vwap > 0 {
		deviation := math.Abs(trade.Price-vwap) / vwap
		if deviation > 0.20 {
			stor := NewSTORDraft(STORMarketManipulation, trade.AssetID, "", trade.ID, trade.BuyerID,
				fmt.Sprintf("price-deviation: trade price %.4f deviates %.1f%% from 10-trade VWAP %.4f",
					trade.Price, deviation*100, vwap))
			bc.PendingSTORs[stor.ID] = stor
			bc.emitEvent(EventSTORCreated, map[string]any{
				"stor_id":  stor.ID,
				"category": stor.Category,
				"asset_id": trade.AssetID,
				"trade_id": trade.ID,
				"reason":   "price-deviation",
			})
		}
	}
}

// storAssetVWAP computes the volume-weighted average price for assetID using
// up to n completed trades in bc.Trades, excluding the trade with excludeID
// (the current trade just appended).  Returns the VWAP and the count of trades
// that contributed to it.
func (bc *Blockchain) storAssetVWAP(assetID, excludeID string, n int) (float64, int) {
	relevant := make([]Trade, 0, n)
	for i := len(bc.Trades) - 1; i >= 0 && len(relevant) < n; i-- {
		t := bc.Trades[i]
		if t.AssetID == assetID && t.ID != excludeID {
			relevant = append(relevant, t)
		}
	}
	if len(relevant) == 0 {
		return 0, 0
	}
	var sumPQ, sumQ float64
	for _, t := range relevant {
		sumPQ += t.Price * t.Quantity
		sumQ += t.Quantity
	}
	if sumQ == 0 {
		return 0, 0
	}
	return sumPQ / sumQ, len(relevant)
}

// storCounterpartyKey returns a canonical order-independent key for a
// buyer/seller pair so that A→B and B→A share the same wash-trade bucket.
func storCounterpartyKey(a, b string) string {
	if a <= b {
		return a + ":" + b
	}
	return b + ":" + a
}

// emitEvent sends an event onto bc.Events without blocking.
// If the buffer is full the event is silently dropped — consensus must not stall
// waiting for a WebSocket consumer.
func (bc *Blockchain) emitEvent(eventType string, payload any) {
	if bc.Events == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	event := StreamEvent{
		Type:      eventType,
		Timestamp: time.Now().UTC().Unix(),
		Payload:   json.RawMessage(data),
	}
	select {
	case bc.Events <- event:
	default:
		// buffer full — drop rather than block
	}
}

// AddBlock appends a fully-constructed block to the chain. It sets the block's
// Index (monotone position), PrevHash (sealed hash of the preceding block),
// Nonce (global block counter), and PayloadHash (pre-signature content hash)
// before appending.
//
// The caller must populate all transaction fields BEFORE calling AddBlock.
// Broadcasting to peers is the caller's responsibility; callers that hold
// bc.Mu must broadcast AFTER releasing the lock to avoid network I/O under
// the mutex (see SealBlock).
func (bc *Blockchain) AddBlock(block Block) {
	if len(bc.Blocks) > 0 {
		block.PrevHash = bc.Blocks[len(bc.Blocks)-1].CalculateHash()
	} else {
		block.PrevHash = strings.Repeat("0", 64) // 64-char zero hex (genesis)
	}
	block.Index = len(bc.Blocks)
	block.Nonce = bc.Nonce
	// Set microsecond timestamp and key version before hashing so both are
	// covered by all delegate signatures (MiFIR RTS 22, MAR, CSDR).
	block.SealedAt = time.Now().UnixMicro()
	if bc.OperatorKeyProvider != nil {
		block.KeyVersion = bc.OperatorKeyProvider.PublicKeyString()
	}
	block.SetPayloadHash()
	bc.markCommittedTxHashes(&block)
	bc.Blocks = append(bc.Blocks, block)
	bc.Nonce++
}

func (bc *Blockchain) recordConsensusModeReject(path string, expectedMode string) {
	count := atomic.AddUint64(&bc.consensusModeRejects, 1)
	bc.metricsMu.Lock()
	bc.consensusModeRejectByPath[path]++
	bc.metricsMu.Unlock()
	log.Printf("consensus mode reject: path=%s mode=%s expected=%s count=%d", path, bc.ConsensusMode, expectedMode, count)
	bc.emitEvent(EventConsensusModeRejected, map[string]any{
		"path":          path,
		"active_mode":   bc.ConsensusMode,
		"expected_mode": expectedMode,
		"count":         count,
	})
}

func (bc *Blockchain) recordDuplicateTxHashRejection(hashKey string, reason string) {
	count := atomic.AddUint64(&bc.duplicateTxHashRejections, 1)
	bc.metricsMu.Lock()
	bc.duplicateTxRejectByReason[reason]++
	bc.metricsMu.Unlock()
	log.Printf("duplicate tx hash rejected: reason=%s hash=%s count=%d", reason, hashKey, count)
	bc.emitEvent(EventDuplicateTransactionRejected, map[string]any{
		"reason":    reason,
		"hash":      hashKey,
		"count":     count,
		"blockMode": bc.ConsensusMode,
	})
}

func (bc *Blockchain) ConsensusModeRejectCount() uint64 {
	if bc == nil {
		return 0
	}
	return atomic.LoadUint64(&bc.consensusModeRejects)
}

func (bc *Blockchain) DuplicateTxHashRejectCount() uint64 {
	if bc == nil {
		return 0
	}
	return atomic.LoadUint64(&bc.duplicateTxHashRejections)
}

func (bc *Blockchain) ConsensusModeRejectByPathSnapshot() map[string]uint64 {
	if bc == nil {
		return map[string]uint64{}
	}
	bc.metricsMu.RLock()
	defer bc.metricsMu.RUnlock()
	result := make(map[string]uint64, len(bc.consensusModeRejectByPath))
	for path, count := range bc.consensusModeRejectByPath {
		result[path] = count
	}
	return result
}

func (bc *Blockchain) DuplicateTxRejectByReasonSnapshot() map[string]uint64 {
	if bc == nil {
		return map[string]uint64{}
	}
	bc.metricsMu.RLock()
	defer bc.metricsMu.RUnlock()
	result := make(map[string]uint64, len(bc.duplicateTxRejectByReason))
	for reason, count := range bc.duplicateTxRejectByReason {
		result[reason] = count
	}
	return result
}

func transactionHashKey(tx Transaction) string {
	return "base:" + hex.EncodeToString(tx.hash())
}

func typedTransactionHashKey(prefix string, tx any) string {
	data, _ := json.Marshal(tx)
	hash := sha3.Sum256(data)
	return prefix + ":" + hex.EncodeToString(hash[:])
}

func blockTransactionHashKeys(block *Block) []string {
	count := len(block.Transactions) + len(block.AssetTransactions) + len(block.OrderTransactions) + len(block.CredentialTransactions)
	keys := make([]string, 0, count)

	for _, tx := range block.Transactions {
		keys = append(keys, transactionHashKey(tx))
	}
	for _, tx := range block.AssetTransactions {
		keys = append(keys, typedTransactionHashKey("asset", tx))
	}
	for _, tx := range block.OrderTransactions {
		keys = append(keys, typedTransactionHashKey("order", tx))
	}
	for _, tx := range block.CredentialTransactions {
		keys = append(keys, typedTransactionHashKey("credential", tx))
	}

	return keys
}

func (bc *Blockchain) markCommittedTxHashes(block *Block) {
	if bc.CommittedTxHashes == nil {
		bc.CommittedTxHashes = make(map[string]struct{})
	}
	for _, key := range blockTransactionHashKeys(block) {
		bc.CommittedTxHashes[key] = struct{}{}
	}
}

func (bc *Blockchain) rebuildCommittedTxHashes() {
	bc.CommittedTxHashes = make(map[string]struct{})
	for i := range bc.Blocks {
		bc.markCommittedTxHashes(&bc.Blocks[i])
	}
}

func (bc *Blockchain) committedTxHashesSnapshot() map[string]struct{} {
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()

	snapshot := make(map[string]struct{}, len(bc.CommittedTxHashes))
	for key := range bc.CommittedTxHashes {
		snapshot[key] = struct{}{}
	}
	return snapshot
}

// SignTransaction signs the transaction with the given private key
func (t *Transaction) SignTransaction(privateKey *PrivateKey) error {
	if privateKey == nil {
		return fmt.Errorf("private key is not initialized")
	}
	txHash := t.hash()
	signature := privateKey.Sign(txHash)
	t.AddSignature(signature.Bytes())
	return nil
}

// hash returns the SHA-256 hash of the transaction data (excluding the signature)
func (t *Transaction) hash() []byte {
	txCopy := *t
	txCopy.Signatures = nil
	txBytes, _ := json.Marshal(txCopy)
	hash := sha3.Sum256(txBytes)
	return hash[:]
}

func (bc *Blockchain) ValidateBlock(block Block) bool {
	// Check if the block's previous hash matches the hash of the last block in the chain
	if len(bc.Blocks) > 0 {
		lastBlock := bc.Blocks[len(bc.Blocks)-1]
		if block.PrevHash != lastBlock.CalculateHash() {
			fmt.Printf("Invalid block: previous hash does not match (expected: %s, got: %s)\n", lastBlock.CalculateHash(), block.PrevHash)
			return false
		}
	}

	// Verify that PayloadHash is consistent with the block's content. Any field
	// covered by blockHashInput (including SealedAt) that is altered after sealing
	// will produce a different hash and fail this check. A missing PayloadHash
	// (empty string) is allowed only for legacy / test blocks that never went
	// through AddBlock.
	if block.PayloadHash != "" {
		originalHash := block.PayloadHash
		block.SetPayloadHash()
		if block.PayloadHash != originalHash {
			fmt.Printf("Invalid block: PayloadHash does not match block content (got %s, recomputed %s)\n", originalHash, block.PayloadHash)
			return false
		}
		block.PayloadHash = originalHash // restore for downstream signature checks
	}

	// Block must contain at least one of: base transactions, asset transactions,
	// order transactions, or credential transactions. Pure base-tx blocks come
	// from the legacy P2P path; all other types come from the API (SealBlock).
	if len(block.Transactions) == 0 && len(block.AssetTransactions) == 0 &&
		len(block.OrderTransactions) == 0 && len(block.CredentialTransactions) == 0 {
		fmt.Println("Invalid block: contains no transactions of any kind")
		return false
	}

	// Item 24: reject duplicate transactions already committed on-chain and
	// reject duplicate transaction hashes repeated within the same block.
	committed := bc.committedTxHashesSnapshot()
	seen := make(map[string]struct{})
	for _, key := range blockTransactionHashKeys(&block) {
		if _, exists := seen[key]; exists {
			bc.recordDuplicateTxHashRejection(key, "duplicate_within_block")
			fmt.Printf("Invalid block: duplicate transaction hash within block (%s)\n", key)
			return false
		}
		seen[key] = struct{}{}
		if _, exists := committed[key]; exists {
			bc.recordDuplicateTxHashRejection(key, "already_committed")
			fmt.Printf("Invalid block: transaction hash already committed (%s)\n", key)
			return false
		}
	}

	// Verify all transactions in the block
	for _, tx := range block.Transactions {
		fmt.Printf("Validating transaction from %s to %s\n", tx.Sender, tx.Receiver)

		// Decode sender's public key
		pubKey, err := PublicKeyFromString(tx.Sender)
		if err != nil {
			fmt.Printf("Invalid block: error decoding sender's public key (%v)\n", err)
			return false
		}

		pubKeys := []*PublicKey{pubKey}

		// Verify transaction signatures
		if !tx.VerifyMultiSignature(pubKeys) {
			fmt.Println("Invalid block: contains invalid multi-signature transaction")
			return false
		}

		// Verify transaction fields
		if tx.Amount <= 0 {
			fmt.Println("Invalid block: transaction amount must be greater than zero")
			return false
		}
		if tx.Sender == "" || tx.Receiver == "" {
			fmt.Println("Invalid block: transaction sender or receiver is empty")
			return false
		}
	}
	// Item 11 Step A: verify AssetTransaction sender signatures.
	// Entries with RequiredSigs == 0 are genesis / internal issuances that carry
	// no end-user signature; all others must have a valid Ed25519 sender sig.
	for _, at := range block.AssetTransactions {
		if at.Tx.RequiredSigs == 0 {
			continue
		}
		senderPub, err := PublicKeyFromString(at.Tx.Sender)
		if err != nil {
			fmt.Printf("Invalid block: AssetTransaction has invalid sender key: %v\n", err)
			return false
		}
		if !at.Tx.VerifyMultiSignature([]*PublicKey{senderPub}) {
			fmt.Println("Invalid block: AssetTransaction has invalid sender signature")
			return false
		}
	}

	// Item 11 Step B: verify OrderTransaction order signatures.
	// Cancellations are authorised by the base Tx.Sender signature only; new
	// placements must also carry a valid Ed25519 signature over the order fields.
	for _, ot := range block.OrderTransactions {
		if ot.IsCancellation {
			continue
		}
		placerPub, err := PublicKeyFromString(ot.Order.PlacedBy)
		if err != nil {
			fmt.Printf("Invalid block: OrderTransaction has invalid placer key: %v\n", err)
			return false
		}
		if !ot.Order.VerifySignature(placerPub) {
			fmt.Println("Invalid block: OrderTransaction has invalid order signature")
			return false
		}
	}

	// Item 11 Step C: verify CredentialTransaction registry signatures.
	// Skipped when bc.IdentityRegistry is not configured (dev / test without KYC).
	// CredentialAttestation.CredentialHash is the pre-signature hash (same bytes
	// that RegistrySignature covers), so we can verify on-chain without the full
	// IdentityCredential.
	if bc.IdentityRegistry != nil {
		regPub := bc.IdentityRegistry.RegistryPublicKey()
		for _, ct := range block.CredentialTransactions {
			a := &ct.Attestation
			if len(a.RegistrySignature) == 0 {
				fmt.Printf("Invalid block: CredentialTransaction for wallet %s has no registry signature\n", a.WalletPublicKey)
				return false
			}
			credHashBytes, err := hex.DecodeString(a.CredentialHash)
			if err != nil || len(credHashBytes) == 0 {
				fmt.Printf("Invalid block: CredentialTransaction for wallet %s has invalid CredentialHash\n", a.WalletPublicKey)
				return false
			}
			sig := &Signature{value: a.RegistrySignature}
			if !sig.Verify(regPub, credHashBytes) {
				fmt.Printf("Invalid block: CredentialTransaction for wallet %s has invalid registry signature\n", a.WalletPublicKey)
				return false
			}
		}
	}

	// Verify block signatures: require BFT supermajority (⌈2n/3⌉).
	// Guard n==0 for single-operator mode where no delegates are registered.
	if len(bc.Delegates) > 0 {
		required := int(math.Ceil(float64(2*len(bc.Delegates)) / 3.0))
		if len(block.Signatures) < required {
			fmt.Printf("Invalid block: need %d signatures, have %d\n", required, len(block.Signatures))
			return false
		}

		// Item 8 Step C: verify each delegate Ed25519 signature against PayloadHash.
		// All production delegates must have a PublicKey (enforced via Item 7
		// startup guard + createBlock signing). Delegates without a key can no
		// longer contribute valid signatures, so they do not count toward the
		// threshold — the bypass that skipped keyless delegates has been removed.
		payloadHashBytes, err := hex.DecodeString(block.PayloadHash)
		if err != nil {
			fmt.Printf("Invalid block: cannot decode PayloadHash (%v)\n", err)
			return false
		}
		validSigs := 0
		for _, delegate := range bc.Delegates {
			for _, sig := range block.Signatures {
				if ed25519.Verify(delegate.PublicKey, payloadHashBytes, sig) {
					validSigs++
					break
				}
			}
		}
		if validSigs < required {
			fmt.Printf("Invalid block: %d/%d valid Ed25519 delegate signatures\n", validSigs, required)
			return false
		}
	}

	fmt.Println("Block validated successfully")

	return true
}

func (bc *Blockchain) GetLastBlockHash() string {
	if len(bc.Blocks) == 0 {
		return ""
	}
	return bc.Blocks[len(bc.Blocks)-1].CalculateHash()
}

type Shard struct {
	ID              int
	TransactionPool []Transaction
	Blocks          []Block
}

func NewShard(id int) *Shard {
	return &Shard{
		ID:              id,
		TransactionPool: []Transaction{},
		Blocks:          []Block{},
	}
}

func (bc *Blockchain) InitializeShards(numShards int) {
	for i := 0; i < numShards; i++ {
		bc.Shards = append(bc.Shards, NewShard(i))
	}
	fmt.Printf("Initialized %d shards\n", numShards)
}

func (bc *Blockchain) AssignTransactionToShard(tx Transaction) {
	// Use a hash of the sender's public key to determine the shard
	shardID := int(sha3.Sum256([]byte(tx.Sender))[0]) % len(bc.Shards)
	bc.Shards[shardID].TransactionPool = append(bc.Shards[shardID].TransactionPool, tx)
	fmt.Printf("Assigned transaction %+v to shard %d\n", tx, shardID)
}

func (shard *Shard) ValidateShardTransactions() {
	for _, tx := range shard.TransactionPool {
		// Perform transaction validation (reuse existing logic)
		pubKey, err := PublicKeyFromString(tx.Sender)
		if err != nil || !tx.VerifyMultiSignature([]*PublicKey{pubKey}) {
			fmt.Printf("Invalid transaction in shard %d: %+v\n", shard.ID, tx)
			continue
		}
		fmt.Printf("Valid transaction in shard %d: %+v\n", shard.ID, tx)
	}
}

func (bc *Blockchain) ValidateTransactionsInParallel() {
	bc.Mu.RLock()
	if len(bc.TransactionPool) == 0 {
		bc.Mu.RUnlock()
		fmt.Println("No transactions to validate.")
		return
	}
	// Take a stable snapshot so worker goroutines do not race on the pool.
	poolSnapshot := make([]Transaction, len(bc.TransactionPool))
	copy(poolSnapshot, bc.TransactionPool)
	bc.Mu.RUnlock()

	numWorkers := 4                                                // Number of goroutines
	chunkSize := (len(poolSnapshot) + numWorkers - 1) / numWorkers // Ensure chunkSize is valid

	results := make(chan bool, len(poolSnapshot))

	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		if start >= len(poolSnapshot) { // Prevent out-of-bounds access
			break
		}
		end := start + chunkSize
		if end > len(poolSnapshot) {
			end = len(poolSnapshot)
		}

		go func(transactions []Transaction) {
			defer func() {
				// If a worker panics, drain its outstanding result slots so the
				// collect loop below does not block forever.
				if r := recover(); r != nil {
					log.Printf("ValidateTransactionsInParallel: worker panic: %v", r)
					for range transactions {
						results <- false
					}
				}
			}()
			for _, tx := range transactions {
				pubKey, err := PublicKeyFromString(tx.Sender)
				if err != nil || !tx.VerifyMultiSignature([]*PublicKey{pubKey}) {
					results <- false
					continue
				}
				results <- true
			}
		}(poolSnapshot[start:end])
	}

	// Collect results
	validCount := 0
	for i := 0; i < len(poolSnapshot); i++ {
		if <-results {
			validCount++
		}
	}

	fmt.Printf("%d/%d transactions are valid\n", validCount, len(poolSnapshot))
}

// SaveBlockchain saves the blockchain state to a file
func (bc *Blockchain) SaveBlockchain(filename string) error {
	data, err := json.Marshal(bc)
	if err != nil {
		return fmt.Errorf("failed to serialize blockchain: %v", err)
	}
	return os.WriteFile(filename, data, 0644)
}

// LoadBlockchain loads the blockchain state from a file
func LoadBlockchain(filename string) (*Blockchain, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read blockchain file: %v", err)
	}
	var bc Blockchain
	if err := json.Unmarshal(data, &bc); err != nil {
		return nil, fmt.Errorf("failed to deserialize blockchain: %v", err)
	}
	return &bc, nil
}

// ResolveFork has been removed (Item 12). dBFT provides irreversible
// single-path finality — once a block carries ⌈2n/3⌉ valid delegate
// signatures it cannot be reverted. Longest-chain (Nakamoto) fork
// resolution is incompatible with dBFT and would allow a Byzantine peer to
// replace finalised blocks with attacker-controlled content.
// See: HandleFork in dBFT.go.

// CommitBlock is the public entry point for finalising a pre-built block.
// It is used by the simulation and integration tests; the normal production
// productionReadinessError returns a non-nil error if any critical production
// dependency is unset or still uses a mock implementation. Extracted from
// NewBlockchain so tests can verify individual error conditions without
// triggering os.Exit via log.Fatal.
func productionReadinessError(bc *Blockchain) error {
	if _, ok := bc.AMLScreener.(*MockAMLScreener); ok {
		return fmt.Errorf("production: AMLScreener is MockAMLScreener — set a real screener before startup")
	}
	if _, ok := bc.PaymentProvider.(*MockPaymentProvider); ok {
		return fmt.Errorf("production: PaymentProvider is MockPaymentProvider — set a real provider before startup")
	}
	if _, ok := bc.IdentityRegistry.(*MockIdentityRegistry); ok {
		return fmt.Errorf("production: IdentityRegistry is MockIdentityRegistry — set a real registry before startup")
	}
	if bc.OperatorKeyProvider == nil {
		return fmt.Errorf("production: OperatorKeyProvider is nil — set a key provider before startup")
	}
	if os.Getenv("ONFIDO_WEBHOOK_SECRET") == "" {
		return fmt.Errorf("production: ONFIDO_WEBHOOK_SECRET is not set")
	}
	if os.Getenv("GREENHOUSE_REGISTRY_PUBKEY") == "" {
		return fmt.Errorf("production: GREENHOUSE_REGISTRY_PUBKEY is not set — set a hex-encoded Ed25519 registry public key")
	}
	return nil
}

// catchUpBlock applies only the direct state changes from a block during startup
// recovery — AssetTransactions with a positive amount (skipping zero-amount marker
// issue records), CredentialTransactions, and WalletSequence updates — without
// running the order-matching engine. It is used to re-apply blocks that were
// sealed after the most recent SaveState snapshot, bridging the narrow crash
// window between SaveBlock and SaveState.
// Must be called without bc.Mu held; only invoked from NewBlockchain before the
// node begins serving requests.
func (bc *Blockchain) catchUpBlock(block *Block) {
	for _, tx := range block.AssetTransactions {
		if tx.Tx.Amount <= 0 || tx.Tx.Sender == "" || tx.Tx.Receiver == "" {
			continue // skip zero-amount marker transactions
		}
		if err := ApplyAssetTransaction(&tx, bc.Assets, bc.Holdings); err != nil {
			log.Printf("catchUpBlock %d: asset tx error: %v", block.Index, err)
		}
	}
	for _, ct := range block.CredentialTransactions {
		bc.Credentials[ct.Attestation.WalletPublicKey] = &ct.Attestation
	}
	for _, tx := range block.Transactions {
		if tx.Nonce > bc.WalletSequences[tx.Sender] {
			bc.WalletSequences[tx.Sender] = tx.Nonce
		}
	}
}

// path is AchieveConsensus → finalizeBlock.
func (bc *Blockchain) CommitBlock(block Block) {
	bc.finalizeBlock(block)
}

func testConsensusModeOverrideEnabled() bool {
	return os.Getenv("GONETWORK_ALLOW_TEST_CONSENSUS_HYBRID") == "1"
}

func resolveConsensusMode(raw string, production bool) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	testOverride := testConsensusModeOverrideEnabled() && !production
	if mode == "" {
		if testOverride {
			return consensusModeHybrid, nil
		}
		return "", fmt.Errorf("GREENHOUSE_CONSENSUS_MODE must be set to %q or %q", ConsensusModeHTTP, ConsensusModeDBFT)
	}

	switch mode {
	case ConsensusModeHTTP, ConsensusModeDBFT:
		return mode, nil
	case consensusModeHybrid:
		if testOverride {
			return mode, nil
		}
		return "", fmt.Errorf("GREENHOUSE_CONSENSUS_MODE=%q is only allowed in unit tests when GONETWORK_ALLOW_TEST_CONSENSUS_HYBRID=1", consensusModeHybrid)
	default:
		return "", fmt.Errorf("invalid GREENHOUSE_CONSENSUS_MODE %q: expected %q or %q", mode, ConsensusModeHTTP, ConsensusModeDBFT)
	}
}

func parseOptionalBoolEnv(name string) (bool, bool, error) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return false, false, nil
	}
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return false, true, fmt.Errorf("invalid %s=%q: expected boolean", name, raw)
	}
	return v, true, nil
}

func (bc *Blockchain) enforceConsensusStartupInvariant() error {
	httpEnabled := bc.ConsensusMode == ConsensusModeHTTP
	dbftEnabled := bc.ConsensusMode == ConsensusModeDBFT
	if bc.ConsensusMode == consensusModeHybrid {
		httpEnabled = true
		dbftEnabled = true
	}

	if v, set, err := parseOptionalBoolEnv("GREENHOUSE_ENABLE_HTTP_SEAL"); err != nil {
		return err
	} else if set {
		httpEnabled = v
	}
	if v, set, err := parseOptionalBoolEnv("GREENHOUSE_ENABLE_DBFT_CONSENSUS"); err != nil {
		return err
	} else if set {
		dbftEnabled = v
	}

	if httpEnabled && dbftEnabled && !(bc.ConsensusMode == consensusModeHybrid && testConsensusModeOverrideEnabled()) {
		return fmt.Errorf("startup invariant failed: conflicting services enabled (http_seal=true, dbft_consensus=true)")
	}
	if !httpEnabled && !dbftEnabled {
		return fmt.Errorf("startup invariant failed: both block production services are disabled")
	}
	if bc.ConsensusMode == ConsensusModeHTTP && dbftEnabled {
		return fmt.Errorf("startup invariant failed: mode=%s but dbft consensus service is enabled", bc.ConsensusMode)
	}
	if bc.ConsensusMode == ConsensusModeDBFT && httpEnabled {
		return fmt.Errorf("startup invariant failed: mode=%s but http seal service is enabled", bc.ConsensusMode)
	}

	log.Printf("consensus startup invariant: mode=%s http_seal=%t dbft_consensus=%t", bc.ConsensusMode, httpEnabled, dbftEnabled)
	bc.emitEvent(EventConsensusModeInvariant, map[string]any{
		"mode":               bc.ConsensusMode,
		"http_seal":          httpEnabled,
		"dbft_consensus":     dbftEnabled,
		"test_override":      testConsensusModeOverrideEnabled(),
		"consensus_mode_raw": strings.TrimSpace(os.Getenv("GREENHOUSE_CONSENSUS_MODE")),
	})

	return nil
}

func NewBlockchain(ctx context.Context, topicName string) *Blockchain {
	bc := &Blockchain{
		Blocks:          []Block{},
		TransactionPool: []Transaction{},
		// Use the package-level lockedWallets map so that Wallet.LockCurrency
		// (which updates that map) and VoteForDelegates (which reads bc.LockedWallets)
		// both see the same data. Without this alignment the two stores diverge
		// and delegate elections never see any staked balances (H-6).
		LockedWallets:             GetLockedWallets(),
		PublicKeyToID:             make(map[string]string),
		UserIDToDelegateID:        make(map[string]string),
		Wallets:                   make(map[string]*Wallet),
		ConsensusMode:             consensusModeHybrid,
		CommittedTxHashes:         make(map[string]struct{}),
		consensusModeRejectByPath: make(map[string]uint64),
		duplicateTxRejectByReason: make(map[string]uint64),
	}

	consensusMode, err := resolveConsensusMode(os.Getenv("GREENHOUSE_CONSENSUS_MODE"), os.Getenv("GH_ENV") == "production")
	if err != nil {
		log.Fatalf("NewBlockchain: %v", err)
	}
	bc.ConsensusMode = consensusMode

	// Add the genesis block. The PrevHash is a 64-character zero-value hex
	// string (matching the length of a SHA3-256 hex digest) so the genesis
	// block's PrevHash is unambiguously distinguishable from an unset field.
	genesisBlock := Block{
		Index:        0,
		Transactions: []Transaction{},
		PrevHash:     strings.Repeat("0", 64),
		Nonce:        0,
		Signatures:   [][]byte{},
	}
	genesisBlock.SetPayloadHash()
	bc.Blocks = append(bc.Blocks, genesisBlock)

	// Initialise DVP state maps
	bc.Assets = make(map[string]*Asset)
	bc.Holdings = make(map[string]*AssetHolding)
	bc.OrderBooks = make(map[string]*OrderBook)
	bc.Trades = []Trade{}
	bc.Credentials = make(map[string]*CredentialAttestation)
	bc.PendingInstructions = make(map[string]*PaymentInstruction)
	bc.ConfirmedPayments = make(map[string]*PaymentConfirmation)
	bc.PendingSettlements = make(map[string]*AssetTransaction)
	bc.PendingAssetTransactions = []AssetTransaction{}

	// Phase 2: Liquidity Windows
	bc.WindowManager = NewWindowManager()
	bc.WindowResults = []WindowResult{}

	// Phase 2: SPV / Participation Notes
	bc.SPVs = make(map[string]*SPVWrapper)

	// Phase 2: Corporate Actions
	bc.PendingCorporateActions = make(map[string]*CorporateAction)

	// Phase 2: Multi-Jurisdiction Compliance
	bc.ProspectusExemptions = make(map[string]*ProspectusExemption)
	bc.SuitabilityAssessments = make(map[string]*SuitabilityAssessment)
	bc.JurisdictionRules = make(map[string]*JurisdictionRule)

	// G-11: seed the GB jurisdiction rule (Financial Promotion Order 2005).
	// All GreenHouse nodes apply the FPO Article 19 high-net-worth exemption and
	// display the FCA-prescribed risk warning to retail investors in the UK.
	bc.JurisdictionRules["GB"] = &JurisdictionRule{
		CountryCode:         "GB",
		MaxRetailHolders:    0,
		RequiresSuitability: false,
		FPOExemptionType:    "fpo_art19",
		RequiresRiskWarning: true,
	}

	// G-11: seed core EU jurisdiction rules (Prospectus Regulation 2017/1129 and
	// MiFID II compliance). All four jurisdictions use the Art. 3(2)(b) exemption:
	// offers addressed to fewer than 150 natural or legal persons per member state,
	// so MaxRetailHolders is capped at 149. MiFID II suitability is required for
	// complex instruments in all EU jurisdictions (RequiresSuitability = true).

	// Germany (BaFin) — DLT Pilot Regime active; Electronic Securities Act (2021).
	bc.JurisdictionRules["DE"] = &JurisdictionRule{
		CountryCode:         "DE",
		MaxRetailHolders:    149,
		RequiresSuitability: true,
		RequiresRiskWarning: true,
	}

	// Luxembourg (CSSF) — EU fund hub; CSSF proactive with DLT frameworks.
	bc.JurisdictionRules["LU"] = &JurisdictionRule{
		CountryCode:         "LU",
		MaxRetailHolders:    149,
		RequiresSuitability: true,
		RequiresRiskWarning: true,
	}

	// France (AMF/ACPR) — Strong DLT legal framework; Banque de France ECB pilot.
	bc.JurisdictionRules["FR"] = &JurisdictionRule{
		CountryCode:         "FR",
		MaxRetailHolders:    149,
		RequiresSuitability: true,
		RequiresRiskWarning: true,
	}

	// Netherlands (AFM) — AFM published clear DLT guidance; Amsterdam fintech hub.
	bc.JurisdictionRules["NL"] = &JurisdictionRule{
		CountryCode:         "NL",
		MaxRetailHolders:    149,
		RequiresSuitability: true,
		RequiresRiskWarning: true,
	}

	// Phase 2: FiDA Reporting
	bc.CostBasisTracker = NewCostBasisTracker()
	bc.ValuationOracle = NewMockValuationOracle()

	// Phase 2: Deal Anchoring
	bc.Deals = make(map[string]*Deal)

	// Part I: Legal doc amendment log
	bc.LegalDocAmendments = make(map[string][]*LegalDocAmendment)

	// Part III: Dividend holding snapshots
	bc.DividendHoldingSnapshots = make(map[string]map[string]*AssetHolding)

	// Track 4: Real-time event stream (256-event buffer)
	bc.Events = make(chan StreamEvent, 256)

	if err := bc.enforceConsensusStartupInvariant(); err != nil {
		log.Fatalf("NewBlockchain: %v", err)
	}

	// Settlement router — populated by RegisterSettlementProvider after construction.
	bc.SettlementRouter = make(map[SettlementMethod]PaymentProvider)

	// Default to mock service implementations so existing tests need no changes
	if bc.AMLScreener == nil {
		bc.AMLScreener = NewMockAMLScreener()
	}
	// G-09: SAR draft store
	bc.PendingSARs = make(map[string]*SARDraft)
	// G-10: regulatory report log
	bc.RegulatoryReports = []*RegulatoryReport{}
	// MAR Article 18: insider lists
	bc.InsiderLists = make(map[string]*InsiderList)
	// MAR Article 16: STOR drafts and wash-trade detection window
	bc.PendingSTORs = make(map[string]*STORDraft)
	bc.RecentCounterpartyTrades = make(map[string][]Trade)
	if bc.PaymentProvider == nil {
		bc.PaymentProvider = NewMockPaymentProvider()
	}
	if bc.IdentityRegistry == nil {
		bc.IdentityRegistry, _ = NewMockIdentityRegistry()
	}
	if bc.OracleService == nil {
		bc.OracleService, _ = NewMockOracleService()
	}

	// Load the network registry public key from GREENHOUSE_REGISTRY_PUBKEY (hex).
	// Must be set before productionReadinessError so the guard can verify it.
	if regKeyHex := os.Getenv("GREENHOUSE_REGISTRY_PUBKEY"); regKeyHex != "" {
		regKey, err := PublicKeyFromHex(regKeyHex)
		if err != nil {
			log.Fatalf("NewBlockchain: invalid GREENHOUSE_REGISTRY_PUBKEY: %v", err)
		}
		bc.NetworkRegistryKey = regKey
	}

	// I-2: Production guard — refuse mock services at startup.
	// Must come after all fallback mock assignments above so it fires only when
	// no real provider was injected before NewBlockchain was called.
	if os.Getenv("GH_ENV") == "production" {
		if err := productionReadinessError(bc); err != nil {
			log.Fatal(err)
		}
	}

	// Per-wallet sequence/nonce tracking for replay prevention.
	bc.WalletSequences = make(map[string]int64)

	// Default consensus view-change timeout (M-2).
	bc.ConsensusTimeout = 30 * time.Second

	// Bootstrap peers are loaded from the GREENHOUSE_BOOTSTRAP_PEERS environment
	// variable (comma-separated multiaddrs). An empty or unset variable means the
	// node runs in standalone / local-only mode, which is the default for tests
	// and local development. Production nodes are configured via the environment.
	// C-4: Open persistent block store when GREENHOUSE_DB_PATH is set.
	// On first run the store is empty and the genesis block created above is
	// saved immediately. On subsequent runs LoadBlocks restores bc.Blocks and
	// LoadState restores bc.Assets, bc.Holdings, bc.Credentials, and
	// bc.WalletSequences. Any blocks sealed after the last snapshot are replayed
	// via catchUpBlock (no order matching) to close the crash-window gap.
	if dbPath := os.Getenv("GREENHOUSE_DB_PATH"); dbPath != "" {
		store, err := OpenBlockStore(dbPath)
		if err != nil {
			log.Fatalf("NewBlockchain: cannot open block store %q: %v", dbPath, err)
		}
		bc.BlockStore = store

		// Clear the in-memory genesis before loading from disk.
		bc.Blocks = []Block{}
		if err := store.LoadBlocks(bc); err != nil {
			log.Printf("NewBlockchain: block load error: %v", err)
		}

		if len(bc.Blocks) == 0 {
			// First run — re-create genesis and persist it so it survives restart.
			genesis := Block{
				Index:        0,
				Transactions: []Transaction{},
				PrevHash:     strings.Repeat("0", 64),
				Nonce:        0,
				Signatures:   [][]byte{},
			}
			genesis.SetPayloadHash()
			bc.Blocks = append(bc.Blocks, genesis)
			if err := store.SaveBlock(&genesis); err != nil {
				log.Printf("NewBlockchain: failed to persist genesis block: %v", err)
			}
		} else {
			// Restored from store — align the nonce counter with the saved chain.
			// Pattern: genesis direct-append (no Nonce++) + (N-1) AddBlock calls
			// → bc.Nonce = len(bc.Blocks) - 1 after the original run.
			bc.Nonce = len(bc.Blocks) - 1

			// Restore state snapshot (Assets, Holdings, Credentials, WalletSequences).
			lastApplied, err := store.LoadState(bc)
			if err != nil {
				log.Printf("NewBlockchain: state restore error: %v", err)
			}

			// Re-apply any blocks sealed after the last snapshot.
			// Handles the crash window between SaveBlock and SaveState.
			for i := lastApplied + 1; i < len(bc.Blocks); i++ {
				bc.catchUpBlock(&bc.Blocks[i])
			}
		}

		// Restore the active delegate set saved by the last VoteForDelegates call
		// (Item 10 Step B). Re-initialises Inbox and viewChangeRequests so delegates
		// are immediately usable for consensus without a new election round.
		if err := store.LoadDelegates(bc); err != nil {
			log.Printf("NewBlockchain: LoadDelegates: %v", err)
		}

		// Step C: if no delegates were persisted but recovered state indicates the
		// chain had active participants, attempt to re-elect from in-memory state.
		// This is a best-effort hook — it is a no-op until LockedWallets and Nodes
		// are also persisted (a dependency of future Item 11 work).
		if len(bc.Delegates) == 0 && (len(bc.Credentials) > 0 || len(bc.Assets) > 0) {
			bc.VoteForDelegates(nil)
		}
	}

	bc.rebuildCommittedTxHashes()

	var bootstrapPeers []string
	if raw := os.Getenv("GREENHOUSE_BOOTSTRAP_PEERS"); raw != "" {
		for _, addr := range strings.Split(raw, ",") {
			if addr = strings.TrimSpace(addr); addr != "" {
				bootstrapPeers = append(bootstrapPeers, addr)
			}
		}
	}

	// Initialize the P2PNode. A failure is non-fatal: the blockchain operates
	// in standalone mode (bc.P2PNode == nil) without gossip propagation.
	// Skip P2P initialisation when GONETWORK_NO_P2P=1.  This env var is set
	// by newTestBlockchain() so that the ~95 unit-test blockchain instances
	// do not each spin up a real libp2p host with mDNS/GossipSub/DHT.
	// Production and P2P-specific tests leave the variable unset.
	if os.Getenv("GONETWORK_NO_P2P") == "" {
		// log.Fatalf was removed because it called os.Exit, killing the entire
		// test process when port exhaustion or network errors occur.
		p2pNode, err := NewP2PNode(ctx, bc, topicName, bootstrapPeers)
		if err != nil {
			log.Printf("Warning: Failed to initialize P2PNode (running in standalone mode): %v", err)
		} else {
			bc.P2PNode = p2pNode
		}
	}

	// G-10: initialise the regulatory reporting service.
	// DefaultReportingService is used in dev/test (on-chain record only).
	// In production, NCAReportingService also transmits reports to the NCA/ARM.
	// If BlockStore is available, failed submissions are persisted to the
	// "reporting_outbox" bucket and retried by a background goroutine.
	bc.ReportingService = &DefaultReportingService{}
	if os.Getenv("GH_ENV") == "production" {
		ncaSvc := NewNCAReportingService()
		if bc.BlockStore != nil {
			ncaSvc.outbox = bc.BlockStore.SaveToReportingOutbox
			go bc.runReportingOutboxRetry(ctx, ncaSvc)
		}
		bc.ReportingService = ncaSvc
	}

	return bc
}

// runReportingOutboxRetry is a background goroutine that retries any reports
// stored in the BBolt "reporting_outbox" bucket after a failed NCA/ARM
// submission. It applies exponential backoff (100 ms → 30 s) and removes
// each report from the outbox once it is successfully submitted.
func (bc *Blockchain) runReportingOutboxRetry(ctx context.Context, svc *NCAReportingService) {
	const initialDelay = 100 * time.Millisecond
	const maxDelay = 30 * time.Second
	delay := initialDelay
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if bc.BlockStore == nil {
			return
		}
		reports, err := bc.BlockStore.LoadReportingOutbox()
		if err != nil {
			log.Printf("runReportingOutboxRetry: load error: %v", err)
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
			continue
		}
		if len(reports) == 0 {
			delay = initialDelay // reset when outbox is clear
			continue
		}
		anyFailed := false
		for _, report := range reports {
			if err := svc.SubmitReport(report); err == nil {
				if delErr := bc.BlockStore.DeleteFromReportingOutbox(report.ID); delErr != nil {
					log.Printf("runReportingOutboxRetry: delete failed for report %s: %v", report.ID, delErr)
				}
			} else {
				anyFailed = true
			}
		}
		if anyFailed {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		} else {
			delay = initialDelay
		}
	}
}
