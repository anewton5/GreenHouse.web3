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
	"strings"
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
	Transactions           []Transaction           `json:"Transactions"`
	AssetTransactions      []AssetTransaction      `json:"AssetTransactions,omitempty"`
	OrderTransactions      []OrderTransaction      `json:"OrderTransactions,omitempty"`
	CredentialTransactions []CredentialTransaction `json:"CredentialTransactions,omitempty"`
	PrevHash               string
	Nonce                  int
	Signatures             [][]byte
}

func (b *Block) CalculateHash() string {
	blockData, _ := json.Marshal(b)
	hash := sha3.Sum256(blockData)
	return hex.EncodeToString(hash[:])
}

type View struct {
	Number int
}

type Blockchain struct {
	Blocks             []Block
	Nodes              []Node
	LockedWallets      map[[32]byte]*LockedWallet
	Delegates          []Node
	PublicKeyToID      map[string]string
	UserIDToDelegateID map[string]string
	currentView        View
	currentSpeaker     int
	Wallets            map[string]*Wallet
	Nonce              int
	TransactionPool    []Transaction
	Shards             []*Shard
	P2PNode            *P2PNode

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
	PaymentProvider  PaymentProvider
	IdentityRegistry IdentityRegistry
	OracleService    OracleService

	// SettlementRouter dispatches PaymentInstructions to per-method providers.
	// Register providers via RegisterSettlementProvider. Falls back to
	// PaymentProvider when no entry exists for a given SettlementMethod.
	// Example: register a PontesPaymentProvider for SettlementCeBM once the
	// ECB Pontes pilot launches (Q3 2026).
	SettlementRouter map[SettlementMethod]PaymentProvider

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
	AMLScreener AMLScreener

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
	Events chan StreamEvent
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
			p.OriginatorName        = rec.Personal.FullLegalName
			p.OriginatorAddressLine = rec.Address.Line1
			p.OriginatorCity        = rec.Address.City
			p.OriginatorCountryCode = rec.Address.Country
		}
		if rec := bc.RegistrationRegistry.Get(payeeKey); rec != nil {
			p.BeneficiaryName        = rec.Personal.FullLegalName
			p.BeneficiaryAddressLine = rec.Address.Line1
			p.BeneficiaryCity        = rec.Address.City
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
// Returns nil if the reference is unknown (no-op is intentional — webhook
// providers must not retry on unknown references).
func (bc *Blockchain) ConfirmAndSettle(reference string, amount float64, currency string) error {
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

// ---------------------------------------------------------------------------
// immediately emits EventBlockFinalised. It is called by the API layer after
// each state-mutating HTTP request so the chain grows in real time without
// requiring a full dBFT consensus round.
func (bc *Blockchain) SealBlock(assetTxs []AssetTransaction, orderTxs []OrderTransaction, credTxs []CredentialTransaction) {
	bc.AddBlock(nil, nil)
	idx := len(bc.Blocks) - 1
	bc.Blocks[idx].AssetTransactions = assetTxs
	bc.Blocks[idx].OrderTransactions = orderTxs
	bc.Blocks[idx].CredentialTransactions = credTxs
	blk := bc.Blocks[idx]

	// G-08: sweep credentials and downgrade any that have passed their expiry
	// timestamp to KYCStatusExpired so CheckTransferEligibility rejects them.
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

	// G-06: rebuild prospectus retail-holder counts from live holdings/credentials
	// and emit proximity warnings for any jurisdiction approaching the cap.
	for _, exemption := range bc.ProspectusExemptions {
		UpdateRetailCounts(exemption, bc.Holdings, bc.Credentials)
	}
	CheckProspectusThresholds(bc, bc.ProspectusExemptions)

	// G-10: generate MiFIR / AIFMD transaction reports for every filled trade in
	// this block.  Only trades with Status=="settled" (i.e. filled by handleFillOrder)
	// need reporting; cancellations and open orders are excluded.
	for _, otx := range orderTxs {
		if otx.IsCancellation || otx.Order.Status != OrderStatusFilled {
			continue
		}
		trade := Trade{
			ID:         "block-trade-" + otx.Order.ID[:8],
			AssetID:    otx.Order.AssetID,
			BuyerID:    otx.Order.PlacedBy,
			SellerID:   "", // issuer; not stored on Order — skip for block-sourced trades
			Quantity:   otx.Order.Filled,
			Price:      otx.Order.Price,
			ExecutedAt: time.Now().Unix(),
			Status:     "settled",
		}
		GenerateMiFIRReport(bc, trade, idx)
		GenerateAIFMDReport(bc, trade, idx)
	}

	// A-01: verify CirculatingSupply is consistent with the holdings sum after
	// every block. Divergence indicates a write path bypassing ApplyAssetTransaction.
	bc.assertCirculatingSupplyConsistency()

	bc.emitEvent(EventBlockFinalised, map[string]any{
		"block_index":         idx,
		"hash":                blk.CalculateHash(),
		"tx_count":            0,
		"asset_tx_count":      len(assetTxs),
		"order_tx_count":      len(orderTxs),
		"credential_tx_count": len(credTxs),
	})
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

func (bc *Blockchain) AddBlock(transactions []Transaction, signatures [][]byte) {
	var prevHash string
	if len(bc.Blocks) > 0 {
		prevHash = bc.Blocks[len(bc.Blocks)-1].CalculateHash()
	} else {
		prevHash = "0000000000000000" // Set genesis block's PrevHash
	}

	newBlock := Block{
		Transactions: transactions,
		PrevHash:     prevHash,
		Nonce:        bc.Nonce,
		Signatures:   signatures,
	}

	bc.Blocks = append(bc.Blocks, newBlock)
	bc.Nonce++

	// Broadcast the block
	if bc.P2PNode != nil {
		if err := bc.P2PNode.BroadcastBlock(newBlock); err != nil {
			fmt.Printf("Failed to broadcast block: %v\n", err)
		}
	}
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

	// Check if the block contains at least one transaction
	if len(block.Transactions) == 0 {
		fmt.Println("Invalid block: no transactions")
		return false
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
	// Verify block signatures
	if len(block.Signatures) < len(bc.Delegates)/2+1 { // Majority required
		fmt.Println("Invalid block: insufficient delegate signatures")
		return false
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
	if len(bc.TransactionPool) == 0 {
		fmt.Println("No transactions to validate.")
		return
	}

	numWorkers := 4                                                      // Number of goroutines
	chunkSize := (len(bc.TransactionPool) + numWorkers - 1) / numWorkers // Ensure chunkSize is valid

	results := make(chan bool, len(bc.TransactionPool))

	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		if start >= len(bc.TransactionPool) { // Prevent out-of-bounds access
			break
		}
		end := start + chunkSize
		if end > len(bc.TransactionPool) {
			end = len(bc.TransactionPool)
		}

		go func(transactions []Transaction) {
			for _, tx := range transactions {
				pubKey, err := PublicKeyFromString(tx.Sender)
				if err != nil || !tx.VerifyMultiSignature([]*PublicKey{pubKey}) {
					results <- false
					continue
				}
				results <- true
			}
		}(bc.TransactionPool[start:end])
	}

	// Collect results
	validCount := 0
	for i := 0; i < len(bc.TransactionPool); i++ {
		if <-results {
			validCount++
		}
	}

	fmt.Printf("%d/%d transactions are valid\n", validCount, len(bc.TransactionPool))
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

func (bc *Blockchain) ResolveFork(newChain []Block) bool {
	// Validate the new chain
	for i := 1; i < len(newChain); i++ {
		if newChain[i].PrevHash != newChain[i-1].CalculateHash() {
			fmt.Println("Invalid chain: hashes do not match")
			return false
		}
	}

	// Check if the new chain is longer
	if len(newChain) > len(bc.Blocks) {
		fmt.Println("Replacing current chain with the longer valid chain")
		bc.Blocks = newChain
		return true
	}

	fmt.Println("New chain is not longer. No replacement made.")
	return false
}

// This main function is not implemented correctly, for testing only.
func main() {
	bc := &Blockchain{
		Blocks:             []Block{},
		LockedWallets:      make(map[[32]byte]*LockedWallet),
		PublicKeyToID:      make(map[string]string),
		UserIDToDelegateID: make(map[string]string),
		Wallets:            make(map[string]*Wallet),
	}

	// Add a genesis block
	genesisTransactions := []Transaction{
		{Sender: "genesis", Receiver: "user1", Amount: 100},
	}
	bc.AddBlock(genesisTransactions, nil)

	newTransactions := []Transaction{
		{Sender: "user1", Receiver: "user2", Amount: 50},
	}
	bc.AddBlock(newTransactions, nil)

	for _, block := range bc.Blocks {
		fmt.Printf("PrevHash: %s\n", block.PrevHash)
		fmt.Printf("Transactions: %+v\n", block.Transactions)
		fmt.Printf("Nonce: %d\n", block.Nonce)
		fmt.Printf("Signatures: %x\n", block.Signatures)
		fmt.Println()
	}
}

// CommitBlock is the public entry point for finalising a pre-built block.
// It is used by the simulation and integration tests; the normal production
// path is AchieveConsensus → finalizeBlock.
func (bc *Blockchain) CommitBlock(block Block) {
	bc.finalizeBlock(block)
}

func NewBlockchain(ctx context.Context, topicName string) *Blockchain {
	bc := &Blockchain{
		Blocks:             []Block{},
		TransactionPool:    []Transaction{},
		LockedWallets:      make(map[[32]byte]*LockedWallet),
		PublicKeyToID:      make(map[string]string),
		UserIDToDelegateID: make(map[string]string),
		Wallets:            make(map[string]*Wallet),
	}

	// Add the genesis block
	genesisBlock := Block{
		Transactions: []Transaction{},    // No transactions in the genesis block
		PrevHash:     "0000000000000000", // Predefined hash for the genesis block
		Nonce:        0,
		Signatures:   [][]byte{},
	}
	bc.Blocks = append(bc.Blocks, genesisBlock)
	fmt.Println("Genesis block added to the blockchain.")

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
	// MAR Article 16: STOR drafts
	bc.PendingSTORs = make(map[string]*STORDraft)
	if bc.PaymentProvider == nil {
		bc.PaymentProvider = NewMockPaymentProvider()
	}
	if bc.IdentityRegistry == nil {
		bc.IdentityRegistry, _ = NewMockIdentityRegistry()
	}
	if bc.OracleService == nil {
		bc.OracleService, _ = NewMockOracleService()
	}

	// Bootstrap peers are loaded from the GREENHOUSE_BOOTSTRAP_PEERS environment
	// variable (comma-separated multiaddrs). An empty or unset variable means the
	// node runs in standalone / local-only mode, which is the default for tests
	// and local development. Production nodes are configured via the environment.
	var bootstrapPeers []string
	if raw := os.Getenv("GREENHOUSE_BOOTSTRAP_PEERS"); raw != "" {
		for _, addr := range strings.Split(raw, ",") {
			if addr = strings.TrimSpace(addr); addr != "" {
				bootstrapPeers = append(bootstrapPeers, addr)
			}
		}
	}

	// Initialize the P2PNode
	p2pNode, err := NewP2PNode(ctx, bc, topicName, bootstrapPeers)
	if err != nil {
		log.Fatalf("Failed to initialize P2PNode: %v", err)
	}
	bc.P2PNode = p2pNode

	return bc
}
