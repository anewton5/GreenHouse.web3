package gonetwork

// ---------------------------------------------------------------------------
// blockchain_extended_test.go — high-coverage blockchain scenarios
//
// Covers:
//   SealBlock                   — appends block, operator signing, BlockStore
//   ConfirmAndSettle            — idempotency, unknown reference, provider error
//   RegisterSettlementProvider /
//   ProviderForMethod           — routing, fallback to default provider
//   buildTravelRule             — with and without RegistrationRegistry
//   ExpireStaleInstructions     — removes expired, skips active/confirmed
//   AddTransaction              — replay attack (duplicate nonce), sequence
//                                 counter enforcement, invalid sender
//   ResolveFork                 — longer chain wins; invalid chain rejected
//   GetLockedWallets            — static registry not nil
//   GetLastBlockHash            — empty chain vs non-empty
//   Concurrent block additions  — race detector must not fire
//   RegisterDelegateVote        — empty inputs ignored; map updated correctly
// ---------------------------------------------------------------------------

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"encoding/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// SealBlock
// ---------------------------------------------------------------------------

func TestSealBlock_AppendsBlock(t *testing.T) {
	bc := newTestBlockchain(t)
	initial := len(bc.Blocks)
	bc.SealBlock(nil, nil, nil)
	assert.Equal(t, initial+1, len(bc.Blocks))
}

func TestSealBlock_WithOperatorKey_AddsSignature(t *testing.T) {
	bc := newTestBlockchain(t)
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	bc.OperatorKeyProvider = NewLocalKeyProvider(key)

	bc.SealBlock(nil, nil, nil)

	idx := len(bc.Blocks) - 1
	assert.NotEmpty(t, bc.Blocks[idx].Signatures, "operator key should produce a signature")
}

func TestSealBlock_WithBlockStore_PersistsBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seal.db")
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	bc := newTestBlockchain(t)
	bc.BlockStore = bs
	bc.SealBlock(nil, nil, nil)

	count, err := bs.BlockCount()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1)
}

func TestSealBlock_WithCredentialTransaction_RecordsCredential(t *testing.T) {
	bc := newTestBlockchain(t)

	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	wallet := base64.StdEncoding.EncodeToString(key.Public().Bytes())

	// Issue a credential via the mock identity registry
	cred, err := bc.IdentityRegistry.IssueCredential(wallet, InvestorClassRetail, "GB", 365)
	require.NoError(t, err)

	credTx := CredentialTransaction{
		Attestation: *cred,
	}
	bc.SealBlock(nil, nil, []CredentialTransaction{credTx})

	// Credential should now be in bc.Credentials
	assert.NotNil(t, bc.Credentials[wallet])
}

// ---------------------------------------------------------------------------
// RegisterSettlementProvider / ProviderForMethod
// ---------------------------------------------------------------------------

func TestProviderForMethod_RegisteredProvider(t *testing.T) {
	bc := newTestBlockchain(t)
	mock := NewMockPaymentProvider()
	bc.RegisterSettlementProvider(SettlementSEPA, mock)

	got := bc.ProviderForMethod(SettlementSEPA)
	assert.Equal(t, mock, got)
}

func TestProviderForMethod_FallbackToDefault(t *testing.T) {
	bc := newTestBlockchain(t)
	// No custom provider registered for SEPA; falls back to bc.PaymentProvider
	got := bc.ProviderForMethod(SettlementSEPA)
	assert.Equal(t, bc.PaymentProvider, got)
}

// ---------------------------------------------------------------------------
// buildTravelRule
// ---------------------------------------------------------------------------

func TestBuildTravelRule_NoRegistry_UsesWalletKeys(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.RegistrationRegistry = nil

	p := bc.buildTravelRule("payer-key", "payee-key", "REF-001")
	assert.Equal(t, "payer-key", p.OriginatorAccount)
	assert.Equal(t, "payee-key", p.BeneficiaryAccount)
	assert.Equal(t, "REF-001", p.TransferRef)
	assert.Equal(t, "", p.OriginatorName) // no registry
}

func TestBuildTravelRule_WithRegistry_PopulatesNames(t *testing.T) {
	bc := newTestBlockchain(t)
	rr := NewRegistrationRegistry()
	bc.RegistrationRegistry = rr

	payerRec := validRegistrationRecord("payer-key")
	payeeRec := validRegistrationRecord("payee-key")
	payeeRec.Personal.FullLegalName = "Bob Beneficiary"
	rr.Upsert(payerRec)
	rr.Upsert(payeeRec)

	p := bc.buildTravelRule("payer-key", "payee-key", "REF-002")
	assert.Equal(t, "Alice Olivia Smith", p.OriginatorName)
	assert.Equal(t, "Bob Beneficiary", p.BeneficiaryName)
	assert.Equal(t, "1 City Road", p.OriginatorAddressLine)
	assert.Equal(t, "London", p.OriginatorCity)
	assert.Equal(t, "GB", p.OriginatorCountryCode)
}

// ---------------------------------------------------------------------------
// ConfirmAndSettle
// ---------------------------------------------------------------------------

func TestConfirmAndSettle_UnknownReference_NoError(t *testing.T) {
	bc := newTestBlockchain(t)
	err := bc.ConfirmAndSettle("UNKNOWN-REF", 1000, "EUR")
	assert.NoError(t, err, "unknown reference should be silently ignored")
}

func TestConfirmAndSettle_KnownReference_RecordsConfirmation(t *testing.T) {
	bc := newTestBlockchain(t)
	mock := NewMockPaymentProvider()
	bc.PaymentProvider = mock

	// Register a pending instruction
	instr := &PaymentInstruction{
		Reference:     "REF-SETTLE-001",
		PayerWalletID: "buyer",
		PayeeWalletID: "seller",
		TotalAmount:   5000,
		Currency:      "EUR",
		Method:        SettlementSEPA,
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}
	bc.PendingInstructions["trade-001"] = instr

	err := bc.ConfirmAndSettle("REF-SETTLE-001", 5000, "EUR")
	assert.NoError(t, err)
	assert.NotNil(t, bc.ConfirmedPayments["trade-001"], "confirmation should be recorded")
}

func TestConfirmAndSettle_Idempotent(t *testing.T) {
	bc := newTestBlockchain(t)
	mock := NewMockPaymentProvider()
	bc.PaymentProvider = mock

	instr := &PaymentInstruction{
		Reference:   "REF-IDEM-001",
		Method:      SettlementSEPA,
		TotalAmount: 1000,
		Currency:    "EUR",
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}
	bc.PendingInstructions["trade-idem"] = instr

	// Confirm twice — should not error or double-count
	require.NoError(t, bc.ConfirmAndSettle("REF-IDEM-001", 1000, "EUR"))
	require.NoError(t, bc.ConfirmAndSettle("REF-IDEM-001", 1000, "EUR"))
	assert.Len(t, bc.ConfirmedPayments, 1)
}

// ---------------------------------------------------------------------------
// ExpireStaleInstructions
// ---------------------------------------------------------------------------

func TestExpireStaleInstructions_RemovesExpired(t *testing.T) {
	bc := newTestBlockchain(t)
	instr := &PaymentInstruction{
		Reference: "EXP-001",
		AssetID:   "asset-1",
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(), // 1h in the past
	}
	bc.PendingInstructions["expired-trade"] = instr
	bc.PendingSettlements["expired-trade"] = &AssetTransaction{AssetID: "asset-1"}

	bc.ExpireStaleInstructions()

	assert.NotContains(t, bc.PendingInstructions, "expired-trade",
		"expired instruction must be removed")
	assert.NotContains(t, bc.PendingSettlements, "expired-trade",
		"linked settlement must be removed when the instruction expires")
}

func TestExpireStaleInstructions_KeepsActiveInstructions(t *testing.T) {
	bc := newTestBlockchain(t)
	instr := &PaymentInstruction{
		Reference: "ACTIVE-001",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(), // 1h in the future
	}
	bc.PendingInstructions["active-trade"] = instr

	bc.ExpireStaleInstructions()

	assert.Contains(t, bc.PendingInstructions, "active-trade",
		"active instruction must not be removed")
}

func TestExpireStaleInstructions_SkipsAlreadyConfirmed(t *testing.T) {
	bc := newTestBlockchain(t)
	instr := &PaymentInstruction{
		Reference: "CONF-001",
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
	}
	bc.PendingInstructions["conf-trade"] = instr
	bc.ConfirmedPayments["conf-trade"] = &PaymentConfirmation{Reference: "CONF-001"}

	bc.ExpireStaleInstructions()

	// The implementation skips (continue) when a trade is already confirmed,
	// so the pending instruction is NOT deleted — ConfirmedPayments is authoritative.
	assert.Contains(t, bc.PendingInstructions, "conf-trade",
		"confirmed instruction must not be removed by the expiry sweep")
}

func TestExpireStaleInstructions_EventPayloadIncludesSettlementMetadata(t *testing.T) {
	bc := newTestBlockchain(t)
	instr := &PaymentInstruction{
		Reference:           "EXP-002",
		AssetID:             "asset-2",
		Method:              SettlementCeBM,
		PontesTransactionID: "pontes-tx-123",
		ExpiresAt:           time.Now().Add(-1 * time.Hour).Unix(),
	}
	bc.PendingInstructions["expired-trade-2"] = instr
	bc.PendingSettlements["expired-trade-2"] = &AssetTransaction{AssetID: "asset-2"}
	select {
	case <-bc.Events:
	default:
	}

	bc.ExpireStaleInstructions()

	select {
	case evt := <-bc.Events:
		assert.Equal(t, EventPaymentExpired, evt.Type)
		var payload map[string]any
		require.NoError(t, json.Unmarshal(evt.Payload, &payload))
		assert.Equal(t, "expired-trade-2", payload["trade_id"])
		assert.Equal(t, "pontes_cbm", payload["settlement_method"])
		assert.Equal(t, "pontes-tx-123", payload["pontes_transaction_id"])
		assert.Equal(t, "asset-2", payload["asset_id"])
	default:
		t.Fatal("expected EventPaymentExpired to be emitted")
	}
}

func TestConfirmedPayments_RetentionPrune_UsesDurableLedger(t *testing.T) {
	path := tempDBPath(t)
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	bc := newTestBlockchain(t)
	bc.BlockStore = bs
	bc.ConfirmedPaymentRetention = time.Hour

	tradeID := "retained-trade"
	reference := "REF-RET-001"
	oldConfirmation := &PaymentConfirmation{
		InstructionID:   tradeID,
		Reference:       reference,
		ConfirmedAmount: 250,
		Currency:        "EUR",
		ConfirmedAt:     time.Now().Add(-2 * time.Hour).Unix(),
	}
	bc.ConfirmedPayments[tradeID] = oldConfirmation
	require.NoError(t, bs.SaveConfirmedPayment(oldConfirmation))

	bc.pruneConfirmedPaymentsLocked(time.Now())
	assert.NotContains(t, bc.ConfirmedPayments, tradeID, "stale confirmation should be pruned from memory")

	bc.PendingInstructions[tradeID] = &PaymentInstruction{
		Reference:   reference,
		AssetID:     "asset-retained",
		TotalAmount: 250,
		Currency:    "EUR",
		Method:      SettlementSEPA,
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}
	bc.PendingSettlements[tradeID] = &AssetTransaction{AssetID: "asset-retained"}

	require.NoError(t, bc.ConfirmAndSettle(reference, 250, "EUR"))
	assert.Contains(t, bc.PendingInstructions, tradeID, "durable ledger should prevent re-settlement")
	assert.Contains(t, bc.PendingSettlements, tradeID, "duplicate webhook must not consume the settlement")
	assert.NotContains(t, bc.ConfirmedPayments, tradeID, "pruned confirmation should stay out of memory until re-used")
}

// ---------------------------------------------------------------------------
// AddTransaction — replay protection (M-9)
// ---------------------------------------------------------------------------

func TestAddTransaction_ReplayAttack_Rejected(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.InitializeShards(1)

	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	senderPub := base64.StdEncoding.EncodeToString(key.Public().Bytes())

	tx := Transaction{
		Sender:       senderPub,
		Receiver:     "receiver-key",
		Amount:       10,
		RequiredSigs: 1,
	}
	tx.GenerateNonce()
	require.NoError(t, tx.SignTransaction(key))

	// First submission accepted
	initialLen := transactionPoolLength(bc)
	bc.AddTransaction(tx)
	require.Greater(t, transactionPoolLength(bc), initialLen, "first tx should be accepted")

	// Replay of the same nonce must be rejected
	prevLen := transactionPoolLength(bc)
	bc.AddTransaction(tx)
	assert.Equal(t, prevLen, transactionPoolLength(bc), "replay must be rejected")
}

func TestAddTransaction_SequenceCounterEnforced(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.InitializeShards(1)

	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	sender := base64.StdEncoding.EncodeToString(key.Public().Bytes())

	makeSignedTx := func(nonce int64) Transaction {
		tx := Transaction{
			Sender:       sender,
			Receiver:     "recv",
			Amount:       1,
			Nonce:        nonce,
			RequiredSigs: 1,
		}
		tx.SignTransaction(key)
		return tx
	}

	// Nonce 100 accepted
	bc.AddTransaction(makeSignedTx(100))
	assert.Equal(t, int64(100), bc.WalletSequences[sender])

	// Nonce 50 (< 100) rejected
	prevLen := transactionPoolLength(bc)
	bc.AddTransaction(makeSignedTx(50))
	assert.Equal(t, prevLen, transactionPoolLength(bc), "nonce below last sequence must be rejected")

	// Nonce 101 accepted
	bc.AddTransaction(makeSignedTx(101))
	assert.Equal(t, int64(101), bc.WalletSequences[sender])
}

func TestAddTransaction_InvalidAmount_Rejected(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.InitializeShards(1)

	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	sender := base64.StdEncoding.EncodeToString(key.Public().Bytes())

	tx := Transaction{Sender: sender, Receiver: "recv", Amount: -1, RequiredSigs: 1}
	tx.GenerateNonce()
	tx.SignTransaction(key)

	prevLen := transactionPoolLength(bc)
	bc.AddTransaction(tx)
	assert.Equal(t, prevLen, transactionPoolLength(bc), "negative amount must be rejected")
}

// transactionPoolLength returns the total number of pending transactions across all shards.
func transactionPoolLength(bc *Blockchain) int {
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()
	total := 0
	for _, shard := range bc.Shards {
		total += len(shard.TransactionPool)
	}
	return total
}

// ---------------------------------------------------------------------------
// ResolveFork
// ---------------------------------------------------------------------------

// Item 12: ResolveFork is removed. HandleFork must not replace the local chain
// regardless of peer chain length — dBFT provides single-path finality.
func TestHandleFork_LongerPeerChain_LocalChainUnchanged(t *testing.T) {
	bc1 := newTestBlockchain(t)
	bc2 := newTestBlockchain(t)

	// Give bc2 a longer chain.
	bc2.AddBlock(Block{Transactions: []Transaction{{Sender: "A", Receiver: "B", Amount: 1}}})
	bc2.AddBlock(Block{Transactions: []Transaction{{Sender: "C", Receiver: "D", Amount: 2}}})

	want := len(bc1.Blocks)
	n1 := &Node{ID: "n1", Blockchain: bc1}
	n2 := &Node{ID: "n2", Blockchain: bc2}
	n1.HandleFork(n2)

	assert.Equal(t, want, len(n1.Blockchain.Blocks),
		"HandleFork must not replace local chain: dBFT single-path finality")
}

func TestHandleFork_ShorterPeerChain_LocalChainUnchanged(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.AddBlock(Block{Transactions: []Transaction{{Sender: "A", Receiver: "B", Amount: 1}}})
	bc.AddBlock(Block{Transactions: []Transaction{{Sender: "A", Receiver: "B", Amount: 2}}})

	shortBC := newTestBlockchain(t) // only genesis
	want := len(bc.Blocks)
	n := &Node{ID: "local", Blockchain: bc}
	peer := &Node{ID: "peer", Blockchain: shortBC}
	n.HandleFork(peer)

	assert.Equal(t, want, len(n.Blockchain.Blocks),
		"HandleFork must not modify local chain when peer is shorter")
}

// ---------------------------------------------------------------------------
// GetLastBlockHash
// ---------------------------------------------------------------------------

func TestGetLastBlockHash_EmptyChain(t *testing.T) {
	bc := &Blockchain{Blocks: nil}
	assert.Equal(t, "", bc.GetLastBlockHash())
}

func TestGetLastBlockHash_NonEmptyChain(t *testing.T) {
	bc := newTestBlockchain(t)
	hash := bc.GetLastBlockHash()
	assert.NotEmpty(t, hash)
	assert.Equal(t, bc.Blocks[len(bc.Blocks)-1].CalculateHash(), hash)
}

// ---------------------------------------------------------------------------
// RegisterDelegateVote
// ---------------------------------------------------------------------------

func TestRegisterDelegateVote_PopulatesMap(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.RegisterDelegateVote("user1", "delegate1")
	assert.Equal(t, "delegate1", bc.UserIDToDelegateID["user1"])
}

func TestRegisterDelegateVote_SelfDelegation(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.RegisterDelegateVote("user1", "user1")
	assert.Equal(t, "user1", bc.UserIDToDelegateID["user1"])
}

func TestRegisterDelegateVote_EmptyInputsIgnored(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.RegisterDelegateVote("", "delegate1")
	bc.RegisterDelegateVote("user1", "")
	assert.Empty(t, bc.UserIDToDelegateID)
}

// ---------------------------------------------------------------------------
// Concurrent access — race detector validation
// ---------------------------------------------------------------------------

func TestBlockchain_ConcurrentAddBlock_NoRace(t *testing.T) {
	bc := newTestBlockchain(t)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			bc.Mu.Lock()
			bc.AddBlock(Block{Transactions: []Transaction{
				{Sender: fmt.Sprintf("s%d", n), Receiver: "r", Amount: float64(n)},
			}})
			bc.Mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Chain must have genesis + 10 blocks
	assert.Equal(t, 11, len(bc.Blocks))
}

func TestRegisterDelegateVote_ConcurrentWrites_NoRace(t *testing.T) {
	bc := newTestBlockchain(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			bc.RegisterDelegateVote(
				fmt.Sprintf("user%d", n),
				fmt.Sprintf("delegate%d", n),
			)
		}(i)
	}
	wg.Wait()
	assert.Equal(t, 20, len(bc.UserIDToDelegateID))
}

// ---------------------------------------------------------------------------
// GetLockedWallets
// ---------------------------------------------------------------------------

func TestGetLockedWallets_ReturnsNonNilMap(t *testing.T) {
	lw := GetLockedWallets()
	assert.NotNil(t, lw)
}

// ---------------------------------------------------------------------------
// Block.SetPayloadHash / CalculateHash
// ---------------------------------------------------------------------------

func TestBlock_SetPayloadHash_Deterministic(t *testing.T) {
	b := Block{
		Transactions: []Transaction{{Sender: "A", Receiver: "B", Amount: 10}},
		PrevHash:     "abc",
	}
	b.SetPayloadHash()
	h1 := b.PayloadHash
	b.SetPayloadHash()
	h2 := b.PayloadHash
	assert.Equal(t, h1, h2, "SetPayloadHash must be deterministic")
}

func TestBlock_CalculateHash_ChangesAfterMutation(t *testing.T) {
	b := Block{PrevHash: "x", Nonce: 1}
	h1 := b.CalculateHash()
	b.Nonce = 2
	h2 := b.CalculateHash()
	assert.NotEqual(t, h1, h2, "hash must change when block content changes")
}
