package gonetwork

// ---------------------------------------------------------------------------
// Item 11: ValidateBlock typed-transaction verification tests.
//
// Covers:
//   - AssetTransaction sender signature accepted / rejected
//   - OrderTransaction order signature accepted / rejected
//   - CredentialTransaction registry signature accepted / rejected
//   - RFQTransaction requester/dealer signature accepted / rejected
//   - MarketMakerTransaction operator signature accepted / rejected
//   - DefaultVotingStrategy.Vote covers all five typed transaction families
// ---------------------------------------------------------------------------

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// minimalBC returns a Blockchain with no delegates (single-operator mode) so
// the BFT supermajority check is skipped and we can focus on typed-tx checks.
func minimalBC(t *testing.T) *Blockchain {
	t.Helper()
	return newTestBlockchain(t)
}

// makeSignedAssetTx produces a valid AssetTransaction signed by senderKey.
// receiverKey may be the same key (self-transfer is OK for signature tests).
func makeSignedAssetTx(t *testing.T, senderKey *PrivateKey, receiverKey *PublicKey) AssetTransaction {
	t.Helper()
	at, err := NewAssetTransaction(senderKey, receiverKey, "ASSET-001", 100, AssetTxTypeIssue)
	require.NoError(t, err)
	return *at
}

// makeSignedOrder produces a new Order signed by placerKey.
func makeSignedOrder(t *testing.T, placerKey *PrivateKey) Order {
	t.Helper()
	order, err := NewOrder(placerKey, "ASSET-001", OrderSideBid, 10.0, 5.0, 0)
	require.NoError(t, err)
	return *order
}

func makeSignedMarketMakerTx(t *testing.T, provider KeyProvider, agreement MarketMakerAgreement) MarketMakerTransaction {
	t.Helper()
	mtx, err := NewMarketMakerTransaction(provider, agreement, MarketMakerActionRegister, "")
	require.NoError(t, err)
	return mtx
}

func makeSignedBaseTx(t *testing.T, signer *PrivateKey, receiver string) Transaction {
	t.Helper()
	tx := Transaction{
		Sender:       base64.StdEncoding.EncodeToString(signer.Public().Bytes()),
		Receiver:     receiver,
		Amount:       0,
		RequiredSigs: 1,
		Nonce:        time.Now().UnixNano(),
	}
	require.NoError(t, tx.SignTransaction(signer))
	return tx
}

func makeSignedRFQRequestTx(t *testing.T, requesterKey *PrivateKey) RFQTransaction {
	t.Helper()
	req, err := NewRFQRequest(requesterKey, "ASSET-001", OrderSideBid, 5, 10.0, time.Now().Unix()+300)
	require.NoError(t, err)
	return RFQTransaction{
		Tx:      makeSignedBaseTx(t, requesterKey, req.AssetID),
		Action:  RFQActionRequest,
		Request: *req,
	}
}

func makeSignedRFQQuoteTx(t *testing.T, dealerKey *PrivateKey, requestID string) RFQTransaction {
	t.Helper()
	quote, err := NewRFQQuote(dealerKey, requestID, 9.75, 5, time.Now().Unix()+300)
	require.NoError(t, err)
	return RFQTransaction{
		Tx:     makeSignedBaseTx(t, dealerKey, requestID),
		Action: RFQActionQuote,
		Quote:  *quote,
	}
}

func makeSignedRFQAcceptTx(t *testing.T, requesterKey *PrivateKey, request *RFQRequest, acceptID string) RFQTransaction {
	t.Helper()
	return RFQTransaction{
		Tx:       makeSignedBaseTx(t, requesterKey, acceptID),
		Action:   RFQActionAccept,
		Request:  *request,
		AcceptID: acceptID,
	}
}

// ---------------------------------------------------------------------------
// AssetTransaction signature tests
// ---------------------------------------------------------------------------

func TestValidateBlock_AssetTx_ValidSenderSig_ReturnsTrue(t *testing.T) {
	bc := minimalBC(t)
	senderKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	at := makeSignedAssetTx(t, senderKey, senderKey.Public())
	block := Block{
		PrevHash:          bc.GetLastBlockHash(),
		AssetTransactions: []AssetTransaction{at},
	}

	assert.True(t, bc.ValidateBlock(block))
}

func TestValidateBlock_AssetTx_InvalidSenderSig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	senderKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	at := makeSignedAssetTx(t, senderKey, senderKey.Public())
	// Tamper the signature.
	at.Tx.Signatures[0][0] ^= 0xFF
	block := Block{
		PrevHash:          bc.GetLastBlockHash(),
		AssetTransactions: []AssetTransaction{at},
	}

	assert.False(t, bc.ValidateBlock(block))
}

func TestValidateBlock_AssetTx_RequiredSigsZero_SkipsCheck(t *testing.T) {
	bc := minimalBC(t)
	// RequiredSigs == 0 → internal/genesis entry, no signature required.
	block := Block{
		PrevHash: bc.GetLastBlockHash(),
		AssetTransactions: []AssetTransaction{
			{Tx: Transaction{RequiredSigs: 0}, AssetID: "GENESIS", TxType: AssetTxTypeIssue},
		},
	}
	assert.True(t, bc.ValidateBlock(block))
}

// ---------------------------------------------------------------------------
// OrderTransaction signature tests
// ---------------------------------------------------------------------------

func TestValidateBlock_OrderTx_ValidOrderSig_ReturnsTrue(t *testing.T) {
	bc := minimalBC(t)
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	order := makeSignedOrder(t, placerKey)
	block := Block{
		PrevHash: bc.GetLastBlockHash(),
		OrderTransactions: []OrderTransaction{
			{Order: order, IsCancellation: false},
		},
	}

	assert.True(t, bc.ValidateBlock(block))
}

func TestValidateBlock_OrderTx_InvalidOrderSig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	order := makeSignedOrder(t, placerKey)
	// Tamper the order signature.
	order.Signature[0] ^= 0xFF
	block := Block{
		PrevHash: bc.GetLastBlockHash(),
		OrderTransactions: []OrderTransaction{
			{Order: order, IsCancellation: false},
		},
	}

	assert.False(t, bc.ValidateBlock(block))
}

func TestValidateBlock_OrderTx_Cancellation_SkipsOrderSigCheck(t *testing.T) {
	bc := minimalBC(t)
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	order := makeSignedOrder(t, placerKey)
	// Tamper the order signature — should be ignored for cancellations.
	order.Signature[0] ^= 0xFF
	block := Block{
		PrevHash: bc.GetLastBlockHash(),
		OrderTransactions: []OrderTransaction{
			{Order: order, IsCancellation: true},
		},
	}

	assert.True(t, bc.ValidateBlock(block))
}

// ---------------------------------------------------------------------------
// CredentialTransaction registry-signature tests
// ---------------------------------------------------------------------------

// newCredentialBlock issues a real credential via MockIdentityRegistry, wraps
// it in a Block, and returns both the block and the registry.
// prevHash is set from the caller's blockchain so the chain-linkage check passes.
func newCredentialBlock(t *testing.T, prevHash string) (Block, *MockIdentityRegistry) {
	t.Helper()
	reg, err := NewMockIdentityRegistry()
	require.NoError(t, err)

	att, err := reg.IssueCredential("wallet-alice", InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)

	block := Block{
		PrevHash: prevHash,
		CredentialTransactions: []CredentialTransaction{
			{Attestation: *att},
		},
	}
	return block, reg
}

func TestValidateBlock_CredentialTx_ValidRegistrySig_ReturnsTrue(t *testing.T) {
	bc := minimalBC(t)
	block, reg := newCredentialBlock(t, bc.GetLastBlockHash())
	bc.IdentityRegistry = reg

	assert.True(t, bc.ValidateBlock(block))
}

func TestValidateBlock_CredentialTx_InvalidRegistrySig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	block, reg := newCredentialBlock(t, bc.GetLastBlockHash())
	bc.IdentityRegistry = reg

	// Tamper the registry signature on the embedded attestation.
	block.CredentialTransactions[0].Attestation.RegistrySignature[0] ^= 0xFF

	assert.False(t, bc.ValidateBlock(block))
}

func TestValidateBlock_CredentialTx_NoRegistrySignature_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	reg, err := NewMockIdentityRegistry()
	require.NoError(t, err)
	bc.IdentityRegistry = reg

	// Build an attestation with no RegistrySignature.
	att := CredentialAttestation{
		WalletPublicKey: "wallet-alice",
		CredentialHash:  "aabbcc",
		InvestorClass:   InvestorClassProfessional,
		KYCStatus:       KYCStatusVerified,
		Jurisdiction:    "GB",
	}
	block := Block{
		PrevHash:               bc.GetLastBlockHash(),
		CredentialTransactions: []CredentialTransaction{{Attestation: att}},
	}

	assert.False(t, bc.ValidateBlock(block))
}

func TestValidateBlock_CredentialTx_NoRegistry_Skipped(t *testing.T) {
	// bc.IdentityRegistry == nil → registry-signature check is skipped.
	bc := minimalBC(t)
	bc.IdentityRegistry = nil

	att := CredentialAttestation{
		WalletPublicKey:   "wallet-alice",
		CredentialHash:    "aabbcc",
		RegistrySignature: []byte("definitely-invalid"),
	}
	block := Block{
		PrevHash:               bc.GetLastBlockHash(),
		CredentialTransactions: []CredentialTransaction{{Attestation: att}},
	}

	assert.True(t, bc.ValidateBlock(block))
}

// ---------------------------------------------------------------------------
// RFQTransaction signature tests
// ---------------------------------------------------------------------------

func TestValidateBlock_RFQRequest_ValidRequesterSig_ReturnsTrue(t *testing.T) {
	bc := minimalBC(t)
	requesterKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	block := Block{
		PrevHash:        bc.GetLastBlockHash(),
		RFQTransactions: []RFQTransaction{makeSignedRFQRequestTx(t, requesterKey)},
	}
	assert.True(t, bc.ValidateBlock(block))
}

func TestValidateBlock_RFQRequest_InvalidRequesterSig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	requesterKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	rtx := makeSignedRFQRequestTx(t, requesterKey)
	rtx.Request.Signature[0] ^= 0xFF
	block := Block{PrevHash: bc.GetLastBlockHash(), RFQTransactions: []RFQTransaction{rtx}}
	assert.False(t, bc.ValidateBlock(block))
}

func TestValidateBlock_RFQQuote_InvalidDealerSig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	rtx := makeSignedRFQQuoteTx(t, dealerKey, "rfq-request-1")
	rtx.Quote.Signature[0] ^= 0xFF
	block := Block{PrevHash: bc.GetLastBlockHash(), RFQTransactions: []RFQTransaction{rtx}}
	assert.False(t, bc.ValidateBlock(block))
}

func TestValidateBlock_MarketMakerTx_ValidOperatorSig_ReturnsTrue(t *testing.T) {
	bc := minimalBC(t)
	operatorKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bc.OperatorKeyProvider = NewLocalKeyProvider(operatorKey)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	agreement, err := NewMarketMakerAgreement(
		operatorKey,
		"ASSET-001",
		base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes()),
		"549300ACMECORP0024",
		5, 50, 1, 10, 0, 0,
		time.Now().Unix(), 0,
	)
	require.NoError(t, err)
	block := Block{
		PrevHash:                bc.GetLastBlockHash(),
		MarketMakerTransactions: []MarketMakerTransaction{makeSignedMarketMakerTx(t, bc.OperatorKeyProvider, *agreement)},
	}
	assert.True(t, bc.ValidateBlock(block))
}

func TestValidateBlock_MarketMakerTx_InvalidOperatorSig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	operatorKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bc.OperatorKeyProvider = NewLocalKeyProvider(operatorKey)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	agreement, err := NewMarketMakerAgreement(
		operatorKey,
		"ASSET-001",
		base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes()),
		"549300ACMECORP0025",
		5, 50, 1, 10, 0, 0,
		time.Now().Unix(), 0,
	)
	require.NoError(t, err)
	mtx := makeSignedMarketMakerTx(t, bc.OperatorKeyProvider, *agreement)
	mtx.Agreement.OperatorSignature[0] ^= 0xFF
	block := Block{PrevHash: bc.GetLastBlockHash(), MarketMakerTransactions: []MarketMakerTransaction{mtx}}
	assert.False(t, bc.ValidateBlock(block))
}

// ---------------------------------------------------------------------------
// DefaultVotingStrategy.Vote — OrderTransaction tests
// ---------------------------------------------------------------------------

func TestDefaultVotingStrategy_Vote_ValidOrderTx_ReturnsTrue(t *testing.T) {
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	order := makeSignedOrder(t, placerKey)
	block := Block{
		OrderTransactions: []OrderTransaction{
			{Order: order, IsCancellation: false},
		},
	}

	d := &DefaultVotingStrategy{}
	assert.True(t, d.Vote(block))
}

func TestDefaultVotingStrategy_Vote_InvalidOrderSig_ReturnsFalse(t *testing.T) {
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	order := makeSignedOrder(t, placerKey)
	order.Signature[0] ^= 0xFF
	block := Block{
		OrderTransactions: []OrderTransaction{
			{Order: order, IsCancellation: false},
		},
	}

	d := &DefaultVotingStrategy{}
	assert.False(t, d.Vote(block))
}

func TestDefaultVotingStrategy_Vote_CancellationWithTamperedSig_ReturnsTrue(t *testing.T) {
	// Cancellations skip the Order signature check in Vote.
	placerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	order := makeSignedOrder(t, placerKey)
	order.Signature[0] ^= 0xFF
	block := Block{
		OrderTransactions: []OrderTransaction{
			{Order: order, IsCancellation: true},
		},
	}

	d := &DefaultVotingStrategy{}
	assert.True(t, d.Vote(block))
}

func TestDefaultVotingStrategy_Vote_ValidCredentialTx_ReturnsTrue(t *testing.T) {
	bc := minimalBC(t)
	block, reg := newCredentialBlock(t, bc.GetLastBlockHash())
	bc.IdentityRegistry = reg
	d := &DefaultVotingStrategy{Blockchain: bc}
	assert.True(t, d.Vote(block))
}

func TestDefaultVotingStrategy_Vote_InvalidCredentialSig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	block, reg := newCredentialBlock(t, bc.GetLastBlockHash())
	bc.IdentityRegistry = reg
	block.CredentialTransactions[0].Attestation.RegistrySignature[0] ^= 0xFF
	d := &DefaultVotingStrategy{Blockchain: bc}
	assert.False(t, d.Vote(block))
}

// ---------------------------------------------------------------------------
// AssetTransaction wrong-key test (singer != Tx.Sender)
// ---------------------------------------------------------------------------

func TestValidateBlock_AssetTx_WrongKey_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	senderKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	otherKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	at := makeSignedAssetTx(t, senderKey, senderKey.Public())
	// Replace Tx.Sender with a different (wrong) key so the embedded sig won't verify.
	at.Tx.Sender = base64.StdEncoding.EncodeToString(otherKey.Public().Bytes())
	block := Block{
		PrevHash:          bc.GetLastBlockHash(),
		AssetTransactions: []AssetTransaction{at},
	}

	assert.False(t, bc.ValidateBlock(block))
}

// ---------------------------------------------------------------------------
// DefaultVotingStrategy.Vote — MarketMakerTransaction stub tests
// ---------------------------------------------------------------------------

func TestDefaultVotingStrategy_Vote_RFQRequestValid_ReturnsTrue(t *testing.T) {
	bc := minimalBC(t)
	requesterKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	block := Block{RFQTransactions: []RFQTransaction{makeSignedRFQRequestTx(t, requesterKey)}}
	d := &DefaultVotingStrategy{Blockchain: bc}
	assert.True(t, d.Vote(block))
}

func TestDefaultVotingStrategy_Vote_RFQQuoteInvalidSig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	rtx := makeSignedRFQQuoteTx(t, dealerKey, "rfq-request-2")
	rtx.Quote.Signature[0] ^= 0xFF
	block := Block{RFQTransactions: []RFQTransaction{rtx}}
	d := &DefaultVotingStrategy{Blockchain: bc}
	assert.False(t, d.Vote(block))
}

func TestDefaultVotingStrategy_Vote_RFQAcceptInvalidRequesterSig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	requesterKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	req, err := NewRFQRequest(requesterKey, "ASSET-001", OrderSideBid, 5, 10.0, time.Now().Unix()+300)
	require.NoError(t, err)
	rtx := makeSignedRFQAcceptTx(t, requesterKey, req, "quote-accept-1")
	rtx.Tx.Signatures[0][0] ^= 0xFF
	block := Block{RFQTransactions: []RFQTransaction{rtx}}
	d := &DefaultVotingStrategy{Blockchain: bc}
	assert.False(t, d.Vote(block))
}

func TestDefaultVotingStrategy_Vote_MarketMakerTxOnly_ReturnsTrue(t *testing.T) {
	bc := minimalBC(t)
	operatorKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bc.OperatorKeyProvider = NewLocalKeyProvider(operatorKey)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	agreement, err := NewMarketMakerAgreement(
		operatorKey,
		"ASSET-001",
		base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes()),
		"549300ACMECORP0014",
		5,
		50,
		1,
		10,
		0,
		0,
		time.Now().Unix(),
		0,
	)
	require.NoError(t, err)

	block := Block{MarketMakerTransactions: []MarketMakerTransaction{makeSignedMarketMakerTx(t, bc.OperatorKeyProvider, *agreement)}}
	d := &DefaultVotingStrategy{Blockchain: bc}
	assert.True(t, d.Vote(block))
}

func TestDefaultVotingStrategy_Vote_MarketMakerTxInvalidBaseSig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	operatorKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bc.OperatorKeyProvider = NewLocalKeyProvider(operatorKey)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	agreement, err := NewMarketMakerAgreement(
		operatorKey,
		"ASSET-001",
		base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes()),
		"549300ACMECORP0015",
		5,
		50,
		1,
		10,
		0,
		0,
		time.Now().Unix(),
		0,
	)
	require.NoError(t, err)

	mtx := makeSignedMarketMakerTx(t, bc.OperatorKeyProvider, *agreement)
	mtx.Tx.Signatures[0][0] ^= 0xFF

	block := Block{MarketMakerTransactions: []MarketMakerTransaction{mtx}}
	d := &DefaultVotingStrategy{Blockchain: bc}
	assert.False(t, d.Vote(block))
}

func TestDefaultVotingStrategy_Vote_MarketMakerInvalidOperatorSig_ReturnsFalse(t *testing.T) {
	bc := minimalBC(t)
	operatorKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bc.OperatorKeyProvider = NewLocalKeyProvider(operatorKey)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	agreement, err := NewMarketMakerAgreement(
		operatorKey,
		"ASSET-001",
		base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes()),
		"549300ACMECORP0016",
		5,
		50,
		1,
		10,
		0,
		0,
		time.Now().Unix(),
		0,
	)
	require.NoError(t, err)

	mtx := makeSignedMarketMakerTx(t, bc.OperatorKeyProvider, *agreement)
	mtx.Agreement.OperatorSignature[0] ^= 0xFF

	block := Block{MarketMakerTransactions: []MarketMakerTransaction{mtx}}
	d := &DefaultVotingStrategy{Blockchain: bc}
	assert.False(t, d.Vote(block))
}
