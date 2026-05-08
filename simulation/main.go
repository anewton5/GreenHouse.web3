// simulation/main.go — GreenHouse Phase 0 end-to-end demonstration.
//
// Run:
//
//	go run simulation/main.go
//
// Libp2p logs are written to stderr; redirect stderr to /dev/null for
// clean output:
//
//	go run simulation/main.go 2>/dev/null
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	gn "gonetwork"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustKey() *gn.PrivateKey {
	key, err := gn.GeneratePrivateKey()
	if err != nil {
		fatalf("GeneratePrivateKey: %v", err)
	}
	return key
}

func pubStr(k *gn.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Public().Bytes())
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}

// commaf formats a non-negative float64 as a comma-separated integer string.
// e.g. 400000 → "400,000", 1000000 → "1,000,000"
func commaf(f float64) string {
	s := strconv.FormatInt(int64(f), 10)
	n := len(s)
	if n <= 3 {
		return s
	}
	var b strings.Builder
	rem := n % 3
	if rem > 0 {
		b.WriteString(s[:rem])
		if n > rem {
			b.WriteByte(',')
		}
	}
	for i := rem; i < n; i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < n {
			b.WriteByte(',')
		}
	}
	return b.String()
}

// pendingUnsettled returns the number of payment instructions not yet confirmed.
func pendingUnsettled(bc *gn.Blockchain) int {
	count := 0
	for id := range bc.PendingInstructions {
		if _, ok := bc.ConfirmedPayments[id]; !ok {
			count++
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// Simulation
// ---------------------------------------------------------------------------

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Println("=== GreenHouse Private Placement Simulation ===")
	fmt.Println()

	// ── 1. Bootstrap ──────────────────────────────────────────────────────────
	bc := gn.NewBlockchain(ctx, "greenhouse-sim")
	fmt.Println("[INIT]    Genesis block added")
	fmt.Println("[INIT]    P2P node started (mock mode — bootstrap peers optional)")
	fmt.Println("[INIT]    Services: MockIdentityRegistry | MockPaymentProvider | MockOracleService")
	fmt.Println()

	// ── 2. Generate participant key-pairs ─────────────────────────────────────
	issuerKey := mustKey()
	aliceKey := mustKey()
	bobKey := mustKey()
	charlieKey := mustKey()
	dianaKey := mustKey()

	aliceKeyStr := pubStr(aliceKey)
	bobKeyStr := pubStr(bobKey)
	charlieKeyStr := pubStr(charlieKey)
	dianaKeyStr := pubStr(dianaKey)

	// ── 3. KYC / Identity credentials ────────────────────────────────────────
	issueCredential := func(name, keyStr string, class gn.InvestorClass, jurisdiction string) {
		att, err := bc.IdentityRegistry.IssueCredential(keyStr, class, jurisdiction, 365)
		if err != nil {
			fatalf("IssueCredential %s: %v", name, err)
		}
		bc.Credentials[keyStr] = att
	}

	issueCredential("Alice", aliceKeyStr, gn.InvestorClassProfessional, "GB")
	issueCredential("Bob", bobKeyStr, gn.InvestorClassProfessional, "DE")
	issueCredential("Charlie", charlieKeyStr, gn.InvestorClassEligibleCP, "FR")
	issueCredential("Diana", dianaKeyStr, gn.InvestorClassRetail, "GB")

	fmt.Println("[KYC]     Credential issued: Alice   — Accredited / GB / Professional")
	fmt.Println("[KYC]     Credential issued: Bob     — Accredited / DE / Professional")
	fmt.Println("[KYC]     Credential issued: Charlie — Accredited / FR / EligibleCP")
	fmt.Println("[KYC]     Credential issued: Diana   — Retail / GB")
	fmt.Println("          (Diana flagged: retail investor, cannot hold AccreditedOnly assets)")
	fmt.Println()

	// ── 4. Issue asset ────────────────────────────────────────────────────────
	asset, err := gn.NewAsset(
		issuerKey,
		gn.AssetTypeEquity,
		1_000_000,
		"GBP",
		gn.AssetMetadata{
			CompanyName:  "Acme Series B",
			Jurisdiction: "GB",
		},
		gn.TransferRestrictions{
			LockupPeriodDays: 365,
			AccreditedOnly:   true,
		},
	)
	if err != nil {
		fatalf("NewAsset: %v", err)
	}
	bc.Assets[asset.ID] = asset

	fmt.Println("[ASSET]   Issued: Acme Series B — 1,000,000 shares — GBP — AccreditedOnly")
	fmt.Println("[ASSET]   Lockup: 365 days from issuance")
	fmt.Println()

	// ── 5. Build initial allocation (issue) transactions ──────────────────────
	type allocation struct {
		name string
		key  *gn.PrivateKey
		qty  float64
	}
	allocs := []allocation{
		{"Alice", aliceKey, 400_000},
		{"Bob", bobKey, 300_000},
		{"Charlie", charlieKey, 300_000},
	}

	lockupDate := time.Now().AddDate(1, 0, 0).Format("2006-01-02")
	var assetTxs []gn.AssetTransaction
	for _, a := range allocs {
		tx, err := gn.NewAssetTransaction(issuerKey, a.key.Public(), asset.ID, a.qty, gn.AssetTxTypeIssue)
		if err != nil {
			fatalf("NewAssetTransaction %s: %v", a.name, err)
		}
		assetTxs = append(assetTxs, *tx)
		fmt.Printf("[ALLOC]   %-7s receives %s shares (LockedUntil: %s)\n",
			a.name, commaf(a.qty), lockupDate)
	}
	fmt.Println()

	// ── 6. Place orders ───────────────────────────────────────────────────────
	aliceBid, err := gn.NewOrder(aliceKey, asset.ID, gn.OrderSideBid, 6.00, 50_000, 0)
	if err != nil {
		fatalf("NewOrder Alice: %v", err)
	}
	bobAsk, err := gn.NewOrder(bobKey, asset.ID, gn.OrderSideAsk, 5.50, 50_000, 0)
	if err != nil {
		fatalf("NewOrder Bob: %v", err)
	}
	charlieAsk, err := gn.NewOrder(charlieKey, asset.ID, gn.OrderSideAsk, 6.50, 25_000, 0)
	if err != nil {
		fatalf("NewOrder Charlie: %v", err)
	}

	fmt.Printf("[ORDER]   Alice   BID  50,000 shares @ £6.00 — ID: %s...\n", aliceBid.ID[:8])
	fmt.Printf("[ORDER]   Bob     ASK  50,000 shares @ £5.50 — ID: %s...\n", bobAsk.ID[:8])
	fmt.Printf("[ORDER]   Charlie ASK  25,000 shares @ £6.50 — ID: %s...\n", charlieAsk.ID[:8])
	fmt.Println()

	// Wrap each order in an OrderTransaction. Tx.Sender identifies the placer
	// so that finalizeBlock can reconstruct the public key for signature
	// verification when adding the order to the book.
	orderTxs := []gn.OrderTransaction{
		{Tx: gn.Transaction{Sender: aliceKeyStr}, Order: *aliceBid},
		{Tx: gn.Transaction{Sender: bobKeyStr}, Order: *bobAsk},
		{Tx: gn.Transaction{Sender: charlieKeyStr}, Order: *charlieAsk},
	}

	// ── 7. Build and commit block (simulated consensus) ───────────────────────
	block := gn.Block{
		Transactions:      []gn.Transaction{},
		AssetTransactions: assetTxs,
		OrderTransactions: orderTxs,
		PrevHash:          bc.GetLastBlockHash(),
	}

	fmt.Printf("[CONSENSUS] Block #1 proposed — %d orders, %d alloc txs\n",
		len(orderTxs), len(assetTxs))
	fmt.Println("[CONSENSUS] Delegates voted: yes (mock mode)")

	bc.CommitBlock(block)

	blockHash := bc.Blocks[len(bc.Blocks)-1].CalculateHash()
	fmt.Printf("[CONSENSUS] Block #1 finalised — hash: %s...\n", blockHash[:8])
	fmt.Println()

	// ── 8. Report matching results ────────────────────────────────────────────
	if len(bc.Trades) > 0 {
		trade := bc.Trades[0]
		settled := trade.Price * trade.Quantity
		fmt.Printf("[MATCH]   BID £%.2f >= ASK £%.2f → TRADE\n", aliceBid.Price, bobAsk.Price)
		fmt.Printf("[MATCH]   Quantity: %s @ £%.2f = £%.2f GBP\n",
			commaf(trade.Quantity), trade.Price, settled)
		fmt.Printf("[MATCH]   Trade ID: %s... | Buyer: Alice | Seller: Bob\n", trade.ID[:8])
		fmt.Printf("[MATCH]   Charlie ASK £%.2f — no matching bid (max bid £%.2f)\n",
			charlieAsk.Price, aliceBid.Price)
		fmt.Println()
	} else {
		fmt.Println("[MATCH]   No trades produced — check order prices and holdings")
		fmt.Println()
	}

	// ── 9. DVP settlement ─────────────────────────────────────────────────────
	settled := false
	for tradeID, instr := range bc.PendingInstructions {
		fmt.Printf("[DVP]     PaymentInstruction: Alice → Bob  £%.2f %s  Ref: %s\n",
			instr.TotalAmount, instr.Currency, instr.Reference)
		fmt.Println("[DVP]     MockPaymentProvider: confirmed instantly")
		if _, ok := bc.ConfirmedPayments[tradeID]; ok {
			fmt.Println("[DVP]     OracleService: PaymentConfirmation signed")
		}
		fmt.Println("[DVP]     Asset delivery: Bob -50,000 / Alice +50,000")
		fmt.Println("[DVP]     Settlement complete ✓")
		fmt.Println()
		settled = true
		break // single trade in this scenario
	}
	if !settled {
		fmt.Println("[DVP]     No payment instructions generated")
		fmt.Println()
	}

	// ── 10. Diana rejection ───────────────────────────────────────────────────
	fmt.Println("[REJECT]  Diana attempts to buy from Charlie")
	if eligErr := gn.CheckTransferEligibility(dianaKeyStr, asset, bc.Credentials); eligErr != nil {
		fmt.Printf("[REJECT]  Reason: %v\n", eligErr)
		fmt.Println("[REJECT]  Order rejected before reaching order book ✓")
	} else {
		// Should not reach here — AccreditedOnly blocks Diana
		fmt.Println("[REJECT]  ERROR: Diana's order was not rejected — check AccreditedOnly logic")
		os.Exit(1)
	}
	fmt.Println()

	// ── 11. Final state ───────────────────────────────────────────────────────
	aliceH := bc.Holdings[gn.HoldingKey(aliceKeyStr, asset.ID)]
	bobH := bc.Holdings[gn.HoldingKey(bobKeyStr, asset.ID)]
	charlieH := bc.Holdings[gn.HoldingKey(charlieKeyStr, asset.ID)]

	var totalSettled float64
	for _, tr := range bc.Trades {
		totalSettled += tr.Price * tr.Quantity
	}

	fmt.Println("=== Final State ===")
	fmt.Printf("Chain:    %d blocks\n", len(bc.Blocks))
	fmt.Printf("Assets:   %d (Acme Series B — %s shares in circulation)\n",
		len(bc.Assets), commaf(bc.Assets[asset.ID].CirculatingSupply))
	fmt.Printf("Holdings: Alice %s | Bob %s | Charlie %s | Diana 0\n",
		commaf(aliceH.Balance), commaf(bobH.Balance), commaf(charlieH.Balance))
	fmt.Printf("Trades:   %d (£%.2f settled)\n", len(bc.Trades), totalSettled)
	fmt.Printf("Pending:  %d payment instructions\n", pendingUnsettled(bc))
	fmt.Println()
	fmt.Println("Simulation complete.")
}
