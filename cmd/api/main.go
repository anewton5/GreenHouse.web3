// cmd/api/main.go — GreenHouse HTTP API server.
//
// Starts a blockchain node and exposes the full REST + WebSocket API on
// the configured address. This is the entry point to use when running the
// investor/issuer portals or the mobile app locally.
//
// # Run (development — any wallet is treated as admin)
//
//	go run ./cmd/api/
//
// # Environment variables
//
//	GREENHOUSE_API_ADDR          — listen address (default: :8080)
//	GREENHOUSE_ADMIN_WALLET_KEYS — comma-separated base64 Ed25519 public keys
//	                               allowed to call admin routes. When empty,
//	                               any authenticated wallet is treated as admin
//	                               (safe for local development only).
//	GREENHOUSE_OPERATOR_KEY      — 32-byte hex seed for the OperatorIdentityRegistry.
//	                               When empty, a fresh ephemeral key is generated.
//	ONFIDO_WEBHOOK_SECRET        — HMAC secret for Onfido KYC webhook verification.
//	                               When empty, signature verification is skipped.
//	GREENHOUSE_AML_PROVIDER      — selects the live AML/sanctions screener:
//	                               "complyadvantage", "elliptic", or unset/"mock"
//	                               (default; MockAMLScreener passes every
//	                               transaction — never use in production).
//	COMPLYADVANTAGE_API_KEY      — required when GREENHOUSE_AML_PROVIDER=complyadvantage.
//	COMPLYADVANTAGE_BASE_URL     — optional override (default: https://api.complyadvantage.com).
//	ELLIPTIC_API_KEY             — required when GREENHOUSE_AML_PROVIDER=elliptic.
//	ELLIPTIC_API_SECRET          — required when GREENHOUSE_AML_PROVIDER=elliptic.
//	ELLIPTIC_BASE_URL            — optional override (default: https://aml-api.elliptic.co).
//	GREENHOUSE_PEP_RESCREEN_INTERVAL — periodic PEP/sanctions re-screening interval
//	                               (Go duration string, e.g. "24h"). Default: 24h.
package main

import (
	"context"
	"encoding/hex"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	gn "gonetwork"
	"gonetwork/api"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listenAddr := os.Getenv("GREENHOUSE_API_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	log.Println("GreenHouse API server starting…")
	log.Printf("  Listen address : %s", listenAddr)

	// ── Blockchain ────────────────────────────────────────────────────────────
	// In development we skip P2P (pass an empty topic name to avoid binding a
	// real libp2p host). The blockchain still runs all consensus + matching
	// logic; events just don't propagate to external peers.
	bc := gn.NewBlockchain(ctx, "greenhouse-api-dev")

	// ── Operator Identity Registry ────────────────────────────────────────────
	operatorKey := loadOrGenerateOperatorKey()
	reg, err := gn.NewOperatorIdentityRegistry(operatorKey)
	if err != nil {
		log.Fatalf("Failed to create operator registry: %v", err)
	}
	bc.IdentityRegistry = reg
	// C-2: operator key also signs every sealed block so external verifiers can
	// confirm which node produced the block.
	bc.OperatorKeyProvider = gn.NewLocalKeyProvider(operatorKey)
	log.Println("  KYC registry   : OperatorIdentityRegistry (ephemeral key)")

	// C-4: open bbolt block store so the chain survives process restarts.
	dbPath := "greenhouse.db"
	if v := os.Getenv("GREENHOUSE_DB"); v != "" {
		dbPath = v
	}
	store, err := gn.OpenBlockStore(dbPath)
	if err != nil {
		log.Fatalf("Failed to open block store %s: %v", dbPath, err)
	}
	if err := store.LoadBlocks(bc); err != nil {
		log.Printf("Warning: could not load persisted blocks from %s: %v", dbPath, err)
	} else {
		log.Printf("  Block store    : %s (loaded %d blocks)", dbPath, len(bc.Blocks))
	}
	bc.BlockStore = store

	// ── AML Screener ──────────────────────────────────────────────────────────
	// Defaults to MockAMLScreener (set by NewBlockchain) unless
	// GREENHOUSE_AML_PROVIDER selects a live provider. Live screeners are
	// wrapped with AuditedAMLScreener so every screening decision is durably
	// logged to the "aml_screening_log" bucket for compliance audit trails.
	if screener, provider := loadAMLScreener(); screener != nil {
		bc.AMLScreener = gn.NewAuditedAMLScreener(screener, bc.BlockStore, provider)
		log.Printf("  AML audit log  : persisted to %s (bucket aml_screening_log)", dbPath)
	} else {
		log.Println("  AML screener   : MockAMLScreener (dev/test only — set GREENHOUSE_AML_PROVIDER in production)")
	}

	// ── PEP / Sanctions Re-screening Scheduler ────────────────────────────────
	// JMLSG 3.4.5 requires ongoing periodic re-screening of onboarded investors.
	pepInterval := 24 * time.Hour
	if v := os.Getenv("GREENHOUSE_PEP_RESCREEN_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			pepInterval = d
		} else {
			log.Printf("Warning: invalid GREENHOUSE_PEP_RESCREEN_INTERVAL %q, using default %s", v, pepInterval)
		}
	}
	gn.StartPEPRescreeningScheduler(ctx, bc, pepInterval)
	log.Printf("  PEP rescreen   : every %s", pepInterval)

	// ── API Server ────────────────────────────────────────────────────────────
	srv := api.NewServer(bc, listenAddr)
	srv.OperatorRegistry = reg

	log.Printf("  Admin keys     : %s",
		func() string {
			v := os.Getenv("GREENHOUSE_ADMIN_WALLET_KEYS")
			if v == "" {
				return "none set — all authenticated wallets have admin access (dev mode)"
			}
			return v
		}(),
	)

	// ── Shutdown handler ─────────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received %s — shutting down", sig)
		cancel()
		os.Exit(0)
	}()

	log.Printf("API server ready → http://localhost%s/v1/health", listenAddr)
	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// loadOrGenerateOperatorKey returns a *gn.PrivateKey for the
// OperatorIdentityRegistry. If GREENHOUSE_OPERATOR_KEY is set (32-byte hex seed)
// it is used; otherwise a fresh ephemeral key is generated at startup.
func loadOrGenerateOperatorKey() *gn.PrivateKey {
	if raw := os.Getenv("GREENHOUSE_OPERATOR_KEY"); raw != "" {
		seed, err := hex.DecodeString(raw)
		if err != nil {
			log.Fatalf("GREENHOUSE_OPERATOR_KEY is not valid hex: %v", err)
		}
		key, err := gn.NewPrivateKeyFromSeed(seed)
		if err != nil {
			log.Fatalf("GREENHOUSE_OPERATOR_KEY: %v", err)
		}
		log.Println("  Operator key   : loaded from GREENHOUSE_OPERATOR_KEY")
		return key
	}

	key, err := gn.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate operator key: %v", err)
	}
	log.Printf("  Operator key   : ephemeral (set GREENHOUSE_OPERATOR_KEY=%s to persist across restarts)",
		hex.EncodeToString(key.Bytes()))
	return key
}

// loadAMLScreener constructs a live AML/sanctions screener from environment
// variables when GREENHOUSE_AML_PROVIDER selects one. Returns (nil, "") when
// unset (or "mock"), leaving bc.AMLScreener at its NewBlockchain default
// (MockAMLScreener — passes every transaction; dev/test only). The returned
// provider name labels persisted audit log entries (see AuditedAMLScreener).
func loadAMLScreener() (gn.AMLScreener, string) {
	provider := strings.ToLower(strings.TrimSpace(os.Getenv("GREENHOUSE_AML_PROVIDER")))
	switch provider {
	case "", "mock":
		return nil, ""
	case "complyadvantage":
		apiKey := os.Getenv("COMPLYADVANTAGE_API_KEY")
		if apiKey == "" {
			log.Fatal("GREENHOUSE_AML_PROVIDER=complyadvantage requires COMPLYADVANTAGE_API_KEY")
		}
		baseURL := os.Getenv("COMPLYADVANTAGE_BASE_URL")
		if baseURL == "" {
			baseURL = "https://api.complyadvantage.com"
		}
		log.Println("  AML screener   : ComplyAdvantage")
		return gn.NewComplyAdvantageScreener(apiKey, baseURL), provider
	case "elliptic":
		apiKey := os.Getenv("ELLIPTIC_API_KEY")
		apiSecret := os.Getenv("ELLIPTIC_API_SECRET")
		if apiKey == "" || apiSecret == "" {
			log.Fatal("GREENHOUSE_AML_PROVIDER=elliptic requires ELLIPTIC_API_KEY and ELLIPTIC_API_SECRET")
		}
		baseURL := os.Getenv("ELLIPTIC_BASE_URL")
		if baseURL == "" {
			baseURL = "https://aml-api.elliptic.co"
		}
		log.Println("  AML screener   : Elliptic")
		return gn.NewEllipticScreener(apiKey, apiSecret, baseURL), provider
	default:
		log.Fatalf("unknown GREENHOUSE_AML_PROVIDER %q (expected complyadvantage, elliptic, or mock)", provider)
		return nil, ""
	}
}
