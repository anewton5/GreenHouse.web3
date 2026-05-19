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
package main

import (
	"context"
	"encoding/hex"
	"log"
	"os"
	"os/signal"
	"syscall"

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
