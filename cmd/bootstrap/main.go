// cmd/bootstrap/main.go — GreenHouse bootstrap / relay node.
//
// This binary is intended to run on a publicly reachable server (e.g. a VPS).
// It maintains a stable libp2p identity so its Peer ID never changes across
// restarts, making it a reliable long-lived bootstrap point for the rest of
// the network.
//
// First run:
//
//	./bootstrap
//	# Generates identity.key and prints the full multiaddress.
//	# Copy the /ip4/<PUBLIC_IP>/tcp/4001/p2p/<PeerID> line into blockchain.go.
//
// Subsequent runs use the saved identity.key so the Peer ID stays the same.
//
// Build for Linux (deploy to DigitalOcean):
//
//	GOOS=linux GOARCH=amd64 go build -o bin/bootstrap-linux ./cmd/bootstrap/
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	libp2p "github.com/libp2p/go-libp2p"
	kaddht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
)

const (
	listenPort = 4001
	keyFile    = "identity.key"
)

// loadOrCreateKey loads the node's private key from disk. If the file does not
// exist a new Ed25519 key is generated, saved, and returned.
func loadOrCreateKey(path string) (crypto.PrivKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		keyBytes, err := hex.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("failed to decode key file: %w", err)
		}
		priv, err := crypto.UnmarshalPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
		}
		log.Printf("Loaded existing identity from %s", path)
		return priv, nil
	}

	// Generate a fresh Ed25519 identity.
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	keyBytes, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}

	if writeErr := os.WriteFile(path, []byte(hex.EncodeToString(keyBytes)), 0600); writeErr != nil {
		log.Printf("WARNING: could not save identity key to %s: %v", path, writeErr)
	} else {
		log.Printf("Generated new identity and saved to %s", path)
	}

	return priv, nil
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Identity ──────────────────────────────────────────────────────────────
	priv, err := loadOrCreateKey(keyFile)
	if err != nil {
		log.Fatalf("Identity error: %v", err)
	}

	// ── Listen addresses ──────────────────────────────────────────────────────
	listenMaddrs := []multiaddr.Multiaddr{}
	for _, s := range []string{
		fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort),
		fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", listenPort),
	} {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			log.Fatalf("Invalid listen address %s: %v", s, err)
		}
		listenMaddrs = append(listenMaddrs, ma)
	}

	// ── Create host ───────────────────────────────────────────────────────────
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrs(listenMaddrs...),
	)
	if err != nil {
		log.Fatalf("Failed to create libp2p host: %v", err)
	}
	defer h.Close()

	// ── Print addresses ───────────────────────────────────────────────────────
	log.Printf("Bootstrap node running — Peer ID: %s", h.ID())
	fmt.Println()
	fmt.Println("=== BOOTSTRAP NODE ADDRESSES ===")
	for _, addr := range h.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", addr, h.ID())
	}
	fmt.Println("=================================")
	fmt.Println()
	fmt.Println("Add this line to blockchain.go bootstrapPeers:")
	fmt.Printf("  \"/ip4/206.189.29.191/tcp/%d/p2p/%s\"\n", listenPort, h.ID())
	fmt.Println()

	// ── DHT in server mode ────────────────────────────────────────────────────
	dht, err := kaddht.New(ctx, h, kaddht.Mode(kaddht.ModeServer))
	if err != nil {
		log.Fatalf("Failed to create DHT: %v", err)
	}
	if err := dht.Bootstrap(ctx); err != nil {
		log.Fatalf("Failed to bootstrap DHT: %v", err)
	}
	log.Printf("DHT running in server mode — ready to accept peers")

	// ── Block until SIGINT / SIGTERM ──────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("Received signal %s — shutting down", sig)
}
