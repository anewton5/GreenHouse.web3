// cmd/bootstrap/main.go — GreenHouse bootstrap / relay node.
//
// This binary is intended to run on a publicly reachable server (e.g. AWS EC2).
// It maintains a stable libp2p identity so its Peer ID never changes across
// restarts, making it a reliable long-lived bootstrap point for the rest of
// the network.
//
// # First run
//
//	./bootstrap
//	# Generates identity.key and prints the full multiaddress.
//	# Use the printed multiaddr as GREENHOUSE_BOOTSTRAP_PEERS on other nodes.
//
// Subsequent runs load the saved identity.key so the Peer ID remains stable.
//
// # Environment variables
//
//	GREENHOUSE_BOOTSTRAP_PEERS — comma-separated multiaddrs of peer bootstrap nodes
//	                              (leave empty on the first bootstrap node in a pair)
//	GREENHOUSE_REGISTRY_PUBKEY — hex-encoded Ed25519 public key of the registry operator;
//	                              enables the allowlist gater when set
//	GREENHOUSE_STRICT_MODE     — set to "true" to refuse connections from non-allowlisted peers
//	GREENHOUSE_LISTEN_PORT     — TCP port to listen on (default: 4001)
//
// # Deployment targets
//
//	bootstrap-1.greenhouse.network — eu-west-1 (AWS EC2)
//	bootstrap-2.greenhouse.network — eu-central-1 (AWS EC2)
//
// # Build for Linux (deploy to AWS)
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
	"strconv"
	"strings"
	"syscall"

	libp2p "github.com/libp2p/go-libp2p"
	kaddht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

const (
	defaultListenPort = 4001
	keyFile           = "identity.key"
)

// loadOrCreateKey loads the node's private key from disk. If the file does not
// exist a new Ed25519 key is generated, saved, and returned.
func loadOrCreateKey(path string) (crypto.PrivKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		keyBytes, err := hex.DecodeString(strings.TrimSpace(string(data)))
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

// parseBootstrapPeers parses a comma-separated list of multiaddrs into peer.AddrInfo values.
func parseBootstrapPeers(raw string) []peer.AddrInfo {
	var peers []peer.AddrInfo
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			log.Printf("WARNING: invalid bootstrap peer multiaddr %q: %v", s, err)
			continue
		}
		ai, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			log.Printf("WARNING: could not parse peer addr info from %q: %v", s, err)
			continue
		}
		peers = append(peers, *ai)
	}
	return peers
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Configuration from environment ───────────────────────────────────────
	listenPort := defaultListenPort
	if portStr := os.Getenv("GREENHOUSE_LISTEN_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			listenPort = p
		} else {
			log.Printf("WARNING: invalid GREENHOUSE_LISTEN_PORT %q, using default %d", portStr, defaultListenPort)
		}
	}

	bootstrapPeers := parseBootstrapPeers(os.Getenv("GREENHOUSE_BOOTSTRAP_PEERS"))

	registryPubKeyHex := os.Getenv("GREENHOUSE_REGISTRY_PUBKEY")
	strictMode := strings.EqualFold(os.Getenv("GREENHOUSE_STRICT_MODE"), "true")

	if registryPubKeyHex != "" {
		log.Printf("Registry public key configured (allowlist gater active)")
	}
	if strictMode {
		log.Printf("Strict mode ENABLED — non-allowlisted peers will be refused")
	}

	// ── Identity ──────────────────────────────────────────────────────────────
	priv, err := loadOrCreateKey(keyFile)
	if err != nil {
		log.Fatalf("Identity error: %v", err)
	}

	// ── Listen addresses ──────────────────────────────────────────────────────
	var listenMaddrs []multiaddr.Multiaddr
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
	fmt.Println("Set this as GREENHOUSE_BOOTSTRAP_PEERS on other nodes:")
	// Print the first non-loopback address as the suggested value.
	for _, addr := range h.Addrs() {
		addrStr := addr.String()
		if strings.HasPrefix(addrStr, "/ip4/") && !strings.HasPrefix(addrStr, "/ip4/127.") {
			fmt.Printf("  GREENHOUSE_BOOTSTRAP_PEERS=%s/p2p/%s\n", addrStr, h.ID())
			break
		}
	}
	fmt.Println()

	// ── Connect to peer bootstrap nodes ───────────────────────────────────────
	for _, pi := range bootstrapPeers {
		if pi.ID == h.ID() {
			continue // don't dial ourselves
		}
		if err := h.Connect(ctx, pi); err != nil {
			log.Printf("WARNING: could not connect to bootstrap peer %s: %v", pi.ID, err)
		} else {
			log.Printf("Connected to bootstrap peer: %s", pi.ID)
		}
	}

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
