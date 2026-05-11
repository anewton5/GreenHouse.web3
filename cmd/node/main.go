// cmd/node/main.go — GreenHouse full P2P node entry point.
//
// Starts a blockchain node, connects to bootstrap peers, and runs the P2P
// message handler. Press Ctrl+C to shut down cleanly.
//
// # Environment variables
//
//	GREENHOUSE_BOOTSTRAP_PEERS — comma-separated multiaddrs of bootstrap nodes
//	                              e.g. /ip4/1.2.3.4/tcp/4001/p2p/<PeerID>
//
// # Build
//
//	go build -o bin/gonetwork ./cmd/node/
//
// # Run (standalone, no bootstrap peers)
//
//	./bin/gonetwork
//
// # Run (connect to a specific peer directly via flag)
//
//	./bin/gonetwork --peer /ip4/127.0.0.1/tcp/<PORT>/p2p/<PEERID> --send
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	gn "gonetwork"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Parse flags manually to avoid importing flag package complexity.
	var extraPeer string
	var sendMode bool
	for i, arg := range os.Args[1:] {
		switch arg {
		case "--send":
			sendMode = true
		case "--peer":
			if i+2 < len(os.Args) {
				extraPeer = os.Args[i+2]
			}
		}
	}

	log.Println("Starting GreenHouse node...")

	// Log bootstrap peer configuration from environment.
	if raw := os.Getenv("GREENHOUSE_BOOTSTRAP_PEERS"); raw != "" {
		count := len(strings.Split(strings.TrimSpace(raw), ","))
		log.Printf("Bootstrap peers configured via GREENHOUSE_BOOTSTRAP_PEERS: %d peer(s)", count)
	} else {
		log.Println("No GREENHOUSE_BOOTSTRAP_PEERS set — running in standalone/local mode")
	}

	bc := gn.NewBlockchain(ctx, "greenhouse-p2p-network")
	if bc.P2PNode == nil {
		log.Fatal("P2P node failed to initialize")
	}

	// If a direct peer address was provided, connect to it immediately.
	// This is more reliable than mDNS on macOS and mirrors real network usage.
	if extraPeer != "" {
		ma, err := multiaddr.NewMultiaddr(extraPeer)
		if err != nil {
			log.Fatalf("Invalid --peer address %q: %v", extraPeer, err)
		}
		addrInfo, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			log.Fatalf("Could not parse peer addr info from %q: %v", extraPeer, err)
		}
		if err := bc.P2PNode.Host.Connect(ctx, *addrInfo); err != nil {
			log.Printf("WARNING: could not connect to --peer %s: %v", extraPeer, err)
		} else {
			log.Printf("Directly connected to peer: %s", addrInfo.ID)
		}
	}

	log.Printf("Node is live — Peer ID: %s", bc.P2PNode.Host.ID())
	log.Println("Copy this address to use as --peer on another node:")
	for _, addr := range bc.P2PNode.Host.Addrs() {
		if addr.String()[:6] == "/ip4/1" { // print LAN addresses only (cleaner)
			log.Printf("  %s/p2p/%s", addr, bc.P2PNode.Host.ID())
		}
	}

	// Handle incoming P2P messages in the background.
	go bc.P2PNode.HandleMessages(ctx)

	if sendMode {
		go runLiveTests(ctx, bc)
	}

	// Block until SIGINT or SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("Received %s — shutting down", sig)
}

// runLiveTests waits until at least one peer is in the GossipSub mesh,
// then broadcasts a ping, a transaction, and a block so the listening node
// can confirm receipt.
func runLiveTests(ctx context.Context, bc *gn.Blockchain) {
	log.Println("[TEST] Waiting for a peer to join the GossipSub topic mesh...")

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
		if len(bc.P2PNode.Topic.ListPeers()) > 0 {
			log.Printf("[TEST] %d peer(s) in mesh — starting broadcast tests", len(bc.P2PNode.Topic.ListPeers()))
			break
		}
	}

	// ── Ping ─────────────────────────────────────────────────────────────────
	log.Println("[TEST] Broadcasting ping...")
	if err := bc.P2PNode.BroadcastPing(ctx); err != nil {
		log.Printf("[TEST] Ping failed: %v", err)
	} else {
		log.Println("[TEST] Ping sent — watch the other node for 'Received ping message'")
	}

	time.Sleep(2 * time.Second)

	// ── Transaction ───────────────────────────────────────────────────────────
	log.Println("[TEST] Broadcasting test transaction...")
	tx := gn.Transaction{Sender: "Alice", Receiver: "Bob", Amount: 42.0}
	if err := bc.P2PNode.BroadcastTransaction(tx); err != nil {
		log.Printf("[TEST] Transaction broadcast failed: %v", err)
	} else {
		log.Println("[TEST] Transaction sent — watch the other node for 'Received transaction'")
	}

	time.Sleep(2 * time.Second)

	// ── Block ─────────────────────────────────────────────────────────────────
	log.Println("[TEST] Broadcasting test block...")
	block := gn.Block{Transactions: []gn.Transaction{tx}, Signatures: [][]byte{}}
	if err := bc.P2PNode.BroadcastBlock(block); err != nil {
		log.Printf("[TEST] Block broadcast failed: %v", err)
	} else {
		log.Println("[TEST] Block sent — watch the other node for 'Received block'")
	}

	log.Println("[TEST] Live tests complete. Press Ctrl+C to shut down.")
}
