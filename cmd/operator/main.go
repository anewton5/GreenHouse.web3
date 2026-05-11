package main

// cmd/operator/main.go — GreenHouse node operator onboarding CLI.
//
// This binary is run once by each institutional node operator to:
//  1. Generate a stable Ed25519 keypair and libp2p peer ID.
//  2. Export the peer ID for submission to the GreenHouse registry operator.
//  3. Register with the network by submitting a signed registration request.
//
// # Commands
//
//	operator generate-identity   — generates key + peer ID, saves to ~/.greenhouse/identity
//	operator export-peer-id      — prints the peer ID (for submission to registry)
//	operator register            — submits signed registration request to registry API
//
// # Identity file
//
// The identity is stored in ~/.greenhouse/identity/identity.key as a hex-encoded
// marshalled libp2p private key (0600 permissions). The directory is created if absent.
//
// # Environment variables for register command
//
//	GREENHOUSE_REGISTRY_URL  — base URL of the GreenHouse registry API
//	                            e.g. https://registry.greenhouse.network
//
// # Build
//
//	go build -o bin/operator ./cmd/operator/

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/sha3"
)

const identityFileName = "identity.key"

// identityDir returns the path to the operator's identity directory.
// Defaults to ~/.greenhouse/identity; override with GREENHOUSE_IDENTITY_DIR.
func identityDir() string {
	if d := os.Getenv("GREENHOUSE_IDENTITY_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Could not determine home directory: %v", err)
	}
	return filepath.Join(home, ".greenhouse", "identity")
}

// keyPath returns the full path to the identity key file.
func keyPath() string {
	return filepath.Join(identityDir(), identityFileName)
}

// loadKey loads the operator's private key from disk.
// Returns an error if the identity has not been generated yet.
func loadKey() (crypto.PrivKey, error) {
	data, err := os.ReadFile(keyPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("identity not found — run 'operator generate-identity' first")
		}
		return nil, fmt.Errorf("failed to read identity file: %w", err)
	}
	keyBytes, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to decode identity key: %w", err)
	}
	priv, err := crypto.UnmarshalPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal identity key: %w", err)
	}
	return priv, nil
}

// peerIDFromKey derives the libp2p peer.ID from a private key.
func peerIDFromKey(priv crypto.PrivKey) (peer.ID, error) {
	pub := priv.GetPublic()
	return peer.IDFromPublicKey(pub)
}

// cmdGenerateIdentity generates a new Ed25519 keypair and saves it to disk.
// Refuses to overwrite an existing identity unless --force is passed.
func cmdGenerateIdentity(force bool) {
	dir := identityDir()
	path := keyPath()

	if _, err := os.Stat(path); err == nil && !force {
		fmt.Println("ERROR: identity already exists at", path)
		fmt.Println("  Use --force to overwrite (this will invalidate any existing allowlist entries).")
		os.Exit(1)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatalf("Could not create identity directory %s: %v", dir, err)
	}

	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	keyBytes, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		log.Fatalf("Failed to marshal private key: %v", err)
	}

	if err := os.WriteFile(path, []byte(hex.EncodeToString(keyBytes)), 0600); err != nil {
		log.Fatalf("Failed to write identity file: %v", err)
	}

	id, err := peerIDFromKey(priv)
	if err != nil {
		log.Fatalf("Failed to derive peer ID: %v", err)
	}

	pubBytes, err := crypto.MarshalPublicKey(priv.GetPublic())
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	fmt.Println("Identity generated successfully.")
	fmt.Println()
	fmt.Printf("  Identity file : %s\n", path)
	fmt.Printf("  Peer ID       : %s\n", id)
	fmt.Printf("  Public key    : %s\n", hex.EncodeToString(pubBytes))
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Share your Peer ID with the GreenHouse registry operator.")
	fmt.Println("  2. Once allowlisted, run: operator register")
	fmt.Println("  3. Set GREENHOUSE_BOOTSTRAP_PEERS and start your node.")
}

// cmdExportPeerID prints the peer ID for submission to the registry operator.
func cmdExportPeerID() {
	priv, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	id, err := peerIDFromKey(priv)
	if err != nil {
		log.Fatalf("Failed to derive peer ID: %v", err)
	}

	pubBytes, err := crypto.MarshalPublicKey(priv.GetPublic())
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	fmt.Printf("Peer ID    : %s\n", id)
	fmt.Printf("Public key : %s\n", hex.EncodeToString(pubBytes))
}

// registrationRequest is the JSON payload sent to the registry API.
type registrationRequest struct {
	PeerID      string `json:"peerId"`
	PublicKey   string `json:"publicKey"` // hex-encoded marshalled libp2p public key
	Signature   string `json:"signature"` // hex-encoded SHA3-256(peerID + publicKey + timestamp)
	Timestamp   int64  `json:"timestamp"`
	OperatorOrg string `json:"operatorOrg"` // optional human-readable org name
}

// cmdRegister submits a signed registration request to the registry API.
func cmdRegister(operatorOrg string) {
	registryURL := os.Getenv("GREENHOUSE_REGISTRY_URL")
	if registryURL == "" {
		fmt.Fprintln(os.Stderr, "ERROR: GREENHOUSE_REGISTRY_URL environment variable is not set")
		fmt.Fprintln(os.Stderr, "  Set it to the GreenHouse registry API base URL, e.g.:")
		fmt.Fprintln(os.Stderr, "  export GREENHOUSE_REGISTRY_URL=https://registry.greenhouse.network")
		os.Exit(1)
	}

	priv, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}

	id, err := peerIDFromKey(priv)
	if err != nil {
		log.Fatalf("Failed to derive peer ID: %v", err)
	}

	pubBytes, err := crypto.MarshalPublicKey(priv.GetPublic())
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}
	pubHex := hex.EncodeToString(pubBytes)

	timestamp := time.Now().Unix()

	// Sign SHA3-256(peerID + publicKey + timestamp) with the operator's private key.
	sigInput := fmt.Sprintf("%s:%s:%d", id.String(), pubHex, timestamp)
	h := sha3.New256()
	h.Write([]byte(sigInput))
	digest := h.Sum(nil)

	rawSig, err := priv.Sign(digest)
	if err != nil {
		log.Fatalf("Failed to sign registration payload: %v", err)
	}

	req := registrationRequest{
		PeerID:      id.String(),
		PublicKey:   pubHex,
		Signature:   hex.EncodeToString(rawSig),
		Timestamp:   timestamp,
		OperatorOrg: operatorOrg,
	}

	body, err := json.Marshal(req)
	if err != nil {
		log.Fatalf("Failed to marshal registration request: %v", err)
	}

	endpoint := strings.TrimRight(registryURL, "/") + "/v1/operators/register"
	fmt.Printf("Submitting registration to %s ...\n", endpoint)

	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Fatalf("Failed to build HTTP request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: registration request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		fmt.Println("Registration submitted successfully.")
		fmt.Printf("  Response: %s\n", string(respBody))
		fmt.Println()
		fmt.Println("The registry operator will review your request and add your Peer ID to the allowlist.")
		fmt.Println("You will be notified once allowlisted and can then start your node.")
	} else {
		fmt.Fprintf(os.Stderr, "ERROR: registry returned %d: %s\n", resp.StatusCode, string(respBody))
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "GreenHouse Operator CLI")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  operator generate-identity [--force]")
	fmt.Fprintln(os.Stderr, "      Generate a new Ed25519 keypair and save to ~/.greenhouse/identity/identity.key")
	fmt.Fprintln(os.Stderr, "      --force  overwrite an existing identity (invalidates prior allowlist entries)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  operator export-peer-id")
	fmt.Fprintln(os.Stderr, "      Print your Peer ID and public key for submission to the registry operator")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  operator register [--org <name>]")
	fmt.Fprintln(os.Stderr, "      Submit a signed registration request to the registry API")
	fmt.Fprintln(os.Stderr, "      Requires GREENHOUSE_REGISTRY_URL to be set")
	fmt.Fprintln(os.Stderr, "      --org <name>  optional organisation name (e.g. \"Acme Capital\")")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Environment variables:")
	fmt.Fprintln(os.Stderr, "  GREENHOUSE_REGISTRY_URL    Registry API base URL (required for register)")
	fmt.Fprintln(os.Stderr, "  GREENHOUSE_IDENTITY_DIR    Override identity directory (default: ~/.greenhouse/identity)")
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	switch args[0] {
	case "generate-identity":
		force := false
		for _, a := range args[1:] {
			if a == "--force" {
				force = true
			}
		}
		cmdGenerateIdentity(force)

	case "export-peer-id":
		cmdExportPeerID()

	case "register":
		org := ""
		for i, a := range args[1:] {
			if a == "--org" && i+2 < len(args) {
				org = args[i+2]
			}
		}
		cmdRegister(org)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", args[0])
		usage()
		os.Exit(1)
	}
}
