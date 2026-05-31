package gonetwork

import (
	"os"
	"testing"
)

// TestMain applies stable default network settings for repeated test runs.
// Dedicated P2P discovery tests can opt in to real DHT/mDNS via t.Setenv.
func TestMain(m *testing.M) {
	if os.Getenv("GONETWORK_DISABLE_P2P_DHT") == "" {
		_ = os.Setenv("GONETWORK_DISABLE_P2P_DHT", "1")
	}
	if os.Getenv("GONETWORK_DISABLE_P2P_MDNS") == "" {
		_ = os.Setenv("GONETWORK_DISABLE_P2P_MDNS", "1")
	}
	if os.Getenv("GONETWORK_ALLOW_TEST_CONSENSUS_HYBRID") == "" {
		_ = os.Setenv("GONETWORK_ALLOW_TEST_CONSENSUS_HYBRID", "1")
	}
	os.Exit(m.Run())
}
