package gonetwork

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"crypto/sha256"

	"golang.org/x/crypto/sha3"

	"github.com/ipfs/go-cid"
	golog "github.com/ipfs/go-log/v2"
	libp2p "github.com/libp2p/go-libp2p"
	kaddht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"
	"golang.org/x/time/rate"
)

var logger = golog.Logger("p2pnode")

var ErrNodeShutdown = errors.New("p2p: node is shutting down")

func init() {
	// Enable debug logging for the "p2pnode" logger
	golog.SetLogLevel("p2pnode", "debug")
}

type P2PNode struct {
	Host           host.Host
	PubSub         *pubsub.PubSub
	Topic          *pubsub.Topic
	Sub            *pubsub.Subscription
	ConsensusTopic *pubsub.Topic
	ConsensusSub   *pubsub.Subscription
	Blockchain     *Blockchain
	MdnsService    mdns.Service // Store the mDNS service
	Gater          *AllowlistGater
	// limiter throttles high-volume publish paths (block/tx) to reduce
	// gossip overload and accidental message storms.
	limiter *rate.Limiter
	// cancelBackground cancels the context used by background goroutines
	// (DHT bootstrap/discovery loop). Called by Shutdown to stop the loop.
	cancelBackground context.CancelFunc
	// bgCtx is the node lifecycle context used by publish/connect operations.
	bgCtx context.Context
	// closed is atomically set to 1 when Shutdown begins.
	closed int32
	// bgWg tracks background goroutines (currently DHT bootstrap/discovery)
	// so Shutdown can wait for them to exit before closing the host.
	bgWg sync.WaitGroup
	// bgMu serializes background goroutine registration with Shutdown's wait
	// boundary to prevent Add/Wait races.
	bgMu sync.Mutex
	// reconnecting tracks peers that already have an active reconnect loop.
	reconnecting sync.Map
}

type mdnsNotifee struct {
	ctx  context.Context
	host host.Host
}

// peerReconnectNotifee listens for disconnect events and triggers an
// exponential-backoff reconnect for explicitly allowlisted peers.
type peerReconnectNotifee struct {
	node *P2PNode
}

const (
	MessageTypeTransaction             = "transaction"
	MessageTypeBlock                   = "block"
	MessageTypeAck                     = "ack"
	MessageTypePing                    = "ping"
	MessageTypeAssetTransaction        = "asset_transaction"
	MessageTypeCredential              = "credential"
	MessageTypePaymentInstruction      = "payment_instruction"
	MessageTypePaymentConfirmation     = "payment_confirmation"
	MessageTypeOrderTransaction        = "order_transaction"
	MessageTypeLiquidityWindow         = "liquidity_window"
	MessageTypeSPVTransaction          = "spv_transaction"
	MessageTypeCorporateAction         = "corporate_action"
	MessageTypeCorporateActionResponse = "corporate_action_response"
	MessageTypeDealAnchor              = "deal_anchor"
	MessageTypeDealCommitment          = "deal_commitment"
	MessageTypeAllowlistAdd            = "allowlist_add"
	MessageTypeAllowlistRevoke         = "allowlist_revoke"
)

type P2PMessage struct {
	Type    string `json:"type"`    // Message type (e.g., "transaction", "block")
	Payload []byte `json:"payload"` // Serialized payload
}

// AllowlistTransaction carries a signed allowlist mutation broadcast over P2P.
// All validators verify the registry signature before applying the mutation
// to their local AllowlistGater.
type AllowlistTransaction struct {
	PeerID    string `json:"peer_id"`   // libp2p peer ID string
	Action    string `json:"action"`    // "allow" or "revoke"
	Signature []byte `json:"signature"` // registry Ed25519 sig over SHA3-256([]byte(PeerID))
}

// AllowlistGater enforces a permissioned P2P network by maintaining a set of
// approved peer IDs. Each entry must be authorised by an Ed25519 signature
// from the network registry key over SHA3-256([]byte(peerID)).
//
// When the allowlist is empty the gater operates in open mode (all connections
// permitted), preserving compatibility with development and test environments.
// The network becomes permissioned as soon as the first peer is admitted.
type AllowlistGater struct {
	mu          sync.RWMutex
	allowed     map[peer.ID]struct{}
	registryKey *PublicKey
}

// NewAllowlistGater creates a gater bound to the given registry public key.
// Pass nil to create an open-mode-only gater (useful for tests and development).
func NewAllowlistGater(registryKey *PublicKey) *AllowlistGater {
	return &AllowlistGater{
		allowed:     make(map[peer.ID]struct{}),
		registryKey: registryKey,
	}
}

// AllowPeer admits a peer after verifying the registry signature.
// sig must equal Sign(SHA3-256([]byte(peerID))) produced by the registry private key.
func (g *AllowlistGater) AllowPeer(id peer.ID, sig []byte) error {
	if g.registryKey == nil {
		return fmt.Errorf("allowlist: registry key not configured")
	}
	hash := sha3.Sum256([]byte(id))
	s := &Signature{value: sig}
	if !s.Verify(g.registryKey, hash[:]) {
		return fmt.Errorf("allowlist: invalid registry signature for peer %s", id)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.allowed[id] = struct{}{}
	return nil
}

// RevokePeer removes a peer from the allowlist after verifying the registry signature.
func (g *AllowlistGater) RevokePeer(id peer.ID, sig []byte) error {
	if g.registryKey == nil {
		return fmt.Errorf("allowlist: registry key not configured")
	}
	hash := sha3.Sum256([]byte(id))
	s := &Signature{value: sig}
	if !s.Verify(g.registryKey, hash[:]) {
		return fmt.Errorf("allowlist: invalid registry signature for peer %s", id)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.allowed, id)
	return nil
}

// LoadPeerManifest reads a JSON file at path of the form:
//
//	[{"peer_id":"12D3KooW...","signature":"<hex>"},...]
//
// Each entry's signature must equal Sign(SHA3-256([]byte(peer_id))) produced by
// the network registry private key. Entries with invalid signatures are skipped
// with a warning; the first file-level error (open, parse) is fatal and returned.
// Call this before the node begins accepting connections so the allowlist is
// populated prior to any incoming handshake.
func LoadPeerManifest(path string, gater *AllowlistGater) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("LoadPeerManifest: cannot open %q: %w", path, err)
	}
	defer f.Close()

	var entries []struct {
		PeerID    string `json:"peer_id"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(f).Decode(&entries); err != nil {
		return fmt.Errorf("LoadPeerManifest: cannot parse %q: %w", path, err)
	}

	for _, e := range entries {
		pid, err := peer.Decode(e.PeerID)
		if err != nil {
			log.Printf("LoadPeerManifest: skipping invalid peer_id %q: %v", e.PeerID, err)
			continue
		}
		sigBytes, err := hex.DecodeString(e.Signature)
		if err != nil {
			log.Printf("LoadPeerManifest: skipping peer %q — invalid signature hex: %v", e.PeerID, err)
			continue
		}
		if err := gater.AllowPeer(pid, sigBytes); err != nil {
			log.Printf("LoadPeerManifest: skipping peer %q — %v", e.PeerID, err)
			continue
		}
	}
	return nil
}

// InterceptPeerDial short-circuits outbound dials to unlisted peers early.
func (g *AllowlistGater) InterceptPeerDial(p peer.ID) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if len(g.allowed) == 0 {
		return true // open mode
	}
	_, ok := g.allowed[p]
	return ok
}

// InterceptAddrDial defers to the per-peer check.
func (g *AllowlistGater) InterceptAddrDial(p peer.ID, _ ma.Multiaddr) bool {
	return g.InterceptPeerDial(p)
}

// InterceptAccept allows the TCP accept; peer identity is not yet known.
func (g *AllowlistGater) InterceptAccept(_ network.ConnMultiaddrs) bool {
	return true
}

// InterceptSecured is the primary gate: called after the TLS/Noise handshake
// when the remote peer's identity has been confirmed.
func (g *AllowlistGater) InterceptSecured(_ network.Direction, p peer.ID, _ network.ConnMultiaddrs) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if len(g.allowed) == 0 {
		return true // open mode
	}
	_, ok := g.allowed[p]
	return ok
}

// InterceptUpgraded approves all fully-upgraded connections; gating is done in
// InterceptSecured.
func (g *AllowlistGater) InterceptUpgraded(_ network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}

func (n *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	ctx := n.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := n.host.Connect(ctx, pi); err != nil {
		log.Printf("Failed to connect to mDNS peer: %v", err)
	} else {
		log.Printf("Connected to mDNS peer: %s", pi.ID.String())
	}
}

func setupMdnsDiscovery(ctx context.Context, h host.Host, serviceTag string) (mdns.Service, error) {
	service := mdns.NewMdnsService(h, serviceTag, &mdnsNotifee{ctx: ctx, host: h})
	if service == nil {
		return nil, fmt.Errorf("failed to create mDNS service")
	}
	if err := service.Start(); err != nil {
		return nil, fmt.Errorf("failed to start mDNS service: %v", err)
	}
	log.Printf("mDNS discovery service started (%s)", serviceTag)
	return service, nil
}

func (n *peerReconnectNotifee) Listen(_ network.Network, _ ma.Multiaddr)      {}
func (n *peerReconnectNotifee) ListenClose(_ network.Network, _ ma.Multiaddr) {}
func (n *peerReconnectNotifee) Connected(_ network.Network, _ network.Conn)   {}

func (n *peerReconnectNotifee) Disconnected(_ network.Network, c network.Conn) {
	if n == nil || n.node == nil || n.node.Gater == nil {
		return
	}
	pid := c.RemotePeer()
	if !n.node.Gater.isExplicitlyAllowlisted(pid) {
		return
	}
	n.node.startTrackedBackground(func() {
		n.node.reconnectPeer(pid, c.RemoteMultiaddr())
	})
}

// isExplicitlyAllowlisted returns true only when the peer is present in the
// allowlist map. Unlike InterceptPeerDial, open-mode fallback does not apply.
func (g *AllowlistGater) isExplicitlyAllowlisted(p peer.ID) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	_, ok := g.allowed[p]
	return ok
}

// reconnectPeer retries host-level connect with exponential backoff
// (100ms→...→30s cap, up to 10 attempts).
func (n *P2PNode) reconnectPeer(pid peer.ID, remote ma.Multiaddr) {
	if n == nil || n.Host == nil {
		return
	}
	if _, loaded := n.reconnecting.LoadOrStore(pid.String(), struct{}{}); loaded {
		return
	}
	defer n.reconnecting.Delete(pid.String())

	backoff := 100 * time.Millisecond
	for attempt := 1; attempt <= 10; attempt++ {
		if atomic.LoadInt32(&n.closed) == 1 {
			return
		}

		baseCtx := n.publishCtx()
		if baseCtx.Err() != nil {
			return
		}

		if n.Host.Network().Connectedness(pid) == network.Connected {
			return
		}
		info := n.Host.Peerstore().PeerInfo(pid)
		if info.ID == "" {
			info.ID = pid
		}
		if remote != nil && len(info.Addrs) == 0 {
			info.Addrs = []ma.Multiaddr{remote}
		}

		ctx, cancel := context.WithTimeout(baseCtx, 5*time.Second)
		err := n.Host.Connect(ctx, info)
		cancel()
		if err == nil && n.Host.Network().Connectedness(pid) == network.Connected {
			logger.Infof("Reconnect succeeded for peer %s on attempt %d", pid, attempt)
			return
		}

		t := time.NewTimer(backoff)
		select {
		case <-baseCtx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
	logger.Warnf("Reconnect exhausted for peer %s after 10 attempts", pid)
}

// startTrackedBackground launches fn as a tracked background goroutine unless
// shutdown has already started.
func (n *P2PNode) startTrackedBackground(fn func()) bool {
	if n == nil || fn == nil {
		return false
	}
	n.bgMu.Lock()
	defer n.bgMu.Unlock()
	if atomic.LoadInt32(&n.closed) == 1 {
		return false
	}
	n.bgWg.Add(1)
	go func() {
		defer n.bgWg.Done()
		fn()
	}()
	return true
}

// tunedGossipSubParams derives mesh settings from expected validator count.
// The values are intentionally conservative for small permissioned networks.
func tunedGossipSubParams(validatorCount int) pubsub.GossipSubParams {
	params := pubsub.DefaultGossipSubParams()
	if validatorCount < 5 {
		validatorCount = 5
	}
	d := validatorCount - 1
	if d < 4 {
		d = 4
	}
	if d > 8 {
		d = 8
	}
	params.D = d
	params.Dlo = d - 1
	if params.Dlo < 3 {
		params.Dlo = 3
	}
	params.Dhi = d + 1
	params.Dscore = params.D
	params.Dout = (params.D - 1) / 2
	if params.Dout >= params.Dlo {
		params.Dout = params.Dlo - 1
	}
	if params.Dout < 1 {
		params.Dout = 1
	}
	params.HeartbeatInterval = 500 * time.Millisecond
	return params
}

// NewP2PNode initializes a new libp2p node with mDNS and DHT-based peer discovery
func NewP2PNode(ctx context.Context, blockchain *Blockchain, topicName string, bootstrapPeers []string) (*P2PNode, error) {
	// Create an allowlist gater bound to the blockchain's registry key.
	// When NetworkRegistryKey is nil (dev/test) the gater runs in open mode.
	gater := NewAllowlistGater(blockchain.NetworkRegistryKey)

	// Load a static peer manifest if GREENHOUSE_PEER_MANIFEST is set.
	// This pre-populates the allowlist from a signed JSON manifest before the
	// node begins accepting connections, ensuring no unlisted peer can connect
	// before the manifest is applied.
	if manifestPath := os.Getenv("GREENHOUSE_PEER_MANIFEST"); manifestPath != "" {
		if err := LoadPeerManifest(manifestPath, gater); err != nil {
			return nil, fmt.Errorf("NewP2PNode: failed to load peer manifest %q: %w", manifestPath, err)
		}
		logger.Infof("Loaded peer manifest from %s", manifestPath)
	}

	// Create a bounded connection manager so peers cannot exhaust file
	// descriptors by opening unbounded simultaneous connections.
	cm, err := connmgr.NewConnManager(20, 40, connmgr.WithGracePeriod(time.Minute))
	if err != nil {
		return nil, fmt.Errorf("failed to create connection manager: %v", err)
	}

	// Create a new libp2p host with connection gater + bounded conn manager.
	h, err := libp2p.New(
		libp2p.Security(noise.ID, noise.New),
		libp2p.ConnectionGater(gater),
		libp2p.ConnectionManager(cm),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %v", err)
	}
	logger.Infof("Libp2p host created with ID: %s", h.ID())
	log.Printf("P2P: using Noise XX security transport (mutual auth)")

	// Log listening addresses
	for _, addr := range h.Addrs() {
		logger.Infof("Listening on: %s/p2p/%s", addr.String(), h.ID().String())
	}

	// Production guard (Item 17): DHT discovery is disabled in production.
	// The node relies solely on the static peer manifest for bootstrap. Fail
	// fast here — before any goroutine is launched — if no manifest was set.
	if os.Getenv("GH_ENV") == "production" && os.Getenv("GREENHOUSE_PEER_MANIFEST") == "" {
		return nil, fmt.Errorf("production: GREENHOUSE_PEER_MANIFEST must be set (DHT discovery is disabled in production)")
	}

	// bgCtx/bgCancel: used by the DHT background goroutine (dev/test only).
	// Always initialised so that Shutdown can call cancelBackground()
	// unconditionally regardless of whether DHT is active.
	bgCtx, bgCancel := context.WithCancel(ctx)
	// If NewP2PNode returns an error, cancel bgCtx so any goroutine exits.
	committed := false
	defer func() {
		if !committed {
			if h != nil {
				if err := h.Close(); err != nil {
					logger.Warnf("NewP2PNode cleanup: failed to close host: %v", err)
				}
			}
			bgCancel()
		}
	}()

	var dht *kaddht.IpfsDHT

	if os.Getenv("GH_ENV") != "production" && os.Getenv("GONETWORK_DISABLE_P2P_DHT") != "1" {
		// Initialize the DHT in client mode for peer discovery.
		// Client mode means this node only queries the DHT and never accepts
		// routing table entries from unknown peers, eliminating the Sybil
		// attack surface described in GO-2024-3218. The bootstrap node
		// (cmd/bootstrap) runs in ModeServer and is the sole authoritative
		// DHT server.
		dht, err = kaddht.New(ctx, h, kaddht.Mode(kaddht.ModeClient))
		if err != nil {
			return nil, fmt.Errorf("failed to create DHT: %v", err)
		}
		logger.Infof("DHT initialized in client mode for peer discovery")

		// Bootstrap the DHT with the provided bootstrap peers
		for _, addr := range bootstrapPeers {
			logger.Infof("Attempting to connect to bootstrap peer: %s", addr)
			peerAddr, err := peer.AddrInfoFromString(addr)
			if err != nil {
				logger.Warnf("Invalid bootstrap peer address: %s", addr)
				continue
			}
			if err := h.Connect(bgCtx, *peerAddr); err != nil {
				logger.Warnf("Failed to connect to bootstrap peer: %s", addr)
			} else {
				logger.Infof("Connected to bootstrap peer: %s", addr)
			}
		}

	} else if os.Getenv("GH_ENV") == "production" {
		logger.Infof("DHT discovery disabled in production (GH_ENV=production)")
	} else {
		logger.Infof("DHT discovery disabled (GONETWORK_DISABLE_P2P_DHT=1)")
	}

	// Create a tuned GossipSub service for validator-sized meshes.
	validatorCount := len(blockchain.Delegates)
	if validatorCount == 0 {
		validatorCount = 5 // default expected validator set size in dev/test
	}
	gsParams := tunedGossipSubParams(validatorCount)
	ps, err := pubsub.NewGossipSub(
		ctx,
		h,
		pubsub.WithMaxMessageSize(256*1024),
		pubsub.WithFloodPublish(true),
		pubsub.WithGossipSubParams(gsParams),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub: %v", err)
	}
	logger.Infof("PubSub service initialized (D=%d Dlo=%d Dhi=%d heartbeat=%s)", gsParams.D, gsParams.Dlo, gsParams.Dhi, gsParams.HeartbeatInterval)

	// Join a topic
	topic, err := ps.Join(topicName)
	if err != nil {
		return nil, fmt.Errorf("failed to join topic: %v", err)
	}
	logger.Infof("Joined topic: %s", topicName)

	consensusTopicName := topicName + "/consensus"
	consensusTopic, err := ps.Join(consensusTopicName)
	if err != nil {
		return nil, fmt.Errorf("failed to join consensus topic: %v", err)
	}
	logger.Infof("Joined consensus topic: %s", consensusTopicName)

	// Register a topic validator so that GossipSub rejects messages from
	// peers that are not in the allowlist. This closes the gap where a peer
	// that obtained a connection (or was never connection-gated in open mode)
	// could inject arbitrary payloads to all validators.
	// In open mode (gater.allowed is empty) InterceptPeerDial returns true for
	// all peers, so the validator accepts all messages — behaviour is unchanged
	// for development and test environments.
	if err := ps.RegisterTopicValidator(topicName, func(_ context.Context, pid peer.ID, _ *pubsub.Message) pubsub.ValidationResult {
		if !gater.InterceptPeerDial(pid) {
			return pubsub.ValidationReject
		}
		return pubsub.ValidationAccept
	}); err != nil {
		return nil, fmt.Errorf("failed to register topic validator: %w", err)
	}
	logger.Infof("Topic validator registered for %s", topicName)

	if err := ps.RegisterTopicValidator(consensusTopicName, func(_ context.Context, pid peer.ID, _ *pubsub.Message) pubsub.ValidationResult {
		if !gater.InterceptPeerDial(pid) {
			return pubsub.ValidationReject
		}
		return pubsub.ValidationAccept
	}); err != nil {
		return nil, fmt.Errorf("failed to register consensus topic validator: %w", err)
	}
	logger.Infof("Topic validator registered for %s", consensusTopicName)

	// Subscribe to the topic
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to topic: %v", err)
	}
	logger.Infof("Subscribed to topic")

	consensusSub, err := consensusTopic.Subscribe()
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to consensus topic: %v", err)
	}
	logger.Infof("Subscribed to consensus topic")

	// Enable mDNS for same-machine / LAN peer discovery before creating the
	// node so the service reference can be stored (prevents GC and keeps it live).
	// M-10: mDNS is only enabled outside production to avoid advertising
	// node addresses on the local LAN in production deployments.
	var mdnsSvc mdns.Service
	if os.Getenv("GH_ENV") != "production" && os.Getenv("GONETWORK_DISABLE_P2P_MDNS") != "1" {
		sanitizedTopic := strings.NewReplacer("/", "-", " ", "-").Replace(topicName)
		mdnsTag := "greenhouse-mdns-" + sanitizedTopic
		mdnsSvc, err = setupMdnsDiscovery(bgCtx, h, mdnsTag)
		if err != nil {
			logger.Warnf("mDNS discovery unavailable: %v", err)
		}
	} else if os.Getenv("GH_ENV") == "production" {
		logger.Infof("mDNS discovery disabled in production (GH_ENV=production)")
	} else {
		logger.Infof("mDNS discovery disabled (GONETWORK_DISABLE_P2P_MDNS=1)")
	}

	// Create and return the P2PNode
	node := &P2PNode{
		Host:             h,
		PubSub:           ps,
		Topic:            topic,
		Sub:              sub,
		ConsensusTopic:   consensusTopic,
		ConsensusSub:     consensusSub,
		Blockchain:       blockchain,
		MdnsService:      mdnsSvc,
		Gater:            gater,
		limiter:          rate.NewLimiter(rate.Every(100*time.Millisecond), 10),
		cancelBackground: bgCancel,
		bgCtx:            bgCtx,
	}

	// Bootstrap the DHT and discover peers asynchronously in the background.
	// bgCtx is derived from the caller context and is cancelled by Shutdown,
	// so the goroutine terminates when the node is shut down.
	if dht != nil {
		node.startTrackedBackground(func() {

			// Retry connecting to bootstrap peers
			if len(bootstrapPeers) > 0 {
				retryCount := 0
				maxRetries := 10
				for len(h.Network().Peers()) == 0 && retryCount < maxRetries {
					logger.Debugf("Waiting for peers in the routing table... (attempt %d/%d)", retryCount+1, maxRetries)
					select {
					case <-bgCtx.Done():
						return
					case <-time.After(2 * time.Second):
					}
					retryCount++
				}
				logger.Infof("Current peers in the network: %v", h.Network().Peers())
			}

			if err := dht.Bootstrap(bgCtx); err != nil {
				logger.Warnf("Failed to bootstrap DHT: %v", err)
				return
			}
			logger.Infof("DHT bootstrapped successfully")

			// Give DHT time to populate routing table
			select {
			case <-bgCtx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			peersCount := len(dht.RoutingTable().ListPeers())
			logger.Infof("DHT routing table now has %d peers", peersCount)

			// Advertise the rendezvous point
			rendezvous := "greenhouse-p2p-network"
			logger.Infof("Advertising rendezvous point: %s", rendezvous)

			// Generate a valid CID from the rendezvous string
			hash := sha256.Sum256([]byte(rendezvous))
			mh, err := multihash.Encode(hash[:], multihash.SHA2_256)
			if err != nil {
				logger.Warnf("Failed to create multihash for rendezvous: %v", err)
				return
			}
			rendezvousCID := cid.NewCidV1(cid.Raw, mh)

			if err := dht.Provide(bgCtx, rendezvousCID, true); err != nil {
				logger.Warnf("Failed to advertise rendezvous point: %v", err)
			} else {
				logger.Infof("Rendezvous point advertised successfully")
			}

			// Discover peers advertising the same rendezvous point
			for {
				if bgCtx.Err() != nil {
					return // node is shutting down
				}
				peers, err := dht.FindProviders(bgCtx, rendezvousCID)
				if err != nil {
					logger.Debugf("Error finding providers: %v", err)
				} else {
					for _, p := range peers {
						if p.ID != h.ID() {
							logger.Infof("Discovered peer: %s", p.ID.String())
							if err := h.Connect(bgCtx, p); err != nil {
								logger.Debugf("Failed to connect to peer %s: %v", p.ID.String(), err)
							} else {
								logger.Infof("Successfully connected to peer: %s", p.ID.String())
							}
						}
					}
				}
				select {
				case <-bgCtx.Done():
					return
				case <-time.After(5 * time.Second):
				}
			}
		})
	}

	// Register reconnect notifee (Item 19 Step B).
	h.Network().Notify(&peerReconnectNotifee{node: node})

	// Set a stream handler for direct messaging
	h.SetStreamHandler("/p2p/1.0.0", node.handleStream)
	logger.Infof("Stream handler set for direct messaging")

	committed = true
	return node, nil
}

func (n *P2PNode) BroadcastAllowlistTransaction(at AllowlistTransaction) error {
	if n == nil || n.Topic == nil {
		return fmt.Errorf("P2PNode or Topic is not initialized")
	}
	if err := n.ensureOpen(); err != nil {
		return err
	}
	payload, err := json.Marshal(at)
	if err != nil {
		return fmt.Errorf("failed to serialize allowlist transaction: %w", err)
	}
	msgType := MessageTypeAllowlistAdd
	if at.Action == "revoke" {
		msgType = MessageTypeAllowlistRevoke
	}
	message := P2PMessage{Type: msgType, Payload: payload}
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to serialize P2PMessage: %w", err)
	}
	return n.Topic.Publish(n.publishCtx(), data)
}

// PublishConsensusMessage sends a dBFT coordination message to the dedicated
// consensus sub-topic (Item 19 Step D).
func (n *P2PNode) PublishConsensusMessage(msg Message) error {
	if n == nil || n.ConsensusTopic == nil {
		return fmt.Errorf("P2PNode or ConsensusTopic is not initialized")
	}
	if err := n.ensureOpen(); err != nil {
		return err
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to serialize consensus message: %w", err)
	}
	return n.ConsensusTopic.Publish(n.publishCtx(), data)
}

func (n *P2PNode) BroadcastPing(ctx context.Context) error {
	if n == nil || n.Topic == nil {
		return fmt.Errorf("P2PNode or Topic is not initialized")
	}
	if err := n.ensureOpen(); err != nil {
		return err
	}
	message := P2PMessage{Type: MessageTypePing, Payload: []byte("ping")}
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to serialize ping: %v", err)
	}
	if ctx == nil {
		ctx = n.publishCtx()
	}
	return n.Topic.Publish(ctx, data)
}

func (n *P2PNode) BroadcastTransaction(tx Transaction) error {
	if n == nil || n.Topic == nil {
		return fmt.Errorf("P2PNode or Topic is not initialized")
	}
	if err := n.ensureOpen(); err != nil {
		return err
	}
	if n.limiter != nil {
		if err := n.limiter.Wait(n.publishCtx()); err != nil {
			return fmt.Errorf("broadcast transaction rate-limited: %w", err)
		}
	}

	// Serialize the transaction
	txData, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to serialize transaction: %v", err)
	}

	// Wrap in a P2PMessage
	message := P2PMessage{
		Type:    "transaction",
		Payload: txData,
	}

	// Serialize the P2PMessage
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to serialize P2PMessage: %v", err)
	}

	// Publish the message to the topic
	return n.Topic.Publish(n.publishCtx(), data)
}

func (n *P2PNode) BroadcastBlock(block Block) error {
	if n == nil || n.Topic == nil {
		return fmt.Errorf("P2PNode or Topic is not initialized")
	}
	if err := n.ensureOpen(); err != nil {
		return err
	}
	if n.limiter != nil {
		if err := n.limiter.Wait(n.publishCtx()); err != nil {
			return fmt.Errorf("broadcast block rate-limited: %w", err)
		}
	}

	// Serialize the block
	blockData, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to serialize block: %v", err)
	}

	// Wrap in a P2PMessage
	message := P2PMessage{
		Type:    "block",
		Payload: blockData,
	}

	// Serialize the P2PMessage
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to serialize P2PMessage: %v", err)
	}

	// Publish the message to the topic
	return n.Topic.Publish(n.publishCtx(), data)
}

func (n *P2PNode) BroadcastAssetTransaction(at AssetTransaction) error {
	if n == nil || n.Topic == nil {
		return fmt.Errorf("P2PNode or Topic is not initialized")
	}
	if err := n.ensureOpen(); err != nil {
		return err
	}
	payload, err := json.Marshal(at)
	if err != nil {
		return fmt.Errorf("failed to serialize asset transaction: %w", err)
	}
	message := P2PMessage{Type: MessageTypeAssetTransaction, Payload: payload}
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to serialize P2PMessage: %w", err)
	}
	return n.Topic.Publish(n.publishCtx(), data)
}

func (n *P2PNode) BroadcastCredential(ct CredentialTransaction) error {
	if n == nil || n.Topic == nil {
		return fmt.Errorf("P2PNode or Topic is not initialized")
	}
	if err := n.ensureOpen(); err != nil {
		return err
	}
	payload, err := json.Marshal(ct)
	if err != nil {
		return fmt.Errorf("failed to serialize credential transaction: %w", err)
	}
	message := P2PMessage{Type: MessageTypeCredential, Payload: payload}
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to serialize P2PMessage: %w", err)
	}
	return n.Topic.Publish(n.publishCtx(), data)
}

func (n *P2PNode) BroadcastPaymentConfirmation(pc PaymentConfirmation) error {
	if n == nil || n.Topic == nil {
		return fmt.Errorf("P2PNode or Topic is not initialized")
	}
	if err := n.ensureOpen(); err != nil {
		return err
	}
	payload, err := json.Marshal(pc)
	if err != nil {
		return fmt.Errorf("failed to serialize payment confirmation: %w", err)
	}
	message := P2PMessage{Type: MessageTypePaymentConfirmation, Payload: payload}
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to serialize P2PMessage: %w", err)
	}
	return n.Topic.Publish(n.publishCtx(), data)
}

func (n *P2PNode) HandleMessages(ctx context.Context) {
	if n != nil && n.ConsensusSub != nil {
		go n.handleConsensusMessages(ctx)
	}

	for {
		// Sub.Next blocks until a message arrives, the context is cancelled,
		// or Sub.Cancel() is called (which closes the internal channel and
		// returns "subscription cancelled"). Any error is a permanent stop
		// signal — there are no transient errors from Sub.Next.
		msg, err := n.Sub.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				log.Println("Stopping message handling (context done).")
			} else {
				log.Printf("Stopping message handling (subscription error): %v", err)
			}
			return
		}

		if msg.ReceivedFrom == n.Host.ID() {
			continue
		}

		// Drop messages from peers that have been revoked since the connection
		// was established. The topic validator catches new messages at the
		// GossipSub layer, but in-flight messages may slip through the narrow
		// window between revocation and GossipSub validator propagation.
		if !n.Gater.InterceptPeerDial(msg.ReceivedFrom) {
			continue
		}

		// Deserialize the P2PMessage
		var p2pMessage P2PMessage
		if err := json.Unmarshal(msg.Data, &p2pMessage); err != nil {
			log.Printf("Failed to deserialize P2PMessage: %v", err)
			continue
		}

		// Process the message based on its type
		switch p2pMessage.Type {
		case MessageTypeTransaction:
			var tx Transaction
			if err := json.Unmarshal(p2pMessage.Payload, &tx); err != nil {
				log.Printf("Failed to deserialize transaction: %v", err)
				continue
			}
			log.Printf("Received transaction: %+v", tx)
			n.Blockchain.AddTransaction(tx)

		case MessageTypeBlock:
			var block Block
			if err := json.Unmarshal(p2pMessage.Payload, &block); err != nil {
				log.Printf("Failed to deserialize block: %v", err)
				continue
			}
			log.Printf("Received block: %+v", block)
			// Validate and append under the write lock, but do NOT call
			// AddBlock (which broadcasts) while holding the lock — a slow
			// network publish would deadlock the entire chain. Instead we
			// do the state mutation inline (same as AddBlock minus broadcast).
			n.Blockchain.Mu.Lock()
			if n.Blockchain.ValidateBlock(block) {
				if len(n.Blockchain.Blocks) > 0 {
					block.PrevHash = n.Blockchain.Blocks[len(n.Blockchain.Blocks)-1].CalculateHash()
				} else {
					block.PrevHash = strings.Repeat("0", 64)
				}
				block.Index = len(n.Blockchain.Blocks)
				block.Nonce = n.Blockchain.Nonce
				block.SetPayloadHash()
				n.Blockchain.Blocks = append(n.Blockchain.Blocks, block)
				n.Blockchain.Nonce++
			}
			n.Blockchain.Mu.Unlock()

		case MessageTypeAck:
			log.Println("Received acknowledgment message")

		case MessageTypePing:
			log.Println("Received ping message")
			ackMessage := P2PMessage{
				Type:    MessageTypeAck,
				Payload: []byte("pong"),
			}
			data, _ := json.Marshal(ackMessage)
			n.Topic.Publish(ctx, data)

		case MessageTypeAssetTransaction:
			var at AssetTransaction
			if err := json.Unmarshal(p2pMessage.Payload, &at); err != nil {
				log.Printf("Failed to deserialize asset transaction: %v", err)
				continue
			}
			n.Blockchain.Mu.Lock()
			if err := at.Validate(n.Blockchain, n.Blockchain.Assets, n.Blockchain.Holdings, n.Blockchain.Credentials, n.Blockchain.PendingCorporateActions, n.Blockchain.AMLScreener); err == nil {
				n.Blockchain.PendingAssetTransactions = append(n.Blockchain.PendingAssetTransactions, at)
			} else {
				log.Printf("Received invalid asset transaction: %v", err)
			}
			n.Blockchain.Mu.Unlock()

		case MessageTypeCredential:
			var ct CredentialTransaction
			if err := json.Unmarshal(p2pMessage.Payload, &ct); err != nil {
				log.Printf("Failed to deserialize credential transaction: %v", err)
				continue
			}
			// Credentials are registry-signed — apply directly on receipt.
			n.Blockchain.Mu.Lock()
			if ct.Attestation.IsValid() {
				n.Blockchain.Credentials[ct.Attestation.WalletPublicKey] = &ct.Attestation
			}
			n.Blockchain.Mu.Unlock()

		case MessageTypePaymentConfirmation:
			var pc PaymentConfirmation
			if err := json.Unmarshal(p2pMessage.Payload, &pc); err != nil {
				log.Printf("Failed to deserialize payment confirmation: %v", err)
				continue
			}
			n.Blockchain.Mu.Lock()
			if n.Blockchain.OracleService.VerifyConfirmation(&pc) {
				n.Blockchain.ConfirmedPayments[pc.InstructionID] = &pc
			}
			n.Blockchain.Mu.Unlock()

		case MessageTypeAllowlistAdd:
			var at AllowlistTransaction
			if err := json.Unmarshal(p2pMessage.Payload, &at); err != nil {
				log.Printf("Failed to deserialize allowlist transaction: %v", err)
				continue
			}
			if n.Gater != nil {
				pid, err := peer.Decode(at.PeerID)
				if err != nil {
					log.Printf("Rejected allowlist_add with invalid peer ID %q: %v", at.PeerID, err)
					continue
				}
				if err := n.Gater.AllowPeer(pid, at.Signature); err != nil {
					log.Printf("Rejected allowlist_add for peer %s: %v", at.PeerID, err)
				}
			}

		case MessageTypeAllowlistRevoke:
			var at AllowlistTransaction
			if err := json.Unmarshal(p2pMessage.Payload, &at); err != nil {
				log.Printf("Failed to deserialize allowlist transaction: %v", err)
				continue
			}
			if n.Gater != nil {
				pid, err := peer.Decode(at.PeerID)
				if err != nil {
					log.Printf("Rejected allowlist_revoke with invalid peer ID %q: %v", at.PeerID, err)
					continue
				}
				if err := n.Gater.RevokePeer(pid, at.Signature); err != nil {
					log.Printf("Rejected allowlist_revoke for peer %s: %v", at.PeerID, err)
				}
			}

		default:
			log.Printf("Unknown message type: %s", p2pMessage.Type)
		}
	}
}

func (n *P2PNode) handleConsensusMessages(ctx context.Context) {
	for {
		msg, err := n.ConsensusSub.Next(ctx)
		if err != nil {
			return
		}
		if msg.ReceivedFrom == n.Host.ID() {
			continue
		}
		if !n.Gater.InterceptPeerDial(msg.ReceivedFrom) {
			continue
		}

		var consensusMsg Message
		if err := json.Unmarshal(msg.Data, &consensusMsg); err != nil {
			log.Printf("Failed to deserialize consensus Message: %v", err)
			continue
		}

		n.Blockchain.Mu.RLock()
		for i := range n.Blockchain.Delegates {
			d := &n.Blockchain.Delegates[i]
			if consensusMsg.To != "" && d.ID != consensusMsg.To {
				continue
			}
			d.ReceiveMessage(consensusMsg)
		}
		n.Blockchain.Mu.RUnlock()
	}
}

func (n *P2PNode) SendMessage(peerID string, message string) error {
	var peerInfo peer.AddrInfo
	var err error

	// Try to parse the input as a full multiaddress
	if addrInfo, err := peer.AddrInfoFromString(peerID); err == nil {
		peerInfo = *addrInfo
	} else {
		// If parsing fails, assume it's a plain peer ID and try to resolve it
		log.Printf("Input is not a full multiaddress, attempting to resolve peer ID: %s", peerID)
		peerIDObj, err := peer.Decode(peerID)
		if err != nil {
			return fmt.Errorf("invalid peer ID: %v", err)
		}

		// Check if the peer is in the host's peer store
		peerInfo = n.Host.Peerstore().PeerInfo(peerIDObj)
		if len(peerInfo.Addrs) == 0 {
			return fmt.Errorf("peer ID %s not found in peer store; ensure the peer is reachable", peerID)
		}
	}

	// Connect to the peer
	if err := n.Host.Connect(n.publishCtx(), peerInfo); err != nil {
		return fmt.Errorf("failed to connect to peer %s: %v", peerInfo.ID, err)
	}

	// Open a stream
	stream, err := n.Host.NewStream(n.publishCtx(), peerInfo.ID, "/p2p/1.0.0")
	if err != nil {
		return fmt.Errorf("failed to open stream to peer %s: %v", peerInfo.ID, err)
	}
	defer stream.Close()

	// Send the message
	_, err = stream.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to send message to peer %s: %v", peerInfo.ID, err)
	}

	log.Printf("Message sent successfully to peer %s", peerInfo.ID)
	return nil
}

func (n *P2PNode) SendPing(peerID string) error {
	if n == nil || n.Topic == nil {
		return fmt.Errorf("P2PNode or Topic is not initialized")
	}
	if err := n.ensureOpen(); err != nil {
		return err
	}
	pingMessage := P2PMessage{
		Type:    MessageTypePing,
		Payload: []byte("ping"),
	}

	data, err := json.Marshal(pingMessage)
	if err != nil {
		return fmt.Errorf("failed to serialize ping message: %v", err)
	}

	return n.Topic.Publish(n.publishCtx(), data)
}

func (n *P2PNode) SendAck(peerID string) error {
	if n == nil || n.Topic == nil {
		return fmt.Errorf("P2PNode or Topic is not initialized")
	}
	if err := n.ensureOpen(); err != nil {
		return err
	}
	ackMessage := P2PMessage{
		Type:    MessageTypeAck,
		Payload: []byte("ack"),
	}

	data, err := json.Marshal(ackMessage)
	if err != nil {
		return fmt.Errorf("failed to serialize acknowledgment message: %v", err)
	}

	return n.Topic.Publish(n.publishCtx(), data)
}

func (n *P2PNode) ensureOpen() error {
	if n == nil {
		return fmt.Errorf("P2PNode is nil")
	}
	if atomic.LoadInt32(&n.closed) == 1 {
		return ErrNodeShutdown
	}
	return nil
}

func (n *P2PNode) publishCtx() context.Context {
	if n != nil && n.bgCtx != nil {
		return n.bgCtx
	}
	return context.Background()
}

func (n *P2PNode) handleStream(stream network.Stream) {
	defer stream.Close()

	buf := make([]byte, 1024)
	bytesRead, err := stream.Read(buf)
	if err != nil {
		log.Printf("Error reading from stream: %v", err)
		return
	}

	log.Printf("Received direct message: %s", string(buf[:bytesRead]))
}

func (n *P2PNode) Shutdown(ctx context.Context) error {
	if n == nil {
		log.Println("P2PNode is nil, skipping shutdown.")
		return nil
	}

	log.Println("Shutting down P2PNode...")
	atomic.StoreInt32(&n.closed, 1)
	// Establish the wait boundary after closing the registration gate.
	n.bgMu.Lock()
	n.bgMu.Unlock()

	// Cancel the background DHT discovery goroutine first so it stops
	// polling and making network calls before we tear down the host.
	if n.cancelBackground != nil {
		n.cancelBackground()
	}
	// Wait for DHT bootstrap/discovery goroutine to exit before closing host.
	n.bgWg.Wait()

	// Cancel the PubSub subscription
	if n.Sub != nil {
		log.Println("Closing PubSub subscription...")
		n.Sub.Cancel() // No error handling needed
	}
	if n.ConsensusSub != nil {
		log.Println("Closing consensus PubSub subscription...")
		n.ConsensusSub.Cancel()
	}

	// Close the PubSub topic
	if n.Topic != nil {
		log.Println("Closing PubSub topic...")
		if err := n.Topic.Close(); err != nil {
			log.Printf("Error closing PubSub topic: %v", err)
		}
	}
	if n.ConsensusTopic != nil {
		log.Println("Closing consensus PubSub topic...")
		if err := n.ConsensusTopic.Close(); err != nil {
			log.Printf("Error closing consensus PubSub topic: %v", err)
		}
	}

	// Stop the mDNS discovery service before closing the host so that its
	// background goroutine (zeroconf probe/announce) is not leaked.
	if n.MdnsService != nil {
		log.Println("Closing mDNS service...")
		if err := n.MdnsService.Close(); err != nil {
			log.Printf("Error closing mDNS service: %v", err)
		}
	}

	// Close the libp2p host
	if n.Host != nil {
		log.Println("Closing libp2p host...")
		if err := n.Host.Close(); err != nil {
			log.Printf("Error closing libp2p host: %v", err)
		}
	}

	log.Println("P2PNode shutdown complete.")
	return nil
}
