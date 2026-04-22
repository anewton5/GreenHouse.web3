package gonetwork

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"crypto/sha256"

	"github.com/ipfs/go-cid"
	golog "github.com/ipfs/go-log/v2"
	libp2p "github.com/libp2p/go-libp2p"
	kaddht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/multiformats/go-multihash"
)

var logger = golog.Logger("p2pnode")

func init() {
	// Enable debug logging for the "p2pnode" logger
	golog.SetLogLevel("p2pnode", "debug")
}

type P2PNode struct {
	Host        host.Host
	PubSub      *pubsub.PubSub
	Topic       *pubsub.Topic
	Sub         *pubsub.Subscription
	Blockchain  *Blockchain
	MdnsService mdns.Service // Store the mDNS service
}

type mdnsNotifee struct {
	host host.Host
}

const (
	MessageTypeTransaction = "transaction"
	MessageTypeBlock       = "block"
	MessageTypeAck         = "ack"
	MessageTypePing        = "ping"
)

type P2PMessage struct {
	Type    string `json:"type"`    // Message type (e.g., "transaction", "block")
	Payload []byte `json:"payload"` // Serialized payload
}

func (n *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if err := n.host.Connect(context.Background(), pi); err != nil {
		log.Printf("Failed to connect to mDNS peer: %v", err)
	} else {
		log.Printf("Connected to mDNS peer: %s", pi.ID.String())
	}
}

func setupMdnsDiscovery(h host.Host) error {
	service := mdns.NewMdnsService(h, "greenhouse-mdns", &mdnsNotifee{host: h})
	if service == nil {
		return fmt.Errorf("failed to start mDNS discovery: service is nil")
	}
	log.Println("mDNS discovery service started")
	return nil
}

// NewP2PNode initializes a new libp2p node with mDNS and DHT-based peer discovery
func NewP2PNode(ctx context.Context, blockchain *Blockchain, topicName string, bootstrapPeers []string) (*P2PNode, error) {
	// Create a new libp2p host with default options
	h, err := libp2p.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %v", err)
	}
	logger.Infof("Libp2p host created with ID: %s", h.ID())

	// Initialize the DHT for global peer discovery
	dht, err := kaddht.New(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHT: %v", err)
	}
	logger.Infof("DHT initialized for peer discovery")

	// Log listening addresses
	for _, addr := range h.Addrs() {
		logger.Infof("Listening on: %s/p2p/%s", addr.String(), h.ID().String())
	}

	// Bootstrap the DHT with the provided bootstrap peers
	for _, addr := range bootstrapPeers {
		logger.Infof("Attempting to connect to bootstrap peer: %s", addr)
		peerAddr, err := peer.AddrInfoFromString(addr)
		if err != nil {
			logger.Warnf("Invalid bootstrap peer address: %s", addr)
			continue
		}
		if err := h.Connect(ctx, *peerAddr); err != nil {
			logger.Warnf("Failed to connect to bootstrap peer: %s", addr)
		} else {
			logger.Infof("Connected to bootstrap peer: %s", addr)
		}
	}

	// Bootstrap the DHT and discover peers asynchronously in the background
	go func() {
		// Retry connecting to bootstrap peers
		if len(bootstrapPeers) > 0 {
			retryCount := 0
			maxRetries := 10
			for len(h.Network().Peers()) == 0 && retryCount < maxRetries {
				logger.Debugf("Waiting for peers in the routing table... (attempt %d/%d)", retryCount+1, maxRetries)
				time.Sleep(2 * time.Second)
				retryCount++
			}
			logger.Infof("Current peers in the network: %v", h.Network().Peers())
		}

		if err := dht.Bootstrap(ctx); err != nil {
			logger.Warnf("Failed to bootstrap DHT: %v", err)
			return
		}
		logger.Infof("DHT bootstrapped successfully")

		// Give DHT time to populate routing table
		time.Sleep(5 * time.Second)
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

		if err := dht.Provide(ctx, rendezvousCID, true); err != nil {
			logger.Warnf("Failed to advertise rendezvous point: %v", err)
		} else {
			logger.Infof("Rendezvous point advertised successfully")
		}

		// Discover peers advertising the same rendezvous point
		for {
			peers, err := dht.FindProviders(ctx, rendezvousCID)
			if err != nil {
				logger.Debugf("Error finding providers: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}
			for _, p := range peers {
				if p.ID != h.ID() {
					logger.Infof("Discovered peer: %s", p.ID.String())
					if err := h.Connect(ctx, p); err != nil {
						logger.Debugf("Failed to connect to peer %s: %v", p.ID.String(), err)
					} else {
						logger.Infof("Successfully connected to peer: %s", p.ID.String())
					}
				}
			}
			time.Sleep(5 * time.Second) // Poll every 5 seconds
		}
	}()

	// Create a new PubSub service IMMEDIATELY (non-blocking initialization)
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub: %v", err)
	}
	logger.Infof("PubSub service initialized")

	// Join a topic
	topic, err := ps.Join(topicName)
	if err != nil {
		return nil, fmt.Errorf("failed to join topic: %v", err)
	}
	logger.Infof("Joined topic: %s", topicName)

	// Subscribe to the topic
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to topic: %v", err)
	}
	logger.Infof("Subscribed to topic")

	// Create and return the P2PNode
	node := &P2PNode{
		Host:        h,
		PubSub:      ps,
		Topic:       topic,
		Sub:         sub,
		Blockchain:  blockchain,
		MdnsService: nil, // mDNS is removed, no service is provided
	}

	// Set a stream handler for direct messaging
	h.SetStreamHandler("/p2p/1.0.0", node.handleStream)
	logger.Infof("Stream handler set for direct messaging")

	return node, nil
}

func (n *P2PNode) BroadcastTransaction(tx Transaction) error {
	if n == nil || n.Topic == nil {
		return fmt.Errorf("P2PNode or Topic is not initialized")
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
	return n.Topic.Publish(context.Background(), data)
}

func (n *P2PNode) BroadcastBlock(block Block) error {
	if n == nil || n.Topic == nil {
		return fmt.Errorf("P2PNode or Topic is not initialized")
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
	return n.Topic.Publish(context.Background(), data)
}

func (n *P2PNode) HandleMessages(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			log.Println("Stopping message handling.")
			return
		default:
			msg, err := n.Sub.Next(ctx)
			if err != nil {
				log.Printf("Error reading message: %v", err)
				continue
			}

			if msg.ReceivedFrom == n.Host.ID() {
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
				if n.Blockchain.ValidateBlock(block) {
					n.Blockchain.AddBlock(block.Transactions, block.Signatures)
				}

			case MessageTypeAck:
				log.Println("Received acknowledgment message")

			case MessageTypePing:
				log.Println("Received ping message")
				// Optionally, send an acknowledgment back
				ackMessage := P2PMessage{
					Type:    MessageTypeAck,
					Payload: []byte("pong"),
				}
				data, _ := json.Marshal(ackMessage)
				n.Topic.Publish(ctx, data)

			default:
				log.Printf("Unknown message type: %s", p2pMessage.Type)
			}
		}
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
	if err := n.Host.Connect(context.Background(), peerInfo); err != nil {
		return fmt.Errorf("failed to connect to peer %s: %v", peerInfo.ID, err)
	}

	// Open a stream
	stream, err := n.Host.NewStream(context.Background(), peerInfo.ID, "/p2p/1.0.0")
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
	pingMessage := P2PMessage{
		Type:    MessageTypePing,
		Payload: []byte("ping"),
	}

	data, err := json.Marshal(pingMessage)
	if err != nil {
		return fmt.Errorf("failed to serialize ping message: %v", err)
	}

	return n.Topic.Publish(context.Background(), data)
}

func (n *P2PNode) SendAck(peerID string) error {
	ackMessage := P2PMessage{
		Type:    MessageTypeAck,
		Payload: []byte("ack"),
	}

	data, err := json.Marshal(ackMessage)
	if err != nil {
		return fmt.Errorf("failed to serialize acknowledgment message: %v", err)
	}

	return n.Topic.Publish(context.Background(), data)
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

	// Cancel the PubSub subscription
	if n.Sub != nil {
		log.Println("Closing PubSub subscription...")
		n.Sub.Cancel() // No error handling needed
	}

	// Close the PubSub topic
	if n.Topic != nil {
		log.Println("Closing PubSub topic...")
		if err := n.Topic.Close(); err != nil {
			log.Printf("Error closing PubSub topic: %v", err)
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
