# GreenHouse P2P Networking Guide

## Table of Contents
1. [What is the GreenHouse Network?](#1-what-is-the-greenhouse-network)
2. [What is P2P Multi-Node Networking?](#2-what-is-p2p-multi-node-networking)
3. [How the GreenHouse Network Works](#3-how-the-greenhouse-network-works)
4. [Network Architecture & Components](#4-network-architecture--components)
5. [Setting Up Your First Node](#5-setting-up-your-first-node)
6. [Local Multi-Node Testing](#6-local-multi-node-testing)
7. [Cross-Network (Internet) Testing](#7-cross-network-internet-testing)
8. [Interacting With the Network](#8-interacting-with-the-network)
9. [Running Tests](#9-running-tests)
10. [Troubleshooting](#10-troubleshooting)
11. [Reference: Message Types & Node API](#11-reference-message-types--node-api)

---

## 1. What is the GreenHouse Network?

GreenHouse is a **decentralised blockchain network** implemented in Go using `go-libp2p`. It combines several technologies:

- A **blockchain** ledger for recording transactions and blocks
- A **P2P network layer** for nodes to find each other and communicate
- A **dBFT consensus mechanism** (Delegated Byzantine Fault Tolerant) for agreeing on new blocks
- A **wallet system** with multi-signature support and locked-currency staking for governance
- **Sharding** for parallel transaction processing

When you run the network, every participant runs an equal node. There is no central server. Nodes find each other autonomously, share transactions, propose blocks, vote on consensus, and maintain identical copies of the blockchain.

---

## 2. What is P2P Multi-Node Networking?

### The Traditional Model (Client-Server)
In a conventional application, one central server holds all data. Clients (users) connect to that server to read or write. If the server goes offline, the service stops.

```
  Client A ──┐
  Client B ──┼──► Server  (single point of failure)
  Client C ──┘
```

### The P2P Model
In a peer-to-peer (P2P) network, every participant is both a client **and** a server — called a **node** or **peer**. Nodes connect directly to each other and collectively hold the state of the network. There is no single point of failure.

```
  Node A ──── Node B
    │    ╲  ╱    │
    │     ╲╱     │
    │     ╱╲     │
    │   ╱    ╲   │
  Node C ──── Node D
```

### Multi-Node Means Decentralised
A "multi-node network" simply means more than one node is running simultaneously. Each node:
- Maintains its own full copy of the blockchain
- Independently validates every transaction and block
- Propagates (gossips) valid messages to all connected peers
- Participates in consensus voting

The network becomes more **resilient**, **censorship-resistant**, and **trustless** as more nodes join. No single node can rewrite history or censor transactions — a majority of nodes must agree on every block.

---

## 3. How the GreenHouse Network Works

### Node Lifecycle

```
Start
  │
  ▼
NewBlockchain() ──► Genesis block added
  │
  ▼
NewP2PNode()
  ├── Create libp2p Host     (listen on TCP, QUIC, WebRTC)
  ├── Initialise DHT         (Kademlia routing table)
  ├── Connect bootstrap peers (async, non-blocking)
  ├── Bootstrap DHT          (async)
  ├── Advertise rendezvous   (async)
  ├── Discover peers         (continuous background loop)
  ├── Create GossipSub       (PubSub messaging)
  ├── Join topic             ("greenhouse-p2p-network")
  └── Subscribe to topic     (ready to receive messages)
  │
  ▼
Node is LIVE — ready to broadcast and receive
  │
  ├── go HandleMessages()    (background message loop)
  └── Application code runs
```

### Peer Discovery (How Nodes Find Each Other)

GreenHouse uses two complementary discovery mechanisms:

**1. Bootstrap Peers (for internet-wide discovery)**
You configure one or more known nodes with fixed addresses. Your node connects to them on startup, and they provide introductions to the rest of the DHT network.

**2. Kademlia DHT (for ongoing discovery)**
Once connected to any peer, your node joins a distributed hash table. It can then:
- Advertise itself under the `greenhouse-p2p-network` rendezvous key
- Query the DHT to find other nodes advertising the same key
- Build up a routing table organically over time

Both mechanisms run entirely in the background. Your node is immediately usable for messaging even while peer discovery is still in progress.

### Message Flow

Once two nodes are connected, they exchange messages over **GossipSub** — a publish/subscribe protocol. Every node subscribes to the same topic. When one node publishes a message, GossipSub propagates it to all subscribers automatically:

```
Node A publishes transaction
        │
        ▼
  GossipSub topic
  ╔═══════════════╗
  ║ Node B        ║ ◄── receives + validates transaction
  ║ Node C        ║ ◄── receives + validates transaction
  ║ Node D        ║ ◄── receives + validates transaction
  ╚═══════════════╝
```

### Consensus (How Blocks Are Agreed)

GreenHouse uses **dBFT** (Delegated Byzantine Fault Tolerant):

1. **Delegate election**: Nodes with locked (staked) currency vote for delegates
2. **Speaker selection**: One delegate is chosen as the speaker for the current view
3. **Block proposal**: The speaker proposes a block from the transaction pool
4. **Voting**: All delegates broadcast their votes via P2P
5. **Commit**: If ≥ 2/3 of delegates approve, the block is added to the chain

---

## 4. Network Architecture & Components

### Key Files

| File | Purpose |
|------|---------|
| `p2p.go` | P2P node, peer discovery, message broadcasting, stream handling |
| `p2p_mock.go` | Mock P2P node for testing without real network connections |
| `blockchain.go` | Blockchain state, blocks, transactions, sharding |
| `dBFT.go` | Consensus engine, delegates, voting |
| `wallets.go` | Wallet creation, locking/unlocking currency for staking |
| `keys.go` | Ed25519 key generation, signing, verification |
| `network.go` | Internal message types for consensus communication |

### The P2PNode Struct

```go
type P2PNode struct {
    Host        host.Host          // The libp2p host (manages connections)
    PubSub      *pubsub.PubSub     // The GossipSub instance
    Topic       *pubsub.Topic      // The joined topic ("greenhouse-p2p-network")
    Sub         *pubsub.Subscription // Our subscription to incoming messages
    Blockchain  *Blockchain        // Reference to the local blockchain state
    MdnsService mdns.Service       // mDNS service (local network discovery)
}
```

### Transport Protocols

When a node starts, it automatically listens on multiple transports:

| Protocol | Example Address | Use Case |
|----------|----------------|----------|
| TCP | `/ip4/192.168.1.1/tcp/49416` | Standard TCP connections |
| QUIC v1 | `/ip4/192.168.1.1/udp/56205/quic-v1` | Low-latency UDP connections |
| WebRTC | `/ip4/192.168.1.1/udp/59287/webrtc-direct/...` | Browser and NAT traversal |
| WebTransport | `/ip4/192.168.1.1/udp/54029/quic-v1/webtransport/...` | HTTP/3 based transport |

All addresses include your node's **Peer ID** — a cryptographic identity derived from your node's key pair, e.g.:
```
/ip4/192.168.1.1/tcp/49416/p2p/12D3KooWFrRYj9k5S7x9NRyFcH9Wz9Karz3zW8BJ58Z7aZRQkwHq
```

---

## 5. Setting Up Your First Node

### Prerequisites

- Go 1.23+ installed (`go version`)
- Git
- Network access

### Build

```bash
cd /path/to/GreenHouse.web3
go build -o bin/gonetwork
```

Or use the Makefile:
```bash
make build
```

### Run a Single Node

```bash
./bin/gonetwork
```

You will immediately see output like:
```
Genesis block added to the blockchain.
INFO  p2pnode  Libp2p host created with ID: 12D3KooW...
INFO  p2pnode  DHT initialized for peer discovery
INFO  p2pnode  Listening on: /ip4/127.0.0.1/tcp/49416/p2p/12D3KooW...
INFO  p2pnode  Listening on: /ip4/192.168.1.225/tcp/49416/p2p/12D3KooW...
INFO  p2pnode  Attempting to connect to bootstrap peer: /ip4/206.189.29.191/...
WARN  p2pnode  Failed to connect to bootstrap peer: ...  ← expected if offline
INFO  p2pnode  PubSub service initialized
INFO  p2pnode  Joined topic: greenhouse-p2p-network
INFO  p2pnode  Subscribed to topic
INFO  p2pnode  Stream handler set for direct messaging
```

> **Note on bootstrap peer warnings**: The configured bootstrap peer at `206.189.29.191` is a remote server. If it is offline, you will see a warning — this is normal and non-fatal. Your node is still fully operational for local networking and will connect to any peers it can reach.

### Record Your Node's Multiaddress

Your node's full multiaddress is printed on startup:
```
/ip4/192.168.1.225/tcp/49416/p2p/12D3KooWFrRYj9k5S7x9NRyFcH9Wz9Karz3zW8BJ58Z7aZRQkwHq
```

This is the address other nodes need to connect to you. Save it.

---

## 6. Local Multi-Node Testing

Running multiple nodes on the **same machine** is the easiest way to test P2P behaviour without additional hardware. Each node gets a different random port automatically.

### Step 1 — Start the First Node (Bootstrap Node)

Open Terminal 1:
```bash
cd /path/to/GreenHouse.web3
./bin/gonetwork
```

Watch the logs and copy your node's full multiaddress. It looks like:
```
/ip4/127.0.0.1/tcp/49416/p2p/12D3KooWXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Step 2 — Configure the Second Node to Connect

To make Node 2 connect directly to Node 1, edit `blockchain.go` and add Node 1's address to the bootstrap peers list:

```go
bootstrapPeers := []string{
    "/ip4/127.0.0.1/tcp/49416/p2p/12D3KooWXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
}
```

Then rebuild:
```bash
go build -o bin/gonetwork2
```

### Step 3 — Start the Second Node

Open Terminal 2:
```bash
./bin/gonetwork2
```

Within a few seconds you should see on Node 2:
```
INFO  p2pnode  Connected to bootstrap peer: /ip4/127.0.0.1/tcp/49416/...
INFO  p2pnode  DHT bootstrapped successfully
INFO  p2pnode  DHT routing table now has 1 peers
INFO  p2pnode  Rendezvous point advertised successfully
INFO  p2pnode  Discovered peer: 12D3KooW...
INFO  p2pnode  Successfully connected to peer: 12D3KooW...
```

And on Node 1:
```
INFO  p2pnode  Successfully connected to peer: 12D3KooW...
```

### Step 4 — Start More Nodes

Repeat Step 3 for Node 3, Node 4, etc. After initial connection to the bootstrap node, they will discover each other through the DHT automatically. You do not need to list every node — just one reachable bootstrap node is sufficient.

### What to Observe

Once nodes are connected you can verify the network is live:

**Nodes discover each other:**
```
INFO  p2pnode  Discovered peer: 12D3KooW...
INFO  p2pnode  Successfully connected to peer: 12D3KooW...
```

**Messages propagate:**
When a transaction is broadcast on Node 1, all other nodes log:
```
Received transaction: {Sender:Alice Receiver:Bob Amount:10 ...}
```

**Blocks are validated and accepted:**
```
Block validated successfully
```

### Tip: Run Multiple Nodes in One Terminal

For quick testing you can run all nodes in the background:

```bash
./bin/gonetwork &
./bin/gonetwork &
./bin/gonetwork &
```

Use `kill %1 %2 %3` to stop them all.

---

## 7. Cross-Network (Internet) Testing

To test across different machines (simulating real users), you need to ensure nodes can reach each other over the internet.

### Option A — Same Local Network (LAN)

No special configuration needed. Both nodes' LAN IP addresses (e.g., `192.168.x.x`) are listed in their listening addresses. Simply use those addresses as bootstrap peers.

**Node 1** (on machine at `192.168.1.10`):
```bash
./bin/gonetwork
# Logs: Listening on /ip4/192.168.1.10/tcp/49416/p2p/12D3KooW...
```

**Node 2** (on machine at `192.168.1.15`) — set bootstrap peer to Node 1's LAN address:
```go
bootstrapPeers := []string{
    "/ip4/192.168.1.10/tcp/49416/p2p/12D3KooW...",
}
```

### Option B — Different Networks Over the Internet

#### Requirement: Publicly Reachable Bootstrap Node

At least one node must have a **public IP address** and an **open TCP port**. This is the bootstrap node. All other nodes connect to it first, then discover each other through the DHT.

#### How to Set Up a Bootstrap Node (VPS or Server)

1. **Get a server with a public IP** — any cloud provider (DigitalOcean, AWS, Hetzner, etc.)

2. **Open a firewall port** — pick a port (e.g., `9000`) and allow inbound TCP and UDP:
   ```bash
   # Ubuntu UFW example
   sudo ufw allow 9000/tcp
   sudo ufw allow 9000/udp
   ```

3. **Build and run the node** on the server:
   ```bash
   go build -o bin/gonetwork
   ./bin/gonetwork
   ```

4. **Note the public multiaddress** from the logs:
   ```
   Listening on: /ip4/YOUR_PUBLIC_IP/tcp/49416/p2p/12D3KooW...
   ```

5. **Update the bootstrap peers** in `blockchain.go` on your client nodes:
   ```go
   bootstrapPeers := []string{
       "/ip4/YOUR_PUBLIC_IP/tcp/49416/p2p/12D3KooW...",
   }
   ```

6. **Rebuild and run** client nodes — they will connect to the bootstrap node and discover each other through the DHT.

#### NAT Traversal

libp2p handles most NAT situations automatically via:
- **UPnP/NAT-PMP**: Requests port forwarding from your router
- **QUIC/WebRTC**: Can punch through NAT without port forwarding in many cases
- **Relay nodes**: If direct connection fails, data can be relayed through a third peer

For reliable cross-internet operation, having at least one node with a static public IP and open port is strongly recommended.

### Verifying Cross-Network Connectivity

On any node, watch the logs for:
```
INFO  p2pnode  Connected to bootstrap peer: /ip4/REMOTE_IP/tcp/PORT/...
INFO  p2pnode  DHT bootstrapped successfully
INFO  p2pnode  Discovered peer: 12D3KooW...
INFO  p2pnode  Successfully connected to peer: 12D3KooW...
```

If messages broadcast from Node 1 appear in Node 2's logs, the network is working end-to-end.

---

## 8. Interacting With the Network

The `P2PNode` API is used from application code (e.g., a CLI or API server layer):

### Broadcast a Transaction

```go
tx := gonetwork.Transaction{
    Sender:       senderPublicKeyHex,
    Receiver:     receiverPublicKeyHex,
    Amount:       50.0,
    RequiredSigs: 1,
}

// Sign with private key
err := tx.SignTransaction(privateKey)

// Broadcast to all peers
err = blockchain.P2PNode.BroadcastTransaction(tx)
```

### Broadcast a Block

```go
block := gonetwork.Block{
    Transactions: txPool,
    PrevHash:     blockchain.GetLastBlockHash(),
}

err := blockchain.P2PNode.BroadcastBlock(block)
```

### Send a Direct Message to a Peer

```go
// Using full multiaddress
err := node.SendMessage("/ip4/192.168.1.10/tcp/49416/p2p/12D3KooW...", "hello")

// Using peer ID (must already be in peer store)
err := node.SendMessage("12D3KooW...", "hello")
```

### Ping a Peer

```go
err := node.SendPing("12D3KooW...")
// Sends a ping via PubSub; all subscribed nodes receive it and auto-respond with Ack
```

### Handle Incoming Messages

```go
// Run in a goroutine — blocks until ctx is cancelled
go blockchain.P2PNode.HandleMessages(ctx)
```

`HandleMessages` dispatches on message type:

| Message Type | Action |
|-------------|--------|
| `transaction` | Deserialise + add to `TransactionPool` |
| `block` | Deserialise + validate + add to blockchain if valid |
| `ping` | Log + publish `ack` response |
| `ack` | Log acknowledgement |

### Shutdown a Node Cleanly

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
defer node.Shutdown(ctx)
```

`Shutdown` cancels the PubSub subscription, closes the topic, and closes the libp2p host cleanly.

---

## 9. Running Tests

### All Tests
```bash
go test -v ./...
```

### Specific Test Groups

**Mock / unit tests (no network required, fast):**
```bash
go test -v -run "Mock|Broadcast|HandleMessages|PingAndAck|Shutdown" ./...
```

**Real P2P node tests (local network only, ~5 seconds each):**
```bash
go test -v -run "TestNewP2PNode|TestRealPeersCommunication" ./...
```

**Blockchain logic tests:**
```bash
go test -v -run "TestAddBlock|TestValidateBlock|TestSignTransaction|TestMultiSignature" ./...
```

**Consensus tests:**
```bash
go test -v -run "TestAchieveConsensus|TestVoteForDelegates|TestCreateBlock" ./...
```

**Wallet tests:**
```bash
go test -v -run "TestLockCurrency|TestUnlockCurrency|TestWallet" ./...
```

### Expected Results

| Test | Expected | Notes |
|------|----------|-------|
| `TestBroadcastTransaction` | PASS | Mock node |
| `TestBroadcastBlock` | PASS | Mock node |
| `TestHandleMessages` | PASS | Mock node |
| `TestMockP2PNodeInitialization` | PASS | Mock node |
| `TestPingAndAck` | PASS | Mock node |
| `TestP2PNodeShutdown` | PASS | Mock node |
| `TestNewP2PNode` | PASS | Real node, ~5s |
| `TestRealPeersCommunication` | PASS | Two real nodes |
| `TestPeerDiscovery` | FAIL | Requires external bootstrap node to be online |
| All blockchain/wallet/keys tests | PASS | No networking required |

`TestPeerDiscovery` will always fail unless the configured bootstrap peer at `206.189.29.191` is actively running. To make it pass, replace that address with a running node's address, or run the bootstrap node yourself.

---

## 10. Troubleshooting

### "Failed to connect to bootstrap peer"
**Cause**: The bootstrap node is offline or unreachable.  
**Impact**: Non-fatal. Your node still initialises and is ready for local connections.  
**Fix**: Ensure the bootstrap node is running and the address in `blockchain.go` is correct.

### Nodes are running but not discovering each other
**Possible causes:**
1. Bootstrap peer is unreachable — check logs for `Connected to bootstrap peer`
2. DHT has not had enough time to populate — wait 10–20 seconds after startup
3. Firewall blocking connections — open required TCP/UDP ports

**Debug steps:**
```bash
# Watch for discovery events
./bin/gonetwork 2>&1 | grep -E "Discovered|Connected|routing table"
```

### "no peers in routing table" (old error, now fixed)
This was the original blocking behaviour. If you see it, ensure you have the latest version of `p2p.go` with asynchronous peer discovery.

### Messages not arriving on remote node
1. Confirm both nodes are subscribed to the **same topic** (default: `greenhouse-p2p-network`)
2. Confirm both nodes have at least one common connected peer (the network must be connected)
3. Check that `HandleMessages` is running as a goroutine on the receiving node

### Port conflicts when running multiple local nodes
This is handled automatically — libp2p picks random available ports by default. You do not need to configure ports manually.

### Build errors
```bash
go mod tidy     # Ensure all dependencies are present
go build ./...  # Check for compile errors
```

---

## 11. Reference: Message Types & Node API

### P2PMessage Format

All messages over GossipSub are JSON-encoded `P2PMessage` structs:

```json
{
  "type": "transaction",
  "payload": "<base64-encoded JSON>"
}
```

### Message Types

| Constant | Value | Payload | Direction |
|----------|-------|---------|-----------|
| `MessageTypeTransaction` | `"transaction"` | Serialised `Transaction` | Any node → all nodes |
| `MessageTypeBlock` | `"block"` | Serialised `Block` | Speaker → all delegates |
| `MessageTypePing` | `"ping"` | `"ping"` bytes | Any node → all nodes |
| `MessageTypeAck` | `"ack"` | `"pong"` bytes | Responder → all nodes |

### Direct Messaging Protocol

Stream protocol identifier: `/p2p/1.0.0`

Direct (non-broadcast) messages are sent via a raw stream to a specific peer. The receiving node logs the message. This is used for targeted node-to-node communication outside of GossipSub.

### Key Types

| Type | Description |
|------|-------------|
| `PrivateKey` | Ed25519 private key — used to sign transactions |
| `PublicKey` | Ed25519 public key — used to verify signatures, serves as wallet address |
| `Transaction` | `{Sender, Receiver, Amount, Signatures, RequiredSigs, Nonce}` |
| `Block` | `{Transactions, PrevHash, Nonce, Signatures}` |
| `Blockchain` | Full chain state including wallets, delegates, shards, P2P node |

### Generating Keys

```go
privateKey, err := gonetwork.GeneratePrivateKey()
publicKey := privateKey.PublicKey()
address := publicKey.String() // Hex-encoded, used as wallet address
```

### Configuring Bootstrap Peers

Edit `NewBlockchain()` in `blockchain.go`:

```go
bootstrapPeers := []string{
    "/ip4/SERVER_IP/tcp/PORT/p2p/PEER_ID",
    // Add as many as needed — more = more resilient startup
}
```

For **local-only testing** with no external bootstrap node:
```go
bootstrapPeers := []string{}
```
Nodes will still discover each other if you point them at each other's addresses directly.
