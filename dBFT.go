package gonetwork

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// Simplified Node structure
type Node struct {
	ID             string
	IsDelegate     bool
	Stake          int
	Votes          int
	PrivateKey     ed25519.PrivateKey
	PublicKey      ed25519.PublicKey
	Inbox          chan Message
	VotingStrategy func(block Block) bool
}

// VoteForDelegates selects delegates based on staked currency
func (bc *Blockchain) VoteForDelegates(network *Network) {
	// Reset delegates
	bc.Delegates = []Node{}

	votes := make(map[string]float64)

	// Calculate votes based on locked wallets
	for _, lockedWallet := range bc.LockedWallets {
		// Get the voter's ID and their chosen delegate's ID
		voterID := bc.getVoterID(lockedWallet.OwnerPublicKey)
		delegateID := bc.getDelegateID(voterID)

		if delegateID != "" {
			votes[delegateID] += lockedWallet.Balance
		}
	}

	// Assign votes to nodes and select delegates
	for i := range bc.Nodes {
		node := &bc.Nodes[i]
		if votes[node.ID] > 0 {
			node.Votes = int(votes[node.ID])
			node.IsDelegate = true
			bc.Delegates = append(bc.Delegates, *node)
		}
	}

	// Log the elected delegates
	for _, delegate := range bc.Delegates {
		fmt.Printf("Delegate %s received %d votes\n", delegate.ID, delegate.Votes)
	}

	// Start the consensus process
	if len(bc.Delegates) > 0 {
		bc.startConsensus(network)
	} else {
		fmt.Println("No delegates elected. Consensus cannot start.")
	}
}

// Get voter ID from public key
func (bc *Blockchain) getVoterID(publicKey [32]byte) string {
	publicKeyStr := base64.StdEncoding.EncodeToString(publicKey[:])
	return bc.PublicKeyToID[publicKeyStr]
}

// Get delegate ID from voter ID
func (bc *Blockchain) getDelegateID(voterID string) string {
	return bc.UserIDToDelegateID[voterID]
}

// Start the consensus process
func (bc *Blockchain) startConsensus(network *Network) {
	bc.currentView = View{Number: 0}
	bc.selectSpeaker()

	// Speaker proposes a block
	speaker := bc.Delegates[bc.currentSpeaker]
	block := Block{
		Transactions: []Transaction{}, // Add transactions here
		PrevHash:     "",              // Add previous hash here
	}

	// Validate the block before broadcasting
	if !bc.ValidateBlock(block) {
		fmt.Println("Proposed block is invalid. Consensus cannot proceed.")
		return
	}

	// Broadcast block proposal
	proposalMsg := Message{
		From:    speaker.ID,
		To:      "",
		Type:    BlockProposal,
		Payload: block,
	}
	speaker.SendMessage(network, proposalMsg)

	// Collect votes from delegates
	votes := 0
	for _, delegate := range bc.Delegates {
		voteMsg := Message{
			From:    delegate.ID,
			To:      speaker.ID,
			Type:    Vote,
			Payload: true, // Simplified: all delegates vote "yes"
		}
		delegate.SendMessage(network, voteMsg)
		votes++
	}

	// Check if consensus is achieved
	consensusThreshold := (2 * len(bc.Delegates)) / 3
	if votes > consensusThreshold {
		consensusMsg := Message{
			From:    speaker.ID,
			To:      "",
			Type:    Consensus,
			Payload: "Consensus achieved",
		}
		speaker.SendMessage(network, consensusMsg)
		fmt.Println("Consensus achieved. Block added to the blockchain.")
	} else {
		fmt.Println("Consensus not achieved.")
	}
}

// Select the speaker (proposer) for the current view
func (bc *Blockchain) selectSpeaker() {
	if len(bc.Delegates) == 0 {
		fmt.Println("No delegates available to select a speaker.")
		return
	}
	bc.currentSpeaker = int(bc.currentView.Number) % len(bc.Delegates)
	fmt.Printf("Speaker for view %d is %s\n", bc.currentView.Number, bc.Delegates[bc.currentSpeaker].ID)
}

// AchieveConsensus ensures consensus is reached among delegates
func (bc *Blockchain) AchieveConsensus(block Block, network *Network) bool {
	yesVotes := 0
	noVotes := 0

	// Simulate receiving votes via the network
	for _, delegate := range bc.Delegates {
		vote := delegate.VoteOnBlock(block)
		voteMsg := Message{
			From:    delegate.ID,
			To:      "",
			Type:    Vote,
			Payload: vote,
		}
		delegate.SendMessage(network, voteMsg)

		if vote {
			yesVotes++
		} else {
			noVotes++
		}
	}

	consensusThreshold := (2 * len(bc.Delegates)) / 3
	if yesVotes > consensusThreshold {
		fmt.Printf("Consensus achieved with %d yes votes out of %d\n", yesVotes, len(bc.Delegates))
		return true
	}

	fmt.Printf("Consensus not achieved. Yes votes: %d, No votes: %d\n", yesVotes, noVotes)
	return false
}

// Delegate votes on a block (simplified logic)
func (n *Node) VoteOnBlock(block Block) bool {
	if n.VotingStrategy != nil {
		return n.VotingStrategy(block)
	}
	// Default to "yes" if no strategy is set
	return true
}

// Create a new block and add it to the blockchain
func (bc *Blockchain) createBlock(network *Network) {
	if len(bc.Delegates) == 0 {
		fmt.Println("No delegates available to create a block.")
		return
	}

	// Collect signatures from delegates
	signatures := [][]byte{}
	for _, delegate := range bc.Delegates {
		signatures = append(signatures, []byte(delegate.ID))
	}

	// Collect valid transactions
	transactions := []Transaction{}
	for _, wallet := range bc.Wallets {
		for receiverPublicKeyStr := range bc.Wallets {
			if receiverPublicKeyStr != base64.StdEncoding.EncodeToString(wallet.PublicKey.Bytes()) {
				amount := 10.0
				tx, err := wallet.CreateTransaction(receiverPublicKeyStr, amount)
				if err != nil {
					fmt.Println("Error creating transaction:", err)
					continue
				}
				transactions = append(transactions, *tx)
				break
			}
		}
	}

	// Increment nonce
	bc.Nonce++

	// Attempt to achieve consensus
	if bc.AchieveConsensus(Block{Signatures: signatures}, network) {
		bc.AddBlock(transactions, signatures)
		fmt.Printf("Block %d created with signatures: %v\n", len(bc.Blocks)-1, signatures)
	} else {
		fmt.Println("Failed to achieve consensus. Block not added.")
	}

	// Move to the next view
	bc.currentView = View{Number: bc.currentView.Number + 1}
	bc.selectSpeaker()
}

// NewNode creates a new node
func NewNode(id string) *Node {
	return &Node{
		ID:    id,
		Inbox: make(chan Message, 10), // Buffered channel for messages
	}
}

// SendMessage sends a message to the network
func (n *Node) SendMessage(network *Network, msg Message) {
	network.SendMessage(msg)
}

// ReceiveMessage handles incoming messages
func (n *Node) ReceiveMessage(msg Message) {
	go func() {
		n.Inbox <- msg
	}()
}

// ProcessMessages processes messages from the inbox
func (n *Node) ProcessMessages() {
	for msg := range n.Inbox {
		switch msg.Type {
		case BlockProposal:
			fmt.Printf("Node %s received block proposal: %+v\n", n.ID, msg.Payload)
		case Vote:
			fmt.Printf("Node %s received vote: %+v\n", n.ID, msg.Payload)
		case Consensus:
			fmt.Printf("Node %s received consensus result: %+v\n", n.ID, msg.Payload)
		}
	}
}
