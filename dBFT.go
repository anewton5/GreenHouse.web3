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
	VotingStrategy VotingStrategy
	Blockchain     *Blockchain
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

	// Speaker proposes a block with transactions from the pool
	speaker := bc.Delegates[bc.currentSpeaker]
	block := Block{
		Transactions: bc.TransactionPool, // Use transactions from the pool
		PrevHash:     bc.GetLastBlockHash(),
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

	// Clear the transaction pool after proposing the block
	bc.TransactionPool = []Transaction{}
}

type FuncVotingStrategy struct {
	VoteFunc func(block Block) bool
}

func (f *FuncVotingStrategy) Vote(block Block) bool {
	return f.VoteFunc(block)
}

type VotingStrategy interface {
	Vote(block Block) bool
}

type DefaultVotingStrategy struct{}

func (d *DefaultVotingStrategy) Vote(block Block) bool {
	// Example: Vote "yes" if the block contains at least one transaction
	return len(block.Transactions) > 0
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
		fmt.Printf("Delegate %s voted %v on the block\n", delegate.ID, vote) // Log delegate votes
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
	if yesVotes >= consensusThreshold {
		fmt.Printf("Consensus achieved with %d yes votes out of %d\n", yesVotes, len(bc.Delegates))
		bc.finalizeBlock(block)
		return true
	}

	fmt.Printf("Consensus not achieved. Yes votes: %d, No votes: %d\n", yesVotes, noVotes)
	return false
}

func (bc *Blockchain) AddTransaction(tx Transaction) {
	bc.TransactionPool = append(bc.TransactionPool, tx)
	fmt.Printf("Transaction added to the pool: %+v\n", tx)
}

// Delegate votes on a block (simplified logic)
func (n *Node) VoteOnBlock(block Block) bool {
	if n.VotingStrategy != nil {
		return n.VotingStrategy.Vote(block)
	}
	// Default to "yes" if no strategy is set
	return true
}
func (bc *Blockchain) finalizeBlock(block Block) {
	fmt.Printf("Finalizing block with hash: %s\n", block.CalculateHash())
	bc.Blocks = append(bc.Blocks, block)
}

// Create a new block and add it to the blockchain
func (bc *Blockchain) createBlock(network *Network) {
	if len(bc.Delegates) == 0 {
		fmt.Println("No delegates available to create a block.")
		return
	}

	// Log the transaction pool
	fmt.Printf("Transaction pool before block creation: %+v\n", bc.TransactionPool)

	// Collect signatures from delegates
	signatures := [][]byte{}
	for _, delegate := range bc.Delegates {
		signatures = append(signatures, []byte(delegate.ID))
	}

	// Collect valid transactions
	transactions := []Transaction{}
	for _, tx := range bc.TransactionPool {
		transactions = append(transactions, tx)
	}

	// Increment nonce
	bc.Nonce++

	// Attempt to achieve consensus
	if bc.AchieveConsensus(Block{Transactions: transactions, Signatures: signatures}, network) {
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
func NewNode(id string, blockchain *Blockchain) *Node {
	return &Node{
		ID:         id,
		Inbox:      make(chan Message, 10), // Buffered channel for messages
		Blockchain: blockchain,             // Initialize the blockchain reference
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

func (n *Node) ProcessMessages() {
	for msg := range n.Inbox {
		switch msg.Type {
		case BlockProposal:
			fmt.Printf("Node %s received block proposal: %+v\n", n.ID, msg.Payload)
		case Vote:
			fmt.Printf("Node %s received vote: %+v\n", n.ID, msg.Payload)
		case Consensus:
			fmt.Printf("Node %s received consensus result: %+v\n", n.ID, msg.Payload)
		case "Transaction":
			tx, ok := msg.Payload.(Transaction)
			if ok {
				n.Blockchain.AddTransaction(tx)
			}
		}
	}
}
