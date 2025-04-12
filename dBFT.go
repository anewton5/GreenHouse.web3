package gonetwork

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// Simplified Node structure
type Node struct {
	ID         string
	IsDelegate bool
	Stake      int
	Votes      int
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// VoteForDelegates selects delegates based on staked currency
func (bc *Blockchain) VoteForDelegates() {
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
		bc.startConsensus()
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
func (bc *Blockchain) startConsensus() {
	bc.currentView = View{Number: 0}
	bc.selectSpeaker()
	bc.createBlock()
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
func (bc *Blockchain) AchieveConsensus(block Block) bool {
	votes := 0
	for _, delegate := range bc.Delegates {
		if delegate.VoteOnBlock(block) {
			votes++
		}
	}

	consensusThreshold := (2 * len(bc.Delegates)) / 3
	if votes > consensusThreshold {
		fmt.Printf("Consensus achieved with %d votes out of %d\n", votes, len(bc.Delegates))
		return true
	}

	fmt.Printf("Consensus not achieved, only %d votes out of %d\n", votes, len(bc.Delegates))
	return false
}

// Delegate votes on a block (simplified logic)
func (n *Node) VoteOnBlock(block Block) bool {
	// Add custom logic to validate the block if needed
	return true
}

// Create a new block and add it to the blockchain
func (bc *Blockchain) createBlock() {
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
	if bc.AchieveConsensus(Block{Signatures: signatures}) {
		bc.AddBlock(transactions, signatures)
		fmt.Printf("Block %d created with signatures: %v\n", len(bc.Blocks)-1, signatures)
	} else {
		fmt.Println("Failed to achieve consensus. Block not added.")
	}

	// Move to the next view
	bc.currentView = View{Number: bc.currentView.Number + 1}
	bc.selectSpeaker()
}
