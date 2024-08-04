package gonetwork

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Simplified structures
type Node struct {
	ID         string
	IsDelegate bool
	Stake      int
	Votes      int
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// THis is a simplified version of voting process for consensus nodes in dBFT. For the purpose of GreenHouse.io we will simply select nodes from the pool of nodes that are staking a part of their currency on the network.
func (bc *Blockchain) VoteForDelegates() {
	votes := make(map[string]float64)

	// Iterate over locked wallets to identify staked users
	for _, lockedWallet := range bc.LockedWallets {
		// Calculate voting power based on staked currency
		votingPower := lockedWallet.Balance

		// Get the voter's ID and their chosen delegate's ID
		voterID := bc.getVoterID(lockedWallet.OwnerPublicKey)
		delegateID := bc.getDelegateID(voterID)

		votes[delegateID] += votingPower
	}

	for _, node := range bc.Nodes {
		if votes[node.ID] > 0 {
			node.Votes = int(votes[node.ID])
			node.IsDelegate = true
			bc.Delegates = append(bc.Delegates, node)
		}
	}

	for _, delegate := range bc.Delegates {
		fmt.Printf("Delegate %s received %d votes\n", delegate.ID, delegate.Votes)
	}

	bc.startConsensus()
}

func (bc *Blockchain) getVoterID(publicKey [32]byte) string {
	publicKeyStr := hex.EncodeToString(publicKey[:])
	return bc.PublicKeyToID[publicKeyStr]
}

func (bc *Blockchain) getDelegateID(voterID string) string {
	return bc.UserIDToDelegateID[voterID]
}

func (bc *Blockchain) startConsensus() {
	bc.currentView = View{Number: 0}
	bc.selectSpeaker()
	bc.createBlock()
}

func (bc *Blockchain) selectSpeaker() {
	bc.currentSpeaker = int(bc.currentView.Number) % len(bc.Delegates)
	fmt.Printf("Speaker for view %d is %s\n", bc.currentView, bc.Delegates[bc.currentSpeaker].ID)
}

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

// Method for a delegate to vote on a block. Simplified voting logic: always vote yes.
func (n *Node) VoteOnBlock(block Block) bool {
	return true
}

func (bc *Blockchain) createBlock() {
	signatures := [][]byte{}
	for _, delegate := range bc.Delegates {
		signatures = append(signatures, []byte(delegate.ID))
	}

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

	bc.Nonce++

	if bc.AchieveConsensus(Block{Signatures: signatures}) {
		bc.AddBlock(transactions, signatures)
		fmt.Printf("Block %d created with signatures: %v\n", len(bc.Blocks)-1, signatures)
	}

	bc.currentView = View{Number: bc.currentView.Number + 1}
	bc.selectSpeaker()
}
