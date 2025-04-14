package gonetwork_test

import (
	"encoding/base64"
	"fmt"
	"gonetwork"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBlockchainStress(t *testing.T) {
	startTime := time.Now()
	numNodes := 100
	numTransactions := 1000

	// Create a blockchain
	blockchain := gonetwork.Blockchain{
		Nodes:              createNodes(t, numNodes),
		LockedWallets:      make(map[[32]byte]*gonetwork.LockedWallet),
		Wallets:            make(map[string]*gonetwork.Wallet),
		PublicKeyToID:      make(map[string]string),
		UserIDToDelegateID: make(map[string]string),
	}

	// Lock currency for some wallets to enable voting
	for i := 0; i < 10; i++ { // Lock currency for the first 10 wallets
		wallet, _ := gonetwork.NewWallet()
		wallet.Balance = 100
		err := wallet.LockCurrency(50)
		assert.NoError(t, err)

		// Register the wallet in the blockchain
		publicKeyStr := base64.StdEncoding.EncodeToString(wallet.PublicKey.Bytes())
		blockchain.Wallets[publicKeyStr] = wallet

		// Map the public key to a node ID for voting
		blockchain.PublicKeyToID[publicKeyStr] = fmt.Sprintf("Node-%d", i)
		blockchain.UserIDToDelegateID[fmt.Sprintf("Node-%d", i)] = fmt.Sprintf("Node-%d", i)

		// Add the locked balance to the LockedWallets map
		publicKeyArray := [32]byte{}
		copy(publicKeyArray[:], wallet.PublicKey.Bytes()[:32])
		blockchain.LockedWallets[publicKeyArray] = &gonetwork.LockedWallet{
			OwnerPublicKey: publicKeyArray,
			Balance:        50, // Locked balance
		}
	}

	// Generate transactions
	transactions := generateTransactions(t, numTransactions, &blockchain)

	// Simulate consensus and add transactions to the blockchain
	network := gonetwork.Network{}
	blockchain.VoteForDelegates(&network)

	for _, tx := range transactions {
		block := gonetwork.Block{
			Transactions: []gonetwork.Transaction{tx},
			PrevHash:     blockchain.GetLastBlockHash(),
		}

		// Attempt to achieve consensus for the block
		if blockchain.AchieveConsensus(block, &network) {
			blockchain.AddBlock(block.Transactions, nil)
		}
	}

	elapsedTime := time.Since(startTime)
	t.Logf("Processed %d transactions across %d nodes in %s", numTransactions, numNodes, elapsedTime)
}

func createNodes(t *testing.T, num int) []gonetwork.Node {
	nodes := make([]gonetwork.Node, num)
	for i := 0; i < num; i++ {
		node := gonetwork.NewNode(generateNodeID(i))
		assert.NotNil(t, node) // Pass the testing.T instance
		nodes[i] = *node
	}
	return nodes
}

func generateTransactions(t *testing.T, num int, blockchain *gonetwork.Blockchain) []gonetwork.Transaction {
	transactions := make([]gonetwork.Transaction, num)
	for i := 0; i < num; i++ {
		sender, _ := gonetwork.NewWallet()
		receiver, _ := gonetwork.NewWallet()
		receiverPublicKeyStr := base64.StdEncoding.EncodeToString(receiver.PublicKey.Bytes())

		// Register wallets in the blockchain
		blockchain.Wallets[base64.StdEncoding.EncodeToString(sender.PublicKey.Bytes())] = sender
		blockchain.Wallets[receiverPublicKeyStr] = receiver

		// Create a transaction
		tx := gonetwork.Transaction{
			Sender:       base64.StdEncoding.EncodeToString(sender.PublicKey.Bytes()),
			Receiver:     receiverPublicKeyStr,
			Amount:       float64(i + 1),
			RequiredSigs: 1,
		}
		tx.GenerateNonce()

		// Sign the transaction
		err := tx.SignTransaction(sender.PrivateKey)
		assert.NoError(t, err)

		transactions[i] = tx
	}
	return transactions
}

func generateNodeID(index int) string {
	return fmt.Sprintf("Node-%d", index)
}
