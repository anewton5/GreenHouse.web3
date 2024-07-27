package gonetwork

import (
	"encoding/base64"
	"fmt"
)

// Wallet structure
type Wallet struct {
	PrivateKey *PrivateKey
	PublicKey  *PublicKey
	Balance    float64
}

// NewWallet creates a new wallet with a new pair of keys
func NewWallet() (*Wallet, error) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.Public()
	wallet := &Wallet{PrivateKey: privateKey, PublicKey: publicKey, Balance: 0}
	fmt.Printf("Created new wallet with PublicKey: %x and initial Balance: %f\n", publicKey.Bytes(), wallet.Balance)
	return wallet, nil
}

// CreateTransaction creates a new transaction and signs it
func (w *Wallet) CreateTransaction(receiverPublicKeyStr string, amount float64) (*Transaction, error) {
	senderPublicKeyStr := base64.StdEncoding.EncodeToString(w.PublicKey.Bytes())

	tx := &Transaction{
		Sender:   senderPublicKeyStr,
		Receiver: receiverPublicKeyStr,
		Amount:   amount,
	}

	// Serialize and hash the transaction, then sign it
	if err := tx.SignTransaction(w.PrivateKey); err != nil {
		return nil, err
	}

	fmt.Printf("Created transaction from %s to %s for amount %f\n", senderPublicKeyStr, receiverPublicKeyStr, amount)

	return tx, nil
}
