package gonetwork

import (
	"encoding/base64"
)

// Wallet structure
type Wallet struct {
	PrivateKey *PrivateKey
	PublicKey  *PublicKey
	Balance    int
}

// NewWallet creates a new wallet with a new pair of keys
func NewWallet() (*Wallet, error) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.Public()
	return &Wallet{PrivateKey: privateKey, PublicKey: publicKey, Balance: 0}, nil
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
	return tx, nil
}
