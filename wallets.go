package gonetwork

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// Wallet structure
type Wallet struct {
	PrivateKey *PrivateKey
	PublicKey  *PublicKey
	Balance    float64
}

type LockedWallet struct {
	OwnerPublicKey [32]byte
	Balance        float64
}

var lockedWallets = make(map[[32]byte]*LockedWallet)

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
	if w.PrivateKey == nil {
		return nil, fmt.Errorf("wallet private key is not initialized")
	}
	if amount <= 0 {
		return nil, fmt.Errorf("transaction amount must be greater than zero")
	}

	senderPublicKeyStr := base64.StdEncoding.EncodeToString(w.PublicKey.Bytes())

	tx := &Transaction{
		Sender:   senderPublicKeyStr,
		Receiver: receiverPublicKeyStr,
		Amount:   amount,
	}

	// Serialize and hash the transaction, then sign it
	if err := tx.SignTransaction(w.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}

	fmt.Printf("Created transaction from %s to %s for amount %f\n", senderPublicKeyStr, receiverPublicKeyStr, amount)

	return tx, nil
}

func (w *Wallet) LockCurrency(amount float64) error {
	if amount <= 0 {
		return errors.New("amount must be greater than zero")
	}
	if w.Balance < amount {
		return errors.New("insufficient balance")
	}

	// Deduct the amount from the wallet balance
	w.Balance -= amount

	// Convert public key to a fixed-size array
	var publicKeyArray [32]byte
	copy(publicKeyArray[:], w.PublicKey.Bytes()[:32])

	// Add the amount to the locked wallet
	lockedWallet, exists := lockedWallets[publicKeyArray]
	if !exists {
		lockedWallet = &LockedWallet{
			OwnerPublicKey: publicKeyArray,
			Balance:        0,
		}
		lockedWallets[publicKeyArray] = lockedWallet
	}
	lockedWallet.Balance += amount
	fmt.Printf("Locked %f currency from wallet %x. New wallet balance: %f. Locked wallet balance: %f\n",
		amount, w.PublicKey.Bytes(), w.Balance, lockedWallet.Balance)
	return nil
}
func (w *Wallet) UnlockCurrency(amount float64) error {
	if amount <= 0 {
		return errors.New("amount must be greater than zero")
	}

	// Convert public key to a fixed-size array
	var publicKeyArray [32]byte
	copy(publicKeyArray[:], w.PublicKey.Bytes()[:32])

	lockedWallet, exists := lockedWallets[publicKeyArray]
	if !exists || lockedWallet.Balance < amount {
		return errors.New("insufficient locked balance")
	}

	// Deduct the amount from the locked wallet balance
	lockedWallet.Balance -= amount

	// Add the amount back to the wallet balance
	w.Balance += amount

	// Remove the locked wallet if the balance is zero
	if lockedWallet.Balance == 0 {
		delete(lockedWallets, publicKeyArray)
	}
	fmt.Printf("Unlocked %f currency to wallet %x. New wallet balance: %f. Locked wallet balance: %f\n",
		amount, w.PublicKey.Bytes(), w.Balance, lockedWallet.Balance)
	return nil
}
func GetLockedWallets() map[[32]byte]*LockedWallet {
	return lockedWallets
}
