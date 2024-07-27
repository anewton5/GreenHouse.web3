package gonetwork

import (
	"errors"
	"fmt"
)

type LockedWallet struct {
	OwnerPublicKey [32]byte
	Balance        float64
}

var lockedWallets = make(map[[32]byte]*LockedWallet)
var publicKeyArray [32]byte

// LockCurrency locks a specified amount of currency from the wallet into a LockedWallet
func (w *Wallet) LockCurrency(amount float64) error {
	if amount <= 0 {
		return errors.New("amount must be greater than zero")
	}
	if w.Balance < amount {
		return errors.New("insufficient balance")
	}

	// Deduct the amount from the wallet balance
	w.Balance -= amount

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
	fmt.Printf("Locked %f currency from wallet %x. New wallet balance: %f. Locked wallet balance: %f\n", amount, w.PublicKey.Bytes(), w.Balance, lockedWallet.Balance)
	return nil
}

// UnlockCurrency unlocks a specified amount of currency from the LockedWallet back to the wallet
func (w *Wallet) UnlockCurrency(amount float64) error {
	if amount <= 0 {
		return errors.New("amount must be greater than zero")
	}

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
	fmt.Printf("Unlocked %f currency to wallet %x. New wallet balance: %f. Locked wallet balance: %f\n", amount, w.PublicKey.Bytes(), w.Balance, lockedWallet.Balance)
	return nil
}

func GetLockedWallets() map[[32]byte]*LockedWallet {
	return lockedWallets
}
