package gonetwork_test

import (
	"encoding/base64"
	"gonetwork"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewWallet(t *testing.T) {
	wallet, err := gonetwork.NewWallet()
	assert.NoError(t, err)
	assert.NotNil(t, wallet.PrivateKey)
	assert.NotNil(t, wallet.PublicKey)
	assert.Equal(t, float64(0), wallet.Balance)
}

func TestCreateTransaction(t *testing.T) {
	sender, _ := gonetwork.NewWallet()
	receiver, _ := gonetwork.NewWallet()
	receiverPublicKeyStr := base64.StdEncoding.EncodeToString(receiver.PublicKey.Bytes())

	amount := 100.0
	tx, err := sender.CreateTransaction(receiverPublicKeyStr, amount)
	assert.NoError(t, err)
	assert.Equal(t, base64.StdEncoding.EncodeToString(sender.PublicKey.Bytes()), tx.Sender)
	assert.Equal(t, receiverPublicKeyStr, tx.Receiver)
	assert.Equal(t, amount, tx.Amount)
	assert.NotNil(t, tx.Signatures)
}

func TestVerifyTransaction(t *testing.T) {
	// Generate wallets for sender and receiver
	sender, err := gonetwork.NewWallet()
	assert.NoError(t, err)

	receiver, err := gonetwork.NewWallet()
	assert.NoError(t, err)

	receiverPublicKeyStr := base64.StdEncoding.EncodeToString(receiver.PublicKey.Bytes())

	// Create a transaction
	tx, err := sender.CreateTransaction(receiverPublicKeyStr, 100.0)
	assert.NoError(t, err)

	// Verify the transaction
	pubKeys := []*gonetwork.PublicKey{sender.PublicKey} // Pass the sender's public key
	isValid, err := tx.VerifyTransaction(pubKeys)
	assert.NoError(t, err)
	assert.True(t, isValid)
}

func TestLockAndUnlockCurrency(t *testing.T) {
	wallet, _ := gonetwork.NewWallet()
	wallet.Balance = 100

	// Test locking funds
	err := wallet.LockCurrency(50)
	if err != nil {
		t.Errorf("Failed to lock currency: %v", err)
	}
	if wallet.Balance != 50 {
		t.Errorf("Expected wallet balance to be 50, got %f", wallet.Balance)
	}

	// Test unlocking funds
	err = wallet.UnlockCurrency(30)
	if err != nil {
		t.Errorf("Failed to unlock currency: %v", err)
	}
	if wallet.Balance != 80 {
		t.Errorf("Expected wallet balance to be 80, got %f", wallet.Balance)
	}

	// Test insufficient balance for locking
	err = wallet.LockCurrency(200)
	if err == nil {
		t.Errorf("Expected error for insufficient balance, but got none")
	}

	// Test insufficient locked balance for unlocking
	err = wallet.UnlockCurrency(50)
	if err == nil {
		t.Errorf("Expected error for insufficient locked balance, but got none")
	}
}

func TestLockCurrency(t *testing.T) {
	// Generate a new wallet with a balance of 100
	wallet, err := gonetwork.NewWallet()
	assert.NoError(t, err)
	wallet.Balance = 100.0

	// Lock 50 units of currency
	err = wallet.LockCurrency(50.0)
	assert.NoError(t, err)

	// Check the wallet balance
	assert.Equal(t, 50.0, wallet.Balance)

	// Check the locked wallet balance
	lockedWallets := gonetwork.GetLockedWallets()
	publicKeyArray := [32]byte{}
	copy(publicKeyArray[:], wallet.PublicKey.Bytes()[:32])
	lockedWallet, exists := lockedWallets[publicKeyArray]
	assert.True(t, exists)
	assert.Equal(t, 50.0, lockedWallet.Balance)
}

func TestUnlockCurrency(t *testing.T) {
	// Generate a new wallet with a balance of 100
	wallet, err := gonetwork.NewWallet()
	assert.NoError(t, err)
	wallet.Balance = 100.0

	// Lock 50 units of currency
	err = wallet.LockCurrency(50.0)
	assert.NoError(t, err)

	// Unlock 30 units of currency
	err = wallet.UnlockCurrency(30.0)
	assert.NoError(t, err)

	// Check the wallet balance
	assert.Equal(t, 80.0, wallet.Balance)

	// Check the locked wallet balance
	lockedWallets := gonetwork.GetLockedWallets()
	publicKeyArray := [32]byte{}
	copy(publicKeyArray[:], wallet.PublicKey.Bytes()[:32])
	lockedWallet, exists := lockedWallets[publicKeyArray]
	assert.True(t, exists)
	assert.Equal(t, 20.0, lockedWallet.Balance)

	// Unlock the remaining 20 units of currency
	err = wallet.UnlockCurrency(20.0)
	assert.NoError(t, err)

	// Check the wallet balance
	assert.Equal(t, 100.0, wallet.Balance)

	// Check the locked wallet balance
	_, exists = lockedWallets[publicKeyArray]
	assert.False(t, exists)
}
func TestLockCurrencyInsufficientBalance(t *testing.T) {
	// Generate a new wallet with a balance of 10
	wallet, err := gonetwork.NewWallet()
	assert.NoError(t, err)
	wallet.Balance = 10.0

	// Attempt to lock 50 units of currency
	err = wallet.LockCurrency(50.0)
	assert.Error(t, err)

	// Check the wallet balance
	assert.Equal(t, 10.0, wallet.Balance)
}

func TestUnlockCurrencyInsufficientLockedBalance(t *testing.T) {
	// Generate a new wallet with a balance of 100
	wallet, err := gonetwork.NewWallet()
	assert.NoError(t, err)
	wallet.Balance = 100.0

	// Lock 50 units of currency
	err = wallet.LockCurrency(50.0)
	assert.NoError(t, err)

	// Attempt to unlock 60 units of currency
	err = wallet.UnlockCurrency(60.0)
	assert.Error(t, err)

	// Check the wallet balance
	assert.Equal(t, 50.0, wallet.Balance)

	// Check the locked wallet balance
	lockedWallets := gonetwork.GetLockedWallets()
	publicKeyArray := [32]byte{}
	copy(publicKeyArray[:], wallet.PublicKey.Bytes()[:32])
	lockedWallet, exists := lockedWallets[publicKeyArray]
	assert.True(t, exists)
	assert.Equal(t, 50.0, lockedWallet.Balance)
}
