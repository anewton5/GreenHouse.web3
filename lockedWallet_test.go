package gonetwork_test

import (
	"gonetwork"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
