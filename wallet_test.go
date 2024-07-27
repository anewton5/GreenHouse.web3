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
	assert.NotNil(t, tx.Signature)
}

func TestVerifyTransaction(t *testing.T) {
	sender, err := gonetwork.NewWallet()
	assert.NoError(t, err)

	receiver, err := gonetwork.NewWallet()
	assert.NoError(t, err)

	receiverPublicKeyStr := base64.StdEncoding.EncodeToString(receiver.PublicKey.Bytes())

	tx, err := sender.CreateTransaction(receiverPublicKeyStr, 100.0)
	assert.NoError(t, err)

	isValid := tx.VerifyTransaction()
	assert.True(t, isValid)
}
