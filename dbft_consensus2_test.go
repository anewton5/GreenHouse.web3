package gonetwork

// ---------------------------------------------------------------------------
// dbft_consensus2_test.go — extended dBFT coverage
//
// Targets uncovered paths in:
//   selectSpeaker       — 0-delegate no-op, view-rotation
//   ProcessMessages     — BlockProposal / Vote / Consensus message types
//   ReceiveMessage      — message delivered to inbox
//   PeriodicStateSaving — goroutine starts and saves
//   VoteForDelegates    — no votes path, and delegate-election path
//   startConsensus      — invalid-block early return (called via VoteForDelegates)
// ---------------------------------------------------------------------------

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// selectSpeaker
// ---------------------------------------------------------------------------

func TestSelectSpeaker_NoDelegates_NoOp(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Delegates = nil
	// Must not panic and must not change currentSpeaker.
	before := bc.currentSpeaker
	bc.selectSpeaker()
	assert.Equal(t, before, bc.currentSpeaker)
}

func TestSelectSpeaker_SingleDelegate_SpeakerIsZero(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Delegates = []Node{makeDelegate("d1", bc, nil)}
	bc.currentView = View{Number: 0}
	bc.selectSpeaker()
	assert.Equal(t, 0, bc.currentSpeaker)
}

func TestSelectSpeaker_RotatesWithViewNumber(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Delegates = []Node{
		makeDelegate("d0", bc, nil),
		makeDelegate("d1", bc, nil),
		makeDelegate("d2", bc, nil),
	}

	for viewNum := uint64(0); viewNum < 6; viewNum++ {
		bc.currentView = View{Number: int(viewNum)}
		bc.selectSpeaker()
		want := int(viewNum) % len(bc.Delegates)
		assert.Equal(t, want, bc.currentSpeaker, "view %d", viewNum)
	}
}

// ---------------------------------------------------------------------------
// ProcessMessages — additional message types
// ---------------------------------------------------------------------------

func TestProcessMessages_BlockProposal_NoOp(t *testing.T) {
	bc := newTestBlockchain(t)
	n := makeNode(t, "n1", bc)

	t.Cleanup(func() { close(n.Inbox) }) // terminate goroutine when test ends
	go n.ProcessMessages()
	n.Inbox <- Message{Type: BlockProposal, Payload: "some block data"}
	time.Sleep(50 * time.Millisecond)
	// No assertion needed — just ensuring no panic / deadlock.
}

func TestProcessMessages_Vote_NoOp(t *testing.T) {
	bc := newTestBlockchain(t)
	n := makeNode(t, "n1", bc)

	t.Cleanup(func() { close(n.Inbox) }) // terminate goroutine when test ends
	go n.ProcessMessages()
	n.Inbox <- Message{Type: Vote, Payload: true}
	time.Sleep(50 * time.Millisecond)
}

func TestProcessMessages_Consensus_NoOp(t *testing.T) {
	bc := newTestBlockchain(t)
	n := makeNode(t, "n1", bc)

	t.Cleanup(func() { close(n.Inbox) }) // terminate goroutine when test ends
	go n.ProcessMessages()
	n.Inbox <- Message{Type: Consensus, Payload: "done"}
	time.Sleep(50 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// ReceiveMessage
// ---------------------------------------------------------------------------

func TestReceiveMessage_PushesToInbox(t *testing.T) {
	bc := newTestBlockchain(t)
	n := makeNode(t, "n1", bc)

	msg := Message{Type: Vote, Payload: "test"}
	n.ReceiveMessage(msg)

	// ReceiveMessage starts a goroutine; give it a moment.
	select {
	case got := <-n.Inbox:
		assert.Equal(t, msg.Type, got.Type)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("ReceiveMessage did not deliver message to Inbox in time")
	}
}

// ---------------------------------------------------------------------------
// PeriodicStateSaving
// ---------------------------------------------------------------------------

func TestPeriodicStateSaving_CreatesFileImmediately(t *testing.T) {
	bc := newTestBlockchain(t)
	n := makeNode(t, "n1", bc)

	dir := t.TempDir()
	filename := filepath.Join(dir, "blockchain.json")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel) // stop the goroutine when the test ends
	n.PeriodicStateSaving(ctx, filename)

	// The goroutine calls SaveBlockchain immediately, then sleeps 10s.
	// Wait a short time for the first save to complete.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filename); err == nil {
			return // file created — test passed
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("PeriodicStateSaving did not create the file within 2 seconds")
}

// ---------------------------------------------------------------------------
// VoteForDelegates — no-vote path and delegate-election path
// ---------------------------------------------------------------------------

func TestVoteForDelegates_NoLockedWallets_NoDelegatesElected(t *testing.T) {
	bc := newTestBlockchain(t)
	// No locked wallets → no votes → no delegates.
	bc.VoteForDelegates(nil)
	assert.Empty(t, bc.Delegates)
}

func TestVoteForDelegates_WithLockedWallet_ElectsDelegate(t *testing.T) {
	bc := newTestBlockchain(t)

	// Build a wallet and lock currency.
	w, err := NewWallet()
	require.NoError(t, err)
	w.Balance = 1000
	require.NoError(t, w.LockCurrency(500))

	// Register the public key → voterID mapping.
	pkBytes := w.PublicKey.Bytes()
	var pkArr [32]byte
	copy(pkArr[:], pkBytes[:32])
	pkStr := base64.StdEncoding.EncodeToString(pkArr[:])

	bc.PublicKeyToID[pkStr] = "voter-alice"
	bc.RegisterDelegateVote("voter-alice", "delegate-alice")

	// Inject the locked-wallet entry directly into bc (mirrors what NewBlockchain
	// does when it reads GetLockedWallets()).
	bc.LockedWallets[pkArr] = &LockedWallet{OwnerPublicKey: pkArr, Balance: 500}

	// Add a node with that delegate ID.
	bc.Nodes = append(bc.Nodes, Node{
		ID:    "delegate-alice",
		Inbox: make(chan Message, 10),
	})

	// TransactionPool is empty → ValidateBlock returns false → startConsensus
	// exits before reaching BroadcastBlock, so nil P2PNode is safe here.
	bc.VoteForDelegates(nil)

	require.Len(t, bc.Delegates, 1)
	assert.Equal(t, "delegate-alice", bc.Delegates[0].ID)
}
