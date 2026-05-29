package gonetwork

// ---------------------------------------------------------------------------
// dbft_viewchange_test.go — Item 9: dBFT Distributed View-Change Protocol
//
// Covers:
//   Step A — ViewChangeRequest struct and ViewChangeReq/ViewChangeResp MessageType constants.
//   Step B — createBlock broadcasts ViewChangeRequest to delegate inboxes on failure.
//   Step C — ProcessMessages accumulates ViewChangeReq; advances view when f+1 received.
//   Step D — createBlock retry loop terminates after len(Delegates) attempts;
//             eventually seals when Byzantine delegates start cooperating.
// ---------------------------------------------------------------------------

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// byzantineAfterN returns a VotingStrategy that votes "no" for the first n
// calls and "yes" for all subsequent calls. Uses an atomic counter so that
// concurrent calls from AchieveConsensus goroutines are race-free.
func byzantineAfterN(n int32) VotingStrategy {
	var count atomic.Int32
	return &FuncVotingStrategy{VoteFunc: func(_ Block) bool {
		return count.Add(1) > n
	}}
}

// makeViewChangeDelegate creates a keyed delegate node with the given strategy
// and a large inbox so that buffered view-change messages are never dropped.
func makeViewChangeDelegate(t *testing.T, id string, bc *Blockchain, strategy VotingStrategy) Node {
	t.Helper()
	n := makeDelegateWithKey(t, id, bc, strategy)
	n.Inbox = make(chan Message, 1000)
	return n
}

// ---------------------------------------------------------------------------
// Step A: new types exist and are distinct
// ---------------------------------------------------------------------------

func TestViewChange_TypesExist(t *testing.T) {
	assert.Equal(t, MessageType("view_change_request"), ViewChangeReq)
	assert.Equal(t, MessageType("view_change_response"), ViewChangeResp)
	assert.NotEqual(t, ViewChangeReq, ViewChangeResp)

	req := ViewChangeRequest{View: 3, NodeID: "d1", Reason: "timeout"}
	assert.Equal(t, 3, req.View)
	assert.Equal(t, "d1", req.NodeID)
	assert.Equal(t, "timeout", req.Reason)
}

// ---------------------------------------------------------------------------
// Step B: createBlock broadcasts ViewChangeReq on consensus failure
// ---------------------------------------------------------------------------

// TestViewChange_BroadcastsViewChangeReq verifies that when AchieveConsensus
// returns false on every attempt (all delegates vote no), createBlock sends
// ViewChangeRequest messages to delegate inboxes.
func TestViewChange_BroadcastsViewChangeReq(t *testing.T) {
	bc := newTestBlockchain(t)

	alwaysNo := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return false }}
	bc.Delegates = []Node{
		makeViewChangeDelegate(t, "d1", bc, alwaysNo),
		makeViewChangeDelegate(t, "d2", bc, alwaysNo),
		makeViewChangeDelegate(t, "d3", bc, alwaysNo),
	}
	bc.InitializeShards(1)
	bc.Shards[0].TransactionPool = []Transaction{
		{Sender: "a", Receiver: "b", Amount: 1, Nonce: 1},
	}

	bc.createBlock(nil)

	// Give ReceiveMessage goroutines a moment to deliver to the buffered inboxes.
	time.Sleep(20 * time.Millisecond)

	// At least one ViewChangeReq must have been deposited in at least one inbox.
	found := false
	for i := range bc.Delegates {
		for len(bc.Delegates[i].Inbox) > 0 {
			msg := <-bc.Delegates[i].Inbox
			if msg.Type == ViewChangeReq {
				found = true
				req, ok := msg.Payload.(ViewChangeRequest)
				require.True(t, ok, "payload must be ViewChangeRequest")
				assert.Greater(t, req.View, 0, "view must be >= 1")
				assert.Equal(t, "timeout", req.Reason)
			}
		}
	}
	assert.True(t, found, "expected ViewChangeReq messages in at least one delegate inbox")
}

// TestViewChange_ViewAdvances_OnConsensusFailure verifies that each failed
// AchieveConsensus round increments bc.currentView.
func TestViewChange_ViewAdvances_OnConsensusFailure(t *testing.T) {
	bc := newTestBlockchain(t)

	alwaysNo := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return false }}
	bc.Delegates = []Node{
		makeViewChangeDelegate(t, "d1", bc, alwaysNo),
		makeViewChangeDelegate(t, "d2", bc, alwaysNo),
	}
	bc.InitializeShards(1)
	bc.Shards[0].TransactionPool = []Transaction{
		{Sender: "a", Receiver: "b", Amount: 1, Nonce: 1},
	}

	startView := bc.currentView.Number
	bc.createBlock(nil)

	// 2 delegates, 2 failed attempts → view advanced at least 2 times inside
	// the loop, plus once more at the end.
	assert.Greater(t, bc.currentView.Number, startView,
		"view number must increase after failed consensus rounds")
}

// ---------------------------------------------------------------------------
// Step D: retry loop terminates and emits EventConsensusFailure
// ---------------------------------------------------------------------------

// TestViewChange_RetryLoop_TerminatesAfterMaxAttempts verifies that createBlock
// returns (does not block forever) and emits EventConsensusFailure when all
// delegates refuse to vote yes on every attempt.
func TestViewChange_RetryLoop_TerminatesAfterMaxAttempts(t *testing.T) {
	bc := newTestBlockchain(t)
	// Short timeout so the test doesn't wait on ConsensusTimeout if no delegate blocks.
	bc.ConsensusTimeout = 20 * time.Millisecond

	alwaysNo := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return false }}
	bc.Delegates = []Node{
		makeViewChangeDelegate(t, "d1", bc, alwaysNo),
		makeViewChangeDelegate(t, "d2", bc, alwaysNo),
		makeViewChangeDelegate(t, "d3", bc, alwaysNo),
		makeViewChangeDelegate(t, "d4", bc, alwaysNo),
	}
	bc.InitializeShards(1)
	bc.Shards[0].TransactionPool = []Transaction{
		{Sender: "a", Receiver: "b", Amount: 1, Nonce: 1},
	}

	// Assign a fresh Events channel so we can read emitted events.
	bc.Events = make(chan StreamEvent, 10)

	done := make(chan struct{})
	go func() {
		bc.createBlock(nil)
		close(done)
	}()

	maxWait := time.Duration(len(bc.Delegates))*bc.ConsensusTimeout + 500*time.Millisecond
	select {
	case <-done:
		// Good — returned within the expected window.
	case <-time.After(maxWait):
		t.Fatal("createBlock did not return within expected time")
	}

	// No block must have been appended.
	assert.Len(t, bc.Blocks, 1, "genesis only — no block should be sealed on total failure")

	// EventConsensusFailure must have been emitted.
	found := false
	for len(bc.Events) > 0 {
		ev := <-bc.Events
		if ev.Type == EventConsensusFailure {
			found = true
		}
	}
	assert.True(t, found, "EventConsensusFailure event must be emitted on total failure")
}

// ---------------------------------------------------------------------------
// Step D (success path): retry loop eventually seals the block
// ---------------------------------------------------------------------------

// TestViewChange_RetryLoop_SucceedsOnLaterView verifies the scenario described
// in the Item 9 acceptance criteria: with Byzantine delegates that cooperate
// starting from view 2, consensus is achieved without manual intervention.
//
// Setup: 4 delegates, 2 cooperate always, 2 are Byzantine for the first 2
// calls then cooperate. Threshold = ⌈2×4/3⌉ = 3.
//
//	View 0 (attempt 0): 2 yes + 2 no → 2 < 3 → fail, view-change.
//	View 1 (attempt 1): 2 yes + 2 no → 2 < 3 → fail, view-change.
//	View 2 (attempt 2): 4 yes → 4 ≥ 3 → consensus sealed.
func TestViewChange_RetryLoop_SucceedsOnLaterView(t *testing.T) {
	bc := newTestBlockchain(t)

	alwaysYes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}

	// Two honest delegates (always yes).
	d1 := makeViewChangeDelegate(t, "d1", bc, alwaysYes)
	d2 := makeViewChangeDelegate(t, "d2", bc, alwaysYes)
	// Two Byzantine delegates: vote no for first 2 calls, then cooperate.
	d3 := makeViewChangeDelegate(t, "d3", bc, byzantineAfterN(2))
	d4 := makeViewChangeDelegate(t, "d4", bc, byzantineAfterN(2))

	bc.Delegates = []Node{d1, d2, d3, d4}
	bc.InitializeShards(1)
	bc.Shards[0].TransactionPool = []Transaction{
		{Sender: "a", Receiver: "b", Amount: 1, Nonce: 1},
	}

	bc.createBlock(nil)

	// A block must have been sealed (genesis + 1).
	require.Len(t, bc.Blocks, 2, "a block must be sealed once Byzantine delegates cooperate")
}

// TestViewChange_TwoByzantine_SevenDelegates verifies the second acceptance
// criterion: with 7 delegates and 2 Byzantine (non-cooperating for 2 views),
// consensus completes within the retry window.
//
// Threshold = ⌈2×7/3⌉ = 5.
//
//	Views 0–1: 5 yes + 2 no → wait, 5 ≥ 5 → consensus succeeds in view 0!
//
// Actually with 7 delegates the threshold is 5 and only 2 Byzantine, so
// 5 honest delegates satisfy the threshold immediately. This test confirms
// that the retry loop correctly short-circuits on the first attempt when
// sufficient honest delegates are present.
func TestViewChange_TwoByzantine_SevenDelegates_ConsensusImmediate(t *testing.T) {
	bc := newTestBlockchain(t)

	alwaysYes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}
	alwaysNo := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return false }}

	delegates := make([]Node, 7)
	for i := 0; i < 5; i++ {
		delegates[i] = makeViewChangeDelegate(t, fmt.Sprintf("d%d", i+1), bc, alwaysYes)
	}
	for i := 5; i < 7; i++ {
		delegates[i] = makeViewChangeDelegate(t, fmt.Sprintf("d%d", i+1), bc, alwaysNo)
	}

	bc.Delegates = delegates
	bc.InitializeShards(1)
	bc.Shards[0].TransactionPool = []Transaction{
		{Sender: "a", Receiver: "b", Amount: 1, Nonce: 1},
	}

	bc.createBlock(nil)

	require.Len(t, bc.Blocks, 2,
		"7 delegates, 2 Byzantine voting no: 5 yes ≥ threshold 5, must seal in view 0")
}

// ---------------------------------------------------------------------------
// Step C: ProcessMessages advances view on f+1 ViewChangeReq messages
// ---------------------------------------------------------------------------

// TestViewChange_ProcessMessages_AdvancesView verifies that a node running
// ProcessMessages() advances bc.currentView to the requested view when it
// receives f+1 matching ViewChangeRequest messages (where f = (n-1)/3).
//
// With 4 delegates: f = 1, so f+1 = 2 messages are sufficient.
func TestViewChange_ProcessMessages_AdvancesView(t *testing.T) {
	bc := newTestBlockchain(t)

	alwaysYes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}
	delegates := make([]Node, 4)
	for i := 0; i < 4; i++ {
		delegates[i] = makeViewChangeDelegate(t, fmt.Sprintf("d%d", i+1), bc, alwaysYes)
	}
	bc.Delegates = delegates

	// Observer node processes messages on behalf of the blockchain.
	n := NewNode("observer", bc)

	done := make(chan struct{})
	go func() {
		n.ProcessMessages()
		close(done)
	}()

	// Send exactly f+1 = 2 requests for view 1 — the threshold needed to trigger
	// a view-change.
	n.Inbox <- Message{
		Type:    ViewChangeReq,
		Payload: ViewChangeRequest{View: 1, NodeID: "d1", Reason: "timeout"},
	}
	n.Inbox <- Message{
		Type:    ViewChangeReq,
		Payload: ViewChangeRequest{View: 1, NodeID: "d2", Reason: "timeout"},
	}

	// Close the inbox so ProcessMessages returns after draining all pending messages.
	close(n.Inbox)
	<-done

	assert.Equal(t, 1, bc.currentView.Number,
		"view must advance to 1 after receiving f+1 ViewChangeReq messages")
}

// TestViewChange_ProcessMessages_BelowThreshold_NoAdvance verifies that fewer
// than f+1 requests do NOT trigger a view-change.
func TestViewChange_ProcessMessages_BelowThreshold_NoAdvance(t *testing.T) {
	bc := newTestBlockchain(t)

	alwaysYes := &FuncVotingStrategy{VoteFunc: func(_ Block) bool { return true }}
	delegates := make([]Node, 4)
	for i := 0; i < 4; i++ {
		delegates[i] = makeViewChangeDelegate(t, fmt.Sprintf("d%d", i+1), bc, alwaysYes)
	}
	bc.Delegates = delegates

	n := NewNode("observer", bc)

	done := make(chan struct{})
	go func() {
		n.ProcessMessages()
		close(done)
	}()

	// Send only 1 request (f+1 = 2 required) — should NOT trigger a view-change.
	n.Inbox <- Message{
		Type:    ViewChangeReq,
		Payload: ViewChangeRequest{View: 1, NodeID: "d1", Reason: "timeout"},
	}

	close(n.Inbox)
	<-done

	assert.Equal(t, 0, bc.currentView.Number,
		"view must NOT advance when fewer than f+1 view-change requests are received")
}

// TestViewChange_StartConsensus_NeverBlocksIndefinitely verifies that a
// createBlock call with a non-zero ConsensusTimeout returns within
// len(Delegates)*ConsensusTimeout + a small buffer, satisfying the liveness
// guarantee from the Item 9 acceptance criteria.
func TestViewChange_StartConsensus_NeverBlocksIndefinitely(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.ConsensusTimeout = 10 * time.Millisecond

	// All delegates block for 50 ms (longer than ConsensusTimeout) so
	// AchieveConsensus times out on every attempt.
	blocking := &FuncVotingStrategy{VoteFunc: func(_ Block) bool {
		time.Sleep(50 * time.Millisecond)
		return true
	}}

	bc.Delegates = []Node{
		makeViewChangeDelegate(t, "d1", bc, blocking),
		makeViewChangeDelegate(t, "d2", bc, blocking),
		makeViewChangeDelegate(t, "d3", bc, blocking),
	}
	bc.InitializeShards(1)
	bc.Shards[0].TransactionPool = []Transaction{
		{Sender: "a", Receiver: "b", Amount: 1, Nonce: 1},
	}

	deadline := time.Duration(len(bc.Delegates))*bc.ConsensusTimeout + 500*time.Millisecond

	done := make(chan struct{})
	go func() {
		bc.createBlock(nil)
		close(done)
	}()

	select {
	case <-done:
		// Good — returned within deadline.
	case <-time.After(deadline):
		t.Fatalf("createBlock blocked longer than %v (len(delegates)*ConsensusTimeout + buffer)", deadline)
	}
}
