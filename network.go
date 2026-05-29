package gonetwork

type MessageType string

const (
	BlockProposal MessageType = "BlockProposal"
	Vote          MessageType = "Vote"
	Consensus     MessageType = "Consensus"
	// ViewChangeReq / ViewChangeResp — Item 9: dBFT distributed view-change protocol.
	// ViewChangeReq is broadcast by a node when its AchieveConsensus round times out
	// or fails to reach supermajority, requesting all peers to advance to a new view.
	ViewChangeReq  MessageType = "view_change_request"
	ViewChangeResp MessageType = "view_change_response"
)

type Message struct {
	From    string
	To      string
	Type    MessageType
	Payload interface{}
}
