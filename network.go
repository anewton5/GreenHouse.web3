package gonetwork

type MessageType string

const (
	BlockProposal MessageType = "BlockProposal"
	Vote          MessageType = "Vote"
	Consensus     MessageType = "Consensus"
)

type Message struct {
	From    string
	To      string
	Type    MessageType
	Payload interface{}
}
