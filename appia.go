package gonetwork

// ---------------------------------------------------------------------------
// Appia — ECB tokenised financial ecosystem blueprint (2025–2028)
// ---------------------------------------------------------------------------
//
// The Eurosystem's Appia initiative (launched 2025) is developing a blueprint
// for a European tokenised financial ecosystem, with findings delivered by 2028.
// This file defines the interface stubs that GreenHouse will implement as the
// Appia technical specifications are published.
//
// Integration path:
//  1. Q3 2026 — GreenHouse connects to Pontes pilot as a Market DLT Operator,
//     establishing operator credentials referenced here.
//  2. 2027–2028 — ECB publishes Appia technical standards for cross-network
//     identity, asset metadata, DVP interoperability proofs, and compliance
//     data sharing. Methods on AppiaComplianceAdapter are populated at that time.
//  3. 2028+ — GreenHouse implements AppiaComplianceAdapter, enabling
//     interoperability with other Appia-registered Market DLT platforms.
//
// References:
//   - ECB Appia roadmap (March 2026): https://www.ecb.europa.eu/paym/dlt/appia/html/index.en.html
//   - ECB Pontes pilot: https://www.ecb.europa.eu/paym/target/pontes/html/index.en.html

// AppiaNetwork identifies a DLT network participating in the Appia ecosystem.
type AppiaNetwork string

const (
	// AppiaNetworkGreenHouse is GreenHouse's identifier as a Market DLT Operator
	// in the Appia ecosystem. This value will be confirmed by the Eurosystem
	// during the Pontes operator registration process (target Q3 2026).
	AppiaNetworkGreenHouse AppiaNetwork = "greenhouse"
)

// AppiaComplianceAdapter is the interface that bridges GreenHouse's on-chain
// compliance layer to the Appia ecosystem's common standards. It is
// intentionally empty at this stage — its presence establishes the integration
// point so that implementing Appia standards requires only adding methods here
// and a concrete implementation, without touching core settlement or compliance logic.
//
// Expected areas (to be populated as ECB publishes technical specifications):
//   - Cross-network identity claim portability  (Appia §3.x)
//   - Common tokenised asset metadata schema    (Appia §4.x)
//   - Interoperability proofs for cross-network DVP (Appia §5.x)
//   - Compliance data sharing between Market DLT Operators (Appia §6.x)
type AppiaComplianceAdapter interface {
	// Methods will be added here as the ECB publishes technical specifications.
}

// AppiaMarketDLTOperator holds the registration metadata for GreenHouse as a
// Market DLT Operator under the Appia/Pontes framework. This struct is populated
// during Pontes pilot operator onboarding (target Q3 2026) and stored on-chain
// so that any network participant can verify GreenHouse's Eurosystem credentials.
type AppiaMarketDLTOperator struct {
	// OperatorID is assigned by the Eurosystem upon registration.
	OperatorID string `json:"operator_id"`

	// DLTNetwork identifies the network. Always AppiaNetworkGreenHouse for this node.
	DLTNetwork AppiaNetwork `json:"dlt_network"`

	// PontesParticipantBIC is the BIC of the Eurosystem participant (custodian or
	// CSD) that acts as T2 counterpart for the CeBM cash leg of DVP settlements.
	PontesParticipantBIC string `json:"pontes_participant_bic"`

	// RegisteredAt is the Unix timestamp of operator registration.
	RegisteredAt int64 `json:"registered_at"`

	// Active indicates whether this operator registration is currently valid.
	Active bool `json:"active"`
}
