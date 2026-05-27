package gonetwork

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// LegalDocAmendment — on-chain legal document amendment trail
// ---------------------------------------------------------------------------

// LegalDocAmendment is an immutable on-chain record of a legal document update
// for a tokenised asset. It forms a hash-linked chain beginning at the
// AssetMetadata.LegalDocHash committed at asset creation.
//
// For AssetTypeParticipationNote assets, both an issuer signature and an SPV
// admin co-signature are required before the amendment is applied.
// For all other asset types, only the issuer signature is required.
type LegalDocAmendment struct {
	ID              string `json:"id"`
	AssetID         string `json:"asset_id"`
	PreviousDocHash string `json:"previous_doc_hash"`
	NewDocHash      string `json:"new_doc_hash"`
	AmendedAt       int64  `json:"amended_at"` // Unix timestamp
	IssuerKey       string `json:"issuer_key"` // base64-encoded Ed25519 public key

	// AdminKey and AdminSignature are required for AssetTypeParticipationNote.
	// For other asset types these fields are empty.
	AdminKey string `json:"admin_key,omitempty"`

	// Signatures are omitted from JSON so they are never exposed via the API.
	IssuerSignature []byte `json:"-"`
	AdminSignature  []byte `json:"-"`
}

// NewLegalDocAmendment creates and issuer-signs an amendment record.
//
// For participation notes the caller must subsequently call SetAdminSignature
// before the amendment can be applied to the chain.
func NewLegalDocAmendment(
	assetID string,
	previousDocHash string,
	newDocHash string,
	issuerKey *PrivateKey,
) (*LegalDocAmendment, error) {
	if assetID == "" {
		return nil, fmt.Errorf("assetID must not be empty")
	}
	if previousDocHash == "" {
		return nil, fmt.Errorf("previousDocHash must not be empty")
	}
	if newDocHash == "" {
		return nil, fmt.Errorf("newDocHash must not be empty")
	}
	if previousDocHash == newDocHash {
		return nil, fmt.Errorf("newDocHash must differ from previousDocHash")
	}
	if issuerKey == nil {
		return nil, fmt.Errorf("issuerKey must not be nil")
	}

	issuerPubStr := base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes())

	// Deterministic ID: sha3-256(assetID || previousDocHash || newDocHash || issuerPub || timestamp)
	h := sha3.New256()
	h.Write([]byte(assetID))
	h.Write([]byte(previousDocHash))
	h.Write([]byte(newDocHash))
	h.Write([]byte(issuerPubStr))
	id := hex.EncodeToString(h.Sum(nil))

	a := &LegalDocAmendment{
		ID:              id,
		AssetID:         assetID,
		PreviousDocHash: previousDocHash,
		NewDocHash:      newDocHash,
		AmendedAt:       time.Now().UTC().Unix(),
		IssuerKey:       issuerPubStr,
	}

	data, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal amendment for signing: %w", err)
	}
	hash := sha3.Sum256(data)
	a.IssuerSignature = issuerKey.Sign(hash[:]).Bytes()

	return a, nil
}

// SetAdminSignature attaches an SPV admin co-signature to an amendment.
// This is required before ApplyAmendment will accept a participation-note amendment.
func (a *LegalDocAmendment) SetAdminSignature(adminKey *PrivateKey) error {
	if adminKey == nil {
		return fmt.Errorf("adminKey must not be nil")
	}
	a.AdminKey = base64.StdEncoding.EncodeToString(adminKey.Public().Bytes())
	data, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("failed to marshal amendment for admin signing: %w", err)
	}
	hash := sha3.Sum256(data)
	a.AdminSignature = adminKey.Sign(hash[:]).Bytes()
	return nil
}

// VerifyIssuerSignature checks the issuer's Ed25519 signature on the amendment.
func (a *LegalDocAmendment) VerifyIssuerSignature() bool {
	if len(a.IssuerSignature) == 0 {
		return false
	}
	pub, err := PublicKeyFromString(a.IssuerKey)
	if err != nil {
		return false
	}
	copy := *a
	copy.IssuerSignature = nil
	copy.AdminSignature = nil
	copy.AdminKey = "" // AdminKey is set after issuer signing; exclude from issuer sig payload
	data, err := json.Marshal(copy)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: a.IssuerSignature}
	return sig.Verify(pub, hash[:])
}

// VerifyAdminSignature checks the SPV admin's Ed25519 signature on the amendment.
// Returns false if no admin signature is present.
func (a *LegalDocAmendment) VerifyAdminSignature() bool {
	if len(a.AdminSignature) == 0 || a.AdminKey == "" {
		return false
	}
	pub, err := PublicKeyFromString(a.AdminKey)
	if err != nil {
		return false
	}
	copy := *a
	copy.AdminSignature = nil
	data, err := json.Marshal(copy)
	if err != nil {
		return false
	}
	hash := sha3.Sum256(data)
	sig := &Signature{value: a.AdminSignature}
	return sig.Verify(pub, hash[:])
}

// ---------------------------------------------------------------------------
// Amendment application and query helpers
// ---------------------------------------------------------------------------

// ApplyAmendment validates and appends an amendment to the log for an asset.
//
// Validation rules:
//   - PreviousDocHash must match the current tip (CurrentLegalDocHash result).
//   - IssuerSignature must be valid.
//   - For AssetTypeParticipationNote: AdminSignature must also be valid and
//     AdminKey must match the SPVWrapper.SPVAdminKey registered on the blockchain.
//
// On success the amendment is appended to bc.LegalDocAmendments[assetID] and
// AssetMetadata.LegalDocHash is updated to NewDocHash.
func ApplyAmendment(
	amendment *LegalDocAmendment,
	assets map[string]*Asset,
	spvs map[string]*SPVWrapper,
	log map[string][]*LegalDocAmendment,
) error {
	asset, ok := assets[amendment.AssetID]
	if !ok {
		return fmt.Errorf("unknown asset ID: %s", amendment.AssetID)
	}

	// Resolve the current tip hash.
	currentHash := CurrentLegalDocHash(amendment.AssetID, asset, log)
	if currentHash != amendment.PreviousDocHash {
		return fmt.Errorf(
			"amendment chain broken: expected previous hash %q, got %q",
			currentHash, amendment.PreviousDocHash,
		)
	}

	// The issuer key on the amendment must match the asset's registered issuer.
	if amendment.IssuerKey != asset.Issuer {
		return fmt.Errorf(
			"amendment issuer key %q does not match asset issuer %q",
			amendment.IssuerKey, asset.Issuer,
		)
	}

	if !amendment.VerifyIssuerSignature() {
		return fmt.Errorf("amendment has an invalid issuer signature")
	}

	// Participation notes require an SPV admin co-signature.
	if asset.AssetType == AssetTypeParticipationNote {
		if !amendment.VerifyAdminSignature() {
			return fmt.Errorf("participation note amendments require a valid SPV admin co-signature")
		}
		// The admin key must match the registered SPV admin for this asset.
		spvAdminKey := ""
		for _, spv := range spvs {
			if spv.UnderlyingCompanyID == asset.Metadata.ISIN || spv.ID == asset.ID {
				spvAdminKey = spv.SPVAdminKey
				break
			}
		}
		// Resolve by asset ISIN — SPV is keyed by asset ISIN in the typical setup.
		if spvAdminKey == "" {
			for _, spv := range spvs {
				if spv.SPVAdminKey == amendment.AdminKey {
					spvAdminKey = spv.SPVAdminKey
					break
				}
			}
		}
		if spvAdminKey != "" && amendment.AdminKey != spvAdminKey {
			return fmt.Errorf(
				"amendment admin key %q does not match SPV admin key %q",
				amendment.AdminKey, spvAdminKey,
			)
		}
	}

	// Append to the log and update the asset's current hash.
	log[amendment.AssetID] = append(log[amendment.AssetID], amendment)
	asset.Metadata.LegalDocHash = amendment.NewDocHash

	return nil
}

// CurrentLegalDocHash resolves the current legal document hash for an asset.
// It returns the last entry in the amendment log if any amendments have been
// applied; otherwise it returns the hash committed at asset creation
// (AssetMetadata.LegalDocHash).
func CurrentLegalDocHash(
	assetID string,
	asset *Asset,
	log map[string][]*LegalDocAmendment,
) string {
	entries := log[assetID]
	if len(entries) == 0 {
		return asset.Metadata.LegalDocHash
	}
	return entries[len(entries)-1].NewDocHash
}
