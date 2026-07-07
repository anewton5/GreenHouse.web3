package gonetwork

// ---------------------------------------------------------------------------
// Phase 3 — Institutional / vLEI-Ready Identity Model
//
// This is an INTERNAL data model only: LegalEntityIdentity is deliberately
// schema-compatible with GLEIF's public LEI reference data (ISO 17442 + the
// vLEI's chained-credential role model) so that a future GLEIFQVIProvider can
// populate EntityRegistry from a real Qualified vLEI Issuer credential without
// a schema change — but no live GLEIF integration exists yet (see the plan
// doc's explicit scope decision: vLEI internal model only, QVI integration
// deferred).
//
// Institutional roles (authorised signatory, UBO, director, SPV admin) are
// modelled as ClaimTopicInstitutionalRole claims, reusing the Phase 2
// claim-topic infrastructure (claims.go) rather than introducing a parallel
// role system.
// ---------------------------------------------------------------------------

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// LegalEntityIdentity
// ---------------------------------------------------------------------------

// EntityStatus tracks the lifecycle of a LegalEntityIdentity record.
type EntityStatus string

const (
	// EntityStatusPending — self-declared, not yet reviewed by an operator.
	EntityStatusPending EntityStatus = "pending"
	// EntityStatusActive — reviewed and accepted; may hold institutional roles.
	EntityStatusActive EntityStatus = "active"
	// EntityStatusInactive — dissolved, superseded, or rejected.
	EntityStatusInactive EntityStatus = "inactive"
)

// LegalEntityIdentity is GreenHouse's internal record of a legal entity
// (institutional issuer, custodian, market maker, SPV administrator, etc.).
// Fields deliberately mirror the public GLEIF LEI record schema (ISO 17442 +
// Level 1 "who is who" reference data) so a future GLEIFQVIProvider can
// populate this struct from a real vLEI credential without a schema change.
type LegalEntityIdentity struct {
	LEI          string       `json:"lei"` // ISO 17442, 20 chars
	LegalName    string       `json:"legal_name"`
	Jurisdiction string       `json:"jurisdiction"` // ISO 3166-1 alpha-2, country of incorporation
	Status       EntityStatus `json:"status"`

	// DIDWebs is an optional did:webs-resolvable identifier (GLEIF vLEI uses
	// did:webs for discoverability). Stored as an opaque string; GreenHouse
	// does not resolve it today.
	DIDWebs string `json:"did_webs,omitempty"`

	// RegisteredAddressHash is the SHA-256 hex hash of the registered address
	// document, mirroring IdentityDocument's PII-minimisation pattern.
	RegisteredAddressHash string `json:"registered_address_hash,omitempty"`

	CreatedAt int64 `json:"created_at"`
	UpdatedAt int64 `json:"updated_at"`
	// RegisteredBy is the admin wallet key that registered this entity.
	RegisteredBy string `json:"registered_by,omitempty"`
}

// ValidateLEI returns an error if lei does not conform to ISO 17442 (20
// uppercase alphanumeric characters, ISO/IEC 7064 MOD 97-10 check-digit
// validation — the same checksum algorithm used for IBAN). An empty string is
// accepted (LEI is optional pending full Phase 3 institutional rollout).
// Mirrors ValidateISIN's structural + checksum validation pattern in assets.go.
func ValidateLEI(lei string) error {
	if lei == "" {
		return nil
	}
	if len(lei) != 20 {
		return fmt.Errorf("LEI must be exactly 20 characters (ISO 17442); got %d", len(lei))
	}
	for i, c := range lei {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return fmt.Errorf("LEI position %d must be uppercase alphanumeric; got %q", i, c)
		}
	}

	remainder, err := leiMod97(lei)
	if err != nil {
		return err
	}
	if remainder != 1 {
		return fmt.Errorf("LEI %q has invalid check digits (ISO 7064 MOD 97-10 failed)", lei)
	}
	return nil
}

// leiMod97 computes the running ISO/IEC 7064 MOD 97-10 remainder over s,
// expanding letters to their numeric value (A=10 … Z=35) exactly as IBAN
// validation does. s must contain only uppercase letters and digits.
func leiMod97(s string) (int, error) {
	remainder := 0
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			v := int(c-'A') + 10
			remainder = (remainder*10 + v/10) % 97
			remainder = (remainder*10 + v%10) % 97
		case c >= '0' && c <= '9':
			remainder = (remainder*10 + int(c-'0')) % 97
		default:
			return 0, fmt.Errorf("invalid character %q in LEI", c)
		}
	}
	return remainder, nil
}

// leiCheckDigits computes the 2-digit ISO 17442 check digits for an
// 18-character LEI prefix (4-char LOU code + "00" reserved + entity-specific
// part, or any 18-char alphanumeric prefix), using the ISO/IEC 7064 MOD 97-10
// algorithm. Used by tests to construct a self-consistent test LEI without
// needing a real GLEIF-issued identifier.
func leiCheckDigits(prefix18 string) (string, error) {
	if len(prefix18) != 18 {
		return "", fmt.Errorf("LEI prefix must be exactly 18 characters, got %d", len(prefix18))
	}
	remainder, err := leiMod97(prefix18 + "00")
	if err != nil {
		return "", err
	}
	check := 98 - remainder
	return fmt.Sprintf("%02d", check), nil
}

// ---------------------------------------------------------------------------
// Institutional roles (ClaimTopicInstitutionalRole)
// ---------------------------------------------------------------------------

// EntityRole enumerates the roles a wallet may hold with respect to a
// LegalEntityIdentity. Carried in a ClaimTopicInstitutionalRole Claim's Data
// field as "<LEI>:<role>" (see EntityRoleClaimData / ParseEntityRoleClaim).
type EntityRole string

const (
	EntityRoleAuthorisedSignatory EntityRole = "authorised_signatory"
	EntityRoleUBO                 EntityRole = "ubo"
	EntityRoleDirector            EntityRole = "director"
	EntityRoleSPVAdmin            EntityRole = "spv_admin"
	EntityRoleMarketMaker         EntityRole = "market_maker"
)

// entityRoleDataSeparator joins an LEI and role into a Claim.Data string.
// Safe because a valid LEI is strictly alphanumeric (ISO 17442) and never
// contains ':', so the split below is always unambiguous.
const entityRoleDataSeparator = ":"

// EntityRoleClaimData builds the Claim.Data payload for a
// ClaimTopicInstitutionalRole claim: "<LEI>:<role>". Issue such a claim via
// IdentityRegistry.IssueClaim(walletKey, ClaimTopicInstitutionalRole,
// EntityRoleClaimData(lei, role), validForDays) — this reuses the Phase 2
// claim-issuance machinery rather than introducing a parallel signing path.
func EntityRoleClaimData(lei string, role EntityRole) string {
	return lei + entityRoleDataSeparator + string(role)
}

// ParseEntityRoleClaim extracts the LEI and EntityRole from a
// ClaimTopicInstitutionalRole claim's Data field. Returns an error if c is
// nil, not a claim of that topic, or Data is malformed.
func ParseEntityRoleClaim(c *Claim) (lei string, role EntityRole, err error) {
	if c == nil || c.Topic != ClaimTopicInstitutionalRole {
		return "", "", fmt.Errorf("claim is not a %q claim", ClaimTopicInstitutionalRole)
	}
	parts := strings.SplitN(c.Data, entityRoleDataSeparator, 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("malformed institutional role claim data %q", c.Data)
	}
	return parts[0], EntityRole(parts[1]), nil
}

// HasEntityRole returns true if walletKey currently holds a valid
// ClaimTopicInstitutionalRole claim asserting role within the legal entity
// identified by lei. Consults EffectiveClaims (real claims only —
// institutional role is not something the legacy CredentialAttestation
// adapter can imply).
func HasEntityRole(bc *Blockchain, walletKey string, lei string, role EntityRole) bool {
	for _, c := range EffectiveClaims(bc, walletKey) {
		claimLEI, claimRole, err := ParseEntityRoleClaim(c)
		if err != nil {
			continue
		}
		if claimLEI == lei && claimRole == role {
			return true
		}
	}
	return false
}

// SPVAdminHasRoleClaim returns true if spv's administrator wallet holds a
// valid "spv_admin" institutional role claim for entityLEI.
//
// This is an additive, non-breaking cross-check: existing SPV authorisation
// (spv.SPVAdminKey == caller wallet key, enforced in api/handlers.go) remains
// the primary gate. This function is intended for audit/reporting use, or as
// a secondary signal, until institutional role claims have been populated for
// every existing SPV administrator.
func SPVAdminHasRoleClaim(bc *Blockchain, spv *SPVWrapper, entityLEI string) bool {
	if spv == nil {
		return false
	}
	return HasEntityRole(bc, spv.SPVAdminKey, entityLEI, EntityRoleSPVAdmin)
}

// ---------------------------------------------------------------------------
// EntityRegistry
// ---------------------------------------------------------------------------

// EntityIdentityProvider abstracts legal-entity identity storage and lookup,
// so a real GLEIF Qualified vLEI Issuer (QVI) integration can later replace
// EntityRegistry's manual/self-declared entry without changing call sites.
type EntityIdentityProvider interface {
	RegisterEntity(entity *LegalEntityIdentity) error
	GetEntity(lei string) (*LegalEntityIdentity, error)
	ListEntities() []*LegalEntityIdentity
	UpdateEntityStatus(lei string, status EntityStatus) error
}

// EntityRegistry is a concurrency-safe in-memory EntityIdentityProvider, keyed
// by LEI. Entries are manually/self-declared today (an admin registers an
// entity's LEI + legal name + jurisdiction after off-chain verification) —
// swappable for a real GLEIFQVIProvider later without changing call sites.
type EntityRegistry struct {
	mu       sync.RWMutex
	entities map[string]*LegalEntityIdentity // LEI -> entity
}

// NewEntityRegistry returns an empty EntityRegistry.
func NewEntityRegistry() *EntityRegistry {
	return &EntityRegistry{entities: make(map[string]*LegalEntityIdentity)}
}

// RegisterEntity validates and stores a new LegalEntityIdentity. Returns an
// error if the LEI is invalid, required fields are missing, or an entity with
// the same LEI is already registered.
func (er *EntityRegistry) RegisterEntity(entity *LegalEntityIdentity) error {
	if entity == nil {
		return fmt.Errorf("entity must not be nil")
	}
	if err := ValidateLEI(entity.LEI); err != nil {
		return fmt.Errorf("invalid LEI: %w", err)
	}
	if entity.LEI == "" {
		return fmt.Errorf("LEI is required")
	}
	if strings.TrimSpace(entity.LegalName) == "" {
		return fmt.Errorf("legal_name is required")
	}
	if !IsValidISO3166(entity.Jurisdiction) {
		return fmt.Errorf("%q is not a valid ISO 3166-1 alpha-2 country code", entity.Jurisdiction)
	}

	er.mu.Lock()
	defer er.mu.Unlock()
	if _, exists := er.entities[entity.LEI]; exists {
		return fmt.Errorf("entity with LEI %s is already registered", entity.LEI)
	}
	now := time.Now().Unix()
	entity.CreatedAt = now
	entity.UpdatedAt = now
	if entity.Status == "" {
		entity.Status = EntityStatusPending
	}
	er.entities[entity.LEI] = entity
	return nil
}

// GetEntity returns the registered entity for lei, or an error if not found.
func (er *EntityRegistry) GetEntity(lei string) (*LegalEntityIdentity, error) {
	er.mu.RLock()
	defer er.mu.RUnlock()
	e, ok := er.entities[lei]
	if !ok {
		return nil, fmt.Errorf("no entity registered for LEI %s", lei)
	}
	return e, nil
}

// ListEntities returns all registered entities.
func (er *EntityRegistry) ListEntities() []*LegalEntityIdentity {
	er.mu.RLock()
	defer er.mu.RUnlock()
	out := make([]*LegalEntityIdentity, 0, len(er.entities))
	for _, e := range er.entities {
		out = append(out, e)
	}
	return out
}

// UpdateEntityStatus transitions an entity to a new status (e.g. from pending
// to active after operator review, or to inactive on dissolution/rejection).
func (er *EntityRegistry) UpdateEntityStatus(lei string, status EntityStatus) error {
	er.mu.Lock()
	defer er.mu.Unlock()
	e, ok := er.entities[lei]
	if !ok {
		return fmt.Errorf("no entity registered for LEI %s", lei)
	}
	e.Status = status
	e.UpdatedAt = time.Now().Unix()
	return nil
}
