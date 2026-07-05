package gonetwork

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ValidateLEI / leiCheckDigits
// ---------------------------------------------------------------------------

func TestValidateLEI_Empty(t *testing.T) {
	assert.NoError(t, ValidateLEI(""), "empty LEI is accepted (optional field)")
}

func TestValidateLEI_ValidRoundTrip(t *testing.T) {
	lei := newTestLEI(t, "549300ACMECORP0001")
	assert.NoError(t, ValidateLEI(lei))
}

func TestValidateLEI_WrongLength(t *testing.T) {
	assert.Error(t, ValidateLEI("TOOSHORT"))
	assert.Error(t, ValidateLEI(newTestLEI(t, "549300ACMECORP0001")+"X"))
}

func TestValidateLEI_InvalidCharacters(t *testing.T) {
	lei := newTestLEI(t, "549300ACMECORP0001")
	lowercased := lei[:19] + "a"
	assert.Error(t, ValidateLEI(lowercased))

	withSymbol := "!" + lei[1:]
	assert.Error(t, ValidateLEI(withSymbol))
}

func TestValidateLEI_TamperedCheckDigitsFail(t *testing.T) {
	prefix := "549300ACMECORP0001"
	check, err := leiCheckDigits(prefix)
	require.NoError(t, err)
	valid := prefix + check
	require.NoError(t, ValidateLEI(valid))

	// Changing the last check digit by +1 mod 10 always invalidates the
	// checksum: the last character contributes its value directly to the
	// running MOD-97 remainder, and a difference of 1-9 can never be a
	// multiple of 97.
	lastDigit := valid[19] - '0'
	newLastDigit := byte((int(lastDigit)+1)%10) + '0'
	tampered := valid[:19] + string(newLastDigit)
	assert.Error(t, ValidateLEI(tampered))
}

func TestValidateLEI_TamperedBodyFails(t *testing.T) {
	prefix := "549300ACMECORP0001"
	check, err := leiCheckDigits(prefix)
	require.NoError(t, err)
	valid := prefix + check
	require.NoError(t, ValidateLEI(valid))

	// Mutate one character in the body — checksum must now fail.
	mutated := []byte(valid)
	if mutated[0] == 'A' {
		mutated[0] = 'B'
	} else {
		mutated[0] = 'A'
	}
	assert.Error(t, ValidateLEI(string(mutated)))
}

// ---------------------------------------------------------------------------
// EntityRegistry
// ---------------------------------------------------------------------------

func newTestLEI(t *testing.T, prefix18 string) string {
	t.Helper()
	check, err := leiCheckDigits(prefix18)
	require.NoError(t, err)
	return prefix18 + check
}

func TestEntityRegistry_RegisterGetList(t *testing.T) {
	reg := NewEntityRegistry()
	lei := newTestLEI(t, "549300ACMECORP0001")

	entity := &LegalEntityIdentity{
		LEI:          lei,
		LegalName:    "Acme Capital Partners Ltd",
		Jurisdiction: "GB",
	}
	require.NoError(t, reg.RegisterEntity(entity))
	assert.Equal(t, EntityStatusPending, entity.Status, "defaults to pending")
	assert.NotZero(t, entity.CreatedAt)

	got, err := reg.GetEntity(lei)
	require.NoError(t, err)
	assert.Equal(t, "Acme Capital Partners Ltd", got.LegalName)

	all := reg.ListEntities()
	assert.Len(t, all, 1)
}

func TestEntityRegistry_RegisterRejectsInvalidInput(t *testing.T) {
	reg := NewEntityRegistry()

	err := reg.RegisterEntity(nil)
	assert.Error(t, err)

	err = reg.RegisterEntity(&LegalEntityIdentity{LEI: "not-a-valid-lei", LegalName: "X", Jurisdiction: "GB"})
	assert.Error(t, err, "invalid LEI checksum must be rejected")

	lei := newTestLEI(t, "549300ACMECORP0002")
	err = reg.RegisterEntity(&LegalEntityIdentity{LEI: lei, LegalName: "", Jurisdiction: "GB"})
	assert.Error(t, err, "empty legal name must be rejected")

	err = reg.RegisterEntity(&LegalEntityIdentity{LEI: lei, LegalName: "X", Jurisdiction: "ZZ"})
	assert.Error(t, err, "invalid jurisdiction must be rejected")
}

func TestEntityRegistry_DuplicateLEIRejected(t *testing.T) {
	reg := NewEntityRegistry()
	lei := newTestLEI(t, "549300ACMECORP0003")
	entity := &LegalEntityIdentity{LEI: lei, LegalName: "Acme", Jurisdiction: "GB"}
	require.NoError(t, reg.RegisterEntity(entity))

	dup := &LegalEntityIdentity{LEI: lei, LegalName: "Acme Again", Jurisdiction: "GB"}
	assert.Error(t, reg.RegisterEntity(dup))
}

func TestEntityRegistry_UpdateEntityStatus(t *testing.T) {
	reg := NewEntityRegistry()
	lei := newTestLEI(t, "549300ACMECORP0004")
	require.NoError(t, reg.RegisterEntity(&LegalEntityIdentity{LEI: lei, LegalName: "Acme", Jurisdiction: "GB"}))

	require.NoError(t, reg.UpdateEntityStatus(lei, EntityStatusActive))
	got, err := reg.GetEntity(lei)
	require.NoError(t, err)
	assert.Equal(t, EntityStatusActive, got.Status)

	assert.Error(t, reg.UpdateEntityStatus("nonexistent-lei", EntityStatusActive))
}

// ---------------------------------------------------------------------------
// EntityRoleClaimData / ParseEntityRoleClaim / HasEntityRole
// ---------------------------------------------------------------------------

func TestEntityRoleClaimData_RoundTrip(t *testing.T) {
	lei := newTestLEI(t, "549300ACMECORP0005")
	data := EntityRoleClaimData(lei, EntityRoleSPVAdmin)

	claim := &Claim{Topic: ClaimTopicInstitutionalRole, Data: data}
	parsedLEI, parsedRole, err := ParseEntityRoleClaim(claim)
	require.NoError(t, err)
	assert.Equal(t, lei, parsedLEI)
	assert.Equal(t, EntityRoleSPVAdmin, parsedRole)
}

func TestParseEntityRoleClaim_RejectsWrongTopicOrMalformedData(t *testing.T) {
	_, _, err := ParseEntityRoleClaim(nil)
	assert.Error(t, err)

	_, _, err = ParseEntityRoleClaim(&Claim{Topic: ClaimTopicKYC, Data: "irrelevant"})
	assert.Error(t, err, "wrong topic must be rejected")

	_, _, err = ParseEntityRoleClaim(&Claim{Topic: ClaimTopicInstitutionalRole, Data: "no-separator"})
	assert.Error(t, err, "malformed data must be rejected")
}

func TestHasEntityRole(t *testing.T) {
	bc := newClaimsTestBlockchain(t)
	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	lei := newTestLEI(t, "549300ACMECORP0006")
	walletKey := "wallet-spv-admin"

	claim, err := NewClaim(ClaimTopicInstitutionalRole, "", walletKey, EntityRoleClaimData(lei, EntityRoleSPVAdmin), 30, issuerKey)
	require.NoError(t, err)
	bc.Claims[walletKey] = []*Claim{claim}

	assert.True(t, HasEntityRole(bc, walletKey, lei, EntityRoleSPVAdmin))
	assert.False(t, HasEntityRole(bc, walletKey, lei, EntityRoleDirector), "different role must not match")
	assert.False(t, HasEntityRole(bc, walletKey, "SOME-OTHER-LEI-00000", EntityRoleSPVAdmin), "different LEI must not match")
	assert.False(t, HasEntityRole(bc, "unknown-wallet", lei, EntityRoleSPVAdmin))
}

func TestSPVAdminHasRoleClaim(t *testing.T) {
	bc := newClaimsTestBlockchain(t)
	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	lei := newTestLEI(t, "549300ACMECORP0007")

	spv := &SPVWrapper{
		ID:          "spv-1",
		SPVAdminKey: "admin-wallet-key",
		EntityLEI:   lei,
	}
	assert.False(t, SPVAdminHasRoleClaim(bc, spv, lei), "no role claim issued yet")

	claim, err := NewClaim(ClaimTopicInstitutionalRole, "", spv.SPVAdminKey, EntityRoleClaimData(lei, EntityRoleSPVAdmin), 30, issuerKey)
	require.NoError(t, err)
	bc.Claims[spv.SPVAdminKey] = []*Claim{claim}

	assert.True(t, SPVAdminHasRoleClaim(bc, spv, lei))
	assert.False(t, SPVAdminHasRoleClaim(bc, nil, lei))
}
