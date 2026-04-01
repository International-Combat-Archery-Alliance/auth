package token

import (
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
)

// ICAAAuthToken implements the auth.AuthToken interface using ICAAClaims
type ICAAAuthToken struct {
	claims *ICAAClaims
}

// NewICAAAuthToken creates a new ICAAAuthToken from claims
func NewICAAAuthToken(claims *ICAAClaims) *ICAAAuthToken {
	return &ICAAAuthToken{claims: claims}
}

// ExpiresAt returns when the token expires
func (t *ICAAAuthToken) ExpiresAt() time.Time {
	if t.claims == nil {
		return time.Time{}
	}
	return t.claims.ExpiresAt()
}

// ProfilePicURL returns the user's profile picture URL
func (t *ICAAAuthToken) ProfilePicURL() string {
	if t.claims == nil {
		return ""
	}
	return t.claims.Picture
}

// IsAdmin returns true if the user has the ADMIN role
func (t *ICAAAuthToken) IsAdmin() bool {
	if t.claims == nil {
		return false
	}
	return t.claims.IsAdmin()
}

// UserEmail returns the user's email
func (t *ICAAAuthToken) UserEmail() string {
	if t.claims == nil {
		return ""
	}
	return t.claims.Email
}

// Roles returns the user's roles
func (t *ICAAAuthToken) Roles() []auth.Role {
	if t.claims == nil {
		return []auth.Role{}
	}
	if t.claims.Roles == nil {
		return []auth.Role{}
	}
	return t.claims.Roles
}

// Claims returns the underlying claims (useful for accessing additional data)
func (t *ICAAAuthToken) Claims() *ICAAClaims {
	return t.claims
}

// Ensure ICAAAuthToken implements auth.AuthToken
var _ auth.AuthToken = (*ICAAAuthToken)(nil)
