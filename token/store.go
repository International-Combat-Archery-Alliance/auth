package token

import (
	"context"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
)

// RefreshTokenData holds all user data stored with a refresh token
type RefreshTokenData struct {
	UserEmail string
	Picture   string
	Roles     []auth.Role
}

// RefreshTokenStore defines the interface for storing and retrieving refresh tokens.
// Implementations should handle token persistence, lookup, and revocation.
type RefreshTokenStore interface {
	// Save stores a new refresh token with its associated user data and expiration time.
	// The tokenID should be a unique identifier for the token.
	Save(ctx context.Context, tokenID string, data RefreshTokenData, expiresAt time.Time) error

	// Get retrieves the user data associated with a refresh token ID.
	// Returns an error if the token doesn't exist or has been revoked.
	Get(ctx context.Context, tokenID string) (*RefreshTokenData, error)

	// Delete removes a refresh token from the store (used for logout or token rotation).
	Delete(ctx context.Context, tokenID string) error
}
