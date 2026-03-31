package token

import (
	"fmt"
	"slices"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/golang-jwt/jwt/v5"
)

// TokenType represents the type of ICAA token
type TokenType string

const (
	// TokenTypeAccess is a short-lived access token
	TokenTypeAccess TokenType = "access"
	// TokenTypeRefresh is a long-lived refresh token
	TokenTypeRefresh TokenType = "refresh"
)

// ICAAClaims represents the custom claims for ICAA JWT tokens
type ICAAClaims struct {
	Email     string      `json:"email"`
	Roles     []auth.Role `json:"roles"`
	Picture   string      `json:"picture"`
	TokenType TokenType   `json:"token_type"`
	jwt.RegisteredClaims
}

// Validate performs custom validation on the claims
func (c ICAAClaims) Validate() error {
	if c.Email == "" {
		return fmt.Errorf("email claim is required")
	}
	if c.TokenType != TokenTypeAccess && c.TokenType != TokenTypeRefresh {
		return fmt.Errorf("invalid token type: %s", c.TokenType)
	}
	return nil
}

// IsAdmin checks if the user has the ADMIN role
func (c ICAAClaims) IsAdmin() bool {
	return slices.Contains(c.Roles, auth.RoleAdmin)
}

// ExpiresAt returns the expiration time of the token
func (c ICAAClaims) ExpiresAt() time.Time {
	if c.RegisteredClaims.ExpiresAt == nil {
		return time.Time{}
	}
	return c.RegisteredClaims.ExpiresAt.Time
}
