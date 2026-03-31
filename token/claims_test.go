package token

import (
	"testing"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/golang-jwt/jwt/v5"
)

func TestICAAClaimsValidate(t *testing.T) {
	tests := []struct {
		name    string
		claims  ICAAClaims
		wantErr bool
	}{
		{
			name: "valid access token claims",
			claims: ICAAClaims{
				Email:     "test@example.com",
				Roles:     []auth.Role{auth.RoleAdmin},
				Picture:   "https://example.com/pic.jpg",
				TokenType: TokenTypeAccess,
			},
			wantErr: false,
		},
		{
			name: "valid refresh token claims",
			claims: ICAAClaims{
				Email:     "test@example.com",
				TokenType: TokenTypeRefresh,
			},
			wantErr: false,
		},
		{
			name: "missing email",
			claims: ICAAClaims{
				Email:     "",
				TokenType: TokenTypeAccess,
			},
			wantErr: true,
		},
		{
			name: "invalid token type",
			claims: ICAAClaims{
				Email:     "test@example.com",
				TokenType: TokenType("invalid"),
			},
			wantErr: true,
		},
		{
			name: "empty token type",
			claims: ICAAClaims{
				Email:     "test@example.com",
				TokenType: TokenType(""),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claims.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestICAAClaimsIsAdmin(t *testing.T) {
	tests := []struct {
		name     string
		roles    []auth.Role
		expected bool
	}{
		{
			name:     "has admin role",
			roles:    []auth.Role{auth.RoleAdmin},
			expected: true,
		},
		{
			name:     "has admin role among others",
			roles:    []auth.Role{auth.Role("USER"), auth.RoleAdmin},
			expected: true,
		},
		{
			name:     "no admin role",
			roles:    []auth.Role{auth.Role("USER")},
			expected: false,
		},
		{
			name:     "empty roles",
			roles:    []auth.Role{},
			expected: false,
		},
		{
			name:     "nil roles",
			roles:    nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := ICAAClaims{Roles: tt.roles}
			got := claims.IsAdmin()
			if got != tt.expected {
				t.Errorf("IsAdmin() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestICAAClaimsExpiresAt(t *testing.T) {
	now := time.Now()
	expiry := now.Add(1 * time.Hour)
	// JWT numeric dates truncate to second precision
	jwtExpiry := expiry.Truncate(time.Second)

	tests := []struct {
		name     string
		claims   ICAAClaims
		expected time.Time
	}{
		{
			name: "with expiration",
			claims: ICAAClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(expiry),
				},
			},
			expected: jwtExpiry,
		},
		{
			name:     "without expiration",
			claims:   ICAAClaims{},
			expected: time.Time{},
		},
		{
			name: "nil expiration",
			claims: ICAAClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: nil,
				},
			},
			expected: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.claims.ExpiresAt()
			if !got.Equal(tt.expected) {
				t.Errorf("ExpiresAt() = %v, want %v", got, tt.expected)
			}
		})
	}
}
