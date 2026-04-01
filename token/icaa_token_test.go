package token

import (
	"testing"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/golang-jwt/jwt/v5"
)

func TestICAAAuthTokenExpiresAt(t *testing.T) {
	expiry := time.Now().Add(1 * time.Hour)
	// JWT numeric dates truncate to second precision
	jwtExpiry := expiry.Truncate(time.Second)

	tests := []struct {
		name     string
		claims   *ICAAClaims
		expected time.Time
	}{
		{
			name: "with claims and expiration",
			claims: &ICAAClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(expiry),
				},
			},
			expected: jwtExpiry,
		},
		{
			name:     "with nil claims",
			claims:   nil,
			expected: time.Time{},
		},
		{
			name:     "with claims but nil expiration",
			claims:   &ICAAClaims{},
			expected: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := NewICAAAuthToken(tt.claims)
			got := token.ExpiresAt()
			if !got.Equal(tt.expected) {
				t.Errorf("ExpiresAt() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestICAAAuthTokenProfilePicURL(t *testing.T) {
	tests := []struct {
		name     string
		claims   *ICAAClaims
		expected string
	}{
		{
			name: "with picture",
			claims: &ICAAClaims{
				Picture: "https://example.com/pic.jpg",
			},
			expected: "https://example.com/pic.jpg",
		},
		{
			name:     "with nil claims",
			claims:   nil,
			expected: "",
		},
		{
			name:     "with empty picture",
			claims:   &ICAAClaims{Picture: ""},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := NewICAAAuthToken(tt.claims)
			got := token.ProfilePicURL()
			if got != tt.expected {
				t.Errorf("ProfilePicURL() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestICAAAuthTokenIsAdmin(t *testing.T) {
	tests := []struct {
		name     string
		claims   *ICAAClaims
		expected bool
	}{
		{
			name: "is admin",
			claims: &ICAAClaims{
				Roles: []auth.Role{auth.RoleAdmin},
			},
			expected: true,
		},
		{
			name: "is not admin",
			claims: &ICAAClaims{
				Roles: []auth.Role{auth.Role("USER")},
			},
			expected: false,
		},
		{
			name:     "with nil claims",
			claims:   nil,
			expected: false,
		},
		{
			name:     "with empty roles",
			claims:   &ICAAClaims{Roles: []auth.Role{}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := NewICAAAuthToken(tt.claims)
			got := token.IsAdmin()
			if got != tt.expected {
				t.Errorf("IsAdmin() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestICAAAuthTokenUserEmail(t *testing.T) {
	tests := []struct {
		name     string
		claims   *ICAAClaims
		expected string
	}{
		{
			name: "with email",
			claims: &ICAAClaims{
				Email: "test@example.com",
			},
			expected: "test@example.com",
		},
		{
			name:     "with nil claims",
			claims:   nil,
			expected: "",
		},
		{
			name:     "with empty email",
			claims:   &ICAAClaims{Email: ""},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := NewICAAAuthToken(tt.claims)
			got := token.UserEmail()
			if got != tt.expected {
				t.Errorf("UserEmail() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestICAAAuthTokenRoles(t *testing.T) {
	tests := []struct {
		name     string
		claims   *ICAAClaims
		expected []auth.Role
	}{
		{
			name: "with roles",
			claims: &ICAAClaims{
				Roles: []auth.Role{auth.RoleAdmin, auth.Role("USER")},
			},
			expected: []auth.Role{auth.RoleAdmin, auth.Role("USER")},
		},
		{
			name:     "with nil claims",
			claims:   nil,
			expected: []auth.Role{},
		},
		{
			name:     "with empty roles",
			claims:   &ICAAClaims{Roles: []auth.Role{}},
			expected: []auth.Role{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := NewICAAAuthToken(tt.claims)
			got := token.Roles()

			if len(got) != len(tt.expected) {
				t.Errorf("Roles() length = %v, want %v", len(got), len(tt.expected))
				return
			}

			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("Roles()[%d] = %v, want %v", i, got[i], tt.expected[i])
				}
			}
		})
	}
}
