package auth

import "testing"

func TestRoleIsValid(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		expected bool
	}{
		{
			name:     "admin role is valid",
			role:     RoleAdmin,
			expected: true,
		},
		{
			name:     "empty role is invalid",
			role:     Role(""),
			expected: false,
		},
		{
			name:     "unknown role is invalid",
			role:     Role("UNKNOWN"),
			expected: false,
		},
		{
			name:     "user role is invalid (not defined)",
			role:     Role("USER"),
			expected: false,
		},
		{
			name:     "lowercase admin is invalid",
			role:     Role("admin"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.role.IsValid()
			if got != tt.expected {
				t.Errorf("Role(%q).IsValid() = %v, want %v", tt.role, got, tt.expected)
			}
		})
	}
}
