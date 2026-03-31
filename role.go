package auth

// Role represents a user's role in the ICAA system
type Role string

const (
	// RoleAdmin grants administrative access to the system
	RoleAdmin Role = "ADMIN"
)

// IsValid checks if a role is valid
func (r Role) IsValid() bool {
	switch r {
	case RoleAdmin:
		return true
	default:
		return false
	}
}
