package token

import "time"

// Shared defaults for user-token issuance and validation.
const (
	// DefaultIssuer is the default iss claim.
	DefaultIssuer = "icaa.world"
	// DefaultAudience is the default aud claim for user tokens.
	DefaultAudience = "icaa-api"

	// DefaultAccessTokenLifetime is the default access-token lifetime.
	DefaultAccessTokenLifetime = 1 * time.Hour
	// DefaultRefreshTokenLifetime is the default refresh-token lifetime.
	DefaultRefreshTokenLifetime = 30 * 24 * time.Hour // 30 days
)
