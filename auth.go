package auth

import (
	"context"
	"time"
)

type AuthToken interface {
	ExpiresAt() time.Time
	ProfilePicURL() string
	IsAdmin() bool
	UserEmail() string
}

type Validator interface {
	Validate(ctx context.Context, token string, audience string) (AuthToken, error)
}
