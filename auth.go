package auth

import (
	"context"
	"time"
)

type AuthToken[T any] struct {
	RawToken T

	ExpiresAt     time.Time
	ProfilePicURL string
	IsAdmin       bool
}

type Validator[T any] interface {
	Validate(ctx context.Context, token string, audience string) (AuthToken[T], error)
}
