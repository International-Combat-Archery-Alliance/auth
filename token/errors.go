package token

import "errors"

var (
	// ErrTokenNotFound is returned when a refresh token doesn't exist in the store
	ErrTokenNotFound = errors.New("refresh token not found")
	// ErrTokenExpired is returned when a refresh token has expired
	ErrTokenExpired = errors.New("refresh token expired")
	// ErrUnknownKey is returned when no public key exists for a token's kid.
	// It is fail-closed: callers must treat it as an authentication failure (401).
	ErrUnknownKey = errors.New("unknown key id")
)
