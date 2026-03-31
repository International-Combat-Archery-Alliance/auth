package token

import "errors"

var (
	// ErrTokenNotFound is returned when a refresh token doesn't exist in the store
	ErrTokenNotFound = errors.New("refresh token not found")
	// ErrTokenExpired is returned when a refresh token has expired
	ErrTokenExpired = errors.New("refresh token expired")
)
