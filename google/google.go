package google

import (
	"context"
	"fmt"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"google.golang.org/api/idtoken"
)

var _ auth.Validator = &Validator{}

type Validator struct {
	validator *idtoken.Validator
}

func NewValidator(ctx context.Context) (*Validator, error) {
	validator, err := idtoken.NewValidator(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create google id verifier: %w", err)
	}

	return &Validator{
		validator: validator,
	}, nil
}

func (v *Validator) Validate(ctx context.Context, token string, audience string) (auth.AuthToken, error) {
	payload, err := v.validator.Validate(ctx, token, audience)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	return &GoogleAuthToken{Payload: payload}, nil
}

var _ auth.AuthToken = &GoogleAuthToken{}

type GoogleAuthToken struct {
	Payload *idtoken.Payload
}

func (t *GoogleAuthToken) IsAdmin() bool {
	if t.Payload == nil {
		return false
	}

	org, ok := t.Payload.Claims["hd"]
	if !ok {
		return false
	}
	if org != "icaa.world" {
		return false
	}

	return true
}

func (t *GoogleAuthToken) ProfilePicURL() string {
	if t.Payload == nil {
		return ""
	}

	pic, ok := t.Payload.Claims["picture"]
	if !ok {
		return ""
	}
	picAsStr, ok := pic.(string)
	if !ok {
		return ""
	}

	return picAsStr
}

func (t *GoogleAuthToken) ExpiresAt() time.Time {
	if t.Payload == nil {
		return time.Time{}
	}

	return time.Unix(t.Payload.Expires, 0)
}

func (t *GoogleAuthToken) UserEmail() string {
	if t.Payload == nil {
		return ""
	}

	email, ok := t.Payload.Claims["email"]
	if !ok {
		return ""
	}

	emailStr, ok := email.(string)
	if !ok {
		return ""
	}

	return emailStr
}
