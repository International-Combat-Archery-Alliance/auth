package google

import (
	"context"
	"fmt"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"google.golang.org/api/idtoken"
)

var _ auth.Validator[*idtoken.Payload] = &Validator{}

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

func (v *Validator) Validate(ctx context.Context, token string, audience string) (auth.AuthToken[*idtoken.Payload], error) {
	payload, err := v.validator.Validate(ctx, token, audience)
	if err != nil {
		return auth.AuthToken[*idtoken.Payload]{}, fmt.Errorf("failed to validate token: %w", err)
	}

	return auth.AuthToken[*idtoken.Payload]{
		RawToken: payload,

		ExpiresAt:     expiresAt(payload),
		IsAdmin:       isAdmin(payload),
		ProfilePicURL: profilePictureURL(payload),
	}, nil
}

func isAdmin(payload *idtoken.Payload) bool {
	if payload == nil {
		return false
	}

	org, ok := payload.Claims["hd"]
	if !ok {
		return false
	}
	if org != "icaa.world" {
		return false
	}

	return true
}

func profilePictureURL(payload *idtoken.Payload) string {
	if payload == nil {
		return ""
	}

	pic, ok := payload.Claims["picture"]
	if !ok {
		return ""
	}
	picAsStr, ok := pic.(string)
	if !ok {
		return ""
	}

	return picAsStr
}

func expiresAt(payload *idtoken.Payload) time.Time {
	if payload == nil {
		return time.Time{}
	}

	return time.Unix(payload.Expires, 0)
}
