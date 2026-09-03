package token

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// userLeeway is the clock-skew tolerance for user tokens.
const userLeeway = 30 * time.Second

// buildUserParser returns an RS256-only parser for user tokens with the
// given expected issuer and audience. It pins the signing method and
// requires exp and iat.
func buildUserParser(issuer, audience string) *jwt.Parser {
	return jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(userLeeway),
	)
}

// parseUserTokenClaims parses tokenString as ICAAClaims, resolving the kid
// through lookup. Only RS256 tokens with a user- namespaced kid are accepted.
func parseUserTokenClaims(parser *jwt.Parser, tokenString string, lookup func(kid string) (*rsa.PublicKey, error)) (*ICAAClaims, error) {
	claims := &ICAAClaims{}

	tok, err := parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("token missing kid")
		}
		if !strings.HasPrefix(kid, UserKidPrefix) {
			return nil, fmt.Errorf("unexpected kid namespace %q (user tokens must use %q*)", kid, UserKidPrefix)
		}
		return lookup(kid)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse user token: %w", err)
	}
	if !tok.Valid {
		return nil, fmt.Errorf("user token is invalid")
	}
	return claims, nil
}

// validateUserToken parses tokenString as ICAAClaims with user-* kid binding
// and returns the claims. Callers enforce the expected token_type.
func (c *KeyCache) validateUserToken(ctx context.Context, tokenString string) (*ICAAClaims, error) {
	return parseUserTokenClaims(c.userParser, tokenString, func(kid string) (*rsa.PublicKey, error) {
		return c.Key(ctx, kid)
	})
}

// ValidateUserAccessToken verifies a user access token and returns the claims.
// It rejects tokens with any other token_type, including machine tokens.
func (c *KeyCache) ValidateUserAccessToken(ctx context.Context, tokenString string) (*ICAAClaims, error) {
	claims, err := c.validateUserToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != TokenTypeAccess {
		return nil, fmt.Errorf("expected access token, got %s", claims.TokenType)
	}
	if err := claims.Validate(); err != nil {
		return nil, err
	}
	return claims, nil
}

// ValidateUserRefreshToken verifies a user refresh token and returns the
// token ID.
func (c *KeyCache) ValidateUserRefreshToken(ctx context.Context, tokenString string) (string, error) {
	claims, err := c.validateUserToken(ctx, tokenString)
	if err != nil {
		return "", err
	}

	if claims.TokenType != TokenTypeRefresh {
		return "", fmt.Errorf("expected refresh token, got %s", claims.TokenType)
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("refresh token missing sub (token ID)")
	}
	return claims.Subject, nil
}
