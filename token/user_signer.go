package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// UserKidPrefix is the required key ID namespace for user-token keys.
	UserKidPrefix = "user-"
)

// UserTokenSigner signs RS256 user JWTs.
type UserTokenSigner struct {
	keys                 map[string]*rsa.PrivateKey
	currentKeyID         string
	issuer               string
	audience             string
	accessTokenLifetime  time.Duration
	refreshTokenLifetime time.Duration
}

// UserTokenSignerOption configures a UserTokenSigner.
type UserTokenSignerOption func(*UserTokenSigner)

// WithUserTokenIssuer overrides the iss claim (default: icaa.world).
func WithUserTokenIssuer(issuer string) UserTokenSignerOption {
	return func(s *UserTokenSigner) {
		s.issuer = issuer
	}
}

// WithUserTokenAudience overrides the aud claim (default: icaa-api).
func WithUserTokenAudience(audience string) UserTokenSignerOption {
	return func(s *UserTokenSigner) {
		s.audience = audience
	}
}

// WithUserAccessTokenLifetime overrides the access-token lifetime
// (default: 1 hour).
func WithUserAccessTokenLifetime(d time.Duration) UserTokenSignerOption {
	return func(s *UserTokenSigner) {
		s.accessTokenLifetime = d
	}
}

// WithUserRefreshTokenLifetime overrides the refresh-token lifetime
// (default: 30 days).
func WithUserRefreshTokenLifetime(d time.Duration) UserTokenSignerOption {
	return func(s *UserTokenSigner) {
		s.refreshTokenLifetime = d
	}
}

// NewUserTokenSigner creates a signer for the given RS256 private keys.
// currentKeyID selects which key signs new tokens; all keys remain available
// for validation. Keys must use the user- namespace and be at least 2048 bits.
func NewUserTokenSigner(keys map[string]*rsa.PrivateKey, currentKeyID string, opts ...UserTokenSignerOption) (*UserTokenSigner, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("no user signing keys provided")
	}
	if _, ok := keys[currentKeyID]; !ok {
		return nil, fmt.Errorf("current key ID %q not found in signing keys", currentKeyID)
	}
	for kid, key := range keys {
		if key == nil {
			return nil, fmt.Errorf("user signing key %q is nil", kid)
		}
		if !strings.HasPrefix(kid, UserKidPrefix) {
			return nil, fmt.Errorf("user signing key %q must use %q* namespace", kid, UserKidPrefix)
		}
		if key.N.BitLen() < minKeyBits {
			return nil, fmt.Errorf("user signing key %q must be at least %d bits", kid, minKeyBits)
		}
	}

	s := &UserTokenSigner{
		keys:                 keys,
		currentKeyID:         currentKeyID,
		issuer:               DefaultIssuer,
		audience:             DefaultAudience,
		accessTokenLifetime:  DefaultAccessTokenLifetime,
		refreshTokenLifetime: DefaultRefreshTokenLifetime,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// GenerateAccessToken creates a new RS256 access token for the given user.
func (s *UserTokenSigner) GenerateAccessToken(email string, picture string, roles []auth.Role) (string, error) {
	now := time.Now()
	claims := ICAAClaims{
		Email:     email,
		Roles:     roles,
		Picture:   picture,
		TokenType: TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTokenLifetime)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{s.audience},
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = s.currentKeyID

	signed, err := tok.SignedString(s.keys[s.currentKeyID])
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}
	return signed, nil
}

// GenerateRefreshToken creates a new RS256 refresh token and returns the
// token ID, signed token, and expiration time.
func (s *UserTokenSigner) GenerateRefreshToken() (tokenID string, signedToken string, expiresAt time.Time, err error) {
	tokenIDBytes := make([]byte, 32)
	if _, err := rand.Read(tokenIDBytes); err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to generate token ID: %w", err)
	}
	tokenID = fmt.Sprintf("%x", tokenIDBytes)

	now := time.Now()
	expiresAt = now.Add(s.refreshTokenLifetime)
	claims := ICAAClaims{
		TokenType: TokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   tokenID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{s.audience},
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = s.currentKeyID

	signedToken, err = tok.SignedString(s.keys[s.currentKeyID])
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return tokenID, signedToken, expiresAt, nil
}

// PublicKeys returns the public halves of the signing keys.
func (s *UserTokenSigner) PublicKeys() map[string]*rsa.PublicKey {
	out := make(map[string]*rsa.PublicKey, len(s.keys))
	for kid, priv := range s.keys {
		out[kid] = &priv.PublicKey
	}
	return out
}

// localLookup resolves a kid against the signer's own keys.
func (s *UserTokenSigner) localLookup(kid string) (*rsa.PublicKey, error) {
	priv, ok := s.keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKey, kid)
	}
	return &priv.PublicKey, nil
}

// ValidateUserAccessToken verifies an access token against the signer's own
// keys and returns the claims.
func (s *UserTokenSigner) ValidateUserAccessToken(_ context.Context, tokenString string) (*ICAAClaims, error) {
	claims, err := parseUserTokenClaims(tokenString, s.localLookup)
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

// ValidateUserRefreshToken verifies a refresh token against the signer's own
// keys and returns the token ID.
func (s *UserTokenSigner) ValidateUserRefreshToken(_ context.Context, tokenString string) (string, error) {
	claims, err := parseUserTokenClaims(tokenString, s.localLookup)
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

// GenerateUserDevKeypair creates a 2048-bit RSA keypair for local development.
func GenerateUserDevKeypair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate dev RSA keypair: %w", err)
	}
	return priv, &priv.PublicKey, nil
}
