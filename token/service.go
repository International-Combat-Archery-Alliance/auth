package token

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/golang-jwt/jwt/v5"
)

// SigningKey represents a key used for signing JWTs
type SigningKey struct {
	ID  string
	Key []byte
}

// TokenService handles JWT token generation and validation
type TokenService struct {
	signingKeys          map[string]SigningKey
	currentKeyID         string
	accessTokenLifetime  time.Duration
	refreshTokenLifetime time.Duration
	issuer               string
	audience             string
}

// TokenServiceOption is a functional option for configuring TokenService
type TokenServiceOption func(*TokenService)

// Default token lifetimes
const (
	DefaultAccessTokenLifetime  = 1 * time.Hour
	DefaultRefreshTokenLifetime = 30 * 24 * time.Hour // 30 days
)

// Default issuer and audience
const (
	DefaultIssuer   = "icaa.world"
	DefaultAudience = "icaa-api"
)

// NewTokenService creates a new TokenService with the given signing key and options.
// Uses sensible defaults for all configuration values.
func NewTokenService(signingKey SigningKey, opts ...TokenServiceOption) *TokenService {
	s := &TokenService{
		signingKeys: map[string]SigningKey{
			signingKey.ID: signingKey,
		},
		currentKeyID:         signingKey.ID,
		accessTokenLifetime:  DefaultAccessTokenLifetime,
		refreshTokenLifetime: DefaultRefreshTokenLifetime,
		issuer:               DefaultIssuer,
		audience:             DefaultAudience,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// WithSigningKeys configures multiple signing keys for key rotation support.
// The currentKeyID specifies which key to use for signing new tokens.
// All keys in the map can be used for validation.
func WithSigningKeys(keys map[string]SigningKey, currentKeyID string) TokenServiceOption {
	return func(s *TokenService) {
		s.signingKeys = keys
		s.currentKeyID = currentKeyID
	}
}

// WithAccessTokenLifetime sets the lifetime for access tokens.
func WithAccessTokenLifetime(d time.Duration) TokenServiceOption {
	return func(s *TokenService) {
		s.accessTokenLifetime = d
	}
}

// WithRefreshTokenLifetime sets the lifetime for refresh tokens.
func WithRefreshTokenLifetime(d time.Duration) TokenServiceOption {
	return func(s *TokenService) {
		s.refreshTokenLifetime = d
	}
}

// WithIssuer sets the JWT issuer claim.
func WithIssuer(issuer string) TokenServiceOption {
	return func(s *TokenService) {
		s.issuer = issuer
	}
}

// WithAudience sets the JWT audience claim.
func WithAudience(audience string) TokenServiceOption {
	return func(s *TokenService) {
		s.audience = audience
	}
}

// getSigningKey retrieves a signing key by its ID
func (s *TokenService) getSigningKey(keyID string) ([]byte, error) {
	key, ok := s.signingKeys[keyID]
	if !ok {
		return nil, fmt.Errorf("unknown key ID: %s", keyID)
	}
	return key.Key, nil
}

// getCurrentSigningKey retrieves the current signing key
func (s *TokenService) getCurrentSigningKey() ([]byte, error) {
	return s.getSigningKey(s.currentKeyID)
}

// GenerateAccessToken creates a new access token for the given user
func (s *TokenService) GenerateAccessToken(email string, picture string, roles []auth.Role) (string, error) {
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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = s.currentKeyID

	signingKey, err := s.getCurrentSigningKey()
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return signedToken, nil
}

// GenerateRefreshToken creates a new refresh token and returns the token ID, signed token, and expiration time
func (s *TokenService) GenerateRefreshToken() (tokenID string, signedToken string, expiresAt time.Time, err error) {
	// Generate a random token ID
	tokenIDBytes := make([]byte, 32)
	if _, err := rand.Read(tokenIDBytes); err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to generate token ID: %w", err)
	}
	tokenID = hex.EncodeToString(tokenIDBytes)

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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = s.currentKeyID

	signingKey, err := s.getCurrentSigningKey()
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to get signing key: %w", err)
	}

	signedToken, err = token.SignedString(signingKey)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return tokenID, signedToken, expiresAt, nil
}

// ValidateAccessToken validates an access token and returns the claims
func (s *TokenService) ValidateAccessToken(tokenString string) (*ICAAClaims, error) {
	claims := &ICAAClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID from header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token missing key ID")
		}

		return s.getSigningKey(kid)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	// Validate token type
	if claims.TokenType != TokenTypeAccess {
		return nil, fmt.Errorf("expected access token, got %s", claims.TokenType)
	}

	// Validate custom claims
	if err := claims.Validate(); err != nil {
		return nil, err
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token and returns the token ID
func (s *TokenService) ValidateRefreshToken(tokenString string) (tokenID string, err error) {
	claims := &ICAAClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token missing key ID")
		}

		return s.getSigningKey(kid)
	})

	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("token is invalid")
	}

	if claims.TokenType != TokenTypeRefresh {
		return "", fmt.Errorf("expected refresh token, got %s", claims.TokenType)
	}

	return claims.Subject, nil
}
