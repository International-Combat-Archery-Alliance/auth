package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// TokenTypeMachine is the token_type claim value for machine (m2m) tokens.
	TokenTypeMachine TokenType = "machine"
	// MachineKidPrefix namespaces machine-token keys. User-token keys use
	// the "user-" namespace.
	MachineKidPrefix = "machine-"
	// DefaultMachineTokenLifetime is the default exp for machine tokens.
	DefaultMachineTokenLifetime = 5 * time.Minute
)

// MachineTokenClaims are the claims of a machine (m2m) JWT:
// {sub: clientId, token_type: machine, roles: [m2m:<callee-scope>],
// aud: <callee>-api, iss: icaa.world, exp: 5min}.
type MachineTokenClaims struct {
	TokenType TokenType `json:"token_type"`
	// Roles carries the exact m2m scope string(s) the token was minted for.
	// Scope matching is EXACT, never prefix.
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

// Validate performs custom claim validation. It is a separate type from
// ICAAClaims on purpose: machine tokens NEVER flow through the user-token
// validation path (user routes reject token_type=machine structurally — the
// access-token validator only accepts "access"/"refresh").
func (c *MachineTokenClaims) Validate() error {
	if c.TokenType != TokenTypeMachine {
		return fmt.Errorf("invalid token type: %s", c.TokenType)
	}
	return nil
}

// MachineTokenSigner signs machine JWTs (RS256, kid namespace "machine-*").
// Private keys must never be distributed to token verifiers.
type MachineTokenSigner struct {
	keys         map[string]*rsa.PrivateKey
	currentKeyID string
	issuer       string
	lifetime     time.Duration
}

// MachineTokenSignerOption configures a MachineTokenSigner.
type MachineTokenSignerOption func(*MachineTokenSigner)

// WithMachineTokenIssuer overrides the iss claim (default: icaa.world,
// matching user-token issuance).
func WithMachineTokenIssuer(issuer string) MachineTokenSignerOption {
	return func(s *MachineTokenSigner) {
		s.issuer = issuer
	}
}

// WithMachineTokenLifetime overrides the token lifetime (default: 5 minutes).
func WithMachineTokenLifetime(d time.Duration) MachineTokenSignerOption {
	return func(s *MachineTokenSigner) {
		s.lifetime = d
	}
}

// NewMachineTokenSigner creates a signer for the given RS256 private keys.
// currentKeyID selects which key signs new tokens; all keys remain available
// so a retired kid can still be validated during rotation.
func NewMachineTokenSigner(keys map[string]*rsa.PrivateKey, currentKeyID string, opts ...MachineTokenSignerOption) (*MachineTokenSigner, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("no machine signing keys provided")
	}
	if _, ok := keys[currentKeyID]; !ok {
		return nil, fmt.Errorf("current key ID %q not found in signing keys", currentKeyID)
	}

	s := &MachineTokenSigner{
		keys:         keys,
		currentKeyID: currentKeyID,
		issuer:       DefaultIssuer,
		lifetime:     DefaultMachineTokenLifetime,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// Sign mints a machine token for the given clientId, with a callee-specific
// audience and the exact scope(s) that client is allowed (aud is per-callee,
// never a global audience).
func (s *MachineTokenSigner) Sign(clientID string, audience string, scopes []string) (string, error) {
	now := time.Now()
	claims := MachineTokenClaims{
		TokenType: TokenTypeMachine,
		Roles:     scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   clientID,
			ExpiresAt: jwt.NewNumericDate(now.Add(s.lifetime)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{audience},
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = s.currentKeyID

	signed, err := tok.SignedString(s.keys[s.currentKeyID])
	if err != nil {
		return "", fmt.Errorf("failed to sign machine token: %w", err)
	}
	return signed, nil
}

// ValidateMachineToken verifies a machine JWT against the key cache: RS256
// only with machine-* kid binding, iss=icaa.world, exp required, iat
// validated, 10s leeway, token_type=machine, sub present. Audience is
// callee-specific and requiredScope must match EXACTLY (never prefix). Fail
// closed: no key for the kid -> error, never "allow".
func (c *KeyCache) ValidateMachineToken(ctx context.Context, tokenString string, audience string, requiredScope string) (*MachineTokenClaims, error) {
	claims := &MachineTokenClaims{}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithAudience(audience),
		jwt.WithIssuer(DefaultIssuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		// 10s leeway: tokens live 5 minutes, clocks are NTP-synced.
		jwt.WithLeeway(10*time.Second),
	)

	tok, err := parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("token missing kid")
		}
		if !strings.HasPrefix(kid, MachineKidPrefix) {
			return nil, fmt.Errorf("unexpected kid namespace %q (machine tokens must use %q*)", kid, MachineKidPrefix)
		}
		return c.Key(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse machine token: %w", err)
	}
	if !tok.Valid {
		return nil, fmt.Errorf("machine token is invalid")
	}
	if err := claims.Validate(); err != nil {
		return nil, err
	}
	// jwt/v5 auto-invokes Validate(); explicit call kept as defense-in-depth.
	if claims.Subject == "" {
		return nil, fmt.Errorf("machine token missing sub (clientId)")
	}

	// EXACT scope match, never prefix.
	if !slices.Contains(claims.Roles, requiredScope) {
		return nil, fmt.Errorf("machine token is missing required scope %q", requiredScope)
	}

	return claims, nil
}

// GenerateMachineDevKeypair creates a development RSA keypair for local
// development (LOCAL mode). Prod code must assert !isLocal() before using it;
// auth lib callers only ever install the public key via WithDevKeys.
func GenerateMachineDevKeypair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate dev RSA keypair: %w", err)
	}
	return priv, &priv.PublicKey, nil
}
