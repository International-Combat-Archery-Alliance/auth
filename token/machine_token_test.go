package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/golang-jwt/jwt/v5"
)

func TestValidateMachineTokenHappyPath(t *testing.T) {
	keys := rsaKeys(t, "machine-01")
	cache := setupVerifiedCache(t, keys)

	claims, err := cache.ValidateMachineToken(context.Background(), validToken(t, keys, "machine-01"), testAudience, testScope)
	if err != nil {
		t.Fatalf("expected valid machine token to pass: %v", err)
	}
	if claims.Subject != testClientID {
		t.Fatalf("expected sub %q, got %q", testClientID, claims.Subject)
	}
	if claims.TokenType != TokenTypeMachine {
		t.Fatalf("expected token_type machine, got %q", claims.TokenType)
	}
	if !slicesContains(claims.Audience, testAudience) {
		t.Fatalf("expected aud %q in %v", testAudience, claims.Audience)
	}
	if !slicesContains(claims.Roles, testScope) {
		t.Fatalf("expected scope %q in %v", testScope, claims.Roles)
	}
}

func TestValidateMachineTokenSignerRoundTrip(t *testing.T) {
	keys := rsaKeys(t, "machine-01")
	cache := setupVerifiedCache(t, keys)

	signer, err := NewMachineTokenSigner(keys, "machine-01")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	signed, err := signer.Sign(testClientID, testAudience, []string{testScope})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	claims, err := cache.ValidateMachineToken(context.Background(), signed, testAudience, testScope)
	if err != nil {
		t.Fatalf("signer output must verify: %v", err)
	}
	if claims.Subject != testClientID {
		t.Fatalf("expected sub %q, got %q", testClientID, claims.Subject)
	}

	// 5-minute default lifetime.
	if got := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time); got != DefaultMachineTokenLifetime {
		t.Fatalf("expected default lifetime %v, got %v", DefaultMachineTokenLifetime, got)
	}
}

func TestValidateMachineTokenRejections(t *testing.T) {
	keys := rsaKeys(t, "machine-01")
	cache := setupVerifiedCache(t, keys)
	ctx := context.Background()

	t.Run("wrong audience", func(t *testing.T) {
		if _, err := cache.ValidateMachineToken(ctx, validToken(t, keys, "machine-01"), "voting-api", testScope); err == nil {
			t.Fatal("expected aud mismatch to fail")
		}
	})

	t.Run("multi-aud rejected (exact, not contains)", func(t *testing.T) {
		claims := MachineTokenClaims{
			TokenType: TokenTypeMachine,
			Roles:     []string{testScope},
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   testClientID,
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				Issuer:    DefaultIssuer,
				Audience:  jwt.ClaimStrings{testAudience, "voting-api"},
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "machine-01"
		signed, err := tok.SignedString(keys["machine-01"])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := cache.ValidateMachineToken(ctx, signed, testAudience, testScope); err == nil {
			t.Fatal("expected multi-aud token to be rejected (audience must match exactly)")
		}
	})

	t.Run("wrong scope", func(t *testing.T) {
		if _, err := cache.ValidateMachineToken(ctx, validToken(t, keys, "machine-01"), testAudience, "m2m:other"); err == nil {
			t.Fatal("expected scope mismatch to fail")
		}
	})

	t.Run("scope prefix is not a match", func(t *testing.T) {
		// Required scope "m2m:player" must NOT match token scope "m2m:player-profiles".
		if _, err := cache.ValidateMachineToken(ctx, validToken(t, keys, "machine-01"), testAudience, "m2m:player"); err == nil {
			t.Fatal("expected prefix scope match to fail (scope matching is exact)")
		}
	})

	t.Run("missing scope", func(t *testing.T) {
		tok := signMachine(t, keys["machine-01"], testClientID, testAudience, []string{"m2m:profiles"}, "machine-01")
		if _, err := cache.ValidateMachineToken(ctx, tok, testAudience, testScope); err == nil {
			t.Fatal("expected missing scope to fail")
		}
	})

	t.Run("empty roles", func(t *testing.T) {
		tok := signMachine(t, keys["machine-01"], testClientID, testAudience, nil, "machine-01")
		if _, err := cache.ValidateMachineToken(ctx, tok, testAudience, testScope); err == nil {
			t.Fatal("expected empty roles to fail")
		}
	})

	t.Run("missing sub", func(t *testing.T) {
		tok := signMachine(t, keys["machine-01"], "", testAudience, []string{testScope}, "machine-01")
		if _, err := cache.ValidateMachineToken(ctx, tok, testAudience, testScope); err == nil {
			t.Fatal("expected missing sub to fail")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		tok := signMachine(t, keys["machine-01"], testClientID, testAudience, []string{testScope}, "machine-01")
		// Rewrite exp to the past by signing a fresh variant.
		tok = signMachineAt(t, keys["machine-01"], testClientID, testAudience, []string{testScope}, "machine-01", time.Now().Add(-5*time.Minute))
		if _, err := cache.ValidateMachineToken(ctx, tok, testAudience, testScope); err == nil {
			t.Fatal("expected expired token to fail")
		}
	})

	t.Run("token_type access", func(t *testing.T) {
		claims := ICAAClaims{
			Email:     "user@icaa.world",
			Roles:     []auth.Role{auth.RoleAdmin},
			TokenType: TokenTypeAccess,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   testClientID,
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				Issuer:    DefaultIssuer,
				Audience:  jwt.ClaimStrings{testAudience},
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "machine-01"
		signed, err := tok.SignedString(keys["machine-01"])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := cache.ValidateMachineToken(ctx, signed, testAudience, testScope); err == nil {
			t.Fatal("expected token_type=access to be rejected on the machine path")
		}
	})
}

func TestValidateMachineTokenAlgConfusion(t *testing.T) {
	keys := rsaKeys(t, "machine-01")
	cache := setupVerifiedCache(t, keys)
	ctx := context.Background()

	t.Run("HS256 signed with public key bytes", func(t *testing.T) {
		// Classic alg-confusion attack: sign with HS256 using the public key
		// PKIX DER as the "secret". Must be rejected.
		der, err := x509.MarshalPKIXPublicKey(&keys["machine-01"].PublicKey)
		if err != nil {
			t.Fatalf("marshal public key: %v", err)
		}
		claims := MachineTokenClaims{
			TokenType: TokenTypeMachine,
			Roles:     []string{testScope},
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   testClientID,
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				Issuer:    DefaultIssuer,
				Audience:  jwt.ClaimStrings{testAudience},
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tok.Header["kid"] = "machine-01"
		signed, err := tok.SignedString(der)
		if err != nil {
			t.Fatalf("sign hs256: %v", err)
		}
		if _, err := cache.ValidateMachineToken(ctx, signed, testAudience, testScope); err == nil {
			t.Fatal("expected HS256 token to be rejected (alg confusion)")
		}
	})

	t.Run("alg none", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, MachineTokenClaims{
			TokenType: TokenTypeMachine,
			Roles:     []string{testScope},
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   testClientID,
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				Issuer:    DefaultIssuer,
				Audience:  jwt.ClaimStrings{testAudience},
			},
		})
		tok.Header["kid"] = "machine-01"
		signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("sign none: %v", err)
		}
		if _, err := cache.ValidateMachineToken(ctx, signed, testAudience, testScope); err == nil {
			t.Fatal("expected alg=none token to be rejected")
		}
	})
}

func TestValidateMachineTokenKidNamespace(t *testing.T) {
	keys := rsaKeys(t, "machine-01", "user-01")
	cache := setupVerifiedCache(t, keys)

	t.Run("user kid rejected on machine path", func(t *testing.T) {
		tok := signMachine(t, keys["user-01"], testClientID, testAudience, []string{testScope}, "user-01")
		if _, err := cache.ValidateMachineToken(context.Background(), tok, testAudience, testScope); err == nil {
			t.Fatal("expected user-* kid to be rejected on the machine path")
		}
	})

	t.Run("missing kid", func(t *testing.T) {
		claims := MachineTokenClaims{
			TokenType: TokenTypeMachine,
			Roles:     []string{testScope},
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   testClientID,
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				Issuer:    DefaultIssuer,
				Audience:  jwt.ClaimStrings{testAudience},
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signed, err := tok.SignedString(keys["machine-01"])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := cache.ValidateMachineToken(context.Background(), signed, testAudience, testScope); err == nil {
			t.Fatal("expected missing kid to fail")
		}
	})
}

func TestNewMachineTokenSignerValidation(t *testing.T) {
	keys := rsaKeys(t, "machine-01")

	t.Run("non-machine kid rejected", func(t *testing.T) {
		bad := map[string]*rsa.PrivateKey{"user-01": keys["machine-01"]}
		if _, err := NewMachineTokenSigner(bad, "user-01"); err == nil {
			t.Fatal("expected non-machine kid to be rejected")
		}
	})

	t.Run("weak key rejected", func(t *testing.T) {
		weak, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("generate weak key: %v", err)
		}
		weakKeys := map[string]*rsa.PrivateKey{"machine-weak": weak}
		if _, err := NewMachineTokenSigner(weakKeys, "machine-weak"); err == nil {
			t.Fatal("expected <2048-bit signing key to be rejected")
		}
	})
}

func TestValidateMachineTokenClaimHardening(t *testing.T) {
	keys := rsaKeys(t, "machine-01")
	cache := setupVerifiedCache(t, keys)
	ctx := context.Background()

	t.Run("future iat rejected", func(t *testing.T) {
		claims := MachineTokenClaims{
			TokenType: TokenTypeMachine,
			Roles:     []string{testScope},
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   testClientID,
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				Issuer:    DefaultIssuer,
				Audience:  jwt.ClaimStrings{testAudience},
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "machine-01"
		signed, err := tok.SignedString(keys["machine-01"])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := cache.ValidateMachineToken(ctx, signed, testAudience, testScope); err == nil {
			t.Fatal("expected token with future iat to be rejected")
		}
	})

	t.Run("missing exp rejected", func(t *testing.T) {
		claims := MachineTokenClaims{
			TokenType: TokenTypeMachine,
			Roles:     []string{testScope},
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  testClientID,
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Issuer:   DefaultIssuer,
				Audience: jwt.ClaimStrings{testAudience},
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "machine-01"
		signed, err := tok.SignedString(keys["machine-01"])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := cache.ValidateMachineToken(ctx, signed, testAudience, testScope); err == nil {
			t.Fatal("expected token without exp to be rejected")
		}
	})

	t.Run("missing aud rejected", func(t *testing.T) {
		claims := MachineTokenClaims{
			TokenType: TokenTypeMachine,
			Roles:     []string{testScope},
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   testClientID,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				Issuer:    DefaultIssuer,
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "machine-01"
		signed, err := tok.SignedString(keys["machine-01"])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := cache.ValidateMachineToken(ctx, signed, testAudience, testScope); err == nil {
			t.Fatal("expected token without aud to be rejected")
		}
	})

	t.Run("expired beyond leeway rejected", func(t *testing.T) {
		// exp in the past but within the 10s leeway window is allowed; beyond
		// it is not.
		tok := signMachineAt(t, keys["machine-01"], testClientID, testAudience, []string{testScope}, "machine-01", time.Now().Add(-30*time.Second))
		if _, err := cache.ValidateMachineToken(ctx, tok, testAudience, testScope); err == nil {
			t.Fatal("expected token expired beyond leeway to be rejected")
		}
	})
}

func TestUserTokenValidationRejectsMachineTokens(t *testing.T) {
	// The user-token claims validator must never accept token_type=machine
	// (user routes reject machine tokens structurally).
	claims := &ICAAClaims{TokenType: TokenTypeMachine}
	if err := claims.Validate(); err == nil {
		t.Fatal("expected user claims Validate() to reject token_type=machine")
	}
	if err := (&MachineTokenClaims{TokenType: TokenTypeAccess}).Validate(); err == nil {
		t.Fatal("expected machine claims Validate() to reject token_type=access")
	}
}

func TestValidateMachineTokenUnknownKidBubblesErrUnknownKey(t *testing.T) {
	keys := rsaKeys(t, "machine-01")
	cache := setupVerifiedCache(t, keys)

	tok := signMachine(t, keys["machine-01"], testClientID, testAudience, []string{testScope}, "machine-nope")
	_, err := cache.ValidateMachineToken(context.Background(), tok, testAudience, testScope)
	if err == nil {
		t.Fatal("expected unknown kid to fail verification")
	}
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey reachable via errors.Is, got %v", err)
	}
}
