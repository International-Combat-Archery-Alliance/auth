package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/golang-jwt/jwt/v5"
)

func TestNewUserTokenSignerValidation(t *testing.T) {
	keys := rsaKeys(t, "user-01")

	t.Run("non-user kid rejected", func(t *testing.T) {
		bad := map[string]*rsa.PrivateKey{"machine-01": keys["user-01"]}
		if _, err := NewUserTokenSigner(bad, "machine-01"); err == nil {
			t.Fatal("expected non-user kid to be rejected")
		}
	})

	t.Run("weak key rejected", func(t *testing.T) {
		weak, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("generate weak key: %v", err)
		}
		if _, err := NewUserTokenSigner(map[string]*rsa.PrivateKey{"user-weak": weak}, "user-weak"); err == nil {
			t.Fatal("expected <2048-bit signing key to be rejected")
		}
	})

	t.Run("missing current key rejected", func(t *testing.T) {
		if _, err := NewUserTokenSigner(keys, "user-nope"); err == nil {
			t.Fatal("expected missing current key to be rejected")
		}
	})
}

func TestUserTokenSignerRoundTrip(t *testing.T) {
	keys := rsaKeys(t, "user-01")
	cache := setupVerifiedCache(t, keys)

	signer, err := NewUserTokenSigner(keys, "user-01")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	access, err := signer.GenerateAccessToken("user@icaa.world", "https://example.com/pic.jpg", []auth.Role{auth.RoleAdmin})
	if err != nil {
		t.Fatalf("sign access: %v", err)
	}
	claims, err := cache.ValidateUserAccessToken(t.Context(), access)
	if err != nil {
		t.Fatalf("signer access output must verify: %v", err)
	}
	if claims.Email != "user@icaa.world" {
		t.Fatalf("expected email, got %q", claims.Email)
	}

	refreshID, refresh, _, err := signer.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("sign refresh: %v", err)
	}
	gotID, err := cache.ValidateUserRefreshToken(t.Context(), refresh)
	if err != nil {
		t.Fatalf("signer refresh output must verify: %v", err)
	}
	if gotID != refreshID {
		t.Fatalf("expected refresh ID %q, got %q", refreshID, gotID)
	}

	// Default lifetimes: 1h access, 30d refresh.
	if got := claims.RegisteredClaims.ExpiresAt.Time.Sub(claims.RegisteredClaims.IssuedAt.Time); got != DefaultAccessTokenLifetime {
		t.Fatalf("expected access lifetime %v, got %v", DefaultAccessTokenLifetime, got)
	}
	_ = time.Now // keep time import if lifetimes change
}

func TestUserTokenSignerLocalValidation(t *testing.T) {
	keys := rsaKeys(t, "user-01")
	signer, err := NewUserTokenSigner(keys, "user-01")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	access, err := signer.GenerateAccessToken("u@icaa.world", "", nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := signer.ValidateUserAccessToken(t.Context(), access); err != nil {
		t.Fatalf("signer must validate its own access token: %v", err)
	}

	_, refresh, _, err := signer.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("sign refresh: %v", err)
	}
	if _, err := signer.ValidateUserRefreshToken(t.Context(), refresh); err != nil {
		t.Fatalf("signer must validate its own refresh token: %v", err)
	}

	// Unknown kid fails closed with ErrUnknownKey (same as KeyCache).
	other := rsaKeys(t, "user-02")
	otherSigner, err := NewUserTokenSigner(other, "user-02")
	if err != nil {
		t.Fatalf("new other signer: %v", err)
	}
	foreign, err := otherSigner.GenerateAccessToken("u@icaa.world", "", nil)
	if err != nil {
		t.Fatalf("sign foreign: %v", err)
	}
	_, err = signer.ValidateUserAccessToken(t.Context(), foreign)
	if err == nil {
		t.Fatal("expected unknown kid to fail")
	}
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey, got %v", err)
	}
}

func TestUserTokenSignerLocalAlgConfusion(t *testing.T) {
	keys := rsaKeys(t, "user-01")
	signer, err := NewUserTokenSigner(keys, "user-01")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	ctx := t.Context()

	t.Run("HS256 rejected", func(t *testing.T) {
		der, err := x509.MarshalPKIXPublicKey(&keys["user-01"].PublicKey)
		if err != nil {
			t.Fatalf("marshal public key: %v", err)
		}
		claims := ICAAClaims{
			Email:     "u@icaa.world",
			TokenType: TokenTypeAccess,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    DefaultIssuer,
				Audience:  jwt.ClaimStrings{DefaultAudience},
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tok.Header["kid"] = "user-01"
		signed, err := tok.SignedString(der)
		if err != nil {
			t.Fatalf("sign hs256: %v", err)
		}
		if _, err := signer.ValidateUserAccessToken(ctx, signed); err == nil {
			t.Fatal("expected HS256 token to be rejected by signer-local validation")
		}
	})

	t.Run("alg none rejected", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, ICAAClaims{
			Email:     "u@icaa.world",
			TokenType: TokenTypeAccess,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    DefaultIssuer,
				Audience:  jwt.ClaimStrings{DefaultAudience},
			},
		})
		tok.Header["kid"] = "user-01"
		signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("sign none: %v", err)
		}
		if _, err := signer.ValidateUserAccessToken(ctx, signed); err == nil {
			t.Fatal("expected alg=none token to be rejected by signer-local validation")
		}
	})
}

func TestUserTokenSignerMapCopied(t *testing.T) {
	keys := rsaKeys(t, "user-01")
	signer, err := NewUserTokenSigner(keys, "user-01")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	// Mutating the input map after construction must not affect the signer.
	evil, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keys["user-evil"] = evil
	delete(keys, "user-01")

	if _, err := signer.GenerateAccessToken("u@icaa.world", "", nil); err != nil {
		t.Fatalf("signer must be unaffected by input map mutation: %v", err)
	}
}
