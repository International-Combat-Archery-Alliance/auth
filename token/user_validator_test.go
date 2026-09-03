package token

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/golang-jwt/jwt/v5"
)

func TestValidateUserAccessTokenHappyPath(t *testing.T) {
	keys := rsaKeys(t, "user-01")
	cache := setupVerifiedCache(t, keys)
	signer, err := NewUserTokenSigner(keys, "user-01")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	tok, err := signer.GenerateAccessToken("user@icaa.world", "pic", []auth.Role{auth.RoleAdmin})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims, err := cache.ValidateUserAccessToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("expected valid user access token to pass: %v", err)
	}
	if claims.Email != "user@icaa.world" {
		t.Fatalf("expected email, got %q", claims.Email)
	}
	if claims.TokenType != TokenTypeAccess {
		t.Fatalf("expected token_type access, got %q", claims.TokenType)
	}
}

func TestValidateUserAccessTokenRejections(t *testing.T) {
	keys := rsaKeys(t, "user-01")
	cache := setupVerifiedCache(t, keys)
	ctx := context.Background()
	signer, err := NewUserTokenSigner(keys, "user-01")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	t.Run("refresh token rejected on access path", func(t *testing.T) {
		_, refresh, _, err := signer.GenerateRefreshToken()
		if err != nil {
			t.Fatalf("sign refresh: %v", err)
		}
		if _, err := cache.ValidateUserAccessToken(ctx, refresh); err == nil {
			t.Fatal("expected refresh token to be rejected on access path")
		}
	})

	t.Run("machine kid rejected on user path", func(t *testing.T) {
		mkeys := rsaKeys(t, "machine-01")
		mcache := setupVerifiedCache(t, mkeys)
		_ = mcache
		// Sign user-shaped claims with a machine kid: kid binding must fail
		// before any key lookup.
		tok := signMachine(t, mkeys["machine-01"], "client-1", DefaultAudience, []string{"m2m:x"}, "machine-01")
		if _, err := cache.ValidateUserAccessToken(ctx, tok); err == nil {
			t.Fatal("expected machine-* kid to be rejected on user path")
		}
	})

	t.Run("machine token_type rejected", func(t *testing.T) {
		tok := signMachine(t, keys["user-01"], "client-1", DefaultAudience, []string{"m2m:x"}, "user-01")
		if _, err := cache.ValidateUserAccessToken(ctx, tok); err == nil {
			t.Fatal("expected token_type=machine to be rejected on user path")
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		claims := ICAAClaims{
			Email:     "u@icaa.world",
			TokenType: TokenTypeAccess,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    DefaultIssuer,
				Audience:  jwt.ClaimStrings{"other-api"},
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "user-01"
		signed, err := tok.SignedString(keys["user-01"])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := cache.ValidateUserAccessToken(ctx, signed); err == nil {
			t.Fatal("expected aud mismatch to fail")
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		claims := ICAAClaims{
			Email:     "u@icaa.world",
			TokenType: TokenTypeAccess,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    "evil.example",
				Audience:  jwt.ClaimStrings{DefaultAudience},
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "user-01"
		signed, err := tok.SignedString(keys["user-01"])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := cache.ValidateUserAccessToken(ctx, signed); err == nil {
			t.Fatal("expected iss mismatch to fail")
		}
	})

	t.Run("missing kid", func(t *testing.T) {
		claims := ICAAClaims{
			Email:     "u@icaa.world",
			TokenType: TokenTypeAccess,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    DefaultIssuer,
				Audience:  jwt.ClaimStrings{DefaultAudience},
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signed, err := tok.SignedString(keys["user-01"])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := cache.ValidateUserAccessToken(ctx, signed); err == nil {
			t.Fatal("expected missing kid to fail")
		}
	})
}

func TestValidateUserTokenAlgConfusion(t *testing.T) {
	keys := rsaKeys(t, "user-01")
	cache := setupVerifiedCache(t, keys)
	ctx := context.Background()

	t.Run("HS256 signed with public key bytes", func(t *testing.T) {
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
		if _, err := cache.ValidateUserAccessToken(ctx, signed); err == nil {
			t.Fatal("expected HS256 token to be rejected (alg confusion)")
		}
		if _, err := cache.ValidateUserRefreshToken(ctx, signed); err == nil {
			t.Fatal("expected HS256 token to be rejected on refresh path")
		}
	})

	t.Run("alg none", func(t *testing.T) {
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
		if _, err := cache.ValidateUserAccessToken(ctx, signed); err == nil {
			t.Fatal("expected alg=none token to be rejected")
		}
	})

	t.Run("legacy HS256 fixture rejected", func(t *testing.T) {
		// A token minted the old way (HS256, symmetric secret) must 401
		// everywhere after the cutover.
		legacy := jwt.NewWithClaims(jwt.SigningMethodHS256, ICAAClaims{
			Email:     "u@icaa.world",
			TokenType: TokenTypeAccess,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    DefaultIssuer,
				Audience:  jwt.ClaimStrings{DefaultAudience},
			},
		})
		legacy.Header["kid"] = "user-01"
		signed, err := legacy.SignedString([]byte("legacy-symmetric-secret-32-bytes!!!"))
		if err != nil {
			t.Fatalf("sign legacy: %v", err)
		}
		if _, err := cache.ValidateUserAccessToken(ctx, signed); err == nil {
			t.Fatal("expected legacy HS256 token to be rejected")
		}
	})
}

func TestValidateUserRefreshToken(t *testing.T) {
	keys := rsaKeys(t, "user-01")
	cache := setupVerifiedCache(t, keys)
	ctx := context.Background()
	signer, err := NewUserTokenSigner(keys, "user-01")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	t.Run("round trip returns token ID", func(t *testing.T) {
		id, refresh, _, err := signer.GenerateRefreshToken()
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		got, err := cache.ValidateUserRefreshToken(ctx, refresh)
		if err != nil {
			t.Fatalf("validate refresh: %v", err)
		}
		if got != id {
			t.Fatalf("expected ID %q, got %q", id, got)
		}
	})

	t.Run("access token rejected on refresh path", func(t *testing.T) {
		access, err := signer.GenerateAccessToken("u@icaa.world", "", nil)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := cache.ValidateUserRefreshToken(ctx, access); err == nil {
			t.Fatal("expected access token to be rejected on refresh path")
		}
	})
}

func TestUserDevKeysLocalOnly(t *testing.T) {
	keys := rsaKeys(t, "user-dev")
	signer, err := NewUserTokenSigner(keys, "user-dev")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	tok, err := signer.GenerateAccessToken("u@icaa.world", "", nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	devPubs := map[string]*rsa.PublicKey{"user-dev": &keys["user-dev"].PublicKey}

	prod := NewKeyCache("", WithDevKeys(devPubs))
	if _, err := prod.ValidateUserAccessToken(context.Background(), tok); err == nil {
		t.Fatal("dev keys must be inert without WithLocalMode")
	}

	local := NewKeyCache("", WithLocalMode(), WithDevKeys(devPubs))
	if _, err := local.ValidateUserAccessToken(context.Background(), tok); err != nil {
		t.Fatalf("dev key should verify with local opt-in: %v", err)
	}
}

func TestUserIssuerAudienceConfigSymmetry(t *testing.T) {
	keys := rsaKeys(t, "user-01")
	customSigner, err := NewUserTokenSigner(keys, "user-01",
		WithUserTokenIssuer("custom.example"),
		WithUserTokenAudience("custom-api"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	tok, err := customSigner.GenerateAccessToken("u@icaa.world", "", nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// A cache expecting the same values verifies.
	server := newJWKSServer()
	server.addKey("user-01", keys["user-01"])
	ts := httptest.NewServer(server)
	defer ts.Close()
	matching := NewKeyCache(ts.URL,
		WithExpectedUserIssuer("custom.example"),
		WithExpectedUserAudience("custom-api"),
	)
	if _, err := matching.ValidateUserAccessToken(context.Background(), tok); err != nil {
		t.Fatalf("matching iss/aud must verify: %v", err)
	}

	// A default cache rejects the custom token.
	deflt := NewKeyCache(ts.URL)
	if _, err := deflt.ValidateUserAccessToken(context.Background(), tok); err == nil {
		t.Fatal("default cache must reject custom iss/aud token")
	}
}
