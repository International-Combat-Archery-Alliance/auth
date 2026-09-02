package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testClientID = "event-registration"
	testAudience = "profiles-api"
	testScope    = "m2m:player-profiles"
)

// jwksServer is a mutable JWKS endpoint for tests.
type jwksServer struct {
	mu       sync.Mutex
	keys     map[string]*rsa.PrivateKey
	status   int
	fetchCtr atomic.Int32
}

func newJWKSServer() *jwksServer {
	return &jwksServer{keys: map[string]*rsa.PrivateKey{}, status: http.StatusOK}
}

func (s *jwksServer) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.fetchCtr.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status != http.StatusOK {
		w.WriteHeader(s.status)
		return
	}
	doc := jwksDocument{Keys: []jwkKey{}}
	for kid, priv := range s.keys {
		doc.Keys = append(doc.Keys, jwkKey{
			Kty: "RSA",
			Kid: kid,
			N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (s *jwksServer) addKey(kid string, priv *rsa.PrivateKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[kid] = priv
}

func (s *jwksServer) fetches() int32 {
	return s.fetchCtr.Load()
}

func rsaKeys(t *testing.T, kids ...string) map[string]*rsa.PrivateKey {
	t.Helper()
	keys := map[string]*rsa.PrivateKey{}
	for _, kid := range kids {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key %q: %v", kid, err)
		}
		keys[kid] = priv
	}
	return keys
}

// setupVerifiedCache returns a KeyCache whose JWKS endpoint serves the given
// keys under their own kids.
func setupVerifiedCache(t *testing.T, keys map[string]*rsa.PrivateKey) *KeyCache {
	t.Helper()
	server := newJWKSServer()
	for kid, priv := range keys {
		server.addKey(kid, priv)
	}
	ts := httptest.NewServer(server)
	t.Cleanup(ts.Close)

	return NewKeyCache(ts.URL, WithKeyCacheLogger(slog.New(slog.DiscardHandler)))
}

// validToken mints a machine token with standard test claims, signed by the
// given key under the given kid.
func validToken(t *testing.T, keys map[string]*rsa.PrivateKey, kid string) string {
	t.Helper()
	return signMachine(t, keys[kid], testClientID, testAudience, []string{testScope}, kid)
}

// signMachine mints a machine token signed by priv with the given kid header.
func signMachine(t *testing.T, priv *rsa.PrivateKey, clientID string, audience string, scopes []string, kid string) string {
	t.Helper()
	claims := MachineTokenClaims{
		TokenType: TokenTypeMachine,
		Roles:     scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   clientID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    DefaultIssuer,
			Audience:  jwt.ClaimStrings{audience},
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign machine token: %v", err)
	}
	return signed
}

// signMachineAt mints a machine token with a specific exp time.
func signMachineAt(t *testing.T, priv *rsa.PrivateKey, clientID string, audience string, scopes []string, kid string, exp time.Time) string {
	t.Helper()
	claims := MachineTokenClaims{
		TokenType: TokenTypeMachine,
		Roles:     scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   clientID,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			Issuer:    DefaultIssuer,
			Audience:  jwt.ClaimStrings{audience},
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func slicesContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
