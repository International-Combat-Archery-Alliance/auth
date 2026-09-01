package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
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

func TestKeyCacheStartupFetchNonFatal(t *testing.T) {
	server := httptest.NewServer(&jwksServer{status: http.StatusInternalServerError})
	defer server.Close()

	cache := NewKeyCache(server.URL, WithKeyCacheLogger(slog.New(slog.DiscardHandler)))

	err := cache.StartupFetch(context.Background())
	if err == nil {
		t.Fatal("expected startup fetch to report failure (caller logs but continues)")
	}

	// Cache is empty -> verification fails closed.
	_, keyErr := cache.Key(context.Background(), "machine-a")
	if !errors.Is(keyErr, ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey, got %v", keyErr)
	}
}

func TestKeyCacheLazyRefetchOnUnknownKid(t *testing.T) {
	keys := rsaKeys(t, "machine-a")
	server := newJWKSServer()
	server.addKey("machine-a", keys["machine-a"])
	ts := httptest.NewServer(server)
	defer ts.Close()

	cache := NewKeyCache(ts.URL, WithMinRefetchInterval(150*time.Millisecond))

	// Unknown kid first -> fails and triggers a refetch (negative cache).
	unknown := signMachine(t, keys["machine-a"], "client-1", "profiles-api", []string{"m2m:player-profiles"}, "machine-b")
	if _, err := cache.ValidateMachineToken(context.Background(), unknown, "profiles-api", "m2m:player-profiles"); err == nil {
		t.Fatal("expected unknown kid to fail")
	}

	// Rotation happens: server now serves the new kid.
	server.addKey("machine-b", keys["machine-a"]) // reuse key material; the kid is what matters here

	// Wait out the negative cache + min refetch interval.
	time.Sleep(400 * time.Millisecond)

	claims, err := cache.ValidateMachineToken(context.Background(), unknown, "profiles-api", "m2m:player-profiles")
	if err != nil {
		t.Fatalf("expected refetch to absorb rotation: %v", err)
	}
	if claims.Subject != "client-1" {
		t.Fatalf("unexpected subject: %q", claims.Subject)
	}
}

func TestKeyCacheSingleflightOnConcurrentMisses(t *testing.T) {
	keys := rsaKeys(t, "machine-a")
	server := newJWKSServer()
	server.addKey("machine-a", keys["machine-a"])
	ts := httptest.NewServer(server)
	defer ts.Close()

	cache := NewKeyCache(ts.URL, WithMinRefetchInterval(150*time.Millisecond))

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cache.Key(context.Background(), "machine-unknown")
		}()
	}
	wg.Wait()

	if got := server.fetches(); got != 1 {
		t.Fatalf("expected exactly 1 JWKS fetch for 20 concurrent misses, got %d", got)
	}
}

func TestKeyCacheMinIntervalRespected(t *testing.T) {
	keys := rsaKeys(t, "machine-a")
	server := newJWKSServer()
	server.addKey("machine-a", keys["machine-a"])
	ts := httptest.NewServer(server)
	defer ts.Close()

	cache := NewKeyCache(ts.URL, WithMinRefetchInterval(150*time.Millisecond))

	// Prime the cache with a known kid so the first miss is a true miss.
	known := signMachine(t, keys["machine-a"], "client-1", "profiles-api", []string{"m2m:player-profiles"}, "machine-a")
	if _, err := cache.ValidateMachineToken(context.Background(), known, "profiles-api", "m2m:player-profiles"); err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	fetchesAfterPrime := server.fetches()

	// Wait out the refetch interval, then an unknown kid triggers a refetch.
	time.Sleep(400 * time.Millisecond)

	unknown := signMachine(t, keys["machine-a"], "client-1", "profiles-api", []string{"m2m:player-profiles"}, "machine-zz")
	_, _ = cache.ValidateMachineToken(context.Background(), unknown, "profiles-api", "m2m:player-profiles")
	fetchesAfterMiss := server.fetches()
	if fetchesAfterMiss != fetchesAfterPrime+1 {
		t.Fatalf("expected a refetch attempt on unknown kid after the interval: fetches %d -> %d", fetchesAfterPrime, fetchesAfterMiss)
	}

	// Another unknown kid immediately after: must NOT refetch (min interval).
	unknown2 := signMachine(t, keys["machine-a"], "client-1", "profiles-api", []string{"m2m:player-profiles"}, "machine-yy")
	_, _ = cache.ValidateMachineToken(context.Background(), unknown2, "profiles-api", "m2m:player-profiles")

	if got := server.fetches(); got != fetchesAfterMiss {
		t.Fatalf("expected no refetch within min interval, got %d fetches", got)
	}
}

func TestKeyCacheNegativeCachePreventsHammering(t *testing.T) {
	keys := rsaKeys(t, "machine-a")
	server := newJWKSServer()
	server.addKey("machine-a", keys["machine-a"])
	ts := httptest.NewServer(server)
	defer ts.Close()

	cache := NewKeyCache(ts.URL)

	bad := signMachine(t, keys["machine-a"], "client-1", "profiles-api", []string{"m2m:player-profiles"}, "machine-zz")
	for i := 0; i < 5; i++ {
		_, _ = cache.ValidateMachineToken(context.Background(), bad, "profiles-api", "m2m:player-profiles")
	}

	if got := server.fetches(); got != 1 {
		t.Fatalf("expected 1 fetch total; repeated unknown kid must be negative-cached, got %d", got)
	}
}

func TestKeyCacheLastKnownGoodRetainedOnFailure(t *testing.T) {
	keys := rsaKeys(t, "machine-a")
	server := newJWKSServer()
	server.addKey("machine-a", keys["machine-a"])
	ts := httptest.NewServer(server)
	defer ts.Close()

	cache := NewKeyCache(ts.URL)
	if err := cache.StartupFetch(context.Background()); err != nil {
		t.Fatalf("startup fetch: %v", err)
	}

	// JWKS goes down.
	server.mu.Lock()
	server.status = http.StatusInternalServerError
	server.mu.Unlock()

	// Known keys keep working off last-known-good.
	known := signMachine(t, keys["machine-a"], "client-1", "profiles-api", []string{"m2m:player-profiles"}, "machine-a")
	_, err := cache.ValidateMachineToken(context.Background(), known, "profiles-api", "m2m:player-profiles")
	if err != nil {
		t.Fatalf("last-known-good must keep verifying: %v", err)
	}
}

func TestKeyCacheFailClosedWithoutAnyKeys(t *testing.T) {
	server := httptest.NewServer(newJWKSServer()) // serves an empty key set
	defer server.Close()

	cache := NewKeyCache(server.URL, WithKeyCacheLogger(slog.New(slog.DiscardHandler)))
	if err := cache.StartupFetch(context.Background()); err != nil {
		t.Fatalf("empty key set is not an error; verification fails closed instead: %v", err)
	}

	keys := rsaKeys(t, "machine-a")
	tok := signMachine(t, keys["machine-a"], "client-1", "profiles-api", []string{"m2m:player-profiles"}, "machine-a")
	_, err := cache.ValidateMachineToken(context.Background(), tok, "profiles-api", "m2m:player-profiles")
	if err == nil {
		t.Fatal("verification must fail closed when no key exists")
	}
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey, got %v", err)
	}
}

func TestKeyCacheDevKeysOnlyWhenInstalled(t *testing.T) {
	keys := rsaKeys(t, "machine-dev")
	tok := signMachine(t, keys["machine-dev"], "client-1", "profiles-api", []string{"m2m:player-profiles"}, "machine-dev")

	// Without WithDevKeys, a dev-signed token is rejected (no source
	// configured at all).
	cache := NewKeyCache("", WithKeyCacheLogger(slog.New(slog.DiscardHandler)))
	if _, err := cache.ValidateMachineToken(context.Background(), tok, "profiles-api", "m2m:player-profiles"); err == nil {
		t.Fatal("dev key must never verify unless explicitly installed")
	}

	// With WithDevKeys (LOCAL mode), it verifies.
	devKeys := map[string]*rsa.PublicKey{"machine-dev": &keys["machine-dev"].PublicKey}
	withDev := NewKeyCache("",
		WithDevKeys(devKeys),
		WithKeyCacheLogger(slog.New(slog.DiscardHandler)))
	if _, err := withDev.ValidateMachineToken(context.Background(), tok, "profiles-api", "m2m:player-profiles"); err != nil {
		t.Fatalf("dev key should verify when explicitly installed: %v", err)
	}
}