package token

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// DefaultMinRefetchInterval is the minimum time between lazy refetches of the
// public-key source. Production must keep this at or above 30s.
const DefaultMinRefetchInterval = 30 * time.Second

// jwksDocument mirrors the JSON shape served by
// GET /login/.well-known/jwks.json.
type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// KeyCache holds the RSA public keys used to verify ICAA JWTs, fetched from
// login's JWKS endpoint:
//
//   - The startup fetch is NON-FATAL: a failure logs and leaves the cache
//     empty; boot must never abort because login/JWKS is unreachable.
//   - Verification fails closed: with no key for a kid, validation returns an
//     error (401) — it never falls back to "allow".
//   - Unknown kids trigger a lazy refetch (singleflight, minimum 30s interval,
//     negative-cached), so key rotation is absorbed without manual action.
//   - Last-known-good keys are kept per instance: a failed refetch never
//     clears keys we already hold, so a running instance keeps verifying even
//     if login is down.
//
// Note: ADR-0006/0007 originally specified an SSM /jwtPublicKeys availability
// floor consulted in union with the JWKS endpoint. It was deliberately NOT
// implemented (project decision): no service holds IAM to read it. The
// residual risk — a key rotation landing while an instance cold-starts during
// a login outage — is accepted; avoid rotating keys during incidents.
//
// LOCAL dev mode is an explicit opt-in: WithDevKeys installs a known dev
// keypair and nothing else changes. Prod callers must assert !isLocal() before
// ever passing dev keys.
type KeyCache struct {
	jwksURL    string
	httpClient *http.Client

	minRefetchInterval time.Duration
	logger             *slog.Logger

	mu sync.Mutex
	// keys is the last-known-good set (kid -> public key). It only ever grows
	// within an instance; a failed fetch never removes entries.
	keys map[string]*rsa.PublicKey
	// negative caches kids that were requested but not found, so an unknown
	// kid cannot be used to hammer the source faster than the refetch
	// interval.
	negative map[string]time.Time
	// lastRefetch guards the minimum refetch interval.
	lastRefetch time.Time
	// refetchDone is non-nil while a lazy refetch is in flight (singleflight).
	refetchDone chan struct{}
}

// KeyCacheOption configures a KeyCache.
type KeyCacheOption func(*KeyCache)

// WithKeyCacheHTTPClient overrides the HTTP client used for JWKS fetches.
func WithKeyCacheHTTPClient(c *http.Client) KeyCacheOption {
	return func(k *KeyCache) {
		k.httpClient = c
	}
}

// WithMinRefetchInterval overrides the minimum time between lazy refetches.
// Production MUST keep this at or above 30s per ADR-0006/0007; lower values
// (minimum 100ms) are only useful in tests.
func WithMinRefetchInterval(d time.Duration) KeyCacheOption {
	return func(k *KeyCache) {
		k.minRefetchInterval = max(d, 100*time.Millisecond)
	}
}

// WithKeyCacheLogger sets a logger for refetch warnings.
func WithKeyCacheLogger(l *slog.Logger) KeyCacheOption {
	return func(k *KeyCache) {
		k.logger = l
	}
}

// WithDevKeys installs a dev public key set (LOCAL mode). It is explicit:
// nothing infers LOCAL from the environment, and verification does not consult
// these keys unless they were installed here. Prod code MUST assert !isLocal()
// before calling this option.
func WithDevKeys(keys map[string]*rsa.PublicKey) KeyCacheOption {
	return func(k *KeyCache) {
		for kid, key := range keys {
			k.keys[kid] = key
		}
	}
}

// NewKeyCache creates a KeyCache that fetches keys from the given JWKS
// endpoint. An empty URL is allowed (e.g. LOCAL dev with only dev keys
// installed), but then verification only succeeds for installed dev keys.
func NewKeyCache(jwksURL string, opts ...KeyCacheOption) *KeyCache {
	k := &KeyCache{
		jwksURL:            jwksURL,
		httpClient:         &http.Client{Timeout: 5 * time.Second},
		minRefetchInterval: DefaultMinRefetchInterval,
		logger:             slog.Default(),
		keys:               make(map[string]*rsa.PublicKey),
		negative:           make(map[string]time.Time),
	}

	for _, opt := range opts {
		opt(k)
	}

	return k
}

// StartupFetch loads keys once at boot. It is NON-FATAL by design: it logs and
// returns the error, but callers must continue starting up regardless. The
// cache simply starts empty and lazy refetches pick keys up on first use.
func (c *KeyCache) StartupFetch(ctx context.Context) error {
	err := c.fetch(ctx)
	if err != nil {
		c.logger.Warn("startup public key fetch failed (non-fatal); verification will fail closed until keys are fetched", slog.String("error", err.Error()))
	}
	return err
}

// Key returns the public key for kid, triggering a lazy refetch on a miss.
// It returns ErrUnknownKey (fail closed) if no key can be found. Entries in
// the negative cache short-circuit repeated lookups of the same unknown kid.
func (c *KeyCache) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()

	if key, ok := c.keys[kid]; ok {
		c.mu.Unlock()
		return key, nil
	}

	if until, neg := c.negative[kid]; neg && time.Now().Before(until) {
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: %q", ErrUnknownKey, kid)
	}

	// Singleflight: if a refetch is already in flight, wait for it rather
	// than issuing another.
	if c.refetchDone == nil {
		c.refetchDone = make(chan struct{})
		c.mu.Unlock()

		if err := c.fetch(ctx); err != nil {
			c.logger.Warn("lazy public key refetch failed", slog.String("kid", kid), slog.String("error", err.Error()))
		}

		c.mu.Lock()
		close(c.refetchDone)
		c.refetchDone = nil
		c.mu.Unlock()
	} else {
		done := c.refetchDone
		c.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if key, ok := c.keys[kid]; ok {
		return key, nil
	}

	// Still unknown: negative-cache so repeated requests for this kid cannot
	// hammer the sources.
	c.negative[kid] = time.Now().Add(c.minRefetchInterval)
	return nil, fmt.Errorf("%w: %q", ErrUnknownKey, kid)
}

// fetch pulls keys from the JWKS endpoint and merges them into the
// last-known-good set. It is rate-limited to minRefetchInterval and never
// clears existing keys on failure.
func (c *KeyCache) fetch(ctx context.Context) error {
	c.mu.Lock()
	if time.Since(c.lastRefetch) < c.minRefetchInterval {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	keys, err := c.fetchJWKS(ctx)
	if err != nil {
		c.mu.Lock()
		c.lastRefetch = time.Now()
		c.mu.Unlock()
		return fmt.Errorf("jwks fetch: %w", err)
	}

	c.mu.Lock()
	c.lastRefetch = time.Now()
	for kid, key := range keys {
		c.keys[kid] = key
	}
	c.mu.Unlock()

	return nil
}

func (c *KeyCache) fetchJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned %s", resp.Status)
	}

	var doc jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	return parseJWKS(doc)
}

// parseJWKS converts a jwksDocument into a kid -> public key map. Only RSA
// keys are accepted (kty == "RSA"); anything else is skipped so a malformed or
// foreign key entry can never be installed.
func parseJWKS(doc jwksDocument) (map[string]*rsa.PublicKey, error) {
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		if k.Kid == "" || k.N == "" || k.E == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("invalid base64url modulus for kid %q: %w", k.Kid, err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("invalid base64url exponent for kid %q: %w", k.Kid, err)
		}
		// The exponent is an unsigned big-endian integer, often just "AQAB".
		var e int
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		if e == 0 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: e,
		}
	}
	return keys, nil
}