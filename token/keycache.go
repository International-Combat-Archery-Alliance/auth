package token

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultMinRefetchInterval is the minimum time between lazy refetches of the
// public-key source.
const DefaultMinRefetchInterval = 30 * time.Second

// jwksDocument mirrors the JSON served by GET /login/.well-known/jwks.json.
type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// Bounds for fetched documents and installed keys.
const (
	maxJWKSBodySize    = 1 << 20 // 1 MiB
	minKeyBits         = 2048    // login signs with 2048-bit keys
	maxNegativeEntries = 1024    // cap attacker-controlled cache entries
)

// KeyCache holds the RSA public keys used to verify ICAA JWTs, fetched from
// login's JWKS endpoint. Fetch is non-fatal at startup, verification fails
// closed, unknown kids trigger a rate-limited lazy refetch (singleflight, 30s
// min interval, bounded negative cache), and last-known-good keys survive
// endpoint failures. Only kty=RSA, use=sig, alg=RS256 keys >= 2048 bits are
// installed; malformed entries are skipped, never fatal. Dev keys
// (WithDevKeys) are only consulted with WithLocalMode also set.
type KeyCache struct {
	jwksURL    string
	httpClient *http.Client

	minRefetchInterval time.Duration
	logger             *slog.Logger

	mu sync.Mutex
	// keys is last-known-good (failed fetches never remove entries).
	keys map[string]*rsa.PublicKey
	// devKeys are inert unless localMode is set (double opt-in).
	devKeys   map[string]*rsa.PublicKey
	localMode bool
	// negative caches unknown kids to bound refetch hammering; entries expire
	// and are pruned on insert (bounded by maxNegativeEntries).
	negative    map[string]time.Time
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

// WithMinRefetchInterval overrides the lazy-refetch minimum interval
// (default 30s; minimum 100ms).
func WithMinRefetchInterval(d time.Duration) KeyCacheOption {
	return func(k *KeyCache) {
		k.minRefetchInterval = max(d, 100*time.Millisecond)
	}
}

// WithKeyCacheLogger sets a logger for fetch warnings.
func WithKeyCacheLogger(l *slog.Logger) KeyCacheOption {
	return func(k *KeyCache) {
		k.logger = l
	}
}

// WithLocalMode declares this cache LOCAL. Without it, dev keys are inert.
func WithLocalMode() KeyCacheOption {
	return func(k *KeyCache) {
		k.localMode = true
	}
}

// WithDevKeys installs a dev public key set. Only effective with WithLocalMode.
func WithDevKeys(keys map[string]*rsa.PublicKey) KeyCacheOption {
	return func(k *KeyCache) {
		for kid, key := range keys {
			k.devKeys[kid] = key
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
		devKeys:            make(map[string]*rsa.PublicKey),
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
// Fail closed with ErrUnknownKey if no key can be found (negative cache
// short-circuits repeat lookups).
func (c *KeyCache) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if key, err := c.cachedKey(kid); key != nil || err != nil {
		return key, err
	}

	if err := c.awaitRefetch(ctx); err != nil {
		c.logger.Warn("lazy public key refetch failed", slog.String("kid", kid), slog.String("error", err.Error()))
	}

	// Re-check after the refetch; still missing -> fail closed and
	// negative-cache the kid (bounded: stale/over-limit entries pruned).
	c.mu.Lock()
	defer c.mu.Unlock()

	if key, ok := c.keys[kid]; ok {
		return key, nil
	}
	now := time.Now()
	for existingKid, expiresAt := range c.negative {
		if now.After(expiresAt) {
			delete(c.negative, existingKid)
		}
		if len(c.negative) < maxNegativeEntries {
			break
		}
	}
	if len(c.negative) >= maxNegativeEntries {
		for existingKid := range c.negative {
			delete(c.negative, existingKid)
			if len(c.negative) < maxNegativeEntries {
				break
			}
		}
	}
	c.negative[kid] = now.Add(c.minRefetchInterval)
	return nil, fmt.Errorf("%w: %q", ErrUnknownKey, kid)
}

// cachedKey returns the installed key for kid, or an error for a
// negative-cached miss. (nil, nil) means "not cached, worth refetching".
func (c *KeyCache) cachedKey(kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if key, ok := c.keys[kid]; ok {
		return key, nil
	}
	// Dev keys are LOCAL-only (WithLocalMode must be set).
	if c.localMode {
		if key, ok := c.devKeys[kid]; ok {
			return key, nil
		}
	}
	if until, neg := c.negative[kid]; neg && time.Now().Before(until) {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKey, kid)
	}
	return nil, nil
}

// awaitRefetch waits for an in-flight lazy refetch, or starts one
// (singleflight). The lock is never held across the network call.
func (c *KeyCache) awaitRefetch(ctx context.Context) error {
	c.mu.Lock()
	if c.refetchDone != nil {
		done := c.refetchDone
		c.mu.Unlock()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.refetchDone = make(chan struct{})
	c.mu.Unlock()

	err := c.fetch(ctx)

	c.mu.Lock()
	close(c.refetchDone)
	c.refetchDone = nil
	c.mu.Unlock()
	return err
}

// fetch pulls keys from the JWKS endpoint into the last-known-good set.
// Rate-limited to minRefetchInterval; the slot is claimed BEFORE the network
// call so a concurrent StartupFetch + first lazy miss cannot double-fetch.
func (c *KeyCache) fetch(ctx context.Context) error {
	c.mu.Lock()
	rateLimited := time.Since(c.lastRefetch) < c.minRefetchInterval
	if !rateLimited {
		c.lastRefetch = time.Now()
	}
	c.mu.Unlock()
	if rateLimited {
		return nil
	}

	keys, err := c.fetchJWKS(ctx)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for kid, key := range keys {
		c.keys[kid] = key
	}
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

	// Bound the body so a hostile/misbehaving endpoint can't cause unbounded
	// allocation on every refetch.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("read jwks body: %w", err)
	}
	if len(body) > maxJWKSBodySize {
		return nil, fmt.Errorf("jwks response exceeds %d bytes", maxJWKSBodySize)
	}

	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	return c.parseJWKS(doc), nil
}

// parseJWKS installs only signature-capable RSA keys (use=sig, alg=RS256,
// modulus >= 2048 bits, odd exponent > 1). Invalid entries are skipped so one
// bad key can't poison the document (verification fails closed per-key).
func (c *KeyCache) parseJWKS(doc jwksDocument) map[string]*rsa.PublicKey {
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	skipped := 0
	for _, k := range doc.Keys {
		if k.Kty != "RSA" ||
			(k.Use != "" && k.Use != "sig") ||
			(k.Alg != "" && k.Alg != jwt.SigningMethodRS256.Alg()) ||
			k.Kid == "" || k.N == "" || k.E == "" {
			skipped++
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			skipped++
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			skipped++
			continue
		}
		modulus := new(big.Int).SetBytes(nBytes)
		if modulus.BitLen() < minKeyBits {
			skipped++
			continue
		}
		// Exponent is an unsigned big-endian integer, usually 65537.
		var e int
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		// e=1 or even exponents make verification trivially forgeable.
		if e < 3 || e%2 == 0 {
			skipped++
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: modulus,
			E: e,
		}
	}
	if skipped > 0 {
		c.logger.Warn("skipped invalid jwks entries", slog.Int("count", skipped))
	}
	return keys
}
