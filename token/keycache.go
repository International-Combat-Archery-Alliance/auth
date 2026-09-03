package token

import (
	"container/list"
	"context"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
)

// DefaultMinRefetchInterval is the minimum time between lazy refetches of the
// public-key source.
const DefaultMinRefetchInterval = 30 * time.Second

// maxNegativeEntries caps the negative cache so attacker-controlled unknown
// kids cannot grow memory without bound.
const maxNegativeEntries = 1024

// jwksFetchKey dedupes JWKS fetches across callers (singleflight key).
const jwksFetchKey = "jwks"

// KeyCache holds the RSA public keys used to verify ICAA JWTs, fetched from
// a configured JWKS endpoint. Fetch is non-fatal at startup, verification
// fails closed, unknown kids trigger a rate-limited lazy refetch (singleflight,
// 30s min interval, bounded negative cache), and last-known-good keys survive
// endpoint failures. Only kty=RSA, use=sig, alg=RS256 keys >= 2048 bits are
// installed; malformed entries are skipped, never fatal. Dev keys
// (WithDevKeys) are only consulted with WithLocalMode also set.
type KeyCache struct {
	jwksURL    string
	httpClient *http.Client

	minRefetchInterval time.Duration
	logger             *slog.Logger

	// userIssuer and userAudience are the iss/aud claims the user-token
	// validators expect. userParser is prebuilt from them.
	userIssuer   string
	userAudience string
	userParser   *jwt.Parser

	mu sync.Mutex
	// keys is last-known-good (failed fetches never remove entries).
	keys map[string]*rsa.PublicKey
	// devKeys are inert unless localMode is set (double opt-in).
	devKeys   map[string]*rsa.PublicKey
	localMode bool
	// negative caches unknown kids to bound refetch hammering. It is a map
	// from kid to its list element (O(1) lookup) plus a list ordered by expiry
	// (front = soonest). New entries are always the latest-expiring, so
	// appends are O(1), pruning visits only the expired prefix, and eviction
	// drops the soonest-expiring entry.
	negative     map[string]*list.Element
	negativeList *list.List
	lastRefetch  time.Time
	// group dedupes JWKS fetches: one goroutine fetches, all misses share
	// the result.
	group singleflight.Group
}

// negativeEntry is one negative-cache entry: an unknown kid and when it stops
// being cached.
type negativeEntry struct {
	kid       string
	expiresAt time.Time
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

// WithExpectedUserIssuer overrides the iss claim the user-token validators
// expect (default: icaa.world). It must match the signer's iss.
func WithExpectedUserIssuer(issuer string) KeyCacheOption {
	return func(k *KeyCache) {
		k.userIssuer = issuer
	}
}

// WithExpectedUserAudience overrides the aud claim the user-token validators
// expect (default: icaa-api). It must match the signer's aud.
func WithExpectedUserAudience(audience string) KeyCacheOption {
	return func(k *KeyCache) {
		k.userAudience = audience
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
		userIssuer:         DefaultIssuer,
		userAudience:       DefaultAudience,
		keys:               make(map[string]*rsa.PublicKey),
		devKeys:            make(map[string]*rsa.PublicKey),
		negative:           make(map[string]*list.Element),
		negativeList:       list.New(),
	}

	for _, opt := range opts {
		opt(k)
	}

	k.userParser = buildUserParser(k.userIssuer, k.userAudience)

	return k
}

// StartupFetch loads keys once at boot. It is NON-FATAL by design: it logs
// and returns the error, but callers must continue starting up regardless;
// the cache simply starts empty and lazy refetches pick keys up on first use.
// Routing through the singleflight means a boot that races a lazy miss shares
// its fetch instead of issuing a second one.
func (c *KeyCache) StartupFetch(ctx context.Context) error {
	err := c.awaitRefetch(ctx)
	if err != nil {
		c.logger.Warn("startup public key fetch failed (non-fatal); verification will fail closed until keys are fetched", slog.String("error", err.Error()))
	}
	return err
}

// Key returns the public key for kid, triggering a lazy refetch on a miss.
// Fail closed with ErrUnknownKey if no key can be found.
func (c *KeyCache) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if key, err := c.cachedKey(kid); key != nil || err != nil {
		return key, err
	}

	if err := c.awaitRefetch(ctx); err != nil {
		c.logger.Warn("lazy public key refetch failed", slog.String("kid", kid), slog.String("error", err.Error()))
	}

	// Re-check after the refetch. If a concurrent goroutine recorded a miss
	// for the same kid, cachedKey returns the negative-cache error, which is
	// also the correct fail-closed outcome.
	if key, err := c.cachedKey(kid); key != nil || err != nil {
		return key, err
	}

	return nil, c.recordMiss(kid)
}

// recordMiss negative-caches the kid (bounded) and fails closed. New entries
// append at the tail (newest expiry); re-misses just move the entry to the
// tail. Stale pruning and full-cache eviction operate on the front, so they
// never scan the whole map under lock.
func (c *KeyCache) recordMiss(kid string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	expiresAt := now.Add(c.minRefetchInterval)
	if el, exists := c.negative[kid]; exists {
		el.Value.(*negativeEntry).expiresAt = expiresAt
		c.negativeList.MoveToBack(el)
		return unknownKeyErr(kid)
	}
	c.pruneNegativeLocked(now)
	if c.negativeList.Len() >= maxNegativeEntries {
		c.evictNegativeLocked()
	}
	el := c.negativeList.PushBack(&negativeEntry{kid: kid, expiresAt: expiresAt})
	c.negative[kid] = el
	return unknownKeyErr(kid)
}

// pruneNegativeLocked drops stale entries from the front of the list. Only the
// soonest-expiring entries can be stale, so this visits just the expired
// prefix. Caller must hold c.mu.
func (c *KeyCache) pruneNegativeLocked(now time.Time) {
	front := c.negativeList.Front()
	for front != nil {
		entry := front.Value.(*negativeEntry)
		if !now.After(entry.expiresAt) {
			return
		}
		next := front.Next()
		delete(c.negative, entry.kid)
		c.negativeList.Remove(front)
		front = next
	}
}

// evictNegativeLocked removes the soonest-expiring entry to bound the cache
// when it is full of fresh entries. Caller must hold c.mu.
func (c *KeyCache) evictNegativeLocked() {
	if front := c.negativeList.Front(); front != nil {
		entry := front.Value.(*negativeEntry)
		delete(c.negative, entry.kid)
		c.negativeList.Remove(front)
	}
}

// unknownKeyErr is the canonical fail-closed error for an unknown kid.
func unknownKeyErr(kid string) error {
	return fmt.Errorf("%w: %q", ErrUnknownKey, kid)
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
	if el, ok := c.negative[kid]; ok && time.Now().Before(el.Value.(*negativeEntry).expiresAt) {
		return nil, unknownKeyErr(kid)
	}
	return nil, nil
}

// awaitRefetch starts a JWKS fetch, or joins one already in flight. Only one
// goroutine ever performs the fetch (singleflight); the rest share its
// result, and the fetch itself is rate-limited by fetch().
func (c *KeyCache) awaitRefetch(ctx context.Context) error {
	// The shared fetch must not inherit the first caller's cancellation: a
	// single canceled request must not abort key refresh for every concurrent
	// caller. WithoutCancel keeps the caller's values without its lifetime.
	ch := c.group.DoChan(jwksFetchKey, func() (any, error) {
		return nil, c.fetch(context.WithoutCancel(ctx))
	})
	select {
	case res := <-ch:
		return res.Err
	case <-ctx.Done():
		return ctx.Err()
	}
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
