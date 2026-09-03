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

	"github.com/golang-jwt/jwt/v5"
)

// jwksDocument mirrors the JSON served by a JWKS endpoint.
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
	maxJWKSBodySize = 1 << 20 // 1 MiB
	minKeyBits      = 2048    // RSA-2048 or stronger
	maxKeyBits      = 8192    // cap the exponentiation cost of a hostile document
)

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
// 2048..8192-bit modulus, small odd exponent). Invalid entries are skipped so
// one bad key can't poison the document (verification fails closed per-key).
func (c *KeyCache) parseJWKS(doc jwksDocument) map[string]*rsa.PublicKey {
	keys, skipped := filterJWKSKeys(doc)
	if skipped > 0 {
		c.logger.Warn("skipped invalid jwks entries", slog.Int("count", skipped))
	}
	return keys
}

// filterJWKSKeys applies the key filter shared by the fetch path.
// It returns the installed keys and the skipped-entry count.
func filterJWKSKeys(doc jwksDocument) (map[string]*rsa.PublicKey, int) {
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
		if modulus.BitLen() < minKeyBits || modulus.BitLen() > maxKeyBits {
			skipped++
			continue
		}
		// Exponent is an unsigned big-endian integer, usually 65537. Bound the
		// byte length so the int accumulation below can never overflow into a
		// wrapped value, which would defeat the weak-exponent check.
		if len(eBytes) == 0 || len(eBytes) > 4 {
			skipped++
			continue
		}
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
	return keys, skipped
}
