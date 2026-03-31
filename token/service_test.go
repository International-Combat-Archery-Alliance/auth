package token

import (
	"testing"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/golang-jwt/jwt/v5"
)

func TestNewTokenService(t *testing.T) {
	signingKey := SigningKey{
		ID:  "test-key-1",
		Key: []byte("test-signing-key-that-is-32-bytes!"),
	}

	service := NewTokenService(signingKey)

	if service == nil {
		t.Fatal("NewTokenService returned nil")
	}

	if service.currentKeyID != signingKey.ID {
		t.Errorf("expected currentKeyID to be %s, got %s", signingKey.ID, service.currentKeyID)
	}

	if service.accessTokenLifetime != DefaultAccessTokenLifetime {
		t.Errorf("expected accessTokenLifetime to be %v, got %v", DefaultAccessTokenLifetime, service.accessTokenLifetime)
	}

	if service.refreshTokenLifetime != DefaultRefreshTokenLifetime {
		t.Errorf("expected refreshTokenLifetime to be %v, got %v", DefaultRefreshTokenLifetime, service.refreshTokenLifetime)
	}

	if service.issuer != DefaultIssuer {
		t.Errorf("expected issuer to be %s, got %s", DefaultIssuer, service.issuer)
	}

	if service.audience != DefaultAudience {
		t.Errorf("expected audience to be %s, got %s", DefaultAudience, service.audience)
	}
}

func TestTokenServiceWithOptions(t *testing.T) {
	signingKey := SigningKey{
		ID:  "test-key-1",
		Key: []byte("test-signing-key-that-is-32-bytes!"),
	}

	customAccessLifetime := 30 * time.Minute
	customRefreshLifetime := 7 * 24 * time.Hour
	customIssuer := "custom-issuer"
	customAudience := "custom-audience"

	service := NewTokenService(
		signingKey,
		WithAccessTokenLifetime(customAccessLifetime),
		WithRefreshTokenLifetime(customRefreshLifetime),
		WithIssuer(customIssuer),
		WithAudience(customAudience),
	)

	if service.accessTokenLifetime != customAccessLifetime {
		t.Errorf("expected accessTokenLifetime to be %v, got %v", customAccessLifetime, service.accessTokenLifetime)
	}

	if service.refreshTokenLifetime != customRefreshLifetime {
		t.Errorf("expected refreshTokenLifetime to be %v, got %v", customRefreshLifetime, service.refreshTokenLifetime)
	}

	if service.issuer != customIssuer {
		t.Errorf("expected issuer to be %s, got %s", customIssuer, service.issuer)
	}

	if service.audience != customAudience {
		t.Errorf("expected audience to be %s, got %s", customAudience, service.audience)
	}
}

func TestTokenServiceWithSigningKeys(t *testing.T) {
	keys := map[string]SigningKey{
		"key-1": {ID: "key-1", Key: []byte("first-signing-key-that-is-32-bytes")},
		"key-2": {ID: "key-2", Key: []byte("second-signing-key-that-is-32-by")},
	}

	service := NewTokenService(keys["key-1"], WithSigningKeys(keys, "key-2"))

	if service.currentKeyID != "key-2" {
		t.Errorf("expected currentKeyID to be key-2, got %s", service.currentKeyID)
	}

	if len(service.signingKeys) != 2 {
		t.Errorf("expected 2 signing keys, got %d", len(service.signingKeys))
	}
}

func TestGenerateAccessToken(t *testing.T) {
	signingKey := SigningKey{
		ID:  "test-key-1",
		Key: []byte("test-signing-key-that-is-32-bytes!"),
	}

	service := NewTokenService(signingKey)
	email := "test@example.com"
	picture := "https://example.com/pic.jpg"
	roles := []auth.Role{auth.RoleAdmin}

	tokenString, err := service.GenerateAccessToken(email, picture, roles)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	if tokenString == "" {
		t.Error("GenerateAccessToken returned empty token")
	}

	// Parse and verify the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return signingKey.Key, nil
	})
	if err != nil {
		t.Fatalf("Failed to parse generated token: %v", err)
	}

	if !token.Valid {
		t.Error("Generated token is not valid")
	}

	// Check claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Could not extract claims from token")
	}

	if claims["email"] != email {
		t.Errorf("expected email claim to be %s, got %v", email, claims["email"])
	}

	if claims["picture"] != picture {
		t.Errorf("expected picture claim to be %s, got %v", picture, claims["picture"])
	}

	if claims["token_type"] != string(TokenTypeAccess) {
		t.Errorf("expected token_type claim to be %s, got %v", TokenTypeAccess, claims["token_type"])
	}

	// Check key ID in header
	if token.Header["kid"] != signingKey.ID {
		t.Errorf("expected kid header to be %s, got %v", signingKey.ID, token.Header["kid"])
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	signingKey := SigningKey{
		ID:  "test-key-1",
		Key: []byte("test-signing-key-that-is-32-bytes!"),
	}

	service := NewTokenService(signingKey)

	tokenID, tokenString, expiresAt, err := service.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	if tokenID == "" {
		t.Error("GenerateRefreshToken returned empty tokenID")
	}

	if tokenString == "" {
		t.Error("GenerateRefreshToken returned empty token")
	}

	if expiresAt.IsZero() {
		t.Error("GenerateRefreshToken returned zero expiration")
	}

	// Parse and verify the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return signingKey.Key, nil
	})
	if err != nil {
		t.Fatalf("Failed to parse generated token: %v", err)
	}

	if !token.Valid {
		t.Error("Generated token is not valid")
	}

	// Check claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Could not extract claims from token")
	}

	if claims["sub"] != tokenID {
		t.Errorf("expected sub claim to be %s, got %v", tokenID, claims["sub"])
	}

	if claims["token_type"] != string(TokenTypeRefresh) {
		t.Errorf("expected token_type claim to be %s, got %v", TokenTypeRefresh, claims["token_type"])
	}
}

func TestValidateAccessToken(t *testing.T) {
	signingKey := SigningKey{
		ID:  "test-key-1",
		Key: []byte("test-signing-key-that-is-32-bytes!"),
	}

	service := NewTokenService(signingKey)
	email := "test@example.com"
	picture := "https://example.com/pic.jpg"
	roles := []auth.Role{auth.RoleAdmin}

	// Generate a valid token
	tokenString, err := service.GenerateAccessToken(email, picture, roles)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Validate the token
	claims, err := service.ValidateAccessToken(tokenString)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	if claims.Email != email {
		t.Errorf("expected Email to be %s, got %s", email, claims.Email)
	}

	if claims.Picture != picture {
		t.Errorf("expected Picture to be %s, got %s", picture, claims.Picture)
	}

	if len(claims.Roles) != 1 || claims.Roles[0] != auth.RoleAdmin {
		t.Errorf("expected Roles to be [%s], got %v", auth.RoleAdmin, claims.Roles)
	}

	if claims.TokenType != TokenTypeAccess {
		t.Errorf("expected TokenType to be %s, got %s", TokenTypeAccess, claims.TokenType)
	}
}

func TestValidateAccessToken_InvalidToken(t *testing.T) {
	signingKey := SigningKey{
		ID:  "test-key-1",
		Key: []byte("test-signing-key-that-is-32-bytes!"),
	}

	service := NewTokenService(signingKey)

	// Test with invalid token string
	_, err := service.ValidateAccessToken("invalid.token.string")
	if err == nil {
		t.Error("ValidateAccessToken should fail with invalid token")
	}
}

func TestValidateAccessToken_WrongTokenType(t *testing.T) {
	signingKey := SigningKey{
		ID:  "test-key-1",
		Key: []byte("test-signing-key-that-is-32-bytes!"),
	}

	service := NewTokenService(signingKey)

	// Generate a refresh token
	_, refreshTokenString, _, err := service.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	// Try to validate refresh token as access token
	_, err = service.ValidateAccessToken(refreshTokenString)
	if err == nil {
		t.Error("ValidateAccessToken should fail with refresh token")
	}
}

func TestValidateAccessToken_WrongSigningKey(t *testing.T) {
	signingKey1 := SigningKey{
		ID:  "test-key-1",
		Key: []byte("test-signing-key-that-is-32-bytes!"),
	}

	signingKey2 := SigningKey{
		ID:  "test-key-2",
		Key: []byte("different-signing-key-that-is-32-b"),
	}

	service1 := NewTokenService(signingKey1)
	service2 := NewTokenService(signingKey2)

	// Generate token with service1
	tokenString, err := service1.GenerateAccessToken("test@example.com", "", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Try to validate with service2 (different key)
	_, err = service2.ValidateAccessToken(tokenString)
	if err == nil {
		t.Error("ValidateAccessToken should fail with wrong signing key")
	}
}

func TestValidateRefreshToken(t *testing.T) {
	signingKey := SigningKey{
		ID:  "test-key-1",
		Key: []byte("test-signing-key-that-is-32-bytes!"),
	}

	service := NewTokenService(signingKey)

	// Generate a refresh token
	expectedTokenID, tokenString, _, err := service.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	// Validate the token
	tokenID, err := service.ValidateRefreshToken(tokenString)
	if err != nil {
		t.Fatalf("ValidateRefreshToken failed: %v", err)
	}

	if tokenID != expectedTokenID {
		t.Errorf("expected tokenID to be %s, got %s", expectedTokenID, tokenID)
	}
}

func TestValidateRefreshToken_InvalidToken(t *testing.T) {
	signingKey := SigningKey{
		ID:  "test-key-1",
		Key: []byte("test-signing-key-that-is-32-bytes!"),
	}

	service := NewTokenService(signingKey)

	// Test with invalid token string
	_, err := service.ValidateRefreshToken("invalid.token.string")
	if err == nil {
		t.Error("ValidateRefreshToken should fail with invalid token")
	}
}

func TestValidateRefreshToken_WrongTokenType(t *testing.T) {
	signingKey := SigningKey{
		ID:  "test-key-1",
		Key: []byte("test-signing-key-that-is-32-bytes!"),
	}

	service := NewTokenService(signingKey)

	// Generate an access token
	accessTokenString, err := service.GenerateAccessToken("test@example.com", "", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Try to validate access token as refresh token
	_, err = service.ValidateRefreshToken(accessTokenString)
	if err == nil {
		t.Error("ValidateRefreshToken should fail with access token")
	}
}

func TestKeyRotation(t *testing.T) {
	oldKey := SigningKey{
		ID:  "old-key",
		Key: []byte("old-signing-key-that-is-32-bytes!!"),
	}

	newKey := SigningKey{
		ID:  "new-key",
		Key: []byte("new-signing-key-that-is-32-bytes!!"),
	}

	keys := map[string]SigningKey{
		oldKey.ID: oldKey,
		newKey.ID: newKey,
	}

	// Create service with both keys, but using new key for signing
	service := NewTokenService(oldKey, WithSigningKeys(keys, newKey.ID))

	// Generate token with new key
	tokenString, err := service.GenerateAccessToken("test@example.com", "", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Should be able to validate with both keys available
	_, err = service.ValidateAccessToken(tokenString)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	// Create a token signed with old key (simulate old token)
	oldService := NewTokenService(oldKey)
	oldTokenString, err := oldService.GenerateAccessToken("test@example.com", "", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken with old key failed: %v", err)
	}

	// Should still be able to validate old token with new service (key rotation support)
	_, err = service.ValidateAccessToken(oldTokenString)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed for old token: %v", err)
	}
}
