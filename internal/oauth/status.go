// Package oauth provides OAuth authentication functionality for MCP servers.
package oauth

import (
	"strings"
	"time"

	"github.com/smart-mcp-proxy/mcpproxy-go/internal/storage"
)

// OAuthStatus represents the current authentication state of an OAuth server.
type OAuthStatus string

const (
	// OAuthStatusNone indicates the server does not use OAuth.
	OAuthStatusNone OAuthStatus = "none"

	// OAuthStatusAuthenticated indicates valid OAuth token is available.
	OAuthStatusAuthenticated OAuthStatus = "authenticated"

	// OAuthStatusExpired indicates OAuth token has expired.
	OAuthStatusExpired OAuthStatus = "expired"

	// OAuthStatusError indicates OAuth authentication error.
	OAuthStatusError OAuthStatus = "error"
)

// String returns the string representation of the OAuthStatus.
func (s OAuthStatus) String() string {
	return string(s)
}

// IsValid returns true if the status represents a valid OAuth state.
func (s OAuthStatus) IsValid() bool {
	switch s {
	case OAuthStatusNone, OAuthStatusAuthenticated, OAuthStatusExpired, OAuthStatusError:
		return true
	default:
		return false
	}
}

// CalculateOAuthStatus determines the OAuth status for a server based on token state.
// Returns OAuthStatusNone if token is nil (server doesn't use OAuth).
// Returns OAuthStatusError if lastError contains OAuth-related errors.
// Returns OAuthStatusExpired if token has expired.
// Returns OAuthStatusAuthenticated if token is valid.
func CalculateOAuthStatus(token *storage.OAuthTokenRecord, lastError string) OAuthStatus {
	if token == nil {
		return OAuthStatusNone
	}
	if lastError != "" && containsOAuthError(lastError) {
		return OAuthStatusError
	}
	if time.Now().After(token.ExpiresAt) {
		return OAuthStatusExpired
	}
	return OAuthStatusAuthenticated
}

// ResolveStatus looks up the persisted OAuth token for serverName+serverURL and
// derives the health-facing OAuthStatus, refresh-token presence, and expiry from
// it. Centralizes the token lookup + CalculateOAuthStatus pairing so every
// status surface (REST /api/v1/servers, the upstream_servers MCP tool, the
// tray, the CLI) recomputes OAuth status from the CURRENT stored token on every
// read instead of a caller leaving HealthCalculatorInput.OAuthStatus at its zero
// value (""). The health calculator reads an empty OAuthStatus as "never
// authenticated" and reports "Authentication required" — even once the server
// is Connected/Ready with tools listed. Recomputing here means a later
// successful connection (which persists a fresh token) clears any stale
// auth-required verdict left over from an earlier failed or pending probe.
// Returns OAuthStatusNone (and zero refresh/expiry) when no token is stored or
// storage is unavailable.
func ResolveStatus(store *storage.Manager, serverName, serverURL, lastError string) (status OAuthStatus, hasRefreshToken bool, tokenExpiresAt time.Time) {
	if store == nil {
		return OAuthStatusNone, false, time.Time{}
	}
	serverKey := GenerateServerKey(serverName, serverURL)
	token, err := store.GetOAuthToken(serverKey)
	if err != nil || token == nil {
		return OAuthStatusNone, false, time.Time{}
	}
	return CalculateOAuthStatus(token, lastError), token.RefreshToken != "", token.ExpiresAt
}

// IsOAuthError checks if an error message indicates an OAuth-related problem.
// This is the exported version for use by other packages.
func IsOAuthError(err string) bool {
	return containsOAuthError(err)
}

// containsOAuthError checks if an error message indicates an OAuth-related problem.
func containsOAuthError(err string) bool {
	lowerErr := strings.ToLower(err)
	oauthIndicators := []string{
		"oauth",
		"authentication",
		"unauthorized",
		"401",
		"token",
		"authorization",
		"access denied",
	}
	for _, indicator := range oauthIndicators {
		if strings.Contains(lowerErr, indicator) {
			return true
		}
	}
	return false
}
