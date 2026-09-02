// Package oauth provides OAuth authentication functionality for MCP servers.
package oauth

import (
	"strings"
	"time"

	"github.com/smart-mcp-proxy/mcpproxy-go/internal/health"
	"github.com/smart-mcp-proxy/mcpproxy-go/internal/storage"

	"go.uber.org/zap"
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
//
// A zero ExpiresAt means the token does not expire (matches
// PersistentTokenStore.GetToken, config.go's OAuth expiry checks, and
// Runtime.GetAllServers) and must never be treated as already-expired.
func CalculateOAuthStatus(token *storage.OAuthTokenRecord, lastError string) OAuthStatus {
	if token == nil {
		return OAuthStatusNone
	}
	if lastError != "" && containsOAuthError(lastError) {
		return OAuthStatusError
	}
	if !token.ExpiresAt.IsZero() && time.Now().After(token.ExpiresAt) {
		return OAuthStatusExpired
	}
	return OAuthStatusAuthenticated
}

// ResolveStatusResult is the outcome of ResolveStatus.
type ResolveStatusResult struct {
	// Status is the health-facing OAuth status for the server.
	Status OAuthStatus
	// HasRefreshToken reports whether the stored token can be auto-refreshed.
	HasRefreshToken bool
	// TokenExpiresAt is the stored token's expiry, zero when the token has
	// none or none was found.
	TokenExpiresAt time.Time
	// TokenValid reports whether a token exists and is not expired — purely
	// from the token's own expiry, ignoring any lastError-driven downgrade to
	// OAuthStatusError below. Mirrors the pre-escalation "token_valid" flag
	// Runtime.GetAllServers has always surfaced in its "oauth" config map.
	TokenValid bool
	// HasToken reports whether a persisted token was found for this server,
	// independent of its validity — lets a caller distinguish "token found
	// but expired/errored" from "no token found at all" for display purposes
	// (e.g. only emitting token_expires_at/token_valid when a token exists).
	HasToken bool
	// AutodiscoveredOAuth reports whether OAuth was inferred for this server
	// without an explicit config — because a token was found, or because
	// lastError looked OAuth-shaped — as opposed to the caller already
	// knowing the server is OAuth-enabled via its static config.
	AutodiscoveredOAuth bool
}

// ResolveStatus looks up the persisted OAuth token for serverName+serverURL
// and derives the health-facing OAuthStatus, refresh-token presence, and
// expiry from it, mirroring the semantics Runtime.GetAllServers has always
// implemented inline. Centralizing this pairing here means every status
// surface (REST /api/v1/servers, the upstream_servers MCP tool, the tray,
// the CLI) recomputes OAuth status from the CURRENT stored token on every
// read instead of a caller leaving HealthCalculatorInput.OAuthStatus at its
// zero value (""). The health calculator reads an empty/none OAuthStatus on
// a NOT-connected server as "never authenticated" and reports "Authentication
// required"; recomputing here means a later successful connection (which
// persists a fresh token) clears any stale auth-required verdict left over
// from an earlier failed or pending probe.
//
// connected indicates the server's CURRENT connection state is Ready/Connected.
// When true, lastError is ignored entirely: a stale error from an earlier
// failed attempt must never downgrade a server that is presently connected
// and working — that is exactly the "left over from an earlier probe" bug
// this function exists to prevent. oauthConfigured reports whether the
// caller already treats this server as OAuth-enabled (explicit
// config.ServerConfig.OAuth != nil) before this lookup runs; it only affects
// classification when no token is found.
//
// A token's zero ExpiresAt means it does not expire and is never treated as
// expired (see CalculateOAuthStatus).
//
// A storage lookup error is logged at warn and treated the same as "no
// token found" — it must never be allowed to assert a confident "not
// authenticated" verdict on its own; health.CalculateHealth additionally
// only turns a None/empty OAuthStatus into "Authentication required" when
// the server is NOT connected, so a transient storage hiccup on an actually
// Connected server cannot surface a false alarm either way.
func ResolveStatus(store *storage.Manager, serverName, serverURL string, oauthConfigured, connected bool, lastError string) ResolveStatusResult {
	if connected {
		lastError = ""
	}

	var token *storage.OAuthTokenRecord
	if store != nil {
		serverKey := GenerateServerKey(serverName, serverURL)
		t, err := store.GetOAuthToken(serverKey)
		if err != nil {
			zap.L().Warn("oauth: failed to look up stored token; treating server as not (yet) authenticated rather than asserting a verdict",
				zap.String("server", serverName),
				zap.String("server_key", serverKey),
				zap.Error(err))
		}
		token = t
	}

	var result ResolveStatusResult
	knownOAuth := oauthConfigured

	switch {
	case token != nil:
		result.HasToken = true
		result.HasRefreshToken = token.RefreshToken != ""
		result.TokenExpiresAt = token.ExpiresAt
		result.AutodiscoveredOAuth = true
		knownOAuth = true
		if token.ExpiresAt.IsZero() || time.Now().Before(token.ExpiresAt) {
			result.TokenValid = true
			result.Status = OAuthStatusAuthenticated
		} else {
			result.Status = OAuthStatusExpired
		}
	default:
		// No token found. A server already known to require OAuth (explicit
		// config, or discovered via a token on a previous read) has simply
		// not authenticated yet; a server with no OAuth signal at all stays
		// None too — the caller decides whether that's meaningful based on
		// oauthConfigured/AutodiscoveredOAuth.
		result.Status = OAuthStatusNone
	}

	// lastError-based classification/escalation. Never overrides an
	// already-Expired verdict, and only fires for an OAuth-shaped error. A
	// server newly discovered as OAuth-requiring purely from this error (no
	// prior config, no token) reports None ("needs sign-in"); a server
	// already known to use OAuth (explicit config, or an existing — even if
	// now server-invalidated — token) reports Error instead.
	if result.Status != OAuthStatusExpired && lastError != "" && containsOAuthError(lastError) {
		if knownOAuth {
			result.Status = OAuthStatusError
		} else {
			result.Status = OAuthStatusNone
			result.AutodiscoveredOAuth = true
		}
	}

	return result
}

// ApplyToHealthInput resolves the given server's live OAuth status via
// ResolveStatus and writes it into input's OAuthStatus, HasRefreshToken, and
// TokenExpiresAt fields, using input.Connected and input.LastError as the
// connection signals. Every call site that builds a
// health.HealthCalculatorInput for an OAuth-relevant server (REST
// /api/v1/servers, the upstream_servers MCP tool, Runtime.GetAllServers)
// funnels through this single function instead of hand-rolling the OAuth
// fields, so a later successful connection is guaranteed to clear a stale
// auth-required verdict on every surface identically. Returns the full
// ResolveStatusResult for callers (e.g. Runtime.GetAllServers) that also need
// AutodiscoveredOAuth/TokenValid to build a display-only "oauth" config map.
func ApplyToHealthInput(input *health.HealthCalculatorInput, store *storage.Manager, serverName, serverURL string, oauthConfigured bool) ResolveStatusResult {
	result := ResolveStatus(store, serverName, serverURL, oauthConfigured, input.Connected, input.LastError)
	input.OAuthStatus = result.Status.String()
	input.HasRefreshToken = result.HasRefreshToken
	if !result.TokenExpiresAt.IsZero() {
		expiresAt := result.TokenExpiresAt
		input.TokenExpiresAt = &expiresAt
	}
	return result
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
