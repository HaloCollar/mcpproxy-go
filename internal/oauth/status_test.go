package oauth

import (
	"os"
	"testing"
	"time"

	"github.com/smart-mcp-proxy/mcpproxy-go/internal/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestOAuthStatus_String(t *testing.T) {
	tests := []struct {
		status   OAuthStatus
		expected string
	}{
		{OAuthStatusNone, "none"},
		{OAuthStatusAuthenticated, "authenticated"},
		{OAuthStatusExpired, "expired"},
		{OAuthStatusError, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestOAuthStatus_IsValid(t *testing.T) {
	tests := []struct {
		status   OAuthStatus
		expected bool
	}{
		{OAuthStatusNone, true},
		{OAuthStatusAuthenticated, true},
		{OAuthStatusExpired, true},
		{OAuthStatusError, true},
		{OAuthStatus("invalid"), false},
		{OAuthStatus(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.IsValid())
		})
	}
}

func TestCalculateOAuthStatus(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		token     *storage.OAuthTokenRecord
		lastError string
		expected  OAuthStatus
	}{
		{
			name:      "nil token returns none",
			token:     nil,
			lastError: "",
			expected:  OAuthStatusNone,
		},
		{
			name: "valid token returns authenticated",
			token: &storage.OAuthTokenRecord{
				ExpiresAt: now.Add(1 * time.Hour),
			},
			lastError: "",
			expected:  OAuthStatusAuthenticated,
		},
		{
			name: "expired token returns expired",
			token: &storage.OAuthTokenRecord{
				ExpiresAt: now.Add(-1 * time.Hour),
			},
			lastError: "",
			expected:  OAuthStatusExpired,
		},
		{
			name: "oauth error in lastError returns error",
			token: &storage.OAuthTokenRecord{
				ExpiresAt: now.Add(1 * time.Hour),
			},
			lastError: "OAuth authentication failed",
			expected:  OAuthStatusError,
		},
		{
			name: "unauthorized error returns error",
			token: &storage.OAuthTokenRecord{
				ExpiresAt: now.Add(1 * time.Hour),
			},
			lastError: "401 Unauthorized",
			expected:  OAuthStatusError,
		},
		{
			name: "token error returns error",
			token: &storage.OAuthTokenRecord{
				ExpiresAt: now.Add(1 * time.Hour),
			},
			lastError: "invalid token response",
			expected:  OAuthStatusError,
		},
		{
			name: "non-oauth error with valid token returns authenticated",
			token: &storage.OAuthTokenRecord{
				ExpiresAt: now.Add(1 * time.Hour),
			},
			lastError: "network timeout",
			expected:  OAuthStatusAuthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateOAuthStatus(tt.token, tt.lastError)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestResolveStatus_ClearsStaleAuthRequiredVerdictAfterConnect (the
// end-to-end WP5 bug reproduction pairing ResolveStatus with
// health.CalculateHealth) lives in
// internal/health/oauth_apply_test.go: an internal (package oauth) test
// file importing internal/health would create an import cycle now that
// health imports oauth (for health.ApplyOAuth's oauth.Resolved parameter).

// TestResolveStatus_ConnectedIgnoresStaleLastError reproduces the second
// half of the WP5 bug: a server that is currently Connected/Ready but still
// carries a stale LastError string from an earlier failed probe (the
// connection state machine does not always clear LastError on a later
// successful reconnect at every call site). ResolveStatus must ignore
// lastError entirely once connected — a live, working connection can never
// be downgraded to OAuthStatusError by leftover text from the past.
func TestResolveStatus_ConnectedIgnoresStaleLastError(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "oauth-resolve-status-connected-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	mgr, err := storage.NewManager(tmpDir, zap.NewNop().Sugar())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })

	const (
		serverName = "notion"
		serverURL  = "https://mcp.notion.com/mcp"
	)

	serverKey := GenerateServerKey(serverName, serverURL)
	require.NoError(t, mgr.GetBoltDB().SaveOAuthToken(&storage.OAuthTokenRecord{
		ServerName:  serverKey,
		AccessToken: "at",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	result := ResolveStatus(mgr, serverName, serverURL, true, true, "401 Unauthorized: token invalid")
	assert.Equal(t, OAuthStatusAuthenticated, result.Status, "a stale OAuth-shaped lastError must not downgrade a Connected server")

	// The same lastError on a NOT-connected server (a genuine current
	// failure) must still be classified as an error.
	result = ResolveStatus(mgr, serverName, serverURL, true, false, "401 Unauthorized: token invalid")
	assert.Equal(t, OAuthStatusError, result.Status)
}

// TestResolveStatus_NoURLNoOAuthConfigSkipsLookup guards review item 5: a
// server with no URL and no explicit OAuth config (e.g. a stdio-launched
// server) must get a neutral status without ResolveStatus touching the
// token store at all — GenerateServerKey(name, "") cannot correspond to a
// real persisted token, and OAuth does not apply to stdio transport.
// Exercised against a nil store (which would panic if ResolveStatus tried
// to call GetOAuthToken on it) to prove the lookup is skipped, not merely
// that it happens to return nothing.
func TestResolveStatus_NoURLNoOAuthConfigSkipsLookup(t *testing.T) {
	result := ResolveStatus(nil, "stdio-server", "", false, false, "")
	assert.Equal(t, OAuthStatusNone, result.Status)
	assert.False(t, result.HasToken)
	assert.False(t, result.AutodiscoveredOAuth)

	// Even a connected stdio server with no config reports the same neutral
	// status.
	result = ResolveStatus(nil, "stdio-server", "", false, true, "")
	assert.Equal(t, OAuthStatusNone, result.Status)
}

// TestCalculateOAuthStatus_ZeroExpiresAtNeverExpires guards review item 1: a
// token with no expires_in (zero ExpiresAt) must never be classified as
// expired — it matches PersistentTokenStore, config.go, and
// Runtime.GetAllServers, all of which treat a zero ExpiresAt as "does not
// expire".
func TestCalculateOAuthStatus_ZeroExpiresAtNeverExpires(t *testing.T) {
	token := &storage.OAuthTokenRecord{
		AccessToken: "at",
		// ExpiresAt intentionally left zero.
	}
	assert.Equal(t, OAuthStatusAuthenticated, CalculateOAuthStatus(token, ""))
}

func TestContainsOAuthError(t *testing.T) {
	tests := []struct {
		err      string
		expected bool
	}{
		{"OAuth authentication failed", true},
		{"oauth error", true},
		{"401 Unauthorized", true},
		{"unauthorized access", true},
		{"AUTHENTICATION required", true},
		{"invalid token", true},
		{"Token expired", true},
		{"authorization denied", true},
		{"access denied by server", true},
		{"network timeout", false},
		{"connection refused", false},
		{"server error", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.err, func(t *testing.T) {
			result := containsOAuthError(tt.err)
			assert.Equal(t, tt.expected, result, "containsOAuthError(%q) = %v, want %v", tt.err, result, tt.expected)
		})
	}
}
