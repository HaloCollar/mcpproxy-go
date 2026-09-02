package oauth

import (
	"os"
	"testing"
	"time"

	"github.com/smart-mcp-proxy/mcpproxy-go/internal/health"
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

// TestResolveStatus_ClearsStaleAuthRequiredVerdictAfterConnect reproduces the
// WP5 bug report: a server that connects successfully and lists tools kept
// showing health.Level=unhealthy "Authentication required" alongside
// state=Ready, an empty last_error, and a non-zero tool count — a verdict left
// over from an earlier probe before any token was stored. It asserts the
// end-to-end sequence: verdict set (no token yet) -> connect succeeds (token
// persisted) -> verdict cleared, exercising the exact ResolveStatus +
// CalculateHealth pairing every status surface (REST, MCP tool, CLI, tray)
// now uses.
func TestResolveStatus_ClearsStaleAuthRequiredVerdictAfterConnect(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "oauth-resolve-status-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	mgr, err := storage.NewManager(tmpDir, zap.NewNop().Sugar())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })

	const (
		serverName = "notion"
		serverURL  = "https://mcp.notion.com/mcp"
	)

	// Before any token is stored — e.g., an earlier failed/pending OAuth
	// probe — ResolveStatus must report "none", which is exactly the input
	// that produces the "Authentication required" verdict. Connected is
	// false here (matches an in-progress/failed probe, not yet Ready).
	result := ResolveStatus(mgr, serverName, serverURL, true, false, "")
	assert.Equal(t, OAuthStatusNone, result.Status)
	assert.False(t, result.HasRefreshToken)
	assert.True(t, result.TokenExpiresAt.IsZero())
	assert.False(t, result.HasToken)

	before := health.CalculateHealth(health.HealthCalculatorInput{
		Name:          serverName,
		Enabled:       true,
		State:         "ready",
		Connected:     false,
		OAuthRequired: true,
		OAuthStatus:   result.Status.String(),
		ToolCount:     0,
	}, nil)
	require.Equal(t, health.LevelUnhealthy, before.Level)
	require.Equal(t, "Authentication required", before.Summary)

	// A later connection succeeds and persists a fresh OAuth token, exactly
	// as the real connect flow does via PersistentTokenStore.SaveToken.
	serverKey := GenerateServerKey(serverName, serverURL)
	require.NoError(t, mgr.GetBoltDB().SaveOAuthToken(&storage.OAuthTokenRecord{
		ServerName:  serverKey,
		AccessToken: "at",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	// Recomputing OAuth status against the now-present token must clear the
	// stale verdict — no leftover "Authentication required" once the server
	// is Ready with callable tools.
	result = ResolveStatus(mgr, serverName, serverURL, true, true, "")
	assert.Equal(t, OAuthStatusAuthenticated, result.Status)
	assert.False(t, result.HasRefreshToken) // no refresh token saved above
	assert.False(t, result.TokenExpiresAt.IsZero())
	assert.True(t, result.HasToken)
	assert.True(t, result.TokenValid)

	after := health.CalculateHealth(health.HealthCalculatorInput{
		Name:          serverName,
		Enabled:       true,
		State:         "ready",
		Connected:     true,
		OAuthRequired: true,
		OAuthStatus:   result.Status.String(),
		ToolCount:     34,
	}, nil)
	assert.Equal(t, health.LevelHealthy, after.Level)
	assert.NotEqual(t, "Authentication required", after.Summary)
}

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

// TestApplyToHealthInput_ResolvesFromStore is a call-site assertion (review
// follow-up on 3dfeacec, item 4): it exercises the exact shared constructor
// that internal/server/server.go's GetAllServers, internal/server/mcp.go's
// upstream_servers tool handler, and internal/runtime/runtime.go's
// GetAllServers all call. Reverting any of those wiring hunks back to
// leaving HealthCalculatorInput.OAuthStatus at its zero value would make
// this test's "before" and "after" assertions collapse to the same
// (Unhealthy) result and fail.
func TestApplyToHealthInput_ResolvesFromStore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "oauth-apply-health-input-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	mgr, err := storage.NewManager(tmpDir, zap.NewNop().Sugar())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })

	const (
		serverName = "notion"
		serverURL  = "https://mcp.notion.com/mcp"
	)

	input := health.HealthCalculatorInput{
		Name:          serverName,
		Enabled:       true,
		State:         "connected",
		Connected:     true,
		OAuthRequired: true,
		ToolCount:     34,
		// OAuthStatus intentionally left at its zero value ("") here, as
		// every real call site constructs it before calling
		// ApplyToHealthInput.
	}

	// No token stored yet: ApplyToHealthInput must still resolve a status
	// (not leave OAuthStatus untouched at "") that, combined with
	// Connected+ToolCount, does not produce a stale "Authentication
	// required" verdict.
	result := ApplyToHealthInput(&input, mgr, serverName, serverURL, true)
	assert.Equal(t, OAuthStatusNone, result.Status)
	assert.Equal(t, "none", input.OAuthStatus)
	before := health.CalculateHealth(input, nil)
	assert.NotEqual(t, "Authentication required", before.Summary)

	// Persist a token, exactly as a successful connect does. Expiry is set
	// well beyond health.DefaultHealthConfig's 1-hour ExpiryWarningDuration
	// so the calculator's separate "token expiring soon" degraded branch
	// (calculator.go ~line 233) does not fire here — that branch is
	// correct/unrelated behavior, not the thing under test.
	serverKey := GenerateServerKey(serverName, serverURL)
	require.NoError(t, mgr.GetBoltDB().SaveOAuthToken(&storage.OAuthTokenRecord{
		ServerName:  serverKey,
		AccessToken: "at",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}))

	// ApplyToHealthInput must pick up the fresh token on this call — the
	// entire point of resolving OAuth status from the CURRENT store on
	// every read instead of caching a value.
	result = ApplyToHealthInput(&input, mgr, serverName, serverURL, true)
	assert.Equal(t, OAuthStatusAuthenticated, result.Status)
	assert.Equal(t, "authenticated", input.OAuthStatus)
	require.NotNil(t, input.TokenExpiresAt)
	assert.False(t, input.TokenExpiresAt.IsZero())

	after := health.CalculateHealth(input, nil)
	assert.Equal(t, health.LevelHealthy, after.Level)
	assert.NotEqual(t, "Authentication required", after.Summary)
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
