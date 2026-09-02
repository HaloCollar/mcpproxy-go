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
	// that produces the "Authentication required" verdict.
	status, hasRefresh, expiresAt := ResolveStatus(mgr, serverName, serverURL, "")
	assert.Equal(t, OAuthStatusNone, status)
	assert.False(t, hasRefresh)
	assert.True(t, expiresAt.IsZero())

	before := health.CalculateHealth(health.HealthCalculatorInput{
		Name:          serverName,
		Enabled:       true,
		State:         "ready",
		Connected:     true,
		OAuthRequired: true,
		OAuthStatus:   status.String(),
		ToolCount:     34,
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
	status, hasRefresh, expiresAt = ResolveStatus(mgr, serverName, serverURL, "")
	assert.Equal(t, OAuthStatusAuthenticated, status)
	assert.False(t, hasRefresh) // no refresh token saved above
	assert.False(t, expiresAt.IsZero())

	after := health.CalculateHealth(health.HealthCalculatorInput{
		Name:          serverName,
		Enabled:       true,
		State:         "ready",
		Connected:     true,
		OAuthRequired: true,
		OAuthStatus:   status.String(),
		ToolCount:     34,
	}, nil)
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
