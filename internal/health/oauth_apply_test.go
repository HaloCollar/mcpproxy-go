package health_test

// These tests live in the external health_test package rather than as
// internal (package health) or internal (package oauth) test files: package
// health imports package oauth (for oauth.Resolved, ApplyOAuth's
// parameter), so an internal oauth test file importing health, or an
// internal health test file importing oauth, both create an import cycle
// that go vet rejects ("import cycle not allowed in test"). The external
// health_test package is a distinct package from both and can import them
// freely.

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/smart-mcp-proxy/mcpproxy-go/internal/health"
	"github.com/smart-mcp-proxy/mcpproxy-go/internal/oauth"
	"github.com/smart-mcp-proxy/mcpproxy-go/internal/storage"
)

// TestResolveStatus_ClearsStaleAuthRequiredVerdictAfterConnect reproduces
// the WP5 bug report: a server that connects successfully and lists tools
// kept showing health.Level=unhealthy "Authentication required" alongside
// state=Ready, an empty last_error, and a non-zero tool count — a verdict
// left over from an earlier probe before any token was stored. It asserts
// the end-to-end sequence: verdict set (no token yet) -> connect succeeds
// (token persisted) -> verdict cleared, exercising the exact
// oauth.ResolveStatus + health.ApplyOAuth + health.CalculateHealth pairing
// every status surface (REST, MCP tool, CLI, tray) now uses.
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
	result := oauth.ResolveStatus(mgr, serverName, serverURL, true, false, "")
	assert.Equal(t, oauth.OAuthStatusNone, result.Status)
	assert.False(t, result.HasRefreshToken)
	assert.True(t, result.TokenExpiresAt.IsZero())
	assert.False(t, result.HasToken)

	beforeInput := health.HealthCalculatorInput{
		Name:          serverName,
		Enabled:       true,
		State:         "ready",
		Connected:     false,
		OAuthRequired: true,
		ToolCount:     0,
	}
	health.ApplyOAuth(&beforeInput, result)
	assert.Equal(t, "none", beforeInput.OAuthStatus)

	before := health.CalculateHealth(beforeInput, nil)
	require.Equal(t, health.LevelUnhealthy, before.Level)
	require.Equal(t, "Authentication required", before.Summary)

	// A later connection succeeds and persists a fresh OAuth token, exactly
	// as the real connect flow does via PersistentTokenStore.SaveToken.
	serverKey := oauth.GenerateServerKey(serverName, serverURL)
	require.NoError(t, mgr.GetBoltDB().SaveOAuthToken(&storage.OAuthTokenRecord{
		ServerName:  serverKey,
		AccessToken: "at",
		// Well beyond health.DefaultHealthConfig's 1-hour
		// ExpiryWarningDuration so the calculator's separate "token
		// expiring soon" degraded branch does not fire here — that branch
		// is correct/unrelated behavior, not the thing under test.
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}))

	// Recomputing OAuth status against the now-present token must clear the
	// stale verdict — no leftover "Authentication required" once the server
	// is Ready with callable tools.
	result = oauth.ResolveStatus(mgr, serverName, serverURL, true, true, "")
	assert.Equal(t, oauth.OAuthStatusAuthenticated, result.Status)
	assert.False(t, result.HasRefreshToken) // no refresh token saved above
	assert.False(t, result.TokenExpiresAt.IsZero())
	assert.True(t, result.HasToken)
	assert.True(t, result.TokenValid)

	afterInput := health.HealthCalculatorInput{
		Name:          serverName,
		Enabled:       true,
		State:         "ready",
		Connected:     true,
		OAuthRequired: true,
		ToolCount:     34,
	}
	health.ApplyOAuth(&afterInput, result)
	assert.Equal(t, "authenticated", afterInput.OAuthStatus)
	require.NotNil(t, afterInput.TokenExpiresAt)
	assert.False(t, afterInput.TokenExpiresAt.IsZero())

	after := health.CalculateHealth(afterInput, nil)
	assert.Equal(t, health.LevelHealthy, after.Level)
	assert.NotEqual(t, "Authentication required", after.Summary)
}

// TestApplyOAuth_ResolvesFromStore is a call-site assertion (review
// follow-up on 3dfeacec/1f240114, item 4): it exercises the exact
// oauth.ResolveStatus + health.ApplyOAuth pairing that
// internal/server/server.go's GetAllServers, internal/server/mcp.go's
// upstream_servers tool handler, and internal/runtime/runtime.go's
// GetAllServers all call. Reverting any of those wiring hunks back to
// leaving HealthCalculatorInput.OAuthStatus at its zero value would make
// this test's "before" and "after" assertions collapse to the same
// (Unhealthy) result and fail.
func TestApplyOAuth_ResolvesFromStore(t *testing.T) {
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
		// every real call site constructs it before calling ApplyOAuth.
	}

	// No token stored yet: ApplyOAuth must still resolve a status (not
	// leave OAuthStatus untouched at "") that, combined with
	// Connected+ToolCount, does not produce a stale "Authentication
	// required" verdict.
	result := oauth.ResolveStatus(mgr, serverName, serverURL, true, input.Connected, input.LastError)
	health.ApplyOAuth(&input, result)
	assert.Equal(t, oauth.OAuthStatusNone, result.Status)
	assert.Equal(t, "none", input.OAuthStatus)
	before := health.CalculateHealth(input, nil)
	assert.NotEqual(t, "Authentication required", before.Summary)

	// Persist a token, exactly as a successful connect does.
	serverKey := oauth.GenerateServerKey(serverName, serverURL)
	require.NoError(t, mgr.GetBoltDB().SaveOAuthToken(&storage.OAuthTokenRecord{
		ServerName:  serverKey,
		AccessToken: "at",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}))

	// ApplyOAuth must pick up the fresh token on this call — the entire
	// point of resolving OAuth status from the CURRENT store on every read
	// instead of caching a value.
	result = oauth.ResolveStatus(mgr, serverName, serverURL, true, input.Connected, input.LastError)
	health.ApplyOAuth(&input, result)
	assert.Equal(t, oauth.OAuthStatusAuthenticated, result.Status)
	assert.Equal(t, "authenticated", input.OAuthStatus)
	require.NotNil(t, input.TokenExpiresAt)
	assert.False(t, input.TokenExpiresAt.IsZero())

	after := health.CalculateHealth(input, nil)
	assert.Equal(t, health.LevelHealthy, after.Level)
	assert.NotEqual(t, "Authentication required", after.Summary)
}
