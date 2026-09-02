package health

import (
	"github.com/smart-mcp-proxy/mcpproxy-go/internal/oauth"
)

// ApplyOAuth writes an already-resolved oauth.Resolved verdict (produced by
// oauth.ResolveStatus) into input's OAuthStatus, HasRefreshToken, and
// TokenExpiresAt fields. Every call site that builds a
// HealthCalculatorInput for an OAuth-relevant server (REST
// /api/v1/servers, the upstream_servers MCP tool, Runtime.GetAllServers)
// funnels through this single helper — paired with oauth.ResolveStatus —
// instead of hand-copying the OAuth fields, so a later successful
// connection is guaranteed to clear a stale auth-required verdict on every
// surface identically.
//
// This lives in package health, not oauth: internal/oauth has no
// dependency on internal/health, so pairing ResolveStatus's plain Resolved
// struct with this helper here (rather than oauth accepting or returning a
// *HealthCalculatorInput directly) keeps that dependency one-directional.
func ApplyOAuth(input *HealthCalculatorInput, res oauth.Resolved) {
	input.OAuthStatus = res.Status.String()
	input.HasRefreshToken = res.HasRefreshToken
	if !res.TokenExpiresAt.IsZero() {
		expiresAt := res.TokenExpiresAt
		input.TokenExpiresAt = &expiresAt
	}
}
