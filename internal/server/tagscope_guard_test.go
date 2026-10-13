package server

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smart-mcp-proxy/mcpproxy-go/internal/config"
	"github.com/smart-mcp-proxy/mcpproxy-go/internal/tagscope"
)

func scopedCtx(allowed ...string) context.Context {
	return tagscope.WithTagScope(context.Background(), tagscope.NewTagScope([]string{"halo"}, allowed))
}

func TestFilterDirectToolsForTagScope(t *testing.T) {
	p := &MCPProxyServer{}
	tools := []mcp.Tool{
		{Name: "halo-srv__read"},
		{Name: "personal__secret"},
		{Name: "general__ping"},
		{Name: "not_a_direct_tool"},
	}

	t.Run("no scope returns all tools", func(t *testing.T) {
		got := p.filterDirectToolsForTagScope(context.Background(), tools)
		assert.Len(t, got, 4)
	})

	t.Run("scope hides out-of-scope servers", func(t *testing.T) {
		got := p.filterDirectToolsForTagScope(scopedCtx("halo-srv", "general"), tools)
		var names []string
		for _, tl := range got {
			names = append(names, tl.Name)
		}
		assert.ElementsMatch(t, []string{"halo-srv__read", "general__ping", "not_a_direct_tool"}, names)
	})
}

func TestFilterDirectToolsForTagScope_ServerNameWithSeparator(t *testing.T) {
	// Server "a__b" (out of scope) exposes tool "x" as "a__b__x"; parsing the
	// first "__" would wrongly attribute it to in-scope server "a".
	p := &MCPProxyServer{}
	p.setDirectToolServers(map[string]string{"a__b__x": "a__b", "a__y": "a"})
	got := p.filterDirectToolsForTagScope(scopedCtx("a"), []mcp.Tool{{Name: "a__b__x"}, {Name: "a__y"}})
	require.Len(t, got, 1)
	assert.Equal(t, "a__y", got[0].Name)
}

func TestDirectModeHandler_RefusesOutOfScopeServer(t *testing.T) {
	p := &MCPProxyServer{}
	h := p.makeDirectModeHandler("personal", "secret", nil)
	res, err := h(scopedCtx("halo-srv"), mcp.CallToolRequest{})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.IsError)
	require.NotEmpty(t, res.Content)
	text, ok := res.Content[0].(mcp.TextContent)
	require.True(t, ok)
	assert.Contains(t, text.Text, "out of scope")
}

func TestTagScopeManagementBlock(t *testing.T) {
	// storage == nil → upstreamExists fails closed (treated as existing).
	p := &MCPProxyServer{}
	ctx := scopedCtx("halo-srv")

	cases := []struct {
		name      string
		ctx       context.Context
		operation string
		server    string
		blocked   bool
	}{
		{"unscoped patch of anything", context.Background(), "patch", "personal", false},
		{"list is allowed (handler filters)", ctx, "list", "", false},
		{"list_quarantined is allowed (handler filters)", ctx, "list_quarantined", "", false},
		{"patch in-scope", ctx, "patch", "halo-srv", false},
		{"patch out-of-scope (retag escalation)", ctx, "patch", "personal", true},
		{"update out-of-scope", ctx, "update", "personal", true},
		{"remove out-of-scope", ctx, "remove", "personal", true},
		{"enable out-of-scope", ctx, "enable", "personal", true},
		{"disable out-of-scope", ctx, "disable", "personal", true},
		{"restart out-of-scope", ctx, "restart", "personal", true},
		{"tail_log out-of-scope", ctx, "tail_log", "personal", true},
		{"approve_tool out-of-scope", ctx, "approve_tool", "personal", true},
		{"approve_all_tools out-of-scope", ctx, "approve_all_tools", "personal", true},
		{"inspect_tools out-of-scope", ctx, "inspect_tools", "personal", true},
		{"quarantine out-of-scope", ctx, "quarantine", "personal", true},
		{"named op with empty name", ctx, "approve_all_tools", "", true},
		{"add overwriting existing out-of-scope", ctx, "add", "personal", true},
		{"add in-scope name", ctx, "add", "halo-srv", false},
		{"add_from_registry (AddServer refuses duplicates)", ctx, "add_from_registry", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := p.tagScopeManagementBlock(tc.ctx, tc.operation, tc.server)
			if tc.blocked {
				assert.NotEmpty(t, msg)
				assert.True(t, strings.Contains(msg, "scope"), msg)
			} else {
				assert.Empty(t, msg)
			}
		})
	}
}

func TestValidatePatchedTags(t *testing.T) {
	// No runtime → require_server_tags reads as off; validate the pure helper too.
	p := &MCPProxyServer{}
	merged := &config.ServerConfig{Name: "s", Tags: nil}
	assert.NoError(t, p.validatePatchedTags(&config.ServerConfig{Tags: []string{}}, merged),
		"policy off: clearing tags is allowed")
	assert.NoError(t, p.validatePatchedTags(&config.ServerConfig{}, merged),
		"tags untouched: never re-validated")

	assert.Error(t, config.ValidateServerTagRequirement(true, "s", nil),
		"policy on: an empty merged tag set is rejected")
	assert.NoError(t, config.ValidateServerTagRequirement(true, "s", []string{"halo"}))
}
