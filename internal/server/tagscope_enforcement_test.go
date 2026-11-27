package server_test

import (
	"context"
	"testing"

	"github.com/smart-mcp-proxy/mcpproxy-go/internal/tagscope"

	"github.com/stretchr/testify/assert"
)

// TestCodeExecution_TagScopeBlocksCallTool proves that a per-session tag scope
// is enforced on the code_execution call path (Option B), mirroring the profile
// scope enforcement. It exercises the same helpers as the profile test.
func TestCodeExecution_TagScopeBlocksCallTool(t *testing.T) {
	ctx := context.Background()

	t.Run("tag scope allows only in-scope servers", func(t *testing.T) {
		p := newCodeExecProxy(t)
		// Session scope resolves to only "halo-srv"; calling "personal-srv" is denied.
		scope := tagscope.NewTagScope([]string{"halo"}, []string{"halo-srv"})
		sctx := tagscope.WithTagScope(ctx, scope)

		ok, code := codeExecCallToolResult(t, sctx, p, "personal-srv", "do")
		assert.False(t, ok, "server outside the tag scope must be blocked")
		assert.Equal(t, "SERVER_NOT_ALLOWED", code)
	})

	t.Run("empty tag scope blocks everything (no server matched)", func(t *testing.T) {
		p := newCodeExecProxy(t)
		scope := tagscope.NewTagScope([]string{"halo"}, nil)
		sctx := tagscope.WithTagScope(ctx, scope)

		ok, code := codeExecCallToolResult(t, sctx, p, "anyserver", "anytool")
		assert.False(t, ok, "an empty resolved tag scope must block call_tool")
		assert.Equal(t, "SERVER_NOT_ALLOWED", code)
	})

	t.Run("no tag scope: backward compatible (not blocked as SERVER_NOT_ALLOWED)", func(t *testing.T) {
		p := newCodeExecProxy(t)
		ok, code := codeExecCallToolResult(t, ctx, p, "anyserver", "anytool")
		assert.False(t, ok, "no upstream configured, call fails")
		assert.NotEqual(t, "SERVER_NOT_ALLOWED", code,
			"without a tag scope, an empty allow-list must not block as SERVER_NOT_ALLOWED")
	})
}
