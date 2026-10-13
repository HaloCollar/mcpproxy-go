package server

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/smart-mcp-proxy/mcpproxy-go/internal/config"
	"github.com/smart-mcp-proxy/mcpproxy-go/internal/tagscope"
)

// Option B hardening: the per-session `?tags=` scope must hold on every tool
// surface, not only retrieve_tools / call_tool_* / code_execution. The helpers
// below close the remaining surfaces: direct-mode tools (/mcp/all), the
// upstream_servers management tool and the quarantine_security tool.

// filterDirectToolsForTagScope hides direct-mode tools (serverName__toolName)
// whose server is outside the session's tag scope. A request without a tag
// scope is not filtered.
func (p *MCPProxyServer) filterDirectToolsForTagScope(ctx context.Context, tools []mcp.Tool) []mcp.Tool {
	scope := tagscope.TagScopeFromContext(ctx)
	if scope == nil || len(tools) == 0 {
		return tools
	}
	filtered := make([]mcp.Tool, 0, len(tools))
	for _, tool := range tools {
		serverName, ok := p.lookupDirectToolServer(tool.Name)
		if !ok {
			// Not registered as a direct upstream tool. Fall back to parsing;
			// a name that does not parse is not an upstream tool at all.
			parsed, _, parsedOK := ParseDirectToolName(tool.Name)
			if !parsedOK {
				filtered = append(filtered, tool)
				continue
			}
			serverName = parsed
		}
		if scope.Allows(serverName) {
			filtered = append(filtered, tool)
		}
	}
	return filtered
}

// setDirectToolServers records the direct tool name -> real server name map.
func (p *MCPProxyServer) setDirectToolServers(servers map[string]string) {
	p.directToolPermsMu.Lock()
	defer p.directToolPermsMu.Unlock()
	if len(servers) == 0 {
		p.directToolServers = nil
		return
	}
	copied := make(map[string]string, len(servers))
	for k, v := range servers {
		copied[k] = v
	}
	p.directToolServers = copied
}

// lookupDirectToolServer returns the real upstream server of a direct tool.
func (p *MCPProxyServer) lookupDirectToolServer(directName string) (string, bool) {
	p.directToolPermsMu.RLock()
	defer p.directToolPermsMu.RUnlock()
	s, ok := p.directToolServers[directName]
	return s, ok
}

// tagScopeOutOfScopeMessage is the shared refusal text for out-of-scope servers.
func tagScopeOutOfScopeMessage(scope *tagscope.TagScope, serverName string) string {
	return fmt.Sprintf("server '%s' is out of scope for this session (session tags: %s)", serverName, scope.TagsString())
}

// tagScopeManagementBlock returns a non-empty refusal message when a tag-scoped
// session must not run the given upstream_servers / quarantine_security
// operation against the named server. Unscoped sessions are never blocked.
//
//   - list / list_quarantined: allowed; the handlers filter their output.
//   - add / add_from_registry: allowed for a NEW server. A plain `add` upserts,
//     so overwriting an EXISTING out-of-scope server is refused.
//     (add_from_registry goes through Server.AddServer, which already refuses
//     an existing name.)
//   - every other operation: the named server must be in scope. An empty name
//     is refused (Allows("") is false), so "all servers" forms cannot widen
//     the scope.
func (p *MCPProxyServer) tagScopeManagementBlock(ctx context.Context, operation, name string) string {
	scope := tagscope.TagScopeFromContext(ctx)
	if scope == nil {
		return ""
	}
	switch operation {
	case operationList, "list_quarantined":
		return ""
	case operationAdd:
		if name == "" || scope.Allows(name) || !p.upstreamExists(name) {
			return ""
		}
	case "add_from_registry":
		return ""
	default:
		if scope.Allows(name) {
			return ""
		}
	}
	if name == "" {
		return fmt.Sprintf("operation '%s' requires an explicit in-scope server name for this session (session tags: %s)", operation, scope.TagsString())
	}
	return tagScopeOutOfScopeMessage(scope, name)
}

// upstreamExists reports whether a server with this name is already stored.
// It returns true when storage is unavailable (nil). A lookup error is treated
// as "not stored", because storage reports not-found as an error; a plain add
// of a name that truly does not exist cannot widen the session's scope.
func (p *MCPProxyServer) upstreamExists(name string) bool {
	if p.storage == nil {
		return true
	}
	existing, err := p.storage.GetUpstreamServer(name)
	return err == nil && existing != nil
}

// requireServerTagsEnabled reports whether the require_server_tags policy is on.
func (p *MCPProxyServer) requireServerTagsEnabled() bool {
	if p.mainServer != nil && p.mainServer.runtime != nil {
		if cfg := p.mainServer.runtime.Config(); cfg != nil {
			return cfg.RequireServerTags
		}
	}
	return false
}

// validatePatchedTags enforces require_server_tags when an update/patch changes
// the tag set: a patch must not clear the tags of a server and thereby make it
// visible to every session. A patch that leaves tags untouched (nil) is not
// re-validated, so pre-existing untagged servers stay editable.
func (p *MCPProxyServer) validatePatchedTags(patch *config.ServerConfig, merged *config.ServerConfig) error {
	if patch == nil || patch.Tags == nil || merged == nil {
		return nil
	}
	return config.ValidateServerTagRequirement(p.requireServerTagsEnabled(), merged.Name, merged.Tags)
}
