// Package tagscope carries request-scoped, tag-based upstream filtering for MCP
// client sessions (Option B — per-upstream tags/scopes).
//
// A client declares its scope with a `?tags=a,b` query parameter on the /mcp
// endpoint URL. The tag middleware resolves that scope once against the current
// config snapshot into the concrete set of visible server names — untagged
// ("general") servers plus tagged servers whose tags intersect the request —
// and injects it into the request context. retrieve_tools filters its index
// results by the scope and call_tool_* refuses out-of-scope servers.
//
// A request with no `?tags=` parameter carries no scope (nil) and therefore
// sees every server, preserving pre-feature behaviour. The design mirrors the
// Spec 057 profile scope but resolves membership by tag intersection rather
// than an explicit server list.
package tagscope

import (
	"context"
	"strings"
)

// TagScope is the immutable, request-scoped set of servers a tagged client
// session may see. It is resolved by the tag middleware from the `?tags=` query
// and never mutated for the lifetime of a request.
type TagScope struct {
	// tags is the requested tag set (trimmed, for rejection messages).
	tags []string
	// allowed is the resolved set of visible server names.
	allowed map[string]struct{}
}

// NewTagScope builds a scope for the given requested tags over the resolved set
// of allowed server names. The returned scope is always non-nil; an empty
// allowed set is a legal "deny everything except nothing" scope (which only
// happens when there are no servers at all).
func NewTagScope(requestedTags, allowedServers []string) *TagScope {
	set := make(map[string]struct{}, len(allowedServers))
	for _, s := range allowedServers {
		set[s] = struct{}{}
	}
	return &TagScope{tags: requestedTags, allowed: set}
}

// Allows reports whether the named server is visible under this scope.
//
// A nil receiver means the request did not declare a tag scope (no `?tags=`
// parameter) and therefore is not tag-filtered — every server is allowed. A
// non-nil scope allows only servers in its resolved set.
func (t *TagScope) Allows(serverName string) bool {
	if t == nil {
		return true
	}
	if serverName == "" {
		return false
	}
	_, ok := t.allowed[serverName]
	return ok
}

// AllowedServerNames returns the list of server names visible under this
// scope. Returns nil for a nil receiver (allow-all — no restriction list).
func (t *TagScope) AllowedServerNames() []string {
	if t == nil {
		return nil
	}
	out := make([]string, 0, len(t.allowed))
	for s := range t.allowed {
		out = append(out, s)
	}
	return out
}

// Tags returns the requested tag set (for logging / rejection messages).
// Returns nil for a nil receiver.
func (t *TagScope) Tags() []string {
	if t == nil {
		return nil
	}
	return t.tags
}

// TagsString returns the requested tags joined with commas, for messages.
func (t *TagScope) TagsString() string {
	if t == nil {
		return ""
	}
	return strings.Join(t.tags, ",")
}

// ParseTagsParam parses the raw `?tags=` query values into a trimmed,
// de-duplicated tag list. It accepts both repeated params (`?tags=a&tags=b`)
// and comma-separated values (`?tags=a,b`). Returns nil when no non-empty tag
// is present, which the middleware treats as "no scope declared".
func ParseTagsParam(values []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			t := strings.TrimSpace(part)
			if t == "" {
				continue
			}
			key := strings.ToLower(t)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}

// tagScopeKey is an unexported context key avoiding cross-package collisions.
type tagScopeKey struct{}

// WithTagScope returns a context carrying the given TagScope.
func WithTagScope(ctx context.Context, t *TagScope) context.Context {
	return context.WithValue(ctx, tagScopeKey{}, t)
}

// TagScopeFromContext extracts the TagScope, or nil when the request did not
// declare a tag scope (no filtering).
func TagScopeFromContext(ctx context.Context) *TagScope {
	t, _ := ctx.Value(tagScopeKey{}).(*TagScope)
	return t
}
