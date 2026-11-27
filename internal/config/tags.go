package config

import (
	"fmt"
	"strings"
)

// NormalizeTags trims whitespace, drops empty entries, and de-duplicates the
// given tags case-insensitively while preserving the first-seen casing and
// order. It is applied to tags supplied at registration time (CLI/MCP/REST) so
// stored tags are clean and stable. A nil/empty input returns nil so an
// untagged server serializes byte-identically to the pre-feature shape.
func NormalizeTags(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, t := range in {
		trimmed := strings.TrimSpace(t)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// tagsIntersect reports whether the two tag sets share at least one tag,
// compared case-insensitively after trimming.
func tagsIntersect(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, t := range a {
		set[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}
	for _, t := range b {
		if _, ok := set[strings.ToLower(strings.TrimSpace(t))]; ok {
			return true
		}
	}
	return false
}

// ServersMatchingTags returns the names of servers visible to a client session
// that declared the given tag scope. Visibility rule (spec Option B, FR-1/FR-5):
//   - a server with no tags is "general" and always visible;
//   - a tagged server is visible only when its tags intersect the requested set.
//
// An empty requested set is the caller's responsibility to interpret as
// "no scope declared → see everything"; this function still returns only
// general servers for an empty request, so callers MUST NOT build a scope at
// all when the client omitted the `?tags=` parameter (see tagscope.Resolve).
func (c *Config) ServersMatchingTags(requested []string) []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.Servers))
	for _, s := range c.Servers {
		if s == nil {
			continue
		}
		if len(s.Tags) == 0 || tagsIntersect(s.Tags, requested) {
			out = append(out, s.Name)
		}
	}
	return out
}

// UntaggedServerNames returns the names of configured servers that carry no
// tags. Used at boot to warn loudly when require_server_tags is enabled but
// pre-existing servers were registered before tagging was mandatory.
func (c *Config) UntaggedServerNames() []string {
	if c == nil {
		return nil
	}
	var out []string
	for _, s := range c.Servers {
		if s != nil && len(s.Tags) == 0 {
			out = append(out, s.Name)
		}
	}
	return out
}

// ValidateServerTagRequirement enforces the require_server_tags policy at
// registration time. When the policy is on and the supplied tag set is empty
// (after normalization), it returns an error naming the server; otherwise nil.
// Callers on every add path share this so the rule can never be missed.
func ValidateServerTagRequirement(requireServerTags bool, serverName string, tags []string) error {
	if !requireServerTags {
		return nil
	}
	if len(NormalizeTags(tags)) == 0 {
		return fmt.Errorf("server %q must declare at least one tag: require_server_tags is enabled, so pass --tag <scope> (CLI) or a tags value (API) — a general/untagged server would be visible to every client session", serverName)
	}
	return nil
}

// TagWarnings returns the non-fatal upstream-tag diagnostics captured by the
// most recent Validate() call. The boot path logs these via its logger; an
// empty result means no warnings.
func (c *Config) TagWarnings() []string {
	return c.tagWarnings
}
