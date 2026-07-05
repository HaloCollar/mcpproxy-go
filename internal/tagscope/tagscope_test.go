package tagscope

import (
	"context"
	"sort"
	"testing"
)

func TestParseTagsParam(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{""}, nil},
		{"comma-separated", []string{"a,b,c"}, []string{"a", "b", "c"}},
		{"repeated params", []string{"a", "b"}, []string{"a", "b"}},
		{"mixed with spaces", []string{" a , b ", "c"}, []string{"a", "b", "c"}},
		{"case-insensitive dedupe", []string{"Halo,halo,HALO"}, []string{"Halo"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseTagsParam(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("ParseTagsParam(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ParseTagsParam(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

func TestTagScopeAllows(t *testing.T) {
	// nil scope = no scope declared = allow everything (backward compatible).
	var nilScope *TagScope
	if !nilScope.Allows("anything") {
		t.Fatal("nil TagScope must allow all servers")
	}

	scope := NewTagScope([]string{"halo"}, []string{"general", "halo-only"})
	if !scope.Allows("general") {
		t.Fatal("scope must allow resolved server 'general'")
	}
	if !scope.Allows("halo-only") {
		t.Fatal("scope must allow resolved server 'halo-only'")
	}
	if scope.Allows("personal") {
		t.Fatal("scope must NOT allow out-of-scope server 'personal'")
	}
	if scope.Allows("") {
		t.Fatal("empty server name is never allowed for a real scope")
	}
}

func TestTagScopeAllowedServerNames(t *testing.T) {
	var nilScope *TagScope
	if nilScope.AllowedServerNames() != nil {
		t.Fatal("nil scope must return nil allowed names (allow-all)")
	}
	scope := NewTagScope([]string{"halo"}, []string{"a", "b"})
	got := scope.AllowedServerNames()
	sort.Strings(got)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("AllowedServerNames() = %v, want [a b]", got)
	}
}

func TestTagScopeContextRoundTrip(t *testing.T) {
	ctx := context.Background()
	if TagScopeFromContext(ctx) != nil {
		t.Fatal("fresh context must carry no tag scope")
	}
	scope := NewTagScope([]string{"halo"}, []string{"a"})
	ctx = WithTagScope(ctx, scope)
	got := TagScopeFromContext(ctx)
	if got == nil || !got.Allows("a") {
		t.Fatal("context must carry the injected tag scope")
	}
	if got.TagsString() != "halo" {
		t.Fatalf("TagsString() = %q, want %q", got.TagsString(), "halo")
	}
}
