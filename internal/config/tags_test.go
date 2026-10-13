package config

import (
	"strings"
	"testing"
)

func TestNormalizeTags(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty slice", []string{}, nil},
		{"only blanks", []string{"", "  ", "\t"}, nil},
		{"trim", []string{" halo ", "personal"}, []string{"halo", "personal"}},
		{"drop empties", []string{"halo", "", "  ", "x"}, []string{"halo", "x"}},
		{"case-insensitive dedupe preserves first casing", []string{"Halo", "halo", "HALO"}, []string{"Halo"}},
		{"order preserved", []string{"b", "a", "c"}, []string{"b", "a", "c"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeTags(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("NormalizeTags(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("NormalizeTags(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

func TestServersMatchingTags(t *testing.T) {
	cfg := &Config{Servers: []*ServerConfig{
		{Name: "general"}, // untagged → visible to all
		{Name: "halo-only", Tags: []string{"halo"}},
		{Name: "personal", Tags: []string{"personal"}},
		{Name: "shared", Tags: []string{"halo", "serbocoin"}},
	}}

	tests := []struct {
		name      string
		requested []string
		want      []string
	}{
		{"halo scope", []string{"halo"}, []string{"general", "halo-only", "shared"}},
		{"personal scope", []string{"personal"}, []string{"general", "personal"}},
		{"case-insensitive match", []string{"HALO"}, []string{"general", "halo-only", "shared"}},
		{"multi scope", []string{"personal", "serbocoin"}, []string{"general", "personal", "shared"}},
		{"unknown tag sees only general", []string{"nope"}, []string{"general"}},
		{"empty request sees only general", nil, []string{"general"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cfg.ServersMatchingTags(tc.requested)
			gotSet := map[string]bool{}
			for _, g := range got {
				gotSet[g] = true
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ServersMatchingTags(%v) = %v, want %v", tc.requested, got, tc.want)
			}
			for _, w := range tc.want {
				if !gotSet[w] {
					t.Fatalf("ServersMatchingTags(%v) = %v, missing %q", tc.requested, got, w)
				}
			}
		})
	}
}

func TestValidateServerTagRequirement(t *testing.T) {
	// Policy off: any tag set is fine (backward compatible).
	if err := ValidateServerTagRequirement(false, "s", nil); err != nil {
		t.Fatalf("policy off with no tags should pass, got %v", err)
	}
	// Policy on + no tags: rejected.
	if err := ValidateServerTagRequirement(true, "s", nil); err == nil {
		t.Fatal("policy on with no tags should be rejected")
	}
	// Policy on + only-blank tags: rejected (normalization drops them).
	if err := ValidateServerTagRequirement(true, "s", []string{"  ", ""}); err == nil {
		t.Fatal("policy on with blank tags should be rejected")
	}
	// Policy on + a real tag: accepted.
	if err := ValidateServerTagRequirement(true, "s", []string{"halo"}); err != nil {
		t.Fatalf("policy on with a tag should pass, got %v", err)
	}
}

func TestUntaggedServerNames(t *testing.T) {
	cfg := &Config{Servers: []*ServerConfig{
		{Name: "a"},
		{Name: "b", Tags: []string{"x"}},
		{Name: "c"},
	}}
	got := cfg.UntaggedServerNames()
	if len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("UntaggedServerNames() = %v, want [a c]", got)
	}
}

func TestValidateSurfacesTagWarnings(t *testing.T) {
	cfg := &Config{
		RequireServerTags: true,
		Servers: []*ServerConfig{
			{Name: "tagged", Tags: []string{"halo"}, Enabled: true, Protocol: "stdio", Command: "x"},
			{Name: "untagged", Enabled: true, Protocol: "stdio", Command: "y"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() must not fail on untagged servers, got %v", err)
	}
	warnings := cfg.TagWarnings()
	if len(warnings) == 0 || !strings.Contains(warnings[0], "untagged") {
		t.Fatalf("expected a tag warning naming the untagged server, got %v", warnings)
	}
}

func TestValidateNoTagWarningsWhenPolicyOff(t *testing.T) {
	cfg := &Config{
		Servers: []*ServerConfig{{Name: "untagged", Enabled: true, Protocol: "stdio", Command: "y"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	if w := cfg.TagWarnings(); len(w) != 0 {
		t.Fatalf("expected no tag warnings with policy off, got %v", w)
	}
}
