package config

import "testing"

func TestMergeServerConfigTags(t *testing.T) {
	base := &ServerConfig{Name: "s", Tags: []string{"halo"}, Enabled: true}

	t.Run("nil patch tags preserves existing", func(t *testing.T) {
		patch := &ServerConfig{Name: "s", Enabled: true}
		merged, _, err := MergeServerConfig(base, patch, DefaultMergeOptions())
		if err != nil {
			t.Fatal(err)
		}
		if len(merged.Tags) != 1 || merged.Tags[0] != "halo" {
			t.Fatalf("expected tags preserved, got %v", merged.Tags)
		}
	})

	t.Run("non-nil patch tags replaces", func(t *testing.T) {
		patch := &ServerConfig{Name: "s", Enabled: true, Tags: []string{"personal", "x"}}
		merged, _, err := MergeServerConfig(base, patch, DefaultMergeOptions())
		if err != nil {
			t.Fatal(err)
		}
		if len(merged.Tags) != 2 || merged.Tags[0] != "personal" || merged.Tags[1] != "x" {
			t.Fatalf("expected tags replaced, got %v", merged.Tags)
		}
	})

	t.Run("empty patch tags clears", func(t *testing.T) {
		patch := &ServerConfig{Name: "s", Enabled: true, Tags: []string{}}
		merged, _, err := MergeServerConfig(base, patch, DefaultMergeOptions())
		if err != nil {
			t.Fatal(err)
		}
		if len(merged.Tags) != 0 {
			t.Fatalf("expected tags cleared, got %v", merged.Tags)
		}
	})
}

// TestBackwardCompatUntaggedIdentical guards that a config with no tags anywhere
// keeps ServersMatchingTags returning every server for any request and that a
// nil requested scope is a no-op — i.e. the feature is invisible when unused.
func TestBackwardCompatUntaggedIdentical(t *testing.T) {
	cfg := &Config{Servers: []*ServerConfig{{Name: "a"}, {Name: "b"}, {Name: "c"}}}
	// Every server is "general", so any scope (even a specific one) still
	// yields all of them.
	for _, req := range [][]string{nil, {"halo"}, {"whatever", "else"}} {
		got := cfg.ServersMatchingTags(req)
		if len(got) != 3 {
			t.Fatalf("untagged config must expose all servers for req %v, got %v", req, got)
		}
	}
}
