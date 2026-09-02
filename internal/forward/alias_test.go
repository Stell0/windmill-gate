package forward

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAliasOwnsOnlyItsResolverLineAndReportsURL(t *testing.T) {
	ctx := context.Background()
	store := forwardStore(t)
	defer store.Close()
	implementation := &forwardBackend{}
	forwards, _ := NewManager(ctx, testResolver{implementation}, store)
	forwards.allocate = func() (uint16, error) { return 18443, nil }
	forward, err := forwards.Add(ctx, "gt_one", 443, "operator")
	if err != nil {
		t.Fatal(err)
	}
	hosts := filepath.Join(t.TempDir(), "hosts")
	original := "127.0.0.1 localhost\n10.0.0.2 unrelated.example\n"
	if err := os.WriteFile(hosts, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	aliases, err := NewAliasManager(ctx, hosts, store, forwards)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := aliases.Add(ctx, "gt_one", forward.ID, "Foo.Example.com.", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if alias.URL != "https://foo.example.com:18443/" || alias.Address != Loopback {
		t.Fatalf("unexpected alias: %#v", alias)
	}
	withAlias, _ := os.ReadFile(hosts)
	if !strings.Contains(string(withAlias), original) || !strings.Contains(string(withAlias), "127.0.0.1\tfoo.example.com # gate:") {
		t.Fatalf("hosts content was clobbered: %s", withAlias)
	}
	if err := aliases.Remove(ctx, "gt_one", "foo.example.com", "operator"); err != nil {
		t.Fatal(err)
	}
	cleaned, _ := os.ReadFile(hosts)
	if string(cleaned) != original {
		t.Fatalf("Gate did not remove exactly its line:\n%s", cleaned)
	}
}

func TestAliasRefusesExistingOrInvalidHostnames(t *testing.T) {
	ctx := context.Background()
	store := forwardStore(t)
	defer store.Close()
	implementation := &forwardBackend{}
	forwards, _ := NewManager(ctx, testResolver{implementation}, store)
	forwards.allocate = func() (uint16, error) { return 18080, nil }
	forward, _ := forwards.Add(ctx, "gt_one", 80, "operator")
	hosts := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hosts, []byte("10.0.0.2 existing.example.com # unrelated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	aliases, _ := NewAliasManager(ctx, hosts, store, forwards)
	for _, hostname := range []string{"existing.example.com", "localhost", "127.0.0.1", "not_fqdn"} {
		if _, err := aliases.Add(ctx, "gt_one", forward.ID, hostname, "operator"); err == nil {
			t.Errorf("unsafe hostname %q accepted", hostname)
		}
	}
	data, _ := os.ReadFile(hosts)
	if string(data) != "10.0.0.2 existing.example.com # unrelated\n" {
		t.Fatalf("unrelated hosts content changed: %s", data)
	}
}

func TestAliasCleanupOnTargetClose(t *testing.T) {
	ctx := context.Background()
	store := forwardStore(t)
	defer store.Close()
	implementation := &forwardBackend{}
	forwards, _ := NewManager(ctx, testResolver{implementation}, store)
	forwards.allocate = func() (uint16, error) { return 18443, nil }
	forward, _ := forwards.Add(ctx, "gt_one", 443, "operator")
	hosts := filepath.Join(t.TempDir(), "hosts")
	_ = os.WriteFile(hosts, []byte("127.0.0.1 localhost\n"), 0o644)
	aliases, _ := NewAliasManager(ctx, hosts, store, forwards)
	_, _ = aliases.Add(ctx, "gt_one", forward.ID, "foo.example.com", "operator")
	if err := aliases.CloseTarget(ctx, "gt_one", "operator"); err != nil {
		t.Fatal(err)
	}
	if len(aliases.List("gt_one")) != 0 {
		t.Fatal("alias survived target cleanup")
	}
	data, _ := os.ReadFile(hosts)
	if strings.Contains(string(data), "foo.example.com") {
		t.Fatalf("resolver alias survived cleanup: %s", data)
	}
}
