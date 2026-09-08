//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalListenerPermissionsAndSafeStaleHandling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gate.sock")
	if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenLocal(path); err == nil {
		t.Fatal("non-socket path was replaced")
	}
	if data, _ := os.ReadFile(path); string(data) != "do not replace" {
		t.Fatal("non-socket path was modified")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	listener, err := ListenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o", info.Mode().Perm())
	}
}
