//go:build windows

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsDefaultsUseNamedPipeAndNativeHostsFile(t *testing.T) {
	t.Setenv("GATE_SOCKET", "")
	if path := strings.ToLower(SocketPath()); !strings.HasPrefix(path, `\\.\pipe\windmill-gate-`) {
		t.Fatalf("SocketPath() = %q", path)
	}
	wantSuffix := strings.ToLower(filepath.Join("system32", "drivers", "etc", "hosts"))
	if path := strings.ToLower(HostsPath()); !strings.HasSuffix(path, wantSuffix) {
		t.Fatalf("HostsPath() = %q", path)
	}
}
