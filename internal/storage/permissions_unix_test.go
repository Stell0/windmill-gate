//go:build !windows

package storage

import (
	"os"
	"testing"
)

func assertPrivateDatabase(t *testing.T, path string) {
	t.Helper()
	mode, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode.Mode().Perm() != 0o600 {
		t.Fatalf("database permissions = %o, want 600", mode.Mode().Perm())
	}
}
