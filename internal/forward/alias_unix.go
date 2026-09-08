//go:build !windows

package forward

import (
	"fmt"
	"os"
	"path/filepath"
)

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".gate-hosts-")
	if err != nil {
		return fmt.Errorf("create temporary hosts file: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return fmt.Errorf("preserve hosts file mode: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write hosts file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync hosts file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close hosts file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace hosts file: %w", err)
	}
	return nil
}
