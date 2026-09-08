//go:build windows

package forward

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func atomicWrite(path string, data []byte, _ os.FileMode) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read hosts file permissions: %w", err)
	}
	if descriptor == nil {
		return fmt.Errorf("read hosts file permissions: empty security descriptor")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read hosts file access list: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("read hosts file access list: empty DACL")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".gate-hosts-")
	if err != nil {
		return fmt.Errorf("create temporary hosts file: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
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
	if err := windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("preserve hosts file access list: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace hosts file: %w", err)
	}
	return nil
}
