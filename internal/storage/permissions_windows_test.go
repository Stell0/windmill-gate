//go:build windows

package storage

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func assertPrivateDatabase(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 || strings.Contains(descriptor.String(), "S-1-1-0") {
		t.Fatalf("database does not have a private DACL: %s", descriptor.String())
	}
}
