//go:build windows

package securefs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPrivateFileUsesProtectedCurrentUserDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrivateFile(path); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("private file DACL inherits permissions: %s", descriptor.String())
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(descriptor.String(), user.User.Sid.String()) {
		t.Fatalf("private file DACL does not contain current user: %s", descriptor.String())
	}
	if strings.Contains(descriptor.String(), "S-1-1-0") {
		t.Fatalf("private file DACL grants access to Everyone: %s", descriptor.String())
	}
}
