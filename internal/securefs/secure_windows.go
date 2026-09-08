//go:build windows

package securefs

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func PrivateDir(path string) error  { return applyPrivateDACL(path, true) }
func PrivateFile(path string) error { return applyPrivateDACL(path, false) }

func applyPrivateDACL(path string, inherit bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	inheritance := ""
	if inherit {
		inheritance = "OICI"
	}
	sddl := fmt.Sprintf("D:P(A;%s;GA;;;SY)(A;%s;GA;;;BA)(A;%s;GA;;;%s)",
		inheritance, inheritance, inheritance, user.User.Sid.String())
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
