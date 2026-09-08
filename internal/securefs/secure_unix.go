//go:build !windows

package securefs

import "os"

func PrivateDir(path string) error  { return os.Chmod(path, 0o700) }
func PrivateFile(path string) error { return os.Chmod(path, 0o600) }
