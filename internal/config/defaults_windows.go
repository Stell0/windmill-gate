//go:build windows

package config

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

func SocketPath() string {
	if value := os.Getenv("GATE_SOCKET"); value != "" {
		return value
	}
	identity := os.Getenv("USERNAME")
	if current, err := user.Current(); err == nil && current.Uid != "" {
		identity = current.Uid
	}
	digest := sha256.Sum256([]byte(identity))
	return fmt.Sprintf(`\\.\pipe\windmill-gate-%x`, digest[:6])
}

func HostsPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "drivers", "etc", "hosts")
}

func dataHome() string {
	if value := os.Getenv("XDG_DATA_HOME"); value != "" {
		return value
	}
	if value := os.Getenv("LOCALAPPDATA"); value != "" {
		return value
	}
	return windowsConfigHome()
}

func configHome() string {
	if value := os.Getenv("XDG_CONFIG_HOME"); value != "" {
		return value
	}
	if value := os.Getenv("APPDATA"); value != "" {
		return value
	}
	return windowsConfigHome()
}

func windowsConfigHome() string {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "."
	}
	return directory
}
