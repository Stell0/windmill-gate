//go:build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

func SocketPath() string {
	if value := os.Getenv("GATE_SOCKET"); value != "" {
		return value
	}
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = filepath.Join(os.TempDir(), fmt.Sprintf("gate-%d", os.Getuid()))
	}
	return filepath.Join(runtimeDir, "gate.sock")
}

func HostsPath() string { return "/etc/hosts" }

func dataHome() string {
	if value := os.Getenv("XDG_DATA_HOME"); value != "" {
		return value
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".local", "share")
}

func configHome() string {
	if value := os.Getenv("XDG_CONFIG_HOME"); value != "" {
		return value
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".config")
}
