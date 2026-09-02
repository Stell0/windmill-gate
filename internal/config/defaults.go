// Package config contains shared local defaults for Gate commands.
package config

import (
	"fmt"
	"os"
	"os/user"
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

func DatabasePath() string {
	if value := os.Getenv("GATE_DATABASE"); value != "" {
		return value
	}
	return filepath.Join(dataHome(), "gate", "gate.db")
}

func PolicyPath() string {
	if value := os.Getenv("GATE_POLICY"); value != "" {
		return value
	}
	return filepath.Join(configHome(), "gate", "policy.yaml")
}

func SSHClientsPath() string {
	if value := os.Getenv("GATE_SSH_CLIENTS"); value != "" {
		return value
	}
	return filepath.Join(configHome(), "gate", "ssh-clients.yaml")
}

func AgentIdentity() string {
	if value := os.Getenv("GATE_AGENT_ID"); value != "" {
		return value
	}
	if current, err := user.Current(); err == nil && current.Username != "" {
		return current.Username
	}
	return "local-agent"
}

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
