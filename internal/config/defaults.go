// Package config contains shared local defaults for Gate commands.
package config

import (
	"os"
	"os/user"
	"path/filepath"
)

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

func PolicyReviewPath() string {
	if value := os.Getenv("GATE_POLICY_REVIEW_CONFIG"); value != "" {
		return value
	}
	return filepath.Join(configHome(), "gate", "policy-review.yaml")
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
