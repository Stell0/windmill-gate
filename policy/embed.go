// Package defaultpolicy embeds the initial human-managed policy template.
package defaultpolicy

import _ "embed"

// DefaultYAML is copied only when the configured policy file does not exist.
//
//go:embed default.yaml
var DefaultYAML []byte
