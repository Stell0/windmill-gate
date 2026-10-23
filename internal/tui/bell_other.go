//go:build !linux && !darwin && !windows

package tui

import "context"

func playSystemBell(context.Context) {}
