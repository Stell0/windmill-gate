//go:build linux || darwin

package tui

import (
	"context"
	"os/exec"
	"runtime"
	"time"
)

func playSystemBell(ctx context.Context) {
	playBellCommands(ctx, systemBellCommands(runtime.GOOS))
}

func systemBellCommands(goos string) [][]string {
	if goos == "darwin" {
		return [][]string{{"/usr/bin/afplay", "/System/Library/Sounds/Ping.aiff"}}
	}
	return [][]string{
		{"canberra-gtk-play", "--id", "bell", "--description", "Gate approval required"},
		{"paplay", "/usr/share/sounds/freedesktop/stereo/bell.oga"},
	}
}

func playBellCommands(ctx context.Context, commands [][]string) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for _, argv := range commands {
		if ctx.Err() != nil {
			return
		}
		// Fixed local argv only: no shell, command payload, target data, or
		// inherited console streams. Missing players leave BEL as the fallback.
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		if cmd.Run() == nil {
			return
		}
	}
}
