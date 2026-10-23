//go:build windows

package tui

import (
	"context"

	"golang.org/x/sys/windows"
)

var messageBeep = windows.NewLazySystemDLL("user32.dll").NewProc("MessageBeep")

func playSystemBell(ctx context.Context) {
	if ctx.Err() != nil || messageBeep.Find() != nil {
		return
	}
	// MessageBeep queues the Windows Exclamation sound asynchronously, without
	// depending on the terminal's BEL setting or virtual-terminal output mode.
	messageBeep.Call(0x30)
}
