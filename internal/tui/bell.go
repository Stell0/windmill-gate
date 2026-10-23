package tui

import (
	"context"
	"os"
)

// startAudioBell serializes playback away from the approval loop. A burst of
// requests coalesces rather than starting overlapping players or blocking input.
// BEL still reaches SSH clients; native sound belongs only on a local desktop.
func startAudioBell(ctx context.Context, play func(context.Context)) func() {
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return func() {}
	}
	requests := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-requests:
				if ctx.Err() != nil {
					return
				}
				play(ctx)
			}
		}
	}()
	return func() {
		select {
		case requests <- struct{}{}:
		default:
		}
	}
}
