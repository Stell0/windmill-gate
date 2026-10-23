package tui

import (
	"context"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRedirectedOutputDoesNotSupportBells(t *testing.T) {
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer output.Close()
	for _, writer := range []io.Writer{output, &strings.Builder{}} {
		if writerSupportsBell(writer) {
			t.Fatalf("redirected output %T supports bells", writer)
		}
	}
}

func TestAudioBellDoesNotBlockApprovalsAndStopsOnExit(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, stopped := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	ring := startAudioBell(ctx, func(ctx context.Context) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		close(stopped)
	})
	ring()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("audio did not start")
	}
	done := make(chan struct{})
	go func() {
		for range 1000 {
			ring()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sound playback blocked approval notifications")
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("audio did not stop with the console")
	}
	if calls.Load() != 1 {
		t.Fatal("sound players overlapped")
	}
}

func TestSSHConsoleDoesNotPlaySoundOnServer(t *testing.T) {
	for _, key := range []string{"SSH_CONNECTION", "SSH_TTY"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv("SSH_CONNECTION", "")
			t.Setenv("SSH_TTY", "")
			t.Setenv(key, "ssh")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			played := make(chan struct{}, 1)
			startAudioBell(ctx, func(context.Context) { played <- struct{}{} })()
			select {
			case <-played:
				t.Fatal("SSH console played audio on the server")
			case <-time.After(25 * time.Millisecond):
			}
		})
	}
}
