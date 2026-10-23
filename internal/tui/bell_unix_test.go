//go:build linux || darwin

package tui

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Run the test binary as a disposable audio player; tests never need speakers
// or launch actual desktop audio tools.
func TestBellPlayerProcess(t *testing.T) {
	if os.Getenv("GATE_TEST_BELL_PLAYER") != "1" {
		return
	}
	mode, path := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(2)
	}
	_, _ = file.WriteString(mode + "\n")
	_ = file.Close()
	if mode == "wait" {
		time.Sleep(time.Minute)
	}
	if mode == "fail" {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestBellPlayersFallBackAndStopAfterSuccess(t *testing.T) {
	t.Setenv("GATE_TEST_BELL_PLAYER", "1")
	path := filepath.Join(t.TempDir(), "calls")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := func(mode string) []string {
		return []string{executable, "-test.run=^TestBellPlayerProcess$", "--", mode, path}
	}
	playBellCommands(context.Background(), [][]string{
		{filepath.Join(t.TempDir(), "missing-player")},
		helper("fail"), helper("success"), helper("unexpected"),
	})
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "fail\nsuccess\n" {
		t.Fatalf("player attempts=%q err=%v", got, err)
	}
}

func TestBellPlayerCancelled(t *testing.T) {
	t.Setenv("GATE_TEST_BELL_PLAYER", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "calls")
	done := make(chan struct{})
	go func() {
		playBellCommands(ctx, [][]string{{executable, "-test.run=^TestBellPlayerProcess$", "--", "wait", path}})
		close(done)
	}()
	select {
	case <-done:
		if ctx.Err() == nil {
			t.Fatal("player exited before cancellation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("audio player ignored cancellation")
	}
}
