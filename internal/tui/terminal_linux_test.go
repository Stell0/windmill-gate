//go:build linux

package tui

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stell0/windmill-gate/internal/approval"
	gatecore "github.com/stell0/windmill-gate/internal/gate"
	"github.com/stell0/windmill-gate/internal/policy"
	"github.com/stell0/windmill-gate/internal/storage"
	"golang.org/x/sys/unix"
)

func TestOperatorTerminalHandlesControlKeysAndRestoresMode(t *testing.T) {
	// Avoid playing desktop sounds in a test with real terminal descriptors.
	t.Setenv("SSH_CONNECTION", "test")
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("PTY unavailable: %v", err)
	}
	defer master.Close()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	original, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}

	store, err := storage.Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine, _ := policy.New(policy.Config{})
	service, err := gatecore.NewService(store, engine, approval.NewBroker(), tuiBackend{})
	if err != nil {
		t.Fatal(err)
	}
	output := &lockedBuffer{}
	go func() { _, _ = io.Copy(output, master) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- (&App{Service: service, Input: terminal, Output: terminal}).Run(ctx)
	}()
	waitForOutput(t, output, func(value string) bool { return strings.Contains(value, "gate> ") })
	configured, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if configured.Lflag&(unix.ICANON|unix.ECHO|unix.ECHONL) != 0 {
		t.Fatalf("kernel editing or echo still enabled: %#x", configured.Lflag)
	}
	if _, err := io.WriteString(master, "\x7f\x7f\x1b[C\x1b[Dhistx\x7fory\n"); err != nil {
		t.Fatal(err)
	}
	waitForOutput(t, output, func(value string) bool { return strings.Contains(value, "HISTORY") })
	if got := output.String(); strings.Contains(got, "unknown operator command") || strings.Contains(got, "^?") || strings.Contains(got, "^[[") {
		t.Fatalf("control keys corrupted the operator terminal: %q", got)
	}
	if _, err := io.WriteString(master, "quit\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("operator console did not quit")
	}
	restored, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored, original) {
		t.Fatalf("terminal settings not restored: got %+v, want %+v", restored, original)
	}
}
