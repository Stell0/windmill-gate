//go:build windows

package tui

import (
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestConfigureCharacterInputConsole(t *testing.T) {
	input, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		// Test runners may redirect stdin and have no attached console.
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		if ok, _, err := kernel32.NewProc("AllocConsole").Call(); ok == 0 {
			t.Fatalf("allocate test console: %v", err)
		}
		t.Cleanup(func() { kernel32.NewProc("FreeConsole").Call() })
		input, err = os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { input.Close() })
	handle := windows.Handle(input.Fd())
	var original uint32
	if err := windows.GetConsoleMode(handle, &original); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := windows.SetConsoleMode(handle, original); err != nil {
			t.Errorf("restore test console: %v", err)
		}
	})

	for _, echo := range []bool{true, false} {
		name := "without echo"
		if echo {
			name = "with echo"
		}
		t.Run(name, func(t *testing.T) {
			mode := original | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
			if echo {
				mode |= windows.ENABLE_ECHO_INPUT
			} else {
				mode &^= windows.ENABLE_ECHO_INPUT
			}
			if err := windows.SetConsoleMode(handle, mode); err != nil {
				t.Fatal(err)
			}
			restore, singleKey, err := configureCharacterInput(input)
			if err != nil {
				t.Fatalf("configure character input: %v", err)
			}
			if restore == nil {
				t.Fatal("console did not return a restore function")
			}
			t.Cleanup(restore)
			if !singleKey {
				t.Fatal("console did not enable single-key input")
			}
			var configured uint32
			if err := windows.GetConsoleMode(handle, &configured); err != nil {
				t.Fatal(err)
			}
			if configured&(windows.ENABLE_LINE_INPUT|windows.ENABLE_ECHO_INPUT) != 0 {
				t.Fatalf("line buffering or echo still enabled: %#x", configured)
			}
			if configured|windows.ENABLE_LINE_INPUT|windows.ENABLE_ECHO_INPUT != mode|windows.ENABLE_LINE_INPUT|windows.ENABLE_ECHO_INPUT {
				t.Fatalf("unrelated console flags changed: %#x -> %#x", mode, configured)
			}
			restore()
			var restored uint32
			if err := windows.GetConsoleMode(handle, &restored); err != nil {
				t.Fatal(err)
			}
			if restored != mode {
				t.Fatalf("restored mode = %#x, want %#x", restored, mode)
			}
		})
	}
}

func TestConfigureCharacterInputNonConsole(t *testing.T) {
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer output.Close()
	for _, reader := range []io.Reader{input, strings.NewReader("y\n")} {
		restore, singleKey, err := configureCharacterInput(reader)
		if err != nil || restore != nil || singleKey {
			t.Fatalf("non-console %T: restore=%v, singleKey=%v, err=%v", reader, restore != nil, singleKey, err)
		}
	}
}
