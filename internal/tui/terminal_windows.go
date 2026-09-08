//go:build windows

package tui

import (
	"io"

	"golang.org/x/sys/windows"
)

type windowsFileDescriptor interface {
	Fd() uintptr
}

func configureCharacterInput(input io.Reader) (func(), bool, error) {
	descriptor, ok := input.(windowsFileDescriptor)
	if !ok {
		return nil, false, nil
	}
	handle := windows.Handle(descriptor.Fd())
	var original uint32
	if err := windows.GetConsoleMode(handle, &original); err != nil {
		return nil, false, nil
	}
	characterMode := original &^ windows.ENABLE_LINE_INPUT
	if err := windows.SetConsoleMode(handle, characterMode); err != nil {
		return nil, false, err
	}
	return func() { _ = windows.SetConsoleMode(handle, original) }, true, nil
}

func writerIsTerminal(output io.Writer) bool {
	descriptor, ok := output.(windowsFileDescriptor)
	if !ok {
		return false
	}
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(descriptor.Fd()), &mode) == nil && mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
}
