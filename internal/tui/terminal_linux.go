//go:build linux

package tui

import (
	"io"

	"golang.org/x/sys/unix"
)

type fileDescriptor interface {
	Fd() uintptr
}

func configureCharacterInput(input io.Reader) (func(), bool, error) {
	descriptor, ok := input.(fileDescriptor)
	if !ok {
		return nil, false, nil
	}
	fd := int(descriptor.Fd())
	original, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		if err == unix.ENOTTY {
			return nil, false, nil
		}
		return nil, false, err
	}
	characterMode := *original
	characterMode.Lflag &^= unix.ICANON
	characterMode.Cc[unix.VMIN] = 1
	characterMode.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &characterMode); err != nil {
		return nil, false, err
	}
	return func() {
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, original)
	}, true, nil
}

func writerIsTerminal(output io.Writer) bool {
	descriptor, ok := output.(fileDescriptor)
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(descriptor.Fd()), unix.TCGETS)
	return err == nil
}
