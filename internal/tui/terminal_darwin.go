//go:build darwin

package tui

import (
	"io"

	"golang.org/x/sys/unix"
)

func configureCharacterInput(input io.Reader) (func(), bool, error) {
	descriptor, ok := input.(interface{ Fd() uintptr })
	if !ok {
		return nil, false, nil
	}
	fd := int(descriptor.Fd())
	original, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		if err == unix.ENOTTY {
			return nil, false, nil
		}
		return nil, false, err
	}
	characterMode := *original
	characterMode.Lflag &^= unix.ICANON | unix.ECHO | unix.ECHONL
	characterMode.Cc[unix.VMIN] = 1
	characterMode.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, &characterMode); err != nil {
		return nil, false, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, unix.TIOCSETA, original) }, true, nil
}

// Keep the existing line-oriented renderer on macOS; bells need only a TTY.
func writerIsTerminal(io.Writer) bool { return false }

func writerSupportsBell(output io.Writer) bool {
	descriptor, ok := output.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(descriptor.Fd()), unix.TIOCGETA)
	return err == nil
}
