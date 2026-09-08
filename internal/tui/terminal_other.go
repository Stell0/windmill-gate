//go:build !linux && !windows

package tui

import "io"

func configureCharacterInput(io.Reader) (func(), bool, error) {
	return nil, false, nil
}

func writerIsTerminal(io.Writer) bool {
	return false
}
