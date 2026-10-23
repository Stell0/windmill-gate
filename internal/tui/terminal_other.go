//go:build !linux && !windows && !darwin

package tui

import "io"

func configureCharacterInput(io.Reader) (func(), bool, error) {
	return nil, false, nil
}

func writerIsTerminal(io.Writer) bool {
	return false
}

func writerSupportsBell(io.Writer) bool { return false }
