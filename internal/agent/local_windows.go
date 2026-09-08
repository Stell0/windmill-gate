//go:build windows

package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func LocalTransport() string { return "named-pipe" }

func LocalDialer(path string) Dialer {
	return func(ctx context.Context) (io.ReadWriteCloser, error) {
		return winio.DialPipeContext(ctx, path)
	}
}

func ListenLocal(path string) (net.Listener, error) {
	if !strings.HasPrefix(strings.ToLower(path), `\\.\pipe\`) {
		return nil, fmt.Errorf("Gate named pipe must start with \\\\.\\pipe\\")
	}
	securityDescriptor, err := currentUserPipeSecurityDescriptor()
	if err != nil {
		return nil, fmt.Errorf("secure Gate named pipe: %w", err)
	}
	listener, err := winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: securityDescriptor,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	})
	if err != nil {
		return nil, fmt.Errorf("listen on Gate named pipe: %w", err)
	}
	return listener, nil
}

func currentUserPipeSecurityDescriptor() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	// Protected DACL: only this user, LocalSystem, and local Administrators.
	return fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;%s)", user.User.Sid.String()), nil
}
