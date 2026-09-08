//go:build windows

package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLocalNamedPipeIsCurrentUserScopedAndConnectable(t *testing.T) {
	securityDescriptor, err := currentUserPipeSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(securityDescriptor, "D:P") || !strings.Contains(securityDescriptor, ";;;SY)") || !strings.Contains(securityDescriptor, ";;;BA)") {
		t.Fatalf("named-pipe security descriptor is not protected: %q", securityDescriptor)
	}

	path := fmt.Sprintf(`\\.\pipe\windmill-gate-test-%d`, time.Now().UnixNano())
	listener, err := ListenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			err = connection.Close()
		}
		accepted <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := LocalDialer(path)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("named-pipe listener did not accept the local connection")
	}
}
