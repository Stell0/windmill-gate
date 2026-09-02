package agent

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	"github.com/nethserver/gate/internal/protocol"
)

func TestClientPreservesStreamsAndExitStatus(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	dial := func(context.Context) (io.ReadWriteCloser, error) { return client, nil }
	done := make(chan error, 1)
	go func() {
		decoder := protocol.NewDecoder(server)
		encoder := protocol.NewEncoder(server)
		var hello protocol.Request
		if err := decoder.Decode(&hello); err != nil {
			done <- err
			return
		}
		if err := encoder.Encode(protocol.Response{Type: "hello", Version: protocol.Version, SessionID: "as_1"}); err != nil {
			done <- err
			return
		}
		var request protocol.Request
		if err := decoder.Decode(&request); err != nil {
			done <- err
			return
		}
		if request.Command != "test command" {
			done <- &unexpectedCommand{request.Command}
			return
		}
		code := 23
		for _, response := range []protocol.Response{
			{Type: "stdout", Data: "out\\n"},
			{Type: "stderr", Data: "err\\n"},
			{Type: "exit", Code: &code},
		} {
			if err := encoder.Encode(response); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	var stdout, stderr bytes.Buffer
	exitCode, err := (Client{Dial: dial, AgentID: "codex-1", Stdout: &stdout, Stderr: &stderr}).Exec(context.Background(), "test command")
	if err != nil {
		t.Fatal(err)
	}
	if exitCode != 23 || stdout.String() != "out\\n" || stderr.String() != "err\\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type unexpectedCommand struct{ command string }

func (e *unexpectedCommand) Error() string { return "unexpected command: " + e.command }
