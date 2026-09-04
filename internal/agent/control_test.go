package agent

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/stell0/windmill-gate/internal/protocol"
)

func TestControlReturnsTargetScopedForwardResource(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		decoder, encoder := protocol.NewDecoder(server), protocol.NewEncoder(server)
		var hello protocol.Request
		if err := decoder.Decode(&hello); err != nil {
			done <- err
			return
		}
		if err := encoder.Encode(protocol.Response{Type: "hello", Version: protocol.Version}); err != nil {
			done <- err
			return
		}
		var request protocol.Request
		if err := decoder.Decode(&request); err != nil {
			done <- err
			return
		}
		if request.Type != "forward_add" || request.RemotePort != 443 {
			done <- &unexpectedCommand{command: request.Type}
			return
		}
		if err := encoder.Encode(protocol.Response{
			Type: "forward", ResourceID: "fw_safe", TargetID: "gt_safe",
			LocalHost: "127.0.0.1", LocalPort: 18443, RemotePort: 443,
		}); err != nil {
			done <- err
			return
		}
		code := 0
		done <- encoder.Encode(protocol.Response{Type: "exit", Code: &code})
	}()
	gateClient := Client{
		Dial:    func(context.Context) (io.ReadWriteCloser, error) { return client, nil },
		AgentID: "codex-1",
	}
	response, err := gateClient.Control(context.Background(), protocol.Request{Type: "forward_add", RemotePort: 443})
	if err != nil {
		t.Fatal(err)
	}
	if response.ResourceID != "fw_safe" || response.TargetID != "gt_safe" || response.LocalPort != 18443 {
		t.Fatalf("unexpected forward response: %#v", response)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
