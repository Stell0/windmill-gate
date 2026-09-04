package remote

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/stell0/windmill-gate/internal/protocol"
)

func TestBridgeReplacesClaimedIdentityWithFingerprintMapping(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	dial := func(context.Context) (io.ReadWriteCloser, error) { return client, nil }
	seen := make(chan protocol.Request, 1)
	go func() {
		decoder, encoder := protocol.NewDecoder(server), protocol.NewEncoder(server)
		var hello protocol.Request
		_ = decoder.Decode(&hello)
		seen <- hello
		_ = encoder.Encode(protocol.Response{Type: "hello", Version: protocol.Version})
		var request protocol.Request
		_ = decoder.Decode(&request)
		code := 0
		_ = encoder.Encode(protocol.Response{Type: "exit", Code: &code})
	}()
	input := strings.NewReader(
		`{"type":"hello","version":1,"agent":"attacker-claim"}` + "\n" +
			`{"type":"exec","command":"uptime"}` + "\n",
	)
	var output bytes.Buffer
	bridge := Bridge{
		Dial: dial, Fingerprint: "SHA256:key-one",
		Clients: ClientConfig{Clients: []Client{{Fingerprint: "SHA256:key-one", Identity: "codex-prod"}}},
	}
	if err := bridge.Run(context.Background(), input, &output); err != nil {
		t.Fatal(err)
	}
	hello := <-seen
	if hello.Agent != "codex-prod" || hello.Fingerprint != "SHA256:key-one" {
		t.Fatalf("untrusted identity reached daemon: %#v", hello)
	}
	if strings.Contains(output.String(), "SHA256:key-one") {
		t.Fatalf("fingerprint leaked in agent response: %s", output.String())
	}
}

func TestBridgeRejectsUnknownFingerprint(t *testing.T) {
	input := strings.NewReader(`{"type":"hello","version":1,"agent":"claim"}` + "\n")
	var output bytes.Buffer
	bridge := Bridge{Fingerprint: "SHA256:unknown", Clients: ClientConfig{}}
	if err := bridge.Run(context.Background(), input, &output); err == nil {
		t.Fatal("unknown key fingerprint was accepted")
	}
	if !strings.Contains(output.String(), `"type":"error"`) {
		t.Fatalf("agent did not receive protocol error: %s", output.String())
	}
}
