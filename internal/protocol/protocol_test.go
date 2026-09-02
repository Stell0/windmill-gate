package protocol

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestNDJSONRoundTripAndStreamFraming(t *testing.T) {
	var wire bytes.Buffer
	encoder := NewEncoder(&wire)
	code := 17
	responses := []Response{
		{Type: "stdout", Data: "one\\ntwo\\n"},
		{Type: "stderr", Data: "warning\\n"},
		{Type: "exit", Code: &code},
	}
	for _, response := range responses {
		if err := encoder.Encode(response); err != nil {
			t.Fatal(err)
		}
	}
	decoder := NewDecoder(&wire)
	for index, want := range responses {
		var got Response
		if err := decoder.Decode(&got); err != nil {
			t.Fatalf("decode frame %d: %v", index, err)
		}
		if got.Type != want.Type || got.Data != want.Data {
			t.Fatalf("frame %d mismatch: %#v", index, got)
		}
	}
	var end Response
	if err := decoder.Decode(&end); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestMalformedAndOversizedFramesAreRejected(t *testing.T) {
	var req Request
	if err := NewDecoder(strings.NewReader("{not json}\\n")).Decode(&req); err == nil {
		t.Fatal("malformed frame accepted")
	}
	oversized := strings.Repeat("x", MaxFrameSize+1) + "\\n"
	if err := NewDecoder(strings.NewReader(oversized)).Decode(&req); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestFrameBetweenReaderBufferAndLimitIsAccepted(t *testing.T) {
	command := strings.Repeat("x", 128*1024)
	var wire bytes.Buffer
	if err := NewEncoder(&wire).Encode(Request{Type: "exec", Command: command}); err != nil {
		t.Fatal(err)
	}
	var request Request
	if err := NewDecoder(&wire).Decode(&request); err != nil {
		t.Fatal(err)
	}
	if request.Command != command {
		t.Fatalf("large valid command changed: got %d bytes, want %d", len(request.Command), len(command))
	}
}

func TestExecRequestHasNoTargetOrBackendField(t *testing.T) {
	var req Request
	err := NewDecoder(strings.NewReader(`{"type":"exec","command":"uptime","target_id":"gt_other","backend_id":"secret"}` + "\n")).Decode(&req)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded := []byte{}
	var wire bytes.Buffer
	if err := NewEncoder(&wire).Encode(req); err != nil {
		t.Fatal(err)
	}
	encoded = wire.Bytes()
	if bytes.Contains(encoded, []byte("target")) || bytes.Contains(encoded, []byte("backend")) {
		t.Fatalf("unsafe fields survived protocol decoding: %s", encoded)
	}
}
