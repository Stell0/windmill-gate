// Package protocol implements Gate's bounded newline-delimited JSON protocol.
package protocol

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	Version      = 1
	MaxFrameSize = 1024 * 1024
)

type Request struct {
	Type       string `json:"type"`
	Version    int    `json:"version,omitempty"`
	Agent      string `json:"agent,omitempty"`
	Command    string `json:"command,omitempty"`
	CommandID  string `json:"command_id,omitempty"`
	RemotePort uint16 `json:"remote_port,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
}

func (r Request) Validate() error {
	switch r.Type {
	case "hello":
		if r.Version != Version {
			return fmt.Errorf("unsupported protocol version %d", r.Version)
		}
		if r.Agent == "" {
			return errors.New("agent identity is required")
		}
	case "exec":
		if r.Command == "" {
			return errors.New("command is required")
		}
	case "cancel":
		if r.CommandID == "" {
			return errors.New("command ID is required")
		}
	case "forward_add":
		if r.RemotePort == 0 {
			return errors.New("remote port is required")
		}
	case "forward_list":
	case "forward_remove":
		if r.CommandID == "" {
			return errors.New("forward ID is required")
		}
	case "host_add":
		if r.Hostname == "" || r.RemotePort == 0 {
			return errors.New("hostname and remote port are required")
		}
	case "host_list":
	case "host_remove":
		if r.Hostname == "" {
			return errors.New("hostname is required")
		}
	default:
		return fmt.Errorf("unknown request type %q", r.Type)
	}
	return nil
}

type Response struct {
	Type      string          `json:"type"`
	Version   int             `json:"version,omitempty"`
	CommandID string          `json:"command_id,omitempty"`
	Hash      string          `json:"hash,omitempty"`
	Policy    string          `json:"policy,omitempty"`
	State     string          `json:"state,omitempty"`
	Data      string          `json:"data,omitempty"`
	Code      *int            `json:"code,omitempty"`
	Error     string          `json:"error,omitempty"`
	Items     json.RawMessage `json:"items,omitempty"`
}

type Decoder struct {
	reader *bufio.Reader
}

func NewDecoder(reader io.Reader) *Decoder {
	return &Decoder{reader: bufio.NewReaderSize(reader, 64*1024)}
}

func (d *Decoder) Decode(value any) error {
	frame, err := d.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(frame) > MaxFrameSize {
		return errors.New("protocol frame exceeds 1 MiB")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(frame) == 0 && errors.Is(err, io.EOF) {
		return io.EOF
	}
	if frame[len(frame)-1] == '\n' {
		frame = frame[:len(frame)-1]
	}
	if !json.Valid(frame) {
		return errors.New("malformed JSON frame")
	}
	if err := json.Unmarshal(frame, value); err != nil {
		return fmt.Errorf("decode protocol frame: %w", err)
	}
	return nil
}

type Encoder struct {
	writer *bufio.Writer
}

func NewEncoder(writer io.Writer) *Encoder {
	return &Encoder{writer: bufio.NewWriter(writer)}
}

func (e *Encoder) Encode(value any) error {
	frame, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode protocol frame: %w", err)
	}
	if len(frame)+1 > MaxFrameSize {
		return errors.New("protocol frame exceeds 1 MiB")
	}
	if _, err := e.writer.Write(append(frame, '\n')); err != nil {
		return err
	}
	return e.writer.Flush()
}
