package agent

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/nethserver/gate/internal/protocol"
)

// Control sends one target-scoped capability request over the same transport
// and policy stream used for exec.
func (c Client) Control(ctx context.Context, request protocol.Request) (protocol.Response, error) {
	if c.Dial == nil {
		return protocol.Response{}, errors.New("Gate dialer is not configured")
	}
	if err := request.Validate(); err != nil {
		return protocol.Response{}, err
	}
	conn, err := c.Dial(ctx)
	if err != nil {
		return protocol.Response{}, fmt.Errorf("connect to Gate: %w", err)
	}
	defer conn.Close()
	encoder, decoder := protocol.NewEncoder(conn), protocol.NewDecoder(conn)
	if err := encoder.Encode(protocol.Request{Type: "hello", Version: protocol.Version, Agent: c.AgentID}); err != nil {
		return protocol.Response{}, err
	}
	var hello protocol.Response
	if err := decoder.Decode(&hello); err != nil {
		return protocol.Response{}, err
	}
	if hello.Type == "error" {
		return protocol.Response{}, errors.New(hello.Error)
	}
	if hello.Type != "hello" || hello.Version != protocol.Version {
		return protocol.Response{}, errors.New("invalid Gate hello response")
	}
	if err := encoder.Encode(request); err != nil {
		return protocol.Response{}, err
	}
	var resource protocol.Response
	stderr := c.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	for {
		var response protocol.Response
		if err := decoder.Decode(&response); err != nil {
			return protocol.Response{}, err
		}
		switch response.Type {
		case "accepted", "state":
		case "stderr":
			_, _ = io.WriteString(stderr, response.Data)
		case "forward", "forward_list", "forward_removed", "host", "host_list", "host_removed":
			resource = response
		case "error":
			return protocol.Response{}, errors.New(response.Error)
		case "exit":
			if response.Code == nil {
				return protocol.Response{}, errors.New("Gate exit response omitted status code")
			}
			if *response.Code != 0 {
				return protocol.Response{}, fmt.Errorf("Gate capability request exited with status %d", *response.Code)
			}
			if resource.Type == "" {
				return protocol.Response{}, errors.New("Gate capability response omitted resource")
			}
			return resource, nil
		default:
			return protocol.Response{}, fmt.Errorf("unexpected Gate response type %q", response.Type)
		}
	}
}
