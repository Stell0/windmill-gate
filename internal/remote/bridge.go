// Package remote implements the restricted SSH forced-command bridge.
package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/stell0/windmill-gate/internal/agent"
	"github.com/stell0/windmill-gate/internal/protocol"
	"github.com/stell0/windmill-gate/internal/securefs"
	"gopkg.in/yaml.v3"
)

type Client struct {
	Fingerprint string `yaml:"fingerprint"`
	Identity    string `yaml:"identity"`
}

type ClientConfig struct {
	Clients []Client `yaml:"clients"`
}

func LoadClients(path string) (ClientConfig, error) {
	if err := securefs.PrivateFile(path); err != nil {
		return ClientConfig{}, fmt.Errorf("secure SSH clients file: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ClientConfig{}, fmt.Errorf("read SSH clients: %w", err)
	}
	var config ClientConfig
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return ClientConfig{}, fmt.Errorf("parse SSH clients: %w", err)
	}
	seen := make(map[string]bool)
	for index, client := range config.Clients {
		if client.Fingerprint == "" || client.Identity == "" {
			return ClientConfig{}, fmt.Errorf("SSH client %d requires fingerprint and identity", index+1)
		}
		if seen[client.Fingerprint] {
			return ClientConfig{}, fmt.Errorf("duplicate SSH fingerprint at client %d", index+1)
		}
		seen[client.Fingerprint] = true
	}
	return config, nil
}

func (c ClientConfig) Identity(fingerprint string) (string, error) {
	for _, client := range c.Clients {
		if client.Fingerprint == fingerprint {
			return client.Identity, nil
		}
	}
	return "", errors.New("SSH key fingerprint is not authorized for Gate")
}

type Bridge struct {
	Dial        agent.Dialer
	Clients     ClientConfig
	Fingerprint string
}

// Run handles exactly one request so a forced command can never become a
// general shell or a multiplexed management channel.
func (b Bridge) Run(ctx context.Context, input io.Reader, output io.Writer) error {
	remoteDecoder := protocol.NewDecoder(input)
	remoteEncoder := protocol.NewEncoder(output)
	fail := func(err error) error {
		_ = remoteEncoder.Encode(protocol.Response{Type: "error", Error: err.Error()})
		return err
	}
	var claimedHello protocol.Request
	if err := remoteDecoder.Decode(&claimedHello); err != nil {
		return fail(err)
	}
	if err := claimedHello.Validate(); err != nil || claimedHello.Type != "hello" {
		if err == nil {
			err = errors.New("first request must be hello")
		}
		return fail(err)
	}
	identity, err := b.Clients.Identity(b.Fingerprint)
	if err != nil {
		return fail(err)
	}
	if b.Dial == nil {
		return fail(errors.New("Gate daemon dialer is not configured"))
	}
	conn, err := b.Dial(ctx)
	if err != nil {
		return fail(fmt.Errorf("connect to Gate daemon: %w", err))
	}
	defer conn.Close()
	localEncoder := protocol.NewEncoder(conn)
	localDecoder := protocol.NewDecoder(conn)
	if err := localEncoder.Encode(protocol.Request{
		Type: "hello", Version: protocol.Version, Agent: identity, Fingerprint: b.Fingerprint,
	}); err != nil {
		return fail(err)
	}
	var helloResponse protocol.Response
	if err := localDecoder.Decode(&helloResponse); err != nil {
		return fail(err)
	}
	if err := remoteEncoder.Encode(helloResponse); err != nil {
		return err
	}
	if helloResponse.Type == "error" {
		return errors.New(helloResponse.Error)
	}

	var request protocol.Request
	if err := remoteDecoder.Decode(&request); err != nil {
		return fail(err)
	}
	if err := request.Validate(); err != nil || request.Type == "hello" || request.Type == "cancel" {
		if err == nil {
			err = errors.New("SSH Gate accepts one command or capability request")
		}
		return fail(err)
	}
	if err := localEncoder.Encode(request); err != nil {
		return fail(err)
	}
	for {
		var response protocol.Response
		if err := localDecoder.Decode(&response); err != nil {
			return fail(err)
		}
		if err := remoteEncoder.Encode(response); err != nil {
			return err
		}
		if response.Type == "exit" || response.Type == "error" {
			return nil
		}
	}
}
