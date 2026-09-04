// Package forward manages target-scoped, loopback-only TCP forwards.
package forward

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stell0/windmill-gate/internal/backend"
	"github.com/stell0/windmill-gate/internal/storage"
)

const (
	Loopback = "127.0.0.1"
	Active   = "active"
	Closed   = "closed"
)

var (
	ErrNotFound    = errors.New("forward not found")
	ErrWrongTarget = errors.New("forward belongs to another Gate target")
)

type Resolver interface {
	ResolveBackend(targetID string) (backend.Backend, string, error)
}

type Info struct {
	ID         string    `json:"id"`
	TargetID   string    `json:"target_id"`
	RemoteHost string    `json:"remote_host"`
	RemotePort uint16    `json:"remote_port"`
	LocalHost  string    `json:"local_host"`
	LocalPort  uint16    `json:"local_port"`
	State      string    `json:"state"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
}

func (i Info) Endpoint() string {
	return net.JoinHostPort(i.LocalHost, fmt.Sprint(i.LocalPort))
}

type managed struct {
	info   Info
	handle backend.Forward
}

type Manager struct {
	ctx      context.Context
	resolver Resolver
	store    *storage.Store

	mu       sync.RWMutex
	forwards map[string]*managed
	allocate func() (uint16, error)
}

func NewManager(ctx context.Context, resolver Resolver, store *storage.Store) (*Manager, error) {
	if resolver == nil || store == nil {
		return nil, errors.New("forward resolver and store are required")
	}
	if err := store.CloseStaleForwards(context.WithoutCancel(ctx), time.Now().UTC()); err != nil {
		return nil, err
	}
	return &Manager{
		ctx: ctx, resolver: resolver, store: store,
		forwards: make(map[string]*managed), allocate: allocatePort,
	}, nil
}

func (m *Manager) Add(ctx context.Context, targetID string, remotePort uint16, actor string) (Info, error) {
	if remotePort == 0 {
		return Info{}, errors.New("remote port must be between 1 and 65535")
	}
	if strings.TrimSpace(actor) == "" {
		return Info{}, errors.New("forward actor is required")
	}
	implementation, backendID, err := m.resolver.ResolveBackend(targetID)
	if err != nil {
		return Info{}, err
	}
	id, err := forwardID()
	if err != nil {
		return Info{}, err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		localPort, err := m.allocate()
		if err != nil {
			return Info{}, err
		}
		handle, err := implementation.OpenForward(m.ctx, backendID, backend.ForwardRequest{
			RemoteHost: Loopback, RemotePort: remotePort, LocalPort: localPort,
		})
		if err != nil {
			lastErr = err
			continue
		}
		info := Info{
			ID: id, TargetID: targetID, RemoteHost: Loopback, RemotePort: remotePort,
			LocalHost: Loopback, LocalPort: localPort, State: Active, CreatedBy: actor,
			CreatedAt: time.Now().UTC(),
		}
		record := storage.ForwardRecord{
			ID: info.ID, TargetID: info.TargetID, RemoteHost: info.RemoteHost,
			RemotePort: info.RemotePort, LocalHost: info.LocalHost, LocalPort: info.LocalPort,
			State: info.State, CreatedBy: info.CreatedBy, CreatedAt: info.CreatedAt,
		}
		if err := m.store.SaveForward(ctx, record); err != nil {
			_ = handle.Close()
			return Info{}, err
		}
		item := &managed{info: info, handle: handle}
		m.mu.Lock()
		m.forwards[id] = item
		m.mu.Unlock()
		go m.wait(item)
		return info, nil
	}
	return Info{}, fmt.Errorf("open loopback forward after 3 attempts: %w", lastErr)
}

func (m *Manager) List(targetID string) []Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Info, 0)
	for _, item := range m.forwards {
		if targetID == "" || item.info.TargetID == targetID {
			result = append(result, item.info)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result
}

func (m *Manager) Close(ctx context.Context, targetID, id, actor string) error {
	m.mu.Lock()
	item, ok := m.forwards[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	if item.info.TargetID != targetID {
		m.mu.Unlock()
		return ErrWrongTarget
	}
	delete(m.forwards, id)
	m.mu.Unlock()
	handleErr := item.handle.Close()
	storeErr := m.store.CloseForward(context.WithoutCancel(ctx), id, actor, time.Now().UTC())
	return errors.Join(ignoreProcessDone(handleErr), storeErr)
}

func (m *Manager) CloseTarget(ctx context.Context, targetID, actor string) error {
	items := m.List(targetID)
	var result error
	for _, item := range items {
		result = errors.Join(result, m.Close(ctx, targetID, item.ID, actor))
	}
	return result
}

func (m *Manager) wait(item *managed) {
	_ = item.handle.Wait()
	m.mu.Lock()
	current, ok := m.forwards[item.info.ID]
	if ok && current == item {
		delete(m.forwards, item.info.ID)
	}
	m.mu.Unlock()
	if ok {
		_ = m.store.CloseForward(context.Background(), item.info.ID, "transport", time.Now().UTC())
	}
}

func allocatePort() (uint16, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(Loopback, "0"))
	if err != nil {
		return 0, fmt.Errorf("allocate loopback port: %w", err)
	}
	defer listener.Close()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.IP.String() != Loopback || address.Port < 1 || address.Port > 65535 {
		return 0, errors.New("invalid allocated loopback address")
	}
	return uint16(address.Port), nil
}

func forwardID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("create forward ID: %w", err)
	}
	return "fw_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]), nil
}

func ignoreProcessDone(err error) error {
	if err == nil || strings.Contains(strings.ToLower(err.Error()), "process already finished") {
		return nil
	}
	return err
}
