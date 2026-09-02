package forward

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nethserver/gate/internal/backend"
	"github.com/nethserver/gate/internal/storage"
	"github.com/nethserver/gate/internal/target"
)

type testResolver struct {
	backend *forwardBackend
}

func (r testResolver) ResolveBackend(targetID string) (backend.Backend, string, error) {
	if targetID != "gt_one" && targetID != "gt_two" {
		return nil, "", target.ErrNotFound
	}
	return r.backend, "private-backend-id", nil
}

type forwardBackend struct {
	mu       sync.Mutex
	requests []backend.ForwardRequest
	handles  []*testHandle
}

func (b *forwardBackend) Name() string                                          { return "test" }
func (b *forwardBackend) ListTargets(context.Context) ([]backend.Target, error) { return nil, nil }
func (b *forwardBackend) Exec(context.Context, string, backend.ExecRequest) (backend.ExecResult, error) {
	return backend.ExecResult{}, errors.New("not implemented")
}
func (b *forwardBackend) OpenForward(_ context.Context, backendID string, req backend.ForwardRequest) (backend.Forward, error) {
	if backendID != "private-backend-id" {
		return nil, errors.New("wrong backend target")
	}
	handle := &testHandle{done: make(chan struct{})}
	b.mu.Lock()
	b.requests = append(b.requests, req)
	b.handles = append(b.handles, handle)
	b.mu.Unlock()
	return handle, nil
}

type testHandle struct {
	once sync.Once
	done chan struct{}
}

func (h *testHandle) Close() error {
	h.once.Do(func() { close(h.done) })
	return nil
}
func (h *testHandle) Wait() error { <-h.done; return nil }

func TestForwardIsLoopbackTargetScopedAndAudited(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := forwardStore(t)
	defer store.Close()
	implementation := &forwardBackend{}
	manager, err := NewManager(ctx, testResolver{implementation}, store)
	if err != nil {
		t.Fatal(err)
	}
	manager.allocate = func() (uint16, error) { return 18443, nil }
	info, err := manager.Add(ctx, "gt_one", 443, "codex-1")
	if err != nil {
		t.Fatal(err)
	}
	if info.LocalHost != Loopback || info.RemoteHost != Loopback || info.LocalPort != 18443 {
		t.Fatalf("unsafe mapping: %#v", info)
	}
	if len(implementation.requests) != 1 || implementation.requests[0].RemoteHost != Loopback {
		t.Fatalf("backend destination escaped target loopback: %#v", implementation.requests)
	}
	if got := manager.List("gt_two"); len(got) != 0 {
		t.Fatalf("forward visible to another target: %#v", got)
	}
	records, err := store.ActiveForwards(ctx, "gt_one")
	if err != nil || len(records) != 1 || records[0].ID != info.ID {
		t.Fatalf("forward audit mismatch: %#v, %v", records, err)
	}
	if err := manager.Close(ctx, "gt_two", info.ID); !errors.Is(err, ErrWrongTarget) {
		t.Fatalf("cross-target removal allowed: %v", err)
	}
}

func TestTargetCleanupClosesAllForwards(t *testing.T) {
	ctx := context.Background()
	store := forwardStore(t)
	defer store.Close()
	implementation := &forwardBackend{}
	manager, _ := NewManager(ctx, testResolver{implementation}, store)
	nextPort := uint16(18000)
	manager.allocate = func() (uint16, error) { nextPort++; return nextPort, nil }
	for _, port := range []uint16{80, 443} {
		if _, err := manager.Add(ctx, "gt_one", port, "operator"); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.CloseTarget(ctx, "gt_one"); err != nil {
		t.Fatal(err)
	}
	if len(manager.List("gt_one")) != 0 {
		t.Fatal("forwards survived target cleanup")
	}
	for _, handle := range implementation.handles {
		select {
		case <-handle.done:
		case <-time.After(time.Second):
			t.Fatal("backend forward was not closed")
		}
	}
}

func forwardStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, id := range []string{"gt_one", "gt_two"} {
		binding := target.Binding{Target: target.Target{ID: id, Backend: "test", DisplayName: id, CreatedAt: time.Now()}, BackendID: "private"}
		if err := store.SaveTarget(ctx, binding); err != nil {
			t.Fatal(err)
		}
	}
	return store
}
