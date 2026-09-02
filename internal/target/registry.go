// Package target owns Gate's opaque, agent-safe target namespace.
package target

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrNotFound = errors.New("gate target not found")

// Target is safe to expose through the agent protocol.
type Target struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	Backend     string    `json:"backend"`
	CreatedAt   time.Time `json:"created_at"`
}

// Binding is used only inside Gate to resolve a public target to its backend.
// BackendID is explicitly excluded from serialization as a defense in depth.
type Binding struct {
	Target
	BackendID string `json:"-"`
}

// Registry stores the private Gate target -> backend target mapping.
type Registry struct {
	mu       sync.RWMutex
	bindings map[string]Binding
	now      func() time.Time
	randomID func() (string, error)
}

func NewRegistry() *Registry {
	return &Registry{
		bindings: make(map[string]Binding),
		now:      time.Now,
		randomID: newID,
	}
}

// Add creates a random target ID unrelated to backendID.
func (r *Registry) Add(backendName, backendID, displayName string) (Target, error) {
	if strings.TrimSpace(backendID) == "" {
		return Target{}, errors.New("backend target ID is required")
	}
	if err := validateDisplayName(displayName); err != nil {
		return Target{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for attempts := 0; attempts < 8; attempts++ {
		id, err := r.randomID()
		if err != nil {
			return Target{}, fmt.Errorf("create Gate target ID: %w", err)
		}
		if _, exists := r.bindings[id]; exists {
			continue
		}
		public := Target{
			ID:          id,
			DisplayName: displayName,
			Backend:     backendName,
			CreatedAt:   r.now().UTC(),
		}
		r.bindings[id] = Binding{Target: public, BackendID: backendID}
		return public, nil
	}
	return Target{}, errors.New("could not allocate unique Gate target ID")
}

func validateDisplayName(value string) error {
	if strings.TrimSpace(value) == "" || len(value) > 256 || !utf8.ValidString(value) {
		return errors.New("target display name must be 1-256 UTF-8 bytes")
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return errors.New("target display name contains control characters")
		}
	}
	return nil
}

func (r *Registry) Resolve(id string) (Binding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	binding, ok := r.bindings[id]
	if !ok {
		return Binding{}, ErrNotFound
	}
	return binding, nil
}

func (r *Registry) List() []Target {
	r.mu.RLock()
	defer r.mu.RUnlock()
	targets := make([]Target, 0, len(r.bindings))
	for _, binding := range r.bindings {
		targets = append(targets, binding.Target)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	return targets
}

func (r *Registry) Remove(id string) (Binding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	binding, ok := r.bindings[id]
	if !ok {
		return Binding{}, ErrNotFound
	}
	delete(r.bindings, id)
	return binding, nil
}

func newID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])
	return "gt_" + encoded, nil
}
