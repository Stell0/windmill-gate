package target

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRegistryUsesOpaqueTargetID(t *testing.T) {
	r := NewRegistry()
	backendID := "windmill-session-4837291"
	target, err := r.Add("windmill", backendID, "customer.example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(target.ID, "gt_") || strings.Contains(target.ID, backendID) {
		t.Fatalf("target ID is not opaque: %q", target.ID)
	}

	binding, err := r.Resolve(target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if binding.BackendID != backendID {
		t.Fatalf("private mapping lost: got %q", binding.BackendID)
	}
}

func TestBackendIDCannotAppearInJSON(t *testing.T) {
	r := NewRegistry()
	target, err := r.Add("windmill", "secret-backend-id", "customer.example")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := r.Resolve(target.ID)
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-backend-id") {
		t.Fatalf("backend ID leaked in JSON: %s", data)
	}
}

func TestTargetIDsAreUnique(t *testing.T) {
	r := NewRegistry()
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		target, err := r.Add("windmill", "same-backend-id", "customer.example")
		if err != nil {
			t.Fatal(err)
		}
		if seen[target.ID] {
			t.Fatalf("duplicate target ID %q", target.ID)
		}
		seen[target.ID] = true
	}
}
