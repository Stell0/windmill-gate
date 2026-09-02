package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nethserver/gate/internal/approval"
	"github.com/nethserver/gate/internal/command"
	"github.com/nethserver/gate/internal/policy"
	"github.com/nethserver/gate/internal/target"
)

func TestAuditRecordsSurviveRestartWithoutLeakingBackendID(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "gate.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	registry := target.NewRegistry()
	public, err := registry.Add("windmill", "windmill-private-4837291", "customer.example")
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := registry.Resolve(public.ID)
	if err := store.SaveTarget(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if err := store.StartAgentSession(ctx, "as_test", "codex-1", public.ID, "unix", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	cmd, err := command.New("as_test", public.ID, []byte("uptime"))
	if err != nil {
		t.Fatal(err)
	}
	result := policy.Result{Decision: policy.Ask, Source: "default"}
	if err := store.CreateCommand(ctx, cmd.Snapshot(), result); err != nil {
		t.Fatal(err)
	}
	snapshot := cmd.Snapshot()
	decision := approval.Decision{CommandID: snapshot.ID, Hash: snapshot.Hash, Action: approval.ApproveOnce, Actor: "operator", DecidedAt: time.Now()}
	if err := store.RecordApproval(ctx, decision); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Transition(command.Running, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCommand(ctx, cmd.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendOutput(ctx, snapshot.ID, "stdout", []byte("healthy\\n"), 1024); err != nil {
		t.Fatal(err)
	}
	exitCode := 0
	if err := cmd.Transition(command.Succeeded, &exitCode); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCommand(ctx, cmd.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	history, err := store.HistoryJSON(ctx, "as_test", 10)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(history, []byte("windmill-private-4837291")) {
		t.Fatalf("backend ID leaked through history: %s", history)
	}
	var entries []HistoryEntry
	if err := json.Unmarshal(history, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].State != command.Succeeded || entries[0].OutputBytes != 9 {
		t.Fatalf("audit history did not survive restart: %#v", entries)
	}
	mode, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode.Mode().Perm() != 0o600 {
		t.Fatalf("database permissions = %o, want 600", mode.Mode().Perm())
	}
}

func TestOutputLimitAndTruncationMetadata(t *testing.T) {
	ctx := context.Background()
	store, commandID := seededStore(t)
	defer store.Close()

	first, truncated, err := store.AppendOutput(ctx, commandID, "stdout", []byte("1234"), 6)
	if err != nil || truncated || string(first) != "1234" {
		t.Fatalf("first append = %q, %v, %v", first, truncated, err)
	}
	second, truncated, err := store.AppendOutput(ctx, commandID, "stderr", []byte("56789"), 6)
	if err != nil || !truncated || string(second) != "56" {
		t.Fatalf("second append = %q, %v, %v", second, truncated, err)
	}
	third, truncated, err := store.AppendOutput(ctx, commandID, "stdout", []byte("ignored"), 6)
	if err != nil || !truncated || len(third) != 0 {
		t.Fatalf("third append = %q, %v, %v", third, truncated, err)
	}
	history, err := store.History(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].OutputBytes != 6 || !history[0].Truncated {
		t.Fatalf("unexpected output metadata: %#v", history)
	}
	stdout, stderr, err := store.OutputPreview(ctx, commandID, 1024)
	if err != nil || stdout != "1234" || stderr != "56" {
		t.Fatalf("output preview stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
}

func seededStore(t *testing.T) (*Store, string) {
	t.Helper()
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	registry := target.NewRegistry()
	public, err := registry.Add("windmill", "private", "test target")
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := registry.Resolve(public.ID)
	if err := store.SaveTarget(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if err := store.StartAgentSession(ctx, "as_test", "agent", public.ID, "unix", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	cmd, err := command.New("as_test", public.ID, []byte("uptime"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateCommand(ctx, cmd.Snapshot(), policy.Result{Decision: policy.Allow, Source: "persistent"}); err != nil {
		t.Fatal(err)
	}
	return store, cmd.Snapshot().ID
}

func TestPublicHistoryShapeContainsNoPrivateField(t *testing.T) {
	typeOf, err := json.Marshal(HistoryEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(typeOf), "backend") {
		t.Fatalf("history type exposes backend data: %s", typeOf)
	}
}

func TestRemoteClientIdentityAndFingerprintAreAudited(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	registry := target.NewRegistry()
	public, _ := registry.Add("windmill", "private", "target")
	binding, _ := registry.Resolve(public.ID)
	if err := store.SaveTarget(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if err := store.StartAgentSession(ctx, "as_remote", "codex-prod", public.ID, "ssh", "SHA256:key-one", time.Now()); err != nil {
		t.Fatal(err)
	}
	sessions, err := store.AgentSessions(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Identity != "codex-prod" || sessions[0].Transport != "ssh" || sessions[0].Fingerprint != "SHA256:key-one" {
		t.Fatalf("remote identity audit mismatch: %#v", sessions)
	}
}

func TestOpenMigratesV1ForwardAndAliasAuditColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE forwards (
			id TEXT PRIMARY KEY, target_id TEXT, remote_host TEXT, remote_port INTEGER,
			local_host TEXT, local_port INTEGER, state TEXT, created_by TEXT,
			created_at_ns INTEGER, closed_at_ns INTEGER
		);
		CREATE TABLE host_aliases (
			hostname TEXT PRIMARY KEY, target_id TEXT, forward_id TEXT, address TEXT,
			managed_marker TEXT, created_at_ns INTEGER, removed_at_ns INTEGER
		);`)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for table, columns := range map[string][]string{
		"forwards":     {"closed_by"},
		"host_aliases": {"created_by", "removed_by"},
	} {
		for _, column := range columns {
			var count int
			query := `SELECT COUNT(*) FROM pragma_table_info('` + table + `') WHERE name = ?`
			if err := store.db.QueryRow(query, column).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Errorf("migration omitted %s.%s", table, column)
			}
		}
	}
}
