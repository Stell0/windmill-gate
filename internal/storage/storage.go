// Package storage provides Gate's local SQLite audit store.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nethserver/gate/internal/approval"
	"github.com/nethserver/gate/internal/command"
	"github.com/nethserver/gate/internal/policy"
	"github.com/nethserver/gate/internal/target"
	_ "modernc.org/sqlite"
)

const schema = `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS targets (
    id            TEXT PRIMARY KEY,
    backend       TEXT NOT NULL,
    backend_id    TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    created_at_ns INTEGER NOT NULL,
    detached_at_ns INTEGER
);

CREATE TABLE IF NOT EXISTS agent_sessions (
    id             TEXT PRIMARY KEY,
    identity       TEXT NOT NULL,
    target_id      TEXT NOT NULL REFERENCES targets(id),
    transport      TEXT NOT NULL,
    fingerprint    TEXT,
    started_at_ns  INTEGER NOT NULL,
    ended_at_ns    INTEGER
);

CREATE TABLE IF NOT EXISTS commands (
    id               TEXT PRIMARY KEY,
    agent_session_id TEXT NOT NULL REFERENCES agent_sessions(id),
    target_id        TEXT NOT NULL REFERENCES targets(id),
    payload          BLOB NOT NULL,
    payload_hash     TEXT NOT NULL,
    state            TEXT NOT NULL,
    policy_result    TEXT NOT NULL,
    policy_rule      TEXT,
    policy_source    TEXT NOT NULL,
    created_at_ns    INTEGER NOT NULL,
    started_at_ns    INTEGER,
    finished_at_ns   INTEGER,
    exit_code        INTEGER
);

CREATE TABLE IF NOT EXISTS approvals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id    TEXT NOT NULL REFERENCES commands(id),
    command_hash  TEXT NOT NULL,
    action        TEXT NOT NULL,
    actor         TEXT NOT NULL,
    rule          TEXT,
    decided_at_ns INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS command_output (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id    TEXT NOT NULL REFERENCES commands(id),
    stream        TEXT NOT NULL CHECK(stream IN ('stdout', 'stderr')),
    sequence      INTEGER NOT NULL,
    data          BLOB NOT NULL,
    truncated     INTEGER NOT NULL DEFAULT 0,
    created_at_ns INTEGER NOT NULL,
    UNIQUE(command_id, sequence)
);

CREATE TABLE IF NOT EXISTS forwards (
    id             TEXT PRIMARY KEY,
    target_id      TEXT NOT NULL REFERENCES targets(id),
    remote_host    TEXT NOT NULL,
    remote_port    INTEGER NOT NULL,
    local_host     TEXT NOT NULL,
    local_port     INTEGER NOT NULL,
    state          TEXT NOT NULL,
    created_by     TEXT NOT NULL,
    created_at_ns  INTEGER NOT NULL,
    closed_at_ns   INTEGER
);

CREATE TABLE IF NOT EXISTS host_aliases (
    hostname       TEXT PRIMARY KEY,
    target_id      TEXT NOT NULL REFERENCES targets(id),
    forward_id     TEXT NOT NULL REFERENCES forwards(id),
    address        TEXT NOT NULL,
    managed_marker TEXT NOT NULL,
    created_at_ns  INTEGER NOT NULL,
    removed_at_ns  INTEGER
);

CREATE INDEX IF NOT EXISTS commands_session_idx ON commands(agent_session_id, created_at_ns);
CREATE INDEX IF NOT EXISTS commands_target_idx ON commands(target_id, created_at_ns);
CREATE INDEX IF NOT EXISTS output_command_idx ON command_output(command_id, sequence);
CREATE INDEX IF NOT EXISTS forwards_target_idx ON forwards(target_id, state);
`

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("secure database permissions: %w", err)
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	return nil
}

func (s *Store) SaveTarget(ctx context.Context, binding target.Binding) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO targets(id, backend, backend_id, display_name, created_at_ns, detached_at_ns)
        VALUES (?, ?, ?, ?, ?, NULL)
        ON CONFLICT(id) DO UPDATE SET
            backend = excluded.backend,
            backend_id = excluded.backend_id,
            display_name = excluded.display_name,
            detached_at_ns = NULL`,
		binding.ID, binding.Backend, binding.BackendID, binding.DisplayName, binding.CreatedAt.UnixNano())
	return wrap("save target", err)
}

func (s *Store) DetachTarget(ctx context.Context, targetID string, at time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE targets SET detached_at_ns = ? WHERE id = ? AND detached_at_ns IS NULL`, at.UnixNano(), targetID)
	if err != nil {
		return fmt.Errorf("detach target: %w", err)
	}
	return requireChanged(result, "target not found or already detached")
}

// StoredTarget is private storage data and must not enter protocol responses.
type StoredTarget struct {
	Target    target.Target
	BackendID string
}

func (s *Store) ActiveTargets(ctx context.Context) ([]StoredTarget, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, backend, backend_id, display_name, created_at_ns
        FROM targets WHERE detached_at_ns IS NULL ORDER BY created_at_ns`)
	if err != nil {
		return nil, fmt.Errorf("list active targets: %w", err)
	}
	defer rows.Close()
	var result []StoredTarget
	for rows.Next() {
		var stored StoredTarget
		var created int64
		if err := rows.Scan(&stored.Target.ID, &stored.Target.Backend, &stored.BackendID, &stored.Target.DisplayName, &created); err != nil {
			return nil, fmt.Errorf("scan active target: %w", err)
		}
		stored.Target.CreatedAt = time.Unix(0, created).UTC()
		result = append(result, stored)
	}
	return result, wrap("iterate active targets", rows.Err())
}

func (s *Store) StartAgentSession(ctx context.Context, id, identity, targetID, transport, fingerprint string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO agent_sessions(id, identity, target_id, transport, fingerprint, started_at_ns)
        VALUES (?, ?, ?, ?, ?, ?)`, id, identity, targetID, transport, nullable(fingerprint), at.UnixNano())
	return wrap("start agent session", err)
}

func (s *Store) EndAgentSession(ctx context.Context, id string, at time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE agent_sessions SET ended_at_ns = ? WHERE id = ? AND ended_at_ns IS NULL`, at.UnixNano(), id)
	if err != nil {
		return fmt.Errorf("end agent session: %w", err)
	}
	return requireChanged(result, "agent session not found or already ended")
}

// AgentSessionEntry is operator-only audit data. Fingerprint must not be added
// to agent protocol responses.
type AgentSessionEntry struct {
	ID          string
	Identity    string
	TargetID    string
	Transport   string
	Fingerprint string
	StartedAt   time.Time
	EndedAt     *time.Time
}

func (s *Store) AgentSessions(ctx context.Context, activeOnly bool) ([]AgentSessionEntry, error) {
	query := `
        SELECT id, identity, target_id, transport, COALESCE(fingerprint, ''), started_at_ns, ended_at_ns
        FROM agent_sessions`
	if activeOnly {
		query += ` WHERE ended_at_ns IS NULL`
	}
	query += ` ORDER BY started_at_ns DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query agent sessions: %w", err)
	}
	defer rows.Close()
	var result []AgentSessionEntry
	for rows.Next() {
		var entry AgentSessionEntry
		var started int64
		var ended sql.NullInt64
		if err := rows.Scan(&entry.ID, &entry.Identity, &entry.TargetID, &entry.Transport, &entry.Fingerprint, &started, &ended); err != nil {
			return nil, fmt.Errorf("scan agent session: %w", err)
		}
		entry.StartedAt = time.Unix(0, started).UTC()
		if ended.Valid {
			value := time.Unix(0, ended.Int64).UTC()
			entry.EndedAt = &value
		}
		result = append(result, entry)
	}
	return result, wrap("iterate agent sessions", rows.Err())
}

func (s *Store) CreateCommand(ctx context.Context, snapshot command.Snapshot, result policy.Result) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO commands(
            id, agent_session_id, target_id, payload, payload_hash, state,
            policy_result, policy_rule, policy_source, created_at_ns
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		snapshot.ID, snapshot.AgentSessionID, snapshot.TargetID, []byte(snapshot.Payload), snapshot.Hash,
		string(snapshot.State), string(result.Decision), nullable(result.Rule), result.Source, snapshot.CreatedAt.UnixNano())
	return wrap("create command", err)
}

func (s *Store) UpdateCommand(ctx context.Context, snapshot command.Snapshot) error {
	result, err := s.db.ExecContext(ctx, `
        UPDATE commands SET state = ?, started_at_ns = ?, finished_at_ns = ?, exit_code = ? WHERE id = ?`,
		string(snapshot.State), timeNS(snapshot.StartedAt), timeNS(snapshot.FinishedAt), intValue(snapshot.ExitCode), snapshot.ID)
	if err != nil {
		return fmt.Errorf("update command: %w", err)
	}
	return requireChanged(result, "command not found")
}

func (s *Store) RecordApproval(ctx context.Context, decision approval.Decision) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO approvals(command_id, command_hash, action, actor, rule, decided_at_ns)
        VALUES (?, ?, ?, ?, ?, ?)`, decision.CommandID, decision.Hash, string(decision.Action), decision.Actor,
		nullable(decision.Rule), decision.DecidedAt.UnixNano())
	return wrap("record approval", err)
}

// AppendOutput stores at most limit bytes across both streams for a command.
// The returned bytes are safe to relay; truncation is recorded exactly once.
func (s *Store) AppendOutput(ctx context.Context, commandID, stream string, data []byte, limit int64) ([]byte, bool, error) {
	if stream != "stdout" && stream != "stderr" {
		return nil, false, errors.New("output stream must be stdout or stderr")
	}
	if limit <= 0 {
		return nil, false, errors.New("output limit must be positive")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin output transaction: %w", err)
	}
	defer tx.Rollback()

	var used int64
	var alreadyTruncated bool
	if err := tx.QueryRowContext(ctx, `
        SELECT COALESCE(SUM(length(data)), 0), COALESCE(MAX(truncated), 0)
        FROM command_output WHERE command_id = ?`, commandID).Scan(&used, &alreadyTruncated); err != nil {
		return nil, false, fmt.Errorf("measure command output: %w", err)
	}
	if alreadyTruncated || used >= limit {
		return nil, true, tx.Commit()
	}
	remaining := limit - used
	stored := data
	truncated := int64(len(data)) > remaining
	if truncated {
		stored = append([]byte(nil), data[:remaining]...)
	}
	var sequence int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence), -1) + 1 FROM command_output WHERE command_id = ?`, commandID).Scan(&sequence); err != nil {
		return nil, false, fmt.Errorf("allocate output sequence: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO command_output(command_id, stream, sequence, data, truncated, created_at_ns)
        VALUES (?, ?, ?, ?, ?, ?)`, commandID, stream, sequence, stored, truncated, time.Now().UTC().UnixNano()); err != nil {
		return nil, false, fmt.Errorf("append command output: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit command output: %w", err)
	}
	return stored, truncated, nil
}

type HistoryEntry struct {
	ID             string          `json:"id"`
	AgentSessionID string          `json:"agent_session_id"`
	AgentIdentity  string          `json:"agent_identity"`
	TargetID       string          `json:"target_id"`
	TargetName     string          `json:"target_name"`
	Command        string          `json:"command"`
	Hash           string          `json:"hash"`
	State          command.State   `json:"state"`
	PolicyResult   policy.Decision `json:"policy_result"`
	PolicyRule     string          `json:"policy_rule,omitempty"`
	PolicySource   string          `json:"policy_source"`
	CreatedAt      time.Time       `json:"created_at"`
	ExitCode       *int            `json:"exit_code,omitempty"`
	ApprovalAction string          `json:"approval_action,omitempty"`
	ApprovalActor  string          `json:"approval_actor,omitempty"`
	OutputBytes    int64           `json:"output_bytes"`
	Truncated      bool            `json:"output_truncated"`
}

// History deliberately selects no backend_id column.
func (s *Store) History(ctx context.Context, agentSessionID string, limit int) ([]HistoryEntry, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	query := `
        SELECT c.id, c.agent_session_id, a.identity, c.target_id, t.display_name,
               CAST(c.payload AS TEXT), c.payload_hash, c.state, c.policy_result,
               COALESCE(c.policy_rule, ''), c.policy_source, c.created_at_ns, c.exit_code,
               COALESCE(ap.action, ''), COALESCE(ap.actor, ''),
               COALESCE(o.output_bytes, 0), COALESCE(o.truncated, 0)
        FROM commands c
        JOIN agent_sessions a ON a.id = c.agent_session_id
        JOIN targets t ON t.id = c.target_id
        LEFT JOIN approvals ap ON ap.id = (
            SELECT MAX(id) FROM approvals WHERE command_id = c.id
        )
        LEFT JOIN (
            SELECT command_id, SUM(length(data)) AS output_bytes, MAX(truncated) AS truncated
            FROM command_output GROUP BY command_id
        ) o ON o.command_id = c.id`
	args := make([]any, 0, 2)
	if agentSessionID != "" {
		query += ` WHERE c.agent_session_id = ?`
		args = append(args, agentSessionID)
	}
	query += ` ORDER BY c.created_at_ns DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query command history: %w", err)
	}
	defer rows.Close()
	var entries []HistoryEntry
	for rows.Next() {
		var entry HistoryEntry
		var created int64
		if err := rows.Scan(
			&entry.ID, &entry.AgentSessionID, &entry.AgentIdentity, &entry.TargetID, &entry.TargetName,
			&entry.Command, &entry.Hash, &entry.State, &entry.PolicyResult, &entry.PolicyRule,
			&entry.PolicySource, &created, &entry.ExitCode, &entry.ApprovalAction, &entry.ApprovalActor,
			&entry.OutputBytes, &entry.Truncated,
		); err != nil {
			return nil, fmt.Errorf("scan command history: %w", err)
		}
		entry.CreatedAt = time.Unix(0, created).UTC()
		entries = append(entries, entry)
	}
	return entries, wrap("iterate command history", rows.Err())
}

func (s *Store) HistoryJSON(ctx context.Context, agentSessionID string, limit int) ([]byte, error) {
	entries, err := s.History(ctx, agentSessionID, limit)
	if err != nil {
		return nil, err
	}
	return json.Marshal(entries)
}

func wrap(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func requireChanged(result sql.Result, message string) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New(message)
	}
	return nil
}

func nullable(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func timeNS(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UnixNano()
}

func intValue(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}
