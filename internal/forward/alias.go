package forward

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stell0/windmill-gate/internal/storage"
)

type AliasInfo struct {
	Hostname   string    `json:"hostname"`
	TargetID   string    `json:"target_id"`
	ForwardID  string    `json:"forward_id"`
	Address    string    `json:"address"`
	RemotePort uint16    `json:"remote_port"`
	LocalPort  uint16    `json:"local_port"`
	URL        string    `json:"url"`
	CreatedAt  time.Time `json:"created_at"`

	marker string
}

type AliasManager struct {
	hostsPath string
	store     *storage.Store
	forwards  *Manager

	mu      sync.Mutex
	aliases map[string]AliasInfo
}

func NewAliasManager(ctx context.Context, hostsPath string, store *storage.Store, forwards *Manager) (*AliasManager, error) {
	if hostsPath == "" || store == nil || forwards == nil {
		return nil, errors.New("hosts path, store, and forward manager are required")
	}
	manager := &AliasManager{hostsPath: hostsPath, store: store, forwards: forwards, aliases: make(map[string]AliasInfo)}
	// A live alias cannot survive daemon restart because its linked process does
	// not survive. Remove only exact markers previously owned by Gate.
	stale, err := store.ActiveHostAliases(context.WithoutCancel(ctx), "")
	if err != nil {
		return nil, err
	}
	for _, record := range stale {
		if err := manager.removeOwnedLine(record.Hostname, record.Marker); err != nil {
			return nil, fmt.Errorf("clean stale alias %s: %w", record.Hostname, err)
		}
		if err := store.RemoveHostAlias(context.WithoutCancel(ctx), record.Hostname, "daemon-restart", time.Now().UTC()); err != nil {
			return nil, err
		}
	}
	return manager, nil
}

func (m *AliasManager) Add(ctx context.Context, targetID, forwardID, hostname, actor string) (AliasInfo, error) {
	var err error
	hostname, err = NormalizeHostname(hostname)
	if err != nil {
		return AliasInfo{}, err
	}
	var linked Info
	found := false
	for _, candidate := range m.forwards.List(targetID) {
		if candidate.ID == forwardID {
			linked, found = candidate, true
			break
		}
	}
	if !found {
		return AliasInfo{}, errors.New("linked forward is not active for this target")
	}
	marker, err := aliasMarker()
	if err != nil {
		return AliasInfo{}, err
	}
	info := AliasInfo{
		Hostname: hostname, TargetID: targetID, ForwardID: forwardID, Address: Loopback,
		RemotePort: linked.RemotePort, LocalPort: linked.LocalPort,
		URL: aliasURL(hostname, linked.RemotePort, linked.LocalPort), CreatedAt: time.Now().UTC(), marker: marker,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.aliases[hostname]; exists {
		return AliasInfo{}, errors.New("hostname alias is already managed by Gate")
	}
	if err := m.addOwnedLine(hostname, marker); err != nil {
		return AliasInfo{}, err
	}
	record := storage.HostAliasRecord{
		Hostname: hostname, TargetID: targetID, ForwardID: forwardID,
		Address: Loopback, Marker: marker, CreatedBy: actor, CreatedAt: info.CreatedAt,
	}
	if err := m.store.SaveHostAlias(ctx, record); err != nil {
		_ = m.removeOwnedLine(hostname, marker)
		return AliasInfo{}, err
	}
	m.aliases[hostname] = info
	return publicAlias(info), nil
}

func (m *AliasManager) List(targetID string) []AliasInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]AliasInfo, 0)
	for _, alias := range m.aliases {
		if targetID == "" || alias.TargetID == targetID {
			result = append(result, publicAlias(alias))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Hostname < result[j].Hostname })
	return result
}

func (m *AliasManager) Remove(ctx context.Context, targetID, hostname, actor string) error {
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	m.mu.Lock()
	defer m.mu.Unlock()
	alias, ok := m.aliases[hostname]
	if !ok {
		return errors.New("hostname alias not found")
	}
	if alias.TargetID != targetID {
		return errors.New("hostname alias belongs to another Gate target")
	}
	if err := m.removeOwnedLine(hostname, alias.marker); err != nil {
		return err
	}
	if err := m.store.RemoveHostAlias(context.WithoutCancel(ctx), hostname, actor, time.Now().UTC()); err != nil {
		return err
	}
	delete(m.aliases, hostname)
	return nil
}

func (m *AliasManager) CloseForward(ctx context.Context, targetID, forwardID, actor string) error {
	aliases := m.List(targetID)
	var result error
	for _, alias := range aliases {
		if alias.ForwardID == forwardID {
			result = errors.Join(result, m.Remove(ctx, targetID, alias.Hostname, actor))
		}
	}
	return result
}

func (m *AliasManager) CloseTarget(ctx context.Context, targetID, actor string) error {
	aliases := m.List(targetID)
	var result error
	for _, alias := range aliases {
		result = errors.Join(result, m.Remove(ctx, targetID, alias.Hostname, actor))
	}
	return result
}

func (m *AliasManager) addOwnedLine(hostname, marker string) error {
	data, mode, err := m.readHosts()
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		content := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		fields := strings.Fields(content)
		if len(fields) < 2 {
			continue
		}
		for _, field := range fields[1:] {
			if strings.EqualFold(strings.TrimSuffix(field, "."), hostname) {
				return fmt.Errorf("hostname %s already has a resolver entry not owned by this request", hostname)
			}
		}
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, []byte(fmt.Sprintf("%s\t%s # %s\n", Loopback, hostname, marker))...)
	return atomicWrite(m.hostsPath, data, mode)
}

func (m *AliasManager) removeOwnedLine(hostname, marker string) error {
	data, mode, err := m.readHosts()
	if err != nil {
		return err
	}
	lines := strings.SplitAfter(string(data), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		comment := ""
		if parts := strings.SplitN(line, "#", 2); len(parts) == 2 {
			comment = strings.TrimSpace(parts[1])
		}
		if comment == marker && resolverLineHasHostname(line, hostname) {
			continue
		}
		kept = append(kept, line)
	}
	return atomicWrite(m.hostsPath, []byte(strings.Join(kept, "")), mode)
}

func (m *AliasManager) readHosts() ([]byte, os.FileMode, error) {
	info, err := os.Lstat(m.hostsPath)
	if err != nil {
		return nil, 0, fmt.Errorf("inspect hosts file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, 0, errors.New("hosts path must be a regular file")
	}
	data, err := os.ReadFile(m.hostsPath)
	if err != nil {
		return nil, 0, fmt.Errorf("read hosts file: %w", err)
	}
	return data, info.Mode().Perm(), nil
}

var hostnameLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func NormalizeHostname(hostname string) (string, error) {
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if hostname == "" || len(hostname) > 253 || net.ParseIP(hostname) != nil || hostname == "localhost" {
		return "", errors.New("hostname must be a non-local DNS name")
	}
	labels := strings.Split(hostname, ".")
	if len(labels) < 2 {
		return "", errors.New("hostname alias must be a fully-qualified name")
	}
	for _, label := range labels {
		if !hostnameLabel.MatchString(label) {
			return "", fmt.Errorf("invalid hostname label %q", label)
		}
	}
	return hostname, nil
}

func resolverLineHasHostname(line, hostname string) bool {
	content := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
	fields := strings.Fields(content)
	if len(fields) < 2 {
		return false
	}
	for _, field := range fields[1:] {
		if strings.EqualFold(strings.TrimSuffix(field, "."), hostname) {
			return true
		}
	}
	return false
}

func aliasURL(hostname string, remotePort, localPort uint16) string {
	scheme := "http"
	if remotePort == 443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d/", scheme, hostname, localPort)
}

func aliasMarker() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "gate:" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]), nil
}

func publicAlias(info AliasInfo) AliasInfo {
	info.marker = ""
	return info
}
