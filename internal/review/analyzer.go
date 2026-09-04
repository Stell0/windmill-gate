// Package review turns safe, repeated Gate approvals into reviewable policy candidates.
package review

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/stell0/windmill-gate/internal/approval"
	"github.com/stell0/windmill-gate/internal/command"
	"github.com/stell0/windmill-gate/internal/policy"
	"github.com/stell0/windmill-gate/internal/storage"
)

type Candidate struct {
	Pattern       string   `json:"pattern"`
	Examples      []string `json:"examples"`
	Approvals     int      `json:"approvals"`
	Sessions      int      `json:"sessions"`
	Targets       int      `json:"targets"`
	AllowedSpace  string   `json:"allowed_space"`
	Excluded      []string `json:"excluded"`
	NegativeTests []string `json:"negative_tests"`
}

type candidateGroup struct {
	candidate Candidate
	sessions  map[string]struct{}
	targets   map[string]struct{}
	examples  map[string]struct{}
}

func Analyze(history []storage.HistoryEntry, engine *policy.Engine, minimumApprovals int) []Candidate {
	if engine == nil {
		return nil
	}
	if minimumApprovals < 2 {
		minimumApprovals = 2
	}
	groups := make(map[string]*candidateGroup)
	for _, entry := range history {
		if entry.State != command.Succeeded || entry.PolicyResult != policy.Ask {
			continue
		}
		if entry.ApprovalAction != string(approval.ApproveOnce) && entry.ApprovalAction != string(approval.AllowTarget) {
			continue
		}
		if engine.Evaluate(entry.TargetID, entry.Command).Decision != policy.Ask {
			continue
		}
		candidate, ok := generalize(entry.Command)
		if !ok {
			continue
		}
		group := groups[candidate.Pattern]
		if group == nil {
			group = &candidateGroup{
				candidate: candidate, sessions: make(map[string]struct{}),
				targets: make(map[string]struct{}), examples: make(map[string]struct{}),
			}
			groups[candidate.Pattern] = group
		}
		group.candidate.Approvals++
		group.sessions[entry.AgentSessionID] = struct{}{}
		group.targets[entry.TargetID] = struct{}{}
		if len(group.candidate.Examples) < 5 {
			if _, exists := group.examples[entry.Command]; !exists {
				group.examples[entry.Command] = struct{}{}
				group.candidate.Examples = append(group.candidate.Examples, entry.Command)
			}
		}
	}

	result := make([]Candidate, 0, len(groups))
	for _, group := range groups {
		group.candidate.Sessions = len(group.sessions)
		group.candidate.Targets = len(group.targets)
		if group.candidate.Approvals < minimumApprovals {
			continue
		}
		if group.candidate.Sessions < 2 && group.candidate.Targets < 2 {
			continue
		}
		sort.Strings(group.candidate.Examples)
		result = append(result, group.candidate)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Pattern < result[j].Pattern })
	return result
}

func generalize(value string) (Candidate, bool) {
	if !safeShape(value) {
		return Candidate{}, false
	}
	fields := strings.Fields(value)
	if len(fields) == 0 || strings.Join(fields, " ") != value {
		return Candidate{}, false
	}
	if hasSecret(fields) || hasSideEffects(fields) {
		return Candidate{}, false
	}

	unit := regexp.MustCompile(`^[a-zA-Z0-9_.@-]+$`)
	name := regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	switch {
	case len(fields) == 5 && fields[0] == "journalctl" && fields[1] == "-u" && unit.MatchString(fields[2]) && fields[3] == "-n" && isPositiveInteger(fields[4]):
		return Candidate{
			Pattern:       `^journalctl -u [a-zA-Z0-9_.@-]+ -n [0-9]+$`,
			AllowedSpace:  "bounded journal reads for one syntactically safe systemd unit",
			Excluded:      []string{"--follow", "additional arguments", "pipelines and redirections"},
			NegativeTests: []string{"journalctl -u redis --follow", "journalctl -u redis -n 100 --output=json"},
		}, true
	case len(fields) == 3 && fields[0] == "systemctl" && fields[1] == "status" && unit.MatchString(fields[2]):
		return Candidate{
			Pattern:       `^systemctl status [a-zA-Z0-9_.@-]+$`,
			AllowedSpace:  "read-only status for one syntactically safe systemd unit",
			Excluded:      []string{"restart, stop, or other state changes", "additional arguments"},
			NegativeTests: []string{"systemctl status redis --no-pager", "systemctl restart redis"},
		}, true
	case len(fields) == 5 && fields[0] == "podman" && fields[1] == "logs" && fields[2] == "--tail" && isPositiveInteger(fields[3]) && name.MatchString(fields[4]):
		return Candidate{
			Pattern:       `^podman logs --tail [0-9]+ [a-zA-Z0-9_.-]+$`,
			AllowedSpace:  "bounded logs for one syntactically safe container name",
			Excluded:      []string{"--follow", "exec", "additional arguments"},
			NegativeTests: []string{"podman logs --follow redis", "podman exec redis sh"},
		}, true
	}

	if exactReadOnly(fields) {
		return Candidate{
			Pattern:       "^" + regexp.QuoteMeta(value) + "$",
			AllowedSpace:  "only the exact repeatedly approved read-only command",
			Excluded:      []string{"all additional arguments", "shell composition", "different paths or values"},
			NegativeTests: []string{value + " --unexpected"},
		}, true
	}
	return Candidate{}, false
}

func safeShape(value string) bool {
	if policy.HasUnsafeComposition(value) || strings.ContainsAny(value, "'\"\\*?[]{}~") {
		return false
	}
	lower := strings.ToLower(value)
	return !strings.Contains(lower, "windmill") && !strings.Contains(lower, "sancho")
}

func hasSecret(fields []string) bool {
	for _, field := range fields {
		lower := strings.ToLower(field)
		for _, marker := range []string{"password", "passwd", "token", "secret", "private_key", "authorization", "cookie", "bearer"} {
			if strings.Contains(lower, marker) {
				return true
			}
		}
		if looksHighEntropy(field) {
			return true
		}
	}
	return false
}

func looksHighEntropy(value string) bool {
	if len(value) < 24 || strings.Contains(value, "/") {
		return false
	}
	var letters, digits int
	for _, r := range value {
		if unicode.IsLetter(r) {
			letters++
		} else if unicode.IsDigit(r) {
			digits++
		}
	}
	return letters >= 8 && digits >= 4
}

func hasSideEffects(fields []string) bool {
	blockedPrograms := map[string]bool{
		"bash": true, "sh": true, "zsh": true, "fish": true,
		"vim": true, "vi": true, "nano": true, "less": true, "more": true, "top": true,
		"mysql": true, "psql": true, "redis-cli": true,
		"ssh": true, "scp": true, "sftp": true, "nc": true, "ncat": true, "socat": true,
		"rm": true, "mv": true, "cp": true, "dd": true, "mkfs": true, "mount": true, "umount": true,
		"chmod": true, "chown": true, "kill": true, "pkill": true, "reboot": true, "shutdown": true,
		"apt": true, "dnf": true, "yum": true, "rpm": true, "pip": true,
	}
	if blockedPrograms[fields[0]] {
		return true
	}
	if fields[0] == "sudo" || fields[0] == "env" || fields[0] == "xargs" || fields[0] == "find" {
		return true
	}
	if fields[0] == "systemctl" && (len(fields) < 2 || fields[1] != "status") {
		return true
	}
	if fields[0] == "podman" && (len(fields) < 2 || (fields[1] != "ps" && fields[1] != "logs")) {
		return true
	}
	return false
}

func exactReadOnly(fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "uname":
		return len(fields) == 1 || (len(fields) == 2 && fields[1] == "-a")
	case "uptime":
		return len(fields) == 1
	case "df":
		return len(fields) == 1 || (len(fields) == 2 && fields[1] == "-h")
	case "free":
		return len(fields) == 1 || (len(fields) == 2 && (fields[1] == "-h" || fields[1] == "-m"))
	case "ps", "ss", "stat", "ls", "du":
		return !containsRootPath(fields[1:])
	case "grep":
		if len(fields) < 3 {
			return false
		}
		path := fields[len(fields)-1]
		return strings.HasPrefix(path, "/var/log/") && !strings.Contains(path, "..")
	case "ip":
		return (len(fields) == 2 || (len(fields) == 3 && (fields[2] == "show" || fields[2] == "list"))) &&
			(fields[1] == "addr" || fields[1] == "route" || fields[1] == "link")
	case "podman":
		return len(fields) == 2 && fields[1] == "ps"
	}
	return false
}

func containsRootPath(fields []string) bool {
	for _, field := range fields {
		if field == "/" || field == "." || field == ".." {
			return true
		}
	}
	return false
}

func isPositiveInteger(value string) bool {
	number, err := strconv.ParseUint(value, 10, 31)
	return err == nil && number > 0
}
