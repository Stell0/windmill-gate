// Package review turns safe, repeated Gate approvals into reviewable policy candidates.
package review

import (
	"regexp"
	"sort"
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
	PositiveTests []string `json:"positive_tests"`
}

type candidateGroup struct {
	candidate Candidate
	sessions  map[string]struct{}
	targets   map[string]struct{}
	examples  map[string]struct{}
}

// Report contains only sanitized candidates and aggregate rejection reasons. Audit
// connection IDs describe transport activity, never independent investigations.
type Report struct {
	Considered      int            `json:"commands_considered"`
	ManualApprovals int            `json:"manual_approvals"`
	Candidates      []Candidate    `json:"eligible_candidates"`
	Pending         []Candidate    `json:"pending_evidence"`
	Rejected        map[string]int `json:"rejected_reasons"`
	Tests           string         `json:"tests"`
	Usefulness      string         `json:"diagnostic_usefulness"`
}

func Analyze(history []storage.HistoryEntry, engine *policy.Engine, minimumApprovals int) []Candidate {
	return AnalyzeReport(history, engine, minimumApprovals).Candidates
}

func AnalyzeReport(history []storage.HistoryEntry, engine *policy.Engine, minimumApprovals int) Report {
	report := Report{Considered: len(history), Candidates: []Candidate{}, Pending: []Candidate{}, Rejected: map[string]int{},
		Tests: "not run; analysis does not modify policy", Usefulness: "exit success is not proof of diagnostic usefulness; review investigation observations before publishing"}
	if engine == nil {
		report.Rejected["policy unavailable"] = len(history)
		return report
	}
	if minimumApprovals < 2 {
		minimumApprovals = 2
	}
	groups := make(map[string]*candidateGroup)
	seen := map[string]bool{}
	for _, entry := range history {
		reason := ""
		switch {
		case entry.ID == "" || seen[entry.ID]:
			reason = "missing or duplicate command identity"
		case entry.State != command.Succeeded || entry.ExitCode == nil || *entry.ExitCode != 0:
			reason = "not a confirmed successful execution"
		case entry.PolicyResult != policy.Ask || (entry.ApprovalAction != string(approval.ApproveOnce) && entry.ApprovalAction != string(approval.AllowTarget)):
			reason = "not a manual ASK approval"
		case entry.TargetID == "" || strings.TrimSpace(entry.TargetName) == "":
			reason = "missing target context"
		}
		if entry.ID != "" {
			seen[entry.ID] = true
		}
		if reason != "" {
			report.Rejected[reason]++
			continue
		}
		report.ManualApprovals++
		if engine.Evaluate(entry.TargetID, entry.Command).Decision != policy.Ask {
			report.Rejected["already allowed or currently denied"]++
			continue
		}
		candidate, ok := generalize(entry.Command)
		if !ok {
			report.Rejected["outside bounded read-only grammar or sensitive"]++
			continue
		}
		group := groups[candidate.Pattern]
		if group == nil {
			group = &candidateGroup{candidate: candidate, sessions: map[string]struct{}{}, targets: map[string]struct{}{}, examples: map[string]struct{}{}}
			groups[candidate.Pattern] = group
		}
		group.candidate.Approvals++
		if entry.AgentSessionID != "" {
			group.sessions[entry.AgentSessionID] = struct{}{}
		}
		// Reattachments get new opaque IDs. Repeated operator display names
		// remain one conservative target context; names are never exported.
		group.targets[strings.ToLower(strings.TrimSpace(entry.TargetName))] = struct{}{}
		// Keep the evidence bounded; every included example passes the same grammar.
		if _, exists := group.examples[sanitizedExample(entry.Command)]; !exists && len(group.candidate.Examples) < 5 {
			group.examples[sanitizedExample(entry.Command)] = struct{}{}
			group.candidate.Examples = append(group.candidate.Examples, sanitizedExample(entry.Command))
		}
	}
	for _, group := range groups {
		group.candidate.Sessions = len(group.sessions) // informational only
		group.candidate.Targets = len(group.targets)
		sort.Strings(group.candidate.Examples)
		if group.candidate.Approvals < minimumApprovals || group.candidate.Targets < 2 {
			report.Pending = append(report.Pending, group.candidate)
		} else {
			report.Candidates = append(report.Candidates, group.candidate)
		}
	}
	sort.Slice(report.Candidates, func(i, j int) bool { return report.Candidates[i].Pattern < report.Candidates[j].Pattern })
	sort.Slice(report.Pending, func(i, j int) bool { return report.Pending[i].Pattern < report.Pending[j].Pattern })
	return report
}

const unitGrammar = `[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127}`
const nameGrammar = `[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}`
const countGrammar = `(?:[1-9][0-9]{0,2}|1000)`

var unitName = regexp.MustCompile(`^` + unitGrammar + `$`)
var containerName = regexp.MustCompile(`^` + nameGrammar + `$`)
var boundedCount = regexp.MustCompile(`^` + countGrammar + `$`)

func generalize(value string) (Candidate, bool) {
	if !safeShape(value) {
		return Candidate{}, false
	}
	fields := strings.Fields(value)
	if len(fields) == 0 || strings.Join(fields, " ") != value || hasSecret(fields) || hasSideEffects(fields) {
		return Candidate{}, false
	}
	var candidate Candidate
	switch {
	case len(fields) == 5 && fields[0] == "journalctl" && fields[1] == "-u" && unitName.MatchString(fields[2]) && fields[3] == "-n" && boundedCount.MatchString(fields[4]):
		candidate = Candidate{Pattern: `^journalctl -u ` + unitGrammar + ` -n ` + countGrammar + `$`,
			AllowedSpace:  "one alphanumeric-led unit (at most 128 characters), 1 through 1000 journal lines",
			PositiveTests: []string{"journalctl -u redis -n 1", "journalctl -u redis -n 100", "journalctl -u redis -n 200", "journalctl -u redis -n 1000"},
			NegativeTests: []string{"journalctl -u redis --follow", "journalctl -u redis -n 100 --output=json", "journalctl -u --all -n 100", "journalctl -u ../redis -n 100", "journalctl -u  -n 100", "journalctl -u " + strings.Repeat("a", 129) + " -n 100"}}
		for _, n := range []string{"0", "00", "01", "1001", "99999999999999999999999999999", "-1", "+1", "all", ""} {
			candidate.NegativeTests = append(candidate.NegativeTests, "journalctl -u redis -n "+n)
		}
	case len(fields) == 3 && fields[0] == "systemctl" && fields[1] == "status" && unitName.MatchString(fields[2]):
		candidate = Candidate{Pattern: `^systemctl status ` + unitGrammar + `$`, AllowedSpace: "read-only status of one alphanumeric-led unit (at most 128 characters)",
			PositiveTests: []string{"systemctl status redis", "systemctl status redis@1.service"},
			NegativeTests: []string{"systemctl status --all", "systemctl restart redis", "systemctl status redis --unexpected", "systemctl status ../redis", "systemctl status ", "systemctl status " + strings.Repeat("a", 129)}}
	case len(fields) == 5 && fields[0] == "podman" && fields[1] == "logs" && fields[2] == "--tail" && boundedCount.MatchString(fields[3]) && containerName.MatchString(fields[4]):
		candidate = Candidate{Pattern: `^podman logs --tail ` + countGrammar + ` ` + nameGrammar + `$`, AllowedSpace: "1 through 1000 log lines from one alphanumeric-led container (at most 128 characters)",
			PositiveTests: []string{"podman logs --tail 1 redis", "podman logs --tail 100 redis", "podman logs --tail 1000 redis"},
			NegativeTests: []string{"podman logs --follow redis", "podman logs redis", "podman exec redis sh", "podman logs --tail 100 --latest", "podman logs --tail 100 ../redis", "podman logs --tail 100 ", "podman logs --tail 100 " + strings.Repeat("a", 129)}}
		for _, n := range []string{"0", "00", "01", "1001", "99999999999999999999999999999", "-1", "+1", "all", ""} {
			candidate.NegativeTests = append(candidate.NegativeTests, "podman logs --tail "+n+" redis")
		}
	default:
		if !exactReadOnly(fields) {
			return Candidate{}, false
		}
		candidate = Candidate{Pattern: "^" + regexp.QuoteMeta(value) + "$", AllowedSpace: "only the exact repeatedly approved diagnostic command", PositiveTests: []string{value}}
	}
	candidate.Excluded = []string{"shell composition, quotes, escapes and control characters", "extra arguments, option-like names and paths", "unbounded logs, writes, shells and unsupported wrappers"}
	// Mutations are checked both as raw regexps and through the complete engine.
	for _, positive := range append(append([]string{}, candidate.PositiveTests...), sanitizedExample(value)) {
		candidate.NegativeTests = append(candidate.NegativeTests, adversarialMutations(positive)...)
	}
	return candidate, true
}

func adversarialMutations(value string) []string {
	result := []string{"", "x" + value, value + "x --unexpected", "prefix " + value, value + " --unexpected", " " + value, value + " ", "sudo " + value,
		"runagent -m ../module " + value, "runagent -m module runagent -m nested " + value, "runagent -m module podman exec --privileged redis " + value}
	for _, suffix := range []string{"; reboot", " && reboot", " || reboot", " | sh", " > /tmp/output", " >> /tmp/output", " < /tmp/input", " $(reboot)", " `reboot`", `\`, "\n", "\r", "\t", "\x00", "\x1b", " # comment", " 'unterminated", ` "quoted"`, ` \escaped`} {
		result = append(result, value+suffix)
	}
	return result
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
	case "ip":
		return (len(fields) == 2 || (len(fields) == 3 && (fields[2] == "show" || fields[2] == "list"))) &&
			(fields[1] == "addr" || fields[1] == "route" || fields[1] == "link")
	case "podman":
		return len(fields) == 2 && fields[1] == "ps"
	}
	return false
}

// Variable identifiers can contain customer or transport data that a secret
// heuristic cannot recognize. Only proposal evidence is redacted; the original
// audit payload and approved execution bytes are never modified.
func sanitizedExample(value string) string {
	fields := strings.Split(value, " ")
	if len(fields) == 5 && fields[0] == "journalctl" {
		fields[2] = "example.service"
	}
	if len(fields) == 3 && fields[0] == "systemctl" {
		fields[2] = "example.service"
	}
	if len(fields) == 5 && fields[0] == "podman" && fields[1] == "logs" {
		fields[4] = "example-container"
	}
	return strings.Join(fields, " ")
}
