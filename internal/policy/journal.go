package policy

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var journalSelector = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127}$`)

// validateScopedJournal accepts only bounded, non-interactive reads scoped to
// one UID, syslog identifier or user unit. Options after the selector may be
// reordered, but not repeated.
func validateScopedJournal(words []shellWord) bool {
	if len(words) < 2 || words[0].value != "journalctl" {
		return false
	}
	seen := map[string]bool{}
	values := map[string]string{}
	for i := 1; i < len(words); i++ {
		name, value, attached := strings.Cut(words[i].value, "=")
		switch name {
		case "--no-pager", "--user":
			if attached {
				return false
			}
		case "_UID", "_SYSTEMD_USER_UNIT", "--since", "--until", "--grep", "--case-sensitive":
			if !attached || value == "" {
				return false
			}
		case "-t", "-n", "-o", "-g", "-u":
			if attached || i+1 >= len(words) {
				return false
			}
			i++
			value = words[i].value
		default:
			return false
		}
		if name == "-g" {
			name = "--grep"
		}
		if seen[name] {
			return false
		}
		seen[name], values[name] = true, value
	}
	uid, tag := values["_UID"], values["-t"]
	scopes := 0
	for _, present := range []bool{uid != "", tag != "", seen["--user"]} {
		if present {
			scopes++
		}
	}
	if scopes != 1 || !seen["--no-pager"] {
		return false
	}
	if seen["--user"] && !journalSelector.MatchString(values["-u"]) {
		return false
	}
	if seen["-u"] && !seen["--user"] {
		return false
	}
	if uid != "" && (len(uid) > 10 || !decimal(uid, false)) {
		return false
	}
	if tag != "" && !journalSelector.MatchString(tag) {
		return false
	}
	if unit, ok := values["_SYSTEMD_USER_UNIT"]; ok && (uid == "" || !journalSelector.MatchString(unit)) {
		return false
	}
	count, err := strconv.Atoi(values["-n"])
	if err != nil || count < 1 || count > 1000 || strconv.Itoa(count) != values["-n"] {
		return false
	}
	if output, ok := values["-o"]; ok && output != "short-iso-precise" {
		return false
	}
	if seen["--since"] {
		since, ok := utcTimestamp(values["--since"])
		if !ok {
			return false
		}
		if seen["--until"] {
			until, ok := utcTimestamp(values["--until"])
			if !ok || until.Before(since) {
				return false
			}
		}
	} else if seen["--until"] {
		return false
	}
	if match, ok := values["--grep"]; ok && !safeJournalFilter(match) {
		return false
	}
	if sensitivity, ok := values["--case-sensitive"]; ok && (sensitivity != "no" || !seen["--grep"]) {
		return false
	}
	return true
}

// These observed expressions each contain one wildcard and fixed alternatives,
// with no nested repetition or user-supplied regex fragments. General PCRE
// programs remain outside the allow policy.
var reviewedJournalFilters = map[string]bool{
	"ERROR:|FATAL:|Cannot reload|reload.*fail|Traceback|permission denied|assertion|reconfigur|status is|update-module.d": true,
	"Starting FreePBX|Started FreePBX|Failed to start FreePBX|freepbx.service:.*(timeout|dependency|timed out)":           true,
	"mariadb.service:.*(timed out|timeout)|Starting mariadb server|Started mariadb server|Failed to start mariadb server": true,
}

// Keep existing single-ID filters, simple diagnostic alternatives and the
// exact reviewed expressions above. No arbitrary quantifiers/groups/escapes.
func safeJournalFilter(value string) bool {
	if boundedJournalMatch(value) || reviewedJournalFilters[value] {
		return true
	}
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	if strings.HasPrefix(value, "task/module/") && journalSelector.MatchString(strings.TrimPrefix(value, "task/module/")) {
		return true
	}
	parts := strings.Split(value, "|")
	if len(parts) < 2 || len(parts) > 16 {
		return false
	}
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return false
		}
		for _, c := range part {
			if c > 127 || (!asciiLetter(byte(c)) && !asciiDigit(byte(c)) && c != ' ' && c != ':' && c != '-' && c != '_' && c != '.') {
				return false
			}
		}
	}
	return true
}

func validateUIDJournal(words []shellWord) bool {
	if (len(words) != 9 && len(words) != 11) || words[0].value != "journalctl" ||
		!strings.HasPrefix(words[1].value, "_UID=") ||
		!strings.HasPrefix(words[2].value, "--since=") ||
		!strings.HasPrefix(words[3].value, "--until=") ||
		words[4].value != "--no-pager" || words[5].value != "-o" ||
		words[6].value != "short-iso-precise" || words[7].value != "-n" {
		return false
	}
	uid := strings.TrimPrefix(words[1].value, "_UID=")
	if len(uid) > 10 || !decimal(uid, false) {
		return false
	}
	lineCount, err := strconv.Atoi(words[8].value)
	if err != nil || lineCount < 1 || lineCount > 1000 {
		return false
	}
	since, ok := utcTimestamp(strings.TrimPrefix(words[2].value, "--since="))
	if !ok {
		return false
	}
	until, ok := utcTimestamp(strings.TrimPrefix(words[3].value, "--until="))
	if !ok || until.Before(since) {
		return false
	}
	if len(words) == 11 {
		return words[9].value == "-g" && boundedJournalMatch(words[10].value)
	}
	return true
}

func boundedJournalMatch(value string) bool {
	if len(value) < 3 || len(value) > 256 || (!asciiLetter(value[0]) && !asciiDigit(value[0])) {
		return false
	}
	decimalOnly := asciiDigit(value[0])
	hasDigit := decimalOnly
	hasNonDigit := !decimalOnly
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !asciiLetter(character) && !asciiDigit(character) && !strings.ContainsRune("._:@-", rune(character)) {
			return false
		}
		decimalOnly = decimalOnly && asciiDigit(character)
		hasDigit = hasDigit || asciiDigit(character)
		hasNonDigit = hasNonDigit || !asciiDigit(character)
	}
	return decimalOnly || (len(value) >= 8 && hasDigit && hasNonDigit)
}

func utcTimestamp(value string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02T15:04:05Z", "2006-01-02 15:04:05 UTC"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}
