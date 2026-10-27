package policy

import (
	"regexp"
	"strings"
)

var journalReadMatch = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*=.*$`)
var journalBoot = regexp.MustCompile(`^(?:all|[+-]?[0-9]+|[a-fA-F0-9]{32}(?:[+-][0-9]+)?)$`)

// Only query options from journalctl(1) are accepted. In particular cursor-file
// writes state, and maintenance/follow options must never inherit this rule.
// https://www.freedesktop.org/software/systemd/man/latest/journalctl.html
func validateJournalRead(words []shellWord) bool {
	if len(words) == 0 || words[0].value != "journalctl" {
		return false
	}
	booleanLong := map[string]bool{
		"--system": true, "--user": true, "--no-pager": true, "--quiet": true,
		"--reverse": true, "--utc": true, "--all": true, "--full": true,
		"--catalog": true, "--list-boots": true, "--disk-usage": true,
		"--header": true, "--list-catalog": true, "--verify": true,
		"--list-invocations": true, "--list-namespaces": true, "--fields": true,
		"--help": true, "--version": true, "--no-tail": true, "--merge": true,
		"--dmesg": true, "--show-cursor": true, "--cursor-header": true,
		"--truncate-newline": true, "--pager-end": true,
	}
	valueLong := map[string]bool{
		"--since": true, "--until": true, "--cursor": true, "--after-cursor": true,
		"--unit": true, "--user-unit": true, "--identifier": true,
		"--exclude-identifier": true, "--priority": true, "--facility": true,
		"--grep": true, "--case-sensitive": true, "--output": true,
		"--output-fields": true, "--directory": true, "--file": true,
		"--root": true, "--namespace": true, "--field": true, "--machine": true,
	}
	options := true
	for i := 1; i < len(words); i++ {
		arg := words[i].value
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			name, value, attached := strings.Cut(arg, "=")
			if booleanLong[name] {
				if attached {
					return false
				}
				continue
			}
			if name == "--boot" || name == "--invocation" || name == "--lines" {
				if attached && !journalBoot.MatchString(value) {
					return false
				}
				if !attached && i+1 < len(words) && journalBoot.MatchString(words[i+1].value) {
					i++
				}
				continue
			}
			if !valueLong[name] {
				return false
			}
			if !attached {
				i++
				if i >= len(words) {
					return false
				}
				value = words[i].value
			}
			if value == "" {
				return false
			}
			continue
		}
		if options && len(arg) > 1 && arg[0] == '-' {
			for j := 1; j < len(arg); j++ {
				flag := arg[j]
				if strings.ContainsRune("bIn", rune(flag)) {
					if j+1 < len(arg) && !journalBoot.MatchString(arg[j+1:]) {
						return false
					}
					if j+1 == len(arg) && i+1 < len(words) && journalBoot.MatchString(words[i+1].value) {
						i++
					}
					break
				}
				if strings.ContainsRune("uTtpSUcgoDiFM", rune(flag)) {
					if j+1 == len(arg) {
						i++
						if i >= len(words) || words[i].value == "" {
							return false
						}
					}
					break
				}
				if !strings.ContainsRune("qraxlmkNe", rune(flag)) {
					return false
				}
			}
			continue
		}
		if arg != "+" && !journalReadMatch.MatchString(arg) && !(strings.HasPrefix(arg, "/") && cleanPath(arg, false)) {
			return false
		}
	}
	return true
}

var startupProjection = regexp.MustCompile(`^\{\{(?:json )?\.(?:Config\.(?:Entrypoint|Cmd)|Args|Path)\}\}(?: \{\{(?:json )?\.(?:Config\.(?:Entrypoint|Cmd)|Args|Path)\}\}){0,3}$`)

// Podman ps renders templates over listing data; shell syntax is checked before
// validators run. Keep the command and flags fixed, allowing any quoted format.
func validateContainerPS(words []shellWord) bool {
	return len(words) == 5 && words[0].value == "podman" && words[1].value == "ps" &&
		words[2].value == "-a" && words[3].value == "--format" &&
		(words[4].quote == '\'' || words[4].quote == '"') && !words[4].mixed
}

func validateContainerStartup(words []shellWord) bool {
	if len(words) < 4 || words[0].value != "podman" {
		return false
	}
	i := 1
	if words[i].value == "container" {
		i++
	}
	if words[i].value != "inspect" {
		return false
	}
	containers, formats := 0, 0
	for i++; i < len(words); i++ {
		arg := words[i].value
		name, value, attached := strings.Cut(arg, "=")
		if name == "--format" || name == "-f" {
			if !attached {
				i++
				if i >= len(words) {
					return false
				}
				value = words[i].value
			}
			if !startupProjection.MatchString(value) {
				return false
			}
			formats++
		} else if diagnosticIdentifier.MatchString(arg) {
			containers++
		} else {
			return false
		}
	}
	return formats == 1 && containers >= 1 && containers <= 8
}
