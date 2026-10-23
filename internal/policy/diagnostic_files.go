package policy

import (
	"regexp"
	"strconv"
	"strings"
)

var diagnosticIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var printRange = regexp.MustCompile(`^([1-9][0-9]{0,8}),([1-9][0-9]{0,8})p$`)

func validateModuleChecksums(words []shellWord) bool {
	if len(words) < 2 || len(words) > 9 || words[0].value != "sha256sum" {
		return false
	}
	for _, word := range words[1:] {
		if !cleanPath(word.value, false) {
			return false
		}
		parts := strings.Split(word.value, "/")
		if len(parts) < 6 || parts[0] != "" || parts[1] != "home" ||
			!diagnosticIdentifier.MatchString(parts[2]) || parts[3] != ".config" {
			return false
		}
		if len(parts) == 6 && (parts[4] == "bin" || parts[4] == "update-module.d") && diagnosticIdentifier.MatchString(parts[5]) {
			continue
		}
		if len(parts) == 7 && parts[4] == "systemd" && parts[5] == "user" &&
			diagnosticIdentifier.MatchString(parts[6]) && strings.HasSuffix(parts[6], ".service") {
			continue
		}
		return false
	}
	return true
}

func validateDiagnosticSlice(words []shellWord) bool {
	if len(words) != 4 || words[0].value != "sed" || words[1].value != "-n" || words[2].mixed {
		return false
	}
	match := printRange.FindStringSubmatch(words[2].value)
	if match == nil {
		return false
	}
	start, _ := strconv.Atoi(match[1])
	end, _ := strconv.Atoi(match[2])
	return end >= start && end-start < 1000 && cleanPath(words[3].value, false) &&
		(diagnosticSourcePath(words[3].value) || logOperands(words[3:]))
}

// Explicit configuration/source paths keep these rules away from arbitrary
// credentials, secret mounts and executable sed programs. Existing Asterisk
// grep paths remain supported by containerGrepPath.
func diagnosticSourcePath(value string) bool {
	if !cleanPath(value, false) {
		return false
	}
	switch value {
	case "/etc/kamailio/kamailio.cfg", "/etc/rtpengine/rtpengine.conf",
		"/etc/asterisk/pjsip.endpoint.conf", "/var/lib/asterisk/bin/send_email", "/initdb.d/update.php":
		return true
	}
	return pathWithin(value, "/app") && strings.HasSuffix(value, ".js") ||
		pathWithin(value, "/var/www/html/freepbx/admin/modules") && strings.HasSuffix(value, ".php")
}
