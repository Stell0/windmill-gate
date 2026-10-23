package policy

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

var capturePath = regexp.MustCompile(`^/tmp/gate-[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}\.pcap$`)

func boundedDecimal(value string, maximum int) bool {
	n, err := strconv.Atoi(value)
	return err == nil && n >= 1 && n <= maximum && strconv.Itoa(n) == value
}

func validCapturePath(value string) bool {
	return capturePath.MatchString(value) && !strings.Contains(value, "..")
}

func validatePacketCapture(words []shellWord) bool {
	// Replay one explicit capture file, with finite output.
	if len(words) == 8 && words[0].value == "tcpdump" && words[1].value == "-nn" &&
		words[2].value == "-tttt" && words[3].value == "-A" && words[4].value == "-r" &&
		validCapturePath(words[5].value) && words[6].value == "-c" {
		return boundedDecimal(words[7].value, 1000)
	}
	// Live captures must have a deadline, one fixed interface and a restricted
	// SIP filter. No post-rotation programs, arbitrary paths or extra options.
	if len(words) < 10 || words[0].value != "timeout" || !boundedDecimal(words[1].value, 180) ||
		words[2].value != "tcpdump" || words[3].value != "-ni" || words[4].value != "any" ||
		words[5].value != "-s0" || words[6].value != "-U" {
		return false
	}
	i := 7
	if words[i].value == "-c" {
		if !boundedDecimal(words[i+1].value, 1000) {
			return false
		}
		i += 2
	}
	if len(words) != i+3 || words[i].value != "-w" || !validCapturePath(words[i+1].value) || words[i+2].quote == 0 || words[i+2].mixed {
		return false
	}
	terms := strings.Split(words[i+2].value, " or ")
	if len(terms) < 1 || len(terms) > 8 {
		return false
	}
	for _, term := range terms {
		fields := strings.Split(term, " ")
		if len(fields) != 3 || (fields[0] != "udp" && fields[0] != "tcp") || fields[1] != "port" ||
			(fields[2] != "5060" && fields[2] != "5061" && fields[2] != "20030") {
			return false
		}
	}
	return true
}

func validProbeHost(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.To4() != nil
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c > 127 || (!asciiLetter(byte(c)) && !asciiDigit(byte(c)) && c != '-') {
				return false
			}
		}
	}
	return true
}

func validateTLSProbe(words []shellWord) bool {
	if len(words) != 14 || words[0].value != "timeout" || !boundedDecimal(words[1].value, 30) ||
		words[2].value != "openssl" || words[3].value != "s_client" || words[4].value != "-connect" ||
		words[6].value != "-servername" || words[8].value != "-verify_hostname" || words[10].value != "-verify_return_error" ||
		words[11].value != "<" || words[12].value != "/dev/null" || words[13].value != "2>&1" {
		return false
	}
	host, port, found := strings.Cut(words[5].value, ":")
	return found && (port == "443" || port == "5061") && validProbeHost(host) &&
		words[7].value == host && words[9].value == host
}

// Only the exact EOF/stream-merge suffix of a bounded, certificate-verifying
// TLS probe is recognized. Tokens are classification views of the original
// payload; no execution bytes are rewritten or reconstructed.
func tokenizeTLSRedirect(input string) ([]shellWord, bool) {
	prefix, ok := strings.CutSuffix(input, " < /dev/null 2>&1")
	if !ok {
		return nil, false
	}
	words, err := tokenizeShell(prefix)
	if err != nil {
		return nil, false
	}
	words = append(words, shellWord{value: "<"}, shellWord{value: "/dev/null"}, shellWord{value: "2>&1"})
	inner := words
	if len(inner) >= 3 && inner[0].value == "runagent" && inner[1].value == "-m" && diagnosticIdentifier.MatchString(inner[2].value) {
		inner = inner[3:]
	}
	return words, validateTLSProbe(inner)
}
