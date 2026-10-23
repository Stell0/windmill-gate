package policy

import (
	"path"
	"strconv"
	"strings"
	"unicode"
)

var validators = map[string]func([]shellWord) bool{
	"asterisk_config_slice": validateAsteriskConfigSlice,
	"container_grep":        validateContainerGrep,
	"diagnostic_read":       validateDiagnosticRead,
	"diagnostic_slice":      validateDiagnosticSlice,
	"source_grep":           validateSourceGrep,
	"module_checksums":      validateModuleChecksums,
	"packet_capture":        validatePacketCapture,
	"tls_probe":             validateTLSProbe,
	"mysql_read":            validateMySQLRead,
	"mysql_select":          validateMySQLSelect,
	"mysql_shell_read":      validateMySQLShellRead,
	"rtpengine_read":        validateRTPengineRead,
	"uid_journal":           validateUIDJournal,
	"scoped_journal":        validateScopedJournal,
}

func validateAsteriskConfigSlice(words []shellWord) bool {
	if len(words) != 4 ||
		words[0].value != "sed" || words[1].value != "-n" ||
		(words[2].quote != '\'' && words[2].quote != '"') || words[2].mixed {
		return false
	}

	expression := words[2].value
	if !strings.HasSuffix(expression, "p") {
		return false
	}
	startText, endText, found := strings.Cut(strings.TrimSuffix(expression, "p"), ",")
	if !found {
		return false
	}
	start, startErr := strconv.ParseUint(startText, 10, 32)
	end, endErr := strconv.ParseUint(endText, 10, 32)
	if startErr != nil || endErr != nil || start == 0 || end < start || end-start >= 1000 {
		return false
	}

	filename := words[3].value
	return cleanPath(filename, false) && filename == "/etc/asterisk/pjsip.endpoint.conf"
}

func validateDiagnosticRead(words []shellWord) bool {
	if len(words) == 0 {
		return false
	}
	switch words[0].value {
	case "ls":
		return validateLS(words[1:])
	case "cat":
		return validateCat(words[1:])
	case "tail":
		return validateTail(words[1:])
	case "grep", "egrep":
		return validateGrep(words[1:])
	case "pgrep":
		return validatePgrep(words[1:])
	default:
		return false
	}
}

func validateLS(arguments []shellWord) bool {
	valueOptions := map[string]bool{
		"--block-size": true, "--color": true, "--format": true,
		"--indicator-style": true, "--quoting-style": true, "--sort": true,
		"--tabsize": true, "--time": true, "--time-style": true, "--width": true,
		"--hide": true, "--ignore": true,
	}
	booleanLong := map[string]bool{
		"--all": true, "--almost-all": true, "--author": true,
		"--classify": true, "--dereference": true, "--directory": true,
		"--escape": true, "--file-type": true, "--group-directories-first": true,
		"--help": true, "--hide-control-chars": true, "--human-readable": true,
		"--ignore-backups": true, "--inode": true, "--literal": true,
		"--numeric-uid-gid": true, "--recursive": true, "--reverse": true,
		"--show-control-chars": true, "--size": true, "--version": true,
	}
	const short = "aAbBcCdDfFgGhHiklLmnopqQrRsStuUvxXZ1"
	operands, ok := parseReadOptions(arguments, short, booleanLong, valueOptions, map[byte]bool{'I': true, 'T': true, 'w': true})
	if !ok {
		return false
	}
	for _, operand := range operands {
		if !cleanPath(operand.value, false) {
			return false
		}
	}
	return true
}

func validateCat(arguments []shellWord) bool {
	booleanLong := map[string]bool{
		"--number": true, "--number-nonblank": true, "--show-all": true,
		"--show-ends": true, "--show-nonprinting": true, "--show-tabs": true,
		"--squeeze-blank": true,
	}
	operands, ok := parseReadOptions(arguments, "AbEeEnstTuv", booleanLong, nil, nil)
	return ok && logOperands(operands)
}

func validateTail(arguments []shellWord) bool {
	var operands []shellWord
	options := true
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index].value
		if options && argument == "--" {
			options = false
			continue
		}
		if options && (argument == "-q" || argument == "--quiet" || argument == "--silent" || argument == "-v" || argument == "--verbose" || argument == "-z" || argument == "--zero-terminated") {
			continue
		}
		if options && (argument == "-n" || argument == "--lines" || argument == "-c" || argument == "--bytes") {
			index++
			if index >= len(arguments) || !tailCount(arguments[index].value) {
				return false
			}
			continue
		}
		if options && (strings.HasPrefix(argument, "--lines=") || strings.HasPrefix(argument, "--bytes=")) {
			_, count, _ := strings.Cut(argument, "=")
			if !tailCount(count) {
				return false
			}
			continue
		}
		if options && len(argument) > 2 && (strings.HasPrefix(argument, "-n") || strings.HasPrefix(argument, "-c")) {
			if !tailCount(argument[2:]) {
				return false
			}
			continue
		}
		if options && strings.HasPrefix(argument, "-") {
			return false
		}
		operands = append(operands, arguments[index])
	}
	return logOperands(operands)
}

func validateGrep(arguments []shellWord) bool {
	operands, ok := parseGrepOperands(arguments)
	return ok && logOperands(operands)
}

func parseGrepOperands(arguments []shellWord) ([]shellWord, bool) {
	booleanShort := "EFGPiwxzsvbHhnoqalLIrRUZ"
	booleanLong := map[string]bool{
		"--basic-regexp": true, "--extended-regexp": true, "--fixed-strings": true,
		"--perl-regexp": true, "--ignore-case": true, "--no-ignore-case": true,
		"--word-regexp": true, "--line-regexp": true, "--null-data": true,
		"--no-messages": true, "--invert-match": true, "--version": true,
		"--byte-offset": true, "--with-filename": true, "--no-filename": true,
		"--line-number": true, "--only-matching": true, "--quiet": true,
		"--silent": true, "--text": true, "--binary": true,
		"--binary-files-without-match": true, "--files-with-matches": true,
		"--files-without-match": true, "--count": true, "--initial-tab": true,
		"--null": true, "--recursive": true, "--dereference-recursive": true,
		"--line-buffered": true, "--unix-byte-offsets": true,
	}
	valueLong := map[string]bool{
		"--regexp": true, "--max-count": true, "--after-context": true,
		"--before-context": true, "--context": true, "--binary-files": true,
		"--devices": true, "--directories": true, "--label": true,
	}
	var operands []shellWord
	patternOptions := 0
	options := true
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index].value
		if options && argument == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(argument, "--") {
			name, attached, hasAttached := strings.Cut(argument, "=")
			if booleanLong[name] {
				if hasAttached {
					return nil, false
				}
				continue
			}
			if !valueLong[name] {
				return nil, false
			}
			value := attached
			if !hasAttached {
				index++
				if index >= len(arguments) {
					return nil, false
				}
				value = arguments[index].value
			}
			if name == "--regexp" {
				patternOptions++
			} else if strings.Contains(name, "context") || name == "--max-count" {
				if !decimal(value, true) {
					return nil, false
				}
			}
			continue
		}
		if options && len(argument) > 1 && argument[0] == '-' {
			for position := 1; position < len(argument); position++ {
				flag := argument[position]
				if flag == 'e' || flag == 'm' || flag == 'A' || flag == 'B' || flag == 'C' || flag == 'd' || flag == 'D' {
					value := argument[position+1:]
					if value == "" {
						index++
						if index >= len(arguments) {
							return nil, false
						}
						value = arguments[index].value
					}
					if flag == 'e' {
						patternOptions++
					} else if flag == 'm' || flag == 'A' || flag == 'B' || flag == 'C' {
						if !decimal(value, true) {
							return nil, false
						}
					}
					position = len(argument)
					continue
				}
				if !strings.ContainsRune(booleanShort, rune(flag)) {
					return nil, false
				}
			}
			continue
		}
		operands = append(operands, arguments[index])
	}
	if patternOptions == 0 {
		if len(operands) < 2 {
			return nil, false
		}
		operands = operands[1:]
	}
	return operands, len(operands) > 0
}

func validateContainerGrep(words []shellWord) bool {
	if len(words) < 9 ||
		words[0].value != "runagent" || words[1].value != "-m" ||
		!cleanLiteral(words[2].value) || words[3].value != "podman" ||
		words[4].value != "exec" || !cleanLiteral(words[5].value) ||
		words[6].value != "grep" {
		return false
	}
	return validateSourceGrep(words[6:])
}

func validateSourceGrep(words []shellWord) bool {
	if len(words) < 3 || words[0].value != "grep" {
		return false
	}
	operands, ok := parseGrepOperands(words[1:])
	if !ok {
		return false
	}
	for _, operand := range operands {
		if !containerGrepPath(operand.value) {
			return false
		}
	}
	return true
}

func containerGrepPath(value string) bool {
	if !cleanPath(value, false) || !path.IsAbs(value) {
		return false
	}
	if pathWithin(value, "/var/log") {
		return true
	}
	if diagnosticSourcePath(value) || value == "/etc/asterisk" || value == "/app/plugins/dbconn/sequelize_models" {
		return true
	}
	return pathWithin(value, "/app") && strings.HasSuffix(value, ".js") ||
		pathWithin(value, "/etc/asterisk") && strings.HasSuffix(value, ".conf")
}

func pathWithin(value, root string) bool {
	return value == root || strings.HasPrefix(value, root+"/")
}

func validatePgrep(arguments []shellWord) bool {
	booleanLong := map[string]bool{
		"--list-full": true, "--full": true, "--list-name": true,
		"--newest": true, "--oldest": true, "--inverse": true,
		"--exact": true, "--count": true, "--ignore-case": true,
		"--lightweight": true, "--ignore-ancestors": true,
	}
	valueLong := map[string]bool{
		"--delimiter": true, "--runstates": true, "--parent": true,
		"--pgroup": true, "--group": true, "--session": true,
		"--terminal": true, "--euid": true, "--uid": true, "--older": true,
	}
	operands, ok := parseReadOptions(arguments, "aflnovxciwA", booleanLong, valueLong, map[byte]bool{
		'd': true, 'r': true, 'P': true, 'g': true, 'G': true,
		's': true, 't': true, 'u': true, 'U': true, 'O': true,
	})
	if !ok || len(operands) != 1 || strings.HasPrefix(operands[0].value, "-") {
		return false
	}
	if operands[0].value != "" && operands[0].quote != 0 && !operands[0].mixed {
		return !strings.ContainsFunc(operands[0].value, unicode.IsControl)
	}
	return cleanLiteral(operands[0].value)
}

// parseReadOptions recognizes options without consulting the target system.
// It returns only positional operands, which callers then constrain by type.
func parseReadOptions(arguments []shellWord, booleanShort string, booleanLong, valueLong map[string]bool, valueShort map[byte]bool) ([]shellWord, bool) {
	var operands []shellWord
	options := true
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index].value
		if options && argument == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(argument, "--") {
			name, _, attached := strings.Cut(argument, "=")
			if booleanLong[name] {
				if attached {
					return nil, false
				}
				continue
			}
			if !valueLong[name] {
				return nil, false
			}
			if !attached {
				index++
				if index >= len(arguments) || !cleanLiteral(arguments[index].value) {
					return nil, false
				}
			}
			continue
		}
		if options && len(argument) > 1 && argument[0] == '-' {
			for position := 1; position < len(argument); position++ {
				flag := argument[position]
				if valueShort[flag] {
					if position+1 == len(argument) {
						index++
						if index >= len(arguments) || !cleanLiteral(arguments[index].value) {
							return nil, false
						}
					}
					position = len(argument)
					continue
				}
				if !strings.ContainsRune(booleanShort, rune(flag)) {
					return nil, false
				}
			}
			continue
		}
		operands = append(operands, arguments[index])
	}
	return operands, true
}

func logOperands(operands []shellWord) bool {
	if len(operands) == 0 {
		return false
	}
	for _, operand := range operands {
		if !cleanPath(operand.value, true) {
			return false
		}
	}
	return true
}

func cleanPath(value string, logsOnly bool) bool {
	if value == "" || value == "-" || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "~") || !cleanLiteral(value) {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return false
		}
	}
	if path.Clean(value) != value {
		return false
	}
	if logsOnly && value != "/var/log" && !strings.HasPrefix(value, "/var/log/") {
		return false
	}
	return !logsOnly || path.IsAbs(value)
}

func cleanLiteral(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) || strings.ContainsRune("*?[]{}~$`\\'\";|&><", character) {
			return false
		}
	}
	return true
}

func tailCount(value string) bool {
	if strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
		value = value[1:]
	}
	return decimal(value, true)
}

func decimal(value string, allowZero bool) bool {
	if value == "" {
		return false
	}
	nonzero := false
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
		if character != '0' {
			nonzero = true
		}
	}
	return allowZero || nonzero
}
