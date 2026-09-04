package policy

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type shellWord struct {
	value string
	start int
	end   int
	quote byte
	mixed bool
}

type commandView struct {
	text  string
	words []shellWord
}

// tokenizeShell is classification-only. It records word boundaries from the
// original payload and never produces text for execution.
func tokenizeShell(input string) ([]shellWord, error) {
	if !utf8.ValidString(input) {
		return nil, errors.New("invalid UTF-8")
	}
	for _, character := range input {
		if unicode.IsControl(character) || (unicode.IsSpace(character) && character != ' ') {
			return nil, errors.New("control or non-ASCII whitespace")
		}
	}
	var words []shellWord
	for index := 0; index < len(input); {
		if input[index] == ' ' {
			index++
			continue
		}
		if input[index] < 0x20 || input[index] == 0x7f {
			return nil, errors.New("control character")
		}
		word := shellWord{start: index}
		var value strings.Builder
		quotedSegments := 0
		unquotedSegment := false
		for index < len(input) && input[index] != ' ' {
			ch := input[index]
			if ch < 0x20 || ch == 0x7f {
				return nil, errors.New("control character")
			}
			switch ch {
			case '\'', '"':
				quotedSegments++
				quote := ch
				if word.quote == 0 {
					word.quote = quote
				} else if word.quote != quote {
					word.mixed = true
				}
				index++
				for index < len(input) && input[index] != quote {
					current := input[index]
					if current < 0x20 || current == 0x7f {
						return nil, errors.New("control character")
					}
					if quote == '"' && (current == '`' || current == '\\' || shellExpansionAt(input, index)) {
						return nil, errors.New("expansion or escape in double quote")
					}
					value.WriteByte(current)
					index++
				}
				if index >= len(input) {
					return nil, errors.New("unterminated quote")
				}
				index++
			case ';', '|', '&', '>', '<', '`', '*', '?', '[', '(', ')', '#':
				return nil, errors.New("shell composition or expansion")
			case '~':
				if index == word.start {
					return nil, errors.New("shell expansion")
				}
				unquotedSegment = true
				value.WriteByte(ch)
				index++
			case '$':
				if shellExpansionAt(input, index) {
					return nil, errors.New("shell expansion")
				}
				unquotedSegment = true
				value.WriteByte(ch)
				index++
			case '\\':
				unquotedSegment = true
				word.mixed = true
				index++
				if index >= len(input) || input[index] < 0x20 || input[index] == 0x7f {
					return nil, errors.New("invalid shell escape")
				}
				value.WriteByte(input[index])
				index++
			default:
				unquotedSegment = true
				value.WriteByte(ch)
				index++
			}
		}
		word.end = index
		word.value = value.String()
		if word.value == "" && word.end == word.start {
			return nil, errors.New("empty word")
		}
		// A quote surrounding the whole word is useful to validators that need
		// to distinguish a literal from shell syntax. Adjacent/mixed segments
		// remain valid shell words, but are deliberately marked ambiguous.
		raw := input[word.start:word.end]
		if word.quote != 0 && !(len(raw) >= 2 && raw[0] == word.quote && raw[len(raw)-1] == word.quote) {
			word.mixed = true
		}
		if quotedSegments > 1 || (quotedSegments > 0 && unquotedSegment) {
			word.mixed = true
		}
		words = append(words, word)
	}
	if len(words) == 0 {
		return nil, errors.New("empty command")
	}
	return words, nil
}

func shellExpansionAt(input string, index int) bool {
	if index >= len(input) || input[index] != '$' || index+1 >= len(input) {
		return false
	}
	next := input[index+1]
	return next == '(' || next == '{' || next == '?' || next == '*' || next == '@' ||
		next == '$' || next == '!' || next == '#' || next == '-' || next == '_' ||
		asciiLetter(next) || asciiDigit(next)
}

func commandViews(command string) ([]commandView, error) {
	texts := []string{command}
	if match := runagentView.FindStringSubmatchIndex(command); match != nil {
		inner := command[match[2]:match[3]]
		texts = append(texts, inner)
		if nested := podmanExecView.FindStringSubmatchIndex(inner); nested != nil {
			texts = append(texts, inner[nested[2]:nested[3]])
		}
	}
	views := make([]commandView, 0, len(texts))
	var parseErr error
	for _, text := range texts {
		words, err := tokenizeShell(text)
		views = append(views, commandView{text: text, words: words})
		if parseErr == nil && err != nil {
			parseErr = err
		}
	}
	return views, parseErr
}

var (
	runagentView   = regexp.MustCompile(`^runagent -m [a-zA-Z0-9][a-zA-Z0-9_.-]* (.+)$`)
	podmanExecView = regexp.MustCompile(`^podman exec [a-zA-Z0-9][a-zA-Z0-9_.-]* (.+)$`)
)
