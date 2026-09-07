package policy

import "strings"

func validateRTPengineRead(words []shellWord) bool {
	if len(words) != 8 && len(words) != 10 {
		return false
	}
	for _, word := range words {
		if word.quote != 0 || word.mixed {
			return false
		}
	}
	if words[0].value != "runagent" || words[1].value != "-m" ||
		words[3].value != "podman" || words[4].value != "exec" ||
		words[5].value != "rtpengine" || words[6].value != "rtpengine-ctl" {
		return false
	}
	moduleNumber := strings.TrimPrefix(words[2].value, "nethvoice-proxy")
	if moduleNumber == words[2].value || len(moduleNumber) > 10 || !decimal(moduleNumber, false) {
		return false
	}
	if len(words) == 8 {
		return words[7].value == "--help"
	}
	return words[7].value == "list" && words[8].value == "sessions" && boundedCallID(words[9].value)
}

func boundedCallID(value string) bool {
	if len(value) < 8 || len(value) > 256 || (!asciiLetter(value[0]) && !asciiDigit(value[0])) {
		return false
	}
	hasDigit := asciiDigit(value[0])
	hasNonDigit := !hasDigit
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !asciiLetter(character) && !asciiDigit(character) && !strings.ContainsRune("._:@+-", rune(character)) {
			return false
		}
		hasDigit = hasDigit || asciiDigit(character)
		hasNonDigit = hasNonDigit || !asciiDigit(character)
	}
	return hasDigit && hasNonDigit
}
