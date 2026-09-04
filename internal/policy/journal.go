package policy

import (
	"strconv"
	"strings"
	"time"
)

func validateUIDJournal(words []shellWord) bool {
	if len(words) != 9 || words[0].value != "journalctl" ||
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
	return ok && !until.Before(since)
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
