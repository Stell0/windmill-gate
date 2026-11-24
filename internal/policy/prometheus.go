package policy

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	prometheusLabel  = "[a-zA-Z0-9_][a-zA-Z0-9_-]{0,31}"
	prometheusWindow = `\[(?:[1-9]|1[0-5])m\]`
	prometheusEpoch  = `(?: @ [1-9][0-9]{9})?`
	prometheusUTC    = `[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z`
)

var (
	prometheusModule = regexp.MustCompile(`^metrics[1-9][0-9]{0,8}$`)
	prometheusStart  = regexp.MustCompile("^--start=(" + prometheusUTC + ")$")
	prometheusEnd    = regexp.MustCompile("^--end=(" + prometheusUTC + ")$")
	prometheusStep   = regexp.MustCompile(`^--step=([1-9][0-9]{0,2})s$`)

	// Discovery uses instant queries over the selectors reviewed in the incident.
	prometheusDiscovery = regexp.MustCompile(`^(?:count by \(job\) \(up\)|count by \(__name__\) \(\{__name__=~"(?:\.\*\(cpu\|load\|disk_io\|mysql\|maria\|cdr\|cti\|mem_avail\)\.\*|ns8_container_\.\*\|node_disk_\.\*_total)"\}\))$`)
	prometheusTop       = regexp.MustCompile(`^topk\((?:[1-9]|10), *rate\(ns8_container_(?:cpu_seconds|blkio_bytes)_total` + prometheusWindow + prometheusEpoch + `\)\)$`)

	prometheusContainerCPU = regexp.MustCompile(`^sum by \(container\) \(rate\(ns8_container_cpu_seconds_total\{container=~"` +
		prometheusLabel + `(?:\|` + prometheusLabel + `){0,7}"\}` + prometheusWindow + `\)\)$`)
	prometheusDiskBusy = regexp.MustCompile(`^100 *\* *max\(rate\(node_disk_io_time_seconds_total(?:\{device="` + prometheusLabel + `"\})?` + prometheusWindow + `\)\)$`)
	prometheusDiskRead = regexp.MustCompile(`^max\(rate\((?:node_disk_read_bytes_total\{device="` + prometheusLabel +
		`"|ns8_container_blkio_bytes_total\{container="` + prometheusLabel + `",device="` + prometheusLabel + `",op="(?:read|write)")\}` + prometheusWindow + `\)\) */ *1048576$`)
	prometheusNodeCPU = regexp.MustCompile(`^100 *\* *(?:\(1 *- *avg\(rate\(node_cpu_seconds_total\{mode="idle"\}` +
		prometheusWindow + `\)\)\)|avg\(rate\(node_cpu_seconds_total\{mode="iowait"\}` + prometheusWindow + `\)\))$`)
	prometheusMemory  = regexp.MustCompile(`^min\(node_memory_MemAvailable_bytes\) */ *1073741824$`)
	prometheusMeasure = regexp.MustCompile(`^label_replace\((.+), *"measure", *"([a-z][a-z0-9_]{0,31})", *"", *""\)$`)
)

func validatePrometheusQuery(words []shellWord) bool {
	if (len(words) != 11 && len(words) != 14) ||
		words[0].value != "runagent" || words[1].value != "-m" || !prometheusModule.MatchString(words[2].value) ||
		words[3].value != "podman" || words[4].value != "exec" || words[5].value != "prometheus" ||
		words[6].value != "promtool" || words[7].value != "query" {
		return false
	}
	rangeQuery := words[8].value == "range"
	if rangeQuery {
		if len(words) != 14 || !validPrometheusRange(words[9:12]) {
			return false
		}
	} else if words[8].value != "instant" || len(words) != 11 {
		return false
	}

	for _, word := range words[:len(words)-1] {
		if word.quote != 0 || word.mixed {
			return false
		}
	}
	url, expression := words[len(words)-2].value, words[len(words)-1]
	if (url != "http://127.0.0.1:9090" && url != "http://127.0.0.1:9091") ||
		expression.quote != '\'' || expression.mixed || len(expression.value) > 768 {
		return false
	}
	if !rangeQuery && (prometheusDiscovery.MatchString(expression.value) || prometheusTop.MatchString(expression.value)) {
		return true
	}
	if prometheusContainerCPU.MatchString(expression.value) || prometheusHostMetric(expression.value) {
		return true
	}

	measures := strings.Split(expression.value, " or ")
	if len(measures) > 3 {
		return false
	}
	names := make(map[string]bool, len(measures))
	for _, measure := range measures {
		match := prometheusMeasure.FindStringSubmatch(measure)
		if match == nil || names[match[2]] || !prometheusHostMetric(match[1]) {
			return false
		}
		names[match[2]] = true
	}
	return true
}

func prometheusHostMetric(expression string) bool {
	return prometheusDiskBusy.MatchString(expression) || prometheusDiskRead.MatchString(expression) ||
		prometheusNodeCPU.MatchString(expression) || prometheusMemory.MatchString(expression)
}

func validPrometheusRange(words []shellWord) bool {
	startText := prometheusStart.FindStringSubmatch(words[0].value)
	endText := prometheusEnd.FindStringSubmatch(words[1].value)
	stepText := prometheusStep.FindStringSubmatch(words[2].value)
	if startText == nil || endText == nil || stepText == nil {
		return false
	}
	start, startErr := time.Parse(time.RFC3339, startText[1])
	end, endErr := time.Parse(time.RFC3339, endText[1])
	step, _ := strconv.Atoi(stepText[1])
	window := end.Sub(start)
	return startErr == nil && endErr == nil && window > 0 && window <= 6*time.Hour && step >= 30
}
