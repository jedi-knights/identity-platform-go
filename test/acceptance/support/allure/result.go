// Package allure implements a godog formatter that writes one Allure
// result-file per scenario, so the acceptance suite's pass/fail matrix can
// be browsed as an Allure report instead of only console output. See
// NewFormatter's doc comment for how it plugs into godog, and
// ALLURE_RESULTS_DIR for where results land on disk.
package allure

import "time"

// Result is the subset of Allure's result-file schema this formatter
// populates. See https://allurereport.org/docs/how-it-works-test-result/
// for the full schema — fields not listed here (attachments, parameters,
// links, testCaseId) are left at their zero value and simply omitted or
// ignored by Allure.
type Result struct {
	UUID        string  `json:"uuid"`
	HistoryID   string  `json:"historyId"`
	Name        string  `json:"name"`
	FullName    string  `json:"fullName"`
	Description string  `json:"description,omitempty"`
	Status      string  `json:"status"`
	Stage       string  `json:"stage"`
	Steps       []Step  `json:"steps"`
	Labels      []Label `json:"labels,omitempty"`
	Start       int64   `json:"start"`
	Stop        int64   `json:"stop"`
}

// Step is one Gherkin step rendered as an Allure step.
type Step struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Stage  string `json:"stage"`
	Start  int64  `json:"start"`
	Stop   int64  `json:"stop"`
}

// Label attaches Allure's grouping/filtering metadata (feature, suite, tag)
// to a result.
type Label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Allure statuses. "broken" is Allure's term for a test that errored before
// or outside a plain assertion failure — godog's undefined/pending/
// ambiguous step outcomes all map here since none of them are a clean
// pass/fail/skip.
const (
	StatusPassed  = "passed"
	StatusFailed  = "failed"
	StatusBroken  = "broken"
	StatusSkipped = "skipped"
	StatusUnknown = "unknown"
)

const stageFinished = "finished"

// statusSeverity ranks Allure statuses from most to least severe. A
// scenario's overall status is the most severe status among its steps —
// one failed step fails the whole scenario even if every other step
// passed.
var statusSeverity = map[string]int{
	StatusFailed:  0,
	StatusBroken:  1,
	StatusUnknown: 2,
	StatusSkipped: 3,
	StatusPassed:  4,
}

// worstStatus returns the most severe of the given statuses, per
// statusSeverity. Returns StatusUnknown for an empty input — a scenario
// with no recorded steps is unexpected rather than passing by default.
func worstStatus(statuses []string) string {
	worst := StatusUnknown
	first := true

	for _, s := range statuses {
		if first {
			worst = s
			first = false
			continue
		}
		if statusSeverity[s] < statusSeverity[worst] {
			worst = s
		}
	}

	return worst
}

// epochMillis converts t to the millisecond-epoch timestamp Allure's
// result schema expects for start/stop fields.
func epochMillis(t time.Time) int64 {
	return t.UnixMilli()
}
