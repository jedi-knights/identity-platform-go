package allure

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cucumber/godog"
	"github.com/cucumber/godog/formatters"
	messages "github.com/cucumber/messages/go/v21"
)

func init() {
	godog.Format("allure", "Produces one Allure result-file per scenario (see ALLURE_RESULTS_DIR).", NewFormatter)
}

// resultsDirEnv names the environment variable that selects where Allure
// result files are written. `task test:acceptance:report` points `allure
// generate` at this same directory, so the two must agree — see
// resultsDir.
const resultsDirEnv = "ALLURE_RESULTS_DIR"

const defaultResultsDir = "allure-results"

// NewFormatter builds a godog formatters.Formatter that records one Allure
// result per scenario. Allure's schema is one JSON file per test case
// rather than a single output stream, so — unlike godog's built-in
// formatters — the io.Writer passed in is used only for this formatter's
// own diagnostics; Summary is where results are actually written to
// resultsDir().
func NewFormatter(suite string, out io.Writer) formatters.Formatter {
	return &Formatter{
		suite:    suite,
		out:      out,
		features: map[string]*featureInfo{},
		runs:     map[string]*pickleRun{},
	}
}

// featureInfo holds the per-feature data every scenario in that feature
// needs: its name (for Allure's feature/suite labels), the RFC/ADR header
// comment above `Feature:` (attached as each scenario's description, so
// the generated report doubles as a compliance matrix), and a lookup from
// Gherkin AST step ID to that step's literal keyword ("Given "/"And "/
// etc.) — see stepKeywords's doc comment for why this, not
// formatters.StepDefinition.Keyword, is the correct source.
type featureInfo struct {
	name        string
	description string
	keywords    map[string]string
}

// stepRun accumulates one Gherkin step's outcome as godog's callbacks
// fire. text comes from Defined (or, for steps that never match, straight
// from the PickleStep itself); status/errMsg/stop come from whichever
// terminal callback fires (Passed, Failed, Skipped, ...). The step's
// keyword is resolved separately at build time from featureInfo.keywords,
// not stored here.
type stepRun struct {
	text   string
	status string
	errMsg string
	start  time.Time
	stop   time.Time
}

// pickleRun accumulates one scenario's outcome: the pickle itself (for its
// name, tags, and step order) plus each step's stepRun, keyed by
// PickleStep ID.
type pickleRun struct {
	pickle *messages.Pickle
	steps  map[string]*stepRun
	start  time.Time
}

// Formatter implements godog's formatters.Formatter, buffering every
// scenario and step result in memory as the suite runs and writing one
// Allure result-file per scenario in Summary — see NewFormatter's doc
// comment for why Allure's schema requires this instead of a streaming
// write.
type Formatter struct {
	suite string
	out   io.Writer

	mu       sync.Mutex
	features map[string]*featureInfo // keyed by pickle URI
	runs     map[string]*pickleRun   // keyed by pickle ID
	order    []string                // pickle IDs in first-seen order
}

var _ formatters.Formatter = (*Formatter)(nil)

// TestRunStarted is part of the formatters.Formatter interface; this
// formatter needs no suite-level setup.
func (f *Formatter) TestRunStarted() {}

// Feature receives the parsed Gherkin document for one .feature file,
// including its header comments — see featureInfo's doc comment.
func (f *Formatter) Feature(doc *messages.GherkinDocument, uri string, _ []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.features[uri] = &featureInfo{
		name:        doc.Feature.Name,
		description: joinComments(doc.Comments),
		keywords:    stepKeywords(doc.Feature),
	}
}

// stepKeywords maps every step's Gherkin AST ID to its literal keyword
// ("Given ", "And ", "But ", ...). This is read from the AST rather than
// formatters.StepDefinition.Keyword because every step definition in this
// suite is registered via ScenarioContext.Step (not .Given/.When/.Then),
// which godog always records as Keyword: None — the AST is the only place
// the keyword actually written in the .feature file survives.
func stepKeywords(feature *messages.Feature) map[string]string {
	keywords := map[string]string{}
	for _, child := range feature.Children {
		if child.Background != nil {
			addStepKeywords(keywords, child.Background.Steps)
		}
		if child.Scenario != nil {
			addStepKeywords(keywords, child.Scenario.Steps)
		}
	}
	return keywords
}

func addStepKeywords(keywords map[string]string, steps []*messages.Step) {
	for _, s := range steps {
		if trimmed := strings.TrimSpace(s.Keyword); trimmed != "" {
			keywords[s.Id] = trimmed + " "
		}
	}
}

// Pickle receives one scenario (or one Scenario Outline row) about to run.
func (f *Formatter) Pickle(pickle *messages.Pickle) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.runs[pickle.Id] = &pickleRun{
		pickle: pickle,
		steps:  map[string]*stepRun{},
		start:  time.Now(),
	}
	f.order = append(f.order, pickle.Id)
}

// Defined fires when a step matches a registered step definition, before
// it executes — this is where the step's start time is recorded. It does
// not fire for undefined steps.
func (f *Formatter) Defined(pickle *messages.Pickle, step *messages.PickleStep, _ *formatters.StepDefinition) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.stepRun(pickle, step).start = time.Now()
}

// Passed captures a step that ran and asserted successfully.
func (f *Formatter) Passed(pickle *messages.Pickle, step *messages.PickleStep, _ *formatters.StepDefinition) {
	f.finishStep(pickle, step, StatusPassed, "")
}

// Failed captures a step whose handler returned an error.
func (f *Formatter) Failed(pickle *messages.Pickle, step *messages.PickleStep, _ *formatters.StepDefinition, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	f.finishStep(pickle, step, StatusFailed, msg)
}

// Skipped captures a step godog never attempted, typically because an
// earlier step in the same scenario already failed.
func (f *Formatter) Skipped(pickle *messages.Pickle, step *messages.PickleStep, _ *formatters.StepDefinition) {
	f.finishStep(pickle, step, StatusSkipped, "")
}

// Undefined captures a step with no matching step definition.
func (f *Formatter) Undefined(pickle *messages.Pickle, step *messages.PickleStep, _ *formatters.StepDefinition) {
	f.finishStep(pickle, step, StatusBroken, "no matching step definition")
}

// Pending captures a step definition that explicitly returned
// godog.ErrPending.
func (f *Formatter) Pending(pickle *messages.Pickle, step *messages.PickleStep, _ *formatters.StepDefinition) {
	f.finishStep(pickle, step, StatusBroken, "step definition pending")
}

// Ambiguous captures a step matching more than one registered step
// definition.
func (f *Formatter) Ambiguous(pickle *messages.Pickle, step *messages.PickleStep, _ *formatters.StepDefinition, err error) {
	msg := "ambiguous step definition"
	if err != nil {
		msg = err.Error()
	}
	f.finishStep(pickle, step, StatusBroken, msg)
}

// finishStep records a step's terminal outcome. Callers are godog's
// per-step callbacks, each invoked exactly once per step per scenario run.
func (f *Formatter) finishStep(pickle *messages.Pickle, step *messages.PickleStep, status, errMsg string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	run := f.stepRun(pickle, step)
	run.status = status
	run.errMsg = errMsg
	run.stop = time.Now()
	if run.start.IsZero() {
		run.start = run.stop
	}
}

// stepRun returns the in-flight stepRun for the given pickle step,
// creating it on first access — Defined does not fire for steps that
// never match, so a terminal callback (e.g. Undefined) may be the first
// touch. Callers must hold f.mu.
func (f *Formatter) stepRun(pickle *messages.Pickle, step *messages.PickleStep) *stepRun {
	run := f.runs[pickle.Id]
	s, ok := run.steps[step.Id]
	if !ok {
		s = &stepRun{text: step.Text}
		run.steps[step.Id] = s
	}
	return s
}

// joinComments concatenates a feature's header comments (the RFC/ADR
// description block godog preserves above `Feature:`) into one
// description string, stripping the leading `#` and surrounding
// whitespace from each line.
func joinComments(comments []*messages.Comment) string {
	lines := make([]string, 0, len(comments))
	for _, c := range comments {
		lines = append(lines, strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(c.Text), "#")))
	}
	return strings.Join(lines, "\n")
}

// Summary writes one Allure result-file per scenario to resultsDir(),
// creating the directory if needed. This is Allure's actual write point —
// see NewFormatter's doc comment for why.
func (f *Formatter) Summary() {
	f.mu.Lock()
	results := f.buildResults()
	f.mu.Unlock()

	dir := resultsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		_, _ = fmt.Fprintf(f.out, "allure: creating results dir %s: %v\n", dir, err)
		return
	}

	for _, r := range results {
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintf(f.out, "allure: marshaling result %s: %v\n", r.UUID, err)
			continue
		}

		path := filepath.Join(dir, r.UUID+"-result.json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			_, _ = fmt.Fprintf(f.out, "allure: writing %s: %v\n", path, err)
		}
	}

	_, _ = fmt.Fprintf(f.out, "allure: wrote %d result(s) to %s\n", len(results), dir)
}

// buildResults assembles one Result per pickle, in first-seen order.
// Split out from Summary so tests can exercise it directly without
// touching the filesystem. Callers must hold f.mu (Summary does; tests
// construct a Formatter no other goroutine touches).
func (f *Formatter) buildResults() []Result {
	results := make([]Result, 0, len(f.order))

	for _, id := range f.order {
		results = append(results, f.buildResult(f.runs[id]))
	}

	return results
}

func (f *Formatter) buildResult(run *pickleRun) Result {
	feature := f.features[run.pickle.Uri]
	if feature == nil {
		feature = &featureInfo{}
	}

	steps, statuses, start, stop := buildSteps(run, feature)

	return Result{
		UUID:        uuid.NewString(),
		HistoryID:   feature.name + "/" + run.pickle.Name,
		Name:        run.pickle.Name,
		FullName:    feature.name + ": " + run.pickle.Name,
		Description: feature.description,
		Status:      worstStatus(statuses),
		Stage:       stageFinished,
		Steps:       steps,
		Labels:      buildLabels(feature, run.pickle),
		Start:       epochMillis(start),
		Stop:        epochMillis(stop),
	}
}

// buildSteps renders every step of run in pickle order, alongside the
// scenario-level status list (one per step, for worstStatus) and the
// overall start/stop bounds (the earliest step start and latest step
// stop) used for the scenario's own Start/Stop fields. Each step's
// keyword is resolved from feature.keywords via the pickle step's AST
// node ID — see stepKeywords's doc comment for why.
func buildSteps(run *pickleRun, feature *featureInfo) (steps []Step, statuses []string, start, stop time.Time) {
	steps = make([]Step, 0, len(run.pickle.Steps))
	statuses = make([]string, 0, len(run.pickle.Steps))
	start, stop = run.start, run.start

	for _, ps := range run.pickle.Steps {
		sr, ok := run.steps[ps.Id]
		if !ok {
			sr = &stepRun{text: ps.Text}
		}
		status := orUnknown(sr.status)

		steps = append(steps, Step{
			Name:   keywordFor(feature, ps) + sr.text,
			Status: status,
			Stage:  stageFinished,
			Start:  epochMillis(sr.start),
			Stop:   epochMillis(sr.stop),
		})
		statuses = append(statuses, status)

		start, stop = expandBounds(start, stop, sr)
	}

	return steps, statuses, start, stop
}

func keywordFor(feature *featureInfo, ps *messages.PickleStep) string {
	if len(ps.AstNodeIds) == 0 {
		return ""
	}
	return feature.keywords[ps.AstNodeIds[0]]
}

// expandBounds widens [start, stop] to include sr's own start/stop, if
// sr recorded a non-zero start (a step godog never touched, e.g. one
// dropped from an interrupted run, contributes nothing).
func expandBounds(start, stop time.Time, sr *stepRun) (time.Time, time.Time) {
	if !sr.start.IsZero() && (start.IsZero() || sr.start.Before(start)) {
		start = sr.start
	}
	if sr.stop.After(stop) {
		stop = sr.stop
	}
	return start, stop
}

func buildLabels(feature *featureInfo, pickle *messages.Pickle) []Label {
	labels := []Label{
		{Name: "feature", Value: feature.name},
		{Name: "suite", Value: feature.name},
	}
	for _, tag := range pickle.Tags {
		labels = append(labels, Label{Name: "tag", Value: tag.Name})
	}
	return labels
}

func orUnknown(status string) string {
	if status == "" {
		return StatusUnknown
	}
	return status
}

func resultsDir() string {
	if v := os.Getenv(resultsDirEnv); v != "" {
		return v
	}
	return defaultResultsDir
}
