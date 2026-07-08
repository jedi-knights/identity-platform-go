package allure

import (
	"fmt"
	"io"
	"testing"

	"github.com/cucumber/godog/formatters"
	messages "github.com/cucumber/messages/go/v21"
)

func newTestFormatter(t *testing.T) *Formatter {
	t.Helper()

	f, ok := NewFormatter("test", io.Discard).(*Formatter)
	if !ok {
		t.Fatalf("NewFormatter did not return *Formatter")
	}
	return f
}

// stepFixture describes one Gherkin step at both the AST level (keyword,
// as actually written in a .feature file) and the pickle level (the
// compiled step godog's runner sees) — sharing an ID between the two,
// mirroring how godog's real Gherkin compiler links PickleStep.AstNodeIds
// back to the Step it was compiled from.
type stepFixture struct {
	keyword string
	text    string
}

// buildFixture builds a matching (GherkinDocument, Pickle) pair for one
// scenario, so tests can drive the Formatter's callbacks exactly as
// godog's runner would and verify keyword resolution comes from the AST,
// not from the (Given/When/Then-registration-only) StepDefinition.Keyword.
func buildFixture(featureName, comment, scenarioName string, steps []stepFixture) (*messages.GherkinDocument, *messages.Pickle) {
	astSteps := make([]*messages.Step, len(steps))
	pickleSteps := make([]*messages.PickleStep, len(steps))

	for i, s := range steps {
		id := fmt.Sprintf("step-%d", i)
		astSteps[i] = &messages.Step{Id: id, Keyword: s.keyword, Text: s.text}
		pickleSteps[i] = &messages.PickleStep{Id: id + "-pickle", AstNodeIds: []string{id}, Text: s.text}
	}

	doc := &messages.GherkinDocument{
		Feature: &messages.Feature{
			Name: featureName,
			Children: []*messages.FeatureChild{
				{Scenario: &messages.Scenario{Name: scenarioName, Steps: astSteps}},
			},
		},
	}
	if comment != "" {
		doc.Comments = []*messages.Comment{{Text: "# " + comment}}
	}

	pickle := &messages.Pickle{Id: "pickle-1", Uri: "widgets.feature", Name: scenarioName, Steps: pickleSteps}

	return doc, pickle
}

func TestFormatter_BuildResults_AllStepsPassed(t *testing.T) {
	// Arrange
	f := newTestFormatter(t)
	doc, pickle := buildFixture("Widgets", "RFC 1234 — widget lifecycle", "Create a widget", []stepFixture{
		{keyword: "Given ", text: "a widget exists"},
		{keyword: "When ", text: "I create it"},
		{keyword: "Then ", text: "it should be created"},
	})
	f.Feature(doc, pickle.Uri, nil)
	f.Pickle(pickle)

	for _, step := range pickle.Steps {
		def := &formatters.StepDefinition{} // Keyword is always None — see stepWithKeyword's doc comment in godog.
		f.Defined(pickle, step, def)
		f.Passed(pickle, step, def)
	}

	// Act
	results := f.buildResults()

	// Assert
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	r := results[0]
	if r.Status != StatusPassed {
		t.Errorf("Status = %q, want %q", r.Status, StatusPassed)
	}
	if r.Description != "RFC 1234 — widget lifecycle" {
		t.Errorf("Description = %q, want the joined feature comment", r.Description)
	}
	assertStepNames(t, r.Steps, "Given a widget exists", "When I create it", "Then it should be created")
	assertAllStepsHaveStatus(t, r.Steps, StatusPassed)
}

func assertStepNames(t *testing.T, steps []Step, want ...string) {
	t.Helper()

	if len(steps) != len(want) {
		t.Fatalf("len(steps) = %d, want %d", len(steps), len(want))
	}
	for i, name := range want {
		if steps[i].Name != name {
			t.Errorf("Steps[%d].Name = %q, want %q", i, steps[i].Name, name)
		}
	}
}

func assertAllStepsHaveStatus(t *testing.T, steps []Step, want string) {
	t.Helper()

	for _, s := range steps {
		if s.Status != want {
			t.Errorf("step %q status = %q, want %q", s.Name, s.Status, want)
		}
	}
}

func TestFormatter_BuildResults_FailedStepFailsScenario(t *testing.T) {
	// Arrange
	f := newTestFormatter(t)
	doc, pickle := buildFixture("Widgets", "", "Create a widget fails", []stepFixture{
		{keyword: "Given ", text: "a widget exists"},
		{keyword: "When ", text: "I create it badly"},
		{keyword: "Then ", text: "it should be created"},
	})
	f.Feature(doc, pickle.Uri, nil)
	f.Pickle(pickle)

	def := &formatters.StepDefinition{}

	f.Defined(pickle, pickle.Steps[0], def)
	f.Passed(pickle, pickle.Steps[0], def)

	f.Defined(pickle, pickle.Steps[1], def)
	f.Failed(pickle, pickle.Steps[1], def, fmt.Errorf("boom"))

	f.Skipped(pickle, pickle.Steps[2], nil)

	// Act
	results := f.buildResults()

	// Assert
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	r := results[0]
	if r.Status != StatusFailed {
		t.Errorf("Status = %q, want %q", r.Status, StatusFailed)
	}
	if r.Steps[1].Status != StatusFailed {
		t.Errorf("Steps[1].Status = %q, want %q", r.Steps[1].Status, StatusFailed)
	}
	if r.Steps[2].Status != StatusSkipped {
		t.Errorf("Steps[2].Status = %q, want %q", r.Steps[2].Status, StatusSkipped)
	}
}

func TestFormatter_BuildResults_UndefinedStepIsBroken(t *testing.T) {
	// Arrange
	f := newTestFormatter(t)
	doc, pickle := buildFixture("Widgets", "", "Undefined step", []stepFixture{
		{keyword: "Given ", text: "a step nobody wrote"},
	})
	f.Feature(doc, pickle.Uri, nil)
	f.Pickle(pickle)

	f.Undefined(pickle, pickle.Steps[0], nil)

	// Act
	results := f.buildResults()

	// Assert
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	r := results[0]
	if r.Status != StatusBroken {
		t.Errorf("Status = %q, want %q", r.Status, StatusBroken)
	}
	if r.Steps[0].Name != "Given a step nobody wrote" {
		t.Errorf("Steps[0].Name = %q, want the AST keyword prefix even though Defined never fired", r.Steps[0].Name)
	}
	if r.Steps[0].Status != StatusBroken {
		t.Errorf("Steps[0].Status = %q, want %q", r.Steps[0].Status, StatusBroken)
	}
}
