package extract

import (
	"fmt"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestRunModelsGeminiSessionStartHookAsConditionalHostSelection(t *testing.T) {
	artifacts, contents, configID, targetID := projectConfigFixture(
		"sample/.gemini/settings.json",
		`{"hooks":{"SessionStart":[{"matcher":"startup","sequential":true,"hooks":[{"type":"command","name":"setup","command":"node scripts/start.mjs"}]}]}}`,
		"sample/scripts/start.mjs",
		"fetch('https://must-not-inherit.invalid/p');\n",
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("Gemini roots = %#v", graph.ExecutionRoots)
	}
	root := graph.ExecutionRoots[0]
	if root.Kind != geminiSessionStartRootKind || root.DeclarationNodeID != configID || root.Interpreter != "" || root.StartNodeID != "" {
		t.Fatalf("Gemini SessionStart root = %#v", root)
	}
	if invokedTargetForNode(graph.InvokedTargets, targetID) != nil {
		t.Fatalf("session-cwd-relative Gemini command was promoted to project target: %#v", graph.InvokedTargets)
	}
	if !hasConnectedOperationForNode(graph.Operations, configID, root.ID, behavior.OperationInterpreterInvoke) {
		t.Fatalf("Gemini hook command was not retained: %#v", graph.Operations)
	}
	for _, gate := range []string{"compatible Gemini CLI version", "settings precedence", "project-folder trust", "startup/resume/clear", "session working directory", "host-selected shell", "session occurrence"} {
		if !coverageContains(graph.Coverage, configID, geminiSessionStartAnalysisArea, gate) {
			t.Fatalf("Gemini gate %q missing: %#v", gate, graph.Coverage)
		}
	}
	if err := graph.Sort(); err != nil {
		t.Fatalf("Gemini graph references: %v", err)
	}
}

func TestRunGeminiSessionStartAbsentMatcherRetainsDocumentedSources(t *testing.T) {
	artifacts, contents, _, _ := projectConfigFixture(
		"sample/.gemini/settings.json",
		`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"true"}]}]}}`,
		"sample/inert.txt",
		"inert",
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if len(graph.ExecutionRoots) != 1 || !evidenceHasValue(graph.Evidence, graph.ExecutionRoots[0].EvidenceIDs[0], "sources=startup|resume|clear") {
		t.Fatalf("Gemini default lifecycle sources lost: roots=%#v evidence=%#v", graph.ExecutionRoots, graph.Evidence)
	}
}

func TestRunGeminiSessionStartCloseNegativesFailClosed(t *testing.T) {
	tests := []struct {
		name     string
		settings string
		detail   string
	}{
		{name: "regex matcher", settings: `{"hooks":{"SessionStart":[{"matcher":"start.*","hooks":[{"type":"command","command":"true"}]}]}}`, detail: "exact documented source"},
		{name: "wildcard matcher", settings: `{"hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"true"}]}]}}`, detail: "exact documented source"},
		{name: "prompt handler", settings: `{"hooks":{"SessionStart":[{"hooks":[{"type":"prompt","command":"true"}]}]}}`, detail: `type "prompt" is not modeled`},
		{name: "dynamic command", settings: `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"$ENTRY"}]}]}}`, detail: ""},
		{name: "malformed sequential", settings: `{"hooks":{"SessionStart":[{"sequential":"yes","hooks":[{"type":"command","command":"true"}]}]}}`, detail: "sequential is not a boolean"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts, contents, configID, _ := projectConfigFixture("sample/.gemini/settings.json", test.settings, "sample/inert.txt", "inert")
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			if test.name == "dynamic command" {
				// The host still selects a shell command, but shell expansion is not
				// resolved to a concrete executable or target.
				if len(graph.ExecutionRoots) != 1 {
					t.Fatalf("dynamic command semantics = roots %#v operations %#v", graph.ExecutionRoots, graph.Operations)
				}
				for _, operation := range graph.Operations {
					if operation.Kind == behavior.OperationProcessExecute && operation.RequiredResource().Value != "" {
						t.Fatalf("dynamic executable became concrete: %#v", operation)
					}
				}
				return
			}
			if len(graph.ExecutionRoots) != 0 {
				t.Fatalf("close negative emitted roots: %#v", graph.ExecutionRoots)
			}
			if test.detail != "" && !coverageContains(graph.Coverage, configID, geminiSessionStartAnalysisArea, test.detail) {
				t.Fatalf("coverage %q missing: %#v", test.detail, graph.Coverage)
			}
		})
	}
}

func TestRunGeminiSessionStartHooksAreBoundedAndDeterministic(t *testing.T) {
	var settings strings.Builder
	settings.WriteString(`{"hooks":{"SessionStart":[`)
	for index := 0; index < maxProjectConfigCommands+4; index++ {
		if index > 0 {
			settings.WriteByte(',')
		}
		fmt.Fprintf(&settings, `{"matcher":"startup","hooks":[{"type":"command","command":"true %d"}]}`, index)
	}
	settings.WriteString(`]}}`)
	artifacts, contents, configID, _ := projectConfigFixture("sample/.gemini/settings.json", settings.String(), "sample/inert.txt", "inert")
	first := Run(Context{Artifacts: &artifacts, Contents: contents})
	second := Run(Context{Artifacts: &artifacts, Contents: contents})
	if len(first.ExecutionRoots) != maxProjectConfigCommands || len(second.ExecutionRoots) != maxProjectConfigCommands {
		t.Fatalf("bounded roots = %d and %d", len(first.ExecutionRoots), len(second.ExecutionRoots))
	}
	if !coverageContains(first.Coverage, configID, geminiSessionStartAnalysisArea, fmt.Sprintf("limit %d reached", maxProjectConfigCommands)) {
		t.Fatalf("Gemini hook limit not explicit: %#v", first.Coverage)
	}
	if fmt.Sprintf("%#v", first.ExecutionRoots) != fmt.Sprintf("%#v", second.ExecutionRoots) {
		t.Fatal("Gemini hook planning is nondeterministic")
	}
}
