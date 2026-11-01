package extract

import (
	"strings"
	"testing"
	"time"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestExtractTextReportsOneDerivedCoverageMarkerForDenseQuotedArgv(t *testing.T) {
	if testing.Short() {
		t.Skip("maximum-line hostile-input regression")
	}
	prefix := `child_process.spawn([`
	suffix := `])`
	unit := `"x",`
	line := prefix + strings.Repeat(unit, (maxTextAnalysisLineBytes-len(prefix)-len(suffix))/len(unit)) + suffix

	var graph behavior.Graph
	started := time.Now()
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-text-budget",
		LogicalPath: "loader.js",
		Kind:        "script",
		Data:        []byte(line),
	})
	if elapsed := time.Since(started); elapsed > 15*time.Second {
		t.Fatalf("maximum-size quoted argv took %s", elapsed)
	}
	assertOneTextDerivedCoverage(t, graph)
	for _, operation := range graph.Operations {
		if len(operation.RequiredResource().Value) > maxTextDerivedValueBytes {
			t.Fatalf("oversized derived operation resource retained: %d bytes", len(operation.RequiredResource().Value))
		}
	}
}

func TestTextRegexEnumerationsBoundDenseMaximumLine(t *testing.T) {
	if testing.Short() {
		t.Skip("maximum-line hostile-input regression")
	}
	tests := []struct {
		name  string
		input string
		run   func(string, *textLineBudget) int
	}{
		{
			name:  "URLs",
			input: strings.Repeat("https://repeat.example ", maxTextAnalysisLineBytes/23),
			run: func(input string, budget *textLineBudget) int {
				return len(destinationsBudget(input, budget))
			},
		},
		{
			name:  "paths",
			input: strings.Repeat("/tmp/x ", maxTextAnalysisLineBytes/7),
			run: func(input string, budget *textLineBudget) int {
				return len(boundedTextRegexpMatches(rePath, input, "path", budget))
			},
		},
		{
			name:  "file modes",
			input: strings.Repeat("000 ", maxTextAnalysisLineBytes/4),
			run: func(input string, budget *textLineBudget) int {
				if chmodModeInLineMakesExecutableBudget(input, budget) {
					return 1
				}
				return 0
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := newTextDerivedBudget()
			started := time.Now()
			count := test.run(test.input, state.line())
			if elapsed := time.Since(started); elapsed > 2*time.Second {
				t.Fatalf("dense enumeration took %s", elapsed)
			}
			if count > maxTextDerivedMatchesPerLine {
				t.Fatalf("retained %d results, limit %d", count, maxTextDerivedMatchesPerLine)
			}
			if !state.limited {
				t.Fatal("dense enumeration did not record truncation")
			}
		})
	}
}

func TestObjectiveCSelectorAndLiteralFanoutAreBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("maximum-line hostile-input regression")
	}
	t.Run("selector", func(t *testing.T) {
		state := newTextDerivedBudget()
		expr := "self " + strings.Repeat("a:", (maxTextAnalysisLineBytes-5)/2)
		if selector := objectiveCMessageSelectorBudget(expr, state.line()); selector != "" {
			t.Fatalf("truncated selector was interpreted as complete: %d bytes", len(selector))
		}
		if !state.limited || state.matches > maxTextDerivedMatchesPerLine {
			t.Fatalf("selector budget state = %#v", state)
		}
	})

	t.Run("string literals", func(t *testing.T) {
		state := newTextDerivedBudget()
		line := strings.Repeat(`"a"`, maxTextAnalysisLineBytes/3)
		visited := 0
		forEachSourceStringLiteral(line, state.line(), func(string) bool {
			visited++
			return true
		})
		if visited > maxTextDerivedMatchesPerLine {
			t.Fatalf("visited %d literals, limit %d", visited, maxTextDerivedMatchesPerLine)
		}
		if !state.limited {
			t.Fatal("literal fanout did not record truncation")
		}
	})
}

func TestAnalyzeShellLineReportsFieldFanout(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(
		&graph,
		artifact.Content{NodeID: "node-shell-fields", LogicalPath: "loader.sh", Kind: "script"},
		"curl "+strings.Repeat("x ", 4097),
		1,
		unknownExecutionContext(),
		"",
	)
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "shell-analysis" && coverage.Status == "partial" && strings.Contains(coverage.Detail, "argv field") {
			return
		}
	}
	t.Fatalf("missing shell argv partial coverage: %#v", graph.Coverage)
}

func TestAnalyzeShellLineReportsOversizedSensitiveTarget(t *testing.T) {
	target := "/" + strings.Repeat("a", (1<<20)-128) + "/.ssh/id_rsa"
	directState := newTextDerivedBudget()
	directResource, directOK := sensitiveResourceBudget(target, directState.line())
	if !directOK || !directResource.HasClassification(behavior.ResourceClassSSHPrivateKey) || directResource.Value != ".ssh/id_rsa" || !directState.limited {
		t.Fatalf("direct sensitive resource = %#v, ok=%v, budget=%#v", directResource, directOK, directState)
	}
	var graph behavior.Graph
	AnalyzeShellLine(
		&graph,
		artifact.Content{NodeID: "node-shell-sensitive", LogicalPath: "loader.sh", Kind: "script"},
		"cat "+target,
		1,
		unknownExecutionContext(),
		"ev-shell-sensitive",
	)
	foundCoverage := false
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "shell-sensitive-resource-analysis" && coverage.Status == "partial" {
			foundCoverage = true
		}
	}
	if !foundCoverage {
		t.Fatalf("missing sensitive-resource partial coverage: %#v", graph.Coverage)
	}
	if len(graph.Operations) != 1 || !graph.Operations[0].RequiredResource().HasClassification(behavior.ResourceClassSSHPrivateKey) {
		t.Fatalf("sensitive operation = %#v, coverage = %#v, want bounded ssh-private-key operation", graph.Operations, graph.Coverage)
	}
	if len(graph.Operations[0].RequiredResource().Value) > maxTextDerivedValueBytes {
		t.Fatalf("sensitive resource retained %d bytes", len(graph.Operations[0].RequiredResource().Value))
	}
}

func assertOneTextDerivedCoverage(t *testing.T, graph behavior.Graph) {
	t.Helper()
	count := 0
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea != "text-derived-analysis" {
			continue
		}
		count++
		if coverage.Status != "partial" || !strings.Contains(coverage.Detail, "limit") {
			t.Fatalf("unexpected derived coverage: %#v", coverage)
		}
	}
	if count != 1 {
		t.Fatalf("text-derived-analysis coverage count = %d, want 1: %#v", count, graph.Coverage)
	}
}
