package extract

import (
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestExtractTextMasksPythonTripleQuotedDecoysAndResumesAfterClose(t *testing.T) {
	source := `description = """
import subprocess
subprocess.run(["/bin/false"])
requests.get("https://triple-decoy.example/payload")
"""
import subprocess
subprocess.run(["/bin/echo"])
import requests
requests.get("https://after-triple.example/payload")
`
	graph := extractPythonMultilineFixture("import requests\n" + source)

	assertNetworkDestinationAbsent(t, graph, "https://triple-decoy.example/payload")
	assertShellCommandNetwork(t, graph, "https://after-triple.example/payload")
	assertOperation(t, graph, behavior.OperationProcessExecute, "file", "/bin/echo")
	for _, operation := range graph.Operations {
		if testOperationHasResource(operation, "file", "/bin/false") {
			t.Fatalf("triple-quoted subprocess decoy became an operation: %#v", operation)
		}
	}
	if hasPartialCoverageScope(graph.Coverage, "python-multiline-string-analysis") {
		t.Fatalf("a completely masked ordinary triple-quoted string should not be partial: %#v", graph.Coverage)
	}
}

func TestExtractTextPreservesCodeAfterPythonTripleQuoteClose(t *testing.T) {
	source := `description = """
requests.get("https://interior-decoy.example/payload")
"""; requests.get("https://same-line-suffix.example/payload")
`
	graph := extractPythonMultilineFixture("import requests\n" + source)

	assertNetworkDestinationAbsent(t, graph, "https://interior-decoy.example/payload")
	assertShellCommandNetwork(t, graph, "https://same-line-suffix.example/payload")
}

func TestExtractTextIgnoresTripleQuoteMarkersInsidePythonStringsAndComments(t *testing.T) {
	source := `marker = "\"\"\""
# """ is documentation syntax, not an opener here
import subprocess
subprocess.run(["/bin/echo"])
`
	graph := extractPythonMultilineFixture(source)

	assertOperation(t, graph, behavior.OperationProcessExecute, "file", "/bin/echo")
	if hasPartialCoverageScope(graph.Coverage, "python-multiline-string-analysis") {
		t.Fatalf("delimiter-looking quoted/comment text changed lexical state: %#v", graph.Coverage)
	}
}

func TestExtractTextFailsClosedOnUnterminatedPythonTripleQuote(t *testing.T) {
	source := `description = """
import subprocess
subprocess.run(["/bin/false"])
requests.get("https://unterminated-decoy.example/payload")
`
	graph := extractPythonMultilineFixture(source)

	assertNetworkDestinationAbsent(t, graph, "https://unterminated-decoy.example/payload")
	for _, operation := range graph.Operations {
		if testOperationHasResource(operation, "file", "/bin/false") {
			t.Fatalf("unterminated triple-quoted contents became an operation: %#v", operation)
		}
	}
	assertPythonMultilineCoverage(t, graph, "unterminated triple-quoted string")
}

func TestExtractTextMarksFormattedPythonTripleQuotePartial(t *testing.T) {
	source := `description = f"""{requests.get("https://formatted-expression.example/payload")}"""
requests.get("https://after-formatted.example/payload")
`
	graph := extractPythonMultilineFixture(source)

	assertNetworkDestinationAbsent(t, graph, "https://formatted-expression.example/payload")
	assertNetworkDestinationAbsent(t, graph, "https://after-formatted.example/payload")
	assertPythonMultilineCoverage(t, graph, "following source suffix were not analyzed")
}

func TestExtractTextMarksPythonTemplateTripleQuotePartial(t *testing.T) {
	source := `description = tr"""{requests.get("https://template-expression.example/payload")}"""
requests.get("https://after-template.example/payload")
`
	graph := extractPythonMultilineFixture(source)

	assertNetworkDestinationAbsent(t, graph, "https://template-expression.example/payload")
	assertNetworkDestinationAbsent(t, graph, "https://after-template.example/payload")
	assertPythonMultilineCoverage(t, graph, "formatted or template triple-quoted string")
}

func TestMaskPythonMultilineStringsBoundedBlanksUninspectedSuffix(t *testing.T) {
	lines := []string{
		`description = """`,
		"first interior line",
		"second interior line",
		`"""; requests.get("https://must-not-survive.example/payload")`,
	}
	result := maskPythonMultilineStringsBounded(lines, 2, 1<<20)
	if !result.limited || result.unterminated {
		t.Fatalf("bounded mask status = %#v, want limited only", result)
	}
	if result.lines[2] != "" || result.lines[3] != "" {
		t.Fatalf("uninspected suffix survived line bound: %#v", result.lines)
	}

	byteLimited := maskPythonMultilineStringsBounded(
		[]string{`description = """`, strings.Repeat("x", 32), `"""`},
		100,
		8,
	)
	if !byteLimited.limited || byteLimited.lines[1] != "" || byteLimited.lines[2] != "" {
		t.Fatalf("uninspected suffix survived byte bound: %#v", byteLimited)
	}
}

func extractPythonMultilineFixture(source string) behavior.Graph {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:           "node-python",
		ScopeID:          "scope-python",
		LogicalPath:      "fixture.py",
		Kind:             "script",
		MediaType:        "text/plain",
		SemanticLanguage: "python",
		Data:             []byte(source),
	})
	return graph
}

func assertPythonMultilineCoverage(t *testing.T, graph behavior.Graph, detail string) {
	t.Helper()
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "python-multiline-string-analysis" &&
			coverage.Status == "partial" &&
			strings.Contains(coverage.Detail, detail) {
			return
		}
	}
	t.Fatalf("missing Python multiline-string coverage %q: %#v", detail, graph.Coverage)
}
