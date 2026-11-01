package extract

import (
	"fmt"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestFileMoveCommandEmitsExactSourceAndUnresolvedTarget(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "install.sh"}, `mv -fv /tmp/source /tmp/destination`, 7, testConnectedExecution("root-1"), "ev-line")
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileMove {
		t.Fatalf("file-move operations = %#v", graph.Operations)
	}
	operation := graph.Operations[0]
	source, sourceOK := operation.FirstBinding(behavior.ResourceRoleSource)
	target, targetOK := operation.FirstBinding(behavior.ResourceRoleTarget)
	if !sourceOK || source.Resource.Value != "/tmp/source" || !targetOK || target.Resource.Value != "" {
		t.Fatalf("file-move bindings = %#v", operation.ResourceBindings)
	}
	if operation.Qualifiers["destination_operand"] != "/tmp/destination" || operation.Line != 7 {
		t.Fatalf("file-move qualifier/line = %#v/%d", operation.Qualifiers, operation.Line)
	}
}

func TestFileMoveCommandEmitsOneOperationPerSource(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "install.sh"}, `mv /tmp/a /tmp/b /tmp/directory`, 1, unknownExecutionContext(), "ev-line")
	if len(graph.Operations) != 2 {
		t.Fatalf("multi-source move operations = %#v", graph.Operations)
	}
	for index, want := range []string{"/tmp/a", "/tmp/b"} {
		source, _ := graph.Operations[index].FirstBinding(behavior.ResourceRoleSource)
		if source.Resource.Value != want || graph.Operations[index].Qualifiers["destination_operand"] != "/tmp/directory" {
			t.Fatalf("move %d = %#v", index, graph.Operations[index])
		}
	}
}

func TestFileMoveCommandFailsClosedOnMalformedUnsupportedAndOversizedArgv(t *testing.T) {
	if parsed := parseFileMoveCommand([]string{"mv", "--", "-source", "/tmp/output"}); len(parsed.sources) != 1 || parsed.sources[0] != "-source" {
		t.Fatalf("explicit delimiter parser result = %#v", parsed)
	}
	tests := []struct {
		name        string
		line        string
		wantPartial bool
	}{
		{name: "missing destination", line: `mv /tmp/source`},
		{name: "unknown option", line: `mv --future-mode /tmp/source /tmp/output`, wantPartial: true},
		{name: "ambiguous dash operand", line: `mv /tmp/source -output`, wantPartial: true},
		{name: "delimiter permits dash operand", line: `mv -- -source /tmp/output`},
	}
	hostile := "mv"
	for index := 0; index < maxFileMoveSources+1; index++ {
		hostile += fmt.Sprintf(" /tmp/source-%d", index)
	}
	hostile += " /tmp/output"
	tests = append(tests, struct {
		name        string
		line        string
		wantPartial bool
	}{name: "too many sources", line: hostile, wantPartial: true})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			AnalyzeShellLine(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "install.sh"}, test.line, 1, unknownExecutionContext(), "ev-line")
			if test.name == "delimiter permits dash operand" {
				if len(graph.Operations) != 1 {
					t.Fatalf("explicit delimiter move was not retained: %#v", graph.Operations)
				}
				return
			}
			if len(graph.Operations) != 0 {
				t.Fatalf("invalid mv argv emitted operations: %#v", graph.Operations)
			}
			if got := hasPartialCoverageScope(graph.Coverage, "shell-file-move-analysis"); got != test.wantPartial {
				t.Fatalf("partial coverage = %v, want %v: %#v", got, test.wantPartial, graph.Coverage)
			}
		})
	}
}

func TestFileMoveCommandDoesNotInventDynamicSourceOrDestination(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "install.sh"}, `mv "$SOURCE" "$DESTINATION"`, 1, unknownExecutionContext(), "ev-line")
	if len(graph.Operations) != 1 {
		t.Fatalf("dynamic move operation = %#v", graph.Operations)
	}
	source, _ := graph.Operations[0].FirstBinding(behavior.ResourceRoleSource)
	if source.Resource.Value != "" || len(graph.Operations[0].Qualifiers) != 0 {
		t.Fatalf("dynamic move became concrete: %#v", graph.Operations[0])
	}
}
