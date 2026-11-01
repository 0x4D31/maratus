package extract

import (
	"fmt"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestFileCopyCommandEmitsTypedSourceAndOutputBindings(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `cp -R /tmp/source /tmp/output`, 7, testConnectedExecution("root-1"), "ev-line")
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileCopy {
		t.Fatalf("file-copy operations = %#v", graph.Operations)
	}
	operation := graph.Operations[0]
	source, sourceOK := operation.FirstBinding(behavior.ResourceRoleSource)
	output, outputOK := operation.FirstBinding(behavior.ResourceRoleLocalOutput)
	if !sourceOK || source.Resource.Value != "/tmp/source" || !outputOK || output.Resource.Value != "/tmp/output" || operation.Line != 7 {
		t.Fatalf("file-copy bindings = %#v", operation.ResourceBindings)
	}
}

func TestFileCopyCommandExplicitDelimiterPermitsDashOperand(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "install.sh"}, `cp -- -source /tmp/output`, 1, unknownExecutionContext(), "ev-line")
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileCopy {
		t.Fatalf("explicit delimiter copy operation = %#v", graph.Operations)
	}
	source, _ := graph.Operations[0].FirstBinding(behavior.ResourceRoleSource)
	if source.Resource.Value != "-source" {
		t.Fatalf("explicit delimiter source = %#v", source.Resource)
	}
}

func TestFileCopyCommandRetainsOperationWithRuntimeResolvedPaths(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(
		&graph,
		artifact.Content{NodeID: "node-1", LogicalPath: "install.sh", SupportingEvidenceIDs: []string{"ev-invocation"}},
		`cp $DIR/source /Users/$USER/output`,
		9,
		testConnectedExecution("root-1"),
		"ev-line",
	)
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileCopy {
		t.Fatalf("runtime-resolved copy was lost: %#v", graph.Operations)
	}
	operation := graph.Operations[0]
	source, _ := operation.FirstBinding(behavior.ResourceRoleSource)
	output, _ := operation.FirstBinding(behavior.ResourceRoleLocalOutput)
	if source.Resource.Value != "" || output.Resource.Value != "" {
		t.Fatalf("runtime paths became concrete resources: %#v", operation.ResourceBindings)
	}
	if len(operation.EvidenceIDs) != 2 || operation.EvidenceIDs[0] != "ev-line" || operation.EvidenceIDs[1] != "ev-invocation" {
		t.Fatalf("file-copy evidence = %#v", operation.EvidenceIDs)
	}
}

func TestFileCopyCommandFailsClosedOnMalformedUnsupportedAndHostileArgv(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantPartial bool
	}{
		{name: "missing destination", line: `cp /tmp/source`},
		{name: "unknown option", line: `cp --future-mode /tmp/source /tmp/output`, wantPartial: true},
		{name: "ambiguous dash operand", line: `cp /tmp/source -output`, wantPartial: true},
	}
	hostile := "cp"
	for index := 0; index < maxFileCopySources+1; index++ {
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
			if len(graph.Operations) != 0 {
				t.Fatalf("invalid cp argv emitted operations: %#v", graph.Operations)
			}
			if got := hasPartialCoverageScope(graph.Coverage, "shell-file-copy-analysis"); got != test.wantPartial {
				t.Fatalf("partial coverage = %v, want %v: %#v", got, test.wantPartial, graph.Coverage)
			}
		})
	}
}

func TestConditionalAndDynamicShellAssignmentsDoNotInventCopyPaths(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-1",
		LogicalPath: "install.sh",
		Kind:        "script",
		Data: []byte(`#!/bin/sh
DIR=$(dirname $0)
if [ -z "$DIR" ]; then
  DIR="."
fi
cp $DIR/source /tmp/output
`),
	}
	ExtractText(&graph, content)
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileCopy {
		t.Fatalf("copy operation = %#v", graph.Operations)
	}
	source, _ := graph.Operations[0].FirstBinding(behavior.ResourceRoleSource)
	if source.Resource.Value != "" {
		t.Fatalf("branch-dependent source became concrete: %#v", source.Resource)
	}
}

func TestTopLevelLiteralShellAssignmentStillResolvesCopyPath(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-1",
		LogicalPath: "install.sh",
		Kind:        "script",
		Data:        []byte("#!/bin/sh\nDIR=/tmp/source\ncp $DIR/file /tmp/output\n"),
	}
	ExtractText(&graph, content)
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileCopy {
		t.Fatalf("copy operation = %#v", graph.Operations)
	}
	source, _ := graph.Operations[0].FirstBinding(behavior.ResourceRoleSource)
	if source.Resource.Value != "/tmp/source/file" {
		t.Fatalf("literal source was not resolved: %#v", source.Resource)
	}
}
