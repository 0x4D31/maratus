package extract

import (
	"fmt"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestScreenCaptureBindsExactOutputFiles(t *testing.T) {
	for _, test := range []struct {
		name           string
		line           string
		wantOutputs    []string
		wantClassified bool
	}{
		{name: "ordinary image", line: `screencapture -x -t png /tmp/capture.png`, wantOutputs: []string{"/tmp/capture.png"}, wantClassified: true},
		{name: "attached option and delimiter", line: `screencapture -tpng -- -capture.png`, wantOutputs: []string{"-capture.png"}, wantClassified: true},
		{name: "multiple displays", line: `screencapture -x /tmp/one.png /tmp/two.png`, wantOutputs: []string{"/tmp/one.png", "/tmp/two.png"}, wantClassified: true},
		{name: "video", line: `screencapture -v -V 3 /tmp/capture.mov`, wantOutputs: []string{"/tmp/capture.mov"}},
		{name: "clipboard ignores file", line: `screencapture -c /tmp/ignored.png`},
		{name: "default settings ignore file", line: `screencapture -p /tmp/ignored.png`},
		{name: "ui ignores file", line: `screencapture -u /tmp/ignored.png`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			AnalyzeShellLine(&graph, artifact.Content{NodeID: "node-screen"}, test.line, 1, testConnectedExecution("root-screen"), "ev-screen")
			operation := onlyOperationOfKind(t, graph.Operations, behavior.OperationScreenCapture)
			bindings := operationBindings(operation, behavior.ResourceRoleLocalOutput)
			if len(bindings) != len(test.wantOutputs) {
				t.Fatalf("local outputs = %#v, want %q", bindings, test.wantOutputs)
			}
			for index, want := range test.wantOutputs {
				if bindings[index].Resource.Value != want || bindings[index].Resource.HasClassification(behavior.ResourceClassScreenshot) != test.wantClassified {
					t.Fatalf("local output %d = %#v", index, bindings[index])
				}
			}
			if hasPartialCoverageScope(graph.Coverage, "screencapture-output-analysis") {
				t.Fatalf("supported command was marked partial: %#v", graph.Coverage)
			}
		})
	}
}

func TestScreenCaptureOutputAmbiguityIsExplicitAndDoesNotInventAFile(t *testing.T) {
	for _, line := range []string{
		`screencapture --unknown /tmp/not-proven.png`,
		`screencapture -D`,
		`screencapture "$DYNAMIC_OUTPUT"`,
	} {
		t.Run(line, func(t *testing.T) {
			var graph behavior.Graph
			AnalyzeShellLine(&graph, artifact.Content{NodeID: "node-screen"}, line, 1, testConnectedExecution("root-screen"), "ev-screen")
			operation := onlyOperationOfKind(t, graph.Operations, behavior.OperationScreenCapture)
			if bindings := operationBindings(operation, behavior.ResourceRoleLocalOutput); len(bindings) != 0 {
				t.Fatalf("ambiguous output became a file binding: %#v", bindings)
			}
			if !hasPartialCoverageScope(graph.Coverage, "screencapture-output-analysis") {
				t.Fatalf("ambiguous output omitted partial coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestScreenCaptureOutputBindingIsBounded(t *testing.T) {
	fields := []string{"screencapture"}
	for index := 0; index < maxScreenCaptureOutputs+2; index++ {
		fields = append(fields, fmt.Sprintf("/tmp/capture-%02d.png", index))
	}
	var graph behavior.Graph
	handleScreenCapture(&graph, artifact.Content{NodeID: "node-screen"}, fields, 1, testConnectedExecution("root-screen"), "ev-screen")
	operation := onlyOperationOfKind(t, graph.Operations, behavior.OperationScreenCapture)
	if bindings := operationBindings(operation, behavior.ResourceRoleLocalOutput); len(bindings) != maxScreenCaptureOutputs {
		t.Fatalf("retained outputs = %d, want %d", len(bindings), maxScreenCaptureOutputs)
	}
	if !hasPartialCoverageScope(graph.Coverage, "screencapture-output-analysis") {
		t.Fatalf("output cap omitted partial coverage: %#v", graph.Coverage)
	}
}

func onlyOperationOfKind(t *testing.T, operations []behavior.ModeledOperation, kind behavior.OperationKind) behavior.ModeledOperation {
	t.Helper()
	var matches []behavior.ModeledOperation
	for _, operation := range operations {
		if operation.Kind == kind {
			matches = append(matches, operation)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("%s operations = %#v", kind, matches)
	}
	return matches[0]
}

func operationBindings(operation behavior.ModeledOperation, role behavior.ResourceRole) []behavior.ResourceBinding {
	var out []behavior.ResourceBinding
	for _, binding := range operation.ResourceBindings {
		if binding.Role == role {
			out = append(out, binding)
		}
	}
	return out
}
