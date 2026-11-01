package rules

import (
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestNativePrimitiveRulesRemainOperationBackedAndSupportGated(t *testing.T) {
	tests := []struct {
		spec     Spec
		kind     behavior.OperationKind
		bindings []behavior.ResourceBinding
	}{
		{MacOSFileOpen, behavior.OperationFileOpen, behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "")))},
		{MacOSFileDelete, behavior.OperationFileDelete, behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, "")))},
		{MacOSFileMove, behavior.OperationFileMove, behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "")), behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, "")))},
		{MacOSDescriptorRead, behavior.OperationIORead, behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceIOChannel, "")))},
		{MacOSSocketConnect, behavior.OperationSocketConnect, behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceSocket, "")))},
		{MacOSDataHash, behavior.OperationDataHash, behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceData, "")))},
	}
	for _, test := range tests {
		t.Run(test.spec.Metadata.ID, func(t *testing.T) {
			graph := behavior.Graph{Operations: []behavior.ModeledOperation{{
				ID: "operation-1", SubjectNodeID: "node-1", Kind: test.kind,
				ResourceBindings: test.bindings, Support: behavior.SupportCorroborated,
				Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
			}}}
			got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: test.spec})
			if len(got) != 1 || len(got[0].OperationIDs) != 1 || got[0].OperationIDs[0] != "operation-1" {
				t.Fatalf("operation-backed primitive match = %#v", got)
			}
			graph.Operations[0].Support = behavior.SupportHeuristic
			if weak := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: test.spec}); len(weak) != 0 {
				t.Fatalf("heuristic primitive must not satisfy %s: %#v", test.spec.Metadata.ID, weak)
			}
		})
	}
}
