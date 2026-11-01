package rules

import (
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestAnalysisViewUsesCanonicalFactOrderBeforeChargingIndexBudget(t *testing.T) {
	operation := func(id string) behavior.ModeledOperation {
		return behavior.ModeledOperation{
			ID:            id,
			SubjectNodeID: "node-1",
			Kind:          behavior.OperationProcessExecute,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/bin/sh")),
			),
			EvidenceIDs: []string{"ev-1"},
			Support:     behavior.SupportCorroborated,
			Execution:   unknownExecution(),
		}
	}
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		operation("operation-z"),
		operation("operation-a"),
	}}
	budget := &ruleWorkBudget{graph: &graph, remaining: 3}
	view := newAnalysisView(&graph, budget)
	if _, ok := view.operationsByID["operation-a"]; !ok {
		t.Fatalf("canonical first operation was not indexed: %#v", view.operationsByID)
	}
	if _, ok := view.operationsByID["operation-z"]; ok {
		t.Fatalf("later operation survived exhausted canonical prefix: %#v", view.operationsByID)
	}
	if graph.Operations[0].ID != "operation-z" {
		t.Fatalf("analysis view mutated caller fact order: %#v", graph.Operations)
	}
}
