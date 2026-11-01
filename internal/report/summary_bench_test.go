package report

import (
	"fmt"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func BenchmarkSummaryRepeatedOperationSources(b *testing.B) {
	var rep Report
	for i := 0; i < 8000; i++ {
		id := fmt.Sprintf("ev-%04d", i)
		rep.Evidence = append(rep.Evidence, behavior.Evidence{ID: id, NodeID: "node-1", Line: i + 1})
		rep.Operations = append(rep.Operations, behavior.ModeledOperation{
			ID: fmt.Sprintf("operation-%04d", i), SubjectNodeID: "node-1", Kind: behavior.OperationFileRead,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, "/tmp/input"))),
			EvidenceIDs:      []string{id}, Support: behavior.SupportCorroborated,
			Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ProjectSummary(rep)
	}
}

func TestSummaryRepeatedSourcesRetainsAllReferences(t *testing.T) {
	var rep Report
	for i := 0; i < 8000; i++ {
		id := fmt.Sprintf("ev-%04d", i)
		rep.Evidence = append(rep.Evidence, behavior.Evidence{ID: id, NodeID: "node-1", Line: i + 1})
		rep.Operations = append(rep.Operations, behavior.ModeledOperation{
			ID: fmt.Sprintf("operation-%04d", i), SubjectNodeID: "node-1", Kind: behavior.OperationFileRead,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, "/tmp/input"))),
			EvidenceIDs:      []string{id}, Support: behavior.SupportCorroborated,
			Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
		})
	}
	rows := ProjectSummary(rep).ModeledBehavior
	if len(rows) != 1 || rows[0].Count != 8000 || len(rows[0].Sources) != 8000 || len(rows[0].OperationIDs) != 8000 {
		t.Fatalf("summary dropped provenance: rows=%d", len(rows))
	}
	for i, source := range rows[0].Sources {
		if source.EvidenceID != fmt.Sprintf("ev-%04d", i) || source.Line != i+1 {
			t.Fatalf("source %d: %#v", i, source)
		}
	}
}
