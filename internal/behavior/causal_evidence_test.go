package behavior

import (
	"fmt"
	"testing"
)

func TestCorroborateRangeCoversEveryFactCollection(t *testing.T) {
	graph := Graph{
		Features:    []Feature{{EvidenceIDs: []string{"ev-before"}, Support: SupportDirect}},
		Operations:  []ModeledOperation{{EvidenceIDs: []string{"ev-before"}, Support: SupportDirect}},
		Relations:   []OperationRelation{{EvidenceIDs: []string{"ev-before"}, Support: SupportDirect}},
		Network:     []NetworkImplementationObservation{{EvidenceIDs: []string{"ev-before"}, Support: SupportDirect}},
		StringBytes: 100,
	}
	start := graph.CaptureGraphRange()
	graph.Features = append(graph.Features, Feature{
		EvidenceIDs: []string{"ev-middle", "ev-a", "ev-middle"},
		Support:     SupportDirect,
	})
	graph.Operations = append(graph.Operations, ModeledOperation{
		EvidenceIDs: []string{"ev-middle"},
		Support:     SupportCorroborated,
	})
	graph.Relations = append(graph.Relations, OperationRelation{
		EvidenceIDs: []string{"ev-z"},
		Support:     SupportDirect,
	})
	graph.Network = append(graph.Network, NetworkImplementationObservation{
		EvidenceIDs: []string{"ev-middle"},
		Support:     SupportHeuristic,
	})

	beforeBytes := graph.StringBytes
	if !graph.CorroborateRange(start, []string{"ev-z", "ev-a", "ev-z"}) {
		t.Fatal("bounded causal evidence annotation failed")
	}

	for _, evidence := range [][]string{
		graph.Features[0].EvidenceIDs,
		graph.Operations[0].EvidenceIDs,
		graph.Relations[0].EvidenceIDs,
		graph.Network[0].EvidenceIDs,
	} {
		assertStrings(t, evidence, []string{"ev-before"})
	}
	for _, support := range []Support{
		graph.Features[0].Support,
		graph.Operations[0].Support,
		graph.Relations[0].Support,
		graph.Network[0].Support,
	} {
		if support != SupportDirect {
			t.Fatalf("fact before the captured range was modified: support=%q", support)
		}
	}

	assertStrings(t, graph.Features[1].EvidenceIDs, []string{"ev-a", "ev-middle", "ev-z"})
	assertStrings(t, graph.Operations[1].EvidenceIDs, []string{"ev-a", "ev-middle", "ev-z"})
	assertStrings(t, graph.Relations[1].EvidenceIDs, []string{"ev-a", "ev-z"})
	assertStrings(t, graph.Network[1].EvidenceIDs, []string{"ev-a", "ev-middle", "ev-z"})
	if graph.Features[1].Support != SupportCorroborated ||
		graph.Operations[1].Support != SupportCorroborated ||
		graph.Relations[1].Support != SupportCorroborated ||
		graph.Network[1].Support != SupportHeuristic {
		t.Fatalf(
			"support weakening is incorrect: feature=%q operation=%q relation=%q network=%q",
			graph.Features[1].Support,
			graph.Operations[1].Support,
			graph.Relations[1].Support,
			graph.Network[1].Support,
		)
	}
	wantAdded := causalFactStringDelta(
		[]string{"ev-middle", "ev-a", "ev-middle"},
		SupportDirect,
		[]string{"ev-a", "ev-middle", "ev-z"},
		SupportCorroborated,
	)
	wantAdded = saturatingAddSignedInt64(wantAdded, causalFactStringDelta(
		[]string{"ev-middle"},
		SupportCorroborated,
		[]string{"ev-a", "ev-middle", "ev-z"},
		SupportCorroborated,
	))
	wantAdded = saturatingAddSignedInt64(wantAdded, causalFactStringDelta(
		[]string{"ev-z"},
		SupportDirect,
		[]string{"ev-a", "ev-z"},
		SupportCorroborated,
	))
	wantAdded = saturatingAddSignedInt64(wantAdded, causalFactStringDelta(
		[]string{"ev-middle"},
		SupportHeuristic,
		[]string{"ev-a", "ev-middle", "ev-z"},
		SupportHeuristic,
	))
	if graph.StringBytes-beforeBytes != wantAdded {
		t.Fatalf("causal evidence byte charge = %d, want %d", graph.StringBytes-beforeBytes, wantAdded)
	}
}

func TestCorroborateRangeRejectsInvalidStartsWithoutMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*GraphRange)
	}{
		{name: "negative feature", mutate: func(start *GraphRange) { start.FeatureStart = -1 }},
		{name: "feature past end", mutate: func(start *GraphRange) { start.FeatureStart = 2 }},
		{name: "negative operation", mutate: func(start *GraphRange) { start.OperationStart = -1 }},
		{name: "operation past end", mutate: func(start *GraphRange) { start.OperationStart = 2 }},
		{name: "negative relation", mutate: func(start *GraphRange) { start.RelationStart = -1 }},
		{name: "relation past end", mutate: func(start *GraphRange) { start.RelationStart = 2 }},
		{name: "negative network implementation", mutate: func(start *GraphRange) { start.NetworkStart = -1 }},
		{name: "network implementation past end", mutate: func(start *GraphRange) { start.NetworkStart = 2 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph := causalEvidenceTestGraph()
			start := GraphRange{}
			test.mutate(&start)
			if graph.CorroborateRange(start, []string{"ev-causal"}) {
				t.Fatal("invalid range start was accepted")
			}
			assertCausalEvidenceTestGraphUnchanged(t, graph)
			if graph.StringBytes != 17 || graph.StringBytesDropped != 0 {
				t.Fatalf("invalid range changed string accounting: bytes=%d dropped=%d", graph.StringBytes, graph.StringBytesDropped)
			}
		})
	}
}

func TestCorroborateRangeBoundFailureWeakensWholeRange(t *testing.T) {
	t.Run("causal input bound", func(t *testing.T) {
		graph := causalEvidenceTestGraph()
		evidenceIDs := make([]string, MaxCausalEvidenceIDs+1)
		for index := range evidenceIDs {
			evidenceIDs[index] = fmt.Sprintf("ev-causal-%03d", index)
		}
		if graph.CorroborateRange(GraphRange{}, evidenceIDs) {
			t.Fatal("oversized causal evidence input was accepted")
		}
		assertCausalEvidenceFailure(t, graph)
	})

	t.Run("merged fact bound", func(t *testing.T) {
		existing := make([]string, MaxCausalEvidenceIDs)
		for index := range existing {
			existing[index] = fmt.Sprintf("ev-existing-%03d", index)
		}
		graph := Graph{
			Features: []Feature{{EvidenceIDs: append([]string(nil), existing...), Support: SupportDirect}},
			Operations: []ModeledOperation{{
				EvidenceIDs: []string{"ev-operation"},
				Support:     SupportDirect,
			}},
		}
		if graph.CorroborateRange(GraphRange{}, []string{"ev-new"}) {
			t.Fatal("causal evidence that exceeds a fact's merged bound was accepted")
		}
		assertStrings(t, graph.Features[0].EvidenceIDs, existing)
		assertStrings(t, graph.Operations[0].EvidenceIDs, []string{"ev-operation"})
		if graph.Features[0].Support != SupportHeuristic || graph.Operations[0].Support != SupportHeuristic {
			t.Fatalf("bound failure did not weaken the complete range: features=%#v operations=%#v", graph.Features, graph.Operations)
		}
	})
}

func TestCorroborateRangeStringBudgetFailureIsAtomic(t *testing.T) {
	graph := causalEvidenceTestGraph()
	additionalBytes := int64(4*retainedStringByteCost("ev-causal")) +
		2*(retainedStringByteCost(string(SupportCorroborated))-retainedStringByteCost(string(SupportDirect)))
	graph.StringBytes = 0
	graph.StringByteLimit = additionalBytes - 1

	if graph.CorroborateRange(GraphRange{}, []string{"ev-causal"}) {
		t.Fatal("causal evidence annotation exceeded the string budget")
	}
	assertCausalEvidenceFailure(t, graph)
	heuristicDelta := 2*(retainedStringByteCost(string(SupportHeuristic))-retainedStringByteCost(string(SupportDirect))) +
		retainedStringByteCost(string(SupportHeuristic)) -
		retainedStringByteCost(string(SupportCorroborated))
	if graph.StringBytes != heuristicDelta || graph.StringBytesDropped != additionalBytes {
		t.Fatalf(
			"atomic reservation accounting = bytes %d dropped %d, want %d and %d",
			graph.StringBytes,
			graph.StringBytesDropped,
			heuristicDelta,
			additionalBytes,
		)
	}
}

func TestCorroborateRangeRequiresEvidence(t *testing.T) {
	graph := causalEvidenceTestGraph()
	if graph.CorroborateRange(GraphRange{}, nil) {
		t.Fatal("empty causal evidence was accepted")
	}
	assertCausalEvidenceFailure(t, graph)

	graph = causalEvidenceTestGraph()
	if graph.CorroborateRange(GraphRange{}, []string{"ev-causal", ""}) {
		t.Fatal("causal evidence containing an empty ID was accepted")
	}
	assertCausalEvidenceFailure(t, graph)
}

func TestCorroborateRangeAccountsExactSupportTransitionBytes(t *testing.T) {
	if direct, corroborated, heuristic := retainedStringByteCost(string(SupportDirect)), retainedStringByteCost(string(SupportCorroborated)), retainedStringByteCost(string(SupportHeuristic)); direct != 6 || corroborated != 12 || heuristic != 9 {
		t.Fatalf("support byte costs changed: DIRECT=%d CORROBORATED=%d HEURISTIC=%d", direct, corroborated, heuristic)
	}

	graph := Graph{
		Features:    []Feature{{EvidenceIDs: []string{"ev-causal"}, Support: SupportDirect}},
		StringBytes: 25,
	}
	delta := retainedStringByteCost(string(SupportCorroborated)) - retainedStringByteCost(string(SupportDirect))
	graph.StringByteLimit = graph.StringBytes + delta
	if !graph.CorroborateRange(GraphRange{}, []string{"ev-causal"}) {
		t.Fatal("exactly budgeted support transition failed")
	}
	if graph.StringBytes != graph.StringByteLimit || graph.Features[0].Support != SupportCorroborated {
		t.Fatalf("support transition was not charged exactly: %#v", graph)
	}
}

func TestCorroborateRangeDropsSuffixWhenHeuristicTransitionCannotFit(t *testing.T) {
	var graph Graph
	if graph.AddFeature(Feature{
		Key:         "derived",
		EvidenceIDs: []string{"ev-existing"},
		Support:     SupportDirect,
	}) == "" {
		t.Fatal("test feature was not retained")
	}
	retainedBefore := graph.StringBytes
	graph.StringByteLimit = retainedBefore + 2

	if graph.CorroborateRange(GraphRange{}, []string{"ev-new"}) {
		t.Fatal("corroboration unexpectedly fit the string budget")
	}
	if len(graph.Features) != 0 || graph.ItemsDropped != 1 {
		t.Fatalf("unsafe derived suffix was not dropped: features=%#v drops=%d", graph.Features, graph.ItemsDropped)
	}
	if graph.StringBytes != 0 || graph.StringBytesDropped == 0 {
		t.Fatalf("dropped suffix accounting is incomplete: bytes=%d dropped=%d", graph.StringBytes, graph.StringBytesDropped)
	}
}

func causalEvidenceTestGraph() Graph {
	return Graph{
		Features:    []Feature{{EvidenceIDs: []string{"ev-feature"}, Support: SupportDirect}},
		Operations:  []ModeledOperation{{EvidenceIDs: []string{"ev-operation"}, Support: SupportCorroborated}},
		Relations:   []OperationRelation{{EvidenceIDs: []string{"ev-relation"}, Support: SupportDirect}},
		Network:     []NetworkImplementationObservation{{EvidenceIDs: []string{"ev-network"}, Support: SupportHeuristic}},
		StringBytes: 17,
	}
}

func assertCausalEvidenceTestGraphUnchanged(t *testing.T, graph Graph) {
	t.Helper()
	assertStrings(t, graph.Features[0].EvidenceIDs, []string{"ev-feature"})
	assertStrings(t, graph.Operations[0].EvidenceIDs, []string{"ev-operation"})
	assertStrings(t, graph.Relations[0].EvidenceIDs, []string{"ev-relation"})
	assertStrings(t, graph.Network[0].EvidenceIDs, []string{"ev-network"})
	if graph.Features[0].Support != SupportDirect ||
		graph.Operations[0].Support != SupportCorroborated ||
		graph.Relations[0].Support != SupportDirect ||
		graph.Network[0].Support != SupportHeuristic {
		t.Fatalf("graph facts changed unexpectedly: %#v", graph)
	}
}

func assertCausalEvidenceFailure(t *testing.T, graph Graph) {
	t.Helper()
	assertStrings(t, graph.Features[0].EvidenceIDs, []string{"ev-feature"})
	assertStrings(t, graph.Operations[0].EvidenceIDs, []string{"ev-operation"})
	assertStrings(t, graph.Relations[0].EvidenceIDs, []string{"ev-relation"})
	assertStrings(t, graph.Network[0].EvidenceIDs, []string{"ev-network"})
	for _, support := range []Support{
		graph.Features[0].Support,
		graph.Operations[0].Support,
		graph.Relations[0].Support,
		graph.Network[0].Support,
	} {
		if support != SupportHeuristic {
			t.Fatalf("failed causal annotation retained non-heuristic support %q", support)
		}
	}
}
