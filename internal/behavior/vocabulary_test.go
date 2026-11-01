package behavior

import (
	"slices"
	"testing"
)

func TestOperationVocabularyIsClosedDeterministicAndNeutral(t *testing.T) {
	kinds := OperationKinds()
	if len(kinds) == 0 || !slices.IsSorted(kinds) {
		t.Fatalf("operation vocabulary is empty or nondeterministic: %#v", kinds)
	}
	for i, kind := range kinds {
		if !ValidOperationKind(kind) {
			t.Fatalf("declared operation kind %q is not valid", kind)
		}
		if i > 0 && kinds[i-1] == kind {
			t.Fatalf("duplicate operation kind %q", kind)
		}
	}
	for _, invalid := range []OperationKind{"", "collection.archive", "persistence.launchd", "defense-evasion.remove-quarantine", "process.remote-thread.create", "arbitrary"} {
		if ValidOperationKind(invalid) {
			t.Fatalf("objective-laden or unknown operation kind %q was accepted", invalid)
		}
	}

	copyOfKinds := OperationKinds()
	copyOfKinds[0] = "mutated"
	if OperationKinds()[0] == "mutated" {
		t.Fatal("caller mutated the authoritative operation vocabulary")
	}
}

func TestGraphRejectsUnknownOperationKindsAtInsertionAndSort(t *testing.T) {
	graph := Graph{}
	if graph.AddOperation(ModeledOperation{Kind: "arbitrary", EvidenceIDs: []string{"ev-1"}}) != "" {
		t.Fatal("AddOperation retained an unknown operation kind")
	}
	if graph.ItemsDropped != 0 || graph.InvalidItemsDropped != 1 {
		t.Fatalf("drop count = budget %d invalid %d, want 0/1", graph.ItemsDropped, graph.InvalidItemsDropped)
	}

	graph = Graph{Operations: []ModeledOperation{{Kind: "arbitrary"}}}
	if err := graph.ValidateOperations(); err == nil {
		t.Fatal("direct graph fixture with an unknown operation kind validated")
	}
	if err := graph.Sort(); err == nil {
		t.Fatal("Sort accepted a direct graph fixture with an unknown operation kind")
	}
}
