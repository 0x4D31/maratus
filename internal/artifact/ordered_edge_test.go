package artifact

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestAddOrderedEdgePreservesZeroAndJSONMeaning(t *testing.T) {
	var graph Graph
	graph.AddEdge("carrier", "archive", "contains")
	graph.AddOrderedEdge("carrier", "first", "loader-invokes", 0)
	graph.AddOrderedEdge("carrier", "second", "loader-invokes", 1)
	graph.AddOrderedEdge("carrier", "invalid", "loader-invokes", -1)

	if len(graph.Edges) != 3 || graph.Edges[0].Ordinal != nil {
		t.Fatalf("unordered/ordered edges = %#v", graph.Edges)
	}
	if graph.Edges[1].Ordinal == nil || *graph.Edges[1].Ordinal != 0 || graph.Edges[2].Ordinal == nil || *graph.Edges[2].Ordinal != 1 {
		t.Fatalf("ordered edge ordinals = %#v", graph.Edges)
	}
	encoded, err := json.Marshal(graph.Edges)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, `"kind":"contains","ordinal"`) || !strings.Contains(text, `"kind":"loader-invokes","ordinal":0`) {
		t.Fatalf("edge JSON did not distinguish unordered from ordinal zero: %s", text)
	}
}

func TestArtifactRelationshipSortIsCanonicalByKindAndOrdinal(t *testing.T) {
	zero, one, two := 0, 1, 2
	s := scanner{graph: Graph{Edges: []Edge{
		{From: "b", To: "last", Kind: "contains"},
		{From: "a", To: "z", Kind: "loader-invokes", Ordinal: &two},
		{From: "a", To: "y", Kind: "contains"},
		{From: "a", To: "b", Kind: "loader-invokes", Ordinal: &one},
		{From: "a", To: "a", Kind: "loader-invokes", Ordinal: &zero},
		{From: "a", To: "unordered-z", Kind: "loader-invokes"},
		{From: "a", To: "unordered-a", Kind: "loader-invokes"},
	}}}
	s.sort()

	want := []string{
		"a/contains/unordered/y",
		"a/loader-invokes/unordered/unordered-a",
		"a/loader-invokes/unordered/unordered-z",
		"a/loader-invokes/0/a",
		"a/loader-invokes/1/b",
		"a/loader-invokes/2/z",
		"b/contains/unordered/last",
	}
	got := make([]string, 0, len(s.graph.Edges))
	for _, edge := range s.graph.Edges {
		ordinal := "unordered"
		if edge.Ordinal != nil {
			ordinal = zeroPad(*edge.Ordinal, 1)
		}
		got = append(got, edge.From+"/"+edge.Kind+"/"+ordinal+"/"+edge.To)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("relationship order = %#v, want %#v", got, want)
	}
}

func TestArtifactNodesSerializeCarrierPackagingAndContainerInventory(t *testing.T) {
	declared, modeled := 458, 410
	encoded, err := json.Marshal([]Node{
		{
			ID: "node-1", LogicalPath: "sample", Kind: "macho",
			PackagingTechnology: "PyInstaller", AnalyzeStatus: "analyzed",
		},
		{
			ID: "node-2", ParentID: "node-1", LogicalPath: "sample!_embedded/carchive", Kind: "carchive",
			DeclaredEntryCount: &declared, ModeledEntryCount: &modeled, AnalyzeStatus: "partial",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, want := range []string{
		`"packaging_technology":"PyInstaller"`,
		`"declared_entry_count":458`,
		`"modeled_entry_count":410`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("node JSON missing %s: %s", want, text)
		}
	}
}

func TestArtifactNodeSerializesKnownZeroInventory(t *testing.T) {
	zero := 0
	encoded, err := json.Marshal(Node{
		ID: "node-1", LogicalPath: "empty!_embedded/carchive", Kind: "carchive",
		DeclaredEntryCount: &zero, ModeledEntryCount: &zero, AnalyzeStatus: "analyzed",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if !strings.Contains(text, `"declared_entry_count":0`) || !strings.Contains(text, `"modeled_entry_count":0`) {
		t.Fatalf("known-zero inventory was omitted: %s", text)
	}
}
