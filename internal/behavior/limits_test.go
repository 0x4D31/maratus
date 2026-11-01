package behavior

import (
	"fmt"
	"strings"
	"testing"
)

func TestGraphItemLimitBoundsCollectionsAndReportsPartialCoverage(t *testing.T) {
	graph := Graph{ItemLimit: 3}
	if graph.AddScope(Scope{Function: "main"}) == "" {
		t.Fatal("first item should fit")
	}
	if graph.AddFeature(Feature{Key: "one"}) == "" {
		t.Fatal("second item should fit")
	}
	if graph.AddNetworkImplementation(NetworkImplementationObservation{
		Kind: NetworkImplementationDynamicLinkage, SubjectNodeID: "node-1", APIOrTool: "libcurl",
		EvidenceIDs: []string{"ev-1"}, Support: SupportDirect, Execution: ExecutionContext{Connectivity: ConnectivityUnknown},
	}) == "" {
		t.Fatal("third item should fit")
	}
	if graph.AddOperation(ModeledOperation{
		Kind:             OperationProcessExecute,
		ResourceBindings: Bindings(Bind(ResourceRoleExecutable, NewResource(ResourceFile, ""))),
	}) != "" {
		t.Fatal("item over limit should be rejected")
	}
	if graph.AddArtifactProperty(ArtifactProperty{Kind: "entitlement"}) {
		t.Fatal("all collections must share the same limit")
	}
	if graph.ItemsDropped != 2 {
		t.Fatalf("ItemsDropped = %d, want 2", graph.ItemsDropped)
	}

	graph.FinalizeLimits()
	graph.FinalizeLimits()
	if len(graph.Coverage) != 1 {
		t.Fatalf("FinalizeLimits should add exactly one marker: %#v", graph.Coverage)
	}
	marker := graph.Coverage[0]
	if marker.AnalysisArea != "behavior-ir" || marker.Status != "partial" || !strings.Contains(marker.Detail, "omitted 2") {
		t.Fatalf("unexpected limit marker: %#v", marker)
	}
	if got := graph.itemCount(); got != graph.ItemLimit+1 {
		t.Fatalf("bounded graph has %d items, want %d including marker", got, graph.ItemLimit+1)
	}
}

func TestGraphInvalidItemsAreNotReportedAsBudgetExhaustion(t *testing.T) {
	graph := Graph{}
	if graph.AddOperation(ModeledOperation{Kind: "not-an-operation"}) != "" {
		t.Fatal("invalid operation was retained")
	}
	if graph.ItemsDropped != 0 || graph.InvalidItemsDropped != 1 {
		t.Fatalf("invalid record accounting = budget %d invalid %d, want 0/1", graph.ItemsDropped, graph.InvalidItemsDropped)
	}
	graph.FinalizeLimits()
	if len(graph.Coverage) != 1 || !strings.Contains(graph.Coverage[0].Detail, "rejected 1 invalid behavior items") || strings.Contains(graph.Coverage[0].Detail, "analysis limit") {
		t.Fatalf("invalid producer record was mislabeled as budget exhaustion: %#v", graph.Coverage)
	}
}

func TestGraphStringByteLimitBoundsEvidenceAndItems(t *testing.T) {
	expected := retainedStringBytes(Feature{
		Key:       "four",
		Support:   SupportCorroborated,
		Execution: ExecutionContext{Connectivity: ConnectivityUnknown},
	}) + generatedIDByteReserve
	graph := Graph{ItemLimit: 10, StringByteLimit: expected}
	if graph.AddFeature(Feature{Key: "four"}) == "" {
		t.Fatal("feature plus generated ID reserve should exactly fit")
	}
	if graph.StringBytes != expected {
		t.Fatalf("StringBytes = %d, want %d", graph.StringBytes, expected)
	}
	if graph.AddCoverage(Coverage{Detail: "x"}) {
		t.Fatal("item over retained string budget should be rejected")
	}
	if graph.AddEvidence(Evidence{Value: "evidence"}) != "" {
		t.Fatal("evidence over retained string budget should be rejected")
	}
	if graph.ItemsDropped != 1 || graph.EvidenceLimitDrops != 0 || graph.EvidenceStringDrops != 1 || graph.StringBytesDropped == 0 {
		t.Fatalf("drop accounting is incomplete: items=%d evidence-limit=%d evidence-string=%d bytes=%d", graph.ItemsDropped, graph.EvidenceLimitDrops, graph.EvidenceStringDrops, graph.StringBytesDropped)
	}

	graph.FinalizeLimits()
	if len(graph.Coverage) != 1 || !strings.Contains(graph.Coverage[0].Detail, "retained string byte limit "+fmt.Sprint(expected)) {
		t.Fatalf("missing string budget marker: %#v", graph.Coverage)
	}
}

func TestRetainedStringBudgetChargesJSONExpansion(t *testing.T) {
	if got := retainedStringByteCost("plain"); got != 5 {
		t.Fatalf("plain string cost = %d, want 5", got)
	}
	if got := retainedStringByteCost("\x00\xff"); got != 12 {
		t.Fatalf("escaped string cost = %d, want 12", got)
	}
	if got := retainedStringByteCost("\u2028"); got != 6 {
		t.Fatalf("line-separator cost = %d, want 6", got)
	}
}

func TestGraphRejectsDerivedItemsWhoseEvidenceWasDropped(t *testing.T) {
	graph := Graph{EvidenceLimit: 1}
	first := graph.AddEvidence(Evidence{Value: "first"})
	if first == "" {
		t.Fatal("first evidence should fit")
	}
	dropped := graph.AddEvidence(Evidence{Value: "second"})
	if dropped != "" {
		t.Fatal("second evidence should exceed the limit")
	}
	if graph.EvidenceLimitDrops != 1 || graph.EvidenceStringDrops != 0 {
		t.Fatalf("evidence-count exhaustion was misclassified: limit=%d string=%d", graph.EvidenceLimitDrops, graph.EvidenceStringDrops)
	}
	if graph.AddOperation(ModeledOperation{Kind: "process.execute", EvidenceIDs: []string{dropped}}) != "" {
		t.Fatal("an operation backed only by dropped evidence must not be retained")
	}
	if graph.AddFeature(Feature{Key: "feature", EvidenceIDs: []string{"", first}}) == "" {
		t.Fatal("a feature with at least one retained evidence object should remain valid")
	}
	if !graph.WorkLimitReached() {
		t.Fatal("evidence exhaustion should stop further analyzer work")
	}
	if graph.DerivedItemLimitReached() {
		t.Fatal("evidence-count exhaustion should not block derived items over retained evidence")
	}
}
