package behavior

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestConnectivityVocabularyIsClosedAndIndependent(t *testing.T) {
	values := ConnectivityValues()
	if len(values) != 3 || values[0] != ConnectivityConnected || values[1] != ConnectivityUnconnected || values[2] != ConnectivityUnknown {
		t.Fatalf("connectivity vocabulary = %#v", values)
	}
	values[0] = "mutated"
	if ConnectivityValues()[0] == "mutated" {
		t.Fatal("connectivity vocabulary aliases authoritative storage")
	}
}

func TestOperationAndFeatureDefaultToExplicitUnknownConnectivity(t *testing.T) {
	graph := Graph{}
	operationID := graph.AddOperation(ModeledOperation{Kind: OperationProcessExecute, ResourceBindings: testExecutableBindings()})
	featureID := graph.AddFeature(Feature{Key: "api.import"})
	if operationID == "" || featureID == "" {
		t.Fatal("records with an omitted context should be retained as UNKNOWN")
	}
	if graph.Operations[0].Execution.Connectivity != ConnectivityUnknown || graph.Features[0].Execution.Connectivity != ConnectivityUnknown {
		t.Fatalf("omitted contexts were not normalized: operation=%#v feature=%#v", graph.Operations[0].Execution, graph.Features[0].Execution)
	}
	data, err := json.Marshal(graph.Operations[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"execution":{"connectivity":"UNKNOWN"}`) {
		t.Fatalf("execution context is not explicit in JSON: %s", data)
	}
}

func TestGraphRejectsContradictoryExecutionContexts(t *testing.T) {
	tests := []struct {
		name    string
		context ExecutionContext
	}{
		{name: "connected without root", context: ExecutionContext{Connectivity: ConnectivityConnected}},
		{name: "unconnected with root", context: ExecutionContext{Connectivity: ConnectivityUnconnected, ExecutionRootIDs: []string{"root-0001"}}},
		{name: "unknown with root", context: ExecutionContext{Connectivity: ConnectivityUnknown, ExecutionRootIDs: []string{"root-0001"}}},
		{name: "unknown with target", context: ExecutionContext{Connectivity: ConnectivityUnknown, InvokedTargetIDs: []string{"target-0001"}}},
		{name: "unconnected with target", context: ExecutionContext{Connectivity: ConnectivityUnconnected, InvokedTargetIDs: []string{"target-0001"}}},
		{name: "invalid connectivity", context: ExecutionContext{Connectivity: "MAYBE"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph := Graph{}
			if graph.AddOperation(ModeledOperation{Kind: "fixture", Execution: test.context}) != "" {
				t.Fatalf("contradictory operation context was retained: %#v", graph.Operations)
			}
			if graph.AddFeature(Feature{Key: "fixture", Execution: test.context}) != "" {
				t.Fatalf("contradictory feature context was retained: %#v", graph.Features)
			}
			if graph.ItemsDropped != 0 || graph.InvalidItemsDropped != 2 {
				t.Fatalf("drop accounting = budget %d invalid %d, want 0/2", graph.ItemsDropped, graph.InvalidItemsDropped)
			}
		})
	}
}

func TestValidateExecutionContextsRejectsInvalidDirectFixtures(t *testing.T) {
	graph := Graph{Operations: []ModeledOperation{{
		Execution: ExecutionContext{Connectivity: ConnectivityConnected},
	}}}
	if err := graph.ValidateExecutionContexts(); err == nil || !strings.Contains(err.Error(), "operations[0].execution") {
		t.Fatalf("invalid direct fixture was not located: %v", err)
	}
	if err := graph.Sort(); err == nil || !strings.Contains(err.Error(), "operations[0].execution") {
		t.Fatalf("Sort silently accepted an invalid context: %v", err)
	}
}

func TestExecutionContextNormalizesAndBoundsOwnershipSets(t *testing.T) {
	rootIDs := make([]string, 0, maxExecutionContextIDs+8)
	targetIDs := make([]string, 0, maxExecutionContextIDs+8)
	for i := maxExecutionContextIDs + 7; i >= 0; i-- {
		rootIDs = append(rootIDs, fmt.Sprintf("root-%04d", i))
		targetIDs = append(targetIDs, fmt.Sprintf("target-%04d", i))
	}
	rootIDs = append(rootIDs, "", "root-0001")
	targetIDs = append(targetIDs, "", "target-0001")
	originalFirstRoot := rootIDs[0]

	graph := Graph{}
	if graph.AddOperation(ModeledOperation{
		Kind:             OperationProcessExecute,
		ResourceBindings: testExecutableBindings(),
		Execution: ExecutionContext{
			Connectivity:     ConnectivityConnected,
			ExecutionRootIDs: rootIDs,
			InvokedTargetIDs: targetIDs,
		},
	}) == "" {
		t.Fatal("valid connected context was rejected")
	}
	context := graph.Operations[0].Execution
	if len(context.ExecutionRootIDs) != maxExecutionContextIDs || len(context.InvokedTargetIDs) != maxExecutionContextIDs {
		t.Fatalf("ownership sets are not bounded: roots=%d targets=%d", len(context.ExecutionRootIDs), len(context.InvokedTargetIDs))
	}
	if context.ExecutionRootIDs[0] != "root-0000" || context.ExecutionRootIDs[maxExecutionContextIDs-1] != "root-0063" {
		t.Fatalf("root set is not normalized before truncation: %#v", context.ExecutionRootIDs)
	}
	if context.InvokedTargetIDs[0] != "target-0000" || context.InvokedTargetIDs[maxExecutionContextIDs-1] != "target-0063" {
		t.Fatalf("target set is not normalized before truncation: %#v", context.InvokedTargetIDs)
	}
	if rootIDs[0] != originalFirstRoot {
		t.Fatal("normalization mutated the caller's ownership slice")
	}
}

func testExecutableBindings() []ResourceBinding {
	return Bindings(Bind(ResourceRoleExecutable, NewResource(ResourceFile, "")))
}

func TestExecutionKeyCanonicalizesOwnershipWithoutDelimiterCollisions(t *testing.T) {
	left, err := NewExecutionKey(ExecutionContext{
		Connectivity:     ConnectivityConnected,
		ExecutionRootIDs: []string{"root-b", "root-a", "root-a"},
		InvokedTargetIDs: []string{"target:a,b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewExecutionKey(ExecutionContext{
		Connectivity:     ConnectivityConnected,
		ExecutionRootIDs: []string{"root-a", "root-b"},
		InvokedTargetIDs: []string{"target:a,b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("equivalent ownership sets produced different keys: left=%#v right=%#v", left, right)
	}
	candidate, err := NewExecutionKey(ExecutionContext{
		Connectivity:     ConnectivityConnected,
		ExecutionRootIDs: []string{"root-a", "root-b"},
		InvokedTargetIDs: []string{"target:a", "b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if candidate == left {
		t.Fatal("different target sets collided through delimiter-like values")
	}
	if _, err := NewExecutionKey(ExecutionContext{Connectivity: ConnectivityConnected}); err == nil {
		t.Fatal("contradictory ownership context produced an execution key")
	}
}

func TestContextKeyRetainsExactStaticBoundaryAndExecutionIdentity(t *testing.T) {
	execution := ExecutionContext{Connectivity: ConnectivityConnected, ExecutionRootIDs: []string{"root-main"}}
	caller, err := NewContextKey(execution, "node-main", "scope-caller", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	callee, err := NewContextKey(execution, "node-main", "scope-callee", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	otherArchitecture, err := NewContextKey(execution, "node-main", "scope-caller", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	if caller == callee || caller == otherArchitecture {
		t.Fatalf("distinct static contexts collapsed: caller=%#v callee=%#v other=%#v", caller, callee, otherArchitecture)
	}
	if !caller.SameExecution(callee) || !caller.SameExecution(otherArchitecture) {
		t.Fatal("exact static boundaries lost their shared execution ownership")
	}
	unknown, err := NewContextKey(ExecutionContext{Connectivity: ConnectivityUnknown}, "node-main", "scope-caller", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if caller.SameExecution(unknown) {
		t.Fatal("connected and unknown contexts shared an execution identity")
	}
	if _, err := NewContextKey(execution, "", "scope-caller", "arm64"); err == nil {
		t.Fatal("context without a subject node produced a key")
	}
	keys := []ContextKey{otherArchitecture, callee, caller}
	sort.Slice(keys, func(i, j int) bool { return CompareContextKeys(keys[i], keys[j]) < 0 })
	if CompareContextKeys(keys[0], keys[1]) >= 0 || CompareContextKeys(keys[1], keys[2]) >= 0 {
		t.Fatalf("context ordering is not deterministic: %#v", keys)
	}
}

func TestExecutionRootAndInvokedTargetRequireEvidenceAndUseTypedIDs(t *testing.T) {
	graph := Graph{}
	baseRoot := ExecutionRoot{Kind: "app-main", DeclarationNodeID: "node-plist", StartNodeID: "node-bin"}
	if graph.AddExecutionRoot(baseRoot) != "" {
		t.Fatal("root without evidence was retained")
	}
	baseRoot.EvidenceIDs = []string{"", "ev-0002", "ev-0001", "ev-0001"}
	baseRoot.Arguments = []string{"--second", "--first"}
	if id := graph.AddExecutionRoot(baseRoot); id != "root-0001" {
		t.Fatalf("first retained root ID = %q, want root-0001", id)
	}
	assertStrings(t, graph.ExecutionRoots[0].EvidenceIDs, []string{"ev-0001", "ev-0002"})
	assertStrings(t, graph.ExecutionRoots[0].Arguments, []string{"--second", "--first"})

	baseTarget := InvokedTarget{
		Kind:        "bundle-script",
		NodeID:      "node-script",
		Source:      EntityRef{Kind: EntityKindExecutionRoot, ID: "root-0001"},
		Execution:   ExecutionContext{Connectivity: ConnectivityConnected, ExecutionRootIDs: []string{"root-0001"}},
		EvidenceIDs: []string{""},
	}
	if graph.AddInvokedTarget(baseTarget) != "" {
		t.Fatal("target without retained evidence was accepted")
	}
	baseTarget.EvidenceIDs = []string{"ev-0003"}
	ordinal := 0
	baseTarget.Ordinal = &ordinal
	if id := graph.AddInvokedTarget(baseTarget); id != "target-0001" {
		t.Fatalf("first retained target ID = %q, want target-0001", id)
	}
	ordinal = 99
	if graph.InvokedTargets[0].Ordinal == nil || *graph.InvokedTargets[0].Ordinal != 0 {
		t.Fatalf("target did not retain its own ordinal value: %#v", graph.InvokedTargets[0].Ordinal)
	}

	baseTarget.Source = EntityRef{Kind: "scope", ID: "scope-0001"}
	if graph.AddInvokedTarget(baseTarget) != "" {
		t.Fatal("target with an unsupported source entity kind was retained")
	}
	baseTarget.Source = EntityRef{Kind: EntityKindExecutionRoot, ID: "root-0001"}
	negative := -1
	baseTarget.Ordinal = &negative
	if graph.AddInvokedTarget(baseTarget) != "" {
		t.Fatal("target with a negative ordinal was retained")
	}
	baseTarget.Ordinal = nil
	baseTarget.Kind = ""
	if graph.AddInvokedTarget(baseTarget) != "" {
		t.Fatal("target without a kind was retained")
	}
}

func TestAnalysisSelectionMergesOneBoundedRecordPerNode(t *testing.T) {
	graph := Graph{ItemLimit: 1}
	if !graph.AddAnalysisSelection(AnalysisSelection{
		NodeID:  "node-0001",
		Reasons: []SelectionReason{SelectionReasonRunnableCandidate, SelectionReasonDefaultRelevant, SelectionReasonRunnableCandidate},
	}) {
		t.Fatal("first node selection was rejected")
	}
	if !graph.AddAnalysisSelection(AnalysisSelection{
		NodeID:  "node-0001",
		Reasons: []SelectionReason{SelectionReasonRawFeatures, SelectionReasonDeclaredEntry},
	}) {
		t.Fatal("adding a reason to an existing selection should not consume another item")
	}
	if len(graph.AnalysisSelections) != 1 {
		t.Fatalf("selection count = %d, want one record per node", len(graph.AnalysisSelections))
	}
	assertSelectionReasons(t, graph.AnalysisSelections[0].Reasons, []SelectionReason{
		SelectionReasonDeclaredEntry,
		SelectionReasonDefaultRelevant,
		SelectionReasonRawFeatures,
		SelectionReasonRunnableCandidate,
	})
	if graph.AddAnalysisSelection(AnalysisSelection{NodeID: "node-0002", Reasons: []SelectionReason{SelectionReasonExecutionRoot}}) {
		t.Fatal("a second selection should respect the shared item limit")
	}
	if graph.AddAnalysisSelection(AnalysisSelection{NodeID: "node-0001", Reasons: []SelectionReason{"arbitrary"}}) {
		t.Fatal("an unknown selection reason was retained")
	}
}

func TestNewExecutionCollectionsShareGraphItemLimit(t *testing.T) {
	graph := Graph{ItemLimit: 3}
	rootID := graph.AddExecutionRoot(ExecutionRoot{
		Kind:              "app-main",
		DeclarationNodeID: "node-plist",
		StartNodeID:       "node-bin",
		EvidenceIDs:       []string{"ev-root"},
	})
	if rootID == "" {
		t.Fatal("root should fit")
	}
	if graph.AddInvokedTarget(InvokedTarget{
		Kind:        "bundle-script",
		NodeID:      "node-script",
		Source:      EntityRef{Kind: EntityKindExecutionRoot, ID: rootID},
		Execution:   ExecutionContext{Connectivity: ConnectivityConnected, ExecutionRootIDs: []string{rootID}},
		EvidenceIDs: []string{"ev-target"},
	}) == "" {
		t.Fatal("target should fit")
	}
	if !graph.AddAnalysisSelection(AnalysisSelection{NodeID: "node-script", Reasons: []SelectionReason{SelectionReasonInvokedTarget}}) {
		t.Fatal("selection should fit")
	}
	if graph.AddOperation(ModeledOperation{Kind: "over-limit"}) != "" {
		t.Fatal("new execution collections did not consume the shared item budget")
	}
}
