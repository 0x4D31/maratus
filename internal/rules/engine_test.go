package rules

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func connectedExecution(rootIDs ...string) behavior.ExecutionContext {
	return behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: rootIDs}
}

func connectedExecutionWithTargets(rootIDs, targetIDs []string) behavior.ExecutionContext {
	return behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: rootIDs, InvokedTargetIDs: targetIDs}
}

func unconnectedExecution() behavior.ExecutionContext {
	return behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnconnected}
}

func unknownExecution() behavior.ExecutionContext {
	return behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
}

func manyCapabilityMatchCandidates(id string, count int) []behavior.CapabilityMatch {
	out := make([]behavior.CapabilityMatch, count)
	for i := range out {
		out[i] = behavior.CapabilityMatch{
			RuleID: id, Support: behavior.SupportCorroborated,
			SubjectNodeID: fmt.Sprintf("node-%05d", i),
		}
	}
	return out
}

func mergeCandidateBatchesForTest(graph *behavior.Graph, batches ...[]behavior.CapabilityMatch) []behavior.CapabilityMatch {
	resetRuleEvaluationCoverage(graph)
	return mergeCapabilityMatchCandidateBatches(graph, batches)
}

func evaluateCompiledSpecForTest(graph *behavior.Graph, rule compiledSpec) []behavior.CapabilityMatch {
	return rule.evaluateIndexed(newAnalysisView(graph, newRuleWorkBudget(graph)), newRuleWorkBudget(graph))
}

func TestEvaluateBoundsCapabilityMatchesAndMarksPartialCoverage(t *testing.T) {
	graph := behavior.Graph{}
	var batches [][]behavior.CapabilityMatch
	for i := 0; i < 5; i++ {
		batches = append(batches, manyCapabilityMatchCandidates(fmt.Sprintf("rule-%d", i), maxCapabilityMatchesPerRule+10))
	}
	capabilityMatches := mergeCandidateBatchesForTest(&graph, batches...)
	if len(capabilityMatches) != DefaultCapabilityMatchLimit {
		t.Fatalf("capabilityMatch count = %d, want global limit %d", len(capabilityMatches), DefaultCapabilityMatchLimit)
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "rule-evaluation" || graph.Coverage[0].Status != "partial" {
		t.Fatalf("missing explicit partial rule coverage: %#v", graph.Coverage)
	}
	if !strings.Contains(graph.Coverage[0].Detail, fmt.Sprint(DefaultCapabilityMatchLimit)) || !strings.Contains(graph.Coverage[0].Detail, fmt.Sprint(maxCapabilityMatchesPerRule)) {
		t.Fatalf("rule limit detail is incomplete: %#v", graph.Coverage[0])
	}

	mergeCandidateBatchesForTest(&graph, batches[:1]...)
	if len(graph.Coverage) != 1 {
		t.Fatalf("repeated evaluation duplicated the partial marker: %#v", graph.Coverage)
	}
}

func TestRuleMarkerFitsBehaviorPostLimitAllowance(t *testing.T) {
	graph := behavior.Graph{ItemLimit: 1}
	if graph.AddScope(behavior.Scope{Kind: "fixture"}) == "" {
		t.Fatal("first behavior item should fit")
	}
	if graph.AddScope(behavior.Scope{Kind: "omitted"}) != "" {
		t.Fatal("second behavior item should exceed the extraction limit")
	}
	graph.FinalizeLimits()
	_ = mergeCandidateBatchesForTest(&graph, manyCapabilityMatchCandidates("many", maxCapabilityMatchesPerRule+1))

	if got, want := len(graph.Scopes)+len(graph.Coverage), graph.ItemLimit+behavior.PostLimitCoverageAllowance; got != want {
		t.Fatalf("bounded graph has %d behavior items, want %d including mandatory markers", got, want)
	}
	for _, area := range []string{"behavior-ir", "rule-evaluation"} {
		found := false
		for _, coverage := range graph.Coverage {
			found = found || coverage.AnalysisArea == area && coverage.Status == "partial"
		}
		if !found {
			t.Fatalf("missing %s marker: %#v", area, graph.Coverage)
		}
	}
}

func TestEvaluateBoundsRetainedCapabilityMatchStringsIncludingResources(t *testing.T) {
	resources := make([]behavior.Resource, maxCapabilityMatchResources)
	for i := range resources {
		prefix := fmt.Sprintf("resource-%02d-", i)
		resources[i] = behavior.NewResource(behavior.ResourceFile, prefix+strings.Repeat("x", maxCapabilityMatchValueBytes-len(prefix)))
	}
	candidates := make([]behavior.CapabilityMatch, 200)
	for i := range candidates {
		candidates[i] = behavior.CapabilityMatch{
			RuleID:            "large",
			Support:           behavior.SupportCorroborated,
			SubjectNodeID:     fmt.Sprintf("node-%03d", i),
			AffectedResources: resources,
		}
	}
	graph := behavior.Graph{}
	got := mergeCandidateBatchesForTest(&graph, candidates)
	if len(got) == 0 || len(got) >= len(candidates) {
		t.Fatalf("retained capabilityMatches = %d, want a non-empty prefix bounded below %d", len(got), len(candidates))
	}
	var retained int64
	for _, capabilityMatch := range got {
		retained += capabilityMatchStringBytes(capabilityMatch)
	}
	if retained > DefaultCapabilityMatchStringBytes {
		t.Fatalf("retained capabilityMatch strings = %d, exceeds %d", retained, DefaultCapabilityMatchStringBytes)
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "rule-evaluation" || graph.Coverage[0].Status != "partial" {
		t.Fatalf("capabilityMatch string budget was not surfaced: %#v", graph.Coverage)
	}
}

func TestEvaluateChargesSerializedCapabilityMatchStringExpansion(t *testing.T) {
	// Each control byte is six bytes in JSON. Repeating the same value across
	// capabilityMatches must consume the serialized-output budget, even though its raw Go
	// string is much smaller.
	value := strings.Repeat("\x01", maxCapabilityMatchValueBytes)
	candidates := make([]behavior.CapabilityMatch, 1000)
	for i := range candidates {
		candidates[i] = behavior.CapabilityMatch{
			RuleID:            "expanded-json",
			Support:           behavior.SupportCorroborated,
			SubjectNodeID:     fmt.Sprintf("node-%04d", i),
			AffectedResources: []behavior.Resource{behavior.NewResource(behavior.ResourceFile, value)},
		}
	}
	graph := behavior.Graph{}
	got := mergeCandidateBatchesForTest(&graph, candidates)
	if len(got) == 0 || len(got) >= len(candidates) {
		t.Fatalf("retained capabilityMatches = %d, want a non-empty serialized-budget prefix", len(got))
	}
	var retained int64
	for _, capabilityMatch := range got {
		retained += capabilityMatchStringBytes(capabilityMatch)
	}
	if retained > DefaultCapabilityMatchStringBytes {
		t.Fatalf("serialized capabilityMatch strings = %d, exceeds %d", retained, DefaultCapabilityMatchStringBytes)
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "rule-evaluation" || graph.Coverage[0].Status != "partial" {
		t.Fatalf("serialized capabilityMatch budget was not surfaced: %#v", graph.Coverage)
	}
}

func TestCapabilityMatchComparatorDoesNotAllocateConcatenatedKeys(t *testing.T) {
	prefix := strings.Repeat("x", maxCapabilityMatchValueBytes-1)
	left, _ := normalizeCapabilityMatch(behavior.CapabilityMatch{
		RuleID: "same", Support: behavior.SupportCorroborated, SubjectNodeID: "same",
		AffectedResources: []behavior.Resource{behavior.NewResource(behavior.ResourceFile, prefix+"a")},
	})
	right, _ := normalizeCapabilityMatch(behavior.CapabilityMatch{
		RuleID: "same", Support: behavior.SupportCorroborated, SubjectNodeID: "same",
		AffectedResources: []behavior.Resource{behavior.NewResource(behavior.ResourceFile, prefix+"z")},
	})
	allocations := testing.AllocsPerRun(1000, func() {
		if compareCapabilityMatches(left, right) >= 0 {
			panic("unexpected capabilityMatch order")
		}
	})
	if allocations != 0 {
		t.Fatalf("capabilityMatch comparator allocated %.2f objects per comparison", allocations)
	}
}

func TestEvaluateNormalizesHostileCapabilityMatchFieldsBeforeSorting(t *testing.T) {
	large := strings.Repeat("x", maxCapabilityMatchValueBytes+1024)
	resources := make([]behavior.Resource, maxCapabilityMatchResources+20)
	for i := range resources {
		resources[i] = behavior.NewResource(behavior.ResourceFile, large)
	}
	evidenceIDs := make([]string, maxCapabilityMatchEvidence+20)
	for i := range evidenceIDs {
		evidenceIDs[i] = fmt.Sprintf("%03d-%s", i, large)
	}
	graph := behavior.Graph{}
	got := mergeCandidateBatchesForTest(&graph, []behavior.CapabilityMatch{{
		ID:        large,
		RuleID:    large,
		Title:     large,
		Namespace: large,
		Support:   behavior.Support(large),
		Execution: behavior.ExecutionContext{
			Connectivity:     behavior.Connectivity(large),
			ExecutionRootIDs: []string{large},
		},
		SubjectNodeID:     large,
		AffectedResources: resources,
		EvidenceIDs:       evidenceIDs,
	}})
	if len(got) != 1 {
		t.Fatalf("capabilityMatches = %#v", got)
	}
	capabilityMatch := got[0]
	if len(capabilityMatch.ID) > maxCapabilityMatchIDBytes || len(capabilityMatch.RuleID) > maxCapabilityMatchIDBytes ||
		len(capabilityMatch.Title) > maxCapabilityMatchLabelBytes || len(capabilityMatch.SubjectNodeID) > maxCapabilityMatchIDBytes ||
		len(capabilityMatch.AffectedResources) > maxCapabilityMatchResources || len(capabilityMatch.EvidenceIDs) > maxCapabilityMatchEvidence {
		t.Fatalf("capabilityMatch was not normalized before retention: %#v", capabilityMatch)
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].Status != "partial" {
		t.Fatalf("field truncation was not surfaced: %#v", graph.Coverage)
	}
}

func TestCapabilityMatchBoundsRepeatedEvidenceAndResources(t *testing.T) {
	var evidenceIDs []string
	var resources []behavior.Resource
	var operations []behavior.ModeledOperation
	for i := 0; i < 1000; i++ {
		evidenceIDs = append(evidenceIDs, fmt.Sprintf("ev-%04d", i))
		resources = append(resources, behavior.Resource{Kind: behavior.ResourceFile, Value: fmt.Sprintf("/tmp/%04d", i)})
		operations = append(operations, behavior.ModeledOperation{ID: fmt.Sprintf("operation-%04d", i), Execution: connectedExecution("root-main")})
	}
	got := capabilityMatch(Metadata{ID: "bounded"}, behavior.SupportCorroborated, operations, "node", resources, evidenceIDs, nil)
	if len(got.OperationIDs) != maxCapabilityMatchOperations || len(got.EvidenceIDs) != maxCapabilityMatchEvidence || len(got.AffectedResources) != maxCapabilityMatchResources {
		t.Fatalf("capability-match collections are not bounded: operations=%d evidence=%d resources=%d", len(got.OperationIDs), len(got.EvidenceIDs), len(got.AffectedResources))
	}
}

func TestRuleWorkBudgetMarksPartialCoverage(t *testing.T) {
	graph := behavior.Graph{}
	budget := newRuleWorkBudget(&graph)
	if !budget.charge(maxRuleMatchWork) || budget.charge(1) {
		t.Fatal("rule matching work budget did not enforce its hard limit")
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "rule-evaluation" || graph.Coverage[0].Status != "partial" || !strings.Contains(graph.Coverage[0].Detail, fmt.Sprint(maxRuleMatchWork)) {
		t.Fatalf("correlation exhaustion was not reported: %#v", graph.Coverage)
	}
}

func TestExecutionIDNormalizationBoundsAfterCanonicalSortAndDedup(t *testing.T) {
	values := make([]string, 0, maxCapabilityMatchExecutionIDs+2)
	for i := 0; i < maxCapabilityMatchExecutionIDs+1; i++ {
		values = append(values, fmt.Sprintf("root-%03d", i+1))
	}
	values = append(values, "root-000")
	got, partial := normalizeCapabilityMatch(behavior.CapabilityMatch{
		Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: values},
	})
	if !partial || len(got.Execution.ExecutionRootIDs) != maxCapabilityMatchExecutionIDs || got.Execution.ExecutionRootIDs[0] != "root-000" || got.Execution.ExecutionRootIDs[maxCapabilityMatchExecutionIDs-1] != "root-063" {
		t.Fatalf("execution IDs were truncated before canonical normalization: %#v", got.Execution.ExecutionRootIDs)
	}
}

func TestEvaluateAssignsCapabilityMatchIDsAfterSorting(t *testing.T) {
	capabilityMatches := mergeCandidateBatchesForTest(&behavior.Graph{},
		[]behavior.CapabilityMatch{{RuleID: "z-supported", Support: behavior.SupportCorroborated, SubjectNodeID: "node-2"}},
		[]behavior.CapabilityMatch{{RuleID: "a-proven", Support: behavior.SupportDirect, SubjectNodeID: "node-1"}},
	)
	if len(capabilityMatches) != 2 {
		t.Fatalf("capabilityMatches = %#v", capabilityMatches)
	}
	if capabilityMatches[0].RuleID != "a-proven" || capabilityMatches[0].ID != "match-0001" {
		t.Fatalf("first capabilityMatch not sorted/id-assigned correctly: %#v", capabilityMatches)
	}
	if capabilityMatches[1].RuleID != "z-supported" || capabilityMatches[1].ID != "match-0002" {
		t.Fatalf("second capabilityMatch not sorted/id-assigned correctly: %#v", capabilityMatches)
	}
}

func TestEvaluateSortsCapabilityMatchesByResourceBeforeAssigningIDs(t *testing.T) {
	capabilityMatches := mergeCandidateBatchesForTest(&behavior.Graph{},
		[]behavior.CapabilityMatch{{
			RuleID:            "macos.same",
			Support:           behavior.SupportCorroborated,
			SubjectNodeID:     "node-1",
			AffectedResources: []behavior.Resource{behavior.NewResource(behavior.ResourceFile, "/tmp/z")},
		}},
		[]behavior.CapabilityMatch{{
			RuleID:            "macos.same",
			Support:           behavior.SupportCorroborated,
			SubjectNodeID:     "node-1",
			AffectedResources: []behavior.Resource{behavior.NewResource(behavior.ResourceFile, "/tmp/a")},
		}},
	)
	if len(capabilityMatches) != 2 {
		t.Fatalf("capabilityMatches = %#v", capabilityMatches)
	}
	if capabilityMatches[0].AffectedResources[0].Value != "/tmp/a" || capabilityMatches[0].ID != "match-0001" {
		t.Fatalf("resource tie-breaker should produce stable first capabilityMatch: %#v", capabilityMatches)
	}
	if capabilityMatches[1].AffectedResources[0].Value != "/tmp/z" || capabilityMatches[1].ID != "match-0002" {
		t.Fatalf("resource tie-breaker should produce stable second capabilityMatch: %#v", capabilityMatches)
	}
}

func TestEvaluateRebuildsRuleCoverageWithoutTrustingCallerMarker(t *testing.T) {
	graph := behavior.Graph{Coverage: []behavior.Coverage{
		{AnalysisArea: "fixture", Status: "partial", Detail: "retained"},
		{AnalysisArea: "rule-evaluation", Status: "partial", Detail: "forged"},
	}}
	if matches := evaluateCompiledRules(&graph, nil); len(matches) != 0 {
		t.Fatalf("empty rule set produced matches: %#v", matches)
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "fixture" {
		t.Fatalf("rule engine trusted or removed the wrong coverage: %#v", graph.Coverage)
	}
}

func TestEqualCapabilityMatchSetsIsExactOrderIndependentAndNonMutating(t *testing.T) {
	match := func(id, value string) behavior.CapabilityMatch {
		return behavior.CapabilityMatch{
			ID:                 id,
			RuleID:             "test.exact",
			Title:              "Exact",
			Namespace:          "test",
			Support:            behavior.SupportCorroborated,
			Execution:          unknownExecution(),
			SubjectNodeID:      "node-1",
			AffectedResources:  []behavior.Resource{behavior.NewResource(behavior.ResourceFile, value)},
			OperationIDs:       []string{"operation-1"},
			EvidenceIDs:        []string{"ev-1"},
			ArchitectureScopes: []string{"arm64"},
			MatchTrace: []behavior.MatchTraceClause{{
				Path: "match", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"},
			}},
		}
	}
	left := []behavior.CapabilityMatch{match("match-1", "/tmp/a"), match("match-2", "/tmp/b")}
	right := []behavior.CapabilityMatch{match("match-2", "/tmp/b"), match("match-1", "/tmp/a")}
	leftBefore := append([]behavior.CapabilityMatch(nil), left...)
	rightBefore := append([]behavior.CapabilityMatch(nil), right...)
	if !EqualCapabilityMatchSets(left, right) {
		t.Fatal("equal capability sets differed only by top-level order")
	}
	if !reflect.DeepEqual(left, leftBefore) || !reflect.DeepEqual(right, rightBefore) {
		t.Fatal("exact capability comparison mutated an input")
	}

	right[1].AffectedResources[0].Value = "/tmp/" + strings.Repeat("a", maxCapabilityMatchValueBytes+1)
	if EqualCapabilityMatchSets(left, right) {
		t.Fatal("exact capability comparison normalized away a lossy resource difference")
	}
}

func TestBuiltinRuleMetadataIncludesDescriptions(t *testing.T) {
	for _, rule := range compiledBuiltins() {
		meta := rule.spec.Metadata
		if meta.ID == "" || meta.Title == "" || meta.Namespace == "" || meta.Description == "" {
			t.Fatalf("rule metadata should be complete enough for JSON listing: %#v", meta)
		}
	}
}

func TestBuiltinRuleMetadataIsUniqueAndRegistered(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range compiledBuiltins() {
		meta := rule.spec.Metadata
		if seen[meta.ID] {
			t.Fatalf("duplicate built-in rule ID %q", meta.ID)
		}
		seen[meta.ID] = true
		if _, ok := SpecByID(meta.ID); !ok {
			t.Fatalf("built-in rule %q has no generated Spec declaration", meta.ID)
		}
	}
	if len(seen) != len(Specs()) {
		t.Fatalf("generated catalog has %d specs but %d built-in rules are registered", len(Specs()), len(seen))
	}
}

func TestValidateSpecsReturnsStableSortedDiagnostics(t *testing.T) {
	diagnostics := ValidateSpecs([]Spec{
		{Metadata: Metadata{ID: "Bad ID"}},
		{Metadata: Metadata{ID: "duplicate", Title: "one", Namespace: "test", Description: "one"}, Kind: CapabilityRule, Match: Operation(behavior.OperationClipboardRead), MinimumSupport: behavior.SupportCorroborated},
		{Metadata: Metadata{ID: "duplicate", Title: "two", Namespace: "test", Description: "two"}, Kind: CapabilityRule, Match: Operation(behavior.OperationClipboardRead), MinimumSupport: behavior.SupportCorroborated},
	})
	if len(diagnostics) < 5 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	for i := 1; i < len(diagnostics); i++ {
		left, right := diagnostics[i-1], diagnostics[i]
		if left.RuleID > right.RuleID || left.RuleID == right.RuleID && left.Code > right.Code {
			t.Fatalf("diagnostics are not deterministic: %#v", diagnostics)
		}
	}
	foundDuplicate := false
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == "RULE_ID_DUPLICATE" && diagnostic.RuleID == "duplicate" {
			foundDuplicate = true
		}
	}
	if !foundDuplicate {
		t.Fatalf("missing duplicate diagnostic: %#v", diagnostics)
	}
}

func TestCapabilityMatchCopiesSingleOperationExecutionContext(t *testing.T) {
	operation := behavior.ModeledOperation{
		ID: "operation-1",
		Execution: connectedExecutionWithTargets(
			[]string{"root-z", "root-a", "root-z"},
			[]string{"target-z", "target-a", "target-z"},
		),
	}
	match := capabilityMatch(Metadata{ID: "copy"}, behavior.SupportCorroborated, []behavior.ModeledOperation{operation}, "node", nil, nil, nil)
	if match.Execution.Connectivity != behavior.ConnectivityConnected ||
		!sameStrings(match.Execution.ExecutionRootIDs, []string{"root-a", "root-z"}) ||
		!sameStrings(match.Execution.InvokedTargetIDs, []string{"target-a", "target-z"}) {
		t.Fatalf("single-operation execution context was not copied and normalized: %#v", match.Execution)
	}

	operation.Execution.ExecutionRootIDs[0] = "mutated-root"
	operation.Execution.InvokedTargetIDs[0] = "mutated-target"
	if !sameStrings(match.Execution.ExecutionRootIDs, []string{"root-a", "root-z"}) ||
		!sameStrings(match.Execution.InvokedTargetIDs, []string{"target-a", "target-z"}) {
		t.Fatalf("capability match aliases its supporting operation execution context: %#v", match.Execution)
	}
}

func TestCapabilityMatchIntersectsConnectedRootsAndTargets(t *testing.T) {
	operations := []behavior.ModeledOperation{
		{ID: "operation-left", Execution: connectedExecutionWithTargets([]string{"root-left", "root-shared"}, []string{"target-left"})},
		{ID: "operation-right", Execution: connectedExecutionWithTargets([]string{"root-right", "root-shared"}, []string{"target-right"})},
	}
	match := capabilityMatch(Metadata{ID: "intersection"}, behavior.SupportCorroborated, operations, "node", nil, nil, nil)
	if match.Execution.Connectivity != behavior.ConnectivityConnected ||
		!sameStrings(match.Execution.ExecutionRootIDs, []string{"root-shared"}) ||
		len(match.Execution.InvokedTargetIDs) != 0 {
		t.Fatalf("compatible execution contexts were not intersected safely: %#v", match.Execution)
	}
}

func TestCapabilityMatchExecutionFallsBackConservatively(t *testing.T) {
	tests := []struct {
		name  string
		left  behavior.ExecutionContext
		right behavior.ExecutionContext
		want  behavior.Connectivity
	}{
		{
			name:  "disjoint connected roots",
			left:  connectedExecutionWithTargets([]string{"root-left"}, []string{"target-left"}),
			right: connectedExecutionWithTargets([]string{"root-right"}, []string{"target-right"}),
			want:  behavior.ConnectivityUnknown,
		},
		{
			name:  "all unconnected",
			left:  unconnectedExecution(),
			right: unconnectedExecution(),
			want:  behavior.ConnectivityUnconnected,
		},
		{
			name:  "unknown and unconnected",
			left:  unknownExecution(),
			right: unconnectedExecution(),
			want:  behavior.ConnectivityUnknown,
		},
		{
			name:  "connected and unknown",
			left:  connectedExecution("root-main"),
			right: unknownExecution(),
			want:  behavior.ConnectivityUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			match := capabilityMatch(Metadata{ID: "fallback"}, behavior.SupportCorroborated, []behavior.ModeledOperation{
				{ID: "operation-left", Execution: test.left},
				{ID: "operation-right", Execution: test.right},
			}, "node", nil, nil, nil)
			if match.Execution.Connectivity != test.want || len(match.Execution.ExecutionRootIDs) != 0 || len(match.Execution.InvokedTargetIDs) != 0 {
				t.Fatalf("unsafe execution aggregation for %s: %#v", test.name, match.Execution)
			}
		})
	}
}

func TestCapabilityMatchExecutionUsesSupportingOperationsBeyondOutputIDLimit(t *testing.T) {
	operations := make([]behavior.ModeledOperation, maxCapabilityMatchOperations+1)
	for i := range operations {
		operations[i] = behavior.ModeledOperation{ID: fmt.Sprintf("operation-%03d", i), Execution: connectedExecution("root-main")}
	}
	operations[len(operations)-1].Execution = connectedExecution("root-disjoint")

	match := capabilityMatch(Metadata{ID: "bounded"}, behavior.SupportCorroborated, operations, "node", nil, nil, nil)
	if len(match.OperationIDs) != maxCapabilityMatchOperations {
		t.Fatalf("operation ID output is not bounded: %d", len(match.OperationIDs))
	}
	if match.Execution.Connectivity != behavior.ConnectivityUnknown || len(match.Execution.ExecutionRootIDs) != 0 {
		t.Fatalf("omitted operation IDs caused execution connectivity to be overclaimed: %#v", match.Execution)
	}
}

func TestCapabilityMatchTargetIntersectionIsCanonicalAndOrderIndependent(t *testing.T) {
	lowTargets := make([]string, maxCapabilityMatchExecutionIDs)
	highTargets := make([]string, maxCapabilityMatchExecutionIDs)
	for i := 0; i < maxCapabilityMatchExecutionIDs; i++ {
		lowTargets[i] = fmt.Sprintf("target-%03d", i)
		highTargets[i] = fmt.Sprintf("target-%03d", i+maxCapabilityMatchExecutionIDs/2)
	}
	low := behavior.ModeledOperation{ID: "operation-low", Execution: connectedExecutionWithTargets([]string{"root-main"}, lowTargets)}
	high := behavior.ModeledOperation{ID: "operation-high", Execution: connectedExecutionWithTargets([]string{"root-main"}, highTargets)}

	forward := executionForOperations([]behavior.ModeledOperation{high, low})
	reverse := executionForOperations([]behavior.ModeledOperation{low, high})
	want := lowTargets[maxCapabilityMatchExecutionIDs/2:]
	if !sameStrings(forward.InvokedTargetIDs, reverse.InvokedTargetIDs) ||
		!sameStrings(forward.InvokedTargetIDs, want) {
		t.Fatalf("target intersection is not canonical: forward=%#v reverse=%#v", forward, reverse)
	}
}
