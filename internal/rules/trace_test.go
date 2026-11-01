package rules

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestRuleEngineProjectsExactSuccessfulMatchTrace(t *testing.T) {
	t.Run("any operation", func(t *testing.T) {
		graph := behavior.Graph{Operations: []behavior.ModeledOperation{clipboardOperation("operation-1", behavior.SupportDirect)}}
		spec := traceTestSpec(Any(Operation(behavior.OperationClipboardRead), Operation(behavior.OperationScreenCapture)))
		assertRuleTrace(t, evaluateCompiledSpecForTest(&graph, compiledSpec{spec: spec}), []behavior.MatchTraceClause{{
			Path: "match.any[0]", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"},
		}})
	})

	t.Run("operation feature conjunction", func(t *testing.T) {
		operation := clipboardOperation("operation-1", behavior.SupportDirect)
		graph := behavior.Graph{
			Operations: []behavior.ModeledOperation{operation},
			Features: []behavior.Feature{{
				ID: "feature-1", NodeID: operation.SubjectNodeID, ScopeID: operation.ScopeID, Architecture: operation.Architecture,
				Key: "macho.import_call", EvidenceIDs: append([]string(nil), operation.EvidenceIDs...),
				Support: behavior.SupportCorroborated, Execution: operation.Execution,
			}},
		}
		spec := traceTestSpec(Each(Operation(behavior.OperationClipboardRead), Feature("macho.import_call"), SameContext(), SharedEvidence()))
		assertRuleTrace(t, evaluateCompiledSpecForTest(&graph, compiledSpec{spec: spec}), []behavior.MatchTraceClause{
			{Path: "match.each.left", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"}},
			{Path: "match.each.right", Kind: behavior.MatchTraceFeature, FeatureIDs: []string{"feature-1"}},
		})
	})

	t.Run("operation execution-root conjunction", func(t *testing.T) {
		operation := clipboardOperation("operation-1", behavior.SupportCorroborated)
		graph := behavior.Graph{
			Operations: []behavior.ModeledOperation{operation},
			ExecutionRoots: []behavior.ExecutionRoot{{
				ID: "root-main", Kind: "npm-script", Name: "postinstall", DeclarationNodeID: "node-1", StartNodeID: "node-1", EvidenceIDs: []string{"ev-root"},
			}},
		}
		spec := traceTestSpec(Each(Operation(behavior.OperationClipboardRead), ExecutionRoot("npm-script", "postinstall"), SameExecutionRoot()))
		assertRuleTrace(t, evaluateCompiledSpecForTest(&graph, compiledSpec{spec: spec}), []behavior.MatchTraceClause{
			{Path: "match.each.left", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"}},
			{Path: "match.each.right", Kind: behavior.MatchTraceExecutionRoot, ExecutionRootIDs: []string{"root-main"}},
		})
	})

	t.Run("related operations", func(t *testing.T) {
		left := clipboardOperation("operation-left", behavior.SupportDirect)
		right := clipboardOperation("operation-right", behavior.SupportDirect)
		right.Kind = behavior.OperationScreenCapture
		right.ResourceBindings = behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceScreen, "")))
		graph := behavior.Graph{
			Operations: []behavior.ModeledOperation{left, right},
			Relations: []behavior.OperationRelation{{
				ID: "relation-1", Kind: behavior.RelationPipesTo,
				From:        behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, left.ID),
				To:          behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, right.ID),
				EvidenceIDs: []string{"ev-relation"}, Support: behavior.SupportDirect,
				Execution: left.Execution, Architecture: left.Architecture,
			}},
		}
		spec := traceTestSpec(Relate(Operation(behavior.OperationClipboardRead), Operation(behavior.OperationScreenCapture), RelatedBy(behavior.RelationPipesTo)))
		assertRuleTrace(t, evaluateCompiledSpecForTest(&graph, compiledSpec{spec: spec}), []behavior.MatchTraceClause{
			{Path: "match.relate.constraint", Kind: behavior.MatchTraceOperationRelation, RelationIDs: []string{"relation-1"}},
			{Path: "match.relate.left", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-left"}},
			{Path: "match.relate.right", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-right"}},
		})
	})
}

func TestMatchTraceIsBoundedCanonicalAndPartOfMatchIdentity(t *testing.T) {
	clauses := make([]behavior.MatchTraceClause, maxCapabilityMatchTraceInputs+1)
	for index := range clauses {
		clauses[index] = operationTrace("match.any[0]", "operation-z", "operation-a", "operation-a")
	}
	normalized, partial := normalizeMatchTrace(clauses)
	if !partial || len(normalized) != 1 || !reflect.DeepEqual(normalized[0].OperationIDs, []string{"operation-a", "operation-z"}) {
		t.Fatalf("normalized trace = %#v, partial=%v", normalized, partial)
	}

	left := behavior.CapabilityMatch{RuleID: "test", MatchTrace: []behavior.MatchTraceClause{operationTrace("match.any[0]", "operation-1")}}
	right := left
	right.MatchTrace = []behavior.MatchTraceClause{operationTrace("match.any[1]", "operation-1")}
	if capabilityMatchesEqual(left, right) {
		t.Fatal("different successful proof paths were deduplicated")
	}
}

func TestGroupedPrimitiveMatchTraceRetainsEverySupportingOperation(t *testing.T) {
	graph := behavior.Graph{Operations: make([]behavior.ModeledOperation, 0, maxCapabilityMatchOperations)}
	for index := 0; index < maxCapabilityMatchOperations; index++ {
		graph.Operations = append(graph.Operations, clipboardOperation(fmt.Sprintf("operation-%02d", index), behavior.SupportCorroborated))
	}
	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: traceTestSpec(Operation(behavior.OperationClipboardRead))})
	if len(matches) != 1 {
		t.Fatalf("grouped matches = %#v", matches)
	}
	trace, partial := normalizeMatchTrace(matches[0].MatchTrace)
	if partial || len(trace) != 1 || !slices.Equal(trace[0].OperationIDs, matches[0].OperationIDs) {
		t.Fatalf("grouped operation trace = %#v, operations=%#v, partial=%v", trace, matches[0].OperationIDs, partial)
	}
}

func traceTestSpec(match Pattern) Spec {
	return Spec{
		Metadata: Metadata{ID: "test.trace", Title: "Trace", Namespace: "test", Description: "Tests successful match trace projection."},
		Kind:     CapabilityRule, Match: match, MinimumSupport: behavior.SupportCorroborated,
	}
}

func assertRuleTrace(t *testing.T, matches []behavior.CapabilityMatch, want []behavior.MatchTraceClause) {
	t.Helper()
	if len(matches) != 1 {
		t.Fatalf("matches = %#v", matches)
	}
	got, partial := normalizeMatchTrace(matches[0].MatchTrace)
	if partial || !reflect.DeepEqual(got, want) {
		t.Fatalf("match trace = %#v, want %#v, partial=%v", got, want, partial)
	}
}
