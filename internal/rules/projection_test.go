package rules

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestEvaluateOmitsOverlongAffectedResourceWithoutChangingBoundIdentity(t *testing.T) {
	value := "/tmp/" + strings.Repeat("a", maxCapabilityMatchValueBytes)
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{{
		ID:            "operation-1",
		SubjectNodeID: "node-1",
		ScopeID:       "scope-1",
		Kind:          behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, value)),
		),
		EvidenceIDs: []string{"ev-1"},
		Support:     behavior.SupportCorroborated,
		Execution:   unknownExecution(),
	}}}

	matches := evaluateCompiledRules(&graph, []compiledSpec{{spec: MacOSFileExecution}})
	if len(matches) != 1 {
		t.Fatalf("file-execution matches = %#v, want one match", matches)
	}
	match := matches[0]
	if len(match.AffectedResources) != 0 {
		t.Fatalf("overlong resource was rewritten into a false identity: %#v", match.AffectedResources)
	}
	if !sameStrings(match.OperationIDs, []string{"operation-1"}) || !sameStrings(match.EvidenceIDs, []string{"ev-1"}) {
		t.Fatalf("match lost its retained supporting facts: %#v", match)
	}
	assertPartialRuleProjection(t, graph)
}

func TestEvaluateDerivesEvidenceFromFinalOperationTrace(t *testing.T) {
	graph := behavior.Graph{Operations: make([]behavior.ModeledOperation, 0, maxCapabilityMatchOperations+1)}
	for index := 0; index <= maxCapabilityMatchOperations; index++ {
		evidenceID := "ev-shared"
		if index < maxCapabilityMatchOperations-1 {
			evidenceID = fmt.Sprintf("ev-%04d", index)
		}
		if index == maxCapabilityMatchOperations {
			evidenceID = "ev-late"
		}
		graph.Operations = append(graph.Operations, behavior.ModeledOperation{
			ID:            fmt.Sprintf("operation-%04d", index),
			SubjectNodeID: "node-1",
			ScopeID:       "scope-1",
			Kind:          behavior.OperationProcessExecute,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/bin/sh")),
			),
			EvidenceIDs: []string{evidenceID},
			Support:     behavior.SupportCorroborated,
			Execution:   unknownExecution(),
		})
	}

	first := evaluateCompiledRules(&graph, []compiledSpec{{spec: MacOSFileExecution}})
	second := evaluateCompiledRules(&graph, []compiledSpec{{spec: MacOSFileExecution}})
	if !reflect.DeepEqual(first, second) || len(first) != 1 {
		t.Fatalf("bounded operation projection is nondeterministic: first=%#v second=%#v", first, second)
	}
	match := first[0]
	if len(match.OperationIDs) != maxCapabilityMatchOperations {
		t.Fatalf("operation IDs = %d, want %d", len(match.OperationIDs), maxCapabilityMatchOperations)
	}
	if slices.Contains(match.EvidenceIDs, "ev-late") {
		t.Fatalf("evidence from omitted operation survived final trace: %#v", match)
	}
	if len(match.EvidenceIDs) != maxCapabilityMatchOperations {
		t.Fatalf("retained evidence = %d, want evidence from the final %d operation facts: %#v", len(match.EvidenceIDs), maxCapabilityMatchOperations, match)
	}
	assertPartialRuleProjection(t, graph)
}

func TestEvaluateDerivesEvidenceFromFinalFeatureTrace(t *testing.T) {
	const featureCount = maxCapabilityMatchTraceIDs + 1
	graph := behavior.Graph{
		Operations: []behavior.ModeledOperation{{
			ID:            "operation-1",
			SubjectNodeID: "node-1",
			ScopeID:       "scope-1",
			Architecture:  "arm64",
			Kind:          behavior.OperationProcessExecute,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/bin/sh")),
			),
			EvidenceIDs: []string{"ev-shared"},
			Support:     behavior.SupportCorroborated,
			Execution:   connectedExecution("root-main"),
		}},
		Features: make([]behavior.Feature, 0, featureCount),
	}
	for index := 0; index < featureCount; index++ {
		evidence := []string{"ev-shared"}
		if index == featureCount-1 {
			evidence = append(evidence, "ev-late")
		}
		graph.Features = append(graph.Features, behavior.Feature{
			ID:           fmt.Sprintf("feature-%04d", index),
			NodeID:       "node-1",
			ScopeID:      "scope-1",
			Architecture: "arm64",
			Key:          "macho.import_call",
			Value:        "system",
			EvidenceIDs:  evidence,
			Support:      behavior.SupportCorroborated,
			Execution:    connectedExecution("root-main"),
		})
	}
	spec := Spec{
		Metadata:       Metadata{ID: "test.final-feature-trace", Title: "Test", Namespace: "test", Description: "Test bounded feature evidence projection."},
		Kind:           CapabilityRule,
		Match:          Each(Operation(behavior.OperationProcessExecute), Feature("macho.import_call"), SameContext(), SharedEvidence()),
		MinimumSupport: behavior.SupportCorroborated,
	}

	matches := evaluateCompiledRules(&graph, []compiledSpec{{spec: spec}})
	if len(matches) != 1 {
		t.Fatalf("feature Each matches = %#v, want one match", matches)
	}
	match := matches[0]
	if slices.Contains(match.EvidenceIDs, "ev-late") {
		t.Fatalf("evidence from omitted feature survived final trace: %#v", match)
	}
	var tracedFeatures int
	for _, clause := range match.MatchTrace {
		tracedFeatures += len(clause.FeatureIDs)
	}
	if tracedFeatures != maxCapabilityMatchTraceIDs {
		t.Fatalf("traced features = %d, want %d", tracedFeatures, maxCapabilityMatchTraceIDs)
	}
	assertPartialRuleProjection(t, graph)
}

func TestEvaluateCanonicalizesFactEvidenceBeforeBoundedProjection(t *testing.T) {
	evidenceIDs := make([]string, 0, maxCapabilityMatchEvidence+1)
	for index := maxCapabilityMatchEvidence; index >= 0; index-- {
		evidenceIDs = append(evidenceIDs, fmt.Sprintf("ev-%04d", index))
	}
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{{
		ID:            "operation-1",
		SubjectNodeID: "node-1",
		Kind:          behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/bin/sh")),
		),
		EvidenceIDs: evidenceIDs,
		Support:     behavior.SupportCorroborated,
		Execution:   unknownExecution(),
	}}}

	first := evaluateCompiledRules(&graph, []compiledSpec{{spec: MacOSFileExecution}})
	slices.Reverse(graph.Operations[0].EvidenceIDs)
	second := evaluateCompiledRules(&graph, []compiledSpec{{spec: MacOSFileExecution}})
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("fact evidence order changed bounded projection: first=%#v second=%#v", first, second)
	}
	if len(first) != 1 || slices.Contains(first[0].EvidenceIDs, fmt.Sprintf("ev-%04d", maxCapabilityMatchEvidence)) {
		t.Fatalf("canonical evidence prefix was not retained: %#v", first)
	}
}

func assertPartialRuleProjection(t *testing.T, graph behavior.Graph) {
	t.Helper()
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "rule-evaluation" && coverage.Status == "partial" {
			return
		}
	}
	t.Fatalf("missing partial rule-evaluation coverage: %#v", graph.Coverage)
}
