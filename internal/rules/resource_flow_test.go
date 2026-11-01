package rules

import (
	"fmt"
	"slices"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestResourceFlowMatchesTypedThreeStepPath(t *testing.T) {
	execution := connectedExecution("root-main")
	file := behavior.NewResource(behavior.ResourceFile, "/tmp/payload", behavior.ResourceClassArchive)
	plainFile := behavior.NewResource(behavior.ResourceFile, "/tmp/payload")
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		{
			ID: "operation-download", SubjectNodeID: "node", ScopeID: "scope", Architecture: "arm64",
			Kind: behavior.OperationNetworkDownload,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload")),
				behavior.Bind(behavior.ResourceRoleLocalOutput, file),
			),
			EvidenceIDs: []string{"ev-download"}, Support: behavior.SupportDirect, Execution: execution,
		},
		{
			ID: "operation-chmod", SubjectNodeID: "node", ScopeID: "scope", Architecture: "arm64",
			Kind: behavior.OperationFileMakeExecutable, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, plainFile)),
			EvidenceIDs: []string{"ev-chmod"}, Support: behavior.SupportCorroborated, Execution: execution,
		},
		{
			ID: "operation-execute", SubjectNodeID: "node", ScopeID: "scope", Architecture: "arm64",
			Kind: behavior.OperationProcessExecute, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, plainFile)),
			EvidenceIDs: []string{"ev-execute"}, Support: behavior.SupportDirect, Execution: execution,
		},
	}}
	graph.Relations = []behavior.OperationRelation{
		resourceFlowRelation("relation-produces", behavior.RelationProduces, behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-download"), behavior.ResourceRelationEndpoint(behavior.ResourceRoleLocalOutput, file), behavior.SupportDirect),
		resourceFlowRelation("relation-download-chmod", behavior.RelationPrecedes, behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-download"), behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-chmod"), behavior.SupportDirect),
		resourceFlowRelation("relation-chmod-consumes", behavior.RelationConsumes, behavior.ResourceRelationEndpoint(behavior.ResourceRoleTarget, plainFile), behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-chmod"), behavior.SupportCorroborated),
		resourceFlowRelation("relation-chmod-execute", behavior.RelationPrecedes, behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-chmod"), behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-execute"), behavior.SupportDirect),
		resourceFlowRelation("relation-execute-consumes", behavior.RelationConsumes, behavior.ResourceRelationEndpoint(behavior.ResourceRoleExecutable, plainFile), behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-execute"), behavior.SupportDirect),
	}

	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: testResourceFlowSpec()})
	if len(matches) != 1 || matches[0].Support != behavior.SupportCorroborated {
		t.Fatalf("three-step resource-flow match = %#v", matches)
	}
	if !sameStrings(matches[0].OperationIDs, []string{"operation-download", "operation-chmod", "operation-execute"}) {
		t.Fatalf("three-step operation projection = %#v", matches[0].OperationIDs)
	}
	for _, evidenceID := range []string{"ev-download", "ev-chmod", "ev-execute", "ev-relation-produces", "ev-relation-download-chmod", "ev-relation-chmod-consumes", "ev-relation-chmod-execute", "ev-relation-execute-consumes"} {
		if !slices.Contains(matches[0].EvidenceIDs, evidenceID) {
			t.Fatalf("three-step match missing evidence %q: %#v", evidenceID, matches[0].EvidenceIDs)
		}
	}
	if len(matches[0].AffectedResources) != 1 || matches[0].AffectedResources[0].Value != "/tmp/payload" || !matches[0].AffectedResources[0].HasClassification(behavior.ResourceClassArchive) {
		t.Fatalf("three-step shared resource projection = %#v", matches[0].AffectedResources)
	}
	trace, partial := normalizeMatchTrace(matches[0].MatchTrace)
	if partial || len(trace) != 8 {
		t.Fatalf("three-step match trace = %#v, partial=%v", trace, partial)
	}
	var tracedOperations, tracedRelations []string
	for _, clause := range trace {
		tracedOperations = append(tracedOperations, clause.OperationIDs...)
		tracedRelations = append(tracedRelations, clause.RelationIDs...)
	}
	slices.Sort(tracedOperations)
	slices.Sort(tracedRelations)
	if !slices.Equal(tracedOperations, []string{"operation-chmod", "operation-download", "operation-execute"}) ||
		!slices.Equal(tracedRelations, []string{"relation-chmod-consumes", "relation-chmod-execute", "relation-download-chmod", "relation-execute-consumes", "relation-produces"}) {
		t.Fatalf("resource-flow trace lost exact facts: operations=%#v relations=%#v", tracedOperations, tracedRelations)
	}
}

func TestResourceFlowIsDeterministicAndBoundsHostileOrderingCardinality(t *testing.T) {
	execution := connectedExecution("root-main")
	file := behavior.NewResource(behavior.ResourceFile, "/tmp/payload")
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		{ID: "operation-download", SubjectNodeID: "node", ScopeID: "scope", Architecture: "arm64", Kind: behavior.OperationNetworkDownload, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload")), behavior.Bind(behavior.ResourceRoleLocalOutput, file)), EvidenceIDs: []string{"ev-download"}, Support: behavior.SupportDirect, Execution: execution},
		{ID: "operation-execute", SubjectNodeID: "node", ScopeID: "scope", Architecture: "arm64", Kind: behavior.OperationProcessExecute, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, file)), EvidenceIDs: []string{"ev-execute"}, Support: behavior.SupportDirect, Execution: execution},
	}}
	graph.Relations = append(graph.Relations,
		resourceFlowRelation("relation-produces", behavior.RelationProduces, behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-download"), behavior.ResourceRelationEndpoint(behavior.ResourceRoleLocalOutput, file), behavior.SupportDirect),
		resourceFlowRelation("relation-consumes", behavior.RelationConsumes, behavior.ResourceRelationEndpoint(behavior.ResourceRoleExecutable, file), behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-execute"), behavior.SupportDirect),
	)
	for index := 0; index < ruleCapabilityMatchCandidateLimit+100; index++ {
		graph.Relations = append(graph.Relations, resourceFlowRelation(
			fmt.Sprintf("relation-precedes-%04d", index),
			behavior.RelationPrecedes,
			behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-download"),
			behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-execute"),
			behavior.SupportDirect,
		))
	}

	first := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: testResourceFlowSpec()})
	second := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: testResourceFlowSpec()})
	if len(first) != ruleCapabilityMatchCandidateLimit || !slices.EqualFunc(first, second, capabilityMatchesEqual) {
		t.Fatalf("bounded resource flow is not deterministic: first=%d second=%d", len(first), len(second))
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "rule-evaluation" || graph.Coverage[0].Status != "partial" {
		t.Fatalf("hostile resource-flow cardinality was not disclosed: %#v", graph.Coverage)
	}
}

func testResourceFlowSpec() Spec {
	return Spec{
		Metadata: Metadata{ID: "test.resource-flow", Title: "Test resource flow", Namespace: "test", Description: "Tests a typed download/execute resource flow."},
		Kind:     CapabilityRule,
		Match: Any(
			ResourceFlow(
				FlowStep(Operation(behavior.OperationNetworkDownload, ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)), behavior.ResourceRoleLocalOutput),
				FlowStep(Operation(behavior.OperationProcessExecute, ResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)), behavior.ResourceRoleExecutable),
			),
			ResourceFlow(
				FlowStep(Operation(behavior.OperationNetworkDownload, ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)), behavior.ResourceRoleLocalOutput),
				FlowStep(Operation(behavior.OperationFileMakeExecutable, ResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceFile)), behavior.ResourceRoleTarget),
				FlowStep(Operation(behavior.OperationProcessExecute, ResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)), behavior.ResourceRoleExecutable),
			),
		),
		MinimumSupport: behavior.SupportCorroborated,
	}
}

func resourceFlowRelation(id string, kind behavior.RelationKind, from, to behavior.RelationEndpoint, support behavior.Support) behavior.OperationRelation {
	return behavior.OperationRelation{
		ID: id, Kind: kind, From: from, To: to,
		EvidenceIDs: []string{"ev-" + id}, Support: support,
		Execution: connectedExecution("root-main"), Architecture: "arm64",
	}
}
