package behavior

import (
	"strings"
	"testing"
)

func TestRelationVocabularyIsClosedAndDeterministic(t *testing.T) {
	wantKinds := []RelationKind{RelationCalls, RelationConsumes, RelationInvokes, RelationPipesTo, RelationPrecedes, RelationProduces}
	gotKinds := RelationKinds()
	if len(gotKinds) != len(wantKinds) {
		t.Fatalf("RelationKinds() = %#v, want %#v", gotKinds, wantKinds)
	}
	for index := range wantKinds {
		if gotKinds[index] != wantKinds[index] || !ValidRelationKind(gotKinds[index]) {
			t.Fatalf("RelationKinds()[%d] = %q, want %q", index, gotKinds[index], wantKinds[index])
		}
	}
	gotKinds[0] = "mutated"
	if RelationKinds()[0] != RelationCalls || ValidRelationKind("free-form") {
		t.Fatal("relation vocabulary was mutable or accepted a free-form kind")
	}
	if ValidRelationEndpoints(RelationProduces, RelationEndpointResource, RelationEndpointOperation) {
		t.Fatal("produces accepted reversed endpoints")
	}
}

func TestGraphAddRelationNormalizesAndBoundsShape(t *testing.T) {
	graph := Graph{}
	relationID := graph.AddRelation(OperationRelation{
		Kind: RelationProduces,
		From: IDRelationEndpoint(RelationEndpointOperation, "operation-1"),
		To:   ResourceRelationEndpoint(ResourceRoleLocalOutput, NewResource(ResourceFile, "/tmp/payload")),
		EvidenceIDs: []string{
			"ev-2", "ev-1", "ev-1",
		},
	})
	if relationID != "relation-0001" || len(graph.Relations) != 1 {
		t.Fatalf("AddRelation() = %q, relations = %#v", relationID, graph.Relations)
	}
	got := graph.Relations[0]
	if got.Support != SupportCorroborated || got.Execution.Connectivity != ConnectivityUnknown {
		t.Fatalf("relation defaults = %#v", got)
	}
	assertStrings(t, got.EvidenceIDs, []string{"ev-1", "ev-2"})

	tooMuchEvidence := make([]string, MaxRelationEvidenceIDs+1)
	for index := range tooMuchEvidence {
		tooMuchEvidence[index] = "ev"
	}
	if graph.AddRelation(OperationRelation{
		Kind: RelationProduces, From: IDRelationEndpoint(RelationEndpointOperation, "operation-1"),
		To: ResourceRelationEndpoint(ResourceRoleLocalOutput, NewResource(ResourceFile, "/tmp/payload")), EvidenceIDs: tooMuchEvidence,
	}) != "" {
		t.Fatal("relation exceeding the evidence bound was retained")
	}
	if graph.AddRelation(OperationRelation{
		Kind: RelationProduces, From: IDRelationEndpoint(RelationEndpointOperation, "operation-1"),
		To: ResourceRelationEndpoint(ResourceRoleLocalOutput, NewResource(ResourceFile, "")), EvidenceIDs: []string{"ev-1"},
	}) != "" {
		t.Fatal("unknown empty resource was retained as a joinable relation endpoint")
	}
}

func TestGraphAddRelationRejectsKnownUnrelatedEvidence(t *testing.T) {
	var graph Graph
	scopeID := graph.AddScope(Scope{NodeID: "node", Kind: "function", Function: "main", Architecture: "arm64"})
	leftEvidenceID := graph.AddEvidence(Evidence{
		NodeID: "node", ScopeID: scopeID, Function: "main", Arch: "arm64",
		Method: "fixture", Kind: "operation", Value: "left endpoint",
	})
	rightEvidenceID := graph.AddEvidence(Evidence{
		NodeID: "node", ScopeID: scopeID, Function: "main", Arch: "arm64",
		Method: "fixture", Kind: "operation", Value: "right endpoint",
	})
	unrelatedEvidenceID := graph.AddEvidence(Evidence{
		NodeID: "node", ScopeID: scopeID, Function: "main", Arch: "arm64",
		Method: "fixture", Kind: "unrelated", Value: "same-context lookalike",
	})
	leftID := graph.AddOperation(ModeledOperation{
		SubjectNodeID: "node", ScopeID: scopeID, Kind: OperationProcessExecute,
		ResourceBindings: Bindings(Bind(ResourceRoleExecutable, NewResource(ResourceFile, "/bin/sh"))),
		EvidenceIDs:      []string{leftEvidenceID}, Support: SupportDirect,
		Execution: ExecutionContext{Connectivity: ConnectivityUnknown},
	})
	rightID := graph.AddOperation(ModeledOperation{
		SubjectNodeID: "node", ScopeID: scopeID, Kind: OperationProcessExecute,
		ResourceBindings: Bindings(Bind(ResourceRoleExecutable, NewResource(ResourceFile, "/usr/bin/id"))),
		EvidenceIDs:      []string{rightEvidenceID}, Support: SupportDirect,
		Execution: ExecutionContext{Connectivity: ConnectivityUnknown},
	})
	relation := OperationRelation{
		Kind:        RelationPrecedes,
		From:        IDRelationEndpoint(RelationEndpointOperation, leftID),
		To:          IDRelationEndpoint(RelationEndpointOperation, rightID),
		EvidenceIDs: []string{unrelatedEvidenceID}, Support: SupportDirect,
		Execution: ExecutionContext{Connectivity: ConnectivityUnknown}, Architecture: "arm64",
	}
	if graph.AddRelation(relation) != "" {
		t.Fatal("known same-context evidence unrelated to either operation was retained")
	}
	relation.EvidenceIDs = []string{leftEvidenceID}
	if graph.AddRelation(relation) != "" {
		t.Fatal("evidence from only one operation endpoint was retained")
	}
	relation.EvidenceIDs = []string{leftEvidenceID, rightEvidenceID}
	if graph.AddRelation(relation) == "" {
		t.Fatalf("direct endpoint evidence was rejected: %#v", graph.Relations)
	}

	relation.From, relation.To = relation.To, relation.From
	if graph.AddRelation(relation) != "" {
		t.Fatal("known precedence cycle was retained")
	}
}

func TestGraphAddRelationRequiresExactKnownDirectCallFeature(t *testing.T) {
	var graph Graph
	callerID := graph.AddScope(Scope{NodeID: "node", Kind: "function", Function: "main", Architecture: "arm64"})
	calleeID := graph.AddScope(Scope{NodeID: "node", Kind: "function", Function: "helper", Architecture: "arm64"})
	callEvidenceID := graph.AddEvidence(Evidence{
		NodeID: "node", ScopeID: callerID, Function: "main", Arch: "arm64",
		Method: "fixture", Kind: "direct-call", Value: "helper",
	})
	unrelatedEvidenceID := graph.AddEvidence(Evidence{
		NodeID: "node", ScopeID: callerID, Function: "main", Arch: "arm64",
		Method: "fixture", Kind: "literal", Value: "helper",
	})
	graph.AddFeature(Feature{
		NodeID: "node", ScopeID: callerID, Key: "macho.function_call", Value: "helper",
		EvidenceIDs: []string{callEvidenceID}, Support: SupportDirect,
		Execution: ExecutionContext{Connectivity: ConnectivityUnknown},
	})
	relation := OperationRelation{
		Kind:        RelationCalls,
		From:        IDRelationEndpoint(RelationEndpointScope, callerID),
		To:          IDRelationEndpoint(RelationEndpointScope, calleeID),
		EvidenceIDs: []string{unrelatedEvidenceID}, Support: SupportDirect,
		Execution: ExecutionContext{Connectivity: ConnectivityUnknown}, Architecture: "arm64",
	}
	if graph.AddRelation(relation) != "" {
		t.Fatal("same-context evidence outside the exact direct-call Feature was retained")
	}
	relation.EvidenceIDs = []string{callEvidenceID}
	if graph.AddRelation(relation) == "" {
		t.Fatalf("exact direct-call Feature evidence was rejected: %#v", graph.Relations)
	}
	graph.AddScope(Scope{NodeID: "node", Kind: "function", Function: "helper", Architecture: "arm64"})
	if err := graph.ValidateRelationEvidenceLineage(); err == nil || !strings.Contains(err.Error(), "exact direct-call") {
		t.Fatalf("ambiguous same-identity callee scopes passed strict lineage validation: %v", err)
	}
}

func TestGraphValidateRelationsAcceptsTypedResourceFlow(t *testing.T) {
	graph := relationFixtureGraph()
	file := NewResource(ResourceFile, "/tmp/payload")
	graph.Relations = []OperationRelation{
		{ID: "relation-1", Kind: RelationProduces, From: IDRelationEndpoint(RelationEndpointOperation, "operation-download"), To: ResourceRelationEndpoint(ResourceRoleLocalOutput, file), EvidenceIDs: []string{"ev-1"}, Support: SupportCorroborated, Execution: connectedRelationExecution(), Architecture: "arm64"},
		{ID: "relation-2", Kind: RelationConsumes, From: ResourceRelationEndpoint(ResourceRoleExecutable, file), To: IDRelationEndpoint(RelationEndpointOperation, "operation-execute"), EvidenceIDs: []string{"ev-1"}, Support: SupportCorroborated, Execution: connectedRelationExecution(), Architecture: "arm64"},
		{ID: "relation-3", Kind: RelationPrecedes, From: IDRelationEndpoint(RelationEndpointOperation, "operation-download"), To: IDRelationEndpoint(RelationEndpointOperation, "operation-execute"), EvidenceIDs: []string{"ev-1"}, Support: SupportCorroborated, Execution: connectedRelationExecution(), Architecture: "arm64"},
	}
	if err := graph.ValidateRelations(); err != nil {
		t.Fatalf("ValidateRelations() error = %v", err)
	}
}

func TestGraphValidateRelationsRejectsUnsoundCorrelation(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		mutate func(*Graph)
	}{
		{name: "missing endpoint", want: "missing operation", mutate: func(graph *Graph) { graph.Relations[0].From.ID = "missing" }},
		{name: "wrong binding role", want: "not bound", mutate: func(graph *Graph) { graph.Relations[0].To.ResourceRole = ResourceRoleExecutable }},
		{name: "different architecture", want: "architecture", mutate: func(graph *Graph) { graph.Relations[0].Architecture = "x86_64" }},
		{name: "different execution root", want: "execution context differs", mutate: func(graph *Graph) {
			graph.Relations[0].Execution.ExecutionRootIDs = []string{"root-other"}
		}},
		{name: "strengthened support", want: "exceeds operation", mutate: func(graph *Graph) {
			graph.Operations[0].Support = SupportHeuristic
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph := relationFixtureGraph()
			graph.Relations = []OperationRelation{{
				ID: "relation-1", Kind: RelationProduces,
				From:        IDRelationEndpoint(RelationEndpointOperation, "operation-download"),
				To:          ResourceRelationEndpoint(ResourceRoleLocalOutput, NewResource(ResourceFile, "/tmp/payload")),
				EvidenceIDs: []string{"ev-1"}, Support: SupportCorroborated, Execution: connectedRelationExecution(), Architecture: "arm64",
			}}
			test.mutate(&graph)
			err := graph.ValidateRelations()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateRelations() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestGraphValidateRelationsRejectsPrecedenceCycle(t *testing.T) {
	graph := relationFixtureGraph()
	graph.Relations = []OperationRelation{
		{Kind: RelationPrecedes, From: IDRelationEndpoint(RelationEndpointOperation, "operation-download"), To: IDRelationEndpoint(RelationEndpointOperation, "operation-execute"), EvidenceIDs: []string{"ev-1"}, Support: SupportCorroborated, Execution: connectedRelationExecution(), Architecture: "arm64"},
		{Kind: RelationPrecedes, From: IDRelationEndpoint(RelationEndpointOperation, "operation-execute"), To: IDRelationEndpoint(RelationEndpointOperation, "operation-download"), EvidenceIDs: []string{"ev-1"}, Support: SupportCorroborated, Execution: connectedRelationExecution(), Architecture: "arm64"},
	}
	if err := graph.ValidateRelations(); err == nil || !strings.Contains(err.Error(), "contains a cycle") {
		t.Fatalf("ValidateRelations() error = %v, want cycle rejection", err)
	}
}

func TestGraphValidateRelationsRequiresExplicitCallAcrossScopes(t *testing.T) {
	graph := relationFixtureGraph()
	graph.Operations[1].ScopeID = "scope-helper"
	graph.Relations = []OperationRelation{{
		ID: "relation-precedes", Kind: RelationPrecedes,
		From: IDRelationEndpoint(RelationEndpointOperation, "operation-download"), To: IDRelationEndpoint(RelationEndpointOperation, "operation-execute"),
		EvidenceIDs: []string{"ev-1"}, Support: SupportCorroborated, Execution: connectedRelationExecution(), Architecture: "arm64",
	}}
	if err := graph.ValidateRelations(); err == nil || !strings.Contains(err.Error(), "without a calls relation") {
		t.Fatalf("ValidateRelations() error = %v, want cross-scope rejection", err)
	}

	graph.Relations = append(graph.Relations, OperationRelation{
		ID: "relation-calls", Kind: RelationCalls,
		From: IDRelationEndpoint(RelationEndpointScope, "scope-main"), To: IDRelationEndpoint(RelationEndpointScope, "scope-helper"),
		EvidenceIDs: []string{"ev-call"}, Support: SupportDirect, Execution: connectedRelationExecution(), Architecture: "arm64",
	})
	if err := graph.ValidateRelations(); err != nil {
		t.Fatalf("explicit calls relation did not permit cross-scope ordering: %v", err)
	}

	graph.Relations[1].From, graph.Relations[1].To = graph.Relations[1].To, graph.Relations[1].From
	if err := graph.ValidateRelations(); err != nil {
		t.Fatalf("reverse operation flow across an explicit call boundary was rejected: %v", err)
	}
}

func TestGraphValidateRelationsRejectsCrossNodeUnscopedOrdering(t *testing.T) {
	graph := relationFixtureGraph()
	graph.Operations[0].ScopeID = ""
	graph.Operations[1].ScopeID = ""
	graph.Operations[1].SubjectNodeID = "other-node"
	graph.Relations = []OperationRelation{{
		Kind: RelationPrecedes,
		From: IDRelationEndpoint(RelationEndpointOperation, "operation-download"), To: IDRelationEndpoint(RelationEndpointOperation, "operation-execute"),
		EvidenceIDs: []string{"ev-1"}, Support: SupportCorroborated, Execution: connectedRelationExecution(), Architecture: "arm64",
	}}
	if err := graph.ValidateRelations(); err == nil || !strings.Contains(err.Error(), "crosses artifact nodes") {
		t.Fatalf("ValidateRelations() error = %v, want cross-node rejection", err)
	}

	graph.Operations[1].SubjectNodeID = "node"
	if err := graph.ValidateRelations(); err != nil {
		t.Fatalf("direct same-node unscoped ordering was rejected: %v", err)
	}
}

func TestGraphValidateRelationsUsesInvokedTargetScopeArchitecture(t *testing.T) {
	execution := ExecutionContext{Connectivity: ConnectivityUnknown}
	graph := Graph{
		Scopes: []Scope{
			{ID: "scope-source", NodeID: "node-source", Kind: "function", Architecture: "x86_64"},
			{ID: "scope-target", NodeID: "node-target", Kind: "function", Architecture: "arm64"},
		},
		InvokedTargets: []InvokedTarget{{
			ID: "target-1", NodeID: "node-target", ScopeID: "scope-target",
			Source: EntityRef{Kind: EntityKindArtifactNode, ID: "node-source"}, Execution: execution,
		}},
		Operations: []ModeledOperation{{
			ID: "operation-source", SubjectNodeID: "node-source", ScopeID: "scope-source",
			Kind: OperationProcessExecute, ResourceBindings: Bindings(Bind(ResourceRoleExecutable, NewResource(ResourceFile, "/tmp/launcher"))),
			Support: SupportCorroborated, Execution: execution, Architecture: "x86_64",
		}},
		Relations: []OperationRelation{{
			Kind: RelationInvokes,
			From: IDRelationEndpoint(RelationEndpointOperation, "operation-source"), To: IDRelationEndpoint(RelationEndpointInvokedTarget, "target-1"),
			EvidenceIDs: []string{"ev-1"}, Support: SupportCorroborated, Execution: execution, Architecture: "x86_64",
		}},
	}
	if err := graph.ValidateRelations(); err == nil || !strings.Contains(err.Error(), "target-1") || !strings.Contains(err.Error(), "arm64") {
		t.Fatalf("ValidateRelations() error = %v, want target architecture rejection", err)
	}
}

func TestGraphValidateRelationsRejectsHostileCardinality(t *testing.T) {
	graph := Graph{Relations: make([]OperationRelation, MaxOperationRelations+1)}
	if err := graph.ValidateRelations(); err == nil || !strings.Contains(err.Error(), "limit is") {
		t.Fatalf("ValidateRelations() error = %v, want cardinality rejection", err)
	}
}

func relationFixtureGraph() Graph {
	execution := connectedRelationExecution()
	return Graph{
		ExecutionRoots: []ExecutionRoot{{ID: "root-main"}},
		Scopes: []Scope{
			{ID: "scope-main", NodeID: "node", Kind: "function", Architecture: "arm64"},
			{ID: "scope-helper", NodeID: "node", Kind: "function", Architecture: "arm64"},
		},
		Operations: []ModeledOperation{
			{ID: "operation-download", SubjectNodeID: "node", ScopeID: "scope-main", Kind: OperationNetworkDownload, ResourceBindings: Bindings(Bind(ResourceRoleRemoteSource, NewResource(ResourceURL, "https://example.invalid/payload")), Bind(ResourceRoleLocalOutput, NewResource(ResourceFile, "/tmp/payload"))), Support: SupportCorroborated, Execution: execution, Architecture: "arm64"},
			{ID: "operation-execute", SubjectNodeID: "node", ScopeID: "scope-main", Kind: OperationProcessExecute, ResourceBindings: Bindings(Bind(ResourceRoleExecutable, NewResource(ResourceFile, "/tmp/payload"))), Support: SupportCorroborated, Execution: execution, Architecture: "arm64"},
		},
	}
}

func connectedRelationExecution() ExecutionContext {
	return ExecutionContext{Connectivity: ConnectivityConnected, ExecutionRootIDs: []string{"root-main"}}
}
