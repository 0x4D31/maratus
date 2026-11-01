package behavior

import "testing"

func TestGraphRequiresExactFunctionScopeIdentity(t *testing.T) {
	graph := Graph{}
	if graph.AddScope(Scope{Kind: "function"}) != "" {
		t.Fatal("function scope without a function identity was retained")
	}
	if graph.AddScope(Scope{Kind: "program", Function: "main"}) != "" {
		t.Fatal("non-function scope with a function identity was retained")
	}
	functionScopeID := graph.AddScope(Scope{Function: "main"})
	if functionScopeID == "" || graph.Scopes[len(graph.Scopes)-1].Kind != "function" {
		t.Fatal("function identity did not select a normalized function scope")
	}
	if graph.AddEvidence(Evidence{Function: "main", Method: "fixture", Kind: "literal"}) != "" {
		t.Fatal("function evidence without an exact scope was retained")
	}
	if graph.AddFeature(Feature{SourceFunction: "main", Key: "fixture", EvidenceIDs: []string{"ev-forward"}}) != "" {
		t.Fatal("function feature without an exact scope was retained")
	}
	if graph.AddOperation(ModeledOperation{
		SubjectNodeID: "node-1", SourceFunction: "main", Kind: OperationProcessExecute,
		ResourceBindings: Bindings(Bind(ResourceRoleExecutable, NewResource(ResourceFile, ""))),
		EvidenceIDs:      []string{"ev-forward"},
	}) != "" {
		t.Fatal("function operation without an exact scope was retained")
	}
	if graph.ItemsDropped != 0 || graph.InvalidItemsDropped != 5 {
		t.Fatalf("drop accounting = budget %d invalid %d, want 0/5", graph.ItemsDropped, graph.InvalidItemsDropped)
	}
}

func TestAddEvidenceUsesTypedArchitectureContext(t *testing.T) {
	graph := Graph{}
	scopeID := graph.AddScope(Scope{Kind: "function", Function: "main", Architecture: "arm64"})
	if scopeID == "" {
		t.Fatal("scope was not retained")
	}
	if graph.AddEvidence(Evidence{ScopeID: scopeID, Method: "source", Kind: "match", Value: "derived"}) == "" {
		t.Fatal("evidence with scope-derived architecture was not retained")
	}
	if got := graph.Evidence[0].Arch; got != "arm64" {
		t.Fatalf("evidence architecture = %q, want scope architecture", got)
	}
	if got := graph.Evidence[0].Function; got != "main" {
		t.Fatalf("evidence function = %q, want scope function", got)
	}
	if graph.AddEvidence(Evidence{ScopeID: scopeID, Arch: "arm64", Method: "source", Kind: "match", Value: "explicit"}) == "" {
		t.Fatal("evidence with matching scope architecture was not retained")
	}
	if graph.AddEvidence(Evidence{ScopeID: scopeID, Arch: "x86_64", Method: "source", Kind: "match", Value: "conflict"}) != "" {
		t.Fatal("evidence with conflicting scope architecture was retained")
	}
	if graph.AddEvidence(Evidence{ScopeID: scopeID, Function: "other", Method: "source", Kind: "match", Value: "conflict"}) != "" {
		t.Fatal("evidence with conflicting scope function was retained")
	}
	if graph.ItemsDropped != 0 || graph.InvalidItemsDropped != 2 {
		t.Fatalf("drop accounting = budget %d invalid %d, want 0/2", graph.ItemsDropped, graph.InvalidItemsDropped)
	}
}

func TestAddOperationAndNetworkUseTypedScopeContext(t *testing.T) {
	graph := Graph{}
	scopeID := graph.AddScope(Scope{Kind: "function", Function: "main", Architecture: "arm64"})
	evidenceID := graph.AddEvidence(Evidence{ScopeID: scopeID, Method: "source", Kind: "match", Value: "proof"})
	operationID := graph.AddOperation(ModeledOperation{
		SubjectNodeID: "node-1",
		ScopeID:       scopeID,
		Kind:          OperationNetworkConnect,
		ResourceBindings: Bindings(
			Bind(ResourceRoleRemoteDestination, NewResource(ResourceNetworkEndpoint, "")),
		),
		EvidenceIDs: []string{evidenceID},
	})
	if operationID == "" {
		t.Fatal("operation with scope-derived context was not retained")
	}
	if got := graph.Operations[0].Architecture; got != "arm64" {
		t.Fatalf("operation architecture = %q, want scope architecture", got)
	}
	if got := graph.Operations[0].SourceFunction; got != "main" {
		t.Fatalf("operation function = %q, want scope function", got)
	}
	if graph.AddOperation(ModeledOperation{
		SubjectNodeID: "node-1", ScopeID: scopeID, Architecture: "x86_64", Kind: OperationNetworkConnect,
		ResourceBindings: Bindings(Bind(ResourceRoleRemoteDestination, NewResource(ResourceNetworkEndpoint, ""))), EvidenceIDs: []string{evidenceID},
	}) != "" {
		t.Fatal("operation with conflicting scope architecture was retained")
	}
	if graph.AddOperation(ModeledOperation{
		SubjectNodeID: "node-1", ScopeID: scopeID, SourceFunction: "other", Kind: OperationNetworkConnect,
		ResourceBindings: Bindings(Bind(ResourceRoleRemoteDestination, NewResource(ResourceNetworkEndpoint, ""))), EvidenceIDs: []string{evidenceID},
	}) != "" {
		t.Fatal("operation with conflicting scope function was retained")
	}
	if graph.AddNetworkImplementation(NetworkImplementationObservation{
		Kind: NetworkImplementationAPICall, SubjectNodeID: "node-1", ScopeID: scopeID,
		OperationIDs: []string{operationID}, APIOrTool: "URLSession", EvidenceIDs: []string{evidenceID},
	}) == "" {
		t.Fatal("network observation with scope-derived architecture was not retained")
	}
	if got := graph.Network[0].Architecture; got != "arm64" {
		t.Fatalf("network observation architecture = %q, want scope architecture", got)
	}
	if graph.AddNetworkImplementation(NetworkImplementationObservation{
		Kind: NetworkImplementationAPICall, SubjectNodeID: "node-1", ScopeID: scopeID, Architecture: "x86_64",
		OperationIDs: []string{operationID}, APIOrTool: "URLSession", EvidenceIDs: []string{evidenceID},
	}) != "" {
		t.Fatal("network observation with conflicting scope architecture was retained")
	}
}

func TestAddFeatureUsesTypedArchitectureContext(t *testing.T) {
	graph := Graph{}
	scopeID := graph.AddScope(Scope{NodeID: "node", Kind: "function", Function: "main", Architecture: "arm64"})
	if scopeID == "" {
		t.Fatal("scope was not retained")
	}
	evidenceID := graph.AddEvidence(Evidence{NodeID: "node", ScopeID: scopeID, Method: "macho", Kind: "call", Value: "system"})
	if graph.AddFeature(Feature{NodeID: "node", ScopeID: scopeID, Key: "macho.import_call", Value: "system", EvidenceIDs: []string{evidenceID}}) == "" {
		t.Fatal("feature with scope-derived architecture was not retained")
	}
	if got := graph.Features[0].Architecture; got != "arm64" {
		t.Fatalf("feature architecture = %q, want scope architecture", got)
	}
	if graph.AddFeature(Feature{NodeID: "node", ScopeID: scopeID, Architecture: "x86_64", Key: "macho.import_call", Value: "execve", EvidenceIDs: []string{"ev-2"}}) != "" {
		t.Fatal("feature with conflicting scope architecture was retained")
	}
	if graph.AddFeature(Feature{NodeID: "node", Architecture: "arm64", Key: "macho.import", Value: "system", Qualifiers: map[string]string{"arch": "arm64"}, EvidenceIDs: []string{"ev-3"}}) != "" {
		t.Fatal("feature with architecture hidden in qualifiers was retained")
	}
	if graph.ItemsDropped != 0 || graph.InvalidItemsDropped != 2 {
		t.Fatalf("drop accounting = budget %d invalid %d, want 0/2", graph.ItemsDropped, graph.InvalidItemsDropped)
	}
}

func TestGraphRejectsEvidenceFromAnotherTypedContext(t *testing.T) {
	graph := Graph{}
	mainScope := graph.AddScope(Scope{Kind: "function", Function: "main", Architecture: "arm64"})
	otherScope := graph.AddScope(Scope{Kind: "function", Function: "other", Architecture: "arm64"})
	sameNameScope := graph.AddScope(Scope{Kind: "function", Function: "main", Architecture: "arm64"})
	x86Scope := graph.AddScope(Scope{Kind: "function", Function: "main", Architecture: "x86_64"})
	mainEvidence := graph.AddEvidence(Evidence{ScopeID: mainScope, Method: "macho", Kind: "call", Value: "main"})
	otherEvidence := graph.AddEvidence(Evidence{ScopeID: otherScope, Method: "macho", Kind: "call", Value: "other"})
	sameNameEvidence := graph.AddEvidence(Evidence{ScopeID: sameNameScope, Method: "macho", Kind: "call", Value: "same-name-other-scope"})
	x86Evidence := graph.AddEvidence(Evidence{ScopeID: x86Scope, Method: "macho", Kind: "call", Value: "x86"})

	if graph.AddFeature(Feature{ScopeID: mainScope, Key: "macho.import_call", Value: "system", EvidenceIDs: []string{otherEvidence}}) != "" {
		t.Fatal("feature retained cross-function evidence")
	}
	validBindings := Bindings(Bind(ResourceRoleExecutable, NewResource(ResourceFile, "")))
	if graph.AddOperation(ModeledOperation{SubjectNodeID: "node-1", ScopeID: mainScope, Kind: OperationProcessExecute, ResourceBindings: validBindings, EvidenceIDs: []string{otherEvidence}}) != "" {
		t.Fatal("operation retained cross-function evidence")
	}
	bindingsWithForeignEvidence := Bindings(Bind(ResourceRoleExecutable, NewResource(ResourceFile, ""), otherEvidence))
	if graph.AddOperation(ModeledOperation{SubjectNodeID: "node-1", ScopeID: mainScope, Kind: OperationProcessExecute, ResourceBindings: bindingsWithForeignEvidence, EvidenceIDs: []string{mainEvidence}}) != "" {
		t.Fatal("operation retained cross-function binding evidence")
	}
	if graph.AddFeature(Feature{ScopeID: mainScope, Key: "macho.import_call", Value: "system", EvidenceIDs: []string{x86Evidence}}) != "" {
		t.Fatal("feature retained cross-architecture evidence")
	}
	if graph.AddNetworkImplementation(NetworkImplementationObservation{
		Kind: NetworkImplementationAPIImport, SubjectNodeID: "node-1", ScopeID: mainScope,
		APIOrTool: "URLSession", EvidenceIDs: []string{otherEvidence},
	}) != "" {
		t.Fatal("network observation retained cross-function evidence")
	}
	if graph.AddNetworkImplementation(NetworkImplementationObservation{
		Kind: NetworkImplementationAPIImport, SubjectNodeID: "node-1",
		APIOrTool: "URLSession", EvidenceIDs: []string{otherEvidence},
	}) != "" {
		t.Fatal("unscoped network observation erased function evidence context")
	}
	if graph.AddFeature(Feature{ScopeID: mainScope, Key: "macho.import_call", Value: "system", EvidenceIDs: []string{sameNameEvidence}}) != "" {
		t.Fatal("feature joined a same-named function in another scope")
	}
	if graph.AddOperation(ModeledOperation{SubjectNodeID: "node-1", ScopeID: mainScope, Kind: OperationProcessExecute, ResourceBindings: validBindings, EvidenceIDs: []string{sameNameEvidence}}) != "" {
		t.Fatal("operation joined a same-named function in another scope")
	}
	sameNameBinding := Bindings(Bind(ResourceRoleExecutable, NewResource(ResourceFile, ""), sameNameEvidence))
	if graph.AddOperation(ModeledOperation{SubjectNodeID: "node-1", ScopeID: mainScope, Kind: OperationProcessExecute, ResourceBindings: sameNameBinding, EvidenceIDs: []string{mainEvidence}}) != "" {
		t.Fatal("operation binding joined a same-named function in another scope")
	}
	if graph.AddNetworkImplementation(NetworkImplementationObservation{
		Kind: NetworkImplementationAPIImport, SubjectNodeID: "node-1", ScopeID: mainScope,
		APIOrTool: "URLSession", EvidenceIDs: []string{sameNameEvidence},
	}) != "" {
		t.Fatal("network observation joined a same-named function in another scope")
	}
	if graph.InvalidItemsDropped != 10 {
		t.Fatalf("invalid context drops = %d, want 10", graph.InvalidItemsDropped)
	}
}

func TestGraphSortOrdersNestedReportFields(t *testing.T) {
	graph := Graph{
		Features: []Feature{
			{
				ID:          "feature-0001",
				EvidenceIDs: []string{"ev-0002", "ev-0001", "ev-0001"},
				Execution: ExecutionContext{
					Connectivity:     ConnectivityConnected,
					ExecutionRootIDs: []string{"root-0002", "root-0001", "root-0001"},
				},
			},
		},
		ExecutionRoots: []ExecutionRoot{
			{ID: "root-0002", Arguments: []string{"second", "first"}, EvidenceIDs: []string{"ev-0004", "ev-0003"}},
			{ID: "root-0001", EvidenceIDs: []string{"ev-0002", "ev-0001", "ev-0002"}},
		},
		InvokedTargets: []InvokedTarget{
			{
				ID:          "target-0001",
				EvidenceIDs: []string{"ev-0002", "ev-0001", "ev-0002"},
				Execution: ExecutionContext{
					Connectivity:     ConnectivityConnected,
					ExecutionRootIDs: []string{"root-0002", "root-0001", "root-0001"},
				},
			},
		},
		AnalysisSelections: []AnalysisSelection{
			{NodeID: "node-0002", Reasons: []SelectionReason{SelectionReasonRawFeatures}},
			{NodeID: "node-0001", Reasons: []SelectionReason{SelectionReasonRunnableCandidate, SelectionReasonDefaultRelevant, SelectionReasonDefaultRelevant}},
		},
		Operations: []ModeledOperation{
			{
				ID:   "operation-0001",
				Kind: OperationProcessExecute,
				ResourceBindings: Bindings(
					Bind(ResourceRoleExecutable, NewResource(ResourceFile, "/tmp/tool", ResourceClassInterpreter), "ev-0002", "ev-0001"),
					Bind(ResourceRoleArguments, NewResource(ResourceCommand, "--help"), "ev-0003"),
				),
				EvidenceIDs: []string{"ev-0002", "ev-0001", "ev-0001"},
				Execution: ExecutionContext{
					Connectivity:     ConnectivityConnected,
					ExecutionRootIDs: []string{"root-0002", "root-0001", "root-0001"},
					InvokedTargetIDs: []string{"target-0002", "target-0001", "target-0001"},
				},
			},
		},
		Network: []NetworkImplementationObservation{
			{
				ID:           "network-implementation-0002",
				OperationIDs: []string{"operation-0002"},
				Kind:         NetworkImplementationToolInvocation,
				APIOrTool:    "curl",
				SecurityProperties: []NetworkSecurityProperty{
					NetworkSecurityTLSCertificateVerificationDisabled,
					NetworkSecurityTLSCertificateVerificationDisabled,
				},
				UnresolvedProperties: []string{"tool version", "proxy policy", "proxy policy"},
				EvidenceIDs:          []string{"ev-0002", "ev-0001", "ev-0002"},
			},
			{
				ID:           "network-implementation-0001",
				OperationIDs: []string{"operation-0001"},
				Kind:         NetworkImplementationToolInvocation,
				APIOrTool:    "curl",
			},
		},
		ArtifactProperties: []ArtifactProperty{
			{NodeID: "node-0002", Kind: "entitlement", Value: "b", EvidenceIDs: []string{"ev-0004", "ev-0003"}},
			{NodeID: "node-0001", Kind: "entitlement", Value: "a", EvidenceIDs: []string{"ev-0002", "ev-0001", "ev-0001"}},
		},
		Coverage: []Coverage{
			{NodeID: "node-0001", AnalysisArea: "script", Status: "partial"},
			{NodeID: "node-0001", AnalysisArea: "macho", Status: "partial"},
		},
	}

	if err := graph.Sort(); err != nil {
		t.Fatal(err)
	}

	if len(graph.Network[0].OperationIDs) != 1 || graph.Network[0].OperationIDs[0] != "operation-0001" ||
		len(graph.Network[1].OperationIDs) != 1 || graph.Network[1].OperationIDs[0] != "operation-0002" {
		t.Fatalf("network implementation order not deterministic: %#v", graph.Network)
	}
	assertStrings(t, graph.Features[0].EvidenceIDs, []string{"ev-0001", "ev-0002"})
	assertStrings(t, graph.Features[0].Execution.ExecutionRootIDs, []string{"root-0001", "root-0002"})
	assertStrings(t, graph.ExecutionRoots[1].Arguments, []string{"second", "first"})
	assertStrings(t, graph.ExecutionRoots[0].EvidenceIDs, []string{"ev-0001", "ev-0002"})
	assertStrings(t, graph.InvokedTargets[0].EvidenceIDs, []string{"ev-0001", "ev-0002"})
	assertStrings(t, graph.InvokedTargets[0].Execution.ExecutionRootIDs, []string{"root-0001", "root-0002"})
	assertSelectionReasons(t, graph.AnalysisSelections[0].Reasons, []SelectionReason{SelectionReasonDefaultRelevant, SelectionReasonRunnableCandidate})
	assertStrings(t, graph.Operations[0].EvidenceIDs, []string{"ev-0001", "ev-0002"})
	if graph.Operations[0].ResourceBindings[0].Role != ResourceRoleArguments || graph.Operations[0].ResourceBindings[1].Role != ResourceRoleExecutable {
		t.Fatalf("operation bindings not sorted: %#v", graph.Operations[0].ResourceBindings)
	}
	assertStrings(t, graph.Operations[0].ResourceBindings[1].EvidenceIDs, []string{"ev-0001", "ev-0002"})
	assertStrings(t, graph.Operations[0].Execution.ExecutionRootIDs, []string{"root-0001", "root-0002"})
	assertStrings(t, graph.Operations[0].Execution.InvokedTargetIDs, []string{"target-0001", "target-0002"})
	if len(graph.Network[1].SecurityProperties) != 1 || graph.Network[1].SecurityProperties[0] != NetworkSecurityTLSCertificateVerificationDisabled {
		t.Fatalf("network security properties were not normalized: %#v", graph.Network[1].SecurityProperties)
	}
	assertStrings(t, graph.Network[1].EvidenceIDs, []string{"ev-0001", "ev-0002"})
	assertStrings(t, graph.ArtifactProperties[0].EvidenceIDs, []string{"ev-0001", "ev-0002"})
	if graph.ExecutionRoots[0].ID != "root-0001" || graph.AnalysisSelections[0].NodeID != "node-0001" || graph.ArtifactProperties[0].NodeID != "node-0001" || graph.Coverage[0].AnalysisArea != "macho" {
		t.Fatalf("report fields not sorted: artifact_properties=%#v coverage=%#v", graph.ArtifactProperties, graph.Coverage)
	}
}

func TestGraphSortUsesUnresolvedAndEvidenceForNetworkOrder(t *testing.T) {
	graph := Graph{
		Network: []NetworkImplementationObservation{
			{Kind: NetworkImplementationToolInvocation, APIOrTool: "curl", UnresolvedProperties: []string{"z"}, EvidenceIDs: []string{"ev-0002"}},
			{Kind: NetworkImplementationToolInvocation, APIOrTool: "curl", UnresolvedProperties: []string{"a"}, EvidenceIDs: []string{"ev-0001"}},
		},
	}

	if err := graph.Sort(); err != nil {
		t.Fatal(err)
	}

	if graph.Network[0].UnresolvedProperties[0] != "a" || graph.Network[0].EvidenceIDs[0] != "ev-0001" {
		t.Fatalf("network implementation sort should include unresolved conditions and evidence IDs: %#v", graph.Network)
	}
}

func TestGraphInsertionRejectsInvalidFactSupport(t *testing.T) {
	graph := Graph{}
	if graph.AddFeature(Feature{Key: "fixture", Support: "PLAUSIBLE"}) != "" {
		t.Fatal("feature with unknown support was retained")
	}
	if graph.AddOperation(ModeledOperation{
		Kind: OperationProcessExecute, ResourceBindings: testExecutableBindings(), Support: "PLAUSIBLE",
	}) != "" {
		t.Fatal("operation with unknown support was retained")
	}
	if graph.AddArtifactProperty(ArtifactProperty{Kind: "fixture", EvidenceIDs: []string{"ev-1"}, Support: "PLAUSIBLE"}) {
		t.Fatal("artifact property with unknown support was retained")
	}
	if graph.InvalidItemsDropped != 3 || graph.ItemsDropped != 0 {
		t.Fatalf("invalid support accounting = budget %d invalid %d", graph.ItemsDropped, graph.InvalidItemsDropped)
	}
}

func TestArtifactPropertyDefaultsToCorroboratedSupport(t *testing.T) {
	graph := Graph{}
	if !graph.AddArtifactProperty(ArtifactProperty{Kind: "fixture", EvidenceIDs: []string{"ev-1"}}) {
		t.Fatal("valid artifact property was rejected")
	}
	if graph.ArtifactProperties[0].Support != SupportCorroborated {
		t.Fatalf("artifact property support = %q", graph.ArtifactProperties[0].Support)
	}
}

func TestNetworkImplementationComparatorDoesNotBuildConcatenatedKeys(t *testing.T) {
	left := NetworkImplementationObservation{Kind: NetworkImplementationToolInvocation, APIOrTool: "a", EvidenceIDs: []string{"ev-1"}}
	right := NetworkImplementationObservation{Kind: NetworkImplementationToolInvocation, APIOrTool: "z", EvidenceIDs: []string{"ev-2"}}
	allocations := testing.AllocsPerRun(1000, func() {
		if compareNetworkImplementationObservations(left, right) >= 0 {
			panic("unexpected network order")
		}
	})
	if allocations != 0 {
		t.Fatalf("network comparator allocated %.2f objects per comparison", allocations)
	}
}

func TestAddNetworkImplementationRejectsIncompleteTypedFacts(t *testing.T) {
	valid := NetworkImplementationObservation{
		Kind: NetworkImplementationDynamicLinkage, SubjectNodeID: "node-1", APIOrTool: "/usr/lib/libcurl.4.dylib",
		TLSProvider: "libcurl-selected TLS backend", TLSProviderBasis: TLSProviderBasisDynamicLibrary,
		EvidenceIDs: []string{"ev-1"}, Support: SupportDirect, Execution: ExecutionContext{Connectivity: ConnectivityUnknown},
	}
	tests := []struct {
		name   string
		mutate func(*NetworkImplementationObservation)
	}{
		{name: "unknown kind", mutate: func(item *NetworkImplementationObservation) { item.Kind = "guess" }},
		{name: "missing subject", mutate: func(item *NetworkImplementationObservation) { item.SubjectNodeID = "" }},
		{name: "missing implementation identity", mutate: func(item *NetworkImplementationObservation) { item.APIOrTool = "" }},
		{name: "missing evidence", mutate: func(item *NetworkImplementationObservation) { item.EvidenceIDs = nil }},
		{name: "linkage with operation", mutate: func(item *NetworkImplementationObservation) { item.OperationIDs = []string{"operation-1"} }},
		{name: "provider without basis", mutate: func(item *NetworkImplementationObservation) { item.TLSProviderBasis = "" }},
		{name: "basis without provider", mutate: func(item *NetworkImplementationObservation) { item.TLSProvider = "" }},
		{name: "unknown security property", mutate: func(item *NetworkImplementationObservation) {
			item.SecurityProperties = []NetworkSecurityProperty{"guess"}
		}},
		{name: "invalid execution", mutate: func(item *NetworkImplementationObservation) {
			item.Execution = ExecutionContext{Connectivity: ConnectivityConnected}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph Graph
			item := valid
			test.mutate(&item)
			if id := graph.AddNetworkImplementation(item); id != "" || len(graph.Network) != 0 || graph.InvalidItemsDropped != 1 {
				t.Fatalf("malformed implementation observation was retained: id=%q network=%#v invalid=%d", id, graph.Network, graph.InvalidItemsDropped)
			}
		})
	}
}

func assertStrings(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func assertSelectionReasons(t *testing.T, got, want []SelectionReason) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}
