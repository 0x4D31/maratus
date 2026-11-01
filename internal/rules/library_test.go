package rules

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestLibraryRuleReferencesValidateAndExpandDeterministically(t *testing.T) {
	leaf := testLibrarySpec("library.install-root", ExecutionRoot("npm-script", "postinstall"))
	wrapper := testLibrarySpec("library.install-root-wrapper", LibraryRuleRef(leaf.Metadata.ID))
	capability := testCapabilitySpec("test.lifecycle", Each(Operation(behavior.OperationNetworkDownload), LibraryRuleRef(wrapper.Metadata.ID), SameExecutionRoot()))
	specs := []Spec{capability, wrapper, leaf}
	if diagnostics := ValidateSpecs(specs); len(diagnostics) != 0 {
		t.Fatalf("valid library dependency DAG = %#v", diagnostics)
	}

	expanded, err := expandLibraryRuleReferences(capability.Match, librarySpecs(specs))
	if err != nil {
		t.Fatal(err)
	}
	want := Each(Operation(behavior.OperationNetworkDownload), ExecutionRoot("npm-script", "postinstall"), SameExecutionRoot())
	if !reflect.DeepEqual(expanded, want) {
		t.Fatalf("expanded library expression = %#v, want %#v", expanded, want)
	}
	second, err := expandLibraryRuleReferences(capability.Match, librarySpecs([]Spec{leaf, capability, wrapper}))
	if err != nil || !reflect.DeepEqual(second, expanded) {
		t.Fatalf("library expansion depends on catalog order: %#v, %v", second, err)
	}
}

func TestLibraryRuleReferenceValidationRejectsInvalidDependencies(t *testing.T) {
	capabilityTarget := testCapabilitySpec("test.target", Operation(behavior.OperationClipboardRead))
	tests := []struct {
		name  string
		specs []Spec
		code  string
	}{
		{name: "malformed ID", specs: []Spec{testCapabilitySpec("test.consumer", Each(Operation(behavior.OperationNetworkDownload), LibraryRuleRef("Bad ID"), SameExecutionRoot()))}, code: "RULE_LIBRARY_REFERENCE_ID_INVALID"},
		{name: "missing", specs: []Spec{testCapabilitySpec("test.consumer", Each(Operation(behavior.OperationNetworkDownload), LibraryRuleRef("library.missing"), SameExecutionRoot()))}, code: "RULE_LIBRARY_REFERENCE_NOT_FOUND"},
		{name: "capability target", specs: []Spec{testCapabilitySpec("test.consumer", LibraryRuleRef(capabilityTarget.Metadata.ID)), capabilityTarget}, code: "RULE_LIBRARY_REFERENCE_KIND"},
		{name: "self cycle", specs: []Spec{testLibrarySpec("library.loop", LibraryRuleRef("library.loop"))}, code: "RULE_LIBRARY_REFERENCE_CYCLE"},
		{name: "two-node cycle", specs: []Spec{testLibrarySpec("library.one", LibraryRuleRef("library.two")), testLibrarySpec("library.two", LibraryRuleRef("library.one"))}, code: "RULE_LIBRARY_REFERENCE_CYCLE"},
		{name: "direct support policy", specs: []Spec{{Metadata: Metadata{ID: "library.direct", Title: "Direct", Namespace: "library.test", Description: "Invalid direct library policy."}, Kind: LibraryRule, Match: Operation(behavior.OperationClipboardRead), MinimumSupport: behavior.SupportDirect}}, code: "RULE_LIBRARY_SUPPORT_POLICY"},
		{name: "analyst mapping", specs: []Spec{{Metadata: Metadata{ID: "library.mapped", Title: "Mapped", Namespace: "library.test", Description: "Invalid mapped library.", Attack: []string{"T1115"}}, Kind: LibraryRule, Match: Operation(behavior.OperationClipboardRead), MinimumSupport: behavior.SupportCorroborated}}, code: "RULE_LIBRARY_MAPPING_INVALID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diagnostics := ValidateSpecs(test.specs)
			if !hasSpecDiagnosticCode(diagnostics, test.code) {
				t.Fatalf("diagnostics = %#v, want %s", diagnostics, test.code)
			}
		})
	}
}

func TestLibraryRuleCannotEmitCapabilityAndConsumerKeepsEnginePolicy(t *testing.T) {
	library := testLibrarySpec("library.install-root", ExecutionRoot("npm-script", "postinstall"))
	capability := testCapabilitySpec("test.lifecycle", Each(Operation(behavior.OperationNetworkDownload), LibraryRuleRef(library.Metadata.ID), SameExecutionRoot()))
	specs := []Spec{library, capability}
	libraries := librarySpecs(specs)
	expanded, err := expandLibraryRuleReferences(capability.Match, libraries)
	if err != nil {
		t.Fatal(err)
	}
	graph := behavior.Graph{ExecutionRoots: []behavior.ExecutionRoot{{ID: "root-install", DeclarationNodeID: "node-package", Kind: "npm-script", Name: "postinstall", EvidenceIDs: []string{"ev-root"}}}}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-package", ScopeID: "scope-install", Kind: behavior.OperationNetworkDownload,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload"))),
		EvidenceIDs:      []string{"ev-operation"}, Support: behavior.SupportCorroborated, Execution: connectedExecution("root-install"),
	})
	if matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: library, match: library.Match}); len(matches) != 0 {
		t.Fatalf("library rule emitted analyst-facing matches: %#v", matches)
	}
	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: capability, match: expanded})
	if len(matches) != 1 || matches[0].RuleID != capability.Metadata.ID || matches[0].Support != behavior.SupportCorroborated || !reflect.DeepEqual(matches[0].Execution.ExecutionRootIDs, []string{"root-install"}) {
		t.Fatalf("library consumer projection = %#v", matches)
	}
}

func TestLibraryRuleExpansionIsBounded(t *testing.T) {
	specs := make([]Spec, 0, maxLibraryDependencyDepth+2)
	for index := 0; index <= maxLibraryDependencyDepth; index++ {
		id := fmt.Sprintf("library.depth-%02d", index)
		match := Pattern(ExecutionRoot("npm-script", "postinstall"))
		if index < maxLibraryDependencyDepth {
			match = LibraryRuleRef(fmt.Sprintf("library.depth-%02d", index+1))
		}
		specs = append(specs, testLibrarySpec(id, match))
	}
	consumer := testCapabilitySpec("test.depth", LibraryRuleRef("library.depth-00"))
	specs = append(specs, consumer)
	if diagnostics := ValidateSpecs(specs); !hasSpecDiagnosticCode(diagnostics, "RULE_LIBRARY_DEPENDENCY_LIMIT") {
		t.Fatalf("deep dependency diagnostics = %#v", diagnostics)
	}
	if _, err := expandLibraryRuleReferences(consumer.Match, librarySpecs(specs)); err == nil {
		t.Fatal("deep dependency expansion was not bounded")
	}

	leaf := testLibrarySpec("library.leaf", ExecutionRoot("npm-script", "postinstall"))
	references := make([]Pattern, maxExpandedPatternNodes+1)
	for index := range references {
		references[index] = LibraryRuleRef(leaf.Metadata.ID)
	}
	if _, err := expandLibraryRuleReferences(Any(references...), librarySpecs([]Spec{leaf})); err == nil {
		t.Fatal("wide dependency expansion was not bounded")
	}
}

func TestCatalogEntriesExposeIndependentTypedDependencies(t *testing.T) {
	first := CatalogEntries()
	if len(first) != len(Specs()) {
		t.Fatalf("catalog entries = %d, specs = %d", len(first), len(Specs()))
	}
	var library, consumer *CatalogEntry
	for index := range first {
		if index > 0 && first[index-1].ID >= first[index].ID {
			t.Fatalf("catalog entries are not strictly sorted: %q then %q", first[index-1].ID, first[index].ID)
		}
		switch first[index].ID {
		case "library.package-json-install-lifecycle-root":
			library = &first[index]
		case "package.package-json-lifecycle":
			consumer = &first[index]
		}
	}
	if library == nil || library.Kind != LibraryRule || len(library.LibraryRuleIDs) != 0 || consumer == nil || consumer.Kind != CapabilityRule || !reflect.DeepEqual(consumer.LibraryRuleIDs, []string{library.ID}) {
		t.Fatalf("typed catalog dependency entries are incomplete: library=%#v consumer=%#v", library, consumer)
	}
	consumer.LibraryRuleIDs[0] = "mutated"
	for index := range first {
		if len(first[index].Attack) != 0 {
			first[index].Attack[0] = "mutated"
			break
		}
	}
	second := CatalogEntries()
	for _, entry := range second {
		if entry.ID == "package.package-json-lifecycle" && !reflect.DeepEqual(entry.LibraryRuleIDs, []string{"library.package-json-install-lifecycle-root"}) {
			t.Fatalf("catalog dependency storage was aliased: %#v", entry)
		}
		for _, attack := range entry.Attack {
			if attack == "mutated" {
				t.Fatalf("catalog metadata storage was aliased: %#v", entry)
			}
		}
	}
}

func testLibrarySpec(id string, match Pattern) Spec {
	return Spec{Metadata: Metadata{ID: id, Title: id, Namespace: "library.test", Description: "Reusable test expression."}, Kind: LibraryRule, Match: match, MinimumSupport: behavior.SupportCorroborated}
}

func testCapabilitySpec(id string, match Pattern) Spec {
	return Spec{Metadata: Metadata{ID: id, Title: id, Namespace: "test", Description: "Operation-backed test capability."}, Kind: CapabilityRule, Match: match, MinimumSupport: behavior.SupportCorroborated}
}

func hasSpecDiagnosticCode(diagnostics []SpecDiagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}
