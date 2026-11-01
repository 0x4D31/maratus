package rules

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

type invalidEachConstraint struct{}

func (invalidEachConstraint) eachConstraintNode() {}

type invalidResourceFlowStep struct{}

func (invalidResourceFlowStep) resourceFlowStepNode() {}

func clipboardOperation(id string, support behavior.Support) behavior.ModeledOperation {
	return behavior.ModeledOperation{
		ID:            id,
		SubjectNodeID: "node-1",
		ScopeID:       "scope-1",
		Kind:          behavior.OperationClipboardRead,
		ResourceBindings: behavior.Bindings(behavior.Bind(
			behavior.ResourceRoleSource,
			behavior.NewResource(behavior.ResourceClipboard, ""),
		)),
		EvidenceIDs:    []string{"ev-" + id},
		Support:        support,
		Execution:      connectedExecution("root-main"),
		SourceFunction: "main",
		Architecture:   "arm64",
	}
}

func TestClipboardPatternFiltersSupportAndMalformedContext(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		clipboardOperation("operation-direct", behavior.SupportDirect),
		clipboardOperation("operation-corroborated", behavior.SupportCorroborated),
		clipboardOperation("operation-heuristic", behavior.SupportHeuristic),
		{
			ID: "operation-screen", SubjectNodeID: "node-1", ScopeID: "scope-1",
			Kind: behavior.OperationScreenCapture, Support: behavior.SupportDirect,
			Execution: connectedExecution("root-main"), EvidenceIDs: []string{"ev-screen"},
		},
		{
			ID: "operation-invalid-context", SubjectNodeID: "node-1", ScopeID: "scope-1",
			Kind: behavior.OperationClipboardRead, Support: behavior.SupportDirect,
			Execution:   behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected},
			EvidenceIDs: []string{"ev-invalid"},
		},
	}}

	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSClipboardRead})
	SortCapabilityMatches(matches)
	if len(matches) != 2 || matches[0].Support != behavior.SupportDirect || matches[1].Support != behavior.SupportCorroborated {
		t.Fatalf("typed support filtering = %#v", matches)
	}
}

func TestPatternSpecValidationIsClosedAndTyped(t *testing.T) {
	base := Metadata{ID: "test.operation", Title: "Test", Namespace: "test", Description: "Test pattern."}
	tests := []struct {
		name string
		spec Spec
		code string
	}{
		{name: "valid", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Operation(behavior.OperationClipboardRead), MinimumSupport: behavior.SupportCorroborated}},
		{name: "valid relation", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Relate(Operation(behavior.OperationNetworkDownload), Operation(behavior.OperationInterpreterInvoke), RelatedBy(behavior.RelationPipesTo)), MinimumSupport: behavior.SupportCorroborated}},
		{name: "valid feature conjunction", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), Feature("macho.import_call"), SameContext(), SharedEvidence()), MinimumSupport: behavior.SupportCorroborated}},
		{name: "valid execution-root conjunction", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), ExecutionRoot("npm-script", "install", "postinstall"), SameExecutionRoot()), MinimumSupport: behavior.SupportCorroborated}},
		{name: "valid resource flow", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: ResourceFlow(
			FlowStep(Operation(behavior.OperationNetworkDownload, ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)), behavior.ResourceRoleLocalOutput),
			FlowStep(Operation(behavior.OperationProcessExecute, ResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)), behavior.ResourceRoleExecutable),
		), MinimumSupport: behavior.SupportCorroborated}},
		{name: "invalid rule kind", spec: Spec{Metadata: base, Kind: RuleKind("detector"), Match: Operation(behavior.OperationClipboardRead), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_KIND_INVALID"},
		{name: "invalid operation", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Operation(behavior.OperationKind("clipboard.capture")), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_OPERATION_KIND_INVALID"},
		{name: "invalid support", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Operation(behavior.OperationClipboardRead), MinimumSupport: behavior.Support("CERTAIN")}, code: "RULE_MINIMUM_SUPPORT_INVALID"},
		{name: "heuristic capability minimum", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Operation(behavior.OperationClipboardRead), MinimumSupport: behavior.SupportHeuristic}, code: "RULE_MINIMUM_SUPPORT_HEURISTIC"},
		{name: "relation missing constraint", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Relate(Operation(behavior.OperationNetworkDownload), Operation(behavior.OperationInterpreterInvoke)), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_RELATE_CONSTRAINT_ARITY"},
		{name: "relation invalid kind", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Relate(Operation(behavior.OperationNetworkDownload), Operation(behavior.OperationInterpreterInvoke), RelatedBy(behavior.RelationKind("flows"))), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_RELATION_KIND_INVALID"},
		{name: "relation incompatible endpoints", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Relate(Operation(behavior.OperationNetworkDownload), Operation(behavior.OperationInterpreterInvoke), RelatedBy(behavior.RelationProduces)), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_RELATION_ENDPOINTS_INCOMPATIBLE"},
		{name: "relation invalid operand", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Relate(Any(Operation(behavior.OperationNetworkDownload), Operation(behavior.OperationNetworkConnect)), Operation(behavior.OperationInterpreterInvoke), RelatedBy(behavior.RelationPipesTo)), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_RELATE_OPERAND_INVALID"},
		{name: "feature capability without operation", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Feature("macho.import"), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_CAPABILITY_OPERATION_REQUIRED"},
		{name: "feature alternative without operation", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Any(Operation(behavior.OperationClipboardRead), Feature("macho.import")), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_CAPABILITY_OPERATION_REQUIRED"},
		{name: "execution root without operation", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: ExecutionRoot("npm-script"), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_CAPABILITY_OPERATION_REQUIRED"},
		{name: "invalid execution root kind", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), ExecutionRoot("NPM script", "install"), SameExecutionRoot()), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_EXECUTION_ROOT_KIND_INVALID"},
		{name: "empty execution root name", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), ExecutionRoot("npm-script", ""), SameExecutionRoot()), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_EXECUTION_ROOT_NAME_INVALID"},
		{name: "duplicate execution root name", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), ExecutionRoot("npm-script", "install", "install"), SameExecutionRoot()), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_EXECUTION_ROOT_NAME_DUPLICATE"},
		{name: "invalid feature key", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), Feature("MachO Import"), SameContext(), SharedEvidence()), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_FEATURE_KEY_INVALID"},
		{name: "each invalid operation operand", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Feature("macho.import"), Feature("macho.import_call"), SameContext(), SharedEvidence()), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_EACH_OPERAND_INVALID"},
		{name: "each invalid feature operand", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), Operation(behavior.OperationClipboardRead), SameContext(), SharedEvidence()), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_EACH_OPERAND_INVALID"},
		{name: "each missing context", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), Feature("macho.import_call"), SharedEvidence()), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_EACH_CONTEXT_REQUIRED"},
		{name: "each missing evidence", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), Feature("macho.import_call"), SameContext()), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_EACH_EVIDENCE_REQUIRED"},
		{name: "each duplicate constraint", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), Feature("macho.import_call"), SameContext(), SameContext(), SharedEvidence()), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_EACH_CONSTRAINT_DUPLICATE"},
		{name: "each unknown constraint", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), Feature("macho.import_call"), SameContext(), SharedEvidence(), invalidEachConstraint{}), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_EACH_CONSTRAINT_INVALID"},
		{name: "root each missing ownership", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), ExecutionRoot("npm-script", "install")), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_EACH_EXECUTION_ROOT_REQUIRED"},
		{name: "root each feature constraints", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), ExecutionRoot("npm-script", "install"), SameContext(), SharedEvidence()), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_EACH_CONSTRAINT_INCOMPATIBLE"},
		{name: "feature each root constraint", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: Each(Operation(behavior.OperationProcessExecute), Feature("macho.import_call"), SameContext(), SharedEvidence(), SameExecutionRoot()), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_EACH_CONSTRAINT_INCOMPATIBLE"},
		{name: "resource flow too short", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: ResourceFlow(FlowStep(Operation(behavior.OperationNetworkDownload, ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)), behavior.ResourceRoleLocalOutput)), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_RESOURCE_FLOW_ARITY_INVALID"},
		{name: "resource flow invalid step", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: ResourceFlow(invalidResourceFlowStep{}, FlowStep(Operation(behavior.OperationProcessExecute, ResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)), behavior.ResourceRoleExecutable)), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_RESOURCE_FLOW_STEP_INVALID"},
		{name: "resource flow indirect operation", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: ResourceFlow(FlowStep(Any(Operation(behavior.OperationNetworkDownload), Operation(behavior.OperationNetworkConnect)), behavior.ResourceRoleLocalOutput), FlowStep(Operation(behavior.OperationProcessExecute, ResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)), behavior.ResourceRoleExecutable)), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_RESOURCE_FLOW_OPERATION_INVALID"},
		{name: "resource flow invalid role", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: ResourceFlow(FlowStep(Operation(behavior.OperationNetworkDownload, ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)), behavior.ResourceRole("payload")), FlowStep(Operation(behavior.OperationProcessExecute, ResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)), behavior.ResourceRoleExecutable)), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_RESOURCE_FLOW_ROLE_INVALID"},
		{name: "resource flow missing role binding", spec: Spec{Metadata: base, Kind: CapabilityRule, Match: ResourceFlow(FlowStep(Operation(behavior.OperationNetworkDownload, ResourceBinding(behavior.ResourceRoleRemoteSource, behavior.ResourceURL)), behavior.ResourceRoleLocalOutput), FlowStep(Operation(behavior.OperationProcessExecute, ResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)), behavior.ResourceRoleExecutable)), MinimumSupport: behavior.SupportCorroborated}, code: "RULE_RESOURCE_FLOW_BINDING_REQUIRED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diagnostics := ValidateSpecs([]Spec{test.spec})
			if test.code == "" {
				if len(diagnostics) != 0 {
					t.Fatalf("diagnostics = %#v", diagnostics)
				}
				return
			}
			for _, diagnostic := range diagnostics {
				if diagnostic.Code == test.code {
					return
				}
			}
			t.Fatalf("missing %s in %#v", test.code, diagnostics)
		})
	}
}

func TestExecutionRootPatternCopiesAndBoundsAcceptedNames(t *testing.T) {
	names := make([]string, maxExecutionRootPatternNames+1)
	for index := range names {
		names[index] = fmt.Sprintf("hook-%02d", index)
	}
	pattern := ExecutionRoot("npm-script", names...).(executionRootPattern)
	names[0] = "mutated"
	if pattern.names[0] != "hook-00" {
		t.Fatalf("ExecutionRoot pattern aliases caller names: %#v", pattern.names)
	}
	spec := Spec{
		Metadata:       Metadata{ID: "library.execution-root-limit", Title: "Test", Namespace: "test", Description: "Test bounded root names."},
		Kind:           LibraryRule,
		Match:          pattern,
		MinimumSupport: behavior.SupportCorroborated,
	}
	for _, diagnostic := range ValidateSpecs([]Spec{spec}) {
		if diagnostic.Code == "RULE_EXECUTION_ROOT_NAMES_LIMIT" {
			return
		}
	}
	t.Fatal("missing RULE_EXECUTION_ROOT_NAMES_LIMIT diagnostic")
}

func TestHeuristicMinimumCannotBypassReportableOperationPolicy(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{clipboardOperation("operation-1", behavior.SupportDirect)}}
	spec := Spec{
		Metadata:       Metadata{ID: "test.heuristic", Title: "Test", Namespace: "test", Description: "Test heuristic minimum."},
		Kind:           CapabilityRule,
		Match:          Operation(behavior.OperationClipboardRead),
		MinimumSupport: behavior.SupportHeuristic,
	}
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: spec}); len(got) != 0 {
		t.Fatalf("invalid heuristic-minimum spec emitted capability matches: %#v", got)
	}
}

func TestLibraryPatternDoesNotEmitPublicCapabilityMatch(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{clipboardOperation("operation-1", behavior.SupportDirect)}}
	spec := Spec{
		Metadata:       Metadata{ID: "library.clipboard", Title: "Clipboard primitive", Namespace: "library.collection", Description: "Reusable clipboard expression."},
		Kind:           LibraryRule,
		Match:          Operation(behavior.OperationClipboardRead),
		MinimumSupport: behavior.SupportCorroborated,
	}
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: spec}); len(got) != 0 {
		t.Fatalf("library rule emitted public capability matches: %#v", got)
	}
}

func TestFeaturePatternIsValidOnlyAsLibraryFactOrOperationBackedConjunction(t *testing.T) {
	spec := Spec{
		Metadata:       Metadata{ID: "library.macho-import", Title: "Mach-O import", Namespace: "library.macho", Description: "Reusable Mach-O import fact."},
		Kind:           LibraryRule,
		Match:          Feature("macho.import"),
		MinimumSupport: behavior.SupportCorroborated,
	}
	if diagnostics := ValidateSpecs([]Spec{spec}); len(diagnostics) != 0 {
		t.Fatalf("library Feature diagnostics = %#v", diagnostics)
	}
	if got := evaluateCompiledSpecForTest(&behavior.Graph{}, compiledSpec{spec: spec}); len(got) != 0 {
		t.Fatalf("library Feature emitted public capability matches: %#v", got)
	}
}

func TestAnalysisViewCopiesIndexedOperations(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{clipboardOperation("operation-1", behavior.SupportDirect)}}
	graph.Operations[0].Qualifiers = map[string]string{"origin": "fixture"}
	view := newAnalysisView(&graph, newRuleWorkBudget(&graph))
	pattern := operationPattern{kind: behavior.OperationClipboardRead}
	first := view.matchingOperations(pattern, newRuleWorkBudget(&graph))
	first[0].EvidenceIDs[0] = "mutated-evidence"
	first[0].ResourceBindings[0].Resource.Kind = behavior.ResourceFile
	first[0].Qualifiers["origin"] = "mutated"

	second := view.matchingOperations(pattern, newRuleWorkBudget(&graph))
	if graph.Operations[0].EvidenceIDs[0] != "ev-operation-1" || second[0].EvidenceIDs[0] != "ev-operation-1" {
		t.Fatalf("evidence aliases graph or view: graph=%#v view=%#v", graph.Operations[0], second[0])
	}
	if graph.Operations[0].ResourceBindings[0].Resource.Kind != behavior.ResourceClipboard || second[0].ResourceBindings[0].Resource.Kind != behavior.ResourceClipboard {
		t.Fatalf("resource binding aliases graph or view: graph=%#v view=%#v", graph.Operations[0], second[0])
	}
	if graph.Operations[0].Qualifiers["origin"] != "fixture" || second[0].Qualifiers["origin"] != "fixture" {
		t.Fatalf("qualifiers alias graph or view: graph=%#v view=%#v", graph.Operations[0], second[0])
	}
}

func TestAnalysisViewCopiesIndexedFeatures(t *testing.T) {
	graph := behavior.Graph{Features: []behavior.Feature{{
		ID: "feature-1", NodeID: "node-1", ScopeID: "scope-1", Architecture: "arm64",
		Key: "macho.import_call", Value: "system", Qualifiers: map[string]string{"function": "main"},
		EvidenceIDs: []string{"ev-call"}, Support: behavior.SupportCorroborated,
		Execution: connectedExecution("root-main"), SourceFunction: "main",
	}}}
	view := newAnalysisView(&graph, newRuleWorkBudget(&graph))
	pattern := featurePattern{key: "macho.import_call"}
	first := view.matchingFeatures(pattern, newRuleWorkBudget(&graph))
	first[0].EvidenceIDs[0] = "mutated-evidence"
	first[0].Execution.ExecutionRootIDs[0] = "mutated-root"
	first[0].Qualifiers["function"] = "mutated-function"

	second := view.matchingFeatures(pattern, newRuleWorkBudget(&graph))
	if graph.Features[0].EvidenceIDs[0] != "ev-call" || second[0].EvidenceIDs[0] != "ev-call" || second[0].Execution.ExecutionRootIDs[0] != "root-main" || second[0].Qualifiers["function"] != "main" {
		t.Fatalf("indexed Feature aliases graph or caller: graph=%#v view=%#v", graph.Features[0], second[0])
	}
}

func TestAnalysisViewCopiesIndexedExecutionOwnership(t *testing.T) {
	graph := behavior.Graph{
		ExecutionRoots: []behavior.ExecutionRoot{{ID: "root-1", Kind: "npm-script", Name: "install", Arguments: []string{"node install.js"}, EvidenceIDs: []string{"ev-root"}}},
		InvokedTargets: []behavior.InvokedTarget{{ID: "target-1", Kind: "script", NodeID: "node-target", Arguments: []string{"install.js"}, EvidenceIDs: []string{"ev-target"}, Execution: connectedExecution("root-1")}},
	}
	view := newAnalysisView(&graph, newRuleWorkBudget(&graph))
	first := view.matchingExecutionRoots(executionRootPattern{kind: "npm-script", names: []string{"install"}}, newRuleWorkBudget(&graph))
	first[0].Arguments[0] = "mutated"
	first[0].EvidenceIDs[0] = "mutated"
	target, ok := view.invokedTarget("target-1", newRuleWorkBudget(&graph))
	if !ok {
		t.Fatal("indexed target not found")
	}
	target.Execution.ExecutionRootIDs[0] = "mutated"
	target.Arguments[0] = "mutated"

	second := view.matchingExecutionRoots(executionRootPattern{kind: "npm-script", names: []string{"install"}}, newRuleWorkBudget(&graph))
	secondTarget, ok := view.invokedTarget("target-1", newRuleWorkBudget(&graph))
	if !ok {
		t.Fatal("indexed target not found on second lookup")
	}
	if graph.ExecutionRoots[0].Arguments[0] != "node install.js" || second[0].Arguments[0] != "node install.js" || second[0].EvidenceIDs[0] != "ev-root" {
		t.Fatalf("indexed ExecutionRoot aliases graph or caller: graph=%#v view=%#v", graph.ExecutionRoots[0], second[0])
	}
	if graph.InvokedTargets[0].Arguments[0] != "install.js" || secondTarget.Arguments[0] != "install.js" || secondTarget.Execution.ExecutionRootIDs[0] != "root-1" {
		t.Fatalf("indexed InvokedTarget aliases graph or caller: graph=%#v view=%#v", graph.InvokedTargets[0], secondTarget)
	}
}

func TestEachJoinBudgetMarksPartialCoverage(t *testing.T) {
	graph := behavior.Graph{
		Features: []behavior.Feature{{
			ID: "feature-1", NodeID: "node-1", ScopeID: "scope-1", Architecture: "arm64",
			Key: "macho.import_call", Value: "system", EvidenceIDs: []string{"ev-call"}, Support: behavior.SupportCorroborated,
			Execution: connectedExecution("root-main"),
		}},
		Operations: []behavior.ModeledOperation{{
			ID: "operation-1", SubjectNodeID: "node-1", ScopeID: "scope-1", Architecture: "arm64",
			Kind: behavior.OperationProcessExecute, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/bin/sh"))),
			EvidenceIDs: []string{"ev-call"}, Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
		}},
	}
	view := newAnalysisView(&graph, newRuleWorkBudget(&graph))
	spec := Spec{
		Metadata:       Metadata{ID: "test.each-budget", Title: "Test", Namespace: "test", Description: "Test Each work budget."},
		Kind:           CapabilityRule,
		Match:          Each(Operation(behavior.OperationProcessExecute), Feature("macho.import_call"), SameContext(), SharedEvidence()),
		MinimumSupport: behavior.SupportCorroborated,
	}
	if got := evaluatePatternSpec(view, &ruleWorkBudget{graph: &graph, remaining: 7}, spec); len(got) != 0 {
		t.Fatalf("over-budget Each returned matches: %#v", got)
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "rule-evaluation" || graph.Coverage[0].Status != "partial" {
		t.Fatalf("missing partial coverage after Each budget exhaustion: %#v", graph.Coverage)
	}
}

func TestEachJoinIsBoundedUnderHostileCardinality(t *testing.T) {
	const candidates = 1100
	graph := behavior.Graph{
		Features:   make([]behavior.Feature, 0, candidates),
		Operations: make([]behavior.ModeledOperation, 0, candidates),
	}
	for index := 0; index < candidates; index++ {
		graph.Features = append(graph.Features, behavior.Feature{
			ID: fmt.Sprintf("feature-%04d", index), NodeID: "node-1", ScopeID: "scope-1", Architecture: "arm64",
			Key: "macho.import_call", Value: "system", EvidenceIDs: []string{"ev-shared"}, Support: behavior.SupportCorroborated,
			Execution: connectedExecution("root-main"),
		})
		graph.Operations = append(graph.Operations, behavior.ModeledOperation{
			ID: fmt.Sprintf("operation-%04d", index), SubjectNodeID: "node-1", ScopeID: "scope-1", Architecture: "arm64",
			Kind: behavior.OperationProcessExecute, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/bin/sh"))),
			EvidenceIDs: []string{"ev-shared"}, Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
		})
	}
	spec := Spec{
		Metadata:       Metadata{ID: "test.each-cardinality", Title: "Test", Namespace: "test", Description: "Test hostile Each cardinality."},
		Kind:           CapabilityRule,
		Match:          Each(Operation(behavior.OperationProcessExecute), Feature("macho.import_call"), SameContext(), SharedEvidence()),
		MinimumSupport: behavior.SupportCorroborated,
	}
	first := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: spec})
	second := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: spec})
	if len(first) != 0 || len(second) != 0 {
		t.Fatalf("over-budget hostile join returned matches: first=%d second=%d", len(first), len(second))
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "rule-evaluation" || graph.Coverage[0].Status != "partial" || !strings.Contains(graph.Coverage[0].Detail, "work limit") {
		t.Fatalf("hostile join did not report deterministic partial coverage: %#v", graph.Coverage)
	}
}

func TestAnalysisViewCopiesIndexedRelations(t *testing.T) {
	graph := behavior.Graph{}
	leftID := graph.AddOperation(clipboardOperation("operation-left", behavior.SupportDirect))
	right := clipboardOperation("operation-right", behavior.SupportDirect)
	right.Kind = behavior.OperationScreenCapture
	right.ResourceBindings = behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceScreen, "")))
	rightID := graph.AddOperation(right)
	relationID := graph.AddRelation(behavior.OperationRelation{
		Kind:        behavior.RelationPipesTo,
		From:        behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, leftID),
		To:          behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, rightID),
		EvidenceIDs: []string{"ev-relation"}, Support: behavior.SupportDirect,
		Execution: connectedExecution("root-main"), Architecture: "arm64",
	})
	view := newAnalysisView(&graph, newRuleWorkBudget(&graph))
	leftIDs := map[string]bool{leftID: true}
	rightIDs := map[string]bool{rightID: true}
	first := view.matchingOperationRelations(behavior.RelationPipesTo, leftIDs, rightIDs, newRuleWorkBudget(&graph))[0]
	first.EvidenceIDs[0] = "mutated"
	first.Execution.ExecutionRootIDs[0] = "mutated"
	second := view.matchingOperationRelations(behavior.RelationPipesTo, leftIDs, rightIDs, newRuleWorkBudget(&graph))[0]
	if graph.Relations[0].EvidenceIDs[0] != "ev-relation" || second.EvidenceIDs[0] != "ev-relation" || second.Execution.ExecutionRootIDs[0] != "root-main" {
		t.Fatalf("indexed relation %s aliases graph or caller: graph=%#v view=%#v", relationID, graph.Relations[0], second)
	}
}

func TestAnalysisViewBudgetMarksPartialCoverage(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		clipboardOperation("operation-1", behavior.SupportDirect),
		clipboardOperation("operation-2", behavior.SupportDirect),
	}}
	view := newAnalysisView(&graph, &ruleWorkBudget{graph: &graph, remaining: 2})
	if got := len(view.matchingOperations(operationPattern{kind: behavior.OperationClipboardRead}, newRuleWorkBudget(&graph))); got != 1 {
		t.Fatalf("indexed operations = %d, want bounded prefix 1", got)
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "rule-evaluation" || graph.Coverage[0].Status != "partial" {
		t.Fatalf("missing partial coverage after index budget exhaustion: %#v", graph.Coverage)
	}
}

func TestPackageInstallBindingPatternRequiresClassification(t *testing.T) {
	operation := func(id string, role behavior.ResourceRole, kind behavior.ResourceKind, classifications ...behavior.ResourceClassification) behavior.ModeledOperation {
		return behavior.ModeledOperation{
			ID: id, SubjectNodeID: "node-1", ScopeID: "scope-1", Kind: behavior.OperationPackageInstall,
			ResourceBindings: behavior.Bindings(behavior.Bind(role, behavior.NewResource(kind, "/tmp/payload.pkg", classifications...))),
			EvidenceIDs:      []string{"ev-" + id}, Support: behavior.SupportCorroborated,
			Execution: connectedExecution("root-main"), Architecture: "arm64",
		}
	}
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		operation("operation-package", behavior.ResourceRoleLocalInput, behavior.ResourceFile, behavior.ResourceClassPackage),
		operation("operation-unclassified", behavior.ResourceRoleLocalInput, behavior.ResourceFile),
	}}

	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSPackageInstall})
	if len(matches) != 1 || matches[0].OperationIDs[0] != "operation-package" {
		t.Fatalf("binding pattern matches = %#v", matches)
	}
}

func TestResourceBindingPatternValidationUsesTypedCompatibility(t *testing.T) {
	base := Metadata{ID: "test.binding", Title: "Test", Namespace: "test", Description: "Test binding pattern."}
	tests := []struct {
		name       string
		constraint OperationConstraint
		code       string
	}{
		{name: "valid", constraint: ClassifiedResourceBinding(behavior.ResourceRoleLocalInput, behavior.ResourceFile, behavior.ResourceClassPackage)},
		{name: "unknown role", constraint: ResourceBinding(behavior.ResourceRole("payload"), behavior.ResourceFile), code: "RULE_RESOURCE_ROLE_INVALID"},
		{name: "unknown kind", constraint: ResourceBinding(behavior.ResourceRoleLocalInput, behavior.ResourceKind("package")), code: "RULE_RESOURCE_KIND_INVALID"},
		{name: "operation incompatible", constraint: ResourceBinding(behavior.ResourceRoleRemoteSource, behavior.ResourceURL), code: "RULE_RESOURCE_BINDING_INCOMPATIBLE"},
		{name: "classification incompatible", constraint: ClassifiedResourceBinding(behavior.ResourceRoleLocalInput, behavior.ResourceFile, behavior.ResourceClassBundleIdentifier), code: "RULE_RESOURCE_CLASSIFICATION_INVALID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := Spec{Metadata: base, Kind: CapabilityRule, Match: Operation(behavior.OperationPackageInstall, test.constraint), MinimumSupport: behavior.SupportCorroborated}
			diagnostics := ValidateSpecs([]Spec{spec})
			if test.code == "" {
				if len(diagnostics) != 0 {
					t.Fatalf("diagnostics = %#v", diagnostics)
				}
				return
			}
			for _, diagnostic := range diagnostics {
				if diagnostic.Code == test.code {
					return
				}
			}
			t.Fatalf("missing %s in %#v", test.code, diagnostics)
		})
	}
}

func TestBindingLookupBudgetMarksPartialCoverage(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{clipboardOperation("operation-1", behavior.SupportDirect)}}
	view := newAnalysisView(&graph, newRuleWorkBudget(&graph))
	pattern := operationPattern{kind: behavior.OperationClipboardRead, constraints: []OperationConstraint{ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceClipboard)}}
	if got := view.matchingOperations(pattern, &ruleWorkBudget{graph: &graph, remaining: 1}); len(got) != 0 {
		t.Fatalf("over-budget lookup returned operations: %#v", got)
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "rule-evaluation" || graph.Coverage[0].Status != "partial" {
		t.Fatalf("missing partial coverage after lookup budget exhaustion: %#v", graph.Coverage)
	}
}

func TestAnyPatternReturnsDeterministicUnion(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		clipboardOperation("operation-clipboard", behavior.SupportDirect),
		{
			ID: "operation-screen", SubjectNodeID: "node-1", ScopeID: "scope-1",
			Kind: behavior.OperationScreenCapture,
			ResourceBindings: behavior.Bindings(behavior.Bind(
				behavior.ResourceRoleSource,
				behavior.NewResource(behavior.ResourceScreen, ""),
			)),
			EvidenceIDs: []string{"ev-screen"}, Support: behavior.SupportCorroborated,
			Execution: connectedExecution("root-main"), Architecture: "arm64",
		},
	}}
	spec := Spec{
		Metadata: Metadata{ID: "test.capture", Title: "Captures input", Namespace: "test", Description: "Test Any expression."},
		Kind:     CapabilityRule,
		Match: Any(
			Operation(behavior.OperationClipboardRead, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceClipboard)),
			Operation(behavior.OperationScreenCapture, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceScreen)),
		),
		MinimumSupport: behavior.SupportCorroborated,
	}
	first := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: spec})
	second := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: spec})
	SortCapabilityMatches(first)
	SortCapabilityMatches(second)
	if !slices.EqualFunc(first, second, capabilityMatchesEqual) || len(first) != 2 {
		t.Fatalf("Any matches are not a deterministic two-operation union: first=%#v second=%#v", first, second)
	}
}

func TestAnyPatternValidationRejectsRedundantAndInvalidChildren(t *testing.T) {
	base := Metadata{ID: "test.any", Title: "Test", Namespace: "test", Description: "Test Any validation."}
	tests := []struct {
		name  string
		match Pattern
		code  string
	}{
		{name: "one child", match: Any(Operation(behavior.OperationClipboardRead)), code: "RULE_ANY_ARITY_INVALID"},
		{name: "invalid child", match: Any(Operation(behavior.OperationClipboardRead), Operation(behavior.OperationKind("unknown"))), code: "RULE_OPERATION_KIND_INVALID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diagnostics := ValidateSpecs([]Spec{{Metadata: base, Kind: CapabilityRule, Match: test.match, MinimumSupport: behavior.SupportCorroborated}})
			for _, diagnostic := range diagnostics {
				if diagnostic.Code == test.code {
					return
				}
			}
			t.Fatalf("missing %s in %#v", test.code, diagnostics)
		})
	}
}

func TestConcreteResourceBindingRequiresValueAndProjectsMatchedRole(t *testing.T) {
	operation := func(id, executable string) behavior.ModeledOperation {
		return behavior.ModeledOperation{
			ID: id, SubjectNodeID: "node-1", ScopeID: "scope-1", Kind: behavior.OperationProcessExecute,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, executable)),
				behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, "--verbose")),
			),
			EvidenceIDs: []string{"ev-" + id}, Support: behavior.SupportCorroborated,
			Execution: connectedExecution("root-main"), Architecture: "arm64",
		}
	}
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		operation("operation-concrete", "/tmp/tool"),
		operation("operation-abstract", ""),
	}}
	spec := Spec{
		Metadata:       Metadata{ID: "test.concrete", Title: "Executes file", Namespace: "test", Description: "Test concrete binding."},
		Kind:           CapabilityRule,
		Match:          Operation(behavior.OperationProcessExecute, ConcreteResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)),
		MinimumSupport: behavior.SupportCorroborated,
	}
	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: spec})
	if len(matches) != 1 || !slices.Equal(matches[0].OperationIDs, []string{"operation-concrete"}) {
		t.Fatalf("concrete binding matches = %#v", matches)
	}
	if len(matches[0].AffectedResources) != 1 || matches[0].AffectedResources[0].Value != "/tmp/tool" {
		t.Fatalf("matched role projection = %#v", matches[0].AffectedResources)
	}
}

func TestConcreteClassifiedResourceBindingRequiresBothOnSameBinding(t *testing.T) {
	classified := behavior.NewResource(behavior.ResourceFile, "", behavior.ResourceClassBrowserCookieStore)
	concrete := behavior.NewResource(behavior.ResourceFile, "/tmp/unclassified")
	exact := behavior.NewResource(behavior.ResourceFile, "~/Library/Application Support/Google/Chrome/Default/Cookies", behavior.ResourceClassBrowserCookieStore)
	operation := func(id string, resources ...behavior.Resource) behavior.ModeledOperation {
		bindings := make([]behavior.ResourceBinding, 0, len(resources))
		for _, resource := range resources {
			bindings = append(bindings, behavior.Bind(behavior.ResourceRoleSource, resource))
		}
		return behavior.ModeledOperation{ID: id, SubjectNodeID: "node", Kind: behavior.OperationFileRead, ResourceBindings: bindings, EvidenceIDs: []string{"ev-" + id}, Support: behavior.SupportCorroborated, Execution: unknownExecution()}
	}
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		operation("operation-split", classified, concrete),
		operation("operation-exact", exact),
	}}
	spec := Spec{
		Metadata: Metadata{ID: "test.concrete-classified", Title: "Exact classified read", Namespace: "test", Description: "Tests one-binding classification and value proof."},
		Kind:     CapabilityRule,
		Match: Operation(behavior.OperationFileRead,
			ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassBrowserCookieStore)),
		MinimumSupport: behavior.SupportCorroborated,
	}
	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: spec})
	if len(matches) != 1 || !slices.Equal(matches[0].OperationIDs, []string{"operation-exact"}) || len(matches[0].AffectedResources) != 1 || matches[0].AffectedResources[0].Value != exact.Value {
		t.Fatalf("concrete classified matches = %#v", matches)
	}
}
