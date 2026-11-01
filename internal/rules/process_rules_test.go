package rules

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestProcessPrimitiveRulesPreserveNeutralTypedSupport(t *testing.T) {
	for _, test := range []struct {
		name string
		spec Spec
		kind behavior.OperationKind
	}{
		{name: "task access", spec: MacOSProcessTaskAccess, kind: behavior.OperationProcessTaskAccess},
		{name: "thread creation", spec: MacOSProcessThreadCreation, kind: behavior.OperationProcessThreadCreate},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !strings.HasPrefix(test.spec.Metadata.Title, "Requests Mach ") || !strings.Contains(test.spec.Metadata.Description, "ownership") || !strings.Contains(test.spec.Metadata.Description, "runtime success") || !strings.Contains(test.spec.Metadata.Description, "does not by itself") {
				t.Fatalf("process rule metadata overstates or obscures the primitive: %#v", test.spec.Metadata)
			}
			graph := behavior.Graph{Operations: []behavior.ModeledOperation{
				processPrimitiveRuleOperation("operation-direct", test.kind, behavior.ResourceRoleTargetProcess, behavior.ResourceProcess, behavior.SupportDirect, connectedExecution("root-main")),
				processPrimitiveRuleOperation("operation-corroborated", test.kind, behavior.ResourceRoleTargetProcess, behavior.ResourceProcess, behavior.SupportCorroborated, unknownExecution()),
				processPrimitiveRuleOperation("operation-wrong-role", test.kind, behavior.ResourceRoleTargetMemory, behavior.ResourceProcess, behavior.SupportDirect, connectedExecution("root-main")),
				processPrimitiveRuleOperation("operation-wrong-resource", test.kind, behavior.ResourceRoleTargetProcess, behavior.ResourceProcessMemory, behavior.SupportDirect, connectedExecution("root-main")),
				processPrimitiveRuleOperation("operation-weak", test.kind, behavior.ResourceRoleTargetProcess, behavior.ResourceProcess, behavior.SupportHeuristic, connectedExecution("root-main")),
				processPrimitiveRuleOperation("operation-malformed", test.kind, behavior.ResourceRoleTargetProcess, behavior.ResourceProcess, behavior.SupportDirect, behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected}),
				processPrimitiveRuleOperation("operation-unrelated", behavior.OperationProcessMemoryRead, behavior.ResourceRoleTargetProcess, behavior.ResourceProcess, behavior.SupportDirect, connectedExecution("root-main")),
			}}

			matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: test.spec})
			if len(matches) != 2 {
				t.Fatalf("matches = %#v, want direct and corroborated typed operations", matches)
			}
			if matches[0].OperationIDs[0] != "operation-corroborated" || matches[0].Support != behavior.SupportCorroborated || matches[0].Execution.Connectivity != behavior.ConnectivityUnknown {
				t.Fatalf("corroborated match lost honest support/connectivity: %#v", matches[0])
			}
			if matches[1].OperationIDs[0] != "operation-direct" || matches[1].Support != behavior.SupportDirect || matches[1].Execution.Connectivity != behavior.ConnectivityConnected {
				t.Fatalf("direct match lost honest support/connectivity: %#v", matches[1])
			}
			for _, match := range matches {
				if match.RuleID != test.spec.Metadata.ID || len(match.Attack) != 0 || len(match.MBC) != 0 {
					t.Fatalf("neutral process match gained a tactic mapping: %#v", match)
				}
				if len(match.AffectedResources) != 1 || match.AffectedResources[0].Kind != behavior.ResourceProcess || match.AffectedResources[0].Value != "pid:42" {
					t.Fatalf("target process projection = %#v", match.AffectedResources)
				}
				if len(match.EvidenceIDs) != 1 || match.EvidenceIDs[0] != "ev-"+match.OperationIDs[0] {
					t.Fatalf("operation evidence was not projected: %#v", match)
				}
				if len(match.ArchitectureScopes) != 1 || match.ArchitectureScopes[0] != "arm64" {
					t.Fatalf("architecture scope was not preserved: %#v", match)
				}
			}

			reversed := graph
			reversed.Operations = append([]behavior.ModeledOperation(nil), graph.Operations...)
			for left, right := 0, len(reversed.Operations)-1; left < right; left, right = left+1, right-1 {
				reversed.Operations[left], reversed.Operations[right] = reversed.Operations[right], reversed.Operations[left]
			}
			if got := evaluateCompiledSpecForTest(&reversed, compiledSpec{spec: test.spec}); !reflect.DeepEqual(got, matches) {
				t.Fatalf("input order changed matches:\nfirst: %#v\nsecond: %#v", matches, got)
			}
		})
	}
}

func TestProcessTaskAccessRuleBoundsHostileCardinality(t *testing.T) {
	graph := behavior.Graph{}
	for index := 0; index < ruleCapabilityMatchCandidateLimit+100; index++ {
		operation := processPrimitiveRuleOperation(
			fmt.Sprintf("operation-%04d", index),
			behavior.OperationProcessTaskAccess,
			behavior.ResourceRoleTargetProcess,
			behavior.ResourceProcess,
			behavior.SupportDirect,
			unknownExecution(),
		)
		operation.SubjectNodeID = fmt.Sprintf("node-%04d", index)
		operation.ResourceBindings[0].Resource.Value = fmt.Sprintf("pid:%d", index)
		graph.Operations = append(graph.Operations, operation)
	}

	matches := evaluateCompiledRules(&graph, []compiledSpec{{spec: MacOSProcessTaskAccess}})
	if len(matches) != maxCapabilityMatchesPerRule {
		t.Fatalf("matches = %d, want bounded %d", len(matches), maxCapabilityMatchesPerRule)
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "rule-evaluation" || graph.Coverage[0].Status != "partial" {
		t.Fatalf("hostile cardinality was not disclosed: %#v", graph.Coverage)
	}
}

func processPrimitiveRuleOperation(id string, kind behavior.OperationKind, role behavior.ResourceRole, resourceKind behavior.ResourceKind, support behavior.Support, execution behavior.ExecutionContext) behavior.ModeledOperation {
	return behavior.ModeledOperation{
		ID:            id,
		SubjectNodeID: "node-process",
		ScopeID:       "scope-main",
		Kind:          kind,
		ResourceBindings: behavior.Bindings(behavior.Bind(
			role,
			behavior.NewResource(resourceKind, "pid:42"),
		)),
		EvidenceIDs:    []string{"ev-" + id},
		Support:        support,
		Execution:      execution,
		SourceFunction: "main",
		Architecture:   "arm64",
	}
}
