package rules

import (
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestLocalAgentInvocationRulesRequireTypedExecutableAndExactSafeguardArguments(t *testing.T) {
	operation := behavior.ModeledOperation{
		ID: "operation-agent", SubjectNodeID: "node-agent", Kind: behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "", behavior.ResourceClassAgentRuntime)),
			behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, "--dangerously-skip-permissions -p prompt", behavior.ResourceClassAgentReducedSafeguards)),
		),
		EvidenceIDs: []string{"ev-agent"}, Support: behavior.SupportCorroborated,
		Execution: connectedExecution("root-agent"),
	}
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{operation}}
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSLocalAgentInvocation}); len(got) != 1 {
		t.Fatalf("agent invocation matches = %#v", got)
	}
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSLocalAgentReducedSafeguards}); len(got) != 1 {
		t.Fatalf("reduced-safeguard matches = %#v", got)
	}
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSFileExecution}); len(got) != 0 {
		t.Fatalf("runtime PATH command became concrete file execution: %#v", got)
	}

	graph.Operations[0].ResourceBindings[1].Resource.Classifications = nil
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSLocalAgentInvocation}); len(got) != 1 {
		t.Fatalf("ordinary agent invocation should remain reportable: %#v", got)
	}
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSLocalAgentReducedSafeguards}); len(got) != 0 {
		t.Fatalf("unclassified arguments matched reduced safeguards: %#v", got)
	}

	graph.Operations[0].Support = behavior.SupportHeuristic
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSLocalAgentInvocation}); len(got) != 0 {
		t.Fatalf("heuristic source operation matched agent capability: %#v", got)
	}
}

func TestLocalAgentFileRulesRemainNeutralAndRoleExact(t *testing.T) {
	state := behavior.NewResource(behavior.ResourceFile, "/Users/test/.claude/projects/work/session.jsonl", behavior.ResourceClassAgentState)
	config := behavior.NewResource(behavior.ResourceFile, "/work/.cursor/mcp.json", behavior.ResourceClassAgentMCPConfig)
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		{
			ID: "operation-read", SubjectNodeID: "node-agent", Kind: behavior.OperationFileRead,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, state)),
			EvidenceIDs:      []string{"ev-read"}, Support: behavior.SupportCorroborated, Execution: connectedExecution("root-agent"),
		},
		{
			ID: "operation-write", SubjectNodeID: "node-agent", Kind: behavior.OperationFileWrite,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, config)),
			EvidenceIDs:      []string{"ev-write"}, Support: behavior.SupportCorroborated, Execution: connectedExecution("root-agent"),
		},
	}}
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSLocalAgentStateAccess}); len(got) != 1 {
		t.Fatalf("agent state-access matches = %#v", got)
	}
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSLocalAgentConfigurationModification}); len(got) != 1 {
		t.Fatalf("agent configuration matches = %#v", got)
	}
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSLocalAgentStateModification}); len(got) != 0 {
		t.Fatalf("read-only state access became modification: %#v", got)
	}

	graph.Operations[1].ResourceBindings[0].Role = behavior.ResourceRoleSource
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSLocalAgentConfigurationModification}); len(got) != 0 {
		t.Fatalf("wrong-role config resource matched modification: %#v", got)
	}
}
