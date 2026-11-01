package extract

import (
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestRecognizeLocalAgentInvocationUsesClosedProductAndSafeguardProfiles(t *testing.T) {
	tests := []struct {
		name    string
		fields  []string
		product string
		reduced bool
		want    bool
	}{
		{name: "Claude", fields: []string{"claude", "--dangerously-skip-permissions", "-p", "inventory"}, product: "Claude Code", reduced: true, want: true},
		{name: "Codex", fields: []string{"/opt/bin/codex", "exec", "prompt", "--ask-for-approval", "never", "--sandbox", "danger-full-access"}, product: "OpenAI Codex CLI", reduced: true, want: true},
		{name: "Gemini", fields: []string{"gemini", "--yolo", "-p", "prompt"}, product: "Gemini CLI", reduced: true, want: true},
		{name: "Amazon Q", fields: []string{"q", "chat", "--trust-all-tools", "--no-interactive", "prompt"}, product: "Amazon Q Developer CLI", reduced: true, want: true},
		{name: "Copilot", fields: []string{"copilot", "--autopilot", "--yolo", "-p", "prompt"}, product: "GitHub Copilot CLI", reduced: true, want: true},
		{name: "Kiro", fields: []string{"kiro-cli", "chat", "--no-interactive", "prompt"}, product: "Kiro CLI", want: true},
		{name: "ordinary interactive Claude", fields: []string{"claude"}, product: "Claude Code", want: true},
		{name: "Claude version", fields: []string{"claude", "--version"}},
		{name: "Codex login", fields: []string{"codex", "login"}},
		{name: "Gemini MCP administration", fields: []string{"gemini", "mcp", "list"}},
		{name: "unrelated q", fields: []string{"q", "search", "text"}},
		{name: "similar basename", fields: []string{"claude-helper", "-p", "prompt"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := recognizeLocalAgentInvocation(test.fields)
			if ok != test.want {
				t.Fatalf("recognized = %v, want %v: %#v", ok, test.want, got)
			}
			if !ok {
				return
			}
			if got.command.product != test.product {
				t.Fatalf("product = %q, want %q", got.command.product, test.product)
			}
			if (len(got.reducedSafeguards) > 0) != test.reduced {
				t.Fatalf("reduced safeguards = %#v, want present=%v", got.reducedSafeguards, test.reduced)
			}
		})
	}
}

func TestLocalAgentFileClassificationRequiresExactKnownPaths(t *testing.T) {
	tests := []struct {
		path  string
		class behavior.ResourceClassification
	}{
		{path: "/Users/test/.claude/settings.json", class: behavior.ResourceClassAgentConfiguration},
		{path: "/Users/test/.codex/hooks.json", class: behavior.ResourceClassAgentHookConfig},
		{path: "/work/.cursor/mcp.json", class: behavior.ResourceClassAgentMCPConfig},
		{path: ".cursor/mcp.json", class: behavior.ResourceClassAgentMCPConfig},
		{path: "/work/.cursor/rules/startup.mdc", class: behavior.ResourceClassAgentInstruction},
		{path: "/work/AGENTS.md", class: behavior.ResourceClassAgentInstruction},
		{path: "/Users/test/.claude/projects/work/session.jsonl", class: behavior.ResourceClassAgentState},
		{path: "/Users/test/.codex/sessions/2026/session.jsonl", class: behavior.ResourceClassAgentState},
	}
	for _, test := range tests {
		resource, ok := localAgentFileResource(test.path)
		if !ok || !resource.HasClassification(test.class) || resource.Value != test.path {
			t.Fatalf("classification for %q = %#v, ok=%v", test.path, resource, ok)
		}
	}
	for _, value := range []string{
		"https://example.invalid/.claude/settings.json",
		"/tmp/.claude/settings.json.bak",
		"/tmp/CLAUDE.md.txt",
		"/tmp/claude.md",
		".gemini/trustedfolders.json",
		`.claude\settings.json`,
		"/tmp/settings.json",
		"/tmp/mcp.json",
		"/tmp/session.jsonl",
	} {
		if resource, ok := localAgentFileResource(value); ok {
			t.Fatalf("close negative %q classified as %#v", value, resource)
		}
	}
}

func TestJavaScriptAgentActivityUsesGenericProcessAndFileOperations(t *testing.T) {
	source := `const { spawnSync } = require("child_process");
const fs = require("fs");
spawnSync("claude", ["--dangerously-skip-permissions", "-p", "inventory"]);
fs.readFileSync("/Users/test/.claude/projects/work/session.jsonl");
fs.copyFileSync("/tmp/replacement.jsonl", "/Users/test/.claude/projects/work/session.jsonl");
fs.writeFileSync("/Users/test/.cursor/mcp.json", "{}");
`
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{NodeID: "node-js", LogicalPath: "fixture.js", Kind: "script", MediaType: "text/javascript", Data: []byte(source)})

	process := findOperationWithClassification(graph.Operations, behavior.OperationProcessExecute, behavior.ResourceClassAgentRuntime)
	if process == nil || process.Support != behavior.SupportCorroborated || process.Qualifiers["agent_product"] != "Claude Code" {
		t.Fatalf("agent process operation = %#v", process)
	}
	arguments, ok := process.FirstBinding(behavior.ResourceRoleArguments)
	if !ok || !arguments.Resource.HasClassification(behavior.ResourceClassAgentReducedSafeguards) || arguments.Resource.Value != "--dangerously-skip-permissions -p inventory" {
		t.Fatalf("agent arguments = %#v, ok=%v", arguments, ok)
	}
	if findOperationWithClassification(graph.Operations, behavior.OperationFileRead, behavior.ResourceClassAgentState) == nil {
		t.Fatalf("agent state read not retained: %#v", graph.Operations)
	}
	if findOperationWithClassification(graph.Operations, behavior.OperationFileCopy, behavior.ResourceClassAgentState) == nil {
		t.Fatalf("agent state copy target not retained: %#v", graph.Operations)
	}
	if findOperationWithClassification(graph.Operations, behavior.OperationFileWrite, behavior.ResourceClassAgentMCPConfig) == nil {
		t.Fatalf("agent MCP configuration write not retained: %#v", graph.Operations)
	}
	if err := graph.Sort(); err != nil {
		t.Fatalf("agent graph references: %v", err)
	}
}

func TestAgentInvocationParityAcrossShellPythonAndJavaScript(t *testing.T) {
	tests := []struct {
		path string
		data string
	}{
		{path: "fixture.sh", data: "#!/bin/sh\nclaude --dangerously-skip-permissions -p inventory\n"},
		{path: "fixture.py", data: "import subprocess\nsubprocess.run(['claude', '--dangerously-skip-permissions', '-p', 'inventory'])\n"},
		{path: "fixture.js", data: "const { spawnSync } = require('child_process');\nspawnSync('claude', ['--dangerously-skip-permissions', '-p', 'inventory']);\n"},
	}
	for _, test := range tests {
		var graph behavior.Graph
		ExtractText(&graph, artifact.Content{NodeID: "node", LogicalPath: test.path, Kind: "script", MediaType: "text/plain", Data: []byte(test.data)})
		operation := findOperationWithClassification(graph.Operations, behavior.OperationProcessExecute, behavior.ResourceClassAgentRuntime)
		if operation == nil || operation.Qualifiers["agent_product"] != "Claude Code" {
			t.Fatalf("%s agent invocation = %#v; operations=%#v", test.path, operation, graph.Operations)
		}
	}
}

func TestLocalAgentOperationEnrichmentPreservesNativeProofBoundaries(t *testing.T) {
	operation := behavior.ModeledOperation{
		Kind: behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "claude"), "ev-executable"),
			behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, `["claude","--dangerously-skip-permissions","-p","inventory"]`), "ev-argv"),
		),
		Qualifiers: map[string]string{"api": "execvp"},
	}
	if !applyLocalAgentInvocationSemantics(&operation, []string{"claude", "--dangerously-skip-permissions", "-p", "inventory"}) {
		t.Fatal("exact native agent fields were not enriched")
	}
	executable, _ := operation.FirstBinding(behavior.ResourceRoleExecutable)
	if executable.Resource.Value != "" || !executable.Resource.HasClassification(behavior.ResourceClassAgentRuntime) || len(executable.EvidenceIDs) != 1 {
		t.Fatalf("PATH-selected executable proof changed: %#v", executable)
	}
	arguments, _ := operation.FirstBinding(behavior.ResourceRoleArguments)
	if !arguments.Resource.HasClassification(behavior.ResourceClassAgentReducedSafeguards) || len(arguments.EvidenceIDs) != 1 {
		t.Fatalf("exact native argv proof changed: %#v", arguments)
	}
	if operation.Qualifiers["api"] != "execvp" || operation.Qualifiers["path_resolution"] != "runtime PATH lookup not authenticated" {
		t.Fatalf("native qualifiers changed or lost: %#v", operation.Qualifiers)
	}

	pathOperation := behavior.ModeledOperation{
		Kind: behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/opt/tools/codex")),
		),
	}
	if !applyLocalAgentInvocationSemantics(&pathOperation, []string{"/opt/tools/codex", "exec", "inventory"}) {
		t.Fatal("path-qualified agent invocation was not enriched")
	}
	pathExecutable, _ := pathOperation.FirstBinding(behavior.ResourceRoleExecutable)
	if pathExecutable.Resource.Value != "/opt/tools/codex" || pathOperation.Qualifiers["path_resolution"] != "exact static path; executable bytes not authenticated" {
		t.Fatalf("path-qualified executable identity changed: resource=%#v qualifiers=%#v", pathExecutable.Resource, pathOperation.Qualifiers)
	}
}

func findOperationWithClassification(operations []behavior.ModeledOperation, kind behavior.OperationKind, class behavior.ResourceClassification) *behavior.ModeledOperation {
	for index := range operations {
		if operations[index].Kind != kind {
			continue
		}
		for _, binding := range operations[index].ResourceBindings {
			if binding.Resource.HasClassification(class) {
				return &operations[index]
			}
		}
	}
	return nil
}
