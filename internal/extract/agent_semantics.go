package extract

import (
	"path/filepath"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const localAgentCLIProfile = "local-agent-cli-2026-08-23"

// Local-agent recognition is deliberately a closed, versioned semantic table.
// It describes ordinary developer tools and data locations; it does not assign
// malicious intent or imply that an invoked agent completed any requested work.
type localAgentCommand struct {
	product string
	tool    string
}

var localAgentCommands = map[string]localAgentCommand{
	"claude":       {product: "Claude Code", tool: "claude"},
	"codex":        {product: "OpenAI Codex CLI", tool: "codex"},
	"copilot":      {product: "GitHub Copilot CLI", tool: "copilot"},
	"cursor-agent": {product: "Cursor Agent", tool: "cursor-agent"},
	"gemini":       {product: "Gemini CLI", tool: "gemini"},
	"kiro-cli":     {product: "Kiro CLI", tool: "kiro-cli"},
	"q":            {product: "Amazon Q Developer CLI", tool: "q"},
}

type localAgentInvocation struct {
	command           localAgentCommand
	reducedSafeguards []string
}

func recognizeLocalAgentInvocation(fields []string) (localAgentInvocation, bool) {
	if len(fields) == 0 {
		return localAgentInvocation{}, false
	}
	base := filepath.Base(strings.TrimSpace(fields[0]))
	command, ok := localAgentCommands[base]
	if !ok || !localAgentSessionForm(command.tool, fields[1:]) {
		return localAgentInvocation{}, false
	}
	return localAgentInvocation{
		command:           command,
		reducedSafeguards: localAgentReducedSafeguards(command.tool, fields[1:]),
	}, true
}

func localAgentSessionForm(tool string, args []string) bool {
	if tool == "q" {
		return len(args) > 0 && args[0] == "chat"
	}
	if tool == "kiro-cli" {
		return len(args) > 0 && args[0] == "chat"
	}
	if len(args) == 0 {
		return true
	}
	first := args[0]
	if first == "--help" || first == "-h" || first == "--version" || first == "-v" {
		return false
	}
	switch tool {
	case "claude":
		return first != "doctor" && first != "install" && first != "mcp" && first != "plugin" && first != "update"
	case "codex":
		return first != "app-server" && first != "completion" && first != "features" && first != "login" && first != "logout" && first != "mcp" && first != "mcp-server" && first != "sandbox"
	case "gemini":
		return first != "extensions" && first != "hooks" && first != "mcp"
	default:
		return true
	}
}

func localAgentReducedSafeguards(tool string, args []string) []string {
	var modes []string
	add := func(value string) {
		for _, existing := range modes {
			if existing == value {
				return
			}
		}
		modes = append(modes, value)
	}
	for index, arg := range args {
		next := ""
		if index+1 < len(args) {
			next = args[index+1]
		}
		switch tool {
		case "claude":
			switch {
			case arg == "--dangerously-skip-permissions":
				add("permission prompts bypassed")
			case arg == "--permission-mode" && next == "bypassPermissions", arg == "--permission-mode=bypassPermissions":
				add("bypassPermissions mode selected")
			}
		case "codex":
			switch {
			case arg == "--dangerously-bypass-approvals-and-sandbox":
				add("approvals and sandbox bypass requested")
			case arg == "--ask-for-approval" && next == "never", arg == "--ask-for-approval=never":
				add("approval policy never selected")
			case arg == "--sandbox" && next == "danger-full-access", arg == "--sandbox=danger-full-access":
				add("danger-full-access sandbox mode selected")
			}
		case "gemini":
			switch {
			case arg == "--yolo" || arg == "-y":
				add("yolo approval mode selected")
			case arg == "--approval-mode" && next == "yolo", arg == "--approval-mode=yolo":
				add("yolo approval mode selected")
			}
		case "q":
			if arg == "--trust-all-tools" {
				add("all tools trusted")
			}
		case "copilot":
			if arg == "--yolo" {
				add("yolo mode selected")
			}
		}
	}
	return modes
}

func addLocalAgentInvocationOperation(
	graph *behavior.Graph,
	content artifact.Content,
	fields []string,
	lineNo int,
	execution behavior.ExecutionContext,
	evidenceID string,
) string {
	if _, ok := recognizeLocalAgentInvocation(fields); !ok {
		return ""
	}
	executable := behavior.NewResource(behavior.ResourceFile, staticShellResource(fields[0]))
	bindings := behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, executable))
	if arguments := staticShellResource(strings.Join(fields[1:], " ")); arguments != "" {
		bindings = append(bindings, behavior.Bind(
			behavior.ResourceRoleArguments,
			behavior.NewResource(behavior.ResourceCommand, arguments),
		))
	}
	operation := behavior.ModeledOperation{
		SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationProcessExecute,
		ResourceBindings: bindings,
		EvidenceIDs:      shellOperationEvidence(content, evidenceID), Support: behavior.SupportCorroborated,
		Execution: execution, Architecture: content.Architecture, Line: lineNo,
	}
	if !applyLocalAgentInvocationSemantics(&operation, fields) {
		return ""
	}
	return graph.AddOperation(operation)
}

// applyLocalAgentInvocationSemantics enriches an already-proven process
// operation. Callers must supply exact fields recovered by their own adapter;
// this function never tokenizes strings or searches unrelated literals.
func applyLocalAgentInvocationSemantics(operation *behavior.ModeledOperation, fields []string) bool {
	if operation == nil || operation.Kind != behavior.OperationProcessExecute {
		return false
	}
	invocation, ok := recognizeLocalAgentInvocation(fields)
	if !ok {
		return false
	}
	foundExecutable := false
	for index := range operation.ResourceBindings {
		binding := &operation.ResourceBindings[index]
		if binding.Role != behavior.ResourceRoleExecutable || binding.Resource.Kind != behavior.ResourceFile {
			continue
		}
		executableValue := ""
		if strings.Contains(fields[0], "/") {
			executableValue = binding.Resource.Value
			if executableValue == "" {
				executableValue = fields[0]
			}
		}
		binding.Resource = behavior.NewResource(behavior.ResourceFile, executableValue, behavior.ResourceClassAgentRuntime)
		foundExecutable = true
		break
	}
	if !foundExecutable {
		return false
	}
	if len(invocation.reducedSafeguards) > 0 {
		for index := range operation.ResourceBindings {
			binding := &operation.ResourceBindings[index]
			if binding.Role == behavior.ResourceRoleArguments && binding.Resource.Kind == behavior.ResourceCommand {
				binding.Resource.Classifications = append(binding.Resource.Classifications, behavior.ResourceClassAgentReducedSafeguards)
				break
			}
		}
	}
	if operation.Qualifiers == nil {
		operation.Qualifiers = make(map[string]string)
	}
	operation.Qualifiers["agent_profile"] = localAgentCLIProfile
	operation.Qualifiers["agent_product"] = invocation.command.product
	operation.Qualifiers["agent_tool"] = invocation.command.tool
	operation.Qualifiers["invocation_profile"] = "documented-local-cli"
	if strings.Contains(fields[0], "/") {
		operation.Qualifiers["path_resolution"] = "exact static path; executable bytes not authenticated"
	} else {
		operation.Qualifiers["path_resolution"] = "runtime PATH lookup not authenticated"
	}
	if len(invocation.reducedSafeguards) > 0 {
		operation.Qualifiers["reduced_safeguards"] = strings.Join(invocation.reducedSafeguards, "; ")
	}
	return true
}

func classifiedFileResource(value string) behavior.Resource {
	if resource, ok := localAgentFileResource(value); ok {
		return resource
	}
	if resource, ok := sensitiveResource(value); ok {
		return resource
	}
	return behavior.NewResource(behavior.ResourceFile, value)
}

func localAgentFileResource(value string) (behavior.Resource, bool) {
	normalized := strings.TrimSpace(value)
	if normalized == "" || strings.ContainsRune(normalized, '\x00') || strings.Contains(normalized, "://") {
		return behavior.Resource{}, false
	}
	classification := localAgentFileClassification(normalized)
	if classification == "" {
		return behavior.Resource{}, false
	}
	return behavior.NewResource(behavior.ResourceFile, value, classification), true
}

func localAgentFileClassification(path string) behavior.ResourceClassification {
	base := filepath.Base(path)
	switch base {
	case "AGENTS.md", "CLAUDE.md", "GEMINI.md":
		return behavior.ResourceClassAgentInstruction
	}
	if agentPathContains(path, ".cursor/rules/") && strings.HasSuffix(path, ".mdc") ||
		agentPathHasSuffix(path, ".github/copilot-instructions.md") {
		return behavior.ResourceClassAgentInstruction
	}
	if agentPathHasSuffix(path, ".codex/hooks.json") {
		return behavior.ResourceClassAgentHookConfig
	}
	for _, suffix := range []string{
		".cursor/mcp.json",
		".factory/mcp.json",
		".vscode/mcp.json",
		".aws/amazonq/mcp.json",
		".codeium/windsurf/mcp_config.json",
		"Library/Application Support/Claude/claude_desktop_config.json",
	} {
		if agentPathHasSuffix(path, suffix) {
			return behavior.ResourceClassAgentMCPConfig
		}
	}
	for _, suffix := range []string{
		".claude/settings.json",
		".claude/settings.local.json",
		".claude.json",
		".codex/config.toml",
		".continue/config.json",
		".gemini/settings.json",
		".gemini/trustedFolders.json",
	} {
		if agentPathHasSuffix(path, suffix) {
			return behavior.ResourceClassAgentConfiguration
		}
	}
	if agentPathHasSuffix(path, ".claude/history.jsonl") ||
		agentPathContains(path, ".claude/projects/") && strings.HasSuffix(path, ".jsonl") ||
		agentPathHasSuffix(path, ".codex/history.jsonl") ||
		agentPathContains(path, ".codex/sessions/") && strings.HasSuffix(path, ".jsonl") ||
		agentPathContains(path, ".codex/archived_sessions/") && strings.HasSuffix(path, ".jsonl") {
		return behavior.ResourceClassAgentState
	}
	return ""
}

func agentPathHasSuffix(path, suffix string) bool {
	return path == suffix || strings.HasSuffix(path, "/"+suffix)
}

func agentPathContains(path, segment string) bool {
	return strings.HasPrefix(path, segment) || strings.Contains(path, "/"+segment)
}
