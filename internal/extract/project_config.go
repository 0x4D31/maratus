package extract

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxProjectConfigCommands       = 256
	maxProjectConfigCommandArgs    = 256
	maxProjectConfigCommandBytes   = 64 << 10
	maxProjectConfigResolutionWork = 4096
)

type projectCommandMode string

const (
	projectCommandShell projectCommandMode = "shell"
	projectCommandExec  projectCommandMode = "exec"
)

type projectCommandPlan struct {
	content     artifact.Content
	rootKind    string
	rootName    string
	mode        projectCommandMode
	interpreter string
	// interpreterUnresolved separates shell-language parsing from a claim
	// about the concrete host shell. Some hosts select a runtime shell rather
	// than a fixed executable declared by the artifact.
	interpreterUnresolved bool
	command               string
	args                  []string
	evidenceKind          string
	evidenceValue         string
	coverageArea          string
	gateDetail            string
	targets               []string
}

type projectConfigIssue struct {
	nodeID string
	area   string
	detail string
}

type projectCommandPlanSet struct {
	commands []projectCommandPlan
	issues   []projectConfigIssue
}

// commandTargetPolicy records the exact host-relative logical paths
// that one modeled project command may resolve. Presence of an operation ID is
// significant even when its set is empty: project configuration must not fall
// through to the generic sibling-target resolver after a host-specific base
// check failed.
type commandTargetPolicy map[string]map[string]bool

func planProjectConfigCommands(contents []artifact.Content) projectCommandPlanSet {
	var plans projectCommandPlanSet
	codexHookPlanningWork := 0
	for _, content := range contents {
		if content.RawFeaturesOnly || !executionRootAllowed(content) || !behaviorSourceRoleAllowed(content.Role, false) {
			continue
		}
		_, vscodeConfig := vscodeTasksProjectRoot(content.LogicalPath)
		_, claudeConfig := claudeSettingsProjectRoot(content.LogicalPath)
		_, codexHooksConfig := codexHooksProjectRoot(content.LogicalPath)
		_, geminiConfig := geminiSettingsProjectRoot(content.LogicalPath)
		if !vscodeConfig && !claudeConfig && !codexHooksConfig && !geminiConfig {
			continue
		}
		area := vscodeTasksAnalysisArea
		if claudeConfig {
			area = claudeSessionStartAnalysisArea
		} else if codexHooksConfig {
			area = codexHooksAnalysisArea
		} else if geminiConfig {
			area = geminiSessionStartAnalysisArea
		}
		if len(plans.commands) >= maxProjectConfigResolutionWork {
			plans.issues = append(plans.issues, projectConfigIssue{
				nodeID: content.NodeID,
				area:   area,
				detail: fmt.Sprintf("project command work limit %d reached; remaining configurations were not analyzed", maxProjectConfigResolutionWork),
			})
			break
		}
		var commands []projectCommandPlan
		var issues []projectConfigIssue
		if vscodeConfig {
			commands, issues = planVSCodeFolderOpenTasks(content)
		} else if claudeConfig {
			commands, issues = planClaudeSessionStartHooks(content)
		} else if codexHooksConfig {
			commands, issues = planCodexProjectHooks(content, &codexHookPlanningWork)
		} else {
			commands, issues = planGeminiSessionStartHooks(content)
		}
		remaining := maxProjectConfigResolutionWork - len(plans.commands)
		if len(commands) > remaining {
			commands = commands[:remaining]
			issues = append(issues, projectConfigIssue{
				nodeID: content.NodeID,
				area:   area,
				detail: fmt.Sprintf("project command work limit %d reached; remaining project commands were not analyzed", maxProjectConfigResolutionWork),
			})
		}
		plans.commands = append(plans.commands, commands...)
		plans.issues = append(plans.issues, issues...)
	}
	sort.SliceStable(plans.commands, func(i, j int) bool {
		left, right := plans.commands[i], plans.commands[j]
		if left.content.LogicalPath != right.content.LogicalPath {
			return left.content.LogicalPath < right.content.LogicalPath
		}
		if left.rootKind != right.rootKind {
			return left.rootKind < right.rootKind
		}
		if left.rootName != right.rootName {
			return left.rootName < right.rootName
		}
		if left.command != right.command {
			return left.command < right.command
		}
		return strings.Join(left.args, "\x00") < strings.Join(right.args, "\x00")
	})
	return plans
}

func projectConfigExplicitTargetNodes(plans projectCommandPlanSet, contents []artifact.Content) map[string]bool {
	index := newLogicalContentIndex(contents)
	targets := map[string]bool{}
	for _, plan := range plans.commands {
		for _, logical := range plan.targets {
			content, ok := index.unique[logical]
			if !ok || index.ambiguous[logical] || !retainedScriptTarget(content) {
				continue
			}
			targets[content.NodeID] = true
		}
	}
	return targets
}

func ResolveProjectConfigCommands(graph *behavior.Graph, plans projectCommandPlanSet) commandTargetPolicy {
	targetPolicy := make(commandTargetPolicy)
	for _, issue := range plans.issues {
		addPartialCoverageOnce(graph, issue.nodeID, issue.area, issue.detail)
	}
	for _, plan := range plans.commands {
		if graph.WorkLimitReached() {
			markDerivedGraphLimit(graph, plan.coverageArea)
			return targetPolicy
		}
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:   plan.content.NodeID,
			ScopeID:  plan.content.ScopeID,
			Logical:  plan.content.LogicalPath,
			Physical: plan.content.PhysicalPath,
			Method:   "project-configuration",
			Kind:     plan.evidenceKind,
			Value:    plan.evidenceValue,
		})
		if evidenceID == "" {
			markDerivedGraphLimit(graph, plan.coverageArea)
			return targetPolicy
		}
		scopeID := graph.AddScope(behavior.Scope{
			NodeID:     plan.content.NodeID,
			ParentID:   plan.content.ScopeID,
			Kind:       "project-command",
			Name:       plan.rootName,
			SourceRole: plan.content.Role,
		})
		if scopeID == "" {
			markDerivedGraphLimit(graph, plan.coverageArea)
			return targetPolicy
		}
		rootArguments := append([]string{plan.command}, plan.args...)
		rootID := graph.AddExecutionRoot(behavior.ExecutionRoot{
			Kind:              plan.rootKind,
			DeclarationNodeID: plan.content.NodeID,
			StartScopeID:      scopeID,
			Name:              plan.rootName,
			Interpreter:       projectCommandInterpreter(plan),
			Arguments:         rootArguments,
			EvidenceIDs:       []string{evidenceID},
		})
		if rootID == "" {
			markDerivedGraphLimit(graph, plan.coverageArea)
			return targetPolicy
		}
		graph.AddAnalysisSelection(behavior.AnalysisSelection{NodeID: plan.content.NodeID, Reasons: []behavior.SelectionReason{behavior.SelectionReasonExecutionRoot}})
		addPartialCoverageOnce(graph, plan.content.NodeID, plan.coverageArea, plan.gateDetail)

		commandContent := plan.content
		commandContent.ScopeID = scopeID
		execution := connectedExecutionContext([]string{rootID}, nil)
		commandContent = contentWithExecutionContext(commandContent, execution)
		operationStart := len(graph.Operations)
		analyzeProjectCommand(graph, commandContent, plan, execution, evidenceID)
		allowed := make(map[string]bool, len(plan.targets))
		for _, logical := range plan.targets {
			allowed[logical] = true
		}
		for index := operationStart; index < len(graph.Operations); index++ {
			operation := graph.Operations[index]
			if scriptTargetSourceOperation(operation) {
				targetPolicy[operation.ID] = allowed
			}
		}
	}
	return targetPolicy
}

func projectCommandInterpreter(plan projectCommandPlan) string {
	if plan.interpreterUnresolved {
		return ""
	}
	return plan.interpreter
}

func analyzeProjectCommand(graph *behavior.Graph, content artifact.Content, plan projectCommandPlan, execution behavior.ExecutionContext, evidenceID string) {
	fields, simple := projectCommandFields(plan)
	if plan.mode == projectCommandExec {
		if len(fields) == 0 {
			return
		}
		operationStart := len(graph.Operations)
		analyzeShellFields(graph, content, fields, 0, execution, evidenceID, 0, nil)
		if len(graph.Operations) == operationStart {
			addProcessExecuteOperation(graph, content, fields, 0, execution, evidenceID)
		}
		return
	}
	if simple {
		analyzeShellFields(graph, content, fields, 0, execution, evidenceID, 0, nil)
		return
	}
	AnalyzeShellLine(graph, content, normalizeProjectCommandShellText(plan), 0, execution, evidenceID)
}

func projectCommandFields(plan projectCommandPlan) ([]string, bool) {
	if plan.mode == projectCommandExec {
		fields := append([]string{plan.command}, plan.args...)
		return normalizeProjectCommandFields(plan, fields), true
	}
	command := normalizeProjectCommandShellText(plan)
	commands := 0
	var only string
	complete := visitCommands(command, func(command string) bool {
		commands++
		only = command
		return commands <= 1
	})
	if !complete || commands != 1 || len(splitPipeline(only)) != 1 || shellSourceOrderHasAlternativeControlFlow(only) {
		return nil, false
	}
	if foreground, background := stripTerminalBackgroundOperator(only); background || foreground != strings.TrimSpace(only) {
		return nil, false
	}
	hasSubstitution, unsupportedGrouping, unsupportedExpansion, malformed := shellSubstitutionStatus(only)
	if hasSubstitution || unsupportedGrouping || unsupportedExpansion || malformed {
		return nil, false
	}
	fields, err := CommandFields(only)
	if err != nil || len(fields) == 0 {
		return nil, false
	}
	normalized := fields
	if len(plan.args) > 0 {
		normalized = append(normalized, normalizeProjectCommandFields(plan, plan.args)...)
	}
	return normalized, true
}

func normalizeProjectCommandFields(plan projectCommandPlan, fields []string) []string {
	out := make([]string, len(fields))
	for index, field := range fields {
		out[index] = normalizeProjectCommandField(plan, field)
	}
	return out
}

func normalizeProjectCommandShellText(plan projectCommandPlan) string {
	command := plan.command
	switch plan.rootKind {
	case claudeSessionStartRootKind:
		for _, placeholder := range []string{"${CLAUDE_PROJECT_DIR}", "$CLAUDE_PROJECT_DIR"} {
			command = replaceShellProjectRootPlaceholder(command, placeholder, ".", placeholder)
		}
	case vscodeTasksRootKind:
		// VS Code performs variable substitution before passing a shell task to
		// the selected automation shell, so shell quoting does not suppress this
		// host-side workspaceFolder expansion.
		command = strings.ReplaceAll(command, "${workspaceFolder}", ".")
	}
	return command
}

func hasUnresolvedProjectCommandExpansion(values []string, allowed ...string) bool {
	for _, value := range values {
		for _, placeholder := range allowed {
			value = replaceProjectCommandExpansion(value, placeholder, "")
		}
		if strings.ContainsAny(value, "$`") {
			return true
		}
	}
	return false
}

func replaceProjectCommandExpansion(value, placeholder, replacement string) string {
	var output strings.Builder
	output.Grow(len(value))
	for index := 0; index < len(value); {
		if projectCommandExpansionAt(value, index, placeholder) {
			output.WriteString(replacement)
			index += len(placeholder)
			continue
		}
		output.WriteByte(value[index])
		index++
	}
	return output.String()
}

func projectCommandExpansionAt(value string, index int, placeholder string) bool {
	if index < 0 || index > len(value) || !strings.HasPrefix(value[index:], placeholder) {
		return false
	}
	if placeholder != "$CLAUDE_PROJECT_DIR" {
		return true
	}
	end := index + len(placeholder)
	return end == len(value) || !shellVariableNameByte(value[end])
}

func shellVariableNameByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_'
}

func normalizeProjectCommandField(plan projectCommandPlan, field string) string {
	var placeholders []string
	switch plan.rootKind {
	case claudeSessionStartRootKind:
		placeholders = []string{"${CLAUDE_PROJECT_DIR}"}
	case vscodeTasksRootKind:
		placeholders = []string{"${workspaceFolder}"}
	}
	for _, placeholder := range placeholders {
		if field == placeholder {
			return "."
		}
		if strings.HasPrefix(field, placeholder+"/") {
			return "./" + strings.TrimPrefix(field, placeholder+"/")
		}
	}
	return field
}

const (
	projectRootTargetMarker  = "__MARATUS_PROJECT_ROOT_TARGET__"
	projectRootLiteralMarker = "__MARATUS_LITERAL_PROJECT_ROOT__"
)

func projectCommandTargets(plan projectCommandPlan, requiredRootPlaceholder string) []string {
	targetPlan, ok := projectCommandTargetPlan(plan, requiredRootPlaceholder)
	if !ok {
		return nil
	}
	fields, simple := projectCommandFields(targetPlan)
	if !simple || len(fields) == 0 {
		return nil
	}
	tool := filepath.Base(fields[0])
	var candidates []string
	switch tool {
	case "sh", "bash", "zsh", "python", "python3", "node", "deno", "osascript":
		candidates = InterpreterScriptTargets(tool, fields[1:])
	default:
		if looksLocalScript(fields[0]) {
			candidates = []string{fields[0]}
		}
	}
	seen := map[string]bool{}
	var targets []string
	for _, candidate := range candidates {
		if requiredRootPlaceholder != "" {
			switch {
			case candidate == projectRootTargetMarker:
				candidate = "."
			case strings.HasPrefix(candidate, projectRootTargetMarker+"/"):
				candidate = "./" + strings.TrimPrefix(candidate, projectRootTargetMarker+"/")
			default:
				// Claude hooks run from the session cwd. Only the documented
				// project-root placeholder fixes a retained artifact target.
				continue
			}
		}
		if logical, ok := resolveProjectConfigLogical(plan.content.LogicalPath, candidate); ok && !seen[logical] {
			seen[logical] = true
			targets = append(targets, logical)
		}
	}
	sort.Strings(targets)
	return targets
}

func projectCommandTargetPlan(plan projectCommandPlan, requiredRootPlaceholder string) (projectCommandPlan, bool) {
	if requiredRootPlaceholder == "" {
		return plan, true
	}
	values := append([]string{plan.command}, plan.args...)
	for _, value := range values {
		if strings.Contains(value, projectRootTargetMarker) || strings.Contains(value, projectRootLiteralMarker) {
			return projectCommandPlan{}, false
		}
	}
	targetPlan := plan
	if plan.mode == projectCommandExec {
		targetPlan.command = strings.ReplaceAll(plan.command, requiredRootPlaceholder, projectRootTargetMarker)
		targetPlan.args = append([]string(nil), plan.args...)
		for index := range targetPlan.args {
			targetPlan.args[index] = strings.ReplaceAll(targetPlan.args[index], requiredRootPlaceholder, projectRootTargetMarker)
		}
		return targetPlan, true
	}
	targetPlan.command = replaceShellProjectRootPlaceholder(plan.command, requiredRootPlaceholder, projectRootTargetMarker, projectRootLiteralMarker)
	if requiredRootPlaceholder == "${CLAUDE_PROJECT_DIR}" {
		// Shell form also receives CLAUDE_PROJECT_DIR as an environment
		// variable. The unbraced spelling therefore has the same bounded path
		// meaning when ordinary shell expansion is active.
		targetPlan.command = replaceShellProjectRootPlaceholder(targetPlan.command, "$CLAUDE_PROJECT_DIR", projectRootTargetMarker, projectRootLiteralMarker)
	}
	return targetPlan, true
}

// replaceShellProjectRootPlaceholder distinguishes expandable unquoted or
// double-quoted occurrences from escaped and single-quoted literals. Both are
// replaced with caller-selected text. Target discovery uses inert tokens so
// the ordinary bounded shell parser never sees a dollar expansion; semantic
// command normalization replaces only the forms the shell would expand.
func replaceShellProjectRootPlaceholder(command, placeholder, expanded, literal string) string {
	var output strings.Builder
	output.Grow(len(command))
	inSingle := false
	inDouble := false
	for index := 0; index < len(command); {
		if command[index] == '\\' && !inSingle {
			output.WriteByte(command[index])
			index++
			if index < len(command) {
				if projectCommandExpansionAt(command, index, placeholder) {
					output.WriteString(literal)
					index += len(placeholder)
				} else {
					output.WriteByte(command[index])
					index++
				}
			}
			continue
		}
		switch command[index] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
			output.WriteByte(command[index])
			index++
			continue
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
			output.WriteByte(command[index])
			index++
			continue
		}
		if projectCommandExpansionAt(command, index, placeholder) {
			if inSingle {
				output.WriteString(literal)
			} else {
				output.WriteString(expanded)
			}
			index += len(placeholder)
			continue
		}
		output.WriteByte(command[index])
		index++
	}
	return output.String()
}

func projectConfigRoot(logical string) (string, string, bool) {
	if root, ok := vscodeTasksProjectRoot(logical); ok {
		return root, vscodeTasksAnalysisArea, true
	}
	if root, ok := claudeSettingsProjectRoot(logical); ok {
		return root, claudeSessionStartAnalysisArea, true
	}
	if root, ok := codexHooksProjectRoot(logical); ok {
		return root, codexHooksAnalysisArea, true
	}
	if root, ok := geminiSettingsProjectRoot(logical); ok {
		return root, geminiSessionStartAnalysisArea, true
	}
	return "", "", false
}

func resolveProjectConfigLogical(configLogical, target string) (string, bool) {
	root, _, ok := projectConfigRoot(configLogical)
	if !ok {
		return "", false
	}
	clean, ok := cleanStaticRelativeTarget(target)
	if !ok {
		return "", false
	}
	logical := root + clean
	return logical, len(logical) <= artifact.MaxArchiveLogicalPathBytes
}

func projectRootForSuffix(logical, relative string) (string, bool) {
	logical = filepath.ToSlash(logical)
	if logical == relative {
		return "", true
	}
	for _, separator := range []string{"/", "!"} {
		marker := separator + relative
		if strings.HasSuffix(logical, marker) {
			return strings.TrimSuffix(logical, marker) + separator, true
		}
	}
	return "", false
}

func decodeProjectJSONObject(data []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, fmt.Errorf("document is not an object")
	}
	return object, nil
}

func decodeProjectRawArray(raw json.RawMessage, field string) ([]json.RawMessage, error) {
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("%s is not an array: %w", field, err)
	}
	if values == nil {
		return nil, fmt.Errorf("%s is not an array", field)
	}
	return values, nil
}

func decodeProjectString(raw json.RawMessage, field string) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s is not a string: %w", field, err)
	}
	if len(value) > maxProjectConfigCommandBytes {
		return "", fmt.Errorf("%s exceeds byte limit %d", field, maxProjectConfigCommandBytes)
	}
	return value, nil
}

func decodeProjectStringArray(raw json.RawMessage, field string) ([]string, error) {
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("%s is not a string array: %w", field, err)
	}
	if values == nil {
		return nil, fmt.Errorf("%s is not a string array", field)
	}
	if len(values) > maxProjectConfigCommandArgs {
		return nil, fmt.Errorf("%s exceeds argument limit %d", field, maxProjectConfigCommandArgs)
	}
	total := 0
	for _, value := range values {
		total += len(value)
		if len(value) > maxProjectConfigCommandBytes || total > maxProjectConfigCommandBytes {
			return nil, fmt.Errorf("%s exceeds retained byte limit %d", field, maxProjectConfigCommandBytes)
		}
	}
	return values, nil
}
