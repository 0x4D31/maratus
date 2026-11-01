package extract

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
)

const (
	claudeSessionStartAnalysisArea = "claude-session-start-hook"
	claudeSessionStartRootKind     = "claude-session-start-hook"
	claudeSessionStartGateDetail   = "SessionStart hook selection is conditional on a compatible Claude Code version, the matched session source, effective workspace trust, hook settings and policy, session mode, and the session working directory for relative commands; static analysis did not observe those host states or a session occurrence"
)

var claudeSessionStartSources = [...]string{"startup", "resume", "clear", "compact", "fork"}

func claudeSettingsProjectRoot(logical string) (string, bool) {
	return projectRootForSuffix(logical, ".claude/settings.json")
}

func planClaudeSessionStartHooks(content artifact.Content) ([]projectCommandPlan, []projectConfigIssue) {
	if len(content.Data) > maxStructuredDocumentBytes {
		return nil, []projectConfigIssue{{
			nodeID: content.NodeID,
			area:   claudeSessionStartAnalysisArea,
			detail: fmt.Sprintf("settings.json structured decode skipped over parser input limit %d", maxStructuredDocumentBytes),
		}}
	}
	if err := preflightPackageJSON(content.Data); err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: claudeSessionStartAnalysisArea, detail: "settings.json decode failed: " + err.Error()}}
	}
	root, err := decodeProjectJSONObject(content.Data)
	if err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: claudeSessionStartAnalysisArea, detail: "settings.json decode failed: " + err.Error()}}
	}
	if rawDisabled, ok := root["disableAllHooks"]; ok {
		var disabled bool
		if err := json.Unmarshal(rawDisabled, &disabled); err != nil {
			return nil, []projectConfigIssue{{nodeID: content.NodeID, area: claudeSessionStartAnalysisArea, detail: "disableAllHooks is not a boolean; SessionStart hooks were not modeled"}}
		}
		if disabled {
			return nil, []projectConfigIssue{{nodeID: content.NodeID, area: claudeSessionStartAnalysisArea, detail: "this project settings file declares disableAllHooks=true; effective settings precedence was not modeled and no SessionStart root was emitted"}}
		}
	}
	rawHooks, ok := root["hooks"]
	if !ok {
		return nil, nil
	}
	hooks, err := decodeProjectJSONObject(rawHooks)
	if err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: claudeSessionStartAnalysisArea, detail: "hooks is malformed: " + err.Error()}}
	}
	rawGroups, ok := hooks["SessionStart"]
	if !ok {
		return nil, nil
	}
	groups, err := decodeProjectRawArray(rawGroups, "hooks.SessionStart")
	if err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: claudeSessionStartAnalysisArea, detail: err.Error()}}
	}
	var plans []projectCommandPlan
	var issues []projectConfigIssue
	if len(groups) > maxProjectConfigCommands {
		issues = append(issues, projectConfigIssue{
			nodeID: content.NodeID,
			area:   claudeSessionStartAnalysisArea,
			detail: fmt.Sprintf("SessionStart matcher-group limit %d reached; remaining groups were not analyzed", maxProjectConfigCommands),
		})
		groups = groups[:maxProjectConfigCommands]
	}
	for groupIndex, rawGroup := range groups {
		group, err := decodeProjectJSONObject(rawGroup)
		if err != nil {
			issues = append(issues, claudeHookIssue(content.NodeID, groupIndex, -1, "matcher group is malformed: "+err.Error()))
			continue
		}
		matcher, sources, detail, ok := decodeClaudeSessionStartMatcher(group)
		if !ok {
			issues = append(issues, claudeHookIssue(content.NodeID, groupIndex, -1, detail))
			continue
		}
		if len(sources) == 0 {
			continue
		}
		rawHandlers, ok := group["hooks"]
		if !ok {
			issues = append(issues, claudeHookIssue(content.NodeID, groupIndex, -1, "hooks array is absent"))
			continue
		}
		handlers, err := decodeProjectRawArray(rawHandlers, "SessionStart matcher-group hooks")
		if err != nil {
			issues = append(issues, claudeHookIssue(content.NodeID, groupIndex, -1, err.Error()))
			continue
		}
		if len(handlers) > maxProjectConfigCommands {
			issues = append(issues, claudeHookIssue(content.NodeID, groupIndex, -1, fmt.Sprintf("handler limit %d reached; remaining handlers were not analyzed", maxProjectConfigCommands)))
			handlers = handlers[:maxProjectConfigCommands]
		}
		for handlerIndex, rawHandler := range handlers {
			handler, err := decodeProjectJSONObject(rawHandler)
			if err != nil {
				issues = append(issues, claudeHookIssue(content.NodeID, groupIndex, handlerIndex, "handler is malformed: "+err.Error()))
				continue
			}
			plan, detail, ok := planClaudeSessionStartHandler(content, handler, matcher, sources, groupIndex, handlerIndex)
			if !ok {
				issues = append(issues, claudeHookIssue(content.NodeID, groupIndex, handlerIndex, detail))
				continue
			}
			plan.targets = projectCommandTargets(plan, "${CLAUDE_PROJECT_DIR}")
			plans = append(plans, plan)
		}
	}
	return plans, issues
}

func decodeClaudeSessionStartMatcher(group map[string]json.RawMessage) (string, []string, string, bool) {
	rawMatcher, ok := group["matcher"]
	if !ok {
		return "*", append([]string(nil), claudeSessionStartSources[:]...), "", true
	}
	matcher, err := decodeProjectString(rawMatcher, "SessionStart matcher")
	if err != nil {
		return "", nil, err.Error(), false
	}
	if matcher == "" || matcher == "*" {
		return "*", append([]string(nil), claudeSessionStartSources[:]...), "", true
	}
	if !claudeExactMatcherSyntax(matcher) {
		return "", nil, "SessionStart JavaScript regular-expression matcher was not evaluated", false
	}
	requested := map[string]bool{}
	for _, value := range strings.Split(matcher, "|") {
		if !claudeSessionStartSource(value) {
			return "", nil, "SessionStart JavaScript regular-expression matcher was not evaluated", false
		}
		requested[value] = true
	}
	var sources []string
	for _, source := range claudeSessionStartSources {
		if requested[source] {
			sources = append(sources, source)
		}
	}
	return matcher, sources, "", true
}

func claudeExactMatcherSyntax(matcher string) bool {
	for _, character := range []byte(matcher) {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '|' {
			continue
		}
		return false
	}
	return true
}

func claudeSessionStartSource(value string) bool {
	for _, source := range claudeSessionStartSources {
		if value == source {
			return true
		}
	}
	return false
}

func planClaudeSessionStartHandler(content artifact.Content, handler map[string]json.RawMessage, matcher string, sources []string, groupIndex, handlerIndex int) (projectCommandPlan, string, bool) {
	if _, conditional := handler["if"]; conditional {
		return projectCommandPlan{}, "handler if-condition is present and was not evaluated", false
	}
	rawType, ok := handler["type"]
	if !ok {
		return projectCommandPlan{}, "handler type is absent", false
	}
	handlerType, err := decodeProjectString(rawType, "handler.type")
	if err != nil {
		return projectCommandPlan{}, err.Error(), false
	}
	if handlerType != "command" {
		return projectCommandPlan{}, fmt.Sprintf("SessionStart handler type %q is not modeled", handlerType), false
	}
	rawCommand, ok := handler["command"]
	if !ok {
		return projectCommandPlan{}, "command handler command is absent", false
	}
	command, err := decodeProjectString(rawCommand, "handler.command")
	if err != nil {
		return projectCommandPlan{}, err.Error(), false
	}
	command = strings.TrimSpace(command)
	if command == "" {
		return projectCommandPlan{}, "command handler command is empty", false
	}
	mode := projectCommandShell
	var args []string
	if rawArgs, execForm := handler["args"]; execForm {
		mode = projectCommandExec
		args, err = decodeProjectStringArray(rawArgs, "handler.args")
		if err != nil {
			return projectCommandPlan{}, err.Error(), false
		}
	}
	allowedExpansions := []string{"${CLAUDE_PROJECT_DIR}"}
	if mode == projectCommandShell {
		allowedExpansions = append(allowedExpansions, "$CLAUDE_PROJECT_DIR")
	}
	if hasUnresolvedProjectCommandExpansion(append([]string{command}, args...), allowedExpansions...) {
		return projectCommandPlan{}, "command handler contains a variable or expansion outside the bounded CLAUDE_PROJECT_DIR forms", false
	}
	interpreter := ""
	if mode == projectCommandShell {
		interpreter = "sh"
		if rawShell, specified := handler["shell"]; specified {
			shell, err := decodeProjectString(rawShell, "handler.shell")
			if err != nil {
				return projectCommandPlan{}, err.Error(), false
			}
			if shell != "bash" {
				return projectCommandPlan{}, fmt.Sprintf("command-hook shell %q is not modeled for macOS", shell), false
			}
			interpreter = "bash"
		}
	}
	rootName := fmt.Sprintf("SessionStart %s group %d handler %d", matcher, groupIndex+1, handlerIndex+1)
	encodedArgs, _ := json.Marshal(args)
	return projectCommandPlan{
		content:       content,
		rootKind:      claudeSessionStartRootKind,
		rootName:      rootName,
		mode:          mode,
		interpreter:   interpreter,
		command:       command,
		args:          args,
		evidenceKind:  "claude-session-start-hook",
		evidenceValue: fmt.Sprintf("event=SessionStart; matcher=%s; sources=%s; type=command; mode=%s; command=%s; args=%s", matcher, strings.Join(sources, "|"), mode, command, encodedArgs),
		coverageArea:  claudeSessionStartAnalysisArea,
		gateDetail:    claudeSessionStartGateDetail,
	}, "", true
}

func claudeHookIssue(nodeID string, groupIndex, handlerIndex int, detail string) projectConfigIssue {
	prefix := fmt.Sprintf("SessionStart group %d", groupIndex+1)
	if handlerIndex >= 0 {
		prefix += fmt.Sprintf(" handler %d", handlerIndex+1)
	}
	return projectConfigIssue{
		nodeID: nodeID,
		area:   claudeSessionStartAnalysisArea,
		detail: prefix + ": " + detail,
	}
}
