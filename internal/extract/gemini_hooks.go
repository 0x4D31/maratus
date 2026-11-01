package extract

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
)

const (
	geminiSessionStartAnalysisArea = "gemini-session-start-hook"
	geminiSessionStartRootKind     = "gemini-session-start-hook"
	geminiSessionStartGateDetail   = "Gemini CLI SessionStart hook selection is conditional on a compatible Gemini CLI version, effective settings precedence, project-folder trust or an explicit trust bypass, the matched startup/resume/clear source, the session working directory, and the host-selected shell; static analysis did not observe those host states, a session occurrence, or command success"
)

var geminiSessionStartSources = [...]string{"startup", "resume", "clear"}

func geminiSettingsProjectRoot(logical string) (string, bool) {
	return projectRootForSuffix(logical, ".gemini/settings.json")
}

func planGeminiSessionStartHooks(content artifact.Content) ([]projectCommandPlan, []projectConfigIssue) {
	if len(content.Data) > maxStructuredDocumentBytes {
		return nil, []projectConfigIssue{{
			nodeID: content.NodeID,
			area:   geminiSessionStartAnalysisArea,
			detail: fmt.Sprintf("settings.json structured decode skipped over parser input limit %d", maxStructuredDocumentBytes),
		}}
	}
	if err := preflightPackageJSON(content.Data); err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: geminiSessionStartAnalysisArea, detail: "settings.json decode failed: " + err.Error()}}
	}
	root, err := decodeProjectJSONObject(content.Data)
	if err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: geminiSessionStartAnalysisArea, detail: "settings.json decode failed: " + err.Error()}}
	}
	rawHooks, ok := root["hooks"]
	if !ok {
		return nil, nil
	}
	hooks, err := decodeProjectJSONObject(rawHooks)
	if err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: geminiSessionStartAnalysisArea, detail: "hooks is malformed: " + err.Error()}}
	}
	rawGroups, ok := hooks["SessionStart"]
	if !ok {
		return nil, nil
	}
	groups, err := decodeProjectRawArray(rawGroups, "hooks.SessionStart")
	if err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: geminiSessionStartAnalysisArea, detail: err.Error()}}
	}
	var plans []projectCommandPlan
	var issues []projectConfigIssue
	if len(groups) > maxProjectConfigCommands {
		issues = append(issues, projectConfigIssue{
			nodeID: content.NodeID,
			area:   geminiSessionStartAnalysisArea,
			detail: fmt.Sprintf("SessionStart hook-definition limit %d reached; remaining definitions were not analyzed", maxProjectConfigCommands),
		})
		groups = groups[:maxProjectConfigCommands]
	}
	for groupIndex, rawGroup := range groups {
		group, err := decodeProjectJSONObject(rawGroup)
		if err != nil {
			issues = append(issues, geminiHookIssue(content.NodeID, groupIndex, -1, "hook definition is malformed: "+err.Error()))
			continue
		}
		matcher, sources, detail, ok := decodeGeminiSessionStartMatcher(group)
		if !ok {
			issues = append(issues, geminiHookIssue(content.NodeID, groupIndex, -1, detail))
			continue
		}
		if rawSequential, present := group["sequential"]; present {
			var sequential bool
			if err := json.Unmarshal(rawSequential, &sequential); err != nil {
				issues = append(issues, geminiHookIssue(content.NodeID, groupIndex, -1, "sequential is not a boolean"))
				continue
			}
		}
		rawHandlers, present := group["hooks"]
		if !present {
			issues = append(issues, geminiHookIssue(content.NodeID, groupIndex, -1, "hooks array is absent"))
			continue
		}
		handlers, err := decodeProjectRawArray(rawHandlers, "SessionStart hook-definition hooks")
		if err != nil {
			issues = append(issues, geminiHookIssue(content.NodeID, groupIndex, -1, err.Error()))
			continue
		}
		if len(handlers) > maxProjectConfigCommands {
			issues = append(issues, geminiHookIssue(content.NodeID, groupIndex, -1, fmt.Sprintf("handler limit %d reached; remaining handlers were not analyzed", maxProjectConfigCommands)))
			handlers = handlers[:maxProjectConfigCommands]
		}
		for handlerIndex, rawHandler := range handlers {
			handler, err := decodeProjectJSONObject(rawHandler)
			if err != nil {
				issues = append(issues, geminiHookIssue(content.NodeID, groupIndex, handlerIndex, "handler is malformed: "+err.Error()))
				continue
			}
			plan, detail, ok := planGeminiSessionStartHandler(content, handler, matcher, sources, groupIndex, handlerIndex)
			if !ok {
				issues = append(issues, geminiHookIssue(content.NodeID, groupIndex, handlerIndex, detail))
				continue
			}
			plans = append(plans, plan)
		}
	}
	return plans, issues
}

func decodeGeminiSessionStartMatcher(group map[string]json.RawMessage) (string, []string, string, bool) {
	rawMatcher, present := group["matcher"]
	if !present {
		return "*", append([]string(nil), geminiSessionStartSources[:]...), "", true
	}
	matcher, err := decodeProjectString(rawMatcher, "SessionStart matcher")
	if err != nil {
		return "", nil, err.Error(), false
	}
	for _, source := range geminiSessionStartSources {
		if matcher == source {
			return matcher, []string{source}, "", true
		}
	}
	return "", nil, "SessionStart lifecycle matcher is not one exact documented source", false
}

func planGeminiSessionStartHandler(content artifact.Content, handler map[string]json.RawMessage, matcher string, sources []string, groupIndex, handlerIndex int) (projectCommandPlan, string, bool) {
	typeName, err := decodeProjectString(handler["type"], "handler.type")
	if err != nil {
		return projectCommandPlan{}, err.Error(), false
	}
	if typeName != "command" {
		return projectCommandPlan{}, fmt.Sprintf("SessionStart handler type %q is not modeled", typeName), false
	}
	command, err := decodeProjectString(handler["command"], "handler.command")
	if err != nil {
		return projectCommandPlan{}, err.Error(), false
	}
	command = strings.TrimSpace(command)
	if command == "" {
		return projectCommandPlan{}, "command handler command is empty", false
	}
	if len(command) > maxProjectConfigCommandBytes {
		return projectCommandPlan{}, fmt.Sprintf("command exceeds byte limit %d", maxProjectConfigCommandBytes), false
	}
	rootName := fmt.Sprintf("SessionStart %s definition %d handler %d", matcher, groupIndex+1, handlerIndex+1)
	return projectCommandPlan{
		content: content, rootKind: geminiSessionStartRootKind, rootName: rootName,
		mode: projectCommandShell, interpreterUnresolved: true, command: command,
		evidenceKind:  "gemini-session-start-hook",
		evidenceValue: fmt.Sprintf("event=SessionStart; matcher=%s; sources=%s; type=command; command=%s", matcher, strings.Join(sources, "|"), command),
		coverageArea:  geminiSessionStartAnalysisArea,
		gateDetail:    geminiSessionStartGateDetail,
	}, "", true
}

func geminiHookIssue(nodeID string, groupIndex, handlerIndex int, detail string) projectConfigIssue {
	prefix := fmt.Sprintf("SessionStart definition %d", groupIndex+1)
	if handlerIndex >= 0 {
		prefix += fmt.Sprintf(" handler %d", handlerIndex+1)
	}
	return projectConfigIssue{nodeID: nodeID, area: geminiSessionStartAnalysisArea, detail: prefix + ": " + detail}
}
