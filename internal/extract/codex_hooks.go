package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
)

const (
	codexHooksAnalysisArea = "codex-lifecycle-hook"
	codexHooksRootKind     = "codex-lifecycle-hook"
	codexHooksGateDetail   = "Codex project-hook selection is conditional on a compatible Codex frontend/version, a trusted project .codex layer, effective per-hook enablement, either hash-bound trust of the exact non-managed hook definition or an explicit hook-trust bypass, effective hook feature and managed-policy settings, the lifecycle event and matcher, the session working directory, and the effective shell selected from the Codex session environment; static analysis did not observe those host states, the concrete shell, or an event occurrence"

	maxCodexHookMatcherBytes = 4096
	maxCodexHookLabelBytes   = 256
)

var codexHookEvents = [...]string{
	"SessionStart",
	"SessionEnd",
	"PreToolUse",
	"PermissionRequest",
	"PostToolUse",
	"PreCompact",
	"PostCompact",
	"UserPromptSubmit",
	"SubagentStart",
	"SubagentStop",
	"Stop",
}

var codexSessionStartSources = [...]string{"startup", "resume", "clear", "compact"}
var codexCompactionSources = [...]string{"manual", "auto"}

func codexHooksProjectRoot(logical string) (string, bool) {
	return projectRootForSuffix(logical, ".codex/hooks.json")
}

func planCodexProjectHooks(content artifact.Content, planningWork *int) ([]projectCommandPlan, []projectConfigIssue) {
	if len(content.Data) > maxStructuredDocumentBytes {
		return nil, []projectConfigIssue{{
			nodeID: content.NodeID,
			area:   codexHooksAnalysisArea,
			detail: fmt.Sprintf("hooks.json structured decode skipped over parser input limit %d", maxStructuredDocumentBytes),
		}}
	}
	if !utf8.Valid(content.Data) {
		return nil, []projectConfigIssue{{
			nodeID: content.NodeID,
			area:   codexHooksAnalysisArea,
			detail: "hooks.json decode failed: input is not valid UTF-8",
		}}
	}
	if err := preflightPackageJSON(content.Data); err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: codexHooksAnalysisArea, detail: "hooks.json decode failed: " + err.Error()}}
	}
	if err := validateUniqueCodexJSONKeys(content.Data); err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: codexHooksAnalysisArea, detail: "hooks.json decode failed: " + err.Error()}}
	}
	hooks, err := decodeValidatedCodexHooksFile(content.Data)
	if err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: codexHooksAnalysisArea, detail: "hooks.json schema validation failed: " + err.Error()}}
	}
	if hooks == nil {
		return nil, nil
	}

	var plans []projectCommandPlan
	var issues []projectConfigIssue
	for _, event := range codexHookEvents {
		rawGroups, ok := hooks[event]
		if !ok {
			continue
		}
		groups, _ := decodeProjectRawArray(rawGroups, "hooks."+event)
		if len(groups) > maxProjectConfigCommands {
			issues = append(issues, projectConfigIssue{
				nodeID: content.NodeID,
				area:   codexHooksAnalysisArea,
				detail: fmt.Sprintf("%s matcher-group limit %d reached; remaining groups were not analyzed", event, maxProjectConfigCommands),
			})
			groups = groups[:maxProjectConfigCommands]
		}
		for groupIndex, rawGroup := range groups {
			if !takeCodexHookPlanningWork(planningWork) {
				issues = append(issues, codexHookTraversalLimitIssue(content.NodeID))
				return plans, issues
			}
			group, _ := decodeProjectJSONObject(rawGroup)
			matcher, matchedValues, matcherIgnored, detail, ok := decodeCodexHookMatcher(event, group)
			if !ok {
				issues = append(issues, codexHookIssue(content.NodeID, event, groupIndex, -1, detail))
				continue
			}
			if detail != "" {
				issues = append(issues, codexHookIssue(content.NodeID, event, groupIndex, -1, detail))
			}
			rawHandlers, ok := group["hooks"]
			if !ok {
				continue
			}
			handlers, _ := decodeProjectRawArray(rawHandlers, event+" matcher-group hooks")
			if len(handlers) > maxProjectConfigCommands {
				issues = append(issues, codexHookIssue(content.NodeID, event, groupIndex, -1, fmt.Sprintf("handler limit %d reached; remaining handlers were not analyzed", maxProjectConfigCommands)))
				handlers = handlers[:maxProjectConfigCommands]
			}
			for handlerIndex, rawHandler := range handlers {
				if !takeCodexHookPlanningWork(planningWork) {
					issues = append(issues, codexHookTraversalLimitIssue(content.NodeID))
					return plans, issues
				}
				handler, _ := decodeProjectJSONObject(rawHandler)
				plan, detail, ok := planCodexHookHandler(content, event, matcher, matchedValues, matcherIgnored, groupIndex, handlerIndex, handler)
				if !ok {
					issues = append(issues, codexHookIssue(content.NodeID, event, groupIndex, handlerIndex, detail))
					continue
				}
				// Codex runs commands with the session cwd. A repository-local
				// configuration does not prove that cwd is the repository root, so
				// relative command operands are not promoted to exact artifact targets.
				plans = append(plans, plan)
			}
		}
	}
	issues = append(issues, unknownCodexHookEventIssues(content.NodeID, hooks)...)
	return plans, issues
}

func decodeValidatedCodexHooksFile(data []byte) (map[string]json.RawMessage, error) {
	root, err := decodeProjectJSONObject(data)
	if err != nil {
		return nil, err
	}
	for field := range root {
		if field != "description" && field != "hooks" {
			return nil, fmt.Errorf("unknown top-level field")
		}
	}
	if rawDescription, ok := root["description"]; ok {
		if err := validateCodexNullableString(rawDescription, "description"); err != nil {
			return nil, err
		}
	}
	rawHooks, ok := root["hooks"]
	if !ok {
		return nil, nil
	}
	hooks, err := decodeProjectJSONObject(rawHooks)
	if err != nil {
		return nil, fmt.Errorf("hooks is malformed: %w", err)
	}
	for _, event := range codexHookEvents {
		rawGroups, ok := hooks[event]
		if !ok {
			continue
		}
		groups, err := decodeProjectRawArray(rawGroups, "hooks."+event)
		if err != nil {
			return nil, err
		}
		for groupIndex, rawGroup := range groups {
			group, err := decodeProjectJSONObject(rawGroup)
			if err != nil {
				return nil, fmt.Errorf("%s group %d is malformed: %w", event, groupIndex+1, err)
			}
			if rawMatcher, ok := group["matcher"]; ok {
				if err := validateCodexNullableString(rawMatcher, event+" matcher"); err != nil {
					return nil, err
				}
			}
			rawHandlers, ok := group["hooks"]
			if !ok {
				continue
			}
			handlers, err := decodeProjectRawArray(rawHandlers, event+" matcher-group hooks")
			if err != nil {
				return nil, err
			}
			for handlerIndex, rawHandler := range handlers {
				handler, err := decodeProjectJSONObject(rawHandler)
				if err != nil {
					return nil, fmt.Errorf("%s group %d handler %d is malformed: %w", event, groupIndex+1, handlerIndex+1, err)
				}
				if err := validateCodexHookHandlerSchema(handler); err != nil {
					return nil, fmt.Errorf("%s group %d handler %d: %w", event, groupIndex+1, handlerIndex+1, err)
				}
			}
		}
	}
	return hooks, nil
}

func validateCodexHookHandlerSchema(handler map[string]json.RawMessage) error {
	rawType, ok := handler["type"]
	if !ok {
		return fmt.Errorf("handler type is absent")
	}
	handlerType, err := decodeCodexRequiredString(rawType, "handler.type")
	if err != nil {
		return err
	}
	switch handlerType {
	case "prompt", "agent":
		return nil
	case "mcp_tool":
		return validateCodexMCPToolHandlerSchema(handler)
	case "command":
	default:
		return fmt.Errorf("handler type is outside the documented Codex hook profile")
	}

	rawCommand, ok := handler["command"]
	if !ok {
		return fmt.Errorf("command handler command is absent")
	}
	if _, err := decodeCodexRequiredString(rawCommand, "handler.command"); err != nil {
		return err
	}
	if _, camel := handler["commandWindows"]; camel {
		if _, snake := handler["command_windows"]; snake {
			return fmt.Errorf("commandWindows is declared more than once")
		}
	}
	for _, field := range []string{"commandWindows", "command_windows", "statusMessage"} {
		if raw, ok := handler[field]; ok {
			if err := validateCodexNullableString(raw, "handler."+field); err != nil {
				return err
			}
		}
	}
	for _, field := range []string{"timeout", "additionalContextLimit"} {
		if raw, ok := handler[field]; ok {
			if err := validateCodexNullableUint(raw, "handler."+field); err != nil {
				return err
			}
		}
	}
	if rawAsync, ok := handler["async"]; ok {
		if bytes.Equal(bytes.TrimSpace(rawAsync), []byte("null")) {
			return fmt.Errorf("handler.async is not a boolean")
		}
		var value bool
		if err := json.Unmarshal(rawAsync, &value); err != nil {
			return fmt.Errorf("handler.async is not a boolean: %w", err)
		}
	}
	return nil
}

func validateCodexMCPToolHandlerSchema(handler map[string]json.RawMessage) error {
	for _, field := range []string{"server", "tool"} {
		raw, ok := handler[field]
		if !ok {
			return fmt.Errorf("MCP tool handler %s is absent", field)
		}
		if _, err := decodeCodexRequiredString(raw, "handler."+field); err != nil {
			return err
		}
	}
	if rawInput, ok := handler["input"]; ok {
		decoder := json.NewDecoder(bytes.NewReader(rawInput))
		decoder.UseNumber()
		var input any
		if err := decoder.Decode(&input); err != nil {
			return fmt.Errorf("handler.input is not an object: %w", err)
		}
		object, ok := input.(map[string]any)
		if !ok {
			return fmt.Errorf("handler.input is not an object")
		}
		if err := validateCodexTOMLRepresentableValue(object); err != nil {
			return fmt.Errorf("handler.input is outside the bounded TOML-representable profile: %w", err)
		}
	}
	if rawTimeout, ok := handler["timeout"]; ok {
		if err := validateCodexNullableUint(rawTimeout, "handler.timeout"); err != nil {
			return err
		}
	}
	if rawStatus, ok := handler["statusMessage"]; ok {
		if err := validateCodexNullableString(rawStatus, "handler.statusMessage"); err != nil {
			return err
		}
	}
	return nil
}

func validateCodexTOMLRepresentableValue(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := validateCodexTOMLRepresentableValue(typed[key]); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for _, child := range typed {
			if err := validateCodexTOMLRepresentableValue(child); err != nil {
				return err
			}
		}
		return nil
	case string, bool:
		return nil
	case json.Number:
		raw := typed.String()
		if strings.ContainsAny(raw, ".eE") {
			value, err := strconv.ParseFloat(raw, 64)
			if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
				return fmt.Errorf("number is outside finite TOML float range")
			}
			return nil
		}
		if _, err := strconv.ParseInt(raw, 10, 64); err != nil {
			return fmt.Errorf("integer is outside signed 64-bit TOML range")
		}
		return nil
	case nil:
		return fmt.Errorf("null is not representable in TOML")
	default:
		return fmt.Errorf("value type is not representable in TOML")
	}
}

func decodeCodexRequiredString(raw json.RawMessage, field string) (string, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", fmt.Errorf("%s is not a string", field)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s is not a string: %w", field, err)
	}
	return value, nil
}

func validateCodexNullableString(raw json.RawMessage, field string) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	_, err := decodeCodexRequiredString(raw, field)
	return err
}

func validateCodexNullableUint(raw json.RawMessage, field string) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var value uint64
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("%s is not an unsigned integer: %w", field, err)
	}
	return nil
}

func validateUniqueCodexJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validateUniqueCodexJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple top-level JSON values")
		}
		return err
	}
	return nil
}

func validateUniqueCodexJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON object key")
			}
			seen[key] = true
			if err := validateUniqueCodexJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return fmt.Errorf("malformed JSON object")
		}
	case '[':
		for decoder.More() {
			if err := validateUniqueCodexJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("malformed JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	return nil
}

func takeCodexHookPlanningWork(planningWork *int) bool {
	if planningWork == nil || *planningWork >= maxProjectConfigResolutionWork {
		return false
	}
	*planningWork = *planningWork + 1
	return true
}

func codexHookTraversalLimitIssue(nodeID string) projectConfigIssue {
	return projectConfigIssue{
		nodeID: nodeID,
		area:   codexHooksAnalysisArea,
		detail: fmt.Sprintf("Codex hook traversal work limit %d reached; remaining matcher groups and handlers were not analyzed", maxProjectConfigResolutionWork),
	}
}

func decodeCodexHookMatcher(event string, group map[string]json.RawMessage) (string, []string, bool, string, bool) {
	rawMatcher, present := group["matcher"]
	if present && bytes.Equal(bytes.TrimSpace(rawMatcher), []byte("null")) {
		present = false
	}
	matcher := "*"
	if codexEventIgnoresMatcher(event) {
		if !present {
			return matcher, nil, false, "", true
		}
		var decoded string
		_ = json.Unmarshal(rawMatcher, &decoded)
		digest := sha256.Sum256([]byte(decoded))
		matcher = fmt.Sprintf("<present; bytes=%d; sha256=%x>", len(decoded), digest)
		return matcher, nil, true, "", true
	}
	if present {
		decoded, err := decodeProjectString(rawMatcher, event+" matcher")
		if err != nil {
			return "", nil, false, err.Error(), false
		}
		matcher = decoded
		if len(matcher) > maxCodexHookMatcherBytes {
			return "", nil, false, fmt.Sprintf("matcher exceeds byte limit %d", maxCodexHookMatcherBytes), false
		}
		if matcher == "" {
			matcher = "*"
		}
	}
	if matcher == "*" {
		return matcher, codexKnownMatcherValues(event), false, "", true
	}
	values, ok := boundedExactMatcherAlternatives(matcher)
	if !ok {
		return "", nil, false, "matcher regular expression is outside the bounded exact-alternative profile", false
	}
	known := codexKnownMatcherValues(event)
	if len(known) == 0 {
		return matcher, values, false, "", true
	}
	allowed := make(map[string]bool, len(known))
	for _, value := range known {
		allowed[value] = true
	}
	retained := make([]string, 0, len(values))
	unsupported := 0
	for _, value := range values {
		if allowed[value] {
			retained = append(retained, value)
		} else {
			unsupported++
		}
	}
	if len(retained) == 0 {
		return "", nil, false, fmt.Sprintf("matcher has no documented exact alternative for %s", event), false
	}
	detail := ""
	if unsupported > 0 {
		detail = fmt.Sprintf("matcher contains %d exact alternative(s) outside the documented %s values; those alternatives were not modeled", unsupported, event)
	}
	return matcher, retained, false, detail, true
}

func codexKnownMatcherValues(event string) []string {
	switch event {
	case "SessionStart":
		return append([]string(nil), codexSessionStartSources[:]...)
	case "PreCompact", "PostCompact":
		return append([]string(nil), codexCompactionSources[:]...)
	case "SessionEnd":
		return []string{"other"}
	default:
		return nil
	}
}

func codexEventIgnoresMatcher(event string) bool {
	return event == "UserPromptSubmit" || event == "Stop"
}

func boundedExactMatcherAlternatives(matcher string) ([]string, bool) {
	if strings.HasPrefix(matcher, "^") || strings.HasSuffix(matcher, "$") {
		if !strings.HasPrefix(matcher, "^") || !strings.HasSuffix(matcher, "$") || len(matcher) < 3 {
			return nil, false
		}
		matcher = strings.TrimSuffix(strings.TrimPrefix(matcher, "^"), "$")
		if strings.Contains(matcher, "|") {
			// ^a|b$ does not anchor both alternatives. Grouped expressions are
			// outside this deliberately small matcher profile.
			return nil, false
		}
	}
	parts := strings.Split(matcher, "|")
	if len(parts) == 0 || len(parts) > maxProjectConfigCommandArgs {
		return nil, false
	}
	seen := map[string]bool{}
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || len(part) > maxProjectConfigCommandBytes {
			return nil, false
		}
		for _, character := range []byte(part) {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("_.:-", rune(character)) {
				continue
			}
			return nil, false
		}
		if !seen[part] {
			seen[part] = true
			values = append(values, part)
		}
	}
	return values, true
}

func planCodexHookHandler(content artifact.Content, event, matcher string, matchedValues []string, matcherIgnored bool, groupIndex, handlerIndex int, handler map[string]json.RawMessage) (projectCommandPlan, string, bool) {
	rawType := handler["type"]
	handlerType, err := decodeProjectString(rawType, "handler.type")
	if err != nil {
		return projectCommandPlan{}, err.Error(), false
	}
	if handlerType != "command" {
		return projectCommandPlan{}, fmt.Sprintf("handler type %q is valid but outside Maratus's bounded command-handler adapter; no root was emitted", handlerType), false
	}
	rawCommand := handler["command"]
	command, err := decodeProjectString(rawCommand, "handler.command")
	if err != nil {
		return projectCommandPlan{}, err.Error(), false
	}
	if strings.TrimSpace(command) == "" {
		return projectCommandPlan{}, "command handler command is empty", false
	}
	matcherStatus := matcher
	if matcherIgnored {
		matcherStatus += " (matcher field ignored by host for this event)"
	}
	alternatives := strings.Join(matchedValues, "|")
	if alternatives == "" {
		alternatives = "event-dependent"
	}
	rootName := fmt.Sprintf("%s %s group %d handler %d", event, matcher, groupIndex+1, handlerIndex+1)
	return projectCommandPlan{
		content:               content,
		rootKind:              codexHooksRootKind,
		rootName:              rootName,
		mode:                  projectCommandShell,
		interpreterUnresolved: true,
		command:               command,
		evidenceKind:          "codex-lifecycle-hook",
		evidenceValue:         fmt.Sprintf("event=%s; matcher=%s; bounded-alternatives=%s; type=command; command=%s", event, matcherStatus, alternatives, command),
		coverageArea:          codexHooksAnalysisArea,
		gateDetail:            codexHooksGateDetail,
	}, "", true
}

func unknownCodexHookEventIssues(nodeID string, hooks map[string]json.RawMessage) []projectConfigIssue {
	known := make(map[string]bool, len(codexHookEvents))
	for _, event := range codexHookEvents {
		known[event] = true
	}
	var unknown []string
	for event := range hooks {
		if !known[event] {
			unknown = append(unknown, event)
		}
	}
	sort.Strings(unknown)
	limit := len(unknown)
	if limit > maxProjectConfigCommands {
		limit = maxProjectConfigCommands
	}
	issues := make([]projectConfigIssue, 0, limit+1)
	for _, event := range unknown[:limit] {
		issues = append(issues, projectConfigIssue{
			nodeID: nodeID,
			area:   codexHooksAnalysisArea,
			detail: fmt.Sprintf("hook event %s is not in the documented Codex event vocabulary; no root was emitted", boundedCodexHookLabel(event)),
		})
	}
	if len(unknown) > limit {
		issues = append(issues, projectConfigIssue{
			nodeID: nodeID,
			area:   codexHooksAnalysisArea,
			detail: fmt.Sprintf("unknown-event diagnostic limit %d reached; remaining event names were omitted", maxProjectConfigCommands),
		})
	}
	return issues
}

func boundedCodexHookLabel(value string) string {
	if len(value) <= maxCodexHookLabelBytes {
		return fmt.Sprintf("%q", value)
	}
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("<bytes=%d; sha256=%x>", len(value), digest)
}

func codexHookIssue(nodeID, event string, groupIndex, handlerIndex int, detail string) projectConfigIssue {
	prefix := fmt.Sprintf("%s group %d", event, groupIndex+1)
	if handlerIndex >= 0 {
		prefix += fmt.Sprintf(" handler %d", handlerIndex+1)
	}
	return projectConfigIssue{
		nodeID: nodeID,
		area:   codexHooksAnalysisArea,
		detail: prefix + ": " + detail,
	}
}
