package extract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
)

const (
	vscodeTasksAnalysisArea = "vscode-folder-open-task"
	vscodeTasksRootKind     = "vscode-folder-open-task"
	vscodeTasksGateDetail   = "folderOpen task selection is conditional on a trusted workspace and the effective task.allowAutomaticTasks or Manage Automatic Tasks decision; the concrete automation shell for a shell task depends on effective VS Code settings; static analysis did not observe those host decisions, the concrete shell, or a folder-open occurrence"
)

func vscodeTasksProjectRoot(logical string) (string, bool) {
	return projectRootForSuffix(logical, ".vscode/tasks.json")
}

func planVSCodeFolderOpenTasks(content artifact.Content) ([]projectCommandPlan, []projectConfigIssue) {
	data, err := decodeJSONC(content.Data)
	if err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: vscodeTasksAnalysisArea, detail: "tasks.json decode failed: " + err.Error()}}
	}
	if len(data) > maxStructuredDocumentBytes {
		return nil, []projectConfigIssue{{
			nodeID: content.NodeID,
			area:   vscodeTasksAnalysisArea,
			detail: fmt.Sprintf("tasks.json structured decode skipped over parser input limit %d", maxStructuredDocumentBytes),
		}}
	}
	if err := preflightPackageJSON(data); err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: vscodeTasksAnalysisArea, detail: "tasks.json decode failed: " + err.Error()}}
	}
	root, err := decodeProjectJSONObject(data)
	if err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: vscodeTasksAnalysisArea, detail: "tasks.json decode failed: " + err.Error()}}
	}
	if _, overridden := root["osx"]; overridden {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: vscodeTasksAnalysisArea, detail: "top-level macOS-specific task configuration is present and was not modeled"}}
	}
	if rawOptions, ok := root["options"]; ok {
		options, err := decodeProjectJSONObject(rawOptions)
		if err != nil {
			return nil, []projectConfigIssue{{nodeID: content.NodeID, area: vscodeTasksAnalysisArea, detail: "top-level task options are malformed: " + err.Error()}}
		}
		for _, field := range []string{"cwd", "shell", "env"} {
			if _, changesExecution := options[field]; changesExecution {
				return nil, []projectConfigIssue{{nodeID: content.NodeID, area: vscodeTasksAnalysisArea, detail: fmt.Sprintf("top-level task %s override is present and was not modeled", field)}}
			}
		}
	}
	rawTasks, ok := root["tasks"]
	if !ok {
		return nil, nil
	}
	tasks, err := decodeProjectRawArray(rawTasks, "tasks")
	if err != nil {
		return nil, []projectConfigIssue{{nodeID: content.NodeID, area: vscodeTasksAnalysisArea, detail: "tasks.json decode failed: " + err.Error()}}
	}
	var plans []projectCommandPlan
	var issues []projectConfigIssue
	if len(tasks) > maxProjectConfigCommands {
		issues = append(issues, projectConfigIssue{
			nodeID: content.NodeID,
			area:   vscodeTasksAnalysisArea,
			detail: fmt.Sprintf("task limit %d reached; remaining folder-open tasks were not analyzed", maxProjectConfigCommands),
		})
		tasks = tasks[:maxProjectConfigCommands]
	}
	for index, rawTask := range tasks {
		task, err := decodeProjectJSONObject(rawTask)
		if err != nil {
			issues = append(issues, vscodeTaskIssue(content.NodeID, index, "task is malformed: "+err.Error()))
			continue
		}
		folderOpen, malformed := vscodeTaskRunsOnFolderOpen(task)
		if malformed != "" {
			issues = append(issues, vscodeTaskIssue(content.NodeID, index, malformed))
			continue
		}
		if !folderOpen {
			continue
		}
		plan, detail, ok := planVSCodeFolderOpenTask(content, task, index)
		if !ok {
			issues = append(issues, vscodeTaskIssue(content.NodeID, index, detail))
			continue
		}
		plan.targets = projectCommandTargets(plan, "")
		plans = append(plans, plan)
	}
	return plans, issues
}

func vscodeTaskRunsOnFolderOpen(task map[string]json.RawMessage) (bool, string) {
	rawOptions, ok := task["runOptions"]
	if !ok {
		return false, ""
	}
	options, err := decodeProjectJSONObject(rawOptions)
	if err != nil {
		return false, "runOptions is malformed: " + err.Error()
	}
	rawRunOn, ok := options["runOn"]
	if !ok {
		return false, ""
	}
	runOn, err := decodeProjectString(rawRunOn, "runOptions.runOn")
	if err != nil {
		return false, err.Error()
	}
	return runOn == "folderOpen", ""
}

func planVSCodeFolderOpenTask(content artifact.Content, task map[string]json.RawMessage, index int) (projectCommandPlan, string, bool) {
	if _, overridden := task["osx"]; overridden {
		return projectCommandPlan{}, "macOS-specific task override is present and was not modeled", false
	}
	if _, dependent := task["dependsOn"]; dependent {
		return projectCommandPlan{}, "folder-open task dependency graph is present and was not modeled", false
	}
	if rawOptions, ok := task["options"]; ok {
		options, err := decodeProjectJSONObject(rawOptions)
		if err != nil {
			return projectCommandPlan{}, "task options are malformed: " + err.Error(), false
		}
		if _, changesCWD := options["cwd"]; changesCWD {
			return projectCommandPlan{}, "task working-directory override is present; project-relative command resolution was not modeled", false
		}
		if _, changesShell := options["shell"]; changesShell {
			return projectCommandPlan{}, "task shell override is present; command semantics were not modeled", false
		}
		if _, changesEnvironment := options["env"]; changesEnvironment {
			return projectCommandPlan{}, "task environment override is present; variable and executable resolution were not modeled", false
		}
	}
	rawType, ok := task["type"]
	if !ok {
		return projectCommandPlan{}, "folder-open task type is absent", false
	}
	taskType, err := decodeProjectString(rawType, "task.type")
	if err != nil {
		return projectCommandPlan{}, err.Error(), false
	}
	mode := projectCommandMode("")
	switch taskType {
	case "shell":
		mode = projectCommandShell
	case "process":
		mode = projectCommandExec
	default:
		return projectCommandPlan{}, fmt.Sprintf("folder-open task type %q is not modeled", taskType), false
	}
	rawCommand, ok := task["command"]
	if !ok {
		return projectCommandPlan{}, "folder-open task command is absent", false
	}
	command, err := decodeProjectString(rawCommand, "task.command")
	if err != nil {
		return projectCommandPlan{}, err.Error(), false
	}
	command = strings.TrimSpace(command)
	if command == "" {
		return projectCommandPlan{}, "folder-open task command is empty", false
	}
	var args []string
	if rawArgs, ok := task["args"]; ok {
		args, err = decodeProjectStringArray(rawArgs, "task.args")
		if err != nil {
			return projectCommandPlan{}, err.Error(), false
		}
	}
	if hasUnresolvedProjectCommandExpansion(append([]string{command}, args...), "${workspaceFolder}") {
		return projectCommandPlan{}, "folder-open task contains a variable or expansion outside the bounded ${workspaceFolder} form", false
	}
	if mode == projectCommandShell && len(args) > 0 {
		probe := projectCommandPlan{rootKind: vscodeTasksRootKind, mode: mode, command: command, args: args}
		if _, simple := projectCommandFields(probe); !simple {
			return projectCommandPlan{}, "shell task combines args with compound or unsupported command syntax; command semantics were not modeled", false
		}
	}
	label := fmt.Sprintf("folderOpen task %d", index+1)
	if rawLabel, ok := task["label"]; ok {
		decoded, err := decodeProjectString(rawLabel, "task.label")
		if err != nil {
			return projectCommandPlan{}, err.Error(), false
		}
		if strings.TrimSpace(decoded) != "" {
			label = strings.TrimSpace(decoded)
		}
	}
	encodedArgs, _ := json.Marshal(args)
	return projectCommandPlan{
		content:               content,
		rootKind:              vscodeTasksRootKind,
		rootName:              label,
		mode:                  mode,
		interpreterUnresolved: mode == projectCommandShell,
		command:               command,
		args:                  args,
		evidenceKind:          "vscode-folder-open-task",
		evidenceValue:         fmt.Sprintf("label=%s; type=%s; runOn=folderOpen; command=%s; args=%s", label, taskType, command, encodedArgs),
		coverageArea:          vscodeTasksAnalysisArea,
		gateDetail:            vscodeTasksGateDetail,
	}, "", true
}

func vscodeTaskIssue(nodeID string, index int, detail string) projectConfigIssue {
	return projectConfigIssue{
		nodeID: nodeID,
		area:   vscodeTasksAnalysisArea,
		detail: fmt.Sprintf("task %d: %s", index+1, detail),
	}
}

// tasks.json uses JSON with Comments. This bounded sanitizer preserves string
// contents, replaces comments with whitespace, and removes only commas whose
// next non-whitespace byte closes the containing array or object.
func decodeJSONC(data []byte) ([]byte, error) {
	if len(data) > maxStructuredDocumentBytes {
		return data, nil
	}
	clean := append([]byte(nil), data...)
	inString := false
	escaped := false
	for index := 0; index < len(clean); index++ {
		current := clean[index]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if current == '\\' {
				escaped = true
				continue
			}
			if current == '"' {
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
			continue
		}
		if current != '/' || index+1 >= len(clean) {
			continue
		}
		switch clean[index+1] {
		case '/':
			clean[index], clean[index+1] = ' ', ' '
			index += 2
			for ; index < len(clean) && clean[index] != '\n' && clean[index] != '\r'; index++ {
				clean[index] = ' '
			}
			index--
		case '*':
			clean[index], clean[index+1] = ' ', ' '
			index += 2
			closed := false
			for ; index < len(clean); index++ {
				if clean[index] == '*' && index+1 < len(clean) && clean[index+1] == '/' {
					clean[index], clean[index+1] = ' ', ' '
					index++
					closed = true
					break
				}
				if clean[index] != '\n' && clean[index] != '\r' {
					clean[index] = ' '
				}
			}
			if !closed {
				return nil, fmt.Errorf("unterminated block comment")
			}
		}
	}
	if inString {
		return nil, fmt.Errorf("unterminated string")
	}

	inString = false
	escaped = false
	for index := 0; index < len(clean); index++ {
		current := clean[index]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch current {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
			continue
		}
		if current != ',' {
			continue
		}
		next := index + 1
		for next < len(clean) && bytes.ContainsRune([]byte(" \t\r\n"), rune(clean[next])) {
			next++
		}
		if next < len(clean) && (clean[next] == ']' || clean[next] == '}') {
			clean[index] = ' '
		}
	}
	return clean, nil
}
