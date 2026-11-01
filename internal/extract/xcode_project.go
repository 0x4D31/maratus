package extract

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/plistx"
)

const (
	maxXcodeTargets               = 4096
	maxXcodeTargetPhaseReferences = 8192
	maxXcodeRunScriptPhases       = 1024
)

type xcodeRunScriptPhase struct {
	id      string
	name    string
	shell   string
	script  string
	targets []xcodeTargetReference
}

type xcodeTargetReference struct {
	id   string
	name string
}

func extractXcodeProject(graph *behavior.Graph, content artifact.Content) {
	data, ok := boundedStructuredDocument(graph, content, "xcode-project", content.Data)
	if !ok {
		return
	}
	project, err := plistx.Decode(data)
	if err != nil {
		addPartialCoverageOnce(graph, content.NodeID, "xcode-project", "OpenStep project decode failed: "+err.Error())
		return
	}
	objects, ok := project["objects"].(plistx.Dict)
	if !ok {
		addPartialCoverageOnce(graph, content.NodeID, "xcode-project", "project objects dictionary is absent or malformed")
		return
	}

	referenced, complete := xcodeReferencedBuildPhases(graph, content, project, objects, nil)
	phaseIDs := make([]string, 0, len(objects))
	for objectID, raw := range objects {
		object, ok := raw.(plistx.Dict)
		if ok && plistx.String(object, "isa") == "PBXShellScriptBuildPhase" {
			phaseIDs = append(phaseIDs, objectID)
		}
	}
	sort.Slice(phaseIDs, func(i, j int) bool {
		leftReferenced := len(referenced[phaseIDs[i]]) > 0
		rightReferenced := len(referenced[phaseIDs[j]]) > 0
		if leftReferenced != rightReferenced {
			return leftReferenced
		}
		return phaseIDs[i] < phaseIDs[j]
	})
	if len(phaseIDs) > maxXcodeRunScriptPhases {
		phaseIDs = phaseIDs[:maxXcodeRunScriptPhases]
		addPartialCoverageOnce(graph, content.NodeID, "xcode-project-run-scripts", fmt.Sprintf("run-script phase limit %d reached; remaining phases were not modeled", maxXcodeRunScriptPhases))
	}

	for _, phaseID := range phaseIDs {
		object := objects[phaseID].(plistx.Dict)
		phase := xcodeRunScriptPhase{
			id:      phaseID,
			name:    plistx.String(object, "name"),
			shell:   plistx.String(object, "shellPath"),
			script:  xcodeExactString(object["shellScript"]),
			targets: sortedUniqueXcodeTargetReferences(referenced[phaseID]),
		}
		if phase.name == "" {
			phase.name = "Run Script " + phase.id
		}
		extractXcodeRunScriptPhase(graph, content, phase)
	}
	if !complete {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			"xcode-project-run-scripts",
			fmt.Sprintf(
				"Xcode target/reference inventory was incomplete; target ownership was not fully evaluated (bounds: %d targets, %d build-phase references)",
				maxXcodeTargets,
				maxXcodeTargetPhaseReferences,
			),
		)
	}
}

func xcodeReferencedBuildPhases(
	graph *behavior.Graph,
	content artifact.Content,
	project, objects plistx.Dict,
	derivedWork *derivedWorkBudget,
) (map[string][]xcodeTargetReference, bool) {
	referenced := map[string][]xcodeTargetReference{}
	rootObjectID := plistx.String(project, "rootObject")
	rootObject, ok := objects[rootObjectID].(plistx.Dict)
	if rootObjectID == "" || !ok || plistx.String(rootObject, "isa") != "PBXProject" {
		addPartialCoverageOnce(graph, content.NodeID, "xcode-project-run-scripts", "root PBXProject object is absent or malformed; no build-phase execution roots were created")
		return referenced, true
	}
	rawTargetIDs, ok := rootObject["targets"].([]any)
	if !ok || len(rawTargetIDs) > maxXcodeTargets ||
		derivedWork != nil && len(rawTargetIDs) > derivedWork.remaining {
		addPartialCoverageOnce(graph, content.NodeID, "xcode-project-run-scripts", "root project target list is malformed or exceeded the bounded target/work budget; no build-phase execution roots were created")
		return referenced, false
	}
	targetIDs, ok := xcodeStringArray(rawTargetIDs)
	if !ok {
		addPartialCoverageOnce(graph, content.NodeID, "xcode-project-run-scripts", "root project target list is malformed; no build-phase execution roots were created")
		return referenced, true
	}
	sort.Strings(targetIDs)
	references := 0
	complete := true
	for _, targetID := range targetIDs {
		if derivedWork != nil && !derivedWork.take() {
			return referenced, false
		}
		target, ok := objects[targetID].(plistx.Dict)
		if !ok || !xcodeBuildTargetKind(plistx.String(target, "isa")) {
			addPartialCoverageOnce(graph, content.NodeID, "xcode-project-run-scripts", "one or more root project target references were absent or unsupported")
			complete = false
			continue
		}
		rawPhaseIDs, ok := target["buildPhases"].([]any)
		if !ok || len(rawPhaseIDs) > maxXcodeTargetPhaseReferences-references ||
			derivedWork != nil && len(rawPhaseIDs) > derivedWork.remaining {
			addPartialCoverageOnce(graph, content.NodeID, "xcode-project-run-scripts", "one or more target buildPhases lists were malformed or exceeded the bounded reference/work budget")
			return referenced, false
		}
		phaseIDs, ok := xcodeStringArray(rawPhaseIDs)
		if !ok {
			addPartialCoverageOnce(graph, content.NodeID, "xcode-project-run-scripts", "one or more target buildPhases lists were malformed")
			complete = false
			continue
		}
		targetName := plistx.String(target, "name")
		if targetName == "" {
			targetName = targetID
		}
		for _, phaseID := range phaseIDs {
			if references >= maxXcodeTargetPhaseReferences {
				return referenced, false
			}
			references++
			if derivedWork != nil && !derivedWork.take() {
				return referenced, false
			}
			if _, exists := objects[phaseID]; !exists {
				addPartialCoverageOnce(graph, content.NodeID, "xcode-project-run-scripts", "one or more target build-phase references were absent from the objects dictionary")
				complete = false
				continue
			}
			referenced[phaseID] = append(referenced[phaseID], xcodeTargetReference{id: targetID, name: targetName})
		}
	}
	return referenced, complete
}

func xcodeBuildTargetKind(kind string) bool {
	switch kind {
	case "PBXNativeTarget", "PBXAggregateTarget", "PBXLegacyTarget":
		return true
	default:
		return false
	}
}

func xcodeStringArray(value any) ([]string, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		value, ok := item.(string)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, false
		}
		result = append(result, strings.TrimSpace(value))
	}
	return result, true
}

func xcodeExactString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func extractXcodeRunScriptPhase(graph *behavior.Graph, content artifact.Content, phase xcodeRunScriptPhase) {
	targetNames := make([]string, 0, len(phase.targets))
	for _, target := range phase.targets {
		targetNames = append(targetNames, target.name)
	}
	targets := strings.Join(sortedUniqueNonemptyStrings(targetNames), ", ")
	evidenceValue := "phase " + phase.name
	if targets != "" {
		evidenceValue = "targets " + targets + " -> " + evidenceValue
	}
	if phase.shell != "" {
		evidenceValue += "; shell " + phase.shell
	}
	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID:   content.NodeID,
		ScopeID:  content.ScopeID,
		Logical:  content.LogicalPath,
		Physical: content.PhysicalPath,
		Method:   "xcode-project",
		Kind:     "xcode-run-script-phase",
		Value:    evidenceValue,
	})
	if evidenceID == "" {
		return
	}

	execution := unknownExecutionContext()
	rootID := ""
	phaseScopeID := content.ScopeID
	if len(phase.targets) > 0 && executionRootAllowed(content) {
		switch {
		case phase.script == "":
			addPartialCoverageOnce(graph, content.NodeID, "xcode-project-run-scripts", "one or more target-referenced run-script phases had no literal shellScript value")
		case phase.shell == "":
			addPartialCoverageOnce(graph, content.NodeID, "xcode-project-run-scripts", "one or more target-referenced run-script phases had no literal shellPath value")
		default:
			phaseScopeID = graph.AddScope(behavior.Scope{
				NodeID:     content.NodeID,
				ParentID:   content.ScopeID,
				Kind:       "xcode-run-script",
				Name:       phase.name,
				SourceRole: content.Role,
			})
			rootID = graph.AddExecutionRoot(behavior.ExecutionRoot{
				Kind:              "xcode-run-script",
				DeclarationNodeID: content.NodeID,
				StartNodeID:       content.NodeID,
				StartScopeID:      phaseScopeID,
				Name:              phase.name,
				Interpreter:       phase.shell,
				EvidenceIDs:       []string{evidenceID},
			})
			if rootID != "" {
				execution = connectedExecutionContext([]string{rootID}, nil)
				graph.AddAnalysisSelection(behavior.AnalysisSelection{NodeID: content.NodeID, Reasons: []behavior.SelectionReason{behavior.SelectionReasonExecutionRoot}})
			}
		}
	}

	if phase.script != "" {
		qualifiers := map[string]string{
			"phase":    phase.name,
			"phase_id": phase.id,
			"shell":    phase.shell,
		}
		if targets != "" {
			qualifiers["targets"] = targets
		}
		graph.AddFeature(behavior.Feature{
			NodeID:      content.NodeID,
			ScopeID:     phaseScopeID,
			Key:         "xcode.build_phase.shell_script",
			Value:       phase.script,
			Qualifiers:  qualifiers,
			EvidenceIDs: []string{evidenceID},
			Support:     behavior.SupportDirect,
			Execution:   execution,
		})
	}
	if rootID == "" {
		return
	}

	scriptContent := content
	scriptContent.ScopeID = phaseScopeID
	if !xcodeSupportedShellPath(phase.shell) {
		addPartialCoverageOnce(graph, content.NodeID, "xcode-project-run-scripts", "one or more target-referenced run-script phases used an unsupported shellPath; script semantics were not analyzed")
		return
	}
	scriptContent.SemanticLanguage = "shell"
	scriptContent.BehaviorAnalysisForced = true
	scriptContent = contentWithExecutionContext(scriptContent, execution)
	if _, ok := xcodeShellBuildSettingReference(phase.script); ok {
		// Resolution needs the target and project configuration lists, plus any
		// retained target-level xcconfig. The bounded post-pass has access to
		// the complete content index and records explicit partial coverage when
		// it cannot prove one effective declared value.
		return
	}
	scriptContent.Data = []byte(phase.script)
	ExtractText(graph, scriptContent)
}

func xcodeSupportedShellPath(value string) bool {
	switch strings.TrimSpace(value) {
	case "sh", "bash", "zsh", "/bin/sh", "/bin/bash", "/bin/zsh":
		return true
	default:
		return false
	}
}

func sortedUniqueXcodeTargetReferences(values []xcodeTargetReference) []xcodeTargetReference {
	seen := make(map[string]bool, len(values))
	result := make([]xcodeTargetReference, 0, len(values))
	for _, value := range values {
		value.id = strings.TrimSpace(value.id)
		value.name = strings.TrimSpace(value.name)
		if value.id == "" || value.name == "" || seen[value.id] {
			continue
		}
		seen[value.id] = true
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].id != result[j].id {
			return result[i].id < result[j].id
		}
		return result[i].name < result[j].name
	})
	return result
}

func sortedUniqueNonemptyStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
