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
	npmBindingGypSelectionArea  = "npm-implicit-node-gyp-selection"
	npmBindingGypActivationArea = "npm-implicit-node-gyp-activation"
	npmBindingGypRootKind       = "npm-implicit-node-gyp-install"
	npmBindingGypProfile        = "npm-implicit-node-gyp-json-v1"

	maxNPMBindingGypPackages     = 32
	maxNPMBindingGypTargets      = 64
	maxNPMBindingGypSources      = 1024
	maxNPMBindingGypCommands     = 256
	maxNPMBindingGypCommandBytes = 64 << 10
	maxNPMBindingGypNameBytes    = 256
	maxNPMBindingGypTargetWork   = 4096
)

type npmBindingGypExpansion struct {
	targetName  string
	sourceIndex int
	command     string
}

type npmBindingGypPlan struct {
	manifest          artifact.Content
	binding           artifact.Content
	packageName       string
	attributionReason string
	expansions        []npmBindingGypExpansion
	targetNodeIDs     []string
}

type npmBindingGypIssue struct {
	nodeID string
	detail string
}

type npmBindingGypPlanSet struct {
	plans  []npmBindingGypPlan
	issues []npmBindingGypIssue
}

// planNPMBindingGypInstall selects a deliberately small npm/node-gyp profile.
// It pairs a package.json only with its exact sibling binding.gyp, requires the
// manifest conditions for npm's implicit node-gyp install default, and accepts
// a JSON-compatible GYP document with literal targets/sources only. It does not
// execute GYP, evaluate Python syntax, expand variables, or infer package-manager
// configuration.
func planNPMBindingGypInstall(contents []artifact.Content) npmBindingGypPlanSet {
	ordered := append([]artifact.Content(nil), contents...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].LogicalPath != ordered[j].LogicalPath {
			return ordered[i].LogicalPath < ordered[j].LogicalPath
		}
		return ordered[i].NodeID < ordered[j].NodeID
	})
	index := newLogicalContentIndex(contents)
	set := npmBindingGypPlanSet{}
	candidates := 0
	for _, manifest := range ordered {
		if manifest.RawFeaturesOnly || manifest.Kind != "manifest" || manifest.NodeID == "" ||
			!strings.EqualFold(virtualBase(manifest.LogicalPath), "package.json") ||
			!executionRootAllowed(manifest) || !behaviorSourceRoleAllowed(manifest.Role, false) ||
			!packageScriptsCanExecuteAtInstall(manifest.LogicalPath) {
			continue
		}
		if len(manifest.Data) > maxStructuredDocumentBytes || preflightPackageJSON(manifest.Data) != nil {
			// The ordinary package.json extractor owns precise decode coverage.
			continue
		}
		pkg, err := decodePackageJSONObject(manifest.Data)
		if err != nil || isVSCodeExtensionPackage(pkg, manifest.LogicalPath) {
			continue
		}
		overrides, reason := npmManifestOverridesImplicitNodeGyp(pkg)
		if reason != "" {
			set.issues = append(set.issues, npmBindingGypIssue{nodeID: manifest.NodeID, detail: reason})
			continue
		}
		if overrides {
			continue
		}
		bindingLogical, ok := resolveSiblingLogical(manifest.LogicalPath, "binding.gyp")
		if !ok {
			continue
		}
		if index.ambiguous[bindingLogical] || index.foldedAmbiguous[strings.ToLower(bindingLogical)] {
			set.issues = append(set.issues, npmBindingGypIssue{
				nodeID: manifest.NodeID,
				detail: "the exact sibling binding.gyp path was ambiguous in the retained artifact graph; no implicit node-gyp execution root was created",
			})
			continue
		}
		binding, ok := index.unique[bindingLogical]
		if !ok || binding.RawFeaturesOnly || !executionRootAllowed(binding) {
			continue
		}
		candidates++
		if candidates > maxNPMBindingGypPackages {
			set.plans = nil
			set.issues = append(set.issues, npmBindingGypIssue{
				detail: fmt.Sprintf("package-root binding.gyp candidate limit %d exceeded; no implicit node-gyp execution roots were created", maxNPMBindingGypPackages),
			})
			return set
		}
		expansions, reason := parseNPMBindingGyp(binding.Data)
		if reason != "" {
			set.issues = append(set.issues, npmBindingGypIssue{nodeID: binding.NodeID, detail: reason})
			continue
		}
		if len(expansions) == 0 {
			continue
		}
		plan := npmBindingGypPlan{manifest: manifest, binding: binding, expansions: expansions}
		if validNodePackageRootName(pkg.Name) {
			plan.packageName = pkg.Name
		} else {
			plan.attributionReason = "package name is absent or outside the bounded attribution grammar; implicit node-gyp selection was retained without claiming an external package specifier"
		}
		plan.targetNodeIDs, reason = npmBindingGypTargetNodes(plan, index)
		if reason != "" {
			set.issues = append(set.issues, npmBindingGypIssue{nodeID: binding.NodeID, detail: reason})
		}
		set.plans = append(set.plans, plan)
	}
	return set
}

func npmManifestOverridesImplicitNodeGyp(pkg packageJSON) (bool, string) {
	if len(pkg.Gypfile) > 0 {
		var enabled bool
		if err := json.Unmarshal(pkg.Gypfile, &enabled); err != nil {
			return false, "package.json gypfile is not a boolean; the implicit node-gyp default was not modeled"
		}
		if !enabled {
			return true, ""
		}
	}
	_, hasPreinstall := pkg.Scripts["preinstall"]
	_, hasInstall := pkg.Scripts["install"]
	return hasPreinstall || hasInstall, ""
}

func parseNPMBindingGyp(data []byte) ([]npmBindingGypExpansion, string) {
	if len(data) > maxStructuredDocumentBytes {
		return nil, fmt.Sprintf("binding.gyp structured decode skipped over parser input limit %d", maxStructuredDocumentBytes)
	}
	if err := preflightPackageJSON(data); err != nil {
		return nil, "binding.gyp is outside the bounded JSON-compatible GYP profile; Python-style syntax, malformed JSON, variables, includes, and conditions were not evaluated"
	}
	object, err := decodeProjectJSONObject(data)
	if err != nil {
		return nil, "binding.gyp is outside the bounded JSON-compatible GYP profile; Python-style syntax, malformed JSON, variables, includes, and conditions were not evaluated"
	}
	if key := firstUnsupportedNPMBindingGypField(object, "targets"); key != "" {
		return nil, fmt.Sprintf("binding.gyp top-level field %q is outside the bounded literal targets/sources profile; no command expansion was modeled", key)
	}
	rawTargets, ok := object["targets"]
	if !ok {
		return nil, "binding.gyp has no literal targets array; no command expansion was modeled"
	}
	var targets []json.RawMessage
	if err := json.Unmarshal(rawTargets, &targets); err != nil || targets == nil {
		return nil, "binding.gyp targets is not a literal array; no command expansion was modeled"
	}
	if len(targets) > maxNPMBindingGypTargets {
		return nil, fmt.Sprintf("binding.gyp target limit %d exceeded; no command expansion was modeled", maxNPMBindingGypTargets)
	}
	expansions := make([]npmBindingGypExpansion, 0)
	sourcesSeen := 0
	commandBytes := 0
	for targetIndex, rawTarget := range targets {
		target, err := decodeProjectJSONObject(rawTarget)
		if err != nil {
			return nil, fmt.Sprintf("binding.gyp target %d is not a literal object; no command expansion was modeled", targetIndex)
		}
		if key := firstUnsupportedNPMBindingGypField(target, "sources", "target_name", "type"); key != "" {
			return nil, fmt.Sprintf("binding.gyp target %d field %q is outside the bounded literal targets/sources profile; no command expansion was modeled", targetIndex, key)
		}
		targetName := fmt.Sprintf("target-%d", targetIndex)
		if rawName, exists := target["target_name"]; exists {
			name, err := decodeProjectString(rawName, fmt.Sprintf("targets[%d].target_name", targetIndex))
			if err != nil || name == "" || len(name) > maxNPMBindingGypNameBytes {
				return nil, fmt.Sprintf("binding.gyp target %d has an invalid literal target_name; no command expansion was modeled", targetIndex)
			}
			targetName = name
		}
		if rawType, exists := target["type"]; exists {
			if _, err := decodeProjectString(rawType, fmt.Sprintf("targets[%d].type", targetIndex)); err != nil {
				return nil, fmt.Sprintf("binding.gyp target %d has a non-literal type; no command expansion was modeled", targetIndex)
			}
		}
		rawSources, exists := target["sources"]
		if !exists {
			continue
		}
		var sources []json.RawMessage
		if err := json.Unmarshal(rawSources, &sources); err != nil || sources == nil {
			return nil, fmt.Sprintf("binding.gyp target %d sources is not a literal array; no command expansion was modeled", targetIndex)
		}
		sourcesSeen += len(sources)
		if sourcesSeen > maxNPMBindingGypSources {
			return nil, fmt.Sprintf("binding.gyp source limit %d exceeded; no command expansion was modeled", maxNPMBindingGypSources)
		}
		for sourceIndex, rawSource := range sources {
			source, err := decodeProjectString(rawSource, fmt.Sprintf("targets[%d].sources[%d]", targetIndex, sourceIndex))
			if err != nil {
				return nil, fmt.Sprintf("binding.gyp target %d source %d is not a bounded literal string; no command expansion was modeled", targetIndex, sourceIndex)
			}
			command, disposition := npmBindingGypCommandExpansion(source)
			switch disposition {
			case npmGypSourceLiteral:
				continue
			case npmGypSourceUnsupported:
				return nil, fmt.Sprintf("binding.gyp target %d source %d uses an unsupported or ambiguous GYP expansion; no command expansion was modeled", targetIndex, sourceIndex)
			case npmGypSourceCommand:
			}
			commandBytes += len(command)
			if len(expansions) >= maxNPMBindingGypCommands || commandBytes > maxNPMBindingGypCommandBytes {
				return nil, fmt.Sprintf("binding.gyp command count/byte limit %d/%d exceeded; no command expansion was modeled", maxNPMBindingGypCommands, maxNPMBindingGypCommandBytes)
			}
			expansions = append(expansions, npmBindingGypExpansion{targetName: targetName, sourceIndex: sourceIndex, command: command})
		}
	}
	return expansions, ""
}

func firstUnsupportedNPMBindingGypField(object map[string]json.RawMessage, allowed ...string) string {
	allowedSet := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = true
	}
	var unsupported []string
	for key := range object {
		if !allowedSet[key] {
			unsupported = append(unsupported, key)
		}
	}
	sort.Strings(unsupported)
	if len(unsupported) == 0 {
		return ""
	}
	return unsupported[0]
}

type npmGypSourceDisposition uint8

const (
	npmGypSourceLiteral npmGypSourceDisposition = iota
	npmGypSourceCommand
	npmGypSourceUnsupported
)

func npmBindingGypCommandExpansion(source string) (string, npmGypSourceDisposition) {
	trimmed := strings.TrimSpace(source)
	if !strings.Contains(trimmed, "<!") {
		return "", npmGypSourceLiteral
	}
	if !strings.HasPrefix(trimmed, "<!(") || !strings.HasSuffix(trimmed, ")") {
		return "", npmGypSourceUnsupported
	}
	command := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "<!("), ")"))
	if command == "" || len(command) > maxNPMBindingGypCommandBytes || strings.ContainsAny(command, "\x00\r\n()") {
		return "", npmGypSourceUnsupported
	}
	return command, npmGypSourceCommand
}

func npmBindingGypTargetNodes(plan npmBindingGypPlan, index logicalContentIndex) ([]string, string) {
	seen := map[string]bool{}
	var targetIDs []string
	work := 0
	incomplete := false
	missing := false
	for _, expansion := range plan.expansions {
		remaining := maxNPMBindingGypTargetWork - work
		if remaining <= 0 {
			incomplete = true
			break
		}
		targets, complete := localScriptTargetsLimited(expansion.command, remaining)
		if !complete {
			incomplete = true
		}
		for _, target := range targets {
			work++
			logical, ok := resolveSiblingLogical(plan.binding.LogicalPath, target)
			if !ok || index.ambiguous[logical] || index.foldedAmbiguous[strings.ToLower(logical)] {
				missing = true
				continue
			}
			content, ok := index.unique[logical]
			if !ok || !retainedScriptTarget(content) {
				missing = true
				continue
			}
			if !seen[content.NodeID] {
				seen[content.NodeID] = true
				targetIDs = append(targetIDs, content.NodeID)
			}
		}
	}
	sort.Strings(targetIDs)
	var details []string
	if incomplete {
		details = append(details, fmt.Sprintf("binding.gyp local command-target work limit %d reached; remaining targets were not preselected for behavior analysis", maxNPMBindingGypTargetWork))
	}
	if missing {
		details = append(details, "one or more concrete local binding.gyp command targets were absent or ambiguous in the retained artifact graph; target semantics were not associated")
	}
	return targetIDs, strings.Join(details, "; ")
}

func npmBindingGypExplicitTargetNodes(plans npmBindingGypPlanSet) map[string]bool {
	targets := map[string]bool{}
	for _, plan := range plans.plans {
		targets[plan.binding.NodeID] = true
		for _, nodeID := range plan.targetNodeIDs {
			targets[nodeID] = true
		}
	}
	return targets
}

func resolveNPMBindingGypInstall(graph *behavior.Graph, plans npmBindingGypPlanSet) commandTargetPolicy {
	targetPolicy := make(commandTargetPolicy)
	for _, issue := range plans.issues {
		addPartialCoverageOnce(graph, issue.nodeID, npmBindingGypSelectionArea, issue.detail)
	}
	for _, plan := range plans.plans {
		if graph.WorkLimitReached() {
			markDerivedGraphLimit(graph, npmBindingGypSelectionArea)
			return targetPolicy
		}
		manifestEvidenceValue := "preinstall/install absent; gypfile is not false; exact sibling binding.gyp retained"
		if plan.packageName != "" {
			manifestEvidenceValue = "package " + plan.packageName + "; " + manifestEvidenceValue
		}
		manifestEvidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:   plan.manifest.NodeID,
			ScopeID:  plan.manifest.ScopeID,
			Logical:  plan.manifest.LogicalPath,
			Physical: plan.manifest.PhysicalPath,
			Method:   "package.json",
			Kind:     "npm-implicit-node-gyp-selection",
			Value:    manifestEvidenceValue,
		})
		if manifestEvidenceID == "" {
			markDerivedGraphLimit(graph, npmBindingGypSelectionArea)
			return targetPolicy
		}
		expansionEvidence := make([]string, 0, len(plan.expansions))
		for _, expansion := range plan.expansions {
			evidenceID := graph.AddEvidence(behavior.Evidence{
				NodeID:   plan.binding.NodeID,
				ScopeID:  plan.binding.ScopeID,
				Logical:  plan.binding.LogicalPath,
				Physical: plan.binding.PhysicalPath,
				Method:   npmBindingGypProfile,
				Kind:     "gyp-command-expansion",
				Value:    fmt.Sprintf("%s sources[%d]: %s", expansion.targetName, expansion.sourceIndex, expansion.command),
			})
			if evidenceID == "" {
				markDerivedGraphLimit(graph, npmBindingGypSelectionArea)
				return targetPolicy
			}
			expansionEvidence = append(expansionEvidence, evidenceID)
		}
		scopeName := plan.packageName
		if scopeName == "" {
			scopeName = filepath.Base(filepath.Dir(filepath.ToSlash(plan.binding.LogicalPath)))
		}
		scopeID := graph.AddScope(behavior.Scope{
			NodeID:     plan.binding.NodeID,
			ParentID:   plan.binding.ScopeID,
			Kind:       "npm-implicit-node-gyp",
			Name:       scopeName,
			SourceRole: plan.binding.Role,
		})
		if scopeID == "" {
			markDerivedGraphLimit(graph, npmBindingGypSelectionArea)
			return targetPolicy
		}
		rootID := graph.AddExecutionRoot(behavior.ExecutionRoot{
			Kind:              npmBindingGypRootKind,
			DeclarationNodeID: plan.binding.NodeID,
			StartScopeID:      scopeID,
			Name:              plan.packageName,
			Interpreter:       "node-gyp",
			Arguments:         []string{"rebuild"},
			EvidenceIDs:       append([]string{manifestEvidenceID}, expansionEvidence...),
		})
		if rootID == "" {
			markDerivedGraphLimit(graph, npmBindingGypSelectionArea)
			return targetPolicy
		}
		graph.AddAnalysisSelection(behavior.AnalysisSelection{NodeID: plan.binding.NodeID, Reasons: []behavior.SelectionReason{behavior.SelectionReasonExecutionRoot}})
		graph.AddCoverage(behavior.Coverage{
			NodeID:       plan.binding.NodeID,
			AnalysisArea: npmBindingGypSelectionArea,
			Status:       "analyzed",
			Detail:       "literal command expansion selected by the bounded " + npmBindingGypProfile + " profile",
		})
		addPartialCoverageOnce(
			graph,
			plan.manifest.NodeID,
			npmBindingGypActivationArea,
			"the implicit node-gyp relationship is conditional: npm version and dependency-script policy, ignore-scripts/allowScripts configuration, node-gyp and build-tool availability, platform shell behavior, install occurrence, command success, and later payload behavior were not observed",
		)
		if plan.attributionReason != "" {
			addPartialCoverageOnce(graph, plan.manifest.NodeID, npmBindingGypSelectionArea, plan.attributionReason)
		}
		execution := connectedExecutionContext([]string{rootID}, nil)
		commandContent := plan.binding
		commandContent.ScopeID = scopeID
		commandContent = contentWithExecutionContext(commandContent, execution)
		for index, expansion := range plan.expansions {
			operationStart := len(graph.Operations)
			AnalyzeShellLine(graph, commandContent, expansion.command, index+1, execution, expansionEvidence[index])
			allowed := map[string]bool{}
			targets, _ := localScriptTargetsLimited(expansion.command, maxNPMBindingGypTargetWork)
			for _, target := range targets {
				if logical, ok := resolveSiblingLogical(plan.binding.LogicalPath, target); ok {
					allowed[logical] = true
				}
			}
			for operationIndex := operationStart; operationIndex < len(graph.Operations); operationIndex++ {
				operation := graph.Operations[operationIndex]
				if scriptTargetSourceOperation(operation) {
					targetPolicy[operation.ID] = allowed
				}
			}
			if graph.WorkLimitReached() {
				markDerivedGraphLimit(graph, npmBindingGypSelectionArea)
				return targetPolicy
			}
		}
	}
	return targetPolicy
}
