package extract

import (
	"bytes"
	"container/heap"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Type                 string            `json:"type"`
	Main                 string            `json:"main"`
	Exports              json.RawMessage   `json:"exports"`
	Browser              packageBrowser    `json:"browser"`
	ActivationEvents     json.RawMessage   `json:"activationEvents"`
	Scripts              map[string]string `json:"scripts"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Engines              map[string]string `json:"engines"`
	Gypfile              json.RawMessage   `json:"gypfile"`
}

// decodePackageJSONObject follows JSON/Node key casing exactly. The standard
// struct decoder accepts case-folded field names, which can make Maratus model a
// lifecycle script or entry module that npm/Node would ignore.
func decodePackageJSONObject(data []byte) (packageJSON, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return packageJSON{}, err
	}
	if object == nil {
		return packageJSON{}, fmt.Errorf("package manifest is not an object")
	}
	var pkg packageJSON
	fields := []struct {
		name   string
		target any
	}{
		{name: "name", target: &pkg.Name},
		{name: "version", target: &pkg.Version},
		{name: "type", target: &pkg.Type},
		{name: "main", target: &pkg.Main},
		{name: "exports", target: &pkg.Exports},
		{name: "browser", target: &pkg.Browser},
		{name: "activationEvents", target: &pkg.ActivationEvents},
		{name: "scripts", target: &pkg.Scripts},
		{name: "dependencies", target: &pkg.Dependencies},
		{name: "devDependencies", target: &pkg.DevDependencies},
		{name: "optionalDependencies", target: &pkg.OptionalDependencies},
		{name: "peerDependencies", target: &pkg.PeerDependencies},
		{name: "engines", target: &pkg.Engines},
		{name: "gypfile", target: &pkg.Gypfile},
	}
	for _, field := range fields {
		raw, ok := object[field.name]
		if !ok {
			continue
		}
		if err := json.Unmarshal(raw, field.target); err != nil {
			return packageJSON{}, fmt.Errorf("invalid %s: %w", field.name, err)
		}
	}
	return pkg, nil
}

// package.json permits browser to be either a string entrypoint or a mapping.
// maratus only consumes the string form. A custom scalar avoids materializing an
// attacker-controlled object or array through interface{} just to discard it.
type packageBrowser string

func (browser *packageBrowser) UnmarshalJSON(data []byte) error {
	*browser = ""
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '"' {
		return nil
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*browser = packageBrowser(value)
	return nil
}

const (
	// Token and nesting limits bound allocation amplification in encoding/json
	// for documents such as arrays containing millions of empty values. Normal
	// package manifests are several orders of magnitude smaller.
	maxPackageJSONTokens = 32768
	maxPackageJSONDepth  = 64
	// Dependency declarations are inventory facts, not a request to resolve the
	// dependency graph. Bound retained declarations independently so isolated
	// extractor use remains safe even when the graph itself has no item limit.
	maxPackageDependencyFacts = 4096
)

// Target propagation is linear after indexing, but attacker-controlled
// manifests and commands can still name many relationships. Keep independent
// work budgets so these derived passes remain bounded even for graphs without
// item limits.
const (
	maxPackageTargetResolutionWork = 4 * behavior.DefaultItemLimit
	maxVSCodeTargetResolutionWork  = 2 * behavior.DefaultItemLimit
	maxScriptTargetResolutionWork  = 4 * behavior.DefaultItemLimit
	maxVSCodeActivationEvents      = 256
	maxVSCodeActivationEventBytes  = 4096
	maxVSCodeActivationEventWork   = 4096
)

func ExtractPackageHooks(graph *behavior.Graph, content artifact.Content) {
	base := strings.ToLower(virtualBase(content.LogicalPath))
	if filepath.Ext(base) == ".pbxproj" {
		extractXcodeProject(graph, content)
		return
	}
	switch base {
	case "package.json":
		extractPackageJSON(graph, content)
	case "entry_points.txt":
		extractPythonEntrypoints(graph, content)
	}
}

func extractPackageJSON(graph *behavior.Graph, content artifact.Content) {
	pkg, ok := decodePackageJSON(graph, content)
	if !ok {
		return
	}
	names := make([]string, 0, len(pkg.Scripts))
	for name := range pkg.Scripts {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		leftLifecycle := isLifecycleEntrypointScript(names[i])
		rightLifecycle := isLifecycleEntrypointScript(names[j])
		if leftLifecycle != rightLifecycle {
			return leftLifecycle
		}
		return names[i] < names[j]
	})
	for _, name := range names {
		command := strings.TrimSpace(pkg.Scripts[name])
		if command == "" {
			continue
		}
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:   content.NodeID,
			Logical:  content.LogicalPath,
			Physical: content.PhysicalPath,
			Method:   "package.json",
			Kind:     "package-script",
			Value:    name + ": " + command,
		})
		execution := unknownExecutionContext()
		rootID := ""
		if executionRootAllowed(content) && packageScriptsCanExecuteAtInstall(content.LogicalPath) && !isVSCodeExtensionPackage(pkg, content.LogicalPath) && isLifecycleEntrypointScript(name) {
			rootID = graph.AddExecutionRoot(behavior.ExecutionRoot{
				Kind:              "npm-script",
				DeclarationNodeID: content.NodeID,
				StartNodeID:       content.NodeID,
				StartScopeID:      content.ScopeID,
				Name:              name,
				Arguments:         []string{command},
				EvidenceIDs:       []string{evidenceID},
			})
			if rootID != "" {
				execution = connectedExecutionContext([]string{rootID}, nil)
			}
		}
		graph.AddFeature(behavior.Feature{
			NodeID:  content.NodeID,
			ScopeID: content.ScopeID,
			Key:     "package.script",
			Value:   command,
			Qualifiers: map[string]string{
				"name": name,
			},
			EvidenceIDs: []string{evidenceID},
			Support:     behavior.SupportDirect,
			Execution:   execution,
		})
		if rootID == "" {
			continue
		}
		graph.AddAnalysisSelection(behavior.AnalysisSelection{NodeID: content.NodeID, Reasons: []behavior.SelectionReason{behavior.SelectionReasonExecutionRoot}})
		scriptContent := content
		scriptContent.ScopeID = graph.AddScope(behavior.Scope{NodeID: content.NodeID, ParentID: content.ScopeID, Kind: "package-script", Name: name, SourceRole: content.Role})
		scriptContent = contentWithExecutionContext(scriptContent, execution)
		AnalyzeShellLine(graph, scriptContent, command, 0, execution, evidenceID)
	}
	// Execution-bearing declarations take priority over bounded observational
	// inventory when a hostile manifest reaches the shared evidence ceiling.
	extractNodePackageManifestFeatures(graph, content, pkg)
	extractPackageDependencyFeatures(graph, content, pkg)
}

func extractPackageDependencyFeatures(graph *behavior.Graph, content artifact.Content, pkg packageJSON) {
	sections := []struct {
		name   string
		values map[string]string
	}{
		{name: "dependencies", values: pkg.Dependencies},
		{name: "devDependencies", values: pkg.DevDependencies},
		{name: "optionalDependencies", values: pkg.OptionalDependencies},
		{name: "peerDependencies", values: pkg.PeerDependencies},
	}
	retained := 0
	for _, section := range sections {
		names := make([]string, 0, len(section.values))
		for name := range section.values {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if retained >= maxPackageDependencyFacts {
				addPartialCoverageOnce(graph, content.NodeID, "package-dependency-inventory", fmt.Sprintf("dependency declaration limit %d reached; remaining declarations were not retained", maxPackageDependencyFacts))
				return
			}
			specifier := section.values[name]
			evidenceID := graph.AddEvidence(behavior.Evidence{
				NodeID:   content.NodeID,
				Logical:  content.LogicalPath,
				Physical: content.PhysicalPath,
				Method:   "package.json",
				Kind:     "package-dependency",
				Value:    section.name + ": " + name + "@" + specifier,
			})
			if evidenceID == "" {
				return
			}
			if graph.AddFeature(behavior.Feature{
				NodeID:  content.NodeID,
				ScopeID: content.ScopeID,
				Key:     "package.dependency",
				Value:   name,
				Qualifiers: map[string]string{
					"section":   section.name,
					"specifier": specifier,
				},
				EvidenceIDs: []string{evidenceID},
				Support:     behavior.SupportDirect,
				Execution:   unknownExecutionContext(),
			}) == "" {
				return
			}
			retained++
		}
	}
}

func decodePackageJSON(graph *behavior.Graph, content artifact.Content) (packageJSON, bool) {
	data, ok := boundedStructuredDocument(graph, content, "package-json", content.Data)
	if !ok {
		return packageJSON{}, false
	}
	if err := preflightPackageJSON(data); err != nil {
		addPartialCoverageOnce(graph, content.NodeID, "package-json", "package manifest decode failed: "+err.Error())
		return packageJSON{}, false
	}
	pkg, err := decodePackageJSONObject(data)
	if err != nil {
		addPartialCoverageOnce(graph, content.NodeID, "package-json", "package manifest decode failed: "+err.Error())
		return packageJSON{}, false
	}
	return pkg, true
}

func preflightPackageJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	depth := 0
	for count := 1; ; count++ {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if count > maxPackageJSONTokens {
			return fmt.Errorf("JSON token limit %d reached", maxPackageJSONTokens)
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			continue
		}
		switch delimiter {
		case '{', '[':
			depth++
			if depth > maxPackageJSONDepth {
				return fmt.Errorf("JSON nesting limit %d reached", maxPackageJSONDepth)
			}
		case '}', ']':
			depth--
		}
	}
}

func packageScriptsCanExecuteAtInstall(logical string) bool {
	logical = strings.ToLower(strings.ReplaceAll(filepath.ToSlash(logical), "!", "/"))
	logical = "/" + strings.Trim(logical, "/") + "/"
	return !strings.Contains(logical, ".app/") && !strings.Contains(logical, "/node_modules/")
}

func isLifecycleEntrypointScript(name string) bool {
	return isLifecycleScript(name)
}

func isLifecycleScript(name string) bool {
	switch name {
	case "preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare":
		return true
	default:
		return false
	}
}

func extractPythonEntrypoints(graph *behavior.Graph, content artifact.Content) {
	section := ""
	input := boundedText(content.Data)
	addBoundedTextCoverage(graph, content, "python-entrypoints", input)
	lines := input.Lines
	for i, raw := range lines {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			break
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		if section != "console_scripts" && section != "gui_scripts" {
			continue
		}
		name, target, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:  content.NodeID,
			Logical: content.LogicalPath,
			Line:    i + 1,
			Method:  "python-wheel-entrypoints",
			Kind:    "python-entrypoint",
			Value:   strings.TrimSpace(line),
		})
		if executionRootAllowed(content) {
			rootID := graph.AddExecutionRoot(behavior.ExecutionRoot{
				Kind:              section,
				DeclarationNodeID: content.NodeID,
				StartNodeID:       content.NodeID,
				StartScopeID:      content.ScopeID,
				Name:              strings.TrimSpace(name),
				Arguments:         []string{strings.TrimSpace(target)},
				EvidenceIDs:       []string{evidenceID},
			})
			if rootID != "" {
				graph.AddAnalysisSelection(behavior.AnalysisSelection{NodeID: content.NodeID, Reasons: []behavior.SelectionReason{behavior.SelectionReasonExecutionRoot}})
			}
		}
	}
}

func ResolvePackageScriptTargets(graph *behavior.Graph, contents []artifact.Content) {
	resolvePackageScriptTargets(graph, contents, maxPackageTargetResolutionWork)
}

type packageScriptRootKey struct {
	nodeID string
	name   string
}

func resolvePackageScriptTargets(graph *behavior.Graph, contents []artifact.Content, workLimit int) {
	if graph.WorkLimitReached() {
		markDerivedGraphLimit(graph, "package-script-target-resolution")
		return
	}
	byLogical := newLogicalContentIndex(contents).unique
	operationsByNode := operationIndicesBySubjectNode(graph.Operations)
	roots := packageScriptRootIndex(graph.ExecutionRoots)
	work := newDerivedWorkBudget(workLimit)
	for _, content := range contents {
		if graph.WorkLimitReached() {
			markDerivedGraphLimit(graph, "package-script-target-resolution")
			return
		}
		if content.RawFeaturesOnly || strings.ToLower(virtualBase(content.LogicalPath)) != "package.json" {
			continue
		}
		if !packageScriptsCanExecuteAtInstall(content.LogicalPath) {
			continue
		}
		pkg, ok := decodePackageJSON(graph, content)
		if !ok {
			continue
		}
		if isVSCodeExtensionPackage(pkg, content.LogicalPath) {
			continue
		}
		names := make([]string, 0, len(pkg.Scripts))
		for name := range pkg.Scripts {
			if isLifecycleScript(name) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			if graph.WorkLimitReached() {
				markDerivedGraphLimit(graph, "package-script-target-resolution")
				return
			}
			rootID := roots[packageScriptRootKey{nodeID: content.NodeID, name: name}]
			if rootID == "" {
				// Without the retained lifecycle execution root there is no sound
				// source from which to establish target execution connectivity.
				continue
			}
			if !packageCommandBaseIsStable(pkg.Scripts[name]) {
				addPartialCoverageOnce(graph, content.NodeID, "package-script-target-resolution", "the lifecycle command has unmodeled shell state or working-directory changes; local target and package-script associations were not inferred")
				continue
			}
			if !resolveReferencedPackageScripts(graph, content, pkg.Scripts, name, pkg.Scripts[name], rootID, &work, workLimit) {
				return
			}
			targets, complete := localScriptTargetsLimited(pkg.Scripts[name], work.remaining)
			for _, target := range targets {
				if graph.WorkLimitReached() {
					markDerivedGraphLimit(graph, "package-script-target-resolution")
					return
				}
				if !work.take() {
					markDerivedWorkLimit(graph, "package-script-target-resolution", workLimit, "package script target relationships")
					return
				}
				logical, ok := resolveSiblingLogical(content.LogicalPath, target)
				if !ok {
					continue
				}
				targetContent, ok := byLogical[logical]
				if !ok {
					addPartialCoverageOnce(
						graph,
						content.NodeID,
						"package-script-target-resolution",
						"one or more concrete local lifecycle targets were absent from the retained artifact graph; target semantics were not analyzed and the target may be generated at runtime or missing from the inspected artifact",
					)
					continue
				}
				evidenceID := graph.AddEvidence(behavior.Evidence{
					NodeID:   targetContent.NodeID,
					ScopeID:  targetContent.ScopeID,
					Logical:  targetContent.LogicalPath,
					Physical: targetContent.PhysicalPath,
					Method:   "package-script-target",
					Kind:     "resolved-script-target",
					Value:    name + " -> " + target,
				})
				if evidenceID == "" {
					markDerivedGraphLimit(graph, "package-script-target-resolution")
					return
				}
				if graph.WorkLimitReached() {
					markDerivedGraphLimit(graph, "package-script-target-resolution")
					return
				}
				targetID := graph.AddInvokedTarget(behavior.InvokedTarget{
					Kind:        "lifecycle-target",
					NodeID:      targetContent.NodeID,
					ScopeID:     targetContent.ScopeID,
					Source:      behavior.EntityRef{Kind: behavior.EntityKindExecutionRoot, ID: rootID},
					Execution:   connectedExecutionContext([]string{rootID}, nil),
					Arguments:   []string{targetContent.LogicalPath},
					EvidenceIDs: []string{evidenceID},
				})
				if targetID == "" {
					markDerivedGraphLimit(graph, "package-script-target-resolution")
					return
				}
				graph.AddAnalysisSelection(behavior.AnalysisSelection{NodeID: targetContent.NodeID, Reasons: []behavior.SelectionReason{behavior.SelectionReasonInvokedTarget}})
				if !promoteIndexedNodeOperations(
					graph,
					operationsByNode[targetContent.NodeID],
					targetContent.ScopeID,
					connectedExecutionContext([]string{rootID}, []string{targetID}),
					&work,
					workLimit,
					"package-script-target-resolution",
					"package script operation promotions",
				) {
					return
				}
			}
			if !complete {
				markDerivedWorkLimit(graph, "package-script-target-resolution", workLimit, "package script target relationships")
				return
			}
		}
	}
}

const maxPackageScriptReferenceDepth = 8

func packageScriptRootIndex(roots []behavior.ExecutionRoot) map[packageScriptRootKey]string {
	out := make(map[packageScriptRootKey]string)
	for _, root := range roots {
		if root.ID == "" || root.Kind != "npm-script" {
			continue
		}
		key := packageScriptRootKey{nodeID: root.DeclarationNodeID, name: root.Name}
		if out[key] == "" {
			// Preserve first-match behavior for malformed caller-supplied
			// graphs containing duplicate npm-script roots.
			out[key] = root.ID
		}
	}
	return out
}

func resolveReferencedPackageScripts(graph *behavior.Graph, content artifact.Content, scripts map[string]string, rootName, command, rootID string, work *derivedWorkBudget, workLimit int) bool {
	if rootID == "" || len(scripts) == 0 {
		return true
	}
	visited := map[string]bool{rootName: true}
	return resolvePackageScriptReferenceDepth(graph, content, scripts, rootName, command, rootID, visited, 0, work, workLimit)
}

func resolvePackageScriptReferenceDepth(graph *behavior.Graph, content artifact.Content, scripts map[string]string, parentName, command, rootID string, visited map[string]bool, depth int, work *derivedWorkBudget, workLimit int) bool {
	if depth >= maxPackageScriptReferenceDepth {
		addPartialCoverageOnce(graph, content.NodeID, "package-script-target-resolution", "package-script reference depth limit reached; deeper script references were not followed")
		return true
	}
	if !packageCommandBaseIsStable(command) {
		addPartialCoverageOnce(graph, content.NodeID, "package-script-target-resolution", "the package command has unmodeled shell state or working-directory changes; further local script associations were not inferred")
		return true
	}
	targetNames, complete := packageScriptReferencesLimited(command, work.remaining)
	for _, targetName := range targetNames {
		if graph.WorkLimitReached() {
			markDerivedGraphLimit(graph, "package-script-target-resolution")
			return false
		}
		if !work.take() {
			markDerivedWorkLimit(graph, "package-script-target-resolution", workLimit, "package script references")
			return false
		}
		targetCommand := strings.TrimSpace(scripts[targetName])
		if targetCommand == "" || visited[targetName] {
			continue
		}
		visited[targetName] = true
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:   content.NodeID,
			ScopeID:  content.ScopeID,
			Logical:  content.LogicalPath,
			Physical: content.PhysicalPath,
			Method:   "package-script-target",
			Kind:     "resolved-package-script",
			Value:    parentName + " -> " + targetName + ": " + targetCommand,
		})
		if evidenceID == "" {
			markDerivedGraphLimit(graph, "package-script-target-resolution")
			return false
		}
		if graph.WorkLimitReached() {
			markDerivedGraphLimit(graph, "package-script-target-resolution")
			return false
		}
		if graph.AddFeature(behavior.Feature{
			NodeID:  content.NodeID,
			ScopeID: content.ScopeID,
			Key:     "package.script.reference",
			Value:   targetName,
			Qualifiers: map[string]string{
				"from": parentName,
			},
			EvidenceIDs: []string{evidenceID},
			Support:     behavior.SupportDirect,
			Execution:   connectedExecutionContext([]string{rootID}, nil),
		}) == "" {
			markDerivedGraphLimit(graph, "package-script-target-resolution")
			return false
		}
		if graph.WorkLimitReached() {
			markDerivedGraphLimit(graph, "package-script-target-resolution")
			return false
		}
		targetContent := content
		targetContent.ScopeID = graph.AddScope(behavior.Scope{
			NodeID:     content.NodeID,
			ParentID:   content.ScopeID,
			Kind:       "package-script",
			Name:       targetName,
			SourceRole: content.Role,
		})
		if targetContent.ScopeID == "" {
			markDerivedGraphLimit(graph, "package-script-target-resolution")
			return false
		}
		if graph.WorkLimitReached() {
			markDerivedGraphLimit(graph, "package-script-target-resolution")
			return false
		}
		targetID := graph.AddInvokedTarget(behavior.InvokedTarget{
			Kind:        "package-script-reference",
			NodeID:      content.NodeID,
			ScopeID:     targetContent.ScopeID,
			Source:      behavior.EntityRef{Kind: behavior.EntityKindExecutionRoot, ID: rootID},
			Execution:   connectedExecutionContext([]string{rootID}, nil),
			Arguments:   []string{targetName},
			EvidenceIDs: []string{evidenceID},
		})
		if targetID == "" {
			markDerivedGraphLimit(graph, "package-script-target-resolution")
			return false
		}
		graph.AddAnalysisSelection(behavior.AnalysisSelection{NodeID: content.NodeID, Reasons: []behavior.SelectionReason{behavior.SelectionReasonInvokedTarget}})
		execution := connectedExecutionContext([]string{rootID}, []string{targetID})
		targetContent = contentWithExecutionContext(targetContent, execution)
		AnalyzeShellLine(graph, targetContent, targetCommand, 0, execution, evidenceID)
		if graph.WorkLimitReached() {
			markDerivedGraphLimit(graph, "package-script-target-resolution")
			return false
		}
		if !resolvePackageScriptReferenceDepth(graph, content, scripts, targetName, targetCommand, rootID, visited, depth+1, work, workLimit) {
			return false
		}
	}
	if !complete {
		markDerivedWorkLimit(graph, "package-script-target-resolution", workLimit, "package script references")
		return false
	}
	return true
}

func ResolveVSCodeExtensionEntrypoints(graph *behavior.Graph, contents []artifact.Content) {
	resolveVSCodeExtensionEntrypoints(graph, contents, maxVSCodeTargetResolutionWork)
}

func resolveVSCodeExtensionEntrypoints(graph *behavior.Graph, contents []artifact.Content, workLimit int) {
	if graph.WorkLimitReached() {
		markDerivedGraphLimit(graph, "vscode-entrypoint-resolution")
		return
	}
	contentIndex := newLogicalContentIndex(contents)
	operationsByNode := operationIndicesBySubjectNode(graph.Operations)
	work := newDerivedWorkBudget(workLimit)
	for _, content := range contents {
		if graph.WorkLimitReached() {
			markDerivedGraphLimit(graph, "vscode-entrypoint-resolution")
			return
		}
		if content.RawFeaturesOnly || strings.ToLower(virtualBase(content.LogicalPath)) != "package.json" {
			continue
		}
		pkg, ok := decodePackageJSON(graph, content)
		if !ok {
			continue
		}
		if !isVSCodeExtensionPackage(pkg, content.LogicalPath) {
			continue
		}
		for _, target := range vscodeExtensionTargets(pkg) {
			if graph.WorkLimitReached() {
				markDerivedGraphLimit(graph, "vscode-entrypoint-resolution")
				return
			}
			if !work.take() {
				markDerivedWorkLimit(graph, "vscode-entrypoint-resolution", workLimit, "VS Code extension target relationships")
				return
			}
			evidenceID := graph.AddEvidence(behavior.Evidence{
				NodeID:   content.NodeID,
				ScopeID:  content.ScopeID,
				Logical:  content.LogicalPath,
				Physical: content.PhysicalPath,
				Method:   "vscode-extension-package",
				Kind:     "vscode-extension-entrypoint",
				Value:    target.field + ": " + target.path,
			})
			if evidenceID == "" {
				markDerivedGraphLimit(graph, "vscode-entrypoint-resolution")
				return
			}
			if graph.WorkLimitReached() {
				markDerivedGraphLimit(graph, "vscode-entrypoint-resolution")
				return
			}
			if graph.AddFeature(behavior.Feature{
				NodeID:  content.NodeID,
				ScopeID: content.ScopeID,
				Key:     "vscode.extension.entrypoint",
				Value:   target.path,
				Qualifiers: map[string]string{
					"field": target.field,
					"name":  pkg.Name,
				},
				EvidenceIDs: []string{evidenceID},
				Support:     behavior.SupportDirect,
			}) == "" {
				markDerivedGraphLimit(graph, "vscode-entrypoint-resolution")
				return
			}
			if graph.WorkLimitReached() {
				markDerivedGraphLimit(graph, "vscode-entrypoint-resolution")
				return
			}
			resolution := resolveVSCodeTarget(contentIndex, content.LogicalPath, target.path, target.field == "main")
			switch resolution.disposition {
			case vscodeTargetInvalid:
				addPartialCoverageOnce(graph, content.NodeID, "vscode-entrypoint-resolution", vscodeEntrypointUnsafeCoverage)
				continue
			case vscodeTargetUnsupported:
				addPartialCoverageOnce(graph, content.NodeID, "vscode-entrypoint-resolution", vscodeEntrypointDirectoryCoverage)
				continue
			case vscodeTargetAmbiguous:
				addPartialCoverageOnce(graph, content.NodeID, "vscode-entrypoint-resolution", vscodeEntrypointAmbiguousCoverage)
				continue
			case vscodeTargetMissing:
				detail := vscodeEntrypointMissingCoverage
				if resolution.extensionless && target.field == "main" {
					detail = vscodeEntrypointExtensionlessCoverage
				} else if resolution.extensionless && target.field == "browser" {
					detail = vscodeBrowserEntrypointExtensionlessCoverage
				}
				addPartialCoverageOnce(graph, content.NodeID, "vscode-entrypoint-resolution", detail)
				continue
			}
			targetContent := resolution.content
			resolutionEvidenceID := graph.AddEvidence(behavior.Evidence{
				NodeID:   targetContent.NodeID,
				ScopeID:  targetContent.ScopeID,
				Logical:  targetContent.LogicalPath,
				Physical: targetContent.PhysicalPath,
				Method:   "vscode-extension-package",
				Kind:     "resolved-vscode-extension-entrypoint",
				Value:    target.field + ": " + target.path + " -> " + targetContent.LogicalPath,
			})
			if resolutionEvidenceID == "" {
				markDerivedGraphLimit(graph, "vscode-entrypoint-resolution")
				return
			}
			evidenceIDs := []string{evidenceID, resolutionEvidenceID}
			if target.field == "browser" {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					"vscode-browser-runtime",
					"the browser entrypoint was resolved and retained as an invoked target, but VS Code web-extension runtime semantics were not modeled; no local execution root or operation connectivity was inferred",
				)
				targetID := graph.AddInvokedTarget(behavior.InvokedTarget{
					Kind:        "vscode-extension-browser",
					NodeID:      targetContent.NodeID,
					ScopeID:     targetContent.ScopeID,
					Source:      behavior.EntityRef{Kind: behavior.EntityKindArtifactNode, ID: content.NodeID},
					Execution:   unknownExecutionContext(),
					Arguments:   []string{targetContent.LogicalPath},
					EvidenceIDs: evidenceIDs,
				})
				if targetID == "" {
					markDerivedGraphLimit(graph, "vscode-entrypoint-resolution")
					return
				}
				graph.AddAnalysisSelection(behavior.AnalysisSelection{NodeID: targetContent.NodeID, Reasons: []behavior.SelectionReason{behavior.SelectionReasonInvokedTarget}})
				continue
			}
			if !executionRootAllowed(content) {
				continue
			}
			rootID := graph.AddExecutionRoot(behavior.ExecutionRoot{
				Kind:              "vscode-extension-" + target.field,
				DeclarationNodeID: content.NodeID,
				StartNodeID:       targetContent.NodeID,
				StartScopeID:      targetContent.ScopeID,
				Name:              vscodeExtensionName(pkg, targetContent),
				Arguments:         []string{targetContent.LogicalPath},
				EvidenceIDs:       evidenceIDs,
			})
			if rootID == "" {
				markDerivedGraphLimit(graph, "vscode-entrypoint-resolution")
				return
			}
			graph.AddAnalysisSelection(behavior.AnalysisSelection{NodeID: targetContent.NodeID, Reasons: []behavior.SelectionReason{behavior.SelectionReasonExecutionRoot}})
			if !promoteIndexedNodeOperations(
				graph,
				operationsByNode[targetContent.NodeID],
				targetContent.ScopeID,
				connectedExecutionContext([]string{rootID}, nil),
				&work,
				workLimit,
				"vscode-entrypoint-resolution",
				"VS Code extension operation promotions",
			) {
				return
			}
		}
	}
	retainVSCodeActivationEventFeaturesForContents(graph, contents)
}

func retainVSCodeActivationEventFeaturesForContents(graph *behavior.Graph, contents []artifact.Content) {
	work := newDerivedWorkBudget(maxVSCodeActivationEventWork)
	for _, content := range contents {
		if graph.WorkLimitReached() {
			return
		}
		if content.RawFeaturesOnly || strings.ToLower(virtualBase(content.LogicalPath)) != "package.json" {
			continue
		}
		pkg, ok := decodePackageJSON(graph, content)
		if !ok || !isVSCodeExtensionPackage(pkg, content.LogicalPath) {
			continue
		}
		if !retainVSCodeActivationEventFeatures(graph, content, pkg.ActivationEvents, &work) {
			return
		}
	}
}

func retainVSCodeActivationEventFeatures(graph *behavior.Graph, content artifact.Content, raw json.RawMessage, work *derivedWorkBudget) bool {
	events, coverageDetail := boundedVSCodeActivationEvents(raw)
	if coverageDetail != "" {
		addPartialCoverageOnce(graph, content.NodeID, "vscode-activation-events", coverageDetail)
	}
	for _, event := range events {
		if !work.take() {
			addPartialCoverageOnce(
				graph,
				"",
				"vscode-activation-events",
				fmt.Sprintf("activation-event work limit %d reached; remaining string entries were not retained", maxVSCodeActivationEventWork),
			)
			return false
		}
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:   content.NodeID,
			ScopeID:  content.ScopeID,
			Logical:  content.LogicalPath,
			Physical: content.PhysicalPath,
			Method:   "vscode-extension-package",
			Kind:     "vscode-extension-activation-event-declaration",
			Value:    "activationEvents: " + event,
		})
		if evidenceID == "" {
			markDerivedGraphLimit(graph, "vscode-activation-events")
			return false
		}
		if graph.AddFeature(behavior.Feature{
			NodeID:      content.NodeID,
			ScopeID:     content.ScopeID,
			Key:         "vscode.extension.activation_event",
			Value:       event,
			EvidenceIDs: []string{evidenceID},
			Support:     behavior.SupportDirect,
			Execution:   unknownExecutionContext(),
		}) == "" {
			markDerivedGraphLimit(graph, "vscode-activation-events")
			return false
		}
	}
	return true
}

func boundedVSCodeActivationEvents(raw json.RawMessage) ([]string, string) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, ""
	}
	if raw[0] != '[' {
		return nil, "activationEvents was not an array of strings; no declared activation-event metadata was retained"
	}
	var encoded []json.RawMessage
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, "activationEvents was not an array of strings; no declared activation-event metadata was retained"
	}

	limited := len(encoded) > maxVSCodeActivationEvents
	if limited {
		encoded = encoded[:maxVSCodeActivationEvents]
	}
	seen := make(map[string]bool, len(encoded))
	events := make([]string, 0, len(encoded))
	invalid := false
	oversized := false
	for _, candidate := range encoded {
		// A JSON string can use up to six encoded bytes for one escaped code
		// point. Reject larger representations before allocating their decoded
		// value; the post-decode byte check below is authoritative.
		if len(candidate) > 6*maxVSCodeActivationEventBytes+2 {
			oversized = true
			continue
		}
		var event string
		if err := json.Unmarshal(candidate, &event); err != nil || event == "" {
			invalid = true
			continue
		}
		if len(event) > maxVSCodeActivationEventBytes {
			oversized = true
			continue
		}
		if seen[event] {
			continue
		}
		seen[event] = true
		events = append(events, event)
	}
	sort.Strings(events)

	var details []string
	if invalid {
		details = append(details, "activationEvents contained non-string or empty entries; only bounded string entries were retained")
	}
	if oversized {
		details = append(details, fmt.Sprintf("activationEvents contained values longer than %d bytes; oversized declarations were not retained", maxVSCodeActivationEventBytes))
	}
	if limited {
		details = append(details, fmt.Sprintf("activationEvents entry limit %d reached; remaining declarations were not analyzed", maxVSCodeActivationEvents))
	}
	return events, strings.Join(details, "; ")
}

type vscodeTarget struct {
	field string
	path  string
}

type vscodeTargetDisposition uint8

const (
	vscodeTargetInvalid vscodeTargetDisposition = iota
	vscodeTargetUnsupported
	vscodeTargetMissing
	vscodeTargetAmbiguous
	vscodeTargetResolved
)

type vscodeTargetResolution struct {
	disposition   vscodeTargetDisposition
	content       artifact.Content
	extensionless bool
}

type logicalContentIndex struct {
	unique          map[string]artifact.Content
	ambiguous       map[string]bool
	foldedAmbiguous map[string]bool
	foldedLogical   map[string]string
}

func newLogicalContentIndex(contents []artifact.Content) logicalContentIndex {
	index := logicalContentIndex{
		unique:          make(map[string]artifact.Content, len(contents)),
		ambiguous:       map[string]bool{},
		foldedAmbiguous: map[string]bool{},
		foldedLogical:   make(map[string]string, len(contents)),
	}
	for _, content := range contents {
		logical := content.LogicalPath
		if content.RawFeaturesOnly || logical == "" || index.ambiguous[logical] {
			continue
		}
		if _, exists := index.unique[logical]; exists {
			delete(index.unique, logical)
			index.ambiguous[logical] = true
			continue
		}
		index.unique[logical] = content
		folded := strings.ToLower(logical)
		if prior, exists := index.foldedLogical[folded]; exists && prior != logical {
			index.foldedAmbiguous[folded] = true
		} else {
			index.foldedLogical[folded] = logical
		}
	}
	return index
}

const (
	vscodeEntrypointUnsafeCoverage               = "one or more VS Code extension entrypoint declarations exceeded the supported path bound or used unsafe path syntax; no target was associated"
	vscodeEntrypointDirectoryCoverage            = "one or more VS Code extension entrypoint declarations used directory-style resolution, which is not modeled; target semantics were not analyzed"
	vscodeEntrypointAmbiguousCoverage            = "one or more VS Code extension entrypoint paths matched multiple retained nodes; no target was associated"
	vscodeEntrypointMissingCoverage              = "one or more concrete VS Code extension entrypoint files were absent from the retained artifact graph; target semantics were not analyzed"
	vscodeEntrypointExtensionlessCoverage        = "one or more extensionless VS Code Node entrypoints did not resolve through the supported exact-file or .js lookup; target semantics were not analyzed"
	vscodeBrowserEntrypointExtensionlessCoverage = "one or more extensionless VS Code browser entrypoints did not resolve through the supported exact-file lookup; web-runtime module resolution was not modeled"
)

func resolveVSCodeTarget(index logicalContentIndex, manifestLogical, declared string, allowJSFallback bool) vscodeTargetResolution {
	candidates, disposition, extensionless := vscodeTargetLogicalCandidates(manifestLogical, declared, allowJSFallback)
	if disposition != vscodeTargetResolved {
		return vscodeTargetResolution{disposition: disposition, extensionless: extensionless}
	}
	for _, logical := range candidates {
		if index.ambiguous[logical] {
			return vscodeTargetResolution{disposition: vscodeTargetAmbiguous, extensionless: extensionless}
		}
		if content, exists := index.unique[logical]; exists {
			return vscodeTargetResolution{disposition: vscodeTargetResolved, content: content, extensionless: extensionless}
		}
	}
	return vscodeTargetResolution{disposition: vscodeTargetMissing, extensionless: extensionless}
}

func vscodeTargetLogicalCandidates(manifestLogical, declared string, allowJSFallback bool) ([]string, vscodeTargetDisposition, bool) {
	if len(declared) > artifact.MaxArchiveNameBytes {
		return nil, vscodeTargetInvalid, false
	}
	trimmed := declared
	if strings.HasSuffix(trimmed, "/") || strings.HasSuffix(trimmed, "/.") || strings.HasSuffix(trimmed, "/..") {
		return nil, vscodeTargetUnsupported, false
	}
	exact, ok := resolveSiblingLogical(manifestLogical, declared)
	if !ok {
		return nil, vscodeTargetInvalid, false
	}
	candidates := []string{exact}
	extensionless := filepath.Ext(filepath.Base(trimmed)) == ""
	if allowJSFallback && extensionless {
		candidates = append(candidates, exact+".js")
	}
	return candidates, vscodeTargetResolved, extensionless
}

func isVSCodeExtensionPackage(pkg packageJSON, logical string) bool {
	if packageJSONInDependencyTree(logical) {
		return false
	}
	if pkg.Engines != nil && strings.TrimSpace(pkg.Engines["vscode"]) != "" {
		return true
	}
	if isVSIXExtensionRootPackage(logical) {
		return true
	}
	return false
}

func packageJSONInDependencyTree(logical string) bool {
	lower := strings.ToLower(filepath.ToSlash(logical))
	return strings.Contains(lower, "/node_modules/") || strings.Contains(lower, "!node_modules/")
}

func isVSIXExtensionRootPackage(logical string) bool {
	lower := strings.ToLower(filepath.ToSlash(logical))
	return strings.Contains(lower, ".vsix!extension/package.json") ||
		strings.Contains(lower, ".vsix/extension/package.json")
}

func vscodeExtensionTargets(pkg packageJSON) []vscodeTarget {
	var targets []vscodeTarget
	if strings.TrimSpace(pkg.Main) != "" {
		targets = append(targets, vscodeTarget{field: "main", path: pkg.Main})
	}
	if browser := string(pkg.Browser); strings.TrimSpace(browser) != "" {
		targets = append(targets, vscodeTarget{field: "browser", path: browser})
	}
	return uniqueVSCodeTargets(targets)
}

func uniqueVSCodeTargets(targets []vscodeTarget) []vscodeTarget {
	seen := map[string]bool{}
	var out []vscodeTarget
	for _, target := range targets {
		key := target.field + "\x00" + target.path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, target)
	}
	return out
}

func vscodeExtensionName(pkg packageJSON, content artifact.Content) string {
	if strings.TrimSpace(pkg.Name) != "" {
		return strings.TrimSpace(pkg.Name)
	}
	return virtualBase(content.LogicalPath)
}

func ResolveScriptOperationTargets(graph *behavior.Graph, contents []artifact.Content, commandTargets commandTargetPolicy) {
	resolveScriptOperationTargets(graph, contents, commandTargets, maxScriptTargetResolutionWork)
}

type scriptTargetOperationState struct {
	indices []int
}

type scriptTargetQueueItem struct {
	pass  int
	index int
}

type scriptTargetQueue []scriptTargetQueueItem

func (q scriptTargetQueue) Len() int { return len(q) }
func (q scriptTargetQueue) Less(i, j int) bool {
	if q[i].pass != q[j].pass {
		return q[i].pass < q[j].pass
	}
	return q[i].index < q[j].index
}
func (q scriptTargetQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *scriptTargetQueue) Push(value any) {
	*q = append(*q, value.(scriptTargetQueueItem))
}
func (q *scriptTargetQueue) Pop() any {
	old := *q
	last := len(old) - 1
	value := old[last]
	*q = old[:last]
	return value
}

func resolveScriptOperationTargets(graph *behavior.Graph, contents []artifact.Content, commandTargets commandTargetPolicy, workLimit int) {
	if graph.WorkLimitReached() {
		markDerivedGraphLimit(graph, "script-target-resolution")
		return
	}
	logicalIndex := newLogicalContentIndex(contents)
	byLogical := logicalIndex.unique
	byNode := map[string]artifact.Content{}
	// Disk artifacts have root-relative logical names. An absolute invocation
	// may match an exact retained physical file, but an archive's physical path
	// names its carrier and must never be used as a member's runtime location.
	var diskContents []artifact.Content
	for _, content := range contents {
		if !content.RawFeaturesOnly {
			byNode[content.NodeID] = content
		}
		if !strings.Contains(content.LogicalPath, "!") && filepath.IsAbs(content.PhysicalPath) {
			alias := content
			alias.LogicalPath = content.PhysicalPath
			diskContents = append(diskContents, alias)
		}
	}
	diskIndex := newLogicalContentIndex(diskContents)
	for path, alias := range diskIndex.unique {
		byLogical[path] = byNode[alias.NodeID]
	}
	runtimeTargets := map[scriptRuntimeTargetKey][]artifact.Content{}
	for _, content := range contents {
		if content.RawFeaturesOnly {
			continue
		}
		byNode[content.NodeID] = content
		if retainedScriptTarget(content) && filepath.IsAbs(content.PackageInstallPath) {
			if key, ok := newScriptRuntimeTargetKey(content.LogicalPath, content.PackageInstallPath); ok {
				runtimeTargets[key] = append(runtimeTargets[key], content)
			}
		}
	}

	states := make(map[string]*scriptTargetOperationState)
	queue := make(scriptTargetQueue, 0, len(graph.Operations))
	pending := make([]bool, len(graph.Operations))
	for i := range graph.Operations {
		operation := graph.Operations[i]
		state := states[operation.SubjectNodeID]
		if state == nil {
			state = &scriptTargetOperationState{}
			states[operation.SubjectNodeID] = state
		}
		state.indices = append(state.indices, i)
		if scriptTargetSourceOperation(operation) && operation.Execution.Connectivity == behavior.ConnectivityConnected {
			heap.Push(&queue, scriptTargetQueueItem{index: i})
			pending[i] = true
		}
	}
	resolvedTargetContexts := make(map[scriptTargetContextKey]string)
	for _, target := range graph.InvokedTargets {
		// Package lifecycle resolution runs first so an exact local script is
		// analyzed even when command parsing is incomplete. When parsing also
		// yields an invocation operation, relate that operation to the existing
		// target instead of presenting the same node/root context twice.
		if (target.Kind == "script-target" || target.Kind == "lifecycle-target") && target.NodeID != "" {
			if key, ok := newScriptTargetContextKey(target.NodeID, target.Execution); ok {
				resolvedTargetContexts[key] = target.ID
			}
		}
	}

	work := newDerivedWorkBudget(workLimit)
	resolver := scriptTargetResolver{
		graph:                  graph,
		byNode:                 byNode,
		byLogical:              byLogical,
		runtimeTargets:         runtimeTargets,
		resolvedTargetContexts: resolvedTargetContexts,
		relationKeys:           existingRelationKeys(graph.Relations),
		work:                   &work,
		workLimit:              workLimit,
		commandTargets:         commandTargets,
		packageTargets:         packageScopeTargetPolicies(graph, byNode),
	}
	for queue.Len() > 0 {
		if graph.WorkLimitReached() {
			markDerivedGraphLimit(graph, "script-target-resolution")
			return
		}
		current := heap.Pop(&queue).(scriptTargetQueueItem)
		pending[current.index] = false
		operation := graph.Operations[current.index]
		if !resolver.resolve(operation, func(targetContent artifact.Content, targetID string) bool {
			state := states[targetContent.NodeID]
			if state == nil {
				return true
			}
			promoted := operation.Execution
			promoted.InvokedTargetIDs = append(append([]string(nil), promoted.InvokedTargetIDs...), targetID)
			promoted = connectedExecutionContext(promoted.ExecutionRootIDs, promoted.InvokedTargetIDs)
			for _, operationIndex := range state.indices {
				if !work.take() {
					markDerivedWorkLimit(graph, "script-target-resolution", workLimit, "script target relationships")
					return false
				}
				targetOperation := &graph.Operations[operationIndex]
				if targetOperation.SourceFunction != "" || targetOperation.ScopeID != targetContent.ScopeID {
					continue
				}
				operationChanged := mergeOperationExecution(targetOperation, promoted)
				if operationChanged && scriptTargetSourceOperation(*targetOperation) && !pending[operationIndex] {
					pass := current.pass
					if operationIndex <= current.index {
						pass++
					}
					heap.Push(&queue, scriptTargetQueueItem{pass: pass, index: operationIndex})
					pending[operationIndex] = true
				}
			}
			return true
		}) {
			return
		}
	}
	for _, operation := range graph.Operations {
		if graph.WorkLimitReached() {
			markDerivedGraphLimit(graph, "script-target-resolution")
			return
		}
		if !scriptTargetSourceOperation(operation) || operation.Execution.Connectivity == behavior.ConnectivityConnected {
			continue
		}
		if !resolver.resolve(operation, nil) {
			return
		}
	}
}

type scriptTargetResolver struct {
	graph                  *behavior.Graph
	byNode                 map[string]artifact.Content
	byLogical              map[string]artifact.Content
	runtimeTargets         map[scriptRuntimeTargetKey][]artifact.Content
	resolvedTargetContexts map[scriptTargetContextKey]string
	relationKeys           map[string]bool
	work                   *derivedWorkBudget
	workLimit              int
	commandTargets         commandTargetPolicy
	packageTargets         map[string]map[string]bool
}

func packageScopeTargetPolicies(graph *behavior.Graph, byNode map[string]artifact.Content) map[string]map[string]bool {
	policies := map[string]map[string]bool{}
	packages := map[string]packageJSON{}
	cached := map[packageScriptRootKey]map[string]bool{}
	work := newDerivedWorkBudget(maxScriptTargetResolutionWork)
	bytesRemaining := 16 << 20
	for _, scope := range graph.Scopes {
		if scope.Kind != "package-script" {
			continue
		}
		content, ok := byNode[scope.NodeID]
		if !ok || virtualBase(content.LogicalPath) != "package.json" {
			continue
		}
		key := packageScriptRootKey{nodeID: scope.NodeID, name: scope.Name}
		if allowed, found := cached[key]; found {
			policies[scope.ID] = allowed
			continue
		}
		if !work.take() {
			markDerivedWorkLimit(graph, "script-target-resolution", maxScriptTargetResolutionWork, "package command target policies")
			break
		}
		pkg, found := packages[scope.NodeID]
		if !found {
			if len(content.Data) > maxStructuredDocumentBytes || preflightPackageJSON(content.Data) != nil {
				continue
			}
			var err error
			pkg, err = decodePackageJSONObject(content.Data)
			if err != nil {
				continue
			}
			packages[scope.NodeID] = pkg
		}
		command := pkg.Scripts[scope.Name]
		if len(command) > bytesRemaining {
			addPartialCoverageOnce(graph, scope.NodeID, "script-target-resolution", "package command target-policy byte budget exhausted; remaining command targets were not associated")
			break
		}
		bytesRemaining -= len(command)
		targets, complete := localScriptTargetsLimited(command, work.remaining)
		work.remaining -= len(targets)
		if !complete {
			markDerivedWorkLimit(graph, "script-target-resolution", maxScriptTargetResolutionWork, "package command target policies")
		}
		allowed := map[string]bool{}
		for _, target := range targets {
			allowed[target] = true
		}
		policies[scope.ID] = allowed
		cached[key] = allowed
	}
	return policies
}

func (resolver *scriptTargetResolver) resolve(operation behavior.ModeledOperation, onTarget func(artifact.Content, string) bool) bool {
	source, ok := resolver.byNode[operation.SubjectNodeID]
	if !ok {
		return true
	}
	allowedHostTargets, hostCommand := resolver.commandTargets[operation.ID]
	if _, _, projectConfig := projectConfigRoot(source.LogicalPath); projectConfig && !hostCommand {
		// Project-host adapters own their command-resolution bases. Do not let a
		// generic sibling resolver reinterpret a command that the adapter did not
		// explicitly authorize for project-relative target binding.
		return true
	}
	targets, complete := operationScriptTargetsLimited(operation, resolver.work.remaining)
	for _, target := range targets {
		if resolver.graph.WorkLimitReached() {
			markDerivedGraphLimit(resolver.graph, "script-target-resolution")
			return false
		}
		if !resolver.work.take() {
			markDerivedWorkLimit(resolver.graph, "script-target-resolution", resolver.workLimit, "script target relationships")
			return false
		}
		if hostCommand {
			logical, ok := resolveCommandTargetLogical(source, target)
			if !ok || !allowedHostTargets[logical] {
				continue
			}
		}
		if !hostCommand && !filepath.IsAbs(target) {
			allowed := resolver.packageTargets[operation.ScopeID]
			if !allowed[target] {
				addPartialCoverageOnce(resolver.graph, source.NodeID, "script-target-resolution", "a relative invocation target has no established working-directory mapping; no retained sibling was selected")
				continue
			}
		}
		targetContent, ok := resolveRetainedScriptTarget(source, target, resolver.byLogical, resolver.runtimeTargets)
		if !ok || targetContent.NodeID == source.NodeID {
			if _, area, projectConfig := projectConfigRoot(source.LogicalPath); projectConfig {
				addPartialCoverageOnce(
					resolver.graph,
					source.NodeID,
					area,
					"one or more exact project-relative command targets were absent or ambiguous in the retained artifact graph; target semantics were not associated",
				)
			}
			continue
		}
		// The explicit invocation remains useful when the retained target has
		// no decoded operations or the source has no proven execution root.
		targetKey, ok := newScriptTargetContextKey(targetContent.NodeID, operation.Execution)
		if !ok {
			continue
		}
		targetID := resolver.resolvedTargetContexts[targetKey]
		if targetID == "" {
			targetID = addScriptInvokedTarget(resolver.graph, targetContent, operation, target)
			if targetID == "" {
				markDerivedGraphLimit(resolver.graph, "script-target-resolution")
				return false
			}
			resolver.resolvedTargetContexts[targetKey] = targetID
			resolver.graph.AddAnalysisSelection(behavior.AnalysisSelection{NodeID: targetContent.NodeID, Reasons: []behavior.SelectionReason{behavior.SelectionReasonInvokedTarget}})
		}
		if !addScriptInvocationRelation(resolver.graph, resolver.relationKeys, operation, targetID) {
			markDerivedGraphLimit(resolver.graph, "script-target-resolution")
			return false
		}
		if onTarget != nil && !onTarget(targetContent, targetID) {
			return false
		}
	}
	if !complete {
		markDerivedWorkLimit(resolver.graph, "script-target-resolution", resolver.workLimit, "script target relationships")
		return false
	}
	return true
}

func resolveCommandTargetLogical(source artifact.Content, target string) (string, bool) {
	if _, _, projectConfig := projectConfigRoot(source.LogicalPath); projectConfig {
		return resolveProjectConfigLogical(source.LogicalPath, target)
	}
	return resolveSiblingLogical(source.LogicalPath, target)
}

func scriptTargetSourceOperation(operation behavior.ModeledOperation) bool {
	return operation.Kind == behavior.OperationInterpreterInvoke || operation.Kind == behavior.OperationProcessExecute
}

func operationInvocationText(operation behavior.ModeledOperation) string {
	executable, _ := operation.FirstBinding(behavior.ResourceRoleExecutable)
	arguments, _ := operation.FirstBinding(behavior.ResourceRoleArguments)
	return strings.TrimSpace(strings.TrimSpace(executable.Resource.Value) + " " + strings.TrimSpace(arguments.Resource.Value))
}

func operationScriptTargetsLimited(operation behavior.ModeledOperation, limit int) ([]string, bool) {
	if input, ok := operation.FirstBinding(behavior.ResourceRoleLocalInput); ok && input.Resource.Value != "" {
		if limit <= 0 {
			return nil, false
		}
		return []string{input.Resource.Value}, true
	}
	executable, ok := operation.FirstBinding(behavior.ResourceRoleExecutable)
	if !ok {
		return nil, true
	}
	exe := executable.Resource.Value
	arguments, _ := operation.FirstBinding(behavior.ResourceRoleArguments)
	var args []string
	switch operation.Qualifiers["argument_encoding"] {
	case "shell-quoted":
		var err error
		args, err = CommandFields(arguments.Resource.Value)
		if err != nil {
			return nil, !shellFieldLimitReached(err)
		}
	case "json-array":
		if len(arguments.Resource.Value) > maxTextAnalysisLineBytes {
			return nil, false
		}
		if json.Unmarshal([]byte(arguments.Resource.Value), &args) != nil {
			return nil, true
		}
		if len(args) > maxInterpreterArgumentTokens {
			return nil, false
		}
	default:
		// A file binding is one executable path, never a command to tokenize.
		if operation.Kind == behavior.OperationProcessExecute && (looksLocalScript(exe) || filepath.IsAbs(exe)) {
			if limit <= 0 {
				return nil, false
			}
			return []string{exe}, true
		}
		return nil, true
	}
	var targets []string
	switch tool := filepath.Base(exe); tool {
	case "sh", "bash", "zsh", "python", "python3", "node", "deno", "osascript":
		var limited bool
		targets, limited = InterpreterScriptTargetsLimited(tool, args)
		if limited {
			return nil, false
		}
	default:
		if looksLocalScript(exe) || filepath.IsAbs(exe) {
			targets = []string{exe}
		}
	}
	if len(targets) > limit {
		return targets[:limit], false
	}
	return targets, true
}

type scriptTargetContextKey struct {
	nodeID    string
	execution behavior.ExecutionKey
}

func newScriptTargetContextKey(nodeID string, execution behavior.ExecutionContext) (scriptTargetContextKey, bool) {
	key, ok := executionContextKey(execution)
	return scriptTargetContextKey{nodeID: nodeID, execution: key}, ok && nodeID != ""
}

func addScriptInvokedTarget(graph *behavior.Graph, content artifact.Content, operation behavior.ModeledOperation, target string) string {
	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID:   content.NodeID,
		Logical:  content.LogicalPath,
		Physical: content.PhysicalPath,
		Method:   "script-target",
		Kind:     "resolved-script-target",
		Value:    operationInvocationText(operation) + " -> " + target,
	})
	if evidenceID == "" {
		return ""
	}
	invokedTarget := behavior.InvokedTarget{
		Kind:        "script-target",
		NodeID:      content.NodeID,
		ScopeID:     content.ScopeID,
		Source:      executionSourceForOperation(operation),
		Execution:   operation.Execution,
		Arguments:   []string{content.LogicalPath},
		EvidenceIDs: []string{evidenceID},
	}
	if executable, ok := operation.FirstBinding(behavior.ResourceRoleExecutable); ok && filepath.Base(executable.Resource.Value) == "osascript" {
		invokedTarget.Interpreter = executable.Resource.Value
	}
	return graph.AddInvokedTarget(invokedTarget)
}

func addScriptInvocationRelation(graph *behavior.Graph, relationKeys map[string]bool, operation behavior.ModeledOperation, targetID string) bool {
	if operation.ID == "" || targetID == "" {
		return false
	}
	targetEvidence := []string(nil)
	for _, target := range graph.InvokedTargets {
		if target.ID == targetID {
			targetEvidence = target.EvidenceIDs
			break
		}
	}
	evidenceIDs := append(append([]string(nil), operation.EvidenceIDs...), targetEvidence...)
	return addOperationRelationOnce(graph, relationKeys, behavior.OperationRelation{
		Kind:         behavior.RelationInvokes,
		From:         behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, operation.ID),
		To:           behavior.IDRelationEndpoint(behavior.RelationEndpointInvokedTarget, targetID),
		EvidenceIDs:  evidenceIDs,
		Support:      operation.Support,
		Execution:    operation.Execution,
		Architecture: operation.Architecture,
	})
}

type scriptRuntimeTargetKey struct {
	container string
	base      string // exact installed path, not a basename
}

func newScriptRuntimeTargetKey(logical, base string) (scriptRuntimeTargetKey, bool) {
	logical = filepath.ToSlash(logical)
	boundary := strings.LastIndexByte(logical, '!')
	if boundary < 0 || base == "" {
		return scriptRuntimeTargetKey{}, false
	}
	return scriptRuntimeTargetKey{container: logical[:boundary], base: base}, true
}

func retainedScriptTarget(content artifact.Content) bool {
	return content.Kind == "script" || content.Kind == "compiled-applescript" || content.SemanticLanguage != ""
}

func resolveRetainedScriptTarget(source artifact.Content, target string, byLogical map[string]artifact.Content, runtimeTargets map[scriptRuntimeTargetKey][]artifact.Content) (artifact.Content, bool) {
	if _, _, projectConfig := projectConfigRoot(source.LogicalPath); projectConfig {
		logical, ok := resolveProjectConfigLogical(source.LogicalPath, target)
		if !ok {
			return artifact.Content{}, false
		}
		content, found := byLogical[logical]
		return content, found
	}
	if logical, ok := resolveSiblingLogical(source.LogicalPath, target); ok {
		content, found := byLogical[logical]
		return content, found
	}
	if !filepath.IsAbs(target) {
		return artifact.Content{}, false
	}
	if content, found := byLogical[target]; found {
		return content, true
	}
	if source.PackageInstallPath == "" {
		return artifact.Content{}, false
	}
	key, ok := newScriptRuntimeTargetKey(source.LogicalPath, target)
	if !ok {
		return artifact.Content{}, false
	}
	candidates := runtimeTargets[key]
	if len(candidates) != 1 {
		return artifact.Content{}, false
	}
	return candidates[0], true
}

func isStaticLaunchdScriptTarget(value string) bool {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	if value == "" || strings.Contains(value, "!") || strings.Contains(value, "://") || strings.ContainsAny(value, "$`*?[]{}\x00\r\n") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(value))
	lower := strings.ToLower(clean)
	for _, prefix := range []string{
		"~/library/launchagents/",
		"~/library/launchdaemons/",
		"/library/launchagents/",
		"/library/launchdaemons/",
		"/system/library/launchagents/",
		"/system/library/launchdaemons/",
	} {
		if strings.HasPrefix(lower, prefix) && filepath.Base(clean) != "." && filepath.Base(clean) != ".." {
			return true
		}
	}
	return false
}

func localScriptTargets(command string) []string {
	out, _ := localScriptTargetsLimited(command, int(^uint(0)>>1))
	return out
}

// npm establishes the package root as cwd, but shell state can invalidate that
// base. This deliberately closed command-list grammar does not interpret cd,
// sourced code, aliases, grouping, substitutions or directory-changing wrappers.
func packageCommandBaseIsStable(command string) bool {
	if strings.ContainsAny(command, "\r\n") {
		return false
	}
	return visitCommands(command, func(part string) bool {
		fields, simple := projectCommandFields(projectCommandPlan{command: part})
		if !simple || len(fields) == 0 {
			return false
		}
		for _, field := range fields {
			if field == "-C" || field == "--chdir" || field == "-D" || strings.HasPrefix(field, "--chdir=") {
				return false
			}
		}
		fields = normalizeCommandFields(fields)
		if len(fields) == 0 {
			return false
		}
		switch filepath.Base(fields[0]) {
		case "cd", "pushd", "popd", ".", "source", "eval", "alias", "unalias", "function":
			return false
		case "npm", "pnpm", "bun", "yarn":
			return packageScriptReference(fields) != ""
		}
		return true
	})
}

func localScriptTargetsLimited(command string, limit int) ([]string, bool) {
	if !packageCommandBaseIsStable(command) {
		return nil, true
	}
	seen := map[string]bool{}
	var out []string
	complete := visitCommands(command, func(part string) bool {
		fields, err := shellCommandFields(part)
		if err != nil || len(fields) == 0 {
			return true
		}
		fields = normalizeCommandFields(fields)
		if len(fields) == 0 {
			return true
		}
		tool := filepath.Base(fields[0])
		var candidates []string
		candidateIsLocal := looksLocalScript
		switch tool {
		case "sh", "bash", "zsh", "python", "python3", "node", "deno", "osascript":
			candidates = InterpreterScriptTargets(tool, fields[1:])
			if tool == "osascript" {
				// Compiled AppleScript is frequently disguised behind non-script
				// suffixes. The interpreter syntax establishes the role here, so
				// require a static relative path without requiring a familiar
				// source-script extension.
				candidateIsLocal = func(candidate string) bool {
					return isStaticRelativeTarget(candidate) || isStaticLaunchdScriptTarget(candidate)
				}
			}
		default:
			if looksLocalScript(fields[0]) {
				candidates = []string{fields[0]}
			}
		}
		for _, candidate := range candidates {
			if !candidateIsLocal(candidate) || seen[candidate] {
				continue
			}
			if len(out) >= limit {
				return false
			}
			seen[candidate] = true
			out = append(out, candidate)
		}
		return true
	})
	sort.Strings(out)
	return out, complete
}

func packageScriptReferences(command string) []string {
	out, _ := packageScriptReferencesLimited(command, int(^uint(0)>>1))
	return out
}

func packageScriptReferencesLimited(command string, limit int) ([]string, bool) {
	if !packageCommandBaseIsStable(command) {
		return nil, true
	}
	seen := map[string]bool{}
	var out []string
	complete := visitCommands(command, func(part string) bool {
		fields, err := shellCommandFields(part)
		if err != nil || len(fields) == 0 {
			return true
		}
		fields = normalizeCommandFields(fields)
		if len(fields) == 0 {
			return true
		}
		name := packageScriptReference(fields)
		if name == "" || seen[name] {
			return true
		}
		if len(out) >= limit {
			return false
		}
		seen[name] = true
		out = append(out, name)
		return true
	})
	sort.Strings(out)
	return out, complete
}

func packageScriptReference(fields []string) string {
	tool := filepath.Base(fields[0])
	switch tool {
	case "npm":
		return npmRunScriptName(fields[1:])
	case "pnpm", "bun", "yarn":
		return packageRunScriptName(fields[1:])
	default:
		return ""
	}
}

func npmRunScriptName(args []string) string {
	return exactPackageRunScriptName(args, true)
}

func packageRunScriptName(args []string) string {
	return exactPackageRunScriptName(args, false)
}

func exactPackageRunScriptName(args []string, npm bool) string {
	var positional []string
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if arg == "--silent" || arg == "-s" || (npm && arg == "--if-present") {
			continue
		}
		// Unknown options can select another prefix, workspace, shell or config.
		// They must be checked even after the script name (npm accepts both).
		if strings.HasPrefix(arg, "-") {
			return ""
		}
		positional = append(positional, arg)
	}
	if len(positional) < 2 || !(positional[0] == "run" || npm && positional[0] == "run-script") || !validPackageScriptName(positional[1]) {
		return ""
	}
	return positional[1]
}

func validPackageScriptName(name string) bool {
	if name == "" || strings.HasPrefix(name, "-") || strings.Contains(name, "$") {
		return false
	}
	return !strings.ContainsAny(name, `/\`)
}

func looksLocalScript(value string) bool {
	original := value
	clean, ok := cleanStaticRelativeTarget(value)
	if !ok {
		return false
	}
	ext := strings.ToLower(filepath.Ext(clean))
	if strings.HasPrefix(original, "./") || strings.Contains(clean, "/") {
		return true
	}
	switch ext {
	case ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".py", ".command":
		return true
	default:
		return false
	}
}

func isStaticRelativeTarget(value string) bool {
	_, ok := cleanStaticRelativeTarget(value)
	return ok
}

// cleanStaticRelativeTarget accepts only a literal path that can be resolved
// inside the current virtual container. In particular, runtime expansion and
// Maratus's virtual-container separator are not treated as filesystem syntax.
func cleanStaticRelativeTarget(value string) (string, bool) {
	if value == "" || value == "-" || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "~") ||
		filepath.IsAbs(value) || strings.Contains(value, "://") || strings.Contains(value, "!") ||
		strings.ContainsAny(value, "$`*?[]{}\x00\r\n") {
		return "", false
	}
	clean := filepath.ToSlash(filepath.Clean(value))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", false
	}
	return strings.TrimPrefix(clean, "./"), true
}

func resolveSiblingLogical(parentLogical, target string) (string, bool) {
	clean, ok := cleanStaticRelativeTarget(target)
	if !ok {
		return "", false
	}
	parentLogical = filepath.ToSlash(parentLogical)
	// `!` is Maratus's virtual container boundary. filepath.Dir does not know
	// that outer.zip!package.json and outer.zip!payload.js are siblings, so
	// preserve a final boundary that appears after the final slash.
	if boundary := strings.LastIndexByte(parentLogical, '!'); boundary > strings.LastIndexByte(parentLogical, '/') {
		return parentLogical[:boundary+1] + clean, true
	}
	base := filepath.ToSlash(filepath.Dir(parentLogical))
	if base == "." {
		return clean, true
	}
	return filepath.ToSlash(base + "/" + clean), true
}

func operationIndicesBySubjectNode(operations []behavior.ModeledOperation) map[string][]int {
	out := make(map[string][]int)
	for i := range operations {
		out[operations[i].SubjectNodeID] = append(out[operations[i].SubjectNodeID], i)
	}
	return out
}

func promoteIndexedNodeOperations(
	graph *behavior.Graph,
	indices []int,
	startScopeID string,
	execution behavior.ExecutionContext,
	work *derivedWorkBudget,
	workLimit int,
	coverageScope string,
	workUnit string,
) bool {
	if execution.Connectivity != behavior.ConnectivityConnected {
		return false
	}
	for _, index := range indices {
		if graph.WorkLimitReached() {
			markDerivedGraphLimit(graph, coverageScope)
			return false
		}
		if !work.take() {
			markDerivedWorkLimit(graph, coverageScope, workLimit, workUnit)
			return false
		}
		operation := &graph.Operations[index]
		if operation.SourceFunction != "" || operation.ScopeID != startScopeID {
			// Resolving a file as an entrypoint proves its module/start scope,
			// not every function or nested scope recovered from the same node.
			// Supported direct script calls are promoted separately after the
			// final root/target ownership sets have been recomputed.
			continue
		}
		mergeOperationExecution(operation, execution)
	}
	return true
}

func promoteNodeOperations(graph *behavior.Graph, nodeID string, execution behavior.ExecutionContext) bool {
	if execution.Connectivity != behavior.ConnectivityConnected {
		return false
	}
	changed := false
	for i := range graph.Operations {
		if graph.Operations[i].SubjectNodeID == nodeID && mergeOperationExecution(&graph.Operations[i], execution) {
			changed = true
		}
	}
	return changed
}
