package extract

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	nodePackageEntryAnalysisArea      = "node-package-entry-resolution"
	nodePackageModuleAnalysisArea     = "node-package-module-resolution"
	nodePackageRootExecutionKind      = "node-package-root-load"
	nodePackageEntryProfile           = "node-24.16.0-package-root-v1"
	maxNodePackageEntryCandidates     = 32
	maxNodePackageEntryPathSegments   = 128
	maxNodePackageEntryTargetBytes    = 4 << 10
	maxNodePackageRootNameBytes       = 214
	maxNodePackageEntryResolutionWork = 2 * behavior.DefaultItemLimit
)

type nodePackageEntryDisposition uint8

const (
	nodePackageEntryNone nodePackageEntryDisposition = iota
	nodePackageEntryResolved
	nodePackageEntryPartial
)

type nodePackageEntryPlan struct {
	manifest          artifact.Content
	name              string
	field             string
	declared          string
	target            artifact.Content
	disposition       nodePackageEntryDisposition
	reason            string
	attributionReason string
}

type nodePackageEntryPlanSet struct {
	plans                 []nodePackageEntryPlan
	lifecycleDeclarations map[string]bool
	globalReason          string
}

type nodePackageEntryTopology struct {
	known                   bool
	present                 map[string]bool
	excluded                map[string]bool
	incomplete              map[string]bool
	rootKind                map[string]string
	directDirectoryManifest map[string]bool
	manifestPaths           map[string]bool
}

// planNodePackageEntries implements one deliberately small Node package-root
// selection profile. It is side-effect free so Run can use the exact same
// result both to prioritize a generated entry file before behavior extraction
// and to emit its evidence-backed execution root afterwards.
func planNodePackageEntries(contents []artifact.Content) nodePackageEntryPlanSet {
	return planNodePackageEntriesWithTopology(contents, nodePackageEntryTopology{})
}

func planNodePackageEntriesWithArtifacts(contents []artifact.Content, artifacts artifact.Graph) nodePackageEntryPlanSet {
	return planNodePackageEntriesWithTopology(contents, buildNodePackageEntryTopology(artifacts))
}

func planNodePackageEntriesWithTopology(contents []artifact.Content, topology nodePackageEntryTopology) nodePackageEntryPlanSet {
	ordered := append([]artifact.Content(nil), contents...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].LogicalPath != ordered[j].LogicalPath {
			return ordered[i].LogicalPath < ordered[j].LogicalPath
		}
		return ordered[i].NodeID < ordered[j].NodeID
	})

	index := newLogicalContentIndex(contents)
	manifestPaths := make(map[string]bool, len(topology.manifestPaths))
	for logical := range topology.manifestPaths {
		manifestPaths[logical] = true
	}
	for _, content := range contents {
		if strings.EqualFold(virtualBase(content.LogicalPath), "package.json") {
			manifestPaths[normalizedNodePackageLogical(content.LogicalPath)] = true
		}
	}

	set := nodePackageEntryPlanSet{lifecycleDeclarations: map[string]bool{}}
	boundaries := 0
	for _, content := range ordered {
		if !nodePackageRootManifestEligible(content, topology) {
			continue
		}
		boundaries++
		if boundaries > maxNodePackageEntryCandidates {
			set.plans = nil
			set.globalReason = fmt.Sprintf("package-root candidate limit %d exceeded; no Node package entry was selected", maxNodePackageEntryCandidates)
			return set
		}
		if len(content.Data) > maxStructuredDocumentBytes || preflightPackageJSON(content.Data) != nil {
			// The ordinary package decoder records the precise malformed/size
			// coverage. Do not produce a second, less useful resolver diagnosis.
			continue
		}
		pkg, err := decodePackageJSONObject(content.Data)
		if err != nil {
			continue
		}
		if isVSCodeExtensionPackage(pkg, content.LogicalPath) {
			boundaries--
			continue
		}
		if nodePackageHasLifecycleDeclaration(pkg) {
			set.lifecycleDeclarations[content.NodeID] = true
		}
		plan := selectNodePackageEntry(content, pkg, index, manifestPaths, topology)
		if plan.disposition == nodePackageEntryNone {
			continue
		}
		set.plans = append(set.plans, plan)
	}

	// An inspection of a project tree or collection can contain several
	// independently loadable packages. Without a retained external request or
	// package boundary, choosing one would invent root ownership. v1 therefore
	// accepts one unambiguous package candidate per inspection only.
	if boundaries > 1 {
		set.plans = nil
		set.globalReason = "multiple eligible package-root declarations were retained; the bounded profile cannot determine a single externally loadable package root"
	}
	return set
}

func nodePackageRootManifestEligible(content artifact.Content, topology nodePackageEntryTopology) bool {
	if content.RawFeaturesOnly || !executionRootAllowed(content) ||
		content.Kind != "manifest" || content.NodeID == "" ||
		!strings.EqualFold(virtualBase(content.LogicalPath), "package.json") ||
		!behaviorSourceRoleAllowed(content.Role, false) || packageJSONInDependencyTree(content.LogicalPath) {
		return false
	}
	if content.Role == "packaged-content" {
		return false
	}
	if topology.known {
		if !topology.present[content.NodeID] || topology.excluded[content.NodeID] {
			return false
		}
		// A directory input names its package boundary directly. Restrict that
		// mode to package.json immediately below the inspected root so a partial
		// sibling subtree cannot create an ambiguous implicit package choice.
		if topology.rootKind[content.NodeID] == "directory" {
			return topology.directDirectoryManifest[content.NodeID]
		}
		return true
	}
	// Isolated extractor tests have no artifact ancestry. Production selection
	// uses the structural topology above; this conservative fallback prevents
	// obvious facade/package paths from becoming roots in standalone callers.
	lower := "/" + strings.Trim(strings.ToLower(normalizedNodePackageLogical(content.LogicalPath)), "/") + "/"
	for _, marker := range []string{".app/", ".vsix/", ".asar/", ".pkg/", "/carchive/"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

func buildNodePackageEntryTopology(graph artifact.Graph) nodePackageEntryTopology {
	topology := nodePackageEntryTopology{
		known:                   true,
		present:                 make(map[string]bool, len(graph.Nodes)),
		excluded:                make(map[string]bool, len(graph.Nodes)),
		incomplete:              make(map[string]bool, len(graph.Nodes)),
		rootKind:                make(map[string]string, len(graph.Nodes)),
		directDirectoryManifest: make(map[string]bool),
		manifestPaths:           make(map[string]bool),
	}
	byID := make(map[string]artifact.Node, len(graph.Nodes))
	for _, node := range graph.Nodes {
		byID[node.ID] = node
		topology.present[node.ID] = true
		if strings.EqualFold(virtualBase(node.LogicalPath), "package.json") {
			topology.manifestPaths[normalizedNodePackageLogical(node.LogicalPath)] = true
		}
	}
	rootByNode := make(map[string]string, len(graph.Nodes))
	for _, start := range graph.Nodes {
		seen := map[string]bool{}
		current := start
		for {
			if seen[current.ID] {
				topology.excluded[start.ID] = true
				break
			}
			seen[current.ID] = true
			if current.ParentID == "" {
				rootByNode[start.ID] = current.ID
				topology.rootKind[start.ID] = current.Kind
				if current.Kind == "directory" && start.ParentID == current.ID && strings.EqualFold(virtualBase(start.LogicalPath), "package.json") {
					topology.directDirectoryManifest[start.ID] = true
				}
				if !nodePackageEntryAllowedInspectionRoot(current) || strings.TrimSpace(current.PackagingTechnology) != "" {
					topology.excluded[start.ID] = true
				}
				if current.Kind != "directory" && nodePackageEntryInventoryIncomplete(current) {
					topology.incomplete[start.ID] = true
				}
				break
			}
			if nodePackageEntryForbiddenCarrier(current) {
				topology.excluded[start.ID] = true
				break
			}
			if nodePackageEntryInventoryIncomplete(current) {
				topology.incomplete[start.ID] = true
			}
			parent, ok := byID[current.ParentID]
			if !ok {
				topology.excluded[start.ID] = true
				break
			}
			current = parent
		}
	}
	// ZIP/TAR/GZIP mode must discover every possible package boundary before it can
	// choose the only one. Any incomplete retained descendant invalidates that
	// root-wide uniqueness proof, even when it is a sibling of the candidate.
	incompleteRoots := map[string]bool{}
	for _, node := range graph.Nodes {
		if nodePackageEntryInventoryIncomplete(node) {
			incompleteRoots[rootByNode[node.ID]] = true
		}
	}
	for nodeID, rootID := range rootByNode {
		if incompleteRoots[rootID] && (topology.rootKind[nodeID] == "zip" || topology.rootKind[nodeID] == "tar" || topology.rootKind[nodeID] == "gzip") {
			topology.incomplete[nodeID] = true
		}
	}
	return topology
}

func nodePackageEntryAllowedInspectionRoot(node artifact.Node) bool {
	switch node.Kind {
	case "directory", "zip", "tar", "gzip":
		return true
	default:
		return false
	}
}

func nodePackageEntryInventoryIncomplete(node artifact.Node) bool {
	if node.AnalyzeStatus != "analyzed" {
		return true
	}
	if (node.DeclaredEntryCount == nil) != (node.ModeledEntryCount == nil) {
		return true
	}
	return node.DeclaredEntryCount != nil && *node.DeclaredEntryCount != *node.ModeledEntryCount
}

func nodePackageEntryForbiddenCarrier(node artifact.Node) bool {
	if strings.TrimSpace(node.PackagingTechnology) != "" {
		return true
	}
	if nodePackageEntryContainerKind(node.Kind) {
		return true
	}
	switch node.Kind {
	case "app-bundle", "carchive":
		return true
	default:
		return false
	}
}

func nodePackageEntryContainerKind(kind string) bool {
	switch kind {
	case "zip", "java-archive", "python-wheel", "nuget-package", "vsix", "gzip", "tar", "cpio", "asar", "pkg", "dmg":
		return true
	default:
		return false
	}
}

func normalizedNodePackageLogical(logical string) string {
	return path.Clean(strings.ReplaceAll(strings.ReplaceAll(logical, "!", "/"), "\\", "/"))
}

// validNodePackageRootName is an attribution bound, not part of entry
// selection. Node can resolve an unnamed package directory. The conservative
// ASCII grammar prevents a manifest-controlled attribution label from looking
// like a URL, path, or terminal control sequence in the public root. It does
// not claim that the label was the consumer's external module specifier.
func validNodePackageRootName(name string) bool {
	if name == "" || len(name) > maxNodePackageRootNameBytes || name != strings.TrimSpace(name) || strings.ContainsAny(name, "\x00\r\n\t\\:%") {
		return false
	}
	parts := []string{name}
	if strings.HasPrefix(name, "@") {
		if strings.Count(name, "/") != 1 {
			return false
		}
		parts = strings.SplitN(name[1:], "/", 2)
	} else if strings.Contains(name, "/") {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || part[0] == '.' || part[0] == '_' {
			return false
		}
		for _, character := range part {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("-._~", character) {
				continue
			}
			return false
		}
	}
	return true
}

func selectNodePackageEntry(content artifact.Content, pkg packageJSON, index logicalContentIndex, manifestPaths map[string]bool, topology nodePackageEntryTopology) nodePackageEntryPlan {
	plan := nodePackageEntryPlan{manifest: content}
	if validNodePackageRootName(pkg.Name) {
		plan.name = pkg.Name
	} else {
		plan.attributionReason = "package name is absent or outside the bounded attribution grammar; entry selection was retained without claiming an external package specifier"
	}
	if topology.incomplete[content.NodeID] {
		plan.disposition = nodePackageEntryPartial
		plan.reason = "containing artifact inventory is incomplete; uniqueness of the package boundary and declared entry cannot be established"
		return plan
	}

	export := parseNodePackageRootExport(pkg.Exports)
	switch export.disposition {
	case nodePackageRootExportResolved:
		plan.field, plan.declared = "exports", export.value
	case nodePackageRootExportNotExported:
		// A subpath-only exports map intentionally blocks a bare package-root
		// request. This is a complete negative for the supported request form,
		// not a reason to fall back to main.
		return plan
	case nodePackageRootExportUnsupported, nodePackageRootExportMalformed:
		plan.disposition = nodePackageEntryPartial
		plan.reason = export.reason
		return plan
	case nodePackageRootExportAbsent:
		if pkg.Main == "" {
			plan.disposition = nodePackageEntryPartial
			plan.reason = "package root has no explicit main or exports target; Node default-index and directory fallback are not modeled"
			return plan
		}
		plan.field, plan.declared = "main", pkg.Main
	}

	targetLogical, reason := nodePackageEntryLogicalTarget(content.LogicalPath, plan.field, plan.declared)
	if reason != "" {
		plan.disposition = nodePackageEntryPartial
		plan.reason = reason
		return plan
	}
	if index.ambiguous[targetLogical] || index.foldedAmbiguous[strings.ToLower(targetLogical)] {
		plan.disposition = nodePackageEntryPartial
		plan.reason = "the declared package-root entry matched ambiguous retained paths; no execution root was created"
		return plan
	}
	target, ok := index.unique[targetLogical]
	if !ok {
		plan.disposition = nodePackageEntryPartial
		plan.reason = "the exact declared package-root entry was absent from the retained artifact graph; no extension, directory, or index fallback was attempted"
		return plan
	}
	if target.NodeID == "" || target.ScopeID == "" || target.RawFeaturesOnly || !executionRootAllowed(target) ||
		topology.known && (!topology.present[target.NodeID] || topology.excluded[target.NodeID] || topology.incomplete[target.NodeID]) ||
		target.Kind != "script" && target.Kind != "text" {
		plan.disposition = nodePackageEntryPartial
		plan.reason = "the exact declared package-root entry was retained without supported textual JavaScript semantics and a start scope; no execution root was created"
		return plan
	}
	if crossesNestedNodePackageBoundary(content.LogicalPath, targetLogical, manifestPaths) {
		plan.disposition = nodePackageEntryPartial
		plan.reason = "the declared package-root entry crosses a nested package boundary; nested package-scope semantics are not modeled"
		return plan
	}
	plan.target = target
	plan.disposition = nodePackageEntryResolved
	return plan
}

func nodePackageEntryLogicalTarget(manifestLogical, field, declared string) (string, string) {
	if declared == "" || declared != strings.TrimSpace(declared) || len(declared) > maxNodePackageEntryTargetBytes {
		return "", fmt.Sprintf("package %s entry is empty, padded, or exceeds the %d-byte path limit; no target was selected", field, maxNodePackageEntryTargetBytes)
	}
	if strings.ContainsAny(declared, "\\!?#%:\x00\r\n") || strings.HasPrefix(declared, "/") || strings.HasPrefix(declared, "~") {
		return "", fmt.Sprintf("package %s entry uses unsupported or unsafe path syntax; no target was selected", field)
	}
	if field == "exports" && !strings.HasPrefix(declared, "./") {
		return "", "package exports root target does not begin with ./; Node package-target validation was not satisfied"
	}
	relative := strings.TrimPrefix(declared, "./")
	if relative == "" || strings.HasSuffix(relative, "/") || strings.Contains(relative, "//") {
		return "", fmt.Sprintf("package %s entry requires unsupported directory-style resolution; no target was selected", field)
	}
	segments := strings.Split(relative, "/")
	if len(segments) > maxNodePackageEntryPathSegments {
		return "", fmt.Sprintf("package %s entry exceeds the %d-segment path bound; no target was selected", field, maxNodePackageEntryPathSegments)
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || strings.EqualFold(segment, "node_modules") {
			return "", fmt.Sprintf("package %s entry crosses an unsupported path segment; no target was selected", field)
		}
	}
	extension := strings.ToLower(path.Ext(relative))
	if extension != ".js" && extension != ".cjs" && extension != ".mjs" || path.Ext(relative) != extension {
		return "", fmt.Sprintf("package %s entry is not an exact .js, .cjs, or .mjs file; extension and directory fallback are not modeled", field)
	}
	logical, ok := resolveSiblingLogical(manifestLogical, relative)
	if !ok {
		return "", fmt.Sprintf("package %s entry could not be resolved inside the retained package boundary", field)
	}
	return logical, ""
}

func crossesNestedNodePackageBoundary(manifestLogical, targetLogical string, manifestPaths map[string]bool) bool {
	root := path.Dir(normalizedNodePackageLogical(manifestLogical))
	targetDir := path.Dir(normalizedNodePackageLogical(targetLogical))
	if root == "." || targetDir == root {
		return false
	}
	for current := targetDir; current != "." && current != root; current = path.Dir(current) {
		candidate := current + "/package.json"
		if manifestPaths[candidate] && candidate != normalizedNodePackageLogical(manifestLogical) {
			return true
		}
	}
	return false
}

func nodePackageExplicitTargets(plans nodePackageEntryPlanSet) map[string]bool {
	targets := map[string]bool{}
	for _, plan := range plans.plans {
		if plan.disposition == nodePackageEntryResolved && plan.target.NodeID != "" {
			targets[plan.target.NodeID] = true
		}
	}
	return targets
}

func nodePackageLifecycleDeclarationNodes(plans nodePackageEntryPlanSet) map[string]bool {
	nodes := map[string]bool{}
	for nodeID := range plans.lifecycleDeclarations {
		nodes[nodeID] = true
	}
	return nodes
}

func nodePackageHasLifecycleDeclaration(pkg packageJSON) bool {
	for name, command := range pkg.Scripts {
		if isLifecycleEntrypointScript(name) && strings.TrimSpace(command) != "" {
			return true
		}
	}
	return false
}

func applyNodePackageEntrySemantics(contents []artifact.Content, plans nodePackageEntryPlanSet) {
	targets := nodePackageExplicitTargets(plans)
	for index := range contents {
		if targets[contents[index].NodeID] {
			// The exact package entry is JavaScript under the pinned Node profile.
			// Override JXA-looking source markers and misleading content guesses;
			// this does not claim that parsing or evaluation succeeded.
			contents[index].SemanticLanguage = "javascript"
		}
	}
}

// ResolveNodePackageEntrypoints is the isolated-test entrypoint. Production
// Run uses the precomputed plan so behavior prioritization and root emission
// cannot disagree about the selected file.
func ResolveNodePackageEntrypoints(graph *behavior.Graph, contents []artifact.Content) {
	resolveNodePackageEntrypoints(graph, planNodePackageEntries(contents), maxNodePackageEntryResolutionWork)
}

func resolveNodePackageEntrypoints(graph *behavior.Graph, plans nodePackageEntryPlanSet, workLimit int) {
	if plans.globalReason != "" {
		addPartialCoverageOnce(graph, "", nodePackageEntryAnalysisArea, plans.globalReason)
		return
	}
	if graph.WorkLimitReached() {
		markDerivedGraphLimit(graph, nodePackageEntryAnalysisArea)
		return
	}
	operationsByNode := operationIndicesBySubjectNode(graph.Operations)
	work := newDerivedWorkBudget(workLimit)
	for _, plan := range plans.plans {
		if !work.take() {
			markDerivedWorkLimit(graph, nodePackageEntryAnalysisArea, workLimit, "Node package-root entry candidates")
			return
		}
		if plan.disposition == nodePackageEntryPartial {
			addPartialCoverageOnce(graph, plan.manifest.NodeID, nodePackageEntryAnalysisArea, plan.reason)
			continue
		}
		if plan.disposition != nodePackageEntryResolved {
			continue
		}
		declarationEvidenceID := nodePackageEntrypointFeatureEvidence(graph, plan)
		if declarationEvidenceID == "" {
			declarationEvidenceID = graph.AddEvidence(behavior.Evidence{
				NodeID:   plan.manifest.NodeID,
				ScopeID:  plan.manifest.ScopeID,
				Logical:  plan.manifest.LogicalPath,
				Physical: plan.manifest.PhysicalPath,
				Method:   nodePackageEntryProfile,
				Kind:     "node-package-entry-declaration",
				Value:    plan.field + ": " + plan.declared,
			})
		}
		if declarationEvidenceID == "" {
			markDerivedGraphLimit(graph, nodePackageEntryAnalysisArea)
			return
		}
		evidenceIDs := []string{declarationEvidenceID}
		if plan.name != "" {
			nameEvidenceID := nodePackageNameFeatureEvidence(graph, plan)
			if nameEvidenceID == "" {
				nameEvidenceID = graph.AddEvidence(behavior.Evidence{
					NodeID:   plan.manifest.NodeID,
					ScopeID:  plan.manifest.ScopeID,
					Logical:  plan.manifest.LogicalPath,
					Physical: plan.manifest.PhysicalPath,
					Method:   nodePackageEntryProfile,
					Kind:     "node-package-name",
					Value:    plan.name,
				})
			}
			if nameEvidenceID == "" {
				markDerivedGraphLimit(graph, nodePackageEntryAnalysisArea)
				return
			}
			evidenceIDs = append(evidenceIDs, nameEvidenceID)
		}
		targetEvidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:   plan.target.NodeID,
			ScopeID:  plan.target.ScopeID,
			Logical:  plan.target.LogicalPath,
			Physical: plan.target.PhysicalPath,
			Method:   nodePackageEntryProfile,
			Kind:     "resolved-node-package-root-entry",
			Value:    plan.target.LogicalPath,
		})
		if targetEvidenceID == "" {
			markDerivedGraphLimit(graph, nodePackageEntryAnalysisArea)
			return
		}
		evidenceIDs = append(evidenceIDs, targetEvidenceID)
		rootID := graph.AddExecutionRoot(behavior.ExecutionRoot{
			Kind:              nodePackageRootExecutionKind,
			DeclarationNodeID: plan.manifest.NodeID,
			StartNodeID:       plan.target.NodeID,
			StartScopeID:      plan.target.ScopeID,
			Name:              plan.name,
			Interpreter:       "node",
			EvidenceIDs:       evidenceIDs,
		})
		if rootID == "" {
			markDerivedGraphLimit(graph, nodePackageEntryAnalysisArea)
			return
		}
		graph.AddAnalysisSelection(behavior.AnalysisSelection{NodeID: plan.target.NodeID, Reasons: []behavior.SelectionReason{behavior.SelectionReasonExecutionRoot}})
		graph.AddCoverage(behavior.Coverage{
			NodeID:       plan.manifest.NodeID,
			AnalysisArea: nodePackageEntryAnalysisArea,
			Status:       "analyzed",
			Detail:       "exact package-root entry selected by the bounded " + nodePackageEntryProfile + " profile; this conditional relationship does not establish that a package request occurred or that module evaluation completed",
		})
		if plan.attributionReason != "" {
			addPartialCoverageOnce(graph, plan.manifest.NodeID, nodePackageEntryAnalysisArea, plan.attributionReason)
		}
		addPartialCoverageOnce(
			graph,
			plan.target.NodeID,
			nodePackageModuleAnalysisArea,
			"exact declared top-level JavaScript module analyzed; conditional exports, extension and directory fallback, custom loaders, and transitive require/import resolution are not modeled",
		)
		if !promoteIndexedNodeOperations(
			graph,
			operationsByNode[plan.target.NodeID],
			plan.target.ScopeID,
			connectedExecutionContext([]string{rootID}, nil),
			&work,
			workLimit,
			nodePackageEntryAnalysisArea,
			"Node package entry operation promotions",
		) {
			return
		}
	}
}

func nodePackageEntrypointFeatureEvidence(graph *behavior.Graph, plan nodePackageEntryPlan) string {
	for _, feature := range graph.Features {
		if feature.NodeID == plan.manifest.NodeID && feature.Key == "node.package.entrypoint" &&
			feature.Value == plan.declared && feature.Qualifiers["field"] == plan.field && len(feature.EvidenceIDs) > 0 {
			return feature.EvidenceIDs[0]
		}
	}
	return ""
}

func nodePackageNameFeatureEvidence(graph *behavior.Graph, plan nodePackageEntryPlan) string {
	for _, feature := range graph.Features {
		if feature.NodeID == plan.manifest.NodeID && feature.Key == "package.name" && feature.Value == plan.name && len(feature.EvidenceIDs) > 0 {
			return feature.EvidenceIDs[0]
		}
	}
	return ""
}
