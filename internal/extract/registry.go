package extract

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

type Context struct {
	Artifacts *artifact.Graph
	Contents  []artifact.Content
	Options   artifact.Options
}

func Run(ctx Context) behavior.Graph {
	graph := behavior.Graph{
		EvidenceLimit:   ctx.Options.Normalized().MaxEvidence,
		ItemLimit:       behavior.DefaultItemLimit,
		StringByteLimit: behavior.DefaultStringByteLimit,
	}
	contents := append([]artifact.Content(nil), ctx.Contents...)
	artifacts := artifact.Graph{}
	if ctx.Artifacts != nil {
		artifacts = *ctx.Artifacts
	}
	markPrimaryExecutables(contents, artifacts.Edges)
	scopeByNode := addNodeScopes(&graph, artifacts)
	rootEligibility := executionRootEligibility(artifacts.Nodes)
	packageInstallPaths := packagePayloadInstallPaths(artifacts, contents)
	for i := range contents {
		contents[i].ScopeID = scopeByNode[contents[i].NodeID]
		contents[i].ExecutionRootEligibilityKnown = true
		contents[i].ExecutionRootEligible = rootEligibility[contents[i].NodeID]
		contents[i].PackageInstallPath = packageInstallPaths[contents[i].NodeID]
	}
	artifactExecutionRoots(&graph, artifacts, contents, scopeByNode, rootEligibility)
	preparePythonSourceBuild(&graph, artifacts, contents, scopeByNode, rootEligibility)
	prepareCargoBuildScripts(&graph, artifacts, contents, scopeByNode, rootEligibility)
	pythonPTHHandled := preparePythonWheelPTH(&graph, artifacts, contents)
	addArtifactPackagingFeatures(&graph, ctx.Artifacts, scopeByNode)
	addArtifactInvokedTargets(&graph, artifacts, contents, scopeByNode)
	invokedTargets := invokedTargetNodes(artifacts.Edges)
	unresolvedInvocationTargets := unresolvedInvocationTargetNodes(artifacts.Edges)
	for index := range contents {
		if unresolvedInvocationTargets[contents[index].NodeID] && !invokedTargets[contents[index].NodeID] {
			contents[index].HostSelectionUnresolved = true
		}
	}
	loaderTargetOrder := loaderInvokedTargetOrder(artifacts.Edges)
	loaderInvokedTargets := relationshipTargetNodes(artifacts.Edges, "loader-invokes")
	for _, content := range contents {
		if content.RawFeaturesOnly && !loaderInvokedTargets[content.NodeID] {
			// Generic raw-only representations cannot inherit executable target
			// semantics. A format-specific loader-invokes relationship retains
			// its target context for prioritization and a future semantic decoder,
			// while the raw-feature lane still bars operations and execution roots.
			delete(invokedTargets, content.NodeID)
		}
	}
	nodePackageEntries := planNodePackageEntriesWithArtifacts(contents, artifacts)
	applyNodePackageEntrySemantics(contents, nodePackageEntries)
	npmBindingGypPlans := planNPMBindingGypInstall(contents)
	projectConfigPlans := planProjectConfigCommands(contents)
	explicitTargets := packageExplicitTargetNodes(contents, nodePackageEntries)
	for nodeID := range npmBindingGypExplicitTargetNodes(npmBindingGypPlans) {
		explicitTargets[nodeID] = true
	}
	for nodeID := range projectConfigExplicitTargetNodes(projectConfigPlans, contents) {
		explicitTargets[nodeID] = true
	}
	for nodeID := range invokedTargets {
		explicitTargets[nodeID] = true
	}
	runnableCandidates := candidateRunnableArtifactNodes(artifacts, contents)
	defaultRelevant := defaultRelevantArtifactNodes(artifacts)
	rootIDsByNode := executionRootIDsByStartNode(graph.ExecutionRoots)
	for nodeID := range rootIDsByNode {
		explicitTargets[nodeID] = true
	}
	targetExecutionByNode := invokedTargetExecutionByNode(graph.InvokedTargets)
	assignContentExecution(contents, rootIDsByNode, targetExecutionByNode, runnableCandidates)
	for i := range contents {
		explicit := explicitTargets[contents[i].NodeID]
		candidate := runnableCandidates[contents[i].NodeID]
		agentSkill := contents[i].Kind == "agent-skill"
		contents[i].BehaviorAnalysisForced = explicit || candidate || agentSkill || defaultRelevant[contents[i].NodeID] || ctx.Options.IncludeUnreferenced
	}
	contents = prioritizeBehaviorContents(contents, rootIDsByNode, explicitTargets, runnableCandidates, loaderTargetOrder, nodePackageEntries)
	appStartByMetadata := appExecutableStarts(artifacts, scopeByNode, rootEligibility)
	for _, node := range artifacts.Nodes {
		addCoverageForNode(&graph, node)
	}
	addProgramEntryCoverage(&graph, artifacts)
	addSourceRoleCoverage(&graph, contents)
	rawFeatures := newRawFeatureExtractor()
	for _, content := range contents {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			break
		}
		if pythonPTHHandled[content.NodeID] {
			continue
		}
		if content.RawFeaturesOnly {
			rawFeatures.extract(&graph, content)
			continue
		}
		if !behaviorSourceRoleAllowed(content.Role, content.BehaviorAnalysisForced) {
			continue
		}
		switch content.Kind {
		case "macho", "macho-fat":
			ExtractMachO(&graph, content, ctx.Options)
		case "agent-skill":
			ExtractAgentSkill(&graph, content)
		case "plist":
			ExtractPlist(&graph, content, appStartByMetadata[content.NodeID])
		case "manifest":
			ExtractPackageHooks(&graph, content)
			ExtractText(&graph, content)
		case "compiled-applescript":
			// The FasdUAS header establishes that this is compiled OSA bytecode,
			// not source text. Retain the artifact and execution context, but do
			// not feed attacker-controlled binary bytes into text extractors. The
			// node-level coverage pass records the unsupported semantics even when
			// content bytes could not be retained.
		case "script", "text":
			ExtractText(&graph, content)
		case "pkg":
			graph.AddCoverage(behavior.Coverage{
				NodeID:       content.NodeID,
				AnalysisArea: "pkg",
				Status:       "analyzed",
				Detail:       "flat XAR package entries modeled; install not executed",
			})
		default:
			if content.MediaType == "text/plain" {
				ExtractText(&graph, content)
			}
		}
	}
	finalizeCargoBuildScriptExecution(&graph)
	ResolveXcodeBuildSettings(&graph, ctx.Artifacts, contents)
	gypCommandTargets := resolveNPMBindingGypInstall(&graph, npmBindingGypPlans)
	projectCommandTargets := ResolveProjectConfigCommands(&graph, projectConfigPlans)
	for operationID, targets := range gypCommandTargets {
		projectCommandTargets[operationID] = targets
	}
	// Metadata and package analyzers can add roots after the structural pass.
	// Refresh structural target ownership so every supported root is retained
	// instead of collapsing ambiguous/multiple roots to no context.
	refreshArtifactInvokedTargetExecution(&graph, artifacts)
	rootIDsByNode = executionRootIDsByStartNode(graph.ExecutionRoots)
	targetExecutionByNode = invokedTargetExecutionByNode(graph.InvokedTargets)
	assignContentExecution(contents, rootIDsByNode, targetExecutionByNode, runnableCandidates)
	executionByNode := executionContextsByNode(graph.ExecutionRoots, targetExecutionByNode)
	// These promotions only annotate retained records. Apply them even when a
	// later analyzer exhausted the shared IR budget so high-priority connected
	// operations extracted earlier do not remain falsely UNKNOWN.
	promoteNodeExecution(&graph, executionByNode)
	promoteDirectScriptFunctionCalls(&graph, executionByNode)
	synchronizeOperationRelationExecution(&graph)
	synchronizeNetworkImplementationExecution(&graph)
	if graph.WorkLimitReached() {
		graph.MarkWorkOmitted()
	} else {
		ResolvePackageScriptTargets(&graph, contents)
		resolveNodePackageEntrypoints(&graph, nodePackageEntries, maxNodePackageEntryResolutionWork)
		ResolveVSCodeExtensionEntrypoints(&graph, contents)
		ResolveScriptOperationTargets(&graph, contents, projectCommandTargets)
		// Resolvers can add both roots and invoked targets. Recompute ownership
		// before chain linking so dynamically targeted operations and direct
		// function calls use the final bounded context sets.
		refreshArtifactInvokedTargetExecution(&graph, artifacts)
		rootIDsByNode = executionRootIDsByStartNode(graph.ExecutionRoots)
		targetExecutionByNode = invokedTargetExecutionByNode(graph.InvokedTargets)
		assignContentExecution(contents, rootIDsByNode, targetExecutionByNode, runnableCandidates)
		executionByNode = executionContextsByNode(graph.ExecutionRoots, targetExecutionByNode)
		promoteNodeExecution(&graph, executionByNode)
		promoteDirectScriptFunctionCalls(&graph, executionByNode)
		synchronizeOperationRelationExecution(&graph)
		synchronizeNetworkImplementationExecution(&graph)
	}
	// Evidence-count exhaustion prevents new evidence-backed semantic facts,
	// but it does not invalidate bounded relations over facts already retained.
	// The linker applies its own item/string and candidate-work bounds.
	LinkOperationRelations(&graph)
	addAnalysisSelections(&graph, contents, runnableCandidates, nodePackageEntries, ctx.Options)
	// Structural inventory is deliberately lower priority than executable
	// semantics. Run it after extraction and linking so many checkpoint-shaped
	// containers cannot consume shared evidence/items before behavior.
	addPyTorchZIPProperties(&graph, artifacts, contents, scopeByNode)
	// Cheap Python syntax observations are lower priority still. They retain
	// directly visible imports and qualified calls without contributing
	// execution ownership or modeled behavior.
	addPythonSourceFeatures(&graph, contents)
	// JavaScript uses the same independent observational lane. It retains
	// exact module specifiers and selected whole-literal resources even when
	// semantic process/data-flow recovery failed closed.
	addJavaScriptSourceFeatures(&graph, contents)
	graph.FinalizeLimits()
	_ = graph.Sort()
	return graph
}

// defaultRelevantArtifactNodes identifies structurally recognized executable
// surfaces that merit bounded semantic analysis without claiming that they are
// execution roots or statically invoked targets. A nested app helper is a
// common macOS behavior carrier, but containment alone does not prove that the
// enclosing app launches it.
func defaultRelevantArtifactNodes(artifacts artifact.Graph) map[string]bool {
	relevant := map[string]bool{}
	for _, edge := range artifacts.Edges {
		if edge.Kind == "bundle-helper" && edge.To != "" {
			relevant[edge.To] = true
		}
	}
	// A structurally decoded native member of a length-prefixed gzip bundle is a
	// useful default macOS analysis surface even though containment does not
	// prove that a loader selected or executed it. Keeping its packaged-content
	// role bars it from becoming a root; forcing analysis only recovers bounded
	// native facts and operations with UNKNOWN connectivity.
	byID := make(map[string]artifact.Node, len(artifacts.Nodes))
	for _, node := range artifacts.Nodes {
		byID[node.ID] = node
	}
	for _, node := range artifacts.Nodes {
		parent := byID[node.ParentID]
		if parent.Kind == "indexed-gzip-bundle" && (node.Kind == "macho" || node.Kind == "macho-fat") {
			relevant[node.ID] = true
		}
	}
	return relevant
}

func invokedTargetNodes(edges []artifact.Edge) map[string]bool {
	targets := map[string]bool{}
	for _, edge := range edges {
		if edge.Kind == "program-entry" || edge.Kind == "bundle-script" || edge.Kind == "loader-invokes" {
			if edge.InvocationHostUnresolved {
				continue
			}
			if edge.InvocationInterpreter != "" && artifact.InterpreterTargetLanguage(strings.TrimSpace(edge.InvocationInterpreter), edge.InterpreterArguments) == "" {
				continue
			}
			targets[edge.To] = true
		}
	}
	return targets
}

func unresolvedInvocationTargetNodes(edges []artifact.Edge) map[string]bool {
	targets := map[string]bool{}
	for _, edge := range edges {
		if edge.InvocationHostUnresolved && (edge.Kind == "program-entry" || edge.Kind == "bundle-script" || edge.Kind == "loader-invokes") {
			targets[edge.To] = true
		}
	}
	return targets
}

func relationshipTargetNodes(edges []artifact.Edge, kind string) map[string]bool {
	targets := map[string]bool{}
	for _, edge := range edges {
		if edge.Kind == kind {
			targets[edge.To] = true
		}
	}
	return targets
}

// executionRootEligibility is an artifact-topology policy, not a source-role
// heuristic. Ordinary containment inherits eligibility from the inspection
// root. Crossing into a CArchive member disables root declaration for that
// member and every recursively decoded descendant; supported invocation edges
// can still make an exact child a connected invoked target later.
func executionRootEligibility(nodes []artifact.Node) map[string]bool {
	byID := make(map[string]artifact.Node, len(nodes))
	for _, node := range nodes {
		byID[node.ID] = node
	}
	resolved := make(map[string]bool, len(nodes))
	known := make(map[string]bool, len(nodes))
	for _, start := range nodes {
		if known[start.ID] {
			continue
		}
		path := make([]string, 0, 8)
		seen := map[string]bool{}
		current := start
		eligible := false
		for {
			if known[current.ID] {
				eligible = resolved[current.ID]
				break
			}
			if seen[current.ID] {
				// Malformed caller-supplied graphs fail closed. Inspection-built
				// graphs are acyclic and parents precede descendants.
				eligible = false
				break
			}
			seen[current.ID] = true
			path = append(path, current.ID)
			// A generic gzip member is a decompressed representation, not a
			// package or launch contract. Retain and analyze its facts, but do
			// not let it or a container nested beneath it declare an execution
			// root. Gzip-decoded TAR/CPIO members carry their format-specific
			// provenance instead and preserve the established package profiles.
			if current.Provenance == "gzip-member" {
				eligible = false
				break
			}
			if current.ParentID == "" {
				eligible = true
				break
			}
			parent, ok := byID[current.ParentID]
			if !ok {
				eligible = false
				break
			}
			if parent.Kind == "carchive" {
				eligible = false
				break
			}
			current = parent
		}
		for _, nodeID := range path {
			known[nodeID] = true
			resolved[nodeID] = eligible
		}
	}
	return resolved
}

func loaderInvokedTargetOrder(edges []artifact.Edge) map[string]int {
	order := map[string]int{}
	for _, edge := range edges {
		if edge.Kind != "loader-invokes" || edge.Ordinal == nil || *edge.Ordinal < 0 {
			continue
		}
		prior, exists := order[edge.To]
		if !exists || *edge.Ordinal < prior {
			order[edge.To] = *edge.Ordinal
		}
	}
	return order
}

func addArtifactPackagingFeatures(graph *behavior.Graph, artifacts *artifact.Graph, scopeByNode map[string]string) {
	if artifacts == nil {
		return
	}
	type factKey struct {
		nodeID string
		offset int64
		kind   string
		value  string
	}
	nodes := make(map[string]artifact.Node, len(artifacts.Nodes))
	for _, node := range artifacts.Nodes {
		nodes[node.ID] = node
	}
	evidenceByFact := map[factKey]string{}
	addFact := func(nodeID string, fact artifact.LocatedArtifactEvidence) string {
		if fact.NodeID != "" {
			nodeID = fact.NodeID
		}
		fact.Kind = strings.TrimSpace(fact.Kind)
		if nodeID == "" || fact.Kind == "" || fact.Offset < 0 {
			return ""
		}
		key := factKey{nodeID: nodeID, offset: fact.Offset, kind: fact.Kind, value: fact.Value}
		if evidenceID := evidenceByFact[key]; evidenceID != "" {
			return evidenceID
		}
		node := nodes[nodeID]
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:      nodeID,
			ScopeID:     scopeByNode[nodeID],
			Logical:     node.LogicalPath,
			Offset:      fact.Offset,
			OffsetKnown: true,
			Method:      "facade-recognizer",
			Kind:        fact.Kind,
			Value:       fact.Value,
		})
		if evidenceID != "" {
			evidenceByFact[key] = evidenceID
		}
		return evidenceID
	}
	for _, node := range artifacts.Nodes {
		technology := strings.TrimSpace(node.PackagingTechnology)
		if technology == "" || len(node.PackagingEvidence) == 0 {
			continue
		}
		evidenceIDs := make([]string, 0, len(node.PackagingEvidence))
		for _, fact := range node.PackagingEvidence {
			evidenceID := addFact(node.ID, fact)
			if evidenceID != "" {
				evidenceIDs = append(evidenceIDs, evidenceID)
			}
		}
		if len(evidenceIDs) == 0 {
			continue
		}
		graph.AddFeature(behavior.Feature{
			NodeID:      node.ID,
			ScopeID:     scopeByNode[node.ID],
			Key:         "artifact.packaging_technology",
			Value:       technology,
			EvidenceIDs: evidenceIDs,
			Support:     behavior.SupportCorroborated,
		})
	}
	for index := range artifacts.Edges {
		edge := &artifacts.Edges[index]
		edge.EvidenceIDs = edge.EvidenceIDs[:0]
		for _, fact := range edge.SupportingEvidence {
			if evidenceID := addFact(edge.From, fact); evidenceID != "" && !containsString(edge.EvidenceIDs, evidenceID) {
				edge.EvidenceIDs = append(edge.EvidenceIDs, evidenceID)
			}
		}
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func addProgramEntryCoverage(graph *behavior.Graph, artifacts artifact.Graph) {
	nodes := make(map[string]artifact.Node, len(artifacts.Nodes))
	for _, node := range artifacts.Nodes {
		nodes[node.ID] = node
	}
	covered := map[string]bool{}
	for _, edge := range artifacts.Edges {
		if edge.Kind != "program-entry" {
			continue
		}
		target, ok := nodes[edge.To]
		if !ok || target.ParentID == "" || covered[target.ParentID] {
			continue
		}
		covered[target.ParentID] = true
		graph.AddCoverage(behavior.Coverage{
			NodeID:       target.ParentID,
			AnalysisArea: "electron/node-module-resolution",
			Status:       "partial",
			Detail:       "exact declared top-level module analyzed; transitive relative require/import resolution is not implemented",
		})
	}
}

// executionRootIDsByStartNode retains every supported start context. Multiple
// triggers can legitimately start the same executable (for example ordinary
// app launch, URL handlers, and document handlers), so ambiguity is a set, not
// a reason to discard ownership.
func executionRootIDsByStartNode(roots []behavior.ExecutionRoot) map[string][]string {
	result := map[string][]string{}
	for _, root := range roots {
		if root.ID == "" || root.StartNodeID == "" {
			continue
		}
		result[root.StartNodeID] = append(result[root.StartNodeID], root.ID)
	}
	for nodeID, rootIDs := range result {
		result[nodeID] = connectedExecutionContext(rootIDs, nil).ExecutionRootIDs
	}
	return result
}

func appExecutionRootIDs(artifacts artifact.Graph, rootIDsByNode map[string][]string) map[string][]string {
	result := map[string][]string{}
	for _, edge := range artifacts.Edges {
		if edge.Kind != "bundle-executable" {
			continue
		}
		result[edge.From] = append(result[edge.From], rootIDsByNode[edge.To]...)
	}
	for appID, rootIDs := range result {
		if len(rootIDs) == 0 {
			delete(result, appID)
			continue
		}
		result[appID] = connectedExecutionContext(rootIDs, nil).ExecutionRootIDs
	}
	return result
}

func structuralTargetRootIDs(kind, sourceNodeID string, rootIDsByNode, appRootIDs map[string][]string) []string {
	switch kind {
	case "program-entry", "bundle-script":
		return appRootIDs[sourceNodeID]
	case "loader-invokes":
		return rootIDsByNode[sourceNodeID]
	default:
		return nil
	}
}

func addArtifactInvokedTargets(graph *behavior.Graph, artifacts artifact.Graph, contents []artifact.Content, scopeByNode map[string]string) {
	nodes := make(map[string]artifact.Node, len(artifacts.Nodes))
	for _, node := range artifacts.Nodes {
		nodes[node.ID] = node
	}
	rawFeatureOnly := make(map[string]bool, len(contents))
	contentIndex := make(map[string]int, len(contents))
	for index, content := range contents {
		rawFeatureOnly[content.NodeID] = content.RawFeaturesOnly
		contentIndex[content.NodeID] = index
	}
	rootIDsByNode := executionRootIDsByStartNode(graph.ExecutionRoots)
	appRootIDs := appExecutionRootIDs(artifacts, rootIDsByNode)
	seen := map[string]bool{}
	for _, edge := range artifacts.Edges {
		if edge.Kind != "program-entry" && edge.Kind != "bundle-script" && edge.Kind != "loader-invokes" {
			continue
		}
		target, targetExists := nodes[edge.To]
		if _, sourceExists := nodes[edge.From]; !targetExists || !sourceExists {
			continue
		}
		if rawFeatureOnly[edge.To] && edge.Kind != "loader-invokes" {
			continue
		}
		key := edge.From + "\x00" + edge.Kind + "\x00" + edge.To
		if edge.Ordinal != nil {
			key += fmt.Sprintf("\x00%d", *edge.Ordinal)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		if edge.InvocationHostUnresolved {
			graph.AddCoverage(behavior.Coverage{
				NodeID:       target.ID,
				AnalysisArea: "artifact-invocation-host-selection",
				Status:       "skipped",
				Detail:       "structural target retained, but configured interpreter arguments were not validated",
			})
			continue
		}
		evidenceIDs := nonemptyExecutionEvidenceIDs(edge.EvidenceIDs)
		if len(evidenceIDs) == 0 {
			evidenceID := graph.AddEvidence(behavior.Evidence{
				NodeID:  target.ID,
				ScopeID: scopeByNode[target.ID],
				Logical: target.LogicalPath,
				Method:  "artifact-graph",
				Kind:    "invoked-target-classification",
				Value:   edge.Kind,
			})
			if evidenceID == "" {
				continue
			}
			evidenceIDs = []string{evidenceID}
		}
		rootIDs := structuralTargetRootIDs(edge.Kind, edge.From, rootIDsByNode, appRootIDs)
		execution := behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		if len(rootIDs) > 0 {
			execution = connectedExecutionContext(rootIDs, nil)
		}
		arguments := []string{target.LogicalPath}
		interpreter := strings.TrimSpace(edge.InvocationInterpreter)
		if interpreter != "" {
			if artifact.InterpreterTargetLanguage(interpreter, edge.InterpreterArguments) == "" {
				graph.AddCoverage(behavior.Coverage{
					NodeID:       target.ID,
					AnalysisArea: "artifact-invocation-host-selection",
					Status:       "skipped",
					Detail:       "structural interpreter arguments do not prove that the retained artifact is the selected program input",
				})
				continue
			}
			arguments = append(append([]string(nil), edge.InterpreterArguments...), target.LogicalPath)
			arguments = append(arguments, edge.InvocationArguments...)
		}
		if index, ok := contentIndex[target.ID]; ok {
			contents[index].SupportingEvidenceIDs = appendBoundedUniqueStrings(contents[index].SupportingEvidenceIDs, evidenceIDs, 64)
			if language := artifact.InterpreterTargetLanguage(interpreter, edge.InterpreterArguments); language != "" {
				contents[index].SemanticLanguage = language
			}
		}
		graph.AddInvokedTarget(behavior.InvokedTarget{
			Kind:        edge.Kind,
			NodeID:      target.ID,
			ScopeID:     scopeByNode[target.ID],
			Source:      behavior.EntityRef{Kind: behavior.EntityKindArtifactNode, ID: edge.From},
			Execution:   execution,
			Interpreter: interpreter,
			Arguments:   arguments,
			Ordinal:     edge.Ordinal,
			EvidenceIDs: evidenceIDs,
		})
	}
}

func appendBoundedUniqueStrings(existing, incoming []string, limit int) []string {
	out := append([]string(nil), existing...)
	for _, candidate := range incoming {
		if candidate == "" || containsString(out, candidate) {
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, candidate)
	}
	return out
}

func refreshArtifactInvokedTargetExecution(graph *behavior.Graph, artifacts artifact.Graph) {
	rootIDsByNode := executionRootIDsByStartNode(graph.ExecutionRoots)
	appRootIDs := appExecutionRootIDs(artifacts, rootIDsByNode)
	for i := range graph.InvokedTargets {
		target := &graph.InvokedTargets[i]
		if target.Source.Kind != behavior.EntityKindArtifactNode || target.Kind != "program-entry" && target.Kind != "bundle-script" && target.Kind != "loader-invokes" {
			continue
		}
		rootIDs := structuralTargetRootIDs(target.Kind, target.Source.ID, rootIDsByNode, appRootIDs)
		if len(rootIDs) == 0 {
			target.Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
			continue
		}
		target.Execution = connectedExecutionContext(rootIDs, nil)
	}
}

func invokedTargetExecutionByNode(targets []behavior.InvokedTarget) map[string]behavior.ExecutionContext {
	rootIDsByNode := map[string][]string{}
	targetIDsByNode := map[string][]string{}
	connectivityByNode := map[string]behavior.Connectivity{}
	for _, target := range targets {
		if target.NodeID == "" {
			continue
		}
		if target.Execution.Connectivity == behavior.ConnectivityConnected && len(target.Execution.ExecutionRootIDs) > 0 {
			rootIDsByNode[target.NodeID] = append(rootIDsByNode[target.NodeID], target.Execution.ExecutionRootIDs...)
			targetIDsByNode[target.NodeID] = append(targetIDsByNode[target.NodeID], target.ID)
			connectivityByNode[target.NodeID] = behavior.ConnectivityConnected
			continue
		}
		if connectivityByNode[target.NodeID] == "" || connectivityByNode[target.NodeID] == behavior.ConnectivityUnconnected && target.Execution.Connectivity == behavior.ConnectivityUnknown {
			connectivityByNode[target.NodeID] = target.Execution.Connectivity
		}
	}
	result := make(map[string]behavior.ExecutionContext, len(connectivityByNode))
	for nodeID, connectivity := range connectivityByNode {
		if connectivity == behavior.ConnectivityConnected {
			result[nodeID] = connectedExecutionContext(rootIDsByNode[nodeID], targetIDsByNode[nodeID])
			continue
		}
		if connectivity != behavior.ConnectivityUnconnected {
			connectivity = behavior.ConnectivityUnknown
		}
		result[nodeID] = behavior.ExecutionContext{Connectivity: connectivity}
	}
	return result
}

func prioritizeBehaviorContents(contents []artifact.Content, rootIDsByNode map[string][]string, explicitlyInvoked, runnableCandidates map[string]bool, loaderTargetOrder map[string]int, nodePackageEntries nodePackageEntryPlanSet) []artifact.Content {
	type contentPriority struct {
		tier    int
		ordinal int
	}
	nodePackageTargets := nodePackageExplicitTargets(nodePackageEntries)
	nodePackageDeclarations := nodePackageLifecycleDeclarationNodes(nodePackageEntries)
	priority := func(content artifact.Content) contentPriority {
		if len(rootIDsByNode[content.NodeID]) > 0 {
			return contentPriority{tier: 0}
		}
		if ordinal, ok := loaderTargetOrder[content.NodeID]; ok {
			return contentPriority{tier: 1, ordinal: ordinal}
		}
		if (explicitlyInvoked[content.NodeID] && !nodePackageTargets[content.NodeID]) ||
			nodePackageDeclarations[content.NodeID] {
			return contentPriority{tier: 2}
		}
		if nodePackageTargets[content.NodeID] {
			return contentPriority{tier: 3}
		}
		if runnableCandidates[content.NodeID] {
			return contentPriority{tier: 4}
		}
		if content.PrimaryExecutable || content.Role == "target" {
			return contentPriority{tier: 5}
		}
		if content.RawFeaturesOnly {
			return contentPriority{tier: 6}
		}
		switch content.Kind {
		case "agent-skill", "script", "plist", "manifest", "text":
			return contentPriority{tier: 7}
		case "macho", "macho-fat":
			return contentPriority{tier: 8}
		default:
			return contentPriority{tier: 9}
		}
	}
	sort.SliceStable(contents, func(i, j int) bool {
		left, right := priority(contents[i]), priority(contents[j])
		if left.tier != right.tier {
			return left.tier < right.tier
		}
		return left.tier == 1 && left.ordinal < right.ordinal
	})
	return contents
}

func behaviorSourceRoleAllowed(role string, forced bool) bool {
	// A source role is a noise-control hint, not a trust boundary. Archive and
	// package paths are attacker controlled, so a structurally declared target
	// always wins over the role. IncludeUnreferenced also wins over every role,
	// including the toolchain hint inferred from attacker-controlled paths.
	if forced {
		return true
	}
	switch role {
	case "documentation", "test", "fixture", "vendor", "vendor/toolchain", "packaged-content":
		return false
	case "generated/build":
		return false
	default:
		return true
	}
}

func executionRootAllowed(content artifact.Content) bool {
	return !content.ExecutionRootEligibilityKnown || content.ExecutionRootEligible
}

func addSourceRoleCoverage(graph *behavior.Graph, contents []artifact.Content) {
	counts := map[string]int{}
	for _, content := range contents {
		if content.RawFeaturesOnly {
			continue
		}
		if behaviorSourceRoleAllowed(content.Role, content.BehaviorAnalysisForced) {
			continue
		}
		counts[content.Role]++
	}
	roles := make([]string, 0, len(counts))
	for role := range counts {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		count := counts[role]
		noun := "nodes were"
		if count == 1 {
			noun = "node was"
		}
		detail := fmt.Sprintf("%d retained %s content %s excluded from behavior extraction by the default source-role policy; use --include-unreferenced to include this content", count, role, noun)
		graph.AddCoverage(behavior.Coverage{
			AnalysisArea: "behavior-source-role/" + strings.ReplaceAll(role, "/", "-"),
			Status:       "skipped",
			Detail:       detail,
		})
	}
}

// packageExplicitTargetNodes identifies retained scripts selected by a bounded
// package declaration: an install lifecycle, extension manifest, or supported
// Node package-root entry. Paths such as dist/ and node_modules/ are attacker
// controlled; a concrete declaration can make the exact file part of the
// behavior-analysis surface regardless of its path-derived source role. This
// pre-index is side-effect free; resolvers later add evidence and execution
// context only when their complete contract remains satisfied.
func packageExplicitTargetNodes(contents []artifact.Content, nodePackageEntries nodePackageEntryPlanSet) map[string]bool {
	byLogical := make(map[string]artifact.Content, len(contents))
	for _, content := range contents {
		if content.RawFeaturesOnly {
			continue
		}
		byLogical[content.LogicalPath] = content
	}
	vscodeContents := newLogicalContentIndex(contents)
	targets := nodePackageExplicitTargets(nodePackageEntries)
	work := 0
	for _, content := range contents {
		if content.RawFeaturesOnly || work >= maxPackageTargetResolutionWork || strings.ToLower(virtualBase(content.LogicalPath)) != "package.json" || !behaviorSourceRoleAllowed(content.Role, false) {
			continue
		}
		if len(content.Data) > maxStructuredDocumentBytes || preflightPackageJSON(content.Data) != nil {
			continue
		}
		pkg, err := decodePackageJSONObject(content.Data)
		if err != nil {
			continue
		}
		if packageScriptsCanExecuteAtInstall(content.LogicalPath) && !isVSCodeExtensionPackage(pkg, content.LogicalPath) {
			names := make([]string, 0, len(pkg.Scripts))
			for name := range pkg.Scripts {
				if isLifecycleEntrypointScript(name) {
					names = append(names, name)
				}
			}
			sort.Strings(names)
			visited := map[string]bool{}
			var visit func(string, int)
			visit = func(name string, depth int) {
				if depth >= maxPackageScriptReferenceDepth || visited[name] || work >= maxPackageTargetResolutionWork {
					return
				}
				visited[name] = true
				command := pkg.Scripts[name]
				for _, target := range localScriptTargets(command) {
					work++
					logical, ok := resolveSiblingLogical(content.LogicalPath, target)
					if ok {
						if targetContent, exists := byLogical[logical]; exists {
							targets[targetContent.NodeID] = true
						}
					}
					if work >= maxPackageTargetResolutionWork {
						return
					}
				}
				for _, reference := range packageScriptReferences(command) {
					work++
					if _, exists := pkg.Scripts[reference]; exists {
						visit(reference, depth+1)
					}
					if work >= maxPackageTargetResolutionWork {
						return
					}
				}
			}
			for _, name := range names {
				visit(name, 0)
			}
		}
		if isVSCodeExtensionPackage(pkg, content.LogicalPath) {
			for _, target := range vscodeExtensionTargets(pkg) {
				work++
				resolution := resolveVSCodeTarget(vscodeContents, content.LogicalPath, target.path, target.field == "main")
				if resolution.disposition == vscodeTargetResolved {
					targets[resolution.content.NodeID] = true
				}
				if work >= maxPackageTargetResolutionWork {
					break
				}
			}
		}
	}
	return targets
}

func markPrimaryExecutables(contents []artifact.Content, edges []artifact.Edge) {
	primary := map[string]bool{}
	for _, edge := range edges {
		if edge.Kind == "bundle-executable" {
			primary[edge.To] = true
		}
	}
	for i := range contents {
		contents[i].PrimaryExecutable = !contents[i].RawFeaturesOnly && primary[contents[i].NodeID]
	}
}

func addNodeScopes(graph *behavior.Graph, artifacts artifact.Graph) map[string]string {
	out := map[string]string{}
	for _, node := range artifacts.Nodes {
		out[node.ID] = graph.AddScope(behavior.Scope{
			NodeID:         node.ID,
			ParentID:       out[node.ParentID],
			Kind:           "artifact-node",
			Name:           node.LogicalPath,
			SourceRole:     node.SourceRole,
			CoverageDetail: node.CoverageDetail,
		})
	}
	return out
}

// appExecutableStarts resolves declarations in an app's Info.plist to the
// executable that the operating system actually starts. A loose plist or an
// app with conflicting executable relationships has no resolved start and
// therefore cannot mint URL/document-handler execution roots.
func appExecutableStarts(artifacts artifact.Graph, scopeByNode map[string]string, rootEligibility map[string]bool) map[string]PlistExecutionStart {
	nodes := make(map[string]artifact.Node, len(artifacts.Nodes))
	for _, node := range artifacts.Nodes {
		nodes[node.ID] = node
	}
	executableByApp := map[string]string{}
	ambiguousApps := map[string]bool{}
	for _, edge := range artifacts.Edges {
		if edge.Kind != "bundle-executable" || edge.From == "" || edge.To == "" || ambiguousApps[edge.From] {
			continue
		}
		if _, sourceExists := nodes[edge.From]; !sourceExists {
			continue
		}
		if _, targetExists := nodes[edge.To]; !targetExists {
			continue
		}
		if prior := executableByApp[edge.From]; prior != "" && prior != edge.To {
			delete(executableByApp, edge.From)
			ambiguousApps[edge.From] = true
			continue
		}
		executableByApp[edge.From] = edge.To
	}
	result := map[string]PlistExecutionStart{}
	ambiguousMetadata := map[string]bool{}
	for _, edge := range artifacts.Edges {
		if edge.Kind != "bundle-metadata" || ambiguousApps[edge.From] || ambiguousMetadata[edge.To] {
			continue
		}
		metadata, exists := nodes[edge.To]
		if !exists || strings.ToLower(virtualBase(metadata.LogicalPath)) != "info.plist" {
			continue
		}
		executableNodeID := executableByApp[edge.From]
		if executableNodeID == "" || !rootEligibility[metadata.ID] || !rootEligibility[executableNodeID] {
			continue
		}
		start := PlistExecutionStart{NodeID: executableNodeID, ScopeID: scopeByNode[executableNodeID]}
		if prior, exists := result[edge.To]; exists && prior.NodeID != start.NodeID {
			delete(result, edge.To)
			ambiguousMetadata[edge.To] = true
			continue
		}
		result[edge.To] = start
	}
	return result
}

func artifactExecutionRoots(graph *behavior.Graph, artifacts artifact.Graph, contents []artifact.Content, scopeByNode map[string]string, rootEligibility map[string]bool) {
	seen := map[string]bool{}
	nodes := map[string]artifact.Node{}
	rawFeatureOnly := map[string]bool{}
	contentByNode := make(map[string]artifact.Content, len(contents))
	for _, content := range contents {
		rawFeatureOnly[content.NodeID] = content.RawFeaturesOnly
		contentByNode[content.NodeID] = content
	}
	for _, node := range artifacts.Nodes {
		nodes[node.ID] = node
	}
	for _, node := range artifacts.Nodes {
		if rawFeatureOnly[node.ID] {
			continue
		}
		if node.ParentID == "" {
			switch node.Kind {
			case "script":
				// A script-shaped file is an execution root only when its exact
				// filename, shebang, or structural adapter selects a supported
				// interpreter. Executable mode and an unsupported #! declaration do
				// not establish host semantics; native source remains analyzable as
				// source without becoming directly executable.
				if content, ok := contentByNode[node.ID]; ok && scriptSemanticLanguage(contentLanguage(content)) {
					addArtifactExecutionRoot(graph, seen, node.ID, node, scopeByNode[node.ID], "script", filepath.Base(node.LogicalPath), rootEligibility[node.ID])
				}
			case "compiled-applescript":
				addArtifactExecutionRoot(graph, seen, node.ID, node, scopeByNode[node.ID], "compiled-applescript", filepath.Base(node.LogicalPath), rootEligibility[node.ID])
			case "macho", "macho-fat", "executable":
				addArtifactExecutionRoot(graph, seen, node.ID, node, scopeByNode[node.ID], "executable", filepath.Base(node.LogicalPath), rootEligibility[node.ID])
			}
		}
		if isPackageScriptExecutionRoot(node) {
			addArtifactExecutionRoot(graph, seen, node.ID, node, scopeByNode[node.ID], "pkg-script", virtualBase(node.LogicalPath), rootEligibility[node.ID])
		}
	}
	for _, edge := range artifacts.Edges {
		if edge.Kind != "bundle-executable" {
			continue
		}
		if _, sourceExists := nodes[edge.From]; !sourceExists {
			continue
		}
		node, ok := nodes[edge.To]
		if !ok || rawFeatureOnly[node.ID] {
			continue
		}
		addArtifactExecutionRoot(graph, seen, edge.From, node, scopeByNode[node.ID], "app-main", filepath.Base(node.LogicalPath), rootEligibility[edge.From] && rootEligibility[node.ID])
	}
}

// candidateRunnableArtifactNodes identifies shallow, independently runnable
// content for analysis prioritization only. Container membership is not an
// execution mechanism: candidates never become roots or gain connectivity
// unless a separate, supported relationship establishes that context.
func candidateRunnableArtifactNodes(artifacts artifact.Graph, contents []artifact.Content) map[string]bool {
	contentByNode := make(map[string]artifact.Content, len(contents))
	for _, content := range contents {
		contentByNode[content.NodeID] = content
	}
	rootID, rootKind, rootLogical := "", "", ""
	for _, node := range artifacts.Nodes {
		if node.ParentID == "" {
			rootID, rootKind, rootLogical = node.ID, node.Kind, node.LogicalPath
			break
		}
	}
	candidates := map[string]bool{}
	if looseDirectoryCandidatesAllowed(rootID, rootKind, artifacts.Nodes) {
		for _, node := range artifacts.Nodes {
			if node.ParentID == rootID {
				if _, ok := standaloneRunnableArtifact(node, contentByNode[node.ID]); ok {
					candidates[node.ID] = true
				}
			}
		}
	}
	for _, node := range archiveRunnableCandidates(rootID, rootKind, rootLogical, artifacts.Nodes, contentByNode) {
		candidates[node.ID] = true
	}
	return candidates
}

func archiveRunnableCandidates(rootID, rootKind, rootLogical string, nodes []artifact.Node, contentByNode map[string]artifact.Content) []artifact.Node {
	if rootID == "" || rootLogical == "" || !archivePayloadRootKind(rootKind) {
		return nil
	}
	var candidates []artifact.Node
	for _, node := range nodes {
		if node.ID == rootID || node.AnalyzeStatus == "skipped" {
			continue
		}
		if !archivePayloadPath(rootLogical, node.LogicalPath) {
			continue
		}
		if _, ok := standaloneRunnableArtifact(node, contentByNode[node.ID]); !ok {
			continue
		}
		candidates = append(candidates, node)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return filepath.ToSlash(candidates[i].LogicalPath) < filepath.ToSlash(candidates[j].LogicalPath)
	})
	if rootKind == "dmg" && len(candidates) != 1 {
		return nil
	}
	return candidates
}

func archivePayloadRootKind(kind string) bool {
	return kind == "zip" || kind == "gzip" || kind == "tar" || kind == "dmg"
}

func archivePayloadPath(rootLogical, logical string) bool {
	rootPrefix := filepath.ToSlash(rootLogical) + "!"
	logical = filepath.ToSlash(logical)
	if !strings.HasPrefix(logical, rootPrefix) {
		return false
	}
	rel := strings.TrimPrefix(logical, rootPrefix)
	if rel == "" || strings.Contains(rel, "!") {
		return false
	}
	parts := strings.Split(rel, "/")
	switch len(parts) {
	case 1:
		return parts[0] != ""
	case 2:
		return parts[0] != "" && parts[1] != "" && !strings.HasPrefix(parts[0], ".")
	default:
		return false
	}
}

func looseDirectoryCandidatesAllowed(rootID, rootKind string, nodes []artifact.Node) bool {
	if rootID == "" || rootKind != "directory" {
		return false
	}
	for _, node := range nodes {
		if node.ParentID != rootID {
			continue
		}
		base := strings.ToLower(filepath.Base(node.LogicalPath))
		if base == "package.json" || strings.HasSuffix(base, ".plist") || node.Kind == "app-bundle" || node.Kind == "pkg" {
			return false
		}
	}
	return true
}

func standaloneRunnableArtifact(node artifact.Node, content artifact.Content) (string, bool) {
	if content.RawFeaturesOnly {
		return "", false
	}
	switch node.Kind {
	case "script":
		return "script", true
	case "compiled-applescript":
		return "compiled-applescript", true
	case "macho", "macho-fat", "executable":
		return "executable", true
	case "text":
		if content.NodeID == "" {
			return "", false
		}
		if lang := contentLanguage(content); lang == "shell" || lang == "applescript" || lang == "jxa" || lang == "python" || lang == "javascript" {
			return "script", true
		}
	}
	return "", false
}

func addArtifactExecutionRoot(graph *behavior.Graph, seen map[string]bool, declarationNodeID string, node artifact.Node, scopeID, kind, name string, eligible bool) {
	key := declarationNodeID + "\x00" + node.ID + "\x00" + kind + "\x00" + name
	if !eligible || declarationNodeID == "" || seen[key] {
		return
	}
	seen[key] = true
	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID:  node.ID,
		ScopeID: scopeID,
		Logical: node.LogicalPath,
		Method:  "artifact-graph",
		Kind:    "execution-root-classification",
		Value:   kind,
	})
	if evidenceID == "" {
		return
	}
	graph.AddExecutionRoot(behavior.ExecutionRoot{
		Kind:              kind,
		DeclarationNodeID: declarationNodeID,
		StartNodeID:       node.ID,
		StartScopeID:      scopeID,
		Name:              name,
		Arguments:         []string{node.LogicalPath},
		EvidenceIDs:       []string{evidenceID},
	})
}

func isPackageScriptExecutionRoot(node artifact.Node) bool {
	if node.Kind != "script" {
		return false
	}
	logical := strings.ToLower(filepath.ToSlash(node.LogicalPath))
	return (strings.Contains(logical, "!scripts!") || strings.Contains(logical, "/scripts!")) &&
		(strings.HasSuffix(logical, "/preinstall") ||
			strings.HasSuffix(logical, "/postinstall") ||
			strings.HasSuffix(logical, "!preinstall") ||
			strings.HasSuffix(logical, "!postinstall"))
}

func virtualBase(logical string) string {
	return filepath.Base(strings.ReplaceAll(filepath.ToSlash(logical), "!", "/"))
}

func nonemptyExecutionEvidenceIDs(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !containsString(result, value) {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func mergeConnectedExecution(current, inherited behavior.ExecutionContext) behavior.ExecutionContext {
	if inherited.Connectivity != behavior.ConnectivityConnected || len(inherited.ExecutionRootIDs) == 0 {
		if normalized, err := behavior.NormalizeExecutionContext(current); err == nil {
			return normalized
		}
		return behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
	}
	rootIDs := append([]string(nil), inherited.ExecutionRootIDs...)
	targetIDs := append([]string(nil), inherited.InvokedTargetIDs...)
	if current.Connectivity == behavior.ConnectivityConnected {
		rootIDs = append(rootIDs, current.ExecutionRootIDs...)
		targetIDs = append(targetIDs, current.InvokedTargetIDs...)
	}
	return connectedExecutionContext(rootIDs, targetIDs)
}

func executionContextsByNode(roots []behavior.ExecutionRoot, targetExecutionByNode map[string]behavior.ExecutionContext) map[string]behavior.ExecutionContext {
	rootIDsByNode := executionRootIDsByStartNode(roots)
	result := make(map[string]behavior.ExecutionContext, len(rootIDsByNode)+len(targetExecutionByNode))
	for nodeID, execution := range targetExecutionByNode {
		result[nodeID] = execution
	}
	rootCountByNode := map[string]int{}
	allRootsDeclaredElsewhere := map[string]bool{}
	for _, root := range roots {
		if root.StartNodeID == "" || root.ID == "" {
			continue
		}
		rootCountByNode[root.StartNodeID]++
		if rootCountByNode[root.StartNodeID] == 1 {
			allRootsDeclaredElsewhere[root.StartNodeID] = true
		}
		if root.DeclarationNodeID == root.StartNodeID {
			allRootsDeclaredElsewhere[root.StartNodeID] = false
		}
	}
	for nodeID, rootIDs := range rootIDsByNode {
		// Multiple roots declared inside one node can own disjoint derived
		// scopes (notably npm lifecycle scripts in one package.json). Those
		// extractors already attach exact contexts; a node-wide union would make
		// every operation appear under every lifecycle root. Roots declared by
		// other artifacts and converging on one executable are genuine alternate
		// starts and can safely be unioned.
		if rootCountByNode[nodeID] > 1 && !allRootsDeclaredElsewhere[nodeID] {
			continue
		}
		rootExecution := connectedExecutionContext(rootIDs, nil)
		result[nodeID] = mergeConnectedExecution(result[nodeID], rootExecution)
	}
	return result
}

func assignContentExecution(contents []artifact.Content, rootIDsByNode map[string][]string, targetExecutionByNode map[string]behavior.ExecutionContext, runnableCandidates map[string]bool) {
	for i := range contents {
		rootIDs := rootIDsByNode[contents[i].NodeID]
		targetExecution, isTarget := targetExecutionByNode[contents[i].NodeID]
		execution := behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		if len(rootIDs) > 0 {
			execution = connectedExecutionContext(rootIDs, nil)
		}
		if targetExecution.Connectivity == behavior.ConnectivityConnected {
			execution = mergeConnectedExecution(execution, targetExecution)
		} else if len(rootIDs) == 0 && isTarget {
			execution.Connectivity = targetExecution.Connectivity
			if execution.Connectivity == "" {
				execution.Connectivity = behavior.ConnectivityUnknown
			}
		} else if len(rootIDs) == 0 && !isTarget && runnableCandidates[contents[i].NodeID] {
			execution.Connectivity = behavior.ConnectivityUnconnected
		}
		contents[i].ExecutionConnectivity = string(execution.Connectivity)
		contents[i].ExecutionRootIDs = append([]string(nil), execution.ExecutionRootIDs...)
		contents[i].InvokedTargetIDs = append([]string(nil), execution.InvokedTargetIDs...)
	}
}

func addAnalysisSelections(graph *behavior.Graph, contents []artifact.Content, runnableCandidates map[string]bool, nodePackageEntries nodePackageEntryPlanSet, options artifact.Options) {
	rootIDsByNode := executionRootIDsByStartNode(graph.ExecutionRoots)
	declaredEntryTargets := nodePackageExplicitTargets(nodePackageEntries)
	targetNodes := map[string]bool{}
	for _, target := range graph.InvokedTargets {
		targetNodes[target.NodeID] = true
	}
	for _, content := range contents {
		if !content.RawFeaturesOnly && !behaviorSourceRoleAllowed(content.Role, content.BehaviorAnalysisForced) {
			continue
		}
		reasons := make([]behavior.SelectionReason, 0, 4)
		if len(rootIDsByNode[content.NodeID]) > 0 {
			reasons = append(reasons, behavior.SelectionReasonExecutionRoot)
		}
		if targetNodes[content.NodeID] {
			reasons = append(reasons, behavior.SelectionReasonInvokedTarget)
		}
		if len(rootIDsByNode[content.NodeID]) == 0 && declaredEntryTargets[content.NodeID] {
			// Planning selected this exact retained file and forced its bounded
			// analysis, but a later evidence/item ceiling may have prevented the
			// evidence-backed ExecutionRoot from being emitted. Preserve why the
			// node was analyzed without claiming execution connectivity.
			reasons = append(reasons, behavior.SelectionReasonDeclaredEntry)
		}
		if runnableCandidates[content.NodeID] {
			reasons = append(reasons, behavior.SelectionReasonRunnableCandidate)
		}
		if content.RawFeaturesOnly {
			reasons = append(reasons, behavior.SelectionReasonRawFeatures)
		}
		if len(reasons) == 0 {
			switch {
			case content.Kind == "agent-skill":
				reasons = append(reasons, behavior.SelectionReasonDefaultRelevant)
			case behaviorSourceRoleAllowed(content.Role, false):
				reasons = append(reasons, behavior.SelectionReasonDefaultRelevant)
			case options.IncludeUnreferenced:
				reasons = append(reasons, behavior.SelectionReasonIncludeUnreferenced)
			}
		}
		if len(reasons) > 0 {
			graph.AddAnalysisSelection(behavior.AnalysisSelection{NodeID: content.NodeID, Reasons: reasons})
		}
	}
}

func promoteNodeExecution(graph *behavior.Graph, executionByNode map[string]behavior.ExecutionContext) {
	observational := observationalSourceFeatures(graph)
	for i := range graph.Operations {
		inherited := executionByNode[graph.Operations[i].SubjectNodeID]
		if inherited.Connectivity != behavior.ConnectivityConnected {
			continue
		}
		if graph.Operations[i].SourceFunction != "" && graph.Operations[i].Execution.Connectivity != behavior.ConnectivityConnected {
			// A node-level invocation does not make every recovered native or
			// script function executable. Local control-flow or a direct script
			// call must establish function reachability first.
			continue
		}
		graph.Operations[i].Execution = mergeConnectedExecution(graph.Operations[i].Execution, inherited)
	}
	for i := range graph.Features {
		if nodeExecutionPromotionExcludedFeature(graph.Features[i].Key) ||
			observational[i] {
			continue
		}
		inherited := executionByNode[graph.Features[i].NodeID]
		if inherited.Connectivity != behavior.ConnectivityConnected {
			continue
		}
		if graph.Features[i].SourceFunction != "" && graph.Features[i].Execution.Connectivity != behavior.ConnectivityConnected {
			continue
		}
		graph.Features[i].Execution = mergeConnectedExecution(graph.Features[i].Execution, inherited)
	}
}

func nodeExecutionPromotionExcludedFeature(key string) bool {
	// Manifest declarations and observational language facts need their own
	// exact trigger or control-flow relationship. Node co-location alone must
	// not make them execution-backed.
	switch key {
	case "package.name",
		"package.version",
		"node.package.type",
		"node.package.entrypoint",
		"package.script",
		"package.dependency",
		"vscode.extension.entrypoint",
		"vscode.extension.activation_event",
		"xcode.build_phase.shell_script":
		return true
	default:
		return false
	}
}

func promoteDirectScriptFunctionCalls(graph *behavior.Graph, executionByNode map[string]behavior.ExecutionContext) {
	calledByNode := map[string]map[string]bool{}
	for _, feature := range graph.Features {
		if feature.Key != "script.function_call" || feature.Value == "" {
			continue
		}
		execution := executionByNode[feature.NodeID]
		if execution.Connectivity != behavior.ConnectivityConnected || feature.SourceFunction != "" {
			continue
		}
		if calledByNode[feature.NodeID] == nil {
			calledByNode[feature.NodeID] = map[string]bool{}
		}
		calledByNode[feature.NodeID][feature.Value] = true
	}
	for i := range graph.Operations {
		if graph.Operations[i].SourceFunction == "" {
			continue
		}
		execution := executionByNode[graph.Operations[i].SubjectNodeID]
		if execution.Connectivity != behavior.ConnectivityConnected || !calledByNode[graph.Operations[i].SubjectNodeID][graph.Operations[i].SourceFunction] {
			continue
		}
		graph.Operations[i].Execution = mergeConnectedExecution(graph.Operations[i].Execution, execution)
	}
	observational := observationalSourceFeatures(graph)
	for i := range graph.Features {
		if graph.Features[i].SourceFunction == "" ||
			observational[i] {
			continue
		}
		execution := executionByNode[graph.Features[i].NodeID]
		if execution.Connectivity != behavior.ConnectivityConnected || !calledByNode[graph.Features[i].NodeID][graph.Features[i].SourceFunction] {
			continue
		}
		graph.Features[i].Execution = mergeConnectedExecution(graph.Features[i].Execution, execution)
	}
}

func synchronizeNetworkImplementationExecution(graph *behavior.Graph) {
	operations := make(map[string]behavior.ModeledOperation, len(graph.Operations))
	for _, operation := range graph.Operations {
		operations[operation.ID] = operation
	}
	for index := range graph.Network {
		observation := &graph.Network[index]
		if len(observation.OperationIDs) == 0 {
			continue
		}
		first, ok := operations[observation.OperationIDs[0]]
		if !ok {
			continue
		}
		compatible := true
		for _, operationID := range observation.OperationIDs[1:] {
			operation, exists := operations[operationID]
			if !exists || !sameExecutionContext(first.Execution, operation.Execution) {
				compatible = false
				break
			}
		}
		if compatible {
			observation.Execution = first.Execution
		}
	}
}

// synchronizeOperationRelationExecution keeps relations derived before a
// late structural resolver consistent with their operation endpoints. A
// package or extension entry resolver can connect already-retained operations
// to a newly established root; the evidenced relation remains valid only when
// every context-bearing endpoint receives the same ownership. Incompatible
// relations are omitted instead of weakening or inventing a shared context.
func synchronizeOperationRelationExecution(graph *behavior.Graph) {
	operations := make(map[string]behavior.ExecutionContext, len(graph.Operations))
	for _, operation := range graph.Operations {
		operations[operation.ID] = operation.Execution
	}
	targets := make(map[string]behavior.ExecutionContext, len(graph.InvokedTargets))
	for _, target := range graph.InvokedTargets {
		targets[target.ID] = target.Execution
	}
	retained := graph.Relations[:0]
	omitted := false
	for _, relation := range graph.Relations {
		contexts := make([]behavior.ExecutionContext, 0, 2)
		for endpointIndex, endpoint := range []behavior.RelationEndpoint{relation.From, relation.To} {
			if endpoint.Kind == behavior.RelationEndpointOperation {
				if context, ok := operations[endpoint.ID]; ok {
					contexts = append(contexts, context)
				}
			}
			if endpointIndex == 1 && relation.Kind == behavior.RelationInvokes && endpoint.Kind == behavior.RelationEndpointInvokedTarget {
				if context, ok := targets[endpoint.ID]; ok {
					contexts = append(contexts, context)
				}
			}
		}
		if len(contexts) == 0 {
			retained = append(retained, relation)
			continue
		}
		compatible := true
		for _, context := range contexts[1:] {
			if !sameExecutionContext(contexts[0], context) {
				compatible = false
				break
			}
		}
		if !compatible {
			omitted = true
			continue
		}
		relation.Execution = contexts[0]
		retained = append(retained, relation)
	}
	graph.Relations = retained
	if omitted {
		addPartialCoverageOnce(
			graph,
			"",
			"operation-relation-execution-context",
			"one or more precomputed operation relations had incompatible execution ownership after structural target resolution and were omitted",
		)
	}
}

func sameExecutionContext(left, right behavior.ExecutionContext) bool {
	return left.Connectivity == right.Connectivity &&
		slices.Equal(left.ExecutionRootIDs, right.ExecutionRootIDs) &&
		slices.Equal(left.InvokedTargetIDs, right.InvokedTargetIDs)
}

func addCoverageForNode(graph *behavior.Graph, node artifact.Node) {
	status := node.AnalyzeStatus
	if status == "" {
		status = "unknown"
	}
	graph.AddCoverage(behavior.Coverage{
		NodeID:       node.ID,
		AnalysisArea: node.Kind,
		Status:       status,
		Detail:       node.CoverageDetail,
	})
	if node.Kind == "compiled-applescript" {
		graph.AddCoverage(behavior.Coverage{
			NodeID:       node.ID,
			AnalysisArea: "compiled-applescript-semantics",
			Status:       "partial",
			Detail:       "compiled AppleScript bytecode/decompilation is not implemented; binary content was not semantically analyzed",
		})
	}
}
