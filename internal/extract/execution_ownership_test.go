package extract

import (
	"fmt"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestExecutionRootIDsByStartNodePreservesBoundedRootSet(t *testing.T) {
	roots := make([]behavior.ExecutionRoot, 80)
	for i := range roots {
		roots[i] = behavior.ExecutionRoot{ID: fmt.Sprintf("root-%04d", i+1), StartNodeID: "node-start"}
	}

	rootIDs := executionRootIDsByStartNode(roots)["node-start"]
	if len(rootIDs) != 64 {
		t.Fatalf("bounded root IDs = %d, want 64: %#v", len(rootIDs), rootIDs)
	}
	if rootIDs[0] != "root-0001" || rootIDs[len(rootIDs)-1] != "root-0064" {
		t.Fatalf("root IDs are not deterministic: %#v", rootIDs)
	}
}

func TestAssignContentExecutionKeepsCandidateSeparateFromUnknown(t *testing.T) {
	contents := []artifact.Content{{NodeID: "node-candidate"}, {NodeID: "node-generic"}}
	assignContentExecution(contents, nil, nil, map[string]bool{"node-candidate": true})

	if got := contents[0].ExecutionConnectivity; got != string(behavior.ConnectivityUnconnected) {
		t.Fatalf("candidate connectivity = %q, want UNCONNECTED", got)
	}
	if got := contents[1].ExecutionConnectivity; got != string(behavior.ConnectivityUnknown) {
		t.Fatalf("generic connectivity = %q, want UNKNOWN", got)
	}
	if len(contents[0].ExecutionRootIDs) != 0 || len(contents[0].InvokedTargetIDs) != 0 {
		t.Fatalf("candidate acquired execution ownership: %#v", contents[0])
	}
}

func TestAnalysisSelectionRecordsCandidateWithoutCreatingConnectivity(t *testing.T) {
	contents := []artifact.Content{
		{NodeID: "node-candidate", Role: "packaged-content", BehaviorAnalysisForced: true},
		{NodeID: "node-generic"},
	}
	candidates := map[string]bool{"node-candidate": true}
	assignContentExecution(contents, nil, nil, candidates)
	var graph behavior.Graph
	addAnalysisSelections(&graph, contents, candidates, nodePackageEntryPlanSet{}, artifact.Options{})

	selections := map[string][]behavior.SelectionReason{}
	for _, selection := range graph.AnalysisSelections {
		selections[selection.NodeID] = selection.Reasons
	}
	if !hasSelectionReason(selections["node-candidate"], behavior.SelectionReasonRunnableCandidate) {
		t.Fatalf("candidate selection = %#v, want runnable-candidate", selections["node-candidate"])
	}
	if !hasSelectionReason(selections["node-generic"], behavior.SelectionReasonDefaultRelevant) {
		t.Fatalf("generic selection = %#v, want default-relevant", selections["node-generic"])
	}
	if contents[0].ExecutionConnectivity != string(behavior.ConnectivityUnconnected) {
		t.Fatalf("selection changed candidate connectivity: %#v", contents[0])
	}
}

func TestRootlessLoaderTargetRetainsArtifactSourceAndUnknownContext(t *testing.T) {
	var artifacts artifact.Graph
	rootID := artifacts.AddNode(artifact.Node{LogicalPath: "archive.zip", Kind: "zip", AnalyzeStatus: "analyzed"})
	carrierID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: "archive.zip!nested/carrier", Kind: "macho", AnalyzeStatus: "analyzed"})
	targetID := artifacts.AddNode(artifact.Node{ParentID: carrierID, LogicalPath: "archive.zip!nested/carrier!main", Kind: "python-marshal", AnalyzeStatus: "partial"})
	artifacts.AddEdge(rootID, carrierID, "contains")
	artifacts.AddOrderedEdge(carrierID, targetID, "loader-invokes", 0)

	var graph behavior.Graph
	scopes := addNodeScopes(&graph, artifacts)
	artifactExecutionRoots(&graph, artifacts, nil, scopes, executionRootEligibility(artifacts.Nodes))
	addArtifactInvokedTargets(&graph, artifacts, []artifact.Content{{NodeID: targetID, RawFeaturesOnly: true}}, scopes)

	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("nested carrier became an execution root: %#v", graph.ExecutionRoots)
	}
	if len(graph.InvokedTargets) != 1 {
		t.Fatalf("invoked targets = %#v, want one loader target", graph.InvokedTargets)
	}
	target := graph.InvokedTargets[0]
	if target.NodeID != targetID || target.Source != (behavior.EntityRef{Kind: behavior.EntityKindArtifactNode, ID: carrierID}) {
		t.Fatalf("loader target lost artifact source: %#v", target)
	}
	if target.Execution.Connectivity != behavior.ConnectivityUnknown || len(target.Execution.ExecutionRootIDs) != 0 || len(target.Execution.InvokedTargetIDs) != 0 {
		t.Fatalf("rootless loader target execution = %#v, want UNKNOWN with no ownership IDs", target.Execution)
	}
}

func TestBundleHelperWithoutInvocationIsNeitherRootNorTarget(t *testing.T) {
	var artifacts artifact.Graph
	appID := artifacts.AddNode(artifact.Node{LogicalPath: "Fixture.app", Kind: "app-bundle", AnalyzeStatus: "analyzed"})
	mainID := artifacts.AddNode(artifact.Node{ParentID: appID, LogicalPath: "Fixture.app/Contents/MacOS/Fixture", Kind: "macho", AnalyzeStatus: "analyzed"})
	helperID := artifacts.AddNode(artifact.Node{ParentID: appID, LogicalPath: "Fixture.app/Contents/Frameworks/Helper", Kind: "macho", AnalyzeStatus: "analyzed"})
	artifacts.AddEdge(appID, mainID, "bundle-executable")
	artifacts.AddEdge(appID, helperID, "bundle-helper")

	var graph behavior.Graph
	scopes := addNodeScopes(&graph, artifacts)
	artifactExecutionRoots(&graph, artifacts, nil, scopes, executionRootEligibility(artifacts.Nodes))
	addArtifactInvokedTargets(&graph, artifacts, nil, scopes)

	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].Kind != "app-main" || graph.ExecutionRoots[0].StartNodeID != mainID {
		t.Fatalf("app roots = %#v, want only the main executable", graph.ExecutionRoots)
	}
	for _, root := range graph.ExecutionRoots {
		if root.StartNodeID == helperID {
			t.Fatalf("helper became an execution root: %#v", root)
		}
	}
	for _, target := range graph.InvokedTargets {
		if target.NodeID == helperID {
			t.Fatalf("helper became an invoked target without invocation evidence: %#v", target)
		}
	}
}

func TestBundleHelperIsDefaultRelevantWithoutBecomingConnected(t *testing.T) {
	artifacts := artifact.Graph{Edges: []artifact.Edge{
		{From: "node-app", To: "node-main", Kind: "bundle-executable"},
		{From: "node-app", To: "node-helper", Kind: "bundle-helper"},
	}}

	relevant := defaultRelevantArtifactNodes(artifacts)
	if !relevant["node-helper"] || relevant["node-main"] {
		t.Fatalf("default-relevant nodes = %#v, want only the bundle helper", relevant)
	}

	contents := []artifact.Content{{NodeID: "node-helper"}}
	assignContentExecution(contents, nil, nil, nil)
	if contents[0].ExecutionConnectivity != string(behavior.ConnectivityUnknown) {
		t.Fatalf("structural relevance must not invent execution connectivity: %#v", contents[0])
	}
}

func TestIndexedGzipNativeMemberIsDefaultRelevantWithoutBecomingConnected(t *testing.T) {
	artifacts := artifact.Graph{Nodes: []artifact.Node{
		{ID: "node-container", Kind: "indexed-gzip-bundle"},
		{ID: "node-macho", ParentID: "node-container", Kind: "macho", SourceRole: "packaged-content"},
		{ID: "node-other", ParentID: "node-container", Kind: "blob", SourceRole: "packaged-content"},
		{ID: "node-unrelated", Kind: "macho"},
	}}
	relevant := defaultRelevantArtifactNodes(artifacts)
	if !relevant["node-macho"] || relevant["node-other"] || relevant["node-unrelated"] {
		t.Fatalf("default-relevant nodes = %#v, want only the indexed-gzip Mach-O member", relevant)
	}
	contents := []artifact.Content{{NodeID: "node-macho", Role: "packaged-content"}}
	assignContentExecution(contents, nil, nil, nil)
	if contents[0].ExecutionConnectivity != string(behavior.ConnectivityUnknown) {
		t.Fatalf("indexed-gzip relevance must not invent execution connectivity: %#v", contents[0])
	}
}

func TestOSAAppletTargetInheritsEveryResolvedAppRoot(t *testing.T) {
	var artifacts artifact.Graph
	appID := artifacts.AddNode(artifact.Node{LogicalPath: "Scripted.app", Kind: "app-bundle", AnalyzeStatus: "analyzed"})
	infoID := artifacts.AddNode(artifact.Node{ParentID: appID, LogicalPath: "Scripted.app/Contents/Info.plist", Kind: "plist", AnalyzeStatus: "analyzed"})
	executableID := artifacts.AddNode(artifact.Node{ParentID: appID, LogicalPath: "Scripted.app/Contents/MacOS/applet", Kind: "macho", AnalyzeStatus: "analyzed"})
	scriptID := artifacts.AddNode(artifact.Node{ParentID: appID, LogicalPath: "Scripted.app/Contents/Resources/Scripts/main.scpt", Kind: "compiled-applescript", AnalyzeStatus: "partial"})
	artifacts.AddEdge(appID, infoID, "bundle-metadata")
	artifacts.AddEdge(appID, executableID, "bundle-executable")
	artifacts.AddEdge(appID, scriptID, "bundle-script")

	contents := []artifact.Content{{NodeID: infoID, LogicalPath: "Scripted.app/Contents/Info.plist", Kind: "plist"}}
	var graph behavior.Graph
	scopes := addNodeScopes(&graph, artifacts)
	eligibility := executionRootEligibility(artifacts.Nodes)
	artifactExecutionRoots(&graph, artifacts, contents, scopes, eligibility)
	addArtifactInvokedTargets(&graph, artifacts, contents, scopes)
	starts := appExecutableStarts(artifacts, scopes, eligibility)
	contents[0].ScopeID = scopes[infoID]
	contents[0].ExecutionRootEligibilityKnown = true
	contents[0].ExecutionRootEligible = eligibility[infoID]
	contents[0].Data = []byte(`<plist><dict>
<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>maratus</string><string>maratuss</string></array></dict></array>
<key>CFBundleDocumentTypes</key><array><dict><key>CFBundleTypeName</key><string>Maratus Sample</string><key>CFBundleTypeExtensions</key><array><string>spt</string></array></dict></array>
</dict></plist>`)
	ExtractPlist(&graph, contents[0], starts[infoID])
	refreshArtifactInvokedTargetExecution(&graph, artifacts)

	if len(graph.ExecutionRoots) != 4 {
		t.Fatalf("execution roots = %#v, want app-main, two URL handlers, and one document handler", graph.ExecutionRoots)
	}
	for _, root := range graph.ExecutionRoots {
		if root.StartNodeID != executableID {
			t.Fatalf("app trigger root starts at %q, want resolved executable %q: %#v", root.StartNodeID, executableID, root)
		}
		if root.Kind != "app-main" && root.DeclarationNodeID != infoID {
			t.Fatalf("handler root declaration = %q, want Info.plist %q: %#v", root.DeclarationNodeID, infoID, root)
		}
	}
	if len(graph.InvokedTargets) != 1 {
		t.Fatalf("invoked targets = %#v, want main.scpt target", graph.InvokedTargets)
	}
	target := graph.InvokedTargets[0]
	if target.NodeID != scriptID || target.Kind != "bundle-script" || target.Source != (behavior.EntityRef{Kind: behavior.EntityKindArtifactNode, ID: appID}) {
		t.Fatalf("OSA target structure = %#v", target)
	}
	if target.Execution.Connectivity != behavior.ConnectivityConnected || len(target.Execution.ExecutionRootIDs) != len(graph.ExecutionRoots) {
		t.Fatalf("OSA target did not inherit every app root: target=%#v roots=%#v", target.Execution, graph.ExecutionRoots)
	}
}

func TestLoosePlistHandlersRemainDeclarationsWithoutResolvedStart(t *testing.T) {
	content := artifact.Content{
		NodeID:                        "node-plist",
		LogicalPath:                   "Info.plist",
		ExecutionRootEligibilityKnown: true,
		ExecutionRootEligible:         true,
		Data: []byte(`<plist><dict><key>CFBundleURLTypes</key><array><dict>
<key>CFBundleURLSchemes</key><array><string>loose-handler</string></array>
</dict></array></dict></plist>`),
	}
	var graph behavior.Graph
	ExtractPlist(&graph, content, PlistExecutionStart{})

	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("loose plist minted an execution root without a resolved executable: %#v", graph.ExecutionRoots)
	}
	for _, feature := range graph.Features {
		if feature.Key == "bundle.url_scheme" && feature.Value == "loose-handler" {
			return
		}
	}
	t.Fatalf("loose handler declaration feature missing: %#v", graph.Features)
}

func hasSelectionReason(reasons []behavior.SelectionReason, target behavior.SelectionReason) bool {
	for _, reason := range reasons {
		if reason == target {
			return true
		}
	}
	return false
}
