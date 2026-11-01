package extract

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestCargoCrateCreatesConditionalDefaultBuildScriptRoot(t *testing.T) {
	inspected := inspectCargoCrate(t, "sample-crate-1.2.3.crate", map[string]string{
		"sample-crate-1.2.3/Cargo.toml": "[package]\nname = \"sample-crate\"\nversion = \"1.2.3\"\n",
		"sample-crate-1.2.3/build.rs":   "fn main() {\n    println!(\"cargo:rerun-if-changed=build.rs\");\n}\n",
		"sample-crate-1.2.3/src/lib.rs": "pub fn value() -> bool { true }\n",
	})
	graph := Run(Context{Artifacts: &inspected.Graph, Contents: inspected.Contents})
	if err := graph.Sort(); err != nil {
		t.Fatal(err)
	}
	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("execution roots = %#v, want one conditional Cargo build-script root", graph.ExecutionRoots)
	}
	root := graph.ExecutionRoots[0]
	if root.Kind != "cargo-build-script" || root.Interpreter != "cargo" ||
		root.Name != "sample-crate 1.2.3" || root.DeclarationNodeID == "" ||
		root.StartNodeID == "" || root.StartScopeID == "" || len(root.EvidenceIDs) != 8 {
		t.Fatalf("unexpected Cargo root: %#v", root)
	}
	var startScope behavior.Scope
	for _, scope := range graph.Scopes {
		if scope.ID == root.StartScopeID {
			startScope = scope
			break
		}
	}
	if startScope.Kind != "function" || startScope.Function != "main" || startScope.NodeID != root.StartNodeID {
		t.Fatalf("Cargo root is not bound to the exact retained main function: root=%#v scope=%#v", root, startScope)
	}
	if len(graph.ArtifactProperties) != 1 || graph.ArtifactProperties[0].Kind != "cargo-package-format" ||
		graph.ArtifactProperties[0].Value != "crate" || graph.ArtifactProperties[0].Support != behavior.SupportCorroborated {
		t.Fatalf("Cargo package property = %#v", graph.ArtifactProperties)
	}
	if !cargoCoverageContains(graph, "conditional Cargo host entry") ||
		!cargoCoverageContains(graph, "dependency resolution/source selection") ||
		!cargoCoverageContains(graph, "command occurrence") ||
		!cargoCoverageContains(graph, "execution") {
		t.Fatalf("Cargo activation boundary is incomplete: %#v", graph.Coverage)
	}
	if !cargoBuildStartWasAnalyzed(graph, root.StartNodeID) {
		t.Fatalf("exact Cargo-selected build script was not analyzed: selections=%#v features=%#v", graph.AnalysisSelections, graph.Features)
	}
	var defaultSelection *behavior.Evidence
	for index := range graph.Evidence {
		if graph.Evidence[index].Kind == "cargo-build-script-selection" {
			defaultSelection = &graph.Evidence[index]
			break
		}
	}
	if defaultSelection == nil || defaultSelection.ByteOffsetKnown() || defaultSelection.Line != 0 {
		t.Fatalf("an absent package.build key gained an invented coordinate: %#v", defaultSelection)
	}
}

func TestCargoCrateCreatesConditionalCustomBuildScriptRoot(t *testing.T) {
	inspected := inspectCargoCrate(t, "custom-build-0.4.0.crate", map[string]string{
		"custom-build-0.4.0/Cargo.toml":        "[package]\nname = \"custom-build\"\nversion = \"0.4.0\"\nbuild = \"tools/generate.rs\"\n",
		"custom-build-0.4.0/tools/generate.rs": "fn main() {\n}\n",
	})
	graph := Run(Context{Artifacts: &inspected.Graph, Contents: inspected.Contents})
	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].Kind != "cargo-build-script" {
		t.Fatalf("custom Cargo build path was not selected: roots=%#v coverage=%#v", graph.ExecutionRoots, graph.Coverage)
	}
	if !evidenceValueContains(graph.Evidence, graph.ExecutionRoots[0].EvidenceIDs, "explicit package.build=tools/generate.rs") {
		t.Fatalf("custom build selection lost exact evidence: %#v", graph.Evidence)
	}
}

func TestCargoCrateBuildFalseAndMissingDefaultDoNotCreateRoots(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		entries  map[string]string
		want     string
	}{
		{
			name:     "disabled",
			manifest: "[package]\nname = \"disabled\"\nversion = \"1.0.0\"\nbuild = false\n",
			entries:  map[string]string{"disabled-1.0.0/build.rs": "fn main() { panic!() }\n"},
			want:     "package.build=false",
		},
		{
			name:     "absent",
			manifest: "[package]\nname = \"absent\"\nversion = \"1.0.0\"\n",
			want:     "no exact root build.rs",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := map[string]string{test.name + "-1.0.0/Cargo.toml": test.manifest}
			for name, data := range test.entries {
				entries[name] = data
			}
			inspected := inspectCargoCrate(t, test.name+"-1.0.0.crate", entries)
			graph := Run(Context{Artifacts: &inspected.Graph, Contents: inspected.Contents})
			if len(graph.ExecutionRoots) != 0 || len(graph.Operations) != 0 {
				t.Fatalf("disabled/missing Cargo build script gained semantics: roots=%#v operations=%#v", graph.ExecutionRoots, graph.Operations)
			}
			if !cargoCoverageContains(graph, test.want) {
				t.Fatalf("Cargo negative lacks explicit coverage %q: %#v", test.want, graph.Coverage)
			}
		})
	}
}

func TestCargoCrateCompactMainFailsClosedWithoutExactFunctionScope(t *testing.T) {
	inspected := inspectCargoCrate(t, "compact-1.0.0.crate", map[string]string{
		"compact-1.0.0/Cargo.toml": "[package]\nname = \"compact\"\nversion = \"1.0.0\"\n",
		"compact-1.0.0/build.rs":   "fn main() {}\n",
	})
	graph := Run(Context{Artifacts: &inspected.Graph, Contents: inspected.Contents})
	if len(graph.ExecutionRoots) != 0 || !cargoCoverageContains(graph, "exact top-level ordinary Rust fn main") {
		t.Fatalf("compact main gained a provisional root without an exact function scope: roots=%#v coverage=%#v", graph.ExecutionRoots, graph.Coverage)
	}
}

func TestCargoVersionProfileUsesExplicitSemVer(t *testing.T) {
	for _, value := range []string{"0.1.0", "1.2.3-alpha.1", "1.2.3+build.01", "1.2.3-rc.1+build.5"} {
		if !supportedCargoVersion(value) {
			t.Fatalf("supported SemVer %q was rejected", value)
		}
	}
	for _, value := range []string{"1", "1.2", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01", "1.2.3-", "1.2.3+", "1.2.3+bad_idea"} {
		if supportedCargoVersion(value) {
			t.Fatalf("unsupported SemVer %q was accepted", value)
		}
	}
}

func TestCargoCrateCloseNegativesFailClosed(t *testing.T) {
	tests := []struct {
		name     string
		logical  string
		manifest string
		build    string
		want     string
	}{
		{name: "identity mismatch", logical: "other-1.0.0.crate", manifest: "[package]\nname = \"sample\"\nversion = \"1.0.0\"\n", build: "build.rs", want: "do not agree exactly"},
		{name: "unsafe path", logical: "sample-1.0.0.crate", manifest: "[package]\nname = \"sample\"\nversion = \"1.0.0\"\nbuild = \"../build.rs\"\n", build: "build.rs", want: "package-relative path"},
		{name: "wrong build type", logical: "sample-1.0.0.crate", manifest: "[package]\nname = \"sample\"\nversion = \"1.0.0\"\nbuild = [\"build.rs\"]\n", build: "build.rs", want: "neither a string path nor false"},
		{name: "missing custom target", logical: "sample-1.0.0.crate", manifest: "[package]\nname = \"sample\"\nversion = \"1.0.0\"\nbuild = \"tools/missing.rs\"\n", build: "build.rs", want: "absent or ambiguous"},
		{name: "workspace identity", logical: "sample-1.0.0.crate", manifest: "[package]\nname = { workspace = true }\nversion = \"1.0.0\"\n", build: "build.rs", want: "package.name"},
		{name: "dotted keys", logical: "sample-1.0.0.crate", manifest: "package.name = \"sample\"\npackage.version = \"1.0.0\"\n", build: "build.rs", want: "located [package] key profile"},
		{name: "malformed TOML", logical: "sample-1.0.0.crate", manifest: "[package\nname = \"sample\"\n", build: "build.rs", want: "not valid TOML"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stem := strings.TrimSuffix(test.logical, ".crate")
			entries := map[string]string{
				stem + "/Cargo.toml":    test.manifest,
				stem + "/" + test.build: "fn main() {}\n",
			}
			inspected := inspectCargoCrate(t, test.logical, entries)
			graph := Run(Context{Artifacts: &inspected.Graph, Contents: inspected.Contents})
			if len(graph.ExecutionRoots) != 0 || len(graph.ArtifactProperties) != 0 {
				t.Fatalf("close negative gained Cargo semantics: roots=%#v properties=%#v", graph.ExecutionRoots, graph.ArtifactProperties)
			}
			if !cargoCoverageContains(graph, test.want) {
				t.Fatalf("close negative lacks explicit coverage %q: %#v", test.want, graph.Coverage)
			}
		})
	}
}

func TestCargoCrateCaseCollisionAndExpansionBudgetFailClosed(t *testing.T) {
	collision := inspectCargoCrate(t, "sample-1.0.0.crate", map[string]string{
		"sample-1.0.0/Cargo.toml": "[package]\nname = \"sample\"\nversion = \"1.0.0\"\n",
		"sample-1.0.0/build.rs":   "fn main() {\n}\n",
		"sample-1.0.0/Build.rs":   "fn main() {\n}\n",
	})
	graph := Run(Context{Artifacts: &collision.Graph, Contents: collision.Contents})
	if len(graph.ExecutionRoots) != 0 || !cargoCoverageContains(graph, "case-fold-colliding paths") {
		t.Fatalf("case-colliding Cargo target gained a root: roots=%#v coverage=%#v", graph.ExecutionRoots, graph.Coverage)
	}

	encoded := cargoCrateBytes(t, map[string]string{
		"limited-1.0.0/Cargo.toml": "[package]\nname = \"limited\"\nversion = \"1.0.0\"\n",
		"limited-1.0.0/build.rs":   "fn main() {\n}\n",
	})
	limited, err := artifact.InspectBytes("limited-1.0.0.crate", encoded, artifact.Options{MaxExpandedBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	graph = Run(Context{Artifacts: &limited.Graph, Contents: limited.Contents})
	if len(graph.ExecutionRoots) != 0 || !cargoCoverageContains(graph, "incomplete or not fully analyzed") {
		t.Fatalf("budget-limited Cargo archive gained a root or lost coverage: roots=%#v coverage=%#v nodes=%#v", graph.ExecutionRoots, graph.Coverage, limited.Graph.Nodes)
	}
}

func TestCargoCrateNestedCandidateIsInventoryOnly(t *testing.T) {
	inner := cargoCrateBytes(t, map[string]string{
		"inner-1.0.0/Cargo.toml": "[package]\nname = \"inner\"\nversion = \"1.0.0\"\n",
		"inner-1.0.0/build.rs":   "fn main() {}\n",
	})
	var outer bytes.Buffer
	writer := tar.NewWriter(&outer)
	if err := writer.WriteHeader(&tar.Header{Name: "inner-1.0.0.crate", Mode: 0o600, Size: int64(len(inner))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(inner); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	inspected, err := artifact.InspectBytes("outer.tar", outer.Bytes(), artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	graph := Run(Context{Artifacts: &inspected.Graph, Contents: inspected.Contents})
	if len(graph.ExecutionRoots) != 0 || !cargoCoverageContains(graph, "nested .crate candidate is inventory only") {
		t.Fatalf("nested .crate gained an independent root: roots=%#v coverage=%#v", graph.ExecutionRoots, graph.Coverage)
	}
}

func TestCargoCrateCandidateLimitIsDeterministicAndExplicit(t *testing.T) {
	nodes := make([]artifact.Node, 0, maxCargoCrateArchives+1)
	for index := maxCargoCrateArchives; index >= 0; index-- {
		nodes = append(nodes, artifact.Node{ID: fmt.Sprintf("node-%03d", index), LogicalPath: fmt.Sprintf("crate-%03d-1.0.0.crate", index), Kind: "gzip", MediaType: "application/gzip", AnalyzeStatus: "analyzed"})
	}
	archives, truncated := boundedCargoCrateArchives(nodes)
	if !truncated || len(archives) != maxCargoCrateArchives || archives[0].LogicalPath != "crate-000-1.0.0.crate" || archives[len(archives)-1].LogicalPath != "crate-031-1.0.0.crate" {
		t.Fatalf("bounded Cargo candidates = %#v truncated=%v", archives, truncated)
	}
	graph := behavior.Graph{}
	prepareCargoBuildScripts(&graph, artifact.Graph{Nodes: nodes}, nil, nil, nil)
	if !cargoCoverageContains(graph, fmt.Sprintf("first %d deterministic", maxCargoCrateArchives)) {
		t.Fatalf("Cargo candidate truncation is not explicit: %#v", graph.Coverage)
	}
}

func TestCargoBenignBuildScriptIsNeutralAndDeterministic(t *testing.T) {
	inspected := inspectCargoCrate(t, "benign-2.0.0.crate", map[string]string{
		"benign-2.0.0/Cargo.toml": "[package]\nname = \"benign\"\nversion = \"2.0.0\"\n",
		"benign-2.0.0/build.rs":   "fn main() {\n    let out = std::env::var(\"OUT_DIR\").unwrap();\n    println!(\"cargo:rustc-env=OUT={out}\");\n}\n",
	})
	first := Run(Context{Artifacts: &inspected.Graph, Contents: inspected.Contents})
	second := Run(Context{Artifacts: &inspected.Graph, Contents: inspected.Contents})
	left, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatal("Cargo build-script analysis is nondeterministic")
	}
	if len(first.ExecutionRoots) != 1 || len(first.Operations) != 0 {
		t.Fatalf("benign Cargo control should retain only conditional host/source facts: roots=%#v operations=%#v", first.ExecutionRoots, first.Operations)
	}
}

func inspectCargoCrate(t *testing.T, logical string, entries map[string]string) artifact.Result {
	t.Helper()
	inspected, err := artifact.InspectBytes(logical, cargoCrateBytes(t, entries), artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return inspected
}

func cargoCrateBytes(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var encoded bytes.Buffer
	gzipWriter := gzip.NewWriter(&encoded)
	tarWriter := tar.NewWriter(gzipWriter)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := []byte(entries[name])
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func cargoCoverageContains(graph behavior.Graph, fragment string) bool {
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == cargoBuildScriptAnalysisArea && strings.Contains(coverage.Detail, fragment) {
			return true
		}
	}
	return false
}

func cargoBuildStartWasAnalyzed(graph behavior.Graph, nodeID string) bool {
	for _, selection := range graph.AnalysisSelections {
		if selection.NodeID == nodeID {
			return true
		}
	}
	return false
}

func evidenceValueContains(evidence []behavior.Evidence, ids []string, fragment string) bool {
	selected := map[string]bool{}
	for _, id := range ids {
		selected[id] = true
	}
	for _, item := range evidence {
		if selected[item.ID] && strings.Contains(item.Value, fragment) {
			return true
		}
	}
	return false
}
