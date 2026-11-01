package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestNotableStaticFeaturesRequireSemanticSameNodeLinkage(t *testing.T) {
	const repeatedURL = "https://unlinked.example.test/payload"
	rep := Report{
		Artifact: "bundle",
		ArtifactNodes: []artifact.Node{
			{ID: "node-a", LogicalPath: "bundle/A", Kind: "macho"},
			{ID: "node-b", LogicalPath: "bundle/B", Kind: "macho"},
		},
		Operations: []behavior.ModeledOperation{
			// Sharing a line/evidence record with an unrelated process operation does
			// not make the URL or sensitive path a network/read operation.
			{ID: "operation-process", SubjectNodeID: "node-a", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: ""})), EvidenceIDs: []string{"ev-shared"}, Support: behavior.SupportCorroborated, Execution: testConnectedExecution("")},
			// An exact URL on another bundled node must not suppress node-b's
			// observation merely because the raw string is the same.
			{ID: "operation-other-node", SubjectNodeID: "node-a", Kind: "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: repeatedURL})), EvidenceIDs: []string{"ev-network-a"}, Support: behavior.SupportCorroborated, Execution: testConnectedExecution("")},
			// This one is genuinely linked and should be omitted.
			{ID: "operation-linked", SubjectNodeID: "node-a", Kind: "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://linked.example.test"})), EvidenceIDs: []string{"ev-linked"}, Support: behavior.SupportCorroborated, Execution: testConnectedExecution("")},
		},
		Features: []behavior.Feature{
			{ID: "feature-url-a", NodeID: "node-a", Key: "network.url", Value: "https://shared-line.example.test", EvidenceIDs: []string{"ev-shared"}, Support: behavior.SupportCorroborated},
			{ID: "feature-url-b", NodeID: "node-b", Key: "network.url", Value: repeatedURL, EvidenceIDs: []string{"ev-url-b"}, Support: behavior.SupportCorroborated},
			{ID: "feature-sensitive", NodeID: "node-a", Architecture: "arm64", Key: "macho.sensitive_resource", Value: "~/Library/Keychains/login.keychain-db", Qualifiers: map[string]string{"category": "keychain"}, EvidenceIDs: []string{"ev-shared"}, Support: behavior.SupportCorroborated},
			{ID: "feature-input-arm", NodeID: "node-a", Architecture: "arm64", Key: "macho.security_api_import", Value: "CGEventTapCreate", Qualifiers: map[string]string{"category": "input-event-monitoring"}, EvidenceIDs: []string{"ev-input-arm"}, Support: behavior.SupportHeuristic},
			{ID: "feature-input-x86", NodeID: "node-a", Architecture: "x86_64", Key: "macho.security_api_import", Value: "CGEventTapCreate", Qualifiers: map[string]string{"category": "input-event-monitoring"}, EvidenceIDs: []string{"ev-input-x86"}, Support: behavior.SupportHeuristic},
			{ID: "feature-linked", NodeID: "node-a", Key: "network.url", Value: "https://linked.example.test", EvidenceIDs: []string{"ev-linked"}, Support: behavior.SupportCorroborated},
		},
	}

	items := notableUnlinkedFeatures(rep)
	if len(items) != 2 {
		t.Fatalf("notable features = %d, want one resource and one merged input API; network observables have their own section: %#v", len(items), items)
	}
	seen := map[string]notableFeatureView{}
	for _, item := range items {
		seen[item.feature.NodeID+"/"+item.feature.Value] = item
	}
	for _, key := range []string{
		"node-a/~/Library/Keychains/login.keychain-db",
		"node-a/CGEventTapCreate",
	} {
		if _, ok := seen[key]; !ok {
			t.Errorf("missing unlinked observation %q in %#v", key, items)
		}
	}
	if _, ok := seen["node-a/https://linked.example.test"]; ok {
		t.Fatalf("semantically linked URL remained notable: %#v", items)
	}
	input := seen["node-a/CGEventTapCreate"]
	if got := strings.Join(input.architectures, ","); got != "arm64,x86_64" {
		t.Fatalf("input API architectures = %q, want deduplicated universal-binary scopes", got)
	}
}

func TestNotableStaticFeaturesAreExplicitInConciseAndVerboseOutput(t *testing.T) {
	rep := Report{
		Artifact:      "Kitty",
		ArtifactNodes: []artifact.Node{{ID: "node-1", LogicalPath: "Kitty", Kind: "macho"}},
		Features: []behavior.Feature{{
			ID: "feature-1", NodeID: "node-1", Architecture: "arm64", Key: "macho.sensitive_resource",
			Value:       "~/Library/Application Support/Google/Chrome/Default/Cookies",
			Qualifiers:  map[string]string{"category": "browser.cookies"},
			EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportCorroborated,
		}},
		Evidence: []behavior.Evidence{{ID: "ev-1", NodeID: "node-1", Logical: "Kitty", Method: "macho-string-xref", Kind: "sensitive-resource", Value: "Chrome/Default/Cookies"}},
	}
	var concise bytes.Buffer
	if err := WriteTextWithOptions(&concise, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"OBSERVABLES (1 static item)", "browser.cookies", "~/Library/Application Support/Google/Chrome/Default/Cookies",
		"Static observations do not by themselves establish the implied resource access or behavior.",
	} {
		if !strings.Contains(concise.String(), want) {
			t.Errorf("concise output missing %q:\n%s", want, concise.String())
		}
	}
	for _, hidden := range []string{"interpretation  ", "feature        macho.sensitive_resource", "evidence      "} {
		if strings.Contains(concise.String(), hidden) {
			t.Errorf("concise output unexpectedly contains %q:\n%s", hidden, concise.String())
		}
	}

	var verbose bytes.Buffer
	if err := WriteTextWithOptions(&verbose, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"NOTABLE FEATURES (1 unlinked feature)",
		"Retained static observations not linked to a modeled operation or capability match",
		"browser.cookies: ~/Library/Application Support/Google/Chrome/Default/Cookies",
		"interpretation  unlinked observation; behavior not established",
		"feature       macho.sensitive_resource", "evidence",
	} {
		if !strings.Contains(verbose.String(), want) {
			t.Errorf("verbose output missing %q:\n%s", want, verbose.String())
		}
	}

	var veryVerbose bytes.Buffer
	if err := WriteTextWithOptions(&veryVerbose, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(veryVerbose.String(), "NOTABLE FEATURES") || !strings.Contains(veryVerbose.String(), "FEATURES") {
		t.Fatalf("-vv should use the complete prioritized feature section without duplicating notable features:\n%s", veryVerbose.String())
	}
}

func TestBundledCommonJSModulesAreStaticObservationsOnly(t *testing.T) {
	rep := Report{
		Artifact:      "bundle.js",
		ArtifactNodes: []artifact.Node{{ID: "node-1", LogicalPath: "bundle.js", Kind: "script"}},
		Features: []behavior.Feature{
			{ID: "feature-bundle", NodeID: "node-1", Key: "javascript.module_specifier", Value: "child_process", Qualifiers: map[string]string{"form": "bundled-commonjs-wrapper"}, EvidenceIDs: []string{"ev-bundle"}, Support: behavior.SupportDirect},
			{ID: "feature-ordinary", NodeID: "node-1", Key: "javascript.module_specifier", Value: "node:path", Qualifiers: map[string]string{"form": "commonjs-require"}, EvidenceIDs: []string{"ev-ordinary"}, Support: behavior.SupportDirect},
		},
		Evidence: []behavior.Evidence{
			{ID: "ev-bundle", NodeID: "node-1"},
			{ID: "ev-ordinary", NodeID: "node-1"},
		},
	}
	items := notableUnlinkedFeatures(rep)
	if len(items) != 1 || items[0].category != "bundled CommonJS module" || items[0].feature.Value != "child_process" {
		t.Fatalf("bundled module observations = %#v", items)
	}
	if !strings.Contains(notableFeatureInterpretation(items[0].feature), "behavior are not established") {
		t.Fatalf("bundled module interpretation = %q", notableFeatureInterpretation(items[0].feature))
	}
	var output bytes.Buffer
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "bundled CommonJS module") || !strings.Contains(output.String(), "child_process") || strings.Contains(output.String(), "node:path") {
		t.Fatalf("concise bundled module output:\n%s", output.String())
	}
}

func TestObjCStaticLaunchPathIsVisibleWithoutClaimingExecutionBinding(t *testing.T) {
	rep := Report{
		Artifact:      "benign-control",
		ArtifactNodes: []artifact.Node{{ID: "node-1", LogicalPath: "benign-control", Kind: "macho"}},
		Features: []behavior.Feature{
			{ID: "feature-path", NodeID: "node-1", Architecture: "arm64", Key: "objc.message_argument", Value: "/usr/bin/true", Qualifiers: map[string]string{"selector": "setLaunchPath:", "argument_index": "0", "representation": "static-cfstring"}, EvidenceIDs: []string{"ev-call", "ev-path"}, Support: behavior.SupportCorroborated},
			{ID: "feature-unrelated", NodeID: "node-1", Key: "objc.message_argument", Value: "not executable", Qualifiers: map[string]string{"selector": "setObject:forKey:", "argument_index": "1", "representation": "static-cfstring"}, EvidenceIDs: []string{"ev-other"}, Support: behavior.SupportCorroborated},
		},
		Operations: []behavior.ModeledOperation{{
			ID: "operation-1", SubjectNodeID: "node-1", Kind: behavior.OperationProcessExecute,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, ""))),
			Qualifiers:       map[string]string{"api": "NSTask", "receiver_identity": "unresolved", "resource_binding": "unresolved"},
			EvidenceIDs:      []string{"ev-call"}, Support: behavior.SupportHeuristic,
		}},
		Evidence: []behavior.Evidence{
			{ID: "ev-call", NodeID: "node-1", Logical: "benign-control", Method: "macho-objc", Kind: "objc-message-call"},
			{ID: "ev-path", NodeID: "node-1", Logical: "benign-control", Method: "macho-call-argument-backing", Kind: "call-string-argument-backing"},
			{ID: "ev-other", NodeID: "node-1", Logical: "benign-control"},
		},
	}

	items := notableUnlinkedFeatures(rep)
	if len(items) != 1 || items[0].category != "configured executable path" || items[0].feature.Value != "/usr/bin/true" {
		t.Fatalf("Objective-C configuration observations = %#v", items)
	}
	if interpretation := notableFeatureInterpretation(items[0].feature); !strings.Contains(interpretation, "receiver identity") || !strings.Contains(interpretation, "not established") {
		t.Fatalf("Objective-C configuration interpretation = %q", interpretation)
	}
	var output bytes.Buffer
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"configured executable path", "/usr/bin/true", "Static observations do not by themselves establish"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("concise output missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "not executable") {
		t.Fatalf("unrelated Objective-C argument leaked into concise output:\n%s", output.String())
	}

	summary := ProjectSummary(rep)
	if len(summary.StaticObservables) != 1 || summary.StaticObservables[0].Category != "configured executable path" || summary.StaticObservables[0].Value != "/usr/bin/true" || len(summary.StaticObservables[0].FeatureIDs) != 1 || summary.StaticObservables[0].FeatureIDs[0] != "feature-path" {
		t.Fatalf("summary lost Objective-C launch-path lineage: %#v", summary.StaticObservables)
	}
}

func TestMetadataNamespaceURLIsJSONFactButNotConciseObservable(t *testing.T) {
	const namespace = "http://www.w3.org/2000/svg"
	rep := Report{
		Artifact: "bundle",
		Features: []behavior.Feature{
			{ID: "feature-namespace", NodeID: "node-1", Key: "network.url", Value: namespace, EvidenceIDs: []string{"ev-namespace"}, Support: behavior.SupportDirect},
			{ID: "feature-endpoint", NodeID: "node-1", Key: "network.url", Value: "https://api.example.test/p", EvidenceIDs: []string{"ev-endpoint"}, Support: behavior.SupportDirect},
		},
		Evidence: []behavior.Evidence{
			{ID: "ev-namespace", NodeID: "node-1"},
			{ID: "ev-endpoint", NodeID: "node-1"},
		},
	}
	if len(rep.Features) != 2 {
		t.Fatal("fixture lost retained JSON facts")
	}
	for _, verbosity := range []TextVerbosity{TextConcise, TextVerbose} {
		var output bytes.Buffer
		if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: verbosity}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), namespace) ||
			!strings.Contains(output.String(), "https://api.example.test/p") {
			t.Fatalf("metadata URL presentation at verbosity %d:\n%s", verbosity, output.String())
		}
	}
	var complete bytes.Buffer
	if err := WriteTextWithOptions(&complete, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(complete.String(), namespace) {
		t.Fatalf("full detail hid retained metadata URL:\n%s", complete.String())
	}
}

func TestMetadataNamespaceURLRequiresExactCanonicalShape(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "http://www.w3.org/2000/svg", want: true},
		{value: "http://www.w3.org/1999/xhtml", want: true},
		{value: "http://www.w3.org/2001/XMLSchema", want: true},
		{value: "http://www.w3.org/XML/1998/namespace", want: true},
		{value: " https://www.w3.org/2000/svg"},
		{value: "https://www.w3.org/2000/svg"},
		{value: "http://WWW.W3.ORG/2000/svg"},
		{value: "http://www.w3.org/2000/SVG"},
		{value: "http://www.w3.org/2000/svg/"},
		{value: "https://www.w3.org/2000/svg?payload=x"},
		{value: "https://www.w3.org/2000/svg#payload"},
		{value: "http://www.w3.org/2000/svg?"},
		{value: "http://www.w3.org/2000/svg#"},
		{value: "https://www.w3.org:8443/2000/svg"},
		{value: "https://user@www.w3.org/2000/svg"},
		{value: "ftp://www.w3.org/2000/svg"},
		{value: "https://www.w3.org/2000/svg/payload"},
		{value: "https://example.test/2000/svg"},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			if got := metadataNamespaceURL(test.value); got != test.want {
				t.Fatalf("metadataNamespaceURL(%q) = %v, want %v", test.value, got, test.want)
			}
		})
	}
}

func TestMachOLoaderContextSurfacesOnlyActionableStructuralFacts(t *testing.T) {
	rep := Report{
		Artifact: "Loader.app",
		Features: []behavior.Feature{
			{ID: "feature-rpath", NodeID: "node-1", Key: "macho.rpath", Value: "@executable_path/../Frameworks", EvidenceIDs: []string{"ev-rpath"}, Support: behavior.SupportDirect},
			{ID: "feature-relative", NodeID: "node-1", Key: "macho.dylib", Value: "@rpath/Helper.dylib", Qualifiers: map[string]string{"linkage": "load"}, EvidenceIDs: []string{"ev-relative"}, Support: behavior.SupportDirect},
			{ID: "feature-third-party", NodeID: "node-1", Key: "macho.dylib", Value: "/Library/Frameworks/ThirdParty.framework/ThirdParty", Qualifiers: map[string]string{"linkage": "weak"}, EvidenceIDs: []string{"ev-third-party"}, Support: behavior.SupportDirect},
			{ID: "feature-system", NodeID: "node-1", Key: "macho.dylib", Value: "/System/Library/Frameworks/Foundation.framework/Foundation", EvidenceIDs: []string{"ev-system"}, Support: behavior.SupportDirect},
			{ID: "feature-usr-lib", NodeID: "node-1", Key: "macho.dylib", Value: "/usr/lib/libSystem.B.dylib", EvidenceIDs: []string{"ev-usr-lib"}, Support: behavior.SupportDirect},
		},
		Evidence: []behavior.Evidence{
			{ID: "ev-rpath", NodeID: "node-1"}, {ID: "ev-relative", NodeID: "node-1"},
			{ID: "ev-third-party", NodeID: "node-1"}, {ID: "ev-system", NodeID: "node-1"}, {ID: "ev-usr-lib", NodeID: "node-1"},
		},
	}

	items := notableUnlinkedFeatures(rep)
	if len(items) != 3 {
		t.Fatalf("loader observations = %d, want rpath and two non-system dependencies: %#v", len(items), items)
	}
	joined := ""
	for _, item := range items {
		joined += notableFeatureTitle(item) + "\n" + notableFeatureInterpretation(item.feature) + "\n"
	}
	for _, want := range []string{
		"Mach-O runtime search path: @executable_path/../Frameworks",
		"exact LC_RPATH loader search path",
		"Mach-O non-system dependency: @rpath/Helper.dylib",
		"exact Mach-O load dependency declaration",
		"Mach-O non-system dependency: /Library/Frameworks/ThirdParty.framework/ThirdParty",
		"exact Mach-O weak dependency declaration",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("loader presentation missing %q:\n%s", want, joined)
		}
	}
	for _, hidden := range []string{"/System/Library/Frameworks/Foundation.framework/Foundation", "/usr/lib/libSystem.B.dylib"} {
		if strings.Contains(joined, hidden) {
			t.Errorf("routine platform dependency leaked into actionable loader context: %q", hidden)
		}
	}
}

func TestRawByteURLUsesCandidateWordingAtEveryTextLayer(t *testing.T) {
	const value = "http://www.google.comt"
	rep := Report{
		Artifact:      "Enigma",
		ArtifactNodes: []artifact.Node{{ID: "node-1", LogicalPath: "Enigma!main", Kind: "python-marshal", AnalyzeStatus: "partial"}},
		Features: []behavior.Feature{{
			ID: "feature-1", NodeID: "node-1", Key: "network.url", Value: value,
			Qualifiers: map[string]string{
				"extraction": "ascii-run-regex", "origin": "raw-bytes", "representation": "python-marshal", "string_boundary": "unresolved",
			},
			EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportHeuristic,
		}},
		Evidence: []behavior.Evidence{{ID: "ev-1", NodeID: "node-1", Logical: "Enigma!main", Method: "raw-byte-strings", Kind: "url", Value: value}},
	}

	var concise bytes.Buffer
	if err := WriteTextWithOptions(&concise, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(concise.String(), "URL candidate") || !strings.Contains(concise.String(), value) {
		t.Fatalf("concise output presented raw bytes as an exact URL:\n%s", concise.String())
	}

	var verbose bytes.Buffer
	if err := WriteTextWithOptions(&verbose, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"URL candidate: " + value,
		"heuristic URL candidate from undecoded bytes; exact string boundary and behavior not established",
		"support       HEURISTIC",
	} {
		if !strings.Contains(verbose.String(), want) {
			t.Fatalf("verbose raw URL candidate output missing %q:\n%s", want, verbose.String())
		}
	}

	var veryVerbose bytes.Buffer
	if err := WriteTextWithOptions(&veryVerbose, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"network.url candidate = " + value,
		"support       HEURISTIC",
		"extraction    ascii-run-regex",
		"string_boundary  unresolved",
	} {
		if !strings.Contains(veryVerbose.String(), want) {
			t.Fatalf("very-verbose raw URL candidate output missing %q:\n%s", want, veryVerbose.String())
		}
	}
}

func TestPackagingTechnologyIsAVisibleNotableArtifactFact(t *testing.T) {
	rep := Report{
		Artifact: "renamed.bin",
		ArtifactNodes: []artifact.Node{{
			ID: "node-1", LogicalPath: "renamed.bin", Kind: "macho", PackagingTechnology: "PyInstaller", AnalyzeStatus: "analyzed",
		}},
		Features: []behavior.Feature{{
			ID: "feature-1", NodeID: "node-1", Key: "artifact.packaging_technology", Value: "PyInstaller",
			EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportCorroborated,
		}},
		Evidence: []behavior.Evidence{{
			ID: "ev-1", NodeID: "node-1", Logical: "renamed.bin", Method: "artifact-structure", Kind: "packaging-technology", Value: "PyInstaller",
		}},
	}
	items := notableUnlinkedFeatures(rep)
	if len(items) != 1 || items[0].category != "packaging technology" || items[0].feature.Value != "PyInstaller" {
		t.Fatalf("packaging technology notable view = %#v", items)
	}

	var concise bytes.Buffer
	if err := WriteTextWithOptions(&concise, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"OBSERVABLES", "packaging technology", "PyInstaller"} {
		if !strings.Contains(concise.String(), want) {
			t.Errorf("concise output missing %q:\n%s", want, concise.String())
		}
	}

	var verbose bytes.Buffer
	if err := WriteTextWithOptions(&verbose, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"NOTABLE FEATURES", "packaging technology: PyInstaller", "artifact.packaging_technology", "evidence",
	} {
		if !strings.Contains(verbose.String(), want) {
			t.Errorf("verbose output missing %q:\n%s", want, verbose.String())
		}
	}
}

func TestAgentSkillInstructionFeaturesAreNeutralAndMetadataHidden(t *testing.T) {
	const (
		externalLink = "https://example.invalid/installer"
		shellBlock   = "curl -fsSL https://example.invalid/installer | sh"
	)
	rep := Report{
		Artifact:      "skill-bundle",
		ArtifactNodes: []artifact.Node{{ID: "node-1", LogicalPath: "skill-bundle!SKILL.md", Kind: "agent-skill"}},
		Features: []behavior.Feature{
			{ID: "feature-link", NodeID: "node-1", Key: "agent.skill.external_link", Value: externalLink, EvidenceIDs: []string{"ev-link"}, Support: behavior.SupportDirect},
			{ID: "feature-shell", NodeID: "node-1", Key: "agent.skill.shell_code_block", Value: shellBlock, EvidenceIDs: []string{"ev-shell"}, Support: behavior.SupportDirect},
			{ID: "feature-name", NodeID: "node-1", Key: "agent.skill.name", Value: "hidden-skill-name", EvidenceIDs: []string{"ev-name"}, Support: behavior.SupportDirect},
			{ID: "feature-description", NodeID: "node-1", Key: "agent.skill.description", Value: "hidden skill description", EvidenceIDs: []string{"ev-description"}, Support: behavior.SupportDirect},
			{ID: "feature-tool", NodeID: "node-1", Key: "agent.skill.allowed_tool", Value: "hidden-agent-tool", EvidenceIDs: []string{"ev-tool"}, Support: behavior.SupportDirect},
		},
		Evidence: []behavior.Evidence{
			{ID: "ev-link", NodeID: "node-1", Logical: "skill-bundle!SKILL.md"},
			{ID: "ev-shell", NodeID: "node-1", Logical: "skill-bundle!SKILL.md"},
			{ID: "ev-name", NodeID: "node-1", Logical: "skill-bundle!SKILL.md"},
			{ID: "ev-description", NodeID: "node-1", Logical: "skill-bundle!SKILL.md"},
			{ID: "ev-tool", NodeID: "node-1", Logical: "skill-bundle!SKILL.md"},
		},
	}

	items := notableUnlinkedFeatures(rep)
	if len(items) != 2 {
		t.Fatalf("agent-skill notable features = %#v, want only instruction-bearing observations", items)
	}
	if items[0].feature.Key != "agent.skill.external_link" || items[1].feature.Key != "agent.skill.shell_code_block" {
		t.Fatalf("agent-skill notable ordering = %#v", items)
	}

	var concise bytes.Buffer
	if err := WriteTextWithOptions(&concise, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"agent instruction link", externalLink,
		"agent shell code block", shellBlock,
		"Static observations do not by themselves establish the implied resource access or behavior.",
	} {
		if !strings.Contains(concise.String(), want) {
			t.Errorf("concise agent-skill output missing %q:\n%s", want, concise.String())
		}
	}

	var verbose bytes.Buffer
	if err := WriteTextWithOptions(&verbose, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"agent instructions containing an external link do not establish retrieval, approval, tool dispatch, or OS execution",
		"agent instructions containing shell code blocks may be examples and do not establish retrieval, approval, tool dispatch, or OS execution",
		"feature       agent.skill.external_link",
		"feature       agent.skill.shell_code_block",
	} {
		if !strings.Contains(verbose.String(), want) {
			t.Errorf("verbose agent-skill output missing %q:\n%s", want, verbose.String())
		}
	}
	for _, hidden := range []string{"hidden-skill-name", "hidden skill description", "hidden-agent-tool"} {
		if strings.Contains(concise.String(), hidden) || strings.Contains(verbose.String(), hidden) {
			t.Errorf("agent-skill metadata %q became visible by default", hidden)
		}
	}
}

func TestRemotePackageDependencySpecifierVocabulary(t *testing.T) {
	tests := []struct {
		specifier string
		want      bool
	}{
		{specifier: "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c", want: true},
		{specifier: "gitlab:group/subgroup/repository#release", want: true},
		{specifier: "bitbucket:owner/repository", want: true},
		{specifier: "git+https://github.com/owner/repository.git#commit", want: true},
		{specifier: "ssh://git@example.test/owner/repository.git", want: true},
		{specifier: "git@example.test:owner/repository.git#commit", want: true},
		{specifier: "https://packages.example.test/archive.tgz", want: true},
		{specifier: "^1.2.3"},
		{specifier: "latest"},
		{specifier: "npm:other-package@1.2.3"},
		{specifier: "workspace:*"},
		{specifier: "file:../local-package"},
		{specifier: "github:"},
		{specifier: "github:owner"},
		{specifier: "github:owner/repository extra"},
		{specifier: "git+file:../local-repository"},
		{specifier: "https://"},
	}
	for _, test := range tests {
		if got := remotePackageDependencySpecifier(test.specifier); got != test.want {
			t.Errorf("remotePackageDependencySpecifier(%q) = %v, want %v", test.specifier, got, test.want)
		}
	}
	if got := sanitizedRemotePackageDependencySpecifier(
		"git+https://user:secret@example.test/owner/repository.git#commit",
	); got != "git+https://example.test/owner/repository.git#commit" {
		t.Errorf("sanitized remote dependency specifier = %q, want URL userinfo removed", got)
	}
}

func TestRemotePackageDependenciesAreVisibleButNeutral(t *testing.T) {
	const remote = "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
	rep := Report{
		Artifact:      "package.json",
		ArtifactNodes: []artifact.Node{{ID: "node-1", LogicalPath: "package.json", Kind: "manifest"}},
		Features: []behavior.Feature{
			{
				ID: "feature-remote", NodeID: "node-1", Key: "package.dependency", Value: "@tanstack/setup",
				Qualifiers:  map[string]string{"section": "optionalDependencies", "specifier": remote},
				EvidenceIDs: []string{"ev-remote"}, Support: behavior.SupportDirect,
				Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
			},
			{
				ID: "feature-registry", NodeID: "node-1", Key: "package.dependency", Value: "react",
				Qualifiers: map[string]string{"section": "dependencies", "specifier": "^19.0.0"},
				Support:    behavior.SupportDirect,
			},
			{
				ID: "feature-malformed", NodeID: "node-1", Key: "package.dependency", Value: "malformed",
				Qualifiers: map[string]string{"section": "dependencies", "specifier": "github:"},
				Support:    behavior.SupportDirect,
			},
		},
		Evidence: []behavior.Evidence{{
			ID: "ev-remote", NodeID: "node-1", Logical: "package.json", Method: "package.json",
			Kind: "package-dependency", Value: "optionalDependencies: @tanstack/setup@" + remote,
		}},
	}

	items := notableUnlinkedFeatures(rep)
	if len(items) != 1 || items[0].feature.ID != "feature-remote" {
		t.Fatalf("notable dependency features = %#v, want only the remote declaration", items)
	}
	if len(rep.ExecutionRoots) != 0 || len(rep.InvokedTargets) != 0 || len(rep.Operations) != 0 || len(rep.Capabilities) != 0 {
		t.Fatalf("dependency presentation fixture unexpectedly contains behavior objects: %#v", rep)
	}

	var concise bytes.Buffer
	if err := WriteTextWithOptions(&concise, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"VCS/URL dependency",
		"@tanstack/setup -> github:tanstack/router#79ac49ee",
		"Static observations do not by themselves establish the implied resource access or behavior.",
	} {
		if !strings.Contains(concise.String(), want) {
			t.Errorf("concise dependency output missing %q:\n%s", want, concise.String())
		}
	}
	for _, hidden := range []string{"react", "malformed"} {
		if strings.Contains(concise.String(), hidden) {
			t.Errorf("ordinary or malformed dependency %q became notable:\n%s", hidden, concise.String())
		}
	}

	var verbose bytes.Buffer
	if err := WriteTextWithOptions(&verbose, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"VCS/URL dependency: @tanstack/setup -> " + remote,
		"direct package-manifest declaration; dependency resolution, retrieval, installation, and execution are not established",
		"feature       package.dependency",
		"support       DIRECT",
	} {
		if !strings.Contains(verbose.String(), want) {
			t.Errorf("verbose dependency output missing %q:\n%s", want, verbose.String())
		}
	}
}

func TestRemotePackageDependencyPresentationIsDeterministicAndBounded(t *testing.T) {
	const dependencyCount = 32
	features := make([]behavior.Feature, 0, dependencyCount)
	for i := 0; i < dependencyCount; i++ {
		features = append(features, behavior.Feature{
			ID: "feature-" + fmt.Sprintf("%02d", i), NodeID: "node-1",
			Key: "package.dependency", Value: fmt.Sprintf("remote-%02d", i),
			Qualifiers: map[string]string{
				"section":   "optionalDependencies",
				"specifier": fmt.Sprintf("github:owner/repository-%02d#commit", i),
			},
			Support: behavior.SupportDirect,
		})
	}
	reversed := append([]behavior.Feature(nil), features...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	render := func(features []behavior.Feature) string {
		t.Helper()
		var output bytes.Buffer
		if err := WriteTextWithOptions(&output, Report{Artifact: "package.json", Features: features}, TextOptions{Verbosity: TextVerbose}); err != nil {
			t.Fatal(err)
		}
		return output.String()
	}
	first, second := render(features), render(reversed)
	if first != second {
		t.Fatal("remote dependency presentation changed with feature input order")
	}
	for _, want := range []string{
		"NOTABLE FEATURES (8 shown · 32 unlinked features retained)",
		"... 24 more unlinked Features",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("bounded dependency output missing %q:\n%s", want, first)
		}
	}
}

func TestNotableFeaturesIncludeScriptResourcesAndDoNotDuplicateNetworkIndicators(t *testing.T) {
	rep := Report{
		Features: []behavior.Feature{
			{ID: "feature-visible-url", NodeID: "node-1", Key: "network.url", Value: "https://visible.example.test", EvidenceIDs: []string{"ev-visible"}, Support: behavior.SupportCorroborated},
			{ID: "feature-weak-url", NodeID: "node-1", Key: "network.url", Value: "https://weak.example.test", EvidenceIDs: []string{"ev-weak"}, Support: behavior.SupportCorroborated},
			{ID: "feature-domain", NodeID: "node-1", Key: "network.domain", Value: "c2.example.test", EvidenceIDs: []string{"ev-domain"}, Support: behavior.SupportCorroborated},
			{ID: "feature-script-resource", NodeID: "node-1", Key: "script.sensitive_resource", Value: "/Library/Keychains/login.keychain-db", Qualifiers: map[string]string{"category": "keychain"}, EvidenceIDs: []string{"ev-resource"}, Support: behavior.SupportCorroborated},
			{ID: "feature-browser-store", NodeID: "node-1", Key: "script.browser_credential_store", Value: "cookies.sqlite, key4.db, logins.json", EvidenceIDs: []string{"ev-browser"}, Support: behavior.SupportCorroborated},
		},
		Evidence: []behavior.Evidence{
			{ID: "ev-visible", NodeID: "node-1"}, {ID: "ev-weak", NodeID: "node-1"},
			{ID: "ev-domain", NodeID: "node-1"}, {ID: "ev-resource", NodeID: "node-1"}, {ID: "ev-browser", NodeID: "node-1"},
		},
	}
	items := notableUnlinkedFeatures(rep)
	values := map[string]string{}
	for _, item := range items {
		values[item.feature.Value] = item.category
	}
	if _, ok := values["https://visible.example.test"]; ok {
		t.Fatalf("default-visible network observable was duplicated as a notable feature: %#v", items)
	}
	if _, ok := values["https://weak.example.test"]; ok {
		t.Fatalf("unlinked network observable was duplicated as a notable feature: %#v", items)
	}
	for value, category := range map[string]string{
		"/Library/Keychains/login.keychain-db": "keychain",
		"cookies.sqlite, key4.db, logins.json": "browser credential store",
	} {
		if values[value] != category {
			t.Errorf("notable value %q category = %q, want %q; items=%#v", value, values[value], category, items)
		}
	}
	if !featureVisibleInText(behavior.Feature{Key: "network.domain", Value: "c2.example.test"}) {
		t.Fatal("network.domain should remain visible when -vv replaces the notable section with prioritized features")
	}
	if !featureVisibleInText(behavior.Feature{Key: "xcode.build_phase.shell_script", Value: "echo build"}) {
		t.Fatal("Xcode Run Script declaration should be visible in detailed text output")
	}
}

func TestBoundedNotableFeaturesBalancesObservationCategories(t *testing.T) {
	var items []notableFeatureView
	for i := 0; i < 20; i++ {
		items = append(items, notableFeatureView{feature: behavior.Feature{Key: "network.url", Value: "https://example.test/" + string(rune('a'+i))}})
	}
	items = append(items,
		notableFeatureView{feature: behavior.Feature{Key: "macho.security_api_import", Value: "CGEventTapCreate"}},
		notableFeatureView{feature: behavior.Feature{Key: "script.sensitive_resource", Value: "login.keychain-db"}},
	)
	selected := boundedNotableFeatures(items, presentationNotableFeatureLimit)
	if len(selected) != presentationNotableFeatureLimit {
		t.Fatalf("bounded notable count = %d, want %d", len(selected), presentationNotableFeatureLimit)
	}
	var input, sensitive bool
	for _, item := range selected {
		input = input || item.feature.Key == "macho.security_api_import"
		sensitive = sensitive || sensitiveResourceFeature(item.feature)
	}
	if !input || !sensitive {
		t.Fatalf("raw URLs crowded out input-event or sensitive-resource observations: %#v", selected)
	}
}
