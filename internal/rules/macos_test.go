package rules

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestCredentialRuleMetadataUsesUnifiedNamespace(t *testing.T) {
	for _, ruleID := range []string{
		"macos.credential-prompt",
		"macos.credential-validation",
		"macos.keychain-access",
		"macos.browser-credential-collection",
		"macos.credential-material-collection",
	} {
		spec, ok := SpecByID(ruleID)
		if !ok {
			t.Fatalf("credential rule %s is not registered", ruleID)
		}
		if metadata := spec.Metadata; metadata.Namespace != "macos.credentials" {
			t.Fatalf("credential rule %s namespace = %q, want macos.credentials", ruleID, metadata.Namespace)
		}
	}
	materialSpec, _ := SpecByID("macos.credential-material-collection")
	material := materialSpec.Metadata
	for _, term := range []string{"wallet", "SSH", "cloud", "package-manager", "developer credential material"} {
		if !strings.Contains(material.Title+" "+material.Description, term) {
			t.Fatalf("credential-material metadata does not name %q: %#v", term, material)
		}
	}
}

func TestSensitiveFileRulesRequireConcreteClassifiedResources(t *testing.T) {
	for _, test := range []struct {
		name           string
		spec           Spec
		classification behavior.ResourceClassification
	}{
		{name: "browser credentials", spec: MacOSBrowserCredentialCollection, classification: behavior.ResourceClassBrowserCookieStore},
		{name: "credential material", spec: MacOSCredentialMaterialCollection, classification: behavior.ResourceClassSSHPrivateKey},
		{name: "application data", spec: MacOSApplicationDataCollection, classification: behavior.ResourceClassMessagingDataStore},
		{name: "browser data", spec: MacOSBrowserDataCollection, classification: behavior.ResourceClassBrowserDataStore},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := behavior.Graph{Operations: []behavior.ModeledOperation{{
				ID: "operation-abstract", SubjectNodeID: "node", Kind: behavior.OperationFileRead,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "", test.classification))),
				EvidenceIDs:      []string{"ev-abstract"}, Support: behavior.SupportCorroborated, Execution: unknownExecution(),
			}}}
			if matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: test.spec}); len(matches) != 0 {
				t.Fatalf("abstract classified resource produced capability: %#v", matches)
			}
		})
	}
}

func TestArchiveCollectionRequiresConcreteSource(t *testing.T) {
	operation := func(id, source string) behavior.ModeledOperation {
		return behavior.ModeledOperation{
			ID: id, SubjectNodeID: "node", Kind: behavior.OperationArchiveCreate,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, source)),
				behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/archive.zip", behavior.ResourceClassArchive)),
			),
			EvidenceIDs: []string{"ev-" + id}, Support: behavior.SupportCorroborated, Execution: unknownExecution(),
		}
	}
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{operation("operation-abstract", ""), operation("operation-exact", "/Users/example/Documents")}}
	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSArchiveLocalData})
	if len(matches) != 1 || !slices.Equal(matches[0].OperationIDs, []string{"operation-exact"}) {
		t.Fatalf("archive collection matches = %#v", matches)
	}
}

func TestArchiveExtractionCapabilityRequiresConcreteSource(t *testing.T) {
	operation := func(id, source string) behavior.ModeledOperation {
		return behavior.ModeledOperation{
			ID: id, SubjectNodeID: "node", Kind: behavior.OperationArchiveExtract,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, source, behavior.ResourceClassArchive)),
				behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "")),
			),
			EvidenceIDs: []string{"ev-" + id}, Support: behavior.SupportCorroborated, Execution: unknownExecution(),
		}
	}
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{operation("operation-abstract", ""), operation("operation-exact", "/tmp/stage.zip")}}
	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSArchiveExtract})
	if len(matches) != 1 || !slices.Equal(matches[0].OperationIDs, []string{"operation-exact"}) || len(matches[0].Attack) != 0 {
		t.Fatalf("archive extraction matches = %#v", matches)
	}
}

func TestArchiveATTACKMappingRequiresConcreteClassifiedSource(t *testing.T) {
	operation := func(id, source string, classifications ...behavior.ResourceClassification) behavior.ModeledOperation {
		return behavior.ModeledOperation{
			ID: id, SubjectNodeID: "node", Kind: behavior.OperationArchiveCreate,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, source, classifications...)),
				behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/archive.zip", behavior.ResourceClassArchive)),
			),
			EvidenceIDs: []string{"ev-" + id}, Support: behavior.SupportCorroborated, Execution: unknownExecution(),
		}
	}
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		operation("operation-generic", "/Users/example/Documents"),
		operation("operation-abstract", "", behavior.ResourceClassBrowserPasswordStore),
		operation("operation-classified", "/Users/example/Library/Application Support/Google/Chrome/Default/Login Data", behavior.ResourceClassBrowserPasswordStore),
	}}
	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSArchiveClassifiedData})
	if len(matches) != 1 || !slices.Equal(matches[0].OperationIDs, []string{"operation-classified"}) || !slices.Equal(matches[0].Attack, []string{"T1560"}) {
		t.Fatalf("classified archive mapping = %#v", matches)
	}
	generic := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSArchiveLocalData})
	if len(generic) != 2 {
		t.Fatalf("generic exact archives = %#v", generic)
	}
	for _, match := range generic {
		if len(match.Attack) != 0 {
			t.Fatalf("generic archive carried ATT&CK mapping: %#v", match)
		}
	}
}

func TestStagedUploadRequiresConcreteArchiveSource(t *testing.T) {
	archive := behavior.NewResource(behavior.ResourceFile, "/tmp/archive.zip", behavior.ResourceClassArchive)
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		{
			ID: "operation-archive", SubjectNodeID: "node", Kind: behavior.OperationArchiveCreate,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "")),
				behavior.Bind(behavior.ResourceRoleLocalOutput, archive),
			),
			EvidenceIDs: []string{"ev-archive"}, Support: behavior.SupportCorroborated, Execution: unknownExecution(),
		},
		{
			ID: "operation-upload", SubjectNodeID: "node", Kind: behavior.OperationNetworkUpload,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleLocalInput, archive),
				behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/upload")),
			),
			EvidenceIDs: []string{"ev-upload"}, Support: behavior.SupportCorroborated, Execution: unknownExecution(),
		},
	}}
	graph.Relations = []behavior.OperationRelation{
		{ID: "relation-produces", Kind: behavior.RelationProduces, From: behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-archive"), To: behavior.ResourceRelationEndpoint(behavior.ResourceRoleLocalOutput, archive), EvidenceIDs: []string{"ev-archive"}, Support: behavior.SupportCorroborated, Execution: unknownExecution()},
		{ID: "relation-precedes", Kind: behavior.RelationPrecedes, From: behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-archive"), To: behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-upload"), EvidenceIDs: []string{"ev-archive", "ev-upload"}, Support: behavior.SupportCorroborated, Execution: unknownExecution()},
		{ID: "relation-consumes", Kind: behavior.RelationConsumes, From: behavior.ResourceRelationEndpoint(behavior.ResourceRoleLocalInput, archive), To: behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-upload"), EvidenceIDs: []string{"ev-upload"}, Support: behavior.SupportCorroborated, Execution: unknownExecution()},
	}
	if matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSUploadStagedData}); len(matches) != 0 {
		t.Fatalf("archive without a concrete local source became staged-data upload: %#v", matches)
	}
}

func TestStagedUploadDoesNotClaimC2Exfiltration(t *testing.T) {
	archive := behavior.NewResource(behavior.ResourceFile, "/tmp/archive.zip", behavior.ResourceClassArchive)
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		{
			ID: "operation-archive", SubjectNodeID: "node", Kind: behavior.OperationArchiveCreate,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "/Users/example/Documents")),
				behavior.Bind(behavior.ResourceRoleLocalOutput, archive),
			),
			EvidenceIDs: []string{"ev-archive"}, Support: behavior.SupportCorroborated, Execution: unknownExecution(),
		},
		{
			ID: "operation-upload", SubjectNodeID: "node", Kind: behavior.OperationNetworkUpload,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleLocalInput, archive),
				behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/upload")),
			),
			EvidenceIDs: []string{"ev-upload"}, Support: behavior.SupportCorroborated, Execution: unknownExecution(),
		},
	}}
	graph.Relations = []behavior.OperationRelation{
		{ID: "relation-produces", Kind: behavior.RelationProduces, From: behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-archive"), To: behavior.ResourceRelationEndpoint(behavior.ResourceRoleLocalOutput, archive), EvidenceIDs: []string{"ev-archive"}, Support: behavior.SupportCorroborated, Execution: unknownExecution()},
		{ID: "relation-precedes", Kind: behavior.RelationPrecedes, From: behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-archive"), To: behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-upload"), EvidenceIDs: []string{"ev-archive", "ev-upload"}, Support: behavior.SupportCorroborated, Execution: unknownExecution()},
		{ID: "relation-consumes", Kind: behavior.RelationConsumes, From: behavior.ResourceRelationEndpoint(behavior.ResourceRoleLocalInput, archive), To: behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-upload"), EvidenceIDs: []string{"ev-upload"}, Support: behavior.SupportCorroborated, Execution: unknownExecution()},
	}
	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSUploadStagedData})
	if len(matches) != 1 || matches[0].Namespace != "macos.transfer" || len(matches[0].Attack) != 0 {
		t.Fatalf("staged upload overclaimed exfiltration or C2: %#v", matches)
	}
}

func TestNetworkConfigurationDiscoveryIsDistinctFromCommunication(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{{
		ID: "operation-network-config", SubjectNodeID: "node", Kind: behavior.OperationNetworkConfigurationQuery,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceConfiguration, "local network interfaces"))),
		EvidenceIDs:      []string{"ev-query"}, Support: behavior.SupportCorroborated, Execution: unknownExecution(),
	}}}
	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSNetworkConfigurationDiscovery})
	if len(matches) != 1 || !slices.Equal(matches[0].Attack, []string{"T1016"}) {
		t.Fatalf("network configuration discovery = %#v", matches)
	}
	if communication := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSNetworkCommunication}); len(communication) != 0 {
		t.Fatalf("configuration query became communication: %#v", communication)
	}
}

func TestGenericKeychainQueryStaysDistinctFromCredentialAccess(t *testing.T) {
	query := behavior.Graph{Operations: []behavior.ModeledOperation{{
		ID: "operation-query", SubjectNodeID: "node", Kind: behavior.OperationKeychainItemQuery,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceCredentialStore, "", behavior.ResourceClassKeychain))),
		EvidenceIDs:      []string{"ev-query"}, Support: behavior.SupportCorroborated, Execution: unknownExecution(),
	}}}
	matches := evaluateCompiledSpecForTest(&query, compiledSpec{spec: MacOSKeychainItemQuery})
	if len(matches) != 1 || len(matches[0].Attack) != 0 || matches[0].Namespace != "macos.technical.credentials" {
		t.Fatalf("generic Keychain item query = %#v", matches)
	}
	if credential := evaluateCompiledSpecForTest(&query, compiledSpec{spec: MacOSKeychainAccess}); len(credential) != 0 {
		t.Fatalf("generic Keychain item query became credential access: %#v", credential)
	}

	password := behavior.Graph{Operations: []behavior.ModeledOperation{{
		ID: "operation-password", SubjectNodeID: "node", Kind: behavior.OperationCredentialStoreRead,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceCredentialStore, "", behavior.ResourceClassKeychain))),
		EvidenceIDs:      []string{"ev-password"}, Support: behavior.SupportCorroborated, Execution: unknownExecution(),
	}}}
	credential := evaluateCompiledSpecForTest(&password, compiledSpec{spec: MacOSKeychainAccess})
	if len(credential) != 1 || !slices.Equal(credential[0].Attack, []string{"T1555.001"}) {
		t.Fatalf("credential-specific Keychain operation = %#v", credential)
	}
}

func TestLaunchAndLoginRulesCoverDistinctNeutralPrimitives(t *testing.T) {
	for _, test := range []struct {
		name     string
		kind     behavior.OperationKind
		resource behavior.Resource
		spec     Spec
	}{
		{name: "launchd declaration", kind: behavior.OperationLaunchdJobDeclare, resource: behavior.NewResource(behavior.ResourceLaunchdJob, "", behavior.ResourceClassLaunchAgent), spec: MacOSLaunchPersistence},
		{name: "launchd installation", kind: behavior.OperationLaunchdJobInstall, resource: behavior.NewResource(behavior.ResourceLaunchdJob, "", behavior.ResourceClassLaunchAgent), spec: MacOSLaunchPersistence},
		{name: "launchd load", kind: behavior.OperationLaunchdJobLoad, resource: behavior.NewResource(behavior.ResourceLaunchdJob, "", behavior.ResourceClassLaunchAgent), spec: MacOSLaunchPersistence},
		{name: "launchd registration", kind: behavior.OperationLaunchdJobRegister, resource: behavior.NewResource(behavior.ResourceLaunchdJob, "", behavior.ResourceClassLaunchAgent), spec: MacOSLaunchPersistence},
		{name: "login item enable", kind: behavior.OperationLoginItemEnable, resource: behavior.NewResource(behavior.ResourceLoginItem, ""), spec: MacOSLoginItem},
		{name: "login item registration", kind: behavior.OperationLoginItemRegister, resource: behavior.NewResource(behavior.ResourceLoginItem, ""), spec: MacOSLoginItem},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := behavior.Graph{Operations: []behavior.ModeledOperation{{
				ID: "operation-1", SubjectNodeID: "node-1", Kind: test.kind,
				ResourceBindings: testRequiredBindings(test.kind, test.resource), EvidenceIDs: []string{"ev-1"},
				Support: behavior.SupportCorroborated, Execution: unknownExecution(),
			}}}
			matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: test.spec})
			if len(matches) != 1 || !sameStrings(matches[0].OperationIDs, []string{"operation-1"}) {
				t.Fatalf("neutral primitive %q produced unexpected matches: %#v", test.kind, matches)
			}
		})
	}
}

func TestPlistModificationDoesNotClaimPersistenceMapping(t *testing.T) {
	graph := behavior.Graph{}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-plist", Kind: behavior.OperationPlistModify,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, "/tmp/App.plist", behavior.ResourceClassPropertyList))),
		Qualifiers:       map[string]string{"key": "LSEnvironment.DYLD_INSERT_LIBRARIES", "dynamic_loader_configuration": "true"},
		Support:          behavior.SupportCorroborated, Execution: unknownExecution(),
	})
	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSPlistModification})
	if len(matches) != 1 {
		t.Fatalf("plist modification match = %#v", matches)
	}
	if len(matches[0].Attack) != 0 || len(matches[0].MBC) != 0 || matches[0].Namespace != "macos.configuration" {
		t.Fatalf("neutral plist modification claimed persistence or behavior mapping: %#v", matches[0])
	}
}

func TestPrivacyAuthorizationResetStaysNeutralAndOperationBacked(t *testing.T) {
	graph := behavior.Graph{}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-tccutil", Kind: behavior.OperationPrivacyAuthorizationReset,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceConfiguration, "AppleEvents"))),
		Qualifiers:       map[string]string{"tool": "tccutil", "service": "AppleEvents"},
		EvidenceIDs:      []string{"ev-1"}, Support: behavior.SupportCorroborated, Execution: unknownExecution(),
	})
	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSPrivacyAuthorizationReset})
	if len(matches) != 1 || !sameStrings(matches[0].OperationIDs, []string{"operation-0001"}) || !sameStrings(matches[0].EvidenceIDs, []string{"ev-1"}) {
		t.Fatalf("privacy reset match = %#v", matches)
	}
	if len(matches[0].Attack) != 0 || len(matches[0].MBC) != 0 || matches[0].Namespace != "macos.configuration" {
		t.Fatalf("privacy reset claimed a bypass or objective mapping: %#v", matches[0])
	}
	graph.Operations[0].Support = behavior.SupportHeuristic
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSPrivacyAuthorizationReset}); len(got) != 0 {
		t.Fatalf("heuristic privacy reset became a capability match: %#v", got)
	}
}

func TestPackageInstallRuleRequiresReportableTypedPackageOperation(t *testing.T) {
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		{ID: "operation-install", SubjectNodeID: "node-script", Kind: "package.install", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalInput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/Library/program.pkg", Classifications: []behavior.ResourceClassification{behavior.ResourceClassPackage}})), EvidenceIDs: []string{"ev-install"}, Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main")},
		{ID: "operation-runtime", SubjectNodeID: "node-script", Kind: "package.install", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalInput, behavior.Resource{Kind: behavior.ResourceFile, Value: "", Classifications: []behavior.ResourceClassification{behavior.ResourceClassPackage}})), EvidenceIDs: []string{"ev-runtime"}, Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main")},
		{ID: "operation-possible", SubjectNodeID: "node-script", Kind: "package.install", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalInput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/possible.pkg", Classifications: []behavior.ResourceClassification{behavior.ResourceClassPackage}})), Support: behavior.SupportHeuristic, Execution: connectedExecution("root-main")},
		{ID: "operation-wrong-resource", SubjectNodeID: "node-script", Kind: "package.install", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalInput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/not-a-package.pkg"})), Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main")},
		{ID: "operation-unrelated", SubjectNodeID: "node-script", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/unrelated.pkg", Classifications: []behavior.ResourceClassification{behavior.ResourceClassPackage}})), Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main")},
	}}

	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSPackageInstall})
	if len(matches) != 2 {
		t.Fatalf("package-install matches = %d, want concrete and unresolved typed operations: %#v", len(matches), matches)
	}
	var match behavior.CapabilityMatch
	for _, candidate := range matches {
		if hasResource(candidate.AffectedResources, "package", "/Library/program.pkg") {
			match = candidate
		}
	}
	if match.RuleID != "macos.package-install" || match.Support != behavior.SupportCorroborated || match.Execution.Connectivity != behavior.ConnectivityConnected {
		t.Fatalf("package-install match lost rule, support, or execution context: %#v", match)
	}
	if !hasResource(match.AffectedResources, "package", "/Library/program.pkg") || !sameStrings(match.OperationIDs, []string{"operation-install"}) || !sameStrings(match.EvidenceIDs, []string{"ev-install"}) {
		t.Fatalf("package-install match lost its concrete support: %#v", match)
	}
	var foundRuntime bool
	for _, candidate := range matches {
		if hasResource(candidate.AffectedResources, "package", "") && sameStrings(candidate.OperationIDs, []string{"operation-runtime"}) {
			foundRuntime = true
		}
	}
	if !foundRuntime {
		t.Fatalf("package-install match lost the statically visible invocation with a runtime operand: %#v", matches)
	}
}

func TestClipboardAndScreenCaptureUseIndependentRulesAndMappings(t *testing.T) {
	clipboard := behavior.Graph{}
	clipboard.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-clipboard",
		Kind:          "clipboard.read", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.Resource{Kind: behavior.ResourceClipboard, Value: ""})), Support: behavior.SupportCorroborated,
		Execution: connectedExecution("root-main"),
	})
	clipboardCapabilityMatches := evaluateCompiledSpecForTest(&clipboard, compiledSpec{spec: MacOSClipboardRead})
	if len(clipboardCapabilityMatches) != 1 || !sameStrings(clipboardCapabilityMatches[0].Attack, []string{"T1115"}) || len(clipboardCapabilityMatches[0].MBC) != 0 {
		t.Fatalf("clipboard capture should map only to ATT&CK T1115: %#v", clipboardCapabilityMatches)
	}
	if got := evaluateCompiledSpecForTest(&clipboard, compiledSpec{spec: MacOSScreenCapture}); len(got) != 0 {
		t.Fatalf("clipboard capture must not become a screen-capture capabilityMatch: %#v", got)
	}

	screen := behavior.Graph{}
	screen.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-screen",
		Kind:          "screen.capture", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.Resource{Kind: behavior.ResourceScreen, Value: ""})), Support: behavior.SupportCorroborated,
		Execution: connectedExecution("root-main"),
	})
	screenCapabilityMatches := evaluateCompiledSpecForTest(&screen, compiledSpec{spec: MacOSScreenCapture})
	if len(screenCapabilityMatches) != 1 || !sameStrings(screenCapabilityMatches[0].Attack, []string{"T1113"}) || !sameStrings(screenCapabilityMatches[0].MBC, []string{"E1113"}) {
		t.Fatalf("screen capture should map to ATT&CK T1113 and MBC E1113: %#v", screenCapabilityMatches)
	}
	if got := evaluateCompiledSpecForTest(&screen, compiledSpec{spec: MacOSClipboardRead}); len(got) != 0 {
		t.Fatalf("screen capture must not become a clipboard capabilityMatch: %#v", got)
	}
}

func TestCollectionAndVisibilityRulesKeepClaimsNarrow(t *testing.T) {
	tests := []struct {
		name       string
		kind       behavior.OperationKind
		resource   behavior.Resource
		spec       Spec
		wantAttack []string
	}{
		{"clipboard write", behavior.OperationClipboardWrite, behavior.NewResource(behavior.ResourceClipboard, "pbcopy"), MacOSClipboardWrite, nil},
		{"input event tap", behavior.OperationInputEventTapCreate, behavior.NewResource(behavior.ResourceInputEventStream, "Quartz event stream"), MacOSInputEventTap, nil},
		{"audio recording queue", behavior.OperationAudioRecordingQueueCreate, behavior.NewResource(behavior.ResourceAudioInput, "system audio input"), MacOSAudioRecordingQueue, nil},
		{"camera capture", behavior.OperationCameraCapture, behavior.NewResource(behavior.ResourceCamera, ""), MacOSCameraCapture, []string{"T1125"}},
		{"file visibility", behavior.OperationFileVisibilityModify, behavior.NewResource(behavior.ResourceFile, "/tmp/hidden"), MacOSFileVisibilityModification, []string{"T1564.001"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph := behavior.Graph{}
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID: "node-1", Kind: test.kind,
				ResourceBindings: testRequiredBindings(test.kind, test.resource),
				EvidenceIDs:      []string{"ev-1"}, Support: behavior.SupportCorroborated, Execution: unknownExecution(),
			})
			matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: test.spec})
			if len(matches) != 1 || !sameStrings(matches[0].Attack, test.wantAttack) {
				t.Fatalf("narrow rule match = %#v", matches)
			}
			graph.Operations[0].Support = behavior.SupportHeuristic
			if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: test.spec}); len(got) != 0 {
				t.Fatalf("HEURISTIC operation became a capability match: %#v", got)
			}
		})
	}
}

func TestPossibleOperationDoesNotBecomeCapabilityMatch(t *testing.T) {
	graph := behavior.Graph{}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001",
		Kind:          "credential.store.read", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.Resource{Kind: behavior.ResourceCredentialStore, Value: "", Classifications: []behavior.ResourceClassification{behavior.ResourceClassKeychain}})), Support: behavior.SupportHeuristic,
		Execution: unknownExecution(),
	})
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSKeychainAccess}); len(got) != 0 {
		t.Fatalf("possible operation should remain out of capabilityMatches: %#v", got)
	}
}

func TestSupportedOperationBecomesCapabilityMatch(t *testing.T) {
	graph := behavior.Graph{}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001",
		Kind:          "credential.store.read", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.Resource{Kind: behavior.ResourceCredentialStore, Value: "", Classifications: []behavior.ResourceClassification{behavior.ResourceClassKeychain}})), Support: behavior.SupportCorroborated,
		Execution: connectedExecution("root-main"),
	})
	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSKeychainAccess})
	if len(got) != 1 {
		t.Fatalf("supported operation should produce capabilityMatch: %#v", got)
	}
}

func TestCapabilityMatchPreservesOperationArchitectureScope(t *testing.T) {
	graph := behavior.Graph{}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-macho",
		ScopeID:       "scope-collect",
		Kind:          "credential.store.read", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.Resource{Kind: behavior.ResourceCredentialStore, Value: "", Classifications: []behavior.ResourceClassification{behavior.ResourceClassKeychain}})), Support: behavior.SupportCorroborated,
		Execution:      connectedExecution("root-main"),
		SourceFunction: "collect",
		Architecture:   "arm64",
	})

	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSKeychainAccess})
	if len(got) != 1 {
		t.Fatalf("expected one capabilityMatch, got %#v", got)
	}
	if len(got[0].ArchitectureScopes) != 1 || got[0].ArchitectureScopes[0] != "arm64" {
		t.Fatalf("capabilityMatch should preserve operation architecture scope: %#v", got[0])
	}
}

func TestCapabilityMatchSeparatesExactArchitectureScopes(t *testing.T) {
	graph := behavior.Graph{}
	for _, arch := range []string{"x86_64", "arm64"} {
		scopeID := graph.AddScope(behavior.Scope{NodeID: "node-macho", Kind: "function", Function: "collect", Architecture: arch})
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: "node-macho",
			ScopeID:       scopeID,
			Kind:          "file.read", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.Resource{Kind: behavior.ResourceFile, Value: "~/Library/Application Support/Google/Chrome/Default/Cookies", Classifications: []behavior.ResourceClassification{behavior.ResourceClassBrowserCookieStore}})), Support: behavior.SupportCorroborated,
			Execution:      connectedExecution("root-main"),
			SourceFunction: "collect",
			Architecture:   arch,
		})
	}

	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSBrowserCredentialCollection})
	if len(got) != 2 {
		t.Fatalf("expected one capability match per exact architecture, got %#v", got)
	}
	for _, match := range got {
		if len(match.ArchitectureScopes) != 1 {
			t.Fatalf("capability match crossed architecture contexts: %#v", got)
		}
	}
}

func TestSupportedUnresolvedOperationBecomesUnresolvedCapabilityMatch(t *testing.T) {
	graph := behavior.Graph{}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001",
		Kind:          "credential.store.read", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.Resource{Kind: behavior.ResourceCredentialStore, Value: "", Classifications: []behavior.ResourceClassification{behavior.ResourceClassKeychain}})), Support: behavior.SupportCorroborated,
		Execution: unknownExecution(),
	})
	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSKeychainAccess})
	if len(got) != 1 || got[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("unresolved operation was hidden or promoted: %#v", got)
	}
}

func TestFunctionScopedUnresolvedOperationCanBecomeCapabilityMatch(t *testing.T) {
	graph := behavior.Graph{}
	scopeID := graph.AddScope(behavior.Scope{NodeID: "node-0001", Kind: "function", Function: "helper"})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001",
		ScopeID:       scopeID,
		Kind:          "credential.store.read", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.Resource{Kind: behavior.ResourceCredentialStore, Value: "", Classifications: []behavior.ResourceClassification{behavior.ResourceClassKeychain}})), Support: behavior.SupportCorroborated,
		Execution:      unknownExecution(),
		SourceFunction: "helper",
	})
	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSKeychainAccess})
	if len(got) != 1 {
		t.Fatalf("function-scoped unresolved operation should produce an honest capabilityMatch: %#v", got)
	}
	if got[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("capabilityMatch should preserve unknown connectivity: %#v", got[0])
	}
}

func TestNativeProcessExecutionRequiresSharedCallEvidenceInExactContext(t *testing.T) {
	fixture := func(featureKey string) behavior.Graph {
		return behavior.Graph{
			Features: []behavior.Feature{{
				ID: "feature-call", NodeID: "node-macho", ScopeID: "scope-main", Architecture: "arm64",
				Key: featureKey, Value: "system", EvidenceIDs: []string{"ev-call", "ev-feature-context"}, Support: behavior.SupportDirect,
				Execution: connectedExecution("root-main"), SourceFunction: "main",
			}},
			Operations: []behavior.ModeledOperation{{
				ID: "operation-execute", SubjectNodeID: "node-macho", ScopeID: "scope-main", Architecture: "arm64",
				Kind: behavior.OperationProcessExecute, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/bin/sh"))),
				EvidenceIDs: []string{"ev-call"}, Support: behavior.SupportCorroborated,
				Execution: connectedExecution("root-main"), SourceFunction: "main",
			}},
		}
	}

	for _, featureKey := range []string{"macho.import_call", "objc.message_call"} {
		graph := fixture(featureKey)
		got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSNativeProcessExecution})
		if len(got) != 1 || got[0].SubjectNodeID != "node-macho" || got[0].Support != behavior.SupportCorroborated || !slices.Contains(got[0].EvidenceIDs, "ev-feature-context") {
			t.Fatalf("%s native match = %#v", featureKey, got)
		}
	}

	tests := []struct {
		name   string
		mutate func(*behavior.Graph)
	}{
		{name: "function name alone", mutate: func(graph *behavior.Graph) { graph.Features = nil }},
		{name: "different evidence", mutate: func(graph *behavior.Graph) { graph.Features[0].EvidenceIDs = []string{"ev-other"} }},
		{name: "different node", mutate: func(graph *behavior.Graph) { graph.Features[0].NodeID = "node-other" }},
		{name: "different scope", mutate: func(graph *behavior.Graph) { graph.Features[0].ScopeID = "scope-other" }},
		{name: "empty scope", mutate: func(graph *behavior.Graph) { graph.Features[0].ScopeID = ""; graph.Operations[0].ScopeID = "" }},
		{name: "different architecture", mutate: func(graph *behavior.Graph) { graph.Features[0].Architecture = "x86_64" }},
		{name: "different root", mutate: func(graph *behavior.Graph) { graph.Features[0].Execution = connectedExecution("root-other") }},
		{name: "heuristic feature", mutate: func(graph *behavior.Graph) { graph.Features[0].Support = behavior.SupportHeuristic }},
		{name: "malformed feature context", mutate: func(graph *behavior.Graph) {
			graph.Features[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph := fixture("macho.import_call")
			test.mutate(&graph)
			if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSNativeProcessExecution}); len(got) != 0 {
				t.Fatalf("close negative emitted native capability: %#v", got)
			}
		})
	}
}

func TestNetworkCommunicationGroupsReportableOperationsByResource(t *testing.T) {
	graph := behavior.Graph{}
	firstEvidence := graph.AddEvidence(behavior.Evidence{NodeID: "node-client", Value: "requests.post"})
	secondEvidence := graph.AddEvidence(behavior.Evidence{NodeID: "node-client", Value: "requests.get"})
	connectID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-client", Kind: "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://api.example/v1"})), EvidenceIDs: []string{firstEvidence},
		Support:      behavior.SupportCorroborated,
		Execution:    connectedExecution("root-main"),
		Architecture: "arm64",
	})
	uploadID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-client", Kind: "network.upload", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://api.example/v1"})), EvidenceIDs: []string{secondEvidence},
		Support:      behavior.SupportCorroborated,
		Execution:    connectedExecution("root-main"),
		Architecture: "x86_64",
	})
	downloadID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-client", Kind: "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://cdn.example/payload"))),
		EvidenceIDs: []string{secondEvidence},
		Support:     behavior.SupportCorroborated,
		Execution:   connectedExecution("root-main"),
	})

	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSNetworkCommunication})
	if len(got) != 3 {
		t.Fatalf("network communication matches = %#v, want architecture-safe destination groups", got)
	}
	if !hasCapabilitySupport(got, connectID, "arm64") || !hasCapabilitySupport(got, uploadID, "x86_64") {
		t.Fatalf("same destination from different architectures was incorrectly merged: %#v", got)
	}
	var downloadFound bool
	for _, match := range got {
		downloadFound = downloadFound || sameStrings(match.OperationIDs, []string{downloadID}) && hasResource(match.AffectedResources, "network-destination", "https://cdn.example/payload")
	}
	if !downloadFound {
		t.Fatalf("file-targeted download did not expose its destination as network communication: %#v", got)
	}
	for _, item := range got {
		if item.Namespace != "macos.communication" || len(item.Attack) != 0 || len(item.MBC) != 0 {
			t.Fatalf("neutral network primitive must use the communication namespace without tactic mappings: %#v", item)
		}
	}
}

func TestFileExecutionGroupsOnlyConcreteFileOperations(t *testing.T) {
	graph := behavior.Graph{}
	firstEvidence := graph.AddEvidence(behavior.Evidence{NodeID: "node-script", Value: "subprocess.Popen"})
	secondEvidence := graph.AddEvidence(behavior.Evidence{NodeID: "node-script", Value: "os.system"})
	firstID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})), EvidenceIDs: []string{firstEvidence},
		Support:      behavior.SupportCorroborated,
		Execution:    connectedExecution("root-main"),
		Architecture: "arm64",
	})
	secondID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})), EvidenceIDs: []string{secondEvidence},
		Support:      behavior.SupportCorroborated,
		Execution:    connectedExecution("root-main"),
		Architecture: "x86_64",
	})
	cleanupScopeID := graph.AddScope(behavior.Scope{NodeID: "node-native", Kind: "function", Function: "cleanup"})
	functionID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-native", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/bin/rm"})), Support: behavior.SupportCorroborated,
		Execution:      unknownExecution(),
		ScopeID:        cleanupScopeID,
		SourceFunction: "cleanup",
	})
	mainScopeID := graph.AddScope(behavior.Scope{NodeID: "node-native", Kind: "function", Function: "main"})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-native", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: ""})), Support: behavior.SupportCorroborated,
		Execution:      connectedExecution("root-main"),
		ScopeID:        mainScopeID,
		SourceFunction: "main",
	})

	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSFileExecution})
	if len(got) != 3 {
		t.Fatalf("file execution matches = %#v, want architecture-safe script groups and a function-scoped group", got)
	}
	if !hasCapabilitySupport(got, firstID, "arm64") || !hasCapabilitySupport(got, secondID, "x86_64") {
		t.Fatalf("same-file execution operations crossed architecture contexts: %#v", got)
	}
	var functionFound bool
	for _, match := range got {
		functionFound = functionFound || sameStrings(match.OperationIDs, []string{functionID}) && match.Execution.Connectivity == behavior.ConnectivityUnknown
	}
	if !functionFound {
		t.Fatalf("function-scoped unknown file execution was not represented honestly: %#v", got)
	}
	for _, item := range got {
		if item.Namespace != "macos.execution" || len(item.Attack) != 0 || len(item.MBC) != 0 {
			t.Fatalf("neutral file-execution primitive must remain unmapped: %#v", item)
		}
	}
}

func TestPrimitiveCapabilityRulesRejectWeakOrMalformedOperations(t *testing.T) {
	graph := behavior.Graph{}
	graph.AddFeature(behavior.Feature{
		NodeID: "node", Key: "url", Value: "https://observable.example",
		Support: behavior.SupportCorroborated,
	})
	for _, operation := range []behavior.ModeledOperation{
		{SubjectNodeID: "node", Kind: "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: ""})), Support: behavior.SupportHeuristic, Execution: connectedExecution("root-main")},
		{SubjectNodeID: "node", Kind: "network.upload", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: ""})), Support: behavior.SupportCorroborated, Execution: unknownExecution()},
		{SubjectNodeID: "node", Kind: "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/not-a-destination"})), Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main")},
		{SubjectNodeID: "node", Kind: "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.Resource{Kind: behavior.ResourceFile, Value: "", Classifications: []behavior.ResourceClassification{behavior.ResourceClassArchive}})), Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main")},
		{SubjectNodeID: "node", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: ""})), Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main")},
		{SubjectNodeID: "node", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/possible"})), Support: behavior.SupportHeuristic, Execution: connectedExecution("root-main")},
		{SubjectNodeID: "node", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/unresolved"})), Support: behavior.SupportCorroborated, Execution: unknownExecution()},
		{SubjectNodeID: "node", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: ""})), Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"), SourceFunction: "main"},
	} {
		graph.AddOperation(operation)
	}

	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSNetworkCommunication}); len(got) != 1 || got[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("network rule did not retain exactly the supported unresolved operation: %#v", got)
	}
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSFileExecution}); len(got) != 1 || got[0].Execution.Connectivity != behavior.ConnectivityUnknown || !hasResource(got[0].AffectedResources, "file", "/tmp/unresolved") {
		t.Fatalf("file-execution rule did not retain exactly the supported unresolved file operation: %#v", got)
	}
}

func TestFileExecutionCapabilityProjectsExecutableBinding(t *testing.T) {
	graph := behavior.Graph{}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node", Kind: behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, "--install")),
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
		),
		Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
	})
	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSFileExecution})
	if len(got) != 1 || len(got[0].AffectedResources) != 1 || got[0].AffectedResources[0].Kind != behavior.ResourceFile || got[0].AffectedResources[0].Value != "/tmp/payload" {
		t.Fatalf("file-execution affected resources = %#v", got)
	}
}

func TestFileMakeExecutableRuleRequiresSupportedTypedOperation(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation behavior.ModeledOperation
		wantMatch bool
	}{
		{
			name: "corroborated file target",
			operation: behavior.ModeledOperation{
				ID: "operation-positive", SubjectNodeID: "node", Kind: behavior.OperationFileMakeExecutable,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, "/tmp/payload"))),
				Support:          behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
			},
			wantMatch: true,
		},
		{
			name: "heuristic operation",
			operation: behavior.ModeledOperation{
				ID: "operation-weak", SubjectNodeID: "node", Kind: behavior.OperationFileMakeExecutable,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, "/tmp/possible"))),
				Support:          behavior.SupportHeuristic, Execution: connectedExecution("root-main"),
			},
		},
		{
			name: "wrong physical resource kind",
			operation: behavior.ModeledOperation{
				ID: "operation-wrong-kind", SubjectNodeID: "node", Kind: behavior.OperationFileMakeExecutable,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceCommand, "chmod +x /tmp/payload"))),
				Support:          behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := behavior.Graph{Operations: []behavior.ModeledOperation{test.operation}}
			got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSFileMakeExecutable})
			if !test.wantMatch {
				if len(got) != 0 {
					t.Fatalf("unexpected file-make-executable match: %#v", got)
				}
				return
			}
			if len(got) != 1 || !sameStrings(got[0].OperationIDs, []string{"operation-positive"}) ||
				!hasResource(got[0].AffectedResources, "file", "/tmp/payload") {
				t.Fatalf("file-make-executable match lost its typed operation or target: %#v", got)
			}
		})
	}
}

func TestCredentialPromptRuleRequiresSupportedTypedOperation(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation behavior.ModeledOperation
		wantMatch bool
	}{
		{
			name: "corroborated credential prompt",
			operation: behavior.ModeledOperation{
				ID: "operation-positive", SubjectNodeID: "node", Kind: behavior.OperationCredentialPrompt,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleCredential, behavior.NewResource(behavior.ResourceCredential, ""))),
				EvidenceIDs:      []string{"ev-prompt"}, Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
			},
			wantMatch: true,
		},
		{
			name: "heuristic operation",
			operation: behavior.ModeledOperation{
				ID: "operation-weak", SubjectNodeID: "node", Kind: behavior.OperationCredentialPrompt,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleCredential, behavior.NewResource(behavior.ResourceCredential, ""))),
				Support:          behavior.SupportHeuristic, Execution: connectedExecution("root-main"),
			},
		},
		{
			name: "wrong physical resource kind",
			operation: behavior.ModeledOperation{
				ID: "operation-wrong-kind", SubjectNodeID: "node", Kind: behavior.OperationCredentialPrompt,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleCredential, behavior.NewResource(behavior.ResourceCredentialStore, "login.keychain-db"))),
				Support:          behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := behavior.Graph{Operations: []behavior.ModeledOperation{test.operation}}
			got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSCredentialPrompt})
			if !test.wantMatch {
				if len(got) != 0 {
					t.Fatalf("unexpected credential-prompt match: %#v", got)
				}
				return
			}
			if len(got) != 1 || !sameStrings(got[0].OperationIDs, []string{"operation-positive"}) ||
				!sameStrings(got[0].EvidenceIDs, []string{"ev-prompt"}) || got[0].Support != behavior.SupportCorroborated {
				t.Fatalf("credential-prompt match lost its typed operation evidence: %#v", got)
			}
		})
	}
}

func TestPrimitiveCapabilityRulesEvaluateDeterministically(t *testing.T) {
	graph := behavior.Graph{}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node", Kind: "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://api.example"})), Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})), Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
	})

	forward := evaluateCompiledRules(&graph, []compiledSpec{{spec: MacOSNetworkCommunication}, {spec: MacOSFileExecution}})
	reverse := evaluateCompiledRules(&graph, []compiledSpec{{spec: MacOSFileExecution}, {spec: MacOSNetworkCommunication}})
	if !reflect.DeepEqual(forward, reverse) {
		t.Fatalf("primitive capability output depends on rule registration order:\nforward=%#v\nreverse=%#v", forward, reverse)
	}
}

func TestConnectedSensitiveFeatureAndNetworkOperationStayIndependent(t *testing.T) {
	graph := behavior.Graph{}
	resourceEvidence := graph.AddEvidence(behavior.Evidence{NodeID: "node-macho", Value: "~/Library/Application Support/Google/Chrome/Default/Cookies", Function: "collect", Arch: "arm64"})
	networkEvidence := graph.AddEvidence(behavior.Evidence{NodeID: "node-macho", Value: "collect -> curl_easy_perform", Function: "collect", Arch: "arm64"})
	graph.AddFeature(behavior.Feature{
		NodeID:         "node-macho",
		ScopeID:        "scope-collect",
		Key:            "macho.sensitive_resource",
		Value:          "~/Library/Application Support/Google/Chrome/Default/Cookies",
		Architecture:   "arm64",
		Qualifiers:     map[string]string{"category": "browser.cookies", "function": "collect"},
		EvidenceIDs:    []string{resourceEvidence},
		Support:        behavior.SupportCorroborated,
		Execution:      connectedExecution("root-main"),
		SourceFunction: "collect",
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-macho",
		ScopeID:       "scope-collect",
		Kind:          "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: ""})), EvidenceIDs: []string{networkEvidence},
		Support:        behavior.SupportCorroborated,
		Execution:      connectedExecution("root-main"),
		SourceFunction: "collect",
		Architecture:   "arm64",
	})

	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSBrowserCredentialCollection}); len(got) != 0 {
		t.Fatalf("shared execution ownership does not bind a sensitive feature to an unrelated operation: %#v", got)
	}
}

func TestGenericMachOFileReadDoesNotBindSensitiveFeature(t *testing.T) {
	graph := behavior.Graph{}
	resourceEvidence := graph.AddEvidence(behavior.Evidence{NodeID: "node-macho", Value: "~/Library/Application Support/Google/Chrome/Default/Cookies", Function: "collect"})
	readEvidence := graph.AddEvidence(behavior.Evidence{NodeID: "node-macho", Value: "collect -> sqlite3_open", Function: "collect"})
	graph.AddFeature(behavior.Feature{
		NodeID:         "node-macho",
		ScopeID:        "scope-collect",
		Key:            "macho.sensitive_resource",
		Value:          "~/Library/Application Support/Google/Chrome/Default/Cookies",
		Qualifiers:     map[string]string{"category": "browser.cookies", "function": "collect"},
		EvidenceIDs:    []string{resourceEvidence},
		Support:        behavior.SupportCorroborated,
		Execution:      connectedExecution("root-main"),
		SourceFunction: "collect",
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-macho",
		ScopeID:       "scope-collect",
		Kind:          "file.read", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.Resource{Kind: behavior.ResourceFile, Value: ""})), EvidenceIDs: []string{readEvidence},
		Support:        behavior.SupportCorroborated,
		Execution:      connectedExecution("root-main"),
		SourceFunction: "collect",
	})

	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSBrowserCredentialCollection}); len(got) != 0 {
		t.Fatalf("generic file.read without the sensitive resource binding must not become collection: %#v", got)
	}
}

func TestUncorroboratedMachOSensitiveResourceStaysFeature(t *testing.T) {
	graph := behavior.Graph{}
	resourceEvidence := graph.AddEvidence(behavior.Evidence{NodeID: "node-macho", Value: "~/Library/Application Support/Google/Chrome/Default/Cookies"})
	graph.AddFeature(behavior.Feature{
		NodeID:      "node-macho",
		Key:         "macho.sensitive_resource",
		Value:       "~/Library/Application Support/Google/Chrome/Default/Cookies",
		Qualifiers:  map[string]string{"category": "browser.cookies"},
		EvidenceIDs: []string{resourceEvidence},
		Support:     behavior.SupportCorroborated,
	})

	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSBrowserCredentialCollection}); len(got) != 0 {
		t.Fatalf("uncorroborated resource string should remain out of capabilityMatches: %#v", got)
	}
}

func TestScriptSensitiveFeatureAndWrappedArchiveCommandStayIndependent(t *testing.T) {
	graph := behavior.Graph{}
	resourceEvidence := graph.AddEvidence(behavior.Evidence{NodeID: "node-script", Value: "~/.ssh/id_rsa"})
	commandEvidence := graph.AddEvidence(behavior.Evidence{NodeID: "node-script", Value: `sudo -E env PATH=/usr/bin command tar -czf "/tmp/out.tgz" "$HOME/.ssh"`})
	graph.AddFeature(behavior.Feature{
		NodeID:      "node-script",
		ScopeID:     "scope-script",
		Key:         "script.sensitive_resource",
		Value:       "~/.ssh/id_rsa",
		Qualifiers:  map[string]string{"category": "ssh-private-key"},
		EvidenceIDs: []string{resourceEvidence},
		Support:     behavior.SupportCorroborated,
		Execution:   connectedExecution("root-main"),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script",
		ScopeID:       "scope-script",
		Kind:          "interpreter.invoke", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleArguments, behavior.Resource{Kind: behavior.ResourceCommand, Value: `sudo -E env PATH=/usr/bin command tar -czf "/tmp/out.tgz" "$HOME/.ssh"`}), behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "", behavior.ResourceClassInterpreter))), EvidenceIDs: []string{commandEvidence},
		Support:   behavior.SupportCorroborated,
		Execution: connectedExecution("root-main"),
	})

	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSCredentialMaterialCollection}); len(got) != 0 {
		t.Fatalf("a sensitive script feature and wrapped archive command must not become collection: %#v", got)
	}
}

func TestLifecycleNetworkUsesExecutionRootIdentity(t *testing.T) {
	graph := behavior.Graph{ExecutionRoots: []behavior.ExecutionRoot{
		{ID: "root-lifecycle", DeclarationNodeID: "node-pkg", Kind: "npm-script", Name: "postinstall"},
		{ID: "root-build", DeclarationNodeID: "node-pkg", Kind: "npm-script", Name: "build"},
	}}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-pkg",
		ScopeID:       "scope-lifecycle",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://lifecycle.example/p"})), Support: behavior.SupportDirect,
		Execution: connectedExecution("root-lifecycle"),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-pkg",
		ScopeID:       "scope-lifecycle",
		Kind:          "interpreter.invoke", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "sh", Classifications: []behavior.ResourceClassification{behavior.ResourceClassInterpreter}})), Support: behavior.SupportDirect,
		Execution: connectedExecution("root-lifecycle"),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-pkg",
		ScopeID:       "scope-build",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://build.example/p"})), Support: behavior.SupportDirect,
		Execution: connectedExecution("root-build"),
	})
	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: PackageJSONLifecycle})
	if len(got) != 2 {
		t.Fatalf("expected one match for each qualifying lifecycle operation, got %#v", got)
	}
	for _, match := range got {
		if !sameStrings(match.Execution.ExecutionRootIDs, []string{"root-lifecycle"}) || len(match.OperationIDs) != 1 {
			t.Fatalf("lifecycle match retained unrelated ownership or merged alternatives: %#v", got)
		}
	}
	if !hasResource(got[0].AffectedResources, "interpreter", "sh") && !hasResource(got[1].AffectedResources, "interpreter", "sh") {
		t.Fatalf("missing lifecycle interpreter resource: %#v", got)
	}
	if !hasResource(got[0].AffectedResources, "network-destination", "https://lifecycle.example/p") && !hasResource(got[1].AffectedResources, "network-destination", "https://lifecycle.example/p") {
		t.Fatalf("missing lifecycle network resource: %#v", got)
	}
}

func TestLifecycleExecutionDoesNotClaimSupplyChainCompromise(t *testing.T) {
	metadata := PackageJSONLifecycle.Metadata
	if len(metadata.Attack) != 0 {
		t.Fatalf("lifecycle execution must not claim ATT&CK supply-chain compromise: %#v", metadata.Attack)
	}
	if metadata.Namespace != "package.execution" {
		t.Fatalf("unexpected lifecycle namespace: %#v", metadata)
	}
}

func TestNPMImplicitNodeGypRequiresConnectedOperationAndExactRootKind(t *testing.T) {
	graph := behavior.Graph{ExecutionRoots: []behavior.ExecutionRoot{
		{ID: "root-gyp", DeclarationNodeID: "node-gyp", Kind: "npm-implicit-node-gyp-install", Name: "fixture"},
		{ID: "root-explicit", DeclarationNodeID: "node-package", Kind: "npm-script", Name: "install"},
	}}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-gyp",
		ScopeID:       "scope-gyp",
		Kind:          behavior.OperationInterpreterInvoke,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "node", behavior.ResourceClassInterpreter)),
			behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, "index.js")),
		),
		Support:   behavior.SupportCorroborated,
		Execution: connectedExecution("root-gyp"),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-package", ScopeID: "scope-explicit", Kind: behavior.OperationInterpreterInvoke,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "node", behavior.ResourceClassInterpreter))),
		Support:          behavior.SupportCorroborated,
		Execution:        connectedExecution("root-explicit"),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-unconnected", ScopeID: "scope-unconnected", Kind: behavior.OperationInterpreterInvoke,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "node", behavior.ResourceClassInterpreter))),
		Support:          behavior.SupportCorroborated,
		Execution:        behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
	})

	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: PackageNPMImplicitNodeGyp})
	if len(got) != 1 || !sameStrings(got[0].Execution.ExecutionRootIDs, []string{"root-gyp"}) || !sameStrings(got[0].OperationIDs, []string{"operation-0001"}) {
		t.Fatalf("implicit node-gyp rule matched the wrong operation/root context: %#v", got)
	}
	if len(got[0].Attack) != 0 || len(got[0].MBC) != 0 {
		t.Fatalf("implicit node-gyp selection must not claim maliciousness mappings: %#v", got[0])
	}
}

func TestProcessMemoryReadRemainsNeutralPrimitive(t *testing.T) {
	graph := behavior.Graph{}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-macho",
		ScopeID:       "scope-read",
		Kind:          "process.memory.read", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTargetProcess, behavior.Resource{Kind: behavior.ResourceProcess, Value: ""})), Support: behavior.SupportCorroborated,
		Execution:      connectedExecution("root-main"),
		SourceFunction: "inspect",
	})
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSProcessMemory}); len(got) != 1 || len(got[0].Attack) != 0 {
		t.Fatalf("memory access should remain an unmapped primitive capabilityMatch: %#v", got)
	}
}

func TestProcessMemoryRuleDoesNotPromoteOtherProcessPrimitives(t *testing.T) {
	graph := behavior.Graph{}
	for _, kind := range []behavior.OperationKind{behavior.OperationProcessMemoryWrite, behavior.OperationProcessTaskAccess, behavior.OperationProcessThreadCreate} {
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: "node-macho",
			ScopeID:       "scope-inject",
			Kind:          kind,
			ResourceBindings: behavior.Bindings(behavior.Bind(
				behavior.ResourceRoleTargetProcess,
				behavior.NewResource(behavior.ResourceProcess, ""),
			)),
			Support:        behavior.SupportCorroborated,
			Execution:      connectedExecution("root-main"),
			SourceFunction: "inject",
		})
	}
	memory := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSProcessMemory})
	if len(memory) != 1 || !sameStrings(memory[0].OperationIDs, []string{"operation-0001"}) {
		t.Fatalf("process-memory capability should retain only the memory write: %#v", memory)
	}
	if _, ok := SpecByID("macos.remote-thread-creation"); ok {
		t.Fatal("legacy remote-thread capability must not return")
	}
	if len(memory[0].Attack) != 0 || len(memory[0].MBC) != 0 || len(memory[0].OperationIDs) != 1 {
		t.Fatalf("process-memory primitive must remain unmapped and operation-backed: %#v", memory[0])
	}
}

func TestLifecycleNetworkIncludesPrepareHooks(t *testing.T) {
	for _, hook := range []string{"preprepare", "prepare", "postprepare"} {
		t.Run(hook, func(t *testing.T) {
			graph := behavior.Graph{ExecutionRoots: []behavior.ExecutionRoot{{ID: "root-lifecycle", DeclarationNodeID: "node-pkg", Kind: "npm-script", Name: hook}}}
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID: "node-pkg",
				ScopeID:       "scope-lifecycle",
				Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://prepare.example/p"})), Support: behavior.SupportDirect,
				Execution: connectedExecution("root-lifecycle"),
			})
			if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: PackageJSONLifecycle}); len(got) != 1 {
				t.Fatalf("expected %s lifecycle network capabilityMatch, got %#v", hook, got)
			}
		})
	}
}

func TestLifecycleNetworkExcludesPrepack(t *testing.T) {
	graph := behavior.Graph{ExecutionRoots: []behavior.ExecutionRoot{{ID: "root-prepack", DeclarationNodeID: "node-pkg", Kind: "npm-script", Name: "prepack"}}}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-pkg",
		ScopeID:       "scope-prepack",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://prepack.example/p"})), Support: behavior.SupportDirect,
		Execution: connectedExecution("root-prepack"),
	})
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: PackageJSONLifecycle}); len(got) != 0 {
		t.Fatalf("prepack is not part of npm install lifecycle, got %#v", got)
	}
}

func TestPackageJSONLifecycleDoesNotMatchFlatPKGScripts(t *testing.T) {
	graph := behavior.Graph{ExecutionRoots: []behavior.ExecutionRoot{{ID: "root-pkg-script", DeclarationNodeID: "node-pkg-script", Kind: "pkg-script", Name: "postinstall"}}}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-pkg-script",
		ScopeID:       "scope-pkg-script",
		Kind:          "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://flat-pkg.example/p"})), Support: behavior.SupportCorroborated,
		Execution: connectedExecution("root-pkg-script"),
	})
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: PackageJSONLifecycle}); len(got) != 0 {
		t.Fatalf("flat-PKG script must not become a package.json lifecycle match: %#v", got)
	}
}

func TestPackageJSONLifecycleDoesNotTreatInvokedTargetKindAsExecutionRoot(t *testing.T) {
	graph := behavior.Graph{ExecutionRoots: []behavior.ExecutionRoot{{
		ID: "root-invalid", DeclarationNodeID: "node-helper", Kind: "lifecycle-target", Name: "postinstall",
	}}}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-helper",
		ScopeID:       "scope-helper",
		Kind:          "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://example.invalid"})), Support: behavior.SupportCorroborated,
		Execution: connectedExecution("root-invalid"),
	})
	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: PackageJSONLifecycle}); len(got) != 0 {
		t.Fatalf("invoked-target kind must not be accepted as an npm lifecycle execution root: %#v", got)
	}
}

func TestLifecycleNetworkProjectsInheritedRootAndTargetPerOperation(t *testing.T) {
	graph := behavior.Graph{
		ExecutionRoots: []behavior.ExecutionRoot{{ID: "root-lifecycle", DeclarationNodeID: "node-pkg", Kind: "npm-script", Name: "postinstall"}},
		InvokedTargets: []behavior.InvokedTarget{{ID: "target-helper", NodeID: "node-helper", Kind: "lifecycle-target", Execution: connectedExecution("root-lifecycle")}},
	}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-helper",
		ScopeID:       "scope-helper",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://postinstall-target.example/p"})), Support: behavior.SupportDirect,
		Execution: connectedExecutionWithTargets([]string{"root-lifecycle"}, []string{"target-helper"}),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-helper",
		ScopeID:       "scope-helper",
		Kind:          "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "./helper"})), Support: behavior.SupportDirect,
		Execution: connectedExecutionWithTargets([]string{"root-lifecycle"}, []string{"target-helper"}),
	})
	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: PackageJSONLifecycle})
	if len(got) != 2 {
		t.Fatalf("expected one match per lifecycle target operation, got %#v", got)
	}
	for _, match := range got {
		if !sameStrings(match.Execution.ExecutionRootIDs, []string{"root-lifecycle"}) || !sameStrings(match.Execution.InvokedTargetIDs, []string{"target-helper"}) || len(match.OperationIDs) != 1 {
			t.Fatalf("wrong lifecycle target ownership: %#v", got)
		}
	}
	if !hasResource(got[0].AffectedResources, "network-destination", "https://postinstall-target.example/p") && !hasResource(got[1].AffectedResources, "network-destination", "https://postinstall-target.example/p") {
		t.Fatalf("missing lifecycle target network resource: %#v", got)
	}
	if !hasResource(got[0].AffectedResources, "file", "./helper") && !hasResource(got[1].AffectedResources, "file", "./helper") {
		t.Fatalf("missing lifecycle target executable resource: %#v", got)
	}
}

func TestPackageLifecycleProjectsOnlyQualifyingRootsAndCompatibleTargets(t *testing.T) {
	graph := behavior.Graph{
		ExecutionRoots: []behavior.ExecutionRoot{
			{ID: "root-lifecycle", DeclarationNodeID: "node-pkg", Kind: "npm-script", Name: "postinstall", EvidenceIDs: []string{"ev-root-lifecycle"}},
			{ID: "root-build", DeclarationNodeID: "node-pkg", Kind: "npm-script", Name: "build", EvidenceIDs: []string{"ev-root-build"}},
		},
		InvokedTargets: []behavior.InvokedTarget{
			{ID: "target-lifecycle", NodeID: "node-helper", Kind: "script", Execution: connectedExecution("root-lifecycle")},
			{ID: "target-build", NodeID: "node-helper", Kind: "script", Execution: connectedExecution("root-build")},
		},
		Operations: []behavior.ModeledOperation{{
			ID: "operation", SubjectNodeID: "node-helper", ScopeID: "scope-helper", Kind: "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://example.invalid/payload"})), Support: behavior.SupportCorroborated,
			EvidenceIDs: []string{"ev-operation"}, Execution: connectedExecutionWithTargets([]string{"root-build", "root-lifecycle"}, []string{"target-build", "target-lifecycle"}),
		}},
	}
	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: PackageJSONLifecycle})
	if len(got) != 1 || !sameStrings(got[0].Execution.ExecutionRootIDs, []string{"root-lifecycle"}) || !sameStrings(got[0].Execution.InvokedTargetIDs, []string{"target-lifecycle"}) {
		t.Fatalf("lifecycle match retained unrelated root or target ownership: %#v", got)
	}
	if !sameStrings(got[0].EvidenceIDs, []string{"ev-operation", "ev-root-lifecycle"}) {
		t.Fatalf("lifecycle match did not project exact operation and qualifying-root evidence: %#v", got)
	}
}

func TestPackageLifecycleRejectsWeakAndMalformedOperationContext(t *testing.T) {
	graph := behavior.Graph{ExecutionRoots: []behavior.ExecutionRoot{{ID: "root-lifecycle", Kind: "npm-script", Name: "install", EvidenceIDs: []string{"ev-root"}}}}
	operation := func(id string, support behavior.Support, scope string, execution behavior.ExecutionContext) behavior.ModeledOperation {
		return behavior.ModeledOperation{
			ID: id, SubjectNodeID: "node-pkg", ScopeID: scope, Kind: behavior.OperationNetworkConnect,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/"+id))),
			EvidenceIDs:      []string{"ev-" + id}, Support: support, Execution: execution,
		}
	}
	graph.Operations = []behavior.ModeledOperation{
		operation("operation-valid", behavior.SupportCorroborated, "scope-install", connectedExecution("root-lifecycle")),
		operation("operation-heuristic", behavior.SupportHeuristic, "scope-install", connectedExecution("root-lifecycle")),
		operation("operation-unknown", behavior.SupportCorroborated, "scope-install", unknownExecution()),
		operation("operation-malformed", behavior.SupportCorroborated, "scope-install", behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected}),
		operation("operation-unscoped", behavior.SupportCorroborated, "", connectedExecution("root-lifecycle")),
	}
	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: PackageJSONLifecycle})
	if len(got) != 1 || !sameStrings(got[0].OperationIDs, []string{"operation-valid"}) {
		t.Fatalf("lifecycle root join accepted weak or malformed operation context: %#v", got)
	}
}

func TestPackageLifecycleRootJoinIsDeterministicAndBounded(t *testing.T) {
	const operationCount = 1100
	graph := behavior.Graph{ExecutionRoots: []behavior.ExecutionRoot{{ID: "root-lifecycle", Kind: "npm-script", Name: "postinstall", EvidenceIDs: []string{"ev-root"}}}}
	for index := 0; index < operationCount; index++ {
		graph.Operations = append(graph.Operations, behavior.ModeledOperation{
			ID: fmt.Sprintf("operation-%04d", index), SubjectNodeID: "node-pkg", ScopeID: "scope-install", Kind: behavior.OperationNetworkConnect,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, fmt.Sprintf("https://example.invalid/%04d", index)))),
			EvidenceIDs:      []string{fmt.Sprintf("ev-%04d", index)}, Support: behavior.SupportCorroborated, Execution: connectedExecution("root-lifecycle"),
		})
	}
	first := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: PackageJSONLifecycle})
	second := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: PackageJSONLifecycle})
	if len(first) != ruleCapabilityMatchCandidateLimit || !slices.EqualFunc(first, second, capabilityMatchesEqual) {
		t.Fatalf("bounded lifecycle root join is not deterministic: first=%d second=%d", len(first), len(second))
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "rule-evaluation" || graph.Coverage[0].Status != "partial" {
		t.Fatalf("bounded lifecycle root join did not mark partial coverage: %#v", graph.Coverage)
	}
}

func TestPromptAndValidationDoNotFormCompositeWithoutTypedIdentity(t *testing.T) {
	graph := behavior.Graph{}
	promptID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-credential",
		ScopeID:       "scope-credential",
		Kind:          "credential.prompt", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleCredential, behavior.Resource{Kind: behavior.ResourceCredential, Value: ""})), Support: behavior.SupportCorroborated,
		Execution: connectedExecution("root-main"),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-credential",
		ScopeID:       "scope-credential",
		Kind:          "credential.validate", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleCredential, behavior.Resource{Kind: behavior.ResourceCredential, Value: ""})), Support: behavior.SupportCorroborated,
		Execution: connectedExecution("root-main"),
	})
	got := Evaluate(&graph)
	if len(got) != 2 || !hasRuleOperation(got, "macos.credential-prompt", promptID) || !hasRuleOperation(got, "macos.credential-validation", "operation-0002") {
		t.Fatalf("prompt and validation without typed credential identity should remain independent primitives: %#v", got)
	}
}

func TestCredentialValidationPatternProjectsEvidenceAndRejectsCloseNegatives(t *testing.T) {
	valid := behavior.ModeledOperation{
		ID: "operation-valid", SubjectNodeID: "node-valid", ScopeID: "scope-valid",
		Kind: behavior.OperationCredentialValidate,
		ResourceBindings: behavior.Bindings(behavior.Bind(
			behavior.ResourceRoleCredential,
			behavior.NewResource(behavior.ResourceCredential, ""),
		)),
		EvidenceIDs: []string{"evidence-valid"}, Support: behavior.SupportCorroborated,
		Execution: connectedExecution("root-main"), Architecture: "arm64",
	}
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{
		valid,
		{
			ID: "operation-heuristic", SubjectNodeID: "node-heuristic", ScopeID: "scope-heuristic",
			Kind:             behavior.OperationCredentialValidate,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleCredential, behavior.NewResource(behavior.ResourceCredential, ""))),
			EvidenceIDs:      []string{"evidence-heuristic"}, Support: behavior.SupportHeuristic, Execution: connectedExecution("root-main"),
		},
		{
			ID: "operation-wrong-role", SubjectNodeID: "node-role", ScopeID: "scope-role",
			Kind:             behavior.OperationCredentialValidate,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceCredential, ""))),
			EvidenceIDs:      []string{"evidence-role"}, Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
		},
		{
			ID: "operation-wrong-resource", SubjectNodeID: "node-resource", ScopeID: "scope-resource",
			Kind:             behavior.OperationCredentialValidate,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleCredential, behavior.NewResource(behavior.ResourceFile, "/tmp/value"))),
			EvidenceIDs:      []string{"evidence-resource"}, Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
		},
		{
			ID: "operation-malformed-execution", SubjectNodeID: "node-execution", ScopeID: "scope-execution",
			Kind:             behavior.OperationCredentialValidate,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleCredential, behavior.NewResource(behavior.ResourceCredential, ""))),
			EvidenceIDs:      []string{"evidence-execution"}, Support: behavior.SupportCorroborated,
			Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected},
		},
	}}

	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSCredentialValidation})
	if len(got) != 1 || !sameStrings(got[0].OperationIDs, []string{"operation-valid"}) || !sameStrings(got[0].EvidenceIDs, []string{"evidence-valid"}) {
		t.Fatalf("credential-validation projection = %#v", got)
	}
	if len(got[0].AffectedResources) != 1 || got[0].AffectedResources[0].Kind != behavior.ResourceCredential {
		t.Fatalf("credential-validation resources = %#v", got[0].AffectedResources)
	}
}

func hasRuleOperation(matches []behavior.CapabilityMatch, ruleID, operationID string) bool {
	for _, match := range matches {
		if match.RuleID == ruleID && sameStrings(match.OperationIDs, []string{operationID}) {
			return true
		}
	}
	return false
}

func TestDownloadExecuteRequiresCompleteRelationPath(t *testing.T) {
	graph := behavior.Graph{}
	operationID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/p"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, ""))), Support: behavior.SupportDirect,
		Execution: connectedExecution("root-main"),
	})
	graph.Relations = append(graph.Relations, behavior.OperationRelation{
		Kind: behavior.RelationPrecedes,
		From: behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, operationID),
		To:   behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-missing"),
	})

	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSDownloadExecute}); len(got) != 0 {
		t.Fatalf("incomplete relation path should not produce capability match: %#v", got)
	}
}

func TestDownloadExecuteSupportDoesNotExceedSupportingOperations(t *testing.T) {
	graph := behavior.Graph{}
	downloadID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001", Kind: "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/p"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, ""))), Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
	})
	executeID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/p"})), Support: behavior.SupportDirect, Execution: connectedExecution("root-main"),
	})
	addDownloadExecuteTestRelations(&graph, downloadID, executeID)

	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSDownloadExecute})
	if len(got) != 1 || got[0].Support != behavior.SupportCorroborated {
		t.Fatalf("relation match support should be bounded by its weakest supporting fact: %#v", got)
	}
	for _, evidenceID := range []string{"ev-relation-0", "ev-relation-1", "ev-relation-2"} {
		if !slices.Contains(got[0].EvidenceIDs, evidenceID) {
			t.Fatalf("resource-flow match did not project required relation evidence %q: %#v", evidenceID, got)
		}
	}
}

func TestDownloadExecuteProjectsSharedPhysicalResource(t *testing.T) {
	graph := behavior.Graph{}
	downloadID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001", Kind: behavior.OperationNetworkDownload,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/p", behavior.ResourceClassArchive)),
			behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/p")),
		),
		Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
	})
	executeID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001", Kind: behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, "--install")),
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/tmp/p")),
		),
		Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
	})
	addDownloadExecuteTestRelations(&graph, downloadID, executeID)

	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSDownloadExecute})
	if len(got) != 1 || len(got[0].AffectedResources) != 1 || got[0].AffectedResources[0].Kind != behavior.ResourceFile || got[0].AffectedResources[0].Value != "/tmp/p" || !got[0].AffectedResources[0].HasClassification(behavior.ResourceClassArchive) {
		t.Fatalf("download-execute affected resources = %#v", got)
	}
}

func TestDownloadExecuteSupportsOnlyProvenInterpreterLocalInput(t *testing.T) {
	newGraph := func(role behavior.ResourceRole, execution behavior.ExecutionContext) (behavior.Graph, string, string) {
		var graph behavior.Graph
		downloadID := graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: "node-0001", ScopeID: "scope-main",
			Kind: behavior.OperationNetworkDownload,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/p")),
				behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/p")),
			),
			Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
		})
		bindings := behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "python", behavior.ResourceClassInterpreter)),
		)
		switch role {
		case behavior.ResourceRoleLocalInput:
			bindings = append(bindings, behavior.Bind(role, behavior.NewResource(behavior.ResourceFile, "/tmp/p")))
		case behavior.ResourceRoleStandardInput:
			bindings = append(bindings, behavior.Bind(role, behavior.NewResource(behavior.ResourceCommand, "sha256=fixture bytes=6")))
		case behavior.ResourceRoleExecutable:
			bindings[0] = behavior.Bind(role, behavior.NewResource(behavior.ResourceFile, "/tmp/p", behavior.ResourceClassInterpreter))
		}
		interpreterID := graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: "node-0001", ScopeID: "scope-main",
			Kind:             behavior.OperationInterpreterInvoke,
			ResourceBindings: bindings,
			Support:          behavior.SupportCorroborated,
			Execution:        execution,
		})
		return graph, downloadID, interpreterID
	}

	t.Run("local input", func(t *testing.T) {
		graph, downloadID, interpreterID := newGraph(behavior.ResourceRoleLocalInput, connectedExecution("root-main"))
		addDownloadConsumerTestRelations(&graph, downloadID, interpreterID, behavior.ResourceRoleLocalInput)
		got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSDownloadExecute})
		if len(got) != 1 || len(got[0].AffectedResources) != 1 || got[0].AffectedResources[0].Value != "/tmp/p" {
			t.Fatalf("downloaded interpreter input did not match exactly once: %#v", got)
		}
	})

	for name, role := range map[string]behavior.ResourceRole{
		"interpreter executable": behavior.ResourceRoleExecutable,
		"standard input":         behavior.ResourceRoleStandardInput,
	} {
		t.Run(name, func(t *testing.T) {
			graph, downloadID, interpreterID := newGraph(role, connectedExecution("root-main"))
			addDownloadConsumerTestRelations(&graph, downloadID, interpreterID, role)
			if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSDownloadExecute}); len(got) != 0 {
				t.Fatalf("%s was mistaken for an executed local input: %#v", name, got)
			}
		})
	}

	t.Run("incompatible root", func(t *testing.T) {
		graph, downloadID, interpreterID := newGraph(behavior.ResourceRoleLocalInput, connectedExecution("root-other"))
		addDownloadConsumerTestRelations(&graph, downloadID, interpreterID, behavior.ResourceRoleLocalInput)
		if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSDownloadExecute}); len(got) != 0 {
			t.Fatalf("incompatible execution roots matched download/interpreter flow: %#v", got)
		}
	})
}

func TestDownloadExecuteRejectsRelationsWithIncompatibleOperationContext(t *testing.T) {
	graph := behavior.Graph{}
	downloadID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001", Kind: "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/p"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, ""))), Support: behavior.SupportDirect, Execution: connectedExecution("root-main"),
	})
	executeID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/p"})), Support: behavior.SupportDirect,
		Execution:      unknownExecution(),
		SourceFunction: "main",
	})
	addDownloadExecuteTestRelations(&graph, downloadID, executeID)

	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSDownloadExecute})
	if len(got) != 0 {
		t.Fatalf("relations whose context conflicts with an endpoint operation must fail closed: %#v", got)
	}
}

func TestRelationRulesUseTypedKinds(t *testing.T) {
	graph := behavior.Graph{}
	downloadID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://pipe.example/p"})), Support: behavior.SupportDirect,
		Execution: connectedExecution("root-main"),
	})
	execID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001",
		Kind:          "interpreter.invoke", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "sh", Classifications: []behavior.ResourceClassification{behavior.ResourceClassInterpreter}})), Support: behavior.SupportDirect,
		Execution: connectedExecution("root-main"),
	})
	addPipeTestRelation(&graph, downloadID, execID)

	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSDownloadExecute}); len(got) != 0 {
		t.Fatalf("typed pipe relation should not match the download-execute rule: %#v", got)
	}
	typed := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSDownloadPipeInterpreter})
	SortCapabilityMatches(typed)
	if len(typed) != 1 {
		t.Fatalf("typed pipe relation should match the pipe rule: %#v", typed)
	}
}

func TestPipeRelationPatternFailsClosedOnWeakOrMismatchedRelations(t *testing.T) {
	graph := behavior.Graph{}
	downloadID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001", ScopeID: "scope-main", Architecture: "arm64",
		Kind:             behavior.OperationNetworkDownload,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://pipe.example/p"))),
		EvidenceIDs:      []string{"ev-download"}, Support: behavior.SupportDirect, Execution: connectedExecution("root-main"),
	})
	interpreterID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001", ScopeID: "scope-main", Architecture: "arm64",
		Kind:             behavior.OperationInterpreterInvoke,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "sh", behavior.ResourceClassInterpreter))),
		EvidenceIDs:      []string{"ev-interpreter"}, Support: behavior.SupportDirect, Execution: connectedExecution("root-main"),
	})
	add := func(id string, from, to string, support behavior.Support, execution behavior.ExecutionContext, architecture string) {
		graph.Relations = append(graph.Relations, behavior.OperationRelation{
			ID: id, Kind: behavior.RelationPipesTo,
			From:        behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, from),
			To:          behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, to),
			EvidenceIDs: []string{"ev-" + id}, Support: support,
			Execution: execution, Architecture: architecture,
		})
	}
	add("relation-valid", downloadID, interpreterID, behavior.SupportCorroborated, connectedExecution("root-main"), "arm64")
	add("relation-reversed", interpreterID, downloadID, behavior.SupportDirect, connectedExecution("root-main"), "arm64")
	add("relation-heuristic", downloadID, interpreterID, behavior.SupportHeuristic, connectedExecution("root-main"), "arm64")
	add("relation-wrong-root", downloadID, interpreterID, behavior.SupportDirect, connectedExecution("root-other"), "arm64")
	add("relation-wrong-architecture", downloadID, interpreterID, behavior.SupportDirect, connectedExecution("root-main"), "x86_64")

	matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSDownloadPipeInterpreter})
	if len(matches) != 1 || matches[0].Support != behavior.SupportCorroborated || !slices.Contains(matches[0].EvidenceIDs, "ev-relation-valid") {
		t.Fatalf("relation pattern did not fail closed: %#v", matches)
	}
}

func TestPipeToInterpreterRequiresCompleteRelation(t *testing.T) {
	graph := behavior.Graph{}
	operationID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://pipe.example/p"})), Support: behavior.SupportDirect,
		Execution: connectedExecution("root-main"),
	})
	graph.Relations = append(graph.Relations, behavior.OperationRelation{
		Kind: behavior.RelationPipesTo,
		From: behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, operationID),
		To:   behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-missing"),
	})

	if got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSDownloadPipeInterpreter}); len(got) != 0 {
		t.Fatalf("incomplete relation should not produce capability match: %#v", got)
	}
}

func TestPipeToInterpreterBoundsHostileRelationCardinality(t *testing.T) {
	var graph behavior.Graph
	downloadID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001", Kind: behavior.OperationNetworkDownload,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://pipe.example/p"))),
		EvidenceIDs:      []string{"ev-download"}, Support: behavior.SupportDirect, Execution: connectedExecution("root-main"),
	})
	interpreterID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-0001", Kind: behavior.OperationInterpreterInvoke,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "sh", behavior.ResourceClassInterpreter))),
		EvidenceIDs:      []string{"ev-interpreter"}, Support: behavior.SupportDirect, Execution: connectedExecution("root-main"),
	})
	for index := 0; index < ruleCapabilityMatchCandidateLimit+100; index++ {
		graph.Relations = append(graph.Relations, behavior.OperationRelation{
			ID: fmt.Sprintf("relation-%04d", index), Kind: behavior.RelationPipesTo,
			From:        behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, downloadID),
			To:          behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, interpreterID),
			EvidenceIDs: []string{fmt.Sprintf("ev-relation-%04d", index)}, Support: behavior.SupportDirect,
			Execution: connectedExecution("root-main"),
		})
	}

	got := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSDownloadPipeInterpreter})
	if len(got) != ruleCapabilityMatchCandidateLimit {
		t.Fatalf("relation candidate count = %d, want %d", len(got), ruleCapabilityMatchCandidateLimit)
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "rule-evaluation" || graph.Coverage[0].Status != "partial" {
		t.Fatalf("hostile relation cardinality was not disclosed: %#v", graph.Coverage)
	}
}

func TestEvaluateEmitsOperationBackedCapabilityMatches(t *testing.T) {
	graph := behavior.Graph{
		ExecutionRoots: []behavior.ExecutionRoot{{ID: "root-main", DeclarationNodeID: "node", Kind: "npm-script", Name: "postinstall"}},
	}
	addOperation := func(kind behavior.OperationKind, resource behavior.Resource) string {
		id := fmt.Sprintf("operation-%04d", len(graph.Operations)+1)
		graph.Operations = append(graph.Operations, behavior.ModeledOperation{
			ID: id, SubjectNodeID: "node", ScopeID: "scope-main", Kind: kind,
			ResourceBindings: testRequiredBindings(kind, resource),
			Support:          behavior.SupportCorroborated, Execution: connectedExecution("root-main"),
			SourceFunction: "main",
		})
		return id
	}

	download := addOperation(behavior.OperationNetworkDownload, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload"))
	graph.Operations[len(graph.Operations)-1].ResourceBindings = append(graph.Operations[len(graph.Operations)-1].ResourceBindings,
		behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")))
	execute := addOperation(behavior.OperationProcessExecute, behavior.NewResource(behavior.ResourceFile, "/tmp/payload"))
	pipe := addOperation(behavior.OperationInterpreterInvoke, behavior.NewResource(behavior.ResourceFile, "sh", behavior.ResourceClassInterpreter))
	addDownloadExecuteTestRelations(&graph, download, execute)
	addPipeTestRelation(&graph, download, pipe)
	graph.Operations = append(graph.Operations, behavior.ModeledOperation{
		ID: "operation-shell", SubjectNodeID: "node", ScopeID: "scope-main", Kind: behavior.OperationInterpreterInvoke,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, "echo test")),
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "sh", behavior.ResourceClassInterpreter)),
		),
		Support: behavior.SupportCorroborated, Execution: connectedExecution("root-main"), SourceFunction: "main",
	})
	addOperation(behavior.OperationProcessExecute, behavior.NewResource(behavior.ResourceFile, "system"))
	addOperation(behavior.OperationFileMakeExecutable, behavior.NewResource(behavior.ResourceFile, "/tmp/payload"))
	addOperation(behavior.OperationPackageInstall, behavior.NewResource(behavior.ResourceFile, "/tmp/installer.pkg", behavior.ResourceClassPackage))
	addOperation(behavior.OperationCredentialPrompt, behavior.NewResource(behavior.ResourceCredential, ""))
	addOperation(behavior.OperationCredentialStoreRead, behavior.NewResource(behavior.ResourceCredentialStore, "", behavior.ResourceClassKeychain))
	addOperation(behavior.OperationFileRead, behavior.NewResource(behavior.ResourceFile, "~/Library/Cookies", behavior.ResourceClassBrowserCookieStore))
	addOperation(behavior.OperationFileRead, behavior.NewResource(behavior.ResourceFile, "~/.ssh/id_ed25519", behavior.ResourceClassSSHPrivateKey))
	addOperation(behavior.OperationLaunchdJobInstall, behavior.NewResource(behavior.ResourceLaunchdJob, "~/Library/LaunchAgents/example.plist", behavior.ResourceClassLaunchAgent))
	addOperation(behavior.OperationShellProfileModify, behavior.NewResource(behavior.ResourceFile, "~/.zshrc", behavior.ResourceClassShellProfile))
	addOperation(behavior.OperationLoginItemRegister, behavior.NewResource(behavior.ResourceLoginItem, "com.example.helper"))
	addOperation(behavior.OperationQuarantineAttributeRemove, behavior.NewResource(behavior.ResourceFile, "com.apple.quarantine"))
	addOperation(behavior.OperationGatekeeperConfigurationModify, behavior.NewResource(behavior.ResourceConfiguration, "disable"))
	addOperation(behavior.OperationClipboardRead, behavior.NewResource(behavior.ResourceClipboard, "pbpaste"))
	addOperation(behavior.OperationScreenCapture, behavior.NewResource(behavior.ResourceScreen, ""))
	addOperation(behavior.OperationProcessMemoryRead, behavior.NewResource(behavior.ResourceProcess, ""))
	addOperation(behavior.OperationNetworkConnect, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/install"))

	operations := make(map[string]behavior.ModeledOperation, len(graph.Operations))
	for _, operation := range graph.Operations {
		operations[operation.ID] = operation
	}
	for _, match := range Evaluate(&graph) {
		if len(match.OperationIDs) == 0 {
			t.Fatalf("capability match %s has no supporting operation IDs: %#v", match.RuleID, match)
		}
		subjectResolved := false
		for _, operationID := range match.OperationIDs {
			operation, ok := operations[operationID]
			if !ok {
				t.Fatalf("capability match %s references unknown operation %s", match.RuleID, operationID)
			}
			if operation.SubjectNodeID == match.SubjectNodeID {
				subjectResolved = true
			}
		}
		if !subjectResolved {
			t.Fatalf("capability match %s subject %s is not resolved by its operations: %#v", match.RuleID, match.SubjectNodeID, match.OperationIDs)
		}
	}
}

func hasResource(resources []behavior.Resource, category, concrete string) bool {
	for _, resource := range resources {
		if testResourceCategory(resource) == category && resource.Value == concrete {
			return true
		}
	}
	return false
}

func testResourceCategory(resource behavior.Resource) string {
	for _, classification := range resource.Classifications {
		switch classification {
		case behavior.ResourceClassArchive:
			return "archive"
		case behavior.ResourceClassBrowserCookieStore:
			return "browser.cookies"
		case behavior.ResourceClassBrowserPasswordStore:
			return "browser.password-store"
		case behavior.ResourceClassCloudCredentialStore:
			return "cloud-credentials"
		case behavior.ResourceClassCryptoWalletStore:
			return "crypto-wallet"
		case behavior.ResourceClassDeveloperTokenStore:
			return "developer-token"
		case behavior.ResourceClassKeychain:
			return "keychain"
		case behavior.ResourceClassPackage:
			return "package"
		case behavior.ResourceClassInterpreter:
			return "interpreter"
		case behavior.ResourceClassShellProfile:
			return "shell-profile"
		case behavior.ResourceClassSSHPrivateKey:
			return "ssh-private-key"
		}
	}
	switch resource.Kind {
	case behavior.ResourceURL, behavior.ResourceNetworkEndpoint:
		return "network-destination"
	case behavior.ResourceProcess, behavior.ResourceProcessMemory:
		return "process-memory"
	case behavior.ResourceScreen:
		return "screenshot"
	case behavior.ResourceConfiguration:
		return "gatekeeper"
	}
	return string(resource.Kind)
}

func testRequiredBindings(kind behavior.OperationKind, resource behavior.Resource) []behavior.ResourceBinding {
	for _, policy := range behavior.OperationResourcePolicy(kind) {
		if policy.Required && behavior.ValidOperationResourceRole(kind, policy.Role, resource.Kind) {
			return behavior.Bindings(behavior.Bind(policy.Role, resource))
		}
	}
	return nil
}

func addDownloadExecuteTestRelations(graph *behavior.Graph, downloadID, executeID string) {
	addDownloadConsumerTestRelations(graph, downloadID, executeID, behavior.ResourceRoleExecutable)
}

func addDownloadConsumerTestRelations(graph *behavior.Graph, downloadID, executeID string, consumerRole behavior.ResourceRole) {
	download, downloadOK := testOperationByID(graph.Operations, downloadID)
	execute, executeOK := testOperationByID(graph.Operations, executeID)
	output, outputOK := download.FirstBinding(behavior.ResourceRoleLocalOutput)
	consumer, consumerOK := execute.FirstBinding(consumerRole)
	if !downloadOK || !executeOK || !outputOK || !consumerOK {
		return
	}
	for index, relation := range []behavior.OperationRelation{
		{
			Kind: behavior.RelationProduces,
			From: behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, downloadID),
			To:   behavior.ResourceRelationEndpoint(output.Role, output.Resource),
		},
		{
			Kind: behavior.RelationConsumes,
			From: behavior.ResourceRelationEndpoint(consumer.Role, consumer.Resource),
			To:   behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, executeID),
		},
		{
			Kind: behavior.RelationPrecedes,
			From: behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, downloadID),
			To:   behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, executeID),
		},
	} {
		relation.EvidenceIDs = []string{fmt.Sprintf("ev-relation-%d", index)}
		relation.Support = weakerTestSupport(download.Support, execute.Support)
		relation.Execution = download.Execution
		relation.Architecture = download.Architecture
		graph.AddRelation(relation)
	}
}

func weakerTestSupport(left, right behavior.Support) behavior.Support {
	strength := func(value behavior.Support) int {
		switch value {
		case behavior.SupportDirect:
			return 3
		case behavior.SupportCorroborated:
			return 2
		case behavior.SupportHeuristic:
			return 1
		default:
			return 0
		}
	}
	if strength(left) <= strength(right) {
		return left
	}
	return right
}

func addPipeTestRelation(graph *behavior.Graph, downloadID, interpreterID string) {
	download, ok := testOperationByID(graph.Operations, downloadID)
	if !ok {
		return
	}
	graph.AddRelation(behavior.OperationRelation{
		Kind:        behavior.RelationPipesTo,
		From:        behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, downloadID),
		To:          behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, interpreterID),
		EvidenceIDs: []string{"ev-relation"}, Support: behavior.SupportDirect,
		Execution: download.Execution, Architecture: download.Architecture,
	})
}

func testOperationByID(operations []behavior.ModeledOperation, id string) (behavior.ModeledOperation, bool) {
	for _, operation := range operations {
		if operation.ID == id {
			return operation, true
		}
	}
	return behavior.ModeledOperation{}, false
}

func hasCapabilitySupport(matches []behavior.CapabilityMatch, operationID, architecture string) bool {
	for _, match := range matches {
		if sameStrings(match.OperationIDs, []string{operationID}) && sameStrings(match.ArchitectureScopes, []string{architecture}) {
			return true
		}
	}
	return false
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
