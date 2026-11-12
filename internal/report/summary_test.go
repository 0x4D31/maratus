package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestProjectSummaryRetainsCanonicalFactsWithoutInventingNetworkActivity(t *testing.T) {
	rep := Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test", Artifact: "fixture",
		Operations: []behavior.ModeledOperation{{
			ID: "op-1", SubjectNodeID: "node-1", Kind: behavior.OperationFileDelete,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, "/tmp/inert"))),
			Support:          behavior.SupportCorroborated, Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
		}},
		Features: []behavior.Feature{{
			ID: "feat-1", NodeID: "node-1", Key: "network.url", Value: "https://static.example/inert",
			EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportDirect,
		}},
		Evidence: []behavior.Evidence{{ID: "ev-1", NodeID: "node-1", Logical: "fixture", Line: 7, Method: "literal", Kind: "url", Value: "https://static.example/inert"}},
	}

	summary := ProjectSummary(rep)
	if summary.Overview.Operations != len(rep.Operations) || len(summary.ModeledBehavior) != 1 || len(summary.ModeledBehavior[0].OperationIDs) != 1 || summary.ModeledBehavior[0].OperationIDs[0] != "op-1" {
		t.Fatalf("summary operation projection = %#v", summary)
	}
	if len(summary.NetworkActivity) != 0 {
		t.Fatalf("static URL became network activity: %#v", summary.NetworkActivity)
	}
	if len(summary.StaticObservables) != 2 {
		t.Fatalf("static observable projection = %#v", summary.StaticObservables)
	}
	seen := map[string]SummaryObservable{}
	for _, item := range summary.StaticObservables {
		seen[item.Category] = item
	}
	if seen["URL"].Value != "https://static.example/inert" || seen["URL"].FeatureIDs[0] != "feat-1" || seen["domain"].Value != "static.example" || seen["domain"].FeatureIDs[0] != "feat-1" {
		t.Fatalf("URL/domain observable lineage = %#v", summary.StaticObservables)
	}
}

func TestProjectSummaryRetainsOnlyCoverageExceptions(t *testing.T) {
	rep := Report{Coverage: []behavior.Coverage{
		{NodeID: "node-1", AnalysisArea: "structure", Status: "analyzed", Detail: "complete"},
		{NodeID: "node-1", AnalysisArea: "calls", Status: "partial", Detail: "bounded decoding"},
		{NodeID: "node-2", AnalysisArea: "syntax", Status: "skipped", Detail: "unsupported input"},
	}}
	summary := ProjectSummary(rep)
	if summary.Overview.CoverageLimitations != 2 {
		t.Fatalf("coverage limitation count = %d, want 2", summary.Overview.CoverageLimitations)
	}
	if len(summary.CoverageGapsAndLimits) != 2 {
		t.Fatalf("summary coverage exceptions = %#v", summary.CoverageGapsAndLimits)
	}
	for _, item := range summary.CoverageGapsAndLimits {
		if item.Status == "analyzed" {
			t.Fatalf("routine analyzed coverage leaked into summary: %#v", summary.CoverageGapsAndLimits)
		}
	}
}

func TestSummaryPrivateKeyObservationDoesNotContainKeyBytes(t *testing.T) {
	const secret = "-----BEGIN PRIVATE KEY-----SUPER-SECRET-----END PRIVATE KEY-----"
	rep := Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test", Artifact: "fixture",
		Features: []behavior.Feature{{
			ID: "feat-key", NodeID: "node-1", Key: "cryptographic.private_key",
			Value: "PRIVATE KEY spki-sha256:0123456789abcdef", Support: behavior.SupportDirect,
			Qualifiers: map[string]string{"key_type": "PRIVATE KEY", "fingerprint": "0123456789abcdef", "secret_bytes": "redacted"},
		}},
	}
	var output bytes.Buffer
	if err := WriteSummaryJSON(&output, rep); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) || strings.Contains(output.String(), "BEGIN PRIVATE KEY") {
		t.Fatalf("summary exposed key material: %s", output.String())
	}
	var decoded Summary
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.StaticObservables) != 1 || !strings.Contains(decoded.StaticObservables[0].Value, "spki-sha256") {
		t.Fatalf("private-key fingerprint missing: %#v", decoded.StaticObservables)
	}
}

func TestSummaryCertificateObservationKeepsFingerprintStaticOnly(t *testing.T) {
	rep := Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test", Artifact: "fixture",
		Features: []behavior.Feature{{
			ID: "feat-cert", NodeID: "node-1", Key: "cryptographic.certificate",
			Value: "x509-certificate sha256:0123456789abcdef", Support: behavior.SupportDirect,
			Qualifiers: map[string]string{"fingerprint": "0123456789abcdef", "trust": "not-evaluated"},
		}},
	}
	summary := ProjectSummary(rep)
	if len(summary.StaticObservables) != 1 || summary.StaticObservables[0].Category != "complete X.509 certificate fingerprint" || !strings.Contains(summary.StaticObservables[0].Interpretation, "trust") {
		t.Fatalf("certificate projection = %#v", summary.StaticObservables)
	}
	if len(summary.ModeledBehavior) != 0 || len(summary.Capabilities) != 0 || len(summary.NetworkActivity) != 0 {
		t.Fatalf("certificate data became behavior: %#v", summary)
	}
}

func TestSummaryBehaviorResourceShowsLocalFlowWithoutRepeatingRemoteURL(t *testing.T) {
	archive := SummaryBehavior{Kind: behavior.OperationArchiveCreate, Resources: behavior.Bindings(
		behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "~/Library/Mail")),
		behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz")),
	)}
	if got := summaryBehaviorResource(archive); got != "~/Library/Mail → /tmp/data.tgz" {
		t.Fatalf("archive flow = %q", got)
	}
	upload := SummaryBehavior{Kind: behavior.OperationNetworkUpload, Resources: behavior.Bindings(
		behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz")),
		behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://upload.example/x")),
	)}
	if got := summaryBehaviorResource(upload); got != "/tmp/data.tgz" || strings.Contains(got, "upload.example") {
		t.Fatalf("upload local resource = %q", got)
	}
}

func TestProjectSummaryDoesNotCrossPairGroupedResources(t *testing.T) {
	rep := Report{SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test", Artifact: "fixture"}
	for index, pair := range [][2]string{{"/source/a", "/tmp/a.tgz"}, {"/source/b", "/tmp/b.tgz"}} {
		rep.Operations = append(rep.Operations, behavior.ModeledOperation{
			ID: "op-" + string(rune('1'+index)), SubjectNodeID: "node", Kind: behavior.OperationArchiveCreate,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, pair[0])),
				behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, pair[1])),
			),
			Support: behavior.SupportCorroborated,
		})
	}
	summary := ProjectSummary(rep)
	if len(summary.ModeledBehavior) != 2 {
		t.Fatalf("distinct archive flows were merged: %#v", summary.ModeledBehavior)
	}
	for _, row := range summary.ModeledBehavior {
		flow := summaryBehaviorResource(row)
		if flow != "/source/a → /tmp/a.tgz" && flow != "/source/b → /tmp/b.tgz" {
			t.Fatalf("cross-paired archive resources: %q", flow)
		}
	}
	textRows := summaryBehaviorTextRows(summary.ModeledBehavior)
	if len(textRows) != 1 || textRows[0].Count != 2 || textRows[0].Detail != "resources: /source/a → /tmp/a.tgz, /source/b → /tmp/b.tgz" {
		t.Fatalf("terminal behavior grouping = %#v", textRows)
	}
}

func TestSummaryBehaviorTextRowsListsBoundedProcessExecutables(t *testing.T) {
	var rows []SummaryBehavior
	for index, executable := range []string{"cp", "curl", "ps", "sh", "tar", "xattr", "zsh"} {
		rows = append(rows, SummaryBehavior{
			Kind: behavior.OperationProcessExecute, Count: 1, Support: behavior.SupportCorroborated,
			Connectivity: behavior.ConnectivityUnknown,
			Resources:    behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, executable))),
			OperationIDs: []string{fmt.Sprintf("operation-%d", index)}, Unresolved: []string{"variadic argv"},
		})
	}
	textRows := summaryBehaviorTextRows(rows)
	if len(textRows) != 1 || textRows[0].Detail != "executables: cp, curl, ps, sh, tar, xattr (+1 more) · variadic argv unresolved" {
		t.Fatalf("terminal executable detail = %#v", textRows)
	}
}

func TestSummaryBehaviorTextRowsKeepsProcessArgumentsOutOfExecutableLabel(t *testing.T) {
	rows := []SummaryBehavior{
		{
			Kind: behavior.OperationProcessExecute, Count: 1, Support: behavior.SupportHeuristic,
			Connectivity: behavior.ConnectivityConnected,
			Resources: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, `["--version"]`)),
				behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "")),
			),
		},
		{
			Kind: behavior.OperationProcessExecute, Count: 1, Support: behavior.SupportHeuristic,
			Connectivity: behavior.ConnectivityConnected,
			Resources: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "chmod")),
			),
		},
	}
	textRows := summaryBehaviorTextRows(rows)
	if len(textRows) != 1 || textRows[0].Detail != `commands/executables: <unresolved executable> argv ["--version"], chmod` {
		t.Fatalf("terminal command detail = %#v", textRows)
	}
}

func TestSummaryOperationUnresolvedIncludesExplicitArgumentGap(t *testing.T) {
	operation := behavior.ModeledOperation{Qualifiers: map[string]string{"argument_coverage": "executable-only", "unresolved_arguments": "variadic argv"}}
	if got := summaryOperationUnresolved(operation); !slices.Equal(got, []string{"variadic argv"}) {
		t.Fatalf("unresolved arguments = %#v", got)
	}
}

func TestSummaryOperationDoesNotInventGapForSingletonResource(t *testing.T) {
	operation := behavior.ModeledOperation{ResourceBindings: behavior.Bindings(
		behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceScreen, "")),
	)}
	if got := summaryOperationUnresolved(operation); len(got) != 0 {
		t.Fatalf("screen resource produced false unresolved fields: %#v", got)
	}
}

func TestSummaryOperationRetainsMoveDestinationOperandWithoutClaimingTargetIdentity(t *testing.T) {
	operation := behavior.ModeledOperation{
		Kind: behavior.OperationFileMove,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "/tmp/source")),
			behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, "")),
		),
		Qualifiers: map[string]string{"destination_operand": "/tmp/destination"},
	}
	if implementations := summaryOperationImplementations(operation); len(implementations) != 0 {
		t.Fatalf("move destination operand was misrepresented as an implementation: %#v", implementations)
	}
	if unresolved := summaryOperationUnresolved(operation); !slices.Contains(unresolved, "target (operand: /tmp/destination)") {
		t.Fatalf("ambiguous mv result lost its unresolved target: %#v", unresolved)
	}
}

func TestSummaryOperationRetainsUnresolvedLaunchdDestinationOperand(t *testing.T) {
	operation := behavior.ModeledOperation{
		Kind: behavior.OperationLaunchdJobInstall,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleJob, behavior.NewResource(behavior.ResourceLaunchdJob, "", behavior.ResourceClassLaunchAgent)),
		),
		Qualifiers: map[string]string{"destination_operand": "$HOME/Library/LaunchAgents/com.example.job.plist"},
	}
	want := "job (operand: $HOME/Library/LaunchAgents/com.example.job.plist)"
	if unresolved := summaryOperationUnresolved(operation); !slices.Contains(unresolved, want) {
		t.Fatalf("launchd destination operand missing from unresolved summary: %#v", unresolved)
	}
}

func TestProjectSummaryNetworkFallbackKeepsOperationDirectionAndSupport(t *testing.T) {
	rep := Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test", Artifact: "fixture",
		Operations: []behavior.ModeledOperation{{
			ID: "op-upload", SubjectNodeID: "node", Kind: behavior.OperationNetworkUpload,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://upload.example/x"))),
			Support:          behavior.SupportHeuristic,
		}},
	}
	summary := ProjectSummary(rep)
	if len(summary.NetworkActivity) != 1 || summary.NetworkActivity[0].Direction != "upload" || summary.NetworkActivity[0].Support != behavior.SupportHeuristic {
		t.Fatalf("network fallback projection = %#v", summary.NetworkActivity)
	}
}

func TestProjectSummarySurfacesExactCalledNetworkAPIWithoutInventingOperation(t *testing.T) {
	rep := Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test", Artifact: "fixture",
		NetworkImplementations: []behavior.NetworkImplementationObservation{{
			ID: "net-1", Kind: behavior.NetworkImplementationAPICall, SubjectNodeID: "node", ScopeID: "scope",
			APIOrTool: "connect", UnresolvedProperties: []string{"destination", "socket address family"},
			EvidenceIDs: []string{"ev-call"}, Support: behavior.SupportCorroborated,
		}},
	}
	summary := ProjectSummary(rep)
	if summary.Overview.Operations != 0 || len(summary.NetworkActivity) != 1 {
		t.Fatalf("network API projection = %#v", summary)
	}
	item := summary.NetworkActivity[0]
	if !item.StaticOnly || item.Implementation != "connect" || len(item.OperationIDs) != 0 || len(item.Destinations) != 0 || len(item.Unresolved) != 2 {
		t.Fatalf("network API observation = %#v", item)
	}
}

func TestProjectSummarySurfacesOperationImplementationAndUnresolvedBinding(t *testing.T) {
	rep := Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test", Artifact: "fixture",
		Operations: []behavior.ModeledOperation{{
			ID: "op-1", SubjectNodeID: "node", Kind: behavior.OperationProcessExecute,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, ""))),
			Qualifiers:       map[string]string{"api": "execve", "semantic_basis": "exact-called-import", "resource_binding": "unresolved"},
			Support:          behavior.SupportCorroborated,
		}},
	}
	summary := ProjectSummary(rep)
	if len(summary.ModeledBehavior) != 1 || !stringSliceContains(summary.ModeledBehavior[0].Implementations, "api: execve") || !stringSliceContains(summary.ModeledBehavior[0].Unresolved, "executable") {
		t.Fatalf("operation context = %#v", summary.ModeledBehavior)
	}
}

func TestProjectSummaryKeepsCapabilityArtifactLineageSeparate(t *testing.T) {
	rep := Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test", Artifact: "fixture",
		Evidence: []behavior.Evidence{
			{ID: "ev-a", NodeID: "node-a", Logical: "a", Method: "disassembly/imported-call", Kind: "call", Value: "_open"},
			{ID: "ev-b", NodeID: "node-b", Logical: "b", Method: "disassembly/imported-call", Kind: "call", Value: "_open"},
		},
		Operations: []behavior.ModeledOperation{
			{ID: "op-a", SubjectNodeID: "node-a", Kind: behavior.OperationFileOpen, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, ""))), Qualifiers: map[string]string{"api": "open", "resource_binding": "unresolved"}, EvidenceIDs: []string{"ev-a"}, Support: behavior.SupportCorroborated},
			{ID: "op-b", SubjectNodeID: "node-b", Kind: behavior.OperationFileOpen, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, ""))), Qualifiers: map[string]string{"api": "open", "resource_binding": "unresolved"}, EvidenceIDs: []string{"ev-b"}, Support: behavior.SupportCorroborated},
		},
		Capabilities: []behavior.CapabilityMatch{
			{ID: "cap-a", RuleID: "macos.file-open", Title: "Opens filesystem paths", Namespace: "macos.filesystem", SubjectNodeID: "node-a", OperationIDs: []string{"op-a"}, Support: behavior.SupportCorroborated},
			{ID: "cap-b", RuleID: "macos.file-open", Title: "Opens filesystem paths", Namespace: "macos.filesystem", SubjectNodeID: "node-b", OperationIDs: []string{"op-b"}, Support: behavior.SupportCorroborated},
		},
	}
	summary := ProjectSummary(rep)
	if len(summary.Capabilities) != 2 {
		t.Fatalf("distinct artifacts were merged: %#v", summary.Capabilities)
	}
	for _, item := range summary.Capabilities {
		if item.Count != 1 || len(item.SubjectNodeIDs) != 1 || len(item.Sources) != 1 || item.SubjectNodeIDs[0] != item.Sources[0].NodeID || !stringSliceContains(item.Implementations, "api: open") || !stringSliceContains(item.Unresolved, "source") {
			t.Fatalf("capability lineage = %#v", item)
		}
	}
}

func TestProjectSummaryRetainsProducerAndAnalysisProvenance(t *testing.T) {
	rep := Report{Tool: "maratus", ToolVersion: "test", ToolCommit: "0123456789abcdef", ToolModified: true, RulesetVersion: "rules-test", RuleCatalogDigest: strings.Repeat("a", 64), Analysis: AnalysisMetadata{Architecture: "arm64", MaxFileBytes: 1024, ExpandContainers: true, ZipPasswordSupplied: true}}
	summary := ProjectSummary(rep)
	if summary.ToolCommit != rep.ToolCommit || !summary.ToolModified || summary.RulesetVersion != rep.RulesetVersion || summary.RuleCatalogDigest != rep.RuleCatalogDigest || summary.Analysis != rep.Analysis {
		t.Fatalf("summary lost producer or analysis provenance: %#v", summary)
	}
	var output bytes.Buffer
	if err := WriteSummaryJSON(&output, rep); err != nil {
		t.Fatal(err)
	}
	var roundTrip Summary
	if err := json.Unmarshal(output.Bytes(), &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.ToolCommit != rep.ToolCommit || roundTrip.Analysis != rep.Analysis {
		t.Fatalf("JSON provenance = %#v", roundTrip)
	}
}

func TestProjectSummarySeparatesExecutionAndArchitectureContexts(t *testing.T) {
	rep := Report{}
	for index, context := range []struct{ node, root, arch, scope, resource string }{
		{"node-a", "root-a", "arm64", "scope-a", "/tmp/a"},
		{"node-a", "root-b", "arm64", "scope-a", "/tmp/a"},
		{"node-a", "root-a", "x86_64", "scope-b", "/tmp/a"},
		{"node-b", "root-c", "arm64", "scope-c", "/tmp/b"},
	} {
		execution := behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{context.root}, InvokedTargetIDs: []string{fmt.Sprintf("target-%d", index)}}
		resource := behavior.NewResource(behavior.ResourceFile, context.resource)
		opID := fmt.Sprintf("op-%d", index)
		rep.Operations = append(rep.Operations, behavior.ModeledOperation{ID: opID, SubjectNodeID: context.node, ScopeID: context.scope, Architecture: context.arch, Kind: behavior.OperationProcessExecute, Support: behavior.SupportCorroborated, Execution: execution, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, resource))})
		rep.Capabilities = append(rep.Capabilities, behavior.CapabilityMatch{ID: fmt.Sprintf("cap-%d", index), RuleID: "test.execute", SubjectNodeID: context.node, Support: behavior.SupportCorroborated, Execution: execution, ArchitectureScopes: []string{context.arch}, AffectedResources: []behavior.Resource{resource}, OperationIDs: []string{opID}})
	}
	summary := ProjectSummary(rep)
	if len(summary.ModeledBehavior) != 4 || len(summary.Capabilities) != 4 || len(summaryBehaviorTextRows(summary.ModeledBehavior)) != 4 {
		t.Fatalf("summary merged execution owners or architecture: %#v", summary)
	}
	for _, row := range summary.ModeledBehavior {
		if row.Count != 1 || len(row.Execution.ExecutionRootIDs) != 1 || len(row.Execution.InvokedTargetIDs) != 1 || row.Architecture == "" || row.ScopeID == "" {
			t.Fatalf("behavior context = %#v", row)
		}
	}
	for _, row := range summary.Capabilities {
		if row.Count != 1 || len(row.SubjectNodeIDs) != 1 || len(row.Execution.ExecutionRootIDs) != 1 || len(row.ArchitectureScopes) != 1 || len(row.AffectedResources) != 1 {
			t.Fatalf("capability context = %#v", row)
		}
	}
}

func TestSummaryRetainsRequestedArgumentsWithoutBindingExecutable(t *testing.T) {
	op := behavior.ModeledOperation{ID: "op", Kind: behavior.OperationProcessExecute, Qualifiers: map[string]string{"command_argument": "printf inert", "unresolved_process_options": "launch options", "api": "exec"}, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "")))}
	summary := ProjectSummary(Report{Operations: []behavior.ModeledOperation{op}})
	row := summary.ModeledBehavior[0]
	if !slices.Equal(row.RequestedArguments, []string{"command argument: printf inert"}) || !slices.Contains(row.Unresolved, "launch options") || row.Resources[0].Resource.Value != "" {
		t.Fatalf("requested argument was lost or promoted: %#v", row)
	}
	text := summaryBehaviorTextRows(summary.ModeledBehavior)[0].Detail
	if !strings.Contains(text, "command argument: printf inert") || strings.Contains(text, "executable: printf inert") {
		t.Fatalf("requested argument presentation = %q", text)
	}
}

func TestSummaryGroupingRetainsRequestedArgumentBoundaries(t *testing.T) {
	base := behavior.ModeledOperation{ID: "operation-a", Kind: behavior.OperationProcessExecute}
	left, right := base, base
	right.ID = "operation-b"
	left.Qualifiers = map[string]string{"command_argument": "a\x00executable argument: b"}
	right.Qualifiers = map[string]string{"command_argument": "a", "executable_argument": "b"}
	if rows := projectBehavior(Report{Operations: []behavior.ModeledOperation{left, right}}); len(rows) != 2 {
		t.Fatalf("requested operand boundaries were merged: %#v", rows)
	}
	first := behavior.ResourceBinding{Role: behavior.ResourceRoleSource, Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: "x\x00y", Classifications: []behavior.ResourceClassification{"z"}}}
	second := behavior.ResourceBinding{Role: behavior.ResourceRoleSource, Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: "x", Classifications: []behavior.ResourceClassification{"y\x00z"}}}
	if summaryBindingIdentity([]behavior.ResourceBinding{first}) == summaryBindingIdentity([]behavior.ResourceBinding{second}) {
		t.Fatal("summary resource field boundaries collided")
	}
}

func TestSummaryPrioritizesConcreteBehaviorBeforeUnresolvedInventory(t *testing.T) {
	rep := Report{Operations: []behavior.ModeledOperation{
		{ID: "generic-exec", Kind: behavior.OperationProcessExecute},
		{ID: "known-file", Kind: behavior.OperationFileOpen, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "/tmp/inert")))},
		{ID: "known-exec", Kind: behavior.OperationProcessExecute, Qualifiers: map[string]string{"command_argument": "printf inert"}},
	}}
	rows := projectBehavior(rep)
	if len(rows) != 3 || rows[0].OperationIDs[0] != "known-exec" || rows[1].OperationIDs[0] != "known-file" || rows[2].OperationIDs[0] != "generic-exec" {
		t.Fatalf("concrete behavior priority = %#v", rows)
	}
}

func TestProjectSummarySeparatesRuntimeSupportFromApplicationCapability(t *testing.T) {
	rep := Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test", Artifact: "fixture",
		Operations: []behavior.ModeledOperation{
			{ID: "op-runtime", SubjectNodeID: "node", Kind: behavior.OperationFileOpen, Qualifiers: map[string]string{"api": "open", "function_origin": "go-runtime-compiler"}, Support: behavior.SupportCorroborated},
			{ID: "op-stdlib", SubjectNodeID: "node", Kind: behavior.OperationFileOpen, Qualifiers: map[string]string{"api": "os.Open", "function_origin": "go-standard-library"}, Support: behavior.SupportCorroborated},
			{ID: "op-rust-runtime", SubjectNodeID: "node", Kind: behavior.OperationFileOpen, Qualifiers: map[string]string{"api": "open", "function_origin": "rust-runtime-compiler"}, Support: behavior.SupportCorroborated},
			{ID: "op-rust-stdlib", SubjectNodeID: "node", Kind: behavior.OperationFileOpen, Qualifiers: map[string]string{"api": "open", "function_origin": "rust-standard-library"}, Support: behavior.SupportCorroborated},
			{ID: "op-cxx-runtime", SubjectNodeID: "node", Kind: behavior.OperationFileOpen, Qualifiers: map[string]string{"api": "open", "function_origin": "cxx-runtime-compiler"}, Support: behavior.SupportCorroborated},
			{ID: "op-cxx-stdlib", SubjectNodeID: "node", Kind: behavior.OperationFileOpen, Qualifiers: map[string]string{"api": "open", "function_origin": "cxx-standard-library"}, Support: behavior.SupportCorroborated},
			{ID: "op-swift-runtime", SubjectNodeID: "node", Kind: behavior.OperationFileOpen, Qualifiers: map[string]string{"api": "open", "function_origin": "swift-runtime-compiler"}, Support: behavior.SupportCorroborated},
			{ID: "op-swift-stdlib", SubjectNodeID: "node", Kind: behavior.OperationFileOpen, Qualifiers: map[string]string{"api": "open", "function_origin": "swift-standard-library"}, Support: behavior.SupportCorroborated},
			{ID: "op-app", SubjectNodeID: "node", Kind: behavior.OperationFileOpen, Qualifiers: map[string]string{"api": "open", "function_origin": "go-other"}, Support: behavior.SupportCorroborated},
		},
		Capabilities: []behavior.CapabilityMatch{
			{ID: "cap-runtime", RuleID: "macos.file-open", Title: "Opens filesystem paths", Namespace: "macos.technical.filesystem", OperationIDs: []string{"op-runtime"}, Support: behavior.SupportCorroborated},
			{ID: "cap-stdlib", RuleID: "macos.file-open", Title: "Opens filesystem paths", Namespace: "macos.technical.filesystem", OperationIDs: []string{"op-stdlib"}, Support: behavior.SupportCorroborated},
			{ID: "cap-rust-runtime", RuleID: "macos.file-open", Title: "Opens filesystem paths", Namespace: "macos.technical.filesystem", OperationIDs: []string{"op-rust-runtime"}, Support: behavior.SupportCorroborated},
			{ID: "cap-rust-stdlib", RuleID: "macos.file-open", Title: "Opens filesystem paths", Namespace: "macos.technical.filesystem", OperationIDs: []string{"op-rust-stdlib"}, Support: behavior.SupportCorroborated},
			{ID: "cap-cxx-runtime", RuleID: "macos.file-open", Title: "Opens filesystem paths", Namespace: "macos.technical.filesystem", OperationIDs: []string{"op-cxx-runtime"}, Support: behavior.SupportCorroborated},
			{ID: "cap-cxx-stdlib", RuleID: "macos.file-open", Title: "Opens filesystem paths", Namespace: "macos.technical.filesystem", OperationIDs: []string{"op-cxx-stdlib"}, Support: behavior.SupportCorroborated},
			{ID: "cap-swift-runtime", RuleID: "macos.file-open", Title: "Opens filesystem paths", Namespace: "macos.technical.filesystem", OperationIDs: []string{"op-swift-runtime"}, Support: behavior.SupportCorroborated},
			{ID: "cap-swift-stdlib", RuleID: "macos.file-open", Title: "Opens filesystem paths", Namespace: "macos.technical.filesystem", OperationIDs: []string{"op-swift-stdlib"}, Support: behavior.SupportCorroborated},
			{ID: "cap-app", RuleID: "macos.file-open", Title: "Opens filesystem paths", Namespace: "macos.technical.filesystem", OperationIDs: []string{"op-app"}, Support: behavior.SupportCorroborated},
		},
	}
	summary := ProjectSummary(rep)
	if len(summary.Capabilities) != 2 || summary.Capabilities[0].Category == summary.Capabilities[1].Category {
		t.Fatalf("runtime and application matches were merged: %#v", summary.Capabilities)
	}
	categories := []SummaryCapabilityCategory{summary.Capabilities[0].Category, summary.Capabilities[1].Category}
	slices.Sort(categories)
	if !slices.Equal(categories, []SummaryCapabilityCategory{SummaryCapabilityRuntimeSupport, SummaryCapabilityTechnical}) || summary.Capabilities[0].Count+summary.Capabilities[1].Count != 9 {
		t.Fatalf("capability categories = %#v", categories)
	}
}

func TestProjectSummaryRetainsSwiftModuleContextWithoutDemangling(t *testing.T) {
	rep := Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test", Artifact: "fixture",
		Scopes: []behavior.Scope{
			{ID: "scope-run", NodeID: "node", Kind: "function", Function: "$s4Demo3runyyF", Architecture: "arm64"},
			{ID: "scope-read", NodeID: "node", Kind: "function", Function: "$s4Demo4readyyF", Architecture: "arm64"},
		},
		Features: []behavior.Feature{{
			ID: "feature-swift-call", NodeID: "node", ScopeID: "scope-run", Architecture: "arm64", Key: "macho.function_call", Value: "$s4Demo4readyyF",
			SourceFunction: "$s4Demo3runyyF", Qualifiers: map[string]string{
				"function_origin": "swift-other", "function_module": "Demo",
				"target_origin": "swift-other", "target_module": "Demo",
			}, Support: behavior.SupportCorroborated,
		}},
	}
	summary := ProjectSummary(rep)
	if len(summary.CodeContext) != 2 || summary.CodeContext[0].Kind != "swift-function" || summary.CodeContext[0].Name != "Demo · $s4Demo3runyyF" || summary.CodeContext[0].ScopeID != "scope-run" || summary.CodeContext[1].Name != "Demo · $s4Demo4readyyF" || summary.CodeContext[1].ScopeID != "scope-read" {
		t.Fatalf("Swift code context lost module or exact scope identity: %#v", summary.CodeContext)
	}
}

func TestProjectSummaryRetainsReadableCXXContextWithoutReplacingIdentity(t *testing.T) {
	rep := Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test", Artifact: "fixture",
		Scopes: []behavior.Scope{
			{ID: "scope-run", NodeID: "node", Kind: "function", Function: "_ZN4demo3runEv", Architecture: "arm64"},
			{ID: "scope-read", NodeID: "node", Kind: "function", Function: "_ZN4demo4readEv", Architecture: "arm64"},
		},
		Features: []behavior.Feature{{
			ID: "feature-cxx-call", NodeID: "node", ScopeID: "scope-run", Architecture: "arm64", Key: "macho.function_call", Value: "_ZN4demo4readEv",
			SourceFunction: "_ZN4demo3runEv", Qualifiers: map[string]string{
				"function_origin": "cxx-other", "function_display": "demo::run",
				"target_origin": "cxx-other", "target_display": "demo::read",
			}, Support: behavior.SupportCorroborated,
		}},
	}
	summary := ProjectSummary(rep)
	if len(summary.CodeContext) != 2 || summary.CodeContext[0].Kind != "cxx-function" || summary.CodeContext[0].Name != "demo::read" || summary.CodeContext[0].ScopeID != "scope-read" || summary.CodeContext[1].Name != "demo::run" || summary.CodeContext[1].ScopeID != "scope-run" {
		t.Fatalf("C++ code context lost readable names or exact scope identity: %#v", summary.CodeContext)
	}
}

func TestProjectSummaryRetainsExactNonRuntimeRustCallContext(t *testing.T) {
	rep := Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test", Artifact: "fixture",
		Scopes: []behavior.Scope{
			{ID: "scope-run", NodeID: "node", Kind: "function", Function: "demo::run", Architecture: "arm64"},
			{ID: "scope-collect", NodeID: "node", Kind: "function", Function: "demo::collect", Architecture: "arm64"},
		},
		Features: []behavior.Feature{{
			ID: "feature-rust-call", NodeID: "node", ScopeID: "scope-run", Architecture: "arm64", Key: "macho.function_call", Value: "demo::collect",
			SourceFunction: "demo::run", Qualifiers: map[string]string{"function_origin": "rust-other", "target_origin": "rust-other"}, Support: behavior.SupportCorroborated,
		}},
	}
	summary := ProjectSummary(rep)
	if len(summary.CodeContext) != 2 || summary.CodeContext[0].Kind != "rust-function" || summary.CodeContext[1].Kind != "rust-function" {
		t.Fatalf("Rust code context = %#v", summary.CodeContext)
	}
}

func TestProjectSummaryRetainsExactNonRuntimeGoCallContext(t *testing.T) {
	rep := Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test", Artifact: "fixture",
		Scopes: []behavior.Scope{
			{ID: "scope-main", NodeID: "node", Kind: "function", Function: "main.main", Architecture: "arm64"},
			{ID: "scope-collect", NodeID: "node", Kind: "function", Function: "main.collect", Architecture: "arm64"},
		},
		Features: []behavior.Feature{{
			ID: "feature-call", NodeID: "node", ScopeID: "scope-main", Architecture: "arm64", Key: "macho.function_call", Value: "main.collect",
			SourceFunction: "main.main", Qualifiers: map[string]string{"function_origin": "go-other", "target_origin": "go-other"}, Support: behavior.SupportCorroborated,
		}},
	}
	summary := ProjectSummary(rep)
	if len(summary.CodeContext) != 2 || summary.CodeContextOmitted != 0 {
		t.Fatalf("Go code context = %#v omitted=%d", summary.CodeContext, summary.CodeContextOmitted)
	}
	if summary.CodeContext[0].Name != "main.main" || summary.CodeContext[0].ScopeID != "scope-main" ||
		summary.CodeContext[1].Name != "main.collect" || summary.CodeContext[1].ScopeID != "scope-collect" ||
		!slices.Equal(summary.CodeContext[0].FeatureIDs, []string{"feature-call"}) {
		t.Fatalf("Go code context lost exact call/scope identity: %#v", summary.CodeContext)
	}
}

func TestSummaryDeclaredEventsBelongToManifest(t *testing.T) {
	rep := Report{
		ExecutionRoots: []behavior.ExecutionRoot{{ID: "root-a", Kind: "vscode-extension-main", DeclarationNodeID: "manifest-a", StartNodeID: "entry"}},
		Features: []behavior.Feature{
			{ID: "feature-b", NodeID: "manifest-b", Key: "vscode.extension.activation_event", Value: "onUri"},
			{ID: "feature-a", NodeID: "manifest-a", Key: "vscode.extension.activation_event", Value: "onStartupFinished"},
		},
	}
	context := ProjectSummary(rep).ConditionalActivation[0].Context
	if len(context) != 1 || context[0].FeatureID != "feature-a" || context[0].Value != "onStartupFinished" {
		t.Fatalf("wrong manifest context: %#v", context)
	}
}
