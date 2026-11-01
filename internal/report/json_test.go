package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/rules"
)

func TestWriteJSONDoesNotEscapeHTMLSentinels(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, Report{
		Artifact: "<command>",
		Evidence: []behavior.Evidence{{
			ID: "ev-1", Method: "source", Kind: "literal", Value: "<evidence>&",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"artifact": "<command>"`) {
		t.Fatalf("JSON output should preserve readable sentinel values:\n%s", out)
	}
	if strings.Contains(out, `\u003ccommand\u003e`) {
		t.Fatalf("JSON output should not HTML-escape sentinel values:\n%s", out)
	}
	if !strings.Contains(out, `"matched_value": "<evidence>&"`) || strings.Contains(out, `\u003cevidence\u003e`) {
		t.Fatalf("custom evidence JSON should honor the report's readable escaping policy:\n%s", out)
	}
}

func TestWriteJSONEmitsStableEmptyCollections(t *testing.T) {
	var output bytes.Buffer
	if err := WriteJSON(&output, Report{Artifact: "empty"}); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"artifact_nodes", "relationships", "scopes", "analysis_selection", "execution_roots", "invoked_targets", "capability_matches",
		"features", "operations", "operation_relations", "artifact_properties", "network_implementations", "coverage", "evidence",
		"diagnostics",
	} {
		want := `"` + field + `": []`
		if !strings.Contains(output.String(), want) {
			t.Fatalf("empty report collection %q was not an array:\n%s", field, output.String())
		}
	}
	if strings.Contains(output.String(), ": null") {
		t.Fatalf("report emitted a null collection:\n%s", output.String())
	}
}

func TestRuleCatalogIncludesMachineReadableProvenance(t *testing.T) {
	info := ListRules()
	if info.SchemaVersion != RuleCatalogSchemaVersion || info.Tool != "maratus" || info.ToolVersion == "" || info.RulesetVersion != RulesetVersion {
		t.Fatalf("rule catalog provenance is incomplete: %#v", info)
	}
	if !rules.ValidCatalogDigest(info.RuleCatalogDigest) || info.RuleCatalogDigest != rules.CatalogDigest() {
		t.Fatalf("rule catalog digest is invalid: %q", info.RuleCatalogDigest)
	}
	if len(info.Rules) == 0 {
		t.Fatal("rule catalog is empty")
	}
}

func TestReportJSONUsesFinalSchemaVocabulary(t *testing.T) {
	rep := Report{
		Analysis: AnalysisMetadata{AllowDMGMount: true},
		Capabilities: []behavior.CapabilityMatch{{
			ID: "capability-0001", RuleID: "example", SubjectNodeID: "node-0001",
			OperationIDs: []string{"operation-0001"}, ArchitectureScopes: []string{"arm64"},
		}},
		Features: []behavior.Feature{{ID: "feature-0001", Architecture: "arm64", Key: "example", Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{"root-0001"}}}},
		Operations: []behavior.ModeledOperation{{
			ID: "operation-0001", SubjectNodeID: "node-0001", Kind: behavior.OperationNetworkConnect, Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{"root-0001"}},
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://example.invalid"))),
		}},
		NetworkImplementations: []behavior.NetworkImplementationObservation{{Kind: behavior.NetworkImplementationAPICall, SubjectNodeID: "node-0001", OperationIDs: []string{"operation-0001"}, APIOrTool: "URLSession", EvidenceIDs: []string{"evidence-0001"}, Support: behavior.SupportCorroborated, Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{"root-0001"}}}},
		ArtifactProperties:     []behavior.ArtifactProperty{{Kind: "entitlement", Value: "com.example"}},
		Coverage:               []behavior.Coverage{{AnalysisArea: "macho", Status: "analyzed"}},
	}
	var output bytes.Buffer
	if err := WriteJSON(&output, rep); err != nil {
		t.Fatal(err)
	}
	encoded := output.String()
	for _, field := range []string{
		`"artifact_properties"`, `"analysis_area"`, `"subject_node_id"`, `"operation_ids"`,
		`"architecture_scopes"`, `"architecture": "arm64"`, `"execution_root_ids"`, `"allow_dmg_mount"`, `"resource_bindings"`, `"role"`, `"kind"`, `"value"`,
	} {
		if !strings.Contains(encoded, field) {
			t.Fatalf("final report JSON is missing %s:\n%s", field, encoded)
		}
	}
	for _, legacy := range []string{
		`"trust"`, `"scope"`, `"subject"`, `"action_id"`, `"architecture_scope"`,
		`"entrypoints"`, `"source_entrypoint"`, `"reachability"`, `"allow_system_extractors"`, `"concrete"`, `"confidence"`, `"default_certainty"`,
		`"signals"`, `"actions"`, `"security_context"`, `"certainty"`, `"action_ids"`,
		`"category"`, `"execution_chains"`, `"execution_chain_ids"`,
	} {
		if strings.Contains(encoded, legacy) {
			t.Fatalf("final report JSON retained legacy field %s:\n%s", legacy, encoded)
		}
	}
}

func TestReportIncludesNormalizedAnalysisMetadataWithoutZipPassword(t *testing.T) {
	opts := artifact.Options{
		IncludeUnreferenced: true,
		Architecture:        "arm64",
		MaxEvidence:         7,
		ZipPassword:         "must-not-appear",
	}
	rep := mustFromGraphs(t, "sample", artifact.Graph{}, behavior.Graph{}, nil, opts)
	if rep.Tool != "maratus" || rep.ToolVersion == "" || rep.RulesetVersion != RulesetVersion {
		t.Fatalf("missing report provenance: %#v", rep)
	}
	if rep.RuleCatalogDigest != rules.CatalogDigest() {
		t.Fatalf("report catalog digest = %q, want %q", rep.RuleCatalogDigest, rules.CatalogDigest())
	}
	if !rep.Analysis.IncludeUnreferenced || rep.Analysis.Architecture != "arm64" || rep.Analysis.MaxEvidence != 7 {
		t.Fatalf("analysis metadata was not normalized: %#v", rep.Analysis)
	}
	if rep.Analysis.MaxFileBytes != artifact.DefaultMaxFileBytes {
		t.Fatalf("default limits should be explicit in metadata: %#v", rep.Analysis)
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), opts.ZipPassword) {
		t.Fatalf("report exposed ZIP password material:\n%s", buf.String())
	}
	if !rep.Analysis.ZipPasswordSupplied || !strings.Contains(buf.String(), `"zip_password_supplied"`) {
		t.Fatalf("report should record only that a ZIP password was supplied:\n%s", buf.String())
	}
}

func TestFromGraphsPreservesEvidenceAtByteZero(t *testing.T) {
	rep := mustFromGraphs(t, "sample", artifact.Graph{}, behavior.Graph{Evidence: []behavior.Evidence{
		{ID: "ev-1", Method: "macho-strings", Kind: "url", Offset: 0},
		{ID: "ev-2", Method: "macho-strings", Kind: "entitlement-string", Offset: 0},
		{ID: "ev-3", Method: "macho-objc", Kind: "objc-message-call", Offset: 0},
		{ID: "ev-4", Method: "macho-xref", Kind: "string-reference", Offset: 0},
	}}, nil, artifact.Options{})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"byte_offset": 0`) {
		t.Fatalf("known byte-zero offset was omitted:\n%s", buf.String())
	}
	if strings.Count(buf.String(), `"byte_offset": 0`) != 1 {
		t.Fatalf("unknown offsets were incorrectly forced to byte zero:\n%s", buf.String())
	}

	var rewritten Report
	if err := json.Unmarshal(buf.Bytes(), &rewritten); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := WriteJSON(&buf, rewritten); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"byte_offset": 0`) {
		t.Fatalf("known byte-zero offset was lost on rewrite:\n%s", buf.String())
	}
}

func TestFromGraphsSurfacesPartialRuleEvaluationAsDiagnostic(t *testing.T) {
	value := "/tmp/" + strings.Repeat("x", 5000)
	graph := behavior.Graph{Operations: []behavior.ModeledOperation{{
		ID:            "operation-1",
		SubjectNodeID: "node-1",
		Kind:          behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, value)),
		),
		EvidenceIDs: []string{"ev-1"},
		Support:     behavior.SupportCorroborated,
		Execution:   behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
	}}}
	rep := mustFromGraphs(t, "sample", artifact.Graph{}, graph, nil, artifact.Options{})
	if len(rep.Diagnostics) != 1 || !strings.HasPrefix(rep.Diagnostics[0], "rule evaluation partial: rule capability-match output limit reached") {
		t.Fatalf("partial rule evaluation was not surfaced in diagnostics: %#v", rep.Diagnostics)
	}
}

func TestFromGraphsPropagatesBehaviorGraphSortErrors(t *testing.T) {
	graph := behavior.Graph{Features: []behavior.Feature{{
		ID: "feature-1", Key: "fixture", Value: "present", EvidenceIDs: []string{"ev-1"},
		Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected},
	}}}
	_, err := fromGraphs("sample", artifact.Graph{}, graph, nil, artifact.Options{})
	if err == nil || !strings.Contains(err.Error(), "sort behavior graph: features[0].execution") {
		t.Fatalf("fromGraphs() error = %v, want behavior graph sort error", err)
	}
}

func TestFromGraphsKeepsMachOCallEdgesInternalButRetainsPubliclyReferencedEvidence(t *testing.T) {
	graph := behavior.Graph{
		Evidence: []behavior.Evidence{
			{ID: "ev-unused-call", Kind: "function-call", Value: "main -> helper"},
			{ID: "ev-used-call", Kind: "function-call", Value: "main -> relevant"},
			{ID: "ev-feature", Kind: "literal", Value: "value"},
		},
		Features: []behavior.Feature{
			{ID: "feature-1", Key: "macho.function_call", Value: "helper", EvidenceIDs: []string{"ev-unused-call"}},
			{ID: "feature-2", Key: "macho.function_call", Value: "relevant", EvidenceIDs: []string{"ev-used-call"}},
			{ID: "feature-3", Key: "example.feature", Value: "value", EvidenceIDs: []string{"ev-feature"}},
		},
		ArtifactProperties: []behavior.ArtifactProperty{{
			NodeID: "node-1", Kind: "fixture", Value: "retained reference",
			EvidenceIDs: []string{"ev-used-call"}, Support: behavior.SupportDirect,
		}},
	}
	rep := mustFromGraphs(t, "sample", artifact.Graph{}, graph, nil, artifact.Options{})
	if len(rep.Features) != 1 || rep.Features[0].Key != "example.feature" {
		t.Fatalf("internal Mach-O call edges leaked into report features: %#v", rep.Features)
	}
	seen := map[string]bool{}
	for _, item := range rep.Evidence {
		seen[item.ID] = true
	}
	if seen["ev-unused-call"] || !seen["ev-used-call"] || !seen["ev-feature"] {
		t.Fatalf("call evidence pruning did not preserve public references: %#v", rep.Evidence)
	}
}

func TestPublicFeaturesRetainsInternalKeyWhenCatalogReferencesIt(t *testing.T) {
	features := []behavior.Feature{
		{ID: "feature-1", Key: "macho.function_call", Value: "helper"},
		{ID: "feature-2", Key: "example.feature", Value: "value"},
	}
	got := publicFeaturesForRuleKeys(features, []string{"macho.function_call"}, nil)
	if len(got) != 2 {
		t.Fatalf("catalog-required internal Feature was omitted: %#v", got)
	}
}

func TestPublicFeaturesRetainsExactCallsRelationProof(t *testing.T) {
	features := []behavior.Feature{
		{ID: "feature-unused", Key: "macho.function_call", Value: "unused", EvidenceIDs: []string{"ev-unused"}},
		{ID: "feature-call", Key: "macho.function_call", Value: "helper", EvidenceIDs: []string{"ev-call"}},
		{ID: "feature-public", Key: "example.feature", Value: "value", EvidenceIDs: []string{"ev-public"}},
	}
	relations := []behavior.OperationRelation{{
		Kind: behavior.RelationCalls, EvidenceIDs: []string{"ev-call"},
	}}
	got := publicFeaturesForRuleKeys(features, nil, relations)
	if len(got) != 2 || got[0].ID != "feature-call" || got[1].ID != "feature-public" {
		t.Fatalf("retained calls relation lost or widened its exact feature proof: %#v", got)
	}
}

func TestFromGraphsRetainsCallsRelationFeatureForStrictReload(t *testing.T) {
	unknown := behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
	graph := behavior.Graph{
		Scopes: []behavior.Scope{
			{ID: "scope-caller", NodeID: "node-1", Kind: "function", Name: "main", Function: "main", Architecture: "arm64"},
			{ID: "scope-callee", NodeID: "node-1", Kind: "function", Name: "helper", Function: "helper", Architecture: "arm64"},
		},
		Evidence: []behavior.Evidence{{
			ID: "ev-call", NodeID: "node-1", ScopeID: "scope-caller", Function: "main", Arch: "arm64",
			Method: "macho-callgraph", Kind: "function-call", Value: "main -> helper",
		}},
		Features: []behavior.Feature{{
			ID: "feature-call", NodeID: "node-1", ScopeID: "scope-caller", Architecture: "arm64",
			SourceFunction: "main", Key: "macho.function_call", Value: "helper",
			EvidenceIDs: []string{"ev-call"}, Support: behavior.SupportCorroborated, Execution: unknown,
		}},
		Relations: []behavior.OperationRelation{{
			ID: "relation-call", Kind: behavior.RelationCalls,
			From:        behavior.IDRelationEndpoint(behavior.RelationEndpointScope, "scope-caller"),
			To:          behavior.IDRelationEndpoint(behavior.RelationEndpointScope, "scope-callee"),
			EvidenceIDs: []string{"ev-call"}, Support: behavior.SupportCorroborated,
			Execution: unknown, Architecture: "arm64",
		}},
	}
	rep := mustFromGraphs(t, "sample", artifact.Graph{Nodes: []artifact.Node{{
		ID: "node-1", LogicalPath: "sample", Kind: "mach-o", AnalyzeStatus: "analyzed",
	}}}, graph, nil, artifact.Options{})
	if len(rep.Features) != 1 || rep.Features[0].ID != "feature-call" {
		t.Fatalf("calls relation proof was pruned during report projection: %#v", rep.Features)
	}
	if err := validateReportReferences(rep); err != nil {
		t.Fatalf("projected calls relation report failed strict validation: %v", err)
	}
}

func TestFromGraphsSortsArtifactNodesAndRelationships(t *testing.T) {
	zero, one := 0, 1
	rep := mustFromGraphs(t, "sample", artifact.Graph{
		Nodes: []artifact.Node{
			{ID: "node-0002", LogicalPath: "child", Kind: "script", AnalyzeStatus: "analyzed"},
			{ID: "node-0001", LogicalPath: "root", Kind: "directory", AnalyzeStatus: "analyzed"},
		},
		Edges: []artifact.Edge{
			{From: "node-0002", To: "node-0003", Kind: "contains"},
			{From: "node-0001", To: "node-z", Kind: "loader-invokes", Ordinal: &one, EvidenceIDs: []string{"ev-2", "ev-1"}},
			{From: "node-0001", To: "node-a", Kind: "loader-invokes", Ordinal: &zero},
			{From: "node-0001", To: "node-0002", Kind: "contains"},
		},
	}, behavior.Graph{}, nil, artifact.Options{})

	if got := []string{rep.ArtifactNodes[0].ID, rep.ArtifactNodes[1].ID}; got[0] != "node-0001" || got[1] != "node-0002" {
		t.Fatalf("artifact nodes not sorted by ID: %#v", got)
	}
	if first := rep.Relationships[0]; first.From != "node-0001" || first.To != "node-0002" {
		t.Fatalf("relationships not sorted deterministically: %#v", rep.Relationships)
	}
	if len(rep.Relationships) != 4 || rep.Relationships[1].Ordinal == nil || *rep.Relationships[1].Ordinal != 0 || rep.Relationships[2].Ordinal == nil || *rep.Relationships[2].Ordinal != 1 {
		t.Fatalf("ordered relationships lost declared order: %#v", rep.Relationships)
	}
	if got := rep.Relationships[2].EvidenceIDs; len(got) != 2 || got[0] != "ev-1" || got[1] != "ev-2" {
		t.Fatalf("relationship evidence IDs are not canonical: %#v", got)
	}
}

func TestFromGraphsDeduplicatesArtifactProperty(t *testing.T) {
	graph := behavior.Graph{
		ArtifactProperties: []behavior.ArtifactProperty{
			{NodeID: "node-0001", Kind: "entitlement", Value: "com.apple.security.get-task-allow", EvidenceIDs: []string{"ev-2"}, Support: behavior.SupportHeuristic},
			{NodeID: "node-0001", Kind: "entitlement", Value: "com.apple.security.get-task-allow", EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportDirect},
			{NodeID: "node-0001", Kind: "entitlement", Value: "com.apple.security.get-task-allow", EvidenceIDs: []string{"ev-3"}, Support: behavior.SupportDirect},
		},
	}

	rep := mustFromGraphs(t, "sample", artifact.Graph{}, graph, nil, artifact.Options{})

	if len(rep.ArtifactProperties) != 1 {
		t.Fatalf("expected one deduplicated artifact property entry, got %#v", rep.ArtifactProperties)
	}
	got := rep.ArtifactProperties[0]
	if got.Support != behavior.SupportDirect {
		t.Fatalf("deduplicated artifact property should prefer direct over heuristic: %#v", got)
	}
	if len(got.EvidenceIDs) != 2 || got.EvidenceIDs[0] != "ev-1" || got.EvidenceIDs[1] != "ev-3" {
		t.Fatalf("deduplicated artifact property should preserve direct evidence IDs: %#v", got)
	}
}

func TestNetworkPresentationPrefersScopedObservableOverRawDuplicate(t *testing.T) {
	graph := behavior.Graph{
		Features: []behavior.Feature{
			{NodeID: "node-1", Key: "network.url", Value: "https://raw-only.example/p"},
			{NodeID: "node-1", Key: "network.url", Value: "https://same.example/p"},
			{NodeID: "node-1", ScopeID: "scope-main", Key: "network.url", Value: "https://same.example/p"},
		},
	}

	rep := mustFromGraphs(t, "sample", artifact.Graph{}, graph, nil, artifact.Options{})

	records := networkPresentationRecords(rep)
	if len(records) != 2 {
		t.Fatalf("expected scoped destination plus filtered raw-only destination, got %#v", records)
	}
	for _, item := range records {
		if len(item.Destinations) != 1 {
			t.Fatalf("presentation observable should remain singular: %#v", records)
		}
	}
}

func TestFromGraphsDeduplicatesIdenticalNetworkImplementations(t *testing.T) {
	graph := behavior.Graph{
		Network: []behavior.NetworkImplementationObservation{
			{
				Kind: behavior.NetworkImplementationAPICall, SubjectNodeID: "node-1", OperationIDs: []string{"operation-1"}, APIOrTool: "SSLHandshake",
				HTTPImplementation: "SecureTransport", TLSProvider: "Apple system TLS provider", EvidenceIDs: []string{"ev-2"},
				UnresolvedProperties: []string{"macOS build"}, Support: behavior.SupportCorroborated, Execution: testUnknownExecution(),
			},
			{
				Kind: behavior.NetworkImplementationAPICall, SubjectNodeID: "node-1", OperationIDs: []string{"operation-1"}, APIOrTool: "SSLHandshake",
				HTTPImplementation: "SecureTransport", TLSProvider: "Apple system TLS provider", EvidenceIDs: []string{"ev-1"},
				UnresolvedProperties: []string{"macOS build"}, Support: behavior.SupportCorroborated, Execution: testUnknownExecution(),
			},
		},
	}

	rep := mustFromGraphs(t, "sample", artifact.Graph{}, graph, nil, artifact.Options{})

	if len(rep.NetworkImplementations) != 1 {
		t.Fatalf("expected one deduplicated network implementation, got %#v", rep.NetworkImplementations)
	}
	got := rep.NetworkImplementations[0]
	if strings.Join(got.OperationIDs, ",") != "operation-1" {
		t.Fatalf("deduplicated network implementation should preserve its operation id, got %#v", got)
	}
	if strings.Join(got.EvidenceIDs, ",") != "ev-1,ev-2" {
		t.Fatalf("deduplicated network should preserve evidence ids, got %#v", got)
	}
	if strings.Join(got.UnresolvedProperties, ",") != "macOS build" {
		t.Fatalf("deduplicated network should drop destination once resolved, got %#v", got)
	}
}

func mustFromGraphs(t *testing.T, artifactPath string, artifacts artifact.Graph, graph behavior.Graph, diagnostics []string, options artifact.Options) Report {
	t.Helper()
	rep, err := fromGraphs(artifactPath, artifacts, graph, diagnostics, options)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}
