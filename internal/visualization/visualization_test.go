package visualization

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/report"
	"github.com/0x4D31/maratus/internal/rules"
)

func TestWriteDeterministicSelfContainedDocument(t *testing.T) {
	rep := visualizationFixture()
	var first, second bytes.Buffer
	if err := Write(&first, rep, Options{Title: "Offline analysis"}); err != nil {
		t.Fatal(err)
	}
	if err := Write(&second, rep, Options{Title: "Offline analysis"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("identical reports produced different HTML")
	}
	output := first.String()
	for _, want := range []string{
		"<!doctype html>", "Content-Security-Policy", "connect-src 'none'", "OFFLINE · SINGLE FILE",
		"Static findings", "Report sections", "Behavioral capabilities", "Conditional activation", "Network evidence", "Static observables", "Mach-O loader context", "Artifact and build context", "Technical capabilities", "Underlying modeled operations", "Runtime and standard-library support surface", "Native code context", "Evidence graph", "Search facts and evidence", "Advanced filters", "Core flow", "All facts", "Report notes", "Fit", "Focus neighbors", "Wheel to zoom",
		`id="review-capabilities-detail" open`, `id="review-activation-detail" open`, `id="review-network-detail"`, `id="review-observables-detail"`,
		`id="theme-toggle"`, "Theme: Auto", `prefers-color-scheme:dark`, `data-theme="dark"`,
		`--rail-capability:#d20f39`, `--rail-network:#1e66f5`, `--rail-capability:#ed8796`, `--rail-network:#8aadf4`, `.review-detail>summary h2:before`, `background:var(--section-tone)`, `border-left:3px solid var(--finding-tone)`, `.review-card>.finding-list>.finding,.review-limitations>.finding-list>.finding{--finding-tone:var(--section-tone)}`,
		"grid-template-columns:minmax(0,1fr)", ".review-grid{display:block}", ".details.open{transform:translateX(0)}",
		"Capability match ID", "Modeled operations", "Match support", "Artifact properties",
		"unreferenced content included", "container expansion enabled", `"include_unreferenced":true`, `"expand_containers":true`,
		`role="group"`, "Arrow keys move between nodes", `tabindex: state.focused === node.id`,
		`(outgoing ? "→ " : "← ") + link.kind + " · " + other.title`,
		"CONNECTED means modeled reachability, not observed execution",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("HTML does not contain %q", want)
		}
	}
	for _, forbidden := range []string{"<script src=", "<link rel=", "fetch(", "XMLHttpRequest", "WebSocket(", "border-left:3px solid var(--section-tone)", `data-view="limitations"`, `>Limits</a>`} {
		if strings.Contains(output, forbidden) {
			t.Errorf("self-contained HTML contains %q", forbidden)
		}
	}
	for _, collapsed := range []string{`id="review-network-detail" open`, `id="review-observables-detail" open`} {
		if strings.Contains(output, collapsed) {
			t.Errorf("secondary review section should be collapsed by default: %q", collapsed)
		}
	}
	for _, stale := range []string{"Evidence state", "CapabilityMatch ID", "Any certainty", "Match confidence", "analysis.deep", "analysis.no_archives", `"actions":`, `"certainty":`, "Entrypoint", "Reachability", `"entrypoints":`, `"reachability":`} {
		if strings.Contains(output, stale) {
			t.Errorf("HTML still contains stale label %q", stale)
		}
	}
	doc := decodeEmbeddedDocument(t, output)
	if doc.SchemaVersion != visualizationSchema || doc.Title != "Offline analysis" {
		t.Fatalf("document identity = %q %q", doc.SchemaVersion, doc.Title)
	}
	if doc.ToolCommit != "0123456789abcdef" || !doc.ToolModified || doc.RuleCatalogDigest != rules.CatalogDigest() || !doc.Analysis.IncludeUnreferenced || !doc.Analysis.ExpandContainers || doc.Analysis.Architecture != "arm64" || doc.Analysis.MaxFileBytes != 1024 {
		t.Fatalf("report build or analysis provenance was not embedded: %+v", doc)
	}
	if doc.Source.Artifacts != 2 || doc.Shown.Artifacts != 2 || doc.Source.AnalysisSelections != 1 || doc.Shown.AnalysisSelections != 1 ||
		doc.Source.ExecutionRoots != 1 || doc.Shown.ExecutionRoots != 1 || doc.Source.InvokedTargets != 1 || doc.Shown.InvokedTargets != 1 ||
		doc.Source.Operations != 2 || doc.Shown.Operations != 2 || doc.Shown.Links == 0 || doc.Source.Diagnostics != 1 || doc.Shown.Diagnostics != 1 {
		t.Fatalf("unexpected counts: source=%+v shown=%+v", doc.Source, doc.Shown)
	}
	if doc.Summary.Capabilities != 1 || doc.Summary.CorroboratedMatches != 0 || doc.Summary.DirectMatches != 1 || doc.Summary.ConnectedMatches != 1 || doc.Summary.CoverageLimitations != 1 {
		t.Fatalf("unexpected analyst summary: %+v", doc.Summary)
	}
	if len(doc.Diagnostics) != 1 || doc.Diagnostics[0] != "fixture diagnostic" {
		t.Fatalf("diagnostics were not retained in the bounded view: %#v", doc.Diagnostics)
	}
	if len(doc.Projection.Capabilities) != 1 || !slices.Equal(doc.Projection.Capabilities[0].MatchIDs, []string{"capability-1"}) ||
		!slices.Equal(doc.Projection.Capabilities[0].OperationIDs, []string{"operation-1", "operation-2"}) {
		t.Fatalf("capability projection lost exact evidence links: %#v", doc.Projection.Capabilities)
	}
	var projectedOperationIDs []string
	for _, item := range doc.Projection.ModeledBehavior {
		projectedOperationIDs = append(projectedOperationIDs, item.OperationIDs...)
	}
	slices.Sort(projectedOperationIDs)
	if !slices.Equal(projectedOperationIDs, []string{"operation-1", "operation-2"}) {
		t.Fatalf("operation projection lost canonical IDs: %#v", doc.Projection.ModeledBehavior)
	}
	if !strings.Contains(strings.Join(doc.Omissions, "\n"), "Report-only detail: 0 Features, 1 evidence records, 1 artifact property records") {
		t.Fatalf("non-node report collections were not disclosed: %#v", doc.Omissions)
	}
}

func TestBoundedVisualProjectionSeparatesUnresolvedArgumentsFromResources(t *testing.T) {
	rep := visualizationFixture()
	rep.Operations = []behavior.ModeledOperation{{
		ID: "operation-1", SubjectNodeID: "node-2", Kind: behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile})),
		Qualifiers:       map[string]string{"api": "execve", "resource_binding": "unresolved"}, Support: behavior.SupportCorroborated,
	}}
	projection := boundedVisualProjection(rep)
	if len(projection.ModeledBehavior) != 1 {
		t.Fatalf("modeled behavior = %#v", projection.ModeledBehavior)
	}
	item := projection.ModeledBehavior[0]
	if len(item.Resources) != 0 || !slices.Contains(item.Implementations, "api: execve") || !slices.Contains(item.Unresolved, "executable") {
		t.Fatalf("unresolved operation projection = %#v", item)
	}
}

func TestWriteEscapesUntrustedReportData(t *testing.T) {
	attack := `</script><img src=x onerror="alert(1)">&`
	rep := visualizationFixture()
	rep.Artifact = attack
	rep.ArtifactNodes[0].LogicalPath = attack
	rep.Capabilities[0].Title = attack
	rep.Operations[0].Qualifiers = map[string]string{attack: attack}
	var output bytes.Buffer
	if err := Write(&output, rep, Options{Title: attack}); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if strings.Contains(html, attack) || strings.Contains(html, "<img src=x") {
		t.Fatal("untrusted report data appeared as raw HTML")
	}
	if count := strings.Count(html, "</script>"); count != 2 {
		t.Fatalf("closing script count = %d, want the two static script elements", count)
	}
	if !strings.Contains(html, `\u003c/script\u003e`) || !strings.Contains(html, `\u003cimg`) {
		t.Fatal("expected HTML-sensitive JSON characters to be escaped")
	}
	doc := decodeEmbeddedDocument(t, html)
	if doc.Artifact != attack || doc.Title != attack {
		t.Fatalf("escaped values did not round trip: artifact=%q title=%q", doc.Artifact, doc.Title)
	}
}

func TestBuildDocumentModelsAnalystRelationships(t *testing.T) {
	options, adjustments, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(visualizationFixture(), options, adjustments)
	wantTypes := map[string]int{"artifact": 2, "analysis-selection": 1, "execution-root": 1, "invoked-target": 1, "operation": 2, "capability": 1, "coverage": 1}
	gotTypes := make(map[string]int)
	for _, node := range doc.Nodes {
		gotTypes[node.Type]++
	}
	for kind, want := range wantTypes {
		if gotTypes[kind] != want {
			t.Errorf("%s nodes = %d, want %d", kind, gotTypes[kind], want)
		}
	}
	for _, node := range doc.Nodes {
		labels := make(map[string]struct{}, len(node.Details))
		for _, detail := range node.Details {
			if _, duplicate := labels[detail.Label]; duplicate {
				t.Errorf("%s node %q repeats detail label %q: %#v", node.Type, node.Title, detail.Label, node.Details)
			}
			labels[detail.Label] = struct{}{}
		}
	}
	wantLinks := []visualLink{
		{From: "artifact-0001", To: "artifact-0002", Kind: "contains"},
		{From: "artifact-0002", To: "analysis-selection-0001", Kind: "selected for analysis"},
		{From: "artifact-0001", To: "execution-root-0001", Kind: "declares execution root"},
		{From: "execution-root-0001", To: "artifact-0002", Kind: "starts at artifact"},
		{From: "execution-root-0001", To: "invoked-target-0001", Kind: "invokes target"},
		{From: "invoked-target-0001", To: "artifact-0002", Kind: "targets artifact"},
		{From: "execution-root-0001", To: "operation-0001", Kind: "owns modeled operation"},
		{From: "invoked-target-0001", To: "operation-0001", Kind: "owns modeled operation"},
		{From: "execution-root-0001", To: "operation-0002", Kind: "owns modeled operation"},
		{From: "operation-0001", To: "operation-0002", Kind: "precedes"},
		{From: "artifact-0002", To: "capability-0001", Kind: "has capability match"},
		{From: "operation-0001", To: "capability-0001", Kind: "supports match"},
		{From: "operation-0002", To: "capability-0001", Kind: "supports match"},
		{From: "artifact-0002", To: "coverage-0001", Kind: "has coverage"},
	}
	for _, want := range wantLinks {
		if !containsLink(doc.Links, want) {
			t.Errorf("missing link %+v in %+v", want, doc.Links)
		}
	}
	if got := nodeDetail(doc.Nodes, "operation", "Evidence locations"); !strings.Contains(got, "sample.app/Contents/MacOS/sample · line 7") || !strings.Contains(got, "disassembly/imported-call") {
		t.Fatalf("modeled-operation evidence was not resolved into a useful location: %q", got)
	}
	if got := nodeDetail(doc.Nodes, "operation", "Support"); got != "DIRECT" {
		t.Fatalf("modeled-operation support = %q, want DIRECT", got)
	}
	if got := nodeDetail(doc.Nodes, "capability", "Connectivity"); got != "CONNECTED" {
		t.Fatalf("capability connectivity = %q, want CONNECTED", got)
	}
	if got := nodeDetail(doc.Nodes, "capability", "Match trace"); !strings.Contains(got, "match.relate.left · operation · operation-1") || !strings.Contains(got, "match.relate.constraint · operation-relation · relation-1") {
		t.Fatalf("capability match trace = %q", got)
	}
	if got := nodeDetail(doc.Nodes, "artifact", "Artifact properties"); !strings.Contains(got, "entitlement=com.apple.security.network.client (DIRECT)") {
		t.Fatalf("artifact property was not summarized on the artifact: %q", got)
	}
	if got := nodeDetail(doc.Nodes, "operation", "Network context"); !strings.Contains(got, "api-call") || !strings.Contains(got, "URLSession") {
		t.Fatalf("network context was not summarized on the modeled operation: %q", got)
	}
}

func TestBuildDocumentLabelsUnresolvedTypedResources(t *testing.T) {
	rep := visualizationFixture()
	rep.Operations[1].ResourceBindings = behavior.Bindings(
		behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile}),
	)
	rep.Capabilities[0].AffectedResources = []behavior.Resource{{Kind: behavior.ResourceFile}}

	options, adjustments, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(rep, options, adjustments)
	var operationBindings string
	for _, node := range doc.Nodes {
		if node.Type != "operation" || node.Title != string(behavior.OperationProcessExecute) {
			continue
		}
		for _, item := range node.Details {
			if item.Label == "Resource bindings" {
				operationBindings = item.Value
				break
			}
		}
	}
	if operationBindings != "executable = file: (unresolved)" {
		t.Fatalf("process resource bindings = %q", operationBindings)
	}
	if got := nodeDetail(doc.Nodes, "capability", "Resources"); got != "file: (unresolved)" {
		t.Fatalf("capability resources = %q", got)
	}
}

func TestCapabilitySummaryUsesExecutionConnectivity(t *testing.T) {
	rep := visualizationFixture()
	unconnected := rep.Capabilities[0]
	unconnected.ID = "capability-2"
	unconnected.Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnconnected}
	unknown := rep.Capabilities[0]
	unknown.ID = "capability-3"
	unknown.Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
	rep.Capabilities = append(rep.Capabilities, unconnected, unknown)
	options, adjustments, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(rep, options, adjustments)
	if doc.Summary.ConnectedMatches != 1 || doc.Summary.UnconnectedMatches != 1 || doc.Summary.UnknownMatches != 1 {
		t.Fatalf("execution-connectivity summary = %+v", doc.Summary)
	}
	want := map[string]int{"CONNECTED": 1, "UNCONNECTED": 1, "UNKNOWN": 1}
	for _, node := range doc.Nodes {
		if node.Type == "capability" {
			want[node.Connectivity]--
		}
	}
	for connectivity, remaining := range want {
		if remaining != 0 {
			t.Errorf("capability nodes with %s connectivity differ by %d", connectivity, remaining)
		}
	}
}

func TestReviewProjectionGroupsCapabilityAndArtifactContext(t *testing.T) {
	rep := visualizationFixture()
	second := rep.Capabilities[0]
	second.ID = "capability-2"
	second.SubjectNodeID = "node-1"
	second.Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
	rep.Capabilities = append(rep.Capabilities, second)
	rep.ArtifactProperties = append(rep.ArtifactProperties, behavior.ArtifactProperty{
		NodeID: "node-1", Kind: rep.ArtifactProperties[0].Kind,
		Value: rep.ArtifactProperties[0].Value, Support: rep.ArtifactProperties[0].Support,
	})

	projection := boundedVisualProjection(rep)
	if len(projection.Capabilities) != 1 || projection.Capabilities[0].Count != 2 || projection.Capabilities[0].Connectivity != "CONNECTED + UNKNOWN" {
		t.Fatalf("capability review grouping = %#v", projection.Capabilities)
	}
	if len(projection.ArtifactContext) != 1 || projection.ArtifactContext[0].Count != 2 {
		t.Fatalf("artifact context review grouping = %#v", projection.ArtifactContext)
	}
}

func TestReviewGroupsRetainAllRenderedInstancesWithExactContexts(t *testing.T) {
	rep := visualizationFixture()
	baseOperation, baseCapability := rep.Operations[0], rep.Capabilities[0]
	rep.Operations, rep.Capabilities = nil, nil
	for index := 0; index < 40; index++ {
		op := baseOperation
		op.ID = fmt.Sprintf("operation-%d", index)
		op.SubjectNodeID = fmt.Sprintf("node-%d", index%2+1)
		op.Architecture = []string{"arm64", "x86_64"}[index%2]
		op.Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{fmt.Sprintf("root-%d", index)}}
		op.ResourceBindings = behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, fmt.Sprintf("/usr/bin/inert-%d", index))))
		rep.Operations = append(rep.Operations, op)
		capability := baseCapability
		capability.ID = fmt.Sprintf("capability-%d", index)
		capability.SubjectNodeID = op.SubjectNodeID
		capability.Execution = op.Execution
		capability.ArchitectureScopes = []string{op.Architecture}
		capability.OperationIDs = []string{op.ID}
		capability.AffectedResources = []behavior.Resource{op.ResourceBindings[0].Resource}
		rep.Capabilities = append(rep.Capabilities, capability)
	}
	options, adjustments, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(rep, options, adjustments)
	if len(doc.Projection.Capabilities) != 1 {
		t.Fatalf("review groups = %#v", doc.Projection.Capabilities)
	}
	group := doc.Projection.Capabilities[0]
	if group.Count != 40 || group.OperationCount != 40 || group.OperationCountLimited || len(group.MatchIDs) != maxReviewItems {
		t.Fatalf("group counts = %#v", group)
	}
	instances := 0
	for _, node := range doc.Nodes {
		if node.Type != "capability" {
			continue
		}
		if node.ReviewGroup != group.GroupID || node.RecordID == "" {
			t.Fatalf("instance missing exact group reference: %#v", node)
		}
		instances++
		fields := map[string]string{}
		for _, detail := range node.Details {
			fields[detail.Label] = detail.Value
		}
		if fields["Artifact path"] == "" || fields["Execution root IDs"] == "" || fields["Architecture scopes"] == "" || fields["Resources"] == "" {
			t.Fatalf("instance context = %#v", fields)
		}
	}
	if instances != 40 {
		t.Fatalf("rendered grouped instances = %d", instances)
	}
}

func TestReviewGroupMembershipKeepsRulesAndRuntimeCategoriesSeparate(t *testing.T) {
	rep := visualizationFixture()
	second := rep.Capabilities[0]
	second.ID, second.RuleID = "capability-2", "different-rule"
	rep.Capabilities = append(rep.Capabilities, second)
	runtimeOperation := rep.Operations[0]
	runtimeOperation.ID = "operation-runtime"
	runtimeOperation.Qualifiers = map[string]string{"function_origin": "go-runtime-compiler"}
	rep.Operations = append(rep.Operations, runtimeOperation)
	runtimeCapability := rep.Capabilities[0]
	runtimeCapability.ID, runtimeCapability.OperationIDs = "capability-runtime", []string{runtimeOperation.ID}
	rep.Capabilities = append(rep.Capabilities, runtimeCapability)
	projection, membership := buildVisualProjection(rep)
	if len(projection.Capabilities) != 3 {
		t.Fatalf("distinct rules or categories merged: %#v", projection.Capabilities)
	}
	groups := map[string]bool{}
	for _, id := range []string{"capability-1", "capability-2", "capability-runtime"} {
		group := membership["capability\x00"+id]
		if group == "" || groups[group] {
			t.Fatalf("incorrect group membership: %#v", membership)
		}
		groups[group] = true
	}
}

func TestReviewNavigationRejectsAmbiguousCanonicalIDsOutsideView(t *testing.T) {
	rep := visualizationFixture()
	duplicate := rep.Capabilities[0]
	rep.Capabilities = append(rep.Capabilities, duplicate)
	options, adjustments, err := normalizeOptions(Options{MaxCapabilityMatches: 1})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(rep, options, adjustments)
	for _, node := range doc.Nodes {
		if node.Type == "capability" && (node.RecordID != "" || node.ReviewGroup != "") {
			t.Fatalf("ambiguous ID acquired an exact navigation target: %#v", node)
		}
	}
}

func TestReviewNavigationRejectsEscapedOversizedOrTruncatedIDs(t *testing.T) {
	for _, test := range []struct {
		name, id string
		bytes    int
	}{
		{"control", "capability-\x1b[31m", 0},
		{"invalid UTF-8", "capability-\xff", 0},
		{"oversized", strings.Repeat("a", maxReferenceBytes+1), 0},
		{"truncated", "capability-" + strings.Repeat("a", 50), 32},
	} {
		t.Run(test.name, func(t *testing.T) {
			rep := visualizationFixture()
			rep.Capabilities[0].ID = test.id
			options, adjustments, err := normalizeOptions(Options{MaxStringBytes: test.bytes})
			if err != nil {
				t.Fatal(err)
			}
			doc := buildDocument(rep, options, adjustments)
			for _, node := range doc.Nodes {
				if node.Type == "capability" && (node.RecordID != "" || node.ReviewGroup != "") {
					t.Fatalf("display-transformed ID became an exact reference: %#v", node)
				}
			}
		})
	}
}

func TestReviewMembershipBoundsAndTypedIDs(t *testing.T) {
	membership := make(map[string]string)
	addReviewMembership(membership, "operation", "operation-group", []string{"shared"})
	addReviewMembership(membership, "capability", "capability-group", []string{"shared"})
	if membership["operation\x00shared"] != "operation-group" || membership["capability\x00shared"] != "capability-group" {
		t.Fatalf("typed IDs collided: %#v", membership)
	}
	ids := make([]string, maxReferenceTailScan+1)
	for index := range ids {
		ids[index] = fmt.Sprintf("id-%d", index)
	}
	addReviewMembership(membership, "operation", "bounded", ids)
	if len(membership) != maxReferenceTailScan {
		t.Fatalf("membership index size = %d", len(membership))
	}
}

func TestInvokedTargetLinksUseTypedSources(t *testing.T) {
	rep := visualizationFixture()
	rep.InvokedTargets = append(rep.InvokedTargets,
		behavior.InvokedTarget{
			ID: "target-2", Kind: "artifact-owned", NodeID: "node-2",
			Source:    behavior.EntityRef{Kind: behavior.EntityKindArtifactNode, ID: "node-1"},
			Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}, EvidenceIDs: []string{"ev-1"},
		},
		behavior.InvokedTarget{
			ID: "target-3", Kind: "nested", NodeID: "node-2",
			Source:    behavior.EntityRef{Kind: behavior.EntityKindInvokedTarget, ID: "target-1"},
			Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{"root-1"}, InvokedTargetIDs: []string{"target-1"}}, EvidenceIDs: []string{"ev-1"},
		},
	)
	options, adjustments, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(rep, options, adjustments)
	for _, want := range []visualLink{
		{From: "artifact-0001", To: "invoked-target-0002", Kind: "invokes target"},
		{From: "invoked-target-0001", To: "invoked-target-0003", Kind: "invokes target"},
	} {
		if !containsLink(doc.Links, want) {
			t.Errorf("missing typed target-source link %+v in %+v", want, doc.Links)
		}
	}
}

func TestCoverageGraphFoldsRepetitionWithoutLosingArtifactLinks(t *testing.T) {
	rep := visualizationFixture()
	rep.Coverage = []behavior.Coverage{
		{NodeID: "node-1", AnalysisArea: "macho-analysis/arm64", Status: "partial", Detail: "bounded analysis"},
		{NodeID: "node-2", AnalysisArea: "macho-analysis/x86_64", Status: "partial", Detail: "bounded analysis"},
		{NodeID: "node-1", AnalysisArea: "macho-structure", Status: "analyzed", Detail: "complete"},
	}
	options, adjustments, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(rep, options, adjustments)
	if doc.Source.Coverage != 3 || doc.Shown.Coverage != 1 {
		t.Fatalf("coverage counts do not disclose folding: source=%+v shown=%+v", doc.Source, doc.Shown)
	}
	if got := nodeDetail(doc.Nodes, "coverage", "Scope"); got != "macho-analysis (arm64, x86_64)" {
		t.Fatalf("folded coverage scope = %q", got)
	}
	for _, artifactID := range []string{"artifact-0001", "artifact-0002"} {
		if !containsLink(doc.Links, visualLink{From: artifactID, To: "coverage-0001", Kind: "has coverage"}) {
			t.Errorf("folded coverage node lost link from %s: %#v", artifactID, doc.Links)
		}
	}
	if !strings.Contains(strings.Join(doc.Omissions, "\n"), "2 source records") {
		t.Fatalf("coverage folding was not disclosed: %#v", doc.Omissions)
	}
}

func TestDiagnosticsAreBoundedAndDisclosed(t *testing.T) {
	rep := visualizationFixture()
	rep.Diagnostics = make([]string, maxDiagnosticItems+3)
	for i := range rep.Diagnostics {
		rep.Diagnostics[i] = fmt.Sprintf("diagnostic %d", i)
	}
	options, adjustments, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(rep, options, adjustments)
	if len(doc.Diagnostics) != maxDiagnosticItems || doc.Source.Diagnostics != maxDiagnosticItems+3 || doc.Shown.Diagnostics != maxDiagnosticItems {
		t.Fatalf("diagnostic bounds are incorrect: source=%+v shown=%+v values=%d", doc.Source, doc.Shown, len(doc.Diagnostics))
	}
	if !strings.Contains(strings.Join(doc.Omissions, "\n"), "Diagnostics: showing 20 of 23") {
		t.Fatalf("diagnostic truncation was not disclosed: %#v", doc.Omissions)
	}
}

func TestVisualizationLimitsAreVisibleAndEnforced(t *testing.T) {
	rep := visualizationFixture()
	extraArtifact := rep.ArtifactNodes[1]
	extraArtifact.ID = "node-3"
	rep.ArtifactNodes = append(rep.ArtifactNodes, extraArtifact)
	extraSelection := rep.AnalysisSelection[0]
	extraSelection.NodeID = "node-3"
	rep.AnalysisSelection = append(rep.AnalysisSelection, extraSelection)
	extraRoot := rep.ExecutionRoots[0]
	extraRoot.ID = "root-2"
	rep.ExecutionRoots = append(rep.ExecutionRoots, extraRoot)
	extraTarget := rep.InvokedTargets[0]
	extraTarget.ID = "target-2"
	rep.InvokedTargets = append(rep.InvokedTargets, extraTarget)
	extraOperation := rep.Operations[0]
	extraOperation.ID = "operation-3"
	rep.Operations = append(rep.Operations, extraOperation)
	extraCapabilityMatch := rep.Capabilities[0]
	extraCapabilityMatch.ID = "capability-2"
	rep.Capabilities = append(rep.Capabilities, extraCapabilityMatch)
	extraRelation := rep.OperationRelations[0]
	extraRelation.ID = "relation-2"
	rep.OperationRelations = append(rep.OperationRelations, extraRelation)
	extraCoverage := rep.Coverage[0]
	extraCoverage.AnalysisArea = "archive-inspection"
	extraCoverage.Detail = "archive coverage differs"
	rep.Coverage = append(rep.Coverage, extraCoverage)
	options, adjustments, err := normalizeOptions(Options{
		MaxArtifactNodes: 1, MaxAnalysisSelections: 1, MaxExecutionRoots: 1, MaxInvokedTargets: 1,
		MaxOperations: 1, MaxCapabilityMatches: 1,
		MaxOperationRelations: 1, MaxCoverageItems: 1, MaxLinks: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(rep, options, adjustments)
	if len(doc.Nodes) != 7 || len(doc.Links) > 1 {
		t.Fatalf("bounded document has %d nodes and %d links", len(doc.Nodes), len(doc.Links))
	}
	notes := strings.Join(doc.Omissions, "\n")
	for _, want := range []string{"Artifact nodes: showing 1 of 3", "Analysis selections: showing 1 of 2", "Execution roots: showing 1 of 2", "Invoked targets: showing 1 of 2", "Modeled operations: showing 1 of 3", "Capability matches: showing 1 of 2", "Operation relations: showing 1 of 2", "Coverage graph nodes: showing 1 of 2", "Connections:"} {
		if !strings.Contains(notes, want) {
			t.Errorf("omission notes do not contain %q:\n%s", want, notes)
		}
	}
}

func TestBehaviorLinksHavePriorityUnderLowLimit(t *testing.T) {
	options, adjustments, err := normalizeOptions(Options{MaxLinks: 1})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(visualizationFixture(), options, adjustments)
	want := visualLink{From: "artifact-0002", To: "capability-0001", Kind: "has capability match"}
	if len(doc.Links) != 1 || doc.Links[0] != want {
		t.Fatalf("first bounded link = %+v, want actionable link %+v", doc.Links, want)
	}
}

func TestLinkIdentityPreservesNULDelimitedValues(t *testing.T) {
	b := documentBuilder{
		options:  normalizedOptions{links: 10},
		text:     textBudget{remaining: 1024, perString: 128},
		linkKeys: make(map[visualLinkIdentity]struct{}),
	}
	b.addLink("a", "b\x00c", "d")
	b.addLink("a\x00b", "c", "d")
	b.addLink("a", "b\x00c", "d")
	if len(b.doc.Links) != 2 {
		t.Fatalf("distinct NUL-containing links were collapsed or a duplicate was retained: %#v", b.doc.Links)
	}
}

func TestMissingAndDuplicateReferencesAreDisclosed(t *testing.T) {
	rep := visualizationFixture()
	rep.ArtifactNodes = append(rep.ArtifactNodes, artifact.Node{ID: "node-2", LogicalPath: "duplicate", AnalyzeStatus: "analyzed"})
	rep.ExecutionRoots[0].DeclarationNodeID = "missing-node"
	options, adjustments, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(rep, options, adjustments)
	notes := strings.Join(doc.Omissions, "\n")
	if !strings.Contains(notes, "ordinary reference attempts could not be resolved") || !strings.Contains(notes, "duplicate source identifier definitions were marked ambiguous") || !strings.Contains(notes, "reference attempts targeted ambiguous identifiers") {
		t.Fatalf("reference limitations were not disclosed:\n%s", notes)
	}
	for _, link := range doc.Links {
		if link == (visualLink{From: "artifact-0001", To: "artifact-0002", Kind: "contains"}) ||
			link == (visualLink{From: "artifact-0002", To: "capability-0001", Kind: "has capability match"}) {
			t.Fatalf("ambiguous source ID produced a false edge: %+v", link)
		}
	}
}

func TestDuplicateReferenceBeyondDisplayLimitNeverDrawsFirstMatchEdge(t *testing.T) {
	rep := visualizationFixture()
	rep.ArtifactNodes = []artifact.Node{
		{ID: "duplicate", LogicalPath: "shown"},
		{ID: "duplicate", LogicalPath: "omitted"},
	}
	rep.Relationships = nil
	rep.Capabilities[0].SubjectNodeID = "duplicate"
	options, adjustments, err := normalizeOptions(Options{MaxArtifactNodes: 1})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(rep, options, adjustments)
	for _, link := range doc.Links {
		if link.From == "artifact-0001" && link.To == "capability-0001" {
			t.Fatalf("duplicate ID outside the display limit produced a first-match edge: %+v", link)
		}
	}
	if !strings.Contains(strings.Join(doc.Omissions, "\n"), "duplicate source identifier definitions were marked ambiguous") {
		t.Fatalf("tail duplicate was not disclosed: %v", doc.Omissions)
	}
}

func TestDuplicateContextTargetIDsFailClosed(t *testing.T) {
	t.Run("artifact property", func(t *testing.T) {
		rep := visualizationFixture()
		rep.ArtifactNodes = append(rep.ArtifactNodes, artifact.Node{ID: "node-2", LogicalPath: "duplicate", AnalyzeStatus: "analyzed"})
		options, adjustments, err := normalizeOptions(Options{})
		if err != nil {
			t.Fatal(err)
		}
		doc := buildDocument(rep, options, adjustments)
		if got := nodeDetail(doc.Nodes, "artifact", "Artifact properties"); got != "" {
			t.Fatalf("ambiguous artifact ID received an artifact property: %q", got)
		}
		if !strings.Contains(strings.Join(doc.Omissions, "\n"), "Context: 1 artifact property or network/TLS observation associations") {
			t.Fatalf("omitted ambiguous artifact property was not disclosed: %#v", doc.Omissions)
		}
	})

	t.Run("modeled operation network context", func(t *testing.T) {
		rep := visualizationFixture()
		duplicate := rep.Operations[0]
		rep.Operations = append(rep.Operations, duplicate)
		options, adjustments, err := normalizeOptions(Options{})
		if err != nil {
			t.Fatal(err)
		}
		doc := buildDocument(rep, options, adjustments)
		if got := nodeDetail(doc.Nodes, "operation", "Network context"); got != "" {
			t.Fatalf("ambiguous operation ID received network context: %q", got)
		}
		if !strings.Contains(strings.Join(doc.Omissions, "\n"), "Context:") {
			t.Fatalf("omitted ambiguous network context was not disclosed: %#v", doc.Omissions)
		}
	})
}

func TestReferenceUniquenessScanFailsClosedAtHardLimit(t *testing.T) {
	rep := visualizationFixture()
	rep.ArtifactNodes = make([]artifact.Node, maxReferenceTailScan+2)
	rep.ArtifactNodes[0] = artifact.Node{ID: "shown", LogicalPath: "shown"}
	for i := 1; i < len(rep.ArtifactNodes); i++ {
		rep.ArtifactNodes[i].ID = fmt.Sprintf("tail-%d", i)
	}
	rep.Relationships = nil
	rep.Capabilities[0].SubjectNodeID = "shown"
	options, adjustments, err := normalizeOptions(Options{MaxArtifactNodes: 1})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(rep, options, adjustments)
	for _, link := range doc.Links {
		if link.From == "artifact-0001" && link.To == "capability-0001" {
			t.Fatalf("indeterminate source-ID uniqueness produced an edge: %+v", link)
		}
	}
	notes := strings.Join(doc.Omissions, "\n")
	if !strings.Contains(notes, "exceeded the bounded uniqueness scan") || !strings.Contains(notes, "first-match edges") {
		t.Fatalf("bounded uniqueness fallback was not disclosed: %v", doc.Omissions)
	}
}

func TestPerRecordLinkTraversalLimitIsDisclosed(t *testing.T) {
	rep := visualizationFixture()
	for i := 0; i < maxListItems+2; i++ {
		rep.Capabilities[0].OperationIDs = append(rep.Capabilities[0].OperationIDs, "extra-operation")
	}
	options, adjustments, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc := buildDocument(rep, options, adjustments)
	if !strings.Contains(strings.Join(doc.Omissions, "\n"), "additional execution-owner or modeled-operation references were not traversed") {
		t.Fatalf("per-record traversal limit was not disclosed: %v", doc.Omissions)
	}
}

func TestHardLimitsAndInvalidOptions(t *testing.T) {
	tooLarge := hardTextByteLimit + hardStringByteLimit + hardLinkLimit + hardArtifactNodeLimit + 1
	options, adjustments, err := normalizeOptions(Options{
		MaxArtifactNodes: tooLarge, MaxAnalysisSelections: tooLarge, MaxExecutionRoots: tooLarge, MaxInvokedTargets: tooLarge,
		MaxOperations:        tooLarge,
		MaxCapabilityMatches: tooLarge, MaxOperationRelations: tooLarge, MaxCoverageItems: tooLarge,
		MaxLinks: tooLarge, MaxTextBytes: tooLarge, MaxStringBytes: tooLarge,
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.artifactNodes != hardArtifactNodeLimit || options.analysisSelections != hardAnalysisSelectionLimit ||
		options.executionRoots != hardExecutionRootLimit || options.invokedTargets != hardInvokedTargetLimit ||
		options.modeledOperations != hardOperationLimit || options.capabilityMatches != hardCapabilityMatchLimit ||
		options.operationRelations != hardOperationRelationLimit || options.coverage != hardCoverageLimit ||
		options.links != hardLinkLimit || options.textBytes != hardTextByteLimit || options.stringBytes != hardStringByteLimit {
		t.Fatalf("hard limits were not applied: %+v", options)
	}
	if len(adjustments) != 11 {
		t.Fatalf("adjustment notes = %d, want 11", len(adjustments))
	}
	if _, _, err := normalizeOptions(Options{MaxOperations: -1}); err == nil {
		t.Fatal("negative limit was accepted")
	}
}

func TestHostileStringsAndCollectionsRemainBounded(t *testing.T) {
	huge := strings.Repeat("x", 8<<20)
	rep := report.Report{
		Artifact:      huge,
		Analysis:      report.AnalysisMetadata{Architecture: huge},
		ArtifactNodes: []artifact.Node{{ID: huge, LogicalPath: huge, Kind: huge, AnalyzeStatus: "analyzed"}},
		Operations: []behavior.ModeledOperation{{
			ID: huge, SubjectNodeID: huge, Kind: behavior.OperationKind(huge),
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceKind(huge), huge))),
			EvidenceIDs:      []string{huge, huge}, Qualifiers: oversizedQualifierMap(),
		}},
		Relationships: make([]artifact.Edge, maxRelationshipScan+100),
	}
	for i := range rep.Relationships {
		rep.Relationships[i] = artifact.Edge{From: huge, To: huge, Kind: huge}
	}
	var output bytes.Buffer
	if err := Write(&output, rep, Options{MaxTextBytes: 4096, MaxStringBytes: 128, MaxLinks: 4}); err != nil {
		t.Fatal(err)
	}
	if output.Len() > 250_000 {
		t.Fatalf("bounded hostile report produced %d bytes", output.Len())
	}
	doc := decodeEmbeddedDocument(t, output.String())
	for _, node := range doc.Nodes {
		if len(node.Title) > 128 || len(node.Subtitle) > 128 {
			t.Fatalf("unbounded node strings: %+v", node)
		}
		for _, detail := range node.Details {
			if len(detail.Label) > 128 || len(detail.Value) > 128 {
				t.Fatalf("unbounded detail: %+v", detail)
			}
		}
	}
	notes := strings.Join(doc.Omissions, "\n")
	if !strings.Contains(notes, "Text:") || !strings.Contains(notes, "Cross-references:") || !strings.Contains(notes, "Connections:") {
		t.Fatalf("missing hostile-input omission notes:\n%s", notes)
	}
}

func TestDirectNetworkContextCollectionsRemainBounded(t *testing.T) {
	rep := visualizationFixture()
	rep.NetworkImplementations = make([]behavior.NetworkImplementationObservation, 10_000)
	for i := range rep.NetworkImplementations {
		rep.NetworkImplementations[i] = behavior.NetworkImplementationObservation{
			Kind: behavior.NetworkImplementationAPICall, OperationIDs: []string{"operation-1"}, APIOrTool: fmt.Sprintf("network-api-%d", i),
		}
	}
	var output bytes.Buffer
	if err := Write(&output, rep, Options{MaxTextBytes: 16 << 10}); err != nil {
		t.Fatal(err)
	}
	if output.Len() > 300_000 {
		t.Fatalf("direct context collections produced %d bytes", output.Len())
	}
	doc := decodeEmbeddedDocument(t, output.String())
	context := nodeDetail(doc.Nodes, "operation", "Network context")
	if !strings.Contains(context, "network-api-0") || strings.Contains(context, "network-api-9999") {
		t.Fatalf("network implementation context was not bounded: %q", context)
	}
	if !strings.Contains(strings.Join(doc.Omissions, "\n"), "Context:") {
		t.Fatalf("bounded modeled-operation association traversal was not disclosed: %#v", doc.Omissions)
	}
}

func TestDisplayControlsAndInvalidUTF8AreVisiblyEscaped(t *testing.T) {
	rep := report.Report{Artifact: "left\u202eright\n" + string([]byte{0xff})}
	var output bytes.Buffer
	if err := Write(&output, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	doc := decodeEmbeddedDocument(t, output.String())
	if strings.ContainsRune(doc.Artifact, '\u202e') || strings.ContainsRune(doc.Artifact, '\n') || !strings.Contains(doc.Artifact, `\u202e`) || !strings.Contains(doc.Artifact, `\n`) || !strings.Contains(doc.Artifact, `\xff`) {
		t.Fatalf("artifact = %q, want visible escapes for bidi, newline, and invalid byte", doc.Artifact)
	}
}

func TestControlEscapingDoesNotConsumeUnwrittenBudget(t *testing.T) {
	budget := textBudget{remaining: 4, perString: 4}
	if got := budget.keep("\n"); got != `\n` {
		t.Fatalf("escaped newline = %q", got)
	}
	if budget.remaining != 2 || budget.truncated != 0 || budget.escaped != 1 || budget.exhausted {
		t.Fatalf("budget after visible escape = %+v", budget)
	}
	if got := budget.keep("ab"); got != "ab" || budget.remaining != 0 || !budget.exhausted {
		t.Fatalf("budget after exact final value = %q %+v", got, budget)
	}
}

func TestWritePropagatesWriterErrors(t *testing.T) {
	want := errors.New("write failed")
	if err := Write(errorWriter{err: want}, report.Report{}, Options{}); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if err := Write(zeroWriter{}, report.Report{}, Options{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short writer error = %v, want %v", err, io.ErrShortWrite)
	}
	if err := Write(nil, report.Report{}, Options{}); err == nil {
		t.Fatal("nil writer was accepted")
	}
}

func visualizationFixture() report.Report {
	return report.Report{
		SchemaVersion: report.SchemaVersion, Tool: "maratus", ToolVersion: "v0.1.0", ToolCommit: "0123456789abcdef", ToolModified: true, RulesetVersion: report.RulesetVersion, RuleCatalogDigest: rules.CatalogDigest(),
		Analysis: report.AnalysisMetadata{IncludeUnreferenced: true, ExpandContainers: true, Architecture: "arm64", MaxFileBytes: 1024},
		Artifact: "sample.app",
		ArtifactNodes: []artifact.Node{
			{ID: "node-1", LogicalPath: "sample.app", Kind: "app-bundle", AnalyzeStatus: "analyzed"},
			{ID: "node-2", ParentID: "node-1", LogicalPath: "sample.app/Contents/MacOS/sample", Kind: "macho", AnalyzeStatus: "partial", Architectures: []string{"arm64"}},
		},
		Relationships: []artifact.Edge{{From: "node-1", To: "node-2", Kind: "contains"}},
		AnalysisSelection: []behavior.AnalysisSelection{{
			NodeID: "node-2", Reasons: []behavior.SelectionReason{behavior.SelectionReasonExecutionRoot},
		}},
		ExecutionRoots: []behavior.ExecutionRoot{{
			ID: "root-1", Kind: "application", DeclarationNodeID: "node-1", StartNodeID: "node-2", Name: "sample", EvidenceIDs: []string{"ev-1"},
		}},
		InvokedTargets: []behavior.InvokedTarget{{
			ID: "target-1", Kind: "bundle-script", NodeID: "node-2",
			Source:      behavior.EntityRef{Kind: behavior.EntityKindExecutionRoot, ID: "root-1"},
			Execution:   behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{"root-1"}},
			Interpreter: "sh", EvidenceIDs: []string{"ev-1"},
		}},
		Operations: []behavior.ModeledOperation{
			{ID: "operation-1", SubjectNodeID: "node-2", Kind: "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://example.invalid/payload"})), EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportDirect, Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{"root-1"}, InvokedTargetIDs: []string{"target-1"}}},
			{ID: "operation-2", SubjectNodeID: "node-2", Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})), Support: behavior.SupportDirect, Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{"root-1"}}},
		},
		Evidence: []behavior.Evidence{{
			ID: "ev-1", NodeID: "node-2", Logical: "sample.app/Contents/MacOS/sample", Line: 7,
			Method: "disassembly", Kind: "imported-call", Value: "_curl_easy_perform",
		}},
		ArtifactProperties: []behavior.ArtifactProperty{{
			NodeID: "node-2", Kind: "entitlement", Value: "com.apple.security.network.client", Support: behavior.SupportDirect,
		}},
		NetworkImplementations: []behavior.NetworkImplementationObservation{{
			Kind: behavior.NetworkImplementationAPICall, SubjectNodeID: "node-2", OperationIDs: []string{"operation-1"}, APIOrTool: "Objective-C", HTTPImplementation: "URLSession", TLSProvider: "Apple system TLS",
			EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportDirect, Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{"root-1"}, InvokedTargetIDs: []string{"target-1"}},
		}},
		OperationRelations: []behavior.OperationRelation{{
			ID: "relation-1", Kind: behavior.RelationPrecedes,
			From:        behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-1"),
			To:          behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-2"),
			EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportDirect,
			Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{"root-1"}},
		}},
		Capabilities: []behavior.CapabilityMatch{{
			ID: "capability-1", RuleID: "macos.download-execute", Title: "Downloads and executes a payload", Namespace: "macos.execution",
			Support: behavior.SupportDirect, Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{"root-1"}, InvokedTargetIDs: []string{"target-1"}}, SubjectNodeID: "node-2", OperationIDs: []string{"operation-1", "operation-2"}, EvidenceIDs: []string{"ev-1"},
			MatchTrace: []behavior.MatchTraceClause{
				{Path: "match.relate.constraint", Kind: behavior.MatchTraceOperationRelation, RelationIDs: []string{"relation-1"}},
				{Path: "match.relate.left", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"}},
				{Path: "match.relate.right", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-2"}},
			},
		}},
		Coverage:    []behavior.Coverage{{NodeID: "node-2", AnalysisArea: "macho-instructions", Status: "partial", Detail: "bounded instruction decoding"}},
		Diagnostics: []string{"fixture diagnostic"},
	}
}

func nodeDetail(nodes []visualNode, nodeType, label string) string {
	for _, node := range nodes {
		if node.Type != nodeType {
			continue
		}
		for _, detail := range node.Details {
			if detail.Label == label && detail.Value != "" {
				return detail.Value
			}
		}
	}
	return ""
}

func decodeEmbeddedDocument(t *testing.T, output string) visualDocument {
	t.Helper()
	const marker = `<script id="scan-data" type="application/json">`
	start := strings.Index(output, marker)
	if start < 0 {
		t.Fatal("embedded data element not found")
	}
	start += len(marker)
	end := strings.Index(output[start:], "</script>")
	if end < 0 {
		t.Fatal("embedded data element is not closed")
	}
	var doc visualDocument
	if err := json.Unmarshal([]byte(output[start:start+end]), &doc); err != nil {
		t.Fatalf("embedded JSON: %v", err)
	}
	return doc
}

func containsLink(links []visualLink, want visualLink) bool {
	for _, link := range links {
		if link == want {
			return true
		}
	}
	return false
}

func oversizedQualifierMap() map[string]string {
	result := make(map[string]string, maxQualifierKeys+1)
	for i := 0; i <= maxQualifierKeys; i++ {
		result[string(rune('a'+i%26))+strings.Repeat("q", i/26)] = "value"
	}
	return result
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
