package extract

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/rules"
)

func TestPythonSourceFeaturesInventoryImportsAndQualifiedCalls(t *testing.T) {
	source := `import torch
import os.path as osp
import json, collections.abc as cabc
from pathlib import Path
from package.submodule import thing as renamed, other
from ..relative import item as rel
from . import *

torch.load(target)
renamed.member.invoke()
package.submodule.provider.call()
standalone()
`
	graph, _ := pythonSourceFeatureFixture(t, source)

	want := []pythonFeatureExpectation{
		{key: "python.import", value: "torch", line: 1, form: "import"},
		{key: "python.import", value: "os.path", line: 2, form: "import", alias: "osp"},
		{key: "python.import", value: "json", line: 3, form: "import"},
		{key: "python.import", value: "collections.abc", line: 3, form: "import", alias: "cabc"},
		{key: "python.import", value: "pathlib.Path", line: 4, form: "from-import"},
		{key: "python.import", value: "package.submodule.thing", line: 5, form: "from-import", alias: "renamed"},
		{key: "python.import", value: "package.submodule.other", line: 5, form: "from-import"},
		{key: "python.import", value: "..relative.item", line: 6, form: "from-import", alias: "rel"},
		{key: "python.import", value: ".*", line: 7, form: "from-import"},
		{key: "python.qualified_call", value: "torch.load", line: 9},
		{key: "python.qualified_call", value: "renamed.member.invoke", line: 10},
		{key: "python.qualified_call", value: "package.submodule.provider.call", line: 11},
	}
	assertPythonFeaturesExactly(t, graph, source, want)

	if got := pythonFeatureByKeyValue(graph, "python.qualified_call", "osp.join"); got != nil {
		t.Fatalf("invented a call from an import alias: %#v", got)
	}
	for _, feature := range pythonSourceFeatures(graph) {
		if feature.Key == "python.qualified_call" && len(feature.Qualifiers) != 0 {
			t.Fatalf("qualified-call syntax gained semantic qualifiers: %#v", feature)
		}
	}
}

func TestPythonSourceFeaturesPreserveSyntacticAliasesWithoutNameResolution(t *testing.T) {
	source := `import torch as t
from client.api import session as s
t.load(model_path)
s.transport.send(payload)
torch.load(other_path)
`
	graph, _ := pythonSourceFeatureFixture(t, source)

	for _, expectation := range []pythonFeatureExpectation{
		{key: "python.import", value: "torch", line: 1, form: "import", alias: "t"},
		{key: "python.import", value: "client.api.session", line: 2, form: "from-import", alias: "s"},
		{key: "python.qualified_call", value: "t.load", line: 3},
		{key: "python.qualified_call", value: "s.transport.send", line: 4},
		{key: "python.qualified_call", value: "torch.load", line: 5},
	} {
		assertPythonFeature(t, graph, source, expectation)
	}
	if pythonFeatureByKeyValue(graph, "python.qualified_call", "torch.load") == nil {
		t.Fatal("literal torch.load spelling was lost")
	}
	if pythonFeatureCount(graph, "python.qualified_call", "torch.load") != 1 {
		t.Fatalf("the alias t was resolved to torch instead of being retained syntactically: %#v", pythonSourceFeatures(graph))
	}
}

func TestPythonSourceFeaturesRequireSelectedEligiblePhysicalSource(t *testing.T) {
	tests := []struct {
		nodeID    string
		role      string
		mediaType string
		data      []byte
		selected  bool
		rawOnly   bool
		forced    bool
		want      bool
	}{
		{nodeID: "node-selected", selected: true, want: true},
		{nodeID: "node-unselected"},
		{nodeID: "node-raw", selected: true, rawOnly: true},
		{nodeID: "node-doc", role: "documentation", selected: true},
		{nodeID: "node-generated", role: "generated/build", selected: true},
		{
			nodeID: "node-binary", mediaType: "application/octet-stream",
			data: []byte("\x00provider.call()\n"), selected: true,
		},
		{nodeID: "node-forced-target", role: "packaged-content", selected: true, forced: true, want: true},
	}

	var graph behavior.Graph
	contents := make([]artifact.Content, 0, len(tests))
	for _, test := range tests {
		mediaType := test.mediaType
		if mediaType == "" {
			mediaType = "text/plain"
		}
		data := test.data
		if data == nil {
			data = []byte("provider.call()\n")
		}
		scopeID := graph.AddScope(behavior.Scope{
			NodeID: test.nodeID,
			Kind:   "artifact-node",
			Name:   test.nodeID + ".py",
		})
		contents = append(contents, artifact.Content{
			NodeID:                 test.nodeID,
			ScopeID:                scopeID,
			LogicalPath:            test.nodeID + ".py",
			Kind:                   "script",
			MediaType:              mediaType,
			Data:                   data,
			Role:                   test.role,
			RawFeaturesOnly:        test.rawOnly,
			BehaviorAnalysisForced: test.forced,
		})
		if test.selected {
			graph.AddAnalysisSelection(behavior.AnalysisSelection{
				NodeID: test.nodeID,
				Reasons: []behavior.SelectionReason{
					behavior.SelectionReasonDefaultRelevant,
				},
			})
		}
	}

	addPythonSourceFeatures(&graph, contents)
	for _, test := range tests {
		feature := pythonFeatureByNode(graph, test.nodeID)
		if test.want && feature == nil {
			t.Errorf("%s was eligible but produced no Python Feature", test.nodeID)
		}
		if !test.want && feature != nil {
			t.Errorf("%s was ineligible but produced a Python Feature: %#v", test.nodeID, feature)
		}
	}
}

func TestPythonSourceFeaturesSuppressCommentsAndAllStringDecoys(t *testing.T) {
	source := `# import comment.decoy
# comment.decoy.call()
ordinary = "import string.decoy; string.decoy.call()"
raw = r'raw.decoy.call()'
formatted = f"{formatted.decoy.call()}"
continued = "first \
continued.decoy.call()"
"""Module docstring.
import triple.decoy
triple.decoy.call()
"""
def worker():
    """Function docstring with function.decoy.call()."""
    value = 'ordinary.decoy.call()'
    real.provider.call()

after.provider.call()  # inline.decoy.call()
`
	graph, _ := pythonSourceFeatureFixture(t, source)

	assertPythonFeaturesExactly(t, graph, source, []pythonFeatureExpectation{
		{key: "python.qualified_call", value: "real.provider.call", line: 15, function: "worker"},
		{key: "python.qualified_call", value: "after.provider.call", line: 17},
	})
	for _, decoy := range []string{
		"comment.decoy.call",
		"string.decoy.call",
		"raw.decoy.call",
		"formatted.decoy.call",
		"continued.decoy.call",
		"triple.decoy.call",
		"function.decoy.call",
		"ordinary.decoy.call",
		"inline.decoy.call",
	} {
		if feature := pythonFeatureByKeyValue(graph, "python.qualified_call", decoy); feature != nil {
			t.Fatalf("string or comment decoy %q became a feature: %#v", decoy, feature)
		}
	}
}

func TestPythonSourceFeaturesFailClosedOnContinuedFormattedString(t *testing.T) {
	for _, prefix := range []string{"f", "t"} {
		t.Run(prefix, func(t *testing.T) {
			source := "before.real.call()\n" +
				"value = " + prefix + "\"{decoy \\\n" +
				"continued.decoy.call()}\"\n" +
				"after.must_not_survive.call()\n"
			graph, _ := pythonSourceFeatureFixture(t, source)

			assertPythonFeaturesExactly(t, graph, source, []pythonFeatureExpectation{
				{key: "python.qualified_call", value: "before.real.call", line: 1},
			})
			if !hasCoverageArea(graph, "node-python-features", "python-feature-analysis", "partial") {
				t.Fatalf("continued %s-string omission lacks partial coverage: %#v", prefix, graph.Coverage)
			}
		})
	}
}

func TestPythonSourceFeaturesFailClosedOnMalformedAndUnsupportedSyntax(t *testing.T) {
	tests := []struct {
		name          string
		source        string
		validLine     int
		absentImports []string
		absentCall    string
	}{
		{
			name: "malformed imports",
			source: `import
import valid.prefix, broken as
from package import
from package
valid.after.call()
`,
			validLine:     5,
			absentImports: []string{"valid.prefix", "package"},
		},
		{
			name: "parenthesized import",
			source: `from package import (
    multiline.provider.call(),
)
valid.after.call()
`,
			validLine:     4,
			absentImports: []string{"package.multiline"},
			absentCall:    "multiline.provider.call",
		},
		{
			name: "backslash continued import",
			source: `import continued.module \
    as continued_alias
valid.after.call()
`,
			validLine:     3,
			absentImports: []string{"continued.module"},
		},
		{
			name: "non-ASCII identifier",
			source: `naïve.provider.call()
valid.after.call()
`,
			validLine:  2,
			absentCall: "naïve.provider.call",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph, _ := pythonSourceFeatureFixture(t, test.source)
			assertPythonFeaturesExactly(t, graph, test.source, []pythonFeatureExpectation{
				{key: "python.qualified_call", value: "valid.after.call", line: test.validLine},
			})
			if !hasCoverageArea(graph, "node-python-features", "python-feature-analysis", "partial") {
				t.Fatalf("unsupported Python syntax lacks exact-node partial coverage: %#v", graph.Coverage)
			}
			for _, value := range test.absentImports {
				if feature := pythonFeatureByKeyValue(graph, "python.import", value); feature != nil {
					t.Fatalf("unsupported or partly malformed import retained a prefix fact %q: %#v", value, feature)
				}
			}
			if test.absentCall != "" {
				if feature := pythonFeatureByKeyValue(graph, "python.qualified_call", test.absentCall); feature != nil {
					t.Fatalf("unsupported non-ASCII identifier became a partial identifier fact: %#v", feature)
				}
			}
		})
	}
}

func TestPythonSourceFeaturesReportTheActualImportLimit(t *testing.T) {
	for _, test := range []struct {
		name       string
		importLine string
	}{
		{
			name: "component limit",
			importLine: "import " + strings.Repeat(
				"component.",
				maxPythonQualifiedCallComponents,
			) + "leaf",
		},
		{
			name:       "byte limit",
			importLine: "import " + strings.Repeat("a", maxPythonQualifiedCallBytes+1),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := test.importLine + "\nvalid.after.call()\n"
			graph, _ := pythonSourceFeatureFixture(t, source)

			assertPythonFeaturesExactly(t, graph, source, []pythonFeatureExpectation{
				{key: "python.qualified_call", value: "valid.after.call", line: 2},
			})
			want := fmt.Sprintf(
				"Python import name exceeded %d components or %d bytes",
				maxPythonQualifiedCallComponents,
				maxPythonQualifiedCallBytes,
			)
			for _, coverage := range graph.Coverage {
				if coverage.NodeID == "node-python-features" &&
					coverage.AnalysisArea == "python-feature-analysis" &&
					coverage.Status == "partial" &&
					strings.Contains(coverage.Detail, want) {
					return
				}
			}
			t.Fatalf("oversized import lacks its bounded-limit reason %q: %#v", want, graph.Coverage)
		})
	}
}

func TestPythonSourceFeaturesBoundCombinedFromImportComponents(t *testing.T) {
	module := func(components int) string {
		return strings.TrimSuffix(strings.Repeat("m.", components), ".")
	}
	allowedModule := module(maxPythonQualifiedCallComponents - 1)
	blockedModule := module(maxPythonQualifiedCallComponents)
	source := "from " + allowedModule + " import leaf\n" +
		"from " + blockedModule + " import leaf\n" +
		"valid.after.call()\n"
	graph, _ := pythonSourceFeatureFixture(t, source)

	assertPythonFeaturesExactly(t, graph, source, []pythonFeatureExpectation{
		{
			key: "python.import", value: allowedModule + ".leaf",
			line: 1, form: "from-import",
		},
		{key: "python.qualified_call", value: "valid.after.call", line: 3},
	})
	if feature := pythonFeatureByKeyValue(graph, "python.import", blockedModule+".leaf"); feature != nil {
		t.Fatalf("from-import exceeded the combined component limit: %#v", feature)
	}
	if !hasCoverageArea(graph, "node-python-features", "python-feature-analysis", "partial") {
		t.Fatalf("combined from-import component limit lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestPythonSourceFeaturesStopAtTruncatedPhysicalLine(t *testing.T) {
	source := "before.provider.call()\nimport package" +
		strings.Repeat(" ", maxTextAnalysisLineBytes) +
		".suffix\nafter.must_not_survive.call()\n"
	graph, _ := pythonSourceFeatureFixture(t, source)

	assertPythonFeaturesExactly(t, graph, source, []pythonFeatureExpectation{
		{key: "python.qualified_call", value: "before.provider.call", line: 1},
	})
	if !hasCoverageArea(graph, "node-python-features", "python-feature-analysis", "partial") {
		t.Fatalf("truncated physical line lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestPythonSourceFeaturesReportSameLineSuites(t *testing.T) {
	source := `def worker(): pass; package.body.call()
def quiet(): pass; import hidden_local
class Holder: pass; import class_body
if ready: pass; import conditional
after.provider.call()
`
	graph, _ := pythonSourceFeatureFixture(t, source)

	assertPythonFeaturesExactly(t, graph, source, []pythonFeatureExpectation{
		{key: "python.qualified_call", value: "after.provider.call", line: 5},
	})
	for _, omitted := range []struct {
		key   string
		value string
	}{
		{key: "python.qualified_call", value: "package.body.call"},
		{key: "python.import", value: "hidden_local"},
		{key: "python.import", value: "class_body"},
		{key: "python.import", value: "conditional"},
	} {
		if feature := pythonFeatureByKeyValue(graph, omitted.key, omitted.value); feature != nil {
			t.Fatalf("same-line suite observation escaped the bounded grammar: %#v", feature)
		}
	}
	if !hasCoverageArea(graph, "node-python-features", "python-feature-analysis", "partial") {
		t.Fatalf("same-line suite omissions lack partial coverage: %#v", graph.Coverage)
	}
}

func TestPythonSourceFeaturesDoNotCreateScopeFromIncompleteDeclaration(t *testing.T) {
	var source strings.Builder
	source.WriteString("before.provider.call()\ndef broken(\n")
	for index := 0; index <= maxSemanticContinuationLines; index++ {
		fmt.Fprintf(&source, "    argument%d,\n", index)
	}
	source.WriteString("):\n    hidden.provider.call()\nafter.provider.call()\n")

	graph, _ := pythonSourceFeatureFixture(t, source.String())
	assertPythonFeaturesExactly(t, graph, source.String(), []pythonFeatureExpectation{
		{key: "python.qualified_call", value: "before.provider.call", line: 1},
	})
	for _, scope := range graph.Scopes {
		if scope.Kind == "function" && scope.Function == "broken" {
			t.Fatalf("incomplete declaration created an unproved function scope: %#v", scope)
		}
	}
	if !hasCoverageArea(graph, "node-python-features", "python-feature-analysis", "partial") {
		t.Fatalf("incomplete declaration lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestPythonSourceFeaturesFailClosedWhenDeclarationScopeIsUnclear(t *testing.T) {
	t.Run("valid tab-separated declaration", func(t *testing.T) {
		source := "def\tworker():\n\tinside.provider.call()\nafter.provider.call()\n"
		graph, _ := pythonSourceFeatureFixture(t, source)
		assertPythonFeaturesExactly(t, graph, source, []pythonFeatureExpectation{
			{key: "python.qualified_call", value: "inside.provider.call", line: 2, function: "worker"},
			{key: "python.qualified_call", value: "after.provider.call", line: 3},
		})
	})

	for _, test := range []struct {
		name        string
		declaration string
		function    string
	}{
		{name: "missing parameters", declaration: "def worker:", function: "worker"},
		{name: "missing header colon", declaration: "def worker()", function: "worker"},
		{name: "hard-keyword name", declaration: "def class():", function: "class"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := "before.provider.call()\n" + test.declaration +
				"\n    hidden.provider.call()\nafter.provider.call()\n"
			graph, _ := pythonSourceFeatureFixture(t, source)
			assertPythonFeaturesExactly(t, graph, source, []pythonFeatureExpectation{
				{key: "python.qualified_call", value: "before.provider.call", line: 1},
			})
			for _, scope := range graph.Scopes {
				if scope.Kind == "function" && scope.Function == test.function {
					t.Fatalf("malformed declaration created an unproved function scope: %#v", scope)
				}
			}
			if !hasCoverageArea(graph, "node-python-features", "python-feature-analysis", "partial") {
				t.Fatalf("malformed declaration lacks partial coverage: %#v", graph.Coverage)
			}
		})
	}

	t.Run("non-ASCII tab-separated declaration", func(t *testing.T) {
		source := "before.provider.call()\ndef\tnaïve():\n\thidden.provider.call()\nafter.provider.call()\n"
		graph, _ := pythonSourceFeatureFixture(t, source)
		assertPythonFeaturesExactly(t, graph, source, []pythonFeatureExpectation{
			{key: "python.qualified_call", value: "before.provider.call", line: 1},
		})
		if !hasCoverageArea(graph, "node-python-features", "python-feature-analysis", "partial") {
			t.Fatalf("non-ASCII declaration lacks partial coverage: %#v", graph.Coverage)
		}
	})

	t.Run("explicit async continuation", func(t *testing.T) {
		source := "before.provider.call()\nasync \\\ndef worker():\n    hidden.provider.call()\nafter.provider.call()\n"
		graph, _ := pythonSourceFeatureFixture(t, source)
		assertPythonFeaturesExactly(t, graph, source, []pythonFeatureExpectation{
			{key: "python.qualified_call", value: "before.provider.call", line: 1},
		})
		if !hasCoverageArea(graph, "node-python-features", "python-feature-analysis", "partial") {
			t.Fatalf("async declaration continuation lacks partial coverage: %#v", graph.Coverage)
		}
	})
}

func TestPythonSourceFeaturesRejectHardKeywordsButRetainSoftKeywords(t *testing.T) {
	source := `import package as for
from package import class
class.provider()
object.class()
import match
match.provider()
valid.after.call()
`
	graph, _ := pythonSourceFeatureFixture(t, source)

	assertPythonFeaturesExactly(t, graph, source, []pythonFeatureExpectation{
		{key: "python.import", value: "match", line: 5, form: "import"},
		{key: "python.qualified_call", value: "match.provider", line: 6},
		{key: "python.qualified_call", value: "valid.after.call", line: 7},
	})
	for _, value := range []string{"package", "package.class"} {
		if feature := pythonFeatureByKeyValue(graph, "python.import", value); feature != nil {
			t.Fatalf("hard-keyword import syntax became a Feature: %#v", feature)
		}
	}
	for _, value := range []string{"class.provider", "object.class"} {
		if feature := pythonFeatureByKeyValue(graph, "python.qualified_call", value); feature != nil {
			t.Fatalf("hard-keyword call syntax became a Feature: %#v", feature)
		}
	}
}

func TestPythonSourceFeaturesUseExactFunctionAndMethodScopes(t *testing.T) {
	source := `module.top.call()
def outer(default=declaration.default.call()):
    outer.body.call()
    def inner(arg=inner.default.call()):
        inner.body.call()
    class Nested(base.Factory()):
        import nested.class_import
        nested.class_body.call()
        def nested_method(self):
            nested.method.call()
class TopLevel(root.Factory()):
    top.class_body.call()
    def top_method(self):
        top.method.call()
module.after.call()
`
	graph, content := pythonSourceFeatureFixture(t, source)

	want := []pythonFeatureExpectation{
		{key: "python.qualified_call", value: "module.top.call", line: 1},
		{key: "python.qualified_call", value: "outer.body.call", line: 3, function: "outer"},
		{key: "python.qualified_call", value: "inner.body.call", line: 5, function: "inner"},
		{key: "python.qualified_call", value: "nested.method.call", line: 10, function: "nested_method"},
		{key: "python.qualified_call", value: "top.method.call", line: 14, function: "top_method"},
		{key: "python.qualified_call", value: "module.after.call", line: 15},
	}
	assertPythonFeaturesExactly(t, graph, source, want)

	for _, expectation := range want {
		feature := pythonFeatureByKeyValue(graph, expectation.key, expectation.value)
		if expectation.function == "" {
			if feature.ScopeID != content.ScopeID || feature.SourceFunction != "" {
				t.Fatalf("module observation %q scope = %q/%q, want program scope %q", expectation.value, feature.ScopeID, feature.SourceFunction, content.ScopeID)
			}
			continue
		}
		scope := pythonFeatureScopeByID(graph, feature.ScopeID)
		if scope == nil || scope.NodeID != content.NodeID || scope.Kind != "function" ||
			scope.Function != expectation.function || feature.SourceFunction != expectation.function {
			t.Fatalf("observation %q lost exact function scope: feature=%#v scope=%#v", expectation.value, feature, scope)
		}
		matchingScopes := 0
		for _, candidate := range graph.Scopes {
			if candidate.NodeID == content.NodeID && candidate.Kind == "function" && candidate.Function == expectation.function {
				matchingScopes++
			}
		}
		if matchingScopes != 1 {
			t.Fatalf("observation %q created or selected an ambiguous duplicate scope for %q: %#v", expectation.value, expectation.function, graph.Scopes)
		}
	}

	for _, suppressed := range []string{
		"declaration.default.call",
		"inner.default.call",
		"base.Factory",
		"nested.class_body.call",
		"root.Factory",
		"top.class_body.call",
	} {
		if feature := pythonFeatureByKeyValue(graph, "python.qualified_call", suppressed); feature != nil {
			t.Fatalf("declaration or class-body call %q became a feature: %#v", suppressed, feature)
		}
	}
	if feature := pythonFeatureByKeyValue(graph, "python.import", "nested.class_import"); feature != nil {
		t.Fatalf("class-body import became an observation: %#v", feature)
	}
}

func TestPythonSourceFeaturesKeepRedefinedFunctionScopesDistinct(t *testing.T) {
	source := `def worker():
    first.provider.call()
def worker():
    second.provider.call()
`
	graph, _ := pythonSourceFeatureFixture(t, source)
	first := pythonFeatureByKeyValue(graph, "python.qualified_call", "first.provider.call")
	second := pythonFeatureByKeyValue(graph, "python.qualified_call", "second.provider.call")
	if first == nil || second == nil {
		t.Fatalf("missing call from a redefined function body: %#v", pythonSourceFeatures(graph))
		return
	}
	if first.SourceFunction != "worker" || second.SourceFunction != "worker" ||
		first.ScopeID == "" || second.ScopeID == "" || first.ScopeID == second.ScopeID {
		t.Fatalf("same-named function declarations shared a lexical scope: first=%#v second=%#v", first, second)
	}
	firstScope := pythonFeatureScopeByID(graph, first.ScopeID)
	secondScope := pythonFeatureScopeByID(graph, second.ScopeID)
	if firstScope == nil || secondScope == nil || firstScope.LineStart != 1 || secondScope.LineStart != 3 {
		t.Fatalf("features did not retain their declaration-specific scopes: first=%#v second=%#v", firstScope, secondScope)
	}
}

func TestPythonSourceFeaturesBoundCandidatesPerLineAndContinue(t *testing.T) {
	calls := make([]string, 0, maxPythonFeatureObservationsPerLine+1)
	for index := 0; index <= maxPythonFeatureObservationsPerLine; index++ {
		calls = append(calls, fmt.Sprintf("provider%d.call()", index))
	}
	source := strings.Join(calls, ", ") + "\nlater.provider.call()\n"
	graph, _ := pythonSourceFeatureFixture(t, source)

	lineOne := 0
	for _, feature := range pythonSourceFeatures(graph) {
		evidence := pythonFeatureEvidence(t, graph, feature)
		if evidence.Line == 1 {
			lineOne++
		}
	}
	if lineOne != maxPythonFeatureObservationsPerLine {
		t.Fatalf("line candidate count = %d, want bounded %d", lineOne, maxPythonFeatureObservationsPerLine)
	}
	if pythonFeatureByKeyValue(graph, "python.qualified_call", fmt.Sprintf("provider%d.call", maxPythonFeatureObservationsPerLine)) != nil {
		t.Fatalf("candidate beyond the per-line limit was retained: %#v", pythonSourceFeatures(graph))
	}
	assertPythonFeature(t, graph, source, pythonFeatureExpectation{
		key: "python.qualified_call", value: "later.provider.call", line: 2,
	})
	if !hasCoverageArea(graph, "node-python-features", "python-feature-analysis", "partial") {
		t.Fatalf("per-line truncation lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestPythonSourceFeaturesBoundCandidatesPerNode(t *testing.T) {
	var source strings.Builder
	for index := 0; index <= maxPythonFeatureObservationsPerNode; index++ {
		fmt.Fprintf(&source, "provider%d.call()\n", index)
	}
	graph, _ := pythonSourceFeatureFixture(t, source.String())

	features := pythonSourceFeatures(graph)
	if len(features) != maxPythonFeatureObservationsPerNode {
		t.Fatalf("node feature count = %d, want bounded %d", len(features), maxPythonFeatureObservationsPerNode)
	}
	if pythonFeatureByKeyValue(graph, "python.qualified_call", fmt.Sprintf("provider%d.call", maxPythonFeatureObservationsPerNode)) != nil {
		t.Fatalf("candidate beyond the per-node limit was retained: %#v", features[len(features)-1])
	}
	if !hasCoverageArea(graph, "node-python-features", "python-feature-analysis", "partial") {
		t.Fatalf("per-node truncation lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestPythonSourceFeaturesExactNodeCapAtEOFIsComplete(t *testing.T) {
	var source strings.Builder
	for index := 0; index < maxPythonFeatureObservationsPerNode; index++ {
		fmt.Fprintf(&source, "provider%d.call()\n", index)
	}
	graph, _ := pythonSourceFeatureFixture(t, source.String())

	if got := len(pythonSourceFeatures(graph)); got != maxPythonFeatureObservationsPerNode {
		t.Fatalf("exact-cap node retained %d observations, want %d", got, maxPythonFeatureObservationsPerNode)
	}
	if hasCoverageArea(graph, "node-python-features", "python-feature-analysis", "partial") {
		t.Fatalf("exact node cap at EOF overclaimed omitted source: %#v", graph.Coverage)
	}
}

func TestPythonSourceFeaturesBoundInspectionObservationsAndRemainDeterministic(t *testing.T) {
	// One observation per node makes the exact inspection-wide observation
	// boundary and the first omitted node easy to verify independently.
	contents := make([]artifact.Content, 0, maxPythonFeatureObservationsPerInspection+1)
	for index := 0; index <= maxPythonFeatureObservationsPerInspection; index++ {
		contents = append(contents, artifact.Content{
			NodeID:           fmt.Sprintf("node-%05d", index),
			ScopeID:          fmt.Sprintf("scope-%05d", index),
			LogicalPath:      fmt.Sprintf("module-%05d.py", index),
			Kind:             "script",
			MediaType:        "text/plain",
			SemanticLanguage: "python",
			Data:             []byte(fmt.Sprintf("provider%d.call()\n", index)),
		})
	}
	run := func() behavior.Graph {
		var graph behavior.Graph
		for _, content := range contents {
			graph.AddAnalysisSelection(behavior.AnalysisSelection{
				NodeID: content.NodeID,
				Reasons: []behavior.SelectionReason{
					behavior.SelectionReasonDefaultRelevant,
				},
			})
		}
		addPythonSourceFeatures(&graph, contents)
		return graph
	}
	first := run()
	second := run()
	if !reflect.DeepEqual(first, second) {
		t.Fatal("bounded Python feature inventory is nondeterministic")
	}
	if got := len(pythonSourceFeatures(first)); got != maxPythonFeatureObservationsPerInspection {
		t.Fatalf("inspection observations = %d, want %d", got, maxPythonFeatureObservationsPerInspection)
	}
	last := contents[len(contents)-1]
	if pythonFeatureByNode(first, last.NodeID) != nil {
		t.Fatalf("node beyond the inspection cap was scanned: %#v", pythonFeatureByNode(first, last.NodeID))
	}
	if !hasCoverageArea(first, last.NodeID, "python-feature-analysis", "partial") &&
		!hasCoverageArea(first, "", "python-feature-analysis", "partial") {
		t.Fatalf("inspection cap lacks deterministic partial coverage: %#v", first.Coverage)
	}
}

func TestPythonSourceFeaturesAreObservationalOnlyAndDoNotMatchCapabilities(t *testing.T) {
	source := `import torch
torch.load(model)
client.transport.send(payload)
`
	first, _ := pythonSourceFeatureFixture(t, source)
	second, _ := pythonSourceFeatureFixture(t, source)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("same Python source produced different graphs:\nfirst=%#v\nsecond=%#v", first, second)
	}
	if len(first.Operations) != 0 || len(first.Relations) != 0 || len(first.ExecutionRoots) != 0 ||
		len(first.InvokedTargets) != 0 || len(first.Network) != 0 {
		t.Fatalf("observational Python features emitted executable IR: %#v", first)
	}
	if matches := rules.Evaluate(&first); len(matches) != 0 {
		t.Fatalf("observational Python features became capabilities: %#v", matches)
	}
}

func TestPythonSourceFeaturesCannotBePromotedToExecution(t *testing.T) {
	source := `module.top.call()
def worker():
    module.worker.call()
`
	graph, content := pythonSourceFeatureFixture(t, source)
	connected := connectedExecutionContext([]string{"root-python"}, []string{"target-python"})

	promoteNodeExecution(&graph, map[string]behavior.ExecutionContext{content.NodeID: connected})
	for _, feature := range pythonSourceFeatures(graph) {
		if feature.Execution.Connectivity != behavior.ConnectivityUnknown {
			t.Fatalf("node ownership promoted an observational Python feature: %#v", feature)
		}
	}

	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID: content.NodeID, ScopeID: content.ScopeID, Logical: content.LogicalPath,
		Line: 4, Offset: int64(len(source)), OffsetKnown: true,
		Method: "test", Kind: "function-call", Value: "worker",
	})
	graph.AddFeature(behavior.Feature{
		NodeID: content.NodeID, ScopeID: content.ScopeID,
		Key: "script.function_call", Value: "worker",
		EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect, Execution: connected,
	})
	promoteDirectScriptFunctionCalls(&graph, map[string]behavior.ExecutionContext{content.NodeID: connected})
	for _, feature := range pythonSourceFeatures(graph) {
		if feature.Execution.Connectivity != behavior.ConnectivityUnknown {
			t.Fatalf("direct-call reachability promoted an observational Python feature: %#v", feature)
		}
	}
}

func TestRunPythonFeatureInventoryCannotStarveLaterSemanticOperation(t *testing.T) {
	var noisy strings.Builder
	for index := 0; index <= maxPythonFeatureObservationsPerNode; index++ {
		fmt.Fprintf(&noisy, "provider%d.call()\n", index)
	}

	var artifacts artifact.Graph
	rootID := artifacts.AddNode(artifact.Node{
		LogicalPath: "fixture", Kind: "directory", AnalyzeStatus: "analyzed",
	})
	noisyID := artifacts.AddNode(artifact.Node{
		ParentID: rootID, LogicalPath: "fixture/noisy.py", Kind: "script",
		MediaType: "text/plain", AnalyzeStatus: "analyzed",
	})
	executeID := artifacts.AddNode(artifact.Node{
		ParentID: rootID, LogicalPath: "fixture/execute.py", Kind: "script",
		MediaType: "text/plain", AnalyzeStatus: "analyzed",
	})
	artifacts.AddEdge(rootID, noisyID, "contains")
	artifacts.AddEdge(rootID, executeID, "contains")

	graph := Run(Context{
		Artifacts: &artifacts,
		Options: artifact.Options{
			IncludeUnreferenced: true,
			MaxEvidence:         3,
		},
		Contents: []artifact.Content{
			{
				NodeID: noisyID, LogicalPath: "fixture/noisy.py", Kind: "script",
				MediaType: "text/plain", SemanticLanguage: "python", Data: []byte(noisy.String()),
			},
			{
				NodeID: executeID, LogicalPath: "fixture/execute.py", Kind: "script",
				MediaType: "text/plain", SemanticLanguage: "python",
				Data: []byte("import subprocess\nsubprocess.run(['/bin/echo'])\n"),
			},
		},
	})

	assertOperation(t, graph, behavior.OperationProcessExecute, "file", "/bin/echo")
	for _, operation := range graph.Operations {
		if operation.SubjectNodeID == executeID && len(operation.EvidenceIDs) != 2 {
			t.Fatalf("later semantic operation lost its evidence before low-priority feature inventory: %#v", operation)
		}
	}
	if graph.EvidenceLimitDrops == 0 {
		t.Fatalf("fixture did not exercise the late Python Feature lane after semantic evidence exhausted: %#v", graph)
	}
}

type pythonFeatureExpectation struct {
	key      string
	value    string
	line     int
	form     string
	alias    string
	function string
}

func pythonSourceFeatureFixture(t *testing.T, source string) (behavior.Graph, artifact.Content) {
	t.Helper()
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:           "node-python-features",
		LogicalPath:      "fixture.py",
		PhysicalPath:     "/private/test/fixture.py",
		Kind:             "script",
		MediaType:        "text/plain",
		SemanticLanguage: "python",
		Data:             []byte(source),
	}
	content.ScopeID = graph.AddScope(behavior.Scope{
		NodeID: content.NodeID, Kind: "artifact-node", Name: content.LogicalPath,
	})
	graph.AddAnalysisSelection(behavior.AnalysisSelection{
		NodeID: content.NodeID,
		Reasons: []behavior.SelectionReason{
			behavior.SelectionReasonDefaultRelevant,
		},
	})
	ExtractText(&graph, content)
	addPythonSourceFeatures(&graph, []artifact.Content{content})
	if err := graph.Sort(); err != nil {
		t.Fatalf("invalid Python feature fixture graph: %v", err)
	}
	return graph, content
}

func assertPythonFeaturesExactly(t *testing.T, graph behavior.Graph, source string, want []pythonFeatureExpectation) {
	t.Helper()
	got := pythonSourceFeatures(graph)
	if len(got) != len(want) {
		t.Fatalf("Python feature count = %d, want %d:\ngot=%#v\nwant=%#v", len(got), len(want), got, want)
	}
	for _, expectation := range want {
		assertPythonFeature(t, graph, source, expectation)
	}
}

func assertPythonFeature(t *testing.T, graph behavior.Graph, source string, want pythonFeatureExpectation) {
	t.Helper()
	feature := pythonFeatureByKeyValue(graph, want.key, want.value)
	if feature == nil {
		t.Fatalf("missing %s=%q: %#v", want.key, want.value, pythonSourceFeatures(graph))
		return
	}
	if feature.Support != behavior.SupportDirect ||
		feature.Execution.Connectivity != behavior.ConnectivityUnknown ||
		len(feature.Execution.ExecutionRootIDs) != 0 ||
		len(feature.Execution.InvokedTargetIDs) != 0 {
		t.Fatalf("%s=%q gained weak support or execution ownership: %#v", want.key, want.value, feature)
	}
	if feature.NodeID != "node-python-features" || feature.ScopeID == "" {
		t.Fatalf("%s=%q lost its exact node or scope: %#v", want.key, want.value, feature)
	}
	if feature.SourceFunction != want.function {
		t.Fatalf("%s=%q function = %q, want %q", want.key, want.value, feature.SourceFunction, want.function)
	}
	scope := pythonFeatureScopeByID(graph, feature.ScopeID)
	if scope == nil || scope.NodeID != feature.NodeID {
		t.Fatalf("%s=%q references a missing or cross-node scope: feature=%#v scope=%#v", want.key, want.value, feature, scope)
	}
	if want.function == "" && scope.Kind != "artifact-node" {
		t.Fatalf("%s=%q module observation scope = %#v, want artifact-node", want.key, want.value, scope)
	}
	if want.function != "" && (scope.Kind != "function" || scope.Function != want.function) {
		t.Fatalf("%s=%q function observation scope = %#v, want function %q", want.key, want.value, scope, want.function)
	}
	if feature.Qualifiers["form"] != want.form {
		t.Fatalf("%s=%q form = %q, want %q", want.key, want.value, feature.Qualifiers["form"], want.form)
	}
	if feature.Qualifiers["alias"] != want.alias {
		t.Fatalf("%s=%q alias = %q, want %q", want.key, want.value, feature.Qualifiers["alias"], want.alias)
	}
	expectedQualifierCount := 0
	if want.form != "" {
		expectedQualifierCount++
	}
	if want.alias != "" {
		expectedQualifierCount++
	}
	if len(feature.Qualifiers) != expectedQualifierCount {
		t.Fatalf("%s=%q qualifiers = %#v, want only form/alias", want.key, want.value, feature.Qualifiers)
	}

	evidence := pythonFeatureEvidence(t, graph, *feature)
	if evidence.NodeID != feature.NodeID || evidence.ScopeID != feature.ScopeID ||
		evidence.Logical != "fixture.py" || evidence.Physical != "/private/test/fixture.py" ||
		evidence.Line != want.line || !evidence.ByteOffsetKnown() ||
		evidence.Function != want.function || evidence.Value != want.value {
		t.Fatalf("%s=%q evidence is not exact: feature=%#v evidence=%#v", want.key, want.value, feature, evidence)
	}
	if want.line > 0 {
		start, end := pythonSourceLineBounds(source, want.line)
		if evidence.Offset < int64(start) || evidence.Offset >= int64(end) {
			t.Fatalf("%s=%q byte offset %d is outside source line %d [%d,%d)", want.key, want.value, evidence.Offset, want.line, start, end)
		}
	}
	wantKind := "python-import"
	if want.key == "python.qualified_call" {
		wantKind = "python-qualified-call"
	}
	if evidence.Method != "python-lexical" || evidence.Kind != wantKind {
		t.Fatalf("%s=%q evidence provenance = %q/%q, want python-lexical/%s", want.key, want.value, evidence.Method, evidence.Kind, wantKind)
	}
}

func pythonSourceFeatures(graph behavior.Graph) []behavior.Feature {
	out := make([]behavior.Feature, 0, len(graph.Features))
	for _, feature := range graph.Features {
		if feature.Key == "python.import" || feature.Key == "python.qualified_call" {
			out = append(out, feature)
		}
	}
	return out
}

func pythonFeatureByKeyValue(graph behavior.Graph, key, value string) *behavior.Feature {
	for index := range graph.Features {
		if graph.Features[index].Key == key && graph.Features[index].Value == value {
			return &graph.Features[index]
		}
	}
	return nil
}

func pythonFeatureByNode(graph behavior.Graph, nodeID string) *behavior.Feature {
	for index := range graph.Features {
		if (graph.Features[index].Key == "python.import" || graph.Features[index].Key == "python.qualified_call") &&
			graph.Features[index].NodeID == nodeID {
			return &graph.Features[index]
		}
	}
	return nil
}

func pythonFeatureCount(graph behavior.Graph, key, value string) int {
	count := 0
	for _, feature := range graph.Features {
		if feature.Key == key && feature.Value == value {
			count++
		}
	}
	return count
}

func pythonFeatureEvidence(t *testing.T, graph behavior.Graph, feature behavior.Feature) behavior.Evidence {
	t.Helper()
	if len(feature.EvidenceIDs) != 1 {
		t.Fatalf("feature has %d evidence references, want exactly one: %#v", len(feature.EvidenceIDs), feature)
	}
	for _, evidence := range graph.Evidence {
		if evidence.ID == feature.EvidenceIDs[0] {
			return evidence
		}
	}
	t.Fatalf("feature references missing evidence %q: %#v", feature.EvidenceIDs[0], graph.Evidence)
	return behavior.Evidence{}
}

func pythonFeatureScopeByID(graph behavior.Graph, scopeID string) *behavior.Scope {
	for index := range graph.Scopes {
		if graph.Scopes[index].ID == scopeID {
			return &graph.Scopes[index]
		}
	}
	return nil
}

func pythonSourceLineBounds(source string, line int) (int, int) {
	start := 0
	for current := 1; current < line; current++ {
		next := strings.IndexByte(source[start:], '\n')
		if next < 0 {
			return len(source), len(source)
		}
		start += next + 1
	}
	end := strings.IndexByte(source[start:], '\n')
	if end < 0 {
		return start, len(source)
	}
	return start, start + end
}
