package extract

import (
	"fmt"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestJavaScriptASTLexicalStringResources(t *testing.T) {
	for _, declaration := range []string{
		`const path="/tmp/inert";`,
		`let path="/tmp/inert";`,
		`const base="/tmp/"; const path=base+"inert";`,
		`const first="/tmp/inert"; const path=first;`,
		"const base=\"/tmp\"; const path=`${base}/inert`;",
		`const first="/tmp/", last="inert", path=first+last;`,
	} {
		graph := javaScriptASTExtract(`const fs=require("fs");` + declaration + `fs.readFileSync(path);`)
		if len(graph.Operations) != 1 {
			t.Fatalf("%s: operations=%#v", declaration, graph.Operations)
		}
		op := graph.Operations[0]
		binding := op.ResourceBindings[0]
		if binding.Resource.Value != "/tmp/inert" || len(binding.EvidenceIDs) < 2 || len(op.EvidenceIDs) < 5 || op.Support != behavior.SupportCorroborated {
			t.Fatalf("%s: value or declaration provenance lost: %#v", declaration, op)
		}
	}
}

func TestJavaScriptASTValuesKeepAmbiguityUnknown(t *testing.T) {
	for _, body := range []string{
		`fs.readFileSync(path);const path="/tmp/inert";`,
		`const path=path;fs.readFileSync(path);`,
		`const path=later;const later="/tmp/inert";fs.readFileSync(path);`,
		`let path="/tmp/inert";path=other;fs.readFileSync(path);`,
		`let path="/tmp/inert";[path]=other;fs.readFileSync(path);`,
		`let path;if(condition)path="/tmp/inert";fs.readFileSync(path);`,
		`var path="/tmp/inert";fs.readFileSync(path);`,
		`const path="/tmp/inert";function read(path){fs.readFileSync(path);}`,
		`const path="/tmp/inert";function read(){fs.readFileSync(path);}`,
		`function read(){if(condition)var path="/tmp/inert";fs.readFileSync(path);}`,
		`const path="/tmp/"+unknown;fs.readFileSync(path);`,
		"const path=`/tmp/${unknown}`;fs.readFileSync(path);",
		"const path=String.raw`/tmp/inert`;fs.readFileSync(path);",
		`const path="/tmp/"+1;fs.readFileSync(path);`,
		`const path=["/tmp/","inert"].join("");fs.readFileSync(path);`,
		`const path={toString(){return "/tmp/inert"}};fs.readFileSync(path);`,
	} {
		graph := javaScriptASTExtract(`const fs=require("fs");` + body)
		if len(graph.Operations) != 1 || graph.Operations[0].ResourceBindings[0].Resource.Value != "" {
			t.Fatalf("ambiguous operand acquired a value: %s\n%#v", body, graph.Operations)
		}
	}
}

func TestJavaScriptASTFunctionLocalImmutableVar(t *testing.T) {
	graph := javaScriptASTExtract(`const fs=require("fs");function read(){var path="/tmp/inert";fs.readFileSync(path);}`)
	if len(graph.Operations) != 1 || graph.Operations[0].ResourceBindings[0].Resource.Value != "/tmp/inert" {
		t.Fatalf("local var initializer was not retained: %#v", graph.Operations)
	}
}

func TestJavaScriptASTStringCommandsUseSharedSemantics(t *testing.T) {
	for _, body := range []string{
		`const command="curl "+"https://example.invalid/test";cp.execSync(command);`,
		"const host=\"https://example.invalid\";const command=`curl ${host}/test`;cp.execSync(command);",
		`const exe="/usr/bin/curl"; const url="https://example.invalid/test";cp.spawnSync(exe,["-I",url]);`,
	} {
		graph := javaScriptASTExtract(`const cp=require("child_process");` + body)
		assertShellCommandNetwork(t, graph, "https://example.invalid/test")
		for _, op := range graph.Operations {
			if len(op.EvidenceIDs) < 5 || op.Support != behavior.SupportCorroborated {
				t.Fatalf("derived command lost causal evidence: %#v", op)
			}
		}
	}
}

func TestJavaScriptASTStringValuesDoNotBypassSelectionOrIdentity(t *testing.T) {
	graph := javaScriptASTExtract(`const cp=require("child_process");const command="curl https://example.invalid/test";cp.execSync(command,{shell:customShell});`)
	if len(graph.Network) != 0 || len(graph.Operations) != 1 || graph.Operations[0].Qualifiers["command_argument"] != "curl https://example.invalid/test" || graph.Operations[0].ResourceBindings[0].Resource.Value != "" {
		t.Fatalf("unknown options changed selection: %#v", graph.Operations)
	}
	for _, body := range []string{
		`const cp=require("child_process");const command="curl https://example.invalid/test";eval(source);cp.execSync(command);`,
		`const cp=require("child_process");const command="curl https://example.invalid/test";capture(cp);cp.execSync(command);`,
		`const cp=require("child_process");const command="curl https://example.invalid/test";cp.execSync=other;cp.execSync(command);`,
	} {
		if graph := javaScriptASTExtract(body); len(graph.Operations) != 0 || len(graph.Network) != 0 {
			t.Fatalf("value resolution bypassed namespace proof: %s", body)
		}
	}
	graph = javaScriptASTExtract(`const cp=require("child_process");const url="https://example.invalid/test";cp.spawnSync("/usr/bin/curl",[unknown,url]);`)
	if len(graph.Network) != 0 || len(graph.Operations) != 1 || graph.Operations[0].Qualifiers["argument_coverage"] != "executable-only" {
		t.Fatalf("partial argv became a complete command: %#v", graph.Operations)
	}
	graph = javaScriptASTExtract(`const cp=require("child_process");const args=["-I","https://example.invalid/test"];const alias=args;alias[0]=unknown;cp.spawnSync("/usr/bin/curl",args);`)
	if len(graph.Network) != 0 || len(graph.Operations) != 1 || graph.Operations[0].Qualifiers["argument_coverage"] != "unresolved" || graph.Operations[0].Qualifiers["executable_argument"] != "/usr/bin/curl" {
		t.Fatalf("mutable bound array result: operations=%#v network=%#v", graph.Operations, graph.Network)
	}
	// Without an array/type proof, the overloaded second argument may also be
	// launch options. Retain the requested literal, not executable selection.
	if args, bound := graph.Operations[0].FirstBinding(behavior.ResourceRoleArguments); bound || args.Resource.Value != "" {
		t.Fatal("an aliased array acquired complete argv semantics")
	}
}

func TestJavaScriptASTLocalEmptyStringsAndFetchValues(t *testing.T) {
	graph := javaScriptASTExtract(`const cp=require("child_process");const exe="/usr/bin/printf", empty="";cp.spawnSync(exe,["%s",empty]);`)
	if len(graph.Operations) != 1 {
		t.Fatalf("empty argv changed the invocation: %#v", graph.Operations)
	}
	args, ok := graph.Operations[0].FirstBinding(behavior.ResourceRoleArguments)
	if !ok || !strings.Contains(args.Resource.Value, `''`) {
		t.Fatalf("empty argv was not retained: %#v", args)
	}
	graph = javaScriptASTExtract(`const endpoint="https://example.invalid/test";fetch(endpoint);`)
	if len(graph.Network) != 1 || len(graph.Operations) != 1 || len(graph.Operations[0].EvidenceIDs) < 3 {
		t.Fatalf("fetch value lost its proofs: %#v", graph)
	}
}

func TestJavaScriptASTValueRequotingPreservesShellBoundaries(t *testing.T) {
	for _, source := range []string{
		`const cp=require("child_process");const data="curl https://example.invalid/decoy";cp.spawnSync("/usr/bin/printf",["%s",data]);`,
		`const cp=require("child_process");const data="'curl https://example.invalid/decoy'";const command="printf %s "+data;cp.execSync(command);`,
	} {
		graph := javaScriptASTExtract(source)
		if len(graph.Operations) == 0 || len(graph.Network) != 0 {
			t.Fatalf("quoted argument data became communication: %#v", graph.Operations)
		}
	}
	graph := javaScriptASTExtract(`const cp=require("child_process");const command="curl 'https://example.invalid/test?a=1&b=2'";cp.execSync(command);`)
	assertShellCommandNetwork(t, graph, "https://example.invalid/test?a=1&b=2")
}

func TestJavaScriptASTStringsDoNotReplaceUnpairedSurrogates(t *testing.T) {
	for _, literal := range []string{`"/tmp/\ud800"`, `"/tmp/\udc00"`, "`/tmp/\\ud800`", `"/tmp/"+"\ud83d"+"\ude00"`} {
		graph := javaScriptASTExtract(`const fs=require("fs");const path=` + literal + `;fs.readFileSync(path);`)
		if len(graph.Operations) != 1 || graph.Operations[0].ResourceBindings[0].Resource.Value != "" || !hasPartialCoverageScope(graph.Coverage, "javascript-ast-string-encoding") {
			t.Fatalf("unrepresentable string acquired a guessed value: %s\n%#v", literal, graph.Operations)
		}
	}
	for _, tt := range []struct{ literal, value string }{
		{`"/tmp/\ud83d\ude00"`, "/tmp/😀"},
		{`"/tmp/�"`, "/tmp/�"},
	} {
		graph := javaScriptASTExtract(`const fs=require("fs");const path=` + tt.literal + `;fs.readFileSync(path);`)
		if len(graph.Operations) != 1 || graph.Operations[0].ResourceBindings[0].Resource.Value != tt.value {
			t.Fatalf("well-formed Unicode was lost: %#v", graph.Operations)
		}
	}
}

func TestJavaScriptURLArgumentsAreCompleteValues(t *testing.T) {
	for _, value := range []string{"prefix https://example.invalid/decoy", "https://example.invalid/%zz", "data:text/plain,https://example.invalid/decoy"} {
		source := fmt.Sprintf(`const endpoint=%q;fetch(endpoint);`, value)
		for _, graph := range []behavior.Graph{javaScriptASTExtract(source), javaScriptAPIExtract(source)} {
			if len(graph.Operations) != 1 || graph.Operations[0].Qualifiers["api"] != "fetch" || graph.Operations[0].Qualifiers["resource_binding"] != "unresolved" {
				t.Fatalf("the API request was lost or duplicated: %q\n%#v", value, graph.Operations)
			}
			for _, binding := range graph.Operations[0].ResourceBindings {
				if binding.Resource.Value != "" {
					t.Fatalf("a URL substring became a selected destination: %q\n%#v", value, binding)
				}
			}
		}
	}
	for _, value := range []string{"https://example.invalid/inert.", "https://example.invalid/test?a=1&b=2"} {
		source := fmt.Sprintf(`const endpoint=%q;fetch(endpoint);`, value)
		for _, graph := range []behavior.Graph{javaScriptASTExtract(source), javaScriptAPIExtract(source)} {
			if len(graph.Operations) != 1 {
				t.Fatalf("complete URL was lost: %q", value)
			}
			binding, ok := graph.Operations[0].FirstBinding(behavior.ResourceRoleRemoteDestination)
			if !ok || binding.Resource.Value != value {
				t.Fatalf("complete URL was truncated or rewritten: %#v", binding)
			}
		}
	}
}

func TestJavaScriptUnknownFetchDestinationRetainsOnlyTheRequest(t *testing.T) {
	for _, source := range []string{
		`fetch(endpoint);`,
		`const endpoint=unknown;fetch(endpoint);`,
		`const endpoint="https://example.invalid/"+unknown;fetch(endpoint);`,
		"let endpoint=\"https://example.invalid/stale\";\nendpoint=unknown;\nfetch(endpoint);",
		"const endpoint=\"https://example.invalid/captured\";\nfunction request(){fetch(endpoint);}",
	} {
		for _, graph := range []behavior.Graph{javaScriptASTExtract(source), javaScriptAPIExtract(source)} {
			if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationNetworkConnect || graph.Operations[0].Qualifiers["resource_binding"] != "unresolved" {
				t.Fatalf("unknown request acquired stronger semantics: %s\n%#v", source, graph.Operations)
			}
			for _, binding := range graph.Operations[0].ResourceBindings {
				if binding.Resource.Value != "" {
					t.Fatal("unknown destination became concrete")
				}
			}
		}
	}
	graph := javaScriptAPIExtract(`const client=require("axios");client.get("prefix https://example.invalid/decoy");`)
	if len(graph.Operations) != 1 || graph.Operations[0].ResourceBindings[0].Resource.Value != "" {
		t.Fatalf("module API selected a URL substring: %#v", graph.Operations)
	}
	for _, source := range []string{`fetch();`, `fetch(...args);`, `fetch(endpoint,options,...extra);`, `fetch(endpoint,options,extra);`} {
		for _, graph := range []behavior.Graph{javaScriptASTExtract(source), javaScriptAPIExtract(source)} {
			if len(graph.Operations) != 0 {
				t.Fatalf("unsupported argument shape acquired request semantics: %s\n%#v", source, graph.Operations)
			}
		}
	}
}

func TestJavaScriptHTTPValueResolutionDoesNotInventEscapedPaths(t *testing.T) {
	for _, declaration := range []string{"", `const endpoint="https://example.invalid/\u0070";`} {
		call := `fetch("https://example.invalid/\u0070");`
		if declaration != "" {
			call = `fetch(endpoint);`
		}
		graph := javaScriptAPIExtract(declaration + call)
		if len(graph.Operations) != 1 || graph.Operations[0].ResourceBindings[0].Resource.Value != "" {
			t.Fatalf("unsupported Unicode escape became literal path bytes: %#v", graph.Operations)
		}
		graph = javaScriptASTExtract(declaration + call)
		if len(graph.Operations) != 1 || graph.Operations[0].ResourceBindings[0].Resource.Value != "https://example.invalid/p" {
			t.Fatalf("AST parser's exact decoded operand was lost: %#v", graph.Operations)
		}
	}
}

func TestJavaScriptMultipleFetchesDoNotSkipLaterWrites(t *testing.T) {
	graph := javaScriptAPIExtract("let endpoint=\"https://example.invalid/stale\";\nfetch(endpoint);fetch(endpoint);endpoint=unknown;\nfetch(endpoint);")
	for _, operation := range graph.Operations {
		if operation.Line == 3 {
			for _, binding := range operation.ResourceBindings {
				if binding.Resource.Value != "" {
					t.Fatalf("multi-call line skipped an invalidating write: %#v", operation)
				}
			}
		}
	}
}

func TestJavaScriptASTValueBudgetsRetainUnknownOperations(t *testing.T) {
	var source strings.Builder
	source.WriteString(`const fs=require("fs");`)
	for i := 0; i <= maxJavaScriptCommandScalars; i++ {
		fmt.Fprintf(&source, `const p%d="/tmp/inert-%d";fs.readFileSync(p%d);`, i, i, i)
	}
	graph := javaScriptASTExtract(source.String())
	if len(graph.Operations) != maxJavaScriptCommandScalars+1 || graph.Operations[len(graph.Operations)-1].ResourceBindings[0].Resource.Value != "" || !hasPartialCoverageScope(graph.Coverage, "javascript-ast-value-analysis") {
		t.Fatalf("scalar budget was not explicit: operations=%d coverage=%#v", len(graph.Operations), graph.Coverage)
	}
	graph = javaScriptASTExtract(`const fs=require("fs");const path="` + strings.Repeat("a", maxJavaScriptCommandValueBytes+1) + `";fs.readFileSync(path);`)
	if len(graph.Operations) != 1 || graph.Operations[0].ResourceBindings[0].Resource.Value != "" || !hasPartialCoverageScope(graph.Coverage, "javascript-ast-value-analysis") {
		t.Fatal("oversized scalar became a resource")
	}
}

func TestJavaScriptASTValueDepthByteAndProofBudgets(t *testing.T) {
	var deep, total strings.Builder
	deep.WriteString(`const fs=require("fs");const p0="/tmp/inert";`)
	for i := 1; i <= maxJavaScriptCommandExpressionDepth+1; i++ {
		fmt.Fprintf(&deep, `const p%d=p%d;`, i, i-1)
	}
	fmt.Fprintf(&deep, `fs.readFileSync(p%d);`, maxJavaScriptCommandExpressionDepth+1)
	total.WriteString(`const fs=require("fs");`)
	for i := 0; i < 18; i++ {
		fmt.Fprintf(&total, `const p%d="%s";fs.readFileSync(p%d);`, i, strings.Repeat("a", maxJavaScriptCommandValueBytes), i)
	}
	balanced := `"a"`
	for i := 0; i < 4; i++ {
		balanced = "(" + balanced + "+" + balanced + ")"
	}
	for _, source := range []string{deep.String(), total.String(), `const fs=require("fs");const path=` + balanced + `;fs.readFileSync(path);`} {
		graph := javaScriptASTExtract(source)
		if len(graph.Operations) == 0 || graph.Operations[len(graph.Operations)-1].ResourceBindings[0].Resource.Value != "" || !hasPartialCoverageScope(graph.Coverage, "javascript-ast-value-analysis") {
			t.Fatalf("value budget lost the neutral operation or retained a value: operations=%d coverage=%#v", len(graph.Operations), graph.Coverage)
		}
	}
}

func TestJavaScriptASTValueEvidenceFailureDoesNotExpandCommands(t *testing.T) {
	graph := behavior.Graph{EvidenceLimit: 4}
	extractJavaScriptASTSource(&graph, artifact.Content{NodeID: "node-js", LogicalPath: "fixture.js"}, `const cp=require("child_process");const command="curl https://example.invalid/test";cp.execSync(command);`)
	if len(graph.Network) != 0 || len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute || graph.Operations[0].ResourceBindings[0].Resource.Value != "" {
		t.Fatalf("unretained value evidence drove command expansion: %#v", graph.Operations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "javascript-ast-value-analysis") {
		t.Fatal("evidence retention failure was not explicit")
	}
}

func FuzzJavaScriptASTSourceValues(f *testing.F) {
	for _, seed := range []string{
		`const fs=require("fs");const path="/tmp/inert";fs.readFileSync(path);`,
		`const cp=require("child_process");const a="uname",b=a+" -a";cp.execSync(b);`,
		"const endpoint=\"https://example.invalid/test\";fetch(`${endpoint}`);",
		`const fs=require("fs");function f(){const p="/tmp/inert";if(condition){fs.readFileSync(p);}}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 16<<10 {
			return
		}
		graph := behavior.Graph{EvidenceLimit: 512, ItemLimit: 512, StringByteLimit: 1 << 20}
		extractJavaScriptASTSource(&graph, artifact.Content{NodeID: "node-js", LogicalPath: "fixture.js"}, source)
		if len(graph.Operations) > 512 || len(graph.Evidence) > 512 {
			t.Fatal("value extraction exceeded graph bounds")
		}
	})
}
