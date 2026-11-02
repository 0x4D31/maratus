package extract

import (
	"fmt"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const jxaInertReceiver = `const app=Application.currentApplication();app.includeStandardAdditions=true;`

func extractJXAForTest(source string) behavior.Graph {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{NodeID: "node-jxa", LogicalPath: "fixture.jxa", Kind: "script", Data: []byte(source)})
	return graph
}

func TestJXAStringValuesUseSharedCommandSemantics(t *testing.T) {
	for _, source := range []string{
		`const command="curl https://example.invalid/test";app.doShellScript(command);`,
		`const base="curl ";const command=base+"https://example.invalid/test";app.doShellScript(command);`,
		"const destination=\"https://example.invalid/test\";app.doShellScript(`curl ${destination}`);",
		`const result=app.doShellScript("curl https://example.invalid/test");`,
		`const result=app.doShellScript("curl https://example.invalid/test").trim();`,
	} {
		graph := extractJXAForTest(jxaInertReceiver + source)
		assertShellCommandNetwork(t, graph, "https://example.invalid/test")
		for _, operation := range graph.Operations {
			if len(operation.EvidenceIDs) < 3 {
				t.Fatalf("receiver/setup/call evidence lost: %#v", operation)
			}
		}
	}
	graph := extractJXAForTest(jxaInertReceiver + `const command="printf '%s' 'curl https://example.invalid/data'";app.doShellScript(command);`)
	if len(graph.Network) != 0 {
		t.Fatal("quoted output text became communication")
	}
}

func TestJXAScopedCallsDoNotInventReachability(t *testing.T) {
	for _, source := range []string{
		`function collect(){const command="curl https://example.invalid/test";return app.doShellScript(command);}`,
		`function collect(){const result=app.doShellScript("curl https://example.invalid/test").trim();}`,
		`if(condition){app.doShellScript("curl https://example.invalid/test");}`,
		`false && app.doShellScript("curl https://example.invalid/test");`,
	} {
		graph := extractJXAForTest(jxaInertReceiver + source)
		assertShellCommandNetwork(t, graph, "https://example.invalid/test")
		for _, operation := range graph.Operations {
			if operation.Execution.Connectivity != behavior.ConnectivityUnknown {
				t.Fatalf("nested call acquired entry connectivity: %#v", operation)
			}
			if strings.Contains(source, "function collect") && operation.SourceFunction != "collect" {
				t.Fatalf("function lineage lost: %#v", operation)
			}
		}
	}
}

func TestJXAUnresolvedOperandsDoNotSynthesizeCommands(t *testing.T) {
	for _, source := range []string{
		`const command="curl "+unknown;app.doShellScript(command);`,
		`const command=makeCommand();app.doShellScript(command);`,
		`let command="curl https://example.invalid/stale";command=unknown;app.doShellScript(command);`,
		`app.doShellScript(command);const command="curl https://example.invalid/late";`,
		`const command="curl https://example.invalid/captured";function collect(){app.doShellScript(command);}`,
		`var command="curl https://example.invalid/global";app.doShellScript(command);`,
		`function collect(){const command="curl https://example.invalid/context";if(condition){app.doShellScript(command);}}`,
		`app.doShellScript("curl https://example.invalid/nul\u0000ignored");`,
		`app.doShellScript("curl https://example.invalid/\ud800");`,
	} {
		graph := extractJXAForTest(jxaInertReceiver + source)
		if len(graph.Network) != 0 || len(graph.Operations) != 1 {
			t.Fatalf("unresolved operand became behavior or lost its request: %s\n%#v", source, graph.Operations)
		}
		argument, ok := graph.Operations[0].FirstBinding(behavior.ResourceRoleArguments)
		if !ok || argument.Resource.Value != "" {
			t.Fatalf("unknown command became concrete: %s\n%#v", source, argument)
		}
	}
}

func TestJXAValuesDoNotWeakenReceiverIdentity(t *testing.T) {
	for _, source := range []string{
		`const app={};app.includeStandardAdditions=true;`,
		`const Application=other;` + jxaInertReceiver,
		jxaInertReceiver + `const alias=app;`,
		jxaInertReceiver + `function mutate(){app.includeStandardAdditions=false;}`,
		jxaInertReceiver + `function mutate(){app.doShellScript=other;}`,
		jxaInertReceiver + `function collect(app){return app.doShellScript("curl https://example.invalid/shadowed");}`,
		jxaInertReceiver + `eval(source);`,
	} {
		graph := extractJXAForTest(source + `const command="curl https://example.invalid/test";app.doShellScript(command);`)
		if strings.Contains(source, "function collect(app)") {
			if len(graph.Network) != 1 {
				t.Fatalf("shadowed receiver affected the distinct root call: %#v", graph.Operations)
			}
			for _, operation := range graph.Operations {
				if operation.SourceFunction != "" {
					t.Fatalf("shadowed receiver became the runtime object: %#v", operation)
				}
			}
		} else if len(graph.Operations) != 0 {
			t.Fatalf("unproved receiver identity acquired behavior: %s\n%#v", source, graph.Operations)
		}
	}
	graph := extractJXAForTest(`const fs=require("fs");fs.readFileSync("/tmp/inert");fetch("https://example.invalid/test");`)
	if len(graph.Operations) != 0 {
		t.Fatal("Node or fetch semantics were applied to JXA")
	}
}

func TestJXAStringValueBudgetsRemainExplicit(t *testing.T) {
	var many strings.Builder
	many.WriteString(jxaInertReceiver)
	for i := 0; i <= maxJavaScriptCommandScalars; i++ {
		fmt.Fprintf(&many, `const command%d="printf inert";app.doShellScript(command%d);`, i, i)
	}
	for _, source := range []string{many.String(), jxaInertReceiver + `app.doShellScript("` + strings.Repeat("a", maxOSAExpressionBytes+1) + `");`} {
		graph := extractJXAForTest(source)
		if len(graph.Operations) == 0 || !hasPartialCoverageScope(graph.Coverage, "javascript-ast-value-analysis") {
			t.Fatalf("value budget was silent: operations=%d coverage=%#v", len(graph.Operations), graph.Coverage)
		}
		argument, ok := graph.Operations[len(graph.Operations)-1].FirstBinding(behavior.ResourceRoleArguments)
		if !ok || argument.Resource.Value != "" {
			t.Fatal("an exhausted value became a complete command")
		}
	}
}

func TestJXAValueEvidenceFailureDoesNotExpandCommands(t *testing.T) {
	graph := behavior.Graph{EvidenceLimit: 2}
	extractJXAShellCalls(&graph, artifact.Content{NodeID: "node-jxa", LogicalPath: "fixture.jxa"}, jxaInertReceiver+`const command="curl https://example.invalid/test";app.doShellScript(command);`)
	if len(graph.Network) != 0 || !hasPartialCoverageScope(graph.Coverage, "javascript-ast-value-analysis") {
		t.Fatalf("incomplete evidence drove command semantics or failed silently: %#v", graph)
	}
}

func TestJXAForeignFunctionReceiverProofStaysPartial(t *testing.T) {
	var graph behavior.Graph
	scope := graph.AddScope(behavior.Scope{NodeID: "node-jxa", Kind: "function", Function: "outer", LineStart: 1, LineEnd: 1})
	source := jxaInertReceiver + `app.doShellScript("printf inert");function collect(){app.doShellScript("curl https://example.invalid/test");}`
	extractJXAShellCalls(&graph, artifact.Content{NodeID: "node-jxa", LogicalPath: "fixture.jxa", ScopeID: scope, Function: "outer"}, source)
	if len(graph.Network) != 0 || len(graph.Operations) != 1 || graph.Operations[0].SourceFunction != "outer" || !hasPartialCoverageScope(graph.Coverage, "jxa-standard-additions-context") {
		t.Fatalf("foreign receiver setup was reused or silently dropped: %#v", graph)
	}
}

func FuzzJXAStandardAdditionsValues(f *testing.F) {
	for _, source := range []string{
		jxaInertReceiver + `const command="printf inert";app.doShellScript(command);`,
		jxaInertReceiver + `function collect(){return app.doShellScript("printf inert").trim();}`,
		jxaInertReceiver + `if(condition){app.doShellScript("printf inert");}`,
		jxaInertReceiver + `app.doShellScript(...args);`,
	} {
		f.Add(source)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > maxOSAExpressionBytes {
			return
		}
		graph := behavior.Graph{EvidenceLimit: 512, ItemLimit: 512, StringByteLimit: 1 << 20}
		ExtractText(&graph, artifact.Content{NodeID: "node-jxa", LogicalPath: "fixture.jxa", Kind: "script", Data: []byte(source)})
		if len(graph.Operations) > 512 || len(graph.Scopes) > 512 {
			t.Fatal("JXA analysis exceeded graph bounds")
		}
	})
}
