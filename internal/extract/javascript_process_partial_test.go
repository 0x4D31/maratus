package extract

import (
	"fmt"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func assertUnresolvedJavaScriptProcess(t *testing.T, graph behavior.Graph, executable string) {
	t.Helper()
	if len(graph.Operations) != 1 || len(graph.Relations) != 0 {
		t.Fatalf("want one process primitive without downstream flow: %#v", graph)
	}
	op := graph.Operations[0]
	if op.Kind != behavior.OperationProcessExecute || op.Support != behavior.SupportCorroborated ||
		op.RequiredResource().Value != executable || len(op.ResourceBindings) != 1 ||
		op.Qualifiers["unresolved_arguments"] == "" || len(op.EvidenceIDs) < 3 {
		t.Fatalf("unresolved process lost precision boundaries or binding proof: %#v", op)
	}
}

func TestJavaScriptDynamicProcessRetainsExactAPI(t *testing.T) {
	for _, method := range []string{"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"} {
		t.Run(method, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, javascriptCommandTestContent(fmt.Sprintf("const cp = require('node:child_process');\ncp.%s(command);", method)))
			assertUnresolvedJavaScriptProcess(t, graph, "")
			if graph.Operations[0].Qualifiers["api"] != "child_process."+method {
				t.Fatalf("lost exact API identity: %#v", graph.Operations[0])
			}
		})
	}
}

func TestJavaScriptPartialArgvRejectsUnsupportedSyntax(t *testing.T) {
	for _, argv := range []string{`["literal", ...args]`, `["bad\uZZZZ", value]`, `[nested()]`, `[value`, `[value,,other]`, `[return]`, `[null]`} {
		if javaScriptPartialArgv(argv) {
			t.Fatalf("unsupported argv admitted: %s", argv)
		}
	}
	if !javaScriptPartialArgv(`["literal", value]`) {
		t.Fatal("closed literal/identifier array rejected")
	}
}
