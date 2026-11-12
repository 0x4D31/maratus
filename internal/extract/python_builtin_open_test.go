package extract

import (
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestPythonBuiltinOpenReadSupportedOptions(t *testing.T) {
	for name, call := range map[string]string{
		"defaults":          `open("/tmp/input").read()`,
		"keywords":          `open(file="/tmp/input", mode="rt", encoding="utf-8", errors="strict", newline="\n", closefd=True, opener=None).read(1_024)`,
		"ascii":             `open("/tmp/input", encoding="ASCII", errors="replace").read(-2)`,
		"raw binary":        `open("/tmp/input", "rb", 0).read(-1)`,
		"default buffering": `open("/tmp/input", buffering=-2).read()`,
		"binary defaults":   `open("/tmp/input", "rb", encoding=None, errors=None, newline=None).read()`,
		"all positional":    `open("/tmp/input", "r+b", -1, None, None, None, True, None).read(None)`,
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract("def inspect_data():\n    return " + call + "\n")
			operation, ok := pythonAPIOperation(graph, behavior.OperationFileRead, behavior.ResourceRoleSource, "/tmp/input")
			if !ok || operation.Support != behavior.SupportCorroborated || operation.SourceFunction != "inspect_data" || len(operation.EvidenceIDs) != 1 {
				t.Fatalf("supported builtin read lost exact context: operation=%#v graph=%#v", operation, graph)
			}
			if operation.Execution.Connectivity == behavior.ConnectivityConnected {
				t.Fatalf("uncalled function was treated as connected: %#v", operation)
			}
		})
	}
	for _, mode := range []string{"r", "rt", "rb", "r+", "r+t", "rt+", "r+b", "rb+"} {
		t.Run("mode "+mode, func(t *testing.T) {
			graph := pythonAPIExtract(`open("/tmp/input", "` + mode + `").read()` + "\n")
			if _, ok := pythonAPIOperation(graph, behavior.OperationFileRead, behavior.ResourceRoleSource, "/tmp/input"); !ok {
				t.Fatalf("readable mode %q was not retained: %#v", mode, graph.Operations)
			}
		})
	}
}

func TestPythonBuiltinOpenReadRejectsUnprovenOrImpossibleConsumers(t *testing.T) {
	for name, call := range map[string]string{
		"write only":         `open("/tmp/input", "w").read()`,
		"append only":        `open("/tmp/input", "ab").read()`,
		"create only":        `open("/tmp/input", "x").read()`,
		"truncated update":   `open("/tmp/input", "w+").read()`,
		"created update":     `open("/tmp/input", "x+b").read()`,
		"append update":      `open("/tmp/input", "a+").read()`,
		"unknown mode":       `open("/tmp/input", mode).read()`,
		"empty mode":         `open("/tmp/input", "").read()`,
		"duplicate mode":     `open("/tmp/input", "rr").read()`,
		"two primary modes":  `open("/tmp/input", "rw+").read()`,
		"two data modes":     `open("/tmp/input", "rbt").read()`,
		"no primary mode":    `open("/tmp/input", "b+").read()`,
		"duplicate update":   `open("/tmp/input", "r++").read()`,
		"custom opener":      `open("/tmp/input", opener=redirect).read()`,
		"positional opener":  `open("/tmp/input", "r", -1, None, None, None, True, redirect).read()`,
		"filename closefd":   `open("/tmp/input", closefd=False).read()`,
		"dynamic closefd":    `open("/tmp/input", closefd=closefd).read()`,
		"unknown encoding":   `open("/tmp/input", encoding="custom-codec").read()`,
		"dynamic encoding":   `open("/tmp/input", encoding=encoding).read()`,
		"binary encoding":    `open("/tmp/input", "rb", encoding="utf-8").read()`,
		"binary errors":      `open("/tmp/input", "rb", errors="strict").read()`,
		"binary newline":     `open("/tmp/input", "rb", newline="").read()`,
		"invalid newline":    `open("/tmp/input", newline="other").read()`,
		"custom errors":      `open("/tmp/input", errors="custom-handler").read()`,
		"unbuffered text":    `open("/tmp/input", buffering=0).read()`,
		"dynamic buffering":  `open("/tmp/input", buffering=amount).read()`,
		"unknown keyword":    `open("/tmp/input", unexpected=True).read()`,
		"duplicate mode arg": `open("/tmp/input", "rb", mode="rb").read()`,
		"no bytes requested": `open("/tmp/input").read(0)`,
		"dynamic size":       `open("/tmp/input").read(size)`,
		"string size":        `open("/tmp/input").read("32")`,
		"two read arguments": `open("/tmp/input").read(1, 2)`,
		"read keyword":       `open("/tmp/input").read(size=32)`,
		"read expansion":     `open("/tmp/input").read(*sizes)`,
		"read call":          `open("/tmp/input").read(get_size())`,
		"oversized integer":  `open("/tmp/input").read(9223372036854775808)`,
		"non Python literal": "open(`/tmp/input`).read()",
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract(call + "\n")
			if _, ok := pythonAPIOperation(graph, behavior.OperationFileRead, behavior.ResourceRoleSource, "/tmp/input"); ok {
				t.Fatalf("unsupported consumer acquired an exact read: %#v", graph.Operations)
			}
			if name != "non Python literal" && !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
				t.Fatalf("unresolved builtin consumer lacks explicit coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestPythonBuiltinOpenReadBudgetIsExplicit(t *testing.T) {
	for name, source := range map[string]string{
		"open call": `open("/tmp/` + strings.Repeat("a", maxPythonAPICallBytes) + `").read()`,
		"read call": `open("/tmp/input").read(` + strings.Repeat("1", maxPythonAPICallBytes) + `)`,
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract(source + "\n")
			if len(graph.Operations) != 0 || !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
				t.Fatalf("oversized builtin consumer was not bounded: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
			}
		})
	}
}
