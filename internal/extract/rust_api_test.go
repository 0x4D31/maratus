package extract

import (
	"fmt"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestRustSourceAPIsEmitNeutralOperationsWithExactScopes(t *testing.T) {
	source := `use std::process::{self, Command, Stdio};

fn agent() -> ureq::Agent {
    todo!()
}

fn main() {
    std::fs::write("/tmp/output", b"data").unwrap();
    Command::new("/bin/echo")
        .arg("hello")
        .status()
        .unwrap();
    let response = agent()
        .get("https://example.invalid/payload")
        .call()
        .unwrap();
}
`
	graph := extractRustFixture(t, source)
	if len(graph.Operations) != 3 {
		t.Fatalf("Rust operations = %#v, want file write, process execute, and network download", graph.Operations)
	}
	assertRustOperation(t, graph, behavior.OperationFileWrite, behavior.ResourceFile, "/tmp/output", "main")
	assertRustOperation(t, graph, behavior.OperationProcessExecute, behavior.ResourceFile, "/bin/echo", "main")
	assertRustOperation(t, graph, behavior.OperationNetworkDownload, behavior.ResourceURL, "https://example.invalid/payload", "main")
	for _, operation := range graph.Operations {
		if operation.Support != behavior.SupportHeuristic || operation.Execution.Connectivity != behavior.ConnectivityUnknown || operation.ScopeID == "" || operation.SourceFunction != "main" {
			t.Fatalf("Rust source operation overclaimed support/connectivity/scope: %#v", operation)
		}
	}
	if len(graph.Network) != 1 || graph.Network[0].Support != behavior.SupportHeuristic || len(graph.Network[0].OperationIDs) != 1 {
		t.Fatalf("Rust network implementation = %#v", graph.Network)
	}
	if err := graph.Sort(); err != nil {
		t.Fatal(err)
	}
}

func TestRustUnaryFilesystemAPITableUsesSharedTypedVocabulary(t *testing.T) {
	for _, spec := range rustUnaryAPISpecs {
		t.Run(spec.api, func(t *testing.T) {
			extra := ""
			switch spec.api {
			case "std::fs::write":
				extra = `, b"inert"`
			case "std::fs::set_permissions":
				extra = ", permissions"
			}
			source := "fn main() {\n    " + spec.api + "(\"/tmp/maratus-inert\"" + extra + ");\n}\n"
			graph := extractRustFixture(t, source)
			if len(graph.Operations) != 1 {
				t.Fatalf("operations = %#v", graph.Operations)
			}
			operation := graph.Operations[0]
			if operation.Kind != spec.kind || operation.RequiredResource().Kind != behavior.ResourceFile || operation.RequiredResource().Value != "/tmp/maratus-inert" || operation.Support != behavior.SupportHeuristic || operation.Qualifiers["api"] != spec.api {
				t.Fatalf("operation = %#v; spec = %#v", operation, spec)
			}
		})
	}
}

func TestRustBinaryFilesystemAPITableRetainsExactSourceAndDestination(t *testing.T) {
	for _, spec := range rustBinaryAPISpecs {
		t.Run(spec.api, func(t *testing.T) {
			source := `const SOURCE: &str = "/tmp/maratus-source";
const TARGET: &str = "/tmp/maratus-target";
fn main() {
    ` + spec.api + `(SOURCE, TARGET).unwrap();
}
`
			graph := extractRustFixture(t, source)
			if len(graph.Operations) != 1 {
				t.Fatalf("operations = %#v", graph.Operations)
			}
			operation := graph.Operations[0]
			if operation.Kind != spec.kind || operation.Support != behavior.SupportHeuristic || operation.Qualifiers["api"] != spec.api || len(operation.EvidenceIDs) != 3 || len(operation.ResourceBindings) != 2 {
				t.Fatalf("operation = %#v; spec = %#v", operation, spec)
			}
			want := map[behavior.ResourceRole]string{
				spec.firstRole:  "/tmp/maratus-source",
				spec.secondRole: "/tmp/maratus-target",
			}
			for _, binding := range operation.ResourceBindings {
				if binding.Resource.Kind != behavior.ResourceFile || want[binding.Role] != binding.Resource.Value || len(binding.EvidenceIDs) != 1 {
					t.Fatalf("binding = %#v; want = %#v", binding, want)
				}
				delete(want, binding.Role)
			}
			if len(want) != 0 {
				t.Fatalf("missing bindings = %#v; operation = %#v", want, operation)
			}
		})
	}
}

func TestRustFilesystemAPIsRejectWrongArityAndNestedStdPath(t *testing.T) {
	graph := extractRustFixture(t, `fn main() {
    std::fs::read();
    std::fs::read("/tmp/a", "/tmp/b");
    std::fs::write("/tmp/a");
    std::fs::copy("/tmp/a");
    std::fs::rename("/tmp/a", "/tmp/b", "/tmp/c");
    facade::std::fs::remove_file("/tmp/a");
}
`)
	if len(graph.Operations) != 0 {
		t.Fatalf("invalid Rust API shapes became operations: %#v", graph.Operations)
	}
}

func TestRustSourceAPIsLeaveDynamicResourcesUnresolved(t *testing.T) {
	graph := extractRustFixture(t, `use std::process::Command;
fn main() {
    let path = choose_at_runtime();
    std::fs::write(&path, b"x").unwrap();
    Command::new(&path).spawn().unwrap();
}
`)
	if len(graph.Operations) != 2 {
		t.Fatalf("dynamic Rust operations = %#v", graph.Operations)
	}
	for _, operation := range graph.Operations {
		if operation.RequiredResource().Value != "" {
			t.Fatalf("dynamic Rust argument gained a concrete resource: %#v", operation)
		}
	}
}

func TestRustSourceAPIsResolveUniqueImmutableStringBindings(t *testing.T) {
	graph := extractRustFixture(t, `use std::process::Command;
const TOOL: &str = "/bin/echo";
fn main() {
    let endpoint: &str = "https://example.invalid/bound";
    Command::new(TOOL).status().unwrap();
    ureq::get(&endpoint).call().unwrap();
}
`)
	assertRustOperation(t, graph, behavior.OperationProcessExecute, behavior.ResourceFile, "/bin/echo", "main")
	assertRustOperation(t, graph, behavior.OperationNetworkDownload, behavior.ResourceURL, "https://example.invalid/bound", "main")
	for _, operation := range graph.Operations {
		if operation.Support != behavior.SupportHeuristic || len(operation.EvidenceIDs) != 2 || len(operation.ResourceBindings) != 1 || len(operation.ResourceBindings[0].EvidenceIDs) != 1 {
			t.Fatalf("resolved binding lost proof tier or lineage: %#v", operation)
		}
	}
}

func TestRustResolvedCommandUsesSharedVocabularyWithoutStrongerProof(t *testing.T) {
	graph := extractRustFixture(t, `use std::process::Command;
const TOOL: &str = "whoami";
fn main() {
    Command::new(TOOL).status().unwrap();
}
`)
	assertRustOperation(t, graph, behavior.OperationProcessExecute, behavior.ResourceFile, "whoami", "main")
	assertRustOperation(t, graph, behavior.OperationUserInfoQuery, behavior.ResourceUserAccount, "local users", "main")
	for _, operation := range graph.Operations {
		if operation.Support != behavior.SupportHeuristic {
			t.Fatalf("Rust shared command semantics gained stronger support: %#v", operation)
		}
	}
}

func TestRustCommandRetainsExactFluentArgvAndSharedSemantics(t *testing.T) {
	graph := extractRustFixture(t, `use std::process::Command;
const DATA_TYPE: &str = "SPHardwareDataType";
fn main() {
    Command::new("system_profiler")
        .arg("-detailLevel")
        .args(["mini", DATA_TYPE])
        .output()
        .unwrap();
}
`)
	var process, discovery *behavior.ModeledOperation
	for index := range graph.Operations {
		operation := &graph.Operations[index]
		switch operation.Kind {
		case behavior.OperationProcessExecute:
			process = operation
		case behavior.OperationSystemInfoQuery:
			discovery = operation
		}
	}
	if process == nil || process.Support != behavior.SupportHeuristic || process.Qualifiers["argument_coverage"] != "exact-static-argv" || process.Qualifiers["argument_encoding"] != "json-array" {
		t.Fatalf("process operation = %#v", process)
	}
	arguments, ok := rustResourceForRole(*process, behavior.ResourceRoleArguments)
	if !ok || arguments.Kind != behavior.ResourceCommand || arguments.Value != `["-detailLevel","mini","SPHardwareDataType"]` || len(arguments.Classifications) != 0 {
		t.Fatalf("argument resource = %#v, present=%v", arguments, ok)
	}
	if discovery == nil || discovery.Support != behavior.SupportHeuristic || discovery.RequiredResource().Kind != behavior.ResourceSystem {
		t.Fatalf("shared system discovery = %#v; all operations = %#v", discovery, graph.Operations)
	}
}

func TestRustCommandDynamicArgvStaysExplicitlyUnresolved(t *testing.T) {
	graph := extractRustFixture(t, `use std::process::Command;
fn main() {
    Command::new("system_profiler").arg(runtime_value()).output().unwrap();
}
`)
	if len(graph.Operations) != 1 {
		t.Fatalf("operations = %#v", graph.Operations)
	}
	operation := graph.Operations[0]
	if operation.Kind != behavior.OperationProcessExecute || operation.Qualifiers["argument_coverage"] != "executable-only" || operation.Qualifiers["unresolved_arguments"] != "dynamic or unsupported argv" {
		t.Fatalf("dynamic argv operation = %#v", operation)
	}
	if _, ok := rustResourceForRole(operation, behavior.ResourceRoleArguments); ok {
		t.Fatalf("dynamic argv gained a concrete arguments binding: %#v", operation.ResourceBindings)
	}
}

func TestRustSourceAPIsRejectMutableOrAmbiguousBindings(t *testing.T) {
	graph := extractRustFixture(t, `use std::process::Command;
fn main() {
    let mut tool = "/bin/echo";
    tool = "/bin/sh";
    Command::new(tool).status().unwrap();
}
`)
	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Value != "" || len(graph.Operations[0].EvidenceIDs) != 1 {
		t.Fatalf("mutable binding became concrete: %#v", graph.Operations)
	}
}

func TestRustSourceAPICloseNegativesFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{name: "constructor only", source: `use std::process::Command;
fn main() {
    let command = Command::new("/bin/echo");
}
`},
		{name: "terminal on unrelated object", source: `use std::process::Command;
fn main() {
    let command = Command::new("/bin/echo");
    other.spawn();
}
`},
		{name: "same statement unrelated terminal", source: `use std::process::Command;
fn main() {
    consume(Command::new("/bin/echo"), other.spawn());
}
`},
		{name: "unproved command type", source: `use attacker::Command;
fn main() {
    Command::new("/bin/echo").spawn();
}
`},
		{name: "wrong command constructor arity", source: `use std::process::Command;
fn main() {
    Command::new("/bin/echo", "extra").status();
}
`},
		{name: "wrong command terminal arity", source: `use std::process::Command;
fn main() {
    Command::new("/bin/echo").status("extra");
}
`},
		{name: "shadowed command type", source: `use std::process::Command;
struct Command;
fn main() {
    Command::new("/bin/echo").spawn();
}
`},
		{name: "shadowed std root", source: `mod std { pub mod fs { pub fn write(_: &str, _: &[u8]) {} } }
fn main() {
    std::fs::write("/tmp/not-system", b"x");
}
`},
		{name: "unproved get call", source: `fn agent() -> attacker::Agent { todo!() }
fn main() {
    agent().get("https://example.invalid/p").call();
}
`},
		{name: "comments and strings", source: `fn main() {
    // std::fs::write("/tmp/comment", b"x");
    let text = "Command::new(\"/bin/echo\").spawn()";
}
`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph := extractRustFixture(t, test.source)
			if len(graph.Operations) != 0 || len(graph.Network) != 0 {
				t.Fatalf("Rust close negative gained semantics: operations=%#v network=%#v", graph.Operations, graph.Network)
			}
		})
	}
}

func TestRustSourceAPIMalformedRawStringAndEventBudgetAreExplicit(t *testing.T) {
	malformed := extractRustFixture(t, "fn main() {\n    let value = r#\"std::fs::write(\\\"/tmp/x\\\", b\\\"x\\\");\n}\n")
	if len(malformed.Operations) != 0 || !rustAPICoverageContains(malformed, "bounded lexical limit") {
		t.Fatalf("unterminated raw string was not failed closed: operations=%#v coverage=%#v", malformed.Operations, malformed.Coverage)
	}

	var source strings.Builder
	source.WriteString("fn main() {\n")
	for index := 0; index < maxRustAPIMatches+1; index++ {
		fmt.Fprintf(&source, "    std::fs::write(\"/tmp/%04d\", b\"x\");\n", index)
	}
	source.WriteString("}\n")
	bounded := extractRustFixture(t, source.String())
	if len(bounded.Operations) != maxRustAPIMatches || !rustAPICoverageContains(bounded, fmt.Sprintf("%d events", maxRustAPIMatches)) {
		t.Fatalf("Rust API event bound = operations %d coverage %#v", len(bounded.Operations), bounded.Coverage)
	}

	arguments := make([]string, maxRustCommandArguments+1)
	for index := range arguments {
		arguments[index] = fmt.Sprintf("%q", fmt.Sprintf("arg-%03d", index))
	}
	argvBounded := extractRustFixture(t, "use std::process::Command;\nfn main() {\n    Command::new(\"/bin/echo\").args(["+strings.Join(arguments, ",")+"]).status();\n}\n")
	if len(argvBounded.Operations) != 1 || argvBounded.Operations[0].Qualifiers["argument_coverage"] != "executable-only" || !rustAPICoverageContains(argvBounded, "bounded lexical limit") {
		t.Fatalf("Rust argv bound = operations %#v coverage %#v", argvBounded.Operations, argvBounded.Coverage)
	}
}

func TestRustSourceAPIDeepBlockCommentFailsClosed(t *testing.T) {
	source := "fn main() {\n" + strings.Repeat("/*", 65) +
		` std::fs::write("/tmp/comment", b"x"); ` + strings.Repeat("*/", 65) +
		"\n}\n"
	graph := extractRustFixture(t, source)
	if len(graph.Operations) != 0 || !rustAPICoverageContains(graph, "bounded lexical limit") {
		t.Fatalf("over-deep Rust block comment exposed its contents: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
	}
}

func TestRustSourceBenignFileWriteRemainsNeutral(t *testing.T) {
	graph := extractRustFixture(t, `fn main() {
    std::fs::write("generated/version.rs", b"pub const VERSION: &str = \"1\";").unwrap();
}
`)
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileWrite || graph.Operations[0].Support != behavior.SupportHeuristic {
		t.Fatalf("benign build generation should be one neutral weak file-write operation: %#v", graph.Operations)
	}
}

func rustResourceForRole(operation behavior.ModeledOperation, role behavior.ResourceRole) (behavior.Resource, bool) {
	for _, binding := range operation.ResourceBindings {
		if binding.Role == role {
			return binding.Resource, true
		}
	}
	return behavior.Resource{}, false
}

func extractRustFixture(t *testing.T, source string) behavior.Graph {
	t.Helper()
	graph := behavior.Graph{}
	scopeID := graph.AddScope(behavior.Scope{NodeID: "node-rust", Kind: "artifact-node", Name: "build.rs", SourceRole: "runtime"})
	ExtractText(&graph, artifact.Content{
		NodeID: "node-rust", ScopeID: scopeID, LogicalPath: "fixture/build.rs",
		Kind: "text", MediaType: "text/plain", Role: "runtime", Data: []byte(source),
		SemanticLanguage: "native-source", BehaviorAnalysisForced: true,
	})
	return graph
}

func assertRustOperation(t *testing.T, graph behavior.Graph, kind behavior.OperationKind, resourceKind behavior.ResourceKind, value, function string) {
	t.Helper()
	for _, operation := range graph.Operations {
		resource := operation.RequiredResource()
		if operation.Kind == kind && resource.Kind == resourceKind && resource.Value == value && operation.SourceFunction == function {
			return
		}
	}
	t.Fatalf("missing Rust operation %s %s %q in %#v", kind, resourceKind, value, graph.Operations)
}

func rustAPICoverageContains(graph behavior.Graph, fragment string) bool {
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "rust-source-api-analysis" && strings.Contains(coverage.Detail, fragment) {
			return true
		}
	}
	return false
}
