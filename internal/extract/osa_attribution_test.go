package extract

import (
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestOSADataDoesNotBecomeBehavior(t *testing.T) {
	for _, source := range []string{
		`set note to "do shell script curl https://example.invalid/only-data"`,
		`set note to "display dialog hidden answer"`,
		`set note to "open location https://example.invalid/only-data"`,
	} {
		var graph behavior.Graph
		ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", MediaType: "text/plain", SemanticLanguage: "applescript", Data: []byte(source)})
		if len(graph.Operations) != 0 || len(graph.Network) != 0 || len(graph.Relations) != 0 {
			t.Fatalf("inert data acquired behavior: %q\n%#v", source, graph.Operations)
		}
	}
}

func TestOSACommandBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, source, command string
	}{
		{"literal", `do shell script "curl https://example.invalid/test"`, "curl https://example.invalid/test"},
		{"concatenation", `do shell script ("curl " & "https://example.invalid/test")`, "curl https://example.invalid/test"},
		{"escaped quotes", `do shell script "printf '%s' \"hello\""`, `printf '%s' "hello"`},
		{"assigned result", `set output to do shell script "printf test"`, "printf test"},
		{"returned result", `return do shell script "printf test"`, "printf test"},
		{"unknown suffix", `do shell script "curl https://example.invalid/test" & unknown`, ""},
		{"unknown prefix", `do shell script prefix & "curl https://example.invalid/test"`, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(test.source)})
			found := false
			for _, operation := range graph.Operations {
				if operation.Kind != behavior.OperationInterpreterInvoke {
					if test.command == "" && isNetworkOperationKind(operation.Kind) {
						t.Fatal("unresolved expression became communication")
					}
					continue
				}
				arguments, ok := testOperationBinding(operation, behavior.ResourceRoleArguments)
				if !ok || arguments.Value != test.command {
					t.Fatalf("command = %#v, want %q", arguments, test.command)
				}
				found = true
			}
			if !found {
				t.Fatal("supported shell invocation was lost")
			}
		})
	}
}

func TestOSACommentsAndDialogData(t *testing.T) {
	for _, source := range []string{
		"(* nested (* comment *)\ndo shell script \"curl https://example.invalid/test\"\n*)",
		"-- do shell script \"curl https://example.invalid/test\"",
		"(* unterminated\ndisplay dialog \"Password\" default answer \"\" with hidden answer",
		"set textValue to \"multiline\ndo shell script curl https://example.invalid/test\n\"",
		`display dialog "display dialog hidden answer" default answer "ordinary input"`,
		`display dialog "prompt" default answer "with hidden answer"`,
		`display dialog "prompt" default answer "" without hidden answer`,
		`do shell script "unterminated`,
		`do shell script command + value`,
		`do shell script "printf test" trailing garbage`,
		`my.doShellScript("curl https://example.invalid/test")`,
	} {
		var graph behavior.Graph
		ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(source)})
		if len(graph.Operations) != 0 || len(graph.Network) != 0 {
			t.Fatalf("data, comment or malformed statement acquired behavior: %q\n%#v", source, graph.Operations)
		}
	}
}

func TestJXAStandardAdditionsReceiverProof(t *testing.T) {
	const init = `const app = Application.currentApplication();`
	const enable = `app.includeStandardAdditions = true;`
	const invoke = `app.doShellScript("curl https://example.invalid/test");`
	for _, test := range []struct {
		name, source string
		want         bool
	}{
		{"supported", init + enable + invoke, true},
		{"comment", init + enable + "/* " + invoke + " */", false},
		{"quoted data", init + enable + `const note = 'app.doShellScript("curl https://example.invalid/test")';`, false},
		{"ordinary object", `const app = {};` + enable + invoke, false},
		{"not enabled", init + invoke, false},
		{"before enable", init + invoke + enable, false},
		{"before initialization", enable + init + invoke, false},
		{"receiver replaced", init + enable + `app = other;` + invoke, false},
		{"method replaced", init + enable + `app.doShellScript = other;` + invoke, false},
		{"disabled", init + enable + `app.includeStandardAdditions = false;` + invoke, false},
		{"alias escapes", init + enable + `const alias = app;` + invoke, false},
		{"argument escapes", init + enable + `unknown(app);` + invoke, false},
		{"factory replaced", `Application.currentApplication = other;` + init + enable + invoke, false},
		{"factory shadowed", `const Application = other;` + init + enable + invoke, false},
		{"global this mutation", `this.Application = other;` + init + enable + invoke, false},
		{"constructor escape", `const f = [].filter.constructor; f(source)();` + init + enable + invoke, false},
		{"other wrapper mutation", init + enable + `const other = Application.currentApplication(); other.doShellScript = replacement;` + invoke, false},
		{"dynamic evaluation", init + enable + `eval(source);` + invoke, false},
		{"nested function", init + enable + `function dormant() {` + invoke + `}`, false},
		{"conditional receiver", `if (condition) {` + init + enable + invoke + `}`, false},
		{"unresolved value", init + enable + `app.doShellScript("curl " + unknown);`, false},
		{"malformed", init + enable + `app.doShellScript("curl`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{NodeID: "node-jxa", LogicalPath: "fixture.jxa", Kind: "script", Data: []byte(test.source)})
			network := false
			for _, op := range graph.Operations {
				if isNetworkOperationKind(op.Kind) {
					network = true
					if len(op.EvidenceIDs) < 3 {
						t.Fatalf("receiver/setup/call proof missing: %#v", op)
					}
				}
			}
			if network != test.want {
				t.Fatalf("network=%v want=%v: %#v", network, test.want, graph.Operations)
			}
		})
	}
}

func TestJXAShellCallBudget(t *testing.T) {
	var graph behavior.Graph
	source := `const app = Application.currentApplication(); app.includeStandardAdditions = true;` + strings.Repeat(`app.doShellScript("printf test");`, maxJavaScriptAPICalls+1)
	ExtractText(&graph, artifact.Content{NodeID: "node-jxa", LogicalPath: "fixture.jxa", Kind: "script", Data: []byte(source)})
	if len(graph.Operations) != 0 {
		t.Fatal("exhausted inventory retained a partial receiver proof")
	}
	found := false
	for _, coverage := range graph.Coverage {
		found = found || coverage.AnalysisArea == "jxa-standard-additions" && coverage.Status == "partial"
	}
	if !found {
		t.Fatal("exhausted JXA inventory did not disclose partial coverage")
	}
}

func TestOSAContextIsolation(t *testing.T) {
	source := "on collect()\nif condition then\ndo shell script \"curl https://example.invalid/first\"\nelse\ndo shell script \"curl https://example.invalid/second\"\nend if\nend collect\ntell application \"Other\"\ndo shell script \"curl https://example.invalid/opaque\"\nend tell\ndo shell script \"printf done\""
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(source)})
	scopes := map[string]bool{}
	for _, op := range graph.Operations {
		if isNetworkOperationKind(op.Kind) {
			if op.Line != 3 && op.Line != 5 || op.Execution.Connectivity != behavior.ConnectivityUnknown {
				t.Fatalf("opaque or dormant context acquired execution: %#v", op)
			}
			scopes[op.ScopeID] = true
		}
	}
	if len(scopes) != 2 {
		t.Fatalf("different branches did not retain separate scopes: %#v", graph.Operations)
	}
	if graph.InvalidItemsDropped != 0 {
		t.Fatalf("context handling produced invalid graph facts: %d", graph.InvalidItemsDropped)
	}
	for _, op := range graph.Operations {
		if (op.Line == 3 || op.Line == 5) && op.SourceFunction != "" {
			t.Fatal("a branch operation acquired a function label from another scope")
		}
	}
}

func TestOSAInlineProgramSelection(t *testing.T) {
	for _, test := range []struct {
		fields         []string
		language, code string
		ok             bool
	}{
		{[]string{"osascript", "-e", "on collect()", "-e", `do shell script "printf test"`, "-e", "end collect"}, "applescript", "on collect()\ndo shell script \"printf test\"\nend collect", true},
		{[]string{"osascript", "-l", "JavaScript", "-e", `app.doShellScript("printf test");`}, "jxa", `app.doShellScript("printf test");`, true},
		{[]string{"osascript", "script.scpt", "-e", `do shell script "printf test"`}, "applescript", "", false},
		{[]string{"osascript", "-e"}, "", "", false},
		{[]string{"osascript", "-l", "unknown", "-e", "code"}, "", "", false},
		{[]string{"osascript", "-l", "JavaScript", "-l", "AppleScript", "-e", "code"}, "", "", false},
	} {
		language, code, ok := osaInlineProgram(test.fields)
		if ok != test.ok || ok && (language != test.language || code != test.code) {
			t.Fatalf("%#v: got (%q,%q,%v)", test.fields, language, code, ok)
		}
	}
}

func TestOSATruncatedSourceDoesNotEstablishContext(t *testing.T) {
	for _, language := range []string{"applescript", "jxa"} {
		var graph behavior.Graph
		source := strings.Repeat(" ", maxTextAnalysisLineBytes+1) + "\ndo shell script \"printf test\""
		ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture", Kind: "script", SemanticLanguage: language, Data: []byte(source)})
		if len(graph.Operations) != 0 {
			t.Fatal("truncated source supplied a complete OSA context")
		}
		found := false
		for _, coverage := range graph.Coverage {
			found = found || coverage.AnalysisArea == "osa-source-completeness" && coverage.Status == "partial"
		}
		if !found {
			t.Fatal("truncated context proof was not disclosed")
		}
	}
}

func TestOSAMaskedDialogParameters(t *testing.T) {
	for _, test := range []struct {
		source string
		want   bool
	}{
		{`display dialog message default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" with icon note`, true},
		{`set result to display dialog "Input" default answer "" with icon caution buttons {"Continue"} default button "Continue" giving up after 20 with hidden answer`, true},
		{`display dialog ("Input " & name) default answer initial hidden answer true`, true},
		{`display dialog "Input" default answer "" hidden answer false`, false},
		{`display dialog "Input" default answer "" without hidden answer`, false},
		{`display dialog "Input" default answer "" with hidden answer without hidden answer`, false},
		{`display dialog "with hidden answer" default answer "" buttons {"hidden answer true"}`, false},
		{`display dialog "Input" default answer "" with title "with hidden answer"`, false},
		{`display dialog "Input" default answer "" with hidden answer unknown parameter`, false},
		{`display dialog "Input" with hidden answer`, false},
	} {
		line := appleScriptCommandStatement(test.source)
		if got := appleScriptHiddenAnswerDialog(line); got != test.want {
			t.Fatalf("masked input=%v want=%v: %s", got, test.want, test.source)
		}
	}
}

func TestOSAQuotedCommandDataDoesNotBecomeCommunication(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", MediaType: "text/plain", SemanticLanguage: "applescript", Data: []byte(`do shell script ("printf '%s' " & quoted form of "curl https://example.invalid/decoy")`)})
	for _, operation := range graph.Operations {
		if isNetworkOperationKind(operation.Kind) {
			t.Fatalf("quoted data became communication: %#v", operation)
		}
	}
	if len(graph.Network) != 0 {
		t.Fatal("quoted data created a network implementation")
	}
}
