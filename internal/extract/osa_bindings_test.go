package extract

import (
	"fmt"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestOSALocalStringBindingCommands(t *testing.T) {
	for _, test := range []struct {
		name, source, want string
	}{
		{"literal local", "set commandValue to \"printf test\"\ndo shell script commandValue", "printf test"},
		{"case insensitive", "set CommandValue to \"printf test\"\ndo shell script commandvalue", "printf test"},
		{"concatenation", "set toolName to \"curl \"\nset destination to \"https://example.invalid/test\"\ndo shell script toolName & quoted form of destination", "curl 'https://example.invalid/test'"},
		{"immutable text alias", "set firstValue to \"printf test\"\nset secondValue to firstValue\nset firstValue to \"printf other\"\ndo shell script secondValue", "printf test"},
		{"reassignment", "set commandValue to \"printf old\"\nset commandValue to \"printf new\"\ndo shell script commandValue", "printf new"},
		{"after use", "do shell script commandValue\nset commandValue to \"printf late\"", ""},
		{"unknown write", "set commandValue to \"printf stale\"\nset commandValue to unknownValue\ndo shell script commandValue", ""},
		{"branch mutation", "set commandValue to \"printf old\"\nif condition then\nset commandValue to \"printf branch\"\nend if\ndo shell script commandValue", ""},
		{"opaque call", "set commandValue to \"printf old\"\nunknownHandler()\ndo shell script commandValue", ""},
		{"persistent global", "global commandValue\nset commandValue to \"printf global\"\ndo shell script commandValue", ""},
		{"persistent property", "property commandValue : \"printf default\"\ndo shell script commandValue", ""},
		{"handler separation", "set commandValue to \"printf run\"\non collect()\ndo shell script commandValue\nend collect", ""},
		{"mutable object", "set commandValue to {\"printf list\"}\ndo shell script commandValue", ""},
		{"reference escape", "set commandValue to \"printf old\"\nset aliasValue to a reference to commandValue\ndo shell script commandValue", ""},
		{"global after use", "set commandValue to \"printf old\"\ndo shell script commandValue\nglobal commandValue", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(test.source)})
			var calls []behavior.ModeledOperation
			for _, op := range graph.Operations {
				if op.Kind == behavior.OperationInterpreterInvoke {
					calls = append(calls, op)
				}
			}
			if len(calls) != 1 {
				t.Fatalf("shell call count=%d: %#v", len(calls), graph.Operations)
			}
			arg, ok := testOperationBinding(calls[0], behavior.ResourceRoleArguments)
			if !ok || arg.Value != test.want {
				t.Fatalf("command=%q want=%q", arg.Value, test.want)
			}
			if test.want != "" && len(calls[0].EvidenceIDs) < 2 {
				t.Fatalf("local binding proof was lost: %#v", calls[0])
			}
		})
	}
}

func TestOSAClosedQueryDoesNotPreserveItsOldReturnBinding(t *testing.T) {
	var graph behavior.Graph
	source := "set commandValue to \"curl https://example.invalid/stale\"\nset commandValue to do shell script \"whoami\"\ndo shell script commandValue"
	ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(source)})
	for _, op := range graph.Operations {
		if isNetworkOperationKind(op.Kind) {
			t.Fatal("an unknown shell return reused its previous binding")
		}
	}
}

func TestOSANULSourceStaysObservational(t *testing.T) {
	for _, suffix := range []string{"\n\x00"} {
		var graph behavior.Graph
		source := `do shell script "curl https://example.invalid/test"` + suffix
		ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(source)})
		if len(graph.Operations) != 0 {
			t.Fatal("invalid whole-source encoding supplied OSA behavior")
		}
		found := false
		for _, gap := range graph.Coverage {
			found = found || gap.AnalysisArea == "osa-source-encoding" && gap.Status == "partial"
		}
		if !found {
			t.Fatal("unsupported OSA encoding was not disclosed")
		}
	}
}

func TestOSAUnknownEncodingDoesNotGuessUnicodeOperand(t *testing.T) {
	var graph behavior.Graph
	found := false
	source := "-- legacy byte \xff\ndo shell script \"printf café\""
	ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(source)})
	for _, op := range graph.Operations {
		if op.Kind == behavior.OperationInterpreterInvoke {
			found = true
			arguments, _ := testOperationBinding(op, behavior.ResourceRoleArguments)
			if arguments.Value != "" {
				t.Fatal("UTF-8-looking bytes were guessed under an unknown whole-source encoding")
			}
		}
	}
	if !found {
		t.Fatal("an unresolved operand erased the known shell invocation form")
	}
}

func TestOSAUnsupportedHandlerNameIsNotTruncated(t *testing.T) {
	var graph behavior.Graph
	source := "on café()\ndo shell script \"printf test\"\nend café"
	ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(source)})
	if len(graph.Operations) != 0 {
		t.Fatalf("unsupported Unicode handler was attributed to an ASCII prefix: %#v", graph.Operations)
	}
}

func TestOSACommentEncodingDoesNotChangeASCIIOperands(t *testing.T) {
	var graph behavior.Graph
	source := "-- legacy comment \xff\nset commandValue to \"printf test\"\ndo shell script commandValue"
	ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(source)})
	for _, op := range graph.Operations {
		if op.Kind == behavior.OperationInterpreterInvoke {
			arguments, _ := testOperationBinding(op, behavior.ResourceRoleArguments)
			if arguments.Value == "printf test" {
				return
			}
		}
	}
	t.Fatal("ignored comment encoding changed a proved ASCII command")
}

func TestOSALocalTextSurvivesClosedShellQuery(t *testing.T) {
	var graph behavior.Graph
	source := "set destination to \"https://example.invalid/test\"\nset identityValue to do shell script \"whoami\"\ndo shell script \"curl \" & quoted form of destination"
	ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(source)})
	for _, op := range graph.Operations {
		if isNetworkOperationKind(op.Kind) {
			return
		}
	}
	t.Fatal("a closed shell query erased another immutable local string")
}

func TestOSAStringBindingBudgets(t *testing.T) {
	var manyNames, manyProofs, manyBytes strings.Builder
	for i := 0; i <= maxOSAStringBindings; i++ {
		fmt.Fprintf(&manyNames, "set value%d to \"printf test\"\n", i)
	}
	manyNames.WriteString("do shell script value0")
	manyProofs.WriteString("set value0 to \"printf test\"\n")
	for i := 1; i <= maxOSAStringProofs; i++ {
		fmt.Fprintf(&manyProofs, "set value%d to value%d\n", i, i-1)
	}
	fmt.Fprintf(&manyProofs, "do shell script value%d", maxOSAStringProofs)
	for i := 0; i < 18; i++ {
		fmt.Fprintf(&manyBytes, "set value%d to \"%s\"\n", i, strings.Repeat("x", maxOSAExpressionBytes-2))
	}
	manyBytes.WriteString("do shell script value0")
	for _, source := range []string{manyNames.String(), manyProofs.String(), manyBytes.String()} {
		var graph behavior.Graph
		ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(source)})
		for _, op := range graph.Operations {
			if op.Kind == behavior.OperationInterpreterInvoke {
				arguments, _ := testOperationBinding(op, behavior.ResourceRoleArguments)
				if arguments.Value != "" {
					t.Fatal("exhausted binding proof retained a command value")
				}
			}
		}
		found := false
		for _, gap := range graph.Coverage {
			found = found || gap.AnalysisArea == "applescript-string-bindings" && strings.Contains(gap.Detail, "budget")
		}
		if !found {
			t.Fatal("exhausted binding proof was not disclosed")
		}
	}
}

func TestOSAResolvedPrintedCommandRemainsData(t *testing.T) {
	var graph behavior.Graph
	source := "set note to \"curl https://example.invalid/test\"\ndo shell script \"printf '%s' \" & quoted form of note"
	ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(source)})
	for _, op := range graph.Operations {
		if isNetworkOperationKind(op.Kind) {
			t.Fatal("resolving quoted printed data invented communication")
		}
	}
}

func TestOSABindingProofDoesNotCreateInvalidNestedContexts(t *testing.T) {
	var graph behavior.Graph
	command := `osascript -e 'on inner()' -e 'do shell script "printf test"' -e 'end inner'`
	source := fmt.Sprintf("on outer()\nset commandValue to %q\ndo shell script commandValue\nend outer", command)
	ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(source)})
	if graph.InvalidItemsDropped != 0 {
		t.Fatalf("nested scoped derivation constructed %d invalid facts", graph.InvalidItemsDropped)
	}
	retained := false
	for _, op := range graph.Operations {
		if op.Kind == behavior.OperationInterpreterInvoke && op.SourceFunction == "outer" {
			arguments, _ := testOperationBinding(op, behavior.ResourceRoleArguments)
			retained = retained || arguments.Value == command
		}
	}
	if !retained {
		t.Fatal("the outer requested command was lost")
	}
	partial := false
	for _, gap := range graph.Coverage {
		partial = partial || gap.AnalysisArea == "osa-derived-handler-context" && gap.Status == "partial"
	}
	if !partial {
		t.Fatal("unsupported scoped nested handler was not disclosed")
	}
}

func TestOSAStringResolutionWorkBudget(t *testing.T) {
	state := newOSAStringBindings(nil)
	state.values["commandvalue"] = osaResolvedString{value: "printf test", evidenceIDs: []string{"ev-0001"}}
	state.work = maxTextVariableExpansionWorkBytes - 1
	if _, _, ok := resolveAppleScriptStringExpression("commandValue", state); ok || !state.limited {
		t.Fatal("string substitution exceeded its aggregate expansion-work bound")
	}
	if value, _, ok := resolveAppleScriptStringExpression(`"printf independent"`, state); !ok || value != "printf independent" {
		t.Fatal("an independent literal was lost after binding budget exhaustion")
	}
}
