package extract

import (
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func FuzzOSAExpression(f *testing.F) {
	for _, seed := range []string{`"printf test"`, `("one" & "two")`, `quoted form of "a'b"`, `"curl " & unknown`, `"unterminated`, "(* nested (* comment *) *)"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		value, ok := exactAppleScriptStringExpression(source)
		boundedAppleScriptArgumentShape(source)
		if ok && len(value) > maxOSAExpressionBytes {
			t.Fatal("expression exceeded its retained value bound")
		}
		if len(source) > maxOSAExpressionBytes {
			return
		}
		lines := strings.Split(source, "\n")
		masked := maskAppleScriptComments(lines)
		if len(masked) != len(lines) {
			t.Fatal("comment masking changed physical line count")
		}
		for _, line := range masked {
			statement := appleScriptCommandStatement(line)
			appleScriptHiddenAnswerDialog(statement)
			appleScriptHiddenAnswerDialog("display dialog " + statement)
			appleScriptCommandArgument(statement, "do shell script")
		}
	})
}

func FuzzOSASource(f *testing.F) {
	for _, source := range []string{
		"set commandValue to \"printf test\"\ndo shell script commandValue",
		"on collect()\nset commandValue to \"printf test\"\ndo shell script commandValue\nend collect",
		`set answer to text returned of (display dialog labelForUser(name) default answer "" with hidden answer)`,
		"(* nested (* comment *)\ndo shell script \"printf test\"\n*)",
	} {
		f.Add(source)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > maxOSAExpressionBytes {
			return
		}
		graph := behavior.Graph{EvidenceLimit: 512, ItemLimit: 512, StringByteLimit: 1 << 20}
		ExtractText(&graph, artifact.Content{NodeID: "node-osa", LogicalPath: "fixture.applescript", Kind: "script", Data: []byte(source)})
		if len(graph.Operations) > 512 || len(graph.Scopes) > 512 {
			t.Fatal("OSA source analysis exceeded graph item limits")
		}
	})
}
