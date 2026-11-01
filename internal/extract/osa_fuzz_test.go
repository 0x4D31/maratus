package extract

import (
	"strings"
	"testing"
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
