package extract

import (
	"strings"
	"testing"
)

func TestAppleScriptLiteralExpression(t *testing.T) {
	for _, test := range []struct{ source, want string }{
		{`"printf '%s' " & quoted form of "curl https://example.invalid/decoy"`, `printf '%s' 'curl https://example.invalid/decoy'`},
		{`("one" & ("two"))`, "onetwo"},
		{`quoted form of "a'b"`, `'a'\''b'`},
		{`"awk -F\"x\""`, `awk -F"x"`},
		{`""`, ""},
	} {
		value, ok := exactAppleScriptStringExpression(test.source)
		if !ok || value != test.want {
			t.Fatalf("%q: value=%q ok=%v want=%q", test.source, value, ok, test.want)
		}
	}
}

func TestAppleScriptLiteralExpressionRejectsPartialAndBudget(t *testing.T) {
	for _, source := range []string{
		`"curl " & target`, `"prefix" trailing`, `"unterminated`, `("one"`, `"one" &`,
		`handler("text")`, `"unknown\q"`, `quotedform of "text"`,
		strings.Repeat("(", maxOSAExpressionDepth) + `"text"` + strings.Repeat(")", maxOSAExpressionDepth),
		`"` + strings.Repeat("x", maxOSAExpressionBytes) + `"`,
		strings.Repeat(`"a" & `, maxOSAExpressionTerms) + `"b"`,
	} {
		if value, ok := exactAppleScriptStringExpression(source); ok {
			t.Fatalf("unsupported expression accepted: %q -> %q", source, value)
		}
	}
}
