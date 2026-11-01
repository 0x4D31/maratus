package extract

import (
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestJavaScriptUnicodeIdentifierBoundaries(t *testing.T) {
	for _, name := range []string{"español", "日本語", "cpé", "écp", "cp\u0301", "cp\u200c", "cp\u200d"} {
		source := name + `.exec(command); cp.exec(command);`
		positions := javaScriptIdentifierPositions(source, "cp")
		want := []int{strings.LastIndex(source, "cp.exec")}
		if !reflect.DeepEqual(positions, want) {
			t.Fatalf("%q split an identifier: got %v want %v", name, positions, want)
		}
		_, valid := scanJavaScriptSyntax(source, 0, len(source), 0, func(javaScriptSyntaxEvent) bool { return true })
		if !valid {
			t.Fatalf("supported identifier rejected: %q", name)
		}
	}
}

func TestJavaScriptStructuralTokenStorageBudget(t *testing.T) {
	size := unsafe.Sizeof(javaScriptStructuralToken{})
	if size > 48 || uintptr(maxJavaScriptStructuralTokens)*size > 64<<20 {
		t.Fatalf("token payload exceeds retained storage budget: size=%d count=%d", size, maxJavaScriptStructuralTokens)
	}
}

func TestJavaScriptUnicodeNamesDoNotBlindOrAliasProcessBinding(t *testing.T) {
	const prefix = `const cp = require("child_process"); const labels = {español:"es",日本語:"ja"};`
	var positive behavior.Graph
	ExtractText(&positive, javascriptCommandTestContent(prefix+`cp.exec("curl https://example.invalid/data");`))
	assertShellCommandNetwork(t, positive, "https://example.invalid/data")
	for _, name := range []string{"cpé", "écp", "cp\u0301", "cp\u200d"} {
		var negative behavior.Graph
		ExtractText(&negative, javascriptCommandTestContent(prefix+name+`.exec("curl https://example.invalid/data");`))
		if len(negative.Operations) != 0 {
			t.Fatalf("Unicode name aliased ASCII builtin binding: %q %#v", name, negative.Operations)
		}
	}
}

func TestJavaScriptUnicodeSyntaxFailsClosed(t *testing.T) {
	for _, source := range []string{"const \xff = 1;", "const \u0301name = 1;", "const 😀 = 1;", "const \u200dname = 1;"} {
		_, valid := scanJavaScriptSyntax(source, 0, len(source), 0, func(javaScriptSyntaxEvent) bool { return true })
		if valid {
			t.Fatalf("unsupported identifier accepted: %q", source)
		}
	}
}

func TestJavaScriptTemplateBoundariesShareLexicalRules(t *testing.T) {
	for _, source := range []string{"`value=${total / count}`", "`value=${/}/.test(text)}`", "`value=${`nested ${value}`}`"} {
		end, _, ok := simpleJavaScriptStructuralTemplateEnd(source, 0)
		if !ok || end != len(source) {
			t.Fatalf("valid template boundary lost: %q end=%d ok=%v", source, end, ok)
		}
	}
	for _, source := range []string{"`value=${/unterminated}`", "`value=${value]}`", "`value=${`nested}`"} {
		if _, _, ok := simpleJavaScriptStructuralTemplateEnd(source, 0); ok {
			t.Fatalf("malformed template admitted: %q", source)
		}
	}
}
