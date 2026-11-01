package extract

import (
	"reflect"
	"strings"
	"testing"
)

func TestExactJavaScriptCallContent(t *testing.T) {
	source := `prefix run("escaped \") text", nested([1, {value: /[,)]/}]), ` + "`value ${ignored})`" + `) suffix`
	open := strings.IndexByte(source, '(')
	content, close, ok := exactJavaScriptCallContent(source, open, len(source))
	if !ok {
		t.Fatal("balanced call was rejected")
	}
	want := `"escaped \") text", nested([1, {value: /[,)]/}]), ` + "`value ${ignored})`"
	if content != want {
		t.Fatalf("content = %q, want %q", content, want)
	}
	if source[close] != ')' || source[close+1:] != " suffix" {
		t.Fatalf("closing index = %d in %q", close, source)
	}
}

func TestExactJavaScriptCallContentRejectsMalformedAndBoundedInput(t *testing.T) {
	tests := []struct {
		name   string
		source string
		limit  int
	}{
		{name: "not opening parenthesis", source: `run("x")`, limit: 8},
		{name: "unclosed call", source: `("x"`, limit: 4},
		{name: "mismatched delimiter", source: `([)]`, limit: 4},
		{name: "unclosed quote", source: `("x)`, limit: 4},
		{name: "unclosed template", source: "(`x ${value})", limit: 13},
		{name: "unclosed block comment", source: `(value /* )`, limit: 11},
		{name: "over budget", source: `("0123456789")`, limit: 8},
		{name: "over nested", source: strings.Repeat("(", maxJavaScriptSyntaxNesting+1) + strings.Repeat(")", maxJavaScriptSyntaxNesting+1), limit: 2*maxJavaScriptSyntaxNesting + 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			open := strings.IndexByte(test.source, '(')
			if test.name == "not opening parenthesis" {
				open = 0
			}
			if content, close, ok := exactJavaScriptCallContent(test.source, open, test.limit); ok {
				t.Fatalf("accepted malformed input: content=%q close=%d", content, close)
			}
		})
	}
}

func TestSplitJavaScriptArgumentsExact(t *testing.T) {
	text := `nested({value: [1, 2]}, "escaped \", comma"), ` + "`template, ${ignored}`" + `,`
	got, ok := splitJavaScriptArgumentsExact(text, len(text), 3)
	if !ok {
		t.Fatal("valid nested arguments were rejected")
	}
	want := []string{
		`nested({value: [1, 2]}, "escaped \", comma")`,
		"`template, ${ignored}`",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("arguments = %#v, want %#v", got, want)
	}
}

func TestSplitJavaScriptArgumentsExactRejectsHolesAndMalformedSyntax(t *testing.T) {
	tests := []string{
		`,value`,
		`value,,other`,
		`"first",, "third"`,
		`value,,`,
		`value, /* comment only */, other`,
		`value, [mismatch)`,
		`value, "unclosed`,
		`value, /* unclosed`,
	}
	for _, text := range tests {
		t.Run(text, func(t *testing.T) {
			if got, ok := splitJavaScriptArgumentsExact(text, len(text), 8); ok {
				t.Fatalf("accepted invalid argument list: %#v", got)
			}
		})
	}
}

func TestSplitJavaScriptArgumentsExactBoundsWork(t *testing.T) {
	text := strings.Repeat("a", 4096)
	if got, ok := splitJavaScriptArgumentsExact(text, len(text)-1, 1); ok {
		t.Fatalf("accepted over-budget argument: %#v", got)
	}
	if got, ok := splitJavaScriptArgumentsExact(`first, second`, 13, 1); ok {
		t.Fatalf("accepted too many arguments: %#v", got)
	}
}

func TestScanJavaScriptIdentifierOccurrencesExact(t *testing.T) {
	text := `target = "hidden = value"; /* commentWrite = 1 */ /regexWrite\s*=/.test(input); ` +
		"`template ${templateWrite = 1}`; target += 1; object.member = 2; other++; ++counter;"
	got, ok := scanJavaScriptIdentifierOccurrencesExact(text, len(text), 32)
	if !ok {
		t.Fatal("valid bounded source was rejected")
	}

	var writes []string
	for _, occurrence := range got {
		if occurrence.Write {
			writes = append(writes, occurrence.Name)
		}
		if occurrence.Name == "member" && occurrence.Reference {
			t.Fatalf("member property became a lexical reference: %#v", occurrence)
		}
		switch occurrence.Name {
		case "hidden", "commentWrite", "regexWrite", "templateWrite":
			t.Fatalf("retained identifier from ignored lexical region: %#v", occurrence)
		}
	}
	wantWrites := []string{"target", "target", "other", "counter"}
	if !reflect.DeepEqual(writes, wantWrites) {
		t.Fatalf("writes = %#v, want %#v; all=%#v", writes, wantWrites, got)
	}
}

func TestScanJavaScriptIdentifierOccurrencesClassifiesPropertyKeys(t *testing.T) {
	text := `{exec: "metadata", shorthand}; condition ? exec : other; object.exec;`
	got, ok := scanJavaScriptIdentifierOccurrencesExact(text, len(text), 32)
	if !ok {
		t.Fatal("valid property syntax was rejected")
	}
	var references []string
	for _, occurrence := range got {
		if occurrence.Reference {
			references = append(references, occurrence.Name)
		}
	}
	want := []string{"shorthand", "condition", "exec", "other", "object"}
	if !reflect.DeepEqual(references, want) {
		t.Fatalf("references = %#v, want %#v; all=%#v", references, want, got)
	}
}

func TestScanJavaScriptIdentifierOccurrencesIncludesTemplateExpressionWritesOnRequest(t *testing.T) {
	text := "`rawName = ignored ${first}${++second} ${target = nested(`${other++}`)} tailName = ignored`"
	got, ok := scanJavaScriptIdentifierOccurrencesIncludingTemplateExpressionsExact(
		text,
		len(text),
		16,
	)
	if !ok {
		t.Fatal("valid template expression was rejected")
	}
	var writes []string
	for _, occurrence := range got {
		if occurrence.Write {
			writes = append(writes, occurrence.Name)
		}
		switch occurrence.Name {
		case "rawName", "tailName", "ignored":
			t.Fatalf("template text became an identifier: %#v", occurrence)
		case "first":
			if occurrence.Write {
				t.Fatalf("write state crossed interpolation boundary: %#v", occurrence)
			}
		}
	}
	if want := []string{"second", "target", "other"}; !reflect.DeepEqual(writes, want) {
		t.Fatalf("writes = %#v, want %#v; all=%#v", writes, want, got)
	}
}

func TestScanJavaScriptIdentifierOccurrencesExactFailsClosed(t *testing.T) {
	if got, ok := scanJavaScriptIdentifierOccurrencesExact(`value = "`+strings.Repeat("x", 4096), 64, 8); ok || got != nil {
		t.Fatalf("accepted over-budget or malformed source: %#v", got)
	}
	if got, ok := scanJavaScriptIdentifierOccurrencesExact(`a = 1; b = 2`, 14, 1); ok || got != nil {
		t.Fatalf("accepted occurrence overflow: %#v", got)
	}
}
