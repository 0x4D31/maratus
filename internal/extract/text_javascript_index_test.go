package extract

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestJavaScriptStructuralIndexRetainsModuleAndUnindentedFunctionStatements(t *testing.T) {
	lines := []string{
		`const moduleValue = "value";`,
		`function activate(context) {`,
		`const localValue = moduleValue;`,
		`run(localValue);`,
		`}`,
		`after();`,
	}
	index := buildJavaScriptStructuralIndex(lines)
	if index.Disposition != javaScriptStructuralComplete {
		t.Fatalf("disposition = %q, detail=%q", index.Disposition, index.Detail)
	}
	if len(index.Scopes) != 1 ||
		index.Scopes[0].Key != "activate@2" ||
		index.Scopes[0].Name != "activate" {
		t.Fatalf("scopes = %#v", index.Scopes)
	}
	got := structuralStatementSummary(index.Statements)
	want := []string{
		`1-1||:const moduleValue = "value";`,
		`3-3|activate@2|activate:const localValue = moduleValue;`,
		`4-4|activate@2|activate:run(localValue);`,
		`6-6||:after();`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statements = %#v, want %#v", got, want)
	}
}

func TestJavaScriptStructuralIndexTreatsWholeProgramZeroArgumentIIFEAsModule(t *testing.T) {
	lines := strings.Split(`(() => {
const childProcess = require("child_process");
function activate() {
childProcess.exec("whoami");
}
activate();
})();`, "\n")
	index := buildJavaScriptStructuralIndex(lines)
	if index.Disposition != javaScriptStructuralComplete {
		t.Fatalf("disposition = %q, detail=%q", index.Disposition, index.Detail)
	}
	got := structuralStatementSummary(index.Statements)
	want := []string{
		`2-2||:const childProcess = require("child_process");`,
		`4-4|activate@3|activate:childProcess.exec("whoami");`,
		`6-6||:activate();`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statements = %#v, want %#v", got, want)
	}
}

func TestJavaScriptStructuralIndexNormalizesCRLFLines(t *testing.T) {
	index := buildJavaScriptStructuralIndex([]string{
		"const childProcess = require('child_process');\r",
		"function activate() {\r",
		"childProcess.exec('whoami');\r",
		"}\r",
	})
	if index.Disposition != javaScriptStructuralComplete {
		t.Fatalf("disposition = %q, detail=%q", index.Disposition, index.Detail)
	}
	got := structuralStatementSummary(index.Statements)
	want := []string{
		`1-1||:const childProcess = require('child_process');`,
		`3-3|activate@2|activate:childProcess.exec('whoami');`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statements = %#v, want %#v", got, want)
	}
}

func TestJavaScriptStructuralIndexRejectsEmbeddedCarriageReturn(t *testing.T) {
	index := buildJavaScriptStructuralIndex([]string{
		"safe();\rhidden();",
	})
	if index.Disposition != javaScriptStructuralMalformed ||
		!strings.Contains(index.Detail, "embedded line separator") ||
		len(index.Statements) != 0 {
		t.Fatalf("index = %#v", index)
	}
}

func TestJavaScriptStructuralIndexKeepsAssignmentContinuationTogether(t *testing.T) {
	index := buildJavaScriptStructuralIndex([]string{
		`let command = "old";`,
		`command`,
		`= dynamic();`,
		`use(command);`,
	})
	if index.Disposition != javaScriptStructuralComplete {
		t.Fatalf("disposition = %q, detail=%q", index.Disposition, index.Detail)
	}
	got := structuralStatementSummary(index.Statements)
	want := []string{
		`1-1||:let command = "old";`,
		"2-3||:command\n= dynamic();",
		`4-4||:use(command);`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statements = %#v, want %#v", got, want)
	}
}

func TestJavaScriptStructuralIndexGroupsMultilineOuterCallAndHidesArrowBody(t *testing.T) {
	lines := []string{
		`function activate(context) {`,
		`(0, import_child_process.exec)(`,
		`  cdnURL,`,
		`  (error, stdout, stderr) => {`,
		`    nestedCall(error);`,
		`  }`,
		`);`,
		`}`,
	}
	index := buildJavaScriptStructuralIndex(lines)
	if index.Disposition != javaScriptStructuralComplete {
		t.Fatalf("disposition = %q, detail=%q", index.Disposition, index.Detail)
	}
	if len(index.Statements) != 1 {
		t.Fatalf("statements = %#v", index.Statements)
	}
	statement := index.Statements[0]
	if statement.StartLine != 2 || statement.EndLine != 7 ||
		statement.ScopeKey != "activate@1" {
		t.Fatalf("statement metadata = %#v", statement)
	}
	if !strings.Contains(statement.Text, "nestedCall") {
		t.Fatalf("evidence text lost source: %q", statement.Text)
	}
	if !strings.Contains(statement.DirectText, "import_child_process.exec") ||
		!strings.Contains(statement.DirectText, "cdnURL") ||
		strings.Contains(statement.DirectText, "nestedCall") {
		t.Fatalf("direct text exposed or lost the wrong region: %q", statement.DirectText)
	}
	if hasJavaScriptStructuralUse(statement, "nestedCall") ||
		hasJavaScriptStructuralUse(statement, "error") {
		t.Fatalf("opaque arrow use escaped: %#v", statement.Uses)
	}
	if !hasJavaScriptStructuralUse(statement, "import_child_process") ||
		!hasJavaScriptStructuralUse(statement, "cdnURL") {
		t.Fatalf("direct outer uses missing: %#v", statement.Uses)
	}
	if index.Lines[4].Disposition != javaScriptLineOpaque ||
		index.Lines[1].Disposition != javaScriptLineDirect {
		t.Fatalf("line dispositions = %#v", index.Lines)
	}
}

func TestJavaScriptStructuralIndexMakesNestedConstructsOpaqueAndRestoresScope(t *testing.T) {
	lines := strings.Split(`function activate() {
function nested() { hiddenFunction(); }
try { hiddenTry(); } catch (error) { hiddenCatch(); }
if (condition) { hiddenControl(); }
{
hiddenBlock();
}
class Hidden { method() { hiddenClass(); } }
const objectValue = { method() { hiddenObjectMethod(); } };
const arrowValue = () => hiddenArrow();
visible();
}`, "\n")
	index := buildJavaScriptStructuralIndex(lines)
	if index.Disposition != javaScriptStructuralComplete {
		t.Fatalf("disposition = %q, detail=%q", index.Disposition, index.Detail)
	}
	if len(index.Scopes) != 1 {
		t.Fatalf("nested function became a scope: %#v", index.Scopes)
	}
	got := structuralStatementSummary(index.Statements)
	want := []string{
		`9-9|activate@1|activate:const objectValue = { method() { hiddenObjectMethod(); } };`,
		`10-10|activate@1|activate:const arrowValue = () => hiddenArrow();`,
		`11-11|activate@1|activate:visible();`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statements = %#v, want %#v", got, want)
	}
	for _, statement := range index.Statements {
		for _, hidden := range []string{
			"hiddenFunction", "hiddenTry", "hiddenCatch", "hiddenControl",
			"hiddenBlock", "hiddenClass", "hiddenObjectMethod", "hiddenArrow",
		} {
			if hasJavaScriptStructuralUse(statement, hidden) ||
				strings.Contains(statement.DirectText, hidden) {
				t.Fatalf("%q escaped opaque region in %#v", hidden, statement)
			}
		}
	}
	if !strings.Contains(index.Statements[2].DirectText, "visible") {
		t.Fatalf("direct scope was not restored: %#v", index.Statements[2])
	}
}

func TestJavaScriptStructuralIndexRetainsScopedHiddenUses(t *testing.T) {
	lines := []string{
		`function activate(cp) {`,
		`if (condition) { mutate(cp); }`,
		"const marker = `${os = replacement}`;",
		`direct();`,
		`}`,
	}
	index := buildJavaScriptStructuralIndex(lines)
	if index.Disposition != javaScriptStructuralComplete {
		t.Fatalf("disposition = %q, detail=%q", index.Disposition, index.Detail)
	}
	for _, name := range []string{"cp", "condition", "mutate", "os", "replacement"} {
		if !hasJavaScriptStructuralHiddenUse(index, "activate@1", name) {
			t.Fatalf("missing hidden use %q: %#v", name, index.HiddenUses)
		}
	}
	if hasJavaScriptStructuralHiddenUse(index, "activate@1", "direct") {
		t.Fatalf("direct statement use became hidden: %#v", index.HiddenUses)
	}
}

func TestJavaScriptStructuralIndexOmitsMultilineTemplateAndRegexStatements(t *testing.T) {
	lines := []string{
		"const templateDecoy = `first",
		"hiddenTemplate();",
		"last`;",
		`const regexDecoy = /}; hiddenRegex(); function fake() {/;`,
		`safeCall();`,
	}
	index := buildJavaScriptStructuralIndex(lines)
	if index.Disposition != javaScriptStructuralUnsupported {
		t.Fatalf("disposition = %q, detail=%q", index.Disposition, index.Detail)
	}
	if len(index.Statements) != 1 || index.Statements[0].Text != "safeCall();" {
		t.Fatalf("unsafe decoys were retained: %#v", index.Statements)
	}
	if !strings.Contains(index.Detail, "multiline template") {
		t.Fatalf("unstable first unsupported detail = %q", index.Detail)
	}
	for _, hidden := range []string{"hiddenTemplate", "hiddenRegex", "fake"} {
		if hasJavaScriptStructuralUse(index.Statements[0], hidden) {
			t.Fatalf("decoy use escaped: %q", hidden)
		}
	}
}

func TestJavaScriptStructuralIndexRejectsMalformedInputAndComplexFunctions(t *testing.T) {
	for _, lines := range [][]string{
		{`function activate() {`, `call();`},
		{`call([mismatch);`},
		{`call(`, `value;`},
	} {
		index := buildJavaScriptStructuralIndex(lines)
		if index.Disposition != javaScriptStructuralMalformed ||
			len(index.Statements) != 0 {
			t.Fatalf("malformed input accepted: %#v", index)
		}
	}

	index := buildJavaScriptStructuralIndex([]string{
		`function defaults(value = call()) { hiddenDefault(); }`,
		`function destructured({value}) { hiddenDestructure(); }`,
		`function rest(...values) { hiddenRest(); }`,
		`safe();`,
	})
	if index.Disposition != javaScriptStructuralUnsupported ||
		len(index.Scopes) != 3 ||
		len(index.Statements) != 1 ||
		index.Statements[0].Text != "safe();" {
		t.Fatalf("complex functions were not isolated as opaque scopes: %#v", index)
	}
	for _, statement := range index.Statements {
		if statement.ScopeKey != "" {
			t.Fatalf("complex function body became executable: %#v", statement)
		}
	}
}

func TestJavaScriptStructuralIndexCapsAndDeterminism(t *testing.T) {
	source := []string{
		`const first = one;`,
		`const second = two;`,
	}
	first := buildJavaScriptStructuralIndex(source)
	second := buildJavaScriptStructuralIndex(source)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("index was nondeterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}

	tests := []struct {
		name   string
		lines  []string
		limits javaScriptStructuralLimits
		detail string
	}{
		{
			name:  "bytes",
			lines: []string{`value();`},
			limits: javaScriptStructuralLimits{
				bytes: 4, statements: 8, depth: 8, tokens: 32, uses: 32,
			},
			detail: "byte limit 4",
		},
		{
			name:  "statements",
			lines: source,
			limits: javaScriptStructuralLimits{
				bytes: 128, statements: 1, depth: 8, tokens: 32, uses: 32,
			},
			detail: "statement limit 1",
		},
		{
			name:  "depth",
			lines: []string{`call((value));`},
			limits: javaScriptStructuralLimits{
				bytes: 128, statements: 8, depth: 1, tokens: 32, uses: 32,
			},
			detail: "depth limit 1",
		},
		{
			name:  "tokens",
			lines: []string{`call(value);`},
			limits: javaScriptStructuralLimits{
				bytes: 128, statements: 8, depth: 8, tokens: 2, uses: 32,
			},
			detail: "token limit 2",
		},
		{
			name:  "uses",
			lines: []string{`first(second);`},
			limits: javaScriptStructuralLimits{
				bytes: 128, statements: 8, depth: 8, tokens: 32, uses: 1,
			},
			detail: "use limit 1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			index := buildJavaScriptStructuralIndexWithLimits(test.lines, test.limits)
			if index.Disposition != javaScriptStructuralLimited ||
				len(index.Statements) != 0 ||
				!strings.Contains(index.Detail, test.detail) {
				t.Fatalf("cap result = %#v", index)
			}
			repeated := buildJavaScriptStructuralIndexWithLimits(test.lines, test.limits)
			if !reflect.DeepEqual(index, repeated) {
				t.Fatalf("cap result was nondeterministic:\n%#v\n%#v", index, repeated)
			}
		})
	}
}

func structuralStatementSummary(statements []javaScriptStructuralStatement) []string {
	result := make([]string, 0, len(statements))
	for _, statement := range statements {
		result = append(result,
			strings.Join([]string{
				lineRange(statement.StartLine, statement.EndLine),
				statement.ScopeKey,
				statement.FunctionName + ":" + statement.Text,
			}, "|"),
		)
	}
	return result
}

func lineRange(start, end int) string {
	return fmt.Sprintf("%d-%d", start, end)
}

func hasJavaScriptStructuralUse(statement javaScriptStructuralStatement, name string) bool {
	for _, use := range statement.Uses {
		if use.Name == name {
			return true
		}
	}
	return false
}

func hasJavaScriptStructuralHiddenUse(index javaScriptStructuralIndex, scope, name string) bool {
	for _, use := range index.HiddenUses {
		if use.ScopeKey == scope && use.Name == name {
			return true
		}
	}
	return false
}
