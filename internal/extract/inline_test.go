package extract

import (
	"strings"
	"testing"
)

func TestSplitTopLevelSemicolonStatementsKeepsQuotedSemicolons(t *testing.T) {
	code := `const url = "https://one.example/a;b"; call("x;y"); next();`
	got := splitTopLevelSemicolonStatements(code, false)
	lines := strings.Split(got, "\n")
	want := []string{
		`const url = "https://one.example/a;b"`,
		`call("x;y")`,
		`next()`,
	}
	if len(lines) != len(want) {
		t.Fatalf("split lines = %#v; want %#v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("line %d = %q; want %q", i, lines[i], want[i])
		}
	}
}

func TestSplitTopLevelSemicolonStatementsKeepsPythonCommentRemainderInert(t *testing.T) {
	code := "# inert; requests.get(\"https://comment-decoy.example/\")\nprint('ok')"
	if got := splitTopLevelSemicolonStatements(code, true); got != code {
		t.Fatalf("Python comment was split into executable-looking text: %q", got)
	}
}
