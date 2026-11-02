package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestInspectJXALineEndingsPreserveEvidenceLocations(t *testing.T) {
	for _, separator := range []string{"\n", "\r", "\r\n"} {
		source := strings.Join([]string{
			`const app=Application.currentApplication();`,
			`app.includeStandardAdditions=true;`,
			`const command="curl https://example.invalid/test";`,
			`const output=app.doShellScript(command);`,
		}, separator)
		path := filepath.Join(t.TempDir(), "fixture.jxa")
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		rep, err := InspectPath(path, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertNetworkDestination(t, rep, "https://example.invalid/test")
		for _, operation := range rep.Operations {
			if operation.Line != 4 {
				t.Fatalf("line ending changed the call location: %q %#v", separator, operation)
			}
		}
		for _, evidence := range rep.Evidence {
			if evidence.Method == "javascript-ast" && evidence.Kind == "jxa-shell-call" &&
				(evidence.Line != 4 || evidence.Offset != int64(strings.Index(source, "app.doShellScript"))) {
				t.Fatalf("source offset or line was normalized: %#v", evidence)
			}
		}
		if _, err := encodeAndDecodeReport(rep); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInspectJXAValuesKeepScopesAndCausalEvidence(t *testing.T) {
	const setup = `const app=Application.currentApplication();app.includeStandardAdditions=true;`
	for _, body := range []string{
		`const command="curl https://example.invalid/test";const output=app.doShellScript(command).trim();`,
		`function collect(){const command="curl https://example.invalid/test";return app.doShellScript(command);}collect();`,
		`if(condition){const command="curl https://example.invalid/test";app.doShellScript(command);}`,
		`function collect(){const command="curl https://example.invalid/test";if(condition){app.doShellScript(command);}}`,
	} {
		path := filepath.Join(t.TempDir(), "fixture.jxa")
		if err := os.WriteFile(path, []byte(setup+body), 0o600); err != nil {
			t.Fatal(err)
		}
		one, err := InspectPath(path, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(one.Operations) == 0 {
			t.Fatal("JXA requests were lost")
		}
		for _, operation := range one.Operations {
			if len(operation.EvidenceIDs) < 3 {
				t.Fatalf("receiver and value evidence lost: %#v", operation)
			}
		}
		assertReportReferencesValid(t, one)
		if _, err := encodeAndDecodeReport(one); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		two, err := InspectPath(path, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		var a, b bytes.Buffer
		if err := WriteJSON(&a, one); err != nil {
			t.Fatal(err)
		}
		if err := WriteJSON(&b, two); err != nil || !bytes.Equal(a.Bytes(), b.Bytes()) {
			t.Fatal("JXA value recovery was nondeterministic")
		}
	}
}

func TestInspectInlineJXAFunctionCallsRemainConditional(t *testing.T) {
	command := `osascript -l JavaScript -e 'const app=Application.currentApplication();app.includeStandardAdditions=true;function collect(){const command="curl https://example.invalid/test";return app.doShellScript(command);}collect();'`
	rep, err := inspectInlineShellForTest(command, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkDestination(t, rep, "https://example.invalid/test")
	for _, operation := range rep.Operations {
		if operation.Kind == behavior.OperationNetworkConnect && (operation.Execution.Connectivity != behavior.ConnectivityUnknown || operation.SourceFunction != "collect") {
			t.Fatalf("a source helper call became proved entry execution: %#v", operation)
		}
	}
	assertReportReferencesValid(t, rep)
	if _, err := encodeAndDecodeReport(rep); err != nil {
		t.Fatal(err)
	}
}
