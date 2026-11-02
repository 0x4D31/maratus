package report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestInspectJavaScriptNetworkOperandsRemainComplete(t *testing.T) {
	for _, extra := range []string{"", "function* unrelated(){yield 1;}"} {
		for _, endpoint := range []struct {
			value string
			known bool
		}{
			{"prefix https://example.invalid/decoy", false},
			{"https://example.invalid/%zz", false},
			{"data:text/plain,https://example.invalid/decoy", false},
			{"https://example.invalid/inert.", true},
			{"https://example.invalid/test?a=1&b=2", true},
		} {
			path := filepath.Join(t.TempDir(), "fixture.js")
			source := fmt.Sprintf(`%s const endpoint=%q;fetch(endpoint);`, extra, endpoint.value)
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			rep, err := InspectPath(path, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(rep.Operations) != 1 {
				t.Fatalf("request was lost or duplicated: %s\n%#v", source, rep.Operations)
			}
			operation := rep.Operations[0]
			binding, ok := operation.FirstBinding(behavior.ResourceRoleRemoteDestination)
			want := ""
			if endpoint.known {
				want = endpoint.value
			}
			if !ok || binding.Resource.Value != want || operation.Qualifiers["api"] != "fetch" {
				t.Fatalf("destination was fabricated or rewritten: %s\n%#v", source, operation)
			}
			assertReportReferencesValid(t, rep)
			if _, err := encodeAndDecodeReport(rep); err != nil {
				t.Fatalf("%s: %v", source, err)
			}
		}
	}
}

func TestInspectJavaScriptUnrelatedSyntaxPreservesConstantResource(t *testing.T) {
	for _, extra := range []string{"", "function* unrelated(value) { yield value; }\n"} {
		path := filepath.Join(t.TempDir(), "fixture.js")
		source := "const fs=require('fs');\nconst source='/tmp/inert-input';\n" + extra + "fs.readFileSync(source);\n"
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		one, err := InspectPath(path, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, op := range one.Operations {
			if op.Kind == behavior.OperationFileRead {
				binding, ok := op.FirstBinding(behavior.ResourceRoleSource)
				if !ok || binding.Resource.Value != "/tmp/inert-input" {
					t.Fatalf("unrelated syntax lost the constant source: %#v", op)
				}
				found = true
			}
		}
		if !found {
			t.Fatal("file operation was lost")
		}
		assertReportReferencesValid(t, one)
		if _, err := encodeAndDecodeReport(one); err != nil {
			t.Fatal(err)
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
			t.Fatal("value recovery was nondeterministic")
		}
	}
}

func TestInspectJavaScriptValueLineageAcrossScopesRemainsReloadable(t *testing.T) {
	for _, test := range []struct {
		body  string
		known bool
	}{
		{`const path="/tmp/inert";if(condition){fs.readFileSync(path);}`, true},
		{`function read(){const path="/tmp/inert";fs.readFileSync(path);}`, true},
		{`function read(){var path="/tmp/inert";fs.readFileSync(path);}`, true},
		{`function read(){const path="/tmp/inert";if(condition){fs.readFileSync(path);}}`, false},
		{`function read(){if(condition){const path="/tmp/inert";fs.readFileSync(path);}}`, true},
		{`function read(){const command="curl https://example.invalid/test";if(condition){cp.execSync(command);}}`, false},
		{`const endpoint="https://example.invalid/test";fetch(endpoint);`, true},
	} {
		body := test.body
		path := filepath.Join(t.TempDir(), "fixture.js")
		source := `const fs=require("fs"),cp=require("child_process");function* unrelated(){yield 1;}` + body
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		rep, err := InspectPath(path, artifact.Options{})
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		known := false
		for _, operation := range rep.Operations {
			for _, binding := range operation.ResourceBindings {
				known = known || binding.Resource.Value == "/tmp/inert" || binding.Resource.Value == "https://example.invalid/test"
			}
		}
		if len(rep.Operations) == 0 || known != test.known {
			t.Fatalf("value context changed: %s\n%#v", body, rep.Operations)
		}
		if !test.known {
			partial := false
			for _, coverage := range rep.Coverage {
				partial = partial || coverage.AnalysisArea == "javascript-ast-value-context" && coverage.Status == "partial"
			}
			if !partial {
				t.Fatal("incompatible value context was not disclosed")
			}
		}
		assertReportReferencesValid(t, rep)
		if _, err := encodeAndDecodeReport(rep); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
	}
}
