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

func TestInspectOSADataDoesNotAcquireCapabilities(t *testing.T) {
	for _, source := range []string{
		`set note to "do shell script curl https://example.invalid/only-data"`,
		`set note to "display dialog hidden answer"`,
		`set note to "open location https://example.invalid/only-data"`,
		`do shell script ("printf '%s' " & quoted form of "curl https://example.invalid/decoy")`,
	} {
		path := filepath.Join(t.TempDir(), "fixture.applescript")
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		first, err := InspectPath(path, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		for _, capability := range first.Capabilities {
			if capability.RuleID == "macos.network-communication" || capability.RuleID == "macos.credential-prompt" {
				t.Fatalf("quoted data acquired capability: %#v", capability)
			}
		}
		for _, op := range first.Operations {
			if op.Kind == behavior.OperationNetworkConnect || op.Kind == behavior.OperationCredentialPrompt {
				t.Fatalf("quoted data acquired behavior: %#v", op)
			}
		}
		assertReportReferencesValid(t, first)
		second, err := InspectPath(path, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		var a, b, c bytes.Buffer
		if err := WriteJSON(&a, first); err != nil {
			t.Fatal(err)
		}
		if err := WriteJSON(&b, second); err != nil || !bytes.Equal(a.Bytes(), b.Bytes()) {
			t.Fatal("OSA attribution was nondeterministic")
		}
		stored := filepath.Join(t.TempDir(), "report.json")
		if err := os.WriteFile(stored, a.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		reloaded, err := Load(stored)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteJSON(&c, reloaded); err != nil || !bytes.Equal(a.Bytes(), c.Bytes()) {
			t.Fatal("OSA report did not round-trip canonically")
		}
	}
}

func TestInspectOSALocalBindingProvenanceAndContexts(t *testing.T) {
	for _, source := range []string{
		"set commandValue to \"curl https://example.invalid/test\"\ndo shell script commandValue",
		"on collect()\nset commandValue to \"curl https://example.invalid/test\"\ndo shell script commandValue\nend collect",
		"on collect()\nif condition then\nset commandValue to \"curl https://example.invalid/test\"\ndo shell script commandValue\nend if\nend collect",
		fmt.Sprintf("on outer()\nset commandValue to %q\ndo shell script commandValue\nend outer", `osascript -e 'on inner()' -e 'do shell script "printf test"' -e 'end inner'`),
	} {
		path := filepath.Join(t.TempDir(), "fixture.applescript")
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		rep, err := InspectPath(path, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertReportReferencesValid(t, rep)
		if _, err := encodeAndDecodeReport(rep); err != nil {
			t.Fatal(err)
		}
		for _, op := range rep.Operations {
			if op.Kind == behavior.OperationNetworkConnect && len(op.EvidenceIDs) < 2 {
				t.Fatalf("binding/call evidence was lost: %#v", op)
			}
		}
	}
}

func TestInspectOSAHandlerDoesNotAcquireEntryConnectivity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.applescript")
	source := "on collect()\n do shell script \"curl https://example.invalid/test\"\nend collect\ndo shell script \"printf done\"\n"
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertReportReferencesValid(t, rep)
	found := false
	for _, op := range rep.Operations {
		if op.Line == 2 {
			found = true
			if op.Execution.Connectivity != behavior.ConnectivityUnknown || op.SourceFunction != "collect" {
				t.Fatalf("dormant handler acquired entry context: %#v", op)
			}
		}
	}
	if !found {
		t.Fatal("handler behavior was not retained")
	}
}

func TestInspectInlineOSAProgramsPreserveDialectAndHandlerContext(t *testing.T) {
	for _, command := range []string{
		`osascript -e 'on collect()' -e 'do shell script "curl https://example.invalid/dormant"' -e 'end collect'`,
		`osascript script.scpt -e 'do shell script "curl https://example.invalid/argument"'`,
		`osascript -l JavaScript -e 'const note = "do shell script curl https://example.invalid/data";'`,
	} {
		rep, err := inspectInlineShellForTest(command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertReportReferencesValid(t, rep)
		for _, op := range rep.Operations {
			if op.Kind == behavior.OperationNetworkConnect && op.Execution.Connectivity == behavior.ConnectivityConnected {
				t.Fatalf("inline data or dormant handler acquired entry connectivity: %#v", op)
			}
		}
	}
	command := `osascript -l JavaScript -e 'const app = Application.currentApplication(); app.includeStandardAdditions = true; app.doShellScript("curl https://example.invalid/test");'`
	rep, err := inspectInlineShellForTest(command, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertReportReferencesValid(t, rep)
	assertNetworkDestination(t, rep, "https://example.invalid/test")
}

func TestInspectOSABranchesWithinHandlerRemainReloadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.applescript")
	source := "on collect()\nif condition then\ndo shell script \"whoami\"\nelse\ndo shell script \"uname -a\"\nend if\nend collect"
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertReportReferencesValid(t, rep)
	if len(rep.Operations) < 4 {
		t.Fatalf("branch behavior was lost: %#v", rep.Operations)
	}
	if _, err := encodeAndDecodeReport(rep); err != nil {
		t.Fatal(err)
	}
}
