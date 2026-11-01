package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
)

func TestShellReviewDoesNotInventDestinationsOrCommands(t *testing.T) {
	for name, source := range map[string]string{
		"single quoted variable":  "URL=https://example.invalid/p\ncurl '$URL'\n",
		"escaped variable":        "URL=https://example.invalid/p\ncurl \\$URL\n",
		"empty reassignment":      "URL=https://example.invalid/p\nURL=\ncurl \"$URL\"\n",
		"dynamic reassignment":    `URL=https://example.invalid/p; URL=$UNKNOWN; curl "$URL"`,
		"append reassignment":     "URL=https://example.invalid/p\nURL+=different\ncurl \"$URL\"\n",
		"unset":                   "URL=https://example.invalid/p\nunset URL\ncurl \"$URL\"\n",
		"expanded reserved word":  `CMD=if; $CMD curl https://example.invalid/p`,
		"expanded assignment":     `CMD=A=1; $CMD curl https://example.invalid/p`,
		"multiple assignments":    "URL=https://example.invalid/p\nURL= OTHER=value\ncurl \"$URL\"\n",
		"quoted reserved word":    `'if' curl https://example.invalid/p`,
		"uppercase command":       `IF curl https://example.invalid/p`,
		"quoted assignment name":  `"A=1" curl https://example.invalid/p`,
		"shell script argument":   `sh /tmp/inert.sh -c 'curl https://example.invalid/p'`,
		"shell validation only":   `sh -n -c 'curl https://example.invalid/p'`,
		"python script argument":  `python3 inert.py -c 'import os; os.system("curl https://example.invalid/p")'`,
		"node trailing check":     `node -e 'fetch("https://example.invalid/p")' --check`,
		"node trailing help":      `node -e 'fetch("https://example.invalid/p")' --help`,
		"node script argument":    `node inert.js -e 'fetch("https://example.invalid/p")'`,
		"expansion is not syntax": `CMD='echo | curl https://example.invalid/p'; $CMD`,
	} {
		t.Run(name, func(t *testing.T) {
			rep, err := inspectInlineShellForTest(source, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range rep.Operations {
				for _, binding := range op.ResourceBindings {
					if strings.HasPrefix(string(op.Kind), "network.") && binding.Resource.Value == "https://example.invalid/p" {
						t.Fatalf("invented network destination: %#v", op)
					}
				}
			}
			assertStableReportEncoding(t, rep)
		})
	}
}

func TestShellReviewPreservesLiteralAssignedPaths(t *testing.T) {
	source := "P='/tmp/has space'\ncurl https://example.invalid/p -o \"$P\"\n/tmp/has\n"
	rep, err := inspectInlineShellForTest(source, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.download", "file", "/tmp/has space")
	if hasCapability(rep, "macos.download-execute") {
		t.Fatal("different filenames were joined")
	}
	assertStableReportEncoding(t, rep)
}

func TestShellReviewSupportedVariableFlow(t *testing.T) {
	for _, source := range []string{
		"URL=https://example.invalid/p\ncurl \"$URL\"\n",
		`URL=https://example.invalid/p; curl "$URL"`,
		`URL=https://example.invalid/p; curl "${URL}"`,
		"URL=https://old.invalid/p\nURL=https://example.invalid/p; curl \"$URL\"\n",
	} {
		rep, err := inspectInlineShellForTest(source, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertNetworkDestination(t, rep, "https://example.invalid/p")
		assertStableReportEncoding(t, rep)
	}
}

func TestLaunchdReviewRejectsInvalidArgvWithoutPanicking(t *testing.T) {
	for name, declaration := range map[string]string{
		"wrapper query":            `<key>ProgramArguments</key><array><string>sudo</string><string>-l</string><string>/bin/sh</string></array>`,
		"empty executable":         `<key>ProgramArguments</key><array><string></string><string>curl</string><string>https://example.invalid/p</string></array>`,
		"mistyped argument":        `<key>ProgramArguments</key><array><string>curl</string><integer>1</integer><string>https://example.invalid/p</string></array>`,
		"scalar argv":              `<key>ProgramArguments</key><string>curl</string>`,
		"program is not argv zero": `<key>Program</key><string>/bin/sh</string><key>ProgramArguments</key><array><string>-c</string><string>curl https://example.invalid/p</string></array>`,
		"script operand":           `<key>ProgramArguments</key><array><string>/bin/sh</string><string>/tmp/inert.sh</string><string>-c</string><string>curl https://example.invalid/p</string></array>`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "job.plist")
			if err := os.WriteFile(path, []byte(`<plist><dict><key>Label</key><string>review.job</string>`+declaration+`</dict></plist>`), 0600); err != nil {
				t.Fatal(err)
			}
			rep, err := InspectPath(path, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range rep.Operations {
				if strings.HasPrefix(string(op.Kind), "network.") {
					t.Fatalf("invented network operation: %#v", op)
				}
			}
			assertStableReportEncoding(t, rep)
			second, err := InspectPath(path, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			var a, b bytes.Buffer
			if err := WriteJSON(&a, rep); err != nil {
				t.Fatal(err)
			}
			if err := WriteJSON(&b, second); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a.Bytes(), b.Bytes()) {
				t.Fatal("repeat scan changed canonical output")
			}
		})
	}
}

func TestShellReviewLiteralWhitespaceDoesNotCreateResourceFlow(t *testing.T) {
	for _, output := range []string{"/tmp/p ", " /tmp/p", " "} {
		rep, err := inspectInlineShellForTest("curl https://example.invalid/p -o '"+output+"'; /tmp/p", artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertOperation(t, rep, "network.download", "file", output)
		if hasCapability(rep, "macos.download-execute") {
			t.Fatalf("distinct output %q joined to /tmp/p", output)
		}
		assertStableReportEncoding(t, rep)
	}
}

func TestShellReviewVariableOperationRetainsAssignmentEvidence(t *testing.T) {
	rep, err := inspectInlineShellForTest("URL=https://example.invalid/p\ncurl \"$URL\"\n", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceMap(rep.Evidence)
	found := false
	for _, op := range rep.Operations {
		if string(op.Kind) != "network.connect" {
			continue
		}
		lines := map[int]bool{}
		for _, id := range op.EvidenceIDs {
			lines[evidence[id].Line] = true
		}
		if !lines[1] || !lines[2] {
			t.Fatalf("variable-derived operation lost assignment or use evidence: %#v", op)
		}
		found = true
	}
	if !found {
		t.Fatal("supported operation was lost")
	}
	assertStableReportEncoding(t, rep)
}
