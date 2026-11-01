package artifact

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesystemOSAAppletAddsCanonicalBundleScript(t *testing.T) {
	app := writeFilesystemOSAApplet(t, osaAppletFixture{
		info:       osaAppletInfoPlist("applet", "com.apple.ScriptEditor.id.main", "APPL", "aplt"),
		scriptPath: osaAppletScriptRelativePath,
		scriptData: testCompiledAppleScript(),
		appletData: testThinMachO(),
	})

	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertSingleBundleScriptEdge(t, result.Graph,
		"Fixture.app",
		"Fixture.app/"+osaAppletScriptRelativePath,
	)
	if !artifactHasEdgeToLogical(result.Graph, "bundle-executable", "Fixture.app/"+osaAppletExecutableRelativePath) {
		t.Fatalf("missing corroborating applet executable edge: %#v", result.Graph.Edges)
	}
	script := contentByLogical(result.Contents, "Fixture.app/"+osaAppletScriptRelativePath)
	if script == nil || script.Kind != "compiled-applescript" || script.Role != "runtime" {
		t.Fatalf("OSA applet script content = %#v", script)
	}
	if script.PrimaryExecutable {
		t.Fatalf("invoked applet script must not become an independent root: %#v", script)
	}
}

func TestFilesystemOSAAppletRejectsUncorroboratedLayouts(t *testing.T) {
	validInfo := osaAppletInfoPlist("applet", "com.apple.ScriptEditor.id.main", "APPL", "aplt")
	spoofInfo := `<?xml version="1.0"?><plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>applet</string>
<key>Description</key><string>com.apple.ScriptEditor.id.main APPL aplt</string>
</dict></plist>`
	tests := []struct {
		name    string
		fixture osaAppletFixture
	}{
		{
			name: "metadata string spoof",
			fixture: osaAppletFixture{
				info: spoofInfo, scriptPath: osaAppletScriptRelativePath,
				scriptData: testCompiledAppleScript(), appletData: testThinMachO(),
			},
		},
		{
			name: "malformed plist",
			fixture: osaAppletFixture{
				info:       "bplist00CFBundleExecutable applet com.apple.ScriptEditor.id.main APPL aplt",
				scriptPath: osaAppletScriptRelativePath,
				scriptData: testCompiledAppleScript(), appletData: testThinMachO(),
			},
		},
		{
			name: "wrong declared executable",
			fixture: osaAppletFixture{
				info:       osaAppletInfoPlist("Runner", "com.apple.ScriptEditor.id.main", "APPL", "aplt"),
				scriptPath: osaAppletScriptRelativePath,
				scriptData: testCompiledAppleScript(), appletData: testThinMachO(),
			},
		},
		{
			name: "missing signature corroboration",
			fixture: osaAppletFixture{
				info:       osaAppletInfoPlist("applet", "com.apple.ScriptEditor.id.main", "APPL", ""),
				scriptPath: osaAppletScriptRelativePath,
				scriptData: testCompiledAppleScript(), appletData: testThinMachO(),
			},
		},
		{
			name: "printable magic spoof",
			fixture: osaAppletFixture{
				info: validInfo, scriptPath: osaAppletScriptRelativePath,
				scriptData: []byte("FasdUAS printable text is not a compiled script"), appletData: testThinMachO(),
			},
		},
		{
			name: "backup path",
			fixture: osaAppletFixture{
				info: validInfo, scriptPath: osaAppletScriptRelativePath + ".backup",
				scriptData: testCompiledAppleScript(), appletData: testThinMachO(),
			},
		},
		{
			name: "wrong resource path",
			fixture: osaAppletFixture{
				info: validInfo, scriptPath: "Contents/Resources/main.scpt",
				scriptData: testCompiledAppleScript(), appletData: testThinMachO(),
			},
		},
		{
			name: "case variant path",
			fixture: osaAppletFixture{
				info: validInfo, scriptPath: "Contents/Resources/Scripts/Main.scpt",
				scriptData: testCompiledAppleScript(), appletData: testThinMachO(),
			},
		},
		{
			name: "non Mach-O applet carrier",
			fixture: osaAppletFixture{
				info: validInfo, scriptPath: osaAppletScriptRelativePath,
				scriptData: testCompiledAppleScript(), appletData: []byte("#!/bin/sh\nexit 0\n"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app := writeFilesystemOSAApplet(t, test.fixture)
			result, err := InspectPath(app, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if artifactHasEdgeKind(result.Graph.Edges, "bundle-script") {
				t.Fatalf("unproven filesystem applet created bundle-script: %#v", result.Graph.Edges)
			}
		})
	}
}

func TestArchivedOSAAppletAddsCanonicalBundleScript(t *testing.T) {
	result := inspectOSAAppletArchive(t, validOSAAppletArchiveEntries())
	assertSingleBundleScriptEdge(t, result.Graph,
		"sample.zip!Payload/Fixture.app",
		"sample.zip!Payload/Fixture.app/"+osaAppletScriptRelativePath,
	)
	if !artifactHasEdgeToLogical(result.Graph, "bundle-executable", "sample.zip!Payload/Fixture.app/"+osaAppletExecutableRelativePath) {
		t.Fatalf("missing archived applet executable edge: %#v", result.Graph.Edges)
	}
}

func TestArchivedOSAAppletRejectsAmbiguousOrNoncanonicalMembers(t *testing.T) {
	tests := []struct {
		name    string
		entries []osaArchiveEntry
	}{
		{
			name: "duplicate canonical script",
			entries: append(validOSAAppletArchiveEntries(), osaArchiveEntry{
				name: "Payload/Fixture.app/" + osaAppletScriptRelativePath,
				data: testCompiledAppleScript(),
			}),
		},
		{
			name: "case-colliding script",
			entries: append(validOSAAppletArchiveEntries(), osaArchiveEntry{
				name: "Payload/Fixture.app/Contents/Resources/Scripts/Main.scpt",
				data: testCompiledAppleScript(),
			}),
		},
		{
			name: "duplicate canonical metadata",
			entries: append(validOSAAppletArchiveEntries(), osaArchiveEntry{
				name: "Payload/Fixture.app/" + appInfoRelativePath,
				data: []byte(osaAppletInfoPlist("applet", "com.apple.ScriptEditor.id.main", "APPL", "aplt")),
			}),
		},
		{
			name: "backup only",
			entries: replaceOSAArchiveEntry(validOSAAppletArchiveEntries(), osaAppletScriptRelativePath,
				osaAppletScriptRelativePath+".backup", testCompiledAppleScript()),
		},
		{
			name: "wrong path",
			entries: replaceOSAArchiveEntry(validOSAAppletArchiveEntries(), osaAppletScriptRelativePath,
				"Contents/Resources/main.scpt", testCompiledAppleScript()),
		},
		{
			name: "case variant only",
			entries: replaceOSAArchiveEntry(validOSAAppletArchiveEntries(), osaAppletScriptRelativePath,
				"Contents/Resources/Scripts/Main.scpt", testCompiledAppleScript()),
		},
		{
			name: "wrong script magic",
			entries: replaceOSAArchiveEntry(validOSAAppletArchiveEntries(), osaAppletScriptRelativePath,
				osaAppletScriptRelativePath, []byte("FasdUAS printable spoof")),
		},
		{
			name: "malformed plist",
			entries: replaceOSAArchiveEntry(validOSAAppletArchiveEntries(), appInfoRelativePath,
				appInfoRelativePath, []byte("bplist00 applet com.apple.ScriptEditor.id.main APPL aplt")),
		},
		{
			name: "case variant metadata path",
			entries: replaceOSAArchiveEntry(validOSAAppletArchiveEntries(), appInfoRelativePath,
				"contents/Info.plist", []byte(osaAppletInfoPlist("applet", "com.apple.ScriptEditor.id.main", "APPL", "aplt"))),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := inspectOSAAppletArchive(t, test.entries)
			if artifactHasEdgeKind(result.Graph.Edges, "bundle-script") {
				t.Fatalf("ambiguous or noncanonical archive applet created bundle-script: %#v", result.Graph.Edges)
			}
		})
	}
}

func TestRecognizeOSAAppletRejectsOversizedMetadataWithoutParsingTail(t *testing.T) {
	metadata := append(bytes.Repeat([]byte(" "), int(maxAppMetadataBytes)+1),
		[]byte(osaAppletInfoPlist("applet", "com.apple.ScriptEditor.id.main", "APPL", "aplt"))...)
	members := []appBundleMember{
		{relativePath: appInfoRelativePath, data: metadata, kind: "plist", available: true},
		{relativePath: osaAppletExecutableRelativePath, data: testThinMachO(), kind: "macho", available: true},
		{relativePath: osaAppletScriptRelativePath, data: testCompiledAppleScript(), kind: "compiled-applescript", available: true},
	}
	if _, ok := recognizeOSAApplet(members); ok {
		t.Fatal("oversized metadata established an OSA applet invocation")
	}
}

type osaAppletFixture struct {
	info       string
	scriptPath string
	scriptData []byte
	appletData []byte
}

func writeFilesystemOSAApplet(t *testing.T, fixture osaAppletFixture) string {
	t.Helper()
	app := filepath.Join(t.TempDir(), "Fixture.app")
	files := map[string][]byte{
		appInfoRelativePath:             []byte(fixture.info),
		osaAppletExecutableRelativePath: fixture.appletData,
		fixture.scriptPath:              fixture.scriptData,
	}
	for relative, data := range files {
		path := filepath.Join(app, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o600)
		if relative == osaAppletExecutableRelativePath {
			mode = 0o700
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	return app
}

type osaArchiveEntry struct {
	name string
	data []byte
}

func validOSAAppletArchiveEntries() []osaArchiveEntry {
	root := "Payload/Fixture.app/"
	return []osaArchiveEntry{
		{name: root + appInfoRelativePath, data: []byte(osaAppletInfoPlist("applet", "com.apple.ScriptEditor.id.main", "APPL", "aplt"))},
		{name: root + osaAppletExecutableRelativePath, data: testThinMachO()},
		{name: root + osaAppletScriptRelativePath, data: testCompiledAppleScript()},
	}
}

func replaceOSAArchiveEntry(entries []osaArchiveEntry, oldRelative, newRelative string, data []byte) []osaArchiveEntry {
	out := append([]osaArchiveEntry(nil), entries...)
	oldSuffix := "/" + oldRelative
	for i := range out {
		if strings.HasSuffix(out[i].name, oldSuffix) {
			out[i].name = strings.TrimSuffix(out[i].name, oldSuffix) + "/" + newRelative
			out[i].data = data
			break
		}
	}
	return out
}

func inspectOSAAppletArchive(t *testing.T, entries []osaArchiveEntry) Result {
	t.Helper()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		if strings.HasSuffix(entry.name, "/"+osaAppletExecutableRelativePath) {
			header.SetMode(0o755)
		}
		member, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sample.zip")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertSingleBundleScriptEdge(t *testing.T, graph Graph, wantFrom, wantTo string) {
	t.Helper()
	nodes := make(map[string]string, len(graph.Nodes))
	for _, node := range graph.Nodes {
		nodes[node.ID] = node.LogicalPath
	}
	count := 0
	for _, edge := range graph.Edges {
		if edge.Kind != "bundle-script" {
			continue
		}
		count++
		if nodes[edge.From] != wantFrom || nodes[edge.To] != wantTo {
			t.Fatalf("bundle-script edge = %q -> %q, want %q -> %q", nodes[edge.From], nodes[edge.To], wantFrom, wantTo)
		}
	}
	if count != 1 {
		t.Fatalf("bundle-script edge count = %d, want 1: %#v", count, graph.Edges)
	}
}

func testCompiledAppleScript() []byte {
	return append([]byte(compiledAppleScriptMagic+" 1.101.10"), 0, 4, 15, 0xff, 0xff)
}

func osaAppletInfoPlist(executable, identifier, packageType, signature string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>` + executable + `</string>
<key>CFBundleIdentifier</key><string>` + identifier + `</string>
<key>CFBundlePackageType</key><string>` + packageType + `</string>
<key>CFBundleSignature</key><string>` + signature + `</string>
</dict></plist>`
}
