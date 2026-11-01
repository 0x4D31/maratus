package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validPlatypusSettingsPlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Creator</key><string>Platypus-5.3</string>
<key>ScriptInterpreter</key><string>/bin/sh</string>
<key>InterpreterArgs</key><array/>
<key>ScriptArgs</key><array/>
</dict></plist>`

func TestArchivedPlatypusAppAddsOnlyCanonicalBundleScript(t *testing.T) {
	entries := archivedPlatypusBaseEntries()
	entries["Payload/Platypus.app/Contents/Resources/AppSettings.plist"] = []byte(validPlatypusSettingsPlist)
	entries["Payload/Platypus.app/Contents/Resources/script"] = []byte("#!/bin/sh\necho canonical\n")
	entries["Payload/Platypus.app/Contents/Resources/script.backup"] = []byte("#!/bin/sh\necho decoy\n")
	entries["Payload/Platypus.app/Contents/Resources/AppSettings.plist.bak"] = []byte(validPlatypusSettingsPlist)

	result := inspectArchiveEntries(t, entries)
	nodes := map[string]Node{}
	for _, node := range result.Graph.Nodes {
		nodes[node.ID] = node
	}
	wantFrom := "sample.zip!Payload/Platypus.app"
	wantTo := "sample.zip!Payload/Platypus.app/Contents/Resources/script"
	wantSettings := "sample.zip!Payload/Platypus.app/Contents/Resources/AppSettings.plist"
	count := 0
	for _, edge := range result.Graph.Edges {
		if edge.Kind != "bundle-script" {
			continue
		}
		count++
		if nodes[edge.From].LogicalPath != wantFrom || nodes[edge.To].LogicalPath != wantTo {
			t.Fatalf("bundle-script edge targeted a non-canonical entry: %#v", edge)
		}
		if edge.InvocationInterpreter != "/bin/sh" || len(edge.InterpreterArguments) != 0 || len(edge.InvocationArguments) != 0 || len(edge.SupportingEvidence) != 4 {
			t.Fatalf("bundle-script invocation metadata = %#v", edge)
		}
	}
	if count != 1 {
		t.Fatalf("bundle-script edge count = %d, want 1: %#v", count, result.Graph.Edges)
	}
	var app, settings *Node
	for index := range result.Graph.Nodes {
		node := &result.Graph.Nodes[index]
		switch node.LogicalPath {
		case wantFrom:
			app = node
		case wantSettings:
			settings = node
		}
	}
	if app == nil || settings == nil || app.PackagingTechnology != "Platypus" || len(app.PackagingEvidence) != 2 {
		t.Fatalf("Platypus packaging attribution missing: app=%#v settings=%#v", app, settings)
	}
	for _, evidence := range app.PackagingEvidence {
		if evidence.NodeID != settings.ID || evidence.Offset < 0 || evidence.Kind == "" || evidence.Value == "" {
			t.Fatalf("invalid cross-node Platypus evidence: %#v", evidence)
		}
	}
}

func TestArchivedPlatypusKeepsTargetButDefersMalformedInvocationArguments(t *testing.T) {
	entries := archivedPlatypusBaseEntries()
	entries["Payload/Platypus.app/Contents/Resources/AppSettings.plist"] = []byte(`<plist><dict>
<key>Creator</key><string>Platypus-5.3</string>
<key>ScriptInterpreter</key><string>/bin/sh</string>
<key>InterpreterArgs</key><string>-x</string>
<key>ScriptArgs</key><array/>
</dict></plist>`)
	entries["Payload/Platypus.app/Contents/Resources/script"] = []byte("#!/bin/sh\necho canonical\n")

	result := inspectArchiveEntries(t, entries)
	var app *Node
	var scriptEdge *Edge
	for index := range result.Graph.Nodes {
		if result.Graph.Nodes[index].LogicalPath == "sample.zip!Payload/Platypus.app" {
			app = &result.Graph.Nodes[index]
		}
	}
	for index := range result.Graph.Edges {
		if result.Graph.Edges[index].Kind == "bundle-script" {
			scriptEdge = &result.Graph.Edges[index]
		}
	}
	if app == nil || app.PackagingTechnology != "Platypus" || app.AnalyzeStatus != "partial" || !strings.Contains(app.CoverageDetail, "exact interpreter arguments") {
		t.Fatalf("malformed invocation metadata lost attribution or coverage: %#v", app)
	}
	if scriptEdge == nil || scriptEdge.InvocationInterpreter != "" || !scriptEdge.InvocationHostUnresolved || len(scriptEdge.SupportingEvidence) != 0 {
		t.Fatalf("malformed invocation arguments became exact target metadata: %#v", scriptEdge)
	}
}

func TestPlatypusInvocationTreatsAbsentOptionalArgumentsAsEmpty(t *testing.T) {
	settings := []byte(`<plist><dict>
<key>Creator</key><string>Platypus-5.3</string>
<key>ScriptInterpreter</key><string>/bin/sh</string>
</dict></plist>`)
	invocation, ok := platypusInvocation(settings)
	if !ok || invocation.interpreter != "/bin/sh" || len(invocation.interpreterArgs) != 0 || len(invocation.scriptArgs) != 0 {
		t.Fatalf("minimal Platypus invocation = %#v, %v", invocation, ok)
	}
	if len(invocation.evidence) != 2 {
		t.Fatalf("minimal invocation evidence = %#v, want exact creator/interpreter pair", invocation.evidence)
	}
}

func TestPlatypusInvocationArgumentsAreBoundedAndTyped(t *testing.T) {
	tooMany := strings.Repeat("<string>x</string>", maxPlatypusArguments+1)
	for name, settings := range map[string]string{
		"too many":   `<plist><dict><key>Creator</key><string>Platypus-5.3</string><key>ScriptInterpreter</key><string>/bin/sh</string><key>InterpreterArgs</key><array>` + tooMany + `</array><key>ScriptArgs</key><array/></dict></plist>`,
		"non-string": `<plist><dict><key>Creator</key><string>Platypus-5.3</string><key>ScriptInterpreter</key><string>/bin/sh</string><key>InterpreterArgs</key><array><integer>1</integer></array><key>ScriptArgs</key><array/></dict></plist>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := platypusInvocation([]byte(settings)); ok {
				t.Fatal("hostile or mistyped Platypus argv was accepted")
			}
		})
	}
}

func TestArchivedPlatypusAppRejectsUnprovenOrDecoyScript(t *testing.T) {
	spoofedSettings := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Description</key><string>Platypus InterpreterPath /bin/sh</string></dict></plist>`
	tests := []struct {
		name    string
		entries map[string][]byte
	}{
		{
			name: "missing settings",
			entries: map[string][]byte{
				"Payload/Platypus.app/Contents/Resources/script": []byte("#!/bin/sh\necho no\n"),
			},
		},
		{
			name: "malformed settings",
			entries: map[string][]byte{
				"Payload/Platypus.app/Contents/Resources/AppSettings.plist": []byte("bplist00Platypus-5.3\x00InterpreterPath\x00/bin/sh"),
				"Payload/Platypus.app/Contents/Resources/script":            []byte("#!/bin/sh\necho no\n"),
			},
		},
		{
			name: "spoofed settings text",
			entries: map[string][]byte{
				"Payload/Platypus.app/Contents/Resources/AppSettings.plist": []byte(spoofedSettings),
				"Payload/Platypus.app/Contents/Resources/script":            []byte("#!/bin/sh\necho no\n"),
			},
		},
		{
			name: "interpreter without creator",
			entries: map[string][]byte{
				"Payload/Platypus.app/Contents/Resources/AppSettings.plist": []byte(`<plist><dict><key>ScriptInterpreter</key><string>/bin/sh</string></dict></plist>`),
				"Payload/Platypus.app/Contents/Resources/script":            []byte("#!/bin/sh\necho no\n"),
			},
		},
		{
			name: "creator without interpreter",
			entries: map[string][]byte{
				"Payload/Platypus.app/Contents/Resources/AppSettings.plist": []byte(`<plist><dict><key>Creator</key><string>Platypus-5.3</string></dict></plist>`),
				"Payload/Platypus.app/Contents/Resources/script":            []byte("#!/bin/sh\necho no\n"),
			},
		},
		{
			name: "settings decoy",
			entries: map[string][]byte{
				"Payload/Platypus.app/Contents/Resources/AppSettings.plist.bak": []byte(validPlatypusSettingsPlist),
				"Payload/Platypus.app/Contents/Resources/script":                []byte("#!/bin/sh\necho no\n"),
			},
		},
		{
			name: "script decoy",
			entries: map[string][]byte{
				"Payload/Platypus.app/Contents/Resources/AppSettings.plist": []byte(validPlatypusSettingsPlist),
				"Payload/Platypus.app/Contents/Resources/script.backup":     []byte("#!/bin/sh\necho no\n"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := archivedPlatypusBaseEntries()
			for name, data := range test.entries {
				entries[name] = data
			}
			result := inspectArchiveEntries(t, entries)
			if artifactHasEdgeKind(result.Graph.Edges, "bundle-script") {
				t.Fatalf("unproven Platypus archive created bundle-script: %#v", result.Graph.Edges)
			}
			for _, node := range result.Graph.Nodes {
				if node.PackagingTechnology == "Platypus" {
					t.Fatalf("unproven Platypus archive created packaging attribution: %#v", node)
				}
			}
		})
	}
}

func archivedPlatypusBaseEntries() map[string][]byte {
	return map[string][]byte{
		"Payload/Platypus.app/Contents/Info.plist":   []byte(appInfoPlist("Runner")),
		"Payload/Platypus.app/Contents/MacOS/Runner": []byte("#!/bin/sh\nexit 0\n"),
	}
}

func inspectArchiveEntries(t *testing.T, entries map[string][]byte) Result {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.zip")
	if err := os.WriteFile(path, testZipEntries(t, entries), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
