package extract

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestPythonSourceBuildCreatesConditionalLegacyRoot(t *testing.T) {
	artifacts, contents := pythonSourceBuildFixture()
	graph := behavior.Graph{}
	preparePythonSourceBuild(
		&graph,
		artifacts,
		contents,
		map[string]string{"node-archive": "scope-archive", "node-setup": "scope-setup"},
		map[string]bool{"node-archive": true, "node-setup": true},
	)
	if err := graph.Sort(); err != nil {
		t.Fatal(err)
	}

	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("execution roots = %#v, want one conditional source-build root", graph.ExecutionRoots)
	}
	root := graph.ExecutionRoots[0]
	if root.Kind != "python-source-build" || root.DeclarationNodeID != "node-archive" ||
		root.StartNodeID != "node-setup" || root.StartScopeID != "scope-setup" ||
		root.Name != pythonSourceBuildBackend || root.Interpreter != "python" ||
		len(root.Arguments) != 0 || len(root.EvidenceIDs) != 7 {
		t.Fatalf("unexpected source-build root: %#v", root)
	}
	if len(graph.ArtifactProperties) != 1 {
		t.Fatalf("artifact properties = %#v, want one source-distribution property", graph.ArtifactProperties)
	}
	property := graph.ArtifactProperties[0]
	if property.NodeID != "node-archive" || property.Kind != "python-distribution-format" ||
		property.Value != "source-distribution" || property.Support != behavior.SupportCorroborated ||
		!slices.Equal(property.EvidenceIDs, root.EvidenceIDs) {
		t.Fatalf("unexpected source-distribution property: %#v", property)
	}
	if !pythonSourceBuildCoverageContains(graph, pythonSourceBuildProfile) ||
		!pythonSourceBuildCoverageContains(graph, "conditional source-build entry") ||
		!pythonSourceBuildCoverageContains(graph, "source-vs-wheel/cache selection") ||
		!pythonSourceBuildCoverageContains(graph, "hook order/count/success") ||
		!pythonSourceBuildCoverageContains(graph, "installation") {
		t.Fatalf("conditional activation boundary is incomplete: %#v", graph.Coverage)
	}
}

func TestPythonSourceBuildRecognizesScannerProducedGzipTAR(t *testing.T) {
	var encoded bytes.Buffer
	gzipWriter := gzip.NewWriter(&encoded)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range []struct {
		name string
		data string
	}{
		{name: "sample_pkg-1.2.3/PKG-INFO", data: "Metadata-Version: 2.4\nName: sample-pkg\nVersion: 1.2.3\n"},
		{name: "sample_pkg-1.2.3/setup.py", data: "pass\n"},
	} {
		body := []byte(entry.data)
		if err := tarWriter.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	inspected, err := artifact.InspectBytes("sample_pkg-1.2.3.tar.gz", encoded.Bytes(), artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	graph := behavior.Graph{}
	scopes := addNodeScopes(&graph, inspected.Graph)
	eligibility := executionRootEligibility(inspected.Graph.Nodes)
	preparePythonSourceBuild(&graph, inspected.Graph, inspected.Contents, scopes, eligibility)
	if len(graph.ExecutionRoots) != 1 {
		result := recognizePythonSourceBuild(inspected.Graph.Nodes[0], inspected.Graph.Nodes, inspected.Contents)
		t.Fatalf("scanner-produced sdist roots = %#v; recognition=%#v nodes=%#v contents=%#v coverage=%#v", graph.ExecutionRoots, result, inspected.Graph.Nodes, inspected.Contents, graph.Coverage)
	}
}

func TestPythonSourceBuildRejectsGzipDecodedCPIO(t *testing.T) {
	var cpio []byte
	cpio = appendPythonSourceBuildCPIOEntry(cpio, 1, "sample_package-1.2.3/PKG-INFO", []byte("Metadata-Version: 2.4\nName: sample-package\nVersion: 1.2.3\n"))
	cpio = appendPythonSourceBuildCPIOEntry(cpio, 2, "sample_package-1.2.3/setup.py", []byte("pass\n"))
	cpio = appendPythonSourceBuildCPIOEntry(cpio, 3, "TRAILER!!!", nil)
	inspected, err := artifact.InspectBytes(
		"sample_package-1.2.3.tar.gz",
		pythonSourceBuildGzip(t, cpio),
		artifact.Options{},
	)
	if err != nil {
		t.Fatal(err)
	}
	graph := behavior.Graph{}
	scopes := addNodeScopes(&graph, inspected.Graph)
	preparePythonSourceBuild(&graph, inspected.Graph, inspected.Contents, scopes, executionRootEligibility(inspected.Graph.Nodes))
	if len(graph.ExecutionRoots) != 0 || len(graph.ArtifactProperties) != 0 {
		t.Fatalf("gzip-decoded CPIO gained sdist semantics: roots=%#v properties=%#v", graph.ExecutionRoots, graph.ArtifactProperties)
	}
	if !pythonSourceBuildCoverageContains(graph, "gzip-decoded CPIO") {
		t.Fatalf("gzip-decoded CPIO lacks explicit rejection coverage: %#v", graph.Coverage)
	}
}

func TestPythonSourceBuildIgnoresNestedContainerAnalysisState(t *testing.T) {
	nestedSdist := pythonSourceBuildTGZ(t, []pythonSourceBuildTestArchiveEntry{
		{name: "nested_pkg-9.0/PKG-INFO", data: []byte("Metadata-Version: 2.4\nName: nested-pkg\nVersion: 9.0\n")},
		{name: "nested_pkg-9.0/setup.py", data: []byte("pass\n")},
	})
	outer := pythonSourceBuildTGZ(t, []pythonSourceBuildTestArchiveEntry{
		{name: "sample_package-1.2.3/PKG-INFO", data: []byte("Metadata-Version: 2.4\nName: sample-package\nVersion: 1.2.3\n")},
		{name: "sample_package-1.2.3/setup.py", data: []byte("pass\n")},
		{name: "sample_package-1.2.3/vendor/nested_pkg-9.0.tar.gz", data: nestedSdist},
		{name: "sample_package-1.2.3/data/broken.tar.gz", data: []byte{0x1f, 0x8b, 0x08, 0x00, 0xff}},
	})
	inspected, err := artifact.InspectBytes("sample_package-1.2.3.tar.gz", outer, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	nestedPartial := false
	for _, node := range inspected.Graph.Nodes {
		if strings.HasSuffix(node.LogicalPath, "broken.tar.gz") && node.AnalyzeStatus == "partial" {
			nestedPartial = true
		}
	}
	if !nestedPartial {
		t.Fatalf("fixture did not produce the intended unrelated malformed nested archive: %#v", inspected.Graph.Nodes)
	}
	graph := behavior.Graph{}
	scopes := addNodeScopes(&graph, inspected.Graph)
	preparePythonSourceBuild(&graph, inspected.Graph, inspected.Contents, scopes, executionRootEligibility(inspected.Graph.Nodes))
	if len(graph.ExecutionRoots) != 1 || len(graph.ArtifactProperties) != 1 {
		t.Fatalf("nested archive state blocked the exact parent sdist: roots=%#v properties=%#v coverage=%#v", graph.ExecutionRoots, graph.ArtifactProperties, graph.Coverage)
	}
}

func TestPythonSourceBuildEmbeddedAppDoesNotPolluteTAREntryIdentity(t *testing.T) {
	outer := pythonSourceBuildTGZ(t, []pythonSourceBuildTestArchiveEntry{
		{name: "sample_package-1.2.3/PKG-INFO", data: []byte("Metadata-Version: 2.4\nName: sample-package\nVersion: 1.2.3\n")},
		{name: "sample_package-1.2.3/setup.py", data: []byte("pass\n")},
		{name: "sample_package-1.2.3/Payload/Test.app/Contents/Info.plist", data: []byte(`<?xml version="1.0"?><plist><dict><key>CFBundleExecutable</key><string>Test</string></dict></plist>`)},
		{name: "sample_package-1.2.3/Payload/Test.app/Contents/MacOS/Test", data: []byte("#!/bin/sh\nexit 0\n")},
	})
	inspected, err := artifact.InspectBytes("sample_package-1.2.3.tar.gz", outer, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	appSeen := false
	for _, node := range inspected.Graph.Nodes {
		appSeen = appSeen || node.Kind == "app-bundle"
	}
	if !appSeen {
		t.Fatalf("fixture did not create an embedded app structural node: %#v", inspected.Graph.Nodes)
	}
	graph := behavior.Graph{}
	scopes := addNodeScopes(&graph, inspected.Graph)
	preparePythonSourceBuild(&graph, inspected.Graph, inspected.Contents, scopes, executionRootEligibility(inspected.Graph.Nodes))
	if len(graph.ExecutionRoots) != 1 || len(graph.ArtifactProperties) != 1 {
		t.Fatalf("embedded app structure polluted parent TAR entry identity: roots=%#v properties=%#v coverage=%#v", graph.ExecutionRoots, graph.ArtifactProperties, graph.Coverage)
	}
}

func TestPythonSourceBuildDoesNotTreatWheelAsSourceDistribution(t *testing.T) {
	var encoded bytes.Buffer
	writer := zip.NewWriter(&encoded)
	for _, entry := range []struct {
		name string
		data string
	}{
		{name: "sample_package-1.2.3/PKG-INFO", data: "Metadata-Version: 2.4\nName: sample-package\nVersion: 1.2.3\n"},
		{name: "sample_package-1.2.3/setup.py", data: "pass\n"},
	} {
		file, err := writer.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(entry.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	inspected, err := artifact.InspectBytes("sample_package-1.2.3-py3-none-any.whl", encoded.Bytes(), artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	graph := behavior.Graph{}
	scopes := addNodeScopes(&graph, inspected.Graph)
	preparePythonSourceBuild(&graph, inspected.Graph, inspected.Contents, scopes, executionRootEligibility(inspected.Graph.Nodes))
	if len(graph.ExecutionRoots) != 0 || len(graph.ArtifactProperties) != 0 {
		t.Fatalf("wheel gained source-build semantics: roots=%#v properties=%#v", graph.ExecutionRoots, graph.ArtifactProperties)
	}
}

func TestPythonSourceBuildFailsClosedOnUnsupportedOrAmbiguousEnvelope(t *testing.T) {
	tests := map[string]struct {
		mutate      func(*artifact.Graph, *[]artifact.Content)
		disposition pythonSourceBuildDisposition
		reason      string
	}{
		"root pyproject": {
			mutate: func(graph *artifact.Graph, contents *[]artifact.Content) {
				pythonSourceBuildAddMember(graph, contents, "node-pyproject", "pyproject.toml", []byte("[build-system]\n"), "text")
			},
			disposition: pythonSourceBuildUnsupported,
			reason:      "requires backend selection outside profile",
		},
		"duplicate setup": {
			mutate: func(graph *artifact.Graph, contents *[]artifact.Content) {
				pythonSourceBuildAddMember(graph, contents, "node-setup-copy", "setup.py", []byte("pass\n"), "script")
			},
			disposition: pythonSourceBuildMalformed,
			reason:      "duplicate normalized member path",
		},
		"case variant marker": {
			mutate: func(graph *artifact.Graph, contents *[]artifact.Content) {
				pythonSourceBuildAddMember(graph, contents, "node-pyproject", "PyProject.toml", []byte("[build-system]\n"), "text")
			},
			disposition: pythonSourceBuildMalformed,
			reason:      "case-variant top-level Python distribution marker",
		},
		"case fold path collision": {
			mutate: func(graph *artifact.Graph, contents *[]artifact.Content) {
				pythonSourceBuildAddMember(graph, contents, "node-readme-copy", "readme.md", []byte("second\n"), "text")
			},
			disposition: pythonSourceBuildMalformed,
			reason:      "ASCII case-fold-colliding member paths",
		},
		"metadata identity mismatch": {
			mutate: func(_ *artifact.Graph, contents *[]artifact.Content) {
				for index := range *contents {
					if (*contents)[index].NodeID == "node-pkg-info" {
						(*contents)[index].Data = []byte("Metadata-Version: 2.1\nName: Other\nVersion: 1.2.3\n\n")
					}
				}
			},
			disposition: pythonSourceBuildMalformed,
			reason:      "do not agree exactly",
		},
		"incomplete archive": {
			mutate: func(graph *artifact.Graph, _ *[]artifact.Content) {
				graph.Nodes[0].AnalyzeStatus = "partial"
				graph.Nodes[0].CoverageDetail = "fixture entry limit"
			},
			disposition: pythonSourceBuildMalformed,
			reason:      "inventory was incomplete",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			artifacts, contents := pythonSourceBuildFixture()
			test.mutate(&artifacts, &contents)
			result := recognizePythonSourceBuild(artifacts.Nodes[0], artifacts.Nodes, contents)
			if result.disposition != test.disposition || !strings.Contains(result.reason, test.reason) {
				t.Fatalf("result = %#v, want disposition %d and reason containing %q", result, test.disposition, test.reason)
			}

			graph := behavior.Graph{}
			preparePythonSourceBuild(
				&graph,
				artifacts,
				contents,
				map[string]string{"node-setup": "scope-setup"},
				map[string]bool{"node-archive": true, "node-setup": true},
			)
			if len(graph.ExecutionRoots) != 0 || len(graph.ArtifactProperties) != 0 {
				t.Fatalf("unsupported or malformed envelope gained semantics: roots=%#v properties=%#v", graph.ExecutionRoots, graph.ArtifactProperties)
			}
			if !pythonSourceBuildCoverageContains(graph, test.reason) {
				t.Fatalf("failure lacks stable partial coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestPythonSourceBuildStrictMetadataBounds(t *testing.T) {
	tests := map[string]struct {
		data        []byte
		disposition pythonSourceBuildDisposition
		reason      string
	}{
		"duplicate name": {
			data:        []byte("Metadata-Version: 2.1\nName: Sample-Package\nName: Other\nVersion: 1.2.3\n\n"),
			disposition: pythonSourceBuildMalformed,
			reason:      "duplicate identity headers",
		},
		"folded header": {
			data:        []byte("Metadata-Version: 2.1\nName: Sample-Package\n continuation\nVersion: 1.2.3\n\n"),
			disposition: pythonSourceBuildUnsupported,
			reason:      "folded PKG-INFO headers",
		},
		"oversized line": {
			data:        []byte("Summary: " + strings.Repeat("x", maxPythonSourceBuildHeaderLine+1) + "\n"),
			disposition: pythonSourceBuildUnsupported,
			reason:      "header line exceeds",
		},
		"invalid utf8": {
			data:        append([]byte("Metadata-Version: 2.1\nName: Sample"), 0xff),
			disposition: pythonSourceBuildMalformed,
			reason:      "empty, malformed",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, disposition, reason := parsePythonSourceBuildMetadata(test.data)
			if disposition != test.disposition || !strings.Contains(reason, test.reason) {
				t.Fatalf("metadata result = (%d, %q), want (%d, contains %q)", disposition, reason, test.disposition, test.reason)
			}
		})
	}
}

func TestPythonSourceBuildVersionSubsetIsCanonicalAndCovered(t *testing.T) {
	for _, valid := range []string{"0", "1", "1.0", "2026.7.26", strings.Repeat("9", maxPythonSourceBuildVersionPart)} {
		if !supportedPythonSourceBuildVersion(valid) {
			t.Fatalf("canonical final release %q was rejected", valid)
		}
	}
	invalid := []string{
		"01.2",
		"1.",
		"1..2",
		"1!2.3",
		"1.0rc1",
		"1.0.post1",
		"1.0.dev1",
		"1.0+local",
		"1_0",
		strings.Repeat("9", maxPythonSourceBuildVersionPart+1),
		strings.Repeat("1.", maxPythonSourceBuildVersionParts) + "1",
	}
	for _, version := range invalid {
		t.Run(version, func(t *testing.T) {
			if supportedPythonSourceBuildVersion(version) {
				t.Fatalf("non-canonical or unsupported version %q was accepted", version)
			}
			artifacts, contents := pythonSourceBuildFixture()
			for index := range contents {
				if contents[index].NodeID == "node-pkg-info" {
					contents[index].Data = []byte("Metadata-Version: 2.4\nName: Sample-Package\nVersion: " + version + "\n")
				}
			}
			graph := behavior.Graph{}
			preparePythonSourceBuild(
				&graph,
				artifacts,
				contents,
				map[string]string{"node-archive": "scope-archive", "node-setup": "scope-setup"},
				map[string]bool{"node-archive": true, "node-setup": true},
			)
			if len(graph.ExecutionRoots) != 0 || len(graph.ArtifactProperties) != 0 {
				t.Fatalf("unsupported version gained sdist semantics: roots=%#v properties=%#v", graph.ExecutionRoots, graph.ArtifactProperties)
			}
			if !pythonSourceBuildCoverageContains(graph, "Version requires normalization outside the closed") {
				t.Fatalf("unsupported version candidate disappeared without coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestPythonSourceBuildMetadataEvidenceOffsetsPointToValues(t *testing.T) {
	data := []byte("Metadata-Version:\t 2.4 \r\nName:   Sample-Package\t\r\nVersion:\t1.2.3 \r\n\r\n")
	metadata, disposition, reason := parsePythonSourceBuildMetadata(data)
	if disposition != pythonSourceBuildRecognized || reason != "" {
		t.Fatalf("metadata parse = (%#v, %d, %q)", metadata, disposition, reason)
	}
	for name, header := range map[string]pythonSourceBuildHeader{
		"metadata version": metadata.metadataVersion,
		"name":             metadata.name,
		"version":          metadata.version,
	} {
		end := header.offset + len(header.value)
		if header.offset < 0 || end > len(data) || string(data[header.offset:end]) != header.value {
			t.Fatalf("%s evidence offset %d does not point to first matched byte of %q in %q", name, header.offset, header.value, data)
		}
	}

	artifacts, contents := pythonSourceBuildFixture()
	for index := range contents {
		if contents[index].NodeID == "node-pkg-info" {
			contents[index].Data = data
		}
	}
	graph := behavior.Graph{}
	preparePythonSourceBuild(
		&graph,
		artifacts,
		contents,
		map[string]string{"node-archive": "scope-archive", "node-setup": "scope-setup"},
		map[string]bool{"node-archive": true, "node-setup": true},
	)
	content := data
	found := 0
	for _, evidence := range graph.Evidence {
		if evidence.NodeID != "node-pkg-info" {
			continue
		}
		end := int(evidence.Offset) + len(evidence.Value)
		if !evidence.OffsetKnown || evidence.Offset < 0 || end > len(content) ||
			string(content[evidence.Offset:int64(end)]) != evidence.Value {
			t.Fatalf("located metadata evidence does not point at its exact value: %#v", evidence)
		}
		found++
	}
	if found != 3 {
		t.Fatalf("located PKG-INFO evidence count = %d, want 3: %#v", found, graph.Evidence)
	}
}

func TestPythonSourceBuildMemberLimitIsBounded(t *testing.T) {
	artifacts, contents := pythonSourceBuildFixture()
	for index := len(artifacts.Nodes) - 1; index < artifact.MaxArchiveEntries+1; index++ {
		pythonSourceBuildAddMember(
			&artifacts,
			&contents,
			fmt.Sprintf("node-extra-%04d", index),
			fmt.Sprintf("data/%04d.txt", index),
			[]byte("x"),
			"text",
		)
	}
	result := recognizePythonSourceBuild(artifacts.Nodes[0], artifacts.Nodes, contents)
	if result.disposition != pythonSourceBuildUnsupported ||
		!strings.Contains(result.reason, fmt.Sprintf("member limit %d reached", artifact.MaxArchiveEntries)) {
		t.Fatalf("hostile member count did not fail at the stable bound: %#v", result)
	}
}

func TestPythonSourceBuildIsDeterministicAcrossMemberOrder(t *testing.T) {
	firstArtifacts, firstContents := pythonSourceBuildFixture()
	secondArtifacts := artifact.Graph{Nodes: slices.Clone(firstArtifacts.Nodes)}
	secondContents := slices.Clone(firstContents)
	slices.Reverse(secondArtifacts.Nodes)
	slices.Reverse(secondContents)

	run := func(artifacts artifact.Graph, contents []artifact.Content) []byte {
		graph := behavior.Graph{}
		preparePythonSourceBuild(
			&graph,
			artifacts,
			contents,
			map[string]string{"node-archive": "scope-archive", "node-setup": "scope-setup"},
			map[string]bool{"node-archive": true, "node-setup": true},
		)
		if err := graph.Sort(); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(graph)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	first := run(firstArtifacts, firstContents)
	second := run(secondArtifacts, secondContents)
	if string(first) != string(second) {
		t.Fatalf("source-build result depends on member order:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestPythonSourceBuildRequiresRootEligibleExactScope(t *testing.T) {
	artifacts, contents := pythonSourceBuildFixture()
	for name, scopes := range map[string]map[string]string{
		"missing setup scope": {"node-archive": "scope-archive"},
		"missing topology eligibility": {
			"node-archive": "scope-archive",
			"node-setup":   "scope-setup",
		},
	} {
		t.Run(name, func(t *testing.T) {
			eligibility := map[string]bool{"node-archive": true, "node-setup": true}
			if name == "missing topology eligibility" {
				eligibility["node-setup"] = false
			}
			graph := behavior.Graph{}
			preparePythonSourceBuild(&graph, artifacts, contents, scopes, eligibility)
			if len(graph.ExecutionRoots) != 0 || len(graph.ArtifactProperties) != 1 {
				t.Fatalf("ineligible source-build entry gained semantics: roots=%#v properties=%#v", graph.ExecutionRoots, graph.ArtifactProperties)
			}
			if !pythonSourceBuildCoverageContains(graph, "does not permit an independent source-build execution root") {
				t.Fatalf("ineligible topology lacks explicit coverage: %#v", graph.Coverage)
			}
		})
	}
}

func pythonSourceBuildFixture() (artifact.Graph, []artifact.Content) {
	archiveLogical := "sample_package-1.2.3.tar.gz"
	nodes := []artifact.Node{{
		ID:            "node-archive",
		LogicalPath:   archiveLogical,
		Kind:          "gzip",
		MediaType:     "application/gzip",
		AnalyzeStatus: "analyzed",
	}}
	contents := []artifact.Content{{
		NodeID:      "node-archive",
		LogicalPath: archiveLogical,
		Kind:        "gzip",
		MediaType:   "application/gzip",
		Data:        []byte{0x1f, 0x8b, 0x08, 0x00},
		Role:        "target",
	}}
	graph := artifact.Graph{Nodes: nodes}
	pythonSourceBuildAddMember(
		&graph,
		&contents,
		"node-pkg-info",
		"PKG-INFO",
		[]byte("Metadata-Version: 2.1\nName: Sample-Package\nVersion: 1.2.3\nSummary: fixture\n\nbody\n"),
		"text",
	)
	pythonSourceBuildAddMember(&graph, &contents, "node-setup", "setup.py", []byte("print('fixture')\n"), "script")
	pythonSourceBuildAddMember(&graph, &contents, "node-readme", "README.md", []byte("fixture\n"), "text")
	return graph, contents
}

func pythonSourceBuildAddMember(graph *artifact.Graph, contents *[]artifact.Content, id, relative string, data []byte, kind string) {
	if id == "" {
		return
	}
	logical := "sample_package-1.2.3.tar.gz!sample_package-1.2.3/" + relative
	graph.Nodes = append(graph.Nodes, artifact.Node{
		ID:            id,
		ParentID:      "node-archive",
		LogicalPath:   logical,
		Kind:          kind,
		MediaType:     "text/plain",
		SourceRole:    "runtime",
		Provenance:    "tar-entry",
		AnalyzeStatus: "analyzed",
	})
	*contents = append(*contents, artifact.Content{
		NodeID:      id,
		LogicalPath: logical,
		Kind:        kind,
		MediaType:   "text/plain",
		Data:        data,
		Role:        "runtime",
	})
}

func pythonSourceBuildCoverageContains(graph behavior.Graph, fragment string) bool {
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == pythonSourceBuildAnalysisArea &&
			coverage.Status == "partial" && strings.Contains(coverage.Detail, fragment) {
			return true
		}
	}
	return false
}

type pythonSourceBuildTestArchiveEntry struct {
	name string
	data []byte
}

func pythonSourceBuildTGZ(t *testing.T, entries []pythonSourceBuildTestArchiveEntry) []byte {
	t.Helper()
	var encoded bytes.Buffer
	gzipWriter := gzip.NewWriter(&encoded)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		if err := tarWriter.WriteHeader(&tar.Header{
			Name: entry.name,
			Mode: 0o755,
			Size: int64(len(entry.data)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func pythonSourceBuildGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func appendPythonSourceBuildCPIOEntry(out []byte, inode uint64, name string, data []byte) []byte {
	header := fmt.Sprintf(
		"070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		inode,
		uint64(0o100755),
		0,
		0,
		1,
		0,
		len(data),
		0,
		0,
		0,
		0,
		len(name)+1,
		0,
	)
	out = append(out, header...)
	out = append(out, name...)
	out = append(out, 0)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	out = append(out, data...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}
