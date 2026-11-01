package artifact

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDirectoryEntryFloodIsBoundedAndMarksPartial(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 12; i++ {
		name := filepath.Join(root, fmt.Sprintf("file-%02d.sh", i))
		if err := os.WriteFile(name, []byte("echo bounded\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	result, err := InspectPath(root, Options{MaxArtifactNodes: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Graph.Nodes) != 5 {
		t.Fatalf("directory flood produced %d nodes, want hard limit 5", len(result.Graph.Nodes))
	}
	rootNode := artifactNodeByLogical(result.Graph.Nodes, filepath.Base(root))
	if rootNode == nil || rootNode.AnalyzeStatus != "partial" {
		t.Fatalf("bounded directory root should be partial: %#v", rootNode)
	}
	if !strings.Contains(rootNode.CoverageDetail, "filesystem traversal entry/node limit 5 reached") {
		t.Fatalf("partial root should explain bounded traversal: %#v", rootNode)
	}
	if !strings.Contains(strings.Join(result.Diagnostics, "\n"), "remaining directory entries not inspected") {
		t.Fatalf("missing traversal limit diagnostic: %#v", result.Diagnostics)
	}
}

func TestDirectoryTraversalExactBudgetIsComplete(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 4; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("file-%d.sh", i)), []byte("echo complete\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	result, err := InspectPath(root, Options{MaxArtifactNodes: 5})
	if err != nil {
		t.Fatal(err)
	}
	rootNode := artifactNodeByLogical(result.Graph.Nodes, filepath.Base(root))
	if rootNode == nil || rootNode.AnalyzeStatus != "analyzed" {
		t.Fatalf("exact traversal budget should not be marked partial: %#v", rootNode)
	}
}

func TestAppTraversalFloodIsBoundedAndMarksPartial(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Flood.app")
	contents := filepath.Join(root, "Contents")
	if err := os.MkdirAll(contents, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contents, "Info.plist"), []byte(appInfoPlist("Flood")), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		name := filepath.Join(contents, fmt.Sprintf("script-%02d.scpt", i))
		if err := os.WriteFile(name, []byte(`display dialog "bounded"`), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	result, err := InspectPath(root, Options{MaxArtifactNodes: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Graph.Nodes) > 5 {
		t.Fatalf("app traversal flood exceeded node limit: %#v", result.Graph.Nodes)
	}
	app := artifactNodeByLogical(result.Graph.Nodes, "Flood.app")
	if app == nil || app.AnalyzeStatus != "partial" {
		t.Fatalf("bounded app root should be partial: %#v", app)
	}
	if !strings.Contains(strings.Join(result.Diagnostics, "\n"), "filesystem traversal entry/node limit 5 reached") {
		t.Fatalf("missing app traversal limit diagnostic: %#v", result.Diagnostics)
	}
}

func TestOversizedArchiveNamesDoNotAmplifyDiagnostics(t *testing.T) {
	entries := make(map[string][]byte)
	for i := 0; i < 12; i++ {
		name := strings.Repeat("x", MaxArchiveNameBytes+1) + fmt.Sprintf("-%02d", i)
		entries[name] = nil
	}
	path := filepath.Join(t.TempDir(), "oversized.zip")
	if err := os.WriteFile(path, testZipEntries(t, entries), 0o600); err != nil {
		t.Fatal(err)
	}
	options := Options{MaxDiagnostics: 4, MaxDiagnosticBytes: 512}
	first, err := InspectPath(path, options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectPath(path, options)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(first.Diagnostics, "\x00") != strings.Join(second.Diagnostics, "\x00") {
		t.Fatalf("bounded diagnostics are not deterministic: first=%#v second=%#v", first.Diagnostics, second.Diagnostics)
	}
	if len(first.Diagnostics) > options.MaxDiagnostics {
		t.Fatalf("diagnostic count exceeded limit: %#v", first.Diagnostics)
	}
	var totalBytes int64
	summaryCount := 0
	for _, diagnostic := range first.Diagnostics {
		totalBytes += int64(len(diagnostic))
		if strings.HasPrefix(diagnostic, diagnosticSummaryPrefix) {
			summaryCount++
		}
	}
	if totalBytes > options.MaxDiagnosticBytes {
		t.Fatalf("diagnostic bytes = %d, limit = %d", totalBytes, options.MaxDiagnosticBytes)
	}
	if summaryCount != 1 {
		t.Fatalf("diagnostic budget should produce one summary: %#v", first.Diagnostics)
	}
	joined := strings.Join(first.Diagnostics, "\n")
	if strings.Contains(joined, strings.Repeat("x", 64)) {
		t.Fatalf("oversized archive name leaked into diagnostics: %q", joined)
	}
	if len(first.Graph.Nodes) != 1 {
		t.Fatalf("oversized archive names should not become nodes: %#v", first.Graph.Nodes)
	}
}

func TestDiagnosticBudgetEmitsSingleDeterministicSummary(t *testing.T) {
	messages := make([]string, 10)
	for i := range messages {
		messages[i] = fmt.Sprintf("diagnostic-%02d-%s", i, strings.Repeat("z", 16))
	}
	collect := func() []string {
		s := scanner{options: Options{MaxDiagnostics: 3, MaxDiagnosticBytes: 512}.normalized()}
		for _, message := range messages {
			s.addDiagnostic(message)
		}
		return append([]string(nil), s.diagnostics...)
	}
	first := collect()
	second := collect()
	if strings.Join(first, "\x00") != strings.Join(second, "\x00") {
		t.Fatalf("diagnostic summaries differ: first=%#v second=%#v", first, second)
	}
	if len(first) != 3 || first[0] != messages[0] || first[1] != messages[1] {
		t.Fatalf("collector did not retain deterministic prefix: %#v", first)
	}
	omittedBytes := 0
	for _, message := range messages[2:] {
		omittedBytes += len(message)
	}
	wantSummary := fmt.Sprintf("%s8 messages (%d bytes)", diagnosticSummaryPrefix, omittedBytes)
	if first[2] != wantSummary {
		t.Fatalf("summary = %q, want %q", first[2], wantSummary)
	}
}

func TestClassicEncryptedZIPRespectsInputAndOutputMemoryBudgets(t *testing.T) {
	payload := bytes.Repeat([]byte("payload"), 1024)
	archive := testClassicEncryptedZipFile(t, "payload.bin", payload, "correct", zip.Store)
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	file := reader.File[0]
	if data, err := readClassicEncryptedZipEntry(file, archive, "correct", 16, int64(len(payload))); err == nil || data != nil || !strings.Contains(err.Error(), "encrypted zip input exceeds 16 bytes") {
		t.Fatalf("encrypted input budget was not enforced: data=%d err=%v", len(data), err)
	}
	if data, err := readClassicEncryptedZipEntry(file, archive, "correct", int64(len(archive)), 16); err == nil || data != nil {
		t.Fatalf("encrypted output budget was not enforced: data=%d err=%v", len(data), err)
	} else {
		var limitErr *byteLimitError
		if !errors.As(err, &limitErr) || limitErr.Limit != 16 {
			t.Fatalf("output limit error = %T %v", err, err)
		}
	}
	data, err := readClassicEncryptedZipEntry(file, archive, "correct", int64(len(archive)), int64(len(payload)))
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatalf("bounded encrypted read failed: data=%d err=%v", len(data), err)
	}
}

func TestScanVirtualRetainedBudgetCreatesOneSkippedNode(t *testing.T) {
	s := scanner{options: Options{MaxArtifactNodes: 2, MaxTotalBytes: 1}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "outer.zip", Kind: "zip"})
	childID := s.scanVirtual(parentID, "outer.zip!child.bin", []byte("too large"), false, "zip-entry", 1)
	if childID == "" || len(s.graph.Nodes) != 2 {
		t.Fatalf("retained-budget skip should consume exactly one reserved node: id=%q nodes=%#v", childID, s.graph.Nodes)
	}
	child := artifactNodeByLogical(s.graph.Nodes, "outer.zip!child.bin")
	if child == nil || child.AnalyzeStatus != "skipped" {
		t.Fatalf("retained-budget child should be represented as skipped: %#v", child)
	}
	if strings.Contains(strings.Join(s.diagnostics, "\n"), "artifact node limit") {
		t.Fatalf("skip path reserved the node twice: %#v", s.diagnostics)
	}
}

func TestSafeFileReadRejectsSymlinkSwapAndCapsGrowth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.bin")
	target := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, bytes.Repeat([]byte("target"), 128), 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if file, _, err := openStableRegularFile(path, expected); err == nil {
		_ = file.Close()
		t.Fatal("safe open followed a swapped symlink")
	}

	data, exceeded, err := readAllAtMost(bytes.NewReader(bytes.Repeat([]byte("g"), 4096)), 32)
	if err != nil || !exceeded || len(data) != 33 {
		t.Fatalf("bounded growth read = (%d, %v, %v), want (33, true, nil)", len(data), exceeded, err)
	}
}

func TestHdiutilEnvironmentExcludesZIPPassword(t *testing.T) {
	environment := []string{"HOME=/tmp/home", "MARATUS_ZIP_PASSWORD=super-secret", "PATH=/usr/bin", "MARATUS_ZIP_PASSWORD"}
	filtered := withoutEnvironmentVariable(environment, zipPasswordEnvironmentName)
	joined := strings.Join(filtered, "\n")
	if strings.Contains(joined, zipPasswordEnvironmentName) {
		t.Fatalf("password environment variable survived filtering: %#v", filtered)
	}
	if len(filtered) != 2 || filtered[0] != environment[0] || filtered[1] != environment[2] {
		t.Fatalf("unrelated environment changed: %#v", filtered)
	}
}

func TestDMGAttachKeepsImageVerificationEnabled(t *testing.T) {
	arguments := dmgAttachArguments("image.dmg", "mount-root")
	joined := strings.Join(arguments, " ")
	if strings.Contains(joined, "-noverify") {
		t.Fatalf("DMG attach disables image verification: %#v", arguments)
	}
	for _, required := range []string{"-readonly", "-nobrowse", "-noautoopen", "-mountroot", "-plist"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("DMG attach argument %q missing: %#v", required, arguments)
		}
	}
}

func TestHdiutilOutputAndPlistDecodeAreBounded(t *testing.T) {
	capture := &boundedCommandOutput{maxBytes: 16}
	payload := bytes.Repeat([]byte("o"), 128)
	written, err := capture.Write(payload)
	if err != nil || written != len(payload) {
		t.Fatalf("bounded output write = (%d, %v)", written, err)
	}
	output, exceeded := capture.bytes()
	if !exceeded || len(output) != 16 {
		t.Fatalf("bounded output = (%d, %v), want (16, true)", len(output), exceeded)
	}
	if _, err := dmgAttachments(make([]byte, maxHdiutilOutputBytes+1)); err == nil || !strings.Contains(err.Error(), "hdiutil plist exceeds") {
		t.Fatalf("oversized hdiutil plist error = %v", err)
	}
}

func TestHdiutilDiagnosticOutputPrefersStderr(t *testing.T) {
	stdout := []byte("plist output")
	stderr := []byte("warning output")
	if got := string(hdiutilDiagnosticOutput(stdout, stderr)); got != string(stderr) {
		t.Fatalf("diagnostic output = %q, want stderr", got)
	}
	if got := string(hdiutilDiagnosticOutput(stdout, nil)); got != string(stdout) {
		t.Fatalf("diagnostic fallback = %q, want stdout", got)
	}
}

func TestArchiveAppInfoPlistDecodeIsBounded(t *testing.T) {
	entries := []VirtualEntry{{
		Name:       "Payload/Large.app/Contents/Info.plist",
		Data:       bytes.Repeat([]byte("x"), int(maxAppMetadataBytes)+1),
		Provenance: "zip-entry",
	}}
	bundles := archiveAppBundles(entries)
	if len(bundles) != 1 {
		t.Fatalf("archive app bundle was not identified: %#v", bundles)
	}
	if bundles[0].executable != "" {
		t.Fatalf("oversized archive Info.plist was decoded: %#v", bundles[0])
	}
}

func TestArtifactPathStringBudgetBoundsNodesAndMarksPartial(t *testing.T) {
	s := scanner{options: Options{MaxArtifactNodes: 10, MaxArtifactPathBytes: 40}.normalized()}
	parentID := s.addDirectory("", "root", "", "directory")
	for i := 0; i < 8; i++ {
		name := strings.Repeat("p", 20) + fmt.Sprintf("-%d", i)
		s.addSkippedVirtualEntry(parentID, "root", name, VirtualEntry{
			Name:       name,
			Provenance: "zip-entry",
			SkipDetail: "fixture",
		})
	}
	if len(s.graph.Nodes) != 2 {
		t.Fatalf("path-string budget should retain a deterministic prefix of nodes: %#v", s.graph.Nodes)
	}
	if s.artifactPathBytes > s.options.MaxArtifactPathBytes {
		t.Fatalf("path bytes = %d, limit = %d", s.artifactPathBytes, s.options.MaxArtifactPathBytes)
	}
	parent := artifactNodeByLogical(s.graph.Nodes, "root")
	if parent == nil || parent.AnalyzeStatus != "partial" || !strings.Contains(parent.CoverageDetail, "path-string limit 40 reached") {
		t.Fatalf("parent should record partial path coverage: %#v", parent)
	}
	if !strings.Contains(strings.Join(s.diagnostics, "\n"), "remaining nodes not modeled") {
		t.Fatalf("missing path-string budget diagnostic: %#v", s.diagnostics)
	}
}

func TestArtifactPathBudgetBoundsJSONEscapedBytes(t *testing.T) {
	values := []string{"normal/path", "control\npath", "<script>&", string([]byte{'x', 0xff, 'y'}), "line\u2028separator"}
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		want := int64(len(encoded) - 2)
		// Go 1.27 encodes replacement runes as UTF-8 rather than \ufffd.
		// The resource budget may overestimate, but must never undercount.
		if got := jsonEscapedStringBytes(value); got < want {
			t.Fatalf("jsonEscapedStringBytes(%q) = %d, below encoded size %d (%s)", value, got, want, encoded)
		}
	}

	s := scanner{options: Options{MaxArtifactNodes: 2, MaxArtifactPathBytes: 3}.normalized()}
	if s.reserveNode("a\nb", "", "") {
		t.Fatal("JSON-escaped path exceeding three bytes should not be admitted")
	}
}

func TestDirectoryTraversalRejectsSymlinkSwap(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "child")
	moved := filepath.Join(base, "moved")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(directory, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, directory); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	s := scanner{options: Options{}.normalized()}
	entries, _, err := s.readTraversalDirectory(directory, expected)
	if err == nil || len(entries) != 0 {
		t.Fatalf("swapped directory symlink was traversed: entries=%#v err=%v", entries, err)
	}
}

func TestZIPPreflightRejectsCentralDirectoryEntryFlood(t *testing.T) {
	data := testZIPCentralDirectoryFlood(t, maxZIPCentralDirectoryRecords+1, 1)
	// A forged small directory size triggers archive/zip's base-offset
	// compatibility path; preflight must still count every header NewReader sees.
	eocdOffset := len(data) - zipDirectoryEndLength
	binary.LittleEndian.PutUint32(data[eocdOffset+12:eocdOffset+16], zipDirectoryHeaderLength)
	err := preflightZIPDirectory(data)
	if err == nil || !strings.Contains(err.Error(), "central directory record safety limit 65536 exceeded") {
		t.Fatalf("entry-flood preflight error = %v", err)
	}
}

func TestZIPPreflightRejectsZIP64DeclaredEntryFlood(t *testing.T) {
	data := testZIP64WithDeclaredRecords(t, maxZIPCentralDirectoryRecords+1)
	err := preflightZIPDirectory(data)
	if err == nil || !strings.Contains(err.Error(), "central directory record safety limit 65536 exceeded by declared count 65537") {
		t.Fatalf("ZIP64 entry-flood preflight error = %v", err)
	}
}

func TestZIPPreflightAllowsMoreEntriesThanProcessingLimit(t *testing.T) {
	records := MaxArchiveEntries + 1
	data := testZIPCentralDirectoryFlood(t, records, uint16(records))
	if err := preflightZIPDirectory(data); err != nil {
		t.Fatalf("bounded central directory above processing limit should be accepted: %v", err)
	}
}

func TestZIPPreflightRejectsOversizedCentralDirectory(t *testing.T) {
	var out bytes.Buffer
	writeTestZIPEOCD(t, &out, 0, uint32(maxZIPCentralDirectoryBytes+1), 0)
	err := preflightZIPDirectory(out.Bytes())
	if err == nil || !strings.Contains(err.Error(), "central directory exceeds maximum size") {
		t.Fatalf("central-directory size preflight error = %v", err)
	}
}

func TestZIPPreflightRejectsAppendedFakeEmptyDirectory(t *testing.T) {
	data := testZipFile(t, "payload.txt", []byte("not empty"))
	var fake bytes.Buffer
	writeTestZIPEOCD(t, &fake, 0, 0, 0)
	data = append(data, fake.Bytes()...)

	err := preflightZIPDirectory(data)
	if err == nil || !strings.Contains(err.Error(), "multiple valid end-of-central-directory records") {
		t.Fatalf("appended fake EOCD preflight error = %v", err)
	}
}

func TestZIPPreflightRejectsConcatenatedNonemptyArchives(t *testing.T) {
	first := testZipFile(t, "hidden.txt", []byte("first archive"))
	second := testZipFile(t, "visible.txt", []byte("second archive"))
	data := append(append([]byte(nil), first...), second...)

	err := preflightZIPDirectory(data)
	if err == nil || !strings.Contains(err.Error(), "multiple valid end-of-central-directory records") {
		t.Fatalf("concatenated nonempty ZIP preflight error = %v", err)
	}
}

func TestZIPPreflightRejectsConcatenationBeforeLargeTrailingArchive(t *testing.T) {
	first := testZipFile(t, "hidden.txt", []byte("first archive"))
	second := testZipFile(t, "large.bin", bytes.Repeat([]byte("x"), 80<<10))
	data := append(append([]byte(nil), first...), second...)

	err := preflightZIPDirectory(data)
	if err == nil || !strings.Contains(err.Error(), "multiple valid end-of-central-directory records") {
		t.Fatalf("large trailing ZIP concatenation preflight error = %v", err)
	}
}

func TestZIPPreflightRejectsConcatenationSeparatedByPadding(t *testing.T) {
	first := testZipFile(t, "hidden.txt", []byte("first archive"))
	second := testZipFile(t, "visible.txt", []byte("second archive"))
	data := append(append([]byte(nil), first...), bytes.Repeat([]byte{0x90}, 80<<10)...)
	data = append(data, second...)

	err := preflightZIPDirectory(data)
	if err == nil || !strings.Contains(err.Error(), "multiple valid end-of-central-directory records") {
		t.Fatalf("padded ZIP concatenation preflight error = %v", err)
	}
}

func TestZIPPreflightAllowsStoredNestedArchive(t *testing.T) {
	inner := testZipFile(t, "payload.txt", []byte("nested payload"))
	outer := testZipFile(t, "inner.zip", inner)
	if err := preflightZIPDirectory(outer); err != nil {
		t.Fatalf("stored nested ZIP should not be confused with concatenation: %v", err)
	}
}

func TestZIPPreflightAllowsSelfExtractingPrefix(t *testing.T) {
	archive := testZipFile(t, "payload.txt", []byte("payload"))
	data := append([]byte("#!/bin/sh\nexit 0\n"), archive...)
	if err := preflightZIPDirectory(data); err != nil {
		t.Fatalf("self-extracting ZIP prefix should remain supported: %v", err)
	}
}

func TestZIPPreflightBoundsFalseEOCDCandidatesInPrefix(t *testing.T) {
	record := make([]byte, zipDirectoryEndLength)
	binary.LittleEndian.PutUint32(record[:4], zipDirectoryEndSignature)
	binary.LittleEndian.PutUint16(record[4:6], 1) // invalid non-zero disk
	prefix := bytes.Repeat(record, maxZIPEarlierEOCDCandidates+1)
	data := append(prefix, testZipFile(t, "payload.txt", []byte("payload"))...)

	err := preflightZIPDirectory(data)
	if err == nil || !strings.Contains(err.Error(), "EOCD candidate validation limit") {
		t.Fatalf("false EOCD candidate limit error = %v", err)
	}
}

func TestZIPPreflightRejectsTrailingData(t *testing.T) {
	data := append(testZipFile(t, "payload.txt", []byte("data")), []byte("trailing-data")...)
	err := preflightZIPDirectory(data)
	if err == nil || !strings.Contains(err.Error(), "end of central directory not found") {
		t.Fatalf("trailing-data preflight error = %v", err)
	}
}

func testZIPCentralDirectoryFlood(t *testing.T, actual int, declared uint16) []byte {
	t.Helper()
	var out bytes.Buffer
	for i := 0; i < actual; i++ {
		writeZipCentralHeader(&out, nil, zip.Store, 0, 0, 0)
	}
	writeTestZIPEOCD(t, &out, declared, uint32(actual*zipDirectoryHeaderLength), 0)
	return out.Bytes()
}

func testZIP64WithDeclaredRecords(t *testing.T, records uint64) []byte {
	t.Helper()
	var out bytes.Buffer
	writeBinary := func(value any) {
		if err := binary.Write(&out, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	writeBinary(uint32(zipDirectory64EndSignature))
	writeBinary(uint64(44))
	writeBinary(uint16(45))
	writeBinary(uint16(45))
	writeBinary(uint32(0))
	writeBinary(uint32(0))
	writeBinary(records)
	writeBinary(records)
	writeBinary(uint64(0))
	writeBinary(uint64(0))
	writeBinary(uint32(zipDirectory64LocatorSignature))
	writeBinary(uint32(0))
	writeBinary(uint64(0))
	writeBinary(uint32(1))
	writeBinary(uint32(zipDirectoryEndSignature))
	writeBinary(uint16(0))
	writeBinary(uint16(0))
	writeBinary(uint16(0xffff))
	writeBinary(uint16(0xffff))
	writeBinary(uint32(0xffffffff))
	writeBinary(uint32(0xffffffff))
	writeBinary(uint16(0))
	return out.Bytes()
}

func writeTestZIPEOCD(t *testing.T, out *bytes.Buffer, records uint16, directorySize, directoryOffset uint32) {
	t.Helper()
	for _, value := range []any{
		uint32(zipDirectoryEndSignature),
		uint16(0),
		uint16(0),
		records,
		records,
		directorySize,
		directoryOffset,
		uint16(0),
	} {
		if err := binary.Write(out, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVirtualArchiveLinksHonorArtifactNodeLimit(t *testing.T) {
	s := scanner{options: Options{MaxArtifactNodes: 2}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.tar", Kind: "tar"})
	s.addVirtualEntries(parentID, "sample.tar", []VirtualEntry{
		{Name: "first", Symlink: true},
		{Name: "second", Hardlink: true},
	}, 1)

	if len(s.graph.Nodes) != 2 {
		t.Fatalf("artifact node limit was bypassed by archive links: %#v", s.graph.Nodes)
	}
	if artifactNodeByLogical(s.graph.Nodes, "sample.tar!second") != nil {
		t.Fatalf("hard link beyond artifact node limit should not be added: %#v", s.graph.Nodes)
	}
	if !strings.Contains(strings.Join(s.diagnostics, "\n"), "artifact node limit 2 reached") {
		t.Fatalf("missing artifact node limit diagnostic: %#v", s.diagnostics)
	}
}

func TestAppBundleIncludesSCPTSource(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Example.app")
	resources := filepath.Join(root, "Contents", "Resources")
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	info := []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>example.test</string></dict></plist>`)
	if err := os.WriteFile(filepath.Join(root, "Contents", "Info.plist"), info, 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(resources, "prompt.scpt")
	if err := os.WriteFile(script, []byte(`display dialog "Password:" default answer "" with hidden answer`), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	logical := "Example.app/Contents/Resources/prompt.scpt"
	content := contentByLogical(result.Contents, logical)
	if content == nil || content.Kind != "script" {
		t.Fatalf("app-contained .scpt source was not inspected as a script: %#v", result.Contents)
	}
}

func TestAppBundleTraversalFailureIsReported(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Missing.app")
	s := scanner{options: Options{}.normalized()}
	s.scanAppBundle(root, "Missing.app", "")
	if !strings.Contains(strings.Join(s.diagnostics, "\n"), "Missing.app/Contents: app traversal failed") {
		t.Fatalf("app traversal error was swallowed: %#v", s.diagnostics)
	}
}

func TestParseXAREnforcesCompressionRatioDuringDecode(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 4096)
	data := testGzipXARWithoutDeclaredSize(t, payload)
	files, diagnostics, err := parseXAR(data, Options{
		MaxFileBytes:        8192,
		MaxArchiveBytes:     8192,
		MaxCompressionRatio: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("entry over compression ratio limit was extracted: %#v", files)
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "compression ratio limit 2") {
		t.Fatalf("missing compression ratio diagnostic: %#v", diagnostics)
	}
}

func TestParseXAREnforcesRemainingInspectionBudgetDuringDecode(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 4096)
	data := testGzipXARWithoutDeclaredSize(t, payload)
	files, diagnostics, err := parseXARWithBudget(data, Options{
		MaxFileBytes:        8192,
		MaxArchiveBytes:     8192,
		MaxExpandedBytes:    512,
		MaxCompressionRatio: 10000,
	}, 128)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("entry over remaining inspection budget was extracted: %#v", files)
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "inspection expanded-byte limit 512") {
		t.Fatalf("missing remaining-budget diagnostic: %#v", diagnostics)
	}
}

func TestDMGMountPointsAreConstrainedToPrivateRoot(t *testing.T) {
	mountRoot := filepath.Join(t.TempDir(), "mount")
	inside := filepath.Join(mountRoot, "Volume")
	outside := filepath.Join(filepath.Dir(mountRoot), "outside")
	valid, rejected := dmgMountPointsWithinRoot([]dmgAttachment{
		{MountPoint: inside},
		{MountPoint: outside},
	}, mountRoot)
	if len(valid) != 1 || valid[0] != inside {
		t.Fatalf("valid private mount point was not retained: %#v", valid)
	}
	if len(rejected) != 1 || rejected[0] != outside {
		t.Fatalf("outside mount point was not rejected: %#v", rejected)
	}
}

func TestDMGMountPointAllowsResolvedPrivateRootSpelling(t *testing.T) {
	realRoot := filepath.Join(t.TempDir(), "real-mount")
	volume := filepath.Join(realRoot, "Volume")
	if err := os.MkdirAll(volume, 0o700); err != nil {
		t.Fatal(err)
	}
	linkRoot := filepath.Join(t.TempDir(), "mount-link")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	valid, rejected := dmgMountPointsWithinRoot([]dmgAttachment{{MountPoint: volume}}, linkRoot)
	if len(valid) != 1 || valid[0] != volume || len(rejected) != 0 {
		t.Fatalf("resolved mount-root spelling should be accepted: valid=%#v rejected=%#v", valid, rejected)
	}
}

func TestDMGMountPointRejectsIntermediateSymlinkEscape(t *testing.T) {
	mountRoot := filepath.Join(t.TempDir(), "mount")
	if err := os.Mkdir(mountRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside-volume")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(mountRoot, "Volume")
	if err := os.Symlink(outside, escape); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	valid, rejected := dmgMountPointsWithinRoot([]dmgAttachment{{MountPoint: escape}}, mountRoot)
	if len(valid) != 0 || len(rejected) != 1 || rejected[0] != escape {
		t.Fatalf("symlink escape accepted: valid=%#v rejected=%#v", valid, rejected)
	}
}

func TestDMGCleanupDiscoversMountWhenAttachOutputCannotBeParsed(t *testing.T) {
	mountRoot := t.TempDir()
	mount := filepath.Join(mountRoot, "Volume")
	if err := os.Mkdir(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	targets, err := dmgCleanupTargets(nil, mountRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != mount {
		t.Fatalf("cleanup did not discover mounted volume without parsed attachments: %#v", targets)
	}
}

func TestDMGCleanupDoesNotDetachMountOutsidePrivateRoot(t *testing.T) {
	mountRoot := t.TempDir()
	targets, err := dmgCleanupTargets([]dmgAttachment{{
		MountPoint: filepath.Join(filepath.Dir(mountRoot), "outside"),
		Device:     "/dev/disk9",
	}}, mountRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != "/dev/disk9" {
		t.Fatalf("cleanup should fall back to the attached device, got %#v", targets)
	}
}

func TestDMGCleanupUnionsSafeMountsAndRejectedEntityDevices(t *testing.T) {
	mountRoot := t.TempDir()
	inside := filepath.Join(mountRoot, "Volume")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(mountRoot), "outside")
	targets, err := dmgCleanupTargets([]dmgAttachment{
		{MountPoint: inside, Device: "/dev/disk9s1"},
		{MountPoint: outside, Device: "/dev/disk9s2"},
		{Device: "/dev/disk9s3"},
	}, mountRoot)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(targets, "\n")
	for _, want := range []string{inside, "/dev/disk9s2", "/dev/disk9s3"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("cleanup target %q missing from %#v", want, targets)
		}
	}
	if strings.Contains(joined, "/dev/disk9s1") || strings.Contains(joined, outside) {
		t.Fatalf("cleanup included redundant or unsafe target: %#v", targets)
	}
}

func TestDMGCleanupTargetsAreBounded(t *testing.T) {
	attachments := make([]dmgAttachment, 0, maxDMGCleanupTargets+10)
	for i := range maxDMGCleanupTargets + 10 {
		attachments = append(attachments, dmgAttachment{Device: fmt.Sprintf("/dev/disk%04d", i)})
	}
	targets, err := dmgCleanupTargets(attachments, t.TempDir())
	if len(targets) != maxDMGCleanupTargets {
		t.Fatalf("cleanup targets = %d, want %d", len(targets), maxDMGCleanupTargets)
	}
	if err == nil || !strings.Contains(err.Error(), "cleanup target limit") {
		t.Fatalf("cleanup limit error = %v", err)
	}
}

func TestDMGTemporaryCleanupAvoidsUnconfirmedMountTraversal(t *testing.T) {
	temporaryRoot := t.TempDir()
	imagePath := filepath.Join(temporaryRoot, "image.dmg")
	if err := os.WriteFile(imagePath, []byte("hostile image"), 0o600); err != nil {
		t.Fatal(err)
	}
	mountedPath := filepath.Join(temporaryRoot, "mount", "Volume", "nested", "payload")
	if err := os.MkdirAll(filepath.Dir(mountedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mountedPath, []byte("must remain untouched"), 0o600); err != nil {
		t.Fatal(err)
	}

	scanner := scanner{}
	scanner.cleanupDMGTemporary("sample.dmg", temporaryRoot, imagePath, false)
	if _, err := os.Stat(imagePath); !os.IsNotExist(err) {
		t.Fatalf("known temporary image was not removed: %v", err)
	}
	if data, err := os.ReadFile(mountedPath); err != nil || string(data) != "must remain untouched" {
		t.Fatalf("uncertain mount contents were traversed or removed: data=%q err=%v", data, err)
	}
	diagnostics := strings.Join(scanner.diagnostics, "\n")
	if !strings.Contains(diagnostics, "temporary directory retained") {
		t.Fatalf("retained-directory diagnostic missing: %q", diagnostics)
	}
}

func TestDMGTemporaryDirectoryUsesSeparateWorkerParent(t *testing.T) {
	parent := t.TempDir()
	t.Setenv(DMGTemporaryDirectoryEnvironment, parent)
	root, err := newDMGTemporaryDirectory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(root) })
	relative, err := filepath.Rel(parent, root)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("DMG temporary root %q was not created below %q: relative=%q err=%v", root, parent, relative, err)
	}
}

func TestDMGTemporaryDirectoryRejectsNonDirectoryParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parent, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(DMGTemporaryDirectoryEnvironment, parent)
	if _, err := newDMGTemporaryDirectory(); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("non-directory DMG scratch parent error = %v", err)
	}
}

func TestDMGMountRootSafeToRemoveWhenUnmounted(t *testing.T) {
	temporaryRoot := t.TempDir()
	mountRoot := filepath.Join(temporaryRoot, "mount")
	if err := os.MkdirAll(filepath.Join(mountRoot, "Volume"), 0o700); err != nil {
		t.Fatal(err)
	}
	safe, err := dmgMountRootSafeToRemove(mountRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !safe {
		t.Fatal("ordinary unmounted directories should be safe to remove")
	}
}

func TestArchiveSizeComparisonsRemainExactAtUint64Limits(t *testing.T) {
	maximum := ^uint64(0)
	if compressionRatioExceeded(maximum, maximum, 1) {
		t.Fatal("equal maximum sizes must not exceed a 1:1 ratio")
	}
	if !compressionRatioExceeded(maximum, maximum-1, 1) {
		t.Fatal("a ratio just over 1:1 must remain detectable without floating-point rounding")
	}
	if !compressionRatioExceeded(maximum, 1, int64(^uint64(0)>>1)) {
		t.Fatal("maximum uint64 input must exceed the maximum int64 ratio")
	}
	if uint64ExceedsInt64Limit(10, 10) || !uint64ExceedsInt64Limit(11, 10) || !uint64ExceedsInt64Limit(0, -1) {
		t.Fatal("uint64/int64 limit comparison did not preserve exact or invalid-limit boundaries")
	}
}

func testGzipXARWithoutDeclaredSize(t *testing.T, payload []byte) []byte {
	t.Helper()
	encoded := gzipBytes(t, payload)
	toc := `<xar><toc><file id="1"><name>payload</name><type>file</type><data><length>` +
		strconv.Itoa(len(encoded)) +
		`</length><offset>0</offset><encoding style="application/x-gzip"/></data></file></toc></xar>`
	return buildTestXAR(t, toc, encoded)
}
