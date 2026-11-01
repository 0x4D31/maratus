package artifact

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseXARPreflightsFileCollectionBeforeMaterializing(t *testing.T) {
	if testing.Short() {
		t.Skip("large hostile-input regression")
	}
	toc := `<xar><toc>` + strings.Repeat(`<file><name>x</name></file>`, MaxArchiveEntries+1) + `</toc></xar>`
	data := buildTestXAR(t, toc, nil)
	started := time.Now()
	_, _, err := parseXAR(data, Options{})
	if err == nil || !strings.Contains(err.Error(), "archive entry limit") {
		t.Fatalf("parseXAR() error = %v, want entry preflight limit", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("XAR collection preflight took %s", elapsed)
	}
}

func TestParseXARPreflightsNestedFileDepth(t *testing.T) {
	const maxDepth = 4
	toc := `<xar><toc>` + strings.Repeat(`<file><name>x</name>`, maxDepth+1) + strings.Repeat(`</file>`, maxDepth+1) + `</toc></xar>`
	data := buildTestXAR(t, toc, nil)
	_, _, err := parseXAR(data, Options{MaxDirectoryDepth: maxDepth})
	if err == nil || !strings.Contains(err.Error(), "file nesting limit") {
		t.Fatalf("parseXAR() error = %v, want file-depth preflight limit", err)
	}
}

func TestParseXARExtractsFile(t *testing.T) {
	data := buildTestXAR(t, `<xar><toc><file id="1"><name>Scripts</name><type>file</type><data><length>4</length><offset>0</offset><size>4</size></data></file></toc></xar>`, []byte("test"))
	files, diagnostics, err := parseXAR(data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %#v", diagnostics)
	}
	if len(files) != 1 {
		t.Fatalf("files = %d, want 1: %#v", len(files), files)
	}
	if files[0].Name != "Scripts" || string(files[0].Data) != "test" {
		t.Fatalf("unexpected extracted file: %#v", files[0])
	}
}

func TestParseXARAcceptsRichFileMetadataWithinStructuralBudget(t *testing.T) {
	toc := `<xar><toc><file id="1"><name>PackageInfo</name><type>file</type>` +
		`<mode>0644</mode><uid>0</uid><gid>0</gid><user>root</user><group>wheel</group>` +
		`<mtime>2026-01-01T00:00:00Z</mtime><data><length>4</length><offset>0</offset><size>4</size>` +
		`<encoding style="application/octet-stream"/><archived-checksum style="sha1">0000</archived-checksum>` +
		`<extracted-checksum style="sha1">0000</extracted-checksum></data></file></toc></xar>`
	files, diagnostics, err := parseXAR(buildTestXAR(t, toc, []byte("test")), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 0 || len(files) != 1 || files[0].Name != "PackageInfo" || string(files[0].Data) != "test" {
		t.Fatalf("unexpected rich-metadata XAR result: files=%#v diagnostics=%#v", files, diagnostics)
	}
}

func TestParseXARDecodesGzipEncodedMember(t *testing.T) {
	tests := []struct {
		name    string
		encoded []byte
	}{
		{name: "gzip", encoded: gzipBytes(t, []byte("<pkg-info/>"))},
		{name: "zlib", encoded: zlibBytes(t, []byte("<pkg-info/>"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildTestXAR(t, `<xar><toc><file id="1"><name>PackageInfo</name><type>file</type><data><encoding style="application/x-gzip"/><length>`+strconv.Itoa(len(tt.encoded))+`</length><offset>0</offset><size>11</size></data></file></toc></xar>`, tt.encoded)
			files, diagnostics, err := parseXAR(data, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(diagnostics) != 0 {
				t.Fatalf("unexpected diagnostics: %#v", diagnostics)
			}
			if len(files) != 1 || files[0].Name != "PackageInfo" || string(files[0].Data) != "<pkg-info/>" {
				t.Fatalf("unexpected extracted file: %#v", files)
			}
			if files[0].CompressedSize != int64(len(tt.encoded)) {
				t.Fatalf("compressed size not retained: %#v", files[0])
			}
		})
	}
}

func TestParseXARRejectsOversizedTOC(t *testing.T) {
	data := make([]byte, 28)
	copy(data[:4], "xar!")
	binary.BigEndian.PutUint16(data[4:6], 28)
	binary.BigEndian.PutUint16(data[6:8], 1)
	binary.BigEndian.PutUint64(data[16:24], maxXARTOCBytes+1)

	_, _, err := parseXAR(data, Options{})
	if err == nil || !strings.Contains(err.Error(), "TOC exceeds maximum") {
		t.Fatalf("expected oversized TOC error, got %v", err)
	}
}

func TestParseXARRejectsInvalidTOCBounds(t *testing.T) {
	data := make([]byte, 28)
	copy(data[:4], "xar!")
	binary.BigEndian.PutUint16(data[4:6], 28)
	binary.BigEndian.PutUint16(data[6:8], 1)
	binary.BigEndian.PutUint64(data[8:16], 1)

	_, _, err := parseXAR(data, Options{})
	if err == nil || !strings.Contains(err.Error(), "invalid xar TOC bounds") {
		t.Fatalf("expected invalid bounds error, got %v", err)
	}
}

func TestParseXARRejectsUnsafePathBeforeExtraction(t *testing.T) {
	data := buildTestXAR(t, `<xar><toc><file id="1"><name>../evil.sh</name><type>file</type><data><length>4</length><offset>0</offset><size>4</size></data></file></toc></xar>`, []byte("test"))
	files, diagnostics, err := parseXAR(data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("unsafe XAR entry should not be returned: %#v", files)
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "rejected unsafe archive path") {
		t.Fatalf("missing unsafe path diagnostic: %#v", diagnostics)
	}
}

func TestParseXARReportsSkippedMalformedEntries(t *testing.T) {
	tests := []struct {
		name string
		toc  string
		want string
	}{
		{
			name: "invalid-bounds",
			toc:  `<xar><toc><file id="1"><name>Scripts</name><type>file</type><data><length>nope</length><offset>0</offset></data></file></toc></xar>`,
			want: "Scripts: skipped entry with invalid data bounds",
		},
		{
			name: "outside-heap",
			toc:  `<xar><toc><file id="1"><name>Payload</name><type>file</type><data><length>4</length><offset>99</offset><size>4</size></data></file></toc></xar>`,
			want: "Payload: skipped entry outside xar heap bounds",
		},
		{
			name: "invalid-declared-size",
			toc:  `<xar><toc><file id="1"><name>Payload</name><type>file</type><data><length>4</length><offset>0</offset><size>invalid</size></data></file></toc></xar>`,
			want: "Payload: skipped entry with invalid declared size",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, diagnostics, err := parseXAR(buildTestXAR(t, tt.toc, []byte("test")), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 0 {
				t.Fatalf("malformed entry should not be returned: %#v", files)
			}
			if !strings.Contains(strings.Join(diagnostics, "\n"), tt.want) {
				t.Fatalf("missing diagnostic %q: %#v", tt.want, diagnostics)
			}
		})
	}
}

func TestParseXAREnforcesEntryAndByteLimits(t *testing.T) {
	data := buildTestXAR(t, `<xar><toc>
		<file id="1"><name>a</name><type>file</type><data><length>4</length><offset>0</offset><size>4</size></data></file>
		<file id="2"><name>b</name><type>file</type><data><length>4</length><offset>4</offset><size>4</size></data></file>
	</toc></xar>`, []byte("aaaabbbb"))
	files, diagnostics, err := parseXAR(data, Options{MaxArchiveBytes: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("XAR byte limit should stop after one entry, got %#v", files)
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "archive content byte limit") {
		t.Fatalf("missing archive byte limit diagnostic: %#v", diagnostics)
	}

	data = buildTestXAR(t, `<xar><toc><file id="1"><name>large</name><type>file</type><data><length>8</length><offset>0</offset><size>8</size></data></file></toc></xar>`, []byte("12345678"))
	files, diagnostics, err = parseXAR(data, Options{MaxFileBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("oversized XAR entry should be skipped: %#v", files)
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "skipped entry over max file bytes") {
		t.Fatalf("missing max-file diagnostic: %#v", diagnostics)
	}
}

func TestParseXARSkipsLargePayloadAndKeepsLaterScripts(t *testing.T) {
	scriptArchive := gzipBytes(t, testCPIOOdc(map[string][]byte{"postinstall": []byte("#!/bin/sh\necho ok\n")}))
	payloadSize := len(scriptArchive) + 10
	heap := append(bytes.Repeat([]byte("p"), payloadSize), scriptArchive...)
	data := buildTestXAR(t, `<xar><toc>
		<file id="1"><name>config.pkg</name><type>directory</type>
			<file id="2"><name>Payload</name><type>file</type><data><length>`+strconv.Itoa(payloadSize)+`</length><offset>0</offset><size>`+strconv.Itoa(payloadSize)+`</size><encoding style="application/octet-stream"/></data></file>
			<file id="3"><name>Scripts</name><type>file</type><data><length>`+strconv.Itoa(len(scriptArchive))+`</length><offset>`+strconv.Itoa(payloadSize)+`</offset><size>`+strconv.Itoa(len(scriptArchive))+`</size><encoding style="application/octet-stream"/></data></file>
		</file>
	</toc></xar>`, heap)
	files, diagnostics, err := parseXAR(data, Options{MaxArchiveBytes: int64(len(scriptArchive) + 1)})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name != "config.pkg/Scripts" {
		t.Fatalf("large payload should be skipped while later Scripts remains: files=%#v diagnostics=%#v", files, diagnostics)
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "config.pkg/Payload: skipped entry over archive content byte limit") {
		t.Fatalf("missing payload budget diagnostic: %#v", diagnostics)
	}
}

func TestParseXARRejectsDecodedDataLargerThanDeclared(t *testing.T) {
	encoded := gzipBytes(t, []byte("12345678"))
	data := buildTestXAR(t, `<xar><toc>
		<file id="1"><name>Scripts</name><type>file</type><data><encoding style="application/x-gzip"/><length>`+strconv.Itoa(len(encoded))+`</length><offset>0</offset><size>1</size></data></file>
	</toc></xar>`, encoded)

	files, diagnostics, err := parseXAR(data, Options{MaxArchiveBytes: int64(len(encoded)), MaxFileBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("decoded member larger than its declared size should be skipped: %#v", files)
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "Scripts: skipped entry whose decoded size exceeds declared size 1") {
		t.Fatalf("missing declared-size mismatch diagnostic: %#v", diagnostics)
	}
}

func TestScanPKGMarksNestedScriptsAsPackageScripts(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.pkg")
	data := buildTestXAR(t, `<xar><toc>
		<file id="1"><name>Scripts</name><type>directory</type>
			<file id="2"><name>postinstall</name><type>file</type><data><length>18</length><offset>0</offset><size>18</size></data></file>
		</file>
	</toc></xar>`, []byte("#!/bin/sh\necho ok\n"))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !artifactHasEdgeToLogical(result.Graph, "package-script", "sample.pkg!Scripts/postinstall") {
		t.Fatalf("nested PKG script should have package-script relationship: %#v", result.Graph.Edges)
	}
	node := artifactNodeByLogical(result.Graph.Nodes, "sample.pkg!Scripts/postinstall")
	if node == nil || node.Kind != "script" {
		t.Fatalf("nested PKG script should be analyzed as script: %#v", node)
	}
}

func TestScanPKGMarksCompressedScriptsArchiveEntriesAsPackageScripts(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.pkg")
	scripts := gzipBytes(t, testCPIOOdc(map[string][]byte{"postinstall": []byte("#!/bin/sh\necho ok\n")}))
	data := buildTestXAR(t, `<xar><toc>
		<file id="1"><name>config.pkg/Scripts</name><type>file</type><data><length>`+strconv.Itoa(len(scripts))+`</length><offset>0</offset><size>`+strconv.Itoa(len(scripts))+`</size></data></file>
	</toc></xar>`, scripts)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !artifactHasEdgeToLogical(result.Graph, "package-script", "sample.pkg!config.pkg/Scripts!postinstall") {
		t.Fatalf("compressed PKG script should have package-script relationship: %#v", result.Graph.Edges)
	}
}

func buildTestXAR(t *testing.T, toc string, heap []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write([]byte(toc)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	header := make([]byte, 28)
	copy(header[:4], "xar!")
	binary.BigEndian.PutUint16(header[4:6], 28)
	binary.BigEndian.PutUint16(header[6:8], 1)
	binary.BigEndian.PutUint64(header[8:16], uint64(compressed.Len()))
	binary.BigEndian.PutUint64(header[16:24], uint64(len(toc)))

	out := append(header, compressed.Bytes()...)
	out = append(out, heap...)
	return out
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func zlibBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zlib.NewWriter(&out)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
