package artifact

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type indexedGzipTestPayload struct {
	tag  byte
	data []byte
}

func TestIndexedGzipBundleClassificationAndBoundedExpansion(t *testing.T) {
	payloads := []indexedGzipTestPayload{
		{tag: 0, data: []byte("ordinary inert payload")},
		{tag: 1, data: []byte("another inert payload")},
		{tag: 2, data: []byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0}},
	}
	bundle := buildTestIndexedGzipBundle(t, [5]byte{'N', 'O', 'T', 'C', 'S'}, payloads)
	if kind, media := Detect("misleading.js", bundle, false); kind != "indexed-gzip-bundle" || media != "application/x-indexed-gzip-bundle" {
		t.Fatalf("Detect(indexed gzip bundle with misleading suffix) = %q %q", kind, media)
	}

	result, err := InspectBytes("misleading.js", bundle, Options{IncludeUnreferenced: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Graph.Nodes) != 4 || len(result.Contents) != 4 {
		t.Fatalf("indexed gzip inventory = %d nodes, %d contents", len(result.Graph.Nodes), len(result.Contents))
	}
	root := result.Graph.Nodes[0]
	if root.Kind != "indexed-gzip-bundle" || root.AnalyzeStatus != "analyzed" ||
		root.DeclaredEntryCount == nil || *root.DeclaredEntryCount != 3 ||
		root.ModeledEntryCount == nil || *root.ModeledEntryCount != 3 {
		t.Fatalf("indexed gzip root = %#v", root)
	}
	for index, payload := range payloads {
		node := result.Graph.Nodes[index+1]
		content := result.Contents[index+1]
		if node.ParentID != root.ID || node.Provenance != "indexed-gzip-member" ||
			node.SourceRole != "packaged-content" || content.Role != "packaged-content" ||
			content.Executable || !bytes.Equal(content.Data, payload.data) {
			t.Fatalf("indexed gzip child %d = node %#v content %#v", index, node, content)
		}
		wantName := fmt.Sprintf("member-%03d-tag-%03d", index, payload.tag)
		if !strings.HasSuffix(node.LogicalPath, "!"+wantName) {
			t.Fatalf("indexed gzip child logical path = %q, want suffix %q", node.LogicalPath, wantName)
		}
	}
	if result.Graph.Nodes[3].Kind != "macho" {
		t.Fatalf("decoded Mach-O payload was not content-classified: %#v", result.Graph.Nodes[3])
	}
}

func TestIndexedGzipBundleRejectsMalformedStructures(t *testing.T) {
	valid := buildTestIndexedGzipBundle(t, [5]byte{1, 2, 3, 4, 5}, []indexedGzipTestPayload{{tag: 2, data: []byte("inert")}})
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "zero count", mutate: func(data []byte) []byte { data[5] = 0; return data }},
		{name: "member limit", mutate: func(data []byte) []byte { data[5] = maxIndexedGzipBundleMembers + 1; return data }},
		{name: "truncated header", mutate: func(data []byte) []byte { return data[:indexedGzipBundleHeaderSize+3] }},
		{name: "zero compressed extent", mutate: func(data []byte) []byte { binary.LittleEndian.PutUint64(data[15:23], 0); return data }},
		{name: "oversized compressed extent", mutate: func(data []byte) []byte { binary.LittleEndian.PutUint64(data[15:23], uint64(len(data))); return data }},
		{name: "non gzip member", mutate: func(data []byte) []byte { data[23] = 0; return data }},
		{name: "trailing data", mutate: func(data []byte) []byte { return append(data, 0) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := test.mutate(bytes.Clone(valid))
			if _, err := parseIndexedGzipBundle(data); err == nil {
				t.Fatal("malformed indexed gzip structure was accepted")
			}
			if kind, _ := Detect("candidate.bin", data, false); kind == "indexed-gzip-bundle" {
				t.Fatal("malformed indexed gzip structure was content-classified")
			}
		})
	}
}

func TestIndexedGzipBundleRejectsInvalidDecodedMembers(t *testing.T) {
	valid := buildTestIndexedGzipBundle(t, [5]byte{9, 8, 7, 6, 5}, []indexedGzipTestPayload{{tag: 2, data: []byte("inert")}})
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "declared size mismatch", mutate: func(data []byte) []byte { binary.LittleEndian.PutUint64(data[7:15], 6); return data }},
		{name: "corrupt gzip", mutate: func(data []byte) []byte { data[len(data)-1] ^= 0xff; return data }},
		{name: "concatenated gzip", mutate: func(data []byte) []byte {
			extra := gzipTestBytes(t, []byte("second"))
			binary.LittleEndian.PutUint64(data[15:23], uint64(len(data)-23+len(extra)))
			return append(data, extra...)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := test.mutate(bytes.Clone(valid))
			if _, err := parseIndexedGzipBundle(data); err != nil {
				t.Fatalf("complete length structure should remain recognizable: %v", err)
			}
			result, err := InspectBytes("candidate.bin", data, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if root := result.Graph.Nodes[0]; root.Kind != "indexed-gzip-bundle" || root.AnalyzeStatus != "partial" {
				t.Fatalf("invalid decoded-member root = %#v", root)
			}
			for _, node := range result.Graph.Nodes[1:] {
				if node.AnalyzeStatus == "analyzed" {
					t.Fatalf("invalid member became analyzed content: %#v", node)
				}
			}
		})
	}
}

func TestIndexedGzipBundleBudgetsAndDisabledExpansionAreExplicit(t *testing.T) {
	bundle := buildTestIndexedGzipBundle(t, [5]byte{1, 1, 2, 3, 5}, []indexedGzipTestPayload{
		{tag: 0, data: bytes.Repeat([]byte("a"), 1024)},
		{tag: 2, data: bytes.Repeat([]byte("b"), 1024)},
	})
	largeBundle := buildTestIndexedGzipBundle(t, [5]byte{1, 1, 2, 3, 5}, []indexedGzipTestPayload{
		{tag: 2, data: bytes.Repeat([]byte("compressible"), 4096)},
	})
	fileLimited, err := InspectBytes("candidate.bin", largeBundle, Options{
		MaxFileBytes: int64(len(largeBundle)), MaxArchiveBytes: 1 << 20,
		MaxExpandedBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxCompressionRatio: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if root := fileLimited.Graph.Nodes[0]; root.AnalyzeStatus != "partial" || !strings.Contains(root.CoverageDetail, "max file bytes") {
		t.Fatalf("file-byte coverage = %#v diagnostics=%#v", root, fileLimited.Diagnostics)
	}
	retainedLimited, err := InspectBytes("candidate.bin", largeBundle, Options{
		MaxFileBytes: 1 << 20, MaxArchiveBytes: 1 << 20,
		MaxExpandedBytes: 1 << 20, MaxTotalBytes: int64(len(largeBundle) + 128), MaxCompressionRatio: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if root := retainedLimited.Graph.Nodes[0]; root.AnalyzeStatus != "partial" || !strings.Contains(root.CoverageDetail, "retained-byte limit") {
		t.Fatalf("retained-byte coverage = %#v diagnostics=%#v", root, retainedLimited.Diagnostics)
	}

	tests := []struct {
		name    string
		options Options
		detail  string
	}{
		{name: "compression ratio", options: Options{MaxFileBytes: 1 << 20, MaxArchiveBytes: 1 << 20, MaxExpandedBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxCompressionRatio: 1}, detail: "compression ratio"},
		{name: "archive bytes", options: Options{MaxFileBytes: 1 << 20, MaxArchiveBytes: 1536, MaxExpandedBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxCompressionRatio: 1000}, detail: "decoded-output byte limit"},
		{name: "expanded bytes", options: Options{MaxFileBytes: 1 << 20, MaxArchiveBytes: 1 << 20, MaxExpandedBytes: 1536, MaxTotalBytes: 1 << 20, MaxCompressionRatio: 1000}, detail: "expanded-byte limit"},
		{name: "disabled", options: Options{DisableContainerExpansion: true}, detail: "container expansion skipped"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := InspectBytes("candidate.bin", bundle, test.options)
			if err != nil {
				t.Fatal(err)
			}
			root := result.Graph.Nodes[0]
			if root.AnalyzeStatus != "partial" || !strings.Contains(root.CoverageDetail, test.detail) {
				t.Fatalf("budget coverage = %#v diagnostics=%#v", root, result.Diagnostics)
			}
		})
	}
}

func TestIndexedGzipBundleCloseNegativeAndDeterminism(t *testing.T) {
	lookalike := append([]byte{'H', 'E', 'A', 'D', 'R', 1}, bytes.Repeat([]byte{0}, 32)...)
	if kind, _ := Detect("example.js", lookalike, false); kind == "indexed-gzip-bundle" {
		t.Fatalf("length-table lookalike became an indexed gzip bundle")
	}

	bundle := buildTestIndexedGzipBundle(t, [5]byte{0xff, 0, 0x7f, 'X', 3}, []indexedGzipTestPayload{
		{tag: 7, data: []byte("first")},
		{tag: 7, data: []byte("second")},
	})
	first, err := InspectBytes("candidate.bin", bundle, Options{MaxCompressionRatio: 1000})
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectBytes("candidate.bin", bundle, Options{MaxCompressionRatio: 1000})
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("indexed gzip inspection was nondeterministic")
	}
}

func buildTestIndexedGzipBundle(t *testing.T, prefix [5]byte, payloads []indexedGzipTestPayload) []byte {
	t.Helper()
	var out bytes.Buffer
	out.Write(prefix[:])
	out.WriteByte(byte(len(payloads)))
	for _, payload := range payloads {
		compressed := gzipTestBytes(t, payload.data)
		out.WriteByte(payload.tag)
		if err := binary.Write(&out, binary.LittleEndian, uint64(len(payload.data))); err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(&out, binary.LittleEndian, uint64(len(compressed))); err != nil {
			t.Fatal(err)
		}
		out.Write(compressed)
	}
	return out.Bytes()
}

func gzipTestBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
