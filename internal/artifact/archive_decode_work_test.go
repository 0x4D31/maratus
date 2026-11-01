package artifact

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"
	"testing"
)

func TestXARDuplicateExtentsRespectAggregateDecodeWorkBudget(t *testing.T) {
	raw := testEmptyZlibWork(256)
	var toc strings.Builder
	toc.WriteString(`<xar><toc>`)
	// This entry is rejected before its extent is decoded and therefore must
	// not consume decode-work budget.
	fmt.Fprintf(&toc, `<file id="0"><name>../rejected</name><data><encoding style="application/x-gzip"/><length>%d</length><offset>0</offset><size>0</size></data></file>`, len(raw))
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&toc, `<file id="%d"><name>f%d</name><data><encoding style="application/x-gzip"/><length>%d</length><offset>0</offset><size>0</size></data></file>`, i+1, i, len(raw))
	}
	toc.WriteString(`</toc></xar>`)

	limit := int64(2 * len(raw))
	s := scanner{options: Options{MaxArchiveBytes: limit}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.pkg", Kind: "pkg"})
	s.scanPKG(parentID, "sample.pkg", buildTestXAR(t, toc.String(), raw), 1)

	for _, name := range []string{"f0", "f1"} {
		node := artifactNodeByLogical(s.graph.Nodes, "sample.pkg!"+name)
		if node == nil || node.AnalyzeStatus != "analyzed" {
			t.Fatalf("%s should be decoded before the work budget is exhausted: %#v", name, node)
		}
	}
	skipped := artifactNodeByLogical(s.graph.Nodes, "sample.pkg!f2")
	if skipped == nil || skipped.AnalyzeStatus != "skipped" || !strings.Contains(skipped.CoverageDetail, "decode-work byte limit "+strconv.FormatInt(limit, 10)) {
		t.Fatalf("budget-exhausting XAR entry should retain explicit skipped coverage: %#v", skipped)
	}
	parent := artifactNodeByLogical(s.graph.Nodes, "sample.pkg")
	if parent == nil || parent.AnalyzeStatus != "partial" || !strings.Contains(parent.CoverageDetail, "decode-work byte limit") {
		t.Fatalf("partially decoded XAR should mark its parent partial: %#v", parent)
	}
	if !strings.Contains(strings.Join(s.diagnostics, "\n"), "archive decode-work byte limit") {
		t.Fatalf("missing aggregate XAR decode-work diagnostic: %#v", s.diagnostics)
	}
}

func TestZIPDuplicateExtentsRespectAggregateDecodeWorkBudget(t *testing.T) {
	raw := testEmptyDeflateWork(256)
	archive := testDuplicateZIPExtentWork(raw, []string{"../rejected", "f0", "f1", "f2"})
	limit := int64(2 * len(raw))
	s := scanner{options: Options{MaxArchiveBytes: limit}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.zip", Kind: "zip"})
	s.scanZip(parentID, "sample.zip", archive, 1)

	for _, name := range []string{"f0", "f1"} {
		node := artifactNodeByLogical(s.graph.Nodes, "sample.zip!"+name)
		if node == nil || node.AnalyzeStatus != "analyzed" {
			t.Fatalf("%s should be decoded before the work budget is exhausted: %#v", name, node)
		}
	}
	skipped := artifactNodeByLogical(s.graph.Nodes, "sample.zip!f2")
	if skipped == nil || skipped.AnalyzeStatus != "skipped" || !strings.Contains(skipped.CoverageDetail, "decode-work byte limit "+strconv.FormatInt(limit, 10)) {
		t.Fatalf("budget-exhausting ZIP entry should retain explicit skipped coverage: %#v", skipped)
	}
	parent := artifactNodeByLogical(s.graph.Nodes, "sample.zip")
	if parent == nil || parent.AnalyzeStatus != "partial" || !strings.Contains(parent.CoverageDetail, "decode-work byte limit") {
		t.Fatalf("partially decoded ZIP should mark its parent partial: %#v", parent)
	}
	if !strings.Contains(strings.Join(s.diagnostics, "\n"), "archive decode-work byte limit") {
		t.Fatalf("missing aggregate ZIP decode-work diagnostic: %#v", s.diagnostics)
	}
}

func TestXARFailedDuplicateDecodesConsumeAggregateWorkBudget(t *testing.T) {
	raw := bytes.Repeat([]byte{0}, 64)
	var toc strings.Builder
	toc.WriteString(`<xar><toc>`)
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&toc, `<file id="%d"><name>f%d</name><data><encoding style="application/x-gzip"/><length>%d</length><offset>0</offset><size>0</size></data></file>`, i, i, len(raw))
	}
	toc.WriteString(`</toc></xar>`)

	limit := int64(2 * len(raw))
	files, diagnostics, err := parseXAR(buildTestXAR(t, toc.String(), raw), Options{MaxArchiveBytes: limit})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(diagnostics, "\n")
	if strings.Count(joined, "unsupported or malformed encoding") != 2 {
		t.Fatalf("exactly two failed XAR decode attempts should fit the work budget: %#v", diagnostics)
	}
	if len(files) != 1 || files[0].Name != "f2" || !strings.Contains(files[0].SkipDetail, "decode-work byte limit") {
		t.Fatalf("third repeated extent should stop at the work budget: %#v", files)
	}
	if strings.Contains(joined, "f3:") {
		t.Fatalf("entries after aggregate work exhaustion must not be decoded: %#v", diagnostics)
	}
}

func TestXARDecodeWorkExhaustionStopsOuterExtentAfterNestedFiles(t *testing.T) {
	raw := testEmptyZlibWork(64)
	toc := `<xar><toc><file id="0"><name>container</name>` +
		`<data><length>1</length><offset>0</offset><size>1</size></data>` +
		`<file id="1"><name>f0</name><data><encoding style="application/x-gzip"/><length>` + strconv.Itoa(len(raw)) + `</length><offset>0</offset><size>0</size></data></file>` +
		`<file id="2"><name>f1</name><data><encoding style="application/x-gzip"/><length>` + strconv.Itoa(len(raw)) + `</length><offset>0</offset><size>0</size></data></file>` +
		`</file></toc></xar>`

	files, diagnostics, err := parseXAR(buildTestXAR(t, toc, raw), Options{MaxArchiveBytes: int64(len(raw) + 1)})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].Name != "container/f0" || files[1].Name != "container/f1" || files[1].SkipDetail == "" {
		t.Fatalf("nested work exhaustion should return the decoded child and one skipped child: %#v", files)
	}
	for _, file := range files {
		if file.Name == "container" {
			t.Fatalf("outer extent was decoded after nested work exhaustion: %#v", files)
		}
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "decode-work byte limit") {
		t.Fatalf("missing nested decode-work diagnostic: %#v", diagnostics)
	}
}

func TestZIPFailedDuplicateDecodesConsumeAggregateWorkBudget(t *testing.T) {
	raw := bytes.Repeat([]byte{0}, 64)
	archive := testDuplicateZIPExtentWork(raw, []string{"f0", "f1", "f2", "f3"})
	limit := int64(2 * len(raw))
	s := scanner{options: Options{MaxArchiveBytes: limit}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.zip", Kind: "zip"})
	s.scanZip(parentID, "sample.zip", archive, 1)

	joined := strings.Join(s.diagnostics, "\n")
	if strings.Count(joined, "read failed") != 2 {
		t.Fatalf("exactly two failed ZIP decode attempts should fit the work budget: %#v", s.diagnostics)
	}
	for _, name := range []string{"f2", "f3"} {
		skipped := artifactNodeByLogical(s.graph.Nodes, "sample.zip!"+name)
		if skipped == nil || skipped.AnalyzeStatus != "skipped" || !strings.Contains(skipped.CoverageDetail, "decode-work byte limit") {
			t.Fatalf("member %s after the work budget should retain skipped metadata without a decode attempt: %#v", name, skipped)
		}
	}
}

func TestZIPBadChecksumAttemptsConsumeAggregateOutputWorkBudget(t *testing.T) {
	// Keep compressed work well below output work across Go compressor versions.
	payload := bytes.Repeat([]byte("x"), 4096)
	raw := testRawDeflateWork(t, payload)
	badCRC := crc32.ChecksumIEEE(payload) ^ 0xffffffff
	archive := testDuplicateZIPExtentMetadataWork(raw, []string{"f0", "f1", "f2", "f3"}, uint32(len(payload)), badCRC)
	limit := int64(2 * len(payload))
	s := scanner{options: Options{MaxArchiveBytes: limit, MaxCompressionRatio: 1000}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.zip", Kind: "zip"})
	s.scanZip(parentID, "sample.zip", archive, 1)

	joined := strings.Join(s.diagnostics, "\n")
	if strings.Count(joined, "checksum") != 2 {
		t.Fatalf("exactly two bad-checksum ZIP outputs should fit the attempted-output budget: %#v", s.diagnostics)
	}
	for _, name := range []string{"f0", "f1"} {
		node := artifactNodeByLogical(s.graph.Nodes, "sample.zip!"+name)
		if node == nil || node.AnalyzeStatus != "skipped" || !strings.Contains(node.CoverageDetail, "checksum") {
			t.Fatalf("bad-checksum entry %s should retain validation coverage: %#v", name, node)
		}
	}
	for _, name := range []string{"f2", "f3"} {
		skipped := artifactNodeByLogical(s.graph.Nodes, "sample.zip!"+name)
		if skipped == nil || skipped.AnalyzeStatus != "skipped" || !strings.Contains(skipped.CoverageDetail, "attempted decoded-output byte limit "+strconv.FormatInt(limit, 10)) {
			t.Fatalf("member %s after the output budget should retain skipped metadata without a decode attempt: %#v", name, skipped)
		}
	}
	parent := artifactNodeByLogical(s.graph.Nodes, "sample.zip")
	if parent == nil || parent.AnalyzeStatus != "partial" || !strings.Contains(parent.CoverageDetail, "attempted decoded-output byte limit") {
		t.Fatalf("partially decoded ZIP should mark its parent partial: %#v", parent)
	}
}

func TestXARDeclaredSizeMismatchAttemptsConsumeActualOutputWork(t *testing.T) {
	// Keep compressed work well below output work across Go compressor versions.
	payload := bytes.Repeat([]byte("x"), 4096)
	raw := zlibBytes(t, payload)
	var toc strings.Builder
	toc.WriteString(`<xar><toc>`)
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&toc, `<file id="%d"><name>f%d</name><data><encoding style="application/x-gzip"/><length>%d</length><offset>0</offset><size>8192</size></data></file>`, i, i, len(raw))
	}
	toc.WriteString(`</toc></xar>`)

	const limit = int64(8192)
	s := scanner{options: Options{MaxArchiveBytes: limit, MaxCompressionRatio: 1000}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.pkg", Kind: "pkg"})
	s.scanPKG(parentID, "sample.pkg", buildTestXAR(t, toc.String(), raw), 1)

	joined := strings.Join(s.diagnostics, "\n")
	if strings.Count(joined, "decoded size 4096; declared size is 8192") != 2 {
		t.Fatalf("actual decoded bytes, not rejected declarations, should consume the XAR output-work budget: %#v", s.diagnostics)
	}
	skipped := artifactNodeByLogical(s.graph.Nodes, "sample.pkg!f2")
	if skipped == nil || !strings.Contains(skipped.CoverageDetail, "attempted decoded-output byte limit 8192") {
		t.Fatalf("third declared-size mismatch should stop at the actual-output budget: %#v", skipped)
	}
	if artifactNodeByLogical(s.graph.Nodes, "sample.pkg!f3") != nil {
		t.Fatalf("entry after attempted-output exhaustion must not be decoded: %#v", s.graph.Nodes)
	}
	parent := artifactNodeByLogical(s.graph.Nodes, "sample.pkg")
	if parent == nil || parent.AnalyzeStatus != "partial" || !strings.Contains(parent.CoverageDetail, "attempted decoded-output byte limit") {
		t.Fatalf("partially decoded XAR should mark its parent partial: %#v", parent)
	}
}

func TestXARFailedDecompressionConsumesActualOutputWork(t *testing.T) {
	// Keep compressed work well below output work across Go compressor versions.
	payload := bytes.Repeat([]byte("x"), 4096)
	raw := zlibBytes(t, payload)
	raw[len(raw)-1] ^= 0xff
	var toc strings.Builder
	toc.WriteString(`<xar><toc>`)
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&toc, `<file id="%d"><name>f%d</name><data><encoding style="application/x-gzip"/><length>%d</length><offset>0</offset></data></file>`, i, i, len(raw))
	}
	toc.WriteString(`</toc></xar>`)

	const limit = int64(8192)
	s := scanner{options: Options{MaxArchiveBytes: limit, MaxCompressionRatio: 1000}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.pkg", Kind: "pkg"})
	s.scanPKG(parentID, "sample.pkg", buildTestXAR(t, toc.String(), raw), 1)

	joined := strings.Join(s.diagnostics, "\n")
	if strings.Count(joined, "unsupported or malformed encoding") != 2 {
		t.Fatalf("failed XAR streams should charge the bytes emitted before validation failed: %#v", s.diagnostics)
	}
	skipped := artifactNodeByLogical(s.graph.Nodes, "sample.pkg!f2")
	if skipped == nil || !strings.Contains(skipped.CoverageDetail, "attempted decoded-output byte limit 8192") {
		t.Fatalf("third malformed stream should stop at the actual-output budget: %#v", skipped)
	}
	if artifactNodeByLogical(s.graph.Nodes, "sample.pkg!f3") != nil {
		t.Fatalf("entry after attempted-output exhaustion must not be decoded: %#v", s.graph.Nodes)
	}
}

func testEmptyZlibWork(minBytes int) []byte {
	var out bytes.Buffer
	out.Write([]byte{0x78, 0x01})
	for out.Len() < minBytes {
		out.Write([]byte{0, 0, 0, 0xff, 0xff})
	}
	out.Write([]byte{1, 0, 0, 0xff, 0xff})
	out.Write([]byte{0, 0, 0, 1})
	return out.Bytes()
}

func testEmptyDeflateWork(minBytes int) []byte {
	var out bytes.Buffer
	for out.Len() < minBytes {
		out.Write([]byte{0, 0, 0, 0xff, 0xff})
	}
	out.Write([]byte{1, 0, 0, 0xff, 0xff})
	return out.Bytes()
}

func testDuplicateZIPExtentWork(raw []byte, names []string) []byte {
	return testDuplicateZIPExtentMetadataWork(raw, names, 0, 0)
}

func testRawDeflateWork(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer, err := flate.NewWriter(&out, flate.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func testDuplicateZIPExtentMetadataWork(raw []byte, names []string, uncompressedSize, checksum uint32) []byte {
	localName := []byte("a")
	local := make([]byte, 30+len(localName))
	binary.LittleEndian.PutUint32(local[0:4], 0x04034b50)
	binary.LittleEndian.PutUint16(local[4:6], 20)
	binary.LittleEndian.PutUint16(local[8:10], 8)
	binary.LittleEndian.PutUint32(local[14:18], checksum)
	binary.LittleEndian.PutUint32(local[18:22], uint32(len(raw)))
	binary.LittleEndian.PutUint32(local[22:26], uncompressedSize)
	binary.LittleEndian.PutUint16(local[26:28], uint16(len(localName)))
	copy(local[30:], localName)
	out := append(local, raw...)
	directoryOffset := len(out)
	for _, name := range names {
		centralName := []byte(name)
		record := make([]byte, 46+len(centralName))
		binary.LittleEndian.PutUint32(record[0:4], 0x02014b50)
		binary.LittleEndian.PutUint16(record[4:6], 20)
		binary.LittleEndian.PutUint16(record[6:8], 20)
		binary.LittleEndian.PutUint16(record[10:12], 8)
		binary.LittleEndian.PutUint32(record[16:20], checksum)
		binary.LittleEndian.PutUint32(record[20:24], uint32(len(raw)))
		binary.LittleEndian.PutUint32(record[24:28], uncompressedSize)
		binary.LittleEndian.PutUint16(record[28:30], uint16(len(centralName)))
		copy(record[46:], centralName)
		out = append(out, record...)
	}
	directorySize := len(out) - directoryOffset
	eocd := make([]byte, 22)
	binary.LittleEndian.PutUint32(eocd[0:4], 0x06054b50)
	binary.LittleEndian.PutUint16(eocd[8:10], uint16(len(names)))
	binary.LittleEndian.PutUint16(eocd[10:12], uint16(len(names)))
	binary.LittleEndian.PutUint32(eocd[12:16], uint32(directorySize))
	binary.LittleEndian.PutUint32(eocd[16:20], uint32(directoryOffset))
	return append(out, eocd...)
}
