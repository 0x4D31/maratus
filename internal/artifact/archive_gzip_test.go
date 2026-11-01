package artifact

import (
	"archive/zip"
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestDetectGzipAsCompressionRepresentation(t *testing.T) {
	data := gzipBytes(t, []byte(`{"value":true}`))
	for _, name := range []string{"record.json.gz", "misleading.tar.gz", "extensionless"} {
		kind, media := Detect(name, data, false)
		if kind != "gzip" || media != "application/gzip" {
			t.Fatalf("Detect(%q gzip) = %q %q, want gzip application/gzip", name, kind, media)
		}
	}
}

func TestGenericGzipEmitsOneContentTypedChild(t *testing.T) {
	result, err := InspectBytes("record.json.gz", gzipBytes(t, []byte(`{"value":true}`)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Diagnostics) != 0 || len(result.Graph.Nodes) != 2 {
		t.Fatalf("generic gzip result = nodes %#v diagnostics %#v", result.Graph.Nodes, result.Diagnostics)
	}
	root, child := result.Graph.Nodes[0], result.Graph.Nodes[1]
	if root.Kind != "gzip" || root.MediaType != "application/gzip" ||
		child.ParentID != root.ID || child.LogicalPath != "record.json.gz!record.json" ||
		child.Kind != "manifest" || child.Provenance != "gzip-member" {
		t.Fatalf("generic gzip graph = %#v", result.Graph.Nodes)
	}
	if strings.Contains(strings.Join(result.Diagnostics, "\n"), "tar parse failed") {
		t.Fatalf("generic gzip was misparsed as TAR: %#v", result.Diagnostics)
	}
}

func TestNestedRootGzipDerivesPayloadNameFromMember(t *testing.T) {
	var encoded bytes.Buffer
	writer := zip.NewWriter(&encoded)
	entry, err := writer.Create("record.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(gzipBytes(t, []byte(`{"value":true}`))); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := InspectBytes("outer.zip", encoded.Bytes(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := "outer.zip!record.json.gz!record.json"
	for _, node := range result.Graph.Nodes {
		if node.LogicalPath == want && node.Kind == "manifest" && node.Provenance == "gzip-member" {
			return
		}
	}
	for _, node := range result.Graph.Nodes {
		if strings.Contains(node.LogicalPath, "outer.zip!record.json.gz!outer.zip!") {
			t.Fatalf("nested gzip duplicated its outer logical prefix: %#v", result.Graph.Nodes)
		}
	}
	t.Fatalf("nested gzip payload %q not found: %#v", want, result.Graph.Nodes)
}

func TestGzipDispatchesTarAndCPIOByDecodedMagic(t *testing.T) {
	tests := []struct {
		name       string
		logical    string
		payload    []byte
		child      string
		provenance string
	}{
		{
			name:       "tar",
			logical:    "sample.tgz",
			payload:    testTarRegularFiles(t, map[string][]byte{"record.json": []byte(`{"value":true}`)}),
			child:      "sample.tgz!record.json",
			provenance: "tar-entry",
		},
		{
			name:       "cpio",
			logical:    "sample.payload",
			payload:    testCPIONewc(map[string][]byte{"record.json": []byte(`{"value":true}`)}),
			child:      "sample.payload!record.json",
			provenance: "cpio-entry",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := InspectBytes(test.logical, gzipBytes(t, test.payload), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Diagnostics) != 0 || len(result.Graph.Nodes) != 2 {
				t.Fatalf("decoded %s graph = %#v diagnostics = %#v", test.name, result.Graph.Nodes, result.Diagnostics)
			}
			if root, child := result.Graph.Nodes[0], result.Graph.Nodes[1]; root.Kind != "gzip" || child.ParentID != root.ID || child.LogicalPath != test.child || child.Provenance != test.provenance {
				t.Fatalf("decoded %s graph = %#v", test.name, result.Graph.Nodes)
			}
		})
	}
}

func TestGzipMalformedAndAmbiguousStreamsFailClosed(t *testing.T) {
	valid := gzipBytes(t, []byte("payload"))
	badCRC := append([]byte(nil), valid...)
	badCRC[len(badCRC)-8] ^= 0xff
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "invalid header", data: []byte{0x1f, 0x8b, 0x08}, want: "gzip parse failed"},
		{name: "truncated", data: valid[:len(valid)-4], want: "gzip read failed"},
		{name: "bad CRC", data: badCRC, want: "gzip read failed"},
		{name: "concatenated", data: append(append([]byte(nil), valid...), valid...), want: "concatenated or trailing gzip data is unsupported"},
		{name: "trailing", data: append(append([]byte(nil), valid...), 0), want: "concatenated or trailing gzip data is unsupported"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, parentID := newContainerCoverageScanner("payload.gz", "gzip", Options{})
			s.scanGzip(parentID, "payload.gz", test.data, 1)
			requireContainerPartial(t, s, "payload.gz", test.want)
			if len(s.graph.Nodes) != 1 || !strings.Contains(strings.Join(s.diagnostics, "\n"), test.want) {
				t.Fatalf("malformed gzip modeled a child or lost its diagnostic: nodes=%#v diagnostics=%#v", s.graph.Nodes, s.diagnostics)
			}
		})
	}
}

func TestEmptyGzipProducesAnEmptyPayload(t *testing.T) {
	result, err := InspectBytes("empty.gz", gzipBytes(t, nil), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Diagnostics) != 0 || len(result.Graph.Nodes) != 2 {
		t.Fatalf("empty gzip result = nodes %#v diagnostics %#v", result.Graph.Nodes, result.Diagnostics)
	}
	child := result.Graph.Nodes[1]
	if child.LogicalPath != "empty.gz!empty" || child.Size != 0 || child.Provenance != "gzip-member" {
		t.Fatalf("empty gzip child = %#v", child)
	}
}

func TestGzipDecodeBudgetsAreNamedAndFailClosed(t *testing.T) {
	data := gzipBytes(t, bytes.Repeat([]byte("x"), 64))
	tests := []struct {
		name    string
		options Options
		want    string
	}{
		{name: "archive", options: Options{MaxArchiveBytes: 8, MaxFileBytes: 128, MaxExpandedBytes: 128}, want: "archive content byte limit 8"},
		{name: "file", options: Options{MaxArchiveBytes: 128, MaxFileBytes: 8, MaxExpandedBytes: 128}, want: "gzip payload exceeds max file bytes 8"},
		{name: "expanded", options: Options{MaxArchiveBytes: 128, MaxFileBytes: 128, MaxExpandedBytes: 8}, want: "inspection expanded-byte limit 8"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, parentID := newContainerCoverageScanner("payload.gz", "gzip", test.options)
			s.scanGzip(parentID, "payload.gz", data, 1)
			requireContainerPartial(t, s, "payload.gz", test.want)
			if len(s.graph.Nodes) != 1 {
				t.Fatalf("budget-limited gzip modeled a child: %#v", s.graph.Nodes)
			}
		})
	}
}

func TestGzipCompressionRatioDepthExpansionAndGraphBudgets(t *testing.T) {
	t.Run("compression ratio", func(t *testing.T) {
		data := gzipBytes(t, bytes.Repeat([]byte("x"), 512))
		s, parentID := newContainerCoverageScanner("payload.gz", "gzip", Options{
			MaxArchiveBytes: 1024, MaxFileBytes: 1024, MaxExpandedBytes: 1024, MaxCompressionRatio: 1,
		})
		s.scanGzip(parentID, "payload.gz", data, 1)
		requireContainerPartial(t, s, "payload.gz", "gzip compression ratio limit 1 exceeded")
		if len(s.graph.Nodes) != 1 {
			t.Fatalf("ratio-limited gzip modeled a child: %#v", s.graph.Nodes)
		}
	})

	t.Run("nested depth", func(t *testing.T) {
		inner := gzipBytes(t, []byte("payload"))
		result, err := InspectBytes("outer.gz", gzipBytes(t, inner), Options{MaxArchiveDepth: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Graph.Nodes) != 2 || result.Graph.Nodes[1].Kind != "gzip" || result.Graph.Nodes[1].AnalyzeStatus != "partial" ||
			!strings.Contains(result.Graph.Nodes[1].CoverageDetail, "archive depth limit 1") {
			t.Fatalf("nested gzip depth result = %#v", result.Graph.Nodes)
		}
	})

	t.Run("expansion disabled", func(t *testing.T) {
		result, err := InspectBytes("payload.gz", gzipBytes(t, []byte("payload")), Options{DisableContainerExpansion: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Graph.Nodes) != 1 || result.Graph.Nodes[0].AnalyzeStatus != "partial" ||
			!strings.Contains(result.Graph.Nodes[0].CoverageDetail, "container expansion skipped") {
			t.Fatalf("disabled gzip expansion result = %#v", result.Graph.Nodes)
		}
	})

	t.Run("node limit", func(t *testing.T) {
		result, err := InspectBytes("payload.gz", gzipBytes(t, []byte("payload")), Options{MaxArtifactNodes: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Graph.Nodes) != 1 || !strings.Contains(result.Graph.Nodes[0].CoverageDetail, "artifact node limit 1") {
			t.Fatalf("node-limited gzip result = %#v", result.Graph.Nodes)
		}
	})

	t.Run("path limit", func(t *testing.T) {
		result, err := InspectBytes("x.gz", gzipBytes(t, []byte("payload")), Options{MaxArtifactPathBytes: 9})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Graph.Nodes) != 1 || !strings.Contains(result.Graph.Nodes[0].CoverageDetail, "path-string limit 9") {
			t.Fatalf("path-limited gzip result = %#v", result.Graph.Nodes)
		}
	})
}

func TestGenericGzipInspectionIsDeterministic(t *testing.T) {
	data := gzipBytes(t, []byte(`{"value":true}`))
	first, err := InspectBytes("record.json.gz", data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectBytes("record.json.gz", data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("generic gzip inspection is not deterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}
}

func TestNestedGenericGzipMembersDoNotProduceTarDiagnostics(t *testing.T) {
	var encoded bytes.Buffer
	writer := zip.NewWriter(&encoded)
	for index := 0; index < 16; index++ {
		entry, err := writer.Create("data/record-" + zeroPad(index, 2) + ".json.gz")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(gzipBytes(t, []byte(`{"value":true}`))); err != nil {
			t.Fatal(err)
		}
	}
	pth, err := writer.Create("ensmallen-setup.pth")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pth.Write([]byte("import example\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := InspectBytes("fixture.whl", encoded.Bytes(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(result.Diagnostics, "\n"), "tar parse failed") {
		t.Fatalf("ordinary gzip members produced TAR diagnostics: %#v", result.Diagnostics)
	}
	gzipNodes, decodedJSON, pthNodes := 0, 0, 0
	for _, node := range result.Graph.Nodes {
		switch {
		case node.Kind == "gzip":
			gzipNodes++
		case strings.HasSuffix(node.LogicalPath, ".json.gz!record-00.json"):
			decodedJSON++
		case strings.HasSuffix(node.LogicalPath, "!ensmallen-setup.pth"):
			pthNodes++
		}
	}
	if gzipNodes != 16 || decodedJSON != 1 || pthNodes != 1 {
		t.Fatalf("nested gzip inventory = gzip %d decoded sentinel %d pth %d; nodes=%#v", gzipNodes, decodedJSON, pthNodes, result.Graph.Nodes)
	}
}
