package artifact

import (
	"archive/tar"
	"bytes"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestMalformedContainerScansMarkParentPartial(t *testing.T) {
	tests := []struct {
		name    string
		logical string
		kind    string
		want    string
		scan    func(*scanner, string, string, []byte)
	}{
		{
			name:    "asar",
			logical: "sample.asar",
			kind:    "asar",
			want:    "asar parse failed",
			scan: func(s *scanner, parentID, logical string, data []byte) {
				s.scanAsar(parentID, logical, data, 1)
			},
		},
		{
			name:    "cpio",
			logical: "sample.cpio",
			kind:    "cpio",
			want:    "cpio parse failed",
			scan: func(s *scanner, parentID, logical string, data []byte) {
				s.scanCPIO(parentID, logical, data, 1)
			},
		},
		{
			name:    "tar",
			logical: "sample.tar",
			kind:    "tar",
			want:    "tar parse failed",
			scan: func(s *scanner, parentID, logical string, data []byte) {
				s.scanTar(parentID, logical, data, 1)
			},
		},
		{
			name:    "xar",
			logical: "sample.pkg",
			kind:    "pkg",
			want:    "pkg/xar parse failed",
			scan: func(s *scanner, parentID, logical string, data []byte) {
				s.scanPKG(parentID, logical, data, 1)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, parentID := newContainerCoverageScanner(test.logical, test.kind, Options{})
			test.scan(s, parentID, test.logical, []byte("malformed"))
			requireContainerPartial(t, s, test.logical, test.want)
			if !strings.Contains(strings.Join(s.diagnostics, "\n"), test.want) {
				t.Fatalf("missing bounded %s diagnostic: %#v", test.name, s.diagnostics)
			}
		})
	}
}

func TestTruncatedCPIOAndLimitedGzipMarkParentPartial(t *testing.T) {
	t.Run("cpio-missing-trailer", func(t *testing.T) {
		data := appendCPIOTestEntry(nil, 1, 0o100755, "install.sh", []byte("echo ok\n"))
		s, parentID := newContainerCoverageScanner("sample.cpio", "cpio", Options{})
		s.scanCPIO(parentID, "sample.cpio", data, 1)
		requireContainerPartial(t, s, "sample.cpio", "archive completeness could not be verified")
	})

	t.Run("gzip-read-limit", func(t *testing.T) {
		data := gzipBytes(t, bytes.Repeat([]byte("x"), 32))
		s, parentID := newContainerCoverageScanner("sample.tar.gz", "gzip", Options{MaxArchiveBytes: 8})
		s.scanGzip(parentID, "sample.tar.gz", data, 1)
		requireContainerPartial(t, s, "sample.tar.gz", "archive content byte limit 8")
	})
}

func TestContainerEntryLimitsMarkParentPartial(t *testing.T) {
	t.Run("asar", func(t *testing.T) {
		files := make(map[string]any, MaxArchiveEntries+1)
		for i := 0; i < MaxArchiveEntries+1; i++ {
			files[fmt.Sprintf("directory-%05d", i)] = map[string]any{"files": map[string]any{}}
		}
		data, err := writeTestAsarRaw(map[string]any{"files": files}, nil)
		if err != nil {
			t.Fatal(err)
		}
		s, parentID := newContainerCoverageScanner("sample.asar", "asar", Options{})
		s.scanAsar(parentID, "sample.asar", data, 1)
		requireContainerPartial(t, s, "sample.asar", fmt.Sprintf("archive entry limit %d reached", MaxArchiveEntries))
	})

	t.Run("cpio", func(t *testing.T) {
		var data []byte
		for i := 0; i < MaxArchiveEntries+1; i++ {
			data = appendCPIOTestEntry(data, uint64(i+1), 0o040755, fmt.Sprintf("directory-%05d", i), nil)
		}
		data = appendCPIOTestEntry(data, MaxArchiveEntries+2, 0, "TRAILER!!!", nil)
		s, parentID := newContainerCoverageScanner("sample.cpio", "cpio", Options{})
		s.scanCPIO(parentID, "sample.cpio", data, 1)
		requireContainerPartial(t, s, "sample.cpio", fmt.Sprintf("archive entry limit %d reached", MaxArchiveEntries))
	})

	t.Run("tar", func(t *testing.T) {
		var out bytes.Buffer
		tw := tar.NewWriter(&out)
		for i := 0; i < MaxArchiveEntries+1; i++ {
			if err := tw.WriteHeader(&tar.Header{
				Name:     fmt.Sprintf("directory-%05d/", i),
				Typeflag: tar.TypeDir,
				Mode:     0o755,
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		s, parentID := newContainerCoverageScanner("sample.tar", "tar", Options{})
		s.scanTar(parentID, "sample.tar", out.Bytes(), 1)
		requireContainerPartial(t, s, "sample.tar", fmt.Sprintf("archive entry limit %d reached", MaxArchiveEntries))
	})

	t.Run("xar-preflight", func(t *testing.T) {
		toc := `<xar><toc>` + strings.Repeat(`<file><name>x</name></file>`, MaxArchiveEntries+1) + `</toc></xar>`
		s, parentID := newContainerCoverageScanner("sample.pkg", "pkg", Options{})
		s.scanPKG(parentID, "sample.pkg", buildTestXAR(t, toc, nil), 1)
		requireContainerPartial(t, s, "sample.pkg", fmt.Sprintf("archive entry limit %d", MaxArchiveEntries))
	})
}

func TestContainerByteLimitsMarkParentPartial(t *testing.T) {
	t.Run("asar-aggregate", func(t *testing.T) {
		data, err := writeTestAsar(map[string][]byte{
			"a": bytes.Repeat([]byte("a"), 4),
			"b": bytes.Repeat([]byte("b"), 4),
		})
		if err != nil {
			t.Fatal(err)
		}
		s, parentID := newContainerCoverageScanner("sample.asar", "asar", Options{MaxArchiveBytes: 5})
		s.scanAsar(parentID, "sample.asar", data, 1)
		requireContainerPartial(t, s, "sample.asar", "archive content byte limit 5")
	})

	t.Run("cpio-aggregate", func(t *testing.T) {
		data := testCPIONewc(map[string][]byte{
			"a": bytes.Repeat([]byte("a"), 4),
			"b": bytes.Repeat([]byte("b"), 4),
		})
		s, parentID := newContainerCoverageScanner("sample.cpio", "cpio", Options{MaxArchiveBytes: 5})
		s.scanCPIO(parentID, "sample.cpio", data, 1)
		requireContainerPartial(t, s, "sample.cpio", "archive content byte limit 5")
	})

	t.Run("tar-aggregate", func(t *testing.T) {
		data := testTarRegularFiles(t, map[string][]byte{
			"a": bytes.Repeat([]byte("a"), 4),
			"b": bytes.Repeat([]byte("b"), 4),
		})
		s, parentID := newContainerCoverageScanner("sample.tar", "tar", Options{MaxArchiveBytes: 5})
		s.scanTar(parentID, "sample.tar", data, 1)
		requireContainerPartial(t, s, "sample.tar", "archive content byte limit 5")
	})

	t.Run("xar-aggregate", func(t *testing.T) {
		data := buildTestXAR(t, `<xar><toc>
			<file><name>a</name><data><length>4</length><offset>0</offset><size>4</size></data></file>
			<file><name>b</name><data><length>4</length><offset>4</offset><size>4</size></data></file>
		</toc></xar>`, []byte("aaaabbbb"))
		s, parentID := newContainerCoverageScanner("sample.pkg", "pkg", Options{MaxArchiveBytes: 5})
		s.scanPKG(parentID, "sample.pkg", data, 1)
		requireContainerPartial(t, s, "sample.pkg", "archive content byte limit 5")
	})
}

func TestContainerPerEntryLimitsMarkParentPartial(t *testing.T) {
	const want = "max file bytes 4"
	t.Run("asar", func(t *testing.T) {
		data, err := writeTestAsar(map[string][]byte{"large": bytes.Repeat([]byte("x"), 8)})
		if err != nil {
			t.Fatal(err)
		}
		s, parentID := newContainerCoverageScanner("sample.asar", "asar", Options{MaxFileBytes: 4})
		s.scanAsar(parentID, "sample.asar", data, 1)
		requireContainerPartial(t, s, "sample.asar", want)
	})

	t.Run("cpio", func(t *testing.T) {
		s, parentID := newContainerCoverageScanner("sample.cpio", "cpio", Options{MaxFileBytes: 4})
		s.scanCPIO(parentID, "sample.cpio", testCPIONewc(map[string][]byte{"large": bytes.Repeat([]byte("x"), 8)}), 1)
		requireContainerPartial(t, s, "sample.cpio", want)
	})

	t.Run("tar", func(t *testing.T) {
		s, parentID := newContainerCoverageScanner("sample.tar", "tar", Options{MaxFileBytes: 4})
		s.scanTar(parentID, "sample.tar", testTarRegularFiles(t, map[string][]byte{"large": bytes.Repeat([]byte("x"), 8)}), 1)
		requireContainerPartial(t, s, "sample.tar", want)
	})

	t.Run("xar", func(t *testing.T) {
		data := buildTestXAR(t, `<xar><toc><file><name>large</name><data><length>8</length><offset>0</offset><size>8</size></data></file></toc></xar>`, []byte("12345678"))
		s, parentID := newContainerCoverageScanner("sample.pkg", "pkg", Options{MaxFileBytes: 4})
		s.scanPKG(parentID, "sample.pkg", data, 1)
		requireContainerPartial(t, s, "sample.pkg", want)
	})
}

func TestMalformedMembersExposeGranularOrContainerCoverage(t *testing.T) {
	t.Run("asar-invalid-bounds", func(t *testing.T) {
		data, err := writeTestAsarRaw(map[string]any{"files": map[string]any{
			"bad": map[string]any{"offset": "99", "size": 1},
		}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		s, parentID := newContainerCoverageScanner("sample.asar", "asar", Options{})
		s.scanAsar(parentID, "sample.asar", data, 1)
		requireContainerAnalyzed(t, s, "sample.asar")
	})

	t.Run("cpio-unsafe-path", func(t *testing.T) {
		s, parentID := newContainerCoverageScanner("sample.cpio", "cpio", Options{})
		s.scanCPIO(parentID, "sample.cpio", testCPIONewc(map[string][]byte{"../bad": nil}), 1)
		requireContainerPartial(t, s, "sample.cpio", "entries were rejected and not modeled")
	})

	t.Run("tar-unsafe-path", func(t *testing.T) {
		s, parentID := newContainerCoverageScanner("sample.tar", "tar", Options{})
		s.scanTar(parentID, "sample.tar", testTarRegularFiles(t, map[string][]byte{"../bad": nil}), 1)
		requireContainerPartial(t, s, "sample.tar", "unsafe paths")
	})

	t.Run("xar-invalid-member-bounds", func(t *testing.T) {
		data := buildTestXAR(t, `<xar><toc><file><name>bad</name><data><length>invalid</length><offset>0</offset></data></file></toc></xar>`, nil)
		s, parentID := newContainerCoverageScanner("sample.pkg", "pkg", Options{})
		s.scanPKG(parentID, "sample.pkg", data, 1)
		requireContainerPartial(t, s, "sample.pkg", "XAR entries were rejected")
	})
}

func newContainerCoverageScanner(logical, kind string, options Options) (*scanner, string) {
	s := &scanner{options: options.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: logical, Kind: kind, AnalyzeStatus: "analyzed"})
	return s, parentID
}

func requireContainerPartial(t *testing.T, s *scanner, logical, wantDetail string) {
	t.Helper()
	node := artifactNodeByLogical(s.graph.Nodes, logical)
	if node == nil || node.AnalyzeStatus != "partial" || !strings.Contains(node.CoverageDetail, wantDetail) {
		t.Fatalf("container %q should be partial with detail %q: %#v", logical, wantDetail, node)
	}
}

func requireContainerAnalyzed(t *testing.T, s *scanner, logical string) {
	t.Helper()
	node := artifactNodeByLogical(s.graph.Nodes, logical)
	if node == nil || node.AnalyzeStatus != "analyzed" || node.CoverageDetail != "" {
		t.Fatalf("container %q should remain analyzed after an isolated malformed member: %#v", logical, node)
	}
}

func testTarRegularFiles(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for _, name := range names {
		payload := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(payload))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
