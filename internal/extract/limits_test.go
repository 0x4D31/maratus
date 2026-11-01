package extract

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestBoundedTextCapsNewlineDenseInput(t *testing.T) {
	data := bytes.Repeat([]byte{'\n'}, maxTextAnalysisLines+100)
	input := boundedText(data)
	if len(input.Lines) != maxTextAnalysisLines || !input.LinesTruncated {
		t.Fatalf("newline-dense input yielded %d lines, truncated=%v", len(input.Lines), input.LinesTruncated)
	}
	if input.BytesTruncated || input.LongLines != 0 {
		t.Fatalf("unexpected secondary limits: %#v", input)
	}

	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "sample.sh", Kind: "script", MediaType: "text/plain", Data: data})
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "text-analysis" || graph.Coverage[0].Status != "partial" {
		t.Fatalf("ExtractText did not report its line limit: %#v", graph.Coverage)
	}
}

func TestBoundedTextCapsBytesAndLongLinesWithCoverage(t *testing.T) {
	data := bytes.Repeat([]byte{'x'}, maxTextAnalysisBytes+1)
	input := boundedText(data)
	if !input.BytesTruncated || input.LongLines != 1 || len(input.Lines) != 1 || len(input.Lines[0]) != maxTextAnalysisLineBytes {
		t.Fatalf("unexpected bounded text result: bytes=%v long=%d lines=%d first=%d", input.BytesTruncated, input.LongLines, len(input.Lines), len(input.Lines[0]))
	}
	var graph behavior.Graph
	addBoundedTextCoverage(&graph, artifact.Content{NodeID: "node-1"}, "text-analysis", input)
	if len(graph.Coverage) != 1 || graph.Coverage[0].Status != "partial" || !strings.Contains(graph.Coverage[0].Detail, "first 33554432 bytes") {
		t.Fatalf("missing explicit partial coverage: %#v", graph.Coverage)
	}
}

func TestDecodeLiteralBase64BoundsInputBeforeDecode(t *testing.T) {
	if decoded, ok := decodeLiteralBase64(strings.Repeat("A", maxEncodedInlineBytes+1)); ok || decoded != nil {
		t.Fatal("oversized encoded literal should be rejected")
	}
	if decoded, ok := decodeLiteralBase64(strings.Repeat(" ", maxInlineWhitespaceBytes+1)); ok || decoded != nil {
		t.Fatal("oversized whitespace wrapper should be rejected")
	}

	want := bytes.Repeat([]byte{'a'}, maxDecodedInlineBytes)
	encoded := base64.StdEncoding.EncodeToString(want)
	got, ok := decodeLiteralBase64(encoded)
	if !ok || !bytes.Equal(got, want) {
		t.Fatalf("maximum allowed payload did not round-trip: ok=%v len=%d", ok, len(got))
	}
}

func TestASCIIStringRunsCapSingleRunAndCount(t *testing.T) {
	runs, truncated := asciiStringRuns(bytes.Repeat([]byte{'a'}, maxMachOASCIIStringBytes+1), 2)
	if !truncated || len(runs) != 1 || len(runs[0].Value) != maxMachOASCIIStringBytes {
		t.Fatalf("long run was not bounded: truncated=%v runs=%d len=%d", truncated, len(runs), len(runs[0].Value))
	}

	data := bytes.Repeat([]byte{'a', 0}, maxMachOASCIIStringRuns+1)
	runs, truncated = asciiStringRuns(data, 1)
	if !truncated || len(runs) != maxMachOASCIIStringRuns {
		t.Fatalf("run count was not bounded: truncated=%v runs=%d", truncated, len(runs))
	}

	budget := asciiRunBudget{scanBytesRemaining: 4, runsRemaining: 10, bytesRemaining: 10}
	runs = budget.scan([]byte("abcdef"), 1)
	if !budget.truncated || budget.scanBytesRemaining != 0 || len(runs) != 1 || runs[0].Value != "abcd" {
		t.Fatalf("input scan was not bounded: budget=%#v runs=%#v", budget, runs)
	}
}

func TestMachORegexMatchesAreBounded(t *testing.T) {
	value := strings.Repeat("1.1.1.1 ", maxMachORegexMatches+1)
	matches, truncated := limitedMachOIPv4Matches(value)
	if !truncated || len(matches) != maxMachORegexMatches {
		t.Fatalf("regex matches were not bounded: truncated=%v matches=%d", truncated, len(matches))
	}
}

func TestCFStringRecordScanIsBounded(t *testing.T) {
	data := make([]byte, (maxMachOObjectiveCRecords+1)*32)
	_, truncated := cfStringLiteralsFromDataBounded(binary.LittleEndian, 0, 0, data, func(uint64, uint64) (string, uint64, int, bool) {
		return "", 0, 0, false
	})
	if !truncated {
		t.Fatal("oversized CFString table should report partial analysis")
	}
}

func TestStructuredDocumentParserInputIsBoundedAndReportedOnce(t *testing.T) {
	content := artifact.Content{
		NodeID:      "node-1",
		LogicalPath: "package.json",
		Kind:        "manifest",
		Data:        bytes.Repeat([]byte{' '}, maxStructuredDocumentBytes+1),
	}
	var graph behavior.Graph
	ExtractPackageHooks(&graph, content)
	ResolvePackageScriptTargets(&graph, []artifact.Content{content})
	ResolveVSCodeExtensionEntrypoints(&graph, []artifact.Content{content})
	if len(graph.Coverage) != 1 {
		t.Fatalf("structured decoder coverage = %#v, want one deduplicated marker", graph.Coverage)
	}
	coverage := graph.Coverage[0]
	if coverage.AnalysisArea != "package-json" || coverage.Status != "partial" || !strings.Contains(coverage.Detail, "parser input limit") {
		t.Fatalf("structured decoder coverage = %#v", coverage)
	}
}

func TestOversizedPlistDecodeIsSkippedWithPartialCoverage(t *testing.T) {
	content := artifact.Content{
		NodeID:      "node-1",
		LogicalPath: "Info.plist",
		Kind:        "plist",
		Data:        bytes.Repeat([]byte{' '}, maxStructuredDocumentBytes+1),
	}
	var graph behavior.Graph
	ExtractPlist(&graph, content, PlistExecutionStart{})
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "plist" || graph.Coverage[0].Status != "partial" {
		t.Fatalf("plist decoder coverage = %#v", graph.Coverage)
	}
}

func TestMalformedPackageManifestReportsPartialCoverageOnce(t *testing.T) {
	content := artifact.Content{NodeID: "node-1", LogicalPath: "package.json", Kind: "manifest", Data: []byte(`{"scripts":`)}
	var graph behavior.Graph
	ExtractPackageHooks(&graph, content)
	ResolvePackageScriptTargets(&graph, []artifact.Content{content})
	ResolveVSCodeExtensionEntrypoints(&graph, []artifact.Content{content})
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "package-json" || graph.Coverage[0].Status != "partial" || !strings.Contains(graph.Coverage[0].Detail, "decode failed") {
		t.Fatalf("malformed package coverage = %#v", graph.Coverage)
	}
}
