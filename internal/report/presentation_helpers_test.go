package report

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestExecutionRootTextLinesHandlesManyDistinctDocumentTypes(t *testing.T) {
	const count = 5_000
	roots := make([]behavior.ExecutionRoot, 0, count)
	for i := range count {
		roots = append(roots, behavior.ExecutionRoot{
			Kind: "document-handler",
			Name: fmt.Sprintf("type-%05d", i),
		})
	}
	lines := executionRootTextLines(roots, nil)
	if len(lines) != 1 || lines[0] != "document-handler -> 5000 registered document types" {
		t.Fatalf("executionRootTextLines() = %#v", lines)
	}
}

func TestArtifactPropertySourceLabelsDisambiguatesDuplicateBasenames(t *testing.T) {
	rep := Report{
		ArtifactNodes: []artifact.Node{
			{ID: "node-0001", LogicalPath: "Sample.app/Contents/Frameworks/A.framework/Versions/A/Helper"},
			{ID: "node-0002", LogicalPath: "Sample.app/Contents/Frameworks/B.framework/Versions/A/Helper"},
		},
	}

	labels := artifactPropertiesSourceLabels(rep)
	if labels["node-0001"] != "A.framework/Versions/A/Helper" || labels["node-0002"] != "B.framework/Versions/A/Helper" {
		t.Fatalf("unexpected fallback labels: %#v", labels)
	}
}

func TestArtifactPropertySourceLabelsHandlesManyDuplicateBasenames(t *testing.T) {
	const count = 2_000
	rep := Report{ArtifactNodes: make([]artifact.Node, count)}
	for i := range rep.ArtifactNodes {
		rep.ArtifactNodes[i] = artifact.Node{
			ID:          fmt.Sprintf("node-%04d", i),
			LogicalPath: fmt.Sprintf("Sample.app/Contents/Helpers/%04d/Helper", i),
		}
	}
	labels := artifactPropertiesSourceLabels(rep)
	if len(labels) != count || labels["node-0000"] != "0000/Helper" || labels["node-1999"] != "1999/Helper" {
		t.Fatalf("duplicate basename labels were not resolved linearly: first=%q last=%q count=%d", labels["node-0000"], labels["node-1999"], len(labels))
	}
}

func TestCompactTruncatesAtRuneBoundary(t *testing.T) {
	got := compact("x" + strings.Repeat("界", 130))
	if !utf8.ValidString(got) {
		t.Fatalf("compact returned invalid UTF-8: %q", got)
	}
	if count := utf8.RuneCountInString(got); count != 120 {
		t.Fatalf("compact rune count = %d, want 120", count)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("compact output missing ellipsis: %q", got)
	}
}

func TestEvidenceTextPreservesLocationsAndFallbacks(t *testing.T) {
	tests := []struct {
		name string
		view EvidenceView
		want string
	}{
		{
			name: "rich location",
			view: EvidenceView{Logical: "Sample.app/Contents/MacOS/Sample", Offset: 0x2a, VA: 0x100003f10, Function: "sub_100003f10", Arch: "arm64", Value: "posix_spawn"},
			want: "Sample.app/Contents/MacOS/Sample [func sub_100003f10, va 0x100003f10, offset 0x2a, arm64] posix_spawn",
		},
		{
			name: "known zero offset",
			view: EvidenceView{Logical: "Sample", OffsetKnown: true, Value: "~/Library/Application Support/Google/Chrome/Default/Cookies"},
			want: "Sample [offset 0x0] ~/Library/Application Support/Google/Chrome/Default/Cookies",
		},
		{
			name: "physical path and kind fallback",
			view: EvidenceView{Physical: "/tmp/sample", Kind: "imported-symbol"},
			want: "/tmp/sample imported-symbol",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := evidenceText(test.view); got != test.want {
				t.Fatalf("evidenceText() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestPresentationBoundsDiagnostics(t *testing.T) {
	rep := Report{Artifact: "sample"}
	for range textSectionLimit + 2 {
		rep.Diagnostics = append(rep.Diagnostics, "diagnostic")
	}

	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if count := strings.Count(got, "diagnostic: diagnostic"); count != textSectionLimit {
		t.Fatalf("printed %d diagnostics, want %d:\n%s", count, textSectionLimit, got)
	}
	if !strings.Contains(got, "... 2 more diagnostics") {
		t.Fatalf("missing diagnostics truncation hint:\n%s", got)
	}
}

func TestDiagnosticsForTextCompactsEncryptedZIPEntries(t *testing.T) {
	values := []string{
		"sample.zip!a: encrypted zip entry not inspected",
		"sample.zip!b: encrypted zip entry not inspected",
		"sample.zip!c: encrypted zip entry not inspected",
		"sample.zip!d: encrypted zip entry not inspected",
		"sample.zip!bad: rejected unsafe archive path",
	}
	got := diagnosticsForText(values)
	if !containsString(got, "4 encrypted zip entries not inspected") {
		t.Fatalf("missing encrypted ZIP summary: %#v", got)
	}
	if containsString(got, values[0]) {
		t.Fatalf("compacted diagnostics retained an individual encrypted entry: %#v", got)
	}
	if !containsString(got, values[len(values)-1]) {
		t.Fatalf("unrelated diagnostic was lost: %#v", got)
	}
}

func TestDiagnosticsForTextCompactsWrongZIPPasswords(t *testing.T) {
	values := []string{
		"sample.zip!a: wrong zip password",
		"sample.zip!b: wrong zip password",
		"sample.zip!c: wrong zip password",
		"sample.zip!d: wrong zip password",
	}
	got := diagnosticsForText(values)
	if !containsString(got, "4 encrypted zip entries skipped due to wrong password") {
		t.Fatalf("missing wrong-password summary: %#v", got)
	}
	if containsString(got, values[0]) {
		t.Fatalf("compacted diagnostics retained an individual wrong-password entry: %#v", got)
	}
}

func TestPathComponentsBoundsDelimiterAndComponentFloods(t *testing.T) {
	if testing.Short() {
		t.Skip("large hostile-input regression")
	}
	allSeparators := strings.Repeat("/", maxReportJSONStringBytes)
	if got := pathComponents(allSeparators); len(got) != 1 || got[0] != "/" {
		t.Fatalf("separator-only path components = %#v", got)
	}
	longComponent := strings.Repeat("x", maxReportJSONStringBytes)
	got := pathComponents(longComponent)
	if len(got) != 1 || len(got[0]) != maxSourceLabelComponentBytes {
		t.Fatalf("long path components = %d entries / %d bytes", len(got), len(got[0]))
	}
	many := strings.Repeat("a/", maxSourceLabelComponents+100) + "tail"
	got = pathComponents(many)
	if len(got) != maxSourceLabelComponents || got[len(got)-1] != "tail" {
		t.Fatalf("component ring did not retain the bounded suffix: len=%d last=%q", len(got), got[len(got)-1])
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
