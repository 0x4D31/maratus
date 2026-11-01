package report

import (
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestDiagnosticLimiterIsBoundedDeduplicatedAndUTF8Safe(t *testing.T) {
	options := artifact.Options{}.Normalized()
	options.MaxDiagnostics = 2
	options.MaxDiagnosticBytes = 80
	got := limitDiagnosticStrings([]string{" first ", "first", strings.Repeat("é", 50), "third"}, options)
	if len(got) > options.MaxDiagnostics {
		t.Fatalf("diagnostic count = %d, want <= %d: %#v", len(got), options.MaxDiagnostics, got)
	}
	var bytes int
	for _, value := range got {
		if strings.ToValidUTF8(value, "?") != value {
			t.Fatalf("invalid UTF-8 diagnostic: %q", value)
		}
		bytes += len(value)
	}
	if int64(bytes) > options.MaxDiagnosticBytes {
		t.Fatalf("diagnostic bytes = %d, want <= %d: %#v", bytes, options.MaxDiagnosticBytes, got)
	}
	if len(got) == 0 || !strings.Contains(got[len(got)-1], "diagnostic budget reached") {
		t.Fatalf("missing omission summary: %#v", got)
	}
}

func TestEvidenceDropDiagnosticsDistinguishCountAndStringLimits(t *testing.T) {
	got := evidenceDropDiagnostics(behavior.Graph{
		EvidenceLimit:       7,
		EvidenceLimitDrops:  2,
		StringByteLimit:     1024,
		EvidenceStringDrops: 3,
	})
	want := []string{
		"evidence object limit 7 reached; omitted at least 2 evidence objects",
		"retained string byte limit 1024 reached; omitted at least 3 evidence objects",
	}
	if len(got) != len(want) {
		t.Fatalf("diagnostics = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("diagnostics = %#v, want %#v", got, want)
		}
	}
}

func TestEvidenceDropDiagnosticsUseSingularObjectWording(t *testing.T) {
	got := evidenceDropDiagnostics(behavior.Graph{EvidenceLimit: 7, EvidenceLimitDrops: 1})
	want := "evidence object limit 7 reached; omitted at least 1 evidence object"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("diagnostics = %#v, want %q", got, want)
	}
}
