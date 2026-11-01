package extract

import (
	"strings"
	"testing"
)

func TestHiddenUseStreamingRetainsLateWritesAfterRepeatedReferences(t *testing.T) {
	source := strings.Repeat("probe();\n", 10000) + "probe = replacement;"
	builder := javaScriptStructuralBuilder{source: source, limits: javaScriptStructuralLimits{uses: 2}, index: javaScriptStructuralIndex{Disposition: javaScriptStructuralComplete}}
	builder.recordHiddenUses(0, len(source), "scope")
	if builder.failed() || len(builder.index.HiddenUses) != 2 {
		t.Fatalf("repeated references exhausted distinct-name budget: %#v", builder.index)
	}
	for _, use := range builder.index.HiddenUses {
		if use.Name == "probe" && !use.Write {
			t.Fatal("late reassignment was lost")
		}
	}
}

func TestHiddenUseStreamingStillRejectsDistinctNameOverflow(t *testing.T) {
	source := "first(); second(); third();"
	builder := javaScriptStructuralBuilder{source: source, limits: javaScriptStructuralLimits{uses: 2}, index: javaScriptStructuralIndex{Disposition: javaScriptStructuralComplete}}
	builder.recordHiddenUses(0, len(source), "scope")
	if !builder.failed() || len(builder.index.HiddenUses) > 2 {
		t.Fatalf("distinct-name limit bypassed: %#v", builder.index)
	}
}

func TestJavaScriptConciseArrowSpanIncludesClosingCallToken(t *testing.T) {
	source := `function cleanup() { return () => receiver[Symbol.dispose]() }`
	index := buildJavaScriptStructuralIndex([]string{source})
	if index.Disposition == javaScriptStructuralMalformed || index.Disposition == javaScriptStructuralLimited {
		t.Fatalf("valid concise arrow was truncated: %#v", index)
	}
	found := false
	for _, use := range index.HiddenUses {
		found = found || use.Name == "receiver"
	}
	if !found {
		t.Fatalf("opaque callback lost hidden reference: %#v", index)
	}
}
