package extract

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestRustConstantBase64RetainsDerivedURLWithEveryFragmentEvidence(t *testing.T) {
	first := base64.StdEncoding.EncodeToString([]byte("endpoint=https://203.0.113.8:9089/"))
	second := base64.StdEncoding.EncodeToString([]byte("payload"))
	source := `const PARTS: &[&str] = &["` + first + `", r#"` + second + `"#];
fn main() { println!("inert"); }
`
	graph := extractRustFixture(t, source)
	if !hasFeatureValue(graph, "network.url", "https://203.0.113.8:9089/payload") {
		t.Fatalf("decoded URL missing: %#v", graph.Features)
	}
	for _, feature := range graph.Features {
		if feature.Key == "network.url" && feature.Value == "https://203.0.113.8:9089/payload" {
			if len(feature.EvidenceIDs) != 2 || feature.Qualifiers["transformation"] != "canonical-base64-constant" || feature.Qualifiers["runtime_use"] != "not-established" {
				t.Fatalf("decoded URL lineage = %#v", feature)
			}
		}
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("constant data became behavior: %#v", graph.Operations)
	}
}

func TestRustConstantBase64CloseNegatives(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("https://must-not-appear.example/p"))
	tests := map[string]string{
		"dynamic element":   `const X: &[&str] = &["` + encoded[:8] + `", suffix];`,
		"cross declaration": `const A: &str = "` + encoded[:8] + `"; const B: &str = "` + encoded[8:] + `";`,
		"noncanonical":      `const X: &str = "` + strings.TrimRight(base64.StdEncoding.EncodeToString([]byte("https://must-not-appear.example/p?x")), "=") + `";`,
		"comment":           `// const X: &str = "` + encoded + `";`,
		"macro body":        `macro_rules! x { () => { const X: &str = "` + encoded + `"; } }`,
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			graph := extractRustFixture(t, "fn main() {}\n"+source)
			if hasFeatureValue(graph, "network.url", "https://must-not-appear.example/p") {
				t.Fatalf("close negative produced decoded URL: %#v", graph.Features)
			}
		})
	}
}

func TestRustConstantBase64CumulativeDecodeBudgetIsExplicit(t *testing.T) {
	large := strings.Repeat("A", 3<<20)
	source := `const FIRST: &str = "` + large + `";
const SECOND: &str = "` + large + `";
fn main() {}
`
	graph := extractRustFixture(t, source)
	derived := 0
	for _, feature := range graph.Features {
		if feature.Key == "derived.base64.content" {
			derived++
		}
	}
	if derived != 0 {
		t.Fatalf("non-semantic decoded constants produced %d observable fingerprints", derived)
	}
	for _, item := range graph.Coverage {
		if item.AnalysisArea == "rust-constant-observations" && item.Status == "partial" {
			return
		}
	}
	t.Fatalf("missing Rust constant budget coverage: %#v", graph.Coverage)
}
