package report

import (
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestSemanticIdentityKeyPreservesArbitraryFieldBoundaries(t *testing.T) {
	left := semanticIdentityKey("\xff\x00a", "b")
	right := semanticIdentityKey("\xff", "a\x00b")
	if left == right {
		t.Fatal("length-framed identities collided on NUL-delimited invalid UTF-8 values")
	}
	if left != semanticIdentityKey("\xff\x00a", "b") {
		t.Fatal("length-framed identity is not deterministic")
	}
	if semanticIdentityKey("a") == semanticIdentityKey("a", "") {
		t.Fatal("length-framed identity lost an empty trailing field")
	}
}

func TestSemanticGroupingPreservesNULDelimitedValues(t *testing.T) {
	t.Run("execution root arguments", func(t *testing.T) {
		items := []behavior.ExecutionRoot{
			{DeclarationNodeID: "node", StartNodeID: "node", Kind: "command", Name: "run", Arguments: []string{"a", "b"}},
			{DeclarationNodeID: "node", StartNodeID: "node", Kind: "command", Name: "run", Arguments: []string{"a\x00b"}},
		}
		if got := uniqueExecutionRoots(items); len(got) != 2 {
			t.Fatalf("distinct command argument boundaries collapsed: %#v", got)
		}
	})

	t.Run("capability fields", func(t *testing.T) {
		base := behavior.CapabilityMatch{
			Support: behavior.SupportCorroborated, Execution: testConnectedExecution(""),
			SubjectNodeID: "node", AffectedResources: []behavior.Resource{{Kind: behavior.ResourceFile, Value: "/tmp/x"}},
		}
		left, right := base, base
		left.RuleID, left.Title = "a", "b\x00c"
		right.RuleID, right.Title = "a\x00b", "c"
		if got := groupCapabilityMatches([]behavior.CapabilityMatch{left, right}); len(got) != 2 {
			t.Fatalf("distinct capability fields collapsed: %#v", got)
		}
	})

	t.Run("capability resources", func(t *testing.T) {
		base := behavior.CapabilityMatch{
			RuleID: "rule", Title: "title", Support: behavior.SupportCorroborated,
			Execution: testConnectedExecution(""), SubjectNodeID: "node",
		}
		left, right := base, base
		left.AffectedResources = []behavior.Resource{{Kind: behavior.ResourceKind("a"), Value: "b\x00c"}}
		right.AffectedResources = []behavior.Resource{{Kind: behavior.ResourceKind("a\x00b"), Value: "c"}}
		if got := groupCapabilityMatches([]behavior.CapabilityMatch{left, right}); len(got) != 2 {
			t.Fatalf("distinct capability resources collapsed: %#v", got)
		}
	})

	t.Run("artifact property", func(t *testing.T) {
		items := []behavior.ArtifactProperty{
			{NodeID: "a", Kind: "b\x00c", Value: "d", Support: behavior.SupportDirect},
			{NodeID: "a\x00b", Kind: "c", Value: "d", Support: behavior.SupportDirect},
		}
		if got := uniqueArtifactProperties(items, true); len(got) != 2 {
			t.Fatalf("human artifact-property inventory collapsed distinct values: %#v", got)
		}
		if got := dedupeArtifactProperties(items); len(got) != 2 {
			t.Fatalf("final report collapsed distinct artifact-property values: %#v", got)
		}
	})

	t.Run("network fields and sets", func(t *testing.T) {
		items := []networkPresentationRecord{
			{Caller: "a", HTTPStack: "b\x00c", Security: []string{"x", "y"}, Destinations: []string{"one"}},
			{Caller: "a\x00b", HTTPStack: "c", Security: []string{"x\x00y"}, Destinations: []string{"two"}},
		}
		if got := uniqueNetworkWithContext(items, nil); len(got) != 2 {
			t.Fatalf("distinct network fields or security sets collapsed: %#v", got)
		}
	})

	t.Run("feature fields and qualifiers", func(t *testing.T) {
		items := []behavior.Feature{
			{NodeID: "node", Key: "key", Value: "value", Support: behavior.SupportCorroborated, Qualifiers: map[string]string{"a": "b\x00c"}},
			{NodeID: "node", Key: "key", Value: "value", Support: behavior.SupportCorroborated, Qualifiers: map[string]string{"a\x00b": "c"}},
		}
		if got := uniqueFeatures(items); len(got) != 2 {
			t.Fatalf("distinct feature qualifiers collapsed: %#v", got)
		}
	})

	t.Run("coverage", func(t *testing.T) {
		items := []behavior.Coverage{
			{AnalysisArea: "a", Status: "b\x00c", Detail: "d"},
			{AnalysisArea: "a\x00b", Status: "c", Detail: "d"},
		}
		if got := uniqueCoverage(items); len(got) != 2 {
			t.Fatalf("distinct coverage records collapsed: %#v", got)
		}
	})
}
