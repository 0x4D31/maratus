package report

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/rules"
)

func TestArtifactAncestryPreservesForestBoundaries(t *testing.T) {
	// Deliberately put children before their parents and interleave trees.
	nodes := []artifact.Node{
		{ID: "leaf", ParentID: "left"},
		{ID: "other-leaf", ParentID: "other"},
		{ID: "root"},
		{ID: "right", ParentID: "root"},
		{ID: "left", ParentID: "root"},
		{ID: "other"},
	}
	parents := make(map[string]string, len(nodes))
	for _, node := range nodes {
		parents[node.ID] = node.ParentID
	}
	ancestry := indexArtifactAncestry(nodes, parents)
	wantAncestors := map[[2]string]bool{
		{"root", "left"}: true, {"root", "right"}: true,
		{"root", "leaf"}: true, {"left", "leaf"}: true,
		{"other", "other-leaf"}: true,
	}
	ids := []string{"", "missing", "root", "left", "right", "leaf", "other", "other-leaf"}
	for _, ancestor := range ids {
		for _, node := range ids {
			if got, want := ancestry.isAncestor(ancestor, node), wantAncestors[[2]string{ancestor, node}]; got != want {
				t.Errorf("isAncestor(%q, %q) = %v, want %v", ancestor, node, got, want)
			}
		}
	}
	if !containmentRelatedNodes("root", "leaf", ancestry) || !containmentRelatedNodes("leaf", "root", ancestry) {
		t.Fatal("ancestor and descendant proofs must remain containment-related")
	}
	if containmentRelatedNodes("left", "right", ancestry) || containmentRelatedNodes("leaf", "other-leaf", ancestry) {
		t.Fatal("sibling and separate-tree evidence must not become containment-related")
	}
	if !sameContainerOrContainmentRelated("left", "right", ancestry) || sameContainerOrContainmentRelated("leaf", "other-leaf", ancestry) {
		t.Fatal("same-container proof must preserve the exact shared parent")
	}
}

func TestDecodeReportDeepArtifactContainment(t *testing.T) {
	// Both dimensions are legal independently. Repeated root-to-leaf evidence
	// checks must not walk this entire chain for every relationship.
	rep := deepArtifactContainmentReport(artifact.DefaultMaxArtifactNodes)
	var encoded bytes.Buffer
	if err := WriteJSON(&encoded, rep); err != nil {
		t.Fatal(err)
	}
	loaded, err := decodeReport(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatalf("valid deep report failed strict reload: %v", err)
	}
	if len(loaded.ArtifactNodes) != len(rep.ArtifactNodes) || len(loaded.Relationships) != len(rep.Relationships) {
		t.Fatal("strict reload lost deep artifact nodes or evidence relationships")
	}
	// An otherwise identical proof from another tree must still fail closed.
	loaded.ArtifactNodes[len(loaded.ArtifactNodes)-1].ParentID = ""
	loaded.Relationships[0].To = loaded.ArtifactNodes[0].ID
	if err := validateReportReferences(loaded); err == nil {
		t.Fatal("unrelated leaf evidence was accepted after separating its tree")
	}
}

func BenchmarkDecodeReportDeepArtifactContainment(b *testing.B) {
	for _, count := range []int{1000, 10000, artifact.DefaultMaxArtifactNodes} {
		b.Run(fmt.Sprintf("nodes-%d", count), func(b *testing.B) {
			var encoded bytes.Buffer
			if err := WriteJSON(&encoded, deepArtifactContainmentReport(count)); err != nil {
				b.Fatal(err)
			}
			data := encoded.Bytes()
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := decodeReport(bytes.NewReader(data)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func deepArtifactContainmentReport(count int) Report {
	rep := Report{
		SchemaVersion: SchemaVersion, Tool: "maratus", ToolVersion: "test",
		RulesetVersion: RulesetVersion, RuleCatalogDigest: rules.CatalogDigest(),
		Analysis: normalizedAnalysisMetadata(artifact.Options{MaxDirectoryDepth: count}),
		Artifact: "deep-fixture", ArtifactNodes: make([]artifact.Node, count),
		Relationships: make([]artifact.Edge, count),
	}
	for index := range rep.ArtifactNodes {
		id := fmt.Sprintf("node-%d", index)
		rep.ArtifactNodes[index] = artifact.Node{ID: id, LogicalPath: id, Kind: "directory", AnalyzeStatus: "analyzed"}
		if index > 0 {
			rep.ArtifactNodes[index].ParentID = rep.ArtifactNodes[index-1].ID
		}
	}
	leaf := rep.ArtifactNodes[count-1].ID
	rep.Evidence = []behavior.Evidence{{ID: "ev-leaf", NodeID: leaf, Method: "fixture", Kind: "fixture"}}
	for index := range rep.Relationships {
		rep.Relationships[index] = artifact.Edge{
			From: rep.ArtifactNodes[0].ID, To: leaf, Kind: "contains", EvidenceIDs: []string{"ev-leaf"},
		}
	}
	return rep
}
