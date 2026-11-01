package report

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
)

func TestArtifactPropertySourceLabelsBoundsDuplicatePathDisambiguation(t *testing.T) {
	const (
		nodeCount      = 4096
		componentCount = 128
	)
	nodes := make([]artifact.Node, nodeCount)
	for i := range nodes {
		parts := make([]string, componentCount)
		for j := 0; j < len(parts)-1; j++ {
			parts[j] = fmt.Sprintf("p%d_%d", i, j)
		}
		parts[len(parts)-1] = "same"
		nodes[i] = artifact.Node{ID: fmt.Sprintf("node-%d", i), LogicalPath: strings.Join(parts, "/")}
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	labels := artifactPropertiesSourceLabels(Report{ArtifactNodes: nodes})
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > 128<<20 {
		t.Fatalf("artifactPropertiesSourceLabels allocated %d bytes for duplicate paths; disambiguation work must remain bounded", allocated)
	}
	if len(labels) != nodeCount {
		t.Fatalf("artifactPropertiesSourceLabels retained %d labels, want %d", len(labels), nodeCount)
	}
	for _, node := range nodes {
		if labels[node.ID] == "" || len(labels[node.ID]) > maxSourceLabelComponentBytes {
			t.Fatalf("missing or unbounded fallback label for %s: %q", node.ID, labels[node.ID])
		}
	}
}
