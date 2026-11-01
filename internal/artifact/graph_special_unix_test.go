//go:build darwin || linux

package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestDirectoryTraversalRepresentsFIFOWithoutOpeningIt(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "regular.txt"), []byte("safe sibling\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fifoPath := filepath.Join(root, "hostile.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := InspectPath(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	logical := filepath.Base(root) + "/hostile.fifo"
	node := artifactNodeByLogical(result.Graph.Nodes, logical)
	if node == nil || node.Kind != "named-pipe" || node.MediaType != "inode/fifo" || node.AnalyzeStatus != "skipped" {
		t.Fatalf("FIFO must be retained as a skipped special-file node: %#v", node)
	}
	if !strings.Contains(node.CoverageDetail, "not opened") {
		t.Fatalf("FIFO coverage does not explain the safety boundary: %#v", node)
	}
	if contentByLogical(result.Contents, logical) != nil {
		t.Fatalf("FIFO was queued as readable content: %#v", result.Contents)
	}
	if contentByLogical(result.Contents, filepath.Base(root)+"/regular.txt") == nil {
		t.Fatalf("regular sibling was not inspected: %#v", result.Contents)
	}
}
