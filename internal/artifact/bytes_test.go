package artifact

import (
	"strings"
	"testing"
)

func TestInspectBytesExpandsContainersAndHonorsDisableOption(t *testing.T) {
	data := testZipFile(t, "payload.txt", []byte("bounded payload\n"))

	expanded, err := InspectBytes("sample.input", data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(expanded.Graph.Nodes) != 2 {
		t.Fatalf("in-memory ZIP was not expanded: %#v", expanded.Graph.Nodes)
	}
	root := expanded.Graph.Nodes[0]
	child := expanded.Graph.Nodes[1]
	if root.ParentID != "" || root.LogicalPath != "sample.input" || root.Kind != "zip" || root.PhysicalPath != "" {
		t.Fatalf("unexpected in-memory root: %#v", root)
	}
	if child.ParentID != root.ID || child.LogicalPath != "sample.input!payload.txt" || child.PhysicalPath != "" {
		t.Fatalf("unexpected in-memory ZIP child: %#v", child)
	}
	if len(expanded.Contents) != 2 {
		t.Fatalf("in-memory ZIP did not retain root and child contents: %#v", expanded.Contents)
	}

	disabled, err := InspectBytes("sample.input", data, Options{DisableContainerExpansion: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(disabled.Graph.Nodes) != 1 || disabled.Graph.Nodes[0].Kind != "zip" {
		t.Fatalf("disabled container expansion modeled children: %#v", disabled.Graph.Nodes)
	}
	if disabled.Graph.Nodes[0].AnalyzeStatus != "partial" ||
		!strings.Contains(disabled.Graph.Nodes[0].CoverageDetail, "container expansion skipped") {
		t.Fatalf("disabled container expansion lacks explicit coverage: %#v", disabled.Graph.Nodes[0])
	}
}

func TestInspectBytesEnforcesRootByteBudgets(t *testing.T) {
	if _, err := InspectBytes("sample", []byte("12345"), Options{MaxFileBytes: 4}); err == nil || !strings.Contains(err.Error(), "max file bytes 4") {
		t.Fatalf("file-byte limit error = %v", err)
	}
	if _, err := InspectBytes("sample", []byte("12345"), Options{MaxFileBytes: 10, MaxTotalBytes: 4}); err == nil || !strings.Contains(err.Error(), "retained-byte limit 4") {
		t.Fatalf("retained-byte limit error = %v", err)
	}
	if _, err := InspectBytes("", nil, Options{}); err == nil || !strings.Contains(err.Error(), "logical path") {
		t.Fatalf("empty logical path error = %v", err)
	}
}
