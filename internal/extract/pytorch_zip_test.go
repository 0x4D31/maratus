package extract

import (
	"archive/zip"
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	ruleengine "github.com/0x4D31/maratus/internal/rules"
)

func TestPyTorchZIPRecognitionVariants(t *testing.T) {
	tests := []struct {
		name         string
		protocol     byte
		version      string
		corroborator string
		value        []byte
	}{
		{name: "little byte order", protocol: 2, version: "3\n", corroborator: "byteorder", value: []byte("little")},
		{name: "big byte order", protocol: 5, version: "10", corroborator: "byteorder", value: []byte("big\n")},
		{name: "serialization identifier", protocol: 4, version: "3", corroborator: ".data/serialization_id", value: []byte("05768588573859962782")},
		{name: "numeric storage record", protocol: 3, version: "3", corroborator: "data/0", value: []byte{1, 2, 3, 4}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := map[string][]byte{
				"model/data.pkl":             testPickleWithProtocol(test.protocol),
				"model/version":              []byte(test.version),
				"model/" + test.corroborator: test.value,
			}
			inspection, graph := runPyTorchZIPFixture(t, entries, artifact.Options{})
			rootID := pyTorchZIPRootNodeID(t, inspection)
			dataNodeID := pyTorchZIPChildNodeID(t, inspection, "model/data.pkl")

			if len(graph.ArtifactProperties) != 1 {
				t.Fatalf("artifact properties = %#v, want one serialization format", graph.ArtifactProperties)
			}
			property := graph.ArtifactProperties[0]
			if property.NodeID != rootID || property.Kind != "serialization-format" || property.Value != "pytorch-zip" ||
				property.Support != behavior.SupportCorroborated || len(property.EvidenceIDs) != 3 {
				t.Fatalf("serialization format property = %#v", property)
			}
			assertPyTorchZIPEvidence(t, inspection, graph, property.EvidenceIDs, []string{
				"model/data.pkl",
				"model/version",
				"model/" + test.corroborator,
			})
			if !hasCoverageArea(graph, dataNodeID, "pytorch-pickle-semantics", "partial") {
				t.Fatalf("missing Pickle semantic boundary on data.pkl: %#v", graph.Coverage)
			}
			assertPyTorchZIPInventoryOnly(t, &graph)
		})
	}
}

func TestPyTorchZIPRecognitionCloseNegatives(t *testing.T) {
	validData := testPickleWithProtocol(4)
	validEntries := func() map[string][]byte {
		return map[string][]byte{
			"model/data.pkl":  validData,
			"model/version":   []byte("3"),
			"model/byteorder": []byte("little"),
		}
	}
	tests := []struct {
		name   string
		mutate func(map[string][]byte)
	}{
		{
			name: "ordinary zip",
			mutate: func(entries map[string][]byte) {
				clear(entries)
				entries["model/README.md"] = []byte("not a serialized model")
			},
		},
		{
			name:   "missing version",
			mutate: func(entries map[string][]byte) { delete(entries, "model/version") },
		},
		{
			name:   "missing corroborator",
			mutate: func(entries map[string][]byte) { delete(entries, "model/byteorder") },
		},
		{
			name: "mixed prefixes",
			mutate: func(entries map[string][]byte) {
				delete(entries, "model/byteorder")
				entries["other/byteorder"] = []byte("little")
			},
		},
		{
			name: "multiple checkpoint prefixes",
			mutate: func(entries map[string][]byte) {
				entries["other/data.pkl"] = validData
				entries["other/version"] = []byte("3")
				entries["other/byteorder"] = []byte("big")
			},
		},
		{
			name:   "unsupported pickle protocol",
			mutate: func(entries map[string][]byte) { entries["model/data.pkl"] = testPickleWithProtocol(6) },
		},
		{
			name:   "missing pickle protocol opcode",
			mutate: func(entries map[string][]byte) { entries["model/data.pkl"] = []byte("N.") },
		},
		{
			name:   "nonpositive version",
			mutate: func(entries map[string][]byte) { entries["model/version"] = []byte("0\n") },
		},
		{
			name:   "nondigit version",
			mutate: func(entries map[string][]byte) { entries["model/version"] = []byte("3.0") },
		},
		{
			name:   "invalid byte order",
			mutate: func(entries map[string][]byte) { entries["model/byteorder"] = []byte("middle") },
		},
		{
			name: "invalid serialization identifier",
			mutate: func(entries map[string][]byte) {
				delete(entries, "model/byteorder")
				entries["model/.data/serialization_id"] = []byte("12x")
			},
		},
		{
			name: "nonnumeric storage record",
			mutate: func(entries map[string][]byte) {
				delete(entries, "model/byteorder")
				entries["model/data/key"] = []byte{1}
			},
		},
		{
			name: "close filenames",
			mutate: func(entries map[string][]byte) {
				delete(entries, "model/data.pkl")
				delete(entries, "model/version")
				entries["model/data.pkl.bak"] = validData
				entries["model/version.txt"] = []byte("3")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := validEntries()
			test.mutate(entries)
			_, graph := runPyTorchZIPFixture(t, entries, artifact.Options{})
			assertNoPyTorchZIPRecognition(t, graph)
		})
	}
}

func TestPyTorchZIPPartialContainerDoesNotEstablishFormat(t *testing.T) {
	entries := map[string][]byte{
		"model/data.pkl":  testPickleWithProtocol(4),
		"model/version":   []byte("3"),
		"model/byteorder": []byte("little"),
	}
	inspection, graph := runPyTorchZIPFixture(t, entries, artifact.Options{DisableContainerExpansion: true})
	rootID := pyTorchZIPRootNodeID(t, inspection)
	root := pyTorchZIPNodeByID(inspection.Graph.Nodes, rootID)
	if root == nil || root.AnalyzeStatus != "partial" {
		t.Fatalf("disabled expansion did not make ZIP coverage partial: %#v", root)
	}
	assertNoPyTorchZIPRecognition(t, graph)
}

func TestPyTorchZIPRecognitionIsIndependentOfSpecializedZIPKind(t *testing.T) {
	entries := map[string][]byte{
		"model/data.pkl":  testPickleWithProtocol(4),
		"model/version":   []byte("3"),
		"model/byteorder": []byte("little"),
	}
	inspection, graph := runNamedPyTorchZIPFixture(t, "checkpoint.whl", entries, artifact.Options{})
	rootID := pyTorchZIPRootNodeID(t, inspection)
	root := pyTorchZIPNodeByID(inspection.Graph.Nodes, rootID)
	if root == nil || root.Kind != "python-wheel" || root.MediaType != "application/zip" {
		t.Fatalf("specialized ZIP kind was not retained: %#v", root)
	}
	if len(graph.ArtifactProperties) != 1 ||
		graph.ArtifactProperties[0].NodeID != rootID ||
		graph.ArtifactProperties[0].Kind != "serialization-format" ||
		graph.ArtifactProperties[0].Value != "pytorch-zip" {
		t.Fatalf("PyTorch structure depended on generic ZIP kind: %#v", graph.ArtifactProperties)
	}
	assertPyTorchZIPInventoryOnly(t, &graph)
}

func TestPyTorchZIPRecognitionIsDeterministic(t *testing.T) {
	entries := map[string][]byte{
		"model/data.pkl":               testPickleWithProtocol(5),
		"model/version":                []byte("3"),
		"model/byteorder":              []byte("little"),
		"model/.data/serialization_id": []byte("123456789"),
		"model/data/0":                 []byte{1},
	}
	_, first := runPyTorchZIPFixture(t, entries, artifact.Options{})
	_, second := runPyTorchZIPFixture(t, entries, artifact.Options{})
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("identical PyTorch ZIP inspections differ:\nfirst=%#v\nsecond=%#v", first, second)
	}
	property := first.ArtifactProperties[0]
	assertEvidenceLogicalPaths(t, first, property.EvidenceIDs, []string{
		"checkpoint.pt!model/byteorder",
		"checkpoint.pt!model/data.pkl",
		"checkpoint.pt!model/version",
	})
}

func TestPyTorchZIPHostileEntryCountIsBoundedAndFailsClosed(t *testing.T) {
	const maxNodes = 32
	entries := map[string][]byte{
		"0000/model/data.pkl":  testPickleWithProtocol(4),
		"0000/model/version":   []byte("3"),
		"0000/model/byteorder": []byte("little"),
	}
	for index := 0; index < 256; index++ {
		entries[fmt.Sprintf("decoys/%04d.bin", index)] = []byte{byte(index)}
	}
	inspection, graph := runPyTorchZIPFixture(t, entries, artifact.Options{MaxArtifactNodes: maxNodes})
	if len(inspection.Graph.Nodes) > maxNodes {
		t.Fatalf("artifact node limit exceeded: got %d, limit %d", len(inspection.Graph.Nodes), maxNodes)
	}
	root := pyTorchZIPNodeByID(inspection.Graph.Nodes, pyTorchZIPRootNodeID(t, inspection))
	if root == nil || root.AnalyzeStatus != "partial" || !strings.Contains(root.CoverageDetail, "node limit") {
		t.Fatalf("hostile archive did not retain bounded partial coverage: %#v", root)
	}
	assertNoPyTorchZIPRecognition(t, graph)
}

func runPyTorchZIPFixture(t *testing.T, entries map[string][]byte, options artifact.Options) (artifact.Result, behavior.Graph) {
	t.Helper()
	return runNamedPyTorchZIPFixture(t, "checkpoint.pt", entries, options)
}

func runNamedPyTorchZIPFixture(t *testing.T, name string, entries map[string][]byte, options artifact.Options) (artifact.Result, behavior.Graph) {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	// Stable fixture bytes keep the artifact graph IDs and evidence ordering
	// reproducible without making the recognizer depend on ZIP entry order.
	sort.Strings(names)
	for _, name := range names {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("create ZIP entry %q: %v", name, err)
		}
		if _, err := entry.Write(entries[name]); err != nil {
			t.Fatalf("write ZIP entry %q: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close ZIP fixture: %v", err)
	}
	inspection, err := artifact.InspectBytes(name, output.Bytes(), options)
	if err != nil {
		t.Fatalf("inspect ZIP fixture: %v", err)
	}
	graph := Run(Context{
		Artifacts: &inspection.Graph,
		Contents:  inspection.Contents,
		Options:   inspection.Options,
	})
	return inspection, graph
}

func testPickleWithProtocol(protocol byte) []byte {
	return []byte{0x80, protocol, 'N', '.'}
}

func assertPyTorchZIPEvidence(t *testing.T, inspection artifact.Result, graph behavior.Graph, evidenceIDs, childPaths []string) {
	t.Helper()
	expected := make(map[string]bool, len(childPaths))
	for _, childPath := range childPaths {
		expected["checkpoint.pt!"+childPath] = !strings.Contains(childPath, "/data/")
	}
	if len(evidenceIDs) != len(expected) {
		t.Fatalf("evidence IDs = %#v, want one per exact proof child %#v", evidenceIDs, expected)
	}
	seen := map[string]bool{}
	for _, evidenceID := range evidenceIDs {
		evidence := pyTorchZIPEvidenceByID(graph.Evidence, evidenceID)
		if evidence == nil {
			t.Fatalf("property references missing evidence %q: %#v", evidenceID, graph.Evidence)
			return
		}
		node := pyTorchZIPNodeByID(inspection.Graph.Nodes, evidence.NodeID)
		offsetKnown, expectedPath := expected[evidence.Logical]
		if node == nil || node.LogicalPath != evidence.Logical || !expectedPath ||
			evidence.Method != "pytorch-zip-recognizer" ||
			evidence.OffsetKnown != offsetKnown ||
			(evidence.OffsetKnown && evidence.Offset != 0) {
			t.Fatalf("evidence %q is not exact child proof: evidence=%#v node=%#v", evidenceID, evidence, node)
		}
		if node.ParentID != pyTorchZIPRootNodeID(t, inspection) {
			t.Fatalf("evidence child %q belongs to unexpected parent %q", node.LogicalPath, node.ParentID)
		}
		seen[evidence.Logical] = offsetKnown
	}
	if !reflect.DeepEqual(seen, expected) {
		t.Fatalf("evidence paths = %#v, want %#v", seen, expected)
	}
}

func assertPyTorchZIPInventoryOnly(t *testing.T, graph *behavior.Graph) {
	t.Helper()
	if len(graph.Features) != 0 || len(graph.ExecutionRoots) != 0 || len(graph.InvokedTargets) != 0 ||
		len(graph.Operations) != 0 || len(graph.Network) != 0 || len(graph.Relations) != 0 {
		t.Fatalf("serialization inventory emitted executable semantics: %#v", graph)
	}
	if matches := ruleengine.Evaluate(graph); len(matches) != 0 {
		t.Fatalf("serialization inventory produced capability matches: %#v", matches)
	}
}

func assertNoPyTorchZIPRecognition(t *testing.T, graph behavior.Graph) {
	t.Helper()
	for _, property := range graph.ArtifactProperties {
		if property.Kind == "serialization-format" && property.Value == "pytorch-zip" {
			t.Fatalf("close negative established PyTorch ZIP format: %#v", graph.ArtifactProperties)
		}
	}
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "pytorch-pickle-semantics" {
			t.Fatalf("unrecognized ZIP received PyTorch semantic coverage: %#v", graph.Coverage)
		}
	}
}

func pyTorchZIPRootNodeID(t *testing.T, inspection artifact.Result) string {
	t.Helper()
	for _, node := range inspection.Graph.Nodes {
		if node.ParentID == "" {
			return node.ID
		}
	}
	t.Fatal("ZIP inspection has no root node")
	return ""
}

func pyTorchZIPChildNodeID(t *testing.T, inspection artifact.Result, path string) string {
	t.Helper()
	logical := "checkpoint.pt!" + path
	for _, node := range inspection.Graph.Nodes {
		if node.LogicalPath == logical {
			return node.ID
		}
	}
	t.Fatalf("ZIP inspection has no child %q: %#v", logical, inspection.Graph.Nodes)
	return ""
}

func pyTorchZIPNodeByID(nodes []artifact.Node, nodeID string) *artifact.Node {
	for index := range nodes {
		if nodes[index].ID == nodeID {
			return &nodes[index]
		}
	}
	return nil
}

func pyTorchZIPEvidenceByID(evidence []behavior.Evidence, evidenceID string) *behavior.Evidence {
	for index := range evidence {
		if evidence[index].ID == evidenceID {
			return &evidence[index]
		}
	}
	return nil
}

func assertEvidenceLogicalPaths(t *testing.T, graph behavior.Graph, evidenceIDs, want []string) {
	t.Helper()
	got := make([]string, 0, len(evidenceIDs))
	for _, evidenceID := range evidenceIDs {
		evidence := pyTorchZIPEvidenceByID(graph.Evidence, evidenceID)
		if evidence == nil {
			t.Fatalf("missing evidence %q", evidenceID)
			return
		}
		got = append(got, evidence.Logical)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence logical paths = %#v, want %#v", got, want)
	}
}
