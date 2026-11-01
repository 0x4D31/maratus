package extract

import (
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
)

func TestPackagePayloadInstallPathsRequiresPairedMetadataAndPayloadTopology(t *testing.T) {
	graph := artifact.Graph{Nodes: []artifact.Node{
		{ID: "pkg", LogicalPath: "sample.pkg", Kind: "pkg"},
		{ID: "info", ParentID: "pkg", LogicalPath: "sample.pkg!PackageInfo", Kind: "manifest", Provenance: "pkg-xar-entry"},
		{ID: "payload", ParentID: "pkg", LogicalPath: "sample.pkg!Payload", Kind: "gzip", Provenance: "pkg-xar-entry"},
		{ID: "cpio", ParentID: "payload", LogicalPath: "sample.pkg!Payload", Kind: "cpio", Provenance: "gzip-member"},
		{ID: "plist", ParentID: "cpio", LogicalPath: "sample.pkg!Payload!Library/LaunchDaemons/com.example.job.plist", Kind: "plist", Provenance: "cpio-entry"},
	}}
	contents := []artifact.Content{
		{NodeID: "info", Data: []byte(`<pkg-info identifier="com.example" install-location="/"/>`)},
		{NodeID: "plist"},
	}
	got := packagePayloadInstallPaths(graph, contents)
	if got["plist"] != "/Library/LaunchDaemons/com.example.job.plist" {
		t.Fatalf("installed path = %q", got["plist"])
	}
}

func TestPackagePayloadInstallPathsFailsClosed(t *testing.T) {
	base := artifact.Graph{Nodes: []artifact.Node{
		{ID: "pkg", LogicalPath: "sample.pkg", Kind: "pkg"},
		{ID: "info", ParentID: "pkg", LogicalPath: "sample.pkg!PackageInfo", Kind: "manifest", Provenance: "pkg-xar-entry"},
		{ID: "payload", ParentID: "pkg", LogicalPath: "sample.pkg!Payload", Kind: "gzip", Provenance: "pkg-xar-entry"},
		{ID: "cpio", ParentID: "payload", LogicalPath: "sample.pkg!Payload", Kind: "cpio", Provenance: "gzip-member"},
		{ID: "plist", ParentID: "cpio", LogicalPath: "sample.pkg!Payload!Library/LaunchAgents/com.example.job.plist", Kind: "plist", Provenance: "cpio-entry"},
	}}
	for _, test := range []struct {
		name string
		data []byte
		edit func(*artifact.Graph)
	}{
		{name: "missing install location", data: []byte(`<pkg-info identifier="com.example"/>`)},
		{name: "relative install location", data: []byte(`<pkg-info install-location="tmp/root"/>`)},
		{name: "parent traversal", data: []byte(`<pkg-info install-location="/tmp/../"/>`)},
		{name: "malformed metadata", data: []byte(`<pkg-info install-location="/">`)},
		{name: "multiple roots", data: []byte(`<pkg-info install-location="/"/><pkg-info/>`)},
		{name: "duplicate install location", data: []byte(`<pkg-info install-location="/" install-location="/tmp"/>`)},
		{name: "directive", data: []byte(`<!unsafe><pkg-info install-location="/"/>`)},
		{name: "namespaced root", data: []byte(`<p:pkg-info xmlns:p="urn:other" install-location="/"/>`)},
		{name: "namespaced attribute", data: []byte(`<pkg-info xmlns:p="urn:other" p:install-location="/"/>`)},
		{name: "token budget", data: []byte(`<pkg-info install-location="/">` + strings.Repeat(`<x/>`, maxPackageInfoTokens) + `</pkg-info>`)},
		{name: "ordinary zip topology", data: []byte(`<pkg-info install-location="/"/>`), edit: func(graph *artifact.Graph) { graph.Nodes[0].Kind = "zip" }},
		{name: "nested archive descendant", data: []byte(`<pkg-info install-location="/"/>`), edit: func(graph *artifact.Graph) { graph.Nodes[4].Provenance = "zip-entry" }},
		{name: "duplicate package metadata", data: []byte(`<pkg-info install-location="/"/>`), edit: func(graph *artifact.Graph) {
			graph.Nodes = append(graph.Nodes, artifact.Node{ID: "info-duplicate", ParentID: "pkg", LogicalPath: "sample.pkg!PackageInfo", Provenance: "pkg-xar-entry"})
		}},
		{name: "duplicate payload", data: []byte(`<pkg-info install-location="/"/>`), edit: func(graph *artifact.Graph) {
			graph.Nodes = append(graph.Nodes, artifact.Node{ID: "payload-duplicate", ParentID: "pkg", LogicalPath: "sample.pkg!Payload", Provenance: "pkg-xar-entry"})
		}},
		{name: "mismatched child topology", data: []byte(`<pkg-info install-location="/"/>`), edit: func(graph *artifact.Graph) {
			graph.Nodes[1].LogicalPath = "other.pkg!PackageInfo"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := base
			graph.Nodes = append([]artifact.Node(nil), base.Nodes...)
			if test.edit != nil {
				test.edit(&graph)
			}
			got := packagePayloadInstallPaths(graph, []artifact.Content{{NodeID: "info", Data: test.data}, {NodeID: "plist"}})
			if got["plist"] != "" {
				t.Fatalf("unsafe installed path = %q", got["plist"])
			}
		})
	}
}

func TestPackagePayloadInstallPathsKeepsComponentsSeparate(t *testing.T) {
	graph := artifact.Graph{Nodes: []artifact.Node{
		{ID: "pkg", LogicalPath: "product.pkg", Kind: "pkg"},
		{ID: "info-a", ParentID: "pkg", LogicalPath: "product.pkg!a.pkg/PackageInfo", Provenance: "pkg-xar-entry"},
		{ID: "payload-a", ParentID: "pkg", LogicalPath: "product.pkg!a.pkg/Payload", Provenance: "pkg-xar-entry"},
		{ID: "cpio-a", ParentID: "payload-a", LogicalPath: "product.pkg!a.pkg/Payload", Provenance: "gzip-member"},
		{ID: "plist-a", ParentID: "cpio-a", LogicalPath: "product.pkg!a.pkg/Payload!Library/LaunchAgents/a.plist", Provenance: "cpio-entry"},
		{ID: "info-b", ParentID: "pkg", LogicalPath: "product.pkg!b.pkg/PackageInfo", Provenance: "pkg-xar-entry"},
		{ID: "payload-b", ParentID: "pkg", LogicalPath: "product.pkg!b.pkg/Payload", Provenance: "pkg-xar-entry"},
		{ID: "cpio-b", ParentID: "payload-b", LogicalPath: "product.pkg!b.pkg/Payload", Provenance: "gzip-member"},
		{ID: "plist-b", ParentID: "cpio-b", LogicalPath: "product.pkg!b.pkg/Payload!Library/LaunchAgents/b.plist", Provenance: "cpio-entry"},
	}}
	contents := []artifact.Content{
		{NodeID: "info-a", Data: []byte(`<pkg-info install-location="/"/>`)},
		{NodeID: "info-b", Data: []byte(`<pkg-info install-location="/opt/example"/>`)},
	}
	got := packagePayloadInstallPaths(graph, contents)
	if got["plist-a"] != "/Library/LaunchAgents/a.plist" || got["plist-b"] != "/opt/example/Library/LaunchAgents/b.plist" {
		t.Fatalf("component paths = %#v", got)
	}
}
