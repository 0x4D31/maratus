package extract

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/plistx"
)

func TestExtractPlistEmitsExactNodeAppTransportSecurityProperties(t *testing.T) {
	content := artifact.Content{
		NodeID:      "node-info",
		LogicalPath: "Fixture.app/Contents/Info.plist",
		Kind:        "plist",
		Data: []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key><dict>
    <key>NSAllowsArbitraryLoads</key><true/>
    <key>NSAllowsLocalNetworking</key><false/>
    <key>NSExceptionDomains</key><dict>
      <key>api.example.invalid</key><dict>
        <key>NSIncludesSubdomains</key><true/>
        <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
        <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.1</string>
      </dict>
    </dict>
  </dict>
</dict></plist>`),
	}
	var graph behavior.Graph
	ExtractPlist(&graph, content, PlistExecutionStart{})

	want := []string{
		"NSAllowsArbitraryLoads=true",
		"NSAllowsLocalNetworking=false",
		`NSExceptionDomains["api.example.invalid"].NSExceptionAllowsInsecureHTTPLoads=true`,
		`NSExceptionDomains["api.example.invalid"].NSIncludesSubdomains=true`,
		`NSExceptionDomains["api.example.invalid"].NSExceptionMinimumTLSVersion=TLSv1.1`,
	}
	if len(graph.ArtifactProperties) != len(want) {
		t.Fatalf("ATS properties = %#v, want %d", graph.ArtifactProperties, len(want))
	}
	evidenceByID := make(map[string]behavior.Evidence, len(graph.Evidence))
	for _, item := range graph.Evidence {
		evidenceByID[item.ID] = item
	}
	for index, property := range graph.ArtifactProperties {
		if property.NodeID != content.NodeID || property.Kind != "app-transport-security" || property.Value != want[index] || property.Support != behavior.SupportDirect || len(property.EvidenceIDs) != 1 {
			t.Fatalf("ATS property[%d] = %#v, want value %q on %q", index, property, want[index], content.NodeID)
		}
		evidence, ok := evidenceByID[property.EvidenceIDs[0]]
		if !ok || evidence.NodeID != content.NodeID || evidence.Logical != content.LogicalPath || evidence.Method != "plist" || evidence.Kind != property.Kind || evidence.Value != property.Value {
			t.Fatalf("ATS evidence for %#v = %#v", property, evidence)
		}
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("ATS metadata became modeled behavior: %#v", graph.Operations)
	}
}

func TestAppTransportSecurityPreservesEmptyExceptionDomain(t *testing.T) {
	plist := plistx.Dict{"NSAppTransportSecurity": plistx.Dict{
		"NSExceptionDomains": plistx.Dict{"": plistx.Dict{
			"NSExceptionAllowsInsecureHTTPLoads": true,
			"NSIncludesSubdomains":               true,
		}},
	}}
	content := artifact.Content{NodeID: "node-info", LogicalPath: "Fixture.app/Contents/Info.plist"}
	var graph behavior.Graph
	extractAppTransportSecurityProperties(&graph, content, plist)
	want := []string{
		`NSExceptionDomains[""].NSExceptionAllowsInsecureHTTPLoads=true`,
		`NSExceptionDomains[""].NSIncludesSubdomains=true`,
	}
	if len(graph.ArtifactProperties) != len(want) {
		t.Fatalf("ATS properties = %#v, want %#v", graph.ArtifactProperties, want)
	}
	for index := range want {
		if graph.ArtifactProperties[index].Value != want[index] {
			t.Fatalf("ATS properties = %#v, want %#v", graph.ArtifactProperties, want)
		}
	}
}

func TestExtractPlistRejectsMistypedAppTransportSecurityValues(t *testing.T) {
	content := artifact.Content{
		NodeID:      "node-info",
		LogicalPath: "Fixture.app/Contents/Info.plist",
		Kind:        "plist",
		Data: []byte(`<plist version="1.0"><dict>
<key>NSAppTransportSecurity</key><dict>
  <key>NSAllowsArbitraryLoads</key><string>true</string>
  <key>NSExceptionDomains</key><dict>
    <key>api.example.invalid</key><string>not-a-dictionary</string>
  </dict>
</dict></dict></plist>`),
	}
	var graph behavior.Graph
	ExtractPlist(&graph, content, PlistExecutionStart{})
	if len(graph.ArtifactProperties) != 0 {
		t.Fatalf("mistyped ATS values became properties: %#v", graph.ArtifactProperties)
	}
}

func TestAppTransportSecurityExceptionDomainsAreDeterministicAndBounded(t *testing.T) {
	exceptions := make(plistx.Dict, maxATSExceptionDomains+2)
	for index := 0; index < maxATSExceptionDomains+2; index++ {
		domain := fmt.Sprintf("%04d.example.invalid", maxATSExceptionDomains+1-index)
		exceptions[domain] = plistx.Dict{"NSExceptionAllowsInsecureHTTPLoads": true}
	}
	plist := plistx.Dict{"NSAppTransportSecurity": plistx.Dict{"NSExceptionDomains": exceptions}}
	content := artifact.Content{NodeID: "node-info", LogicalPath: "Fixture.app/Contents/Info.plist"}

	var first behavior.Graph
	extractAppTransportSecurityProperties(&first, content, plist)
	var second behavior.Graph
	extractAppTransportSecurityProperties(&second, content, plist)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("ATS extraction is not deterministic")
	}
	if len(first.ArtifactProperties) != maxATSExceptionDomains {
		t.Fatalf("ATS property count = %d, want %d", len(first.ArtifactProperties), maxATSExceptionDomains)
	}
	if len(first.Coverage) != 1 || first.Coverage[0].NodeID != content.NodeID || first.Coverage[0].AnalysisArea != "app-transport-security" || first.Coverage[0].Status != "partial" {
		t.Fatalf("ATS bound coverage = %#v", first.Coverage)
	}
}

func TestLaunchdCommandPreservesLiteralArgvAndProgramSelection(t *testing.T) {
	for _, test := range []struct {
		dict plistx.Dict
		want []string
	}{
		{plistx.Dict{"Program": "/selected/curl", "ProgramArguments": []any{"/other/curl", "", " a "}}, []string{"/selected/curl", "", " a "}},
		{plistx.Dict{"ProgramArguments": []any{" /bin/sh", "-c", "echo inert"}}, []string{" /bin/sh", "-c", "echo inert"}},
		{plistx.Dict{"Program": "/bin/sh", "ProgramArguments": []any{"", "-c", "echo inert"}}, []string{"/bin/sh", "-c", "echo inert"}},
	} {
		got, err := launchdCommand(test.dict)
		if err != nil || !reflect.DeepEqual(got, test.want) {
			t.Fatalf("launchdCommand = %#v, %v; want %#v", got, err, test.want)
		}
	}
}
