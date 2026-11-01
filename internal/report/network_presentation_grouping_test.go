package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestNetworkPresentationKeepsSubjectsAndOperationClassesSeparate(t *testing.T) {
	rep := Report{
		Artifact: "RNStealer.zip",
		ArtifactNodes: []artifact.Node{
			{ID: "node-root", LogicalPath: "RNStealer.zip", Kind: "zip"},
			{ID: "node-loader", ParentID: "node-root", LogicalPath: "RNStealer.zip!RNStealer/RN Loader", Kind: "text"},
			{ID: "node-stealer", ParentID: "node-root", LogicalPath: "RNStealer.zip!RNStealer/RN Stealer", Kind: "text"},
		},
		Operations: []behavior.ModeledOperation{
			{ID: "operation-loader-connect", SubjectNodeID: "node-loader", Kind: "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: ""})), EvidenceIDs: []string{"ev-loader"}, Support: behavior.SupportCorroborated, Execution: testConnectedExecution("")},
			{ID: "operation-stealer-connect", SubjectNodeID: "node-stealer", Kind: "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: ""})), EvidenceIDs: []string{"ev-stealer-connect"}, Support: behavior.SupportCorroborated, Execution: testUnknownExecution(), SourceFunction: "get_key"},
			{ID: "operation-stealer-upload", SubjectNodeID: "node-stealer", Kind: "network.upload", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: ""})), EvidenceIDs: []string{"ev-stealer-upload"}, Support: behavior.SupportCorroborated, Execution: testUnknownExecution(), SourceFunction: "post_data"},
		},
		Evidence: []behavior.Evidence{
			{ID: "ev-loader", NodeID: "node-loader", Logical: "RNStealer.zip!RNStealer/RN Loader", Method: "text", Kind: "line", Value: "requests.post"},
			{ID: "ev-stealer-connect", NodeID: "node-stealer", Logical: "RNStealer.zip!RNStealer/RN Stealer", Method: "text", Kind: "line", Value: "requests.post"},
			{ID: "ev-stealer-upload", NodeID: "node-stealer", Logical: "RNStealer.zip!RNStealer/RN Stealer", Method: "text", Kind: "line", Value: "requests.post(..., data=data)"},
		},
		NetworkImplementations: []behavior.NetworkImplementationObservation{
			{Kind: behavior.NetworkImplementationRuntimeAPI, SubjectNodeID: "node-loader", OperationIDs: []string{"operation-loader-connect"}, APIOrTool: "Python", HTTPImplementation: "requests/httpx/urllib", TLSProvider: "Python ssl module", UnresolvedProperties: []string{"destination"}, EvidenceIDs: []string{"ev-loader"}},
			{Kind: behavior.NetworkImplementationRuntimeAPI, SubjectNodeID: "node-stealer", OperationIDs: []string{"operation-stealer-connect"}, APIOrTool: "Python", HTTPImplementation: "requests/httpx/urllib", TLSProvider: "Python ssl module", UnresolvedProperties: []string{"destination"}, EvidenceIDs: []string{"ev-stealer-connect"}},
			{Kind: behavior.NetworkImplementationRuntimeAPI, SubjectNodeID: "node-stealer", OperationIDs: []string{"operation-stealer-upload"}, APIOrTool: "Python", HTTPImplementation: "requests/httpx/urllib", TLSProvider: "Python ssl module", UnresolvedProperties: []string{"destination"}, EvidenceIDs: []string{"ev-stealer-upload"}},
		},
	}

	items := visibleNetwork(rep, false)
	if len(items) != 3 {
		t.Fatalf("visible network paths = %d, want loader connect, stealer connect, and stealer upload: %#v", len(items), items)
	}
	operations := operationsByID(rep.Operations)
	evidence := evidenceMap(rep.Evidence)
	nodeLabels := artifactPropertiesSourceLabels(rep)
	want := map[string]string{
		"node-loader/network.connect":  "RN Loader",
		"node-stealer/network.connect": "RN Stealer",
		"node-stealer/network.upload":  "RN Stealer",
	}
	for _, item := range items {
		if len(item.OperationIDs) != 1 {
			t.Fatalf("presentation path retained mixed operation contexts: %#v", item)
		}
		operation := operations[item.OperationIDs[0]]
		key := operation.SubjectNodeID + "/" + string(operation.Kind)
		sources := networkSourceLabels(item, nodeLabels, operations, evidence)
		if len(sources) != 1 || sources[0] != want[key] {
			t.Fatalf("%s sources = %#v, want only %q", key, sources, want[key])
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing presentation contexts: %#v", want)
	}

	var output bytes.Buffer
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, "NETWORK EVIDENCE (3 paths · 2 destinations)") {
		t.Fatalf("network path count did not disclose the separated contexts:\n%s", text)
	}
	if got := strings.Count(text, "upload API call; destination unresolved"); got != 1 {
		t.Fatalf("upload context count = %d, want exactly the stealer upload path:\n%s", got, text)
	}
	if strings.Contains(text, "source        RN Loader") {
		t.Fatalf("concise output should defer source provenance to -v:\n%s", text)
	}
	var verbose bytes.Buffer
	if err := WriteTextWithOptions(&verbose, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(verbose.String(), "source        RN Loader"); got != 1 {
		t.Fatalf("verbose loader source count = %d, want only its connect path:\n%s", got, verbose.String())
	}
}

func TestNetworkPresentationSplitKeepsDownloadQualifierAndEvidence(t *testing.T) {
	operations := operationsByID([]behavior.ModeledOperation{
		{
			ID: "operation-download", SubjectNodeID: "node-downloader", Kind: "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "  https://example.test/payload  "))),
			EvidenceIDs: []string{"ev-download-operation"}, Support: behavior.SupportCorroborated, Execution: testConnectedExecution(""),
		},
		{
			ID: "operation-connect", SubjectNodeID: "node-helper", Kind: "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://example.test/check"})), EvidenceIDs: []string{"ev-connect-operation"}, Support: behavior.SupportCorroborated, Execution: testConnectedExecution(""),
		},
	})
	items := splitNetworkByPresentationContext([]networkPresentationRecord{{
		OperationIDs: []string{"operation-download", "operation-connect"},
		Caller:       "curl",
		HTTPStack:    "curl/libcurl",
		EvidenceIDs:  []string{"ev-stack-only"},
	}}, operations)
	if len(items) != 2 {
		t.Fatalf("split paths = %d, want connect and download: %#v", len(items), items)
	}
	for _, item := range items {
		if len(item.OperationIDs) != 1 {
			t.Fatalf("path retained mixed operations: %#v", item)
		}
		switch item.OperationIDs[0] {
		case "operation-download":
			if len(item.Destinations) != 1 || item.Destinations[0] != "https://example.test/payload" {
				t.Fatalf("download remote-source binding was lost or not normalized: %#v", item)
			}
			if len(item.EvidenceIDs) != 1 || item.EvidenceIDs[0] != "ev-download-operation" {
				t.Fatalf("download path lost all legitimate operation evidence: %#v", item)
			}
		case "operation-connect":
			if len(item.Destinations) != 1 || item.Destinations[0] != "https://example.test/check" {
				t.Fatalf("connect resource destination was lost: %#v", item)
			}
			if len(item.EvidenceIDs) != 1 || item.EvidenceIDs[0] != "ev-connect-operation" {
				t.Fatalf("connect path lost all legitimate operation evidence: %#v", item)
			}
		default:
			t.Fatalf("unexpected operation context: %#v", item)
		}
	}
}

func TestConciseNetworkObservablesSuppressSameNodeDestinationDuplicate(t *testing.T) {
	rep := Report{
		Artifact: "sample.zip",
		Operations: []behavior.ModeledOperation{{
			ID: "operation-connect", SubjectNodeID: "node-a", Kind: "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://same.example/p"})), Support: behavior.SupportCorroborated, Execution: testConnectedExecution(""),
		}},
		Evidence:               []behavior.Evidence{{ID: "ev-observable", NodeID: "node-a", Method: "text", Kind: "line"}},
		NetworkImplementations: []behavior.NetworkImplementationObservation{{Kind: behavior.NetworkImplementationToolInvocation, SubjectNodeID: "node-a", OperationIDs: []string{"operation-connect"}, APIOrTool: "curl"}},
		Features:               []behavior.Feature{{NodeID: "node-a", Key: "network.url", Value: "https://same.example/p", EvidenceIDs: []string{"ev-observable"}}},
	}

	var concise bytes.Buffer
	if err := WriteTextWithOptions(&concise, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(concise.String(), "https://same.example/p"); got != 1 || strings.Contains(concise.String(), "NETWORK OBSERVABLES") {
		t.Fatalf("concise output did not suppress only the same-node duplicate (count %d):\n%s", got, concise.String())
	}

	var complete bytes.Buffer
	if err := WriteTextWithOptions(&complete, rep, TextOptions{Verbosity: TextVeryVerbose}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(complete.String(), "https://same.example/p"); got < 2 || !strings.Contains(complete.String(), "NETWORK OBSERVABLES") {
		t.Fatalf("very-verbose output must preserve the distinct report records (count %d):\n%s", got, complete.String())
	}
	if !strings.Contains(complete.String(), "not linked to a modeled network operation; network use not established") {
		t.Fatalf("static observable did not disclaim network use:\n%s", complete.String())
	}
}

func TestConciseNetworkObservablesPreserveDifferentNodeAndUniqueDestinations(t *testing.T) {
	rep := Report{
		Artifact: "sample.zip",
		Operations: []behavior.ModeledOperation{{
			ID: "operation-connect", SubjectNodeID: "node-a", Kind: "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://same.example/p"})), Support: behavior.SupportCorroborated, Execution: testConnectedExecution(""),
		}},
		Evidence: []behavior.Evidence{
			{ID: "ev-other", NodeID: "node-b", Method: "text", Kind: "line"},
			{ID: "ev-unique", NodeID: "node-a", Method: "text", Kind: "line"},
		},
		NetworkImplementations: []behavior.NetworkImplementationObservation{{Kind: behavior.NetworkImplementationToolInvocation, SubjectNodeID: "node-a", OperationIDs: []string{"operation-connect"}, APIOrTool: "curl"}},
		Features: []behavior.Feature{
			{NodeID: "node-b", Key: "network.url", Value: "https://same.example/p", EvidenceIDs: []string{"ev-other"}},
			{NodeID: "node-a", Key: "network.url", Value: "https://unique.example/p", EvidenceIDs: []string{"ev-unique"}},
		},
	}

	var output bytes.Buffer
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if got := strings.Count(text, "https://same.example/p"); got != 2 {
		t.Fatalf("same destination from a different node was hidden (count %d):\n%s", got, text)
	}
	if !strings.Contains(text, "https://unique.example/p") || !strings.Contains(text, "OBSERVABLES") {
		t.Fatalf("unique same-node observable was hidden:\n%s", text)
	}
}
