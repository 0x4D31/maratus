package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestVisibleNetworkUsesAnyLinkedOperation(t *testing.T) {
	rep := Report{
		Operations: []behavior.ModeledOperation{
			{ID: "operation-1", Kind: behavior.OperationNetworkConnect, Execution: testUnknownExecution()},
			{ID: "operation-2", Kind: behavior.OperationNetworkConnect, Execution: testConnectedExecution("")},
		},
		NetworkImplementations: []behavior.NetworkImplementationObservation{{Kind: behavior.NetworkImplementationAPICall, OperationIDs: []string{"operation-1", "operation-2"}, APIOrTool: "curl_easy_perform"}},
	}
	got := visibleNetwork(rep, false)
	if len(got) != 1 || strings.Join(got[0].OperationIDs, ",") != "operation-1,operation-2" {
		t.Fatalf("connected operation should expose canonical network context: %#v", got)
	}
	rep.Operations[1].Execution = testUnknownExecution()
	if got := visibleNetwork(rep, false); len(got) != 0 {
		t.Fatalf("weak network detail with only unresolved operations should stay hidden: %#v", got)
	}
}

func TestUniqueNetworkImplementationsCanonicalizesOperationReferences(t *testing.T) {
	got := uniqueNetworkImplementations([]behavior.NetworkImplementationObservation{{Kind: behavior.NetworkImplementationAPICall, OperationIDs: []string{"operation-2", "operation-1", "operation-3", "operation-2"}, APIOrTool: "fixture"}})
	if len(got) != 1 || strings.Join(got[0].OperationIDs, ",") != "operation-1,operation-2,operation-3" {
		t.Fatalf("network operation references are not canonical: %#v", got)
	}
}

func TestUniqueNetworkImplementationsPreservesDistinctOperationBindings(t *testing.T) {
	const count = 5000
	items := make([]behavior.NetworkImplementationObservation, count)
	for i := range items {
		items[i] = behavior.NetworkImplementationObservation{
			Kind:         behavior.NetworkImplementationAPICall,
			OperationIDs: []string{fmt.Sprintf("operation-%04d", i)},
			APIOrTool:    "fixture",
			EvidenceIDs:  []string{fmt.Sprintf("ev-%04d", i)},
		}
	}
	got := uniqueNetworkImplementations(items)
	if len(got) != count {
		t.Fatalf("distinct operation-bound observations were merged: got %d, want %d", len(got), count)
	}
	if got[0].OperationIDs[0] != "operation-0000" || got[count-1].OperationIDs[0] != "operation-4999" {
		t.Fatalf("large network merge is not canonical: %#v", got[0])
	}
}

func TestWriteTextWithOptionsSeparatesNetworkOperationContextAndSources(t *testing.T) {
	rep := Report{
		Artifact: "Sample.app",
		ArtifactNodes: []artifact.Node{
			{ID: "node-1", LogicalPath: "Sample.app/Contents/MacOS/Sample"},
			{ID: "node-2", LogicalPath: "Sample.app/Contents/Helpers/Uploader"},
		},
		Operations: []behavior.ModeledOperation{
			{ID: "operation-1", SubjectNodeID: "node-1", Kind: "network.connect", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://download.example/p"))), Execution: testUnknownExecution()},
			{ID: "operation-2", SubjectNodeID: "node-2", Kind: "network.upload", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://upload.example/p"))), Execution: testConnectedExecution("")},
		},
		NetworkImplementations: []behavior.NetworkImplementationObservation{{
			Kind:         behavior.NetworkImplementationAPICall,
			OperationIDs: []string{"operation-1", "operation-2"},
			APIOrTool:    "URLSession",
		}},
	}
	var buffer bytes.Buffer
	if err := WriteTextWithOptions(&buffer, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	out := buffer.String()
	if !strings.Contains(out, "upload API call") || !strings.Contains(out, "source        Sample") || !strings.Contains(out, "source        Uploader") {
		t.Fatalf("network context lost operation directions or subjects:\n%s", out)
	}
	rep.Operations[0].Kind = "network.download"
	buffer.Reset()
	if err := WriteTextWithOptions(&buffer, rep, TextOptions{Verbosity: TextVerbose}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buffer.String(), "upload API call") || !strings.Contains(buffer.String(), "download API call") {
		t.Fatalf("network directions were merged ambiguously:\n%s", buffer.String())
	}
}
