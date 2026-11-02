package extract

import (
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestCommandRedirectionsDoNotExceedGraphLimits(t *testing.T) {
	var source strings.Builder
	source.WriteString("printf inert")
	for index := 0; index < 256; index++ {
		source.WriteString(" > /tmp/inert-")
		source.WriteString(strings.Repeat("x", index+1))
	}
	graph := behavior.Graph{EvidenceLimit: 16, ItemLimit: 16, StringByteLimit: 4096}
	ExtractText(&graph, artifact.Content{NodeID: "node", LogicalPath: "fixture.sh", Kind: "script", SemanticLanguage: "shell", Data: []byte(source.String())})
	if len(graph.Operations) > 16 {
		t.Fatal("redirections exceeded the graph item budget")
	}
	if !graph.WorkLimitReached() {
		t.Fatal("fixture did not exercise graph exhaustion")
	}
}

func TestLiteralHomeWriteRetainsExactOperand(t *testing.T) {
	for _, word := range []string{`'~/.zshrc'`, `'$HOME/.zshrc'`, `'${HOME}/.zshrc'`} {
		var graph behavior.Graph
		AnalyzeShellLine(&graph, artifact.Content{NodeID: "node", LogicalPath: "fixture.sh"}, "printf '%s' inert > "+word, 1, unknownExecutionContext(), "ev-line")
		if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileWrite {
			t.Fatalf("literal path lost its ordinary write: %#v", graph.Operations)
		}
		binding, ok := graph.Operations[0].FirstBinding(behavior.ResourceRoleLocalOutput)
		if !ok || binding.Resource.Value != strings.Trim(word, "'") || len(binding.Resource.Classifications) != 0 {
			t.Fatalf("literal operand was rewritten or classified as a host path: %#v", binding)
		}
	}
}

func TestMalformedRedirectionDoesNotPromotePrefix(t *testing.T) {
	for _, source := range []string{`printf inert >`, `printf inert > > /etc/profile`, `printf inert 2>< /etc/profile`, `printf inert >/etc/profile >'unterminated`} {
		var graph behavior.Graph
		AnalyzeShellLine(&graph, artifact.Content{NodeID: "node", LogicalPath: "fixture.sh"}, source, 1, unknownExecutionContext(), "ev-line")
		if len(graph.Operations) > 0 {
			t.Fatalf("malformed syntax promoted a retained prefix: %s\n%#v", source, graph.Operations)
		}
		if len(graph.Coverage) == 0 {
			t.Fatal("malformed syntax had no coverage limit")
		}
	}
}
