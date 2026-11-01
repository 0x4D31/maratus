package rules

import (
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestDownloadExecuteDoesNotStripLiteralResourceBytes(t *testing.T) {
	for _, test := range []struct {
		name     string
		produced string
		consumed string
		match    bool
	}{
		{"same file", "/tmp/payload", "/tmp/payload", true},
		{"same literal space", "/tmp/payload ", "/tmp/payload ", true},
		{"trailing space", "/tmp/payload ", "/tmp/payload", false},
		{"leading space", " payload", "payload", false},
		{"double quote", `/tmp/payload"`, "/tmp/payload", false},
		{"single quote", "/tmp/payload'", "/tmp/payload", false},
		{"quoted filename", `"payload"`, "payload", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			execution := connectedExecution("root-main")
			output := behavior.NewResource(behavior.ResourceFile, test.produced)
			executable := behavior.NewResource(behavior.ResourceFile, test.consumed)
			graph := behavior.Graph{Operations: []behavior.ModeledOperation{
				{
					ID: "operation-download", SubjectNodeID: "node", ScopeID: "scope", Architecture: "arm64",
					Kind: behavior.OperationNetworkDownload,
					ResourceBindings: behavior.Bindings(
						behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload")),
						behavior.Bind(behavior.ResourceRoleLocalOutput, output),
					),
					EvidenceIDs: []string{"ev-download"}, Support: behavior.SupportDirect, Execution: execution,
				},
				{
					ID: "operation-execute", SubjectNodeID: "node", ScopeID: "scope", Architecture: "arm64",
					Kind:             behavior.OperationProcessExecute,
					ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, executable)),
					EvidenceIDs:      []string{"ev-execute"}, Support: behavior.SupportDirect, Execution: execution,
				},
			}}
			graph.Relations = []behavior.OperationRelation{
				resourceFlowRelation("relation-produces", behavior.RelationProduces, behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-download"), behavior.ResourceRelationEndpoint(behavior.ResourceRoleLocalOutput, output), behavior.SupportDirect),
				resourceFlowRelation("relation-consumes", behavior.RelationConsumes, behavior.ResourceRelationEndpoint(behavior.ResourceRoleExecutable, executable), behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-execute"), behavior.SupportDirect),
				resourceFlowRelation("relation-precedes", behavior.RelationPrecedes, behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-download"), behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-execute"), behavior.SupportDirect),
			}
			matches := evaluateCompiledSpecForTest(&graph, compiledSpec{spec: MacOSDownloadExecute})
			if (len(matches) != 0) != test.match {
				t.Fatalf("download %q then execute %q: matches=%#v, want match=%v", test.produced, test.consumed, matches, test.match)
			}
			if test.match && (len(matches) != 1 || len(matches[0].AffectedResources) != 1 || matches[0].AffectedResources[0].Value != test.produced) {
				t.Fatalf("matching flow lost its exact resource value: %#v", matches)
			}
		})
	}
}
