package rules

import (
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestValidateCapabilityMatchProjectionBoundsRejectsHostileCardinalityBeforeProjection(t *testing.T) {
	base := behavior.CapabilityMatch{
		ID:            "match-1",
		RuleID:        "test.rule",
		Title:         "Test",
		Namespace:     "test",
		Support:       behavior.SupportCorroborated,
		SubjectNodeID: "node-1",
		Execution:     behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
		OperationIDs:  []string{"operation-1"},
		EvidenceIDs:   []string{"ev-1"},
		AffectedResources: []behavior.Resource{
			behavior.NewResource(behavior.ResourceFile, "/tmp/payload"),
		},
		MatchTrace: []behavior.MatchTraceClause{{
			Path: "match", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"},
		}},
	}
	repeated := func(value string, count int) []string {
		out := make([]string, count)
		for index := range out {
			out[index] = value
		}
		return out
	}
	tests := []struct {
		name   string
		mutate func(*behavior.CapabilityMatch)
	}{
		{name: "operations", mutate: func(match *behavior.CapabilityMatch) {
			match.OperationIDs = repeated("operation-1", maxCapabilityMatchOperations+1)
		}},
		{name: "evidence", mutate: func(match *behavior.CapabilityMatch) {
			match.EvidenceIDs = repeated("ev-1", maxCapabilityMatchEvidence+1)
		}},
		{name: "resources", mutate: func(match *behavior.CapabilityMatch) {
			match.AffectedResources = make([]behavior.Resource, maxCapabilityMatchResources+1)
		}},
		{name: "attack mappings", mutate: func(match *behavior.CapabilityMatch) {
			match.Attack = repeated("T0000", maxCapabilityMatchMappings+1)
		}},
		{name: "architectures", mutate: func(match *behavior.CapabilityMatch) {
			match.ArchitectureScopes = repeated("arm64", maxCapabilityMatchResources+1)
		}},
		{name: "trace clauses", mutate: func(match *behavior.CapabilityMatch) {
			match.MatchTrace = make([]behavior.MatchTraceClause, maxCapabilityMatchTraceClauses+1)
		}},
		{name: "trace facts", mutate: func(match *behavior.CapabilityMatch) {
			match.MatchTrace[0].OperationIDs = repeated("operation-1", maxCapabilityMatchTraceIDs+1)
		}},
		{name: "resource value bytes", mutate: func(match *behavior.CapabilityMatch) {
			match.AffectedResources[0].Value = strings.Repeat("x", maxCapabilityMatchValueBytes+1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			match := base
			match.OperationIDs = append([]string(nil), base.OperationIDs...)
			match.EvidenceIDs = append([]string(nil), base.EvidenceIDs...)
			match.AffectedResources = append([]behavior.Resource(nil), base.AffectedResources...)
			match.MatchTrace = append([]behavior.MatchTraceClause(nil), base.MatchTrace...)
			test.mutate(&match)
			if err := ValidateCapabilityMatchProjectionBounds(match); err == nil {
				t.Fatal("hostile capability projection passed engine bounds")
			}
		})
	}
}
