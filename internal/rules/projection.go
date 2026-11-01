package rules

import (
	"sort"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/behavior"
)

// capabilityTraceFacts is the read-only evidence projection of the final
// retained behavior graph. Capability evidence is rebuilt from the normalized
// match trace so independently bounded fact collections cannot leave evidence
// for an operation, Feature, ExecutionRoot, or OperationRelation that the trace
// no longer names.
type capabilityTraceFacts struct {
	operations     map[string][]string
	features       map[string][]string
	executionRoots map[string][]string
	relations      map[string][]string
}

func newCapabilityTraceFacts(graph *behavior.Graph) capabilityTraceFacts {
	facts := capabilityTraceFacts{
		operations:     make(map[string][]string),
		features:       make(map[string][]string),
		executionRoots: make(map[string][]string),
		relations:      make(map[string][]string),
	}
	if graph == nil {
		return facts
	}
	for _, operation := range graph.Operations {
		facts.operations[operation.ID] = canonicalTraceEvidence(operation.EvidenceIDs)
	}
	for _, feature := range graph.Features {
		facts.features[feature.ID] = canonicalTraceEvidence(feature.EvidenceIDs)
	}
	for _, root := range graph.ExecutionRoots {
		facts.executionRoots[root.ID] = canonicalTraceEvidence(root.EvidenceIDs)
	}
	for _, relation := range graph.Relations {
		facts.relations[relation.ID] = canonicalTraceEvidence(relation.EvidenceIDs)
	}
	return facts
}

func canonicalTraceEvidence(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func (facts capabilityTraceFacts) evidence(trace []behavior.MatchTraceClause) ([]string, bool) {
	out := make([]string, 0, maxCapabilityMatchEvidence)
	seen := make(map[string]bool, maxCapabilityMatchEvidence)
	truncated := false
	add := func(values []string) {
		for _, value := range values {
			if value == "" || seen[value] {
				continue
			}
			// Evidence IDs are references, so truncating or repairing one would
			// manufacture a different ID. Omit an unrepresentable reference and
			// surface the bounded projection as partial.
			if len(value) > maxCapabilityMatchIDBytes || !utf8.ValidString(value) {
				truncated = true
				continue
			}
			if len(out) >= maxCapabilityMatchEvidence {
				truncated = true
				continue
			}
			seen[value] = true
			out = append(out, value)
		}
	}
	for _, clause := range trace {
		for _, id := range clause.OperationIDs {
			add(facts.operations[id])
		}
		for _, id := range clause.FeatureIDs {
			add(facts.features[id])
		}
		for _, id := range clause.ExecutionRootIDs {
			add(facts.executionRoots[id])
		}
		for _, id := range clause.RelationIDs {
			add(facts.relations[id])
		}
	}
	sort.Strings(out)
	return out, truncated
}
