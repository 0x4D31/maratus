package rules

import (
	"sort"

	"github.com/0x4D31/maratus/internal/behavior"
)

// ReferencedFeatureKeys returns the deterministic set of Feature keys consumed
// by the current typed rule catalog. Report finalization uses this to ensure a
// rule input is never removed from the serializable IR before evaluation.
func ReferencedFeatureKeys() []string {
	keys := make(map[string]struct{})
	var visit func(Pattern)
	visit = func(pattern Pattern) {
		switch pattern := pattern.(type) {
		case featurePattern:
			if pattern.key != "" {
				keys[pattern.key] = struct{}{}
			}
		case anyPattern:
			for _, child := range pattern.patterns {
				visit(child)
			}
		case eachPattern:
			visit(pattern.left)
			visit(pattern.right)
		case relatePattern:
			visit(pattern.left)
			visit(pattern.right)
		case resourceFlowPattern:
			for _, rawStep := range pattern.steps {
				if step, ok := rawStep.(resourceFlowStepPattern); ok {
					visit(step.operation)
				}
			}
		}
	}
	for _, spec := range Specs() {
		visit(spec.Match)
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// ReferencedOperationKinds returns the deterministic operation vocabulary
// consumed by capability rules. It supports coverage audits without exposing
// or duplicating evaluator logic.
func ReferencedOperationKinds() []behavior.OperationKind {
	kinds := make(map[behavior.OperationKind]struct{})
	var visit func(Pattern)
	visit = func(pattern Pattern) {
		switch pattern := pattern.(type) {
		case operationPattern:
			if behavior.ValidOperationKind(pattern.kind) {
				kinds[pattern.kind] = struct{}{}
			}
		case anyPattern:
			for _, child := range pattern.patterns {
				visit(child)
			}
		case eachPattern:
			visit(pattern.left)
			visit(pattern.right)
		case relatePattern:
			visit(pattern.left)
			visit(pattern.right)
		case resourceFlowPattern:
			for _, rawStep := range pattern.steps {
				if step, ok := rawStep.(resourceFlowStepPattern); ok {
					visit(step.operation)
				}
			}
		}
	}
	for _, spec := range Specs() {
		if spec.Kind == CapabilityRule {
			visit(spec.Match)
		}
	}
	out := make([]behavior.OperationKind, 0, len(kinds))
	for kind := range kinds {
		out = append(out, kind)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
