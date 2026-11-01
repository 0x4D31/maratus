package rules

import (
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

// analysisView is the engine-owned, read-only index over retained analysis
// facts. It copies indexed records so a pattern evaluator cannot mutate the
// extractor graph, and every indexed record is charged to an explicit budget.
type analysisView struct {
	// graph is retained only for bounded coverage diagnostics. Patterns access
	// facts through the copied typed indexes below.
	graph                    *behavior.Graph
	operationsByID           map[string]behavior.ModeledOperation
	operationIDsByKind       map[behavior.OperationKind][]string
	operationIDsByBinding    map[resourceBindingIndexKey][]string
	featuresByID             map[string]behavior.Feature
	featureIDsByKey          map[string][]string
	executionRootsByID       map[string]behavior.ExecutionRoot
	executionRootIDsByKey    map[executionRootIndexKey][]string
	invokedTargetsByID       map[string]behavior.InvokedTarget
	relationsByID            map[string]behavior.OperationRelation
	relationIDsByKind        map[behavior.RelationKind][]string
	relationIDsFromOperation map[operationRelationIndexKey][]string
	relationIDsToOperation   map[operationRelationIndexKey][]string
}

type operationRelationIndexKey struct {
	kind        behavior.RelationKind
	operationID string
}

type executionRootIndexKey struct {
	kind string
	name string
}

type resourceBindingIndexKey struct {
	operationKind  behavior.OperationKind
	role           behavior.ResourceRole
	resourceKind   behavior.ResourceKind
	classification behavior.ResourceClassification
	concrete       bool
}

func newAnalysisView(graph *behavior.Graph, budget *ruleWorkBudget) *analysisView {
	view := &analysisView{
		graph:                    graph,
		operationsByID:           make(map[string]behavior.ModeledOperation),
		operationIDsByKind:       make(map[behavior.OperationKind][]string),
		operationIDsByBinding:    make(map[resourceBindingIndexKey][]string),
		featuresByID:             make(map[string]behavior.Feature),
		featureIDsByKey:          make(map[string][]string),
		executionRootsByID:       make(map[string]behavior.ExecutionRoot),
		executionRootIDsByKey:    make(map[executionRootIndexKey][]string),
		invokedTargetsByID:       make(map[string]behavior.InvokedTarget),
		relationsByID:            make(map[string]behavior.OperationRelation),
		relationIDsByKind:        make(map[behavior.RelationKind][]string),
		relationIDsFromOperation: make(map[operationRelationIndexKey][]string),
		relationIDsToOperation:   make(map[operationRelationIndexKey][]string),
	}
	if graph == nil || budget == nil {
		return view
	}
indexing:
	for _, operation := range sortedRuleFacts(graph.Operations, func(item behavior.ModeledOperation) string { return item.ID }) {
		if !budget.charge(1) {
			break
		}
		operation = cloneIndexedOperation(operation)
		view.operationsByID[operation.ID] = operation
		view.operationIDsByKind[operation.Kind] = append(view.operationIDsByKind[operation.Kind], operation.ID)
		for _, binding := range operation.ResourceBindings {
			base := resourceBindingIndexKey{operationKind: operation.Kind, role: binding.Role, resourceKind: binding.Resource.Kind}
			if !budget.charge(1) {
				break indexing
			}
			view.operationIDsByBinding[base] = append(view.operationIDsByBinding[base], operation.ID)
			concrete := strings.TrimSpace(binding.Resource.Value) != ""
			if concrete {
				key := base
				key.concrete = true
				if !budget.charge(1) {
					break indexing
				}
				view.operationIDsByBinding[key] = append(view.operationIDsByBinding[key], operation.ID)
			}
			for _, classification := range binding.Resource.Classifications {
				if !budget.charge(1) {
					break indexing
				}
				key := base
				key.classification = classification
				view.operationIDsByBinding[key] = append(view.operationIDsByBinding[key], operation.ID)
				if concrete {
					key.concrete = true
					if !budget.charge(1) {
						break indexing
					}
					view.operationIDsByBinding[key] = append(view.operationIDsByBinding[key], operation.ID)
				}
			}
		}
	}
	for kind := range view.operationIDsByKind {
		sort.Strings(view.operationIDsByKind[kind])
	}
	for key, ids := range view.operationIDsByBinding {
		view.operationIDsByBinding[key] = sortedUniqueOperationIDs(ids)
	}
	if !budget.exhausted {
		for _, feature := range sortedRuleFacts(graph.Features, func(item behavior.Feature) string { return item.ID }) {
			if !budget.charge(1) {
				break
			}
			feature = cloneIndexedFeature(feature)
			view.featuresByID[feature.ID] = feature
			view.featureIDsByKey[feature.Key] = append(view.featureIDsByKey[feature.Key], feature.ID)
		}
	}
	for key, ids := range view.featureIDsByKey {
		view.featureIDsByKey[key] = sortedUniqueOperationIDs(ids)
	}
	if !budget.exhausted {
		for _, root := range sortedRuleFacts(graph.ExecutionRoots, func(item behavior.ExecutionRoot) string { return item.ID }) {
			if !budget.charge(1) {
				break
			}
			root = cloneIndexedExecutionRoot(root)
			view.executionRootsByID[root.ID] = root
			view.executionRootIDsByKey[executionRootIndexKey{kind: root.Kind}] = append(view.executionRootIDsByKey[executionRootIndexKey{kind: root.Kind}], root.ID)
			if root.Name != "" {
				view.executionRootIDsByKey[executionRootIndexKey{kind: root.Kind, name: root.Name}] = append(view.executionRootIDsByKey[executionRootIndexKey{kind: root.Kind, name: root.Name}], root.ID)
			}
		}
	}
	for key, ids := range view.executionRootIDsByKey {
		view.executionRootIDsByKey[key] = sortedUniqueOperationIDs(ids)
	}
	if !budget.exhausted {
		for _, target := range sortedRuleFacts(graph.InvokedTargets, func(item behavior.InvokedTarget) string { return item.ID }) {
			if !budget.charge(1) {
				break
			}
			view.invokedTargetsByID[target.ID] = cloneIndexedInvokedTarget(target)
		}
	}
	if !budget.exhausted {
		for _, relation := range sortedRuleFacts(graph.Relations, func(item behavior.OperationRelation) string { return item.ID }) {
			if !budget.charge(1) {
				break
			}
			normalized, err := behavior.NormalizeOperationRelation(relation)
			if err != nil || normalized.ID == "" {
				continue
			}
			secondaryIndexes := 0
			if normalized.From.Kind == behavior.RelationEndpointOperation {
				secondaryIndexes++
			}
			if normalized.To.Kind == behavior.RelationEndpointOperation {
				secondaryIndexes++
			}
			if !budget.charge(secondaryIndexes) {
				break
			}
			normalized = cloneIndexedRelation(normalized)
			view.relationsByID[normalized.ID] = normalized
			view.relationIDsByKind[normalized.Kind] = append(view.relationIDsByKind[normalized.Kind], normalized.ID)
			if normalized.From.Kind == behavior.RelationEndpointOperation {
				key := operationRelationIndexKey{kind: normalized.Kind, operationID: normalized.From.ID}
				view.relationIDsFromOperation[key] = append(view.relationIDsFromOperation[key], normalized.ID)
			}
			if normalized.To.Kind == behavior.RelationEndpointOperation {
				key := operationRelationIndexKey{kind: normalized.Kind, operationID: normalized.To.ID}
				view.relationIDsToOperation[key] = append(view.relationIDsToOperation[key], normalized.ID)
			}
		}
	}
	for kind, ids := range view.relationIDsByKind {
		view.relationIDsByKind[kind] = sortedUniqueOperationIDs(ids)
	}
	for key, ids := range view.relationIDsFromOperation {
		view.relationIDsFromOperation[key] = sortedUniqueOperationIDs(ids)
	}
	for key, ids := range view.relationIDsToOperation {
		view.relationIDsToOperation[key] = sortedUniqueOperationIDs(ids)
	}
	return view
}

// sortedRuleFacts gives every indexed evaluation path the producer's canonical
// fact order without mutating its graph. This keeps work-budget prefixes stable
// for direct callers and strict report replay alike.
func sortedRuleFacts[T any](values []T, id func(T) string) []T {
	out := append([]T(nil), values...)
	sort.SliceStable(out, func(left, right int) bool {
		return id(out[left]) < id(out[right])
	})
	return out
}

func (view *analysisView) operationRelationsFrom(kind behavior.RelationKind, operationID string, budget *ruleWorkBudget) []behavior.OperationRelation {
	if view == nil || budget == nil {
		return nil
	}
	return view.indexedRelations(view.relationIDsFromOperation[operationRelationIndexKey{kind: kind, operationID: operationID}], budget)
}

func (view *analysisView) operationRelationsTo(kind behavior.RelationKind, operationID string, budget *ruleWorkBudget) []behavior.OperationRelation {
	if view == nil || budget == nil {
		return nil
	}
	return view.indexedRelations(view.relationIDsToOperation[operationRelationIndexKey{kind: kind, operationID: operationID}], budget)
}

func (view *analysisView) indexedRelations(ids []string, budget *ruleWorkBudget) []behavior.OperationRelation {
	if !budget.charge(1 + len(ids)) {
		return nil
	}
	out := make([]behavior.OperationRelation, 0, len(ids))
	for _, id := range ids {
		relation, ok := view.relationsByID[id]
		if ok {
			out = append(out, cloneIndexedRelation(relation))
		}
	}
	return out
}

func (view *analysisView) matchingExecutionRoots(pattern executionRootPattern, budget *ruleWorkBudget) []behavior.ExecutionRoot {
	if view == nil || budget == nil {
		return nil
	}
	var ids []string
	if len(pattern.names) == 0 {
		ids = view.executionRootIDsByKey[executionRootIndexKey{kind: pattern.kind}]
		if !budget.charge(1 + len(ids)) {
			return nil
		}
		ids = append([]string(nil), ids...)
	} else {
		for _, name := range pattern.names {
			candidates := view.executionRootIDsByKey[executionRootIndexKey{kind: pattern.kind, name: name}]
			if !budget.charge(1 + len(candidates)) {
				return nil
			}
			ids = append(ids, candidates...)
		}
		ids = sortedUniqueOperationIDs(ids)
	}
	out := make([]behavior.ExecutionRoot, 0, len(ids))
	for _, id := range ids {
		root, ok := view.executionRootsByID[id]
		if !ok {
			continue
		}
		out = append(out, cloneIndexedExecutionRoot(root))
	}
	return out
}

func (view *analysisView) invokedTarget(id string, budget *ruleWorkBudget) (behavior.InvokedTarget, bool) {
	if view == nil || budget == nil || !budget.charge(1) {
		return behavior.InvokedTarget{}, false
	}
	target, ok := view.invokedTargetsByID[id]
	if !ok {
		return behavior.InvokedTarget{}, false
	}
	return cloneIndexedInvokedTarget(target), true
}

func (view *analysisView) matchingFeatures(pattern featurePattern, budget *ruleWorkBudget) []behavior.Feature {
	if view == nil || budget == nil {
		return nil
	}
	ids := view.featureIDsByKey[pattern.key]
	if !budget.charge(1 + len(ids)) {
		return nil
	}
	out := make([]behavior.Feature, 0, len(ids))
	for _, id := range ids {
		feature, ok := view.featuresByID[id]
		if !ok {
			continue
		}
		out = append(out, cloneIndexedFeature(feature))
	}
	return out
}

func (view *analysisView) matchingOperations(pattern operationPattern, budget *ruleWorkBudget) []behavior.ModeledOperation {
	if view == nil || budget == nil {
		return nil
	}
	ids := view.operationIDsByKind[pattern.kind]
	if !budget.charge(1 + len(ids)) {
		return nil
	}
	ids = append([]string(nil), ids...)
	for _, constraint := range pattern.constraints {
		binding, ok := constraint.(resourceBindingPattern)
		if !ok {
			return nil
		}
		key := resourceBindingIndexKey{operationKind: pattern.kind, role: binding.role, resourceKind: binding.resourceKind, classification: binding.classification, concrete: binding.concrete}
		candidates := view.operationIDsByBinding[key]
		if !budget.charge(1 + len(ids) + len(candidates)) {
			return nil
		}
		ids = intersectSortedOperationIDs(ids, candidates)
		if len(ids) == 0 {
			break
		}
	}
	out := make([]behavior.ModeledOperation, 0, len(ids))
	for _, id := range ids {
		operation, ok := view.operationsByID[id]
		if !ok {
			continue
		}
		out = append(out, cloneIndexedOperation(operation))
	}
	return out
}

func (view *analysisView) matchingOperationRelations(kind behavior.RelationKind, leftIDs, rightIDs map[string]bool, budget *ruleWorkBudget) []behavior.OperationRelation {
	if view == nil || budget == nil || len(leftIDs) == 0 || len(rightIDs) == 0 {
		return nil
	}
	ids := view.relationIDsByKind[kind]
	if !budget.charge(1 + len(ids)) {
		return nil
	}
	out := make([]behavior.OperationRelation, 0, min(len(ids), ruleCapabilityMatchCandidateLimit))
	for _, id := range ids {
		relation, ok := view.relationsByID[id]
		if !ok || !leftIDs[relation.From.ID] || !rightIDs[relation.To.ID] {
			continue
		}
		out = append(out, cloneIndexedRelation(relation))
	}
	return out
}

func projectPatternBindings(operation behavior.ModeledOperation, pattern operationPattern) behavior.ModeledOperation {
	if len(pattern.constraints) == 0 {
		return operation
	}
	projected := make([]behavior.ResourceBinding, 0, len(pattern.constraints))
	seen := make(map[behavior.ResourceKey]map[behavior.ResourceRole]bool, len(pattern.constraints))
	for _, constraint := range pattern.constraints {
		bindingPattern, ok := constraint.(resourceBindingPattern)
		if !ok {
			continue
		}
		for _, binding := range operation.ResourceBindings {
			if !resourceBindingMatchesPattern(binding, bindingPattern) {
				continue
			}
			key := binding.Resource.Key()
			if seen[key] == nil {
				seen[key] = map[behavior.ResourceRole]bool{}
			}
			if seen[key][binding.Role] {
				continue
			}
			seen[key][binding.Role] = true
			projected = append(projected, binding)
		}
	}
	operation.ResourceBindings = projected
	return operation
}

func resourceBindingMatchesPattern(binding behavior.ResourceBinding, pattern resourceBindingPattern) bool {
	if binding.Role != pattern.role || binding.Resource.Kind != pattern.resourceKind {
		return false
	}
	if pattern.concrete && strings.TrimSpace(binding.Resource.Value) == "" {
		return false
	}
	if pattern.classification == "" {
		return true
	}
	for _, classification := range binding.Resource.Classifications {
		if classification == pattern.classification {
			return true
		}
	}
	return false
}

func sortedUniqueOperationIDs(ids []string) []string {
	ids = append([]string(nil), ids...)
	sort.Strings(ids)
	out := ids[:0]
	for _, id := range ids {
		if id == "" || len(out) > 0 && out[len(out)-1] == id {
			continue
		}
		out = append(out, id)
	}
	return out
}

func intersectSortedOperationIDs(left, right []string) []string {
	out := make([]string, 0, min(len(left), len(right)))
	for i, j := 0, 0; i < len(left) && j < len(right); {
		switch {
		case left[i] < right[j]:
			i++
		case left[i] > right[j]:
			j++
		default:
			out = append(out, left[i])
			i++
			j++
		}
	}
	return out
}

func cloneIndexedOperation(operation behavior.ModeledOperation) behavior.ModeledOperation {
	operation.ResourceBindings = append([]behavior.ResourceBinding(nil), operation.ResourceBindings...)
	for i := range operation.ResourceBindings {
		binding := &operation.ResourceBindings[i]
		binding.EvidenceIDs = append([]string(nil), binding.EvidenceIDs...)
		binding.Resource.Classifications = append([]behavior.ResourceClassification(nil), binding.Resource.Classifications...)
	}
	operation.Qualifiers = cloneStringMap(operation.Qualifiers)
	operation.EvidenceIDs = append([]string(nil), operation.EvidenceIDs...)
	operation.Execution.ExecutionRootIDs = append([]string(nil), operation.Execution.ExecutionRootIDs...)
	operation.Execution.InvokedTargetIDs = append([]string(nil), operation.Execution.InvokedTargetIDs...)
	return operation
}

func cloneIndexedFeature(feature behavior.Feature) behavior.Feature {
	feature.Qualifiers = cloneStringMap(feature.Qualifiers)
	feature.EvidenceIDs = append([]string(nil), feature.EvidenceIDs...)
	feature.Execution.ExecutionRootIDs = append([]string(nil), feature.Execution.ExecutionRootIDs...)
	feature.Execution.InvokedTargetIDs = append([]string(nil), feature.Execution.InvokedTargetIDs...)
	return feature
}

func cloneIndexedExecutionRoot(root behavior.ExecutionRoot) behavior.ExecutionRoot {
	root.Arguments = append([]string(nil), root.Arguments...)
	root.EvidenceIDs = append([]string(nil), root.EvidenceIDs...)
	return root
}

func cloneIndexedInvokedTarget(target behavior.InvokedTarget) behavior.InvokedTarget {
	target.Arguments = append([]string(nil), target.Arguments...)
	target.EvidenceIDs = append([]string(nil), target.EvidenceIDs...)
	target.Execution.ExecutionRootIDs = append([]string(nil), target.Execution.ExecutionRootIDs...)
	target.Execution.InvokedTargetIDs = append([]string(nil), target.Execution.InvokedTargetIDs...)
	return target
}

func cloneIndexedRelation(relation behavior.OperationRelation) behavior.OperationRelation {
	relation.EvidenceIDs = append([]string(nil), relation.EvidenceIDs...)
	relation.Execution.ExecutionRootIDs = append([]string(nil), relation.Execution.ExecutionRootIDs...)
	relation.Execution.InvokedTargetIDs = append([]string(nil), relation.Execution.InvokedTargetIDs...)
	if relation.From.Resource != nil {
		resource := *relation.From.Resource
		resource.Classifications = append([]behavior.ResourceClassification(nil), resource.Classifications...)
		relation.From.Resource = &resource
	}
	if relation.To.Resource != nil {
		resource := *relation.To.Resource
		resource.Classifications = append([]behavior.ResourceClassification(nil), resource.Classifications...)
		relation.To.Resource = &resource
	}
	return relation
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
