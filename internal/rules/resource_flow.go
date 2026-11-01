package rules

import (
	"fmt"

	"github.com/0x4D31/maratus/internal/behavior"
)

type resourceFlowMatch struct {
	operations []behavior.ModeledOperation
	relations  []behavior.OperationRelation
	resource   behavior.Resource
}

func evaluateResourceFlowPattern(view *analysisView, budget *ruleWorkBudget, spec Spec, pattern resourceFlowPattern, path string) []behavior.CapabilityMatch {
	if len(pattern.steps) < 2 || len(pattern.steps) > maxResourceFlowSteps {
		return nil
	}

	stepPatterns := make([]operationPattern, len(pattern.steps))
	stepRoles := make([]behavior.ResourceRole, len(pattern.steps))
	operationsByStep := make([][]behavior.ModeledOperation, len(pattern.steps))
	operationsByStepID := make([]map[string]behavior.ModeledOperation, len(pattern.steps))
	for index, rawStep := range pattern.steps {
		step, ok := rawStep.(resourceFlowStepPattern)
		if !ok || !behavior.ValidResourceRole(step.role) {
			return nil
		}
		operationPattern, ok := step.operation.(operationPattern)
		if !ok || !operationPatternConstrainsRole(operationPattern, step.role) {
			return nil
		}
		stepPatterns[index] = operationPattern
		stepRoles[index] = step.role
		operations := reportablePatternOperations(view.matchingOperations(operationPattern, budget), operationPattern, spec.MinimumSupport)
		if len(operations) == 0 {
			return nil
		}
		operationsByStep[index] = operations
		operationsByStepID[index] = operationMap(operations)
	}

	paths := make([]resourceFlowMatch, 0, min(len(operationsByStep[0]), ruleCapabilityMatchCandidateLimit))
	var walk func(int, behavior.ModeledOperation, []behavior.ModeledOperation, []behavior.OperationRelation, behavior.Resource, behavior.ResourceIdentityKey, map[string]bool) bool
	walk = func(stepIndex int, previous behavior.ModeledOperation, operations []behavior.ModeledOperation, relations []behavior.OperationRelation, resource behavior.Resource, resourceKey behavior.ResourceIdentityKey, used map[string]bool) bool {
		if stepIndex == len(stepPatterns) {
			if len(paths) >= ruleCapabilityMatchCandidateLimit {
				markRuleEvaluationPartial(view.graph)
				return false
			}
			paths = append(paths, resourceFlowMatch{
				operations: append([]behavior.ModeledOperation(nil), operations...),
				relations:  append([]behavior.OperationRelation(nil), relations...),
				resource:   resource,
			})
			return true
		}

		orderings := view.operationRelationsFrom(behavior.RelationPrecedes, previous.ID, budget)
		if budget.exhausted {
			return false
		}
		for _, ordering := range orderings {
			if ordering.To.Kind != behavior.RelationEndpointOperation || used[ordering.To.ID] {
				continue
			}
			next, ok := operationsByStepID[stepIndex][ordering.To.ID]
			if !ok || !relationMatchesJoinedOperations(ordering, previous, next) {
				continue
			}
			consumes := view.operationRelationsTo(behavior.RelationConsumes, next.ID, budget)
			if budget.exhausted {
				return false
			}
			for _, consumed := range consumes {
				consumedResource, ok := resourceFlowRelationResource(consumed, behavior.RelationConsumes, next, stepRoles[stepIndex], resourceKey)
				if !ok {
					continue
				}
				merged, ok := mergeCorrelatedResource(resource, consumedResource)
				if !ok {
					continue
				}
				used[next.ID] = true
				complete := walk(
					stepIndex+1,
					next,
					append(operations, next),
					append(relations, ordering, consumed),
					merged,
					resourceKey,
					used,
				)
				delete(used, next.ID)
				if !complete && (budget.exhausted || len(paths) >= ruleCapabilityMatchCandidateLimit) {
					return false
				}
			}
		}
		return true
	}

	for _, first := range operationsByStep[0] {
		produces := view.operationRelationsFrom(behavior.RelationProduces, first.ID, budget)
		if budget.exhausted {
			return nil
		}
		for _, produced := range produces {
			resource, ok := resourceFlowRelationResource(produced, behavior.RelationProduces, first, stepRoles[0], "")
			if !ok {
				continue
			}
			resourceKey, ok := resource.CorrelationKey()
			if !ok {
				continue
			}
			used := map[string]bool{first.ID: true}
			if !walk(1, first, []behavior.ModeledOperation{first}, []behavior.OperationRelation{produced}, resource, resourceKey, used) && (budget.exhausted || len(paths) >= ruleCapabilityMatchCandidateLimit) {
				break
			}
		}
		if budget.exhausted {
			return nil
		}
		if len(paths) >= ruleCapabilityMatchCandidateLimit {
			break
		}
	}

	out := make([]behavior.CapabilityMatch, 0, len(paths))
	for _, flowMatch := range paths {
		matchSupport := supportBoundedByOperations(behavior.SupportDirect, flowMatch.operations)
		evidenceIDs := evidence(flowMatch.operations)
		for _, relation := range flowMatch.relations {
			matchSupport = weakerRuleSupport(matchSupport, relation.Support)
			evidenceIDs = appendBoundedStrings(evidenceIDs, relation.EvidenceIDs, maxCapabilityMatchEvidence)
		}
		if !supportMeetsMinimum(matchSupport, spec.MinimumSupport) {
			continue
		}
		trace := make([]behavior.MatchTraceClause, 0, len(flowMatch.operations)+len(flowMatch.relations))
		for index, operation := range flowMatch.operations {
			trace = append(trace, operationTrace(fmt.Sprintf("%s.resource_flow.steps[%d].operation", path, index), operation.ID))
		}
		for index, relation := range flowMatch.relations {
			tracePath := path + ".resource_flow.steps[0].produces"
			if index > 0 {
				step := (index + 1) / 2
				suffix := "precedes"
				if index%2 == 0 {
					suffix = "consumes"
				}
				tracePath = fmt.Sprintf("%s.resource_flow.steps[%d].%s", path, step, suffix)
			}
			trace = append(trace, operationRelationTrace(tracePath, relation.ID))
		}
		item := capabilityMatch(spec.Metadata, matchSupport, flowMatch.operations, subject(flowMatch.operations), []behavior.Resource{flowMatch.resource}, evidenceIDs, trace)
		item.ArchitectureScopes = operationArchitectureScopes(flowMatch.operations)
		out = append(out, item)
	}
	return deduplicateCapabilityMatches(out)
}

func resourceFlowRelationResource(relation behavior.OperationRelation, kind behavior.RelationKind, operation behavior.ModeledOperation, role behavior.ResourceRole, expectedKey behavior.ResourceIdentityKey) (behavior.Resource, bool) {
	if relation.Kind != kind || relation.Architecture != operation.Architecture || !sameRuleExecution(relation.Execution, operation.Execution) {
		return behavior.Resource{}, false
	}
	var endpoint behavior.RelationEndpoint
	switch kind {
	case behavior.RelationProduces:
		if relation.From.Kind != behavior.RelationEndpointOperation || relation.From.ID != operation.ID || relation.To.Kind != behavior.RelationEndpointResource {
			return behavior.Resource{}, false
		}
		endpoint = relation.To
	case behavior.RelationConsumes:
		if relation.From.Kind != behavior.RelationEndpointResource || relation.To.Kind != behavior.RelationEndpointOperation || relation.To.ID != operation.ID {
			return behavior.Resource{}, false
		}
		endpoint = relation.From
	default:
		return behavior.Resource{}, false
	}
	if endpoint.ResourceRole != role || endpoint.Resource == nil || !operationHasExactResourceBinding(operation, role, *endpoint.Resource) {
		return behavior.Resource{}, false
	}
	key, ok := endpoint.Resource.CorrelationKey()
	if !ok || expectedKey != "" && key != expectedKey {
		return behavior.Resource{}, false
	}
	return *endpoint.Resource, true
}

func operationHasExactResourceBinding(operation behavior.ModeledOperation, role behavior.ResourceRole, resource behavior.Resource) bool {
	for _, binding := range operation.ResourceBindings {
		if binding.Role == role && binding.Resource.Key() == resource.Key() {
			return true
		}
	}
	return false
}

func sameRuleExecution(left, right behavior.ExecutionContext) bool {
	leftKey, leftErr := behavior.NewExecutionKey(left)
	rightKey, rightErr := behavior.NewExecutionKey(right)
	return leftErr == nil && rightErr == nil && leftKey == rightKey
}

func mergeCorrelatedResource(left, right behavior.Resource) (behavior.Resource, bool) {
	leftKey, leftOK := left.CorrelationKey()
	rightKey, rightOK := right.CorrelationKey()
	if !leftOK || !rightOK || leftKey != rightKey {
		return behavior.Resource{}, false
	}
	left.Classifications = append(left.Classifications, right.Classifications...)
	merged, err := behavior.NormalizeResource(left)
	return merged, err == nil
}
