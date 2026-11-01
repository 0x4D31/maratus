package rules

import "github.com/0x4D31/maratus/internal/behavior"

func evaluateRelatePattern(view *analysisView, budget *ruleWorkBudget, spec Spec, pattern relatePattern, path string) []behavior.CapabilityMatch {
	leftPattern, leftOK := pattern.left.(operationPattern)
	rightPattern, rightOK := pattern.right.(operationPattern)
	if !leftOK || !rightOK || len(pattern.constraints) != 1 {
		return nil
	}
	related, ok := pattern.constraints[0].(relatedByPattern)
	if !ok || !behavior.ValidRelationEndpoints(related.kind, behavior.RelationEndpointOperation, behavior.RelationEndpointOperation) {
		return nil
	}

	left := reportablePatternOperations(view.matchingOperations(leftPattern, budget), leftPattern, spec.MinimumSupport)
	right := reportablePatternOperations(view.matchingOperations(rightPattern, budget), rightPattern, spec.MinimumSupport)
	leftByID := operationMap(left)
	rightByID := operationMap(right)
	if len(leftByID) == 0 || len(rightByID) == 0 {
		return nil
	}

	relations := view.matchingOperationRelations(related.kind, operationIDSet(left), operationIDSet(right), budget)
	out := make([]behavior.CapabilityMatch, 0, min(len(relations), ruleCapabilityMatchCandidateLimit))
	for _, relation := range relations {
		if len(out) >= ruleCapabilityMatchCandidateLimit {
			markRuleEvaluationPartial(view.graph)
			break
		}
		if relation.From.Kind != behavior.RelationEndpointOperation || relation.To.Kind != behavior.RelationEndpointOperation {
			continue
		}
		leftOperation, leftOK := leftByID[relation.From.ID]
		rightOperation, rightOK := rightByID[relation.To.ID]
		if !leftOK || !rightOK || !relationMatchesJoinedOperations(relation, leftOperation, rightOperation) {
			continue
		}
		matchSupport := supportBoundedByOperations(behavior.SupportDirect, []behavior.ModeledOperation{leftOperation, rightOperation})
		matchSupport = weakerRuleSupport(matchSupport, relation.Support)
		if !supportMeetsMinimum(matchSupport, spec.MinimumSupport) {
			continue
		}
		operations := []behavior.ModeledOperation{leftOperation, rightOperation}
		evidenceIDs := appendBoundedStrings(evidence(operations), relation.EvidenceIDs, maxCapabilityMatchEvidence)
		trace := []behavior.MatchTraceClause{
			operationTrace(path+".relate.left", leftOperation.ID),
			operationTrace(path+".relate.right", rightOperation.ID),
			operationRelationTrace(path+".relate.constraint", relation.ID),
		}
		match := capabilityMatch(spec.Metadata, matchSupport, operations, subject(operations), resources(operations), evidenceIDs, trace)
		match.ArchitectureScopes = operationArchitectureScopes(operations)
		out = append(out, match)
	}
	return deduplicateCapabilityMatches(out)
}

func reportablePatternOperations(operations []behavior.ModeledOperation, pattern operationPattern, minimum behavior.Support) []behavior.ModeledOperation {
	out := operations[:0]
	for _, operation := range operations {
		if !reportableOperation(operation) || !supportMeetsMinimum(operation.Support, minimum) {
			continue
		}
		out = append(out, projectPatternBindings(operation, pattern))
	}
	return out
}

func operationMap(operations []behavior.ModeledOperation) map[string]behavior.ModeledOperation {
	out := make(map[string]behavior.ModeledOperation, len(operations))
	for _, operation := range operations {
		if operation.ID != "" {
			out[operation.ID] = operation
		}
	}
	return out
}

func operationIDSet(operations []behavior.ModeledOperation) map[string]bool {
	out := make(map[string]bool, len(operations))
	for _, operation := range operations {
		if operation.ID != "" {
			out[operation.ID] = true
		}
	}
	return out
}

func relationMatchesJoinedOperations(relation behavior.OperationRelation, left, right behavior.ModeledOperation) bool {
	if relation.From.ID != left.ID || relation.To.ID != right.ID || left.SubjectNodeID != right.SubjectNodeID {
		return false
	}
	if relation.Architecture != left.Architecture || relation.Architecture != right.Architecture {
		return false
	}
	relationExecution, relationErr := behavior.NewExecutionKey(relation.Execution)
	leftExecution, leftErr := behavior.NewExecutionKey(left.Execution)
	rightExecution, rightErr := behavior.NewExecutionKey(right.Execution)
	return relationErr == nil && leftErr == nil && rightErr == nil && relationExecution == leftExecution && relationExecution == rightExecution
}
