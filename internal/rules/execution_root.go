package rules

import "github.com/0x4D31/maratus/internal/behavior"

func evaluateOperationExecutionRootEach(view *analysisView, budget *ruleWorkBudget, spec Spec, pattern eachPattern, path string) []behavior.CapabilityMatch {
	operationPattern, operationOK := pattern.left.(operationPattern)
	rootPattern, rootOK := pattern.right.(executionRootPattern)
	if !operationOK || !rootOK || !validExecutionRootEachConstraints(pattern.constraints) {
		return nil
	}

	operations := reportablePatternOperations(view.matchingOperations(operationPattern, budget), operationPattern, spec.MinimumSupport)
	roots := view.matchingExecutionRoots(rootPattern, budget)
	if len(operations) == 0 || len(roots) == 0 {
		return nil
	}

	rootsByID := make(map[string]behavior.ExecutionRoot, len(roots))
	for _, root := range roots {
		if !budget.charge(1) {
			return nil
		}
		if root.ID == "" || root.Kind == "" {
			continue
		}
		rootsByID[root.ID] = root
	}
	if len(rootsByID) == 0 {
		return nil
	}

	matched := make([]matchedOperation, 0, min(len(operations), ruleCapabilityMatchCandidateLimit))
	for _, operation := range operations {
		if len(matched) >= ruleCapabilityMatchCandidateLimit {
			markRuleEvaluationPartial(view.graph)
			break
		}
		if operation.ScopeID == "" {
			continue
		}
		execution, ok := normalizedExecution(operation.Execution)
		if !ok || execution.Connectivity != behavior.ConnectivityConnected {
			continue
		}
		if !budget.charge(1 + len(execution.ExecutionRootIDs) + len(execution.InvokedTargetIDs)) {
			return nil
		}

		retainedRoots := make([]string, 0, len(execution.ExecutionRootIDs))
		var rootEvidence []string
		for _, rootID := range execution.ExecutionRootIDs {
			root, exists := rootsByID[rootID]
			if !exists {
				continue
			}
			retainedRoots = append(retainedRoots, rootID)
			rootEvidence = appendBoundedStrings(rootEvidence, root.EvidenceIDs, maxCapabilityMatchEvidence)
		}
		if len(retainedRoots) == 0 {
			continue
		}

		retainedTargets := make([]string, 0, len(execution.InvokedTargetIDs))
		for _, targetID := range execution.InvokedTargetIDs {
			target, exists := view.invokedTarget(targetID, budget)
			if !exists {
				continue
			}
			targetExecution, targetOK := normalizedExecution(target.Execution)
			if !targetOK || targetExecution.Connectivity != behavior.ConnectivityConnected {
				continue
			}
			if !budget.charge(1 + len(targetExecution.ExecutionRootIDs) + len(retainedRoots)) {
				return nil
			}
			if len(intersectSortedStrings(retainedRoots, targetExecution.ExecutionRootIDs)) > 0 {
				retainedTargets = append(retainedTargets, targetID)
			}
		}

		projected, err := behavior.NormalizeExecutionContext(behavior.ExecutionContext{
			Connectivity:     behavior.ConnectivityConnected,
			ExecutionRootIDs: retainedRoots,
			InvokedTargetIDs: retainedTargets,
		})
		if err != nil {
			continue
		}
		operation.Execution = projected
		operation.EvidenceIDs = appendBoundedStrings(operation.EvidenceIDs, rootEvidence, maxCapabilityMatchEvidence)
		matched = append(matched, matchedOperation{operation: operation, trace: []behavior.MatchTraceClause{
			operationTrace(path+".each.left", operation.ID),
			executionRootTrace(path+".each.right", retainedRoots...),
		}})
	}
	return capabilityMatchesForOperations(spec.Metadata, matched)
}
