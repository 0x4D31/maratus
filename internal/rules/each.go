package rules

import "github.com/0x4D31/maratus/internal/behavior"

func evaluateEachPattern(view *analysisView, budget *ruleWorkBudget, spec Spec, pattern eachPattern, path string) []behavior.CapabilityMatch {
	switch pattern.right.(type) {
	case featurePattern:
		return evaluateOperationFeatureEach(view, budget, spec, pattern, path)
	case executionRootPattern:
		return evaluateOperationExecutionRootEach(view, budget, spec, pattern, path)
	default:
		return nil
	}
}

func evaluateOperationFeatureEach(view *analysisView, budget *ruleWorkBudget, spec Spec, pattern eachPattern, path string) []behavior.CapabilityMatch {
	operationPattern, operationOK := pattern.left.(operationPattern)
	featurePattern, featureOK := pattern.right.(featurePattern)
	if !operationOK || !featureOK || !validFeatureEachConstraints(pattern.constraints) {
		return nil
	}

	operations := reportablePatternOperations(view.matchingOperations(operationPattern, budget), operationPattern, spec.MinimumSupport)
	features := reportablePatternFeatures(view.matchingFeatures(featurePattern, budget), spec.MinimumSupport)
	if len(operations) == 0 || len(features) == 0 {
		return nil
	}

	featuresByContext := make(map[behavior.ContextKey][]behavior.Feature)
	for _, feature := range features {
		if !budget.charge(1) {
			return nil
		}
		context, ok := exactFeatureContext(feature)
		if !ok {
			continue
		}
		featuresByContext[context] = append(featuresByContext[context], feature)
	}

	matchedOperations := make([]matchedOperation, 0, min(len(operations), ruleCapabilityMatchCandidateLimit))
	for _, operation := range operations {
		if len(matchedOperations) >= ruleCapabilityMatchCandidateLimit {
			markRuleEvaluationPartial(view.graph)
			break
		}
		context, ok := exactOperationContext(operation)
		if !ok {
			continue
		}
		candidates := featuresByContext[context]
		if !budget.charge(1 + len(candidates)) {
			return nil
		}
		bestSupport := behavior.Support("")
		var featureEvidence []string
		var featureIDs []string
		for _, feature := range candidates {
			shared, complete := recordsShareEvidence(operation.EvidenceIDs, feature.EvidenceIDs, budget)
			if !complete {
				return nil
			}
			if !shared {
				continue
			}
			candidateSupport := weakerRuleSupport(operation.Support, feature.Support)
			if !supportMeetsMinimum(candidateSupport, spec.MinimumSupport) {
				continue
			}
			if bestSupport == "" || supportRank(candidateSupport) < supportRank(bestSupport) {
				bestSupport = candidateSupport
				featureEvidence = appendBoundedStrings(nil, feature.EvidenceIDs, maxCapabilityMatchEvidence)
				featureIDs = appendBoundedStrings(nil, []string{feature.ID}, maxCapabilityMatchTraceIDs)
			} else if candidateSupport == bestSupport {
				featureEvidence = appendBoundedStrings(featureEvidence, feature.EvidenceIDs, maxCapabilityMatchEvidence)
				featureIDs = appendBoundedStrings(featureIDs, []string{feature.ID}, maxCapabilityMatchTraceIDs)
			}
		}
		if bestSupport == "" {
			continue
		}
		operation.Support = bestSupport
		operation.EvidenceIDs = appendBoundedStrings(operation.EvidenceIDs, featureEvidence, maxCapabilityMatchEvidence)
		matchedOperations = append(matchedOperations, matchedOperation{operation: operation, trace: []behavior.MatchTraceClause{
			operationTrace(path+".each.left", operation.ID),
			featureTrace(path+".each.right", featureIDs...),
		}})
	}
	return capabilityMatchesForOperations(spec.Metadata, matchedOperations)
}

func validFeatureEachConstraints(constraints []EachConstraint) bool {
	if len(constraints) != 2 {
		return false
	}
	sameContext := false
	sharedEvidence := false
	for _, constraint := range constraints {
		switch constraint.(type) {
		case sameContextPattern:
			if sameContext {
				return false
			}
			sameContext = true
		case sharedEvidencePattern:
			if sharedEvidence {
				return false
			}
			sharedEvidence = true
		default:
			return false
		}
	}
	return sameContext && sharedEvidence
}

func validExecutionRootEachConstraints(constraints []EachConstraint) bool {
	if len(constraints) != 1 {
		return false
	}
	_, ok := constraints[0].(sameExecutionRootPattern)
	return ok
}

func reportablePatternFeatures(features []behavior.Feature, minimum behavior.Support) []behavior.Feature {
	out := features[:0]
	for _, feature := range features {
		if feature.ID == "" || feature.NodeID == "" || feature.ScopeID == "" || feature.Key == "" || feature.Support == behavior.SupportHeuristic || !feature.Support.Valid() || !supportMeetsMinimum(feature.Support, minimum) || !hasRuleEvidence(feature.EvidenceIDs) {
			continue
		}
		if _, ok := normalizedExecution(feature.Execution); !ok {
			continue
		}
		out = append(out, feature)
	}
	return out
}

func exactFeatureContext(feature behavior.Feature) (behavior.ContextKey, bool) {
	if feature.ScopeID == "" {
		return behavior.ContextKey{}, false
	}
	context, err := behavior.NewContextKey(feature.Execution, feature.NodeID, feature.ScopeID, feature.Architecture)
	return context, err == nil
}

func exactOperationContext(operation behavior.ModeledOperation) (behavior.ContextKey, bool) {
	if operation.ScopeID == "" {
		return behavior.ContextKey{}, false
	}
	context, err := behavior.NewContextKey(operation.Execution, operation.SubjectNodeID, operation.ScopeID, operation.Architecture)
	return context, err == nil
}

func recordsShareEvidence(left, right []string, budget *ruleWorkBudget) (bool, bool) {
	if !budget.charge(1 + len(left) + len(right)) {
		return false, false
	}
	if len(left) == 0 || len(right) == 0 {
		return false, true
	}
	if len(left) > len(right) {
		left, right = right, left
	}
	leftIDs := make(map[string]bool, len(left))
	for _, id := range left {
		if id != "" {
			leftIDs[id] = true
		}
	}
	for _, id := range right {
		if leftIDs[id] {
			return true, true
		}
	}
	return false, true
}

func hasRuleEvidence(values []string) bool {
	for _, value := range values {
		if value != "" {
			return true
		}
	}
	return false
}
