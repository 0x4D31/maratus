package rules

import (
	"slices"
	"strconv"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

type ruleWorkBudget struct {
	graph     *behavior.Graph
	remaining int
	exhausted bool
}

func newRuleWorkBudget(graph *behavior.Graph) *ruleWorkBudget {
	return &ruleWorkBudget{graph: graph, remaining: maxRuleMatchWork}
}

func (budget *ruleWorkBudget) charge(work int) bool {
	if budget == nil || budget.exhausted {
		return false
	}
	if work < 0 || work > budget.remaining {
		budget.exhausted = true
		markRuleWorkPartial(budget.graph)
		return false
	}
	budget.remaining -= work
	return true
}

func capabilityMatchesForOperations(meta Metadata, matched []matchedOperation) []behavior.CapabilityMatch {
	type group struct {
		support    behavior.Support
		subject    string
		resources  []behavior.Resource
		operations []behavior.ModeledOperation
		evidence   []string
		arches     []string
		trace      []behavior.MatchTraceClause
	}
	type groupKey struct {
		support   behavior.Support
		subject   string
		bindings  string
		scope     string
		arch      string
		execution behavior.ExecutionKey
	}
	byKey := map[groupKey]int{}
	var groups []group
	for _, item := range matched {
		operation := item.operation
		execution, ok := normalizedExecution(operation.Execution)
		if !ok {
			continue
		}
		executionKey, err := behavior.NewExecutionKey(execution)
		if err != nil {
			continue
		}
		key := groupKey{
			support:   operation.Support,
			subject:   operation.SubjectNodeID,
			bindings:  operationBindingsKey(operation),
			scope:     operation.ScopeID,
			arch:      operation.Architecture,
			execution: executionKey,
		}
		if idx, ok := byKey[key]; ok {
			groups[idx].operations = appendSupportingOperation(groups[idx].operations, operation)
			groups[idx].evidence = appendBoundedStrings(groups[idx].evidence, operation.EvidenceIDs, maxCapabilityMatchEvidence)
			groups[idx].arches = appendBoundedStrings(groups[idx].arches, []string{operation.Architecture}, maxCapabilityMatchResources)
			groups[idx].trace = mergeMatchTrace(groups[idx].trace, item.trace)
			continue
		}
		byKey[key] = len(groups)
		groups = append(groups, group{
			support:    operation.Support,
			subject:    operation.SubjectNodeID,
			resources:  resources([]behavior.ModeledOperation{operation}),
			operations: appendSupportingOperation(nil, operation),
			evidence:   appendBoundedStrings(nil, operation.EvidenceIDs, maxCapabilityMatchEvidence),
			arches:     appendBoundedStrings(nil, []string{operation.Architecture}, maxCapabilityMatchResources),
			trace:      append([]behavior.MatchTraceClause(nil), item.trace...),
		})
	}
	var out []behavior.CapabilityMatch
	for _, group := range groups {
		if len(out) >= ruleCapabilityMatchCandidateLimit {
			break
		}
		item := capabilityMatch(meta, group.support, group.operations, group.subject, group.resources, group.evidence, group.trace)
		item.ArchitectureScopes = uniqueSortedStrings(group.arches)
		out = append(out, item)
	}
	return out
}

func weakerRuleSupport(left, right behavior.Support) behavior.Support {
	if supportRank(right) > supportRank(left) {
		return right
	}
	return left
}

func supportBoundedByOperations(requested behavior.Support, operations []behavior.ModeledOperation) behavior.Support {
	result := requested
	for _, operation := range operations {
		if supportRank(operation.Support) > supportRank(result) {
			result = operation.Support
		}
	}
	return result
}

func reportableOperation(operation behavior.ModeledOperation) bool {
	if operation.ID == "" || operation.SubjectNodeID == "" || operation.Support == behavior.SupportHeuristic {
		return false
	}
	_, ok := normalizedExecution(operation.Execution)
	return ok
}

func capabilityMatch(meta Metadata, support behavior.Support, operations []behavior.ModeledOperation, subjectNodeID string, resources []behavior.Resource, evidenceIDs []string, trace []behavior.MatchTraceClause) behavior.CapabilityMatch {
	execution := executionForOperations(operations)
	operations = appendSupportingOperations(nil, operations)
	return behavior.CapabilityMatch{
		RuleID:            meta.ID,
		Title:             meta.Title,
		Namespace:         meta.Namespace,
		Support:           support,
		Execution:         execution,
		SubjectNodeID:     subjectNodeID,
		AffectedResources: boundedResources(resources),
		OperationIDs:      operationIDs(operations),
		EvidenceIDs:       boundedUniqueStrings(evidenceIDs, maxCapabilityMatchEvidence),
		Attack:            meta.Attack,
		MBC:               meta.MBC,
		MatchTrace:        trace,
	}
}

func resources(operations []behavior.ModeledOperation) []behavior.Resource {
	var out []behavior.Resource
	seen := map[behavior.ResourceKey]bool{}
	for _, operation := range operations {
		for _, binding := range operation.ResourceBindings {
			key := binding.Resource.Key()
			if binding.Resource.Kind == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, binding.Resource)
			if len(out) >= maxCapabilityMatchResources {
				return out
			}
		}
	}
	return out
}

func evidence(operations []behavior.ModeledOperation) []string {
	var out []string
	for _, operation := range operations {
		out = appendBoundedStrings(out, operation.EvidenceIDs, maxCapabilityMatchEvidence)
		if len(out) >= maxCapabilityMatchEvidence {
			break
		}
	}
	return boundedUniqueStrings(out, maxCapabilityMatchEvidence)
}

func operationIDs(operations []behavior.ModeledOperation) []string {
	var out []string
	for _, operation := range operations {
		out = appendBoundedStrings(out, []string{operation.ID}, maxCapabilityMatchOperations)
		if len(out) >= maxCapabilityMatchOperations {
			break
		}
	}
	return boundedUniqueStrings(out, maxCapabilityMatchOperations)
}

func appendSupportingOperation(operations []behavior.ModeledOperation, operation behavior.ModeledOperation) []behavior.ModeledOperation {
	if operation.ID == "" || len(operations) >= maxCapabilityMatchOperations {
		return operations
	}
	for _, existing := range operations {
		if existing.ID == operation.ID {
			return operations
		}
	}
	return append(operations, operation)
}

func appendSupportingOperations(operations, additions []behavior.ModeledOperation) []behavior.ModeledOperation {
	for _, operation := range additions {
		operations = appendSupportingOperation(operations, operation)
		if len(operations) >= maxCapabilityMatchOperations {
			break
		}
	}
	return operations
}

func normalizedExecution(execution behavior.ExecutionContext) (behavior.ExecutionContext, bool) {
	normalized, err := behavior.NormalizeExecutionContext(execution)
	return normalized, err == nil
}

func executionForOperations(operations []behavior.ModeledOperation) behavior.ExecutionContext {
	contexts := make([]behavior.ExecutionContext, 0, len(operations))
	for _, operation := range operations {
		context, ok := normalizedExecution(operation.Execution)
		if !ok {
			return behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		}
		contexts = append(contexts, context)
	}
	if len(contexts) == 0 {
		return behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
	}
	if len(contexts) == 1 {
		return cloneExecutionContext(contexts[0])
	}
	allUnconnected := true
	allConnected := true
	for _, context := range contexts {
		allUnconnected = allUnconnected && context.Connectivity == behavior.ConnectivityUnconnected
		allConnected = allConnected && context.Connectivity == behavior.ConnectivityConnected
	}
	if allUnconnected {
		return behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnconnected}
	}
	if !allConnected {
		return behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
	}
	commonRoots := append([]string(nil), contexts[0].ExecutionRootIDs...)
	for _, context := range contexts[1:] {
		commonRoots = intersectSortedStrings(commonRoots, context.ExecutionRootIDs)
		if len(commonRoots) == 0 {
			return behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		}
	}
	commonTargets := append([]string(nil), contexts[0].InvokedTargetIDs...)
	for _, context := range contexts[1:] {
		commonTargets = intersectSortedStrings(commonTargets, context.InvokedTargetIDs)
		if len(commonTargets) == 0 {
			break
		}
	}
	normalized, err := behavior.NormalizeExecutionContext(behavior.ExecutionContext{
		Connectivity:     behavior.ConnectivityConnected,
		ExecutionRootIDs: commonRoots,
		InvokedTargetIDs: commonTargets,
	})
	if err != nil {
		return behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
	}
	return normalized
}

func cloneExecutionContext(context behavior.ExecutionContext) behavior.ExecutionContext {
	context.ExecutionRootIDs = append([]string(nil), context.ExecutionRootIDs...)
	context.InvokedTargetIDs = append([]string(nil), context.InvokedTargetIDs...)
	return context
}

func intersectSortedStrings(left, right []string) []string {
	result := make([]string, 0, min(len(left), len(right)))
	for leftIndex, rightIndex := 0, 0; leftIndex < len(left) && rightIndex < len(right); {
		switch {
		case left[leftIndex] < right[rightIndex]:
			leftIndex++
		case left[leftIndex] > right[rightIndex]:
			rightIndex++
		default:
			result = append(result, left[leftIndex])
			leftIndex++
			rightIndex++
		}
	}
	return result
}

func deduplicateCapabilityMatches(items []behavior.CapabilityMatch) []behavior.CapabilityMatch {
	if len(items) < 2 {
		return items
	}
	sortCapabilityMatchesNormalized(items)
	out := items[:0]
	for _, item := range items {
		if len(out) > 0 && capabilityMatchesEqual(out[len(out)-1], item) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func capabilityMatchesEqual(left, right behavior.CapabilityMatch) bool {
	return left.ID == right.ID &&
		left.RuleID == right.RuleID &&
		left.Title == right.Title &&
		left.Namespace == right.Namespace &&
		left.Support == right.Support &&
		left.Execution.Connectivity == right.Execution.Connectivity &&
		left.SubjectNodeID == right.SubjectNodeID &&
		slices.Equal(left.Execution.ExecutionRootIDs, right.Execution.ExecutionRootIDs) &&
		slices.Equal(left.Execution.InvokedTargetIDs, right.Execution.InvokedTargetIDs) &&
		resourcesEqual(left.AffectedResources, right.AffectedResources) &&
		slices.Equal(left.OperationIDs, right.OperationIDs) &&
		slices.Equal(left.EvidenceIDs, right.EvidenceIDs) &&
		slices.Equal(left.Attack, right.Attack) &&
		slices.Equal(left.MBC, right.MBC) &&
		slices.Equal(left.ArchitectureScopes, right.ArchitectureScopes) &&
		compareMatchTrace(left.MatchTrace, right.MatchTrace) == 0
}

func boundedResources(values []behavior.Resource) []behavior.Resource {
	seen := map[behavior.ResourceKey]bool{}
	out := make([]behavior.Resource, 0, min(len(values), maxCapabilityMatchResources))
	for _, value := range values {
		key := value.Key()
		if value.Kind == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
		if len(out) >= maxCapabilityMatchResources {
			break
		}
	}
	return out
}

func operationBindingsKey(operation behavior.ModeledOperation) string {
	var builder strings.Builder
	for _, binding := range operation.ResourceBindings {
		builder.WriteString(strconv.Itoa(len(binding.Role)))
		builder.WriteByte(':')
		builder.WriteString(string(binding.Role))
		resourceKey := string(binding.Resource.Key())
		builder.WriteString(strconv.Itoa(len(resourceKey)))
		builder.WriteByte(':')
		builder.WriteString(resourceKey)
	}
	return builder.String()
}

func resourcesEqual(left, right []behavior.Resource) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Key() != right[index].Key() {
			return false
		}
	}
	return true
}

func appendBoundedStrings(out, values []string, limit int) []string {
	if len(out) >= limit {
		return out
	}
	seen := make(map[string]bool, len(out))
	for _, value := range out {
		if value != "" {
			seen[value] = true
		}
	}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func boundedUniqueStrings(values []string, limit int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, min(len(values), limit))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func operationArchitectureScopes(operations []behavior.ModeledOperation) []string {
	var values []string
	for _, operation := range operations {
		if operation.Architecture != "" {
			values = append(values, operation.Architecture)
		}
	}
	return uniqueSortedStrings(values)
}

func subject(operations []behavior.ModeledOperation) string {
	if len(operations) == 0 {
		return ""
	}
	return operations[0].SubjectNodeID
}

func unique(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
