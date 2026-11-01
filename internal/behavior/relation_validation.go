package behavior

import (
	"fmt"
	"reflect"
)

type relationScopePair struct {
	From string
	To   string
}

func validateRelationAgainstGraph(
	relation OperationRelation,
	operations map[string]ModeledOperation,
	scopes map[string]Scope,
	roots map[string]ExecutionRoot,
	targets map[string]InvokedTarget,
	callScopes map[relationScopePair]struct{},
) error {
	if err := validateRelationEndpointReference("from", relation.From, operations, scopes, roots, targets); err != nil {
		return err
	}
	if err := validateRelationEndpointReference("to", relation.To, operations, scopes, roots, targets); err != nil {
		return err
	}

	switch relation.Kind {
	case RelationProduces:
		operation := operations[relation.From.ID]
		if !operationHasExactBinding(operation, relation.To.ResourceRole, *relation.To.Resource) {
			return fmt.Errorf("to resource is not bound to source operation %q with role %q", operation.ID, relation.To.ResourceRole)
		}
	case RelationConsumes:
		operation := operations[relation.To.ID]
		if !operationHasExactBinding(operation, relation.From.ResourceRole, *relation.From.Resource) {
			return fmt.Errorf("from resource is not bound to target operation %q with role %q", operation.ID, relation.From.ResourceRole)
		}
	case RelationCalls:
		from, to := scopes[relation.From.ID], scopes[relation.To.ID]
		if from.NodeID != "" && to.NodeID != "" && from.NodeID != to.NodeID {
			return fmt.Errorf("calls endpoints belong to different artifact nodes %q and %q", from.NodeID, to.NodeID)
		}
	case RelationInvokes:
		if relation.From.Kind == RelationEndpointInvokedTarget && relation.From.ID == relation.To.ID {
			return fmt.Errorf("invokes relation cannot target itself")
		}
		target := targets[relation.To.ID]
		if relation.From.Kind == RelationEndpointExecutionRoot && (target.Source.Kind != EntityKindExecutionRoot || target.Source.ID != relation.From.ID) {
			return fmt.Errorf("invoked target %q is not sourced from execution root %q", target.ID, relation.From.ID)
		}
		if relation.From.Kind == RelationEndpointInvokedTarget && (target.Source.Kind != EntityKindInvokedTarget || target.Source.ID != relation.From.ID) {
			return fmt.Errorf("invoked target %q is not sourced from invoked target %q", target.ID, relation.From.ID)
		}
	case RelationPipesTo, RelationPrecedes:
		if relation.From.ID == relation.To.ID {
			return fmt.Errorf("%s relation cannot target the same operation", relation.Kind)
		}
		from, to := operations[relation.From.ID], operations[relation.To.ID]
		if from.SubjectNodeID != to.SubjectNodeID {
			return fmt.Errorf("%s relation crosses artifact nodes %q -> %q", relation.Kind, from.SubjectNodeID, to.SubjectNodeID)
		}
		// Empty scope IDs are unscoped, not proof that two operations share a
		// scope. The relation itself may directly support same-node unscoped
		// ordering; distinct known scopes require an explicit call boundary.
		if from.ScopeID != "" && to.ScopeID != "" && from.ScopeID != to.ScopeID {
			_, forward := callScopes[relationScopePair{From: from.ScopeID, To: to.ScopeID}]
			_, reverse := callScopes[relationScopePair{From: to.ScopeID, To: from.ScopeID}]
			if !forward && !reverse {
				return fmt.Errorf("%s relation crosses scopes %q -> %q without a calls relation", relation.Kind, from.ScopeID, to.ScopeID)
			}
		}
	}

	if err := validateRelationSupport(relation, operations); err != nil {
		return err
	}
	if err := validateRelationContext(relation, operations, scopes, targets); err != nil {
		return err
	}
	return nil
}

// validateRelationEvidenceLineage requires every retained relation proof to
// come from one of its exact endpoint facts. Calls are the exception only in
// shape: scope records do not carry evidence, so a calls relation must project
// evidence from a directly observed call Feature that names the exact caller
// scope and callee function in the same node, architecture, and execution
// context.
//
// In permissive mode, evidence IDs absent from the graph are left for final
// report validation. This preserves builders that intentionally assemble
// forward references. An evidence ID that is already known is never allowed to
// bypass the endpoint lineage check.
func validateRelationEvidenceLineage(
	relation OperationRelation,
	evidence map[string]Evidence,
	features []Feature,
	operations map[string]ModeledOperation,
	scopes map[string]Scope,
	roots map[string]ExecutionRoot,
	targets map[string]InvokedTarget,
	strict bool,
) error {
	allowed := make(map[string]struct{})
	addTo := func(set map[string]struct{}, ids []string) {
		for _, id := range ids {
			if id != "" {
				set[id] = struct{}{}
			}
		}
	}
	mergeAllowed := func(set map[string]struct{}) {
		for id := range set {
			allowed[id] = struct{}{}
		}
	}
	var requiredOperationProofs []struct {
		endpointID string
		evidence   map[string]struct{}
	}

	if relation.Kind == RelationCalls {
		caller := scopes[relation.From.ID]
		callee := scopes[relation.To.ID]
		if uniqueRelationCalleeScope(caller, callee, relation, scopes) {
			for _, feature := range features {
				if !relationDirectCallFeature(feature, caller, callee, relation) {
					continue
				}
				addTo(allowed, feature.EvidenceIDs)
			}
		}
	} else {
		for _, endpoint := range []RelationEndpoint{relation.From, relation.To} {
			switch endpoint.Kind {
			case RelationEndpointOperation:
				operation, ok := operations[endpoint.ID]
				if !ok {
					continue
				}
				operationEvidence := make(map[string]struct{})
				addTo(operationEvidence, operation.EvidenceIDs)
				resourceEndpoint, exactResource := relationResourceEndpoint(relation)
				for _, binding := range operation.ResourceBindings {
					if exactResource && (binding.Role != resourceEndpoint.ResourceRole || binding.Resource.Key() != resourceEndpoint.Resource.Key()) {
						continue
					}
					addTo(operationEvidence, binding.EvidenceIDs)
				}
				mergeAllowed(operationEvidence)
				if relation.Kind == RelationPipesTo || relation.Kind == RelationPrecedes {
					requiredOperationProofs = append(requiredOperationProofs, struct {
						endpointID string
						evidence   map[string]struct{}
					}{endpointID: endpoint.ID, evidence: operationEvidence})
				}
			case RelationEndpointExecutionRoot:
				if root, ok := roots[endpoint.ID]; ok {
					addTo(allowed, root.EvidenceIDs)
				}
			case RelationEndpointInvokedTarget:
				if target, ok := targets[endpoint.ID]; ok {
					addTo(allowed, target.EvidenceIDs)
				}
			}
		}
	}

	for _, evidenceID := range relation.EvidenceIDs {
		if _, ok := allowed[evidenceID]; ok {
			continue
		}
		if _, known := evidence[evidenceID]; !known && !strict {
			continue
		}
		if relation.Kind == RelationCalls {
			return fmt.Errorf("evidence %q is not evidence of an exact direct-call feature for scopes %q -> %q", evidenceID, relation.From.ID, relation.To.ID)
		}
		return fmt.Errorf("evidence %q is not direct evidence or resource-binding evidence of a relation endpoint", evidenceID)
	}
	for _, required := range requiredOperationProofs {
		proved := false
		for _, evidenceID := range relation.EvidenceIDs {
			if _, ok := required.evidence[evidenceID]; ok {
				proved = true
				break
			}
		}
		if proved {
			continue
		}
		if !strict && len(required.evidence) == 0 {
			continue
		}
		return fmt.Errorf("evidence does not include direct or resource-binding proof from operation endpoint %q", required.endpointID)
	}
	return nil
}

func uniqueRelationCalleeScope(caller, callee Scope, relation OperationRelation, scopes map[string]Scope) bool {
	if caller.ID == "" || callee.ID == "" || caller.NodeID == "" || callee.Function == "" {
		return false
	}
	matches := 0
	for _, candidate := range scopes {
		if candidate.NodeID == caller.NodeID && candidate.Architecture == relation.Architecture && candidate.Function == callee.Function {
			matches++
		}
	}
	return matches == 1
}

func relationResourceEndpoint(relation OperationRelation) (RelationEndpoint, bool) {
	if relation.From.Kind == RelationEndpointResource {
		return relation.From, true
	}
	if relation.To.Kind == RelationEndpointResource {
		return relation.To, true
	}
	return RelationEndpoint{}, false
}

func relationDirectCallFeature(feature Feature, caller, callee Scope, relation OperationRelation) bool {
	if feature.Key != "script.function_call" && feature.Key != "macho.function_call" {
		return false
	}
	if caller.ID == "" || callee.ID == "" || callee.Function == "" ||
		feature.ScopeID != caller.ID || feature.NodeID == "" ||
		feature.NodeID != caller.NodeID || caller.NodeID != callee.NodeID ||
		feature.Value != callee.Function || feature.Architecture != relation.Architecture ||
		feature.SourceFunction != caller.Function ||
		!sameNormalizedExecution(feature.Execution, relation.Execution) {
		return false
	}
	return supportStrength(relation.Support) <= supportStrength(feature.Support)
}

func validateRelationEndpointReference(
	path string,
	endpoint RelationEndpoint,
	operations map[string]ModeledOperation,
	scopes map[string]Scope,
	roots map[string]ExecutionRoot,
	targets map[string]InvokedTarget,
) error {
	switch endpoint.Kind {
	case RelationEndpointOperation:
		if _, ok := operations[endpoint.ID]; !ok {
			return fmt.Errorf("%s.id references missing operation %q", path, endpoint.ID)
		}
	case RelationEndpointScope:
		if _, ok := scopes[endpoint.ID]; !ok {
			return fmt.Errorf("%s.id references missing scope %q", path, endpoint.ID)
		}
	case RelationEndpointExecutionRoot:
		if _, ok := roots[endpoint.ID]; !ok {
			return fmt.Errorf("%s.id references missing execution root %q", path, endpoint.ID)
		}
	case RelationEndpointInvokedTarget:
		target, ok := targets[endpoint.ID]
		if !ok {
			return fmt.Errorf("%s.id references missing invoked target %q", path, endpoint.ID)
		}
		if target.ScopeID != "" {
			if _, ok := scopes[target.ScopeID]; !ok {
				return fmt.Errorf("%s.id references invoked target %q with missing scope %q", path, endpoint.ID, target.ScopeID)
			}
		}
	case RelationEndpointResource:
		return nil
	default:
		return fmt.Errorf("%s.kind has invalid value %q", path, endpoint.Kind)
	}
	return nil
}

func operationHasExactBinding(operation ModeledOperation, role ResourceRole, resource Resource) bool {
	for _, binding := range operation.ResourceBindings {
		if binding.Role == role && binding.Resource.Key() == resource.Key() {
			return true
		}
	}
	return false
}

func validateRelationSupport(relation OperationRelation, operations map[string]ModeledOperation) error {
	for _, endpoint := range []RelationEndpoint{relation.From, relation.To} {
		if endpoint.Kind != RelationEndpointOperation {
			continue
		}
		operation := operations[endpoint.ID]
		if supportStrength(relation.Support) > supportStrength(operation.Support) {
			return fmt.Errorf("support %s exceeds operation %q support %s", relation.Support, operation.ID, operation.Support)
		}
	}
	return nil
}

func supportStrength(support Support) int {
	switch support {
	case SupportDirect:
		return 3
	case SupportCorroborated:
		return 2
	case SupportHeuristic:
		return 1
	default:
		return 0
	}
}

func validateRelationContext(
	relation OperationRelation,
	operations map[string]ModeledOperation,
	scopes map[string]Scope,
	targets map[string]InvokedTarget,
) error {
	for endpointIndex, endpoint := range []RelationEndpoint{relation.From, relation.To} {
		var architecture string
		switch endpoint.Kind {
		case RelationEndpointOperation:
			operation := operations[endpoint.ID]
			if !sameNormalizedExecution(relation.Execution, operation.Execution) {
				return fmt.Errorf("execution context differs from operation %q", operation.ID)
			}
			architecture = operation.Architecture
		case RelationEndpointScope:
			architecture = scopes[endpoint.ID].Architecture
		case RelationEndpointInvokedTarget:
			target := targets[endpoint.ID]
			if target.ScopeID != "" {
				architecture = scopes[target.ScopeID].Architecture
			}
			if endpointIndex == 1 && relation.Kind == RelationInvokes && !sameNormalizedExecution(relation.Execution, target.Execution) {
				return fmt.Errorf("execution context differs from invoked target %q source ownership", target.ID)
			}
		}
		if endpoint.Kind == RelationEndpointOperation || endpoint.Kind == RelationEndpointScope {
			if relation.Architecture != architecture {
				return fmt.Errorf("architecture %q differs from endpoint %q architecture %q", relation.Architecture, endpoint.ID, architecture)
			}
		} else if architecture != "" && relation.Architecture != architecture {
			return fmt.Errorf("architecture %q differs from endpoint %q architecture %q", relation.Architecture, endpoint.ID, architecture)
		}
	}
	return nil
}

func sameNormalizedExecution(left, right ExecutionContext) bool {
	leftNormalized, leftErr := NormalizeExecutionContext(left)
	rightNormalized, rightErr := NormalizeExecutionContext(right)
	return leftErr == nil && rightErr == nil && reflect.DeepEqual(leftNormalized, rightNormalized)
}

func validatePrecedesAcyclic(relations []OperationRelation) error {
	adjacency := make(map[string][]string)
	indegree := make(map[string]int)
	for _, relation := range relations {
		if relation.Kind != RelationPrecedes {
			continue
		}
		from, to := relation.From.ID, relation.To.ID
		adjacency[from] = append(adjacency[from], to)
		if _, ok := indegree[from]; !ok {
			indegree[from] = 0
		}
		indegree[to]++
	}
	queue := make([]string, 0, len(indegree))
	for operationID, count := range indegree {
		if count == 0 {
			queue = append(queue, operationID)
		}
	}
	visited := 0
	for len(queue) > 0 {
		operationID := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		visited++
		for _, targetID := range adjacency[operationID] {
			indegree[targetID]--
			if indegree[targetID] == 0 {
				queue = append(queue, targetID)
			}
		}
	}
	if visited != len(indegree) {
		return fmt.Errorf("operation_relations precedes graph contains a cycle")
	}
	return nil
}
