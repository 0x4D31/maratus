package behavior

import (
	"fmt"
)

const (
	MaxOperationRelations  = DefaultItemLimit
	MaxRelationEvidenceIDs = 64
)

// RelationEndpoint is a closed tagged union. ID is used by ID-bearing
// endpoints. Resource and ResourceRole are used together by value-resource
// endpoints so produces/consumes facts retain the exact operation binding.
type RelationEndpoint struct {
	Kind         RelationEndpointKind `json:"kind"`
	ID           string               `json:"id,omitempty"`
	ResourceRole ResourceRole         `json:"resource_role,omitempty"`
	Resource     *Resource            `json:"resource,omitempty"`
}

// OperationRelation is an evidenced static relationship. Execution and
// Architecture retain the normalized correlation context used to derive the
// relation; they are not inferred later from display strings.
type OperationRelation struct {
	ID           string           `json:"id"`
	Kind         RelationKind     `json:"kind"`
	From         RelationEndpoint `json:"from"`
	To           RelationEndpoint `json:"to"`
	EvidenceIDs  []string         `json:"evidence_ids"`
	Support      Support          `json:"support"`
	Execution    ExecutionContext `json:"execution"`
	Architecture string           `json:"architecture,omitempty"`
}

func IDRelationEndpoint(kind RelationEndpointKind, id string) RelationEndpoint {
	return RelationEndpoint{Kind: kind, ID: id}
}

func ResourceRelationEndpoint(role ResourceRole, resource Resource) RelationEndpoint {
	resourceCopy := resource
	return RelationEndpoint{Kind: RelationEndpointResource, ResourceRole: role, Resource: &resourceCopy}
}

func NormalizeRelationEndpoint(endpoint RelationEndpoint) (RelationEndpoint, error) {
	if !ValidRelationEndpointKind(endpoint.Kind) {
		return RelationEndpoint{}, fmt.Errorf("invalid relation endpoint kind %q", endpoint.Kind)
	}
	if endpoint.Kind != RelationEndpointResource {
		if endpoint.ID == "" {
			return RelationEndpoint{}, fmt.Errorf("%s endpoint requires an ID", endpoint.Kind)
		}
		if endpoint.ResourceRole != "" || endpoint.Resource != nil {
			return RelationEndpoint{}, fmt.Errorf("%s endpoint cannot carry a resource or resource role", endpoint.Kind)
		}
		return endpoint, nil
	}
	if endpoint.ID != "" {
		return RelationEndpoint{}, fmt.Errorf("resource endpoint cannot carry an ID")
	}
	if !ValidResourceRole(endpoint.ResourceRole) {
		return RelationEndpoint{}, fmt.Errorf("resource endpoint has invalid resource role %q", endpoint.ResourceRole)
	}
	if endpoint.Resource == nil {
		return RelationEndpoint{}, fmt.Errorf("resource endpoint requires a resource")
	}
	resource, err := NormalizeResource(*endpoint.Resource)
	if err != nil {
		return RelationEndpoint{}, err
	}
	if resource.Value == "" {
		return RelationEndpoint{}, fmt.Errorf("resource endpoint requires a non-empty value")
	}
	endpoint.Resource = &resource
	return endpoint, nil
}

// NormalizeOperationRelation validates and canonicalizes the self-contained
// relation shape. Graph/report validation additionally resolves endpoint IDs,
// binding ownership, support, context, and ordering constraints.
func NormalizeOperationRelation(relation OperationRelation) (OperationRelation, error) {
	if !ValidRelationKind(relation.Kind) {
		return OperationRelation{}, fmt.Errorf("invalid relation kind %q", relation.Kind)
	}
	from, err := NormalizeRelationEndpoint(relation.From)
	if err != nil {
		return OperationRelation{}, fmt.Errorf("from: %w", err)
	}
	to, err := NormalizeRelationEndpoint(relation.To)
	if err != nil {
		return OperationRelation{}, fmt.Errorf("to: %w", err)
	}
	if !ValidRelationEndpoints(relation.Kind, from.Kind, to.Kind) {
		return OperationRelation{}, fmt.Errorf("relation %q does not accept %q -> %q endpoints", relation.Kind, from.Kind, to.Kind)
	}
	if relation.Support == "" {
		relation.Support = SupportCorroborated
	}
	if !relation.Support.Valid() {
		return OperationRelation{}, fmt.Errorf("invalid support %q", relation.Support)
	}
	if !hasNonemptyString(relation.EvidenceIDs) {
		return OperationRelation{}, fmt.Errorf("relation requires evidence IDs")
	}
	if len(relation.EvidenceIDs) > MaxRelationEvidenceIDs {
		return OperationRelation{}, fmt.Errorf("relation has %d evidence IDs; limit is %d", len(relation.EvidenceIDs), MaxRelationEvidenceIDs)
	}
	execution, err := NormalizeExecutionContext(relation.Execution)
	if err != nil {
		return OperationRelation{}, fmt.Errorf("execution: %w", err)
	}
	relation.From = from
	relation.To = to
	relation.EvidenceIDs = sortedUniqueStrings(append([]string(nil), relation.EvidenceIDs...))
	relation.Execution = execution
	return relation, nil
}
