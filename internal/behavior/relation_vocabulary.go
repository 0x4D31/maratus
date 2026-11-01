package behavior

// RelationKind is the closed vocabulary for supported semantic relationships.
// Relations describe retained static facts; capability interpretation belongs
// to rules rather than this vocabulary.
type RelationKind string

const (
	RelationCalls    RelationKind = "calls"
	RelationConsumes RelationKind = "consumes"
	RelationInvokes  RelationKind = "invokes"
	RelationPipesTo  RelationKind = "pipes-to"
	RelationPrecedes RelationKind = "precedes"
	RelationProduces RelationKind = "produces"
)

var relationKinds = [...]RelationKind{
	RelationCalls,
	RelationConsumes,
	RelationInvokes,
	RelationPipesTo,
	RelationPrecedes,
	RelationProduces,
}

// RelationEndpointKind is the closed endpoint union used by operation
// relations. It is separate from EntityKind because execution ownership
// sources must not silently start accepting operations or value resources.
type RelationEndpointKind string

const (
	RelationEndpointExecutionRoot RelationEndpointKind = "execution-root"
	RelationEndpointInvokedTarget RelationEndpointKind = "invoked-target"
	RelationEndpointOperation     RelationEndpointKind = "operation"
	RelationEndpointResource      RelationEndpointKind = "resource"
	RelationEndpointScope         RelationEndpointKind = "scope"
)

var relationEndpointKinds = [...]RelationEndpointKind{
	RelationEndpointExecutionRoot,
	RelationEndpointInvokedTarget,
	RelationEndpointOperation,
	RelationEndpointResource,
	RelationEndpointScope,
}

// RelationEndpointPolicy describes one allowed directed endpoint pair for a
// relation kind.
type RelationEndpointPolicy struct {
	From RelationEndpointKind `json:"from"`
	To   RelationEndpointKind `json:"to"`
}

var relationEndpointPolicies = map[RelationKind][]RelationEndpointPolicy{
	RelationCalls:    {{From: RelationEndpointScope, To: RelationEndpointScope}},
	RelationConsumes: {{From: RelationEndpointResource, To: RelationEndpointOperation}},
	RelationInvokes: {
		{From: RelationEndpointExecutionRoot, To: RelationEndpointInvokedTarget},
		{From: RelationEndpointInvokedTarget, To: RelationEndpointInvokedTarget},
		{From: RelationEndpointOperation, To: RelationEndpointInvokedTarget},
		{From: RelationEndpointScope, To: RelationEndpointInvokedTarget},
	},
	RelationPipesTo:  {{From: RelationEndpointOperation, To: RelationEndpointOperation}},
	RelationPrecedes: {{From: RelationEndpointOperation, To: RelationEndpointOperation}},
	RelationProduces: {{From: RelationEndpointOperation, To: RelationEndpointResource}},
}

func RelationKinds() []RelationKind {
	return append([]RelationKind(nil), relationKinds[:]...)
}

func RelationEndpointKinds() []RelationEndpointKind {
	return append([]RelationEndpointKind(nil), relationEndpointKinds[:]...)
}

// RelationEndpointPolicies returns a defensive copy of the directed endpoint
// pairs accepted by kind.
func RelationEndpointPolicies(kind RelationKind) []RelationEndpointPolicy {
	return append([]RelationEndpointPolicy(nil), relationEndpointPolicies[kind]...)
}

func ValidRelationKind(kind RelationKind) bool {
	for _, candidate := range relationKinds {
		if candidate == kind {
			return true
		}
	}
	return false
}

func ValidRelationEndpointKind(kind RelationEndpointKind) bool {
	for _, candidate := range relationEndpointKinds {
		if candidate == kind {
			return true
		}
	}
	return false
}

func ValidRelationEndpoints(kind RelationKind, from, to RelationEndpointKind) bool {
	for _, pair := range relationEndpointPolicies[kind] {
		if pair.From == from && pair.To == to {
			return true
		}
	}
	return false
}
