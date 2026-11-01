package behavior

import (
	"reflect"
	"slices"
	"testing"
)

func TestRelationVocabularyIsClosedSortedAndIndependent(t *testing.T) {
	if !slices.IsSorted(RelationKinds()) || !slices.IsSorted(RelationEndpointKinds()) {
		t.Fatal("relation vocabulary is not sorted")
	}
	for _, kind := range RelationKinds() {
		policies := RelationEndpointPolicies(kind)
		if len(policies) == 0 {
			t.Fatalf("relation %q has no endpoint policy", kind)
		}
		for _, policy := range policies {
			if !ValidRelationEndpointKind(policy.From) || !ValidRelationEndpointKind(policy.To) || !ValidRelationEndpoints(kind, policy.From, policy.To) {
				t.Fatalf("relation %q has invalid policy %#v", kind, policy)
			}
		}
		policies[0].From = "mutated"
		if RelationEndpointPolicies(kind)[0].From == "mutated" {
			t.Fatalf("relation %q policy aliases authoritative storage", kind)
		}
	}
	if policies := RelationEndpointPolicies("arbitrary"); policies != nil {
		t.Fatalf("unknown relation policies = %#v", policies)
	}
	if !reflect.DeepEqual(RelationEndpointPolicies(RelationProduces), []RelationEndpointPolicy{{From: RelationEndpointOperation, To: RelationEndpointResource}}) {
		t.Fatalf("produces endpoint policy = %#v", RelationEndpointPolicies(RelationProduces))
	}
}
