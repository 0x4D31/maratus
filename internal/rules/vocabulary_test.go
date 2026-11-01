package rules

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestRuleVocabularyDescribesOnlyImplementedClosedSurface(t *testing.T) {
	vocabulary := RuleVocabulary()
	if vocabulary.SchemaVersion != VocabularySchemaVersion {
		t.Fatalf("schema version = %q", vocabulary.SchemaVersion)
	}
	if !reflect.DeepEqual(vocabulary.RuleKinds, []RuleKind{CapabilityRule, LibraryRule}) {
		t.Fatalf("rule kinds = %#v", vocabulary.RuleKinds)
	}
	if !reflect.DeepEqual(vocabulary.PatternNodes, []PatternNodeKind{PatternNodeOperation, PatternNodeFeature, PatternNodeExecutionRoot, PatternNodeLibraryRule, PatternNodeAny, PatternNodeEach, PatternNodeRelate, PatternNodeResourceFlow}) {
		t.Fatalf("pattern nodes = %#v", vocabulary.PatternNodes)
	}
	if !reflect.DeepEqual(vocabulary.OperationConstraints, []OperationConstraintKind{OperationConstraintClassifiedResourceBinding, OperationConstraintConcreteClassifiedResourceBinding, OperationConstraintConcreteResourceBinding, OperationConstraintResourceBinding}) {
		t.Fatalf("operation constraints = %#v", vocabulary.OperationConstraints)
	}
	if !reflect.DeepEqual(vocabulary.EachConstraints, []EachConstraintKind{EachConstraintSameContext, EachConstraintSameExecutionRoot, EachConstraintSharedEvidence}) {
		t.Fatalf("Each constraints = %#v", vocabulary.EachConstraints)
	}
	if !reflect.DeepEqual(vocabulary.RelationConstraints, []RelationConstraintKind{RelationConstraintRelatedBy}) {
		t.Fatalf("relation constraints = %#v", vocabulary.RelationConstraints)
	}
	if !reflect.DeepEqual(vocabulary.TypedCapabilityMinimumSupport, []behavior.Support{behavior.SupportDirect, behavior.SupportCorroborated}) {
		t.Fatalf("typed capability support = %#v", vocabulary.TypedCapabilityMinimumSupport)
	}
	if len(vocabulary.OperationKinds) != len(behavior.OperationKinds()) || len(vocabulary.RelationKinds) != len(behavior.RelationKinds()) {
		t.Fatalf("semantic vocabulary is incomplete: operations=%d relations=%d", len(vocabulary.OperationKinds), len(vocabulary.RelationKinds))
	}
	for _, operation := range vocabulary.OperationKinds {
		if !behavior.ValidOperationKind(operation.Kind) || !reflect.DeepEqual(operation.ResourceRoles, behavior.OperationResourcePolicy(operation.Kind)) {
			t.Fatalf("operation vocabulary drift for %q: %#v", operation.Kind, operation.ResourceRoles)
		}
	}
	for _, relation := range vocabulary.RelationKinds {
		if !behavior.ValidRelationKind(relation.Kind) || !reflect.DeepEqual(relation.Endpoints, behavior.RelationEndpointPolicies(relation.Kind)) {
			t.Fatalf("relation vocabulary drift for %q: %#v", relation.Kind, relation.Endpoints)
		}
	}
}

func TestRuleVocabularyIsDeterministicAndIndependent(t *testing.T) {
	first := RuleVocabulary()
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(RuleVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("vocabulary JSON is nondeterministic:\n%s\n%s", firstJSON, secondJSON)
	}
	if bytes.Contains(firstJSON, []byte(`"From"`)) || bytes.Contains(firstJSON, []byte(`"Kinds"`)) {
		t.Fatalf("vocabulary leaked Go field names: %s", firstJSON)
	}

	first.ResourceKinds[0] = "mutated"
	first.EachConstraints[0] = "mutated"
	first.OperationKinds[0].ResourceRoles[0].Kinds[0] = "mutated"
	first.RelationKinds[0].Endpoints[0].From = "mutated"
	second := RuleVocabulary()
	if second.ResourceKinds[0] == "mutated" || second.EachConstraints[0] == "mutated" || second.OperationKinds[0].ResourceRoles[0].Kinds[0] == "mutated" || second.RelationKinds[0].Endpoints[0].From == "mutated" {
		t.Fatal("vocabulary result aliases authoritative storage")
	}
}
