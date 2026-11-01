package rules

import "github.com/0x4D31/maratus/internal/behavior"

const VocabularySchemaVersion = "maratus.rule-vocabulary.v0.2-preview.8"

type Vocabulary struct {
	SchemaVersion                 string                             `json:"schema_version"`
	RuleKinds                     []RuleKind                         `json:"rule_kinds"`
	PatternNodes                  []PatternNodeKind                  `json:"pattern_nodes"`
	OperationConstraints          []OperationConstraintKind          `json:"operation_constraints"`
	EachConstraints               []EachConstraintKind               `json:"each_constraints"`
	RelationConstraints           []RelationConstraintKind           `json:"relation_constraints"`
	TypedCapabilityMinimumSupport []behavior.Support                 `json:"typed_capability_minimum_support"`
	Support                       []behavior.Support                 `json:"support"`
	Connectivity                  []behavior.Connectivity            `json:"connectivity"`
	OperationKinds                []OperationVocabulary              `json:"operation_kinds"`
	ResourceKinds                 []behavior.ResourceKind            `json:"resource_kinds"`
	ResourceRoles                 []behavior.ResourceRole            `json:"resource_roles"`
	ResourceClassifications       []ResourceClassificationVocabulary `json:"resource_classifications"`
	RelationKinds                 []RelationVocabulary               `json:"relation_kinds"`
	RelationEndpointKinds         []behavior.RelationEndpointKind    `json:"relation_endpoint_kinds"`
}

type OperationVocabulary struct {
	Kind          behavior.OperationKind        `json:"kind"`
	ResourceRoles []behavior.ResourceRolePolicy `json:"resource_roles"`
}

type ResourceClassificationVocabulary struct {
	Classification behavior.ResourceClassification `json:"classification"`
	PhysicalKinds  []behavior.ResourceKind         `json:"physical_kinds"`
}

type RelationVocabulary struct {
	Kind      behavior.RelationKind             `json:"kind"`
	Endpoints []behavior.RelationEndpointPolicy `json:"endpoints"`
}

// RuleVocabulary returns the deterministic, compiler-backed vocabulary that
// an author can use today. Planned AST nodes are omitted until implemented.
func RuleVocabulary() Vocabulary {
	operationKinds := behavior.OperationKinds()
	operations := make([]OperationVocabulary, 0, len(operationKinds))
	for _, kind := range operationKinds {
		operations = append(operations, OperationVocabulary{
			Kind:          kind,
			ResourceRoles: behavior.OperationResourcePolicy(kind),
		})
	}

	classifications := behavior.ResourceClassifications()
	classificationVocabulary := make([]ResourceClassificationVocabulary, 0, len(classifications))
	for _, classification := range classifications {
		classificationVocabulary = append(classificationVocabulary, ResourceClassificationVocabulary{
			Classification: classification,
			PhysicalKinds:  behavior.ResourceClassificationKinds(classification),
		})
	}

	relationKinds := behavior.RelationKinds()
	relations := make([]RelationVocabulary, 0, len(relationKinds))
	for _, kind := range relationKinds {
		relations = append(relations, RelationVocabulary{
			Kind:      kind,
			Endpoints: behavior.RelationEndpointPolicies(kind),
		})
	}

	return Vocabulary{
		SchemaVersion:                 VocabularySchemaVersion,
		RuleKinds:                     RuleKinds(),
		PatternNodes:                  PatternNodeKinds(),
		OperationConstraints:          OperationConstraintKinds(),
		EachConstraints:               EachConstraintKinds(),
		RelationConstraints:           RelationConstraintKinds(),
		TypedCapabilityMinimumSupport: []behavior.Support{behavior.SupportDirect, behavior.SupportCorroborated},
		Support:                       behavior.SupportValues(),
		Connectivity:                  behavior.ConnectivityValues(),
		OperationKinds:                operations,
		ResourceKinds:                 behavior.ResourceKinds(),
		ResourceRoles:                 behavior.ResourceRoles(),
		ResourceClassifications:       classificationVocabulary,
		RelationKinds:                 relations,
		RelationEndpointKinds:         behavior.RelationEndpointKinds(),
	}
}
