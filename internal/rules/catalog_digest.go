package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/0x4D31/maratus/internal/behavior"
)

const catalogDigestNormalizationVersion = "maratus.rule-catalog-digest.v1"

type normalizedCatalogDigest struct {
	Schema string                     `json:"schema"`
	Rules  []normalizedRuleDigestSpec `json:"rules"`
}

type normalizedRuleDigestSpec struct {
	Metadata       normalizedRuleDigestMetadata `json:"metadata"`
	Kind           RuleKind                     `json:"kind"`
	MinimumSupport behavior.Support             `json:"minimum_support"`
	Match          normalizedPatternDigest      `json:"match"`
}

type normalizedRuleDigestMetadata struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Namespace   string   `json:"namespace"`
	Description string   `json:"description"`
	Attack      []string `json:"attack"`
	MBC         []string `json:"mbc"`
}

type normalizedPatternDigest struct {
	Node                 PatternNodeKind                    `json:"node"`
	OperationKind        behavior.OperationKind             `json:"operation_kind,omitempty"`
	FeatureKey           string                             `json:"feature_key,omitempty"`
	ExecutionRootKind    string                             `json:"execution_root_kind,omitempty"`
	ExecutionRootNames   []string                           `json:"execution_root_names,omitempty"`
	LibraryRuleID        string                             `json:"library_rule_id,omitempty"`
	OperationConstraints []normalizedOperationDigest        `json:"operation_constraints,omitempty"`
	EachConstraints      []EachConstraintKind               `json:"each_constraints,omitempty"`
	RelationConstraints  []normalizedRelationDigest         `json:"relation_constraints,omitempty"`
	Children             []normalizedPatternDigest          `json:"children,omitempty"`
	FlowSteps            []normalizedResourceFlowDigestStep `json:"flow_steps,omitempty"`
}

type normalizedOperationDigest struct {
	Kind           OperationConstraintKind         `json:"kind"`
	Role           behavior.ResourceRole           `json:"role"`
	ResourceKind   behavior.ResourceKind           `json:"resource_kind"`
	Classification behavior.ResourceClassification `json:"classification,omitempty"`
	Concrete       bool                            `json:"concrete,omitempty"`
}

type normalizedRelationDigest struct {
	Kind         RelationConstraintKind `json:"kind"`
	RelationKind behavior.RelationKind  `json:"relation_kind"`
}

type normalizedResourceFlowDigestStep struct {
	Role      behavior.ResourceRole   `json:"role"`
	Operation normalizedPatternDigest `json:"operation"`
}

// CatalogDigest returns a deterministic semantic identity for the generated
// built-in catalog. It deliberately ignores declaration order and Go source
// formatting while retaining every rule field and meaningful Pattern order.
func CatalogDigest() string {
	digest, err := catalogDigest(Specs())
	if err != nil {
		panic("invalid generated rule catalog: " + err.Error())
	}
	return digest
}

// ValidCatalogDigest reports whether value is a self-describing SHA-256
// catalog identity in the public report format.
func ValidCatalogDigest(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+sha256.Size*2 || value[:len(prefix)] != prefix {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func catalogDigest(specs []Spec) (string, error) {
	if diagnostics := ValidateSpecs(specs); len(diagnostics) != 0 {
		return "", fmt.Errorf("%s: %s", diagnostics[0].Code, diagnostics[0].Message)
	}
	normalized := normalizedCatalogDigest{Schema: catalogDigestNormalizationVersion, Rules: make([]normalizedRuleDigestSpec, 0, len(specs))}
	for _, spec := range specs {
		match, err := normalizePatternDigest(spec.Match)
		if err != nil {
			return "", fmt.Errorf("rule %s: %w", spec.Metadata.ID, err)
		}
		normalized.Rules = append(normalized.Rules, normalizedRuleDigestSpec{
			Metadata: normalizedRuleDigestMetadata{
				ID: spec.Metadata.ID, Title: spec.Metadata.Title, Namespace: spec.Metadata.Namespace, Description: spec.Metadata.Description,
				Attack: normalizedDigestStrings(spec.Metadata.Attack), MBC: normalizedDigestStrings(spec.Metadata.MBC),
			},
			Kind: spec.Kind, MinimumSupport: spec.MinimumSupport, Match: match,
		})
	}
	sort.Slice(normalized.Rules, func(i, j int) bool { return normalized.Rules[i].Metadata.ID < normalized.Rules[j].Metadata.ID })
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func normalizePatternDigest(pattern Pattern) (normalizedPatternDigest, error) {
	switch pattern := pattern.(type) {
	case operationPattern:
		constraints := make([]normalizedOperationDigest, 0, len(pattern.constraints))
		for _, raw := range pattern.constraints {
			binding, ok := raw.(resourceBindingPattern)
			if !ok {
				return normalizedPatternDigest{}, fmt.Errorf("unsupported operation constraint %T", raw)
			}
			kind := OperationConstraintResourceBinding
			switch {
			case binding.classification != "" && binding.concrete:
				kind = OperationConstraintConcreteClassifiedResourceBinding
			case binding.classification != "":
				kind = OperationConstraintClassifiedResourceBinding
			case binding.concrete:
				kind = OperationConstraintConcreteResourceBinding
			}
			constraints = append(constraints, normalizedOperationDigest{Kind: kind, Role: binding.role, ResourceKind: binding.resourceKind, Classification: binding.classification, Concrete: binding.concrete})
		}
		sort.Slice(constraints, func(i, j int) bool {
			return normalizedOperationDigestKey(constraints[i]) < normalizedOperationDigestKey(constraints[j])
		})
		return normalizedPatternDigest{Node: PatternNodeOperation, OperationKind: pattern.kind, OperationConstraints: constraints}, nil
	case featurePattern:
		return normalizedPatternDigest{Node: PatternNodeFeature, FeatureKey: pattern.key}, nil
	case executionRootPattern:
		return normalizedPatternDigest{Node: PatternNodeExecutionRoot, ExecutionRootKind: pattern.kind, ExecutionRootNames: normalizedDigestStrings(pattern.names)}, nil
	case libraryRulePattern:
		return normalizedPatternDigest{Node: PatternNodeLibraryRule, LibraryRuleID: pattern.id}, nil
	case anyPattern:
		children := make([]normalizedPatternDigest, 0, len(pattern.patterns))
		for _, child := range pattern.patterns {
			normalized, err := normalizePatternDigest(child)
			if err != nil {
				return normalizedPatternDigest{}, err
			}
			children = append(children, normalized)
		}
		sortNormalizedPatternDigests(children)
		return normalizedPatternDigest{Node: PatternNodeAny, Children: children}, nil
	case eachPattern:
		left, err := normalizePatternDigest(pattern.left)
		if err != nil {
			return normalizedPatternDigest{}, err
		}
		right, err := normalizePatternDigest(pattern.right)
		if err != nil {
			return normalizedPatternDigest{}, err
		}
		constraints := make([]EachConstraintKind, 0, len(pattern.constraints))
		for _, constraint := range pattern.constraints {
			switch constraint.(type) {
			case sameContextPattern:
				constraints = append(constraints, EachConstraintSameContext)
			case sameExecutionRootPattern:
				constraints = append(constraints, EachConstraintSameExecutionRoot)
			case sharedEvidencePattern:
				constraints = append(constraints, EachConstraintSharedEvidence)
			default:
				return normalizedPatternDigest{}, fmt.Errorf("unsupported Each constraint %T", constraint)
			}
		}
		sort.Slice(constraints, func(i, j int) bool { return constraints[i] < constraints[j] })
		return normalizedPatternDigest{Node: PatternNodeEach, Children: []normalizedPatternDigest{left, right}, EachConstraints: constraints}, nil
	case relatePattern:
		left, err := normalizePatternDigest(pattern.left)
		if err != nil {
			return normalizedPatternDigest{}, err
		}
		right, err := normalizePatternDigest(pattern.right)
		if err != nil {
			return normalizedPatternDigest{}, err
		}
		constraints := make([]normalizedRelationDigest, 0, len(pattern.constraints))
		for _, constraint := range pattern.constraints {
			related, ok := constraint.(relatedByPattern)
			if !ok {
				return normalizedPatternDigest{}, fmt.Errorf("unsupported relation constraint %T", constraint)
			}
			constraints = append(constraints, normalizedRelationDigest{Kind: RelationConstraintRelatedBy, RelationKind: related.kind})
		}
		sort.Slice(constraints, func(i, j int) bool {
			return normalizedRelationDigestKey(constraints[i]) < normalizedRelationDigestKey(constraints[j])
		})
		return normalizedPatternDigest{Node: PatternNodeRelate, Children: []normalizedPatternDigest{left, right}, RelationConstraints: constraints}, nil
	case resourceFlowPattern:
		steps := make([]normalizedResourceFlowDigestStep, 0, len(pattern.steps))
		for _, raw := range pattern.steps {
			step, ok := raw.(resourceFlowStepPattern)
			if !ok {
				return normalizedPatternDigest{}, fmt.Errorf("unsupported resource-flow step %T", raw)
			}
			operation, err := normalizePatternDigest(step.operation)
			if err != nil {
				return normalizedPatternDigest{}, err
			}
			steps = append(steps, normalizedResourceFlowDigestStep{Role: step.role, Operation: operation})
		}
		return normalizedPatternDigest{Node: PatternNodeResourceFlow, FlowSteps: steps}, nil
	default:
		return normalizedPatternDigest{}, fmt.Errorf("unsupported Pattern %T", pattern)
	}
}

func normalizedDigestStrings(values []string) []string {
	out := append(make([]string, 0, len(values)), values...)
	sort.Strings(out)
	unique := out[:0]
	for _, value := range out {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}

func sortNormalizedPatternDigests(patterns []normalizedPatternDigest) {
	sort.Slice(patterns, func(i, j int) bool {
		left, _ := json.Marshal(patterns[i])
		right, _ := json.Marshal(patterns[j])
		return string(left) < string(right)
	})
}

func normalizedOperationDigestKey(constraint normalizedOperationDigest) string {
	encoded, _ := json.Marshal(constraint)
	return string(encoded)
}

func normalizedRelationDigestKey(constraint normalizedRelationDigest) string {
	encoded, _ := json.Marshal(constraint)
	return string(encoded)
}
