package rules

import (
	"fmt"
	"regexp"

	"github.com/0x4D31/maratus/internal/behavior"
)

// Pattern is the sealed rule-expression surface. Rule declarations compose
// values returned by the constructors in this package; arbitrary evaluators
// cannot implement Pattern outside the rule engine.
type Pattern interface {
	patternNode()
}

type PatternNodeKind string

const (
	PatternNodeOperation     PatternNodeKind = "operation"
	PatternNodeFeature       PatternNodeKind = "feature"
	PatternNodeExecutionRoot PatternNodeKind = "execution-root"
	PatternNodeLibraryRule   PatternNodeKind = "library-rule"
	PatternNodeAny           PatternNodeKind = "any"
	PatternNodeEach          PatternNodeKind = "each"
	PatternNodeRelate        PatternNodeKind = "relate"
	PatternNodeResourceFlow  PatternNodeKind = "resource-flow"
)

// PatternNodeKinds returns the pattern nodes implemented by the current
// closed expression surface. It deliberately excludes planned constructs.
func PatternNodeKinds() []PatternNodeKind {
	return []PatternNodeKind{PatternNodeOperation, PatternNodeFeature, PatternNodeExecutionRoot, PatternNodeLibraryRule, PatternNodeAny, PatternNodeEach, PatternNodeRelate, PatternNodeResourceFlow}
}

type anyPattern struct {
	patterns []Pattern
}

type eachPattern struct {
	left        Pattern
	right       Pattern
	constraints []EachConstraint
}

func (eachPattern) patternNode() {}

func (anyPattern) patternNode() {}

type relatePattern struct {
	left        Pattern
	right       Pattern
	constraints []RelationConstraint
}

func (relatePattern) patternNode() {}

type resourceFlowPattern struct {
	steps []ResourceFlowStep
}

func (resourceFlowPattern) patternNode() {}

// ResourceFlowStep is the sealed step surface accepted by ResourceFlow.
type ResourceFlowStep interface {
	resourceFlowStepNode()
}

type resourceFlowStepPattern struct {
	operation Pattern
	role      behavior.ResourceRole
}

func (resourceFlowStepPattern) resourceFlowStepNode() {}

const maxResourceFlowSteps = 8

type operationPattern struct {
	kind        behavior.OperationKind
	constraints []OperationConstraint
}

func (operationPattern) patternNode() {}

type featurePattern struct {
	key string
}

func (featurePattern) patternNode() {}

type executionRootPattern struct {
	kind  string
	names []string
}

const (
	maxExecutionRootPatternKindBytes = 128
	maxExecutionRootPatternNames     = 64
	maxExecutionRootPatternNameBytes = 512
)

func (executionRootPattern) patternNode() {}

type libraryRulePattern struct {
	id string
}

func (libraryRulePattern) patternNode() {}

// EachConstraint is the sealed join surface accepted by Each.
type EachConstraint interface {
	eachConstraintNode()
}

type EachConstraintKind string

const (
	EachConstraintSameContext       EachConstraintKind = "same-context"
	EachConstraintSameExecutionRoot EachConstraintKind = "same-execution-root"
	EachConstraintSharedEvidence    EachConstraintKind = "shared-evidence"
)

// EachConstraintKinds returns the conjunction constraints implemented by the
// current closed expression surface.
func EachConstraintKinds() []EachConstraintKind {
	return []EachConstraintKind{EachConstraintSameContext, EachConstraintSameExecutionRoot, EachConstraintSharedEvidence}
}

type sameContextPattern struct{}

func (sameContextPattern) eachConstraintNode() {}

// SameContext requires exact subject-node, scope, architecture, and normalized
// execution ownership equality between an operation and a Feature. The scope
// must be non-empty.
func SameContext() EachConstraint { return sameContextPattern{} }

type sameExecutionRootPattern struct{}

func (sameExecutionRootPattern) eachConstraintNode() {}

// SameExecutionRoot requires an operation to be connected to an exact matched
// ExecutionRoot. The engine projects only the qualifying roots and compatible
// invoked targets into the public match.
func SameExecutionRoot() EachConstraint { return sameExecutionRootPattern{} }

type sharedEvidencePattern struct{}

func (sharedEvidencePattern) eachConstraintNode() {}

// SharedEvidence requires at least one identical located evidence record to
// support both sides of an Each expression.
func SharedEvidence() EachConstraint { return sharedEvidencePattern{} }

// OperationConstraint is the sealed constraint surface accepted by Operation.
// Constructors in this package return valid implementations.
type OperationConstraint interface {
	operationConstraintNode()
}

type OperationConstraintKind string

const (
	OperationConstraintClassifiedResourceBinding         OperationConstraintKind = "classified-resource-binding"
	OperationConstraintConcreteClassifiedResourceBinding OperationConstraintKind = "concrete-classified-resource-binding"
	OperationConstraintConcreteResourceBinding           OperationConstraintKind = "concrete-resource-binding"
	OperationConstraintResourceBinding                   OperationConstraintKind = "resource-binding"
)

// OperationConstraintKinds returns the operation constraints implemented by
// the current closed expression surface.
func OperationConstraintKinds() []OperationConstraintKind {
	return []OperationConstraintKind{
		OperationConstraintClassifiedResourceBinding,
		OperationConstraintConcreteClassifiedResourceBinding,
		OperationConstraintConcreteResourceBinding,
		OperationConstraintResourceBinding,
	}
}

// RelationConstraint is the sealed constraint surface accepted by Relate.
type RelationConstraint interface {
	relationConstraintNode()
}

type RelationConstraintKind string

const RelationConstraintRelatedBy RelationConstraintKind = "related-by"

// RelationConstraintKinds returns the relation constraints implemented by the
// current closed expression surface.
func RelationConstraintKinds() []RelationConstraintKind {
	return []RelationConstraintKind{RelationConstraintRelatedBy}
}

type relatedByPattern struct {
	kind behavior.RelationKind
}

func (relatedByPattern) relationConstraintNode() {}

// RelatedBy requires an evidenced typed relation directed from the left
// operation to the right operation of a Relate expression.
func RelatedBy(kind behavior.RelationKind) RelationConstraint {
	return relatedByPattern{kind: kind}
}

type resourceBindingPattern struct {
	role           behavior.ResourceRole
	resourceKind   behavior.ResourceKind
	classification behavior.ResourceClassification
	concrete       bool
}

func (resourceBindingPattern) operationConstraintNode() {}

// ResourceBinding requires an operation binding with the exact semantic role
// and physical resource kind.
func ResourceBinding(role behavior.ResourceRole, kind behavior.ResourceKind) OperationConstraint {
	return resourceBindingPattern{role: role, resourceKind: kind}
}

// ClassifiedResourceBinding additionally requires one semantic classification
// without changing the resource's physical kind.
func ClassifiedResourceBinding(role behavior.ResourceRole, kind behavior.ResourceKind, classification behavior.ResourceClassification) OperationConstraint {
	return resourceBindingPattern{role: role, resourceKind: kind, classification: classification}
}

// ConcreteClassifiedResourceBinding requires both an exact semantic
// classification and a statically known non-empty resource value. Keeping
// these requirements in one constraint ensures they apply to the same
// binding when an operation carries multiple resources under one role.
func ConcreteClassifiedResourceBinding(role behavior.ResourceRole, kind behavior.ResourceKind, classification behavior.ResourceClassification) OperationConstraint {
	return resourceBindingPattern{role: role, resourceKind: kind, classification: classification, concrete: true}
}

// ConcreteResourceBinding additionally requires a statically known non-empty
// resource value. It is distinct from ResourceBinding because an abstract
// resource can be a valid operation input without establishing a concrete
// affected resource for a capability match.
func ConcreteResourceBinding(role behavior.ResourceRole, kind behavior.ResourceKind) OperationConstraint {
	return resourceBindingPattern{role: role, resourceKind: kind, concrete: true}
}

// Operation matches one reportable modeled operation of the requested kind.
// The engine derives the public CapabilityMatch; the rule declaration never
// receives the graph or constructs report records itself.
func Operation(kind behavior.OperationKind, constraints ...OperationConstraint) Pattern {
	return operationPattern{kind: kind, constraints: append([]OperationConstraint(nil), constraints...)}
}

// Feature matches one retained scoped observation by its exact stable key.
// A Feature cannot independently emit a public CapabilityMatch.
func Feature(key string) Pattern {
	return featurePattern{key: key}
}

// ExecutionRoot matches a retained structural root by exact kind and, when
// supplied, one of the exact names. Root facts constrain operation-backed
// matches; they cannot independently emit a public CapabilityMatch.
func ExecutionRoot(kind string, names ...string) Pattern {
	return executionRootPattern{kind: kind, names: append([]string(nil), names...)}
}

// LibraryRuleRef reuses the Match expression of one stable LibraryRule ID.
// Catalog compilation resolves references into a cycle-checked dependency DAG;
// the referenced library rule never emits an analyst-facing capability itself.
func LibraryRuleRef(id string) Pattern {
	return libraryRulePattern{id: id}
}

// Any matches each alternative independently and returns the deterministic
// union of their engine-derived matches. Alternatives remain closed Patterns;
// Any cannot invoke rule code or inspect the graph itself.
func Any(patterns ...Pattern) Pattern {
	return anyPattern{patterns: append([]Pattern(nil), patterns...)}
}

// Each requires one direct Operation and one direct Feature to satisfy every
// explicit conjunction constraint. The initial surface deliberately requires
// exact context and shared evidence instead of treating co-occurrence as a
// join.
func Each(left, right Pattern, constraints ...EachConstraint) Pattern {
	return eachPattern{left: left, right: right, constraints: append([]EachConstraint(nil), constraints...)}
}

// Relate joins two operation patterns through one or more explicit typed
// relation constraints. Co-occurrence is never an implicit join.
func Relate(left, right Pattern, constraints ...RelationConstraint) Pattern {
	return relatePattern{left: left, right: right, constraints: append([]RelationConstraint(nil), constraints...)}
}

// FlowStep declares the resource role through which one direct Operation
// participates in a ResourceFlow. The operation must explicitly constrain the
// same role to a physical resource kind.
func FlowStep(operation Pattern, role behavior.ResourceRole) ResourceFlowStep {
	return resourceFlowStepPattern{operation: operation, role: role}
}

// ResourceFlow requires the first step to produce one concrete resource, every
// later step to consume that same physical resource under its declared role,
// and an explicit precedes relation between each adjacent operation.
func ResourceFlow(steps ...ResourceFlowStep) Pattern {
	return resourceFlowPattern{steps: append([]ResourceFlowStep(nil), steps...)}
}

type patternDiagnostic struct {
	Code       string
	Field      string
	Message    string
	Suggestion string
}

func validatePattern(pattern Pattern) []patternDiagnostic {
	return validatePatternAt(pattern, "match")
}

func validatePatternAt(pattern Pattern, fieldPrefix string) []patternDiagnostic {
	switch pattern := pattern.(type) {
	case operationPattern:
		var diagnostics []patternDiagnostic
		if !behavior.ValidOperationKind(pattern.kind) {
			diagnostics = append(diagnostics, patternDiagnostic{
				Code:       "RULE_OPERATION_KIND_INVALID",
				Field:      fieldPrefix + ".operation.kind",
				Message:    fmt.Sprintf("operation kind %q is not in the closed vocabulary", pattern.kind),
				Suggestion: "choose a kind returned by the operation vocabulary",
			})
		}
		for index, constraint := range pattern.constraints {
			field := fmt.Sprintf("%s.operation.constraints[%d]", fieldPrefix, index)
			binding, ok := constraint.(resourceBindingPattern)
			if !ok {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_OPERATION_CONSTRAINT_INVALID", Field: field, Message: "operation constraint is not in the closed vocabulary", Suggestion: "use ResourceBinding with typed vocabulary values"})
				continue
			}
			if !behavior.ValidResourceRole(binding.role) {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RESOURCE_ROLE_INVALID", Field: field + ".role", Message: fmt.Sprintf("resource role %q is not in the closed vocabulary", binding.role), Suggestion: "choose a role returned by the resource-role vocabulary"})
			}
			if !behavior.ValidResourceKind(binding.resourceKind) {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RESOURCE_KIND_INVALID", Field: field + ".kind", Message: fmt.Sprintf("resource kind %q is not in the closed vocabulary", binding.resourceKind), Suggestion: "choose a physical kind returned by the resource vocabulary"})
			}
			if behavior.ValidOperationKind(pattern.kind) && behavior.ValidResourceRole(binding.role) && behavior.ValidResourceKind(binding.resourceKind) && !behavior.ValidOperationResourceRole(pattern.kind, binding.role, binding.resourceKind) {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RESOURCE_BINDING_INCOMPATIBLE", Field: field, Message: fmt.Sprintf("resource role %q and kind %q are incompatible with operation %q", binding.role, binding.resourceKind, pattern.kind), Suggestion: "use a role and physical kind accepted by the operation resource policy"})
			}
			if binding.classification != "" && !behavior.ValidResourceClassificationForKind(binding.resourceKind, binding.classification) {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RESOURCE_CLASSIFICATION_INVALID", Field: field + ".classification", Message: fmt.Sprintf("classification %q is incompatible with resource kind %q", binding.classification, binding.resourceKind), Suggestion: "choose a classification accepted by the physical resource kind"})
			}
		}
		return diagnostics
	case featurePattern:
		if !stableFeatureKey.MatchString(pattern.key) {
			return []patternDiagnostic{{
				Code:       "RULE_FEATURE_KEY_INVALID",
				Field:      fieldPrefix + ".feature.key",
				Message:    fmt.Sprintf("feature key %q is not a stable dotted identifier", pattern.key),
				Suggestion: "use the exact normalized key emitted by a retained Feature producer",
			}}
		}
		return nil
	case executionRootPattern:
		var diagnostics []patternDiagnostic
		if len(pattern.kind) > maxExecutionRootPatternKindBytes || !stableExecutionRootKind.MatchString(pattern.kind) {
			diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EXECUTION_ROOT_KIND_INVALID", Field: fieldPrefix + ".execution_root.kind", Message: fmt.Sprintf("execution-root kind %q is not a stable identifier", pattern.kind), Suggestion: "use an exact non-empty execution-root kind"})
		}
		if len(pattern.names) > maxExecutionRootPatternNames {
			diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EXECUTION_ROOT_NAMES_LIMIT", Field: fieldPrefix + ".execution_root.names", Message: fmt.Sprintf("execution-root pattern has %d names; limit is %d", len(pattern.names), maxExecutionRootPatternNames), Suggestion: "split the rule into bounded alternatives or reduce the accepted name set"})
		}
		seen := map[string]bool{}
		for index, name := range pattern.names {
			field := fmt.Sprintf("%s.execution_root.names[%d]", fieldPrefix, index)
			if name == "" || len(name) > maxExecutionRootPatternNameBytes {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EXECUTION_ROOT_NAME_INVALID", Field: field, Message: "execution-root name is empty or exceeds the bounded length", Suggestion: "use an exact non-empty bounded root name or omit the name constraint"})
			} else if seen[name] {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EXECUTION_ROOT_NAME_DUPLICATE", Field: field, Message: fmt.Sprintf("execution-root name %q is repeated", name), Suggestion: "declare each accepted name once"})
			}
			seen[name] = true
		}
		return diagnostics
	case anyPattern:
		if len(pattern.patterns) < 2 {
			return []patternDiagnostic{{
				Code:       "RULE_ANY_ARITY_INVALID",
				Field:      fieldPrefix + ".any",
				Message:    "Any requires at least two alternatives",
				Suggestion: "declare two or more closed patterns, or remove the redundant Any",
			}}
		}
		var diagnostics []patternDiagnostic
		for index, child := range pattern.patterns {
			diagnostics = append(diagnostics, validatePatternAt(child, fmt.Sprintf("%s.any[%d]", fieldPrefix, index))...)
		}
		return diagnostics
	case eachPattern:
		var diagnostics []patternDiagnostic
		if _, ok := pattern.left.(operationPattern); !ok {
			diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EACH_OPERAND_INVALID", Field: fieldPrefix + ".each.left", Message: "Each currently requires a direct Operation pattern on the left", Suggestion: "use Operation as the left operand"})
		}
		_, featureRight := pattern.right.(featurePattern)
		_, rootRight := pattern.right.(executionRootPattern)
		if !featureRight && !rootRight {
			diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EACH_OPERAND_INVALID", Field: fieldPrefix + ".each.right", Message: "Each requires a direct Feature or ExecutionRoot pattern on the right", Suggestion: "use Feature or ExecutionRoot as the right operand"})
		}
		diagnostics = append(diagnostics, validatePatternAt(pattern.left, fieldPrefix+".each.left")...)
		diagnostics = append(diagnostics, validatePatternAt(pattern.right, fieldPrefix+".each.right")...)
		seenSameContext := false
		seenSameExecutionRoot := false
		seenSharedEvidence := false
		for index, constraint := range pattern.constraints {
			field := fmt.Sprintf("%s.each.constraints[%d]", fieldPrefix, index)
			switch constraint.(type) {
			case sameContextPattern:
				if seenSameContext {
					diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EACH_CONSTRAINT_DUPLICATE", Field: field, Message: "Each repeats SameContext", Suggestion: "declare SameContext once"})
				}
				seenSameContext = true
			case sameExecutionRootPattern:
				if seenSameExecutionRoot {
					diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EACH_CONSTRAINT_DUPLICATE", Field: field, Message: "Each repeats SameExecutionRoot", Suggestion: "declare SameExecutionRoot once"})
				}
				seenSameExecutionRoot = true
			case sharedEvidencePattern:
				if seenSharedEvidence {
					diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EACH_CONSTRAINT_DUPLICATE", Field: field, Message: "Each repeats SharedEvidence", Suggestion: "declare SharedEvidence once"})
				}
				seenSharedEvidence = true
			default:
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EACH_CONSTRAINT_INVALID", Field: field, Message: "Each constraint is not in the closed vocabulary", Suggestion: "use the constraints required by the right-hand fact"})
			}
		}
		if featureRight {
			if !seenSameContext {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EACH_CONTEXT_REQUIRED", Field: fieldPrefix + ".each.constraints", Message: "an operation/Feature Each requires explicit exact context equality", Suggestion: "add SameContext"})
			}
			if !seenSharedEvidence {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EACH_EVIDENCE_REQUIRED", Field: fieldPrefix + ".each.constraints", Message: "an operation/Feature Each requires an explicit shared evidence identity", Suggestion: "add SharedEvidence"})
			}
			if seenSameExecutionRoot {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EACH_CONSTRAINT_INCOMPATIBLE", Field: fieldPrefix + ".each.constraints", Message: "SameExecutionRoot is not a Feature join constraint", Suggestion: "remove SameExecutionRoot"})
			}
		}
		if rootRight {
			if !seenSameExecutionRoot {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EACH_EXECUTION_ROOT_REQUIRED", Field: fieldPrefix + ".each.constraints", Message: "an operation/ExecutionRoot Each requires explicit root ownership", Suggestion: "add SameExecutionRoot"})
			}
			if seenSameContext || seenSharedEvidence {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_EACH_CONSTRAINT_INCOMPATIBLE", Field: fieldPrefix + ".each.constraints", Message: "Feature context/evidence constraints are not ExecutionRoot join constraints", Suggestion: "use only SameExecutionRoot"})
			}
		}
		return diagnostics
	case relatePattern:
		var diagnostics []patternDiagnostic
		if _, ok := pattern.left.(operationPattern); !ok {
			diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RELATE_OPERAND_INVALID", Field: fieldPrefix + ".relate.left", Message: "Relate currently requires a direct Operation pattern on the left", Suggestion: "use Operation as the left operand"})
		}
		if _, ok := pattern.right.(operationPattern); !ok {
			diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RELATE_OPERAND_INVALID", Field: fieldPrefix + ".relate.right", Message: "Relate currently requires a direct Operation pattern on the right", Suggestion: "use Operation as the right operand"})
		}
		diagnostics = append(diagnostics, validatePatternAt(pattern.left, fieldPrefix+".relate.left")...)
		diagnostics = append(diagnostics, validatePatternAt(pattern.right, fieldPrefix+".relate.right")...)
		if len(pattern.constraints) != 1 {
			diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RELATE_CONSTRAINT_ARITY", Field: fieldPrefix + ".relate.constraints", Message: "Relate requires exactly one explicit typed relation", Suggestion: "add one RelatedBy with an operation-to-operation relation kind"})
		}
		for index, constraint := range pattern.constraints {
			field := fmt.Sprintf("%s.relate.constraints[%d]", fieldPrefix, index)
			related, ok := constraint.(relatedByPattern)
			if !ok {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RELATION_CONSTRAINT_INVALID", Field: field, Message: "relation constraint is not in the closed vocabulary", Suggestion: "use RelatedBy with a typed relation kind"})
				continue
			}
			if !behavior.ValidRelationKind(related.kind) {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RELATION_KIND_INVALID", Field: field + ".kind", Message: fmt.Sprintf("relation kind %q is not in the closed vocabulary", related.kind), Suggestion: "choose a kind returned by the relation vocabulary"})
			} else if !behavior.ValidRelationEndpoints(related.kind, behavior.RelationEndpointOperation, behavior.RelationEndpointOperation) {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RELATION_ENDPOINTS_INCOMPATIBLE", Field: field, Message: fmt.Sprintf("relation kind %q does not connect operation to operation", related.kind), Suggestion: "choose an operation-to-operation relation kind"})
			}
		}
		return diagnostics
	case resourceFlowPattern:
		var diagnostics []patternDiagnostic
		if len(pattern.steps) < 2 || len(pattern.steps) > maxResourceFlowSteps {
			diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RESOURCE_FLOW_ARITY_INVALID", Field: fieldPrefix + ".resource_flow.steps", Message: fmt.Sprintf("ResourceFlow has %d steps; expected 2 through %d", len(pattern.steps), maxResourceFlowSteps), Suggestion: "declare a bounded path with at least a producer and consumer"})
		}
		for index, rawStep := range pattern.steps {
			field := fmt.Sprintf("%s.resource_flow.steps[%d]", fieldPrefix, index)
			step, ok := rawStep.(resourceFlowStepPattern)
			if !ok {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RESOURCE_FLOW_STEP_INVALID", Field: field, Message: "resource-flow step is not in the closed vocabulary", Suggestion: "construct each step with FlowStep"})
				continue
			}
			operation, operationOK := step.operation.(operationPattern)
			if !operationOK {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RESOURCE_FLOW_OPERATION_INVALID", Field: field + ".operation", Message: "resource-flow step requires a direct Operation pattern", Suggestion: "use Operation inside FlowStep"})
			}
			diagnostics = append(diagnostics, validatePatternAt(step.operation, field+".operation")...)
			if !behavior.ValidResourceRole(step.role) {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RESOURCE_FLOW_ROLE_INVALID", Field: field + ".role", Message: fmt.Sprintf("resource-flow role %q is not in the closed vocabulary", step.role), Suggestion: "choose a role returned by the resource-role vocabulary"})
				continue
			}
			if operationOK && !operationPatternConstrainsRole(operation, step.role) {
				diagnostics = append(diagnostics, patternDiagnostic{Code: "RULE_RESOURCE_FLOW_BINDING_REQUIRED", Field: field + ".operation", Message: fmt.Sprintf("operation %q does not constrain resource-flow role %q", operation.kind, step.role), Suggestion: "add ResourceBinding for the same role and physical resource kind"})
			}
		}
		return diagnostics
	default:
		return []patternDiagnostic{{
			Code:       "RULE_PATTERN_INVALID",
			Field:      fieldPrefix,
			Message:    "rule match expression is not a supported closed pattern",
			Suggestion: "construct the expression with the rules package pattern constructors",
		}}
	}
}

var stableFeatureKey = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)
var stableExecutionRootKind = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)

func everyPatternMatchHasOperation(pattern Pattern) bool {
	switch pattern := pattern.(type) {
	case operationPattern, eachPattern, relatePattern, resourceFlowPattern:
		return true
	case featurePattern, executionRootPattern:
		return false
	case anyPattern:
		if len(pattern.patterns) == 0 {
			return false
		}
		for _, child := range pattern.patterns {
			if !everyPatternMatchHasOperation(child) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func evaluatePatternSpec(view *analysisView, budget *ruleWorkBudget, spec Spec) []behavior.CapabilityMatch {
	if view == nil || spec.Kind != CapabilityRule || spec.Match == nil || !spec.MinimumSupport.Valid() || spec.MinimumSupport == behavior.SupportHeuristic {
		return nil
	}
	return evaluatePatternNode(view, budget, spec, spec.Match, "match")
}

func evaluatePatternNode(view *analysisView, budget *ruleWorkBudget, spec Spec, pattern Pattern, path string) []behavior.CapabilityMatch {
	switch pattern := pattern.(type) {
	case operationPattern:
		operations := view.matchingOperations(pattern, budget)
		matched := operations[:0]
		for _, operation := range operations {
			if !reportableOperation(operation) || !supportMeetsMinimum(operation.Support, spec.MinimumSupport) {
				continue
			}
			matched = append(matched, projectPatternBindings(operation, pattern))
		}
		traced := make([]matchedOperation, 0, len(matched))
		for _, operation := range matched {
			traced = append(traced, matchedOperation{operation: operation, trace: []behavior.MatchTraceClause{operationTrace(path, operation.ID)}})
		}
		return capabilityMatchesForOperations(spec.Metadata, traced)
	case anyPattern:
		var matches []behavior.CapabilityMatch
		for index, child := range pattern.patterns {
			if !budget.charge(1) {
				return deduplicateCapabilityMatches(matches)
			}
			matches = append(matches, evaluatePatternNode(view, budget, spec, child, fmt.Sprintf("%s.any[%d]", path, index))...)
		}
		return deduplicateCapabilityMatches(matches)
	case eachPattern:
		return evaluateEachPattern(view, budget, spec, pattern, path)
	case relatePattern:
		return evaluateRelatePattern(view, budget, spec, pattern, path)
	case resourceFlowPattern:
		return evaluateResourceFlowPattern(view, budget, spec, pattern, path)
	default:
		return nil
	}
}

func operationPatternConstrainsRole(pattern operationPattern, role behavior.ResourceRole) bool {
	for _, constraint := range pattern.constraints {
		binding, ok := constraint.(resourceBindingPattern)
		if ok && binding.role == role && behavior.ValidResourceKind(binding.resourceKind) {
			return true
		}
	}
	return false
}

func supportMeetsMinimum(actual, minimum behavior.Support) bool {
	if !actual.Valid() || !minimum.Valid() {
		return false
	}
	return supportRank(actual) <= supportRank(minimum)
}
