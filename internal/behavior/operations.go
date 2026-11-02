package behavior

import "regexp"

type ModeledOperation struct {
	ID               string            `json:"id"`
	SubjectNodeID    string            `json:"subject_node_id"`
	ScopeID          string            `json:"scope_id,omitempty"`
	Kind             OperationKind     `json:"kind"`
	ResourceBindings []ResourceBinding `json:"resource_bindings"`
	Qualifiers       map[string]string `json:"qualifiers,omitempty"`
	EvidenceIDs      []string          `json:"evidence_ids,omitempty"`
	Support          Support           `json:"support"`
	Execution        ExecutionContext  `json:"execution"`
	SourceFunction   string            `json:"source_function,omitempty"`
	Architecture     string            `json:"architecture,omitempty"`
	Line             int               `json:"line,omitempty"`
	// SourceOrderGroup, SourceOrdinal, and SourceOrderUncertain are transient
	// extractor facts used to distinguish proved source order from lexical or
	// concurrent lookalikes. The resulting evidenced OperationRelation is
	// serialized; parser bookkeeping is not.
	SourceOrderGroup     int  `json:"-"`
	SourceOrdinal        int  `json:"-"`
	SourceOrderUncertain bool `json:"-"`
	// Directory contexts are transient parser proofs, not execution roots or
	// resolved host paths. Only equal nonzero contexts permit relative joins.
	WorkingDirectoryContext int `json:"-"`
	HomeDirectoryContext    int `json:"-"`
}

type FilePathInterpretation uint8

const (
	FilePathUnknown FilePathInterpretation = iota
	FilePathLiteral
	FilePathHomeRelative
)

type ResourceBinding struct {
	Role        ResourceRole `json:"role"`
	Resource    Resource     `json:"resource"`
	EvidenceIDs []string     `json:"evidence_ids,omitempty"`
	// FilePathInterpretation retains quote/expansion provenance until relation
	// derivation. The resulting evidenced relation is the serialized proof.
	FilePathInterpretation FilePathInterpretation `json:"-"`
}

type Feature struct {
	ID             string            `json:"id"`
	NodeID         string            `json:"node_id,omitempty"`
	ScopeID        string            `json:"scope_id,omitempty"`
	Architecture   string            `json:"architecture,omitempty"`
	Key            string            `json:"key"`
	Value          string            `json:"value"`
	Qualifiers     map[string]string `json:"qualifiers,omitempty"`
	EvidenceIDs    []string          `json:"evidence_ids,omitempty"`
	Support        Support           `json:"support"`
	Execution      ExecutionContext  `json:"execution"`
	SourceFunction string            `json:"source_function,omitempty"`
}

// MatchTraceClauseKind identifies one typed fact family that satisfied a leaf
// in a rule expression. The rule engine supplies the exact referenced fact IDs;
// renderers never reconstruct successful reasoning from display strings.
type MatchTraceClauseKind string

const (
	MatchTraceOperation         MatchTraceClauseKind = "operation"
	MatchTraceFeature           MatchTraceClauseKind = "feature"
	MatchTraceExecutionRoot     MatchTraceClauseKind = "execution-root"
	MatchTraceOperationRelation MatchTraceClauseKind = "operation-relation"
)

var matchTraceClauseKinds = [...]MatchTraceClauseKind{
	MatchTraceOperation,
	MatchTraceFeature,
	MatchTraceExecutionRoot,
	MatchTraceOperationRelation,
}

func MatchTraceClauseKinds() []MatchTraceClauseKind {
	return append([]MatchTraceClauseKind(nil), matchTraceClauseKinds[:]...)
}

func ValidMatchTraceClauseKind(kind MatchTraceClauseKind) bool {
	for _, allowed := range matchTraceClauseKinds {
		if kind == allowed {
			return true
		}
	}
	return false
}

var (
	matchTraceOperationPath = regexp.MustCompile(`^match(?:\.any\[[0-9]+\])*(?:\.each\.left|\.relate\.(?:left|right)|\.resource_flow\.steps\[[0-9]+\]\.operation)?$`)
	matchTraceEachRightPath = regexp.MustCompile(`^match(?:\.any\[[0-9]+\])*\.each\.right$`)
	matchTraceRelationPath  = regexp.MustCompile(`^match(?:\.any\[[0-9]+\])*(?:\.relate\.constraint|\.resource_flow\.steps\[[0-9]+\]\.(?:produces|precedes|consumes))$`)
)

// ValidMatchTraceClausePath accepts only expression paths that the closed rule
// evaluator can generate for the supplied typed fact family.
func ValidMatchTraceClausePath(kind MatchTraceClauseKind, path string) bool {
	switch kind {
	case MatchTraceOperation:
		return matchTraceOperationPath.MatchString(path)
	case MatchTraceFeature, MatchTraceExecutionRoot:
		return matchTraceEachRightPath.MatchString(path)
	case MatchTraceOperationRelation:
		return matchTraceRelationPath.MatchString(path)
	default:
		return false
	}
}

// MatchTraceClause records the exact typed facts that satisfied one rule leaf.
// Path is an engine-generated position in the expanded Match expression, such
// as match.any[0].each.right. Exactly one ID collection is populated according
// to Kind.
type MatchTraceClause struct {
	Path             string               `json:"path"`
	Kind             MatchTraceClauseKind `json:"kind"`
	OperationIDs     []string             `json:"operation_ids,omitempty"`
	FeatureIDs       []string             `json:"feature_ids,omitempty"`
	ExecutionRootIDs []string             `json:"execution_root_ids,omitempty"`
	RelationIDs      []string             `json:"operation_relation_ids,omitempty"`
}

type CapabilityMatch struct {
	ID                 string             `json:"id"`
	RuleID             string             `json:"rule_id"`
	Title              string             `json:"title"`
	Namespace          string             `json:"namespace"`
	Support            Support            `json:"support"`
	Execution          ExecutionContext   `json:"execution"`
	SubjectNodeID      string             `json:"subject_node_id"`
	AffectedResources  []Resource         `json:"affected_resources,omitempty"`
	OperationIDs       []string           `json:"operation_ids"`
	EvidenceIDs        []string           `json:"evidence_ids,omitempty"`
	Attack             []string           `json:"attack,omitempty"`
	MBC                []string           `json:"mbc,omitempty"`
	ArchitectureScopes []string           `json:"architecture_scopes,omitempty"`
	MatchTrace         []MatchTraceClause `json:"match_trace"`
}

type Scope struct {
	ID             string `json:"id"`
	NodeID         string `json:"node_id,omitempty"`
	ParentID       string `json:"parent_id,omitempty"`
	Kind           string `json:"kind"`
	Name           string `json:"name,omitempty"`
	SourceRole     string `json:"source_role,omitempty"`
	Function       string `json:"function,omitempty"`
	LineStart      int    `json:"line_start,omitempty"`
	LineEnd        int    `json:"line_end,omitempty"`
	Architecture   string `json:"architecture,omitempty"`
	CoverageDetail string `json:"coverage_detail,omitempty"`
}

type ArtifactProperty struct {
	NodeID      string   `json:"node_id,omitempty"`
	Kind        string   `json:"kind"`
	Value       string   `json:"value"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	Support     Support  `json:"support"`
}

type Coverage struct {
	NodeID       string `json:"node_id,omitempty"`
	AnalysisArea string `json:"analysis_area"`
	Status       string `json:"status"`
	Detail       string `json:"detail,omitempty"`
}
