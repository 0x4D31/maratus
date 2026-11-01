package behavior

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Connectivity describes whether a record is statically connected to one or
// more declared execution roots. UNCONNECTED means no connection exists in
// the retained static model; it does not claim that execution is impossible.
type Connectivity string

const (
	ConnectivityConnected   Connectivity = "CONNECTED"
	ConnectivityUnconnected Connectivity = "UNCONNECTED"
	ConnectivityUnknown     Connectivity = "UNKNOWN"
)

var connectivityValues = [...]Connectivity{
	ConnectivityConnected,
	ConnectivityUnconnected,
	ConnectivityUnknown,
}

// ConnectivityValues returns the closed execution-connectivity vocabulary.
func ConnectivityValues() []Connectivity {
	return append([]Connectivity(nil), connectivityValues[:]...)
}

const maxExecutionContextIDs = 64

// ExecutionContext retains bounded ownership sets instead of collapsing a
// record to a single, potentially ambiguous root or target.
type ExecutionContext struct {
	Connectivity     Connectivity `json:"connectivity"`
	ExecutionRootIDs []string     `json:"execution_root_ids,omitempty"`
	InvokedTargetIDs []string     `json:"invoked_target_ids,omitempty"`
}

// ExecutionKey is the comparable, canonical identity of an execution context.
// It is deliberately opaque: callers must construct it through NewExecutionKey
// so invalid ownership sets cannot participate in correlation.
type ExecutionKey struct {
	identity string
}

// ContextKey is the normalized static correlation boundary shared by
// extractors and rules. ScopeID may be empty for derived work that groups at
// node/architecture granularity before applying an explicit scope relation.
type ContextKey struct {
	Execution     ExecutionKey
	SubjectNodeID string
	ScopeID       string
	Architecture  string
}

// NewExecutionKey normalizes ownership sets before constructing a collision-
// resistant identity. Equal semantic contexts therefore produce equal map
// keys regardless of input order or duplicates.
func NewExecutionKey(context ExecutionContext) (ExecutionKey, error) {
	normalized, err := NormalizeExecutionContext(context)
	if err != nil {
		return ExecutionKey{}, err
	}
	var identity strings.Builder
	appendIdentityField(&identity, "connectivity", string(normalized.Connectivity))
	for _, rootID := range normalized.ExecutionRootIDs {
		appendIdentityField(&identity, "root", rootID)
	}
	for _, targetID := range normalized.InvokedTargetIDs {
		appendIdentityField(&identity, "target", targetID)
	}
	return ExecutionKey{identity: identity.String()}, nil
}

// NewContextKey constructs a comparable context over normalized execution
// ownership. SubjectNodeID is required; callers that require an exact scope
// must additionally reject an empty ScopeID.
func NewContextKey(context ExecutionContext, subjectNodeID, scopeID, architecture string) (ContextKey, error) {
	if subjectNodeID == "" {
		return ContextKey{}, fmt.Errorf("context key requires a subject node ID")
	}
	execution, err := NewExecutionKey(context)
	if err != nil {
		return ContextKey{}, err
	}
	return ContextKey{
		Execution:     execution,
		SubjectNodeID: subjectNodeID,
		ScopeID:       scopeID,
		Architecture:  architecture,
	}, nil
}

// SameExecution reports whether two static contexts have exactly the same
// normalized connectivity and root/target ownership.
func (key ContextKey) SameExecution(other ContextKey) bool {
	return key.Execution == other.Execution && key.Execution.identity != ""
}

// CompareContextKeys provides deterministic ordering without exposing the
// opaque execution identity as an authoring surface.
func CompareContextKeys(left, right ContextKey) int {
	if compared := strings.Compare(left.Execution.identity, right.Execution.identity); compared != 0 {
		return compared
	}
	if compared := strings.Compare(left.SubjectNodeID, right.SubjectNodeID); compared != 0 {
		return compared
	}
	if compared := strings.Compare(left.ScopeID, right.ScopeID); compared != 0 {
		return compared
	}
	return strings.Compare(left.Architecture, right.Architecture)
}

func appendIdentityField(output *strings.Builder, name, value string) {
	output.WriteString(name)
	output.WriteByte(':')
	output.WriteString(strconv.Itoa(len(value)))
	output.WriteByte(':')
	output.WriteString(value)
	output.WriteByte(';')
}

type EntityKind string

const (
	EntityKindArtifactNode  EntityKind = "artifact-node"
	EntityKindExecutionRoot EntityKind = "execution-root"
	EntityKindInvokedTarget EntityKind = "invoked-target"
)

// EntityRef is the closed endpoint vocabulary shared by execution ownership
// records. Additional endpoint kinds can be introduced with typed relations.
type EntityRef struct {
	Kind EntityKind `json:"kind"`
	ID   string     `json:"id"`
}

type ExecutionRoot struct {
	ID                string   `json:"id"`
	Kind              string   `json:"kind"`
	DeclarationNodeID string   `json:"declaration_node_id"`
	StartNodeID       string   `json:"start_node_id,omitempty"`
	StartScopeID      string   `json:"start_scope_id,omitempty"`
	Name              string   `json:"name,omitempty"`
	Interpreter       string   `json:"interpreter,omitempty"`
	Arguments         []string `json:"arguments,omitempty"`
	EvidenceIDs       []string `json:"evidence_ids"`
}

type InvokedTarget struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	NodeID  string    `json:"node_id"`
	ScopeID string    `json:"scope_id,omitempty"`
	Source  EntityRef `json:"source"`
	// Execution carries roots inherited from Source. It intentionally does not
	// include this target's own generated ID; operations modeled in the target
	// carry that ID in their ExecutionContext.InvokedTargetIDs.
	Execution   ExecutionContext `json:"execution"`
	Interpreter string           `json:"interpreter,omitempty"`
	Arguments   []string         `json:"arguments,omitempty"`
	Ordinal     *int             `json:"ordinal,omitempty"`
	EvidenceIDs []string         `json:"evidence_ids"`
}

type SelectionReason string

const (
	SelectionReasonExecutionRoot       SelectionReason = "execution-root"
	SelectionReasonInvokedTarget       SelectionReason = "invoked-target"
	SelectionReasonDeclaredEntry       SelectionReason = "declared-entry-candidate"
	SelectionReasonRunnableCandidate   SelectionReason = "runnable-candidate"
	SelectionReasonIncludeUnreferenced SelectionReason = "include-unreferenced"
	SelectionReasonDefaultRelevant     SelectionReason = "default-relevant"
	SelectionReasonRawFeatures         SelectionReason = "raw-features"
)

// AnalysisSelection records why a node was analyzed. It is deliberately
// separate from execution connectivity: selecting a runnable candidate does
// not make it reachable.
type AnalysisSelection struct {
	NodeID  string            `json:"node_id"`
	Reasons []SelectionReason `json:"reasons"`
}

// NormalizeExecutionContext returns a bounded, deterministic context or an
// error when the connectivity and ownership sets contradict one another.
func NormalizeExecutionContext(context ExecutionContext) (ExecutionContext, error) {
	if context.Connectivity == "" {
		context.Connectivity = ConnectivityUnknown
	}
	context.ExecutionRootIDs = boundedSortedUniqueStrings(context.ExecutionRootIDs, maxExecutionContextIDs)
	context.InvokedTargetIDs = boundedSortedUniqueStrings(context.InvokedTargetIDs, maxExecutionContextIDs)
	switch context.Connectivity {
	case ConnectivityConnected:
		if len(context.ExecutionRootIDs) == 0 {
			return ExecutionContext{}, fmt.Errorf("CONNECTED execution context requires at least one execution root ID")
		}
		return context, nil
	case ConnectivityUnconnected, ConnectivityUnknown:
		if len(context.ExecutionRootIDs) != 0 || len(context.InvokedTargetIDs) != 0 {
			return ExecutionContext{}, fmt.Errorf("%s execution context cannot carry root or target IDs", context.Connectivity)
		}
		return context, nil
	default:
		return ExecutionContext{}, fmt.Errorf("invalid execution connectivity %q", context.Connectivity)
	}
}

func boundedSortedUniqueStrings(values []string, limit int) []string {
	values = sortedUniqueStrings(append([]string(nil), values...))
	if len(values) > limit {
		values = values[:limit]
	}
	return values
}

func validEntityRef(ref EntityRef) bool {
	if ref.ID == "" {
		return false
	}
	switch ref.Kind {
	case EntityKindArtifactNode, EntityKindExecutionRoot, EntityKindInvokedTarget:
		return true
	default:
		return false
	}
}

func validSelectionReason(reason SelectionReason) bool {
	switch reason {
	case SelectionReasonExecutionRoot,
		SelectionReasonInvokedTarget,
		SelectionReasonDeclaredEntry,
		SelectionReasonRunnableCandidate,
		SelectionReasonIncludeUnreferenced,
		SelectionReasonDefaultRelevant,
		SelectionReasonRawFeatures:
		return true
	default:
		return false
	}
}

func normalizeSelectionReasons(reasons []SelectionReason) []SelectionReason {
	if len(reasons) == 0 {
		return nil
	}
	reasons = append([]SelectionReason(nil), reasons...)
	sort.Slice(reasons, func(i, j int) bool { return reasons[i] < reasons[j] })
	out := reasons[:0]
	for _, reason := range reasons {
		if reason == "" || len(out) > 0 && out[len(out)-1] == reason {
			continue
		}
		out = append(out, reason)
	}
	return out
}

func compareSelectionReasons(left, right []SelectionReason) int {
	for i := 0; i < min(len(left), len(right)); i++ {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	return len(left) - len(right)
}
