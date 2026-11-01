package rules

import (
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxCapabilityMatchTraceClauses = 32
	maxCapabilityMatchTraceIDs     = 64
	maxCapabilityMatchTracePath    = 512
	maxCapabilityMatchTraceInputs  = maxCapabilityMatchTraceClauses * maxCapabilityMatchTraceIDs
)

type matchedOperation struct {
	operation behavior.ModeledOperation
	trace     []behavior.MatchTraceClause
}

func operationTrace(path string, operationIDs ...string) behavior.MatchTraceClause {
	return behavior.MatchTraceClause{Path: path, Kind: behavior.MatchTraceOperation, OperationIDs: operationIDs}
}

func featureTrace(path string, featureIDs ...string) behavior.MatchTraceClause {
	return behavior.MatchTraceClause{Path: path, Kind: behavior.MatchTraceFeature, FeatureIDs: featureIDs}
}

func executionRootTrace(path string, rootIDs ...string) behavior.MatchTraceClause {
	return behavior.MatchTraceClause{Path: path, Kind: behavior.MatchTraceExecutionRoot, ExecutionRootIDs: rootIDs}
}

func operationRelationTrace(path string, relationIDs ...string) behavior.MatchTraceClause {
	return behavior.MatchTraceClause{Path: path, Kind: behavior.MatchTraceOperationRelation, RelationIDs: relationIDs}
}

func mergeMatchTrace(left, right []behavior.MatchTraceClause) []behavior.MatchTraceClause {
	return append(append([]behavior.MatchTraceClause(nil), left...), right...)
}

func normalizeMatchTrace(clauses []behavior.MatchTraceClause) ([]behavior.MatchTraceClause, bool) {
	partial := false
	if len(clauses) > maxCapabilityMatchTraceInputs {
		clauses = clauses[:maxCapabilityMatchTraceInputs]
		partial = true
	}
	type traceKey struct {
		path string
		kind behavior.MatchTraceClauseKind
	}
	byKey := make(map[traceKey]int, len(clauses))
	out := make([]behavior.MatchTraceClause, 0, min(len(clauses), maxCapabilityMatchTraceClauses))
	for _, clause := range clauses {
		path, truncated := boundedCapabilityMatchString(clause.Path, maxCapabilityMatchTracePath)
		partial = partial || truncated
		clause.Path = path
		if clause.Path == "" || !behavior.ValidMatchTraceClauseKind(clause.Kind) {
			partial = true
			continue
		}
		clause, truncated = normalizeMatchTraceClause(clause)
		partial = partial || truncated
		key := traceKey{path: clause.Path, kind: clause.Kind}
		if index, exists := byKey[key]; exists {
			out[index] = appendMatchTraceIDs(out[index], clause)
			continue
		}
		byKey[key] = len(out)
		out = append(out, clause)
	}
	for index := range out {
		var truncated bool
		out[index], truncated = normalizeMatchTraceClause(out[index])
		partial = partial || truncated
	}
	sort.Slice(out, func(i, j int) bool {
		if compared := strings.Compare(out[i].Path, out[j].Path); compared != 0 {
			return compared < 0
		}
		return strings.Compare(string(out[i].Kind), string(out[j].Kind)) < 0
	})
	if len(out) > maxCapabilityMatchTraceClauses {
		out = out[:maxCapabilityMatchTraceClauses]
		partial = true
	}
	return out, partial
}

func appendMatchTraceIDs(left, right behavior.MatchTraceClause) behavior.MatchTraceClause {
	left.OperationIDs = append(left.OperationIDs, right.OperationIDs...)
	left.FeatureIDs = append(left.FeatureIDs, right.FeatureIDs...)
	left.ExecutionRootIDs = append(left.ExecutionRootIDs, right.ExecutionRootIDs...)
	left.RelationIDs = append(left.RelationIDs, right.RelationIDs...)
	return left
}

func normalizeMatchTraceClause(clause behavior.MatchTraceClause) (behavior.MatchTraceClause, bool) {
	partial := false
	normalize := func(values []string) []string {
		normalized, truncated := normalizeCapabilityMatchStrings(values, maxCapabilityMatchTraceIDs, maxCapabilityMatchIDBytes)
		partial = partial || truncated
		return normalized
	}
	switch clause.Kind {
	case behavior.MatchTraceOperation:
		partial = partial || len(clause.FeatureIDs) > 0 || len(clause.ExecutionRootIDs) > 0 || len(clause.RelationIDs) > 0
		clause.OperationIDs = normalize(clause.OperationIDs)
		clause.FeatureIDs, clause.ExecutionRootIDs, clause.RelationIDs = nil, nil, nil
	case behavior.MatchTraceFeature:
		partial = partial || len(clause.OperationIDs) > 0 || len(clause.ExecutionRootIDs) > 0 || len(clause.RelationIDs) > 0
		clause.FeatureIDs = normalize(clause.FeatureIDs)
		clause.OperationIDs, clause.ExecutionRootIDs, clause.RelationIDs = nil, nil, nil
	case behavior.MatchTraceExecutionRoot:
		partial = partial || len(clause.OperationIDs) > 0 || len(clause.FeatureIDs) > 0 || len(clause.RelationIDs) > 0
		clause.ExecutionRootIDs = normalize(clause.ExecutionRootIDs)
		clause.OperationIDs, clause.FeatureIDs, clause.RelationIDs = nil, nil, nil
	case behavior.MatchTraceOperationRelation:
		partial = partial || len(clause.OperationIDs) > 0 || len(clause.FeatureIDs) > 0 || len(clause.ExecutionRootIDs) > 0
		clause.RelationIDs = normalize(clause.RelationIDs)
		clause.OperationIDs, clause.FeatureIDs, clause.ExecutionRootIDs = nil, nil, nil
	}
	return clause, partial
}

func compareMatchTrace(left, right []behavior.MatchTraceClause) int {
	for index := 0; index < min(len(left), len(right)); index++ {
		if compared := strings.Compare(left[index].Path, right[index].Path); compared != 0 {
			return compared
		}
		if compared := strings.Compare(string(left[index].Kind), string(right[index].Kind)); compared != 0 {
			return compared
		}
		for _, values := range [][2][]string{
			{left[index].OperationIDs, right[index].OperationIDs},
			{left[index].FeatureIDs, right[index].FeatureIDs},
			{left[index].ExecutionRootIDs, right[index].ExecutionRootIDs},
			{left[index].RelationIDs, right[index].RelationIDs},
		} {
			if compared := compareCapabilityMatchStrings(values[0], values[1]); compared != 0 {
				return compared
			}
		}
	}
	return len(left) - len(right)
}
