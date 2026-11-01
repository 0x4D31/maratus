package behavior

import "testing"

func TestMatchTraceClausePathVocabulary(t *testing.T) {
	valid := []struct {
		kind MatchTraceClauseKind
		path string
	}{
		{MatchTraceOperation, "match"},
		{MatchTraceOperation, "match.any[1].each.left"},
		{MatchTraceFeature, "match.any[0].each.right"},
		{MatchTraceExecutionRoot, "match.each.right"},
		{MatchTraceOperationRelation, "match.relate.constraint"},
		{MatchTraceOperationRelation, "match.any[1].resource_flow.steps[2].consumes"},
	}
	for _, test := range valid {
		if !ValidMatchTraceClausePath(test.kind, test.path) {
			t.Errorf("rejected valid %s path %q", test.kind, test.path)
		}
	}
	invalid := []struct {
		kind MatchTraceClauseKind
		path string
	}{
		{MatchTraceFeature, "match"},
		{MatchTraceOperation, "match.each.right"},
		{MatchTraceOperationRelation, "match.relate.left"},
		{MatchTraceExecutionRoot, "match.any[-1].each.right"},
		{MatchTraceClauseKind("guess"), "match"},
	}
	for _, test := range invalid {
		if ValidMatchTraceClausePath(test.kind, test.path) {
			t.Errorf("accepted invalid %s path %q", test.kind, test.path)
		}
	}
}
