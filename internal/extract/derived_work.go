package extract

import (
	"fmt"

	"github.com/0x4D31/maratus/internal/behavior"
)

type derivedWorkBudget struct {
	remaining int
}

func newDerivedWorkBudget(limit int) derivedWorkBudget {
	if limit < 0 {
		limit = 0
	}
	return derivedWorkBudget{remaining: limit}
}

func (b *derivedWorkBudget) take() bool {
	if b.remaining <= 0 {
		return false
	}
	b.remaining--
	return true
}

func markDerivedWorkLimit(graph *behavior.Graph, scope string, limit int, unit string) {
	addPartialCoverageOnce(
		graph,
		"",
		scope,
		fmt.Sprintf("derived-work limit %d reached while evaluating %s; remaining relationships were not evaluated", limit, unit),
	)
}

func markDerivedGraphLimit(graph *behavior.Graph, scope string) {
	addPartialCoverageOnce(
		graph,
		"",
		scope,
		"behavior graph limit reached; remaining derived relationships were not evaluated",
	)
	graph.MarkWorkOmitted()
}
