package report

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestGroupCapabilityMatchesBoundsDuplicateGroupReferenceWork(t *testing.T) {
	const (
		capabilityMatchCount = 1024
		referencesPerHit     = 64
	)
	capabilityMatches := make([]behavior.CapabilityMatch, capabilityMatchCount)
	for i := range capabilityMatches {
		ids := make([]string, referencesPerHit)
		for j := range ids {
			ids[j] = fmt.Sprintf("ev-%06d", i*len(ids)+j)
		}
		capabilityMatches[i] = behavior.CapabilityMatch{
			RuleID:        "rule",
			Title:         "title",
			SubjectNodeID: "node",
			EvidenceIDs:   ids,
		}
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	groups := groupCapabilityMatches(capabilityMatches)
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > 256<<20 {
		t.Fatalf("groupCapabilityMatches allocated %d bytes for %d references; duplicate grouping must remain linear", allocated, capabilityMatchCount*referencesPerHit)
	}
	if len(groups) != 1 {
		t.Fatalf("groupCapabilityMatches produced %d groups, want 1", len(groups))
	}
	if groups[0].count != capabilityMatchCount || len(groups[0].evidenceIDs) != capabilityMatchCount*referencesPerHit {
		t.Fatalf("groupCapabilityMatches lost references: matches=%d evidence=%d", groups[0].count, len(groups[0].evidenceIDs))
	}
}
