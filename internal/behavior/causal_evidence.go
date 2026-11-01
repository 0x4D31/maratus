package behavior

// MaxCausalEvidenceIDs bounds both the causal evidence supplied to
// CorroborateRange and the resulting top-level evidence set on every affected
// fact.
const MaxCausalEvidenceIDs = 64

// GraphRange captures the beginning of a suffix of evidence-bearing facts.
// Callers take a snapshot before invoking a derived analyzer, then annotate the
// facts emitted after that snapshot with the evidence that justified the
// derived analysis.
type GraphRange struct {
	FeatureStart   int
	OperationStart int
	RelationStart  int
	NetworkStart   int
}

// CaptureGraphRange returns a range start at the current end of every fact
// collection supported by CorroborateRange.
func (g *Graph) CaptureGraphRange() GraphRange {
	return GraphRange{
		FeatureStart:   len(g.Features),
		OperationStart: len(g.Operations),
		RelationStart:  len(g.Relations),
		NetworkStart:   len(g.Network),
	}
}

// CorroborateRange adds causal evidence to every Feature,
// ModeledOperation, OperationRelation, and NetworkImplementationObservation
// emitted since start. Evidence lists are normalized deterministically and all
// additional retained evidence bytes are reserved atomically before any list
// changes.
//
// Direct facts become CORROBORATED because their interpretation now depends on
// the supplied causal evidence. If the evidence input or a resulting evidence
// list exceeds MaxCausalEvidenceIDs, or the atomic string reservation fails,
// evidence remains unchanged and every retained affected fact becomes
// HEURISTIC. If even that smaller safety transition cannot fit, the captured
// suffix is discarded and charged to drop accounting. This prevents a
// partially evidenced derived range from producing an execution-backed typed
// capability without exceeding the retained-string budget. An invalid range
// start returns false without changing the graph.
func (g *Graph) CorroborateRange(start GraphRange, evidenceIDs []string) bool {
	if !g.validFactRangeStart(start) {
		return false
	}
	causal, ok := normalizeCausalEvidenceIDs(evidenceIDs)
	if !ok {
		g.weakenOrDropFactRange(start, false)
		return false
	}

	featureEvidence := make([][]string, 0, len(g.Features)-start.FeatureStart)
	operationEvidence := make([][]string, 0, len(g.Operations)-start.OperationStart)
	relationEvidence := make([][]string, 0, len(g.Relations)-start.RelationStart)
	networkEvidence := make([][]string, 0, len(g.Network)-start.NetworkStart)
	var stringDelta int64

	appendPlan := func(destination *[][]string, current []string, support Support) bool {
		merged, valid := mergeCausalEvidenceIDs(current, causal)
		if !valid {
			return false
		}
		*destination = append(*destination, merged)
		stringDelta = saturatingAddSignedInt64(
			stringDelta,
			causalFactStringDelta(current, support, merged, corroboratedSupport(support)),
		)
		return true
	}
	for index := start.FeatureStart; index < len(g.Features); index++ {
		if !appendPlan(&featureEvidence, g.Features[index].EvidenceIDs, g.Features[index].Support) {
			g.weakenOrDropFactRange(start, false)
			return false
		}
	}
	for index := start.OperationStart; index < len(g.Operations); index++ {
		if !appendPlan(&operationEvidence, g.Operations[index].EvidenceIDs, g.Operations[index].Support) {
			g.weakenOrDropFactRange(start, false)
			return false
		}
	}
	for index := start.RelationStart; index < len(g.Relations); index++ {
		if !appendPlan(&relationEvidence, g.Relations[index].EvidenceIDs, g.Relations[index].Support) {
			g.weakenOrDropFactRange(start, false)
			return false
		}
	}
	for index := start.NetworkStart; index < len(g.Network); index++ {
		if !appendPlan(&networkEvidence, g.Network[index].EvidenceIDs, g.Network[index].Support) {
			g.weakenOrDropFactRange(start, false)
			return false
		}
	}

	if stringDelta > 0 && !g.reserveStrings(stringDelta) {
		g.weakenOrDropFactRange(start, true)
		return false
	}

	for offset, evidence := range featureEvidence {
		fact := &g.Features[start.FeatureStart+offset]
		fact.EvidenceIDs = evidence
		weakenDirectSupport(&fact.Support)
	}
	for offset, evidence := range operationEvidence {
		fact := &g.Operations[start.OperationStart+offset]
		fact.EvidenceIDs = evidence
		weakenDirectSupport(&fact.Support)
	}
	for offset, evidence := range relationEvidence {
		fact := &g.Relations[start.RelationStart+offset]
		fact.EvidenceIDs = evidence
		weakenDirectSupport(&fact.Support)
	}
	for offset, evidence := range networkEvidence {
		fact := &g.Network[start.NetworkStart+offset]
		fact.EvidenceIDs = evidence
		weakenDirectSupport(&fact.Support)
	}
	if stringDelta < 0 {
		g.releaseStrings(-stringDelta)
	}
	return true
}

func (g *Graph) validFactRangeStart(start GraphRange) bool {
	return start.FeatureStart >= 0 && start.FeatureStart <= len(g.Features) &&
		start.OperationStart >= 0 && start.OperationStart <= len(g.Operations) &&
		start.RelationStart >= 0 && start.RelationStart <= len(g.Relations) &&
		start.NetworkStart >= 0 && start.NetworkStart <= len(g.Network)
}

func normalizeCausalEvidenceIDs(evidenceIDs []string) ([]string, bool) {
	if len(evidenceIDs) == 0 || len(evidenceIDs) > MaxCausalEvidenceIDs {
		return nil, false
	}
	for _, evidenceID := range evidenceIDs {
		if evidenceID == "" {
			return nil, false
		}
	}
	normalized := sortedUniqueStrings(append([]string(nil), evidenceIDs...))
	if len(normalized) == 0 || len(normalized) > MaxCausalEvidenceIDs {
		return nil, false
	}
	return normalized, true
}

func mergeCausalEvidenceIDs(current, causal []string) ([]string, bool) {
	if len(current) > MaxCausalEvidenceIDs {
		return nil, false
	}
	normalizedCurrent := sortedUniqueStrings(append([]string(nil), current...))
	merged := sortedUniqueStrings(append(append([]string(nil), normalizedCurrent...), causal...))
	if len(merged) > MaxCausalEvidenceIDs {
		return nil, false
	}
	return merged, true
}

func causalFactStringDelta(currentEvidence []string, currentSupport Support, nextEvidence []string, nextSupport Support) int64 {
	currentBytes := saturatingAddInt64(retainedStringBytes(currentEvidence), retainedStringByteCost(string(currentSupport)))
	nextBytes := saturatingAddInt64(retainedStringBytes(nextEvidence), retainedStringByteCost(string(nextSupport)))
	return nextBytes - currentBytes
}

func corroboratedSupport(support Support) Support {
	if support == SupportDirect {
		return SupportCorroborated
	}
	return support
}

func (g *Graph) weakenOrDropFactRange(start GraphRange, priorReservationFailed bool) {
	var stringDelta int64
	for index := start.FeatureStart; index < len(g.Features); index++ {
		stringDelta = saturatingAddSignedInt64(stringDelta, causalFactStringDelta(
			g.Features[index].EvidenceIDs,
			g.Features[index].Support,
			g.Features[index].EvidenceIDs,
			SupportHeuristic,
		))
	}
	for index := start.OperationStart; index < len(g.Operations); index++ {
		stringDelta = saturatingAddSignedInt64(stringDelta, causalFactStringDelta(
			g.Operations[index].EvidenceIDs,
			g.Operations[index].Support,
			g.Operations[index].EvidenceIDs,
			SupportHeuristic,
		))
	}
	for index := start.RelationStart; index < len(g.Relations); index++ {
		stringDelta = saturatingAddSignedInt64(stringDelta, causalFactStringDelta(
			g.Relations[index].EvidenceIDs,
			g.Relations[index].Support,
			g.Relations[index].EvidenceIDs,
			SupportHeuristic,
		))
	}
	for index := start.NetworkStart; index < len(g.Network); index++ {
		stringDelta = saturatingAddSignedInt64(stringDelta, causalFactStringDelta(
			g.Network[index].EvidenceIDs,
			g.Network[index].Support,
			g.Network[index].EvidenceIDs,
			SupportHeuristic,
		))
	}

	if stringDelta > 0 {
		reserved := false
		if priorReservationFailed {
			reserved = g.reserveSafetyStrings(stringDelta)
		} else {
			reserved = g.reserveStrings(stringDelta)
		}
		if !reserved {
			g.dropFactRange(start)
			return
		}
	}
	for index := start.FeatureStart; index < len(g.Features); index++ {
		g.Features[index].Support = SupportHeuristic
	}
	for index := start.OperationStart; index < len(g.Operations); index++ {
		g.Operations[index].Support = SupportHeuristic
	}
	for index := start.RelationStart; index < len(g.Relations); index++ {
		g.Relations[index].Support = SupportHeuristic
	}
	for index := start.NetworkStart; index < len(g.Network); index++ {
		g.Network[index].Support = SupportHeuristic
	}
	if stringDelta < 0 {
		g.releaseStrings(-stringDelta)
	}
}

// reserveSafetyStrings admits a smaller safety-only transition after a larger
// atomic corroboration reservation has failed. The ordinary reserveStrings
// path deliberately rejects all later additions once StringBytesDropped is
// non-zero, but changing retained derived facts to HEURISTIC is necessary to
// prevent those facts from supporting a typed capability.
func (g *Graph) reserveSafetyStrings(size int64) bool {
	if size <= 0 {
		return true
	}
	if g.StringByteLimit > 0 && (g.StringBytes > g.StringByteLimit || size > g.StringByteLimit-g.StringBytes) {
		return false
	}
	g.StringBytes = saturatingAddInt64(g.StringBytes, size)
	return true
}

func (g *Graph) releaseStrings(size int64) {
	if size <= 0 {
		return
	}
	if size >= g.StringBytes {
		g.StringBytes = 0
		return
	}
	g.StringBytes -= size
}

func (g *Graph) dropFactRange(start GraphRange) {
	var released int64
	for index := start.FeatureStart; index < len(g.Features); index++ {
		fact := g.Features[index]
		fact.ID = ""
		released = saturatingAddInt64(released, saturatingAddInt64(retainedStringBytes(fact), generatedIDByteReserve))
		g.dropItem()
	}
	for index := start.OperationStart; index < len(g.Operations); index++ {
		fact := g.Operations[index]
		fact.ID = ""
		released = saturatingAddInt64(released, saturatingAddInt64(retainedStringBytes(fact), generatedIDByteReserve))
		g.dropItem()
	}
	for index := start.RelationStart; index < len(g.Relations); index++ {
		fact := g.Relations[index]
		fact.ID = ""
		released = saturatingAddInt64(released, saturatingAddInt64(retainedStringBytes(fact), generatedIDByteReserve))
		g.dropItem()
	}
	for index := start.NetworkStart; index < len(g.Network); index++ {
		fact := g.Network[index]
		fact.ID = ""
		released = saturatingAddInt64(released, saturatingAddInt64(retainedStringBytes(fact), generatedIDByteReserve))
		g.dropItem()
	}
	g.Features = g.Features[:start.FeatureStart]
	g.Operations = g.Operations[:start.OperationStart]
	g.Relations = g.Relations[:start.RelationStart]
	g.Network = g.Network[:start.NetworkStart]
	g.releaseStrings(released)
}

const minInt64 = -maxInt64 - 1

func saturatingAddSignedInt64(left, right int64) int64 {
	if right > 0 && left > maxInt64-right {
		return maxInt64
	}
	if right < 0 && left < minInt64-right {
		return minInt64
	}
	return left + right
}

func weakenDirectSupport(support *Support) {
	if *support == SupportDirect {
		*support = SupportCorroborated
	}
}
