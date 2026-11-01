package rules

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	// DefaultCapabilityMatchLimit bounds the machine-readable capability-match set retained for
	// one report. Rules may examine more IR, but hostile inputs cannot grow the
	// output without bound.
	DefaultCapabilityMatchLimit       = 4096
	DefaultCapabilityMatchStringBytes = 8 << 20
	maxCapabilityMatchesPerRule       = 1024
	ruleCapabilityMatchCandidateLimit = maxCapabilityMatchesPerRule + 1
	maxCapabilityMatchOperations      = 64
	maxCapabilityMatchEvidence        = 64
	maxCapabilityMatchResources       = 16
	maxCapabilityMatchMappings        = 16
	maxCapabilityMatchExecutionIDs    = 64
	maxCapabilityMatchIDBytes         = 256
	maxCapabilityMatchLabelBytes      = 512
	maxCapabilityMatchValueBytes      = 4096
	// maxRuleMatchWork bounds intermediate indexing, lookup, and join work for one
	// bounded evaluation path. It is deliberately independent of output limits:
	// adversarial inputs can otherwise create a huge call-edge cross-product
	// while yielding few or no capability matches.
	maxRuleMatchWork = 1 << 20
)

// Evaluate runs the generated, compiler-validated typed rule catalog. Callers
// cannot supply arbitrary evaluators or construct public CapabilityMatches.
func Evaluate(graph *behavior.Graph) []behavior.CapabilityMatch {
	return evaluateCompiledRules(graph, compiledBuiltins())
}

func evaluateCompiledRules(graph *behavior.Graph, rules []compiledSpec) []behavior.CapabilityMatch {
	resetRuleEvaluationCoverage(graph)
	view := newAnalysisView(graph, newRuleWorkBudget(graph))
	candidateBatches := make([][]behavior.CapabilityMatch, 0, len(rules))
	for _, rule := range rules {
		candidateBatches = append(candidateBatches, rule.evaluateIndexed(view, newRuleWorkBudget(graph)))
	}
	return mergeCapabilityMatchCandidateBatches(graph, candidateBatches)
}

// mergeCapabilityMatchCandidateBatches owns normalization, projection limits,
// deterministic ordering, and IDs after the closed rule evaluator has produced
// one candidate batch per compiled rule. Keeping this stage independent lets
// focused tests exercise hostile candidate collections without restoring an
// arbitrary production Rule interface.
func mergeCapabilityMatchCandidateBatches(graph *behavior.Graph, candidateBatches [][]behavior.CapabilityMatch) []behavior.CapabilityMatch {
	type batch struct {
		capabilityMatches []behavior.CapabilityMatch
		next              int
	}
	var batches []batch
	partial := false
	traceFacts := newCapabilityTraceFacts(graph)
	for _, candidates := range candidateBatches {
		if len(candidates) > ruleCapabilityMatchCandidateLimit {
			// Copy the retained prefix so a hostile rule cannot keep an
			// arbitrarily large backing array alive through the merge.
			candidates = append([]behavior.CapabilityMatch(nil), candidates[:ruleCapabilityMatchCandidateLimit]...)
			partial = true
		}
		for i := range candidates {
			var truncated bool
			candidates[i], truncated = normalizeCapabilityMatch(candidates[i])
			if len(candidates[i].MatchTrace) > 0 {
				evidenceIDs, evidenceTruncated := traceFacts.evidence(candidates[i].MatchTrace)
				if !slices.Equal(candidates[i].EvidenceIDs, evidenceIDs) {
					evidenceTruncated = true
				}
				candidates[i].EvidenceIDs = evidenceIDs
				truncated = truncated || evidenceTruncated
			}
			partial = partial || truncated
		}
		candidates = deduplicateCapabilityMatches(candidates)
		if len(candidates) > maxCapabilityMatchesPerRule {
			candidates = candidates[:maxCapabilityMatchesPerRule]
			partial = true
		}
		if len(candidates) > 0 {
			batches = append(batches, batch{capabilityMatches: candidates})
		}
	}

	// Each rule batch is already sorted. Merge only the globally retained
	// prefix instead of concatenating and sorting every per-rule candidate.
	capabilityMatches := make([]behavior.CapabilityMatch, 0, DefaultCapabilityMatchLimit)
	var retainedBytes int64
	for len(capabilityMatches) < DefaultCapabilityMatchLimit {
		best := -1
		for i := range batches {
			if batches[i].next >= len(batches[i].capabilityMatches) {
				continue
			}
			if best < 0 || compareCapabilityMatches(batches[i].capabilityMatches[batches[i].next], batches[best].capabilityMatches[batches[best].next]) < 0 {
				best = i
			}
		}
		if best < 0 {
			break
		}
		item := batches[best].capabilityMatches[batches[best].next]
		if item.ID == "" {
			item.ID = fmt.Sprintf("match-%04d", len(capabilityMatches)+1)
		}
		size := capabilityMatchStringBytes(item)
		if len(capabilityMatches) > 0 && size > int64(DefaultCapabilityMatchStringBytes)-retainedBytes {
			partial = true
			break
		}
		capabilityMatches = append(capabilityMatches, item)
		retainedBytes += size
		batches[best].next++
	}
	for _, batch := range batches {
		if batch.next < len(batch.capabilityMatches) {
			partial = true
			break
		}
	}
	if partial {
		markRuleEvaluationPartial(graph)
	}
	return capabilityMatches
}

// resetRuleEvaluationCoverage makes the rule engine the sole owner of its
// coverage projection. Re-evaluation must derive the marker again rather than
// trusting a stale or caller-supplied claim.
func resetRuleEvaluationCoverage(graph *behavior.Graph) {
	if graph == nil || len(graph.Coverage) == 0 {
		return
	}
	out := graph.Coverage[:0]
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea != "rule-evaluation" {
			out = append(out, coverage)
		}
	}
	graph.Coverage = out
}

func markRuleEvaluationPartial(graph *behavior.Graph) {
	detail := fmt.Sprintf("rule capability-match output limit reached (maximum %d total, %d per rule, %d retained string bytes, %d bytes per value, and bounded collections); fields or additional matches omitted", DefaultCapabilityMatchLimit, maxCapabilityMatchesPerRule, DefaultCapabilityMatchStringBytes, maxCapabilityMatchValueBytes)
	markRuleEvaluationPartialWithDetail(graph, detail)
}

func markRuleWorkPartial(graph *behavior.Graph) {
	detail := fmt.Sprintf("rule matching work limit reached (maximum %d indexed, looked-up, or joined records per bounded evaluation path); additional match candidates omitted", maxRuleMatchWork)
	markRuleEvaluationPartialWithDetail(graph, detail)
}

func markRuleEvaluationPartialWithDetail(graph *behavior.Graph, detail string) {
	for i := range graph.Coverage {
		if graph.Coverage[i].AnalysisArea == "rule-evaluation" {
			graph.Coverage[i].Status = "partial"
			graph.Coverage[i].Detail = detail
			return
		}
	}
	// Extraction budgets may already be finalized, so this mandatory marker is
	// retained as one bounded post-analysis item.
	graph.Coverage = append(graph.Coverage, behavior.Coverage{AnalysisArea: "rule-evaluation", Status: "partial", Detail: detail})
}

func capabilityMatchStringBytes(capabilityMatch behavior.CapabilityMatch) int64 {
	var total int64
	add := func(value string) {
		size := capabilityMatchStringJSONBytes(value)
		if size > int64(^uint64(0)>>1)-total {
			total = int64(^uint64(0) >> 1)
			return
		}
		total += size
	}
	add(capabilityMatch.ID)
	add(capabilityMatch.RuleID)
	add(capabilityMatch.Title)
	add(capabilityMatch.Namespace)
	add(string(capabilityMatch.Support))
	add(string(capabilityMatch.Execution.Connectivity))
	add(capabilityMatch.SubjectNodeID)
	for _, resource := range capabilityMatch.AffectedResources {
		add(string(resource.Kind))
		add(resource.Value)
		for _, classification := range resource.Classifications {
			add(string(classification))
		}
	}
	for _, values := range [][]string{capabilityMatch.Execution.ExecutionRootIDs, capabilityMatch.Execution.InvokedTargetIDs, capabilityMatch.OperationIDs, capabilityMatch.EvidenceIDs, capabilityMatch.Attack, capabilityMatch.MBC, capabilityMatch.ArchitectureScopes} {
		for _, value := range values {
			add(value)
		}
	}
	for _, clause := range capabilityMatch.MatchTrace {
		add(clause.Path)
		add(string(clause.Kind))
		for _, values := range [][]string{clause.OperationIDs, clause.FeatureIDs, clause.ExecutionRootIDs, clause.RelationIDs} {
			for _, value := range values {
				add(value)
			}
		}
	}
	return total
}

// capabilityMatchStringJSONBytes charges the larger of the in-memory string and its
// JSON representation. Report JSON deliberately disables HTML escaping, but
// control characters, quotes, backslashes, U+2028/U+2029, and invalid UTF-8
// still expand. Accounting for that expansion keeps the capability-match budget useful
// as a bound on the serialized report, not only on its Go strings.
func capabilityMatchStringJSONBytes(value string) int64 {
	rawBytes := int64(len(value))
	var jsonBytes int64
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			jsonBytes = saturatingCapabilityMatchBytes(jsonBytes, 6) // \ufffd
			value = value[1:]
			continue
		}
		value = value[size:]
		switch r {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			jsonBytes = saturatingCapabilityMatchBytes(jsonBytes, 2)
		case '\u2028', '\u2029':
			jsonBytes = saturatingCapabilityMatchBytes(jsonBytes, 6)
		default:
			if r < 0x20 {
				jsonBytes = saturatingCapabilityMatchBytes(jsonBytes, 6)
			} else {
				jsonBytes = saturatingCapabilityMatchBytes(jsonBytes, int64(size))
			}
		}
	}
	if jsonBytes > rawBytes {
		return jsonBytes
	}
	return rawBytes
}

func saturatingCapabilityMatchBytes(left, right int64) int64 {
	const maxInt64 = int64(^uint64(0) >> 1)
	if right > maxInt64-left {
		return maxInt64
	}
	return left + right
}

func SortCapabilityMatches(capabilityMatches []behavior.CapabilityMatch) {
	for i := range capabilityMatches {
		capabilityMatches[i], _ = normalizeCapabilityMatch(capabilityMatches[i])
	}
	sortCapabilityMatchesNormalized(capabilityMatches)
}

// EqualCapabilityMatchSets compares two already validated capability
// collections without normalizing, truncating, deduplicating, or mutating
// either input. Top-level order is presentation-only; every retained match
// field, including its engine-assigned ID and match trace, remains exact.
func EqualCapabilityMatchSets(left, right []behavior.CapabilityMatch) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]behavior.CapabilityMatch(nil), left...)
	right = append([]behavior.CapabilityMatch(nil), right...)
	sortCapabilityMatchesNormalized(left)
	sortCapabilityMatchesNormalized(right)
	for index := range left {
		if !capabilityMatchesEqual(left[index], right[index]) {
			return false
		}
	}
	return true
}

func sortCapabilityMatchesNormalized(capabilityMatches []behavior.CapabilityMatch) {
	sort.SliceStable(capabilityMatches, func(i, j int) bool {
		return compareCapabilityMatches(capabilityMatches[i], capabilityMatches[j]) < 0
	})
}

func normalizeCapabilityMatch(capabilityMatch behavior.CapabilityMatch) (behavior.CapabilityMatch, bool) {
	partial := false
	normalize := func(value string, limit int) string {
		bounded, truncated := boundedCapabilityMatchString(value, limit)
		partial = partial || truncated
		return bounded
	}
	capabilityMatch.ID = normalize(capabilityMatch.ID, maxCapabilityMatchIDBytes)
	capabilityMatch.RuleID = normalize(capabilityMatch.RuleID, maxCapabilityMatchIDBytes)
	capabilityMatch.Title = normalize(capabilityMatch.Title, maxCapabilityMatchLabelBytes)
	capabilityMatch.Namespace = normalize(capabilityMatch.Namespace, maxCapabilityMatchLabelBytes)
	capabilityMatch.Support = behavior.Support(normalize(string(capabilityMatch.Support), maxCapabilityMatchLabelBytes))
	capabilityMatch.SubjectNodeID = normalize(capabilityMatch.SubjectNodeID, maxCapabilityMatchIDBytes)
	capabilityMatch.Execution.Connectivity = behavior.Connectivity(normalize(string(capabilityMatch.Execution.Connectivity), maxCapabilityMatchLabelBytes))

	var truncated bool
	capabilityMatch.Execution.ExecutionRootIDs, truncated = normalizeCapabilityMatchStrings(capabilityMatch.Execution.ExecutionRootIDs, maxCapabilityMatchExecutionIDs, maxCapabilityMatchIDBytes)
	partial = partial || truncated
	capabilityMatch.Execution.InvokedTargetIDs, truncated = normalizeCapabilityMatchStrings(capabilityMatch.Execution.InvokedTargetIDs, maxCapabilityMatchExecutionIDs, maxCapabilityMatchIDBytes)
	partial = partial || truncated
	execution, executionErr := behavior.NormalizeExecutionContext(capabilityMatch.Execution)
	if executionErr != nil {
		partial = true
		execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
	}
	capabilityMatch.Execution = execution
	capabilityMatch.AffectedResources, truncated = normalizeCapabilityMatchResources(capabilityMatch.AffectedResources)
	partial = partial || truncated
	capabilityMatch.OperationIDs, truncated = normalizeCapabilityMatchStrings(capabilityMatch.OperationIDs, maxCapabilityMatchOperations, maxCapabilityMatchIDBytes)
	partial = partial || truncated
	capabilityMatch.EvidenceIDs, truncated = normalizeCapabilityMatchStrings(capabilityMatch.EvidenceIDs, maxCapabilityMatchEvidence, maxCapabilityMatchIDBytes)
	partial = partial || truncated
	capabilityMatch.Attack, truncated = normalizeCapabilityMatchStrings(capabilityMatch.Attack, maxCapabilityMatchMappings, maxCapabilityMatchLabelBytes)
	partial = partial || truncated
	capabilityMatch.MBC, truncated = normalizeCapabilityMatchStrings(capabilityMatch.MBC, maxCapabilityMatchMappings, maxCapabilityMatchLabelBytes)
	partial = partial || truncated
	capabilityMatch.ArchitectureScopes, truncated = normalizeCapabilityMatchStrings(capabilityMatch.ArchitectureScopes, maxCapabilityMatchResources, maxCapabilityMatchLabelBytes)
	partial = partial || truncated
	capabilityMatch.MatchTrace, truncated = normalizeMatchTrace(capabilityMatch.MatchTrace)
	partial = partial || truncated
	return capabilityMatch, partial
}

func boundedCapabilityMatchString(value string, limit int) (string, bool) {
	if len(value) <= limit {
		valid := strings.ToValidUTF8(value, "?")
		return valid, valid != value
	}
	return strings.ToValidUTF8(value[:limit], "?"), true
}

func normalizeCapabilityMatchStrings(values []string, limit, byteLimit int) ([]string, bool) {
	partial := false
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value, truncated := boundedCapabilityMatchString(value, byteLimit)
		partial = partial || truncated
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
		partial = true
	}
	return out, partial
}

func normalizeCapabilityMatchResources(values []behavior.Resource) ([]behavior.Resource, bool) {
	partial := len(values) > maxCapabilityMatchResources
	if len(values) > maxCapabilityMatchResources {
		values = values[:maxCapabilityMatchResources]
	}
	seen := make(map[behavior.ResourceKey]bool, len(values))
	out := make([]behavior.Resource, 0, len(values))
	for _, resource := range values {
		// A truncated or UTF-8-repaired value is no longer the physical identity
		// bound to the supporting operation. Omit that presentation projection
		// instead; the operation and match trace retain the complete fact and the
		// rule-evaluation coverage marker records that a field was omitted.
		if len(resource.Value) > maxCapabilityMatchValueBytes || !utf8.ValidString(resource.Value) {
			partial = true
			continue
		}
		resource, err := behavior.NormalizeResource(resource)
		if err != nil {
			partial = true
			continue
		}
		key := resource.Key()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, resource)
	}
	sort.Slice(out, func(i, j int) bool {
		if compared := strings.Compare(string(out[i].Kind), string(out[j].Kind)); compared != 0 {
			return compared < 0
		}
		if compared := strings.Compare(out[i].Value, out[j].Value); compared != 0 {
			return compared < 0
		}
		return out[i].Key() < out[j].Key()
	})
	return out, partial
}

func compareCapabilityMatches(left, right behavior.CapabilityMatch) int {
	if leftRank, rightRank := supportRank(left.Support), supportRank(right.Support); leftRank != rightRank {
		return leftRank - rightRank
	}
	if compared := strings.Compare(left.RuleID, right.RuleID); compared != 0 {
		return compared
	}
	if compared := strings.Compare(left.Namespace, right.Namespace); compared != 0 {
		return compared
	}
	if compared := strings.Compare(left.Title, right.Title); compared != 0 {
		return compared
	}
	if compared := strings.Compare(string(left.Execution.Connectivity), string(right.Execution.Connectivity)); compared != 0 {
		return compared
	}
	if compared := compareCapabilityMatchStrings(left.Execution.ExecutionRootIDs, right.Execution.ExecutionRootIDs); compared != 0 {
		return compared
	}
	if compared := compareCapabilityMatchStrings(left.Execution.InvokedTargetIDs, right.Execution.InvokedTargetIDs); compared != 0 {
		return compared
	}
	if compared := strings.Compare(left.SubjectNodeID, right.SubjectNodeID); compared != 0 {
		return compared
	}
	if compared := compareCapabilityMatchResources(left.AffectedResources, right.AffectedResources); compared != 0 {
		return compared
	}
	if compared := compareCapabilityMatchStrings(left.ArchitectureScopes, right.ArchitectureScopes); compared != 0 {
		return compared
	}
	if compared := compareCapabilityMatchStrings(left.OperationIDs, right.OperationIDs); compared != 0 {
		return compared
	}
	if compared := compareCapabilityMatchStrings(left.EvidenceIDs, right.EvidenceIDs); compared != 0 {
		return compared
	}
	if compared := compareCapabilityMatchStrings(left.Attack, right.Attack); compared != 0 {
		return compared
	}
	if compared := compareCapabilityMatchStrings(left.MBC, right.MBC); compared != 0 {
		return compared
	}
	if compared := compareMatchTrace(left.MatchTrace, right.MatchTrace); compared != 0 {
		return compared
	}
	return strings.Compare(left.ID, right.ID)
}

func compareCapabilityMatchResources(left, right []behavior.Resource) int {
	for i := 0; i < min(len(left), len(right)); i++ {
		if compared := strings.Compare(string(left[i].Kind), string(right[i].Kind)); compared != 0 {
			return compared
		}
		if compared := strings.Compare(left[i].Value, right[i].Value); compared != 0 {
			return compared
		}
		if compared := strings.Compare(string(left[i].Key()), string(right[i].Key())); compared != 0 {
			return compared
		}
	}
	return len(left) - len(right)
}

func compareCapabilityMatchStrings(left, right []string) int {
	for i := 0; i < min(len(left), len(right)); i++ {
		if compared := strings.Compare(left[i], right[i]); compared != 0 {
			return compared
		}
	}
	return len(left) - len(right)
}

func supportRank(c behavior.Support) int {
	switch c {
	case behavior.SupportDirect:
		return 0
	case behavior.SupportCorroborated:
		return 1
	default:
		return 2
	}
}
