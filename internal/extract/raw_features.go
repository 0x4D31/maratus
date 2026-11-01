package extract

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

// rawFeatureExtractor is an intentionally narrow lane for structurally known
// representations whose semantics maratus cannot yet decode. Its budgets are
// shared across all such contents in one inspection so an archive cannot
// multiply per-entry string and regexp limits.
type rawFeatureExtractor struct {
	strings        asciiRunBudget
	urls           rawFeatureMatchBudget
	ips            rawFeatureMatchBudget
	limitsReported bool
}

type rawFeatureMatchBudget struct {
	remaining int
}

func newRawFeatureExtractor() rawFeatureExtractor {
	return rawFeatureExtractor{
		strings: newASCIIRunBudget(),
		urls:    rawFeatureMatchBudget{remaining: maxMachORegexMatches},
		ips:     rawFeatureMatchBudget{remaining: maxMachORegexMatches},
	}
}

func (extractor *rawFeatureExtractor) extract(graph *behavior.Graph, content artifact.Content) {
	representation := strings.TrimSpace(content.Kind)
	if representation == "" {
		representation = "uninterpreted-bytes"
	}
	area := strings.TrimSpace(content.SemanticCoverageArea)
	if area == "" {
		area = "representation-semantics/" + strings.ReplaceAll(representation, " ", "-")
	}
	detail := strings.TrimSpace(content.SemanticCoverageDetail)
	if detail == "" {
		detail = fmt.Sprintf("%s representation identified; semantic decoding is not implemented", representation)
	}
	graph.AddCoverage(behavior.Coverage{
		NodeID:       content.NodeID,
		AnalysisArea: area,
		Status:       "partial",
		Detail:       detail,
	})
	if graph.WorkLimitReached() {
		graph.MarkWorkOmitted()
		return
	}

	stringsWereTruncated := extractor.strings.truncated
	runs := extractor.strings.scan(content.Data, 6)
	stringsTruncated := extractor.strings.truncated && (!stringsWereTruncated || len(content.Data) > 0)
	regexTruncated := false
	urlCandidateRetained := false
	seen := map[string]bool{}
	for _, run := range runs {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			break
		}
		urlMatches, truncated := extractor.urls.matches(reURL, run.Value)
		regexTruncated = regexTruncated || truncated
		for _, match := range urlMatches {
			value, ok := normalizeStaticURL(run.Value[match[0]:match[1]])
			if !ok || seen["url\x00"+value] {
				continue
			}
			seen["url\x00"+value] = true
			if !addRawFeatureFeature(graph, content, representation, "network.url", "url", value, run.Offset+match[0], behavior.SupportHeuristic) {
				return
			}
			urlCandidateRetained = true
		}

		ipMatches, truncated := extractor.ips.matches(reIP, run.Value)
		regexTruncated = regexTruncated || truncated
		for _, match := range validatedIPv4MatchIndexes(run.Value, ipMatches) {
			value, _ := validatedIPv4Match(run.Value, match)
			if seen["ip\x00"+value] {
				continue
			}
			seen["ip\x00"+value] = true
			if !addRawFeatureFeature(graph, content, representation, "network.ip", "ip", value, run.Offset+match[0], behavior.SupportHeuristic) {
				return
			}
		}
	}
	if urlCandidateRetained {
		addPartialCoverageOnce(graph, content.NodeID, "raw-byte-url-candidates", "URL candidates were extracted from printable byte runs; encoded-string boundaries are unresolved, so candidates may include adjacent representation bytes")
	}
	if (stringsTruncated || regexTruncated) && !extractor.limitsReported {
		extractor.limitsReported = true
		detail := fmt.Sprintf("raw ASCII feature extraction capped across uninterpreted representations at %d input bytes, %d runs, %d captured bytes, and %d bytes per string", maxMachOASCIIInputBytes, maxMachOASCIIStringRuns, maxMachOASCIIBytes, maxMachOASCIIStringBytes)
		if regexTruncated {
			detail += fmt.Sprintf("; URL and IPv4 candidates capped at %d each", maxMachORegexMatches)
		}
		addPartialCoverageOnce(graph, content.NodeID, "raw-byte-features", detail)
	}
}

func (budget *rawFeatureMatchBudget) matches(expression *regexp.Regexp, value string) ([][]int, bool) {
	matches, truncated := limitedStringMatches(expression, value, budget.remaining)
	budget.remaining -= len(matches)
	return matches, truncated
}

func addRawFeatureFeature(graph *behavior.Graph, content artifact.Content, representation, key, evidenceKind, value string, offset int, support behavior.Support) bool {
	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID:      content.NodeID,
		ScopeID:     content.ScopeID,
		Logical:     content.LogicalPath,
		Physical:    content.PhysicalPath,
		Offset:      int64(offset),
		OffsetKnown: true,
		Method:      "raw-byte-strings",
		Kind:        evidenceKind,
		Value:       value,
	})
	if evidenceID == "" {
		graph.MarkWorkOmitted()
		return false
	}
	if graph.AddFeature(behavior.Feature{
		NodeID:  content.NodeID,
		ScopeID: content.ScopeID,
		Key:     key,
		Value:   value,
		Qualifiers: map[string]string{
			"extraction":      "ascii-run-regex",
			"origin":          "raw-bytes",
			"representation":  representation,
			"string_boundary": "unresolved",
		},
		EvidenceIDs: []string{evidenceID},
		Support:     support,
		Execution:   executionContextForContent(content),
	}) == "" {
		graph.MarkWorkOmitted()
		return false
	}
	return true
}
