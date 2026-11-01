package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxRustConstantDeclarations = 256
	maxRustConstantFragments    = 256
	maxRustConstantEncodedBytes = 4 << 20
	maxRustConstantDecodedBytes = 4 << 20
)

type rustConstantFragment struct {
	value  string
	offset int
}

type rustConstantSequence struct {
	name      string
	fragments []rustConstantFragment
}

var rustConstantDeclaration = regexp.MustCompile(`(?m)\b(?:pub(?:\s*\([^\n)]*\))?\s+)?(?:const|static)\s+([A-Za-z_][A-Za-z0-9_]*)[^=;\n]{0,1000}=`)

// extractRustConstantObservations decodes only a complete immutable constant
// string or string array. It is a static-observation lane, not Rust execution
// or name resolution, and therefore never creates an operation.
func extractRustConstantObservations(graph *behavior.Graph, content artifact.Content, source string, mask []bool) {
	sequences, limited := rustConstantSequences(source, mask)
	if limited {
		addPartialCoverageOnce(graph, content.NodeID, "rust-constant-observations", fmt.Sprintf("Rust constant observation analysis capped at %d declarations, %d fragments, %d encoded bytes, and %d decoded bytes", maxRustConstantDeclarations, maxRustConstantFragments, maxRustConstantEncodedBytes, maxRustConstantDecodedBytes))
	}
	seen := map[string]bool{}
	encodedBytes := 0
	decodedBytes := 0
	for _, sequence := range sequences {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
		var decoded bytes.Buffer
		valid := len(sequence.fragments) > 0
		for _, fragment := range sequence.fragments {
			if len(fragment.value) > maxRustConstantEncodedBytes-encodedBytes || len(fragment.value)%4 != 0 {
				valid = false
				limited = limited || len(fragment.value) > maxRustConstantEncodedBytes-encodedBytes
				break
			}
			encodedBytes += len(fragment.value)
			part, err := base64.StdEncoding.Strict().DecodeString(fragment.value)
			if err != nil || len(part) == 0 || base64.StdEncoding.EncodeToString(part) != fragment.value {
				valid = false
				break
			}
			if len(part) > maxRustConstantDecodedBytes-decodedBytes-decoded.Len() {
				valid = false
				limited = true
				break
			}
			decoded.Write(part)
		}
		if !valid {
			continue
		}
		decodedValue := decoded.Bytes()
		decodedBytes += len(decodedValue)
		decodedText := string(decodedValue)
		urls := make([]string, 0)
		ips := make([]string, 0)
		pending := map[string]bool{}
		for _, match := range firstLimitedMatches(reURL, decodedText, maxMachORegexMatches) {
			value, ok := normalizeStaticURL(decodedText[match[0]:match[1]])
			key := "url\x00" + value
			if ok && !seen[key] && !pending[key] {
				pending[key] = true
				urls = append(urls, value)
			}
		}
		for _, match := range validatedIPv4MatchIndexes(decodedText, firstLimitedMatches(reIP, decodedText, maxMachORegexMatches)) {
			value, ok := validatedIPv4Match(decodedText, match)
			key := "ip\x00" + value
			if ok && !seen[key] && !pending[key] {
				pending[key] = true
				ips = append(ips, value)
			}
		}
		if len(urls) == 0 && len(ips) == 0 {
			continue
		}
		evidenceIDs := make([]string, 0, len(sequence.fragments))
		for _, fragment := range sequence.fragments {
			digest := sha256.Sum256([]byte(fragment.value))
			evidenceID := graph.AddEvidence(behavior.Evidence{
				NodeID: content.NodeID, Logical: content.LogicalPath, Physical: content.PhysicalPath,
				Offset: int64(fragment.offset), OffsetKnown: true,
				Method: "rust-constant", Kind: "base64-fragment",
				Value: fmt.Sprintf("sha256:%s length:%d", hex.EncodeToString(digest[:]), len(fragment.value)),
			})
			if evidenceID == "" {
				return
			}
			evidenceIDs = append(evidenceIDs, evidenceID)
		}
		decodedDigest := sha256.Sum256(decodedValue)
		qualifiers := map[string]string{
			"binding":         sequence.name,
			"decoded_sha256":  hex.EncodeToString(decodedDigest[:]),
			"decoded_size":    fmt.Sprintf("%d", len(decodedValue)),
			"fragment_count":  fmt.Sprintf("%d", len(sequence.fragments)),
			"transformation":  "canonical-base64-constant",
			"runtime_use":     "not-established",
			"source_language": "rust",
		}
		addRustDerivedFeature(graph, content, "derived.base64.content", "sha256:"+hex.EncodeToString(decodedDigest[:]), qualifiers, evidenceIDs)
		for _, value := range urls {
			seen["url\x00"+value] = true
			addRustDerivedFeature(graph, content, "network.url", value, qualifiers, evidenceIDs)
		}
		for _, value := range ips {
			seen["ip\x00"+value] = true
			addRustDerivedFeature(graph, content, "network.ip", value, qualifiers, evidenceIDs)
		}
	}
	if limited {
		addPartialCoverageOnce(graph, content.NodeID, "rust-constant-observations", fmt.Sprintf("Rust constant observation analysis capped at %d declarations, %d fragments, %d encoded bytes, and %d decoded bytes", maxRustConstantDeclarations, maxRustConstantFragments, maxRustConstantEncodedBytes, maxRustConstantDecodedBytes))
	}
}

func firstLimitedMatches(expression *regexp.Regexp, value string, limit int) [][]int {
	matches, _ := limitedStringMatches(expression, value, limit)
	return matches
}

func addRustDerivedFeature(graph *behavior.Graph, content artifact.Content, key, value string, qualifiers map[string]string, evidenceIDs []string) {
	graph.AddFeature(behavior.Feature{
		NodeID: content.NodeID, Key: key, Value: value,
		Qualifiers: qualifiers, EvidenceIDs: append([]string(nil), evidenceIDs...),
		Support: behavior.SupportDirect, Execution: unknownExecutionContext(),
	})
}

func rustConstantSequences(source string, mask []bool) ([]rustConstantSequence, bool) {
	matches := rustConstantDeclaration.FindAllStringSubmatchIndex(source, maxRustConstantDeclarations+1)
	limited := len(matches) > maxRustConstantDeclarations
	if limited {
		matches = matches[:maxRustConstantDeclarations]
	}
	sequences := make([]rustConstantSequence, 0, len(matches))
	for _, match := range matches {
		if len(match) < 4 || !rustCodeAt(mask, match[0]) || rustOffsetInsideMacroDefinition(source, mask, match[0]) {
			continue
		}
		end, ok := rustConstantInitializerEnd(source, mask, match[1])
		if !ok {
			limited = true
			continue
		}
		fragments, ok := parseRustConstantStringSequence(source, match[1], end)
		if !ok {
			continue
		}
		if len(fragments) > maxRustConstantFragments {
			limited = true
			continue
		}
		sequences = append(sequences, rustConstantSequence{name: source[match[2]:match[3]], fragments: fragments})
	}
	return sequences, limited
}

func rustOffsetInsideMacroDefinition(source string, mask []bool, offset int) bool {
	macro := regexp.MustCompile(`\bmacro_rules\s*!\s*[A-Za-z_][A-Za-z0-9_]*\s*\{`)
	for _, match := range macro.FindAllStringIndex(source[:min(offset, len(source))], maxRustConstantDeclarations+1) {
		if len(match) != 2 || !rustCodeAt(mask, match[0]) {
			continue
		}
		open := strings.LastIndex(source[match[0]:match[1]], "{") + match[0]
		depth := 0
		for index := open; index < len(source); index++ {
			if !rustCodeAt(mask, index) {
				continue
			}
			switch source[index] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					if offset > open && offset < index {
						return true
					}
					index = len(source)
				}
			}
		}
	}
	return false
}

func rustConstantInitializerEnd(source string, mask []bool, start int) (int, bool) {
	depth := 0
	limit := min(len(source), start+maxRustConstantEncodedBytes+maxRustAPIStatementBytes)
	for index := start; index < limit; index++ {
		if !rustCodeAt(mask, index) {
			continue
		}
		switch source[index] {
		case '[', '(', '{':
			depth++
		case ']', ')', '}':
			if depth == 0 {
				return 0, false
			}
			depth--
		case ';':
			if depth == 0 {
				return index, true
			}
		}
	}
	return 0, false
}

func parseRustConstantStringSequence(source string, start, end int) ([]rustConstantFragment, bool) {
	position := skipRustWhitespace(source, start, end)
	if position < end && source[position] == '&' {
		position = skipRustWhitespace(source, position+1, end)
	}
	if position < end && source[position] == '[' {
		position++
		fragments := make([]rustConstantFragment, 0, 4)
		for {
			position = skipRustWhitespace(source, position, end)
			if position < end && source[position] == ']' {
				position = skipRustWhitespace(source, position+1, end)
				return fragments, position == end && len(fragments) > 0
			}
			fragment, next, ok := readExactRustStringAt(source, position, end)
			if !ok {
				return nil, false
			}
			fragments = append(fragments, rustConstantFragment{value: fragment, offset: position})
			if len(fragments) > maxRustConstantFragments {
				return fragments, true
			}
			position = skipRustWhitespace(source, next, end)
			if position < end && source[position] == ',' {
				position++
				continue
			}
			if position >= end || source[position] != ']' {
				return nil, false
			}
		}
	}
	fragment, next, ok := readExactRustStringAt(source, position, end)
	if !ok || skipRustWhitespace(source, next, end) != end {
		return nil, false
	}
	return []rustConstantFragment{{value: fragment, offset: position}}, true
}

func readExactRustStringAt(source string, start, end int) (string, int, bool) {
	if start < 0 || start >= end {
		return "", start, false
	}
	if source[start] == '"' {
		value, close, ok, oversized := readSourceStringLiteralLimited(source[:end], start, '"', maxRustConstantEncodedBytes)
		if !ok || oversized || strings.Contains(source[start:close+1], "\\") {
			return "", start, false
		}
		return value, close + 1, true
	}
	if source[start] != 'r' {
		return "", start, false
	}
	hashes := 0
	quote := start + 1
	for quote < end && source[quote] == '#' {
		hashes++
		quote++
	}
	if quote >= end || source[quote] != '"' || hashes > 64 {
		return "", start, false
	}
	closing := `"` + strings.Repeat("#", hashes)
	relative := strings.Index(source[quote+1:end], closing)
	if relative < 0 || relative > maxRustConstantEncodedBytes {
		return "", start, false
	}
	valueStart := quote + 1
	valueEnd := valueStart + relative
	return source[valueStart:valueEnd], valueEnd + len(closing), true
}

func skipRustWhitespace(source string, position, end int) int {
	for position < end {
		switch source[position] {
		case ' ', '\t', '\r', '\n':
			position++
		default:
			return position
		}
	}
	return position
}
