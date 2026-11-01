package extract

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxJavaScriptFeatureBytes            = 8 << 20
	maxJavaScriptFeatureLines            = 200_000
	maxJavaScriptFeatureLineBytes        = 1 << 20
	maxJavaScriptFeatureTokens           = 1 << 20
	maxJavaScriptFeatureValuesPerLine    = 64
	maxJavaScriptModuleSpecifiersPerNode = 256
	maxJavaScriptURLsPerNode             = 256
	maxJavaScriptSensitivePathsPerNode   = 256
	maxJavaScriptModuleSpecifiersTotal   = 512
	maxJavaScriptURLsTotal               = 512
	maxJavaScriptSensitivePathsTotal     = 512
	maxJavaScriptFeatureValueBytes       = 4 << 10
	javaScriptFeatureAnalysisArea        = "javascript-feature-analysis"
	javaScriptModuleSpecifierFeatureKey  = "javascript.module_specifier"
	javaScriptFeatureFamilyModule        = "module specifier"
	javaScriptFeatureFamilyURL           = "URL literal"
	javaScriptFeatureFamilySensitive     = "sensitive-path literal"
)

type javaScriptFeatureToken struct {
	kind  javaScriptSyntaxEventKind
	text  string
	start int
	end   int
	line  int
	depth int
}

type javaScriptFeatureObservation struct {
	key      string
	value    string
	form     string
	family   string
	offset   int
	line     int
	scopeKey string
	scoped   bool
}

type javaScriptFeatureLineScope struct {
	key    string
	scoped bool
}

type javaScriptFeatureInventoryLimits struct {
	inspection map[string]int
	line       map[string]map[int]int
	reported   map[string]bool
}

func newJavaScriptFeatureInventoryLimits() javaScriptFeatureInventoryLimits {
	return javaScriptFeatureInventoryLimits{
		inspection: map[string]int{},
		line:       map[string]map[int]int{},
		reported:   map[string]bool{},
	}
}

// addJavaScriptSourceFeatures is an independent, late syntax inventory. It
// never creates execution roots, targets, operations, relations, network-stack
// observations, or capability matches. All retained facts remain UNKNOWN even
// when the containing artifact is an execution root.
func addJavaScriptSourceFeatures(graph *behavior.Graph, contents []artifact.Content) {
	selected := make(map[string]bool, len(graph.AnalysisSelections))
	selectionPriority := make(map[string]int, len(graph.AnalysisSelections))
	for _, selection := range graph.AnalysisSelections {
		selected[selection.NodeID] = true
		priority := 5
		for _, reason := range selection.Reasons {
			switch reason {
			case behavior.SelectionReasonExecutionRoot:
				priority = min(priority, 0)
			case behavior.SelectionReasonInvokedTarget:
				priority = min(priority, 1)
			case behavior.SelectionReasonDeclaredEntry:
				priority = min(priority, 2)
			case behavior.SelectionReasonRunnableCandidate:
				priority = min(priority, 3)
			case behavior.SelectionReasonDefaultRelevant:
				priority = min(priority, 4)
			case behavior.SelectionReasonIncludeUnreferenced:
				priority = min(priority, 5)
			}
		}
		selectionPriority[selection.NodeID] = priority
	}
	enforceSelection := len(graph.AnalysisSelections) > 0

	candidates := make([]artifact.Content, 0, len(contents))
	for _, content := range contents {
		if enforceSelection && !selected[content.NodeID] ||
			content.RawFeaturesOnly ||
			content.MediaType != "text/plain" ||
			contentLanguage(content) != "javascript" ||
			!behaviorSourceRoleAllowed(content.Role, content.BehaviorAnalysisForced) ||
			!semanticTextAllowed(content, "javascript") {
			continue
		}
		candidates = append(candidates, content)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		leftPriority := selectionPriority[candidates[i].NodeID]
		rightPriority := selectionPriority[candidates[j].NodeID]
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		if candidates[i].NodeID != candidates[j].NodeID {
			return candidates[i].NodeID < candidates[j].NodeID
		}
		if candidates[i].LogicalPath != candidates[j].LogicalPath {
			return candidates[i].LogicalPath < candidates[j].LogicalPath
		}
		return candidates[i].Architecture < candidates[j].Architecture
	})
	inspection := map[string]int{}
	existingScopes := javaScriptFeatureScopes(graph)
	for _, content := range candidates {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			break
		}
		addJavaScriptContentFeatures(graph, content, existingScopes, inspection)
	}
}

func addJavaScriptContentFeatures(
	graph *behavior.Graph,
	content artifact.Content,
	existingScopes map[javaScriptFeatureScopeIdentity][]javaScriptFeatureScopeCandidate,
	inspection map[string]int,
) {
	if detail := unsupportedJavaScriptFeatureDialect(content.LogicalPath); detail != "" {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			javaScriptFeatureAnalysisArea,
			detail,
		)
		return
	}
	source, sourceLimitDetail := boundedJavaScriptFeatureSource(content.Data)
	if sourceLimitDetail != "" {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			javaScriptFeatureAnalysisArea,
			sourceLimitDetail,
		)
	}
	if source == "" {
		return
	}
	source = maskJavaScriptFeatureSourcePrefix(source)

	// Build and release the higher-level structural token workspace before
	// retaining the independent lexical token slice. Keeping both million-token
	// worksets live at once would needlessly multiply peak memory.
	lines := strings.Split(source, "\n")
	prescan := prescanJavaScriptCommands(lines)
	index := prescan.index
	if prescan.limited {
		detail := prescan.limitDetail
		if detail == "" {
			detail = "JavaScript structural index was incomplete"
		}
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			javaScriptFeatureAnalysisArea,
			detail+"; JavaScript Feature scoping and CommonJS runtime-identity proof were incomplete",
		)
	}
	scopeByLine := javaScriptFeatureScopeKeysByLine(index)
	scopeByKey := javaScriptFeatureScopesByKey(index)

	tokens, tailLiteralObservations, lexicalDetails := scanJavaScriptFeatureTokens(source)
	for _, lexicalDetail := range lexicalDetails {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			javaScriptFeatureAnalysisArea,
			lexicalDetail,
		)
	}
	if len(tokens) == 0 {
		return
	}
	matches := javaScriptFeatureDelimiterMatches(tokens)
	reverseMatches := javaScriptFeatureReverseDelimiterMatches(matches)
	markupOffset := javaScriptFeatureUnsupportedMarkupOffset(
		tokens,
		reverseMatches,
	)
	if markupOffset >= 0 {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			javaScriptFeatureAnalysisArea,
			"JSX-like markup encountered in JavaScript source; Feature inventory stopped before the unsupported markup region",
		)
		tokens = javaScriptFeatureTokensBefore(tokens, markupOffset)
		if len(tokens) == 0 {
			return
		}
		matches = javaScriptFeatureDelimiterMatches(tokens)
	}

	observations, observationDetails := collectJavaScriptFeatureObservations(
		tokens,
		matches,
		prescan,
		scopeByLine,
		sourceLimitDetail == "" &&
			len(lexicalDetails) == 0 &&
			!prescan.limited &&
			markupOffset < 0,
	)
	observations = append(observations, tailLiteralObservations...)
	bundleObservations, bundleObservationDetail := javaScriptBundleFeatureObservations(
		source,
		prescan.bundleModules,
		observations,
	)
	observations = append(observations, bundleObservations...)
	if bundleObservationDetail != "" {
		observationDetails = append(observationDetails, bundleObservationDetail)
	}
	for _, detail := range observationDetails {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			javaScriptFeatureAnalysisArea,
			detail,
		)
	}

	scopeIDs := map[string]string{}
	limits := newJavaScriptFeatureInventoryLimits()
	limits.inspection = inspection
	seen := map[string]bool{}
	for _, observation := range observations {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
		scopeID, sourceFunction := javaScriptObservationScope(
			graph,
			content,
			observation,
			scopeByKey,
			scopeIDs,
			existingScopes,
		)
		identity := strings.Join([]string{
			observation.key,
			observation.value,
			observation.form,
			scopeID,
			sourceFunction,
		}, "\x00")
		if seen[identity] {
			continue
		}
		seen[identity] = true
		if !limits.retain(graph, content.NodeID, observation) {
			continue
		}

		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:      content.NodeID,
			ScopeID:     scopeID,
			Logical:     content.LogicalPath,
			Physical:    content.PhysicalPath,
			Line:        observation.line,
			Offset:      int64(observation.offset),
			OffsetKnown: true,
			Function:    sourceFunction,
			Arch:        content.Architecture,
			Method:      "javascript-lexical",
			Kind:        javaScriptFeatureEvidenceKind(observation),
			Value:       observation.value,
		})
		if evidenceID == "" {
			graph.MarkWorkOmitted()
			return
		}
		qualifiers := map[string]string(nil)
		if observation.form != "" {
			qualifiers = map[string]string{
				"form": observation.form,
			}
		}
		if observation.key == "script.sensitive_resource" {
			if qualifiers == nil {
				qualifiers = map[string]string{}
			}
			if category, ok := JavaScriptSensitiveLiteralCategory(
				observation.value,
			); ok {
				qualifiers["category"] = category
			}
		}
		if graph.AddFeature(behavior.Feature{
			NodeID:         content.NodeID,
			ScopeID:        scopeID,
			Architecture:   content.Architecture,
			Key:            observation.key,
			Value:          observation.value,
			Qualifiers:     qualifiers,
			EvidenceIDs:    []string{evidenceID},
			Support:        behavior.SupportDirect,
			Execution:      unknownExecutionContext(),
			SourceFunction: sourceFunction,
		}) == "" {
			graph.MarkWorkOmitted()
			return
		}
	}
}

func javaScriptBundleFeatureObservations(
	source string,
	modules []javaScriptBundleModule,
	existing []javaScriptFeatureObservation,
) ([]javaScriptFeatureObservation, string) {
	if len(modules) == 0 {
		return nil, ""
	}
	lineStarts := javaScriptStructuralLineStarts(source)
	seen := map[string]bool{}
	for _, observation := range existing {
		if observation.key == javaScriptModuleSpecifierFeatureKey {
			seen[fmt.Sprintf("%s\x00%d", observation.value, observation.offset)] = true
		}
	}
	var observations []javaScriptFeatureObservation
	for _, module := range modules {
		if module.literalLine <= 0 || module.literalLine > len(lineStarts) || module.literalColumn < 0 {
			return observations, "exact bundled CommonJS module location could not be represented; the affected module observation was omitted"
		}
		offset := lineStarts[module.literalLine-1] + module.literalColumn
		if offset < 0 || len(module.specifier) > len(source)-offset || source[offset:offset+len(module.specifier)] != module.specifier {
			return observations, "exact bundled CommonJS module location disagreed with retained source bytes; the affected module observation was omitted"
		}
		identity := fmt.Sprintf("%s\x00%d", module.specifier, offset)
		if seen[identity] {
			continue
		}
		seen[identity] = true
		observations = append(observations, javaScriptFeatureObservation{
			key: javaScriptModuleSpecifierFeatureKey, value: module.specifier,
			form: "bundled-commonjs-wrapper", family: javaScriptFeatureFamilyModule,
			offset: offset, line: module.literalLine,
		})
	}
	return observations, ""
}

func unsupportedJavaScriptFeatureDialect(logicalPath string) string {
	switch strings.ToLower(filepath.Ext(logicalPath)) {
	case ".jsx", ".tsx":
		return "JSX/TSX source identified; JavaScript Feature inventory is unavailable because markup regions are not decoded"
	case ".ts":
		return "TypeScript source identified; JavaScript Feature inventory is unavailable because type syntax is not decoded"
	default:
		return ""
	}
}

func maskJavaScriptFeatureSourcePrefix(source string) string {
	prefixEnd := 0
	if strings.HasPrefix(source, "\xef\xbb\xbf") {
		prefixEnd = len("\xef\xbb\xbf")
	}
	hashbangStart := prefixEnd
	if strings.HasPrefix(source[hashbangStart:], "#!") {
		prefixEnd = len(source)
		for index := hashbangStart; index < len(source); index++ {
			if source[index] == '\n' || source[index] == '\r' {
				prefixEnd = index
				break
			}
		}
	}
	if prefixEnd == 0 {
		return source
	}
	masked := []byte(source)
	for index := 0; index < prefixEnd; index++ {
		masked[index] = ' '
	}
	return string(masked)
}

func boundedJavaScriptFeatureSource(data []byte) (string, string) {
	end := min(len(data), maxJavaScriptFeatureBytes)
	lineStart := 0
	lines := 1
	for index := 0; index < end; index++ {
		if index-lineStart >= maxJavaScriptFeatureLineBytes {
			return string(data[:index]), fmt.Sprintf(
				"JavaScript Feature inventory physical-line limit %d bytes reached; the affected line suffix and remaining source were not inventoried",
				maxJavaScriptFeatureLineBytes,
			)
		}
		if data[index] != '\n' {
			continue
		}
		lines++
		lineStart = index + 1
		if lines > maxJavaScriptFeatureLines {
			return string(data[:index+1]), fmt.Sprintf(
				"JavaScript Feature inventory line limit %d reached; remaining source was not inventoried",
				maxJavaScriptFeatureLines,
			)
		}
	}
	if len(data) > end {
		return string(data[:end]), fmt.Sprintf(
			"JavaScript Feature inventory byte limit %d reached; remaining source was not inventoried",
			maxJavaScriptFeatureBytes,
		)
	}
	return string(data[:end]), ""
}

func scanJavaScriptFeatureTokens(source string) ([]javaScriptFeatureToken, []javaScriptFeatureObservation, []string) {
	return scanJavaScriptFeatureTokensWithLimit(source, maxJavaScriptFeatureTokens)
}

func scanJavaScriptFeatureTokensWithLimit(source string, maxTokens int) ([]javaScriptFeatureToken, []javaScriptFeatureObservation, []string) {
	if !utf8.ValidString(source) {
		return nil, nil, []string{"JavaScript Feature inventory rejected invalid UTF-8 source"}
	}
	if maxTokens < 0 {
		return nil, nil, []string{"JavaScript Feature inventory token limit was invalid"}
	}
	lineStarts := javaScriptStructuralLineStarts(source)
	tokens := make([]javaScriptFeatureToken, 0, min(min(len(source)/4, maxTokens), 4096))
	limited := false
	tail := newJavaScriptTailLiteralCollector()
	_, valid := scanJavaScriptSyntaxMode(
		source,
		0,
		len(source),
		0,
		true,
		func(event javaScriptSyntaxEvent) bool {
			text := source[event.start:event.end]
			tailActive := limited || len(tokens) >= maxTokens
			if text == "/" || tailActive && javaScriptFeatureQuotedText(text) {
				line := javaScriptFeatureLineAt(lineStarts, event.start)
				tail.observe(text, event.start, line, tailActive)
			}
			if len(tokens) >= maxTokens {
				limited = true
				return true
			}
			line := javaScriptFeatureLineAt(lineStarts, event.start)
			tokens = append(tokens, javaScriptFeatureToken{
				kind:  event.kind,
				text:  text,
				start: event.start,
				end:   event.end,
				line:  line,
				depth: event.depth,
			})
			return true
		},
	)
	observations, tailDetails := tail.result()
	var details []string
	if limited {
		details = append(details, fmt.Sprintf(
			"JavaScript Feature inventory token limit %d reached; remaining source was not structurally inventoried, but exact URL and sensitive-path literals remained eligible for bounded unscoped inventory",
			maxTokens,
		))
	}
	if !valid {
		details = append(details, "JavaScript Feature inventory stopped at malformed, non-ASCII, or unsupported lexical syntax; independently proven prefix observations were retained")
	}
	details = append(details, tailDetails...)
	return tokens, observations, uniqueJavaScriptFeatureDetails(details)
}

func javaScriptFeatureLineAt(lineStarts []int, offset int) int {
	line := sort.Search(len(lineStarts), func(index int) bool {
		return lineStarts[index] > offset
	})
	if line == 0 {
		return 1
	}
	return line
}

func javaScriptFeatureQuotedText(text string) bool {
	return len(text) >= 2 && (text[0] == '\'' || text[0] == '"')
}

type javaScriptTailLiteralCollector struct {
	observations  []javaScriptFeatureObservation
	suppressed    map[int]bool
	seen          map[string]bool
	counts        map[string]int
	limited       map[string]bool
	lastSlashLine int
	pending       []int
}

func newJavaScriptTailLiteralCollector() javaScriptTailLiteralCollector {
	return javaScriptTailLiteralCollector{
		suppressed: map[int]bool{}, seen: map[string]bool{},
		counts: map[string]int{}, limited: map[string]bool{},
	}
}

func (collector *javaScriptTailLiteralCollector) observe(text string, offset, line int, active bool) {
	if collector == nil {
		return
	}
	if collector.lastSlashLine != 0 && line != collector.lastSlashLine {
		collector.lastSlashLine = 0
		collector.pending = collector.pending[:0]
	}
	if text == "/" {
		if collector.lastSlashLine == line {
			for _, index := range collector.pending {
				collector.suppressed[index] = true
			}
		}
		collector.lastSlashLine = line
		collector.pending = collector.pending[:0]
		return
	}
	if !active || !javaScriptFeatureQuotedText(text) {
		return
	}
	value, exact, overlong := exactJavaScriptFeatureLiteral(text)
	if !exact {
		if overlong && javaScriptFeatureOverlongLiteralCandidate(text) {
			collector.limited["value"] = true
		}
		return
	}
	appendObservation := func(key, family string) {
		identity := family + "\x00" + value
		if collector.seen[identity] {
			return
		}
		limit, _ := javaScriptFeatureFamilyLimits(family)
		if collector.counts[family] >= limit {
			collector.limited[family] = true
			return
		}
		collector.seen[identity] = true
		collector.counts[family]++
		collector.observations = append(collector.observations, javaScriptFeatureObservation{
			key: key, value: value, family: family, offset: offset, line: line,
		})
		if collector.lastSlashLine == line {
			collector.pending = append(collector.pending, len(collector.observations)-1)
		}
	}
	if exactJavaScriptFeatureURL(value) {
		appendObservation("network.url", javaScriptFeatureFamilyURL)
	}
	if _, valid := exactJavaScriptSensitiveResource(value); valid {
		appendObservation("script.sensitive_resource", javaScriptFeatureFamilySensitive)
	}
}

func (collector javaScriptTailLiteralCollector) result() ([]javaScriptFeatureObservation, []string) {
	observations := make([]javaScriptFeatureObservation, 0, len(collector.observations))
	for index, observation := range collector.observations {
		if !collector.suppressed[index] {
			observations = append(observations, observation)
		}
	}
	var details []string
	for _, family := range []string{javaScriptFeatureFamilyURL, javaScriptFeatureFamilySensitive} {
		if collector.limited[family] {
			limit, _ := javaScriptFeatureFamilyLimits(family)
			details = append(details, fmt.Sprintf("JavaScript unscoped tail %s candidate limit %d reached; remaining candidates of that family were not inventoried", family, limit))
		}
	}
	if collector.limited["value"] {
		details = append(details, fmt.Sprintf("JavaScript tail literal exceeded Feature value limit %d bytes; exact resource observations from that literal were not retained", maxJavaScriptFeatureValueBytes))
	}
	return observations, details
}

func javaScriptFeatureUnsupportedMarkupOffset(
	tokens []javaScriptFeatureToken,
	reverseMatches map[int]int,
) int {
	for index, token := range tokens {
		if token.text != "<" ||
			index+1 >= len(tokens) ||
			(!javaScriptFeatureExpressionPrefix(tokens, index) &&
				!javaScriptFeatureControlBodyPrefix(
					tokens,
					reverseMatches,
					index,
				)) {
			continue
		}
		next := tokens[index+1]
		switch {
		case next.text == ">":
			return token.start
		case next.kind == javaScriptSyntaxIdentifier &&
			next.start == token.end:
			return token.start
		}
	}
	return -1
}

func javaScriptFeatureControlBodyPrefix(
	tokens []javaScriptFeatureToken,
	reverseMatches map[int]int,
	index int,
) bool {
	if index <= 0 {
		return false
	}
	previous := index - 1
	switch tokens[previous].text {
	case "do", "else":
		return true
	case ")":
		open, ok := reverseMatches[previous]
		if !ok || open <= 0 {
			return false
		}
		switch tokens[open-1].text {
		case "for", "if", "while", "with":
			return true
		}
	}
	return false
}

func javaScriptFeatureExpressionPrefix(
	tokens []javaScriptFeatureToken,
	index int,
) bool {
	if index <= 0 {
		return true
	}
	switch tokens[index-1].text {
	case "(", "[", "{", ",", ":", "?", "=", "+=", "-=", "*=",
		"/=", "%=", "**=", "&&=", "||=", "??=", "=>", ";", "+", "-",
		"*", "/", "%", "**", "&&", "||", "??", "==", "===", "!=", "!==",
		"<", ">", "<=", ">=", "<<", ">>", ">>>", "&", "|", "^", "!", "~",
		"await", "case", "delete", "return", "throw", "typeof", "void",
		"yield":
		return true
	default:
		return false
	}
}

func javaScriptFeatureTokensBefore(
	tokens []javaScriptFeatureToken,
	offset int,
) []javaScriptFeatureToken {
	end := sort.Search(len(tokens), func(index int) bool {
		return tokens[index].start >= offset
	})
	return tokens[:end]
}

func javaScriptFeatureDelimiterMatches(tokens []javaScriptFeatureToken) map[int]int {
	matches := map[int]int{}
	var stack []int
	for index, token := range tokens {
		switch token.text {
		case "(", "[", "{", "${":
			stack = append(stack, index)
		case ")", "]", "}":
			if len(stack) == 0 {
				continue
			}
			openIndex := stack[len(stack)-1]
			open := tokens[openIndex].text
			if !javaScriptFeatureDelimitersMatch(open, token.text) {
				continue
			}
			stack = stack[:len(stack)-1]
			matches[openIndex] = index
		}
	}
	return matches
}

func javaScriptFeatureReverseDelimiterMatches(
	matches map[int]int,
) map[int]int {
	reverse := make(map[int]int, len(matches))
	for open, close := range matches {
		reverse[close] = open
	}
	return reverse
}

func javaScriptFeatureDelimitersMatch(open, close string) bool {
	return open == "(" && close == ")" ||
		open == "[" && close == "]" ||
		(open == "{" || open == "${") && close == "}"
}

func collectJavaScriptFeatureObservations(
	tokens []javaScriptFeatureToken,
	matches map[int]int,
	prescan javaScriptCommandPrescan,
	scopeByLine map[int]javaScriptFeatureLineScope,
	complete bool,
) ([]javaScriptFeatureObservation, []string) {
	var observations []javaScriptFeatureObservation
	var details []string
	overlongModule := false
	ambiguousSlashSuppressed := false
	ambiguousLiteralOffsets := javaScriptFeatureAmbiguousLiteralOffsets(tokens)
	candidateCounts := map[string]int{}
	candidateSeen := map[string]bool{}
	candidateLimited := map[string]bool{}
	appendObservation := func(observation javaScriptFeatureObservation) {
		if ambiguousLiteralOffsets[observation.offset] {
			ambiguousSlashSuppressed = true
			return
		}
		scope := scopeByLine[observation.line]
		observation.scopeKey = scope.key
		observation.scoped = scope.scoped
		identity := strings.Join([]string{
			observation.family,
			observation.key,
			observation.value,
			observation.form,
			observation.scopeKey,
			fmt.Sprint(observation.scoped),
		}, "\x00")
		if candidateSeen[identity] {
			return
		}
		nodeLimit, _ := javaScriptFeatureFamilyLimits(observation.family)
		if candidateCounts[observation.family] >= nodeLimit {
			candidateLimited[observation.family] = true
			return
		}
		candidateSeen[identity] = true
		candidateCounts[observation.family]++
		observations = append(observations, observation)
	}

	for cursor := 0; cursor < len(tokens); cursor++ {
		token := tokens[cursor]
		if token.kind == javaScriptSyntaxIdentifier && token.text == "import" {
			scope := scopeByLine[token.line]
			if observation, ok, overlong := javaScriptImportObservation(
				tokens,
				matches,
				cursor,
				scope.scoped,
			); ok {
				appendObservation(observation)
			} else {
				overlongModule = overlongModule || overlong
			}
		}
		if token.kind == javaScriptSyntaxIdentifier && token.text == "export" {
			if observation, ok, overlong := javaScriptReExportObservation(
				tokens,
				matches,
				cursor,
			); ok {
				appendObservation(observation)
			} else {
				overlongModule = overlongModule || overlong
			}
		}
		if token.kind == javaScriptSyntaxIdentifier &&
			token.text == "require" &&
			complete {
			scope := scopeByLine[token.line]
			if scope.scoped && prescan.runtimeSafe[scope.key] {
				if observation, ok, overlong := javaScriptRequireObservation(tokens, matches, cursor); ok {
					appendObservation(observation)
				} else {
					overlongModule = overlongModule || overlong
				}
			}
		}
		if value, ok, overlong := exactJavaScriptFeatureLiteral(token.text); ok {
			if exactJavaScriptFeatureURL(value) {
				appendObservation(javaScriptFeatureObservation{
					key: "network.url", value: value, family: javaScriptFeatureFamilyURL,
					offset: token.start, line: token.line,
				})
			}
			if _, valid := exactJavaScriptSensitiveResource(value); valid {
				appendObservation(javaScriptFeatureObservation{
					key: "script.sensitive_resource", value: value,
					family: javaScriptFeatureFamilySensitive,
					offset: token.start, line: token.line,
				})
			}
		} else if overlong &&
			javaScriptFeatureOverlongLiteralCandidate(token.text) {
			details = append(details, fmt.Sprintf(
				"JavaScript literal exceeded Feature value limit %d bytes; exact resource observations from that literal were not retained",
				maxJavaScriptFeatureValueBytes,
			))
		}
	}
	for _, family := range []string{
		javaScriptFeatureFamilyModule,
		javaScriptFeatureFamilyURL,
		javaScriptFeatureFamilySensitive,
	} {
		if !candidateLimited[family] {
			continue
		}
		nodeLimit, _ := javaScriptFeatureFamilyLimits(family)
		details = append(details, fmt.Sprintf(
			"JavaScript %s candidate limit %d reached for node; remaining candidates of that family were not inventoried",
			family,
			nodeLimit,
		))
	}
	if overlongModule {
		details = append(details, fmt.Sprintf(
			"JavaScript module specifier exceeded %d bytes and was not inventoried",
			maxJavaScriptFeatureValueBytes,
		))
	}
	if ambiguousSlashSuppressed {
		details = append(details,
			"JavaScript Feature observation in slash-ambiguous syntax was not retained because the bounded lexer cannot always distinguish division from a regular expression",
		)
	}
	return observations, uniqueJavaScriptFeatureDetails(details)
}

func javaScriptFeatureAmbiguousLiteralOffsets(
	tokens []javaScriptFeatureToken,
) map[int]bool {
	out := map[int]bool{}
	lastSlashLine := 0
	var pending []int
	for _, token := range tokens {
		if lastSlashLine != 0 && token.line != lastSlashLine {
			lastSlashLine = 0
			pending = pending[:0]
		}
		if token.text == "/" {
			if lastSlashLine == token.line {
				for _, offset := range pending {
					out[offset] = true
				}
			}
			lastSlashLine = token.line
			pending = pending[:0]
			continue
		}
		if lastSlashLine == token.line &&
			javaScriptFeatureQuotedToken(token) {
			pending = append(pending, token.start)
		}
	}
	return out
}

func uniqueJavaScriptFeatureDetails(details []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(details))
	for _, detail := range details {
		if detail == "" || seen[detail] {
			continue
		}
		seen[detail] = true
		out = append(out, detail)
	}
	sort.Strings(out)
	return out
}

func javaScriptImportObservation(
	tokens []javaScriptFeatureToken,
	matches map[int]int,
	cursor int,
	allowDynamic bool,
) (javaScriptFeatureObservation, bool, bool) {
	if cursor < 0 || cursor >= len(tokens) || tokens[cursor].text != "import" {
		return javaScriptFeatureObservation{}, false, false
	}
	token := tokens[cursor]
	if cursor+1 >= len(tokens) {
		return javaScriptFeatureObservation{}, false, false
	}
	if cursor > 0 &&
		(tokens[cursor-1].text == "." || tokens[cursor-1].text == "?.") {
		return javaScriptFeatureObservation{}, false, false
	}
	next := tokens[cursor+1]
	if next.text == "(" {
		if !allowDynamic ||
			!javaScriptFeatureDynamicImportPrefix(tokens, cursor) {
			return javaScriptFeatureObservation{}, false, false
		}
		close, ok := matches[cursor+1]
		if !ok ||
			!javaScriptFeatureQuotedToken(tokens[cursor+2]) ||
			!javaScriptFeatureDynamicImportTail(tokens, matches, cursor+1, close) ||
			!javaScriptFeatureCallResultUsage(tokens, close) {
			return javaScriptFeatureObservation{}, false, false
		}
		value, exact, overlong := exactJavaScriptFeatureLiteral(tokens[cursor+2].text)
		if !exact || value == "" {
			return javaScriptFeatureObservation{}, false, overlong
		}
		return javaScriptFeatureObservation{
			key: javaScriptModuleSpecifierFeatureKey, value: value,
			form: "dynamic-import", family: javaScriptFeatureFamilyModule,
			offset: tokens[cursor+2].start, line: tokens[cursor+2].line,
		}, true, false
	}
	if token.depth != 0 ||
		next.text == "." ||
		!javaScriptFeatureStaticImportPrefix(tokens, cursor) {
		return javaScriptFeatureObservation{}, false, false
	}
	var literal int
	if javaScriptFeatureQuotedToken(next) {
		literal = cursor + 1
	} else {
		literal = javaScriptStaticImportSpecifierToken(
			tokens,
			matches,
			cursor,
		)
	}
	if literal < 0 ||
		!javaScriptFeatureImportTerminates(tokens, matches, literal, token.depth) {
		return javaScriptFeatureObservation{}, false, false
	}
	value, exact, overlong := exactJavaScriptFeatureLiteral(tokens[literal].text)
	if !exact || value == "" {
		return javaScriptFeatureObservation{}, false, overlong
	}
	return javaScriptFeatureObservation{
		key: javaScriptModuleSpecifierFeatureKey, value: value,
		form: "esm-import", family: javaScriptFeatureFamilyModule,
		offset: tokens[literal].start, line: tokens[literal].line,
	}, true, false
}

func javaScriptFeatureStaticImportPrefix(
	tokens []javaScriptFeatureToken,
	cursor int,
) bool {
	if cursor <= 0 {
		return true
	}
	previous := tokens[cursor-1]
	if previous.line == tokens[cursor].line {
		return previous.text == ";"
	}
	switch previous.text {
	case "(", "[", "{", ",", ":", "?", "=", "+=", "-=", "*=", "/=",
		"%=", "**=", "&&=", "||=", "??=", "=>", ".", "?.", ")", "await",
		"case", "default", "delete", "do", "else", "export", "for", "if",
		"new", "return", "throw", "typeof", "void", "while", "with", "yield":
		return false
	default:
		return true
	}
}

func javaScriptReExportObservation(
	tokens []javaScriptFeatureToken,
	matches map[int]int,
	cursor int,
) (javaScriptFeatureObservation, bool, bool) {
	if cursor < 0 ||
		cursor+1 >= len(tokens) ||
		tokens[cursor].text != "export" ||
		tokens[cursor].depth != 0 ||
		!javaScriptFeatureStaticImportPrefix(tokens, cursor) ||
		cursor > 0 && (tokens[cursor-1].text == "." ||
			tokens[cursor-1].text == "?.") {
		return javaScriptFeatureObservation{}, false, false
	}
	position := cursor + 1
	switch tokens[position].text {
	case "*":
		position++
		if position < len(tokens) && tokens[position].text == "as" {
			if position+1 >= len(tokens) ||
				tokens[position+1].kind != javaScriptSyntaxIdentifier {
				return javaScriptFeatureObservation{}, false, false
			}
			position += 2
		}
	case "{":
		close, ok := matches[position]
		if !ok ||
			!validJavaScriptNamedReExportTokens(tokens, position, close) {
			return javaScriptFeatureObservation{}, false, false
		}
		position = close + 1
	default:
		return javaScriptFeatureObservation{}, false, false
	}
	if position+1 >= len(tokens) ||
		tokens[position].text != "from" ||
		!javaScriptFeatureQuotedToken(tokens[position+1]) ||
		!javaScriptFeatureImportTerminates(
			tokens,
			matches,
			position+1,
			tokens[cursor].depth,
		) {
		return javaScriptFeatureObservation{}, false, false
	}
	literal := tokens[position+1]
	value, exact, overlong := exactJavaScriptFeatureLiteral(literal.text)
	if !exact || value == "" {
		return javaScriptFeatureObservation{}, false, overlong
	}
	return javaScriptFeatureObservation{
		key: javaScriptModuleSpecifierFeatureKey, value: value,
		form: "esm-re-export", family: javaScriptFeatureFamilyModule,
		offset: literal.start, line: literal.line,
	}, true, false
}

func validJavaScriptNamedReExportTokens(
	tokens []javaScriptFeatureToken,
	open, close int,
) bool {
	if open < 0 || close <= open || close >= len(tokens) {
		return false
	}
	expectItem := true
	sawItem := false
	exportedNames := map[string]bool{}
	for position := open + 1; position < close; {
		token := tokens[position]
		if token.depth != tokens[open].depth+1 {
			return false
		}
		if !expectItem {
			if token.text != "," {
				return false
			}
			expectItem = true
			position++
			continue
		}
		quoted := javaScriptFeatureQuotedToken(token)
		if token.kind != javaScriptSyntaxIdentifier && !quoted {
			return false
		}
		sawItem = true
		exportedName, ok := javaScriptFeatureModuleName(token)
		if !ok {
			return false
		}
		position++
		if position < close && tokens[position].text == "as" {
			if position+1 >= close ||
				(tokens[position+1].kind != javaScriptSyntaxIdentifier &&
					!javaScriptFeatureQuotedToken(tokens[position+1])) {
				return false
			}
			exportedName, ok = javaScriptFeatureModuleName(tokens[position+1])
			if !ok {
				return false
			}
			position += 2
		} else if quoted {
			return false
		}
		if exportedNames[exportedName] {
			return false
		}
		exportedNames[exportedName] = true
		expectItem = false
	}
	return !sawItem || !expectItem || tokens[close-1].text == ","
}

func javaScriptFeatureDynamicImportPrefix(
	tokens []javaScriptFeatureToken,
	cursor int,
) bool {
	if cursor <= 0 {
		return true
	}
	previous := tokens[cursor-1]
	if previous.line < tokens[cursor].line {
		return previous.text != "new" && previous.text != "throw"
	}
	switch previous.text {
	case "(", "[", "{", ",", ":", "?", "=", "+=", "-=", "*=",
		"%=", "**=", "&&=", "||=", "??=", "+", "-", "*", "%",
		"**", "&&", "||", "??", "==", "===", "!=", "!==", "<", ">",
		"<=", ">=", "<<", ">>", ">>>", "&", "|", "^", "!", "~", "=>",
		";", "await", "case", "return", "throw", "void", "yield":
		return true
	default:
		return false
	}
}

func javaScriptStaticImportSpecifierToken(
	tokens []javaScriptFeatureToken,
	matches map[int]int,
	cursor int,
) int {
	position := cursor + 1
	if position >= len(tokens) {
		return -1
	}
	boundNames := map[string]bool{}
	// Optional default binding.
	parseNamedOrNamespace := true
	if javaScriptFeatureBindingIdentifier(tokens[position]) {
		boundNames[tokens[position].text] = true
		position++
		if position < len(tokens) && tokens[position].text == "," {
			position++
		} else {
			parseNamedOrNamespace = false
		}
	}
	if position >= len(tokens) {
		return -1
	}
	if parseNamedOrNamespace {
		switch tokens[position].text {
		case "*":
			if position+2 >= len(tokens) ||
				tokens[position+1].text != "as" ||
				!javaScriptFeatureBindingIdentifier(tokens[position+2]) {
				return -1
			}
			if boundNames[tokens[position+2].text] {
				return -1
			}
			boundNames[tokens[position+2].text] = true
			position += 3
		case "{":
			close, ok := matches[position]
			if !ok ||
				!validJavaScriptNamedImportTokens(
					tokens,
					position,
					close,
					boundNames,
				) {
				return -1
			}
			position = close + 1
		default:
			return -1
		}
	}
	if position+1 >= len(tokens) ||
		tokens[position].text != "from" ||
		!javaScriptFeatureQuotedToken(tokens[position+1]) {
		return -1
	}
	return position + 1
}

func validJavaScriptNamedImportTokens(
	tokens []javaScriptFeatureToken,
	open, close int,
	boundNames map[string]bool,
) bool {
	if open < 0 || close <= open || close >= len(tokens) ||
		boundNames == nil {
		return false
	}
	expectItem := true
	sawItem := false
	for position := open + 1; position < close; {
		token := tokens[position]
		if token.depth != tokens[open].depth+1 {
			return false
		}
		if !expectItem {
			if token.text != "," {
				return false
			}
			expectItem = true
			position++
			continue
		}
		quoted := javaScriptFeatureQuotedToken(token)
		if token.kind != javaScriptSyntaxIdentifier && !quoted {
			return false
		}
		sawItem = true
		boundName := token.text
		position++
		if position < close && tokens[position].text == "as" {
			if position+1 >= close ||
				!javaScriptFeatureBindingIdentifier(tokens[position+1]) {
				return false
			}
			boundName = tokens[position+1].text
			position += 2
		} else if quoted || !javaScriptFeatureBindingIdentifier(token) {
			return false
		}
		if boundNames[boundName] {
			return false
		}
		boundNames[boundName] = true
		expectItem = false
	}
	return !sawItem || !expectItem || tokens[close-1].text == ","
}

func javaScriptFeatureImportTerminates(
	tokens []javaScriptFeatureToken,
	matches map[int]int,
	literal int,
	depth int,
) bool {
	end := literal
	next := javaScriptFeatureNextTokenAtDepth(tokens, end+1, depth)
	if next < len(tokens) &&
		(tokens[next].text == "with" || tokens[next].text == "assert") {
		open := javaScriptFeatureNextTokenAtDepth(tokens, next+1, depth)
		close, ok := matches[open]
		if open >= len(tokens) ||
			tokens[open].text != "{" ||
			!ok ||
			!validJavaScriptImportAttributes(tokens, open, close) {
			return false
		}
		end = close
	}
	for index := end + 1; index < len(tokens); index++ {
		if tokens[index].depth != depth {
			continue
		}
		if tokens[index].text == ";" {
			return true
		}
		return tokens[index].line > tokens[end].line
	}
	return true
}

func javaScriptFeatureDynamicImportTail(
	tokens []javaScriptFeatureToken,
	matches map[int]int,
	open, close int,
) bool {
	literal := open + 1
	if literal >= close {
		return false
	}
	if close == literal+1 {
		return true
	}
	if tokens[literal+1].text != "," {
		return false
	}
	if close == literal+2 {
		return true
	}
	optionsOpen := literal + 2
	optionsClose, ok := matches[optionsOpen]
	return ok &&
		tokens[optionsOpen].text == "{" &&
		optionsClose == close-1 &&
		validJavaScriptDynamicImportOptions(
			tokens,
			matches,
			optionsOpen,
			optionsClose,
		)
}

func validJavaScriptImportAttributes(
	tokens []javaScriptFeatureToken,
	open, close int,
) bool {
	if open < 0 || close <= open || close >= len(tokens) {
		return false
	}
	expectItem := true
	sawItem := false
	attributeKeys := map[string]bool{}
	for position := open + 1; position < close; {
		token := tokens[position]
		if token.depth != tokens[open].depth+1 {
			return false
		}
		if !expectItem {
			if token.text != "," {
				return false
			}
			expectItem = true
			position++
			continue
		}
		if token.kind != javaScriptSyntaxIdentifier &&
			!javaScriptFeatureQuotedToken(token) {
			return false
		}
		key, ok := javaScriptFeatureModuleName(token)
		if !ok || attributeKeys[key] {
			return false
		}
		attributeKeys[key] = true
		if position+2 >= close ||
			tokens[position+1].text != ":" ||
			tokens[position+1].depth != token.depth ||
			!javaScriptFeatureQuotedToken(tokens[position+2]) ||
			tokens[position+2].depth != token.depth {
			return false
		}
		sawItem = true
		expectItem = false
		position += 3
	}
	return !sawItem || !expectItem || tokens[close-1].text == ","
}

func validJavaScriptDynamicImportOptions(
	tokens []javaScriptFeatureToken,
	matches map[int]int,
	open, close int,
) bool {
	if open < 0 || close <= open || close >= len(tokens) {
		return false
	}
	expectItem := true
	sawItem := false
	for position := open + 1; position < close; {
		token := tokens[position]
		if token.depth != tokens[open].depth+1 {
			return false
		}
		if !expectItem {
			if token.text != "," {
				return false
			}
			expectItem = true
			position++
			continue
		}
		if token.text != "with" && token.text != "assert" {
			return false
		}
		if position+2 >= close ||
			tokens[position+1].text != ":" ||
			tokens[position+1].depth != token.depth ||
			tokens[position+2].text != "{" {
			return false
		}
		attributesClose, ok := matches[position+2]
		if !ok ||
			attributesClose >= close ||
			!validJavaScriptImportAttributes(
				tokens,
				position+2,
				attributesClose,
			) {
			return false
		}
		sawItem = true
		expectItem = false
		position = attributesClose + 1
	}
	return !sawItem || !expectItem || tokens[close-1].text == ","
}

func javaScriptFeatureCallResultUsage(
	tokens []javaScriptFeatureToken,
	close int,
) bool {
	if close < 0 || close >= len(tokens) {
		return false
	}
	if close+1 >= len(tokens) {
		return true
	}
	current := tokens[close]
	next := tokens[close+1]
	if next.depth < current.depth {
		return true
	}
	if next.depth != current.depth ||
		javaScriptSyntaxAssignmentToken(next.text) ||
		next.text == "++" ||
		next.text == "--" ||
		next.text == "=>" {
		return false
	}
	switch next.text {
	case ";", ",", ")", "]", "}", ".", "?.", "[", "(", "?", ":",
		"+", "-", "*", "/", "%", "**", "&&", "||", "??", "==", "===",
		"!=", "!==", "<", ">", "<=", ">=", "<<", ">>", ">>>", "&", "|",
		"^", "in", "instanceof", "`":
		return true
	}
	// Automatic semicolon insertion can separate a completed import()
	// expression from the next statement. Same-line adjacent values cannot.
	return next.line > current.line
}

func javaScriptFeatureNextTokenAtDepth(
	tokens []javaScriptFeatureToken,
	start, depth int,
) int {
	for index := max(start, 0); index < len(tokens); index++ {
		if tokens[index].depth == depth {
			return index
		}
	}
	return len(tokens)
}

func javaScriptRequireObservation(
	tokens []javaScriptFeatureToken,
	matches map[int]int,
	cursor int,
) (javaScriptFeatureObservation, bool, bool) {
	if cursor < 0 || cursor+3 >= len(tokens) ||
		tokens[cursor].text != "require" ||
		tokens[cursor+1].text != "(" ||
		!javaScriptFeatureQuotedToken(tokens[cursor+2]) {
		return javaScriptFeatureObservation{}, false, false
	}
	if cursor > 0 && (tokens[cursor-1].text == "." ||
		tokens[cursor-1].text == "?." ||
		javaScriptFeatureNonKeywordIdentifier(tokens[cursor-1])) {
		return javaScriptFeatureObservation{}, false, false
	}
	close, ok := matches[cursor+1]
	if !ok ||
		(close != cursor+3 &&
			(close != cursor+4 || tokens[cursor+3].text != ",")) ||
		!javaScriptFeatureCallResultUsage(tokens, close) {
		return javaScriptFeatureObservation{}, false, false
	}
	value, exact, overlong := exactJavaScriptFeatureLiteral(tokens[cursor+2].text)
	if !exact || value == "" {
		return javaScriptFeatureObservation{}, false, overlong
	}
	return javaScriptFeatureObservation{
		key: javaScriptModuleSpecifierFeatureKey, value: value,
		form: "commonjs-require", family: javaScriptFeatureFamilyModule,
		offset: tokens[cursor+2].start, line: tokens[cursor+2].line,
	}, true, false
}

func javaScriptFeatureQuotedToken(token javaScriptFeatureToken) bool {
	return token.kind == javaScriptSyntaxToken &&
		len(token.text) >= 2 &&
		(token.text[0] == '\'' || token.text[0] == '"')
}

func javaScriptFeatureModuleName(
	token javaScriptFeatureToken,
) (string, bool) {
	if token.kind == javaScriptSyntaxIdentifier {
		return token.text, true
	}
	if !javaScriptFeatureQuotedToken(token) {
		return "", false
	}
	value, exact, overlong := exactJavaScriptFeatureLiteral(token.text)
	return value, exact && !overlong
}

func javaScriptFeatureNonKeywordIdentifier(token javaScriptFeatureToken) bool {
	return token.kind == javaScriptSyntaxIdentifier &&
		!javaScriptSyntaxKeyword(token.text)
}

func javaScriptFeatureBindingIdentifier(token javaScriptFeatureToken) bool {
	if token.kind != javaScriptSyntaxIdentifier {
		return false
	}
	switch token.text {
	case "arguments", "await", "break", "case", "catch", "class", "const",
		"continue", "debugger", "default", "delete", "do", "else", "enum",
		"eval", "export", "extends", "false", "finally", "for", "function",
		"if", "implements", "import", "in", "instanceof", "interface", "let",
		"new", "null", "package", "private", "protected", "public", "return",
		"super", "switch", "this", "throw", "true", "try", "typeof", "var",
		"void", "while", "with", "yield":
		return false
	default:
		return true
	}
}

func exactJavaScriptFeatureLiteral(token string) (string, bool, bool) {
	if len(token) < 2 ||
		(token[0] != '\'' && token[0] != '"') ||
		token[len(token)-1] != token[0] {
		return "", false, false
	}
	if len(token)-2 > maxJavaScriptFeatureValueBytes {
		return "", false, true
	}
	body := token[1 : len(token)-1]
	if !utf8.ValidString(body) ||
		strings.ContainsAny(body, "\\\r\n\x00") {
		return "", false, false
	}
	return body, true, false
}

func javaScriptFeatureOverlongLiteralCandidate(token string) bool {
	if len(token) < 2 {
		return false
	}
	body := token[1 : len(token)-1]
	for _, prefix := range []string{
		"http://",
		"https://",
		"ws://",
		"wss://",
		"ftp://",
		"/",
		"~/",
		"./",
		"../",
		"$home/",
		"${home}/",
		"library/",
		".ssh/",
		".aws/",
		".config/",
		".docker/",
	} {
		if len(body) >= len(prefix) &&
			strings.EqualFold(body[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

func exactJavaScriptFeatureURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" ||
		parsed.Hostname() == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "ws", "wss", "ftp":
		return true
	default:
		return false
	}
}

func exactJavaScriptSensitiveResource(
	value string,
) (behavior.Resource, bool) {
	if value == "" || strings.TrimSpace(value) != value {
		return behavior.Resource{}, false
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" {
		return behavior.Resource{}, false
	}
	if !javaScriptSensitiveLiteralShape(value) {
		return behavior.Resource{}, false
	}
	resource, ok := sensitiveResource(value)
	if !ok ||
		resource.Value != value ||
		sensitiveResourceFeatureCategory(resource) == "" ||
		!javaScriptSensitiveCategoryPathAnchored(
			strings.ToLower(value),
			sensitiveResourceFeatureCategory(resource),
		) {
		return behavior.Resource{}, false
	}
	return resource, true
}

// JavaScriptSensitiveLiteralCategory applies the exact closed classifier used
// by the JavaScript lexical Feature lane. Report loading reuses it so accepted
// saved facts cannot drift from extraction semantics.
func JavaScriptSensitiveLiteralCategory(value string) (string, bool) {
	resource, ok := exactJavaScriptSensitiveResource(value)
	if !ok {
		return "", false
	}
	category := sensitiveResourceFeatureCategory(resource)
	return category, category != ""
}

func javaScriptSensitiveLiteralShape(value string) bool {
	lower := strings.ToLower(value)
	switch lower {
	case ".npmrc", ".pypirc", "github_token":
		return true
	}
	for _, prefix := range []string{
		"/",
		"~/",
		"./",
		"../",
		"$home/",
		"${home}/",
		"library/",
		".ssh/",
		".aws/",
		".config/",
		".docker/",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func javaScriptSensitiveCategoryPathAnchored(
	lower, category string,
) bool {
	var markers []string
	switch category {
	case "browser.cookies":
		markers = []string{
			"library/application support/google/chrome",
			"library/application support/firefox/profiles",
		}
	case "browser.password-store":
		markers = []string{
			"library/application support/google/chrome",
		}
	case "cloud-credentials":
		markers = []string{
			".aws/credentials",
			".config/gcloud",
			".docker/config.json",
		}
	case "crypto-wallet":
		markers = []string{
			"library/application support/exodus",
			"library/application support/electrum",
			".electrum",
			"library/application support/ledger live",
			"library/application support/metamask",
			"library/containers/io.metamask",
			".metamask",
		}
	case "developer-token":
		if lower == "github_token" {
			return true
		}
		markers = []string{".npmrc", ".pypirc"}
	case "keychain":
		markers = []string{"library/keychains", "login.keychain-db"}
	case "ssh-private-key":
		markers = []string{".ssh/id_rsa", ".ssh/id_ed25519"}
	default:
		return false
	}
	for _, marker := range markers {
		if javaScriptSensitivePathMarker(lower, marker) {
			return true
		}
	}
	return false
}

func javaScriptSensitivePathMarker(value, marker string) bool {
	for start := 0; start <= len(value)-len(marker); {
		relative := strings.Index(value[start:], marker)
		if relative < 0 {
			return false
		}
		index := start + relative
		if index == 0 || value[index-1] == '/' {
			return true
		}
		start = index + 1
	}
	return false
}

func javaScriptFeatureScopeKeysByLine(
	index javaScriptStructuralIndex,
) map[int]javaScriptFeatureLineScope {
	out := map[int]javaScriptFeatureLineScope{}
	if index.Disposition == javaScriptStructuralLimited ||
		index.Disposition == javaScriptStructuralMalformed {
		return out
	}
	scopeSets := map[int]map[string]bool{}
	for _, statement := range index.Statements {
		for line := statement.StartLine; line <= statement.EndLine; line++ {
			if scopeSets[line] == nil {
				scopeSets[line] = map[string]bool{}
			}
			scopeSets[line][statement.ScopeKey] = true
		}
	}
	for _, line := range index.Lines {
		if line.Line <= 0 ||
			line.Disposition != javaScriptLineDirect ||
			len(scopeSets[line.Line]) != 1 {
			continue
		}
		out[line.Line] = javaScriptFeatureLineScope{
			key: line.ScopeKey, scoped: true,
		}
	}
	return out
}

type javaScriptFeatureScopeIdentity struct {
	nodeID   string
	function string
}

type javaScriptFeatureScopeCandidate struct {
	id        string
	lineStart int
	lineEnd   int
}

func javaScriptFeatureScopes(
	graph *behavior.Graph,
) map[javaScriptFeatureScopeIdentity][]javaScriptFeatureScopeCandidate {
	out := map[javaScriptFeatureScopeIdentity][]javaScriptFeatureScopeCandidate{}
	for _, scope := range graph.Scopes {
		if scope.Kind != "function" ||
			scope.NodeID == "" ||
			scope.Function == "" ||
			scope.LineStart <= 0 {
			continue
		}
		identity := javaScriptFeatureScopeIdentity{
			nodeID: scope.NodeID, function: scope.Function,
		}
		out[identity] = append(out[identity], javaScriptFeatureScopeCandidate{
			id: scope.ID, lineStart: scope.LineStart, lineEnd: scope.LineEnd,
		})
	}
	return out
}

func javaScriptFeatureScopesByKey(
	index javaScriptStructuralIndex,
) map[string]javaScriptStructuralScope {
	out := make(map[string]javaScriptStructuralScope, len(index.Scopes))
	for _, scope := range index.Scopes {
		if scope.Key != "" {
			out[scope.Key] = scope
		}
	}
	return out
}

func javaScriptObservationScope(
	_ *behavior.Graph,
	content artifact.Content,
	observation javaScriptFeatureObservation,
	scopesByKey map[string]javaScriptStructuralScope,
	scopeIDs map[string]string,
	existing map[javaScriptFeatureScopeIdentity][]javaScriptFeatureScopeCandidate,
) (string, string) {
	if !observation.scoped {
		return "", ""
	}
	if observation.scopeKey == "" {
		return content.ScopeID, ""
	}
	descriptor, found := scopesByKey[observation.scopeKey]
	if !found || descriptor.Name == "" {
		return "", ""
	}
	if scopeID := scopeIDs[descriptor.Key]; scopeID != "" {
		return scopeID, descriptor.Name
	}
	identity := javaScriptFeatureScopeIdentity{
		nodeID: content.NodeID, function: descriptor.Name,
	}
	scopeID := ""
	for _, candidate := range existing[identity] {
		if candidate.lineStart < descriptor.StartLine ||
			candidate.lineStart > descriptor.EndLine ||
			candidate.lineEnd > descriptor.EndLine {
			continue
		}
		if scopeID != "" {
			return "", ""
		}
		scopeID = candidate.id
	}
	if scopeID != "" {
		scopeIDs[descriptor.Key] = scopeID
		return scopeID, descriptor.Name
	}
	// The low-priority inventory must not manufacture new semantic scopes.
	// If higher-priority extraction did not retain this exact function scope,
	// keep the observation node-located and unusable by scoped rule joins.
	return "", ""
}

func javaScriptFeatureEvidenceKind(
	observation javaScriptFeatureObservation,
) string {
	switch observation.key {
	case javaScriptModuleSpecifierFeatureKey:
		return "javascript-module-specifier"
	case "network.url":
		return "javascript-url-literal"
	default:
		return "javascript-sensitive-resource-literal"
	}
}

func (limits *javaScriptFeatureInventoryLimits) retain(
	graph *behavior.Graph,
	nodeID string,
	observation javaScriptFeatureObservation,
) bool {
	lineCounts := limits.line[observation.family]
	if lineCounts == nil {
		lineCounts = map[int]int{}
		limits.line[observation.family] = lineCounts
	}
	if lineCounts[observation.line] >= maxJavaScriptFeatureValuesPerLine {
		limits.report(
			graph,
			nodeID,
			observation.family+"-line",
			fmt.Sprintf(
				"JavaScript %s Feature limit %d reached on one physical line; additional observations on that line were not inventoried",
				observation.family,
				maxJavaScriptFeatureValuesPerLine,
			),
		)
		return false
	}
	_, inspectionLimit := javaScriptFeatureFamilyLimits(observation.family)
	if limits.inspection[observation.family] >= inspectionLimit {
		limits.report(
			graph,
			nodeID,
			observation.family+"-inspection",
			fmt.Sprintf(
				"JavaScript %s Feature limit %d reached for inspection; additional observations of that family were not inventoried",
				observation.family,
				inspectionLimit,
			),
		)
		return false
	}
	lineCounts[observation.line]++
	limits.inspection[observation.family]++
	return true
}

func (limits *javaScriptFeatureInventoryLimits) report(
	graph *behavior.Graph,
	nodeID, key, detail string,
) {
	if limits.reported[key] {
		return
	}
	limits.reported[key] = true
	addPartialCoverageOnce(
		graph,
		nodeID,
		javaScriptFeatureAnalysisArea,
		detail,
	)
}

func javaScriptFeatureFamilyLimits(family string) (int, int) {
	switch family {
	case javaScriptFeatureFamilyModule:
		return maxJavaScriptModuleSpecifiersPerNode, maxJavaScriptModuleSpecifiersTotal
	case javaScriptFeatureFamilyURL:
		return maxJavaScriptURLsPerNode, maxJavaScriptURLsTotal
	default:
		return maxJavaScriptSensitivePathsPerNode, maxJavaScriptSensitivePathsTotal
	}
}

func javaScriptObservationalFeatureKey(key string) bool {
	return key == javaScriptModuleSpecifierFeatureKey
}

func observationalSourceFeatureKey(key string) bool {
	return pythonObservationalFeatureKey(key) ||
		javaScriptObservationalFeatureKey(key)
}

func observationalSourceFeatures(
	graph *behavior.Graph,
) []bool {
	lexicalEvidence := make(map[string]bool, len(graph.Evidence))
	for _, evidence := range graph.Evidence {
		if evidence.Method == "python-lexical" ||
			evidence.Method == "javascript-lexical" {
			lexicalEvidence[evidence.ID] = true
		}
	}
	out := make([]bool, len(graph.Features))
	for index, feature := range graph.Features {
		if observationalSourceFeatureKey(feature.Key) {
			out[index] = true
			continue
		}
		for _, evidenceID := range feature.EvidenceIDs {
			if lexicalEvidence[evidenceID] {
				out[index] = true
				break
			}
		}
	}
	return out
}
