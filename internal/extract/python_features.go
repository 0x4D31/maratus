package extract

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxPythonFeatureObservationsPerLine       = 64
	maxPythonFeatureObservationsPerNode       = 2048
	maxPythonFeatureObservationsPerInspection = 4096
	maxPythonQualifiedCallComponents          = 32
	maxPythonQualifiedCallBytes               = 1024
)

const pythonFeatureAnalysisArea = "python-feature-analysis"

type pythonSourceObservation struct {
	key        string
	value      string
	form       string
	alias      string
	byteOffset int
}

type pythonImportDisposition uint8

const (
	pythonImportAbsent pythonImportDisposition = iota
	pythonImportRecognized
	pythonImportUnsupported
	pythonImportMalformed
)

type pythonImportResult struct {
	disposition  pythonImportDisposition
	observations []pythonSourceObservation
	total        int
	continued    bool
	reason       string
}

// addPythonSourceFeatures is intentionally a late, observational pass. It runs
// only over nodes already selected for analysis and never creates operations,
// execution roots, invoked targets, relations, or capability matches.
func addPythonSourceFeatures(graph *behavior.Graph, contents []artifact.Content) {
	selected := make(map[string]bool, len(graph.AnalysisSelections))
	for _, selection := range graph.AnalysisSelections {
		selected[selection.NodeID] = true
	}
	enforceSelection := len(graph.AnalysisSelections) > 0

	candidates := make([]artifact.Content, 0, len(contents))
	for _, content := range contents {
		if enforceSelection && !selected[content.NodeID] ||
			content.RawFeaturesOnly ||
			content.MediaType != "text/plain" ||
			contentLanguage(content) != "python" ||
			!behaviorSourceRoleAllowed(content.Role, content.BehaviorAnalysisForced) ||
			!semanticTextAllowed(content, "python") {
			continue
		}
		candidates = append(candidates, content)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].NodeID != candidates[j].NodeID {
			return candidates[i].NodeID < candidates[j].NodeID
		}
		if candidates[i].LogicalPath != candidates[j].LogicalPath {
			return candidates[i].LogicalPath < candidates[j].LogicalPath
		}
		return candidates[i].Architecture < candidates[j].Architecture
	})

	existingScopes := pythonFunctionScopes(graph)
	inspectionCount := 0
	for _, content := range candidates {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			break
		}
		stopped := addPythonContentFeatures(graph, content, existingScopes, &inspectionCount)
		if stopped {
			break
		}
	}
}

func addPythonContentFeatures(
	graph *behavior.Graph,
	content artifact.Content,
	existingScopes map[pythonFunctionScopeIdentity]string,
	inspectionCount *int,
) bool {
	input := boundedText(content.Data)
	if input.truncated() {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			pythonFeatureAnalysisArea,
			"Python Feature inventory was limited by retained text bytes, lines, or physical-line length; the omitted source was not inventoried",
		)
	}

	multiline := maskPythonMultilineStrings(input.Lines)
	switch {
	case multiline.formattedExpression:
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			pythonFeatureAnalysisArea,
			"formatted or template triple-quoted string encountered; embedded expressions and the masked source suffix were not inventoried",
		)
	case multiline.limited:
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			pythonFeatureAnalysisArea,
			fmt.Sprintf(
				"triple-quoted string masking limit reached (%d lines or %d bytes); the masked source suffix was not inventoried",
				maxPythonMultilineStringLines,
				maxPythonMultilineStringBytes,
			),
		)
	case multiline.unterminated:
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			pythonFeatureAnalysisArea,
			"unterminated triple-quoted string reached the retained source boundary; its contents and the masked source suffix were not inventoried",
		)
	}

	lineOffsets := pythonPhysicalLineOffsets(input.Source, len(input.Lines))
	scopeIDs := map[string]string{}
	var lexical pythonLexicalScopeState
	var stringState pythonOrdinaryStringState
	var importContinuation pythonImportContinuationState
	nodeCount := 0

	for index := 0; index < len(multiline.lines); index++ {
		lineNo := index + 1
		if pythonPhysicalLineTruncated(input, index, lineOffsets) {
			// The omitted suffix could change string continuation, bracket
			// balance, or lexical scope. Keep observations from earlier complete
			// lines, but do not infer through this boundary.
			return false
		}
		masked, stringResult := maskPythonOrdinaryStringsAndComments(multiline.lines[index], &stringState)
		if stringResult.malformed {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonFeatureAnalysisArea,
				"malformed ordinary Python string reached a physical-line boundary; the remainder of the affected physical line was not inventoried",
			)
		}
		if stringResult.formatted {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonFeatureAnalysisArea,
				"formatted or template string expressions are not parsed; the remainder of the affected physical line was not inventoried",
			)
		}

		trimmed := strings.TrimSpace(masked)
		if stringResult.stop {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonFeatureAnalysisArea,
				"a backslash-continued formatted or template string was not parsed; the remaining source was not inventoried",
			)
			return false
		}
		if importContinuation.active {
			if importContinuation.consume(masked) {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					pythonFeatureAnalysisArea,
					fmt.Sprintf(
						"Python import continuation exceeded %d lines or %d bytes; remaining Feature inventory was not inferred",
						maxSemanticContinuationLines,
						maxSemanticContinuationBytes,
					),
				)
				return false
			}
			continue
		}
		if stringResult.malformed {
			if pythonPossibleDeclarationPrefix(trimmed) {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					pythonFeatureAnalysisArea,
					"a malformed string occurred in a possible Python declaration header; the remaining source was not inventoried because lexical scope could not be established",
				)
				return false
			}
			continue
		}
		if trimmed == "" {
			continue
		}
		if pythonContainsNonASCII(masked) {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonFeatureAnalysisArea,
				"non-ASCII Python identifier syntax is outside the bounded ASCII Feature inventory",
			)
			if pythonPossibleDeclarationPrefix(trimmed) {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					pythonFeatureAnalysisArea,
					"non-ASCII syntax occurred in a possible Python declaration header; the remaining source was not inventoried because lexical scope could not be established",
				)
				return false
			}
			continue
		}
		if pythonUnsupportedAsyncContinuation(trimmed) {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonFeatureAnalysisArea,
				"an explicit Python continuation after async was not parsed; remaining Feature inventory was not inferred because declaration scope could not be established",
			)
			return false
		}

		rawForScope, declarationForScope, declarationEnd, declarationIncomplete :=
			joinPythonLexicalDeclaration(multiline.lines, index, masked, trimmed, nil)
		if declarationIncomplete {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonFeatureAnalysisArea,
				fmt.Sprintf(
					"Python declaration header exceeded %d lines or %d bytes; remaining Feature inventory was not inferred",
					maxSemanticContinuationLines,
					maxSemanticContinuationBytes,
				),
			)
			return false
		}
		if pythonPossibleDeclarationPrefix(trimmed) && !pythonBoundedDeclarationHeaderValid(declarationForScope) {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonFeatureAnalysisArea,
				"a possible Python declaration header was malformed or outside the bounded grammar; remaining Feature inventory was not inferred because lexical scope could not be established",
			)
			return false
		}
		lexicalObservation := lexical.observe(rawForScope, declarationForScope, lineNo)
		if lexical.limited {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonFeatureAnalysisArea,
				fmt.Sprintf("Python lexical scope depth limit %d reached; remaining Feature inventory was not inferred", maxPythonLexicalScopeDepth),
			)
			return false
		}

		scopeID := content.ScopeID
		sourceFunction := lexicalObservation.function.name
		if sourceFunction != "" {
			scopeID = pythonFeatureScope(
				graph,
				content,
				lexicalObservation.function,
				lineNo,
				declarationEnd+1,
				scopeIDs,
				existingScopes,
			)
			if scopeID == "" {
				graph.MarkWorkOmitted()
				return true
			}
		}

		if lexicalObservation.declaration.name != "" {
			if suite, ok := pythonSameLineSuite(declarationForScope); ok && pythonSuiteMayContainFeature(suite) {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					pythonFeatureAnalysisArea,
					"Python statements in a same-line declaration suite were not inventoried because declaration-suite execution is outside the bounded grammar",
				)
			} else if calls, limited := pythonQualifiedCalls(declarationForScope, 1); len(calls) > 0 || limited {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					pythonFeatureAnalysisArea,
					"qualified calls in Python declaration headers, defaults, or base expressions were not inventoried",
				)
			}
			index = declarationEnd
			continue
		}

		if lexicalObservation.classBody {
			if pythonLineMayContainFeature(masked) {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					pythonFeatureAnalysisArea,
					"direct Python class-body import and qualified-call observations were suppressed because class execution and namespace semantics are not modeled",
				)
			}
			continue
		}

		if suite, ok := pythonSameLineSuite(masked); ok && pythonSuiteContainsImport(suite) {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonFeatureAnalysisArea,
				"Python imports in same-line compound-statement suites are outside the closed import grammar",
			)
		}

		importResult := parsePythonImportLine(masked)
		switch importResult.disposition {
		case pythonImportRecognized:
			if retainPythonObservations(
				graph,
				content,
				scopeID,
				sourceFunction,
				lineNo,
				lineOffsets[index],
				importResult.observations,
				importResult.total,
				&nodeCount,
				inspectionCount,
			) {
				return true
			}
		case pythonImportUnsupported:
			detail := importResult.reason
			if detail == "" {
				detail = "the Python import used syntax outside the closed single-physical-line grammar"
			}
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonFeatureAnalysisArea,
				detail,
			)
			if importResult.continued {
				importContinuation.start(masked)
			}
		case pythonImportMalformed:
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonFeatureAnalysisArea,
				"a Python import statement was malformed or outside the closed import grammar; no import Feature was emitted for it",
			)
		case pythonImportAbsent:
			calls, limited := pythonQualifiedCalls(masked, maxPythonFeatureObservationsPerLine+1)
			if limited {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					pythonFeatureAnalysisArea,
					fmt.Sprintf(
						"a qualified-call name exceeded %d components or %d bytes and was not inventoried",
						maxPythonQualifiedCallComponents,
						maxPythonQualifiedCallBytes,
					),
				)
			}
			if retainPythonObservations(
				graph,
				content,
				scopeID,
				sourceFunction,
				lineNo,
				lineOffsets[index],
				calls,
				len(calls),
				&nodeCount,
				inspectionCount,
			) {
				return true
			}
		}

		if nodeCount >= maxPythonFeatureObservationsPerNode {
			if pythonRemainingPhysicalSource(multiline.lines, index+1) {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					pythonFeatureAnalysisArea,
					fmt.Sprintf("Python Feature observation limit %d reached for node; remaining source was not inventoried", maxPythonFeatureObservationsPerNode),
				)
			}
			return false
		}
	}

	if stringState.quote != 0 {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			pythonFeatureAnalysisArea,
			"a backslash-continued ordinary Python string reached the retained source boundary; its contents were not inventoried",
		)
	}
	if importContinuation.active {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			pythonFeatureAnalysisArea,
			"a continued Python import reached the retained source boundary; its remaining physical lines were not inventoried",
		)
	}
	return false
}

func retainPythonObservations(
	graph *behavior.Graph,
	content artifact.Content,
	scopeID, sourceFunction string,
	lineNo int,
	lineOffset int64,
	observations []pythonSourceObservation,
	total int,
	nodeCount, inspectionCount *int,
) bool {
	if total > maxPythonFeatureObservationsPerLine {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			pythonFeatureAnalysisArea,
			fmt.Sprintf("Python Feature observation limit %d reached on a physical line; additional observations on that line were not inventoried", maxPythonFeatureObservationsPerLine),
		)
		observations = observations[:min(len(observations), maxPythonFeatureObservationsPerLine)]
	}
	for _, observation := range observations {
		if *nodeCount >= maxPythonFeatureObservationsPerNode {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonFeatureAnalysisArea,
				fmt.Sprintf("Python Feature observation limit %d reached for node; remaining source was not inventoried", maxPythonFeatureObservationsPerNode),
			)
			return false
		}
		if *inspectionCount >= maxPythonFeatureObservationsPerInspection {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonFeatureAnalysisArea,
				fmt.Sprintf("Python Feature observation limit %d reached for inspection; remaining Python sources were not inventoried", maxPythonFeatureObservationsPerInspection),
			)
			return true
		}
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return true
		}

		qualifiers := map[string]string(nil)
		if observation.form != "" {
			qualifiers = map[string]string{"form": observation.form}
			if observation.alias != "" {
				qualifiers["alias"] = observation.alias
			}
		}
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:      content.NodeID,
			ScopeID:     scopeID,
			Logical:     content.LogicalPath,
			Physical:    content.PhysicalPath,
			Line:        lineNo,
			Offset:      lineOffset + int64(observation.byteOffset),
			OffsetKnown: true,
			Function:    sourceFunction,
			Arch:        content.Architecture,
			Method:      "python-lexical",
			Kind:        pythonFeatureEvidenceKind(observation.key),
			Value:       observation.value,
		})
		if evidenceID == "" {
			graph.MarkWorkOmitted()
			return true
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
			return true
		}
		*nodeCount++
		*inspectionCount++
	}
	return false
}

func pythonFeatureEvidenceKind(key string) string {
	if key == "python.import" {
		return "python-import"
	}
	return "python-qualified-call"
}

type pythonFunctionScopeIdentity struct {
	nodeID   string
	function string
	line     int
}

func pythonFunctionScopes(graph *behavior.Graph) map[pythonFunctionScopeIdentity]string {
	out := map[pythonFunctionScopeIdentity]string{}
	for _, scope := range graph.Scopes {
		if scope.Kind != "function" || scope.NodeID == "" || scope.Function == "" || scope.LineStart <= 0 {
			continue
		}
		out[pythonFunctionScopeIdentity{nodeID: scope.NodeID, function: scope.Function, line: scope.LineStart}] = scope.ID
	}
	return out
}

func pythonFeatureScope(
	graph *behavior.Graph,
	content artifact.Content,
	function functionState,
	lineNo, lineEnd int,
	scopeIDs map[string]string,
	existing map[pythonFunctionScopeIdentity]string,
) string {
	if scopeID := scopeIDs[function.scopeKey]; scopeID != "" {
		return extendPythonFeatureScope(graph, scopeID, lineEnd)
	}
	identity := pythonFunctionScopeIdentity{nodeID: content.NodeID, function: function.name, line: lineNo}
	if scopeID := existing[identity]; scopeID != "" {
		scopeIDs[function.scopeKey] = scopeID
		return extendPythonFeatureScope(graph, scopeID, lineEnd)
	}
	scopeID := textExecutionScope(graph, content, function.name, function.scopeKey, lineNo, scopeIDs)
	if scopeID != "" {
		existing[identity] = scopeID
		return extendPythonFeatureScope(graph, scopeID, lineEnd)
	}
	return ""
}

func extendPythonFeatureScope(graph *behavior.Graph, scopeID string, line int) string {
	for index := range graph.Scopes {
		if graph.Scopes[index].ID == scopeID {
			if line > graph.Scopes[index].LineEnd {
				graph.Scopes[index].LineEnd = line
			}
			return scopeID
		}
	}
	return ""
}

func pythonPhysicalLineOffsets(source string, count int) []int64 {
	offsets := make([]int64, count)
	start := 0
	for index := 0; index < count; index++ {
		offsets[index] = int64(start)
		if start >= len(source) {
			continue
		}
		newline := strings.IndexByte(source[start:], '\n')
		if newline < 0 {
			start = len(source)
		} else {
			start += newline + 1
		}
	}
	return offsets
}

func pythonPhysicalLineTruncated(input boundedTextInput, index int, offsets []int64) bool {
	if index < 0 || index >= len(input.Lines) || index >= len(offsets) {
		return true
	}
	start := int(offsets[index])
	end := start + len(input.Lines[index])
	if start < 0 || end < start || end > len(input.Source) {
		return true
	}
	if end < len(input.Source) {
		return input.Source[end] != '\n'
	}
	return input.BytesTruncated && (len(input.Source) == 0 || input.Source[len(input.Source)-1] != '\n')
}

func pythonRemainingPhysicalSource(lines []string, start int) bool {
	for index := max(0, start); index < len(lines); index++ {
		if strings.TrimSpace(lines[index]) != "" {
			return true
		}
	}
	return false
}

type pythonOrdinaryStringState struct {
	quote byte
}

type pythonStringMaskResult struct {
	malformed bool
	formatted bool
	stop      bool
}

func maskPythonOrdinaryStringsAndComments(line string, state *pythonOrdinaryStringState) (string, pythonStringMaskResult) {
	if state.quote == 0 && !strings.ContainsAny(line, "#'\"") {
		return line, pythonStringMaskResult{}
	}
	masked := []byte(line)
	mask := func(start, end int) {
		for index := max(0, start); index < min(end, len(masked)); index++ {
			masked[index] = ' '
		}
	}
	result := pythonStringMaskResult{}
	index := 0
	if state.quote != 0 {
		close := pythonOrdinaryQuoteClose(line, 0, state.quote)
		if close < 0 {
			mask(0, len(line))
			if !pythonEscapedPhysicalNewline(line) {
				state.quote = 0
				result.malformed = true
			}
			return string(masked), result
		}
		mask(0, close)
		state.quote = 0
		index = close
	}

	for index < len(line) {
		switch line[index] {
		case '#':
			mask(index, len(line))
			return string(masked), result
		case '\'', '"':
			start, _, formatted := pythonStringPrefix(line, index)
			if formatted {
				mask(start, len(line))
				result.formatted = true
				result.stop = pythonEscapedPhysicalNewline(line)
				return string(masked), result
			}
			close := pythonOrdinaryQuoteClose(line, index+1, line[index])
			if close < 0 {
				mask(start, len(line))
				if pythonEscapedPhysicalNewline(line) {
					state.quote = line[index]
				} else {
					result.malformed = true
				}
				return string(masked), result
			}
			mask(start, close)
			index = close
		default:
			index++
		}
	}
	return string(masked), result
}

func pythonStringPrefix(line string, quote int) (int, string, bool) {
	start := quote
	for start > 0 {
		ch := line[start-1]
		if ch < 'A' || ch > 'Z' && ch < 'a' || ch > 'z' {
			break
		}
		start--
	}
	if start < quote && start > 0 && isIdentifierByte(line[start-1]) {
		start = quote
	}
	prefix := strings.ToLower(line[start:quote])
	switch prefix {
	case "", "b", "r", "u", "br", "rb", "ur", "ru":
		return start, prefix, false
	case "f", "fr", "rf", "t", "tr", "rt":
		return start, prefix, true
	default:
		return quote, "", false
	}
}

func pythonOrdinaryQuoteClose(line string, start int, quote byte) int {
	for index := start; index < len(line); index++ {
		if line[index] == quote && !pythonQuoteEscaped(line, index) {
			return index + 1
		}
	}
	return -1
}

func pythonEscapedPhysicalNewline(line string) bool {
	backslashes := 0
	for index := len(line) - 1; index >= 0 && line[index] == '\\'; index-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func pythonContainsNonASCII(line string) bool {
	for index := 0; index < len(line); index++ {
		if line[index] >= 0x80 {
			return true
		}
	}
	return false
}

func pythonPossibleDeclarationPrefix(trimmed string) bool {
	trimmed = strings.TrimSpace(trimmed)
	if pythonDeclarationKeywordAt(trimmed, 0, "def") || pythonDeclarationKeywordAt(trimmed, 0, "class") {
		return true
	}
	if !pythonDeclarationKeywordAt(trimmed, 0, "async") {
		return false
	}
	cursor := pythonSkipHorizontal(trimmed, len("async"))
	return cursor > len("async") && pythonDeclarationKeywordAt(trimmed, cursor, "def")
}

func pythonUnsupportedAsyncContinuation(trimmed string) bool {
	trimmed = strings.TrimSpace(trimmed)
	if !pythonDeclarationKeywordAt(trimmed, 0, "async") {
		return false
	}
	return strings.TrimSpace(trimmed[len("async"):]) == "\\"
}

func pythonBoundedDeclarationHeaderValid(line string) bool {
	_, name, declared := pythonLexicalDeclarationStart(line)
	if !declared || pythonHardKeyword(name) {
		return false
	}
	_, colon := pythonTopLevelColon(line)
	return colon
}

func pythonDeclarationKeywordAt(line string, cursor int, keyword string) bool {
	if cursor < 0 || cursor+len(keyword) > len(line) || line[cursor:cursor+len(keyword)] != keyword {
		return false
	}
	end := cursor + len(keyword)
	return end == len(line) || pythonHorizontal(line[end])
}

func pythonLineMayContainFeature(line string) bool {
	if pythonImportStatementStart(line) {
		return true
	}
	calls, limited := pythonQualifiedCalls(line, 1)
	return len(calls) > 0 || limited
}

func pythonTopLevelColon(line string) (int, bool) {
	depth := 0
	for index := 0; index < len(line); {
		switch line[index] {
		case '\'', '"':
			next, ok := skipPythonQuoted(line, index)
			if !ok {
				return 0, false
			}
			index = next
			continue
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				return index, true
			}
		}
		index++
	}
	return 0, false
}

func pythonSameLineSuite(line string) (string, bool) {
	colon, ok := pythonTopLevelColon(line)
	if !ok {
		return "", false
	}
	suite := strings.TrimSpace(line[colon+1:])
	return suite, suite != ""
}

func pythonSuiteMayContainFeature(suite string) bool {
	if pythonSuiteContainsImport(suite) {
		return true
	}
	calls, limited := pythonQualifiedCalls(suite, 1)
	return len(calls) > 0 || limited
}

func pythonSuiteContainsImport(suite string) bool {
	start := 0
	depth := 0
	for index := 0; index < len(suite); {
		switch suite[index] {
		case '\'', '"':
			next, ok := skipPythonQuoted(suite, index)
			if !ok {
				return false
			}
			index = next
			continue
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				if pythonImportStatementStart(suite[start:index]) {
					return true
				}
				start = index + 1
			}
		}
		index++
	}
	return pythonImportStatementStart(suite[start:])
}

func pythonImportStatementStart(line string) bool {
	start := pythonSkipHorizontal(line, 0)
	return pythonKeywordAt(line, start, "import") || pythonKeywordAt(line, start, "from")
}

func parsePythonImportLine(line string) pythonImportResult {
	start := pythonSkipHorizontal(line, 0)
	switch {
	case pythonKeywordAt(line, start, "import"):
		return parsePythonDirectImport(line, start+len("import"))
	case pythonKeywordAt(line, start, "from"):
		return parsePythonFromImport(line, start+len("from"))
	default:
		return pythonImportResult{disposition: pythonImportAbsent}
	}
}

func parsePythonDirectImport(line string, cursor int) pythonImportResult {
	if cursor >= len(line) || !pythonHorizontal(line[cursor]) {
		return pythonImportResult{disposition: pythonImportMalformed}
	}
	if pythonImportUnsupportedShape(line) {
		return pythonImportResult{
			disposition: pythonImportUnsupported,
			continued:   pythonImportContinued(line),
			reason:      "parenthesized, backslash-continued, multi-statement, or multiline imports are outside the closed single-physical-line import grammar",
		}
	}
	result := pythonImportResult{disposition: pythonImportRecognized}
	cursor = pythonSkipHorizontal(line, cursor)
	for {
		name, offset, next, ok, limited := pythonDottedName(line, cursor, false)
		if limited {
			return pythonImportLimitResult()
		}
		if !ok {
			return pythonImportResult{disposition: pythonImportMalformed}
		}
		cursor = pythonSkipHorizontal(line, next)
		alias := ""
		if pythonKeywordAt(line, cursor, "as") {
			cursor = pythonSkipHorizontal(line, cursor+2)
			alias, _, cursor, ok = pythonASCIIIdentifier(line, cursor)
			if !ok {
				return pythonImportResult{disposition: pythonImportMalformed}
			}
			cursor = pythonSkipHorizontal(line, cursor)
		}
		result.total++
		if len(result.observations) < maxPythonFeatureObservationsPerLine+1 {
			result.observations = append(result.observations, pythonSourceObservation{
				key: "python.import", value: name, form: "import", alias: alias, byteOffset: offset,
			})
		}
		if cursor >= len(line) {
			return result
		}
		if line[cursor] != ',' {
			return pythonImportResult{disposition: pythonImportMalformed}
		}
		cursor = pythonSkipHorizontal(line, cursor+1)
		if cursor >= len(line) {
			return pythonImportResult{disposition: pythonImportMalformed}
		}
	}
}

func parsePythonFromImport(line string, cursor int) pythonImportResult {
	if cursor >= len(line) || !pythonHorizontal(line[cursor]) {
		return pythonImportResult{disposition: pythonImportMalformed}
	}
	if pythonImportUnsupportedShape(line) {
		return pythonImportResult{
			disposition: pythonImportUnsupported,
			continued:   pythonImportContinued(line),
			reason:      "parenthesized, backslash-continued, multi-statement, or multiline imports are outside the closed single-physical-line import grammar",
		}
	}
	cursor = pythonSkipHorizontal(line, cursor)
	module, _, next, ok, limited := pythonDottedName(line, cursor, true)
	if limited {
		return pythonImportLimitResult()
	}
	if !ok {
		return pythonImportResult{disposition: pythonImportMalformed}
	}
	cursor = next
	if cursor >= len(line) || !pythonHorizontal(line[cursor]) {
		return pythonImportResult{disposition: pythonImportMalformed}
	}
	cursor = pythonSkipHorizontal(line, cursor)
	if !pythonKeywordAt(line, cursor, "import") {
		return pythonImportResult{disposition: pythonImportMalformed}
	}
	cursor += len("import")
	if cursor >= len(line) || !pythonHorizontal(line[cursor]) {
		return pythonImportResult{disposition: pythonImportMalformed}
	}
	cursor = pythonSkipHorizontal(line, cursor)
	result := pythonImportResult{disposition: pythonImportRecognized}
	for {
		name := ""
		offset := cursor
		if cursor < len(line) && line[cursor] == '*' {
			name = "*"
			cursor++
		} else {
			var nameOK bool
			name, _, cursor, nameOK = pythonASCIIIdentifier(line, cursor)
			if !nameOK {
				return pythonImportResult{disposition: pythonImportMalformed}
			}
		}
		cursor = pythonSkipHorizontal(line, cursor)
		alias := ""
		if pythonKeywordAt(line, cursor, "as") {
			if name == "*" {
				return pythonImportResult{disposition: pythonImportMalformed}
			}
			cursor = pythonSkipHorizontal(line, cursor+2)
			var aliasOK bool
			alias, _, cursor, aliasOK = pythonASCIIIdentifier(line, cursor)
			if !aliasOK {
				return pythonImportResult{disposition: pythonImportMalformed}
			}
			cursor = pythonSkipHorizontal(line, cursor)
		}
		value := module + "." + name
		if strings.HasSuffix(module, ".") {
			value = module + name
		}
		if len(value) > maxPythonQualifiedCallBytes ||
			pythonDottedNameComponents(module)+1 > maxPythonQualifiedCallComponents {
			return pythonImportLimitResult()
		}
		result.total++
		if len(result.observations) < maxPythonFeatureObservationsPerLine+1 {
			result.observations = append(result.observations, pythonSourceObservation{
				key: "python.import", value: value, form: "from-import", alias: alias, byteOffset: offset,
			})
		}
		if cursor >= len(line) {
			return result
		}
		if name == "*" || line[cursor] != ',' {
			return pythonImportResult{disposition: pythonImportMalformed}
		}
		cursor = pythonSkipHorizontal(line, cursor+1)
		if cursor >= len(line) {
			return pythonImportResult{disposition: pythonImportMalformed}
		}
	}
}

func pythonImportLimitResult() pythonImportResult {
	return pythonImportResult{
		disposition: pythonImportUnsupported,
		reason: fmt.Sprintf(
			"a Python import name exceeded %d components or %d bytes; no import Feature was emitted for it",
			maxPythonQualifiedCallComponents,
			maxPythonQualifiedCallBytes,
		),
	}
}

func pythonDottedNameComponents(name string) int {
	name = strings.TrimLeft(name, ".")
	if name == "" {
		return 0
	}
	return strings.Count(name, ".") + 1
}

func pythonImportUnsupportedShape(line string) bool {
	for index := 0; index < len(line); index++ {
		switch line[index] {
		case '(', ')', '[', ']', '{', '}', '\\', ';':
			return true
		}
	}
	return false
}

func pythonImportContinued(line string) bool {
	trimmed := strings.TrimRight(line, " \t\r")
	return strings.HasSuffix(trimmed, "\\") || pythonImportBracketDelta(line) > 0
}

type pythonImportContinuationState struct {
	active bool
	depth  int
	lines  int
	bytes  int
}

func (state *pythonImportContinuationState) start(line string) {
	state.active = true
	state.depth = pythonImportBracketDelta(line)
	state.lines = 1
	state.bytes = len(line)
}

func (state *pythonImportContinuationState) consume(line string) bool {
	if !state.active {
		return false
	}
	state.lines++
	state.bytes += len(line)
	state.depth += pythonImportBracketDelta(line)
	trimmed := strings.TrimRight(line, " \t\r")
	state.active = state.depth > 0 || strings.HasSuffix(trimmed, "\\")
	if state.depth < 0 {
		state.active = false
	}
	return state.lines > maxSemanticContinuationLines || state.bytes > maxSemanticContinuationBytes
}

func pythonImportBracketDelta(line string) int {
	depth := 0
	for index := 0; index < len(line); index++ {
		switch line[index] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		}
	}
	return depth
}

func pythonDottedName(line string, cursor int, relative bool) (string, int, int, bool, bool) {
	start := cursor
	if relative {
		for cursor < len(line) && line[cursor] == '.' {
			cursor++
		}
	}
	components := 0
	if cursor < len(line) && identifierStartByte(line[cursor]) {
		for {
			_, _, next, ok := pythonASCIIIdentifier(line, cursor)
			if !ok {
				return "", start, cursor, false, false
			}
			components++
			cursor = next
			if cursor >= len(line) || line[cursor] != '.' {
				break
			}
			if cursor+1 >= len(line) || !identifierStartByte(line[cursor+1]) {
				return "", start, cursor, false, false
			}
			cursor++
		}
	} else if cursor == start {
		return "", start, cursor, false, false
	}
	name := line[start:cursor]
	if len(name) > maxPythonQualifiedCallBytes || components > maxPythonQualifiedCallComponents {
		return "", start, cursor, false, true
	}
	return name, start, cursor, true, false
}

func pythonASCIIIdentifier(line string, cursor int) (string, int, int, bool) {
	if cursor >= len(line) || !identifierStartByte(line[cursor]) {
		return "", cursor, cursor, false
	}
	start := cursor
	cursor++
	for cursor < len(line) && isIdentifierByte(line[cursor]) {
		cursor++
	}
	identifier := line[start:cursor]
	if pythonHardKeyword(identifier) {
		return "", start, cursor, false
	}
	return identifier, start, cursor, true
}

func pythonHardKeyword(identifier string) bool {
	switch identifier {
	case "False", "None", "True",
		"and", "as", "assert", "async", "await",
		"break", "class", "continue", "def", "del",
		"elif", "else", "except", "finally", "for", "from",
		"global", "if", "import", "in", "is", "lambda",
		"nonlocal", "not", "or", "pass", "raise", "return",
		"try", "while", "with", "yield":
		return true
	default:
		return false
	}
}

func pythonQualifiedCalls(line string, retain int) ([]pythonSourceObservation, bool) {
	observations := make([]pythonSourceObservation, 0, min(retain, 8))
	limited := false
	for cursor := 0; cursor < len(line); {
		if !identifierStartByte(line[cursor]) || cursor > 0 && (isIdentifierByte(line[cursor-1]) || line[cursor-1] == '.') {
			cursor++
			continue
		}
		start := cursor
		components := 0
		for {
			_, _, next, ok := pythonASCIIIdentifier(line, cursor)
			if !ok {
				break
			}
			components++
			cursor = next
			if cursor >= len(line) || line[cursor] != '.' || cursor+1 >= len(line) || !identifierStartByte(line[cursor+1]) {
				break
			}
			cursor++
		}
		end := cursor
		call := pythonSkipHorizontal(line, end)
		if components >= 2 && call < len(line) && line[call] == '(' {
			if components > maxPythonQualifiedCallComponents || end-start > maxPythonQualifiedCallBytes {
				limited = true
			} else if len(observations) < retain {
				observations = append(observations, pythonSourceObservation{
					key: "python.qualified_call", value: line[start:end], byteOffset: start,
				})
			}
		}
		if cursor <= start {
			cursor = start + 1
		}
	}
	return observations, limited
}

func pythonSkipHorizontal(line string, cursor int) int {
	for cursor < len(line) && pythonHorizontal(line[cursor]) {
		cursor++
	}
	return cursor
}

func pythonHorizontal(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\f' || ch == '\r'
}

func pythonKeywordAt(line string, cursor int, keyword string) bool {
	if cursor < 0 || cursor+len(keyword) > len(line) || line[cursor:cursor+len(keyword)] != keyword {
		return false
	}
	end := cursor + len(keyword)
	return end == len(line) || !isIdentifierByte(line[end])
}

func pythonObservationalFeatureKey(key string) bool {
	return key == "python.import" || key == "python.qualified_call"
}
