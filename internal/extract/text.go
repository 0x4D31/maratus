package extract

import (
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

var (
	reURL        = regexp.MustCompile(`(?i)\b(?:https?|wss?|ftp)://[^\s"'<>` + "`" + `{}]+`)
	reHost       = regexp.MustCompile(`\b([a-z0-9][a-z0-9.-]+\.[a-z]{2,})(:[0-9]{1,5})?\b`)
	reIP         = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	rePath       = regexp.MustCompile(`(?:~|/)[A-Za-z0-9._~+/@%-][^,\s)\]}'"]*`)
	reQuoted     = regexp.MustCompile(`["']([^"']+)["']`)
	reJSAssign   = regexp.MustCompile(`^\s*(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']+)["']`)
	rePyGetenv   = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:os\.)?(?:getenv|environ\.get)\(\s*["'][^"']+["']\s*,\s*["']([^"']+)["']\s*\)`)
	reOSASet     = regexp.MustCompile(`(?i)^\s*set\s+([A-Za-z_][A-Za-z0-9_]*)\s+to\s+["']([^"']+)["']`)
	reFetch      = regexp.MustCompile(`\b(fetch|Bun\.fetch|axios\.(?:get|post|put|patch|request)|requests\.(?:get|post|put|patch|request)|httpx\.(?:get|post|put|patch|request)|urllib\.request\.(?:urlopen|urlretrieve)|urllib2\.(?:urlopen|Request))\s*\(`)
	reChmodMode  = regexp.MustCompile(`(?:0o[0-7]+|\b[0-7]{3,4}\b)`)
	reNativeExec = regexp.MustCompile(`\b(posix_spawn|execve|system|NSTask|Process\s*\(|NSAppleScript|do shell script|osascript)\b`)
)

// validatedIPv4MatchIndexes filters already-bounded regexp results without
// performing another enumeration. IPv4-looking substrings inside OIDs and
// longer dotted numeric tokens are not addresses in their own right, and
// netip supplies the strict octet validation that the intentionally simple
// candidate regexp does not.
func validatedIPv4MatchIndexes(value string, matches [][]int) [][]int {
	out := matches[:0]
	for _, match := range matches {
		if _, ok := validatedIPv4Match(value, match); ok {
			out = append(out, match)
		}
	}
	return out
}

func boundedTextIPv4Matches(value string, budget *textLineBudget) [][]int {
	return validatedIPv4MatchIndexes(value, boundedTextRegexpMatches(reIP, value, "IP address", budget))
}

func validatedIPv4Match(value string, match []int) (string, bool) {
	if len(match) != 2 || match[0] < 0 || match[1] <= match[0] || match[1] > len(value) {
		return "", false
	}
	if match[0] > 0 && isDottedNumericByte(value[match[0]-1]) {
		return "", false
	}
	if match[1] < len(value) && isDottedNumericByte(value[match[1]]) {
		return "", false
	}
	addr, err := netip.ParseAddr(value[match[0]:match[1]])
	if err != nil || !addr.Is4() {
		return "", false
	}
	return addr.String(), true
}

func isDottedNumericByte(value byte) bool {
	return value == '.' || value >= '0' && value <= '9'
}

func ExtractText(graph *behavior.Graph, content artifact.Content) {
	extractStaticContentObservations(graph, content, content.Data, "source-static-observation", "", content.ByteOffsetBase)
	language := contentLanguage(content)
	if language == "" {
		if unresolvedTextSemanticsRelevant(content) {
			graph.AddCoverage(behavior.Coverage{
				NodeID:       content.NodeID,
				AnalysisArea: "text-semantics",
				Status:       "skipped",
				Detail:       "semantic text analysis skipped because no trusted interpreter, filename adapter, or structural host selection established a supported language",
			})
		}
		return
	}
	if language == "yaml" {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			"structured-yaml-semantics",
			"structured YAML retained; schema-specific execution and embedded language blocks are not modeled",
		)
		return
	}
	if language == "java-source" {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			"java-source-semantics",
			"Java source retained; Java syntax, execution, data flow, and control flow are not modeled",
		)
		return
	}
	if language == "windows-command" {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			"windows-command-semantics",
			"Windows batch script retained; cmd.exe syntax and execution are not modeled",
		)
		return
	}
	if !semanticTextAllowed(content, language) {
		return
	}
	if language == "native-source" && strings.EqualFold(filepath.Ext(content.LogicalPath), ".go") {
		addPartialCoverageOnce(
			graph,
			"",
			"native-source-semantics/go",
			"Go source receives bounded literal, API-name, and function-name pattern analysis only; no Go AST, call graph, data flow, or control-flow reconstruction",
		)
	}
	if language == "native-source" && strings.EqualFold(filepath.Ext(content.LogicalPath), ".rs") {
		addPartialCoverageOnce(
			graph,
			"",
			"native-source-semantics/rust",
			"Rust source receives bounded literal, API-name, function-name, and direct-call pattern analysis only; no Rust AST, macro expansion, type resolution, complete call graph, data flow, or control-flow reconstruction",
		)
	}
	var input boundedTextInput
	if language == "applescript" {
		input = boundedAppleScriptText(content.Data)
	} else {
		input = boundedText(content.Data)
	}
	addBoundedTextCoverage(graph, content, "text-analysis", input)
	lines := input.Lines
	if (language == "applescript" || language == "jxa") && input.truncated() {
		addPartialCoverageOnce(graph, content.NodeID, "osa-source-completeness", "truncated source cannot establish complete statement contexts or stable host receivers; OSA source semantics were not inferred")
		return
	}
	if (language == "applescript" || language == "jxa") && strings.ContainsRune(input.Source, 0) {
		addPartialCoverageOnce(graph, content.NodeID, "osa-source-encoding", "NUL-containing OSA source encoding is unsupported; source semantics were not inferred")
		return
	}
	if language == "applescript" {
		lines = maskAppleScriptComments(lines)
		extractAppleScriptSource(graph, content, lines, !utf8.ValidString(input.Source))
	}
	if language == "jxa" {
		extractJXAShellCalls(graph, content, input.Source)
	}
	if language == "python" {
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.TrimLeft(line, " \t") != line {
				addPartialCoverageOnce(graph, content.NodeID, "python-lexical-scope-analysis", "the first Python module statement is indented without an enclosing suite; source semantics were not inferred")
				return
			}
			break
		}
		masked := maskPythonMultilineStrings(lines)
		lines = masked.lines
		if masked.formattedExpression {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				"python-multiline-string-analysis",
				"formatted or template triple-quoted string encountered; embedded Python expressions and the following source suffix were not analyzed",
			)
		}
		if masked.limited {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				"python-multiline-string-analysis",
				fmt.Sprintf(
					"triple-quoted string masking limit reached (%d lines or %d bytes); the uninspected source suffix was not analyzed",
					maxPythonMultilineStringLines,
					maxPythonMultilineStringBytes,
				),
			)
		} else if masked.unterminated {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				"python-multiline-string-analysis",
				"an unterminated triple-quoted string reached the retained source boundary; its contents and the remaining source were not analyzed",
			)
		}
	}
	var pythonAPIBindings pythonStableAPIBindings
	var pythonOrderedBindings pythonOrderedAPIBindings
	var pythonLineOffsets []int64
	if language == "python" {
		pythonLineOffsets = pythonPhysicalLineOffsets(input.Source, len(lines))
		pythonAPIBindings = scanPythonStableAPIBindings(lines, pythonLineOffsets)
		pythonOrderedBindings = newPythonOrderedAPIBindings(pythonAPIBindings.bindings)
		if pythonAPIBindings.limited {
			addPartialCoverageOnce(graph, content.NodeID, pythonAPIBindingAnalysisArea, fmt.Sprintf("stable Python module binding inventory reached its limit of %d bindings", maxPythonAPIBindings))
		}
		if pythonAPIBindings.invalidated {
			addPartialCoverageOnce(graph, content.NodeID, pythonAPIBindingAnalysisArea, "a candidate Python module binding was rebound, ambiguously referenced, or had a rooted member replaced; affected qualified calls were not promoted to operations")
		}
		if pythonAPIBindings.dynamicNamespace {
			addPartialCoverageOnce(graph, content.NodeID, pythonAPIBindingAnalysisArea, "dynamic Python namespace access or a wildcard import invalidated global module identity; affected qualified calls remained observational")
		}
	}
	variableState := newTextVariableState()
	derivedBudget := newTextDerivedBudget()
	browserDefinitions := browserCredentialDefinitionTracker{}
	knownFunctions := map[string]bool{}
	ambiguousFunctions := map[string]bool{}
	pythonFunctionDeclarations := map[string]int{}
	functionScopes := map[string]string{}
	functionLanguage := language
	if language == "native-source" && strings.EqualFold(filepath.Ext(content.LogicalPath), ".rs") {
		functionLanguage = "rust-source"
	}
	if language == "native-source" {
		knownFunctions = collectNativeFunctionNames(lines, functionLanguage)
	}
	var fn functionState
	var pythonScopes pythonLexicalScopeState
	inBlockComment := false
	var shellHeredocs shellHeredocState
	shellCompoundDepth := 0
	var javascriptProcessBindings javaScriptProcessBindings
	var javascriptNetworkValues javaScriptCommandState
	javascriptFetchSafe := false
	if language == "javascript" {
		javascriptProcessBindings = newJavaScriptProcessBindings(lines)
		if requiresJavaScriptASTFrontend(javascriptProcessBindings.prescan) {
			extractJavaScriptASTSource(graph, content, input.Source)
			return
		}
		javascriptFetchSafe = javaScriptBuiltinFetchIdentitySafe(javascriptProcessBindings.prescan)
		javascriptNetworkValues = newJavaScriptCommandState(javascriptProcessBindings.prescan)
	}
	pythonSubprocessBindings := map[string]bool{}
	for i := 0; i < len(lines); i++ {
		if derivedBudget.exhausted {
			break
		}
		if variableState.limited {
			addPartialCoverageOnce(graph, content.NodeID, "text-variable-analysis", variableState.coverageDetail())
			break
		}
		if graph.WorkLimitReached() {
			// Record an attempted item so FinalizeLimits emits the mandatory
			// partial-coverage marker, then stop derived work that cannot be kept.
			graph.MarkWorkOmitted()
			break
		}
		raw := lines[i]
		lineNo := i + 1
		var javaScriptStatements []javaScriptCommandStatement
		if language == "javascript" {
			javaScriptStatements = javascriptProcessBindings.prescan.byLine[lineNo]
			if len(javaScriptStatements) == 0 {
				// The structural index admits only semicolon-terminated module
				// statements and direct statements in exact named functions.
				// Opaque, mixed-scope, continuation, and malformed lines retain
				// raw artifact features elsewhere but cannot emit semantic facts.
				continue
			}
			if !sameJavaScriptStatementScope(javaScriptStatements) {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					"javascript-structural-analysis",
					"module and function statements shared one physical JavaScript line; mixed-scope semantics were not inferred",
				)
				continue
			}
			var evidenceParts []string
			for _, statement := range javaScriptStatements {
				evidenceParts = append(evidenceParts, statement.evidenceText)
			}
			raw = strings.Join(evidenceParts, "\n")
			if len(raw) > maxTextAnalysisLineBytes {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					"javascript-structural-analysis",
					fmt.Sprintf("retained JavaScript statement exceeded semantic line limit %d; statement semantics were not inferred", maxTextAnalysisLineBytes),
				)
				continue
			}
		}
		if language == "shell" {
			if shellHeredocs.consumeBodyLine(raw) {
				continue
			}
			details, suppress := shellHeredocs.observeCommandLine(raw, lineNo)
			for _, detail := range details {
				addPartialCoverageOnce(graph, content.NodeID, "shell-heredoc-analysis", detail)
			}
			if suppress {
				continue
			}
		}
		lineBudget := derivedBudget.line()
		var semanticRaw string
		if language == "javascript" {
			directParts := make([]string, 0, len(javaScriptStatements))
			for _, statement := range javaScriptStatements {
				directParts = append(directParts, statement.text)
			}
			semanticRaw = strings.Join(directParts, "\n")
		} else {
			semanticRaw = stripSemanticComment(language, raw, &inBlockComment)
		}
		line := strings.TrimSpace(semanticRaw)
		if language == "python" {
			if pythonUnsupportedAsyncContinuation(line) {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					"python-lexical-scope-analysis",
					"an explicit Python continuation after async was not parsed; remaining source semantics were not inferred because declaration scope could not be established",
				)
				break
			}
			var end int
			var incomplete bool
			semanticRaw, line, end, incomplete = joinPythonLexicalDeclaration(
				lines,
				i,
				semanticRaw,
				line,
				&inBlockComment,
			)
			if incomplete {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					"python-lexical-scope-analysis",
					fmt.Sprintf(
						"Python declaration header exceeded %d lines or %d bytes; remaining source semantics were not inferred",
						maxSemanticContinuationLines,
						maxSemanticContinuationBytes,
					),
				)
				break
			}
			if pythonPossibleDeclarationPrefix(line) && !pythonBoundedDeclarationHeaderValid(line) {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					"python-lexical-scope-analysis",
					"a possible Python declaration header was malformed or outside the bounded grammar; remaining source semantics were not inferred because lexical scope could not be established",
				)
				break
			}
			i = end
		}
		var scopeKey string
		pythonClassBody := false
		if language == "python" {
			lexical := pythonScopes.observe(semanticRaw, line, lineNo)
			if pythonScopes.limited {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					"python-lexical-scope-analysis",
					fmt.Sprintf("Python lexical scope depth limit %d reached; remaining source semantics were not inferred", maxPythonLexicalScopeDepth),
				)
				break
			}
			fn = lexical.function
			scopeKey = lexical.scopeKey
			pythonClassBody = lexical.classBody
			if lexical.declaration.name != "" {
				name := lexical.declaration.name
				if name == "subprocess" {
					// A def/class statement binds its name in the enclosing
					// namespace after the declaration is evaluated. Observing the
					// declaration under its new child scope must not leave an
					// earlier enclosing subprocess import usable.
					pythonSubprocessBindings[lexical.enclosingScopeKey] = false
				}
				if lexical.declaration.kind == pythonScopeFunction ||
					lexical.declaration.kind == pythonScopeAsyncFunction {
					pythonFunctionDeclarations[name]++
				}
				if pythonFunctionDeclarations[name] == 2 {
					ambiguousFunctions[name] = true
					addPartialCoverageOnce(
						graph,
						content.NodeID,
						"python-direct-call-analysis",
						"multiple same-named Python function declarations were retained; call-by-name execution was not inferred",
					)
				}
				if lexical.declaration.topLevel &&
					lexical.declaration.kind == pythonScopeFunction &&
					!ambiguousFunctions[name] {
					knownFunctions[name] = true
				} else if lexical.declaration.topLevel || ambiguousFunctions[name] {
					delete(knownFunctions, name)
				}
				if !lexical.declaration.topLevel && lexical.enclosingScopeKey == "" {
					addPartialCoverageOnce(
						graph,
						content.NodeID,
						"python-direct-call-analysis",
						"an indented Python function or class declaration is control-flow dependent; module-level call reachability was not inferred",
					)
				}
			}
		} else if language == "javascript" {
			retained := javaScriptStatements[0]
			fn = functionState{
				name:     retained.functionName,
				scopeKey: retained.scopeKey,
			}
			scopeKey = retained.scopeKey
		} else {
			startedFunctionName, startedFunction := functionStart(functionLanguage, line)
			fn = updateFunctionState(functionLanguage, semanticRaw, line, fn)
			if startedFunction && fn.name == startedFunctionName {
				// Function names are not unique lexical scopes: a later
				// redefinition must not inherit bindings or share same-scope rule
				// matches with an earlier body of the same name.
				fn.scopeKey = fmt.Sprintf("%s@%d", startedFunctionName, lineNo)
			}
			scopeKey = fn.scopeKey
			if fn.name != "" {
				knownFunctions[fn.name] = true
			}
		}
		semanticLine := line
		if semanticLine == "" {
			continue
		}
		if language != "javascript" {
			if joined, end := joinSemanticContinuation(language, lines, i, semanticLine, &inBlockComment); end > i {
				semanticLine = joined
				line = joined
				i = end
			}
		}
		var javascriptProcess javaScriptProcessResolution
		if language == "javascript" {
			javascriptProcess = javascriptProcessBindings.observeAndResolve(semanticLine, scopeKey, lineNo)
		}
		pythonSubprocessBound := false
		pythonStableSubprocessBinding := ""
		pythonOrderedState := pythonOrderedAPIBindingState{}
		if language == "python" {
			offsetBase := int64(0)
			if lineNo > 0 && lineNo <= len(pythonLineOffsets) {
				offsetBase = pythonLineOffsets[lineNo-1]
			}
			pythonOrderedBindings.observe(scopeKey, semanticRaw, semanticLine, lineNo, offsetBase)
			pythonOrderedState = pythonOrderedBindings.stateAt(scopeKey, semanticRaw)
			pythonSubprocessBound = observePythonSubprocessBinding(
				pythonSubprocessBindings,
				scopeKey,
				semanticLine,
			)
			if bindingName, stable := pythonAPIBindings.stableSubprocessCallBinding(semanticLine, lineNo); stable {
				pythonSubprocessBound = true
				pythonStableSubprocessBinding = bindingName
			}
			if pythonClassBody {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					"python-lexical-scope-analysis",
					"Python class-body execution and namespace semantics are not modeled; class-body behavior was not inferred",
				)
				continue
			}
		}
		shellConditionalAssignment := false
		if language == "shell" {
			var limited bool
			shellConditionalAssignment, shellCompoundDepth, limited = shellCompoundAssignmentContext(semanticLine, shellCompoundDepth)
			if limited {
				variableState.markLimited(fmt.Sprintf("shell compound-statement limit %d reached on one line", maxShellStatementsPerLine))
			}
		}
		semanticScopeID := textExecutionScope(graph, content, fn.name, scopeKey, lineNo, functionScopes)
		if definition, ok := browserDefinitions.ObserveScoped(language, semanticLine, lineNo, fn.name, scopeKey); ok {
			addBrowserCredentialDefinitionFeature(graph, content, definition, semanticScopeID)
		}
		analysisLine := semanticLine
		if language == "shell" {
			invalidateShellMutation(semanticLine, variableState, scopeKey)
			assignmentContent := content
			assignmentContent.ScopeID, assignmentContent.Function = semanticScopeID, fn.name
			retainStandaloneShellAssignments(semanticLine, variableState, scopeKey, shellConditionalAssignment, graph, assignmentContent, lineNo)
		}
		vars := variableState.variables(scopeKey)
		requestVars := variableState.requestVariables(scopeKey)
		assigned := false
		assignedName := ""
		assignmentRetained := true
		writtenName := ""
		if language == "python" {
			writtenName, _ = pythonIdentifierAssignmentTarget(semanticLine)
		}
		if name, value, ok := assignment(language, semanticLine, vars); ok {
			if language == "shell" {
				// The shell-specific pass already retained the complete value
				// together with its assignment evidence, or invalidated it.
				assignmentRetained = len(value) <= maxTextVariableValueBytes
			} else {
				assignmentRetained = variableState.setVariable(scopeKey, name, resolveAssignedValue(language, value, vars))
			}
			variableState.clearRequestVariable(scopeKey, name)
			assigned = true
			assignedName = name
		} else if writtenName != "" {
			// A simple write whose value is outside the bounded resolver makes
			// any previously retained ordinary or request binding unknown.
			// Keeping the stale value can fabricate later data flow.
			assignmentRetained = variableState.invalidateVariable(scopeKey, writtenName)
			if pythonAssignmentValueOversized(semanticLine) {
				variableState.markOmitted(fmt.Sprintf("variable value exceeded %d bytes", maxTextVariableValueBytes))
				assignmentRetained = false
			}
			variableState.clearRequestVariable(scopeKey, writtenName)
			assigned = true
			assignedName = writtenName
		}
		if variableState.limited {
			addPartialCoverageOnce(graph, content.NodeID, "text-variable-analysis", variableState.coverageDetail())
			break
		}
		if assigned && !assignmentRetained {
			continue
		}
		assignedURLs := []string(nil)
		if assigned && scriptSemanticLanguage(language) && staticURLAssignmentName(assignedName) {
			assignedURLs = staticAssignedURLsBudget(semanticLine, lineBudget)
		}
		if !assigned && language != "shell" && language != "applescript" && language != "jxa" {
			analysisLine = expandSimpleVars(language, semanticLine, vars)
		}
		if variableState.limited {
			addPartialCoverageOnce(graph, content.NodeID, "text-variable-analysis", variableState.coverageDetail())
			break
		}
		networkSemanticLine := semanticLine
		networkCall := languageNetworkCallObserved(language, semanticLine)
		networkCallObserved := networkCall
		var networkDestinations []string
		var javascriptNetworkProof []javaScriptCommandProof
		pythonNetworkBindingName := ""
		switch language {
		case "python":
			var observed bool
			pythonNetworkBindingName, networkSemanticLine, observed, networkCall = pythonNetworkCallBinding(semanticLine, lineNo, &pythonAPIBindings)
			networkCallObserved = networkCallObserved || observed
		case "javascript":
			if javascriptFetchSafe {
				// Preserve the existing request/download value flow only for the
				// globally unshadowed runtime builtin. Bound module APIs such as
				// axios are emitted by the structural API recognizer below.
				var exact bool
				networkDestinations, javascriptNetworkProof, exact = javaScriptFetchLineDestinations(&javascriptNetworkValues, javaScriptStatements)
				networkCall = networkCall && exact
			} else {
				networkCall = false
			}
		case "jxa":
			if networkCall {
				networkCall = false
			}
		}
		if language == "python" && networkCallObserved && !networkCall {
			pythonAPIBindings.unsupportedCalls = true
		}
		if networkCall && language != "javascript" {
			networkDestinations = languageNetworkDestinationsBudget(language, networkSemanticLine, vars, lineBudget)
		}
		var javascriptNetworkEvidence []string
		if len(javascriptNetworkProof) > 0 {
			proofContent := content
			proofContent.ScopeID, proofContent.Function = semanticScopeID, fn.name
			javascriptNetworkEvidence = javaScriptAPIProofEvidence(graph, proofContent, javascriptNetworkProof)
			if len(javascriptNetworkEvidence) != len(javascriptNetworkProof) {
				networkDestinations = nil
			}
		}
		if variableState.limited {
			addPartialCoverageOnce(graph, content.NodeID, "text-variable-analysis", variableState.coverageDetail())
			break
		}
		if name, destinations, ok := languageNetworkAssignmentWithDestinations(language, semanticLine, networkDestinations); ok {
			variableState.setRequestVariable(scopeKey, name, destinations)
			requestVars = variableState.requestVariables(scopeKey)
		}
		if variableState.limited {
			addPartialCoverageOnce(graph, content.NodeID, "text-variable-analysis", variableState.coverageDetail())
			break
		}
		requestWriteTarget, requestWriteDestinations, requestWriteOK := languageRequestWriteTargetBudget(language, analysisLine, requestVars, lineBudget)
		if variableState.limited {
			addPartialCoverageOnce(graph, content.NodeID, "text-variable-analysis", variableState.coverageDetail())
			break
		}
		directCalls := directFunctionCallsBudget(language, semanticLine, fn.name, knownFunctions, lineBudget)
		if language == "shell" && len(directCalls) > 0 {
			invalidateAllShellBindings(variableState, scopeKey)
		}
		if language == "python" {
			directCalls = unambiguousPythonDirectCalls(directCalls, ambiguousFunctions)
			if scopeKey == "" && writtenName != "" {
				// Python evaluates an assignment's right-hand side before binding
				// its target. directCalls above may therefore retain an exact call
				// on this line, but subsequent lines must not treat the overwritten
				// name as the original function declaration.
				delete(knownFunctions, writtenName)
			}
		}
		pythonAPICandidate := language == "python" && pythonSourceAPICallObserved(analysisLine, lineNo, &pythonAPIBindings, pythonOrderedState)
		shellStateRelevant := language == "shell" && shellDirectoryStateRelevant(analysisLine)
		if len(directCalls) == 0 && len(assignedURLs) == 0 && !javascriptProcess.candidate && !javascriptProcess.unmodeledOuter && !pythonAPICandidate && pythonStableSubprocessBinding == "" && !networkCall && !shellStateRelevant && !lineMayHaveSemanticsBudget(language, analysisLine, lineBudget) {
			continue
		}
		lineContent := content
		if fn.name != "" {
			lineContent.Function = fn.name
		}
		lineContent.ScopeID = semanticScopeID
		lineContent.SupportingEvidenceIDs = append(append([]string(nil), content.SupportingEvidenceIDs...), javascriptNetworkEvidence...)
		evidenceID := addLineEvidence(graph, lineContent, lineNo, "text-line", line)
		if pythonNetworkBindingName != "" {
			bindingEvidenceID := pythonAPIBindings.bindingEvidence(graph, content, pythonNetworkBindingName)
			if bindingEvidenceID == "" {
				return
			}
			lineContent.SupportingEvidenceIDs = append(lineContent.SupportingEvidenceIDs, bindingEvidenceID)
		}
		addDirectFunctionCallFeatures(graph, lineContent, directCalls, evidenceID)
		addStaticAssignedURLs(graph, lineContent, language, assignedURLs, evidenceID)
		extractSensitiveResourceFeaturesBudget(graph, lineContent, language, analysisLine, lineNo, evidenceID, lineBudget)
		extractSensitiveReadsBudget(graph, lineContent, language, analysisLine, lineNo, evidenceID, lineBudget)
		extractNativeAPIsBudget(graph, lineContent, language, analysisLine, lineNo, evidenceID, lineBudget)
		if language == "python" && pythonAPICandidate {
			extractPythonSourceAPIs(graph, content, lineContent, semanticLine, lineNo, evidenceID, vars, lineBudget, &pythonAPIBindings, pythonOrderedState)
		}
		switch language {
		case "shell":
			analyzeShellLineVariables(graph, lineContent, analysisLine, lineNo, executionContextForContent(lineContent), evidenceID, 0,
				&shellSourceOrder{group: graph.NewSourceOrderGroup(), uncertain: shellConditionalAssignment}, variableState, scopeKey)
		case "python", "javascript":
			if networkCall {
				extractResolvedLanguageNetworkBudget(graph, lineContent, language, networkSemanticLine, analysisLine, networkDestinations, lineNo, evidenceID, lineBudget)
			}
			if requestWriteOK {
				extractResolvedLanguageRequestWrite(graph, lineContent, language, requestWriteTarget, requestWriteDestinations, lineNo, evidenceID)
			}
			extractLanguageFileModeBudget(graph, lineContent, language, analysisLine, lineNo, evidenceID, lineBudget)
			invocation, ok, incomplete := javascriptProcess.invocation, javascriptProcess.candidate && !javascriptProcess.incomplete, javascriptProcess.incomplete
			if language == "python" {
				invocationAnalysisLine := analysisLine
				invocationSourceLine := semanticLine
				if pythonStableSubprocessBinding != "" && pythonStableSubprocessBinding != "subprocess" {
					invocationAnalysisLine = canonicalizePythonSubprocessRoot(invocationAnalysisLine, pythonStableSubprocessBinding)
					invocationSourceLine = canonicalizePythonSubprocessRoot(invocationSourceLine, pythonStableSubprocessBinding)
				}
				invocation, ok, incomplete = extractPythonEmbeddedInvocationBudget(
					invocationAnalysisLine,
					invocationSourceLine,
					pythonSubprocessBound,
					lineBudget,
				)
			}
			if ok {
				cmdEvidence := addLineEvidence(graph, lineContent, lineNo, "subprocess-command", invocation.evidenceValue())
				causalEvidence, causalOK := addJavaScriptCommandProofEvidence(
					graph,
					content,
					lineContent,
					scopeKey,
					javascriptProcess.proofs,
				)
				if language != "javascript" {
					causalEvidence = nil
					causalOK = true
				}
				commandContent := lineContent
				if language == "python" && pythonStableSubprocessBinding != "" {
					bindingEvidenceID := pythonAPIBindings.bindingEvidence(graph, content, pythonStableSubprocessBinding)
					if bindingEvidenceID == "" {
						return
					}
					commandContent.SupportingEvidenceIDs = append(commandContent.SupportingEvidenceIDs, bindingEvidenceID)
				}
				start := graph.CaptureGraphRange()
				if invocation.processAttempt {
					apiPrefix := "subprocess."
					apiIdentity := "stable-python-import-and-exact-qualified-call"
					if language == "javascript" {
						apiPrefix = "child_process."
						apiIdentity = "stable-javascript-binding-and-exact-call"
						addPartialCoverageOnce(graph, content.NodeID, "javascript-process-command-analysis", "a proven child_process call retained a process operation with unresolved arguments; command behavior and downstream effects were not inferred")
					}
					qualifiers := map[string]string{
						"api":                  apiPrefix + invocation.api,
						"api_identity":         apiIdentity,
						"argument_coverage":    "unresolved",
						"unresolved_arguments": "dynamic or unsupported argv",
					}
					if invocation.executableOnly != "" {
						qualifiers["argument_coverage"] = "executable-only"
					} else {
						qualifiers["unresolved_executable"] = "dynamic or unsupported expression"
					}
					for name, value := range invocation.qualifiers {
						qualifiers[name] = value
					}
					graph.AddOperation(behavior.ModeledOperation{
						SubjectNodeID: content.NodeID,
						ScopeID:       lineContent.ScopeID,
						Kind:          behavior.OperationProcessExecute,
						ResourceBindings: behavior.Bindings(
							behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, invocation.executableOnly)),
						),
						Qualifiers:     qualifiers,
						EvidenceIDs:    shellOperationEvidence(commandContent, cmdEvidence),
						Support:        behavior.SupportCorroborated,
						Execution:      executionContextForContent(commandContent),
						SourceFunction: commandContent.Function,
						Line:           lineNo,
					})
				} else if invocation.shellCommand != "" {
					AnalyzeShellLine(graph, commandContent, invocation.shellCommand, lineNo, executionContextForContent(commandContent), cmdEvidence)
				} else {
					analyzeShellFields(graph, commandContent, invocation.argv, lineNo, executionContextForContent(commandContent), cmdEvidence, 0, nil)
				}
				if language == "javascript" {
					causalEvidence = append(causalEvidence, evidenceID, cmdEvidence)
					if evidenceID == "" || cmdEvidence == "" {
						causalOK = false
					}
					if !causalOK {
						// An incomplete proof set must force the range through
						// CorroborateRange's safety path rather than leaving
						// derived facts with DIRECT support.
						causalEvidence = nil
					}
					if corroborated := graph.CorroborateRange(start, causalEvidence); !causalOK || !corroborated {
						addPartialCoverageOnce(
							graph,
							content.NodeID,
							"javascript-process-command-analysis",
							"causal evidence for a statically resolved child_process command exceeded retained bounds; affected process and command facts were weakened or discarded",
						)
					}
				}
			} else if incomplete {
				analysisArea := "python-subprocess-analysis"
				detail := "subprocess binding was unproved or invalidated, or argv was dynamic or outside the bounded literal model; process and command semantics were not inferred"
				if language == "javascript" {
					analysisArea = "javascript-process-command-analysis"
					detail = "a proven child_process call used a dynamic or unsupported command outside the bounded literal and variable model; process and command semantics were not inferred"
				}
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					analysisArea,
					detail,
				)
			}
			if language == "javascript" && javascriptProcess.multiple {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					"javascript-process-command-analysis",
					"multiple proven child_process calls occurred on one source line; only the first call was analyzed",
				)
			}
			if language == "javascript" && javascriptProcess.unmodeledOuter {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					"javascript-process-binding-analysis",
					"a module child_process binding was referenced inside a function but could not be inherited because retained scope, shadowing, reassignment, or binding bounds were ambiguous; process semantics were not inferred",
				)
			}
		default:
			if networkCall {
				extractResolvedLanguageNetworkBudget(graph, lineContent, language, networkSemanticLine, analysisLine, networkDestinations, lineNo, evidenceID, lineBudget)
			}
		}
	}
	if language == "python" && len(ambiguousFunctions) > 0 {
		removeAmbiguousPythonDirectCallFeatures(graph, content.NodeID, ambiguousFunctions)
	}
	if language == "python" && pythonAPIBindings.unsupportedCalls {
		addPartialCoverageOnce(graph, content.NodeID, pythonAPIBindingAnalysisArea, "a recognized Python filesystem, environment, discovery, or network call lacked one stable import binding, exact call shape, or required argument; the call remained observational")
	}
	if language == "python" && pythonOrderedBindings.limited {
		addPartialCoverageOnce(graph, content.NodeID, pythonAPIBindingAnalysisArea, fmt.Sprintf("source-ordered Python binding analysis reached its limit of %d state changes; ordered promotion was disabled", maxPythonAPIOrderedBindingEvents))
	}
	if language == "python" && pythonOrderedBindings.badIndent {
		addPartialCoverageOnce(graph, content.NodeID, pythonAPIBindingAnalysisArea, "tab-indented Python source was outside exact ordered-binding analysis; affected local or conditional API calls were not promoted")
	}
	if language == "shell" {
		if detail := shellHeredocs.incompleteDetail(); detail != "" {
			addPartialCoverageOnce(graph, content.NodeID, "shell-heredoc-analysis", detail)
		}
	}
	if detail := variableState.omittedCoverageDetail(); detail != "" {
		addPartialCoverageOnce(graph, content.NodeID, "text-variable-analysis", detail)
	}
	if language == "javascript" && (javascriptProcessBindings.limited || javascriptProcessBindings.prescanLimited) {
		addPartialCoverageOnce(graph, content.NodeID, "javascript-process-binding-analysis", javascriptProcessBindings.coverageDetail())
	}
	if language == "javascript" && javascriptProcessBindings.hiddenBinding {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			"javascript-process-binding-analysis",
			"a child_process or os binding intersected an opaque or unsupported lexical use; affected process-command correlation was disabled",
		)
	}
	if language == "javascript" &&
		javascriptProcessBindings.prescan.dynamicCode {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			"javascript-dynamic-code-analysis",
			"an exact direct eval call intersected a retained lexical scope; process binding, runtime loader, module interop, and static command-value correlation were disabled for the affected scope without decoding or executing dynamic code",
		)
	}
	if language == "javascript" && javascriptProcessBindings.command.limited {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			"javascript-process-command-analysis",
			javascriptProcessBindings.command.limitDetail+"; later exact commands remained eligible for bounded analysis",
		)
	}
	if language == "javascript" && javascriptProcessBindings.prescan.bundlePartial {
		detail := javascriptProcessBindings.prescan.bundleDetail
		if detail == "" {
			detail = "JavaScript bundle module analysis was incomplete; affected numeric module aliases were not normalized"
		}
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			"javascript-bundle-module-analysis",
			detail,
		)
	}
	if language == "javascript" {
		extractJavaScriptSourceAPIs(graph, content, javascriptProcessBindings.prescan)
	}
	if language == "native-source" && strings.EqualFold(filepath.Ext(content.LogicalPath), ".rs") {
		extractRustSourceAPIs(graph, content, input.Source)
	}
	if language == "javascript" &&
		javascriptProcessBindings.prescan.index.Disposition == javaScriptStructuralUnsupported {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			"javascript-structural-analysis",
			javascriptProcessBindings.prescan.index.Detail,
		)
	}
	addTextDerivedCoverageOnce(graph, content, derivedBudget)
}

func sameJavaScriptStatementScope(
	statements []javaScriptCommandStatement,
) bool {
	if len(statements) < 2 {
		return true
	}
	scope := statements[0].scopeKey
	for _, statement := range statements[1:] {
		if statement.scopeKey != scope {
			return false
		}
	}
	return true
}

func shellCompoundAssignmentContext(line string, depth int) (inside bool, updated int, limited bool) {
	inside = depth > 0
	updated = depth
	commands := 0
	complete := visitCommands(line, func(command string) bool {
		if commands >= maxShellStatementsPerLine {
			return false
		}
		commands++
		fields, err := CommandFields(command)
		if err != nil || len(fields) == 0 {
			return true
		}
		switch strings.ToLower(fields[0]) {
		case "fi", "done", "esac":
			if updated > 0 {
				inside = true
				updated--
			}
		case "if", "for", "while", "until", "case", "select":
			inside = true
			updated++
		}
		return true
	})
	return inside, updated, !complete
}

func textExecutionScope(graph *behavior.Graph, content artifact.Content, function, scopeKey string, line int, scopes map[string]string) string {
	if function == "" {
		return content.ScopeID
	}
	if scopeID := scopes[scopeKey]; scopeID != "" {
		for i := range graph.Scopes {
			if graph.Scopes[i].ID == scopeID && line > graph.Scopes[i].LineEnd {
				graph.Scopes[i].LineEnd = line
				break
			}
		}
		return scopeID
	}
	scopeID := graph.AddScope(behavior.Scope{
		NodeID:       content.NodeID,
		ParentID:     content.ScopeID,
		Kind:         "function",
		Name:         function,
		SourceRole:   content.Role,
		Function:     function,
		Architecture: content.Architecture,
		LineStart:    line,
		LineEnd:      line,
	})
	if scopeID != "" {
		scopes[scopeKey] = scopeID
	}
	return scopeID
}

type functionState struct {
	name     string
	scopeKey string
	indent   int
}

const maxPythonLexicalScopeDepth = 128

type pythonLexicalScopeKind uint8

const (
	pythonScopeFunction pythonLexicalScopeKind = iota + 1
	pythonScopeAsyncFunction
	pythonScopeClass
)

type pythonLexicalScope struct {
	kind     pythonLexicalScopeKind
	name     string
	scopeKey string
	indent   int
}

type pythonLexicalDeclaration struct {
	kind     pythonLexicalScopeKind
	name     string
	topLevel bool
}

type pythonLexicalObservation struct {
	function          functionState
	scopeKey          string
	enclosingScopeKey string
	classBody         bool
	declaration       pythonLexicalDeclaration
}

// pythonLexicalScopeState tracks only the indentation-delimited namespaces
// needed by the bounded source recognizers. It is deliberately not a Python
// parser: unsupported runtime name resolution still fails closed. The stack
// prevents a nested or async declaration from being mistaken for module code,
// and restores the enclosing function after a nested scope ends.
type pythonLexicalScopeState struct {
	stack   []pythonLexicalScope
	limited bool
}

func (state *pythonLexicalScopeState) observe(raw, trimmed string, line int) pythonLexicalObservation {
	if state == nil || state.limited {
		return pythonLexicalObservation{}
	}
	if trimmed == "" {
		return state.current()
	}

	indent := leadingWhitespace(raw)
	for len(state.stack) > 0 && indent <= state.stack[len(state.stack)-1].indent {
		state.stack = state.stack[:len(state.stack)-1]
	}

	kind, name, declared := pythonLexicalDeclarationStart(trimmed)
	if !declared {
		return state.current()
	}
	if len(state.stack) >= maxPythonLexicalScopeDepth {
		state.limited = true
		return pythonLexicalObservation{}
	}

	declaration := pythonLexicalDeclaration{
		kind:     kind,
		name:     name,
		topLevel: len(state.stack) == 0 && indent == 0,
	}
	enclosingScopeKey := state.current().scopeKey
	state.stack = append(state.stack, pythonLexicalScope{
		kind:     kind,
		name:     name,
		scopeKey: fmt.Sprintf("python:%d:%s@%d", kind, name, line),
		indent:   indent,
	})
	observation := state.current()
	observation.declaration = declaration
	observation.enclosingScopeKey = enclosingScopeKey
	return observation
}

func (state *pythonLexicalScopeState) current() pythonLexicalObservation {
	if state == nil || len(state.stack) == 0 {
		return pythonLexicalObservation{}
	}
	current := state.stack[len(state.stack)-1]
	observation := pythonLexicalObservation{
		scopeKey:  current.scopeKey,
		classBody: current.kind == pythonScopeClass,
	}
	if current.kind == pythonScopeFunction || current.kind == pythonScopeAsyncFunction {
		observation.function = functionState{
			name:     current.name,
			scopeKey: current.scopeKey,
			indent:   current.indent,
		}
	}
	return observation
}

func pythonLexicalDeclarationStart(line string) (pythonLexicalScopeKind, string, bool) {
	line = strings.TrimSpace(line)
	if rest, ok := pythonKeywordTail(line, "async"); ok {
		if rest, ok = pythonKeywordTail(rest, "def"); ok {
			if name, ok := pythonDeclarationName(rest, true); ok {
				return pythonScopeAsyncFunction, name, true
			}
		}
		return 0, "", false
	}
	if rest, ok := pythonKeywordTail(line, "def"); ok {
		if name, ok := pythonDeclarationName(rest, true); ok {
			return pythonScopeFunction, name, true
		}
		return 0, "", false
	}
	if rest, ok := pythonKeywordTail(line, "class"); ok {
		if name, ok := pythonDeclarationName(rest, false); ok {
			return pythonScopeClass, name, true
		}
	}
	return 0, "", false
}

func pythonKeywordTail(line, keyword string) (string, bool) {
	if !strings.HasPrefix(line, keyword) || len(line) == len(keyword) {
		return "", false
	}
	next := line[len(keyword)]
	if next != ' ' && next != '\t' {
		return "", false
	}
	return strings.TrimLeft(line[len(keyword):], " \t"), true
}

func pythonDeclarationName(tail string, requireParameters bool) (string, bool) {
	if tail == "" || !identifierStartByte(tail[0]) {
		return "", false
	}
	end := 1
	for end < len(tail) && isIdentifierByte(tail[end]) {
		end++
	}
	name := tail[:end]
	rest := strings.TrimSpace(tail[end:])
	if requireParameters {
		return name, strings.HasPrefix(rest, "(") || strings.HasPrefix(rest, "[")
	}
	return name, strings.HasPrefix(rest, "(") || strings.HasPrefix(rest, "[") || strings.HasPrefix(rest, ":")
}

func updateFunctionState(language, raw, trimmed string, current functionState) functionState {
	if language != "python" && language != "javascript" && language != "jxa" && language != "native-source" && language != "rust-source" {
		return functionState{}
	}
	if trimmed == "" {
		return current
	}
	indent := leadingWhitespace(raw)
	if current.name != "" && indent <= current.indent && startsTopLevelStatement(trimmed) {
		current = functionState{}
	}
	if name, ok := functionStart(language, trimmed); ok {
		return functionState{name: name, indent: indent}
	}
	return current
}

func leadingWhitespace(value string) int {
	count := 0
	for _, r := range value {
		switch r {
		case ' ':
			count++
		case '\t':
			count += 4
		default:
			return count
		}
	}
	return count
}

func startsTopLevelStatement(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" || strings.HasPrefix(lower, "#") || strings.HasPrefix(lower, "//") {
		return false
	}
	for _, prefix := range []string{"def ", "class ", "function ", "func ", "if ", "for ", "while ", "try", "catch", "else", "elif ", "switch "} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return !strings.HasPrefix(lower, "}") && !strings.HasPrefix(lower, ")")
}

func functionStart(language, line string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(line))
	switch language {
	case "python":
		if !strings.HasPrefix(lower, "def ") {
			return "", false
		}
		name := functionName(line[4:])
		return name, name != ""
	case "javascript", "jxa":
		for _, prefix := range []string{"function ", "async function "} {
			if strings.HasPrefix(lower, prefix) {
				name := functionName(line[len(prefix):])
				return name, name != ""
			}
		}
	case "native-source":
		if strings.Contains(line, "(") && strings.HasSuffix(strings.TrimSpace(line), "{") {
			name := nativeFunctionName(line)
			return name, name != ""
		}
	case "rust-source":
		name := rustFunctionName(line)
		return name, name != ""
	}
	return "", false
}

func directFunctionCallsBudget(language, line, currentFunction string, knownFunctions map[string]bool, budget *textLineBudget) []string {
	switch language {
	case "python":
		return directTopLevelPythonFunctionCalls(line, currentFunction, knownFunctions)
	case "native-source":
		return directNativeSourceFunctionCallsBudget(line, currentFunction, knownFunctions, budget)
	default:
		return nil
	}
}

func directTopLevelPythonFunctionCalls(line, currentFunction string, knownFunctions map[string]bool) []string {
	if currentFunction != "" || len(knownFunctions) == 0 {
		return nil
	}
	expr := strings.TrimSpace(line)
	if strings.HasPrefix(expr, "if ") || strings.HasPrefix(expr, "for ") || strings.HasPrefix(expr, "while ") {
		return nil
	}
	if _, rhs, ok := strings.Cut(expr, "="); ok {
		expr = strings.TrimSpace(rhs)
	}
	name := leadingCallName(expr)
	if name == "" || !knownFunctions[name] {
		return nil
	}
	return []string{name}
}

func unambiguousPythonDirectCalls(calls []string, ambiguous map[string]bool) []string {
	if len(calls) == 0 || len(ambiguous) == 0 {
		return calls
	}
	out := calls[:0]
	for _, call := range calls {
		if !ambiguous[call] {
			out = append(out, call)
		}
	}
	return out
}

// removeAmbiguousPythonDirectCallFeatures conservatively withdraws earlier
// call-by-name candidates when a later declaration proves that the name maps
// to multiple retained function scopes. The current public call feature
// carries a function name rather than an exact callee scope ID, so keeping any
// such feature would let the relation linker connect it to every same-named
// declaration. Filtering once bounds this cleanup to O(retained features),
// independent of hostile declaration cardinality.
func removeAmbiguousPythonDirectCallFeatures(graph *behavior.Graph, nodeID string, ambiguous map[string]bool) {
	if graph == nil || nodeID == "" || len(ambiguous) == 0 {
		return
	}
	retained := graph.Features[:0]
	for _, feature := range graph.Features {
		if feature.NodeID == nodeID &&
			feature.Key == "script.function_call" &&
			ambiguous[feature.Value] {
			continue
		}
		retained = append(retained, feature)
	}
	graph.Features = retained
}

func leadingCallName(expr string) string {
	name := functionName(expr)
	if name == "" {
		return ""
	}
	rest := strings.TrimSpace(expr[len(name):])
	if strings.HasPrefix(rest, "(") {
		return name
	}
	return ""
}

func addDirectFunctionCallFeatures(graph *behavior.Graph, content artifact.Content, calls []string, evidenceID string) {
	for _, call := range calls {
		graph.AddFeature(behavior.Feature{
			NodeID:         content.NodeID,
			ScopeID:        content.ScopeID,
			Key:            "script.function_call",
			Value:          call,
			EvidenceIDs:    []string{evidenceID},
			Support:        behavior.SupportDirect,
			Execution:      executionContextForContent(content),
			SourceFunction: content.Function,
		})
	}
}

func functionName(value string) string {
	value = strings.TrimSpace(value)
	var out strings.Builder
	for _, r := range value {
		if r == '_' || r == '$' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			out.WriteRune(r)
			continue
		}
		break
	}
	return out.String()
}

func addLineEvidence(graph *behavior.Graph, content artifact.Content, line int, kind, value string) string {
	return graph.AddEvidence(behavior.Evidence{
		NodeID:   content.NodeID,
		ScopeID:  content.ScopeID,
		Logical:  content.LogicalPath,
		Physical: content.PhysicalPath,
		Line:     line,
		Method:   "text",
		Kind:     kind,
		Value:    compactTextEvidenceValue(value),
	})
}

const maxTextEvidenceValueRunes = 512

func compactTextEvidenceValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= maxTextEvidenceValueRunes {
		return value
	}
	runes := []rune(value)
	if len(runes) <= maxTextEvidenceValueRunes {
		return value
	}
	return string(runes[:maxTextEvidenceValueRunes]) + "..."
}

type commentMarker struct {
	token         string
	shellBoundary bool
}

func stripInlineComment(language, line string) string {
	switch language {
	case "shell":
		return stripLineComment(line, []commentMarker{{token: "#", shellBoundary: true}})
	case "python", "toml", "yaml":
		return stripLineComment(line, []commentMarker{{token: "#"}})
	case "javascript", "jxa", "native-source":
		return stripLineComment(line, []commentMarker{{token: "//"}, {token: "/*"}})
	case "applescript":
		return stripLineComment(line, []commentMarker{{token: "--"}})
	default:
		return line
	}
}

// stripSemanticComment removes language comments while carrying C-style
// block-comment state across lines. Go, JavaScript, JXA, and the supported
// native-source languages all permit an ordinary block-comment body whose
// lines need not begin with '*'. Treating those lines independently can turn
// examples inside comments into supported behavior.
func stripSemanticComment(language, line string, inBlockComment *bool) string {
	switch language {
	case "javascript", "jxa":
		return stripSlashComments(line, inBlockComment, true)
	case "native-source":
		return stripSlashComments(line, inBlockComment, false)
	default:
		return stripInlineComment(language, line)
	}
}

func stripJavaScriptStatementComments(statement string) string {
	lines := strings.Split(statement, "\n")
	masked := make([]string, 0, len(lines))
	inBlockComment := false
	for _, line := range lines {
		masked = append(masked, stripSlashComments(line, &inBlockComment, true))
	}
	return strings.Join(masked, "\n")
}

func stripSlashComments(line string, inBlockComment *bool, singleQuotedStrings bool) string {
	if inBlockComment == nil {
		state := false
		inBlockComment = &state
	}
	var out strings.Builder
	var quote byte
	escaped := false
	for i := 0; i < len(line); {
		if *inBlockComment {
			end := strings.Index(line[i:], "*/")
			if end < 0 {
				return out.String()
			}
			i += end + 2
			*inBlockComment = false
			if out.Len() > 0 {
				out.WriteByte(' ')
			}
			continue
		}
		ch := line[i]
		if escaped {
			out.WriteByte(ch)
			escaped = false
			i++
			continue
		}
		if quote != 0 {
			out.WriteByte(ch)
			switch ch {
			case '\\':
				escaped = true
			case quote:
				quote = 0
			}
			i++
			continue
		}
		if ch == '\'' && !singleQuotedStrings {
			if end, ok := nativeCharLiteralEnd(line, i); ok {
				out.WriteString(line[i : end+1])
				i = end + 1
				continue
			}
			// Rust lifetimes and C++ digit separators use apostrophes without
			// opening a string. Keep the byte as source and continue looking for
			// the actual line-comment marker.
			out.WriteByte(ch)
			i++
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			quote = ch
			out.WriteByte(ch)
			i++
			continue
		}
		if strings.HasPrefix(line[i:], "//") {
			break
		}
		if strings.HasPrefix(line[i:], "/*") {
			*inBlockComment = true
			i += 2
			if out.Len() > 0 {
				out.WriteByte(' ')
			}
			continue
		}
		out.WriteByte(ch)
		i++
	}
	return out.String()
}

// nativeCharLiteralEnd recognizes the bounded character/rune literal forms
// needed to keep comment markers inside native-source literals. It deliberately
// accepts only one rune or one escape sequence; this avoids pairing a Rust
// lifetime or C++ digit separator with an unrelated later apostrophe.
func nativeCharLiteralEnd(line string, start int) (int, bool) {
	if start < 0 || start+2 >= len(line) || line[start] != '\'' {
		return 0, false
	}
	i := start + 1
	if line[i] == '\\' {
		i++
		if i >= len(line) {
			return 0, false
		}
		switch line[i] {
		case 'x':
			i++
			startDigits := i
			for i < len(line) && i-startDigits < 2 && isHexByte(line[i]) {
				i++
			}
			if i == startDigits {
				return 0, false
			}
		case 'u':
			i++
			if i < len(line) && line[i] == '{' {
				i++
				startDigits := i
				for i < len(line) && i-startDigits < 6 && isHexByte(line[i]) {
					i++
				}
				if i == startDigits || i >= len(line) || line[i] != '}' {
					return 0, false
				}
				i++
			} else {
				for count := 0; count < 4; count++ {
					if i >= len(line) || !isHexByte(line[i]) {
						return 0, false
					}
					i++
				}
			}
		case 'U':
			i++
			for count := 0; count < 8; count++ {
				if i >= len(line) || !isHexByte(line[i]) {
					return 0, false
				}
				i++
			}
		default:
			if line[i] >= '0' && line[i] <= '7' {
				for count := 0; count < 3 && i < len(line) && line[i] >= '0' && line[i] <= '7'; count++ {
					i++
				}
			} else {
				i++
			}
		}
	} else {
		r, size := utf8.DecodeRuneInString(line[i:])
		if r == utf8.RuneError && size == 1 || r == '\n' || r == '\r' {
			return 0, false
		}
		i += size
	}
	if i >= len(line) || line[i] != '\'' {
		return 0, false
	}
	return i, true
}

func isHexByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func stripLineComment(line string, markers []commentMarker) string {
	var quote byte
	escaped := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			quote = ch
			continue
		}
		for _, marker := range markers {
			if strings.HasPrefix(line[i:], marker.token) && inlineCommentAllowed(line, i, marker) {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return line
}

func inlineCommentAllowed(line string, index int, marker commentMarker) bool {
	if !marker.shellBoundary {
		return true
	}
	return index == 0 || line[index-1] == ' ' || line[index-1] == '\t'
}

func assignment(language, line string, vars any) (string, string, bool) {
	var candidates []*regexp.Regexp
	switch language {
	case "shell":
		var name, value string
		count := 0
		valid := false
		visitCommands(line, func(command string) bool {
			count++
			if count > 1 {
				return false
			}
			fields, err := shellCommandFields(command)
			if err != nil {
				return false
			}
			if len(fields) > 0 && fields[0] == "export" {
				fields = fields[1:]
			}
			if len(fields) == 1 {
				name, value, valid = splitShellAssignment(fields[0])
			}
			return true
		})
		return name, value, valid && count == 1
	case "python":
		if match := rePyGetenv.FindStringSubmatch(line); len(match) == 3 {
			return match[1], strings.TrimSpace(match[2]), true
		}
		if name, value, ok := stringLiteralAssignment(line); ok {
			return name, value, true
		}
		return expressionAssignment(language, line, vars)
	case "javascript", "jxa":
		candidates = []*regexp.Regexp{reJSAssign}
	case "applescript":
		candidates = []*regexp.Regexp{reOSASet}
	default:
		if name, value, ok := stringLiteralAssignment(line); ok {
			return name, value, true
		}
		candidates = []*regexp.Regexp{reJSAssign}
	}
	for _, re := range candidates {
		if match := re.FindStringSubmatch(line); len(match) == 3 {
			return match[1], strings.TrimSpace(match[2]), true
		}
	}
	return "", "", false
}

func expressionAssignment(language, line string, vars any) (string, string, bool) {
	nameEnd := strings.Index(line, "=")
	if nameEnd <= 0 {
		return "", "", false
	}
	name := strings.TrimSpace(line[:nameEnd])
	if !identifierName(name) {
		return "", "", false
	}
	expr := strings.TrimSpace(line[nameEnd+1:])
	if language == "python" && unsafePythonAssignmentExpression(expr) {
		return "", "", false
	}
	value := resolveStringExpression(language, expr, vars)
	if value == "" {
		return "", "", false
	}
	return name, value, true
}

func unsafePythonAssignmentExpression(expr string) bool {
	lower := strings.ToLower(strings.TrimSpace(expr))
	if !strings.Contains(lower, "(") {
		return false
	}
	return !strings.HasPrefix(lower, "os.path.expanduser(") &&
		!strings.HasPrefix(lower, "os.path.join(")
}

func stringLiteralAssignment(line string) (string, string, bool) {
	nameEnd := strings.Index(line, "=")
	if nameEnd <= 0 {
		return "", "", false
	}
	name := strings.TrimSpace(line[:nameEnd])
	if !identifierName(name) {
		return "", "", false
	}
	rest := strings.TrimSpace(line[nameEnd+1:])
	value, ok := exactQuotedExpressionLiteral(rest)
	if !ok {
		return "", "", false
	}
	return name, value, true
}

// pythonIdentifierAssignmentTarget recognizes only a simple leading identifier
// write. The returned expression is non-empty only for ordinary "=" writes;
// augmented writes still return the target so stale bindings can be
// invalidated.
func pythonIdentifierAssignmentTarget(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" || !identifierStartByte(line[0]) {
		return "", ""
	}
	end := 1
	for end < len(line) && isIdentifierByte(line[end]) {
		end++
	}
	name := line[:end]
	rest := strings.TrimLeft(line[end:], " \t")
	if strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") {
		return name, strings.TrimSpace(rest[1:])
	}
	for _, operator := range []string{"**=", "//=", "<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "@=", "&=", "|=", "^="} {
		if strings.HasPrefix(rest, operator) {
			return name, ""
		}
	}
	return "", ""
}

func pythonAssignmentValueOversized(line string) bool {
	_, expression := pythonIdentifierAssignmentTarget(line)
	return len(expression) > maxTextVariableValueBytes
}

func identifierName(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		switch {
		case r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func leadingQuotedLiteralEndMode(value string, raw bool) (string, int, bool) {
	if value == "" {
		return "", 0, false
	}
	quote := value[0]
	var out strings.Builder
	escaped := false
	for i := 1; i < len(value); i++ {
		ch := value[i]
		if escaped {
			if raw {
				out.WriteByte('\\')
				out.WriteByte(ch)
			} else {
				switch ch {
				case '\\':
					out.WriteByte('\\')
				case 'n':
					out.WriteByte('\n')
				case 'r':
					out.WriteByte('\r')
				case 't':
					out.WriteByte('\t')
				case quote:
					out.WriteByte(ch)
				default:
					// Python preserves unknown escape sequences such as
					// "\\Public". Keeping the slash is also the conservative
					// choice for other source languages: dropping it invents a
					// different concrete path.
					out.WriteByte('\\')
					out.WriteByte(ch)
				}
			}
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == quote {
			return out.String(), i + 1, true
		}
		out.WriteByte(ch)
	}
	return "", 0, false
}

func stringLiteralPrefix(value string) (literal string, raw bool) {
	value = strings.TrimSpace(value)
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '\'', '"', '`':
			prefix := strings.ToLower(value[:index])
			for _, ch := range prefix {
				if !strings.ContainsRune("rubf", ch) {
					return value, false
				}
			}
			return value[index:], strings.Contains(prefix, "r")
		default:
			if value[index] == ' ' || value[index] == '\t' {
				return value, false
			}
		}
	}
	return value, false
}

func exactQuotedExpressionLiteral(value string) (string, bool) {
	value = strings.TrimSpace(value)
	literal, raw := stringLiteralPrefix(value)
	if literal == "" || literal[0] != '"' && literal[0] != '\'' && literal[0] != '`' {
		return "", false
	}
	decoded, end, ok := leadingQuotedLiteralEndMode(literal, raw)
	if !ok || strings.TrimSpace(literal[end:]) != "" {
		return "", false
	}
	return decoded, true
}

func resolveAssignedValue(language, value string, vars any) string {
	if language == "python" {
		return expandFormatPlaceholders(value, vars)
	}
	return value
}

func expandFormatPlaceholders(value string, vars any) string {
	return expandTextFormatPlaceholders(value, vars)
}

func expandSimpleVars(language, line string, vars any) string {
	return expandTextSimpleVariables(language, line, vars)
}

func contentLanguage(content artifact.Content) string {
	filenameLanguage := artifact.Language(content.LogicalPath)
	if content.HostSelectionUnresolved {
		// An unresolved host bars host-backed script semantics, but it does not
		// erase syntax established by an exact source filename. Native and Java
		// source observations remain UNKNOWN unless a separate execution
		// relationship supplies connectivity.
		if filenameLanguage == "native-source" || filenameLanguage == "java-source" {
			return filenameLanguage
		}
		return ""
	}
	if content.SemanticLanguage != "" {
		return content.SemanticLanguage
	}
	if len(content.Data) >= 2 && content.Data[0] == '#' && content.Data[1] == '!' {
		if inferred := artifact.ShebangLanguage(content.Data); inferred != "" {
			return inferred
		}
		// Rust inner attributes begin with #![...]. They resemble an unsupported
		// kernel interpreter declaration but the exact .rs filename still proves
		// source syntax. It does not prove that the source is directly runnable.
		if filenameLanguage == "native-source" || filenameLanguage == "java-source" {
			return filenameLanguage
		}
		// An explicit but malformed or unsupported interpreter declaration is
		// stronger contrary evidence than filename or body-language heuristics.
		return ""
	}
	if filenameLanguage != "" {
		return filenameLanguage
	}
	// Executable mode bits and body-language resemblance do not select an
	// interpreter. Unsupported or absent declarations stay unresolved unless a
	// trusted structural adapter supplied SemanticLanguage above.
	return ""
}

func semanticTextAllowed(content artifact.Content, language string) bool {
	if language == "" {
		return false
	}
	if !semanticTextLanguage(language) {
		return false
	}
	if content.BehaviorAnalysisForced {
		return true
	}
	switch content.Role {
	case "documentation", "test", "fixture", "vendor", "vendor/toolchain", "packaged-content":
		return false
	default:
		return true
	}
}

func semanticTextLanguage(language string) bool {
	return scriptSemanticLanguage(language) || language == "native-source"
}

func unresolvedTextSemanticsRelevant(content artifact.Content) bool {
	if content.BehaviorAnalysisForced {
		return content.Kind == "script" || content.Executable || content.Role == "target" || content.Role == "unknown" || content.Role == ""
	}
	switch content.Role {
	case "documentation", "test", "fixture", "vendor", "vendor/toolchain", "generated/build", "packaged-content":
		return false
	default:
		return content.Kind == "script" || content.Executable || content.Role == "target" || content.Role == "unknown" || content.Role == ""
	}
}

func lineMayHaveSemanticsBudget(language, line string, budget *textLineBudget) bool {
	lower := strings.ToLower(line)
	if language == "shell" {
		if fields := FirstShellCommandFields(line); len(fields) > 0 {
			if sharedShellCommandTool(filepath.Base(fields[0])) {
				return true
			}
			if _, ok := recognizeLocalAgentInvocation(fields); ok {
				return true
			}
		}
	}
	if sensitiveReadContext(language, line) || languageNetworkCallObserved(language, line) || reNativeExec.MatchString(line) {
		return true
	}
	if language == "python" && strings.Contains(lower, ".write(") && strings.Contains(lower, ".content") {
		return true
	}
	if (language == "javascript" || language == "jxa") && javascriptFileWrite(lower) && javascriptResponseBodyMarker(lower) {
		return true
	}
	for _, token := range []string{
		"curl", "wget", "chmod", "xattr", "spctl", "launchctl", "security", "dscl", "zip", "unzip", "tar", "ditto",
		"base64", "cat", "cp", "deno", "echo", "installer", "mv", "node", "open", "plutil", "printf", "python", "sqlite3", "tee",
		"pbpaste", "pbcopy", "screencapture", "setfile", "chflags", "tccutil",
		"do shell script", "display dialog", "open location", "subprocess.", "os.system(", "child_process",
		".exec(", ".execsync(", ".execfile(", ".execfilesync(", ".spawn(", ".spawnsync(",
		"readfilesync", "readfile(", "createreadstream(", "sqlite", "secitemcopymatching", "nsclipboard",
		"nspasteboard", "pasteboardcopyitemflavordata", "pasteboardputitemflavor", "cgwindowlistcreateimage", "task_for_pid", "mach_vm_", "thread_create_running",
		"cgeventtapcreate", "audioqueuenewinput", "avcapturephotooutput", "avcapturestillimageoutput", "nsworkspace", "smloginitemsetenabled", "smappservice",
	} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	if _, ok := sensitiveResourceBudget(line, budget); ok {
		return true
	}
	for _, quoted := range quotedValuesBudget(line, budget) {
		if _, ok := sensitiveResourceBudget(quoted, budget); ok {
			return true
		}
	}
	if language == "shell" {
		fields, err := CommandFields(line)
		if shellFieldLimitReached(err) {
			budget = textBudgetOrStandalone(budget)
			budget.markLimited("shell argv field or decoded-byte limit reached", false)
			return false
		}
		if err == nil && len(fields) > 0 {
			fields, err = normalizeCommandFieldsChecked(fields)
			if shellFieldLimitReached(err) {
				budget = textBudgetOrStandalone(budget)
				budget.markLimited("shell argv field or decoded-byte limit reached in a wrapped command", false)
				return false
			}
			return len(fields) > 0 && looksExecutable(fields[0])
		}
	}
	return false
}

const (
	maxSemanticContinuationLines = 12
	maxSemanticContinuationBytes = 8192
)

// joinPythonLexicalDeclaration retains one bounded multiline def/class header
// as a single lexical observation. Without this pre-pass, the closing header
// line has the declaration's indentation and would pop the just-opened scope,
// causing the dormant body to be analyzed as module execution. An incomplete
// header fails closed because its body boundary cannot be established safely.
func joinPythonLexicalDeclaration(lines []string, start int, firstRaw, first string, inBlockComment *bool) (string, string, int, bool) {
	if _, _, declared := pythonLexicalDeclarationStart(first); !declared || bracketDepth(first) <= 0 {
		return firstRaw, first, start, false
	}

	indent := firstRaw[:len(firstRaw)-len(strings.TrimLeft(firstRaw, " \t"))]
	parts := []string{first}
	total := len(first)
	last := start
	for index := start + 1; index < len(lines) && index <= start+maxSemanticContinuationLines; index++ {
		last = index
		next := strings.TrimSpace(stripSemanticComment("python", lines[index], inBlockComment))
		if next == "" {
			continue
		}
		total += len(next) + 1
		if total > maxSemanticContinuationBytes {
			return indent + strings.Join(parts, " "), strings.Join(parts, " "), last, true
		}
		parts = append(parts, next)
		joined := strings.Join(parts, " ")
		if bracketDepth(joined) <= 0 {
			return indent + joined, joined, index, false
		}
	}
	joined := strings.Join(parts, " ")
	return indent + joined, joined, last, true
}

func joinSemanticContinuation(language string, lines []string, start int, first string, inBlockComment *bool) (string, int) {
	if !multilineSemanticCandidate(language, first) {
		return first, start
	}
	if bracketDepth(first) <= 0 {
		return first, start
	}
	var parts []string
	parts = append(parts, first)
	total := len(first)
	last := start
	for i := start + 1; i < len(lines) && i <= start+maxSemanticContinuationLines; i++ {
		next := strings.TrimSpace(stripSemanticComment(language, lines[i], inBlockComment))
		if next == "" {
			continue
		}
		last = i
		total += len(next) + 1
		if total > maxSemanticContinuationBytes {
			return strings.Join(parts, " "), last
		}
		parts = append(parts, next)
		joined := strings.Join(parts, " ")
		if bracketDepth(joined) <= 0 {
			return joined, i
		}
	}
	return strings.Join(parts, " "), last
}

func multilineSemanticCandidate(language, line string) bool {
	if language != "python" && language != "javascript" && language != "jxa" {
		return false
	}
	return languageNetworkCallObserved(language, line)
}

func bracketDepth(line string) int {
	depth := 0
	var quote rune
	escaped := false
	for _, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' || r == '`' {
			quote = r
			continue
		}
		switch r {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return depth
}

func shellBase(value string) string {
	if idx := strings.LastIndex(value, "/"); idx >= 0 {
		value = value[idx+1:]
	}
	return value
}

func commonShellTool(tool string) bool {
	switch tool {
	case "curl", "wget", "chmod", "chown", "xattr", "spctl", "launchctl", "defaults", "plutil",
		"osascript", "open", "security", "dscl", "ditto", "zip", "unzip", "tar", "base64", "mktemp",
		"hdiutil", "installer", "pkgutil", "killall", "pkill", "sudo", "sh", "bash", "zsh",
		"python", "python3", "node", "rm", "mv", "cp", "sqlite3", "system_profiler", "sysctl",
		"uuidgen", "md5", "sleep", "nohup", "cat", "grep", "tr", "awk", "dig", "echo", "printf",
		"screencapture", "pbpaste", "pbcopy", "SetFile", "chflags", "tccutil":
		return true
	default:
		return false
	}
}

func staticAssignedURLsBudget(line string, budget *textLineBudget) []string {
	var out []string
	for _, destination := range destinationsBudget(line, budget) {
		parsed, err := url.Parse(destination)
		if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
			continue
		}
		out = append(out, destination)
	}
	return out
}

func staticURLAssignmentName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return name == "url" || name == "uri" ||
		strings.HasPrefix(name, "url_") || strings.HasPrefix(name, "uri_") ||
		strings.HasSuffix(name, "_url") || strings.HasSuffix(name, "_uri") ||
		strings.Contains(name, "_url_") || strings.Contains(name, "_uri_")
}

func addStaticAssignedURLs(graph *behavior.Graph, content artifact.Content, language string, destinations []string, evidenceID string) {
	if len(destinations) == 0 {
		return
	}
	for _, destination := range destinations {
		graph.AddFeature(behavior.Feature{
			NodeID:         content.NodeID,
			ScopeID:        content.ScopeID,
			Key:            "network.url",
			Value:          destination,
			Qualifiers:     map[string]string{"context": "static-assignment", "language": language},
			EvidenceIDs:    []string{evidenceID},
			Support:        behavior.SupportCorroborated,
			SourceFunction: content.Function,
		})
	}
}

func extractResolvedLanguageNetworkBudget(graph *behavior.Graph, content artifact.Content, language, line, expandedLine string, destinations []string, lineNo int, evidenceID string, budget *textLineBudget) {
	kind := languageNetworkOperationKind(language, line)
	bindings := networkOperationBindings(kind, destinations, "", "")
	if target := languageDownloadTargetBudget(language, expandedLine, budget); target != "" {
		kind = behavior.OperationNetworkDownload
		bindings = networkOperationBindings(kind, destinations, target, "")
	}
	evidenceIDs := mergeEvidenceIDs(append([]string{evidenceID}, content.SupportingEvidenceIDs...)...)
	operationID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID:    content.NodeID,
		ScopeID:          content.ScopeID,
		Kind:             kind,
		ResourceBindings: bindings,
		EvidenceIDs:      evidenceIDs,
		Support:          behavior.SupportCorroborated,
		Execution:        executionContextForContent(content),
		Line:             lineNo,
	})
	observation := networkImplementationObservation(operationID, content, language, evidenceID)
	observation.EvidenceIDs = append([]string(nil), evidenceIDs...)
	graph.AddNetworkImplementation(observation)
}

func languageNetworkAssignmentWithDestinations(language, line string, destinations []string) (string, []string, bool) {
	name, _, ok := requestAssignmentParts(language, line)
	if !ok {
		return "", nil, false
	}
	if len(destinations) == 0 {
		return "", nil, false
	}
	return name, destinations, true
}

func requestAssignmentParts(language, line string) (string, string, bool) {
	nameEnd := strings.Index(line, "=")
	if nameEnd <= 0 {
		return "", "", false
	}
	name := strings.TrimSpace(line[:nameEnd])
	if language == "javascript" || language == "jxa" {
		for _, declaration := range []string{"const", "let", "var"} {
			if strings.HasPrefix(name, declaration) && len(name) > len(declaration) && isSourceSpace(name[len(declaration)]) {
				name = strings.TrimSpace(name[len(declaration):])
				break
			}
		}
	}
	if !identifierName(name) {
		return "", "", false
	}
	return name, strings.TrimSpace(line[nameEnd+1:]), true
}

func extractResolvedLanguageRequestWrite(graph *behavior.Graph, content artifact.Content, language, target string, destinations []string, lineNo int, evidenceID string) {
	evidenceIDs := mergeEvidenceIDs(append([]string{evidenceID}, content.SupportingEvidenceIDs...)...)
	operationID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID:    content.NodeID,
		ScopeID:          content.ScopeID,
		Kind:             behavior.OperationNetworkDownload,
		ResourceBindings: networkOperationBindings(behavior.OperationNetworkDownload, destinations, target, ""),
		EvidenceIDs:      evidenceIDs,
		Support:          behavior.SupportCorroborated,
		Execution:        executionContextForContent(content),
		Line:             lineNo,
	})
	observation := networkImplementationObservation(operationID, content, language, evidenceID)
	observation.EvidenceIDs = append([]string(nil), evidenceIDs...)
	graph.AddNetworkImplementation(observation)
}

func languageRequestWriteTargetBudget(language, line string, requestVars any, budget *textLineBudget) (string, []string, bool) {
	if textRequestVariableCount(requestVars) == 0 {
		return "", nil, false
	}
	lower := strings.ToLower(line)
	switch language {
	case "python":
		if !strings.Contains(lower, ".write(") || !strings.Contains(lower, ".content") {
			return "", nil, false
		}
		target := firstPythonOpenPathBudget(line, budget)
		if target == "" {
			return "", nil, false
		}
		name := firstRequestVariableWithSuffix(line, requestVars, func(suffix string) bool {
			return strings.HasPrefix(suffix, ".content")
		})
		if name != "" {
			destinations, _ := lookupTextRequestVariable(requestVars, name)
			return target, destinations, true
		}
	case "javascript", "jxa":
		if !javascriptFileWrite(lower) || !javascriptResponseBodyMarker(lower) {
			return "", nil, false
		}
		target := firstJavaScriptWritePathBudget(line, lower, budget)
		if target == "" {
			return "", nil, false
		}
		name := firstRequestVariableWithSuffix(line, requestVars, javascriptResponseSuffix)
		if name != "" {
			destinations, _ := lookupTextRequestVariable(requestVars, name)
			return target, destinations, true
		}
	}
	return "", nil, false
}

func firstRequestVariableWithSuffix(line string, requestVars any, accepts func(string) bool) string {
	budget := requestVariableBudget(requestVars)
	if budget != nil && !budget.chargeExpansionWork(int64(len(line))) {
		return ""
	}
	for i := 0; i < len(line); {
		if !identifierStartByte(line[i]) {
			i++
			continue
		}
		end := i + 1
		for end < len(line) && isIdentifierByte(line[end]) {
			end++
		}
		name := line[i:end]
		if _, ok := lookupTextRequestVariable(requestVars, name); ok && accepts(line[end:]) {
			return name
		}
		i = end
	}
	return ""
}

func requestVariableBudget(values any) *textVariableState {
	switch vars := values.(type) {
	case textRequestVariableView:
		return vars.state
	case *textRequestVariableView:
		if vars != nil {
			return vars.state
		}
	}
	return nil
}

func firstPythonOpenPathBudget(line string, budget *textLineBudget) string {
	lower := strings.ToLower(line)
	call := callTextAfterMarker(line, lower, "open(")
	if call == "" {
		return ""
	}
	args := boundedTextCallArguments(call, "file-write arguments", budget)
	if len(args) == 0 {
		return ""
	}
	return firstDownloadPathBudget(args[0], budget)
}

func firstJavaScriptWritePathBudget(line, lower string, budget *textLineBudget) string {
	for _, marker := range []string{"writefilesync(", "writefile("} {
		call := callTextAfterMarker(line, lower, marker)
		if call == "" {
			continue
		}
		args := boundedTextCallArguments(call, "file-write arguments", budget)
		if len(args) == 0 {
			continue
		}
		if target := firstDownloadPathBudget(args[0], budget); target != "" {
			return target
		}
	}
	return ""
}

func containsJavaScriptResponseBody(line, name string) bool {
	for {
		idx := strings.Index(line, name)
		if idx < 0 {
			return false
		}
		end := idx + len(name)
		if (idx == 0 || !isIdentifierByte(line[idx-1])) &&
			(end >= len(line) || !isIdentifierByte(line[end])) &&
			javascriptResponseSuffix(line[end:]) {
			return true
		}
		line = line[end:]
	}
}

func javascriptResponseBodyMarker(line string) bool {
	for _, marker := range []string{".arraybuffer(", ".text(", ".blob("} {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return containsJavaScriptPropertyMarker(line, ".body") || containsJavaScriptPropertyMarker(line, ".data")
}

func javascriptResponseSuffix(suffix string) bool {
	lower := strings.ToLower(suffix)
	for _, marker := range []string{".arraybuffer(", ".text(", ".blob("} {
		if strings.HasPrefix(lower, marker) {
			return true
		}
	}
	for _, marker := range []string{".body", ".data"} {
		if strings.HasPrefix(lower, marker) && (len(lower) == len(marker) || !isIdentifierByte(lower[len(marker)])) {
			return true
		}
	}
	return false
}

func containsJavaScriptPropertyMarker(line, marker string) bool {
	for {
		idx := strings.Index(line, marker)
		if idx < 0 {
			return false
		}
		end := idx + len(marker)
		if end >= len(line) || !isIdentifierByte(line[end]) {
			return true
		}
		line = line[end:]
	}
}

func languageNetworkDestinationsBudget(language, line string, vars any, budget *textLineBudget) []string {
	lower := strings.ToLower(line)
	if language == "python" {
		marker, open, ok := pythonNetworkCallLocation(line)
		if !ok {
			return nil
		}
		call := callTextAtOpen(line, open)
		if call == "" {
			return nil
		}
		args := boundedTextCallArguments(call, "network-call arguments", budget)
		for _, index := range networkDestinationArgumentIndexes(marker, args) {
			if index >= len(args) {
				continue
			}
			if dest := destinationsBudget(resolveNetworkExpression(language, args[index], vars), budget); len(dest) > 0 {
				return dest
			}
		}
		return nil
	}
	for _, marker := range languageNetworkCallMarkers(language) {
		call := callTextAfterMarker(line, lower, marker)
		if call == "" {
			continue
		}
		args := boundedTextCallArguments(call, "network-call arguments", budget)
		for _, index := range networkDestinationArgumentIndexes(marker, args) {
			if index >= len(args) {
				continue
			}
			value := resolveNetworkExpression(language, args[index], vars)
			if language == "javascript" {
				// A selected API argument is a complete value, not prose to
				// search for a URL substring. Preserve query and path bytes.
				if exactJavaScriptHTTPURL(value) {
					return []string{value}
				}
				continue
			}
			if dest := destinationsBudget(value, budget); len(dest) > 0 {
				return dest
			}
		}
		return nil
	}
	return nil
}

func resolveNetworkExpression(language, expr string, vars any) string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return ""
	}
	if dynamicInterpolatedStringExpression(language, expr) {
		return ""
	}
	resolved := resolveStringExpression(language, expr, vars)
	if resolved != "" {
		return resolved
	}
	// A failed expression resolution is not an exact destination. Scanning the
	// original expression can turn a formatted/template string or one literal
	// fragment of a concatenation into a fabricated partial URL. The enclosing
	// API call remains a network operation with an unresolved endpoint.
	return ""
}

func dynamicInterpolatedStringExpression(language, expression string) bool {
	switch language {
	case "python":
		parts, limited := splitStringConcatLimited(expression, maxTextStringExpressionParts)
		if limited {
			return true
		}
		for _, part := range parts {
			part = strings.TrimSpace(part)
			quote := strings.IndexAny(part, "'\"")
			if quote <= 0 {
				continue
			}
			prefix := strings.ToLower(part[:quote])
			validPrefix := true
			for _, current := range prefix {
				if !strings.ContainsRune("rubft", current) {
					validPrefix = false
					break
				}
			}
			if validPrefix && (strings.Contains(prefix, "f") || strings.Contains(prefix, "t")) {
				return true
			}
		}
	case "javascript", "jxa":
		return strings.Contains(expression, "${") && strings.Contains(expression, "`")
	}
	return false
}

func resolveStringExpression(language, expr string, vars any) string {
	return resolveStringExpressionDepth(language, expr, vars, 0)
}

func resolveStringExpressionDepth(language, expr string, vars any, depth int) string {
	switch language {
	case "python", "javascript", "jxa":
	default:
		return ""
	}
	// Literal decoders do not implement Python f/t-string or JavaScript
	// template interpolation. Reject those forms before a quoted-literal lane
	// can turn their known prefix into a fabricated exact path, command, or URL.
	// The JavaScript command resolver may still call this function after its
	// separate exact constant-template resolver has failed.
	if dynamicInterpolatedStringExpression(language, expr) {
		return ""
	}
	budget := textVariableBudget(vars)
	if depth >= maxTextStringExpressionDepth {
		if budget != nil {
			budget.markLimited(fmt.Sprintf("string expression nesting limit %d reached", maxTextStringExpressionDepth))
		}
		return ""
	}
	if budget != nil && !budget.chargeExpansionWork(int64(len(expr))) {
		return ""
	}
	if language == "python" {
		if value := resolvePythonPathExpressionDepth(expr, vars, depth); value != "" {
			return value
		}
		if budget != nil && budget.limited {
			return ""
		}
	}
	parts, truncated := splitStringConcatLimited(expr, maxTextStringExpressionParts)
	if truncated {
		if budget != nil {
			budget.markLimited(fmt.Sprintf("string expression part limit %d reached", maxTextStringExpressionParts))
		}
		return ""
	}
	if len(parts) == 0 {
		return ""
	}
	var out strings.Builder
	resolved := false
	substitutions := 0
	appendValue := func(value string, substitution bool) bool {
		if out.Len() > maxTextVariableExpandedLineBytes-len(value) {
			if budget != nil {
				budget.markLimited(fmt.Sprintf("resolved expression limit %d bytes reached", maxTextVariableExpandedLineBytes))
			}
			return false
		}
		if substitution {
			if substitutions >= maxTextVariableSubstitutionsPerLine {
				if budget != nil {
					budget.markLimited(fmt.Sprintf("variable substitution limit %d reached in one expression", maxTextVariableSubstitutionsPerLine))
				}
				return false
			}
			if budget != nil && !budget.chargeExpansionWork(int64(len(value))) {
				return false
			}
			substitutions++
		}
		out.WriteString(value)
		return true
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if value, ok := quotedExpressionLiteral(part); ok {
			if !appendValue(value, false) {
				return ""
			}
			resolved = true
			continue
		}
		if value, ok := lookupTextVariable(vars, part); ok {
			if !appendValue(value, true) {
				return ""
			}
			resolved = true
			continue
		}
		// A partially reconstructed expression is not an exact value. Never
		// concatenate the known literals around an unresolved component: doing
		// so fabricates resources such as /Users//Library/... and can create
		// false cross-operation flow.
		return ""
	}
	if !resolved {
		return ""
	}
	return out.String()
}

func resolvePythonPathExpression(expr string, vars any) string {
	return resolvePythonPathExpressionDepth(expr, vars, 0)
}

func resolvePythonPathExpressionDepth(expr string, vars any, depth int) string {
	expr = strings.TrimSpace(expr)
	lower := strings.ToLower(expr)
	switch {
	case strings.HasPrefix(lower, "os.path.expanduser("):
		call := callTextAfterMarker(expr, lower, "os.path.expanduser(")
		args, truncated := splitCallArgumentsLimited(call, maxTextStringExpressionArguments)
		if truncated {
			markTextStringExpressionLimited(vars, fmt.Sprintf("string expression argument limit %d reached", maxTextStringExpressionArguments))
			return ""
		}
		if len(args) == 0 {
			return ""
		}
		return resolveStringExpressionDepth("python", args[0], vars, depth+1)
	case strings.HasPrefix(lower, "os.path.join("):
		call := callTextAfterMarker(expr, lower, "os.path.join(")
		args, truncated := splitCallArgumentsLimited(call, maxTextStringExpressionArguments)
		if truncated {
			markTextStringExpressionLimited(vars, fmt.Sprintf("string expression argument limit %d reached", maxTextStringExpressionArguments))
			return ""
		}
		parts := make([]string, 0, len(args))
		partBytes := 0
		for _, arg := range args {
			value := resolveStringExpressionDepth("python", arg, vars, depth+1)
			if value == "" {
				return ""
			}
			if partBytes > maxTextVariableExpandedLineBytes-len(value) {
				markTextStringExpressionLimited(vars, fmt.Sprintf("resolved expression limit %d bytes reached", maxTextVariableExpandedLineBytes))
				return ""
			}
			partBytes += len(value)
			parts = append(parts, value)
		}
		return joinPythonPath(parts)
	default:
		return ""
	}
}

func markTextStringExpressionLimited(vars any, detail string) {
	if budget := textVariableBudget(vars); budget != nil {
		budget.markLimited(detail)
	}
}

func joinPythonPath(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	normalized := make([]string, len(parts))
	lastRoot := 0
	for i, part := range parts {
		normalized[i] = filepath.ToSlash(part)
		if i > 0 && strings.HasPrefix(normalized[i], "/") {
			lastRoot = i
		}
	}
	if len(normalized)-lastRoot == 1 {
		return normalized[lastRoot]
	}
	return path.Join(normalized[lastRoot:]...)
}

func splitStringConcatLimited(expr string, maxParts int) ([]string, bool) {
	var parts []string
	var quote rune
	escaped := false
	start := 0
	for i, r := range expr {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' || r == '`' {
			quote = r
			continue
		}
		if r == '+' {
			parts = append(parts, expr[start:i])
			if maxParts > 0 && len(parts) >= maxParts {
				return nil, true
			}
			start = i + 1
		}
	}
	parts = append(parts, expr[start:])
	return parts, false
}

func quotedExpressionLiteral(expr string) (string, bool) {
	return exactQuotedExpressionLiteral(expr)
}

func languageNetworkCallMarkers(language string) []string {
	switch language {
	case "python":
		return []string{
			"requests.get(", "requests.post(", "requests.put(", "requests.patch(", "requests.request(",
			"httpx.get(", "httpx.post(", "httpx.put(", "httpx.patch(", "httpx.request(",
			"urllib.request.urlopen(", "urllib.request.urlretrieve(",
			"urllib2.urlopen(", "urllib2.Request(",
		}
	case "javascript", "jxa":
		return []string{
			"bun.fetch(", "fetch(",
			"axios.get(", "axios.post(", "axios.put(", "axios.patch(", "axios.request(",
		}
	default:
		return nil
	}
}

func languageNetworkCallObserved(language, line string) bool {
	if language == "python" {
		_, _, ok := pythonNetworkCallLocation(line)
		return ok
	}
	return reFetch.MatchString(line)
}

func pythonNetworkCallLocation(line string) (string, int, bool) {
	for _, marker := range languageNetworkCallMarkers("python") {
		if index := pythonMarkerLocation(line, marker); index >= 0 {
			return marker, index + len(marker) - 1, true
		}
	}
	return "", 0, false
}

func pythonNetworkCallBinding(line string, lineNo int, bindings *pythonStableAPIBindings) (bindingName, canonicalLine string, observed, proven bool) {
	canonicalLine = line
	if bindings == nil {
		return "", canonicalLine, languageNetworkCallObserved("python", line), false
	}
	calls, limited := pythonQualifiedCalls(pythonCodeContext(line), maxPythonAPICallsPerLine+1)
	if limited || len(calls) > maxPythonAPICallsPerLine {
		bindings.unsupportedCalls = true
		if len(calls) > maxPythonAPICallsPerLine {
			calls = calls[:maxPythonAPICallsPerLine]
		}
	}
	for _, call := range calls {
		components := strings.Split(call.value, ".")
		if len(components) < 2 {
			continue
		}
		root := components[0]
		canonical := call.value
		proof, bound := bindings.bindings[root]
		if bound {
			canonical = proof.canonical + "." + strings.Join(components[1:], ".")
		}
		if _, _, recognized := pythonNetworkCallLocation(canonical + "("); !recognized {
			continue
		}
		observed = true
		if !bound || proof.line >= lineNo {
			return "", canonicalLine, true, false
		}
		open := pythonSkipHorizontal(line, call.byteOffset+len(call.value))
		argumentsText, _, exact, _ := exactPythonCallContent(line, open, maxPythonAPICallBytes)
		if !exact {
			bindings.unsupportedCalls = true
			return "", canonicalLine, true, false
		}
		arguments, argumentLimited, malformed := exactPythonArguments(argumentsText, maxTextStringExpressionArguments)
		if argumentLimited || malformed || !pythonNetworkArgumentsSupported(canonical, arguments) {
			bindings.unsupportedCalls = true
			return "", canonicalLine, true, false
		}
		canonicalLine = line[:call.byteOffset] + canonical + line[call.byteOffset+len(call.value):]
		return root, canonicalLine, true, true
	}
	return "", canonicalLine, observed, false
}

func pythonNetworkArgumentsSupported(canonical string, arguments []string) bool {
	minimum := 1
	destinationIndex := 0
	destinationParameter := "url"
	if canonical == "requests.request" || canonical == "httpx.request" {
		minimum = 2
		destinationIndex = 1
	}
	if canonical == "urllib.request.urlopen" || canonical == "urllib2.urlopen" {
		destinationParameter = "url"
	} else if canonical == "urllib.request.urlretrieve" {
		destinationParameter = "url"
	}
	if len(arguments) < minimum || len(arguments) > maxTextStringExpressionArguments {
		return false
	}
	positional, keywords, stable := pythonStableArgumentShape(arguments)
	if !stable || len(positional) <= destinationIndex && keywords[destinationParameter] == "" {
		return false
	}
	if destinationIndex == 1 && len(positional) == 0 && keywords["method"] == "" {
		return false
	}
	return len(positional) <= destinationIndex || keywords[destinationParameter] == ""
}

func pythonMarkerLocation(line, marker string) int {
	for index := 0; index < len(line); {
		switch line[index] {
		case '#':
			return -1
		case '\'', '"':
			next, ok := skipPythonQuoted(line, index)
			if !ok {
				return -1
			}
			index = next
			continue
		}
		if index > 0 && pythonIdentifierByte(line[index-1]) {
			index++
			continue
		}
		if strings.HasPrefix(line[index:], marker) {
			return index
		}
		index++
	}
	return -1
}

func pythonCodeContext(line string) string {
	masked := []byte(line)
	for index := 0; index < len(line); {
		switch line[index] {
		case '#':
			for cursor := index; cursor < len(masked); cursor++ {
				masked[cursor] = ' '
			}
			return string(masked)
		case '\'', '"':
			next, ok := skipPythonQuoted(line, index)
			if !ok {
				next = len(line)
			}
			for cursor := index; cursor < next; cursor++ {
				masked[cursor] = ' '
			}
			index = next
		default:
			index++
		}
	}
	return string(masked)
}

func networkDestinationArgumentIndexes(marker string, args []string) []int {
	switch marker {
	case "requests.request(", "httpx.request(":
		if len(args) > 1 && httpMethodLiteral(args[0]) {
			return []int{1}
		}
	case "axios.request(":
		return []int{0}
	}
	return []int{0}
}

func httpMethodLiteral(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.Trim(value, `"'`+"`")
	switch value {
	case "get", "post", "put", "patch", "delete", "head", "options":
		return true
	default:
		return false
	}
}

func languageNetworkOperationKind(language, line string) behavior.OperationKind {
	if languageUploadCall(language, line) {
		return "network.upload"
	}
	return "network.connect"
}

func languageUploadCall(language, line string) bool {
	lower := strings.ToLower(line)
	switch language {
	case "python":
		if strings.Contains(lower, "urllib.request.urlopen(") {
			return pythonURLopenUploadPayload(lower)
		}
		if !uploadPayloadIndicator(lower) {
			return false
		}
		return strings.Contains(lower, "requests.post(") ||
			strings.Contains(lower, "requests.put(") ||
			strings.Contains(lower, "requests.patch(") ||
			strings.Contains(lower, "httpx.post(") ||
			strings.Contains(lower, "httpx.put(") ||
			strings.Contains(lower, "httpx.patch(") ||
			(strings.Contains(lower, "requests.request(") && uploadMethodIndicator(lower)) ||
			(strings.Contains(lower, "httpx.request(") && uploadMethodIndicator(lower))
	case "javascript", "jxa":
		if !uploadPayloadIndicator(lower) {
			return false
		}
		return strings.Contains(lower, "axios.post(") ||
			strings.Contains(lower, "axios.put(") ||
			strings.Contains(lower, "axios.patch(") ||
			(strings.Contains(lower, "axios.request(") && uploadMethodIndicator(lower)) ||
			((strings.Contains(lower, "fetch(") || strings.Contains(lower, "bun.fetch(")) && uploadMethodIndicator(lower))
	default:
		return false
	}
}

func pythonURLopenUploadPayload(line string) bool {
	call := firstCallText(line, "urllib.request.urlopen(")
	if call == "" {
		return false
	}
	return strings.Contains(condensed(call), ",data=")
}

func uploadPayloadIndicator(line string) bool {
	for _, token := range []string{"data=", "json=", "files=", "content=", "body=", "body:", "formdata", "readfile"} {
		if strings.Contains(line, token) {
			return true
		}
	}
	for _, token := range []string{", open(", ",open(", "=open("} {
		if strings.Contains(line, token) {
			return true
		}
	}
	for _, value := range []string{"payload", "buffer", "blob"} {
		if strings.Contains(line, ", "+value) || strings.Contains(line, ","+value) {
			return true
		}
	}
	return false
}

func uploadMethodIndicator(line string) bool {
	for _, token := range []string{`"post"`, `'post'`, "`post`", `"put"`, `'put'`, "`put`", `"patch"`, `'patch'`, "`patch`", "method:post", "method=post"} {
		if strings.Contains(line, token) {
			return true
		}
	}
	return false
}

func extractLanguageFileModeBudget(graph *behavior.Graph, content artifact.Content, language, line string, lineNo int, evidenceID string, budget *textLineBudget) {
	lower := strings.ToLower(line)
	if !languageChmodMakesExecutableBudget(language, lower, budget) {
		return
	}
	target := firstDownloadPathBudget(line, budget)
	if target == "" {
		return
	}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID:    content.NodeID,
		ScopeID:          content.ScopeID,
		Kind:             behavior.OperationFileMakeExecutable,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, target))),
		EvidenceIDs:      []string{evidenceID},
		Support:          behavior.SupportCorroborated,
		Execution:        executionContextForContent(content),
		Line:             lineNo,
	})
}

func languageChmodMakesExecutableBudget(language, line string, budget *textLineBudget) bool {
	switch language {
	case "python":
		context := pythonCodeContext(line)
		return strings.Contains(context, "chmod(") && chmodModeInLineMakesExecutableBudget(context, budget)
	case "javascript":
		return javascriptChmodCall(line) && chmodModeInLineMakesExecutableBudget(line, budget)
	default:
		return false
	}
}

func javascriptChmodCall(line string) bool {
	return strings.Contains(line, "chmodsync(") ||
		strings.Contains(line, "chmod(") ||
		strings.Contains(line, ".chmod(")
}

func chmodModeInLineMakesExecutableBudget(line string, budget *textLineBudget) bool {
	if strings.Contains(line, "stat.s_ix") {
		return true
	}
	for _, match := range boundedTextRegexpMatches(reChmodMode, line, "file-mode", budget) {
		mode := line[match[0]:match[1]]
		mode = strings.TrimPrefix(mode, "0o")
		if numericModeMakesExecutable(mode) {
			return true
		}
	}
	return false
}

func languageDownloadTargetBudget(language, line string, budget *textLineBudget) string {
	lower := strings.ToLower(line)
	switch language {
	case "python":
		if !pythonDownloadCall(lower) || !pythonFileWrite(lower) {
			return ""
		}
	case "javascript", "jxa":
		if !javascriptDownloadCall(lower) || !javascriptFileWrite(lower) {
			return ""
		}
	default:
		return ""
	}
	return firstDownloadPathBudget(line, budget)
}

func pythonDownloadCall(line string) bool {
	line = pythonCodeContext(line)
	return strings.Contains(line, "requests.get(") ||
		strings.Contains(line, "httpx.get(") ||
		strings.Contains(line, "urllib.request.urlopen(") ||
		strings.Contains(line, "urllib.request.urlretrieve(") ||
		strings.Contains(line, "urllib2.urlopen(")
}

func pythonFileWrite(line string) bool {
	line = pythonCodeContext(line)
	return strings.Contains(line, "open(") && strings.Contains(line, ".write(") ||
		strings.Contains(line, "write_bytes(") ||
		strings.Contains(line, "urllib.request.urlretrieve(")
}

func javascriptDownloadCall(line string) bool {
	return strings.Contains(line, "fetch(") ||
		strings.Contains(line, "bun.fetch(") ||
		strings.Contains(line, "axios.get(")
}

func javascriptFileWrite(line string) bool {
	return strings.Contains(line, "writefilesync(") ||
		strings.Contains(line, "writefile(")
}

func firstDownloadPathBudget(line string, budget *textLineBudget) string {
	for _, value := range quotedValuesBudget(line, budget) {
		if downloadPath(value) {
			return value
		}
	}
	for _, match := range boundedTextRegexpMatches(rePath, line, "path", budget) {
		value := line[match[0]:match[1]]
		if downloadPath(value) {
			return value
		}
	}
	return ""
}

func downloadPath(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") || strings.HasPrefix(value, "//") {
		return false
	}
	return strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~/")
}

func analyzeAppleScriptLineBudget(graph *behavior.Graph, content artifact.Content, line string, lineNo int, execution behavior.ExecutionContext, evidenceID string, budget *textLineBudget, bindings *osaStringBindings) bool {
	line = appleScriptCommandStatement(line)
	start := graph.CaptureGraphRange()
	var requiredEvidence []string
	closedRequest := false
	defer func() {
		if len(requiredEvidence) > 0 {
			graph.CorroborateRange(start, requiredEvidence)
		}
	}()
	if argument, ok := appleScriptCommandArgument(line, "open location"); ok {
		if value, proofs, exact := resolveAppleScriptStringExpression(argument, bindings); exact {
			closedRequest = true
			requiredEvidence = proofs
			if dest := delegatedURLDestinationsBudget(value, budget); len(dest) > 0 {
				addDelegatedNetworkOperation(graph, content, "AppleScript open location", dest, lineNo, execution, evidenceID)
			}
		}
	}
	if appleScriptHiddenAnswerDialog(line) {
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID:    content.NodeID,
			ScopeID:          content.ScopeID,
			Kind:             behavior.OperationCredentialPrompt,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleCredential, behavior.NewResource(behavior.ResourceCredential, ""))),
			EvidenceIDs:      []string{evidenceID},
			Support:          behavior.SupportCorroborated,
			Execution:        execution,
			Line:             lineNo,
		})
	}
	if argument, ok := appleScriptCommandArgument(line, "do shell script"); ok {
		command, proofs, exact := resolveAppleScriptStringExpression(argument, bindings)
		if exact {
			requiredEvidence = proofs
			closedRequest = true
		}
		if !exact {
			command = ""
			addPartialCoverageOnce(graph, content.NodeID, "osa-command-arguments", "a shell invocation had an unresolved complete argument expression; no command was synthesized from literal fragments")
			if !boundedAppleScriptArgumentShape(argument) {
				return false
			}
		}
		addOSAShellInvocation(graph, content, command, lineNo, execution, evidenceID)
	}
	return closedRequest
}

func addOSAShellInvocation(graph *behavior.Graph, content artifact.Content, command string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID:  content.NodeID,
		ScopeID:        content.ScopeID,
		SourceFunction: content.Function,
		Kind:           behavior.OperationInterpreterInvoke,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, command)),
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/bin/sh", behavior.ResourceClassInterpreter)),
		),
		EvidenceIDs: mergeEvidenceIDs(append([]string{evidenceID}, content.SupportingEvidenceIDs...)...),
		Support:     behavior.SupportCorroborated,
		Execution:   execution,
		Line:        lineNo,
	})
	if command != "" {
		AnalyzeShellLine(graph, content, command, lineNo, execution, evidenceID)
	}
}

func extractNativeAPIsBudget(graph *behavior.Graph, content artifact.Content, language, line string, lineNo int, evidenceID string, budget *textLineBudget) {
	if !nativeAPIScanEnabled(language) {
		return
	}
	support := behavior.SupportCorroborated
	execution := executionContextForContent(content)
	if language == "native-source" && strings.EqualFold(filepath.Ext(content.LogicalPath), ".rs") {
		// Exact source spelling does not establish Rust name resolution, cfg
		// applicability, macro expansion, or reachability. Keep possible FFI/API
		// behavior visible, but below the capability-rule support threshold.
		support = behavior.SupportHeuristic
		execution = unknownExecutionContext()
	}
	if containsDirectUnquotedCall(line, "SecItemCopyMatching") {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationKeychainItemQuery, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceCredentialStore, "", behavior.ResourceClassKeychain))), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	if containsAnyDirectUnquotedCall(line, "SecKeychainFindGenericPassword", "SecKeychainFindInternetPassword") {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationCredentialStoreRead, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceCredentialStore, "", behavior.ResourceClassKeychain))), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	if kind, resource, ok := nativeServiceManagementOperationBudget(line, budget); ok {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: kind, ResourceBindings: requiredResourceBindings(kind, resource), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	if containsAnyDirectUnquotedCall(line, "CGWindowListCreateImage", "CGDisplayCreateImage", "CGDisplayCreateImageForRect") {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationScreenCapture, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceScreen, ""))), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	if containsDirectUnquotedCall(line, "PasteboardCopyItemFlavorData") {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationPasteboardItemRead, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourcePasteboard, "unresolved pasteboard reference"))), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	if containsAnyDirectUnquotedCall(line, "PasteboardPutItemFlavor", "PasteboardPutItemFlavorData") {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationPasteboardItemWrite, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourcePasteboard, "unresolved pasteboard reference"))), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	if nativeClipboardReadCall(line) {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationClipboardRead, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceClipboard, ""))), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	if nativeClipboardWriteCall(line) {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationClipboardWrite, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceClipboard, ""))), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	if containsAnyDirectUnquotedCall(line, "CGEventTapCreate", "CGEventTapCreateForPSN", "CGEventTapCreateForPid") {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationInputEventTapCreate, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceInputEventStream, "Quartz event stream"))), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	if containsAnyDirectUnquotedCall(line, "AudioQueueNewInput", "AudioQueueNewInputWithDispatchQueue") {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationAudioRecordingQueueCreate, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceAudioInput, "system audio input"))), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	if nativeCameraCaptureCall(line) {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationCameraCapture, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceCamera, ""))), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	if nativeWorkspaceProcessEnumerationCall(line) {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationProcessEnumerate, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceProcess, "local processes"))), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	if containsAnyDirectUnquotedCall(line, "getifaddrs", "if_nameindex") {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationNetworkConfigurationQuery, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceConfiguration, "local network interfaces and addresses"))), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	for _, kind := range processPrimitiveOperationKindsInText(line) {
		graph.AddOperation(behavior.ModeledOperation{SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: kind, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleTargetProcess, behavior.NewResource(behavior.ResourceProcess, ""))), EvidenceIDs: []string{evidenceID}, Support: support, Execution: execution, Line: lineNo})
	}
	if reNativeExec.MatchString(line) {
		graph.AddFeature(behavior.Feature{NodeID: content.NodeID, ScopeID: content.ScopeID, Key: "native.execution.api", Value: line, EvidenceIDs: []string{evidenceID}, Support: support})
	}
	if language == "native-source" && support != behavior.SupportHeuristic {
		extractNativeSourceCommandLiteralsBudget(graph, content, line, lineNo, evidenceID, budget)
	}
}

func nativeClipboardReadCall(line string) bool {
	// NSPasteboard is also used for drag and drop, type declarations, writes,
	// and availability checks. Require the concrete class and a content-reading
	// member on one retained source line rather than promoting every pasteboard
	// reference into clipboard collection.
	if !nativeGeneralPasteboardReference(line) {
		return false
	}
	for _, member := range []string{
		".string(forType:",
		".data(forType:",
		".propertyList(forType:",
		".readObjects(forClasses:",
		".stringForType(",
		".dataForType(",
		".propertyListForType(",
		".readObjectsForClasses(",
		"stringForType:",
		"dataForType:",
		"propertyListForType:",
		"readObjectsForClasses:",
	} {
		if containsUnquotedSubstring(line, member) {
			return true
		}
	}
	return false
}

func nativeClipboardWriteCall(line string) bool {
	if !nativeGeneralPasteboardReference(line) {
		return false
	}
	for _, member := range []string{
		".setString(", ".setData(", ".setPropertyList(", ".writeObjects(",
		"setString:forType:", "setData:forType:", "setPropertyList:forType:", "writeObjects:",
	} {
		if containsUnquotedSubstring(line, member) {
			return true
		}
	}
	for _, setter := range []string{"setString:", "setData:", "setPropertyList:"} {
		if containsUnquotedSubstring(line, setter) && containsUnquotedSubstring(line, "forType:") {
			return true
		}
	}
	return false
}

func nativeGeneralPasteboardReference(line string) bool {
	if !containsUnquotedIdentifier(line, "NSPasteboard") {
		return false
	}
	return containsUnquotedSubstring(line, "NSPasteboard.general") ||
		containsUnquotedSubstring(line, "NSPasteboard generalPasteboard") ||
		containsUnquotedSubstring(line, "$.NSPasteboard.generalPasteboard")
}

func containsAnyDirectUnquotedCall(line string, names ...string) bool {
	for _, name := range names {
		if containsDirectUnquotedCall(line, name) {
			return true
		}
	}
	return false
}

func containsDirectUnquotedCall(line, name string) bool {
	_, ok := unquotedCallOpen(line, name)
	return ok
}

func nativeCameraCaptureCall(line string) bool {
	if containsUnquotedSubstring(line, "AVCapturePhotoOutput().capturePhoto(") {
		return true
	}
	if (containsUnquotedSubstring(line, "(AVCapturePhotoOutput *)") || containsUnquotedSubstring(line, "(AVCapturePhotoOutput*)")) &&
		containsUnquotedSubstring(line, "capturePhotoWithSettings:") && containsUnquotedSubstring(line, "delegate:") {
		return true
	}
	if containsUnquotedSubstring(line, "AVCaptureStillImageOutput().captureStillImageAsynchronously(") {
		return true
	}
	return (containsUnquotedSubstring(line, "(AVCaptureStillImageOutput *)") || containsUnquotedSubstring(line, "(AVCaptureStillImageOutput*)")) &&
		containsUnquotedSubstring(line, "captureStillImageAsynchronouslyFromConnection:") && containsUnquotedSubstring(line, "completionHandler:")
}

func nativeWorkspaceProcessEnumerationCall(line string) bool {
	return containsUnquotedSubstring(line, "NSWorkspace.shared.runningApplications") ||
		containsUnquotedSubstring(line, "$.NSWorkspace.sharedWorkspace.runningApplications") ||
		containsUnquotedSubstring(line, "[[NSWorkspace sharedWorkspace] runningApplications]") ||
		containsUnquotedSubstring(line, "[[NSWorkspace sharedWorkspace] launchedApplications]")
}

func nativeServiceManagementOperationBudget(line string, budget *textLineBudget) (behavior.OperationKind, behavior.Resource, bool) {
	if nativeSMLoginItemEnableCall(line) {
		return behavior.OperationLoginItemEnable, behavior.NewResource(behavior.ResourceLoginItem, firstQuotedBudget(line, budget)), true
	}
	service, ok := nativeSMAppServiceRegistration(line)
	if !ok {
		return "", behavior.Resource{}, false
	}
	switch service {
	case "daemonService":
		return behavior.OperationLaunchdJobRegister, behavior.NewResource(behavior.ResourceLaunchdJob, quotedNamedArgumentBudget(line, "plistName", budget), behavior.ResourceClassLaunchDaemon), true
	case "agentService":
		return behavior.OperationLaunchdJobRegister, behavior.NewResource(behavior.ResourceLaunchdJob, quotedNamedArgumentBudget(line, "plistName", budget), behavior.ResourceClassLaunchAgent), true
	case "mainAppService", "mainApp", "loginItem":
		return behavior.OperationLoginItemRegister, behavior.NewResource(behavior.ResourceLoginItem, quotedNamedArgumentBudget(line, "identifier", budget)), true
	default:
		return "", behavior.Resource{}, false
	}
}

func nativeSMLoginItemEnableCall(line string) bool {
	open, found := unquotedCallOpen(line, "SMLoginItemSetEnabled")
	if !found {
		return false
	}
	body, _, exact := exactJavaScriptCallContent(line, open, maxJavaScriptAPICallBytes)
	if !exact {
		return false
	}
	arguments, exact := splitJavaScriptArgumentsExact(body, maxJavaScriptAPICallBytes, 2)
	return exact && len(arguments) == 2 && strings.TrimSpace(arguments[1]) == "true"
}

func nativeSMAppServiceRegistration(line string) (string, bool) {
	for _, service := range []string{"daemonService", "agentService", "loginItem"} {
		prefix := "SMAppService." + service
		start := unquotedSubstringIndex(line, prefix)
		if start < 0 {
			continue
		}
		open := start + len(prefix)
		for open < len(line) && (line[open] == ' ' || line[open] == '\t') {
			open++
		}
		_, close, exact := exactJavaScriptCallContent(line, open, maxJavaScriptAPICallBytes)
		if exact && directMemberCallAfter(line, close+1, "register") {
			return service, true
		}
	}
	for _, service := range []string{"mainAppService", "mainApp"} {
		prefix := "SMAppService." + service
		start := unquotedSubstringIndex(line, prefix)
		if start >= 0 && directMemberCallAfter(line, start+len(prefix), "register") {
			return service, true
		}
	}
	return "", false
}

func directMemberCallAfter(line string, cursor int, member string) bool {
	for cursor < len(line) && (line[cursor] == ' ' || line[cursor] == '\t') {
		cursor++
	}
	if cursor >= len(line) || line[cursor] != '.' {
		return false
	}
	cursor++
	if !strings.HasPrefix(line[cursor:], member) || !callNameBoundary(line, cursor, len(member)) {
		return false
	}
	cursor += len(member)
	for cursor < len(line) && (line[cursor] == ' ' || line[cursor] == '\t') {
		cursor++
	}
	return cursor < len(line) && line[cursor] == '('
}

func unquotedSubstringIndex(line, value string) int {
	index := -1
	findUnquoted(line, value, func(_ string, start, _ int) bool {
		index = start
		return true
	})
	return index
}

func containsUnquotedSubstring(line, value string) bool {
	return findUnquoted(line, value, func(string, int, int) bool { return true })
}

func containsUnquotedIdentifier(line, value string) bool {
	return findUnquoted(line, value, func(line string, start, length int) bool {
		return (start == 0 || !isIdentifierByte(line[start-1])) &&
			(start+length == len(line) || !isIdentifierByte(line[start+length]))
	})
}

func findUnquoted(line, value string, accept func(string, int, int) bool) bool {
	var quote byte
	escaped := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			quote = ch
			continue
		}
		if strings.HasPrefix(line[i:], value) && accept(line, i, len(value)) {
			return true
		}
	}
	return false
}

func callNameBoundary(line string, start, length int) bool {
	if start > 0 && isIdentifierByte(line[start-1]) {
		return false
	}
	end := start + length
	for end < len(line) && (line[end] == ' ' || line[end] == '\t') {
		end++
	}
	return end < len(line) && line[end] == '('
}

func isIdentifierByte(ch byte) bool {
	return ch == '_' || ch >= '0' && ch <= '9' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
}

func quotedNamedArgumentBudget(line, name string, budget *textLineBudget) string {
	lower := strings.ToLower(line)
	index := strings.Index(lower, strings.ToLower(name))
	if index < 0 {
		return ""
	}
	return firstQuotedBudget(line[index:], budget)
}

func extractSensitiveResourceFeaturesBudget(graph *behavior.Graph, content artifact.Content, language, line string, lineNo int, evidenceID string, budget *textLineBudget) {
	if !scriptSemanticLanguage(language) {
		return
	}
	// Shell commands have an argv-aware sensitive-read analyzer. Do not also
	// turn every sensitive-looking shell operand into a neutral resource feature:
	// option values such as `tar --exclude ~/.ssh/id_rsa` would otherwise be
	// correlated with the archive operation and reported as collection even
	// though that path is explicitly excluded. Other script languages retain
	// neutral resource features because their collection context may be expressed
	// separately from the resource definition.
	if language == "shell" {
		return
	}
	seen := map[string]bool{}
	add := func(resource behavior.Resource) {
		category := sensitiveResourceFeatureCategory(resource)
		if category == "" {
			return
		}
		key := category + "\x00" + resource.Value
		if seen[key] {
			return
		}
		seen[key] = true
		graph.AddFeature(behavior.Feature{
			NodeID:         content.NodeID,
			ScopeID:        content.ScopeID,
			Key:            "script.sensitive_resource",
			Value:          resource.Value,
			EvidenceIDs:    []string{evidenceID},
			Support:        behavior.SupportCorroborated,
			Execution:      executionContextForContent(content),
			SourceFunction: content.Function,
			Qualifiers: map[string]string{
				"category": category,
				"line":     strconv.Itoa(lineNo),
			},
		})
	}
	for _, quoted := range quotedValuesBudget(line, budget) {
		if resource, ok := sensitiveResourceBudget(quoted, budget); ok {
			add(resource)
		}
	}
	// A whole source expression is useful only when no quoted literal already
	// supplied the resource. Otherwise it produces a second, malformed value
	// such as "send_file(... os.path.join(...))" beside the concrete literal.
	if len(seen) == 0 {
		if resource, ok := sensitiveResourceBudget(line, budget); ok {
			add(resource)
		}
	}
}

func scriptSemanticLanguage(language string) bool {
	switch language {
	case "shell", "applescript", "jxa", "javascript", "python":
		return true
	default:
		return false
	}
}

func browserCredentialDefinition(line string) bool {
	// A minified frontend can place hundreds of unrelated strings on one line.
	// Do not turn that entire blob into a feature or infer a definition merely
	// because a browser name appears somewhere in the bundle.
	if len(line) > 2048 {
		return false
	}
	return browserCredentialFamily(line) && browserCredentialFile(line) && browserCredentialDefinitionSyntax(line)
}

func browserCredentialFamily(line string) bool {
	lower := strings.ToLower(line)
	for _, marker := range []string{
		"google/chrome", "bravesoftware/brave-browser", "microsoft edge", "firefox/profiles",
		"waterfox/profiles", "pale moon/profiles", "arc/", "vivaldi/", "operasoftware",
		"chromium/",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func browserCredentialFile(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "cookies") ||
		strings.Contains(lower, "login data") ||
		strings.Contains(lower, "logins.json") ||
		strings.Contains(lower, "key4.db") ||
		strings.Contains(lower, "formhistory.sqlite")
}

func browserCredentialDefinitionSyntax(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "extractfiles") ||
		strings.Contains(lower, "readfile") ||
		strings.Contains(lower, "sqlite") ||
		strings.ContainsAny(line, "[]:=(){}")
}

const maxBrowserCredentialDefinitionLineGap = 8

type browserCredentialDefinitionCandidate struct {
	line     int
	text     string
	function string
	scopeKey string
}

type browserCredentialDefinitionObservation struct {
	familyLine     int
	familyText     string
	credentialLine int
	credentialText string
	function       string
}

type browserCredentialDefinitionTracker struct {
	candidate browserCredentialDefinitionCandidate
}

func (t *browserCredentialDefinitionTracker) Observe(language, line string, lineNo int, function string) (browserCredentialDefinitionObservation, bool) {
	return t.ObserveScoped(language, line, lineNo, function, function)
}

func (t *browserCredentialDefinitionTracker) ObserveScoped(language, line string, lineNo int, function, scopeKey string) (browserCredentialDefinitionObservation, bool) {
	if language != "javascript" && language != "jxa" {
		return browserCredentialDefinitionObservation{}, false
	}
	if len(line) > 2048 {
		t.candidate = browserCredentialDefinitionCandidate{}
		return browserCredentialDefinitionObservation{}, false
	}
	if t.candidate.line != 0 && (scopeKey != t.candidate.scopeKey || lineNo-t.candidate.line > maxBrowserCredentialDefinitionLineGap) {
		t.candidate = browserCredentialDefinitionCandidate{}
	}
	family := browserCredentialFamily(line) && browserCredentialDefinitionSyntax(line)
	credential := browserCredentialFile(line) && browserCredentialDefinitionSyntax(line)
	if family && credential {
		t.candidate = browserCredentialDefinitionCandidate{}
		return browserCredentialDefinitionObservation{
			familyLine: lineNo, familyText: line,
			credentialLine: lineNo, credentialText: line,
			function: function,
		}, true
	}
	if family {
		t.candidate = browserCredentialDefinitionCandidate{line: lineNo, text: line, function: function, scopeKey: scopeKey}
		return browserCredentialDefinitionObservation{}, false
	}
	if credential && t.candidate.line != 0 {
		candidate := t.candidate
		t.candidate = browserCredentialDefinitionCandidate{}
		return browserCredentialDefinitionObservation{
			familyLine: candidate.line, familyText: candidate.text,
			credentialLine: lineNo, credentialText: line,
			function: function,
		}, true
	}
	if t.candidate.line != 0 && strings.Contains(line, "}") {
		t.candidate = browserCredentialDefinitionCandidate{}
	}
	return browserCredentialDefinitionObservation{}, false
}

func addBrowserCredentialDefinitionFeature(graph *behavior.Graph, content artifact.Content, definition browserCredentialDefinitionObservation, scopeID string) {
	lineContent := content
	lineContent.Function = definition.function
	lineContent.ScopeID = scopeID
	evidenceIDs := []string{addLineEvidence(graph, lineContent, definition.familyLine, "browser-profile-definition", definition.familyText)}
	if definition.credentialLine != definition.familyLine {
		evidenceIDs = append(evidenceIDs, addLineEvidence(graph, lineContent, definition.credentialLine, "browser-credential-file-definition", definition.credentialText))
	}
	graph.AddFeature(behavior.Feature{
		NodeID:         content.NodeID,
		ScopeID:        lineContent.ScopeID,
		Key:            "script.browser_credential_store",
		Value:          "browser credential-store definition",
		EvidenceIDs:    evidenceIDs,
		Support:        behavior.SupportCorroborated,
		Execution:      executionContextForContent(lineContent),
		SourceFunction: definition.function,
		Qualifiers: map[string]string{
			"line_start": strconv.Itoa(definition.familyLine),
			"line_end":   strconv.Itoa(definition.credentialLine),
		},
	})
}

func nativeAPIScanEnabled(language string) bool {
	switch language {
	case "native-source", "jxa":
		return true
	default:
		return false
	}
}

func extractSensitiveReadsBudget(graph *behavior.Graph, content artifact.Content, language, line string, lineNo int, evidenceID string, budget *textLineBudget) {
	// Python and JavaScript file reads are handled by their stable binding and
	// exact-call recognizers. This fallback is observational for JXA because a
	// command-like member name and path literal do not establish API identity.
	if language == "python" || language == "javascript" {
		return
	}
	if !sensitiveReadContext(language, line) {
		return
	}
	seen := map[behavior.ResourceKey]bool{}
	add := func(resource behavior.Resource) {
		key := resource.Key()
		if seen[key] {
			return
		}
		seen[key] = true
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID:    content.NodeID,
			ScopeID:          content.ScopeID,
			Kind:             behavior.OperationFileRead,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, resource)),
			EvidenceIDs:      []string{evidenceID},
			Support:          behavior.SupportHeuristic,
			Execution:        unknownExecutionContext(),
			Line:             lineNo,
		})
	}
	for _, quoted := range quotedValuesBudget(line, budget) {
		if res, ok := sensitiveResourceBudget(quoted, budget); ok {
			add(res)
		}
	}
	// Fall back to the complete expression only when no quoted literal already
	// supplied a resource. Otherwise a call such as open("path").read() emits
	// both the concrete path and a malformed source-expression duplicate.
	if len(seen) == 0 {
		if res, ok := sensitiveResourceBudget(line, budget); ok {
			add(res)
		}
	}
}

func sensitiveReadContext(language, line string) bool {
	lower := strings.ToLower(line)
	switch language {
	case "python":
		lower = pythonCodeContext(lower)
		return (strings.Contains(lower, "open(") && strings.Contains(lower, ".read(")) ||
			strings.Contains(lower, "read_text(") ||
			strings.Contains(lower, "read_bytes(") ||
			strings.Contains(lower, "sqlite3.connect(")
	case "javascript", "jxa":
		return strings.Contains(lower, "readfilesync(") ||
			strings.Contains(lower, "readfile(") ||
			strings.Contains(lower, "createreadstream(") ||
			strings.Contains(lower, "sqlite")
	default:
		return false
	}
}

func sensitiveResource(value string) (behavior.Resource, bool) {
	return sensitiveResourceBudget(value, nil)
}

func sensitiveResourceBudget(value string, budget *textLineBudget) (behavior.Resource, bool) {
	lower := strings.ToLower(strings.ReplaceAll(value, "\\", "/"))
	switch {
	case strings.Contains(lower, "library/keychains") || strings.Contains(lower, "login.keychain-db"):
		return sensitiveFileResource(value, budget, behavior.ResourceClassKeychain, "library/keychains", "login.keychain-db")
	case browserDataFamilyPath(lower) && browserCookiePath(lower):
		return sensitiveFileResource(value, budget, behavior.ResourceClassBrowserCookieStore, browserDataPathMarkers()...)
	case browserDataFamilyPath(lower) && browserPasswordPath(lower):
		return sensitiveFileResource(value, budget, behavior.ResourceClassBrowserPasswordStore, browserDataPathMarkers()...)
	case browserDataFamilyPath(lower):
		return sensitiveFileResource(value, budget, behavior.ResourceClassBrowserDataStore, browserDataPathMarkers()...)
	case messagingDataPath(lower):
		return sensitiveFileResource(value, budget, behavior.ResourceClassMessagingDataStore, "library/messages", "library/application support/telegram desktop", "library/application support/signal", "library/application support/discord", "library/application support/slack", "group containers/6n38vws5bx.ru.keepcoder.telegram", "group.net.whatsapp.whatsapp.shared")
	case mailDataPath(lower):
		return sensitiveFileResource(value, budget, behavior.ResourceClassMailDataStore, "library/mail", "envelope index")
	case strings.Contains(lower, "group containers/group.com.apple.notes") || strings.Contains(lower, "notestore.sqlite"):
		return sensitiveFileResource(value, budget, behavior.ResourceClassNotesDataStore, "group containers/group.com.apple.notes", "notestore.sqlite")
	case vpnProfilePath(lower):
		return sensitiveFileResource(value, budget, behavior.ResourceClassVPNProfileStore, "library/application support/tunnelblick/configurations", "library/application support/openvpn connect", ".ovpn", ".tblk")
	case strings.Contains(lower, "library/application support/exodus") ||
		looksLikeElectrumDataPath(lower) ||
		strings.Contains(lower, "library/application support/ledger live") ||
		strings.Contains(lower, "library/application support/atomic") ||
		strings.Contains(lower, "library/application support/coinomi") ||
		strings.Contains(lower, "library/application support/guarda") ||
		looksLikeMetaMaskDataPath(lower):
		return sensitiveFileResource(value, budget, behavior.ResourceClassCryptoWalletStore, "library/application support/exodus", "library/application support/electrum", "/.electrum", "library/application support/ledger live", "library/application support/atomic", "library/application support/coinomi", "library/application support/guarda", "library/application support/metamask", "library/containers/io.metamask", "/.metamask")
	case strings.Contains(lower, ".ssh/id_rsa") || strings.Contains(lower, ".ssh/id_ed25519") || strings.Contains(lower, ".ssh/id_ecdsa") || strings.Contains(lower, ".ssh/id_dsa"):
		return sensitiveFileResource(value, budget, behavior.ResourceClassSSHPrivateKey, ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/id_dsa")
	case strings.Contains(lower, ".aws/credentials") || strings.Contains(lower, ".config/gcloud") || strings.Contains(lower, ".docker/config.json") || hiddenPathComponent(lower, ".azure") || localSensitivePathMarker(lower, ".kube/config"):
		return sensitiveFileResource(value, budget, behavior.ResourceClassCloudCredentialStore, ".aws/credentials", ".config/gcloud", ".docker/config.json", "/.azure", ".kube/config")
	case strings.Contains(lower, ".npmrc") || strings.Contains(lower, ".pypirc") || strings.Contains(lower, "github_token") || localSensitivePathMarker(lower, ".git-credentials") || localSensitivePathMarker(lower, ".config/gh/hosts.yml") || localSensitivePathMarker(lower, ".cargo/credentials") || localSensitivePathMarker(lower, ".gem/credentials"):
		return sensitiveFileResource(value, budget, behavior.ResourceClassDeveloperTokenStore, ".npmrc", ".pypirc", "github_token", ".git-credentials", ".config/gh/hosts.yml", ".cargo/credentials.toml", ".cargo/credentials", ".gem/credentials")
	default:
		return behavior.Resource{}, false
	}
}

func sensitiveFileResource(value string, budget *textLineBudget, classification behavior.ResourceClassification, markers ...string) (behavior.Resource, bool) {
	concrete := sensitiveResourceConcreteBudget(value, budget, markers...)
	if concrete == "" {
		return behavior.Resource{}, false
	}
	return behavior.NewResource(behavior.ResourceFile, concrete, classification), true
}

func browserDataPathMarkers() []string {
	return []string{
		"library/safari", "library/cookies/cookies.binarycookies",
		"library/application support/google/chrome", "library/application support/chromium",
		"library/application support/bravesoftware/brave-browser", "library/application support/microsoft edge",
		"library/application support/arc/user data", "library/application support/com.operasoftware.opera",
		"library/application support/com.operasoftware.operagx", "library/application support/vivaldi",
		"library/application support/firefox/profiles",
	}
}

func browserDataFamilyPath(lower string) bool {
	for _, marker := range browserDataPathMarkers() {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func browserCookiePath(lower string) bool {
	return strings.Contains(lower, "cookies.binarycookies") || strings.Contains(lower, "/cookies") || strings.Contains(lower, "cookies.sqlite")
}

func browserPasswordPath(lower string) bool {
	return strings.Contains(lower, "login data") || strings.Contains(lower, "logins.json") || strings.Contains(lower, "key4.db") || strings.Contains(lower, "web data")
}

func messagingDataPath(lower string) bool {
	normalized := strings.TrimRight(strings.ReplaceAll(lower, "\\", "/"), "/")
	return strings.HasSuffix(normalized, "/library/messages") || strings.Contains(normalized, "/library/messages/") ||
		strings.Contains(lower, "library/application support/telegram desktop") ||
		strings.Contains(lower, "group containers/6n38vws5bx.ru.keepcoder.telegram") ||
		strings.Contains(lower, "library/application support/signal") ||
		strings.Contains(lower, "library/application support/discord") ||
		strings.Contains(lower, "library/application support/slack") ||
		strings.Contains(lower, "group.net.whatsapp.whatsapp.shared")
}

func hiddenPathComponent(lower, component string) bool {
	normalized := strings.TrimRight(strings.ReplaceAll(lower, "\\", "/"), "/")
	if strings.Contains(normalized, "://") {
		return false
	}
	return strings.Contains(normalized, "/"+component+"/") || strings.HasSuffix(normalized, "/"+component) || strings.HasPrefix(normalized, component+"/")
}

func localSensitivePathMarker(lower, marker string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(lower, "\\", "/"))
	if !strings.Contains(normalized, marker) {
		return false
	}
	if !strings.Contains(normalized, "://") {
		return true
	}
	return strings.Contains(normalized, "~/"+marker) || strings.Contains(normalized, "/users/") || strings.HasPrefix(strings.TrimSpace(normalized), marker)
}

func mailDataPath(lower string) bool {
	normalized := strings.TrimRight(strings.ReplaceAll(lower, "\\", "/"), "/")
	return strings.HasSuffix(normalized, "/library/mail") || strings.Contains(normalized, "/library/mail/") || strings.Contains(normalized, "envelope index")
}

func vpnProfilePath(lower string) bool {
	return strings.Contains(lower, "library/application support/tunnelblick/configurations") ||
		strings.Contains(lower, "library/application support/openvpn connect") ||
		strings.HasSuffix(lower, ".ovpn") || strings.Contains(lower, ".ovpn/") ||
		strings.HasSuffix(lower, ".tblk") || strings.Contains(lower, ".tblk/")
}

func looksLikeElectrumDataPath(lower string) bool {
	normalized := strings.ReplaceAll(lower, "\\", "/")
	return strings.Contains(normalized, "library/application support/electrum") ||
		strings.Contains(normalized, "/.electrum/") ||
		strings.HasSuffix(strings.TrimRight(normalized, "/"), "/.electrum")
}

func looksLikeMetaMaskDataPath(lower string) bool {
	normalized := strings.ReplaceAll(lower, "\\", "/")
	if !strings.Contains(normalized, "metamask") {
		return false
	}
	return strings.Contains(normalized, "library/application support/metamask") ||
		strings.Contains(normalized, "library/containers/io.metamask") ||
		strings.Contains(normalized, "/.metamask/") ||
		strings.HasSuffix(strings.TrimRight(normalized, "/"), "/.metamask")
}

func sensitiveResourceConcreteBudget(value string, budget *textLineBudget, markers ...string) string {
	for _, match := range boundedTextRegexpMatches(rePath, value, "sensitive-path", budget) {
		candidate := value[match[0]:match[1]]
		candidate = trimResourcePunctuation(candidate)
		if sensitivePathCandidate(candidate, markers) {
			return candidate
		}
	}
	fallback := strings.TrimSpace(value)
	lowerFallback := strings.ToLower(strings.ReplaceAll(fallback, "\\", "/"))
	pathMarker := false
	anchoredAtStart := false
	rootMarkerCount := 0
	for _, marker := range markers {
		if !sensitiveMarkerAnchorsPath(marker) {
			continue
		}
		if index := strings.Index(lowerFallback, marker); index >= 0 {
			pathMarker = true
			anchoredAtStart = anchoredAtStart || index == 0
			if strings.Contains(marker, "/") {
				rootMarkerCount++
			}
		}
	}
	// Printable runs in native binaries can concatenate adjacent constants.
	// Without a syntactic path boundary, do not turn a marker somewhere inside
	// such a run into one invented concrete resource. A standalone relative
	// marker remains usable when it begins the complete supplied value.
	pathPrefix := anchoredAtStart || strings.HasPrefix(fallback, "~/") || strings.HasPrefix(fallback, "/") || strings.HasPrefix(fallback, "$HOME/") || strings.HasPrefix(fallback, "${HOME}/")
	if pathMarker && (!pathPrefix || rootMarkerCount > 1) {
		return ""
	}
	explicitPathPrefix := strings.HasPrefix(fallback, "~/") || strings.HasPrefix(fallback, "/") || strings.HasPrefix(fallback, "$HOME/") || strings.HasPrefix(fallback, "${HOME}/")
	if pathMarker && explicitPathPrefix && len(fallback) <= maxTextDerivedValueBytes && !sensitivePathCandidate(fallback, markers) {
		return ""
	}
	if len(fallback) > maxTextDerivedValueBytes {
		budget = textBudgetOrStandalone(budget)
		budget.markLimited(fmt.Sprintf("sensitive resource value exceeded %d bytes", maxTextDerivedValueBytes), false)
		for _, marker := range markers {
			if index := strings.Index(lowerFallback, marker); index >= 0 {
				return fallback[index : index+len(marker)]
			}
		}
		fallback = fallback[:maxTextDerivedValueBytes]
	}
	return fallback
}

func sensitivePathCandidate(candidate string, markers []string) bool {
	candidate = strings.TrimSpace(strings.ReplaceAll(candidate, "\\", "/"))
	if candidate == "" || len(candidate) > maxTextDerivedValueBytes || strings.Contains(candidate, "://") || strings.Contains(candidate, "//") || strings.Count(strings.ToLower(candidate), "/.") > 1 {
		return false
	}
	lower := strings.ToLower(candidate)
	pathPrefix := strings.HasPrefix(candidate, "~/") || strings.HasPrefix(candidate, "/") || strings.HasPrefix(candidate, "$HOME/") || strings.HasPrefix(candidate, "${HOME}/")
	if !pathPrefix || (strings.Contains(lower, "$home") && !strings.HasPrefix(lower, "$home/")) {
		return false
	}
	matches := 0
	for _, marker := range markers {
		marker = strings.ToLower(strings.ReplaceAll(marker, "\\", "/"))
		if !sensitiveMarkerAnchorsPath(marker) {
			continue
		}
		for offset := 0; offset < len(lower); {
			index := strings.Index(lower[offset:], marker)
			if index < 0 {
				break
			}
			index += offset
			beforeOK := index == 0 || strings.HasPrefix(marker, "/") || lower[index-1] == '/'
			after := index + len(marker)
			afterOK := after == len(lower) || lower[after] == '/' || (strings.Contains(marker, "library/containers/") && lower[after] == '.')
			if beforeOK && afterOK && plausibleSensitiveMarkerPrefix(lower[:index], marker) {
				matches++
				break
			}
			offset = index + 1
		}
	}
	return matches > 0
}

func plausibleSensitiveMarkerPrefix(prefix, marker string) bool {
	prefix = strings.ToLower(strings.ReplaceAll(prefix, "\\", "/"))
	marker = strings.ToLower(strings.ReplaceAll(marker, "\\", "/"))
	if prefix == "" {
		return true
	}
	userHomePrefix := prefix == "~/" || prefix == "$home/" || prefix == "${home}/" || prefix == "~" || prefix == "$home" || prefix == "${home}" || prefix == "/private/var/root/" || prefix == "/var/root/"
	if strings.HasPrefix(prefix, "/users/") {
		rest := strings.TrimSuffix(strings.TrimPrefix(prefix, "/users/"), "/")
		userHomePrefix = rest != "" && !strings.Contains(rest, "/")
	}
	if strings.HasPrefix(marker, "group containers/") && strings.HasSuffix(prefix, "library/") {
		return plausibleSensitiveMarkerPrefix(strings.TrimSuffix(prefix, "library/"), "library/")
	}
	if strings.HasPrefix(marker, "library/") || strings.HasPrefix(marker, "group containers/") || strings.HasPrefix(marker, "/.") || strings.HasPrefix(marker, ".") {
		return userHomePrefix
	}
	return prefix == "/" || userHomePrefix
}

func sensitiveMarkerAnchorsPath(marker string) bool {
	return strings.Contains(marker, "/") || strings.HasPrefix(marker, ".") || strings.Contains(marker, ".keychain")
}

func trimResourcePunctuation(value string) string {
	value = strings.TrimSpace(value)
	for value != "" {
		last := value[len(value)-1]
		switch last {
		case '.', ',', ';', ':', ')', ']':
			value = strings.TrimSpace(value[:len(value)-1])
		default:
			return value
		}
	}
	return ""
}

type embeddedInvocation struct {
	shellCommand        string
	argv                []string
	executableOnly      string
	processAttempt      bool
	argumentsUnresolved bool
	api                 string
	qualifiers          map[string]string
}

func (i embeddedInvocation) evidenceValue() string {
	if i.shellCommand != "" {
		return i.shellCommand
	}
	if i.executableOnly != "" {
		return i.executableOnly + " <dynamic or unsupported argv>"
	}
	if i.processAttempt {
		return "<dynamic or unsupported executable and argv>"
	}
	return strings.Join(i.argv, " ")
}

func extractPythonEmbeddedInvocationBudget(line, sourceLine string, pythonSubprocessBound bool, budget *textLineBudget) (embeddedInvocation, bool, bool) {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "subprocess.") && !strings.Contains(lower, "os.system(") && !strings.Contains(lower, "os.popen(") {
		return embeddedInvocation{}, false, false
	}
	call := exactPythonSubprocessCall(sourceLine)
	if call.candidate && !pythonSubprocessBound {
		return embeddedInvocation{}, false, true
	}
	if invocation, recognized, incomplete := pythonSubprocessInvocationBudget(sourceLine, budget); recognized || incomplete {
		return invocation, recognized, incomplete
	}
	if command := shellEmbeddedCommand("python", line, lower); command != "" {
		return embeddedInvocation{shellCommand: command}, true, false
	}
	return embeddedInvocation{}, false, false
}

func shellEmbeddedCommand(language, line, lower string) string {
	switch language {
	case "python":
		for _, marker := range []string{"os.system(", "os.popen("} {
			index := pythonMarkerLocation(line, marker)
			if index < 0 {
				continue
			}
			if command := firstCallStringArgument(line, index+len(marker)-1); command != "" {
				return command
			}
		}
	}
	return ""
}

type pythonSubprocessCall struct {
	method    string
	arguments string
	candidate bool
	malformed bool
	ambiguous bool
}

const maxPythonSubprocessImportItems = 32

// observePythonSubprocessBinding retains only an exact, unaliased import in
// the same lexical scope as a later subprocess call. Any other use of the name
// outside the one closed call statement invalidates the binding. This is
// intentionally conservative: generic text recovery does not attempt Python
// global/nonlocal resolution or runtime name binding.
func observePythonSubprocessBinding(bindings map[string]bool, scopeKey, line string) bool {
	if exactPythonSubprocessImport(line) {
		bindings[scopeKey] = true
		return true
	}
	call := exactPythonSubprocessCall(line)
	if call.candidate {
		if call.malformed || call.ambiguous {
			bindings[scopeKey] = false
			return false
		}
		return bindings[scopeKey]
	}
	if pythonIdentifierTokenPresent(line, "subprocess") {
		bindings[scopeKey] = false
	}
	return bindings[scopeKey]
}

func exactPythonSubprocessImport(line string) bool {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "import ") && !strings.HasPrefix(line, "import\t") {
		return false
	}
	items := strings.Split(strings.TrimSpace(line[len("import"):]), ",")
	if len(items) == 0 || len(items) > maxPythonSubprocessImportItems {
		return false
	}
	found := false
	for _, item := range items {
		item = strings.TrimSpace(item)
		if !pythonDottedIdentifierName(item) {
			return false
		}
		if item == "subprocess" {
			found = true
		}
	}
	return found
}

func pythonDottedIdentifierName(value string) bool {
	if value == "" {
		return false
	}
	for _, component := range strings.Split(value, ".") {
		if !identifierName(component) {
			return false
		}
	}
	return true
}

func pythonIdentifierTokenPresent(line, want string) bool {
	for index := 0; index < len(line); {
		switch line[index] {
		case '#':
			return false
		case '\'', '"':
			next, ok := skipPythonQuoted(line, index)
			if !ok {
				return false
			}
			index = next
			continue
		}
		if !strings.HasPrefix(line[index:], want) {
			index++
			continue
		}
		end := index + len(want)
		if (index == 0 || !pythonIdentifierByte(line[index-1])) &&
			(end == len(line) || !pythonIdentifierByte(line[end])) {
			return true
		}
		index = end
	}
	return false
}

func pythonSubprocessInvocationBudget(line string, budget *textLineBudget) (embeddedInvocation, bool, bool) {
	call := exactPythonSubprocessCall(line)
	if !call.candidate {
		return embeddedInvocation{}, false, false
	}
	if call.malformed || call.ambiguous {
		return embeddedInvocation{}, false, true
	}
	args, limited, malformed := exactPythonArguments(call.arguments, maxTextStringExpressionArguments)
	if limited {
		if budget != nil {
			budget.markLimited(fmt.Sprintf("Python subprocess argument limit %d reached", maxTextStringExpressionArguments), false)
		}
		return embeddedInvocation{}, false, true
	}
	if malformed || len(args) == 0 {
		return embeddedInvocation{}, false, true
	}
	shell := false
	shellUnresolved := false
	executableOverride := ""
	executableOverrideUnresolved := false
	contextQualifiers := map[string]string{}
	seenKeyword := map[string]bool{}
	keywordValues := map[string]string{}
	for _, argument := range args[1:] {
		name, value, keyword := exactPythonKeywordArgument(argument)
		if !keyword || seenKeyword[name] || !supportedPythonSubprocessKeyword(call.method, name) {
			return embeddedInvocation{}, false, true
		}
		seenKeyword[name] = true
		keywordValues[name] = strings.TrimSpace(value)
		if !exactPythonSubprocessKeywordValue(keywordValues[name]) {
			return embeddedInvocation{}, false, true
		}
		switch name {
		case "shell":
			switch keywordValues[name] {
			case "True":
				shell = true
			case "False":
			default:
				if !boundedPythonExpression(keywordValues[name], 0) {
					return embeddedInvocation{}, false, true
				}
				shellUnresolved = true
			}
		case "cwd", "env":
			if !boundedPythonExpression(keywordValues[name], 0) {
				return embeddedInvocation{}, false, true
			}
			contextQualifiers[name+"_coverage"] = "provided-unresolved"
		case "executable":
			if value, exact := exactPythonStringLiteral(keywordValues[name]); exact && value != "" {
				executableOverride = value
				contextQualifiers["executable_override"] = "exact-static"
			} else if boundedPythonExpression(keywordValues[name], 0) {
				executableOverrideUnresolved = true
				contextQualifiers["executable_override"] = "provided-unresolved"
			} else {
				return embeddedInvocation{}, false, true
			}
		}
	}
	if _, input := keywordValues["input"]; input {
		if _, stdin := keywordValues["stdin"]; stdin {
			return embeddedInvocation{}, false, true
		}
	}
	if capture, present := keywordValues["capture_output"]; present {
		switch capture {
		case "True":
			if _, stdout := keywordValues["stdout"]; stdout {
				return embeddedInvocation{}, false, true
			}
			if _, stderr := keywordValues["stderr"]; stderr {
				return embeddedInvocation{}, false, true
			}
		case "False":
		default:
			return embeddedInvocation{}, false, true
		}
	}
	if !boundedPythonExpression(args[0], 0) || pythonEmptyCollectionExpression(args[0]) {
		return embeddedInvocation{}, false, true
	}
	if shellUnresolved {
		return embeddedInvocation{
			processAttempt: true, argumentsUnresolved: true, api: call.method,
			qualifiers: contextQualifiers,
		}, true, false
	}
	if shell {
		command, ok := exactPythonArgvElement(args[0])
		if executableOverride == "" && !executableOverrideUnresolved && ok && command != "" && (budget == nil || budget.retainMatch(len(command), "Python shell command literal")) {
			return embeddedInvocation{shellCommand: command, api: call.method}, true, false
		}
		executable := executableOverride
		if executable == "" && !executableOverrideUnresolved {
			executable = "/bin/sh"
			contextQualifiers["shell_executable"] = "python-posix-default"
		}
		contextQualifiers["shell"] = "true"
		return embeddedInvocation{
			executableOnly: executable, processAttempt: true, argumentsUnresolved: true,
			api: call.method, qualifiers: contextQualifiers,
		}, true, false
	}
	fields, ok := exactPythonArgvFields(args[0], budget)
	if !ok {
		if executable, exact := exactPythonArgvExecutable(args[0], budget); exact {
			if executableOverrideUnresolved {
				executable = ""
			} else if executableOverride != "" {
				executable = executableOverride
			}
			return embeddedInvocation{
				executableOnly:      executable,
				processAttempt:      true,
				argumentsUnresolved: true,
				api:                 call.method,
				qualifiers:          contextQualifiers,
			}, true, false
		}
		return embeddedInvocation{
			processAttempt: true, argumentsUnresolved: true, api: call.method,
			qualifiers: contextQualifiers,
		}, true, false
	}
	if executableOverrideUnresolved {
		return embeddedInvocation{
			processAttempt: true, argumentsUnresolved: true, api: call.method,
			qualifiers: contextQualifiers,
		}, true, false
	}
	if executableOverride != "" {
		return embeddedInvocation{
			executableOnly: executableOverride, processAttempt: true, argumentsUnresolved: true,
			api: call.method, qualifiers: contextQualifiers,
		}, true, false
	}
	return embeddedInvocation{argv: fields, api: call.method}, true, false
}

func exactPythonArgvExecutable(expression string, budget *textLineBudget) (string, bool) {
	expression = strings.TrimSpace(expression)
	if len(expression) < 2 || expression[0] != '[' && expression[0] != '(' {
		return "", false
	}
	close := byte(']')
	if expression[0] == '(' {
		close = ')'
	}
	if expression[len(expression)-1] != close {
		return "", false
	}
	elements, limited, malformed := exactPythonArguments(expression[1:len(expression)-1], maxTextStringExpressionArguments)
	if limited {
		if budget != nil {
			budget.markLimited(fmt.Sprintf("Python argv argument limit %d reached", maxTextStringExpressionArguments), false)
		}
		return "", false
	}
	if malformed || len(elements) < 2 {
		// A one-element exact argv is handled by exactPythonArgvFields. This lane
		// exists only when later elements are dynamic or unsupported.
		return "", false
	}
	executable, ok := exactPythonArgvElement(elements[0])
	if !ok || executable == "" || budget != nil && !budget.retainMatch(len(executable), "Python argv executable literal") {
		return "", false
	}
	allExact := true
	for _, element := range elements[1:] {
		if _, exact := exactPythonArgvElement(element); !exact {
			if !boundedPythonExpression(element, 1) {
				return "", false
			}
			allExact = false
		}
	}
	if allExact {
		return "", false
	}
	return executable, true
}

// boundedPythonExpression accepts only a small, non-evaluating
// expression grammar. It distinguishes a valid but unresolved argv or keyword
// value from malformed source. Acceptance proves only that the exact
// subprocess call evaluates an expression at runtime; it does not resolve the
// value, type, control flow, or whether process creation succeeds.
func boundedPythonExpression(expression string, depth int) bool {
	if depth > maxTextStringExpressionDepth {
		return false
	}
	expression = strings.TrimSpace(expression)
	if expression == "" || len(expression) > maxPythonAPICallBytes {
		return false
	}
	if _, ok := exactPythonStringLiteral(expression); ok {
		return true
	}
	if len(expression) > 1 && strings.ContainsRune("bBrRuU", rune(expression[0])) {
		prefixEnd := 0
		for prefixEnd < len(expression) && prefixEnd < 2 && strings.ContainsRune("bBrRuU", rune(expression[prefixEnd])) {
			prefixEnd++
		}
		prefix := strings.ToLower(expression[:prefixEnd])
		if (prefix == "b" || prefix == "r" || prefix == "u" || prefix == "br" || prefix == "rb") && prefixEnd < len(expression) && (expression[prefixEnd] == '\'' || expression[prefixEnd] == '"') {
			if next, ok := skipPythonQuoted(expression, prefixEnd); ok && next == len(expression) {
				return true
			}
		}
	}
	if pythonDottedIdentifierName(expression) || expression == "None" || expression == "True" || expression == "False" || pythonDecimalIntegerLiteral(expression) {
		return true
	}
	if len(expression) >= 2 {
		open := expression[0]
		close := expression[len(expression)-1]
		if open == '[' && close == ']' || open == '(' && close == ')' || open == '{' && close == '}' {
			items, limited, malformed := exactPythonArguments(expression[1:len(expression)-1], maxTextStringExpressionArguments)
			if limited || malformed {
				return false
			}
			for _, item := range items {
				if !boundedPythonExpression(item, depth+1) {
					return false
				}
			}
			return open != '[' || len(items) > 0
		}
	}
	open := strings.IndexByte(expression, '(')
	if open > 0 && pythonDottedIdentifierName(strings.TrimSpace(expression[:open])) {
		arguments, close, exact, limited := exactPythonCallContent(expression, open, maxPythonAPICallBytes)
		if limited || !exact || close != len(expression)-1 {
			return false
		}
		items, itemLimited, malformed := exactPythonArguments(arguments, maxTextStringExpressionArguments)
		if itemLimited || malformed {
			return false
		}
		for _, item := range items {
			_, value, keyword := exactPythonKeywordArgument(item)
			if keyword {
				item = value
			}
			if strings.HasPrefix(strings.TrimSpace(item), "*") || !boundedPythonExpression(item, depth+1) {
				return false
			}
		}
		return true
	}
	return false
}

func pythonDecimalIntegerLiteral(value string) bool {
	if value == "" {
		return false
	}
	if value[0] == '+' || value[0] == '-' {
		value = value[1:]
	}
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] >= '0' && value[index] <= '9' {
			continue
		}
		if value[index] != '_' || index == 0 || index+1 == len(value) || value[index-1] < '0' || value[index-1] > '9' || value[index+1] < '0' || value[index+1] > '9' {
			return false
		}
	}
	return true
}

func pythonEmptyCollectionExpression(value string) bool {
	switch strings.TrimSpace(value) {
	case "[]", "()", "{}":
		return true
	default:
		return false
	}
}

func exactPythonSubprocessKeywordValue(value string) bool {
	if value == "" {
		return false
	}
	if _, ok := exactPythonStringLiteral(value); ok {
		return true
	}
	if len(value) > 1 && (value[0] == 'b' || value[0] == 'B') {
		if _, ok := exactPythonStringLiteral(value[1:]); ok {
			return true
		}
	}
	if value == "()" || value == "[]" || pythonDottedIdentifierName(value) {
		return true
	}
	start := 0
	if value[0] == '+' || value[0] == '-' {
		start = 1
	}
	if start == len(value) {
		return false
	}
	digits := 0
	dot := false
	for index := start; index < len(value); index++ {
		switch {
		case value[index] >= '0' && value[index] <= '9':
			digits++
		case value[index] == '.' && !dot:
			dot = true
		default:
			return false
		}
	}
	return digits > 0
}

func supportedPythonSubprocessKeyword(method, name string) bool {
	if pythonPopenKeyword(name) {
		if method == "check_output" && name == "stdout" {
			return false
		}
		return true
	}
	switch method {
	case "run":
		return name == "input" || name == "capture_output" || name == "check" || name == "timeout"
	case "call", "check_call":
		return name == "timeout"
	case "check_output":
		return name == "input" || name == "timeout"
	default:
		return false
	}
}

func pythonPopenKeyword(name string) bool {
	switch name {
	case "shell", "executable", "cwd", "env",
		"bufsize", "stdin", "stdout", "stderr", "preexec_fn", "close_fds",
		"pass_fds", "startupinfo", "creationflags", "restore_signals",
		"start_new_session", "process_group", "group", "extra_groups", "user",
		"umask", "encoding", "errors", "text", "universal_newlines":
		return true
	default:
		return false
	}
}

func exactPythonArgvFields(expression string, budget *textLineBudget) ([]string, bool) {
	expression = strings.TrimSpace(expression)
	if value, ok := exactPythonArgvElement(expression); ok {
		if value == "" || budget != nil && !budget.retainMatch(len(value), "Python argv literal") {
			return nil, false
		}
		return []string{value}, true
	}
	if len(expression) < 2 || expression[0] != '[' && expression[0] != '(' {
		return nil, false
	}
	close := byte(']')
	if expression[0] == '(' {
		close = ')'
	}
	if expression[len(expression)-1] != close {
		return nil, false
	}
	elements, limited, malformed := exactPythonArguments(expression[1:len(expression)-1], maxTextStringExpressionArguments)
	if limited {
		if budget != nil {
			budget.markLimited(fmt.Sprintf("Python argv argument limit %d reached", maxTextStringExpressionArguments), false)
		}
		return nil, false
	}
	if malformed || len(elements) == 0 {
		return nil, false
	}
	fields := make([]string, 0, len(elements))
	for _, element := range elements {
		value, ok := exactPythonArgvElement(element)
		if !ok || budget != nil && !budget.retainMatch(len(value), "Python argv literal") {
			return nil, false
		}
		fields = append(fields, value)
	}
	if fields[0] == "" {
		return nil, false
	}
	return fields, true
}

func exactPythonArgvElement(expression string) (string, bool) {
	expression = strings.TrimSpace(expression)
	return exactPythonStringLiteral(expression)
}

func exactPythonSubprocessCall(line string) pythonSubprocessCall {
	result := pythonSubprocessCall{}
	for index := 0; index < len(line); {
		switch line[index] {
		case '#':
			return result
		case '\'', '"':
			next, ok := skipPythonQuoted(line, index)
			if !ok {
				if result.candidate {
					result.malformed = true
				}
				return result
			}
			index = next
			continue
		}
		method, tokenBytes := pythonSubprocessMethodAt(line, index)
		if method == "" {
			index++
			continue
		}
		open := index + tokenBytes
		for open < len(line) && (line[open] == ' ' || line[open] == '\t') {
			open++
		}
		if open >= len(line) || line[open] != '(' {
			index += tokenBytes
			continue
		}
		result.candidate = true
		if strings.TrimSpace(line[:index]) != "" {
			result.malformed = true
			return result
		}
		close, ok := exactPythonMatchingClose(line, open)
		if !ok {
			result.malformed = true
			return result
		}
		if strings.TrimSpace(line[close+1:]) != "" {
			result.malformed = true
			return result
		}
		if result.method != "" {
			result.ambiguous = true
			return result
		}
		result.method = method
		result.arguments = line[open+1 : close]
		index = close + 1
	}
	return result
}

func pythonSubprocessMethodAt(line string, index int) (string, int) {
	if index > 0 && (pythonIdentifierByte(line[index-1]) || line[index-1] == '.') {
		return "", 0
	}
	const prefix = "subprocess."
	if !strings.HasPrefix(line[index:], prefix) {
		return "", 0
	}
	for _, method := range []string{"check_output", "check_call", "Popen", "call", "run"} {
		token := prefix + method
		if !strings.HasPrefix(line[index:], token) {
			continue
		}
		end := index + len(token)
		if end < len(line) && pythonIdentifierByte(line[end]) {
			continue
		}
		return method, len(token)
	}
	return "", 0
}

func callTextAfterMarker(line, lower, marker string) string {
	idx := strings.Index(lower, marker)
	if idx < 0 {
		return ""
	}
	return callTextAtOpen(line, idx+len(marker)-1)
}

func firstCallText(line, marker string) string {
	idx := strings.Index(line, marker)
	if idx < 0 {
		return ""
	}
	open := idx + len(marker) - 1
	if open < 0 || open >= len(line) || line[open] != '(' {
		return ""
	}
	return callTextAtOpen(line, open)
}

func callTextAtOpen(line string, open int) string {
	if open < 0 || open >= len(line) || line[open] != '(' {
		return ""
	}
	var quote rune
	escaped := false
	depth := 0
	for i, r := range line[open:] {
		pos := open + i
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' || r == '`' {
			quote = r
			continue
		}
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return line[open+1 : pos]
			}
		}
	}
	return line[open+1:]
}

func firstCallStringArgument(line string, open int) string {
	if open < 0 || open >= len(line) || line[open] != '(' {
		return ""
	}
	return firstCallStringArgumentFromText(callTextAtOpen(line, open))
}

func firstCallArgumentFromText(text string) string {
	start := 0
	depth := 0
	var quote rune
	escaped := false
	for i, r := range text {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' || r == '`' {
			quote = r
			continue
		}
		switch r {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				return strings.TrimSpace(text[start:i])
			}
		}
	}
	return strings.TrimSpace(text[start:])
}

func firstCallStringArgumentFromText(text string) string {
	value := firstCallArgumentFromText(text)
	if value == "" {
		return ""
	}
	if literal := simpleStringLiteral(value); literal != "" {
		return literal
	}
	if looksLikeExpandedShellCommand(value) {
		return strings.TrimSpace(value)
	}
	return ""
}

func simpleStringLiteral(expr string) string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return ""
	}
	rawLiteral := false
	formatLiteral := false
	lower := strings.ToLower(expr)
	for _, prefix := range []string{"br", "rb", "fr", "rf", "ur", "ru", "b", "r", "u", "f"} {
		if strings.HasPrefix(lower, prefix) && len(expr) > len(prefix) {
			next := expr[len(prefix)]
			if next == '\'' || next == '"' || next == '`' {
				rawLiteral = strings.Contains(prefix, "r")
				formatLiteral = strings.Contains(prefix, "f")
				expr = strings.TrimSpace(expr[len(prefix):])
				break
			}
		}
	}
	if len(expr) < 2 {
		return ""
	}
	quote := expr[0]
	if quote != '\'' && quote != '"' && quote != '`' {
		return ""
	}
	if expr[len(expr)-1] != quote {
		return ""
	}
	value := expr[1 : len(expr)-1]
	if quote == '`' && strings.Contains(value, "${") {
		return ""
	}
	if formatLiteral && strings.Contains(value, "{") {
		return ""
	}
	if rawLiteral {
		return value
	}
	return unescapeSimpleString(value)
}

func unescapeSimpleString(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	escaped := false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if !escaped {
			if ch == '\\' {
				escaped = true
				continue
			}
			out.WriteByte(ch)
			continue
		}
		escaped = false
		switch ch {
		case '\\':
			out.WriteByte('\\')
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case '"', '\'', '`':
			out.WriteByte(ch)
		default:
			out.WriteByte('\\')
			out.WriteByte(ch)
		}
	}
	if escaped {
		out.WriteByte('\\')
	}
	return out.String()
}

func looksLikeExpandedShellCommand(expr string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" || strings.ContainsAny(expr, "()[]{}+") {
		return false
	}
	tool := FirstShellCommand(expr)
	if tool == "" {
		return false
	}
	switch filepath.Base(tool) {
	case "curl", "wget", "sh", "bash", "zsh", "python", "python3", "node", "deno", "chmod", "xattr", "spctl", "launchctl", "security", "dscl", "zip", "unzip", "tar", "ditto":
		return true
	default:
		return looksExecutable(tool)
	}
}

func splitCallArgumentsLimited(text string, maxArguments int) ([]string, bool) {
	var out []string
	start := 0
	var quote rune
	escaped := false
	depth := 0
	for i, r := range text {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' || r == '`' {
			quote = r
			continue
		}
		switch r {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				appendCallArgument(&out, text[start:i])
				if maxArguments > 0 && len(out) > maxArguments {
					return nil, true
				}
				start = i + 1
			}
		}
	}
	appendCallArgument(&out, text[start:])
	if maxArguments > 0 && len(out) > maxArguments {
		return nil, true
	}
	return out, false
}

func appendCallArgument(out *[]string, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		*out = append(*out, value)
	}
}

func condensed(value string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		default:
			return r
		}
	}, value)
}

func firstQuotedBudget(line string, budget *textLineBudget) string {
	values := quotedValuesBudget(line, budget)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func quotedValuesBudget(line string, budget *textLineBudget) []string {
	var out []string
	for _, match := range boundedTextRegexpMatches(reQuoted, line, "quoted value", budget) {
		if match[1]-match[0] >= 2 {
			value := line[match[0]+1 : match[1]-1]
			if strings.TrimSpace(value) != "" {
				out = append(out, value)
			}
		}
	}
	return out
}

func destinations(text string) []string {
	destinations, _ := destinationsWithStatus(text)
	return destinations
}

func destinationsWithStatus(text string) ([]string, bool) {
	state := newTextDerivedBudget()
	destinations := destinationsBudget(text, state.line())
	return destinations, state.limited
}

func destinationsBudget(text string, budget *textLineBudget) []string {
	seen := map[string]bool{}
	urlHosts := map[string]bool{}
	var out []string
	add := func(value string) {
		value = strings.TrimRight(value, `.,);]}`)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}
	for _, match := range boundedTextRegexpMatches(reURL, text, "URL", budget) {
		raw := text[match[0]:match[1]]
		parsed, err := url.Parse(cleanRawURL(raw))
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		urlHosts[strings.ToLower(parsed.Hostname())] = true
		add(parsed.String())
	}
	for _, index := range boundedTextIPv4Matches(text, budget) {
		match, _ := validatedIPv4Match(text, index)
		if urlHosts[strings.ToLower(match)] {
			continue
		}
		add(match)
	}
	if len(text) < 1000 {
		lowerText := strings.ToLower(text)
		for _, index := range boundedTextRegexpMatches(reHost, lowerText, "hostname", budget) {
			match := lowerText[index[0]:index[1]]
			if colon := strings.LastIndexByte(match, ':'); colon >= 0 {
				match = match[:colon]
			}
			if likelyHost(match) {
				if urlHosts[match] {
					continue
				}
				add(match)
			}
		}
	}
	sort.Strings(out)
	return out
}

func cleanRawURL(value string) string {
	if idx := strings.Index(value, ")."); idx > 0 {
		value = value[:idx]
	}
	return strings.TrimRight(value, `.,);]}`)
}

func likelyHost(value string) bool {
	if strings.Contains(value, "..") {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	tld := parts[len(parts)-1]
	switch tld {
	case "com", "org", "net", "io", "dev", "app", "cloud", "ai", "example", "co", "uk", "us", "shop":
		return true
	default:
		return false
	}
}

func networkResource(dest []string) behavior.Resource {
	if len(dest) == 0 {
		return behavior.NewResource(behavior.ResourceNetworkEndpoint, "")
	}
	if strings.Contains(dest[0], "://") {
		return behavior.NewResource(behavior.ResourceURL, dest[0])
	}
	return behavior.NewResource(behavior.ResourceNetworkEndpoint, dest[0])
}

func networkOperationBindings(kind behavior.OperationKind, destinations []string, localOutput, localInput string) []behavior.ResourceBinding {
	remote := networkResource(destinations)
	switch kind {
	case behavior.OperationNetworkDownload:
		bindings := behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteSource, remote))
		if localOutput != "" {
			bindings = append(bindings, behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, localOutput)))
		}
		return bindings
	case behavior.OperationNetworkUpload:
		bindings := behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, remote))
		if localInput != "" {
			bindings = append(bindings, behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, localInput)))
		}
		return bindings
	default:
		return behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, remote))
	}
}

func requiredResourceBindings(kind behavior.OperationKind, resource behavior.Resource) []behavior.ResourceBinding {
	for _, policy := range behavior.OperationResourcePolicy(kind) {
		if policy.Required && behavior.ValidOperationResourceRole(kind, policy.Role, resource.Kind) {
			return behavior.Bindings(behavior.Bind(policy.Role, resource))
		}
	}
	return nil
}

func sensitiveResourceFeatureCategory(resource behavior.Resource) string {
	for _, classification := range resource.Classifications {
		switch classification {
		case behavior.ResourceClassKeychain:
			return "keychain"
		case behavior.ResourceClassBrowserDataStore:
			return "browser.data-store"
		case behavior.ResourceClassBrowserCookieStore:
			return "browser.cookies"
		case behavior.ResourceClassBrowserPasswordStore:
			return "browser.password-store"
		case behavior.ResourceClassCryptoWalletStore:
			return "crypto-wallet"
		case behavior.ResourceClassSSHPrivateKey:
			return "ssh-private-key"
		case behavior.ResourceClassCloudCredentialStore:
			return "cloud-credentials"
		case behavior.ResourceClassDeveloperTokenStore:
			return "developer-token"
		case behavior.ResourceClassMessagingDataStore:
			return "messaging.data-store"
		case behavior.ResourceClassMailDataStore:
			return "mail.data-store"
		case behavior.ResourceClassNotesDataStore:
			return "notes.data-store"
		case behavior.ResourceClassVPNProfileStore:
			return "vpn.profile-store"
		}
	}
	return ""
}

func delegatedURLDestinationsWithStatus(text string) ([]string, bool) {
	if !reURL.MatchString(text) {
		return nil, false
	}
	return destinationsWithStatus(text)
}

func delegatedURLDestinationsBudget(text string, budget *textLineBudget) []string {
	if !reURL.MatchString(text) {
		return nil
	}
	return destinationsBudget(text, budget)
}

func addDelegatedNetworkOperation(graph *behavior.Graph, content artifact.Content, caller string, dest []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) string {
	operationID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID:    content.NodeID,
		ScopeID:          content.ScopeID,
		Kind:             behavior.OperationNetworkConnect,
		ResourceBindings: networkOperationBindings(behavior.OperationNetworkConnect, dest, "", ""),
		Qualifiers:       map[string]string{"delegated": "true"},
		EvidenceIDs:      []string{evidenceID},
		Support:          behavior.SupportCorroborated,
		Execution:        execution,
		Line:             lineNo,
	})
	graph.AddNetworkImplementation(behavior.NetworkImplementationObservation{
		Kind:                 behavior.NetworkImplementationDelegatedHandler,
		SubjectNodeID:        content.NodeID,
		ScopeID:              content.ScopeID,
		Architecture:         content.Architecture,
		OperationIDs:         []string{operationID},
		APIOrTool:            caller,
		HTTPImplementation:   "LaunchServices URL handler",
		TLSProvider:          "delegated application",
		TLSProviderBasis:     behavior.TLSProviderBasisDelegated,
		TLSProfileFamily:     "handler-dependent",
		UnresolvedProperties: []string{"default URL handler", "handler application version", "proxy policy", "ALPN", "session state"},
		EvidenceIDs:          []string{evidenceID},
		Support:              behavior.SupportCorroborated,
		Execution:            execution,
	})
	return operationID
}

func networkImplementationObservation(operationID string, content artifact.Content, language, evidenceID string) behavior.NetworkImplementationObservation {
	caller, httpStack, tlsOwner, family := runtimeNetworkStack(language)
	return behavior.NetworkImplementationObservation{
		Kind:                 behavior.NetworkImplementationRuntimeAPI,
		SubjectNodeID:        content.NodeID,
		ScopeID:              content.ScopeID,
		Architecture:         content.Architecture,
		OperationIDs:         []string{operationID},
		APIOrTool:            caller,
		HTTPImplementation:   httpStack,
		TLSProvider:          tlsOwner,
		TLSProviderBasis:     behavior.TLSProviderBasisRuntimeSelected,
		TLSProfileFamily:     family,
		UnresolvedProperties: []string{"runtime version", "proxy policy", "ALPN", "session state"},
		EvidenceIDs:          []string{evidenceID},
		Support:              behavior.SupportCorroborated,
		Execution:            executionContextForContent(content),
	}
}

func runtimeNetworkStack(language string) (caller, httpStack, tlsOwner, family string) {
	switch language {
	case "python":
		return "Python", "requests/httpx/urllib", "Python ssl module", "OpenSSL-compatible runtime provider"
	case "javascript":
		return "JavaScript runtime", "fetch/axios/http", "selected JavaScript runtime TLS provider", "runtime-dependent"
	case "shell":
		return "shell command", "command-selected", "command-selected TLS provider", "command-dependent"
	case "rust-source":
		return "Rust source", "curl crate or Rust HTTP client", "crate-selected TLS provider", "crate-dependent"
	default:
		return "source", "unknown", "unknown", "unknown"
	}
}
