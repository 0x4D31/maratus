package extract

import (
	"fmt"
	"sort"
	"strings"
)

const (
	maxJavaScriptStructuralBytes      = 8 << 20
	maxJavaScriptStructuralStatements = 64 << 10
	maxJavaScriptStructuralDepth      = 128
	// Compact tokens retain more syntax within the former 64 MiB token payload
	// allowance. This fixed count is identical across architectures.
	maxJavaScriptStructuralTokens = (64 << 20) / 48
	maxJavaScriptStructuralUses   = 256 << 10
)

type javaScriptStructuralDisposition string

const (
	javaScriptStructuralComplete    javaScriptStructuralDisposition = "complete"
	javaScriptStructuralLimited     javaScriptStructuralDisposition = "limited"
	javaScriptStructuralMalformed   javaScriptStructuralDisposition = "malformed"
	javaScriptStructuralUnsupported javaScriptStructuralDisposition = "unsupported"
)

type javaScriptLineDisposition string

const (
	javaScriptLineIgnored    javaScriptLineDisposition = "ignored"
	javaScriptLineStructural javaScriptLineDisposition = "structural"
	javaScriptLineDirect     javaScriptLineDisposition = "direct"
	javaScriptLineOpaque     javaScriptLineDisposition = "opaque"
	javaScriptLineRejected   javaScriptLineDisposition = "rejected"
)

type javaScriptStructuralUse struct {
	Name string
	Line int
}

type javaScriptStructuralRange struct {
	StartLine int
	EndLine   int
}

// javaScriptStructuralStatement is one semicolon-terminated statement that is
// directly owned either by the module or by an exact supported function body.
// Text retains the source for evidence. DirectText has opaque nested regions
// replaced with spaces (newlines are retained) and is the only representation
// suitable for subsequent closed matching.
type javaScriptStructuralStatement struct {
	Text         string
	DirectText   string
	StartLine    int
	EndLine      int
	ScopeKey     string
	FunctionName string
	Uses         []javaScriptStructuralUse
	OpaqueRanges []javaScriptStructuralRange
}

type javaScriptStructuralScope struct {
	Key       string
	Name      string
	StartLine int
	EndLine   int
}

type javaScriptStructuralLine struct {
	Line        int
	Disposition javaScriptLineDisposition
	ScopeKey    string
}

type javaScriptStructuralHiddenUse struct {
	Name          string
	ScopeKey      string
	Line          int
	Write         bool
	UnsafeRuntime bool
}

// javaScriptStructuralIndex is a fail-closed structural view, not a JavaScript
// AST. Limited and malformed results contain no statements. Unsupported
// results may retain independently proven statements while reporting that at
// least one source statement was deliberately made opaque.
type javaScriptStructuralIndex struct {
	Statements  []javaScriptStructuralStatement
	Scopes      []javaScriptStructuralScope
	Lines       []javaScriptStructuralLine
	HiddenUses  []javaScriptStructuralHiddenUse
	Disposition javaScriptStructuralDisposition
	Detail      string
}

type javaScriptStructuralLimits struct {
	bytes      int
	statements int
	depth      int
	tokens     int
	uses       int
}

var defaultJavaScriptStructuralLimits = javaScriptStructuralLimits{
	bytes:      maxJavaScriptStructuralBytes,
	statements: maxJavaScriptStructuralStatements,
	depth:      maxJavaScriptStructuralDepth,
	tokens:     maxJavaScriptStructuralTokens,
	uses:       maxJavaScriptStructuralUses,
}

type javaScriptStructuralTokenKind uint8

const (
	javaScriptStructuralIdentifier javaScriptStructuralTokenKind = iota + 1
	javaScriptStructuralPunctuator
	javaScriptStructuralLiteral
	javaScriptStructuralNumber
	javaScriptStructuralTemplate
	javaScriptStructuralSlash
)

type javaScriptStructuralToken struct {
	text      string
	start     int
	end       int
	depth     int
	line      uint32
	kind      javaScriptStructuralTokenKind
	multiline bool
}

type javaScriptStructuralSpan struct {
	start int
	end   int
}

type javaScriptFunctionDescriptor struct {
	name            string
	scopeKey        string
	start           int
	parametersOpen  int
	parametersClose int
	bodyOpen        int
	bodyClose       int
	generator       bool
}

type javaScriptStructuralBuilder struct {
	source         string
	lineStarts     []int
	tokens         []javaScriptStructuralToken
	match          map[int]int
	reverseMatch   map[int]int
	limits         javaScriptStructuralLimits
	index          javaScriptStructuralIndex
	statementCount int
	useCount       int
	hiddenUseKey   map[string]int
}

func buildJavaScriptStructuralIndex(lines []string) javaScriptStructuralIndex {
	return buildJavaScriptStructuralIndexWithLimits(lines, defaultJavaScriptStructuralLimits)
}

func buildJavaScriptStructuralIndexWithLimits(
	lines []string,
	limits javaScriptStructuralLimits,
) javaScriptStructuralIndex {
	builder := javaScriptStructuralBuilder{
		limits: limits,
		index: javaScriptStructuralIndex{
			Disposition: javaScriptStructuralComplete,
			Lines:       make([]javaScriptStructuralLine, len(lines)),
		},
	}
	for index := range builder.index.Lines {
		builder.index.Lines[index] = javaScriptStructuralLine{
			Line:        index + 1,
			Disposition: javaScriptLineIgnored,
		}
	}
	if detail := validateJavaScriptStructuralLimits(limits); detail != "" {
		return builder.reject(javaScriptStructuralLimited, detail)
	}
	normalizedLines := lines
	copiedLines := false
	totalBytes := 0
	for index, line := range lines {
		if strings.ContainsRune(line, '\n') ||
			strings.ContainsRune(strings.TrimSuffix(line, "\r"), '\r') {
			return builder.reject(
				javaScriptStructuralMalformed,
				"JavaScript structural index input contained an embedded line separator",
			)
		}
		if strings.HasSuffix(line, "\r") {
			if !copiedLines {
				normalizedLines = append([]string(nil), lines...)
				copiedLines = true
			}
			line = strings.TrimSuffix(line, "\r")
			normalizedLines[index] = line
		}
		if index > 0 {
			if totalBytes >= limits.bytes {
				return builder.reject(
					javaScriptStructuralLimited,
					fmt.Sprintf("JavaScript structural index byte limit %d reached", limits.bytes),
				)
			}
			totalBytes++
		}
		if len(line) > limits.bytes-totalBytes {
			return builder.reject(
				javaScriptStructuralLimited,
				fmt.Sprintf("JavaScript structural index byte limit %d reached", limits.bytes),
			)
		}
		totalBytes += len(line)
	}
	builder.source = strings.Join(normalizedLines, "\n")
	builder.lineStarts = javaScriptStructuralLineStarts(builder.source)

	var limitDetail string
	_, valid := scanJavaScriptSyntax(
		builder.source,
		0,
		len(builder.source),
		0,
		func(event javaScriptSyntaxEvent) bool {
			if event.depth > limits.depth {
				limitDetail = fmt.Sprintf(
					"JavaScript structural index depth limit %d reached",
					limits.depth,
				)
				return false
			}
			if len(builder.tokens) >= limits.tokens {
				limitDetail = fmt.Sprintf(
					"JavaScript structural index token limit %d reached",
					limits.tokens,
				)
				return false
			}
			builder.tokens = append(builder.tokens, builder.token(event))
			return true
		},
	)
	if limitDetail != "" {
		return builder.reject(javaScriptStructuralLimited, limitDetail)
	}
	if !valid {
		return builder.reject(
			javaScriptStructuralMalformed,
			"JavaScript structural index rejected malformed or unbalanced syntax",
		)
	}
	if detail := builder.finishTemplateTokens(); detail != "" {
		return builder.reject(javaScriptStructuralUnsupported, detail)
	}
	if !builder.buildDelimiterMatches() {
		return builder.reject(
			javaScriptStructuralMalformed,
			"JavaScript structural index rejected malformed or unbalanced delimiters",
		)
	}

	builder.collectRange(0, len(builder.tokens), 0, "", "")
	if builder.index.Disposition == javaScriptStructuralLimited ||
		builder.index.Disposition == javaScriptStructuralMalformed {
		return builder.reject(builder.index.Disposition, builder.index.Detail)
	}
	sort.Slice(builder.index.HiddenUses, func(i, j int) bool {
		if builder.index.HiddenUses[i].ScopeKey != builder.index.HiddenUses[j].ScopeKey {
			return builder.index.HiddenUses[i].ScopeKey < builder.index.HiddenUses[j].ScopeKey
		}
		if builder.index.HiddenUses[i].Line != builder.index.HiddenUses[j].Line {
			return builder.index.HiddenUses[i].Line < builder.index.HiddenUses[j].Line
		}
		return builder.index.HiddenUses[i].Name < builder.index.HiddenUses[j].Name
	})
	return builder.index
}

func validateJavaScriptStructuralLimits(limits javaScriptStructuralLimits) string {
	switch {
	case limits.bytes < 0 || limits.bytes > maxJavaScriptStructuralBytes:
		return "JavaScript structural index byte limit was invalid"
	case limits.statements < 0:
		return "JavaScript structural index statement limit was invalid"
	case limits.depth < 0 || limits.depth > maxJavaScriptSyntaxNesting:
		return "JavaScript structural index depth limit was invalid"
	case limits.tokens < 0:
		return "JavaScript structural index token limit was invalid"
	case limits.uses < 0:
		return "JavaScript structural index use limit was invalid"
	default:
		return ""
	}
}

func (builder *javaScriptStructuralBuilder) token(event javaScriptSyntaxEvent) javaScriptStructuralToken {
	text := builder.source[event.start:event.end]
	token := javaScriptStructuralToken{
		text:  text,
		start: event.start,
		end:   event.end,
		line:  uint32(builder.lineAt(event.start)),
		depth: event.depth,
	}
	switch {
	case event.kind == javaScriptSyntaxIdentifier:
		token.kind = javaScriptStructuralIdentifier
	case len(text) > 0 && (text[0] == '\'' || text[0] == '"'):
		token.kind = javaScriptStructuralLiteral
	case len(text) > 0 && text[0] >= '0' && text[0] <= '9':
		token.kind = javaScriptStructuralNumber
	case text == "`":
		token.kind = javaScriptStructuralTemplate
	case strings.HasPrefix(text, "/"):
		token.kind = javaScriptStructuralSlash
	default:
		token.kind = javaScriptStructuralPunctuator
	}
	return token
}

// scanJavaScriptSyntax intentionally reports only the opening backtick because
// template internals are not identifiers available to matching. Recover the
// complete token in a bounded local walk. Interpolations use the same lexical
// delimiter rules as whole-file validation and hidden-use inventory.
func (builder *javaScriptStructuralBuilder) finishTemplateTokens() string {
	for index := range builder.tokens {
		token := &builder.tokens[index]
		if token.kind != javaScriptStructuralTemplate {
			continue
		}
		end, multiline, ok := simpleJavaScriptStructuralTemplateEnd(
			builder.source,
			token.start,
		)
		if !ok {
			return "JavaScript structural index rejected unsupported template interpolation syntax"
		}
		token.end = end
		token.text = builder.source[token.start:end]
		token.multiline = multiline
	}
	return ""
}

func simpleJavaScriptStructuralTemplateEnd(source string, start int) (int, bool, bool) {
	if start < 0 || start >= len(source) || source[start] != '`' {
		return 0, false, false
	}
	multiline := false
	for index := start + 1; index < len(source); {
		switch source[index] {
		case '\\':
			if index+1 >= len(source) {
				return 0, multiline, false
			}
			index += 2
		case '\n', '\r':
			multiline = true
			index++
		case '`':
			return index + 1, multiline, true
		case '$':
			if index+1 >= len(source) || source[index+1] != '{' {
				index++
				continue
			}
			end, nestedMultiline, ok := simpleJavaScriptStructuralInterpolationEnd(
				source,
				index+2,
			)
			if !ok {
				return 0, multiline, false
			}
			multiline = multiline || nestedMultiline
			index = end
		default:
			index++
		}
	}
	return 0, multiline, false
}

func simpleJavaScriptStructuralInterpolationEnd(source string, start int) (int, bool, bool) {
	// Share the bounded lexer rather than treating every slash as an unknown
	// delimiter. Regex literals and division must follow the same rules here
	// as in the complete-file validation and hidden-write inventory.
	end, ok := scanJavaScriptSyntax(source, start, len(source), '{', nil)
	if !ok || end < start {
		return 0, false, false
	}
	return end + 1, strings.ContainsAny(source[start:end], "\r\n"), true
}

func (builder *javaScriptStructuralBuilder) buildDelimiterMatches() bool {
	builder.match = make(map[int]int)
	builder.reverseMatch = make(map[int]int)
	var stack []int
	for index, token := range builder.tokens {
		if token.kind != javaScriptStructuralPunctuator || len(token.text) != 1 {
			continue
		}
		switch token.text[0] {
		case '(', '[', '{':
			stack = append(stack, index)
		case ')', ']', '}':
			if len(stack) == 0 {
				return false
			}
			open := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if !javaScriptDelimitersMatch(builder.tokens[open].text[0], token.text[0]) {
				return false
			}
			builder.match[open] = index
			builder.reverseMatch[index] = open
		}
	}
	return len(stack) == 0
}

func (builder *javaScriptStructuralBuilder) collectRange(
	start int,
	limit int,
	baseDepth int,
	scopeKey string,
	functionName string,
) {
	for cursor := start; cursor < limit; {
		cursor = builder.nextAtDepth(cursor, limit, baseDepth)
		if cursor >= limit || builder.failed() {
			return
		}
		token := builder.tokens[cursor]
		if token.text == ";" {
			cursor++
			continue
		}

		if baseDepth == 0 {
			if bodyOpen, bodyClose, end, ok := builder.wholeProgramIIFE(cursor, limit); ok {
				builder.markRange(
					builder.tokens[cursor].start,
					builder.tokens[bodyOpen].end,
					javaScriptLineStructural,
					"",
				)
				builder.markRange(
					builder.tokens[bodyClose].start,
					builder.tokens[end-1].end,
					javaScriptLineStructural,
					"",
				)
				builder.collectRange(
					bodyOpen+1,
					bodyClose,
					builder.tokens[bodyOpen].depth+1,
					"",
					"",
				)
				return
			}
		}

		if functionName == "" {
			if function, ok := builder.namedFunctionAtDepth(cursor, limit, baseDepth); ok {
				builder.recordHiddenUses(
					function.start,
					builder.tokens[function.bodyOpen].start,
					function.scopeKey,
				)
				if builder.failed() {
					return
				}
				builder.index.Scopes = append(builder.index.Scopes, javaScriptStructuralScope{
					Key:       function.scopeKey,
					Name:      function.name,
					StartLine: builder.lineAt(function.start),
					EndLine:   builder.lineAt(builder.tokens[function.bodyClose].start),
				})
				exact := !function.generator &&
					builder.simpleFunctionParameters(
						function.parametersOpen+1,
						function.parametersClose,
						baseDepth+1,
					)
				if !exact {
					if !builder.chargeStatement() {
						return
					}
					builder.recordHiddenUses(
						builder.tokens[function.bodyOpen].start,
						builder.tokens[function.bodyClose].end,
						function.scopeKey,
					)
					if builder.failed() {
						return
					}
					builder.markRange(
						function.start,
						builder.tokens[function.bodyClose].end,
						javaScriptLineOpaque,
						function.scopeKey,
					)
					builder.noteUnsupported(
						"JavaScript structural index omitted an unsupported named function signature",
					)
					cursor = function.bodyClose + 1
					if cursor < limit &&
						builder.tokens[cursor].depth == baseDepth &&
						builder.tokens[cursor].text == ";" {
						cursor++
					}
					continue
				}
				builder.markRange(
					function.start,
					builder.tokens[function.bodyOpen].end,
					javaScriptLineStructural,
					function.scopeKey,
				)
				builder.markRange(
					builder.tokens[function.bodyClose].start,
					builder.tokens[function.bodyClose].end,
					javaScriptLineStructural,
					function.scopeKey,
				)
				builder.collectRange(
					function.bodyOpen+1,
					function.bodyClose,
					baseDepth+1,
					function.scopeKey,
					function.name,
				)
				cursor = function.bodyClose + 1
				if cursor < limit &&
					builder.tokens[cursor].depth == baseDepth &&
					builder.tokens[cursor].text == ";" {
					cursor++
				}
				continue
			}
		}

		if javaScriptStructuralOpaqueStatementStart(token.text) {
			if !builder.chargeStatement() {
				return
			}
			end := builder.opaqueStatementEnd(cursor, limit, baseDepth)
			if end <= cursor {
				builder.noteUnsupported(
					"JavaScript structural index omitted an unsupported compound statement",
				)
				return
			}
			builder.recordHiddenUses(
				builder.tokens[cursor].start,
				builder.tokens[end-1].end,
				scopeKey,
			)
			if builder.failed() {
				return
			}
			builder.markRange(
				builder.tokens[cursor].start,
				builder.tokens[end-1].end,
				javaScriptLineOpaque,
				scopeKey,
			)
			cursor = end
			continue
		}

		statementEnd, complete := builder.nextStatementEnd(cursor, limit, baseDepth)
		if !complete {
			builder.recordHiddenUses(
				builder.tokens[cursor].start,
				builder.tokens[limit-1].end,
				scopeKey,
			)
			if builder.failed() {
				return
			}
			builder.markRange(
				builder.tokens[cursor].start,
				builder.tokens[limit-1].end,
				javaScriptLineOpaque,
				scopeKey,
			)
			builder.noteUnsupported(
				"JavaScript structural index omitted a semicolon-less statement",
			)
			return
		}
		if builder.containsDirectCompoundBoundary(cursor+1, statementEnd, baseDepth) {
			builder.recordHiddenUses(
				builder.tokens[cursor].start,
				builder.tokens[statementEnd].end,
				scopeKey,
			)
			if builder.failed() {
				return
			}
			builder.markRange(
				builder.tokens[cursor].start,
				builder.tokens[statementEnd].end,
				javaScriptLineOpaque,
				scopeKey,
			)
			builder.noteUnsupported(
				"JavaScript structural index omitted an ambiguous compound boundary",
			)
			cursor = statementEnd + 1
			continue
		}
		builder.addStatement(cursor, statementEnd, scopeKey, functionName)
		cursor = statementEnd + 1
	}
}

func (builder *javaScriptStructuralBuilder) nextAtDepth(start, limit, depth int) int {
	for index := start; index < limit; index++ {
		if builder.tokens[index].depth == depth {
			return index
		}
	}
	return limit
}

func (builder *javaScriptStructuralBuilder) nextStatementEnd(start, limit, depth int) (int, bool) {
	previous := -1
	for index := start; index < limit; index++ {
		token := builder.tokens[index]
		if token.depth != depth {
			continue
		}
		if token.text == ";" {
			return index, true
		}
		if previous >= start &&
			builder.tokens[previous].line < token.line &&
			javaScriptStructuralASIBoundary(builder.tokens[previous], token) {
			return previous, true
		}
		previous = index
	}
	if previous >= start && javaScriptStructuralASIEnd(builder.tokens[previous]) {
		return previous, true
	}
	return -1, false
}

func javaScriptStructuralASIBoundary(previous, next javaScriptStructuralToken) bool {
	if !javaScriptStructuralASIEnd(previous) {
		return false
	}
	if javaScriptSyntaxAssignmentToken(next.text) {
		return false
	}
	switch next.text {
	case ".", "?.", "(", "[", ",", "?", ":", "+", "-", "*", "/", "%",
		"**", "&&", "||", "??", "==", "===", "!=", "!==", "<", ">", "<=",
		">=", "<<", ">>", ">>>", "&", "|", "^", "=>":
		return false
	}
	return next.kind != javaScriptStructuralTemplate
}

func javaScriptStructuralASIEnd(token javaScriptStructuralToken) bool {
	switch token.text {
	case "=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=",
		"&=", "|=", "^=", "&&=", "||=", "??=", ".", "?.", ",", "?", ":",
		"(", "[", "{", "+", "-", "*", "/", "%", "**", "&&", "||", "??", "==", "===",
		"!=", "!==", "<", ">", "<=", ">=", "<<", ">>", ">>>", "&", "|",
		"^", "!", "~", "=>", "await", "case", "delete", "in", "instanceof",
		"new", "of", "throw", "typeof", "void", "yield":
		return false
	default:
		return token.text != ""
	}
}

func (builder *javaScriptStructuralBuilder) containsDirectCompoundBoundary(
	start int,
	limit int,
	depth int,
) bool {
	for index := start; index < limit; index++ {
		if builder.tokens[index].depth != depth {
			continue
		}
		switch builder.tokens[index].text {
		case "catch", "do", "else", "finally", "for", "if", "switch", "try",
			"while", "with":
			return true
		}
	}
	return false
}

func (builder *javaScriptStructuralBuilder) namedFunctionAtDepth(
	start int,
	limit int,
	depth int,
) (javaScriptFunctionDescriptor, bool) {
	if start >= limit || builder.tokens[start].depth != depth {
		return javaScriptFunctionDescriptor{}, false
	}
	declarationStart := start
	functionToken := start
	if builder.tokens[functionToken].text == "async" {
		functionToken++
		if functionToken >= limit ||
			builder.tokens[functionToken].line != builder.tokens[declarationStart].line {
			return javaScriptFunctionDescriptor{}, false
		}
	}
	if functionToken+5 >= limit ||
		builder.tokens[functionToken].depth != depth ||
		builder.tokens[functionToken].text != "function" {
		return javaScriptFunctionDescriptor{}, false
	}
	nameIndex := functionToken + 1
	generator := false
	if builder.tokens[nameIndex].text == "*" {
		generator = true
		nameIndex++
	}
	if nameIndex+4 >= limit {
		return javaScriptFunctionDescriptor{}, false
	}
	name := builder.tokens[nameIndex]
	openParameters := builder.tokens[nameIndex+1]
	if name.depth != depth ||
		name.kind != javaScriptStructuralIdentifier ||
		javaScriptSyntaxKeyword(name.text) ||
		openParameters.depth != depth ||
		openParameters.text != "(" {
		return javaScriptFunctionDescriptor{}, false
	}
	closeParameters, ok := builder.match[nameIndex+1]
	if !ok || closeParameters+1 >= limit {
		return javaScriptFunctionDescriptor{}, false
	}
	bodyOpen := closeParameters + 1
	if builder.tokens[bodyOpen].depth != depth || builder.tokens[bodyOpen].text != "{" {
		return javaScriptFunctionDescriptor{}, false
	}
	bodyClose, ok := builder.match[bodyOpen]
	if !ok || bodyClose >= limit {
		return javaScriptFunctionDescriptor{}, false
	}
	line := builder.lineAt(builder.tokens[declarationStart].start)
	return javaScriptFunctionDescriptor{
		name:            name.text,
		scopeKey:        fmt.Sprintf("%s@%d", name.text, line),
		start:           builder.tokens[declarationStart].start,
		parametersOpen:  nameIndex + 1,
		parametersClose: closeParameters,
		bodyOpen:        bodyOpen,
		bodyClose:       bodyClose,
		generator:       generator,
	}, true
}

// wholeProgramIIFE recognizes only a zero-argument immediately invoked wrapper
// that encloses the complete retained program. Treating that wrapper as the
// module scope is sound because no code exists beside it and no call argument
// can alter its lexical bindings. This admits common bundler output without
// evaluating arbitrary call expressions or flattening nested callbacks.
func (builder *javaScriptStructuralBuilder) wholeProgramIIFE(
	start int,
	limit int,
) (bodyOpen, bodyClose, end int, ok bool) {
	if start < 0 || start >= limit || builder.tokens[start].depth != 0 ||
		builder.tokens[start].text != "(" {
		return 0, 0, 0, false
	}
	outerClose, matched := builder.match[start]
	if !matched || outerClose+2 >= limit ||
		builder.tokens[outerClose+1].depth != 0 ||
		builder.tokens[outerClose+1].text != "(" {
		return 0, 0, 0, false
	}
	callClose, matched := builder.match[outerClose+1]
	if !matched || callClose != outerClose+2 {
		return 0, 0, 0, false
	}
	end = callClose + 1
	if end < limit && builder.tokens[end].depth == 0 && builder.tokens[end].text == ";" {
		end++
	}
	if end != limit {
		return 0, 0, 0, false
	}

	inner := start + 1
	if inner >= outerClose {
		return 0, 0, 0, false
	}
	switch builder.tokens[inner].text {
	case "(":
		parametersClose, matched := builder.match[inner]
		if !matched || parametersClose != inner+1 || parametersClose+2 >= outerClose ||
			builder.tokens[parametersClose+1].text != "=>" ||
			builder.tokens[parametersClose+2].text != "{" {
			return 0, 0, 0, false
		}
		bodyOpen = parametersClose + 2
	case "function":
		parametersOpen := inner + 1
		// A named IIFE is permitted, but its name is not exposed as a module
		// binding and therefore cannot affect retained source-order facts.
		if parametersOpen < outerClose && builder.tokens[parametersOpen].kind == javaScriptStructuralIdentifier {
			parametersOpen++
		}
		if parametersOpen >= outerClose || builder.tokens[parametersOpen].text != "(" {
			return 0, 0, 0, false
		}
		parametersClose, matched := builder.match[parametersOpen]
		if !matched || parametersClose != parametersOpen+1 || parametersClose+1 >= outerClose ||
			builder.tokens[parametersClose+1].text != "{" {
			return 0, 0, 0, false
		}
		bodyOpen = parametersClose + 1
	default:
		return 0, 0, 0, false
	}
	bodyClose, matched = builder.match[bodyOpen]
	if !matched || bodyClose+1 != outerClose {
		return 0, 0, 0, false
	}
	return bodyOpen, bodyClose, end, true
}

func (builder *javaScriptStructuralBuilder) simpleFunctionParameters(
	start int,
	limit int,
	depth int,
) bool {
	expectIdentifier := true
	sawIdentifier := false
	for index := start; index < limit; index++ {
		token := builder.tokens[index]
		if token.depth != depth {
			return false
		}
		if expectIdentifier {
			if token.kind != javaScriptStructuralIdentifier ||
				javaScriptSyntaxKeyword(token.text) {
				return false
			}
			sawIdentifier = true
			expectIdentifier = false
			continue
		}
		if token.text != "," {
			return false
		}
		expectIdentifier = true
	}
	return !expectIdentifier || !sawIdentifier
}

func javaScriptStructuralOpaqueStatementStart(token string) bool {
	switch token {
	case "{", "async", "catch", "class", "do", "else", "finally", "for",
		"function", "if", "switch", "try", "while", "with":
		return true
	default:
		return false
	}
}

func (builder *javaScriptStructuralBuilder) opaqueStatementEnd(
	start int,
	limit int,
	depth int,
) int {
	end := builder.oneOpaqueClauseEnd(start, limit, depth)
	if end <= start {
		return end
	}
	first := builder.tokens[start].text
	for end < limit {
		next := builder.nextAtDepth(end, limit, depth)
		if next >= limit {
			return end
		}
		word := builder.tokens[next].text
		absorb := false
		switch first {
		case "if":
			absorb = word == "else"
		case "try":
			absorb = word == "catch" || word == "finally"
		case "do":
			absorb = word == "while"
		}
		if !absorb {
			return end
		}
		end = builder.oneOpaqueClauseEnd(next, limit, depth)
		if end <= next {
			return end
		}
		if first == "if" && word == "else" {
			return end
		}
		if first == "do" && word == "while" {
			return end
		}
	}
	return end
}

func (builder *javaScriptStructuralBuilder) oneOpaqueClauseEnd(
	start int,
	limit int,
	depth int,
) int {
	for index := start; index < limit; index++ {
		token := builder.tokens[index]
		if token.depth != depth {
			continue
		}
		if token.text == ";" {
			return index + 1
		}
		if token.text != "{" {
			continue
		}
		close, ok := builder.match[index]
		if !ok || close >= limit {
			return -1
		}
		end := close + 1
		if end < limit &&
			builder.tokens[end].depth == depth &&
			builder.tokens[end].text == ";" {
			end++
		}
		return end
	}
	return -1
}

func (builder *javaScriptStructuralBuilder) addStatement(
	start int,
	semicolon int,
	scopeKey string,
	functionName string,
) {
	if !builder.chargeStatement() {
		return
	}
	startOffset := builder.tokens[start].start
	endOffset := builder.tokens[semicolon].end
	opaque := builder.statementOpaqueSpans(start, semicolon)
	if builder.statementHasUnsupportedSyntax(start, semicolon, opaque) {
		builder.recordHiddenUses(startOffset, endOffset, scopeKey)
		builder.markRange(startOffset, endOffset, javaScriptLineOpaque, scopeKey)
		return
	}
	for _, span := range opaque {
		builder.recordHiddenUses(span.start, span.end, scopeKey)
	}
	for index := start; index <= semicolon; index++ {
		token := builder.tokens[index]
		if token.kind == javaScriptStructuralTemplate &&
			strings.Contains(builder.source[token.start:token.end], "${") {
			builder.recordHiddenUses(token.start, token.end, scopeKey)
		}
	}
	if builder.failed() {
		return
	}

	directText := maskJavaScriptStructuralSpans(
		builder.source[startOffset:endOffset],
		startOffset,
		opaque,
	)
	statement := javaScriptStructuralStatement{
		Text:         builder.source[startOffset:endOffset],
		DirectText:   directText,
		StartLine:    builder.lineAt(startOffset),
		EndLine:      builder.lineAt(endOffset - 1),
		ScopeKey:     scopeKey,
		FunctionName: functionName,
	}
	for _, span := range opaque {
		statement.OpaqueRanges = append(statement.OpaqueRanges, javaScriptStructuralRange{
			StartLine: builder.lineAt(span.start),
			EndLine:   builder.lineAt(span.end - 1),
		})
	}
	for index := start; index <= semicolon; index++ {
		token := builder.tokens[index]
		if token.kind != javaScriptStructuralIdentifier ||
			javaScriptStructuralOffsetInSpans(token.start, opaque) {
			continue
		}
		if builder.useCount >= builder.limits.uses {
			builder.index.Disposition = javaScriptStructuralLimited
			builder.index.Detail = fmt.Sprintf(
				"JavaScript structural index use limit %d reached",
				builder.limits.uses,
			)
			return
		}
		builder.useCount++
		statement.Uses = append(statement.Uses, javaScriptStructuralUse{
			Name: token.text,
			Line: int(token.line),
		})
	}
	builder.index.Statements = append(builder.index.Statements, statement)
	builder.markRange(startOffset, endOffset, javaScriptLineDirect, scopeKey)
	for _, span := range opaque {
		builder.markRange(span.start, span.end, javaScriptLineOpaque, scopeKey)
	}
}

func (builder *javaScriptStructuralBuilder) recordHiddenUses(start, end int, scopeKey string) {
	if builder.failed() || start < 0 || end <= start || end > len(builder.source) {
		return
	}
	fragment := builder.source[start:end]
	if builder.hiddenUseKey == nil {
		builder.hiddenUseKey = map[string]int{}
	}
	exact := visitJavaScriptIdentifierOccurrences(fragment, len(fragment), true, func(occurrence javaScriptIdentifierOccurrence) bool {
		if !occurrence.Reference ||
			javaScriptStructuralMethodKeyOccurrence(fragment, occurrence) {
			return true
		}
		key := scopeKey + "\x00" + occurrence.Name
		unsafeRuntime := !exactJavaScriptRuntimeRequireCallAt(
			fragment,
			occurrence,
		)
		if retained, exists := builder.hiddenUseKey[key]; exists {
			builder.index.HiddenUses[retained].Write =
				builder.index.HiddenUses[retained].Write || occurrence.Write
			builder.index.HiddenUses[retained].UnsafeRuntime =
				builder.index.HiddenUses[retained].UnsafeRuntime ||
					unsafeRuntime
			return true
		}
		if len(builder.index.HiddenUses) >= builder.limits.uses {
			builder.index.Disposition = javaScriptStructuralLimited
			builder.index.Detail = fmt.Sprintf(
				"JavaScript structural hidden-use limit %d reached",
				builder.limits.uses,
			)
			return false
		}
		builder.hiddenUseKey[key] = len(builder.index.HiddenUses)
		builder.index.HiddenUses = append(
			builder.index.HiddenUses,
			javaScriptStructuralHiddenUse{
				Name:          occurrence.Name,
				ScopeKey:      scopeKey,
				Line:          builder.lineAt(start + occurrence.Offset),
				Write:         occurrence.Write,
				UnsafeRuntime: unsafeRuntime,
			},
		)
		return true
	})
	if !exact && !builder.failed() {
		builder.index.Disposition = javaScriptStructuralLimited
		builder.index.Detail = fmt.Sprintf("JavaScript structural hidden-use lexical scan was incomplete at byte %d (length %d)", start, end-start)
	}
}

func exactJavaScriptRuntimeRequireCallAt(
	source string,
	occurrence javaScriptIdentifierOccurrence,
) bool {
	if occurrence.Name != "require" || occurrence.Write {
		return false
	}
	open, exact := skipJavaScriptTriviaExact(
		source,
		occurrence.Offset+len(occurrence.Name),
	)
	if !exact {
		return false
	}
	if open >= len(source) || source[open] != '(' {
		return false
	}
	body, _, exact := exactJavaScriptCallContent(
		source,
		open,
		maxJavaScriptProcessStatementBytes,
	)
	if !exact {
		return false
	}
	arguments, exact := splitJavaScriptArgumentsExact(
		body,
		maxJavaScriptProcessStatementBytes,
		1,
	)
	if !exact || len(arguments) != 1 {
		return false
	}
	argument := stripJavaScriptStatementComments(arguments[0])
	_, literal := exactJavaScriptQuotedLiteral(argument)
	return literal
}

func skipJavaScriptTriviaExact(source string, index int) (int, bool) {
	if index < 0 || index > len(source) {
		return 0, false
	}
	for {
		index = skipJavaScriptSpace(source, index)
		if index+1 >= len(source) || source[index] != '/' {
			return index, true
		}
		switch source[index+1] {
		case '/':
			index = skipJavaScriptLineComment(source, index+2, len(source))
		case '*':
			end, ok := skipJavaScriptBlockComment(
				source,
				index+2,
				len(source),
			)
			if !ok {
				return 0, false
			}
			index = end
		default:
			return index, true
		}
	}
}

func javaScriptStructuralMethodKeyOccurrence(
	source string,
	occurrence javaScriptIdentifierOccurrence,
) bool {
	if occurrence.previousToken == "function" ||
		occurrence.Offset < 0 ||
		occurrence.Offset+len(occurrence.Name) > len(source) {
		return false
	}
	open := skipJavaScriptSpace(source, occurrence.Offset+len(occurrence.Name))
	if open >= len(source) || source[open] != '(' {
		return false
	}
	_, close, exact := exactJavaScriptCallContent(
		source,
		open,
		len(source),
	)
	if !exact {
		return false
	}
	next := skipJavaScriptSpace(source, close+1)
	return next < len(source) && source[next] == '{'
}

func (builder *javaScriptStructuralBuilder) chargeStatement() bool {
	if builder.statementCount >= builder.limits.statements {
		builder.index.Disposition = javaScriptStructuralLimited
		builder.index.Detail = fmt.Sprintf(
			"JavaScript structural index statement limit %d reached",
			builder.limits.statements,
		)
		return false
	}
	builder.statementCount++
	return true
}

func (builder *javaScriptStructuralBuilder) statementHasUnsupportedSyntax(
	start int,
	end int,
	opaque []javaScriptStructuralSpan,
) bool {
	for index := start; index <= end; index++ {
		token := builder.tokens[index]
		if javaScriptStructuralOffsetInSpans(token.start, opaque) {
			continue
		}
		switch {
		case token.kind == javaScriptStructuralSlash:
			builder.noteUnsupported(
				"JavaScript structural index omitted ambiguous regular-expression or division syntax",
			)
			return true
		case token.kind == javaScriptStructuralTemplate && token.multiline:
			builder.noteUnsupported(
				"JavaScript structural index omitted a multiline template statement",
			)
			return true
		}
	}
	return false
}

func (builder *javaScriptStructuralBuilder) statementOpaqueSpans(
	start int,
	end int,
) []javaScriptStructuralSpan {
	var spans []javaScriptStructuralSpan
	for index := start; index <= end; index++ {
		token := builder.tokens[index]
		if token.text == "=>" {
			span, ok := builder.arrowSpan(start, end, index)
			if ok {
				spans = append(spans, span)
			}
			continue
		}
		if token.text == "{" {
			close, ok := builder.match[index]
			if ok && close <= end {
				if builder.declarationBindingBrace(start, index) {
					continue
				}
				if !builder.executableBodyBrace(start, index) {
					continue
				}
				spans = append(spans, javaScriptStructuralSpan{
					start: builder.executableBodySpanStart(start, index),
					end:   builder.tokens[close].end,
				})
				index = close
			}
		}
	}
	return mergeJavaScriptStructuralSpans(spans)
}

func (builder *javaScriptStructuralBuilder) executableBodySpanStart(
	statementStart int,
	brace int,
) int {
	start := builder.tokens[brace].start
	if brace <= statementStart || builder.tokens[brace-1].text != ")" {
		return start
	}
	open, ok := builder.reverseMatch[brace-1]
	if !ok || open <= statementStart {
		return start
	}
	signature := open - 1
	if signature < statementStart {
		return start
	}
	if builder.tokens[signature].kind == javaScriptStructuralIdentifier {
		start = builder.tokens[signature].start
		if signature > statementStart && builder.tokens[signature-1].text == "*" {
			signature--
			start = builder.tokens[signature].start
		}
		if signature > statementStart &&
			(builder.tokens[signature-1].text == "async" ||
				builder.tokens[signature-1].text == "function") {
			signature--
			start = builder.tokens[signature].start
		}
		if signature > statementStart && builder.tokens[signature-1].text == "async" {
			start = builder.tokens[signature-1].start
		}
		return start
	}
	if builder.tokens[signature].text == "function" {
		start = builder.tokens[signature].start
		if signature > statementStart && builder.tokens[signature-1].text == "async" {
			start = builder.tokens[signature-1].start
		}
	}
	return start
}

func (builder *javaScriptStructuralBuilder) executableBodyBrace(statementStart, brace int) bool {
	if brace <= statementStart || brace >= len(builder.tokens) {
		return false
	}
	previous := brace - 1
	switch builder.tokens[previous].text {
	case "class", "function":
		return true
	case ")":
		open, ok := builder.reverseMatch[previous]
		if !ok || open <= statementStart {
			return false
		}
		before := builder.tokens[open-1]
		if before.text == "function" ||
			before.kind == javaScriptStructuralIdentifier ||
			before.kind == javaScriptStructuralLiteral ||
			before.kind == javaScriptStructuralNumber ||
			before.text == "]" {
			return true
		}
	}
	for index := statementStart; index < brace; index++ {
		if builder.tokens[index].text == "class" &&
			builder.tokens[index].depth == builder.tokens[brace].depth {
			return true
		}
	}
	return false
}

func (builder *javaScriptStructuralBuilder) declarationBindingBrace(statementStart, brace int) bool {
	if brace != statementStart+1 || statementStart < 0 || statementStart >= len(builder.tokens) {
		return false
	}
	switch builder.tokens[statementStart].text {
	case "import", "const", "let", "var":
		return true
	default:
		return false
	}
}

func (builder *javaScriptStructuralBuilder) arrowSpan(
	statementStart int,
	statementEnd int,
	arrow int,
) (javaScriptStructuralSpan, bool) {
	start := builder.tokens[arrow].start
	if arrow > statementStart {
		previous := builder.tokens[arrow-1]
		if previous.text == ")" {
			if open, ok := builder.reverseMatch[arrow-1]; ok && open >= statementStart {
				start = builder.tokens[open].start
			}
		} else if previous.kind == javaScriptStructuralIdentifier {
			start = previous.start
		}
	}
	if arrow+1 > statementEnd {
		return javaScriptStructuralSpan{}, false
	}
	next := builder.tokens[arrow+1]
	if next.text == "{" {
		close, ok := builder.match[arrow+1]
		if !ok || close > statementEnd {
			return javaScriptStructuralSpan{}, false
		}
		return javaScriptStructuralSpan{
			start: start,
			end:   builder.tokens[close].end,
		}, true
	}
	arrowDepth := builder.tokens[arrow].depth
	for index := arrow + 1; index <= statementEnd; index++ {
		token := builder.tokens[index]
		if token.text == "," && token.depth == arrowDepth {
			return javaScriptStructuralSpan{start: start, end: token.start}, true
		}
		if (token.text == ")" || token.text == "]" || token.text == "}") &&
			token.depth < arrowDepth {
			return javaScriptStructuralSpan{start: start, end: token.start}, true
		}
		if token.text == ";" && token.depth <= arrowDepth {
			return javaScriptStructuralSpan{start: start, end: token.start}, true
		}
	}
	return javaScriptStructuralSpan{
		start: start,
		end:   builder.tokens[statementEnd].end,
	}, true
}

func mergeJavaScriptStructuralSpans(spans []javaScriptStructuralSpan) []javaScriptStructuralSpan {
	sort.Slice(spans, func(left, right int) bool {
		if spans[left].start != spans[right].start {
			return spans[left].start < spans[right].start
		}
		return spans[left].end < spans[right].end
	})
	var merged []javaScriptStructuralSpan
	for _, span := range spans {
		if span.end <= span.start {
			continue
		}
		if len(merged) == 0 || span.start > merged[len(merged)-1].end {
			merged = append(merged, span)
			continue
		}
		if span.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = span.end
		}
	}
	return merged
}

func maskJavaScriptStructuralSpans(
	text string,
	offset int,
	spans []javaScriptStructuralSpan,
) string {
	if len(spans) == 0 {
		return text
	}
	masked := []byte(text)
	for _, span := range spans {
		start := span.start - offset
		end := span.end - offset
		if start < 0 {
			start = 0
		}
		if end > len(masked) {
			end = len(masked)
		}
		for index := start; index < end; index++ {
			if masked[index] != '\n' && masked[index] != '\r' {
				masked[index] = ' '
			}
		}
	}
	return string(masked)
}

func javaScriptStructuralOffsetInSpans(offset int, spans []javaScriptStructuralSpan) bool {
	position := sort.Search(len(spans), func(index int) bool {
		return spans[index].end > offset
	})
	return position < len(spans) && spans[position].start <= offset
}

func (builder *javaScriptStructuralBuilder) lineAt(offset int) int {
	if len(builder.lineStarts) == 0 {
		return 1
	}
	line := sort.Search(len(builder.lineStarts), func(index int) bool {
		return builder.lineStarts[index] > offset
	})
	if line == 0 {
		return 1
	}
	return line
}

func javaScriptStructuralLineStarts(source string) []int {
	starts := []int{0}
	for index := 0; index < len(source); index++ {
		if source[index] == '\n' {
			starts = append(starts, index+1)
		}
	}
	return starts
}

func (builder *javaScriptStructuralBuilder) markRange(
	start int,
	end int,
	disposition javaScriptLineDisposition,
	scopeKey string,
) {
	if end <= start || len(builder.index.Lines) == 0 {
		return
	}
	startLine := builder.lineAt(start)
	endLine := builder.lineAt(end - 1)
	for line := startLine; line <= endLine && line <= len(builder.index.Lines); line++ {
		current := &builder.index.Lines[line-1]
		if javaScriptLineDispositionPriority(disposition) <
			javaScriptLineDispositionPriority(current.Disposition) {
			continue
		}
		current.Disposition = disposition
		current.ScopeKey = scopeKey
	}
}

func javaScriptLineDispositionPriority(disposition javaScriptLineDisposition) int {
	switch disposition {
	case javaScriptLineRejected:
		return 5
	case javaScriptLineOpaque:
		return 4
	case javaScriptLineDirect:
		return 3
	case javaScriptLineStructural:
		return 2
	default:
		return 1
	}
}

func (builder *javaScriptStructuralBuilder) noteUnsupported(detail string) {
	if builder.index.Disposition == javaScriptStructuralComplete {
		builder.index.Disposition = javaScriptStructuralUnsupported
		builder.index.Detail = detail
	}
}

func (builder *javaScriptStructuralBuilder) failed() bool {
	return builder.index.Disposition == javaScriptStructuralLimited ||
		builder.index.Disposition == javaScriptStructuralMalformed
}

func (builder *javaScriptStructuralBuilder) reject(
	disposition javaScriptStructuralDisposition,
	detail string,
) javaScriptStructuralIndex {
	builder.index.Statements = nil
	builder.index.Scopes = nil
	builder.index.HiddenUses = nil
	builder.index.Disposition = disposition
	builder.index.Detail = detail
	for index := range builder.index.Lines {
		builder.index.Lines[index].Disposition = javaScriptLineRejected
		builder.index.Lines[index].ScopeKey = ""
	}
	return builder.index
}
