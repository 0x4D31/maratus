package extract

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func collectNativeFunctionNames(lines []string, functionLanguage string) map[string]bool {
	out := map[string]bool{}
	state := functionState{}
	inBlockComment := false
	for _, raw := range lines {
		semanticRaw := stripSemanticComment("native-source", raw, &inBlockComment)
		trimmed := strings.TrimSpace(semanticRaw)
		state = updateFunctionState(functionLanguage, semanticRaw, trimmed, state)
		if state.name != "" {
			out[state.name] = true
		}
	}
	return out
}

// rustFunctionName accepts only a bounded Rust function declaration prefix.
// Rust expressions such as match arms (`Err(...) => {`) and calls followed by
// blocks also contain '(' and end in '{', so the broader C-family heuristic is
// not safe for .rs source.
func rustFunctionName(line string) string {
	declaration := strings.TrimSpace(line)
	if !strings.HasSuffix(declaration, "{") {
		return ""
	}
	declaration = strings.TrimSpace(strings.TrimSuffix(declaration, "{"))

	if tail, ok := rustVisibilityTail(declaration); ok {
		declaration = tail
	}

	for _, qualifier := range []string{"const", "async", "unsafe"} {
		if tail, ok := rustKeywordTail(declaration, qualifier); ok {
			declaration = tail
		}
	}
	if tail, ok := rustKeywordTail(declaration, "extern"); ok {
		var valid bool
		declaration, valid = rustOptionalABITail(tail)
		if !valid {
			return ""
		}
	}

	tail, ok := rustKeywordTail(declaration, "fn")
	if !ok || tail == "" || !identifierStartByte(tail[0]) {
		return ""
	}
	end := 1
	for end < len(tail) && isIdentifierByte(tail[end]) {
		end++
	}
	name := tail[:end]
	remainder := strings.TrimSpace(tail[end:])
	if strings.HasPrefix(remainder, "<") {
		close := matchingRustAngle(remainder)
		if close < 0 {
			return ""
		}
		remainder = strings.TrimSpace(remainder[close+1:])
	}
	if !strings.HasPrefix(remainder, "(") {
		return ""
	}
	return name
}

func rustVisibilityTail(value string) (string, bool) {
	if value == "pub" {
		return "", true
	}
	if !strings.HasPrefix(value, "pub") {
		return value, false
	}
	remainder := value[len("pub"):]
	if remainder == "" {
		return "", true
	}
	switch remainder[0] {
	case ' ', '\t':
		return strings.TrimSpace(remainder), true
	case '(':
		close := strings.IndexByte(remainder, ')')
		if close < 0 {
			return "", false
		}
		return strings.TrimSpace(remainder[close+1:]), true
	default:
		return value, false
	}
}

func rustKeywordTail(value, keyword string) (string, bool) {
	if !strings.HasPrefix(value, keyword) || len(value) == len(keyword) {
		return "", false
	}
	next := value[len(keyword)]
	if next != ' ' && next != '\t' {
		return "", false
	}
	return strings.TrimSpace(value[len(keyword):]), true
}

func rustOptionalABITail(value string) (string, bool) {
	if value == "" || value[0] != '"' {
		return value, true
	}
	escaped := false
	for index := 1; index < len(value); index++ {
		switch {
		case escaped:
			escaped = false
		case value[index] == '\\':
			escaped = true
		case value[index] == '"':
			return strings.TrimSpace(value[index+1:]), true
		}
	}
	return "", false
}

func matchingRustAngle(value string) int {
	depth := 0
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '<':
			depth++
		case '>':
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func directNativeSourceFunctionCalls(line, currentFunction string, knownFunctions map[string]bool) []string {
	return directNativeSourceFunctionCallsBudget(line, currentFunction, knownFunctions, nil)
}

func directNativeSourceFunctionCallsBudget(line, currentFunction string, knownFunctions map[string]bool, budget *textLineBudget) []string {
	if currentFunction == "" || len(knownFunctions) == 0 || nativeSourceDeclarationLine(line) {
		return nil
	}
	calls := map[string]bool{}
	for _, call := range objectiveCMessageCallsBudget(line, budget) {
		if call != "" && call != currentFunction && knownFunctions[call] {
			calls[call] = true
		}
	}
	for _, call := range nativeCCallsBudget(line, budget) {
		if call != "" && call != currentFunction && knownFunctions[call] {
			calls[call] = true
		}
	}
	out := make([]string, 0, len(calls))
	for call := range calls {
		out = append(out, call)
	}
	sort.Strings(out)
	return out
}

func nativeSourceDeclarationLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, "-") || strings.HasPrefix(trimmed, "+") {
		return true
	}
	return strings.HasSuffix(trimmed, "{") && nativeFunctionName(trimmed) != ""
}

func nativeFunctionName(line string) string {
	if name := objectiveCMethodName(line); name != "" {
		return name
	}
	before, _, ok := strings.Cut(line, "(")
	if !ok {
		return ""
	}
	before = strings.TrimSpace(before)
	if before == "" {
		return ""
	}
	start := len(before)
	for start > 0 && !isSourceSpace(before[start-1]) {
		start--
	}
	name := strings.Trim(before[start:], "*&")
	switch name {
	case "if", "for", "while", "switch":
		return ""
	default:
		return name
	}
}

func objectiveCMethodName(line string) string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "+") {
		return ""
	}
	closeReturn := strings.Index(line, ")")
	if closeReturn < 0 {
		return ""
	}
	rest := strings.TrimSpace(line[closeReturn+1:])
	first, remainder := readSelectorPart(rest)
	if first == "" {
		return ""
	}
	if !strings.HasSuffix(first, ":") {
		return first
	}
	var selector strings.Builder
	selector.WriteString(first)
	labels := 1
	for {
		label, remaining := nextSelectorLabel(remainder)
		if label == "" {
			break
		}
		labels++
		if labels > maxTextDerivedMatchesPerLine || selector.Len()+len(label) > maxTextDerivedValueBytes {
			return ""
		}
		selector.WriteString(label)
		remainder = remaining
	}
	return selector.String()
}

func objectiveCMessageCalls(line string) []string {
	return objectiveCMessageCallsBudget(line, nil)
}

func objectiveCMessageCallsBudget(line string, budget *textLineBudget) []string {
	budget = textBudgetOrStandalone(budget)
	if !budget.chargeScan(len(line), "Objective-C message") {
		return nil
	}
	var out []string
	var quote byte
	escaped := false
	for i := 0; i < len(line); i++ {
		if !sourceByteIsCode(line[i], &quote, &escaped) || line[i] != '[' {
			continue
		}
		end := sourceClosingBracket(line, i)
		if end < 0 {
			break
		}
		expr := line[i+1 : end]
		if selector := objectiveCMessageSelectorBudget(expr, budget); selector != "" {
			out = append(out, selector)
		}
		i = end
	}
	return out
}

func sourceClosingBracket(line string, open int) int {
	depth := 1
	var quote byte
	escaped := false
	for i := open + 1; i < len(line); i++ {
		if !sourceByteIsCode(line[i], &quote, &escaped) {
			continue
		}
		switch line[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func objectiveCMessageSelectorBudget(expr string, budget *textLineBudget) string {
	budget = textBudgetOrStandalone(budget)
	if !budget.chargeScan(len(expr), "Objective-C selector") {
		return ""
	}
	expr = strings.TrimSpace(expr)
	receiverEnd := 0
	for receiverEnd < len(expr) && !isSourceSpace(expr[receiverEnd]) {
		receiverEnd++
	}
	messageStart := receiverEnd
	for messageStart < len(expr) && isSourceSpace(expr[messageStart]) {
		messageStart++
	}
	if receiverEnd == 0 || messageStart >= len(expr) {
		return ""
	}
	message := strings.TrimSpace(expr[messageStart:])
	if !strings.Contains(message, ":") {
		label := readObjectiveCSelectorLabel(message)
		if label == "" || !budget.retainMatch(len(label), "Objective-C selector") {
			return ""
		}
		return label
	}
	var selector strings.Builder
	segmentStart := 0
	for i := 0; i < len(message); i++ {
		if message[i] != ':' {
			continue
		}
		label := lastIdentifier(message[segmentStart:i])
		if label == "" {
			return ""
		}
		if selector.Len()+len(label)+1 > maxTextDerivedValueBytes || !budget.retainMatch(len(label)+1, "Objective-C selector label") {
			budget.markLimited(fmt.Sprintf("Objective-C selector exceeded %d labels or %d bytes", maxTextDerivedMatchesPerLine, maxTextDerivedValueBytes), false)
			return ""
		}
		selector.WriteString(label)
		selector.WriteByte(':')
		segmentStart = i + 1
	}
	return selector.String()
}

func isSourceSpace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f'
}

func readObjectiveCSelectorLabel(value string) string {
	label, _ := readSelectorPart(strings.TrimSpace(value))
	return label
}

func readSelectorPart(value string) (string, string) {
	value = strings.TrimSpace(value)
	var out strings.Builder
	for i, r := range value {
		if r == ':' {
			out.WriteRune(r)
			return out.String(), value[i+1:]
		}
		if isIdentifierRune(r) {
			if out.Len() >= maxTextDerivedValueBytes {
				return "", value[i:]
			}
			out.WriteRune(r)
			continue
		}
		if out.Len() > 0 {
			return out.String(), value[i:]
		}
		return "", value[i:]
	}
	return out.String(), ""
}

func nextSelectorLabel(value string) (string, string) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "(") {
		if idx := strings.Index(value, ")"); idx >= 0 {
			value = strings.TrimSpace(value[idx+1:])
		}
	}
	if value == "" {
		return "", ""
	}
	// Skip the argument bound to the previous selector label, then parse the
	// next label in place. Avoid Fields/Join fan-out on adversarial declarations.
	argumentEnd := 0
	for argumentEnd < len(value) && !isSourceSpace(value[argumentEnd]) {
		argumentEnd++
	}
	next := argumentEnd
	for next < len(value) && isSourceSpace(value[next]) {
		next++
	}
	if argumentEnd == 0 || next >= len(value) {
		return "", ""
	}
	return readSelectorPart(value[next:])
}

func nativeCCalls(line string) []string {
	return nativeCCallsBudget(line, nil)
}

func nativeCCallsBudget(line string, budget *textLineBudget) []string {
	budget = textBudgetOrStandalone(budget)
	if !budget.chargeScan(len(line), "native call") {
		return nil
	}
	var out []string
	var quote byte
	escaped := false
	for i := 0; i < len(line); i++ {
		if !sourceByteIsCode(line[i], &quote, &escaped) || line[i] != '(' {
			continue
		}
		name := identifierBefore(line, i)
		if name != "" && !nativeControlKeyword(name) {
			if !budget.retainMatch(len(name), "native call") {
				break
			}
			out = append(out, name)
		}
	}
	return out
}

func identifierBefore(line string, index int) string {
	i := index - 1
	for i >= 0 && (line[i] == ' ' || line[i] == '\t') {
		i--
	}
	end := i + 1
	for i >= 0 && isIdentifierByte(line[i]) {
		i--
	}
	if i+1 == end {
		return ""
	}
	return line[i+1 : end]
}

func lastIdentifier(value string) string {
	value = strings.TrimSpace(value)
	end := len(value)
	for end > 0 && !isIdentifierByte(value[end-1]) {
		end--
	}
	start := end
	for start > 0 && isIdentifierByte(value[start-1]) {
		start--
	}
	return value[start:end]
}

func nativeControlKeyword(value string) bool {
	switch value {
	case "if", "for", "while", "switch", "return", "sizeof":
		return true
	default:
		return false
	}
}

// sourceByteIsCode advances a small C-family quote state and reports whether
// the current byte is outside a string/character literal. Callers scan from
// left to right, so candidate delimiters never trigger a prefix rescan.
func sourceByteIsCode(current byte, quote *byte, escaped *bool) bool {
	if *escaped {
		*escaped = false
		return *quote == 0
	}
	if current == '\\' {
		*escaped = true
		return *quote == 0
	}
	if *quote != 0 {
		if current == *quote {
			*quote = 0
		}
		return false
	}
	if current == '"' || current == '\'' {
		*quote = current
		return false
	}
	return true
}

func extractNativeSourceCommandLiteralsBudget(graph *behavior.Graph, content artifact.Content, line string, lineNo int, evidenceID string, budget *textLineBudget) {
	command, ok := directNativeShellCommandLiteral(line)
	if !ok || !nativeSourceShellCommandLiteral(command) {
		return
	}
	start := graphPosition(graph)
	AnalyzeShellLine(graph, content, command, lineNo, executionContextForContent(content), evidenceID)
	annotateGraphRangeSourceFunction(graph, start, content.Function)
}

// directNativeShellCommandLiteral accepts only a literal first argument to a
// direct C-family system(3) or popen(3) call. A command-looking source string
// may otherwise be configuration, a log message, documentation, or dead data;
// its contents alone do not establish invocation.
func directNativeShellCommandLiteral(line string) (string, bool) {
	for _, name := range []string{"system", "popen"} {
		open, found := unquotedCallOpen(line, name)
		if !found {
			continue
		}
		command := firstCallStringArgument(line, open)
		if command == "" {
			return "", false
		}
		return command, true
	}
	return "", false
}

func unquotedCallOpen(line, name string) (int, bool) {
	var quote byte
	escaped := false
	for index := 0; index < len(line); index++ {
		current := line[index]
		if escaped {
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if current == quote {
				quote = 0
			}
			continue
		}
		if current == '\'' || current == '"' || current == '`' {
			quote = current
			continue
		}
		if !strings.HasPrefix(line[index:], name) || !callNameBoundary(line, index, len(name)) {
			continue
		}
		// A selector/method named system or popen does not establish the C
		// process API. Namespace-qualified variants are likewise unresolved.
		prefix := strings.TrimRight(line[:index], " \t\r\n")
		if strings.HasSuffix(prefix, ".") || strings.HasSuffix(prefix, ":") || strings.HasSuffix(prefix, ">") {
			continue
		}
		open := index + len(name)
		for open < len(line) && (line[open] == ' ' || line[open] == '\t') {
			open++
		}
		if open < len(line) && line[open] == '(' {
			return open, true
		}
	}
	return 0, false
}

func annotateGraphRangeSourceFunction(graph *behavior.Graph, start graphPositionSnapshot, function string) {
	if function == "" {
		return
	}
	for i := start.operations; i < len(graph.Operations); i++ {
		if graph.Operations[i].SourceFunction == "" {
			graph.Operations[i].SourceFunction = function
		}
	}
	for i := start.features; i < len(graph.Features); i++ {
		if graph.Features[i].SourceFunction == "" {
			graph.Features[i].SourceFunction = function
		}
	}
}

func nativeSourceShellCommandLiteral(value string) bool {
	fields, err := CommandFields(value)
	if err != nil || len(fields) == 0 {
		return false
	}
	fields = normalizeCommandFields(fields)
	if len(fields) == 0 {
		return false
	}
	switch filepath.Base(fields[0]) {
	case "osascript", "curl", "wget", "security", "dscl", "chmod", "xattr", "spctl", "launchctl",
		"zip", "unzip", "tar", "ditto", "sh", "bash", "zsh", "python", "python3", "node", "open",
		"screencapture", "pbpaste", "pbcopy", "SetFile", "chflags", "tccutil":
		return true
	default:
		return false
	}
}

func forEachSourceStringLiteral(line string, budget *textLineBudget, visit func(string) bool) {
	budget = textBudgetOrStandalone(budget)
	if !budget.chargeScan(len(line), "native string literal") {
		return
	}
	for i := 0; i < len(line); i++ {
		quote := line[i]
		if quote != '"' && quote != '\'' {
			continue
		}
		value, end, ok, oversized := readSourceStringLiteralLimited(line, i, quote, maxTextDerivedValueBytes)
		if oversized {
			budget.markLimited(fmt.Sprintf("native string literal exceeded %d bytes", maxTextDerivedValueBytes), false)
			return
		}
		if !ok {
			continue
		}
		if strings.TrimSpace(value) != "" {
			if !budget.retainMatch(len(value), "native string literal") || !visit(value) {
				return
			}
		}
		i = end
	}
}

func readSourceStringLiteralLimited(line string, start int, quote byte, maxBytes int) (string, int, bool, bool) {
	var out strings.Builder
	escaped := false
	for i := start + 1; i < len(line); i++ {
		c := line[i]
		if escaped {
			switch c {
			case 'n', 'r', 't':
				out.WriteByte(' ')
			case '\\', '"', '\'':
				out.WriteByte(c)
			default:
				out.WriteByte(c)
			}
			escaped = false
			if maxBytes > 0 && out.Len() > maxBytes {
				return "", i, false, true
			}
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == quote {
			return out.String(), i, true, false
		}
		out.WriteByte(c)
		if maxBytes > 0 && out.Len() > maxBytes {
			return "", i, false, true
		}
	}
	return "", start, false, false
}

func isIdentifierRune(r rune) bool {
	return r == '_' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z'
}
