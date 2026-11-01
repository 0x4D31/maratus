package extract

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxJavaScriptSyntaxNesting = 128

type javaScriptSyntaxEventKind uint8

const (
	javaScriptSyntaxIdentifier javaScriptSyntaxEventKind = iota + 1
	javaScriptSyntaxToken
)

type javaScriptSyntaxEvent struct {
	kind  javaScriptSyntaxEventKind
	start int
	end   int
	depth int
}

// javaScriptIdentifierOccurrence is a lexical occurrence outside quoted
// strings, template literals (including interpolations), comments, and regular
// expression literals. Write is set only for a direct bare-identifier
// assignment or update that this closed scanner can prove.
type javaScriptIdentifierOccurrence struct {
	Name          string
	Offset        int
	Write         bool
	Reference     bool
	previousToken string
}

// exactJavaScriptCallContent returns the bytes inside the balanced call whose
// opening parenthesis is at open, together with the closing-parenthesis index.
// It recognizes a deliberately small lexical subset; malformed, unsupported,
// over-nested, and over-budget input fails without a partial result.
func exactJavaScriptCallContent(source string, open, maxBytes int) (string, int, bool) {
	if open < 0 || open >= len(source) || source[open] != '(' || maxBytes < 2 {
		return "", 0, false
	}
	limit := open + maxBytes
	if limit < open || limit > len(source) {
		limit = len(source)
	}
	close, ok := scanJavaScriptSyntax(source, open+1, limit, '(', nil)
	if !ok {
		return "", 0, false
	}
	return source[open+1 : close], close, true
}

// splitJavaScriptArgumentsExact splits a call or array body at top-level
// commas. Empty leading or interior entries are rejected. One trailing comma
// is accepted and does not create an argument.
func splitJavaScriptArgumentsExact(text string, maxBytes, maxArguments int) ([]string, bool) {
	if maxBytes < 0 || maxArguments < 0 || len(text) > maxBytes {
		return nil, false
	}
	var (
		arguments      []string
		start          int
		segmentHasCode bool
		sawComma       bool
		valid          = true
	)
	_, ok := scanJavaScriptSyntax(text, 0, len(text), 0, func(event javaScriptSyntaxEvent) bool {
		if event.depth == 0 && text[event.start:event.end] == "," {
			sawComma = true
			if !segmentHasCode {
				valid = false
				return false
			}
			if len(arguments) >= maxArguments {
				valid = false
				return false
			}
			arguments = append(arguments, strings.TrimSpace(text[start:event.start]))
			start = event.end
			segmentHasCode = false
			return true
		}
		segmentHasCode = true
		return true
	})
	if !ok || !valid {
		return nil, false
	}
	if segmentHasCode {
		if len(arguments) >= maxArguments {
			return nil, false
		}
		arguments = append(arguments, strings.TrimSpace(text[start:]))
	} else if !sawComma {
		return nil, true
	}
	return arguments, true
}

// scanJavaScriptIdentifierOccurrencesExact performs one bounded lexical pass.
// The boolean reports lexical success, not complete JavaScript write coverage:
// destructuring, computed targets, and other complex assignment forms remain
// outside this helper's contract.
func scanJavaScriptIdentifierOccurrencesExact(text string, maxBytes, maxOccurrences int) ([]javaScriptIdentifierOccurrence, bool) {
	return scanJavaScriptIdentifierOccurrencesMode(
		text,
		maxBytes,
		maxOccurrences,
		false,
	)
}

func scanJavaScriptIdentifierOccurrencesIncludingTemplateExpressionsExact(
	text string,
	maxBytes int,
	maxOccurrences int,
) ([]javaScriptIdentifierOccurrence, bool) {
	return scanJavaScriptIdentifierOccurrencesMode(
		text,
		maxBytes,
		maxOccurrences,
		true,
	)
}

func scanJavaScriptIdentifierOccurrencesMode(
	text string,
	maxBytes int,
	maxOccurrences int,
	includeTemplateExpressions bool,
) ([]javaScriptIdentifierOccurrence, bool) {
	if maxBytes < 0 || maxOccurrences < 0 || len(text) > maxBytes {
		return nil, false
	}
	var occurrences []javaScriptIdentifierOccurrence
	ok := visitJavaScriptIdentifierOccurrences(text, maxBytes, includeTemplateExpressions, func(occurrence javaScriptIdentifierOccurrence) bool {
		if len(occurrences) >= maxOccurrences {
			return false
		}
		occurrences = append(occurrences, occurrence)
		return true
	})
	if !ok {
		return nil, false
	}
	return occurrences, true
}

// Emit an occurrence only after the following token has resolved property-key
// and update/assignment context. At most one pending occurrence is retained.
func visitJavaScriptIdentifierOccurrences(text string, maxBytes int, includeTemplateExpressions bool, visit func(javaScriptIdentifierOccurrence) bool) bool {
	if maxBytes < 0 || len(text) > maxBytes {
		return false
	}
	var (
		pending          javaScriptIdentifierOccurrence
		hasPending       bool
		lastBare         bool
		prefixCandidate  bool
		prefixUpdateNext bool
		previousToken    string
		valid            = true
	)
	flush := func() bool {
		if !hasPending {
			return true
		}
		hasPending = false
		return visit(pending)
	}
	finalizePrefix := func(next string) {
		if !prefixCandidate || !hasPending {
			return
		}
		switch next {
		case ".", "?.", "[", "(":
		default:
			pending.Write = true
		}
		prefixCandidate = false
	}
	finalizeReference := func(next string) {
		if !hasPending || !pending.Reference || next != ":" {
			return
		}
		switch pending.previousToken {
		case "", "{", ",":
			// An object property key or statement label is not a
			// reference to a same-named lexical binding. Ternary and
			// switch expressions retain their preceding context.
			pending.Reference = false
		}
	}
	_, ok := scanJavaScriptSyntaxMode(text, 0, len(text), 0, includeTemplateExpressions, func(event javaScriptSyntaxEvent) bool {
		token := text[event.start:event.end]
		finalizePrefix(token)
		finalizeReference(token)

		if event.kind == javaScriptSyntaxIdentifier {
			if !flush() {
				valid = false
				return false
			}
			if javaScriptSyntaxKeyword(token) {
				lastBare = false
				prefixUpdateNext = false
				previousToken = token
				return true
			}
			bare := previousToken != "." && previousToken != "?."
			pending = javaScriptIdentifierOccurrence{
				Name:          token,
				Offset:        event.start,
				Reference:     bare,
				previousToken: previousToken,
			}
			hasPending = true
			lastBare = bare
			if prefixUpdateNext && bare {
				prefixCandidate = true
			}
			prefixUpdateNext = false
			previousToken = token
			return true
		}

		switch {
		case javaScriptSyntaxAssignmentToken(token):
			if hasPending && lastBare {
				pending.Write = true
			}
		case token == "++" || token == "--":
			if hasPending && lastBare {
				pending.Write = true
			} else {
				prefixUpdateNext = true
			}
		default:
			prefixUpdateNext = false
		}
		if !flush() {
			valid = false
			return false
		}
		lastBare = false
		previousToken = token
		return true
	})
	if !ok || !valid {
		return false
	}
	finalizePrefix("")
	return flush()
}

// scanJavaScriptSyntax validates one bounded lexical fragment. With rootOpen
// non-zero, scanning stops at its matching close and returns that byte index.
// With no root, the whole fragment must balance and the returned index is len.
func scanJavaScriptSyntax(
	source string,
	start int,
	limit int,
	rootOpen byte,
	visit func(javaScriptSyntaxEvent) bool,
) (int, bool) {
	return scanJavaScriptSyntaxMode(source, start, limit, rootOpen, false, visit)
}

func scanJavaScriptSyntaxMode(
	source string,
	start int,
	limit int,
	rootOpen byte,
	includeTemplateExpressions bool,
	visit func(javaScriptSyntaxEvent) bool,
) (int, bool) {
	if start < 0 || start > len(source) || limit < start || limit > len(source) {
		return 0, false
	}
	var delimiters []byte
	if rootOpen != 0 {
		delimiters = append(delimiters, rootOpen)
	}
	templateDepth := 0
	inTemplate := false
	regexAllowed := true

	emit := func(kind javaScriptSyntaxEventKind, tokenStart, tokenEnd, depth int) bool {
		if visit == nil || templateDepth > 0 && !includeTemplateExpressions {
			return true
		}
		return visit(javaScriptSyntaxEvent{
			kind:  kind,
			start: tokenStart,
			end:   tokenEnd,
			depth: depth,
		})
	}

	for index := start; index < limit; {
		if inTemplate {
			switch source[index] {
			case '\\':
				if index+1 >= limit {
					return 0, false
				}
				index += 2
			case '`':
				templateDepth--
				inTemplate = false
				regexAllowed = false
				index++
			case '$':
				if index+1 < limit && source[index+1] == '{' {
					if len(delimiters) >= maxJavaScriptSyntaxNesting {
						return 0, false
					}
					if !emit(
						javaScriptSyntaxToken,
						index,
						index+2,
						len(delimiters),
					) {
						return 0, false
					}
					delimiters = append(delimiters, '$')
					inTemplate = false
					regexAllowed = true
					index += 2
					continue
				}
				index++
			default:
				index++
			}
			continue
		}

		char := source[index]
		if javaScriptSyntaxSpace(char) {
			index++
			continue
		}
		if char >= 0x80 && !javaScriptUnicodeIdentifierStart(source[index:limit]) {
			return 0, false
		}
		depth := len(delimiters)

		if char == '\'' || char == '"' {
			end, ok := skipJavaScriptQuotedSyntax(source, index, limit, char)
			if !ok || !emit(javaScriptSyntaxToken, index, end, depth) {
				return 0, false
			}
			regexAllowed = false
			index = end
			continue
		}
		if char == '`' {
			if templateDepth >= maxJavaScriptSyntaxNesting ||
				!emit(javaScriptSyntaxToken, index, index+1, depth) {
				return 0, false
			}
			templateDepth++
			inTemplate = true
			index++
			continue
		}
		if char == '/' && index+1 < limit {
			switch source[index+1] {
			case '/':
				index = skipJavaScriptLineComment(source, index+2, limit)
				continue
			case '*':
				end, ok := skipJavaScriptBlockComment(source, index+2, limit)
				if !ok {
					return 0, false
				}
				index = end
				continue
			}
		}
		if char == '/' && regexAllowed {
			end, ok := skipJavaScriptRegexSyntax(source, index+1, limit)
			if !ok || !emit(javaScriptSyntaxToken, index, end, depth) {
				return 0, false
			}
			regexAllowed = false
			index = end
			continue
		}
		if javaScriptIdentifierStartByte(char) || javaScriptUnicodeIdentifierStart(source[index:limit]) {
			end := javaScriptIdentifierEnd(source, index, limit)
			if !emit(javaScriptSyntaxIdentifier, index, end, depth) {
				return 0, false
			}
			regexAllowed = javaScriptRegexPrefixKeyword(source[index:end])
			index = end
			continue
		}
		if char >= '0' && char <= '9' {
			end := skipJavaScriptNumberSyntax(source, index, limit)
			if !emit(javaScriptSyntaxToken, index, end, depth) {
				return 0, false
			}
			regexAllowed = false
			index = end
			continue
		}

		switch char {
		case '(', '[', '{':
			if len(delimiters) >= maxJavaScriptSyntaxNesting ||
				!emit(javaScriptSyntaxToken, index, index+1, depth) {
				return 0, false
			}
			delimiters = append(delimiters, char)
			regexAllowed = true
			index++
			continue
		case ')', ']', '}':
			if len(delimiters) == 0 {
				return 0, false
			}
			open := delimiters[len(delimiters)-1]
			if open == '$' {
				if char != '}' {
					return 0, false
				}
				if !emit(
					javaScriptSyntaxToken,
					index,
					index+1,
					len(delimiters)-1,
				) {
					return 0, false
				}
				delimiters = delimiters[:len(delimiters)-1]
				inTemplate = true
				regexAllowed = false
				index++
				continue
			}
			if !javaScriptDelimitersMatch(open, char) {
				return 0, false
			}
			delimiters = delimiters[:len(delimiters)-1]
			if rootOpen != 0 && len(delimiters) == 0 {
				return index, true
			}
			if !emit(javaScriptSyntaxToken, index, index+1, len(delimiters)) {
				return 0, false
			}
			regexAllowed = false
			index++
			continue
		}

		end := javaScriptPunctuatorEnd(source, index, limit)
		if !emit(javaScriptSyntaxToken, index, end, depth) {
			return 0, false
		}
		token := source[index:end]
		switch token {
		case ".", "?.", "++", "--":
			regexAllowed = false
		default:
			regexAllowed = true
		}
		index = end
	}

	if rootOpen != 0 || len(delimiters) != 0 || inTemplate || templateDepth != 0 {
		return 0, false
	}
	return limit, true
}

// Support ordinary Unicode identifier letters without folding or normalizing
// names. Escaped identifiers and unsupported code points remain fail-closed.
func javaScriptUnicodeIdentifierStart(source string) bool {
	if len(source) == 0 || source[0] < utf8.RuneSelf {
		return false
	}
	r, size := utf8.DecodeRuneInString(source)
	return size > 1 && !unicode.Is(unicode.Pattern_Syntax, r) &&
		!unicode.Is(unicode.Pattern_White_Space, r) && (unicode.IsLetter(r) || unicode.Is(unicode.Nl, r))
}

func javaScriptIdentifierEnd(source string, start, limit int) int {
	_, size := utf8.DecodeRuneInString(source[start:limit])
	end := start + size
	for end < limit {
		if source[end] < utf8.RuneSelf {
			if !javaScriptIdentifierByte(source[end]) {
				break
			}
			end++
			continue
		}
		r, size := utf8.DecodeRuneInString(source[end:limit])
		if size == 1 || unicode.Is(unicode.Pattern_Syntax, r) || unicode.Is(unicode.Pattern_White_Space, r) ||
			!(javaScriptUnicodeIdentifierStart(source[end:limit]) || unicode.In(r, unicode.Mn, unicode.Mc, unicode.Nd, unicode.Pc) || r == '\u200c' || r == '\u200d') {
			break
		}
		end += size
	}
	return end
}

func skipJavaScriptQuotedSyntax(source string, start, limit int, quote byte) (int, bool) {
	for index := start + 1; index < limit; index++ {
		switch source[index] {
		case '\\':
			index++
			if index >= limit {
				return 0, false
			}
		case '\n', '\r':
			return 0, false
		default:
			if source[index] == quote {
				return index + 1, true
			}
		}
	}
	return 0, false
}

func skipJavaScriptLineComment(source string, start, limit int) int {
	for index := start; index < limit; index++ {
		if source[index] == '\n' || source[index] == '\r' {
			return index + 1
		}
	}
	return limit
}

func skipJavaScriptBlockComment(source string, start, limit int) (int, bool) {
	for index := start; index+1 < limit; index++ {
		if source[index] == '*' && source[index+1] == '/' {
			return index + 2, true
		}
	}
	return 0, false
}

func skipJavaScriptRegexSyntax(source string, start, limit int) (int, bool) {
	inClass := false
	for index := start; index < limit; index++ {
		switch source[index] {
		case '\\':
			index++
			if index >= limit {
				return 0, false
			}
		case '\n', '\r':
			return 0, false
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if inClass {
				continue
			}
			index++
			for index < limit && javaScriptIdentifierByte(source[index]) {
				index++
			}
			return index, true
		}
	}
	return 0, false
}

func skipJavaScriptNumberSyntax(source string, start, limit int) int {
	index := start + 1
	for index < limit {
		char := source[index]
		if char >= '0' && char <= '9' ||
			char >= 'a' && char <= 'f' ||
			char >= 'A' && char <= 'F' ||
			char == 'x' || char == 'X' || char == 'o' || char == 'O' ||
			char == 'b' || char == 'B' || char == 'e' || char == 'E' ||
			char == 'n' || char == '_' || char == '.' {
			index++
			continue
		}
		if (char == '+' || char == '-') && index > start &&
			(source[index-1] == 'e' || source[index-1] == 'E') {
			index++
			continue
		}
		break
	}
	return index
}

func javaScriptPunctuatorEnd(source string, start, limit int) int {
	for _, punctuator := range []string{
		">>>=", "===", "!==", "**=", ">>>", "<<=", ">>=", "&&=", "||=", "??=", "...",
		"=>", "==", "!=", "<=", ">=", "++", "--", "**", "<<", ">>", "&&", "||", "??", "?.",
		"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
	} {
		if len(punctuator) <= limit-start && source[start:start+len(punctuator)] == punctuator {
			return start + len(punctuator)
		}
	}
	return start + 1
}

func javaScriptSyntaxAssignmentToken(token string) bool {
	switch token {
	case "=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=",
		"&=", "|=", "^=", "&&=", "||=", "??=":
		return true
	default:
		return false
	}
}

func javaScriptRegexPrefixKeyword(value string) bool {
	switch value {
	case "await", "case", "delete", "do", "else", "in", "instanceof", "new",
		"of", "return", "throw", "typeof", "void", "yield":
		return true
	default:
		return false
	}
}

func javaScriptSyntaxKeyword(value string) bool {
	switch value {
	case "as", "async", "await", "break", "case", "catch", "class", "const",
		"continue", "debugger", "default", "delete", "do", "else", "export",
		"extends", "false", "finally", "for", "from", "function", "get", "if",
		"import", "in", "instanceof", "let", "new", "null", "of", "return",
		"set", "static", "super", "switch", "this", "throw", "true", "try",
		"typeof", "var", "void", "while", "with", "yield":
		return true
	default:
		return false
	}
}

func javaScriptDelimitersMatch(open, close byte) bool {
	return open == '(' && close == ')' ||
		open == '[' && close == ']' ||
		open == '{' && close == '}'
}

func javaScriptSyntaxSpace(char byte) bool {
	switch char {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}
