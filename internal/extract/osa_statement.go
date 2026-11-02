package extract

import "strings"

// maskAppleScriptComments preserves physical lines and byte columns. Comment
// delimiters inside strings are data; nested block comments are AppleScript
// syntax, unlike JavaScript's non-nesting comments. Work is linear in the
// already-bounded text input, with no recursion or comment-body allocation.
func maskAppleScriptComments(lines []string) []string {
	out := make([]string, len(lines))
	depth := 0
	quoted, escaped := false, false
	for n, line := range lines {
		masked := []byte(line)
		continuedString := quoted
		for i := 0; i < len(line); i++ {
			if depth > 0 {
				masked[i] = ' '
				if i+1 < len(line) {
					switch line[i : i+2] {
					case "(*":
						depth++
					case "*)":
						depth--
					default:
						continue
					}
					masked[i+1] = ' '
					i++
				}
				continue
			}
			if quoted {
				if escaped {
					escaped = false
				} else if line[i] == '\\' {
					escaped = true
				} else if line[i] == '"' {
					quoted = false
				}
				// A preceding physical line opened this string. Its contents
				// cannot be interpreted as a new command statement.
				continue
			}
			if line[i] == '"' {
				quoted = true
			} else if i+1 < len(line) && line[i:i+2] == "(*" {
				depth = 1
				masked[i], masked[i+1] = ' ', ' '
				i++
			} else if i+1 < len(line) && line[i:i+2] == "--" {
				for j := i; j < len(line); j++ {
					masked[j] = ' '
				}
				break
			}
		}
		if continuedString || quoted {
			out[n] = ""
		} else {
			out[n] = string(masked)
		}
		escaped = false // a physical newline cannot escape the next line's quote
	}
	return out
}

// Only direct statements, return expressions, and simple result assignments
// are admitted. In particular a quoted string or another application's tell
// command cannot supply a Standard Additions invocation by keyword occurrence.
func appleScriptCommandStatement(line string) string {
	line = strings.TrimSpace(line)
	p := osaLiteralExpression{source: line}
	if p.word("return") || p.word("get") {
		return unwrapOSACommandExpression(strings.TrimSpace(line[p.pos:]))
	}
	if !p.word("set") {
		return unwrapOSACommandExpression(line)
	}
	p.space()
	start := p.pos
	for p.pos < len(line) && isIdentifierByte(line[p.pos]) {
		p.pos++
	}
	if p.pos == start || (line[start] >= '0' && line[start] <= '9') || !p.word("to") {
		return ""
	}
	return unwrapOSACommandExpression(strings.TrimSpace(line[p.pos:]))
}

func unwrapOSACommandExpression(line string) string {
	for depth := 0; depth < maxOSAExpressionDepth; depth++ {
		p := osaLiteralExpression{source: line}
		if p.word("text") && p.word("returned") && p.word("of") {
			line = strings.TrimSpace(line[p.pos:])
			if !strings.HasPrefix(line, "(") {
				return ""
			}
		}
		if !strings.HasPrefix(line, "(") {
			return line
		}
		if len(line) > maxOSAExpressionBytes || !osaWholeParenthesizedExpression(line) {
			return ""
		}
		line = strings.TrimSpace(line[1 : len(line)-1])
	}
	return ""
}

func osaWholeParenthesizedExpression(source string) bool {
	depth := 0
	quoted, escaped := false, false
	for i := 0; i < len(source); i++ {
		c := source[i]
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case '(':
			depth++
			if depth > maxOSAExpressionDepth {
				return false
			}
		case ')':
			depth--
			if depth == 0 {
				return i == len(source)-1
			}
		}
	}
	return false
}

func appleScriptCommandArgument(line, command string) (string, bool) {
	p := osaLiteralExpression{source: line}
	for _, word := range strings.Fields(command) {
		if !p.word(word) {
			return "", false
		}
	}
	argument := strings.TrimSpace(line[p.pos:])
	return argument, argument != ""
}

func appleScriptHiddenAnswerDialog(line string) bool {
	argument, ok := appleScriptCommandArgument(line, "display dialog")
	if !ok || len(argument) > maxOSAExpressionBytes {
		return false
	}
	p := osaLiteralExpression{source: argument}
	if !osaDialogValue(&p, 0) {
		return false
	}
	seen := map[string]bool{}
	hidden, input := false, false
	for {
		p.space()
		if p.pos == len(argument) {
			return hidden && input
		}
		key, boolean := "", false
		switch {
		case p.word("default"):
			if p.word("answer") {
				key, input = "default answer", true
			} else if p.word("button") {
				key = "default button"
			}
		case p.word("cancel"):
			if p.word("button") {
				key = "cancel button"
			}
		case p.word("with"):
			if p.word("hidden") && p.word("answer") {
				key, boolean, hidden = "hidden answer", true, true
			} else if p.word("icon") {
				key = "icon"
			} else if p.word("title") {
				key = "title"
			}
		case p.word("without"):
			if p.word("hidden") && p.word("answer") {
				key, boolean, hidden = "hidden answer", true, false
			}
		case p.word("hidden"):
			if p.word("answer") {
				key, boolean = "hidden answer", true
				if p.word("true") {
					hidden = true
				} else if p.word("false") {
					hidden = false
				} else {
					return false
				}
			}
		case p.word("buttons"):
			key = "buttons"
		case p.word("giving"):
			if p.word("up") && p.word("after") {
				key = "giving up after"
			}
		}
		if key == "" || seen[key] {
			return false
		}
		seen[key] = true
		if !boolean && !osaDialogValue(&p, 0) {
			return false
		}
	}
}

// Dialog labels/defaults may be unresolved without changing the fact that a
// masked input was requested. Consume a closed expression grammar to locate
// actual named parameters, never parameter-looking words inside string data.
func osaDialogValue(p *osaLiteralExpression, depth int) bool {
	if depth >= maxOSAExpressionDepth || p.terms >= maxOSAExpressionTerms {
		return false
	}
	p.terms++
	p.space()
	if p.pos == len(p.source) {
		return false
	}
	if p.source[p.pos] == '"' {
		if _, ok := p.term(depth); !ok {
			return false
		}
	} else if p.source[p.pos] == '{' || p.source[p.pos] == '(' {
		closing := byte('}')
		list := p.source[p.pos] == '{'
		if !list {
			closing = ')'
		}
		p.pos++
		if !osaDialogValue(p, depth+1) {
			return false
		}
		p.space()
		for list && p.pos < len(p.source) && p.source[p.pos] == ',' {
			p.pos++
			if !osaDialogValue(p, depth+1) {
				return false
			}
			p.space()
		}
		if p.pos >= len(p.source) || p.source[p.pos] != closing {
			return false
		}
		p.pos++
	} else if p.word("quoted") {
		if !p.word("form") || !p.word("of") || !osaDialogValue(p, depth+1) {
			return false
		}
	} else {
		start := p.pos
		for p.pos < len(p.source) && isIdentifierByte(p.source[p.pos]) {
			p.pos++
		}
		if p.pos == start {
			return false
		}
		switch strings.ToLower(p.source[start:p.pos]) {
		case "default", "cancel", "with", "without", "hidden", "buttons", "giving":
			return false
		}
		p.space()
		if p.pos < len(p.source) && p.source[p.pos] == '(' {
			p.pos++
			p.space()
			if p.pos >= len(p.source) {
				return false
			}
			if p.source[p.pos] != ')' {
				if !osaDialogValue(p, depth+1) {
					return false
				}
				p.space()
				for p.pos < len(p.source) && p.source[p.pos] == ',' {
					p.pos++
					if !osaDialogValue(p, depth+1) {
						return false
					}
					p.space()
				}
			}
			if p.pos >= len(p.source) || p.source[p.pos] != ')' {
				return false
			}
			p.pos++
		}
	}
	p.space()
	if p.pos < len(p.source) && p.source[p.pos] == '&' {
		p.pos++
		return osaDialogValue(p, depth+1)
	}
	return true
}
