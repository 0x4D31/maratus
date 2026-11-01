package extract

import (
	"strings"
)

// exactPythonStringLiteral accepts only an unprefixed, single-line Python
// string literal with the small escape set needed by closed static grammars.
// It deliberately rejects concatenation, formatting, bytes/raw prefixes,
// Unicode escapes, and triple-quoted strings.
func exactPythonStringLiteral(expression string) (string, bool) {
	expression = strings.TrimSpace(expression)
	if len(expression) < 2 {
		return "", false
	}
	quote := expression[0]
	if quote != '\'' && quote != '"' || expression[len(expression)-1] != quote {
		return "", false
	}
	var out strings.Builder
	out.Grow(len(expression) - 2)
	escaped := false
	for index := 1; index < len(expression)-1; index++ {
		current := expression[index]
		if escaped {
			switch current {
			case '\\', quote:
				out.WriteByte(current)
			case 'n':
				out.WriteByte('\n')
			case 'r':
				out.WriteByte('\r')
			case 't':
				out.WriteByte('\t')
			default:
				return "", false
			}
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
			continue
		}
		if current == quote {
			return "", false
		}
		out.WriteByte(current)
	}
	if escaped {
		return "", false
	}
	return out.String(), true
}

func pythonIdentifierByte(value byte) bool {
	return value == '_' ||
		value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9'
}

func exactPythonMatchingClose(value string, open int) (int, bool) {
	if open < 0 || open >= len(value) {
		return -1, false
	}
	var stack []byte
	for index := open; index < len(value); {
		current := value[index]
		if current == '\'' || current == '"' {
			next, ok := skipPythonQuoted(value, index)
			if !ok {
				return -1, false
			}
			index = next
			continue
		}
		if current == '#' {
			return -1, false
		}
		switch current {
		case '(', '[', '{':
			if len(stack) >= maxTextStringExpressionDepth {
				return -1, false
			}
			stack = append(stack, current)
		case ')', ']', '}':
			if len(stack) == 0 || !pythonDelimiterPair(stack[len(stack)-1], current) {
				return -1, false
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return index, true
			}
		}
		index++
	}
	return -1, false
}

func skipPythonQuoted(value string, start int) (int, bool) {
	if start < 0 || start >= len(value) || value[start] != '\'' && value[start] != '"' {
		return start, false
	}
	quote := value[start]
	width := 1
	if start+2 < len(value) && value[start+1] == quote && value[start+2] == quote {
		width = 3
	}
	escaped := false
	for index := start + width; index < len(value); index++ {
		current := value[index]
		if escaped {
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
			continue
		}
		if current != quote {
			continue
		}
		if width == 1 {
			return index + 1, true
		}
		if index+2 < len(value) && value[index+1] == quote && value[index+2] == quote {
			return index + 3, true
		}
	}
	return len(value), false
}

func exactPythonArguments(value string, limit int) ([]string, bool, bool) {
	var arguments []string
	start := 0
	var stack []byte
	appendArgument := func(end int, trailing bool) (bool, bool) {
		argument := strings.TrimSpace(value[start:end])
		if argument == "" {
			if trailing && len(arguments) > 0 {
				return true, false
			}
			return false, true
		}
		if limit > 0 && len(arguments) >= limit {
			return false, false
		}
		arguments = append(arguments, argument)
		return true, false
	}
	for index := 0; index < len(value); {
		current := value[index]
		if current == '\'' || current == '"' {
			next, ok := skipPythonQuoted(value, index)
			if !ok {
				return nil, false, true
			}
			index = next
			continue
		}
		if current == '#' {
			return nil, false, true
		}
		switch current {
		case '(', '[', '{':
			if len(stack) >= maxTextStringExpressionDepth {
				return nil, true, false
			}
			stack = append(stack, current)
		case ')', ']', '}':
			if len(stack) == 0 || !pythonDelimiterPair(stack[len(stack)-1], current) {
				return nil, false, true
			}
			stack = stack[:len(stack)-1]
		case ',':
			if len(stack) == 0 {
				ok, malformed := appendArgument(index, false)
				if malformed {
					return nil, false, true
				}
				if !ok {
					return nil, true, false
				}
				start = index + 1
			}
		case ';':
			// A semicolon is a statement separator, never part of a Python
			// call-argument expression in this closed grammar.
			return nil, false, true
		}
		index++
	}
	if len(stack) != 0 {
		return nil, false, true
	}
	if strings.TrimSpace(value[start:]) == "" {
		if start == 0 {
			return nil, false, false
		}
		return arguments, false, false
	}
	ok, malformed := appendArgument(len(value), true)
	if malformed {
		return nil, false, true
	}
	if !ok {
		return nil, true, false
	}
	return arguments, false, false
}

func exactPythonKeywordArgument(argument string) (string, string, bool) {
	var stack []byte
	for index := 0; index < len(argument); {
		current := argument[index]
		if current == '\'' || current == '"' {
			next, ok := skipPythonQuoted(argument, index)
			if !ok {
				return "", "", false
			}
			index = next
			continue
		}
		switch current {
		case '(', '[', '{':
			if len(stack) >= maxTextStringExpressionDepth {
				return "", "", false
			}
			stack = append(stack, current)
		case ')', ']', '}':
			if len(stack) == 0 || !pythonDelimiterPair(stack[len(stack)-1], current) {
				return "", "", false
			}
			stack = stack[:len(stack)-1]
		case '=':
			if len(stack) == 0 {
				name := strings.TrimSpace(argument[:index])
				value := strings.TrimSpace(argument[index+1:])
				if !identifierName(name) || value == "" || strings.HasPrefix(value, "=") {
					return "", "", false
				}
				return name, value, true
			}
		}
		index++
	}
	return "", "", false
}

func pythonDelimiterPair(open, close byte) bool {
	switch open {
	case '(':
		return close == ')'
	case '[':
		return close == ']'
	case '{':
		return close == '}'
	default:
		return false
	}
}
