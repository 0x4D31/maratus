package extract

import "strings"

const (
	maxPythonMultilineStringLines = 8192
	maxPythonMultilineStringBytes = 4 << 20
)

type pythonMultilineStringMask struct {
	lines               []string
	formattedExpression bool
	limited             bool
	unterminated        bool
}

// maskPythonMultilineStrings removes triple-quoted Python string contents
// before the lightweight line recognizers run. It is a lexical safety pass,
// not a Python parser: ordinary quoted strings and comments are skipped so
// delimiter-looking text inside them cannot change state, and code following
// a proved closing delimiter remains available for analysis.
//
// If the dedicated work bound is reached, the uninspected suffix is blanked.
// This fails closed instead of allowing string contents to become operations.
func maskPythonMultilineStrings(lines []string) pythonMultilineStringMask {
	return maskPythonMultilineStringsBounded(
		lines,
		maxPythonMultilineStringLines,
		maxPythonMultilineStringBytes,
	)
}

func maskPythonMultilineStringsBounded(lines []string, maxLines, maxBytes int) pythonMultilineStringMask {
	result := pythonMultilineStringMask{lines: append([]string(nil), lines...)}
	delimiter := ""
	maskedLines := 0
	maskedBytes := 0

	for lineIndex, line := range lines {
		if result.limited {
			result.lines[lineIndex] = ""
			continue
		}

		var masked []byte
		maskRange := func(start, end int) bool {
			if start < 0 {
				start = 0
			}
			if end > len(line) {
				end = len(line)
			}
			if end <= start {
				return true
			}
			if masked == nil {
				masked = []byte(line)
			}
			for index := start; index < end; index++ {
				masked[index] = ' '
			}
			maskedBytes += end - start
			return maxBytes <= 0 || maskedBytes <= maxBytes
		}

		index := 0
		lineCounted := false
		if delimiter != "" {
			maskedLines++
			lineCounted = true
			if maxLines > 0 && maskedLines > maxLines {
				result.limited = true
				result.lines[lineIndex] = ""
				continue
			}
		}
		for index < len(line) {
			if delimiter != "" {
				close := pythonTripleQuoteClose(line, index, delimiter)
				if close < 0 {
					if !maskRange(index, len(line)) {
						result.limited = true
					}
					break
				}
				if !maskRange(index, close+len(delimiter)) {
					result.limited = true
					break
				}
				index = close + len(delimiter)
				delimiter = ""
				continue
			}

			switch line[index] {
			case '#':
				index = len(line)
				continue
			case '\'', '"':
				if !pythonTripleQuoteAt(line, index) {
					next, ok := skipPythonQuoted(line, index)
					if !ok {
						index = len(line)
						continue
					}
					index = next
					continue
				}

				delimiter = line[index : index+3]
				if pythonTripleQuoteFormatted(line, index) {
					result.formattedExpression = true
					// Replacement fields may themselves contain strings and
					// quote tokens. Without a Python expression parser, the
					// apparent outer closing delimiter is not trustworthy.
					// Preserve only the proved prefix and fail closed for the
					// remainder of the retained source.
					_ = maskRange(index, len(line))
					result.lines[lineIndex] = string(masked)
					for suffix := lineIndex + 1; suffix < len(result.lines); suffix++ {
						result.lines[suffix] = ""
					}
					return result
				}
				if !lineCounted {
					maskedLines++
					lineCounted = true
					if maxLines > 0 && maskedLines > maxLines {
						result.limited = true
						break
					}
				}
				close := pythonTripleQuoteClose(line, index+len(delimiter), delimiter)
				if close < 0 {
					if !maskRange(index, len(line)) {
						result.limited = true
					}
					index = len(line)
					break
				}
				if !maskRange(index, close+len(delimiter)) {
					result.limited = true
					break
				}
				index = close + len(delimiter)
				delimiter = ""
				continue
			default:
				index++
			}
		}

		if result.limited {
			result.lines[lineIndex] = ""
			continue
		}
		if masked != nil {
			result.lines[lineIndex] = string(masked)
		}
	}

	result.unterminated = delimiter != "" && !result.limited
	return result
}

func pythonTripleQuoteAt(line string, index int) bool {
	if index < 0 || index+2 >= len(line) {
		return false
	}
	quote := line[index]
	return (quote == '\'' || quote == '"') &&
		line[index+1] == quote &&
		line[index+2] == quote
}

func pythonTripleQuoteClose(line string, start int, delimiter string) int {
	if len(delimiter) != 3 {
		return -1
	}
	for index := start; index+len(delimiter) <= len(line); index++ {
		if !strings.HasPrefix(line[index:], delimiter) || pythonQuoteEscaped(line, index) {
			continue
		}
		return index
	}
	return -1
}

func pythonQuoteEscaped(line string, index int) bool {
	backslashes := 0
	for index--; index >= 0 && line[index] == '\\'; index-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func pythonTripleQuoteFormatted(line string, quoteIndex int) bool {
	start := quoteIndex
	for start > 0 {
		current := line[start-1]
		if current < 'A' || current > 'Z' && current < 'a' || current > 'z' {
			break
		}
		start--
	}
	if start == quoteIndex || start > 0 && pythonIdentifierByte(line[start-1]) {
		return false
	}
	prefix := strings.ToLower(line[start:quoteIndex])
	switch prefix {
	case "f", "fr", "rf", "t", "tr", "rt":
		return true
	default:
		return false
	}
}
