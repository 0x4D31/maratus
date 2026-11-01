package extract

import (
	"fmt"
	"strings"
)

const (
	maxShellHeredocsPerArtifact = 64
	maxShellHeredocsPerLine     = 16
	maxShellHeredocDelimiter    = 256
)

type shellHeredoc struct {
	delimiter string
	stripTabs bool
	quoted    bool
	line      int
}

type shellHeredocState struct {
	pending []shellHeredoc
	total   int
	opaque  bool
}

// consumeBodyLine reports whether a physical source line belongs to a pending
// heredoc. Terminator lines are syntax, not commands, so they are consumed too.
func (state *shellHeredocState) consumeBodyLine(line string) bool {
	if state.opaque {
		return true
	}
	if len(state.pending) == 0 {
		return false
	}
	candidate := strings.TrimSuffix(line, "\r")
	current := state.pending[0]
	if current.stripTabs {
		candidate = strings.TrimLeft(candidate, "\t")
	}
	if candidate == current.delimiter {
		state.pending = state.pending[1:]
	}
	return true
}

// observeCommandLine records heredocs whose bodies begin on the next physical
// line. If a delimiter cannot be recovered safely, subsequent shell modeling
// is suppressed: guessing where its body ends would recreate the false
// positives this state machine exists to prevent.
func (state *shellHeredocState) observeCommandLine(line string, lineNo int) (details []string, suppress bool) {
	openers, scanDetails, unsafe := scanShellHeredocOpeners(line, lineNo)
	details = append(details, scanDetails...)
	if unsafe {
		state.opaque = true
		return details, true
	}
	if len(openers) == 0 {
		return details, false
	}
	if len(openers) > maxShellHeredocsPerLine || state.total > maxShellHeredocsPerArtifact-len(openers) {
		state.opaque = true
		details = append(details, fmt.Sprintf("shell heredoc limit reached at line %d; subsequent shell text was not modeled", lineNo))
		return details, true
	}
	state.total += len(openers)
	state.pending = append(state.pending, openers...)
	for _, opener := range openers {
		if !opener.quoted {
			details = append(details, fmt.Sprintf("unquoted shell heredoc at line %d can expand parameters, commands, and arithmetic in its body; body expansions were not modeled", opener.line))
		}
	}
	return details, false
}

func (state *shellHeredocState) incompleteDetail() string {
	if state.opaque {
		return "a malformed or unsupported shell heredoc prevented safe recovery of subsequent command boundaries"
	}
	if len(state.pending) == 0 {
		return ""
	}
	return fmt.Sprintf("%d shell heredoc body or bodies were not terminated within the analyzed text", len(state.pending))
}

func scanShellHeredocOpeners(line string, lineNo int) (openers []shellHeredoc, details []string, unsafe bool) {
	line = strings.TrimSuffix(line, "\r")
	scanner := newShellSyntaxScanner()
	for index := 0; index < len(line); {
		context := scanner.contexts[len(scanner.contexts)-1]
		unquoted := context.quote == 0
		if unquoted && line[index] == '#' && inlineCommentAllowed(line, index, commentMarker{token: "#", shellBoundary: true}) {
			break
		}
		if unquoted && !context.arithmetic && strings.HasPrefix(line[index:], "<<<") {
			details = append(details, fmt.Sprintf("shell here-string syntax at line %d was not modeled as a heredoc", lineNo))
			index += 3
			continue
		}
		if unquoted && !context.arithmetic && strings.HasPrefix(line[index:], "<<") {
			stripTabs := false
			wordStart := index + 2
			if wordStart < len(line) && line[wordStart] == '-' {
				stripTabs = true
				wordStart++
			}
			for wordStart < len(line) && (line[wordStart] == ' ' || line[wordStart] == '\t') {
				wordStart++
			}
			if wordStart >= len(line) || line[wordStart] == '#' && inlineCommentAllowed(line, wordStart, commentMarker{token: "#", shellBoundary: true}) {
				details = append(details, fmt.Sprintf("shell heredoc at line %d has no recoverable delimiter; subsequent shell text was not modeled", lineNo))
				return openers, details, true
			}
			delimiter, end, quoted, dynamic, malformed, complex := parseShellHeredocDelimiter(line, wordStart)
			if malformed || complex || end <= wordStart || len(delimiter) > maxShellHeredocDelimiter {
				details = append(details, fmt.Sprintf("shell heredoc delimiter at line %d is malformed, complex, or over the %d-byte limit; subsequent shell text was not modeled", lineNo, maxShellHeredocDelimiter))
				return openers, details, true
			}
			if dynamic {
				details = append(details, fmt.Sprintf("shell heredoc delimiter at line %d contains unquoted expansion syntax; it was matched conservatively as literal text", lineNo))
			}
			openers = append(openers, shellHeredoc{delimiter: delimiter, stripTabs: stripTabs, quoted: quoted, line: lineNo})
			index = end
			continue
		}
		index += scanner.advance(line, index)
	}
	return openers, details, false
}

func parseShellHeredocDelimiter(line string, start int) (delimiter string, end int, quoted, dynamic, malformed, complex bool) {
	var out strings.Builder
	var quote byte
	escaped := false
	sawWord := false
	for index := start; index < len(line); index++ {
		current := line[index]
		if escaped {
			out.WriteByte(current)
			escaped = false
			sawWord = true
			continue
		}
		if quote != 0 {
			if current == quote {
				quote = 0
				sawWord = true
				continue
			}
			if current == '\\' && quote == '"' {
				escaped = true
				continue
			}
			out.WriteByte(current)
			sawWord = true
			continue
		}
		if current == '\\' {
			escaped = true
			quoted = true
			sawWord = true
			continue
		}
		if current == '\'' || current == '"' {
			quote = current
			quoted = true
			sawWord = true
			continue
		}
		if current == '`' || current == '$' && index+1 < len(line) && (line[index+1] == '(' || line[index+1] == '\'' || line[index+1] == '"') {
			return out.String(), index, quoted, dynamic, false, true
		}
		if current == '$' {
			dynamic = true
		}
		if current == ' ' || current == '\t' || strings.ContainsRune(";|&<>()", rune(current)) {
			if !sawWord {
				return "", index, quoted, dynamic, true, false
			}
			return out.String(), index, quoted, dynamic, false, false
		}
		out.WriteByte(current)
		sawWord = true
	}
	if escaped || quote != 0 || !sawWord {
		return out.String(), len(line), quoted, dynamic, true, false
	}
	return out.String(), len(line), quoted, dynamic, false, false
}
