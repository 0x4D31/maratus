// Package terminal provides helpers for safely rendering untrusted text in a
// terminal without changing machine-readable output.
package terminal

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ColorMode controls ANSI styling in human-readable command output. Machine
// output must never pass through color rendering.
type ColorMode string

const (
	ColorAuto   ColorMode = "auto"
	ColorAlways ColorMode = "always"
	ColorNever  ColorMode = "never"
)

type escapedChunk struct {
	text  string
	width int
}

// ParseColorMode validates a --color value.
func ParseColorMode(value string) (ColorMode, error) {
	switch ColorMode(strings.ToLower(strings.TrimSpace(value))) {
	case ColorAuto:
		return ColorAuto, nil
	case ColorAlways:
		return ColorAlways, nil
	case ColorNever:
		return ColorNever, nil
	default:
		return "", fmt.Errorf("invalid --color %q (want auto, always, or never)", value)
	}
}

// ColorEnabled resolves a validated color mode. Automatic styling is only
// enabled for a terminal and follows the NO_COLOR convention and TERM=dumb.
// An explicit "always" choice deliberately overrides those environment hints.
func ColorEnabled(mode ColorMode, isTerminal bool, noColor, term string) bool {
	switch mode {
	case ColorAlways:
		return true
	case ColorNever:
		return false
	case ColorAuto:
		return isTerminal && noColor == "" && !strings.EqualFold(strings.TrimSpace(term), "dumb")
	default:
		return false
	}
}

// Escape replaces terminal-active control characters with visible escape
// sequences. Printable Unicode is preserved. Invalid UTF-8 bytes are escaped
// as bytes so the returned string is always valid UTF-8.
func Escape(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			appendHexByte(&out, value[0])
			value = value[1:]
			continue
		}
		value = value[size:]
		if !mustEscape(r) {
			out.WriteRune(r)
			continue
		}
		switch r {
		case '\a':
			out.WriteString(`\a`)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\v':
			out.WriteString(`\v`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			appendEscapedRune(&out, r)
		}
	}
	return out.String()
}

// EscapeTruncate escapes terminal-active text and bounds the rendered value by
// Unicode code points. Escape sequences are kept intact and an ellipsis marks
// truncation. This avoids scanning or emitting an arbitrarily large untrusted
// field when producing concise human-readable output.
func EscapeTruncate(value string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	chunks := make([]escapedChunk, 0, min(len(value), maxRunes))
	written := 0
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		width := escapedRuneWidth(r, size)
		if written+width > maxRunes {
			return truncatedEscapedChunks(chunks, written, maxRunes)
		}
		var chunk strings.Builder
		if r == utf8.RuneError && size == 1 {
			appendHexByte(&chunk, value[0])
			value = value[1:]
		} else {
			value = value[size:]
			appendEscaped(&chunk, r)
		}
		chunks = append(chunks, escapedChunk{text: chunk.String(), width: width})
		written += width
		if value != "" && written == maxRunes {
			return truncatedEscapedChunks(chunks, written, maxRunes)
		}
	}
	return joinEscapedChunks(chunks, maxRunes)
}

func truncatedEscapedChunks(chunks []escapedChunk, written, maxRunes int) string {
	if maxRunes <= 3 {
		return strings.Repeat(".", maxRunes)
	}
	limit := maxRunes - 3
	for len(chunks) > 0 && written > limit {
		last := chunks[len(chunks)-1]
		written -= last.width
		chunks = chunks[:len(chunks)-1]
	}
	var out strings.Builder
	out.Grow(maxRunes)
	for _, chunk := range chunks {
		out.WriteString(chunk.text)
	}
	out.WriteString("...")
	return out.String()
}

func joinEscapedChunks(chunks []escapedChunk, capacity int) string {
	var out strings.Builder
	out.Grow(capacity)
	for _, chunk := range chunks {
		out.WriteString(chunk.text)
	}
	return out.String()
}

func escapedRuneWidth(r rune, size int) int {
	if r == utf8.RuneError && size == 1 {
		return 4
	}
	if !mustEscape(r) {
		return 1
	}
	switch r {
	case '\a', '\b', '\t', '\n', '\v', '\f', '\r':
		return 2
	}
	if r <= 0xff {
		return 4
	}
	if r <= 0xffff {
		return 6
	}
	return 10
}

func appendEscaped(out *strings.Builder, r rune) {
	if !mustEscape(r) {
		out.WriteRune(r)
		return
	}
	switch r {
	case '\a':
		out.WriteString(`\a`)
	case '\b':
		out.WriteString(`\b`)
	case '\t':
		out.WriteString(`\t`)
	case '\n':
		out.WriteString(`\n`)
	case '\v':
		out.WriteString(`\v`)
	case '\f':
		out.WriteString(`\f`)
	case '\r':
		out.WriteString(`\r`)
	default:
		appendEscapedRune(out, r)
	}
}

func mustEscape(r rune) bool {
	return unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) ||
		r == '\u2028' || r == '\u2029'
}

func appendEscapedRune(out *strings.Builder, r rune) {
	switch {
	case r <= 0xff:
		out.WriteString(`\x`)
		appendHex(out, uint32(r), 2)
	case r <= 0xffff:
		out.WriteString(`\u`)
		appendHex(out, uint32(r), 4)
	default:
		out.WriteString(`\U`)
		appendHex(out, uint32(r), 8)
	}
}

func appendHexByte(out *strings.Builder, value byte) {
	out.WriteString(`\x`)
	appendHex(out, uint32(value), 2)
}

func appendHex(out *strings.Builder, value uint32, width int) {
	const digits = "0123456789abcdef"
	var buf [8]byte
	for i := width - 1; i >= 0; i-- {
		buf[i] = digits[value&0xf]
		value >>= 4
	}
	out.Write(buf[:width])
}
