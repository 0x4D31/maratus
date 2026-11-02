package extract

import (
	"strings"
	"unicode/utf8"
)

const (
	maxOSAExpressionBytes = 16 << 10
	maxOSAExpressionDepth = 8
	maxOSAExpressionTerms = 128
)

// osaLiteralExpression is a closed string transformer. It never evaluates
// handlers, coercions, shell expansions or application objects. Identifiers
// resolve only through an explicit bounded local immutable-text proof table.
type osaLiteralExpression struct {
	source     string
	pos, terms int
	bindings   *osaStringBindings
	proofs     []string
}

func exactAppleScriptStringExpression(source string) (string, bool) {
	value, _, exact := resolveAppleScriptStringExpression(source, nil)
	return value, exact
}

func resolveAppleScriptStringExpression(source string, bindings *osaStringBindings) (string, []string, bool) {
	if len(source) > maxOSAExpressionBytes || !utf8.ValidString(source) {
		return "", nil, false
	}
	if bindings != nil && bindings.asciiOnly {
		for i := 0; i < len(source); i++ {
			if source[i] >= 0x80 {
				return "", nil, false
			}
		}
	}
	p := osaLiteralExpression{source: source, bindings: bindings}
	value, ok := p.expression(0)
	p.space()
	return value, p.proofs, ok && p.pos == len(source)
}

func boundedAppleScriptArgumentShape(source string) bool {
	if len(source) > maxOSAExpressionBytes || !utf8.ValidString(source) {
		return false
	}
	p := osaLiteralExpression{source: source}
	ok := osaDialogValue(&p, 0)
	p.space()
	return ok && p.pos == len(source)
}

func (p *osaLiteralExpression) space() {
	for p.pos < len(p.source) && strings.ContainsRune(" \t\r\n", rune(p.source[p.pos])) {
		p.pos++
	}
}

func (p *osaLiteralExpression) expression(depth int) (string, bool) {
	if depth >= maxOSAExpressionDepth {
		return "", false
	}
	value, ok := p.term(depth)
	if !ok {
		return "", false
	}
	for {
		p.space()
		if p.pos >= len(p.source) || p.source[p.pos] != '&' {
			return value, true
		}
		p.pos++
		next, ok := p.term(depth)
		if !ok || len(value) > maxOSAExpressionBytes-len(next) {
			return "", false
		}
		value += next
	}
}

func (p *osaLiteralExpression) term(depth int) (string, bool) {
	if depth >= maxOSAExpressionDepth {
		return "", false
	}
	p.terms++
	if p.terms > maxOSAExpressionTerms {
		return "", false
	}
	p.space()
	if p.pos >= len(p.source) {
		return "", false
	}
	if p.source[p.pos] == '(' {
		p.pos++
		value, ok := p.expression(depth + 1)
		p.space()
		if !ok || p.pos >= len(p.source) || p.source[p.pos] != ')' {
			return "", false
		}
		p.pos++
		return value, true
	}
	if p.word("quoted") {
		if !p.word("form") || !p.word("of") {
			return "", false
		}
		value, ok := p.term(depth + 1)
		if !ok || depth+1 >= maxOSAExpressionDepth {
			return "", false
		}
		value = "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
		return value, len(value) <= maxOSAExpressionBytes
	}
	if p.source[p.pos] != '"' {
		if p.bindings != nil {
			name := osaBindingIdentifier(p)
			binding, known := p.bindings.lookup(name)
			if known {
				p.proofs = mergeEvidenceIDs(append(p.proofs, binding.evidenceIDs...)...)
				if len(p.proofs) <= maxOSAStringProofs {
					return binding.value, true
				}
				p.bindings.limited = true
			}
		}
		return "", false
	}
	p.pos++
	var value strings.Builder
	for p.pos < len(p.source) {
		c := p.source[p.pos]
		p.pos++
		if c == 0 || c == '\n' || c == '\r' {
			return "", false
		}
		if c == '"' {
			return value.String(), true
		}
		if c == '\\' {
			if p.pos >= len(p.source) {
				return "", false
			}
			c = p.source[p.pos]
			p.pos++
			switch c {
			case '\\', '"':
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			default:
				return "", false
			}
		}
		value.WriteByte(c)
	}
	return "", false
}

func (p *osaLiteralExpression) word(word string) bool {
	p.space()
	end := p.pos + len(word)
	if end > len(p.source) || !strings.EqualFold(p.source[p.pos:end], word) {
		return false
	}
	if end < len(p.source) && !strings.ContainsRune(" \t\r\n(\"", rune(p.source[end])) {
		return false
	}
	p.pos = end
	return true
}
