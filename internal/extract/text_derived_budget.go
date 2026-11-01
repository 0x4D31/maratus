package extract

import (
	"fmt"
	"regexp"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

// Text recognizers deliberately work on a bounded prefix of a file, but a
// short input can still describe hundreds of thousands of derived values (for
// example: adjacent quoted strings or one-character argv entries). Keep those
// derived products bounded independently of the source-byte limit.
const (
	maxTextDerivedMatchesPerLine       = 256
	maxTextDerivedMatchesPerFile       = 16_384
	maxTextDerivedRetainedBytesPerLine = 256 << 10
	maxTextDerivedRetainedBytesPerFile = 8 << 20
	maxTextDerivedScanBytesPerLine     = 32 << 20
	maxTextDerivedScanBytesPerFile     = 256 << 20
	maxTextDerivedValueBytes           = 64 << 10
)

type textDerivedBudget struct {
	matches       int
	retainedBytes int64
	scanBytes     int64
	limited       bool
	exhausted     bool
	detail        string
}

type textLineBudget struct {
	file          *textDerivedBudget
	matches       int
	retainedBytes int64
	scanBytes     int64
	limited       bool
}

func newTextDerivedBudget() *textDerivedBudget {
	return &textDerivedBudget{}
}

func (b *textDerivedBudget) line() *textLineBudget {
	return &textLineBudget{file: b}
}

func standaloneTextLineBudget() *textLineBudget {
	return newTextDerivedBudget().line()
}

func textBudgetOrStandalone(b *textLineBudget) *textLineBudget {
	if b != nil {
		return b
	}
	return standaloneTextLineBudget()
}

func (b *textLineBudget) chargeScan(size int, kind string) bool {
	if b == nil {
		return true
	}
	if size < 0 || b.limited || b.file == nil || b.file.exhausted {
		return false
	}
	amount := int64(size)
	if amount > maxTextDerivedScanBytesPerLine-b.scanBytes {
		b.markLimited(fmt.Sprintf("%s scan-work limit %d bytes per line reached", kind, maxTextDerivedScanBytesPerLine), false)
		return false
	}
	if amount > maxTextDerivedScanBytesPerFile-b.file.scanBytes {
		b.markLimited(fmt.Sprintf("derived scan-work limit %d bytes per file reached", maxTextDerivedScanBytesPerFile), true)
		return false
	}
	b.scanBytes += amount
	b.file.scanBytes += amount
	return true
}

func (b *textLineBudget) matchAllowance() int {
	if b == nil || b.file == nil || b.limited || b.file.exhausted {
		return 0
	}
	lineRemaining := maxTextDerivedMatchesPerLine - b.matches
	fileRemaining := maxTextDerivedMatchesPerFile - b.file.matches
	if lineRemaining < fileRemaining {
		return lineRemaining
	}
	return fileRemaining
}

func (b *textLineBudget) retainMatch(size int, kind string) bool {
	if b == nil {
		return true
	}
	if size < 0 || b.limited || b.file == nil || b.file.exhausted {
		return false
	}
	if b.matches >= maxTextDerivedMatchesPerLine {
		b.markLimited(fmt.Sprintf("%s match limit %d per line reached", kind, maxTextDerivedMatchesPerLine), false)
		return false
	}
	if b.file.matches >= maxTextDerivedMatchesPerFile {
		b.markLimited(fmt.Sprintf("derived match limit %d per file reached", maxTextDerivedMatchesPerFile), true)
		return false
	}
	if size > maxTextDerivedValueBytes {
		b.markLimited(fmt.Sprintf("%s value exceeded %d retained bytes", kind, maxTextDerivedValueBytes), false)
		return false
	}
	amount := int64(size)
	if amount > maxTextDerivedRetainedBytesPerLine-b.retainedBytes {
		b.markLimited(fmt.Sprintf("%s retained-byte limit %d per line reached", kind, maxTextDerivedRetainedBytesPerLine), false)
		return false
	}
	if amount > maxTextDerivedRetainedBytesPerFile-b.file.retainedBytes {
		b.markLimited(fmt.Sprintf("derived retained-byte limit %d per file reached", maxTextDerivedRetainedBytesPerFile), true)
		return false
	}
	b.matches++
	b.file.matches++
	b.retainedBytes += amount
	b.file.retainedBytes += amount
	return true
}

func (b *textLineBudget) markMore(kind string) {
	if b == nil {
		return
	}
	fileLimit := b.file != nil && b.file.matches >= maxTextDerivedMatchesPerFile
	limit := maxTextDerivedMatchesPerLine
	if fileLimit {
		limit = maxTextDerivedMatchesPerFile
	}
	scope := "line"
	if fileLimit {
		scope = "file"
	}
	b.markLimited(fmt.Sprintf("%s match limit %d per %s reached", kind, limit, scope), fileLimit)
}

func (b *textLineBudget) markLimited(detail string, exhaustFile bool) {
	if b == nil {
		return
	}
	b.limited = true
	if b.file == nil {
		return
	}
	b.file.limited = true
	if b.file.detail == "" {
		b.file.detail = detail
	}
	if exhaustFile {
		b.file.exhausted = true
	}
}

func (b *textDerivedBudget) coverageDetail() string {
	detail := b.detail
	if detail == "" {
		detail = "derived text-analysis budget reached"
	}
	if b.exhausted {
		return detail + "; remaining derived text analysis was not performed"
	}
	return detail + "; excess candidates on at least one line were not analyzed"
}

func addTextDerivedCoverageOnce(graph *behavior.Graph, content artifact.Content, budget *textDerivedBudget) {
	if budget == nil || !budget.limited {
		return
	}
	const scope = "text-derived-analysis"
	for _, coverage := range graph.Coverage {
		if coverage.NodeID == content.NodeID && coverage.AnalysisArea == scope && coverage.Status == "partial" {
			return
		}
	}
	addPartialCoverageOnce(graph, content.NodeID, scope, budget.coverageDetail())
}

// boundedTextRegexpMatches performs one bounded regexp enumeration. Returned
// indexes reference value and are themselves capped before regexp can allocate
// a result proportional to a maximum-size input line.
func boundedTextRegexpMatches(expression *regexp.Regexp, value, kind string, budget *textLineBudget) [][]int {
	budget = textBudgetOrStandalone(budget)
	if !budget.chargeScan(len(value), kind) {
		return nil
	}
	allowance := budget.matchAllowance()
	if allowance <= 0 {
		budget.markMore(kind)
		return nil
	}
	matches := expression.FindAllStringIndex(value, allowance+1)
	truncated := len(matches) > allowance
	if truncated {
		matches = matches[:allowance]
	}
	out := matches[:0]
	for _, match := range matches {
		if len(match) != 2 || match[0] < 0 || match[1] < match[0] || match[1] > len(value) {
			continue
		}
		if !budget.retainMatch(match[1]-match[0], kind) {
			break
		}
		out = append(out, match)
	}
	if truncated {
		budget.markMore(kind)
	}
	return out
}

func boundedTextCallArguments(value, kind string, budget *textLineBudget) []string {
	budget = textBudgetOrStandalone(budget)
	if !budget.chargeScan(len(value), kind) {
		return nil
	}
	allowance := budget.matchAllowance()
	if allowance <= 0 {
		budget.markMore(kind)
		return nil
	}
	arguments, truncated := splitCallArgumentsLimited(value, allowance)
	if truncated {
		// A truncated argv/call expression must not be interpreted as though it
		// were complete. Callers can continue analyzing later source lines.
		budget.markMore(kind)
		return nil
	}
	for _, argument := range arguments {
		if !budget.retainMatch(len(argument), kind) {
			return nil
		}
	}
	return arguments
}
