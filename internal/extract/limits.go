package extract

import (
	"fmt"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxTextAnalysisBytes     = 32 << 20
	maxTextAnalysisLines     = 200000
	maxTextAnalysisLineBytes = 1 << 20
	// Structured decoders can allocate several times their input size. Package
	// manifests, plists, and embedded entitlement plists are normally tiny, so
	// keep their parser input well below the general artifact-file limit.
	maxStructuredDocumentBytes = 4 << 20
)

// boundedTextInput keeps derived allocations independent of the artifact file
// limit. Lines reference Source, so even newline-dense input creates at most the
// configured number of string headers and one bounded copy of the source bytes.
type boundedTextInput struct {
	Source         string
	Lines          []string
	BytesTruncated bool
	LinesTruncated bool
	LongLines      int
}

func boundedText(data []byte) boundedTextInput {
	return boundedTextLineBreaks(data, false)
}

func boundedAppleScriptText(data []byte) boundedTextInput {
	return boundedTextLineBreaks(data, true)
}

func boundedTextLineBreaks(data []byte, appleScriptLines bool) boundedTextInput {
	end := len(data)
	input := boundedTextInput{}
	if end > maxTextAnalysisBytes {
		end = maxTextAnalysisBytes
		input.BytesTruncated = true
	}
	input.Source = string(data[:end])
	input.Lines = make([]string, 0, min(1024, maxTextAnalysisLines))

	for start := 0; start <= len(input.Source); {
		if len(input.Lines) >= maxTextAnalysisLines {
			input.LinesTruncated = true
			break
		}
		relativeEnd := strings.IndexByte(input.Source[start:], '\n')
		if appleScriptLines {
			relativeEnd = strings.IndexAny(input.Source[start:], "\r\n")
		}
		lineEnd := len(input.Source)
		if relativeEnd >= 0 {
			lineEnd = start + relativeEnd
		}
		line := input.Source[start:lineEnd]
		if len(line) > maxTextAnalysisLineBytes {
			line = line[:maxTextAnalysisLineBytes]
			input.LongLines++
		}
		input.Lines = append(input.Lines, line)
		if relativeEnd < 0 {
			break
		}
		start = lineEnd + 1
		if appleScriptLines && input.Source[lineEnd] == '\r' && start < len(input.Source) && input.Source[start] == '\n' {
			start++
		}
	}
	return input
}

func (input boundedTextInput) truncated() bool {
	return input.BytesTruncated || input.LinesTruncated || input.LongLines > 0
}

func addBoundedTextCoverage(graph *behavior.Graph, content artifact.Content, scope string, input boundedTextInput) {
	if !input.truncated() {
		return
	}
	var limits []string
	if input.BytesTruncated {
		limits = append(limits, fmt.Sprintf("only the first %d bytes were analyzed", maxTextAnalysisBytes))
	}
	if input.LinesTruncated {
		limits = append(limits, fmt.Sprintf("only the first %d lines were analyzed", maxTextAnalysisLines))
	}
	if input.LongLines > 0 {
		limits = append(limits, fmt.Sprintf("%d lines were truncated to %d bytes", input.LongLines, maxTextAnalysisLineBytes))
	}
	graph.AddCoverage(behavior.Coverage{
		NodeID:       content.NodeID,
		AnalysisArea: scope,
		Status:       "partial",
		Detail:       strings.Join(limits, "; "),
	})
}

func boundedStructuredDocument(graph *behavior.Graph, content artifact.Content, scope string, data []byte) ([]byte, bool) {
	if len(data) <= maxStructuredDocumentBytes {
		return data, true
	}
	detail := fmt.Sprintf("structured decode skipped over parser input limit %d", maxStructuredDocumentBytes)
	addPartialCoverageOnce(graph, content.NodeID, scope, detail)
	return nil, false
}

func addPartialCoverageOnce(graph *behavior.Graph, nodeID, scope, detail string) {
	for _, coverage := range graph.Coverage {
		if coverage.NodeID == nodeID && coverage.AnalysisArea == scope && coverage.Status == "partial" && coverage.Detail == detail {
			return
		}
	}
	graph.AddCoverage(behavior.Coverage{
		NodeID:       nodeID,
		AnalysisArea: scope,
		Status:       "partial",
		Detail:       detail,
	})
}
