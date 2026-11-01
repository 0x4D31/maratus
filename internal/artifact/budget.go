package artifact

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

const diagnosticSummaryPrefix = "diagnostic budget reached; omitted "

func archiveDecodedOutputWorkLimitDetail(limit int64) string {
	return fmt.Sprintf("archive attempted decoded-output byte limit %d reached; this and remaining entries were not fully decoded", limit)
}

func (s *scanner) addDiagnostic(message string) {
	maxCount := s.options.MaxDiagnostics
	if maxCount <= 0 {
		maxCount = DefaultMaxDiagnostics
	}
	maxBytes := s.options.MaxDiagnosticBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxDiagnosticBytes
	}
	if s.suppressedDiagnostics == 0 && len(s.diagnostics) < maxCount && s.diagnosticBytes+int64(len(message)) <= maxBytes {
		s.diagnostics = append(s.diagnostics, message)
		s.diagnosticBytes += int64(len(message))
		return
	}
	if s.suppressedDiagnostics > 0 {
		s.removeDiagnosticSummary()
	}
	s.suppressedDiagnostics++
	s.suppressedDiagnosticBytes += int64(len(message))
	s.appendDiagnosticSummary(maxCount, maxBytes)
}

func (s *scanner) removeDiagnosticSummary() {
	if !s.diagnosticSummary || len(s.diagnostics) == 0 {
		return
	}
	last := len(s.diagnostics) - 1
	s.diagnosticBytes -= int64(len(s.diagnostics[last]))
	s.diagnostics = s.diagnostics[:last]
	s.diagnosticSummary = false
}

func (s *scanner) appendDiagnosticSummary(maxCount int, maxBytes int64) {
	for {
		summary := fmt.Sprintf("%s%d messages (%d bytes)", diagnosticSummaryPrefix, s.suppressedDiagnostics, s.suppressedDiagnosticBytes)
		if int64(len(summary)) > maxBytes {
			summary = summary[:maxBytes]
		}
		if len(s.diagnostics) < maxCount && s.diagnosticBytes+int64(len(summary)) <= maxBytes {
			s.diagnostics = append(s.diagnostics, summary)
			s.diagnosticBytes += int64(len(summary))
			s.diagnosticSummary = true
			return
		}
		if len(s.diagnostics) == 0 {
			return
		}
		last := len(s.diagnostics) - 1
		s.suppressedDiagnostics++
		s.suppressedDiagnosticBytes += int64(len(s.diagnostics[last]))
		s.diagnosticBytes -= int64(len(s.diagnostics[last]))
		s.diagnostics = s.diagnostics[:last]
	}
}

func (s *scanner) remainingTraversalEntries() int {
	limit := s.options.MaxArtifactNodes
	if limit <= 0 {
		limit = DefaultMaxArtifactNodes
	}
	workRemaining := limit - s.traversalEntries
	nodeRemaining := limit - len(s.graph.Nodes)
	if workRemaining < nodeRemaining {
		nodeRemaining = workRemaining
	}
	if nodeRemaining < 0 {
		return 0
	}
	return nodeRemaining
}

func (s *scanner) readTraversalDirectory(path string, expected os.FileInfo) ([]os.DirEntry, bool, error) {
	remaining := s.remainingTraversalEntries()
	if remaining <= 0 {
		return nil, true, nil
	}
	directory, err := s.openStableDirectory(path, expected)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = directory.Close() }()
	entries, limited, err := readDirectoryEntriesFromFile(directory, remaining)
	s.traversalEntries += len(entries)
	return entries, limited, err
}

func readDirectoryEntries(path string, maxEntries int) ([]os.DirEntry, bool, error) {
	directory, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = directory.Close() }()
	return readDirectoryEntriesFromFile(directory, maxEntries)
}

func readDirectoryEntriesFromFile(directory *os.File, maxEntries int) ([]os.DirEntry, bool, error) {
	if maxEntries <= 0 {
		return nil, true, nil
	}
	entries := make([]os.DirEntry, 0, min(maxEntries, 256))
	for len(entries) < maxEntries {
		batchSize := min(256, maxEntries-len(entries))
		batch, readErr := directory.ReadDir(batchSize)
		entries = append(entries, batch...)
		if readErr == io.EOF {
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			return entries, false, nil
		}
		if readErr != nil {
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			return entries, false, readErr
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	probe, probeErr := directory.ReadDir(1)
	if len(probe) > 0 {
		return entries, true, probeErr
	}
	if probeErr == io.EOF {
		return entries, false, nil
	}
	return entries, false, probeErr
}

func (s *scanner) markNodePartial(nodeID, detail string) {
	if nodeID == "" {
		return
	}
	for i := range s.graph.Nodes {
		if s.graph.Nodes[i].ID != nodeID || s.graph.Nodes[i].AnalyzeStatus == "skipped" {
			continue
		}
		s.graph.Nodes[i].AnalyzeStatus = "partial"
		if s.graph.Nodes[i].CoverageDetail == "" {
			s.graph.Nodes[i].CoverageDetail = detail
		} else if !strings.Contains(s.graph.Nodes[i].CoverageDetail, detail) {
			s.graph.Nodes[i].CoverageDetail += "; " + detail
		}
		return
	}
}

func traversalLimitDetail(limit int) string {
	return fmt.Sprintf("filesystem traversal entry/node limit %d reached; remaining directory entries not inspected", limit)
}

// jsonEscapedStringBytes bounds the default encoding/json string representation.
// Invalid UTF-8 is charged as a six-byte escape even on toolchains that emit a
// three-byte replacement rune, keeping this a conservative resource bound.
func jsonEscapedStringBytes(value string) int64 {
	var bytes int64
	for offset := 0; offset < len(value); {
		c := value[offset]
		if c < utf8.RuneSelf {
			switch c {
			case '\b', '\t', '\n', '\f', '\r', '"', '\\':
				bytes += 2
			case '<', '>', '&':
				bytes += 6
			default:
				if c < 0x20 {
					bytes += 6
				} else {
					bytes++
				}
			}
			offset++
			continue
		}
		r, size := utf8.DecodeRuneInString(value[offset:])
		if r == utf8.RuneError && size == 1 {
			bytes += 6
			offset++
			continue
		}
		if r == '\u2028' || r == '\u2029' {
			bytes += 6
		} else {
			bytes += int64(size)
		}
		offset += size
	}
	return bytes
}
