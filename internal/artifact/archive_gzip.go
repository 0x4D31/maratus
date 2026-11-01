package artifact

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"strings"
)

type gzipDecodeBudget struct {
	limit  int64
	detail string
}

// scanGzip decodes one gzip member. A gzip stream is a representation, not a
// TAR claim: TAR and CPIO semantics are selected only after inspecting the
// complete decompressed bytes. Concatenated members and trailing data fail
// closed so one outer artifact cannot silently produce ambiguous payloads.
func (s *scanner) scanGzip(parentID, logical string, data []byte, depth int) {
	input := bytes.NewReader(data)
	reader, err := gzip.NewReader(input)
	if err != nil {
		s.markGzipPartial(parentID, logical, fmt.Sprintf("gzip parse failed: %v; contents not inspected", err))
		return
	}
	reader.Multistream(false)

	budget := s.gzipDecodeBudget()
	decoded, err := readAllLimited(reader, budget.limit)
	closeErr := reader.Close()
	if err != nil {
		var limitErr *byteLimitError
		if errors.As(err, &limitErr) {
			s.markGzipPartial(parentID, logical, budget.detail)
		} else {
			s.markGzipPartial(parentID, logical, fmt.Sprintf("gzip read failed: %v; contents not inspected", err))
		}
		return
	}
	if closeErr != nil {
		s.markGzipPartial(parentID, logical, fmt.Sprintf("gzip close failed: %v; stream integrity could not be verified and no payload was modeled", closeErr))
		return
	}
	if input.Len() != 0 {
		s.markGzipPartial(parentID, logical, "concatenated or trailing gzip data is unsupported; no payload was modeled")
		return
	}
	if compressionRatioExceeded(uint64(len(decoded)), uint64(len(data)), s.options.MaxCompressionRatio) {
		s.markGzipPartial(parentID, logical, fmt.Sprintf("gzip compression ratio limit %d exceeded; contents not inspected", s.options.MaxCompressionRatio))
		return
	}

	switch {
	case hasTarMagic(decoded):
		s.scanTar(parentID, logical, decoded, depth)
	case isCPIO(decoded):
		s.scanCPIO(parentID, logical, decoded, depth)
	default:
		s.addVirtualEntries(parentID, logical, []VirtualEntry{{
			Name:           gzipPayloadName(logical),
			Data:           decoded,
			Size:           int64(len(decoded)),
			CompressedSize: int64(len(data)),
			Provenance:     "gzip-member",
		}}, depth)
	}
}

func (s *scanner) gzipDecodeBudget() gzipDecodeBudget {
	budget := gzipDecodeBudget{
		limit:  s.options.MaxArchiveBytes,
		detail: fmt.Sprintf("archive content byte limit %d reached while decoding gzip; contents not inspected", s.options.MaxArchiveBytes),
	}
	if s.options.MaxFileBytes < budget.limit {
		budget = gzipDecodeBudget{
			limit:  s.options.MaxFileBytes,
			detail: fmt.Sprintf("gzip payload exceeds max file bytes %d; contents not inspected", s.options.MaxFileBytes),
		}
	}
	remainingExpanded := s.options.MaxExpandedBytes - s.expandedBytes
	if remainingExpanded < 0 {
		remainingExpanded = 0
	}
	if remainingExpanded < budget.limit {
		budget = gzipDecodeBudget{
			limit:  remainingExpanded,
			detail: fmt.Sprintf("inspection expanded-byte limit %d reached while decoding gzip; contents not inspected", s.options.MaxExpandedBytes),
		}
	}
	return budget
}

func (s *scanner) markGzipPartial(parentID, logical, detail string) {
	s.markNodePartial(parentID, detail)
	s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
}

func gzipPayloadName(logical string) string {
	base := logicalBase(logical)
	lower := strings.ToLower(base)
	var name string
	switch {
	case strings.HasSuffix(lower, ".tar.gz"):
		name = base[:len(base)-len(".gz")]
	case strings.HasSuffix(lower, ".tgz"):
		name = base[:len(base)-len(".tgz")] + ".tar"
	case strings.HasSuffix(lower, ".crate"):
		name = base[:len(base)-len(".crate")] + ".tar"
	case strings.HasSuffix(lower, ".gz"):
		name = base[:len(base)-len(".gz")]
	default:
		name = base + ".decompressed"
	}
	if name == "" || name == ".tar" {
		return "payload"
	}
	return name
}
