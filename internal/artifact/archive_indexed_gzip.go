package artifact

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	indexedGzipBundleHeaderSize = 6
	indexedGzipRecordHeaderSize = 17
	maxIndexedGzipBundleMembers = 16
)

type indexedGzipBundleMember struct {
	index          int
	tag            byte
	declaredSize   uint64
	compressedSize uint64
	compressed     []byte
}

func isIndexedGzipBundle(data []byte) bool {
	_, err := parseIndexedGzipBundle(data)
	return err == nil
}

// parseIndexedGzipBundle recognizes a generic six-byte envelope followed by
// one or more tagged, little-endian length records and independent gzip
// streams. The first five envelope bytes and each record tag are opaque: no
// producer, version, platform, architecture, or execution meaning is inferred
// from them. Exact payload type is determined from decoded bytes later.
//
// Requiring the records to consume the complete carrier makes this a bounded
// structural adapter, rather than an embedded-signature carver.
func parseIndexedGzipBundle(data []byte) ([]indexedGzipBundleMember, error) {
	if len(data) < indexedGzipBundleHeaderSize {
		return nil, fmt.Errorf("indexed gzip bundle header is truncated")
	}
	count := int(data[5])
	if count == 0 {
		return nil, fmt.Errorf("indexed gzip bundle declared no members")
	}
	if count > maxIndexedGzipBundleMembers {
		return nil, fmt.Errorf("indexed gzip member count %d exceeds limit %d", count, maxIndexedGzipBundleMembers)
	}

	members := make([]indexedGzipBundleMember, 0, count)
	offset := indexedGzipBundleHeaderSize
	for index := 0; index < count; index++ {
		if offset > len(data)-indexedGzipRecordHeaderSize {
			return nil, fmt.Errorf("indexed gzip member %d header is truncated", index)
		}
		declaredSize := binary.LittleEndian.Uint64(data[offset+1 : offset+9])
		compressedSize := binary.LittleEndian.Uint64(data[offset+9 : offset+17])
		compressedOffset := offset + indexedGzipRecordHeaderSize
		if compressedSize == 0 || compressedSize > uint64(len(data)-compressedOffset) {
			return nil, fmt.Errorf("indexed gzip member %d compressed extent is invalid", index)
		}
		compressedEnd := compressedOffset + int(compressedSize)
		compressed := data[compressedOffset:compressedEnd]
		if len(compressed) < 2 || compressed[0] != 0x1f || compressed[1] != 0x8b {
			return nil, fmt.Errorf("indexed gzip member %d is not a gzip stream", index)
		}
		members = append(members, indexedGzipBundleMember{
			index:          index,
			tag:            data[offset],
			declaredSize:   declaredSize,
			compressedSize: compressedSize,
			compressed:     compressed,
		})
		offset = compressedEnd
	}
	if offset != len(data) {
		return nil, fmt.Errorf("indexed gzip bundle has %d trailing bytes", len(data)-offset)
	}
	return members, nil
}

func (s *scanner) scanIndexedGzipBundle(parentID, logical string, data []byte, depth int) {
	members, err := parseIndexedGzipBundle(data)
	if err != nil {
		s.markIndexedGzipBundlePartial(parentID, logical, fmt.Sprintf("indexed gzip structure validation failed: %v; members not inspected", err))
		return
	}
	s.setContainerEntryCounts(parentID, len(members), 0)

	entries := make([]VirtualEntry, 0, len(members))
	var attemptedOutputBytes int64
	var decodeWorkBytes int64
	var decodedBytes int64
	for _, member := range members {
		entry := VirtualEntry{
			Name:           fmt.Sprintf("member-%03d-tag-%03d", member.index, member.tag),
			Size:           uint64ToInt64(member.declaredSize),
			CompressedSize: uint64ToInt64(member.compressedSize),
			Provenance:     "indexed-gzip-member",
			SourceRole:     "packaged-content",
		}
		detail := ""
		switch {
		case member.declaredSize > uint64(^uint64(0)>>1):
			detail = "indexed gzip member declared size cannot be represented"
		case uint64ExceedsInt64Limit(member.declaredSize, s.options.MaxFileBytes):
			detail = fmt.Sprintf("indexed gzip member exceeds max file bytes %d", s.options.MaxFileBytes)
		case s.compressionRatioExceeded(member.declaredSize, member.compressedSize):
			detail = fmt.Sprintf("indexed gzip member exceeds compression ratio limit %d", s.options.MaxCompressionRatio)
		case archiveBudgetExceeded(attemptedOutputBytes, member.declaredSize, s.options.MaxArchiveBytes):
			detail = fmt.Sprintf("indexed gzip decoded-output byte limit %d reached", s.options.MaxArchiveBytes)
		case archiveBudgetExceeded(decodeWorkBytes, member.compressedSize, s.options.MaxArchiveBytes):
			detail = fmt.Sprintf("indexed gzip decode-work byte limit %d reached", s.options.MaxArchiveBytes)
		case archiveBudgetExceeded(s.expandedBytes+decodedBytes, member.declaredSize, s.options.MaxExpandedBytes):
			detail = fmt.Sprintf("inspection expanded-byte limit %d reached while decoding indexed gzip bundle", s.options.MaxExpandedBytes)
		case archiveBudgetExceeded(s.retainedBytes+decodedBytes, member.declaredSize, s.options.MaxTotalBytes):
			detail = fmt.Sprintf("inspection retained-byte limit %d reached while decoding indexed gzip bundle", s.options.MaxTotalBytes)
		}
		if detail != "" {
			s.markIndexedGzipBundlePartial(parentID, logical, fmt.Sprintf("member %d: %s; contents not inspected", member.index, detail))
			entries = append(entries, entry.withSkipDetail(detail))
			continue
		}

		attemptedOutputBytes += int64(member.declaredSize)
		decodeWorkBytes += int64(member.compressedSize)
		entry.Data, err = decodeIndexedGzipMember(member.compressed, int64(member.declaredSize))
		if err != nil {
			detail = fmt.Sprintf("indexed gzip member validation failed: %v", err)
			s.markIndexedGzipBundlePartial(parentID, logical, fmt.Sprintf("member %d: %s; contents not inspected", member.index, detail))
			entries = append(entries, entry.withSkipDetail(detail))
			continue
		}
		decodedBytes += int64(len(entry.Data))
		entries = append(entries, entry)
	}

	s.addVirtualEntries(parentID, logical, entries, depth)
	s.setContainerEntryCounts(parentID, len(members), s.directChildCount(parentID))
}

func decodeIndexedGzipMember(compressed []byte, declaredSize int64) ([]byte, error) {
	input := bytes.NewReader(compressed)
	reader, err := gzip.NewReader(input)
	if err != nil {
		return nil, err
	}
	reader.Multistream(false)
	decoded, readErr := readAllLimited(reader, declaredSize)
	closeErr := reader.Close()
	if readErr != nil {
		var limitErr *byteLimitError
		if errors.As(readErr, &limitErr) {
			return nil, fmt.Errorf("decoded data exceeds declared size %d", declaredSize)
		}
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if input.Len() != 0 {
		return nil, fmt.Errorf("concatenated or trailing gzip data")
	}
	if int64(len(decoded)) != declaredSize {
		return nil, fmt.Errorf("decoded size %d differs from declared size %d", len(decoded), declaredSize)
	}
	return decoded, nil
}

func (s *scanner) markIndexedGzipBundlePartial(parentID, logical, detail string) {
	s.markNodePartial(parentID, detail)
	s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
}

func (s *scanner) setContainerEntryCounts(nodeID string, declared, modeled int) {
	for index := range s.graph.Nodes {
		if s.graph.Nodes[index].ID != nodeID {
			continue
		}
		s.graph.Nodes[index].DeclaredEntryCount = intPointer(declared)
		s.graph.Nodes[index].ModeledEntryCount = intPointer(modeled)
		return
	}
}

func (s *scanner) directChildCount(parentID string) int {
	count := 0
	for _, node := range s.graph.Nodes {
		if node.ParentID == parentID {
			count++
		}
	}
	return count
}

func intPointer(value int) *int {
	return &value
}
