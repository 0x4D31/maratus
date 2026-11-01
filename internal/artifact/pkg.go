package artifact

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
)

type xarHeader struct {
	Magic               uint32
	Size                uint16
	Version             uint16
	TOCCompressedSize   uint64
	TOCUncompressedSize uint64
	ChecksumAlgorithm   uint32
}

const (
	maxXARTOCBytes = 4 << 20
	maxXARTOCDepth = 64
	// Real XAR records may include ownership, mode, timestamps, checksums, and
	// encoding metadata in addition to the data extents maratus consumes.
	maxXARTOCStructural  = MaxArchiveEntries*64 + 1024
	maxXARTOCScalarBytes = maxXARTOCBytes
)

type xarTOC struct {
	Files       []xarFile `xml:"toc>file"`
	DirectFiles []xarFile `xml:"file"`
}

type xarFile struct {
	ID       string    `xml:"id,attr"`
	Name     string    `xml:"name"`
	Type     string    `xml:"type,attr"`
	Data     *xarData  `xml:"data"`
	Children []xarFile `xml:"file"`
}

type xarData struct {
	Length   string       `xml:"length"`
	Offset   string       `xml:"offset"`
	Size     string       `xml:"size"`
	Encoding *xarEncoding `xml:"encoding"`
}

type xarEncoding struct {
	Style string `xml:"style,attr"`
}

func (s *scanner) scanPKG(parentID, logical string, data []byte, depth int) {
	remainingExpandedBytes := s.options.MaxExpandedBytes - s.expandedBytes
	if remainingExpandedBytes < 0 {
		remainingExpandedBytes = 0
	}
	files, diagnostics, err := parseXARWithBudget(data, s.options, remainingExpandedBytes)
	if err != nil {
		detail := fmt.Sprintf("pkg/xar parse failed: %v; contents not inspected", err)
		s.markNodePartial(parentID, detail)
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
		return
	}
	for _, diagnostic := range diagnostics {
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, diagnostic))
		if detail := xarLimitCoverageDetail(diagnostic, s.options); detail != "" {
			s.markNodePartial(parentID, detail)
		} else {
			s.markNodePartial(parentID, "one or more XAR entries were rejected or not fully inspected; see diagnostics")
		}
	}
	var entries []VirtualEntry
	for _, file := range files {
		if file.SkipDetail != "" {
			s.markNodePartial(parentID, file.SkipDetail)
		}
		entries = append(entries, VirtualEntry{
			Name:           file.Name,
			Data:           file.Data,
			Size:           file.Size,
			CompressedSize: file.CompressedSize,
			SkipDetail:     file.SkipDetail,
			Executable:     isPackageScriptName(file.Name),
			Relation:       packageEntryRelation(file.Name),
			Provenance:     "pkg-xar-entry",
		})
	}
	s.addVirtualEntries(parentID, logical, entries, depth)
}

func xarLimitCoverageDetail(diagnostic string, options Options) string {
	options = options.normalized()
	entryLimit := fmt.Sprintf("archive entry limit %d reached; remaining entries were not inspected", MaxArchiveEntries)
	if diagnostic == entryLimit {
		return entryLimit
	}
	limits := []struct {
		suffix string
		detail string
	}{
		{
			suffix: fmt.Sprintf(": skipped entry over max file bytes %d", options.MaxFileBytes),
			detail: fmt.Sprintf("one or more XAR entries exceeded max file bytes %d and were not inspected", options.MaxFileBytes),
		},
		{
			suffix: fmt.Sprintf(": skipped entry over archive content byte limit %d", options.MaxArchiveBytes),
			detail: fmt.Sprintf("one or more XAR entries exceeded archive content byte limit %d and were not inspected", options.MaxArchiveBytes),
		},
		{
			suffix: fmt.Sprintf(": skipped entry over inspection expanded-byte limit %d", options.MaxExpandedBytes),
			detail: fmt.Sprintf("one or more XAR entries exceeded inspection expanded-byte limit %d and were not inspected", options.MaxExpandedBytes),
		},
		{
			suffix: fmt.Sprintf(": skipped entry over compression ratio limit %d", options.MaxCompressionRatio),
			detail: fmt.Sprintf("one or more XAR entries exceeded compression ratio limit %d and were not inspected", options.MaxCompressionRatio),
		},
	}
	for _, limit := range limits {
		if strings.HasSuffix(diagnostic, limit.suffix) {
			return limit.detail
		}
	}
	return ""
}

func packageEntryRelation(name string) string {
	lower := strings.ToLower(filepath.ToSlash(name))
	base := filepath.Base(lower)
	switch {
	case base == "distribution" || base == "packageinfo":
		return "package-metadata"
	case base == "payload":
		return "package-payload"
	case base == "scripts" || isPackageScriptName(lower) || strings.HasPrefix(lower, "scripts/"):
		return "package-script"
	default:
		return "package-payload"
	}
}

func markPackageScriptArchiveEntries(logical string, entries []VirtualEntry) {
	if !isPackageScriptsArchive(logical) {
		return
	}
	for i := range entries {
		if isPackageScriptName(entries[i].Name) {
			entries[i].Executable = true
			entries[i].Relation = "package-script"
		}
	}
}

func isPackageScriptsArchive(logical string) bool {
	lower := strings.ToLower(filepath.ToSlash(logical))
	return strings.HasSuffix(lower, "!scripts") ||
		strings.HasSuffix(lower, "/scripts")
}

type xarExtractedFile struct {
	Name           string
	Data           []byte
	Size           int64
	CompressedSize int64
	SkipDetail     string
}

func parseXAR(data []byte, options Options) ([]xarExtractedFile, []string, error) {
	options = options.normalized()
	return parseXARWithBudget(data, options, options.MaxExpandedBytes)
}

func parseXARWithBudget(data []byte, options Options, remainingExpandedBytes int64) ([]xarExtractedFile, []string, error) {
	options = options.normalized()
	if remainingExpandedBytes < 0 {
		remainingExpandedBytes = 0
	}
	archiveLimit := options.MaxArchiveBytes
	archiveLimitDetail := fmt.Sprintf("over archive content byte limit %d", options.MaxArchiveBytes)
	if remainingExpandedBytes < archiveLimit {
		archiveLimit = remainingExpandedBytes
		archiveLimitDetail = fmt.Sprintf("over inspection expanded-byte limit %d", options.MaxExpandedBytes)
	}
	if len(data) < 28 || string(data[:4]) != "xar!" {
		return nil, nil, fmt.Errorf("missing xar magic")
	}
	header := xarHeader{
		Magic:               binary.BigEndian.Uint32(data[0:4]),
		Size:                binary.BigEndian.Uint16(data[4:6]),
		Version:             binary.BigEndian.Uint16(data[6:8]),
		TOCCompressedSize:   binary.BigEndian.Uint64(data[8:16]),
		TOCUncompressedSize: binary.BigEndian.Uint64(data[16:24]),
		ChecksumAlgorithm:   binary.BigEndian.Uint32(data[24:28]),
	}
	if header.Magic != 0x78617221 || header.Size < 28 {
		return nil, nil, fmt.Errorf("invalid xar header")
	}
	if int(header.Size) > len(data) {
		return nil, nil, fmt.Errorf("invalid xar header size")
	}
	if header.TOCUncompressedSize > maxXARTOCBytes {
		return nil, nil, fmt.Errorf("xar TOC exceeds maximum size %d", maxXARTOCBytes)
	}
	tocStart := int(header.Size)
	if header.TOCCompressedSize > uint64(len(data)-tocStart) {
		return nil, nil, fmt.Errorf("invalid xar TOC bounds")
	}
	tocEnd := tocStart + int(header.TOCCompressedSize)
	zr, err := zlib.NewReader(bytes.NewReader(data[tocStart:tocEnd]))
	if err != nil {
		return nil, nil, err
	}
	tocBytes, err := io.ReadAll(io.LimitReader(zr, int64(header.TOCUncompressedSize)+1))
	closeErr := zr.Close()
	if err != nil {
		return nil, nil, err
	}
	if closeErr != nil {
		return nil, nil, closeErr
	}
	if uint64(len(tocBytes)) > header.TOCUncompressedSize {
		return nil, nil, fmt.Errorf("xar TOC exceeds declared size")
	}
	if err := preflightXARTOC(tocBytes, options.MaxDirectoryDepth); err != nil {
		return nil, nil, err
	}
	var toc xarTOC
	if err := xml.Unmarshal(tocBytes, &toc); err != nil {
		return nil, nil, err
	}
	heapStart := tocEnd
	var out []xarExtractedFile
	var diagnostics []string
	var readBytes int64
	var decodeWorkBytes int64
	var attemptedOutputBytes int64
	entryCount := 0
	stop := false
	var walk func(prefix string, files []xarFile)
	walk = func(prefix string, files []xarFile) {
		if stop {
			return
		}
		for _, file := range files {
			if stop {
				return
			}
			if entryCount >= MaxArchiveEntries {
				diagnostics = append(diagnostics, fmt.Sprintf("archive entry limit %d reached; remaining entries were not inspected", MaxArchiveEntries))
				stop = true
				return
			}
			entryCount++
			name := strings.TrimSpace(file.Name)
			if name == "" {
				continue
			}
			if len(name) > MaxArchiveNameBytes || (prefix != "" && len(prefix)+1+len(name) > MaxArchiveNameBytes) {
				diagnostics = append(diagnostics, fmt.Sprintf("rejected archive entry name over %d bytes", MaxArchiveNameBytes))
				continue
			}
			path := name
			if prefix != "" {
				path = prefix + "/" + name
			}
			if len(file.Children) > 0 {
				walk(path, file.Children)
				if stop {
					return
				}
			}
			if file.Data == nil {
				continue
			}
			cleanPath, ok := cleanArchiveName(path)
			if !ok {
				diagnostics = append(diagnostics, rejectedArchivePathDiagnostic("", path))
				continue
			}
			offset, length, ok := xarDataBounds(*file.Data)
			if !ok {
				diagnostics = append(diagnostics, fmt.Sprintf("%s: skipped entry with invalid data bounds", cleanPath))
				continue
			}
			size, hasSize, validSize := xarDeclaredSize(*file.Data)
			if !validSize {
				diagnostics = append(diagnostics, fmt.Sprintf("%s: skipped entry with invalid declared size", cleanPath))
				continue
			}
			if hasSize && size > options.MaxFileBytes {
				diagnostics = append(diagnostics, fmt.Sprintf("%s: skipped entry over max file bytes %d", cleanPath, options.MaxFileBytes))
				continue
			}
			remaining := archiveLimit - readBytes
			if remaining < 0 {
				remaining = 0
			}
			if hasSize && size > remaining {
				diagnostics = append(diagnostics, fmt.Sprintf("%s: skipped entry %s", cleanPath, archiveLimitDetail))
				continue
			}
			available := int64(len(data) - heapStart)
			if offset > available || length > available-offset {
				diagnostics = append(diagnostics, fmt.Sprintf("%s: skipped entry outside xar heap bounds", cleanPath))
				continue
			}
			start := heapStart + int(offset)
			end := start + int(length)
			raw := data[start:end]
			if hasSize && compressionRatioExceeded(uint64(size), uint64(len(raw)), options.MaxCompressionRatio) {
				diagnostics = append(diagnostics, fmt.Sprintf("%s: skipped entry over compression ratio limit %d", cleanPath, options.MaxCompressionRatio))
				continue
			}
			decodeLimit := options.MaxFileBytes
			limitDetail := fmt.Sprintf("over max file bytes %d", options.MaxFileBytes)
			if remaining < decodeLimit {
				decodeLimit = remaining
				limitDetail = archiveLimitDetail
			}
			ratioLimit := xarCompressionByteLimit(int64(len(raw)), options.MaxCompressionRatio)
			if ratioLimit < decodeLimit {
				decodeLimit = ratioLimit
				limitDetail = fmt.Sprintf("over compression ratio limit %d", options.MaxCompressionRatio)
			}
			if hasSize && size <= decodeLimit {
				decodeLimit = size
				limitDetail = fmt.Sprintf("whose decoded size exceeds declared size %d", size)
			}
			if attemptedOutputBytes >= options.MaxArchiveBytes {
				detail := archiveDecodedOutputWorkLimitDetail(options.MaxArchiveBytes)
				diagnostics = append(diagnostics, fmt.Sprintf("%s: %s", cleanPath, detail))
				out = append(out, xarExtractedFile{
					Name:           cleanPath,
					Size:           size,
					CompressedSize: int64(len(raw)),
					SkipDetail:     detail,
				})
				stop = true
				return
			}
			if archiveBudgetExceeded(decodeWorkBytes, uint64(len(raw)), options.MaxArchiveBytes) {
				detail := fmt.Sprintf("archive decode-work byte limit %d reached; this and remaining entries were not decoded", options.MaxArchiveBytes)
				diagnostics = append(diagnostics, fmt.Sprintf("%s: %s", cleanPath, detail))
				out = append(out, xarExtractedFile{
					Name:           cleanPath,
					Size:           size,
					CompressedSize: int64(len(raw)),
					SkipDetail:     detail,
				})
				stop = true
				return
			}
			attemptOutputRemaining := options.MaxArchiveBytes - attemptedOutputBytes
			if attemptOutputRemaining < decodeLimit {
				decodeLimit = attemptOutputRemaining
			}
			decodeWorkBytes += int64(len(raw))
			decoded, decodedBytes, err := decodeXARData(raw, *file.Data, decodeLimit)
			if decodedBytes > attemptOutputRemaining {
				attemptedOutputBytes = options.MaxArchiveBytes
				detail := archiveDecodedOutputWorkLimitDetail(options.MaxArchiveBytes)
				diagnostics = append(diagnostics, fmt.Sprintf("%s: %s", cleanPath, detail))
				out = append(out, xarExtractedFile{
					Name:           cleanPath,
					Size:           size,
					CompressedSize: int64(len(raw)),
					SkipDetail:     detail,
				})
				stop = true
				return
			}
			attemptedOutputBytes += decodedBytes
			if err != nil {
				var limitErr *xarDecodeLimitError
				if errors.As(err, &limitErr) {
					diagnostics = append(diagnostics, fmt.Sprintf("%s: skipped entry %s", cleanPath, limitDetail))
				} else {
					diagnostics = append(diagnostics, fmt.Sprintf("%s: skipped entry with unsupported or malformed encoding: %v", cleanPath, err))
				}
				continue
			}
			if hasSize && int64(len(decoded)) != size {
				diagnostics = append(diagnostics, fmt.Sprintf("%s: skipped entry with decoded size %d; declared size is %d", cleanPath, len(decoded), size))
				continue
			}
			out = append(out, xarExtractedFile{Name: cleanPath, Data: decoded, CompressedSize: int64(len(raw))})
			readBytes += int64(len(decoded))
		}
	}
	files := toc.Files
	if len(files) == 0 {
		files = toc.DirectFiles
	}
	walk("", files)
	return out, diagnostics, nil
}

func preflightXARTOC(data []byte, maxFileDepth int) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	fileDepth := 0
	fileCount := 0
	structuralTokens := 0
	scalarBytes := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("invalid xar TOC XML: %w", err)
		}
		structuralTokens++
		if structuralTokens > maxXARTOCStructural {
			return fmt.Errorf("xar TOC exceeds structural token limit %d", maxXARTOCStructural)
		}
		switch value := token.(type) {
		case xml.StartElement:
			depth++
			if depth > maxXARTOCDepth {
				return fmt.Errorf("xar TOC exceeds XML depth limit %d", maxXARTOCDepth)
			}
			for _, attribute := range value.Attr {
				scalarBytes += len(attribute.Name.Space) + len(attribute.Name.Local) + len(attribute.Value)
				if scalarBytes > maxXARTOCScalarBytes {
					return fmt.Errorf("xar TOC exceeds scalar byte limit %d", maxXARTOCScalarBytes)
				}
			}
			if value.Name.Local == "file" {
				fileCount++
				if fileCount > MaxArchiveEntries {
					return fmt.Errorf("xar TOC exceeds archive entry limit %d", MaxArchiveEntries)
				}
				fileDepth++
				if maxFileDepth > 0 && fileDepth > maxFileDepth {
					return fmt.Errorf("xar TOC exceeds file nesting limit %d", maxFileDepth)
				}
			}
		case xml.EndElement:
			if value.Name.Local == "file" {
				fileDepth--
			}
			depth--
		case xml.CharData:
			scalarBytes += len(value)
			if scalarBytes > maxXARTOCScalarBytes {
				return fmt.Errorf("xar TOC exceeds scalar byte limit %d", maxXARTOCScalarBytes)
			}
		}
	}
}

func xarDataBounds(data xarData) (offset, length int64, ok bool) {
	offset, err := strconv.ParseInt(strings.TrimSpace(data.Offset), 10, 64)
	if err != nil {
		return 0, 0, false
	}
	lengthText := strings.TrimSpace(data.Length)
	if lengthText == "" {
		lengthText = strings.TrimSpace(data.Size)
	}
	length, err = strconv.ParseInt(lengthText, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return offset, length, offset >= 0 && length >= 0
}

func xarDeclaredSize(data xarData) (size int64, present, valid bool) {
	sizeText := strings.TrimSpace(data.Size)
	if sizeText == "" {
		return 0, false, true
	}
	size, err := strconv.ParseInt(sizeText, 10, 64)
	if err != nil || size < 0 {
		return 0, true, false
	}
	return size, true, true
}

func decodeXARData(data []byte, meta xarData, maxDecodedBytes int64) ([]byte, int64, error) {
	style := ""
	if meta.Encoding != nil {
		style = strings.ToLower(strings.TrimSpace(meta.Encoding.Style))
	}
	switch style {
	case "", "application/octet-stream", "application/x-octet-stream":
		return readXARDataLimited(bytes.NewReader(data), maxDecodedBytes)
	case "application/x-gzip", "application/gzip":
		return decodeXARGzip(data, maxDecodedBytes)
	case "application/x-bzip2", "application/bzip2":
		return readXARDataLimited(bzip2.NewReader(bytes.NewReader(data)), maxDecodedBytes)
	default:
		return nil, 0, fmt.Errorf("%s", style)
	}
}

func decodeXARGzip(data []byte, maxDecodedBytes int64) ([]byte, int64, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err == nil {
		decoded, decodedBytes, readErr := readXARDataLimited(gz, maxDecodedBytes)
		closeErr := gz.Close()
		if readErr != nil {
			return nil, decodedBytes, readErr
		}
		if closeErr != nil {
			return nil, decodedBytes, closeErr
		}
		return decoded, decodedBytes, nil
	}
	zr, zerr := zlib.NewReader(bytes.NewReader(data))
	if zerr != nil {
		return nil, 0, err
	}
	defer func() { _ = zr.Close() }()
	return readXARDataLimited(zr, maxDecodedBytes)
}

type xarDecodeLimitError struct {
	max int64
}

func (e *xarDecodeLimitError) Error() string {
	return fmt.Sprintf("entry exceeds %d bytes", e.max)
}

func readXARDataLimited(r io.Reader, max int64) ([]byte, int64, error) {
	if max < 0 {
		max = 0
	}
	readLimit := max
	if max < int64(1<<63-1) {
		readLimit++
	}
	var out bytes.Buffer
	if _, err := io.Copy(&out, io.LimitReader(r, readLimit)); err != nil {
		return nil, int64(out.Len()), err
	}
	if int64(out.Len()) > max {
		return nil, int64(out.Len()), &xarDecodeLimitError{max: max}
	}
	return out.Bytes(), int64(out.Len()), nil
}

func xarCompressionByteLimit(compressedBytes, ratio int64) int64 {
	if ratio <= 0 {
		return int64(1<<63 - 1)
	}
	if compressedBytes <= 0 {
		return 0
	}
	const maxInt64 = int64(1<<63 - 1)
	if compressedBytes > maxInt64/ratio {
		return maxInt64
	}
	return compressedBytes * ratio
}

func isPackageScriptName(name string) bool {
	base := strings.ToLower(name)
	return strings.HasSuffix(base, "/preinstall") ||
		strings.HasSuffix(base, "/postinstall") ||
		base == "preinstall" ||
		base == "postinstall"
}
