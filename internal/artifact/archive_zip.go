package artifact

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var errWrongZipPassword = errors.New("wrong zip password")

const (
	zipDirectoryHeaderSignature    = 0x02014b50
	zipDirectoryEndSignature       = 0x06054b50
	zipDirectory64EndSignature     = 0x06064b50
	zipDirectory64LocatorSignature = 0x07064b50
	zipDirectoryHeaderLength       = 46
	zipDirectoryEndLength          = 22
	zipDirectory64EndLength        = 56
	zipDirectory64LocatorLength    = 20
	maxZIPCentralDirectoryBytes    = 32 << 20
	// ZIP metadata can legitimately describe more entries than Maratus will
	// retain. Bound central-directory validation separately from the lower
	// per-archive processing ceiling so a large archive yields a partial,
	// evidence-bearing report instead of an all-or-nothing structure-validation failure.
	maxZIPCentralDirectoryRecords = 65536
	// Each candidate can trigger bounded central-directory validation. Cap the
	// number attempted so a prefix or comment full of EOCD signatures cannot
	// amplify structure-validation work. Hitting the cap fails closed.
	maxZIPEarlierEOCDCandidates = 64

	wheelNativeInspectionRank = 3
)

func (s *scanner) scanZip(parentID, logical string, data []byte, depth int) {
	kind := archiveKind(strings.ToLower(filepath.Ext(logical)))
	s.scanZipKind(parentID, logical, data, kind, depth)
}

func (s *scanner) scanZipKind(parentID, logical string, data []byte, kind string, depth int) {
	if err := preflightZIPDirectory(data); err != nil {
		detail := fmt.Sprintf("ZIP structure validation failed: %v", err)
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
		s.markNodePartial(parentID, detail)
		return
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		detail := fmt.Sprintf("zip parse failed: %v", err)
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
		s.markNodePartial(parentID, detail)
		return
	}
	var entries []VirtualEntry
	var readBytes int64
	var decodeWorkBytes int64
	var attemptedOutputBytes int64
	for processed, index := range zipInspectionOrder(reader.File, kind) {
		if processed >= MaxArchiveEntries {
			detail := fmt.Sprintf("archive entry processing limit %d reached; remaining entries were not inspected", MaxArchiveEntries)
			s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
			s.markNodePartial(parentID, detail)
			break
		}
		file := reader.File[index]
		name, ok := cleanArchiveName(file.Name)
		if !ok {
			detail := rejectedArchivePathDiagnostic(logical, file.Name)
			s.addDiagnostic(detail)
			s.markNodePartial(parentID, "one or more ZIP entries had unsafe paths and were not inspected")
			continue
		}
		if _, ok := archiveLogicalPath(logical, name); !ok {
			detail := fmt.Sprintf("rejected archive logical path over %d bytes", MaxArchiveLogicalPathBytes)
			s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
			s.markNodePartial(parentID, detail)
			continue
		}
		mode := file.FileInfo().Mode()
		entry := VirtualEntry{
			Name:           name,
			Directory:      file.FileInfo().IsDir(),
			Symlink:        mode&os.ModeSymlink != 0,
			Executable:     fileModeExecutable(mode),
			Size:           uint64ToInt64(file.UncompressedSize64),
			CompressedSize: uint64ToInt64(file.CompressedSize64),
			Provenance:     "zip-entry",
		}
		if entry.Directory || entry.Symlink {
			entries = append(entries, entry)
			continue
		}
		if file.Flags&0x1 != 0 {
			if s.options.ZipPassword == "" {
				detail := "encrypted zip entry not inspected"
				s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
				s.markNodePartial(parentID, detail)
				entries = append(entries, entry.withSkipDetail(detail))
				continue
			}
			if !supportedZIPMethod(file.Method) {
				detail := fmt.Sprintf("encrypted zip entry uses unsupported method %d", file.Method)
				s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
				s.markNodePartial(parentID, detail)
				entries = append(entries, entry.withSkipDetail(detail))
				continue
			}
			if uint64ExceedsInt64Limit(file.CompressedSize64, s.options.MaxFileBytes) {
				detail := fmt.Sprintf("encrypted zip input exceeds %d bytes", s.options.MaxFileBytes)
				s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
				s.markNodePartial(parentID, detail)
				entries = append(entries, entry.withSkipDetail(detail))
				continue
			}
		}
		if !supportedZIPMethod(file.Method) {
			detail := fmt.Sprintf("zip entry uses unsupported compression method %d", file.Method)
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			s.markNodePartial(parentID, detail)
			entries = append(entries, entry.withSkipDetail(detail))
			continue
		}
		if s.compressionRatioExceeded(file.UncompressedSize64, file.CompressedSize64) {
			detail := fmt.Sprintf("skipped entry over compression ratio limit %d", s.options.MaxCompressionRatio)
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			s.markNodePartial(parentID, detail)
			entries = append(entries, entry.withSkipDetail(detail))
			continue
		}
		if uint64ExceedsInt64Limit(file.UncompressedSize64, s.options.MaxFileBytes) {
			detail := fmt.Sprintf("skipped entry over max file bytes %d", s.options.MaxFileBytes)
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			s.markNodePartial(parentID, detail)
			entries = append(entries, entry.withSkipDetail(detail))
			continue
		}
		if archiveBudgetExceeded(readBytes, file.UncompressedSize64, s.options.MaxArchiveBytes) {
			detail := fmt.Sprintf("archive content byte limit %d reached; entry skipped because it would exceed remaining budget", s.options.MaxArchiveBytes)
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			entries = append(entries, entry.withSkipDetail(detail))
			s.markNodePartial(parentID, detail)
			continue
		}
		if archiveBudgetExceeded(s.expandedBytes+readBytes, file.UncompressedSize64, s.options.MaxExpandedBytes) {
			detail := fmt.Sprintf("inspection expanded-byte limit %d reached; entry skipped because it would exceed remaining budget", s.options.MaxExpandedBytes)
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			entries = append(entries, entry.withSkipDetail(detail))
			s.markNodePartial(parentID, detail)
			continue
		}
		if archiveBudgetExceeded(attemptedOutputBytes, file.UncompressedSize64, s.options.MaxArchiveBytes) {
			detail := fmt.Sprintf("archive attempted decoded-output byte limit %d reached; entry skipped because it would exceed remaining budget", s.options.MaxArchiveBytes)
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			entries = append(entries, entry.withSkipDetail(detail))
			s.markNodePartial(parentID, detail)
			continue
		}
		if archiveBudgetExceeded(decodeWorkBytes, file.CompressedSize64, s.options.MaxArchiveBytes) {
			detail := fmt.Sprintf("archive decode-work byte limit %d reached; entry skipped because it would exceed remaining budget", s.options.MaxArchiveBytes)
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			entries = append(entries, entry.withSkipDetail(detail))
			s.markNodePartial(parentID, detail)
			continue
		}
		attemptedOutputBytes += uint64ToInt64(file.UncompressedSize64)
		decodeWorkBytes += uint64ToInt64(file.CompressedSize64)
		outputLimit := uint64ToInt64(file.UncompressedSize64)
		if file.Flags&0x1 != 0 {
			entry.Data, err = readClassicEncryptedZipEntry(file, data, s.options.ZipPassword, s.options.MaxFileBytes, outputLimit)
		} else {
			entry.Data, err = readPlainZipEntry(file, outputLimit)
		}
		if err != nil {
			detail := zipReadErrorDetail(err)
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			s.markNodePartial(parentID, detail)
			entries = append(entries, entry.withSkipDetail(detail))
			continue
		}
		readBytes += int64(len(entry.Data))
		entries = append(entries, entry)
	}
	markBundledGoDistributionRoles(entries)
	s.addVirtualEntries(parentID, logical, entries, depth)
}

// Wheels commonly place large native extensions or generated datasets before
// the package initialization and installation records that define how Python
// can select code. Inspecting only central-directory order lets those bulky
// members exhaust a bounded analysis before the execution-relevant structure
// is reached. This ordering affects inspection priority only: it does not infer
// execution, promote an entry to a root, or apply to an ordinary ZIP.
func zipInspectionOrder(files []*zip.File, kind string) []int {
	order := make([]int, len(files))
	for index := range files {
		order[index] = index
	}
	if kind != "python-wheel" {
		return order
	}
	sort.SliceStable(order, func(i, j int) bool {
		leftIndex, rightIndex := order[i], order[j]
		leftRank, leftDepth := wheelEntryInspectionPriority(files[leftIndex].Name)
		rightRank, rightDepth := wheelEntryInspectionPriority(files[rightIndex].Name)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		// Preserve declared member order among equivalent native variants.
		// Their size does not predict semantic value, and choosing the smallest
		// variant can systematically select a fallback that exposes fewer exact
		// operations. An over-budget member is skipped without consuming bytes,
		// so a later smaller variant remains eligible.
		if leftRank == wheelNativeInspectionRank {
			return leftIndex < rightIndex
		}
		if files[leftIndex].UncompressedSize64 != files[rightIndex].UncompressedSize64 {
			return files[leftIndex].UncompressedSize64 < files[rightIndex].UncompressedSize64
		}
		return leftIndex < rightIndex
	})
	return order
}

func wheelEntryInspectionPriority(name string) (rank, depth int) {
	cleaned, ok := cleanArchiveName(name)
	if !ok {
		return 5, strings.Count(filepath.ToSlash(name), "/")
	}
	lower := strings.ToLower(filepath.ToSlash(cleaned))
	depth = strings.Count(lower, "/")
	base := filepath.Base(lower)

	// Metadata precedes executable members so a wheel containing many candidate
	// startup files cannot starve the records required to validate their install
	// identity. Prioritization is not itself evidence that installation or any
	// activation condition occurred.
	if strings.Contains(lower, ".dist-info/") {
		switch base {
		case "wheel", "metadata", "entry_points.txt", "record":
			return 0, depth
		}
	}
	if depth == 0 && (strings.HasSuffix(base, ".pth") || base == "sitecustomize.py" || base == "usercustomize.py") {
		return 1, depth
	}
	if base == "__init__.py" {
		return 2, depth
	}

	ext := strings.ToLower(filepath.Ext(base))
	switch ext {
	case ".so", ".dylib", ".bundle", ".a":
		// A wheel may be predominantly native code. Keep a native lane ahead
		// of ordinary source so activation-focused traversal does not erase
		// representative Mach-O analysis under the shared byte budget. Entries
		// that do not fit are skipped individually, allowing later shallow
		// source to remain eligible.
		return wheelNativeInspectionRank, depth
	case ".py", ".pyw", ".js", ".mjs", ".cjs", ".sh", ".zsh", ".bash", ".command", ".applescript", ".scpt":
		return 4, depth
	case ".json", ".toml", ".yaml", ".yml", ".plist", ".xml", ".cfg", ".ini":
		return 5, depth
	default:
		return 6, depth
	}
}

// Some payloads bundle an entire Go SDK beside a small malicious app or
// launcher. Preserve the SDK in the artifact inventory, but give its owned
// subtrees a toolchain role hint. These paths do not authenticate SDK content:
// explicit declarations, shallow runnable entrypoints, and an explicit
// include-unreferenced scan must still override default noise suppression.
func markBundledGoDistributionRoles(entries []VirtualEntry) {
	hasGo := false
	hasCompiler := false
	for _, entry := range entries {
		name := strings.ToLower(filepath.ToSlash(entry.Name))
		switch name {
		case "bin/go":
			hasGo = true
		case "pkg/tool/darwin_arm64/compile", "pkg/tool/darwin_amd64/compile":
			hasCompiler = true
		}
	}
	if !hasGo || !hasCompiler {
		return
	}
	for index := range entries {
		name := strings.Trim(strings.ToLower(filepath.ToSlash(entries[index].Name)), "/")
		first := name
		if separator := strings.IndexByte(first, '/'); separator >= 0 {
			first = first[:separator]
		}
		switch first {
		case "api", "bin", "doc", "lib", "misc", "pkg", "src", "test":
			entries[index].SourceRole = "vendor/toolchain"
		}
	}
}

func preflightZIPDirectory(data []byte) error {
	eocdOffset, ok := findZIPEndOfCentralDirectory(data)
	if !ok {
		return fmt.Errorf("end of central directory not found")
	}
	selected, err := validateZIPDirectoryAt(data, eocdOffset)
	if err != nil {
		return err
	}
	// archive/zip selects the last EOCD record. Without this check, an attacker
	// can append a second valid ZIP and make an earlier payload invisible. Keep
	// the raw archive base: archive/zip's absolute-directory compatibility path
	// may reset the effective base to zero when crafted prefix bytes happen to
	// resemble a central header.
	checked := make(map[int]struct{})
	candidates := 0
	scanEarlier := func(start, end int) error {
		if start < 0 {
			start = 0
		}
		if end > eocdOffset {
			end = eocdOffset
		}
		for offset := end - 1; offset >= start; offset-- {
			if offset+zipDirectoryEndLength > len(data) || binary.LittleEndian.Uint32(data[offset:offset+4]) != zipDirectoryEndSignature {
				continue
			}
			if _, seen := checked[offset]; seen {
				continue
			}
			checked[offset] = struct{}{}
			candidates++
			if candidates > maxZIPEarlierEOCDCandidates {
				return fmt.Errorf("ZIP EOCD candidate validation limit %d exceeded", maxZIPEarlierEOCDCandidates)
			}
			commentLength := int(binary.LittleEndian.Uint16(data[offset+20 : offset+22]))
			if offset+zipDirectoryEndLength+commentLength > len(data) {
				continue
			}
			previous, err := validateZIPDirectoryAt(data, offset)
			if err != nil {
				continue
			}
			if int64(offset) < selected.rawBaseOffset || previous.rawBaseOffset <= selected.rawBaseOffset || (selected.records == 0 && selected.directorySize == 0) {
				return fmt.Errorf("ambiguous ZIP contains multiple valid end-of-central-directory records")
			}
		}
		return nil
	}
	// Search the complete self-extracting prefix before the raw archive base.
	// This catches a valid earlier archive even when arbitrary padding or a
	// trailing archive larger than the normal 65 KiB EOCD window separates it
	// from the selected EOCD.
	if selected.rawBaseOffset > 0 {
		if err := scanEarlier(0, int(selected.rawBaseOffset)); err != nil {
			return err
		}
	}
	// Separately inspect the selected archive's normal EOCD search window. This
	// catches appended fake records while allowing a stored nested ZIP whose
	// base lies after the selected outer archive base.
	windowStart := eocdOffset - (65<<10 + 2*zipDirectoryEndLength)
	if err := scanEarlier(windowStart, eocdOffset); err != nil {
		return err
	}
	return nil
}

type zipDirectoryDescriptor struct {
	rawBaseOffset int64
	records       uint64
	directorySize uint64
}

func validateZIPDirectoryAt(data []byte, eocdOffset int) (zipDirectoryDescriptor, error) {
	invalid := func(err error) (zipDirectoryDescriptor, error) {
		return zipDirectoryDescriptor{}, err
	}
	eocd := data[eocdOffset:]
	disk := uint32(binary.LittleEndian.Uint16(eocd[4:6]))
	directoryDisk := uint32(binary.LittleEndian.Uint16(eocd[6:8]))
	recordsOnDisk := uint64(binary.LittleEndian.Uint16(eocd[8:10]))
	records := uint64(binary.LittleEndian.Uint16(eocd[10:12]))
	directorySize := uint64(binary.LittleEndian.Uint32(eocd[12:16]))
	directoryOffset := uint64(binary.LittleEndian.Uint32(eocd[16:20]))
	directoryEndOffset := int64(eocdOffset)
	zip64 := records == 0xffff || recordsOnDisk == 0xffff || directorySize == 0xffffffff || directoryOffset == 0xffffffff
	if zip64 {
		if eocdOffset < zipDirectory64LocatorLength {
			return invalid(fmt.Errorf("ZIP64 locator missing"))
		}
		locator := data[eocdOffset-zipDirectory64LocatorLength : eocdOffset]
		if binary.LittleEndian.Uint32(locator[:4]) != zipDirectory64LocatorSignature {
			return invalid(fmt.Errorf("ZIP64 locator missing"))
		}
		if binary.LittleEndian.Uint32(locator[4:8]) != 0 || binary.LittleEndian.Uint32(locator[16:20]) != 1 {
			return invalid(fmt.Errorf("multi-disk ZIP64 archives are unsupported"))
		}
		zip64Offset := binary.LittleEndian.Uint64(locator[8:16])
		if zip64Offset > uint64(len(data)) || uint64(len(data))-zip64Offset < zipDirectory64EndLength {
			return invalid(fmt.Errorf("ZIP64 end of central directory bounds invalid"))
		}
		zip64End := data[zip64Offset : zip64Offset+zipDirectory64EndLength]
		if binary.LittleEndian.Uint32(zip64End[:4]) != zipDirectory64EndSignature {
			return invalid(fmt.Errorf("ZIP64 end of central directory missing"))
		}
		if binary.LittleEndian.Uint64(zip64End[4:12]) < 44 {
			return invalid(fmt.Errorf("ZIP64 end of central directory is too short"))
		}
		disk = binary.LittleEndian.Uint32(zip64End[16:20])
		directoryDisk = binary.LittleEndian.Uint32(zip64End[20:24])
		recordsOnDisk = binary.LittleEndian.Uint64(zip64End[24:32])
		records = binary.LittleEndian.Uint64(zip64End[32:40])
		directorySize = binary.LittleEndian.Uint64(zip64End[40:48])
		directoryOffset = binary.LittleEndian.Uint64(zip64End[48:56])
		directoryEndOffset = uint64ToInt64(zip64Offset)
	}
	if disk != 0 || directoryDisk != 0 || recordsOnDisk != records {
		return invalid(fmt.Errorf("multi-disk ZIP archives are unsupported"))
	}
	if records > maxZIPCentralDirectoryRecords {
		return invalid(fmt.Errorf("central directory record safety limit %d exceeded by declared count %d", maxZIPCentralDirectoryRecords, records))
	}
	if directorySize > maxZIPCentralDirectoryBytes {
		return invalid(fmt.Errorf("central directory exceeds maximum size %d", maxZIPCentralDirectoryBytes))
	}
	if directorySize > uint64(1<<63-1) || directoryOffset > uint64(1<<63-1) {
		return invalid(fmt.Errorf("central directory bounds invalid"))
	}
	rawBaseOffset := directoryEndOffset - int64(directorySize) - int64(directoryOffset)
	if rawBaseOffset < 0 {
		return invalid(fmt.Errorf("central directory bounds invalid"))
	}
	baseOffset := rawBaseOffset
	start := baseOffset + int64(directoryOffset)
	if baseOffset > 0 && directoryOffset <= uint64(len(data)-4) {
		absolute := int64(directoryOffset)
		if absolute >= 0 && absolute+4 <= int64(len(data)) && binary.LittleEndian.Uint32(data[absolute:absolute+4]) == zipDirectoryHeaderSignature {
			start = absolute
		}
	}
	if start < 0 || start > directoryEndOffset || int64(directorySize) > directoryEndOffset-start {
		return invalid(fmt.Errorf("central directory bounds invalid"))
	}
	scanEnd := directoryEndOffset
	position := start
	actualRecords := uint64(0)
	for position+4 <= scanEnd && binary.LittleEndian.Uint32(data[position:position+4]) == zipDirectoryHeaderSignature {
		if actualRecords >= maxZIPCentralDirectoryRecords {
			return invalid(fmt.Errorf("central directory record safety limit %d exceeded", maxZIPCentralDirectoryRecords))
		}
		if scanEnd-position < zipDirectoryHeaderLength {
			return invalid(fmt.Errorf("truncated central directory header"))
		}
		header := data[position : position+zipDirectoryHeaderLength]
		nameLength := int64(binary.LittleEndian.Uint16(header[28:30]))
		extraLength := int64(binary.LittleEndian.Uint16(header[30:32]))
		commentLength := int64(binary.LittleEndian.Uint16(header[32:34]))
		recordLength := int64(zipDirectoryHeaderLength) + nameLength + extraLength + commentLength
		if recordLength > scanEnd-position {
			return invalid(fmt.Errorf("truncated central directory record"))
		}
		if recordLength > maxZIPCentralDirectoryBytes-(position-start) {
			return invalid(fmt.Errorf("central directory exceeds maximum size %d", maxZIPCentralDirectoryBytes))
		}
		actualRecords++
		position += recordLength
	}
	if actualRecords != records {
		return invalid(fmt.Errorf("central directory record count %d does not match declared count %d", actualRecords, records))
	}
	return zipDirectoryDescriptor{rawBaseOffset: rawBaseOffset, records: records, directorySize: directorySize}, nil
}

func findZIPEndOfCentralDirectory(data []byte) (int, bool) {
	if len(data) < zipDirectoryEndLength {
		return 0, false
	}
	start := len(data) - (65<<10 + zipDirectoryEndLength)
	if start < 0 {
		start = 0
	}
	for offset := len(data) - zipDirectoryEndLength; offset >= start; offset-- {
		if binary.LittleEndian.Uint32(data[offset:offset+4]) != zipDirectoryEndSignature {
			continue
		}
		commentLength := int(binary.LittleEndian.Uint16(data[offset+20 : offset+22]))
		if offset+zipDirectoryEndLength+commentLength == len(data) {
			return offset, true
		}
	}
	return 0, false
}

func supportedZIPMethod(method uint16) bool {
	return method == zip.Store || method == zip.Deflate
}

func readPlainZipEntry(file *zip.File, maxFileBytes int64) ([]byte, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("open failed: %w", err)
	}
	data, readErr := readAllLimited(rc, maxFileBytes)
	closeErr := rc.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read failed: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close failed: %w", closeErr)
	}
	return data, nil
}

func readClassicEncryptedZipEntry(file *zip.File, archive []byte, password string, maxInputBytes, maxOutputBytes int64) ([]byte, error) {
	offset, err := file.DataOffset()
	if err != nil {
		return nil, fmt.Errorf("encrypted data offset failed: %w", err)
	}
	if uint64ExceedsInt64Limit(file.CompressedSize64, maxInputBytes) {
		return nil, fmt.Errorf("encrypted zip input exceeds %d bytes", maxInputBytes)
	}
	size := uint64ToInt64(file.CompressedSize64)
	archiveSize := int64(len(archive))
	if size < zipCryptoHeaderSize || offset < 0 || offset > archiveSize || size > archiveSize-offset {
		return nil, fmt.Errorf("encrypted data bounds invalid")
	}
	decrypted := &zipCryptoReader{
		reader: io.NewSectionReader(bytes.NewReader(archive), offset, size),
		keys:   newZipCryptoKeys([]byte(password)),
	}
	header := make([]byte, zipCryptoHeaderSize)
	if _, err := io.ReadFull(decrypted, header); err != nil {
		return nil, fmt.Errorf("encrypted zip header read failed: %w", err)
	}
	if !zipCryptoHeaderMatches(file, header[zipCryptoHeaderSize-1]) {
		return nil, errWrongZipPassword
	}
	var reader io.ReadCloser
	switch file.Method {
	case zip.Store:
		reader = io.NopCloser(decrypted)
	case zip.Deflate:
		reader = flate.NewReader(decrypted)
	default:
		return nil, fmt.Errorf("unsupported encrypted zip method %d", file.Method)
	}
	data, readErr := readAllLimited(reader, maxOutputBytes)
	closeErr := reader.Close()
	if readErr != nil {
		var limitErr *byteLimitError
		if errors.As(readErr, &limitErr) {
			return nil, readErr
		}
		return nil, errWrongZipPassword
	}
	if closeErr != nil {
		return nil, errWrongZipPassword
	}
	if uint64(len(data)) != file.UncompressedSize64 {
		return nil, errWrongZipPassword
	}
	if crc32.ChecksumIEEE(data) != file.CRC32 {
		return nil, errWrongZipPassword
	}
	return data, nil
}

func zipReadErrorDetail(err error) string {
	if errors.Is(err, errWrongZipPassword) {
		return "wrong zip password"
	}
	return err.Error()
}

func zipCryptoHeaderMatches(file *zip.File, got byte) bool {
	return got == byte(file.CRC32>>24) || got == byte(file.ModifiedTime>>8)
}

const zipCryptoHeaderSize = 12

var zipCryptoTable = crc32.MakeTable(crc32.IEEE)

type zipCryptoKeys struct {
	k0 uint32
	k1 uint32
	k2 uint32
}

func newZipCryptoKeys(password []byte) zipCryptoKeys {
	keys := zipCryptoKeys{k0: 0x12345678, k1: 0x23456789, k2: 0x34567890}
	for _, b := range password {
		keys.update(b)
	}
	return keys
}

type zipCryptoReader struct {
	reader io.Reader
	keys   zipCryptoKeys
}

func (r *zipCryptoReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	for i := 0; i < n; i++ {
		plain := p[i] ^ r.keys.byte()
		r.keys.update(plain)
		p[i] = plain
	}
	return n, err
}

func (k *zipCryptoKeys) update(b byte) {
	k.k0 = zipCryptoCRC32(k.k0, b)
	k.k1 += k.k0 & 0xff
	k.k1 = k.k1*134775813 + 1
	k.k2 = zipCryptoCRC32(k.k2, byte(k.k1>>24))
}

func (k zipCryptoKeys) byte() byte {
	temp := k.k2 | 2
	return byte((temp * (temp ^ 1)) >> 8)
}

func zipCryptoCRC32(crc uint32, b byte) uint32 {
	return zipCryptoTable[(crc^uint32(b))&0xff] ^ (crc >> 8)
}
