package artifact

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const (
	cpioNewcHeaderSize = 110
	cpioOdcHeaderSize  = 76
)

func (s *scanner) scanCPIO(parentID, logical string, data []byte, depth int) {
	entries, diagnostics, err := parseCPIO(data, s.options)
	if err != nil {
		detail := fmt.Sprintf("cpio parse failed: %v; contents not fully inspected", err)
		s.markNodePartial(parentID, detail)
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
		return
	}
	for _, diagnostic := range diagnostics {
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, diagnostic))
		s.markCPIOPartialCoverage(parentID, diagnostic)
	}
	for _, entry := range entries {
		if entry.SkipDetail == fmt.Sprintf("skipped entry over max file bytes %d", s.options.MaxFileBytes) {
			s.markNodePartial(parentID, fmt.Sprintf("one or more CPIO entries exceeded max file bytes %d and were not inspected", s.options.MaxFileBytes))
		}
	}
	markPackageScriptArchiveEntries(logical, entries)
	s.addVirtualEntries(parentID, logical, entries, depth)
}

func (s *scanner) markCPIOPartialCoverage(parentID, diagnostic string) {
	switch diagnostic {
	case "cpio archive ended before trailer":
		s.markNodePartial(parentID, "cpio archive ended before trailer; archive completeness could not be verified")
	case fmt.Sprintf("archive entry limit %d reached; remaining entries were not inspected", MaxArchiveEntries):
		s.markNodePartial(parentID, diagnostic)
	case fmt.Sprintf("archive content byte limit %d reached; this and remaining entries were not inspected", s.options.MaxArchiveBytes):
		s.markNodePartial(parentID, diagnostic)
	default:
		if strings.HasPrefix(diagnostic, "rejected ") {
			s.markNodePartial(parentID, "one or more CPIO entries were rejected and not modeled")
		}
	}
}

func parseCPIO(data []byte, options Options) ([]VirtualEntry, []string, error) {
	switch {
	case isCPIONewc(data):
		return parseCPIONewc(data, options)
	case isCPIOOdc(data):
		return parseCPIOOdc(data, options)
	default:
		if len(data) >= 6 {
			return nil, nil, fmt.Errorf("unsupported cpio magic %q", string(data[:6]))
		}
		return nil, nil, fmt.Errorf("missing cpio header")
	}
}

func parseCPIONewc(data []byte, options Options) ([]VirtualEntry, []string, error) {
	options = options.normalized()
	var entries []VirtualEntry
	var diagnostics []string
	offset := 0
	entryCount := 0
	var readBytes int64
	for {
		if offset+cpioNewcHeaderSize > len(data) {
			if len(entries) == 0 {
				return nil, diagnostics, fmt.Errorf("missing newc header")
			}
			diagnostics = append(diagnostics, "cpio archive ended before trailer")
			return entries, diagnostics, nil
		}
		header := data[offset : offset+cpioNewcHeaderSize]
		if !isCPIONewc(header) {
			return nil, diagnostics, fmt.Errorf("unsupported cpio magic %q", string(header[:6]))
		}
		mode, ok := parseCPIOHex(header[14:22])
		if !ok {
			return nil, diagnostics, fmt.Errorf("invalid mode")
		}
		size, ok := parseCPIOHex(header[54:62])
		if !ok {
			return nil, diagnostics, fmt.Errorf("invalid file size")
		}
		nameSize, ok := parseCPIOHex(header[94:102])
		if !ok || nameSize == 0 {
			return nil, diagnostics, fmt.Errorf("invalid name size")
		}
		if nameSize > uint64(len(data)-offset-cpioNewcHeaderSize) {
			return nil, diagnostics, fmt.Errorf("truncated file name")
		}
		offset += cpioNewcHeaderSize
		nameEnd := offset + int(nameSize)
		if nameEnd > len(data) {
			return nil, diagnostics, fmt.Errorf("truncated file name")
		}
		oversizedName := nameSize > MaxArchiveNameBytes+1
		name := ""
		if !oversizedName {
			var err error
			name, err = cpioEntryName(data[offset:nameEnd])
			if err != nil {
				return nil, diagnostics, err
			}
		}
		offset = align4(nameEnd)
		if !oversizedName && name == "TRAILER!!!" {
			if size != 0 {
				return nil, diagnostics, fmt.Errorf("nonempty cpio trailer")
			}
			return entries, diagnostics, nil
		}
		if entryCount >= MaxArchiveEntries {
			diagnostics = append(diagnostics, fmt.Sprintf("archive entry limit %d reached; remaining entries were not inspected", MaxArchiveEntries))
			return entries, diagnostics, nil
		}
		entryCount++
		if offset > len(data) || size > uint64(len(data)-offset) {
			return nil, diagnostics, fmt.Errorf("truncated file data for %s", name)
		}
		dataEnd := offset + int(size)
		if oversizedName {
			diagnostics = append(diagnostics, fmt.Sprintf("rejected archive entry name over %d bytes", MaxArchiveNameBytes))
			offset = align4(dataEnd)
			continue
		}
		if name == "." {
			offset = align4(dataEnd)
			continue
		}
		cleanName, ok := cleanArchiveName(name)
		if !ok {
			diagnostics = append(diagnostics, rejectedArchivePathDiagnostic("", name))
			offset = align4(dataEnd)
			continue
		}
		if uint64ExceedsInt64Limit(size, options.MaxFileBytes) {
			detail := fmt.Sprintf("skipped entry over max file bytes %d", options.MaxFileBytes)
			diagnostics = append(diagnostics, fmt.Sprintf("%s: %s", cleanName, detail))
			entries = append(entries, skippedVirtualEntry(cleanName, uint64ToInt64(size), mode&0o111 != 0, "cpio-entry", detail))
			offset = align4(dataEnd)
			continue
		}
		if archiveBudgetExceeded(readBytes, size, options.MaxArchiveBytes) {
			detail := fmt.Sprintf("archive content byte limit %d reached", options.MaxArchiveBytes)
			diagnostics = append(diagnostics, detail+"; this and remaining entries were not inspected")
			entries = append(entries, skippedVirtualEntry(cleanName, uint64ToInt64(size), mode&0o111 != 0, "cpio-entry", detail))
			return entries, diagnostics, nil
		}
		if string(header[:6]) == "070702" {
			expected, ok := parseCPIOHex(header[102:110])
			if !ok {
				return nil, diagnostics, fmt.Errorf("invalid checksum")
			}
			// The crc variant uses an unsigned byte sum, not a CRC polynomial.
			// Only retained, budget-checked entries incur this additional work.
			var checksum uint32
			for _, value := range data[offset:dataEnd] {
				checksum += uint32(value)
			}
			if uint64(checksum) != expected {
				return nil, diagnostics, fmt.Errorf("checksum mismatch for %s", cleanName)
			}
		}
		entry := VirtualEntry{
			Name:       cleanName,
			Data:       append([]byte(nil), data[offset:dataEnd]...),
			Directory:  cpioFileType(mode) == 0o040000,
			Symlink:    cpioFileType(mode) == 0o120000,
			Executable: mode&0o111 != 0,
			Provenance: "cpio-entry",
		}
		if entry.Symlink {
			entry.Data = nil
		}
		readBytes += int64(len(entry.Data))
		entries = append(entries, entry)
		offset = align4(dataEnd)
	}
}

func isCPIO(data []byte) bool {
	return isCPIONewc(data) || isCPIOOdc(data)
}

func isCPIONewc(data []byte) bool {
	return len(data) >= 6 && (string(data[:6]) == "070701" || string(data[:6]) == "070702")
}

func isCPIOOdc(data []byte) bool {
	return len(data) >= 6 && string(data[:6]) == "070707"
}

func parseCPIOHex(data []byte) (uint64, bool) {
	if _, err := hex.DecodeString(string(data)); err != nil {
		return 0, false
	}
	value, err := strconv.ParseUint(string(data), 16, 64)
	return value, err == nil
}

func parseCPIOOctal(data []byte) (uint64, bool) {
	value, err := strconv.ParseUint(string(data), 8, 64)
	return value, err == nil
}

func parseCPIOOdc(data []byte, options Options) ([]VirtualEntry, []string, error) {
	options = options.normalized()
	var entries []VirtualEntry
	var diagnostics []string
	offset := 0
	entryCount := 0
	var readBytes int64
	for {
		if offset+cpioOdcHeaderSize > len(data) {
			if len(entries) == 0 {
				return nil, diagnostics, fmt.Errorf("missing odc header")
			}
			diagnostics = append(diagnostics, "cpio archive ended before trailer")
			return entries, diagnostics, nil
		}
		header := data[offset : offset+cpioOdcHeaderSize]
		if !isCPIOOdc(header) {
			return nil, diagnostics, fmt.Errorf("unsupported cpio magic %q", string(header[:6]))
		}
		mode, ok := parseCPIOOctal(header[18:24])
		if !ok {
			return nil, diagnostics, fmt.Errorf("invalid mode")
		}
		nameSize, ok := parseCPIOOctal(header[59:65])
		if !ok || nameSize == 0 {
			return nil, diagnostics, fmt.Errorf("invalid name size")
		}
		size, ok := parseCPIOOctal(header[65:76])
		if !ok {
			return nil, diagnostics, fmt.Errorf("invalid file size")
		}
		offset += cpioOdcHeaderSize
		if nameSize > uint64(len(data)-offset) {
			return nil, diagnostics, fmt.Errorf("truncated file name")
		}
		nameEnd := offset + int(nameSize)
		oversizedName := nameSize > MaxArchiveNameBytes+1
		name := ""
		if !oversizedName {
			var err error
			name, err = cpioEntryName(data[offset:nameEnd])
			if err != nil {
				return nil, diagnostics, err
			}
		}
		offset = nameEnd
		if !oversizedName && name == "TRAILER!!!" {
			if size != 0 {
				return nil, diagnostics, fmt.Errorf("nonempty cpio trailer")
			}
			return entries, diagnostics, nil
		}
		if entryCount >= MaxArchiveEntries {
			diagnostics = append(diagnostics, fmt.Sprintf("archive entry limit %d reached; remaining entries were not inspected", MaxArchiveEntries))
			return entries, diagnostics, nil
		}
		entryCount++
		if offset > len(data) || size > uint64(len(data)-offset) {
			return nil, diagnostics, fmt.Errorf("truncated file data for %s", name)
		}
		dataEnd := offset + int(size)
		if oversizedName {
			diagnostics = append(diagnostics, fmt.Sprintf("rejected archive entry name over %d bytes", MaxArchiveNameBytes))
			offset = dataEnd
			continue
		}
		if name == "." {
			offset = dataEnd
			continue
		}
		cleanName, ok := cleanArchiveName(name)
		if !ok {
			diagnostics = append(diagnostics, rejectedArchivePathDiagnostic("", name))
			offset = dataEnd
			continue
		}
		if uint64ExceedsInt64Limit(size, options.MaxFileBytes) {
			detail := fmt.Sprintf("skipped entry over max file bytes %d", options.MaxFileBytes)
			diagnostics = append(diagnostics, fmt.Sprintf("%s: %s", cleanName, detail))
			entries = append(entries, skippedVirtualEntry(cleanName, uint64ToInt64(size), mode&0o111 != 0, "cpio-entry", detail))
			offset = dataEnd
			continue
		}
		if archiveBudgetExceeded(readBytes, size, options.MaxArchiveBytes) {
			detail := fmt.Sprintf("archive content byte limit %d reached", options.MaxArchiveBytes)
			diagnostics = append(diagnostics, detail+"; this and remaining entries were not inspected")
			entries = append(entries, skippedVirtualEntry(cleanName, uint64ToInt64(size), mode&0o111 != 0, "cpio-entry", detail))
			return entries, diagnostics, nil
		}
		entry := VirtualEntry{
			Name:       cleanName,
			Data:       append([]byte(nil), data[offset:dataEnd]...),
			Directory:  cpioFileType(mode) == 0o040000,
			Symlink:    cpioFileType(mode) == 0o120000,
			Executable: mode&0o111 != 0,
			Provenance: "cpio-entry",
		}
		if entry.Symlink {
			entry.Data = nil
		}
		readBytes += int64(len(entry.Data))
		entries = append(entries, entry)
		offset = dataEnd
	}
}

func cpioFileType(mode uint64) uint64 {
	return mode & 0o170000
}

func cpioEntryName(data []byte) (string, error) {
	if len(data) == 0 || data[len(data)-1] != 0 {
		return "", fmt.Errorf("file name is not NUL-terminated")
	}
	// newc permits additional trailing NULs in the declared name size.
	name := bytes.TrimRight(data, "\x00")
	if len(name) == 0 || bytes.IndexByte(name, 0) >= 0 {
		return "", fmt.Errorf("empty file name or embedded NUL")
	}
	return string(name), nil
}

func align4(value int) int {
	if rem := value % 4; rem != 0 {
		return value + 4 - rem
	}
	return value
}
