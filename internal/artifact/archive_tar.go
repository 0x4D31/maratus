package artifact

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
)

func (s *scanner) scanTar(parentID, logical string, data []byte, depth int) {
	tr := tar.NewReader(bytes.NewReader(data))
	var entries []VirtualEntry
	var readBytes int64
	entryCount := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			detail := fmt.Sprintf("tar parse failed: %v; remaining entries were not inspected", err)
			s.markNodePartial(parentID, detail)
			s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
			break
		}
		if entryCount >= MaxArchiveEntries {
			detail := fmt.Sprintf("archive entry limit %d reached; remaining entries were not inspected", MaxArchiveEntries)
			s.markNodePartial(parentID, detail)
			s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
			break
		}
		entryCount++
		name, ok := cleanArchiveName(header.Name)
		if !ok {
			s.markNodePartial(parentID, "one or more TAR entries had unsafe paths and were not modeled")
			s.addDiagnostic(rejectedArchivePathDiagnostic(logical, header.Name))
			continue
		}
		if _, ok := archiveLogicalPath(logical, name); !ok {
			s.markNodePartial(parentID, fmt.Sprintf("one or more TAR logical paths exceeded %d bytes and were not modeled", MaxArchiveLogicalPathBytes))
			s.addDiagnostic(fmt.Sprintf("%s: rejected archive logical path over %d bytes", logical, MaxArchiveLogicalPathBytes))
			continue
		}
		entry := VirtualEntry{
			Name:           name,
			Directory:      header.FileInfo().IsDir(),
			Symlink:        header.Typeflag == tar.TypeSymlink,
			Hardlink:       header.Typeflag == tar.TypeLink,
			Executable:     fileModeExecutable(header.FileInfo().Mode()),
			Size:           header.Size,
			CompressedSize: header.Size,
			Provenance:     "tar-entry",
		}
		if entry.Directory || entry.Symlink || entry.Hardlink {
			entries = append(entries, entry)
			continue
		}
		if header.Size < 0 {
			detail := "skipped entry with negative size"
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			entries = append(entries, entry.withSkipDetail(detail))
			continue
		}
		if header.Size > s.options.MaxFileBytes {
			detail := fmt.Sprintf("skipped entry over max file bytes %d", s.options.MaxFileBytes)
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			s.markNodePartial(parentID, fmt.Sprintf("one or more TAR entries exceeded max file bytes %d and were not inspected", s.options.MaxFileBytes))
			entries = append(entries, entry.withSkipDetail(detail))
			continue
		}
		if archiveBudgetExceeded(readBytes, uint64(header.Size), s.options.MaxArchiveBytes) {
			detail := fmt.Sprintf("archive content byte limit %d reached", s.options.MaxArchiveBytes)
			containerDetail := detail + "; this and remaining entries were not inspected"
			s.markNodePartial(parentID, containerDetail)
			s.addDiagnostic(fmt.Sprintf("%s: %s", logical, containerDetail))
			entries = append(entries, entry.withSkipDetail(detail))
			break
		}
		entry.Data, err = readAllLimited(tr, s.options.MaxFileBytes)
		if err != nil {
			detail := "read failed: " + err.Error()
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			entries = append(entries, entry.withSkipDetail(detail))
			continue
		}
		readBytes += int64(len(entry.Data))
		entries = append(entries, entry)
	}
	markPackageScriptArchiveEntries(logical, entries)
	s.addVirtualEntries(parentID, logical, entries, depth)
}
