package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Result struct {
	Graph       Graph
	Contents    []Content
	Diagnostics []string
	Options     Options
}

func InspectPath(root string, options Options) (Result, error) {
	options = options.normalized()
	info, err := os.Lstat(root)
	if err != nil {
		return Result{}, err
	}
	filesystemRootPath := filepath.Dir(root)
	if info.IsDir() {
		filesystemRootPath = root
	}
	filesystemRoot, err := os.OpenRoot(filesystemRootPath)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = filesystemRoot.Close() }()
	builder := scanner{
		options:            options,
		root:               root,
		filesystemRoot:     filesystemRoot,
		filesystemRootPath: filesystemRootPath,
	}
	stableInfo, err := builder.lstatFilesystemPath(root)
	if err != nil {
		return Result{}, err
	}
	if !os.SameFile(info, stableInfo) {
		return Result{}, fmt.Errorf("inspection target changed while opening")
	}
	info = stableInfo
	if info.IsDir() {
		if builder.isAppBundle(root) {
			appID := builder.addDirectory(root, filepath.Base(root), "", "app-bundle")
			builder.scanAppBundle(root, filepath.Base(root), appID)
		} else {
			builder.addDirectory(root, filepath.Base(root), "", "directory")
			builder.scanDirectory(root, filepath.Base(root), builder.rootID, 0, info)
		}
	} else {
		builder.scanFile(root, filepath.Base(root), "", "root", 0)
	}
	builder.propagatePackagedContentRoles()
	builder.sort()
	return Result{
		Graph:       builder.graph,
		Contents:    builder.contents,
		Diagnostics: builder.diagnostics,
		Options:     options,
	}, nil
}

// InspectBytes scans one caller-supplied in-memory artifact through the same
// detection, container-expansion, graph, and budget pipeline as a regular
// file. logical is report provenance only: it is never opened, resolved
// against the host filesystem, or used as a working directory.
func InspectBytes(logical string, data []byte, options Options) (Result, error) {
	if strings.TrimSpace(logical) == "" {
		return Result{}, fmt.Errorf("in-memory artifact logical path must not be empty")
	}
	options = options.normalized()
	if int64(len(data)) > options.MaxFileBytes {
		return Result{}, fmt.Errorf("in-memory artifact exceeds max file bytes %d", options.MaxFileBytes)
	}
	if int64(len(data)) > options.MaxTotalBytes {
		return Result{}, fmt.Errorf("in-memory artifact exceeds retained-byte limit %d", options.MaxTotalBytes)
	}

	builder := scanner{options: options, root: logical}
	// Own the retained bytes just as InspectPath owns the bytes read from its
	// file descriptor. Callers may safely reuse or mutate their input after this
	// function returns without changing the inspection result.
	retained := bytes.Clone(data)
	builder.rootID = builder.scanVirtualWithRole("", logical, retained, false, "", "target", 0)
	if builder.rootID == "" {
		return Result{}, fmt.Errorf("in-memory artifact root could not be modeled within inspection limits")
	}
	builder.propagatePackagedContentRoles()
	builder.sort()
	return Result{
		Graph:       builder.graph,
		Contents:    builder.contents,
		Diagnostics: builder.diagnostics,
		Options:     options,
	}, nil
}

// propagatePackagedContentRoles carries the structural meaning of an
// unreferenced packaged member through containers recursively decoded from that
// member. Path-derived roles on a ZIP/TAR/app/pkg descendant cannot establish
// that the outer carrier executes it. A later supported invocation relationship
// may still force behavior analysis without changing this provenance context.
func (s *scanner) propagatePackagedContentRoles() {
	packaged := make(map[string]bool, len(s.graph.Nodes))
	for index := range s.graph.Nodes {
		node := &s.graph.Nodes[index]
		if node.SourceRole == "packaged-content" || packaged[node.ParentID] {
			node.SourceRole = "packaged-content"
			packaged[node.ID] = true
		}
	}
	if len(packaged) == 0 {
		return
	}
	for index := range s.contents {
		if packaged[s.contents[index].NodeID] {
			s.contents[index].Role = "packaged-content"
		}
	}
}

type scanner struct {
	options                   Options
	root                      string
	rootID                    string
	graph                     Graph
	contents                  []Content
	diagnostics               []string
	diagnosticBytes           int64
	diagnosticSummary         bool
	suppressedDiagnostics     int
	suppressedDiagnosticBytes int64
	retainedBytes             int64
	expandedBytes             int64
	traversalEntries          int
	artifactPathBytes         int64
	nodeLimitHit              bool
	artifactPathLimitHit      bool
	electronApps              map[string]bool
	transientRoots            []string
	filesystemRoot            *os.Root
	filesystemRootPath        string
}

func (s *scanner) addDirectory(path, logical, parentID, kind string) string {
	physical := s.reportPhysicalPath(path)
	if !s.reserveNode(logical, physical, parentID) {
		return ""
	}
	id := s.graph.AddNode(Node{
		ParentID:      parentID,
		LogicalPath:   filepath.ToSlash(logical),
		PhysicalPath:  physical,
		Kind:          kind,
		MediaType:     "inode/directory",
		SourceRole:    sourceRole(logical, kind, parentID == ""),
		AnalyzeStatus: "analyzed",
	})
	if parentID != "" {
		s.graph.AddEdge(parentID, id, "contains")
	}
	if s.rootID == "" {
		s.rootID = id
	}
	return id
}

func (s *scanner) addSkippedDirectory(path, logical, parentID, provenance, detail string, size int64) string {
	physical := s.reportPhysicalPath(path)
	if !s.reserveNode(logical, physical, parentID) {
		return ""
	}
	id := s.graph.AddNode(Node{
		ParentID:       parentID,
		LogicalPath:    filepath.ToSlash(logical),
		PhysicalPath:   physical,
		Kind:           "directory",
		MediaType:      "inode/directory",
		Size:           size,
		Provenance:     provenance,
		SourceRole:     sourceRole(logical, "directory", parentID == ""),
		AnalyzeStatus:  "skipped",
		CoverageDetail: detail,
	})
	if parentID != "" {
		s.graph.AddEdge(parentID, id, "contains")
	}
	return id
}

func (s *scanner) addSymlink(path, logical, parentID, provenance string, size int64) string {
	physical := s.reportPhysicalPath(path)
	if !s.reserveNode(logical, physical, parentID) {
		return ""
	}
	id := s.graph.AddNode(Node{
		ParentID:       parentID,
		LogicalPath:    filepath.ToSlash(logical),
		PhysicalPath:   physical,
		Kind:           "symlink",
		MediaType:      "inode/symlink",
		Size:           size,
		Provenance:     provenance,
		SourceRole:     sourceRole(logical, "symlink", parentID == ""),
		AnalyzeStatus:  "skipped",
		CoverageDetail: "symlink not followed",
	})
	if parentID != "" {
		s.graph.AddEdge(parentID, id, "contains")
	}
	return id
}

func (s *scanner) addSkippedSpecialFile(path, logical, parentID, provenance string, info fs.FileInfo) string {
	physical := s.reportPhysicalPath(path)
	if !s.reserveNode(logical, physical, parentID) {
		return ""
	}
	kind := "special-file"
	mediaType := "inode/special"
	switch mode := info.Mode(); {
	case mode&os.ModeNamedPipe != 0:
		kind, mediaType = "named-pipe", "inode/fifo"
	case mode&os.ModeSocket != 0:
		kind, mediaType = "socket", "inode/socket"
	case mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0:
		kind, mediaType = "character-device", "inode/chardevice"
	case mode&os.ModeDevice != 0:
		kind, mediaType = "block-device", "inode/blockdevice"
	}
	detail := "non-regular filesystem entry not opened"
	id := s.graph.AddNode(Node{
		ParentID:       parentID,
		LogicalPath:    filepath.ToSlash(logical),
		PhysicalPath:   physical,
		Kind:           kind,
		MediaType:      mediaType,
		Size:           info.Size(),
		Provenance:     provenance,
		SourceRole:     sourceRole(logical, kind, parentID == ""),
		AnalyzeStatus:  "skipped",
		CoverageDetail: detail,
	})
	if parentID != "" {
		s.graph.AddEdge(parentID, id, "contains")
	}
	return id
}

func (s *scanner) reportPhysicalPath(path string) string {
	if path == "" {
		return ""
	}
	for _, root := range s.transientRoots {
		if pathWithin(root, path) {
			return ""
		}
		if resolvedRoot, err := filepath.EvalSymlinks(root); err == nil {
			if resolvedPath, err := filepath.EvalSymlinks(path); err == nil && pathWithin(resolvedRoot, resolvedPath) {
				return ""
			}
		}
	}
	return path
}

func pathWithin(root, path string) bool {
	if root == "" || path == "" {
		return false
	}
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func (s *scanner) scanDirectory(path, logical, parentID string, depth int, expectedInfo ...fs.FileInfo) {
	var expected fs.FileInfo
	if len(expectedInfo) > 0 {
		expected = expectedInfo[0]
	} else {
		expected, _ = s.lstatFilesystemPath(path)
	}
	entries, limited, err := s.readTraversalDirectory(path, expected)
	if err != nil {
		detail := "directory read failed: " + err.Error()
		s.markNodePartial(parentID, detail)
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
	}
	if limited {
		limit := s.options.MaxArtifactNodes
		if limit <= 0 {
			limit = DefaultMaxArtifactNodes
		}
		detail := traversalLimitDetail(limit)
		s.markNodePartial(parentID, detail)
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
	}
	for _, entry := range entries {
		name := entry.Name()
		if skipDirectoryName(name) && entry.IsDir() {
			full := filepath.Join(path, name)
			childLogical := filepath.ToSlash(filepath.Join(logical, name))
			size := int64(0)
			if info, err := s.lstatFilesystemPath(full); err == nil {
				size = info.Size()
			}
			detail := skipDirectoryDetail(name)
			s.addSkippedDirectory(full, childLogical, parentID, "filesystem", detail, size)
			s.addDiagnostic(fmt.Sprintf("%s: %s", childLogical, detail))
			continue
		}
		full := filepath.Join(path, name)
		childLogical := filepath.ToSlash(filepath.Join(logical, name))
		info, err := s.lstatFilesystemPath(full)
		if err != nil {
			detail := "directory entry stat failed; entry not inspected"
			s.markNodePartial(parentID, detail)
			s.addDiagnostic(fmt.Sprintf("%s: stat failed: %v; entry not inspected", childLogical, err))
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			s.addSymlink(full, childLogical, parentID, "filesystem", info.Size())
			continue
		}
		if info.IsDir() {
			childDepth := depth + 1
			if childDepth > s.options.MaxDirectoryDepth {
				detail := fmt.Sprintf("directory depth limit %d reached", s.options.MaxDirectoryDepth)
				s.addSkippedDirectory(full, childLogical, parentID, "filesystem", detail, info.Size())
				s.addDiagnostic(fmt.Sprintf("%s: %s", childLogical, detail))
				continue
			}
			if s.isAppBundle(full) {
				childID := s.addDirectory(full, childLogical, parentID, "app-bundle")
				if childID == "" {
					continue
				}
				s.scanAppBundle(full, childLogical, childID)
				continue
			}
			childID := s.addDirectory(full, childLogical, parentID, "directory")
			if childID == "" {
				continue
			}
			s.scanDirectory(full, childLogical, childID, childDepth, info)
			continue
		}
		if info.Mode().IsRegular() {
			s.scanFile(full, childLogical, parentID, "filesystem", depth)
			continue
		}
		s.addSkippedSpecialFile(full, childLogical, parentID, "filesystem", info)
		s.addDiagnostic(fmt.Sprintf("%s: non-regular filesystem entry not opened", childLogical))
	}
}

func (s *scanner) scanFile(path, logical, parentID, provenance string, depth int) string {
	info, err := s.lstatFilesystemPath(path)
	if err != nil {
		s.addDiagnostic(fmt.Sprintf("%s: stat failed: %v", logical, err))
		return ""
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return s.addSymlink(path, logical, parentID, provenance, info.Size())
	}
	physical := s.reportPhysicalPath(path)
	if !s.reserveNode(logical, physical, parentID) {
		return ""
	}
	executable := info.Mode()&0o111 != 0
	var data []byte
	var detectData []byte
	status := "analyzed"
	detail := ""
	file, openedInfo, openErr := s.openStableRegularFile(path, info)
	if openErr != nil {
		status = "partial"
		detail = "safe open failed: " + openErr.Error()
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
	} else {
		info = openedInfo
		executable = info.Mode()&0o111 != 0
		defer func() { _ = file.Close() }()
		remainingRetained := s.options.MaxTotalBytes - s.retainedBytes
		if remainingRetained < 0 {
			remainingRetained = 0
		}
		switch {
		case info.Size() > s.options.MaxFileBytes:
			status = "partial"
			detail = fmt.Sprintf("content scan skipped over max file bytes %d", s.options.MaxFileBytes)
			detectData, err = readPrefix(file, detectPrefixBytes)
		case info.Size() > remainingRetained:
			status = "skipped"
			detail = fmt.Sprintf("inspection retained-byte limit %d reached", s.options.MaxTotalBytes)
			s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
			detectData, err = readPrefix(file, detectPrefixBytes)
		default:
			readLimit := min(s.options.MaxFileBytes, remainingRetained)
			var exceeded bool
			data, exceeded, err = readAllAtMost(file, readLimit)
			detectData = data
			if exceeded {
				if int64(len(detectData)) > detectPrefixBytes {
					detectData = detectData[:detectPrefixBytes]
				}
				data = nil
				if readLimit == s.options.MaxFileBytes {
					status = "partial"
					detail = fmt.Sprintf("content changed while reading and exceeded max file bytes %d", s.options.MaxFileBytes)
				} else {
					status = "skipped"
					detail = fmt.Sprintf("content changed while reading and exceeded retained-byte limit %d", s.options.MaxTotalBytes)
				}
				s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
			} else if err == nil && !s.reserveRetainedBytes(logical, int64(len(data))) {
				status = "skipped"
				detail = fmt.Sprintf("inspection retained-byte limit %d reached", s.options.MaxTotalBytes)
				data = nil
			}
		}
		if currentInfo, statErr := file.Stat(); statErr == nil {
			info = currentInfo
			if status == "analyzed" && currentInfo.Size() != int64(len(data)) {
				status = "partial"
				detail = "content size changed during inspection"
				s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
				s.retainedBytes -= int64(len(data))
				if int64(len(data)) > detectPrefixBytes {
					detectData = append([]byte(nil), data[:detectPrefixBytes]...)
				}
				data = nil
			}
		}
		if err != nil {
			status = "partial"
			detail = "read failed: " + err.Error()
			s.addDiagnostic(fmt.Sprintf("%s: read failed: %v", logical, err))
			data = nil
		}
	}
	kind, media := Detect(path, detectData, executable)
	hash := ""
	if status == "analyzed" {
		hash = sha256Hex(data)
	}
	role := sourceRole(logical, kind, parentID == "")
	id := s.graph.AddNode(Node{
		ParentID:       parentID,
		LogicalPath:    filepath.ToSlash(logical),
		PhysicalPath:   physical,
		Kind:           kind,
		MediaType:      media,
		Size:           info.Size(),
		SHA256:         hash,
		Architectures:  architectures(detectData),
		Provenance:     provenance,
		SourceRole:     role,
		AnalyzeStatus:  status,
		CoverageDetail: detail,
	})
	if parentID != "" {
		s.graph.AddEdge(parentID, id, "contains")
	}
	if len(data) > 0 && status == "analyzed" {
		s.contents = append(s.contents, Content{
			NodeID:       id,
			LogicalPath:  filepath.ToSlash(logical),
			PhysicalPath: physical,
			Kind:         kind,
			MediaType:    media,
			Data:         data,
			Executable:   executable,
			Role:         role,
		})
		s.scanContainer(id, logical, data, kind, depth)
	}
	if kind == "dmg" && (len(data) == 0 || status != "analyzed") {
		s.markNodePartial(id, "DMG contents not inspected")
		s.addDMGDiagnostic(logical)
	}
	return id
}

const detectPrefixBytes int64 = 8192

func readPrefix(reader io.Reader, max int64) ([]byte, error) {
	var out bytes.Buffer
	if _, err := io.Copy(&out, io.LimitReader(reader, max)); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func readAllAtMost(reader io.Reader, max int64) ([]byte, bool, error) {
	if max < 0 {
		return nil, false, fmt.Errorf("invalid byte limit %d", max)
	}
	readLimit := max
	if max < int64(1<<63-1) {
		readLimit++
	}
	var out bytes.Buffer
	if _, err := io.Copy(&out, io.LimitReader(reader, readLimit)); err != nil {
		return out.Bytes(), false, err
	}
	data := out.Bytes()
	return data, int64(len(data)) > max, nil
}

func openStableRegularFile(path string, expected fs.FileInfo) (*os.File, fs.FileInfo, error) {
	file, err := openFileForReadNoFollow(path)
	if err != nil {
		return nil, nil, err
	}
	return validateStableRegularFile(file, expected)
}

func (s *scanner) openStableRegularFile(path string, expected fs.FileInfo) (*os.File, fs.FileInfo, error) {
	file, err := s.openFilesystemPath(path)
	if err != nil {
		return nil, nil, err
	}
	return validateStableRegularFile(file, expected)
}

func validateStableRegularFile(file *os.File, expected fs.FileInfo) (*os.File, fs.FileInfo, error) {
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("opened path is not a regular file")
	}
	if expected == nil || !expected.Mode().IsRegular() || !os.SameFile(expected, info) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("file changed between metadata check and open")
	}
	if err := clearFileNonblocking(file); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, info, nil
}

func (s *scanner) openStableDirectory(path string, expected fs.FileInfo) (*os.File, error) {
	file, err := s.openFilesystemPath(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.IsDir() {
		_ = file.Close()
		return nil, fmt.Errorf("opened path is not a directory")
	}
	if expected == nil || !expected.IsDir() || !os.SameFile(expected, info) {
		_ = file.Close()
		return nil, fmt.Errorf("directory changed between metadata check and open")
	}
	if err := clearFileNonblocking(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func (s *scanner) lstatFilesystemPath(path string) (fs.FileInfo, error) {
	if s.filesystemRoot == nil || s.pathWithinTransientRoot(path) {
		return os.Lstat(path)
	}
	rel, err := s.filesystemRelativePath(path)
	if err != nil {
		return nil, err
	}
	return s.filesystemRoot.Lstat(rel)
}

func (s *scanner) openFilesystemPath(path string) (*os.File, error) {
	if s.filesystemRoot == nil || s.pathWithinTransientRoot(path) {
		return openFileForReadNoFollow(path)
	}
	rel, err := s.filesystemRelativePath(path)
	if err != nil {
		return nil, err
	}
	return s.filesystemRoot.OpenFile(rel, os.O_RDONLY|nonblockingReadFlag(), 0)
}

func (s *scanner) filesystemRelativePath(path string) (string, error) {
	rel, err := filepath.Rel(s.filesystemRootPath, path)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path escapes inspection root")
	}
	if rel == "" {
		rel = "."
	}
	return rel, nil
}

func (s *scanner) pathWithinTransientRoot(path string) bool {
	for _, root := range s.transientRoots {
		if pathWithin(root, path) {
			return true
		}
	}
	return false
}

func (s *scanner) scanVirtual(parentID, logical string, data []byte, executable bool, provenance string, depth int) string {
	return s.scanVirtualEntry(parentID, logical, VirtualEntry{
		Data:       data,
		Executable: executable,
		Provenance: provenance,
	}, depth)
}

func (s *scanner) scanVirtualWithRole(parentID, logical string, data []byte, executable bool, provenance, roleOverride string, depth int) string {
	return s.scanVirtualEntry(parentID, logical, VirtualEntry{
		Data:       data,
		Executable: executable,
		Provenance: provenance,
		SourceRole: roleOverride,
	}, depth)
}

func (s *scanner) scanVirtualEntry(parentID, logical string, entry VirtualEntry, depth int) string {
	executable := entry.Executable && !entry.RawFeaturesOnly
	kind, media := Detect(logical, entry.Data, executable)
	if entry.Kind != "" {
		kind = entry.Kind
	} else if entry.RawFeaturesOnly {
		kind = "uninterpreted-bytes"
	}
	if entry.MediaType != "" {
		media = entry.MediaType
	} else if entry.RawFeaturesOnly {
		media = "application/octet-stream"
	}
	semanticArea, semanticDetail := rawFeatureSemanticCoverage(entry, kind)
	if !s.reserveNode(logical, "", parentID) {
		return ""
	}
	if !s.reserveRetainedBytes(logical, int64(len(entry.Data))) {
		detail := fmt.Sprintf("inspection retained-byte limit %d reached", s.options.MaxTotalBytes)
		return s.addSkippedVirtualEntryReserved(parentID, logical, entry.withSkipDetail(detail))
	}
	role := entry.SourceRole
	if role == "" {
		role = sourceRole(logical, kind, parentID == "")
	}
	var archs []string
	if !entry.RawFeaturesOnly {
		archs = architectures(entry.Data)
	}
	id := s.graph.AddNode(Node{
		ParentID:      parentID,
		LogicalPath:   filepath.ToSlash(logical),
		Kind:          kind,
		MediaType:     media,
		Size:          int64(len(entry.Data)),
		SHA256:        sha256Hex(entry.Data),
		Architectures: archs,
		Provenance:    entry.Provenance,
		SourceRole:    role,
		AnalyzeStatus: "analyzed",
	})
	s.graph.AddEdge(parentID, id, "contains")
	s.contents = append(s.contents, Content{
		NodeID:                 id,
		LogicalPath:            filepath.ToSlash(logical),
		Kind:                   kind,
		MediaType:              media,
		Data:                   entry.Data,
		Executable:             executable,
		RawFeaturesOnly:        entry.RawFeaturesOnly,
		SemanticCoverageArea:   semanticArea,
		SemanticCoverageDetail: semanticDetail,
		Role:                   role,
	})
	if !entry.RawFeaturesOnly {
		s.scanContainer(id, logical, entry.Data, kind, depth)
	}
	return id
}

func (s *scanner) addDMGDiagnostic(logical string) {
	if s.options.AllowDMGMount {
		s.addDiagnostic(fmt.Sprintf("%s: DMG detected; no retained image bytes available for system extraction; contents not inspected", logical))
		return
	}
	s.addDiagnostic(fmt.Sprintf("%s: DMG detected; contents not inspected by the portable core", logical))
}

func (s *scanner) scanContainer(parentID, logical string, data []byte, kind string, depth int) {
	// Embedded CArchive discovery is a representation check, so retain its
	// neutral inventory even when recursive archive expansion is disabled or at
	// its depth limit. Known containers are inspected through their decoded
	// children instead of searching their raw/compressed bytes for signatures.
	s.scanBunStandalone(parentID, logical, data, kind, depth)
	if !archiveContainerKind(kind) {
		s.scanCArchives(parentID, logical, data, kind, depth)
	}
	if s.options.DisableContainerExpansion {
		if archiveContainerKind(kind) {
			detail := "container expansion skipped by --expand-containers=false"
			s.markNodePartial(parentID, detail)
			s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
		}
		return
	}
	if depth >= s.options.MaxArchiveDepth {
		if archiveContainerKind(kind) {
			detail := fmt.Sprintf("archive depth limit %d reached; nested contents not inspected", s.options.MaxArchiveDepth)
			s.markNodePartial(parentID, detail)
			s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
		}
		return
	}
	switch kind {
	case "zip", "java-archive", "python-wheel", "nuget-package", "vsix":
		s.scanZipKind(parentID, logical, data, kind, depth+1)
	case "gzip":
		s.scanGzip(parentID, logical, data, depth+1)
	case "tar":
		s.scanTar(parentID, logical, data, depth+1)
	case "cpio":
		s.scanCPIO(parentID, logical, data, depth+1)
	case "asar":
		s.scanAsar(parentID, logical, data, depth+1)
	case "indexed-gzip-bundle":
		s.scanIndexedGzipBundle(parentID, logical, data, depth+1)
	case "pkg":
		s.scanPKG(parentID, logical, data, depth+1)
	case "dmg":
		s.scanDMG(parentID, logical, data, depth+1)
	}
}

func archiveContainerKind(kind string) bool {
	switch kind {
	case "zip", "java-archive", "python-wheel", "nuget-package", "vsix", "gzip", "tar", "cpio", "asar", "indexed-gzip-bundle", "pkg", "dmg":
		return true
	default:
		return false
	}
}

func (s *scanner) sort() {
	sort.SliceStable(s.graph.Nodes, func(i, j int) bool {
		return s.graph.Nodes[i].ID < s.graph.Nodes[j].ID
	})
	sort.SliceStable(s.graph.Edges, func(i, j int) bool {
		left, right := s.graph.Edges[i], s.graph.Edges[j]
		if left.From != right.From {
			return left.From < right.From
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.Ordinal == nil && right.Ordinal != nil {
			return true
		}
		if left.Ordinal != nil && right.Ordinal == nil {
			return false
		}
		if left.Ordinal != nil && right.Ordinal != nil && *left.Ordinal != *right.Ordinal {
			return *left.Ordinal < *right.Ordinal
		}
		return left.To < right.To
	})
	sort.SliceStable(s.contents, func(i, j int) bool {
		return s.contents[i].LogicalPath < s.contents[j].LogicalPath
	})
	sort.Strings(s.diagnostics)
}

func (s *scanner) addVirtualEntries(parentID, outer string, entries []VirtualEntry, depth int) {
	var readBytes int64
	apps := s.addArchiveAppBundleNodes(parentID, outer, entries)
	defer s.addArchiveAppBundleDeferredEdges(apps)
	for i, entry := range entries {
		if i >= MaxArchiveEntries {
			detail := fmt.Sprintf("archive entry limit %d reached; remaining entries were not inspected", MaxArchiveEntries)
			s.markNodePartial(parentID, detail)
			s.addDiagnostic(fmt.Sprintf("%s: %s", outer, detail))
			return
		}
		name, ok := cleanArchiveName(entry.Name)
		if !ok {
			s.markNodePartial(parentID, "one or more archive entries had unsafe paths and were not modeled")
			s.addDiagnostic(rejectedArchivePathDiagnostic(outer, entry.Name))
			continue
		}
		if _, ok := archiveLogicalPath(outer, name); !ok {
			s.markNodePartial(parentID, fmt.Sprintf("one or more archive logical paths exceeded %d bytes and were not modeled", MaxArchiveLogicalPathBytes))
			s.addDiagnostic(fmt.Sprintf("%s: rejected archive logical path over %d bytes", outer, MaxArchiveLogicalPathBytes))
			continue
		}
		childParentID := parentID
		var app *archiveAppBundle
		if appRoot := archiveAppRootForEntry(name, apps); appRoot != "" {
			app = apps[appRoot]
			childParentID = app.nodeID
		}
		if entry.SkipDetail != "" {
			childID := s.addSkippedVirtualEntry(childParentID, outer, name, entry)
			if entry.Relation != "" {
				s.graph.AddEdge(childParentID, childID, entry.Relation)
			}
			continue
		}
		if entry.Symlink || entry.Hardlink {
			kind := "symlink"
			mediaType := "inode/symlink"
			detail := "archive symlink not followed"
			if entry.Hardlink {
				kind = "hardlink"
				mediaType = "inode/hardlink"
				detail = "archive hard link not followed"
			}
			childLogical, _ := archiveLogicalPath(outer, name)
			if !s.reserveNode(childLogical, "", childParentID) {
				continue
			}
			childID := s.graph.AddNode(Node{
				ParentID:       childParentID,
				LogicalPath:    childLogical,
				Kind:           kind,
				MediaType:      mediaType,
				Provenance:     entry.Provenance,
				AnalyzeStatus:  "skipped",
				CoverageDetail: detail,
			})
			s.graph.AddEdge(childParentID, childID, "contains")
			if entry.Relation != "" {
				s.graph.AddEdge(childParentID, childID, entry.Relation)
			}
			continue
		}
		if entry.Directory {
			continue
		}
		if s.entryCompressionRatioExceeded(entry) {
			detail := fmt.Sprintf("skipped entry over compression ratio limit %d", s.options.MaxCompressionRatio)
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", outer, name, detail))
			s.addSkippedVirtualEntry(childParentID, outer, name, entry.withSkipDetail(detail))
			continue
		}
		if int64(len(entry.Data)) > s.options.MaxFileBytes {
			detail := fmt.Sprintf("skipped entry over max file bytes %d", s.options.MaxFileBytes)
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", outer, name, detail))
			s.addSkippedVirtualEntry(childParentID, outer, name, entry.withSkipDetail(detail))
			continue
		}
		readBytes += int64(len(entry.Data))
		if readBytes > s.options.MaxArchiveBytes {
			detail := fmt.Sprintf("archive content byte limit %d reached", s.options.MaxArchiveBytes)
			s.markNodePartial(parentID, detail+"; this and remaining entries were not inspected")
			s.addDiagnostic(fmt.Sprintf("%s: %s", outer, detail))
			s.addSkippedVirtualEntry(childParentID, outer, name, entry.withSkipDetail(detail))
			return
		}
		if s.expandedBytes > s.options.MaxExpandedBytes-int64(len(entry.Data)) {
			detail := fmt.Sprintf("inspection expanded-byte limit %d reached", s.options.MaxExpandedBytes)
			s.markNodePartial(parentID, detail+"; this and remaining entries were not inspected")
			s.addDiagnostic(fmt.Sprintf("%s: %s", outer, detail))
			s.addSkippedVirtualEntry(childParentID, outer, name, entry.withSkipDetail(detail))
			return
		}
		s.expandedBytes += int64(len(entry.Data))
		childLogical, _ := archiveLogicalPath(outer, name)
		childID := s.scanVirtualEntry(childParentID, childLogical, entry, depth)
		if app != nil {
			s.addArchiveAppBundleEdge(app, name, childID, entry)
		}
		if entry.Relation != "" {
			s.graph.AddEdge(childParentID, childID, entry.Relation)
		}
	}
}

func (s *scanner) addSkippedVirtualEntry(parentID, outer, name string, entry VirtualEntry) string {
	childLogical := filepath.ToSlash(name)
	if outer != "" {
		var ok bool
		childLogical, ok = archiveLogicalPath(outer, name)
		if !ok {
			s.addDiagnostic(fmt.Sprintf("%s: rejected archive logical path over %d bytes", outer, MaxArchiveLogicalPathBytes))
			return ""
		}
	}
	if !s.reserveNode(childLogical, "", parentID) {
		return ""
	}
	return s.addSkippedVirtualEntryReserved(parentID, childLogical, entry)
}

func (s *scanner) addSkippedVirtualEntryReserved(parentID, childLogical string, entry VirtualEntry) string {
	kind, media := detectSkippedEntry(childLogical, entry.Executable && !entry.RawFeaturesOnly)
	if entry.Kind != "" {
		kind = entry.Kind
	} else if entry.RawFeaturesOnly {
		kind = "uninterpreted-bytes"
	}
	if entry.MediaType != "" {
		media = entry.MediaType
	} else if entry.RawFeaturesOnly {
		media = "application/octet-stream"
	}
	size := entry.Size
	if size == 0 {
		size = int64(len(entry.Data))
	}
	if size < 0 {
		size = 0
	}
	id := s.graph.AddNode(Node{
		ParentID:       parentID,
		LogicalPath:    childLogical,
		Kind:           kind,
		MediaType:      media,
		Size:           size,
		Provenance:     entry.Provenance,
		SourceRole:     virtualEntrySourceRole(entry, childLogical, kind),
		AnalyzeStatus:  "skipped",
		CoverageDetail: entry.SkipDetail,
	})
	s.graph.AddEdge(parentID, id, "contains")
	return id
}

func detectSkippedEntry(path string, executable bool) (kind, media string) {
	lower := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(lower))
	switch {
	case ext == ".zip" || ext == ".jar" || ext == ".war" || ext == ".ear" || ext == ".whl" || ext == ".nupkg" || ext == ".vsix":
		return archiveKind(ext), "application/zip"
	case ext == ".gz" || ext == ".tgz" || ext == ".crate" || strings.HasSuffix(lower, ".tar.gz"):
		return "gzip", "application/gzip"
	case ext == ".tar":
		return "tar", "application/x-tar"
	case ext == ".cpio":
		return "cpio", "application/x-cpio"
	case ext == ".pkg":
		return "pkg", "application/x-xar"
	case ext == ".dmg":
		return "dmg", "application/x-apple-diskimage"
	case ext == ".asar":
		return "asar", "application/x-asar"
	case ext == ".plist":
		return "plist", "text/plain"
	case ext == ".json" || ext == ".toml" || ext == ".lock" || ext == ".xml" || ext == ".gradle" || ext == ".kts" || ext == ".vsixmanifest":
		return "manifest", "text/plain"
	case hasResourceType(ext, nil):
		kind, media, _ := resourceType(ext, nil)
		return kind, media
	case scriptExtension(ext) || manifestName(lower):
		return scriptOrTextKind(ext, lower, executable, nil), "text/plain"
	case executable:
		return "executable", "application/octet-stream"
	default:
		return "blob", "application/octet-stream"
	}
}

type VirtualEntry struct {
	Name           string
	Data           []byte
	Kind           string
	MediaType      string
	Directory      bool
	Symlink        bool
	Hardlink       bool
	Executable     bool
	Size           int64
	CompressedSize int64
	SkipDetail     string
	Relation       string
	Provenance     string
	SourceRole     string
	// RawFeaturesOnly preserves structurally known uninterpreted bytes while
	// preventing recursive container or semantic interpretation. The
	// accompanying coverage fields explain exactly which representation
	// semantics remain unsupported.
	RawFeaturesOnly        bool
	SemanticCoverageArea   string
	SemanticCoverageDetail string
}

func virtualEntrySourceRole(entry VirtualEntry, logical, kind string) string {
	if entry.SourceRole != "" {
		return entry.SourceRole
	}
	return sourceRole(logical, kind, false)
}

func rawFeatureSemanticCoverage(entry VirtualEntry, kind string) (string, string) {
	if !entry.RawFeaturesOnly {
		return "", ""
	}
	area := strings.TrimSpace(entry.SemanticCoverageArea)
	if area == "" {
		area = "representation-semantics/" + strings.ReplaceAll(strings.TrimSpace(kind), " ", "-")
	}
	detail := strings.TrimSpace(entry.SemanticCoverageDetail)
	if detail == "" {
		detail = fmt.Sprintf("%s representation identified; semantic decoding is not implemented", kind)
	}
	return area, detail
}

func (e VirtualEntry) withSkipDetail(detail string) VirtualEntry {
	e.SkipDetail = detail
	if e.Size == 0 {
		e.Size = int64(len(e.Data))
	}
	return e
}

func skippedVirtualEntry(name string, size int64, executable bool, provenance, detail string) VirtualEntry {
	return VirtualEntry{
		Name:       name,
		Size:       size,
		Executable: executable,
		Provenance: provenance,
		SkipDetail: detail,
	}
}

func (s *scanner) entryCompressionRatioExceeded(entry VirtualEntry) bool {
	if len(entry.Data) == 0 || entry.CompressedSize <= 0 {
		return false
	}
	return compressionRatioExceeded(uint64(len(entry.Data)), uint64(entry.CompressedSize), s.options.MaxCompressionRatio)
}

func (s *scanner) compressionRatioExceeded(uncompressed, compressed uint64) bool {
	return compressionRatioExceeded(uncompressed, compressed, s.options.MaxCompressionRatio)
}

func compressionRatioExceeded(uncompressed, compressed uint64, limit int64) bool {
	if uncompressed == 0 || limit <= 0 {
		return false
	}
	if compressed == 0 {
		return true
	}
	quotient := uncompressed / compressed
	maximum := uint64(limit)
	return quotient > maximum || quotient == maximum && uncompressed%compressed != 0
}

func archiveBudgetExceeded(current int64, next uint64, max int64) bool {
	if max <= 0 {
		return false
	}
	if current >= max {
		return true
	}
	return next > uint64(max-current)
}

func cleanArchiveName(name string) (string, bool) {
	if len(name) > MaxArchiveNameBytes {
		return "", false
	}
	name = strings.ReplaceAll(filepath.ToSlash(name), "\\", "/")
	for strings.HasPrefix(name, "./") {
		name = strings.TrimPrefix(name, "./")
	}
	var ok bool
	name, ok = normalizeMacOSArchiveSpecialName(name)
	if !ok {
		return "", false
	}
	if hasWindowsDrivePrefix(name) {
		return "", false
	}
	for _, r := range name {
		if r == 0 || r < 0x20 {
			return "", false
		}
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", false
		}
	}
	clean := filepath.Clean(name)
	clean = filepath.ToSlash(clean)
	if len(clean) > MaxArchiveNameBytes {
		return "", false
	}
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || strings.Contains(clean, "/../") {
		return "", false
	}
	return clean, true
}

func archiveLogicalPath(outer, name string) (string, bool) {
	logical := filepath.ToSlash(name)
	if outer != "" {
		logical = filepath.ToSlash(outer + "!" + name)
	}
	return logical, len(logical) <= MaxArchiveLogicalPathBytes
}

func rejectedArchivePathDiagnostic(outer, name string) string {
	if len(name) > MaxArchiveNameBytes {
		return fmt.Sprintf("%s: rejected archive entry name over %d bytes", outer, MaxArchiveNameBytes)
	}
	if outer == "" {
		return "rejected unsafe archive path"
	}
	return fmt.Sprintf("%s: rejected unsafe archive path", outer)
}

func normalizeMacOSArchiveSpecialName(name string) (string, bool) {
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if part == "Icon\r" {
			if i != len(parts)-1 {
				return "", false
			}
			parts[i] = "Icon#015"
		}
	}
	return strings.Join(parts, "/"), true
}

func hasWindowsDrivePrefix(name string) bool {
	return len(name) >= 2 &&
		((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')) &&
		name[1] == ':'
}

func skipDirectoryName(name string) bool {
	switch name {
	case ".git", ".hg", ".svn",
		"node_modules", "vendor", ".venv", "venv",
		"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
		".gocache", ".uv-cache", ".tox", ".nox", "coverage",
		".fseventsd", ".Spotlight-V100", ".Trashes", ".DocumentRevisions-V100":
		return true
	default:
		return false
	}
}

func skipDirectoryDetail(name string) string {
	switch name {
	case ".fseventsd", ".Spotlight-V100", ".Trashes", ".DocumentRevisions-V100":
		return "macOS volume metadata directory skipped during default traversal"
	default:
		return "dependency/cache directory skipped during default traversal"
	}
}

func (s *scanner) reserveNode(logical, physical, parentID string) bool {
	if s.options.MaxArtifactNodes > 0 && len(s.graph.Nodes) >= s.options.MaxArtifactNodes {
		if !s.nodeLimitHit {
			s.nodeLimitHit = true
			detail := fmt.Sprintf("artifact node limit %d reached; remaining nodes not modeled", s.options.MaxArtifactNodes)
			s.markNodePartial(parentID, detail)
			s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
		}
		return false
	}
	if s.artifactPathLimitHit {
		return false
	}
	pathBytes := jsonEscapedStringBytes(logical) + jsonEscapedStringBytes(physical)
	if pathBytes > s.options.MaxArtifactPathBytes-s.artifactPathBytes {
		s.artifactPathLimitHit = true
		detail := fmt.Sprintf("artifact node path-string limit %d reached; remaining nodes not modeled", s.options.MaxArtifactPathBytes)
		s.markNodePartial(parentID, detail)
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
		return false
	}
	s.artifactPathBytes += pathBytes
	return true
}

func (s *scanner) reserveRetainedBytes(logical string, size int64) bool {
	if size <= 0 || s.options.MaxTotalBytes <= 0 {
		return true
	}
	if s.retainedBytes > s.options.MaxTotalBytes-size {
		s.addDiagnostic(fmt.Sprintf("%s: inspection retained-byte limit %d reached", logical, s.options.MaxTotalBytes))
		return false
	}
	s.retainedBytes += size
	return true
}

func sourceRole(logical, kind string, root bool) string {
	if root {
		return "target"
	}
	// Logical archive paths use ! as the boundary between a container and its
	// contents. Treat that boundary like a path separator so top-level archive
	// directories receive the same source role as ordinary filesystem paths.
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(logical), "!", "/"))
	lower := "/" + strings.Trim(normalized, "/") + "/"
	base := strings.ToLower(filepath.Base(lower))
	switch {
	case strings.Contains(lower, "/node_modules/") || strings.Contains(lower, "/vendor/") ||
		strings.Contains(lower, "/.venv/") || strings.Contains(lower, "/venv/"):
		return "vendor"
	case strings.Contains(lower, "/.gocache/") || strings.Contains(lower, "/.uv-cache/") ||
		strings.Contains(lower, "/.pytest_cache/") || strings.Contains(lower, "/.mypy_cache/") ||
		strings.Contains(lower, "/.ruff_cache/") || strings.Contains(lower, "/coverage/"):
		return "generated/build"
	case strings.Contains(lower, "/testdata/") || strings.Contains(lower, "/fixtures/"):
		return "fixture"
	case strings.Contains(lower, "/test/") || strings.Contains(lower, "/tests/") ||
		strings.HasSuffix(base, "_test.go") || strings.Contains(base, ".test."):
		return "test"
	case strings.Contains(lower, "/docs/") || strings.Contains(lower, "/doc/") ||
		base == "readme" || strings.HasPrefix(base, "readme.") ||
		strings.HasSuffix(base, ".md") || strings.HasSuffix(base, ".markdown") ||
		strings.HasSuffix(base, ".rst"):
		return "documentation"
	case strings.Contains(lower, "/dist/") || strings.Contains(lower, "/build/"):
		return "generated/build"
	case kind == "script" || kind == "compiled-applescript" || kind == "macho" || kind == "macho-fat" || kind == "executable" || kind == "plist" || kind == "manifest":
		return "runtime"
	default:
		return "unknown"
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readAllLimited(r io.Reader, max int64) ([]byte, error) {
	if max < 0 {
		return nil, fmt.Errorf("invalid byte limit %d", max)
	}
	var out bytes.Buffer
	readLimit := max
	if max < int64(1<<63-1) {
		readLimit++
	}
	limited := io.LimitReader(r, readLimit)
	if _, err := io.Copy(&out, limited); err != nil {
		return nil, err
	}
	data := out.Bytes()
	if int64(len(data)) > max {
		return nil, &byteLimitError{Limit: max}
	}
	return data, nil
}

type byteLimitError struct {
	Limit int64
}

func (e *byteLimitError) Error() string {
	return fmt.Sprintf("entry exceeds %d bytes", e.Limit)
}

func uint64ToInt64(value uint64) int64 {
	const maxInt64 = int64(1<<63 - 1)
	if value > uint64(maxInt64) {
		return maxInt64
	}
	return int64(value)
}

func uint64ExceedsInt64Limit(value uint64, limit int64) bool {
	return limit < 0 || value > uint64(limit)
}

func fileModeExecutable(mode fs.FileMode) bool {
	return mode&0o111 != 0
}
