package artifact

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	maxASARHeaderBytes       = 4 << 20
	maxASARHeaderDepth       = 128
	maxASARHeaderTokens      = MaxArchiveEntries * 16
	maxASARPackageJSONDepth  = 64
	maxASARPackageJSONTokens = 32768
)

type asarHeader struct {
	Files map[string]asarEntry `json:"files"`
}

type asarEntry struct {
	Files      map[string]asarEntry `json:"files,omitempty"`
	Link       string               `json:"link,omitempty"`
	HasLink    bool                 `json:"-"`
	Offset     string               `json:"offset,omitempty"`
	Size       int64                `json:"size,omitempty"`
	Unpacked   bool                 `json:"unpacked,omitempty"`
	Executable bool                 `json:"executable,omitempty"`
}

// decodeASARHeader uses exact JSON member names. encoding/json's ordinary
// struct decoding accepts case-folded matches (for example "Files" for
// "files"), but Electron's ASAR reader consumes the canonical lowercase
// format. Accepting aliases here could classify or promote a program that the
// runtime would not see.
func decodeASARHeader(data []byte) (asarHeader, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return asarHeader{}, err
	}
	rawFiles, ok := object["files"]
	if !ok {
		return asarHeader{}, fmt.Errorf("missing files map")
	}
	files, err := decodeASAREntryMap(rawFiles)
	if err != nil {
		return asarHeader{}, err
	}
	return asarHeader{Files: files}, nil
}

func decodeASAREntryMap(data []byte) (map[string]asarEntry, error) {
	var rawEntries map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawEntries); err != nil {
		return nil, err
	}
	if rawEntries == nil {
		return nil, fmt.Errorf("files is not an object")
	}
	entries := make(map[string]asarEntry, len(rawEntries))
	names := make([]string, 0, len(rawEntries))
	for name := range rawEntries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := rawEntries[name]
		entry, err := decodeASAREntry(raw)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", name, err)
		}
		entries[name] = entry
	}
	return entries, nil
}

func decodeASAREntry(data []byte) (asarEntry, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return asarEntry{}, err
	}
	if object == nil {
		return asarEntry{}, fmt.Errorf("entry is not an object")
	}
	var entry asarEntry
	if raw, ok := object["files"]; ok {
		files, err := decodeASAREntryMap(raw)
		if err != nil {
			return asarEntry{}, err
		}
		entry.Files = files
	}
	if raw, ok := object["link"]; ok {
		if err := json.Unmarshal(raw, &entry.Link); err != nil {
			return asarEntry{}, fmt.Errorf("invalid link: %w", err)
		}
		entry.HasLink = true
	}
	fields := []struct {
		key    string
		target any
	}{
		{key: "offset", target: &entry.Offset},
		{key: "size", target: &entry.Size},
		{key: "unpacked", target: &entry.Unpacked},
		{key: "executable", target: &entry.Executable},
	}
	for _, field := range fields {
		key, target := field.key, field.target
		raw, ok := object[key]
		if !ok {
			continue
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return asarEntry{}, fmt.Errorf("invalid %s: %w", key, err)
		}
	}
	return entry, nil
}

func (s *scanner) scanAsar(parentID, logical string, data []byte, depth int) {
	appID, electronRuntime := s.canonicalAppASARContext(parentID, logical)
	header, base, err := parseAsarHeader(data)
	if err != nil {
		detail := fmt.Sprintf("asar parse failed: %v; contents not inspected", err)
		s.markNodePartial(parentID, detail)
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
		return
	}
	var entries []VirtualEntry
	var readBytes int64
	items, limited := flattenAsar(header, MaxArchiveEntries)
	if electronRuntime {
		// Root metadata and its exact declared target are execution-relevant.
		// Put them ahead of vendor trees so deterministic traversal and byte
		// budgets cannot spend the entire prefix in node_modules first.
		items = prioritizeASARProgramItems(header, data, base, items, MaxArchiveEntries)
	}
	if limited {
		detail := fmt.Sprintf("archive entry limit %d reached; remaining entries were not inspected", MaxArchiveEntries)
		s.markNodePartial(parentID, detail)
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
	}
	for _, item := range items {
		if item.UnsafeName {
			s.markNodePartial(parentID, "one or more ASAR header keys were not canonical path components and were not modeled")
			s.addDiagnostic(rejectedArchivePathDiagnostic(logical, item.Name))
			continue
		}
		if item.OversizedName {
			s.markNodePartial(parentID, fmt.Sprintf("one or more ASAR entry names exceeded %d bytes and were not modeled", MaxArchiveNameBytes))
			s.addDiagnostic(fmt.Sprintf("%s: rejected archive entry name over %d bytes", logical, MaxArchiveNameBytes))
			continue
		}
		name, ok := cleanArchiveName(item.Name)
		if !ok {
			s.markNodePartial(parentID, "one or more ASAR entries had unsafe paths and were not modeled")
			s.addDiagnostic(rejectedArchivePathDiagnostic(logical, item.Name))
			continue
		}
		if _, ok := archiveLogicalPath(logical, name); !ok {
			s.markNodePartial(parentID, fmt.Sprintf("one or more ASAR logical paths exceeded %d bytes and were not modeled", MaxArchiveLogicalPathBytes))
			s.addDiagnostic(fmt.Sprintf("%s: rejected archive logical path over %d bytes", logical, MaxArchiveLogicalPathBytes))
			continue
		}
		if item.HasLink {
			detail := "skipped ASAR symbolic link; bounded link resolution is not supported"
			s.markNodePartial(parentID, "one or more ASAR symbolic links were not resolved")
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			entries = append(entries, VirtualEntry{
				Name:       name,
				Symlink:    true,
				Size:       int64(len(item.Link)),
				Provenance: "asar-link",
			})
			continue
		}
		if item.Unpacked {
			detail := "skipped unpacked asar entry; external content not present in archive"
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			entries = append(entries, skippedVirtualEntry(name, item.Size, item.Executable, "asar-entry", detail))
			continue
		}
		if item.Size < 0 {
			detail := "skipped entry with negative size"
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			entries = append(entries, skippedVirtualEntry(name, 0, item.Executable, "asar-entry", detail))
			continue
		}
		if item.Size > s.options.MaxFileBytes {
			detail := fmt.Sprintf("skipped entry over max file bytes %d", s.options.MaxFileBytes)
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			s.markNodePartial(parentID, fmt.Sprintf("one or more ASAR entries exceeded max file bytes %d and were not inspected", s.options.MaxFileBytes))
			entries = append(entries, skippedVirtualEntry(name, item.Size, item.Executable, "asar-entry", detail))
			continue
		}
		if archiveBudgetExceeded(readBytes, uint64(item.Size), s.options.MaxArchiveBytes) {
			detail := fmt.Sprintf("archive content byte limit %d reached", s.options.MaxArchiveBytes)
			containerDetail := detail + "; this and remaining entries were not inspected"
			s.markNodePartial(parentID, containerDetail)
			s.addDiagnostic(fmt.Sprintf("%s: %s", logical, containerDetail))
			entries = append(entries, skippedVirtualEntry(name, item.Size, item.Executable, "asar-entry", detail))
			break
		}
		offset, err := strconv.ParseInt(item.Offset, 10, 64)
		if err != nil || offset < 0 {
			detail := "invalid asar offset"
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			entries = append(entries, skippedVirtualEntry(name, item.Size, item.Executable, "asar-entry", detail))
			continue
		}
		payloadSize := int64(len(data)) - base
		if offset > payloadSize || item.Size > payloadSize-offset {
			detail := "invalid asar bounds"
			s.addDiagnostic(fmt.Sprintf("%s!%s: %s", logical, name, detail))
			entries = append(entries, skippedVirtualEntry(name, item.Size, item.Executable, "asar-entry", detail))
			continue
		}
		start := int64(base) + offset
		end := start + item.Size
		readBytes += item.Size
		entries = append(entries, VirtualEntry{
			Name:       name,
			Data:       append([]byte(nil), data[start:end]...),
			Executable: item.Executable,
			Provenance: "asar-entry",
		})
	}
	programTarget := ""
	programDetail := ""
	if electronRuntime {
		programTarget, programDetail = resolveASARProgramTarget(entries)
	}
	contentStart := len(s.contents)
	s.addVirtualEntries(parentID, logical, entries, depth)
	if electronRuntime {
		s.addASARProgramEntry(appID, parentID, logical, programTarget, programDetail, contentStart)
	} else if appID != "" {
		detail := "canonical app.asar program entry was not connected because an Electron runtime was not corroborated"
		s.markNodePartial(parentID, detail)
		s.addDiagnostic(logical + ": " + detail)
	}
}

func prioritizeASARProgramItems(header asarHeader, data []byte, base int64, items []asarFlatEntry, limit int) []asarFlatEntry {
	manifest, ok := asarItemAtPath(header, "package.json")
	if !ok {
		return items
	}
	priority := []asarFlatEntry{manifest}
	if manifestData, ok := asarItemData(data, base, manifest, int64(maxAppMetadataBytes)); ok {
		if target, err := decodeASARPackageMain(manifestData); err == nil {
			if targetItem, exists := asarItemAtPath(header, target); exists && targetItem.Name != manifest.Name {
				priority = append(priority, targetItem)
			}
		}
	}
	if limit <= 0 {
		limit = MaxArchiveEntries
	}
	out := make([]asarFlatEntry, 0, min(limit, len(items)+len(priority)))
	seen := make(map[string]bool, len(priority))
	for _, item := range priority {
		if len(out) >= limit || seen[item.Name] {
			continue
		}
		seen[item.Name] = true
		out = append(out, item)
	}
	for _, item := range items {
		if len(out) >= limit {
			break
		}
		if item.Name != "" && seen[item.Name] {
			continue
		}
		if item.Name != "" {
			seen[item.Name] = true
		}
		out = append(out, item)
	}
	return out
}

func asarItemAtPath(header asarHeader, name string) (asarFlatEntry, bool) {
	clean, ok := cleanArchiveName(name)
	if !ok || clean != name {
		return asarFlatEntry{}, false
	}
	parts := strings.Split(clean, "/")
	files := header.Files
	for index, part := range parts {
		if !canonicalASARComponent(part) {
			return asarFlatEntry{}, false
		}
		entry, exists := files[part]
		if !exists {
			return asarFlatEntry{}, false
		}
		if index < len(parts)-1 {
			if entry.HasLink || entry.Files == nil {
				return asarFlatEntry{}, false
			}
			files = entry.Files
			continue
		}
		if entry.Files != nil && !entry.HasLink {
			return asarFlatEntry{}, false
		}
		return asarFlatEntry{
			Name:       clean,
			Link:       entry.Link,
			HasLink:    entry.HasLink,
			Offset:     entry.Offset,
			Size:       entry.Size,
			Unpacked:   entry.Unpacked,
			Executable: entry.Executable,
		}, true
	}
	return asarFlatEntry{}, false
}

func asarItemData(data []byte, base int64, item asarFlatEntry, maxBytes int64) ([]byte, bool) {
	if item.HasLink || item.Unpacked || item.Size < 0 || item.Size > maxBytes || base < 0 || base > int64(len(data)) {
		return nil, false
	}
	offset, err := strconv.ParseInt(item.Offset, 10, 64)
	if err != nil || offset < 0 {
		return nil, false
	}
	payloadSize := int64(len(data)) - base
	if offset > payloadSize || item.Size > payloadSize-offset {
		return nil, false
	}
	start := base + offset
	return data[start : start+item.Size], true
}

func (s *scanner) canonicalAppASARContext(parentID, logical string) (string, bool) {
	if parentID == "" || !isCanonicalAppASAR(logical) {
		return "", false
	}
	var asarNode Node
	for i := len(s.graph.Nodes) - 1; i >= 0; i-- {
		if s.graph.Nodes[i].ID == parentID {
			asarNode = s.graph.Nodes[i]
			break
		}
	}
	if asarNode.ID == "" || asarNode.ParentID == "" || !strings.EqualFold(filepath.ToSlash(asarNode.LogicalPath), filepath.ToSlash(logical)) {
		return "", false
	}
	for i := len(s.graph.Nodes) - 1; i >= 0; i-- {
		app := s.graph.Nodes[i]
		if app.ID != asarNode.ParentID || app.Kind != "app-bundle" {
			continue
		}
		expected := strings.TrimSuffix(filepath.ToSlash(app.LogicalPath), "/") + "/Contents/Resources/app.asar"
		if strings.EqualFold(expected, filepath.ToSlash(logical)) {
			return app.ID, s.electronApps[app.ID]
		}
		return "", false
	}
	return "", false
}

func resolveASARProgramTarget(entries []VirtualEntry) (string, string) {
	var manifest *VirtualEntry
	for i := range entries {
		if entries[i].Name == "package.json" {
			manifest = &entries[i]
			break
		}
	}
	if manifest == nil {
		return "", "root package.json is absent"
	}
	if manifest.SkipDetail != "" {
		return "", "root package.json was not available for parsing"
	}
	target, err := decodeASARPackageMain(manifest.Data)
	if err != nil {
		return "", err.Error()
	}
	return target, ""
}

func decodeASARPackageMain(data []byte) (string, error) {
	if len(data) > int(maxAppMetadataBytes) {
		return "", fmt.Errorf("root package.json exceeds parser input limit %d", maxAppMetadataBytes)
	}
	if err := validateASARPackageJSON(data); err != nil {
		return "", fmt.Errorf("root package.json decode failed: %v", err)
	}
	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", fmt.Errorf("root package.json decode failed: %v", err)
	}
	mainValue, ok := manifest["main"]
	if !ok {
		return "index.js", nil
	}
	var main string
	if err := json.Unmarshal(mainValue, &main); err != nil {
		return "", fmt.Errorf("root package.json main is not a literal string")
	}
	if strings.TrimSpace(main) == "" {
		return "", fmt.Errorf("root package.json main is empty")
	}
	if strings.Contains(main, "\\") {
		return "", fmt.Errorf("root package.json main contains a non-POSIX path separator")
	}
	clean, ok := cleanArchiveName(main)
	if !ok {
		return "", fmt.Errorf("root package.json main is not a safe relative ASAR path")
	}
	return clean, nil
}

func validateASARPackageJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	depth := 0
	for count := 1; ; count++ {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if count > maxASARPackageJSONTokens {
			return fmt.Errorf("JSON token limit %d reached", maxASARPackageJSONTokens)
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			continue
		}
		switch delimiter {
		case '{', '[':
			depth++
			if depth > maxASARPackageJSONDepth {
				return fmt.Errorf("JSON nesting limit %d reached", maxASARPackageJSONDepth)
			}
		case '}', ']':
			depth--
		}
	}
}

func (s *scanner) addASARProgramEntry(appID, asarID, logical, target, detail string, contentStart int) {
	fail := func(reason string) {
		coverage := "canonical app.asar program entry was not resolved: " + reason
		s.markNodePartial(asarID, coverage)
		s.addDiagnostic(logical + ": " + coverage)
	}
	if detail != "" {
		fail(detail)
		return
	}
	manifestLogical, manifestOK := archiveLogicalPath(logical, "package.json")
	targetLogical, targetOK := archiveLogicalPath(logical, target)
	if !manifestOK || !targetOK {
		fail("resolved logical path exceeds the artifact path limit")
		return
	}
	manifestRetained := false
	targetNodeID := ""
	var targetContent *Content
	for i := contentStart; i < len(s.contents); i++ {
		content := &s.contents[i]
		switch content.LogicalPath {
		case manifestLogical:
			manifestRetained = true
		case targetLogical:
			targetNodeID = content.NodeID
			targetContent = content
		}
	}
	if !manifestRetained {
		fail("root package.json was not retained")
		return
	}
	if targetNodeID == "" {
		fail("declared program target was not retained: " + target)
		return
	}
	if detail := prepareASARJavaScriptProgram(target, targetContent); detail != "" {
		fail(detail)
		return
	}
	s.graph.AddEdge(appID, targetNodeID, "program-entry")
	s.markNodePartial(asarID, "exact Electron package main was connected, but transitive relative require/import module resolution is not implemented")
}

func prepareASARJavaScriptProgram(target string, content *Content) string {
	if content == nil {
		return "declared program target content is unavailable"
	}
	switch strings.ToLower(filepath.Ext(target)) {
	case "", ".js", ".cjs", ".mjs":
	default:
		return "declared program target is not a supported JavaScript module: " + target
	}
	if content.Kind != "script" && content.Kind != "text" {
		return "declared JavaScript program target is not textual: " + target
	}
	// The package main declaration establishes Node/Electron JavaScript
	// semantics. It overrides misleading script suffixes and JXA-looking text,
	// but applies only to the exact corroborated program target.
	content.SemanticLanguage = "javascript"
	return ""
}

func parseAsarHeader(data []byte) (asarHeader, int64, error) {
	if len(data) < 16 {
		return asarHeader{}, 0, fmt.Errorf("too short")
	}
	if outerPayloadSize := binary.LittleEndian.Uint32(data[0:4]); outerPayloadSize != 4 {
		return asarHeader{}, 0, fmt.Errorf("invalid outer pickle payload size %d", outerPayloadSize)
	}
	headerSize := binary.LittleEndian.Uint32(data[4:8])
	if headerSize < 8 || uint64(headerSize) > uint64(maxASARHeaderBytes+11) || uint64(headerSize)+8 > uint64(len(data)) {
		return asarHeader{}, 0, fmt.Errorf("invalid header size %d", headerSize)
	}
	headerPickle := data[8 : 8+headerSize]
	headerPayloadSize := binary.LittleEndian.Uint32(headerPickle[0:4])
	if headerPayloadSize != headerSize-4 {
		return asarHeader{}, 0, fmt.Errorf("invalid header pickle payload size %d", headerPayloadSize)
	}
	jsonSize := binary.LittleEndian.Uint32(headerPickle[4:8])
	if jsonSize == 0 || jsonSize > maxASARHeaderBytes {
		return asarHeader{}, 0, fmt.Errorf("invalid header JSON size %d", jsonSize)
	}
	alignedJSONSize := (uint64(jsonSize) + 3) &^ uint64(3)
	if uint64(headerPayloadSize) != 4+alignedJSONSize || 8+alignedJSONSize != uint64(len(headerPickle)) {
		return asarHeader{}, 0, fmt.Errorf("header JSON pickle size mismatch")
	}
	headerJSON := headerPickle[8 : 8+jsonSize]
	for _, padding := range headerPickle[8+jsonSize:] {
		if padding != 0 {
			return asarHeader{}, 0, fmt.Errorf("non-zero header JSON pickle padding")
		}
	}
	if err := validateASARHeaderStructure(headerJSON); err != nil {
		return asarHeader{}, 0, err
	}
	header, err := decodeASARHeader(headerJSON)
	if err != nil {
		return asarHeader{}, 0, err
	}
	return header, int64(8 + headerSize), nil
}

// looksLikeASAR recognizes the bounded Pickle/JSON envelope and validates the
// deterministic entry prefix that Maratus can traverse. This allows renamed
// ASARs to be typed from content without trusting a suffix.
func looksLikeASAR(data []byte) bool {
	header, base, err := parseAsarHeader(data)
	if err != nil || base < 0 || base > int64(len(data)) {
		return false
	}
	items, _ := flattenAsar(header, MaxArchiveEntries)
	payloadSize := int64(len(data)) - base
	for _, item := range items {
		if item.UnsafeName || item.OversizedName {
			return false
		}
		if item.HasLink || item.Unpacked {
			continue
		}
		if item.Size < 0 {
			return false
		}
		offset, err := strconv.ParseInt(item.Offset, 10, 64)
		if err != nil || offset < 0 || offset > payloadSize || item.Size > payloadSize-offset {
			return false
		}
	}
	return true
}

func validateASARHeaderStructure(data []byte) error {
	depth := 0
	tokens := 0
	inString := false
	escaped := false
	for _, current := range data {
		if inString {
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		switch current {
		case '"':
			inString = true
		case '{', '[':
			depth++
			tokens++
			if depth > maxASARHeaderDepth {
				return fmt.Errorf("header JSON exceeds nesting depth %d", maxASARHeaderDepth)
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		case ':', ',':
			tokens++
		}
		if tokens > maxASARHeaderTokens {
			return fmt.Errorf("header JSON exceeds structural token limit %d", maxASARHeaderTokens)
		}
	}
	return nil
}

type asarFlatEntry struct {
	Name          string
	UnsafeName    bool
	OversizedName bool
	Link          string
	HasLink       bool
	Offset        string
	Size          int64
	Unpacked      bool
	Executable    bool
}

type asarWalkFrame struct {
	prefix string
	files  map[string]asarEntry
	names  []string
	next   int
}

func flattenAsar(header asarHeader, limit int) ([]asarFlatEntry, bool) {
	if limit <= 0 {
		limit = MaxArchiveEntries
	}
	var out []asarFlatEntry
	visited := 0
	frames := []asarWalkFrame{newAsarWalkFrame("", header.Files)}
	for len(frames) > 0 {
		frame := &frames[len(frames)-1]
		if frame.next >= len(frame.names) {
			frames = frames[:len(frames)-1]
			continue
		}
		// Count every header entry, including directories. Otherwise a deep
		// directory-only tree can bypass the leaf-entry limit and recurse for
		// attacker-controlled work.
		if visited >= limit {
			return out, true
		}
		name := frame.names[frame.next]
		frame.next++
		visited++
		entry := frame.files[name]
		if !canonicalASARComponent(name) {
			out = append(out, asarFlatEntry{Name: name, UnsafeName: true})
			continue
		}
		if len(name) > MaxArchiveNameBytes || (frame.prefix != "" && len(frame.prefix)+1+len(name) > MaxArchiveNameBytes) {
			out = append(out, asarFlatEntry{OversizedName: true})
			continue
		}
		entryPath := name
		if frame.prefix != "" {
			entryPath = frame.prefix + "/" + name
		}
		if entry.HasLink {
			out = append(out, asarFlatEntry{
				Name:    entryPath,
				Link:    entry.Link,
				HasLink: true,
			})
			continue
		}
		if entry.Files != nil {
			if len(entry.Files) > 0 {
				frames = append(frames, newAsarWalkFrame(entryPath, entry.Files))
			}
			continue
		}
		out = append(out, asarFlatEntry{
			Name:       entryPath,
			Link:       entry.Link,
			HasLink:    entry.HasLink,
			Offset:     entry.Offset,
			Size:       entry.Size,
			Unpacked:   entry.Unpacked,
			Executable: entry.Executable,
		})
	}
	return out, false
}

func canonicalASARComponent(name string) bool {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return false
	}
	for _, value := range name {
		if value < 0x20 || value == 0x7f {
			return false
		}
	}
	return true
}

func newAsarWalkFrame(prefix string, files map[string]asarEntry) asarWalkFrame {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return asarWalkFrame{prefix: prefix, files: files, names: names}
}
