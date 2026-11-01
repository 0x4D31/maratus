package extract

import (
	"bytes"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxPythonSourceBuildArchives     = 32
	maxPythonSourceBuildHeaderBytes  = 64 << 10
	maxPythonSourceBuildHeaderLines  = 512
	maxPythonSourceBuildHeaderLine   = 8 << 10
	maxPythonSourceBuildIdentity     = 512
	maxPythonSourceBuildVersionParts = 16
	maxPythonSourceBuildVersionPart  = 32

	pythonSourceBuildAnalysisArea = "python-source-build-activation"
	pythonSourceBuildProfile      = "pip-26.1.2-setuptools-legacy"
	pythonSourceBuildBackend      = "setuptools.build_meta:__legacy__"
)

type pythonSourceBuildDisposition uint8

const (
	pythonSourceBuildRecognized pythonSourceBuildDisposition = iota + 1
	pythonSourceBuildUnsupported
	pythonSourceBuildMalformed
)

type pythonSourceBuildMember struct {
	node         artifact.Node
	content      artifact.Content
	contentCount int
	relative     string
}

type pythonSourceBuildHeader struct {
	value  string
	line   int
	offset int
}

type pythonSourceBuildMetadata struct {
	metadataVersion pythonSourceBuildHeader
	name            pythonSourceBuildHeader
	version         pythonSourceBuildHeader
}

// pythonSourceBuildResult is the single authoritative outcome for one
// candidate archive. Callers must not independently reinterpret members after
// this result has failed closed.
type pythonSourceBuildResult struct {
	disposition pythonSourceBuildDisposition
	reason      string
	archive     artifact.Node
	setup       pythonSourceBuildMember
	pkgInfo     pythonSourceBuildMember
	topDir      string
	metadata    pythonSourceBuildMetadata
}

// preparePythonSourceBuild recognizes only the current pip fallback profile
// for a complete, root-level, gzip-compressed legacy sdist. It never invokes a
// frontend or backend. The resulting root means setup.py is a host-selected
// entry if this exact sdist reaches the pinned source-build profile; it does
// not claim that selection, build success, or installation occurred.
func preparePythonSourceBuild(
	graph *behavior.Graph,
	artifacts artifact.Graph,
	contents []artifact.Content,
	scopeByNode map[string]string,
	rootEligibility map[string]bool,
) {
	archives := boundedPythonSourceBuildArchives(artifacts.Nodes)
	for _, archive := range archives {
		if !pythonSourceBuildCandidateHint(archive, artifacts.Nodes) {
			continue
		}
		result := recognizePythonSourceBuild(archive, artifacts.Nodes, contents)
		if result.disposition != pythonSourceBuildRecognized {
			addPartialCoverageOnce(graph, archive.ID, pythonSourceBuildAnalysisArea, result.reason)
			continue
		}
		emitPythonSourceBuild(graph, result, scopeByNode, rootEligibility)
	}
}

func boundedPythonSourceBuildArchives(nodes []artifact.Node) []artifact.Node {
	archives := make([]artifact.Node, 0, maxPythonSourceBuildArchives)
	for _, node := range nodes {
		if node.ParentID != "" || node.Kind != "gzip" || node.MediaType != "application/gzip" {
			continue
		}
		base := path.Base(strings.ReplaceAll(node.LogicalPath, "\\", "/"))
		if !strings.HasSuffix(base, ".tar.gz") {
			continue
		}
		archives = append(archives, node)
		sort.SliceStable(archives, func(i, j int) bool {
			if archives[i].LogicalPath != archives[j].LogicalPath {
				return archives[i].LogicalPath < archives[j].LogicalPath
			}
			return archives[i].ID < archives[j].ID
		})
		if len(archives) > maxPythonSourceBuildArchives {
			archives = archives[:maxPythonSourceBuildArchives]
		}
	}
	return archives
}

func pythonSourceBuildCandidateHint(archive artifact.Node, nodes []artifact.Node) bool {
	prefix := archive.LogicalPath + "!"
	nodesByID := pythonSourceBuildNodesByID(nodes)
	for _, node := range nodes {
		if !strings.HasPrefix(node.LogicalPath, prefix) {
			continue
		}
		relative := strings.TrimPrefix(node.LogicalPath, prefix)
		if relative == "" ||
			!pythonSourceBuildTarEntryOwnedBy(node, archive.ID, nodesByID) && node.ParentID != archive.ID {
			continue
		}
		switch asciiFoldPythonSourceBuildPath(path.Base(relative)) {
		case "pkg-info", "setup.py", "pyproject.toml":
			return true
		}
	}
	return false
}

func recognizePythonSourceBuild(archive artifact.Node, nodes []artifact.Node, contents []artifact.Content) pythonSourceBuildResult {
	result := pythonSourceBuildResult{archive: archive}
	malformed := func(reason string) pythonSourceBuildResult {
		result.disposition = pythonSourceBuildMalformed
		result.reason = reason
		return result
	}
	unsupported := func(reason string) pythonSourceBuildResult {
		result.disposition = pythonSourceBuildUnsupported
		result.reason = reason
		return result
	}

	if archive.ParentID != "" {
		return unsupported("a nested source-distribution candidate is inventory only; containment does not establish frontend source-build selection, so no execution root was created")
	}
	if archive.Kind != "gzip" || archive.MediaType != "application/gzip" ||
		archive.AnalyzeStatus != "analyzed" || archive.CoverageDetail != "" {
		return malformed("the candidate gzip TAR inventory was incomplete or not fully analyzed; legacy source-distribution identity and source-build activation were not established")
	}
	if (archive.DeclaredEntryCount == nil) != (archive.ModeledEntryCount == nil) ||
		archive.DeclaredEntryCount != nil && *archive.DeclaredEntryCount != *archive.ModeledEntryCount {
		return malformed("the candidate gzip TAR declared and modeled entry counts do not establish a complete inventory; legacy source-distribution identity and source-build activation were not established")
	}
	base := path.Base(strings.ReplaceAll(archive.LogicalPath, "\\", "/"))
	if len(base) > artifact.MaxArchiveNameBytes || !strings.HasSuffix(base, ".tar.gz") {
		return unsupported("the candidate does not use the supported normalized .tar.gz source-distribution filename form; no source-build root was created")
	}
	stem := strings.TrimSuffix(base, ".tar.gz")
	if stem == "" || len(stem) > maxPythonSourceBuildIdentity {
		return unsupported("the candidate source-distribution filename identity is empty or exceeds the supported bound; no source-build root was created")
	}

	members, memberDisposition, reason := collectPythonSourceBuildMembers(archive, nodes, contents)
	if reason != "" {
		result.disposition = memberDisposition
		result.reason = reason
		return result
	}
	if len(members) == 0 {
		return malformed("the candidate gzip TAR has no retained file members; legacy source-distribution identity and source-build activation were not established")
	}
	topDir := ""
	pathCounts := make(map[string]int, len(members))
	foldedPaths := make(map[string]string, len(members))
	for _, member := range members {
		parts := strings.SplitN(member.relative, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return malformed("the candidate gzip TAR does not contain every retained file beneath one top-level distribution directory; no source-build root was created")
		}
		if topDir == "" {
			topDir = parts[0]
		} else if topDir != parts[0] {
			return malformed("the candidate gzip TAR contains more than one top-level file directory; source-distribution identity is ambiguous and no source-build root was created")
		}
		pathCounts[member.relative]++
		if pathCounts[member.relative] > 1 {
			return malformed("the candidate gzip TAR contains a duplicate normalized member path; source-distribution identity is ambiguous and no source-build root was created")
		}
		folded := asciiFoldPythonSourceBuildPath(member.relative)
		if prior := foldedPaths[folded]; prior != "" && prior != member.relative {
			return malformed("the candidate gzip TAR contains ASCII case-fold-colliding member paths; extraction identity is ambiguous on common macOS filesystems and no source-build root was created")
		}
		foldedPaths[folded] = member.relative
	}

	pkgPath := topDir + "/PKG-INFO"
	setupPath := topDir + "/setup.py"
	pyprojectPath := topDir + "/pyproject.toml"
	for _, marker := range []string{pkgPath, setupPath, pyprojectPath} {
		if actual := foldedPaths[asciiFoldPythonSourceBuildPath(marker)]; actual != "" && actual != marker {
			return malformed("the candidate gzip TAR contains a case-variant top-level Python distribution marker; extraction identity is ambiguous on common macOS filesystems and no source-build root was created")
		}
	}
	if pathCounts[pyprojectPath] != 0 {
		return unsupported("a root-level pyproject.toml requires backend selection outside profile " + pythonSourceBuildProfile + "; no source-build root was created")
	}
	if pathCounts[pkgPath] != 1 || pathCounts[setupPath] != 1 {
		return malformed("the candidate gzip TAR lacks one unambiguous top-level PKG-INFO and setup.py pair; legacy source-build activation was not established")
	}
	for _, member := range members {
		switch member.relative {
		case pkgPath:
			result.pkgInfo = member
		case setupPath:
			result.setup = member
		}
	}
	if !pythonSourceBuildTextMember(result.pkgInfo, false) {
		return malformed("the exact top-level PKG-INFO bytes were not retained as analyzed NUL-free UTF-8 text; source-distribution identity was not established")
	}
	if !pythonSourceBuildTextMember(result.setup, true) {
		return malformed("the exact top-level setup.py bytes were not retained as an analyzed Python text representation; no source-build root was created")
	}

	metadata, metadataDisposition, reason := parsePythonSourceBuildMetadata(result.pkgInfo.content.Data)
	if reason != "" {
		result.disposition = metadataDisposition
		result.reason = reason
		return result
	}
	normalizedName, ok := normalizePythonSourceBuildName(metadata.name.value)
	if !ok {
		return malformed("PKG-INFO Name is not a supported bounded distribution identity; source-distribution identity was not established")
	}
	if !supportedPythonSourceBuildVersion(metadata.version.value) {
		return unsupported("PKG-INFO Version requires normalization outside the closed source-distribution identity subset; no source-build root was created")
	}
	expectedStem := normalizedName + "-" + metadata.version.value
	if stem != expectedStem || topDir != expectedStem {
		return malformed("the .tar.gz filename, top-level directory, and normalized PKG-INFO Name/Version do not agree exactly; source-distribution identity was not established")
	}

	result.disposition = pythonSourceBuildRecognized
	result.topDir = topDir
	result.metadata = metadata
	return result
}

func collectPythonSourceBuildMembers(
	archive artifact.Node,
	nodes []artifact.Node,
	contents []artifact.Content,
) ([]pythonSourceBuildMember, pythonSourceBuildDisposition, string) {
	prefix := archive.LogicalPath + "!"
	nodesByID := pythonSourceBuildNodesByID(nodes)
	members := make([]pythonSourceBuildMember, 0, min(len(nodes), artifact.MaxArchiveEntries))
	memberIDs := make(map[string]int, min(len(nodes), artifact.MaxArchiveEntries))
	for _, node := range nodes {
		if !pythonSourceBuildTarEntryOwnedBy(node, archive.ID, nodesByID) {
			continue
		}
		if !strings.HasPrefix(node.LogicalPath, prefix) {
			return nil, pythonSourceBuildMalformed, "a scanner-authoritative TAR entry is not owned by the candidate archive's retained logical namespace; source-distribution identity is ambiguous and no source-build root was created"
		}
		relative := strings.TrimPrefix(node.LogicalPath, prefix)
		if relative == "" {
			return nil, pythonSourceBuildMalformed, "a scanner-authoritative TAR entry has an empty retained path; source-distribution identity is ambiguous and no source-build root was created"
		}
		if len(members) >= artifact.MaxArchiveEntries {
			return nil, pythonSourceBuildUnsupported, fmt.Sprintf("source-distribution member limit %d reached; complete member identity and source-build activation were not established", artifact.MaxArchiveEntries)
		}
		if node.ID == "" || memberIDs[node.ID] != 0 {
			return nil, pythonSourceBuildMalformed, "the candidate gzip TAR contains an empty or duplicate retained member identity; source-distribution identity is ambiguous and no source-build root was created"
		}
		memberIDs[node.ID] = len(members) + 1
		members = append(members, pythonSourceBuildMember{node: node, relative: relative})
	}
	if len(members) == 0 {
		return nil, pythonSourceBuildUnsupported, "the gzip payload did not yield scanner-authoritative tar-entry members owned by this archive; gzip-decoded CPIO and other non-TAR payloads are not source distributions under the supported profile"
	}

	contentCounts := make(map[string]int, len(members))
	var archiveContents []artifact.Content
	for _, content := range contents {
		if content.NodeID == archive.ID {
			archiveContents = append(archiveContents, content)
			continue
		}
		position := memberIDs[content.NodeID]
		if position == 0 {
			continue
		}
		contentCounts[content.NodeID]++
		if contentCounts[content.NodeID] == 1 {
			members[position-1].content = content
		}
	}
	if len(archiveContents) != 1 || archiveContents[0].RawFeaturesOnly ||
		len(archiveContents[0].Data) < 2 || archiveContents[0].Data[0] != 0x1f || archiveContents[0].Data[1] != 0x8b {
		return nil, pythonSourceBuildMalformed, "the candidate archive lacks one exact retained gzip representation; legacy source-distribution identity was not established"
	}
	for index := range members {
		members[index].contentCount = contentCounts[members[index].node.ID]
	}
	sort.SliceStable(members, func(i, j int) bool {
		if members[i].relative != members[j].relative {
			return members[i].relative < members[j].relative
		}
		return members[i].node.ID < members[j].node.ID
	})
	return members, pythonSourceBuildRecognized, ""
}

func pythonSourceBuildTextMember(member pythonSourceBuildMember, requirePython bool) bool {
	content := member.content
	if member.node.AnalyzeStatus != "analyzed" || member.node.CoverageDetail != "" ||
		member.contentCount != 1 || content.NodeID == "" || content.RawFeaturesOnly || content.MediaType != "text/plain" ||
		!utf8.Valid(content.Data) || bytes.IndexByte(content.Data, 0) >= 0 {
		return false
	}
	if !requirePython {
		// Archive mode bits can make metadata look executable to the generic
		// detector. Exact placement plus retained text bytes, not that
		// attacker-controlled mode bit, establishes PKG-INFO here.
		return true
	}
	return content.Kind == "script" || content.Kind == "text"
}

func pythonSourceBuildNodesByID(nodes []artifact.Node) map[string]artifact.Node {
	result := make(map[string]artifact.Node, len(nodes))
	for _, node := range nodes {
		if node.ID != "" {
			result[node.ID] = node
		}
	}
	return result
}

func pythonSourceBuildTarEntryOwnedBy(node artifact.Node, archiveID string, nodesByID map[string]artifact.Node) bool {
	if node.Provenance != "tar-entry" || node.ID == "" || archiveID == "" {
		return false
	}
	current := node
	seen := map[string]bool{}
	for depth := 0; depth < 64; depth++ {
		if current.ParentID == archiveID {
			return true
		}
		if current.ParentID == "" || seen[current.ParentID] {
			return false
		}
		seen[current.ParentID] = true
		parent, ok := nodesByID[current.ParentID]
		if !ok {
			return false
		}
		if pythonSourceBuildContainerKind(parent.Kind) {
			return false
		}
		current = parent
	}
	return false
}

func pythonSourceBuildContainerKind(kind string) bool {
	switch kind {
	case "zip", "java-archive", "python-wheel", "nuget-package", "vsix",
		"gzip", "tar", "cpio", "asar", "pkg", "dmg", "carchive":
		return true
	default:
		return false
	}
}

func asciiFoldPythonSourceBuildPath(value string) string {
	var folded strings.Builder
	folded.Grow(len(value))
	for index := 0; index < len(value); index++ {
		current := value[index]
		if current >= 'A' && current <= 'Z' {
			current += 'a' - 'A'
		}
		folded.WriteByte(current)
	}
	return folded.String()
}

func parsePythonSourceBuildMetadata(data []byte) (pythonSourceBuildMetadata, pythonSourceBuildDisposition, string) {
	var metadata pythonSourceBuildMetadata
	if len(data) == 0 || len(data) > maxPythonSourceBuildHeaderBytes ||
		!utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return metadata, pythonSourceBuildMalformed, fmt.Sprintf("PKG-INFO headers are empty, malformed, or exceed the %d-byte bound; source-distribution identity was not established", maxPythonSourceBuildHeaderBytes)
	}
	relevant := map[string]*pythonSourceBuildHeader{
		"metadata-version": &metadata.metadataVersion,
		"name":             &metadata.name,
		"version":          &metadata.version,
	}
	seen := map[string]bool{}
	offset := 0
	for lineNumber := 1; offset < len(data); lineNumber++ {
		if lineNumber > maxPythonSourceBuildHeaderLines {
			return pythonSourceBuildMetadata{}, pythonSourceBuildUnsupported, fmt.Sprintf("PKG-INFO header line limit %d reached; source-distribution identity was not established", maxPythonSourceBuildHeaderLines)
		}
		end := bytes.IndexByte(data[offset:], '\n')
		next := len(data)
		if end >= 0 {
			end += offset
			next = end + 1
		} else {
			end = len(data)
		}
		line := data[offset:end]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) > maxPythonSourceBuildHeaderLine {
			return pythonSourceBuildMetadata{}, pythonSourceBuildUnsupported, fmt.Sprintf("PKG-INFO header line exceeds the %d-byte bound; source-distribution identity was not established", maxPythonSourceBuildHeaderLine)
		}
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			return pythonSourceBuildMetadata{}, pythonSourceBuildUnsupported, "folded PKG-INFO headers are outside the closed metadata subset; source-distribution identity was not established"
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || !pythonSourceBuildHeaderName(line[:colon]) {
			return pythonSourceBuildMetadata{}, pythonSourceBuildMalformed, "PKG-INFO contains a malformed header line; source-distribution identity was not established"
		}
		key := strings.ToLower(string(line[:colon]))
		target, wanted := relevant[key]
		if wanted {
			if seen[key] {
				return pythonSourceBuildMetadata{}, pythonSourceBuildMalformed, "PKG-INFO contains duplicate identity headers; source-distribution identity was not established"
			}
			rawValue := line[colon+1:]
			leading := len(rawValue) - len(bytes.TrimLeft(rawValue, " \t"))
			value := string(bytes.TrimRight(rawValue[leading:], " \t"))
			if value == "" || len(value) > maxPythonSourceBuildIdentity || pythonSourceBuildControlByte(value) {
				return pythonSourceBuildMetadata{}, pythonSourceBuildMalformed, "PKG-INFO contains an empty, oversized, or invalid identity header; source-distribution identity was not established"
			}
			*target = pythonSourceBuildHeader{value: value, line: lineNumber, offset: offset + colon + 1 + leading}
			seen[key] = true
		}
		offset = next
	}
	if !seen["metadata-version"] || !seen["name"] || !seen["version"] {
		return pythonSourceBuildMetadata{}, pythonSourceBuildMalformed, "PKG-INFO lacks one unambiguous Metadata-Version, Name, and Version header set; source-distribution identity was not established"
	}
	switch metadata.metadataVersion.value {
	case "1.0", "1.1", "1.2", "2.1", "2.2", "2.3", "2.4", "2.5":
	default:
		return pythonSourceBuildMetadata{}, pythonSourceBuildUnsupported, "PKG-INFO Metadata-Version is outside the supported pinned metadata vocabulary; source-distribution identity was not established"
	}
	return metadata, pythonSourceBuildRecognized, ""
}

func pythonSourceBuildHeaderName(value []byte) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, current := range value {
		if current != '-' &&
			(current < 'A' || current > 'Z') &&
			(current < 'a' || current > 'z') &&
			(current < '0' || current > '9') {
			return false
		}
	}
	return true
}

func pythonSourceBuildControlByte(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return true
		}
	}
	return false
}

func normalizePythonSourceBuildName(value string) (string, bool) {
	if value == "" || len(value) > maxPythonSourceBuildIdentity {
		return "", false
	}
	var normalized strings.Builder
	normalized.Grow(len(value))
	separator := false
	for index := 0; index < len(value); index++ {
		current := value[index]
		switch {
		case current >= 'A' && current <= 'Z':
			normalized.WriteByte(current + ('a' - 'A'))
			separator = false
		case current >= 'a' && current <= 'z' || current >= '0' && current <= '9':
			normalized.WriteByte(current)
			separator = false
		case current == '-' || current == '_' || current == '.':
			if index == 0 || index == len(value)-1 {
				return "", false
			}
			if !separator {
				normalized.WriteByte('_')
				separator = true
			}
		default:
			return "", false
		}
	}
	return normalized.String(), normalized.Len() > 0
}

func supportedPythonSourceBuildVersion(value string) bool {
	if value == "" || len(value) > maxPythonSourceBuildIdentity {
		return false
	}
	// This first adapter deliberately supports only an already-canonical PEP
	// 440 final release: one to sixteen dot-separated decimal components, each
	// at most 32 digits, with no leading zero except the canonical component
	// "0". Epochs and pre/post/dev/local forms require normalization and remain
	// explicitly unsupported.
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > maxPythonSourceBuildVersionParts {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > maxPythonSourceBuildVersionPart ||
			len(part) > 1 && part[0] == '0' {
			return false
		}
		for index := 0; index < len(part); index++ {
			if part[index] < '0' || part[index] > '9' {
				return false
			}
		}
	}
	return true
}

func emitPythonSourceBuild(
	graph *behavior.Graph,
	result pythonSourceBuildResult,
	scopeByNode map[string]string,
	rootEligibility map[string]bool,
) {
	setupScope := scopeByNode[result.setup.node.ID]
	evidence := []behavior.Evidence{
		{
			NodeID:  result.archive.ID,
			Logical: result.archive.LogicalPath,
			Method:  "python-source-build-recognizer",
			Kind:    "python-sdist-filename",
			Value:   path.Base(strings.ReplaceAll(result.archive.LogicalPath, "\\", "/")),
		},
		{
			NodeID:      result.archive.ID,
			Logical:     result.archive.LogicalPath,
			Offset:      0,
			OffsetKnown: true,
			Method:      "python-source-build-recognizer",
			Kind:        "python-sdist-gzip-representation",
			Value:       "gzip TAR",
		},
		{
			NodeID:  result.archive.ID,
			Logical: result.archive.LogicalPath,
			Method:  "python-source-build-recognizer",
			Kind:    "verified-python-sdist-envelope",
			Value:   result.topDir + "; complete retained inventory; no root pyproject.toml",
		},
		pythonSourceBuildHeaderEvidence(result.pkgInfo.content, result.metadata.metadataVersion, "python-core-metadata-version"),
		pythonSourceBuildHeaderEvidence(result.pkgInfo.content, result.metadata.name, "python-distribution-name"),
		pythonSourceBuildHeaderEvidence(result.pkgInfo.content, result.metadata.version, "python-distribution-version"),
		{
			NodeID:   result.setup.node.ID,
			ScopeID:  setupScope,
			Logical:  result.setup.content.LogicalPath,
			Physical: result.setup.content.PhysicalPath,
			Method:   "python-source-build-recognizer",
			Kind:     "python-source-build-entry",
			Value:    result.setup.relative,
		},
	}
	evidenceIDs := make([]string, 0, len(evidence))
	for _, item := range evidence {
		evidenceID := graph.AddEvidence(item)
		if evidenceID == "" {
			addPartialCoverageOnce(
				graph,
				result.archive.ID,
				pythonSourceBuildAnalysisArea,
				"source-distribution evidence could not be retained within the analysis budget; no source-build root was created",
			)
			return
		}
		evidenceIDs = append(evidenceIDs, evidenceID)
	}
	if !graph.AddArtifactProperty(behavior.ArtifactProperty{
		NodeID:      result.archive.ID,
		Kind:        "python-distribution-format",
		Value:       "source-distribution",
		EvidenceIDs: evidenceIDs,
		Support:     behavior.SupportCorroborated,
	}) {
		addPartialCoverageOnce(
			graph,
			result.archive.ID,
			pythonSourceBuildAnalysisArea,
			"the behavior graph budget prevented retaining the recognized source-distribution property and source-build root",
		)
		return
	}
	if !rootEligibility[result.archive.ID] || !rootEligibility[result.setup.node.ID] || setupScope == "" {
		addPartialCoverageOnce(
			graph,
			result.archive.ID,
			pythonSourceBuildAnalysisArea,
			"the legacy source distribution was recognized, but its retained topology or scope does not permit an independent source-build execution root",
		)
		return
	}
	rootID := graph.AddExecutionRoot(behavior.ExecutionRoot{
		Kind:              "python-source-build",
		DeclarationNodeID: result.archive.ID,
		StartNodeID:       result.setup.node.ID,
		StartScopeID:      setupScope,
		Name:              pythonSourceBuildBackend,
		Interpreter:       "python",
		EvidenceIDs:       evidenceIDs,
	})
	if rootID == "" {
		addPartialCoverageOnce(
			graph,
			result.archive.ID,
			pythonSourceBuildAnalysisArea,
			"the behavior graph budget prevented retaining the conditional source-build execution root",
		)
		return
	}
	addPartialCoverageOnce(
		graph,
		result.setup.node.ID,
		pythonSourceBuildAnalysisArea,
		"profile "+pythonSourceBuildProfile+" establishes only a conditional source-build entry through "+pythonSourceBuildBackend+"; it does not prove source-vs-wheel/cache selection or requirement choice, build-requirement availability, hook order/count/success, build success, or installation",
	)
}

func pythonSourceBuildHeaderEvidence(content artifact.Content, header pythonSourceBuildHeader, kind string) behavior.Evidence {
	return behavior.Evidence{
		NodeID:      content.NodeID,
		ScopeID:     content.ScopeID,
		Logical:     content.LogicalPath,
		Physical:    content.PhysicalPath,
		Line:        header.line,
		Offset:      int64(header.offset),
		OffsetKnown: true,
		Method:      "python-source-build-recognizer",
		Kind:        kind,
		Value:       header.value,
	}
}
