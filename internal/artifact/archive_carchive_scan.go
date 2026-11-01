package artifact

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

const cArchiveMemberProvenance = "carchive-toc-record"

type scannedCArchiveCandidate struct {
	candidate cArchiveCandidate
	nodeID    string
	logical   string
}

type cArchiveDecodeBudget struct {
	decodedBytesAttempted int64
	compressedBytesRead   int64
}

// cArchiveMemberDecodeKey contains every TOC field that can change the result
// of decoding a payload extent. Exact aliases with the same key share bounded
// decode work, but each selected TOC record still receives its own artifact
// node and retained-content accounting.
type cArchiveMemberDecodeKey struct {
	payload          cArchiveExtent
	compressedLength uint32
	declaredSize     uint32
	compressionFlag  byte
}

type cArchiveMemberDecodeResult struct {
	decoded []byte
	detail  string
}

type cArchiveMaterializeStats struct {
	modeled        int
	omitted        int
	skipped        int
	rawOnly        int
	decodeFailures int
}

type cArchiveMemberSelection struct {
	index      int
	anchorTier int
	typeRank   int
	digest     [sha256.Size]byte
	ordinal    int
}

type cArchiveLoaderTarget struct {
	childID          string
	member           cArchiveMember
	executionOrdinal int
}

// scanCArchives discovers neutral CArchive envelopes in an arbitrary carrier.
// The producer recognizer is deliberately separate: an envelope can be
// inventoried and expanded without claiming PyInstaller or executable Python
// semantics.
func (s *scanner) scanCArchives(carrierID, logical string, data []byte, carrierKind string, depth int) bool {
	parsed := parseCArchives(data)
	if len(parsed.Candidates) == 0 {
		if parsed.CandidateValidationTruncated && parsed.PlausibleEnvelopeCount > 0 {
			detail := fmt.Sprintf("CArchive candidate selection limit reached; %d plausible envelopes were not validated", parsed.OmittedPlausibleEnvelopeOffsets)
			s.markNodePartial(carrierID, detail)
			s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
		}
		return false
	}

	pyInstallerRecognition, pyInstaller := recognizePyInstallerFacade(parsed, data, carrierKind)
	if pyInstaller {
		setArtifactPackagingTechnology(&s.graph, carrierID, "PyInstaller", pyInstallerRecognition.evidence)
	}

	scanned := make([]scannedCArchiveCandidate, 0, len(parsed.Candidates))
	packageDigests, omittedPackageDigests := cArchiveCandidateDigests(data, parsed.Candidates, s.options.MaxArchiveBytes)
	for _, candidate := range parsed.Candidates {
		candidateLogical, ok := cArchiveCandidateLogicalPath(logical, candidate)
		if !ok || !s.reserveNode(candidateLogical, "", carrierID) {
			detail := "embedded CArchive candidate path could not be modeled within artifact limits"
			s.markNodePartial(carrierID, detail)
			continue
		}
		status, coverage := cArchiveCandidateInitialStatus(candidate)
		digest := packageDigests[candidate.Package]
		if omittedPackageDigests[candidate.Package] {
			status = "partial"
			detail := fmt.Sprintf("candidate package SHA-256 omitted because shared CArchive hash-work limit %d would be exceeded", s.options.MaxArchiveBytes)
			if coverage == "" {
				coverage = detail
			} else {
				coverage += "; " + detail
			}
		}
		var declaredEntryCount *int
		if !candidate.TOCValidationLimited && !candidate.MalformedTOCTail {
			declaredEntryCount = cArchiveIntPointer(len(candidate.Members))
		}
		nodeID := s.graph.AddNode(Node{
			ParentID:           carrierID,
			LogicalPath:        candidateLogical,
			Kind:               "carchive",
			MediaType:          "application/x-carchive",
			Size:               uint64ToInt64(candidate.Package.Length),
			SHA256:             digest,
			Provenance:         "embedded-carchive/" + string(candidate.CookieLayout),
			SourceRole:         "unknown",
			DeclaredEntryCount: declaredEntryCount,
			ModeledEntryCount:  cArchiveIntPointer(0),
			AnalyzeStatus:      status,
			CoverageDetail:     coverage,
		})
		s.graph.AddEdge(carrierID, nodeID, "contains")
		scanned = append(scanned, scannedCArchiveCandidate{candidate: candidate, nodeID: nodeID, logical: candidateLogical})
	}
	if len(scanned) == 0 {
		return true
	}
	if parsed.CandidateValidationTruncated || parsed.OmittedMagicOffsets > 0 || parsed.OmittedPlausibleEnvelopeOffsets > 0 {
		detail := cArchiveDiscoveryCoverageDetail(parsed)
		s.markNodePartial(carrierID, detail)
		for _, item := range scanned {
			s.markNodePartial(item.nodeID, detail)
		}
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
	}

	if s.options.DisableContainerExpansion || depth >= s.options.MaxArchiveDepth {
		hasMembers := false
		for _, item := range scanned {
			if len(item.candidate.Members) > 0 {
				hasMembers = true
				break
			}
		}
		if !hasMembers {
			return true
		}
		detail := "embedded CArchive members not expanded"
		if s.options.DisableContainerExpansion {
			detail += " because archive expansion is disabled"
		} else {
			detail += fmt.Sprintf(" because archive depth limit %d was reached", s.options.MaxArchiveDepth)
		}
		for _, item := range scanned {
			if len(item.candidate.Members) > 0 {
				s.markNodePartial(item.nodeID, detail)
			}
		}
		s.markNodePartial(carrierID, detail)
		s.addDiagnostic(fmt.Sprintf("%s: %s", logical, detail))
		return true
	}

	expand := selectCArchiveCandidatesForExpansion(scanned)
	decodeBudget := &cArchiveDecodeBudget{}
	for index := range scanned {
		item := &scanned[index]
		if !expand[index] {
			s.markNodePartial(item.nodeID, "member expansion skipped because this package overlaps a later selected CArchive candidate")
			continue
		}
		attributed := pyInstaller && pyInstallerRecognition.identity.matches(item.candidate)
		var loaderEvidence []LocatedArtifactEvidence
		if attributed {
			loaderEvidence = pyInstallerRecognition.evidence
		}
		stats := s.materializeCArchiveMembers(carrierID, *item, data, depth+1, attributed, loaderEvidence, decodeBudget)
		updateCArchiveNodeInventory(&s.graph, item.nodeID, stats.modeled)
		if stats.omitted > 0 {
			s.markNodePartial(item.nodeID, fmt.Sprintf("modeled %d of %d parsed TOC records; omissions reflect deterministic whole-TOC selection or artifact limits", stats.modeled, len(item.candidate.Members)))
		}
		if stats.skipped > 0 {
			s.markNodePartial(item.nodeID, fmt.Sprintf("%d selected TOC records were inventoried without payload decoding", stats.skipped))
		}
		if stats.decodeFailures > 0 {
			s.markNodePartial(item.nodeID, fmt.Sprintf("%d selected TOC records could not be decoded exactly", stats.decodeFailures))
		}
		if stats.rawOnly > 0 {
			s.markNodePartial(item.nodeID, fmt.Sprintf("%d selected Python/PYZ representations were retained as raw features without semantic decoding", stats.rawOnly))
		}
	}
	return true
}

func cArchiveExtentSHA256(data []byte, extent cArchiveExtent) string {
	end, ok := extent.end()
	if !ok || extent.Offset > uint64(len(data)) || end > uint64(len(data)) {
		return ""
	}
	return sha256Hex(data[int(extent.Offset):int(end)])
}

func cArchiveCandidateDigests(data []byte, candidates []cArchiveCandidate, maxWork int64) (map[cArchiveExtent]string, map[cArchiveExtent]bool) {
	digests := make(map[cArchiveExtent]string, len(candidates))
	omitted := make(map[cArchiveExtent]bool)
	work := int64(0)
	// Match expansion priority: later candidates receive bounded hash work
	// before earlier overlapping or nested interpretations.
	for index := len(candidates) - 1; index >= 0; index-- {
		extent := candidates[index].Package
		if _, seen := digests[extent]; seen || omitted[extent] {
			continue
		}
		if archiveBudgetExceeded(work, extent.Length, maxWork) {
			omitted[extent] = true
			continue
		}
		digest := cArchiveExtentSHA256(data, extent)
		if digest == "" {
			omitted[extent] = true
			continue
		}
		digests[extent] = digest
		work += uint64ToInt64(extent.Length)
	}
	return digests, omitted
}

func cArchiveDiscoveryCoverageDetail(parsed cArchiveParseResult) string {
	limitedTOCs := 0
	for _, candidate := range parsed.Candidates {
		if candidate.TOCValidationLimited {
			limitedTOCs++
		}
	}
	return fmt.Sprintf(
		"CArchive discovery validation was bounded (examined %d marker offsets; omitted %d marker offsets, including %d plausible envelopes; TOC validation limited for %d candidates); candidate inventory may be incomplete",
		parsed.ExaminedOffsets,
		parsed.OmittedMagicOffsets,
		parsed.OmittedPlausibleEnvelopeOffsets,
		limitedTOCs,
	)
}

func cArchiveCandidateLogicalPath(outer string, candidate cArchiveCandidate) (string, bool) {
	name := fmt.Sprintf("_embedded/carchive-%016x-%s", candidate.Cookie.Offset, candidate.CookieLayout)
	return archiveLogicalPath(outer, name)
}

func cArchiveCandidateInitialStatus(candidate cArchiveCandidate) (string, string) {
	var details []string
	if candidate.TOCValidationLimited {
		details = append(details, fmt.Sprintf("TOC validation stopped at a configured work limit with %d bytes unvalidated", candidate.UnvalidatedTOCBytes))
	}
	if candidate.MalformedTOCTail {
		details = append(details, fmt.Sprintf("TOC tail is malformed with %d bytes unvalidated", candidate.UnvalidatedTOCBytes))
	}
	if candidate.InvalidMemberExtents > 0 {
		details = append(details, fmt.Sprintf("%d TOC records have payload extents outside the package data region", candidate.InvalidMemberExtents))
	}
	if candidate.NonIdenticalPayloadOverlap {
		details = append(details, "non-identical member payload extents overlap and will not be decoded")
	}
	if len(details) == 0 {
		return "analyzed", ""
	}
	return "partial", strings.Join(details, "; ")
}

func selectCArchiveCandidatesForExpansion(candidates []scannedCArchiveCandidate) []bool {
	selected := make([]bool, len(candidates))
	var extents []cArchiveExtent
	for index := len(candidates) - 1; index >= 0; index-- {
		overlaps := false
		for _, extent := range extents {
			if extentsOverlap(candidates[index].candidate.Package, extent) {
				overlaps = true
				break
			}
		}
		if overlaps {
			continue
		}
		selected[index] = true
		extents = append(extents, candidates[index].candidate.Package)
	}
	return selected
}

func (s *scanner) materializeCArchiveMembers(carrierID string, scanned scannedCArchiveCandidate, carrier []byte, depth int, attributed bool, loaderEvidence []LocatedArtifactEvidence, budget *cArchiveDecodeBudget) cArchiveMaterializeStats {
	candidate := scanned.candidate
	attributedCurrentCookie := attributed && candidate.CookieLayout == cArchiveCookieCurrent
	var loaderOrdinals map[int]int
	if attributed {
		loaderOrdinals = cArchiveLoaderExecutionOrdinals(candidate.Members)
	}
	loaderTargets := make([]cArchiveLoaderTarget, 0)
	retainLoaderTarget := func(childID string, member cArchiveMember) {
		if !attributed || childID == "" {
			return
		}
		executionOrdinal, ok := loaderOrdinals[member.Ordinal]
		if !ok {
			return
		}
		loaderTargets = append(loaderTargets, cArchiveLoaderTarget{
			childID: childID, member: member, executionOrdinal: executionOrdinal,
		})
	}
	selected := selectCArchiveMemberIndexes(candidate, MaxArchiveEntries)
	stats := cArchiveMaterializeStats{omitted: len(candidate.Members) - len(selected)}
	names := cArchiveMemberLogicalNames(candidate, scanned.logical)
	repeatedDecodeKeys := cArchiveRepeatedDecodeKeys(candidate, selected)
	decodeCache := make(map[cArchiveMemberDecodeKey]cArchiveMemberDecodeResult, len(repeatedDecodeKeys))
	for _, memberIndex := range selected {
		member := candidate.Members[memberIndex]
		sourceRole := cArchiveMemberSourceRole(member, attributed)
		name := names[memberIndex]
		childLogical, ok := archiveLogicalPath(scanned.logical, name)
		if !ok {
			stats.omitted++
			continue
		}
		kind, media, _, _, _ := cArchiveMemberRepresentation(member, nil, attributedCurrentCookie)
		if member.TypeCode == 'd' || member.TypeCode == 'o' {
			childID := s.addCArchiveInventoryNode(scanned.nodeID, childLogical, member, "carchive-metadata", "application/x-carchive-metadata", sourceRole, "analyzed", "CArchive metadata record; no payload decoding is applicable")
			if childID != "" {
				stats.modeled++
			}
			continue
		}
		if member.TypeCode == 'n' {
			childID := s.addCArchiveInventoryNode(scanned.nodeID, childLogical, member, "symlink", "inode/symlink", sourceRole, "skipped", "CArchive symbolic-link record inventoried; link target not followed")
			if childID != "" {
				stats.modeled++
				stats.skipped++
			}
			continue
		}

		skipDetail := ""
		switch {
		case !member.PayloadInBounds:
			skipDetail = "CArchive member payload extent is outside the package data region"
		case member.OverlapsAnotherPayload:
			skipDetail = "CArchive member payload overlaps a non-identical record and was not decoded"
		case member.CompressionFlag != 0 && member.CompressionFlag != 1:
			skipDetail = fmt.Sprintf("CArchive compression flag %d is unsupported", member.CompressionFlag)
		}
		if skipDetail != "" {
			childID := s.addCArchiveInventoryNode(scanned.nodeID, childLogical, member, kind, media, sourceRole, "skipped", skipDetail)
			if childID != "" {
				stats.modeled++
				stats.skipped++
				retainLoaderTarget(childID, member)
			}
			continue
		}

		decodeKey := cArchiveDecodeKey(member)
		result, cached := decodeCache[decodeKey]
		if !cached {
			result.decoded, result.detail = s.decodeCArchiveMember(carrier, member, budget)
			// Unique selected extents are already retained by their content node;
			// do not hold a second reference in the decode cache. Only repeated
			// keys need to survive until a later selected alias is materialized.
			if repeatedDecodeKeys[decodeKey] {
				decodeCache[decodeKey] = result
			}
		}
		decoded, detail := result.decoded, result.detail
		if detail == "" {
			detail = s.cArchiveDecodedMemberCapacity(uint64(len(decoded)))
		}
		if detail != "" {
			childID := s.addCArchiveInventoryNode(scanned.nodeID, childLogical, member, kind, media, sourceRole, "skipped", detail)
			if childID != "" {
				stats.modeled++
				stats.skipped++
				stats.decodeFailures++
				retainLoaderTarget(childID, member)
			}
			continue
		}

		kind, media, rawOnly, semanticArea, semanticDetail := cArchiveMemberRepresentation(member, decoded, attributedCurrentCookie)
		entry := VirtualEntry{
			Data:                   decoded,
			Kind:                   kind,
			MediaType:              media,
			Size:                   int64(len(decoded)),
			CompressedSize:         int64(member.CompressedLength),
			Provenance:             cArchiveMemberProvenance,
			SourceRole:             sourceRole,
			RawFeaturesOnly:        rawOnly,
			SemanticCoverageArea:   semanticArea,
			SemanticCoverageDetail: semanticDetail,
		}
		s.expandedBytes += int64(len(decoded))
		childID := s.scanVirtualEntry(scanned.nodeID, childLogical, entry, depth)
		if childID == "" {
			stats.omitted++
			continue
		}
		stats.modeled++
		if rawOnly {
			stats.rawOnly++
		}
		retainLoaderTarget(childID, member)
	}
	sort.SliceStable(loaderTargets, func(i, j int) bool {
		return loaderTargets[i].executionOrdinal < loaderTargets[j].executionOrdinal
	})
	for _, target := range loaderTargets {
		s.addCArchiveLoaderEdge(carrierID, target.childID, target.member, target.executionOrdinal, loaderEvidence)
	}
	return stats
}

func cArchiveDecodeKey(member cArchiveMember) cArchiveMemberDecodeKey {
	return cArchiveMemberDecodeKey{
		payload:          member.Payload,
		compressedLength: member.CompressedLength,
		declaredSize:     member.DeclaredSize,
		compressionFlag:  member.CompressionFlag,
	}
}

func cArchiveRepeatedDecodeKeys(candidate cArchiveCandidate, selected []int) map[cArchiveMemberDecodeKey]bool {
	counts := make(map[cArchiveMemberDecodeKey]int)
	for _, memberIndex := range selected {
		if memberIndex < 0 || memberIndex >= len(candidate.Members) {
			continue
		}
		member := candidate.Members[memberIndex]
		if member.TypeCode == 'd' || member.TypeCode == 'o' || member.TypeCode == 'n' || !member.PayloadInBounds || member.OverlapsAnotherPayload || member.CompressionFlag != 0 && member.CompressionFlag != 1 {
			continue
		}
		counts[cArchiveDecodeKey(member)]++
	}
	repeated := make(map[cArchiveMemberDecodeKey]bool)
	for key, count := range counts {
		if count > 1 {
			repeated[key] = true
		}
	}
	return repeated
}

func cArchiveMemberSourceRole(member cArchiveMember, attributed bool) string {
	if attributed && (member.TypeCode == 'm' || member.TypeCode == 'M' || member.TypeCode == 's') {
		return "runtime"
	}
	// A CArchive TOC inventories bundled content but, without a loader
	// relationship, does not establish that the carrier executes every record.
	// Keep those bytes available for --include-unreferenced analysis without treating a name or
	// content signature as execution context.
	return "packaged-content"
}

func (s *scanner) addCArchiveLoaderEdge(carrierID, childID string, member cArchiveMember, executionOrdinal int, recognitionEvidence []LocatedArtifactEvidence) {
	evidence := make([]LocatedArtifactEvidence, 0, len(recognitionEvidence)+1)
	evidence = append(evidence, recognitionEvidence...)
	evidence = append(evidence, cArchiveLoaderRecordEvidence(member, executionOrdinal))
	s.graph.AddSupportedOrderedEdge(carrierID, childID, "loader-invokes", executionOrdinal, evidence)
}

func cArchiveLoaderRecordEvidence(member cArchiveMember, executionOrdinal int) LocatedArtifactEvidence {
	return LocatedArtifactEvidence{
		Offset: uint64ToInt64(member.TOCRecordOffset + 17),
		Kind:   "carchive-loader-record",
		Value:  fmt.Sprintf("type=%c; toc_ordinal=%d; loader_ordinal=%d", member.TypeCode, member.Ordinal, executionOrdinal),
	}
}

func cArchiveLoaderExecutionOrdinals(members []cArchiveMember) map[int]int {
	ordinals := make(map[int]int)
	next := 0
	for _, member := range members {
		if member.TypeCode != 'm' && member.TypeCode != 'M' {
			continue
		}
		ordinals[member.Ordinal] = next
		next++
	}
	for _, member := range members {
		if member.TypeCode != 's' {
			continue
		}
		ordinals[member.Ordinal] = next
		next++
	}
	return ordinals
}

func cArchiveMemberRepresentation(member cArchiveMember, decoded []byte, attributedCurrentCookie bool) (kind, media string, rawOnly bool, semanticArea, semanticDetail string) {
	switch member.TypeCode {
	case 's':
		if attributedCurrentCookie {
			return "python-marshal", "application/x-python-marshal", true, "python-marshal-semantics", "Python marshal record identified by a corroborated PyInstaller carrier; code-object semantics are not decoded"
		}
		return "carchive-python-record", "application/x-carchive-python-record", true, "carchive-python-record-semantics", "CArchive Python record identified; producer, representation version, and code-object semantics are not established"
	case 'M', 'm':
		if attributedCurrentCookie {
			return "pyinstaller-python-module-record", "application/x-pyinstaller-python-module-record", true, "pyinstaller-python-module-record-semantics", "PyInstaller Python module record identified; historical releases may store a full PYC while newer releases store direct marshal bytes, and framing/code-object semantics are not decoded"
		}
		return "carchive-python-record", "application/x-carchive-python-record", true, "carchive-python-record-semantics", "CArchive Python record identified; producer, representation version, and code-object semantics are not established"
	case 'z':
		if len(decoded) >= 4 && bytes.Equal(decoded[:4], []byte{'P', 'Y', 'Z', 0}) {
			return "python-pyz", "application/x-python-pyz", true, "python-pyz-module-inventory", "PYZ container identified; its marshal table and module semantics are not decoded"
		}
		return "carchive-record", "application/octet-stream", true, "carchive-record-semantics", "CArchive record retained as uninterpreted bytes because the declared PYZ type was not corroborated by PYZ magic"
	case 'd', 'o':
		return "carchive-metadata", "application/x-carchive-metadata", false, "", ""
	case 'n':
		return "symlink", "inode/symlink", false, "", ""
	default:
		kind, media = Detect("", decoded, false)
		return kind, media, false, "", ""
	}
}

func (s *scanner) addCArchiveInventoryNode(parentID, logical string, member cArchiveMember, kind, media, sourceRole, status, detail string) string {
	if !s.reserveNode(logical, "", parentID) {
		return ""
	}
	size := int64(member.DeclaredSize)
	if size == 0 {
		size = int64(member.CompressedLength)
	}
	id := s.graph.AddNode(Node{
		ParentID:       parentID,
		LogicalPath:    logical,
		Kind:           kind,
		MediaType:      media,
		Size:           size,
		Provenance:     cArchiveMemberProvenance,
		SourceRole:     sourceRole,
		AnalyzeStatus:  status,
		CoverageDetail: detail,
	})
	s.graph.AddEdge(parentID, id, "contains")
	return id
}

func (s *scanner) cArchiveDecodedMemberCapacity(size uint64) string {
	if archiveBudgetExceeded(s.expandedBytes, size, s.options.MaxExpandedBytes) {
		return fmt.Sprintf("inspection expanded-byte limit %d reached", s.options.MaxExpandedBytes)
	}
	if archiveBudgetExceeded(s.retainedBytes, size, s.options.MaxTotalBytes) {
		return fmt.Sprintf("inspection retained-byte limit %d reached", s.options.MaxTotalBytes)
	}
	return ""
}

func (s *scanner) decodeCArchiveMember(carrier []byte, member cArchiveMember, budget *cArchiveDecodeBudget) ([]byte, string) {
	compressed := uint64(member.CompressedLength)
	declared := uint64(member.DeclaredSize)
	if uint64ExceedsInt64Limit(declared, s.options.MaxFileBytes) {
		return nil, fmt.Sprintf("CArchive decoded member exceeds max file bytes %d", s.options.MaxFileBytes)
	}
	if member.CompressionFlag == 0 && member.CompressedLength != member.DeclaredSize {
		return nil, "stored CArchive member lengths disagree"
	}
	if member.CompressionFlag == 1 && s.compressionRatioExceeded(declared, compressed) {
		return nil, fmt.Sprintf("CArchive member exceeds compression ratio limit %d", s.options.MaxCompressionRatio)
	}
	if archiveBudgetExceeded(budget.decodedBytesAttempted, declared, s.options.MaxArchiveBytes) {
		return nil, fmt.Sprintf("CArchive attempted decoded-output byte limit %d reached", s.options.MaxArchiveBytes)
	}
	if archiveBudgetExceeded(budget.compressedBytesRead, compressed, s.options.MaxArchiveBytes) {
		return nil, fmt.Sprintf("CArchive decode-work byte limit %d reached", s.options.MaxArchiveBytes)
	}
	if archiveBudgetExceeded(s.expandedBytes, declared, s.options.MaxExpandedBytes) {
		return nil, fmt.Sprintf("inspection expanded-byte limit %d reached", s.options.MaxExpandedBytes)
	}
	if archiveBudgetExceeded(s.retainedBytes, declared, s.options.MaxTotalBytes) {
		return nil, fmt.Sprintf("inspection retained-byte limit %d reached", s.options.MaxTotalBytes)
	}
	start := member.Payload.Offset
	end, ok := member.Payload.end()
	if !ok || start > uint64(len(carrier)) || end > uint64(len(carrier)) {
		return nil, "CArchive member payload extent is outside retained carrier bytes"
	}
	budget.decodedBytesAttempted += uint64ToInt64(declared)
	budget.compressedBytesRead += uint64ToInt64(compressed)
	payload := carrier[int(start):int(end)]
	if member.CompressionFlag == 0 {
		return append([]byte(nil), payload...), ""
	}
	if member.CompressionFlag != 1 {
		return nil, fmt.Sprintf("CArchive compression flag %d is unsupported", member.CompressionFlag)
	}

	input := bytes.NewBuffer(payload)
	reader, err := zlib.NewReader(input)
	if err != nil {
		return nil, "CArchive zlib header is invalid"
	}
	decoded, readErr := io.ReadAll(io.LimitReader(reader, int64(member.DeclaredSize)+1))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, "CArchive zlib stream or checksum is invalid"
	}
	if closeErr != nil {
		return nil, "CArchive zlib stream close failed"
	}
	if len(decoded) != int(member.DeclaredSize) {
		return nil, fmt.Sprintf("CArchive decoded size %d disagrees with declared size %d", len(decoded), member.DeclaredSize)
	}
	if input.Len() != 0 {
		return nil, "CArchive zlib payload has trailing bytes"
	}
	return decoded, ""
}

func selectCArchiveMemberIndexes(candidate cArchiveCandidate, limit int) []int {
	if limit <= 0 || len(candidate.Members) == 0 {
		return nil
	}
	firstByType, lastByType := [256]int{}, [256]int{}
	for index := range firstByType {
		firstByType[index] = -1
		lastByType[index] = -1
	}
	for index, member := range candidate.Members {
		code := int(member.TypeCode)
		if firstByType[code] < 0 {
			firstByType[code] = index
		}
		lastByType[code] = index
	}
	selections := make([]cArchiveMemberSelection, 0, len(candidate.Members))
	for index, member := range candidate.Members {
		anchorTier := 2
		if index == 0 || index == len(candidate.Members)-1 {
			anchorTier = 0
		} else if firstByType[int(member.TypeCode)] == index || lastByType[int(member.TypeCode)] == index {
			anchorTier = 1
		}
		selections = append(selections, cArchiveMemberSelection{
			index:      index,
			anchorTier: anchorTier,
			typeRank:   cArchiveMemberTypeRank(member.TypeCode),
			digest:     cArchiveMemberSelectionDigest(candidate, member),
			ordinal:    member.Ordinal,
		})
	}
	sort.SliceStable(selections, func(i, j int) bool {
		left, right := selections[i], selections[j]
		if left.anchorTier != right.anchorTier {
			return left.anchorTier < right.anchorTier
		}
		if left.typeRank != right.typeRank {
			return left.typeRank < right.typeRank
		}
		if compared := bytes.Compare(left.digest[:], right.digest[:]); compared != 0 {
			return compared < 0
		}
		return left.ordinal < right.ordinal
	})
	if len(selections) > limit {
		selections = selections[:limit]
	}
	sort.SliceStable(selections, func(i, j int) bool {
		if selections[i].ordinal != selections[j].ordinal {
			return selections[i].ordinal < selections[j].ordinal
		}
		return selections[i].index < selections[j].index
	})
	selected := make([]int, len(selections))
	for index, selection := range selections {
		selected[index] = selection.index
	}
	return selected
}

func cArchiveMemberTypeRank(code byte) int {
	switch code {
	case 's', 'M', 'm':
		return 0
	case 'z':
		return 1
	case 'Z':
		return 2
	case 'n', 'd', 'o':
		return 3
	case 'b', 'x', 'l':
		return 4
	default:
		return 5
	}
}

func cArchiveMemberSelectionDigest(candidate cArchiveCandidate, member cArchiveMember) [sha256.Size]byte {
	buffer := make([]byte, 0, 64+len(member.RawName))
	fixed := make([]byte, 8)
	binary.BigEndian.PutUint64(fixed, candidate.Cookie.Offset)
	buffer = append(buffer, fixed...)
	binary.BigEndian.PutUint64(fixed, uint64(member.Ordinal))
	buffer = append(buffer, fixed...)
	binary.BigEndian.PutUint64(fixed, member.Payload.Offset)
	buffer = append(buffer, fixed...)
	binary.BigEndian.PutUint64(fixed, member.Payload.Length)
	buffer = append(buffer, fixed...)
	buffer = append(buffer, member.TypeCode, member.CompressionFlag)
	buffer = append(buffer, member.RawName...)
	return sha256.Sum256(buffer)
}

func cArchiveMemberLogicalNames(candidate cArchiveCandidate, candidateLogical string) []string {
	canonical := make([]string, len(candidate.Members))
	counts := make(map[string]int)
	reserved := make(map[string]bool)
	for index, member := range candidate.Members {
		if !member.NameTerminated || member.NameTruncated || member.NamePaddingNonZero || !member.NameUTF8 || len(member.RawName) == 0 || !utf8.Valid(member.RawName) {
			continue
		}
		name, ok := cleanArchiveName(string(member.RawName))
		if !ok || name == "" || strings.Contains(name, "!") {
			continue
		}
		if _, ok := archiveLogicalPath(candidateLogical, name); !ok {
			continue
		}
		canonical[index] = name
		key := strings.ToLower(name)
		counts[key]++
		reserved[key] = true
	}
	used := make(map[string]bool)
	names := make([]string, len(candidate.Members))
	for index, member := range candidate.Members {
		name := canonical[index]
		if name == "" || counts[strings.ToLower(name)] > 1 || used[strings.ToLower(name)] {
			name = cArchiveSyntheticMemberName(member, reserved, used)
		}
		names[index] = name
		used[strings.ToLower(name)] = true
	}
	return names
}

func cArchiveSyntheticMemberName(member cArchiveMember, reserved, used map[string]bool) string {
	base := fmt.Sprintf("_carchive_records/record-%06d-type-%02x", member.Ordinal, member.TypeCode)
	name := base
	for suffix := 1; reserved[strings.ToLower(name)] || used[strings.ToLower(name)]; suffix++ {
		name = fmt.Sprintf("%s-synthetic-%d", base, suffix)
	}
	return name
}

func updateCArchiveNodeInventory(graph *Graph, nodeID string, modeled int) {
	if graph == nil {
		return
	}
	for index := range graph.Nodes {
		if graph.Nodes[index].ID == nodeID {
			graph.Nodes[index].ModeledEntryCount = cArchiveIntPointer(modeled)
			return
		}
	}
}

func cArchiveIntPointer(value int) *int {
	return &value
}

func setArtifactPackagingTechnology(graph *Graph, nodeID, technology string, evidence []LocatedArtifactEvidence) {
	if graph == nil || nodeID == "" || technology == "" || len(evidence) == 0 {
		return
	}
	for index := range graph.Nodes {
		if graph.Nodes[index].ID == nodeID {
			graph.Nodes[index].PackagingTechnology = technology
			graph.Nodes[index].PackagingEvidence = append([]LocatedArtifactEvidence(nil), evidence...)
			return
		}
	}
}
