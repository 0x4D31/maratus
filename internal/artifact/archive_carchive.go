package artifact

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"unicode/utf8"
)

var cArchiveCookieMagic = []byte{'M', 'E', 'I', 0x0c, 0x0b, 0x0a, 0x0b, 0x0e}

const (
	cArchiveLegacyCookieSize      = 24
	cArchiveCurrentCookieSize     = 88
	maxCArchiveTOCBytes           = 32 << 20
	maxCArchiveRecords            = 65536
	initialCArchiveMemberCapacity = 256
	maxCArchiveCandidateOffsets   = 64
	maxCArchiveLeadingOffsets     = 16
	maxCArchiveTrailingOffsets    = maxCArchiveCandidateOffsets - maxCArchiveLeadingOffsets
	maxCArchiveValidationBytes    = 64 << 20
	maxCArchiveRetainedNameBytes  = MaxArchiveNameBytes
)

type cArchiveCookieLayout string

const (
	cArchiveCookieLegacy  cArchiveCookieLayout = "legacy-24"
	cArchiveCookieCurrent cArchiveCookieLayout = "current-88"
)

type cArchiveExtent struct {
	Offset uint64
	Length uint64
}

func (e cArchiveExtent) end() (uint64, bool) {
	end := e.Offset + e.Length
	return end, end >= e.Offset
}

type cArchiveMember struct {
	Ordinal                int
	TOCRecordOffset        uint64
	Payload                cArchiveExtent
	CompressedLength       uint32
	DeclaredSize           uint32
	CompressionFlag        byte
	TypeCode               byte
	RawName                []byte
	RawNameLength          uint64
	NameTerminated         bool
	NameTruncated          bool
	NamePaddingNonZero     bool
	NameUTF8               bool
	StoredLengthMismatch   bool
	PayloadInBounds        bool
	AliasOfOrdinal         int
	OverlapsAnotherPayload bool
}

type cArchiveCandidate struct {
	Package                      cArchiveExtent
	Cookie                       cArchiveExtent
	TOC                          cArchiveExtent
	CookieLayout                 cArchiveCookieLayout
	PythonVersion                uint32
	PythonVersionPlausible       bool
	PythonLibraryRaw             []byte
	PythonLibraryNameLength      uint64
	PythonLibraryTerminated      bool
	PythonLibraryNonEmpty        bool
	PythonLibraryUTF8            bool
	PythonLibraryPaddingNonZero  bool
	PythonLibraryFieldWellFormed bool
	Members                      []cArchiveMember
	StructureFullyValidated      bool
	EmptyTOC                     bool
	TOCValidationLimited         bool
	TOCRecordsTruncated          bool
	MalformedTOCTail             bool
	UnvalidatedTOCBytes          uint64
	InvalidMemberExtents         int
	NonIdenticalPayloadOverlap   bool
}

type cArchiveParseResult struct {
	MagicCount                          int
	LastMagicOffset                     uint64
	LastMagicHasFullyValidatedCandidate bool
	ExaminedOffsets                     int
	InvalidSelectedOffsets              int
	OmittedMagicOffsets                 int
	PlausibleEnvelopeCount              int
	OmittedPlausibleEnvelopeOffsets     int
	CandidateValidationTruncated        bool
	TOCBytesCharged                     uint64
	TOCRecordsVisited                   int
	Candidates                          []cArchiveCandidate
	NestedCandidates                    bool
	AliasedCandidates                   bool
	ConflictingCandidateOverlap         bool
}

type cArchiveOffsetSelection struct {
	MagicCount                      int
	LastOffset                      int
	PlausibleEnvelopeCount          int
	OmittedMagicOffsets             int
	OmittedPlausibleEnvelopeOffsets int
	Offsets                         []int
}

type cArchiveTOCParseResult struct {
	Members              []cArchiveMember
	BytesVisited         uint64
	RecordsVisited       int
	ValidationLimited    bool
	RecordLimitReached   bool
	MalformedTail        bool
	UnvalidatedBytes     uint64
	InvalidMemberExtents int
}

// parseCArchives inventories canonical CArchive envelopes and every TOC record
// that can be parsed within shared work limits, without attributing a producer
// or execution semantics. A candidate may therefore be partial; only
// StructureFullyValidated candidates can satisfy the later attribution gate.
// Candidate selection is bounded, prioritizes the final marker and plausible
// envelopes across the carrier, and discloses every selection or work limit.
func parseCArchives(data []byte) cArchiveParseResult {
	selection := selectCArchiveMagicOffsets(data)
	result := cArchiveParseResult{
		MagicCount:                      selection.MagicCount,
		PlausibleEnvelopeCount:          selection.PlausibleEnvelopeCount,
		OmittedMagicOffsets:             selection.OmittedMagicOffsets,
		OmittedPlausibleEnvelopeOffsets: selection.OmittedPlausibleEnvelopeOffsets,
		CandidateValidationTruncated:    selection.OmittedMagicOffsets > 0,
	}
	if len(selection.Offsets) == 0 {
		return result
	}
	result.LastMagicOffset = uint64(selection.LastOffset)

	// Validate from the end towards the beginning so the finite structural
	// work budget favors the marker a real loader searches for first.
	offsets := selection.Offsets
	sort.Sort(sort.Reverse(sort.IntSlice(offsets)))
	remainingTOCBytes := uint64(maxCArchiveValidationBytes)
	remainingRecords := maxCArchiveRecords
	for _, offset := range offsets {
		candidateAtOffset := false
		fullyValidatedAtOffset := false
		examinedAtOffset := false
		for _, layout := range []cArchiveCookieLayout{cArchiveCookieCurrent, cArchiveCookieLegacy} {
			candidate, tocBytes, recordsVisited, err := parseCArchiveCookie(data, offset, layout, remainingTOCBytes, remainingRecords)
			examinedAtOffset = true
			if err != nil {
				continue
			}
			remainingTOCBytes -= tocBytes
			remainingRecords -= recordsVisited
			result.TOCBytesCharged += tocBytes
			result.TOCRecordsVisited += recordsVisited
			candidateAtOffset = true
			fullyValidatedAtOffset = fullyValidatedAtOffset || candidate.StructureFullyValidated
			if candidate.TOCValidationLimited {
				result.CandidateValidationTruncated = true
			}
			result.Candidates = append(result.Candidates, candidate)
		}
		if examinedAtOffset {
			result.ExaminedOffsets++
		}
		if fullyValidatedAtOffset && uint64(offset) == result.LastMagicOffset {
			result.LastMagicHasFullyValidatedCandidate = true
		}
		if examinedAtOffset && !candidateAtOffset {
			result.InvalidSelectedOffsets++
		}
	}

	sort.SliceStable(result.Candidates, func(i, j int) bool {
		if result.Candidates[i].Cookie.Offset != result.Candidates[j].Cookie.Offset {
			return result.Candidates[i].Cookie.Offset < result.Candidates[j].Cookie.Offset
		}
		return result.Candidates[i].CookieLayout < result.Candidates[j].CookieLayout
	})
	for i := range result.Candidates {
		markCArchiveMemberOverlaps(&result.Candidates[i])
		for j := 0; j < i; j++ {
			classifyCArchiveCandidateRelation(&result, result.Candidates[j].Package, result.Candidates[i].Package)
		}
	}
	return result
}

func selectCArchiveMagicOffsets(data []byte) cArchiveOffsetSelection {
	var leading, plausibleLeading []int
	trailing := make([]int, maxCArchiveTrailingOffsets)
	plausibleTrailing := make([]int, maxCArchiveTrailingOffsets)
	trailingCount := 0
	plausibleTrailingCount := 0
	selection := cArchiveOffsetSelection{LastOffset: -1}
	for search := 0; search <= len(data)-len(cArchiveCookieMagic); {
		relative := bytes.Index(data[search:], cArchiveCookieMagic)
		if relative < 0 {
			break
		}
		offset := search + relative
		selection.MagicCount++
		selection.LastOffset = offset
		if len(leading) < maxCArchiveLeadingOffsets {
			leading = append(leading, offset)
		}
		trailing[trailingCount%len(trailing)] = offset
		trailingCount++
		if cArchiveCookieEnvelopePlausible(data, offset, cArchiveCookieCurrent) || cArchiveCookieEnvelopePlausible(data, offset, cArchiveCookieLegacy) {
			selection.PlausibleEnvelopeCount++
			if len(plausibleLeading) < maxCArchiveLeadingOffsets {
				plausibleLeading = append(plausibleLeading, offset)
			}
			plausibleTrailing[plausibleTrailingCount%len(plausibleTrailing)] = offset
			plausibleTrailingCount++
		}
		search = offset + 1
	}
	if selection.MagicCount == 0 {
		return selection
	}
	selected := make(map[int]bool, min(selection.MagicCount, maxCArchiveCandidateOffsets))
	add := func(offset int) {
		if offset >= 0 && len(selected) < maxCArchiveCandidateOffsets {
			selected[offset] = true
		}
	}

	// A real loader gives the final marker special meaning, so it is retained
	// even when its fixed-size envelope is implausible. Plausible envelopes from
	// the full carrier then outrank bare marker strings.
	add(selection.LastOffset)
	for _, offset := range plausibleLeading {
		add(offset)
	}
	for _, offset := range cArchiveRingOffsetsNewestFirst(plausibleTrailing, plausibleTrailingCount) {
		add(offset)
	}
	for _, offset := range leading {
		add(offset)
	}
	for _, offset := range cArchiveRingOffsetsNewestFirst(trailing, trailingCount) {
		add(offset)
	}

	selection.Offsets = make([]int, 0, len(selected))
	selectedPlausible := 0
	for offset := range selected {
		selection.Offsets = append(selection.Offsets, offset)
		if cArchiveCookieEnvelopePlausible(data, offset, cArchiveCookieCurrent) || cArchiveCookieEnvelopePlausible(data, offset, cArchiveCookieLegacy) {
			selectedPlausible++
		}
	}
	sort.Ints(selection.Offsets)
	selection.OmittedMagicOffsets = selection.MagicCount - len(selection.Offsets)
	selection.OmittedPlausibleEnvelopeOffsets = selection.PlausibleEnvelopeCount - selectedPlausible
	return selection
}

func cArchiveRingOffsetsNewestFirst(ring []int, count int) []int {
	retained := min(count, len(ring))
	if retained == 0 {
		return nil
	}
	start := 0
	if count > len(ring) {
		start = count % len(ring)
	}
	offsets := make([]int, 0, retained)
	for index := retained - 1; index >= 0; index-- {
		offsets = append(offsets, ring[(start+index)%len(ring)])
	}
	return offsets
}

func cArchiveCookieEnvelopePlausible(data []byte, cookieOffset int, layout cArchiveCookieLayout) bool {
	cookieSize := cArchiveCookieSize(layout)
	if cookieOffset < 0 || cookieSize == 0 || cookieOffset > len(data)-cookieSize {
		return false
	}
	cookie := data[cookieOffset : cookieOffset+cookieSize]
	if !bytes.Equal(cookie[:len(cArchiveCookieMagic)], cArchiveCookieMagic) {
		return false
	}
	packageLength := uint64(binary.BigEndian.Uint32(cookie[8:12]))
	tocOffset := uint64(binary.BigEndian.Uint32(cookie[12:16]))
	tocLength := uint64(binary.BigEndian.Uint32(cookie[16:20]))
	cookieEnd := uint64(cookieOffset + cookieSize)
	if packageLength < uint64(cookieSize) || packageLength > cookieEnd {
		return false
	}
	packageDataLength := packageLength - uint64(cookieSize)
	return tocOffset <= packageDataLength && tocLength <= packageDataLength-tocOffset && tocOffset+tocLength == packageDataLength
}

func parseCArchiveCookie(data []byte, cookieOffset int, layout cArchiveCookieLayout, remainingTOCBytes uint64, remainingRecords int) (cArchiveCandidate, uint64, int, error) {
	cookieSize := cArchiveCookieSize(layout)
	if cookieOffset < 0 || cookieSize == 0 || cookieOffset > len(data)-cookieSize {
		return cArchiveCandidate{}, 0, 0, errors.New("truncated CArchive cookie")
	}
	cookie := data[cookieOffset : cookieOffset+cookieSize]
	if !bytes.Equal(cookie[:len(cArchiveCookieMagic)], cArchiveCookieMagic) {
		return cArchiveCandidate{}, 0, 0, errors.New("CArchive cookie magic mismatch")
	}

	packageLength := uint64(binary.BigEndian.Uint32(cookie[8:12]))
	tocOffset := uint64(binary.BigEndian.Uint32(cookie[12:16]))
	tocLength := uint64(binary.BigEndian.Uint32(cookie[16:20]))
	pythonVersion := binary.BigEndian.Uint32(cookie[20:24])
	cookieEnd := uint64(cookieOffset + cookieSize)
	if packageLength < uint64(cookieSize) || packageLength > cookieEnd {
		return cArchiveCandidate{}, 0, 0, errors.New("CArchive package length is outside carrier")
	}
	packageDataLength := packageLength - uint64(cookieSize)
	// The supported structural profile deliberately requires the writer's
	// canonical layout: the TOC is contiguous with the cookie. More permissive
	// readers exist, but their acceptance is not treated as structural proof.
	if tocOffset > packageDataLength || tocLength > packageDataLength-tocOffset || tocOffset+tocLength != packageDataLength {
		return cArchiveCandidate{}, 0, 0, errors.New("CArchive TOC is outside package or does not end at cookie")
	}
	packageStart := cookieEnd - packageLength
	tocStart := packageStart + tocOffset
	tocEnd := tocStart + tocLength
	if tocEnd != uint64(cookieOffset) || tocEnd > uint64(len(data)) {
		return cArchiveCandidate{}, 0, 0, errors.New("CArchive absolute TOC bounds are invalid")
	}
	byteLimit := min(tocLength, uint64(maxCArchiveTOCBytes), remainingTOCBytes)
	tocResult := parseCArchiveTOC(
		data[int(tocStart):int(tocEnd)],
		packageStart,
		tocOffset,
		remainingRecords,
		byteLimit,
	)
	candidate := cArchiveCandidate{
		Package:                 cArchiveExtent{Offset: packageStart, Length: packageLength},
		Cookie:                  cArchiveExtent{Offset: uint64(cookieOffset), Length: uint64(cookieSize)},
		TOC:                     cArchiveExtent{Offset: tocStart, Length: tocLength},
		CookieLayout:            layout,
		PythonVersion:           pythonVersion,
		PythonVersionPlausible:  plausibleCArchivePythonVersion(pythonVersion),
		Members:                 tocResult.Members,
		StructureFullyValidated: !tocResult.ValidationLimited && !tocResult.MalformedTail && tocResult.InvalidMemberExtents == 0,
		// An empty TOC is a safe neutral container shape. It proves neither an
		// executable target nor producer attribution by itself.
		EmptyTOC:             tocLength == 0,
		TOCValidationLimited: tocResult.ValidationLimited,
		TOCRecordsTruncated:  tocResult.RecordLimitReached,
		MalformedTOCTail:     tocResult.MalformedTail,
		UnvalidatedTOCBytes:  tocResult.UnvalidatedBytes,
		InvalidMemberExtents: tocResult.InvalidMemberExtents,
	}
	if layout == cArchiveCookieCurrent {
		candidate.PythonLibraryRaw = append([]byte(nil), cookie[24:88]...)
		candidate.PythonLibraryTerminated,
			candidate.PythonLibraryUTF8,
			candidate.PythonLibraryPaddingNonZero,
			candidate.PythonLibraryNameLength,
			candidate.PythonLibraryNonEmpty,
			candidate.PythonLibraryFieldWellFormed = cArchiveLibraryFieldProperties(candidate.PythonLibraryRaw)
	}
	return candidate, tocResult.BytesVisited, tocResult.RecordsVisited, nil
}

func cArchiveCookieSize(layout cArchiveCookieLayout) int {
	switch layout {
	case cArchiveCookieLegacy:
		return cArchiveLegacyCookieSize
	case cArchiveCookieCurrent:
		return cArchiveCurrentCookieSize
	default:
		return 0
	}
}

func parseCArchiveTOC(data []byte, packageStart, dataRegionLength uint64, recordLimit int, byteLimit uint64) cArchiveTOCParseResult {
	if recordLimit < 0 {
		recordLimit = 0
	}
	retainedCapacity := min(recordLimit, len(data)/32, initialCArchiveMemberCapacity)
	result := cArchiveTOCParseResult{Members: make([]cArchiveMember, 0, retainedCapacity)}
	allowedBytes := min(uint64(len(data)), byteLimit)
	for cursor, ordinal := 0, 0; cursor < len(data); ordinal++ {
		if ordinal >= recordLimit {
			result.ValidationLimited = true
			result.RecordLimitReached = true
			result.UnvalidatedBytes = uint64(len(data) - cursor)
			return result
		}
		if uint64(cursor) >= allowedBytes {
			result.ValidationLimited = true
			result.UnvalidatedBytes = uint64(len(data) - cursor)
			return result
		}
		remainingData := len(data) - cursor
		remainingBudget := allowedBytes - uint64(cursor)
		if remainingData < 18 {
			if uint64(remainingData) > remainingBudget {
				result.ValidationLimited = true
				result.UnvalidatedBytes = uint64(remainingData)
				return result
			}
			result.RecordsVisited++
			result.BytesVisited += uint64(remainingData)
			result.MalformedTail = true
			result.UnvalidatedBytes = uint64(remainingData)
			return result
		}
		if remainingBudget < 18 {
			result.ValidationLimited = true
			result.UnvalidatedBytes = uint64(remainingData)
			return result
		}
		result.RecordsVisited++
		result.BytesVisited += 18
		recordLength := uint64(binary.BigEndian.Uint32(data[cursor : cursor+4]))
		if recordLength < 18 || recordLength%16 != 0 || recordLength > uint64(len(data)-cursor) {
			result.MalformedTail = true
			result.UnvalidatedBytes = uint64(len(data) - cursor)
			return result
		}
		if recordLength > allowedBytes-uint64(cursor) {
			result.ValidationLimited = true
			result.UnvalidatedBytes = uint64(len(data) - cursor)
			return result
		}
		record := data[cursor : cursor+int(recordLength)]
		result.BytesVisited += recordLength - 18
		memberOffset := uint64(binary.BigEndian.Uint32(record[4:8]))
		compressedLength := binary.BigEndian.Uint32(record[8:12])
		declaredSize := binary.BigEndian.Uint32(record[12:16])
		payloadLength := uint64(compressedLength)
		payloadInBounds := memberOffset <= dataRegionLength && payloadLength <= dataRegionLength-memberOffset
		nameField := record[18:]
		nul := bytes.IndexByte(nameField, 0)
		nameEnd := len(nameField)
		terminated := nul >= 0
		paddingNonZero := false
		if terminated {
			nameEnd = nul
			for _, value := range nameField[nul+1:] {
				if value != 0 {
					paddingNonZero = true
					break
				}
			}
		}
		retainedNameLength := min(nameEnd, maxCArchiveRetainedNameBytes)
		rawName := append([]byte(nil), nameField[:retainedNameLength]...)
		member := cArchiveMember{
			Ordinal:              ordinal,
			TOCRecordOffset:      packageStart + dataRegionLength + uint64(cursor),
			Payload:              cArchiveExtent{Offset: packageStart + memberOffset, Length: payloadLength},
			CompressedLength:     compressedLength,
			DeclaredSize:         declaredSize,
			CompressionFlag:      record[16],
			TypeCode:             record[17],
			RawName:              rawName,
			RawNameLength:        uint64(nameEnd),
			NameTerminated:       terminated,
			NameTruncated:        nameEnd > retainedNameLength,
			NamePaddingNonZero:   paddingNonZero,
			NameUTF8:             utf8.Valid(nameField[:nameEnd]),
			StoredLengthMismatch: record[16] == 0 && compressedLength != declaredSize,
			PayloadInBounds:      payloadInBounds,
			AliasOfOrdinal:       -1,
		}
		if !payloadInBounds {
			result.InvalidMemberExtents++
		}
		result.Members = append(result.Members, member)
		cursor += int(recordLength)
	}
	return result
}

func plausibleCArchivePythonVersion(version uint32) bool {
	major := version / 10
	if version >= 100 {
		major = version / 100
	}
	return major == 2 || major == 3
}

func cArchiveLibraryFieldProperties(raw []byte) (terminated, validUTF8, paddingNonZero bool, nameLength uint64, nonEmpty, wellFormed bool) {
	nul := bytes.IndexByte(raw, 0)
	if nul < 0 {
		return false, utf8.Valid(raw), false, uint64(len(raw)), len(raw) > 0, false
	}
	for _, value := range raw[nul+1:] {
		if value != 0 {
			paddingNonZero = true
			break
		}
	}
	name := raw[:nul]
	validUTF8 = utf8.Valid(name)
	printableASCII := true
	for _, value := range name {
		if value < 0x20 || value > 0x7e {
			printableASCII = false
			break
		}
	}
	nonEmpty = len(name) > 0
	wellFormed = validUTF8 && nonEmpty && !paddingNonZero && printableASCII
	return true, validUTF8, paddingNonZero, uint64(len(name)), nonEmpty, wellFormed
}

func markCArchiveMemberOverlaps(candidate *cArchiveCandidate) {
	if candidate == nil || len(candidate.Members) < 2 {
		return
	}
	type extentGroup struct {
		extent  cArchiveExtent
		indices []int
	}
	byExtent := make(map[cArchiveExtent][]int, len(candidate.Members))
	for index, member := range candidate.Members {
		if member.PayloadInBounds && member.Payload.Length != 0 {
			byExtent[member.Payload] = append(byExtent[member.Payload], index)
		}
	}
	groups := make([]extentGroup, 0, len(byExtent))
	for extent, indices := range byExtent {
		sort.SliceStable(indices, func(i, j int) bool {
			return candidate.Members[indices[i]].Ordinal < candidate.Members[indices[j]].Ordinal
		})
		firstOrdinal := candidate.Members[indices[0]].Ordinal
		for _, index := range indices[1:] {
			candidate.Members[index].AliasOfOrdinal = firstOrdinal
		}
		groups = append(groups, extentGroup{extent: extent, indices: indices})
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].extent.Offset != groups[j].extent.Offset {
			return groups[i].extent.Offset < groups[j].extent.Offset
		}
		if groups[i].extent.Length != groups[j].extent.Length {
			return groups[i].extent.Length < groups[j].extent.Length
		}
		return candidate.Members[groups[i].indices[0]].Ordinal < candidate.Members[groups[j].indices[0]].Ordinal
	})
	if len(groups) < 2 {
		return
	}
	maxEndGroup := 0
	maxEnd, _ := groups[0].extent.end()
	for position := 1; position < len(groups); position++ {
		currentEnd, _ := groups[position].extent.end()
		if groups[position].extent.Offset < maxEnd {
			for _, index := range groups[maxEndGroup].indices {
				candidate.Members[index].OverlapsAnotherPayload = true
			}
			for _, index := range groups[position].indices {
				candidate.Members[index].OverlapsAnotherPayload = true
			}
			candidate.NonIdenticalPayloadOverlap = true
		}
		if currentEnd > maxEnd {
			maxEnd = currentEnd
			maxEndGroup = position
		}
	}
}

func classifyCArchiveCandidateRelation(result *cArchiveParseResult, left, right cArchiveExtent) {
	if result == nil || left.Length == 0 || right.Length == 0 {
		return
	}
	if left == right {
		result.AliasedCandidates = true
		return
	}
	if extentContains(left, right) || extentContains(right, left) {
		result.NestedCandidates = true
		return
	}
	if extentsOverlap(left, right) {
		result.ConflictingCandidateOverlap = true
	}
}

func extentContains(outer, inner cArchiveExtent) bool {
	outerEnd, outerOK := outer.end()
	innerEnd, innerOK := inner.end()
	if !outerOK || !innerOK || outer.Length == 0 || inner.Length == 0 {
		return false
	}
	return outer.Offset <= inner.Offset && innerEnd <= outerEnd
}

func extentsOverlap(left, right cArchiveExtent) bool {
	leftEnd, leftOK := left.end()
	rightEnd, rightOK := right.end()
	if !leftOK || !rightOK || left.Length == 0 || right.Length == 0 {
		return false
	}
	return left.Offset < rightEnd && right.Offset < leftEnd
}
