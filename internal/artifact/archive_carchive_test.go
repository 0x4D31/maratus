package artifact

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

type testCArchiveMember struct {
	name               []byte
	data               []byte
	typeCode           byte
	compressionFlag    byte
	declaredSize       uint32
	unterminated       bool
	nonZeroNamePadding bool
}

type testCArchiveOptions struct {
	layout        cArchiveCookieLayout
	pythonVersion uint32
	pythonLibrary []byte
}

func TestParseCArchiveCurrentAndLegacyLayouts(t *testing.T) {
	for _, layout := range []cArchiveCookieLayout{cArchiveCookieLegacy, cArchiveCookieCurrent} {
		t.Run(string(layout), func(t *testing.T) {
			data := buildTestCArchive(t, []byte("carrier-prefix"), []testCArchiveMember{{
				name: []byte("payload"), data: []byte("content"), typeCode: 'x',
			}}, testCArchiveOptions{layout: layout, pythonVersion: 310, pythonLibrary: []byte("Python")})
			data = append(data, []byte("trailing-signature-data")...)
			result := parseCArchives(data)
			if result.MagicCount != 1 || len(result.Candidates) != 1 || !result.LastMagicHasFullyValidatedCandidate {
				t.Fatalf("parseCArchives() = %#v", result)
			}
			candidate := result.Candidates[0]
			if candidate.CookieLayout != layout || candidate.PythonVersion != 310 || len(candidate.Members) != 1 {
				t.Fatalf("candidate = %#v", candidate)
			}
			if got := string(candidate.Members[0].RawName); got != "payload" {
				t.Fatalf("member name = %q", got)
			}
			if layout == cArchiveCookieCurrent && (!candidate.PythonLibraryTerminated || !candidate.PythonLibraryNonEmpty || !candidate.PythonLibraryUTF8 || candidate.PythonLibraryPaddingNonZero || !candidate.PythonLibraryFieldWellFormed || candidate.PythonLibraryNameLength != 6) {
				t.Fatalf("current library properties = %#v", candidate)
			}
		})
	}
}

func TestParseCArchiveLaterInvalidMagicDoesNotHideEarlierCandidate(t *testing.T) {
	data := buildTestCArchive(t, nil, []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	data = append(data, cArchiveCookieMagic...)
	data = append(data, make([]byte, cArchiveLegacyCookieSize-len(cArchiveCookieMagic))...)
	result := parseCArchives(data)
	if result.MagicCount != 2 || len(result.Candidates) != 1 || result.InvalidSelectedOffsets != 1 || result.LastMagicHasFullyValidatedCandidate {
		t.Fatalf("later invalid marker hid valid archive: %#v", result)
	}
	if result.Candidates[0].Cookie.Offset >= uint64(len(data)-cArchiveLegacyCookieSize) {
		t.Fatalf("selected invalid final marker: %#v", result.Candidates[0])
	}
}

func TestParseCArchiveReportsMultipleNestedCandidates(t *testing.T) {
	inner := buildTestCArchive(t, nil, []testCArchiveMember{{name: []byte("inner"), data: []byte("one"), typeCode: 'x'}}, testCArchiveOptions{layout: cArchiveCookieLegacy})
	outer := buildTestCArchive(t, nil, []testCArchiveMember{{name: []byte("nested.pkg"), data: inner, typeCode: 'x'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	first := parseCArchives(outer)
	if len(first.Candidates) != 2 || !first.NestedCandidates || first.ConflictingCandidateOverlap || first.AliasedCandidates {
		t.Fatalf("nested candidates not retained explicitly: %#v", first)
	}
	if first.Candidates[0].Cookie.Offset >= first.Candidates[1].Cookie.Offset {
		t.Fatalf("candidate order is not deterministic: %#v", first.Candidates)
	}
	second := parseCArchives(outer)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("candidate parsing is not deterministic")
	}
}

func TestParseCArchiveRetainsNoncanonicalInterpretationFields(t *testing.T) {
	longName := bytes.Repeat([]byte{'a'}, maxCArchiveRetainedNameBytes+17)
	data := buildTestCArchive(t, nil, []testCArchiveMember{
		{name: []byte(""), data: []byte("empty"), typeCode: 0xff, compressionFlag: 7, nonZeroNamePadding: true},
		{name: []byte{'/', '.', '.', '/', 0xff}, data: []byte("unsafe"), typeCode: 0x01, compressionFlag: 2},
		{name: longName, data: []byte("long"), typeCode: 'x', unterminated: true},
	}, testCArchiveOptions{
		layout:        cArchiveCookieCurrent,
		pythonVersion: 999,
		pythonLibrary: bytes.Repeat([]byte{0xff}, 64),
	})
	result := parseCArchives(data)
	if len(result.Candidates) != 1 {
		t.Fatalf("noncanonical archive was rejected: %#v", result)
	}
	candidate := result.Candidates[0]
	if candidate.PythonVersionPlausible || candidate.PythonLibraryTerminated || candidate.PythonLibraryUTF8 || candidate.PythonLibraryFieldWellFormed || candidate.PythonLibraryNameLength != 64 || !candidate.PythonLibraryNonEmpty {
		t.Fatalf("cookie anomalies were not retained: %#v", candidate)
	}
	if len(candidate.Members) != 3 || !candidate.Members[0].NamePaddingNonZero || candidate.Members[1].NameUTF8 {
		t.Fatalf("member anomalies were not retained: %#v", candidate.Members)
	}
	last := candidate.Members[2]
	if last.NameTerminated || !last.NameTruncated || len(last.RawName) != maxCArchiveRetainedNameBytes || last.RawNameLength <= uint64(len(last.RawName)) {
		t.Fatalf("unterminated/long name metadata = %#v", last)
	}
}

func TestParseCArchiveRejectsMalformedEnvelope(t *testing.T) {
	base := buildTestCArchive(t, nil, []testCArchiveMember{{name: []byte("entry"), data: []byte("data"), typeCode: 'x'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	parsed := parseCArchives(base)
	if len(parsed.Candidates) != 1 {
		t.Fatalf("fixture did not parse: %#v", parsed)
	}
	candidate := parsed.Candidates[0]
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "package length", mutate: func(data []byte) {
			binary.BigEndian.PutUint32(data[candidate.Cookie.Offset+8:candidate.Cookie.Offset+12], ^uint32(0))
		}},
		{name: "toc relation", mutate: func(data []byte) {
			length := binary.BigEndian.Uint32(data[candidate.Cookie.Offset+16 : candidate.Cookie.Offset+20])
			binary.BigEndian.PutUint32(data[candidate.Cookie.Offset+16:candidate.Cookie.Offset+20], length-1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := append([]byte(nil), base...)
			test.mutate(data)
			result := parseCArchives(data)
			if len(result.Candidates) != 0 || result.MagicCount != 1 || result.InvalidSelectedOffsets != 1 {
				t.Fatalf("malformed structure accepted: %#v", result)
			}
		})
	}
}

func TestParseCArchiveRetainsInvalidMemberExtentAndFollowingRecords(t *testing.T) {
	base := buildTestCArchive(t, nil, []testCArchiveMember{
		{name: []byte("first"), data: []byte("one"), typeCode: 's'},
		{name: []byte("poison"), data: []byte("two"), typeCode: 0xff},
		{name: []byte("third"), data: []byte("three"), typeCode: 's'},
	}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	parsed := parseCArchives(base)
	records := testCArchiveRecordOffsets(t, base, parsed.Candidates[0])
	data := append([]byte(nil), base...)
	binary.BigEndian.PutUint32(data[records[1]+4:records[1]+8], ^uint32(0))

	result := parseCArchives(data)
	if len(result.Candidates) != 1 || result.LastMagicHasFullyValidatedCandidate {
		t.Fatalf("invalid member extent hid candidate or supported attribution: %#v", result)
	}
	candidate := result.Candidates[0]
	if candidate.StructureFullyValidated || candidate.InvalidMemberExtents != 1 || candidate.MalformedTOCTail || len(candidate.Members) != 3 {
		t.Fatalf("invalid extent metadata = %#v", candidate)
	}
	if !candidate.Members[0].PayloadInBounds || candidate.Members[1].PayloadInBounds || !candidate.Members[2].PayloadInBounds {
		t.Fatalf("member extent validity = %#v", candidate.Members)
	}
}

func TestParseCArchiveRetainsPrefixOnMalformedTOCTail(t *testing.T) {
	base := buildTestCArchive(t, nil, []testCArchiveMember{
		{name: []byte("first"), data: []byte("one"), typeCode: 's'},
		{name: []byte("second"), data: []byte("two"), typeCode: 's'},
		{name: []byte("third"), data: []byte("three"), typeCode: 's'},
	}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	parsed := parseCArchives(base)
	records := testCArchiveRecordOffsets(t, base, parsed.Candidates[0])
	data := append([]byte(nil), base...)
	binary.BigEndian.PutUint32(data[records[1]:records[1]+4], 17)

	result := parseCArchives(data)
	if len(result.Candidates) != 1 || result.LastMagicHasFullyValidatedCandidate {
		t.Fatalf("malformed TOC tail hid candidate or supported attribution: %#v", result)
	}
	candidate := result.Candidates[0]
	if candidate.StructureFullyValidated || !candidate.MalformedTOCTail || candidate.TOCValidationLimited || len(candidate.Members) != 1 || candidate.UnvalidatedTOCBytes == 0 {
		t.Fatalf("malformed TOC tail metadata = %#v", candidate)
	}
	if result.TOCRecordsVisited != 2 {
		t.Fatalf("visited records = %d, want 2", result.TOCRecordsVisited)
	}
}

func TestCArchiveCandidateSelectionDisclosesOmittedMiddleMarkers(t *testing.T) {
	data := buildTestCArchive(t, nil, []testCArchiveMember{{name: []byte("entry"), data: []byte("data"), typeCode: 'x'}}, testCArchiveOptions{layout: cArchiveCookieLegacy})
	for index := 0; index < maxCArchiveCandidateOffsets+20; index++ {
		data = append(data, cArchiveCookieMagic...)
	}
	result := parseCArchives(data)
	if !result.CandidateValidationTruncated || result.MagicCount != maxCArchiveCandidateOffsets+21 {
		t.Fatalf("candidate truncation is not explicit: %#v", result)
	}
	if len(result.Candidates) != 1 {
		t.Fatalf("leading valid candidate was hidden by appended markers: %#v", result)
	}
}

func TestCArchiveCandidateSelectionPrioritizesPlausibleMiddleEnvelope(t *testing.T) {
	prefix := bytes.Repeat(cArchiveCookieMagic, maxCArchiveLeadingOffsets+4)
	data := buildTestCArchive(t, prefix, []testCArchiveMember{{name: []byte("entry"), data: []byte("data"), typeCode: 'x'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	data = append(data, bytes.Repeat(cArchiveCookieMagic, maxCArchiveTrailingOffsets+12)...)
	result := parseCArchives(data)
	if len(result.Candidates) != 1 || result.PlausibleEnvelopeCount != 1 || result.OmittedPlausibleEnvelopeOffsets != 0 {
		t.Fatalf("plausible middle envelope was displaced by marker noise: %#v", result)
	}
	if result.OmittedMagicOffsets == 0 || !result.CandidateValidationTruncated {
		t.Fatalf("omitted raw markers were not disclosed: %#v", result)
	}
}

func TestParseCArchiveTOCRecordLimitIsPartial(t *testing.T) {
	record := make([]byte, 32)
	binary.BigEndian.PutUint32(record[0:4], uint32(len(record)))
	record[18] = 0
	data := bytes.Repeat(record, 4)
	result := parseCArchiveTOC(data, 0, uint64(len(data)), 2, uint64(len(data)))
	if !result.ValidationLimited || !result.RecordLimitReached || len(result.Members) != 2 || result.UnvalidatedBytes != uint64(2*len(record)) || result.RecordsVisited != 2 || result.BytesVisited != uint64(2*len(record)) {
		t.Fatalf("parseCArchiveTOC() = %#v", result)
	}
}

func TestParseCArchiveTOCMalformedAttemptChargesWorkWithoutLargePreallocation(t *testing.T) {
	record := make([]byte, 32)
	binary.BigEndian.PutUint32(record[0:4], uint32(len(record)))
	data := bytes.Repeat(record, initialCArchiveMemberCapacity*4)
	binary.BigEndian.PutUint32(data[0:4], 17)
	result := parseCArchiveTOC(data, 0, uint64(len(data)), maxCArchiveRecords, uint64(len(data)))
	if !result.MalformedTail || result.ValidationLimited || result.RecordsVisited != 1 || result.BytesVisited != 18 || len(result.Members) != 0 || result.UnvalidatedBytes != uint64(len(data)) {
		t.Fatalf("malformed TOC work accounting = %#v", result)
	}
	if capacity := cap(result.Members); capacity > initialCArchiveMemberCapacity {
		t.Fatalf("initial member capacity = %d, want <= %d", capacity, initialCArchiveMemberCapacity)
	}
}

func TestParseCArchiveCookieReportsByteBudgetAsPartial(t *testing.T) {
	data := buildTestCArchive(t, nil, []testCArchiveMember{{name: []byte("entry"), data: []byte("data"), typeCode: 'x'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	cookieOffset := bytes.LastIndex(data, cArchiveCookieMagic)
	candidate, bytesVisited, recordsVisited, err := parseCArchiveCookie(data, cookieOffset, cArchiveCookieCurrent, 18, maxCArchiveRecords)
	if err != nil || !candidate.TOCValidationLimited || candidate.StructureFullyValidated || candidate.MalformedTOCTail || len(candidate.Members) != 0 {
		t.Fatalf("byte-limited candidate = %#v err=%v", candidate, err)
	}
	if bytesVisited != 18 || recordsVisited != 1 || candidate.UnvalidatedTOCBytes != candidate.TOC.Length {
		t.Fatalf("byte budget accounting = bytes %d records %d candidate %#v", bytesVisited, recordsVisited, candidate)
	}
}

func TestCArchiveRecordLimitedCandidateCannotSupportAttribution(t *testing.T) {
	data := buildTestCArchive(t, nil, []testCArchiveMember{
		{name: []byte("first"), data: []byte("one"), typeCode: 's'},
		{name: []byte("second"), data: []byte("two"), typeCode: 's'},
	}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	cookieOffset := bytes.LastIndex(data, cArchiveCookieMagic)
	candidate, _, _, err := parseCArchiveCookie(data, cookieOffset, cArchiveCookieCurrent, maxCArchiveValidationBytes, 1)
	if err != nil || !candidate.TOCRecordsTruncated || candidate.StructureFullyValidated {
		t.Fatalf("record-limited candidate may support attribution: candidate=%#v err=%v", candidate, err)
	}
}

func TestParseCArchiveAcceptsEmptyNeutralContainer(t *testing.T) {
	data := buildTestCArchive(t, nil, nil, testCArchiveOptions{layout: cArchiveCookieCurrent})
	result := parseCArchives(data)
	if len(result.Candidates) != 1 || !result.LastMagicHasFullyValidatedCandidate {
		t.Fatalf("empty neutral CArchive rejected: %#v", result)
	}
	candidate := result.Candidates[0]
	if !candidate.EmptyTOC || !candidate.StructureFullyValidated || len(candidate.Members) != 0 || result.TOCBytesCharged != 0 || result.TOCRecordsVisited != 0 {
		t.Fatalf("empty neutral CArchive metadata = %#v result=%#v", candidate, result)
	}
}

func TestParseCArchiveLibraryFieldShape(t *testing.T) {
	tests := []struct {
		name       string
		library    []byte
		length     uint64
		nonEmpty   bool
		terminated bool
		padding    bool
		wellFormed bool
	}{
		{name: "well formed", library: []byte("Python"), length: 6, nonEmpty: true, terminated: true, wellFormed: true},
		{name: "empty", library: []byte{}, length: 0, terminated: true},
		{name: "non-zero padding", library: []byte{'P', 'y', 0, 'X'}, length: 2, nonEmpty: true, terminated: true, padding: true},
		{name: "unterminated", library: bytes.Repeat([]byte{'A'}, 64), length: 64, nonEmpty: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := buildTestCArchive(t, nil, []testCArchiveMember{{name: []byte("entry"), data: nil, typeCode: 'x'}}, testCArchiveOptions{layout: cArchiveCookieCurrent, pythonLibrary: test.library})
			candidate := parseCArchives(data).Candidates[0]
			if candidate.PythonLibraryNameLength != test.length || candidate.PythonLibraryNonEmpty != test.nonEmpty || candidate.PythonLibraryTerminated != test.terminated || candidate.PythonLibraryPaddingNonZero != test.padding || candidate.PythonLibraryFieldWellFormed != test.wellFormed {
				t.Fatalf("library metadata = %#v", candidate)
			}
		})
	}
}

func TestParseCArchiveRetainsStoredLengthMismatchAndZeroLengthBoundary(t *testing.T) {
	data := buildTestCArchive(t, nil, []testCArchiveMember{
		{name: []byte("mismatch"), data: []byte("data"), typeCode: 'x', declaredSize: 99},
		{name: []byte("empty"), data: nil, typeCode: 'o'},
	}, testCArchiveOptions{layout: cArchiveCookieLegacy})
	result := parseCArchives(data)
	if len(result.Candidates) != 1 || !result.Candidates[0].StructureFullyValidated {
		t.Fatalf("fixture rejected: %#v", result)
	}
	members := result.Candidates[0].Members
	if !members[0].StoredLengthMismatch || !members[0].PayloadInBounds || !members[1].PayloadInBounds || members[1].Payload.Length != 0 {
		t.Fatalf("member metadata = %#v", members)
	}
}

func TestMarkCArchiveMemberOverlapsDistinguishesAliases(t *testing.T) {
	candidate := cArchiveCandidate{Members: []cArchiveMember{
		{Ordinal: 0, Payload: cArchiveExtent{Offset: 10, Length: 20}, PayloadInBounds: true, AliasOfOrdinal: -1},
		{Ordinal: 1, Payload: cArchiveExtent{Offset: 10, Length: 20}, PayloadInBounds: true, AliasOfOrdinal: -1},
		{Ordinal: 2, Payload: cArchiveExtent{Offset: 12, Length: 2}, PayloadInBounds: true, AliasOfOrdinal: -1},
		{Ordinal: 3, Payload: cArchiveExtent{Offset: 16, Length: 2}, PayloadInBounds: true, AliasOfOrdinal: -1},
	}}
	markCArchiveMemberOverlaps(&candidate)
	if candidate.Members[1].AliasOfOrdinal != 0 || !candidate.NonIdenticalPayloadOverlap {
		t.Fatalf("overlap metadata = %#v", candidate)
	}
	for _, member := range candidate.Members {
		if !member.OverlapsAnotherPayload {
			t.Fatalf("non-adjacent overlap was not retained on every involved member: %#v", candidate)
		}
	}
	if candidate.Members[2].AliasOfOrdinal != -1 || candidate.Members[3].AliasOfOrdinal != -1 {
		t.Fatalf("overlap metadata = %#v", candidate)
	}
}

func TestClassifyCArchiveCandidateRelations(t *testing.T) {
	result := cArchiveParseResult{}
	classifyCArchiveCandidateRelation(&result, cArchiveExtent{Offset: 10, Length: 20}, cArchiveExtent{Offset: 10, Length: 20})
	classifyCArchiveCandidateRelation(&result, cArchiveExtent{Offset: 0, Length: 100}, cArchiveExtent{Offset: 20, Length: 10})
	classifyCArchiveCandidateRelation(&result, cArchiveExtent{Offset: 200, Length: 20}, cArchiveExtent{Offset: 210, Length: 20})
	if !result.AliasedCandidates || !result.NestedCandidates || !result.ConflictingCandidateOverlap {
		t.Fatalf("candidate relations = %#v", result)
	}
}

func testCArchiveRecordOffsets(t *testing.T, data []byte, candidate cArchiveCandidate) []int {
	t.Helper()
	cursor := int(candidate.TOC.Offset)
	end := int(candidate.TOC.Offset + candidate.TOC.Length)
	var offsets []int
	for cursor < end {
		if end-cursor < 18 {
			t.Fatalf("fixture has truncated TOC at %d", cursor)
		}
		recordLength := int(binary.BigEndian.Uint32(data[cursor : cursor+4]))
		if recordLength < 18 || recordLength > end-cursor {
			t.Fatalf("fixture has invalid record length %d at %d", recordLength, cursor)
		}
		offsets = append(offsets, cursor)
		cursor += recordLength
	}
	return offsets
}

func buildTestCArchive(t *testing.T, prefix []byte, members []testCArchiveMember, options testCArchiveOptions) []byte {
	t.Helper()
	if options.layout == "" {
		options.layout = cArchiveCookieCurrent
	}
	if options.pythonVersion == 0 {
		options.pythonVersion = 310
	}
	data := append([]byte(nil), prefix...)
	packageStart := len(data)
	type tocItem struct {
		offset uint32
		member testCArchiveMember
	}
	items := make([]tocItem, 0, len(members))
	for _, member := range members {
		if uint64(len(data)-packageStart) > uint64(^uint32(0)) {
			t.Fatal("test CArchive payload offset exceeds uint32")
		}
		items = append(items, tocItem{offset: uint32(len(data) - packageStart), member: member})
		data = append(data, member.data...)
	}
	tocOffset := len(data) - packageStart
	for _, item := range items {
		member := item.member
		nameLength := len(member.name)
		if !member.unterminated {
			nameLength++
		}
		recordLength := 18 + nameLength
		if remainder := recordLength % 16; remainder != 0 {
			recordLength += 16 - remainder
		}
		record := make([]byte, recordLength)
		binary.BigEndian.PutUint32(record[0:4], uint32(recordLength))
		binary.BigEndian.PutUint32(record[4:8], item.offset)
		binary.BigEndian.PutUint32(record[8:12], uint32(len(member.data)))
		declared := member.declaredSize
		if declared == 0 {
			declared = uint32(len(member.data))
		}
		binary.BigEndian.PutUint32(record[12:16], declared)
		record[16] = member.compressionFlag
		record[17] = member.typeCode
		copy(record[18:], member.name)
		if member.unterminated {
			for index := 18 + len(member.name); index < len(record); index++ {
				record[index] = 0xa5
			}
		} else if member.nonZeroNamePadding && 18+len(member.name)+1 < len(record) {
			record[18+len(member.name)+1] = 0xa5
		}
		data = append(data, record...)
	}
	tocLength := len(data) - packageStart - tocOffset
	cookieSize := cArchiveCookieSize(options.layout)
	packageLength := len(data) - packageStart + cookieSize
	cookie := make([]byte, cookieSize)
	copy(cookie, cArchiveCookieMagic)
	binary.BigEndian.PutUint32(cookie[8:12], uint32(packageLength))
	binary.BigEndian.PutUint32(cookie[12:16], uint32(tocOffset))
	binary.BigEndian.PutUint32(cookie[16:20], uint32(tocLength))
	binary.BigEndian.PutUint32(cookie[20:24], options.pythonVersion)
	if options.layout == cArchiveCookieCurrent {
		library := options.pythonLibrary
		if library == nil {
			library = []byte("Python")
		}
		copy(cookie[24:88], library)
	}
	return append(data, cookie...)
}
