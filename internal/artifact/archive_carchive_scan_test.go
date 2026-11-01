package artifact

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func TestScanCArchivesMaterializesNeutralCandidateWithoutAttribution(t *testing.T) {
	data := buildTestCArchive(t, nil, []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	s, carrierID := newCArchiveScanner(t, Options{}, "blob")
	if !s.scanCArchives(carrierID, "sample", data, "blob", 0) {
		t.Fatal("neutral CArchive was not discovered")
	}
	carrier := artifactTestNode(t, &s.graph, carrierID)
	if carrier.PackagingTechnology != "" {
		t.Fatalf("neutral carrier attributed as %q", carrier.PackagingTechnology)
	}
	candidate := artifactTestNodeByKind(t, &s.graph, "carchive")
	if artifactTestIntValue(candidate.DeclaredEntryCount) != 1 || artifactTestIntValue(candidate.ModeledEntryCount) != 1 {
		t.Fatalf("candidate inventory = %#v", candidate)
	}
	parsedCandidate := parseCArchives(data).Candidates[0]
	wantDigest := cArchiveExtentSHA256(data, parsedCandidate.Package)
	if candidate.SHA256 == "" || candidate.SHA256 != wantDigest {
		t.Fatalf("candidate digest = %q, want exact package digest %q", candidate.SHA256, wantDigest)
	}
	member := artifactTestNodeByKind(t, &s.graph, "carchive-python-record")
	content := artifactTestContent(t, s.contents, member.ID)
	if !content.RawFeaturesOnly || content.Executable || content.Kind != "carchive-python-record" {
		t.Fatalf("neutral Python record was interpreted semantically: %#v", content)
	}
}

func TestScanCArchivesUsesSafeSyntheticNamesForEveryAmbiguousName(t *testing.T) {
	longName := bytes.Repeat([]byte{'a'}, maxCArchiveRetainedNameBytes+32)
	data := buildTestCArchive(t, nil, []testCArchiveMember{
		{name: []byte("../evil"), data: []byte("one"), typeCode: 'x'},
		{name: nil, data: []byte("two"), typeCode: 'x'},
		{name: []byte{0xff}, data: []byte("three"), typeCode: 'x'},
		{name: longName, data: []byte("four"), typeCode: 'x', unterminated: true},
		{name: []byte("duplicate"), data: []byte("five"), typeCode: 'x'},
		{name: []byte("DUPLICATE"), data: []byte("six"), typeCode: 'x'},
	}, testCArchiveOptions{layout: cArchiveCookieLegacy})
	s, carrierID := newCArchiveScanner(t, Options{}, "blob")
	s.scanCArchives(carrierID, "sample", data, "blob", 0)
	candidate := artifactTestNodeByKind(t, &s.graph, "carchive")
	children := artifactTestChildren(s.graph, candidate.ID)
	if len(children) != 6 {
		t.Fatalf("modeled children = %d, want 6: %#v", len(children), children)
	}
	seen := map[string]bool{}
	for _, child := range children {
		if !strings.Contains(child.LogicalPath, "!_carchive_records/record-") {
			t.Fatalf("ambiguous name was exposed instead of synthesized: %q", child.LogicalPath)
		}
		if seen[child.LogicalPath] {
			t.Fatalf("duplicate synthetic path %q", child.LogicalPath)
		}
		seen[child.LogicalPath] = true
	}
}

func TestScanCArchivesInventoriesMetadataAndSymlinkWithoutFollowingPayloads(t *testing.T) {
	data := buildTestCArchive(t, nil, []testCArchiveMember{
		{name: []byte("dependency"), data: []byte("ignored"), typeCode: 'd', compressionFlag: 7},
		{name: []byte("option"), data: []byte("ignored"), typeCode: 'o', compressionFlag: 7},
		{name: []byte("link"), data: []byte("../../outside"), typeCode: 'n'},
	}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	s, carrierID := newCArchiveScanner(t, Options{}, "blob")
	s.scanCArchives(carrierID, "sample", data, "blob", 0)
	for _, name := range []string{"dependency", "option"} {
		node := artifactTestNodeBySuffix(t, &s.graph, "!"+name)
		if node.Kind != "carchive-metadata" || node.AnalyzeStatus != "analyzed" {
			t.Fatalf("metadata record %s = %#v", name, node)
		}
	}
	link := artifactTestNodeBySuffix(t, &s.graph, "!link")
	if link.Kind != "symlink" || link.AnalyzeStatus != "skipped" || !strings.Contains(link.CoverageDetail, "not followed") {
		t.Fatalf("symlink inventory = %#v", link)
	}
	if len(s.contents) != 0 {
		t.Fatalf("metadata/symlink payloads were retained or followed: %#v", s.contents)
	}
}

func TestScanCArchivesExactDecodingAndTypePolicy(t *testing.T) {
	pyz := []byte{'P', 'Y', 'Z', 0, 'd', 'a', 't', 'a'}
	plain := []byte("not a pyz")
	validPYZ := testCArchiveZlib(t, pyz)
	validPlain := testCArchiveZlib(t, plain)
	trailing := append(testCArchiveZlib(t, pyz), []byte("tail")...)
	concatenated := append(testCArchiveZlib(t, pyz), testCArchiveZlib(t, []byte("second"))...)
	badChecksum := append([]byte(nil), validPYZ...)
	badChecksum[len(badChecksum)-1] ^= 0xff
	data := buildTestCArchive(t, nil, []testCArchiveMember{
		{name: []byte("mismatch"), data: []byte("data"), typeCode: 'x', declaredSize: 99},
		{name: []byte("flag"), data: []byte("data"), typeCode: 'x', compressionFlag: 7},
		{name: []byte("corrupt"), data: []byte("bad"), typeCode: 'z', compressionFlag: 1, declaredSize: 10},
		{name: []byte("checksum"), data: badChecksum, typeCode: 'z', compressionFlag: 1, declaredSize: uint32(len(pyz))},
		{name: []byte("trailing"), data: trailing, typeCode: 'z', compressionFlag: 1, declaredSize: uint32(len(pyz))},
		{name: []byte("concatenated"), data: concatenated, typeCode: 'z', compressionFlag: 1, declaredSize: uint32(len(pyz))},
		{name: []byte("short"), data: validPYZ, typeCode: 'z', compressionFlag: 1, declaredSize: uint32(len(pyz) + 1)},
		{name: []byte("long"), data: validPYZ, typeCode: 'z', compressionFlag: 1, declaredSize: uint32(len(pyz) - 1)},
		{name: []byte("pyz"), data: validPYZ, typeCode: 'z', compressionFlag: 1, declaredSize: uint32(len(pyz))},
		{name: []byte("notpyz"), data: validPlain, typeCode: 'z', compressionFlag: 1, declaredSize: uint32(len(plain))},
		{name: []byte("vendor/binary"), data: testThinMachO(), typeCode: 'b'},
		{name: []byte("archive"), data: testThinMachO(), typeCode: 'Z'},
		{name: []byte("executable"), data: testThinMachO(), typeCode: 'x'},
		{name: []byte("library"), data: testThinMachO(), typeCode: 'l'},
		{name: []byte("unknown"), data: testThinMachO(), typeCode: 0xfe},
	}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	s, carrierID := newCArchiveScanner(t, Options{MaxCompressionRatio: 1000}, "blob")
	s.scanCArchives(carrierID, "sample", data, "blob", 0)

	for _, name := range []string{"mismatch", "flag", "corrupt", "checksum", "trailing", "concatenated", "short", "long"} {
		node := artifactTestNodeBySuffix(t, &s.graph, "!"+name)
		if node.AnalyzeStatus != "skipped" || node.CoverageDetail == "" {
			t.Fatalf("%s decoding status = %#v", name, node)
		}
	}
	pyzNode := artifactTestNodeBySuffix(t, &s.graph, "!pyz")
	if pyzNode.Kind != "python-pyz" || !artifactTestContent(t, s.contents, pyzNode.ID).RawFeaturesOnly {
		t.Fatalf("PYZ representation = %#v", pyzNode)
	}
	plainNode := artifactTestNodeBySuffix(t, &s.graph, "!notpyz")
	if plainNode.Kind != "carchive-record" || !artifactTestContent(t, s.contents, plainNode.ID).RawFeaturesOnly {
		t.Fatalf("non-PYZ z record = %#v", plainNode)
	}
	binaryNode := artifactTestNodeBySuffix(t, &s.graph, "!vendor/binary")
	binaryContent := artifactTestContent(t, s.contents, binaryNode.ID)
	if binaryNode.Kind != "macho" || binaryNode.SourceRole != "packaged-content" || binaryContent.Role != "packaged-content" || binaryContent.Executable || binaryContent.RawFeaturesOnly {
		t.Fatalf("binary record policy = node %#v content %#v", binaryNode, binaryContent)
	}
	for _, name := range []string{"archive", "executable", "library", "unknown"} {
		node := artifactTestNodeBySuffix(t, &s.graph, "!"+name)
		content := artifactTestContent(t, s.contents, node.ID)
		if node.Kind != "macho" || node.SourceRole != "packaged-content" || content.Role != "packaged-content" || content.Executable || content.RawFeaturesOnly {
			t.Fatalf("content-first record %s = node %#v content %#v", name, node, content)
		}
	}
	if pyzNode.SourceRole != "packaged-content" || artifactTestContent(t, s.contents, pyzNode.ID).Role != "packaged-content" {
		t.Fatalf("raw PYZ source role changed semantic policy: node=%#v content=%#v", pyzNode, artifactTestContent(t, s.contents, pyzNode.ID))
	}
}

func TestCArchiveDecodeFailuresConsumeSharedAttemptBudgets(t *testing.T) {
	payload := testCArchiveZlib(t, []byte("data"))
	s := scanner{options: Options{MaxArchiveBytes: 64, MaxCompressionRatio: 1000}.normalized()}
	budget := &cArchiveDecodeBudget{}
	member := cArchiveMember{
		Payload:          cArchiveExtent{Offset: 0, Length: uint64(len(payload))},
		CompressedLength: uint32(len(payload)),
		DeclaredSize:     64,
		CompressionFlag:  1,
		PayloadInBounds:  true,
		AliasOfOrdinal:   -1,
		NameTerminated:   true,
	}
	if _, detail := s.decodeCArchiveMember(payload, member, budget); !strings.Contains(detail, "decoded size") {
		t.Fatalf("first decode detail = %q", detail)
	}
	member.DeclaredSize = 4
	if _, detail := s.decodeCArchiveMember(payload, member, budget); !strings.Contains(detail, "attempted decoded-output") {
		t.Fatalf("failed attempt did not consume output budget: %q budget=%#v", detail, budget)
	}

	corrupt := []byte("not-zlib")
	s = scanner{options: Options{MaxArchiveBytes: int64(len(corrupt)), MaxCompressionRatio: 1000}.normalized()}
	budget = &cArchiveDecodeBudget{}
	member.Payload = cArchiveExtent{Offset: 0, Length: uint64(len(corrupt))}
	member.CompressedLength = uint32(len(corrupt))
	member.DeclaredSize = 1
	if _, detail := s.decodeCArchiveMember(corrupt, member, budget); !strings.Contains(detail, "header") {
		t.Fatalf("first corrupt decode detail = %q", detail)
	}
	if _, detail := s.decodeCArchiveMember(corrupt, member, budget); !strings.Contains(detail, "decode-work") {
		t.Fatalf("failed attempt did not consume compressed-work budget: %q budget=%#v", detail, budget)
	}
}

func TestScanCArchivesPreservesCandidateWhenExpansionDisabledOrDepthLimited(t *testing.T) {
	data := buildTestCArchive(t, nil, []testCArchiveMember{{name: []byte("payload"), data: []byte("data"), typeCode: 'x'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	tests := []struct {
		name    string
		options Options
		depth   int
	}{
		{name: "disabled", options: Options{DisableContainerExpansion: true}},
		{name: "depth", options: Options{MaxArchiveDepth: 1}, depth: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, carrierID := newCArchiveScanner(t, test.options, "blob")
			s.scanCArchives(carrierID, "sample", data, "blob", test.depth)
			candidate := artifactTestNodeByKind(t, &s.graph, "carchive")
			if candidate.AnalyzeStatus != "partial" || artifactTestIntValue(candidate.ModeledEntryCount) != 0 || len(artifactTestChildren(s.graph, candidate.ID)) != 0 {
				t.Fatalf("preserved candidate = %#v graph=%#v", candidate, s.graph)
			}
		})
	}
}

func TestScanCArchivesEmptyTOCIsCompleteWhenExpansionDisabledOrDepthLimited(t *testing.T) {
	data := buildTestCArchive(t, nil, nil, testCArchiveOptions{layout: cArchiveCookieCurrent})
	tests := []struct {
		name    string
		options Options
		depth   int
	}{
		{name: "disabled", options: Options{DisableContainerExpansion: true}},
		{name: "depth", options: Options{MaxArchiveDepth: 1}, depth: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, carrierID := newCArchiveScanner(t, test.options, "blob")
			s.scanCArchives(carrierID, "sample", data, "blob", test.depth)
			carrier := artifactTestNode(t, &s.graph, carrierID)
			candidate := artifactTestNodeByKind(t, &s.graph, "carchive")
			if carrier.AnalyzeStatus != "analyzed" || carrier.CoverageDetail != "" || candidate.AnalyzeStatus != "analyzed" || candidate.CoverageDetail != "" || artifactTestIntValue(candidate.ModeledEntryCount) != 0 {
				t.Fatalf("empty candidate was presented as incomplete: carrier=%#v candidate=%#v", carrier, candidate)
			}
			if len(s.diagnostics) != 0 {
				t.Fatalf("empty candidate emitted expansion diagnostics: %#v", s.diagnostics)
			}
		})
	}
}

func TestScanCArchivesDisclosesCandidateDigestWorkLimit(t *testing.T) {
	data := buildTestCArchive(t, nil, []testCArchiveMember{{name: []byte("payload"), data: []byte("data"), typeCode: 'x'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	s, carrierID := newCArchiveScanner(t, Options{MaxArchiveBytes: 1, DisableContainerExpansion: true}, "blob")
	s.scanCArchives(carrierID, "sample", data, "blob", 0)
	candidate := artifactTestNodeByKind(t, &s.graph, "carchive")
	if candidate.SHA256 != "" || candidate.AnalyzeStatus != "partial" || !strings.Contains(candidate.CoverageDetail, "SHA-256 omitted") {
		t.Fatalf("candidate digest coverage = %#v", candidate)
	}
}

func TestScanCArchivesInventoriesInvalidExtentWithoutReadingIt(t *testing.T) {
	data := buildTestCArchive(t, nil, []testCArchiveMember{{name: []byte("outside"), data: []byte("data"), typeCode: 'x'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	parsed := parseCArchives(data)
	record := testCArchiveRecordOffsets(t, data, parsed.Candidates[0])[0]
	binary.BigEndian.PutUint32(data[record+4:record+8], ^uint32(0))

	s, carrierID := newCArchiveScanner(t, Options{}, "blob")
	if !s.scanCArchives(carrierID, "sample", data, "blob", 0) {
		t.Fatal("partial neutral CArchive was not inventoried")
	}
	candidate := artifactTestNodeByKind(t, &s.graph, "carchive")
	if candidate.AnalyzeStatus != "partial" || candidate.SHA256 == "" {
		t.Fatalf("candidate coverage/digest = %#v", candidate)
	}
	member := artifactTestNodeBySuffix(t, &s.graph, "!outside")
	if member.AnalyzeStatus != "skipped" || !strings.Contains(member.CoverageDetail, "outside") {
		t.Fatalf("invalid extent inventory = %#v", member)
	}
	if len(s.contents) != 0 {
		t.Fatalf("invalid payload was retained: %#v", s.contents)
	}
}

func TestScanCArchivesDoesNotPresentPartialTOCPrefixAsDeclaredTotal(t *testing.T) {
	base := buildTestCArchive(t, nil, []testCArchiveMember{{name: []byte("parsed"), data: []byte("data"), typeCode: 'x'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	parsed := parseCArchives(base).Candidates[0]
	cookieOffset := int(parsed.Cookie.Offset)
	data := make([]byte, 0, len(base)+1)
	data = append(data, base[:cookieOffset]...)
	data = append(data, 0xff)
	data = append(data, base[cookieOffset:]...)
	newCookieOffset := cookieOffset + 1
	binary.BigEndian.PutUint32(data[newCookieOffset+8:newCookieOffset+12], uint32(parsed.Package.Length+1))
	binary.BigEndian.PutUint32(data[newCookieOffset+16:newCookieOffset+20], uint32(parsed.TOC.Length+1))
	partial := parseCArchives(data)
	if len(partial.Candidates) != 1 || !partial.Candidates[0].MalformedTOCTail || len(partial.Candidates[0].Members) != 1 {
		t.Fatalf("fixture did not retain a parsed TOC prefix: %#v", partial)
	}

	s, carrierID := newCArchiveScanner(t, Options{}, "blob")
	s.scanCArchives(carrierID, "sample", data, "blob", 0)
	candidate := artifactTestNodeByKind(t, &s.graph, "carchive")
	if candidate.DeclaredEntryCount != nil || artifactTestIntValue(candidate.ModeledEntryCount) != 1 || candidate.AnalyzeStatus != "partial" {
		t.Fatalf("partial TOC inventory looks complete: %#v", candidate)
	}
}

func TestMaterializeCArchiveAliasesRetainEachSelectedRecordWithoutRepeatingDecodeWork(t *testing.T) {
	data := buildTestCArchive(t, nil, []testCArchiveMember{
		{name: []byte("decoded"), data: []byte("one"), typeCode: 'x'},
		{name: []byte("alias"), data: []byte("two"), typeCode: 'x'},
		{name: []byte("overlap"), data: []byte("three"), typeCode: 'x'},
	}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	candidate := parseCArchives(data).Candidates[0]
	candidate.Members[1].Payload = candidate.Members[0].Payload
	candidate.Members[1].CompressedLength = candidate.Members[0].CompressedLength
	candidate.Members[1].DeclaredSize = candidate.Members[0].DeclaredSize
	candidate.Members[1].AliasOfOrdinal = candidate.Members[0].Ordinal
	candidate.Members[2].OverlapsAnotherPayload = true

	s, carrierID := newCArchiveScanner(t, Options{}, "blob")
	candidateID := s.graph.AddNode(Node{ParentID: carrierID, LogicalPath: "sample!candidate", Kind: "carchive"})
	budget := &cArchiveDecodeBudget{}
	stats := s.materializeCArchiveMembers(carrierID, scannedCArchiveCandidate{
		candidate: candidate,
		nodeID:    candidateID,
		logical:   "sample!candidate",
	}, data, 1, false, nil, budget)
	if stats.modeled != 3 || stats.skipped != 1 || len(s.contents) != 2 {
		t.Fatalf("alias/conflict inventory = stats %#v contents %#v", stats, s.contents)
	}
	wantWork := int64(candidate.Members[0].DeclaredSize)
	if budget.decodedBytesAttempted != wantWork || budget.compressedBytesRead != wantWork {
		t.Fatalf("decode work multiplied across alias/conflict: budget=%#v want=%d", budget, wantWork)
	}
	first := artifactTestNodeBySuffix(t, &s.graph, "!decoded")
	alias := artifactTestNodeBySuffix(t, &s.graph, "!alias")
	if first.ID == alias.ID || first.AnalyzeStatus != "analyzed" || alias.AnalyzeStatus != "analyzed" {
		t.Fatalf("selected alias did not retain its own analyzed node: first=%#v alias=%#v", first, alias)
	}
	if got := artifactTestContent(t, s.contents, alias.ID).Data; !bytes.Equal(got, []byte("one")) {
		t.Fatalf("alias decoded bytes = %q, want canonical extent bytes", got)
	}
}

func TestCArchiveRepeatedDecodeKeysRetainsOnlySelectedAliases(t *testing.T) {
	candidate := cArchiveCandidate{Members: []cArchiveMember{
		{Payload: cArchiveExtent{Offset: 1, Length: 2}, CompressedLength: 2, DeclaredSize: 2, PayloadInBounds: true, AliasOfOrdinal: -1},
		{Payload: cArchiveExtent{Offset: 3, Length: 4}, CompressedLength: 4, DeclaredSize: 4, PayloadInBounds: true, AliasOfOrdinal: -1},
		{Payload: cArchiveExtent{Offset: 1, Length: 2}, CompressedLength: 2, DeclaredSize: 2, PayloadInBounds: true, AliasOfOrdinal: 0},
	}}
	got := cArchiveRepeatedDecodeKeys(candidate, []int{0, 1, 2})
	wantKey := cArchiveDecodeKey(candidate.Members[0])
	if len(got) != 1 || !got[wantKey] {
		t.Fatalf("repeated decode cache keys = %#v, want only exact alias key %#v", got, wantKey)
	}
}

func TestScanCArchivesLargeTOCDecodesSelectedLoaderAliasWhenCanonicalRecordIsOmitted(t *testing.T) {
	memberCount := MaxArchiveEntries + 64
	members := make([]testCArchiveMember, memberCount)
	for ordinal := range members {
		members[ordinal] = testCArchiveMember{name: []byte("record-" + zeroPad(ordinal, 6)), data: []byte{byte(ordinal)}, typeCode: 'x'}
	}
	members[memberCount-1] = testCArchiveMember{name: []byte("selected-loader-alias"), data: []byte("unused-alias-payload"), typeCode: 's'}
	base := buildTestCArchive(t, pyInstallerTestPrefix(), members, testCArchiveOptions{layout: cArchiveCookieCurrent})
	baseCandidate := parseCArchives(base).Candidates[0]
	selected := map[int]bool{}
	for _, index := range selectCArchiveMemberIndexes(baseCandidate, MaxArchiveEntries) {
		selected[index] = true
	}
	canonicalIndex := -1
	for index := 1; index < memberCount-1; index++ {
		if !selected[index] {
			canonicalIndex = index
			break
		}
	}
	if canonicalIndex < 0 {
		t.Fatal("fixture did not contain an omitted canonical record")
	}

	data := append([]byte(nil), base...)
	records := testCArchiveRecordOffsets(t, data, baseCandidate)
	canonical := baseCandidate.Members[canonicalIndex]
	aliasRecord := records[memberCount-1]
	relativeOffset := canonical.Payload.Offset - baseCandidate.Package.Offset
	binary.BigEndian.PutUint32(data[aliasRecord+4:aliasRecord+8], uint32(relativeOffset))
	binary.BigEndian.PutUint32(data[aliasRecord+8:aliasRecord+12], canonical.CompressedLength)
	binary.BigEndian.PutUint32(data[aliasRecord+12:aliasRecord+16], canonical.DeclaredSize)
	data[aliasRecord+16] = canonical.CompressionFlag

	parsed := parseCArchives(data)
	if len(parsed.Candidates) != 1 || parsed.Candidates[0].Members[memberCount-1].AliasOfOrdinal != canonical.Ordinal {
		aliasOf := -2
		if len(parsed.Candidates) == 1 && len(parsed.Candidates[0].Members) == memberCount {
			aliasOf = parsed.Candidates[0].Members[memberCount-1].AliasOfOrdinal
		}
		t.Fatalf("fixture did not establish an exact alias: candidates=%d alias-of=%d want=%d", len(parsed.Candidates), aliasOf, canonical.Ordinal)
	}
	selected = map[int]bool{}
	for _, index := range selectCArchiveMemberIndexes(parsed.Candidates[0], MaxArchiveEntries) {
		selected[index] = true
	}
	if selected[canonicalIndex] || !selected[memberCount-1] {
		t.Fatalf("fixture selection canonical=%v alias=%v, want omitted/selected", selected[canonicalIndex], selected[memberCount-1])
	}

	s, carrierID := newCArchiveScanner(t, Options{}, "macho")
	s.scanCArchives(carrierID, "sample", data, "macho", 0)
	alias := artifactTestNodeBySuffix(t, &s.graph, "!selected-loader-alias")
	content := artifactTestContent(t, s.contents, alias.ID)
	canonicalEnd, ok := canonical.Payload.end()
	if !ok {
		t.Fatal("canonical fixture extent overflowed")
	}
	wantPayload := data[int(canonical.Payload.Offset):int(canonicalEnd)]
	if alias.AnalyzeStatus != "analyzed" || alias.Kind != "python-marshal" || alias.SourceRole != "runtime" || content.Role != "runtime" || !content.RawFeaturesOnly || !bytes.Equal(content.Data, wantPayload) {
		t.Fatalf("selected loader alias was not decoded safely: node=%#v content=%#v", alias, content)
	}
	canonicalModeled := false
	for _, node := range s.graph.Nodes {
		canonicalModeled = canonicalModeled || strings.HasSuffix(node.LogicalPath, "!record-"+zeroPad(canonicalIndex, 6))
	}
	if canonicalModeled {
		t.Fatalf("omitted canonical record %d unexpectedly consumed a logical child", canonicalIndex)
	}
	loaderEdges := 0
	for _, edge := range s.graph.Edges {
		if edge.From == carrierID && edge.To == alias.ID && edge.Kind == "loader-invokes" {
			loaderEdges++
		}
	}
	if loaderEdges != 1 {
		t.Fatalf("selected alias loader relationships = %d, want 1: %#v", loaderEdges, s.graph.Edges)
	}
}

func TestScanCArchivesWholeTOCSelectionRetainsOrderedScriptAnchors(t *testing.T) {
	members := make([]testCArchiveMember, MaxArchiveEntries+2)
	for ordinal := range members {
		members[ordinal] = testCArchiveMember{name: []byte("record-" + zeroPad(ordinal, 6)), typeCode: 'x'}
	}
	members[5].typeCode = 's'
	members[len(members)-1].typeCode = 's'
	data := buildTestCArchive(t, pyInstallerTestPrefix(), members, testCArchiveOptions{layout: cArchiveCookieCurrent})
	s, carrierID := newCArchiveScanner(t, Options{}, "macho")
	s.scanCArchives(carrierID, "sample", data, "macho", 0)

	candidate := artifactTestNodeByKind(t, &s.graph, "carchive")
	if artifactTestIntValue(candidate.DeclaredEntryCount) != len(members) || artifactTestIntValue(candidate.ModeledEntryCount) != MaxArchiveEntries || candidate.AnalyzeStatus != "partial" {
		t.Fatalf("whole-TOC candidate inventory = %#v", candidate)
	}
	var ordinals []int
	for _, edge := range s.graph.Edges {
		if edge.From == carrierID && edge.Kind == "loader-invokes" && edge.Ordinal != nil {
			ordinals = append(ordinals, *edge.Ordinal)
		}
	}
	want := []int{0, 1}
	if !reflect.DeepEqual(ordinals, want) {
		t.Fatalf("selected loader order = %v, want %v", ordinals, want)
	}
}

func TestSelectCArchiveMembersUsesWholeTOCAnchorsAndHash(t *testing.T) {
	candidate := cArchiveCandidate{Cookie: cArchiveExtent{Offset: 1234}}
	for ordinal := 0; ordinal < MaxArchiveEntries+4; ordinal++ {
		typeCode := byte('x')
		if ordinal == MaxArchiveEntries+3 {
			typeCode = 's'
		}
		candidate.Members = append(candidate.Members, cArchiveMember{
			Ordinal: ordinal, TypeCode: typeCode, RawName: []byte(zeroPad(ordinal, 6)),
			Payload: cArchiveExtent{Offset: uint64(ordinal * 4), Length: 4}, PayloadInBounds: true,
		})
	}
	first := selectCArchiveMemberIndexes(candidate, MaxArchiveEntries)
	second := selectCArchiveMemberIndexes(candidate, MaxArchiveEntries)
	if !reflect.DeepEqual(first, second) || len(first) != MaxArchiveEntries {
		t.Fatalf("selection is not deterministic/bounded: %d %#v", len(first), first)
	}
	selected := map[int]bool{}
	for _, index := range first {
		selected[index] = true
	}
	if !selected[0] || !selected[len(candidate.Members)-1] {
		t.Fatalf("whole-TOC anchors were not retained: first=%v last=%v", selected[0], selected[len(candidate.Members)-1])
	}
	if selected[MaxArchiveEntries-1] && !selected[MaxArchiveEntries] && !selected[MaxArchiveEntries+1] && !selected[MaxArchiveEntries+2] {
		t.Fatal("selection degenerated to the first-N records")
	}
}

func TestSelectCArchiveMembersSamplesAllDirectExecutionTypesAtOnePriority(t *testing.T) {
	candidate := cArchiveCandidate{Cookie: cArchiveExtent{Offset: 4321}}
	types := []byte{'s', 'm', 'M'}
	for ordinal := 0; ordinal < MaxArchiveEntries*2; ordinal++ {
		candidate.Members = append(candidate.Members, cArchiveMember{
			Ordinal: ordinal, TypeCode: types[ordinal%len(types)], RawName: []byte(zeroPad(ordinal, 6)),
			Payload: cArchiveExtent{Offset: uint64(ordinal * 4), Length: 4}, PayloadInBounds: true,
		})
	}
	selected := selectCArchiveMemberIndexes(candidate, MaxArchiveEntries)
	counts := map[byte]int{}
	for _, index := range selected {
		counts[candidate.Members[index].TypeCode]++
	}
	if len(selected) != MaxArchiveEntries || counts['s'] <= 2 || counts['m'] <= 2 || counts['M'] <= 2 {
		t.Fatalf("direct-execution selection was type-starved: selected=%d counts=%v", len(selected), counts)
	}
	if cArchiveMemberTypeRank('s') != cArchiveMemberTypeRank('m') || cArchiveMemberTypeRank('s') != cArchiveMemberTypeRank('M') {
		t.Fatalf("direct-execution types have different selection ranks: s=%d m=%d M=%d", cArchiveMemberTypeRank('s'), cArchiveMemberTypeRank('m'), cArchiveMemberTypeRank('M'))
	}
}

func TestSelectCArchiveCandidatesExpandsLatestNonOverlappingSet(t *testing.T) {
	candidates := []scannedCArchiveCandidate{
		{candidate: cArchiveCandidate{Package: cArchiveExtent{Offset: 0, Length: 20}}},
		{candidate: cArchiveCandidate{Package: cArchiveExtent{Offset: 10, Length: 20}}},
		{candidate: cArchiveCandidate{Package: cArchiveExtent{Offset: 40, Length: 10}}},
	}
	selected := selectCArchiveCandidatesForExpansion(candidates)
	want := []bool{false, true, true}
	if !reflect.DeepEqual(selected, want) {
		t.Fatalf("expansion selection = %#v, want %#v", selected, want)
	}
}

func TestCArchiveCandidateDigestsUseLatestFirstSharedWorkCap(t *testing.T) {
	data := []byte("0123456789abcdef")
	earlier := cArchiveExtent{Offset: 0, Length: 8}
	later := cArchiveExtent{Offset: 8, Length: 8}
	digests, omitted := cArchiveCandidateDigests(data, []cArchiveCandidate{
		{Package: earlier},
		{Package: later},
		{Package: later}, // exact aliases reuse the digest without more work
	}, 8)
	if digests[later] != cArchiveExtentSHA256(data, later) || omitted[later] || !omitted[earlier] || digests[earlier] != "" {
		t.Fatalf("bounded candidate digests = digests %#v omitted %#v", digests, omitted)
	}
}

func testCArchiveZlib(t *testing.T, data []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zlib.NewWriter(&output)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func newCArchiveScanner(t *testing.T, options Options, kind string) (*scanner, string) {
	t.Helper()
	s := &scanner{options: options.normalized()}
	id := s.graph.AddNode(Node{LogicalPath: "sample", Kind: kind, AnalyzeStatus: "analyzed", SourceRole: "target"})
	return s, id
}

func artifactTestNode(t *testing.T, graph *Graph, id string) Node {
	t.Helper()
	for _, node := range graph.Nodes {
		if node.ID == id {
			return node
		}
	}
	t.Fatalf("node %s not found", id)
	return Node{}
}

func artifactTestNodeByKind(t *testing.T, graph *Graph, kind string) Node {
	t.Helper()
	for _, node := range graph.Nodes {
		if node.Kind == kind {
			return node
		}
	}
	t.Fatalf("node kind %s not found: %#v", kind, graph.Nodes)
	return Node{}
}

func artifactTestNodeBySuffix(t *testing.T, graph *Graph, suffix string) Node {
	t.Helper()
	for _, node := range graph.Nodes {
		if strings.HasSuffix(node.LogicalPath, suffix) {
			return node
		}
	}
	t.Fatalf("node suffix %s not found: %#v", suffix, graph.Nodes)
	return Node{}
}

func artifactTestContent(t *testing.T, contents []Content, nodeID string) Content {
	t.Helper()
	for _, content := range contents {
		if content.NodeID == nodeID {
			return content
		}
	}
	t.Fatalf("content for node %s not found", nodeID)
	return Content{}
}

func artifactTestChildren(graph Graph, parentID string) []Node {
	var children []Node
	for _, node := range graph.Nodes {
		if node.ParentID == parentID {
			children = append(children, node)
		}
	}
	return children
}

func artifactTestIntValue(value *int) int {
	if value == nil {
		return -1
	}
	return *value
}
