package artifact

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"strings"
	"testing"
)

func TestPyInstallerRecognizerRequiresIndependentPrefixEvidence(t *testing.T) {
	markers := pyInstallerTestMarkers()
	tests := []struct {
		name        string
		carrierKind string
		prefix      []byte
		memberData  []byte
	}{
		{name: "no markers", carrierKind: "macho", prefix: pyInstallerTestThinMachO(), memberData: []byte("marshal")},
		{name: "member-only markers", carrierKind: "macho", prefix: pyInstallerTestThinMachO(), memberData: markers},
		{name: "non Mach-O", carrierKind: "blob", prefix: markers, memberData: []byte("marshal")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := buildTestCArchive(t, test.prefix, []testCArchiveMember{{name: []byte("main"), data: test.memberData, typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
			parsed := parseCArchives(data)
			if _, ok := recognizePyInstallerFacade(parsed, data, test.carrierKind); ok {
				t.Fatalf("untrusted evidence attributed PyInstaller: %#v", parsed)
			}
		})
	}
}

func TestPyInstallerRecognizerRequiresExecutableThinMachOCarrier(t *testing.T) {
	for _, fileType := range []macho.Type{macho.TypeDylib, macho.TypeObj} {
		t.Run(fileType.String(), func(t *testing.T) {
			prefix := pyInstallerTestThinMachO()
			binary.LittleEndian.PutUint32(prefix[12:16], uint32(fileType))
			prefix = append(prefix, pyInstallerTestMarkers()...)
			data := buildTestCArchive(t, prefix, []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
			if _, err := PreflightMachO(data); err != nil {
				t.Fatalf("adversarial %s carrier is not preflight-valid: %v", fileType, err)
			}
			if kind, _ := Detect("", data, true); kind != "macho" {
				t.Fatalf("adversarial %s carrier detected as %q", fileType, kind)
			}
			parsed := parseCArchives(data)
			if len(parsed.Candidates) != 1 {
				t.Fatalf("neutral CArchive was not parsed: %#v", parsed)
			}
			if _, ok := recognizePyInstallerFacade(parsed, data, "macho"); ok {
				t.Fatalf("%s carrier was attributed as a PyInstaller executable", fileType)
			}

			s, carrierID := newCArchiveScanner(t, Options{}, "macho")
			if !s.scanCArchives(carrierID, "sample", data, "macho", 0) {
				t.Fatal("neutral CArchive scanning was disabled with producer attribution")
			}
			carrier := artifactTestNode(t, &s.graph, carrierID)
			if carrier.PackagingTechnology != "" {
				t.Fatalf("neutral %s carrier packaging = %q", fileType, carrier.PackagingTechnology)
			}
			_ = artifactTestNodeByKind(t, &s.graph, "carchive")
		})
	}
}

func TestPyInstallerRecognizerRequiresRunnableThinMachOShape(t *testing.T) {
	prefix := append(testThinMachO(), pyInstallerTestMarkers()...)
	data := buildTestCArchive(t, prefix, []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	if _, err := PreflightMachO(data); err != nil {
		t.Fatalf("zero-command MH_EXECUTE fixture should remain neutral-preflight valid: %v", err)
	}
	parsed := parseCArchives(data)
	if len(parsed.Candidates) != 1 {
		t.Fatalf("neutral CArchive was not parsed: %#v", parsed)
	}
	if _, ok := recognizePyInstallerFacade(parsed, data, "macho"); ok {
		t.Fatal("zero-command MH_EXECUTE was attributed as a runnable PyInstaller carrier")
	}
}

func TestPyInstallerRunnableMachORequiresExecutableSegmentAndEntryCommand(t *testing.T) {
	mainCommand := testMachOLoadCommand(pyInstallerLCMain, 24)
	binary.LittleEndian.PutUint64(mainCommand[8:16], 128)
	nonExecutableSegment := pyInstallerTestExecutableSegment64(132)
	binary.LittleEndian.PutUint32(nonExecutableSegment[60:64], 1)
	malformedThread := testMachOLoadCommand(macho.LoadCmdUnixThread, 16)
	binary.LittleEndian.PutUint32(malformedThread[8:12], 4)
	validThread := testMachOLoadCommand(macho.LoadCmdUnixThread, 20)
	binary.LittleEndian.PutUint32(validThread[8:12], 4)
	binary.LittleEndian.PutUint32(validThread[12:16], 1)
	tests := []struct {
		name     string
		commands [][]byte
		code     []byte
		want     bool
	}{
		{name: "no commands"},
		{name: "segment only", commands: [][]byte{pyInstallerTestExecutableSegment64(108)}, code: make([]byte, 4)},
		{name: "main only", commands: [][]byte{mainCommand}, code: make([]byte, 4)},
		{name: "non-executable segment", commands: [][]byte{nonExecutableSegment, mainCommand}, code: make([]byte, 4)},
		{name: "entry outside segment", commands: [][]byte{pyInstallerTestExecutableSegment64(128), mainCommand}, code: make([]byte, 4)},
		{name: "malformed unix thread", commands: [][]byte{pyInstallerTestExecutableSegment64(124), malformedThread}, code: make([]byte, 4)},
		{name: "main entry", commands: [][]byte{pyInstallerTestExecutableSegment64(132), mainCommand}, code: make([]byte, 4), want: true},
		{name: "legacy unix thread", commands: [][]byte{pyInstallerTestExecutableSegment64(128), validThread}, code: make([]byte, 4), want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := testThinMachO(test.commands...)
			image = append(image, test.code...)
			if _, err := PreflightMachO(image); err != nil {
				t.Fatalf("runnable-shape fixture should remain neutral-preflight valid: %v", err)
			}
			if got := pyInstallerRunnableMachO(image); got != test.want {
				t.Fatalf("pyInstallerRunnableMachO() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPyInstallerRecognizerRequiresExecutableFatMachOSlices(t *testing.T) {
	makeSlice := func(cpu macho.Cpu, fileType macho.Type, markers bool) []byte {
		image := pyInstallerTestThinMachO()
		binary.LittleEndian.PutUint32(image[4:8], uint32(cpu))
		binary.LittleEndian.PutUint32(image[12:16], uint32(fileType))
		if markers {
			image = append(image, pyInstallerTestMarkers()...)
		}
		return image
	}
	tests := []struct {
		name           string
		slices         [][]byte
		preflightValid bool
	}{
		{
			name:           "all dylib",
			preflightValid: true,
			slices: [][]byte{
				makeSlice(macho.CpuArm64, macho.TypeDylib, true),
				makeSlice(macho.CpuAmd64, macho.TypeDylib, false),
			},
		},
		{
			name: "mixed executable and dylib",
			slices: [][]byte{
				makeSlice(macho.CpuArm64, macho.TypeExec, true),
				makeSlice(macho.CpuAmd64, macho.TypeDylib, false),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := testFatMachO(binary.BigEndian, false, test.slices...)
			data := buildTestCArchive(t, prefix, []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
			_, preflightErr := PreflightMachO(data)
			if (preflightErr == nil) != test.preflightValid {
				t.Fatalf("PreflightMachO() error = %v, valid=%v", preflightErr, test.preflightValid)
			}
			if kind, _ := Detect("", data, true); kind != "macho-fat" {
				t.Fatalf("adversarial fat carrier detected as %q", kind)
			}
			parsed := parseCArchives(data)
			if len(parsed.Candidates) != 1 {
				t.Fatalf("neutral outer CArchive was not parsed: %#v", parsed)
			}
			if _, ok := recognizePyInstallerFacade(parsed, data, "macho-fat"); ok {
				t.Fatal("non-executable fat carrier was attributed as PyInstaller")
			}
		})
	}
}

func TestPyInstallerRecognizerRequiresCompleteMarkerProfileInEveryFatSlice(t *testing.T) {
	makeSlice := func(cpu macho.Cpu, markers []byte) []byte {
		image := pyInstallerTestThinMachO()
		binary.LittleEndian.PutUint32(image[4:8], uint32(cpu))
		return append(image, markers...)
	}
	apiMarkers := []byte("\x00PyMarshal_ReadObjectFromString\x00PyEval_EvalCode\x00")
	runtimeLoaderMarkers := []byte("\x00_MEIPASS\x00")
	runtimeLoaderMarkers = append(runtimeLoaderMarkers, cArchiveCookieMagic...)
	runtimeLoaderMarkers = append(runtimeLoaderMarkers, 0)
	tests := []struct {
		name  string
		arm64 []byte
		x8664 []byte
	}{
		{name: "only one complete slice", arm64: pyInstallerTestMarkers()},
		{name: "union split across slices", arm64: apiMarkers, x8664: runtimeLoaderMarkers},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fat := testFatMachO(binary.BigEndian, false,
				makeSlice(macho.CpuArm64, test.arm64),
				makeSlice(macho.CpuAmd64, test.x8664),
			)
			data := buildTestCArchive(t, fat, []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
			if _, err := PreflightMachO(data); err != nil {
				t.Fatalf("adversarial universal carrier failed preflight: %v", err)
			}
			if _, ok := recognizePyInstallerFacade(parseCArchives(data), data, "macho-fat"); ok {
				t.Fatal("marker evidence from different slices was combined")
			}
		})
	}
}

func TestPyInstallerRecognizerRejectsFatPaddingAndOuterOverlayMarkers(t *testing.T) {
	arm64 := pyInstallerTestThinMachO()
	x8664 := pyInstallerTestThinMachO()
	binary.LittleEndian.PutUint32(x8664[4:8], uint32(macho.CpuAmd64))
	fat := testFatMachO(binary.BigEndian, false, arm64, x8664)
	tests := []struct {
		name   string
		prefix []byte
	}{
		{
			name:   "fat padding",
			prefix: insertTestFatPadding(t, fat, pyInstallerTestMarkers()),
		},
		{
			name:   "outer overlay",
			prefix: append(append([]byte(nil), fat...), pyInstallerTestMarkers()...),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := buildTestCArchive(t, test.prefix, []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
			if _, err := PreflightMachO(data); err != nil {
				t.Fatalf("adversarial universal carrier failed preflight: %v", err)
			}
			if kind, _ := Detect("", data, true); kind != "macho-fat" {
				t.Fatalf("adversarial universal carrier detected as %q", kind)
			}
			if _, ok := recognizePyInstallerFacade(parseCArchives(data), data, "macho-fat"); ok {
				t.Fatal("non-slice markers supported PyInstaller attribution")
			}
		})
	}
}

func TestPyInstallerRecognizerRejectsInvalidFinalMarker(t *testing.T) {
	data := buildTestCArchive(t, pyInstallerTestPrefix(), []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	data = append(data, cArchiveCookieMagic...)
	data = append(data, make([]byte, cArchiveLegacyCookieSize-len(cArchiveCookieMagic))...)
	parsed := parseCArchives(data)
	if parsed.LastMagicHasFullyValidatedCandidate {
		t.Fatalf("fixture final marker unexpectedly valid: %#v", parsed)
	}
	if _, ok := recognizePyInstallerFacade(parsed, data, "macho"); ok {
		t.Fatal("invalid final marker was bypassed")
	}
}

func TestPyInstallerRecognizerRequiresScriptRecord(t *testing.T) {
	data := buildTestCArchive(t, pyInstallerTestPrefix(), []testCArchiveMember{{name: []byte("data"), data: []byte("payload"), typeCode: 'x'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	if _, ok := recognizePyInstallerFacade(parseCArchives(data), data, "macho"); ok {
		t.Fatal("bootloader-like carrier without an s record was attributed")
	}
}

func TestPyInstallerRecognizerRejectsAmbiguousFullyValidatedFinalInterpretation(t *testing.T) {
	data := buildTestCArchive(t, pyInstallerTestPrefix(), []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	parsed := parseCArchives(data)
	parsed.Candidates = append(parsed.Candidates, parsed.Candidates[0])
	if _, ok := recognizePyInstallerFacade(parsed, data, "macho"); ok {
		t.Fatal("ambiguous fully validated interpretation was attributed")
	}
}

func TestScanCArchivesCorroboratesPyInstallerAndOrdersInterleavedLoaderTargets(t *testing.T) {
	data := buildTestCArchive(t, pyInstallerTestPrefix(), []testCArchiveMember{
		{name: []byte("script-first"), data: []byte("marshal-script-one"), typeCode: 's'},
		{name: []byte("module-one"), data: []byte("marshal-module-one"), typeCode: 'm'},
		{name: []byte("script-second"), data: []byte("marshal-script-two"), typeCode: 's'},
		{name: []byte("package"), data: []byte("marshal-package"), typeCode: 'M'},
		{name: []byte("module-two"), data: []byte("marshal-module-two"), typeCode: 'm'},
	}, testCArchiveOptions{layout: cArchiveCookieCurrent, pythonLibrary: []byte("Python")})
	s, carrierID := newCArchiveScanner(t, Options{}, "macho")
	if !s.scanCArchives(carrierID, "sample", data, "macho", 0) {
		t.Fatal("corroborated CArchive was not scanned")
	}
	carrier := artifactTestNode(t, &s.graph, carrierID)
	if carrier.PackagingTechnology != "PyInstaller" || len(carrier.PackagingEvidence) != 9 {
		t.Fatalf("carrier packaging = %q", carrier.PackagingTechnology)
	}
	for _, proof := range carrier.PackagingEvidence {
		if proof.Offset < 0 || proof.Offset >= int64(len(data)) || proof.Kind == "" || proof.Value == "" {
			t.Fatalf("invalid packaging proof: %#v", proof)
		}
		if proof.Kind == "carchive-cookie" && proof.Value != "magic=4d45490c0b0a0b0e; layout=current-88" {
			t.Fatalf("cookie proof is not printable/layout-specific: %#v", proof)
		}
	}

	var targets []Edge
	for _, edge := range s.graph.Edges {
		if edge.From == carrierID && edge.Kind == "loader-invokes" {
			targets = append(targets, edge)
		}
	}
	wantTargets := []struct {
		suffix        string
		typeCode      byte
		kind          string
		tocOrdinal    int
		loaderOrdinal int
	}{
		{suffix: "!module-one", typeCode: 'm', kind: "pyinstaller-python-module-record", tocOrdinal: 1, loaderOrdinal: 0},
		{suffix: "!package", typeCode: 'M', kind: "pyinstaller-python-module-record", tocOrdinal: 3, loaderOrdinal: 1},
		{suffix: "!module-two", typeCode: 'm', kind: "pyinstaller-python-module-record", tocOrdinal: 4, loaderOrdinal: 2},
		{suffix: "!script-first", typeCode: 's', kind: "python-marshal", tocOrdinal: 0, loaderOrdinal: 3},
		{suffix: "!script-second", typeCode: 's', kind: "python-marshal", tocOrdinal: 2, loaderOrdinal: 4},
	}
	if len(targets) != len(wantTargets) {
		t.Fatalf("ordered loader targets = %#v", targets)
	}
	for index, edge := range targets {
		want := wantTargets[index]
		if edge.Ordinal == nil || *edge.Ordinal != want.loaderOrdinal {
			t.Fatalf("loader target %d ordinal = %#v, want %d", index, edge.Ordinal, want.loaderOrdinal)
		}
		if len(edge.SupportingEvidence) != len(carrier.PackagingEvidence)+1 {
			t.Fatalf("loader edge proof = %#v", edge.SupportingEvidence)
		}
		memberProof := edge.SupportingEvidence[len(edge.SupportingEvidence)-1]
		wantProof := "type=" + string(want.typeCode) + "; toc_ordinal=" + zeroPad(want.tocOrdinal, 1) + "; loader_ordinal=" + zeroPad(want.loaderOrdinal, 1)
		if memberProof.Kind != "carchive-loader-record" || memberProof.Value != wantProof || data[memberProof.Offset] != want.typeCode {
			t.Fatalf("loader member proof = %#v", memberProof)
		}
		node := artifactTestNode(t, &s.graph, edge.To)
		if !strings.HasSuffix(node.LogicalPath, want.suffix) {
			t.Fatalf("loader target %d path = %q, want suffix %q", index, node.LogicalPath, want.suffix)
		}
		content := artifactTestContent(t, s.contents, node.ID)
		if node.Kind != want.kind || node.SourceRole != "runtime" || content.Role != "runtime" || !content.RawFeaturesOnly || content.Executable || content.PrimaryExecutable {
			t.Fatalf("script target crossed raw/root boundary: node=%#v content=%#v", node, content)
		}
		if want.typeCode != 's' && (content.SemanticCoverageArea != "pyinstaller-python-module-record-semantics" || !strings.Contains(content.SemanticCoverageDetail, "full PYC") || !strings.Contains(content.SemanticCoverageDetail, "direct marshal")) {
			t.Fatalf("module framing uncertainty is not explicit: %#v", content)
		}
		if len(artifactTestChildren(s.graph, node.ID)) != 0 {
			t.Fatalf("raw marshal record was recursively interpreted: %#v", node)
		}
	}
}

func TestScanCArchivesLegacyAttributionDoesNotClaimMarshalRepresentation(t *testing.T) {
	data := buildTestCArchive(t, pyInstallerTestPrefix(), []testCArchiveMember{{name: []byte("main"), data: []byte("legacy-python-record"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieLegacy, pythonVersion: 27})
	s, carrierID := newCArchiveScanner(t, Options{}, "macho")
	s.scanCArchives(carrierID, "sample", data, "macho", 0)
	carrier := artifactTestNode(t, &s.graph, carrierID)
	member := artifactTestNodeBySuffix(t, &s.graph, "!main")
	content := artifactTestContent(t, s.contents, member.ID)
	if carrier.PackagingTechnology != "PyInstaller" || member.Kind != "carchive-python-record" || !content.RawFeaturesOnly {
		t.Fatalf("legacy attribution crossed representation boundary: carrier=%#v member=%#v content=%#v", carrier, member, content)
	}
	var invokes []Edge
	for _, edge := range s.graph.Edges {
		if edge.From == carrierID && edge.Kind == "loader-invokes" {
			invokes = append(invokes, edge)
		}
	}
	if len(invokes) != 1 || invokes[0].Ordinal == nil || *invokes[0].Ordinal != 0 || invokes[0].To != member.ID {
		t.Fatalf("legacy loader target = %#v", invokes)
	}
}

func TestPyInstallerRecognizerAllowsLegacyCookieButRequiresPlausibleVersion(t *testing.T) {
	data := buildTestCArchive(t, pyInstallerTestPrefix(), []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieLegacy, pythonVersion: 27})
	parsed := parseCArchives(data)
	if _, ok := recognizePyInstallerFacade(parsed, data, "macho"); !ok {
		t.Fatalf("corroborated legacy carrier was rejected: %#v", parsed)
	}

	invalid := append([]byte(nil), data...)
	cookie := bytes.LastIndex(invalid, cArchiveCookieMagic)
	invalid[cookie+20], invalid[cookie+21], invalid[cookie+22], invalid[cookie+23] = 0, 0, 3, 231 // 999
	parsed = parseCArchives(invalid)
	if _, ok := recognizePyInstallerFacade(parsed, invalid, "macho"); ok {
		t.Fatal("implausible Python version supported attribution")
	}
}

func TestPyInstallerRecognizerAcceptsValidatedFatCarrierWithOuterArchiveOverlay(t *testing.T) {
	nativeSlice := append(pyInstallerTestThinMachO(), pyInstallerTestMarkers()...)
	fatPrefix := testFatMachO(binary.LittleEndian, true, nativeSlice)
	data := buildTestCArchive(t, fatPrefix, []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	parsed := parseCArchives(data)
	recognition, ok := recognizePyInstallerFacade(parsed, data, "macho-fat")
	if !ok {
		t.Fatalf("validated little-endian FAT64 carrier was rejected: %#v", parsed)
	}
	if recognition.identity.cookieOffset <= uint64(len(fatPrefix)) {
		t.Fatalf("CArchive cookie offset %d falls inside fat carrier extent %d", recognition.identity.cookieOffset, len(fatPrefix))
	}

	corrupt := append([]byte(nil), data...)
	format, isFat := detectFatMachOFormat(corrupt)
	if !isFat {
		t.Fatal("fat fixture magic was not detected")
	}
	architectures, err := parseFatMachOArchitectures(corrupt, format)
	if err != nil || len(architectures) != 1 {
		t.Fatalf("fat fixture architecture table = %#v, %v", architectures, err)
	}
	corrupt[architectures[0].offset] = 0
	if _, err := PreflightMachO(corrupt); err == nil {
		t.Fatal("corrupted native fat slice passed preflight")
	}
	if _, ok := recognizePyInstallerFacade(parseCArchives(corrupt), corrupt, "macho-fat"); ok {
		t.Fatal("outer CArchive evidence bypassed invalid native fat-slice validation")
	}
}

func TestPyInstallerRecognizerAcceptsCArchiveInsideIndexedUniversalSlice(t *testing.T) {
	pyInstallerPrefix := pyInstallerTestPrefix()
	binary.LittleEndian.PutUint32(pyInstallerPrefix[4:8], uint32(macho.CpuAmd64))
	binary.LittleEndian.PutUint32(pyInstallerPrefix[8:12], 3)
	pyInstallerSlice := buildTestCArchive(t, pyInstallerPrefix, []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	arm64Slice := append(pyInstallerTestThinMachO(), pyInstallerTestMarkers()...)
	data := testFatMachO(binary.BigEndian, false, arm64Slice, pyInstallerSlice)

	isFat, slices, err := PreflightMachOSlices(data)
	if !isFat || err != nil || len(slices) != 2 {
		t.Fatalf("universal PyInstaller fixture failed preflight: isFat=%v slices=%#v err=%v", isFat, slices, err)
	}
	parsed := parseCArchives(data)
	recognition, ok := recognizePyInstallerFacade(parsed, data, "macho-fat")
	if !ok {
		t.Fatalf("CArchive inside indexed x86_64 slice was rejected: %#v", parsed)
	}
	for sliceIndex, descriptor := range slices {
		counts := map[string]int{}
		for _, proof := range recognition.evidence {
			if proof.Offset < uint64ToInt64(descriptor.Offset) || proof.Offset >= uint64ToInt64(descriptor.Offset+descriptor.Size) {
				continue
			}
			switch proof.Kind {
			case "pyinstaller-python-api", "pyinstaller-runtime-marker", "pyinstaller-carchive-loader-marker":
				counts[proof.Kind]++
			}
		}
		if counts["pyinstaller-python-api"] != 2 || counts["pyinstaller-runtime-marker"] != 1 || counts["pyinstaller-carchive-loader-marker"] != 1 {
			t.Fatalf("slice %d translated marker evidence = %#v", sliceIndex, counts)
		}
	}
	pyInstallerExtent := slices[1]
	pyInstallerEnd := pyInstallerExtent.Offset + pyInstallerExtent.Size
	if recognition.identity.cookieOffset < pyInstallerExtent.Offset || recognition.identity.cookieOffset >= pyInstallerEnd {
		t.Fatalf("CArchive cookie offset %d is outside indexed PyInstaller slice [%d,%d)", recognition.identity.cookieOffset, pyInstallerExtent.Offset, pyInstallerEnd)
	}
	image, ok := pyInstallerExtent.Bytes(data)
	if !ok || !bytes.Contains(image, cArchiveCookieMagic) {
		t.Fatal("indexed PyInstaller slice did not retain its CArchive bytes")
	}

	corrupt := append([]byte(nil), data...)
	corrupt[pyInstallerExtent.Offset] = 0
	if _, err := PreflightMachO(corrupt); err == nil {
		t.Fatal("corrupted indexed PyInstaller slice passed native preflight")
	}
	if _, ok := recognizePyInstallerFacade(parseCArchives(corrupt), corrupt, "macho-fat"); ok {
		t.Fatal("CArchive inside a corrupt fat slice bypassed native validation")
	}
}

func TestPyInstallerRecognizerUsesBoundedVersionAndExactMacLibraryProfiles(t *testing.T) {
	versionTests := []struct {
		encoded uint32
		want    bool
	}{
		{encoded: 24, want: true},
		{encoded: 27, want: true},
		{encoded: 23, want: false},
		{encoded: 299, want: false},
		{encoded: 33, want: true},
		{encoded: 39, want: true},
		{encoded: 310, want: true},
		{encoded: 314, want: true},
		{encoded: 315, want: true},
		{encoded: 316, want: false},
		{encoded: 399, want: false},
	}
	for _, test := range versionTests {
		if got := plausiblePyInstallerPythonVersion(test.encoded); got != test.want {
			t.Fatalf("version %d plausible = %v, want %v", test.encoded, got, test.want)
		}
	}

	libraryTests := []struct {
		name    string
		version uint32
		want    bool
	}{
		{name: "Python", want: true},
		{name: "libpython3.10.dylib", want: true},
		{name: "libpython3.10m.dylib", want: true},
		{name: "libpython3.10d.dylib", want: true},
		{name: "libpython3.10dm.dylib", want: true},
		{name: "libpython3.13t.dylib", version: 313, want: true},
		{name: "libpython3.12t.dylib", version: 312, want: false},
		{name: "libpython3.13td.dylib", version: 313, want: false},
		{name: "libpython3.13dt.dylib", version: 313, want: false},
		{name: "libpython3.13tt.dylib", version: 313, want: false},
		{name: "libpython3.9.dylib", want: false},
		{name: "Framework/Python", want: false},
		{name: "Framework/libpython3.13t.dylib", version: 313, want: false},
		{name: "libpython3.10.so", want: false},
		{name: "python3.10.dylib", want: false},
		{name: "Other", want: false},
	}
	for _, test := range libraryTests {
		t.Run(test.name, func(t *testing.T) {
			version := test.version
			if version == 0 {
				version = 310
			}
			data := buildTestCArchive(t, nil, []testCArchiveMember{{name: []byte("main"), typeCode: 's'}}, testCArchiveOptions{
				layout: cArchiveCookieCurrent, pythonVersion: version, pythonLibrary: []byte(test.name),
			})
			candidate := parseCArchives(data).Candidates[0]
			if got := plausiblePyInstallerPythonLibrary(candidate); got != test.want {
				t.Fatalf("library %q plausible = %v, want %v; candidate=%#v", test.name, got, test.want, candidate)
			}
		})
	}
}

func TestPyInstallerRecognizerAcceptsExactReleaseLoaderProfilesWithoutMagicOrSymbols(t *testing.T) {
	tests := []struct {
		name       string
		loaderText string
		wantValue  string
	}{
		{
			name:       "modern",
			loaderText: "Could not load PyInstaller's embedded PKG archive from the executable (%s)\n",
			wantValue:  "Could not load PyInstaller's embedded PKG archive from the executable (%s)",
		},
		{
			name:       "legacy",
			loaderText: "Cannot open PyInstaller archive from executable (%s) or external archive (%s)\n",
			wantValue:  "Cannot open PyInstaller archive from executable (%s) or external archive (%s)",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := pyInstallerTestPrefixWithLoaderText(test.loaderText)
			if bytes.Contains(prefix, cArchiveCookieMagic) || bytes.Contains(prefix, []byte("pyi_archive_open")) {
				t.Fatalf("release-profile fixture contains an older loader shortcut: %x", prefix)
			}
			data := buildTestCArchive(t, prefix, []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
			recognition, ok := recognizePyInstallerFacade(parseCArchives(data), data, "macho")
			if !ok {
				t.Fatal("exact official release loader profile was rejected")
			}
			found := false
			for _, proof := range recognition.evidence {
				if proof.Kind != "pyinstaller-carchive-loader-marker" {
					continue
				}
				found = true
				if proof.Value != test.wantValue || strings.Contains(proof.Value, "\n") {
					t.Fatalf("printable loader proof = %#v, want %q", proof, test.wantValue)
				}
				end := proof.Offset + int64(len(test.loaderText))
				if proof.Offset < 0 || end > int64(len(data)) || string(data[proof.Offset:end]) != test.loaderText {
					t.Fatalf("loader proof does not locate the exact release C string: %#v", proof)
				}
			}
			if !found {
				t.Fatalf("release loader proof not retained: %#v", recognition.evidence)
			}
		})
	}
}

func TestPyInstallerRecognizerRejectsIncompleteReleaseLoaderStrings(t *testing.T) {
	nearMisses := []string{
		"Cannot open PyInstaller archive\n",
		"Cannot open PyInstaller archive from executable (%s) or external archive (%s)",
		"Could not load PyInstaller's embedded PKG archive from the executable (%s)",
		"Could not load PyInstaller's embedded PKG archive from executable (%s)\n",
	}
	for _, nearMiss := range nearMisses {
		prefix := pyInstallerTestPrefixWithLoaderText(nearMiss)
		data := buildTestCArchive(t, prefix, []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
		if _, ok := recognizePyInstallerFacade(parseCArchives(data), data, "macho"); ok {
			t.Fatalf("incomplete loader string supported attribution: %q", nearMiss)
		}
	}
}

func TestPyInstallerRecognizerIgnoresBoundedDecoyMarkerSelectionButDisclosesCoverage(t *testing.T) {
	prefix := append([]byte(nil), pyInstallerTestPrefix()...)
	prefix = append(prefix, bytes.Repeat(cArchiveCookieMagic, maxCArchiveCandidateOffsets+8)...)
	data := buildTestCArchive(t, prefix, []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	parsed := parseCArchives(data)
	if !parsed.CandidateValidationTruncated || parsed.OmittedMagicOffsets == 0 {
		t.Fatalf("fixture did not exercise bounded marker selection: %#v", parsed)
	}
	if _, ok := recognizePyInstallerFacade(parsed, data, "macho"); !ok {
		t.Fatalf("bounded decoy-marker selection vetoed valid final candidate: %#v", parsed)
	}
	s, carrierID := newCArchiveScanner(t, Options{}, "macho")
	s.scanCArchives(carrierID, "sample", data, "macho", 0)
	carrier := artifactTestNode(t, &s.graph, carrierID)
	candidate := artifactTestNodeByKind(t, &s.graph, "carchive")
	if carrier.PackagingTechnology != "PyInstaller" || carrier.AnalyzeStatus != "partial" || candidate.AnalyzeStatus != "partial" || !strings.Contains(candidate.CoverageDetail, "omitted") {
		t.Fatalf("bounded discovery coverage = carrier %#v candidate %#v", carrier, candidate)
	}
}

func TestPyInstallerRecognizerRejectsGenericFailureTextAsLoaderProof(t *testing.T) {
	prefix := append([]byte(nil), pyInstallerTestThinMachO()...)
	prefix = append(prefix, []byte("\x00PyMarshal_ReadObjectFromString\x00PyEval_EvalCode\x00_MEIPASS\x00Failed to execute script\x00")...)
	data := buildTestCArchive(t, prefix, []testCArchiveMember{{name: []byte("main"), data: []byte("marshal"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	if _, ok := recognizePyInstallerFacade(parseCArchives(data), data, "macho"); ok {
		t.Fatal("generic failure text was accepted as a CArchive-loader marker")
	}
}

func TestPyInstallerRecognizerUsesExactCStringMarkerBoundaries(t *testing.T) {
	for _, prefix := range [][]byte{
		[]byte("\x00XPyMarshal_ReadObjectFromString\x00"),
		[]byte("\x00PyMarshal_ReadObjectFromStringSuffix\x00"),
	} {
		if proof, ok := locateExactCStringPrefixMarker(prefix, "api", []byte("PyMarshal_ReadObjectFromString"), true); ok {
			t.Fatalf("substring accepted as exact API marker: %#v", proof)
		}
	}
	if proof, ok := locateExactCStringPrefixMarker([]byte("\x00_PyMarshal_ReadObjectFromString\x00"), "api", []byte("PyMarshal_ReadObjectFromString"), true); !ok || proof.Offset != 2 {
		t.Fatalf("Mach-O symbol marker not located exactly: proof=%#v ok=%v", proof, ok)
	}
	runtime, ok := locateFirstExactCStringPrefixMarker([]byte("\x00_MEIPASS2\x00"), "runtime", [][]byte{
		[]byte("_MEIPASS"), []byte("_MEIPASS2"), []byte("_MEIXXXXXX"),
	})
	if !ok || runtime.Value != "_MEIPASS2" {
		t.Fatalf("old bootloader runtime marker = %#v ok=%v", runtime, ok)
	}
	if proof, ok := locateExactCStringPrefixMarker([]byte("\x00_MEIPASS2suffix\x00"), "runtime", []byte("_MEIPASS2"), false); ok {
		t.Fatalf("runtime substring accepted as exact marker: %#v", proof)
	}
}

func TestPyInstallerRecognizerAcceptsExactLegacyMEIPASS2Marker(t *testing.T) {
	prefix := append([]byte(nil), pyInstallerTestThinMachO()...)
	prefix = append(prefix, []byte("PyMarshal_ReadObjectFromString\x00PyEval_EvalCode\x00_MEIPASS2\x00")...)
	prefix = append(prefix, cArchiveCookieMagic...)
	data := buildTestCArchive(t, prefix, []testCArchiveMember{{name: []byte("main"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieLegacy, pythonVersion: 27})
	recognition, ok := recognizePyInstallerFacade(parseCArchives(data), data, "macho")
	if !ok {
		t.Fatal("exact _MEIPASS2 bootloader marker was rejected")
	}
	for _, proof := range recognition.evidence {
		if proof.Kind == "pyinstaller-runtime-marker" && proof.Value == "_MEIPASS2" {
			return
		}
	}
	t.Fatalf("_MEIPASS2 proof not retained: %#v", recognition.evidence)
}

func TestPyInstallerRecognizerRetainsFirstLocatedPrefixProofs(t *testing.T) {
	prefix := append([]byte(nil), pyInstallerTestThinMachO()...)
	prefix = append(prefix, []byte("PyMarshal_ReadObjectFromString\x00PyEval_EvalCode\x00_PYI_APPLICATION_HOME_DIR\x00")...)
	prefix = append(prefix, []byte("pyi_archive_open\x00_MEIPASS\x00")...)
	prefix = append(prefix, cArchiveCookieMagic...)
	data := buildTestCArchive(t, prefix, []testCArchiveMember{{name: []byte("main"), typeCode: 's'}}, testCArchiveOptions{layout: cArchiveCookieCurrent})
	recognition, ok := recognizePyInstallerFacade(parseCArchives(data), data, "macho")
	if !ok {
		t.Fatal("corroborated fixture was not recognized")
	}
	evidenceByKind := make(map[string]LocatedArtifactEvidence)
	for _, proof := range recognition.evidence {
		if _, exists := evidenceByKind[proof.Kind]; !exists {
			evidenceByKind[proof.Kind] = proof
		}
	}
	if got := evidenceByKind["pyinstaller-runtime-marker"].Value; got != "_PYI_APPLICATION_HOME_DIR" {
		t.Fatalf("runtime proof = %q", got)
	}
	if got := evidenceByKind["pyinstaller-carchive-loader-marker"].Value; got != "pyi_archive_open" {
		t.Fatalf("loader proof = %q", got)
	}
	for _, proof := range recognition.evidence {
		switch proof.Kind {
		case "pyinstaller-python-api", "pyinstaller-runtime-marker", "pyinstaller-carchive-loader-marker":
			end := proof.Offset + int64(len(proof.Value))
			if proof.Offset < 0 || end > int64(len(data)) || string(data[proof.Offset:end]) != proof.Value {
				t.Fatalf("proof is not exact at retained offset: %#v", proof)
			}
		case "carchive-loader-record":
			if proof.Offset < 0 || proof.Offset >= int64(len(data)) || data[proof.Offset] != 's' || proof.Value != "type=s; toc_ordinal=0; loader_ordinal=0" {
				t.Fatalf("loader-record proof is not exact: %#v", proof)
			}
		}
	}
}

func insertTestFatPadding(t *testing.T, data, padding []byte) []byte {
	t.Helper()
	format, isFat := detectFatMachOFormat(data)
	if !isFat {
		t.Fatal("padding fixture is not fat Mach-O")
	}
	architectures, err := parseFatMachOArchitectures(data, format)
	if err != nil || len(architectures) == 0 {
		t.Fatalf("padding fixture architecture table = %#v, %v", architectures, err)
	}
	insertion := architectures[0].offset
	for _, architecture := range architectures[1:] {
		insertion = min(insertion, architecture.offset)
	}
	if insertion > uint64(len(data)) {
		t.Fatalf("padding insertion offset %d exceeds fixture size %d", insertion, len(data))
	}
	padded := make([]byte, len(data)+len(padding))
	copy(padded, data[:int(insertion)])
	copy(padded[int(insertion):], padding)
	copy(padded[int(insertion)+len(padding):], data[int(insertion):])

	narch := int(format.order.Uint32(padded[4:8]))
	for index := 0; index < narch; index++ {
		entry := 8 + index*int(format.archBytes)
		if format.is64 {
			offset := format.order.Uint64(padded[entry+8 : entry+16])
			if offset >= insertion {
				format.order.PutUint64(padded[entry+8:entry+16], offset+uint64(len(padding)))
			}
			continue
		}
		offset := format.order.Uint32(padded[entry+8 : entry+12])
		if uint64(offset) >= insertion {
			format.order.PutUint32(padded[entry+8:entry+12], offset+uint32(len(padding)))
		}
	}
	return padded
}

func pyInstallerTestExecutableSegment64(fileSize uint64) []byte {
	segment := testMachOSegment64Command(0)
	copy(segment[8:24], []byte("__TEXT"))
	binary.LittleEndian.PutUint64(segment[24:32], 0x100000000)
	binary.LittleEndian.PutUint64(segment[32:40], 0x1000)
	binary.LittleEndian.PutUint64(segment[48:56], fileSize)
	binary.LittleEndian.PutUint32(segment[56:60], 7)
	binary.LittleEndian.PutUint32(segment[60:64], 5)
	return segment
}

func pyInstallerTestThinMachO() []byte {
	const entryOffset = thinMachOHeader64Size + segment64CommandSize + 24
	mainCommand := testMachOLoadCommand(pyInstallerLCMain, 24)
	binary.LittleEndian.PutUint64(mainCommand[8:16], entryOffset)
	image := testThinMachO(
		pyInstallerTestExecutableSegment64(entryOffset+4),
		mainCommand,
	)
	return append(image, make([]byte, 4)...)
}

func pyInstallerTestPrefix() []byte {
	prefix := append([]byte(nil), pyInstallerTestThinMachO()...)
	return append(prefix, pyInstallerTestMarkers()...)
}

func pyInstallerTestPrefixWithLoaderText(loaderText string) []byte {
	prefix := append([]byte(nil), pyInstallerTestThinMachO()...)
	prefix = append(prefix, []byte("\x00PyMarshal_ReadObjectFromString\x00PyEval_EvalCode\x00_MEIPASS\x00")...)
	prefix = append(prefix, loaderText...)
	return append(prefix, 0)
}

func pyInstallerTestMarkers() []byte {
	markers := []byte("\x00PyMarshal_ReadObjectFromString\x00PyEval_EvalCode\x00_MEIPASS\x00")
	markers = append(markers, cArchiveCookieMagic...)
	return append(markers, []byte("\x00")...)
}
