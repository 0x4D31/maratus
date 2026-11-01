package artifact

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	pyInstallerLCMain        macho.LoadCmd = 0x80000028
	pyInstallerVMProtExecute uint32        = 0x4
)

type cArchiveCandidateIdentity struct {
	cookieOffset uint64
	layout       cArchiveCookieLayout
}

type pyInstallerFacadeRecognition struct {
	identity cArchiveCandidateIdentity
	evidence []LocatedArtifactEvidence
}

func (identity cArchiveCandidateIdentity) matches(candidate cArchiveCandidate) bool {
	return identity.cookieOffset == candidate.Cookie.Offset && identity.layout == candidate.CookieLayout
}

// recognizePyInstallerFacade promotes neutral CArchive evidence only when a
// complete native carrier and every executable image independently corroborate
// the PyInstaller bootloader. Archived member bytes, fat padding, and outer
// overlays are intentionally excluded from marker searches so non-native bytes
// cannot assert loader provenance.
func recognizePyInstallerFacade(parsed cArchiveParseResult, carrier []byte, carrierKind string) (pyInstallerFacadeRecognition, bool) {
	if carrierKind != "macho" && carrierKind != "macho-fat" {
		return pyInstallerFacadeRecognition{}, false
	}
	detectedKind, _ := Detect("", carrier, true)
	if detectedKind != carrierKind {
		return pyInstallerFacadeRecognition{}, false
	}
	nativeSlices, ok := pyInstallerExecutableMachOSlices(carrier)
	if !ok {
		return pyInstallerFacadeRecognition{}, false
	}

	var selected *cArchiveCandidate
	fullyValidatedAtLast := 0
	for index := range parsed.Candidates {
		candidate := &parsed.Candidates[index]
		if candidate.Cookie.Offset != parsed.LastMagicOffset || !candidate.StructureFullyValidated {
			continue
		}
		fullyValidatedAtLast++
		selected = candidate
	}
	if fullyValidatedAtLast != 1 || selected == nil || !plausiblePyInstallerPythonVersion(selected.PythonVersion) {
		return pyInstallerFacadeRecognition{}, false
	}
	if selected.CookieLayout == cArchiveCookieCurrent && !plausiblePyInstallerPythonLibrary(*selected) {
		return pyInstallerFacadeRecognition{}, false
	}
	if selected.CookieLayout != cArchiveCookieCurrent && selected.CookieLayout != cArchiveCookieLegacy {
		return pyInstallerFacadeRecognition{}, false
	}
	scriptIndex := -1
	for index, member := range selected.Members {
		if member.TypeCode == 's' {
			scriptIndex = index
			break
		}
	}
	if scriptIndex < 0 || selected.Package.Offset > uint64(len(carrier)) {
		return pyInstallerFacadeRecognition{}, false
	}
	nativeMarkerEvidence, ok := locatePyInstallerSliceMarkerProfiles(carrier, nativeSlices, selected.Package)
	if !ok {
		return pyInstallerFacadeRecognition{}, false
	}
	scriptMember := selected.Members[scriptIndex]
	loaderOrdinals := cArchiveLoaderExecutionOrdinals(selected.Members)
	scriptExecutionOrdinal, ok := loaderOrdinals[scriptMember.Ordinal]
	if !ok {
		return pyInstallerFacadeRecognition{}, false
	}
	scriptTypeOffset := scriptMember.TOCRecordOffset + 17
	if scriptTypeOffset >= uint64(len(carrier)) || carrier[int(scriptTypeOffset)] != 's' {
		return pyInstallerFacadeRecognition{}, false
	}
	evidence := []LocatedArtifactEvidence{
		{Offset: uint64ToInt64(selected.Cookie.Offset), Kind: "carchive-cookie", Value: fmt.Sprintf("magic=%x; layout=%s", cArchiveCookieMagic, selected.CookieLayout)},
		{Offset: uint64ToInt64(selected.TOC.Offset), Kind: "carchive-toc", Value: fmt.Sprintf("length=%d; records=%d; fully-validated", selected.TOC.Length, len(selected.Members))},
		cArchiveLoaderRecordEvidence(scriptMember, scriptExecutionOrdinal),
		{Offset: uint64ToInt64(selected.Cookie.Offset + 20), Kind: "pyinstaller-python-version", Value: fmt.Sprintf("%d", selected.PythonVersion)},
	}
	evidence = append(evidence, nativeMarkerEvidence...)
	if selected.CookieLayout == cArchiveCookieCurrent {
		library := string(selected.PythonLibraryRaw[:selected.PythonLibraryNameLength])
		evidence = append(evidence, LocatedArtifactEvidence{
			Offset: uint64ToInt64(selected.Cookie.Offset + 24),
			Kind:   "pyinstaller-python-library",
			Value:  library,
		})
	}
	return pyInstallerFacadeRecognition{
		identity: cArchiveCandidateIdentity{cookieOffset: selected.Cookie.Offset, layout: selected.CookieLayout},
		evidence: evidence,
	}, true
}

// A PyInstaller bootloader carrier is an executable, not merely any valid
// Mach-O container. Return every validated image only when all universal slices
// are MH_EXECUTE so later attribution can corroborate each one independently.
func pyInstallerExecutableMachOSlices(carrier []byte) ([]MachOSliceDescriptor, bool) {
	_, slices, err := PreflightMachOSlices(carrier)
	if err != nil || len(slices) == 0 {
		return nil, false
	}
	for _, descriptor := range slices {
		image, ok := descriptor.Bytes(carrier)
		if !ok {
			return nil, false
		}
		_, _, fileType, ok := thinMachOIdentity(image)
		if !ok || fileType != macho.TypeExec || !pyInstallerRunnableMachO(image) {
			return nil, false
		}
	}
	return slices, true
}

type pyInstallerExecutableSegment struct {
	fileOffset uint64
	fileSize   uint64
}

// pyInstallerRunnableMachO is intentionally narrower than neutral Mach-O
// preflight. Producer attribution requires a file-backed executable segment and
// an actual process-entry load command. LC_MAIN must point inside such a
// segment; legacy LC_UNIXTHREAD must contain complete, non-empty thread-state
// records. This shape gate does not attempt architecture-specific instruction
// or thread-register decoding.
func pyInstallerRunnableMachO(image []byte) bool {
	order, magic, ok := thinMachOByteOrder(image)
	if !ok {
		return false
	}
	headerSize := thinMachOHeader32Size
	is64 := magic == macho.Magic64
	if is64 {
		headerSize = thinMachOHeader64Size
	}
	if len(image) < headerSize {
		return false
	}
	ncmd := uint64(order.Uint32(image[16:20]))
	commandBytes := uint64(order.Uint32(image[20:24]))
	if commandBytes > uint64(len(image)-headerSize) {
		return false
	}
	commands := image[headerSize : headerSize+int(commandBytes)]
	executableSegments := make([]pyInstallerExecutableSegment, 0, 1)
	mainEntrypoints := make([]uint64, 0, 1)
	hasUnixThread := false
	for index := uint64(0); index < ncmd; index++ {
		if len(commands) < loadCommandHeaderSize {
			return false
		}
		cmd := macho.LoadCmd(order.Uint32(commands[0:4]))
		size := uint64(order.Uint32(commands[4:8]))
		if size < loadCommandHeaderSize || size%4 != 0 || size > uint64(len(commands)) {
			return false
		}
		command := commands[:int(size)]
		switch cmd {
		case macho.LoadCmdSegment:
			if !is64 {
				if segment, ok := pyInstallerRunnableSegment(image, command, order, false); ok {
					executableSegments = append(executableSegments, segment)
				}
			}
		case macho.LoadCmdSegment64:
			if is64 {
				if segment, ok := pyInstallerRunnableSegment(image, command, order, true); ok {
					executableSegments = append(executableSegments, segment)
				}
			}
		case pyInstallerLCMain:
			if len(command) == 24 {
				mainEntrypoints = append(mainEntrypoints, order.Uint64(command[8:16]))
			}
		case macho.LoadCmdUnixThread:
			hasUnixThread = hasUnixThread || validPyInstallerUnixThreadCommand(command, order)
		}
		commands = commands[int(size):]
	}
	if len(commands) != 0 || len(executableSegments) == 0 {
		return false
	}
	for _, entrypoint := range mainEntrypoints {
		for _, segment := range executableSegments {
			if entrypoint >= segment.fileOffset && entrypoint-segment.fileOffset < segment.fileSize {
				return true
			}
		}
	}
	return hasUnixThread
}

func pyInstallerRunnableSegment(image, command []byte, order binary.ByteOrder, is64 bool) (pyInstallerExecutableSegment, bool) {
	baseSize := segment32CommandSize
	fileOffset := uint64(0)
	fileSize := uint64(0)
	vmSize := uint64(0)
	initProtectionOffset := 44
	if is64 {
		baseSize = segment64CommandSize
		initProtectionOffset = 60
	}
	if len(command) < baseSize {
		return pyInstallerExecutableSegment{}, false
	}
	if is64 {
		vmSize = order.Uint64(command[32:40])
		fileOffset = order.Uint64(command[40:48])
		fileSize = order.Uint64(command[48:56])
	} else {
		vmSize = uint64(order.Uint32(command[28:32]))
		fileOffset = uint64(order.Uint32(command[32:36]))
		fileSize = uint64(order.Uint32(command[36:40]))
	}
	initProtection := order.Uint32(command[initProtectionOffset : initProtectionOffset+4])
	if fileSize == 0 || vmSize == 0 || fileSize > vmSize || initProtection&pyInstallerVMProtExecute == 0 || !machORangeWithinData(len(image), fileOffset, fileSize) {
		return pyInstallerExecutableSegment{}, false
	}
	return pyInstallerExecutableSegment{fileOffset: fileOffset, fileSize: fileSize}, true
}

func validPyInstallerUnixThreadCommand(command []byte, order binary.ByteOrder) bool {
	states := command[loadCommandHeaderSize:]
	stateCount := 0
	for len(states) > 0 {
		if len(states) < 8 {
			return false
		}
		flavor := order.Uint32(states[0:4])
		wordCount := uint64(order.Uint32(states[4:8]))
		if flavor == 0 || wordCount == 0 || wordCount > uint64(len(states)-8)/4 {
			return false
		}
		recordSize := 8 + int(wordCount)*4
		states = states[recordSize:]
		stateCount++
	}
	return stateCount > 0
}

// locatePyInstallerSliceMarkerProfiles requires a complete marker profile in
// every validated native image. Fat-container padding and outer overlays are
// absent from the descriptor extents. For thin input, whose descriptor spans
// the retained file, and for an archive inside an indexed fat slice, the scope
// is truncated before the CArchive package so archived bytes cannot contribute.
func locatePyInstallerSliceMarkerProfiles(carrier []byte, slices []MachOSliceDescriptor, archive cArchiveExtent) ([]LocatedArtifactEvidence, bool) {
	evidence := make([]LocatedArtifactEvidence, 0, len(slices)*4)
	for _, descriptor := range slices {
		start := descriptor.Offset
		end := descriptor.Offset + descriptor.Size
		if end < start || end > uint64(len(carrier)) {
			return nil, false
		}
		sliceExtent := cArchiveExtent{Offset: start, Length: descriptor.Size}
		if extentsOverlap(sliceExtent, archive) {
			if archive.Offset <= start {
				return nil, false
			}
			end = min(end, archive.Offset)
		}
		profile, ok := locatePyInstallerMarkerProfile(carrier[int(start):int(end)])
		if !ok {
			return nil, false
		}
		base := uint64ToInt64(start)
		for index := range profile {
			profile[index].Offset += base
		}
		evidence = append(evidence, profile...)
	}
	return evidence, true
}

func locatePyInstallerMarkerProfile(nativeImage []byte) ([]LocatedArtifactEvidence, bool) {
	marshalMarker, ok := locateExactCStringPrefixMarker(nativeImage, "pyinstaller-python-api", []byte("PyMarshal_ReadObjectFromString"), true)
	if !ok {
		return nil, false
	}
	evalMarker, ok := locateExactCStringPrefixMarker(nativeImage, "pyinstaller-python-api", []byte("PyEval_EvalCode"), true)
	if !ok {
		return nil, false
	}
	runtimeMarker, ok := locateFirstExactCStringPrefixMarker(nativeImage, "pyinstaller-runtime-marker", [][]byte{
		[]byte("_MEIPASS"),
		[]byte("_MEIPASS2"),
		[]byte("_PYI_APPLICATION_HOME_DIR"),
		[]byte("_MEIXXXXXX"),
	})
	if !ok {
		return nil, false
	}
	rawLoaderMagic, rawLoaderMagicOK := locateRawPrefixMarker(
		nativeImage,
		"pyinstaller-carchive-loader-marker",
		cArchiveCookieMagic,
		fmt.Sprintf("magic=%x", cArchiveCookieMagic),
	)
	loaderFunction, loaderFunctionOK := locateExactCStringPrefixMarker(nativeImage, "pyinstaller-carchive-loader-marker", []byte("pyi_archive_open"), true)
	// Recent PyInstaller bootloaders deliberately construct the CArchive magic
	// at runtime so the loader does not find its own marker while scanning the
	// executable. Release bootloaders are also stripped, so their internal
	// pyi_archive_open symbol is not a reliable marker. Retain exact, complete
	// release error strings for the modern and legacy loader generations; the
	// trailing newline is part of each C string's byte-level identity but is
	// omitted from the printable evidence value.
	modernLoaderError, modernLoaderErrorOK := locateExactCStringPrefixMarker(
		nativeImage,
		"pyinstaller-carchive-loader-marker",
		[]byte("Could not load PyInstaller's embedded PKG archive from the executable (%s)\n"),
		false,
	)
	if modernLoaderErrorOK {
		modernLoaderError.Value = strings.TrimSuffix(modernLoaderError.Value, "\n")
	}
	legacyLoaderError, legacyLoaderErrorOK := locateExactCStringPrefixMarker(
		nativeImage,
		"pyinstaller-carchive-loader-marker",
		[]byte("Cannot open PyInstaller archive from executable (%s) or external archive (%s)\n"),
		false,
	)
	if legacyLoaderErrorOK {
		legacyLoaderError.Value = strings.TrimSuffix(legacyLoaderError.Value, "\n")
	}
	loaderMarker, ok := firstLocatedPrefixEvidence([]locatedPrefixEvidence{
		{evidence: rawLoaderMagic, found: rawLoaderMagicOK},
		{evidence: loaderFunction, found: loaderFunctionOK},
		{evidence: modernLoaderError, found: modernLoaderErrorOK},
		{evidence: legacyLoaderError, found: legacyLoaderErrorOK},
	})
	if !ok {
		return nil, false
	}
	return []LocatedArtifactEvidence{marshalMarker, evalMarker, runtimeMarker, loaderMarker}, true
}

type locatedPrefixEvidence struct {
	evidence LocatedArtifactEvidence
	found    bool
}

func locateRawPrefixMarker(prefix []byte, kind string, marker []byte, printableValue string) (LocatedArtifactEvidence, bool) {
	offset := bytes.Index(prefix, marker)
	if offset < 0 {
		return LocatedArtifactEvidence{}, false
	}
	return LocatedArtifactEvidence{Offset: int64(offset), Kind: kind, Value: printableValue}, true
}

func locateExactCStringPrefixMarker(prefix []byte, kind string, marker []byte, allowMachOSymbolPrefix bool) (LocatedArtifactEvidence, bool) {
	if len(marker) == 0 {
		return LocatedArtifactEvidence{}, false
	}
	for search := 0; search <= len(prefix)-len(marker); {
		relative := bytes.Index(prefix[search:], marker)
		if relative < 0 {
			break
		}
		offset := search + relative
		end := offset + len(marker)
		leftBoundary := offset == 0 || prefix[offset-1] == 0
		if !leftBoundary && allowMachOSymbolPrefix && prefix[offset-1] == '_' {
			leftBoundary = offset == 1 || prefix[offset-2] == 0
		}
		rightBoundary := end == len(prefix) || prefix[end] == 0
		if leftBoundary && rightBoundary {
			return LocatedArtifactEvidence{Offset: int64(offset), Kind: kind, Value: string(marker)}, true
		}
		search = offset + 1
	}
	return LocatedArtifactEvidence{}, false
}

func locateFirstExactCStringPrefixMarker(prefix []byte, kind string, markers [][]byte) (LocatedArtifactEvidence, bool) {
	candidates := make([]locatedPrefixEvidence, 0, len(markers))
	for _, marker := range markers {
		located, ok := locateExactCStringPrefixMarker(prefix, kind, marker, false)
		candidates = append(candidates, locatedPrefixEvidence{evidence: located, found: ok})
	}
	return firstLocatedPrefixEvidence(candidates)
}

func firstLocatedPrefixEvidence(candidates []locatedPrefixEvidence) (LocatedArtifactEvidence, bool) {
	var selected LocatedArtifactEvidence
	found := false
	for _, candidate := range candidates {
		if !candidate.found || found && candidate.evidence.Offset >= selected.Offset {
			continue
		}
		selected = candidate.evidence
		found = true
	}
	return selected, found
}

// PyInstaller has historical CArchive artifacts for Python 2.4 through 2.7
// and Python 3.3 onward. This evidence gate intentionally covers the supported
// Python 3 minor window through 3.15 and must be reviewed for later versions;
// it does not treat speculative versions such as 2.99 or 3.99 as proof.
func plausiblePyInstallerPythonVersion(encoded uint32) bool {
	major, minor, ok := decodePyInstallerPythonVersion(encoded)
	if !ok {
		return false
	}
	switch major {
	case 2:
		return minor >= 4 && minor <= 7
	case 3:
		return minor >= 3 && minor <= 15
	default:
		return false
	}
}

func decodePyInstallerPythonVersion(encoded uint32) (major, minor uint32, ok bool) {
	if encoded < 10 || encoded > 999 {
		return 0, 0, false
	}
	if encoded < 100 {
		return encoded / 10, encoded % 10, true
	}
	return encoded / 100, encoded % 100, true
}

func plausiblePyInstallerPythonLibrary(candidate cArchiveCandidate) bool {
	if !candidate.PythonLibraryFieldWellFormed || candidate.PythonLibraryNameLength > uint64(len(candidate.PythonLibraryRaw)) {
		return false
	}
	name := string(candidate.PythonLibraryRaw[:candidate.PythonLibraryNameLength])
	if name == "Python" {
		return true
	}
	// The cookie field is a dylib basename, not an attacker-selected path.
	if strings.ContainsAny(name, "/\\") {
		return false
	}
	major, minor, ok := decodePyInstallerPythonVersion(candidate.PythonVersion)
	if !ok {
		return false
	}
	prefix := fmt.Sprintf("libpython%d.%d", major, minor)
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	switch strings.TrimPrefix(name, prefix) {
	case ".dylib", "m.dylib", "d.dylib", "dm.dylib":
		return true
	case "t.dylib":
		// PyInstaller 6.21's macOS Python-library discovery explicitly
		// constructs this suffix for Py_GIL_DISABLED builds. Free-threaded
		// CPython starts at 3.13; do not broaden this evidence profile to
		// speculative compound debug/free-threaded suffix orders.
		return major == 3 && minor >= 13
	default:
		return false
	}
}
