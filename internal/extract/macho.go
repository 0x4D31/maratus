package extract

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net/netip"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/machox"
	"github.com/0x4D31/maratus/internal/plistx"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

const (
	lcCodeSignature      = 0x1d
	lcEncryptionInfo     = 0x21
	lcEncryptionInfo64   = 0x2c
	lcUUID               = 0x1b
	lcVersionMinMacOSX   = 0x24
	lcVersionMinIPhoneOS = 0x25
	lcVersionMinTvOS     = 0x2f
	lcVersionMinWatch    = 0x30
	lcBuildVersion       = 0x32
	lcMain               = 0x80000028
	lcDataInCode         = 0x29

	lcLoadDylib       = uint32(macho.LoadCmdDylib)
	lcLoadWeakDylib   = 0x80000018
	lcReexportDylib   = 0x8000001f
	lcLazyLoadDylib   = 0x20
	lcLoadUpwardDylib = 0x80000023

	x86AddressStateWindow     = 96
	machOCFString64RecordSize = 32

	maxMachOASCIIStringRuns          = 100000
	maxMachOASCIIInputBytes          = 64 << 20
	maxMachOASCIIBytes               = 32 << 20
	maxMachOASCIIStringBytes         = 1 << 20
	maxMachOCFStringBackingBytes     = 32 << 20
	maxMachORegexMatches             = 4096
	maxMachOStringLiterals           = 100000
	maxMachOStringXrefs              = 100000
	maxMachOObjectiveCRecords        = 200000
	maxMachOFunctionStarts           = 200000
	maxMachOFunctionRecords          = 400000
	maxMachOFunctions                = 200000
	maxMachOFunctionStartBytes       = 4 << 20
	maxMachOTextAnalysisBytes        = 64 << 20
	maxMachOEntropySectionBytes      = 64 << 10
	maxMachOEntropyInputBytes        = 8 << 20
	maxMachODirectCallScanBytes      = 64 << 20
	maxMachODirectCallCandidates     = 200000
	maxMachOLocalCallEdges           = 200000
	maxMachOFunctionCallFeatures     = 4096
	maxMachOGoRuntimeCallFeatures    = 512
	maxMachOGoStandardCallFeatures   = 1024
	maxMachORustRuntimeCallFeatures  = 512
	maxMachORustStandardCallFeatures = 1024
	maxMachORelocationRecords        = 200000
	maxMachOStubRecords              = 400000
	maxMachOCodeSignatureSlots       = 4096
	maxMachOCodeSignatureBlobs       = 256
	maxMachOCodeDirectorySlots       = 131072
	maxMachOUnscopedProcessPaths     = 256

	csMagicSuperBlob       = 0xfade0cc0
	csMagicCodeDirectory   = 0xfade0c02
	csMagicBlobWrapper     = 0xfade0b01
	csMagicEntitlementsXML = 0xfade7171

	csSlotCodeDirectory               = 0
	csSlotEntitlements                = 5
	csSlotDerEntitlements             = 7
	csSlotAlternateCodeDirectories    = 0x1000
	csSlotAlternateCodeDirectoryLimit = 0x1005
	csSlotCMSSignature                = 0x10000
)

func ExtractMachO(graph *behavior.Graph, content artifact.Content, options artifact.Options) {
	rawFeatures := newRawFeatureExtractor()
	extractMachOWithRawFeatures(graph, content, options, &rawFeatures)
}

func extractMachOWithRawFeatures(graph *behavior.Graph, content artifact.Content, options artifact.Options, rawFeatures *rawFeatureExtractor) {
	isFat, slices, preflightErr := artifact.PreflightMachOSlices(content.Data)
	if preflightErr != nil {
		graph.AddCoverage(behavior.Coverage{
			NodeID:       content.NodeID,
			AnalysisArea: "macho",
			Status:       "partial",
			Detail:       "Mach-O parse failed: structure validation rejected input before allocation: " + preflightErr.Error(),
		})
		content.SemanticCoverageArea = "macho-raw-fallback"
		content.SemanticCoverageDetail = "Mach-O structure was rejected; only bounded heuristic URL and IP byte candidates were retained without architecture, function, call, or operation attribution"
		rawFeatures.extract(graph, content)
		return
	}
	if isFat {
		type parsedFatSlice struct {
			file       *macho.File
			arch       string
			image      []byte
			byteOffset int64
		}
		parsed := make([]parsedFatSlice, 0, len(slices))
		for index, descriptor := range slices {
			image, ok := descriptor.Bytes(content.Data)
			if !ok {
				graph.AddCoverage(behavior.Coverage{
					NodeID:       content.NodeID,
					AnalysisArea: "macho",
					Status:       "partial",
					Detail:       fmt.Sprintf("fat Mach-O architecture %d has an invalid slice extent after structure validation", index),
				})
				return
			}
			file, err := machox.NewFile(bytes.NewReader(image))
			if err != nil {
				graph.AddCoverage(behavior.Coverage{
					NodeID:       content.NodeID,
					AnalysisArea: "macho",
					Status:       "partial",
					Detail:       fmt.Sprintf("fat Mach-O architecture %d parse failed after structure validation: %v", index, err),
				})
				return
			}
			if file.Cpu != descriptor.CPU || file.SubCpu != descriptor.SubCPU {
				graph.AddCoverage(behavior.Coverage{
					NodeID:       content.NodeID,
					AnalysisArea: "macho",
					Status:       "partial",
					Detail:       fmt.Sprintf("fat Mach-O architecture %d identity changed after structure validation", index),
				})
				return
			}
			if descriptor.Offset > math.MaxInt64 || content.ByteOffsetBase < 0 || int64(descriptor.Offset) > math.MaxInt64-content.ByteOffsetBase {
				graph.AddCoverage(behavior.Coverage{
					NodeID:       content.NodeID,
					AnalysisArea: "macho",
					Status:       "partial",
					Detail:       fmt.Sprintf("fat Mach-O architecture %d has an unrepresentable node-relative slice offset", index),
				})
				return
			}
			parsed = append(parsed, parsedFatSlice{
				file:       file,
				arch:       machoArch(file.Cpu, file.SubCpu),
				image:      image,
				byteOffset: content.ByteOffsetBase + int64(descriptor.Offset),
			})
		}
		for _, item := range parsed {
			if graph.WorkLimitReached() {
				graph.MarkWorkOmitted()
				break
			}
			if !architectureSelected(options.Architecture, item.arch) {
				addSkippedArchitectureCoverage(graph, content, item.arch, options.Architecture)
				continue
			}
			sliceContent := content
			sliceContent.ByteOffsetBase = item.byteOffset
			extractMachOFile(graph, sliceContent, item.file, item.arch, item.image, options)
		}
		return
	}
	file, err := machox.NewFile(bytes.NewReader(content.Data))
	if err != nil {
		graph.AddCoverage(behavior.Coverage{
			NodeID:       content.NodeID,
			AnalysisArea: "macho",
			Status:       "partial",
			Detail:       "Mach-O parse failed: " + err.Error(),
		})
		return
	}
	archName := machoArch(file.Cpu, file.SubCpu)
	if !architectureSelected(options.Architecture, archName) {
		addSkippedArchitectureCoverage(graph, content, archName, options.Architecture)
		return
	}
	extractMachOFile(graph, content, file, archName, content.Data, options)
}

func architectureSelected(filter, arch string) bool {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" || filter == "all" {
		return true
	}
	arch = strings.ToLower(arch)
	if filter == "arm64" && strings.HasPrefix(arch, "arm64") {
		return true
	}
	if filter == "x86_64" && strings.HasPrefix(arch, "x86_64") {
		return true
	}
	return arch == filter || strings.HasPrefix(arch, filter+"/")
}

func addSkippedArchitectureCoverage(graph *behavior.Graph, content artifact.Content, arch, filter string) {
	graph.AddCoverage(behavior.Coverage{
		NodeID:       content.NodeID,
		AnalysisArea: "macho/" + arch,
		Status:       "skipped",
		Detail:       "architecture excluded by filter " + filter,
	})
}

func extractMachOFile(graph *behavior.Graph, content artifact.Content, file *macho.File, arch string, image []byte, options artifact.Options) {
	if graph.WorkLimitReached() {
		graph.MarkWorkOmitted()
		return
	}
	headerEvidence := graph.AddEvidence(machOEvidenceAt(content, 0, behavior.Evidence{
		NodeID:  content.NodeID,
		Logical: content.LogicalPath,
		Method:  "macho-header",
		Kind:    "macho-header",
		Value:   fmt.Sprintf("type=%s flags=%#x", file.Type, file.Flags),
		Arch:    arch,
	}))
	graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Architecture: arch, Key: "macho.filetype", Value: file.Type.String(), EvidenceIDs: []string{headerEvidence}, Support: behavior.SupportDirect})
	if file.Flags&macho.FlagPIE != 0 {
		graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Architecture: arch, Key: "macho.flag", Value: "PIE", EvidenceIDs: []string{headerEvidence}, Support: behavior.SupportDirect})
	}
	extractMachOLoadCommandFeatures(graph, content, file, arch)
	encrypted := extractEncryptionInfo(graph, content, file, arch)
	for _, lib := range importedLibraryLoads(file) {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
		ev := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-load-command", Kind: lib.Linkage + "-dylib", Value: lib.Name, Arch: arch})
		graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Architecture: arch, Key: "macho.dylib", Value: lib.Name, EvidenceIDs: []string{ev}, Support: behavior.SupportDirect, Qualifiers: map[string]string{"linkage": lib.Linkage}})
		if lib.Linkage != "load" {
			graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Architecture: arch, Key: "macho.dylib.linkage", Value: lib.Linkage, EvidenceIDs: []string{ev}, Support: behavior.SupportDirect, Qualifiers: map[string]string{"library": lib.Name}})
		}
		addNetworkFeatureFromDylib(graph, content, lib.Name, arch, ev)
	}
	for _, symbol := range importedSymbols(file) {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
		ev := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-symbols", Kind: "imported-symbol", Value: symbol, Arch: arch})
		graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Architecture: arch, Key: "macho.import", Value: symbol, EvidenceIDs: []string{ev}, Support: behavior.SupportDirect})
		addOperationFromImportedSymbol(graph, content, symbol, arch, ev)
	}
	chainedImports, chainedPresent, chainedDetail := machoChainedImports(file, image, content.ByteOffsetBase)
	if chainedDetail != "" {
		addPartialCoverageOnce(graph, content.NodeID, "macho-chained-imports/"+arch, chainedDetail)
	}
	if chainedPresent {
		seenImports := map[string]bool{}
		for _, symbol := range importedSymbols(file) {
			seenImports[symbol] = true
		}
		for _, imported := range chainedImports {
			if seenImports[imported.name] {
				continue
			}
			if graph.WorkLimitReached() {
				graph.MarkWorkOmitted()
				return
			}
			seenImports[imported.name] = true
			ev := graph.AddEvidence(behavior.Evidence{
				NodeID: content.NodeID, Logical: content.LogicalPath,
				Method: "macho-chained-fixups", Kind: "imported-symbol", Value: imported.name,
				Offset: imported.nameOffset, OffsetKnown: true, Arch: arch,
			})
			graph.AddFeature(behavior.Feature{
				NodeID: content.NodeID, Architecture: arch, Key: "macho.import", Value: imported.name,
				EvidenceIDs: []string{ev}, Support: behavior.SupportDirect,
				Qualifiers: map[string]string{"source": "dyld-chained-fixups"},
			})
			addOperationFromImportedSymbol(graph, content, imported.name, arch, ev)
		}
	}
	entropyBytesRemaining := maxMachOEntropyInputBytes
	entropyCache := map[machoSectionExtent]float64{}
	entropyTruncated := false
	for _, section := range file.Sections {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
		entropy := float64(0)
		if machoSectionHasFileData(section) && section.Size > 0 {
			readLimit := min(maxMachOEntropySectionBytes, entropyBytesRemaining)
			key := machoSectionExtent{offset: section.Offset, size: min(section.Size, uint64(readLimit))}
			if cached, ok := entropyCache[key]; ok {
				entropy = cached
			} else {
				data, truncated, err := machoSectionPrefix(image, section, readLimit)
				if err == nil {
					entropy = entropyForBytes(data)
					entropyCache[key] = entropy
					entropyBytesRemaining -= len(data)
				}
				entropyTruncated = entropyTruncated || truncated || err != nil
			}
		}
		value := fmt.Sprintf("%s,%s size=%d entropy=%.2f", section.Seg, section.Name, section.Size, entropy)
		ev := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-section", Kind: "section", Value: value, Arch: arch})
		graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Architecture: arch, Key: "macho.section", Value: value, EvidenceIDs: []string{ev}, Support: behavior.SupportDirect})
	}
	if entropyTruncated {
		addPartialCoverageOnce(graph, content.NodeID, "macho-section-entropy/"+arch, fmt.Sprintf("section entropy sampled at most %d bytes per section and %d bytes per architecture; duplicate extents reused cached samples", maxMachOEntropySectionBytes, maxMachOEntropyInputBytes))
	}
	if !encrypted {
		extractMachOGoBuildInfo(graph, content, file, arch, image)
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
		extractMachOStaticObservations(graph, content, file, arch, image)
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
		extractObjectiveCMetadata(graph, content, file, arch, image)
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
		extractMachOInterestingStrings(graph, content, file, arch, image)
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
	}
	for _, load := range file.Loads {
		switch item := load.(type) {
		case *macho.Rpath:
			ev := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-load-command", Kind: "rpath", Value: item.Path, Arch: arch})
			graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Architecture: arch, Key: "macho.rpath", Value: item.Path, EvidenceIDs: []string{ev}, Support: behavior.SupportDirect})
		}
	}
	entitlementSlotsAbsent := extractCodeSignature(graph, content, file, arch, image)
	if encrypted {
		// cryptid is a loader assertion that bytes in the declared encrypted
		// range are ciphertext. Conservatively avoid behavioral byte decoding for
		// this slice so ciphertext cannot become strings, calls, xrefs, operations,
		// or reachability. Structural headers, imports, section metadata (including
		// bounded entropy), rpaths, and the embedded signature remain safe to report.
		return
	}
	extractEntitlementStrings(graph, content, arch, image, entitlementSlotsAbsent)
	if graph.WorkLimitReached() {
		graph.MarkWorkOmitted()
		return
	}
	if file.Cpu != macho.CpuAmd64 && file.Cpu != macho.CpuArm64 {
		graph.AddCoverage(behavior.Coverage{
			NodeID:       content.NodeID,
			AnalysisArea: "macho-function-scope/" + arch,
			Status:       "skipped",
			Detail:       "instruction-level function-scope analysis is unsupported for " + arch + "; structural metadata, imports, and bounded strings were still analyzed",
		})
		return
	}
	if isAppBundleLogical(content.LogicalPath) && !content.PrimaryExecutable && !content.BehaviorAnalysisForced && !options.IncludeUnreferenced {
		graph.AddCoverage(behavior.Coverage{
			NodeID:       content.NodeID,
			AnalysisArea: "macho-function-scope/" + arch,
			Status:       "skipped",
			Detail:       "unreferenced non-primary app-bundle Mach-O function-scope analysis requires --include-unreferenced",
		})
		return
	}
	scopedEvidence, boundaries, hasStubMap := extractFunctionScopedCalls(graph, content, file, arch, image)
	if boundaries == "" {
		boundaries = "symbols/fallback"
	}
	stubs := "stub symbols unresolved"
	if hasStubMap {
		stubs = "import stubs, Objective-C message stubs, and exact x86_64 indirect-symbol calls mapped conservatively"
	}
	detail := "function boundaries from " + boundaries + "; branch relocations, direct calls, and string xrefs recovered conservatively; " + stubs
	if scopedEvidence == 0 {
		detail = "function boundaries from " + boundaries + "; no branch relocation, direct call, or string xref evidence recovered; " + stubs
	}
	detail += "; only exact x86_64 LC_UNIXTHREAD states are supported; module-initializer entrypoints, tail calls, general register/vtable/function-pointer indirect calls, and intra-function control-flow paths are not traversed"
	graph.AddCoverage(behavior.Coverage{
		NodeID:       content.NodeID,
		AnalysisArea: "macho-function-scope/" + arch,
		Status:       "partial",
		Detail:       detail,
	})
}

func extractMachOStaticObservations(graph *behavior.Graph, content artifact.Content, file *macho.File, arch string, image []byte) {
	const instructionAttributes = 0x80000400 // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
	for _, section := range file.Sections {
		if graph.WorkLimitReached() {
			return
		}
		if section == nil || !machoSectionHasFileData(section) || section.Size == 0 || section.Seg == "__LINKEDIT" || section.Flags&(instructionAttributes|machoSectionAttributeDebug) != 0 {
			continue
		}
		data, truncated, err := machoSectionPrefix(image, section, maxStaticObservationInputBytes)
		if err != nil {
			continue
		}
		sectionContent := content
		sectionContent.ScopeID = ""
		extractStaticContentObservations(graph, sectionContent, data, "macho-data-section", arch, content.ByteOffsetBase+int64(section.Offset))
		if truncated {
			addPartialCoverageOnce(graph, content.NodeID, "macho-static-observations/"+arch, fmt.Sprintf("static observation scanning capped at %d bytes per non-code data section", maxStaticObservationInputBytes))
		}
	}
}

// machOEvidenceAt composes a slice-local byte location with the validated
// subimage origin. If an internal caller ever supplies an unrepresentable
// location, the evidence retains its other exact coordinates but does not
// invent a byte offset.
func machOEvidenceAt(content artifact.Content, relative int, evidence behavior.Evidence) behavior.Evidence {
	if relative < 0 || content.ByteOffsetBase < 0 || uint64(relative) > math.MaxInt64 || int64(relative) > math.MaxInt64-content.ByteOffsetBase {
		return evidence
	}
	evidence.Offset = content.ByteOffsetBase + int64(relative)
	evidence.OffsetKnown = true
	return evidence
}

func extractMachOInterestingStrings(graph *behavior.Graph, content artifact.Content, file *macho.File, arch string, image []byte) {
	seen := map[string]bool{}
	unscopedProcessPaths := 0
	processPathsTruncated := false
	skipRanges := machoStringSkipRanges(file, len(image))
	runs, stringsTruncated := asciiStringRuns(image, 6)
	regexTruncated := false
	for _, item := range runs {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			break
		}
		if offsetInRanges(item.Offset, skipRanges) {
			continue
		}
		urlMatches, truncated := limitedMachOStringMatches(reURL, item.Value)
		regexTruncated = regexTruncated || truncated
		for _, match := range urlMatches {
			urlOffset := item.Offset + match[0]
			if offsetInRanges(urlOffset, skipRanges) {
				continue
			}
			rawURL := item.Value[match[0]:match[1]]
			value, ok := normalizeStaticURL(rawURL)
			if !ok {
				continue
			}
			key := "url\x00" + value
			if seen[key] {
				continue
			}
			seen[key] = true
			ev := graph.AddEvidence(machOEvidenceAt(content, urlOffset, behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-strings", Kind: "url", Value: value, Arch: arch}))
			graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Architecture: arch, Key: "network.url", Value: value, EvidenceIDs: []string{ev}, Support: behavior.SupportCorroborated})
		}
		ipMatches, truncated := limitedMachOIPv4Matches(item.Value)
		regexTruncated = regexTruncated || truncated
		for _, match := range ipMatches {
			ipOffset := item.Offset + match[0]
			if offsetInRanges(ipOffset, skipRanges) {
				continue
			}
			value, _ := validatedIPv4Match(item.Value, match)
			key := "ip\x00" + value
			if seen[key] {
				continue
			}
			seen[key] = true
			ev := graph.AddEvidence(machOEvidenceAt(content, ipOffset, behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-strings", Kind: "ip", Value: value, Arch: arch}))
			graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Architecture: arch, Key: "network.ip", Value: value, EvidenceIDs: []string{ev}, Support: behavior.SupportHeuristic})
			// An IPv4-looking data string is too weak to present as a runtime
			// destination. Keep it as a queryable feature; a same-function
			// connect call will promote it to an operation and network detail.
		}
		extractMachOSensitiveResourceString(graph, content, arch, item.Value, item.Offset, seen)
		applicationMatches, truncated := limitedMachOApplicationPathMatches(item.Value)
		regexTruncated = regexTruncated || truncated
		for _, match := range applicationMatches {
			path := item.Value[match[0]:match[1]]
			offset := item.Offset + match[0]
			if !addMachOUnscopedProcessPathFeature(graph, content, arch, path, offset, seen, &unscopedProcessPaths) {
				processPathsTruncated = true
			}
		}
		pathMatches, truncated := limitedMachOStringMatches(rePath, item.Value)
		regexTruncated = regexTruncated || truncated
		for _, match := range pathMatches {
			path := item.Value[match[0]:match[1]]
			offset := item.Offset
			if relative := strings.Index(item.Value, path); relative >= 0 {
				offset += relative
			}
			extractMachOSensitiveResourceString(graph, content, arch, path, offset, seen)
			if !addMachOUnscopedProcessPathFeature(graph, content, arch, path, offset, seen, &unscopedProcessPaths) && looksProcessLaunchPath(path) {
				processPathsTruncated = true
			}
		}
	}
	if stringsTruncated || regexTruncated {
		detail := fmt.Sprintf("ASCII string extraction capped at %d input bytes, %d runs, %d captured bytes, and %d bytes per string", maxMachOASCIIInputBytes, maxMachOASCIIStringRuns, maxMachOASCIIBytes, maxMachOASCIIStringBytes)
		if regexTruncated {
			detail += fmt.Sprintf("; regex matches capped at %d per string", maxMachORegexMatches)
		}
		graph.AddCoverage(behavior.Coverage{
			NodeID:       content.NodeID,
			AnalysisArea: "macho-strings/" + arch,
			Status:       "partial",
			Detail:       detail,
		})
	}
	if processPathsTruncated {
		graph.AddCoverage(behavior.Coverage{
			NodeID:       content.NodeID,
			AnalysisArea: "macho-process-path-strings/" + arch,
			Status:       "partial",
			Detail:       fmt.Sprintf("only the first %d unique unscoped executable-path string features were retained", maxMachOUnscopedProcessPaths),
		})
	}
}

// addMachOUnscopedProcessPathFeature retains an executable-looking path as a
// binary-wide feature. It deliberately does not attach a function or scope, so
// it cannot satisfy function-correlated operations or rules without a recovered
// code reference.
func addMachOUnscopedProcessPathFeature(graph *behavior.Graph, content artifact.Content, arch, value string, offset int, seen map[string]bool, retained *int) bool {
	value = normalizeProcessLaunchPath(value)
	if !looksProcessLaunchPath(value) {
		return true
	}
	key := "process-path\x00" + value
	if seen[key] {
		return true
	}
	if retained == nil || *retained >= maxMachOUnscopedProcessPaths {
		return false
	}
	seen[key] = true
	(*retained)++
	ev := graph.AddEvidence(machOEvidenceAt(content, offset, behavior.Evidence{
		NodeID:  content.NodeID,
		Logical: content.LogicalPath,
		Method:  "macho-strings",
		Kind:    "unscoped-process-path",
		Value:   value,
		Arch:    arch,
	}))
	graph.AddFeature(behavior.Feature{
		NodeID:       content.NodeID,
		Architecture: arch,
		Key:          "macho.process_launch_path",
		Value:        value,
		EvidenceIDs:  []string{ev},
		Support:      behavior.SupportHeuristic,
		Qualifiers:   map[string]string{"binding": "unscoped", "scope": "binary-wide"},
	})
	return true
}

func limitedMachOStringMatches(expression interface {
	FindAllStringIndex(string, int) [][]int
}, value string) ([][]int, bool) {
	return limitedStringMatches(expression, value, maxMachORegexMatches)
}

func limitedStringMatches(expression interface {
	FindAllStringIndex(string, int) [][]int
}, value string, limit int) ([][]int, bool) {
	if limit <= 0 {
		return nil, len(expression.FindAllStringIndex(value, 1)) > 0
	}
	matches := expression.FindAllStringIndex(value, limit+1)
	if len(matches) <= limit {
		return matches, false
	}
	return matches[:limit], true
}

func limitedMachOIPv4Matches(value string) ([][]int, bool) {
	matches, truncated := limitedMachOStringMatches(reIP, value)
	return validatedIPv4MatchIndexes(value, matches), truncated
}

type byteRange struct {
	start int
	end   int
}

const machoSectionAttributeDebug = 0x02000000 // S_ATTR_DEBUG

type asciiRun struct {
	Offset int
	Value  string
}

func machoStringSkipRanges(file *macho.File, imageSize int) []byteRange {
	var ranges []byteRange
	cmd := linkeditDataCommand(file, lcCodeSignature)
	if cmd.dataSize > 0 {
		appendMachOStringSkipRange := func(start, size uint64) {
			if start > uint64(imageSize) || size > uint64(imageSize)-start {
				return
			}
			ranges = append(ranges, byteRange{start: int(start), end: int(start + size)})
		}
		appendMachOStringSkipRange(uint64(cmd.dataOff), uint64(cmd.dataSize))
	}
	for _, section := range file.Sections {
		if section == nil || section.Size == 0 || section.Flags&machoSectionAttributeDebug == 0 {
			continue
		}
		start := uint64(section.Offset)
		if start > uint64(imageSize) || section.Size > uint64(imageSize)-start {
			continue
		}
		ranges = append(ranges, byteRange{start: int(start), end: int(start + section.Size)})
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start != ranges[j].start {
			return ranges[i].start < ranges[j].start
		}
		return ranges[i].end < ranges[j].end
	})
	merged := ranges[:0]
	for _, item := range ranges {
		if item.end <= item.start {
			continue
		}
		if len(merged) == 0 || item.start > merged[len(merged)-1].end {
			merged = append(merged, item)
			continue
		}
		if item.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = item.end
		}
	}
	return merged
}

func offsetInRanges(offset int, ranges []byteRange) bool {
	index := sort.Search(len(ranges), func(index int) bool { return ranges[index].end > offset })
	if index >= len(ranges) {
		return false
	}
	return offset >= ranges[index].start
}

func normalizeStaticURL(raw string) (string, bool) {
	value := strings.TrimRight(raw, ".,;:)]}\\")
	parseValue := strings.ReplaceAll(value, "%", "%25")
	parsed, err := url.Parse(parseValue)
	if err != nil || parsed.Scheme == "" {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || strings.Contains(host, "%") {
		return "", false
	}
	if !plausibleStaticURLHost(host) {
		return "", false
	}
	if commonStaticURL(host, parsed.EscapedPath()) {
		return "", false
	}
	return value, true
}

func normalizeMachOIP(raw string) (string, bool) {
	raw = strings.Trim(raw, " \t\r\n'\"`.,;:)]}>")
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() {
		return "", false
	}
	return addr.String(), true
}

func plausibleStaticURLHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if strings.Contains(host, "..") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	if len(labels) == 2 && labels[0] == "www" {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	tld := labels[len(labels)-1]
	if strings.HasPrefix(tld, "xn--") {
		return true
	}
	if len(tld) < 2 {
		return false
	}
	for _, r := range tld {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

func commonStaticURL(host, path string) bool {
	path = strings.ToLower(path)
	switch {
	case commonCertificateDistributionURL(host, path):
		return true
	case host == "go.dev" || strings.HasSuffix(host, ".go.dev") || host == "golang.org" || strings.HasSuffix(host, ".golang.org"):
		return true
	case host == "www.w3.org":
		return true
	case (host == "www.apple.com" || host == "apple.com") && (strings.Contains(path, "/dtds/") || strings.Contains(path, "/certificateauthority/")):
		return true
	case host == "ocsp.apple.com" || host == "crl.apple.com":
		return true
	case host == "curl.se" && (strings.HasPrefix(path, "/docs/") || strings.HasPrefix(path, "/libcurl/")):
		return true
	case host == "docs.rs" || strings.HasSuffix(host, ".docs.rs"):
		return true
	case host == "tauri.app" && (strings.Contains(path, "/docs/") || strings.Contains(path, "/api/")):
		return true
	case host == "github.com" && strings.HasPrefix(path, "/tauri-apps/tauri/issues/"):
		return true
	case (host == "www.mongodb.com" || host == "mongodb.com") && strings.HasPrefix(path, "/supportability/"):
		return true
	case host == "crl.verisign.com" || host == "logo.verisign.com" || strings.HasPrefix(host, "ocsp.verisign.com") || strings.HasSuffix(host, ".verisign.com"):
		return true
	case host == "ns.adobe.com" || strings.HasSuffix(host, ".adobe.com") && strings.Contains(path, "/xap/"):
		return true
	case host == "bugreports.qt.io":
		return true
	case host == "purl.org" || host == "schema.omg.org" || host == "www.abisource.com" ||
		host == "www.daa.com.au" || host == "www.freedesktop.org" || host == "www.gribuser.ru" ||
		host == "www.iec.ch" || host == "www.lysator.liu.se" || host == "www.metalinker.org" ||
		host == "www.mozilla.org" || host == "www.opengis.net" || host == "www.openssl.org" ||
		host == "www.phreedom.org" || host == "xspf.org" || host == "www.ascendercorp.com":
		return true
	case host == "upload.ffmpeg.org":
		return true
	case (host == "github.com" || host == "raw.githubusercontent.com") && (strings.Contains(path, "/license") || strings.Contains(path, "/legal")):
		return true
	case host == "telegram.org" || host == "core.telegram.org":
		return true
	default:
		return false
	}
}

func commonCertificateDistributionURL(host, path string) bool {
	switch {
	case strings.Contains(host, "ocsp") || strings.Contains(path, "ocsp"):
		return true
	case strings.HasPrefix(host, "aia"):
		return true
	case strings.Contains(host, "crl") || strings.Contains(path, ".crl"):
		return true
	case strings.Contains(path, ".crt") || strings.Contains(path, ".cer") || strings.Contains(path, ".der"):
		return true
	case strings.Contains(path, "/repository") && (strings.Contains(host, "cert") || strings.Contains(host, "pki") || strings.Contains(host, "godaddy")):
		return true
	default:
		return false
	}
}

func extractMachOSensitiveResourceString(graph *behavior.Graph, content artifact.Content, arch, value string, offset int, seen map[string]bool) {
	resource, ok := sensitiveResource(value)
	if !ok {
		return
	}
	// A binary-wide printable run has no source-level expression boundary. Keep
	// only path-shaped resources here; bare words such as github_token remain
	// useful in source adapters but are too weak to become a binary resource.
	resourceValue := strings.TrimSpace(resource.Value)
	if !plausibleMachOSensitiveResourceValue(resourceValue) {
		return
	}
	category := sensitiveResourceFeatureCategory(resource)
	if category == "" {
		return
	}
	key := "resource\x00" + string(resource.Key())
	if seen[key] {
		return
	}
	seen[key] = true
	ev := graph.AddEvidence(machOEvidenceAt(content, offset, behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-strings", Kind: "sensitive-resource", Value: resource.Value, Arch: arch}))
	graph.AddFeature(behavior.Feature{
		NodeID:       content.NodeID,
		Architecture: arch,
		Key:          "macho.sensitive_resource",
		Value:        resource.Value,
		EvidenceIDs:  []string{ev},
		Support:      behavior.SupportCorroborated,
		Qualifiers: map[string]string{
			"category": category,
		},
	})
}

type objcStringMetadata struct {
	VA     uint64
	Offset int
	Value  string
}

func extractObjectiveCMetadata(graph *behavior.Graph, content artifact.Content, file *macho.File, arch string, image []byte) {
	seen := map[string]bool{}
	budget := newASCIIRunBudget()
	recordsTruncated := false
	selectorRecords := 0
	seenSections := map[machoSectionExtent]bool{}
	sectionIndex := newMachOSectionIndex(file)
	for _, section := range file.Sections {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			break
		}
		switch section.Name {
		case "__objc_methname":
			if budget.scanBytesRemaining <= 0 {
				budget.truncated = true
				continue
			}
			key := machoSectionExtent{offset: section.Offset, size: section.Size}
			if seenSections[key] {
				recordsTruncated = true
				continue
			}
			seenSections[key] = true
			data, truncated, err := machoSectionPrefix(image, section, budget.scanBytesRemaining)
			budget.truncated = budget.truncated || truncated
			if err != nil {
				continue
			}
			items := objcSelectorStringsFromDataWithBudget(section.Addr, int(section.Offset), data, &budget)
			for _, item := range items {
				if graph.WorkLimitReached() {
					graph.MarkWorkOmitted()
					return
				}
				if !interestingObjectiveCSelector(item.Value) {
					continue
				}
				addObjectiveCSelectorFeature(graph, content, arch, section.Name, "objc.selector", "objc-selector", item, 0, seen)
			}
		case "__objc_selrefs":
			if selectorRecords >= maxMachOObjectiveCRecords {
				recordsTruncated = true
				continue
			}
			key := machoSectionExtent{offset: section.Offset, size: section.Size}
			if seenSections[key] {
				recordsTruncated = true
				continue
			}
			seenSections[key] = true
			data, truncated, err := machoSectionPrefix(image, section, (maxMachOObjectiveCRecords-selectorRecords)*8)
			recordsTruncated = recordsTruncated || truncated
			if err != nil {
				continue
			}
			for offset := 0; offset+8 <= len(data); offset += 8 {
				if graph.WorkLimitReached() {
					graph.MarkWorkOmitted()
					return
				}
				if selectorRecords >= maxMachOObjectiveCRecords {
					recordsTruncated = true
					break
				}
				selectorRecords++
				pointer := file.ByteOrder.Uint64(data[offset : offset+8])
				value, ok := readCStringAtPointerIndexed(file, sectionIndex, pointer, 256)
				if !ok || !looksObjectiveCSelector(value) || !interestingObjectiveCSelector(value) {
					continue
				}
				item := objcStringMetadata{
					VA:     section.Addr + uint64(offset),
					Offset: int(section.Offset) + offset,
					Value:  value,
				}
				addObjectiveCSelectorFeature(graph, content, arch, section.Name, "objc.selector_ref", "objc-selector-ref", item, pointer, seen)
			}
		}
	}
	if budget.truncated || recordsTruncated {
		detail := fmt.Sprintf("Objective-C string extraction capped at %d input bytes, %d runs, %d captured bytes, and %d bytes per string", maxMachOASCIIInputBytes, maxMachOASCIIStringRuns, maxMachOASCIIBytes, maxMachOASCIIStringBytes)
		if recordsTruncated {
			detail += fmt.Sprintf("; selector references capped at %d records", maxMachOObjectiveCRecords)
		}
		graph.AddCoverage(behavior.Coverage{
			NodeID:       content.NodeID,
			AnalysisArea: "macho-objc-strings/" + arch,
			Status:       "partial",
			Detail:       detail,
		})
	}
}

func objcSelectorStringsFromData(sectionVA uint64, sectionOffset int, data []byte) ([]objcStringMetadata, bool) {
	budget := newASCIIRunBudget()
	out := objcSelectorStringsFromDataWithBudget(sectionVA, sectionOffset, data, &budget)
	return out, budget.truncated
}

func objcSelectorStringsFromDataWithBudget(sectionVA uint64, sectionOffset int, data []byte, budget *asciiRunBudget) []objcStringMetadata {
	var out []objcStringMetadata
	for _, run := range budget.scan(data, 2) {
		for _, value := range splitCStringRun(run.Value) {
			if !looksObjectiveCSelector(value) {
				continue
			}
			relative := strings.Index(run.Value, value)
			if relative < 0 {
				relative = 0
			}
			out = append(out, objcStringMetadata{
				VA:     sectionVA + uint64(run.Offset+relative),
				Offset: sectionOffset + run.Offset + relative,
				Value:  value,
			})
		}
	}
	return out
}

func splitCStringRun(value string) []string {
	var out []string
	for _, item := range strings.Split(value, "\x00") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func addObjectiveCSelectorFeature(graph *behavior.Graph, content artifact.Content, arch, section, key, kind string, item objcStringMetadata, pointer uint64, seen map[string]bool) {
	seenKey := key + "\x00" + item.Value
	if seen[seenKey] {
		return
	}
	seen[seenKey] = true
	qualifiers := map[string]string{"section": section}
	if pointer != 0 {
		qualifiers["selector_va"] = fmt.Sprintf("%#x", pointer)
	}
	ev := graph.AddEvidence(machOEvidenceAt(content, item.Offset, behavior.Evidence{
		NodeID:  content.NodeID,
		Logical: content.LogicalPath,
		VA:      item.VA,
		Arch:    arch,
		Method:  "macho-objc",
		Kind:    kind,
		Value:   item.Value,
	}))
	graph.AddFeature(behavior.Feature{
		NodeID:       content.NodeID,
		Architecture: arch,
		Key:          key,
		Value:        item.Value,
		EvidenceIDs:  []string{ev},
		Support:      behavior.SupportDirect,
		Qualifiers:   qualifiers,
	})
}

func looksObjectiveCSelector(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 2 || len(value) > 160 {
		return false
	}
	if strings.Contains(value, "://") || strings.ContainsAny(value, "/\\ \t\r\n") {
		return false
	}
	if strings.Contains(value, "::") {
		return false
	}
	hasLetter := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			hasLetter = true
		case c >= '0' && c <= '9' || c == '_' || c == ':':
		default:
			return false
		}
	}
	if !hasLetter {
		return false
	}
	if strings.Contains(value, ":") {
		parts := strings.Split(value, ":")
		for i, part := range parts {
			if part == "" && i != len(parts)-1 {
				return false
			}
		}
		return true
	}
	return knownSingleWordObjectiveCSelector(value)
}

func knownSingleWordObjectiveCSelector(value string) bool {
	switch value {
	case "init", "launch", "run", "resume", "start", "readDataToEndOfFile", "stringValue", "mainAppService":
		return true
	default:
		return false
	}
}

func interestingObjectiveCSelector(value string) bool {
	lower := strings.ToLower(value)
	markers := []string{
		"url", "request", "download", "upload", "session", "connection",
		"doshellscript", "shell", "task", "launch", "process", "execute",
		"password", "hiddenanswer", "authorization", "keychain",
		"pasteboard", "clipboard", "screenshot", "windowlist",
		"write", "remove", "delete", "copyitem", "moveitem",
		"loginitem", "service", "agent", "daemon",
	}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func isAppBundleLogical(logical string) bool {
	return strings.Contains(strings.ToLower(filepath.ToSlash(logical)), ".app/")
}

type machoLibraryLoad struct {
	Name    string
	Linkage string
}

func importedLibraryLoads(file *macho.File) []machoLibraryLoad {
	var out []machoLibraryLoad
	for _, load := range file.Loads {
		raw := load.Raw()
		if len(raw) < 24 {
			continue
		}
		cmd := file.ByteOrder.Uint32(raw[0:4])
		linkage := dylibLoadKind(cmd)
		if linkage == "" {
			continue
		}
		nameOffset := file.ByteOrder.Uint32(raw[8:12])
		if nameOffset < 24 || nameOffset >= uint32(len(raw)) {
			continue
		}
		name := cstring(raw[nameOffset:])
		if name == "" {
			continue
		}
		out = append(out, machoLibraryLoad{Name: name, Linkage: linkage})
	}
	return out
}

func dylibLoadKind(cmd uint32) string {
	switch cmd {
	case lcLoadDylib:
		return "load"
	case lcLoadWeakDylib:
		return "weak"
	case lcReexportDylib:
		return "reexport"
	case lcLazyLoadDylib:
		return "lazy"
	case lcLoadUpwardDylib:
		return "upward"
	default:
		return ""
	}
}

func importedSymbols(file *macho.File) []string {
	seen := map[string]bool{}
	var out []string
	if file.Symtab != nil {
		for _, symbol := range file.Symtab.Syms {
			if !isUndefinedExternal(symbol) || symbol.Name == "" || seen[symbol.Name] {
				continue
			}
			seen[symbol.Name] = true
			out = append(out, symbol.Name)
		}
	}
	sort.Strings(out)
	return out
}

func isUndefinedExternal(symbol macho.Symbol) bool {
	const (
		nType = 0x0e
		nExt  = 0x01
		nUndf = 0x00
	)
	return symbol.Type&nType == nUndf && symbol.Type&nExt != 0 && symbol.Sect == 0 && symbol.Value == 0
}

func addNetworkFeatureFromDylib(graph *behavior.Graph, content artifact.Content, lib, arch, evidenceID string) {
	lower := strings.ToLower(lib)
	if !strings.Contains(lower, "cfnetwork") && !strings.Contains(lower, "network.framework") && !strings.Contains(lower, "libcurl") && !strings.Contains(lower, "libssl") {
		return
	}
	observation := behavior.NetworkImplementationObservation{
		Kind:               behavior.NetworkImplementationDynamicLinkage,
		SubjectNodeID:      content.NodeID,
		Architecture:       arch,
		APIOrTool:          lib,
		HTTPImplementation: dylibHTTPStack(lower),
		TLSProvider:        dylibTLSOwner(lower),
		TLSProfileFamily:   dylibTLSFamily(lower),
		EvidenceIDs:        []string{evidenceID},
		Support:            behavior.SupportDirect,
		Execution:          behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
	}
	if observation.TLSProvider != "" {
		observation.TLSProviderBasis = behavior.TLSProviderBasisDynamicLibrary
		observation.UnresolvedProperties = []string{"whether imported library is reached by executable code", "runtime OS/library version", "destination", "ALPN", "session state"}
	} else {
		observation.UnresolvedProperties = []string{"whether imported library is reached by executable code", "whether TLS protocol options are configured", "runtime OS/library version", "destination"}
	}
	graph.AddNetworkImplementation(observation)
}

func addOperationFromImportedSymbol(graph *behavior.Graph, content artifact.Content, symbol, arch, evidenceID string) {
	plain := strings.TrimPrefix(symbol, "_")
	switch {
	case plain == "SecItemCopyMatching" || plain == "SecKeychainFindGenericPassword" || plain == "SecKeychainFindInternetPassword":
		addSecurityAPIImportFeature(graph, content, plain, "keychain", arch, evidenceID)
	case isNativeProcessExecutionSymbol(plain):
		addSecurityAPIImportFeature(graph, content, plain, "process-exec", arch, evidenceID)
	case isProcessPrimitive(plain):
		category, _ := processPrimitiveFeatureCategory(plain)
		addSecurityAPIImportFeature(graph, content, plain, category, arch, evidenceID)
	case isInputEventMonitoringSymbol(plain):
		addSecurityAPIImportFeature(graph, content, plain, "input-event-monitoring", arch, evidenceID)
	case isAudioRecordingQueueSymbol(plain):
		addSecurityAPIImportFeature(graph, content, plain, "audio-recording", arch, evidenceID)
	case isScreenshotSymbol(plain):
		addSecurityAPIImportFeature(graph, content, plain, "screenshot", arch, evidenceID)
	case isPasteboardReadSymbol(plain), isPasteboardWriteSymbol(plain):
		addSecurityAPIImportFeature(graph, content, plain, "pasteboard", arch, evidenceID)
	case isClipboardSetupSymbol(plain):
		addSecurityAPIImportFeature(graph, content, plain, "clipboard", arch, evidenceID)
	case isDisplaySetupSymbol(plain):
		addSecurityAPIImportFeature(graph, content, plain, "display", arch, evidenceID)
	case isFileOpenSymbol(plain):
		addSecurityAPIImportFeature(graph, content, plain, "file-open", arch, evidenceID)
	case isLibcurlPerformSymbol(plain):
		addSecurityAPIImportFeature(graph, content, plain, "libcurl", arch, evidenceID)
	case isSocketConnectSymbol(plain):
		addSecurityAPIImportFeature(graph, content, plain, "socket-connect", arch, evidenceID)
	case isLoginItemSymbol(plain):
		addSecurityAPIImportFeature(graph, content, plain, "login-item", arch, evidenceID)
	case strings.Contains(plain, "URLSession") || strings.Contains(plain, "nw_connection") || strings.Contains(plain, "SSLHandshake"):
		graph.AddNetworkImplementation(apiNetworkImplementation(
			behavior.NetworkImplementationAPIImport, content, "", arch,
			behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}, behavior.SupportDirect,
			"", plain, evidenceID, false,
		))
	}
}

func addSecurityAPIImportFeature(graph *behavior.Graph, content artifact.Content, symbol, category, arch, evidenceID string) {
	graph.AddFeature(behavior.Feature{
		NodeID:       content.NodeID,
		Architecture: arch,
		Key:          "macho.security_api_import",
		Value:        symbol,
		EvidenceIDs:  []string{evidenceID},
		Support:      behavior.SupportHeuristic,
		Qualifiers: map[string]string{
			"category": category,
		},
	})
}

type machoFunction struct {
	Name                    string
	DisplayName             string
	Language                string
	Module                  string
	Mangling                string
	DisplayTruncated        bool
	RustSymbolInputLimited  bool
	CXXSymbolInputLimited   bool
	SwiftSymbolInputLimited bool
	Start                   uint64
	End                     uint64
	Entrypoint              bool
	Reachable               bool
	Metadata                string
}

type machoCodeRange struct {
	start int // inclusive, relative to the beginning of __text
	end   int // exclusive, relative to the beginning of __text
}

// machoDataInCodeRanges returns LC_DATA_IN_CODE intervals intersecting the
// analyzed __text prefix. The loader marks literal data and jump tables in an
// executable section this way; decoding those bytes can manufacture calls.
func machoDataInCodeRanges(file *macho.File, text *macho.Section, image []byte, textLength int) ([]machoCodeRange, bool, error) {
	cmd := linkeditDataCommand(file, lcDataInCode)
	if cmd.dataSize == 0 {
		return nil, false, nil
	}
	if cmd.dataSize%8 != 0 {
		return nil, true, fmt.Errorf("LC_DATA_IN_CODE size %d is not a multiple of 8", cmd.dataSize)
	}
	start := uint64(cmd.dataOff)
	size := uint64(cmd.dataSize)
	if start > uint64(len(image)) || size > uint64(len(image))-start {
		return nil, true, fmt.Errorf("LC_DATA_IN_CODE table points outside the architecture slice")
	}
	textStart := uint64(text.Offset)
	textEnd := textStart + uint64(textLength)
	if textEnd < textStart {
		return nil, true, fmt.Errorf("__text range overflows")
	}
	table := image[int(start):int(start+size)]
	ranges := make([]machoCodeRange, 0, len(table)/8)
	for offset := 0; offset < len(table); offset += 8 {
		entryStart := uint64(file.ByteOrder.Uint32(table[offset : offset+4]))
		entryLength := uint64(file.ByteOrder.Uint16(table[offset+4 : offset+6]))
		if entryLength == 0 {
			continue
		}
		entryEnd := entryStart + entryLength
		if entryEnd < entryStart || entryStart >= textEnd || entryEnd <= textStart {
			continue
		}
		intersectionStart := max(entryStart, textStart)
		intersectionEnd := min(entryEnd, textEnd)
		ranges = append(ranges, machoCodeRange{
			start: int(intersectionStart - textStart),
			end:   int(intersectionEnd - textStart),
		})
	}
	if len(ranges) == 0 {
		return nil, true, nil
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start != ranges[j].start {
			return ranges[i].start < ranges[j].start
		}
		return ranges[i].end < ranges[j].end
	})
	merged := ranges[:0]
	for _, current := range ranges {
		if len(merged) == 0 || current.start > merged[len(merged)-1].end {
			merged = append(merged, current)
			continue
		}
		if current.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = current.end
		}
	}
	return merged, true, nil
}

func machoCodeRangeContaining(offset int, ranges []machoCodeRange) (machoCodeRange, bool) {
	index := sort.Search(len(ranges), func(i int) bool { return ranges[i].end > offset })
	if index < len(ranges) && offset >= ranges[index].start {
		return ranges[index], true
	}
	return machoCodeRange{}, false
}

func machoCodeInstructionExcluded(offset, size int, ranges []machoCodeRange) (int, bool) {
	if size <= 0 {
		size = 1
	}
	end := offset + size
	if end < offset {
		return offset, true
	}
	index := sort.Search(len(ranges), func(i int) bool { return ranges[i].end > offset })
	if index < len(ranges) && ranges[index].start < end {
		return max(end, ranges[index].end), true
	}
	return end, false
}

func extractFunctionScopedCalls(graph *behavior.Graph, content artifact.Content, file *macho.File, arch string, image []byte) (int, string, bool) {
	text, textIndex := textSection(file)
	if text == nil {
		if file.Type != macho.TypeObj && hasNamedMachOTextSection(file) {
			addPartialCoverageOnce(graph, content.NodeID, "macho-executable-text/"+arch, "__TEXT,__text is not uniquely owned by an initially executable loaded segment; skipped function-scope decoding")
		}
		return 0, "", false
	}
	data, textTruncated, err := machoSectionPrefix(image, text, maxMachOTextAnalysisBytes)
	if err != nil {
		return 0, "", false
	}
	if textTruncated {
		addPartialCoverageOnce(graph, content.NodeID, "macho-text-analysis/"+arch, fmt.Sprintf("executable text analysis capped at %d bytes", maxMachOTextAnalysisBytes))
	}
	dataRanges, dataInCodePresent, dataInCodeErr := machoDataInCodeRanges(file, text, image, len(data))
	if dataInCodeErr != nil {
		addPartialCoverageOnce(graph, content.NodeID, "macho-data-in-code/"+arch, "LC_DATA_IN_CODE could not be applied safely: "+dataInCodeErr.Error()+"; skipped function-scope decoding")
		return 0, "", false
	}
	if dataInCodePresent {
		graph.AddCoverage(behavior.Coverage{
			NodeID:       content.NodeID,
			AnalysisArea: "macho-data-in-code/" + arch,
			Status:       "analyzed",
			Detail:       fmt.Sprintf("excluded %d normalized LC_DATA_IN_CODE interval(s) from instruction decoding", len(dataRanges)),
		})
	}
	functions, hasFunctionStarts, functionsTruncated, goStatus := functionRangesBoundedDetailed(file, text, textIndex, image)
	addMachORustSymbolCoverage(graph, content, arch, functions)
	addMachOCXXSymbolCoverage(graph, content, arch, functions)
	addMachOSwiftSymbolCoverage(graph, content, arch, functions)
	if goStatus.present {
		if goStatus.used {
			value := fmt.Sprintf("functions=%d runtime_compiler=%d standard_library=%d", goStatus.functions, goStatus.runtime, goStatus.standard)
			evidenceID := graph.AddEvidence(machOEvidenceAt(content, int(goStatus.sectionOffset), behavior.Evidence{
				NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-go-pclntab", Kind: "go-function-table", Value: value, Arch: arch,
			}))
			graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Architecture: arch, Key: "go.pclntab", Value: value, EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect})
			graph.AddCoverage(behavior.Coverage{NodeID: content.NodeID, AnalysisArea: "macho-go-pclntab/" + arch, Status: "analyzed", Detail: fmt.Sprintf("bounded Go 1.18+ pclntab recovered %d exact function boundaries and names (%d runtime/compiler, %d standard-library, %d other)", goStatus.functions, goStatus.runtime, goStatus.standard, goStatus.functions-goStatus.runtime-goStatus.standard)})
			addPartialCoverageOnce(graph, content.NodeID, "macho-go-semantics/"+arch, machoGoSemanticCoverageDetail)
		} else {
			addPartialCoverageOnce(graph, content.NodeID, "macho-go-pclntab/"+arch, goStatus.detail)
		}
	}
	if functionsTruncated {
		addPartialCoverageOnce(graph, content.NodeID, "macho-function-boundaries/"+arch, fmt.Sprintf("function boundary extraction capped at %d function-start bytes, %d records, %d starts, and %d retained functions", maxMachOFunctionStartBytes, maxMachOFunctionRecords, maxMachOFunctionStarts, maxMachOFunctions))
	}
	if file.Type == macho.TypeExec {
		if _, ok := machoEntrypointVA(file); !ok {
			addPartialCoverageOnce(graph, content.NodeID, "macho-entrypoint/"+arch, "no unique supported LC_MAIN or x86_64 LC_UNIXTHREAD entrypoint was available; function-scoped behavior was retained with UNKNOWN execution connectivity")
		} else {
			retainMachOUnixThreadEntry(graph, content, file, arch)
		}
	}
	callGraphTruncated, callGraphDecodeIncomplete := markReachableFunctionsWithRangesDetailedSeeded(file, text, data, functions, dataRanges, machoExecutionSeedForContent(content))
	if callGraphTruncated {
		addPartialCoverageOnce(graph, content.NodeID, "macho-local-callgraph/"+arch, fmt.Sprintf("local call graph capped at %d code bytes, %d call candidates, and %d retained edges", maxMachODirectCallScanBytes, maxMachODirectCallCandidates, maxMachOLocalCallEdges))
	}
	if callGraphDecodeIncomplete {
		addPartialCoverageOnce(graph, content.NodeID, "macho-x86-reachability-decode/"+arch, "x86_64 reachability decoding stopped at the first undecodable instruction in each affected recovered function; no byte resynchronization was attempted")
	}
	importStubs, importStubsTruncated := importedStubMapBounded(file, maxMachOStubRecords)
	objcStubs, objcStubsTruncated := objcMessageStubMapBounded(file, maxMachOStubRecords)
	if importStubsTruncated || objcStubsTruncated {
		addPartialCoverageOnce(graph, content.NodeID, "macho-stubs/"+arch, fmt.Sprintf("stub extraction capped at %d indirect-symbol or Objective-C symbol records", maxMachOStubRecords))
	}
	count := 0
	lookup := newMachOCallLookup(graph, content, arch)
	if bindings, present, detail := machoClassicDyldBindings(file, image); present {
		lookup.dyldBindings = bindings
		if detail != "" {
			lookup.dyldIncomplete = true
			addPartialCoverageOnce(graph, content.NodeID, "macho-dyld-bind/"+arch, detail)
		} else {
			graph.AddCoverage(behavior.Coverage{
				NodeID: content.NodeID, AnalysisArea: "macho-dyld-bind/" + arch, Status: "analyzed",
				Detail: fmt.Sprintf("bounded classic dyld binding streams recovered %d exact pointer-slot symbol bindings; bindings are not calls or execution", len(bindings)),
			})
		}
	}
	if bindings, present, detail := machoChainedPointerBindings(file, image); present {
		if detail != "" {
			lookup.dyldIncomplete = true
			addPartialCoverageOnce(graph, content.NodeID, "macho-chained-bind/"+arch, detail)
		} else {
			conflict := false
			if lookup.dyldBindings == nil {
				lookup.dyldBindings = map[uint64]machoDyldBinding{}
			}
			for slot, binding := range bindings {
				if existing, exists := lookup.dyldBindings[slot]; exists && existing.Name != binding.Name {
					delete(lookup.dyldBindings, slot)
					if lookup.dyldAmbiguous == nil {
						lookup.dyldAmbiguous = map[uint64]bool{}
					}
					lookup.dyldAmbiguous[slot] = true
					conflict = true
					continue
				}
				lookup.dyldBindings[slot] = binding
			}
			if conflict {
				addPartialCoverageOnce(graph, content.NodeID, "macho-chained-bind/"+arch, "classic and chained binding metadata assigned conflicting symbols to a pointer slot; affected slots were discarded")
			} else {
				graph.AddCoverage(behavior.Coverage{
					NodeID: content.NodeID, AnalysisArea: "macho-chained-bind/" + arch, Status: "analyzed",
					Detail: fmt.Sprintf("bounded chained-fixup traversal recovered %d exact pointer-slot symbol bindings; bindings are not calls or execution", len(bindings)),
				})
			}
		}
	}
	count += extractFunctionStringXrefsIndexedWithRanges(lookup, file, text, data, functions, image, dataRanges)
	relocatedCount, relocatedTruncated := extractRelocatedImportCallsIndexedWithRanges(lookup, file, text, functions, maxMachORelocationRecords, dataRanges)
	count += relocatedCount
	if relocatedTruncated {
		addPartialCoverageOnce(graph, content.NodeID, "macho-relocated-calls/"+arch, fmt.Sprintf("relocation call extraction capped at %d relocation records or the behavior graph work limit", maxMachORelocationRecords))
	}
	directCount, directTruncated := extractDirectLocalCallsIndexedWithRanges(lookup, file, text, data, functions, importStubs, objcStubs, dataRanges)
	count += directCount
	if directTruncated {
		addPartialCoverageOnce(graph, content.NodeID, "macho-direct-calls/"+arch, fmt.Sprintf("direct call extraction capped at %d code bytes, %d call candidates, %d cumulative Objective-C argument bytes, or the behavior graph work limit", maxMachODirectCallScanBytes, maxMachODirectCallCandidates, maxMachOCFStringBackingBytes))
	}
	boundarySources := make([]string, 0, 3)
	if goStatus.used {
		boundarySources = append(boundarySources, "Go pclntab")
	}
	if hasFunctionStarts {
		boundarySources = append(boundarySources, "LC_FUNCTION_STARTS")
	}
	boundarySources = append(boundarySources, "symbols/fallback")
	return count, strings.Join(boundarySources, "/"), len(importStubs) > 0 || len(objcStubs) > 0
}

func textSection(file *macho.File) (*macho.Section, int) {
	for i, section := range file.Sections {
		if section.Seg == "__TEXT" && section.Name == "__text" {
			// Relocatable objects describe instruction-bearing sections but are
			// not mapped by the kernel yet. For loaded images, names alone are
			// insufficient: only bytes in an initially executable segment may
			// drive call/reachability semantics.
			if file.Type != macho.TypeObj {
				segment, ok := owningLoadedMachOSegment(file, section)
				if !ok || segment.Prot&0x4 == 0 { // VM_PROT_EXECUTE
					continue
				}
			}
			return section, i + 1
		}
	}
	return nil, 0
}

func hasNamedMachOTextSection(file *macho.File) bool {
	for _, section := range file.Sections {
		if section.Seg == "__TEXT" && section.Name == "__text" {
			return true
		}
	}
	return false
}

func owningLoadedMachOSegment(file *macho.File, section *macho.Section) (*macho.Segment, bool) {
	var owner *macho.Segment
	for _, load := range file.Loads {
		segment, ok := load.(*macho.Segment)
		if !ok || segment.Name != section.Seg || section.Addr < segment.Addr || uint64(section.Offset) < segment.Offset {
			continue
		}
		vmDelta := section.Addr - segment.Addr
		fileDelta := uint64(section.Offset) - segment.Offset
		if vmDelta != fileDelta || vmDelta > segment.Memsz || section.Size > segment.Memsz-vmDelta || fileDelta > segment.Filesz || section.Size > segment.Filesz-fileDelta {
			continue
		}
		if owner != nil {
			return nil, false
		}
		owner = segment
	}
	return owner, owner != nil
}

func functionRangesBounded(file *macho.File, text *macho.Section, textIndex int, image []byte) ([]machoFunction, bool, bool) {
	functions, starts, truncated, _ := functionRangesBoundedDetailed(file, text, textIndex, image)
	return functions, starts, truncated
}

func functionRangesBoundedDetailed(file *macho.File, text *macho.Section, textIndex int, image []byte) ([]machoFunction, bool, bool, goPCLNStatus) {
	goFunctions, goStatus := goPCLNFunctionRangesBounded(file, text, image)
	funcs := append([]machoFunction(nil), goFunctions...)
	truncated := false
	if file.Symtab != nil {
		for index, symbol := range file.Symtab.Syms {
			if index >= maxMachOFunctionRecords {
				truncated = true
				break
			}
			if !isDefinedMachOSectionSymbol(symbol) || symbol.Sect != uint8(textIndex) || symbol.Value < text.Addr || symbol.Value >= text.Addr+text.Size {
				continue
			}
			if len(funcs) >= maxMachOFunctions {
				truncated = true
				break
			}
			name := strings.TrimPrefix(symbol.Name, "_")
			if name == "" {
				name = fmt.Sprintf("sub_%x", symbol.Value)
			}
			function := machoFunction{Name: name, Start: symbol.Value, Metadata: "macho-symbol"}
			if rust, ok := machoRustSymbolInfo(name); ok {
				function.DisplayName = rust.display
				function.Language = "rust"
				function.Module = rust.module
				function.Mangling = rust.mangling
				function.DisplayTruncated = rust.displayTruncated
				function.Metadata = rust.origin
			} else if len(name) > maxMachOSymbolDemangleInputBytes && strings.HasPrefix(name, "_R") {
				// The v0 prefix is language-specific, but an over-budget body is
				// deliberately not parsed or classified beyond that exact fact.
				function.Language = "rust"
				function.Mangling = "v0"
				function.RustSymbolInputLimited = true
			} else if cxx, ok := machoCXXSymbolInfo(name); ok {
				function.DisplayName = cxx.display
				function.Language = "c++"
				function.Module = cxx.module
				function.Mangling = "itanium"
				function.DisplayTruncated = cxx.displayTruncated
				function.Metadata = cxx.origin
			} else if len(name) > maxMachOSymbolDemangleInputBytes && strings.HasPrefix(name, "_Z") && !legacyRustSymbolHashTail(name) {
				function.Language = "c++"
				function.Mangling = "itanium"
				function.CXXSymbolInputLimited = true
			} else if swift, ok := machoSwiftSymbolInfo(name); ok {
				function.Language = "swift"
				function.Module = swift.module
				function.Mangling = swift.mangling
				function.Metadata = swift.origin
			} else if len(name) > maxMachOSymbolDemangleInputBytes && isSwiftMangledPrefix(name) {
				function.Language = "swift"
				function.SwiftSymbolInputLimited = true
			}
			funcs = append(funcs, function)
		}
	}
	starts, startsTruncated := functionStartsBounded(file, text, image)
	truncated = truncated || startsTruncated
	for _, start := range starts {
		if len(funcs) >= maxMachOFunctions {
			truncated = true
			break
		}
		funcs = append(funcs, machoFunction{Name: fmt.Sprintf("sub_%x", start), Start: start, Metadata: "function-start"})
	}
	// A supported process entry command is itself a function boundary. In stripped files it
	// prevents the fallback whole-__text range from making every call look as
	// though it came directly from the process entrypoint.
	if entryVA, ok := machoEntrypointVA(file); ok && entryVA >= text.Addr && entryVA < text.Addr+text.Size {
		if len(funcs) < maxMachOFunctions {
			funcs = append(funcs, machoFunction{Name: fmt.Sprintf("sub_%x", entryVA), Start: entryVA, Metadata: "entrypoint"})
		} else {
			truncated = true
		}
	}
	sort.SliceStable(funcs, func(i, j int) bool { return funcs[i].Start < funcs[j].Start })
	funcs = dedupeFunctions(funcs)
	uniquifyMachOFunctionNames(funcs)
	uniquifyMachOFunctionDisplayNames(funcs)
	if len(funcs) == 0 {
		funcs = append(funcs, machoFunction{Name: fmt.Sprintf("sub_%x", text.Addr), Start: text.Addr, Metadata: "fallback"})
	}
	for i := range funcs {
		boundaryEnd := text.Addr + text.Size
		if i+1 < len(funcs) {
			boundaryEnd = funcs[i+1].Start
		}
		if funcs[i].End == 0 || funcs[i].End > boundaryEnd {
			funcs[i].End = boundaryEnd
		}
	}
	return funcs, len(starts) > 0, truncated, goStatus
}

func uniquifyMachOFunctionNames(functions []machoFunction) {
	counts := make(map[string]int, len(functions))
	for _, function := range functions {
		counts[function.Name]++
	}
	for i := range functions {
		if counts[functions[i].Name] > 1 {
			functions[i].Name = fmt.Sprintf("%s@0x%x", functions[i].Name, functions[i].Start)
		}
	}
}

func uniquifyMachOFunctionDisplayNames(functions []machoFunction) {
	counts := make(map[string]int, len(functions))
	for _, function := range functions {
		if function.DisplayName != "" {
			counts[function.DisplayName]++
		}
	}
	for i := range functions {
		if functions[i].DisplayName != "" && counts[functions[i].DisplayName] > 1 {
			functions[i].DisplayName = fmt.Sprintf("%s@0x%x", functions[i].DisplayName, functions[i].Start)
		}
	}
}

func dedupeFunctions(in []machoFunction) []machoFunction {
	var out []machoFunction
	var last uint64
	for i, fn := range in {
		if i > 0 && fn.Start == last {
			if machoFunctionMetadataPriority(fn) > machoFunctionMetadataPriority(out[len(out)-1]) {
				out[len(out)-1] = fn
			}
			continue
		}
		out = append(out, fn)
		last = fn.Start
	}
	return out
}

func machoFunctionMetadataPriority(function machoFunction) int {
	switch function.Metadata {
	case "go-other", "go-runtime-compiler", "go-standard-library", "rust-other", "rust-runtime-compiler", "rust-standard-library", "cxx-other", "cxx-runtime-compiler", "cxx-standard-library", "swift-other", "swift-runtime-compiler", "swift-standard-library":
		return 4
	case "macho-symbol":
		return 3
	case "entrypoint":
		return 2
	case "function-start":
		return 1
	default:
		if !strings.HasPrefix(function.Name, "sub_") {
			return 3
		}
		return 0
	}
}

func functionStartsBounded(file *macho.File, text *macho.Section, image []byte) ([]uint64, bool) {
	if len(image) == 0 {
		return nil, false
	}
	cmd := linkeditDataCommand(file, 0x26)
	if cmd.dataSize == 0 {
		return nil, false
	}
	start := int(cmd.dataOff)
	end := start + int(cmd.dataSize)
	if start < 0 || end < start || end > len(image) {
		return nil, true
	}
	base := textSegmentBase(file, text)
	return decodeFunctionStartsBounded(image[start:end], base, text.Addr, text.Addr+text.Size, maxMachOFunctionStartBytes, maxMachOFunctionRecords, maxMachOFunctionStarts)
}

func markEntrypointFunction(file *macho.File, functions []machoFunction) {
	entryVA, ok := machoEntrypointVA(file)
	if !ok {
		return
	}
	for index := range functions {
		if entryVA >= functions[index].Start && entryVA < functions[index].End {
			functions[index].Entrypoint = true
			functions[index].Reachable = true
			return
		}
	}
}

type machoExecutionSeed uint8

const (
	machoExecutionSeedNone machoExecutionSeed = iota
	machoExecutionSeedRoot
	machoExecutionSeedLocalEntry
)

func machoExecutionSeedForContent(content artifact.Content) machoExecutionSeed {
	// Direct extractor fixtures predate artifact-wide execution context. Keep
	// their local behavior unless the production registry explicitly supplied a
	// complete context.
	if content.ExecutionConnectivity == "" {
		return machoExecutionSeedRoot
	}
	if content.ExecutionConnectivity != string(behavior.ConnectivityConnected) || len(content.ExecutionRootIDs) == 0 {
		// The Mach-O header still identifies a local program entry even when the
		// surrounding artifact model cannot connect that program to a declared
		// execution root. Seed bounded intra-binary reachability while preserving
		// the content's UNKNOWN or UNCONNECTED context on derived records.
		return machoExecutionSeedLocalEntry
	}
	if len(content.InvokedTargetIDs) > 0 {
		return machoExecutionSeedLocalEntry
	}
	return machoExecutionSeedRoot
}

func markMachOExecutionSeed(file *macho.File, functions []machoFunction, seed machoExecutionSeed, queue *[]int, queued []bool) {
	if seed == machoExecutionSeedNone {
		return
	}
	mark := func(index int) {
		if index < 0 || index >= len(functions) {
			return
		}
		if seed == machoExecutionSeedRoot {
			functions[index].Entrypoint = true
		}
		functions[index].Reachable = true
		if queue != nil && len(queued) == len(functions) && !queued[index] {
			*queue = append(*queue, index)
			queued[index] = true
		}
	}
	entryVA, ok := machoEntrypointVA(file)
	if ok {
		for index := range functions {
			if entryVA >= functions[index].Start && entryVA < functions[index].End {
				mark(index)
				break
			}
		}
	}
}

func markReachableFunctions(file *macho.File, text *macho.Section, data []byte, functions []machoFunction) bool {
	return markReachableFunctionsWithRanges(file, text, data, functions, nil)
}

func markReachableFunctionsWithRanges(file *macho.File, text *macho.Section, data []byte, functions []machoFunction, dataRanges []machoCodeRange) bool {
	truncated, decodeIncomplete := markReachableFunctionsWithRangesDetailed(file, text, data, functions, dataRanges)
	return truncated || decodeIncomplete
}

func markReachableFunctionsWithRangesDetailed(file *macho.File, text *macho.Section, data []byte, functions []machoFunction, dataRanges []machoCodeRange) (bool, bool) {
	return markReachableFunctionsWithRangesDetailedSeeded(file, text, data, functions, dataRanges, machoExecutionSeedRoot)
}

func markReachableFunctionsWithRangesDetailedSeeded(file *macho.File, text *macho.Section, data []byte, functions []machoFunction, dataRanges []machoCodeRange, seed machoExecutionSeed) (bool, bool) {
	var queue []int
	queued := make([]bool, len(functions))
	// A supported entry command seeds local traversal. Artifact execution
	// ownership remains independent: a local entry does not create a root or
	// turn UNKNOWN/UNCONNECTED content into CONNECTED content.
	markMachOExecutionSeed(file, functions, seed, &queue, queued)
	var edges []localCallEdge
	truncated := false
	decodeIncomplete := false
	if file.Cpu == macho.CpuAmd64 {
		edges, truncated, decodeIncomplete = x86LocalCallEdgesBoundedWithRangesDetailed(text.Addr, data, functions, maxMachODirectCallScanBytes, maxMachODirectCallCandidates, maxMachOLocalCallEdges, dataRanges)
	} else {
		edges, truncated = directLocalCallEdgesBoundedWithRanges(file.Cpu, file.ByteOrder, text.Addr, data, functions, maxMachODirectCallScanBytes, maxMachODirectCallCandidates, maxMachOLocalCallEdges, dataRanges)
	}
	if len(edges) == 0 {
		return truncated, decodeIncomplete
	}
	calls := make([][]int, len(functions))
	for _, edge := range edges {
		calls[edge.caller] = append(calls[edge.caller], edge.callee)
	}
	for len(queue) > 0 {
		caller := queue[0]
		queue = queue[1:]
		for _, callee := range calls[caller] {
			if queued[callee] {
				continue
			}
			functions[callee].Reachable = true
			queue = append(queue, callee)
			queued[callee] = true
		}
	}
	return truncated, decodeIncomplete
}

func machoEntrypointVA(file *macho.File) (uint64, bool) {
	if file.Type != macho.TypeExec || file.ByteOrder == nil {
		return 0, false
	}
	var entryOff uint64
	found := false
	var unixThread []byte
	for _, load := range file.Loads {
		rawer, ok := load.(interface{ Raw() []byte })
		if !ok {
			continue
		}
		raw := rawer.Raw()
		if len(raw) >= 8 && file.ByteOrder.Uint32(raw[0:4]) == 5 { // LC_UNIXTHREAD
			if unixThread != nil {
				return 0, false
			}
			unixThread = raw
		}
		if len(raw) < 8 || file.ByteOrder.Uint32(raw[0:4]) != lcMain {
			continue
		}
		if found || len(raw) < 24 || file.ByteOrder.Uint32(raw[4:8]) != 24 {
			return 0, false
		}
		entryOff = file.ByteOrder.Uint64(raw[8:16])
		found = true
	}
	if unixThread != nil {
		if found { // Conflicting process-entry mechanisms are not resolved by guessing.
			return 0, false
		}
		return machoUnixThreadEntrypointVA(file, unixThread)
	}
	if !found {
		return 0, false
	}
	return fileOffsetToVA(file, entryOff)
}

func fileOffsetToVA(file *macho.File, fileOffset uint64) (uint64, bool) {
	var matchedVA uint64
	matched := false
	for _, load := range file.Loads {
		segment, ok := load.(*macho.Segment)
		if !ok || segment.Filesz == 0 {
			continue
		}
		if segment.Offset > ^uint64(0)-segment.Filesz || segment.Addr > ^uint64(0)-segment.Filesz {
			return 0, false
		}
		if fileOffset < segment.Offset || fileOffset >= segment.Offset+segment.Filesz {
			continue
		}
		candidate := segment.Addr + fileOffset - segment.Offset
		if matched {
			return 0, false
		}
		matchedVA = candidate
		matched = true
	}
	return matchedVA, matched
}

type linkeditCommand struct {
	dataOff  uint32
	dataSize uint32
}

func linkeditDataCommand(file *macho.File, command uint32) linkeditCommand {
	result, _ := findLinkeditDataCommand(file, command)
	return result
}

func findLinkeditDataCommand(file *macho.File, command uint32) (linkeditCommand, bool) {
	if file == nil || file.ByteOrder == nil {
		return linkeditCommand{}, false
	}
	for _, load := range file.Loads {
		rawer, ok := load.(interface{ Raw() []byte })
		if !ok {
			continue
		}
		raw := rawer.Raw()
		if len(raw) < 16 || file.ByteOrder.Uint32(raw[0:4]) != command {
			continue
		}
		return linkeditCommand{
			dataOff:  file.ByteOrder.Uint32(raw[8:12]),
			dataSize: file.ByteOrder.Uint32(raw[12:16]),
		}, true
	}
	return linkeditCommand{}, false
}

func extractEncryptionInfo(graph *behavior.Graph, content artifact.Content, file *macho.File, arch string) bool {
	for _, load := range file.Loads {
		rawer, ok := load.(interface{ Raw() []byte })
		if !ok {
			continue
		}
		raw := rawer.Raw()
		if len(raw) < 20 {
			continue
		}
		cmd := file.ByteOrder.Uint32(raw[0:4])
		if cmd != lcEncryptionInfo && cmd != lcEncryptionInfo64 {
			continue
		}
		cryptOff := file.ByteOrder.Uint32(raw[8:12])
		cryptSize := file.ByteOrder.Uint32(raw[12:16])
		cryptID := file.ByteOrder.Uint32(raw[16:20])
		state := "not-encrypted"
		if cryptID != 0 {
			state = "encrypted"
		}
		ev := graph.AddEvidence(behavior.Evidence{
			NodeID:  content.NodeID,
			Logical: content.LogicalPath,
			Method:  "macho-load-command",
			Kind:    "encryption-info",
			Value:   fmt.Sprintf("cryptoff=%d cryptsize=%d cryptid=%d", cryptOff, cryptSize, cryptID),
			Arch:    arch,
		})
		graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "macho-encryption", Value: state, EvidenceIDs: []string{ev}, Support: behavior.SupportDirect})
		if cryptID != 0 {
			graph.AddCoverage(behavior.Coverage{
				NodeID:       content.NodeID,
				AnalysisArea: "macho-byte-analysis/" + arch,
				Status:       "partial",
				Detail:       "cryptid is nonzero; skipped byte-derived string, Objective-C, entitlement-fallback, function, call, xref, and reachability analysis for this architecture; retained structural metadata, imports, sections with bounded entropy, rpaths, and embedded-signature metadata",
			})
		}
		return cryptID != 0
	}
	return false
}

type codeSignatureBlob struct {
	kind string
	data []byte
}

type codeSignatureInspection struct {
	blobs               []codeSignatureBlob
	truncated           bool
	invalid             bool
	recognized          bool
	validCodeDirectory  bool
	hasEntitlementSlots bool
}

func (inspection codeSignatureInspection) entitlementSlotsConclusiveAbsent() bool {
	// This is a structural conclusion, not cryptographic signature validation.
	// A complete embedded-signature index with a valid CodeDirectory is enough
	// to show that XML and DER entitlement slots are absent.
	return inspection.recognized && !inspection.truncated && !inspection.invalid && inspection.validCodeDirectory && !inspection.hasEntitlementSlots
}

func extractCodeSignature(graph *behavior.Graph, content artifact.Content, file *macho.File, arch string, image []byte) bool {
	cmd := linkeditDataCommand(file, lcCodeSignature)
	if cmd.dataSize == 0 {
		return false
	}
	start := int(cmd.dataOff)
	end := start + int(cmd.dataSize)
	if start < 0 || end < start || end > len(image) {
		graph.AddCoverage(behavior.Coverage{
			NodeID:       content.NodeID,
			AnalysisArea: "macho-code-signature/" + arch,
			Status:       "partial",
			Detail:       "LC_CODE_SIGNATURE points outside file data",
		})
		return false
	}
	ev := graph.AddEvidence(behavior.Evidence{
		NodeID:  content.NodeID,
		Logical: content.LogicalPath,
		Method:  "macho-code-signature",
		Kind:    "code-signature",
		Value:   "LC_CODE_SIGNATURE present",
		Arch:    arch,
	})
	graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "code-signature-structure", Value: "present", EvidenceIDs: []string{ev}, Support: behavior.SupportDirect})
	return parseCodeSignatureBlobs(graph, content, image[start:end], image[:start], arch, ev)
}

func parseCodeSignatureBlobs(graph *behavior.Graph, content artifact.Content, data, image []byte, arch, parentEvidence string) bool {
	inspection := inspectCodeSignatureBlobs(data, maxMachOCodeSignatureSlots, maxMachOCodeSignatureBlobs)
	if inspection.truncated {
		addPartialCoverageOnce(graph, content.NodeID, "macho-code-signature/"+arch, fmt.Sprintf("code-signature parsing capped at %d index slots and %d unique blobs, or encountered a truncated index", maxMachOCodeSignatureSlots, maxMachOCodeSignatureBlobs))
	}
	for _, blob := range inspection.blobs {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return false
		}
		switch blob.kind {
		case "code-directory":
			parseCodeDirectory(graph, content, blob.data, image, arch, parentEvidence)
		case "cms-signature":
			parseCMSSignatureBlob(graph, content, blob.data, arch, parentEvidence)
		case "entitlements":
			parseEntitlementsXMLBlob(graph, content, blob.data, arch)
		case "der-entitlements":
			ev := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-code-signature", Kind: "entitlements-der", Value: "DER entitlements present", Arch: arch})
			graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "entitlements-der", Value: "present", EvidenceIDs: []string{ev}, Support: behavior.SupportDirect})
		}
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return false
		}
	}
	return inspection.entitlementSlotsConclusiveAbsent()
}

func codeSignatureBlobsBounded(data []byte, slotLimit, blobLimit int) ([]codeSignatureBlob, bool) {
	inspection := inspectCodeSignatureBlobs(data, slotLimit, blobLimit)
	return inspection.blobs, inspection.truncated
}

func inspectCodeSignatureBlobs(data []byte, slotLimit, blobLimit int) codeSignatureInspection {
	var inspection codeSignatureInspection
	if len(data) < 8 {
		return inspection
	}
	if slotLimit < 0 {
		slotLimit = 0
	}
	if blobLimit < 0 {
		blobLimit = 0
	}
	magic := binary.BigEndian.Uint32(data[0:4])
	declaredLength := uint64(binary.BigEndian.Uint32(data[4:8]))
	length := int(declaredLength)
	inspection.truncated = declaredLength < 8 || declaredLength > uint64(len(data))
	if inspection.truncated {
		length = len(data)
	}
	data = data[:length]
	if magic != csMagicSuperBlob {
		inspection.blobs = singleCodeSignatureBlob(data)
		inspection.recognized = len(inspection.blobs) > 0
		if magic == csMagicCodeDirectory && len(data) >= 44 {
			inspection.validCodeDirectory = true
		}
		if magic == csMagicEntitlementsXML {
			inspection.hasEntitlementSlots = true
		}
		if len(inspection.blobs) > blobLimit {
			inspection.blobs = inspection.blobs[:blobLimit]
			inspection.truncated = true
		}
		return inspection
	}
	inspection.recognized = true
	if len(data) < 12 {
		inspection.truncated = true
		return inspection
	}
	declaredCount := uint64(binary.BigEndian.Uint32(data[8:12]))
	availableCount := uint64((len(data) - 12) / 8)
	count := declaredCount
	if count > availableCount {
		count = availableCount
		inspection.truncated = true
	}
	if count > uint64(slotLimit) {
		count = uint64(slotLimit)
		inspection.truncated = true
	}
	indexEnd := uint64(12) + declaredCount*8
	if declaredCount > (math.MaxUint64-12)/8 || indexEnd > uint64(len(data)) {
		inspection.truncated = true
		indexEnd = uint64(len(data))
	}
	type signatureIndexKey struct {
		slot   uint32
		offset uint32
	}
	seen := make(map[signatureIndexKey]struct{}, int(count))
	for i := uint64(0); i < count; i++ {
		entryOffset := 12 + int(i)*8
		slot := binary.BigEndian.Uint32(data[entryOffset : entryOffset+4])
		rawOffset := binary.BigEndian.Uint32(data[entryOffset+4 : entryOffset+8])
		if slot == csSlotEntitlements || slot == csSlotDerEntitlements {
			inspection.hasEntitlementSlots = true
		}
		key := signatureIndexKey{slot: slot, offset: rawOffset}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		offset := uint64(rawOffset)
		if offset > uint64(len(data)) || uint64(len(data))-offset < 8 {
			inspection.truncated = true
			continue
		}
		if offset < indexEnd {
			inspection.truncated = true
		}
		blobLength := uint64(binary.BigEndian.Uint32(data[int(offset)+4 : int(offset)+8]))
		if blobLength < 8 || blobLength > uint64(len(data))-offset {
			inspection.truncated = true
			continue
		}
		blob := data[int(offset):int(offset+blobLength)]
		kind := ""
		switch {
		case slot == csSlotCodeDirectory ||
			(slot >= csSlotAlternateCodeDirectories && slot < csSlotAlternateCodeDirectoryLimit):
			kind = "code-directory"
			if len(blob) >= 44 && binary.BigEndian.Uint32(blob[0:4]) == csMagicCodeDirectory {
				inspection.validCodeDirectory = true
			} else {
				inspection.invalid = true
			}
		case slot == csSlotEntitlements:
			kind = "entitlements"
		case slot == csSlotDerEntitlements:
			kind = "der-entitlements"
		case slot == csSlotCMSSignature:
			kind = "cms-signature"
		}
		if kind == "" {
			continue
		}
		if len(inspection.blobs) >= blobLimit {
			inspection.truncated = true
			return inspection
		}
		inspection.blobs = append(inspection.blobs, codeSignatureBlob{kind: kind, data: blob})
	}
	return inspection
}

func singleCodeSignatureBlob(data []byte) []codeSignatureBlob {
	magic := binary.BigEndian.Uint32(data[0:4])
	switch magic {
	case csMagicCodeDirectory:
		return []codeSignatureBlob{{kind: "code-directory", data: data}}
	case csMagicEntitlementsXML:
		return []codeSignatureBlob{{kind: "entitlements", data: data}}
	default:
		return nil
	}
}

func parseCodeDirectory(graph *behavior.Graph, content artifact.Content, data, image []byte, arch, parentEvidence string) {
	if len(data) < 44 || binary.BigEndian.Uint32(data[0:4]) != csMagicCodeDirectory {
		return
	}
	flags := binary.BigEndian.Uint32(data[12:16])
	identOffset := int(binary.BigEndian.Uint32(data[20:24]))
	ev := graph.AddEvidence(behavior.Evidence{
		NodeID:  content.NodeID,
		Logical: content.LogicalPath,
		Method:  "macho-code-signature",
		Kind:    "code-directory",
		Value:   fmt.Sprintf("flags=%#x", flags),
		Arch:    arch,
	})
	graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "code-signature-flags", Value: fmt.Sprintf("%#x", flags), EvidenceIDs: []string{ev}, Support: behavior.SupportDirect})
	if flags&0x2 != 0 {
		graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "code-signature-kind", Value: "ad-hoc", EvidenceIDs: []string{ev, parentEvidence}, Support: behavior.SupportDirect})
	}
	verifyCodeDirectoryPages(graph, content, data, image, arch, parentEvidence)
	if ident := codeDirectoryString(data, identOffset); ident != "" {
		idEv := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-code-signature", Kind: "code-directory-identifier", Value: ident, Arch: arch})
		graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "code-directory-identifier", Value: ident, EvidenceIDs: []string{idEv, parentEvidence}, Support: behavior.SupportDirect})
	}
	version := binary.BigEndian.Uint32(data[8:12])
	if version >= 0x20200 && len(data) >= 52 {
		teamOffset := int(binary.BigEndian.Uint32(data[48:52]))
		if teamID := codeDirectoryString(data, teamOffset); teamID != "" {
			teamEv := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-code-signature", Kind: "code-directory-team-id", Value: teamID, Arch: arch})
			graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "code-directory-team-id", Value: teamID, EvidenceIDs: []string{teamEv, parentEvidence}, Support: behavior.SupportDirect})
		}
	}
}

func codeDirectoryString(data []byte, offset int) string {
	if offset <= 0 || offset >= len(data) {
		return ""
	}
	return strings.TrimSpace(cstring(data[offset:]))
}

func parseEntitlementsXMLBlob(graph *behavior.Graph, content artifact.Content, data []byte, arch string) {
	if len(data) < 8 || binary.BigEndian.Uint32(data[0:4]) != csMagicEntitlementsXML {
		return
	}
	body := data[8:]
	ev := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-code-signature", Kind: "entitlements-xml", Value: "XML entitlements present", Arch: arch})
	graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "entitlements-xml", Value: "present", EvidenceIDs: []string{ev}, Support: behavior.SupportDirect})
	parseBody, complete := boundedStructuredDocument(graph, content, "macho-entitlements", body)
	if !complete {
		parseBody = body[:maxStructuredDocumentBytes]
	}
	entitlements, _ := plistx.Decode(parseBody)
	keys := entitlementKeys(parseBody)
	if len(entitlements) > 0 {
		keys = entitlementMapKeys(entitlements)
	}
	for _, key := range keys {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
		keyEv := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-code-signature", Kind: "entitlement", Value: key, Arch: arch})
		graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "entitlement", Value: key, EvidenceIDs: []string{keyEv}, Support: behavior.SupportDirect})
		graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Architecture: arch, Key: "entitlement", Value: key, EvidenceIDs: []string{keyEv}, Support: behavior.SupportDirect})
		addNormalizedEntitlementContext(graph, content, arch, key, entitlements[key], keyEv)
	}
}

func entitlementMapKeys(items map[string]any) []string {
	var out []string
	for key := range items {
		if entitlementKeyLooksTopLevel(key) {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func addNormalizedEntitlementContext(graph *behavior.Graph, content artifact.Content, arch, key string, value any, evidenceID string) {
	if !entitlementValueEnabled(value) {
		return
	}
	for _, context := range entitlementContexts(key) {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
		graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "entitlement-context", Value: context, EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect})
		graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Architecture: arch, Key: "entitlement.context", Value: context, EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect, Qualifiers: map[string]string{"entitlement": key}})
	}
	switch key {
	case "keychain-access-groups", "com.apple.security.keychain-access-groups":
		for _, group := range plistx.StringsValue(value) {
			if graph.WorkLimitReached() {
				graph.MarkWorkOmitted()
				return
			}
			graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "entitlement-keychain-access-group", Value: group, EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect})
		}
	case "com.apple.security.application-groups":
		for _, group := range plistx.StringsValue(value) {
			if graph.WorkLimitReached() {
				graph.MarkWorkOmitted()
				return
			}
			graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "entitlement-application-group", Value: group, EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect})
		}
	}
}

func entitlementValueEnabled(value any) bool {
	switch item := value.(type) {
	case nil:
		return true
	case bool:
		return item
	case string:
		return strings.TrimSpace(item) != "" && strings.TrimSpace(item) != "false"
	case []any:
		return len(item) > 0
	default:
		return true
	}
}

func entitlementContexts(key string) []string {
	switch key {
	case "com.apple.security.get-task-allow", "get-task-allow":
		return []string{"debuggable"}
	case "com.apple.security.cs.disable-library-validation":
		return []string{"library-validation-disabled"}
	case "com.apple.security.cs.allow-dyld-environment-variables":
		return []string{"dyld-environment-allowed"}
	case "com.apple.security.cs.allow-unsigned-executable-memory":
		return []string{"unsigned-executable-memory"}
	case "com.apple.security.cs.debugger":
		return []string{"debugger"}
	case "com.apple.security.app-sandbox":
		return []string{"app-sandbox"}
	case "com.apple.security.automation.apple-events":
		return []string{"apple-events-automation"}
	case "com.apple.security.network.client":
		return []string{"network-client"}
	case "com.apple.security.network.server":
		return []string{"network-server"}
	case "keychain-access-groups", "com.apple.security.keychain-access-groups":
		return []string{"keychain-access-groups"}
	case "com.apple.security.application-groups":
		return []string{"application-groups"}
	}
	switch {
	case strings.HasPrefix(key, "com.apple.security.files."):
		return []string{"file-access"}
	case strings.HasPrefix(key, "com.apple.security.personal-information."):
		return []string{"personal-data-access"}
	case strings.HasPrefix(key, "com.apple.security.device."):
		return []string{"device-access"}
	default:
		return nil
	}
}

func entitlementKeys(data []byte) []string {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var inKey bool
	var enteredRootDict bool
	var dictDepth int
	seen := map[string]bool{}
	var out []string
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out
		}
		switch item := tok.(type) {
		case xml.StartElement:
			switch item.Name.Local {
			case "dict":
				dictDepth++
				enteredRootDict = true
			case "key":
				inKey = enteredRootDict && dictDepth == 1
			}
		case xml.CharData:
			if !inKey {
				continue
			}
			key := strings.TrimSpace(string(item))
			if key != "" && entitlementKeyLooksTopLevel(key) && !seen[key] {
				seen[key] = true
				out = append(out, key)
			}
		case xml.EndElement:
			if item.Name.Local == "key" {
				inKey = false
			}
			if item.Name.Local == "dict" && enteredRootDict {
				dictDepth--
				if dictDepth <= 0 {
					sort.Strings(out)
					return out
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func entitlementKeyLooksTopLevel(key string) bool {
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "com.apple.") {
		return true
	}
	switch key {
	case "application-identifier",
		"aps-environment",
		"beta-reports-active",
		"get-task-allow",
		"keychain-access-groups",
		"platform-application":
		return true
	default:
		return false
	}
}

func textSegmentBase(file *macho.File, text *macho.Section) uint64 {
	if file.Type != macho.TypeObj {
		segment, ok := owningLoadedMachOSegment(file, text)
		if !ok {
			return text.Addr
		}
		return segment.Addr
	}
	return text.Addr
}

func decodeFunctionStartsBounded(data []byte, base, textStart, textEnd uint64, byteLimit, recordLimit, startLimit int) ([]uint64, bool) {
	if byteLimit < 0 {
		byteLimit = 0
	}
	if recordLimit < 0 {
		recordLimit = 0
	}
	if startLimit < 0 {
		startLimit = 0
	}
	input := data
	if len(input) > byteLimit {
		input = input[:byteLimit]
	}
	var out []uint64
	address := base
	records := 0
	for offset := 0; offset < len(input); {
		delta, n, ok := readULEB128(input[offset:])
		if !ok {
			return out, true
		}
		offset += n
		if delta == 0 {
			return out, false
		}
		if records >= recordLimit {
			return out, true
		}
		records++
		if delta > ^uint64(0)-address {
			return out, true
		}
		address += delta
		if address >= textStart && address < textEnd {
			if len(out) >= startLimit {
				return out, true
			}
			out = append(out, address)
		}
	}
	return out, len(input) < len(data) || len(input) > 0
}

func readULEB128(data []byte) (uint64, int, bool) {
	var value uint64
	var shift uint
	for i, b := range data {
		if shift >= 64 {
			return 0, 0, false
		}
		payload := uint64(b & 0x7f)
		if payload<<shift>>shift != payload {
			return 0, 0, false
		}
		value |= payload << shift
		if b&0x80 == 0 {
			return value, i + 1, true
		}
		shift += 7
	}
	return 0, 0, false
}

func extractRelocatedImportCallsIndexedWithRanges(lookup *machoCallLookup, file *macho.File, text *macho.Section, functions []machoFunction, recordLimit int, dataRanges []machoCodeRange) (int, bool) {
	if file.Symtab == nil {
		return 0, false
	}
	if recordLimit < 0 {
		recordLimit = 0
	}
	count := 0
	for index, reloc := range text.Relocs {
		if index >= recordLimit {
			return count, true
		}
		if index&0xfff == 0 && lookup.graph.WorkLimitReached() {
			lookup.graph.MarkWorkOmitted()
			return count, true
		}
		if reloc.Scattered || !reloc.Extern || !reloc.Pcrel || reloc.Len != 2 || !isBranchReloc(file.Cpu, reloc.Type) {
			continue
		}
		callOffset, instructionSize, ok := relocatedCallInstruction(file, text, reloc)
		if !ok {
			continue
		}
		if _, excluded := machoCodeInstructionExcluded(callOffset, instructionSize, dataRanges); excluded {
			continue
		}
		if int(reloc.Value) >= len(file.Symtab.Syms) {
			continue
		}
		symbolRecord := file.Symtab.Syms[reloc.Value]
		if !isUndefinedExternal(symbolRecord) {
			continue
		}
		symbol := symbolRecord.Name
		if symbol == "" {
			continue
		}
		callVA := text.Addr + uint64(callOffset)
		count++
		if !isSemanticImportedSymbol(symbol) {
			continue
		}
		fn := functionForVA(functions, callVA)
		scopeID := lookup.functionScopeID(fn)
		ev := lookup.graph.AddEvidence(behavior.Evidence{
			NodeID:   lookup.content.NodeID,
			ScopeID:  scopeID,
			Logical:  lookup.content.LogicalPath,
			VA:       callVA,
			Function: fn.Name,
			Arch:     lookup.arch,
			Method:   "macho-reloc",
			Kind:     "imported-call",
			Value:    fn.Name + " -> " + strings.TrimPrefix(symbol, "_"),
		})
		if ev == "" {
			lookup.graph.MarkWorkOmitted()
			return count, true
		}
		lookup.addFeature(behavior.Feature{
			NodeID:         lookup.content.NodeID,
			ScopeID:        scopeID,
			Architecture:   lookup.arch,
			Key:            "macho.import_call",
			Value:          strings.TrimPrefix(symbol, "_"),
			EvidenceIDs:    []string{ev},
			Support:        behavior.SupportCorroborated,
			Execution:      executionContextForMachOFunction(lookup.content, fn),
			SourceFunction: fn.Name,
			Qualifiers:     map[string]string{"function": fn.Name},
		})
		addOperationFromCalledImportedSymbolWithContextIndexed(lookup, symbol, ev, fn, machoCallContext{})
		if lookup.graph.WorkLimitReached() {
			lookup.graph.MarkWorkOmitted()
			return count, true
		}
	}
	return count, false
}

func relocatedCallInstruction(file *macho.File, text *macho.Section, reloc macho.Reloc) (int, int, bool) {
	switch file.Cpu {
	case macho.CpuAmd64:
		// X86_64_RELOC_BRANCH identifies a signed rel32 field, which is also
		// used by jumps. The relocation address points one byte after the E8
		// opcode, so validate the complete five-byte CALL instruction.
		if reloc.Addr == 0 {
			return 0, 0, false
		}
		offset := uint64(reloc.Addr - 1)
		if offset > text.Size || 5 > text.Size-offset {
			return 0, 0, false
		}
		data, err := readMachOSectionAt(text, offset, 5)
		if err != nil || len(data) != 5 || data[0] != 0xe8 {
			return 0, 0, false
		}
		return int(offset), 5, true
	case macho.CpuArm64:
		offset := uint64(reloc.Addr)
		if offset&3 != 0 || offset > text.Size || 4 > text.Size-offset || file.ByteOrder == nil {
			return 0, 0, false
		}
		data, err := readMachOSectionAt(text, offset, 4)
		if err != nil || len(data) != 4 || file.ByteOrder.Uint32(data)&0xfc000000 != 0x94000000 {
			return 0, 0, false
		}
		return int(offset), 4, true
	default:
		return 0, 0, false
	}
}

func isBranchReloc(cpu macho.Cpu, typ uint8) bool {
	switch cpu {
	case macho.CpuAmd64:
		return typ == uint8(macho.X86_64_RELOC_BRANCH)
	case macho.CpuArm64:
		return typ == uint8(macho.ARM64_RELOC_BRANCH26)
	default:
		return false
	}
}

func extractDirectLocalCallsIndexedWithRanges(lookup *machoCallLookup, file *macho.File, text *macho.Section, data []byte, functions []machoFunction, importStubs, objcStubs map[uint64]string, dataRanges []machoCodeRange) (int, bool) {
	switch file.Cpu {
	case macho.CpuAmd64:
		return extractX86DirectCallsIndexedWithRanges(lookup, file, text, data, functions, importStubs, objcStubs, maxMachODirectCallScanBytes, maxMachODirectCallCandidates, dataRanges)
	case macho.CpuArm64:
		return extractArm64DirectCallsIndexedWithRanges(lookup, file, text, data, functions, importStubs, objcStubs, maxMachODirectCallScanBytes, maxMachODirectCallCandidates, dataRanges)
	default:
		return 0, false
	}
}

type machoStringLiteral struct {
	VA                 uint64
	Offset             int
	Value              string
	Kind               string
	Resource           behavior.Resource
	Size               int
	ValueVA            uint64
	ValueOffset        int
	ValueLocationKnown bool
}

type machoStringXref struct {
	RefVA          uint64
	RefOffset      int
	RefOffsetKnown bool
	Function       machoFunction
	Literal        machoStringLiteral
}

type localCallEdge struct {
	caller int
	callee int
}

type machoCallFeatureKey struct {
	function string
	key      string
}

type machoCallFeatureValueKey struct {
	function string
	key      string
	value    string
}

type machoCallOperationKey struct {
	function string
	kind     behavior.OperationKind
	category string
}

type machoCallPair struct {
	caller string
	callee string
}

type machoCallFeatureGroup struct {
	values map[string][]string
}

type machoSMServiceState struct {
	kind                  behavior.OperationKind
	category              string
	bindsConcreteResource bool
	evidence              []string
}

type machoSMFunctionState struct {
	services map[string]machoSMServiceState
}

// machoCallLookup is built once per node/architecture and shared across
// string-xref and direct-call extraction. Helpers use it for constant-time
// context lookups instead of rescanning the growing behavior graph.
type machoCallLookup struct {
	graph            *behavior.Graph
	content          artifact.Content
	arch             string
	features         map[machoCallFeatureKey]*machoCallFeatureGroup
	evidence         map[machoCallFeatureValueKey][]string
	scopes           map[string]string
	operations       map[machoCallOperationKey]bool
	localCalls       map[machoCallPair]bool
	localCallOrigins map[string]int
	localCallsCapped bool
	smFunctions      map[string]*machoSMFunctionState
	nstaskReceivers  map[string]*machoNSTaskReceiverState
	objcReturns      map[uint64]machoObjCReceiverValue
	dyldBindings     map[uint64]machoDyldBinding
	dyldAmbiguous    map[uint64]bool
	dyldIncomplete   bool
	sectionIndex     *machoSectionIndex
}

func newMachOCallLookup(graph *behavior.Graph, content artifact.Content, arch string) *machoCallLookup {
	lookup := &machoCallLookup{
		graph:            graph,
		content:          content,
		arch:             arch,
		features:         map[machoCallFeatureKey]*machoCallFeatureGroup{},
		evidence:         map[machoCallFeatureValueKey][]string{},
		scopes:           map[string]string{},
		operations:       map[machoCallOperationKey]bool{},
		localCalls:       map[machoCallPair]bool{},
		localCallOrigins: map[string]int{},
		smFunctions:      map[string]*machoSMFunctionState{},
		nstaskReceivers:  map[string]*machoNSTaskReceiverState{},
		objcReturns:      map[uint64]machoObjCReceiverValue{},
	}
	for _, scope := range graph.Scopes {
		if scope.NodeID == content.NodeID && scope.Kind == "function" && scope.Architecture == arch && scope.Function != "" {
			lookup.scopes[scope.Function] = scope.ID
		}
	}
	for _, feature := range graph.Features {
		lookup.recordFeature(feature)
	}
	for _, operation := range graph.Operations {
		lookup.recordOperation(operation)
	}
	return lookup
}

func (lookup *machoCallLookup) recordFeature(feature behavior.Feature) {
	if feature.NodeID != lookup.content.NodeID || feature.SourceFunction == "" || feature.Architecture != lookup.arch {
		return
	}
	key := machoCallFeatureKey{function: feature.SourceFunction, key: feature.Key}
	group := lookup.features[key]
	if group == nil {
		group = &machoCallFeatureGroup{values: map[string][]string{}}
		lookup.features[key] = group
	}
	group.values[feature.Value] = append(group.values[feature.Value], feature.EvidenceIDs...)
	valueKey := machoCallFeatureValueKey{function: feature.SourceFunction, key: feature.Key, value: feature.Value}
	lookup.evidence[valueKey] = append(lookup.evidence[valueKey], feature.EvidenceIDs...)

	switch feature.Key {
	case "macho.function_call":
		lookup.localCalls[machoCallPair{caller: feature.SourceFunction, callee: feature.Value}] = true
		lookup.localCallOrigins[feature.Qualifiers["function_origin"]]++
	case "objc.message_call":
		lookup.recordSMSelector(feature.SourceFunction, feature.Value, feature.EvidenceIDs)
	}
}

func (lookup *machoCallLookup) recordSMSelector(function, selector string, evidence []string) {
	state := lookup.smFunctions[function]
	if state == nil {
		state = &machoSMFunctionState{services: map[string]machoSMServiceState{}}
		lookup.smFunctions[function] = state
	}
	if isSMAppServiceRegisterSelector(selector) {
		return
	}
	kind, category, ok := smAppServiceFactoryOperation(selector)
	if !ok {
		return
	}
	service := state.services[category]
	service.kind = kind
	service.category = category
	service.bindsConcreteResource = service.bindsConcreteResource || smAppServiceSelectorBindsConcreteResource(selector)
	service.evidence = append(service.evidence, evidence...)
	state.services[category] = service
}

func (lookup *machoCallLookup) recordOperation(operation behavior.ModeledOperation) {
	if operation.SubjectNodeID != lookup.content.NodeID || operation.Architecture != lookup.arch || operation.SourceFunction == "" {
		return
	}
	lookup.operations[machoCallOperationKey{function: operation.SourceFunction, kind: operation.Kind, category: operationResourceCategory(operation)}] = true
}

func (lookup *machoCallLookup) addFeature(feature behavior.Feature) string {
	id := lookup.graph.AddFeature(feature)
	if id != "" {
		lookup.recordFeature(lookup.graph.Features[len(lookup.graph.Features)-1])
	}
	return id
}

func (lookup *machoCallLookup) addOperation(operation behavior.ModeledOperation) string {
	id := lookup.graph.AddOperation(operation)
	if id != "" {
		operation.ID = id
		lookup.recordOperation(operation)
	}
	return id
}

func (lookup *machoCallLookup) featureEvidence(function, key, value string) []string {
	return lookup.featureEvidenceBounded(function, key, value, -1)
}

func (lookup *machoCallLookup) featureEvidenceBounded(function, key, value string, evidenceLimit int) []string {
	return boundedEvidenceCopy(lookup.evidence[machoCallFeatureValueKey{function: function, key: key, value: value}], evidenceLimit)
}

func boundedEvidenceCopy(evidence []string, limit int) []string {
	if limit >= 0 && len(evidence) > limit {
		evidence = evidence[:limit]
	}
	return append([]string(nil), evidence...)
}

func serviceManagementResourceClassification(category string) behavior.ResourceClassification {
	if category == "plist-name" {
		return behavior.ResourceClassPlistName
	}
	return behavior.ResourceClassBundleIdentifier
}

func operationResourceCategory(operation behavior.ModeledOperation) string {
	for _, binding := range operation.ResourceBindings {
		for _, classification := range binding.Resource.Classifications {
			switch classification {
			case behavior.ResourceClassLaunchAgent:
				return "launch-agent"
			case behavior.ResourceClassLaunchDaemon:
				return "launch-daemon"
			}
		}
		if binding.Resource.Kind == behavior.ResourceLoginItem {
			return "login-item"
		}
	}
	return ""
}

func serviceOperationResource(category, value string) behavior.Resource {
	switch category {
	case "launch-agent":
		return behavior.NewResource(behavior.ResourceLaunchdJob, value, behavior.ResourceClassLaunchAgent)
	case "launch-daemon":
		return behavior.NewResource(behavior.ResourceLaunchdJob, value, behavior.ResourceClassLaunchDaemon)
	case "launchd-service":
		return behavior.NewResource(behavior.ResourceLaunchdJob, value)
	default:
		return behavior.NewResource(behavior.ResourceLoginItem, value)
	}
}

func (lookup *machoCallLookup) featureExists(function, key string) bool {
	group := lookup.features[machoCallFeatureKey{function: function, key: key}]
	return group != nil && len(group.values) > 0
}

func (lookup *machoCallLookup) sectionIndexFor(file *macho.File) *machoSectionIndex {
	if lookup.sectionIndex == nil {
		lookup.sectionIndex = newMachOSectionIndex(file)
	}
	return lookup.sectionIndex
}

func (lookup *machoCallLookup) functionScopeID(function machoFunction) string {
	if function.Name == "" {
		return ""
	}
	if id := lookup.scopes[function.Name]; id != "" {
		return id
	}
	id := lookup.graph.AddScope(behavior.Scope{
		NodeID:       lookup.content.NodeID,
		Kind:         "function",
		Name:         function.Name,
		SourceRole:   lookup.content.Role,
		Function:     function.Name,
		Architecture: lookup.arch,
	})
	if id != "" {
		lookup.scopes[function.Name] = id
	}
	return id
}

func extractFunctionStringXrefsIndexedWithRanges(lookup *machoCallLookup, file *macho.File, text *macho.Section, data []byte, functions []machoFunction, image []byte, dataRanges []machoCodeRange) int {
	graph := lookup.graph
	content := lookup.content
	arch := lookup.arch
	literals, literalsTruncated, cfBackingTruncated, cfTrailingBytes := interestingMachOStringLiterals(file, image)
	addMachOFunctionStringCoverage(graph, content.NodeID, arch, literalsTruncated, cfBackingTruncated, cfTrailingBytes)
	if len(literals) == 0 {
		return 0
	}
	index := newMachOStringLiteralIndex(literals)
	var xrefs []machoStringXref
	decoderIncomplete := false
	switch file.Cpu {
	case macho.CpuAmd64:
		xrefs, decoderIncomplete = x86StringXrefsIndexedBounded(file, lookup.sectionIndexFor(file), text.Addr, data, functions, index, dataRanges)
	case macho.CpuArm64:
		xrefs = arm64StringXrefsIndexedWithRanges(file, lookup.sectionIndexFor(file), text.Addr, data, functions, index, dataRanges)
	default:
		return 0
	}
	annotateMachOStringXrefOffsets(xrefs, text)
	if decoderIncomplete {
		addPartialCoverageOnce(graph, content.NodeID, "macho-x86-string-decode/"+arch, "x86_64 string-xref decoding stopped at the first undecodable instruction in each affected recovered function; no byte resynchronization was attempted")
	}
	if len(xrefs) >= maxMachOStringXrefs {
		graph.AddCoverage(behavior.Coverage{
			NodeID:       content.NodeID,
			AnalysisArea: "macho-function-string-xrefs/" + arch,
			Status:       "partial",
			Detail:       fmt.Sprintf("only the first %d function string references were retained", maxMachOStringXrefs),
		})
	}
	seen := map[string]bool{}
	for _, xref := range xrefs {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			break
		}
		key := fmt.Sprintf("%s\x00%x\x00%s\x00%s", xref.Function.Name, xref.RefVA, xref.Literal.Kind, xref.Literal.Value)
		if seen[key] {
			continue
		}
		seen[key] = true
		addMachOStringXrefIndexed(lookup, xref)
	}
	return len(seen)
}

func addMachOFunctionStringCoverage(graph *behavior.Graph, nodeID, arch string, literalsTruncated, cfBackingTruncated bool, cfTrailingBytes int) {
	details := make([]string, 0, 3)
	if literalsTruncated {
		details = append(details, fmt.Sprintf("function string candidates capped at %d literals, %d input bytes, %d ASCII runs, and %d captured bytes", maxMachOStringLiterals, maxMachOASCIIInputBytes, maxMachOASCIIStringRuns, maxMachOASCIIBytes))
	}
	if cfBackingTruncated {
		details = append(details, fmt.Sprintf("CFString backing reads capped at %d cumulative bytes", maxMachOCFStringBackingBytes))
	}
	if cfTrailingBytes > 0 {
		details = append(details, fmt.Sprintf("skipped %d trailing __cfstring bytes that did not form complete %d-byte object records", cfTrailingBytes, machOCFString64RecordSize))
	}
	if len(details) == 0 {
		return
	}
	graph.AddCoverage(behavior.Coverage{
		NodeID:       nodeID,
		AnalysisArea: "macho-function-strings/" + arch,
		Status:       "partial",
		Detail:       strings.Join(details, "; "),
	})
}

func annotateMachOStringXrefOffsets(xrefs []machoStringXref, text *macho.Section) {
	if text == nil {
		return
	}
	for index := range xrefs {
		if xrefs[index].RefVA < text.Addr {
			continue
		}
		delta := xrefs[index].RefVA - text.Addr
		if delta >= text.Size || delta > ^uint64(0)-uint64(text.Offset) {
			continue
		}
		offset := uint64(text.Offset) + delta
		if offset > uint64(^uint(0)>>1) {
			continue
		}
		xrefs[index].RefOffset = int(offset)
		xrefs[index].RefOffsetKnown = true
	}
}

func interestingMachOStringLiterals(file *macho.File, image []byte) ([]machoStringLiteral, bool, bool, int) {
	skipRanges := machoStringSkipRanges(file, len(image))
	seen := map[string]bool{}
	var out []machoStringLiteral
	budget := newASCIIRunBudget()
	literalsTruncated := false
	cfRecordsRemaining := maxMachOObjectiveCRecords
	cfTrailingBytes := 0
	seenSectionExtents := map[machoSectionExtent]bool{}
	sectionIndex := newMachOSectionIndex(file)
	cfReader := newMachOCFStringReader(sectionIndex, maxMachOCFStringBackingBytes)
	for _, section := range file.Sections {
		if len(out) >= maxMachOStringLiterals {
			literalsTruncated = true
			break
		}
		if section.Size == 0 || section.Seg == "__LINKEDIT" || section.Flags&machoSectionAttributeDebug != 0 {
			continue
		}
		if budget.scanBytesRemaining <= 0 {
			budget.truncated = true
			break
		}
		extent := machoSectionExtent{offset: section.Offset, size: section.Size}
		if seenSectionExtents[extent] {
			literalsTruncated = true
			continue
		}
		seenSectionExtents[extent] = true
		data, sectionTruncated, err := machoSectionPrefix(image, section, budget.scanBytesRemaining)
		literalsTruncated = literalsTruncated || sectionTruncated
		if err != nil {
			continue
		}
		for _, run := range budget.scan(data, 6) {
			fileOffset := int(section.Offset) + run.Offset
			if offsetInRanges(fileOffset, skipRanges) {
				continue
			}
			runVA := section.Addr + uint64(run.Offset)
			var truncated bool
			out, truncated = appendInterestingStringValueLiteralsBounded(out, seen, run.Value, runVA, fileOffset, 0)
			literalsTruncated = literalsTruncated || truncated
		}
		if section.Name == "__cfstring" {
			if cfRecordsRemaining <= 0 {
				literalsTruncated = true
				continue
			}
			sectionTrailingBytes := 0
			if !sectionTruncated && uint64(len(data)) == section.Size {
				sectionTrailingBytes = len(data) % machOCFString64RecordSize
			}
			maxCFBytes := cfRecordsRemaining * machOCFString64RecordSize
			if len(data) > maxCFBytes {
				data = data[:maxCFBytes]
				literalsTruncated = true
			}
			cfLiterals, truncated := cfStringLiteralsFromDataBounded(file.ByteOrder, section.Addr, int(section.Offset), data, cfReader.read)
			cfTrailingBytes += sectionTrailingBytes
			cfRecordsRemaining -= len(data) / machOCFString64RecordSize
			out = append(out, cfLiterals...)
			literalsTruncated = literalsTruncated || truncated
			if len(out) > maxMachOStringLiterals {
				out = out[:maxMachOStringLiterals]
				literalsTruncated = true
			}
		}
	}
	if len(out) >= maxMachOStringLiterals {
		literalsTruncated = true
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].VA != out[j].VA {
			return out[i].VA < out[j].VA
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out, budget.truncated || literalsTruncated, cfReader.truncated, cfTrailingBytes
}

func appendInterestingStringValueLiterals(out []machoStringLiteral, seen map[string]bool, value string, va uint64, offset, size int) []machoStringLiteral {
	out, _ = appendInterestingStringValueLiteralsBounded(out, seen, value, va, offset, size)
	return out
}

func appendInterestingStringValueLiteralsBounded(out []machoStringLiteral, seen map[string]bool, value string, va uint64, offset, size int) ([]machoStringLiteral, bool) {
	truncated := false
	if len(value) > maxMachOASCIIStringBytes {
		value = value[:maxMachOASCIIStringBytes]
		truncated = true
	}
	out = appendShellCommandStringLiteral(out, seen, value, va, offset, size)
	urlMatches, limited := limitedMachOStringMatches(reURL, value)
	truncated = truncated || limited
	for _, match := range urlMatches {
		urlValue, ok := normalizeStaticURL(value[match[0]:match[1]])
		if !ok {
			continue
		}
		literalVA := va + uint64(match[0])
		literalOffset := offset + match[0]
		literalSize := len(urlValue)
		if size > 0 {
			literalVA = va
			literalOffset = offset
			literalSize = size
		}
		out = appendUniqueStringLiteral(out, seen, machoStringLiteral{
			VA:     literalVA,
			Offset: literalOffset,
			Value:  urlValue,
			Kind:   "url",
			Size:   literalSize,
		})
	}
	ipMatches, limited := limitedMachOIPv4Matches(value)
	truncated = truncated || limited
	for _, match := range ipMatches {
		ipValue, _ := validatedIPv4Match(value, match)
		literalVA := va + uint64(match[0])
		literalOffset := offset + match[0]
		literalSize := len(ipValue)
		if size > 0 {
			literalVA = va
			literalOffset = offset
			literalSize = size
		}
		out = appendUniqueStringLiteral(out, seen, machoStringLiteral{
			VA:     literalVA,
			Offset: literalOffset,
			Value:  ipValue,
			Kind:   "ip",
			Size:   literalSize,
		})
	}
	out = appendSensitiveStringLiteralsWithSize(out, seen, value, va, offset, size)
	out = appendServiceManagementStringLiteral(out, seen, value, va, offset, size)
	applicationMatches, limited := limitedMachOApplicationPathMatches(value)
	truncated = truncated || limited
	for _, match := range applicationMatches {
		literalVA := va + uint64(match[0])
		literalOffset := offset + match[0]
		if size > 0 {
			literalVA = va
			literalOffset = offset
		}
		out = appendProcessLaunchPathLiteral(out, seen, value[match[0]:match[1]], literalVA, literalOffset, size)
	}
	pathMatches, limited := limitedMachOStringMatches(rePath, value)
	truncated = truncated || limited
	for _, match := range pathMatches {
		literalVA := va + uint64(match[0])
		literalOffset := offset + match[0]
		if size > 0 {
			literalVA = va
			literalOffset = offset
		}
		out = appendSensitiveStringLiteralsWithSize(out, seen, value[match[0]:match[1]], literalVA, literalOffset, size)
		out = appendProcessLaunchPathLiteral(out, seen, value[match[0]:match[1]], literalVA, literalOffset, size)
	}
	return out, truncated
}

func cfStringLiteralsFromData(order binary.ByteOrder, sectionVA uint64, sectionOffset int, data []byte, readString func(uint64, uint64) (string, uint64, int, bool)) []machoStringLiteral {
	out, _ := cfStringLiteralsFromDataBounded(order, sectionVA, sectionOffset, data, readString)
	return out
}

func cfStringLiteralsFromDataBounded(order binary.ByteOrder, sectionVA uint64, sectionOffset int, data []byte, readString func(uint64, uint64) (string, uint64, int, bool)) ([]machoStringLiteral, bool) {
	var out []machoStringLiteral
	truncated := false
	for offset := 0; offset+machOCFString64RecordSize <= len(data); offset += machOCFString64RecordSize {
		if offset/machOCFString64RecordSize >= maxMachOObjectiveCRecords || len(out) >= maxMachOStringLiterals {
			truncated = true
			break
		}
		pointer := order.Uint64(data[offset+16 : offset+24])
		length := order.Uint64(data[offset+24 : offset+32])
		value, valueVA, valueOffset, ok := readString(pointer, length)
		if !ok || value == "" {
			continue
		}
		// Equal values in distinct CFString objects need distinct object VAs so
		// scoped xrefs to either record preserve exact lineage. Deduplicate only
		// multiple matches produced inside this one backing value.
		seen := map[string]bool{}
		start := len(out)
		var limited bool
		out, limited = appendInterestingStringValueLiteralsBounded(out, seen, value, sectionVA+uint64(offset), sectionOffset+offset, machOCFString64RecordSize)
		for index := start; index < len(out); index++ {
			relative := strings.Index(value, out[index].Value)
			if relative < 0 || valueOffset < 0 || uint64(relative) > ^uint64(0)-valueVA || relative > int(^uint(0)>>1)-valueOffset {
				continue
			}
			out[index].ValueVA = valueVA + uint64(relative)
			out[index].ValueOffset = valueOffset + relative
			out[index].ValueLocationKnown = true
		}
		truncated = truncated || limited
	}
	return out, truncated
}

func appendSensitiveStringLiteralsWithSize(out []machoStringLiteral, seen map[string]bool, value string, va uint64, offset, size int) []machoStringLiteral {
	resource, ok := sensitiveResource(value)
	if !ok {
		return out
	}
	if size == 0 && !plausibleMachOSensitiveResourceValue(resource.Value) {
		return out
	}
	literalSize := len(resource.Value)
	if size > 0 {
		literalSize = size
	}
	return appendUniqueStringLiteral(out, seen, machoStringLiteral{
		VA:       va,
		Offset:   offset,
		Value:    resource.Value,
		Kind:     "sensitive-resource",
		Resource: resource,
		Size:     literalSize,
	})
}

func plausibleMachOSensitiveResourceValue(value string) bool {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" || len(value) > 512 || strings.Contains(value, "://") || strings.ContainsAny(value, "()[]{}<>|%") {
		return false
	}
	lower := strings.ToLower(value)
	pathShaped := strings.HasPrefix(value, "~/") || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "$HOME/") || strings.HasPrefix(value, "${HOME}/") || strings.HasPrefix(lower, "library/") || strings.HasPrefix(lower, "group containers/") || strings.HasPrefix(value, ".")
	if !pathShaped {
		return false
	}
	if index := strings.Index(lower, "/library/"); index >= 0 {
		prefix := strings.TrimSuffix(lower[:index], "/")
		validHome := prefix == "~" || prefix == "$home" || prefix == "${home}" || prefix == "/private/var/root" || prefix == "/var/root"
		if strings.HasPrefix(prefix, "/users/") {
			rest := strings.TrimPrefix(prefix, "/users/")
			validHome = rest != "" && !strings.Contains(rest, "/")
		}
		if !validHome {
			return false
		}
	}
	return true
}

func appendUniqueStringLiteral(out []machoStringLiteral, seen map[string]bool, literal machoStringLiteral) []machoStringLiteral {
	if len(out) >= maxMachOStringLiterals {
		return out
	}
	key := fmt.Sprintf("%x\x00%s\x00%s", literal.VA, literal.Kind, literal.Value)
	if seen[key] {
		return out
	}
	seen[key] = true
	return append(out, literal)
}

func appendServiceManagementStringLiteral(out []machoStringLiteral, seen map[string]bool, value string, va uint64, offset, size int) []machoStringLiteral {
	value = strings.TrimSpace(value)
	if !looksServiceManagementResource(value) {
		return out
	}
	category := serviceManagementLiteralCategory(value)
	literalSize := len(value)
	if size > 0 {
		literalSize = size
	}
	return appendUniqueStringLiteral(out, seen, machoStringLiteral{
		VA:       va,
		Offset:   offset,
		Value:    value,
		Kind:     "service-management-resource",
		Resource: behavior.NewResource(behavior.ResourceIdentifier, value, serviceManagementResourceClassification(category)),
		Size:     literalSize,
	})
}

func serviceManagementLiteralCategory(value string) string {
	if strings.HasSuffix(strings.ToLower(value), ".plist") {
		return "plist-name"
	}
	return "bundle-id"
}

func looksServiceManagementResource(value string) bool {
	if len(value) < 6 || len(value) > 255 || strings.Contains(value, "://") || strings.ContainsAny(value, "/\\") {
		return false
	}
	if _, ok := normalizeMachOIP(value); ok {
		return false
	}
	allowUnderscore := strings.HasSuffix(strings.ToLower(value), ".plist")
	stem := value
	if allowUnderscore {
		stem = stem[:len(stem)-len(".plist")]
	}
	labels := strings.Split(stem, ".")
	if len(labels) < 3 {
		return false
	}
	// SMAppService resources use reverse-DNS-style bundle identifiers or
	// bundled plist names. Requiring a lowercase DNS root and well-formed
	// labels keeps unrelated dotted constants (for example sysctl keys) from
	// becoming service-management resources merely because they contain dots.
	root := labels[0]
	if root == "" || root[0] < 'a' || root[0] > 'z' {
		return false
	}
	for index, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || label[0] == '_' || label[len(label)-1] == '_' {
			return false
		}
		for _, r := range label {
			if index == 0 && r >= 'A' && r <= 'Z' {
				return false
			}
			if r == '-' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || allowUnderscore && index > 0 && r == '_' {
				continue
			}
			return false
		}
	}
	return true
}

// limitedMachOApplicationPathMatches recovers complete application paths from
// printable data runs. The generic path expression intentionally stops at
// whitespace, which would otherwise turn a valid path such as
// "/Applications/Google Chrome.app/" into the misleading executable-looking
// prefix "/Applications/Google".
func limitedMachOApplicationPathMatches(value string) ([][]int, bool) {
	lower := strings.ToLower(value)
	var matches [][]int
	cursor := 0
	for cursor < len(value) {
		start := nextMachOApplicationPathStart(lower, cursor)
		if start < 0 {
			break
		}
		end, ok := machoApplicationPathEnd(value, lower, start)
		if !ok {
			cursor = start + 1
			continue
		}
		if len(matches) >= maxMachORegexMatches {
			return matches, true
		}
		matches = append(matches, []int{start, end})
		cursor = end
	}
	return matches, false
}

func nextMachOApplicationPathStart(lower string, cursor int) int {
	best := -1
	for _, prefix := range []string{"/applications/", "/system/applications/"} {
		if relative := strings.Index(lower[cursor:], prefix); relative >= 0 {
			candidate := cursor + relative
			if best < 0 || candidate < best {
				best = candidate
			}
		}
	}
	return best
}

func machoApplicationPathEnd(value, lower string, start int) (int, bool) {
	root := "/applications/"
	if strings.HasPrefix(lower[start:], "/system/applications/") {
		root = "/system/applications/"
	} else if !strings.HasPrefix(lower[start:], root) {
		return 0, false
	}
	nameStart := start + len(root)
	appRelative := strings.Index(lower[nameStart:], ".app")
	if appRelative < 1 {
		return 0, false
	}
	appEnd := nameStart + appRelative + len(".app")
	for _, b := range []byte(value[nameStart : appEnd-len(".app")]) {
		if !machOApplicationNameByte(b) {
			return 0, false
		}
	}
	if appEnd == len(value) || machOStringLiteralBoundary(value[appEnd]) {
		return appEnd, true
	}
	if value[appEnd] != '/' {
		return 0, false
	}
	rootPathEnd := appEnd + 1
	if rootPathEnd == len(value) || machOStringLiteralBoundary(value[rootPathEnd]) {
		return rootPathEnd, true
	}
	const executableMarker = "contents/macos/"
	if !strings.HasPrefix(lower[rootPathEnd:], executableMarker) {
		return 0, false
	}
	executableStart := rootPathEnd + len(executableMarker)
	if executableStart >= len(value) {
		return 0, false
	}
	bundleName := value[nameStart : appEnd-len(".app")]
	if strings.HasPrefix(value[executableStart:], bundleName) {
		bundleEnd := executableStart + len(bundleName)
		if bundleEnd == len(value) || machOStringLiteralHardBoundary(value[bundleEnd]) {
			return bundleEnd, true
		}
	}
	end := executableStart
	for end < len(value) && !machOStringLiteralHardBoundary(value[end]) {
		if value[end] == '/' {
			return 0, false
		}
		end++
	}
	for end > executableStart && value[end-1] == ' ' {
		end--
	}
	if end == executableStart {
		return 0, false
	}
	return end, true
}

func machOApplicationNameByte(value byte) bool {
	return value == ' ' || value == '-' || value == '_' || value == '+' || value == '@' || value == '&' || value == '(' || value == ')' || value == '.' ||
		value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func machOStringLiteralBoundary(value byte) bool {
	switch value {
	case 0, ' ', '\t', '\r', '\n', '\'', '"', '`', ',', ';', ':', ')', ']', '}', '>':
		return true
	default:
		return false
	}
}

func machOStringLiteralHardBoundary(value byte) bool {
	if value == '$' {
		return true
	}
	return value != ' ' && machOStringLiteralBoundary(value)
}

func appendShellCommandStringLiteral(out []machoStringLiteral, seen map[string]bool, value string, va uint64, offset, size int) []machoStringLiteral {
	if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
		return out
	}
	value = strings.TrimSpace(value)
	if !looksShellCommandLiteral(value) {
		return out
	}
	literalSize := len(value)
	if size > 0 {
		literalSize = size
	}
	return appendUniqueStringLiteral(out, seen, machoStringLiteral{
		VA:     va,
		Offset: offset,
		Value:  value,
		Kind:   "shell-command",
		Size:   literalSize,
	})
}

func looksShellCommandLiteral(value string) bool {
	if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	value = strings.TrimSpace(value)
	if value == "pbpaste" || value == "pbcopy" {
		return true
	}
	if len(value) < 8 {
		return false
	}
	fields, hasOperator, ok := machOShellCommandGrammar(value)
	if !ok {
		return false
	}
	tool := shellBase(fields[0])
	if len(fields) >= 3 && (tool == "sh" || tool == "bash" || tool == "zsh") && (fields[1] == "-c" || fields[1] == "--command") {
		return true
	}
	if strings.Contains(value, "://") && (tool == "curl" || tool == "wget" || tool == "osascript" || tool == "open") {
		return true
	}
	if hasOperator {
		return true
	}
	if sideEffectfulShellTool(tool) && len(fields) >= 2 {
		// "base64" is also common in Rust/library prose (for example error
		// messages beginning "base64 is always valid"). Without an operator,
		// option, or path-shaped operand, that text is not strong enough to call
		// an executable command literal.
		if tool == "base64" && !plausibleBase64CommandOperands(fields[1:]) {
			return false
		}
		return true
	}
	return false
}

func plausibleBase64CommandOperands(fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	// Inspect the first operand only. Looking for punctuation anywhere in the
	// remainder lets a long prose/error string become command-shaped merely
	// because a later sentence contains a Rust path or method name.
	field := fields[0]
	return strings.HasPrefix(field, "-") || strings.ContainsAny(field, `/.$=~%`)
}

const (
	// A native command candidate is already bounded to 4096 bytes above. Keep
	// its lightweight grammar view much smaller than the general shell parser's
	// limits: real system(3)/popen(3) literals are compact, while Rust string
	// tables commonly concatenate many unrelated crate strings without NULs.
	maxMachOShellCommandParts  = 32
	maxMachOShellCommandFields = 128
)

// machOShellCommandGrammar validates the complete printable run instead of
// accepting it merely because it begins with an executable-looking path and
// contains a '|', ';', or '&' somewhere later. That latter pattern is common
// in Rust/Tauri length-delimited string tables (for example a .cargo source
// path concatenated with Rust type text containing &str).
func machOShellCommandGrammar(value string) ([]string, bool, bool) {
	if _, _, _, malformed := shellSubstitutionStatus(value); malformed {
		return nil, false, false
	}
	background := false
	if foreground, ok := stripTerminalBackgroundOperator(value); ok {
		value = foreground
		background = true
	}
	malformed, unsupportedPipeBoth, unsupportedBackground, unsupportedBraceGroup := shellTopLevelOperatorStatus(value)
	if malformed || unsupportedPipeBoth || unsupportedBackground || unsupportedBraceGroup {
		return nil, false, false
	}

	var firstFields []string
	parts := 0
	fieldsSeen := 0
	valid := true
	visitCommands(value, func(command string) bool {
		pipeline, truncated := splitPipelineLimited(command, maxMachOShellCommandParts-parts)
		if truncated || len(pipeline) == 0 {
			valid = false
			return false
		}
		for _, part := range pipeline {
			parts++
			if parts > maxMachOShellCommandParts {
				valid = false
				return false
			}
			fields, err := shellCommandFields(strings.TrimSpace(part))
			if err != nil {
				valid = false
				return false
			}
			fields, err = normalizeCommandFieldsChecked(fields)
			if err != nil || len(fields) == 0 {
				valid = false
				return false
			}
			fieldsSeen += len(fields)
			if fieldsSeen > maxMachOShellCommandFields {
				valid = false
				return false
			}
			tool := shellBase(fields[0])
			if !commonShellTool(tool) && !looksExecutable(fields[0]) {
				valid = false
				return false
			}
			if firstFields == nil {
				firstFields = fields
			}
		}
		return true
	})
	if !valid || len(firstFields) == 0 {
		return nil, false, false
	}
	return firstFields, background || parts > 1, true
}

func sideEffectfulShellTool(tool string) bool {
	switch tool {
	case "chmod", "chown", "xattr", "spctl", "launchctl", "defaults", "plutil", "osascript",
		"security", "dscl", "ditto", "zip", "unzip", "tar", "base64", "hdiutil", "installer",
		"pkgutil", "killall", "pkill", "rm", "mv", "cp", "sqlite3", "screencapture", "pbpaste", "pbcopy", "SetFile", "chflags", "tccutil":
		return true
	default:
		return false
	}
}

func appendProcessLaunchPathLiteral(out []machoStringLiteral, seen map[string]bool, value string, va uint64, offset, size int) []machoStringLiteral {
	value = normalizeProcessLaunchPath(value)
	if !looksProcessLaunchPath(value) {
		return out
	}
	literalSize := len(value)
	if size > 0 {
		literalSize = size
	}
	return appendUniqueStringLiteral(out, seen, machoStringLiteral{
		VA:       va,
		Offset:   offset,
		Value:    value,
		Kind:     "process-launch-path",
		Resource: behavior.NewResource(behavior.ResourceFile, value),
		Size:     literalSize,
	})
}

func looksProcessLaunchPath(value string) bool {
	value = normalizeProcessLaunchPath(value)
	if value == "" || strings.Contains(value, "://") {
		return false
	}
	// A literal command may start with an absolute executable path, but the
	// complete command is not itself a process path. Command expansion retains
	// the executable and its effects separately when the call site supports it.
	if looksShellCommandLiteral(value) {
		return false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "/applications/") || strings.HasPrefix(lower, "/system/applications/") {
		return looksApplicationLaunchPath(value)
	}
	if strings.ContainsAny(value, " \t") && !looksSpacedApplicationExecutablePath(value) {
		return false
	}
	trimmed := strings.TrimRight(value, `"'`)
	base := filepath.Base(trimmed)
	ext := strings.ToLower(filepath.Ext(trimmed))
	// filepath.Ext(".payload") is ".payload", but a single leading dot is
	// a hidden extensionless filename, not a data-file suffix.
	if strings.HasPrefix(base, ".") && strings.Count(base, ".") == 1 {
		ext = ""
	}
	if obviousNonExecutableExtension(ext) {
		return false
	}
	if strings.HasPrefix(lower, "/bin/") {
		return looksCanonicalMacOSBinExecutable(value)
	}
	for _, prefix := range []string{
		"/sbin/",
		"/usr/bin/",
		"/usr/sbin/",
		"/usr/local/bin/",
		"/opt/homebrew/bin/",
	} {
		if strings.HasPrefix(lower, prefix) {
			// These are flat executable directories. A later slash usually
			// means a length-delimited binary string pool concatenated an
			// executable spelling with an unrelated source or build path.
			// Reject the whole unproved literal instead of truncating it into
			// a concrete executable that the binary may never reference.
			name := value[len(prefix):]
			return name != "" && !strings.ContainsAny(name, "/\r\n\t ")
		}
	}
	// Temporary directories commonly contain command output, configuration,
	// archives, and screenshots alongside executable payloads. Treating every
	// absolute /tmp path as an executable lets an unrelated system()/exec call
	// inherit a concrete data-file path from the same function. Keep extensionless
	// payloads and common script/binary suffixes, but leave obvious data files as
	// ordinary strings.
	if strings.HasPrefix(lower, "/tmp/") || strings.HasPrefix(lower, "/private/tmp/") || strings.HasPrefix(lower, "/var/tmp/") {
		if ext != "" && !temporaryExecutableExtension(ext) {
			return false
		}
	}
	for _, prefix := range []string{
		"/tmp/",
		"/private/tmp/",
		"/var/tmp/",
	} {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) && !strings.HasSuffix(value, "/") {
			return true
		}
	}
	return false
}

func looksApplicationLaunchPath(value string) bool {
	lower := strings.ToLower(value)
	root := "/applications/"
	if strings.HasPrefix(lower, "/system/applications/") {
		root = "/system/applications/"
	} else if !strings.HasPrefix(lower, root) {
		return false
	}
	appRelative := strings.Index(lower[len(root):], ".app")
	if appRelative < 1 {
		return false
	}
	appEnd := len(root) + appRelative + len(".app")
	if appEnd == len(value) || appEnd+1 == len(value) && value[appEnd] == '/' {
		return true
	}
	const executableMarker = "/contents/macos/"
	if !strings.HasPrefix(lower[appEnd:], executableMarker) {
		return false
	}
	executable := value[appEnd+len(executableMarker):]
	if executable == "" || strings.ContainsAny(executable, "/\t\r\n") {
		return false
	}
	if strings.Contains(executable, " ") {
		return looksSpacedApplicationExecutablePath(value)
	}
	return true
}

func looksCanonicalMacOSBinExecutable(value string) bool {
	if strings.Contains(value[len("/bin/"):], "/") {
		return false
	}
	switch filepath.Base(value) {
	case "[", "bash", "cat", "chmod", "cp", "csh", "date", "dd", "df", "echo", "ed", "expr", "hostname", "kill", "ksh", "launchctl", "link", "ln", "ls", "mkdir", "mv", "pax", "ps", "pwd", "rm", "rmdir", "sh", "sleep", "stty", "sync", "tcsh", "test", "unlink", "wait4path", "zsh":
		return true
	default:
		return false
	}
}

func looksSpacedApplicationExecutablePath(value string) bool {
	lower := strings.ToLower(value)
	if !strings.HasPrefix(lower, "/applications/") && !strings.HasPrefix(lower, "/system/applications/") {
		return false
	}
	const marker = ".app/contents/macos/"
	markerIndex := strings.LastIndex(lower, marker)
	if markerIndex < 0 {
		return false
	}
	executable := value[markerIndex+len(marker):]
	if executable == "" || strings.ContainsAny(executable, "/\t") {
		return false
	}
	if !strings.Contains(executable, " ") {
		// Spaces occur only in the application/bundle path.
		return true
	}
	bundlePath := value[:markerIndex]
	if slash := strings.LastIndexByte(bundlePath, '/'); slash >= 0 {
		bundlePath = bundlePath[slash+1:]
	}
	// Preserve the common convention where a spaced executable name matches
	// its .app bundle name, while rejecting an executable followed by argv.
	return executable == bundlePath
}

func normalizeProcessLaunchPath(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.IndexAny(value, "\x00\r\n\t<>"); index >= 0 {
		value = value[:index]
	}
	value = strings.TrimRight(strings.TrimSpace(value), `"'`)
	return trimPackedAbsolutePathSuffix(value)
}

// Rust and other length-delimited string pools can place absolute path
// literals directly next to one another without a NUL byte. The generic ASCII
// run then looks like a single syntactically valid path. When a temporary path
// runs directly into a distinctive second macOS root, retain the first path
// rather than reporting the concatenation as a concrete executable spelling.
func trimPackedAbsolutePathSuffix(value string) string {
	lower := strings.ToLower(value)
	start := 0
	switch {
	case strings.HasPrefix(lower, "/private/tmp/"):
		start = len("/private/tmp/")
	case strings.HasPrefix(lower, "/var/tmp/"):
		start = len("/var/tmp/")
	case strings.HasPrefix(lower, "/tmp/"):
		start = len("/tmp/")
	default:
		return value
	}
	for _, prefix := range []string{
		"/applications/", "/system/", "/library/", "/users/", "/private/tmp/", "/tmp/",
		"/usr/bin/", "/usr/sbin/", "/usr/local/", "/bin/", "/sbin/",
		"/var/at/", "/var/db/", "/var/folders/", "/var/run/", "/var/tmp/",
	} {
		if relative := strings.Index(lower[start:], prefix); relative >= 0 {
			end := start + relative
			if end > 0 && end < len(value) {
				value = value[:end]
				lower = lower[:end]
			}
		}
	}
	return strings.TrimRight(value, "/")
}

func obviousNonExecutableExtension(ext string) bool {
	switch ext {
	case ".7z", ".bmp", ".bz2", ".cer", ".cfg", ".conf", ".crt", ".csv", ".db", ".der", ".dmg",
		".gif", ".gz", ".htm", ".html", ".icns", ".ico", ".ini", ".jpeg", ".jpg", ".json", ".log",
		".pdf", ".pem", ".pkg", ".plist", ".png", ".rar", ".sqlite", ".sqlite3", ".tar", ".tif", ".tiff",
		".toml", ".txt", ".xml", ".xz", ".yaml", ".yml", ".zip":
		return true
	default:
		return false
	}
}

func temporaryExecutableExtension(ext string) bool {
	switch ext {
	case ".app", ".bin", ".command", ".js", ".jxa", ".out", ".pl", ".py", ".rb", ".scpt", ".sh", ".tool":
		return true
	default:
		return false
	}
}

func addMachOStringXref(graph *behavior.Graph, content artifact.Content, arch string, xref machoStringXref) {
	addMachOStringXrefIndexed(newMachOCallLookup(graph, content, arch), xref)
}

// addMachOStringXrefEvidence keeps the reference instruction and referenced
// literal as two locations. Combining an instruction VA with a literal byte
// offset in one Evidence record would describe a location that does not exist.
func addMachOStringXrefEvidence(lookup *machoCallLookup, xref machoStringXref, xrefKind, literalKind, displayedValue string) []string {
	literalVA := xref.Literal.VA
	literalOffset := xref.Literal.Offset
	if xref.Literal.ValueLocationKnown {
		literalVA = xref.Literal.ValueVA
		literalOffset = xref.Literal.ValueOffset
	}
	targetEvidence := machOEvidenceAt(lookup.content, literalOffset, behavior.Evidence{
		NodeID:  lookup.content.NodeID,
		Logical: lookup.content.LogicalPath,
		VA:      literalVA,
		Arch:    lookup.arch,
		Method:  "macho-literal",
		Kind:    literalKind,
		Value:   displayedValue,
	})
	targetID := lookup.graph.AddEvidence(targetEvidence)
	if targetID == "" {
		lookup.graph.MarkWorkOmitted()
		return nil
	}

	scopeID := lookup.functionScopeID(xref.Function)
	referenceEvidence := behavior.Evidence{
		NodeID:   lookup.content.NodeID,
		ScopeID:  scopeID,
		Logical:  lookup.content.LogicalPath,
		VA:       xref.RefVA,
		Function: xref.Function.Name,
		Arch:     lookup.arch,
		Method:   "macho-xref",
		Kind:     xrefKind,
		Value:    xref.Function.Name + " -> " + displayedValue,
	}
	if xref.RefOffsetKnown {
		referenceEvidence = machOEvidenceAt(lookup.content, xref.RefOffset, referenceEvidence)
	}
	referenceID := lookup.graph.AddEvidence(referenceEvidence)
	if referenceID == "" {
		lookup.graph.MarkWorkOmitted()
		return nil
	}
	return []string{referenceID, targetID}
}

func machoSectionFileOffsetForVA(index *machoSectionIndex, va uint64) (int, bool) {
	if index == nil {
		return 0, false
	}
	section := index.containing(va, 1)
	if section == nil || va < section.Addr {
		return 0, false
	}
	delta := va - section.Addr
	if delta > ^uint64(0)-uint64(section.Offset) {
		return 0, false
	}
	offset := uint64(section.Offset) + delta
	if offset > uint64(^uint(0)>>1) {
		return 0, false
	}
	return int(offset), true
}

func addMachOStringXrefIndexed(lookup *machoCallLookup, xref machoStringXref) {
	content := lookup.content
	arch := lookup.arch
	if xref.Literal.Kind == "service-management-resource" {
		// A dotted string xref does not prove that it is the argument to an
		// SMAppService factory. Do not retain correlation state that could later
		// be mistaken for exact argument provenance.
		return
	}
	scopeID := lookup.functionScopeID(xref.Function)
	switch xref.Literal.Kind {
	case "url":
		evidence := addMachOStringXrefEvidence(lookup, xref, "url-xref", "url-literal", xref.Literal.Value)
		if len(evidence) != 2 {
			return
		}
		lookup.addFeature(behavior.Feature{
			NodeID:         content.NodeID,
			ScopeID:        scopeID,
			Architecture:   arch,
			Key:            "network.url",
			Value:          xref.Literal.Value,
			EvidenceIDs:    evidence,
			Support:        behavior.SupportCorroborated,
			Execution:      executionContextForMachOFunction(content, xref.Function),
			SourceFunction: xref.Function.Name,
			Qualifiers:     machoFunctionQualifiers(xref.Function, map[string]string{"function": xref.Function.Name, "xref": "true"}),
		})
	case "ip":
		evidence := addMachOStringXrefEvidence(lookup, xref, "ip-xref", "ip-literal", xref.Literal.Value)
		if len(evidence) != 2 {
			return
		}
		lookup.addFeature(behavior.Feature{
			NodeID:         content.NodeID,
			ScopeID:        scopeID,
			Architecture:   arch,
			Key:            "network.ip",
			Value:          xref.Literal.Value,
			EvidenceIDs:    evidence,
			Support:        behavior.SupportHeuristic,
			Execution:      executionContextForMachOFunction(content, xref.Function),
			SourceFunction: xref.Function.Name,
			Qualifiers:     machoFunctionQualifiers(xref.Function, map[string]string{"function": xref.Function.Name, "xref": "true"}),
		})
	case "shell-command":
		evidence := addMachOStringXrefEvidence(lookup, xref, "shell-command-xref", "shell-command-literal", evidenceSnippet(xref.Literal.Value))
		if len(evidence) != 2 {
			return
		}
		lookup.addFeature(behavior.Feature{
			NodeID:         content.NodeID,
			ScopeID:        scopeID,
			Architecture:   arch,
			Key:            "macho.shell_command",
			Value:          xref.Literal.Value,
			EvidenceIDs:    evidence,
			Support:        behavior.SupportCorroborated,
			Execution:      executionContextForMachOFunction(content, xref.Function),
			SourceFunction: xref.Function.Name,
			Qualifiers:     machoFunctionQualifiers(xref.Function, map[string]string{"function": xref.Function.Name, "xref": "true"}),
		})
	case "sensitive-resource":
		evidence := addMachOStringXrefEvidence(lookup, xref, "sensitive-resource-xref", "sensitive-resource-literal", xref.Literal.Resource.Value)
		if len(evidence) != 2 {
			return
		}
		lookup.addFeature(behavior.Feature{
			NodeID:         content.NodeID,
			ScopeID:        scopeID,
			Architecture:   arch,
			Key:            "macho.sensitive_resource",
			Value:          xref.Literal.Resource.Value,
			EvidenceIDs:    evidence,
			Support:        behavior.SupportCorroborated,
			Execution:      executionContextForMachOFunction(content, xref.Function),
			SourceFunction: xref.Function.Name,
			Qualifiers: machoFunctionQualifiers(xref.Function, map[string]string{
				"category": sensitiveResourceFeatureCategory(xref.Literal.Resource),
				"function": xref.Function.Name,
				"xref":     "true",
			}),
		})
	case "process-launch-path":
		evidence := addMachOStringXrefEvidence(lookup, xref, "process-launch-path-xref", "process-launch-path-literal", xref.Literal.Value)
		if len(evidence) != 2 {
			return
		}
		lookup.addFeature(behavior.Feature{
			NodeID:         content.NodeID,
			ScopeID:        scopeID,
			Architecture:   arch,
			Key:            "macho.process_launch_path",
			Value:          xref.Literal.Value,
			EvidenceIDs:    evidence,
			Support:        behavior.SupportCorroborated,
			Execution:      executionContextForMachOFunction(content, xref.Function),
			SourceFunction: xref.Function.Name,
			Qualifiers: machoFunctionQualifiers(xref.Function, map[string]string{
				"function": xref.Function.Name,
				"xref":     "true",
			}),
		})
	}
}

func x86StringXrefs(file *macho.File, textAddr uint64, data []byte, functions []machoFunction, literals []machoStringLiteral) []machoStringXref {
	return x86StringXrefsIndexed(file, newMachOSectionIndex(file), textAddr, data, functions, newMachOStringLiteralIndex(literals))
}

func x86StringXrefsIndexed(file *macho.File, sections *machoSectionIndex, textAddr uint64, data []byte, functions []machoFunction, literals machoStringLiteralIndex) []machoStringXref {
	out, _ := x86StringXrefsIndexedBounded(file, sections, textAddr, data, functions, literals, nil)
	return out
}

func x86StringXrefsIndexedBounded(file *macho.File, sections *machoSectionIndex, textAddr uint64, data []byte, functions []machoFunction, literals machoStringLiteralIndex, dataRanges []machoCodeRange) ([]machoStringXref, bool) {
	var out []machoStringXref
	incomplete := false
	addressRegisters := map[uint8]x86AddressValue{}
	currentFunction := -2
	for i := 0; i < len(data); {
		va := textAddr + uint64(i)
		if functionIndex := functionIndexForSequentialVA(functions, currentFunction, va); functionIndex != currentFunction {
			clearX86AddressState(addressRegisters)
			currentFunction = functionIndex
		}
		if dataRange, excluded := machoCodeRangeContaining(i, dataRanges); excluded {
			clearX86AddressState(addressRegisters)
			i = dataRange.end
			continue
		}
		inst, err := decodeX86Instruction(x86DecodeInput(data, textAddr, i, functions, dataRanges))
		if err != nil || inst.Len <= 0 || inst.Op == 0 {
			incomplete = true
			clearX86AddressState(addressRegisters)
			i = x86DecodeFailureResumeOffset(textAddr, i, len(data), functions)
			continue
		}
		next, excluded := machoCodeInstructionExcluded(i, inst.Len, dataRanges)
		if excluded {
			clearX86AddressState(addressRegisters)
			i = next
			continue
		}
		instruction := data[i : i+inst.Len]
		if target, reg, size, loadsMemory, ok := x86RIPRelativeTargetAndReg(va, instruction); ok && size == inst.Len {
			if !loadsMemory {
				addressRegisters[reg] = x86AddressValue{value: target, instruction: i}
			} else {
				delete(addressRegisters, reg)
			}
			if literal, ok := stringLiteralForX86TargetIndexed(file, sections, literals, target, loadsMemory); ok {
				out = appendMachOStringXrefForIndex(out, functions, currentFunction, va, literal)
			}
			i += inst.Len
			continue
		}
		if target, dst, base, size, loadsMemory, ok := x86BaseRelativeTargetAndReg(instruction, addressRegisters); ok && size == inst.Len {
			baseFresh := true
			if baseValue, ok := addressRegisters[base]; ok && i-baseValue.instruction > x86AddressStateWindow {
				baseFresh = false
				delete(addressRegisters, base)
			}
			if baseFresh {
				if literal, ok := stringLiteralForX86TargetIndexed(file, sections, literals, target, loadsMemory); ok {
					out = appendMachOStringXrefForIndex(out, functions, currentFunction, va, literal)
				}
			}
			if baseFresh && !loadsMemory {
				addressRegisters[dst] = x86AddressValue{value: target, instruction: i}
			} else {
				delete(addressRegisters, dst)
			}
			i += inst.Len
			continue
		}
		if dst, src, size, ok := x86RegisterMove(instruction); ok && size == inst.Len {
			copyX86AddressState(addressRegisters, dst, src, i)
			i += inst.Len
			continue
		}
		if reg, size, ok := x86RegisterWrite(instruction); ok && size == inst.Len {
			delete(addressRegisters, reg)
			i += inst.Len
			continue
		}
		// Unknown decoded semantics never preserve inferred register values.
		// We still advance by the decoder-established instruction boundary.
		clearX86AddressState(addressRegisters)
		i += inst.Len
	}
	return out, incomplete
}

func x86DecodeFailureResumeOffset(textAddr uint64, offset, dataLength int, functions []machoFunction) int {
	va := textAddr + uint64(offset)
	if functionIndex := functionIndexForVA(functions, va); functionIndex >= 0 {
		end := functions[functionIndex].End
		if end > va && end-textAddr <= uint64(dataLength) {
			return int(end - textAddr)
		}
	}
	for _, function := range functions {
		if function.Start > va && function.Start-textAddr <= uint64(dataLength) {
			return int(function.Start - textAddr)
		}
	}
	return dataLength
}

type x86AddressValue struct {
	value       uint64
	instruction int
}

func decodeX86Instruction(data []byte) (inst x86asm.Inst, err error) {
	// The decoder is applied to hostile bytes. Keep a recovery boundary even
	// though x86asm normally reports malformed input as an error; this prevents
	// a decoder bug from becoming a scanner crash.
	defer func() {
		if recovered := recover(); recovered != nil {
			inst = x86asm.Inst{}
			err = fmt.Errorf("x86 decoder panic: %v", recovered)
		}
	}()
	return x86asm.Decode(data, 64)
}

func x86DecodeInput(data []byte, textAddr uint64, offset int, functions []machoFunction, dataRanges []machoCodeRange) []byte {
	end := min(len(data), offset+15) // architectural maximum x86 instruction size
	va := textAddr + uint64(offset)
	if functionIndex := functionIndexForVA(functions, va); functionIndex >= 0 {
		functionEnd := functions[functionIndex].End
		if functionEnd > va && functionEnd-textAddr < uint64(end) {
			end = int(functionEnd - textAddr)
		}
	}
	index := sort.Search(len(dataRanges), func(i int) bool { return dataRanges[i].start > offset })
	if index < len(dataRanges) && dataRanges[index].start < end {
		end = dataRanges[index].start
	}
	if end <= offset {
		return nil
	}
	return data[offset:end]
}

func clearX86AddressState(addresses map[uint8]x86AddressValue) {
	for register := range addresses {
		delete(addresses, register)
	}
}

func copyX86AddressState(addresses map[uint8]x86AddressValue, dst, src uint8, instruction int) {
	if value, ok := addresses[src]; ok {
		value.instruction = instruction
		addresses[dst] = value
	} else {
		delete(addresses, dst)
	}
}

func x86ObjCStringCallContextIndexed(file *macho.File, reader *machoCFStringReader, text *macho.Section, instructionOffset int, addresses map[uint8]x86AddressValue, integers map[uint8]machoRegisterInteger, receivers map[uint8]machoObjCReceiverValue, stackAddresses map[uint8]machoStackAddressValue, stackSlots map[int64]machoObjCStackSlot) machoCallContext {
	var context machoCallContext
	if receiver, ok := receivers[7]; ok && instructionOffset-receiver.Instruction <= 96 {
		context.setObjCReceiver(receiver)
	}
	for position, register := range [...]uint8{7, 6, 2, 1, 8, 9} {
		if position < 2 {
			continue
		}
		address, ok := addresses[register]
		if !ok || instructionOffset-address.instruction > 96 {
			continue
		}
		argument, ok := objcCFStringAtTargetLocationIndexed(file, reader, address.value, false)
		if !ok {
			continue
		}
		argument.ReferenceVA = text.Addr + uint64(address.instruction)
		argument.ReferenceOff = int(text.Offset) + address.instruction
		context.setStringArgument(position, argument)
		continue
	}
	for position, register := range [...]uint8{7, 6, 2, 1, 8, 9} {
		if position < 2 {
			continue
		}
		address, ok := addresses[register]
		if !ok || instructionOffset-address.instruction > 96 {
			continue
		}
		array, ok := objcCFStringArrayAtTargetLocationIndexed(file, reader, address.value, false)
		if !ok {
			continue
		}
		array.ReferenceVA = text.Addr + uint64(address.instruction)
		array.ReferenceOff = int(text.Offset) + address.instruction
		context.setObjCStringArray(position, array)
	}
	for position, register := range [...]uint8{7, 6, 2, 1, 8, 9} {
		object, ok := receivers[register]
		if !ok || instructionOffset-object.Instruction > 96 || len(object.StringArray.Elements) == 0 {
			continue
		}
		array := object.StringArray
		array.ReferenceVA = object.ReferenceVA
		array.ReferenceOff = object.ReferenceOff
		context.setObjCStringArray(position, array)
	}
	if address, ok := stackAddresses[2]; ok && instructionOffset-address.Instruction <= 96 {
		if count, ok := integers[1]; ok && instructionOffset-count.instruction <= 96 {
			if array, ok := objcStringArrayFromStack(address, count.value, stackSlots, text.Addr+uint64(address.Instruction), int(text.Offset)+address.Instruction); ok {
				context.setObjCStringArray(2, array)
			}
		}
	}
	return context
}

func x86RIPRelativeIndirectCallPointer(instructionVA uint64, data []byte) (uint64, bool) {
	// Canonical CALL qword ptr [RIP+disp32]. Reject prefixes and other ModR/M
	// forms: only this encoding identifies one immutable indirect-symbol slot
	// without register or memory-state inference.
	if len(data) != 6 || data[0] != 0xff || data[1] != 0x15 {
		return 0, false
	}
	displacement := int64(int32(binary.LittleEndian.Uint32(data[2:6])))
	if instructionVA > ^uint64(0)-uint64(len(data)) {
		return 0, false
	}
	base := instructionVA + uint64(len(data))
	if displacement < 0 {
		magnitude := uint64(-displacement)
		if magnitude > base {
			return 0, false
		}
		return base - magnitude, true
	}
	if uint64(displacement) > ^uint64(0)-base {
		return 0, false
	}
	return base + uint64(displacement), true
}

func x86BaseRelativeTargetAndReg(data []byte, addresses map[uint8]x86AddressValue) (target uint64, reg, base uint8, size int, loadsMemory bool, ok bool) {
	// Pointer-producing base-relative forms require one canonical REX.W prefix
	// immediately before the opcode. Reject legacy and repeated prefixes rather
	// than accumulating extension bits across hostile byte sequences.
	if len(data) < 3 || data[0] < 0x48 || data[0] > 0x4f {
		return 0, 0, 0, 0, false, false
	}
	const i = 1
	rex := data[0]
	rexR := ((rex >> 2) & 0x1) * 8
	rexX := ((rex >> 1) & 0x1) * 8
	rexB := (rex & 0x1) * 8
	opcode := data[i]
	if opcode != 0x8d && opcode != 0x8b {
		return 0, 0, 0, 0, false, false
	}
	modrm := data[i+1]
	mod := modrm >> 6
	rm := modrm & 0x7
	if mod != 0 && mod != 1 && mod != 2 {
		return 0, 0, 0, 0, false, false
	}
	dispOffset := i + 2
	if rm == 4 {
		if i+3 > len(data) {
			return 0, 0, 0, 0, false, false
		}
		sib := data[i+2]
		index := ((sib >> 3) & 0x7) | rexX
		if index != 4 {
			return 0, 0, 0, 0, false, false
		}
		if mod == 0 && sib&0x7 == 5 {
			return 0, 0, 0, 0, false, false
		}
		base = (sib & 0x7) | rexB
		dispOffset = i + 3
	} else {
		if mod == 0 && rm == 5 {
			return 0, 0, 0, 0, false, false
		}
		base = rm | rexB
	}
	baseValue, ok := addresses[base]
	if !ok {
		return 0, 0, 0, 0, false, false
	}
	reg = ((modrm >> 3) & 0x7) | rexR
	loadsMemory = opcode == 0x8b
	switch mod {
	case 0:
		size = dispOffset
		target = baseValue.value
	case 1:
		if dispOffset+1 > len(data) {
			return 0, 0, 0, 0, false, false
		}
		size = dispOffset + 1
		disp := int64(int8(data[dispOffset]))
		target = uint64(int64(baseValue.value) + disp)
	case 2:
		if dispOffset+4 > len(data) {
			return 0, 0, 0, 0, false, false
		}
		size = dispOffset + 4
		disp := int64(int32(binary.LittleEndian.Uint32(data[dispOffset : dispOffset+4])))
		target = uint64(int64(baseValue.value) + disp)
	default:
		return 0, 0, 0, 0, false, false
	}
	return target, reg, base, size, loadsMemory, true
}

func appendMachOStringXrefForIndex(out []machoStringXref, functions []machoFunction, functionIndex int, va uint64, literal machoStringLiteral) []machoStringXref {
	if len(out) >= maxMachOStringXrefs {
		return out
	}
	if functionIndex >= 0 && functionIndex < len(functions) {
		fn := functions[functionIndex]
		return append(out, machoStringXref{RefVA: va, Function: fn, Literal: literal})
	}
	return out
}

func stringLiteralForX86TargetIndexed(file *macho.File, sections *machoSectionIndex, literals machoStringLiteralIndex, target uint64, loadsMemory bool) (machoStringLiteral, bool) {
	if literal, ok := literals.forVA(target); ok {
		return literal, true
	}
	if !loadsMemory {
		return machoStringLiteral{}, false
	}
	pointer, ok := readPointerAtVAIndexed(file, sections, target)
	if !ok {
		return machoStringLiteral{}, false
	}
	return literals.forPointerIndexed(sections, pointer)
}

func x86RIPRelativeTargetAndReg(instrVA uint64, data []byte) (target uint64, reg uint8, size int, loadsMemory bool, ok bool) {
	// Accept only the canonical 64-bit forms 48/4c 8d|8b /r disp32.
	// Operand-size overrides and REX prefixes without W truncate pointers.
	// Multiple REX prefixes are intentionally rejected instead of combining
	// bits from prefixes whose architectural handling depends on their order.
	if len(data) < 7 || data[0] != 0x48 && data[0] != 0x4c {
		return 0, 0, 0, false, false
	}
	rexR := ((data[0] >> 2) & 0x1) * 8
	opcode := data[1]
	if opcode != 0x8d && opcode != 0x8b {
		return 0, 0, 0, false, false
	}
	modrm := data[2]
	if modrm&0xc7 != 0x05 {
		return 0, 0, 0, false, false
	}
	size = 7
	reg = ((modrm >> 3) & 0x7) | rexR
	loadsMemory = opcode == 0x8b
	disp := int64(int32(binary.LittleEndian.Uint32(data[3:7])))
	target = uint64(int64(instrVA+uint64(size)) + disp)
	return target, reg, size, loadsMemory, true
}

type arm64RegisterValue struct {
	value       uint64
	instruction int
	loadsMemory bool
}

type machoRegisterInteger struct {
	value       uint64
	instruction int
}

type arm64SelectorValue struct {
	selector    string
	instruction int
}

type x86SelectorValue struct {
	selector    string
	instruction int
}

type x86StringValue struct {
	value         string
	instruction   int
	referenceVA   uint64
	referenceOff  int
	literalVA     uint64
	literalOffset int
}

type machoCallStringArgument struct {
	Value          string
	ReferenceVA    uint64
	ReferenceOff   int
	LiteralVA      uint64
	LiteralOffset  int
	BackingVA      uint64
	BackingOffset  int
	Representation string
	EvidenceIDs    []string
}

type machoCallContext struct {
	Argument0String  string
	Argument1String  string
	StringArguments  [6]machoCallStringArgument
	ObjCStringArrays [6]machoObjCStringArray
	ObjCReceiver     machoObjCReceiverValue
	ArgumentVector   []machoStaticArgument
	SocketAddress    machoStaticSocketAddress
}

func (context machoCallContext) stringArgument(index int) machoCallStringArgument {
	if index < 0 || index >= len(context.StringArguments) {
		return machoCallStringArgument{}
	}
	argument := context.StringArguments[index]
	if argument.Value != "" {
		return argument
	}
	// Retain compatibility with focused recognizer tests and internal callers
	// that provide a value without instruction-level provenance. Production
	// direct-call decoding populates StringArguments with exact locations.
	switch index {
	case 0:
		argument.Value = context.Argument0String
	case 1:
		argument.Value = context.Argument1String
	}
	return argument
}

func (context *machoCallContext) setStringArgument(index int, argument machoCallStringArgument) {
	if context == nil || index < 0 || index >= len(context.StringArguments) || argument.Value == "" {
		return
	}
	context.StringArguments[index] = argument
	switch index {
	case 0:
		context.Argument0String = argument.Value
	case 1:
		context.Argument1String = argument.Value
	}
}

func arm64StringXrefs(file *macho.File, textAddr uint64, data []byte, functions []machoFunction, literals []machoStringLiteral) []machoStringXref {
	return arm64StringXrefsIndexed(file, newMachOSectionIndex(file), textAddr, data, functions, newMachOStringLiteralIndex(literals))
}

func arm64StringXrefsIndexed(file *macho.File, sections *machoSectionIndex, textAddr uint64, data []byte, functions []machoFunction, literals machoStringLiteralIndex) []machoStringXref {
	return arm64StringXrefsIndexedWithRanges(file, sections, textAddr, data, functions, literals, nil)
}

func arm64StringXrefsIndexedWithRanges(file *macho.File, sections *machoSectionIndex, textAddr uint64, data []byte, functions []machoFunction, literals machoStringLiteralIndex, dataRanges []machoCodeRange) []machoStringXref {
	var out []machoStringXref
	registers := map[uint32]arm64RegisterValue{}
	currentFunction := -2
	for i := 0; i+4 <= len(data); i += 4 {
		va := textAddr + uint64(i)
		if functionIndex := functionIndexForSequentialVA(functions, currentFunction, va); functionIndex != currentFunction {
			clearArm64RegisterState(registers, nil)
			currentFunction = functionIndex
		}
		if _, excluded := machoCodeInstructionExcluded(i, 4, dataRanges); excluded {
			clearArm64RegisterState(registers, nil)
			continue
		}
		insn := file.ByteOrder.Uint32(data[i : i+4])
		if rd, target, isPage, ok := arm64ADRTargetKind(va, insn); ok {
			registers[rd] = arm64RegisterValue{value: target, instruction: i}
			if !isPage {
				if literal, ok := literals.forVA(target); ok {
					out = appendMachOStringXrefForIndex(out, functions, currentFunction, va, literal)
				}
			}
			continue
		}
		if rd, rn, imm, ok := arm64ADDImmediate(insn); ok {
			base, ok := registers[rn]
			if !ok || base.loadsMemory || i-base.instruction > 32 {
				delete(registers, rd)
				continue
			}
			target := base.value + imm
			registers[rd] = arm64RegisterValue{value: target, instruction: i}
			if literal, ok := literals.forVA(target); ok {
				out = appendMachOStringXrefForIndex(out, functions, currentFunction, va, literal)
			}
			continue
		}
		if rt, rn, offset, ok := arm64LDRUnsignedImmediate(insn); ok {
			base, ok := registers[rn]
			if !ok || base.loadsMemory || i-base.instruction > 32 {
				delete(registers, rt)
				continue
			}
			pointerVA := base.value + offset
			registers[rt] = arm64RegisterValue{value: pointerVA, instruction: i, loadsMemory: true}
			if pointer, ok := readPointerAtVAIndexed(file, sections, pointerVA); ok {
				if literal, ok := literals.forPointerIndexed(sections, pointer); ok {
					out = appendMachOStringXrefForIndex(out, functions, currentFunction, va, literal)
				}
			}
			continue
		}
		if rd, rn, ok := arm64MOVRegister(insn); ok {
			copyArm64RegisterState(registers, nil, rd, rn, i)
			continue
		}
		if rt, pointerVA, ok := arm64LDRLiteralTarget(va, insn); ok {
			registers[rt] = arm64RegisterValue{value: pointerVA, instruction: i, loadsMemory: true}
			if pointer, ok := readPointerAtVAIndexed(file, sections, pointerVA); ok {
				if literal, ok := literals.forPointerIndexed(sections, pointer); ok {
					out = appendMachOStringXrefForIndex(out, functions, currentFunction, va, literal)
				}
			}
			continue
		}
		if arm64BreaksLinearState(insn) {
			clearArm64RegisterState(registers, nil)
			continue
		}
		// Preserve inferred addresses only across instructions whose complete
		// register effects are modeled above. An unknown instruction may write
		// multiple registers (for example LDP), so guessing one low-bit Rd would
		// allow stale arguments to survive into a later semantic match.
		clearArm64RegisterState(registers, nil)
	}
	return out
}

func arm64ADRTarget(va uint64, insn uint32) (uint32, uint64, bool) {
	rd, target, _, ok := arm64ADRTargetKind(va, insn)
	return rd, target, ok
}

func arm64ADRTargetKind(va uint64, insn uint32) (rd uint32, target uint64, isPage bool, ok bool) {
	if insn&0x9f000000 != 0x90000000 && insn&0x9f000000 != 0x10000000 {
		return 0, 0, false, false
	}
	rd = insn & 0x1f
	if rd == 31 {
		return 0, 0, false, false
	}
	immlo := (insn >> 29) & 0x3
	immhi := (insn >> 5) & 0x7ffff
	imm := signExtend64(uint64((immhi<<2)|immlo), 21)
	if insn&0x9f000000 == 0x90000000 {
		page := int64(va) &^ 0xfff
		return rd, uint64(page + (imm << 12)), true, true
	}
	return rd, uint64(int64(va) + imm), false, true
}

func arm64ADDImmediate(insn uint32) (rd, rn uint32, imm uint64, ok bool) {
	// Only ADD Xd, Xn, #imm preserves a 64-bit pointer. The W-register form
	// zero-extends/truncates and must not participate in address recovery.
	if insn&0xff000000 != 0x91000000 {
		return 0, 0, 0, false
	}
	shift := (insn >> 22) & 0x3
	if shift > 1 {
		return 0, 0, 0, false
	}
	rd = insn & 0x1f
	rn = (insn >> 5) & 0x1f
	if rd == 31 || rn == 31 {
		return 0, 0, 0, false
	}
	imm = uint64((insn >> 10) & 0xfff)
	if shift == 1 {
		imm <<= 12
	}
	return rd, rn, imm, true
}

func arm64ADDImmediateDestination(insn uint32) (rd uint32, ok bool) {
	if insn&0xff000000 != 0x91000000 || (insn>>22)&0x3 > 1 {
		return 0, false
	}
	rd = insn & 0x1f
	return rd, rd != 31
}

func arm64MOVRegister(insn uint32) (rd, rn uint32, ok bool) {
	if insn&0xffe0ffe0 != 0xaa0003e0 {
		return 0, 0, false
	}
	rd = insn & 0x1f
	rn = (insn >> 16) & 0x1f
	if rd == 31 || rn == 31 {
		return 0, 0, false
	}
	return rd, rn, true
}

func arm64ImmediateRegister(insn uint32) (rd uint32, value uint64, ok bool) {
	// MOVZ Xd, #imm{, LSL #shift}. Go commonly uses this for ABI string
	// lengths.
	if insn&0xff800000 == 0xd2800000 {
		rd = insn & 0x1f
		if rd == 31 {
			return 0, 0, false
		}
		shift := ((insn >> 21) & 0x3) * 16
		return rd, uint64((insn>>5)&0xffff) << shift, true
	}
	// MOVZ Wd is an exact zero-extending write to the corresponding X
	// register. Retain the value for bounded count/length arguments; integer
	// state never enters the pointer-address lane.
	if insn&0xff800000 == 0x52800000 {
		rd = insn & 0x1f
		if rd == 31 {
			return 0, 0, false
		}
		shift := ((insn >> 21) & 0x1) * 16
		return rd, uint64((insn>>5)&0xffff) << shift, true
	}
	// MOV Xd, #bitmask is an alias for ORR Xd, XZR, #imm. Delegate only
	// this closed encoding to the pinned instruction decoder; no decoded
	// register state is trusted beyond the exact destination and immediate.
	if insn&0xff8003e0 != 0xb20003e0 {
		return 0, 0, false
	}
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], insn)
	decoded, err := arm64asm.Decode(raw[:])
	if err != nil || decoded.Op != arm64asm.ORR {
		return 0, 0, false
	}
	destination, ok := decoded.Args[0].(arm64asm.RegSP)
	if !ok {
		if register, registerOK := decoded.Args[0].(arm64asm.Reg); registerOK {
			destination = arm64asm.RegSP(register)
		} else {
			return 0, 0, false
		}
	}
	register := arm64asm.Reg(destination)
	if register < arm64asm.X0 || register > arm64asm.X30 {
		return 0, 0, false
	}
	immediate, ok := decoded.Args[2].(arm64asm.Imm64)
	if !ok {
		return 0, 0, false
	}
	return uint32(register - arm64asm.X0), immediate.Imm, true
}

func arm64LDRUnsignedImmediate(insn uint32) (rt, rn uint32, offset uint64, ok bool) {
	switch insn & 0xffc00000 {
	case 0xf9400000:
		rt = insn & 0x1f
		rn = (insn >> 5) & 0x1f
		if rt == 31 || rn == 31 {
			return 0, 0, 0, false
		}
		return rt, rn, uint64((insn>>10)&0xfff) * 8, true
	default:
		return 0, 0, 0, false
	}
}

func arm64FrameAddressDestination(insn uint32) (uint32, bool) {
	// Accept only 64-bit ADD/SUB (immediate) rooted directly at x29. The
	// computed value is treated as an escaped frame address, never as an image
	// pointer or concrete resource. Flag-setting and register-offset forms are
	// deliberately excluded.
	op := insn & 0xff000000
	if (op != 0x91000000 && op != 0xd1000000) || (insn>>5)&0x1f != 29 {
		return 0, false
	}
	destination := insn & 0x1f
	if destination == 31 {
		return 0, false
	}
	return destination, true
}

func arm64FrameRelativeReceiverAccess(insn uint32) (register uint32, offset int64, load, ok bool) {
	// Closed 64-bit x29-relative spill/reload forms emitted by Clang for local
	// Objective-C strong references. No pre/post-index, pair, 32-bit, SP-based,
	// or register-offset addressing is admitted.
	masked := insn & 0xffe00c00
	switch masked {
	case 0xf8000000: // STUR Xt, [x29, #simm9]
		load = false
	case 0xf8400000: // LDUR Xt, [x29, #simm9]
		load = true
	default:
		unsigned := insn & 0xffc00000
		if unsigned != 0xf9000000 && unsigned != 0xf9400000 {
			return 0, 0, false, false
		}
		if (insn>>5)&0x1f != 29 {
			return 0, 0, false, false
		}
		register = insn & 0x1f
		if register == 31 {
			return 0, 0, false, false
		}
		return register, int64((insn>>10)&0xfff) * 8, unsigned == 0xf9400000, true
	}
	if (insn>>5)&0x1f != 29 {
		return 0, 0, false, false
	}
	register = insn & 0x1f
	if register == 31 {
		return 0, 0, false, false
	}
	immediate := int64((insn >> 12) & 0x1ff)
	if immediate&0x100 != 0 {
		immediate -= 0x200
	}
	return register, immediate, load, true
}

func arm64KnownMemoryAccess(insn uint32) (register, base uint32, load, ok bool) {
	// Recognize only non-indexed immediate scalar LDR/STR and LDUR/STUR forms.
	// This applies exact destination-write semantics without pretending to
	// resolve the referenced memory.
	masked := insn & 0xffe00c00
	switch masked {
	case 0xf8000000, 0xb8000000: // STUR X/W
		load = false
	case 0xf8400000, 0xb8400000: // LDUR X/W
		load = true
	default:
		op := insn & 0xffc00000
		switch op {
		case 0xf9000000, 0xb9000000: // STR X/W
			load = false
		case 0xf9400000, 0xb9400000: // LDR X/W
			load = true
		default:
			return 0, 0, false, false
		}
	}
	return insn & 0x1f, (insn >> 5) & 0x1f, load, true
}

func arm64LDRLiteralTarget(va uint64, insn uint32) (rt uint32, target uint64, ok bool) {
	// Accept only LDR Xt, label. W-register and LDRSW literal forms do not
	// produce a 64-bit pointer value suitable for later dereference tracking.
	if insn&0xff000000 != 0x58000000 {
		return 0, 0, false
	}
	rt = insn & 0x1f
	if rt == 31 {
		return 0, 0, false
	}
	imm := signExtend64(uint64((insn>>5)&0x7ffff), 19) << 2
	return rt, uint64(int64(va) + imm), true
}

func signExtend64(value uint64, bits uint) int64 {
	shift := 64 - bits
	return int64(value<<shift) >> shift
}

type machoSectionExtent struct {
	offset uint32
	size   uint64
}

type machoSectionInterval struct {
	start   uint64
	end     uint64
	section *macho.Section
}

type machoAddressIndex struct {
	intervals  []machoSectionInterval
	prefixEnds []uint64
	prefixBest []*macho.Section
}

type machoSectionIndex struct {
	all       machoAddressIndex
	byName    map[string]*machoAddressIndex
	imageBase uint64
}

func newMachOSectionIndex(file *macho.File) *machoSectionIndex {
	index := &machoSectionIndex{byName: map[string]*machoAddressIndex{}}
	baseSet := false
	for _, section := range file.Sections {
		if section == nil || section.Size == 0 || !machoSectionHasFileData(section) || section.Addr > ^uint64(0)-section.Size {
			continue
		}
		interval := machoSectionInterval{start: section.Addr, end: section.Addr + section.Size, section: section}
		index.all.intervals = append(index.all.intervals, interval)
		nameIndex := index.byName[section.Name]
		if nameIndex == nil {
			nameIndex = &machoAddressIndex{}
			index.byName[section.Name] = nameIndex
		}
		nameIndex.intervals = append(nameIndex.intervals, interval)
		if !baseSet || section.Addr < index.imageBase {
			index.imageBase = section.Addr
			baseSet = true
		}
	}
	index.all.finalize()
	for _, nameIndex := range index.byName {
		nameIndex.finalize()
	}
	index.imageBase &^= 0xfff
	return index
}

func (index *machoAddressIndex) finalize() {
	sort.Slice(index.intervals, func(i, j int) bool {
		if index.intervals[i].start != index.intervals[j].start {
			return index.intervals[i].start < index.intervals[j].start
		}
		return index.intervals[i].end > index.intervals[j].end
	})
	index.prefixEnds = make([]uint64, len(index.intervals))
	index.prefixBest = make([]*macho.Section, len(index.intervals))
	var bestEnd uint64
	var best *macho.Section
	for i, interval := range index.intervals {
		if best == nil || interval.end > bestEnd {
			bestEnd = interval.end
			best = interval.section
		}
		index.prefixEnds[i] = bestEnd
		index.prefixBest[i] = best
	}
}

func (index *machoAddressIndex) containing(va, size uint64) *macho.Section {
	if index == nil || len(index.intervals) == 0 || size > ^uint64(0)-va {
		return nil
	}
	requiredEnd := va + size
	i := sort.Search(len(index.intervals), func(i int) bool { return index.intervals[i].start > va }) - 1
	if i < 0 || index.prefixEnds[i] < requiredEnd {
		return nil
	}
	section := index.prefixBest[i]
	if section == nil || va < section.Addr {
		return nil
	}
	offset := va - section.Addr
	if offset > section.Size || size > section.Size-offset {
		return nil
	}
	return section
}

func (index *machoSectionIndex) containing(va, size uint64) *macho.Section {
	if index == nil {
		return nil
	}
	return index.all.containing(va, size)
}

func (index *machoSectionIndex) namedContaining(va, size uint64, name string) *macho.Section {
	if index == nil {
		return nil
	}
	return index.byName[name].containing(va, size)
}

func machoSectionHasFileData(section *macho.Section) bool {
	if section == nil {
		return false
	}
	switch section.Flags & 0xff {
	case 0x1, 0xc, 0x12:
		return false
	default:
		return true
	}
}

func machoSectionPrefix(image []byte, section *macho.Section, maxBytes int) ([]byte, bool, error) {
	if section == nil || section.Size == 0 || !machoSectionHasFileData(section) {
		return nil, false, nil
	}
	if maxBytes < 0 {
		maxBytes = 0
	}
	readSize := section.Size
	if readSize > uint64(maxBytes) {
		readSize = uint64(maxBytes)
	}
	truncated := readSize < section.Size
	if readSize == 0 {
		return nil, truncated, nil
	}
	fileOffset := uint64(section.Offset)
	if len(image) > 0 {
		if fileOffset > uint64(len(image)) || readSize > uint64(len(image))-fileOffset {
			return nil, true, fmt.Errorf("section %s points outside slice image", section.Name)
		}
		return image[int(fileOffset):int(fileOffset+readSize)], truncated, nil
	}
	data, err := readMachOSectionAt(section, 0, int(readSize))
	if err != nil {
		return nil, true, err
	}
	return data, truncated || uint64(len(data)) < section.Size, nil
}

func readPointerAtVAIndexed(file *macho.File, index *machoSectionIndex, va uint64) (uint64, bool) {
	section := index.containing(va, 8)
	if section == nil {
		return 0, false
	}
	offset := va - section.Addr
	data, err := readMachOSectionAt(section, offset, 8)
	if err != nil || len(data) != 8 {
		return 0, false
	}
	return file.ByteOrder.Uint64(data), true
}

type machoStringLiteralIndex struct {
	literals   []machoStringLiteral
	ends       []uint64
	prefixEnds []uint64
	prefixBest []int
}

func newMachOStringLiteralIndex(literals []machoStringLiteral) machoStringLiteralIndex {
	out := make([]machoStringLiteral, 0, len(literals))
	for _, literal := range literals {
		if _, ok := machoStringLiteralEnd(literal); ok {
			out = append(out, literal)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].VA == out[j].VA {
			return out[i].size() < out[j].size()
		}
		return out[i].VA < out[j].VA
	})
	idx := machoStringLiteralIndex{
		literals:   out,
		ends:       make([]uint64, len(out)),
		prefixEnds: make([]uint64, len(out)),
		prefixBest: make([]int, len(out)),
	}
	best := -1
	var bestEnd uint64
	for i, literal := range out {
		end, _ := machoStringLiteralEnd(literal)
		idx.ends[i] = end
		// Prefer the later-starting literal when two ranges share an end.
		if best < 0 || end >= bestEnd {
			best = i
			bestEnd = end
		}
		idx.prefixEnds[i] = bestEnd
		idx.prefixBest[i] = best
	}
	return idx
}

func (idx machoStringLiteralIndex) forVA(va uint64) (machoStringLiteral, bool) {
	i := sort.Search(len(idx.literals), func(i int) bool {
		return idx.literals[i].VA > va
	})
	if i == 0 || idx.prefixEnds[i-1] <= va {
		return machoStringLiteral{}, false
	}
	best := idx.prefixBest[i-1]
	if best < 0 || va < idx.literals[best].VA || va >= idx.ends[best] {
		return machoStringLiteral{}, false
	}
	return idx.literals[best], true
}

func (idx machoStringLiteralIndex) forPointerIndexed(sections *machoSectionIndex, pointer uint64) (machoStringLiteral, bool) {
	for _, candidate := range normalizedMachOPointersIndexed(sections, pointer) {
		if literal, ok := idx.forVA(candidate); ok {
			return literal, true
		}
	}
	return machoStringLiteral{}, false
}

func stringLiteralForVA(literals []machoStringLiteral, va uint64) (machoStringLiteral, bool) {
	for _, literal := range literals {
		end, ok := machoStringLiteralEnd(literal)
		if !ok {
			continue
		}
		if va >= literal.VA && va < end {
			return literal, true
		}
	}
	return machoStringLiteral{}, false
}

func (literal machoStringLiteral) size() int {
	if literal.Size > 0 {
		return literal.Size
	}
	if literal.Value != "" {
		return len(literal.Value)
	}
	return 1
}

func machoStringLiteralEnd(literal machoStringLiteral) (uint64, bool) {
	size := literal.size()
	// A semantic literal recovered from a CFString record is addressed by the
	// object's exact VA. Its 32-byte Size describes evidence extent, not a range
	// in which interior flags/backing-pointer/length fields are equivalent xref
	// targets. ValueLocationKnown is set only for these object-backed literals.
	if literal.ValueLocationKnown {
		size = 1
	}
	// URL and path candidates may deliberately describe a substring inside a
	// larger printable run. A shell command, however, is executable grammar
	// rooted at its first byte. Letting every address inside its retained range
	// resolve to the whole command caused hundreds of unrelated Rust/Tauri
	// string references to inherit one concatenated .cargo string-table value.
	if literal.Kind == "shell-command" {
		size = 1
	}
	if size <= 0 || uint64(size) > ^uint64(0)-literal.VA {
		return 0, false
	}
	return literal.VA + uint64(size), true
}

func stringLiteralForPointer(file *macho.File, literals []machoStringLiteral, pointer uint64) (machoStringLiteral, bool) {
	for _, candidate := range normalizedMachOPointers(file, pointer) {
		if literal, ok := stringLiteralForVA(literals, candidate); ok {
			return literal, true
		}
	}
	return machoStringLiteral{}, false
}

func normalizedMachOPointers(file *macho.File, pointer uint64) []uint64 {
	return normalizedMachOPointersIndexed(newMachOSectionIndex(file), pointer)
}

func normalizedMachOPointersIndexed(index *machoSectionIndex, pointer uint64) []uint64 {
	candidates := []uint64{pointer}
	base := uint64(0)
	if index != nil {
		base = index.imageBase
	}
	if base == 0 {
		return candidates
	}
	for _, offset := range []uint64{pointer, pointer & 0xffffffff} {
		if offset > ^uint64(0)-base {
			continue
		}
		candidate := base + offset
		duplicate := false
		for _, existing := range candidates {
			if existing == candidate {
				duplicate = true
				break
			}
		}
		if !duplicate {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func readCStringAtPointerIndexed(file *macho.File, index *machoSectionIndex, pointer, maxLen uint64) (string, bool) {
	value, _, _, ok := readCStringAtPointerLocationIndexed(file, index, pointer, maxLen)
	return value, ok
}

func readCStringAtPointerLocationIndexed(_ *macho.File, index *machoSectionIndex, pointer, maxLen uint64) (string, uint64, int, bool) {
	for _, candidate := range normalizedMachOPointersIndexed(index, pointer) {
		value, ok := readCStringAtVAIndexed(index, candidate, maxLen)
		if !ok {
			continue
		}
		offset, ok := machoSectionFileOffsetForVA(index, candidate)
		if !ok {
			return "", 0, 0, false
		}
		return value, candidate, offset, true
	}
	return "", 0, 0, false
}

type machoCFStringReadKey struct {
	pointer uint64
	length  uint64
}

type machoCFStringReadResult struct {
	value  string
	va     uint64
	offset int
	ok     bool
}

type machoCFStringReader struct {
	index          *machoSectionIndex
	bytesRemaining uint64
	truncated      bool
	cache          map[machoCFStringReadKey]machoCFStringReadResult
}

func newMachOCFStringReader(index *machoSectionIndex, byteLimit uint64) *machoCFStringReader {
	return &machoCFStringReader{
		index:          index,
		bytesRemaining: byteLimit,
		cache:          make(map[machoCFStringReadKey]machoCFStringReadResult),
	}
}

// read bounds cumulative CFString backing work. The charge conservatively
// covers every normalized pointer candidate the exact reader may inspect, and
// the raw pointer/length cache prevents duplicate object records from rereading
// or reallocating the same backing value.
func (reader *machoCFStringReader) read(pointer, length uint64) (string, uint64, int, bool) {
	key := machoCFStringReadKey{pointer: pointer, length: length}
	if result, ok := reader.cache[key]; ok {
		return result.value, result.va, result.offset, result.ok
	}
	if length == 0 || length > maxMachOASCIIStringBytes {
		reader.cache[key] = machoCFStringReadResult{}
		return "", 0, 0, false
	}
	candidates := normalizedMachOPointersIndexed(reader.index, pointer)
	if len(candidates) == 0 {
		reader.cache[key] = machoCFStringReadResult{}
		return "", 0, 0, false
	}
	if uint64(len(candidates)) > reader.bytesRemaining/length {
		reader.truncated = true
		reader.cache[key] = machoCFStringReadResult{}
		return "", 0, 0, false
	}
	reader.bytesRemaining -= length * uint64(len(candidates))
	value, va, offset, ok := readExactStringAtPointerLocationIndexed(reader.index, pointer, length)
	result := machoCFStringReadResult{value: value, va: va, offset: offset, ok: ok}
	reader.cache[key] = result
	return result.value, result.va, result.offset, result.ok
}

// readExactStringAtPointerLocationIndexed reads a validated length-delimited
// static string backing value. CFString and Go strings both declare their byte
// length separately from any optional trailing NUL, so the ordinary C-string
// reader would reject valid values whenever more section bytes follow the
// exact window.
func readExactStringAtPointerLocationIndexed(index *machoSectionIndex, pointer, length uint64) (string, uint64, int, bool) {
	if length == 0 || length > maxMachOASCIIStringBytes {
		return "", 0, 0, false
	}
	for _, candidate := range normalizedMachOPointersIndexed(index, pointer) {
		section := index.containing(candidate, length)
		if section == nil {
			continue
		}
		window, err := readMachOSectionAt(section, candidate-section.Addr, int(length))
		if err != nil || uint64(len(window)) != length || bytes.IndexByte(window, 0) >= 0 {
			continue
		}
		value := string(window)
		if !mostlyPrintableASCII(value) {
			continue
		}
		offset, ok := machoSectionFileOffsetForVA(index, candidate)
		if !ok {
			return "", 0, 0, false
		}
		return value, candidate, offset, true
	}
	return "", 0, 0, false
}

func readCStringAtVAIndexed(index *machoSectionIndex, va, maxLen uint64) (string, bool) {
	if maxLen == 0 || maxLen > maxMachOASCIIStringBytes {
		maxLen = maxMachOASCIIStringBytes
	}
	section := index.containing(va, 1)
	if section == nil {
		return "", false
	}
	offset := va - section.Addr
	remaining := section.Size - offset
	readLen := min(maxLen, remaining)
	window, err := readMachOSectionAt(section, offset, int(readLen))
	if err != nil || len(window) == 0 {
		return "", false
	}
	if bytes.IndexByte(window, 0) < 0 && uint64(len(window)) < remaining {
		// The string exceeds the analysis limit. The bounded whole-image
		// string pass records partial coverage and may still retain its prefix.
		return "", false
	}
	value := cstring(window)
	if value == "" || !mostlyPrintableASCII(value) {
		return "", false
	}
	return value, true
}

func readMachOSectionAt(section *macho.Section, offset uint64, length int) ([]byte, error) {
	if length < 0 || offset > math.MaxInt64 {
		return nil, fmt.Errorf("section %s read is out of range", section.Name)
	}
	if section.ReaderAt == nil {
		if section.Size > maxMachOASCIIStringBytes {
			return nil, fmt.Errorf("section %s has no bounded reader", section.Name)
		}
		data, err := section.Data()
		if err != nil {
			return nil, err
		}
		if offset > uint64(len(data)) || uint64(length) > uint64(len(data))-offset {
			return nil, io.ErrUnexpectedEOF
		}
		return data[int(offset) : int(offset)+length], nil
	}
	data := make([]byte, length)
	n, err := section.ReadAt(data, int64(offset))
	if err != nil && err != io.EOF {
		return nil, err
	}
	return data[:n], nil
}

func mostlyPrintableASCII(value string) bool {
	if value == "" {
		return false
	}
	printable := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 0x20 && c <= 0x7e:
			printable++
		case c == '\t':
			printable++
		default:
			return false
		}
	}
	return printable > 0
}

func extractX86DirectCalls(graph *behavior.Graph, content artifact.Content, file *macho.File, text *macho.Section, data []byte, functions []machoFunction, importStubs, objcStubs map[uint64]string, arch string) int {
	count, _ := extractX86DirectCallsIndexed(newMachOCallLookup(graph, content, arch), file, text, data, functions, importStubs, objcStubs, maxMachODirectCallScanBytes, maxMachODirectCallCandidates)
	return count
}

func extractX86DirectCallsIndexed(lookup *machoCallLookup, file *macho.File, text *macho.Section, data []byte, functions []machoFunction, importStubs, objcStubs map[uint64]string, byteLimit, candidateLimit int) (int, bool) {
	return extractX86DirectCallsIndexedWithRanges(lookup, file, text, data, functions, importStubs, objcStubs, byteLimit, candidateLimit, nil)
}

func extractX86DirectCallsIndexedWithRanges(lookup *machoCallLookup, file *macho.File, text *macho.Section, data []byte, functions []machoFunction, importStubs, objcStubs map[uint64]string, byteLimit, candidateLimit int, dataRanges []machoCodeRange) (int, bool) {
	data, truncated := boundedMachOCallData(data, byteLimit)
	sections := lookup.sectionIndexFor(file)
	importPointers, importPointersTruncated := importedPointerMapForLookup(file, lookup, maxMachOStubRecords)
	if importPointersTruncated {
		addPartialCoverageOnce(lookup.graph, lookup.content.NodeID, "macho-stubs/"+lookup.arch, fmt.Sprintf("stub and indirect-symbol-pointer extraction capped at %d records", maxMachOStubRecords))
	}
	objcStrings := newMachOCFStringReader(sections, maxMachOCFStringBackingBytes)
	count := 0
	candidates := 0
	stringRegisters := map[uint8]x86StringValue{}
	selectorRegisters := map[uint8]x86SelectorValue{}
	addressRegisters := map[uint8]x86AddressValue{}
	integerRegisters := map[uint8]machoRegisterInteger{}
	importPointerRegisters := map[uint8]x86ImportedPointerValue{}
	objcReceivers := map[uint8]machoObjCReceiverValue{}
	objcClasses := map[uint8]machoObjCClassValue{}
	stackAddresses := map[uint8]machoStackAddressValue{}
	stackSlots := map[int64]machoObjCStackSlot{}
	var pendingGoLaunch *machoGoLaunchConfiguration
	currentFunction := -2
	for i := 0; i < len(data); {
		if i&0xfff == 0 && lookup.graph.WorkLimitReached() {
			lookup.graph.MarkWorkOmitted()
			return count, true
		}
		va := text.Addr + uint64(i)
		if pendingGoLaunch != nil && pendingGoLaunch.nextOffset != i {
			pendingGoLaunch = nil
		}
		if functionIndex := functionIndexForVA(functions, va); functionIndex != currentFunction {
			clearX86RegisterState(stringRegisters, selectorRegisters)
			clearX86AddressState(addressRegisters)
			clearMachOIntegerState(integerRegisters)
			clearX86ImportedPointerState(importPointerRegisters)
			clearMachOObjCReceiverState(objcReceivers)
			clearMachOObjCClassState(objcClasses)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			pendingGoLaunch = nil
			currentFunction = functionIndex
		}
		if dataRange, excluded := machoCodeRangeContaining(i, dataRanges); excluded {
			clearX86RegisterState(stringRegisters, selectorRegisters)
			clearX86AddressState(addressRegisters)
			clearMachOIntegerState(integerRegisters)
			clearX86ImportedPointerState(importPointerRegisters)
			clearMachOObjCReceiverState(objcReceivers)
			clearMachOObjCClassState(objcClasses)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			pendingGoLaunch = nil
			i = dataRange.end
			continue
		}
		inst, err := decodeX86Instruction(x86DecodeInput(data, text.Addr, i, functions, dataRanges))
		if err != nil || inst.Len <= 0 || inst.Op == 0 {
			addPartialCoverageOnce(lookup.graph, lookup.content.NodeID, "macho-x86-direct-call-decode/"+lookup.arch, "x86_64 direct-call decoding stopped at the first undecodable instruction in each affected recovered function; no byte resynchronization was attempted")
			clearX86RegisterState(stringRegisters, selectorRegisters)
			clearX86AddressState(addressRegisters)
			clearMachOIntegerState(integerRegisters)
			clearX86ImportedPointerState(importPointerRegisters)
			clearMachOObjCReceiverState(objcReceivers)
			clearMachOObjCClassState(objcClasses)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			pendingGoLaunch = nil
			i = x86DecodeFailureResumeOffset(text.Addr, i, len(data), functions)
			continue
		}
		next, excluded := machoCodeInstructionExcluded(i, inst.Len, dataRanges)
		if excluded {
			clearX86RegisterState(stringRegisters, selectorRegisters)
			clearX86AddressState(addressRegisters)
			clearMachOIntegerState(integerRegisters)
			clearX86ImportedPointerState(importPointerRegisters)
			clearMachOObjCReceiverState(objcReceivers)
			clearMachOObjCClassState(objcClasses)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			pendingGoLaunch = nil
			i = next
			continue
		}
		instruction := data[i : i+inst.Len]
		if target, reg, size, loadsMemory, ok := x86RIPRelativeTargetAndReg(va, instruction); ok && size == inst.Len {
			delete(integerRegisters, reg)
			delete(objcReceivers, reg)
			delete(objcClasses, reg)
			delete(stackAddresses, reg)
			if !loadsMemory {
				addressRegisters[reg] = x86AddressValue{value: target, instruction: i}
			} else {
				delete(addressRegisters, reg)
			}
			if value, literalVA, literalOffset, ok := cstringAtTargetLocationIndexed(file, sections, target, loadsMemory); ok {
				stringRegisters[reg] = x86StringValue{
					value: value, instruction: i,
					referenceVA: va, referenceOff: int(text.Offset) + i,
					literalVA: literalVA, literalOffset: literalOffset,
				}
			} else {
				delete(stringRegisters, reg)
			}
			if loadsMemory {
				if symbol := importPointers[target]; symbol != "" {
					importPointerRegisters[reg] = x86ImportedPointerValue{Symbol: symbol, SlotVA: target, Instruction: i}
					if class, ok := objcClassNameFromImportedSymbol(symbol); ok {
						objcClasses[reg] = machoObjCClassValue{Name: class, Instruction: i, ReferenceVA: va, ReferenceOff: int(text.Offset) + i, SlotVA: target}
					} else {
						delete(objcClasses, reg)
					}
				} else {
					delete(importPointerRegisters, reg)
					delete(objcClasses, reg)
				}
				if value, ok := readObjectiveCSelectorRefAtVAIndexed(file, sections, target); ok {
					selectorRegisters[reg] = x86SelectorValue{selector: value, instruction: i}
				} else {
					delete(selectorRegisters, reg)
				}
			} else {
				delete(importPointerRegisters, reg)
				delete(selectorRegisters, reg)
				delete(objcClasses, reg)
			}
			i += inst.Len
			continue
		}
		if target, dst, base, size, loadsMemory, ok := x86BaseRelativeTargetAndReg(instruction, addressRegisters); ok && size == inst.Len {
			delete(integerRegisters, dst)
			delete(objcReceivers, dst)
			delete(objcClasses, dst)
			delete(stackAddresses, dst)
			baseFresh := true
			if baseValue, ok := addressRegisters[base]; ok && i-baseValue.instruction > x86AddressStateWindow {
				baseFresh = false
				delete(addressRegisters, base)
			}
			if baseFresh {
				if value, literalVA, literalOffset, ok := cstringAtTargetLocationIndexed(file, sections, target, loadsMemory); ok {
					stringRegisters[dst] = x86StringValue{
						value: value, instruction: i,
						referenceVA: va, referenceOff: int(text.Offset) + i,
						literalVA: literalVA, literalOffset: literalOffset,
					}
				} else {
					delete(stringRegisters, dst)
				}
				if loadsMemory {
					if symbol := importPointers[target]; symbol != "" {
						importPointerRegisters[dst] = x86ImportedPointerValue{Symbol: symbol, SlotVA: target, Instruction: i}
						if class, ok := objcClassNameFromImportedSymbol(symbol); ok {
							objcClasses[dst] = machoObjCClassValue{Name: class, Instruction: i, ReferenceVA: va, ReferenceOff: int(text.Offset) + i, SlotVA: target}
						} else {
							delete(objcClasses, dst)
						}
					} else {
						delete(importPointerRegisters, dst)
						delete(objcClasses, dst)
					}
					if value, ok := readObjectiveCSelectorRefAtVAIndexed(file, sections, target); ok {
						selectorRegisters[dst] = x86SelectorValue{selector: value, instruction: i}
					} else {
						delete(selectorRegisters, dst)
					}
				} else {
					delete(importPointerRegisters, dst)
					delete(selectorRegisters, dst)
					delete(objcClasses, dst)
				}
			} else {
				delete(stringRegisters, dst)
				delete(selectorRegisters, dst)
				delete(importPointerRegisters, dst)
				delete(objcClasses, dst)
			}
			if baseFresh && !loadsMemory {
				addressRegisters[dst] = x86AddressValue{value: target, instruction: i}
			} else {
				delete(addressRegisters, dst)
			}
			i += inst.Len
			continue
		}
		target := uint64(0)
		calledSymbols := importStubs
		callSize := 0
		directRelativeCall := inst.Op == x86asm.CALL && inst.Len == 5 && instruction[0] == 0xe8
		indirectImportCall := false
		if directRelativeCall {
			rel := int64(int32(binary.LittleEndian.Uint32(instruction[1:5])))
			target = uint64(int64(va+5) + rel)
			callSize = 5
		} else if inst.Op == x86asm.CALL {
			if pointerVA, ok := x86RIPRelativeIndirectCallPointer(va, instruction); ok && importPointers[pointerVA] != "" {
				target = pointerVA
				calledSymbols = importPointers
				callSize = inst.Len
				indirectImportCall = true
			} else if register, size, ok := x86RegisterIndirectCall(instruction); ok && size == inst.Len {
				pointer := importPointerRegisters[register]
				if pointer.Symbol != "" {
					target = pointer.SlotVA
					calledSymbols = importPointers
					callSize = inst.Len
					indirectImportCall = true
				}
			}
		}
		if callSize == 0 {
			if register, offset, size, ok := x86FrameRelativeLEA(instruction); ok && size == inst.Len {
				delete(stringRegisters, register)
				delete(selectorRegisters, register)
				delete(addressRegisters, register)
				delete(integerRegisters, register)
				delete(importPointerRegisters, register)
				delete(objcReceivers, register)
				delete(objcClasses, register)
				stackAddresses[register] = machoStackAddressValue{Offset: offset, Instruction: i}
				i += inst.Len
				continue
			}
			if source, offset, size, ok := x86RegisterStackStore(instruction, stackAddresses); ok && size == inst.Len {
				address, present := addressRegisters[source]
				if present && i-address.instruction <= 96 {
					if argument, ok := objcCFStringAtTargetLocationIndexed(file, objcStrings, address.value, false); ok {
						argument.ReferenceVA = va
						argument.ReferenceOff = int(text.Offset) + i
						stackSlots[offset] = machoObjCStackSlot{String: argument}
					} else {
						delete(stackSlots, offset)
					}
				} else {
					delete(stackSlots, offset)
				}
				i += inst.Len
				continue
			}
			if dst, src, size, ok := x86RegisterMove(instruction); ok && size == inst.Len {
				copyX86RegisterState(stringRegisters, selectorRegisters, dst, src, i)
				copyX86AddressState(addressRegisters, dst, src, i)
				copyMachOIntegerState(integerRegisters, dst, src, i)
				copyX86ImportedPointerState(importPointerRegisters, dst, src, i)
				copyMachOObjCReceiverState(objcReceivers, dst, src, i, va, int(text.Offset)+i)
				copyMachOObjCClassState(objcClasses, dst, src, i)
				copyMachOStackAddressState(stackAddresses, dst, src, i)
				i += inst.Len
				continue
			}
			if reg, value, size, ok := x86ImmediateRegister(instruction); ok && size == inst.Len {
				delete(stringRegisters, reg)
				delete(selectorRegisters, reg)
				delete(addressRegisters, reg)
				integerRegisters[reg] = machoRegisterInteger{value: value, instruction: i}
				delete(importPointerRegisters, reg)
				delete(objcReceivers, reg)
				delete(objcClasses, reg)
				delete(stackAddresses, reg)
				i += inst.Len
				continue
			}
			if reg, size, ok := x86RegisterWrite(instruction); ok && size == inst.Len {
				delete(stringRegisters, reg)
				delete(selectorRegisters, reg)
				delete(addressRegisters, reg)
				delete(integerRegisters, reg)
				delete(importPointerRegisters, reg)
				delete(objcReceivers, reg)
				delete(objcClasses, reg)
				delete(stackAddresses, reg)
				i += inst.Len
				continue
			}
			// Decoded instructions whose register/control-flow semantics are not
			// modeled invalidate all inferred values. This is intentionally
			// conservative and never re-enters in the middle of an instruction.
			clearX86RegisterState(stringRegisters, selectorRegisters)
			clearX86AddressState(addressRegisters)
			clearMachOIntegerState(integerRegisters)
			clearX86ImportedPointerState(importPointerRegisters)
			clearMachOObjCReceiverState(objcReceivers)
			clearMachOObjCClassState(objcClasses)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			pendingGoLaunch = nil
			i += inst.Len
			continue
		}
		callVA := va
		if candidates >= candidateLimit {
			return count, true
		}
		candidates++
		caller := functionForVA(functions, callVA)
		callee := machoFunction{}
		if directRelativeCall {
			callee = functionForVA(functions, target)
		}
		goContext := x86GoCallContext(sections, text.Offset, text.Addr, i, addressRegisters, integerRegisters)
		if pendingGoLaunch != nil {
			if directRelativeCall && callee.Start == target {
				addGoImmediateLaunchExecutionIndexed(lookup, pendingGoLaunch, caller, callee, callVA)
			}
			pendingGoLaunch = nil
		}
		objcContext := machoCallContext{}
		ownershipInput := objcReceivers[7]
		allocationClass := objcClasses[7]
		if i-allocationClass.Instruction > 96 {
			allocationClass = machoObjCClassValue{}
		}
		if isObjCMsgSendSymbol(calledSymbols[target]) || objcStubs[target] != "" {
			objcContext = x86ObjCStringCallContextIndexed(file, objcStrings, text, i, addressRegisters, integerRegisters, objcReceivers, stackAddresses, stackSlots)
		}
		selector := selectorRegisters[6]
		if selector.selector == "init" && (isObjCMsgSendSymbol(calledSymbols[target]) || objcStubs[target] != "") {
			if returned, ok := initializedMachOObjCReceiver(lookup, caller, callVA, int(text.Offset)+i, i, objcContext); ok {
				clearX86RegisterState(stringRegisters, selectorRegisters)
				clearX86AddressState(addressRegisters)
				clearMachOIntegerState(integerRegisters)
				preserveX86ImportedCalleeSaved(importPointerRegisters)
				preserveX86ObjCCalleeSaved(objcReceivers)
				preserveX86ObjCClassCalleeSaved(objcClasses)
				clearMachOStackAddressState(stackAddresses)
				clearMachOObjCStackSlots(stackSlots)
				objcReceivers[0] = returned
				i += callSize
				continue
			}
		}
		if addObjCMessageSendResolvedSelectorCallIndexed(lookup, functions, calledSymbols, selector.selector, selector.instruction, i, callVA, target, objcContext) {
			count++
			clearX86RegisterState(stringRegisters, selectorRegisters)
			clearX86AddressState(addressRegisters)
			clearMachOIntegerState(integerRegisters)
			preserveX86ImportedCalleeSaved(importPointerRegisters)
			preserveX86ObjCCalleeSaved(objcReceivers)
			preserveX86ObjCClassCalleeSaved(objcClasses)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			if returned, ok := lookup.objcReturns[callVA]; ok {
				returned.Instruction = i
				objcReceivers[0] = returned
				delete(lookup.objcReturns, callVA)
			}
			i += callSize
			continue
		}
		context := machoCallContext{}
		// x86_64 SysV passes the first six integer/pointer arguments in these
		// registers. Retain only fresh, exactly recovered C-string values.
		for position, register := range [...]uint8{7, 6, 2, 1, 8, 9} {
			argument := stringRegisters[register]
			if argument.value == "" || i-argument.instruction > 96 {
				continue
			}
			context.setStringArgument(position, machoCallStringArgument{
				Value: argument.value, ReferenceVA: argument.referenceVA, ReferenceOff: argument.referenceOff,
				LiteralVA: argument.literalVA, LiteralOffset: argument.literalOffset,
			})
		}
		if symbol := calledSymbols[target]; nativeConnectUsesSockaddr(symbol) {
			if address, ok := addressRegisters[6]; ok && i-address.instruction <= 96 {
				if socketAddress, ok := readMachOStaticSocketAddressIndexed(file, sections, address.value, false); ok {
					context.SocketAddress = socketAddress
				}
			}
		}
		if argvIndex, ok := nativeProcessArgvIndex(calledSymbols[target]); ok {
			argumentRegisters := [...]uint8{7, 6, 2, 1, 8, 9}
			if address, ok := addressRegisters[argumentRegisters[argvIndex]]; ok && i-address.instruction <= 96 {
				if arguments, ok := readMachOStaticArgvIndexed(file, sections, address.value); ok {
					context.ArgumentVector = arguments
				}
			}
		}
		importAdded := false
		if indirectImportCall {
			importAdded = addImportedPointerCallIndexed(lookup, functions, calledSymbols, callVA, target, context)
		} else {
			importAdded = addStubCallIndexed(lookup, functions, calledSymbols, callVA, target, context)
		}
		if importAdded {
			count++
			if !objcOwnershipOnlyCall(calledSymbols[target]) {
				invalidateNSTaskReceiverArguments(lookup, objcReceivers, uint8(7), uint8(6), uint8(2), uint8(1), uint8(8), uint8(9))
			}
			clearX86RegisterState(stringRegisters, selectorRegisters)
			clearX86AddressState(addressRegisters)
			clearMachOIntegerState(integerRegisters)
			preserveX86ImportedCalleeSaved(importPointerRegisters)
			preserveX86ObjCCalleeSaved(objcReceivers)
			preserveX86ObjCClassCalleeSaved(objcClasses)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			if receiver, ok := newMachOObjCReceiverValue(lookup, caller, callVA, int(text.Offset)+i, i, strings.TrimPrefix(calledSymbols[target], "_"), allocationClass); ok {
				objcReceivers[0] = receiver
			} else if objcOwnershipPassthrough(calledSymbols[target]) && ownershipInput.Identity != "" {
				ownershipInput.Instruction = i
				ownershipInput.ReferenceVA = callVA
				ownershipInput.ReferenceOff = int(text.Offset) + i
				objcReceivers[0] = ownershipInput
			}
			i += callSize
			continue
		}
		if !indirectImportCall && addObjCMessageStubCallWithContextIndexed(lookup, functions, objcStubs, callVA, target, objcContext) {
			count++
			clearX86RegisterState(stringRegisters, selectorRegisters)
			clearX86AddressState(addressRegisters)
			clearMachOIntegerState(integerRegisters)
			preserveX86ImportedCalleeSaved(importPointerRegisters)
			preserveX86ObjCCalleeSaved(objcReceivers)
			preserveX86ObjCClassCalleeSaved(objcClasses)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			if returned, ok := lookup.objcReturns[callVA]; ok {
				returned.Instruction = i
				objcReceivers[0] = returned
				delete(lookup.objcReturns, callVA)
			}
			i += callSize
			continue
		}
		if directRelativeCall && addLocalCallFeatureIndexed(lookup, functions, callVA, target) {
			count++
		}
		swiftObjCReceiver, hasSwiftObjCReceiver := newMachOSwiftObjCConstructorReceiver(lookup, caller, callee, callVA, int(text.Offset)+i, i)
		invalidateNSTaskReceiverArguments(lookup, objcReceivers, uint8(7), uint8(6), uint8(2), uint8(1), uint8(8), uint8(9))
		if directRelativeCall && callee.Start == target {
			pendingGoLaunch = addGoLocalCallSemanticsIndexed(lookup, caller, callee, callVA, goContext, i+callSize)
		}
		if lookup.graph.WorkLimitReached() {
			lookup.graph.MarkWorkOmitted()
			return count, true
		}
		clearX86RegisterState(stringRegisters, selectorRegisters)
		clearX86AddressState(addressRegisters)
		clearMachOIntegerState(integerRegisters)
		preserveX86ImportedCalleeSaved(importPointerRegisters)
		preserveX86ObjCCalleeSaved(objcReceivers)
		preserveX86ObjCClassCalleeSaved(objcClasses)
		clearMachOStackAddressState(stackAddresses)
		clearMachOObjCStackSlots(stackSlots)
		if directRelativeCall && callee.Start == target && hasSwiftObjCReceiver {
			objcReceivers[0] = swiftObjCReceiver
		}
		i += callSize
	}
	return count, truncated || objcStrings.truncated
}

func clearX86RegisterState(strings map[uint8]x86StringValue, selectors map[uint8]x86SelectorValue) {
	for register := range strings {
		delete(strings, register)
	}
	for register := range selectors {
		delete(selectors, register)
	}
}

type machoRegisterIndex interface {
	~uint8 | ~uint32
}

func clearMachOIntegerState[T machoRegisterIndex](integers map[T]machoRegisterInteger) {
	for register := range integers {
		delete(integers, register)
	}
}

func copyMachOIntegerState[T machoRegisterIndex](integers map[T]machoRegisterInteger, dst, src T, instruction int) {
	if value, ok := integers[src]; ok {
		value.instruction = instruction
		integers[dst] = value
	} else {
		delete(integers, dst)
	}
}

func copyX86RegisterState(strings map[uint8]x86StringValue, selectors map[uint8]x86SelectorValue, dst, src uint8, instruction int) {
	if value, ok := strings[src]; ok {
		value.instruction = instruction
		strings[dst] = value
	} else {
		delete(strings, dst)
	}
	if value, ok := selectors[src]; ok {
		value.instruction = instruction
		selectors[dst] = value
	} else {
		delete(selectors, dst)
	}
}

func x86RegisterMove(data []byte) (dst, src uint8, size int, ok bool) {
	// State propagation requires one canonical 64-bit register move. A missing
	// REX.W, legacy prefix, or repeated REX sequence cannot preserve a pointer.
	if len(data) < 3 || data[0] < 0x48 || data[0] > 0x4f {
		return 0, 0, 0, false
	}
	const i = 1
	rex := data[0]
	rexR := ((rex >> 2) & 0x1) * 8
	rexB := (rex & 0x1) * 8
	opcode := data[i]
	if opcode != 0x89 && opcode != 0x8b {
		return 0, 0, 0, false
	}
	modrm := data[i+1]
	if modrm>>6 != 3 {
		return 0, 0, 0, false
	}
	reg := ((modrm >> 3) & 0x7) | rexR
	rm := (modrm & 0x7) | rexB
	switch opcode {
	case 0x89:
		return rm, reg, i + 2, true
	case 0x8b:
		return reg, rm, i + 2, true
	default:
		return 0, 0, 0, false
	}
}

func x86ImmediateRegister(data []byte) (register uint8, value uint64, size int, ok bool) {
	if len(data) < 5 {
		return 0, 0, 0, false
	}
	prefixSize := 0
	rex := byte(0)
	if data[0] >= 0x40 && data[0] <= 0x4f {
		rex = data[0]
		prefixSize = 1
	}
	if len(data) <= prefixSize {
		return 0, 0, 0, false
	}
	opcode := data[prefixSize]
	if opcode < 0xb8 || opcode > 0xbf {
		return 0, 0, 0, false
	}
	register = opcode - 0xb8
	if rex&0x1 != 0 {
		register += 8
	}
	if rex&0x8 != 0 {
		size = prefixSize + 9
		if len(data) < size {
			return 0, 0, 0, false
		}
		return register, binary.LittleEndian.Uint64(data[prefixSize+1 : size]), size, true
	}
	size = prefixSize + 5
	if len(data) < size {
		return 0, 0, 0, false
	}
	// A 32-bit register write zero-extends to the full amd64 register.
	return register, uint64(binary.LittleEndian.Uint32(data[prefixSize+1 : size])), size, true
}

func x86RegisterWrite(data []byte) (reg uint8, size int, ok bool) {
	i := 0
	var rex byte
	if len(data) > 0 && data[0] >= 0x40 && data[0] <= 0x4f {
		rex = data[0]
		i = 1
	}
	if i >= len(data) {
		return 0, 0, false
	}
	// No legacy-prefix or multiple-REX interpretation is attempted here. The
	// caller treats an unmodeled decoded instruction as a boundary and clears
	// all inferred state, which is safer than accumulating hostile prefixes.
	if data[i] == 0x66 || data[i] >= 0x40 && data[i] <= 0x4f {
		return 0, 0, false
	}
	rexW := rex&0x8 != 0
	rexR := ((rex >> 2) & 0x1) * 8
	rexB := (rex & 0x1) * 8
	opcode := data[i]
	if opcode >= 0xb8 && opcode <= 0xbf {
		size = i + 5
		if rexW {
			size = i + 9
		}
		if size > len(data) {
			return 0, 0, false
		}
		return (opcode - 0xb8) | rexB, size, true
	}
	if i+2 > len(data) {
		return 0, 0, false
	}
	modrm := data[i+1]
	mod := modrm >> 6
	switch opcode {
	case 0x89:
		if mod != 3 {
			return 0, 0, false
		}
		return (modrm & 0x7) | rexB, i + 2, true
	case 0x01, 0x09, 0x11, 0x19, 0x21, 0x29, 0x31:
		if mod != 3 {
			return 0, 0, false
		}
		return (modrm & 0x7) | rexB, i + 2, true
	case 0x8b, 0x8d:
		instructionSize := i + x86ModRMInstructionSize(data[i:])
		if instructionSize <= i || instructionSize > len(data) {
			return 0, 0, false
		}
		return ((modrm >> 3) & 0x7) | rexR, instructionSize, true
	default:
		return 0, 0, false
	}
}

func x86ModRMInstructionSize(data []byte) int {
	if len(data) < 2 {
		return 0
	}
	size := 2
	modrm := data[1]
	mod := modrm >> 6
	rm := modrm & 0x7
	if mod != 3 && rm == 4 {
		if len(data) <= size {
			return 0
		}
		sib := data[size]
		size++
		base := sib & 0x7
		if mod == 0 && base == 5 {
			size += 4
		}
	} else if mod == 0 && rm == 5 {
		size += 4
	}
	switch mod {
	case 1:
		size++
	case 2:
		size += 4
	}
	if size > len(data) {
		return 0
	}
	return size
}

func extractArm64DirectCalls(graph *behavior.Graph, content artifact.Content, file *macho.File, text *macho.Section, data []byte, functions []machoFunction, importStubs, objcStubs map[uint64]string, arch string) int {
	count, _ := extractArm64DirectCallsIndexed(newMachOCallLookup(graph, content, arch), file, text, data, functions, importStubs, objcStubs, maxMachODirectCallScanBytes, maxMachODirectCallCandidates)
	return count
}

func extractArm64DirectCallsIndexed(lookup *machoCallLookup, file *macho.File, text *macho.Section, data []byte, functions []machoFunction, importStubs, objcStubs map[uint64]string, byteLimit, candidateLimit int) (int, bool) {
	return extractArm64DirectCallsIndexedWithRanges(lookup, file, text, data, functions, importStubs, objcStubs, byteLimit, candidateLimit, nil)
}

func extractArm64DirectCallsIndexedWithRanges(lookup *machoCallLookup, file *macho.File, text *macho.Section, data []byte, functions []machoFunction, importStubs, objcStubs map[uint64]string, byteLimit, candidateLimit int, dataRanges []machoCodeRange) (int, bool) {
	data, truncated := boundedMachOCallData(data, byteLimit)
	sections := lookup.sectionIndexFor(file)
	importPointers, importPointersTruncated := importedPointerMapForLookup(file, lookup, maxMachOStubRecords)
	if importPointersTruncated {
		addPartialCoverageOnce(lookup.graph, lookup.content.NodeID, "macho-stubs/"+lookup.arch, fmt.Sprintf("stub and indirect-symbol-pointer extraction capped at %d records", maxMachOStubRecords))
	}
	objcStrings := newMachOCFStringReader(sections, maxMachOCFStringBackingBytes)
	count := 0
	candidates := 0
	registers := map[uint32]arm64RegisterValue{}
	integerRegisters := map[uint32]machoRegisterInteger{}
	selectors := map[uint32]arm64SelectorValue{}
	objcReceivers := map[uint32]machoObjCReceiverValue{}
	objcClasses := map[uint32]machoObjCClassValue{}
	objcReceiverStackSlots := map[int64]machoObjCReceiverValue{}
	stackAddresses := map[uint32]machoStackAddressValue{}
	stackSlots := map[int64]machoObjCStackSlot{}
	var pendingGoLaunch *machoGoLaunchConfiguration
	currentFunction := -2
	for i := 0; i+4 <= len(data); i += 4 {
		if i&0xfff == 0 && lookup.graph.WorkLimitReached() {
			lookup.graph.MarkWorkOmitted()
			return count, true
		}
		va := text.Addr + uint64(i)
		if pendingGoLaunch != nil && pendingGoLaunch.nextOffset != i {
			pendingGoLaunch = nil
		}
		if functionIndex := functionIndexForVA(functions, va); functionIndex != currentFunction {
			clearArm64RegisterState(registers, selectors)
			clearMachOIntegerState(integerRegisters)
			clearMachOObjCReceiverState(objcReceivers)
			clearMachOObjCClassState(objcClasses)
			clear(objcReceiverStackSlots)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			pendingGoLaunch = nil
			currentFunction = functionIndex
		}
		if _, excluded := machoCodeInstructionExcluded(i, 4, dataRanges); excluded {
			clearArm64RegisterState(registers, selectors)
			clearMachOIntegerState(integerRegisters)
			clearMachOObjCReceiverState(objcReceivers)
			clearMachOObjCClassState(objcClasses)
			clear(objcReceiverStackSlots)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			pendingGoLaunch = nil
			continue
		}
		insn := file.ByteOrder.Uint32(data[i : i+4])
		if destination, ok := arm64FrameAddressDestination(insn); ok {
			delete(registers, destination)
			delete(integerRegisters, destination)
			delete(selectors, destination)
			delete(objcReceivers, destination)
			delete(objcClasses, destination)
			delete(stackAddresses, destination)
			// Once a caller-frame address is materialized, an exact local call
			// could mutate a tracked slot through that alias. Discard all prior
			// frame-slot identities rather than attempting pointer escape flow.
			clear(objcReceiverStackSlots)
			continue
		}
		if register, offset, load, ok := arm64FrameRelativeReceiverAccess(insn); ok {
			if !load {
				// SP and x29 share a frame whose relative displacement is not
				// modeled. A frame store may overwrite an SP-relative array.
				clearMachOObjCStackSlots(stackSlots)
				// STUR permits unaligned writes, so remove every overlapping
				// pointer slot, not only one starting at the same offset.
				for slotOffset := range objcReceiverStackSlots {
					if slotOffset > offset-8 && slotOffset < offset+8 {
						delete(objcReceiverStackSlots, slotOffset)
					}
				}
			}
			if load {
				delete(registers, register)
				delete(integerRegisters, register)
				delete(selectors, register)
				delete(objcClasses, register)
				delete(stackAddresses, register)
				if receiver, present := objcReceiverStackSlots[offset]; present {
					receiver.Instruction = i
					receiver.ReferenceVA = va
					receiver.ReferenceOff = int(text.Offset) + i
					objcReceivers[register] = receiver
				} else {
					delete(objcReceivers, register)
				}
			} else if receiver, present := objcReceivers[register]; present {
				receiver.Instruction = i
				receiver.ReferenceVA = va
				receiver.ReferenceOff = int(text.Offset) + i
				objcReceiverStackSlots[offset] = receiver
			} else {
				delete(objcReceiverStackSlots, offset)
			}
			continue
		}
		if rd, target, ok := arm64ADRTarget(va, insn); ok {
			registers[rd] = arm64RegisterValue{value: target, instruction: i}
			delete(integerRegisters, rd)
			delete(selectors, rd)
			delete(objcReceivers, rd)
			delete(objcClasses, rd)
			delete(stackAddresses, rd)
			continue
		}
		if rd, offset, ok := arm64SPRelativeAddress(insn); ok {
			delete(registers, rd)
			delete(integerRegisters, rd)
			delete(selectors, rd)
			delete(objcReceivers, rd)
			delete(objcClasses, rd)
			stackAddresses[rd] = machoStackAddressValue{Offset: offset, Instruction: i}
			continue
		}
		if first, second, offset, ok := arm64SPRelativePairStore(insn); ok {
			clear(objcReceiverStackSlots)
			for index, register := range []uint32{first, second} {
				slotOffset := offset + int64(index*8)
				address, present := registers[register]
				if present && i-address.instruction <= 96 {
					if argument, ok := objcCFStringAtTargetLocationIndexed(file, objcStrings, address.value, address.loadsMemory); ok {
						argument.ReferenceVA = va
						argument.ReferenceOff = int(text.Offset) + i
						stackSlots[slotOffset] = machoObjCStackSlot{String: argument}
						continue
					}
				}
				delete(stackSlots, slotOffset)
			}
			continue
		}
		if register, offset, ok := arm64SPRelativeStore(insn); ok {
			clear(objcReceiverStackSlots)
			address, present := registers[register]
			if present && i-address.instruction <= 96 {
				if argument, ok := objcCFStringAtTargetLocationIndexed(file, objcStrings, address.value, address.loadsMemory); ok {
					argument.ReferenceVA = va
					argument.ReferenceOff = int(text.Offset) + i
					stackSlots[offset] = machoObjCStackSlot{String: argument}
					continue
				}
			}
			delete(stackSlots, offset)
			continue
		}
		if rd, rn, imm, ok := arm64ADDImmediate(insn); ok {
			base, ok := registers[rn]
			if !ok || base.loadsMemory || i-base.instruction > 64 {
				delete(registers, rd)
				delete(integerRegisters, rd)
				delete(selectors, rd)
				delete(objcReceivers, rd)
				delete(objcClasses, rd)
				delete(stackAddresses, rd)
				continue
			}
			registers[rd] = arm64RegisterValue{value: base.value + imm, instruction: i, loadsMemory: base.loadsMemory}
			delete(integerRegisters, rd)
			delete(selectors, rd)
			delete(objcReceivers, rd)
			delete(objcClasses, rd)
			delete(stackAddresses, rd)
			continue
		}
		if rt, rn, offset, ok := arm64LDRUnsignedImmediate(insn); ok {
			base, ok := registers[rn]
			if !ok || base.loadsMemory || i-base.instruction > 64 {
				delete(registers, rt)
				delete(integerRegisters, rt)
				delete(selectors, rt)
				delete(objcReceivers, rt)
				delete(objcClasses, rt)
				delete(stackAddresses, rt)
				continue
			}
			pointerVA := base.value + offset
			registers[rt] = arm64RegisterValue{value: pointerVA, instruction: i, loadsMemory: true}
			delete(integerRegisters, rt)
			delete(objcReceivers, rt)
			delete(stackAddresses, rt)
			if class, ok := objcClassNameFromImportedSymbol(importPointers[pointerVA]); ok {
				objcClasses[rt] = machoObjCClassValue{Name: class, Instruction: i, ReferenceVA: va, ReferenceOff: int(text.Offset) + i, SlotVA: pointerVA}
			} else {
				delete(objcClasses, rt)
			}
			if selector, ok := readObjectiveCSelectorRefAtVAIndexed(file, sections, pointerVA); ok {
				selectors[rt] = arm64SelectorValue{selector: selector, instruction: i}
			} else {
				delete(selectors, rt)
			}
			continue
		}
		if rt, pointerVA, ok := arm64LDRLiteralTarget(va, insn); ok {
			registers[rt] = arm64RegisterValue{value: pointerVA, instruction: i, loadsMemory: true}
			delete(integerRegisters, rt)
			delete(objcReceivers, rt)
			delete(stackAddresses, rt)
			if class, ok := objcClassNameFromImportedSymbol(importPointers[pointerVA]); ok {
				objcClasses[rt] = machoObjCClassValue{Name: class, Instruction: i, ReferenceVA: va, ReferenceOff: int(text.Offset) + i, SlotVA: pointerVA}
			} else {
				delete(objcClasses, rt)
			}
			if selector, ok := readObjectiveCSelectorRefAtVAIndexed(file, sections, pointerVA); ok {
				selectors[rt] = arm64SelectorValue{selector: selector, instruction: i}
			} else {
				delete(selectors, rt)
			}
			continue
		}
		if rd, rn, ok := arm64MOVRegister(insn); ok {
			copyArm64RegisterState(registers, selectors, rd, rn, i)
			copyMachOIntegerState(integerRegisters, rd, rn, i)
			copyMachOObjCReceiverState(objcReceivers, rd, rn, i, va, int(text.Offset)+i)
			copyMachOObjCClassState(objcClasses, rd, rn, i)
			copyMachOStackAddressState(stackAddresses, rd, rn, i)
			continue
		}
		if rd, value, ok := arm64ImmediateRegister(insn); ok {
			delete(registers, rd)
			delete(selectors, rd)
			integerRegisters[rd] = machoRegisterInteger{value: value, instruction: i}
			delete(objcReceivers, rd)
			delete(objcClasses, rd)
			delete(stackAddresses, rd)
			continue
		}
		if rd, ok := arm64ADDImmediateDestination(insn); ok {
			// An address calculation rooted at SP is not a static image pointer,
			// but it has a known single destination and need not destroy other
			// independently recovered ABI arguments.
			delete(registers, rd)
			delete(selectors, rd)
			delete(integerRegisters, rd)
			delete(objcReceivers, rd)
			delete(objcClasses, rd)
			delete(stackAddresses, rd)
			continue
		}
		if register, _, load, ok := arm64KnownMemoryAccess(insn); ok {
			if load && register != 31 {
				delete(registers, register)
				delete(integerRegisters, register)
				delete(selectors, register)
				delete(objcReceivers, register)
				delete(objcClasses, register)
				delete(stackAddresses, register)
			}
			if !load {
				// Stores outside the exact tracked forms may overlap either
				// kind of frame slot, including through a register alias. Keep
				// register arguments, but do not retain stale memory values.
				clear(objcReceiverStackSlots)
				clearMachOObjCStackSlots(stackSlots)
			}
			continue
		}
		if insn&0xfc000000 != 0x94000000 {
			if arm64BreaksLinearState(insn) {
				clearArm64RegisterState(registers, selectors)
				clearMachOIntegerState(integerRegisters)
				clearMachOObjCReceiverState(objcReceivers)
				clearMachOObjCClassState(objcClasses)
				clear(objcReceiverStackSlots)
				clearMachOStackAddressState(stackAddresses)
				clearMachOObjCStackSlots(stackSlots)
				pendingGoLaunch = nil
				continue
			}
			// Unknown instructions are a data-flow boundary. Clear every inferred
			// value rather than assuming the low five bits identify the only
			// destination register.
			clearArm64RegisterState(registers, selectors)
			clearMachOIntegerState(integerRegisters)
			clearMachOObjCReceiverState(objcReceivers)
			clearMachOObjCClassState(objcClasses)
			clear(objcReceiverStackSlots)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			pendingGoLaunch = nil
			continue
		}
		imm := int32(insn&0x03ffffff) << 6 >> 4
		callVA := va
		target := uint64(int64(va) + int64(imm))
		if candidates >= candidateLimit {
			return count, true
		}
		candidates++
		caller := functionForVA(functions, callVA)
		callee := functionForVA(functions, target)
		goContext := arm64GoCallContext(sections, text.Offset, text.Addr, i, registers, integerRegisters)
		if pendingGoLaunch != nil {
			if callee.Start == target {
				addGoImmediateLaunchExecutionIndexed(lookup, pendingGoLaunch, caller, callee, callVA)
			}
			pendingGoLaunch = nil
		}
		objcContext := machoCallContext{}
		ownershipInput := objcReceivers[0]
		allocationClass := objcClasses[0]
		if i-allocationClass.Instruction > 96 {
			allocationClass = machoObjCClassValue{}
		}
		if isObjCMsgSendSymbol(importStubs[target]) || objcStubs[target] != "" {
			objcContext = arm64ObjCStringCallContextIndexed(file, objcStrings, text, i, registers, integerRegisters, objcReceivers, stackAddresses, stackSlots)
		}
		selector := selectors[1]
		if selector.selector == "init" && (isObjCMsgSendSymbol(importStubs[target]) || objcStubs[target] != "") {
			if returned, ok := initializedMachOObjCReceiver(lookup, caller, callVA, int(text.Offset)+i, i, objcContext); ok {
				clearArm64RegisterState(registers, selectors)
				clearMachOIntegerState(integerRegisters)
				preserveArm64ObjCCalleeSaved(objcReceivers)
				preserveArm64ObjCClassCalleeSaved(objcClasses)
				clearMachOStackAddressState(stackAddresses)
				clearMachOObjCStackSlots(stackSlots)
				objcReceivers[0] = returned
				continue
			}
		}
		if addObjCMessageSendSelectorCallIndexed(lookup, functions, importStubs, selectors, i, callVA, target, objcContext) {
			count++
			clearArm64RegisterState(registers, selectors)
			clearMachOIntegerState(integerRegisters)
			preserveArm64ObjCCalleeSaved(objcReceivers)
			preserveArm64ObjCClassCalleeSaved(objcClasses)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			if returned, ok := lookup.objcReturns[callVA]; ok {
				returned.Instruction = i
				objcReceivers[0] = returned
				delete(lookup.objcReturns, callVA)
			}
			continue
		}
		context := machoCallContext{}
		// AAPCS64 passes the leading integer/pointer arguments in x0-x7. Six
		// positions cover the native primitives modeled below while keeping the
		// context and evidence work tightly bounded.
		for position := 0; position < len(context.StringArguments); position++ {
			argument, ok := registers[uint32(position)]
			if !ok || i-argument.instruction > 96 {
				continue
			}
			value, literalVA, literalOffset, ok := cstringAtTargetLocationIndexed(file, sections, argument.value, argument.loadsMemory)
			if !ok {
				continue
			}
			context.setStringArgument(position, machoCallStringArgument{
				Value: value, ReferenceVA: text.Addr + uint64(argument.instruction), ReferenceOff: int(text.Offset) + argument.instruction,
				LiteralVA: literalVA, LiteralOffset: literalOffset,
			})
		}
		if symbol := importStubs[target]; nativeConnectUsesSockaddr(symbol) {
			if address, ok := registers[1]; ok && i-address.instruction <= 96 {
				if socketAddress, ok := readMachOStaticSocketAddressIndexed(file, sections, address.value, address.loadsMemory); ok {
					context.SocketAddress = socketAddress
				}
			}
		}
		if argvIndex, ok := nativeProcessArgvIndex(importStubs[target]); ok {
			if address, ok := registers[uint32(argvIndex)]; ok && !address.loadsMemory && i-address.instruction <= 96 {
				if arguments, ok := readMachOStaticArgvIndexed(file, sections, address.value); ok {
					context.ArgumentVector = arguments
				}
			}
		}
		if addStubCallIndexed(lookup, functions, importStubs, callVA, target, context) {
			count++
			if !objcOwnershipOnlyCall(importStubs[target]) {
				invalidateNSTaskReceiverArguments(lookup, objcReceivers, uint32(0), uint32(1), uint32(2), uint32(3), uint32(4), uint32(5), uint32(6), uint32(7))
			}
			clearArm64RegisterState(registers, selectors)
			clearMachOIntegerState(integerRegisters)
			preserveArm64ObjCCalleeSaved(objcReceivers)
			preserveArm64ObjCClassCalleeSaved(objcClasses)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			if receiver, ok := newMachOObjCReceiverValue(lookup, caller, callVA, int(text.Offset)+i, i, strings.TrimPrefix(importStubs[target], "_"), allocationClass); ok {
				objcReceivers[0] = receiver
			} else if objcOwnershipPassthrough(importStubs[target]) && ownershipInput.Identity != "" {
				ownershipInput.Instruction = i
				ownershipInput.ReferenceVA = callVA
				ownershipInput.ReferenceOff = int(text.Offset) + i
				objcReceivers[0] = ownershipInput
			}
			continue
		}
		if addObjCMessageStubCallWithContextIndexed(lookup, functions, objcStubs, callVA, target, objcContext) {
			count++
			clearArm64RegisterState(registers, selectors)
			clearMachOIntegerState(integerRegisters)
			preserveArm64ObjCCalleeSaved(objcReceivers)
			preserveArm64ObjCClassCalleeSaved(objcClasses)
			clearMachOStackAddressState(stackAddresses)
			clearMachOObjCStackSlots(stackSlots)
			if returned, ok := lookup.objcReturns[callVA]; ok {
				returned.Instruction = i
				objcReceivers[0] = returned
				delete(lookup.objcReturns, callVA)
			}
			continue
		}
		if addLocalCallFeatureIndexed(lookup, functions, callVA, target) {
			count++
		}
		swiftObjCReceiver, hasSwiftObjCReceiver := newMachOSwiftObjCConstructorReceiver(lookup, caller, callee, callVA, int(text.Offset)+i, i)
		invalidateNSTaskReceiverArguments(lookup, objcReceivers, uint32(0), uint32(1), uint32(2), uint32(3), uint32(4), uint32(5), uint32(6), uint32(7))
		if callee.Start == target {
			pendingGoLaunch = addGoLocalCallSemanticsIndexed(lookup, caller, callee, callVA, goContext, i+4)
		}
		if lookup.graph.WorkLimitReached() {
			lookup.graph.MarkWorkOmitted()
			return count, true
		}
		clearArm64RegisterState(registers, selectors)
		clearMachOIntegerState(integerRegisters)
		preserveArm64ObjCCalleeSaved(objcReceivers)
		preserveArm64ObjCClassCalleeSaved(objcClasses)
		clearMachOStackAddressState(stackAddresses)
		clearMachOObjCStackSlots(stackSlots)
		if callee.Start == target && hasSwiftObjCReceiver {
			objcReceivers[0] = swiftObjCReceiver
		}
	}
	return count, truncated || objcStrings.truncated
}

func arm64BreaksLinearState(insn uint32) bool {
	// BR/BLR/RET and direct/conditional branches terminate the current linear
	// register-value path. Direct BL is handled separately by the caller.
	if insn&0xfffffc1f == 0xd61f0000 || insn&0xfffffc1f == 0xd63f0000 || insn&0xfffffc1f == 0xd65f0000 {
		return true
	}
	if insn&0x7c000000 == 0x14000000 || insn&0xff000010 == 0x54000000 {
		return true
	}
	return insn&0x7e000000 == 0x34000000 || insn&0x7e000000 == 0x36000000
}

func copyArm64RegisterState(registers map[uint32]arm64RegisterValue, selectors map[uint32]arm64SelectorValue, dst, src uint32, instruction int) {
	if value, ok := registers[src]; ok {
		value.instruction = instruction
		registers[dst] = value
	} else {
		delete(registers, dst)
	}
	if value, ok := selectors[src]; ok {
		value.instruction = instruction
		selectors[dst] = value
	} else {
		delete(selectors, dst)
	}
}

func clearArm64RegisterState(registers map[uint32]arm64RegisterValue, selectors map[uint32]arm64SelectorValue) {
	for register := range registers {
		delete(registers, register)
	}
	for register := range selectors {
		delete(selectors, register)
	}
}

func arm64ObjCStringCallContextIndexed(file *macho.File, reader *machoCFStringReader, text *macho.Section, instructionOffset int, registers map[uint32]arm64RegisterValue, integers map[uint32]machoRegisterInteger, receivers map[uint32]machoObjCReceiverValue, stackAddresses map[uint32]machoStackAddressValue, stackSlots map[int64]machoObjCStackSlot) machoCallContext {
	var context machoCallContext
	if receiver, ok := receivers[0]; ok && instructionOffset-receiver.Instruction <= 96 {
		context.setObjCReceiver(receiver)
	}
	for position := 2; position < len(context.StringArguments); position++ {
		address, ok := registers[uint32(position)]
		if !ok || instructionOffset-address.instruction > 96 {
			continue
		}
		argument, ok := objcCFStringAtTargetLocationIndexed(file, reader, address.value, address.loadsMemory)
		if !ok {
			continue
		}
		argument.ReferenceVA = text.Addr + uint64(address.instruction)
		argument.ReferenceOff = int(text.Offset) + address.instruction
		context.setStringArgument(position, argument)
	}
	for position := 2; position < len(context.ObjCStringArrays); position++ {
		address, ok := registers[uint32(position)]
		if !ok || instructionOffset-address.instruction > 96 {
			continue
		}
		array, ok := objcCFStringArrayAtTargetLocationIndexed(file, reader, address.value, address.loadsMemory)
		if !ok {
			continue
		}
		array.ReferenceVA = text.Addr + uint64(address.instruction)
		array.ReferenceOff = int(text.Offset) + address.instruction
		context.setObjCStringArray(position, array)
	}
	for position := 2; position < len(context.ObjCStringArrays); position++ {
		object, ok := receivers[uint32(position)]
		if !ok || instructionOffset-object.Instruction > 96 || len(object.StringArray.Elements) == 0 {
			continue
		}
		array := object.StringArray
		array.ReferenceVA = object.ReferenceVA
		array.ReferenceOff = object.ReferenceOff
		context.setObjCStringArray(position, array)
	}
	if address, ok := stackAddresses[2]; ok && instructionOffset-address.Instruction <= 96 {
		if count, ok := integers[3]; ok && instructionOffset-count.instruction <= 96 {
			if array, ok := objcStringArrayFromStack(address, count.value, stackSlots, text.Addr+uint64(address.Instruction), int(text.Offset)+address.Instruction); ok {
				context.setObjCStringArray(2, array)
			}
		}
	}
	return context
}

func addStubCallIndexed(lookup *machoCallLookup, functions []machoFunction, stubs map[uint64]string, callVA, target uint64, context machoCallContext) bool {
	return addImportedSymbolCallIndexed(lookup, functions, stubs, callVA, target, context, "macho-stub", "imported-stub-call", "stub")
}

func addImportedPointerCallIndexed(lookup *machoCallLookup, functions []machoFunction, pointers map[uint64]string, callVA, target uint64, context machoCallContext) bool {
	return addImportedSymbolCallIndexed(lookup, functions, pointers, callVA, target, context, "macho-indirect-symbol-pointer", "imported-pointer-call", "indirect-symbol-pointer")
}

func addImportedSymbolCallIndexed(lookup *machoCallLookup, functions []machoFunction, symbols map[uint64]string, callVA, target uint64, context machoCallContext, evidenceMethod, evidenceKind, via string) bool {
	symbol, ok := symbols[target]
	if !ok {
		return false
	}
	if !isSemanticImportedSymbol(symbol) {
		return true
	}
	fn := functionForVA(functions, callVA)
	scopeID := lookup.functionScopeID(fn)
	ev := lookup.graph.AddEvidence(behavior.Evidence{
		NodeID:   lookup.content.NodeID,
		ScopeID:  scopeID,
		Logical:  lookup.content.LogicalPath,
		VA:       callVA,
		Function: fn.Name,
		Arch:     lookup.arch,
		Method:   evidenceMethod,
		Kind:     evidenceKind,
		Value:    fn.Name + " -> " + strings.TrimPrefix(symbol, "_"),
	})
	if ev == "" {
		return true
	}
	context.materializeStringArgumentEvidence(lookup, fn, scopeID, machoStringArgumentIndexesForSymbol(symbol)...)
	if nativeConnectUsesSockaddr(symbol) {
		context.materializeSocketAddressEvidence(lookup, fn, scopeID)
	}
	lookup.addFeature(behavior.Feature{
		NodeID:         lookup.content.NodeID,
		ScopeID:        scopeID,
		Architecture:   lookup.arch,
		Key:            "macho.import_call",
		Value:          strings.TrimPrefix(symbol, "_"),
		EvidenceIDs:    []string{ev},
		Support:        behavior.SupportCorroborated,
		Execution:      executionContextForMachOFunction(lookup.content, fn),
		SourceFunction: fn.Name,
		Qualifiers:     machoFunctionQualifiers(fn, map[string]string{"function": fn.Name, "via": via}),
	})
	addOperationFromCalledImportedSymbolWithContextIndexed(lookup, symbol, ev, fn, context)
	return true
}

func (context *machoCallContext) materializeStringArgumentEvidence(lookup *machoCallLookup, function machoFunction, scopeID string, positions ...int) {
	if context == nil || lookup == nil {
		return
	}
	for _, position := range positions {
		if position < 0 || position >= len(context.StringArguments) {
			continue
		}
		argument := &context.StringArguments[position]
		if argument.Value == "" || argument.ReferenceVA == 0 || argument.LiteralVA == 0 {
			continue
		}
		referenceID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, argument.ReferenceOff, behavior.Evidence{
			NodeID: lookup.content.NodeID, ScopeID: scopeID, Logical: lookup.content.LogicalPath,
			VA: argument.ReferenceVA, Function: function.Name, Arch: lookup.arch,
			Method: "macho-call-argument-dataflow", Kind: "call-string-argument-reference",
			Value: fmt.Sprintf("arg%d -> %s", position, evidenceSnippet(argument.Value)),
		}))
		literalID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, argument.LiteralOffset, behavior.Evidence{
			NodeID: lookup.content.NodeID, ScopeID: scopeID, Logical: lookup.content.LogicalPath,
			VA: argument.LiteralVA, Function: function.Name, Arch: lookup.arch,
			Method: "macho-call-argument-literal", Kind: "call-string-argument-literal",
			Value: evidenceSnippet(argument.Value),
		}))
		if referenceID == "" || literalID == "" {
			lookup.graph.MarkWorkOmitted()
			argument.EvidenceIDs = nil
			continue
		}
		argument.EvidenceIDs = []string{referenceID, literalID}
		if argument.BackingVA != 0 && argument.BackingVA != argument.LiteralVA {
			backingID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, argument.BackingOffset, behavior.Evidence{
				NodeID: lookup.content.NodeID, ScopeID: scopeID, Logical: lookup.content.LogicalPath,
				VA: argument.BackingVA, Function: function.Name, Arch: lookup.arch,
				Method: "macho-call-argument-backing", Kind: "call-string-argument-backing",
				Value: evidenceSnippet(argument.Value),
			}))
			if backingID == "" {
				lookup.graph.MarkWorkOmitted()
				argument.EvidenceIDs = nil
				continue
			}
			argument.EvidenceIDs = append(argument.EvidenceIDs, backingID)
		}
	}
}

func addObjCMessageStubCall(graph *behavior.Graph, content artifact.Content, functions []machoFunction, stubs map[uint64]string, callVA, target uint64, arch string) bool {
	return addObjCMessageStubCallWithContext(graph, content, functions, stubs, callVA, target, arch, machoCallContext{})
}

func addObjCMessageStubCallWithContext(graph *behavior.Graph, content artifact.Content, functions []machoFunction, stubs map[uint64]string, callVA, target uint64, arch string, context machoCallContext) bool {
	return addObjCMessageStubCallWithContextIndexed(newMachOCallLookup(graph, content, arch), functions, stubs, callVA, target, context)
}

func addObjCMessageStubCallWithContextIndexed(lookup *machoCallLookup, functions []machoFunction, stubs map[uint64]string, callVA, target uint64, context machoCallContext) bool {
	selector, ok := stubs[target]
	if !ok {
		return false
	}
	addObjCMessageCallIndexed(lookup, functions, selector, "objc-msgsend-stub", callVA, context)
	return true
}

func addObjCMessageSendSelectorCallIndexed(lookup *machoCallLookup, functions []machoFunction, importStubs map[uint64]string, selectors map[uint32]arm64SelectorValue, instructionOffset int, callVA, target uint64, context machoCallContext) bool {
	selector, ok := selectors[1]
	if !ok {
		return false
	}
	return addObjCMessageSendResolvedSelectorCallIndexed(lookup, functions, importStubs, selector.selector, selector.instruction, instructionOffset, callVA, target, context)
}

func addObjCMessageSendResolvedSelectorCallIndexed(lookup *machoCallLookup, functions []machoFunction, importStubs map[uint64]string, selector string, selectorInstruction, instructionOffset int, callVA, target uint64, context machoCallContext) bool {
	symbol, ok := importStubs[target]
	if !ok || !isObjCMsgSendSymbol(symbol) {
		return false
	}
	if selector == "" || instructionOffset-selectorInstruction > 96 {
		return false
	}
	addObjCMessageCallIndexed(lookup, functions, selector, "objc-selref", callVA, context)
	return true
}

func addObjCMessageCall(graph *behavior.Graph, content artifact.Content, functions []machoFunction, selector, via string, callVA uint64, arch string, context machoCallContext) {
	addObjCMessageCallIndexed(newMachOCallLookup(graph, content, arch), functions, selector, via, callVA, context)
}

func addObjCMessageCallIndexed(lookup *machoCallLookup, functions []machoFunction, selector, via string, callVA uint64, context machoCallContext) {
	fn := functionForVA(functions, callVA)
	scopeID := lookup.functionScopeID(fn)
	ev := lookup.graph.AddEvidence(behavior.Evidence{
		NodeID:   lookup.content.NodeID,
		ScopeID:  scopeID,
		Logical:  lookup.content.LogicalPath,
		VA:       callVA,
		Function: fn.Name,
		Arch:     lookup.arch,
		Method:   "macho-objc",
		Kind:     "objc-message-call",
		Value:    fn.Name + " -> " + selector,
	})
	if ev == "" {
		return
	}
	argumentCount := min(strings.Count(selector, ":"), len(context.StringArguments)-2)
	argumentPositions := make([]int, 0, argumentCount)
	for position := 0; position < argumentCount; position++ {
		argumentPositions = append(argumentPositions, position+2)
	}
	context.materializeStringArgumentEvidence(lookup, fn, scopeID, argumentPositions...)
	context.materializeObjCStringArrayEvidence(lookup, fn, scopeID, argumentPositions...)
	receiverEvidence := context.materializeObjCReceiverEvidence(lookup, fn, scopeID)
	if context.ObjCReceiver.Identity != "" {
		context.ObjCReceiver.OriginEvidenceIDs = receiverEvidence
	}
	featureEvidence := appendMachOCorrelatedEvidence([]string{ev}, receiverEvidence...)
	if callOffset, ok := machoSectionFileOffsetForVA(lookup.sectionIndex, callVA); ok {
		if returned, ok := newMachOObjCMessageReturnValue(lookup, fn, callVA, callOffset, 0, selector, context); ok {
			lookup.objcReturns[callVA] = returned
		}
	}
	lookup.addFeature(behavior.Feature{
		NodeID:         lookup.content.NodeID,
		ScopeID:        scopeID,
		Architecture:   lookup.arch,
		Key:            "objc.message_call",
		Value:          selector,
		EvidenceIDs:    featureEvidence,
		Support:        behavior.SupportCorroborated,
		Execution:      executionContextForMachOFunction(lookup.content, fn),
		SourceFunction: fn.Name,
		Qualifiers: machoFunctionQualifiers(fn, map[string]string{
			"function":          fn.Name,
			"via":               via,
			"receiver_identity": objcReceiverQualifier(context),
		}),
	})
	for position := 0; position < argumentCount; position++ {
		argument := context.stringArgument(position + 2)
		if argument.Value == "" || len(argument.EvidenceIDs) == 0 {
			continue
		}
		evidence := appendFirstMachOCorrelatedEvidence(nil, []string{ev})
		evidence = appendMachOCorrelatedEvidence(evidence, argument.EvidenceIDs...)
		lookup.addFeature(behavior.Feature{
			NodeID: lookup.content.NodeID, ScopeID: scopeID, Architecture: lookup.arch,
			Key: "objc.message_argument", Value: argument.Value, EvidenceIDs: evidence,
			Support: behavior.SupportCorroborated, Execution: executionContextForMachOFunction(lookup.content, fn),
			SourceFunction: fn.Name,
			Qualifiers: machoFunctionQualifiers(fn, map[string]string{
				"selector": selector, "argument_index": strconv.Itoa(position), "representation": argument.Representation,
			}),
		})
	}
	for position := 0; position < argumentCount; position++ {
		array := context.objcStringArray(position + 2)
		if len(array.Elements) == 0 || len(array.EvidenceIDs) == 0 {
			continue
		}
		for elementIndex, element := range array.Elements {
			evidence := appendFirstMachOCorrelatedEvidence(nil, []string{ev})
			evidence = appendMachOCorrelatedEvidence(evidence, array.EvidenceIDs...)
			lookup.addFeature(behavior.Feature{
				NodeID: lookup.content.NodeID, ScopeID: scopeID, Architecture: lookup.arch,
				Key: "objc.message_argument", Value: element.String.Value, EvidenceIDs: evidence,
				Support: behavior.SupportCorroborated, Execution: executionContextForMachOFunction(lookup.content, fn),
				SourceFunction: fn.Name,
				Qualifiers: machoFunctionQualifiers(fn, map[string]string{
					"selector": selector, "argument_index": strconv.Itoa(position),
					"collection_index": strconv.Itoa(elementIndex), "representation": array.Representation,
				}),
			})
		}
	}
	addOperationFromCalledObjCSelectorWithContextIndexed(lookup, selector, ev, fn, context)
	addOperationFromSMAppServiceSelectorSetIndexed(lookup, fn, selector, ev)
	if !addOperationFromExactNSTaskReceiverIndexed(lookup, fn, selector, ev, context, receiverEvidence) {
		addOperationFromNSTaskSelectorSetIndexed(lookup, fn, selector)
	}
}

type stubSection struct {
	addr          uint64
	size          uint64
	indirectStart uint32
	stubSize      uint32
}

func importedStubMapBounded(file *macho.File, recordLimit int) (map[uint64]string, bool) {
	return importedIndirectSymbolMapBounded(file, recordLimit, stubSections(file))
}

func importedPointerMapBounded(file *macho.File, recordLimit int) (map[uint64]string, bool) {
	return importedIndirectSymbolMapBounded(file, recordLimit, indirectPointerSections(file))
}

func importedPointerMapForLookup(file *macho.File, lookup *machoCallLookup, recordLimit int) (map[uint64]string, bool) {
	if lookup != nil && lookup.dyldIncomplete {
		// Indirect-symbol metadata cannot restore exact identity after a
		// binding stream was rejected: its addends or rebindings may change
		// that slot. The original parser diagnostic already records coverage.
		return nil, false
	}
	out, truncated := importedPointerMapBounded(file, recordLimit)
	if out == nil {
		out = map[uint64]string{}
	}
	if lookup == nil {
		return out, truncated
	}
	for slot, binding := range lookup.dyldBindings {
		if lookup.dyldAmbiguous[slot] {
			delete(out, slot)
			continue
		}
		if existing := out[slot]; existing != "" && existing != binding.Name {
			delete(out, slot)
			continue
		}
		out[slot] = binding.Name
	}
	for slot := range lookup.dyldAmbiguous {
		delete(out, slot)
	}
	return out, truncated
}

func importedIndirectSymbolMapBounded(file *macho.File, recordLimit int, sections []stubSection) (map[uint64]string, bool) {
	if file.Symtab == nil || file.Dysymtab == nil {
		return nil, false
	}
	if recordLimit < 0 {
		recordLimit = 0
	}
	out := map[uint64]string{}
	processed := 0
	truncated := false
	undefinedStart := uint64(file.Dysymtab.Iundefsym)
	undefinedCount := uint64(file.Dysymtab.Nundefsym)
	if undefinedStart > uint64(len(file.Symtab.Syms)) || undefinedCount > uint64(len(file.Symtab.Syms))-undefinedStart {
		return nil, true
	}
	undefinedEnd := undefinedStart + undefinedCount
	for _, section := range sections {
		if section.stubSize == 0 {
			continue
		}
		if section.addr > ^uint64(0)-section.size {
			truncated = true
		}
		if section.size%uint64(section.stubSize) != 0 {
			truncated = true
		}
		declaredCount := section.size / uint64(section.stubSize)
		if uint64(section.indirectStart) >= uint64(len(file.Dysymtab.IndirectSyms)) {
			truncated = truncated || declaredCount > 0
			continue
		}
		available := uint64(len(file.Dysymtab.IndirectSyms)) - uint64(section.indirectStart)
		count := min(declaredCount, available)
		remaining := recordLimit - processed
		if count > uint64(remaining) {
			count = uint64(remaining)
		}
		truncated = truncated || count < declaredCount
		for i := uint64(0); i < count; i++ {
			processed++
			slotSize := uint64(section.stubSize)
			if i > (^uint64(0)-section.addr)/slotSize {
				truncated = true
				break
			}
			slotAddress := section.addr + i*slotSize
			if slotAddress > ^uint64(0)-slotSize {
				truncated = true
				continue
			}
			indirect := uint64(section.indirectStart) + i
			symbolIndex := file.Dysymtab.IndirectSyms[indirect]
			if symbolIndex&0xc0000000 != 0 || int(symbolIndex) >= len(file.Symtab.Syms) {
				continue
			}
			if uint64(symbolIndex) < undefinedStart || uint64(symbolIndex) >= undefinedEnd {
				continue
			}
			symbolRecord := file.Symtab.Syms[symbolIndex]
			if !isUndefinedExternal(symbolRecord) {
				continue
			}
			symbol := symbolRecord.Name
			if symbol == "" {
				continue
			}
			out[slotAddress] = symbol
		}
	}
	if len(out) == 0 {
		return nil, truncated
	}
	return out, truncated
}

func objcMessageStubMap(file *macho.File) map[uint64]string {
	out, _ := objcMessageStubMapBounded(file, maxMachOStubRecords)
	return out
}

func objcMessageStubMapBounded(file *macho.File, recordLimit int) (map[uint64]string, bool) {
	if file.Symtab == nil {
		return nil, false
	}
	if recordLimit < 0 {
		recordLimit = 0
	}
	out := map[uint64]string{}
	limit := min(len(file.Symtab.Syms), recordLimit)
	for _, symbol := range file.Symtab.Syms[:limit] {
		selector, ok := objcSelectorFromMessageStubSymbol(symbol.Name)
		if !ok || symbol.Value == 0 || !isDefinedMachOSectionSymbol(symbol) || int(symbol.Sect) > len(file.Sections) {
			continue
		}
		section := file.Sections[int(symbol.Sect)-1]
		if section == nil || section.Name != "__objc_stubs" || section.Seg != "__TEXT" ||
			symbol.Value < section.Addr || symbol.Value-section.Addr >= section.Size {
			continue
		}
		out[symbol.Value] = selector
	}
	if len(out) == 0 {
		return nil, len(file.Symtab.Syms) > limit
	}
	return out, len(file.Symtab.Syms) > limit
}

func isDefinedMachOSectionSymbol(symbol macho.Symbol) bool {
	const (
		nStab = 0xe0
		nType = 0x0e
		nSect = 0x0e
	)
	return symbol.Type&nStab == 0 && symbol.Type&nType == nSect && symbol.Sect != 0
}

func objcSelectorFromMessageStubSymbol(symbol string) (string, bool) {
	name := strings.TrimPrefix(symbol, "_")
	index := strings.IndexByte(name, '$')
	if index < 0 || index+1 >= len(name) {
		return "", false
	}
	prefix := name[:index]
	if prefix != "objc_msgSend" && prefix != "objc_msgSendSuper" && prefix != "objc_msgSendSuper2" {
		return "", false
	}
	selector := name[index+1:]
	if !looksObjectiveCSelector(selector) {
		return "", false
	}
	return selector, true
}

func isObjCMsgSendSymbol(symbol string) bool {
	name := strings.TrimPrefix(symbol, "_")
	return name == "objc_msgSend"
}

func readObjectiveCSelectorRefAtVA(file *macho.File, va uint64) (string, bool) {
	return readObjectiveCSelectorRefAtVAIndexed(file, newMachOSectionIndex(file), va)
}

func readObjectiveCSelectorRefAtVAIndexed(file *macho.File, sections *machoSectionIndex, va uint64) (string, bool) {
	section := sections.namedContaining(va, 8, "__objc_selrefs")
	if section == nil || section.Flags&0xff != 0x5 || !objectiveCDataSegment(section.Seg) { // S_LITERAL_POINTERS
		return "", false
	}
	data, err := readMachOSectionAt(section, va-section.Addr, 8)
	if err != nil || len(data) != 8 {
		return "", false
	}
	pointer := file.ByteOrder.Uint64(data)
	selector, ok := readCStringAtPointerIndexed(file, sections, pointer, 256)
	if !ok || !looksObjectiveCSelector(selector) {
		return "", false
	}
	return selector, true
}

func objectiveCDataSegment(name string) bool {
	return name == "__DATA" || name == "__DATA_CONST" || name == "__DATA_DIRTY"
}

func stubSections(file *macho.File) []stubSection {
	return indirectSymbolSections(file, func(sectionType uint32) (uint32, bool) {
		if sectionType == 0x8 { // S_SYMBOL_STUBS
			return 0, true
		}
		return 0, false
	})
}

func indirectPointerSections(file *macho.File) []stubSection {
	return indirectSymbolSections(file, func(sectionType uint32) (uint32, bool) {
		switch sectionType {
		case 0x6, 0x7: // S_NON_LAZY_SYMBOL_POINTERS, S_LAZY_SYMBOL_POINTERS
			return 8, true
		default:
			return 0, false
		}
	})
}

func indirectSymbolSections(file *macho.File, slotSize func(uint32) (uint32, bool)) []stubSection {
	var out []stubSection
	for _, load := range file.Loads {
		rawer, ok := load.(interface{ Raw() []byte })
		if !ok {
			continue
		}
		raw := rawer.Raw()
		if len(raw) < 72 || file.ByteOrder.Uint32(raw[0:4]) != uint32(macho.LoadCmdSegment64) {
			continue
		}
		nsects := file.ByteOrder.Uint32(raw[64:68])
		offset := 72
		for i := uint32(0); i < nsects && offset+80 <= len(raw); i++ {
			section := raw[offset : offset+80]
			sectionType := file.ByteOrder.Uint32(section[64:68]) & 0xff
			fixedSize, ok := slotSize(sectionType)
			if ok {
				entrySize := fixedSize
				if entrySize == 0 {
					entrySize = file.ByteOrder.Uint32(section[72:76])
				}
				out = append(out, stubSection{
					addr:          file.ByteOrder.Uint64(section[32:40]),
					size:          file.ByteOrder.Uint64(section[40:48]),
					indirectStart: file.ByteOrder.Uint32(section[68:72]),
					stubSize:      entrySize,
				})
			}
			offset += 80
		}
	}
	return out
}

func addLocalCallFeatureIndexed(lookup *machoCallLookup, functions []machoFunction, callVA, target uint64) bool {
	caller := functionForVA(functions, callVA)
	callee := functionForVA(functions, target)
	if caller.Name == "" || callee.Name == "" || caller.Name == callee.Name {
		return false
	}
	pair := machoCallPair{caller: caller.Name, callee: callee.Name}
	if lookup.localCalls[pair] {
		return false
	}
	originCap := 0
	switch caller.Metadata {
	case "go-runtime-compiler":
		originCap = maxMachOGoRuntimeCallFeatures
	case "go-standard-library":
		originCap = maxMachOGoStandardCallFeatures
	case "rust-runtime-compiler":
		originCap = maxMachORustRuntimeCallFeatures
	case "rust-standard-library":
		originCap = maxMachORustStandardCallFeatures
	}
	if len(lookup.localCalls) >= maxMachOFunctionCallFeatures || originCap > 0 && lookup.localCallOrigins[caller.Metadata] >= originCap {
		if !lookup.localCallsCapped {
			lookup.localCallsCapped = true
			addPartialCoverageOnce(
				lookup.graph,
				lookup.content.NodeID,
				"macho-call-correlation/"+lookup.arch,
				fmt.Sprintf("direct-call correlation capped at %d caller/callee pairs, including per-language runtime/standard-library caps (Go %d/%d, Rust %d/%d) so non-runtime callers retain bounded capacity; additional decoded edges still contribute to reachability but not cross-function composite rules", maxMachOFunctionCallFeatures, maxMachOGoRuntimeCallFeatures, maxMachOGoStandardCallFeatures, maxMachORustRuntimeCallFeatures, maxMachORustStandardCallFeatures),
			)
		}
		return false
	}
	scopeID := lookup.functionScopeID(caller)
	ev := lookup.graph.AddEvidence(behavior.Evidence{
		NodeID:   lookup.content.NodeID,
		ScopeID:  scopeID,
		Logical:  lookup.content.LogicalPath,
		VA:       callVA,
		Function: caller.Name,
		Arch:     lookup.arch,
		Method:   "macho-callgraph",
		Kind:     "function-call",
		Value:    caller.Name + " -> " + callee.Name,
	})
	if ev == "" {
		return false
	}
	qualifiers := map[string]string{
		"function": caller.Name,
		"target":   fmt.Sprintf("0x%x", target),
	}
	applyMachOFunctionQualifiers(qualifiers, caller, "function_")
	applyMachOFunctionQualifiers(qualifiers, callee, "target_")
	if lookup.addFeature(behavior.Feature{
		NodeID:         lookup.content.NodeID,
		ScopeID:        scopeID,
		Architecture:   lookup.arch,
		Key:            "macho.function_call",
		Value:          callee.Name,
		EvidenceIDs:    []string{ev},
		Support:        behavior.SupportCorroborated,
		Execution:      executionContextForMachOFunction(lookup.content, caller),
		SourceFunction: caller.Name,
		Qualifiers:     qualifiers,
	}) == "" {
		return false
	}
	lookup.localCalls[pair] = true
	lookup.localCallOrigins[caller.Metadata]++
	return true
}

func localCallFeatureExists(graph *behavior.Graph, nodeID, arch, caller, callee string) bool {
	for _, feature := range graph.Features {
		if feature.NodeID == nodeID &&
			feature.Key == "macho.function_call" &&
			feature.Value == callee &&
			feature.SourceFunction == caller &&
			feature.Architecture == arch {
			return true
		}
	}
	return false
}

func directLocalCallEdgesBoundedWithRanges(cpu macho.Cpu, order binary.ByteOrder, textAddr uint64, data []byte, functions []machoFunction, byteLimit, candidateLimit, edgeLimit int, dataRanges []machoCodeRange) ([]localCallEdge, bool) {
	if order == nil {
		order = binary.LittleEndian
	}
	switch cpu {
	case macho.CpuAmd64:
		return x86LocalCallEdgesBoundedWithRanges(textAddr, data, functions, byteLimit, candidateLimit, edgeLimit, dataRanges)
	case macho.CpuArm64:
		return arm64LocalCallEdgesBoundedWithRanges(order, textAddr, data, functions, byteLimit, candidateLimit, edgeLimit, dataRanges)
	default:
		return nil, false
	}
}

func x86LocalCallEdgesBoundedWithRanges(textAddr uint64, data []byte, functions []machoFunction, byteLimit, candidateLimit, edgeLimit int, dataRanges []machoCodeRange) ([]localCallEdge, bool) {
	edges, capped, decodeIncomplete := x86LocalCallEdgesBoundedWithRangesDetailed(textAddr, data, functions, byteLimit, candidateLimit, edgeLimit, dataRanges)
	return edges, capped || decodeIncomplete
}

func x86LocalCallEdgesBoundedWithRangesDetailed(textAddr uint64, data []byte, functions []machoFunction, byteLimit, candidateLimit, edgeLimit int, dataRanges []machoCodeRange) ([]localCallEdge, bool, bool) {
	data, capped := boundedMachOCallData(data, byteLimit)
	var out []localCallEdge
	decodeIncomplete := false
	candidates := 0
	for i := 0; i < len(data); {
		if dataRange, excluded := machoCodeRangeContaining(i, dataRanges); excluded {
			i = dataRange.end
			continue
		}
		inst, err := decodeX86Instruction(x86DecodeInput(data, textAddr, i, functions, dataRanges))
		if err != nil || inst.Len <= 0 || inst.Op == 0 {
			decodeIncomplete = true
			i = x86DecodeFailureResumeOffset(textAddr, i, len(data), functions)
			continue
		}
		next, excluded := machoCodeInstructionExcluded(i, inst.Len, dataRanges)
		if excluded {
			i = next
			continue
		}
		if inst.Op != x86asm.CALL || inst.Len != 5 || data[i] != 0xe8 {
			i += inst.Len
			continue
		}
		if candidates >= candidateLimit {
			return out, true, decodeIncomplete
		}
		candidates++
		callVA := textAddr + uint64(i)
		rel := int64(int32(binary.LittleEndian.Uint32(data[i+1 : i+5])))
		target := uint64(int64(callVA+5) + rel)
		if edge, ok := localCallEdgeFor(functions, callVA, target); ok {
			if len(out) >= edgeLimit {
				return out, true, decodeIncomplete
			}
			out = append(out, edge)
		}
		i += inst.Len
	}
	return out, capped, decodeIncomplete
}

func arm64LocalCallEdgesBoundedWithRanges(order binary.ByteOrder, textAddr uint64, data []byte, functions []machoFunction, byteLimit, candidateLimit, edgeLimit int, dataRanges []machoCodeRange) ([]localCallEdge, bool) {
	data, truncated := boundedMachOCallData(data, byteLimit)
	var out []localCallEdge
	candidates := 0
	for i := 0; i+4 <= len(data); i += 4 {
		if _, excluded := machoCodeInstructionExcluded(i, 4, dataRanges); excluded {
			continue
		}
		insn := order.Uint32(data[i : i+4])
		if insn&0xfc000000 != 0x94000000 {
			continue
		}
		if candidates >= candidateLimit {
			return out, true
		}
		candidates++
		callVA := textAddr + uint64(i)
		imm := int32(insn&0x03ffffff) << 6 >> 4
		target := uint64(int64(callVA) + int64(imm))
		if edge, ok := localCallEdgeFor(functions, callVA, target); ok {
			if len(out) >= edgeLimit {
				return out, true
			}
			out = append(out, edge)
		}
	}
	return out, truncated
}

func localCallEdgeFor(functions []machoFunction, callVA, target uint64) (localCallEdge, bool) {
	caller := functionIndexForVA(functions, callVA)
	callee := functionIndexForVA(functions, target)
	// A direct branch into the middle of a recovered function may be a local
	// label, jump table target, or malformed data. Only an exact function start
	// establishes a caller/callee edge.
	if caller < 0 || callee < 0 || caller == callee || functions[callee].Start != target {
		return localCallEdge{}, false
	}
	return localCallEdge{caller: caller, callee: callee}, true
}

func boundedMachOCallData(data []byte, byteLimit int) ([]byte, bool) {
	if byteLimit < 0 {
		byteLimit = 0
	}
	if len(data) <= byteLimit {
		return data, false
	}
	return data[:byteLimit], true
}

func functionIndexForVA(functions []machoFunction, va uint64) int {
	idx := sort.Search(len(functions), func(i int) bool {
		return functions[i].End > va
	})
	if idx < len(functions) && va >= functions[idx].Start {
		return idx
	}
	return -1
}

func functionIndexForSequentialVA(functions []machoFunction, current int, va uint64) int {
	if len(functions) == 0 {
		return -1
	}
	if current >= 0 && current < len(functions) {
		if va >= functions[current].Start && va < functions[current].End {
			return current
		}
		for current+1 < len(functions) && va >= functions[current].End {
			current++
			if va >= functions[current].Start && va < functions[current].End {
				return current
			}
		}
	}
	idx := sort.Search(len(functions), func(i int) bool {
		return functions[i].End > va
	})
	if idx >= len(functions) || va < functions[idx].Start {
		return -1
	}
	return idx
}

func functionForVA(functions []machoFunction, va uint64) machoFunction {
	if idx := functionIndexForVA(functions, va); idx >= 0 {
		return functions[idx]
	}
	return machoFunction{}
}

func addOperationFromCalledImportedSymbol(graph *behavior.Graph, content artifact.Content, symbol, arch, evidenceID string, function machoFunction) {
	addOperationFromCalledImportedSymbolWithContext(graph, content, symbol, arch, evidenceID, function, machoCallContext{})
}

func addOperationFromCalledImportedSymbolWithContext(graph *behavior.Graph, content artifact.Content, symbol, arch, evidenceID string, function machoFunction, context machoCallContext) {
	addOperationFromCalledImportedSymbolWithContextIndexed(newMachOCallLookup(graph, content, arch), symbol, evidenceID, function, context)
}

func addOperationFromCalledImportedSymbolWithContextIndexed(lookup *machoCallLookup, symbol, evidenceID string, function machoFunction, context machoCallContext) {
	plain := strings.TrimPrefix(symbol, "_")
	var resource behavior.Resource
	var bindings []behavior.ResourceBinding
	primitive, hasNativePrimitive := nativePrimitiveForSymbol(plain)
	operation := behavior.ModeledOperation{
		SubjectNodeID:  lookup.content.NodeID,
		ScopeID:        lookup.functionScopeID(function),
		EvidenceIDs:    []string{evidenceID},
		Support:        behavior.SupportCorroborated,
		Execution:      executionContextForMachOFunction(lookup.content, function),
		Architecture:   lookup.arch,
		SourceFunction: function.Name,
		Qualifiers:     map[string]string{"api": plain, "semantic_basis": "exact-called-import"},
	}
	applyMachOFunctionQualifiers(operation.Qualifiers, function, "function_")
	switch {
	case plain == "SecItemCopyMatching":
		operation.Kind = behavior.OperationKeychainItemQuery
		resource = behavior.NewResource(behavior.ResourceCredentialStore, "", behavior.ResourceClassKeychain)
	case plain == "SecKeychainFindGenericPassword" || plain == "SecKeychainFindInternetPassword":
		operation.Kind = behavior.OperationCredentialStoreRead
		resource = behavior.NewResource(behavior.ResourceCredentialStore, "", behavior.ResourceClassKeychain)
	case isNativeSystemInformationSymbol(plain):
		operation.Kind = behavior.OperationSystemInfoQuery
		resource = behavior.NewResource(behavior.ResourceSystem, "macOS system and hardware")
	case isNativeNetworkConfigurationSymbol(plain):
		operation.Kind = behavior.OperationNetworkConfigurationQuery
		resource = behavior.NewResource(behavior.ResourceConfiguration, "local network interfaces and addresses")
	case isNativeUserInformationSymbol(plain):
		operation.Kind = behavior.OperationUserInfoQuery
		resource = behavior.NewResource(behavior.ResourceUserAccount, "local user")
	case isNativeProcessEnumerationSymbol(plain):
		operation.Kind = behavior.OperationProcessEnumerate
		resource = behavior.NewResource(behavior.ResourceProcess, "local processes")
	case isNativeFileEnumerationSymbol(plain):
		operation.Kind = behavior.OperationFileEnumerate
		resource = behavior.NewResource(behavior.ResourceFile, "")
	case isNativeProcessExecutionSymbol(plain):
		operation.Kind = behavior.OperationProcessExecute
		resource = behavior.NewResource(behavior.ResourceFile, "")
		argumentIndex := nativeProcessExecutableArgumentIndex(plain)
		argument := context.stringArgument(argumentIndex)
		if concrete, evidence := exactProcessLaunchArgument(argument); concrete != "" {
			resource.Value = concrete
			operation.EvidenceIDs = append(operation.EvidenceIDs, evidence...)
			operation.Qualifiers["resource_binding"] = "exact-call-argument"
		} else if concrete, evidence := processLaunchPathForFunctionArgumentIndexed(lookup, function.Name, argument.Value); concrete != "" {
			// Compatibility path for already-retained string-xref proof. Production
			// direct-call decoding normally takes the stricter callsite evidence path.
			resource.Value = concrete
			operation.EvidenceIDs = append(operation.EvidenceIDs, evidence...)
			operation.Qualifiers["resource_binding"] = "exact-call-argument"
		} else {
			operation.Qualifiers["resource_binding"] = "unresolved"
		}
		if resource.Value == "" && genericRustStdlibProcessWrapper(function, plain) {
			// Rust's std::process implementation contains generic execvp(3) and
			// posix_spawnp(3) backends in ordinary Tauri applications. A call in
			// that library wrapper proves the runtime primitive is present, but
			// without a recovered executable argument it does not identify an
			// application-directed process launch. The imported-call evidence is
			// retained; only the ungrounded modeled operation is suppressed.
			return
		}
	case isProcessPrimitive(plain):
		operation.Kind, _ = processPrimitiveOperationKind(plain)
		resource = behavior.NewResource(behavior.ResourceProcess, "")
	case hasNativePrimitive:
		operation.Kind = primitive.kind
		resource = primitive.resource
		bindings = primitive.bindings
		for key, value := range primitive.qualifiers {
			operation.Qualifiers[key] = value
		}
	case isDisplaySetupSymbol(plain), isClipboardSetupSymbol(plain), isLoginItemSymbol(plain):
		// The recovered call is useful neutral evidence, but its arguments or a
		// later operation determine whether it reads, captures, collects, or
		// enables persistence. Do not promote it to an operation here.
		return
	case isAudioRecordingQueueSymbol(plain):
		operation.Kind = behavior.OperationAudioRecordingQueueCreate
		resource = behavior.NewResource(behavior.ResourceAudioInput, "system audio input")
	case isInputEventMonitoringSymbol(plain):
		operation.Kind = behavior.OperationInputEventTapCreate
		resource = behavior.NewResource(behavior.ResourceInputEventStream, "Quartz event stream")
	case isScreenshotSymbol(plain):
		operation.Kind = behavior.OperationScreenCapture
		resource = behavior.NewResource(behavior.ResourceScreen, "")
	case isPasteboardReadSymbol(plain):
		operation.Kind = behavior.OperationPasteboardItemRead
		resource = behavior.NewResource(behavior.ResourcePasteboard, "unresolved pasteboard reference")
	case isPasteboardWriteSymbol(plain):
		operation.Kind = behavior.OperationPasteboardItemWrite
		resource = behavior.NewResource(behavior.ResourcePasteboard, "unresolved pasteboard reference")
	case isLibcurlPerformSymbol(plain):
		// curl_easy_perform may use a non-network URL scheme, while connect(2)
		// may address an AF_UNIX socket. A nearby URL/IP string is not handle or
		// sockaddr provenance, so retain the exact called-API observation without
		// manufacturing a network operation or destination binding.
		lookup.graph.AddNetworkImplementation(apiNetworkImplementation(
			behavior.NetworkImplementationAPICall, lookup.content, lookup.functionScopeID(function), lookup.arch,
			executionContextForMachOFunction(lookup.content, function), behavior.SupportCorroborated,
			"", plain, evidenceID, false,
		))
		return
	case plain == "nw_connection_start":
		operation.Kind = behavior.OperationNetworkConnect
		resource = behavior.NewResource(behavior.ResourceNetworkEndpoint, "")
	case strings.Contains(plain, "URLSession") || strings.Contains(plain, "nw_connection") || strings.Contains(plain, "SSLHandshake"):
		// A called TLS handshake uses an already configured transport, and most
		// URLSession/Network.framework symbols create or configure objects rather
		// than start I/O. Preserve the called implementation observation without
		// manufacturing a connection operation. The exact nw_connection_start
		// primitive is handled above; URLSession task/resume lifecycles are
		// recognized from Objective-C calls separately.
		lookup.graph.AddNetworkImplementation(apiNetworkImplementation(
			behavior.NetworkImplementationAPICall, lookup.content, lookup.functionScopeID(function), lookup.arch,
			executionContextForMachOFunction(lookup.content, function), behavior.SupportCorroborated,
			"", plain, evidenceID, false,
		))
		return
	default:
		return
	}
	if hasNativePrimitive {
		if exact := nativePrimitiveArgumentBindings(plain, context); len(exact) > 0 {
			bindings = exact
			operation.Qualifiers["resource_binding"] = "exact-call-argument"
			for _, binding := range exact {
				operation.EvidenceIDs = append(operation.EvidenceIDs, binding.EvidenceIDs...)
			}
		}
	}
	if len(bindings) > 0 {
		operation.ResourceBindings = bindings
	} else {
		operation.ResourceBindings = requiredResourceBindings(operation.Kind, resource)
	}
	if operation.Kind == behavior.OperationProcessExecute {
		bindMachOStaticArgv(lookup, &operation, context.ArgumentVector)
		applyMachOLocalAgentInvocation(&operation, context.ArgumentVector)
	}
	operationID := lookup.addOperation(operation)
	if isNativeShellExecutionSymbol(plain) {
		expandMachONativeShellCommandIndexed(lookup, function, context.Argument0String, evidenceID)
	}
	if isNetworkOperationKind(operation.Kind) {
		lookup.graph.AddNetworkImplementation(apiNetworkImplementation(
			behavior.NetworkImplementationAPICall, lookup.content, operation.ScopeID, lookup.arch,
			operation.Execution, operation.Support, operationID, plain, evidenceID, false,
		))
	}
	if operation.Kind == behavior.OperationSocketConnect && !addMachOStaticSocketNetworkConnect(lookup, function, plain, evidenceID, context.SocketAddress) {
		lookup.graph.AddNetworkImplementation(apiNetworkImplementation(
			behavior.NetworkImplementationAPICall, lookup.content, operation.ScopeID, lookup.arch,
			operation.Execution, operation.Support, "", plain, evidenceID, false,
		))
	}
}

func isNativeSystemInformationSymbol(symbol string) bool {
	switch symbol {
	case "uname", "gethostname", "host_info", "host_statistics", "host_statistics64":
		return true
	default:
		return false
	}
}

func isNativeNetworkConfigurationSymbol(symbol string) bool {
	return symbol == "getifaddrs" || symbol == "if_nameindex"
}

func isNativeUserInformationSymbol(symbol string) bool {
	switch symbol {
	case "getuid", "geteuid", "getgid", "getegid", "getlogin", "getlogin_r", "getpwuid", "getpwuid_r", "SCDynamicStoreCopyConsoleUser":
		return true
	default:
		return false
	}
}

func isNativeProcessEnumerationSymbol(symbol string) bool {
	switch symbol {
	case "proc_listpids", "proc_listallpids", "proc_listchildpids":
		return true
	default:
		return false
	}
}

func isNativeFileEnumerationSymbol(symbol string) bool {
	switch symbol {
	case "readdir", "readdir_r", "fts_read", "getattrlistbulk":
		return true
	default:
		return false
	}
}

func isNetworkOperationKind(kind behavior.OperationKind) bool {
	return kind == "network.connect" || kind == "network.download" || kind == "network.upload"
}

func isNativeShellExecutionSymbol(plain string) bool {
	return plain == "system" || plain == "popen"
}

func isNativeProcessExecutionSymbol(plain string) bool {
	if isNativeShellExecutionSymbol(plain) {
		return true
	}
	switch plain {
	case "execl", "execle", "execlp", "execv", "execve", "execvp", "execvP", "posix_spawn", "posix_spawnp":
		return true
	default:
		return false
	}
}

func nativeProcessExecutableArgumentIndex(plain string) int {
	switch plain {
	case "posix_spawn", "posix_spawnp":
		// int posix_spawn(pid_t *, const char *path, ...)
		return 1
	default:
		// system, popen, and the exec* family take their command/executable
		// pointer as the first argument.
		return 0
	}
}

func exactProcessLaunchArgument(argument machoCallStringArgument) (string, []string) {
	concrete := normalizeProcessLaunchPath(argument.Value)
	if len(argument.EvidenceIDs) == 0 || !looksProcessLaunchPath(concrete) {
		return "", nil
	}
	return concrete, append([]string(nil), argument.EvidenceIDs...)
}

func genericRustStdlibProcessWrapper(function machoFunction, symbol string) bool {
	name := function.DisplayName
	if name == "" {
		name = function.Name
	}
	switch symbol {
	case "posix_spawnp":
		if !strings.Contains(name, "$GT$5spawn17h") && !strings.HasSuffix(name, "::spawn") {
			return false
		}
	case "execvp":
		if !strings.Contains(name, "$GT$7do_exec17h") && !strings.HasSuffix(name, "::do_exec") {
			return false
		}
	default:
		return false
	}
	legacy := strings.Contains(name, "3std3sys3pal4unix7process13process_inner") && strings.Contains(name, "process_common..Command")
	demangled := function.Metadata == "rust-standard-library" &&
		strings.Contains(name, "std::sys::pal::unix::process::process_inner") &&
		strings.Contains(name, "process_common::Command")
	return legacy || demangled
}

func addOperationFromNSTaskSelectorSetIndexed(lookup *machoCallLookup, function machoFunction, currentSelector string) {
	// Correlate only while processing a launch call. Because selector calls are
	// decoded in address order, this requires setLaunchPath: to have appeared
	// earlier in the same recovered function instead of treating an unordered
	// pair of selector names as execution proof.
	if function.Name == "" || currentSelector != "launch" {
		return
	}
	key := machoCallOperationKey{function: function.Name, kind: behavior.OperationProcessExecute}
	if lookup.operations[key] {
		return
	}
	if !lookup.featureExists(function.Name, "objc.message_call") {
		return
	}
	// Check both exact selector values before copying their evidence slices.
	// This keeps repeated setLaunchPath: calls without a later launch linear.
	if len(lookup.evidence[machoCallFeatureValueKey{function: function.Name, key: "objc.message_call", value: "setLaunchPath:"}]) == 0 ||
		len(lookup.evidence[machoCallFeatureValueKey{function: function.Name, key: "objc.message_call", value: "launch"}]) == 0 {
		return
	}
	pathEvidence := lookup.featureEvidenceBounded(function.Name, "objc.message_call", "setLaunchPath:", maxMachOCorrelatedOperationEvidence)
	launchEvidence := lookup.featureEvidenceBounded(function.Name, "objc.message_call", "launch", maxMachOCorrelatedOperationEvidence)
	argumentEvidence := lookup.featureEvidenceBounded(function.Name, "objc.message_call", "setArguments:", maxMachOCorrelatedOperationEvidence)
	resource := behavior.NewResource(behavior.ResourceFile, "")
	// Reserve the leading slots for the selector calls required by the
	// correlation. Same-function path co-occurrence is not argument or receiver
	// provenance, so the executable deliberately stays unresolved.
	evidence := appendFirstMachOCorrelatedEvidence(nil, pathEvidence)
	evidence = appendFirstMachOCorrelatedEvidence(evidence, launchEvidence)
	evidence = appendFirstMachOCorrelatedEvidence(evidence, argumentEvidence)
	evidence = appendMachOCorrelatedEvidence(evidence, pathEvidence...)
	evidence = appendMachOCorrelatedEvidence(evidence, argumentEvidence...)
	evidence = appendMachOCorrelatedEvidence(evidence, launchEvidence...)
	lookup.addOperation(behavior.ModeledOperation{
		SubjectNodeID:    lookup.content.NodeID,
		ScopeID:          lookup.functionScopeID(function),
		Kind:             behavior.OperationProcessExecute,
		ResourceBindings: requiredResourceBindings(behavior.OperationProcessExecute, resource),
		Qualifiers: map[string]string{
			"api":               "NSTask",
			"receiver_identity": "unresolved",
			"resource_binding":  "unresolved",
			"semantic_basis":    "ordered-selector-set",
		},
		EvidenceIDs:    evidence,
		Support:        behavior.SupportHeuristic,
		Execution:      executionContextForMachOFunction(lookup.content, function),
		Architecture:   lookup.arch,
		SourceFunction: function.Name,
	})
}

const maxMachOCorrelatedOperationEvidence = 32

func appendFirstMachOCorrelatedEvidence(existing, candidates []string) []string {
	for _, candidate := range candidates {
		if candidate != "" {
			return appendMachOCorrelatedEvidence(existing, candidate)
		}
	}
	return existing
}

func appendMachOCorrelatedEvidence(existing []string, additions ...string) []string {
	for _, addition := range additions {
		if len(existing) >= maxMachOCorrelatedOperationEvidence {
			break
		}
		if addition == "" {
			continue
		}
		duplicate := false
		for _, current := range existing {
			if current == addition {
				duplicate = true
				break
			}
		}
		if !duplicate {
			existing = append(existing, addition)
		}
	}
	return existing
}

func addOperationFromCalledObjCSelectorWithContextIndexed(lookup *machoCallLookup, selector, evidenceID string, function machoFunction, context machoCallContext) {
	recognizer, ok := machoObjCOperationRecognizerForSelector(selector)
	if !ok {
		return
	}
	var resource behavior.Resource
	operation := behavior.ModeledOperation{
		SubjectNodeID: lookup.content.NodeID,
		ScopeID:       lookup.functionScopeID(function),
		Qualifiers: map[string]string{
			"receiver_identity": objcReceiverQualifier(context),
			"resource_binding":  "unresolved",
			"selector":          selector,
			"semantic_basis":    "exact-called-selector",
		},
		EvidenceIDs:    []string{evidenceID},
		Support:        behavior.SupportHeuristic,
		Execution:      executionContextForMachOFunction(lookup.content, function),
		Architecture:   lookup.arch,
		SourceFunction: function.Name,
		Kind:           recognizer.Kind,
	}
	operation.EvidenceIDs = appendMachOCorrelatedEvidence(operation.EvidenceIDs, context.ObjCReceiver.OriginEvidenceIDs...)
	applyMachOFunctionQualifiers(operation.Qualifiers, function, "function_")
	switch recognizer.Kind {
	case behavior.OperationCameraCapture:
		resource = behavior.NewResource(behavior.ResourceCamera, "")
	case behavior.OperationDirectoryCreate, behavior.OperationFileDelete, behavior.OperationFileEnumerate, behavior.OperationFileMetadataQuery,
		behavior.OperationFileCopy, behavior.OperationFileMove:
		resource = behavior.NewResource(behavior.ResourceFile, "")
	case behavior.OperationProcessEnumerate:
		resource = behavior.NewResource(behavior.ResourceProcess, "local processes")
	case behavior.OperationNetworkConnect:
		resource = behavior.NewResource(behavior.ResourceNetworkEndpoint, "")
	case behavior.OperationFileRead:
		resource = behavior.NewResource(behavior.ResourceFile, "")
	case behavior.OperationFileWrite:
		resource = behavior.NewResource(behavior.ResourceFile, "")
	case behavior.OperationProcessExecute:
		resource = behavior.NewResource(behavior.ResourceFile, "")
	default:
		return
	}
	if recognizer.BindsFirstStringArgument && recognizer.BindsSecondStringArgument {
		first := context.stringArgument(2)
		second := context.stringArgument(3)
		firstResource := machoObjCEvidencedStringResource(first)
		secondResource := machoObjCEvidencedStringResource(second)
		firstRole, secondRole := behavior.ResourceRoleSource, behavior.ResourceRoleTarget
		if recognizer.Kind == behavior.OperationFileCopy {
			secondRole = behavior.ResourceRoleLocalOutput
		}
		operation.ResourceBindings = behavior.Bindings(
			behavior.Bind(firstRole, firstResource, first.EvidenceIDs...),
			behavior.Bind(secondRole, secondResource, second.EvidenceIDs...),
		)
		exact := 0
		if firstResource.Value != "" && len(first.EvidenceIDs) > 0 {
			exact++
			operation.EvidenceIDs = appendMachOCorrelatedEvidence(operation.EvidenceIDs, first.EvidenceIDs...)
			operation.Qualifiers["source_argument_representation"] = first.Representation
		}
		if secondResource.Value != "" && len(second.EvidenceIDs) > 0 {
			exact++
			operation.EvidenceIDs = appendMachOCorrelatedEvidence(operation.EvidenceIDs, second.EvidenceIDs...)
			operation.Qualifiers["target_argument_representation"] = second.Representation
		}
		switch exact {
		case 2:
			operation.Qualifiers["resource_binding"] = "exact-call-arguments"
		case 1:
			operation.Qualifiers["resource_binding"] = "partial-exact-call-arguments"
		}
	} else if recognizer.BindsFirstStringArgument {
		argument := context.stringArgument(2)
		value := argument.Value
		if operation.Kind == behavior.OperationProcessExecute {
			value = normalizeProcessLaunchPath(value)
			if !looksProcessLaunchPath(value) {
				value = ""
			}
		}
		if value != "" && len(argument.EvidenceIDs) > 0 {
			resource.Value = value
			if resource.Kind == behavior.ResourceFile {
				resource = classifiedFileResource(value)
			}
			operation.EvidenceIDs = appendMachOCorrelatedEvidence(operation.EvidenceIDs, argument.EvidenceIDs...)
			operation.Qualifiers["resource_binding"] = "exact-call-argument"
			operation.Qualifiers["argument_representation"] = argument.Representation
		}
	}
	if len(operation.ResourceBindings) == 0 {
		operation.ResourceBindings = requiredResourceBindings(operation.Kind, resource)
		if resource.Value != "" {
			for index := range operation.ResourceBindings {
				operation.ResourceBindings[index].EvidenceIDs = append([]string(nil), context.stringArgument(2).EvidenceIDs...)
			}
		}
	}
	operationID := lookup.addOperation(operation)
	if operation.Kind == behavior.OperationNetworkConnect {
		lookup.graph.AddNetworkImplementation(objcSelectorNetworkImplementation(
			lookup.content, operation.ScopeID, lookup.arch, operation.Execution, operation.Support,
			operationID, selector, evidenceID,
		))
	}
}

func machoObjCStringResource(argument machoCallStringArgument) behavior.Resource {
	return classifiedFileResource(argument.Value)
}

func machoObjCEvidencedStringResource(argument machoCallStringArgument) behavior.Resource {
	if len(argument.EvidenceIDs) == 0 {
		argument.Value = ""
	}
	return machoObjCStringResource(argument)
}

func processLaunchPathForFunctionArgumentIndexed(lookup *machoCallLookup, function, argument string) (string, []string) {
	argument = normalizeProcessLaunchPath(argument)
	if !looksProcessLaunchPath(argument) {
		return "", nil
	}
	evidence := lookup.featureEvidence(function, "macho.process_launch_path", argument)
	if len(evidence) == 0 {
		return "", nil
	}
	return argument, evidence
}

func cstringAtTargetLocationIndexed(file *macho.File, sections *machoSectionIndex, target uint64, loadsMemory bool) (string, uint64, int, bool) {
	if loadsMemory {
		pointer, pointerOK := readPointerAtVAIndexed(file, sections, target)
		if !pointerOK {
			return "", 0, 0, false
		}
		return readCStringAtPointerLocationIndexed(file, sections, pointer, 4096)
	}
	value, ok := readCStringAtVAIndexed(sections, target, 4096)
	if !ok {
		return "", 0, 0, false
	}
	offset, ok := machoSectionFileOffsetForVA(sections, target)
	if !ok {
		return "", 0, 0, false
	}
	return value, target, offset, true
}

func objcCFStringAtTargetLocationIndexed(file *macho.File, reader *machoCFStringReader, target uint64, loadsMemory bool) (machoCallStringArgument, bool) {
	if file == nil || file.ByteOrder == nil || reader == nil || reader.index == nil {
		return machoCallStringArgument{}, false
	}
	sections := reader.index
	if loadsMemory {
		pointer, ok := readPointerAtVAIndexed(file, sections, target)
		if !ok {
			return machoCallStringArgument{}, false
		}
		target = pointer
	}
	for _, candidate := range normalizedMachOPointersIndexed(sections, target) {
		section := sections.namedContaining(candidate, machOCFString64RecordSize, "__cfstring")
		if section == nil || (candidate-section.Addr)%machOCFString64RecordSize != 0 {
			continue
		}
		record, err := readMachOSectionAt(section, candidate-section.Addr, machOCFString64RecordSize)
		if err != nil || len(record) != machOCFString64RecordSize {
			continue
		}
		backingPointer := file.ByteOrder.Uint64(record[16:24])
		length := file.ByteOrder.Uint64(record[24:32])
		value, backingVA, backingOffset, ok := reader.read(backingPointer, length)
		if !ok || value == "" {
			continue
		}
		objectOffset, ok := machoSectionFileOffsetForVA(sections, candidate)
		if !ok {
			return machoCallStringArgument{}, false
		}
		return machoCallStringArgument{
			Value: value, LiteralVA: candidate, LiteralOffset: objectOffset,
			BackingVA: backingVA, BackingOffset: backingOffset, Representation: "static-cfstring",
		}, true
	}
	return machoCallStringArgument{}, false
}

func expandMachONativeShellCommandIndexed(lookup *machoCallLookup, function machoFunction, exactCommand string, callEvidence ...string) {
	if function.Name == "" || lookup.featureExists(function.Name, "macho.shell_command_expanded") {
		return
	}
	if exactCommand == "" || !looksShellCommandLiteral(exactCommand) {
		return
	}
	command := exactCommand
	evidence := lookup.featureEvidenceBounded(function.Name, "macho.shell_command", exactCommand, maxMachOCorrelatedOperationEvidence)
	if command == "" || len(evidence) == 0 {
		return
	}
	scopeID := lookup.functionScopeID(function)
	scoped := lookup.content
	scoped.ScopeID = scopeID
	scoped.Function = function.Name
	scoped.Architecture = lookup.arch
	// Reserve proof of both the command literal and the native invocation before
	// repeated xrefs can consume the bounded operation-evidence list.
	expansionEvidence := appendFirstMachOCorrelatedEvidence(nil, evidence)
	expansionEvidence = appendFirstMachOCorrelatedEvidence(expansionEvidence, callEvidence)
	expansionEvidence = appendMachOCorrelatedEvidence(expansionEvidence, evidence...)
	expansionEvidence = appendMachOCorrelatedEvidence(expansionEvidence, callEvidence...)
	scoped.SupportingEvidenceIDs = expansionEvidence
	operationStart := len(lookup.graph.Operations)
	AnalyzeShellLine(lookup.graph, scoped, command, 0, executionContextForMachOFunction(lookup.content, function), evidence[0])
	for i := operationStart; i < len(lookup.graph.Operations); i++ {
		if lookup.graph.Operations[i].Qualifiers == nil {
			lookup.graph.Operations[i].Qualifiers = map[string]string{}
		}
		applyMachOFunctionQualifiers(lookup.graph.Operations[i].Qualifiers, function, "function_")
		lookup.recordOperation(lookup.graph.Operations[i])
	}
	lookup.addFeature(behavior.Feature{
		NodeID:         lookup.content.NodeID,
		ScopeID:        scopeID,
		Architecture:   lookup.arch,
		Key:            "macho.shell_command_expanded",
		Value:          command,
		EvidenceIDs:    expansionEvidence,
		Support:        behavior.SupportCorroborated,
		Execution:      executionContextForMachOFunction(lookup.content, function),
		SourceFunction: function.Name,
		Qualifiers:     map[string]string{"function": function.Name},
	})
}

func addOperationFromSMAppServiceSelectorSetIndexed(lookup *machoCallLookup, function machoFunction, currentSelector, currentEvidence string) {
	if function.Name == "" || !isSMAppServiceRegisterSelector(currentSelector) || currentEvidence == "" {
		return
	}
	state := lookup.smFunctions[function.Name]
	if state == nil || len(state.services) == 0 {
		return
	}
	categories := make([]string, 0, len(state.services))
	for category := range state.services {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	for _, category := range categories {
		item := state.services[category]
		key := machoCallOperationKey{function: function.Name, kind: item.kind, category: item.category}
		if lookup.operations[key] {
			continue
		}
		// A unique dotted string in the same function is not proof that it was
		// passed to this factory or that the later register call uses its return
		// value. Keep the typed category but leave the concrete identity empty.
		concrete := ""
		evidence := appendFirstMachOCorrelatedEvidence(nil, item.evidence)
		evidence = appendFirstMachOCorrelatedEvidence(evidence, []string{currentEvidence})
		evidence = appendMachOCorrelatedEvidence(evidence, item.evidence...)
		evidence = appendMachOCorrelatedEvidence(evidence, currentEvidence)
		lookup.addOperation(behavior.ModeledOperation{
			SubjectNodeID:    lookup.content.NodeID,
			ScopeID:          lookup.functionScopeID(function),
			Kind:             item.kind,
			ResourceBindings: requiredResourceBindings(item.kind, serviceOperationResource(item.category, concrete)),
			Qualifiers: map[string]string{
				"api":               "SMAppService",
				"receiver_identity": "unresolved",
				"resource_binding":  "unresolved",
				"semantic_basis":    "ordered-selector-set",
			},
			EvidenceIDs:    evidence,
			Support:        behavior.SupportHeuristic,
			Execution:      executionContextForMachOFunction(lookup.content, function),
			Architecture:   lookup.arch,
			SourceFunction: function.Name,
		})
	}
}

func isSMAppServiceRegisterSelector(selector string) bool {
	return selector == "registerAndReturnError:"
}

func smAppServiceSelectorBindsConcreteResource(selector string) bool {
	switch selector {
	case "loginItemServiceWithIdentifier:", "agentServiceWithPlistName:", "daemonServiceWithPlistName:":
		return true
	default:
		return false
	}
}

func smAppServiceFactoryOperation(selector string) (behavior.OperationKind, string, bool) {
	switch selector {
	case "mainAppService", "loginItemServiceWithIdentifier:":
		return behavior.OperationLoginItemRegister, "login-item", true
	case "agentServiceWithPlistName:":
		return behavior.OperationLaunchdJobRegister, "launch-agent", true
	case "daemonServiceWithPlistName:":
		return behavior.OperationLaunchdJobRegister, "launch-daemon", true
	default:
		return "", "", false
	}
}

type machoObjCOperationRecognizer struct {
	Selector                  string
	Kind                      behavior.OperationKind
	BindsFirstStringArgument  bool
	BindsSecondStringArgument bool
}

// machoObjCOperationRecognizers is deliberately exact and sorted. A called
// selector remains a neutral objc.message_call Feature unless its complete,
// case-sensitive spelling has stable platform-selector semantics. Receiver and
// class identity are not recovered, so every promoted operation says that its
// receiver identity is unresolved. A closed subset of path-taking methods can
// bind an exact static CFString passed in the first Objective-C argument;
// arbitrary NSString construction, NSURL, and NSURLRequest object provenance
// remain unresolved. NSURLSession task constructors are absent because they return
// suspended tasks and receiver identity is not yet tracked through a later
// -resume call.
var machoObjCOperationRecognizers = [...]machoObjCOperationRecognizer{
	{Selector: "arrayWithContentsOfFile:", Kind: behavior.OperationFileRead, BindsFirstStringArgument: true},
	{Selector: "attributesOfItemAtPath:error:", Kind: behavior.OperationFileMetadataQuery, BindsFirstStringArgument: true},
	{Selector: "capturePhotoWithSettings:delegate:", Kind: behavior.OperationCameraCapture},
	{Selector: "captureStillImageAsynchronouslyFromConnection:completionHandler:", Kind: behavior.OperationCameraCapture},
	{Selector: "contentsAtPath:", Kind: behavior.OperationFileRead, BindsFirstStringArgument: true},
	{Selector: "contentsOfDirectoryAtPath:error:", Kind: behavior.OperationFileEnumerate, BindsFirstStringArgument: true},
	{Selector: "contentsOfDirectoryAtURL:includingPropertiesForKeys:options:error:", Kind: behavior.OperationFileEnumerate},
	{Selector: "copyItemAtPath:toPath:error:", Kind: behavior.OperationFileCopy, BindsFirstStringArgument: true, BindsSecondStringArgument: true},
	{Selector: "createDirectoryAtPath:attributes:", Kind: behavior.OperationDirectoryCreate, BindsFirstStringArgument: true},
	{Selector: "createDirectoryAtPath:withIntermediateDirectories:attributes:error:", Kind: behavior.OperationDirectoryCreate, BindsFirstStringArgument: true},
	{Selector: "createDirectoryAtURL:withIntermediateDirectories:attributes:error:", Kind: behavior.OperationDirectoryCreate},
	{Selector: "createFileAtPath:contents:attributes:", Kind: behavior.OperationFileWrite, BindsFirstStringArgument: true},
	{Selector: "dataWithContentsOfFile:", Kind: behavior.OperationFileRead, BindsFirstStringArgument: true},
	{Selector: "dataWithContentsOfFile:options:error:", Kind: behavior.OperationFileRead, BindsFirstStringArgument: true},
	{Selector: "dictionaryWithContentsOfFile:", Kind: behavior.OperationFileRead, BindsFirstStringArgument: true},
	{Selector: "enumeratorAtPath:", Kind: behavior.OperationFileEnumerate, BindsFirstStringArgument: true},
	{Selector: "fileExistsAtPath:", Kind: behavior.OperationFileMetadataQuery, BindsFirstStringArgument: true},
	{Selector: "fileExistsAtPath:isDirectory:", Kind: behavior.OperationFileMetadataQuery, BindsFirstStringArgument: true},
	{Selector: "initWithContentsOfFile:", Kind: behavior.OperationFileRead, BindsFirstStringArgument: true},
	{Selector: "initWithContentsOfFile:encoding:error:", Kind: behavior.OperationFileRead, BindsFirstStringArgument: true},
	{Selector: "initWithContentsOfFile:options:error:", Kind: behavior.OperationFileRead, BindsFirstStringArgument: true},
	{Selector: "initWithContentsOfFile:usedEncoding:error:", Kind: behavior.OperationFileRead, BindsFirstStringArgument: true},
	{Selector: "isExecutableFileAtPath:", Kind: behavior.OperationFileMetadataQuery, BindsFirstStringArgument: true},
	{Selector: "isReadableFileAtPath:", Kind: behavior.OperationFileMetadataQuery, BindsFirstStringArgument: true},
	{Selector: "isWritableFileAtPath:", Kind: behavior.OperationFileMetadataQuery, BindsFirstStringArgument: true},
	{Selector: "launchAndReturnError:", Kind: behavior.OperationProcessExecute},
	{Selector: "launchApplication:", Kind: behavior.OperationProcessExecute},
	{Selector: "launchedApplications", Kind: behavior.OperationProcessEnumerate},
	{Selector: "launchedTaskWithExecutableURL:arguments:error:terminationHandler:", Kind: behavior.OperationProcessExecute},
	{Selector: "launchedTaskWithLaunchPath:arguments:", Kind: behavior.OperationProcessExecute, BindsFirstStringArgument: true},
	{Selector: "moveItemAtPath:toPath:error:", Kind: behavior.OperationFileMove, BindsFirstStringArgument: true, BindsSecondStringArgument: true},
	{Selector: "openApplication:", Kind: behavior.OperationProcessExecute},
	{Selector: "openApplicationAtURL:configuration:completionHandler:", Kind: behavior.OperationProcessExecute},
	{Selector: "readDataToEndOfFile", Kind: behavior.OperationFileRead},
	{Selector: "removeItemAtPath:", Kind: behavior.OperationFileDelete, BindsFirstStringArgument: true},
	{Selector: "removeItemAtPath:error:", Kind: behavior.OperationFileDelete, BindsFirstStringArgument: true},
	{Selector: "removeItemAtURL:error:", Kind: behavior.OperationFileDelete},
	{Selector: "runningApplications", Kind: behavior.OperationProcessEnumerate},
	{Selector: "sendAsynchronousRequest:queue:completionHandler:", Kind: behavior.OperationNetworkConnect},
	{Selector: "sendSynchronousRequest:returningResponse:error:", Kind: behavior.OperationNetworkConnect},
	{Selector: "stringWithContentsOfFile:encoding:error:", Kind: behavior.OperationFileRead, BindsFirstStringArgument: true},
	{Selector: "stringWithContentsOfFile:usedEncoding:error:", Kind: behavior.OperationFileRead, BindsFirstStringArgument: true},
	{Selector: "subpathsOfDirectoryAtPath:error:", Kind: behavior.OperationFileEnumerate, BindsFirstStringArgument: true},
	{Selector: "writeToFile:atomically:", Kind: behavior.OperationFileWrite, BindsFirstStringArgument: true},
	{Selector: "writeToFile:atomically:encoding:error:", Kind: behavior.OperationFileWrite, BindsFirstStringArgument: true},
	{Selector: "writeToFile:options:error:", Kind: behavior.OperationFileWrite, BindsFirstStringArgument: true},
}

func machoObjCOperationRecognizerForSelector(selector string) (machoObjCOperationRecognizer, bool) {
	index := sort.Search(len(machoObjCOperationRecognizers), func(index int) bool {
		return machoObjCOperationRecognizers[index].Selector >= selector
	})
	if index >= len(machoObjCOperationRecognizers) || machoObjCOperationRecognizers[index].Selector != selector {
		return machoObjCOperationRecognizer{}, false
	}
	return machoObjCOperationRecognizers[index], true
}

func objcSelectorNetworkImplementation(content artifact.Content, scopeID, arch string, execution behavior.ExecutionContext, support behavior.Support, operationID, selector, evidenceID string) behavior.NetworkImplementationObservation {
	observation := behavior.NetworkImplementationObservation{
		Kind:          behavior.NetworkImplementationAPICall,
		SubjectNodeID: content.NodeID,
		ScopeID:       scopeID,
		Architecture:  arch,
		OperationIDs:  []string{operationID},
		APIOrTool:     selector,
		EvidenceIDs:   []string{evidenceID},
		Support:       support,
		Execution:     execution,
	}
	lower := strings.ToLower(selector)
	switch {
	case strings.Contains(lower, "datatask") || strings.Contains(lower, "downloadtask") || strings.Contains(lower, "uploadtask"):
		observation.HTTPImplementation = "URLSession"
		observation.TLSProvider = "Apple system TLS provider"
		observation.TLSProviderBasis = behavior.TLSProviderBasisOperatingSystem
		observation.TLSProfileFamily = "macOS system TLS family"
		observation.UnresolvedProperties = []string{"receiver type", "destination", "request configuration", "macOS build", "ALPN", "session state"}
	case strings.Contains(lower, "sendsynchronousrequest") || strings.Contains(lower, "sendasynchronousrequest"):
		observation.HTTPImplementation = "NSURLConnection"
		observation.TLSProvider = "Apple system TLS provider"
		observation.TLSProviderBasis = behavior.TLSProviderBasisOperatingSystem
		observation.TLSProfileFamily = "macOS system TLS family"
		observation.UnresolvedProperties = []string{"receiver type", "destination", "request configuration", "macOS build"}
	default:
		observation.UnresolvedProperties = []string{"receiver type", "destination"}
	}
	return observation
}

func removeUnresolved(values []string, value string) []string {
	out := values[:0]
	for _, item := range values {
		if item == value {
			continue
		}
		out = append(out, item)
	}
	return out
}

func isSemanticImportedSymbol(symbol string) bool {
	plain := strings.TrimPrefix(symbol, "_")
	if _, ok := nativePrimitiveForSymbol(plain); ok {
		return true
	}
	switch {
	case plain == "SecItemCopyMatching" || plain == "SecKeychainFindGenericPassword" || plain == "SecKeychainFindInternetPassword":
		return true
	case isNativeProcessExecutionSymbol(plain):
		return true
	case isProcessPrimitive(plain):
		return true
	case isInputEventMonitoringSymbol(plain) || isAudioRecordingQueueSymbol(plain) || isScreenshotSymbol(plain) || isDisplaySetupSymbol(plain) || isPasteboardReadSymbol(plain) || isPasteboardWriteSymbol(plain) || isClipboardSetupSymbol(plain) || isLibcurlPerformSymbol(plain) || isSocketConnectSymbol(plain) || isLoginItemSymbol(plain):
		return true
	case strings.Contains(plain, "URLSession") || strings.Contains(plain, "nw_connection") || strings.Contains(plain, "SSLHandshake"):
		return true
	default:
		return false
	}
}

func isScreenshotSymbol(symbol string) bool {
	switch symbol {
	case "CGWindowListCreateImage", "CGDisplayCreateImage":
		return true
	default:
		return false
	}
}

func isInputEventMonitoringSymbol(symbol string) bool {
	// Importing an event-tap constructor establishes only that the binary has
	// the API available. It does not establish that a tap is created, which
	// event mask is requested, or that keyboard data is captured. Import-only
	// evidence remains HEURISTIC; an exact called import becomes the neutral
	// input-event.tap.create operation, never a keylogging claim.
	return symbol == "CGEventTapCreate" || symbol == "CGEventTapCreateForPSN" || symbol == "CGEventTapCreateForPid"
}

func isAudioRecordingQueueSymbol(symbol string) bool {
	return symbol == "AudioQueueNewInput" || symbol == "AudioQueueNewInputWithDispatchQueue"
}

func isDisplaySetupSymbol(symbol string) bool {
	return symbol == "CGDisplayStreamCreate" || symbol == "CGGetActiveDisplayList"
}

func isPasteboardReadSymbol(symbol string) bool {
	return symbol == "PasteboardCopyItemFlavorData"
}

func isPasteboardWriteSymbol(symbol string) bool {
	return symbol == "PasteboardPutItemFlavor" || symbol == "PasteboardPutItemFlavorData"
}

func isClipboardSetupSymbol(symbol string) bool {
	return symbol == "PasteboardCreate" || symbol == "PasteboardSynchronize" || symbol == "OBJC_CLASS_$_NSPasteboard"
}

func isFileReadSymbol(symbol string) bool {
	switch symbol {
	case "read", "pread", "pread$UNIX2003", "readv", "fread", "fread_unlocked":
		return true
	default:
		return false
	}
}

func isFileOpenSymbol(symbol string) bool {
	switch symbol {
	case "open", "openat", "fopen", "fopen$UNIX2003", "freopen", "sqlite3_open", "sqlite3_open_v2":
		return true
	default:
		return false
	}
}

func isLibcurlPerformSymbol(symbol string) bool {
	return symbol == "curl_easy_perform"
}

func isSocketConnectSymbol(symbol string) bool {
	return isSocketConnectPrimitiveSymbol(symbol)
}

func isLoginItemSymbol(symbol string) bool {
	return symbol == "SMLoginItemSetEnabled"
}

func executionContextForMachOFunction(content artifact.Content, function machoFunction) behavior.ExecutionContext {
	if !function.Entrypoint && !function.Reachable {
		return unknownExecutionContext()
	}
	return executionContextForContent(content)
}

func extractEntitlementStrings(graph *behavior.Graph, content artifact.Content, arch string, image []byte, entitlementSlotsAbsent bool) {
	if entitlementSlotsAbsent || hasParsedEntitlementsXML(graph, content.NodeID, arch) {
		return
	}
	seen := map[string]bool{}
	items, truncated := asciiStrings(image, 8)
	for _, item := range items {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			break
		}
		item, ok := normalizeEntitlementString(item)
		if !ok || seen[item] {
			continue
		}
		seen[item] = true
		ev := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-strings", Kind: "entitlement-string", Value: item, Arch: arch})
		graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "entitlement", Value: item, EvidenceIDs: []string{ev}, Support: behavior.SupportHeuristic})
	}
	if truncated {
		graph.AddCoverage(behavior.Coverage{
			NodeID:       content.NodeID,
			AnalysisArea: "macho-entitlement-strings/" + arch,
			Status:       "partial",
			Detail:       fmt.Sprintf("entitlement string extraction capped at %d input bytes, %d runs, %d captured bytes, and %d bytes per string", maxMachOASCIIInputBytes, maxMachOASCIIStringRuns, maxMachOASCIIBytes, maxMachOASCIIStringBytes),
		})
	}
}

func hasParsedEntitlementsXML(graph *behavior.Graph, nodeID, arch string) bool {
	for _, item := range graph.ArtifactProperties {
		if item.NodeID != nodeID || item.Kind != "entitlements-xml" || item.Support != behavior.SupportDirect {
			continue
		}
		for _, evidenceID := range item.EvidenceIDs {
			if evidenceArchitecture(graph, evidenceID) == arch {
				return true
			}
		}
	}
	return false
}

func evidenceArchitecture(graph *behavior.Graph, evidenceID string) string {
	for _, evidence := range graph.Evidence {
		if evidence.ID == evidenceID {
			return evidence.Arch
		}
	}
	return ""
}

func normalizeEntitlementString(value string) (string, bool) {
	start := -1
	for _, marker := range []string{"com.apple.security.", "com.apple.private."} {
		if idx := strings.Index(value, marker); idx >= 0 && (start == -1 || idx < start) {
			start = idx
		}
	}
	if start < 0 {
		return "", false
	}
	value = value[start:]
	end := 0
	for end < len(value) {
		c := value[end]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' {
			end++
			continue
		}
		break
	}
	if end == 0 {
		return "", false
	}
	return value[:end], true
}

func dylibHTTPStack(lib string) string {
	switch {
	case strings.Contains(lib, "libcurl"):
		return "libcurl"
	case strings.Contains(lib, "cfnetwork"):
		return "CFNetwork"
	case strings.Contains(lib, "network.framework"):
		return "Apple Network.framework"
	default:
		return ""
	}
}

func dylibTLSOwner(lib string) string {
	switch {
	case strings.Contains(lib, "libssl"):
		return "OpenSSL-compatible TLS"
	case strings.Contains(lib, "libcurl"):
		return "libcurl-selected TLS backend"
	case strings.Contains(lib, "cfnetwork"):
		return "Apple system TLS provider"
	default:
		return ""
	}
}

func dylibTLSFamily(lib string) string {
	switch {
	case strings.Contains(lib, "libssl"):
		return "OpenSSL-compatible"
	case strings.Contains(lib, "libcurl"):
		return "backend-dependent"
	case strings.Contains(lib, "cfnetwork"):
		return "CFNetwork/SecureTransport"
	default:
		return ""
	}
}

func apiNetworkImplementation(kind behavior.NetworkImplementationKind, content artifact.Content, scopeID, arch string, execution behavior.ExecutionContext, support behavior.Support, operationID, symbol, evidenceID string, destinationKnown bool) behavior.NetworkImplementationObservation {
	observation := behavior.NetworkImplementationObservation{
		Kind:          kind,
		SubjectNodeID: content.NodeID,
		ScopeID:       scopeID,
		Architecture:  arch,
		OperationIDs:  []string{operationID},
		APIOrTool:     symbol,
		EvidenceIDs:   []string{evidenceID},
		Support:       support,
		Execution:     execution,
	}
	switch {
	case strings.Contains(symbol, "URLSession"):
		observation.HTTPImplementation = "URLSession"
		observation.TLSProvider = "Apple system TLS provider"
		observation.TLSProviderBasis = behavior.TLSProviderBasisOperatingSystem
		observation.TLSProfileFamily = "macOS system TLS family"
		observation.UnresolvedProperties = []string{"URL scheme", "macOS build", "session configuration", "destination", "ALPN", "session state"}
	case strings.Contains(symbol, "SSLHandshake"):
		observation.HTTPImplementation = "SecureTransport"
		observation.TLSProvider = "Apple system TLS provider"
		observation.TLSProviderBasis = behavior.TLSProviderBasisOperatingSystem
		observation.TLSProfileFamily = "SecureTransport"
		observation.UnresolvedProperties = []string{"macOS build", "TLS context options", "destination", "ALPN", "session state"}
	case strings.Contains(symbol, "nw_connection"):
		observation.HTTPImplementation = "Apple Network.framework"
		observation.UnresolvedProperties = []string{"whether TLS protocol options are configured", "macOS build", "destination"}
	case isLibcurlPerformSymbol(symbol):
		observation.HTTPImplementation = "libcurl"
		observation.TLSProvider = "libcurl-selected TLS backend"
		observation.TLSProviderBasis = behavior.TLSProviderBasisDynamicLibrary
		observation.TLSProfileFamily = "backend-dependent"
		observation.UnresolvedProperties = []string{"libcurl options", "runtime-selected TLS backend", "destination", "proxy configuration"}
	case isSocketConnectSymbol(symbol):
		observation.UnresolvedProperties = []string{"socket address family", "transport protocol", "port", "destination", "sockaddr-to-IP binding"}
	}
	if kind == behavior.NetworkImplementationAPIImport {
		observation.UnresolvedProperties = append(observation.UnresolvedProperties, "whether imported API is reached by executable code")
	}
	if destinationKnown {
		observation.UnresolvedProperties = removeUnresolved(observation.UnresolvedProperties, "destination")
	}
	return observation
}

func entropyForBytes(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var entropy float64
	total := float64(len(data))
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func machoArch(cpu macho.Cpu, sub uint32) string {
	sub = sub & 0x00ffffff
	switch cpu {
	case macho.CpuAmd64:
		if sub == 8 {
			return "x86_64h"
		}
		if sub != 0 && sub != 3 {
			return fmt.Sprintf("x86_64/%#x", sub)
		}
		return "x86_64"
	case macho.CpuArm64:
		if sub == 2 {
			return "arm64e"
		}
		if sub != 0 {
			return fmt.Sprintf("arm64/%#x", sub)
		}
		return "arm64"
	case macho.Cpu386:
		return "i386"
	default:
		return cpu.String()
	}
}

func extractMachOLoadCommandFeatures(graph *behavior.Graph, content artifact.Content, file *macho.File, arch string) {
	for _, load := range file.Loads {
		rawer, ok := load.(interface{ Raw() []byte })
		if !ok {
			continue
		}
		raw := rawer.Raw()
		if len(raw) < 8 {
			continue
		}
		switch cmd := file.ByteOrder.Uint32(raw[0:4]); cmd {
		case lcUUID:
			if len(raw) >= 24 {
				addMachOLoadFeature(graph, content, arch, "uuid", "macho.uuid", formatUUID(raw[8:24]))
			}
		case lcVersionMinMacOSX, lcVersionMinIPhoneOS, lcVersionMinTvOS, lcVersionMinWatch:
			if len(raw) >= 16 {
				value := machoBuildValue(
					versionMinPlatform(cmd),
					machoVersion(file.ByteOrder.Uint32(raw[8:12])),
					machoVersion(file.ByteOrder.Uint32(raw[12:16])),
				)
				addMachOLoadFeature(graph, content, arch, "version-min", "macho.version_min", value)
			}
		case lcBuildVersion:
			if len(raw) >= 24 {
				value := machoBuildValue(
					buildPlatform(file.ByteOrder.Uint32(raw[8:12])),
					machoVersion(file.ByteOrder.Uint32(raw[12:16])),
					machoVersion(file.ByteOrder.Uint32(raw[16:20])),
				)
				addMachOLoadFeature(graph, content, arch, "build-version", "macho.build_version", value)
			}
		}
	}
}

func addMachOLoadFeature(graph *behavior.Graph, content artifact.Content, arch, kind, key, value string) {
	if value == "" {
		return
	}
	ev := graph.AddEvidence(behavior.Evidence{
		NodeID:  content.NodeID,
		Logical: content.LogicalPath,
		Method:  "macho-load-command",
		Kind:    kind,
		Value:   value,
		Arch:    arch,
	})
	graph.AddFeature(behavior.Feature{
		NodeID:       content.NodeID,
		Architecture: arch,
		Key:          key,
		Value:        value,
		EvidenceIDs:  []string{ev},
		Support:      behavior.SupportDirect,
	})
}

func formatUUID(data []byte) string {
	if len(data) != 16 {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", data[0:4], data[4:6], data[6:8], data[8:10], data[10:16])
}

func machoVersion(value uint32) string {
	return fmt.Sprintf("%d.%d.%d", value>>16, (value>>8)&0xff, value&0xff)
}

func machoBuildValue(platform, minOS, sdk string) string {
	return fmt.Sprintf("platform=%s minos=%s sdk=%s", platform, minOS, sdk)
}

func versionMinPlatform(command uint32) string {
	switch command {
	case lcVersionMinMacOSX:
		return "macos"
	case lcVersionMinIPhoneOS:
		return "ios"
	case lcVersionMinTvOS:
		return "tvos"
	case lcVersionMinWatch:
		return "watchos"
	default:
		return fmt.Sprintf("load-command-%#x", command)
	}
}

func buildPlatform(platform uint32) string {
	switch platform {
	case 1:
		return "macos"
	case 2:
		return "ios"
	case 3:
		return "tvos"
	case 4:
		return "watchos"
	case 5:
		return "bridgeos"
	case 6:
		return "mac-catalyst"
	case 7:
		return "ios-simulator"
	case 8:
		return "tvos-simulator"
	case 9:
		return "watchos-simulator"
	case 10:
		return "driverkit"
	default:
		return fmt.Sprintf("platform-%d", platform)
	}
}

func asciiStrings(data []byte, min int) ([]string, bool) {
	runs, truncated := asciiStringRuns(data, min)
	out := make([]string, 0, len(runs))
	for _, run := range runs {
		out = append(out, run.Value)
	}
	return out, truncated
}

func asciiStringRuns(data []byte, min int) ([]asciiRun, bool) {
	budget := newASCIIRunBudget()
	runs := budget.scan(data, min)
	return runs, budget.truncated
}

type asciiRunBudget struct {
	scanBytesRemaining int
	runsRemaining      int
	bytesRemaining     int
	truncated          bool
}

func newASCIIRunBudget() asciiRunBudget {
	return asciiRunBudget{
		scanBytesRemaining: maxMachOASCIIInputBytes,
		runsRemaining:      maxMachOASCIIStringRuns,
		bytesRemaining:     maxMachOASCIIBytes,
	}
}

func (budget *asciiRunBudget) scan(data []byte, min int) []asciiRun {
	if min <= 0 {
		min = 1
	}
	if budget.scanBytesRemaining <= 0 || budget.runsRemaining <= 0 || budget.bytesRemaining < min {
		if len(data) > 0 {
			budget.truncated = true
		}
		return nil
	}
	if len(data) > budget.scanBytesRemaining {
		data = data[:budget.scanBytesRemaining]
		budget.truncated = true
	}
	budget.scanBytesRemaining -= len(data)
	var runs []asciiRun
	start := -1
	for i, b := range data {
		if b >= 32 && b < 127 {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= min {
			runs = budget.append(runs, data, start, i, min)
			if budget.runsRemaining <= 0 || budget.bytesRemaining < min {
				if i+1 < len(data) {
					budget.truncated = true
				}
				return runs
			}
		}
		start = -1
	}
	if start >= 0 && len(data)-start >= min {
		runs = budget.append(runs, data, start, len(data), min)
	}
	return runs
}

func (budget *asciiRunBudget) append(runs []asciiRun, data []byte, start, end, min int) []asciiRun {
	if budget.runsRemaining <= 0 || budget.bytesRemaining < min {
		budget.truncated = true
		return runs
	}
	originalEnd := end
	if end-start > maxMachOASCIIStringBytes {
		end = start + maxMachOASCIIStringBytes
		budget.truncated = true
	}
	if end-start > budget.bytesRemaining {
		end = start + budget.bytesRemaining
		budget.truncated = true
	}
	if end-start < min {
		budget.truncated = true
		return runs
	}
	runs = append(runs, asciiRun{Offset: start, Value: string(data[start:end])})
	budget.runsRemaining--
	budget.bytesRemaining -= end - start
	if end < originalEnd {
		budget.truncated = true
	}
	return runs
}

func cstring(data []byte) string {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		data = data[:i]
	}
	return string(data)
}
