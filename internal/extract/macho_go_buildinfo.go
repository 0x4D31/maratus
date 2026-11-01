package extract

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxGoBuildInfoBytes   = 2 << 20
	maxGoBuildInfoRecords = 1024
	maxGoBuildInfoLine    = 16 << 10
)

var goBuildInfoMagic = []byte("\xff Go buildinf:")

type goBuildInfoRecord struct {
	key        string
	value      string
	qualifiers map[string]string
	offset     int
	length     int
}

// extractMachOGoBuildInfo decodes only the modern (Go 1.18+) inline build-info
// representation from the dedicated Mach-O section. It never invokes another
// executable parser or interprets Go code, pclntab data, or ABI values; the
// separate direct-call enricher owns the small supported ABI subset.
func extractMachOGoBuildInfo(graph *behavior.Graph, content artifact.Content, file *macho.File, arch string, image []byte) {
	for _, section := range file.Sections {
		if section == nil || section.Name != "__go_buildinfo" || !machoSectionHasFileData(section) || section.Size == 0 {
			continue
		}
		data, truncated, err := machoSectionPrefix(image, section, maxGoBuildInfoBytes)
		if err != nil {
			addPartialCoverageOnce(graph, content.NodeID, "macho-go-buildinfo/"+arch, "Go build-info section could not be read within its validated file extent")
			return
		}
		records, detail, ok := decodeInlineGoBuildInfo(data)
		if !ok {
			addPartialCoverageOnce(graph, content.NodeID, "macho-go-buildinfo/"+arch, detail)
			return
		}
		if truncated {
			addPartialCoverageOnce(graph, content.NodeID, "macho-go-buildinfo/"+arch, fmt.Sprintf("Go build-info input was capped at %d bytes", maxGoBuildInfoBytes))
		}
		counts := map[string]int{}
		for _, record := range records {
			if graph.WorkLimitReached() {
				graph.MarkWorkOmitted()
				return
			}
			localOffset := uint64(section.Offset) + uint64(record.offset)
			if localOffset > uint64(^uint(0)>>1) {
				addPartialCoverageOnce(graph, content.NodeID, "macho-go-buildinfo/"+arch, "Go build-info evidence offset is not representable on this build")
				return
			}
			evidenceID := graph.AddEvidence(machOEvidenceAt(content, int(localOffset), behavior.Evidence{
				NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-go-buildinfo", Kind: record.key,
				Value: record.value, Arch: arch,
			}))
			if evidenceID == "" {
				continue
			}
			graph.AddFeature(behavior.Feature{
				NodeID: content.NodeID, Architecture: arch, Key: record.key, Value: record.value,
				Qualifiers: record.qualifiers, EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect,
			})
			counts[record.key]++
			switch record.key {
			case "go.build.version":
				graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "go-toolchain", Value: record.value, EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect})
			case "go.package.path":
				graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "go-package-path", Value: record.value, EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect})
			case "go.main.module":
				graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "go-main-module", Value: goModuleDisplay(record.value, record.qualifiers["version"]), EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect})
			}
		}
		graph.AddCoverage(behavior.Coverage{
			NodeID: content.NodeID, AnalysisArea: "macho-go-buildinfo/" + arch, Status: "analyzed",
			Detail: fmt.Sprintf("bounded inline Go build metadata recovered: %d records (%d dependencies)", len(records), counts["go.dependency"]),
		})
		// addPartialCoverageOnce also suppresses the same area emitted by the
		// pclntab/direct-call path. Build metadata can survive stripping or a
		// rejected function table, so its presence must not silently imply full
		// Go semantic support.
		addPartialCoverageOnce(graph, content.NodeID, "macho-go-semantics/"+arch, machoGoSemanticCoverageDetail)
		return
	}
}

func decodeInlineGoBuildInfo(data []byte) ([]goBuildInfoRecord, string, bool) {
	start := bytes.Index(data, goBuildInfoMagic)
	if start < 0 {
		return nil, "Go build-info section does not contain the expected bounded header", false
	}
	if bytes.Contains(data[start+len(goBuildInfoMagic):], goBuildInfoMagic) {
		return nil, "Go build-info section contains multiple headers; provenance is ambiguous", false
	}
	if start+32 > len(data) {
		return nil, "Go build-info header is truncated", false
	}
	if data[start+14] != 4 && data[start+14] != 8 {
		return nil, "Go build-info pointer size is invalid", false
	}
	flags := data[start+15]
	if flags&^byte(0x3) != 0 {
		return nil, "Go build-info flags contain unsupported bits", false
	}
	if flags&0x2 == 0 {
		return nil, "pointer-based Go build info predating the inline Go 1.18 format is unsupported", false
	}
	position := start + 32
	version, versionOffset, next, ok := goBuildInfoString(data, position)
	if !ok || !validGoBuildInfoValue(version, 256) {
		return nil, "Go build-info version string is malformed or exceeds its bound", false
	}
	module, moduleOffset, _, ok := goBuildInfoString(data, next)
	if !ok || len(module) > maxGoBuildInfoBytes-32 {
		return nil, "Go build-info module string is malformed or exceeds its bound", false
	}
	records := []goBuildInfoRecord{{key: "go.build.version", value: version, offset: versionOffset, length: len(version)}}
	if len(module) >= 33 && module[len(module)-17] == '\n' {
		module = module[16 : len(module)-16]
		moduleOffset += 16
	} else if module != "" {
		return nil, "Go build-info module framing is malformed", false
	}
	if module != "" && (!utf8.ValidString(module) || strings.ContainsAny(module, "\x00\r")) {
		return nil, "Go build-info module records are not valid bounded text", false
	}
	parsed, detail, ok := parseGoBuildInfoLines(module, moduleOffset)
	if !ok {
		return nil, detail, false
	}
	return append(records, parsed...), "", true
}

func goBuildInfoString(data []byte, offset int) (value string, valueOffset, next int, ok bool) {
	if offset < 0 || offset >= len(data) {
		return "", 0, 0, false
	}
	length, prefix := binary.Uvarint(data[offset:])
	if prefix <= 0 || length > maxGoBuildInfoBytes || uint64(offset+prefix) > uint64(len(data)) || length > uint64(len(data)-(offset+prefix)) {
		return "", 0, 0, false
	}
	valueOffset = offset + prefix
	next = valueOffset + int(length)
	return string(data[valueOffset:next]), valueOffset, next, true
}

func parseGoBuildInfoLines(module string, baseOffset int) ([]goBuildInfoRecord, string, bool) {
	var records []goBuildInfoRecord
	previousModule := -1
	for position := 0; position < len(module); {
		if len(records) >= maxGoBuildInfoRecords {
			return nil, fmt.Sprintf("Go build-info record count exceeds %d", maxGoBuildInfoRecords), false
		}
		end := strings.IndexByte(module[position:], '\n')
		if end < 0 {
			return nil, "Go build-info line is not newline terminated", false
		}
		end += position
		if end-position > maxGoBuildInfoLine {
			return nil, fmt.Sprintf("Go build-info line exceeds %d bytes", maxGoBuildInfoLine), false
		}
		line := module[position:end]
		recordOffset := baseOffset + position
		position = end + 1
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "path\t"):
			value := strings.TrimPrefix(line, "path\t")
			if !validGoBuildInfoValue(value, maxGoBuildInfoLine) {
				return nil, "Go package path is malformed", false
			}
			records = append(records, goBuildInfoRecord{key: "go.package.path", value: value, offset: recordOffset + len("path\t"), length: len(value)})
			previousModule = -1
		case strings.HasPrefix(line, "mod\t"), strings.HasPrefix(line, "dep\t"):
			key, prefix := "go.main.module", "mod\t"
			if strings.HasPrefix(line, "dep\t") {
				key, prefix = "go.dependency", "dep\t"
			}
			path, qualifiers, ok := parseGoModuleFields(strings.TrimPrefix(line, prefix))
			if !ok {
				return nil, "Go module record is malformed", false
			}
			records = append(records, goBuildInfoRecord{key: key, value: path, qualifiers: qualifiers, offset: recordOffset + len(prefix), length: len(line) - len(prefix)})
			previousModule = len(records) - 1
		case strings.HasPrefix(line, "=>\t"):
			if previousModule < 0 {
				return nil, "Go module replacement has no preceding module", false
			}
			path, qualifiers, ok := parseGoModuleFields(strings.TrimPrefix(line, "=>\t"))
			if !ok {
				return nil, "Go module replacement is malformed", false
			}
			qualifiers["replaces"] = records[previousModule].value
			records = append(records, goBuildInfoRecord{key: "go.module.replacement", value: path, qualifiers: qualifiers, offset: recordOffset + len("=>\t"), length: len(line) - len("=>\t")})
			previousModule = -1
		case strings.HasPrefix(line, "build\t"):
			value := strings.TrimPrefix(line, "build\t")
			if !validGoBuildInfoValue(value, maxGoBuildInfoLine) || !strings.Contains(value, "=") {
				return nil, "Go build setting is malformed", false
			}
			records = append(records, goBuildInfoRecord{key: "go.build.setting", value: value, offset: recordOffset + len("build\t"), length: len(value)})
			previousModule = -1
		default:
			return nil, "Go build-info contains an unsupported record", false
		}
	}
	return records, "", true
}

func parseGoModuleFields(value string) (string, map[string]string, bool) {
	fields := strings.Split(value, "\t")
	if len(fields) < 2 || len(fields) > 3 || !validGoBuildInfoValue(fields[0], maxGoBuildInfoLine) || !validGoBuildInfoValue(fields[1], maxGoBuildInfoLine) {
		return "", nil, false
	}
	qualifiers := map[string]string{"version": fields[1]}
	if len(fields) == 3 {
		if fields[2] != "" && !validGoBuildInfoValue(fields[2], maxGoBuildInfoLine) {
			return "", nil, false
		}
		if fields[2] != "" {
			qualifiers["checksum"] = fields[2]
		}
	}
	return fields[0], qualifiers, true
}

func validGoBuildInfoValue(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func goModuleDisplay(path, version string) string {
	if version == "" || version == "(devel)" {
		return path
	}
	return path + "@" + version
}
