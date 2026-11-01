package artifact

import (
	"bytes"
	"debug/macho"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/machox"
)

const (
	bunStandaloneSegment     = "__BUN"
	bunStandaloneSection     = "__bun"
	bunStandalonePathPrefix  = "/$bunfs/root/"
	bunStandaloneEntryHeader = "#!/usr/bin/env bun\n// @bun\n"
	bunStandaloneFooter      = "\n---- Bun! ----\n"
	maxBunStandalonePath     = 4096
)

type bunStandaloneEntry struct {
	sectionOffset int64
	sectionSize   int64
	embeddedPath  string
	sourceOffset  int64
	source        []byte
	evidence      []LocatedArtifactEvidence
}

// recognizeBunStandaloneThin validates Bun's dedicated Mach-O payload
// representation before returning the exact textual entrypoint. It does not
// scan the runtime for Bun-looking strings and does not interpret the trailing
// module/asset metadata.
func recognizeBunStandaloneThin(data []byte) (bunStandaloneEntry, bool) {
	isFat, _, err := PreflightMachOSlices(data)
	if err != nil || isFat {
		return bunStandaloneEntry{}, false
	}
	file, err := machox.NewFile(bytes.NewReader(data))
	if err != nil {
		return bunStandaloneEntry{}, false
	}
	defer func() { _ = file.Close() }()

	var selected *macho.Section
	for _, section := range file.Sections {
		if section == nil || section.Seg != bunStandaloneSegment || section.Name != bunStandaloneSection {
			continue
		}
		if selected != nil {
			return bunStandaloneEntry{}, false
		}
		selected = section
	}
	if selected == nil || selected.Size < 8 || uint64(selected.Offset) > uint64(len(data)) ||
		selected.Size > uint64(len(data))-uint64(selected.Offset) {
		return bunStandaloneEntry{}, false
	}
	payload := data[int(selected.Offset):int(uint64(selected.Offset)+selected.Size)]
	if file.ByteOrder.Uint64(payload[:8]) != uint64(len(payload)-8) {
		return bunStandaloneEntry{}, false
	}
	body := payload[8:]
	pathEnd := bytes.IndexByte(body, 0)
	if pathEnd <= len(bunStandalonePathPrefix) || pathEnd > maxBunStandalonePath {
		return bunStandaloneEntry{}, false
	}
	embeddedPath := string(body[:pathEnd])
	if !utf8.ValidString(embeddedPath) || !strings.HasPrefix(embeddedPath, bunStandalonePathPrefix) {
		return bunStandaloneEntry{}, false
	}
	sourceStart := pathEnd + 1
	sourceEndRelative := bytes.IndexByte(body[sourceStart:], 0)
	if sourceEndRelative <= 0 {
		return bunStandaloneEntry{}, false
	}
	sourceEnd := sourceStart + sourceEndRelative
	source := body[sourceStart:sourceEnd]
	if !utf8.Valid(source) || !bytes.HasPrefix(source, []byte(bunStandaloneEntryHeader)) ||
		!bytes.HasSuffix(payload, []byte(bunStandaloneFooter)) {
		return bunStandaloneEntry{}, false
	}

	sectionOffset := int64(selected.Offset)
	sourceOffset := sectionOffset + 8 + int64(sourceStart)
	footerOffset := sectionOffset + int64(len(payload)-len(bunStandaloneFooter))
	evidence := []LocatedArtifactEvidence{
		{
			Offset: sectionOffset,
			Kind:   "bun-standalone-section",
			Value:  fmt.Sprintf("%s,%s size=%d", bunStandaloneSegment, bunStandaloneSection, selected.Size),
		},
		{
			Offset: sectionOffset + 8,
			Kind:   "bun-embedded-entry-path",
			Value:  embeddedPath,
		},
		{
			Offset: sourceOffset,
			Kind:   "bun-entry-header",
			Value:  "#!/usr/bin/env bun; // @bun",
		},
		{
			Offset: footerOffset,
			Kind:   "bun-standalone-footer",
			Value:  strings.TrimSpace(bunStandaloneFooter),
		},
	}
	return bunStandaloneEntry{
		sectionOffset: sectionOffset,
		sectionSize:   uint64ToInt64(selected.Size),
		embeddedPath:  embeddedPath,
		sourceOffset:  sourceOffset,
		source:        source,
		evidence:      evidence,
	}, true
}

func (s *scanner) scanBunStandalone(carrierID, logical string, data []byte, kind string, depth int) bool {
	if kind != "macho" {
		return false
	}
	entry, ok := recognizeBunStandaloneThin(data)
	if !ok {
		return false
	}
	setArtifactPackagingTechnology(&s.graph, carrierID, "Bun", entry.evidence)

	const unsupportedDetail = "Bun standalone textual entrypoint recovered; trailing embedded module/asset metadata is not decoded"
	if s.options.DisableContainerExpansion {
		s.markNodePartial(carrierID, unsupportedDetail+"; entry extraction skipped by --expand-containers=false")
		return true
	}
	if depth >= s.options.MaxArchiveDepth {
		s.markNodePartial(carrierID, fmt.Sprintf("%s; archive depth limit %d prevented entry extraction", unsupportedDetail, s.options.MaxArchiveDepth))
		return true
	}

	childLogical, ok := archiveLogicalPath(logical, "_bun/entry.js")
	if !ok {
		s.markNodePartial(carrierID, unsupportedDetail+"; synthetic entry path exceeded the artifact path limit")
		return true
	}
	var childID string
	if int64(len(entry.source)) > s.options.MaxFileBytes {
		childID = s.addSkippedVirtualEntry(carrierID, "", childLogical, VirtualEntry{
			Kind:       "script",
			MediaType:  "text/plain",
			Size:       int64(len(entry.source)),
			Provenance: "bun-standalone-entry",
			SourceRole: "runtime",
			SkipDetail: fmt.Sprintf("Bun standalone entry exceeds max file bytes %d", s.options.MaxFileBytes),
		})
	} else {
		childID = s.scanVirtualWithRole(carrierID, childLogical, entry.source, false, "bun-standalone-entry", "runtime", depth+1)
	}
	if childID == "" {
		s.markNodePartial(carrierID, unsupportedDetail+"; declared entry could not be retained")
		return true
	}
	s.graph.AddSupportedOrderedEdge(carrierID, childID, "loader-invokes", 0, entry.evidence)
	s.markNodePartial(carrierID, unsupportedDetail)
	return true
}
