package extract

import (
	"debug/macho"
	"fmt"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func retainMachOUnixThreadEntry(graph *behavior.Graph, content artifact.Content, file *macho.File, arch string) {
	offset := 32 // The only supported thread state is in a 64-bit image.
	for _, load := range file.Loads {
		raw := load.Raw()
		if len(raw) >= 8 && file.ByteOrder.Uint32(raw[:4]) == 5 {
			entry, ok := machoUnixThreadEntrypointVA(file, raw)
			if !ok {
				return
			}
			value := fmt.Sprintf("0x%x", entry)
			evidence := graph.AddEvidence(machOEvidenceAt(content, offset+144, behavior.Evidence{
				NodeID: content.NodeID, Logical: content.LogicalPath, Arch: arch,
				Method: "macho-unixthread", Kind: "declared-process-entry", Value: value,
			}))
			graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Architecture: arch,
				Key: "macho.entrypoint", Value: value, Qualifiers: map[string]string{"command": "LC_UNIXTHREAD"},
				EvidenceIDs: []string{evidence}, Support: behavior.SupportDirect})
			return
		}
		offset += len(raw)
	}
}

// Decode the complete x86_THREAD_STATE64 layout from XNU's
// mach/i386/{thread_status.h,_structs.h}: flavor 4, 42 uint32 words,
// with RIP at register index 16. Additional or other states remain unsupported.
func machoUnixThreadEntrypointVA(file *macho.File, raw []byte) (uint64, bool) {
	const commandSize = 16 + 42*4
	if file.Cpu != macho.CpuAmd64 || len(raw) != commandSize ||
		file.ByteOrder.Uint32(raw[4:8]) != commandSize ||
		file.ByteOrder.Uint32(raw[8:12]) != 4 ||
		file.ByteOrder.Uint32(raw[12:16]) != 42 {
		return 0, false
	}
	entry := file.ByteOrder.Uint64(raw[16+16*8 : 16+17*8])
	matched := false
	for _, load := range file.Loads {
		segment, ok := load.(*macho.Segment)
		if !ok || segment.Filesz == 0 {
			continue
		}
		if segment.Addr > ^uint64(0)-segment.Filesz || segment.Offset > ^uint64(0)-segment.Filesz {
			return 0, false
		}
		if entry < segment.Addr || entry-segment.Addr >= segment.Filesz {
			continue
		}
		if matched || segment.Prot&4 == 0 || segment.Filesz > segment.Memsz {
			return 0, false
		}
		// Require the reverse mapping to identify the same unique file-backed VA.
		mapped, ok := fileOffsetToVA(file, segment.Offset+entry-segment.Addr)
		if !ok || mapped != entry {
			return 0, false
		}
		matched = true
	}
	return entry, matched
}
