package extract

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
)

const (
	maxMachOChainedSegments        = 4096
	maxMachOChainedBindFixups      = 200000
	dyldChainedPtrStartNone        = 0xffff
	dyldChainedPtrStartMulti       = 0x8000
	dyldChainedPtrArm64E           = 1
	dyldChainedPtr64               = 2
	dyldChainedPtr64Offset         = 6
	dyldChainedPtrArm64EUserland   = 9
	dyldChainedPtrArm64EUserland24 = 12
)

// machoChainedPointerBindings walks only the validated 64-bit userland bind
// subset of LC_DYLD_CHAINED_FIXUPS. A result identifies an on-image pointer
// slot and its exact import-table symbol. It does not apply rebases, resolve a
// library, materialize a pointer value, or prove that the slot is read.
func machoChainedPointerBindings(file *macho.File, image []byte) (map[uint64]machoDyldBinding, bool, string) {
	return machoChainedPointerBindingsWithLimit(file, image, maxMachOChainedBindFixups)
}

func machoChainedPointerBindingsWithLimit(file *macho.File, image []byte, recordLimit int) (map[uint64]machoDyldBinding, bool, string) {
	out := map[uint64]machoDyldBinding{}
	if file == nil || file.ByteOrder == nil {
		return out, false, ""
	}
	command, present, commandDetail := findMachOChainedFixupCommand(file)
	if !present || commandDetail != "" {
		return out, present, commandDetail
	}
	if file.Magic != macho.Magic64 || file.ByteOrder != binary.LittleEndian {
		return out, true, "LC_DYLD_CHAINED_FIXUPS pointer bindings require a little-endian 64-bit Mach-O"
	}
	if recordLimit < 0 {
		return out, true, "LC_DYLD_CHAINED_FIXUPS pointer binding budget is invalid"
	}
	imports, _, importDetail := machoChainedImports(file, image, 0)
	if importDetail != "" {
		return out, true, importDetail
	}
	if command.dataSize < 28 || command.dataSize > maxMachOChainedFixupBytes {
		return out, true, "LC_DYLD_CHAINED_FIXUPS payload is outside the supported binding size"
	}
	start, size := uint64(command.dataOff), uint64(command.dataSize)
	if start > uint64(len(image)) || size > uint64(len(image))-start {
		return out, true, "LC_DYLD_CHAINED_FIXUPS payload exceeds retained Mach-O bytes"
	}
	payload := image[start : start+size]
	startsOffset := uint64(file.ByteOrder.Uint32(payload[4:8]))
	if startsOffset > uint64(len(payload)) || uint64(len(payload))-startsOffset < 4 {
		return out, true, "LC_DYLD_CHAINED_FIXUPS starts-in-image header is outside its payload"
	}
	starts := payload[startsOffset:]
	segmentCount := uint64(file.ByteOrder.Uint32(starts[0:4]))
	if segmentCount > maxMachOChainedSegments || segmentCount > (uint64(len(starts))-4)/4 {
		return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment count %d exceeds its table or parser limit %d", segmentCount, maxMachOChainedSegments)
	}
	segments := loadedMachOSegments(file)
	if segmentCount > uint64(len(segments)) {
		return out, true, "LC_DYLD_CHAINED_FIXUPS segment table exceeds retained Mach-O segments"
	}
	imageBase, ok := chainedFixupImageBase(segments)
	if !ok && segmentCount > 0 {
		return out, true, "LC_DYLD_CHAINED_FIXUPS has no file-backed image base"
	}
	processed := 0
	for segmentIndex := uint64(0); segmentIndex < segmentCount; segmentIndex++ {
		infoOffset := uint64(file.ByteOrder.Uint32(starts[4+segmentIndex*4 : 8+segmentIndex*4]))
		if infoOffset == 0 {
			continue
		}
		if infoOffset > uint64(len(starts)) || uint64(len(starts))-infoOffset < 22 {
			return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d starts record is truncated", segmentIndex)
		}
		info := starts[infoOffset:]
		infoSize := uint64(file.ByteOrder.Uint32(info[0:4]))
		if infoSize < 22 || infoSize > uint64(len(info)) {
			return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d starts record has an invalid size", segmentIndex)
		}
		info = info[:infoSize]
		pageSize := uint64(file.ByteOrder.Uint16(info[4:6]))
		pointerFormat := file.ByteOrder.Uint16(info[6:8])
		segmentOffset := file.ByteOrder.Uint64(info[8:16])
		pageCount := uint64(file.ByteOrder.Uint16(info[20:22]))
		if pageSize != 0x1000 && pageSize != 0x4000 {
			return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d uses unsupported page size 0x%x", segmentIndex, pageSize)
		}
		if pageCount > (uint64(len(info))-22)/2 {
			return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d page-start table is truncated", segmentIndex)
		}
		segment := segments[segmentIndex]
		if segment.Addr < imageBase || segmentOffset != segment.Addr-imageBase {
			return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d memory offset does not match the retained segment", segmentIndex)
		}
		segmentPages := segment.Memsz / pageSize
		if segment.Memsz%pageSize != 0 {
			segmentPages++
		}
		if pageCount > segmentPages {
			return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d page count exceeds segment memory", segmentIndex)
		}
		stride, ordinalBits, supported := chainedBindFormat(pointerFormat)
		for pageIndex := uint64(0); pageIndex < pageCount; pageIndex++ {
			pageStart := file.ByteOrder.Uint16(info[22+pageIndex*2 : 24+pageIndex*2])
			if pageStart == dyldChainedPtrStartNone {
				continue
			}
			if pageStart&dyldChainedPtrStartMulti != 0 {
				return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d page %d uses unsupported multiple chain starts", segmentIndex, pageIndex)
			}
			if !supported {
				return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS pointer format %d is unsupported for exact bind-slot recovery", pointerFormat)
			}
			if uint64(pageStart) > pageSize-8 {
				return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d page %d starts outside the page", segmentIndex, pageIndex)
			}
			location := pageIndex*pageSize + uint64(pageStart)
			pageEnd := min((pageIndex+1)*pageSize, segment.Filesz)
			for {
				if processed >= recordLimit {
					return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS pointer binding record limit %d reached", recordLimit)
				}
				processed++
				if location > segment.Filesz || 8 > segment.Filesz-location || segment.Offset > uint64(len(image)) || location > uint64(len(image))-segment.Offset || 8 > uint64(len(image))-segment.Offset-location {
					return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d chain leaves retained file bytes", segmentIndex)
				}
				fileOffset := segment.Offset + location
				raw := file.ByteOrder.Uint64(image[fileOffset : fileOffset+8])
				ordinal, next, bind, valid := decodeChainedBindPointer(raw, pointerFormat, ordinalBits)
				if !valid {
					return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d contains a malformed bind pointer", segmentIndex)
				}
				if bind {
					if ordinal >= uint64(len(imports)) {
						return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d bind ordinal %d exceeds the import table", segmentIndex, ordinal)
					}
					if imports[ordinal].addend != 0 || chainedBindHasAddend(raw, pointerFormat) {
						return out, true, "LC_DYLD_CHAINED_FIXUPS nonzero binding addend does not identify an exact imported symbol"
					}
					if segment.Addr > ^uint64(0)-location || fileOffset > uint64(^uint(0)>>1) || uint64(imports[ordinal].nameOffset) > uint64(^uint(0)>>1) {
						return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d bind location is unrepresentable", segmentIndex)
					}
					slotVA := segment.Addr + location
					binding := machoDyldBinding{Name: imports[ordinal].name, SlotVA: slotVA, SymbolOffset: int(imports[ordinal].nameOffset), StreamOffset: int(fileOffset), Stream: "chained-fixups"}
					if existing, exists := out[slotVA]; exists && existing.Name != binding.Name {
						return out, true, "LC_DYLD_CHAINED_FIXUPS assigns conflicting symbols to one pointer slot"
					}
					out[slotVA] = binding
				}
				if next == 0 {
					break
				}
				delta := next * stride
				if delta == 0 || location > ^uint64(0)-delta {
					return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d chain has an invalid next delta", segmentIndex)
				}
				location += delta
				if location >= pageEnd || location > pageIndex*pageSize+pageSize-8 {
					return out, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS segment %d chain crosses its page boundary", segmentIndex)
				}
			}
		}
	}
	return out, true, ""
}

func chainedBindHasAddend(raw uint64, format uint16) bool {
	switch format {
	case dyldChainedPtr64, dyldChainedPtr64Offset:
		return (raw>>24)&0xff != 0
	case dyldChainedPtrArm64E, dyldChainedPtrArm64EUserland, dyldChainedPtrArm64EUserland24:
		// Authenticated binds use these bits for diversity/address/key data,
		// not an addend. Only unauthenticated binds carry the signed addend.
		return raw>>63 == 0 && (raw>>32)&0x7ffff != 0
	default:
		return false
	}
}

func chainedFixupImageBase(segments []*macho.Segment) (uint64, bool) {
	var base uint64
	found := false
	for _, segment := range segments {
		if segment == nil || segment.Offset != 0 || segment.Filesz == 0 {
			continue
		}
		if !found || segment.Addr < base {
			base, found = segment.Addr, true
		}
	}
	return base, found
}

func chainedBindFormat(format uint16) (stride, ordinalBits uint64, ok bool) {
	switch format {
	case dyldChainedPtr64, dyldChainedPtr64Offset:
		return 4, 24, true
	case dyldChainedPtrArm64E, dyldChainedPtrArm64EUserland:
		return 8, 16, true
	case dyldChainedPtrArm64EUserland24:
		return 8, 24, true
	default:
		return 0, 0, false
	}
}

func decodeChainedBindPointer(raw uint64, format uint16, ordinalBits uint64) (ordinal, next uint64, bind, valid bool) {
	switch format {
	case dyldChainedPtr64, dyldChainedPtr64Offset:
		bind = raw>>63 == 1
		next = (raw >> 51) & 0xfff
		if !bind {
			if (raw>>44)&0x7f != 0 {
				return 0, 0, false, false
			}
			return 0, next, false, true
		}
		if (raw>>32)&0x7ffff != 0 {
			return 0, 0, true, false
		}
	case dyldChainedPtrArm64E, dyldChainedPtrArm64EUserland, dyldChainedPtrArm64EUserland24:
		bind = (raw>>62)&1 == 1
		next = (raw >> 51) & 0x7ff
		if !bind {
			return 0, next, false, true
		}
		zeroBits := uint64(16)
		if ordinalBits == 24 {
			zeroBits = 8
		}
		if (raw>>ordinalBits)&((uint64(1)<<zeroBits)-1) != 0 {
			return 0, 0, true, false
		}
	default:
		return 0, 0, false, false
	}
	return raw & ((uint64(1) << ordinalBits) - 1), next, true, true
}
