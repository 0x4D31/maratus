package extract

import (
	"debug/macho"
	"fmt"
)

const (
	lcDyldInfo                       = 0x22
	lcDyldInfoOnly                   = 0x80000022
	maxMachODyldBindBytes            = 16 << 20
	maxMachODyldBindRecordsPerStream = 200000
	maxMachODyldBindSymbolNameLen    = 4096

	dyldBindTypePointer = 1
)

type machoDyldBinding struct {
	Name         string
	SlotVA       uint64
	SymbolOffset int
	StreamOffset int
	Stream       string
}

type machoDyldInfoCommand struct {
	bindOff, bindSize         uint32
	lazyBindOff, lazyBindSize uint32
}

// machoClassicDyldBindings interprets only the bounded pointer-binding subset
// of LC_DYLD_INFO[_ONLY]. The result maps exact image slots to exact imported
// symbols. It does not apply rebases, resolve libraries, or infer that a slot
// is read or called.
func machoClassicDyldBindings(file *macho.File, image []byte) (map[uint64]machoDyldBinding, bool, string) {
	command, present, detail := findMachODyldInfoCommand(file)
	if !present || detail != "" {
		return nil, present, detail
	}
	segments := loadedMachOSegments(file)
	if len(segments) == 0 {
		return nil, true, "LC_DYLD_INFO binding streams have no loaded segments"
	}
	out := map[uint64]machoDyldBinding{}
	ambiguous := map[uint64]bool{}
	for _, stream := range []struct {
		name      string
		off, size uint32
		lazy      bool
	}{
		{name: "bind", off: command.bindOff, size: command.bindSize},
		{name: "lazy-bind", off: command.lazyBindOff, size: command.lazyBindSize, lazy: true},
	} {
		if stream.size == 0 {
			continue
		}
		if stream.size > maxMachODyldBindBytes {
			return nil, true, fmt.Sprintf("LC_DYLD_INFO %s stream size %d exceeds parser limit %d", stream.name, stream.size, maxMachODyldBindBytes)
		}
		start, size := uint64(stream.off), uint64(stream.size)
		if start > uint64(len(image)) || size > uint64(len(image))-start {
			return nil, true, fmt.Sprintf("LC_DYLD_INFO %s stream exceeds retained Mach-O bytes", stream.name)
		}
		parsed, parseDetail := parseMachODyldBindStream(file, image[start:start+size], int(stream.off), segments, stream.name, stream.lazy, maxMachODyldBindRecordsPerStream)
		if parseDetail != "" {
			// An unparsed suffix may rebind a slot already seen in either
			// stream. A prefix cannot establish the final exact identity.
			return nil, true, parseDetail
		}
		for slot, binding := range parsed {
			if ambiguous[slot] {
				continue
			}
			if existing, exists := out[slot]; exists && existing.Name != binding.Name {
				delete(out, slot)
				ambiguous[slot] = true
				continue
			}
			out[slot] = binding
		}
	}
	if len(ambiguous) > 0 {
		return out, true, "LC_DYLD_INFO assigns conflicting symbols across binding streams; affected slots were discarded"
	}
	return out, true, ""
}

func findMachODyldInfoCommand(file *macho.File) (machoDyldInfoCommand, bool, string) {
	if file == nil || file.ByteOrder == nil {
		return machoDyldInfoCommand{}, false, ""
	}
	var result machoDyldInfoCommand
	found := false
	for _, load := range file.Loads {
		raw := load.Raw()
		if len(raw) < 4 {
			continue
		}
		command := file.ByteOrder.Uint32(raw[0:4])
		if command != lcDyldInfo && command != lcDyldInfoOnly {
			continue
		}
		if found {
			return machoDyldInfoCommand{}, true, "multiple LC_DYLD_INFO binding commands are ambiguous"
		}
		if len(raw) < 48 {
			return machoDyldInfoCommand{}, true, "LC_DYLD_INFO command is truncated"
		}
		result = machoDyldInfoCommand{
			bindOff: file.ByteOrder.Uint32(raw[16:20]), bindSize: file.ByteOrder.Uint32(raw[20:24]),
			lazyBindOff: file.ByteOrder.Uint32(raw[32:36]), lazyBindSize: file.ByteOrder.Uint32(raw[36:40]),
		}
		found = true
	}
	return result, found, ""
}

func loadedMachOSegments(file *macho.File) []*macho.Segment {
	if file == nil {
		return nil
	}
	segments := make([]*macho.Segment, 0, len(file.Loads))
	for _, load := range file.Loads {
		if segment, ok := load.(*macho.Segment); ok {
			segments = append(segments, segment)
		}
	}
	return segments
}

func parseMachODyldBindStream(file *macho.File, stream []byte, streamFileOffset int, segments []*macho.Segment, streamName string, lazy bool, recordLimit int) (map[uint64]machoDyldBinding, string) {
	out := map[uint64]machoDyldBinding{}
	if file == nil || file.Magic != macho.Magic64 || recordLimit < 0 {
		return out, "LC_DYLD_INFO pointer bindings require a 64-bit Mach-O and a non-negative record budget"
	}
	type bindState struct {
		segment      int
		offset       uint64
		typ          uint8
		symbol       string
		symbolOffset int
		addend       uint64
	}
	state := bindState{segment: -1, typ: dyldBindTypePointer}
	processed := 0
	reset := func() { state = bindState{segment: -1, typ: dyldBindTypePointer} }
	for cursor := 0; cursor < len(stream); {
		opcodeOffset := cursor
		bytecode := stream[cursor]
		cursor++
		opcode, immediate := bytecode&0xf0, bytecode&0x0f
		bind := func() string {
			if processed >= recordLimit {
				return fmt.Sprintf("LC_DYLD_INFO binding record limit %d reached", recordLimit)
			}
			processed++
			if state.typ != dyldBindTypePointer || state.symbol == "" || state.segment < 0 || state.segment >= len(segments) {
				return "LC_DYLD_INFO bind action lacks an exact pointer type, symbol, or segment"
			}
			segment := segments[state.segment]
			if state.offset&7 != 0 || state.offset > segment.Memsz || 8 > segment.Memsz-state.offset || segment.Addr > ^uint64(0)-state.offset {
				return "LC_DYLD_INFO pointer binding is unaligned or outside its segment"
			}
			slot := segment.Addr + state.offset
			if state.addend != 0 {
				return "LC_DYLD_INFO nonzero binding addend does not identify an exact imported symbol"
			}
			binding := machoDyldBinding{Name: state.symbol, SlotVA: slot, SymbolOffset: state.symbolOffset, StreamOffset: streamFileOffset + opcodeOffset, Stream: streamName}
			if existing, exists := out[slot]; exists && existing.Name != binding.Name {
				delete(out, slot)
				return "LC_DYLD_INFO assigns conflicting symbols to one pointer slot"
			}
			out[slot] = binding
			return ""
		}
		advance := func(amount uint64) {
			// dyld binding bytecode performs pointer-width unsigned arithmetic.
			// Linkers use a 64-bit ULEB encoding of a negative delta when moving
			// between nearby pointer sections, so modular addition is intentional;
			// every eventual bind location is still range/alignment checked.
			state.offset += amount
		}
		switch opcode {
		case 0x00: // DONE
			if lazy {
				reset()
				continue
			}
			return out, ""
		case 0x10, 0x30, 0x50: // ordinal immediate, special ordinal, type
			if opcode == 0x50 {
				state.typ = immediate
			}
		case 0x20, 0x60: // ordinal ULEB or addend SLEB
			value, next, ok := readMachOBindLEB(stream, cursor, opcode == 0x60)
			if !ok {
				return out, "LC_DYLD_INFO contains a malformed or overflowing LEB128 operand"
			}
			cursor = next
			if opcode == 0x60 {
				state.addend = value
			}
		case 0x40: // symbol trailing flags immediate
			start := cursor
			limit := min(len(stream), start+maxMachODyldBindSymbolNameLen+1)
			for cursor < limit && stream[cursor] != 0 {
				cursor++
			}
			if cursor == start || cursor >= limit || stream[cursor] != 0 {
				return out, "LC_DYLD_INFO contains an empty, unterminated, or overlong symbol"
			}
			state.symbol = string(stream[start:cursor])
			state.symbolOffset = streamFileOffset + start
			if !validMachOChainedImportName(state.symbol) {
				return out, "LC_DYLD_INFO contains an invalid symbol name"
			}
			cursor++
		case 0x70: // segment and offset ULEB
			value, next, ok := readMachOBindLEB(stream, cursor, false)
			if !ok || int(immediate) >= len(segments) {
				return out, "LC_DYLD_INFO contains an invalid segment or segment offset"
			}
			state.segment, state.offset, cursor = int(immediate), value, next
		case 0x80: // add address ULEB
			value, next, ok := readMachOBindLEB(stream, cursor, false)
			if !ok {
				return out, "LC_DYLD_INFO address addition is malformed"
			}
			advance(value)
			cursor = next
		case 0x90: // do bind
			if detail := bind(); detail != "" {
				return out, detail
			}
			advance(8)
		case 0xa0: // do bind, add ULEB
			value, next, ok := readMachOBindLEB(stream, cursor, false)
			if !ok {
				return out, "LC_DYLD_INFO bind address operand is malformed"
			}
			if detail := bind(); detail != "" {
				return out, detail
			}
			advance(8 + value)
			cursor = next
		case 0xb0: // do bind, add immediate scaled
			if detail := bind(); detail != "" {
				return out, detail
			}
			advance(uint64(immediate+1) * 8)
		case 0xc0: // do bind ULEB times, skipping ULEB
			count, next, ok := readMachOBindLEB(stream, cursor, false)
			if !ok {
				return out, "LC_DYLD_INFO bind repetition count is malformed"
			}
			skip, after, ok := readMachOBindLEB(stream, next, false)
			if !ok || count > uint64(recordLimit-processed) {
				return out, fmt.Sprintf("LC_DYLD_INFO binding record limit %d reached", recordLimit)
			}
			cursor = after
			for index := uint64(0); index < count; index++ {
				if detail := bind(); detail != "" {
					return out, detail
				}
				advance(8 + skip)
			}
		default:
			return out, fmt.Sprintf("LC_DYLD_INFO %s stream uses unsupported opcode 0x%02x", streamName, opcode)
		}
	}
	return out, ""
}

func readMachOBindLEB(data []byte, offset int, signed bool) (uint64, int, bool) {
	var value uint64
	var shift uint
	for index := 0; index < 10 && offset+index < len(data); index++ {
		current := data[offset+index]
		payload := uint64(current & 0x7f)
		if shift >= 64 || payload<<shift>>shift != payload {
			return 0, offset, false
		}
		value |= payload << shift
		shift += 7
		if current&0x80 == 0 {
			if signed && shift < 64 && current&0x40 != 0 {
				value |= ^uint64(0) << shift
			}
			return value, offset + index + 1, true
		}
	}
	return 0, offset, false
}
