package extract

import (
	"bytes"
	"debug/macho"
	"sort"

	"golang.org/x/arch/x86/x86asm"
)

const (
	maxMachOLinearWrites       = 64
	machoSGReadOnlyAfterFixups = 0x10
)

type machoMemoryRange struct{ start, end uint64 }

type machoImportSlots struct {
	bySymbol   map[string][]uint64
	incomplete bool
	oversized  bool
}

func newMachOImportSlots(pointers map[uint64]string, truncated bool) machoImportSlots {
	index := machoImportSlots{bySymbol: map[string][]uint64{}, incomplete: truncated, oversized: len(pointers) > maxMachOStubRecords}
	if index.oversized {
		return index
	}
	for address, symbol := range pointers {
		index.bySymbol[symbol] = append(index.bySymbol[symbol], address)
	}
	for _, addresses := range index.bySymbol {
		sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })
	}
	return index
}

func (slots machoImportSlots) retained(lookup *machoCallLookup, index *machoSectionIndex, symbol string) bool {
	if symbol == "" {
		return true
	}
	if !machoImportBindingBudgetRetained(lookup, index) {
		return false
	}
	if len(index.memory.writes) == 0 {
		return true
	}
	if slots.oversized {
		addPartialCoverageOnce(lookup.graph, lookup.content.NodeID, "macho-import-binding/"+lookup.arch, "import identity omitted because pointer-slot metadata exceeded its bounded record limit")
		return false
	}
	if slots.incomplete {
		addPartialCoverageOnce(lookup.graph, lookup.content.NodeID, "macho-import-binding-limits/"+lookup.arch, "partial pointer-slot metadata limits write correlation; retained static import identities do not establish runtime dispatch")
	}
	// Search retained same-symbol slots for each bounded write. A partial
	// binding stream is not itself a contradiction, and no exact stub-to-slot
	// relationship is inferred when several slots name the same import.
	addresses := slots.bySymbol[symbol]
	for _, write := range index.memory.writes {
		first := uint64(0)
		if write.start >= 7 {
			first = write.start - 7
		}
		position := sort.Search(len(addresses), func(i int) bool { return addresses[i] >= first })
		if position < len(addresses) && addresses[position] < write.end {
			addPartialCoverageOnce(lookup.graph, lookup.content.NodeID, "macho-import-binding/"+lookup.arch, "imported stub identity omitted after an exact overlapping same-symbol pointer-slot write")
			return false
		}
	}
	return true
}

// machoLinearMemory never reconstructs mutable memory. It only prevents a
// later call from reusing initial image bytes after a possibly aliasing store
// in the same recovered function. Invalidation survives register resets and
// branches; no path-sensitive execution or heap state is inferred.
type machoLinearMemory struct {
	writes       []machoMemoryRange
	unknownWrite bool
	callBoundary bool
	readOnly     map[*macho.Section]bool
	segments     []*macho.Segment
	truncated    bool
	lostWrites   bool
	dyldReadOnly bool
}

func (index *machoSectionIndex) withLinearMemory(file *macho.File) *machoSectionIndex {
	copy := *index
	copy.memory = &machoLinearMemory{readOnly: map[*macho.Section]bool{}}
	// Protection is established by segment mappings, never a section name.
	// Bound this optional exemption; unusually large load tables simply lose
	// the exemption after an unresolved store.
	if len(file.Loads) <= 256 {
		copy.memory.dyldReadOnly = machoDyldReadOnlyProfile(file)
		for _, load := range file.Loads {
			if segment, ok := load.(*macho.Segment); ok {
				copy.memory.segments = append(copy.memory.segments, segment)
			}
		}
	}
	return &copy
}

func (memory *machoLinearMemory) reset() {
	memory.writes = memory.writes[:0]
	memory.unknownWrite = false
	memory.callBoundary = false
	memory.lostWrites = false
}

func (memory *machoLinearMemory) store(address, size uint64, known bool) {
	if !known || size == 0 || size > ^uint64(0)-address {
		memory.unknownWrite = true
		return
	}
	write := machoMemoryRange{address, address + size}
	first := sort.Search(len(memory.writes), func(i int) bool { return memory.writes[i].end >= write.start })
	last := first
	// Only overlap or adjacency can join intervals. A gap is included only
	// when this new store itself writes every byte of that gap.
	for last < len(memory.writes) && memory.writes[last].start <= write.end {
		write.start = min(write.start, memory.writes[last].start)
		write.end = max(write.end, memory.writes[last].end)
		last++
	}
	if last > first {
		memory.writes[first] = write
		copy(memory.writes[first+1:], memory.writes[last:])
		memory.writes = memory.writes[:len(memory.writes)-(last-first)+1]
		return
	}
	if len(memory.writes) >= maxMachOLinearWrites {
		memory.truncated, memory.lostWrites, memory.unknownWrite = true, true, true
		return
	}
	memory.writes = append(memory.writes, machoMemoryRange{})
	copy(memory.writes[first+1:], memory.writes[first:])
	memory.writes[first] = write
}

func (memory *machoLinearMemory) allows(section *macho.Section, address, size uint64) bool {
	if memory == nil {
		return true
	}
	if memory.lostWrites || size > ^uint64(0)-address || (memory.unknownWrite || memory.callBoundary) && !memory.sectionReadOnly(section) {
		return false
	}
	return !memory.overwrites(address, size)
}

func (memory *machoLinearMemory) overwrites(address, size uint64) bool {
	if memory == nil || len(memory.writes) == 0 {
		return false
	}
	if size > ^uint64(0)-address {
		return true
	}
	for _, write := range memory.writes {
		if address < write.end && write.start < address+size {
			return true
		}
	}
	return false
}

func machoImportBindingRetained(lookup *machoCallLookup, index *machoSectionIndex, address uint64) bool {
	// Import identity follows the documented loader contract, not the initial
	// pointer bytes. Only an exact overlapping write contradicts that binding;
	// unresolved writes remain a runtime-dispatch limitation.
	if !machoImportBindingBudgetRetained(lookup, index) {
		return false
	}
	if !index.memory.overwrites(address, 8) {
		return true
	}
	addPartialCoverageOnce(lookup.graph, lookup.content.NodeID, "macho-import-binding/"+lookup.arch, "imported call or class identity omitted after an exact overlapping pointer-slot write")
	return false
}

func machoImportBindingBudgetRetained(lookup *machoCallLookup, index *machoSectionIndex) bool {
	if index.memory.lostWrites {
		addPartialCoverageOnce(lookup.graph, lookup.content.NodeID, "macho-import-binding/"+lookup.arch, "import identity omitted after the per-function write-range budget was exhausted")
		return false
	}
	if index.memory.unknownWrite {
		addPartialCoverageOnce(lookup.graph, lookup.content.NodeID, "macho-import-binding-limits/"+lookup.arch, "import identities follow retained loader metadata; effects of unresolved writes and dynamic interposition on runtime dispatch are not resolved")
	}
	return true
}

func machoImportStubOverwritten(memory *machoLinearMemory, sections []stubSection, address uint64) bool {
	if memory == nil || len(memory.writes) == 0 {
		return false
	}
	for _, section := range sections {
		if address >= section.addr && address-section.addr < section.size && section.stubSize != 0 {
			return memory.overwrites(address, uint64(section.stubSize))
		}
	}
	return memory.overwrites(address, 1)
}

func (memory *machoLinearMemory) sectionReadOnly(section *macho.Section) bool {
	if readOnly, checked := memory.readOnly[section]; checked {
		return readOnly
	}
	if section == nil || section.Size > ^uint64(0)-section.Addr {
		return false
	}
	covered, writable := false, false
	for _, segment := range memory.segments {
		if segment.Memsz > ^uint64(0)-segment.Addr {
			continue
		}
		end := segment.Addr + segment.Memsz
		readOnly := segment.Prot&1 != 0 && segment.Prot&2 == 0
		if memory.dyldReadOnly && segment.Flag&machoSGReadOnlyAfterFixups != 0 && segment.Prot == 3 && segment.Maxprot&3 == 3 {
			// SG_READ_ONLY: dyld removes write permission after fixups.
			readOnly = true
		}
		if section.Addr < end && segment.Addr < section.Addr+section.Size {
			writable = writable || segment.Prot&2 != 0 && !readOnly
		}
		if readOnly && segment.Addr <= section.Addr && section.Addr+section.Size <= end && uint64(section.Offset) >= segment.Offset && segment.Filesz <= segment.Memsz && segment.Filesz <= ^uint64(0)-segment.Offset {
			fileDelta := uint64(section.Offset) - segment.Offset
			covered = covered || fileDelta == section.Addr-segment.Addr && fileDelta <= segment.Filesz && section.Size <= segment.Filesz-fileDelta
		}
	}
	memory.readOnly[section] = covered && !writable
	return covered && !writable
}

func machoDyldReadOnlyProfile(file *macho.File) bool {
	if file.Magic != macho.Magic64 || file.Flags&macho.FlagDyldLink == 0 {
		return false
	}
	switch file.Type {
	case macho.TypeDylib, macho.TypeBundle:
		return true
	case macho.TypeExec:
		if file.ByteOrder == nil {
			return false
		}
	default:
		return false
	}
	// Static executables have no dyld load command and do not acquire dyld's
	// post-fixup protection. A custom or ambiguous loader is unsupported.
	found := false
	for _, load := range file.Loads {
		if load == nil {
			continue
		}
		raw := load.Raw()
		if len(raw) < 8 || file.ByteOrder.Uint32(raw[:4]) != 0xe {
			continue
		} // LC_LOAD_DYLINKER
		if found || len(raw) < 12 || uint64(file.ByteOrder.Uint32(raw[4:8])) != uint64(len(raw)) {
			return false
		}
		offset := uint64(file.ByteOrder.Uint32(raw[8:12]))
		name := []byte("/usr/lib/dyld\x00")
		if offset < 12 || offset > uint64(len(raw)) || uint64(len(name)) > uint64(len(raw))-offset || !bytes.Equal(raw[offset:offset+uint64(len(name))], name) {
			return false
		}
		found = true
	}
	return found
}

func addMachOMemoryOffset(base uint64, offset int64) (uint64, bool) {
	if offset < 0 {
		distance := uint64(-(offset + 1)) + 1
		if distance > base {
			return 0, false
		}
		return base - distance, true
	}
	if uint64(offset) > ^uint64(0)-base {
		return 0, false
	}
	return base + uint64(offset), true
}

func arm64ImmediateStackMemory(insn uint32) bool {
	if (insn>>5)&31 != 31 {
		return false
	}
	// Closed SP-relative immediate scalar/vector and pair addressing classes.
	// Register-offset SP accesses are excluded: their index may alias the image.
	return insn&0x3b200000 == 0x38000000 || insn&0x3b000000 == 0x39000000 || insn&0x3a000000 == 0x28000000
}

func (memory *machoLinearMemory) arm64Store(insn uint32, instruction int, registers map[uint32]arm64RegisterValue, stack map[uint32]machoStackAddressValue) {
	_, base, load, ok := arm64KnownMemoryAccess(insn)
	if !ok || load || base == 31 {
		return
	}
	value, known := registers[base]
	if address, local := stack[base]; local && instruction-address.Instruction <= x86AddressStateWindow {
		return
	}
	size := uint64(1) << (insn >> 30)
	offset := int64((insn>>10)&0xfff) * int64(size)
	if insn&0x01000000 == 0 { // unscaled signed immediate
		offset = int64(int32(insn<<11) >> 23)
	}
	address, valid := addMachOMemoryOffset(value.value, offset)
	memory.store(address, size, known && !value.loadsMemory && instruction-value.instruction <= x86AddressStateWindow && valid)
}

func (memory *machoLinearMemory) x86Store(inst x86asm.Inst, va uint64, instruction int, addresses map[uint8]x86AddressValue) {
	// Intel syntax places the memory destination first. Conservatively treat
	// other explicit first-memory operands as writes except closed read-only
	// forms. XCHG and string stores also write a non-first/implicit operand.
	argument := inst.Args[0]
	switch inst.Op {
	case x86asm.CMP, x86asm.TEST, x86asm.LEA, x86asm.CALL, x86asm.JMP, x86asm.BT, x86asm.PREFETCHNTA, x86asm.PREFETCHT0, x86asm.PREFETCHT1, x86asm.PREFETCHT2, x86asm.NOP:
		return
	case x86asm.XCHG:
		if _, ok := argument.(x86asm.Mem); !ok {
			argument = inst.Args[1]
		}
	case x86asm.BTS, x86asm.BTR, x86asm.BTC:
		if _, memoryDestination := argument.(x86asm.Mem); memoryDestination {
			// A register bit offset may address another memory word entirely.
			memory.store(0, 0, false)
		}
		return
	case x86asm.MOVSB, x86asm.MOVSW, x86asm.MOVSD, x86asm.MOVSQ, x86asm.STOSB, x86asm.STOSW, x86asm.STOSD, x86asm.STOSQ, x86asm.MASKMOVQ, x86asm.MASKMOVDQU:
		memory.store(0, 0, false)
		return
	}
	operand, ok := argument.(x86asm.Mem)
	if !ok {
		return
	}
	if operand.Index != 0 || operand.Segment != 0 {
		memory.store(0, 0, false)
		return
	}
	if operand.Base == x86asm.RSP {
		return
	}
	base, known := uint64(0), false
	if operand.Base == x86asm.RIP {
		base, known = va+uint64(inst.Len), va <= ^uint64(0)-uint64(inst.Len)
	} else if operand.Base >= x86asm.RAX && operand.Base <= x86asm.R15 {
		value, present := addresses[uint8(operand.Base-x86asm.RAX)]
		base, known = value.value, present && instruction-value.instruction <= x86AddressStateWindow
	}
	address, valid := addMachOMemoryOffset(base, operand.Disp)
	memory.store(address, uint64(inst.MemBytes), known && valid)
}

func machoImageStringRetained(index *machoSectionIndex, argument machoCallStringArgument) bool {
	if argument.Value == "" {
		return false
	}
	if argument.BackingVA != 0 {
		return index.containing(argument.LiteralVA, machOCFString64RecordSize) != nil && index.containing(argument.BackingVA, uint64(len(argument.Value))) != nil
	}
	return index.containing(argument.LiteralVA, uint64(len(argument.Value))+1) != nil
}

func machoImageArrayRetained(index *machoSectionIndex, array machoObjCStringArray) bool {
	if len(array.Elements) == 0 || array.ObjectVA != 0 && index.containing(array.ObjectVA, machOObjCArray64RecordSize) == nil || array.DataVA != 0 && index.containing(array.DataVA, uint64(len(array.Elements))*8) == nil {
		return false
	}
	for _, element := range array.Elements {
		if !machoImageStringRetained(index, element.String) {
			return false
		}
	}
	return true
}

// Previously constructed receiver and stack contexts may retain image-backed
// strings across calls. Recheck their original byte ranges before using them
// in a later conclusion; this does not infer the contents of mutable objects.
func invalidateMachOCachedImageArguments[Register machoRegisterIndex](lookup *machoCallLookup, index *machoSectionIndex, receivers map[Register]machoObjCReceiverValue, slots map[int64]machoObjCStackSlot) {
	for register, receiver := range receivers {
		if len(receiver.StringArray.Elements) != 0 && !machoImageArrayRetained(index, receiver.StringArray) {
			receiver.StringArray = machoObjCStringArray{}
			receivers[register] = receiver
		}
		if state := lookup.nstaskReceivers[receiver.Identity]; state != nil {
			if state.Path.Value != "" && !machoImageStringRetained(index, state.Path) {
				state.Path = machoCallStringArgument{}
			}
			if len(state.Arguments.Elements) != 0 && !machoImageArrayRetained(index, state.Arguments) {
				state.Arguments = machoObjCStringArray{}
			}
		}
	}
	for offset, slot := range slots {
		if !machoImageStringRetained(index, slot.String) {
			delete(slots, offset)
		}
	}
}
