package extract

import (
	"debug/macho"
	"encoding/binary"
	"strings"
	"testing"
)

func TestMachOChainedPointerBindingsRecoverExactUserlandBindSlots(t *testing.T) {
	rebaseWithNext := uint64(1) << 51
	bind := uint64(1)<<62 | uint64(1) // ordinal 1
	file, image, slotVA := chainedBindingFixture(t, dyldChainedPtrArm64EUserland, []string{"_open", "_OBJC_CLASS_$_NSTask"}, []uint64{rebaseWithNext, bind})

	bindings, present, detail := machoChainedPointerBindings(file, image)
	if !present || detail != "" || len(bindings) != 1 {
		t.Fatalf("chained bindings = %#v present=%v detail=%q", bindings, present, detail)
	}
	got, ok := bindings[slotVA+8]
	if !ok || got.Name != "_OBJC_CLASS_$_NSTask" || got.Stream != "chained-fixups" || got.SlotVA != slotVA+8 {
		t.Fatalf("exact chained slot = %#v", got)
	}
}

func TestMachOChainedPointerBindingsKeepRebasesNonSemantic(t *testing.T) {
	file, image, _ := chainedBindingFixture(t, dyldChainedPtr64Offset, []string{"_open"}, []uint64{0})
	bindings, present, detail := machoChainedPointerBindings(file, image)
	if !present || detail != "" || len(bindings) != 0 {
		t.Fatalf("rebase became an import binding: %#v present=%v detail=%q", bindings, present, detail)
	}
}

func TestMachOChainedFixupsRejectDuplicateCommands(t *testing.T) {
	file, image, _ := chainedBindingFixture(t, dyldChainedPtr64, []string{"_open"}, []uint64{uint64(1) << 63})
	file.Loads = append(file.Loads, file.Loads[len(file.Loads)-1])
	imports, present, detail := machoChainedImports(file, image, 0)
	if !present || !strings.Contains(detail, "multiple") || len(imports) != 0 {
		t.Fatalf("duplicate commands retained imports: %#v present=%v detail=%q", imports, present, detail)
	}
	bindings, present, detail := machoChainedPointerBindings(file, image)
	if !present || !strings.Contains(detail, "multiple") || len(bindings) != 0 {
		t.Fatalf("duplicate commands retained exact bindings: %#v present=%v detail=%q", bindings, present, detail)
	}
}

func TestMachOChainedPointerBindingsFailClosed(t *testing.T) {
	tests := []struct {
		name          string
		format        uint16
		raw           uint64
		limit         int
		mutate        func([]byte)
		wantSubstring string
	}{
		{name: "ordinal", format: dyldChainedPtrArm64EUserland, raw: uint64(1)<<62 | 7, limit: maxMachOChainedBindFixups, wantSubstring: "ordinal"},
		{name: "reserved bits", format: dyldChainedPtrArm64EUserland, raw: uint64(1)<<62 | uint64(1)<<16, limit: maxMachOChainedBindFixups, wantSubstring: "malformed"},
		{name: "64 bit addend", format: dyldChainedPtr64, raw: uint64(1)<<63 | uint64(1)<<24, limit: maxMachOChainedBindFixups, wantSubstring: "nonzero binding addend"},
		{name: "arm64e addend", format: dyldChainedPtrArm64EUserland, raw: uint64(1)<<62 | uint64(1)<<32, limit: maxMachOChainedBindFixups, wantSubstring: "nonzero binding addend"},
		{name: "arm64e24 negative addend", format: dyldChainedPtrArm64EUserland24, raw: uint64(1)<<62 | uint64(0x7ffff)<<32, limit: maxMachOChainedBindFixups, wantSubstring: "nonzero binding addend"},
		{name: "rebase reserved bits", format: dyldChainedPtr64Offset, raw: uint64(1) << 44, limit: maxMachOChainedBindFixups, wantSubstring: "malformed"},
		{name: "unsupported format", format: 7, raw: 0, limit: maxMachOChainedBindFixups, wantSubstring: "pointer format"},
		{name: "record budget", format: dyldChainedPtrArm64EUserland, raw: uint64(1) << 62, limit: 0, wantSubstring: "record limit"},
		{name: "multiple starts", format: dyldChainedPtrArm64EUserland, raw: uint64(1) << 62, limit: maxMachOChainedBindFixups, mutate: func(payload []byte) {
			binary.LittleEndian.PutUint16(payload[28+8+22:28+8+24], dyldChainedPtrStartMulti)
		}, wantSubstring: "multiple chain starts"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, image, _ := chainedBindingFixture(t, test.format, []string{"_open"}, []uint64{test.raw})
			if test.mutate != nil {
				command, _ := findLinkeditDataCommand(file, lcDyldChainedFixups)
				test.mutate(image[command.dataOff : command.dataOff+command.dataSize])
			}
			bindings, present, detail := machoChainedPointerBindingsWithLimit(file, image, test.limit)
			if !present || !strings.Contains(detail, test.wantSubstring) || len(bindings) != 0 {
				t.Fatalf("bindings = %#v present=%v detail=%q, want %q", bindings, present, detail, test.wantSubstring)
			}
		})
	}
}

func TestMachOChainedInitialPointerCannotCrossPageBoundary(t *testing.T) {
	for _, offset := range []uint16{0xff8, 0xffc} {
		file, image, _ := chainedBindingFixture(t, dyldChainedPtr64, []string{"_open"}, []uint64{uint64(1) << 63})
		// Retain the next page so a cross-page read cannot fail merely because
		// it runs out of image or segment bytes.
		image = append(image, make([]byte, 0x2000-len(image))...)
		segment := file.Loads[0].(*macho.Segment)
		segment.Memsz, segment.Filesz = uint64(len(image)), uint64(len(image))
		binary.LittleEndian.PutUint64(image[int(offset):int(offset)+8], uint64(1)<<63)
		command, _ := findLinkeditDataCommand(file, lcDyldChainedFixups)
		payload := image[command.dataOff : command.dataOff+command.dataSize]
		binary.LittleEndian.PutUint16(payload[28+8+22:28+8+24], offset)
		bindings, _, detail := machoChainedPointerBindings(file, image)
		if offset == 0xff8 {
			if detail != "" || bindings[segment.Addr+uint64(offset)].Name != "_open" {
				t.Fatalf("last in-page slot rejected: bindings=%#v detail=%q", bindings, detail)
			}
		} else if !strings.Contains(detail, "outside the page") || len(bindings) != 0 {
			t.Fatalf("cross-page first slot accepted: bindings=%#v detail=%q", bindings, detail)
		}
	}
}

func TestMachOChainedPointerBindingsRejectImportAddends(t *testing.T) {
	for _, format := range []uint32{2, 3} {
		file, image, slot := chainedBindingFixture(t, dyldChainedPtr64, []string{"_open"}, []uint64{uint64(1) << 63}, format)
		bindings, _, detail := machoChainedPointerBindings(file, image)
		if detail != "" || bindings[slot].Name != "_open" {
			t.Fatalf("format %d zero addend: bindings=%#v detail=%q", format, bindings, detail)
		}
		command, _ := findLinkeditDataCommand(file, lcDyldChainedFixups)
		payload := image[command.dataOff : command.dataOff+command.dataSize]
		offset := binary.LittleEndian.Uint32(payload[8:12])
		if format == 2 {
			binary.LittleEndian.PutUint32(payload[offset+4:offset+8], 1)
		} else {
			binary.LittleEndian.PutUint64(payload[offset+8:offset+16], ^uint64(0))
		}
		imports, _, importDetail := machoChainedImports(file, image, 0)
		if importDetail != "" || len(imports) != 1 || imports[0].name != "_open" {
			t.Fatalf("format %d lost import observation: imports=%#v detail=%q", format, imports, importDetail)
		}
		bindings, _, detail = machoChainedPointerBindings(file, image)
		if !strings.Contains(detail, "nonzero binding addend") || len(bindings) != 0 {
			t.Fatalf("format %d nonzero addend: bindings=%#v detail=%q", format, bindings, detail)
		}
	}
}

func TestMachOChainedAuthenticatedBindingDiversityIsNotAnAddend(t *testing.T) {
	for _, format := range []uint16{dyldChainedPtrArm64E, dyldChainedPtrArm64EUserland, dyldChainedPtrArm64EUserland24} {
		raw := uint64(1)<<63 | uint64(1)<<62 | uint64(0x7ffff)<<32
		file, image, slot := chainedBindingFixture(t, format, []string{"_open"}, []uint64{raw})
		bindings, _, detail := machoChainedPointerBindings(file, image)
		if detail != "" || bindings[slot].Name != "_open" {
			t.Fatalf("format %d authentication data rejected: bindings=%#v detail=%q", format, bindings, detail)
		}
	}
}

func TestDecodeChainedBindPointerSupportsClosedFormats(t *testing.T) {
	for _, test := range []struct {
		format      uint16
		ordinalBits uint64
		raw         uint64
		ordinal     uint64
		next        uint64
	}{
		{dyldChainedPtr64, 24, uint64(1)<<63 | uint64(3)<<51 | 0x123456, 0x123456, 3},
		{dyldChainedPtrArm64E, 16, uint64(1)<<62 | uint64(4)<<51 | 0x1234, 0x1234, 4},
		{dyldChainedPtrArm64EUserland24, 24, uint64(1)<<63 | uint64(1)<<62 | uint64(5)<<51 | 0x123456, 0x123456, 5},
	} {
		ordinal, next, bind, valid := decodeChainedBindPointer(test.raw, test.format, test.ordinalBits)
		if !valid || !bind || ordinal != test.ordinal || next != test.next {
			t.Fatalf("format %d decoded ordinal=%x next=%d bind=%v valid=%v", test.format, ordinal, next, bind, valid)
		}
	}
}

func TestImportedPointerMapDiscardsAmbiguousDyldSlot(t *testing.T) {
	const slot = 0x1000
	lookup := &machoCallLookup{
		dyldBindings:  map[uint64]machoDyldBinding{slot: {Name: "_OBJC_CLASS_$_NSTask", SlotVA: slot}},
		dyldAmbiguous: map[uint64]bool{slot: true},
	}
	got, _ := importedPointerMapForLookup(&macho.File{}, lookup, 8)
	if value := got[slot]; value != "" {
		t.Fatalf("ambiguous dyld slot remained resolved as %q", value)
	}
}

func chainedBindingFixture(t *testing.T, pointerFormat uint16, names []string, chain []uint64, importFormats ...uint32) (*macho.File, []byte, uint64) {
	t.Helper()
	if len(chain) == 0 {
		t.Fatal("fixture requires a chain")
	}
	const (
		dataOffset  = 0x500
		chainOffset = 0x200
		segmentAddr = 0x100000000
	)
	startsOffset := 28
	startsSize := 8 + 24
	importsOffset := startsOffset + startsSize
	importFormat, entrySize := uint32(1), 4
	if len(importFormats) > 0 {
		importFormat = importFormats[0]
		switch importFormat {
		case 2:
			entrySize = 8
		case 3:
			entrySize = 16
		default:
			t.Fatal("unsupported fixture import format")
		}
	}
	symbolsOffset := importsOffset + entrySize*len(names)
	payload := make([]byte, symbolsOffset)
	binary.LittleEndian.PutUint32(payload[4:8], uint32(startsOffset))
	binary.LittleEndian.PutUint32(payload[8:12], uint32(importsOffset))
	binary.LittleEndian.PutUint32(payload[12:16], uint32(symbolsOffset))
	binary.LittleEndian.PutUint32(payload[16:20], uint32(len(names)))
	binary.LittleEndian.PutUint32(payload[20:24], importFormat)
	binary.LittleEndian.PutUint32(payload[startsOffset:startsOffset+4], 1)
	binary.LittleEndian.PutUint32(payload[startsOffset+4:startsOffset+8], 8)
	segmentInfo := payload[startsOffset+8 : startsOffset+startsSize]
	binary.LittleEndian.PutUint32(segmentInfo[0:4], uint32(len(segmentInfo)))
	binary.LittleEndian.PutUint16(segmentInfo[4:6], 0x1000)
	binary.LittleEndian.PutUint16(segmentInfo[6:8], pointerFormat)
	binary.LittleEndian.PutUint64(segmentInfo[8:16], 0)
	binary.LittleEndian.PutUint16(segmentInfo[20:22], 1)
	binary.LittleEndian.PutUint16(segmentInfo[22:24], chainOffset)
	nameOffset := 0
	for index, name := range names {
		entry := payload[importsOffset+index*entrySize : importsOffset+(index+1)*entrySize]
		if importFormat == 3 {
			binary.LittleEndian.PutUint64(entry[:8], uint64(nameOffset)<<32|1)
		} else {
			binary.LittleEndian.PutUint32(entry[:4], uint32(nameOffset)<<9|1)
		}
		payload = append(payload, name...)
		payload = append(payload, 0)
		nameOffset += len(name) + 1
	}
	image := make([]byte, dataOffset+len(payload))
	copy(image[dataOffset:], payload)
	for index, raw := range chain {
		binary.LittleEndian.PutUint64(image[chainOffset+index*8:chainOffset+(index+1)*8], raw)
	}
	command := make([]byte, 16)
	binary.LittleEndian.PutUint32(command[0:4], lcDyldChainedFixups)
	binary.LittleEndian.PutUint32(command[4:8], 16)
	binary.LittleEndian.PutUint32(command[8:12], dataOffset)
	binary.LittleEndian.PutUint32(command[12:16], uint32(len(payload)))
	segment := &macho.Segment{SegmentHeader: macho.SegmentHeader{Name: "__TEXT", Addr: segmentAddr, Memsz: 0x1000, Offset: 0, Filesz: 0x400}}
	file := &macho.File{FileHeader: macho.FileHeader{Magic: macho.Magic64}, ByteOrder: binary.LittleEndian, Loads: []macho.Load{segment, macho.LoadBytes(command)}}
	return file, image, segmentAddr + chainOffset
}
