package extract

import (
	"debug/macho"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestClassicDyldBindingsRecoverExactPointerSlots(t *testing.T) {
	stream := []byte{0x11, 0x40}
	stream = append(stream, []byte("_OBJC_CLASS_$_NSTask")...)
	stream = append(stream, 0, 0x51, 0x71, 0x40, 0x90, 0x80)
	stream = append(stream, 0xd8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x90, 0x00)
	file, image := testClassicDyldBindFixture(stream, nil)

	bindings, present, detail := machoClassicDyldBindings(file, image)
	if !present || detail != "" || len(bindings) != 2 {
		t.Fatalf("classic bindings = %#v present %v detail %q", bindings, present, detail)
	}
	for _, slot := range []uint64{0x2040, 0x2020} {
		binding := bindings[slot]
		if binding.Name != "_OBJC_CLASS_$_NSTask" || binding.SlotVA != slot || binding.Stream != "bind" || binding.SymbolOffset <= 0 || binding.StreamOffset <= 0 {
			t.Fatalf("binding at %#x = %#v", slot, binding)
		}
	}
}

func TestClassicDyldLazyBindingResetsStateAtDone(t *testing.T) {
	lazy := append(testDyldLazyBindSequence("_first", 0x18), testDyldLazyBindSequence("_second", 0x28)...)
	file, image := testClassicDyldBindFixture(nil, lazy)
	bindings, present, detail := machoClassicDyldBindings(file, image)
	if !present || detail != "" || bindings[0x2018].Name != "_first" || bindings[0x2028].Name != "_second" {
		t.Fatalf("lazy bindings = %#v present %v detail %q", bindings, present, detail)
	}
}

func TestClassicDyldBindingsKeepCrossStreamConflictsUnresolved(t *testing.T) {
	bind := testDyldLazyBindSequence("_first", 0x18)
	lazy := testDyldLazyBindSequence("_second", 0x18)
	file, image := testClassicDyldBindFixture(bind, lazy)
	bindings, present, detail := machoClassicDyldBindings(file, image)
	if !present || !strings.Contains(detail, "conflicting") {
		t.Fatalf("conflicting streams present=%v detail=%q", present, detail)
	}
	if binding, exists := bindings[0x2018]; exists {
		t.Fatalf("conflicting pointer slot remained resolved as %#v", binding)
	}
}

func TestClassicDyldBindingsRejectAddendsAndIncompleteIdentity(t *testing.T) {
	for _, test := range []struct {
		name string
		bind []byte
		lazy []byte
		want string
	}{
		{name: "positive addend", bind: []byte{0x40, '_', 'x', 0, 0x71, 0x18, 0x60, 1, 0x90, 0}, want: "nonzero binding addend"},
		{name: "negative addend", bind: []byte{0x40, '_', 'x', 0, 0x71, 0x18, 0x60, 0x7f, 0x90, 0}, want: "nonzero binding addend"},
		{name: "same stream conflict", lazy: append(testDyldLazyBindSequence("_first", 0x18), testDyldLazyBindSequence("_second", 0x18)...), want: "conflicting"},
		{name: "unsupported suffix", bind: []byte{0x40, '_', 'x', 0, 0x71, 0x18, 0x90, 0xd0}, want: "unsupported opcode"},
		{name: "incomplete later stream", bind: testDyldLazyBindSequence("_first", 0x18), lazy: []byte{0xd0}, want: "unsupported opcode"},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, image := testClassicDyldBindFixture(test.bind, test.lazy)
			bindings, present, detail := machoClassicDyldBindings(file, image)
			if !present || !strings.Contains(detail, test.want) || len(bindings) != 0 {
				t.Fatalf("non-exact identity retained: bindings=%#v present=%v detail=%q", bindings, present, detail)
			}
		})
	}
	// A nonzero addend reset before the bind does not affect its identity.
	file, image := testClassicDyldBindFixture([]byte{0x40, '_', 'x', 0, 0x71, 0x18, 0x60, 1, 0x60, 0, 0x90, 0}, nil)
	bindings, present, detail := machoClassicDyldBindings(file, image)
	if !present || detail != "" || bindings[0x2018].Name != "_x" {
		t.Fatalf("zero addend rejected: bindings=%#v present=%v detail=%q", bindings, present, detail)
	}
}

func TestDyldAddendCannotRegainExactIdentityFromIndirectSymbols(t *testing.T) {
	for _, addend := range []byte{0, 1} {
		stream := []byte{0x40}
		stream = append(stream, "_system"...)
		stream = append(stream, 0, 0x71, 0x18, 0x60, addend, 0x90, 0)
		file, image := testClassicDyldBindFixture(stream, nil)
		file.Cpu, file.Type = macho.CpuAmd64, macho.TypeExec
		segment := file.Loads[0].(*macho.Segment)
		segment.Prot, segment.Filesz = 5, 0x100
		data := encodeTestX86IndirectCALL(0x1000, 0x2018)
		copy(image, data)
		text := testMachOSection("__text", 0x1000, data)
		text.Seg = "__TEXT"
		file.Sections = []*macho.Section{text}
		file.Loads = append(file.Loads, testMachOIndirectSectionLoad("__got", "__DATA", 0x2018, 8, 0x6, 0, 0))
		file.Symtab = &macho.Symtab{Syms: []macho.Symbol{{Name: "_system", Type: 0x01}}}
		file.Dysymtab = &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Iundefsym: 0, Nundefsym: 1}, IndirectSyms: []uint32{0}}
		var graph behavior.Graph
		extractMachOFile(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "inert-bind-control", Data: image}, file, "x86_64", image, artifact.Options{})
		if addend == 0 && len(graph.Operations) != 1 {
			t.Fatalf("exact zero-addend call was lost: %#v", graph.Operations)
		}
		if addend != 0 && len(graph.Operations) != 0 {
			t.Fatalf("indirect symbol restored non-exact call identity: %#v", graph.Operations)
		}
		foundImport := false
		for _, feature := range graph.Features {
			if feature.Key == "macho.import" && feature.Value == "_system" {
				foundImport = true
			}
		}
		if !foundImport {
			t.Fatal("binding uncertainty removed the structural import observation")
		}
	}
}

func TestClassicDyldBindingBudgetCountsActionsNotUniqueSlots(t *testing.T) {
	segments := []*macho.Segment{{SegmentHeader: macho.SegmentHeader{Name: "__DATA", Addr: 0x2000, Memsz: 0x100}}}
	stream := []byte{0x40, '_', 'x', 0, 0x70, 0x20, 0x90, 0x80, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x90}
	bindings, detail := parseMachODyldBindStream(&macho.File{FileHeader: macho.FileHeader{Magic: macho.Magic64}}, stream, 0, segments, "bind", false, 1)
	if !strings.Contains(detail, "record limit") || len(bindings) != 1 {
		t.Fatalf("repeated-slot budget produced %#v detail %q", bindings, detail)
	}
}

func TestClassicDyldBindingsFailClosedOnMalformedAndBudgetedStreams(t *testing.T) {
	segments := []*macho.Segment{
		{SegmentHeader: macho.SegmentHeader{Name: "__TEXT", Addr: 0x1000, Memsz: 0x100}},
		{SegmentHeader: macho.SegmentHeader{Name: "__DATA", Addr: 0x2000, Memsz: 0x100}},
	}
	for _, test := range []struct {
		name   string
		stream []byte
		limit  int
		want   string
	}{
		{name: "unterminated symbol", stream: append([]byte{0x40}, []byte("_symbol")...), limit: 8, want: "unterminated"},
		{name: "invalid segment", stream: []byte{0x40, '_', 'x', 0, 0x7f, 0, 0x90}, limit: 8, want: "invalid segment"},
		{name: "unaligned slot", stream: []byte{0x40, '_', 'x', 0, 0x71, 1, 0x90}, limit: 8, want: "unaligned"},
		{name: "unsupported threaded", stream: []byte{0xd0}, limit: 8, want: "unsupported opcode"},
		{name: "truncated leb", stream: []byte{0x71, 0x80}, limit: 8, want: "invalid segment"},
		{name: "record budget", stream: []byte{0x40, '_', 'x', 0, 0x71, 0x20, 0x90}, limit: 0, want: "record limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			bindings, detail := parseMachODyldBindStream(&macho.File{FileHeader: macho.FileHeader{Magic: macho.Magic64}}, test.stream, 0, segments, "bind", false, test.limit)
			if detail == "" || !strings.Contains(detail, test.want) || len(bindings) != 0 {
				t.Fatalf("malformed stream produced %#v detail %q", bindings, detail)
			}
		})
	}
}

func TestClassicDyldInfoCommandRejectsAmbiguousAndOutOfRangePayloads(t *testing.T) {
	command := testDyldInfoCommand(64, 8, 0, 0)
	file := &macho.File{FileHeader: macho.FileHeader{Magic: macho.Magic64}, ByteOrder: binary.LittleEndian, Loads: []macho.Load{macho.LoadBytes(command), macho.LoadBytes(command)}}
	if _, present, detail := machoClassicDyldBindings(file, make([]byte, 128)); !present || !strings.Contains(detail, "multiple") {
		t.Fatalf("duplicate command present=%v detail=%q", present, detail)
	}
	file.Loads = []macho.Load{
		&macho.Segment{SegmentHeader: macho.SegmentHeader{Name: "__DATA", Addr: 0x2000, Memsz: 0x100}},
		macho.LoadBytes(testDyldInfoCommand(120, 16, 0, 0)),
	}
	if _, present, detail := machoClassicDyldBindings(file, make([]byte, 128)); !present || !strings.Contains(detail, "exceeds") {
		t.Fatalf("out-of-range stream present=%v detail=%q", present, detail)
	}
}

func TestObjCClassImportAndArgumentInvalidationAreExact(t *testing.T) {
	if class, ok := objcClassNameFromImportedSymbol("_OBJC_CLASS_$_NSTask"); !ok || class != "NSTask" {
		t.Fatalf("exact class import = %q, %v", class, ok)
	}
	for _, symbol := range []string{"OBJC_CLASS_$_NSTask", "_OBJC_METACLASS_$_NSTask", "_OBJC_CLASS_$_", "_OBJC_CLASS_$_NS-Task"} {
		if class, ok := objcClassNameFromImportedSymbol(symbol); ok {
			t.Fatalf("invalid class import %q produced %q", symbol, class)
		}
	}
	lookup := newMachOCallLookup(&behavior.Graph{}, artifact.Content{NodeID: "node-1"}, "x86_64")
	lookup.nstaskReceivers["kept"] = &machoNSTaskReceiverState{}
	lookup.nstaskReceivers["passed"] = &machoNSTaskReceiverState{}
	receivers := map[uint8]machoObjCReceiverValue{3: {Identity: "kept"}, 7: {Identity: "passed"}}
	invalidateNSTaskReceiverArguments(lookup, receivers, uint8(7), uint8(6), uint8(2))
	if lookup.nstaskReceivers["kept"] == nil || lookup.nstaskReceivers["passed"] != nil {
		t.Fatalf("argument invalidation = %#v", lookup.nstaskReceivers)
	}
}

func testClassicDyldBindFixture(bind, lazy []byte) (*macho.File, []byte) {
	const bindOffset = 128
	lazyOffset := bindOffset + len(bind)
	image := make([]byte, lazyOffset+len(lazy))
	copy(image[bindOffset:], bind)
	copy(image[lazyOffset:], lazy)
	loads := []macho.Load{
		&macho.Segment{SegmentHeader: macho.SegmentHeader{Name: "__TEXT", Addr: 0x1000, Memsz: 0x100}},
		&macho.Segment{SegmentHeader: macho.SegmentHeader{Name: "__DATA", Addr: 0x2000, Memsz: 0x100}},
		macho.LoadBytes(testDyldInfoCommand(bindOffset, len(bind), lazyOffset, len(lazy))),
	}
	return &macho.File{FileHeader: macho.FileHeader{Magic: macho.Magic64}, ByteOrder: binary.LittleEndian, Loads: loads}, image
}

func testDyldInfoCommand(bindOffset, bindSize, lazyOffset, lazySize int) []byte {
	raw := make([]byte, 48)
	binary.LittleEndian.PutUint32(raw[0:4], lcDyldInfoOnly)
	binary.LittleEndian.PutUint32(raw[4:8], uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[16:20], uint32(bindOffset))
	binary.LittleEndian.PutUint32(raw[20:24], uint32(bindSize))
	binary.LittleEndian.PutUint32(raw[32:36], uint32(lazyOffset))
	binary.LittleEndian.PutUint32(raw[36:40], uint32(lazySize))
	return raw
}

func testDyldLazyBindSequence(symbol string, offset byte) []byte {
	stream := []byte{0x11, 0x40}
	stream = append(stream, symbol...)
	return append(stream, 0, 0x51, 0x71, offset, 0x90, 0x00)
}
