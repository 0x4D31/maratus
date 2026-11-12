package extract

import (
	"debug/macho"
	"encoding/binary"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"golang.org/x/arch/arm64/arm64asm"
)

func TestMachOLinearMemoryInvalidatesSharedReadersAndCachedStrings(t *testing.T) {
	file, original := staticArgvMachOFixture(t, true)
	index := original.withLinearMemory(file)
	reader := newMachOCFStringReader(index, 4096)
	if value, ok := readCStringAtVAIndexed(index, 0x3000, 4096); !ok || value != "/usr/bin/id" {
		t.Fatalf("initial C string = %q, %v", value, ok)
	}
	if value, _, _, ok := reader.read(0x3000, 11); !ok || value != "/usr/bin/id" {
		t.Fatalf("initial length-delimited string = %q, %v", value, ok)
	}
	remaining := reader.bytesRemaining
	if _, ok := readMachOStaticArgvIndexed(file, index, 0x2000); !ok {
		t.Fatal("initial vector was not retained")
	}
	// An interior byte, not only the starting pointer, invalidates C strings,
	// CFString/Go backing data, and any argv element using that backing data.
	index.memory.store(0x3003, 1, true)
	if value, ok := readCStringAtVAIndexed(index, 0x3000, 4096); ok {
		t.Fatalf("overwritten C string retained: %q", value)
	}
	if value, _, _, ok := reader.read(0x3000, 11); ok {
		t.Fatalf("cached backing data retained: %q", value)
	}
	if _, ok := readMachOStaticArgvIndexed(file, index, 0x2000); ok {
		t.Fatal("vector retained overwritten literal")
	}
	if _, ok := readCStringAtVAIndexed(index, 0x300c, 4096); !ok {
		t.Fatal("disjoint string was invalidated by exact store")
	}
	if _, ok := readCStringAtVAIndexed(original, 0x3000, 4096); !ok {
		t.Fatal("scoped mutation changed raw artifact observations")
	}
	index.memory.reset()
	if _, _, _, ok := reader.read(0x3000, 11); !ok {
		t.Fatal("previous function's invalid cache entry survived reset")
	}
	if reader.bytesRemaining != remaining {
		t.Fatal("cached backing bytes were recharged after invalidation/reset")
	}
	index.memory.store(0x300b, 1, true) // actual terminating NUL
	if _, ok := readCStringAtVAIndexed(index, 0x3000, 4096); ok {
		t.Fatal("overwritten terminator was retained")
	}
}

func TestMachOLinearMemoryInvalidatesCapturedObjCArguments(t *testing.T) {
	file, _ := testObjCStringArrayFixture(t, 4096)
	index := newMachOSectionIndex(file).withLinearMemory(file)
	reader := newMachOCFStringReader(index, 4096)
	argument, ok := objcCFStringAtTargetLocationIndexed(file, reader, 0x4000, false)
	if !ok {
		t.Fatal("initial CFString argument missing")
	}
	array, ok := objcCFStringArrayAtTargetLocationIndexed(file, reader, 0x2000, false)
	if !ok {
		t.Fatal("initial constant array missing")
	}
	var graph behavior.Graph
	lookup := newMachOCallLookup(&graph, artifact.Content{NodeID: "node"}, "arm64")
	lookup.nstaskReceivers["receiver"] = &machoNSTaskReceiverState{PathConfigured: true, Path: argument, Arguments: array}
	receivers := map[uint32]machoObjCReceiverValue{0: {Identity: "receiver", StringArray: array}}
	slots := map[int64]machoObjCStackSlot{0: {String: argument}}
	invalidateMachOCachedImageArguments(lookup, index, receivers, slots)
	if lookup.nstaskReceivers["receiver"].Path.Value == "" || len(receivers[0].StringArray.Elements) == 0 || len(slots) == 0 {
		t.Fatal("initial captured arguments were not retained")
	}
	index.memory.store(0x6003, 1, true)
	invalidateMachOCachedImageArguments(lookup, index, receivers, slots)
	if lookup.nstaskReceivers["receiver"].Path.Value != "" || len(lookup.nstaskReceivers["receiver"].Arguments.Elements) != 0 || len(receivers[0].StringArray.Elements) != 0 || len(slots) != 0 {
		t.Fatal("captured receiver or stack argument survived a backing-byte overwrite")
	}
}

func TestMachOLinearMemoryChecksAllStructuredByteRanges(t *testing.T) {
	for _, test := range []struct {
		name string
		va   uint64
	}{
		{"argv pointer interior", 0x2001},
		{"argv null slot interior", 0x2014},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, base := staticArgvMachOFixture(t, true)
			index := base.withLinearMemory(file)
			if _, ok := readMachOStaticArgvIndexed(file, index, 0x2000); !ok {
				t.Fatal("initial vector missing")
			}
			index.memory.store(test.va, 1, true)
			if _, ok := readMachOStaticArgvIndexed(file, index, 0x2000); ok {
				t.Fatal("overwritten vector retained")
			}
		})
	}
	data := make([]byte, 16)
	data[0], data[1] = 16, darwinAFINET
	binary.BigEndian.PutUint16(data[2:4], 443)
	copy(data[4:8], []byte{203, 0, 113, 8})
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{testMachOSection("__data", 0x2000, data)}}
	index := newMachOSectionIndex(file).withLinearMemory(file)
	if _, ok := readMachOStaticSocketAddressIndexed(file, index, 0x2000, false); !ok {
		t.Fatal("initial sockaddr missing")
	}
	index.memory.store(0x2004, 1, true)
	if _, ok := readMachOStaticSocketAddressIndexed(file, index, 0x2000, false); ok {
		t.Fatal("overwritten sockaddr retained")
	}
}

func TestMachOLinearMemoryUnknownWritesRequireReadOnlySegmentProtection(t *testing.T) {
	for _, test := range []struct {
		name  string
		loads []macho.Load
		want  bool
	}{
		{name: "name alone is insufficient"},
		{name: "read only", loads: []macho.Load{testMachOProtectedSegment(0x3000, 0x300, 0x100, 1)}, want: true},
		{name: "writable", loads: []macho.Load{testMachOProtectedSegment(0x3000, 0x300, 0x100, 3)}},
		{name: "partial mapping", loads: []macho.Load{testMachOProtectedSegment(0x3000, 0x300, 3, 1)}},
		{name: "wrong file mapping", loads: []macho.Load{testMachOProtectedSegment(0x3000, 0x200, 0x100, 1)}},
		{name: "overlapping writable mapping", loads: []macho.Load{testMachOProtectedSegment(0x3000, 0x300, 0x100, 1), testMachOProtectedSegment(0x3004, 0x304, 1, 3)}},
		{name: "overflowing mapping", loads: []macho.Load{testMachOProtectedSegment(0x3000, 0x300, ^uint64(0), 1)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, _ := staticArgvMachOFixture(t, true)
			file.Loads = test.loads
			index := newMachOSectionIndex(file).withLinearMemory(file)
			index.memory.store(0, 0, false)
			_, ok := readCStringAtVAIndexed(index, 0x3000, 4096)
			if ok != test.want {
				t.Fatalf("read retained %v, want %v", ok, test.want)
			}
			// Even a read-only mapping does not excuse an exact overlapping
			// write in the analyzed instruction sequence.
			index.memory.store(0x3001, 1, true)
			if _, ok := readCStringAtVAIndexed(index, 0x3000, 4096); ok {
				t.Fatal("exact alias write was ignored")
			}
		})
	}
}

func TestMachOLinearMemoryWriteBudgetAndAddressOverflowFailClosed(t *testing.T) {
	file, original := staticArgvMachOFixture(t, true)
	for _, test := range []struct {
		name  string
		write func(*machoLinearMemory)
	}{
		{"overflow", func(memory *machoLinearMemory) { memory.store(^uint64(0)-3, 8, true) }},
		{"budget", func(memory *machoLinearMemory) {
			for i := 0; i <= maxMachOLinearWrites; i++ {
				memory.store(0x9000+uint64(i)*2, 1, true)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			index := original.withLinearMemory(file)
			test.write(index.memory)
			if _, ok := readCStringAtVAIndexed(index, 0x3000, 4096); ok {
				t.Fatal("uncertain mutable bytes retained")
			}
			if len(index.memory.writes) > maxMachOLinearWrites {
				t.Fatal("unbounded write tracking")
			}
		})
	}
}

func TestMachOLinearMemoryCoalescesExactWrittenIntervals(t *testing.T) {
	for _, test := range []struct {
		name         string
		stores, want []machoMemoryRange
	}{
		{"nested", []machoMemoryRange{{100, 108}, {102, 104}}, []machoMemoryRange{{100, 108}}},
		{"overlap out of order", []machoMemoryRange{{108, 116}, {100, 112}}, []machoMemoryRange{{100, 116}}},
		{"adjacency out of order", []machoMemoryRange{{108, 116}, {100, 108}}, []machoMemoryRange{{100, 116}}},
		{"new write bridges gap", []machoMemoryRange{{100, 104}, {112, 116}, {104, 112}}, []machoMemoryRange{{100, 116}}},
		{"unwritten gap remains", []machoMemoryRange{{100, 104}, {108, 112}}, []machoMemoryRange{{100, 104}, {108, 112}}},
		{"partial bridge leaves gap", []machoMemoryRange{{100, 102}, {105, 107}, {102, 104}}, []machoMemoryRange{{100, 104}, {105, 107}}},
		{"disjoint insertion is sorted", []machoMemoryRange{{1000, 1004}, {100, 104}, {500, 504}}, []machoMemoryRange{{100, 104}, {500, 504}, {1000, 1004}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			memory := &machoLinearMemory{}
			written := map[uint64]bool{}
			for _, store := range test.stores {
				memory.store(store.start, store.end-store.start, true)
				for address := store.start; address < store.end; address++ {
					written[address] = true
				}
			}
			if len(memory.writes) != len(test.want) {
				t.Fatalf("ranges=%#v, want %#v", memory.writes, test.want)
			}
			for i, want := range test.want {
				if memory.writes[i] != want {
					t.Fatalf("ranges=%#v, want %#v", memory.writes, test.want)
				}
			}
			for address := uint64(90); address < 1020; address++ {
				if memory.overwrites(address, 1) != written[address] {
					t.Fatalf("incorrect byte coverage at %d: %#v", address, memory.writes)
				}
			}
		})
	}
}

func TestMachOLinearMemoryBudgetCountsDisjointRegions(t *testing.T) {
	memory := &machoLinearMemory{}
	for i := 0; i < maxMachOLinearWrites; i++ {
		memory.store(0x1000+uint64(i)*16, 8, true)
	}
	for i := 0; i < maxMachOLinearWrites*2; i++ {
		memory.store(0x1001, 1, true)
	}
	if memory.truncated || memory.lostWrites || len(memory.writes) != maxMachOLinearWrites {
		t.Fatal("repeated stores exhausted the region budget")
	}
	memory.store(0x1008, 8, true) // Writes the whole gap between the first two regions.
	if memory.lostWrites || len(memory.writes) != maxMachOLinearWrites-1 {
		t.Fatal("merging at capacity exhausted the budget")
	}
	memory.store(0xf000, 8, true)
	if memory.lostWrites || len(memory.writes) != maxMachOLinearWrites {
		t.Fatal("a freed region was not reusable")
	}
	memory.store(0xf100, 8, true)
	if !memory.lostWrites || !memory.truncated || len(memory.writes) != maxMachOLinearWrites {
		t.Fatal("a genuinely disjoint overflow did not fail closed")
	}
	memory.store(0x1008, 8, true)
	if !memory.lostWrites {
		t.Fatal("a later merge erased evidence of a lost write extent")
	}
	memory.reset()
	if len(memory.writes) != 0 || memory.unknownWrite || memory.lostWrites || !memory.truncated {
		t.Fatal("reset did not clear function state while preserving aggregate coverage")
	}
}

func TestMachOLostWriteExtentInvalidatesProtectedConcreteBytes(t *testing.T) {
	file, _ := staticArgvMachOFixture(t, true)
	addTestMachOReadOnlyMappings(file)
	index := newMachOSectionIndex(file).withLinearMemory(file)
	for i := 0; i < maxMachOLinearWrites; i++ {
		index.memory.store(0x9000+uint64(i)*16, 8, true)
	}
	if _, ok := readCStringAtVAIndexed(index, 0x3000, 4096); !ok {
		t.Fatal("disjoint writes erased protected bytes")
	}
	index.memory.store(0x3003, 1, true) // This literal overwrite cannot fit in the region log.
	if !index.memory.lostWrites {
		t.Fatal("fixture did not exhaust the region budget")
	}
	if _, ok := readCStringAtVAIndexed(index, 0x3000, 4096); ok {
		t.Fatal("read-only exemption bypassed a lost exact write")
	}
}

func FuzzMachOWriteIntervals(f *testing.F) {
	f.Add([]byte{10, 3, 14, 3, 12, 3, 40, 0})
	var disjoint []byte
	for i := 0; i <= maxMachOLinearWrites; i++ {
		disjoint = append(disjoint, byte(i*2), 0)
	}
	f.Add(disjoint)
	f.Fuzz(func(t *testing.T, data []byte) {
		memory := &machoLinearMemory{}
		var written [256]bool
		lost := false
		for i := 0; i+1 < min(len(data), 256); i += 2 {
			start := int(data[i])
			size := min(int(data[i+1]&15)+1, len(written)-start)
			memory.store(uint64(start), uint64(size), true)
			for address := start; address < start+size; address++ {
				written[address] = true
			}
			if len(memory.writes) > maxMachOLinearWrites || lost && !memory.lostWrites || memory.lostWrites && !memory.truncated {
				t.Fatal("write-region budget or loss latch violated")
			}
			for j, interval := range memory.writes {
				if interval.start >= interval.end || j > 0 && memory.writes[j-1].end >= interval.start {
					t.Fatal("write intervals are not sorted, disjoint and coalesced")
				}
			}
			lost = memory.lostWrites
			if !lost {
				for address, want := range written {
					if memory.overwrites(uint64(address), 1) != want {
						t.Fatalf("inexact byte coverage at %d", address)
					}
				}
			}
		}
	})
}

func TestNativeDecodersDoNotResurrectImageArgvAfterStoresOrCalls(t *testing.T) {
	for _, architecture := range []string{"arm64", "x86_64"} {
		for _, mutation := range []string{"exact store", "unknown alias", "branch alias", "derived frame alias", "indexed stack alias", "call", "read only after call", "disjoint store", "stack store", "stack writeback"} {
			t.Run(architecture+"/"+mutation, func(t *testing.T) {
				const textVA, arrayVA, stubVA = uint64(0x1000), uint64(0x2000), uint64(0x1100)
				file, _ := staticArgvMachOFixture(t, true)
				if mutation == "read only after call" {
					addTestMachOReadOnlyMappings(file)
				}
				var data []byte
				if architecture == "arm64" {
					pointer := func(register uint32, address uint64) {
						data = appendArm64Instruction(data, encodeTestADRP(register, textVA+uint64(len(data)), address))
						data = appendArm64Instruction(data, encodeTestADDImmediate(register, register, address&0xfff))
					}
					pointer(1, arrayVA)
					switch mutation {
					case "exact store":
						data = appendArm64Instruction(data, 0xf900003f) // STR xzr, [x1]
					case "unknown alias":
						data = appendArm64Instruction(data, 0xf900011f) // STR xzr, [x8]
					case "branch alias":
						pointer(29, arrayVA)
						data = appendArm64Instruction(data, 0x14000001) // B next
						data = appendArm64Instruction(data, 0xf90003bf) // STR xzr, [x29]
					case "derived frame alias":
						pointer(29, arrayVA)
						data = appendArm64Instruction(data, 0x14000001) // B next
						data = appendArm64Instruction(data, 0x910003a8) // ADD x8, x29, #0
						data = appendArm64Instruction(data, 0xf900011f) // STR xzr, [x8]
					case "indexed stack alias":
						data = appendArm64Instruction(data, 0xf8286bff) // STR xzr, [sp, x8]
					case "disjoint store":
						pointer(8, 0x9000)
						data = appendArm64Instruction(data, 0xf900011f)
					case "stack store":
						data = appendArm64Instruction(data, 0xf90003ff) // STR xzr, [sp]
					case "stack writeback":
						data = appendArm64Instruction(data, 0xa9bf7bfd) // STP x29, x30, [sp, #-16]!
					default:
						data = appendArm64Instruction(data, encodeTestBL(textVA+uint64(len(data)), 0x1200))
					}
					pointer(1, arrayVA) // Recomputing the pointer cannot reset memory.
					data = appendArm64Instruction(data, encodeTestBL(textVA+uint64(len(data)), stubVA))
				} else {
					data = append(data, encodeTestX86RIPRelativeLEAToReg(6, textVA, arrayVA)...)
					switch mutation {
					case "exact store":
						data = append(data, 0x48, 0xc7, 0x06, 0, 0, 0, 0) // MOV qword [rsi], 0
					case "unknown alias":
						data = append(data, 0x49, 0xc7, 0x00, 0, 0, 0, 0) // MOV qword [r8], 0
					case "branch alias":
						data = append(data, encodeTestX86RIPRelativeLEAToReg(5, textVA+uint64(len(data)), arrayVA)...)
						data = append(data, 0xeb, 0)                         // JMP next
						data = append(data, 0x48, 0xc7, 0x45, 0, 0, 0, 0, 0) // MOV qword [rbp], 0
					case "derived frame alias":
						data = append(data, encodeTestX86RIPRelativeLEAToReg(5, textVA+uint64(len(data)), arrayVA)...)
						data = append(data, 0xeb, 0)                      // JMP next
						data = append(data, 0x4c, 0x8d, 0x45, 0)          // LEA r8, [rbp]
						data = append(data, 0x49, 0xc7, 0x00, 0, 0, 0, 0) // MOV qword [r8], 0
					case "indexed stack alias":
						data = append(data, 0x48, 0xc7, 0x04, 0x04, 0, 0, 0, 0) // MOV qword [rsp+rax], 0
					case "disjoint store":
						data = append(data, encodeTestX86RIPRelativeLEAToReg(8, textVA+uint64(len(data)), 0x9000)...)
						data = append(data, 0x49, 0xc7, 0x00, 0, 0, 0, 0)
					case "stack store":
						data = append(data, 0x48, 0xc7, 0x04, 0x24, 0, 0, 0, 0) // MOV qword [rsp], 0
					case "stack writeback":
						data = append(data, 0x6a, 0) // PUSH 0
					default:
						data = append(data, encodeTestX86CALL(textVA+uint64(len(data)), 0x1200)...)
					}
					data = append(data, encodeTestX86RIPRelativeLEAToReg(6, textVA+uint64(len(data)), arrayVA)...)
					data = append(data, encodeTestX86CALL(textVA+uint64(len(data)), stubVA)...)
				}
				text := testMachOSection("__text", textVA, data)
				file.Sections = append([]*macho.Section{text}, file.Sections...)
				var graph behavior.Graph
				functions := []machoFunction{{Name: "main", Start: textVA, End: textVA + uint64(len(data))}}
				content := artifact.Content{NodeID: "node", LogicalPath: "inert-image-alias-control"}
				if architecture == "arm64" {
					extractArm64DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{stubVA: "_execve"}, nil, architecture)
				} else {
					extractX86DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{stubVA: "_execve"}, nil, architecture)
				}
				if len(graph.Operations) != 1 {
					t.Fatalf("neutral call was lost: %#v", graph.Operations)
				}
				_, bound := graph.Operations[0].FirstBinding(behavior.ResourceRoleArguments)
				want := mutation == "read only after call" || mutation == "disjoint store" || mutation == "stack store" || mutation == "stack writeback"
				if bound != want {
					t.Fatalf("argv bound=%v, want=%v: %#v", bound, want, graph.Operations)
				}
			})
		}
	}
}

func TestArm64ImageStoreOffsetsAgreeWithInstructionDecoder(t *testing.T) {
	for _, test := range []struct {
		instruction   uint32
		address, size uint64
	}{
		{0xf900051f, 0x3008, 8}, // STR xzr, [x8, #8]
		{0xb900051f, 0x3004, 4}, // STR wzr, [x8, #4]
		{0xf81fc11f, 0x2ffc, 8}, // STUR xzr, [x8, #-4]
		{0xb81fc11f, 0x2ffc, 4}, // STUR wzr, [x8, #-4]
	} {
		var raw [4]byte
		binary.LittleEndian.PutUint32(raw[:], test.instruction)
		decoded, err := arm64asm.Decode(raw[:])
		if err != nil || decoded.Op != arm64asm.STR && decoded.Op != arm64asm.STUR {
			t.Fatalf("fixture instruction %#x is not a decoded store: %v, %v", test.instruction, decoded, err)
		}
		memory := &machoLinearMemory{}
		memory.arm64Store(test.instruction, 4, map[uint32]arm64RegisterValue{8: {value: 0x3000}}, nil)
		if len(memory.writes) != 1 || memory.writes[0] != (machoMemoryRange{test.address, test.address + test.size}) {
			t.Fatalf("instruction %#x writes %#v", test.instruction, memory.writes)
		}
	}
}

func TestX86ImportSlotMutationDoesNotChangeAnAlreadyLoadedPointer(t *testing.T) {
	for _, loaded := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh slot read", true: "already loaded register"}[loaded], func(t *testing.T) {
			const textVA, commandVA, pointerVA = uint64(0x1000), uint64(0x3000), uint64(0x4000)
			file := &macho.File{
				ByteOrder: binary.LittleEndian,
				Loads:     []macho.Load{testMachOIndirectSectionLoad("__got", "__DATA_CONST", pointerVA, 8, 0x6, 0, 0)},
				Symtab:    &macho.Symtab{Syms: []macho.Symbol{{Name: "_system", Type: 1}}},
				Dysymtab:  &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Iundefsym: 0, Nundefsym: 1}, IndirectSyms: []uint32{0}},
				Sections:  []*macho.Section{testMachOSection("__cstring", commandVA, []byte("/usr/bin/true\x00")), testMachOSection("__got", pointerVA, make([]byte, 8))},
			}
			var data []byte
			if loaded {
				data = append(data, 0x4c, 0x8b, 0x1d, 0, 0, 0, 0) // MOV r11, [rip+slot]
				binary.LittleEndian.PutUint32(data[3:], uint32(pointerVA-(textVA+7)))
			}
			data = append(data, encodeTestX86RIPRelativeLEAToReg(8, textVA+uint64(len(data)), pointerVA)...)
			data = append(data, 0x49, 0xc7, 0x00, 0, 0, 0, 0) // MOV qword [r8], 0
			data = append(data, encodeTestX86RIPRelativeLEAToReg(7, textVA+uint64(len(data)), commandVA)...)
			if loaded {
				data = append(data, 0x41, 0xff, 0xd3) // CALL r11
			} else {
				data = append(data, encodeTestX86IndirectCALL(textVA+uint64(len(data)), pointerVA)...)
			}
			text := testMachOSection("__text", textVA, data)
			file.Sections = append([]*macho.Section{text}, file.Sections...)
			var graph behavior.Graph
			extractX86DirectCalls(&graph, artifact.Content{NodeID: "node", LogicalPath: "inert-import-slot-control"}, file, text, data,
				[]machoFunction{{Name: "main", Start: textVA, End: textVA + uint64(len(data))}}, nil, nil, "x86_64")
			if loaded && len(graph.Operations) == 0 || !loaded && len(graph.Operations) != 0 {
				t.Fatalf("loaded=%v operations=%#v", loaded, graph.Operations)
			}
			if !loaded && len(graph.Coverage) == 0 {
				t.Fatal("lost import identity had no coverage explanation")
			}
		})
	}
}

func TestNativeDecodersStopAtKnownCodeOrStubMutation(t *testing.T) {
	for _, architecture := range []string{"arm64", "x86_64"} {
		for _, stub := range []bool{false, true} {
			t.Run(architecture+map[bool]string{false: "/call bytes", true: "/stub bytes"}[stub], func(t *testing.T) {
				const textVA, arrayVA, stubVA = uint64(0x1000), uint64(0x2000), uint64(0x1100)
				file, _ := staticArgvMachOFixture(t, true)
				var data []byte
				target := stubVA
				if architecture == "arm64" {
					if !stub {
						target = textVA + 20
					}
					data = appendArm64Instruction(data, encodeTestADRP(8, textVA, target))
					data = appendArm64Instruction(data, encodeTestADDImmediate(8, 8, target&0xfff))
					data = appendArm64Instruction(data, 0xf900011f) // STR xzr, [x8]
					data = appendArm64Instruction(data, encodeTestADRP(1, textVA+12, arrayVA))
					data = appendArm64Instruction(data, encodeTestADDImmediate(1, 1, arrayVA&0xfff))
					data = appendArm64Instruction(data, encodeTestBL(textVA+20, stubVA))
				} else {
					if !stub {
						target = textVA + 21
					}
					data = append(data, encodeTestX86RIPRelativeLEAToReg(8, textVA, target)...)
					data = append(data, 0x49, 0xc7, 0x00, 0, 0, 0, 0)
					data = append(data, encodeTestX86RIPRelativeLEAToReg(6, textVA+14, arrayVA)...)
					data = append(data, encodeTestX86CALL(textVA+21, stubVA)...)
				}
				text := testMachOSection("__text", textVA, data)
				file.Sections = append([]*macho.Section{text}, file.Sections...)
				var graph behavior.Graph
				content := artifact.Content{NodeID: "node", LogicalPath: "inert-code-mutation-control"}
				functions := []machoFunction{{Name: "main", Start: textVA, End: textVA + uint64(len(data))}}
				if architecture == "arm64" {
					extractArm64DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{stubVA: "_execve"}, nil, architecture)
				} else {
					extractX86DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{stubVA: "_execve"}, nil, architecture)
				}
				if len(graph.Operations) != 0 || len(graph.Coverage) == 0 {
					t.Fatalf("modified code retained operations or lost coverage: %#v", graph)
				}
			})
		}
	}
}

func TestX86MemoryBitOffsetsAreNotTreatedAsFixedWriteExtents(t *testing.T) {
	for _, opcode := range []byte{0xab, 0xb3, 0xbb} { // BTS/BTR/BTC [rsi], rax
		inst, err := decodeX86Instruction([]byte{0x48, 0x0f, opcode, 0x06})
		if err != nil {
			t.Fatal(err)
		}
		memory := &machoLinearMemory{}
		memory.x86Store(inst, 0x1000, 4, map[uint8]x86AddressValue{6: {value: 0x2000}})
		if !memory.unknownWrite || len(memory.writes) != 0 {
			t.Fatalf("bit offset was interpreted as a fixed write: %#v", memory)
		}
		registerOnly, err := decodeX86Instruction([]byte{0x48, 0x0f, opcode, 0xc6})
		if err != nil {
			t.Fatal(err)
		}
		clean := &machoLinearMemory{}
		clean.x86Store(registerOnly, 0x1000, 4, nil)
		if clean.unknownWrite || len(clean.writes) != 0 {
			t.Fatal("register-only bit operation dirtied image memory")
		}
	}
}

func TestMachOImportSlotCorrelationPreservesPartialMetadata(t *testing.T) {
	file := &macho.File{}
	for _, truncated := range []bool{false, true} {
		pointers := map[uint64]string{}
		for i := 0; i < 128; i++ {
			pointers[0x4000+uint64(i)*8] = "_system"
		}
		slots := newMachOImportSlots(pointers, truncated)
		index := newMachOSectionIndex(file).withLinearMemory(file)
		var graph behavior.Graph
		lookup := newMachOCallLookup(&graph, artifact.Content{NodeID: "node"}, "arm64")
		if !slots.retained(lookup, index, "_system") {
			t.Fatal("unmodified loader binding was discarded")
		}
		index.memory.store(0x9000, 1, true)
		if !slots.retained(lookup, index, "_system") {
			t.Fatal("disjoint write contradicted retained loader identity")
		}
		if truncated && len(graph.Coverage) == 0 {
			t.Fatal("partial pointer metadata lost its coverage limit")
		}
		index.memory.store(0x4000+127*8+7, 1, true)
		if slots.retained(lookup, index, "_system") {
			t.Fatal("interior write to the last retained slot was ignored")
		}
	}
}

func TestMachOImportSlotCorrelationBoundsInput(t *testing.T) {
	pointers := map[uint64]string{}
	for i := 0; i <= maxMachOStubRecords; i++ {
		pointers[0x4000+uint64(i)*8] = "_system"
	}
	slots := newMachOImportSlots(pointers, false)
	index := newMachOSectionIndex(&macho.File{}).withLinearMemory(&macho.File{})
	var graph behavior.Graph
	lookup := newMachOCallLookup(&graph, artifact.Content{NodeID: "node"}, "arm64")
	index.memory.store(0x9000, 1, true)
	if !slots.oversized || len(slots.bySymbol) != 0 || slots.retained(lookup, index, "_system") || len(graph.Coverage) == 0 {
		t.Fatal("oversized pointer metadata was not bounded")
	}
}

func TestNativeDirectStubIdentityRejectsOverwrittenSameSymbolSlots(t *testing.T) {
	for _, architecture := range []string{"arm64", "x86_64"} {
		for _, target := range []uint64{0x4000, 0x4008, 0x9000} {
			t.Run(architecture+map[uint64]string{0x4000: "/same symbol", 0x4008: "/other symbol", 0x9000: "/disjoint"}[target], func(t *testing.T) {
				const textVA, commandVA, stubVA = uint64(0x1000), uint64(0x3000), uint64(0x1100)
				file := &macho.File{
					ByteOrder: binary.LittleEndian,
					Loads:     []macho.Load{testMachOIndirectSectionLoad("__got", "__DATA_CONST", 0x4000, 16, 0x6, 0, 0)},
					Symtab:    &macho.Symtab{Syms: []macho.Symbol{{Name: "_system", Type: 1}, {Name: "_puts", Type: 1}}},
					Dysymtab:  &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Iundefsym: 0, Nundefsym: 2}, IndirectSyms: []uint32{0, 1}},
					Sections:  []*macho.Section{testMachOSection("__cstring", commandVA, []byte("/usr/bin/true\x00")), testMachOSection("__got", 0x4000, make([]byte, 16))},
				}
				var data []byte
				if architecture == "arm64" {
					data = appendArm64Instruction(data, encodeTestADRP(8, textVA, target))
					data = appendArm64Instruction(data, encodeTestADDImmediate(8, 8, target&0xfff))
					data = appendArm64Instruction(data, 0xf900011f)
					data = appendArm64Instruction(data, encodeTestADRP(0, textVA+12, commandVA))
					data = appendArm64Instruction(data, encodeTestADDImmediate(0, 0, commandVA&0xfff))
					data = appendArm64Instruction(data, encodeTestBL(textVA+20, stubVA))
				} else {
					data = append(data, encodeTestX86RIPRelativeLEAToReg(8, textVA, target)...)
					data = append(data, 0x49, 0xc7, 0x00, 0, 0, 0, 0)
					data = append(data, encodeTestX86RIPRelativeLEAToReg(7, textVA+14, commandVA)...)
					data = append(data, encodeTestX86CALL(textVA+21, stubVA)...)
				}
				text := testMachOSection("__text", textVA, data)
				file.Sections = append([]*macho.Section{text}, file.Sections...)
				var graph behavior.Graph
				content := artifact.Content{NodeID: "node", LogicalPath: "inert-stub-slot-control"}
				functions := []machoFunction{{Name: "main", Start: textVA, End: textVA + uint64(len(data))}}
				if architecture == "arm64" {
					extractArm64DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{stubVA: "_system"}, nil, architecture)
				} else {
					extractX86DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{stubVA: "_system"}, nil, architecture)
				}
				if (len(graph.Operations) != 0) != (target != 0x4000) {
					t.Fatalf("target %#x retained operations %#v", target, graph.Operations)
				}
				if target == 0x4000 && len(graph.Coverage) == 0 {
					t.Fatal("missing import-identity coverage")
				}
			})
		}
	}
}

func TestNativeImportsRemainConditionalAfterUnresolvedStores(t *testing.T) {
	for _, architecture := range []string{"arm64", "x86_64"} {
		for _, indirect := range []bool{false, true} {
			if architecture == "arm64" && indirect {
				continue
			}
			t.Run(architecture+map[bool]string{false: "/stub", true: "/slot"}[indirect], func(t *testing.T) {
				const textVA, arrayVA, stubVA, pointerVA = uint64(0x1000), uint64(0x2000), uint64(0x1100), uint64(0x4000)
				file, _ := staticArgvMachOFixture(t, true)
				file.Loads = []macho.Load{testMachOIndirectSectionLoad("__got", "__DATA_CONST", pointerVA, 8, 0x6, 0, 0)}
				file.Sections = append(file.Sections, testMachOSection("__got", pointerVA, make([]byte, 8)))
				file.Symtab = &macho.Symtab{Syms: []macho.Symbol{{Name: "_execve", Type: 1}}}
				file.Dysymtab = &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Nundefsym: 1}, IndirectSyms: []uint32{0}}
				var data []byte
				if architecture == "arm64" {
					data = appendArm64Instruction(data, 0xf900011f) // STR xzr, [x8], with unknown x8
					data = appendArm64Instruction(data, encodeTestADRP(1, textVA+4, arrayVA))
					data = appendArm64Instruction(data, encodeTestADDImmediate(1, 1, arrayVA&0xfff))
					data = appendArm64Instruction(data, encodeTestBL(textVA+12, stubVA))
				} else {
					data = append(data, 0x49, 0xc7, 0x00, 0, 0, 0, 0) // MOV qword [r8], 0, with unknown r8
					data = append(data, encodeTestX86RIPRelativeLEAToReg(6, textVA+uint64(len(data)), arrayVA)...)
					if indirect {
						data = append(data, encodeTestX86IndirectCALL(textVA+uint64(len(data)), pointerVA)...)
					} else {
						data = append(data, encodeTestX86CALL(textVA+uint64(len(data)), stubVA)...)
					}
				}
				text := testMachOSection("__text", textVA, data)
				file.Sections = append([]*macho.Section{text}, file.Sections...)
				var graph behavior.Graph
				content := artifact.Content{NodeID: "node", LogicalPath: "inert-loader-binding-control"}
				functions := []machoFunction{{Name: "main", Start: textVA, End: textVA + uint64(len(data))}}
				if architecture == "arm64" {
					extractArm64DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{stubVA: "_execve"}, nil, architecture)
				} else {
					extractX86DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{stubVA: "_execve"}, nil, architecture)
				}
				if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute || graph.Operations[0].Support != behavior.SupportCorroborated {
					t.Fatalf("conditional imported API was lost: %#v", graph.Operations)
				}
				if _, bound := graph.Operations[0].FirstBinding(behavior.ResourceRoleArguments); bound {
					t.Fatal("writable argv survived an unresolved store")
				}
				found := false
				for _, coverage := range graph.Coverage {
					if coverage.AnalysisArea == "macho-import-binding-limits/"+architecture && coverage.Status == "partial" {
						found = true
					}
				}
				if !found {
					t.Fatal("runtime binding uncertainty was not recorded")
				}
			})
		}
	}
}

func TestMachOImportBindingRejectsLostWriteExtents(t *testing.T) {
	file, base := staticArgvMachOFixture(t, true)
	index := base.withLinearMemory(file)
	var graph behavior.Graph
	lookup := newMachOCallLookup(&graph, artifact.Content{NodeID: "node"}, "x86_64")
	slots := newMachOImportSlots(map[uint64]string{0x4000: "_execve"}, false)
	for i := 0; i < maxMachOLinearWrites; i++ {
		index.memory.store(0x9000+uint64(i)*16, 8, true)
	}
	if !slots.retained(lookup, index, "_execve") || !machoImportBindingRetained(lookup, index, 0x4000) {
		t.Fatal("disjoint known writes erased loader metadata")
	}
	index.memory.store(0x4000, 8, true) // This exact contradiction cannot fit in the range log.
	if !index.memory.lostWrites || slots.retained(lookup, index, "_execve") || machoImportBindingRetained(lookup, index, 0x4000) {
		t.Fatal("lost exact write permitted imported API identity")
	}
	index.memory.reset()
	if !index.memory.truncated || !slots.retained(lookup, index, "_execve") {
		t.Fatal("function reset lost coverage or carried stale mutation into an independent function")
	}
}

func TestObjectiveCSelectorMetadataRetainsRegistrationIdentity(t *testing.T) {
	for _, change := range []string{"call", "unresolved store", "reference write", "name write", "terminator write", "lost write extent"} {
		t.Run(change, func(t *testing.T) {
			file := testWritableSelectorRefFixture()
			index := newMachOSectionIndex(file).withLinearMemory(file)
			if selector, ok := readObjectiveCSelectorRefAtVAIndexed(file, index, 0x2000); !ok || selector != "fileExistsAtPath:" {
				t.Fatal("initial selector metadata was not retained")
			}
			switch change {
			case "call":
				index.memory.callBoundary = true
			case "unresolved store":
				index.memory.store(0, 0, false)
			case "reference write":
				index.memory.store(0x2003, 1, true)
			case "name write":
				index.memory.store(0x3003, 1, true)
			case "terminator write":
				index.memory.store(0x3000+uint64(len("fileExistsAtPath:")), 1, true)
			case "lost write extent":
				for i := 0; i <= maxMachOLinearWrites; i++ {
					index.memory.store(0x9000+uint64(i)*16, 8, true)
				}
			}
			_, retained := readObjectiveCSelectorRefAtVAIndexed(file, index, 0x2000)
			want := change == "call" || change == "unresolved store"
			if retained != want {
				t.Fatalf("selector retained=%v, want=%v", retained, want)
			}
			if want {
				if _, ok := readPointerAtVAIndexed(file, index, 0x2000); ok {
					t.Fatal("structural selector parsing weakened concrete mutable reads")
				}
			}
		})
	}
}

func TestNativeObjCCallsRetainSelectorMetadataAfterRuntimeBoundaries(t *testing.T) {
	for _, architecture := range []string{"arm64", "x86_64"} {
		for _, call := range []bool{false, true} {
			t.Run(architecture+map[bool]string{false: "/unresolved store", true: "/call"}[call], func(t *testing.T) {
				const textVA, refVA, stubVA = uint64(0x1000), uint64(0x2000), uint64(0x1100)
				file := testWritableSelectorRefFixture()
				var data []byte
				if architecture == "arm64" {
					if call {
						data = appendArm64Instruction(data, encodeTestBL(textVA, 0x1200))
					} else {
						data = appendArm64Instruction(data, 0xf900011f)
					}
					data = appendArm64Instruction(data, encodeTestADRP(1, textVA+uint64(len(data)), refVA))
					data = appendArm64Instruction(data, encodeTestLDRXUnsigned(1, 1, 0))
					data = appendArm64Instruction(data, encodeTestBL(textVA+uint64(len(data)), stubVA))
				} else {
					if call {
						data = append(data, encodeTestX86CALL(textVA, 0x1200)...)
					} else {
						data = append(data, 0x49, 0xc7, 0x00, 0, 0, 0, 0)
					}
					data = append(data, encodeTestX86RIPRelativeMOVToReg(6, textVA+uint64(len(data)), refVA)...)
					data = append(data, encodeTestX86CALL(textVA+uint64(len(data)), stubVA)...)
				}
				text := testMachOSection("__text", textVA, data)
				file.Sections = append([]*macho.Section{text}, file.Sections...)
				var graph behavior.Graph
				content := artifact.Content{NodeID: "node", LogicalPath: "inert-selector-registration-control"}
				functions := []machoFunction{{Name: "main", Start: textVA, End: textVA + uint64(len(data))}}
				if architecture == "arm64" {
					extractArm64DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{stubVA: "_objc_msgSend"}, nil, architecture)
				} else {
					extractX86DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{stubVA: "_objc_msgSend"}, nil, architecture)
				}
				if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileMetadataQuery || graph.Operations[0].Support != behavior.SupportHeuristic || graph.Operations[0].RequiredResource().Value != "" {
					t.Fatalf("selector-only operation changed proof threshold or disappeared: %#v", graph.Operations)
				}
			})
		}
	}
}

func testWritableSelectorRefFixture() *macho.File {
	reference := make([]byte, 8)
	binary.LittleEndian.PutUint64(reference, 0x3000)
	refs := testMachOSection("__objc_selrefs", 0x2000, reference)
	refs.Offset = 0x200
	names := testMachOSection("__objc_methname", 0x3000, []byte("fileExistsAtPath:\x00"))
	names.Seg, names.Offset = "__TEXT", 0x300
	return &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{refs, names}, Loads: []macho.Load{
		testMachOProtectedSegment(refs.Addr, uint64(refs.Offset), refs.Size, 3),
		testMachOProtectedSegment(names.Addr, uint64(names.Offset), names.Size, 1),
	}}
}

func TestMachODyldPostFixupProtectionRetainsConcreteCFStrings(t *testing.T) {
	for _, test := range []struct {
		name                 string
		kind                 macho.Type
		flags, prot, maxprot uint32
		segmentFlag          bool
		loader               int
		overlap              bool
		want                 bool
	}{
		{name: "dyld library", kind: macho.TypeDylib, flags: macho.FlagDyldLink, prot: 3, maxprot: 3, segmentFlag: true, want: true},
		{name: "dyld bundle", kind: macho.TypeBundle, flags: macho.FlagDyldLink, prot: 3, maxprot: 3, segmentFlag: true, want: true},
		{name: "dyld executable", kind: macho.TypeExec, flags: macho.FlagDyldLink, prot: 3, maxprot: 3, segmentFlag: true, loader: 1, want: true},
		{name: "static executable", kind: macho.TypeExec, flags: macho.FlagDyldLink, prot: 3, maxprot: 3, segmentFlag: true},
		{name: "custom loader", kind: macho.TypeExec, flags: macho.FlagDyldLink, prot: 3, maxprot: 3, segmentFlag: true, loader: 2},
		{name: "duplicate loader", kind: macho.TypeExec, flags: macho.FlagDyldLink, prot: 3, maxprot: 3, segmentFlag: true, loader: 3},
		{name: "malformed loader", kind: macho.TypeExec, flags: macho.FlagDyldLink, prot: 3, maxprot: 3, segmentFlag: true, loader: 4},
		{name: "no segment flag", kind: macho.TypeDylib, flags: macho.FlagDyldLink, prot: 3, maxprot: 3},
		{name: "no dyld link profile", kind: macho.TypeDylib, prot: 3, maxprot: 3, segmentFlag: true},
		{name: "relocatable object", kind: macho.TypeObj, flags: macho.FlagDyldLink, prot: 3, maxprot: 3, segmentFlag: true},
		{name: "executable writable segment", kind: macho.TypeDylib, flags: macho.FlagDyldLink, prot: 7, maxprot: 7, segmentFlag: true},
		{name: "inconsistent maximum protection", kind: macho.TypeDylib, flags: macho.FlagDyldLink, prot: 3, maxprot: 1, segmentFlag: true},
		{name: "overlapping writable mapping", kind: macho.TypeDylib, flags: macho.FlagDyldLink, prot: 3, maxprot: 3, segmentFlag: true, overlap: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, _ := testObjCStringArrayFixture(t, 4096)
			file.Magic, file.Type, file.Flags = macho.Magic64, test.kind, test.flags
			for _, section := range file.Sections {
				segment := testMachOProtectedSegment(section.Addr, uint64(section.Offset), section.Size, test.prot)
				segment.Maxprot = test.maxprot
				if test.segmentFlag {
					segment.Flag = machoSGReadOnlyAfterFixups
				}
				file.Loads = append(file.Loads, segment)
			}
			switch test.loader {
			case 1:
				file.Loads = append(file.Loads, testDyldLoaderLoad("/usr/lib/dyld"))
			case 2:
				file.Loads = append(file.Loads, testDyldLoaderLoad("/tmp/custom-loader"))
			case 3:
				file.Loads = append(file.Loads, testDyldLoaderLoad("/usr/lib/dyld"), testDyldLoaderLoad("/usr/lib/dyld"))
			case 4:
				load := testDyldLoaderLoad("/usr/lib/dyld")
				binary.LittleEndian.PutUint32(load[8:12], 4)
				file.Loads = append(file.Loads, load)
			}
			if test.overlap {
				file.Loads = append(file.Loads, testMachOProtectedSegment(0x4000, 0, machOCFString64RecordSize, 3))
			}
			index := newMachOSectionIndex(file).withLinearMemory(file)
			reader := newMachOCFStringReader(index, 4096)
			if _, ok := objcCFStringAtTargetLocationIndexed(file, reader, 0x4000, false); !ok {
				t.Fatal("initial CFString was not parsed")
			}
			index.memory.callBoundary = true
			index.memory.store(0, 0, false)
			_, retained := objcCFStringAtTargetLocationIndexed(file, reader, 0x4000, false)
			if retained != test.want {
				t.Fatalf("post-fixup CFString retained=%v, want=%v", retained, test.want)
			}
			if test.want {
				index.memory.store(0x4003, 1, true)
				if _, ok := objcCFStringAtTargetLocationIndexed(file, reader, 0x4000, false); ok {
					t.Fatal("exact object write bypassed protection guard")
				}
				index.memory.reset()
				index.memory.callBoundary = true
				index.memory.store(0x6001, 1, true)
				if _, ok := objcCFStringAtTargetLocationIndexed(file, reader, 0x4000, false); ok {
					t.Fatal("exact backing write bypassed cache/protection guard")
				}
			}
		})
	}
}

func testDyldLoaderLoad(name string) macho.LoadBytes {
	raw := make(macho.LoadBytes, (12+len(name)+1+7)&^7)
	binary.LittleEndian.PutUint32(raw[:4], 0xe) // LC_LOAD_DYLINKER
	binary.LittleEndian.PutUint32(raw[4:8], uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[8:12], 12)
	copy(raw[12:], name)
	return raw
}

func testMachOProtectedSegment(address, offset, size uint64, prot uint32) *macho.Segment {
	return &macho.Segment{SegmentHeader: macho.SegmentHeader{Addr: address, Offset: offset, Filesz: size, Memsz: size, Prot: prot}}
}

func addTestMachOReadOnlyMappings(file *macho.File) {
	// These inert controls use immutable image literals. Include actual segment
	// protections so positive semantics do not rely on familiar section names.
	for _, section := range file.Sections {
		file.Loads = append(file.Loads, testMachOProtectedSegment(section.Addr, uint64(section.Offset), section.Size, 1))
	}
}
