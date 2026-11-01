package extract

import (
	"debug/macho"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestObjCStaticStringArrayRetainsExactElementsAndLocations(t *testing.T) {
	file, reader := testObjCStringArrayFixture(t, 1<<20)
	array, ok := objcCFStringArrayAtTargetLocationIndexed(file, reader, 0x2000, false)
	if !ok {
		t.Fatal("expected exact static Objective-C string array")
	}
	if array.ObjectVA != 0x2000 || array.DataVA != 0x3000 || array.Representation != "static-nsconstantarray" || len(array.Elements) != 2 {
		t.Fatalf("array provenance = %#v", array)
	}
	values := []string{array.Elements[0].String.Value, array.Elements[1].String.Value}
	if !slices.Equal(values, []string{"--version", "fixture-value"}) || array.Elements[0].SlotVA != 0x3000 || array.Elements[1].String.BackingVA != 0x7000 {
		t.Fatalf("array elements = %#v", array.Elements)
	}
	if array, ok := objcCFStringArrayAtTargetLocationIndexed(file, reader, 0x2001, false); ok {
		t.Fatalf("interior array-object address produced %#v", array)
	}
}

func TestObjCStaticStringArrayFailsClosedOnMalformedAndBudgetedInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*macho.File)
		budget uint64
	}{
		{name: "wrong object section", budget: 1 << 20, mutate: func(file *macho.File) { file.Sections[0].Name = "__const" }},
		{name: "wrong data section", budget: 1 << 20, mutate: func(file *macho.File) { file.Sections[1].Name = "__const" }},
		{name: "excess count", budget: 1 << 20, mutate: func(file *macho.File) {
			object := make([]byte, machOObjCArray64RecordSize)
			binary.LittleEndian.PutUint64(object[8:16], maxMachOObjCArrayEntries+1)
			binary.LittleEndian.PutUint64(object[16:24], 0x3000)
			file.Sections[0] = testMachOSection("__objc_arrayobj", 0x2000, object)
		}},
		{name: "non CFString element", budget: 1 << 20, mutate: func(file *macho.File) {
			data := make([]byte, 16)
			binary.LittleEndian.PutUint64(data[0:8], 0xdeadbeef)
			binary.LittleEndian.PutUint64(data[8:16], 0x5000)
			file.Sections[1] = testMachOSection("__objc_arraydata", 0x3000, data)
		}},
		{name: "backing budget", budget: 1, mutate: func(*macho.File) {}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, _ := testObjCStringArrayFixture(t, 1<<20)
			test.mutate(file)
			reader := newMachOCFStringReader(newMachOSectionIndex(file), test.budget)
			if array, ok := objcCFStringArrayAtTargetLocationIndexed(file, reader, 0x2000, false); ok {
				t.Fatalf("malformed or over-budget array produced %#v", array)
			}
		})
	}
}

func TestX86RegisterIndirectCallRequiresCanonicalRegisterForm(t *testing.T) {
	for _, test := range []struct {
		data []byte
		reg  uint8
	}{
		{data: []byte{0xff, 0xd0}, reg: 0},
		{data: []byte{0x41, 0xff, 0xd7}, reg: 15},
	} {
		reg, size, ok := x86RegisterIndirectCall(test.data)
		if !ok || reg != test.reg || size != len(test.data) {
			t.Fatalf("register call %x = reg %d size %d ok %v", test.data, reg, size, ok)
		}
	}
	for _, malformed := range [][]byte{{0xff, 0x10}, {0xff, 0xe0}, {0x48, 0xff, 0xd0, 0x90}, {0x40, 0x41, 0xff, 0xd0}} {
		if reg, size, ok := x86RegisterIndirectCall(malformed); ok {
			t.Fatalf("malformed register call %x = reg %d size %d", malformed, reg, size)
		}
	}
}

func TestArm64StackArrayInstructionFormsAreExactAndBounded(t *testing.T) {
	if register, offset, ok := arm64SPRelativeAddress(0x910023e2); !ok || register != 2 || offset != 8 {
		t.Fatalf("ADD x2, sp, #8 = register %d offset %d ok %v", register, offset, ok)
	}
	if first, second, offset, ok := arm64SPRelativePairStore(0xa900a7e8); !ok || first != 8 || second != 9 || offset != 8 {
		t.Fatalf("STP x8, x9, [sp, #8] = registers %d,%d offset %d ok %v", first, second, offset, ok)
	}
	if register, offset, ok := arm64SPRelativeStore(0xf9000fe8); !ok || register != 8 || offset != 24 {
		t.Fatalf("STR x8, [sp, #24] = register %d offset %d ok %v", register, offset, ok)
	}

	for _, instruction := range []uint32{
		0x910023ff, // destination SP
		0x110023e2, // 32-bit ADD
		0xa880a7e8, // post-index STP
		0xa980a7e8, // pre-index STP
		0xb9000fe8, // 32-bit STR
		0xf8008fe8, // post-index STR
	} {
		if _, _, ok := arm64SPRelativeAddress(instruction); ok {
			t.Fatalf("non-canonical instruction %#08x decoded as SP-relative address", instruction)
		}
		if _, _, _, ok := arm64SPRelativePairStore(instruction); ok {
			t.Fatalf("non-canonical instruction %#08x decoded as SP-relative pair store", instruction)
		}
		if _, _, ok := arm64SPRelativeStore(instruction); ok {
			t.Fatalf("non-canonical instruction %#08x decoded as SP-relative store", instruction)
		}
	}
}

func TestArm64FrameReceiverInstructionFormsAreExact(t *testing.T) {
	if register, offset, load, ok := arm64FrameRelativeReceiverAccess(0xf81f03a0); !ok || register != 0 || offset != -16 || load {
		t.Fatalf("STUR x0, [x29, #-16] = register %d offset %d load %v ok %v", register, offset, load, ok)
	}
	if register, offset, load, ok := arm64FrameRelativeReceiverAccess(0xf85f03a0); !ok || register != 0 || offset != -16 || !load {
		t.Fatalf("LDUR x0, [x29, #-16] = register %d offset %d load %v ok %v", register, offset, load, ok)
	}
	if register, offset, load, ok := arm64FrameRelativeReceiverAccess(0xf9400ba1); !ok || register != 1 || offset != 16 || !load {
		t.Fatalf("LDR x1, [x29, #16] = register %d offset %d load %v ok %v", register, offset, load, ok)
	}
	if destination, ok := arm64FrameAddressDestination(0xd10043a8); !ok || destination != 8 {
		t.Fatalf("SUB x8, x29, #16 = destination %d ok %v", destination, ok)
	}
	for _, instruction := range []uint32{
		0xb81f03a0, // 32-bit STUR
		0xf81f03e0, // SP base
		0xf81f0ba0, // pre/post-index family
		0xa90007a0, // pair store
		0xd10043e8, // SUB rooted at SP
		0xf10043a8, // SUBS changes flags
	} {
		if register, offset, load, ok := arm64FrameRelativeReceiverAccess(instruction); ok {
			t.Fatalf("non-canonical frame access %#08x = register %d offset %d load %v", instruction, register, offset, load)
		}
		if destination, ok := arm64FrameAddressDestination(instruction); ok {
			t.Fatalf("non-canonical frame address %#08x = destination %d", instruction, destination)
		}
	}
}

func TestArm64KnownMemoryAccessInvalidatesOnlyExactDestination(t *testing.T) {
	for _, test := range []struct {
		instruction    uint32
		register, base uint32
		load           bool
	}{
		{0xf94003e1, 1, 31, true},  // LDR x1, [sp]
		{0xf90007e8, 8, 31, false}, // STR x8, [sp, #8]
		{0xb81fc3a0, 0, 29, false}, // STUR w0, [x29, #-4]
		{0xb85fc3a2, 2, 29, true},  // LDUR w2, [x29, #-4]
	} {
		register, base, load, ok := arm64KnownMemoryAccess(test.instruction)
		if !ok || register != test.register || base != test.base || load != test.load {
			t.Fatalf("instruction %#08x = register %d base %d load %v ok %v", test.instruction, register, base, load, ok)
		}
	}
	for _, instruction := range []uint32{0xf8408be0, 0xf8606ba0, 0xa94007a0, 0x58000020} {
		if register, base, load, ok := arm64KnownMemoryAccess(instruction); ok {
			t.Fatalf("indexed, pair, or literal access %#08x = register %d base %d load %v", instruction, register, base, load)
		}
	}
}

func TestArm64ChainedClassAndFrameSpillRecoverExactObjCReceiverLifecycle(t *testing.T) {
	graph, count, truncated := arm64ReceiverSpillControl(t, nil)
	if truncated || count != 3 || len(graph.Operations) != 1 {
		t.Fatalf("exact receiver lifecycle count=%d truncated=%v operations=%#v", count, truncated, graph.Operations)
	}
	operation := graph.Operations[0]
	if operation.Kind != behavior.OperationProcessExecute || operation.Support != behavior.SupportCorroborated || operation.RequiredResource().Value != "/usr/bin/true" || operation.Qualifiers["receiver_class"] != "NSTask" || operation.Qualifiers["receiver_identity"] != "exact-linear-object" {
		t.Fatalf("exact receiver lifecycle operation = %#v", operation)
	}
	classEvidence := false
	for _, evidence := range graph.Evidence {
		if evidence.Kind == "objc-class-reference" && strings.Contains(evidence.Value, "slot 0x100004000 -> NSTask") {
			classEvidence = true
		}
	}
	if !classEvidence {
		t.Fatalf("exact chained class-slot lineage missing: %#v", graph.Evidence)
	}
}

func TestArm64FrameReceiverOverwriteInvalidatesExactLifecycle(t *testing.T) {
	for _, overwrite := range []uint32{
		0xf81f03a1, // STUR x1, [x29, #-16]
		0xb81fc3a1, // STUR w1, [x29, #-4] may overlap an unknown frame slot
	} {
		graph, _, _ := arm64ReceiverSpillControl(t, []uint32{overwrite})
		for _, operation := range graph.Operations {
			if operation.Support == behavior.SupportCorroborated || operation.Qualifiers["receiver_identity"] == "exact-linear-object" || operation.RequiredResource().Value != "" {
				t.Fatalf("frame overwrite %#08x was promoted: %#v", overwrite, graph.Operations)
			}
		}
	}
}

func arm64ReceiverSpillControl(t *testing.T, afterStore []uint32) (behavior.Graph, int, bool) {
	t.Helper()
	const (
		textVA    = uint64(0x100000000)
		classSlot = uint64(0x100004000)
		cfObject  = uint64(0x100005000)
		cfBacking = uint64(0x100006000)
	)
	path := "/usr/bin/true"
	object := make([]byte, machOCFString64RecordSize)
	binary.LittleEndian.PutUint64(object[16:24], cfBacking)
	binary.LittleEndian.PutUint64(object[24:32], uint64(len(path)))
	instructions := []uint32{
		encodeTestADRP(8, textVA, classSlot),
		encodeTestLDRXUnsigned(0, 8, 0),
		encodeTestBL(textVA+8, textVA+0x200), // _objc_alloc_init
		0xf94003e1,                           // LDR x1, [sp]
		0xd10043a8,                           // SUB x8, x29, #16
		0xf90007e8,                           // STR x8, [sp, #8]
		0xf81f03a0,                           // STUR x0, [x29, #-16]
	}
	instructions = append(instructions, afterStore...)
	instructions = append(instructions, 0xf85f03a0) // LDUR x0, [x29, #-16]
	instructions = append(instructions, encodeTestADRP(2, textVA+uint64(len(instructions))*4, cfObject))
	instructions = append(instructions, encodeTestADDImmediate(2, 2, cfObject&0xfff))
	instructions = append(instructions, encodeTestBL(textVA+uint64(len(instructions))*4, textVA+0x300)) // setLaunchPath:
	instructions = append(instructions, 0xf85f03a0)                                                     // LDUR x0, [x29, #-16]
	instructions = append(instructions, encodeTestBL(textVA+uint64(len(instructions))*4, textVA+0x400)) // launch
	data := make([]byte, len(instructions)*4)
	for index, instruction := range instructions {
		binary.LittleEndian.PutUint32(data[index*4:(index+1)*4], instruction)
	}
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{
		testMachOSection("__cfstring", cfObject, object),
		testMachOSection("__cstring", cfBacking, []byte(path)),
	}}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: textVA, Size: uint64(len(data))}}
	function := machoFunction{Name: "main", Start: textVA, End: textVA + uint64(len(data)), Reachable: true}
	graph := behavior.Graph{}
	lookup := newMachOCallLookup(&graph, artifact.Content{NodeID: "node", LogicalPath: "arm64-inert-control"}, "arm64")
	lookup.dyldBindings = map[uint64]machoDyldBinding{classSlot: {Name: "_OBJC_CLASS_$_NSTask", SlotVA: classSlot, Stream: "chained-fixups"}}

	count, truncated := extractArm64DirectCallsIndexed(lookup, file, text, data, []machoFunction{function}, map[uint64]string{textVA + 0x200: "_objc_alloc_init"}, map[uint64]string{textVA + 0x300: "setLaunchPath:", textVA + 0x400: "launch"}, len(data), 32)
	return graph, count, truncated
}

func TestX86StackArrayInstructionFormsRequireKnownFrameAddress(t *testing.T) {
	register, offset, size, ok := x86FrameRelativeLEA([]byte{0x48, 0x8d, 0x55, 0xc0})
	if !ok || register != 2 || offset != -64 || size != 4 {
		t.Fatalf("LEA -0x40(%%rbp), %%rdx = register %d offset %d size %d ok %v", register, offset, size, ok)
	}
	addresses := map[uint8]machoStackAddressValue{2: {Offset: -64}}
	for _, test := range []struct {
		data        []byte
		source      uint8
		offset      int64
		instruction string
	}{
		{data: []byte{0x48, 0x89, 0x02}, source: 0, offset: -64, instruction: "MOV rax, [rdx]"},
		{data: []byte{0x48, 0x89, 0x42, 0x08}, source: 0, offset: -56, instruction: "MOV rax, 8[rdx]"},
	} {
		source, offset, size, ok := x86RegisterStackStore(test.data, addresses)
		if !ok || source != test.source || offset != test.offset || size != len(test.data) {
			t.Fatalf("%s = source %d offset %d size %d ok %v", test.instruction, source, offset, size, ok)
		}
	}

	for _, malformed := range [][]byte{
		{0x8d, 0x55, 0xc0},             // no 64-bit REX prefix
		{0x48, 0x8d, 0x14, 0x25},       // SIB/indexed address
		{0x48, 0x8d, 0x15, 0, 0, 0, 0}, // RIP-relative, not frame-relative
	} {
		if _, _, _, ok := x86FrameRelativeLEA(malformed); ok {
			t.Fatalf("malformed LEA %x was accepted", malformed)
		}
	}
	for _, malformed := range [][]byte{
		{0x89, 0x02},                   // 32-bit store
		{0x48, 0x89, 0x00},             // unknown base register
		{0x48, 0x89, 0x04, 0x02},       // SIB/indexed destination
		{0x48, 0x89, 0xc2},             // register destination
		{0x48, 0x89, 0x42, 0x08, 0x90}, // trailing bytes
	} {
		if _, _, _, ok := x86RegisterStackStore(malformed, addresses); ok {
			t.Fatalf("malformed stack store %x was accepted", malformed)
		}
	}
}

func TestObjCStringArrayFromStackRequiresCompleteExactSlots(t *testing.T) {
	slots := map[int64]machoObjCStackSlot{
		-64: {String: machoCallStringArgument{Value: "--version", ReferenceVA: 0x1000, ReferenceOff: 16}},
		-56: {String: machoCallStringArgument{Value: "fixture", ReferenceVA: 0x1008, ReferenceOff: 24}},
	}
	array, ok := objcStringArrayFromStack(machoStackAddressValue{Offset: -64}, 2, slots, 0x1100, 32)
	if !ok || array.Representation != "stack-cfstring-pointer-array" || len(array.Elements) != 2 || array.Elements[1].String.Value != "fixture" {
		t.Fatalf("complete stack array = %#v ok %v", array, ok)
	}
	delete(slots, -56)
	if array, ok := objcStringArrayFromStack(machoStackAddressValue{Offset: -64}, 2, slots, 0x1100, 32); ok {
		t.Fatalf("incomplete stack array produced %#v", array)
	}
	if array, ok := objcStringArrayFromStack(machoStackAddressValue{Offset: -64}, maxMachOObjCArrayEntries+1, slots, 0x1100, 32); ok {
		t.Fatalf("over-budget stack array produced %#v", array)
	}
}

func TestSwiftImportedObjCAllocatingInitializerIsStrict(t *testing.T) {
	for _, test := range []struct {
		symbol string
		class  string
	}{
		{symbol: "$sSo6NSTaskCABycfC", class: "NSTask"},
		{symbol: "$sSo8NSObjectCABycfC", class: "NSObject"},
		{symbol: "$SSo12NSFileHandleCABycfC", class: "NSFileHandle"},
	} {
		class, ok := swiftImportedObjCAllocatingInit(test.symbol)
		if !ok || class != test.class {
			t.Fatalf("swiftImportedObjCAllocatingInit(%q) = %q, %v", test.symbol, class, ok)
		}
	}
	for _, symbol := range []string{
		"$sSo6NSTaskC",            // class identity, not allocating init
		"$sSo6NSTaskCACycfc",      // different initializer shape
		"$sSo7NSTaskCABycfC",      // wrong length
		"$sSo06NSTaskCABycfC",     // non-canonical length
		"$sSo6NS-askCABycfC",      // invalid class identifier
		"$s3GUI6NSTaskCABycfC",    // application module, not imported Objective-C
		"$sSo999999NSTaskCABycfC", // length budget
		strings.Repeat("x", maxMachOSymbolDemangleInputBytes+1),
	} {
		if class, ok := swiftImportedObjCAllocatingInit(symbol); ok {
			t.Fatalf("malformed or non-constructor symbol %q produced class %q", symbol, class)
		}
	}
}

func TestKnownNSTaskReceiverPromotesOnlyExactLifecycle(t *testing.T) {
	graph, lookup, functions, receiver, ids := testObjCReceiverFlow(t)
	receiver.Class = "NSTask"
	path := machoCallContext{ObjCReceiver: receiver}
	path.StringArguments[2] = machoCallStringArgument{Value: "/usr/bin/true", EvidenceIDs: []string{ids[1]}, Representation: "static-cfstring"}
	addObjCMessageCallIndexed(lookup, functions, "setLaunchPath:", "objc-msgsend-stub", 0x1010, path)
	addObjCMessageCallIndexed(lookup, functions, "launch", "objc-msgsend-stub", 0x1020, machoCallContext{ObjCReceiver: receiver})

	if len(graph.Operations) != 1 {
		t.Fatalf("known NSTask lifecycle operations = %#v", graph.Operations)
	}
	operation := graph.Operations[0]
	if operation.Support != behavior.SupportCorroborated || operation.Qualifiers["receiver_class"] != "NSTask" || operation.RequiredResource().Value != "/usr/bin/true" {
		t.Fatalf("known NSTask lifecycle operation = %#v", operation)
	}

	graph, lookup, functions, receiver, ids = testObjCReceiverFlow(t)
	receiver.Class = "NSFileHandle"
	path = machoCallContext{ObjCReceiver: receiver}
	path.StringArguments[2] = machoCallStringArgument{Value: "/usr/bin/true", EvidenceIDs: []string{ids[1]}, Representation: "static-cfstring"}
	addObjCMessageCallIndexed(lookup, functions, "setLaunchPath:", "objc-msgsend-stub", 0x1010, path)
	addObjCMessageCallIndexed(lookup, functions, "launch", "objc-msgsend-stub", 0x1020, machoCallContext{ObjCReceiver: receiver})
	if len(graph.Operations) != 1 || graph.Operations[0].Support != behavior.SupportHeuristic {
		t.Fatalf("non-NSTask receiver was promoted: %#v", graph.Operations)
	}
}

func TestX86RegisterLoadedImportedPointerFeedsObjectiveCMessageSemantics(t *testing.T) {
	const (
		selectorRefVA = uint64(0x2000)
		selectorVA    = uint64(0x3000)
		objectVA      = uint64(0x4000)
		backingVA     = uint64(0x5000)
		pointerVA     = uint64(0x6000)
	)
	selector := "dataWithContentsOfFile:"
	path := "~/.ssh/id_rsa"
	selectorRef := make([]byte, 8)
	binary.LittleEndian.PutUint64(selectorRef, selectorVA)
	object := make([]byte, machOCFString64RecordSize)
	binary.LittleEndian.PutUint64(object[16:24], backingVA)
	binary.LittleEndian.PutUint64(object[24:32], uint64(len(path)))
	file := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian,
		Loads:    []macho.Load{testMachOIndirectSectionLoad("__got", "__DATA_CONST", pointerVA, 8, 0x6, 0, 0)},
		Symtab:   &macho.Symtab{Syms: []macho.Symbol{{Name: "_objc_msgSend", Type: 0x01}}},
		Dysymtab: &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Iundefsym: 0, Nundefsym: 1}, IndirectSyms: []uint32{0}},
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", selectorRefVA, selectorRef),
			testMachOSection("__objc_methname", selectorVA, append([]byte(selector), 0)),
			testMachOSection("__cfstring", objectVA, object),
			testMachOSection("__cstring", backingVA, []byte(path)),
		},
	}
	selectorMove := encodeTestX86RIPRelativeMOVToReg(6, 0x1000, selectorRefVA)
	argumentMoveVA := 0x1000 + uint64(len(selectorMove))
	argumentMove := encodeTestX86RIPRelativeLEAToReg(2, argumentMoveVA, objectVA)
	importMoveVA := argumentMoveVA + uint64(len(argumentMove))
	importMove := encodeTestX86RIPRelativeMOVToReg(15, importMoveVA, pointerVA)
	call := []byte{0x41, 0xff, 0xd7}
	base := append(append(append([]byte{}, selectorMove...), argumentMove...), importMove...)

	for _, test := range []struct {
		name       string
		between    []byte
		wantCalled bool
	}{
		{name: "fresh typed pointer", wantCalled: true},
		{name: "overwritten register", between: []byte{0x49, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := append(append(append([]byte{}, base...), test.between...), call...)
			text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}
			var graph behavior.Graph
			count := extractX86DirectCalls(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "control"}, file, text, data, []machoFunction{{Name: "run", Start: 0x1000, End: 0x1100, Reachable: true}}, nil, nil, "x86_64")
			if test.wantCalled {
				if count != 1 || len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileRead || graph.Operations[0].RequiredResource().Value != path {
					t.Fatalf("register-loaded import result = count %d operations %#v", count, graph.Operations)
				}
			} else if count != 0 || len(graph.Operations) != 0 {
				t.Fatalf("overwritten imported pointer remained callable: count %d operations %#v", count, graph.Operations)
			}
		})
	}
}

func TestExactObjCReceiverFlowBindsNSTaskPathAndStaticArguments(t *testing.T) {
	graph, lookup, functions, receiver, ids := testObjCReceiverFlow(t)
	path := machoCallContext{ObjCReceiver: receiver}
	path.StringArguments[2] = machoCallStringArgument{Value: "/usr/bin/true", EvidenceIDs: []string{ids[1]}, Representation: "static-cfstring"}
	addObjCMessageCallIndexed(lookup, functions, "setLaunchPath:", "objc-msgsend-stub", 0x1010, path)

	arguments := machoCallContext{ObjCReceiver: receiver}
	arguments.ObjCStringArrays[2] = machoObjCStringArray{
		Representation: "static-nsconstantarray", EvidenceIDs: []string{ids[2], ids[3]},
		Elements: []machoObjCStringArrayElement{
			{String: machoCallStringArgument{Value: "--version", EvidenceIDs: []string{ids[2]}}},
			{String: machoCallStringArgument{Value: "fixture-value", EvidenceIDs: []string{ids[3]}}},
		},
	}
	addObjCMessageCallIndexed(lookup, functions, "setArguments:", "objc-msgsend-stub", 0x1020, arguments)
	addObjCMessageCallIndexed(lookup, functions, "launch", "objc-msgsend-stub", 0x1030, machoCallContext{ObjCReceiver: receiver})

	if len(graph.Operations) != 1 {
		t.Fatalf("exact receiver lifecycle operations = %#v", graph.Operations)
	}
	operation := graph.Operations[0]
	if operation.Support != behavior.SupportHeuristic || operation.RequiredResource().Value != "/usr/bin/true" || operation.Qualifiers["receiver_identity"] != "exact-linear-object" || operation.Qualifiers["receiver_class"] != "unresolved" || operation.Qualifiers["argument_binding"] != "exact-static-nsarray" {
		t.Fatalf("exact receiver operation = %#v", operation)
	}
	if binding, ok := operation.FirstBinding(behavior.ResourceRoleArguments); !ok || binding.Resource.Value != `["--version","fixture-value"]` {
		t.Fatalf("static Objective-C argv binding = %#v, %v", binding, ok)
	}
	if binding, ok := operation.FirstBinding(behavior.ResourceRoleExecutable); !ok || !slices.Equal(binding.EvidenceIDs, []string{ids[1]}) {
		t.Fatalf("executable binding lineage = %#v, %v", binding, ok)
	}
}

func TestObjCReceiverFlowRejectsDifferentReceiverAndInvalidatesUnknownMessage(t *testing.T) {
	for _, test := range []struct {
		name      string
		interpose bool
		different bool
	}{
		{name: "different receiver", different: true},
		{name: "unknown message invalidates", interpose: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph, lookup, functions, receiver, ids := testObjCReceiverFlow(t)
			path := machoCallContext{ObjCReceiver: receiver}
			path.StringArguments[2] = machoCallStringArgument{Value: "/usr/bin/true", EvidenceIDs: []string{ids[1]}, Representation: "static-cfstring"}
			addObjCMessageCallIndexed(lookup, functions, "setLaunchPath:", "objc-msgsend-stub", 0x1010, path)
			if test.interpose {
				addObjCMessageCallIndexed(lookup, functions, "replaceConfiguration:", "objc-msgsend-stub", 0x1020, machoCallContext{ObjCReceiver: receiver})
			}
			launchReceiver := receiver
			if test.different {
				launchReceiver.Identity = "run@different"
			}
			addObjCMessageCallIndexed(lookup, functions, "launch", "objc-msgsend-stub", 0x1030, machoCallContext{ObjCReceiver: launchReceiver})

			if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Value != "" || graph.Operations[0].Qualifiers["semantic_basis"] != "ordered-selector-set" || graph.Operations[0].Qualifiers["receiver_identity"] != "unresolved" {
				t.Fatalf("unsafe receiver correlation was promoted: %#v", graph.Operations)
			}
		})
	}
}

func testObjCStringArrayFixture(t *testing.T, budget uint64) (*macho.File, *machoCFStringReader) {
	t.Helper()
	arrayObject := make([]byte, machOObjCArray64RecordSize)
	binary.LittleEndian.PutUint64(arrayObject[8:16], 2)
	binary.LittleEndian.PutUint64(arrayObject[16:24], 0x3000)
	arrayData := make([]byte, 16)
	binary.LittleEndian.PutUint64(arrayData[0:8], 0x4000)
	binary.LittleEndian.PutUint64(arrayData[8:16], 0x5000)
	first := make([]byte, machOCFString64RecordSize)
	binary.LittleEndian.PutUint64(first[16:24], 0x6000)
	binary.LittleEndian.PutUint64(first[24:32], uint64(len("--version")))
	second := make([]byte, machOCFString64RecordSize)
	binary.LittleEndian.PutUint64(second[16:24], 0x7000)
	binary.LittleEndian.PutUint64(second[24:32], uint64(len("fixture-value")))
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{
		testMachOSection("__objc_arrayobj", 0x2000, arrayObject),
		testMachOSection("__objc_arraydata", 0x3000, arrayData),
		testMachOSection("__cfstring", 0x4000, first),
		testMachOSection("__cfstring", 0x5000, second),
		testMachOSection("__cstring", 0x6000, []byte("--version")),
		testMachOSection("__cstring", 0x7000, []byte("fixture-value")),
	}}
	return file, newMachOCFStringReader(newMachOSectionIndex(file), budget)
}

func testObjCReceiverFlow(t *testing.T) (*behavior.Graph, *machoCallLookup, []machoFunction, machoObjCReceiverValue, []string) {
	t.Helper()
	graph := &behavior.Graph{}
	content := artifact.Content{NodeID: "node-1", LogicalPath: "receiver-control"}
	function := machoFunction{Name: "run", Start: 0x1000, End: 0x1100, Reachable: true}
	scopeID := graph.AddScope(behavior.Scope{NodeID: content.NodeID, Kind: "function", Function: function.Name, Architecture: "arm64"})
	ids := make([]string, 4)
	for index := range ids {
		ids[index] = graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, ScopeID: scopeID, Logical: content.LogicalPath, VA: uint64(0x1000 + index*4), Function: function.Name, Arch: "arm64", Method: "test", Kind: "inert-control", Value: "evidence"})
	}
	receiver := machoObjCReceiverValue{Identity: "run@1000", OriginEvidenceIDs: []string{ids[0]}}
	return graph, newMachOCallLookup(graph, content, "arm64"), []machoFunction{function}, receiver, ids
}
