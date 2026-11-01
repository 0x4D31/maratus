package extract

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestFunctionStartsRejectOverflowingULEB128(t *testing.T) {
	for _, first := range []byte{0x80, 0x81} {
		data := []byte{first, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02, 0}
		starts, truncated := decodeFunctionStartsBounded(data, 0, 0, 100, len(data), 10, 10)
		if len(starts) != 0 || !truncated {
			t.Fatalf("overflowing delta produced starts %v, truncated %v", starts, truncated)
		}
	}
	data := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}
	if value, n, ok := readULEB128(data); !ok || value != ^uint64(0) || n != len(data) {
		t.Fatalf("valid uint64 maximum = %d, %d, %v", value, n, ok)
	}
}

func TestArm64AliasedAndOverlappingStoresInvalidateReceiverSpills(t *testing.T) {
	for _, overwrite := range []uint32{
		0xf90003e1, // STR x1, [sp] may alias the tracked x29-relative slot
		0xa90007e1, // STP x1, x1, [sp] may alias the same slot
		0xf81f43a1, // STUR x1, [x29, #-12] overlaps [-16, -8)
	} {
		t.Run(fmt.Sprintf("%08x", overwrite), func(t *testing.T) {
			graph, _, _ := arm64ReceiverSpillControl(t, []uint32{overwrite})
			for _, operation := range graph.Operations {
				if operation.Support == behavior.SupportCorroborated || operation.Qualifiers["receiver_identity"] == "exact-linear-object" || operation.RequiredResource().Value != "" {
					t.Fatalf("overwritten receiver retained exact provenance: %#v", operation)
				}
			}
		})
	}
}

func TestArm64OverwrittenStackArrayDoesNotBindStaleArguments(t *testing.T) {
	for _, test := range []struct {
		name      string
		overwrite []uint32
		wantBound bool
	}{
		{name: "unchanged pointer", wantBound: true},
		{name: "zero register", overwrite: []uint32{0xf90003ff}},              // STR xzr, [sp]
		{name: "partial zero store", overwrite: []uint32{0xb90003ff}},         // STR wzr, [sp]
		{name: "frame alias", overwrite: []uint32{0xf81f03a9}},                // STUR x9, [x29, #-16]
		{name: "register alias", overwrite: []uint32{0x910003e9, 0xf900013f}}, // ADD x9, sp, #0; STR xzr, [x9]
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := arm64StackArrayOverwriteControl(t, test.overwrite)
			found := false
			for _, operation := range graph.Operations {
				if operation.Kind != behavior.OperationProcessExecute {
					continue
				}
				found = true
				binding, bound := operation.FirstBinding(behavior.ResourceRoleArguments)
				if bound != test.wantBound || bound && binding.Resource.Value != `["--version"]` {
					t.Fatalf("argument binding = %#v, bound %v, want %v", binding, bound, test.wantBound)
				}
			}
			if !found {
				t.Fatalf("process operation missing: %#v", graph.Operations)
			}
		})
	}
}

func arm64StackArrayOverwriteControl(t *testing.T, overwrite []uint32) behavior.Graph {
	t.Helper()
	const textVA = uint64(0x1000)
	file, _ := testObjCStringArrayFixture(t, 1<<20)
	path := []byte("/usr/bin/true")
	object := make([]byte, machOCFString64RecordSize)
	binary.LittleEndian.PutUint64(object[16:24], 0x9000)
	binary.LittleEndian.PutUint64(object[24:32], uint64(len(path)))
	file.Sections = append(file.Sections, testMachOSection("__cfstring", 0x8000, object), testMachOSection("__cstring", 0x9000, path))
	var instructions []uint32
	emitCall := func(target uint64) {
		instructions = append(instructions, encodeTestBL(textVA+uint64(len(instructions))*4, target))
	}
	emitPointer := func(register uint32, target uint64) {
		instructions = append(instructions, encodeTestADRP(register, textVA+uint64(len(instructions))*4, target), encodeTestADDImmediate(register, register, target&0xfff))
	}
	emitCall(0xa000)                                // objc_alloc_init
	instructions = append(instructions, 0xaa0003f3) // MOV x19, x0
	emitPointer(2, 0x8000)
	instructions = append(instructions, 0xaa1303e0) // MOV x0, x19
	emitCall(0xa100)                                // setLaunchPath:
	emitPointer(8, 0x4000)                          // the fixture's --version CFString
	instructions = append(instructions, 0xf90003e8) // STR x8, [sp]
	instructions = append(instructions, overwrite...)
	instructions = append(instructions, 0x910003e2, 0xd2800023) // ADD x2, sp, #0; MOV x3, #1
	emitCall(0xa200)                                            // arrayWithObjects:count:
	instructions = append(instructions, 0xaa0003e2, 0xaa1303e0) // MOV x2, x0; MOV x0, x19
	emitCall(0xa300)                                            // setArguments:
	instructions = append(instructions, 0xaa1303e0)             // MOV x0, x19
	emitCall(0xa400)                                            // launch
	data := make([]byte, len(instructions)*4)
	for i, instruction := range instructions {
		binary.LittleEndian.PutUint32(data[i*4:], instruction)
	}
	text := testMachOSection("__text", textVA, data)
	file.Sections = append([]*macho.Section{text}, file.Sections...)
	var graph behavior.Graph
	lookup := newMachOCallLookup(&graph, artifact.Content{NodeID: "node", LogicalPath: "inert-stack-array"}, "arm64")
	_, truncated := extractArm64DirectCallsIndexed(lookup, file, text, data,
		[]machoFunction{{Name: "main", Start: textVA, End: textVA + uint64(len(data)), Reachable: true}},
		map[uint64]string{0xa000: "_objc_alloc_init"},
		map[uint64]string{0xa100: "setLaunchPath:", 0xa200: "arrayWithObjects:count:", 0xa300: "setArguments:", 0xa400: "launch"}, len(data), 32)
	if truncated {
		t.Fatal("inert control was truncated")
	}
	return graph
}

func TestNativeExecvPReadsThirdArgumentAcrossArchitectures(t *testing.T) {
	for _, architecture := range []string{"x86_64", "arm64"} {
		for _, argvIndex := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/argument-%d", architecture, argvIndex), func(t *testing.T) {
				const textVA = uint64(0x1000)
				const arrayVA = uint64(0x2000)
				const stubVA = uint64(0x1100)
				file, _ := staticArgvMachOFixture(t, true)
				data := make([]byte, 12)
				if architecture == "x86_64" {
					modrm := byte(0x35) // LEA rsi, [rip+disp32]
					if argvIndex == 2 {
						modrm = 0x15 // LEA rdx, [rip+disp32]
					}
					copy(data, []byte{0x48, 0x8d, modrm})
					binary.LittleEndian.PutUint32(data[3:7], uint32(arrayVA-textVA-7))
					data[7] = 0xe8
					binary.LittleEndian.PutUint32(data[8:12], uint32(stubVA-textVA-12))
				} else {
					register := uint32(argvIndex)
					binary.LittleEndian.PutUint32(data[:4], encodeTestADRP(register, textVA, arrayVA))
					binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(register, register, arrayVA&0xfff))
					binary.LittleEndian.PutUint32(data[8:12], encodeTestBL(textVA+8, stubVA))
				}
				text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: textVA, Size: uint64(len(data)), Offset: 0x100}}
				var graph behavior.Graph
				content := artifact.Content{NodeID: "node", LogicalPath: "inert-execvP"}
				functions := []machoFunction{{Name: "main", Start: textVA, End: textVA + uint64(len(data))}}
				imports := map[uint64]string{stubVA: "_execvP"}
				if architecture == "x86_64" {
					extractX86DirectCalls(&graph, content, file, text, data, functions, imports, nil, architecture)
				} else {
					extractArm64DirectCalls(&graph, content, file, text, data, functions, imports, nil, architecture)
				}
				if len(graph.Operations) != 1 {
					t.Fatalf("operations = %#v", graph.Operations)
				}
				binding, bound := graph.Operations[0].FirstBinding(behavior.ResourceRoleArguments)
				if bound != (argvIndex == 2) || bound && binding.Resource.Value != `["/usr/bin/id","--version"]` {
					t.Fatalf("argument binding = %#v, bound %v", binding, bound)
				}
			})
		}
	}
}
