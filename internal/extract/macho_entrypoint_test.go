package extract

import (
	"debug/macho"
	"encoding/binary"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func unixThreadTestCommand(entry uint64) macho.LoadBytes {
	raw := make([]byte, 184)
	binary.LittleEndian.PutUint32(raw, 5)
	binary.LittleEndian.PutUint32(raw[4:], uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[8:], 4)
	binary.LittleEndian.PutUint32(raw[12:], 42)
	binary.LittleEndian.PutUint64(raw[144:], entry)
	return raw
}

func TestMachOUnixThreadEntryEvidenceUsesSliceOffset(t *testing.T) {
	segment := &macho.Segment{LoadBytes: make([]byte, 72), SegmentHeader: macho.SegmentHeader{Addr: 0x1000, Offset: 0x100, Filesz: 0x100, Memsz: 0x100, Prot: 5}}
	file := &macho.File{FileHeader: macho.FileHeader{Type: macho.TypeExec, Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian, Loads: []macho.Load{segment, unixThreadTestCommand(0x1010)}}
	var graph behavior.Graph
	retainMachOUnixThreadEntry(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "fixture", ByteOffsetBase: 4096}, file, "x86_64")
	if len(graph.Features) != 1 || len(graph.Evidence) != 1 {
		t.Fatalf("missing declared entry evidence: %#v", graph)
	}
	evidence := graph.Evidence[0]
	if !evidence.OffsetKnown || evidence.Offset != 4096+32+72+144 || evidence.Arch != "x86_64" || evidence.Value != "0x1010" {
		t.Fatalf("incorrect register location: %#v", evidence)
	}
	if len(graph.Operations) != 0 || len(graph.ExecutionRoots) != 0 {
		t.Fatal("entry metadata created execution behavior")
	}
}

func TestMachOUnixThreadEntrypoint(t *testing.T) {
	for _, name := range []string{"valid", "short", "count", "flavor", "size", "trailing", "cpu", "dylib", "duplicate", "mixed", "zerofill", "nonexecuting", "overlap", "overflow", "virtual-only"} {
		t.Run(name, func(t *testing.T) {
			command := unixThreadTestCommand(0x1010)
			segment := &macho.Segment{SegmentHeader: macho.SegmentHeader{Addr: 0x1000, Offset: 0x100, Filesz: 0x100, Memsz: 0x200, Prot: 5}}
			file := &macho.File{FileHeader: macho.FileHeader{Type: macho.TypeExec, Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
			switch name {
			case "short":
				command = command[:152]
			case "count":
				binary.LittleEndian.PutUint32(command[12:], 0xffffffff)
			case "flavor":
				binary.LittleEndian.PutUint32(command[8:], 1)
			case "size":
				binary.LittleEndian.PutUint32(command[4:], 152)
			case "trailing":
				command = append(command, make([]byte, 8)...)
			case "cpu":
				file.Cpu = macho.CpuArm64
			case "dylib":
				file.Type = macho.TypeDylib
			case "zerofill":
				binary.LittleEndian.PutUint64(command[144:], 0x1100)
			case "nonexecuting":
				segment.Prot = 1
			case "overflow":
				segment.Addr = ^uint64(0) - 8
			case "virtual-only":
				segment.Memsz = 8
			}
			file.Loads = []macho.Load{segment, command}
			switch name {
			case "duplicate":
				file.Loads = append(file.Loads, command)
			case "overlap":
				file.Loads = append(file.Loads, segment)
			case "mixed":
				main := make(macho.LoadBytes, 24)
				binary.LittleEndian.PutUint32(main, lcMain)
				binary.LittleEndian.PutUint32(main[4:], 24)
				file.Loads = append(file.Loads, main)
			}
			entry, ok := machoEntrypointVA(file)
			if ok != (name == "valid") || ok && entry != 0x1010 {
				t.Fatalf("entry=%#x supported=%v", entry, ok)
			}
			functions := []machoFunction{{Start: 0x1000, End: 0x1020}, {Start: 0x1020, End: 0x1040}}
			markMachOExecutionSeed(file, functions, machoExecutionSeedLocalEntry, nil, nil)
			if functions[0].Reachable != ok || functions[0].Entrypoint || functions[1].Reachable {
				t.Fatalf("local seed changed root ownership or unrelated function: %#v", functions)
			}
		})
	}
}
