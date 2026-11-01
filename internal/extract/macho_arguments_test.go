package extract

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestReadMachOStaticArgvIndexedRequiresExactTerminatedPointerArray(t *testing.T) {
	file, index := staticArgvMachOFixture(t, true)
	arguments, ok := readMachOStaticArgvIndexed(file, index, 0x2000)
	if !ok || len(arguments) != 2 {
		t.Fatalf("argv = %#v ok=%v", arguments, ok)
	}
	if arguments[0].Value != "/usr/bin/id" || arguments[1].Value != "--version" {
		t.Fatalf("argv values = %#v", arguments)
	}
	if arguments[1].SlotOffset != 0x208 || arguments[1].LiteralOffset != 0x30c {
		t.Fatalf("argv lineage = %#v", arguments[1])
	}

	unterminated, unterminatedIndex := staticArgvMachOFixture(t, false)
	if values, ok := readMachOStaticArgvIndexed(unterminated, unterminatedIndex, 0x2000); ok || values != nil {
		t.Fatalf("unterminated argv = %#v ok=%v", values, ok)
	}
	if values, ok := readMachOStaticArgvIndexed(file, index, 0x3000); ok || values != nil {
		t.Fatalf("string bytes were accepted as argv = %#v ok=%v", values, ok)
	}
	if values, ok := readMachOStaticArgvIndexed(file, index, 0x2001); ok || values != nil {
		t.Fatalf("unaligned bytes were accepted as argv = %#v ok=%v", values, ok)
	}
}

func TestNativeExecOperationBindsExactStaticArgv(t *testing.T) {
	file, index := staticArgvMachOFixture(t, true)
	arguments, ok := readMachOStaticArgvIndexed(file, index, 0x2000)
	if !ok {
		t.Fatal("fixture argv was not recovered")
	}
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "fixture", Role: "executable"}
	callEvidence := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "test", Kind: "call", Value: "execve", Arch: "arm64"})
	lookup := newMachOCallLookup(&graph, content, "arm64")
	addOperationFromCalledImportedSymbolWithContextIndexed(lookup, "_execve", callEvidence, machoFunction{Name: "main.main", Metadata: "go-other"}, machoCallContext{ArgumentVector: arguments})
	if len(graph.Operations) != 1 {
		t.Fatalf("operations = %#v", graph.Operations)
	}
	operation := graph.Operations[0]
	binding, ok := operation.FirstBinding(behavior.ResourceRoleArguments)
	if !ok || binding.Resource.Kind != behavior.ResourceCommand || binding.Resource.Value != `["/usr/bin/id","--version"]` || len(binding.EvidenceIDs) != 4 {
		t.Fatalf("arguments binding = %#v", binding)
	}
	if operation.Qualifiers["argument_binding"] != "exact-static-argv" || operation.Qualifiers["function_origin"] != "go-other" {
		t.Fatalf("operation qualifiers = %#v", operation.Qualifiers)
	}
	evidenceByID := make(map[string]behavior.Evidence, len(graph.Evidence))
	for _, item := range graph.Evidence {
		evidenceByID[item.ID] = item
	}
	for _, evidenceID := range binding.EvidenceIDs {
		item := evidenceByID[evidenceID]
		if item.NodeID != operation.SubjectNodeID || item.ScopeID != operation.ScopeID || item.Function != operation.SourceFunction || item.Arch != operation.Architecture {
			t.Fatalf("binding evidence %s context = %#v; operation = %#v", evidenceID, item, operation)
		}
	}
}

func TestNativeDecodersBindStaticArgvAcrossArchitectures(t *testing.T) {
	t.Run("x86_64", func(t *testing.T) {
		file, _ := staticArgvMachOFixture(t, true)
		textVA := uint64(0x1000)
		arrayVA := uint64(0x2000)
		stubVA := uint64(0x1100)
		data := make([]byte, 12)
		copy(data[0:3], []byte{0x48, 0x8d, 0x35}) // lea rsi,[rip+disp32]
		binary.LittleEndian.PutUint32(data[3:7], uint32(int64(arrayVA)-int64(textVA+7)))
		data[7] = 0xe8
		binary.LittleEndian.PutUint32(data[8:12], uint32(int64(stubVA)-int64(textVA+12)))
		text := &macho.Section{SectionHeader: macho.SectionHeader{Seg: "__TEXT", Name: "__text", Addr: textVA, Size: uint64(len(data)), Offset: 0x100}, ReaderAt: bytes.NewReader(data)}
		file.Sections = append([]*macho.Section{text}, file.Sections...)
		var graph behavior.Graph
		count := extractX86DirectCalls(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "fixture"}, file, text, data,
			[]machoFunction{{Name: "main", Start: textVA, End: textVA + uint64(len(data))}}, map[uint64]string{stubVA: "_execve"}, nil, "x86_64")
		assertStaticArgvOperation(t, count, graph.Operations)
	})

	t.Run("arm64", func(t *testing.T) {
		textVA := uint64(0x100000000)
		arrayVA := uint64(0x100010000)
		stringVA := uint64(0x100020000)
		stubVA := uint64(0x100000100)
		file, _ := staticArgvMachOFixtureAt(t, true, arrayVA, stringVA)
		data := make([]byte, 12)
		binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(1, textVA, arrayVA))
		binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(1, 1, arrayVA&0xfff))
		binary.LittleEndian.PutUint32(data[8:12], encodeTestBL(textVA+8, stubVA))
		text := &macho.Section{SectionHeader: macho.SectionHeader{Seg: "__TEXT", Name: "__text", Addr: textVA, Size: uint64(len(data)), Offset: 0x100}, ReaderAt: bytes.NewReader(data)}
		file.Sections = append([]*macho.Section{text}, file.Sections...)
		var graph behavior.Graph
		count := extractArm64DirectCalls(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "fixture"}, file, text, data,
			[]machoFunction{{Name: "main", Start: textVA, End: textVA + uint64(len(data))}}, map[uint64]string{stubVA: "_execve"}, nil, "arm64")
		assertStaticArgvOperation(t, count, graph.Operations)
	})
}

func assertStaticArgvOperation(t *testing.T, count int, operations []behavior.ModeledOperation) {
	t.Helper()
	if count != 1 || len(operations) != 1 {
		t.Fatalf("call count=%d operations=%#v", count, operations)
	}
	binding, ok := operations[0].FirstBinding(behavior.ResourceRoleArguments)
	if !ok || binding.Resource.Value != `["/usr/bin/id","--version"]` || len(binding.EvidenceIDs) != 4 {
		t.Fatalf("static argv binding = %#v", binding)
	}
}

func staticArgvMachOFixture(t *testing.T, terminated bool) (*macho.File, *machoSectionIndex) {
	return staticArgvMachOFixtureAt(t, terminated, 0x2000, 0x3000)
}

func staticArgvMachOFixtureAt(t *testing.T, terminated bool, arrayVA, stringVA uint64) (*macho.File, *machoSectionIndex) {
	t.Helper()
	stringsData := []byte("/usr/bin/id\x00--version\x00")
	arrayEntries := maxMachOStaticArgvEntries + 1
	if terminated {
		arrayEntries = 3
	}
	arrayData := make([]byte, arrayEntries*8)
	binary.LittleEndian.PutUint64(arrayData[0:8], stringVA)
	binary.LittleEndian.PutUint64(arrayData[8:16], stringVA+0xc)
	if !terminated {
		for index := 2; index < arrayEntries; index++ {
			binary.LittleEndian.PutUint64(arrayData[index*8:index*8+8], stringVA)
		}
	}
	arraySection := &macho.Section{
		SectionHeader: macho.SectionHeader{Seg: "__DATA_CONST", Name: "__const", Addr: arrayVA, Size: uint64(len(arrayData)), Offset: 0x200},
		ReaderAt:      bytes.NewReader(arrayData),
	}
	stringSection := &macho.Section{
		SectionHeader: macho.SectionHeader{Seg: "__TEXT", Name: "__cstring", Addr: stringVA, Size: uint64(len(stringsData)), Offset: 0x300},
		ReaderAt:      bytes.NewReader(stringsData),
	}
	file := &macho.File{FileHeader: macho.FileHeader{Magic: macho.Magic64}, ByteOrder: binary.LittleEndian, Sections: []*macho.Section{arraySection, stringSection}}
	return file, newMachOSectionIndex(file)
}
