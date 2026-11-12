package extract

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestReadMachOStaticArgvIndexedRequiresExactTerminatedPointerArray(t *testing.T) {
	file, index := staticArgvMachOFixture(t, true)
	arguments, ok := readMachOStaticArgvIndexed(file, index, 0x2000)
	if !ok || len(arguments.Arguments) != 2 {
		t.Fatalf("argv = %#v ok=%v", arguments, ok)
	}
	if arguments.Arguments[0].Value != "/usr/bin/id" || arguments.Arguments[1].Value != "--version" {
		t.Fatalf("argv values = %#v", arguments)
	}
	if arguments.Arguments[1].SlotOffset != 0x208 || arguments.Arguments[1].LiteralOffset != 0x30c || arguments.TerminatorVA != 0x2010 || arguments.TerminatorOffset != 0x210 {
		t.Fatalf("argv lineage = %#v", arguments)
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

func TestArgvLiteralRequiresAnUnambiguousBoundedNULTerminator(t *testing.T) {
	for _, tt := range []struct {
		name, data, value string
		want              bool
	}{
		{"ordinary", "inert\x00tail", "inert", true},
		{"empty", "\x00", "", true},
		{"unterminated section end", "inert", "", false},
		{"nonprintable", "\x01\x00", "", false},
		{"last bounded byte", strings.Repeat("a", 4095) + "\x00", strings.Repeat("a", 4095), true},
		{"past bound", strings.Repeat("a", 4096) + "\x00", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			section := &macho.Section{SectionHeader: macho.SectionHeader{Seg: "__TEXT", Name: "__cstring", Addr: 0x3000, Size: uint64(len(tt.data)), Offset: 0x300}, ReaderAt: strings.NewReader(tt.data)}
			index := newMachOSectionIndex(&macho.File{Sections: []*macho.Section{section}})
			value, va, offset, ok := readMachOArgvLiteral(index, 0x3000)
			if ok != tt.want || ok && (value != tt.value || va != 0x3000 || offset != 0x300) {
				t.Fatalf("literal=%q VA=%x offset=%x ok=%v", value, va, offset, ok)
			}
			_, _, _, callOK := cstringAtTargetLocationIndexed(&macho.File{}, index, 0x3000, false)
			if callOK != (tt.want && tt.value != "") {
				t.Fatal("an empty or unterminated literal became a concrete call operand")
			}
		})
	}
	sections := []*macho.Section{}
	for _, addr := range []uint64{0x3000, 0x4000} {
		sections = append(sections, &macho.Section{SectionHeader: macho.SectionHeader{Seg: "__TEXT", Name: "__cstring", Addr: addr, Size: 2}, ReaderAt: strings.NewReader("a\x00")})
	}
	index := newMachOSectionIndex(&macho.File{Sections: sections})
	index.imageBase = 0x1000
	if _, _, _, ok := readMachOArgvLiteral(index, 0x3000); ok {
		t.Fatal("two valid pointer interpretations were accepted as one literal")
	}
}

func TestNativeArgvPreservesEmptyArgumentAndRejectsUnterminatedLiteral(t *testing.T) {
	for _, data := range []string{"/usr/bin/id\x00\x00", "/usr/bin/id\x00tail"} {
		file, _ := staticArgvMachOFixture(t, true)
		file.Sections[1].Size = uint64(len(data))
		file.Sections[1].ReaderAt = strings.NewReader(data)
		vector, ok := readMachOStaticArgvIndexed(file, newMachOSectionIndex(file), 0x2000)
		if strings.HasSuffix(data, "tail") {
			if ok {
				t.Fatal("section boundary was treated as a C-string terminator")
			}
			continue
		}
		if !ok || len(vector.Arguments) != 2 || vector.Arguments[1].Value != "" {
			t.Fatalf("empty argument lost: %#v", vector)
		}
		var graph behavior.Graph
		lookup := newMachOCallLookup(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "fixture"}, "arm64")
		op := behavior.ModeledOperation{SubjectNodeID: "node-1"}
		if !bindMachOStaticArgv(lookup, &op, vector) {
			t.Fatal("complete argv was not bound")
		}
		binding, found := op.FirstBinding(behavior.ResourceRoleArguments)
		if !found || binding.Resource.Value != `["/usr/bin/id",""]` {
			t.Fatalf("empty argument changed: %#v", binding)
		}
		if last := graph.Evidence[len(graph.Evidence)-1]; last.Kind != "argv-null-slot" || last.VA != vector.TerminatorVA || last.Offset != int64(vector.TerminatorOffset) {
			t.Fatalf("vector terminator proof lost: %#v", last)
		}
	}
}

func TestNativeArgvIncompleteEvidenceCannotClassifyArguments(t *testing.T) {
	for _, limit := range []int{0, 2, 5} {
		file, index := staticArgvMachOFixture(t, true)
		vector, ok := readMachOStaticArgvIndexed(file, index, 0x2000)
		if !ok {
			t.Fatal("fixture was not read")
		}
		vector.Arguments[1].Value = "--dangerously-skip-permissions"
		graph := behavior.Graph{EvidenceLimit: limit}
		content := artifact.Content{NodeID: "node-1", LogicalPath: "fixture"}
		call := graph.AddEvidence(behavior.Evidence{NodeID: "node-1", Method: "test", Kind: "call", Value: "execve"})
		lookup := newMachOCallLookup(&graph, content, "arm64")
		addOperationFromCalledImportedSymbolWithContextIndexed(lookup, "_execve", call, machoFunction{Name: "main"}, machoCallContext{
			ArgumentVector:  vector,
			StringArguments: [6]machoCallStringArgument{{Value: "/usr/local/bin/claude", EvidenceIDs: []string{call}}},
		})
		if len(graph.Operations) != 1 {
			t.Fatalf("neutral operation was lost: %#v", graph.Operations)
		}
		op := graph.Operations[0]
		_, bound := op.FirstBinding(behavior.ResourceRoleArguments)
		if bound != (limit == 0) || (op.Qualifiers["agent_profile"] != "") != bound {
			t.Fatalf("limit=%d: incomplete argv classified arguments: %#v", limit, op)
		}
	}
}

func TestNativeArgvEncodedSizeCannotClassifyUnretainedArguments(t *testing.T) {
	file, index := staticArgvMachOFixture(t, true)
	vector, ok := readMachOStaticArgvIndexed(file, index, 0x2000)
	if !ok {
		t.Fatal("fixture was not read")
	}
	vector.Arguments[1].Value = "--dangerously-skip-permissions"
	for i := 0; i < 2; i++ {
		vector.Arguments = append(vector.Arguments, machoStaticArgument{Value: strings.Repeat(`"`, 4090)})
	}
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "fixture"}
	call := graph.AddEvidence(behavior.Evidence{NodeID: "node-1", Method: "test", Kind: "call", Value: "execve"})
	lookup := newMachOCallLookup(&graph, content, "arm64")
	addOperationFromCalledImportedSymbolWithContextIndexed(lookup, "_execve", call, machoFunction{Name: "main"}, machoCallContext{
		ArgumentVector:  vector,
		StringArguments: [6]machoCallStringArgument{{Value: "/usr/local/bin/claude", EvidenceIDs: []string{call}}},
	})
	if len(graph.Operations) != 1 {
		t.Fatalf("neutral call was lost: %#v", graph.Operations)
	}
	op := graph.Operations[0]
	if _, bound := op.FirstBinding(behavior.ResourceRoleArguments); bound || op.Qualifiers["agent_profile"] != "" {
		t.Fatalf("unretained argv affected semantics: %#v", op)
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
	if !ok || binding.Resource.Kind != behavior.ResourceCommand || binding.Resource.Value != `["/usr/bin/id","--version"]` || len(binding.EvidenceIDs) != 5 {
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

func TestArm64StaticArgvDoesNotReuseImageBytesAfterAliasStore(t *testing.T) {
	textVA := uint64(0x100000000)
	arrayVA := uint64(0x100010000)
	stringVA := uint64(0x100020000)
	stubVA := uint64(0x100000100)
	file, _ := staticArgvMachOFixtureAt(t, true, arrayVA, stringVA)
	words := []uint32{
		encodeTestADRP(1, textVA, arrayVA),
		encodeTestADDImmediate(1, 1, arrayVA&0xfff),
		0xf900003f, // str xzr, [x1]: overwrites argv[0]
		encodeTestBL(textVA+12, stubVA),
	}
	data := make([]byte, len(words)*4)
	for index, word := range words {
		binary.LittleEndian.PutUint32(data[index*4:], word)
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Seg: "__TEXT", Name: "__text", Addr: textVA, Size: uint64(len(data)), Offset: 0x100}, ReaderAt: bytes.NewReader(data)}
	file.Sections = append([]*macho.Section{text}, file.Sections...)
	var graph behavior.Graph
	extractArm64DirectCalls(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "fixture"}, file, text, data,
		[]machoFunction{{Name: "main", Start: textVA, End: textVA + uint64(len(data))}}, map[uint64]string{stubVA: "_execve"}, nil, "arm64")
	if len(graph.Operations) != 1 {
		t.Fatalf("neutral execve call was lost: %#v", graph.Operations)
	}
	if binding, found := graph.Operations[0].FirstBinding(behavior.ResourceRoleArguments); found {
		t.Fatalf("overwritten image argv was retained: %#v", binding)
	}
}

func assertStaticArgvOperation(t *testing.T, count int, operations []behavior.ModeledOperation) {
	t.Helper()
	if count != 1 || len(operations) != 1 {
		t.Fatalf("call count=%d operations=%#v", count, operations)
	}
	binding, ok := operations[0].FirstBinding(behavior.ResourceRoleArguments)
	if !ok || binding.Resource.Value != `["/usr/bin/id","--version"]` || len(binding.EvidenceIDs) != 5 {
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
