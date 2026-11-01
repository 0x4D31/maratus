package extract

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestMachOChainedImportsRecoverSupportedFormatsAndExactOffsets(t *testing.T) {
	for _, format := range []uint32{1, 2, 3} {
		t.Run(fmt.Sprintf("format-%d", format), func(t *testing.T) {
			file, image, symbolOffset := chainedImportFixture(t, format, []string{"_posix_spawn", "_connect"})
			imports, present, detail := machoChainedImports(file, image, 1000)
			if !present || detail != "" || len(imports) != 2 {
				t.Fatalf("imports=%#v present=%v detail=%q", imports, present, detail)
			}
			if imports[0].name != "_posix_spawn" || imports[1].name != "_connect" {
				t.Fatalf("import names = %#v", imports)
			}
			if imports[0].nameOffset != int64(1000+64+symbolOffset) ||
				imports[1].nameOffset != imports[0].nameOffset+int64(len("_posix_spawn")+1) {
				t.Fatalf("import offsets = %#v, symbol table offset=%d", imports, symbolOffset)
			}
		})
	}
}

func TestMachOChainedImportsFailClosedOnMalformedAndUnsupportedPayloads(t *testing.T) {
	tests := map[string]func([]byte){
		"unsupported version": func(payload []byte) { binary.LittleEndian.PutUint32(payload[0:4], 1) },
		"unsupported format":  func(payload []byte) { binary.LittleEndian.PutUint32(payload[20:24], 99) },
		"compressed symbols":  func(payload []byte) { binary.LittleEndian.PutUint32(payload[24:28], 1) },
		"excess imports":      func(payload []byte) { binary.LittleEndian.PutUint32(payload[16:20], maxMachOChainedImports+1) },
		"bad imports offset":  func(payload []byte) { binary.LittleEndian.PutUint32(payload[8:12], uint32(len(payload))) },
		"bad symbols offset":  func(payload []byte) { binary.LittleEndian.PutUint32(payload[12:16], uint32(len(payload))) },
		"bad name offset": func(payload []byte) {
			binary.LittleEndian.PutUint32(payload[28:32], uint32(len(payload))<<9|1)
		},
		"unterminated name": func(payload []byte) { payload[len(payload)-1] = 'x' },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			file, image, _ := chainedImportFixture(t, 1, []string{"_connect"})
			payload := image[64:]
			mutate(payload)
			imports, present, detail := machoChainedImports(file, image, 0)
			if !present || detail == "" || len(imports) != 0 {
				t.Fatalf("malformed payload returned imports=%#v present=%v detail=%q", imports, present, detail)
			}
		})
	}
}

func TestMachOChainedImportsRejectOverlongName(t *testing.T) {
	file, image, _ := chainedImportFixture(t, 1, []string{strings.Repeat("a", maxMachOChainedImportNameLen+1)})
	imports, present, detail := machoChainedImports(file, image, 0)
	if !present || detail == "" || len(imports) != 0 {
		t.Fatalf("overlong name returned imports=%#v present=%v detail=%q", imports, present, detail)
	}
}

func TestMachOChainedImportsAbsentWithoutLoadCommand(t *testing.T) {
	imports, present, detail := machoChainedImports(&macho.File{ByteOrder: binary.LittleEndian}, nil, 0)
	if present || detail != "" || len(imports) != 0 {
		t.Fatalf("absent command returned imports=%#v present=%v detail=%q", imports, present, detail)
	}
}

func TestMachOChainedImportsPresentButEmptyIsExplicitlyMalformed(t *testing.T) {
	command := make([]byte, 16)
	binary.LittleEndian.PutUint32(command[0:4], lcDyldChainedFixups)
	binary.LittleEndian.PutUint32(command[4:8], 16)
	file := &macho.File{ByteOrder: binary.LittleEndian, Loads: []macho.Load{macho.LoadBytes(command)}}
	imports, present, detail := machoChainedImports(file, nil, 0)
	if !present || detail == "" || len(imports) != 0 {
		t.Fatalf("zero-sized command returned imports=%#v present=%v detail=%q", imports, present, detail)
	}
}

func TestExtractMachOChainedImportIsAnObservationNotACall(t *testing.T) {
	file, image, symbolOffset := chainedImportFixture(t, 1, []string{"_posix_spawn"})
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample", ByteOffsetBase: 1000}
	extractMachOFile(&graph, content, file, "arm64", image, artifact.Options{})

	foundImport := false
	foundObservation := false
	for _, feature := range graph.Features {
		switch feature.Key {
		case "macho.import":
			if feature.Value == "_posix_spawn" && feature.Support == behavior.SupportDirect && feature.Qualifiers["source"] == "dyld-chained-fixups" {
				foundImport = true
				if len(feature.EvidenceIDs) != 1 {
					t.Fatalf("chained import evidence = %#v", feature.EvidenceIDs)
				}
				evidence := evidenceByID(graph.Evidence, feature.EvidenceIDs[0])
				wantOffset := int64(1000 + 64 + symbolOffset)
				if evidence.Method != "macho-chained-fixups" || !evidence.OffsetKnown || evidence.Offset != wantOffset {
					t.Fatalf("chained import evidence = %#v, want exact offset %d", evidence, wantOffset)
				}
			}
		case "macho.security_api_import":
			if feature.Value == "posix_spawn" && feature.Support == behavior.SupportHeuristic {
				foundObservation = true
			}
		}
	}
	if !foundImport || !foundObservation {
		t.Fatalf("missing chained import facts: %#v", graph.Features)
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("an imported name must not become an observed call or operation: %#v", graph.Operations)
	}
}

func TestExtractMachOMalformedChainedImportsAddPartialCoverage(t *testing.T) {
	file, image, _ := chainedImportFixture(t, 1, []string{"_connect"})
	binary.LittleEndian.PutUint32(image[64:68], 1)
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	extractMachOFile(&graph, content, file, "arm64", image, artifact.Options{})
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "macho-chained-imports/arm64" && coverage.Status == "partial" && strings.Contains(coverage.Detail, "version 1") {
			return
		}
	}
	t.Fatalf("malformed chained imports did not produce explicit coverage: %#v", graph.Coverage)
}

func evidenceByID(items []behavior.Evidence, id string) behavior.Evidence {
	for _, item := range items {
		if item.ID == id {
			return item
		}
	}
	return behavior.Evidence{}
}

func chainedImportFixture(t *testing.T, format uint32, names []string) (*macho.File, []byte, int) {
	t.Helper()
	entrySize := 4
	switch format {
	case 1:
		entrySize = 4
	case 2:
		entrySize = 8
	case 3:
		entrySize = 16
	default:
		t.Fatalf("unsupported fixture format %d", format)
	}
	importsOffset := 28
	symbolsOffset := importsOffset + entrySize*len(names)
	payload := make([]byte, symbolsOffset)
	binary.LittleEndian.PutUint32(payload[8:12], uint32(importsOffset))
	binary.LittleEndian.PutUint32(payload[12:16], uint32(symbolsOffset))
	binary.LittleEndian.PutUint32(payload[16:20], uint32(len(names)))
	binary.LittleEndian.PutUint32(payload[20:24], format)
	nameOffset := 0
	for index, name := range names {
		entry := payload[importsOffset+index*entrySize : importsOffset+(index+1)*entrySize]
		switch format {
		case 1, 2:
			binary.LittleEndian.PutUint32(entry[0:4], uint32(nameOffset)<<9|1)
		case 3:
			binary.LittleEndian.PutUint64(entry[0:8], uint64(nameOffset)<<32|1)
		}
		payload = append(payload, []byte(name)...)
		payload = append(payload, 0)
		nameOffset += len(name) + 1
	}
	image := make([]byte, 64, 64+len(payload))
	image = append(image, payload...)
	command := make([]byte, 16)
	binary.LittleEndian.PutUint32(command[0:4], lcDyldChainedFixups)
	binary.LittleEndian.PutUint32(command[4:8], 16)
	binary.LittleEndian.PutUint32(command[8:12], 64)
	binary.LittleEndian.PutUint32(command[12:16], uint32(len(payload)))
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Loads:     []macho.Load{macho.LoadBytes(command)},
	}
	return file, image, symbolsOffset
}
