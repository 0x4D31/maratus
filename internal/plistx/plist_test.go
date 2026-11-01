package plistx

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"howett.net/plist"
)

func TestDecodeRejectsOversizedInputBeforeParsing(t *testing.T) {
	data := make([]byte, maxPlistBytes+1)
	if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("Decode() error = %v, want byte-limit error", err)
	}
}

func TestDecodeRejectsTooManyXMLValuesBeforeParsing(t *testing.T) {
	var data strings.Builder
	data.WriteString(`<?xml version="1.0"?><plist version="1.0"><dict>`)
	for range maxPlistNodes/2 + 1 {
		data.WriteString(`<key>x</key><string>x</string>`)
	}
	data.WriteString(`</dict></plist>`)
	if data.Len() > maxPlistBytes {
		t.Fatalf("test plist unexpectedly exceeds byte limit: %d", data.Len())
	}
	if _, err := Decode([]byte(data.String())); err == nil || !strings.Contains(err.Error(), "value limit") {
		t.Fatalf("Decode() error = %v, want value-limit error", err)
	}
}

func TestDecodeRejectsDeepXMLBeforeParsing(t *testing.T) {
	data := `<?xml version="1.0"?><plist version="1.0"><dict><key>value</key>` +
		strings.Repeat(`<array>`, maxPlistDepth+1) + `<string>x</string>` +
		strings.Repeat(`</array>`, maxPlistDepth+1) + `</dict></plist>`
	if _, err := Decode([]byte(data)); err == nil || !strings.Contains(err.Error(), "nesting depth") {
		t.Fatalf("Decode() error = %v, want nesting-depth error", err)
	}
}

func TestDecodeRejectsDeepOpenStepBeforeParsing(t *testing.T) {
	data := `{ value = ` + strings.Repeat(`(`, maxPlistDepth+1) + `"x"` +
		strings.Repeat(`)`, maxPlistDepth+1) + `; }`
	if _, err := Decode([]byte(data)); err == nil || !strings.Contains(err.Error(), "nesting depth") {
		t.Fatalf("Decode() error = %v, want nesting-depth error", err)
	}
}

func TestDecodeRejectsDeepBinaryBeforeParsing(t *testing.T) {
	var value any = "x"
	for range maxPlistDepth + 1 {
		value = []any{value}
	}
	data, err := plist.Marshal(map[string]any{"value": value}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "nesting depth") {
		t.Fatalf("Decode() error = %v, want nesting-depth error", err)
	}
}

func TestDecodeRejectsExponentiallyExpandingBinaryDAG(t *testing.T) {
	data := sharedBinaryPlist(16)
	if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "expanded value limit") {
		t.Fatalf("Decode() error = %v, want expanded-value-limit error", err)
	}
}

func TestDecodeRejectsOverflowingBinaryStringExtentBeforeParsing(t *testing.T) {
	malformedKey := append([]byte{0x5f, 0x13}, bytes.Repeat([]byte{0xff}, 8)...)
	data := buildBinaryPlist([][]byte{
		malformedKey,
		{0x51, 'x'},
		{0xd1, 0, 1},
	}, 2)
	if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "ASCII string extent") {
		t.Fatalf("Decode() error = %v, want ASCII-string-extent error", err)
	}
}

func TestDecodeRejectsAliasedBinaryScalarMaterializationBeforeParsing(t *testing.T) {
	tests := []struct {
		name    string
		aliases int
		scalar  []byte
	}{
		{
			name:    "UTF-16",
			aliases: 1_000,
			scalar:  countedBinaryScalar(0x6f, 32_768, bytes.Repeat([]byte{0, 'A'}, 32_768)),
		},
		{
			name:    "ASCII",
			aliases: 600,
			scalar:  countedBinaryScalar(0x5f, 65_536, bytes.Repeat([]byte{'A'}, 65_536)),
		},
		{
			name:    "data",
			aliases: 600,
			scalar:  countedBinaryScalar(0x4f, 65_536, make([]byte, 65_536)),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := aliasedBinaryScalarPlist(test.aliases, test.scalar)
			if len(data) > maxPlistBytes {
				t.Fatalf("test plist unexpectedly exceeds byte limit: %d", len(data))
			}
			if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "materialized scalar byte limit") {
				t.Fatalf("Decode() error = %v, want materialized-scalar limit error", err)
			}
		})
	}
}

func TestNormalizeRetainsIndependentDepthGuard(t *testing.T) {
	var value any = "x"
	for range maxPlistDepth + 1 {
		value = []any{value}
	}
	if _, err := normalize(value, 0, new(int)); err == nil || !strings.Contains(err.Error(), "nesting depth") {
		t.Fatalf("normalize() error = %v, want nesting-depth error", err)
	}
}

func TestDecodeAcceptsSupportedFormats(t *testing.T) {
	tests := []struct {
		name   string
		format int
	}{
		{name: "xml", format: plist.XMLFormat},
		{name: "binary", format: plist.BinaryFormat},
		{name: "openstep", format: plist.OpenStepFormat},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := plist.Marshal(map[string]any{"name": "maratus"}, test.format)
			if err != nil {
				t.Fatal(err)
			}
			dict, err := Decode(data)
			if err != nil {
				t.Fatal(err)
			}
			if got := String(dict, "name"); got != "maratus" {
				t.Fatalf("name = %q, want maratus", got)
			}
		})
	}
}

func sharedBinaryPlist(levels int) []byte {
	var objects [][]byte
	objects = append(objects, append([]byte{0x55}, []byte("value")...))
	objects = append(objects, []byte{0x51, 'x'})
	prior := byte(1)
	for range levels {
		objects = append(objects, []byte{0xa2, prior, prior})
		prior = byte(len(objects) - 1)
	}
	objects = append(objects, []byte{0xd1, 0, prior})
	return buildBinaryPlist(objects, len(objects)-1)
}

func countedBinaryScalar(tag byte, count uint32, payload []byte) []byte {
	out := []byte{tag, 0x12, byte(count >> 24), byte(count >> 16), byte(count >> 8), byte(count)}
	return append(out, payload...)
}

func aliasedBinaryScalarPlist(aliases int, scalar []byte) []byte {
	if aliases <= 0 || aliases > 65_532 {
		panic("invalid test alias count")
	}
	objects := make([]byte, 0, 32+aliases*2+len(scalar))
	rootOffset := 8 + len(objects)
	objects = append(objects, 0xd1, 0, 1, 0, 2)
	keyOffset := 8 + len(objects)
	objects = append(objects, 0x51, 'x')
	arrayOffset := 8 + len(objects)
	objects = append(objects, 0xaf, 0x11, byte(aliases>>8), byte(aliases))
	for index := 0; index < aliases; index++ {
		id := index + 3
		objects = append(objects, byte(id>>8), byte(id))
	}
	scalarOffset := 8 + len(objects)
	objects = append(objects, scalar...)

	numObjects := aliases + 3
	offsetTable := 8 + len(objects)
	data := append([]byte("bplist00"), objects...)
	for id := 0; id < numObjects; id++ {
		offset := scalarOffset
		switch id {
		case 0:
			offset = rootOffset
		case 1:
			offset = keyOffset
		case 2:
			offset = arrayOffset
		}
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], uint32(offset))
		data = append(data, encoded[:]...)
	}

	trailer := make([]byte, 32)
	trailer[6] = 4
	trailer[7] = 2
	binary.BigEndian.PutUint64(trailer[8:16], uint64(numObjects))
	binary.BigEndian.PutUint64(trailer[16:24], 0)
	binary.BigEndian.PutUint64(trailer[24:32], uint64(offsetTable))
	return append(data, trailer...)
}

func buildBinaryPlist(objects [][]byte, top int) []byte {
	var out bytes.Buffer
	out.WriteString("bplist00")
	offsets := make([]byte, 0, len(objects))
	for _, object := range objects {
		offsets = append(offsets, byte(out.Len()))
		out.Write(object)
	}
	offsetTable := out.Len()
	out.Write(offsets)
	trailer := make([]byte, 32)
	trailer[6] = 1
	trailer[7] = 1
	binary.BigEndian.PutUint64(trailer[8:16], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[16:24], uint64(top))
	binary.BigEndian.PutUint64(trailer[24:32], uint64(offsetTable))
	out.Write(trailer)
	return out.Bytes()
}
