package extract

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestDecodeInlineGoBuildInfoRetainsGenericProvenance(t *testing.T) {
	module := strings.Repeat("S", 16) +
		"path\texample.invalid/cmd/tool\n" +
		"mod\texample.invalid/tool\t(devel)\t\n" +
		"dep\texample.invalid/library\tv1.2.3\th1:fixture\n" +
		"=>\texample.invalid/fork\tv1.2.4\th1:replacement\n" +
		"build\tGOOS=darwin\n" + strings.Repeat("E", 16)
	records, detail, ok := decodeInlineGoBuildInfo(goBuildInfoFixture("go1.25.0", module))
	if !ok {
		t.Fatalf("decode failed: %s", detail)
	}
	want := []struct{ key, value string }{
		{"go.build.version", "go1.25.0"},
		{"go.package.path", "example.invalid/cmd/tool"},
		{"go.main.module", "example.invalid/tool"},
		{"go.dependency", "example.invalid/library"},
		{"go.module.replacement", "example.invalid/fork"},
		{"go.build.setting", "GOOS=darwin"},
	}
	if len(records) != len(want) {
		t.Fatalf("records = %#v", records)
	}
	for index := range want {
		if records[index].key != want[index].key || records[index].value != want[index].value || records[index].offset <= 0 {
			t.Fatalf("record %d = %#v", index, records[index])
		}
	}
	if records[3].qualifiers["version"] != "v1.2.3" || records[4].qualifiers["replaces"] != "example.invalid/library" {
		t.Fatalf("module qualifiers = %#v / %#v", records[3].qualifiers, records[4].qualifiers)
	}
}

func TestDecodeInlineGoBuildInfoRejectsAmbiguousAndMalformedForms(t *testing.T) {
	validModule := strings.Repeat("S", 16) + "path\texample.invalid/tool\n" + strings.Repeat("E", 16)
	invalidPointerSize := goBuildInfoFixture("go1.25", validModule)
	invalidPointerSize[14] = 16
	tests := []struct {
		name   string
		data   []byte
		detail string
	}{
		{name: "pointer format", data: goBuildInfoFixtureFlags("go1.17", validModule, 0), detail: "predating"},
		{name: "invalid pointer size", data: invalidPointerSize, detail: "pointer size"},
		{name: "unknown flags", data: goBuildInfoFixtureFlags("go1.25", validModule, 0x82), detail: "flags"},
		{name: "multiple headers", data: append(goBuildInfoFixture("go1.25", validModule), goBuildInfoFixture("go1.25", validModule)...), detail: "multiple"},
		{name: "missing framing", data: goBuildInfoFixture("go1.25", "path\texample.invalid/tool\n"), detail: "framing"},
		{name: "control in version", data: goBuildInfoFixture("go1.25\x1b", validModule), detail: "version"},
		{name: "unknown record", data: goBuildInfoFixture("go1.25", strings.Repeat("S", 16)+"future\tvalue\n"+strings.Repeat("E", 16)), detail: "unsupported"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, detail, ok := decodeInlineGoBuildInfo(test.data); ok || !strings.Contains(detail, test.detail) {
				t.Fatalf("ok=%v detail=%q", ok, detail)
			}
		})
	}
}

func TestDecodeInlineGoBuildInfoEnforcesRecordAndLineBudgets(t *testing.T) {
	tooMany := strings.Repeat("S", 16) + strings.Repeat("build\tGOOS=darwin\n", maxGoBuildInfoRecords+1) + strings.Repeat("E", 16)
	if _, detail, ok := decodeInlineGoBuildInfo(goBuildInfoFixture("go1.25", tooMany)); ok || !strings.Contains(detail, "record count") {
		t.Fatalf("record budget: ok=%v detail=%q", ok, detail)
	}
	longLine := strings.Repeat("S", 16) + "path\t" + strings.Repeat("x", maxGoBuildInfoLine+1) + "\n" + strings.Repeat("E", 16)
	if _, detail, ok := decodeInlineGoBuildInfo(goBuildInfoFixture("go1.25", longLine)); ok || !strings.Contains(detail, "line exceeds") {
		t.Fatalf("line budget: ok=%v detail=%q", ok, detail)
	}
}

func goBuildInfoFixture(version, module string) []byte {
	return goBuildInfoFixtureFlags(version, module, 0x2)
}

func goBuildInfoFixtureFlags(version, module string, flags byte) []byte {
	header := make([]byte, 32)
	copy(header, goBuildInfoMagic)
	header[14] = 8
	header[15] = flags
	return append(appendGoBuildInfoString(appendGoBuildInfoString(header, version), module), 0)
}

func appendGoBuildInfoString(out []byte, value string) []byte {
	var prefix [binary.MaxVarintLen64]byte
	length := binary.PutUvarint(prefix[:], uint64(len(value)))
	out = append(out, prefix[:length]...)
	return append(out, value...)
}
