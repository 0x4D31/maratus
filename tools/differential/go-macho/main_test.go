package main

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsMissingAndMalformedInputs(t *testing.T) {
	if err := run(nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("missing input error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "malformed")
	if err := os.WriteFile(path, []byte("not a Mach-O"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{path}, &bytes.Buffer{}); err == nil {
		t.Fatal("malformed input was accepted")
	}
}

func TestRunRejectsInputOverSizeBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxInputBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{path}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "bounded regular file") {
		t.Fatalf("oversized input error = %v", err)
	}
}

func TestRunRejectsSymlinkAndFatContainer(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte{0xcf, 0xfa, 0xed, 0xfe}, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{link}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "bounded regular file") {
		t.Fatalf("symlink error = %v", err)
	}

	fat := filepath.Join(directory, "fat")
	if err := os.WriteFile(fat, []byte{0xca, 0xfe, 0xba, 0xbe}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{fat}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "exact thin Mach-O") {
		t.Fatalf("fat input error = %v", err)
	}
}

func TestFunctionCountRequiresDeclaredStarts(t *testing.T) {
	for _, hasStarts := range []bool{false, true} {
		t.Run(fmt.Sprint(hasStarts), func(t *testing.T) {
			const base = uint64(0x100000000)
			commandBytes, commands := uint32(152), uint32(1)
			if hasStarts {
				commandBytes += 16
				commands++
			}
			textOffset := 32 + commandBytes
			var data bytes.Buffer
			write := func(value any) {
				t.Helper()
				if err := binary.Write(&data, binary.LittleEndian, value); err != nil {
					t.Fatal(err)
				}
			}
			write([8]uint32{macho.Magic64, uint32(macho.CpuArm64), 2, uint32(macho.TypeExec), commands, commandBytes, 0, 0})
			segment := macho.Segment64{Cmd: macho.LoadCmdSegment64, Len: 152, Addr: base, Memsz: 4096, Filesz: uint64(textOffset + 12), Maxprot: 7, Prot: 5, Nsect: 1}
			copy(segment.Name[:], "__TEXT")
			write(segment)
			section := macho.Section64{Addr: base + uint64(textOffset), Size: 8, Offset: textOffset, Align: 2, Flags: 0x80000400}
			copy(section.Name[:], "__text")
			copy(section.Seg[:], "__TEXT")
			write(section)
			if hasStarts {
				write([4]uint32{0x26, 16, textOffset + 8, 4}) // LC_FUNCTION_STARTS
			}
			// arm64e PAC prologues trigger the library's heuristic fallback.
			write([2]uint32{0xd503237f, 0xd503237f})
			write([4]byte{0xc8, 0x01, 0x04, 0x00}) // starts at text offset 200, 204
			path := filepath.Join(t.TempDir(), "control")
			if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := run([]string{path}, &output); err != nil {
				t.Fatal(err)
			}
			var got result
			if err := json.Unmarshal(output.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			wantCount := 0
			if hasStarts {
				wantCount = 2
			}
			if got.FunctionStartsPresent != hasStarts || got.FunctionCount != wantCount || len(got.Sections) != 1 || got.Sections[0].Address != base+uint64(textOffset) {
				t.Fatalf("declared starts=%v: %#v", hasStarts, got)
			}
		})
	}
}
