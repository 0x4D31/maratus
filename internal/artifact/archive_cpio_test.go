package artifact

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestCPIONameFraming(t *testing.T) {
	for _, format := range []struct {
		name   string
		header int
		append func([]byte, uint64, uint64, string, []byte) []byte
	}{
		{"newc", cpioNewcHeaderSize, appendCPIOTestEntry},
		{"odc", cpioOdcHeaderSize, appendCPIOOdcTestEntry},
	} {
		for _, test := range []struct {
			name string
			path string
			bad  bool
		}{
			{"ordinary", "install.sh", false},
			{"missing-terminator", "install.sh", true},
			{"embedded-nul", "install.sh\x00decoy", true},
			{"nul-padding", "install.sh\x00\x00", false},
		} {
			t.Run(format.name+"/"+test.name, func(t *testing.T) {
				body := []byte("#!/bin/sh\necho inert\n")
				data := format.append(nil, 1, 0o100755, test.path, body)
				if test.name == "missing-terminator" {
					data[format.header+len(test.path)] = 'X'
				}
				data = format.append(data, 2, 0, "TRAILER!!!", nil)
				entries, _, err := parseCPIO(data, Options{})
				if test.bad {
					if err == nil || len(entries) != 0 {
						t.Fatalf("malformed name was modeled: entries=%#v err=%v", entries, err)
					}
					s, parent := newContainerCoverageScanner("sample.cpio", "cpio", Options{})
					s.scanCPIO(parent, "sample.cpio", data, 1)
					requireContainerPartial(t, s, "sample.cpio", "cpio parse failed")
					if len(s.contents) != 0 {
						t.Fatal("malformed archive retained content")
					}
					return
				}
				if err != nil || len(entries) != 1 || entries[0].Name != "install.sh" || !bytes.Equal(entries[0].Data, body) {
					t.Fatalf("valid name was not preserved: entries=%#v err=%v", entries, err)
				}
			})
		}
		t.Run(format.name+"/nonempty-trailer", func(t *testing.T) {
			data := format.append(nil, 1, 0, "TRAILER!!!", []byte("inert"))
			if _, _, err := parseCPIO(data, Options{}); err == nil {
				t.Fatal("nonempty trailer was accepted")
			}
		})
	}
}

func TestCPIOCRCIntegrity(t *testing.T) {
	body := []byte("#!/bin/sh\necho inert\n")
	data := appendCPIOTestEntry(nil, 1, 0o100755, "install.sh", body)
	copy(data[:6], "070702")
	var checksum uint32
	for _, value := range body {
		checksum += uint32(value)
	}
	copy(data[102:110], fmt.Sprintf("%08x", checksum))
	data = appendCPIOTestEntry(data, 2, 0, "TRAILER!!!", nil)
	for _, test := range []struct {
		name string
		edit func([]byte)
		want string
	}{
		{"valid", func([]byte) {}, ""},
		{"wrong-checksum", func(b []byte) { copy(b[102:110], "00000000") }, "checksum mismatch"},
		{"invalid-checksum", func(b []byte) { b[102] = 'z' }, "invalid checksum"},
		{"modified-data", func(b []byte) { b[align4(cpioNewcHeaderSize+len("install.sh")+1)] ^= 1 }, "checksum mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := bytes.Clone(data)
			test.edit(input)
			entries, _, err := parseCPIO(input, Options{})
			if test.want == "" {
				if err != nil || len(entries) != 1 || !bytes.Equal(entries[0].Data, body) {
					t.Fatalf("valid crc archive rejected: entries=%#v err=%v", entries, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) || len(entries) != 0 {
				t.Fatalf("invalid crc content was modeled: entries=%#v err=%v", entries, err)
			}
			s, parent := newContainerCoverageScanner("sample.cpio", "cpio", Options{})
			s.scanCPIO(parent, "sample.cpio", input, 1)
			requireContainerPartial(t, s, "sample.cpio", test.want)
		})
	}
}
