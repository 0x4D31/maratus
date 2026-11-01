package shellparse

import (
	"errors"
	"strings"
	"testing"
)

func TestFieldsPreservesEmptyQuotedArguments(t *testing.T) {
	for _, test := range []struct {
		command string
		want    []string
	}{
		{`printf "" '' a""b`, []string{"printf", "", "", "ab"}},
		{`"" curl https://example.invalid/payload`, []string{"", "curl", "https://example.invalid/payload"}},
		{`sudo '' /usr/bin/id`, []string{"sudo", "", "/usr/bin/id"}},
		{`env -S 'printf ""'`, []string{"env", "-S", `printf ""`}},
	} {
		fields, err := Fields(test.command)
		if err != nil {
			t.Fatalf("Fields(%q): %v", test.command, err)
		}
		assertFields(t, fields, test.want)
	}
	fields, err := NormalizeFieldsChecked([]string{"sudo", "", "/usr/bin/id"})
	if err != nil {
		t.Fatal(err)
	}
	assertFields(t, fields, []string{"", "/usr/bin/id"})
}

func TestFieldsPreservesShellQuoteEscapeSemantics(t *testing.T) {
	for _, test := range []struct {
		command string
		want    []string
	}{
		{`printf 'a\b' "a\b" "a\$b" "a\"b" "a\\b"`, []string{"printf", `a\b`, `a\b`, "a$b", `a"b`, `a\b`}},
		{`printf 'a\' b`, []string{"printf", `a\`, "b"}},
		{"printf a\\\nb \"c\\\nd\" '\\\n'", []string{"printf", "ab", "cd", "\\\n"}},
		{"\\\n", nil},
		{"\"\\\n\"", []string{""}},
	} {
		fields, err := Fields(test.command)
		if err != nil {
			t.Fatalf("Fields(%q): %v", test.command, err)
		}
		assertFields(t, fields, test.want)
	}
	if _, err := Fields(`printf 'a\'b'`); err == nil {
		t.Fatal("backslash inside single quotes hid an unterminated quote")
	}
}

func TestFieldsCountsEmptyArgumentsAgainstFieldLimit(t *testing.T) {
	fields, err := Fields(strings.Repeat(`'' `, maxFields+1))
	if !errors.Is(err, ErrFieldLimit) || fields != nil {
		t.Fatalf("empty argument fanout = %#v, %v; want nil ErrFieldLimit", fields, err)
	}
	fields, err = Fields(strings.Repeat(`'' `, maxFields))
	if err != nil || len(fields) != maxFields {
		t.Fatalf("exact empty argument limit: count=%d, error=%v", len(fields), err)
	}
}

func TestNormalizeFieldsRejectsNonExecutionSudoModes(t *testing.T) {
	for _, options := range [][]string{
		{"-l"}, {"-ll"}, {"--list"}, {"-nl"},
		{"-e"}, {"--edit"}, {"-v"}, {"--validate"},
		{"-V"}, {"--version"}, {"--help"}, {"-K"}, {"--remove-timestamp"},
		{"-i"}, {"--login"}, {"-s"}, {"--shell"},
		{"-U", "other"}, {"--other-user=other"},
		{"--unknown-option"}, {"-Z"},
	} {
		fields := append(append([]string{"sudo"}, options...), "/usr/bin/id")
		normalized, err := NormalizeFieldsChecked(fields)
		if !errors.Is(err, ErrUnsupportedSyntax) || normalized != nil {
			t.Fatalf("NormalizeFieldsChecked(%#v) = %#v, %v; want nil ErrUnsupportedSyntax", fields, normalized, err)
		}
	}
}

func TestNormalizeFieldsRetainsSupportedSudoExecutionOptions(t *testing.T) {
	for _, options := range [][]string{
		nil, {"-E"}, {"-nE"}, {"-u", "root"}, {"-uroot"},
		{"--user=root"}, {"--non-interactive", "--preserve-env=PATH"}, {"--"},
		{"-p", ""}, {"--prompt", ""}, {"-g", "wheel"}, {"--group", "wheel"},
	} {
		fields := append(append([]string{"sudo"}, options...), "/usr/bin/id")
		normalized, err := NormalizeFieldsChecked(fields)
		if err != nil {
			t.Fatalf("NormalizeFieldsChecked(%#v): %v", fields, err)
		}
		assertFields(t, normalized, []string{"/usr/bin/id"})
	}
	if fields, err := NormalizeFieldsChecked([]string{"sudo", "-u"}); !errors.Is(err, ErrUnsupportedSyntax) || fields != nil {
		t.Fatalf("missing sudo option operand = %#v, %v", fields, err)
	}
}

func TestNormalizeFieldsRejectsEmptySudoUserOrGroup(t *testing.T) {
	for _, options := range [][]string{
		{"-u", ""}, {"--user", ""}, {"--user="},
		{"-g", ""}, {"--group", ""}, {"--group="},
	} {
		fields := append(append([]string{"sudo"}, options...), "/usr/bin/id")
		normalized, err := NormalizeFieldsChecked(fields)
		if !errors.Is(err, ErrUnsupportedSyntax) || normalized != nil {
			t.Fatalf("NormalizeFieldsChecked(%#v) = %#v, %v; want nil ErrUnsupportedSyntax", fields, normalized, err)
		}
	}
}

func TestNormalizeFieldsRejectsFilesystemContextOverrides(t *testing.T) {
	for _, fields := range [][]string{
		{"env", "-C", "sub", "node", "decoy.js"},
		{"env", "-Csub", "node", "decoy.js"},
		{"env", "--chdir=sub", "node", "decoy.js"},
		{"sudo", "-D", "sub", "node", "decoy.js"},
		{"sudo", "-Dsub", "node", "decoy.js"},
		{"sudo", "--chdir=sub", "node", "decoy.js"},
		{"sudo", "-R", "/other", "node", "/decoy.js"},
		{"sudo", "-R/other", "node", "/decoy.js"},
		{"sudo", "--chroot=/other", "node", "/decoy.js"},
		{"env", "-S", "env -Csub node decoy.js"},
		{"env", "-0", "node", "decoy.js"},
		{"env", "--null", "node", "decoy.js"},
	} {
		normalized, err := NormalizeFieldsChecked(fields)
		if !errors.Is(err, ErrUnsupportedSyntax) || normalized != nil {
			t.Fatalf("NormalizeFieldsChecked(%#v) = %#v, %v; want nil ErrUnsupportedSyntax", fields, normalized, err)
		}
	}
}

func TestNormalizeFieldsKeepsOrdinaryWrappersAndProgramArguments(t *testing.T) {
	for _, test := range []struct {
		fields []string
		want   []string
	}{
		{[]string{"env", "-i", "node", "entry.js"}, []string{"node", "entry.js"}},
		{[]string{"env", "-u", "IGNORED", "node", "entry.js"}, []string{"node", "entry.js"}},
		{[]string{"env", "-S", "node entry.js"}, []string{"node", "entry.js"}},
		{[]string{"env", "--", "node", "-Csub"}, []string{"node", "-Csub"}},
		{[]string{"sudo", "--", "node", "-Dsub"}, []string{"node", "-Dsub"}},
	} {
		got, err := NormalizeFieldsChecked(test.fields)
		if err != nil {
			t.Fatal(err)
		}
		assertFields(t, got, test.want)
	}
}
