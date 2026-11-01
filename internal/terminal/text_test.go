package terminal

import (
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestEscapeControlsAndPreservesPrintableUnicode(t *testing.T) {
	input := "café 雪 🙂\x1b[2J\nnext\x7f\u0085\u202e"
	got := Escape(input)
	want := `café 雪 🙂\x1b[2J\nnext\x7f\x85\u202e`
	if got != want {
		t.Fatalf("Escape() = %q, want %q", got, want)
	}
	for _, unsafe := range []string{"\x1b", "\n", "\x7f", "\u0085", "\u202e"} {
		if strings.Contains(got, unsafe) {
			t.Fatalf("escaped output contains raw control %q: %q", unsafe, got)
		}
	}
}

func TestEscapeInvalidUTF8ProducesValidUTF8(t *testing.T) {
	got := Escape(string([]byte{'a', 0xff, 'b'}))
	if got != `a\xffb` {
		t.Fatalf("Escape() = %q", got)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("Escape() returned invalid UTF-8: %q", got)
	}
}

func TestEscapeTruncateBoundsUntrustedText(t *testing.T) {
	got := EscapeTruncate("雪\x1b"+strings.Repeat("界", 1000), 20)
	if !utf8.ValidString(got) {
		t.Fatalf("EscapeTruncate returned invalid UTF-8: %q", got)
	}
	if utf8.RuneCountInString(got) > 20 {
		t.Fatalf("EscapeTruncate returned %d runes, want at most 20: %q", utf8.RuneCountInString(got), got)
	}
	if strings.Contains(got, "\x1b") || !strings.Contains(got, `\x1b`) || !strings.HasSuffix(got, "...") {
		t.Fatalf("EscapeTruncate did not safely escape and truncate: %q", got)
	}
}

func TestEscapeTruncatePreservesExactFit(t *testing.T) {
	tests := []struct {
		name  string
		value string
		limit int
		want  string
	}{
		{name: "printable", value: "abcd", limit: 4, want: "abcd"},
		{name: "unicode", value: "雪界", limit: 2, want: "雪界"},
		{name: "escaped control", value: "a\nb", limit: 4, want: `a\nb`},
		{name: "invalid byte", value: string([]byte{0xff}), limit: 4, want: `\xff`},
		{name: "small exact", value: "ab", limit: 2, want: "ab"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := EscapeTruncate(test.value, test.limit); got != test.want {
				t.Fatalf("EscapeTruncate(%q, %d) = %q, want %q", test.value, test.limit, got, test.want)
			}
		})
	}
}

func TestEscapeTruncateOnlyAddsEllipsisWhenTruncated(t *testing.T) {
	for _, test := range []struct {
		value string
		limit int
		want  string
	}{
		{value: "abcdx", limit: 4, want: "a..."},
		{value: "ab", limit: 1, want: "."},
		{value: "a\nb", limit: 3, want: "..."},
		{value: "a\nbx", limit: 4, want: "a..."},
	} {
		if got := EscapeTruncate(test.value, test.limit); got != test.want {
			t.Errorf("EscapeTruncate(%q, %d) = %q, want %q", test.value, test.limit, got, test.want)
		}
	}
}

func TestParseColorMode(t *testing.T) {
	for _, value := range []string{"auto", "always", "never", " ALWAYS "} {
		if _, err := ParseColorMode(value); err != nil {
			t.Fatalf("ParseColorMode(%q): %v", value, err)
		}
	}
	if _, err := ParseColorMode("sometimes"); err == nil || !strings.Contains(err.Error(), "invalid --color") {
		t.Fatalf("invalid color mode error = %v", err)
	}
}

func TestColorEnabled(t *testing.T) {
	tests := []struct {
		name     string
		mode     ColorMode
		terminal bool
		noColor  string
		term     string
		want     bool
	}{
		{name: "auto terminal", mode: ColorAuto, terminal: true, term: "xterm-256color", want: true},
		{name: "auto pipe", mode: ColorAuto, terminal: false, term: "xterm-256color"},
		{name: "no color", mode: ColorAuto, terminal: true, noColor: "1", term: "xterm-256color"},
		{name: "dumb terminal", mode: ColorAuto, terminal: true, term: "dumb"},
		{name: "always overrides environment", mode: ColorAlways, noColor: "1", term: "dumb", want: true},
		{name: "never", mode: ColorNever, terminal: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ColorEnabled(tt.mode, tt.terminal, tt.noColor, tt.term); got != tt.want {
				t.Fatalf("ColorEnabled() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestIsTerminalRejectsPipeAndRegularFile(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = readEnd.Close() }()
	defer func() { _ = writeEnd.Close() }()
	if IsTerminal(writeEnd) {
		t.Fatal("pipe must not be classified as a terminal")
	}
	file, err := os.CreateTemp(t.TempDir(), "terminal-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if IsTerminal(file) {
		t.Fatal("regular file must not be classified as a terminal")
	}
}
