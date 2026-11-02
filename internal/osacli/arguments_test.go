package osacli

import (
	"strings"
	"testing"
)

func TestProgramSelection(t *testing.T) {
	for _, tt := range []struct {
		name        string
		args        []string
		source      Source
		program     string
		language    string
		interactive bool
		appended    bool
		code        string
	}{
		{name: "default stdin", source: Stdin, language: "applescript", appended: true},
		{name: "option prefix", args: []string{"-s", "ho", "-l", "JavaScript"}, source: Stdin, language: "jxa", appended: true},
		{name: "explicit stdin and script arguments", args: []string{"-", "-i", "-e", "data"}, source: Stdin, language: "applescript"},
		{name: "file", args: []string{"fixture.scpt", "-l", "JavaScript", "-i"}, source: File, program: "fixture.scpt", language: "applescript"},
		{name: "delimiter", args: []string{"--", "-file.scpt"}, source: File, program: "-file.scpt", language: "applescript"},
		{name: "delimiter prefix", args: []string{"--"}, source: Stdin, language: "applescript", appended: true},
		{name: "delimiter stdin", args: []string{"--", "-", "argument"}, source: Stdin, language: "applescript"},
		{name: "successive lines", args: []string{"-e", "set value to 1", "-e", "return value"}, source: Inline, language: "applescript", code: "set value to 1\nreturn value"},
		{name: "inline script arguments", args: []string{"-e", "return 1", "argument", "-i"}, source: Inline, language: "applescript", code: "return 1"},
		{name: "inline delimiter", args: []string{"-e", "return 1", "--", "argument"}, source: Inline, language: "applescript", code: "return 1"},
		{name: "attached options", args: []string{"-lJavaScript", "-sh", "-e1 + 1"}, source: Inline, language: "jxa", code: "1 + 1"},
		{name: "empty inline", args: []string{"-e", ""}, source: Inline, language: "applescript"},
		{name: "interactive file", args: []string{"-i", "fixture.scpt"}, source: File, program: "fixture.scpt", language: "applescript", interactive: true},
		{name: "interactive inline", args: []string{"-e", "return 1", "-i"}, source: Inline, language: "applescript", interactive: true, code: "return 1"},
		{name: "interactive prefix", args: []string{"-i"}, source: Stdin, language: "applescript", interactive: true, appended: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := Parse(tt.args)
			if r.Disposition != Recognized || r.Source != tt.source || r.Program != tt.program || r.Language != tt.language || r.Interactive != tt.interactive || r.AcceptsAppendedProgram != tt.appended || strings.Join(r.Lines, "\n") != tt.code || r.Executes() == tt.interactive {
				t.Fatalf("unexpected selection: %#v", r)
			}
		})
	}
}

func TestUnsupportedAndMalformedOptions(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want Disposition
	}{
		{[]string{"-e"}, Malformed},
		{[]string{"-l"}, Malformed},
		{[]string{"-s"}, Malformed},
		{[]string{"-s", ""}, Malformed},
		{[]string{""}, Malformed},
		{[]string{"-s", "x", "fixture.scpt"}, Unsupported},
		{[]string{"-sx", "fixture.scpt"}, Unsupported},
		{[]string{"-l", "Ruby", "fixture.scpt"}, Unsupported},
		{[]string{"-lAppleScript", "-lJavaScript", "fixture.scpt"}, Unsupported},
		{[]string{"--execute", "return 1"}, Unsupported},
		{[]string{"--language", "JavaScript"}, Unsupported},
		{[]string{"--future", "fixture.scpt"}, Unsupported},
		{[]string{"-e", "return 1\x00"}, Malformed},
		{[]string{"--", "fixture\x00.scpt"}, Malformed},
	} {
		r := Parse(tt.args)
		if r.Disposition != tt.want || r.Executes() || r.Program != "" || len(r.Lines) != 0 || r.AcceptsAppendedProgram {
			t.Fatalf("%q retained an incomplete selection: %#v", tt.args, r)
		}
	}
}

func TestArgumentAndWorkLimits(t *testing.T) {
	args := make([]string, MaxArguments)
	for i := range args {
		args[i] = "-i"
	}
	if r := Parse(args); r.Disposition != Recognized {
		t.Fatal("complete option prefix at the limit was rejected")
	}
	for _, suffix := range [][]string{{"fixture.scpt"}, {"-e", "return 1"}, {"--", "fixture.scpt"}} {
		if r := Parse(append(args, suffix...)); r.Disposition != Limited || r.Executes() {
			t.Fatal("incomplete option prefix acquired a selection")
		}
	}
	if r := Parse(append([]string{"fixture.scpt"}, args...)); r.Disposition != Recognized || !r.Executes() {
		t.Fatal("script arguments were parsed as interpreter options")
	}
	for i := range args {
		args[i] = "-sh"
	}
	if r := Parse(args); r.Disposition != Recognized || r.AcceptsAppendedProgram {
		t.Fatal("a full prefix budget left room for an appended program")
	}
	args[len(args)-1] = "--"
	if r := Parse(args); r.Disposition != Recognized || r.AcceptsAppendedProgram {
		t.Fatal("an option delimiter escaped the appended-program budget")
	}
	large := strings.Repeat("h", MaxProgramBytes/2)
	for _, argv := range [][]string{{"-e", large, "-e", large}, {"-s", large, "-s", large}, {"--", large + large}} {
		if r := Parse(argv); r.Disposition != Limited || r.Executes() || len(r.Lines) != 0 {
			t.Fatal("argument work limit retained a partial proof")
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"-i\nfixture.scpt", "-e\nreturn 1\n-i", "-lJavaScript\n-e1", "--\n-", "-s\nho", "--execute\nreturn 1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 64<<10 {
			return
		}
		r := Parse(strings.Split(source, "\n"))
		if r.Executes() && (r.Interactive || r.Disposition != Recognized) {
			t.Fatal("non-executing profile acquired execution")
		}
		if len(r.Lines) > MaxArguments || len(strings.Join(r.Lines, "\n")) > MaxProgramBytes {
			t.Fatal("inline program exceeded its bound")
		}
	})
}
