package artifact

import (
	"strings"
	"testing"
)

func TestShebangLanguageUsesExactBoundedInterpreterSemantics(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{name: "direct shell", line: "#!/bin/zsh", want: "shell"},
		{name: "env python", line: "#!/usr/bin/env python3.11", want: "python"},
		{name: "env assignment", line: "#!/usr/bin/env PYTHONUTF8=1 python3", want: "python"},
		{name: "env path assignment", line: "#!/usr/bin/env PATH=/tmp python3", want: ""},
		{name: "env path assignment absolute utility", line: "#!/usr/bin/env PATH=/tmp /usr/bin/python3", want: "python"},
		{name: "env split", line: "#!/usr/bin/env -S python3 -O", want: "python"},
		{name: "env split javascript", line: "#!/usr/bin/env -S node --no-warnings", want: "javascript"},
		{name: "javascript", line: "#!/usr/bin/node", want: "javascript"},
		{name: "applescript", line: "#!/usr/bin/osascript", want: "applescript"},
		{name: "jxa", line: "#!/usr/bin/osascript -l JavaScript", want: "jxa"},
		{name: "jxa attached language", line: "#!/usr/bin/osascript -lJavaScript", want: "jxa"},
		{name: "jxa after flags", line: "#!/usr/bin/osascript -s h -l JavaScript", want: "jxa"},
		{name: "jxa after attached flags", line: "#!/usr/bin/osascript -sh -l JavaScript", want: "jxa"},
		{name: "osascript existing program", line: "#!/usr/bin/osascript other.scpt", want: ""},
		{name: "osascript inline", line: "#!/usr/bin/osascript -e 'return 1'", want: ""},
		{name: "osascript interactive", line: "#!/usr/bin/osascript -i", want: ""},
		{name: "osascript unsupported long execute", line: "#!/usr/bin/osascript --execute return", want: ""},
		{name: "osascript repeated language outside profile", line: "#!/usr/bin/osascript -l AppleScript -l JavaScript", want: ""},
		{name: "osascript end options existing program", line: "#!/usr/bin/osascript -- other.scpt", want: ""},
		{name: "shell inline", line: "#!/bin/sh -c 'echo inert'", want: ""},
		{name: "shell stdin", line: "#!/bin/sh -s", want: ""},
		{name: "python module", line: "#!/usr/bin/python3 -m benign", want: ""},
		{name: "python inline", line: "#!/usr/bin/python3 -c pass", want: ""},
		{name: "python stdin", line: "#!/usr/bin/python3 -", want: ""},
		{name: "python existing program", line: "#!/usr/bin/python3 other.py", want: ""},
		{name: "python end options existing program", line: "#!/usr/bin/python3 -- other.py", want: ""},
		{name: "node eval", line: "#!/usr/bin/node --eval 0", want: ""},
		{name: "node existing program", line: "#!/usr/bin/node other.js", want: ""},
		{name: "node end options existing program", line: "#!/usr/bin/node -- other.js", want: ""},
		{name: "invalid osascript output flags", line: "#!/usr/bin/osascript -s x -l JavaScript target", want: ""},
		{name: "invalid attached osascript output flags", line: "#!/usr/bin/osascript -sx -l JavaScript target", want: ""},
		{name: "empty osascript output flags", line: "#!/usr/bin/osascript -s '' -l JavaScript target", want: ""},
		{name: "explicit applescript", line: "#!/usr/bin/osascript -l AppleScript", want: "applescript"},
		{name: "unsupported osa language", line: "#!/usr/bin/osascript -l Ruby", want: ""},
		{name: "unsupported osa language after flags", line: "#!/usr/bin/osascript -s h -l Ruby target", want: ""},
		{name: "unsupported osascript long language", line: "#!/usr/bin/osascript --language JavaScript", want: ""},
		{name: "comment terminator", line: "#!/bin/bash # ignored", want: "shell"},
		{name: "attached comment terminator", line: "#!/bin/bash#ignored", want: "shell"},
		{name: "crlf is not xnu whitespace", line: "#!/bin/bash\r", want: ""},
		{name: "wish is not sh", line: "#!/usr/bin/wish", want: ""},
		{name: "substring helper", line: "#!/opt/tools/bash-helper", want: ""},
		{name: "quoted direct interpreter", line: "#!'/bin/sh'", want: ""},
		{name: "quoted env interpreter", line: "#!/usr/bin/env 'python3'", want: ""},
		{name: "case changed direct interpreter", line: "#!/bin/SH", want: ""},
		{name: "case changed env", line: "#!/usr/bin/ENV python3", want: ""},
		{name: "trailing slash", line: "#!/bin/sh/", want: ""},
		{name: "env trailing slash", line: "#!/usr/bin/env/ python3", want: ""},
		{name: "non-system env", line: "#!/tmp/env python3", want: ""},
		{name: "arbitrary shell path", line: "#!/tmp/sh", want: ""},
		{name: "prefixed relative shell path", line: "#!relative/prefix/sh", want: ""},
		{name: "env option after assignment", line: "#!/usr/bin/env FOO=bar -S python3", want: ""},
		{name: "env quoted split command", line: "#!/usr/bin/env -S 'node --no-warnings'", want: ""},
		{name: "macos verbose env option", line: "#!/usr/bin/env -v python3", want: "python"},
		{name: "env utility path override", line: "#!/usr/bin/env -P /tmp python3", want: ""},
		{name: "env utility path override absolute utility", line: "#!/usr/bin/env -P /tmp /usr/bin/python3", want: "python"},
		{name: "unsupported env option", line: "#!/usr/bin/env -Z python3", want: ""},
		{name: "environment print mode with utility", line: "#!/usr/bin/env -0 python3", want: ""},
		{name: "gnu long ignore option", line: "#!/usr/bin/env --ignore-environment python3", want: ""},
		{name: "gnu long split option", line: "#!/usr/bin/env --split-string=python3", want: ""},
		{name: "gnu long split option separate", line: "#!/usr/bin/env --split-string python3", want: ""},
		{name: "gnu long unset option", line: "#!/usr/bin/env --unset=PATH python3", want: ""},
		{name: "unsupported split escape", line: `#!/usr/bin/env -S p\ython3`, want: ""},
		{name: "empty single-quoted split utility", line: "#!/usr/bin/env -S '' python3", want: ""},
		{name: "empty double-quoted split utility", line: `#!/usr/bin/env -S "" python3`, want: ""},
		{name: "concatenated empty quote split utility", line: "#!/usr/bin/env -S ''python3", want: "python"},
		{name: "unterminated quote", line: "#!/usr/bin/env -S 'python3", want: ""},
		{name: "leading whitespace", line: " #!/bin/sh", want: ""},
		{name: "bom", line: "\ufeff#!/bin/sh", want: ""},
		{name: "unicode whitespace", line: "#!\u00a0/bin/sh", want: ""},
		{name: "nul", line: "#!/bin/sh\x00ignored", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ShebangLanguage([]byte(test.line + "\necho inert\n")); got != test.want {
				t.Fatalf("ShebangLanguage(%q) = %q, want %q", test.line, got, test.want)
			}
		})
	}
}

func TestInterpreterLanguageRequiresConventionalTypedHost(t *testing.T) {
	for _, test := range []struct {
		name        string
		interpreter string
		arguments   []string
		want        string
	}{
		{name: "shell", interpreter: "/bin/sh", want: "shell"},
		{name: "arbitrary shell basename", interpreter: "/tmp/sh", want: ""},
		{name: "arbitrary python basename", interpreter: "/attacker/python3", want: ""},
		{name: "jxa", interpreter: "/usr/bin/osascript", arguments: []string{"-l", "JavaScript"}, want: "jxa"},
		{name: "jxa attached", interpreter: "/usr/bin/osascript", arguments: []string{"-lJavaScript"}, want: "jxa"},
		{name: "jxa after flags", interpreter: "/usr/bin/osascript", arguments: []string{"-s", "h", "-l", "JavaScript", "target"}, want: "jxa"},
		{name: "invalid output flags", interpreter: "/usr/bin/osascript", arguments: []string{"-s", "x", "-l", "JavaScript", "target"}, want: ""},
		{name: "invalid attached output flags", interpreter: "/usr/bin/osascript", arguments: []string{"-sx", "-l", "JavaScript", "target"}, want: ""},
		{name: "unsupported language after flags", interpreter: "/usr/bin/osascript", arguments: []string{"-s", "h", "-l", "Ruby", "target"}, want: ""},
		{name: "script argument is not an option", interpreter: "/usr/bin/osascript", arguments: []string{"target", "-l", "JavaScript"}, want: "applescript"},
		{name: "invalid osascript long option", interpreter: "/usr/bin/osascript", arguments: []string{"--language", "JavaScript"}, want: ""},
		{name: "env path override", interpreter: "/usr/bin/env", arguments: []string{"-P", "/tmp", "python3"}, want: ""},
		{name: "env absolute utility", interpreter: "/usr/bin/env", arguments: []string{"-P", "/tmp", "/usr/bin/python3"}, want: "python"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := InterpreterLanguage(test.interpreter, test.arguments); got != test.want {
				t.Fatalf("InterpreterLanguage(%q, %#v) = %q, want %q", test.interpreter, test.arguments, got, test.want)
			}
		})
	}
}

func TestInterpreterTargetLanguageRequiresAppendedProgramSelection(t *testing.T) {
	for _, test := range []struct {
		name        string
		interpreter string
		arguments   []string
		want        string
	}{
		{name: "shell file", interpreter: "/bin/sh", want: "shell"},
		{name: "shell end options", interpreter: "/bin/sh", arguments: []string{"--"}, want: "shell"},
		{name: "shell inline", interpreter: "/bin/sh", arguments: []string{"-c", "echo inert"}, want: ""},
		{name: "python file", interpreter: "/usr/bin/python3", want: "python"},
		{name: "python optimized file", interpreter: "/usr/bin/python3", arguments: []string{"-O"}, want: "python"},
		{name: "python existing file after end options", interpreter: "/usr/bin/python3", arguments: []string{"--", "other.py"}, want: ""},
		{name: "python module", interpreter: "/usr/bin/python3", arguments: []string{"-m", "module"}, want: ""},
		{name: "python inline", interpreter: "/usr/bin/python3", arguments: []string{"-c", "pass"}, want: ""},
		{name: "node file", interpreter: "/usr/bin/node", want: "javascript"},
		{name: "node no warnings file", interpreter: "/usr/bin/node", arguments: []string{"--no-warnings"}, want: "javascript"},
		{name: "node existing file after end options", interpreter: "/usr/bin/node", arguments: []string{"--", "other.js"}, want: ""},
		{name: "node inline", interpreter: "/usr/bin/node", arguments: []string{"--eval", "0"}, want: ""},
		{name: "osascript file", interpreter: "/usr/bin/osascript", arguments: []string{"-s", "h", "-l", "JavaScript"}, want: "jxa"},
		{name: "osascript invalid output flags", interpreter: "/usr/bin/osascript", arguments: []string{"-s", "x", "-l", "JavaScript"}, want: ""},
		{name: "osascript invalid attached output flags", interpreter: "/usr/bin/osascript", arguments: []string{"-sx", "-l", "JavaScript"}, want: ""},
		{name: "osascript inline", interpreter: "/usr/bin/osascript", arguments: []string{"-e", "return 1"}, want: ""},
		{name: "osascript bare end options", interpreter: "/usr/bin/osascript", arguments: []string{"--"}, want: "applescript"},
		{name: "osascript end options existing file", interpreter: "/usr/bin/osascript", arguments: []string{"--", "other.scpt"}, want: ""},
		{name: "osascript existing file", interpreter: "/usr/bin/osascript", arguments: []string{"other.scpt"}, want: ""},
		{name: "env shell inline", interpreter: "/usr/bin/env", arguments: []string{"sh", "-c", "echo inert"}, want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := InterpreterTargetLanguage(test.interpreter, test.arguments); got != test.want {
				t.Fatalf("InterpreterTargetLanguage(%q, %#v) = %q, want %q", test.interpreter, test.arguments, got, test.want)
			}
		})
	}
}

func TestHasShebangSeparatesStructureFromSupportedHost(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		want bool
	}{
		{name: "supported", data: "#!/bin/sh\n", want: true},
		{name: "unsupported ruby", data: "#!/usr/bin/ruby\n", want: true},
		{name: "unsupported wish", data: "#!/usr/bin/wish\n", want: true},
		{name: "literal quoted path", data: "#!'/bin/sh'\n", want: true},
		{name: "empty declaration", data: "#!  \n", want: false},
		{name: "unterminated declaration", data: "#!/bin/sh", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := HasShebang([]byte(test.data)); got != test.want {
				t.Fatalf("HasShebang(%q) = %v, want %v", test.data, got, test.want)
			}
		})
	}
}

func TestShebangLanguageRejectsOverlongOrExcessiveDeclarations(t *testing.T) {
	overlong := "#!/usr/bin/env " + strings.Repeat("A", maxShebangBytes) + "\n"
	if got := ShebangLanguage([]byte(overlong)); got != "" {
		t.Fatalf("overlong shebang language = %q, want unsupported", got)
	}
	tooMany := "#!/usr/bin/env -S " + strings.Repeat("X ", maxShebangWords+1) + "python3\n"
	if got := ShebangLanguage([]byte(tooMany)); got != "" {
		t.Fatalf("excessive shebang language = %q, want unsupported", got)
	}
	lastValidTerminator := "#!/bin/sh" + strings.Repeat(" ", maxShebangBytes-len("#!/bin/sh")-1) + "\n"
	if got := ShebangLanguage([]byte(lastValidTerminator)); got != "shell" {
		t.Fatalf("declaration terminated in the final XNU buffer byte = %q, want shell", got)
	}
	tooLateTerminator := "#!/bin/sh" + strings.Repeat(" ", maxShebangBytes-len("#!/bin/sh")) + "\n"
	if got := ShebangLanguage([]byte(tooLateTerminator)); got != "" {
		t.Fatalf("declaration terminated beyond the XNU buffer = %q, want unsupported", got)
	}
}

func TestDetectDoesNotPromoteSubstringShebangInterpreter(t *testing.T) {
	kind, media := Detect("extensionless", []byte("#!/usr/bin/wish\nputs inert\n"), false)
	if kind != "script" || media != "text/plain" {
		t.Fatalf("wish shebang detection = %q %q, want unsupported script", kind, media)
	}
}
