package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/report"
)

func TestInspectSupportsSharedSummaryJSONAndDirectHTML(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "inspect.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nps aux\nfind ~/Documents -maxdepth 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	summaryData := captureStdout(t, func() error { return run([]string{"inspect", script, "--format", "summary-json"}) })
	var summary report.Summary
	if err := json.Unmarshal(summaryData, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.SchemaVersion != report.SummarySchemaVersion || summary.Overview.Operations != 2 || len(summary.ModeledBehavior) != 2 {
		t.Fatalf("summary projection = %#v", summary)
	}
	htmlPath := filepath.Join(root, "report.html")
	if err := run([]string{"inspect", script, "--format", "html", "-o", htmlPath}); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(html, []byte("<!doctype html>")) {
		t.Fatalf("direct inspect HTML is invalid: %s", html)
	}
}

func TestInspectCaseBundleIsPrivateDeterministicAndNoOverwrite(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "fixture.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsystem_profiler SPSoftwareDataType\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(root, "case-a")
	second := filepath.Join(root, "case-b")
	for _, directory := range []string{first, second} {
		stdout := captureStdout(t, func() error { return run([]string{"inspect", script, "--output-dir", directory}) })
		if !bytes.Contains(stdout, []byte("CAPABILITIES")) {
			t.Fatalf("case bundle suppressed normal stdout: %s", stdout)
		}
		info, err := os.Stat(directory)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("bundle directory mode = %v error=%v", info, err)
		}
	}
	for _, name := range []string{"report.json", "summary.json", "summary.txt", "report.html", "manifest.json"} {
		left, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(second, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(left, right) {
			t.Fatalf("bundle member %s is nondeterministic", name)
		}
		info, err := os.Stat(filepath.Join(first, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("bundle member %s mode = %v error=%v", name, info, err)
		}
	}
	manifestData, err := os.ReadFile(filepath.Join(first, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest caseBundleManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != bundleSchemaVersion || len(manifest.Outputs) != 4 {
		t.Fatalf("bundle manifest = %#v", manifest)
	}
	if manifest.Supervision.Mode != "in-process" {
		t.Fatalf("bundle supervision = %#v", manifest.Supervision)
	}
	wantAnalysisDigest, err := canonicalValueSHA256(manifest.Analysis)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.ToolSHA256) != 64 || manifest.AnalysisSHA256 != wantAnalysisDigest {
		t.Fatalf("bundle tool/settings digests = %#v", manifest)
	}
	for _, item := range manifest.Outputs {
		data, err := os.ReadFile(filepath.Join(first, item.Path))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if item.Bytes != len(data) || item.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("manifest digest for %s = %#v", item.Path, item)
		}
	}
	if err := run([]string{"inspect", script, "--output-dir", first}); err == nil {
		t.Fatal("existing output directory was overwritten")
	}
}

func TestRenameDirectoryNoReplacePreservesConcurrentDestination(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	destination := filepath.Join(root, "destination")
	if err := os.Mkdir(staged, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := renameDirectoryNoReplace(staged, destination); err == nil {
		t.Fatal("exclusive rename replaced an existing empty directory")
	}
	for _, directory := range []string{staged, destination} {
		if info, err := os.Stat(directory); err != nil || !info.IsDir() {
			t.Fatalf("exclusive rename did not preserve %s: info=%v err=%v", directory, info, err)
		}
	}
}

func TestInspectRefusesExistingCaseBundleBeforeAnalysis(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := executeInspection
	called := false
	executeInspection = func(inspectionRequest) (inspectionResult, error) {
		called = true
		return inspectionResult{}, nil
	}
	t.Cleanup(func() { executeInspection = previous })
	if err := run([]string{"inspect", "must-not-be-opened", "--output-dir", destination}); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("existing destination error = %v", err)
	}
	if called {
		t.Fatal("existing output directory was rejected only after analysis")
	}
}

func TestInspectPreservesInputWhenOutputAliasesIt(t *testing.T) {
	for _, alias := range []string{"same path", "cleaned path", "symlink", "hardlink"} {
		t.Run(alias, func(t *testing.T) {
			root := t.TempDir()
			input := filepath.Join(root, "sample.sh")
			original := []byte("#!/bin/sh\n/usr/bin/id\n")
			if err := os.WriteFile(input, original, 0o600); err != nil {
				t.Fatal(err)
			}
			output := input
			switch alias {
			case "cleaned path":
				output = root + string(filepath.Separator) + "." + string(filepath.Separator) + "sample.sh"
			case "symlink", "hardlink":
				output = filepath.Join(root, "alias.sh")
				link := os.Symlink
				if alias == "hardlink" {
					link = os.Link
				}
				if err := link(input, output); err != nil {
					t.Fatal(err)
				}
			}
			previous := executeInspection
			called := false
			executeInspection = func(inspectionRequest) (inspectionResult, error) {
				called = true
				return inspectionResult{}, nil
			}
			t.Cleanup(func() { executeInspection = previous })
			bundle := filepath.Join(root, "case")
			err := run([]string{"inspect", input, "--format", "json", "-o", output, "--output-dir", bundle})
			if err == nil || exitCode(err) != 2 || !strings.Contains(err.Error(), "must not replace its input artifact") {
				t.Fatalf("input alias error = %v", err)
			}
			if called {
				t.Fatal("input alias was rejected only after analysis")
			}
			for _, path := range []string{input, output} {
				data, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(data, original) {
					t.Fatalf("input evidence changed at %s: data=%q err=%v", path, data, err)
				}
			}
			if _, err := os.Lstat(bundle); !os.IsNotExist(err) {
				t.Fatalf("rejected output created a case bundle: %v", err)
			}
		})
	}
}

func TestInspectRejectsOutputsInsideInputTree(t *testing.T) {
	for _, scenario := range []string{"member", "new file", "directory alias", "input alias", "leaf symlink", "case bundle"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			input := filepath.Join(root, "Sample.app")
			if err := os.Mkdir(input, 0o700); err != nil {
				t.Fatal(err)
			}
			member := filepath.Join(input, "payload.sh")
			original := []byte("#!/bin/sh\necho inert\n")
			if err := os.WriteFile(member, original, 0o600); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(root, "alias")
			if err := os.Symlink(input, alias); err != nil {
				t.Fatal(err)
			}
			output, flag := member, "-o"
			switch scenario {
			case "new file":
				output = filepath.Join(input, "report.json")
			case "directory alias":
				output = filepath.Join(alias, "payload.sh")
			case "input alias":
				input = alias
			case "leaf symlink":
				output = filepath.Join(input, "link")
				if err := os.Symlink(filepath.Join(root, "outside"), output); err != nil {
					t.Fatal(err)
				}
			case "case bundle":
				output, flag = filepath.Join(alias, "case"), "--output-dir"
			}
			previous := executeInspection
			called := false
			executeInspection = func(inspectionRequest) (inspectionResult, error) {
				called = true
				return inspectionResult{}, nil
			}
			t.Cleanup(func() { executeInspection = previous })
			err := run([]string{"inspect", input, flag, output})
			if err == nil || exitCode(err) != 2 || !strings.Contains(err.Error(), "outside its input directory") {
				t.Fatalf("input-tree output error = %v", err)
			}
			if called {
				t.Fatal("input-tree output was rejected only after analysis")
			}
			data, err := os.ReadFile(member)
			if err != nil || !bytes.Equal(data, original) {
				t.Fatalf("input member changed: data=%q err=%v", data, err)
			}
		})
	}
}

func TestInspectRejectsOutputInsideCaseBundle(t *testing.T) {
	for _, name := range []string{"report.json", "manifest.json", "nested/report.txt", "."} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			alias := filepath.Join(root, "alias")
			if err := os.Symlink(root, alias); err != nil {
				t.Fatal(err)
			}
			bundle := filepath.Join(root, "case")
			output := filepath.Join(alias, "case", name)
			previous := executeInspection
			called := false
			executeInspection = func(inspectionRequest) (inspectionResult, error) {
				called = true
				return inspectionResult{}, nil
			}
			t.Cleanup(func() { executeInspection = previous })
			err := runInspectWithInput([]string{"--stdin", "--input-kind", "shell", "--output-dir", bundle, "-o", output}, strings.NewReader("echo inert\n"))
			if err == nil || exitCode(err) != 2 || !strings.Contains(err.Error(), "outside its case bundle") {
				t.Fatalf("case-bundle output error = %v", err)
			}
			if called {
				t.Fatal("case-bundle output was rejected only after analysis")
			}
			if _, err := os.Lstat(bundle); !os.IsNotExist(err) {
				t.Fatalf("rejected output created a case bundle: %v", err)
			}
		})
	}
}

func TestInspectAllowsOutputsOutsideInputAndCaseBundle(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "sample")
	if err := os.Mkdir(input, 0o700); err != nil {
		t.Fatal(err)
	}
	member := filepath.Join(input, "payload.sh")
	original := []byte("#!/bin/sh\necho inert\n")
	if err := os.WriteFile(member, original, 0o600); err != nil {
		t.Fatal(err)
	}
	// A leaf symlink outside the source tree is itself replaced atomically;
	// its target remains untouched. A shared name prefix is not containment.
	output := filepath.Join(root, "sample-report.json")
	if err := os.Symlink(member, output); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "sample-case")
	if err := run([]string{"inspect", input, "--format", "json", "-o", output, "--output-dir", bundle}); err != nil {
		t.Fatal(err)
	}
	if _, err := report.Load(output); err != nil {
		t.Fatalf("outside output is not a valid report: %v", err)
	}
	data, err := os.ReadFile(member)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatalf("outside output changed input member: data=%q err=%v", data, err)
	}
}

func TestInspectProtectsCaseInsensitiveOutputAliases(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "sample")
	if err := os.Mkdir(input, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "SAMPLE")
	if same, err := sameFilePath(input, alias); err != nil || !same {
		t.Skip("requires a case-insensitive filesystem")
	}
	if err := validateInspectOutputLocations(input, filepath.Join(alias, "report.json"), ""); err == nil {
		t.Fatal("differently cased input-directory alias was accepted")
	}
	bundle := filepath.Join(root, "case")
	output := filepath.Join(root, "CASE", "report.json")
	err := runInspectWithInput([]string{"--stdin", "--input-kind", "shell", "--output-dir", bundle, "-o", output}, strings.NewReader("echo inert\n"))
	if err == nil || !strings.Contains(err.Error(), "outside its case bundle") {
		t.Fatalf("differently cased case-bundle output error = %v", err)
	}
	if _, err := report.Load(filepath.Join(bundle, "report.json")); err != nil {
		t.Fatalf("case-bundle report was overwritten: %v", err)
	}
}
