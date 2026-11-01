package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/report"
)

const inspectWorkerHelperArgument = "--maratus-test-worker-helper"

func TestInspectWorkerEnvironmentDoesNotInheritCallerSecrets(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "must-not-cross-worker-boundary")
	t.Setenv("MARATUS_ZIP_PASSWORD", "must-not-be-duplicated-in-environment")
	workspace := t.TempDir()
	dmgWorkspace := t.TempDir()
	environment := inspectWorkerEnvironment(workspace, dmgWorkspace)
	joined := strings.Join(environment, "\n")
	for _, forbidden := range []string{"GITHUB_TOKEN", "must-not-cross-worker-boundary", "MARATUS_ZIP_PASSWORD", "must-not-be-duplicated-in-environment"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("worker environment inherited %q: %q", forbidden, joined)
		}
	}
	for _, required := range []string{
		inspectWorkerMarkerEnv + "=1",
		"TMPDIR=" + workspace,
		"TMP=" + workspace,
		"TEMP=" + workspace,
		artifact.DMGTemporaryDirectoryEnvironment + "=" + dmgWorkspace,
	} {
		if !slices.Contains(environment, required) {
			t.Fatalf("worker environment missing %q: %#v", required, environment)
		}
	}
	memoryEntries := 0
	for _, entry := range environment {
		if strings.HasPrefix(entry, "GOMEMLIMIT=") {
			memoryEntries++
			if entry == "GOMEMLIMIT=" || !strings.HasSuffix(entry, "B") {
				t.Fatalf("invalid worker memory target: %q", entry)
			}
		}
	}
	if memoryEntries != 1 {
		t.Fatalf("worker environment memory targets = %d: %#v", memoryEntries, environment)
	}
}

func TestInspectWorkerMemoryTargetPreservesLowerInheritedLimit(t *testing.T) {
	if got := boundedInspectWorkerMemoryTarget(256 << 20); got != 256<<20 {
		t.Fatalf("lower inherited target = %d", got)
	}
	if got := boundedInspectWorkerMemoryTarget(-1); got != inspectWorkerMemoryBytes {
		t.Fatalf("unbounded inherited target = %d", got)
	}
	if got := boundedInspectWorkerMemoryTarget(2 << 30); got != inspectWorkerMemoryBytes {
		t.Fatalf("higher inherited target = %d", got)
	}
}

func TestSupervisedInspectionMatchesDirectCanonicalReport(t *testing.T) {
	installInspectWorkerHelper(t)
	path := filepath.Join(t.TempDir(), "fixture.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n/usr/bin/whoami\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	request := inspectionRequest{Mode: "path", Path: path, Options: artifact.Options{}.Normalized()}
	direct, err := executeDirectInspection(request)
	if err != nil {
		t.Fatal(err)
	}
	supervised, err := executeSupervisedInspection(request)
	if err != nil {
		t.Fatal(err)
	}
	if supervised.Supervision.Mode != "isolated-worker" || supervised.Supervision.Protocol != inspectWorkerProtocol {
		t.Fatalf("supervision = %#v", supervised.Supervision)
	}
	if !bytes.Equal(canonicalReportBytes(t, direct.Report), canonicalReportBytes(t, supervised.Report)) {
		t.Fatal("worker changed canonical report bytes")
	}
}

func TestSupervisedInlineInspectionUsesPrivateSpool(t *testing.T) {
	installInspectWorkerHelper(t)
	request := inspectionRequest{
		Mode: "inline", InlineKind: "shell", InlineData: []byte("#!/bin/sh\n/usr/bin/id\n"),
		Options: artifact.Options{AllowDMGMount: true}.Normalized(),
	}
	direct, err := executeDirectInspection(request)
	if err != nil {
		t.Fatal(err)
	}
	supervised, err := executeSupervisedInspection(request)
	if err != nil {
		t.Fatal(err)
	}
	if supervised.Report.Artifact != "<stdin:shell>" {
		t.Fatalf("artifact = %q", supervised.Report.Artifact)
	}
	if !bytes.Equal(canonicalReportBytes(t, direct.Report), canonicalReportBytes(t, supervised.Report)) {
		t.Fatal("worker stdin spool changed canonical report bytes")
	}
}

func TestInspectWorkerRejectsMalformedProtocolInput(t *testing.T) {
	for name, input := range map[string]string{
		"unknown field":  `{"schema_version":"maratus.worker.v0.1","mode":"path","path":"x","options":{},"extra":true}`,
		"trailing value": `{"schema_version":"maratus.worker.v0.1","mode":"path","path":"x","options":{}} {}`,
		"wrong version":  `{"schema_version":"maratus.worker.v9","mode":"path","path":"x","options":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			command := inspectWorkerHelperCommand(t)
			command.Env = inspectWorkerEnvironment(t.TempDir(), "")
			command.Stdin = strings.NewReader(input)
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("malformed request succeeded: %s", output)
			}
			if len(output) == 0 {
				t.Fatal("malformed request failed without an explanation")
			}
		})
	}
}

func TestInspectWorkerDMGDirectoryCleanupNeverRecurses(t *testing.T) {
	root := filepath.Join(t.TempDir(), "dmg-worker")
	retained := filepath.Join(root, "mount", "Volume", "evidence")
	if err := os.MkdirAll(filepath.Dir(retained), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(retained, []byte("must remain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeInspectWorkerDMGDirectory(root); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("non-empty DMG workspace cleanup error = %v", err)
	}
	if data, err := os.ReadFile(retained); err != nil || string(data) != "must remain" {
		t.Fatalf("DMG workspace cleanup traversed retained contents: data=%q err=%v", data, err)
	}
	empty := filepath.Join(t.TempDir(), "empty-dmg-worker")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removeInspectWorkerDMGDirectory(empty); err != nil {
		t.Fatal(err)
	}
}

func TestInternalWorkerCommandRequiresMarker(t *testing.T) {
	if err := run([]string{"__worker-inspect"}); err == nil || exitCode(err) != 2 {
		t.Fatalf("hidden worker without marker error = %v", err)
	}
}

func TestWorkerBoundsStderrAndKillsTimedOutProcessGroup(t *testing.T) {
	buffer := &boundedWorkerBuffer{remaining: 4}
	if written, err := buffer.Write([]byte("abcdef")); written != 6 || err != nil {
		t.Fatalf("bounded stderr write = %d, %v", written, err)
	}
	if got := buffer.String(); got != "abcd [stderr truncated]" {
		t.Fatalf("bounded stderr = %q", got)
	}

	command := exec.Command(os.Args[0])
	command.Env = environmentWith(nil, "MARATUS_TEST_SLEEPING_WORKER", "1")
	configureInspectWorkerProcess(command)
	if err, timedOut := runInspectWorkerCommand(command, 20*time.Millisecond); !timedOut || err == nil {
		t.Fatalf("timeout result = err %v, timed_out %v", err, timedOut)
	}
}

func TestValidateArtifactInspectionInputRejectsSavedReportBeforeWorker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	rep, err := report.InspectInline([]byte("#!/bin/sh\n/usr/bin/id\n"), "shell", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := report.WriteJSON(&encoded, rep); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateArtifactInspectionInput(path); err == nil || exitCode(err) != 2 {
		t.Fatalf("saved report validation error = %v", err)
	}
}

func installInspectWorkerHelper(t *testing.T) {
	t.Helper()
	previous := newInspectWorkerCommand
	newInspectWorkerCommand = func() (*exec.Cmd, error) { return inspectWorkerHelperCommand(t), nil }
	t.Cleanup(func() { newInspectWorkerCommand = previous })
}

func inspectWorkerHelperCommand(t *testing.T) *exec.Cmd {
	t.Helper()
	return exec.Command(os.Args[0], inspectWorkerHelperArgument)
}

func canonicalReportBytes(t *testing.T, value report.Report) []byte {
	t.Helper()
	var encoded bytes.Buffer
	if err := report.WriteJSON(&encoded, value); err != nil {
		t.Fatal(err)
	}
	var check report.Report
	if err := json.Unmarshal(encoded.Bytes(), &check); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}
