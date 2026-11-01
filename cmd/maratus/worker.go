package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/report"
)

const (
	inspectWorkerProtocol            = "maratus.worker.v0.1"
	inspectWorkerMarkerEnv           = "MARATUS_INTERNAL_WORKER"
	inspectWorkerRequestLimit        = 1 << 20
	inspectWorkerStderrLimit         = 64 << 10
	inspectWorkerWallTimeout         = 360 * time.Second
	inspectWorkerCPUSeconds   uint64 = 300
	inspectWorkerFileBytes    uint64 = 512 << 20
	inspectWorkerOpenFiles    uint64 = 256
	inspectWorkerMemoryBytes  int64  = 1 << 30
)

type inspectionRequest struct {
	Mode       string
	Path       string
	InlineKind string
	InlineData []byte
	Options    artifact.Options
}

type inspectionResult struct {
	Report      report.Report
	Supervision caseBundleManifestSupervision
}

type inspectWorkerRequest struct {
	SchemaVersion string           `json:"schema_version"`
	Mode          string           `json:"mode"`
	Path          string           `json:"path"`
	InlineKind    string           `json:"inline_kind,omitempty"`
	Options       artifact.Options `json:"options"`
}

var executeInspection = executeSupervisedInspection

var newInspectWorkerCommand = func() (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return exec.Command(executable, "__worker-inspect"), nil
}

func executeDirectInspection(request inspectionRequest) (inspectionResult, error) {
	var rep report.Report
	var err error
	switch request.Mode {
	case "path":
		rep, err = inspectArtifactOnly(request.Path, request.Options)
	case "inline":
		rep, err = report.InspectInline(request.InlineData, request.InlineKind, request.Options)
	default:
		return inspectionResult{}, fmt.Errorf("unsupported inspection mode %q", request.Mode)
	}
	if err != nil {
		return inspectionResult{}, err
	}
	return inspectionResult{Report: rep, Supervision: directSupervision()}, nil
}

func executeSupervisedInspection(request inspectionRequest) (result inspectionResult, retErr error) {
	if request.Mode == "path" {
		if err := validateArtifactInspectionInput(request.Path); err != nil {
			return inspectionResult{}, err
		}
	}

	workspace, err := os.MkdirTemp("", ".maratus-worker-*")
	if err != nil {
		return inspectionResult{}, fmt.Errorf("create inspect worker directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(workspace); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("remove inspect worker directory: %w", err))
		}
	}()
	if err := os.Chmod(workspace, 0o700); err != nil {
		return inspectionResult{}, fmt.Errorf("secure inspect worker directory: %w", err)
	}

	dmgWorkspace := ""
	if request.Options.AllowDMGMount && runtime.GOOS == "darwin" {
		dmgWorkspace, err = os.MkdirTemp("", ".maratus-dmg-worker-*")
		if err != nil {
			return inspectionResult{}, fmt.Errorf("create inspect worker DMG directory: %w", err)
		}
		defer func() {
			if err := removeInspectWorkerDMGDirectory(dmgWorkspace); err != nil {
				retErr = errors.Join(retErr, err)
			}
		}()
		if err := os.Chmod(dmgWorkspace, 0o700); err != nil {
			return inspectionResult{}, fmt.Errorf("secure inspect worker DMG directory: %w", err)
		}
	}

	workerRequest := inspectWorkerRequest{
		SchemaVersion: inspectWorkerProtocol,
		Mode:          request.Mode,
		Path:          request.Path,
		InlineKind:    request.InlineKind,
		Options:       request.Options,
	}
	if request.Mode == "inline" {
		workerRequest.Path = filepath.Join(workspace, "inline-input")
		if err := writePrivateWorkerFile(workerRequest.Path, request.InlineData); err != nil {
			return inspectionResult{}, fmt.Errorf("spool inspect stdin: %w", err)
		}
	}

	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(workerRequest); err != nil {
		return inspectionResult{}, fmt.Errorf("encode inspect worker request: %w", err)
	}
	if encoded.Len() > inspectWorkerRequestLimit {
		return inspectionResult{}, fmt.Errorf("inspect worker request exceeds %d-byte limit", inspectWorkerRequestLimit)
	}

	resultPath := filepath.Join(workspace, "report.json")
	resultFile, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return inspectionResult{}, fmt.Errorf("create inspect worker report: %w", err)
	}
	output := &boundedWorkerFileWriter{file: resultFile, remaining: report.MaxReportInputBytes}
	stderr := &boundedWorkerBuffer{remaining: inspectWorkerStderrLimit}

	command, err := newInspectWorkerCommand()
	if err != nil {
		_ = resultFile.Close()
		return inspectionResult{}, fmt.Errorf("prepare inspect worker: %w", err)
	}
	configureInspectWorkerProcess(command)
	command.Env = inspectWorkerEnvironment(workspace, dmgWorkspace)
	command.Stdin = bytes.NewReader(encoded.Bytes())
	command.Stdout = output
	command.Stderr = stderr

	err, timedOut := runInspectWorkerCommand(command, inspectWorkerWallTimeout)
	if syncErr := resultFile.Sync(); err == nil && syncErr != nil {
		err = syncErr
	}
	if closeErr := resultFile.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if output.exceeded {
		return inspectionResult{}, fmt.Errorf("inspect worker report exceeds %d-byte limit", report.MaxReportInputBytes)
	}
	if timedOut {
		return inspectionResult{}, fmt.Errorf("inspect worker exceeded %s wall limit", inspectWorkerWallTimeout)
	}
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return inspectionResult{}, fmt.Errorf("inspect worker failed: %s", detail)
	}

	rep, err := report.Load(resultPath)
	if err != nil {
		return inspectionResult{}, fmt.Errorf("validate inspect worker report: %w", err)
	}
	return inspectionResult{Report: rep, Supervision: workerSupervision()}, nil
}

// inspectWorkerEnvironment deliberately does not inherit the caller's
// environment. Hostile artifact parsing does not need repository tokens,
// cloud credentials, proxy settings, shell hooks, or unrelated application
// secrets. The ZIP password, when supplied, travels only inside the bounded
// private worker request because the analyzer actually needs it.
func inspectWorkerEnvironment(workspace, dmgWorkspace string) []string {
	memoryTarget := boundedInspectWorkerMemoryTarget(debug.SetMemoryLimit(-1))
	environment := []string{
		inspectWorkerMarkerEnv + "=1",
		fmt.Sprintf("GOMEMLIMIT=%dB", memoryTarget),
		"TMPDIR=" + workspace,
		"TMP=" + workspace,
		"TEMP=" + workspace,
	}
	if dmgWorkspace != "" {
		environment = append(environment, artifact.DMGTemporaryDirectoryEnvironment+"="+dmgWorkspace)
	}
	return environment
}

func removeInspectWorkerDMGDirectory(path string) error {
	if path == "" {
		return nil
	}
	// Never recurse here. A non-empty directory may contain a mount whose
	// detach state the worker could not confirm.
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("private inspect worker DMG directory retained at %q: %w", path, err)
	}
	return nil
}

func runInspectWorker(input io.Reader, output io.Writer) error {
	if os.Getenv(inspectWorkerMarkerEnv) != "1" {
		return usageErrorf("internal inspect worker is unavailable")
	}
	memoryLimit := boundedInspectWorkerMemoryTarget(debug.SetMemoryLimit(-1))
	debug.SetMemoryLimit(memoryLimit)
	if err := applyInspectWorkerResourceLimits(); err != nil {
		return fmt.Errorf("apply inspect worker limits: %w", err)
	}

	limited := io.LimitReader(input, inspectWorkerRequestLimit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read inspect worker request: %w", err)
	}
	if len(data) > inspectWorkerRequestLimit {
		return fmt.Errorf("inspect worker request exceeds %d-byte limit", inspectWorkerRequestLimit)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request inspectWorkerRequest
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("decode inspect worker request: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode inspect worker request: %w", err)
	}
	if request.SchemaVersion != inspectWorkerProtocol {
		return fmt.Errorf("unsupported inspect worker protocol %q", request.SchemaVersion)
	}
	options, err := validatedOptions(func() artifact.Options { return request.Options })
	if err != nil {
		return fmt.Errorf("invalid inspect worker options: %w", err)
	}
	if options.AllowDMGMount && runtime.GOOS == "darwin" && strings.TrimSpace(os.Getenv(artifact.DMGTemporaryDirectoryEnvironment)) == "" {
		return fmt.Errorf("inspect worker DMG directory is unavailable")
	}

	var rep report.Report
	switch request.Mode {
	case "path":
		if request.Path == "" || request.InlineKind != "" {
			return fmt.Errorf("invalid path-mode inspect worker request")
		}
		rep, err = report.InspectPath(request.Path, options)
		if err != nil {
			err = fmt.Errorf("inspect artifact %q: %w", request.Path, err)
		}
	case "inline":
		kind, kindErr := report.NormalizeInlineInputKind(request.InlineKind)
		if kindErr != nil {
			return kindErr
		}
		maxBytes, limitFlag := inlineInputReadLimit(options.MaxFileBytes, options.MaxTotalBytes)
		data, readErr := readInlineWorkerFile(request.Path, maxBytes, limitFlag)
		if readErr != nil {
			return readErr
		}
		rep, err = report.InspectInline(data, kind, options)
	default:
		return fmt.Errorf("unsupported inspect worker mode %q", request.Mode)
	}
	if err != nil {
		return err
	}
	return report.WriteJSON(output, rep)
}

func boundedInspectWorkerMemoryTarget(inherited int64) int64 {
	if inherited >= 0 && inherited < inspectWorkerMemoryBytes {
		return inherited
	}
	return inspectWorkerMemoryBytes
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("trailing JSON value")
}

func readInlineWorkerFile(path string, maxBytes int64, limitFlag string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open inspect worker inline input: %w", err)
	}
	defer func() { _ = file.Close() }()
	return readInlineInput(file, maxBytes, limitFlag)
}

func writePrivateWorkerFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func runInspectWorkerCommand(command *exec.Cmd, timeout time.Duration) (error, bool) {
	if err := command.Start(); err != nil {
		return err, false
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err, false
	case <-timer.C:
		_ = killInspectWorkerProcess(command.Process)
		return <-done, true
	}
}

func environmentWith(environment []string, key, value string) []string {
	if environment == nil {
		environment = os.Environ()
	}
	prefix := key + "="
	out := make([]string, 0, len(environment)+1)
	for _, item := range environment {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}

type boundedWorkerFileWriter struct {
	file      *os.File
	remaining int64
	exceeded  bool
}

func (writer *boundedWorkerFileWriter) Write(data []byte) (int, error) {
	if writer.remaining <= 0 || int64(len(data)) > writer.remaining {
		writer.exceeded = true
		return 0, fmt.Errorf("inspect worker report output limit reached")
	}
	written, err := writer.file.Write(data)
	writer.remaining -= int64(written)
	return written, err
}

type boundedWorkerBuffer struct {
	buffer    bytes.Buffer
	remaining int
	exceeded  bool
}

func (writer *boundedWorkerBuffer) Write(data []byte) (int, error) {
	original := len(data)
	if len(data) > writer.remaining {
		writer.exceeded = true
	}
	if writer.remaining > 0 {
		keep := min(len(data), writer.remaining)
		_, _ = writer.buffer.Write(data[:keep])
		writer.remaining -= keep
	}
	return original, nil
}

func (writer *boundedWorkerBuffer) String() string {
	value := writer.buffer.String()
	if writer.exceeded {
		value += " [stderr truncated]"
	}
	return value
}

func workerSupervision() caseBundleManifestSupervision {
	return caseBundleManifestSupervision{
		Mode: "isolated-worker", Protocol: inspectWorkerProtocol,
		WallSeconds: int(inspectWorkerWallTimeout / time.Second), CPUSeconds: inspectWorkerCPUSeconds,
		MemoryTargetBytes: inspectWorkerMemoryBytes, OutputBytes: report.MaxReportInputBytes,
		FileBytes: inspectWorkerFileBytes, OpenFiles: inspectWorkerOpenFiles, CoreBytes: 0,
	}
}

func directSupervision() caseBundleManifestSupervision {
	return caseBundleManifestSupervision{Mode: "in-process"}
}
