package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/0x4D31/maratus/internal/report"
	"github.com/0x4D31/maratus/internal/terminal"
	"github.com/0x4D31/maratus/internal/visualization"
)

const bundleSchemaVersion = "maratus.bundle.v0.1-preview.2"

type caseBundleManifest struct {
	SchemaVersion  string                        `json:"schema_version"`
	Tool           string                        `json:"tool"`
	ToolVersion    string                        `json:"tool_version"`
	ToolCommit     string                        `json:"tool_commit,omitempty"`
	ToolModified   bool                          `json:"tool_modified"`
	ToolSHA256     string                        `json:"tool_sha256"`
	Input          caseBundleManifestInput       `json:"input"`
	Analysis       report.AnalysisMetadata       `json:"analysis"`
	AnalysisSHA256 string                        `json:"analysis_sha256"`
	Supervision    caseBundleManifestSupervision `json:"supervision"`
	Outputs        []caseBundleManifestOutput    `json:"outputs"`
}

type caseBundleManifestSupervision struct {
	Mode              string `json:"mode"`
	Protocol          string `json:"protocol,omitempty"`
	WallSeconds       int    `json:"wall_seconds,omitempty"`
	CPUSeconds        uint64 `json:"cpu_seconds,omitempty"`
	MemoryTargetBytes int64  `json:"memory_target_bytes,omitempty"`
	OutputBytes       int64  `json:"output_bytes,omitempty"`
	FileBytes         uint64 `json:"file_bytes,omitempty"`
	OpenFiles         uint64 `json:"open_files,omitempty"`
	CoreBytes         uint64 `json:"core_bytes"`
}

type caseBundleManifestInput struct {
	Artifact string `json:"artifact"`
	SHA256   string `json:"sha256,omitempty"`
}

type caseBundleManifestOutput struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

func runInspect(args []string) error {
	return runInspectWithInput(args, os.Stdin)
}

func runInspectWithInput(args []string, stdin io.Reader) error {
	fs := newFlagSet("inspect")
	formatValue := fs.String("format", "text", "output format: text, json, summary-json, or html")
	output := new(string)
	fs.StringVar(output, "o", "", "output path; default standard output")
	fs.StringVar(output, "output", "", "output path; default standard output")
	outputDir := fs.String("output-dir", "", "create a private deterministic case bundle in a new directory")
	stdinInput := fs.Bool("stdin", false, "read one bounded artifact from standard input")
	inputKind := fs.String("input-kind", "", "stdin content kind: "+strings.Join(report.InlineInputKinds(), ", "))
	options := addAnalysisFlags(fs)
	presentation := addPresentationFlags(fs)
	if wantsHelp(fs, args) {
		inspectUsage(os.Stdout)
		return nil
	}
	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return newUsageError(err)
	}
	format, err := parseOutputFormat(*formatValue, "text", "json", "summary-json", "html")
	if err != nil {
		return newUsageError(err)
	}
	toStdout := strings.TrimSpace(*output) == "" || *output == "-"
	textOptions, err := presentation.resolveForTerminal(format, toStdout && terminal.IsTerminal(os.Stdout))
	if err != nil {
		return newUsageError(err)
	}
	opts, err := validatedOptions(options)
	if err != nil {
		return newUsageError(err)
	}
	if strings.TrimSpace(*outputDir) != "" {
		if err := validateCaseBundleDestination(*outputDir); err != nil {
			return fmt.Errorf("write case bundle %q: %w", *outputDir, err)
		}
	}

	var request inspectionRequest
	if *stdinInput {
		if len(positionals) != 0 {
			return usageErrorf("inspect --stdin does not accept a path")
		}
		if strings.TrimSpace(*inputKind) == "" {
			return usageErrorf("inspect --stdin requires --input-kind")
		}
		normalizedKind, err := report.NormalizeInlineInputKind(*inputKind)
		if err != nil {
			return newUsageError(err)
		}
		readLimit, limitFlag := inlineInputReadLimit(opts.MaxFileBytes, opts.MaxTotalBytes)
		data, err := readInlineInput(stdin, readLimit, limitFlag)
		if err != nil {
			return err
		}
		if normalizedKind == "shell" && strings.TrimSpace(string(data)) == "" {
			return usageErrorf("inspect --stdin shell input must not be blank")
		}
		request = inspectionRequest{Mode: "inline", InlineKind: normalizedKind, InlineData: data, Options: opts}
	} else {
		if flagWasSet(fs, "input-kind") {
			return usageErrorf("--input-kind requires --stdin")
		}
		if len(positionals) != 1 {
			return usageErrorf("inspect requires exactly one artifact path, or --stdin with --input-kind")
		}
		request = inspectionRequest{Mode: "path", Path: positionals[0], Options: opts}
	}
	if request.Mode == "path" && !toStdout {
		same, err := sameFilePath(request.Path, *output)
		if err != nil {
			return fmt.Errorf("validate inspect output: %w", err)
		}
		if same {
			return usageErrorf("inspect output must not replace its input artifact")
		}
	}
	if err := validateInspectOutputLocations(request.Path, *output, *outputDir); err != nil {
		return err
	}
	result, err := executeInspection(request)
	if err != nil {
		if request.Mode == "inline" {
			return fmt.Errorf("inspect stdin: %w", err)
		}
		return err
	}
	rep := result.Report
	if strings.TrimSpace(*outputDir) != "" {
		if err := writeCaseBundle(*outputDir, rep, result.Supervision); err != nil {
			return fmt.Errorf("write case bundle %q: %w", *outputDir, err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "Wrote private case bundle to %s\n", terminal.EscapeTruncate(*outputDir, 512)); err != nil {
			return err
		}
	}
	if toStdout {
		return writeReportOutput(os.Stdout, rep, format, textOptions)
	}
	// A newly created bundle now has a filesystem identity, which also
	// catches differently cased aliases on case-insensitive filesystems.
	if strings.TrimSpace(*outputDir) != "" {
		if err := validateInspectOutputLocations("", *output, *outputDir); err != nil {
			return err
		}
	}
	if err := writeFileAtomically(*output, func(writer io.Writer) error { return writeReportOutput(writer, rep, format, textOptions) }); err != nil {
		return fmt.Errorf("write %s output %q: %w", format, *output, err)
	}
	_, err = fmt.Fprintf(os.Stderr, "Wrote %s report to %s\n", format, terminal.EscapeTruncate(*output, 512))
	return err
}

func writeCaseBundle(directory string, rep report.Report, supervision caseBundleManifestSupervision) (retErr error) {
	if err := validateCaseBundleDestination(directory); err != nil {
		return err
	}
	directory = filepath.Clean(strings.TrimSpace(directory))
	parent := filepath.Dir(directory)
	temporary, err := os.MkdirTemp(parent, ".maratus-case-*")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(temporary); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("remove temporary case-bundle directory: %w", err))
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}

	outputs := map[string][]byte{}
	var buffer bytes.Buffer
	if err := report.WriteJSON(&buffer, rep); err != nil {
		return err
	}
	outputs["report.json"] = append([]byte(nil), buffer.Bytes()...)
	buffer.Reset()
	if err := report.WriteSummaryJSON(&buffer, rep); err != nil {
		return err
	}
	outputs["summary.json"] = append([]byte(nil), buffer.Bytes()...)
	buffer.Reset()
	if err := report.WriteSummaryText(&buffer, rep, report.TextOptions{Verbosity: report.TextConcise, Color: false}); err != nil {
		return err
	}
	outputs["summary.txt"] = append([]byte(nil), buffer.Bytes()...)
	buffer.Reset()
	if err := visualization.Write(&buffer, rep, visualization.Options{}); err != nil {
		return err
	}
	outputs["report.html"] = append([]byte(nil), buffer.Bytes()...)

	toolDigest, err := runningToolSHA256()
	if err != nil {
		return fmt.Errorf("digest running Maratus executable: %w", err)
	}
	analysisDigest, err := canonicalValueSHA256(rep.Analysis)
	if err != nil {
		return fmt.Errorf("digest normalized analysis settings: %w", err)
	}
	manifest := caseBundleManifest{
		SchemaVersion: bundleSchemaVersion, Tool: rep.Tool, ToolVersion: rep.ToolVersion, ToolCommit: rep.ToolCommit, ToolModified: rep.ToolModified,
		ToolSHA256: toolDigest, Input: caseBundleManifestInput{Artifact: rep.Artifact, SHA256: presentationRootDigest(rep)}, Analysis: rep.Analysis, AnalysisSHA256: analysisDigest,
		Supervision: supervision,
		Outputs:     make([]caseBundleManifestOutput, 0, len(outputs)),
	}
	for _, name := range []string{"report.json", "summary.json", "summary.txt", "report.html"} {
		data := outputs[name]
		digest := sha256.Sum256(data)
		manifest.Outputs = append(manifest.Outputs, caseBundleManifestOutput{Path: name, SHA256: hex.EncodeToString(digest[:]), Bytes: len(data)})
		if err := writePrivateBundleFile(filepath.Join(temporary, name), data); err != nil {
			return err
		}
	}
	buffer.Reset()
	if err := report.WriteJSON(&buffer, manifest); err != nil {
		return err
	}
	if err := writePrivateBundleFile(filepath.Join(temporary, "manifest.json"), buffer.Bytes()); err != nil {
		return err
	}
	if _, err := os.Lstat(directory); err == nil {
		return fmt.Errorf("refusing to overwrite existing path")
	} else if !os.IsNotExist(err) {
		return err
	}
	return renameDirectoryNoReplace(temporary, directory)
}

func validateCaseBundleDestination(directory string) error {
	directory = filepath.Clean(strings.TrimSpace(directory))
	if directory == "." || directory == "" {
		return fmt.Errorf("output directory must name a new case directory")
	}
	if _, err := os.Lstat(directory); err == nil {
		return fmt.Errorf("refusing to overwrite existing path")
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func runningToolSHA256() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func canonicalValueSHA256(value any) (string, error) {
	var encoded bytes.Buffer
	if err := report.WriteJSON(&encoded, value); err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded.Bytes())
	return hex.EncodeToString(digest[:]), nil
}

func writePrivateBundleFile(path string, data []byte) error {
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

func presentationRootDigest(rep report.Report) string {
	digest := ""
	count := 0
	for _, node := range rep.ArtifactNodes {
		if node.ParentID == "" {
			count++
			digest = node.SHA256
		}
	}
	if count == 1 {
		return digest
	}
	return ""
}

func inlineInputReadLimit(maxFileBytes, maxTotalBytes int64) (int64, string) {
	if maxTotalBytes < maxFileBytes {
		return maxTotalBytes, "--max-total-bytes"
	}
	return maxFileBytes, "--max-file-bytes"
}

func readInlineInput(input io.Reader, maxBytes int64, limitFlag string) ([]byte, error) {
	readLimit := maxBytes
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	limited := &io.LimitedReader{R: input, N: readLimit}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read inspect stdin: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("inspect stdin exceeds %s %d", limitFlag, maxBytes)
	}
	return data, nil
}
