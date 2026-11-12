package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/report"
)

func TestRenderSavedReportAsDeterministicHTML(t *testing.T) {
	root := t.TempDir()
	reportPath := filepath.Join(root, "report.json")
	writeRenderReport(t, reportPath, "https://visual.example/p")

	firstPath := filepath.Join(root, "report.html")
	if err := run([]string{"render", reportPath, "--format", "html", "--output", firstPath}); err != nil {
		t.Fatal(err)
	}
	assertRenderedHTML(t, firstPath, "https://visual.example/p")

	secondPath := filepath.Join(root, "report-again.html")
	if err := run([]string{"render", "--format", "html", "-o", secondPath, reportPath}); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("HTML rendering is not deterministic for the same report")
	}

	titledPath := filepath.Join(root, "titled.html")
	if err := run([]string{"render", reportPath, "--format", "html", "--title", "help", "-o", titledPath}); err != nil {
		t.Fatal(err)
	}
	assertRenderedHTML(t, titledPath, `"title":"help"`)
}

func TestRenderHTMLCanStreamToStdout(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "report.json")
	writeRenderReport(t, reportPath, "streamed")
	data := captureStdout(t, func() error { return run([]string{"render", reportPath, "--format", "html"}) })
	if !bytes.Contains(data, []byte("<!doctype html>")) || !bytes.Contains(data, []byte("streamed")) {
		t.Fatalf("streamed HTML missing markers: %s", data)
	}
}

func TestRenderSavedReportAsSummaryJSON(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "report.json")
	writeRenderReport(t, reportPath, "https://static.example/inert")
	data := captureStdout(t, func() error { return run([]string{"render", reportPath, "--format", "summary-json"}) })
	var summary report.Summary
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.SchemaVersion != report.SummarySchemaVersion || summary.ReportSchemaVersion != report.SchemaVersion {
		t.Fatalf("rendered summary identity = %#v", summary)
	}
}

func TestRenderRejectsOrdinaryArtifactAndAnalysisFlags(t *testing.T) {
	root := t.TempDir()
	artifactPath := filepath.Join(root, "sample.sh")
	if err := os.WriteFile(artifactPath, []byte("echo safe\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"render", artifactPath})
	if err == nil || exitCode(err) != 1 || !errors.Is(err, report.ErrNotReport) {
		t.Fatalf("ordinary artifact error = %v, code %d", err, exitCode(err))
	}

	reportPath := filepath.Join(root, "report.json")
	writeRenderReport(t, reportPath, "fixture")
	for _, flags := range [][]string{{"--include-unreferenced"}, {"--architecture", "arm64"}, {"--allow-dmg-mount"}} {
		args := append([]string{"render", reportPath}, flags...)
		if err := run(args); err == nil || exitCode(err) != 2 {
			t.Fatalf("analysis flags %v error = %v, code %d", flags, err, exitCode(err))
		}
	}
}

func TestRenderOutputValidationAndReplacement(t *testing.T) {
	root := t.TempDir()
	reportPath := filepath.Join(root, "report.json")
	writeRenderReport(t, reportPath, "fixture")
	if err := run([]string{"render", reportPath, "--format", "html", "-o", reportPath}); err == nil || exitCode(err) != 2 {
		t.Fatalf("same-file output error = %v", err)
	}

	output := filepath.Join(root, "analysis.html")
	if err := os.WriteFile(output, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"render", reportPath, "--format", "html", "-o", output}); err != nil {
		t.Fatal(err)
	}
	assertRenderedHTML(t, output, "maratus.visualization.v0.15")

	missingParent := filepath.Join(root, "missing", "analysis.html")
	if err := run([]string{"render", reportPath, "--format", "html", "-o", missingParent}); err == nil || exitCode(err) != 1 {
		t.Fatalf("missing output directory error = %v, code %d", err, exitCode(err))
	}
}

func TestRenderTextColorAutoUsesTheActualDestination(t *testing.T) {
	root := t.TempDir()
	reportPath := filepath.Join(root, "report.json")
	writeRenderReport(t, reportPath, "fixture")

	autoPath := filepath.Join(root, "auto.txt")
	if err := run([]string{"render", reportPath, "--color", "auto", "-o", autoPath}); err != nil {
		t.Fatal(err)
	}
	auto, err := os.ReadFile(autoPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(auto, []byte("\x1b[")) {
		t.Fatalf("auto color escaped a non-terminal file: %q", auto)
	}

	alwaysPath := filepath.Join(root, "always.txt")
	if err := run([]string{"render", reportPath, "--color", "always", "-o", alwaysPath}); err != nil {
		t.Fatal(err)
	}
	always, err := os.ReadFile(alwaysPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(always, []byte("\x1b[")) {
		t.Fatalf("explicit color was not preserved for file output: %q", always)
	}
}

func TestRenderRejectsHardlinkAndSymlinkOutputAliases(t *testing.T) {
	root := t.TempDir()
	reportPath := filepath.Join(root, "report.json")
	writeRenderReport(t, reportPath, "fixture")
	for _, test := range []struct {
		name string
		make func(string) error
	}{
		{name: "hardlink", make: func(path string) error { return os.Link(reportPath, path) }},
		{name: "symlink", make: func(path string) error { return os.Symlink(reportPath, path) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(root, test.name+".html")
			if err := test.make(output); err != nil {
				t.Skipf("link unavailable: %v", err)
			}
			err := run([]string{"render", reportPath, "--format", "html", "-o", output})
			if err == nil || exitCode(err) != 2 || !strings.Contains(err.Error(), "must not replace its input") {
				t.Fatalf("alias output error = %v, code %d", err, exitCode(err))
			}
		})
	}
}

func TestWriteFileAtomicallyPreservesExistingOutputOnFailure(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "analysis.html")
	if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := errors.New("render failed")
	err := writeFileAtomically(output, func(w io.Writer) error {
		if _, err := io.WriteString(w, "partial"); err != nil {
			return err
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("atomic write error = %v, want %v", err, want)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "existing" {
		t.Fatalf("failed render changed existing output: %q", data)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".maratus-render-") {
			t.Fatalf("temporary output was not removed: %s", entry.Name())
		}
	}
}

func writeRenderReport(t *testing.T, path, artifactName string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(savedReportJSONForTest(artifactName, "")), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertRenderedHTML(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"<!doctype html>", "maratus.visualization.v0.15", "Content-Security-Policy", want} {
		if !bytes.Contains(data, []byte(marker)) {
			t.Fatalf("rendered HTML %s missing %q", path, marker)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("rendered HTML permissions = %o, want 600", got)
	}
}
