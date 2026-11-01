package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/0x4D31/maratus/internal/report"
	"github.com/0x4D31/maratus/internal/terminal"
	"github.com/0x4D31/maratus/internal/visualization"
)

func runRender(args []string) error {
	fs := newFlagSet("render")
	formatValue := fs.String("format", "text", "output format: text, json, summary-json, or html")
	output := new(string)
	fs.StringVar(output, "o", "", "output path; default standard output")
	fs.StringVar(output, "output", "", "output path; default standard output")
	title := fs.String("title", "", "custom HTML title")
	presentation := addPresentationFlags(fs)
	if wantsHelp(fs, args) {
		renderUsage(os.Stdout)
		return nil
	}
	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return newUsageError(err)
	}
	if len(positionals) != 1 {
		return usageErrorf("render requires exactly one saved Maratus report")
	}
	format, err := parseOutputFormat(*formatValue, "text", "json", "summary-json", "html")
	if err != nil {
		return newUsageError(err)
	}
	if strings.TrimSpace(*title) != "" && format != "html" {
		return usageErrorf("--title applies only to --format html")
	}
	toStdout := strings.TrimSpace(*output) == "" || *output == "-"
	textOptions, err := presentation.resolveForTerminal(format, toStdout && terminal.IsTerminal(os.Stdout))
	if err != nil {
		return newUsageError(err)
	}
	rep, err := report.Load(positionals[0])
	if err != nil {
		return fmt.Errorf("load saved report %q: %w", positionals[0], err)
	}

	write := func(writer io.Writer) error {
		switch format {
		case "text", "json", "summary-json":
			return writeReportOutput(writer, rep, format, textOptions)
		case "html":
			return visualization.Write(writer, rep, visualization.Options{Title: *title})
		default:
			return fmt.Errorf("unsupported render format %q", format)
		}
	}
	if toStdout {
		return write(os.Stdout)
	}
	same, err := sameFilePath(positionals[0], *output)
	if err != nil {
		return fmt.Errorf("validate render output: %w", err)
	}
	if same {
		return usageErrorf("render output must not replace its input report")
	}
	if err := writeFileAtomically(*output, write); err != nil {
		return fmt.Errorf("write rendered report %q: %w", *output, err)
	}
	_, err = fmt.Fprintf(os.Stderr, "Wrote %s report to %s\n", format, terminal.EscapeTruncate(*output, 512))
	return err
}

func sameFilePath(left, right string) (bool, error) {
	leftAbs, err := filepath.Abs(left)
	if err != nil {
		return false, err
	}
	rightAbs, err := filepath.Abs(right)
	if err != nil {
		return false, err
	}
	if filepath.Clean(leftAbs) == filepath.Clean(rightAbs) {
		return true, nil
	}
	leftInfo, leftErr := os.Stat(left)
	if leftErr != nil && !os.IsNotExist(leftErr) {
		return false, leftErr
	}
	rightInfo, rightErr := os.Stat(right)
	if rightErr != nil && !os.IsNotExist(rightErr) {
		return false, rightErr
	}
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo), nil
}

func writeFileAtomically(path string, write func(io.Writer) error) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".maratus-render-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := write(temporary); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
