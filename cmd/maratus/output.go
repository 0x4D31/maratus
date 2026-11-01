package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/0x4D31/maratus/internal/report"
	"github.com/0x4D31/maratus/internal/visualization"
)

func parseOutputFormat(value string, allowed ...string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, candidate := range allowed {
		if value == candidate {
			return value, nil
		}
	}
	return "", fmt.Errorf("invalid --format %q (want %s)", value, strings.Join(allowed, ", "))
}

func writeReportOutput(output io.Writer, rep report.Report, format string, textOptions report.TextOptions) error {
	switch format {
	case "text":
		return report.WriteTextWithOptions(output, rep, textOptions)
	case "json":
		return report.WriteJSON(output, rep)
	case "summary-json":
		return report.WriteSummaryJSON(output, rep)
	case "html":
		return visualization.Write(output, rep, visualization.Options{})
	default:
		return fmt.Errorf("unsupported report output format %q", format)
	}
}
