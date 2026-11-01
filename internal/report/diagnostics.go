package report

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
)

// limitDiagnosticStrings applies report-wide count and byte bounds without
// depending on the removed command-analysis aggregation subsystem.
func limitDiagnosticStrings(values []string, options artifact.Options) []string {
	options = options.Normalized()
	seen := make(map[string]struct{}, min(len(values), options.MaxDiagnostics))
	retained := make([]string, 0, min(len(values), options.MaxDiagnostics))
	var retainedBytes int64
	var omitted int
	var omittedBytes int64
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		if omitted == 0 && len(retained) < options.MaxDiagnostics && int64(len(value)) <= options.MaxDiagnosticBytes-retainedBytes {
			retained = append(retained, value)
			retainedBytes += int64(len(value))
			continue
		}
		omitted++
		omittedBytes = saturatingAddReportBytes(omittedBytes, int64(len(value)))
	}
	if omitted == 0 {
		return retained
	}
	for {
		summary := truncateUTF8Bytes(
			fmt.Sprintf("diagnostic budget reached; omitted %d messages (%d bytes)", omitted, omittedBytes),
			options.MaxDiagnosticBytes,
		)
		if len(summary) > 0 && len(retained) < options.MaxDiagnostics && int64(len(summary)) <= options.MaxDiagnosticBytes-retainedBytes {
			return append(retained, summary)
		}
		if len(retained) == 0 {
			return nil
		}
		last := len(retained) - 1
		retainedBytes -= int64(len(retained[last]))
		omitted++
		omittedBytes = saturatingAddReportBytes(omittedBytes, int64(len(retained[last])))
		retained = retained[:last]
	}
}

func truncateUTF8Bytes(value string, limit int64) string {
	if limit <= 0 {
		return ""
	}
	if int64(len(value)) <= limit {
		return value
	}
	end := int(limit)
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end]
}

func saturatingAddReportBytes(left, right int64) int64 {
	const maxInt64 = int64(^uint64(0) >> 1)
	if right < 0 || left > maxInt64-right {
		return maxInt64
	}
	return left + right
}
