package report

import "strings"

func joinNonEmpty(values []string, separator string) string {
	var retained []string
	for _, value := range values {
		if value != "" {
			retained = append(retained, value)
		}
	}
	return strings.Join(retained, separator)
}

func analysisMetadataAvailable(metadata AnalysisMetadata) bool {
	return metadata != (AnalysisMetadata{})
}
