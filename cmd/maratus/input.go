package main

import (
	"errors"
	"fmt"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/report"
)

// inspectArtifactOnly keeps analysis and saved-report rendering as separate
// operations. A recognized Maratus report fails closed here instead of being
// silently reinterpreted as an ordinary JSON artifact.
func inspectArtifactOnly(path string, options artifact.Options) (report.Report, error) {
	if err := validateArtifactInspectionInput(path); err != nil {
		return report.Report{}, err
	}
	rep, err := report.InspectPath(path, options)
	if err != nil {
		return report.Report{}, fmt.Errorf("inspect artifact %q: %w", path, err)
	}
	return rep, nil
}

func validateArtifactInspectionInput(path string) error {
	_, loadErr := report.Load(path)
	if loadErr == nil {
		return usageErrorf("inspect expects an artifact; use maratus render for saved reports")
	}
	if errors.Is(loadErr, report.ErrRecognizedReport) {
		return fmt.Errorf("inspect input %q identifies as a Maratus report but is invalid: %w", path, loadErr)
	}
	if !errors.Is(loadErr, report.ErrNotReport) {
		return fmt.Errorf("inspect artifact %q: %w", path, loadErr)
	}
	return nil
}
