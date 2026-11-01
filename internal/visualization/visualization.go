// Package visualization renders Maratus reports as bounded, self-contained HTML.
//
// The generated document has no external dependencies and makes no network
// requests. It is suitable for opening locally or attaching to an analysis
// record. Report values are JSON encoded and are only inserted into the page
// with DOM text APIs; they are never interpreted as HTML.
package visualization

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/0x4D31/maratus/internal/report"
)

const (
	defaultArtifactNodeLimit      = 300
	defaultAnalysisSelectionLimit = 300
	defaultExecutionRootLimit     = 120
	defaultInvokedTargetLimit     = 180
	defaultOperationLimit         = 250
	defaultCapabilityMatchLimit   = 180
	defaultOperationRelationLimit = 300
	defaultCoverageLimit          = 150
	defaultLinkLimit              = 1800
	defaultTextByteLimit          = 2 << 20
	defaultStringByteLimit        = 2048

	hardArtifactNodeLimit      = 800
	hardAnalysisSelectionLimit = 800
	hardExecutionRootLimit     = 400
	hardInvokedTargetLimit     = 500
	hardOperationLimit         = 600
	hardCapabilityMatchLimit   = 400
	hardOperationRelationLimit = 1000
	hardCoverageLimit          = 400
	hardLinkLimit              = 5000
	hardTextByteLimit          = 4 << 20
	hardStringByteLimit        = 4096
)

// Options controls the bounded view embedded in an HTML report. Zero values
// select conservative defaults. Values above the package hard limits are
// clamped and disclosed in the visualization's omission notes. Negative values
// are rejected.
type Options struct {
	Title                 string
	MaxArtifactNodes      int
	MaxAnalysisSelections int
	MaxExecutionRoots     int
	MaxInvokedTargets     int
	MaxOperations         int
	MaxCapabilityMatches  int
	MaxOperationRelations int
	MaxCoverageItems      int
	MaxLinks              int
	MaxTextBytes          int
	MaxStringBytes        int
}

// Write writes a deterministic, single-file interactive visualization of rep.
// The visualization intentionally presents capability matches and coverage,
// not a malware or safety verdict.
func Write(w io.Writer, rep report.Report, options Options) error {
	if w == nil {
		return errors.New("visualization: nil writer")
	}
	normalized, adjustments, err := normalizeOptions(options)
	if err != nil {
		return err
	}
	document := buildDocument(rep, normalized, adjustments)
	data, err := json.Marshal(document)
	if err != nil {
		return errors.New("visualization: encode document: " + err.Error())
	}
	// encoding/json escapes '<', '>', and '&' by default. In particular, an
	// untrusted "</script>" becomes "\u003c/script\u003e" and cannot terminate
	// the inert application/json element below.
	if err := writeAll(w, htmlPrefix); err != nil {
		return err
	}
	if err := writeAll(w, string(data)); err != nil {
		return err
	}
	return writeAll(w, htmlSuffix)
}

type normalizedOptions struct {
	title              string
	artifactNodes      int
	analysisSelections int
	executionRoots     int
	invokedTargets     int
	modeledOperations  int
	capabilityMatches  int
	operationRelations int
	coverage           int
	links              int
	textBytes          int
	stringBytes        int
}

func normalizeOptions(options Options) (normalizedOptions, []string, error) {
	type limitOption struct {
		name       string
		value      int
		defaultVal int
		hard       int
		dest       *int
	}
	n := normalizedOptions{title: options.Title}
	values := []limitOption{
		{"MaxArtifactNodes", options.MaxArtifactNodes, defaultArtifactNodeLimit, hardArtifactNodeLimit, &n.artifactNodes},
		{"MaxAnalysisSelections", options.MaxAnalysisSelections, defaultAnalysisSelectionLimit, hardAnalysisSelectionLimit, &n.analysisSelections},
		{"MaxExecutionRoots", options.MaxExecutionRoots, defaultExecutionRootLimit, hardExecutionRootLimit, &n.executionRoots},
		{"MaxInvokedTargets", options.MaxInvokedTargets, defaultInvokedTargetLimit, hardInvokedTargetLimit, &n.invokedTargets},
		{"MaxOperations", options.MaxOperations, defaultOperationLimit, hardOperationLimit, &n.modeledOperations},
		{"MaxCapabilityMatches", options.MaxCapabilityMatches, defaultCapabilityMatchLimit, hardCapabilityMatchLimit, &n.capabilityMatches},
		{"MaxOperationRelations", options.MaxOperationRelations, defaultOperationRelationLimit, hardOperationRelationLimit, &n.operationRelations},
		{"MaxCoverageItems", options.MaxCoverageItems, defaultCoverageLimit, hardCoverageLimit, &n.coverage},
		{"MaxLinks", options.MaxLinks, defaultLinkLimit, hardLinkLimit, &n.links},
		{"MaxTextBytes", options.MaxTextBytes, defaultTextByteLimit, hardTextByteLimit, &n.textBytes},
		{"MaxStringBytes", options.MaxStringBytes, defaultStringByteLimit, hardStringByteLimit, &n.stringBytes},
	}

	var adjustments []string
	for _, item := range values {
		if item.value < 0 {
			return normalizedOptions{}, nil, errors.New("visualization: " + item.name + " must not be negative")
		}
		value := item.value
		if value == 0 {
			value = item.defaultVal
		}
		if value > item.hard {
			adjustments = append(adjustments, item.name+" was reduced to the visualization hard limit")
			value = item.hard
		}
		*item.dest = value
	}
	return n, adjustments, nil
}

func writeAll(w io.Writer, value string) error {
	for len(value) > 0 {
		n, err := io.WriteString(w, value)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		value = value[n:]
	}
	return nil
}
