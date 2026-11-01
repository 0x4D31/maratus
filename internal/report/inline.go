package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/extract"
)

type inlineInputDescriptor struct {
	logical          string
	semanticLanguage string
}

var inlineInputDescriptors = map[string]inlineInputDescriptor{
	"artifact":     {logical: "<stdin>"},
	"shell":        {logical: "<stdin>.sh", semanticLanguage: "shell"},
	"python":       {logical: "<stdin>.py", semanticLanguage: "python"},
	"javascript":   {logical: "<stdin>.js", semanticLanguage: "javascript"},
	"typescript":   {logical: "<stdin>.ts", semanticLanguage: "javascript"},
	"applescript":  {logical: "<stdin>.applescript", semanticLanguage: "applescript"},
	"text":         {logical: "<stdin>.txt", semanticLanguage: "text"},
	"plist":        {logical: "<stdin>.plist", semanticLanguage: "plist"},
	"json":         {logical: "<stdin>.json", semanticLanguage: "json"},
	"package-json": {logical: "package.json", semanticLanguage: "json"},
}

// InlineInputKinds returns the stable, sorted vocabulary accepted by
// InspectInline and the inspect --stdin CLI boundary.
func InlineInputKinds() []string {
	kinds := make([]string, 0, len(inlineInputDescriptors))
	for kind := range inlineInputDescriptors {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

// NormalizeInlineInputKind returns a canonical supported stdin kind.
func NormalizeInlineInputKind(inputKind string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(inputKind))
	if _, ok := inlineInputDescriptors[normalized]; !ok {
		return "", fmt.Errorf("unsupported inline input kind %q (want %s)", inputKind, strings.Join(InlineInputKinds(), ", "))
	}
	return normalized, nil
}

// InspectInline analyzes caller-supplied bytes as one bounded synthetic
// artifact. It never resolves paths named by the content, reads a working
// directory, invokes an interpreter, or emulates a package manager.
func InspectInline(data []byte, inputKind string, options artifact.Options) (Report, error) {
	normalizedKind, err := NormalizeInlineInputKind(inputKind)
	if err != nil {
		return Report{}, err
	}
	descriptor := inlineInputDescriptors[normalizedKind]
	options = options.Normalized()
	if err := validateReportCollectionOptions(options); err != nil {
		return Report{}, err
	}
	if int64(len(data)) > options.MaxFileBytes {
		return Report{}, fmt.Errorf("inline input exceeds max file bytes %d", options.MaxFileBytes)
	}
	if int64(len(data)) > options.MaxTotalBytes {
		return Report{}, fmt.Errorf("inline input exceeds retained-byte limit %d", options.MaxTotalBytes)
	}

	artifacts, err := artifact.InspectBytes(descriptor.logical, data, options)
	if err != nil {
		return Report{}, err
	}
	if descriptor.semanticLanguage != "" {
		rootID := ""
		for _, node := range artifacts.Graph.Nodes {
			if node.ParentID == "" {
				rootID = node.ID
				break
			}
		}
		for index := range artifacts.Contents {
			if artifacts.Contents[index].NodeID == rootID {
				artifacts.Contents[index].SemanticLanguage = descriptor.semanticLanguage
				break
			}
		}
	}
	behaviorGraph := extract.Run(extract.Context{Artifacts: &artifacts.Graph, Contents: artifacts.Contents, Options: artifacts.Options})
	out, err := fromGraphs("<stdin:"+normalizedKind+">", artifacts.Graph, behaviorGraph, artifacts.Diagnostics, artifacts.Options)
	if err != nil {
		return Report{}, fmt.Errorf("build maratus report: %w", err)
	}
	if err := validateReportReferences(out); err != nil {
		return Report{}, fmt.Errorf("build maratus report: %w", err)
	}
	return out, nil
}
