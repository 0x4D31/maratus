package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/buildinfo"
	"github.com/0x4D31/maratus/internal/extract"
	"github.com/0x4D31/maratus/internal/rules"
)

func InspectPath(path string, options artifact.Options) (Report, error) {
	options = options.Normalized()
	if err := validateReportCollectionOptions(options); err != nil {
		return Report{}, err
	}
	artifacts, err := artifact.InspectPath(path, options)
	if err != nil {
		return Report{}, err
	}
	graph := extract.Run(extract.Context{Artifacts: &artifacts.Graph, Contents: artifacts.Contents, Options: artifacts.Options})
	out, err := fromGraphs(path, artifacts.Graph, graph, artifacts.Diagnostics, artifacts.Options)
	if err != nil {
		return Report{}, fmt.Errorf("build maratus report: %w", err)
	}
	if err := validateReportReferences(out); err != nil {
		return Report{}, fmt.Errorf("build maratus report: %w", err)
	}
	return out, nil
}

// validateReportCollectionOptions keeps every report produced through the
// public report API within the strict saved-report loader's collection bounds.
// Byte and depth budgets may be raised deliberately, but accepting larger
// node/evidence counts here would let Maratus emit a report it cannot reload.
func validateReportCollectionOptions(options artifact.Options) error {
	if options.MaxArtifactNodes > artifact.DefaultMaxArtifactNodes {
		return fmt.Errorf("max artifact nodes %d exceeds reloadable report limit %d", options.MaxArtifactNodes, artifact.DefaultMaxArtifactNodes)
	}
	if options.MaxEvidence > artifact.DefaultMaxEvidence {
		return fmt.Errorf("max evidence %d exceeds reloadable report limit %d", options.MaxEvidence, artifact.DefaultMaxEvidence)
	}
	if options.MaxDiagnostics > artifact.DefaultMaxDiagnostics {
		return fmt.Errorf("max diagnostics %d exceeds reloadable report limit %d", options.MaxDiagnostics, artifact.DefaultMaxDiagnostics)
	}
	return nil
}

func fromGraphs(artifactPath string, artifacts artifact.Graph, graph behavior.Graph, diagnostics []string, options artifact.Options) (Report, error) {
	graph.Features = publicFeatures(graph.Features, graph.Relations)
	if err := graph.Sort(); err != nil {
		return Report{}, fmt.Errorf("sort behavior graph: %w", err)
	}
	capabilityMatches := rules.Evaluate(&graph)
	if err := graph.Sort(); err != nil {
		return Report{}, fmt.Errorf("sort behavior graph after rule evaluation: %w", err)
	}
	diagnostics = append(diagnostics, evidenceDropDiagnostics(graph)...)
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "rule-evaluation" && coverage.Status == "partial" {
			diagnostics = append(diagnostics, "rule evaluation partial: "+coverage.Detail)
		}
	}
	markKnownEvidenceOffsets(graph.Evidence)
	sortArtifactGraph(&artifacts)
	features := graph.Features
	artifactProperties := dedupeArtifactProperties(graph.ArtifactProperties)
	networkImplementations := uniqueNetworkImplementations(graph.Network)
	evidence := publicEvidence(graph.Evidence, artifacts.Edges, features, graph.ExecutionRoots, graph.InvokedTargets, graph.Operations, graph.Relations, artifactProperties, networkImplementations, capabilityMatches)
	tool := buildinfo.Current()
	return Report{
		SchemaVersion:          SchemaVersion,
		Tool:                   "maratus",
		ToolVersion:            tool.Version,
		ToolCommit:             tool.Commit,
		ToolModified:           tool.Modified,
		RulesetVersion:         RulesetVersion,
		RuleCatalogDigest:      rules.CatalogDigest(),
		Analysis:               normalizedAnalysisMetadata(options),
		Artifact:               artifactPath,
		ArtifactNodes:          artifacts.Nodes,
		Relationships:          artifacts.Edges,
		Scopes:                 graph.Scopes,
		AnalysisSelection:      graph.AnalysisSelections,
		ExecutionRoots:         graph.ExecutionRoots,
		InvokedTargets:         graph.InvokedTargets,
		Capabilities:           capabilityMatches,
		Features:               features,
		Operations:             graph.Operations,
		OperationRelations:     graph.Relations,
		ArtifactProperties:     artifactProperties,
		NetworkImplementations: networkImplementations,
		Coverage:               graph.Coverage,
		Evidence:               evidence,
		Diagnostics:            limitDiagnosticStrings(uniqueStrings(diagnostics), options),
	}, nil
}

func evidenceDropDiagnostics(graph behavior.Graph) []string {
	var diagnostics []string
	if graph.EvidenceLimitDrops > 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("evidence object limit %d reached; %s", graph.EvidenceLimit, omittedEvidenceObjects(graph.EvidenceLimitDrops)))
	}
	if graph.EvidenceStringDrops > 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("retained string byte limit %d reached; %s", graph.StringByteLimit, omittedEvidenceObjects(graph.EvidenceStringDrops)))
	}
	return diagnostics
}

func omittedEvidenceObjects(count int) string {
	noun := "evidence objects"
	if count == 1 {
		noun = "evidence object"
	}
	return fmt.Sprintf("omitted at least %d %s", count, noun)
}

// Direct Mach-O calls are an internal correlation input rather than an
// analyst-facing behavior feature. Keeping thousands of stripped-binary edges
// in features made otherwise small machine-readable reports impractical. Any
// call feature that actually proves a retained calls relation or is referenced
// by a capability rule remains public. A relation cannot outlive its proof.
func publicFeatures(features []behavior.Feature, relations []behavior.OperationRelation) []behavior.Feature {
	return publicFeaturesForRuleKeys(features, rules.ReferencedFeatureKeys(), relations)
}

func publicFeaturesForRuleKeys(features []behavior.Feature, referencedKeys []string, relations []behavior.OperationRelation) []behavior.Feature {
	required := make(map[string]struct{}, len(referencedKeys))
	for _, key := range referencedKeys {
		required[key] = struct{}{}
	}
	callEvidence := make(map[string]struct{})
	for _, relation := range relations {
		if relation.Kind != behavior.RelationCalls {
			continue
		}
		for _, evidenceID := range relation.EvidenceIDs {
			if evidenceID != "" {
				callEvidence[evidenceID] = struct{}{}
			}
		}
	}
	out := make([]behavior.Feature, 0, len(features))
	for _, feature := range features {
		_, ruleInput := required[feature.Key]
		relationProof := false
		if feature.Key == "macho.function_call" {
			for _, evidenceID := range feature.EvidenceIDs {
				if _, ok := callEvidence[evidenceID]; ok {
					relationProof = true
					break
				}
			}
		}
		if feature.Key != "macho.function_call" || ruleInput || relationProof {
			out = append(out, feature)
		}
	}
	return out
}

func publicEvidence(
	evidence []behavior.Evidence,
	relationships []artifact.Edge,
	features []behavior.Feature,
	executionRoots []behavior.ExecutionRoot,
	invokedTargets []behavior.InvokedTarget,
	operations []behavior.ModeledOperation,
	relations []behavior.OperationRelation,
	artifactProperties []behavior.ArtifactProperty,
	networkImplementations []behavior.NetworkImplementationObservation,
	capabilityMatches []behavior.CapabilityMatch,
) []behavior.Evidence {
	referenced := map[string]bool{}
	add := func(ids []string) {
		for _, id := range ids {
			if id != "" {
				referenced[id] = true
			}
		}
	}
	for _, item := range relationships {
		add(item.EvidenceIDs)
	}
	for _, item := range features {
		add(item.EvidenceIDs)
	}
	for _, item := range executionRoots {
		add(item.EvidenceIDs)
	}
	for _, item := range invokedTargets {
		add(item.EvidenceIDs)
	}
	for _, item := range operations {
		add(item.EvidenceIDs)
		for _, binding := range item.ResourceBindings {
			add(binding.EvidenceIDs)
		}
	}
	for _, item := range relations {
		add(item.EvidenceIDs)
	}
	for _, item := range artifactProperties {
		add(item.EvidenceIDs)
	}
	for _, item := range networkImplementations {
		add(item.EvidenceIDs)
	}
	for _, item := range capabilityMatches {
		add(item.EvidenceIDs)
	}
	out := make([]behavior.Evidence, 0, len(evidence))
	for _, item := range evidence {
		if item.Kind != "function-call" || referenced[item.ID] {
			out = append(out, item)
		}
	}
	return out
}

// Offset-producing extractors predate Evidence.OffsetKnown. Mark their output
// at the report boundary so an observation at byte zero is serialized as zero,
// while extractors without byte locations continue to omit byte_offset.
func markKnownEvidenceOffsets(evidence []behavior.Evidence) {
	for i := range evidence {
		item := &evidence[i]
		switch item.Method {
		case "macho-strings":
			if item.Kind == "url" || item.Kind == "ip" || item.Kind == "sensitive-resource" {
				item.OffsetKnown = true
			}
		case "macho-objc":
			if item.Kind == "objc-selector" || item.Kind == "objc-selector-ref" {
				item.OffsetKnown = true
			}
		case "rust-source":
			if item.Kind == "rust-xor-string" {
				item.OffsetKnown = true
			}
		}
		if item.Offset != 0 {
			evidence[i].OffsetKnown = true
		}
	}
}

func normalizedAnalysisMetadata(options artifact.Options) AnalysisMetadata {
	options = options.Normalized()
	return AnalysisMetadata{
		ExpandContainers:     !options.DisableContainerExpansion,
		IncludeUnreferenced:  options.IncludeUnreferenced,
		AllowDMGMount:        options.AllowDMGMount,
		Architecture:         options.Architecture,
		MaxFileBytes:         options.MaxFileBytes,
		MaxArchiveBytes:      options.MaxArchiveBytes,
		MaxExpandedBytes:     options.MaxExpandedBytes,
		MaxTotalBytes:        options.MaxTotalBytes,
		MaxArchiveDepth:      options.MaxArchiveDepth,
		MaxDirectoryDepth:    options.MaxDirectoryDepth,
		MaxCompressionRatio:  options.MaxCompressionRatio,
		MaxArtifactNodes:     options.MaxArtifactNodes,
		MaxArtifactPathBytes: options.MaxArtifactPathBytes,
		MaxEvidence:          options.MaxEvidence,
		MaxDiagnostics:       options.MaxDiagnostics,
		MaxDiagnosticBytes:   options.MaxDiagnosticBytes,
		ZipPasswordSupplied:  options.ZipPassword != "",
	}
}

func dedupeArtifactProperties(items []behavior.ArtifactProperty) []behavior.ArtifactProperty {
	strong := map[string]bool{}
	for _, item := range items {
		if item.Support != behavior.SupportHeuristic {
			strong[artifactPropertiesDedupeKey(item, false)] = true
		}
	}
	byKey := map[string]int{}
	var out []behavior.ArtifactProperty
	var evidenceSeen []map[string]bool
	for _, item := range items {
		if item.Support == behavior.SupportHeuristic && strong[artifactPropertiesDedupeKey(item, false)] {
			continue
		}
		key := artifactPropertiesDedupeKey(item, true)
		if idx, ok := byKey[key]; ok {
			out[idx].EvidenceIDs = appendStringsWithSeen(out[idx].EvidenceIDs, evidenceSeen[idx], item.EvidenceIDs)
			continue
		}
		seen := map[string]bool{}
		item.EvidenceIDs = appendStringsWithSeen(nil, seen, item.EvidenceIDs)
		byKey[key] = len(out)
		out = append(out, item)
		evidenceSeen = append(evidenceSeen, seen)
	}
	for i := range out {
		sort.Strings(out[i].EvidenceIDs)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].NodeID != out[j].NodeID {
			return out[i].NodeID < out[j].NodeID
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		return out[i].Support < out[j].Support
	})
	return out
}

func appendStringsWithSeen(out []string, seen map[string]bool, values []string) []string {
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func artifactPropertiesDedupeKey(item behavior.ArtifactProperty, includeSupport bool) string {
	fields := []string{item.NodeID, item.Kind, item.Value}
	if includeSupport {
		fields = append(fields, string(item.Support))
	}
	return semanticIdentityKey(fields...)
}

func sortArtifactGraph(graph *artifact.Graph) {
	sort.SliceStable(graph.Nodes, func(i, j int) bool {
		return graph.Nodes[i].ID < graph.Nodes[j].ID
	})
	for index := range graph.Edges {
		sort.Strings(graph.Edges[index].EvidenceIDs)
	}
	sort.SliceStable(graph.Edges, func(i, j int) bool {
		left, right := graph.Edges[i], graph.Edges[j]
		if left.From != right.From {
			return left.From < right.From
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.Ordinal == nil && right.Ordinal != nil {
			return true
		}
		if left.Ordinal != nil && right.Ordinal == nil {
			return false
		}
		if left.Ordinal != nil && right.Ordinal != nil && *left.Ordinal != *right.Ordinal {
			return *left.Ordinal < *right.Ordinal
		}
		return left.To < right.To
	})
}

// MaxReportInputBytes is the maximum encoded canonical report accepted by the
// strict loader. The inspect supervisor applies the same limit to worker
// output before asking the loader to trust its structure or references.
const MaxReportInputBytes int64 = 64 << 20

const maxReportInputBytes = MaxReportInputBytes

func Load(path string) (Report, error) {
	// A report is always a regular file. Reject directories, FIFOs, devices,
	// sockets, and symlinks before opening so report detection cannot block on
	// a special file or unexpectedly follow an alias. openReportFileNoFollow
	// repeats that guarantee at open time to close the lstat/open race on the
	// supported release platforms.
	expected, err := os.Lstat(path)
	if err != nil {
		return Report{}, err
	}
	if expected.IsDir() {
		return Report{}, fmt.Errorf("%w: path is a directory", ErrNotReport)
	}
	if !expected.Mode().IsRegular() {
		return Report{}, fmt.Errorf("%w: path is not a regular file", ErrNotReport)
	}
	file, err := openReportFileNoFollow(path)
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return Report{}, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(expected, info) {
		return Report{}, fmt.Errorf("%w: path changed while opening", ErrNotReport)
	}
	if err := clearReportFileNonblocking(file); err != nil {
		return Report{}, err
	}
	if info.Mode().IsRegular() && info.Size() > MaxReportInputBytes {
		// Large binaries, JSON documents, and archives are ordinary artifact
		// inputs. A size failure is report-specific, so apply it only after the
		// bounded prefix identifies the current Maratus report schema.
		identity, _, err := sniffReportIdentity(file)
		if err != nil {
			return Report{}, err
		}
		switch identity.kind {
		case reportIdentityCurrent:
			return Report{}, reportTooLargeError()
		case reportIdentityUnsupported:
			return Report{}, unsupportedReportSchemaError(identity.schema)
		default:
			return Report{}, fmt.Errorf("%w: no Maratus report schema in bounded prefix", ErrNotReport)
		}
	}
	return decodeReport(file)
}

func decodeReport(input io.Reader) (Report, error) {
	limited := &io.LimitedReader{R: input, N: MaxReportInputBytes + 1}
	identity, captured, err := sniffReportIdentity(limited)
	if err != nil {
		return Report{}, err
	}
	switch identity.kind {
	case reportIdentityUnsupported:
		return Report{}, unsupportedReportSchemaError(identity.schema)
	case reportIdentityCurrent:
		// Continue below. Bytes read while classifying are replayed because
		// encoding/json may have buffered past the schema marker.
	default:
		return Report{}, fmt.Errorf("%w: no Maratus report schema in bounded prefix", ErrNotReport)
	}

	data, err := io.ReadAll(io.MultiReader(bytes.NewReader(captured), limited))
	if err != nil {
		return Report{}, recognizedReportError(err)
	}
	if int64(len(data)) > MaxReportInputBytes || limited.N == 0 {
		return Report{}, reportTooLargeError()
	}
	// Apply report-specific collection and nesting limits only after the schema
	// identifies this as a report. A valid unrelated JSON object remains an
	// inspectable artifact even if it happens to contain report-like field names.
	if err := validateReportJSONStructure(data); err != nil {
		return Report{}, recognizedReportError(err)
	}
	members, err := validateReportJSONMembers(data)
	if err != nil {
		return Report{}, recognizedReportError(err)
	}
	var report Report
	if err := decodeSingleReportJSON(data, &report, true); err != nil {
		return Report{}, recognizedReportError(err)
	}
	// Duplicate and noncanonical members were rejected by the scan above. Defer
	// its required-member result until after strict decoding so unknown fields and
	// trailing data retain their more specific errors. The decoded value is not
	// used until every member check has passed.
	if err := members.validateRequired(); err != nil {
		return Report{}, recognizedReportError(err)
	}
	if report.SchemaVersion != SchemaVersion {
		if strings.HasPrefix(report.SchemaVersion, "maratus.report.") {
			return Report{}, unsupportedReportSchemaError(report.SchemaVersion)
		}
		return Report{}, recognizedReportError(fmt.Errorf("schema changed during decoding: got %q, expected %q", report.SchemaVersion, SchemaVersion))
	}
	if err := validateRequiredSavedReport(report); err != nil {
		return Report{}, recognizedReportError(fmt.Errorf("invalid maratus report: %w", err))
	}
	if err := validateReportReferences(report); err != nil {
		return Report{}, recognizedReportError(fmt.Errorf("invalid maratus report: %w", err))
	}
	return report, nil
}

func decodeSingleReportJSON(data []byte, destination any, strict bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid report JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("invalid report JSON: trailing data")
		}
		return fmt.Errorf("invalid report JSON trailing data: %w", err)
	}
	return nil
}

func reportTooLargeError() error {
	return recognizedReportError(fmt.Errorf("report exceeds maximum size of %d bytes", maxReportInputBytes))
}

func unsupportedReportSchemaError(schema string) error {
	return recognizedReportError(fmt.Errorf("unsupported maratus report schema %q; expected %q", schema, SchemaVersion))
}

func recognizedReportError(err error) error {
	return fmt.Errorf("%w: %w", ErrRecognizedReport, err)
}

func ListRules() RuleInfo {
	entries := rules.CatalogEntries()
	tool := buildinfo.Current()
	out := RuleInfo{
		SchemaVersion:     RuleCatalogSchemaVersion,
		Tool:              "maratus",
		ToolVersion:       tool.Version,
		ToolCommit:        tool.Commit,
		ToolModified:      tool.Modified,
		RulesetVersion:    RulesetVersion,
		RuleCatalogDigest: rules.CatalogDigest(),
		Rules:             entries,
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
