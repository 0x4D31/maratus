package report

import (
	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/rules"
)

const (
	SchemaVersion            = "maratus.report.v0.3-preview.2"
	RuleCatalogSchemaVersion = "maratus.rule-catalog.v0.3"
	RulesetVersion           = "maratus.rules.v0.2-preview.13"
)

type Report struct {
	SchemaVersion          string                                      `json:"schema_version"`
	Tool                   string                                      `json:"tool"`
	ToolVersion            string                                      `json:"tool_version"`
	ToolCommit             string                                      `json:"tool_commit,omitempty"`
	ToolModified           bool                                        `json:"tool_modified,omitempty"`
	RulesetVersion         string                                      `json:"ruleset_version"`
	RuleCatalogDigest      string                                      `json:"rule_catalog_digest"`
	Analysis               AnalysisMetadata                            `json:"analysis"`
	Artifact               string                                      `json:"artifact"`
	ArtifactNodes          []artifact.Node                             `json:"artifact_nodes"`
	Relationships          []artifact.Edge                             `json:"relationships"`
	Scopes                 []behavior.Scope                            `json:"scopes"`
	AnalysisSelection      []behavior.AnalysisSelection                `json:"analysis_selection"`
	ExecutionRoots         []behavior.ExecutionRoot                    `json:"execution_roots"`
	InvokedTargets         []behavior.InvokedTarget                    `json:"invoked_targets"`
	Capabilities           []behavior.CapabilityMatch                  `json:"capability_matches"`
	Features               []behavior.Feature                          `json:"features"`
	Operations             []behavior.ModeledOperation                 `json:"operations"`
	OperationRelations     []behavior.OperationRelation                `json:"operation_relations"`
	ArtifactProperties     []behavior.ArtifactProperty                 `json:"artifact_properties"`
	NetworkImplementations []behavior.NetworkImplementationObservation `json:"network_implementations"`
	Coverage               []behavior.Coverage                         `json:"coverage"`
	Evidence               []behavior.Evidence                         `json:"evidence"`
	Diagnostics            []string                                    `json:"diagnostics"`
}

// AnalysisMetadata records the normalized settings that can materially change
// report coverage. Secrets such as the ZIP password are deliberately excluded.
type AnalysisMetadata struct {
	ExpandContainers     bool   `json:"expand_containers"`
	IncludeUnreferenced  bool   `json:"include_unreferenced"`
	AllowDMGMount        bool   `json:"allow_dmg_mount"`
	Architecture         string `json:"architecture"`
	MaxFileBytes         int64  `json:"max_file_bytes"`
	MaxArchiveBytes      int64  `json:"max_archive_bytes"`
	MaxExpandedBytes     int64  `json:"max_expanded_bytes"`
	MaxTotalBytes        int64  `json:"max_total_bytes"`
	MaxArchiveDepth      int    `json:"max_archive_depth"`
	MaxDirectoryDepth    int    `json:"max_directory_depth"`
	MaxCompressionRatio  int64  `json:"max_compression_ratio"`
	MaxArtifactNodes     int    `json:"max_artifact_nodes"`
	MaxArtifactPathBytes int64  `json:"max_artifact_path_bytes"`
	MaxEvidence          int    `json:"max_evidence"`
	MaxDiagnostics       int    `json:"max_diagnostics"`
	MaxDiagnosticBytes   int64  `json:"max_diagnostic_bytes"`
	ZipPasswordSupplied  bool   `json:"zip_password_supplied"`
}

type RuleInfo struct {
	SchemaVersion     string               `json:"schema_version"`
	Tool              string               `json:"tool"`
	ToolVersion       string               `json:"tool_version"`
	ToolCommit        string               `json:"tool_commit,omitempty"`
	ToolModified      bool                 `json:"tool_modified,omitempty"`
	RulesetVersion    string               `json:"ruleset_version"`
	RuleCatalogDigest string               `json:"rule_catalog_digest"`
	Rules             []rules.CatalogEntry `json:"rules"`
}
