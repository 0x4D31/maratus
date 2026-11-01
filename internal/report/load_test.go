package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/rules"
)

func TestLoadAcceptsLeadingJSONWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	data := " \n\t\r" + validSavedReportJSON("雪", "")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if report.Artifact != "雪" {
		t.Fatalf("Load() artifact = %q", report.Artifact)
	}
}

func TestLoadRejectsOversizedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(file, `{"schema_version":"`+SchemaVersion+`"`); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Truncate(maxReportInputBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("Load() error = %v, want size limit error", err)
	}
}

func TestReportAPIsRejectCollectionLimitsAboveLoaderBounds(t *testing.T) {
	_, err := InspectPath(filepath.Join(t.TempDir(), "need-not-exist"), artifact.Options{
		MaxArtifactNodes: artifact.DefaultMaxArtifactNodes + 1,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds reloadable report limit") {
		t.Fatalf("InspectPath() error = %v, want reloadable node-limit error", err)
	}

	_, err = inspectInlineShellForTest("echo safe", artifact.Options{
		MaxEvidence: artifact.DefaultMaxEvidence + 1,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds reloadable report limit") {
		t.Fatalf("inspectInlineShellForTest() error = %v, want reloadable evidence-limit error", err)
	}

	_, err = inspectInlineShellForTest("echo safe", artifact.Options{
		MaxDiagnostics: artifact.DefaultMaxDiagnostics + 1,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds reloadable report limit") {
		t.Fatalf("inspectInlineShellForTest() error = %v, want reloadable diagnostic-limit error", err)
	}
}

func TestLoadClassifiesOversizedBinaryAsArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.bin")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("not-json\x00")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Truncate(maxReportInputBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Load(path)
	if !errors.Is(err, ErrNotReport) {
		t.Fatalf("Load() error = %v, want ErrNotReport for oversized binary artifact", err)
	}
}

func TestLoadClassifiesOversizedUnrelatedOrIndeterminateJSONAsArtifact(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
	}{
		{name: "unrelated object", prefix: `{"name":"ordinary-json-artifact"}`},
		{name: "brace-leading script", prefix: "{ printf '%s\\n' safe; }"},
		{name: "whitespace-bound marker", prefix: strings.Repeat(" ", int(maxReportIdentityBytes)) + `{"schema_version":"` + SchemaVersion + `"}`},
		{name: "oversized value before marker", prefix: `{"padding":"` + strings.Repeat("a", int(maxReportIdentityBytes)) + `","schema_version":"` + SchemaVersion + `"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "large-input")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(file, test.prefix); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Truncate(maxReportInputBytes + 1); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}

			_, err = Load(path)
			if !errors.Is(err, ErrNotReport) {
				t.Fatalf("Load() error = %v, want ErrNotReport", err)
			}
		})
	}
}

func TestLoadClassifiesOversizedUnsupportedReportExplicitly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsupported.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(file, `{"schema_version":"maratus.report.v999"}`); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Truncate(maxReportInputBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Load(path)
	if err == nil || errors.Is(err, ErrNotReport) || !errors.Is(err, ErrRecognizedReport) || !strings.Contains(err.Error(), "unsupported maratus report schema") {
		t.Fatalf("Load() error = %v, want explicit unsupported-schema error", err)
	}
}

func TestLoadRejectsTrailingJSONData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trailing.json")
	data := `{"schema_version":"` + SchemaVersion + `"}` + "\n{}"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("Load() error = %v, want trailing data error", err)
	}
}

func TestLoadRejectsWrongTool(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrong-tool.json")
	data := strings.Replace(validSavedReportJSON("fixture", ""), `"tool":"maratus"`, `"tool":"not-maratus"`, 1)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), `tool must equal "maratus"`) {
		t.Fatalf("Load() error = %v, want wrong tool error", err)
	}
}

func TestDecodeReportRejectsMissingOrEmptyCoreFields(t *testing.T) {
	valid := validSavedReportJSON("fixture", "")
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "tool absent", input: strings.Replace(valid, `"tool":"maratus",`, "", 1), want: `missing required member "tool"`},
		{name: "tool empty", input: strings.Replace(valid, `"tool":"maratus"`, `"tool":""`, 1), want: `tool must equal "maratus"`},
		{name: "tool version absent", input: strings.Replace(valid, `"tool_version":"test",`, "", 1), want: `missing required member "tool_version"`},
		{name: "tool version empty", input: strings.Replace(valid, `"tool_version":"test"`, `"tool_version":""`, 1), want: "tool_version must not be empty"},
		{name: "ruleset absent", input: strings.Replace(valid, `"ruleset_version":"`+RulesetVersion+`",`, "", 1), want: `missing required member "ruleset_version"`},
		{name: "ruleset empty", input: strings.Replace(valid, `"ruleset_version":"`+RulesetVersion+`"`, `"ruleset_version":""`, 1), want: "ruleset_version must not be empty"},
		{name: "catalog digest absent", input: strings.Replace(valid, `"rule_catalog_digest":"`+rules.CatalogDigest()+`",`, "", 1), want: `missing required member "rule_catalog_digest"`},
		{name: "catalog digest empty", input: strings.Replace(valid, `"rule_catalog_digest":"`+rules.CatalogDigest()+`"`, `"rule_catalog_digest":""`, 1), want: "rule_catalog_digest must be a sha256 catalog digest"},
		{name: "catalog digest algorithm", input: strings.Replace(valid, rules.CatalogDigest(), `sha512:`+strings.Repeat("a", 64), 1), want: "rule_catalog_digest must be a sha256 catalog digest"},
		{name: "catalog digest length", input: strings.Replace(valid, rules.CatalogDigest(), `sha256:`+strings.Repeat("a", 63), 1), want: "rule_catalog_digest must be a sha256 catalog digest"},
		{name: "catalog digest hex", input: strings.Replace(valid, rules.CatalogDigest(), `sha256:`+strings.Repeat("z", 64), 1), want: "rule_catalog_digest must be a sha256 catalog digest"},
		{name: "analysis absent", input: strings.Replace(valid, `"analysis":`+testAnalysisJSON+`,`, "", 1), want: `missing required member "analysis"`},
		{name: "analysis null", input: strings.Replace(valid, `"analysis":`+testAnalysisJSON, `"analysis":null`, 1), want: `member "analysis" must not be null`},
		{name: "analysis array", input: strings.Replace(valid, `"analysis":`+testAnalysisJSON, `"analysis":[]`, 1), want: "cannot unmarshal array"},
		{name: "analysis empty object", input: strings.Replace(valid, testAnalysisJSON, `{}`, 1), want: `missing required member`},
		{name: "analysis missing limits", input: strings.Replace(valid, testAnalysisJSON, `{"architecture":"all"}`, 1), want: `missing required member`},
		{name: "include-unreferenced boolean absent", input: strings.Replace(valid, `"include_unreferenced":false,`, "", 1), want: `missing required member "include_unreferenced"`},
		{name: "include-unreferenced boolean null", input: strings.Replace(valid, `"include_unreferenced":false`, `"include_unreferenced":null`, 1), want: `member "include_unreferenced" must not be null`},
		{name: "analysis node ceiling", input: strings.Replace(valid, `"max_artifact_nodes":1`, fmt.Sprintf(`"max_artifact_nodes":%d`, artifact.DefaultMaxArtifactNodes+1), 1), want: "analysis.max_artifact_nodes exceeds maximum"},
		{name: "analysis evidence ceiling", input: strings.Replace(valid, `"max_evidence":1`, fmt.Sprintf(`"max_evidence":%d`, artifact.DefaultMaxEvidence+1), 1), want: "analysis.max_evidence exceeds maximum"},
		{name: "artifact absent", input: strings.Replace(valid, `"artifact":"fixture",`, "", 1), want: `missing required member "artifact"`},
		{name: "artifact empty", input: strings.Replace(valid, `"artifact":"fixture"`, `"artifact":""`, 1), want: "artifact must not be empty"},
		{name: "nodes absent", input: strings.Replace(valid, `,"artifact_nodes":[{"id":"node-1","logical_path":"fixture","kind":"text","analysis_status":"analyzed"}]`, "", 1), want: `missing required member "artifact_nodes"`},
		{name: "nodes null", input: strings.Replace(valid, `"artifact_nodes":[{"id":"node-1","logical_path":"fixture","kind":"text","analysis_status":"analyzed"}]`, `"artifact_nodes":null`, 1), want: `member "artifact_nodes" must not be null`},
		{name: "nodes empty", input: strings.Replace(valid, `"artifact_nodes":[{"id":"node-1","logical_path":"fixture","kind":"text","analysis_status":"analyzed"}]`, `"artifact_nodes":[]`, 1), want: "artifact_nodes must not be empty"},
		{name: "collection absent", input: strings.Replace(valid, `,"capability_matches":[]`, "", 1), want: `missing required member "capability_matches"`},
		{name: "collection null", input: strings.Replace(valid, `"capability_matches":[]`, `"capability_matches":null`, 1), want: `member "capability_matches" must not be null`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeReport(strings.NewReader(test.input))
			if err == nil || errors.Is(err, ErrNotReport) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decodeReport() error = %v, want fail-closed %q error", err, test.want)
			}
		})
	}
}

func TestDecodeReportRequiresEveryTopLevelCollection(t *testing.T) {
	valid := validSavedReportJSON("fixture", "")
	for _, field := range []string{
		"relationships", "scopes", "analysis_selection", "execution_roots", "invoked_targets", "capability_matches", "features",
		"operations", "operation_relations", "artifact_properties", "network_implementations", "coverage", "evidence",
		"diagnostics",
	} {
		t.Run(field, func(t *testing.T) {
			input := strings.Replace(valid, `,"`+field+`":[]`, "", 1)
			_, err := decodeReport(strings.NewReader(input))
			want := `missing required member "` + field + `"`
			if err == nil || errors.Is(err, ErrNotReport) || !strings.Contains(err.Error(), want) {
				t.Fatalf("decodeReport() error = %v, want %q", err, want)
			}
		})
	}
}

func TestDecodeReportRequiresEveryAnalysisMember(t *testing.T) {
	valid := validSavedReportJSON("fixture", "")
	fields := []string{
		"expand_containers", "include_unreferenced", "allow_dmg_mount", "architecture", "max_file_bytes",
		"max_archive_bytes", "max_expanded_bytes", "max_total_bytes", "max_archive_depth",
		"max_directory_depth", "max_compression_ratio", "max_artifact_nodes",
		"max_artifact_path_bytes", "max_evidence", "max_diagnostics",
		"max_diagnostic_bytes", "zip_password_supplied",
	}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			var analysis map[string]any
			if err := json.Unmarshal([]byte(testAnalysisJSON), &analysis); err != nil {
				t.Fatal(err)
			}
			delete(analysis, field)
			encoded, err := json.Marshal(analysis)
			if err != nil {
				t.Fatal(err)
			}
			input := strings.Replace(valid, testAnalysisJSON, string(encoded), 1)
			_, err = decodeReport(strings.NewReader(input))
			want := `missing required member "` + field + `"`
			if err == nil || errors.Is(err, ErrNotReport) || !strings.Contains(err.Error(), want) {
				t.Fatalf("decodeReport() error = %v, want %q", err, want)
			}
		})
	}
}

func TestDecodeReportRejectsMissingRequiredRecordMembers(t *testing.T) {
	tests := []struct {
		name  string
		extra string
		want  string
	}{
		{
			name:  "evidence extraction method",
			extra: `"evidence":[{"id":"ev-1","kind":"fixture"}]`,
			want:  `missing required member "extraction_method"`,
		},
		{
			name: "operation resource",
			extra: `"evidence":[{"id":"ev-1","extraction_method":"fixture","kind":"fixture"}],` +
				`"operations":[{"id":"operation-1","subject_node_id":"node-1","kind":"fixture","evidence_ids":["ev-1"],"support":"CORROBORATED","execution":{"connectivity":"UNKNOWN"}}]`,
			want: `missing required member "resource_bindings"`,
		},
		{
			name: "capability rule ID",
			extra: `"evidence":[{"id":"ev-1","extraction_method":"fixture","kind":"fixture"}],` +
				`"operations":[{"id":"operation-1","subject_node_id":"node-1","kind":"process.execute","resource_bindings":[{"role":"executable","resource":{"kind":"file","value":""}}],"evidence_ids":["ev-1"],"support":"CORROBORATED","execution":{"connectivity":"UNKNOWN"}}],` +
				`"capability_matches":[{"id":"cap-1","title":"Fixture","namespace":"fixture","support":"CORROBORATED","execution":{"connectivity":"UNKNOWN"},"subject_node_id":"node-1","operation_ids":["operation-1"],"match_trace":[]}]`,
			want: `missing required member "rule_id"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeReport(strings.NewReader(validSavedReportJSON("fixture", test.extra)))
			if err == nil || errors.Is(err, ErrNotReport) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decodeReport() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDecodeReportRejectsDuplicateJSONMembers(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "top-level exact duplicate",
			input: validSavedReportJSON("fixture", `"tool":"maratus"`),
			want:  `duplicates member "tool"`,
		},
		{
			name:  "top-level typed case alias",
			input: validSavedReportJSON("fixture", `"Tool":"maratus"`),
			want:  `maps members "tool" and "Tool" to typed field "tool"`,
		},
		{
			name: "nested typed case alias",
			input: validSavedReportJSON("fixture", `"evidence":[{"id":"ev-1","extraction_method":"fixture","kind":"fixture"}],`+
				`"operations":[{"id":"operation-1","subject_node_id":"node-1","kind":"one","Kind":"two","resource_bindings":[{"role":"executable","resource":{"kind":"file","value":""}}],"evidence_ids":["ev-1"],"support":"CORROBORATED","execution":{"connectivity":"UNKNOWN"}}]`),
			want: `typed field "kind"`,
		},
		{
			name:  "custom decoder typed case alias",
			input: validSavedReportJSON("fixture", `"evidence":[{"id":"ev-1","extraction_method":"fixture","kind":"fixture","byte_offset":0,"Byte_Offset":1}]`),
			want:  `typed field "byte_offset"`,
		},
		{
			name:  "unknown nested exact duplicate",
			input: validSavedReportJSON("fixture", `"unknown":{"escaped":1,"\u0065scaped":2}`),
			want:  `duplicates member "escaped"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeReport(strings.NewReader(test.input))
			if err == nil || errors.Is(err, ErrNotReport) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decodeReport() error = %v, want duplicate-member error containing %q", err, test.want)
			}
		})
	}
}

func TestDecodeReportRejectsLoneNoncanonicalTypedMember(t *testing.T) {
	input := strings.Replace(validSavedReportJSON("fixture", ""), `"tool":"maratus"`, `"Tool":"maratus"`, 1)
	_, err := decodeReport(strings.NewReader(input))
	if err == nil || errors.Is(err, ErrNotReport) || !strings.Contains(err.Error(), `uses noncanonical member "Tool" for typed field "tool"`) {
		t.Fatalf("decodeReport() error = %v, want noncanonical typed-member error", err)
	}
}

func TestDecodeReportPreservesCaseSensitiveMapMembers(t *testing.T) {
	input := validSavedReportJSON("fixture", `"evidence":[{"id":"ev-1","node_id":"node-1","extraction_method":"fixture","kind":"fixture"}],`+
		`"operations":[{"id":"operation-1","subject_node_id":"node-1","kind":"process.execute","resource_bindings":[{"role":"executable","resource":{"kind":"file","value":""}}],`+
		`"qualifiers":{"mode":"one","Mode":"two"},"evidence_ids":["ev-1"],"support":"CORROBORATED","execution":{"connectivity":"UNKNOWN"}}]`)
	report, err := decodeReport(strings.NewReader(input))
	if err != nil {
		t.Fatalf("decodeReport() error = %v", err)
	}
	if len(report.Operations) != 1 || len(report.Operations[0].Qualifiers) != 2 {
		t.Fatalf("case-sensitive qualifier members were lost: %#v", report.Operations)
	}
}

func TestDecodeReportRequiresEvidenceBackedBehavior(t *testing.T) {
	tests := []struct {
		name  string
		extra string
		want  string
	}{
		{name: "execution root", extra: `"execution_roots":[{"id":"root-1","kind":"fixture","declaration_node_id":"node-1","start_node_id":"node-1","evidence_ids":[]}]`, want: "execution_roots[0].evidence_ids must not be empty"},
		{name: "feature", extra: `"features":[{"id":"feature-1","key":"fixture","value":"fixture","evidence_ids":[],"support":"CORROBORATED","execution":{"connectivity":"UNKNOWN"}}]`, want: "features[0].evidence_ids must not be empty"},
		{name: "operation", extra: `"operations":[{"id":"operation-1","subject_node_id":"node-1","kind":"process.execute","resource_bindings":[{"role":"executable","resource":{"kind":"file","value":""}}],"support":"CORROBORATED","execution":{"connectivity":"UNKNOWN"}}]`, want: "operations[0].evidence_ids must not be empty"},
		{name: "artifact property", extra: `"artifact_properties":[{"kind":"fixture","value":"fixture","support":"CORROBORATED"}]`, want: "artifact_properties[0].evidence_ids must not be empty"},
		{name: "network implementation", extra: `"network_implementations":[{"id":"network-1","kind":"dynamic-linkage","subject_node_id":"node-1","support":"DIRECT","execution":{"connectivity":"UNKNOWN"}}]`, want: `missing required member "evidence_ids"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeReport(strings.NewReader(validSavedReportJSON("fixture", test.extra)))
			if err == nil || errors.Is(err, ErrNotReport) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decodeReport() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDecodeReportClassifiesOnlyUnrelatedInputsAsNotReports(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantNotRep bool
		want       string
	}{
		{name: "ordinary object", input: `{"name":"ordinary-json-artifact"}`, wantNotRep: true},
		{name: "unrelated schema", input: `{"schema_version":"example.v1","name":"artifact"}`, wantNotRep: true},
		{name: "non object", input: `[1,2,3]`, wantNotRep: true},
		{name: "brace-leading shell", input: `{ printf '%s\n' safe; }`, wantNotRep: true},
		{name: "malformed before textual marker", input: `{ not_json "schema_version":"` + SchemaVersion + `"`, wantNotRep: true},
		{name: "unrelated JSON plus source", input: `{"name":"artifact"}` + "\nconst value = 1;", wantNotRep: true},
		{name: "unrelated schema plus source", input: `{"schema_version":"example.v1"}` + "\n#!/bin/sh", wantNotRep: true},
		{name: "nested maratus schema", input: `{"metadata":{"schema_version":"` + SchemaVersion + `"}}`, wantNotRep: true},
		{name: "noncanonical schema key", input: `{"Schema_Version":"` + SchemaVersion + `"}`, wantNotRep: true},
		{name: "unsupported maratus schema", input: `{"schema_version":"maratus.report.v0.2","tool":"maratus"}`, want: "unsupported maratus report schema"},
		{name: "malformed object", input: `{"schema_version":"` + SchemaVersion + `"`, want: "invalid report JSON"},
		{name: "current report plus source", input: `{"schema_version":"` + SchemaVersion + `","tool":"maratus"}` + "\nconst value = 1;", want: "trailing data"},
		{name: "current report unknown field", input: `{"schema_version":"` + SchemaVersion + `","tool":"maratus","unexpected":true}`, want: `unknown field "unexpected"`},
		{name: "removed execution chains", input: `{"schema_version":"` + SchemaVersion + `","tool":"maratus","execution_chains":[]}`, want: `unknown field "execution_chains"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeReport(strings.NewReader(test.input))
			if err == nil {
				t.Fatal("decodeReport() unexpectedly succeeded")
			}
			if got := errors.Is(err, ErrNotReport); got != test.wantNotRep {
				t.Fatalf("errors.Is(error, ErrNotReport) = %v, want %v; error = %v", got, test.wantNotRep, err)
			}
			if test.want != "" && !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decodeReport() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDecodeReportRejectsUnknownFieldsInExactSchema(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "top level",
			input: `{"schema_version":"` + SchemaVersion + `","tool":"maratus","artifact_node":[]}`,
			want:  `unknown field "artifact_node"`,
		},
		{
			name: "nested operation",
			input: `{"schema_version":"` + SchemaVersion + `","tool":"maratus",` +
				`"artifact_nodes":[{"id":"node-1","logical_path":"x","kind":"text","analysis_status":"analyzed"}],` +
				`"operations":[{"id":"operation-1","subject_node_id":"node-1","subject":"node-1"}]}`,
			want: `unknown field "subject"`,
		},
		{
			name: "custom evidence decoder",
			input: `{"schema_version":"` + SchemaVersion + `","tool":"maratus",` +
				`"evidence":[{"id":"ev-1","extraction_method":"text","kind":"literal","matched_valeu":"x"}]}`,
			want: `unknown field "matched_valeu"`,
		},
		{
			name:  "nested analysis",
			input: `{"schema_version":"` + SchemaVersion + `","tool":"maratus","analysis":{"expand_containerss":false}}`,
			want:  `unknown field "expand_containerss"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeReport(strings.NewReader(test.input))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decodeReport() error = %v, want %q", err, test.want)
			}
			if errors.Is(err, ErrNotReport) {
				t.Fatalf("recognized report error must not permit artifact fallback: %v", err)
			}
			if !errors.Is(err, ErrRecognizedReport) {
				t.Fatalf("recognized report error is missing its identity marker: %v", err)
			}
		})
	}
}

func TestLoadRejectsDanglingSavedReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dangling.json")
	data := validSavedReportJSON("dangling", `"evidence":[{"id":"ev-1","extraction_method":"fixture","kind":"fixture"}],`+
		`"operations":[{"id":"operation-1","subject_node_id":"missing","kind":"process.execute","resource_bindings":[{"role":"executable","resource":{"kind":"file","value":""}}],"evidence_ids":["ev-1"],"support":"CORROBORATED","execution":{"connectivity":"UNKNOWN"}}]`)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), `operations[0].subject_node_id references missing artifact node "missing"`) {
		t.Fatalf("Load() error = %v, want dangling-reference error", err)
	}
	if errors.Is(err, ErrNotReport) {
		t.Fatalf("dangling report must not permit artifact fallback: %v", err)
	}
}

func TestDecodeReportRejectsInvalidSemanticStateWithoutArtifactFallback(t *testing.T) {
	for _, invalid := range []string{"UNKNOWN", "SUPPORTED"} {
		input := validSavedReportJSON("sample", `"evidence":[{"id":"ev-1","node_id":"node-1","extraction_method":"fixture","kind":"fixture"}],`+
			`"operations":[{"id":"operation-1","subject_node_id":"node-1","kind":"process.execute","resource_bindings":[{"role":"executable","resource":{"kind":"file","value":""}}],"evidence_ids":["ev-1"],"support":"`+invalid+`","execution":{"connectivity":"UNKNOWN"}}]`)
		_, err := decodeReport(strings.NewReader(input))
		if err == nil || !strings.Contains(err.Error(), `operations[0].support has invalid value "`+invalid+`"`) {
			t.Fatalf("decodeReport() error = %v, want invalid semantic-state error for %s", err, invalid)
		}
		if errors.Is(err, ErrNotReport) {
			t.Fatalf("recognized invalid report must not permit artifact fallback: %v", err)
		}
	}
}

func TestDecodeReportRejectsCompactArtifactNodeFloodBeforeTypedDecode(t *testing.T) {
	var input strings.Builder
	input.WriteString(`{"schema_version":"` + SchemaVersion + `","tool":"maratus","artifact_nodes":[`)
	for index := 0; index < artifact.DefaultMaxArtifactNodes+1; index++ {
		if index > 0 {
			input.WriteByte(',')
		}
		input.WriteString(`{}`)
	}
	input.WriteString(`]}`)
	_, err := decodeReport(strings.NewReader(input.String()))
	if err == nil || !strings.Contains(err.Error(), `field "artifact_nodes"`) {
		t.Fatalf("decodeReport() error = %v, want artifact-node limit error", err)
	}
}

func TestValidateReportJSONRejectsAggregateBehaviorFlood(t *testing.T) {
	input := fmt.Sprintf(`{"scopes":%s,"operations":%s}`,
		emptyObjectArray(30_000), emptyObjectArray(behavior.DefaultItemLimit-30_000+behavior.PostLimitCoverageAllowance+1))
	if err := validateReportJSONStructure([]byte(input)); err == nil || !strings.Contains(err.Error(), "aggregate behavior-item limit") {
		t.Fatalf("validateReportJSONStructure() error = %v, want aggregate behavior limit", err)
	}
}

func TestValidateReportJSONAllowsMandatoryPostLimitCoverageMarkers(t *testing.T) {
	input := fmt.Sprintf(`{"scopes":%s,"coverage":%s}`,
		emptyObjectArray(behavior.DefaultItemLimit), emptyObjectArray(behavior.PostLimitCoverageAllowance))
	if err := validateReportJSONStructure([]byte(input)); err != nil {
		t.Fatalf("producer-bounded behavior graph was rejected: %v", err)
	}
}

func TestValidateReportJSONCaseFoldsBoundedTypedFields(t *testing.T) {
	tests := []string{
		fmt.Sprintf(`{"SCOPES":%s,"OpErAtIoNs":%s}`,
			emptyObjectArray(30_000), emptyObjectArray(behavior.DefaultItemLimit-30_000+behavior.PostLimitCoverageAllowance+1)),
		// U+017F LATIN SMALL LETTER LONG S is in the same Unicode simple-fold
		// class as ASCII s, matching encoding/json's field-name behavior.
		fmt.Sprintf(`{"\u017Fcope\u017F":%s,"OPERATION\u017F":%s}`,
			emptyObjectArray(30_000), emptyObjectArray(behavior.DefaultItemLimit-30_000+behavior.PostLimitCoverageAllowance+1)),
	}
	for _, input := range tests {
		if err := validateReportJSONStructure([]byte(input)); err == nil || !strings.Contains(err.Error(), "aggregate behavior-item limit") {
			t.Fatalf("validateReportJSONStructure() error = %v, want case-folded aggregate behavior limit", err)
		}
	}
}

func TestValidateReportJSONRejectsExcessiveNesting(t *testing.T) {
	input := strings.Repeat(`[`, maxReportJSONDepth+1) + strings.Repeat(`]`, maxReportJSONDepth+1)
	if err := validateReportJSONStructure([]byte(input)); err == nil || !strings.Contains(err.Error(), "nesting depth") {
		t.Fatalf("validateReportJSONStructure() error = %v, want nesting-depth error", err)
	}
}

func TestValidateReportJSONRejectsLargeObjectMap(t *testing.T) {
	var input strings.Builder
	input.WriteByte('{')
	for index := 0; index < maxReportJSONObjectMembers+1; index++ {
		if index > 0 {
			input.WriteByte(',')
		}
		fmt.Fprintf(&input, `"k%d":0`, index)
	}
	input.WriteByte('}')
	if err := validateReportJSONStructure([]byte(input.String())); err == nil || !strings.Contains(err.Error(), "member limit") {
		t.Fatalf("validateReportJSONStructure() error = %v, want object-member error", err)
	}
}

func emptyObjectArray(count int) string {
	if count <= 0 {
		return "[]"
	}
	return "[" + strings.Repeat("{},", count-1) + "{}]"
}

func TestDecodeReportRejectsLargeBinaryAfterSniff(t *testing.T) {
	input := &countingBinaryReader{remaining: maxReportInputBytes + 1}
	_, err := decodeReport(input)
	if err == nil || !strings.Contains(err.Error(), "not report JSON") {
		t.Fatalf("decodeReport() error = %v, want non-JSON error", err)
	}
	if input.read > maxReportIdentityBytes {
		t.Fatalf("decodeReport() read %d bytes before rejecting binary input; limit = %d", input.read, maxReportIdentityBytes)
	}
}

func TestDecodeReportBoundsBraceScriptAndWhitespaceSniffs(t *testing.T) {
	tests := []struct {
		name  string
		input io.Reader
	}{
		{
			name:  "brace script",
			input: strings.NewReader("{ function main() { return safe; } }" + strings.Repeat("x", 1<<20)),
		},
		{
			name:  "whitespace",
			input: io.LimitReader(&repeatingByteReader{value: ' '}, maxReportInputBytes+1),
		},
		{
			name: "deep unrelated JSON",
			input: strings.NewReader(`{"value":` + strings.Repeat("[", maxReportIdentityDepth+1) +
				strings.Repeat("]", maxReportIdentityDepth+1) + `}` + strings.Repeat(" ", 1<<20)),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			counted := &countingReader{input: test.input}
			_, err := decodeReport(counted)
			if !errors.Is(err, ErrNotReport) {
				t.Fatalf("decodeReport() error = %v, want ErrNotReport", err)
			}
			if counted.read > maxReportIdentityBytes {
				t.Fatalf("decodeReport() read %d bytes; identity limit = %d", counted.read, maxReportIdentityBytes)
			}
		})
	}
}

func TestDecodeReportFailsClosedAfterCurrentMarker(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "malformed after marker",
			input: `{"schema_version":"` + SchemaVersion + `","tool":`,
			want:  "invalid report JSON",
		},
		{
			name:  "trailing brace script",
			input: `{"schema_version":"` + SchemaVersion + `","tool":"maratus"}` + "\n{ printf safe; }",
			want:  "trailing data",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeReport(strings.NewReader(test.input))
			if err == nil || errors.Is(err, ErrNotReport) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decodeReport() error = %v, want fail-closed %q error", err, test.want)
			}
		})
	}
}

type countingBinaryReader struct {
	remaining int64
	read      int64
}

type countingReader struct {
	input io.Reader
	read  int64
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	read, err := r.input.Read(buffer)
	r.read += int64(read)
	return read, err
}

type repeatingByteReader struct {
	value byte
}

func (r *repeatingByteReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = r.value
	}
	return len(buffer), nil
}

func (r *countingBinaryReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = 0xca
	}
	r.remaining -= int64(len(p))
	r.read += int64(len(p))
	return len(p), nil
}

func validSavedReportJSON(artifactName, extra string) string {
	fields := []string{
		"relationships", "scopes", "analysis_selection", "execution_roots", "invoked_targets", "capability_matches", "features",
		"operations", "operation_relations", "artifact_properties", "network_implementations", "coverage", "evidence",
		"diagnostics",
	}
	var suffix strings.Builder
	for _, field := range fields {
		if strings.Contains(extra, `"`+field+`"`) {
			continue
		}
		fmt.Fprintf(&suffix, `,"%s":[]`, field)
	}
	if extra != "" {
		suffix.WriteByte(',')
		suffix.WriteString(extra)
	}
	return fmt.Sprintf(`{"schema_version":%q,"tool":"maratus","tool_version":"test","ruleset_version":%q,"rule_catalog_digest":%q,"analysis":%s,"artifact":%q,"artifact_nodes":[{"id":"node-1","logical_path":%q,"kind":"text","analysis_status":"analyzed"}]%s}`,
		SchemaVersion, RulesetVersion, rules.CatalogDigest(), testAnalysisJSON, artifactName, artifactName, suffix.String())
}

const testAnalysisJSON = `{"expand_containers":true,"include_unreferenced":false,"allow_dmg_mount":false,"architecture":"all","max_file_bytes":1,"max_archive_bytes":1,"max_expanded_bytes":1,"max_total_bytes":1,"max_archive_depth":1,"max_directory_depth":1,"max_compression_ratio":1,"max_artifact_nodes":1,"max_artifact_path_bytes":1,"max_evidence":1,"max_diagnostics":1,"max_diagnostic_bytes":1,"zip_password_supplied":false}`
