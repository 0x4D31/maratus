package report

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

const SummarySchemaVersion = "maratus.summary.v0.1-preview.11"

const maxSummaryCodeContext = 128

type SummaryCapabilityCategory string

const (
	SummaryCapabilityBehavior       SummaryCapabilityCategory = "behavior"
	SummaryCapabilityTechnical      SummaryCapabilityCategory = "technical-primitive"
	SummaryCapabilityRuntimeSupport SummaryCapabilityCategory = "runtime-support"
)

// Summary is a deterministic, non-authoritative projection of a canonical
// Report. Canonical fact IDs are retained so every row can be resolved back to
// the typed report without creating a second evaluator or fact plane.
type Summary struct {
	SchemaVersion         string                   `json:"schema_version"`
	ReportSchemaVersion   string                   `json:"report_schema_version"`
	Tool                  string                   `json:"tool"`
	ToolVersion           string                   `json:"tool_version"`
	ToolCommit            string                   `json:"tool_commit,omitempty"`
	ToolModified          bool                     `json:"tool_modified,omitempty"`
	RulesetVersion        string                   `json:"ruleset_version"`
	RuleCatalogDigest     string                   `json:"rule_catalog_digest"`
	Analysis              AnalysisMetadata         `json:"analysis"`
	Artifact              string                   `json:"artifact"`
	Overview              SummaryOverview          `json:"result_overview"`
	Capabilities          []SummaryCapability      `json:"operation_backed_capabilities"`
	ConditionalActivation []SummaryActivation      `json:"conditional_activation"`
	ModeledBehavior       []SummaryBehavior        `json:"modeled_behavior"`
	NetworkActivity       []SummaryNetwork         `json:"network_activity"`
	StaticObservables     []SummaryObservable      `json:"static_observables"`
	CodeContext           []SummaryCodeContext     `json:"code_context"`
	CodeContextOmitted    int                      `json:"code_context_omitted,omitempty"`
	ArtifactContext       []SummaryArtifactContext `json:"artifact_context"`
	CoverageGapsAndLimits []SummaryCoverage        `json:"coverage_gaps_and_limits"`
}

type SummaryOverview struct {
	ArtifactType        string         `json:"artifact_type"`
	MemberKinds         map[string]int `json:"member_kinds,omitempty"`
	ArtifactNodes       int            `json:"artifact_nodes"`
	ExecutionRoots      int            `json:"execution_roots"`
	InvokedTargets      int            `json:"invoked_targets"`
	Operations          int            `json:"operations"`
	CapabilityMatches   int            `json:"capability_matches"`
	Features            int            `json:"features"`
	CoverageLimitations int            `json:"coverage_limitations"`
	RootSHA256          string         `json:"root_sha256,omitempty"`
	Notice              string         `json:"notice"`
}

type EntryOperation struct {
	ID      string                 `json:"operation_id"`
	Kind    behavior.OperationKind `json:"kind"`
	Support behavior.Support       `json:"support"`
	Operand string                 `json:"operand,omitempty"`
}
type SummaryActivation struct {
	ConnectedOperationCount int                       `json:"connected_operation_count,omitempty"`
	ConnectedOperations     []EntryOperation          `json:"connected_operations,omitempty"`
	DeclarationNodeID       string                    `json:"declaration_node_id,omitempty"`
	StartScopeID            string                    `json:"start_scope_id,omitempty"`
	EntryPath               string                    `json:"entry_path,omitempty"`
	Context                 []ActivationFact          `json:"context,omitempty"`
	Kind                    string                    `json:"kind"`
	ID                      string                    `json:"id"`
	Name                    string                    `json:"name,omitempty"`
	Interpreter             string                    `json:"interpreter,omitempty"`
	Arguments               []string                  `json:"arguments"`
	NodeID                  string                    `json:"node_id,omitempty"`
	Source                  *behavior.EntityRef       `json:"source,omitempty"`
	Execution               behavior.ExecutionContext `json:"execution"`
	EvidenceIDs             []string                  `json:"evidence_ids"`
}

type ActivationFact struct {
	FeatureID string `json:"feature_id"`
	Label     string `json:"label"`
	Value     string `json:"value"`
}

type SummaryBehavior struct {
	Kind               behavior.OperationKind     `json:"kind"`
	Count              int                        `json:"count"`
	Support            behavior.Support           `json:"support"`
	Connectivity       behavior.Connectivity      `json:"connectivity"`
	SubjectNodeID      string                     `json:"subject_node_id"`
	ScopeID            string                     `json:"scope_id,omitempty"`
	Architecture       string                     `json:"architecture,omitempty"`
	Execution          behavior.ExecutionContext  `json:"execution"`
	OperationIDs       []string                   `json:"operation_ids"`
	Resources          []behavior.ResourceBinding `json:"resources"`
	Implementations    []string                   `json:"implementations,omitempty"`
	RequestedArguments []string                   `json:"requested_arguments,omitempty"`
	Unresolved         []string                   `json:"unresolved,omitempty"`
	Sources            []SummarySource            `json:"sources"`
}

type SummaryCapability struct {
	Category           SummaryCapabilityCategory `json:"category"`
	RuleID             string                    `json:"rule_id"`
	Title              string                    `json:"title"`
	Namespace          string                    `json:"namespace"`
	Count              int                       `json:"count"`
	Support            behavior.Support          `json:"support"`
	Connectivity       behavior.Connectivity     `json:"connectivity"`
	Execution          behavior.ExecutionContext `json:"execution"`
	ArchitectureScopes []string                  `json:"architecture_scopes"`
	SubjectNodeIDs     []string                  `json:"subject_node_ids"`
	MatchIDs           []string                  `json:"match_ids"`
	OperationIDs       []string                  `json:"operation_ids"`
	AffectedResources  []behavior.Resource       `json:"affected_resources"`
	Implementations    []string                  `json:"implementations,omitempty"`
	RequestedArguments []string                  `json:"requested_arguments,omitempty"`
	Unresolved         []string                  `json:"unresolved,omitempty"`
	Attack             []string                  `json:"attack"`
	Sources            []SummarySource           `json:"sources"`
}

type SummaryNetwork struct {
	Direction      string           `json:"direction,omitempty"`
	Destinations   []string         `json:"destinations"`
	Implementation string           `json:"implementation,omitempty"`
	TLSProvider    string           `json:"tls_provider,omitempty"`
	Support        behavior.Support `json:"support,omitempty"`
	OperationIDs   []string         `json:"operation_ids"`
	EvidenceIDs    []string         `json:"evidence_ids"`
	Unresolved     []string         `json:"unresolved,omitempty"`
	StaticOnly     bool             `json:"static_only"`
}

type SummaryObservable struct {
	Category       string           `json:"category"`
	Value          string           `json:"value"`
	Support        behavior.Support `json:"support"`
	FeatureIDs     []string         `json:"feature_ids"`
	EvidenceIDs    []string         `json:"evidence_ids"`
	Sources        []SummarySource  `json:"sources"`
	Interpretation string           `json:"interpretation"`
}

type SummaryCodeContext struct {
	Kind         string   `json:"kind"`
	Name         string   `json:"name"`
	Origin       string   `json:"origin"`
	NodeID       string   `json:"node_id"`
	LogicalPath  string   `json:"logical_path,omitempty"`
	ScopeID      string   `json:"scope_id,omitempty"`
	Architecture string   `json:"architecture,omitempty"`
	FeatureIDs   []string `json:"feature_ids"`
}

type SummaryArtifactContext struct {
	Kind        string           `json:"kind"`
	Value       string           `json:"value"`
	Support     behavior.Support `json:"support"`
	NodeID      string           `json:"node_id,omitempty"`
	EvidenceIDs []string         `json:"evidence_ids"`
}

type SummaryCoverage struct {
	NodeID       string `json:"node_id,omitempty"`
	AnalysisArea string `json:"analysis_area"`
	Status       string `json:"status"`
	Detail       string `json:"detail,omitempty"`
}

type SummarySource struct {
	VirtualAddress uint64 `json:"virtual_address,omitempty"`
	EvidenceID     string `json:"evidence_id"`
	NodeID         string `json:"node_id,omitempty"`
	LogicalPath    string `json:"logical_path,omitempty"`
	Line           int    `json:"line,omitempty"`
	ByteOffset     *int64 `json:"byte_offset,omitempty"`
	Function       string `json:"function,omitempty"`
	Architecture   string `json:"architecture,omitempty"`
}

// SelectedMemberTypes summarizes recognized packages, code and opaque disk images.
func (o SummaryOverview) SelectedMemberTypes() string {
	var parts []string
	for _, kind := range []string{"app-bundle", "pkg", "dmg", "macho-fat", "macho", "script", "compiled-applescript", "java-archive", "asar", "carchive"} {
		if count := o.MemberKinds[kind]; count > 0 {
			parts = append(parts, fmt.Sprintf("%s (%d)", kind, count))
		}
	}
	return strings.Join(parts, ", ")
}

func ProjectSummary(rep Report) Summary {
	summary := Summary{
		SchemaVersion: SummarySchemaVersion, ReportSchemaVersion: rep.SchemaVersion,
		Tool: rep.Tool, ToolVersion: rep.ToolVersion, ToolCommit: rep.ToolCommit, ToolModified: rep.ToolModified,
		RulesetVersion: rep.RulesetVersion, RuleCatalogDigest: rep.RuleCatalogDigest, Analysis: rep.Analysis, Artifact: rep.Artifact,
		Overview: SummaryOverview{
			ArtifactNodes: len(rep.ArtifactNodes), ExecutionRoots: len(rep.ExecutionRoots), InvokedTargets: len(rep.InvokedTargets),
			Operations: len(rep.Operations), CapabilityMatches: len(rep.Capabilities), Features: len(rep.Features),
			RootSHA256: presentationRootSHA256(rep), ArtifactType: artifactType(rep), MemberKinds: map[string]int{},
			Notice: "Static analysis only. CONNECTED means statically reachable from a modeled root; it does not mean observed execution or successful effect.",
		},
		ConditionalActivation: make([]SummaryActivation, 0, len(rep.ExecutionRoots)+len(rep.InvokedTargets)),
		ModeledBehavior:       make([]SummaryBehavior, 0), Capabilities: make([]SummaryCapability, 0),
		NetworkActivity: make([]SummaryNetwork, 0), StaticObservables: make([]SummaryObservable, 0),
		ArtifactContext:       make([]SummaryArtifactContext, 0),
		CoverageGapsAndLimits: make([]SummaryCoverage, 0),
	}
	paths := make(map[string]string, len(rep.ArtifactNodes))
	for _, node := range rep.ArtifactNodes {
		paths[node.ID] = node.LogicalPath
		if node.ParentID != "" {
			summary.Overview.MemberKinds[node.Kind]++
		}
	}
	events := map[string][]ActivationFact{}
	type phaseOwner struct{ root, node, scope string }
	phases := map[phaseOwner][]ActivationFact{}
	for _, f := range rep.Features {
		switch f.Key {
		case "vscode.extension.activation_event":
			events[f.NodeID] = append(events[f.NodeID], ActivationFact{f.ID, "Declared activation event", f.Value})
		case "xcode.build_phase.shell_script":
			for _, id := range f.Execution.ExecutionRootIDs {
				owner := phaseOwner{id, f.NodeID, f.ScopeID}
				phases[owner] = append(phases[owner], ActivationFact{f.ID, "Build target", f.Qualifiers["targets"]}, ActivationFact{f.ID, "Phase script", f.Value})
				for _, field := range []string{"runOnlyForDeploymentPostprocessing", "alwaysOutOfDate"} {
					if v := f.Qualifiers[field]; v == "0" || v == "1" {
						phases[owner] = append(phases[owner], ActivationFact{f.ID, field, v})
					}
				}
			}
		}
	}
	for _, root := range rep.ExecutionRoots {
		var context []ActivationFact
		switch root.Kind {
		case "xcode-run-script":
			context = phases[phaseOwner{root.ID, root.StartNodeID, root.StartScopeID}]
		case "vscode-extension-main":
			context = events[root.DeclarationNodeID]
		}
		summary.ConditionalActivation = append(summary.ConditionalActivation, SummaryActivation{
			DeclarationNodeID: root.DeclarationNodeID, StartScopeID: root.StartScopeID, EntryPath: paths[root.StartNodeID], Context: context, Kind: "execution-root:" + root.Kind, ID: root.ID, Name: root.Name, Interpreter: root.Interpreter,
			Arguments: nonnilStrings(root.Arguments), NodeID: root.StartNodeID,
			Execution:   behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{root.ID}},
			EvidenceIDs: nonnilStrings(root.EvidenceIDs),
		})
	}
	for _, target := range rep.InvokedTargets {
		source := target.Source
		var context []ActivationFact
		if target.Kind == "vscode-extension-browser" && source.Kind == behavior.EntityKindArtifactNode {
			context = events[source.ID]
		}
		summary.ConditionalActivation = append(summary.ConditionalActivation, SummaryActivation{
			EntryPath: paths[target.NodeID], StartScopeID: target.ScopeID, Context: context, Kind: "invoked-target:" + target.Kind, ID: target.ID, Interpreter: target.Interpreter,
			Arguments: nonnilStrings(target.Arguments), NodeID: target.NodeID, Source: &source,
			Execution: target.Execution, EvidenceIDs: nonnilStrings(target.EvidenceIDs),
		})
	}
	projectEntryOperations(summary.ConditionalActivation, rep.Operations)
	summary.ModeledBehavior = projectBehavior(rep)
	summary.Capabilities = projectCapabilities(rep)
	operationsByID := operationsByID(rep.Operations)
	for _, item := range networkPresentationRecords(rep) {
		operationBacked := len(item.OperationIDs) > 0
		if !operationBacked && (item.ImplementationKind != behavior.NetworkImplementationAPICall || item.Support == behavior.SupportHeuristic) {
			continue
		}
		direction := item.Direction
		if direction == "" {
			direction = networkDirectionForOperations(item.OperationIDs, operationsByID)
		}
		summary.NetworkActivity = append(summary.NetworkActivity, SummaryNetwork{
			Direction: direction, Destinations: nonnilStrings(sortedStrings(item.Destinations)), Implementation: item.Caller,
			TLSProvider: item.TLSOwner, Support: item.Support, OperationIDs: nonnilStrings(sortedStrings(item.OperationIDs)),
			EvidenceIDs: nonnilStrings(sortedStrings(item.EvidenceIDs)), Unresolved: nonnilStrings(sortedStrings(item.Unresolved)), StaticOnly: !operationBacked,
		})
	}
	summary.StaticObservables = projectObservables(rep)
	summary.CodeContext, summary.CodeContextOmitted = projectCodeContext(rep)
	summary.ArtifactContext = projectArtifactContext(rep)
	for _, item := range rep.Coverage {
		if item.Status == "analyzed" {
			continue
		}
		summary.CoverageGapsAndLimits = append(summary.CoverageGapsAndLimits, SummaryCoverage(item))
	}
	summary.Overview.CoverageLimitations = len(summary.CoverageGapsAndLimits)
	return summary
}

func projectCodeContext(rep Report) ([]SummaryCodeContext, int) {
	type identity struct{ node, arch, name string }
	rows := make(map[identity]*SummaryCodeContext)
	scopeIDs := make(map[identity]string)
	logicalPaths := make(map[string]string, len(rep.ArtifactNodes))
	for _, node := range rep.ArtifactNodes {
		logicalPaths[node.ID] = node.LogicalPath
	}
	for _, scope := range rep.Scopes {
		if scope.Kind == "function" && scope.Function != "" {
			scopeIDs[identity{scope.NodeID, scope.Architecture, scope.Function}] = scope.ID
		}
	}
	add := func(feature behavior.Feature, name, display, module, origin, scopeID string) {
		if name == "" || origin != "go-other" && origin != "rust-other" && origin != "cxx-other" && origin != "swift-other" {
			return
		}
		key := identity{feature.NodeID, feature.Architecture, name}
		row := rows[key]
		if row == nil {
			kind := "go-function"
			switch origin {
			case "rust-other":
				kind = "rust-function"
			case "cxx-other":
				kind = "cxx-function"
			case "swift-other":
				kind = "swift-function"
			}
			if display == "" {
				display = name
				if module != "" {
					display = module + " · " + name
				}
			}
			row = &SummaryCodeContext{Kind: kind, Name: display, Origin: origin, NodeID: feature.NodeID, LogicalPath: logicalPaths[feature.NodeID], ScopeID: scopeID, Architecture: feature.Architecture, FeatureIDs: []string{}}
			rows[key] = row
		}
		row.FeatureIDs = append(row.FeatureIDs, feature.ID)
	}
	for _, feature := range rep.Features {
		if feature.Key != "macho.function_call" {
			continue
		}
		add(feature, feature.SourceFunction, feature.Qualifiers["function_display"], feature.Qualifiers["function_module"], feature.Qualifiers["function_origin"], feature.ScopeID)
		targetKey := identity{feature.NodeID, feature.Architecture, feature.Value}
		add(feature, feature.Value, feature.Qualifiers["target_display"], feature.Qualifiers["target_module"], feature.Qualifiers["target_origin"], scopeIDs[targetKey])
	}
	result := make([]SummaryCodeContext, 0, len(rows))
	for _, row := range rows {
		row.FeatureIDs = appendUniqueStrings([]string{}, row.FeatureIDs...)
		result = append(result, *row)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := summaryCodeContextPriority(result[i].Name), summaryCodeContextPriority(result[j].Name)
		if left != right {
			return left < right
		}
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		if result[i].NodeID != result[j].NodeID {
			return result[i].NodeID < result[j].NodeID
		}
		return result[i].Architecture < result[j].Architecture
	})
	if len(result) <= maxSummaryCodeContext {
		return result, 0
	}
	return result[:maxSummaryCodeContext], len(result) - maxSummaryCodeContext
}

func summaryCodeContextPriority(name string) int {
	switch {
	case name == "main.main", name == "main", strings.HasSuffix(name, "::main"):
		return 0
	case strings.HasPrefix(name, "main."), strings.HasPrefix(name, "main::"):
		return 1
	default:
		return 2
	}
}

func projectArtifactContext(rep Report) []SummaryArtifactContext {
	rows := make([]SummaryArtifactContext, 0, len(rep.ArtifactProperties))
	for _, item := range uniqueArtifactProperties(rep.ArtifactProperties, false) {
		rows = append(rows, SummaryArtifactContext{
			Kind: item.Kind, Value: artifactPropertyDisplayValue(item), Support: item.Support,
			NodeID: item.NodeID, EvidenceIDs: nonnilStrings(sortedStrings(item.EvidenceIDs)),
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		left, right := summaryArtifactContextPriority(rows[i]), summaryArtifactContextPriority(rows[j])
		if left != right {
			return left < right
		}
		if rows[i].Kind != rows[j].Kind {
			return rows[i].Kind < rows[j].Kind
		}
		if rows[i].Value != rows[j].Value {
			return rows[i].Value < rows[j].Value
		}
		return rows[i].NodeID < rows[j].NodeID
	})
	return rows
}

func summaryArtifactContextPriority(item SummaryArtifactContext) int {
	kind := strings.ToLower(strings.TrimSpace(item.Kind))
	switch {
	case strings.HasPrefix(kind, "go-"), kind == "cargo-package-format":
		return 0
	case kind == "entitlement-context", kind == "entitlement":
		return 1
	case strings.Contains(kind, "signature"), strings.Contains(kind, "code-directory"):
		return 2
	default:
		return 3
	}
}

func projectBehavior(rep Report) []SummaryBehavior {
	type key struct {
		kind         behavior.OperationKind
		support      behavior.Support
		connectivity behavior.Connectivity
		node         string
		resources    string
		context      string
		architecture string
		scope        string
		requested    string
	}
	evidence := evidenceMap(rep.Evidence)
	indexes := map[key]int{}
	rows := make([]SummaryBehavior, 0)
	for _, operation := range rep.Operations {
		identity := key{operation.Kind, operation.Support, executionConnectivity(operation.Execution), operation.SubjectNodeID, summaryBindingIdentity(operation.ResourceBindings), executionContextIdentityKey(operation.Execution), operation.Architecture, operation.ScopeID, semanticIdentityKey(summaryOperationRequestedArguments(operation)...)}
		index, ok := indexes[identity]
		if !ok {
			index = len(rows)
			indexes[identity] = index
			rows = append(rows, SummaryBehavior{Kind: operation.Kind, Support: operation.Support, Connectivity: identity.connectivity, SubjectNodeID: operation.SubjectNodeID, ScopeID: operation.ScopeID, Architecture: operation.Architecture, Execution: operation.Execution, OperationIDs: []string{}, Resources: []behavior.ResourceBinding{}, Implementations: []string{}, Unresolved: []string{}, Sources: []SummarySource{}})
		}
		rows[index].Count++
		rows[index].OperationIDs = append(rows[index].OperationIDs, operation.ID)
		rows[index].Resources = appendUniqueSummaryBindings(rows[index].Resources, operation.ResourceBindings...)
		rows[index].Implementations = appendUniqueStrings(rows[index].Implementations, summaryOperationImplementations(operation)...)
		rows[index].RequestedArguments = appendUniqueStrings(rows[index].RequestedArguments, summaryOperationRequestedArguments(operation)...)
		rows[index].Unresolved = appendUniqueStrings(rows[index].Unresolved, summaryOperationUnresolved(operation)...)
		rows[index].Sources = append(rows[index].Sources, sourcesForEvidence(operation.EvidenceIDs, evidence)...)
	}
	for index := range rows {
		rows[index].Sources = appendUniqueSummarySources([]SummarySource{}, rows[index].Sources...)
		sort.Strings(rows[index].Implementations)
		sort.Strings(rows[index].Unresolved)
	}
	sort.Slice(rows, func(i, j int) bool {
		if left, right := summaryBehaviorPriority(rows[i]), summaryBehaviorPriority(rows[j]); left != right {
			return left < right
		}
		if rows[i].Kind != rows[j].Kind {
			return rows[i].Kind < rows[j].Kind
		}
		if rows[i].Support != rows[j].Support {
			return rows[i].Support < rows[j].Support
		}
		if rows[i].Connectivity != rows[j].Connectivity {
			return rows[i].Connectivity < rows[j].Connectivity
		}
		if rows[i].SubjectNodeID != rows[j].SubjectNodeID {
			return rows[i].SubjectNodeID < rows[j].SubjectNodeID
		}
		if rows[i].Architecture != rows[j].Architecture {
			return rows[i].Architecture < rows[j].Architecture
		}
		if rows[i].ScopeID != rows[j].ScopeID {
			return rows[i].ScopeID < rows[j].ScopeID
		}
		if left, right := executionContextIdentityKey(rows[i].Execution), executionContextIdentityKey(rows[j].Execution); left != right {
			return left < right
		}
		if left, right := semanticIdentityKey(rows[i].RequestedArguments...), semanticIdentityKey(rows[j].RequestedArguments...); left != right {
			return left < right
		}
		return summaryBindingIdentity(rows[i].Resources) < summaryBindingIdentity(rows[j].Resources)
	})
	return rows
}

// This ordering prioritizes actionable requests, not maliciousness or runtime
// occurrence. Generic inventory remains present in the projection.
func summaryBehaviorPriority(row SummaryBehavior) int {
	concrete := len(row.RequestedArguments) > 0
	for _, binding := range row.Resources {
		if binding.Resource.Value != "" && (binding.Resource.Kind == behavior.ResourceFile || binding.Resource.Kind == behavior.ResourceURL || binding.Resource.Kind == behavior.ResourceCommand) {
			concrete = true
		}
	}
	if concrete {
		switch row.Kind {
		case behavior.OperationProcessExecute, behavior.OperationInterpreterInvoke, behavior.OperationNetworkDownload, behavior.OperationNetworkUpload, behavior.OperationArchiveCreate:
			return 0
		}
		return 1
	}
	return 2
}

func summaryOperationRequestedArguments(operation behavior.ModeledOperation) []string {
	var values []string
	for _, key := range []string{"command_argument", "executable_argument"} {
		if value := operation.Qualifiers[key]; value != "" {
			values = append(values, strings.ReplaceAll(key, "_", " ")+": "+value)
		}
	}
	return values
}

func summaryOperationImplementations(operation behavior.ModeledOperation) []string {
	var out []string
	for _, key := range []string{"api", "selector", "tool", "mechanism", "function_origin", "argument_binding"} {
		if value := strings.TrimSpace(operation.Qualifiers[key]); value != "" {
			label := strings.ReplaceAll(key, "_", " ")
			out = appendUniqueStrings(out, label+": "+value)
		}
	}
	return out
}

func summaryOperationUnresolved(operation behavior.ModeledOperation) []string {
	var unresolved []string
	for _, key := range []string{"unresolved_arguments", "unresolved_process_options"} {
		if value := strings.TrimSpace(operation.Qualifiers[key]); value != "" {
			unresolved = appendUniqueStrings(unresolved, value)
		}
	}
	for _, binding := range operation.ResourceBindings {
		if !binding.Resource.Unresolved() {
			continue
		}
		label := strings.ReplaceAll(string(binding.Role), "_", " ")
		switch binding.Role {
		case behavior.ResourceRoleRemoteDestination, behavior.ResourceRoleRemoteSource:
			label = "destination"
		case behavior.ResourceRoleLocalOutput:
			label = "output"
		case behavior.ResourceRoleLocalInput:
			label = "input"
		case behavior.ResourceRoleTarget:
			if destination := strings.TrimSpace(operation.Qualifiers["destination_operand"]); destination != "" {
				label = "target (operand: " + destination + ")"
			}
		case behavior.ResourceRoleJob:
			if destination := strings.TrimSpace(operation.Qualifiers["destination_operand"]); destination != "" {
				label = "job (operand: " + destination + ")"
			}
		}
		if label == "" {
			label = "resource argument"
		}
		unresolved = appendUniqueStrings(unresolved, label)
	}
	if strings.EqualFold(strings.TrimSpace(operation.Qualifiers["resource_binding"]), "unresolved") && len(unresolved) == 0 {
		unresolved = appendUniqueStrings(unresolved, "resource argument")
	}
	return unresolved
}

func summaryBindingIdentity(bindings []behavior.ResourceBinding) string {
	parts := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		classifications := append([]behavior.ResourceClassification(nil), binding.Resource.Classifications...)
		sort.Slice(classifications, func(i, j int) bool { return classifications[i] < classifications[j] })
		classificationParts := make([]string, len(classifications))
		for index := range classifications {
			classificationParts[index] = string(classifications[index])
		}
		parts = append(parts, semanticIdentityKey(string(binding.Role), string(binding.Resource.Kind), binding.Resource.Value, semanticIdentityKey(classificationParts...)))
	}
	sort.Strings(parts)
	return semanticIdentityKey(parts...)
}

func projectCapabilities(rep Report) []SummaryCapability {
	type key struct {
		category                                SummaryCapabilityCategory
		rule, support, connectivity             string
		node, context, architectures, resources string
	}
	indexes := map[key]int{}
	rows := make([]SummaryCapability, 0)
	seenOperations := make(map[int]map[string]bool)
	operations := operationsByID(rep.Operations)
	evidence := evidenceMap(rep.Evidence)
	for _, match := range rep.Capabilities {
		category := summaryCapabilityCategory(match, operations)
		identity := key{category, match.RuleID, string(match.Support), string(executionConnectivity(match.Execution)), match.SubjectNodeID, executionContextIdentityKey(match.Execution), semanticIdentityKey(match.ArchitectureScopes...), resourcesKey(match.AffectedResources)}
		index, ok := indexes[identity]
		if !ok {
			index = len(rows)
			indexes[identity] = index
			rows = append(rows, SummaryCapability{Category: category, RuleID: match.RuleID, Title: match.Title, Namespace: match.Namespace, Support: match.Support, Connectivity: executionConnectivity(match.Execution), Execution: match.Execution, ArchitectureScopes: nonnilStrings(match.ArchitectureScopes), SubjectNodeIDs: []string{}, MatchIDs: []string{}, OperationIDs: []string{}, AffectedResources: []behavior.Resource{}, Implementations: []string{}, Unresolved: []string{}, Attack: []string{}, Sources: []SummarySource{}})
		}
		rows[index].Count++
		rows[index].SubjectNodeIDs = append(rows[index].SubjectNodeIDs, match.SubjectNodeID)
		rows[index].MatchIDs = append(rows[index].MatchIDs, match.ID)
		rows[index].OperationIDs = append(rows[index].OperationIDs, match.OperationIDs...)
		rows[index].AffectedResources = append(rows[index].AffectedResources, match.AffectedResources...)
		for _, operationID := range match.OperationIDs {
			if seenOperations[index] == nil {
				seenOperations[index] = make(map[string]bool)
			}
			if seenOperations[index][operationID] {
				continue
			}
			seenOperations[index][operationID] = true
			operation, ok := operations[operationID]
			if !ok {
				continue
			}
			rows[index].Implementations = append(rows[index].Implementations, summaryOperationImplementations(operation)...)
			rows[index].RequestedArguments = appendUniqueStrings(rows[index].RequestedArguments, summaryOperationRequestedArguments(operation)...)
			rows[index].Unresolved = append(rows[index].Unresolved, summaryOperationUnresolved(operation)...)
			rows[index].Sources = append(rows[index].Sources, sourcesForEvidence(operation.EvidenceIDs, evidence)...)
		}
		rows[index].Attack = append(rows[index].Attack, match.Attack...)
	}

	for index := range rows {
		rows[index].SubjectNodeIDs = appendUniqueStrings([]string{}, rows[index].SubjectNodeIDs...)
		rows[index].OperationIDs = appendUniqueStrings([]string{}, rows[index].OperationIDs...)
		rows[index].AffectedResources = appendUniqueSummaryResources([]behavior.Resource{}, rows[index].AffectedResources...)
		rows[index].Implementations = appendUniqueStrings([]string{}, rows[index].Implementations...)
		rows[index].Unresolved = appendUniqueStrings([]string{}, rows[index].Unresolved...)
		rows[index].Attack = appendUniqueStrings([]string{}, rows[index].Attack...)
		rows[index].Sources = appendUniqueSummarySources([]SummarySource{}, rows[index].Sources...)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Category != rows[j].Category {
			return rows[i].Category < rows[j].Category
		}
		if rows[i].Namespace != rows[j].Namespace {
			return rows[i].Namespace < rows[j].Namespace
		}
		if rows[i].RuleID != rows[j].RuleID {
			return rows[i].RuleID < rows[j].RuleID
		}
		if left, right := semanticIdentityKey(rows[i].SubjectNodeIDs...), semanticIdentityKey(rows[j].SubjectNodeIDs...); left != right {
			return left < right
		}
		if left, right := executionContextIdentityKey(rows[i].Execution), executionContextIdentityKey(rows[j].Execution); left != right {
			return left < right
		}
		if left, right := semanticIdentityKey(rows[i].ArchitectureScopes...), semanticIdentityKey(rows[j].ArchitectureScopes...); left != right {
			return left < right
		}
		if rows[i].Support != rows[j].Support {
			return rows[i].Support < rows[j].Support
		}
		return resourcesKey(rows[i].AffectedResources) < resourcesKey(rows[j].AffectedResources)
	})
	return rows
}

func summaryCapabilityCategory(match behavior.CapabilityMatch, operations map[string]behavior.ModeledOperation) SummaryCapabilityCategory {
	if len(match.OperationIDs) > 0 {
		runtimeOnly := true
		for _, operationID := range match.OperationIDs {
			operation, ok := operations[operationID]
			if !ok || !runtimeSupportFunctionOrigin(operation.Qualifiers["function_origin"]) {
				runtimeOnly = false
				break
			}
		}
		if runtimeOnly {
			return SummaryCapabilityRuntimeSupport
		}
	}
	if strings.HasPrefix(match.Namespace, "macos.technical.") {
		return SummaryCapabilityTechnical
	}
	return SummaryCapabilityBehavior
}

func runtimeSupportFunctionOrigin(origin string) bool {
	switch origin {
	case "go-runtime-compiler", "go-standard-library", "rust-runtime-compiler", "rust-standard-library", "cxx-runtime-compiler", "cxx-standard-library", "swift-runtime-compiler", "swift-standard-library":
		return true
	default:
		return false
	}
}

func projectObservables(rep Report) []SummaryObservable {
	evidence := evidenceMap(rep.Evidence)
	type key struct{ category, value string }
	indexes := map[key]int{}
	rows := make([]SummaryObservable, 0)
	add := func(category, value string, feature behavior.Feature, interpretation string) {
		identity := key{category, value}
		index, exists := indexes[identity]
		if !exists {
			index = len(rows)
			indexes[identity] = index
			rows = append(rows, SummaryObservable{Category: category, Value: value, Support: feature.Support, FeatureIDs: []string{}, EvidenceIDs: []string{}, Sources: []SummarySource{}, Interpretation: interpretation})
		}
		rows[index].Support = weakerSummarySupport(rows[index].Support, feature.Support)
		rows[index].FeatureIDs = append(rows[index].FeatureIDs, feature.ID)
		rows[index].EvidenceIDs = append(rows[index].EvidenceIDs, feature.EvidenceIDs...)
		rows[index].Sources = append(rows[index].Sources, sourcesForEvidence(feature.EvidenceIDs, evidence)...)
	}
	for _, feature := range uniqueFeatures(rep.Features) {
		category, ok := notableFeatureCategory(feature)
		if !ok {
			continue
		}
		add(category, feature.Value, feature, notableFeatureInterpretation(feature))
		if feature.Key == "network.url" {
			if domain := observableURLDomain(feature.Value); domain != "" {
				add("domain", domain, feature, "hostname parsed from an exact retained URL; communication is not established")
			}
		}
	}

	for index := range rows {
		rows[index].FeatureIDs = appendUniqueStrings([]string{}, rows[index].FeatureIDs...)
		rows[index].EvidenceIDs = appendUniqueStrings([]string{}, rows[index].EvidenceIDs...)
		rows[index].Sources = appendUniqueSummarySources([]SummarySource{}, rows[index].Sources...)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Category != rows[j].Category {
			return rows[i].Category < rows[j].Category
		}
		return rows[i].Value < rows[j].Value
	})
	return rows
}

func observableURLDomain(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" || !strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func weakerSummarySupport(left, right behavior.Support) behavior.Support {
	rank := func(value behavior.Support) int {
		switch value {
		case behavior.SupportDirect:
			return 0
		case behavior.SupportCorroborated:
			return 1
		case behavior.SupportHeuristic:
			return 2
		default:
			return 3
		}
	}
	if left == "" || rank(right) > rank(left) {
		return right
	}
	return left
}

func sourcesForEvidence(ids []string, index map[string]behavior.Evidence) []SummarySource {
	rows := make([]SummarySource, 0, len(ids))
	for _, id := range ids {
		evidence, ok := index[id]
		if !ok {
			continue
		}
		row := SummarySource{VirtualAddress: evidence.VA, EvidenceID: id, NodeID: evidence.NodeID, LogicalPath: evidence.Logical, Line: evidence.Line, Function: evidence.Function, Architecture: evidence.Arch}
		if evidence.ByteOffsetKnown() {
			offset := evidence.Offset
			row.ByteOffset = &offset
		}
		rows = append(rows, row)
	}
	return rows
}

func appendUniqueSummarySources(target []SummarySource, values ...SummarySource) []SummarySource {
	seen := map[string]bool{}
	for _, item := range target {
		seen[item.EvidenceID] = true
	}
	for _, item := range values {
		if !seen[item.EvidenceID] {
			seen[item.EvidenceID] = true
			target = append(target, item)
		}
	}
	sort.Slice(target, func(i, j int) bool { return target[i].EvidenceID < target[j].EvidenceID })
	return target
}

func appendUniqueSummaryBindings(target []behavior.ResourceBinding, values ...behavior.ResourceBinding) []behavior.ResourceBinding {
	seen := map[string]bool{}
	for _, item := range target {
		seen[string(item.Role)+"\x00"+string(item.Resource.Key())] = true
	}
	for _, item := range values {
		key := string(item.Role) + "\x00" + string(item.Resource.Key())
		if !seen[key] {
			seen[key] = true
			target = append(target, item)
		}
	}
	sort.Slice(target, func(i, j int) bool {
		if target[i].Role != target[j].Role {
			return target[i].Role < target[j].Role
		}
		return target[i].Resource.Key() < target[j].Resource.Key()
	})
	return target
}

func appendUniqueSummaryResources(target []behavior.Resource, values ...behavior.Resource) []behavior.Resource {
	seen := map[behavior.ResourceKey]bool{}
	for _, item := range target {
		seen[item.Key()] = true
	}
	for _, item := range values {
		if !seen[item.Key()] {
			seen[item.Key()] = true
			target = append(target, item)
		}
	}
	sort.Slice(target, func(i, j int) bool { return target[i].Key() < target[j].Key() })
	return target
}

func appendUniqueStrings(target []string, values ...string) []string {
	seen := map[string]bool{}
	for _, value := range target {
		seen[value] = true
	}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			target = append(target, value)
		}
	}
	sort.Strings(target)
	return target
}

// Index explicit ownership once. The bounded examples refer to canonical operations.
func projectEntryOperations(entries []SummaryActivation, operations []behavior.ModeledOperation) {
	byID := make(map[string]*SummaryActivation, len(entries))
	for i := range entries {
		byID[entries[i].ID] = &entries[i]
	}
	retain := func(id string, op *behavior.ModeledOperation) {
		entry := byID[id]
		if entry == nil {
			return
		}
		entry.ConnectedOperationCount++
		if len(entry.ConnectedOperations) >= 8 {
			return
		}
		operand := summaryBehaviorResource(SummaryBehavior{Kind: op.Kind, Resources: op.ResourceBindings})
		entry.ConnectedOperations = append(entry.ConnectedOperations, EntryOperation{op.ID, op.Kind, op.Support, operand})
	}
	for i := range operations {
		op := &operations[i]
		if op.Execution.Connectivity != behavior.ConnectivityConnected {
			continue
		}
		for _, id := range op.Execution.ExecutionRootIDs {
			retain(id, op)
		}
		for _, id := range op.Execution.InvokedTargetIDs {
			retain(id, op)
		}
	}
}

func nonnilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return append([]string(nil), values...)
}

func WriteSummaryJSON(w io.Writer, rep Report) error { return WriteJSON(w, ProjectSummary(rep)) }

func WriteSummaryText(w io.Writer, rep Report, options TextOptions) error {
	summary := ProjectSummary(rep)
	p := newPresentation(w, rep, options)
	p.header("STATIC ANALYSIS")
	p.summary()
	if members := summary.Overview.SelectedMemberTypes(); members != "" {
		p.keyValue("Contains", members)
	}
	if len(summary.ConditionalActivation) > 0 {
		p.summaryActivation(summary)
	}
	p.conciseCapabilities()
	if summary.Overview.Operations == 0 && summary.Overview.ExecutionRoots == 0 {
		paths := make(map[string]string, len(rep.ArtifactNodes))
		for _, node := range rep.ArtifactNodes {
			paths[node.ID] = node.LogicalPath
		}
		shown := map[string]bool{}
		for _, gap := range summary.CoverageGapsAndLimits {
			if gap.NodeID == "" || (gap.Status != "partial" && gap.Status != "unsupported") || shown[gap.AnalysisArea] || gap.Detail == "" {
				continue
			}
			if len(shown) == 0 {
				p.section("ANALYSIS LIMITS AT SOURCE", "")
			}
			shown[gap.AnalysisArea] = true
			p.printf("  %s  [%s]\n", boundedText(filepath.Base(paths[gap.NodeID]), 60), gap.NodeID)
			for _, line := range conciseWrappedLines(boundedText(gap.Detail, 240), 90) {
				p.printf("    %s\n", line)
			}
			if len(shown) == 2 {
				break
			}
		}
	}
	p.conciseAttack()
	p.summaryCodeContext(summary)
	p.summaryAdditionalBehavior(summary)
	p.conciseNetworkBehavior()
	p.conciseObservables()
	p.conciseArtifactProperty()
	p.conciseNote("Static analysis only. CONNECTED means modeled reachability, not observed execution or successful effect.")
	return p.output.err
}

func (p *presentation) summaryCodeContext(summary Summary) {
	if len(summary.CodeContext) == 0 {
		return
	}
	total := len(summary.CodeContext) + summary.CodeContextOmitted
	p.section("LANGUAGE FUNCTION CONTEXT", countLabel(total, "function"))
	shown := min(len(summary.CodeContext), 12)
	for _, item := range summary.CodeContext[:shown] {
		location := item.LogicalPath
		if location == "" {
			location = item.NodeID
		}
		if item.Architecture != "" {
			location += " · " + item.Architecture
		}
		p.printf("  %-54s  %s\n", boundedText(item.Name, 54), boundedText(location, 42))
	}
	omitted := total - shown
	if omitted > 0 {
		p.omitted(omitted, "language functions")
	}
	p.println("  " + p.style.faint("Exact non-runtime/standard-library identity from bounded Go metadata or Rust/C++/Swift symbols and retained direct calls."))
	p.println("  " + p.style.faint("Function names do not by themselves establish behavior or application ownership."))
}

func (p *presentation) summaryActivation(summary Summary) {
	p.section("CONDITIONAL ACTIVATION", countLabel(len(summary.ConditionalActivation), "path"))
	if len(summary.ConditionalActivation) == 0 {
		p.println("  No trusted static host-selection or execution-root relationship was established.")
		return
	}
	for _, item := range summary.ConditionalActivation[:min(len(summary.ConditionalActivation), 12)] {
		label := strings.TrimPrefix(item.Kind, "execution-root:")
		label = strings.TrimPrefix(label, "invoked-target:")
		args := append([]string{item.Interpreter}, item.Arguments...)
		for i, arg := range args {
			if arg == item.EntryPath {
				if _, member, ok := strings.Cut(arg, "!"); ok {
					args[i] = member
				}
			}
		}
		detail := strings.TrimSpace(strings.Join(args, " "))
		if item.Name != "" && item.Name != detail {
			detail = strings.TrimSpace(item.Name + "  " + detail)
		}
		p.printf("  %-24s  %s  [%s]\n", boundedText(label, 24), boundedText(detail, 66), item.ID)
		for _, fact := range item.Context[:min(len(item.Context), 6)] {
			label, value := fact.Label, fact.Value
			if label == "Phase script" {
				label = "Script excerpt"
				for line := range strings.Lines(value) {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						value = line
						break
					}
				}
			}
			p.printf("    %s  %s  [%s]\n", label, boundedText(value, 64), fact.FeatureID)
		}
		for _, op := range item.ConnectedOperations[:min(3, len(item.ConnectedOperations))] {
			p.printf("    %s  %s  %s  [%s]\n", op.Kind, op.Support, boundedText(op.Operand, 54), op.ID)
		}
		if remaining := item.ConnectedOperationCount - min(3, len(item.ConnectedOperations)); remaining > 0 {
			p.omitted(remaining, "connected operations")
		}
		if len(item.Context) > 6 {
			p.omitted(len(item.Context)-6, "activation details")
		}
	}
	if len(summary.ConditionalActivation) > 12 {
		p.omitted(len(summary.ConditionalActivation)-12, "activation paths")
	}
}

func (p *presentation) summaryAdditionalBehavior(summary Summary) {
	matched := map[string]bool{}
	for _, capability := range summary.Capabilities {
		for _, operationID := range capability.OperationIDs {
			matched[operationID] = true
		}
	}
	rowsToShow := make([]SummaryBehavior, 0, len(summary.ModeledBehavior))
	for _, row := range summary.ModeledBehavior {
		additional := row.Support == behavior.SupportHeuristic || summaryBehaviorHasConcreteResource(row)
		for _, operationID := range row.OperationIDs {
			if !matched[operationID] {
				additional = true
				break
			}
		}
		if additional {
			rowsToShow = append(rowsToShow, row)
		}
	}
	if len(rowsToShow) == 0 {
		return
	}
	rows := summaryBehaviorTextRows(rowsToShow)
	p.section("ADDITIONAL MODELED BEHAVIOR", countLabel(len(rows), "group"))
	p.printf("  %-24s  %5s  %-13s  %-11s  %s\n", p.style.key("OPERATION"), p.style.key("COUNT"), p.style.key("SUPPORT"), p.style.key("REACHABILITY"), p.style.key("DETAIL"))
	for _, row := range rows[:min(len(rows), 24)] {
		details := conciseWrappedLines(row.Detail, 40)
		if len(details) > 2 {
			details = details[:2]
			details[1] = boundedText(details[1]+" …", 40)
		}
		firstDetail := ""
		if len(details) > 0 {
			firstDetail = details[0]
		}
		p.printf("  %-24s  %5d  %-13s  %-11s  %s\n", boundedText(string(row.Kind), 24), row.Count, row.Support, row.Connectivity, firstDetail)
		if len(details) > 1 {
			for _, detail := range details[1:] {
				p.printf("%63s%s\n", "", detail)
			}
		}
		if row.Context != "" {
			p.printf("%63s%s\n", "", p.style.faint(boundedText(row.Context, 40)))
		}
	}
	if len(rows) > 24 {
		p.omitted(len(rows)-24, "behavior groups")
	}
	p.println(p.style.faint("  Shows heuristic, unmatched, or concretely bound operations not fully conveyed by the capability table."))
}

func summaryBehaviorHasConcreteResource(row SummaryBehavior) bool {
	for _, binding := range row.Resources {
		if strings.TrimSpace(binding.Resource.Value) != "" {
			return true
		}
	}
	return false
}

type summaryBehaviorTextRow struct {
	Kind         behavior.OperationKind
	Count        int
	Support      behavior.Support
	Connectivity behavior.Connectivity
	Detail       string
	Context      string
	priority     int
}

func summaryBehaviorTextRows(rows []SummaryBehavior) []summaryBehaviorTextRow {
	type key struct {
		kind                                 behavior.OperationKind
		support                              behavior.Support
		connectivity                         behavior.Connectivity
		node, scope, architecture, execution string
	}
	type aggregate struct {
		row             summaryBehaviorTextRow
		resources       map[string]bool
		implementations map[string]bool
		unresolved      map[string]bool
		requested       map[string]bool
	}
	indexes := map[key]int{}
	groups := make([]aggregate, 0, len(rows))
	for _, row := range rows {
		identity := key{row.Kind, row.Support, row.Connectivity, row.SubjectNodeID, row.ScopeID, row.Architecture, executionContextIdentityKey(row.Execution)}
		index, ok := indexes[identity]
		if !ok {
			index = len(groups)
			indexes[identity] = index
			groups = append(groups, aggregate{
				row:             summaryBehaviorTextRow{Kind: row.Kind, Support: row.Support, Connectivity: row.Connectivity, Context: summaryBehaviorContext(row), priority: summaryBehaviorPriority(row)},
				resources:       map[string]bool{},
				implementations: map[string]bool{},
				unresolved:      map[string]bool{},
				requested:       map[string]bool{},
			})
		}
		groups[index].row.Count += row.Count
		groups[index].resources[summaryBehaviorResource(row)] = true
		groups[index].row.priority = min(groups[index].row.priority, summaryBehaviorPriority(row))
		for _, item := range row.RequestedArguments {
			groups[index].requested[item] = true
		}
		for _, item := range row.Implementations {
			groups[index].implementations[item] = true
		}
		for _, item := range row.Unresolved {
			groups[index].unresolved[item] = true
		}
	}
	out := make([]summaryBehaviorTextRow, 0, len(groups))
	for _, group := range groups {
		resources := make([]string, 0, len(group.resources))
		for resource := range group.resources {
			if resource != "" {
				resources = append(resources, resource)
			}
		}
		sort.Strings(resources)
		var details []string
		if resourceDetail := summaryBehaviorResourceDetail(group.row.Kind, resources); resourceDetail != "" {
			details = append(details, resourceDetail)
		}
		details = append(details, mapKeysSorted(group.requested)...)
		unresolved := mapKeysSorted(group.unresolved)
		if len(unresolved) > 0 {
			details = append(details, strings.Join(unresolved, ", ")+" unresolved")
		}
		implementations := mapKeysSorted(group.implementations)
		if len(implementations) > 0 {
			for index := range implementations {
				implementations[index] = "via " + strings.TrimPrefix(implementations[index], "api: ")
			}
			details = append(details, strings.Join(implementations, ", "))
		}
		group.row.Detail = strings.Join(details, " · ")
		out = append(out, group.row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].priority != out[j].priority {
			return out[i].priority < out[j].priority
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Support != out[j].Support {
			return out[i].Support < out[j].Support
		}
		if out[i].Connectivity != out[j].Connectivity {
			return out[i].Connectivity < out[j].Connectivity
		}
		if out[i].Context != out[j].Context {
			return out[i].Context < out[j].Context
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}

func summaryBehaviorContext(row SummaryBehavior) string {
	context := row.SubjectNodeID
	for _, source := range row.Sources {
		if source.LogicalPath != "" {
			context = source.LogicalPath
			if source.VirtualAddress != 0 {
				context = fmt.Sprintf("evidence %#x · %s · %s", source.VirtualAddress, source.Function, context)
			}
			break
		}
	}
	if row.Architecture != "" {
		context = strings.TrimSpace(context + " [" + row.Architecture + "]")
	}
	return context
}

func summaryBehaviorResourceDetail(kind behavior.OperationKind, resources []string) string {
	if len(resources) == 0 {
		return ""
	}
	const limit = 6
	shown := min(len(resources), limit)
	values := make([]string, 0, shown)
	for _, resource := range resources[:shown] {
		values = append(values, boundedText(resource, 48))
	}
	detail := strings.Join(values, ", ")
	if len(resources) > shown {
		detail += fmt.Sprintf(" (+%d more)", len(resources)-shown)
	}
	if kind == behavior.OperationProcessExecute || kind == behavior.OperationProcessLaunchConfigure {
		for _, resource := range resources {
			if strings.Contains(resource, " argv ") {
				if len(resources) == 1 {
					return "command: " + detail
				}
				return "commands/executables: " + detail
			}
		}
		if len(resources) == 1 {
			return "executable: " + detail
		}
		return "executables: " + detail
	}
	if len(resources) == 1 {
		return detail
	}
	return "resources: " + detail
}

func mapKeysSorted(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func summaryBehaviorResource(row SummaryBehavior) string {
	byRole := map[behavior.ResourceRole]behavior.Resource{}
	for _, binding := range row.Resources {
		if _, exists := byRole[binding.Role]; !exists {
			byRole[binding.Role] = binding.Resource
		}
	}
	value := func(role behavior.ResourceRole) string { return strings.TrimSpace(byRole[role].Value) }
	flow := func(from, to behavior.ResourceRole) string {
		left, right := value(from), value(to)
		switch {
		case left != "" && right != "":
			return left + " → " + right
		case right != "":
			return right
		default:
			return left
		}
	}
	var selected string
	switch row.Kind {
	case behavior.OperationArchiveCreate, behavior.OperationFileCopy:
		selected = flow(behavior.ResourceRoleSource, behavior.ResourceRoleLocalOutput)
	case behavior.OperationNetworkDownload:
		selected = value(behavior.ResourceRoleLocalOutput)
	case behavior.OperationNetworkUpload:
		selected = value(behavior.ResourceRoleLocalInput)
	case behavior.OperationProcessExecute, behavior.OperationProcessLaunchConfigure:
		executable := value(behavior.ResourceRoleExecutable)
		arguments := value(behavior.ResourceRoleArguments)
		if arguments != "" {
			if executable == "" {
				executable = "<unresolved executable>"
			}
			selected = executable + " argv " + arguments
		} else {
			selected = executable
		}
	}
	if selected != "" {
		return selected
	}
	for _, binding := range row.Resources {
		if isNetworkOperation(row.Kind) && (binding.Role == behavior.ResourceRoleRemoteDestination || binding.Role == behavior.ResourceRoleRemoteSource) {
			continue
		}
		if binding.Resource.Value != "" {
			return binding.Resource.Value
		}
	}
	return ""
}
