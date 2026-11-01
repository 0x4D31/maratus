package extract

import (
	"crypto/sha256"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/plistx"
)

const (
	maxXcodeBuildSettingReferenceBytes = 64 << 10
	maxXcodeResolvedSettingBytes       = 256 << 10
	maxXcodeBuildConfigurations        = 128
	maxXcodeBuildSettingProofs         = 24
	maxXcodeBuildSettingProofBytes     = 64 << 10
	maxXcodeResolvedConfigurationBytes = 64 << 10
	maxXcodeXCConfigBytes              = 1 << 20
	maxXcodeBuildSettingResolutionWork = 4 * behavior.DefaultItemLimit
)

var xcodeBuildSettingCommandPattern = regexp.MustCompile(
	`^(?:/bin/)?(sh|bash|zsh)[ \t]+-c[ \t]+"\$\{([A-Za-z_][A-Za-z0-9_]*)\}"[ \t]*$`,
)

type xcodeShellSettingReference struct {
	tool string
	key  string
}

type xcodeBuildConfiguration struct {
	id              string
	name            string
	settings        plistx.Dict
	baseReferenceID string
}

type xcodeBuildSettingProof struct {
	content          artifact.Content
	method           string
	kind             string
	value            string
	relationToNodeID string
}

type xcodeBuildSettingResolution struct {
	value          string
	configurations []string
	proofs         []xcodeBuildSettingProof
	reason         string
}

type xcodeBuildSettingAccumulator struct {
	configurations     []string
	configurationKeys  map[string]bool
	configurationBytes int
	proofs             []xcodeBuildSettingProof
	proofKeys          map[string]bool
	proofBytes         int
}

type xcodeBuildSettingContentIndex struct {
	byBase          map[string][]xcodeBuildSettingIndexedContent
	xcconfigAbsence map[xcodeXCConfigAbsenceCacheKey]string
}

type xcodeBuildSettingIndexedContent struct {
	// retainedIndex is the exact occurrence in the immutable retained-content
	// slice. Paths and node IDs alone are not sufficient identities for a
	// conservative absence cache.
	retainedIndex int
	content       artifact.Content
}

type xcodeXCConfigAbsenceCacheKey struct {
	retainedIndex int
	setting       string
}

type xcodeProjectGroupIndex struct {
	mainGroupID   string
	parentByChild map[string]string
	ambiguous     map[string]bool
}

type xcodeBuildSettingProjectModel struct {
	objects              plistx.Dict
	referenced           map[string][]xcodeTargetReference
	projectByName        map[string]xcodeBuildConfiguration
	groupIndex           xcodeProjectGroupIndex
	targetConfigurations map[string][]xcodeBuildConfiguration
	targetReasons        map[string]string
	reason               string
}

// ResolveXcodeBuildSettings completes the one supported cross-file Xcode
// substitution after every retained content item is indexed. It deliberately
// does not implement general Xcode expansion or shell evaluation.
func ResolveXcodeBuildSettings(graph *behavior.Graph, artifacts *artifact.Graph, contents []artifact.Content) {
	resolveXcodeBuildSettings(graph, artifacts, contents, maxXcodeBuildSettingResolutionWork)
}

func resolveXcodeBuildSettings(graph *behavior.Graph, artifacts *artifact.Graph, contents []artifact.Content, workLimit int) {
	var contentByNode map[string]artifact.Content
	var rootByID map[string]behavior.ExecutionRoot
	var index xcodeBuildSettingContentIndex
	models := map[string]*xcodeBuildSettingProjectModel{}
	work := newDerivedWorkBudget(workLimit)
	featureCount := len(graph.Features)
	for featureIndex := 0; featureIndex < featureCount; featureIndex++ {
		feature := graph.Features[featureIndex]
		if feature.Key != "xcode.build_phase.shell_script" {
			continue
		}
		reference, ok := xcodeShellBuildSettingReference(feature.Value)
		if !ok {
			continue
		}
		if feature.Execution.Connectivity != behavior.ConnectivityConnected ||
			len(feature.Execution.ExecutionRootIDs) != 1 || feature.ScopeID == "" {
			continue
		}
		if rootByID == nil {
			rootByID = make(map[string]behavior.ExecutionRoot, len(graph.ExecutionRoots))
			for _, root := range graph.ExecutionRoots {
				rootByID[root.ID] = root
			}
		}
		root, ok := rootByID[feature.Execution.ExecutionRootIDs[0]]
		if !ok || root.Kind != "xcode-run-script" || !xcodeSupportedShellPath(root.Interpreter) ||
			root.DeclarationNodeID != feature.NodeID ||
			root.StartScopeID != feature.ScopeID {
			continue
		}
		if contentByNode == nil {
			contentByNode = make(map[string]artifact.Content, len(contents))
			for _, content := range contents {
				if content.NodeID != "" && !content.RawFeaturesOnly {
					contentByNode[content.NodeID] = content
				}
			}
			index = newXcodeBuildSettingContentIndex(contents)
		}
		content, ok := contentByNode[feature.NodeID]
		if !ok {
			continue
		}
		if graph.WorkLimitReached() {
			markDerivedGraphLimit(graph, "xcode-build-setting-resolution")
			return
		}
		if !work.take() {
			markDerivedWorkLimit(graph, "xcode-build-setting-resolution", workLimit, "Xcode build-setting references")
			return
		}
		phaseID := strings.TrimSpace(feature.Qualifiers["phase_id"])
		if phaseID == "" {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				"xcode-build-setting-resolution",
				xcodeBuildSettingCoverageDetail(feature.ScopeID, "the referenced run-script phase did not retain its PBX object identifier"),
			)
			continue
		}
		model := models[content.NodeID]
		if model == nil {
			model = loadXcodeBuildSettingProjectModel(graph, content, &work)
			models[content.NodeID] = model
		}
		resolution := resolveXcodeBuildSetting(content, index, model, phaseID, reference, &work)
		if resolution.reason != "" {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				"xcode-build-setting-resolution",
				xcodeBuildSettingCoverageDetail(feature.ScopeID, resolution.reason),
			)
			continue
		}
		if len(feature.EvidenceIDs)+len(resolution.proofs)+1 > behavior.MaxCausalEvidenceIDs {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				"xcode-build-setting-resolution",
				xcodeBuildSettingCoverageDetail(
					feature.ScopeID,
					fmt.Sprintf("causal evidence count exceeded the %d-item limit", behavior.MaxCausalEvidenceIDs),
				),
			)
			continue
		}
		proofEvidenceIDs, ok := addXcodeBuildSettingProofEvidence(graph, artifacts, content.NodeID, resolution)
		if !ok {
			markDerivedGraphLimit(graph, "xcode-build-setting-resolution")
			return
		}
		digest := sha256.Sum256([]byte(resolution.value))
		resolutionEvidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:   content.NodeID,
			ScopeID:  feature.ScopeID,
			Logical:  content.LogicalPath,
			Physical: content.PhysicalPath,
			Method:   "xcode-project",
			Kind:     "xcode-build-setting-resolution",
			Value: fmt.Sprintf(
				"%s -> sha256:%x bytes:%d configurations:%s",
				reference.key,
				digest,
				len(resolution.value),
				strings.Join(resolution.configurations, ","),
			),
		})
		if resolutionEvidenceID == "" {
			markDerivedGraphLimit(graph, "xcode-build-setting-resolution")
			return
		}
		evidenceIDs := append([]string(nil), feature.EvidenceIDs...)
		evidenceIDs = append(evidenceIDs, proofEvidenceIDs...)
		evidenceIDs = append(evidenceIDs, resolutionEvidenceID)
		evidenceIDs = sortedUniqueNonemptyStrings(evidenceIDs)
		if graph.AddFeature(behavior.Feature{
			NodeID:  content.NodeID,
			ScopeID: feature.ScopeID,
			Key:     "xcode.build_setting.resolved",
			Value:   reference.key,
			Qualifiers: map[string]string{
				"bytes":          fmt.Sprintf("%d", len(resolution.value)),
				"configurations": strings.Join(resolution.configurations, ","),
				"sha256":         fmt.Sprintf("%x", digest),
			},
			EvidenceIDs: evidenceIDs,
			Support:     behavior.SupportCorroborated,
			Execution:   feature.Execution,
		}) == "" {
			markDerivedGraphLimit(graph, "xcode-build-setting-resolution")
			return
		}

		scriptContent := content
		scriptContent.ScopeID = feature.ScopeID
		scriptContent.SemanticLanguage = "shell"
		scriptContent.BehaviorAnalysisForced = true
		scriptContent.SupportingEvidenceIDs = evidenceIDs
		scriptContent = contentWithExecutionContext(scriptContent, feature.Execution)
		start := graph.CaptureGraphRange()
		handleInterpreter(
			graph,
			scriptContent,
			reference.tool,
			[]string{reference.tool, "-c", resolution.value},
			0,
			feature.Execution,
			resolutionEvidenceID,
		)
		if resolution.value != "" {
			AnalyzeInlineCode(graph, scriptContent, "shell", resolution.value, feature.Execution, resolutionEvidenceID)
		}
		corroborateXcodeDerivedGraphRange(graph, start, evidenceIDs)
	}
}

func xcodeBuildSettingCoverageDetail(scopeID, reason string) string {
	if scopeID == "" {
		return reason
	}
	return "run-script scope " + scopeID + ": " + reason
}

func xcodeShellBuildSettingReference(script string) (xcodeShellSettingReference, bool) {
	if len(script) == 0 || len(script) > maxXcodeBuildSettingReferenceBytes {
		return xcodeShellSettingReference{}, false
	}
	var command string
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if command != "" {
			return xcodeShellSettingReference{}, false
		}
		command = line
	}
	match := xcodeBuildSettingCommandPattern.FindStringSubmatch(command)
	if len(match) != 3 {
		return xcodeShellSettingReference{}, false
	}
	return xcodeShellSettingReference{tool: match[1], key: match[2]}, true
}

func loadXcodeBuildSettingProjectModel(
	graph *behavior.Graph,
	content artifact.Content,
	work *derivedWorkBudget,
) *xcodeBuildSettingProjectModel {
	model := &xcodeBuildSettingProjectModel{
		targetConfigurations: map[string][]xcodeBuildConfiguration{},
		targetReasons:        map[string]string{},
	}
	data, ok := boundedStructuredDocument(graph, content, "xcode-project", content.Data)
	if !ok {
		model.reason = "the Xcode project exceeded the structured-document limit"
		return model
	}
	project, err := plistx.Decode(data)
	if err != nil {
		model.reason = "the Xcode project could not be decoded while resolving a referenced build setting"
		return model
	}
	objects, ok := project["objects"].(plistx.Dict)
	if !ok {
		model.reason = "the Xcode project objects dictionary was malformed while resolving a referenced build setting"
		return model
	}
	referenced, complete := xcodeReferencedBuildPhases(graph, content, project, objects, work)
	if !complete {
		model.reason = "target build-phase references were incomplete while resolving a referenced build setting"
		return model
	}
	rootObjectID := plistx.String(project, "rootObject")
	rootObject, ok := objects[rootObjectID].(plistx.Dict)
	if rootObjectID == "" || !ok || plistx.String(rootObject, "isa") != "PBXProject" {
		model.reason = "the root PBXProject was unavailable while resolving a referenced build setting"
		return model
	}
	if rawProjectDirPath, present := rootObject["projectDirPath"]; present {
		projectDirPath, valid := rawProjectDirPath.(string)
		if !valid || projectDirPath != "" {
			model.reason = "the root PBXProject projectDirPath was nonempty or malformed and is unsupported"
			return model
		}
	}
	projectConfigurations, reason := xcodeConfigurationList(
		objects,
		plistx.String(rootObject, "buildConfigurationList"),
		work,
	)
	if reason != "" {
		model.reason = "project " + reason
		return model
	}
	projectByName := make(map[string]xcodeBuildConfiguration, len(projectConfigurations))
	for _, configuration := range projectConfigurations {
		if _, duplicate := projectByName[configuration.name]; duplicate {
			model.reason = "project configuration names were duplicated"
			return model
		}
		projectByName[configuration.name] = configuration
	}
	groupIndex, reason := newXcodeProjectGroupIndex(objects, plistx.String(rootObject, "mainGroup"), work)
	if reason != "" {
		model.reason = reason
		return model
	}
	model.objects = objects
	model.referenced = referenced
	model.projectByName = projectByName
	model.groupIndex = groupIndex
	return model
}

func (model *xcodeBuildSettingProjectModel) xcodeTargetConfigurations(
	target xcodeTargetReference,
	work *derivedWorkBudget,
) ([]xcodeBuildConfiguration, string) {
	if configurations, ok := model.targetConfigurations[target.id]; ok {
		return configurations, model.targetReasons[target.id]
	}
	targetObject, ok := model.objects[target.id].(plistx.Dict)
	if !ok || !xcodeBuildTargetKind(plistx.String(targetObject, "isa")) {
		model.targetReasons[target.id] = "object was unavailable or malformed"
		return nil, model.targetReasons[target.id]
	}
	configurations, reason := xcodeConfigurationList(
		model.objects,
		plistx.String(targetObject, "buildConfigurationList"),
		work,
	)
	model.targetConfigurations[target.id] = configurations
	model.targetReasons[target.id] = reason
	return configurations, reason
}

func resolveXcodeBuildSetting(
	content artifact.Content,
	index xcodeBuildSettingContentIndex,
	model *xcodeBuildSettingProjectModel,
	phaseID string,
	reference xcodeShellSettingReference,
	work *derivedWorkBudget,
) xcodeBuildSettingResolution {
	if model == nil || model.reason != "" {
		reason := "the Xcode project model was unavailable while resolving a referenced build setting"
		if model != nil {
			reason = model.reason
		}
		return xcodeBuildSettingResolution{reason: reason}
	}
	targets := sortedUniqueXcodeTargetReferences(model.referenced[phaseID])
	if len(targets) == 0 {
		return xcodeBuildSettingResolution{reason: "the referenced build-setting command was not owned by a retained target build phase"}
	}

	var expectedValue string
	expectedSet := false
	accumulator := xcodeBuildSettingAccumulator{
		configurationKeys: map[string]bool{},
		proofKeys:         map[string]bool{},
	}
	for _, target := range targets {
		targetConfigurations, reason := model.xcodeTargetConfigurations(target, work)
		if reason != "" {
			return xcodeBuildSettingResolution{reason: "target " + target.name + " " + reason}
		}
		targetNames := make(map[string]bool, len(targetConfigurations))
		for _, targetConfiguration := range targetConfigurations {
			if targetNames[targetConfiguration.name] {
				return xcodeBuildSettingResolution{reason: "target configuration names were duplicated"}
			}
			targetNames[targetConfiguration.name] = true
			projectConfiguration, ok := model.projectByName[targetConfiguration.name]
			if !ok {
				return xcodeBuildSettingResolution{reason: "target and project configuration names did not align"}
			}
			value, sourceLevel, reason := xcodeEffectiveBuildSetting(
				content,
				index,
				model.objects,
				model.groupIndex,
				projectConfiguration,
				targetConfiguration,
				reference.key,
				work,
				&accumulator,
			)
			if reason != "" {
				return xcodeBuildSettingResolution{reason: reason}
			}
			if reason := xcodeResolvedBuildSettingValueReason(value); reason != "" {
				return xcodeBuildSettingResolution{reason: reason}
			}
			if !expectedSet {
				expectedValue = value
				expectedSet = true
			} else if value != expectedValue {
				return xcodeBuildSettingResolution{reason: "effective build-setting values differed across target configurations"}
			}
			if reason := accumulator.addConfiguration(
				target.name + "/" + targetConfiguration.name + "(" + sourceLevel + ")",
			); reason != "" {
				return xcodeBuildSettingResolution{reason: reason}
			}
		}
		if len(targetNames) != len(model.projectByName) {
			return xcodeBuildSettingResolution{reason: "target and project configuration sets did not align"}
		}
		for name := range model.projectByName {
			if !targetNames[name] {
				return xcodeBuildSettingResolution{reason: "target and project configuration sets did not align"}
			}
		}
	}
	if !expectedSet {
		return xcodeBuildSettingResolution{reason: "no effective target configuration was available for the referenced build setting"}
	}
	configurations := sortedUniqueNonemptyStrings(accumulator.configurations)
	return xcodeBuildSettingResolution{
		value:          expectedValue,
		configurations: configurations,
		proofs:         accumulator.proofs,
	}
}

func xcodeConfigurationList(objects plistx.Dict, listID string, work *derivedWorkBudget) ([]xcodeBuildConfiguration, string) {
	list, ok := objects[listID].(plistx.Dict)
	if listID == "" || !ok || plistx.String(list, "isa") != "XCConfigurationList" {
		return nil, "build configuration list was absent or malformed"
	}
	rawConfigurationIDs, ok := list["buildConfigurations"].([]any)
	if !ok || len(rawConfigurationIDs) == 0 {
		return nil, "build configuration references were absent or malformed"
	}
	if len(rawConfigurationIDs) > maxXcodeBuildConfigurations {
		return nil, fmt.Sprintf("build configuration count exceeded the %d-item limit", maxXcodeBuildConfigurations)
	}
	if work == nil || len(rawConfigurationIDs) > work.remaining {
		return nil, "build configuration resolution work limit was reached"
	}
	configurationIDs, ok := xcodeStringArray(rawConfigurationIDs)
	if !ok {
		return nil, "build configuration references were absent or malformed"
	}
	sort.Strings(configurationIDs)
	configurations := make([]xcodeBuildConfiguration, 0, len(configurationIDs))
	for _, configurationID := range configurationIDs {
		if work == nil || !work.take() {
			return nil, "build configuration resolution work limit was reached"
		}
		object, ok := objects[configurationID].(plistx.Dict)
		if !ok || plistx.String(object, "isa") != "XCBuildConfiguration" {
			return nil, "referenced build configuration was absent or malformed"
		}
		name := plistx.String(object, "name")
		settings, ok := object["buildSettings"].(plistx.Dict)
		if name == "" || !ok {
			return nil, "referenced build configuration name or settings dictionary was absent or malformed"
		}
		baseReferenceID := ""
		if rawBaseReferenceID, present := object["baseConfigurationReference"]; present {
			value, valid := rawBaseReferenceID.(string)
			value = strings.TrimSpace(value)
			if !valid || value == "" {
				return nil, "referenced build configuration base configuration reference was empty or malformed"
			}
			baseReferenceID = value
		}
		configurations = append(configurations, xcodeBuildConfiguration{
			id:              configurationID,
			name:            name,
			settings:        settings,
			baseReferenceID: baseReferenceID,
		})
	}
	sort.Slice(configurations, func(i, j int) bool {
		if configurations[i].name != configurations[j].name {
			return configurations[i].name < configurations[j].name
		}
		return configurations[i].id < configurations[j].id
	})
	return configurations, ""
}

func xcodeEffectiveBuildSetting(
	projectContent artifact.Content,
	index xcodeBuildSettingContentIndex,
	objects plistx.Dict,
	groupIndex xcodeProjectGroupIndex,
	projectConfiguration xcodeBuildConfiguration,
	targetConfiguration xcodeBuildConfiguration,
	key string,
	work *derivedWorkBudget,
	accumulator *xcodeBuildSettingAccumulator,
) (string, string, string) {
	conditional, reason := xcodeBuildSettingHasConditionalVariant(targetConfiguration.settings, key, work)
	if reason != "" {
		return "", "", reason
	}
	if conditional {
		return "", "", "a target build configuration used a conditional variant of the referenced setting"
	}
	if value, present, valid := xcodeBuildSettingScalar(targetConfiguration.settings, key); present {
		if !valid || xcodeBuildSettingUsesInheritedValue(value) {
			return "", "", "a target build configuration had a non-scalar or inherited referenced setting"
		}
		if reason := addXcodeProjectSettingProof(accumulator, projectContent, targetConfiguration, key, value, "target"); reason != "" {
			return "", "", reason
		}
		return value, "target", ""
	}
	if targetConfiguration.baseReferenceID != "" {
		baseContent, reason := xcodeTargetBaseConfigurationContent(
			projectContent,
			index,
			objects,
			groupIndex,
			targetConfiguration.baseReferenceID,
			work,
		)
		if reason != "" {
			return "", "", reason
		}
		if reason := index.xcodeXCConfigProvesSettingAbsent(baseContent, key); reason != "" {
			return "", "", reason
		}
		referenceProofKey := fmt.Sprintf("xcconfig-reference:%s:%d", targetConfiguration.id, baseContent.retainedIndex)
		if reason := accumulator.addProof(
			referenceProofKey,
			xcodeBuildSettingProof{
				content:          projectContent,
				method:           "xcode-project",
				kind:             "xcode-base-configuration-reference",
				value:            fmt.Sprintf("target configuration %s [%s] baseConfigurationReference %s -> %s", targetConfiguration.name, targetConfiguration.id, targetConfiguration.baseReferenceID, baseContent.content.LogicalPath),
				relationToNodeID: baseContent.content.NodeID,
			},
		); reason != "" {
			return "", "", reason
		}
		proofKey := fmt.Sprintf("xcconfig:%d:%s", baseContent.retainedIndex, key)
		if reason := accumulator.addProof(
			proofKey,
			xcodeBuildSettingProof{
				content: baseContent.content,
				method:  "xcode-xcconfig",
				kind:    "xcode-build-setting-absence",
				value:   key + " is not assigned and no unsupported '#' marker is present",
			},
		); reason != "" {
			return "", "", reason
		}
	}
	conditional, reason = xcodeBuildSettingHasConditionalVariant(projectConfiguration.settings, key, work)
	if reason != "" {
		return "", "", reason
	}
	if conditional {
		return "", "", "a project build configuration used a conditional variant of the referenced setting"
	}
	value, present, valid := xcodeBuildSettingScalar(projectConfiguration.settings, key)
	if !present {
		return "", "", "the referenced setting was absent from an effective target/project configuration"
	}
	if !valid || xcodeBuildSettingUsesInheritedValue(value) {
		return "", "", "a project build configuration had a non-scalar or inherited referenced setting"
	}
	if reason := addXcodeProjectSettingProof(accumulator, projectContent, projectConfiguration, key, value, "project"); reason != "" {
		return "", "", reason
	}
	return value, "project", ""
}

func xcodeBuildSettingScalar(settings plistx.Dict, key string) (string, bool, bool) {
	raw, present := settings[key]
	if !present {
		return "", false, false
	}
	value, ok := raw.(string)
	return value, true, ok
}

func xcodeBuildSettingHasConditionalVariant(
	settings plistx.Dict,
	key string,
	work *derivedWorkBudget,
) (bool, string) {
	if work == nil || len(settings) > work.remaining {
		return false, "conditional build-setting scan work limit was reached"
	}
	candidates := make([]string, 0, len(settings))
	for candidate := range settings {
		candidates = append(candidates, candidate)
	}
	sort.Strings(candidates)
	for _, candidate := range candidates {
		if work == nil || !work.take() {
			return false, "conditional build-setting scan work limit was reached"
		}
		if candidate != key && strings.HasPrefix(candidate, key+"[") {
			return true, ""
		}
	}
	return false, ""
}

func xcodeBuildSettingUsesInheritedValue(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "$(inherited)") || strings.Contains(lower, "${inherited}")
}

func xcodeResolvedBuildSettingValueReason(value string) string {
	if len(value) > maxXcodeResolvedSettingBytes {
		return fmt.Sprintf("the effective build-setting value exceeded the %d-byte limit", maxXcodeResolvedSettingBytes)
	}
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return "the effective build-setting value was not bounded UTF-8 text"
	}
	if strings.Contains(value, "$") {
		return "the effective build-setting value contained a nested Xcode or runtime expansion"
	}
	return ""
}

func addXcodeProjectSettingProof(
	accumulator *xcodeBuildSettingAccumulator,
	content artifact.Content,
	configuration xcodeBuildConfiguration,
	key, value, level string,
) string {
	proofKey := level + ":" + configuration.id + ":" + key
	if accumulator.proofKeys[proofKey] {
		return ""
	}
	digest := sha256.Sum256([]byte(value))
	return accumulator.addProof(proofKey, xcodeBuildSettingProof{
		content: content,
		method:  "xcode-project",
		kind:    "xcode-build-setting-declaration",
		value: fmt.Sprintf(
			"%s %s [%s] %s -> sha256:%x bytes:%d",
			level,
			configuration.name,
			configuration.id,
			key,
			digest,
			len(value),
		),
	})
}

func (accumulator *xcodeBuildSettingAccumulator) addConfiguration(value string) string {
	if value == "" || accumulator.configurationKeys[value] {
		return ""
	}
	if len(accumulator.configurations) >= maxXcodeBuildConfigurations {
		return fmt.Sprintf("resolved configuration count exceeded the %d-item limit", maxXcodeBuildConfigurations)
	}
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 ||
		len(value) > maxXcodeResolvedConfigurationBytes-accumulator.configurationBytes {
		return fmt.Sprintf("resolved configuration labels exceeded the %d-byte limit", maxXcodeResolvedConfigurationBytes)
	}
	accumulator.configurationKeys[value] = true
	accumulator.configurationBytes += len(value)
	accumulator.configurations = append(accumulator.configurations, value)
	return ""
}

func (accumulator *xcodeBuildSettingAccumulator) addProof(
	key string,
	proof xcodeBuildSettingProof,
) string {
	if accumulator.proofKeys[key] {
		return ""
	}
	if len(accumulator.proofs) >= maxXcodeBuildSettingProofs {
		return fmt.Sprintf("build-setting proof count exceeded the %d-item limit", maxXcodeBuildSettingProofs)
	}
	size := xcodeBuildSettingProofBytes(proof)
	if size < 0 || size > maxXcodeBuildSettingProofBytes-accumulator.proofBytes {
		return fmt.Sprintf("build-setting proof data exceeded the %d-byte limit", maxXcodeBuildSettingProofBytes)
	}
	accumulator.proofKeys[key] = true
	accumulator.proofBytes += size
	accumulator.proofs = append(accumulator.proofs, proof)
	return ""
}

func xcodeBuildSettingProofBytes(proof xcodeBuildSettingProof) int {
	values := []string{
		proof.content.NodeID,
		proof.content.ScopeID,
		proof.content.LogicalPath,
		proof.content.PhysicalPath,
		proof.method,
		proof.kind,
		proof.value,
	}
	total := 0
	for _, value := range values {
		if len(value) > maxXcodeBuildSettingProofBytes-total {
			return -1
		}
		total += len(value)
	}
	return total
}

func newXcodeBuildSettingContentIndex(contents []artifact.Content) xcodeBuildSettingContentIndex {
	index := xcodeBuildSettingContentIndex{
		byBase:          map[string][]xcodeBuildSettingIndexedContent{},
		xcconfigAbsence: map[xcodeXCConfigAbsenceCacheKey]string{},
	}
	for retainedIndex, content := range contents {
		if content.RawFeaturesOnly || content.LogicalPath == "" {
			continue
		}
		base := strings.ToLower(virtualBase(content.LogicalPath))
		index.byBase[base] = append(index.byBase[base], xcodeBuildSettingIndexedContent{
			retainedIndex: retainedIndex,
			content:       content,
		})
	}
	for base := range index.byBase {
		sort.Slice(index.byBase[base], func(i, j int) bool {
			left := index.byBase[base][i]
			right := index.byBase[base][j]
			if left.content.LogicalPath != right.content.LogicalPath {
				return left.content.LogicalPath < right.content.LogicalPath
			}
			return left.retainedIndex < right.retainedIndex
		})
	}
	return index
}

func newXcodeProjectGroupIndex(objects plistx.Dict, mainGroupID string, work *derivedWorkBudget) (xcodeProjectGroupIndex, string) {
	if mainGroupID != "" {
		mainGroup, ok := objects[mainGroupID].(plistx.Dict)
		if !ok || plistx.String(mainGroup, "isa") != "PBXGroup" {
			mainGroupID = ""
		}
	}
	index := xcodeProjectGroupIndex{
		mainGroupID:   mainGroupID,
		parentByChild: map[string]string{},
		ambiguous:     map[string]bool{},
	}
	if work == nil || len(objects) > work.remaining {
		return xcodeProjectGroupIndex{}, "PBX group resolution work limit was reached"
	}
	objectIDs := make([]string, 0, len(objects))
	for objectID := range objects {
		objectIDs = append(objectIDs, objectID)
	}
	sort.Strings(objectIDs)
	for _, objectID := range objectIDs {
		if work == nil || !work.take() {
			return xcodeProjectGroupIndex{}, "PBX group resolution work limit was reached"
		}
		object, ok := objects[objectID].(plistx.Dict)
		if !ok || plistx.String(object, "isa") != "PBXGroup" {
			continue
		}
		rawChildren, ok := object["children"].([]any)
		if !ok {
			continue
		}
		if len(rawChildren) > maxXcodeTargetPhaseReferences ||
			len(rawChildren) > work.remaining {
			return xcodeProjectGroupIndex{}, "PBX group child resolution work limit was reached"
		}
		children, ok := xcodeStringArray(rawChildren)
		if !ok {
			continue
		}
		for _, childID := range children {
			if !work.take() {
				return xcodeProjectGroupIndex{}, "PBX group child resolution work limit was reached"
			}
			if parentID, exists := index.parentByChild[childID]; exists && parentID != objectID {
				index.ambiguous[childID] = true
				continue
			}
			index.parentByChild[childID] = objectID
		}
	}
	return index, ""
}

func xcodeBaseConfigurationRelativePath(objects plistx.Dict, index xcodeProjectGroupIndex, referenceID string) (string, string) {
	fileReference, ok := objects[referenceID].(plistx.Dict)
	if !ok || plistx.String(fileReference, "isa") != "PBXFileReference" {
		return "", "a target base-configuration file reference was absent or malformed"
	}
	referencePath := plistx.String(fileReference, "path")
	switch plistx.String(fileReference, "sourceTree") {
	case "SOURCE_ROOT":
		return referencePath, ""
	case "<group>":
	default:
		return "", "a target base-configuration file used an unsupported sourceTree"
	}
	if index.mainGroupID == "" {
		return "", "the root PBXProject mainGroup was absent or malformed while resolving a target base configuration"
	}
	var groupPaths []string
	current := referenceID
	seen := map[string]bool{referenceID: true}
	for depth := 0; depth < 128; depth++ {
		if index.ambiguous[current] {
			return "", "a target base-configuration group parent was ambiguous"
		}
		parentID := index.parentByChild[current]
		if parentID == "" {
			return "", "a target base-configuration group did not reach the root PBXProject mainGroup"
		}
		if seen[parentID] {
			return "", "a target base-configuration group hierarchy contained a cycle"
		}
		seen[parentID] = true
		group, ok := objects[parentID].(plistx.Dict)
		if !ok || plistx.String(group, "isa") != "PBXGroup" ||
			plistx.String(group, "sourceTree") != "<group>" {
			return "", "a target base-configuration group hierarchy was malformed or used an unsupported sourceTree"
		}
		if groupPath := plistx.String(group, "path"); groupPath != "" {
			groupPath, ok := safeXcodeRelativePath(groupPath)
			if !ok {
				return "", "a target base-configuration group path was unsafe"
			}
			groupPaths = append(groupPaths, groupPath)
		}
		if parentID == index.mainGroupID {
			for left, right := 0, len(groupPaths)-1; left < right; left, right = left+1, right-1 {
				groupPaths[left], groupPaths[right] = groupPaths[right], groupPaths[left]
			}
			groupPaths = append(groupPaths, referencePath)
			return path.Join(groupPaths...), ""
		}
		current = parentID
	}
	return "", "a target base-configuration group hierarchy exceeded the 128-level depth limit"
}

func xcodeTargetBaseConfigurationContent(
	projectContent artifact.Content,
	index xcodeBuildSettingContentIndex,
	objects plistx.Dict,
	groupIndex xcodeProjectGroupIndex,
	referenceID string,
	work *derivedWorkBudget,
) (xcodeBuildSettingIndexedContent, string) {
	referencePath, reason := xcodeBaseConfigurationRelativePath(objects, groupIndex, referenceID)
	if reason != "" {
		return xcodeBuildSettingIndexedContent{}, reason
	}
	referencePath, ok := safeXcodeRelativePath(referencePath)
	if !ok || !strings.EqualFold(path.Ext(referencePath), ".xcconfig") {
		return xcodeBuildSettingIndexedContent{}, "a target base-configuration path was absent, unsafe, or unsupported"
	}
	sourceRoot, ok := xcodeProjectSourceRoot(projectContent.LogicalPath)
	if !ok {
		return xcodeBuildSettingIndexedContent{}, "the Xcode project source root could not be determined"
	}
	expectedLogical := path.Clean(path.Join(sourceRoot, referencePath))
	if strings.HasSuffix(sourceRoot, "!") {
		expectedLogical = sourceRoot + referencePath
	}
	candidates := index.byBase[strings.ToLower(path.Base(referencePath))]
	var matches []xcodeBuildSettingIndexedContent
	for _, candidate := range candidates {
		if work == nil || !work.take() {
			return xcodeBuildSettingIndexedContent{}, "base-configuration content resolution work limit was reached"
		}
		logical := path.Clean(strings.ReplaceAll(candidate.content.LogicalPath, "\\", "/"))
		if logical == expectedLogical {
			matches = append(matches, candidate)
		}
	}
	if len(matches) == 0 {
		return xcodeBuildSettingIndexedContent{}, "a target base-configuration file was absent from the retained artifact"
	}
	if len(matches) != 1 {
		return xcodeBuildSettingIndexedContent{}, "a target base-configuration path was ambiguous in the retained artifact"
	}
	return matches[0], ""
}

func safeXcodeRelativePath(value string) (string, bool) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "!$") {
		return "", false
	}
	cleaned := path.Clean(value)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return cleaned, true
}

func xcodeProjectSourceRoot(logical string) (string, bool) {
	logical = strings.ReplaceAll(logical, "\\", "/")
	prefix := ""
	inner := logical
	if separator := strings.LastIndexByte(logical, '!'); separator >= 0 {
		prefix = logical[:separator+1]
		inner = logical[separator+1:]
	}
	inner = path.Clean(inner)
	if strings.ToLower(path.Base(inner)) != "project.pbxproj" ||
		!strings.HasSuffix(strings.ToLower(path.Base(path.Dir(inner))), ".xcodeproj") {
		return "", false
	}
	root := path.Dir(path.Dir(inner))
	if root == "/" {
		return "", false
	}
	if root == "." {
		if prefix != "" {
			return prefix, true
		}
		return ".", true
	}
	return prefix + root, true
}

func xcodeXCConfigProvesSettingAbsent(content artifact.Content, key string) string {
	if len(content.Data) > maxXcodeXCConfigBytes {
		return fmt.Sprintf("a target base-configuration file exceeded the %d-byte inspection limit", maxXcodeXCConfigBytes)
	}
	if !utf8.Valid(content.Data) {
		return "a target base-configuration file was not complete UTF-8 text"
	}
	text := string(content.Data)
	if strings.IndexByte(text, 0) >= 0 {
		return "a target base-configuration file was not complete UTF-8 text"
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	if strings.Contains(text, "\\\n") {
		return "a target base-configuration file used unsupported line continuation"
	}
	if strings.Contains(text, "#") {
		return "a target base-configuration file contained an unsupported '#' marker"
	}
	for _, line := range strings.Split(text, "\n") {
		// Build-setting identifiers are lexical. Conservatively reject any
		// occurrence of the referenced identifier rather than trying to
		// interpret conditional assignments, comments, or uncommon operators.
		if strings.Contains(line, key) {
			return "a target base-configuration file mentioned the referenced setting; its override semantics were not resolved"
		}
	}
	return ""
}

func (index xcodeBuildSettingContentIndex) xcodeXCConfigProvesSettingAbsent(
	content xcodeBuildSettingIndexedContent,
	key string,
) string {
	cacheKey := xcodeXCConfigAbsenceCacheKey{
		retainedIndex: content.retainedIndex,
		setting:       key,
	}
	if reason, cached := index.xcconfigAbsence[cacheKey]; cached {
		return reason
	}
	reason := xcodeXCConfigProvesSettingAbsent(content.content, key)
	index.xcconfigAbsence[cacheKey] = reason
	return reason
}

func addXcodeBuildSettingProofEvidence(
	graph *behavior.Graph,
	artifacts *artifact.Graph,
	projectNodeID string,
	resolution xcodeBuildSettingResolution,
) ([]string, bool) {
	proofs := append([]xcodeBuildSettingProof(nil), resolution.proofs...)
	sort.Slice(proofs, func(i, j int) bool {
		if proofs[i].content.LogicalPath != proofs[j].content.LogicalPath {
			return proofs[i].content.LogicalPath < proofs[j].content.LogicalPath
		}
		if proofs[i].kind != proofs[j].kind {
			return proofs[i].kind < proofs[j].kind
		}
		return proofs[i].value < proofs[j].value
	})
	type retainedProofEvidence struct {
		proof      xcodeBuildSettingProof
		evidenceID string
	}
	evidenceIDs := make([]string, 0, len(proofs))
	retained := make([]retainedProofEvidence, 0, len(proofs))
	for _, proof := range proofs {
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:   proof.content.NodeID,
			ScopeID:  proof.content.ScopeID,
			Logical:  proof.content.LogicalPath,
			Physical: proof.content.PhysicalPath,
			Method:   proof.method,
			Kind:     proof.kind,
			Value:    proof.value,
		})
		if evidenceID == "" {
			return nil, false
		}
		evidenceIDs = append(evidenceIDs, evidenceID)
		retained = append(retained, retainedProofEvidence{proof: proof, evidenceID: evidenceID})
	}
	if len(evidenceIDs) == 0 {
		return nil, false
	}
	if artifacts != nil {
		for _, item := range retained {
			if item.proof.relationToNodeID == "" || item.proof.content.NodeID != projectNodeID {
				continue
			}
			relationshipEvidenceIDs := []string{item.evidenceID}
			for _, candidate := range retained {
				if candidate.proof.content.NodeID == item.proof.relationToNodeID &&
					candidate.proof.kind == "xcode-build-setting-absence" {
					relationshipEvidenceIDs = append(relationshipEvidenceIDs, candidate.evidenceID)
				}
			}
			if len(relationshipEvidenceIDs) != 2 {
				return nil, false
			}
			addXcodeBaseConfigurationRelationship(
				artifacts,
				projectNodeID,
				item.proof.relationToNodeID,
				relationshipEvidenceIDs,
			)
		}
	}
	return evidenceIDs, true
}

func addXcodeBaseConfigurationRelationship(
	graph *artifact.Graph,
	projectNodeID, configurationNodeID string,
	evidenceIDs []string,
) {
	evidenceIDs = sortedUniqueNonemptyStrings(evidenceIDs)
	if graph == nil || projectNodeID == "" || configurationNodeID == "" || len(evidenceIDs) == 0 {
		return
	}
	const kind = "xcode-base-configuration"
	for index := range graph.Edges {
		edge := &graph.Edges[index]
		if edge.From != projectNodeID || edge.To != configurationNodeID || edge.Kind != kind {
			continue
		}
		edge.EvidenceIDs = sortedUniqueNonemptyStrings(append(edge.EvidenceIDs, evidenceIDs...))
		return
	}
	graph.Edges = append(graph.Edges, artifact.Edge{
		From:        projectNodeID,
		To:          configurationNodeID,
		Kind:        kind,
		EvidenceIDs: evidenceIDs,
	})
}

func corroborateXcodeDerivedGraphRange(
	graph *behavior.Graph,
	start behavior.GraphRange,
	evidenceIDs []string,
) {
	if graph.CorroborateRange(start, evidenceIDs) {
		return
	}
	markDerivedGraphLimit(graph, "xcode-build-setting-resolution")
}
