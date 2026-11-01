package extract

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/pelletier/go-toml/v2"
)

const (
	maxCargoCrateArchives    = 32
	maxCargoManifestBytes    = 1 << 20
	maxCargoManifestLines    = 8192
	maxCargoManifestLine     = 64 << 10
	maxCargoPackageNameBytes = 64
	maxCargoVersionBytes     = 128
	maxCargoBuildPathBytes   = 1024

	cargoBuildScriptAnalysisArea = "cargo-build-script-activation"
	cargoBuildScriptProfile      = "cargo-package-v1"
)

type cargoBuildDisposition uint8

const (
	cargoBuildRecognized cargoBuildDisposition = iota + 1
	cargoBuildDisabled
	cargoBuildUnsupported
	cargoBuildMalformed
)

type cargoBuildMember struct {
	node         artifact.Node
	content      artifact.Content
	contentCount int
	relative     string
}

type cargoManifestField struct {
	value  string
	line   int
	offset int
}

type cargoBuildResult struct {
	disposition cargoBuildDisposition
	reason      string
	archive     artifact.Node
	manifest    cargoBuildMember
	build       cargoBuildMember
	topDir      string
	name        cargoManifestField
	version     cargoManifestField
	buildField  cargoManifestField
	buildPath   string
	defaultPath bool
	mainEntry   cargoManifestField
}

// prepareCargoBuildScripts recognizes a complete root .crate package and the
// exact build-script path selected by Cargo's manifest rule. It never invokes
// Cargo, rustc, or the retained source. The resulting execution root is
// conditional on an external build/check/test operation selecting this exact
// package version and on Cargo reaching its build-script phase.
func prepareCargoBuildScripts(
	graph *behavior.Graph,
	artifacts artifact.Graph,
	contents []artifact.Content,
	scopeByNode map[string]string,
	rootEligibility map[string]bool,
) {
	archives, truncated := boundedCargoCrateArchives(artifacts.Nodes)
	if truncated {
		addPartialCoverageOnce(graph, "", cargoBuildScriptAnalysisArea, fmt.Sprintf("only the first %d deterministic .crate candidates were considered; later candidates remain inventory only", maxCargoCrateArchives))
	}
	for _, archive := range archives {
		result := recognizeCargoBuildScript(archive, artifacts.Nodes, contents)
		switch result.disposition {
		case cargoBuildRecognized:
			emitCargoBuildScript(graph, result, contents, scopeByNode, rootEligibility)
		case cargoBuildDisabled:
			graph.AddCoverage(behavior.Coverage{
				NodeID:       archive.ID,
				AnalysisArea: cargoBuildScriptAnalysisArea,
				Status:       "analyzed",
				Detail:       result.reason,
			})
		case cargoBuildUnsupported, cargoBuildMalformed:
			addPartialCoverageOnce(graph, archive.ID, cargoBuildScriptAnalysisArea, result.reason)
		}
	}
}

func boundedCargoCrateArchives(nodes []artifact.Node) ([]artifact.Node, bool) {
	archives := make([]artifact.Node, 0, maxCargoCrateArchives)
	for _, node := range nodes {
		base := path.Base(strings.ReplaceAll(node.LogicalPath, "\\", "/"))
		if node.Kind != "gzip" || node.MediaType != "application/gzip" || !strings.HasSuffix(base, ".crate") {
			continue
		}
		archives = append(archives, node)
	}
	sort.SliceStable(archives, func(i, j int) bool {
		if archives[i].LogicalPath != archives[j].LogicalPath {
			return archives[i].LogicalPath < archives[j].LogicalPath
		}
		return archives[i].ID < archives[j].ID
	})
	truncated := len(archives) > maxCargoCrateArchives
	if truncated {
		archives = archives[:maxCargoCrateArchives]
	}
	return archives, truncated
}

func recognizeCargoBuildScript(archive artifact.Node, nodes []artifact.Node, contents []artifact.Content) cargoBuildResult {
	result := cargoBuildResult{archive: archive}
	fail := func(disposition cargoBuildDisposition, reason string) cargoBuildResult {
		result.disposition = disposition
		result.reason = reason
		return result
	}
	if archive.ParentID != "" {
		return fail(cargoBuildUnsupported, "a nested .crate candidate is inventory only; containment does not establish Cargo package selection, so no build-script execution root was created")
	}
	if archive.Kind != "gzip" || archive.MediaType != "application/gzip" ||
		archive.AnalyzeStatus != "analyzed" || archive.CoverageDetail != "" {
		return fail(cargoBuildMalformed, "the candidate .crate gzip TAR inventory was incomplete or not fully analyzed; Cargo package identity and build-script selection were not established")
	}
	if (archive.DeclaredEntryCount == nil) != (archive.ModeledEntryCount == nil) ||
		archive.DeclaredEntryCount != nil && *archive.DeclaredEntryCount != *archive.ModeledEntryCount {
		return fail(cargoBuildMalformed, "the candidate .crate declared and modeled entry counts do not establish a complete inventory; Cargo package identity and build-script selection were not established")
	}
	base := path.Base(strings.ReplaceAll(archive.LogicalPath, "\\", "/"))
	if len(base) > artifact.MaxArchiveNameBytes || !strings.HasSuffix(base, ".crate") {
		return fail(cargoBuildUnsupported, "the candidate does not use the supported normalized .crate filename form; no Cargo build-script root was created")
	}
	stem := strings.TrimSuffix(base, ".crate")
	if stem == "" {
		return fail(cargoBuildMalformed, "the candidate .crate filename has an empty package identity; no Cargo build-script root was created")
	}

	members, disposition, reason := collectCargoBuildMembers(archive, nodes, contents)
	if reason != "" {
		return fail(disposition, reason)
	}
	pathCounts := make(map[string]int, len(members))
	foldedPaths := make(map[string]string, len(members))
	for _, member := range members {
		parts := strings.SplitN(member.relative, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fail(cargoBuildMalformed, "the .crate does not contain every retained file beneath one top-level package directory; package identity is ambiguous")
		}
		if result.topDir == "" {
			result.topDir = parts[0]
		} else if result.topDir != parts[0] {
			return fail(cargoBuildMalformed, "the .crate contains more than one top-level file directory; package identity is ambiguous")
		}
		pathCounts[member.relative]++
		if pathCounts[member.relative] > 1 {
			return fail(cargoBuildMalformed, "the .crate contains a duplicate normalized member path; package identity is ambiguous")
		}
		folded := asciiFoldCargoPath(member.relative)
		if prior := foldedPaths[folded]; prior != "" && prior != member.relative {
			return fail(cargoBuildMalformed, "the .crate contains ASCII case-fold-colliding paths; extraction identity is ambiguous on common macOS filesystems")
		}
		foldedPaths[folded] = member.relative
	}
	manifestPath := result.topDir + "/Cargo.toml"
	if actual := foldedPaths[asciiFoldCargoPath(manifestPath)]; actual != "" && actual != manifestPath {
		return fail(cargoBuildMalformed, "the .crate contains a case-variant root Cargo.toml; manifest identity is ambiguous on common macOS filesystems")
	}
	if pathCounts[manifestPath] != 1 {
		return fail(cargoBuildMalformed, "the .crate lacks one unambiguous root Cargo.toml; Cargo package identity was not established")
	}
	for _, member := range members {
		if member.relative == manifestPath {
			result.manifest = member
			break
		}
	}
	if !cargoTextMember(result.manifest) {
		return fail(cargoBuildMalformed, "the exact root Cargo.toml bytes were not retained as analyzed NUL-free UTF-8 text; Cargo package identity was not established")
	}

	name, version, buildField, buildValue, disposition, reason := parseCargoManifest(result.manifest.content.Data)
	if reason != "" {
		return fail(disposition, reason)
	}
	result.name, result.version, result.buildField = name, version, buildField
	expected := name.value + "-" + version.value
	if stem != expected || result.topDir != expected {
		return fail(cargoBuildMalformed, "the .crate filename, top-level directory, and Cargo package name/version do not agree exactly; package identity was not established")
	}
	switch value := buildValue.(type) {
	case nil:
		result.buildPath = "build.rs"
		result.defaultPath = true
	case bool:
		if !value {
			return fail(cargoBuildDisabled, "Cargo.toml explicitly sets package.build=false; Cargo automatic build-script selection is disabled")
		}
		return fail(cargoBuildUnsupported, "Cargo.toml package.build uses an unsupported boolean value; no build-script root was created")
	case string:
		if !safeCargoBuildPath(value) {
			return fail(cargoBuildUnsupported, "Cargo.toml package.build is not a supported bounded package-relative path; no build-script root was created")
		}
		result.buildPath = value
	default:
		return fail(cargoBuildUnsupported, "Cargo.toml package.build is neither a string path nor false; no build-script root was created")
	}
	buildMemberPath := result.topDir + "/" + result.buildPath
	if actual := foldedPaths[asciiFoldCargoPath(buildMemberPath)]; actual != "" && actual != buildMemberPath {
		return fail(cargoBuildMalformed, "the selected Cargo build-script path has an ASCII case-fold collision; target identity is ambiguous on common macOS filesystems")
	}
	if pathCounts[buildMemberPath] == 0 && result.defaultPath {
		return fail(cargoBuildDisabled, "Cargo.toml omits package.build and no exact root build.rs is retained; Cargo automatic build-script selection has no target")
	}
	if pathCounts[buildMemberPath] != 1 {
		return fail(cargoBuildMalformed, "the selected Cargo build-script path is absent or ambiguous in the retained .crate inventory; no execution root was created")
	}
	for _, member := range members {
		if member.relative == buildMemberPath {
			result.build = member
			break
		}
	}
	if !cargoTextMember(result.build) {
		return fail(cargoBuildMalformed, "the exact selected Cargo build-script bytes were not retained as analyzed NUL-free UTF-8 source text; no execution root was created")
	}
	mainEntry, ok := locateCargoRustMain(result.build.content.Data)
	if !ok {
		return fail(cargoBuildUnsupported, "the selected Cargo build script does not contain one exact top-level ordinary Rust fn main entry within the bounded source profile; no execution root was created")
	}
	result.mainEntry = mainEntry
	result.disposition = cargoBuildRecognized
	return result
}

func collectCargoBuildMembers(archive artifact.Node, nodes []artifact.Node, contents []artifact.Content) ([]cargoBuildMember, cargoBuildDisposition, string) {
	prefix := archive.LogicalPath + "!"
	nodesByID := pythonSourceBuildNodesByID(nodes)
	members := make([]cargoBuildMember, 0, min(len(nodes), artifact.MaxArchiveEntries))
	memberIDs := make(map[string]int, min(len(nodes), artifact.MaxArchiveEntries))
	for _, node := range nodes {
		if !cargoTarEntryOwnedBy(node, archive.ID, nodesByID) {
			continue
		}
		if !strings.HasPrefix(node.LogicalPath, prefix) {
			return nil, cargoBuildMalformed, "a scanner-authoritative TAR entry is outside the .crate logical namespace; package identity is ambiguous"
		}
		relative := strings.TrimPrefix(node.LogicalPath, prefix)
		if relative == "" || node.ID == "" || memberIDs[node.ID] != 0 {
			return nil, cargoBuildMalformed, "the .crate contains an empty or duplicate retained member identity; package identity is ambiguous"
		}
		if len(members) >= artifact.MaxArchiveEntries {
			return nil, cargoBuildUnsupported, fmt.Sprintf(".crate member limit %d reached; complete package identity and build-script selection were not established", artifact.MaxArchiveEntries)
		}
		memberIDs[node.ID] = len(members) + 1
		members = append(members, cargoBuildMember{node: node, relative: relative})
	}
	if len(members) == 0 {
		return nil, cargoBuildUnsupported, "the gzip payload did not yield scanner-authoritative TAR entries; non-TAR gzip payloads are not Cargo packages under the supported profile"
	}
	contentCounts := make(map[string]int, len(members))
	archiveContentCount := 0
	archiveRepresentationValid := false
	for _, content := range contents {
		if content.NodeID == archive.ID {
			archiveContentCount++
			archiveRepresentationValid = !content.RawFeaturesOnly && len(content.Data) >= 2 && content.Data[0] == 0x1f && content.Data[1] == 0x8b
			continue
		}
		position := memberIDs[content.NodeID]
		if position == 0 {
			continue
		}
		contentCounts[content.NodeID]++
		if contentCounts[content.NodeID] == 1 {
			members[position-1].content = content
		}
	}
	if archiveContentCount != 1 || !archiveRepresentationValid {
		return nil, cargoBuildMalformed, "the candidate lacks one exact retained gzip representation; .crate identity was not established"
	}
	for index := range members {
		members[index].contentCount = contentCounts[members[index].node.ID]
	}
	sort.SliceStable(members, func(i, j int) bool {
		if members[i].relative != members[j].relative {
			return members[i].relative < members[j].relative
		}
		return members[i].node.ID < members[j].node.ID
	})
	return members, cargoBuildRecognized, ""
}

func cargoTarEntryOwnedBy(node artifact.Node, archiveID string, nodesByID map[string]artifact.Node) bool {
	if node.Provenance != "tar-entry" || node.ID == "" || archiveID == "" {
		return false
	}
	current := node
	seen := map[string]bool{}
	for depth := 0; depth < 64; depth++ {
		if current.ParentID == archiveID {
			return true
		}
		if current.ParentID == "" || seen[current.ParentID] {
			return false
		}
		seen[current.ParentID] = true
		parent, ok := nodesByID[current.ParentID]
		if !ok || pythonSourceBuildContainerKind(parent.Kind) {
			return false
		}
		current = parent
	}
	return false
}

func cargoTextMember(member cargoBuildMember) bool {
	return member.node.AnalyzeStatus == "analyzed" && member.node.CoverageDetail == "" &&
		member.contentCount == 1 && member.content.NodeID != "" && !member.content.RawFeaturesOnly &&
		member.content.MediaType == "text/plain" && utf8.Valid(member.content.Data) &&
		bytes.IndexByte(member.content.Data, 0) < 0
}

func parseCargoManifest(data []byte) (cargoManifestField, cargoManifestField, cargoManifestField, any, cargoBuildDisposition, string) {
	if len(data) == 0 || len(data) > maxCargoManifestBytes {
		return cargoManifestField{}, cargoManifestField{}, cargoManifestField{}, nil, cargoBuildUnsupported, "Cargo.toml is empty or exceeds the bounded manifest size; package identity was not established"
	}
	var document map[string]any
	if err := toml.Unmarshal(data, &document); err != nil {
		return cargoManifestField{}, cargoManifestField{}, cargoManifestField{}, nil, cargoBuildMalformed, "Cargo.toml is not valid TOML; package identity and build-script selection were not established"
	}
	packageValue, exists := document["package"]
	if !exists {
		return cargoManifestField{}, cargoManifestField{}, cargoManifestField{}, nil, cargoBuildMalformed, "Cargo.toml lacks a [package] table; package identity was not established"
	}
	packageTable, ok := packageValue.(map[string]any)
	if !ok {
		return cargoManifestField{}, cargoManifestField{}, cargoManifestField{}, nil, cargoBuildUnsupported, "Cargo.toml package metadata is outside the supported ordinary [package] table form; no build-script root was created"
	}
	nameValue, ok := packageTable["name"].(string)
	if !ok || !supportedCargoPackageName(nameValue) {
		return cargoManifestField{}, cargoManifestField{}, cargoManifestField{}, nil, cargoBuildUnsupported, "Cargo.toml package.name is not a supported crates.io-style bounded ASCII identity; package identity was not established"
	}
	versionValue, ok := packageTable["version"].(string)
	if !ok || !supportedCargoVersion(versionValue) {
		return cargoManifestField{}, cargoManifestField{}, cargoManifestField{}, nil, cargoBuildUnsupported, "Cargo.toml package.version is not a supported bounded explicit SemVer identity; package identity was not established"
	}
	locations, reason := locateCargoPackageFields(data)
	if reason != "" {
		return cargoManifestField{}, cargoManifestField{}, cargoManifestField{}, nil, cargoBuildUnsupported, reason
	}
	name := locations["name"]
	name.value = nameValue
	version := locations["version"]
	version.value = versionValue
	if name.line == 0 || version.line == 0 {
		return cargoManifestField{}, cargoManifestField{}, cargoManifestField{}, nil, cargoBuildUnsupported, "Cargo.toml package identity uses a TOML form outside the supported located [package] key profile; exact evidence lineage was not established"
	}
	build := locations["build"]
	buildValue, hasBuild := packageTable["build"]
	if hasBuild && build.line == 0 {
		return cargoManifestField{}, cargoManifestField{}, cargoManifestField{}, nil, cargoBuildUnsupported, "Cargo.toml package.build uses a TOML form outside the supported located [package] key profile; exact selection evidence was not established"
	}
	return name, version, build, buildValue, cargoBuildRecognized, ""
}

func locateCargoPackageFields(data []byte) (map[string]cargoManifestField, string) {
	result := map[string]cargoManifestField{}
	inPackage := false
	packageTables := 0
	offset := 0
	for lineNumber := 1; offset <= len(data); lineNumber++ {
		if lineNumber > maxCargoManifestLines {
			return nil, fmt.Sprintf("Cargo.toml line limit %d reached; exact package-key evidence was not established", maxCargoManifestLines)
		}
		next := bytes.IndexByte(data[offset:], '\n')
		end := len(data)
		if next >= 0 {
			end = offset + next
		}
		line := data[offset:end]
		if len(line) > maxCargoManifestLine {
			return nil, fmt.Sprintf("Cargo.toml line length exceeds %d bytes; exact package-key evidence was not established", maxCargoManifestLine)
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			inPackage = bytes.Equal(trimmed, []byte("[package]"))
			if inPackage {
				packageTables++
				if packageTables > 1 {
					return nil, "Cargo.toml contains more than one ordinary [package] table; exact package-key evidence is ambiguous"
				}
			}
		} else if inPackage && len(trimmed) > 0 && trimmed[0] != '#' {
			equals := bytes.IndexByte(line, '=')
			if equals > 0 {
				key := string(bytes.TrimSpace(line[:equals]))
				if key == "name" || key == "version" || key == "build" {
					valueStart := equals + 1
					for valueStart < len(line) && (line[valueStart] == ' ' || line[valueStart] == '\t') {
						valueStart++
					}
					if _, duplicate := result[key]; duplicate {
						return nil, "Cargo.toml contains duplicate located [package] identity/build keys; exact evidence is ambiguous"
					}
					result[key] = cargoManifestField{line: lineNumber, offset: offset + valueStart}
				}
			}
		}
		if next < 0 {
			break
		}
		offset = end + 1
	}
	return result, ""
}

func supportedCargoPackageName(value string) bool {
	if value == "" || len(value) > maxCargoPackageNameBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		current := value[index]
		if current != '-' && current != '_' &&
			(current < 'A' || current > 'Z') && (current < 'a' || current > 'z') &&
			(current < '0' || current > '9') {
			return false
		}
	}
	return true
}

func supportedCargoVersion(value string) bool {
	if value == "" || len(value) > maxCargoVersionBytes {
		return false
	}
	buildParts := strings.SplitN(value, "+", 3)
	if len(buildParts) == 3 {
		return false
	}
	coreAndPre := strings.SplitN(buildParts[0], "-", 2)
	core := strings.Split(coreAndPre[0], ".")
	if len(core) != 3 {
		return false
	}
	for _, number := range core {
		if !cargoNumericIdentifier(number) {
			return false
		}
	}
	if len(coreAndPre) == 2 && !cargoVersionIdentifiers(coreAndPre[1], true) {
		return false
	}
	if len(buildParts) == 2 && !cargoVersionIdentifiers(buildParts[1], false) {
		return false
	}
	return true
}

func cargoVersionIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	if value == "" {
		return false
	}
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for index := 0; index < len(identifier); index++ {
			current := identifier[index]
			if current < '0' || current > '9' {
				numeric = false
			}
			if current != '-' && (current < 'A' || current > 'Z') &&
				(current < 'a' || current > 'z') && (current < '0' || current > '9') {
				return false
			}
		}
		if rejectNumericLeadingZero && numeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}

func cargoNumericIdentifier(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func safeCargoBuildPath(value string) bool {
	if value == "" || len(value) > maxCargoBuildPathBytes || strings.Contains(value, "\\") || strings.ContainsRune(value, 0) || path.IsAbs(value) {
		return false
	}
	cleaned := path.Clean(value)
	return cleaned == value && cleaned != "." && cleaned != ".." && !strings.HasPrefix(cleaned, "../")
}

func asciiFoldCargoPath(value string) string {
	var result strings.Builder
	result.Grow(len(value))
	for index := 0; index < len(value); index++ {
		current := value[index]
		if current >= 'A' && current <= 'Z' {
			current += 'a' - 'A'
		}
		result.WriteByte(current)
	}
	return result.String()
}

func emitCargoBuildScript(
	graph *behavior.Graph,
	result cargoBuildResult,
	contents []artifact.Content,
	scopeByNode map[string]string,
	rootEligibility map[string]bool,
) {
	manifestScope := scopeByNode[result.manifest.node.ID]
	buildScope := scopeByNode[result.build.node.ID]
	selection := "explicit package.build=" + result.buildPath
	if result.defaultPath {
		selection = "package.build absent; Cargo default build.rs retained"
	}
	evidence := []behavior.Evidence{
		{NodeID: result.archive.ID, Logical: result.archive.LogicalPath, Method: "cargo-build-script-recognizer", Kind: "cargo-crate-filename", Value: path.Base(strings.ReplaceAll(result.archive.LogicalPath, "\\", "/"))},
		{NodeID: result.archive.ID, Logical: result.archive.LogicalPath, Offset: 0, OffsetKnown: true, Method: "cargo-build-script-recognizer", Kind: "cargo-crate-gzip-representation", Value: "gzip TAR"},
		{NodeID: result.archive.ID, Logical: result.archive.LogicalPath, Method: "cargo-build-script-recognizer", Kind: "verified-cargo-crate-envelope", Value: result.topDir + "; complete retained TAR inventory"},
		cargoManifestEvidence(result.manifest.content, manifestScope, result.name, "cargo-package-name"),
		cargoManifestEvidence(result.manifest.content, manifestScope, result.version, "cargo-package-version"),
		{NodeID: result.manifest.node.ID, ScopeID: manifestScope, Logical: result.manifest.content.LogicalPath, Physical: result.manifest.content.PhysicalPath, Offset: int64(result.buildField.offset), OffsetKnown: true, Line: result.buildField.line, Method: "cargo-build-script-recognizer", Kind: "cargo-build-script-selection", Value: selection},
		{NodeID: result.build.node.ID, ScopeID: buildScope, Logical: result.build.content.LogicalPath, Physical: result.build.content.PhysicalPath, Method: "cargo-build-script-recognizer", Kind: "cargo-build-script-entry", Value: result.build.relative},
		{NodeID: result.build.node.ID, ScopeID: buildScope, Logical: result.build.content.LogicalPath, Physical: result.build.content.PhysicalPath, Line: result.mainEntry.line, Offset: int64(result.mainEntry.offset), OffsetKnown: true, Method: "cargo-build-script-recognizer", Kind: "cargo-rust-main-entry", Value: "fn main"},
	}
	// The default rule is established by the parsed absence of package.build;
	// its evidence belongs to the manifest as a whole rather than an invented
	// byte coordinate for a key that does not exist.
	if result.defaultPath {
		evidence[5].Offset = 0
		evidence[5].OffsetKnown = false
		evidence[5].Line = 0
	}
	evidenceIDs := make([]string, 0, len(evidence))
	for _, item := range evidence {
		id := graph.AddEvidence(item)
		if id == "" {
			addPartialCoverageOnce(graph, result.archive.ID, cargoBuildScriptAnalysisArea, "Cargo package/build-script evidence could not be retained within the analysis budget; no execution root was created")
			return
		}
		evidenceIDs = append(evidenceIDs, id)
	}
	packageEvidenceIDs := append([]string(nil), evidenceIDs[:5]...)
	if !graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: result.archive.ID, Kind: "cargo-package-format", Value: "crate", EvidenceIDs: packageEvidenceIDs, Support: behavior.SupportCorroborated}) {
		addPartialCoverageOnce(graph, result.archive.ID, cargoBuildScriptAnalysisArea, "the behavior graph budget prevented retaining the recognized Cargo package property and build-script root")
		return
	}
	if !rootEligibility[result.archive.ID] || !rootEligibility[result.manifest.node.ID] ||
		!rootEligibility[result.build.node.ID] || manifestScope == "" || buildScope == "" {
		addPartialCoverageOnce(graph, result.archive.ID, cargoBuildScriptAnalysisArea, "the Cargo package was recognized, but its retained topology or scope does not permit an independent build-script execution root")
		return
	}
	rootID := graph.AddExecutionRoot(behavior.ExecutionRoot{
		Kind:              "cargo-build-script",
		DeclarationNodeID: result.manifest.node.ID,
		StartNodeID:       result.build.node.ID,
		StartScopeID:      buildScope,
		Name:              result.name.value + " " + result.version.value,
		Interpreter:       "cargo",
		EvidenceIDs:       evidenceIDs,
	})
	if rootID == "" {
		addPartialCoverageOnce(graph, result.archive.ID, cargoBuildScriptAnalysisArea, "the behavior graph budget prevented retaining the conditional Cargo build-script execution root")
		return
	}
	for index := range contents {
		if contents[index].NodeID == result.build.node.ID {
			contents[index].SemanticLanguage = "native-source"
			contents[index].BehaviorAnalysisForced = true
		}
	}
	addPartialCoverageOnce(graph, result.build.node.ID, cargoBuildScriptAnalysisArea, "profile "+cargoBuildScriptProfile+" establishes only a conditional Cargo host entry: Cargo would compile and run this build script if dependency resolution/source selection chose this exact package and a build/check/test path reached its build-script phase; static analysis did not observe lockfile resolution, registry/cache state, Cargo configuration overrides, target selection, command occurrence, compilation, execution, or build success; direct-call reachability does not resolve platform or branch feasibility")
}

func locateCargoRustMain(data []byte) (cargoManifestField, bool) {
	mask, limited := rustSourceCodeMask(string(data))
	if limited {
		return cargoManifestField{}, false
	}
	depth := 0
	offset := 0
	var selected cargoManifestField
	for lineNumber := 1; offset <= len(data); lineNumber++ {
		if lineNumber > maxCargoManifestLines {
			return cargoManifestField{}, false
		}
		next := bytes.IndexByte(data[offset:], '\n')
		end := len(data)
		if next >= 0 {
			end = offset + next
		}
		line := string(data[offset:end])
		if depth == 0 {
			if fnOffset, declaration := cargoRustMainDeclaration(line, mask[offset:end]); declaration {
				if selected.line != 0 {
					return cargoManifestField{}, false
				}
				selected = cargoManifestField{value: "main", line: lineNumber, offset: offset + fnOffset}
			}
		}
		for index := offset; index < end; index++ {
			if !rustCodeAt(mask, index) {
				continue
			}
			switch data[index] {
			case '{':
				depth++
			case '}':
				if depth == 0 {
					return cargoManifestField{}, false
				}
				depth--
			}
		}
		if next < 0 {
			break
		}
		offset = end + 1
	}
	return selected, selected.line != 0 && depth == 0
}

// Requiring the opening brace to end the retained declaration line matches
// the Rust function-scope extractor. Compact one-line bodies remain explicit
// unsupported coverage rather than creating a provisional file-level root
// that cannot be rebound to the exact first entry.
var cargoRustMainPattern = regexp.MustCompile(`^[ \t]*(?:pub(?:\([^\n)]*\))?[ \t]+)?(?:unsafe[ \t]+)?fn[ \t]+main[ \t]*\([ \t]*\)[^{;]{0,512}\{[ \t]*$`)

func cargoRustMainDeclaration(line string, lineMask []bool) (int, bool) {
	match := cargoRustMainPattern.FindStringIndex(line)
	if len(match) != 2 {
		return 0, false
	}
	fnOffset := strings.Index(line[match[0]:match[1]], "fn")
	if fnOffset < 0 {
		return 0, false
	}
	fnOffset += match[0]
	return fnOffset, rustCodeAt(lineMask, fnOffset) && rustCodeAt(lineMask, match[1]-1)
}

// finalizeCargoBuildScriptExecution replaces the file-level provisional start
// with the exact retained main function scope, then performs bounded direct-
// call reachability inside that source file. CONNECTED remains static root
// reachability only; it does not claim Cargo ran or any call succeeded.
func finalizeCargoBuildScriptExecution(graph *behavior.Graph) {
	for rootIndex := range graph.ExecutionRoots {
		root := &graph.ExecutionRoots[rootIndex]
		if root.Kind != "cargo-build-script" || root.ID == "" || root.StartNodeID == "" || root.StartScopeID == "" {
			continue
		}
		provisionalScope := root.StartScopeID
		mainScope := ""
		for _, scope := range graph.Scopes {
			if scope.NodeID != root.StartNodeID || scope.ParentID != provisionalScope || scope.Kind != "function" || scope.Function != "main" {
				continue
			}
			if mainScope != "" {
				mainScope = ""
				break
			}
			mainScope = scope.ID
		}
		if mainScope == "" {
			addPartialCoverageOnce(graph, root.StartNodeID, cargoBuildScriptAnalysisArea, "the provisional Cargo build-script root could not be rebound to one exact retained Rust main function scope; function-level connectivity remains UNKNOWN")
			continue
		}
		root.StartScopeID = mainScope
		reachable := map[string]bool{mainScope: true}
		ambiguousNames := map[string]bool{}
		scopeByName := map[string]string{}
		for _, scope := range graph.Scopes {
			if scope.NodeID != root.StartNodeID || scope.Kind != "function" || scope.Function == "" {
				continue
			}
			if prior := scopeByName[scope.Function]; prior != "" && prior != scope.ID {
				ambiguousNames[scope.Function] = true
				delete(scopeByName, scope.Function)
				continue
			}
			if !ambiguousNames[scope.Function] {
				scopeByName[scope.Function] = scope.ID
			}
		}
		for changed, passes := true, 0; changed && passes < len(scopeByName)+1; passes++ {
			changed = false
			for _, feature := range graph.Features {
				if feature.NodeID != root.StartNodeID || feature.Key != "script.function_call" || !reachable[feature.ScopeID] || ambiguousNames[feature.Value] {
					continue
				}
				target := scopeByName[feature.Value]
				if target != "" && !reachable[target] {
					reachable[target] = true
					changed = true
				}
			}
		}
		execution := connectedExecutionContext([]string{root.ID}, nil)
		for index := range graph.Features {
			if graph.Features[index].NodeID == root.StartNodeID && reachable[graph.Features[index].ScopeID] {
				graph.Features[index].Execution = mergeConnectedExecution(graph.Features[index].Execution, execution)
			}
		}
		for index := range graph.Operations {
			if graph.Operations[index].SubjectNodeID == root.StartNodeID && reachable[graph.Operations[index].ScopeID] {
				graph.Operations[index].Execution = mergeConnectedExecution(graph.Operations[index].Execution, execution)
			}
		}
	}
}

func cargoManifestEvidence(content artifact.Content, scopeID string, field cargoManifestField, kind string) behavior.Evidence {
	return behavior.Evidence{
		NodeID: content.NodeID, ScopeID: scopeID, Logical: content.LogicalPath, Physical: content.PhysicalPath,
		Line: field.line, Offset: int64(field.offset), OffsetKnown: true,
		Method: "cargo-build-script-recognizer", Kind: kind, Value: field.value,
	}
}
