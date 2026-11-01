package artifact

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/0x4D31/maratus/internal/plistx"
)

const maxAppMetadataBytes int64 = 1 << 20
const maxAppMagicProbeBytes = 4096

const (
	appInfoRelativePath             = "Contents/Info.plist"
	osaAppletExecutableRelativePath = "Contents/MacOS/applet"
	osaAppletScriptRelativePath     = "Contents/Resources/Scripts/main.scpt"
	osaAppletBundleIDPrefix         = "com.apple.ScriptEditor.id."
)

type skippedAppDirectory struct {
	path   string
	detail string
}

type appTraversalIssue struct {
	path   string
	detail string
}

func (s *scanner) isAppBundle(path string) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".app") {
		return false
	}
	info, err := s.lstatFilesystemPath(filepath.Join(path, "Contents", "Info.plist"))
	return err == nil && info.Mode().IsRegular()
}

type archiveAppBundle struct {
	root                   string
	executable             string
	executableDetail       string
	executableNodeID       string
	nodeID                 string
	provenance             string
	electron               bool
	unpacked               bool
	platypus               bool
	platypusEvidence       []LocatedArtifactEvidence
	platypusInvocation     platypusInvocationDescriptor
	platypusInvocationOK   bool
	platypusSettingsNodeID string
	platypusScriptNodeID   string
	tauriEvidence          []LocatedArtifactEvidence
	osaApplet              *appBundleScriptDescriptor
	osaAppletScriptNodeID  string
}

// appBundleScriptDescriptor records a high-confidence, convention-defined
// invocation inside an app bundle. Keeping the launcher and target paths
// together avoids spreading producer-specific booleans across the scanner.
type appBundleScriptDescriptor struct {
	executableRelativePath string
	scriptRelativePath     string
}

// appBundleMember is the bounded view shared by filesystem and archive app
// recognizers. available means the complete regular-file bytes were retained;
// a prefix-only or skipped member must never establish an invocation edge.
type appBundleMember struct {
	relativePath string
	data         []byte
	kind         string
	available    bool
}

func (s *scanner) addArchiveAppBundleNodes(parentID, outer string, entries []VirtualEntry) map[string]*archiveAppBundle {
	bundles := archiveAppBundles(entries)
	if len(bundles) == 0 {
		return nil
	}
	out := make(map[string]*archiveAppBundle, len(bundles))
	for _, bundle := range bundles {
		logical, ok := archiveLogicalPath(outer, bundle.root)
		if !ok {
			s.addDiagnostic(fmt.Sprintf("%s: rejected archive app logical path over %d bytes", outer, MaxArchiveLogicalPathBytes))
			continue
		}
		if !s.reserveNode(logical, "", parentID) {
			continue
		}
		id := s.graph.AddNode(Node{
			ParentID:      parentID,
			LogicalPath:   logical,
			Kind:          "app-bundle",
			MediaType:     "inode/directory",
			Provenance:    bundle.provenance,
			SourceRole:    sourceRole(logical, "app-bundle", false),
			AnalyzeStatus: "analyzed",
		})
		s.graph.AddEdge(parentID, id, "contains")
		bundle.nodeID = id
		if bundle.executableDetail != "" {
			s.markNodePartial(id, bundle.executableDetail)
		}
		if bundle.electron {
			s.markElectronApp(id)
			if bundle.unpacked {
				s.markNodePartial(id, "canonical unpacked Electron app is present; package main and transitive Node module resolution are not implemented")
			}
		}
		copied := bundle
		out[bundle.root] = &copied
	}
	return out
}

func archiveAppBundles(entries []VirtualEntry) []archiveAppBundle {
	byRoot := map[string]*archiveAppBundle{}
	macosExecutables := map[string][]string{}
	membersByRoot := map[string][]appBundleMember{}
	for _, entry := range entries {
		name, ok := cleanArchiveName(entry.Name)
		if !ok {
			continue
		}
		if root, ok := archiveInfoPlistAppRoot(name); ok && !entry.RawFeaturesOnly && !entry.Directory && entry.SkipDetail == "" {
			bundle := ensureArchiveAppBundle(byRoot, root)
			bundle.provenance = entry.Provenance
		}
		root, rel, ok := archiveEntryWithinApp(name)
		if !ok {
			continue
		}
		available := !entry.RawFeaturesOnly && !entry.Directory && !entry.Symlink && !entry.Hardlink && entry.SkipDetail == ""
		kind := ""
		if available {
			kind, _ = Detect(rel, entry.Data, entry.Executable)
		}
		membersByRoot[root] = append(membersByRoot[root], appBundleMember{
			relativePath: rel,
			data:         entry.Data,
			kind:         kind,
			available:    available,
		})
		if isArchiveMacOSExecutable(rel, entry) {
			macosExecutables[root] = append(macosExecutables[root], filepath.Base(rel))
		}
	}
	rootAliases := make(map[string]int, len(membersByRoot))
	for root := range membersByRoot {
		rootAliases[strings.ToLower(root)]++
	}
	for root, bundle := range byRoot {
		if rootAliases[strings.ToLower(root)] > 1 {
			bundle.executableDetail = "app executable was not resolved: app bundle root has ambiguous case aliases"
			continue
		}
		// Archive member order cannot decide which metadata or executable a
		// future extraction selects. Count unavailable members and case aliases
		// too: either can replace the retained bytes on a macOS filesystem.
		info, unique := uniqueCanonicalAppMember(membersByRoot[root], appInfoRelativePath)
		if !unique || !info.available {
			bundle.executable = ""
			bundle.executableDetail = "app executable was not resolved: Info.plist is ambiguous, noncanonical, or unavailable"
			continue
		}
		if len(info.data) > int(maxAppMetadataBytes) {
			bundle.executableDetail = "app executable was not resolved: Info.plist exceeds the metadata byte limit"
			continue
		}
		dict, err := plistx.Decode(info.data)
		if err != nil {
			bundle.executableDetail = "app executable was not resolved: Info.plist could not be decoded"
			continue
		}
		value, declared := dict["CFBundleExecutable"]
		if declared {
			executable, stringValue := value.(string)
			if _, safe := safeAppExecutableName(executable); !stringValue || !safe {
				bundle.executableDetail = "app executable was not resolved: CFBundleExecutable is not a literal safe filename"
				continue
			}
			bundle.executable = executable
		}
		names := macosExecutables[root]
		if !declared && len(names) == 1 {
			bundle.executable = names[0]
		}
		if bundle.executable != "" {
			path := "Contents/MacOS/" + bundle.executable
			target, unique := uniqueCanonicalAppMember(membersByRoot[root], path)
			if !unique || !target.available {
				bundle.executable = ""
				bundle.executableDetail = "app executable was not resolved: selected target is ambiguous, noncanonical, or unavailable"
			}
		} else {
			bundle.executableDetail = "app executable was not resolved: Info.plist does not select a unique executable"
		}
	}
	markArchivePlatypusApps(byRoot, entries)
	markArchiveElectronApps(byRoot, entries)
	for root, bundle := range byRoot {
		if rootAliases[strings.ToLower(root)] > 1 {
			bundle.platypus, bundle.electron, bundle.unpacked = false, false, false
			continue
		}
		if descriptor, ok := recognizeOSAApplet(membersByRoot[root]); ok {
			bundle.osaApplet = &descriptor
		}
		if evidence, ok := recognizeTauriExecutable(membersByRoot[root], bundle.executable); ok {
			bundle.tauriEvidence = evidence
		}
	}
	roots := make([]string, 0, len(byRoot))
	for root := range byRoot {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	out := make([]archiveAppBundle, 0, len(roots))
	for _, root := range roots {
		out = append(out, *byRoot[root])
	}
	return out
}

func ensureArchiveAppBundle(bundles map[string]*archiveAppBundle, root string) *archiveAppBundle {
	if bundle := bundles[root]; bundle != nil {
		return bundle
	}
	bundle := &archiveAppBundle{root: root}
	bundles[root] = bundle
	return bundle
}

func recognizeOSAApplet(members []appBundleMember) (appBundleScriptDescriptor, bool) {
	info, ok := uniqueCanonicalAppMember(members, appInfoRelativePath)
	if !ok || !info.available || int64(len(info.data)) > maxAppMetadataBytes || !looksLikeOSAAppletMetadata(info.data) {
		return appBundleScriptDescriptor{}, false
	}
	executable, ok := uniqueCanonicalAppMember(members, osaAppletExecutableRelativePath)
	if !ok || !executable.available || (executable.kind != "macho" && executable.kind != "macho-fat") {
		return appBundleScriptDescriptor{}, false
	}
	script, ok := uniqueCanonicalAppMember(members, osaAppletScriptRelativePath)
	if !ok || !script.available || script.kind != "compiled-applescript" {
		return appBundleScriptDescriptor{}, false
	}
	// Re-run public content detection instead of trusting an archive-provided or
	// path-derived kind. The FasdUAS observation is the direct script evidence.
	if kind, _ := Detect(script.relativePath, script.data, false); kind != "compiled-applescript" {
		return appBundleScriptDescriptor{}, false
	}
	return appBundleScriptDescriptor{
		executableRelativePath: osaAppletExecutableRelativePath,
		scriptRelativePath:     osaAppletScriptRelativePath,
	}, true
}

func uniqueCanonicalAppMember(members []appBundleMember, canonical string) (appBundleMember, bool) {
	var match appBundleMember
	matches := 0
	for _, member := range members {
		relative := filepath.ToSlash(member.relativePath)
		if !strings.EqualFold(relative, canonical) {
			continue
		}
		matches++
		if relative == canonical {
			match = member
		}
	}
	return match, matches == 1 && match.relativePath != ""
}

func looksLikeOSAAppletMetadata(data []byte) bool {
	dict, err := plistx.Decode(data)
	if err != nil {
		return false
	}
	executable, executableOK := canonicalPlistString(dict, "CFBundleExecutable")
	identifier, identifierOK := canonicalPlistString(dict, "CFBundleIdentifier")
	packageType, packageOK := canonicalPlistString(dict, "CFBundlePackageType")
	signature, signatureOK := canonicalPlistString(dict, "CFBundleSignature")
	return executableOK && executable == "applet" &&
		identifierOK && strings.HasPrefix(identifier, osaAppletBundleIDPrefix) && len(identifier) > len(osaAppletBundleIDPrefix) &&
		packageOK && packageType == "APPL" &&
		signatureOK && signature == "aplt"
}

func canonicalPlistString(dict plistx.Dict, key string) (string, bool) {
	value, ok := dict[key].(string)
	if !ok || value == "" || strings.TrimSpace(value) != value {
		return "", false
	}
	return value, true
}

func archiveInfoPlistAppRoot(name string) (string, bool) {
	root, rel, ok := archiveEntryWithinApp(name)
	if !ok || strings.ToLower(rel) != "contents/info.plist" {
		return "", false
	}
	return root, true
}

func archiveEntryWithinApp(name string) (root, rel string, ok bool) {
	name = filepath.ToSlash(name)
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if !strings.HasSuffix(strings.ToLower(part), ".app") {
			continue
		}
		if i == len(parts)-1 {
			return "", "", false
		}
		return strings.Join(parts[:i+1], "/"), strings.Join(parts[i+1:], "/"), true
	}
	return "", "", false
}

func isArchiveMacOSExecutable(rel string, entry VirtualEntry) bool {
	if entry.RawFeaturesOnly || entry.Directory || entry.Symlink || entry.Hardlink || entry.SkipDetail != "" {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) != 3 || strings.ToLower(parts[0]) != "contents" || strings.ToLower(parts[1]) != "macos" {
		return false
	}
	kind, _ := Detect(parts[2], entry.Data, entry.Executable)
	return entry.Executable || kind == "macho" || kind == "macho-fat" || kind == "executable"
}

func archiveAppRootForEntry(name string, bundles map[string]*archiveAppBundle) string {
	root, _, ok := archiveEntryWithinApp(name)
	if !ok {
		return ""
	}
	if bundle, ok := bundles[root]; !ok || bundle == nil {
		return ""
	}
	return root
}

func (s *scanner) addArchiveAppBundleEdge(bundle *archiveAppBundle, name, childID string, entry VirtualEntry) {
	if bundle == nil || childID == "" || entry.RawFeaturesOnly {
		return
	}
	root, rel, ok := archiveEntryWithinApp(name)
	if !ok || root != bundle.root {
		return
	}
	lowerRel := strings.ToLower(rel)
	if bundle.platypus {
		switch rel {
		case "Contents/Resources/AppSettings.plist":
			bundle.platypusSettingsNodeID = childID
		case "Contents/Resources/script":
			bundle.platypusScriptNodeID = childID
		}
	}
	switch {
	case lowerRel == "contents/info.plist" || lowerRel == "contents/resources/appsettings.plist":
		s.graph.AddEdge(bundle.nodeID, childID, "bundle-metadata")
	case bundle.executable != "" && rel == filepath.ToSlash(filepath.Join("Contents", "MacOS", bundle.executable)):
		bundle.executableNodeID = childID
		s.graph.AddEdge(bundle.nodeID, childID, "bundle-executable")
		if len(bundle.tauriEvidence) != 0 {
			setArtifactPackagingTechnology(&s.graph, childID, "Tauri", bundle.tauriEvidence)
			s.markNodePartial(childID, "Tauri runtime recognized; versioned embedded frontend asset-table extraction is not implemented")
		}
	}
	if bundle.osaApplet != nil && rel == bundle.osaApplet.scriptRelativePath {
		bundle.osaAppletScriptNodeID = childID
	}
}

func markArchivePlatypusApps(bundles map[string]*archiveAppBundle, entries []VirtualEntry) {
	type candidate struct {
		settingsMatches  int
		settingsValid    bool
		settingsEvidence []LocatedArtifactEvidence
		invocation       platypusInvocationDescriptor
		invocationOK     bool
		scriptMatches    int
		scriptValid      bool
	}
	candidates := make(map[string]*candidate, len(bundles))
	for _, entry := range entries {
		if entry.RawFeaturesOnly {
			continue
		}
		name, ok := cleanArchiveName(entry.Name)
		if !ok {
			continue
		}
		root, rel, ok := archiveEntryWithinApp(name)
		if !ok || bundles[root] == nil {
			continue
		}
		state := candidates[root]
		if state == nil {
			state = &candidate{}
			candidates[root] = state
		}
		regular := !entry.Directory && !entry.Symlink && !entry.Hardlink && entry.SkipDetail == ""
		switch {
		case strings.EqualFold(rel, "Contents/Resources/AppSettings.plist"):
			state.settingsMatches++
			state.settingsValid = rel == "Contents/Resources/AppSettings.plist" && regular &&
				len(entry.Data) <= int(maxAppMetadataBytes) && looksLikePlatypusSettings(entry.Data)
			if state.settingsValid {
				state.settingsEvidence, _ = platypusSettingsEvidence(entry.Data)
				state.invocation, state.invocationOK = platypusInvocation(entry.Data)
			}
		case strings.EqualFold(rel, "Contents/Resources/script"):
			state.scriptMatches++
			state.scriptValid = rel == "Contents/Resources/script" && regular
		}
	}
	for root, state := range candidates {
		bundles[root].platypus = state.settingsMatches == 1 && state.settingsValid &&
			state.scriptMatches == 1 && state.scriptValid
		if bundles[root].platypus {
			bundles[root].platypusEvidence = append([]LocatedArtifactEvidence(nil), state.settingsEvidence...)
			bundles[root].platypusInvocation = state.invocation
			bundles[root].platypusInvocationOK = state.invocationOK
		}
	}
}

func (s *scanner) addArchiveAppBundleDeferredEdges(bundles map[string]*archiveAppBundle) {
	roots := make([]string, 0, len(bundles))
	for root := range bundles {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	for _, root := range roots {
		bundle := bundles[root]
		if bundle == nil {
			continue
		}
		if bundle.platypus && bundle.platypusSettingsNodeID != "" && bundle.platypusScriptNodeID != "" {
			evidence := append([]LocatedArtifactEvidence(nil), bundle.platypusEvidence...)
			for index := range evidence {
				evidence[index].NodeID = bundle.platypusSettingsNodeID
			}
			if len(evidence) != 0 {
				setArtifactPackagingTechnology(&s.graph, bundle.nodeID, "Platypus", evidence)
			}
			if bundle.platypusInvocationOK {
				invocationEvidence := append([]LocatedArtifactEvidence(nil), bundle.platypusInvocation.evidence...)
				for index := range invocationEvidence {
					invocationEvidence[index].NodeID = bundle.platypusSettingsNodeID
				}
				s.graph.AddSupportedInvocationEdge(
					bundle.nodeID,
					bundle.platypusScriptNodeID,
					"bundle-script",
					bundle.platypusInvocation.interpreter,
					bundle.platypusInvocation.interpreterArgs,
					bundle.platypusInvocation.scriptArgs,
					invocationEvidence,
				)
			} else {
				s.graph.AddUnresolvedInvocationEdge(bundle.nodeID, bundle.platypusScriptNodeID, "bundle-script")
				s.markNodePartial(bundle.nodeID, "Platypus runtime recognized, but exact interpreter arguments were not established from AppSettings.plist")
			}
		}
		if bundle.osaApplet != nil && bundle.executableNodeID != "" && bundle.osaAppletScriptNodeID != "" {
			s.graph.AddEdge(bundle.nodeID, bundle.osaAppletScriptNodeID, "bundle-script")
		}
	}
}

func (s *scanner) scanAppBundle(root, logical string, appID string) {
	// An inspection may contain many sibling app bundles. Remember the graph
	// boundary for this bundle so relationship classification remains linear in
	// the nodes produced by this call instead of rescanning every prior sibling.
	bundleNodeStart := len(s.graph.Nodes)
	nodesByLogical := map[string]string{}
	var bundleMembers []appBundleMember
	contents := filepath.Join(root, "Contents")
	files, skippedDirs, traversalIssues := s.appBundleFiles(contents)
	exe := s.appBundleExecutable(root, files)
	if exe == "" {
		s.markNodePartial(appID, "app executable was not resolved from available bundle metadata and files")
	}
	if s.filesystemAppHasElectronRuntime(root, exe, files) {
		s.markElectronApp(appID)
		unpackedManifest := filepath.Join(root, "Contents", "Resources", "app", "package.json")
		if info, err := s.lstatFilesystemPath(unpackedManifest); err == nil && info.Mode().IsRegular() {
			detail := "canonical unpacked Electron app is present; package main and transitive Node module resolution are not implemented"
			s.markNodePartial(appID, detail)
			s.addDiagnostic(filepath.ToSlash(filepath.Join(logical, "Contents", "Resources", "app")) + ": " + detail)
		}
	}
	for _, issue := range traversalIssues {
		rel, err := filepath.Rel(root, issue.path)
		if err != nil {
			rel = filepath.Base(issue.path)
		}
		childLogical := filepath.ToSlash(filepath.Join(logical, rel))
		s.markNodePartial(appID, "app bundle traversal incomplete; see diagnostics")
		s.addDiagnostic(childLogical + ": " + issue.detail)
	}
	for _, skipped := range skippedDirs {
		rel, err := filepath.Rel(root, skipped.path)
		if err != nil {
			rel = filepath.Base(skipped.path)
		}
		childLogical := filepath.ToSlash(filepath.Join(logical, rel))
		size := int64(0)
		if info, err := s.lstatFilesystemPath(skipped.path); err == nil {
			size = info.Size()
		}
		s.addSkippedDirectory(skipped.path, childLogical, appID, "app-bundle", skipped.detail, size)
		s.addDiagnostic(childLogical + ": " + skipped.detail)
	}
	for _, full := range files {
		rel, err := filepath.Rel(root, full)
		if err != nil {
			rel = filepath.Base(full)
		}
		childLogical := filepath.ToSlash(filepath.Join(logical, rel))
		member := appBundleMember{relativePath: filepath.ToSlash(rel)}
		contentStart := len(s.contents)
		nodeID := s.scanFile(full, childLogical, appID, "app-bundle", 0)
		if nodeID == "" {
			bundleMembers = append(bundleMembers, member)
			continue
		}
		nodesByLogical[childLogical] = nodeID
		for i := contentStart; i < len(s.contents); i++ {
			if s.contents[i].NodeID != nodeID {
				continue
			}
			member.data = s.contents[i].Data
			member.kind = s.contents[i].Kind
			member.available = true
			break
		}
		bundleMembers = append(bundleMembers, member)
		if rel == filepath.Join("Contents", "Info.plist") {
			s.graph.AddEdge(appID, nodeID, "bundle-metadata")
		}
		if rel == filepath.Join("Contents", "Resources", "AppSettings.plist") {
			s.graph.AddEdge(appID, nodeID, "bundle-metadata")
		}
	}
	if exe != "" {
		rel, _ := filepath.Rel(root, exe)
		if node := nodesByLogical[filepath.ToSlash(filepath.Join(logical, rel))]; node != "" {
			s.graph.AddEdge(appID, node, "bundle-executable")
		}
	}
	if descriptor, ok := recognizeOSAApplet(bundleMembers); ok {
		executableLogical := filepath.ToSlash(filepath.Join(logical, descriptor.executableRelativePath))
		scriptLogical := filepath.ToSlash(filepath.Join(logical, descriptor.scriptRelativePath))
		if nodesByLogical[executableLogical] != "" && nodesByLogical[scriptLogical] != "" {
			s.graph.AddEdge(appID, nodesByLogical[scriptLogical], "bundle-script")
		}
	}
	if evidence, ok := recognizeTauriExecutable(bundleMembers, filepath.Base(exe)); ok {
		if rel, err := filepath.Rel(root, exe); err == nil {
			if node := nodesByLogical[filepath.ToSlash(filepath.Join(logical, rel))]; node != "" {
				setArtifactPackagingTechnology(&s.graph, node, "Tauri", evidence)
				s.markNodePartial(node, "Tauri runtime recognized; versioned embedded frontend asset-table extraction is not implemented")
			}
		}
	}
	if script := s.platypusScriptEntrypoint(root); script != "" {
		rel, _ := filepath.Rel(root, script)
		if node := nodesByLogical[filepath.ToSlash(filepath.Join(logical, rel))]; node != "" {
			invocationAdded := false
			settingsRelative := filepath.ToSlash(filepath.Join("Contents", "Resources", "AppSettings.plist"))
			settingsLogical := filepath.ToSlash(filepath.Join(logical, settingsRelative))
			if settings, ok := uniqueCanonicalAppMember(bundleMembers, settingsRelative); ok && settings.available {
				if evidence, ok := platypusSettingsEvidence(settings.data); ok {
					settingsNodeID := nodesByLogical[settingsLogical]
					for index := range evidence {
						evidence[index].NodeID = settingsNodeID
					}
					if settingsNodeID != "" {
						setArtifactPackagingTechnology(&s.graph, appID, "Platypus", evidence)
						if invocation, ok := platypusInvocation(settings.data); ok {
							for index := range invocation.evidence {
								invocation.evidence[index].NodeID = settingsNodeID
							}
							s.graph.AddSupportedInvocationEdge(appID, node, "bundle-script", invocation.interpreter, invocation.interpreterArgs, invocation.scriptArgs, invocation.evidence)
							invocationAdded = true
						}
					}
				}
			}
			if !invocationAdded {
				s.graph.AddUnresolvedInvocationEdge(appID, node, "bundle-script")
				s.markNodePartial(appID, "Platypus runtime recognized, but exact interpreter arguments were not established from AppSettings.plist")
			}
		}
	}
	for _, node := range s.graph.Nodes[bundleNodeStart:] {
		if isAppHelperExecutable(node) {
			s.graph.AddEdge(appID, node.ID, "bundle-helper")
		}
		lower := strings.ToLower(node.LogicalPath)
		if strings.Contains(lower, "library/launchagents/") || strings.Contains(lower, "library/launchdaemons/") {
			s.graph.AddEdge(appID, node.ID, "persists-via")
		}
	}
}

func (s *scanner) markElectronApp(appID string) {
	if appID == "" {
		return
	}
	if s.electronApps == nil {
		s.electronApps = map[string]bool{}
	}
	s.electronApps[appID] = true
}

func (s *scanner) filesystemAppHasElectronRuntime(root, executable string, files []string) bool {
	if executable == "" {
		return false
	}
	executableInfo, err := s.lstatFilesystemPath(executable)
	if err != nil || !executableInfo.Mode().IsRegular() {
		return false
	}
	executableFile, _, err := s.openStableRegularFile(executable, executableInfo)
	if err != nil {
		return false
	}
	loadsElectron := machoLoadsElectronFramework(executableFile, executableInfo.Size())
	_ = executableFile.Close()
	if !loadsElectron {
		return false
	}
	for _, path := range files {
		rel, err := filepath.Rel(root, path)
		if err != nil || !electronRuntimeRelativePath(rel) {
			continue
		}
		info, err := s.lstatFilesystemPath(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		file, _, err := s.openStableRegularFile(path, info)
		if err != nil {
			continue
		}
		valid := validElectronFrameworkMachO(file, info.Size())
		_ = file.Close()
		if valid {
			return true
		}
	}
	return false
}

func markArchiveElectronApps(bundles map[string]*archiveAppBundle, entries []VirtualEntry) {
	if len(bundles) == 0 {
		return
	}
	frameworkValid := make(map[string]bool, len(bundles))
	loaderValid := make(map[string]bool, len(bundles))
	for _, entry := range entries {
		if entry.RawFeaturesOnly {
			continue
		}
		name, ok := cleanArchiveName(entry.Name)
		if !ok || entry.Directory || entry.Symlink || entry.Hardlink || entry.SkipDetail != "" {
			continue
		}
		entryRoot, rel, ok := archiveEntryWithinApp(name)
		if !ok {
			continue
		}
		bundle := bundles[entryRoot]
		if bundle == nil || bundle.executable == "" {
			continue
		}
		if strings.EqualFold(rel, "Contents/Resources/app/package.json") {
			bundle.unpacked = true
		}
		if !frameworkValid[entryRoot] && electronRuntimeRelativePath(rel) && validElectronFrameworkMachOBytes(entry.Data) {
			frameworkValid[entryRoot] = true
		}
		wantExecutable := filepath.ToSlash(filepath.Join("Contents", "MacOS", bundle.executable))
		if !loaderValid[entryRoot] && rel == wantExecutable && machoLoadsElectronFrameworkBytes(entry.Data) {
			loaderValid[entryRoot] = true
		}
	}
	for root, bundle := range bundles {
		bundle.electron = frameworkValid[root] && loaderValid[root]
		if !bundle.electron {
			bundle.unpacked = false
		}
	}
}

func electronRuntimeRelativePath(rel string) bool {
	rel = strings.ToLower(filepath.ToSlash(filepath.Clean(rel)))
	switch rel {
	case "contents/frameworks/electron framework.framework/electron framework",
		"contents/frameworks/electron framework.framework/versions/a/electron framework":
		return true
	default:
		return false
	}
}

func isAppHelperExecutable(node Node) bool {
	if node.Kind == "symlink" || node.AnalyzeStatus == "skipped" {
		return false
	}
	lower := strings.ToLower(filepath.ToSlash(node.LogicalPath))
	return strings.Contains(lower, ".xpc/contents/macos/") ||
		(strings.Count(lower, ".app/contents/") > 1 && strings.Contains(lower, "/contents/macos/"))
}

func (s *scanner) appBundleFiles(contents string) ([]string, []skippedAppDirectory, []appTraversalIssue) {
	var files []string
	var skippedDirs []skippedAppDirectory
	var traversalIssues []appTraversalIssue
	var walk func(path string, depth int, expected os.FileInfo)
	walk = func(path string, depth int, expected os.FileInfo) {
		entries, limited, err := s.readTraversalDirectory(path, expected)
		if err != nil {
			traversalIssues = append(traversalIssues, appTraversalIssue{
				path:   path,
				detail: "app traversal failed: " + err.Error(),
			})
		}
		if limited {
			limit := s.options.MaxArtifactNodes
			if limit <= 0 {
				limit = DefaultMaxArtifactNodes
			}
			traversalIssues = append(traversalIssues, appTraversalIssue{
				path:   path,
				detail: traversalLimitDetail(limit),
			})
		}
		for _, entry := range entries {
			full := filepath.Join(path, entry.Name())
			info, infoErr := s.lstatFilesystemPath(full)
			if infoErr != nil {
				traversalIssues = append(traversalIssues, appTraversalIssue{
					path:   full,
					detail: "app entry metadata failed: " + infoErr.Error(),
				})
				continue
			}
			if info.IsDir() {
				childDepth := depth + 1
				if s.options.MaxDirectoryDepth > 0 && childDepth > s.options.MaxDirectoryDepth {
					skippedDirs = append(skippedDirs, skippedAppDirectory{
						path:   full,
						detail: "directory depth limit " + strconv.Itoa(s.options.MaxDirectoryDepth) + " reached",
					})
					continue
				}
				if detail, skip := skippedAppDirectoryReason(full, entry.Name(), s.options.IncludeUnreferenced); skip {
					if detail != "" {
						skippedDirs = append(skippedDirs, skippedAppDirectory{path: full, detail: detail})
					}
					continue
				}
				walk(full, childDepth, info)
				continue
			}
			interesting := interestingAppFile(full, info, s.options.IncludeUnreferenced)
			if !interesting && s.appResourceHasStrongMagic(full, info) {
				interesting = true
			}
			if interesting {
				files = append(files, full)
			}
		}
	}
	contentsInfo, err := s.lstatFilesystemPath(contents)
	if err != nil {
		traversalIssues = append(traversalIssues, appTraversalIssue{path: contents, detail: "app traversal failed: " + err.Error()})
	} else if !contentsInfo.IsDir() {
		traversalIssues = append(traversalIssues, appTraversalIssue{path: contents, detail: "app traversal failed: Contents is not a directory"})
	} else {
		walk(contents, 0, contentsInfo)
	}
	sort.Strings(files)
	sort.Slice(skippedDirs, func(i, j int) bool { return skippedDirs[i].path < skippedDirs[j].path })
	sort.Slice(traversalIssues, func(i, j int) bool {
		if traversalIssues[i].path != traversalIssues[j].path {
			return traversalIssues[i].path < traversalIssues[j].path
		}
		return traversalIssues[i].detail < traversalIssues[j].detail
	})
	return files, skippedDirs, traversalIssues
}

func (s *scanner) appResourceHasStrongMagic(path string, expected os.FileInfo) bool {
	if expected == nil || !expected.Mode().IsRegular() {
		return false
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	if !strings.Contains(lower, "/contents/resources/") {
		return false
	}
	file, _, err := s.openStableRegularFile(path, expected)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	probeSize := int64(maxAppMagicProbeBytes)
	if expected.Size() < probeSize {
		probeSize = expected.Size()
	}
	if probeSize <= 0 {
		return false
	}
	probe := make([]byte, probeSize)
	n, _ := file.ReadAt(probe, 0)
	if n == 0 {
		return false
	}
	kind, _ := Detect(path, probe[:n], false)
	switch kind {
	case "compiled-applescript", "macho", "macho-fat":
		return true
	case "script":
		return hasScriptShebang(probe[:n])
	case "plist":
		return n >= 8 && string(probe[:8]) == "bplist00"
	default:
		return false
	}
}

func skippedAppDirectoryReason(path, name string, includeUnreferenced bool) (string, bool) {
	lower := strings.ToLower(name)
	switch lower {
	case ".git", ".hg", ".svn",
		"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
		"node_modules", "bower_components", "jspm_packages", "vendor", ".venv", "venv",
		".gocache", ".uv-cache", ".tox", ".nox", "coverage":
		return "dependency or build directory skipped during app traversal", true
	}
	if !includeUnreferenced && isHeavyAppResourceDir(path, lower) {
		return "large app resource directory skipped; use --include-unreferenced to inspect", true
	}
	if strings.HasSuffix(lower, ".lproj") || name == "_CodeSignature" {
		return "", true
	}
	return "", false
}

func isHeavyAppResourceDir(path, lowerName string) bool {
	lowerPath := strings.ToLower(filepath.ToSlash(path))
	if !strings.Contains(lowerPath, "/contents/resources/") {
		return false
	}
	switch lowerName {
	case "app.asar.unpacked", "plugins", "extensions", "default_app", "cua_node":
		return true
	default:
		return false
	}
}

func interestingAppFile(path string, info os.FileInfo, includeUnreferenced bool) bool {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))
	if base == "info.plist" || base == "package.json" || base == "appsettings.plist" || base == "script" {
		return true
	}
	switch ext {
	case ".dylib", ".so", ".xpc", ".appex", ".jar", ".zip", ".pkg":
		return true
	case ".asar":
		return includeUnreferenced || isCanonicalAppASAR(path)
	case ".plist", ".sh", ".bash", ".zsh", ".command", ".py", ".js", ".mjs", ".cjs", ".ts", ".applescript", ".jxa", ".scpt":
		if ext == ".js" || ext == ".mjs" || ext == ".cjs" || ext == ".ts" {
			return includeUnreferenced
		}
		return true
	}
	return info.Mode().IsRegular() && info.Mode()&0o111 != 0
}

func isCanonicalAppASAR(path string) bool {
	clean := filepath.Clean(path)
	if !strings.EqualFold(filepath.Base(clean), "app.asar") {
		return false
	}
	resources := filepath.Dir(clean)
	if !strings.EqualFold(filepath.Base(resources), "Resources") {
		return false
	}
	return strings.EqualFold(filepath.Base(filepath.Dir(resources)), "Contents")
}

func (s *scanner) appBundleExecutable(root string, files []string) string {
	info := filepath.Join(root, "Contents", "Info.plist")
	dict := s.readRegularPlist(info)
	if dict == nil {
		return ""
	}
	if value, declared := dict["CFBundleExecutable"]; declared {
		// This is an exact filename, not a display string. Do not trim it,
		// coerce another plist type, or substitute an unrelated executable when
		// the declared target is invalid or missing.
		exeName, stringValue := value.(string)
		if _, safe := safeAppExecutableName(exeName); !stringValue || !safe {
			return ""
		}
		candidate := filepath.Join(root, "Contents", "MacOS", exeName)
		if st, err := s.lstatFilesystemPath(candidate); err == nil && st.Mode().IsRegular() {
			return candidate
		}
		return ""
	}
	macos := filepath.Join(root, "Contents", "MacOS")
	var executables []string
	for _, candidate := range files {
		if filepath.Clean(filepath.Dir(candidate)) != filepath.Clean(macos) {
			continue
		}
		info, err := s.lstatFilesystemPath(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			executables = append(executables, candidate)
		}
	}
	sort.Strings(executables)
	if len(executables) == 1 {
		return executables[0]
	}
	return ""
}

func safeAppExecutableName(value string) (string, bool) {
	if value == "" || value == "." || value == ".." || filepath.IsAbs(value) || filepath.Clean(value) != value || filepath.Base(value) != value || strings.ContainsAny(value, `/\`) {
		return "", false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return value, true
}

func platypusScriptEntrypoint(root string) string {
	return (&scanner{}).platypusScriptEntrypoint(root)
}

func (s *scanner) platypusScriptEntrypoint(root string) string {
	settings := filepath.Join(root, "Contents", "Resources", "AppSettings.plist")
	script := filepath.Join(root, "Contents", "Resources", "script")
	scriptInfo, scriptErr := s.lstatFilesystemPath(script)
	if scriptErr != nil {
		return ""
	}
	if !scriptInfo.Mode().IsRegular() {
		return ""
	}
	data, err := s.readStableRegularFile(settings, maxAppMetadataBytes)
	if err != nil || !looksLikePlatypusSettings(data) {
		return ""
	}
	return script
}

func (s *scanner) readRegularPlist(path string) plistx.Dict {
	data, err := s.readStableRegularFile(path, maxAppMetadataBytes)
	if err != nil {
		return nil
	}
	dict, _ := plistx.Decode(data)
	return dict
}

func (s *scanner) readStableRegularFile(path string, max int64) ([]byte, error) {
	info, err := s.lstatFilesystemPath(path)
	if err != nil {
		return nil, err
	}
	file, openedInfo, err := s.openStableRegularFile(path, info)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if openedInfo.Size() > max {
		return nil, &byteLimitError{Limit: max}
	}
	data, exceeded, err := readAllAtMost(file, max)
	if err != nil {
		return nil, err
	}
	if exceeded {
		return nil, &byteLimitError{Limit: max}
	}
	return data, nil
}
