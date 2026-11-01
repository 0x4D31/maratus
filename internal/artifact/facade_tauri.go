package artifact

import (
	"bytes"
	"path/filepath"
	"strings"
)

// recognizeTauriExecutable attributes only the exact declared app executable.
// The three proofs are deliberately independent: two versioned Rust crate
// records establish the core/runtime pairing, while the IPC bootstrap ties
// those implementation strings to a Tauri application runtime.
func recognizeTauriExecutable(members []appBundleMember, executable string) ([]LocatedArtifactEvidence, bool) {
	if executable == "" {
		return nil, false
	}
	canonical := filepath.ToSlash(filepath.Join("Contents", "MacOS", executable))
	member, ok := uniqueCanonicalAppMember(members, canonical)
	if !ok || !member.available || (member.kind != "macho" && member.kind != "macho-fat") {
		return nil, false
	}
	core, ok := locatedTauriCrate(member.data, []byte("/tauri-"), "tauri-core-crate", "tauri")
	if !ok {
		return nil, false
	}
	runtime, ok := locatedTauriCrate(member.data, []byte("/tauri-runtime-wry-"), "tauri-runtime-crate", "tauri-runtime-wry")
	if !ok {
		return nil, false
	}
	ipcOffset := bytes.Index(member.data, []byte("__TAURI_INVOKE_KEY__"))
	if ipcOffset < 0 {
		return nil, false
	}
	return []LocatedArtifactEvidence{
		core,
		runtime,
		{Offset: int64(ipcOffset), Kind: "tauri-ipc-bootstrap", Value: "__TAURI_INVOKE_KEY__"},
	}, true
}

func locatedTauriCrate(data, marker []byte, kind, crate string) (LocatedArtifactEvidence, bool) {
	const maxCandidates = 64
	searchFrom := 0
	for candidate := 0; candidate < maxCandidates && searchFrom < len(data); candidate++ {
		relative := bytes.Index(data[searchFrom:], marker)
		if relative < 0 {
			break
		}
		offset := searchFrom + relative
		versionStart := offset + len(marker)
		versionEndRel := bytes.Index(data[versionStart:], []byte("/src/"))
		if versionEndRel >= 0 && versionEndRel <= 64 && hasCargoRegistryPrefix(data, offset) {
			version := string(data[versionStart : versionStart+versionEndRel])
			if validTauriCrateVersion(version) {
				return LocatedArtifactEvidence{Offset: int64(offset), Kind: kind, Value: crate + "@" + version}, true
			}
		}
		searchFrom = offset + len(marker)
	}
	return LocatedArtifactEvidence{}, false
}

func hasCargoRegistryPrefix(data []byte, crateOffset int) bool {
	const maxRegistryPrefixBytes = 160
	start := crateOffset - maxRegistryPrefixBytes
	if start < 0 {
		start = 0
	}
	prefix := []byte("/.cargo/registry/src/")
	relative := bytes.LastIndex(data[start:crateOffset], prefix)
	if relative < 0 {
		return false
	}
	namespace := data[start+relative+len(prefix) : crateOffset]
	if len(namespace) == 0 || len(namespace) > 128 || bytes.ContainsAny(namespace, "\x00\\") {
		return false
	}
	return bytes.IndexByte(namespace, '/') < 0
}

func validTauriCrateVersion(version string) bool {
	if len(version) < 5 || len(version) > 64 {
		return false
	}
	for _, char := range version {
		if char >= '0' && char <= '9' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char == '.' || char == '-' || char == '+' {
			continue
		}
		return false
	}
	core := version
	if index := strings.IndexAny(core, "-+"); index >= 0 {
		core = core[:index]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}
