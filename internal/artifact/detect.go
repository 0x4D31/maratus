package artifact

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const compiledAppleScriptMagic = "FasdUAS"

func Detect(path string, data []byte, executable bool) (kind, media string) {
	lower := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(lower))
	switch {
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0xfe, 0xed, 0xfa, 0xce}):
		return "macho", "application/x-mach-binary"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0xce, 0xfa, 0xed, 0xfe}):
		return "macho", "application/x-mach-binary"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0xfe, 0xed, 0xfa, 0xcf}):
		return "macho", "application/x-mach-binary"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}):
		return "macho", "application/x-mach-binary"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0xca, 0xfe, 0xba, 0xbe}):
		// Java class files and big-endian 32-bit fat Mach-O containers share
		// the CAFEBABE magic. Prefer a structurally valid fat container, then a
		// structurally valid class file. Preserve malformed fat candidates as
		// Mach-O so downstream coverage still explains why they were rejected.
		if isFat, err := PreflightMachO(data); isFat && err == nil {
			return "macho-fat", "application/x-mach-binary"
		}
		if isJavaClass(data) {
			return "java-class", "application/java-vm"
		}
		return "macho-fat", "application/x-mach-binary"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0xbe, 0xba, 0xfe, 0xca}):
		return "macho-fat", "application/x-mach-binary"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0xca, 0xfe, 0xba, 0xbf}):
		return "macho-fat", "application/x-mach-binary"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0xbf, 0xba, 0xfe, 0xca}):
		return "macho-fat", "application/x-mach-binary"
	case len(data) >= len(compiledAppleScriptMagic) && bytes.Equal(data[:len(compiledAppleScriptMagic)], []byte(compiledAppleScriptMagic)) && !isText(data):
		return "compiled-applescript", "application/x-apple-compiled-applescript"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte("xar!")):
		return "pkg", "application/x-xar"
	case isIndexedGzipBundle(data):
		// Full structural validation wins over a misleading source suffix. The
		// opaque prefix and tags do not attribute a producer or platform.
		return "indexed-gzip-bundle", "application/x-indexed-gzip-bundle"
	case isZipArchive(data):
		return archiveKind(ext), "application/zip"
	case len(data) >= 8 && bytes.Equal(data[:8], []byte("bplist00")):
		return "plist", "application/x-apple-binary-plist"
	case hasUDIFMagic(data):
		return "dmg", "application/x-apple-diskimage"
	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b:
		return "gzip", "application/gzip"
	case looksLikeASAR(data):
		return "asar", "application/x-asar"
	case hasTarMagic(data):
		return "tar", "application/x-tar"
	case len(data) >= 6 && (bytes.Equal(data[:6], []byte("070701")) || bytes.Equal(data[:6], []byte("070702")) || bytes.Equal(data[:6], []byte("070707"))):
		return "cpio", "application/x-cpio"
	case hasResourceMagic(data):
		kind, media, _ := resourceMagicType(data)
		return kind, media
	case strings.HasSuffix(lower, ".asar") && !isText(data):
		// Preserve explicit coverage for malformed binary ASAR candidates, but
		// do not let an attacker-controlled suffix hide ordinary script text.
		return "asar", "application/x-asar"
	case logicalBase(path) == "SKILL.md" && isAgentSkillText(data) && !hasScriptShebang(data):
		return "agent-skill", "text/markdown"
	case isText(data):
		return scriptOrTextKind(ext, lower, executable, data), "text/plain"
	case strings.HasSuffix(lower, ".tar"):
		return "tar", "application/x-tar"
	case strings.HasSuffix(lower, ".dmg"):
		return "dmg", "application/x-apple-diskimage"
	case hasResourceExtension(ext):
		kind, media, _ := resourceExtensionType(ext)
		return kind, media
	case executable:
		return "executable", "application/octet-stream"
	default:
		return "blob", "application/octet-stream"
	}
}

func hasResourceType(ext string, data []byte) bool {
	return hasResourceMagic(data) || hasResourceExtension(ext)
}

func resourceType(ext string, data []byte) (kind, media string, ok bool) {
	if kind, media, ok := resourceMagicType(data); ok {
		return kind, media, true
	}
	return resourceExtensionType(ext)
}

func hasResourceMagic(data []byte) bool {
	_, _, ok := resourceMagicType(data)
	return ok
}

func resourceMagicType(data []byte) (kind, media string, ok bool) {
	switch {
	case isAppleDouble(data):
		return "resource", "application/applefile", true
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0x89, 'P', 'N', 'G'}):
		return "resource", "image/png", true
	case len(data) >= 4 && bytes.Equal(data[:4], []byte("icns")):
		return "resource", "image/icns", true
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		return "resource", "image/jpeg", true
	case len(data) >= 6 && (bytes.Equal(data[:6], []byte("GIF87a")) || bytes.Equal(data[:6], []byte("GIF89a"))):
		return "resource", "image/gif", true
	case len(data) >= 5 && bytes.Equal(data[:5], []byte("%PDF-")):
		return "resource", "application/pdf", true
	case len(data) >= 5 && bytes.Equal(data[:5], []byte("{\\rtf")):
		return "resource", "text/rtf", true
	}
	return "", "", false
}

func isAppleDouble(data []byte) bool {
	// RFC 1740 defines a 26-byte big-endian header followed by a table of
	// 12-byte entry descriptors. Validate enough structure to keep a four-byte
	// collision from hiding an executable as Finder/resource-fork metadata.
	if len(data) < 26 || binary.BigEndian.Uint32(data[:4]) != 0x00051607 {
		return false
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version != 0x00010000 && version != 0x00020000 {
		return false
	}
	entryCount := int(binary.BigEndian.Uint16(data[24:26]))
	if entryCount > (len(data)-26)/12 {
		return false
	}
	for i := 0; i < entryCount; i++ {
		descriptor := data[26+i*12 : 26+(i+1)*12]
		entryID := binary.BigEndian.Uint32(descriptor[0:4])
		offset := uint64(binary.BigEndian.Uint32(descriptor[4:8]))
		length := uint64(binary.BigEndian.Uint32(descriptor[8:12]))
		// Entry zero is invalid, and an AppleDouble header never contains the
		// separately stored data fork (entry one).
		if entryID <= 1 || offset > uint64(len(data)) || length > uint64(len(data))-offset {
			return false
		}
	}
	return true
}

func hasResourceExtension(ext string) bool {
	_, _, ok := resourceExtensionType(ext)
	return ok
}

func resourceExtensionType(ext string) (kind, media string, ok bool) {
	switch ext {
	case ".png":
		return "resource", "image/png", true
	case ".icns":
		return "resource", "image/icns", true
	case ".jpg", ".jpeg":
		return "resource", "image/jpeg", true
	case ".gif":
		return "resource", "image/gif", true
	case ".pdf":
		return "resource", "application/pdf", true
	case ".rtf":
		return "resource", "text/rtf", true
	case ".strings":
		return "resource", "text/plain", true
	case ".nib", ".storyboard", ".xib":
		return "resource", "application/octet-stream", true
	default:
		return "", "", false
	}
}

func isZipArchive(data []byte) bool {
	return len(data) >= 4 && (bytes.Equal(data[:4], []byte("PK\x03\x04")) ||
		bytes.Equal(data[:4], []byte("PK\x05\x06")) ||
		bytes.Equal(data[:4], []byte("PK\x07\x08")))
}

func hasTarMagic(data []byte) bool {
	return len(data) >= 262 && bytes.Equal(data[257:262], []byte("ustar"))
}

func hasUDIFMagic(data []byte) bool {
	const trailerSize = 512
	return len(data) >= trailerSize && bytes.Equal(data[len(data)-trailerSize:len(data)-trailerSize+4], []byte("koly"))
}

func archiveKind(ext string) string {
	switch ext {
	case ".jar", ".war", ".ear":
		return "java-archive"
	case ".whl":
		return "python-wheel"
	case ".nupkg":
		return "nuget-package"
	case ".vsix":
		return "vsix"
	default:
		return "zip"
	}
}

func scriptOrTextKind(ext, name string, executable bool, data []byte) string {
	if scriptExtension(ext) {
		return "script"
	}
	if name == "script" {
		return "script"
	}
	switch ext {
	case ".plist":
		return "plist"
	case ".json", ".toml", ".lock", ".xml", ".gradle", ".kts", ".vsixmanifest", ".pbxproj":
		return "manifest"
	}
	if manifestName(name) {
		return "manifest"
	}
	// Exact source suffixes establish source syntax, not direct execution. A
	// supported shebang may still make a polyglot source file runnable, but an
	// executable mode bit or Rust's #![...] inner-attribute prefix may not.
	if language := Language(name); (language == "native-source" || language == "java-source") && ShebangLanguage(data) == "" {
		return "text"
	}
	if executable {
		return "script"
	}
	if hasScriptShebang(data) {
		return "script"
	}
	return "text"
}

func scriptExtension(ext string) bool {
	switch ext {
	case ".sh", ".bash", ".zsh", ".fish", ".command",
		".py",
		".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
		".applescript", ".jxa", ".scpt":
		return true
	default:
		return false
	}
}

func manifestName(name string) bool {
	switch name {
	case "package.json", "entry_points.txt", "requirements.txt", "pyproject.toml", "pipfile", "cargo.toml", "cargo.lock", "go.mod", "gemfile", "gemfile.lock", "makefile":
		return true
	default:
		return false
	}
}

func hasScriptShebang(data []byte) bool {
	return HasShebang(data)
}

func isText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
		// The bounded prefix may end inside a valid UTF-8 rune. Trim only that
		// incomplete suffix before deciding whether the prefix is textual.
		for trim := 0; trim < utf8.UTFMax-1 && !utf8.Valid(sample); trim++ {
			sample = sample[:len(sample)-1]
		}
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return false
	}
	if !utf8.Valid(sample) {
		return false
	}
	printable := 0
	total := 0
	for _, current := range string(sample) {
		total++
		if current == '\n' || current == '\r' || current == '\t' || unicode.IsPrint(current) {
			printable++
		}
	}
	return total > 0 && printable*100/total >= 85
}

func isAgentSkillText(data []byte) bool {
	// isText intentionally samples a bounded prefix. Agent-skill recognition
	// additionally validates the complete retained content so a late NUL or
	// invalid UTF-8 sequence cannot turn arbitrary bytes into a SKILL.md.
	return bytes.IndexByte(data, 0) < 0 && utf8.Valid(data) && isText(data)
}

func Language(path string) string {
	name := logicalBase(path)
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".sh", ".bash", ".zsh", ".fish", ".command":
		return "shell"
	case ".py":
		return "python"
	case ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx":
		return "javascript"
	case ".bat", ".cmd":
		return "windows-command"
	case ".applescript", ".scpt":
		return "applescript"
	case ".jxa":
		return "jxa"
	case ".java":
		return "java-source"
	case ".c", ".cc", ".cpp", ".h", ".hpp", ".m", ".mm", ".swift", ".rs", ".go":
		return "native-source"
	case ".plist":
		return "plist"
	case ".json":
		return "json"
	case ".toml":
		return "toml"
	case ".yaml", ".yml":
		return "yaml"
	case ".xml":
		return "xml"
	case ".pbxproj":
		return "xcode-project"
	default:
		switch strings.ToLower(name) {
		case "preinstall", "postinstall", "install", "prepare":
			return "shell"
		}
		return ""
	}
}

func logicalBase(path string) string {
	path = filepath.ToSlash(path)
	if bang := strings.LastIndex(path, "!"); bang >= 0 {
		path = path[bang+1:]
	}
	return filepath.Base(path)
}
