package extract

import (
	"bytes"
	"encoding/xml"
	"io"
	"path"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
)

const maxPackageInfoTokens = 256

// packagePayloadInstallPaths derives installed paths only from a real flat-PKG
// topology: a Payload entry and its same-component PackageInfo must be direct
// children of a parsed XAR package, and PackageInfo must declare an absolute
// install-location. Descendants through the Payload's gzip/CPIO representation
// may inherit the destination; recursively embedded archives may not.
func packagePayloadInstallPaths(graph artifact.Graph, contents []artifact.Content) map[string]string {
	contentByID := make(map[string]artifact.Content, len(contents))
	childrenByParent := make(map[string][]artifact.Node, len(graph.Nodes))
	for _, content := range contents {
		contentByID[content.NodeID] = content
	}
	for _, node := range graph.Nodes {
		childrenByParent[node.ParentID] = append(childrenByParent[node.ParentID], node)
	}
	result := map[string]string{}
	for _, pkg := range graph.Nodes {
		if pkg.Kind != "pkg" {
			continue
		}
		locations := map[string]string{}
		payloads := map[string]artifact.Node{}
		ambiguous := map[string]bool{}
		metadataSeen := map[string]bool{}
		payloadSeen := map[string]bool{}
		for _, node := range childrenByParent[pkg.ID] {
			if node.Provenance != "pkg-xar-entry" {
				continue
			}
			component, base, ok := packageComponentAndBase(pkg.LogicalPath, node.LogicalPath)
			if !ok {
				continue
			}
			switch strings.ToLower(base) {
			case "packageinfo":
				if metadataSeen[component] {
					ambiguous[component] = true
					continue
				}
				metadataSeen[component] = true
				if location := packageInfoInstallLocation(contentByID[node.ID].Data); location != "" {
					locations[component] = location
				}
			case "payload":
				if payloadSeen[component] {
					ambiguous[component] = true
					continue
				}
				payloadSeen[component] = true
				payloads[component] = node
			}
		}
		for component, payload := range payloads {
			if ambiguous[component] {
				continue
			}
			location := locations[component]
			if location == "" {
				continue
			}
			for _, node := range childrenByParent[payload.ID] {
				if node.Provenance == "gzip-member" {
					for _, child := range childrenByParent[node.ID] {
						derivePackagePayloadInstallPath(result, child, payload, location)
					}
					continue
				}
				derivePackagePayloadInstallPath(result, node, payload, location)
			}
		}
	}
	return result
}

func derivePackagePayloadInstallPath(result map[string]string, node, payload artifact.Node, location string) {
	if node.Provenance != "cpio-entry" {
		return
	}
	prefix := payload.LogicalPath + "!"
	if !strings.HasPrefix(node.LogicalPath, prefix) {
		return
	}
	relative := strings.TrimPrefix(node.LogicalPath, prefix)
	if relative == "" || strings.Contains(relative, "!") || strings.HasPrefix(relative, "/") || hasParentPathComponent(relative) {
		return
	}
	clean := path.Clean(relative)
	if clean == "." || strings.HasPrefix(clean, "../") {
		return
	}
	result[node.ID] = path.Join(location, clean)
}

func packageComponentAndBase(pkgLogical, childLogical string) (string, string, bool) {
	prefix := pkgLogical + "!"
	if !strings.HasPrefix(childLogical, prefix) {
		return "", "", false
	}
	relative := strings.TrimPrefix(childLogical, prefix)
	clean := path.Clean(strings.ReplaceAll(relative, "\\", "/"))
	if clean == "." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", "", false
	}
	return path.Dir(clean), path.Base(clean), true
}

func packageInfoInstallLocation(data []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	location := ""
	seenRoot := false
	depth := 0
	for tokens := 0; tokens < maxPackageInfoTokens; tokens++ {
		token, err := decoder.Token()
		if err == io.EOF {
			if seenRoot && depth == 0 {
				return location
			}
			return ""
		}
		if err != nil {
			return ""
		}
		switch value := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				if seenRoot || value.Name.Space != "" || value.Name.Local != "pkg-info" {
					return ""
				}
				seenRoot = true
				seenLocation := false
				for _, attr := range value.Attr {
					if attr.Name.Space != "" || attr.Name.Local != "install-location" {
						continue
					}
					if seenLocation {
						return ""
					}
					seenLocation = true
					candidate := strings.TrimSpace(strings.ReplaceAll(attr.Value, "\\", "/"))
					if !strings.HasPrefix(candidate, "/") || strings.ContainsRune(candidate, '\x00') || hasParentPathComponent(candidate) {
						return ""
					}
					location = path.Clean(candidate)
				}
			}
			depth++
		case xml.EndElement:
			depth--
			if depth < 0 {
				return ""
			}
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(value)) != "" {
				return ""
			}
		case xml.Directive:
			return ""
		case xml.ProcInst:
			if seenRoot && depth == 0 {
				return ""
			}
		case xml.Comment:
			if depth == 0 && seenRoot {
				// Trailing comments are valid XML and do not alter metadata.
				continue
			}
		}
	}
	return ""
}

func hasParentPathComponent(value string) bool {
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
