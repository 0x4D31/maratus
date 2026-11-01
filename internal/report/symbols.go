package report

import (
	"strconv"
	"strings"
)

func displayFunctionName(name string) string {
	if decoded := demangleItaniumFunctionName(name); decoded != "" {
		return decoded
	}
	return name
}

func demangleItaniumFunctionName(name string) string {
	encoded := strings.TrimLeft(name, "_")
	if !strings.HasPrefix(encoded, "Z") {
		return ""
	}
	encoded = strings.TrimPrefix(encoded, "Z")
	if encoded == "" {
		return ""
	}
	var parts []string
	var rest string
	if strings.HasPrefix(encoded, "N") {
		parts, rest = parseNestedItaniumName(encoded[1:])
	} else {
		part, next, ok := parseItaniumNamePart(encoded)
		if !ok {
			return ""
		}
		parts = []string{part}
		rest = next
	}
	if len(parts) == 0 {
		return ""
	}
	suffix := "(...)"
	if rest == "" || rest == "v" {
		suffix = "()"
	}
	return strings.Join(parts, "::") + suffix
}

func parseNestedItaniumName(value string) ([]string, string) {
	var parts []string
	for value != "" && value[0] != 'E' {
		part, rest, ok := parseItaniumNamePart(value)
		if !ok {
			return nil, ""
		}
		parts = append(parts, part)
		value = rest
	}
	if value == "" || value[0] != 'E' {
		return nil, ""
	}
	return parts, value[1:]
}

func parseItaniumNamePart(value string) (string, string, bool) {
	i := 0
	for i < len(value) && value[i] >= '0' && value[i] <= '9' {
		i++
	}
	if i == 0 {
		return "", "", false
	}
	size, err := strconv.Atoi(value[:i])
	if err != nil || size <= 0 || i+size > len(value) {
		return "", "", false
	}
	part := value[i : i+size]
	if !readableSymbolPart(part) {
		return "", "", false
	}
	return part, value[i+size:], true
}

func readableSymbolPart(value string) bool {
	for _, r := range value {
		if r == '_' || r == '$' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			continue
		}
		return false
	}
	return true
}
