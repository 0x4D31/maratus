package shellparse

// FieldsWithRaw retains spelling as well as decoded argv. Shell grammar words
// and assignment names are recognized before quote removal, unlike executable
// names and ordinary arguments.
func FieldsWithRaw(command string) ([]string, []string, error) {
	fields, err := Fields(command)
	if err != nil {
		return nil, nil, err
	}
	raw := make([]string, 0, len(fields))
	start := -1
	var quote byte
	escaped := false
	for i := 0; i < len(command); i++ {
		ch := command[i]
		if start < 0 && (ch == ' ' || ch == '\t' || ch == '\n') {
			continue
		}
		if start < 0 {
			start = i
		}
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		if ch == ' ' || ch == '\t' || ch == '\n' {
			// A continuation by itself produces no field.
			if onlyContinuations(command[start:i]) {
				start = -1
				continue
			}
			raw = append(raw, command[start:i])
			start = -1
		}
	}
	if start >= 0 && !onlyContinuations(command[start:]) {
		raw = append(raw, command[start:])
	}
	return fields, raw, nil
}

func onlyContinuations(value string) bool {
	for len(value) >= 2 && value[:2] == "\\\n" {
		value = value[2:]
	}
	return value == ""
}
