package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Saved reports emitted by Maratus put schema_version first. Keep identity
// recognition deliberately small and bounded so a brace-leading script, a
// large JSON artifact, or an attacker-controlled string cannot make the
// artifact/report classifier consume or allocate in proportion to the input.
const (
	maxReportIdentityBytes int64 = 64 << 10
	maxReportIdentityDepth       = 64
)

type reportIdentityKind uint8

const (
	reportIdentityIndeterminate reportIdentityKind = iota
	reportIdentityCurrent
	reportIdentityUnsupported
)

type reportIdentity struct {
	kind   reportIdentityKind
	schema string
}

// sniffReportIdentity recognizes only a syntactically valid, top-level,
// canonical schema_version member whose string value is in the
// maratus.report.* namespace. It captures every byte read so a recognized
// report can be replayed into the full decoder without seeking or losing bytes
// that encoding/json buffered beyond the marker.
func sniffReportIdentity(input io.Reader) (reportIdentity, []byte, error) {
	reader := &reportIdentityReader{input: input, remaining: maxReportIdentityBytes}
	decoder := json.NewDecoder(reader)
	identity := classifyReportIdentity(decoder)
	if reader.readErr != nil {
		return reportIdentity{}, nil, fmt.Errorf("read report identity prefix: %w", reader.readErr)
	}
	return identity, reader.captured.Bytes(), nil
}

func classifyReportIdentity(decoder *json.Decoder) reportIdentity {
	first, err := decoder.Token()
	if err != nil {
		return reportIdentity{}
	}
	delim, ok := first.(json.Delim)
	if !ok || delim != '{' {
		return reportIdentity{}
	}

	depth := 1
	expectTopLevelKey := true
	schemaValue := false
	for {
		token, err := decoder.Token()
		if err != nil {
			return reportIdentity{}
		}

		if depth == 1 && expectTopLevelKey {
			if delim, ok := token.(json.Delim); ok && delim == '}' {
				return reportIdentity{}
			}
			key, ok := token.(string)
			if !ok {
				return reportIdentity{}
			}
			// Use the canonical spelling for the identity boundary. The full
			// strict decoder remains responsible for all other report fields.
			schemaValue = key == "schema_version"
			expectTopLevelKey = false
			continue
		}

		if depth == 1 {
			if schemaValue {
				if schema, ok := token.(string); ok && strings.HasPrefix(schema, "maratus.report.") {
					if schema == SchemaVersion {
						return reportIdentity{kind: reportIdentityCurrent, schema: schema}
					}
					return reportIdentity{kind: reportIdentityUnsupported, schema: schema}
				}
			}
			expectTopLevelKey = true
		}

		delim, ok := token.(json.Delim)
		if !ok {
			continue
		}
		switch delim {
		case '{', '[':
			depth++
			if depth > maxReportIdentityDepth {
				return reportIdentity{}
			}
		case '}', ']':
			depth--
			if depth <= 0 {
				return reportIdentity{}
			}
		}
	}
}

type reportIdentityReader struct {
	input     io.Reader
	remaining int64
	captured  bytes.Buffer
	readErr   error
}

func (r *reportIdentityReader) Read(buffer []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(buffer)) > r.remaining {
		buffer = buffer[:r.remaining]
	}
	read, err := r.input.Read(buffer)
	if read > 0 {
		_, _ = r.captured.Write(buffer[:read])
		r.remaining -= int64(read)
	}
	if err != nil && err != io.EOF {
		r.readErr = err
	}
	return read, err
}
