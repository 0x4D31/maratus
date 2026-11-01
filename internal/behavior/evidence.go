package behavior

import (
	"bytes"
	"encoding/json"
)

type Support string

const (
	SupportDirect       Support = "DIRECT"
	SupportCorroborated Support = "CORROBORATED"
	SupportHeuristic    Support = "HEURISTIC"
)

var supportValues = [...]Support{
	SupportDirect,
	SupportCorroborated,
	SupportHeuristic,
}

// SupportValues returns the closed support vocabulary from strongest to
// weakest. The returned slice cannot mutate the authoritative list.
func SupportValues() []Support {
	return append([]Support(nil), supportValues[:]...)
}

func (support Support) Valid() bool {
	switch support {
	case SupportDirect, SupportCorroborated, SupportHeuristic:
		return true
	default:
		return false
	}
}

type Evidence struct {
	ID       string `json:"id"`
	NodeID   string `json:"node_id,omitempty"`
	ScopeID  string `json:"scope_id,omitempty"`
	Logical  string `json:"logical_path,omitempty"`
	Physical string `json:"physical_path,omitempty"`
	Line     int    `json:"line,omitempty"`
	Offset   int64  `json:"-"`
	// OffsetKnown distinguishes a byte offset of zero from an unknown offset.
	// It is represented by the presence of byte_offset in JSON rather than as a
	// separate schema field.
	OffsetKnown bool   `json:"-"`
	VA          uint64 `json:"virtual_address,omitempty"`
	Function    string `json:"function,omitempty"`
	Arch        string `json:"architecture,omitempty"`
	Method      string `json:"extraction_method"`
	Kind        string `json:"kind"`
	Value       string `json:"matched_value,omitempty"`
}

// ByteOffsetKnown reports whether Offset identifies a location in the source.
// Non-zero offsets remain known for compatibility with callers that predate
// OffsetKnown.
func (e Evidence) ByteOffsetKnown() bool {
	return e.OffsetKnown || e.Offset != 0
}

// MarshalJSON preserves the semantic difference between an unknown byte
// offset (field absent) and the first byte in a source (byte_offset: 0).
func (e Evidence) MarshalJSON() ([]byte, error) {
	type evidenceJSON Evidence
	encoded := struct {
		evidenceJSON
		ByteOffset *int64 `json:"byte_offset,omitempty"`
	}{
		evidenceJSON: evidenceJSON(e),
	}
	if e.ByteOffsetKnown() {
		offset := e.Offset
		encoded.ByteOffset = &offset
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(encoded); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}

// UnmarshalJSON records byte_offset presence so load-and-rewrite operations do
// not turn an unknown offset into zero or lose a known offset at byte zero.
func (e *Evidence) UnmarshalJSON(data []byte) error {
	type evidenceJSON Evidence
	decoded := struct {
		evidenceJSON
		ByteOffset *int64 `json:"byte_offset"`
	}{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*e = Evidence(decoded.evidenceJSON)
	if decoded.ByteOffset != nil {
		e.Offset = *decoded.ByteOffset
		e.OffsetKnown = true
	}
	return nil
}

type Resource struct {
	Kind            ResourceKind             `json:"kind"`
	Value           string                   `json:"value,omitempty"`
	Classifications []ResourceClassification `json:"classifications,omitempty"`
}
