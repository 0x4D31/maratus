package behavior

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvidenceJSONDistinguishesZeroAndUnknownByteOffsets(t *testing.T) {
	tests := []struct {
		name        string
		evidence    Evidence
		wantPresent bool
	}{
		{name: "unknown", evidence: Evidence{ID: "ev-1", Method: "source", Kind: "match"}},
		{name: "known zero", evidence: Evidence{ID: "ev-1", OffsetKnown: true, Method: "source", Kind: "match"}, wantPresent: true},
		{name: "legacy non-zero", evidence: Evidence{ID: "ev-1", Offset: 42, Method: "source", Kind: "match"}, wantPresent: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(test.evidence)
			if err != nil {
				t.Fatal(err)
			}
			present := strings.Contains(string(data), `"byte_offset"`)
			if present != test.wantPresent {
				t.Fatalf("byte_offset presence = %v, want %v: %s", present, test.wantPresent, data)
			}
		})
	}
}

func TestEvidenceJSONPreservesByteOffsetPresenceAcrossRewrite(t *testing.T) {
	for _, input := range []string{
		`{"id":"ev-1","extraction_method":"source","kind":"match"}`,
		`{"id":"ev-1","byte_offset":0,"extraction_method":"source","kind":"match"}`,
	} {
		var evidence Evidence
		if err := json.Unmarshal([]byte(input), &evidence); err != nil {
			t.Fatal(err)
		}
		output, err := json.Marshal(evidence)
		if err != nil {
			t.Fatal(err)
		}
		wantPresent := strings.Contains(input, `"byte_offset"`)
		gotPresent := strings.Contains(string(output), `"byte_offset"`)
		if gotPresent != wantPresent {
			t.Fatalf("byte_offset presence changed: input=%s output=%s", input, output)
		}
		if wantPresent && (!evidence.ByteOffsetKnown() || evidence.Offset != 0) {
			t.Fatalf("known byte zero was not retained: %#v", evidence)
		}
	}
}

func TestEvidenceJSONDoesNotEscapeHTMLSentinels(t *testing.T) {
	data, err := (Evidence{Method: "source", Kind: "match", Value: "<tag>&"}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `\u003c`) || !strings.Contains(string(data), `<tag>&`) {
		t.Fatalf("evidence JSON unexpectedly escaped HTML sentinels: %s", data)
	}
}

func TestSupportVocabularyIsClosedAndIndependent(t *testing.T) {
	values := SupportValues()
	if len(values) != 3 || values[0] != SupportDirect || values[1] != SupportCorroborated || values[2] != SupportHeuristic {
		t.Fatalf("support vocabulary = %#v", values)
	}
	for _, value := range values {
		if !value.Valid() {
			t.Fatalf("declared support %q is invalid", value)
		}
	}
	values[0] = "mutated"
	if SupportValues()[0] == "mutated" {
		t.Fatal("support vocabulary aliases authoritative storage")
	}
}
