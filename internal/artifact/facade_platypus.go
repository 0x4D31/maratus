package artifact

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/0x4D31/maratus/internal/plistx"
)

const (
	maxPlatypusArguments          = 256
	maxPlatypusArgumentBytes      = 16 << 10
	maxPlatypusArgumentTotalBytes = 64 << 10
)

type platypusInvocationDescriptor struct {
	interpreter     string
	interpreterArgs []string
	scriptArgs      []string
	evidence        []LocatedArtifactEvidence
}

func looksLikePlatypusSettings(data []byte) bool {
	_, _, ok := platypusSettingsValues(data)
	return ok
}

// platypusSettingsEvidence requires decoded producer and interpreter fields,
// then locates the exact decoded values in the retained plist bytes. This
// preserves the semantic plist check while giving the public packaging fact
// concrete byte provenance for XML and ordinary binary plists.
func platypusSettingsEvidence(data []byte) ([]LocatedArtifactEvidence, bool) {
	creator, interpreter, ok := platypusSettingsValues(data)
	if !ok {
		return nil, false
	}
	creatorOffset := bytes.Index(data, []byte(creator))
	interpreterOffset := bytes.Index(data, []byte(interpreter))
	if creatorOffset < 0 || interpreterOffset < 0 {
		return nil, false
	}
	return []LocatedArtifactEvidence{
		{Offset: int64(creatorOffset), Kind: "platypus-creator", Value: creator},
		{Offset: int64(interpreterOffset), Kind: "platypus-interpreter", Value: interpreter},
	}, true
}

func platypusSettingsValues(data []byte) (string, string, bool) {
	dict, err := plistx.Decode(data)
	if err != nil {
		return "", "", false
	}
	creator := strings.TrimSpace(plistx.String(dict, "Creator"))
	interpreter := strings.TrimSpace(plistx.String(dict, "ScriptInterpreter"))
	lowerCreator := strings.ToLower(creator)
	if interpreter == "" || creator == "" || lowerCreator != "platypus" && !strings.HasPrefix(lowerCreator, "platypus-") {
		return "", "", false
	}
	return creator, interpreter, true
}

func platypusInvocation(data []byte) (platypusInvocationDescriptor, bool) {
	settingsEvidence, ok := platypusSettingsEvidence(data)
	if !ok {
		return platypusInvocationDescriptor{}, false
	}
	dict, err := plistx.Decode(data)
	if err != nil {
		return platypusInvocationDescriptor{}, false
	}
	interpreterArgs, ok := platypusStringArray(dict, "InterpreterArgs")
	if !ok {
		return platypusInvocationDescriptor{}, false
	}
	scriptArgs, ok := platypusStringArray(dict, "ScriptArgs")
	if !ok {
		return platypusInvocationDescriptor{}, false
	}
	evidence := append([]LocatedArtifactEvidence(nil), settingsEvidence...)
	for _, item := range []struct {
		key  string
		kind string
		args []string
	}{
		{key: "InterpreterArgs", kind: "platypus-interpreter-args", args: interpreterArgs},
		{key: "ScriptArgs", kind: "platypus-script-args", args: scriptArgs},
	} {
		if _, present := dict[item.key]; !present {
			continue
		}
		offset := bytes.Index(data, []byte(item.key))
		if offset < 0 {
			return platypusInvocationDescriptor{}, false
		}
		evidence = append(evidence, LocatedArtifactEvidence{Offset: int64(offset), Kind: item.kind, Value: fmt.Sprintf("%q", item.args)})
	}
	return platypusInvocationDescriptor{
		interpreter:     strings.TrimSpace(plistx.String(dict, "ScriptInterpreter")),
		interpreterArgs: interpreterArgs,
		scriptArgs:      scriptArgs,
		evidence:        evidence,
	}, true
}

func platypusStringArray(dict plistx.Dict, key string) ([]string, bool) {
	value, exists := dict[key]
	if !exists {
		// Older/minimal Platypus settings omit empty argument arrays. Their
		// absence is an exact empty argv, while a present mistyped value remains
		// unsupported and prevents host-selection metadata.
		return nil, true
	}
	items, ok := value.([]any)
	if !ok || len(items) > maxPlatypusArguments {
		return nil, false
	}
	out := make([]string, 0, len(items))
	total := 0
	for _, item := range items {
		argument, ok := item.(string)
		if !ok || len(argument) > maxPlatypusArgumentBytes || len(argument) > maxPlatypusArgumentTotalBytes-total {
			return nil, false
		}
		total += len(argument)
		out = append(out, argument)
	}
	return out, true
}
