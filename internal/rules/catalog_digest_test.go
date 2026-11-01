package rules

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestCatalogDigestIsStableAcrossSemanticallyIrrelevantOrder(t *testing.T) {
	first, err := catalogDigest(digestFixtureSpecs(false))
	if err != nil {
		t.Fatal(err)
	}
	second, err := catalogDigest(digestFixtureSpecs(true))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("semantic catalog digest depends on set or declaration order: %s != %s", first, second)
	}
	if !ValidCatalogDigest(first) || !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+sha256HexLength {
		t.Fatalf("catalog digest format = %q", first)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(first, "sha256:")); err != nil {
		t.Fatalf("catalog digest is not hexadecimal: %v", err)
	}
}

func TestValidCatalogDigestRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{"", "sha256:", "sha256:not-hex", "md5:00000000000000000000000000000000", "sha256:" + strings.Repeat("0", 63), "sha256:" + strings.Repeat("g", 64)} {
		if ValidCatalogDigest(value) {
			t.Fatalf("accepted malformed catalog digest %q", value)
		}
	}
}

func TestCatalogDigestChangesWithSemanticRuleContent(t *testing.T) {
	base := digestFixtureSpecs(false)
	first, err := catalogDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	base[0].Metadata.Description += " Changed."
	second, err := catalogDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("catalog digest ignored a metadata semantic change")
	}

	flow := digestFlowSpec(false)
	forward, err := catalogDigest([]Spec{flow})
	if err != nil {
		t.Fatal(err)
	}
	reverse := digestFlowSpec(true)
	backward, err := catalogDigest([]Spec{reverse})
	if err != nil {
		t.Fatal(err)
	}
	if forward == backward {
		t.Fatal("catalog digest ignored meaningful resource-flow step order")
	}
}

func TestCatalogDigestRejectsInvalidCatalog(t *testing.T) {
	if _, err := catalogDigest([]Spec{{Kind: CapabilityRule}}); err == nil || !strings.Contains(err.Error(), "RULE_") {
		t.Fatalf("invalid catalog digest error = %v", err)
	}
}

const sha256HexLength = 64

func digestFixtureSpecs(reversed bool) []Spec {
	firstAlternative := Operation(behavior.OperationClipboardRead)
	secondAlternative := Operation(behavior.OperationScreenCapture, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceScreen))
	rootNames := []string{"install", "postinstall"}
	eachConstraints := []EachConstraint{SameContext(), SharedEvidence()}
	attack := []string{"T1115", "T1113", "T1115"}
	if reversed {
		firstAlternative, secondAlternative = secondAlternative, firstAlternative
		rootNames[0], rootNames[1] = rootNames[1], rootNames[0]
		eachConstraints[0], eachConstraints[1] = eachConstraints[1], eachConstraints[0]
		attack[0], attack[1] = attack[1], attack[0]
	}
	first := Spec{
		Metadata: Metadata{ID: "test.capture", Title: "Capture", Namespace: "test", Description: "Captures input.", Attack: attack},
		Kind:     CapabilityRule, Match: Any(firstAlternative, secondAlternative), MinimumSupport: behavior.SupportCorroborated,
	}
	second := Spec{
		Metadata: Metadata{ID: "test.native", Title: "Native", Namespace: "test", Description: "Uses exact native evidence."},
		Kind:     CapabilityRule,
		Match: Each(
			Operation(behavior.OperationProcessExecute, ResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)),
			Feature("macho.import_call"),
			eachConstraints...,
		),
		MinimumSupport: behavior.SupportCorroborated,
	}
	third := Spec{
		Metadata: Metadata{ID: "library.lifecycle", Title: "Lifecycle", Namespace: "library", Description: "Selects lifecycle roots."},
		Kind:     LibraryRule, Match: ExecutionRoot("npm-script", rootNames...), MinimumSupport: behavior.SupportCorroborated,
	}
	if reversed {
		return []Spec{third, second, first}
	}
	return []Spec{first, second, third}
}

func digestFlowSpec(reverse bool) Spec {
	download := FlowStep(Operation(behavior.OperationNetworkDownload, ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)), behavior.ResourceRoleLocalOutput)
	execute := FlowStep(Operation(behavior.OperationProcessExecute, ResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)), behavior.ResourceRoleExecutable)
	steps := []ResourceFlowStep{download, execute}
	if reverse {
		steps[0], steps[1] = steps[1], steps[0]
	}
	return Spec{
		Metadata: Metadata{ID: "test.flow", Title: "Flow", Namespace: "test", Description: "Tracks one resource flow."},
		Kind:     CapabilityRule, Match: ResourceFlow(steps...), MinimumSupport: behavior.SupportCorroborated,
	}
}
