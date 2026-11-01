package rules

import (
	"slices"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestReferencedFeatureKeysComeFromTypedCatalog(t *testing.T) {
	got := ReferencedFeatureKeys()
	for _, key := range []string{"macho.import_call", "objc.message_call"} {
		if !slices.Contains(got, key) {
			t.Fatalf("typed catalog Feature keys = %#v, missing %q", got, key)
		}
	}
	if !slices.IsSorted(got) {
		t.Fatalf("typed catalog Feature keys are not deterministic: %#v", got)
	}
}

func TestCapabilityCatalogCoversEveryPublicOperationExceptConfigurationOnlyState(t *testing.T) {
	referenced := ReferencedOperationKinds()
	if !slices.IsSorted(referenced) {
		t.Fatalf("typed catalog operation kinds are not deterministic: %#v", referenced)
	}
	for _, kind := range behavior.OperationKinds() {
		if kind == behavior.OperationProcessLaunchConfigure {
			// Configuration alone is intentionally visible as modeled behavior
			// but cannot become a public capability until an execution method is
			// proven on the exact configured process object.
			continue
		}
		if !slices.Contains(referenced, kind) {
			t.Fatalf("operation %q has no capability-rule projection or documented exclusion", kind)
		}
	}
}
