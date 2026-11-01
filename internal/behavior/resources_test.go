package behavior

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeResourceBindingsSupportsMultipleRolesAndMergesDuplicates(t *testing.T) {
	bindings, err := NormalizeResourceBindings(OperationNetworkDownload, []ResourceBinding{
		Bind(ResourceRoleRemoteSource, NewResource(ResourceURL, "https://example.invalid/payload"), "ev-2"),
		Bind(ResourceRoleLocalOutput, NewResource(ResourceFile, "/tmp/payload", ResourceClassArchive), "ev-3"),
		Bind(ResourceRoleRemoteSource, NewResource(ResourceURL, "https://example.invalid/payload"), "ev-1", "ev-2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []ResourceBinding{
		Bind(ResourceRoleLocalOutput, NewResource(ResourceFile, "/tmp/payload", ResourceClassArchive), "ev-3"),
		Bind(ResourceRoleRemoteSource, NewResource(ResourceURL, "https://example.invalid/payload"), "ev-1", "ev-2"),
	}
	if !reflect.DeepEqual(bindings, want) {
		t.Fatalf("normalized bindings = %#v, want %#v", bindings, want)
	}
}

func TestNormalizeResourceBindingsRejectsInvalidAndMissingRoles(t *testing.T) {
	tests := []struct {
		name     string
		kind     OperationKind
		bindings []ResourceBinding
		want     string
	}{
		{name: "none", kind: OperationProcessExecute, want: "requires resource bindings"},
		{name: "missing required", kind: OperationNetworkDownload, bindings: Bindings(Bind(ResourceRoleLocalOutput, NewResource(ResourceFile, "/tmp/p"))), want: "requires resource role \"remote_source\""},
		{name: "wrong role kind", kind: OperationNetworkDownload, bindings: Bindings(Bind(ResourceRoleRemoteSource, NewResource(ResourceFile, "/tmp/p"))), want: "incompatible"},
		{name: "unknown kind", kind: OperationProcessExecute, bindings: Bindings(Bind(ResourceRoleExecutable, NewResource("arbitrary", ""))), want: "invalid resource kind"},
		{name: "classification kind", kind: OperationProcessExecute, bindings: Bindings(Bind(ResourceRoleExecutable, NewResource(ResourceFile, "", ResourceClassKeychain)), Bind(ResourceRoleExecutable, NewResource(ResourceFile, "", ResourceClassLaunchAgent))), want: "classification \"launch-agent\" is incompatible"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizeResourceBindings(test.kind, test.bindings)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestNormalizeResourceBindingsBoundsHostileCardinalityBeforeWork(t *testing.T) {
	bindings := make([]ResourceBinding, MaxOperationResourceBindings+1)
	for index := range bindings {
		bindings[index] = Bind(ResourceRoleExecutable, NewResource(ResourceFile, strings.Repeat("x", 1024)))
	}
	_, err := NormalizeResourceBindings(OperationProcessExecute, bindings)
	if err == nil || !strings.Contains(err.Error(), "limit is") {
		t.Fatalf("hostile binding cardinality was accepted: %v", err)
	}
}

func TestNormalizeResourceBindingsBoundsNestedCollectionsBeforeSorting(t *testing.T) {
	classifications := make([]ResourceClassification, MaxResourceClassifications+1)
	for index := range classifications {
		classifications[index] = ResourceClassArchive
	}
	_, err := NormalizeResourceBindings(OperationProcessExecute, Bindings(
		Bind(ResourceRoleExecutable, NewResource(ResourceFile, "", classifications...)),
	))
	if err == nil || !strings.Contains(err.Error(), "classifications; limit is") {
		t.Fatalf("hostile classification cardinality was accepted: %v", err)
	}

	evidenceIDs := make([]string, MaxResourceBindingEvidenceIDs+1)
	for index := range evidenceIDs {
		evidenceIDs[index] = "ev"
	}
	_, err = NormalizeResourceBindings(OperationProcessExecute, Bindings(
		Bind(ResourceRoleExecutable, NewResource(ResourceFile, ""), evidenceIDs...),
	))
	if err == nil || !strings.Contains(err.Error(), "evidence_ids") {
		t.Fatalf("hostile binding-evidence cardinality was accepted: %v", err)
	}
}

func TestResourceKeyDoesNotHaveDelimiterCollisions(t *testing.T) {
	left := NewResource(ResourceFile, "a:b", ResourceClassArchive)
	right := NewResource(ResourceFile, "a", ResourceClassification("b:archive"))
	if left.Key() == right.Key() {
		t.Fatalf("distinct resources share key %q", left.Key())
	}
}

func TestResourceIdentitySeparatesPhysicalIdentityFromClassification(t *testing.T) {
	plain := NewResource(ResourceFile, "/tmp/payload")
	classified := NewResource(ResourceFile, "/tmp/payload", ResourceClassArchive)
	if plain.IdentityKey() != classified.IdentityKey() {
		t.Fatal("classification changed physical resource identity")
	}
	if plain.Key() == classified.Key() {
		t.Fatal("semantic resource descriptors collapsed distinct classifications")
	}
	otherKind := NewResource(ResourceCommand, "/tmp/payload")
	if plain.IdentityKey() == otherKind.IdentityKey() {
		t.Fatal("physical resource identity ignored kind")
	}
}

func TestResourceCorrelationKeyUsesConservativeFileEquivalence(t *testing.T) {
	tests := []struct {
		name  string
		left  string
		right string
		same  bool
	}{
		{name: "leading current directory", left: "./payload", right: "payload", same: true},
		{name: "interior current directory", left: "/tmp/./payload", right: "/tmp/payload", same: true},
		{name: "duplicate separator", left: "/tmp//payload", right: "/tmp/payload", same: true},
		{name: "parent traversal", left: "/tmp/stage/../payload", right: "/tmp/payload"},
		{name: "trailing separator", left: "/tmp/payload/", right: "/tmp/payload"},
		{name: "double leading separator", left: "//tmp/payload", right: "/tmp/payload"},
		{name: "backslash is not a macOS separator", left: `tmp\payload`, right: "tmp/payload"},
		{name: "trailing space", left: "/tmp/payload ", right: "/tmp/payload"},
		{name: "leading space", left: " payload", right: "payload"},
		{name: "literal double quote", left: `/tmp/payload"`, right: "/tmp/payload"},
		{name: "literal single quote", left: "/tmp/payload'", right: "/tmp/payload"},
		{name: "quoted filename", left: `"payload"`, right: "payload"},
		{name: "literal whitespace filename", left: " ", right: "\t"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left, leftOK := NewResource(ResourceFile, test.left).CorrelationKey()
			right, rightOK := NewResource(ResourceFile, test.right).CorrelationKey()
			if !leftOK || !rightOK || (left == right) != test.same {
				t.Fatalf("CorrelationKey(%q, %q) = (%q, %q), want same=%v", test.left, test.right, left, right, test.same)
			}
		})
	}
}

func TestResourceCorrelationKeyRejectsUnknownValue(t *testing.T) {
	if _, ok := NewResource(ResourceFile, "").CorrelationKey(); ok {
		t.Fatal("unknown resource value was treated as correlatable")
	}
}

func TestResourceUnresolvedDistinguishesSingletonKindsFromUnknownIdentities(t *testing.T) {
	for _, kind := range []ResourceKind{ResourceAudioInput, ResourceCamera, ResourceClipboard, ResourceInputEventStream, ResourceScreen} {
		if NewResource(kind, "").Unresolved() {
			t.Errorf("singleton resource %q was labeled unresolved", kind)
		}
	}
	for _, kind := range []ResourceKind{ResourceFile, ResourceProcess, ResourceURL, ResourceCredentialStore, ResourcePasteboard} {
		if !NewResource(kind, "").Unresolved() {
			t.Errorf("identity-bearing resource %q was labeled resolved without a value", kind)
		}
	}
	if NewResource(ResourceFile, "/tmp/item").Unresolved() {
		t.Fatal("concrete resource was labeled unresolved")
	}
}
