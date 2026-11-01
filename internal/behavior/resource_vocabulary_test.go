package behavior

import (
	"reflect"
	"sort"
	"testing"
)

func TestResourceVocabulariesAreClosedSortedAndIndependent(t *testing.T) {
	tests := []struct {
		name   string
		values []string
	}{
		{name: "kinds", values: resourceKindStrings(ResourceKinds())},
		{name: "classifications", values: resourceClassificationStrings(ResourceClassifications())},
		{name: "roles", values: resourceRoleStrings(ResourceRoles())},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := append([]string(nil), test.values...)
			sort.Strings(want)
			if !reflect.DeepEqual(test.values, want) {
				t.Fatalf("vocabulary is not sorted: got %q want %q", test.values, want)
			}
			for index := 1; index < len(test.values); index++ {
				if test.values[index] == test.values[index-1] {
					t.Fatalf("duplicate vocabulary value %q", test.values[index])
				}
			}
			test.values[0] = "mutated"
		})
	}
	if ResourceKinds()[0] == "mutated" || ResourceClassifications()[0] == "mutated" || ResourceRoles()[0] == "mutated" {
		t.Fatal("returned vocabulary aliases authoritative storage")
	}
}

func TestEveryOperationKindHasAValidResourcePolicy(t *testing.T) {
	for _, operationKind := range OperationKinds() {
		policy := OperationResourcePolicy(operationKind)
		if len(policy) == 0 {
			t.Fatalf("operation %q has no resource policy", operationKind)
		}
		required := 0
		previous := ResourceRole("")
		for _, item := range policy {
			if !ValidResourceRole(item.Role) {
				t.Fatalf("operation %q has unknown role %q", operationKind, item.Role)
			}
			if previous != "" && previous >= item.Role {
				t.Fatalf("operation %q policy is not sorted or has a duplicate role: %#v", operationKind, policy)
			}
			previous = item.Role
			if item.Required {
				required++
			}
			if len(item.Kinds) == 0 {
				t.Fatalf("operation %q role %q has no allowed kinds", operationKind, item.Role)
			}
			for _, resourceKind := range item.Kinds {
				if !ValidResourceKind(resourceKind) || !ValidOperationResourceRole(operationKind, item.Role, resourceKind) {
					t.Fatalf("operation %q role %q has invalid kind %q", operationKind, item.Role, resourceKind)
				}
			}
			item.Kinds[0] = "mutated"
		}
		if required == 0 {
			t.Fatalf("operation %q has no required resource role", operationKind)
		}
		if OperationResourcePolicy(operationKind)[0].Kinds[0] == "mutated" {
			t.Fatalf("operation %q policy aliases authoritative storage", operationKind)
		}
	}
}

func TestResourceClassificationDoesNotReplacePhysicalKind(t *testing.T) {
	if !ValidResourceClassificationForKind(ResourceFile, ResourceClassBrowserCookieStore) {
		t.Fatal("browser cookie store should classify a file")
	}
	if ValidResourceClassificationForKind(ResourceCredentialStore, ResourceClassBrowserCookieStore) {
		t.Fatal("browser cookie store classification changed physical kind")
	}
	if !ValidResourceClassificationForKind(ResourceCredentialStore, ResourceClassKeychain) {
		t.Fatal("keychain should classify a credential store")
	}
	if !ValidResourceClassificationForKind(ResourceFile, ResourceClassKeychain) {
		t.Fatal("keychain database should also classify a physical file")
	}
	if ValidResourceClassification("arbitrary") || ValidResourceKind("arbitrary") || ValidResourceRole("arbitrary") {
		t.Fatal("unknown vocabulary value was accepted")
	}
	kinds := ResourceClassificationKinds(ResourceClassKeychain)
	if !reflect.DeepEqual(kinds, []ResourceKind{ResourceCredentialStore, ResourceFile}) {
		t.Fatalf("keychain physical kinds = %#v", kinds)
	}
	kinds[0] = "mutated"
	if ResourceClassificationKinds(ResourceClassKeychain)[0] == "mutated" {
		t.Fatal("classification kinds alias authoritative storage")
	}
	if ResourceClassificationKinds("arbitrary") != nil {
		t.Fatal("unknown classification returned physical kinds")
	}
}

func TestOperationResourceCompatibilityCloseNegatives(t *testing.T) {
	if !ValidOperationResourceRole(OperationNetworkDownload, ResourceRoleRemoteSource, ResourceURL) {
		t.Fatal("download remote URL should be accepted")
	}
	if ValidOperationResourceRole(OperationNetworkDownload, ResourceRoleRemoteSource, ResourceFile) {
		t.Fatal("download remote source must not accept a file")
	}
	if ValidOperationResourceRole(OperationProcessExecute, ResourceRoleRemoteSource, ResourceURL) {
		t.Fatal("process execution must not accept a network source")
	}
	if !ValidOperationResourceRole(OperationProcessTaskAccess, ResourceRoleTargetProcess, ResourceProcess) {
		t.Fatal("task access must accept a target process")
	}
	if ValidOperationResourceRole(OperationProcessTaskAccess, ResourceRoleTargetMemory, ResourceProcessMemory) {
		t.Fatal("task access must not claim a process-memory target")
	}
	if !ValidOperationResourceRole(OperationProcessThreadCreate, ResourceRoleTargetProcess, ResourceProcess) {
		t.Fatal("thread creation must accept a target process")
	}
	if ValidOperationResourceRole(OperationProcessThreadCreate, ResourceRoleTargetMemory, ResourceProcessMemory) {
		t.Fatal("thread creation must not imply a memory access")
	}
	if ValidOperationResourceRole("arbitrary", ResourceRoleTarget, ResourceFile) {
		t.Fatal("unknown operation kind was accepted")
	}
}

func resourceKindStrings(values []ResourceKind) []string {
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = string(value)
	}
	return out
}

func resourceClassificationStrings(values []ResourceClassification) []string {
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = string(value)
	}
	return out
}

func resourceRoleStrings(values []ResourceRole) []string {
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = string(value)
	}
	return out
}
