package behavior

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	MaxOperationResourceBindings  = 16
	MaxResourceClassifications    = 16
	MaxResourceBindingEvidenceIDs = 64
)

// NewResource constructs a physical resource with optional semantic
// classifications. Graph insertion performs authoritative validation and
// normalization.
func NewResource(kind ResourceKind, value string, classifications ...ResourceClassification) Resource {
	return Resource{Kind: kind, Value: value, Classifications: append([]ResourceClassification(nil), classifications...)}
}

// Bind constructs an evidenced operation/resource association. Evidence may
// be omitted when the operation evidence supports the complete binding.
func Bind(role ResourceRole, resource Resource, evidenceIDs ...string) ResourceBinding {
	return ResourceBinding{Role: role, Resource: resource, EvidenceIDs: append([]string(nil), evidenceIDs...)}
}

// Bindings is a concise constructor for operation literals. It always returns
// independent storage.
func Bindings(bindings ...ResourceBinding) []ResourceBinding {
	return append([]ResourceBinding(nil), bindings...)
}

func (resource Resource) HasClassification(classification ResourceClassification) bool {
	for _, candidate := range resource.Classifications {
		if candidate == classification {
			return true
		}
	}
	return false
}

// Unresolved reports whether a resource still needs a concrete value to name
// the affected object. A small closed set of singleton capability resources is
// fully identified by its physical kind; presenting an empty screen or
// clipboard value as an unknown argument creates a false analysis gap.
func (resource Resource) Unresolved() bool {
	if resource.Value != "" {
		return false
	}
	switch resource.Kind {
	case ResourceAudioInput, ResourceCamera, ResourceClipboard, ResourceInputEventStream, ResourceScreen:
		return false
	default:
		return true
	}
}

// ResourceIdentityKey identifies a physical resource by kind and value. A
// semantic classification does not make the underlying file, process, or URL
// a different resource. Unknown empty values must not be joined merely because
// they share this key.
type ResourceIdentityKey string

func (resource Resource) IdentityKey() ResourceIdentityKey {
	var builder strings.Builder
	appendResourceKeyPart(&builder, string(resource.Kind))
	appendResourceKeyPart(&builder, resource.Value)
	return ResourceIdentityKey(builder.String())
}

// CorrelationKey returns the conservative physical identity used when static
// facts need to prove that two bindings refer to the same resource. It is
// deliberately stricter than filesystem path cleaning: parent traversal,
// trailing separators, implementation-defined double-leading separators, and
// backslashes remain distinct because resolving them without runtime filesystem
// state could overclaim equivalence.
func (resource Resource) CorrelationKey() (ResourceIdentityKey, bool) {
	// Resource values have already been decoded by their semantic adapter.
	// Quotes and surrounding whitespace can be literal filename bytes, so
	// stripping them here would join distinct physical resources.
	value := resource.Value
	if resource.Kind == "" || value == "" {
		return "", false
	}
	if resource.Kind == ResourceFile {
		value = conservativeFileCorrelationValue(value)
	}
	return NewResource(resource.Kind, value).IdentityKey(), true
}

func conservativeFileCorrelationValue(value string) string {
	if strings.HasPrefix(value, "//") || value != "/" && strings.HasSuffix(value, "/") {
		return value
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if part == ".." {
			return value
		}
	}
	rooted := strings.HasPrefix(value, "/")
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		cleaned = append(cleaned, part)
	}
	result := strings.Join(cleaned, "/")
	if rooted {
		result = "/" + result
	}
	if result == "" && rooted {
		return "/"
	}
	return result
}

// ResourceKey is a collision-resistant semantic descriptor key used for
// deduplication and deterministic ordering. It includes classifications and is
// deliberately opaque: callers must not parse it or expose it in reports.
type ResourceKey string

func (resource Resource) Key() ResourceKey {
	var builder strings.Builder
	appendResourceKeyPart(&builder, string(resource.IdentityKey()))
	for _, classification := range resource.Classifications {
		appendResourceKeyPart(&builder, string(classification))
	}
	return ResourceKey(builder.String())
}

func appendResourceKeyPart(builder *strings.Builder, value string) {
	builder.WriteString(strconv.Itoa(len(value)))
	builder.WriteByte(':')
	builder.WriteString(value)
}

func (operation ModeledOperation) FirstBinding(role ResourceRole) (ResourceBinding, bool) {
	for _, binding := range operation.ResourceBindings {
		if binding.Role == role {
			return binding, true
		}
	}
	return ResourceBinding{}, false
}

// RequiredResource returns the first binding for the operation's first
// required role. It is a convenience for primitive consumers; multi-resource
// reasoning should name roles explicitly.
func (operation ModeledOperation) RequiredResource() Resource {
	for _, policy := range OperationResourcePolicy(operation.Kind) {
		if !policy.Required {
			continue
		}
		if binding, ok := operation.FirstBinding(policy.Role); ok {
			return binding.Resource
		}
	}
	return Resource{}
}

func NormalizeResource(resource Resource) (Resource, error) {
	if !ValidResourceKind(resource.Kind) {
		return Resource{}, fmt.Errorf("invalid resource kind %q", resource.Kind)
	}
	if len(resource.Classifications) > MaxResourceClassifications {
		return Resource{}, fmt.Errorf("resource has %d classifications; limit is %d", len(resource.Classifications), MaxResourceClassifications)
	}
	resource.Classifications = append([]ResourceClassification(nil), resource.Classifications...)
	sort.Slice(resource.Classifications, func(i, j int) bool { return resource.Classifications[i] < resource.Classifications[j] })
	out := resource.Classifications[:0]
	for _, classification := range resource.Classifications {
		if !ValidResourceClassificationForKind(resource.Kind, classification) {
			return Resource{}, fmt.Errorf("classification %q is incompatible with resource kind %q", classification, resource.Kind)
		}
		if len(out) == 0 || out[len(out)-1] != classification {
			out = append(out, classification)
		}
	}
	resource.Classifications = out
	return resource, nil
}

func NormalizeResourceBindings(kind OperationKind, bindings []ResourceBinding) ([]ResourceBinding, error) {
	if !ValidOperationKind(kind) {
		return nil, fmt.Errorf("invalid operation kind %q", kind)
	}
	if len(bindings) == 0 {
		return nil, fmt.Errorf("operation %q requires resource bindings", kind)
	}
	if len(bindings) > MaxOperationResourceBindings {
		return nil, fmt.Errorf("operation %q has %d resource bindings; limit is %d", kind, len(bindings), MaxOperationResourceBindings)
	}

	type mergeKey struct {
		role  ResourceRole
		kind  ResourceKind
		value string
	}
	merged := make(map[mergeKey]ResourceBinding, len(bindings))
	for index, binding := range bindings {
		if len(binding.EvidenceIDs) > MaxResourceBindingEvidenceIDs {
			return nil, fmt.Errorf("resource_bindings[%d].evidence_ids has %d items; limit is %d", index, len(binding.EvidenceIDs), MaxResourceBindingEvidenceIDs)
		}
		resource, err := NormalizeResource(binding.Resource)
		if err != nil {
			return nil, fmt.Errorf("resource_bindings[%d].resource: %w", index, err)
		}
		if !ValidOperationResourceRole(kind, binding.Role, resource.Kind) {
			return nil, fmt.Errorf("resource_bindings[%d] role %q and kind %q are incompatible with operation %q", index, binding.Role, resource.Kind, kind)
		}
		binding.Resource = resource
		binding.EvidenceIDs = sortedUniqueStrings(append([]string(nil), binding.EvidenceIDs...))
		key := mergeKey{role: binding.Role, kind: resource.Kind, value: resource.Value}
		if existing, ok := merged[key]; ok {
			existing.Resource.Classifications = append(existing.Resource.Classifications, resource.Classifications...)
			existing.Resource, _ = NormalizeResource(existing.Resource)
			existing.EvidenceIDs = sortedUniqueStrings(append(existing.EvidenceIDs, binding.EvidenceIDs...))
			merged[key] = existing
			continue
		}
		merged[key] = binding
	}

	out := make([]ResourceBinding, 0, len(merged))
	for _, binding := range merged {
		out = append(out, binding)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		if out[i].Resource.Kind != out[j].Resource.Kind {
			return out[i].Resource.Kind < out[j].Resource.Kind
		}
		if out[i].Resource.Value != out[j].Resource.Value {
			return out[i].Resource.Value < out[j].Resource.Value
		}
		return resourceClassificationsKey(out[i].Resource.Classifications) < resourceClassificationsKey(out[j].Resource.Classifications)
	})

	for _, policy := range OperationResourcePolicy(kind) {
		if !policy.Required {
			continue
		}
		found := false
		for _, binding := range out {
			if binding.Role == policy.Role {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("operation %q requires resource role %q", kind, policy.Role)
		}
	}
	return out, nil
}

func resourceClassificationsKey(values []ResourceClassification) string {
	var builder strings.Builder
	for _, value := range values {
		appendResourceKeyPart(&builder, string(value))
	}
	return builder.String()
}
