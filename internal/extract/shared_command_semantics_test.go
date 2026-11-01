package extract

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestSharedShellCommandSemantics(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		kind     behavior.OperationKind
		resource behavior.ResourceKind
		value    string
	}{
		{"cron stdin", "crontab -", behavior.OperationScheduledJobRegister, behavior.ResourceScheduledJob, "standard input"},
		{"plist file", "plutil -replace LSEnvironment.DYLD_INSERT_LIBRARIES -string /tmp/x /tmp/App.plist", behavior.OperationPlistModify, behavior.ResourceFile, "/tmp/App.plist"},
		{"defaults domain", "defaults write com.example.agent Enabled -bool true", behavior.OperationPlistModify, behavior.ResourceConfiguration, "com.example.agent"},
		{"system", "system_profiler SPHardwareDataType", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"},
		{"system profiler options", "system_profiler -detailLevel mini -json SPHardwareDataType", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"},
		{"system profiler zero timeout", "system_profiler -timeout 0 SPSoftwareDataType", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"},
		{"sysctl all", "sysctl -a", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"},
		{"sysctl read flags", "sysctl -n hw.model", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"},
		{"sw vers", "sw_vers -productVersion", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"},
		{"sw vers long", "sw_vers --productVersionExtra", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"},
		{"uname operating system", "uname -o", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"},
		{"hostname", "/bin/hostname -s", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "local host identity"},
		{"ifconfig all", "/sbin/ifconfig -a", behavior.OperationNetworkConfigurationQuery, behavior.ResourceConfiguration, "local network configuration"},
		{"ifconfig interface", "ifconfig en0", behavior.OperationNetworkConfigurationQuery, behavior.ResourceConfiguration, "local network configuration"},
		{"scutil dns", "/usr/sbin/scutil --dns", behavior.OperationNetworkConfigurationQuery, behavior.ResourceConfiguration, "local network configuration"},
		{"networksetup services", "networksetup -listallnetworkservices", behavior.OperationNetworkConfigurationQuery, behavior.ResourceConfiguration, "local network configuration"},
		{"networksetup dns", "networksetup -getdnsservers Wi-Fi", behavior.OperationNetworkConfigurationQuery, behavior.ResourceConfiguration, "local network configuration"},
		{"user", "whoami", behavior.OperationUserInfoQuery, behavior.ResourceUserAccount, "local users"},
		{"user system path", "/usr/bin/whoami", behavior.OperationUserInfoQuery, behavior.ResourceUserAccount, "local users"},
		{"user id flags", "id -G -n root", behavior.OperationUserInfoQuery, behavior.ResourceUserAccount, "local users"},
		{"process", "ps aux", behavior.OperationProcessEnumerate, behavior.ResourceProcess, "local processes"},
		{"process pid", "ps -p 1", behavior.OperationProcessEnumerate, behavior.ResourceProcess, "local processes"},
		{"process selected columns", "ps -axo pid,command", behavior.OperationProcessEnumerate, behavior.ResourceProcess, "local processes"},
		{"process pgrep", "pgrep -fl launchd", behavior.OperationProcessEnumerate, behavior.ResourceProcess, "local processes"},
		{"software", "system_profiler SPApplicationsDataType", behavior.OperationSoftwareEnumerate, behavior.ResourceSoftware, "installed applications"},
		{"files", "find /Users/shared -type f", behavior.OperationFileEnumerate, behavior.ResourceFile, "/Users/shared"},
		{"files find leading option", "find -H /Users/shared -type f", behavior.OperationFileEnumerate, behavior.ResourceFile, "/Users/shared"},
		{"files find explicit path", "find -f /Users/shared -name token", behavior.OperationFileEnumerate, behavior.ResourceFile, "/Users/shared"},
		{"files metadata query", "mdfind -onlyin /Users/shared -name token", behavior.OperationFileEnumerate, behavior.ResourceFile, "metadata search"},
		{"delete", "rm -f /tmp/stage", behavior.OperationFileDelete, behavior.ResourceFile, "/tmp/stage"},
		{"clipboard write", "pbcopy", behavior.OperationClipboardWrite, behavior.ResourceClipboard, "pbcopy"},
		{"hidden SetFile", "SetFile -a V /tmp/stage", behavior.OperationFileVisibilityModify, behavior.ResourceFile, "/tmp/stage"},
		{"hidden chflags", "chflags hidden /tmp/stage", behavior.OperationFileVisibilityModify, behavior.ResourceFile, "/tmp/stage"},
		{"rm option terminator", "rm -- /tmp/stage", behavior.OperationFileDelete, behavior.ResourceFile, "/tmp/stage"},
		{"unlink exact macOS path", "/bin/unlink -- /tmp/stage", behavior.OperationFileDelete, behavior.ResourceFile, "/tmp/stage"},
		{"rmdir option terminator", "rmdir -- /tmp/stage", behavior.OperationFileDelete, behavior.ResourceFile, "/tmp/stage"},
		{"plist remove", "plutil -remove LSEnvironment /tmp/App.plist", behavior.OperationPlistModify, behavior.ResourceFile, "/tmp/App.plist"},
		{"plist remove silent", "plutil -remove LSEnvironment -s /tmp/App.plist", behavior.OperationPlistModify, behavior.ResourceFile, "/tmp/App.plist"},
		{"plist remove leading silent", "plutil -s -remove LSEnvironment /tmp/App.plist", behavior.OperationPlistModify, behavior.ResourceFile, "/tmp/App.plist"},
		{"plist buddy delete", `/usr/libexec/PlistBuddy -c "Delete :LSEnvironment" /tmp/App.plist`, behavior.OperationPlistModify, behavior.ResourceFile, "/tmp/App.plist"},
		{"privacy reset all", "tccutil reset All", behavior.OperationPrivacyAuthorizationReset, behavior.ResourceConfiguration, "All"},
		{"privacy reset service", "/usr/bin/tccutil reset AppleEvents com.example.App", behavior.OperationPrivacyAuthorizationReset, behavior.ResourceConfiguration, "AppleEvents"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph := extractShellCommandFixture(test.command)
			for _, operation := range graph.Operations {
				if operation.Kind != test.kind {
					continue
				}
				resource := operation.RequiredResource()
				if resource.Kind == test.resource && resource.Value == test.value && operation.Support == behavior.SupportCorroborated {
					return
				}
			}
			t.Fatalf("missing %s %s %q in %#v", test.kind, test.resource, test.value, graph.Operations)
		})
	}
}

func TestSharedShellCommandCloseNegatives(t *testing.T) {
	for _, test := range []struct {
		command string
		kind    behavior.OperationKind
	}{
		{"crontab -l", behavior.OperationScheduledJobRegister},
		{"crontab -r", behavior.OperationScheduledJobRegister},
		{"defaults read com.example.agent", behavior.OperationPlistModify},
		{"plutil -p /tmp/App.plist", behavior.OperationPlistModify},
		{"sysctl net.inet.ip.forwarding", behavior.OperationSystemInfoQuery},
		{"sysctl -w kern.hostname=changed", behavior.OperationSystemInfoQuery},
		{"sysctl -a -w", behavior.OperationSystemInfoQuery},
		{"sysctl -Z hw.model", behavior.OperationSystemInfoQuery},
		{"system_profiler -usage", behavior.OperationSystemInfoQuery},
		{"system_profiler -listDataTypes", behavior.OperationSystemInfoQuery},
		{"system_profiler -detailLevel future SPHardwareDataType", behavior.OperationSystemInfoQuery},
		{"system_profiler SP../../DataType", behavior.OperationSystemInfoQuery},
		{"sw_vers --help", behavior.OperationSystemInfoQuery},
		{"uname --help", behavior.OperationSystemInfoQuery},
		{"hostinfo extra", behavior.OperationSystemInfoQuery},
		{"hostname changed.invalid", behavior.OperationSystemInfoQuery},
		{"hostname -x", behavior.OperationSystemInfoQuery},
		{"ifconfig en0 down", behavior.OperationNetworkConfigurationQuery},
		{"ifconfig en0 inet 192.0.2.1", behavior.OperationNetworkConfigurationQuery},
		{"ifconfig -z", behavior.OperationNetworkConfigurationQuery},
		{"scutil --set ComputerName changed", behavior.OperationNetworkConfigurationQuery},
		{"scutil --dns extra", behavior.OperationNetworkConfigurationQuery},
		{"networksetup -setdnsservers Wi-Fi 192.0.2.1", behavior.OperationNetworkConfigurationQuery},
		{"networksetup -getdnsservers", behavior.OperationNetworkConfigurationQuery},
		{"/tmp/ifconfig -a", behavior.OperationNetworkConfigurationQuery},
		{"whoami --help", behavior.OperationUserInfoQuery},
		{"users extra", behavior.OperationUserInfoQuery},
		{"id --help", behavior.OperationUserInfoQuery},
		{"id -AF", behavior.OperationUserInfoQuery},
		{"ps --help", behavior.OperationProcessEnumerate},
		{"ps -Z", behavior.OperationProcessEnumerate},
		{"ps launchd", behavior.OperationProcessEnumerate},
		{"pgrep --help", behavior.OperationProcessEnumerate},
		{"pgrep -- launchd", behavior.OperationProcessEnumerate},
		{"pgrep", behavior.OperationProcessEnumerate},
		{"pgrep -l", behavior.OperationProcessEnumerate},
		{"pgrep -d", behavior.OperationProcessEnumerate},
		{"ls /tmp", behavior.OperationFileEnumerate},
		{"find --help /tmp", behavior.OperationFileEnumerate},
		{"find -H -future /tmp", behavior.OperationFileEnumerate},
		{"mdfind", behavior.OperationFileEnumerate},
		{"mdfind --help", behavior.OperationFileEnumerate},
		{"mdfind -onlyin /tmp", behavior.OperationFileEnumerate},
		{"rm", behavior.OperationFileDelete},
		{"rm --recursive /tmp/stage", behavior.OperationFileDelete},
		{"pbcopy unexpected operand", behavior.OperationClipboardWrite},
		{"SetFile -a v /tmp/stage", behavior.OperationFileVisibilityModify},
		{"SetFile -a V", behavior.OperationFileVisibilityModify},
		{"chflags nohidden /tmp/stage", behavior.OperationFileVisibilityModify},
		{"chflags hidden /tmp/a /tmp/b", behavior.OperationFileVisibilityModify},
		{"unlink /tmp/a /tmp/b", behavior.OperationFileDelete},
		{"/usr/bin/unlink /tmp/stage", behavior.OperationFileDelete},
		{"crontab -u -e /tmp/job", behavior.OperationScheduledJobRegister},
		{"defaults write com.example.agent Enabled", behavior.OperationPlistModify},
		{"defaults write com.example.agent Enabled -bool maybe", behavior.OperationPlistModify},
		{"defaults write com.example.agent Enabled -dict only-key", behavior.OperationPlistModify},
		{"plutil -replace LSEnvironment /tmp/App.plist", behavior.OperationPlistModify},
		{"plutil -replace LSEnvironment -future value /tmp/App.plist", behavior.OperationPlistModify},
		{`/usr/libexec/PlistBuddy -c "Set :LSEnvironment" /tmp/App.plist`, behavior.OperationPlistModify},
		{`/usr/libexec/PlistBuddy -c "Delete :LSEnvironment; Delete :Other" /tmp/App.plist`, behavior.OperationPlistModify},
		{`/usr/libexec/PlistBuddy -c "Print :LSEnvironment" /tmp/App.plist`, behavior.OperationPlistModify},
		{"tccutil", behavior.OperationPrivacyAuthorizationReset},
		{"tccutil list All", behavior.OperationPrivacyAuthorizationReset},
		{"tccutil reset", behavior.OperationPrivacyAuthorizationReset},
		{"tccutil reset -All", behavior.OperationPrivacyAuthorizationReset},
		{"tccutil reset All com.example.App extra", behavior.OperationPrivacyAuthorizationReset},
		{"tccutil reset $SERVICE", behavior.OperationPrivacyAuthorizationReset},
		{"/tmp/tccutil reset All", behavior.OperationPrivacyAuthorizationReset},
		{"/tmp/whoami", behavior.OperationUserInfoQuery},
		{"relative/tools/ps aux", behavior.OperationProcessEnumerate},
	} {
		graph := extractShellCommandFixture(test.command)
		for _, operation := range graph.Operations {
			if operation.Kind == test.kind {
				t.Fatalf("close negative %q emitted %s: %#v", test.command, test.kind, graph.Operations)
			}
		}
	}
}

func TestSharedPrivacyAuthorizationResetRetainsOptionalBundleIdentifier(t *testing.T) {
	graph := extractShellCommandFixture("/usr/bin/tccutil reset AppleEvents com.example.App")
	for _, operation := range graph.Operations {
		if operation.Kind != behavior.OperationPrivacyAuthorizationReset {
			continue
		}
		if operation.Qualifiers["service"] != "AppleEvents" || operation.Qualifiers["bundle_identifier"] != "com.example.App" || operation.Qualifiers["tool"] != "tccutil" {
			t.Fatalf("privacy reset qualifiers = %#v", operation.Qualifiers)
		}
		return
	}
	t.Fatalf("privacy authorization reset operation missing: %#v", graph.Operations)
}

func TestPrivacyAuthorizationResetUsesOneOperationAcrossScriptAdapters(t *testing.T) {
	tests := []struct {
		name string
		path string
		data string
	}{
		{name: "shell", path: "fixture.sh", data: "tccutil reset AppleEvents\n"},
		{name: "python", path: "fixture.py", data: "import subprocess\nsubprocess.run(['/usr/bin/tccutil', 'reset', 'AppleEvents'])\n"},
		{name: "javascript", path: "fixture.js", data: "const cp = require('child_process');\ncp.spawnSync('/usr/bin/tccutil', ['reset', 'AppleEvents']);\n"},
		{name: "applescript", path: "fixture.applescript", data: "do shell script \"tccutil reset AppleEvents\"\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{NodeID: "node-" + test.name, LogicalPath: test.path, Kind: "script", MediaType: "text/plain", Data: []byte(test.data)})
			var matches []behavior.ModeledOperation
			for _, operation := range graph.Operations {
				if operation.Kind == behavior.OperationPrivacyAuthorizationReset {
					matches = append(matches, operation)
				}
			}
			if len(matches) != 1 || matches[0].RequiredResource().Kind != behavior.ResourceConfiguration || matches[0].RequiredResource().Value != "AppleEvents" || matches[0].Support != behavior.SupportCorroborated {
				t.Fatalf("privacy reset parity = %#v; all adapters must emit one corroborated typed operation", matches)
			}
		})
	}
}

func TestArchiveExtractionUsesOneOperationAcrossScriptAdapters(t *testing.T) {
	tests := []struct {
		name string
		path string
		data string
	}{
		{name: "shell", path: "fixture.sh", data: "unzip -qo /tmp/stage.zip -d /tmp/stage\n"},
		{name: "python subprocess", path: "fixture.py", data: "import subprocess\nsubprocess.run(['unzip', '-qo', '/tmp/stage.zip', '-d', '/tmp/stage'])\n"},
		{name: "python stdlib", path: "fixture.py", data: "import shutil\nshutil.unpack_archive('/tmp/stage.zip', '/tmp/stage')\n"},
		{name: "javascript", path: "fixture.js", data: "const cp = require('child_process');\ncp.spawnSync('unzip', ['-qo', '/tmp/stage.zip', '-d', '/tmp/stage']);\n"},
		{name: "applescript", path: "fixture.applescript", data: "do shell script \"unzip -qo /tmp/stage.zip -d /tmp/stage\"\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{NodeID: "node-" + test.name, LogicalPath: test.path, Kind: "script", MediaType: "text/plain", Data: []byte(test.data)})
			var matches []behavior.ModeledOperation
			for _, operation := range graph.Operations {
				if operation.Kind == behavior.OperationArchiveExtract {
					matches = append(matches, operation)
				}
			}
			if len(matches) != 1 || matches[0].Support != behavior.SupportCorroborated {
				t.Fatalf("archive extraction parity = %#v; all adapters must emit one corroborated typed operation", matches)
			}
			source, sourceOK := matches[0].FirstBinding(behavior.ResourceRoleSource)
			target, targetOK := matches[0].FirstBinding(behavior.ResourceRoleLocalOutput)
			if !sourceOK || !targetOK || source.Resource.Value != "/tmp/stage.zip" || target.Resource.Value != "/tmp/stage" {
				t.Fatalf("archive extraction resources = %#v", matches[0].ResourceBindings)
			}
		})
	}
}

func TestSharedDeletionTargetBudgetIsExplicitAndDeterministic(t *testing.T) {
	command := "rm " + strings.Join(func() []string {
		values := make([]string, behavior.MaxOperationResourceBindings+1)
		for index := range values {
			values[index] = fmt.Sprintf("/tmp/item-%03d", index)
		}
		return values
	}(), " ")
	first := extractShellCommandFixture(command)
	second := extractShellCommandFixture(command)
	if len(first.Operations) != behavior.MaxOperationResourceBindings || !reflect.DeepEqual(first.Operations, second.Operations) {
		t.Fatalf("bounded deletion operations = %d deterministic=%v", len(first.Operations), reflect.DeepEqual(first.Operations, second.Operations))
	}
	for _, item := range first.Coverage {
		if item.Status == "partial" && strings.Contains(item.Detail, "target recognition capped") {
			return
		}
	}
	t.Fatalf("bounded deletion lacks explicit partial coverage: %#v", first.Coverage)
}

func TestSharedPlistDynamicLoaderQualifierUsesTheExactKey(t *testing.T) {
	positive := extractShellCommandFixture("plutil -replace LSEnvironment.DYLD_INSERT_LIBRARIES -string /tmp/x /tmp/App.plist")
	if len(positive.Operations) != 1 || positive.Operations[0].Qualifiers["dynamic_loader_configuration"] != "true" {
		t.Fatalf("exact dynamic-loader key qualifiers = %#v", positive.Operations)
	}
	negative := extractShellCommandFixture("plutil -replace OrdinaryKey -string /tmp/x /tmp/DYLD_INSERT_LIBRARIES.plist")
	if len(negative.Operations) != 1 || negative.Operations[0].Qualifiers["dynamic_loader_configuration"] != "" {
		t.Fatalf("sample-derived target name became a dynamic-loader key: %#v", negative.Operations)
	}
	lookalike := extractShellCommandFixture("plutil -replace NOT_DYLD_INSERT_LIBRARIES_SUFFIX -string /tmp/x /tmp/App.plist")
	if len(lookalike.Operations) != 1 || lookalike.Operations[0].Qualifiers["dynamic_loader_configuration"] != "" {
		t.Fatalf("lookalike key became a dynamic-loader key: %#v", lookalike.Operations)
	}
}

func TestArchiveCreationRetainsExactSources(t *testing.T) {
	graph := extractShellCommandFixture("zip -r /tmp/stage.zip ~/Library/Keychains ~/.ssh")
	for _, operation := range graph.Operations {
		if operation.Kind != behavior.OperationArchiveCreate {
			continue
		}
		seen := map[string]bool{}
		for _, binding := range operation.ResourceBindings {
			if binding.Role == behavior.ResourceRoleSource {
				seen[binding.Resource.Value] = true
			}
		}
		if seen["~/Library/Keychains"] && seen["~/.ssh"] {
			return
		}
		t.Fatalf("archive sources = %#v", operation.ResourceBindings)
	}
	t.Fatalf("archive operation missing: %#v", graph.Operations)
}

func extractShellCommandFixture(command string) behavior.Graph {
	graph := behavior.Graph{}
	content := artifact.Content{NodeID: "node-command", LogicalPath: "fixture.sh"}
	evidenceID := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "test", Kind: "line", Value: command})
	AnalyzeShellLine(&graph, content, command, 1, behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}, evidenceID)
	_ = graph.Sort()
	return graph
}
