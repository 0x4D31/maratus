package extract

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestExtractTextRetainsEmbeddedLaunchdConfigurationAsDataOnly(t *testing.T) {
	plist := `<?xml version="1.0"?><plist version="1.0"><dict>` +
		`<key>Label</key><string>com.example.inert</string>` +
		`<key>ProgramArguments</key><array><string>/bin/zsh</string><string>-c</string><string>echo inert</string></array>` +
		`<key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>` +
		`</dict></plist>`
	content := artifact.Content{NodeID: "node", LogicalPath: "fixture.bin.txt", Data: []byte("prefix\x00" + plist + "\x00suffix")}
	graph := behavior.Graph{}

	ExtractText(&graph, content)

	want := map[string]string{
		"embedded.launchd.configuration": "com.example.inert",
		"embedded.launchd.label":         "com.example.inert",
		"embedded.launchd.program":       "/bin/zsh -c echo inert",
		"embedded.launchd.trigger":       "RunAtLoad",
	}
	for key, value := range want {
		if !hasFeatureValue(graph, key, value) {
			t.Fatalf("missing %s=%q in %#v", key, value, graph.Features)
		}
	}
	if !hasFeatureValue(graph, "embedded.launchd.trigger", "KeepAlive") {
		t.Fatalf("KeepAlive trigger missing: %#v", graph.Features)
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("embedded data became operations: %#v", graph.Operations)
	}
	for _, feature := range graph.Features {
		if strings.HasPrefix(feature.Key, "embedded.launchd.") && (feature.Qualifiers["data_only"] != "true" || feature.Qualifiers["persistence"] != "not-established") {
			t.Fatalf("embedded plist qualification = %#v", feature)
		}
	}
}

func TestEmbeddedLaunchdTemplateRetainsOnlyExactStaticFields(t *testing.T) {
	data := append([]byte(`<plist version="1.0"><dict><key>Label</key><string>`), 0xc0, 'x')
	data = append(data, []byte(`</string><key>ProgramArguments</key><array><string>/bin/zsh</string><string>-c</string><string>`)...)
	data = append(data, 0xc0, 'y')
	data = append(data, []byte(`</string></array><key>RunAtLoad</key><true/></dict></plist>`)...)
	graph := behavior.Graph{}
	extractStaticContentObservations(&graph, artifact.Content{NodeID: "node", LogicalPath: "fixture.bin"}, data, "fixture", "arm64", 40)

	if !hasFeatureValue(graph, "embedded.launchd.program", "/bin/zsh") || !hasFeatureValue(graph, "embedded.launchd.trigger", "RunAtLoad") {
		t.Fatalf("exact template fields missing: %#v", graph.Features)
	}
	for _, feature := range graph.Features {
		if feature.Key == "embedded.launchd.label" || feature.Key == "embedded.launchd.configuration" {
			t.Fatalf("dynamic template field became exact: %#v", feature)
		}
		if strings.HasPrefix(feature.Key, "embedded.launchd.") && (feature.Qualifiers["complete"] != "false" || feature.Qualifiers["data_only"] != "true" || feature.Qualifiers["persistence"] != "not-established") {
			t.Fatalf("template qualification = %#v", feature)
		}
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("template became behavior: %#v", graph.Operations)
	}

	invalidProgram := []byte("<plist><dict><key>Label</key><string>com.example</string><key>Program</key><string>\xc0x</string><key>RunAtLoad</key><true/></dict></plist>")
	rejected := behavior.Graph{}
	extractStaticContentObservations(&rejected, artifact.Content{NodeID: "node", LogicalPath: "fixture.bin"}, invalidProgram, "fixture", "arm64", 0)
	if len(rejected.Features) != 0 {
		t.Fatalf("dynamic executable became a launchd template: %#v", rejected.Features)
	}
}

func TestAssignedCanonicalBase64ObservationsAreFormatNeutralAndNonBehavioral(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("https://decoded.example/p at 203.0.113.44"))
	for _, path := range []string{"fixture.py", "fixture.js", "fixture.sh", "fixture.toml"} {
		t.Run(path, func(t *testing.T) {
			graph := behavior.Graph{}
			ExtractText(&graph, artifact.Content{NodeID: "node", LogicalPath: path, Data: []byte("PAYLOAD = \"" + encoded + "\"\n")})
			if !hasFeatureValue(graph, "network.url", "https://decoded.example/p") || !hasFeatureValue(graph, "network.ip", "203.0.113.44") || len(graph.Operations) != 0 {
				t.Fatalf("format-neutral Base64 observation = features %#v operations %#v", graph.Features, graph.Operations)
			}
		})
	}
	commented := behavior.Graph{}
	ExtractText(&commented, artifact.Content{NodeID: "node", LogicalPath: "fixture.py", Data: []byte("# PAYLOAD = \"" + encoded + "\"\n")})
	if hasFeatureValue(commented, "network.url", "https://decoded.example/p") {
		t.Fatalf("commented assignment became an observable: %#v", commented.Features)
	}
	benign := behavior.Graph{}
	inert := base64.StdEncoding.EncodeToString([]byte("ordinary test fixture bytes without an observable"))
	ExtractText(&benign, artifact.Content{NodeID: "node", LogicalPath: "fixture.py", Data: []byte("PAYLOAD = \"" + inert + "\"\n")})
	if len(benign.Features) != 0 {
		t.Fatalf("non-semantic decoded bytes produced summary noise: %#v", benign.Features)
	}
}

func TestAssignedCanonicalBase64ObservationsRequireLiveSourceCode(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("https://comment-decoy.example.invalid/p"))
	tests := []struct {
		name string
		path string
		data string
	}{
		{name: "javascript block comment", path: "fixture.js", data: "/*\nPAYLOAD = \"" + encoded + "\"\n*/\n"},
		{name: "javascript line comment", path: "fixture.js", data: "let live = 1; // PAYLOAD = \"" + encoded + "\"\n"},
		{name: "javascript quoted example", path: "fixture.js", data: "const example = 'PAYLOAD = \"" + encoded + "\"';\n"},
		{name: "javascript inline fragment", path: "fixture.js", data: "if (ready) PAYLOAD = \"" + encoded + "\";\n"},
		{name: "javascript dynamic suffix", path: "fixture.js", data: "const PAYLOAD = \"" + encoded + "\" + suffix;\n"},
		{name: "javascript invalid hash suffix", path: "fixture.js", data: "const PAYLOAD = \"" + encoded + "\" # not a JavaScript comment\n"},
		{name: "python dynamic suffix", path: "fixture.py", data: "PAYLOAD = \"" + encoded + "\" + suffix\n"},
		{name: "python invalid slash suffix", path: "fixture.py", data: "PAYLOAD = \"" + encoded + "\" // not a Python comment\n"},
		{name: "shell command suffix", path: "fixture.sh", data: "PAYLOAD=\"" + encoded + "\" command\n"},
		{name: "python docstring", path: "fixture.py", data: "\"\"\"\nPAYLOAD = \"" + encoded + "\"\n\"\"\"\n"},
		{name: "python line comment", path: "fixture.py", data: "live = 1 # PAYLOAD = \"" + encoded + "\"\n"},
		{name: "python quoted example", path: "fixture.py", data: "example = 'PAYLOAD = \"" + encoded + "\"'\n"},
		{name: "shell heredoc", path: "fixture.sh", data: "cat <<'EOF'\nPAYLOAD = \"" + encoded + "\"\nEOF\n"},
		{name: "shell line comment", path: "fixture.sh", data: "live=1 # PAYLOAD = \"" + encoded + "\"\n"},
		{name: "swift multiline string", path: "fixture.swift", data: "let example = \"\"\"\nPAYLOAD = \"" + encoded + "\"\n\"\"\"\n"},
		{name: "applescript unsupported assignment grammar", path: "fixture.applescript", data: "PAYLOAD = \"" + encoded + "\"\n"},
		{name: "toml multiline string", path: "fixture.toml", data: "example = \"\"\"\nPAYLOAD = \"" + encoded + "\"\n\"\"\"\n"},
		{name: "yaml unsupported assignment syntax", path: "fixture.yaml", data: "PAYLOAD = \"" + encoded + "\"\n"},
		{name: "unknown syntax", path: "fixture.txt", data: "PAYLOAD = \"" + encoded + "\"\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph := behavior.Graph{}
			ExtractText(&graph, artifact.Content{NodeID: "node", LogicalPath: test.path, Data: []byte(test.data)})
			if hasFeatureValue(graph, "network.url", "https://comment-decoy.example.invalid/p") {
				t.Fatalf("non-code assignment became an observable: %#v", graph.Features)
			}
		})
	}
}

func TestAssignedCanonicalBase64ObservationsPreserveCommentMarkersInsideLiteral(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("https://literal.example.invalid/p"))
	for _, test := range []struct {
		path string
		data string
	}{
		{path: "fixture.py", data: "PAYLOAD = \"" + encoded + "\" # retained assignment\n"},
		{path: "fixture.js", data: "const PAYLOAD = \"" + encoded + "\"; // retained assignment\n"},
		{path: "fixture.sh", data: "PAYLOAD=\"" + encoded + "\" # retained assignment\n"},
	} {
		t.Run(test.path, func(t *testing.T) {
			graph := behavior.Graph{}
			ExtractText(&graph, artifact.Content{NodeID: "node", LogicalPath: test.path, Data: []byte(test.data)})
			if !hasFeatureValue(graph, "network.url", "https://literal.example.invalid/p") {
				t.Fatalf("live assignment was not retained: %#v", graph.Features)
			}
		})
	}
}

func TestAssignedCanonicalBase64ObservationLexicalBudgetFailsClosed(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("https://masked.example.invalid/p"))
	graph := behavior.Graph{}
	data := strings.Repeat("/*", 65) + "\nPAYLOAD = \"" + encoded + "\"\n"
	ExtractText(&graph, artifact.Content{NodeID: "node", LogicalPath: "fixture.js", Data: []byte(data)})
	if hasFeatureValue(graph, "network.url", "https://masked.example.invalid/p") {
		t.Fatalf("lexically uninspected suffix became an observable: %#v", graph.Features)
	}
	for _, item := range graph.Coverage {
		if item.AnalysisArea == "derived-base64-observations" && item.Status == "partial" {
			return
		}
	}
	t.Fatalf("lexical bound lacks explicit partial coverage: %#v", graph.Coverage)
}

func TestExtractTextPrivateKeyUsesFingerprintWithoutSecretBytes(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	secret := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	content := artifact.Content{NodeID: "node", LogicalPath: "fixture.txt", Data: append([]byte("header\n"), secret...)}
	graph := behavior.Graph{}

	ExtractText(&graph, content)

	var observation behavior.Feature
	for _, feature := range graph.Features {
		if feature.Key == "cryptographic.private_key" {
			observation = feature
			break
		}
	}
	if observation.Key == "" || observation.Qualifiers["key_type"] != "RSA PRIVATE KEY" || observation.Qualifiers["fingerprint_kind"] != "spki-sha256" || len(observation.Qualifiers["fingerprint"]) != 64 {
		t.Fatalf("private-key observation = %#v", observation)
	}
	for _, evidence := range graph.Evidence {
		if strings.Contains(evidence.Value, "BEGIN") || strings.Contains(evidence.Value, string(secret)) {
			t.Fatalf("private key leaked through evidence: %#v", evidence)
		}
	}
}

func TestExtractTextCertificateUsesFingerprintWithoutPEMBytes(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Maratus inert control"},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(1_800_000_000, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	content := artifact.Content{NodeID: "node", LogicalPath: "fixture.txt", Data: append([]byte("header\n"), encoded...)}
	graph := behavior.Graph{}
	ExtractText(&graph, content)

	var observation behavior.Feature
	for _, feature := range graph.Features {
		if feature.Key == "cryptographic.certificate" {
			observation = feature
			break
		}
	}
	if observation.Key == "" || observation.Qualifiers["fingerprint_kind"] != "certificate-der-sha256" || len(observation.Qualifiers["fingerprint"]) != 64 || observation.Qualifiers["subject"] != "CN=Maratus inert control" || observation.Qualifiers["trust"] != "not-evaluated" {
		t.Fatalf("certificate observation = %#v", observation)
	}
	for _, evidence := range graph.Evidence {
		if strings.Contains(evidence.Value, "BEGIN CERTIFICATE") || strings.Contains(evidence.Value, string(encoded)) {
			t.Fatalf("certificate bytes leaked through evidence: %#v", evidence)
		}
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("certificate data became behavior: %#v", graph.Operations)
	}
}

func TestStaticObservationsRejectMalformedOrNonLaunchdData(t *testing.T) {
	data := []byte(`-----BEGIN RSA PRIVATE KEY-----\nAQID\n-----END RSA PRIVATE KEY-----` +
		`<plist><dict><key>CFBundleIdentifier</key><string>com.example.app</string></dict></plist>` +
		`<plist><dict><key>Label</key><string>com.example.no-program</string></dict></plist>`)
	graph := behavior.Graph{}
	extractStaticContentObservations(&graph, artifact.Content{NodeID: "node", LogicalPath: "fixture"}, data, "fixture", "", 0)
	if len(graph.Features) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("malformed/non-launchd data produced semantic facts: features=%#v operations=%#v", graph.Features, graph.Operations)
	}
}

func TestStaticObservationCandidateBudgetsAreExplicit(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		area string
	}{
		{name: "embedded plist candidates", data: strings.Repeat("<plist malformed ", maxEmbeddedPlistCandidates+1), area: "embedded-launchd-configurations"},
		{name: "private key candidates", data: strings.Repeat("-----BEGIN NOT A KEY-----\n", maxPrivateKeyCandidates+1), area: "private-key-observations"},
		{name: "certificate candidates", data: strings.Repeat("-----BEGIN CERTIFICATE-----\nmalformed\n", maxCertificateCandidates+1), area: "certificate-observations"},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := behavior.Graph{}
			extractStaticContentObservations(&graph, artifact.Content{NodeID: "node", LogicalPath: "fixture"}, []byte(test.data), "source-static-observation", "", 0)
			found := false
			for _, item := range graph.Coverage {
				if item.AnalysisArea == test.area && item.Status == "partial" {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing explicit %s budget coverage: %#v", test.area, graph.Coverage)
			}
			if len(graph.Operations) != 0 {
				t.Fatalf("budget input produced operations: %#v", graph.Operations)
			}
		})
	}
}
