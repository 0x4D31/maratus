package extract

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestStaticPEMObservationsRetainExactPooledSpan(t *testing.T) {
	key, certificate, keyFingerprint, certificateFingerprint := staticPEMTestMaterials(t)
	for _, material := range []struct {
		name, feature, fingerprint string
		data                       []byte
	}{
		{"key", "cryptographic.private_key", keyFingerprint, key},
		{"certificate", "cryptographic.certificate", certificateFingerprint, certificate},
	} {
		for _, wrapper := range []struct {
			name, prefix, suffix string
			crlf                 bool
		}{
			{"pooled binary", "prefix\x00", "unrelated pooled constant\x80", false},
			{"pooled CRLF", "prefix\x00", "unrelated pooled constant\x80", true},
			{"Rust literal", "const DATA: &str = r#\"", "\"#;", false},
			{"Python literal", "DATA = \"\"\"", "\"\"\"", false},
			{"JS literal", "const data = `", "`;", false},
		} {
			t.Run(material.name+"/"+wrapper.name, func(t *testing.T) {
				span := bytes.TrimSuffix(material.data, []byte{'\n'})
				if wrapper.crlf {
					span = bytes.ReplaceAll(span, []byte{'\n'}, []byte{'\r', '\n'})
				}
				data := append(append([]byte(wrapper.prefix), span...), wrapper.suffix...)
				content := artifact.Content{NodeID: "node", LogicalPath: "inert", ScopeID: "scope"}
				var graph behavior.Graph
				extractStaticContentObservations(&graph, content, data, "test-data-region", "arm64", 4096)
				assertStaticPEMObservation(t, graph, material.feature, material.fingerprint, 4096+int64(len(wrapper.prefix)))
			})
		}
	}
}

func TestStaticPEMObservationCannotSkipMalformedCandidate(t *testing.T) {
	key, certificate, keyFingerprint, certificateFingerprint := staticPEMTestMaterials(t)
	for _, material := range []struct {
		typeName, feature, fingerprint string
		data                           []byte
	}{
		{"RSA PRIVATE KEY", "cryptographic.private_key", keyFingerprint, key},
		{"CERTIFICATE", "cryptographic.certificate", certificateFingerprint, certificate},
	} {
		for name, prefix := range map[string]string{
			"malformed body": "-----BEGIN " + material.typeName + "-----\nnot-base64\n",
			"wrong footer":   "-----BEGIN " + material.typeName + "-----\nAQID\n-----END OTHER TYPE-----\n",
		} {
			t.Run(material.typeName+"/"+name, func(t *testing.T) {
				var graph behavior.Graph
				data := append([]byte(prefix), material.data...)
				extractStaticContentObservations(&graph, artifact.Content{NodeID: "node", LogicalPath: "inert"}, data, "test-data-region", "arm64", 1024)
				assertStaticPEMObservation(t, graph, material.feature, material.fingerprint, 1024+int64(len(prefix)))
			})
		}
	}
}

func TestExactPEMSpanRejectsMalformedAndBoundedInput(t *testing.T) {
	key, _, _, _ := staticPEMTestMaterials(t)
	for name, data := range map[string][]byte{
		"truncated":     key[:len(key)-10],
		"wrong footer":  []byte("-----BEGIN RSA PRIVATE KEY-----\nAQID\n-----END CERTIFICATE-----"),
		"invalid body":  []byte("-----BEGIN RSA PRIVATE KEY-----\n?\n-----END RSA PRIVATE KEY-----"),
		"literal text":  []byte("a benign sentence mentioning PRIVATE KEY"),
		"escaped lines": []byte(`-----BEGIN RSA PRIVATE KEY-----\nAQID\n-----END RSA PRIVATE KEY-----`),
	} {
		t.Run(name, func(t *testing.T) {
			block, _, _ := decodeExactPEMSpan(data, maxPrivateKeyBytes)
			if block != nil {
				t.Fatalf("malformed material became a complete PEM block: %#v", block)
			}
		})
	}
	for _, limit := range []int{-1, 0, len(key) / 2} {
		if block, _, limited := decodeExactPEMSpan(key, limit); block != nil || !limited {
			t.Fatalf("candidate byte budget %d was not enforced", limit)
		}
	}
	for _, kind := range []struct {
		typeName, area string
		byteLimit      int
	}{
		{"RSA PRIVATE KEY", "private-key-observations", maxPrivateKeyBytes},
		{"CERTIFICATE", "certificate-observations", maxCertificateBytes},
	} {
		data := []byte("-----BEGIN " + kind.typeName + "-----\n" + strings.Repeat("A", kind.byteLimit) + "\n-----END " + kind.typeName + "-----")
		var graph behavior.Graph
		extractStaticContentObservations(&graph, artifact.Content{NodeID: "node", LogicalPath: "inert"}, data, "test-data-region", "arm64", 0)
		if len(graph.Features) != 0 || !hasPartialCoverageScope(graph.Coverage, kind.area) {
			t.Fatalf("oversized %s lacks explicit coverage: features=%#v coverage=%#v", kind.typeName, graph.Features, graph.Coverage)
		}
	}
}

func TestStaticPEMRejectsUnvalidatedPrivateKeyMaterial(t *testing.T) {
	for name, block := range map[string]*pem.Block{
		"OpenSSH magic only": {Type: "OPENSSH PRIVATE KEY", Bytes: []byte("openssh-key-v1\x00")},
		"OpenSSH malformed":  {Type: "OPENSSH PRIVATE KEY", Bytes: []byte("not a key")},
		"RSA malformed":      {Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, valid := privateKeyFingerprint(block); valid {
				t.Fatal("unvalidated material acquired a complete-key fingerprint")
			}
			var graph behavior.Graph
			extractStaticContentObservations(&graph, artifact.Content{NodeID: "node", LogicalPath: "inert"}, pem.EncodeToMemory(block), "test-data-region", "arm64", 0)
			if len(graph.Features) != 0 || len(graph.Operations) != 0 {
				t.Fatalf("unvalidated material was promoted: features=%#v operations=%#v", graph.Features, graph.Operations)
			}
			if block.Type == "OPENSSH PRIVATE KEY" && !hasPartialCoverageScope(graph.Coverage, "private-key-observations") {
				t.Fatalf("unsupported OpenSSH validation lacks explicit coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestExactPEMSpanPreservesHeaderWhitespace(t *testing.T) {
	data := []byte("-----BEGIN PRIVATE KEY----- \t\r\nAQID\r\n-----END PRIVATE KEY-----pooled suffix")
	block, consumed, limited := decodeExactPEMSpan(data, maxPrivateKeyBytes)
	if block == nil || block.Type != "PRIVATE KEY" || !bytes.Equal(block.Bytes, []byte{1, 2, 3}) || consumed != bytes.Index(data, []byte("pooled suffix")) || limited {
		t.Fatalf("valid PEM header whitespace/CRLF was rejected or shifted: block=%#v consumed=%d limited=%t", block, consumed, limited)
	}
}

func FuzzExactPEMSpan(f *testing.F) {
	const valid = "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----"
	for _, seed := range []string{valid, valid + "pooled suffix", "-----BEGIN PRIVATE KEY----- \t\r\nAQID\r\n-----END PRIVATE KEY-----suffix", "-----BEGIN PRIVATE KEY-----\n?\n" + valid} {
		f.Add([]byte(seed), len(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte, limit int) {
		if len(data) > maxPrivateKeyBytes+1 {
			t.Skip()
		}
		block, consumed, _ := decodeExactPEMSpan(data, limit)
		if block == nil {
			if consumed != 0 {
				t.Fatal("failed candidate consumed unrelated bytes")
			}
			return
		}
		if consumed <= 0 || consumed > len(data) || consumed > limit {
			t.Fatal("decoded span exceeded its input or byte budget")
		}
		span := data[:consumed]
		if !bytes.HasPrefix(span, []byte("-----BEGIN "+block.Type+"-----")) || !bytes.HasSuffix(span, []byte("-----END "+block.Type+"-----")) || bytes.Contains(span[1:], []byte("\n-----BEGIN ")) {
			t.Fatal("decoded span skipped or mismatched its candidate")
		}
		decoded, rest := pem.Decode(span)
		if decoded == nil || len(rest) != 0 || decoded.Type != block.Type || !bytes.Equal(decoded.Bytes, block.Bytes) || len(decoded.Headers) != len(block.Headers) {
			t.Fatal("decoded span did not retain exactly one complete block")
		}
		for key, value := range block.Headers {
			if decoded.Headers[key] != value {
				t.Fatal("decoded span changed a PEM header")
			}
		}
	})
}

func assertStaticPEMObservation(t *testing.T, graph behavior.Graph, key, fingerprint string, offset int64) {
	t.Helper()
	var found []behavior.Feature
	for _, feature := range graph.Features {
		if feature.Key == key {
			found = append(found, feature)
		}
	}
	value := "RSA PRIVATE KEY spki-sha256:" + fingerprint
	if key == "cryptographic.certificate" {
		value = "x509-certificate sha256:" + fingerprint
	}
	if len(found) != 1 || len(found[0].EvidenceIDs) != 1 || found[0].Support != behavior.SupportDirect || found[0].Qualifiers["fingerprint"] != fingerprint || found[0].Value != value {
		t.Fatalf("complete material was not retained as one fingerprint: %#v", found)
	}
	matched := false
	for _, evidence := range graph.Evidence {
		if strings.Contains(evidence.Value, "-----BEGIN ") || strings.Contains(evidence.Value, "-----END ") {
			t.Fatalf("PEM bytes leaked into evidence: %#v", evidence)
		}
		if evidence.ID == found[0].EvidenceIDs[0] {
			matched = evidence.OffsetKnown && evidence.Offset == offset && evidence.NodeID == found[0].NodeID && evidence.ScopeID == found[0].ScopeID && evidence.Arch == found[0].Architecture
		}
	}
	if !matched || len(graph.Operations) != 0 {
		t.Fatalf("fingerprint lost exact lineage or became behavior: evidence=%#v operations=%#v", graph.Evidence, graph.Operations)
	}
}

func staticPEMTestMaterials(t *testing.T) ([]byte, []byte, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Inert PEM control"}, NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(1_800_000_000, 0)}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicFingerprint, certificateFingerprint := sha256.Sum256(publicDER), sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), hex.EncodeToString(publicFingerprint[:]), hex.EncodeToString(certificateFingerprint[:])
}
