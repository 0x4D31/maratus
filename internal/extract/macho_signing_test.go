package extract

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestCodeDirectoryPageIntegrity(t *testing.T) {
	prefix := make([]byte, 5000)
	for index := range prefix {
		prefix[index] = byte(index % 251)
	}
	signature := testHashedCodeSignature(prefix, 2, 32, 12, 0)
	image := append(append([]byte(nil), prefix...), signature...)
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample", Data: image}
	file := testMachOFileWithCodeSignature(len(prefix), len(signature))

	var valid behavior.Graph
	extractCodeSignature(&valid, content, file, "arm64", image)
	if !hasArtifactProperty(valid.ArtifactProperties, "code-directory-hash-algorithm", "sha256", behavior.SupportDirect) ||
		!hasArtifactProperty(valid.ArtifactProperties, "code-directory-page-integrity", "valid", behavior.SupportDirect) {
		t.Fatalf("missing valid CodeDirectory integrity: properties=%#v coverage=%#v", valid.ArtifactProperties, valid.Coverage)
	}

	tampered := append([]byte(nil), image...)
	tampered[4097] ^= 0xff
	var invalid behavior.Graph
	extractCodeSignature(&invalid, artifact.Content{NodeID: "node-1", LogicalPath: "sample", Data: tampered}, file, "arm64", tampered)
	if !hasArtifactProperty(invalid.ArtifactProperties, "code-directory-page-integrity", "invalid", behavior.SupportDirect) {
		t.Fatalf("tampered page was not rejected: properties=%#v coverage=%#v", invalid.ArtifactProperties, invalid.Coverage)
	}
	if len(invalid.Coverage) != 0 {
		t.Fatalf("a proven hash mismatch is not incomplete analysis: %#v", invalid.Coverage)
	}
}

func TestCodeDirectoryIntegrityUnknownIsExplicitAndBounded(t *testing.T) {
	prefix := []byte("retained Mach-O bytes")
	truncated := testHashedCodeSignature(prefix, 2, 32, 0, 0)
	truncated = truncated[:len(truncated)-1]
	binary.BigEndian.PutUint32(truncated[4:8], uint32(len(truncated)))
	binary.BigEndian.PutUint32(truncated[24:28], uint32(len(truncated)-20))
	tests := []struct {
		name      string
		signature []byte
		want      string
	}{
		{name: "unsupported hash", signature: testHashedCodeSignature(prefix, 99, 32, 0, 0), want: "unsupported hash type 99"},
		{name: "truncated table", signature: truncated, want: "hash table is truncated"},
		{name: "slot cap", signature: testHashedCodeSignature(prefix, 2, 32, 0, int(maxMachOCodeDirectorySlots)), want: "exceeds verification limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := append(append([]byte(nil), prefix...), test.signature...)
			var graph behavior.Graph
			extractCodeSignature(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "sample", Data: image}, testMachOFileWithCodeSignature(len(prefix), len(test.signature)), "arm64", image)
			if !hasArtifactProperty(graph.ArtifactProperties, "code-directory-page-integrity", "unknown", behavior.SupportDirect) {
				t.Fatalf("unknown integrity was not retained: %#v", graph.ArtifactProperties)
			}
			if len(graph.Coverage) != 1 || graph.Coverage[0].Status != "partial" || !strings.Contains(graph.Coverage[0].Detail, test.want) {
				t.Fatalf("missing precise partial coverage containing %q: %#v", test.want, graph.Coverage)
			}
		})
	}
}

func TestCodeDirectoryIntegrityRequiresCanonicalHashSizes(t *testing.T) {
	prefix := []byte("inert code bytes")
	for _, test := range []struct {
		name     string
		hashType byte
		hashSize byte
		valid    bool
	}{
		{name: "sha1", hashType: 1, hashSize: 20, valid: true},
		{name: "sha256", hashType: 2, hashSize: 32, valid: true},
		{name: "sha256 truncated", hashType: 3, hashSize: 20, valid: true},
		{name: "sha384", hashType: 4, hashSize: 48, valid: true},
		{name: "one byte sha256", hashType: 2, hashSize: 1},
		{name: "short sha1", hashType: 1, hashSize: 19},
		{name: "untruncated type 3", hashType: 3, hashSize: 32},
		{name: "short sha384", hashType: 4, hashSize: 32},
	} {
		t.Run(test.name, func(t *testing.T) {
			signature := testHashedCodeSignature(prefix, test.hashType, test.hashSize, 0, 0)
			image := append(append([]byte(nil), prefix...), signature...)
			var graph behavior.Graph
			extractCodeSignature(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "sample", Data: image}, testMachOFileWithCodeSignature(len(prefix), len(signature)), "arm64", image)
			want := "unknown"
			if test.valid {
				want = "valid"
			}
			if !hasArtifactProperty(graph.ArtifactProperties, "code-directory-page-integrity", want, behavior.SupportDirect) {
				t.Fatalf("integrity must be %q: %#v", want, graph.ArtifactProperties)
			}
			if !test.valid && (len(graph.Coverage) != 1 || !strings.Contains(graph.Coverage[0].Detail, "incompatible")) {
				t.Fatalf("noncanonical hash size lacked partial coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestCodeDirectoryScatterIntegrityRemainsUnknown(t *testing.T) {
	prefix := []byte("inert code bytes")
	signature := testHashedCodeSignature(prefix, 2, 32, 0, 0)
	// The existing contiguous hashes match, but a scatter vector changes
	// which file pages those slots describe and is not currently modeled.
	vectorStart := len(signature)
	signature = append(signature, make([]byte, 48)...)
	binary.BigEndian.PutUint32(signature[4:8], uint32(len(signature)))
	binary.BigEndian.PutUint32(signature[24:28], uint32(len(signature)-20))
	binary.BigEndian.PutUint32(signature[20+44:20+48], uint32(vectorStart-20))
	// One page at file offset zero followed by the count-zero sentinel.
	binary.BigEndian.PutUint32(signature[vectorStart:vectorStart+4], 1)
	image := append(append([]byte(nil), prefix...), signature...)
	var graph behavior.Graph
	extractCodeSignature(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "sample", Data: image}, testMachOFileWithCodeSignature(len(prefix), len(signature)), "arm64", image)
	if !hasArtifactProperty(graph.ArtifactProperties, "code-directory-page-integrity", "unknown", behavior.SupportDirect) ||
		len(graph.Coverage) != 1 || !strings.Contains(graph.Coverage[0].Detail, "scatter vectors") {
		t.Fatalf("unsupported scatter layout overclaimed integrity: properties=%#v coverage=%#v", graph.ArtifactProperties, graph.Coverage)
	}
}

func TestCMSSignatureRequiresSignedDataEnvelope(t *testing.T) {
	payload := testCMSSignedDataEnvelope()
	blob := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(blob[0:4], csMagicBlobWrapper)
	binary.BigEndian.PutUint32(blob[4:8], uint32(len(blob)))
	copy(blob[8:], payload)
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	parentEvidence := "ev-parent"

	var valid behavior.Graph
	parseCMSSignatureBlob(&valid, content, blob, "arm64", parentEvidence)
	if !hasArtifactProperty(valid.ArtifactProperties, "cms-signature-structure", "signed-data-envelope", behavior.SupportDirect) ||
		!hasArtifactProperty(valid.ArtifactProperties, "cms-signature-sha256", testSHA256Hex(payload), behavior.SupportDirect) {
		t.Fatalf("valid CMS envelope facts missing: properties=%#v coverage=%#v", valid.ArtifactProperties, valid.Coverage)
	}
	if len(valid.Coverage) != 0 {
		t.Fatalf("valid CMS envelope produced partial coverage: %#v", valid.Coverage)
	}

	malformed := append([]byte(nil), blob[:len(blob)-1]...)
	binary.BigEndian.PutUint32(malformed[4:8], uint32(len(malformed)))
	var invalid behavior.Graph
	parseCMSSignatureBlob(&invalid, content, malformed, "arm64", parentEvidence)
	if !hasArtifactProperty(invalid.ArtifactProperties, "cms-signature-structure", "malformed", behavior.SupportDirect) || len(invalid.Coverage) != 1 {
		t.Fatalf("malformed CMS envelope was overclaimed: properties=%#v coverage=%#v", invalid.ArtifactProperties, invalid.Coverage)
	}
	if hasArtifactPropertyKind(invalid.ArtifactProperties, "cms-signature-sha256") {
		t.Fatalf("malformed CMS envelope received a fingerprint: %#v", invalid.ArtifactProperties)
	}
}

func TestCMSSignedDataEnvelopeAcceptsBoundedBERIndefiniteLengths(t *testing.T) {
	payload := testCMSBERSignedDataEnvelope()
	if err := validateCMSSignedDataEnvelope(payload); err != nil {
		t.Fatalf("valid indefinite-length BER SignedData envelope rejected: %v", err)
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "missing outer eoc", data: payload[:len(payload)-2]},
		{name: "trailing data", data: append(append([]byte(nil), payload...), 0)},
		{name: "wrong oid", data: func() []byte { value := append([]byte(nil), payload...); value[12] ^= 1; return value }()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateCMSSignedDataEnvelope(test.data); err == nil {
				t.Fatal("malformed BER SignedData envelope was accepted")
			}
		})
	}
}

func TestCMSBERParserEnforcesDepthAndElementBudgets(t *testing.T) {
	deep := []byte{0x02, 0x01, 0x01}
	for range maxCMSBERDepth + 1 {
		deep = append([]byte{0x30, 0x80}, append(deep, 0, 0)...)
	}
	elements := 0
	if _, err := parseCMSBERElement(deep, 0, 0, &elements); err == nil || !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("deep BER input did not hit depth limit: %v", err)
	}

	elements = maxCMSBERElements
	if _, err := parseCMSBERElement([]byte{0x02, 0x01, 0x01}, 0, 0, &elements); err == nil || !strings.Contains(err.Error(), "element count exceeds") {
		t.Fatalf("BER element budget was not enforced: %v", err)
	}
}

func testHashedCodeSignature(prefix []byte, hashType, hashSize, pageExponent byte, slotAdjustment int) []byte {
	pageSize := len(prefix)
	if pageExponent != 0 {
		pageSize = 1 << pageExponent
	}
	codeSlots := 0
	if len(prefix) > 0 {
		codeSlots = (len(prefix) + pageSize - 1) / pageSize
	}
	declaredSlots := codeSlots + slotAdjustment
	if declaredSlots < 0 {
		declaredSlots = 0
	}
	identifier := []byte("com.example.integrity-test\x00")
	hashOffset := 48 + len(identifier)
	hashTableSlots := codeSlots
	if slotAdjustment < 0 && hashTableSlots > 0 {
		hashTableSlots--
	}
	codeDirectory := make([]byte, hashOffset+hashTableSlots*int(hashSize))
	binary.BigEndian.PutUint32(codeDirectory[0:4], csMagicCodeDirectory)
	binary.BigEndian.PutUint32(codeDirectory[4:8], uint32(len(codeDirectory)))
	binary.BigEndian.PutUint32(codeDirectory[8:12], 0x20100)
	binary.BigEndian.PutUint32(codeDirectory[12:16], 0x2)
	binary.BigEndian.PutUint32(codeDirectory[16:20], uint32(hashOffset))
	binary.BigEndian.PutUint32(codeDirectory[20:24], 48)
	binary.BigEndian.PutUint32(codeDirectory[28:32], uint32(declaredSlots))
	binary.BigEndian.PutUint32(codeDirectory[32:36], uint32(len(prefix)))
	codeDirectory[36], codeDirectory[37], codeDirectory[39] = hashSize, hashType, pageExponent
	copy(codeDirectory[48:], identifier)
	for slot := 0; slot < hashTableSlots; slot++ {
		start, end := slot*pageSize, (slot+1)*pageSize
		if end > len(prefix) {
			end = len(prefix)
		}
		digest := codeDirectoryDigest(hashType, prefix[start:end])
		if len(digest) >= int(hashSize) {
			copy(codeDirectory[hashOffset+slot*int(hashSize):], digest[:hashSize])
		}
	}

	const indexEnd = 20
	signature := make([]byte, indexEnd+len(codeDirectory))
	binary.BigEndian.PutUint32(signature[0:4], csMagicSuperBlob)
	binary.BigEndian.PutUint32(signature[4:8], uint32(len(signature)))
	binary.BigEndian.PutUint32(signature[8:12], 1)
	binary.BigEndian.PutUint32(signature[12:16], csSlotCodeDirectory)
	binary.BigEndian.PutUint32(signature[16:20], indexEnd)
	copy(signature[indexEnd:], codeDirectory)
	return signature
}

func testCMSSignedDataEnvelope() []byte {
	return []byte{
		0x30, 0x12,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
		0xa0, 0x05,
		0x30, 0x03, 0x02, 0x01, 0x01,
	}
}

func testCMSBERSignedDataEnvelope() []byte {
	return []byte{
		0x30, 0x80,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
		0xa0, 0x80,
		0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
}

func testSHA256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(digest)*2)
	for index, value := range digest {
		out[index*2], out[index*2+1] = alphabet[value>>4], alphabet[value&0xf]
	}
	return string(out)
}

func hasArtifactPropertyKind(items []behavior.ArtifactProperty, kind string) bool {
	for _, item := range items {
		if item.Kind == kind {
			return true
		}
	}
	return false
}

func TestMalformedIndexedCodeDirectoryReportsPartialCoverage(t *testing.T) {
	for _, short := range []bool{false, true} {
		signature := testHashedCodeSignature([]byte("control"), 2, 32, 0, 0)
		if short {
			binary.BigEndian.PutUint32(signature[24:28], 8)
		} else {
			binary.BigEndian.PutUint32(signature[20:24], 0x12345678)
		}
		var graph behavior.Graph
		absent := parseCodeSignatureBlobs(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "sample"}, signature, []byte("control"), "arm64", "")
		if absent || len(graph.Coverage) != 1 || graph.Coverage[0].Status != "partial" || graph.Coverage[0].AnalysisArea != "macho-code-signature/arm64" {
			t.Fatalf("malformed signature lost coverage: absent=%v coverage=%#v", absent, graph.Coverage)
		}
		if hasArtifactProperty(graph.ArtifactProperties, "code-directory-page-integrity", "valid", behavior.SupportDirect) {
			t.Fatal("malformed CodeDirectory acquired valid integrity")
		}
	}
}

func TestUnrecognizedCodeSignatureReportsPartialCoverage(t *testing.T) {
	shortDirectory := make([]byte, 8)
	binary.BigEndian.PutUint32(shortDirectory[:4], csMagicCodeDirectory)
	binary.BigEndian.PutUint32(shortDirectory[4:], 8)
	for _, data := range [][]byte{[]byte("invalid"), make([]byte, 8), shortDirectory} {
		var graph behavior.Graph
		absent := parseCodeSignatureBlobs(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "sample"}, data, nil, "arm64", "")
		if absent || !hasPartialCoverageScope(graph.Coverage, "macho-code-signature/arm64") {
			t.Fatalf("invalid signature lost coverage: absent=%v coverage=%#v", absent, graph.Coverage)
		}
	}
}
