package extract

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxMachOCMSSignatureBytes = 16 << 20
	maxCMSBERDepth            = 32
	maxCMSBERElements         = 65536
)

var cmsSignedDataOIDBytes = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}

func verifyCodeDirectoryPages(graph *behavior.Graph, content artifact.Content, directory, image []byte, arch, parentEvidence string) {
	if len(directory) < 44 {
		return
	}
	version := binary.BigEndian.Uint32(directory[8:12])
	hashOffset := uint64(binary.BigEndian.Uint32(directory[16:20]))
	codeSlots := uint64(binary.BigEndian.Uint32(directory[28:32]))
	codeLimit := uint64(binary.BigEndian.Uint32(directory[32:36]))
	hashSize := uint64(directory[36])
	hashType := directory[37]
	pageExponent := directory[39]
	extendedCodeLimitMissing := version >= 0x20300 && len(directory) < 64
	if version >= 0x20300 && !extendedCodeLimitMissing {
		if extended := binary.BigEndian.Uint64(directory[56:64]); extended != 0 {
			codeLimit = extended
		}
	}
	algorithm, digestSize := codeDirectoryHashAlgorithm(hashType)
	metadataEvidence := graph.AddEvidence(behavior.Evidence{
		NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-code-signature", Kind: "code-directory-hash",
		Value: fmt.Sprintf("algorithm=%s hash_size=%d code_slots=%d code_limit=%d page_exponent=%d", algorithm, hashSize, codeSlots, codeLimit, pageExponent), Arch: arch,
	})
	graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "code-directory-hash-algorithm", Value: algorithm, EvidenceIDs: []string{metadataEvidence, parentEvidence}, Support: behavior.SupportDirect})
	unknown := func(reason string) {
		emitCodeDirectoryIntegrity(graph, content, arch, parentEvidence, algorithm, "unknown", reason)
		addPartialCoverageOnce(graph, content.NodeID, "macho-code-signature-integrity/"+arch, reason)
	}
	if extendedCodeLimitMissing {
		unknown(fmt.Sprintf("CodeDirectory version %#x is truncated before its 64-bit code limit", version))
		return
	}
	if codeSlots == 0 && codeLimit == 0 {
		return
	}
	if version >= 0x20100 {
		if len(directory) < 48 {
			unknown(fmt.Sprintf("CodeDirectory version %#x is truncated before its scatter offset", version))
			return
		}
		if binary.BigEndian.Uint32(directory[44:48]) != 0 {
			unknown("CodeDirectory scatter vectors are unsupported for page integrity verification")
			return
		}
	}
	if digestSize == 0 {
		unknown(fmt.Sprintf("CodeDirectory uses unsupported hash type %d", hashType))
		return
	}
	if hashSize != uint64(digestSize) {
		unknown(fmt.Sprintf("CodeDirectory hash size %d is incompatible with %s", hashSize, algorithm))
		return
	}
	if codeSlots > maxMachOCodeDirectorySlots {
		unknown(fmt.Sprintf("CodeDirectory code-slot count %d exceeds verification limit %d", codeSlots, maxMachOCodeDirectorySlots))
		return
	}
	if codeLimit > uint64(len(image)) {
		unknown(fmt.Sprintf("CodeDirectory code limit %d exceeds the %d bytes preceding LC_CODE_SIGNATURE", codeLimit, len(image)))
		return
	}
	pageSize, expectedSlots, ok := codeDirectoryPageLayout(codeLimit, pageExponent)
	if !ok {
		unknown(fmt.Sprintf("CodeDirectory page exponent %d is unsupported", pageExponent))
		return
	}
	if codeSlots != expectedSlots {
		unknown(fmt.Sprintf("CodeDirectory declares %d code slots but code limit and page size require %d", codeSlots, expectedSlots))
		return
	}
	hashBytes := codeSlots * hashSize
	if hashOffset < 44 || hashOffset > uint64(len(directory)) || hashBytes > uint64(len(directory))-hashOffset {
		unknown("CodeDirectory code-slot hash table is truncated")
		return
	}
	for slot := uint64(0); slot < codeSlots; slot++ {
		start := slot * pageSize
		end := start + pageSize
		if end > codeLimit {
			end = codeLimit
		}
		digest := codeDirectoryDigest(hashType, image[int(start):int(end)])
		expectedStart := hashOffset + slot*hashSize
		expected := directory[int(expectedStart):int(expectedStart+hashSize)]
		if !equalBytes(expected, digest[:hashSize]) {
			emitCodeDirectoryIntegrity(graph, content, arch, parentEvidence, algorithm, "invalid", fmt.Sprintf("code slot %d does not match the retained Mach-O bytes", slot))
			return
		}
	}
	emitCodeDirectoryIntegrity(graph, content, arch, parentEvidence, algorithm, "valid", fmt.Sprintf("all %d CodeDirectory code slots match the retained Mach-O bytes", codeSlots))
}

func codeDirectoryHashAlgorithm(hashType uint8) (string, int) {
	switch hashType {
	case 1:
		return "sha1", sha1.Size
	case 2:
		return "sha256", sha256.Size
	case 3:
		return "sha256-truncated", sha1.Size
	case 4:
		return "sha384", sha512.Size384
	default:
		return fmt.Sprintf("unknown-%d", hashType), 0
	}
}

func codeDirectoryDigest(hashType uint8, data []byte) []byte {
	switch hashType {
	case 1:
		digest := sha1.Sum(data)
		return digest[:]
	case 2, 3:
		digest := sha256.Sum256(data)
		return digest[:]
	case 4:
		digest := sha512.Sum384(data)
		return digest[:]
	default:
		return nil
	}
}

func codeDirectoryPageLayout(codeLimit uint64, exponent uint8) (pageSize, slots uint64, ok bool) {
	if codeLimit == 0 {
		return 0, 0, true
	}
	if exponent == 0 {
		return codeLimit, 1, true
	}
	if exponent > 30 {
		return 0, 0, false
	}
	pageSize = uint64(1) << exponent
	return pageSize, (codeLimit + pageSize - 1) / pageSize, true
}

func emitCodeDirectoryIntegrity(graph *behavior.Graph, content artifact.Content, arch, parentEvidence, algorithm, result, detail string) {
	evidence := graph.AddEvidence(behavior.Evidence{
		NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-code-signature", Kind: "code-directory-page-integrity",
		Value: fmt.Sprintf("%s: %s (%s)", result, detail, algorithm), Arch: arch,
	})
	graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "code-directory-page-integrity", Value: result, EvidenceIDs: []string{evidence, parentEvidence}, Support: behavior.SupportDirect})
}

func parseCMSSignatureBlob(graph *behavior.Graph, content artifact.Content, blob []byte, arch, parentEvidence string) {
	value := "signed-data-envelope"
	reason := ""
	if len(blob) < 8 || binary.BigEndian.Uint32(blob[0:4]) != csMagicBlobWrapper || binary.BigEndian.Uint32(blob[4:8]) != uint32(len(blob)) {
		value, reason = "malformed", "embedded CMS signature wrapper is malformed"
	} else if len(blob)-8 > maxMachOCMSSignatureBytes {
		value, reason = "unknown", fmt.Sprintf("CMS payload exceeds parser limit %d bytes", maxMachOCMSSignatureBytes)
	} else if err := validateCMSSignedDataEnvelope(blob[8:]); err != nil {
		value, reason = "malformed", "embedded CMS signature is not a complete BER/DER ContentInfo/SignedData envelope: "+err.Error()
	}
	evidence := graph.AddEvidence(behavior.Evidence{
		NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-code-signature", Kind: "cms-signature",
		Value: fmt.Sprintf("embedded CMS signature structure %s", value), Arch: arch,
	})
	graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "cms-signature-structure", Value: value, EvidenceIDs: []string{evidence, parentEvidence}, Support: behavior.SupportDirect})
	if reason != "" {
		addPartialCoverageOnce(graph, content.NodeID, "macho-cms-signature/"+arch, reason)
		return
	}
	digest := sha256.Sum256(blob[8:])
	fingerprint := hex.EncodeToString(digest[:])
	fingerprintEvidence := graph.AddEvidence(behavior.Evidence{
		NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-code-signature", Kind: "cms-signature-sha256", Value: fingerprint, Arch: arch,
	})
	graph.AddArtifactProperty(behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "cms-signature-sha256", Value: fingerprint, EvidenceIDs: []string{fingerprintEvidence, parentEvidence}, Support: behavior.SupportDirect})
}

func validateCMSSignedDataEnvelope(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty payload")
	}
	elements := 0
	contentInfo, err := parseCMSBERElement(data, 0, 0, &elements)
	if err != nil {
		return err
	}
	if contentInfo.end != len(data) || contentInfo.class != 0 || contentInfo.tag != 16 || !contentInfo.constructed {
		return fmt.Errorf("contentInfo is not one complete sequence")
	}
	contentType, err := parseCMSBERElement(data, contentInfo.contentStart, 1, &elements)
	if err != nil {
		return err
	}
	if contentType.class != 0 || contentType.tag != 6 || contentType.constructed || !equalBytes(data[contentType.contentStart:contentType.contentEnd], cmsSignedDataOIDBytes) {
		return fmt.Errorf("content type is not signedData")
	}
	explicitContent, err := parseCMSBERElement(data, contentType.end, 1, &elements)
	if err != nil {
		return err
	}
	if explicitContent.end != contentInfo.contentEnd || explicitContent.class != 2 || explicitContent.tag != 0 || !explicitContent.constructed {
		return fmt.Errorf("signedData content is not one explicit field")
	}
	signedData, err := parseCMSBERElement(data, explicitContent.contentStart, 2, &elements)
	if err != nil {
		return err
	}
	if signedData.end != explicitContent.contentEnd || signedData.class != 0 || signedData.tag != 16 || !signedData.constructed {
		return fmt.Errorf("signedData content is not one complete sequence")
	}
	return nil
}

type cmsBERElement struct {
	class        byte
	tag          uint64
	constructed  bool
	contentStart int
	contentEnd   int
	end          int
}

func parseCMSBERElement(data []byte, offset, depth int, elements *int) (cmsBERElement, error) {
	if depth > maxCMSBERDepth {
		return cmsBERElement{}, fmt.Errorf("BER nesting exceeds limit %d", maxCMSBERDepth)
	}
	if elements == nil || *elements >= maxCMSBERElements {
		return cmsBERElement{}, fmt.Errorf("BER element count exceeds limit %d", maxCMSBERElements)
	}
	(*elements)++
	if offset < 0 || offset >= len(data) {
		return cmsBERElement{}, fmt.Errorf("BER element is truncated")
	}
	identifier := data[offset]
	element := cmsBERElement{class: identifier >> 6, constructed: identifier&0x20 != 0, tag: uint64(identifier & 0x1f)}
	cursor := offset + 1
	if element.tag == 0x1f {
		element.tag = 0
		for octets := 0; ; octets++ {
			if cursor >= len(data) || octets >= 9 {
				return cmsBERElement{}, fmt.Errorf("BER high-tag identifier is truncated or excessive")
			}
			value := data[cursor]
			cursor++
			if element.tag > (^uint64(0) >> 7) {
				return cmsBERElement{}, fmt.Errorf("BER tag overflows uint64")
			}
			element.tag = element.tag<<7 | uint64(value&0x7f)
			if value&0x80 == 0 {
				break
			}
		}
	}
	if cursor >= len(data) {
		return cmsBERElement{}, fmt.Errorf("BER length is truncated")
	}
	lengthByte := data[cursor]
	cursor++
	element.contentStart = cursor
	if lengthByte == 0x80 {
		if !element.constructed {
			return cmsBERElement{}, fmt.Errorf("primitive BER element uses indefinite length")
		}
		for {
			if cursor+2 > len(data) {
				return cmsBERElement{}, fmt.Errorf("indefinite BER element lacks end-of-contents")
			}
			if data[cursor] == 0 && data[cursor+1] == 0 {
				element.contentEnd, element.end = cursor, cursor+2
				return element, nil
			}
			child, err := parseCMSBERElement(data, cursor, depth+1, elements)
			if err != nil {
				return cmsBERElement{}, err
			}
			cursor = child.end
		}
	}
	length := uint64(lengthByte)
	if lengthByte&0x80 != 0 {
		octets := int(lengthByte & 0x7f)
		if octets == 0 || octets > 8 || cursor+octets > len(data) {
			return cmsBERElement{}, fmt.Errorf("BER long-form length is invalid or truncated")
		}
		length = 0
		for _, value := range data[cursor : cursor+octets] {
			if length > (^uint64(0) >> 8) {
				return cmsBERElement{}, fmt.Errorf("BER length overflows uint64")
			}
			length = length<<8 | uint64(value)
		}
		cursor += octets
		element.contentStart = cursor
	}
	if length > uint64(len(data)-cursor) {
		return cmsBERElement{}, fmt.Errorf("BER content is truncated")
	}
	element.contentEnd = cursor + int(length)
	element.end = element.contentEnd
	return element, nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}
