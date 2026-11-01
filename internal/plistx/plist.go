package plistx

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"howett.net/plist"
)

type Dict map[string]any

const (
	maxPlistBytes                    = 4 << 20
	maxPlistDepth                    = 128
	maxPlistNodes                    = 65_536
	maxPlistReferences               = 262_144
	maxBinaryPlistMaterializedBytes  = 32 << 20
	binaryPlistScalarObjectOverhead  = 32
	binaryPlistUTF16AllocationFactor = 10
)

func Decode(data []byte) (Dict, error) {
	if len(data) > maxPlistBytes {
		return nil, fmt.Errorf("plist exceeds %d-byte limit", maxPlistBytes)
	}
	if err := preflightStructure(data); err != nil {
		return nil, err
	}

	var value any
	decoder := plist.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	normalized, err := normalize(value, 0, new(int))
	if err != nil {
		return nil, err
	}
	dict, ok := normalized.(Dict)
	if !ok {
		return nil, fmt.Errorf("plist root is not a dictionary")
	}
	return dict, nil
}

func String(dict Dict, key string) string {
	if dict == nil {
		return ""
	}
	return StringValue(dict[key])
}

func Strings(dict Dict, key string) []string {
	if dict == nil {
		return nil
	}
	return StringsValue(dict[key])
}

func Dicts(dict Dict, key string) []Dict {
	if dict == nil {
		return nil
	}
	items, ok := dict[key].([]any)
	if !ok {
		return nil
	}
	out := make([]Dict, 0, len(items))
	for _, item := range items {
		if child, ok := item.(Dict); ok {
			out = append(out, child)
		}
	}
	return out
}

func StringValue(value any) string {
	switch item := value.(type) {
	case string:
		return strings.TrimSpace(item)
	case []byte:
		return strings.TrimSpace(string(item))
	case int:
		return strconv.Itoa(item)
	case int64:
		return strconv.FormatInt(item, 10)
	case uint64:
		return strconv.FormatUint(item, 10)
	case bool:
		if item {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func StringsValue(value any) []string {
	switch item := value.(type) {
	case string:
		if text := strings.TrimSpace(item); text != "" {
			return []string{text}
		}
	case []any:
		out := make([]string, 0, len(item))
		for _, child := range item {
			if text := StringValue(child); text != "" {
				out = append(out, text)
			}
		}
		return out
	}
	return nil
}

func normalize(value any, depth int, nodes *int) (any, error) {
	*nodes++
	if *nodes > maxPlistNodes {
		return nil, fmt.Errorf("plist exceeds %d-value limit", maxPlistNodes)
	}

	switch item := value.(type) {
	case map[string]any:
		if depth >= maxPlistDepth {
			return nil, fmt.Errorf("plist exceeds nesting depth %d", maxPlistDepth)
		}
		out := make(Dict, len(item))
		for key, child := range item {
			normalized, err := normalize(child, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			out[key] = normalized
		}
		return out, nil
	case []any:
		if depth >= maxPlistDepth {
			return nil, fmt.Errorf("plist exceeds nesting depth %d", maxPlistDepth)
		}
		out := make([]any, 0, len(item))
		for _, child := range item {
			normalized, err := normalize(child, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			out = append(out, normalized)
		}
		return out, nil
	case []uint8:
		return []byte(item), nil
	default:
		return item, nil
	}
}

func preflightStructure(data []byte) error {
	if bytes.HasPrefix(data, []byte("bplist")) {
		return preflightBinary(data)
	}
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if len(trimmed) > 0 && trimmed[0] == '<' {
		return preflightXML(data)
	}
	return preflightOpenStep(data)
}

func preflightXML(data []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	collectionDepth := 0
	nodes := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("invalid XML plist: %w", err)
		}
		switch current := token.(type) {
		case xml.StartElement:
			nodes++
			if current.Name.Local == "dict" || current.Name.Local == "array" {
				collectionDepth++
			}
			if collectionDepth > maxPlistDepth {
				return fmt.Errorf("plist exceeds nesting depth %d", maxPlistDepth)
			}
			if nodes > maxPlistNodes {
				return fmt.Errorf("plist exceeds %d-value limit", maxPlistNodes)
			}
		case xml.EndElement:
			if current.Name.Local == "dict" || current.Name.Local == "array" {
				collectionDepth--
			}
		}
	}
}

func preflightOpenStep(data []byte) error {
	depth := 0
	nodes := 0
	inString := false
	escaped := false
	inLineComment := false
	inBlockComment := false
	inData := false

	for i := 0; i < len(data); i++ {
		current := data[i]
		if inLineComment {
			if current == '\n' || current == '\r' {
				inLineComment = false
			}
			continue
		}
		if inBlockComment {
			if current == '*' && i+1 < len(data) && data[i+1] == '/' {
				inBlockComment = false
				i++
			}
			continue
		}
		if inString {
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		if inData {
			if current == '>' {
				inData = false
			}
			continue
		}

		if current == '/' && i+1 < len(data) {
			switch data[i+1] {
			case '/':
				inLineComment = true
				i++
				continue
			case '*':
				inBlockComment = true
				i++
				continue
			}
		}

		switch current {
		case '"':
			inString = true
		case '<':
			inData = true
		case '{', '(':
			depth++
			nodes++
			if depth > maxPlistDepth {
				return fmt.Errorf("plist exceeds nesting depth %d", maxPlistDepth)
			}
		case '}', ')':
			if depth > 0 {
				depth--
			}
		case '=', ',':
			nodes++
		}
		if nodes > maxPlistNodes {
			return fmt.Errorf("plist exceeds %d-value limit", maxPlistNodes)
		}
	}
	return nil
}

type binaryPlistFrame struct {
	id       uint64
	children []uint64
	next     int
}

func preflightBinary(data []byte) error {
	if len(data) < 40 {
		return fmt.Errorf("invalid binary plist: not enough data")
	}
	trailer := data[len(data)-32:]
	offsetSize := uint64(trailer[6])
	refSize := uint64(trailer[7])
	numObjects := binary.BigEndian.Uint64(trailer[8:16])
	topObject := binary.BigEndian.Uint64(trailer[16:24])
	offsetTable := binary.BigEndian.Uint64(trailer[24:32])
	trailerOffset := uint64(len(data) - 32)

	if !supportedBinaryIntegerWidth(offsetSize) || !supportedBinaryIntegerWidth(refSize) {
		return fmt.Errorf("invalid binary plist: unsupported offset or reference width")
	}
	if numObjects == 0 || numObjects > maxPlistNodes {
		return fmt.Errorf("binary plist exceeds %d-object limit", maxPlistNodes)
	}
	if topObject >= numObjects || offsetTable < 8 || offsetTable >= trailerOffset {
		return fmt.Errorf("invalid binary plist trailer")
	}
	tableBytes, ok := checkedMultiply(numObjects, offsetSize)
	if !ok || offsetTable+tableBytes != trailerOffset {
		return fmt.Errorf("invalid binary plist offset table")
	}

	offsets := make([]uint64, int(numObjects))
	for id := uint64(0); id < numObjects; id++ {
		position := offsetTable + id*offsetSize
		offset, ok := readBigEndian(data, position, offsetSize)
		if !ok || offset < 8 || offset >= offsetTable {
			return fmt.Errorf("invalid binary plist object offset")
		}
		offsets[id] = offset
	}

	colors := make([]uint8, int(numObjects))
	expandedSizes := make([]uint64, int(numObjects))
	frames := make([]binaryPlistFrame, 0, maxPlistDepth)
	references := 0
	var materializedBytes uint64
	push := func(id uint64) error {
		if len(frames) >= maxPlistDepth {
			return fmt.Errorf("plist exceeds nesting depth %d", maxPlistDepth)
		}
		children, scalarBytes, err := binaryObject(data, offsets[id], offsetTable, refSize, numObjects)
		if err != nil {
			return err
		}
		if scalarBytes > maxBinaryPlistMaterializedBytes-materializedBytes {
			return fmt.Errorf("binary plist exceeds materialized scalar byte limit %d", maxBinaryPlistMaterializedBytes)
		}
		materializedBytes += scalarBytes
		references += len(children)
		if references > maxPlistReferences {
			return fmt.Errorf("plist exceeds structural work limit %d", maxPlistReferences)
		}
		colors[id] = 1
		frames = append(frames, binaryPlistFrame{id: id, children: children})
		return nil
	}
	if err := push(topObject); err != nil {
		return err
	}
	for len(frames) > 0 {
		frame := &frames[len(frames)-1]
		if frame.next == len(frame.children) {
			expandedSize := uint64(1)
			for _, child := range frame.children {
				childSize := expandedSizes[child]
				if childSize > maxPlistNodes || expandedSize > maxPlistNodes-childSize {
					return fmt.Errorf("binary plist exceeds expanded value limit %d", maxPlistNodes)
				}
				expandedSize += childSize
			}
			expandedSizes[frame.id] = expandedSize
			colors[frame.id] = 2
			frames = frames[:len(frames)-1]
			continue
		}
		child := frame.children[frame.next]
		frame.next++
		switch colors[child] {
		case 0:
			if err := push(child); err != nil {
				return err
			}
		case 1:
			return fmt.Errorf("invalid binary plist: self-referential collection")
		}
	}
	return nil
}

// binaryObject validates one reachable object and estimates the bytes a typed
// decoder can materialize for it. The estimate is charged per object ID, not
// per unique offset: binary plists can give many distinct IDs the same offset,
// while howett/plist caches decoded values by ID and therefore reparses and
// reallocates each alias.
func binaryObject(data []byte, offset, tableOffset, refSize, numObjects uint64) ([]uint64, uint64, error) {
	if offset >= uint64(len(data)) {
		return nil, 0, fmt.Errorf("invalid binary plist object")
	}
	tag := data[offset]
	kind := tag & 0xf0
	switch kind {
	case 0x00:
		if tag != 0x08 && tag != 0x09 {
			return nil, 0, fmt.Errorf("invalid binary plist null/boolean tag")
		}
		return nil, binaryPlistScalarObjectOverhead, nil
	case 0x10:
		exponent := tag & 0x0f
		if exponent > 4 || !binaryExtentWithin(offset+1, uint64(1)<<exponent, tableOffset) {
			return nil, 0, fmt.Errorf("invalid binary plist integer extent")
		}
		return nil, binaryPlistScalarObjectOverhead, nil
	case 0x20:
		if tag != 0x22 && tag != 0x23 || !binaryExtentWithin(offset+1, uint64(1)<<(tag&0x0f), tableOffset) {
			return nil, 0, fmt.Errorf("invalid binary plist real extent")
		}
		return nil, binaryPlistScalarObjectOverhead, nil
	case 0x30:
		if tag != 0x33 || !binaryExtentWithin(offset+1, 8, tableOffset) {
			return nil, 0, fmt.Errorf("invalid binary plist date extent")
		}
		return nil, binaryPlistScalarObjectOverhead, nil
	case 0x40, 0x50, 0x60:
		count, start, err := binaryCount(data, offset, tableOffset)
		if err != nil {
			return nil, 0, err
		}
		length := count
		if kind == 0x60 {
			var ok bool
			length, ok = checkedMultiply(count, 2)
			if !ok {
				return nil, 0, fmt.Errorf("invalid binary plist UTF-16 string extent")
			}
		}
		if !binaryExtentWithin(start, length, tableOffset) {
			name := "data"
			switch kind {
			case 0x50:
				name = "ASCII string"
			case 0x60:
				name = "UTF-16 string"
			}
			return nil, 0, fmt.Errorf("invalid binary plist %s extent", name)
		}
		materialized := count
		if kind == 0x60 {
			// howett/plist allocates the UTF-16 input, decoded rune slice, and
			// final UTF-8 string. Ten bytes per code unit safely covers their
			// worst-case aggregate payload before ordinary object overhead.
			var ok bool
			materialized, ok = checkedMultiply(count, binaryPlistUTF16AllocationFactor)
			if !ok {
				return nil, 0, fmt.Errorf("invalid binary plist UTF-16 materialized size")
			}
		}
		if materialized > ^uint64(0)-binaryPlistScalarObjectOverhead {
			return nil, 0, fmt.Errorf("invalid binary plist scalar materialized size")
		}
		return nil, materialized + binaryPlistScalarObjectOverhead, nil
	case 0x80:
		width := uint64(tag&0x0f) + 1
		if !supportedBinaryIntegerWidth(width) || !binaryExtentWithin(offset+1, width, tableOffset) {
			return nil, 0, fmt.Errorf("invalid binary plist UID extent")
		}
		return nil, binaryPlistScalarObjectOverhead, nil
	case 0xa0, 0xd0:
		// Collection references are validated below.
	default:
		return nil, 0, fmt.Errorf("invalid binary plist object tag 0x%02x", tag)
	}
	count, start, err := binaryCount(data, offset, tableOffset)
	if err != nil {
		return nil, 0, err
	}
	if kind == 0xd0 {
		var ok bool
		count, ok = checkedMultiply(count, 2)
		if !ok {
			return nil, 0, fmt.Errorf("invalid binary plist dictionary size")
		}
	}
	if count > maxPlistReferences {
		return nil, 0, fmt.Errorf("plist exceeds structural work limit %d", maxPlistReferences)
	}
	bytesNeeded, ok := checkedMultiply(count, refSize)
	if !ok || start > tableOffset || bytesNeeded > tableOffset-start {
		return nil, 0, fmt.Errorf("invalid binary plist collection")
	}
	children := make([]uint64, int(count))
	for index := uint64(0); index < count; index++ {
		child, ok := readBigEndian(data, start+index*refSize, refSize)
		if !ok || child >= numObjects {
			return nil, 0, fmt.Errorf("invalid binary plist object reference")
		}
		children[index] = child
	}
	return children, 0, nil
}

func binaryExtentWithin(start, length, limit uint64) bool {
	return start <= limit && length <= limit-start
}

func supportedBinaryIntegerWidth(width uint64) bool {
	return width == 1 || width == 2 || width == 4 || width == 8
}

func binaryCount(data []byte, offset, tableOffset uint64) (uint64, uint64, error) {
	tag := data[offset]
	if tag&0x0f != 0x0f {
		return uint64(tag & 0x0f), offset + 1, nil
	}
	integerOffset := offset + 1
	if integerOffset >= tableOffset || integerOffset >= uint64(len(data)) {
		return 0, 0, fmt.Errorf("invalid binary plist collection size")
	}
	integerTag := data[integerOffset]
	if integerTag&0xf0 != 0x10 || integerTag&0x0f > 3 {
		return 0, 0, fmt.Errorf("invalid binary plist collection size")
	}
	width := uint64(1) << (integerTag & 0x0f)
	valueOffset := integerOffset + 1
	value, ok := readBigEndian(data, valueOffset, width)
	if !ok || valueOffset+width > tableOffset {
		return 0, 0, fmt.Errorf("invalid binary plist collection size")
	}
	return value, valueOffset + width, nil
}

func readBigEndian(data []byte, offset, width uint64) (uint64, bool) {
	if width == 0 || width > 8 || offset > uint64(len(data)) || width > uint64(len(data))-offset {
		return 0, false
	}
	var value uint64
	for _, current := range data[offset : offset+width] {
		value = value<<8 | uint64(current)
	}
	return value, true
}

func checkedMultiply(left, right uint64) (uint64, bool) {
	if left != 0 && right > ^uint64(0)/left {
		return 0, false
	}
	return left * right, true
}
