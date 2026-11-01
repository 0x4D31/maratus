package artifact

import (
	"bytes"
	"encoding/binary"
)

const (
	javaClassHeaderSize   = 10
	javaClassMinimumMajor = 45
)

// isJavaClass validates the bounded ClassFile structure needed to distinguish
// Java bytecode from the colliding big-endian fat Mach-O magic. It does not
// interpret bytecode or attributes.
func isJavaClass(data []byte) bool {
	if len(data) < javaClassHeaderSize || !bytes.Equal(data[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return false
	}

	reader := javaClassReader{data: data, offset: 4}
	if _, ok := reader.readU2(); !ok { // minor_version
		return false
	}
	major, ok := reader.readU2()
	if !ok || major < javaClassMinimumMajor {
		return false
	}
	constantPoolCount, ok := reader.readU2()
	if !ok || constantPoolCount < 2 {
		return false
	}
	for index := uint16(1); index < constantPoolCount; index++ {
		tag, ok := reader.readU1()
		if !ok {
			return false
		}
		switch tag {
		case 1: // CONSTANT_Utf8
			length, ok := reader.readU2()
			if !ok || !reader.skip(uint64(length)) {
				return false
			}
		case 3, 4: // CONSTANT_Integer, CONSTANT_Float
			if !reader.skip(4) {
				return false
			}
		case 5, 6: // CONSTANT_Long, CONSTANT_Double
			if index+1 >= constantPoolCount || !reader.skip(8) {
				return false
			}
			index++
		case 7, 8, 16, 19, 20: // one u2 index
			if !reader.skip(2) {
				return false
			}
		case 9, 10, 11, 12, 17, 18: // two u2 indexes
			if !reader.skip(4) {
				return false
			}
		case 15: // CONSTANT_MethodHandle
			if !reader.skip(3) {
				return false
			}
		default:
			return false
		}
	}

	if !reader.skip(2) { // access_flags
		return false
	}
	thisClass, ok := reader.readU2()
	if !ok || thisClass == 0 || thisClass >= constantPoolCount {
		return false
	}
	superClass, ok := reader.readU2()
	if !ok || superClass >= constantPoolCount {
		return false
	}
	interfacesCount, ok := reader.readU2()
	if !ok || !reader.skip(uint64(interfacesCount)*2) {
		return false
	}
	if !reader.readMembers(constantPoolCount) { // fields
		return false
	}
	if !reader.readMembers(constantPoolCount) { // methods
		return false
	}
	return reader.readAttributes(constantPoolCount) && reader.offset == len(reader.data)
}

type javaClassReader struct {
	data   []byte
	offset int
}

func (r *javaClassReader) remaining() int {
	return len(r.data) - r.offset
}

func (r *javaClassReader) skip(size uint64) bool {
	if size > uint64(r.remaining()) {
		return false
	}
	r.offset += int(size)
	return true
}

func (r *javaClassReader) readU1() (byte, bool) {
	if r.remaining() < 1 {
		return 0, false
	}
	value := r.data[r.offset]
	r.offset++
	return value, true
}

func (r *javaClassReader) readU2() (uint16, bool) {
	if r.remaining() < 2 {
		return 0, false
	}
	value := binary.BigEndian.Uint16(r.data[r.offset : r.offset+2])
	r.offset += 2
	return value, true
}

func (r *javaClassReader) readU4() (uint32, bool) {
	if r.remaining() < 4 {
		return 0, false
	}
	value := binary.BigEndian.Uint32(r.data[r.offset : r.offset+4])
	r.offset += 4
	return value, true
}

func (r *javaClassReader) readMembers(constantPoolCount uint16) bool {
	count, ok := r.readU2()
	if !ok || int(count) > r.remaining()/8 {
		return false
	}
	for range count {
		if !r.skip(2) { // access_flags
			return false
		}
		nameIndex, ok := r.readU2()
		if !ok || nameIndex == 0 || nameIndex >= constantPoolCount {
			return false
		}
		descriptorIndex, ok := r.readU2()
		if !ok || descriptorIndex == 0 || descriptorIndex >= constantPoolCount {
			return false
		}
		if !r.readAttributes(constantPoolCount) {
			return false
		}
	}
	return true
}

func (r *javaClassReader) readAttributes(constantPoolCount uint16) bool {
	count, ok := r.readU2()
	if !ok || int(count) > r.remaining()/6 {
		return false
	}
	for range count {
		nameIndex, ok := r.readU2()
		if !ok || nameIndex == 0 || nameIndex >= constantPoolCount {
			return false
		}
		length, ok := r.readU4()
		if !ok || !r.skip(uint64(length)) {
			return false
		}
	}
	return true
}
