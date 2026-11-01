package artifact

import (
	"bytes"
	"compress/gzip"
	"debug/macho"
	"encoding/binary"
	"testing"
)

func FuzzDetectAndArchiveNames(f *testing.F) {
	for _, seed := range []string{
		"install.sh",
		"../evil.sh",
		"Scripts\\postinstall",
		"/absolute/path",
		"package.tgz!/package/scripts/install.js",
	} {
		f.Add(seed, []byte("#!/bin/sh\necho ok\n"))
	}
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		_, _ = cleanArchiveName(name)
		Detect(name, data, false)
		Detect(name, data, true)
	})
}

func FuzzParseCPIO(f *testing.F) {
	f.Add(testCPIONewc(map[string][]byte{"install.sh": []byte("#!/bin/sh\necho inert\n")}))
	f.Add(testCPIOOdc(map[string][]byte{"install.sh": []byte("#!/bin/sh\necho inert\n")}))
	f.Add([]byte("070701"))
	f.Add([]byte("07070700000000000000000000000000000000000000000000000000000000000000000000000000000000"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		_, _, _ = parseCPIO(data, Options{}.Normalized())
	})
}

func FuzzParseASARHeader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{4, 0, 0, 0, '{', '}', 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		_, _, _ = parseAsarHeader(data)
	})
}

func FuzzParseIndexedGzipBundle(f *testing.F) {
	f.Add([]byte("not an indexed gzip bundle"))
	f.Add(fuzzIndexedGzipBundleSeed())
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		_, _ = parseIndexedGzipBundle(data)
	})
}

func FuzzParseXAR(f *testing.F) {
	f.Add([]byte("xar!"))
	f.Add([]byte{0x78, 0x61, 0x72, 0x21, 0, 0, 0, 28})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		_, _, _ = parseXAR(data, Options{}.Normalized())
	})
}

func FuzzPreflightZIPDirectory(f *testing.F) {
	f.Add([]byte("not a zip"))
	f.Add([]byte{'P', 'K', 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = preflightZIPDirectory(data)
	})
}

func FuzzParseCArchives(f *testing.F) {
	f.Add([]byte("not a CArchive"))
	f.Add(append([]byte(nil), cArchiveCookieMagic...))
	f.Add(fuzzCArchiveSeed(cArchiveCookieLegacy))
	f.Add(fuzzCArchiveSeed(cArchiveCookieCurrent))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		_ = parseCArchives(data)
	})
}

func FuzzPreflightMachO(f *testing.F) {
	f.Add([]byte("not a Mach-O"))
	f.Add(testThinMachO())
	for _, seed := range []struct {
		order binary.ByteOrder
		is64  bool
	}{
		{order: binary.BigEndian},
		{order: binary.LittleEndian},
		{order: binary.BigEndian, is64: true},
		{order: binary.LittleEndian, is64: true},
	} {
		image := testThinMachO()
		binary.LittleEndian.PutUint32(image[4:8], uint32(macho.CpuArm64))
		f.Add(testFatMachO(seed.order, seed.is64, image))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		_, _ = PreflightMachO(data)
	})
}

func fuzzCArchiveSeed(layout cArchiveCookieLayout) []byte {
	record := make([]byte, 32)
	binary.BigEndian.PutUint32(record[0:4], uint32(len(record)))
	record[17] = 'x'
	copy(record[18:], "seed")
	cookieSize := cArchiveCookieSize(layout)
	cookie := make([]byte, cookieSize)
	copy(cookie, cArchiveCookieMagic)
	binary.BigEndian.PutUint32(cookie[8:12], uint32(len(record)+cookieSize))
	binary.BigEndian.PutUint32(cookie[12:16], 0)
	binary.BigEndian.PutUint32(cookie[16:20], uint32(len(record)))
	binary.BigEndian.PutUint32(cookie[20:24], 311)
	if layout == cArchiveCookieCurrent {
		copy(cookie[24:], "Python")
	}
	return append(record, cookie...)
}

func fuzzIndexedGzipBundleSeed() []byte {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("seed")); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	member := compressed.Bytes()
	out := make([]byte, indexedGzipBundleHeaderSize+indexedGzipRecordHeaderSize)
	copy(out[:5], "FUZZ0")
	out[5] = 1
	out[6] = 7
	binary.LittleEndian.PutUint64(out[7:15], 4)
	binary.LittleEndian.PutUint64(out[15:23], uint64(len(member)))
	return append(out, member...)
}
