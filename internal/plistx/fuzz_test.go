package plistx

import "testing"

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`<plist><dict><key>Label</key><string>com.example</string></dict></plist>`))
	f.Add([]byte("bplist00"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		_, _ = Decode(data)
	})
}
