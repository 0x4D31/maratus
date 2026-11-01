package buildinfo

import "testing"

func TestInfoString(t *testing.T) {
	tests := []struct {
		name string
		info Info
		want string
	}{
		{name: "version only", info: Info{Version: "v0.1.0"}, want: "v0.1.0"},
		{name: "commit", info: Info{Version: "v0.1.0", Commit: "0123456789abcdef"}, want: "v0.1.0 (0123456789ab)"},
		{name: "dirty", info: Info{Version: "dev", Commit: "0123456", Modified: true}, want: "dev (0123456-dirty)"},
		{name: "empty", info: Info{}, want: "dev"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.info.String(); got != test.want {
				t.Fatalf("String() = %q, want %q", got, test.want)
			}
		})
	}
}
