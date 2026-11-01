package extract

import (
	"slices"
	"strings"
	"testing"
)

func TestExactPythonArgumentsIsTypedExactAndBounded(t *testing.T) {
	got, limited, malformed := exactPythonArguments(`first, nested(1, [2, 3]), "x,y",`, 4)
	if limited || malformed || !slices.Equal(got, []string{"first", "nested(1, [2, 3])", `"x,y"`}) {
		t.Fatalf("valid typed arguments = (%#v, limited=%v, malformed=%v)", got, limited, malformed)
	}
	for name, value := range map[string]string{
		"leading empty":       `, first`,
		"interior empty":      `first, , second`,
		"mismatched typed":    `first, ([)]`,
		"unterminated quote":  `first, "second`,
		"top-level comment":   `first, # second`,
		"top-level statement": `first; second`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, limited, malformed := exactPythonArguments(value, 4); limited || !malformed {
				t.Fatalf("malformed arguments accepted: %q (limited=%v malformed=%v)", value, limited, malformed)
			}
		})
	}
	if _, limited, malformed := exactPythonArguments(`first, second, third`, 2); !limited || malformed {
		t.Fatalf("argument cardinality was not bounded: limited=%v malformed=%v", limited, malformed)
	}
	hostile := strings.Repeat("(", maxTextStringExpressionDepth+1) + "x" + strings.Repeat(")", maxTextStringExpressionDepth+1)
	if _, limited, malformed := exactPythonArguments(hostile, 4); !limited || malformed {
		t.Fatalf("argument nesting was not bounded: limited=%v malformed=%v", limited, malformed)
	}
}
