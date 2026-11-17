package extract

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestExpandSimpleVarsPreservesSupportedInterpolationSyntax(t *testing.T) {
	tests := []struct {
		name     string
		language string
		line     string
		vars     map[string]string
		want     string
	}{
		{
			name:     "shell braced and unbraced",
			language: "shell",
			line:     `curl https://$HOST/${PAYLOAD} $HOSTNAME`,
			vars:     map[string]string{"HOST": "download.example", "PAYLOAD": "payload"},
			want:     `curl https://'download.example'/'payload' $HOSTNAME`,
		},
		{
			name:     "python identifier",
			language: "python",
			line:     `requests.get(endpoint)`,
			vars:     map[string]string{"endpoint": `"https://python.example/payload"`},
			want:     `requests.get("https://python.example/payload")`,
		},
		{
			name:     "javascript identifier",
			language: "javascript",
			line:     `fetch(endpoint)`,
			vars:     map[string]string{"endpoint": `"https://javascript.example/payload"`},
			want:     `fetch("https://javascript.example/payload")`,
		},
		{
			name:     "applescript identifier",
			language: "applescript",
			line:     `do shell script commandValue`,
			vars:     map[string]string{"commandValue": `"echo ready"`},
			want:     `do shell script "echo ready"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expandSimpleVars(tt.language, tt.line, tt.vars); got != tt.want {
				t.Fatalf("expandSimpleVars() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractTextVariableAndRequestScopesShadowGlobals(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: "scopes.py",
		Kind:        "script",
		MediaType:   "text/plain",
		Data: []byte(
			`import requests` + "\n" +
				`url = "https://global-scope.example/payload"` + "\n" +
				`response = requests.get(url)` + "\n" +
				`def run():` + "\n" +
				`    url = "https://local-scope.example/payload"` + "\n" +
				`    response = requests.get(url)` + "\n" +
				`    open("/tmp/local-payload", "wb").write(response.content)` + "\n" +
				`open("/tmp/global-payload", "wb").write(response.content)` + "\n",
		),
	}

	ExtractText(&graph, content)

	assertShellCommandNetwork(t, graph, "https://global-scope.example/payload")
	assertShellCommandNetwork(t, graph, "https://local-scope.example/payload")
	assertTextDownloadDestination(t, graph, "/tmp/global-payload", "https://global-scope.example/payload")
	assertTextDownloadDestination(t, graph, "/tmp/local-payload", "https://local-scope.example/payload")
}

func TestExtractTextFunctionParameterDoesNotInheritGlobalRequestBinding(t *testing.T) {
	source := `import requests` + "\n" +
		`response = requests.get("https://global-request.example/payload")` + "\n" +
		`def save(response):` + "\n" +
		`    open("/tmp/must-not-inherit", "wb").write(response.content)` + "\n"

	var graph behavior.Graph
	ExtractText(&graph, textVariableTestContent("request-parameter-shadow.py", source))

	assertShellCommandNetwork(t, graph, "https://global-request.example/payload")
	for _, operation := range graph.Operations {
		if output, ok := testOperationBinding(operation, behavior.ResourceRoleLocalOutput); ok &&
			output.Value == "/tmp/must-not-inherit" {
			t.Fatalf("function parameter inherited a module request binding: %#v", operation)
		}
	}
}

func TestExtractTextBoundsTrackedVariablesAndStopsBeforeLaterSemantics(t *testing.T) {
	var source strings.Builder
	for i := 0; i <= maxTextTrackedVariables; i++ {
		source.WriteString("variable_")
		source.WriteString(strconv.Itoa(i))
		source.WriteString(` = "value"`)
		source.WriteByte('\n')
	}
	source.WriteString(`requests.get("https://must-not-be-analyzed.example/payload")`)

	var graph behavior.Graph
	ExtractText(&graph, textVariableTestContent("variable-limit.py", source.String()))

	assertTextVariableCoverage(t, graph, "tracked variable limit")
	if len(graph.Operations) != 0 || len(graph.Network) != 0 {
		t.Fatalf("semantic analysis continued after the variable limit: operations=%#v network=%#v", graph.Operations, graph.Network)
	}
}

func TestExtractTextOversizedVariableSkipsOnlyItsAssignmentLine(t *testing.T) {
	oversized := strings.Repeat("x", maxTextVariableValueBytes+1) +
		` requests.get("https://inside-oversized-assignment.example/")`
	source := `import requests` + "\n" +
		`response = requests.get("https://stale-response.example/payload")` + "\n" +
		`response = "` + oversized + `"` + "\n" +
		`open("/tmp/must-not-inherit", "wb").write(response.content)` + "\n" +
		`requests.get("https://later-independent.example/payload")` + "\n"

	var graph behavior.Graph
	ExtractText(&graph, textVariableTestContent("oversized-variable.py", source))

	assertShellCommandNetwork(t, graph, "https://later-independent.example/payload")
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationNetworkDownload &&
			operation.RequiredResource().Value == "https://stale-response.example/payload" {
			t.Fatalf("oversized reassignment reused a stale request binding: %#v", operation)
		}
		if operation.RequiredResource().Value == "https://inside-oversized-assignment.example/" {
			t.Fatalf("API-looking text inside an omitted assignment became behavior: %#v", operation)
		}
	}
	assertTextVariableCoverage(t, graph, "variable value exceeded 16384 bytes")
	assertTextVariableCoverage(t, graph, "affected variable semantics were not inferred")
}

func TestExtractTextPlainReassignmentClearsRequestBinding(t *testing.T) {
	source := `response = requests.get("https://stale-plain-reassignment.example/payload")` + "\n" +
		`response = "ordinary value"` + "\n" +
		`open("/tmp/must-not-inherit", "wb").write(response.content)` + "\n"

	var graph behavior.Graph
	ExtractText(&graph, textVariableTestContent("request-reassignment.py", source))

	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationNetworkDownload {
			t.Fatalf("plain reassignment reused a stale request binding: %#v", operation)
		}
	}
}

func TestExtractTextUnresolvedReassignmentClearsOrdinaryAndRequestBindings(t *testing.T) {
	source := `target = "/tmp/stale-target"` + "\n" +
		`response = requests.get("https://stale-unresolved.example/payload")` + "\n" +
		`target = make_path()` + "\n" +
		`response = make_response()` + "\n" +
		`subprocess.run([target])` + "\n" +
		`open("/tmp/must-not-inherit", "wb").write(response.content)` + "\n"

	var graph behavior.Graph
	ExtractText(&graph, textVariableTestContent("unresolved-reassignment.py", source))

	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationProcessExecute || operation.Kind == behavior.OperationInterpreterInvoke {
			t.Fatalf("unresolved reassignment reused a stale executable binding: %#v", operation)
		}
		if operation.Kind == behavior.OperationNetworkDownload {
			t.Fatalf("unresolved reassignment reused a stale request binding: %#v", operation)
		}
	}
}

func TestExtractTextBoundsTrackedRequestVariables(t *testing.T) {
	var source strings.Builder
	source.WriteString("import requests\n")
	for i := 0; i <= maxTextTrackedRequestVariables; i++ {
		source.WriteString("response_")
		source.WriteString(strconv.Itoa(i))
		source.WriteString(` = requests.get("https://request-limit.example/payload")`)
		source.WriteByte('\n')
	}

	var graph behavior.Graph
	ExtractText(&graph, textVariableTestContent("request-limit.py", source.String()))

	assertTextVariableCoverage(t, graph, "tracked request variable limit")
	if got := len(graph.Network); got != maxTextTrackedRequestVariables {
		t.Fatalf("retained network details = %d, want %d before the request-variable limit", got, maxTextTrackedRequestVariables)
	}
}

func TestExtractTextDoesNotMergeRedefinedFunctionScopes(t *testing.T) {
	source := `def save():
    response = requests.get("https://first-definition.example/payload")
def save():
    open("/tmp/must-not-download", "wb").write(response.content)
save()
`

	var graph behavior.Graph
	ExtractText(&graph, textVariableTestContent("redefined-function.py", source))

	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationNetworkDownload {
			t.Fatalf("later function redefinition inherited an earlier request binding: %#v", operation)
		}
	}
	for _, feature := range graph.Features {
		if feature.Key == "script.function_call" && feature.Value == "save" {
			t.Fatalf("ambiguous redefined function received a direct-call relation candidate: %#v", feature)
		}
	}
	var scopes []string
	for _, scope := range graph.Scopes {
		if scope.Kind == "function" && scope.Function == "save" {
			scopes = append(scopes, scope.ID)
		}
	}
	if len(scopes) != 2 || scopes[0] == scopes[1] {
		t.Fatalf("redefined functions did not receive distinct lexical scopes: %#v", graph.Scopes)
	}
}

func TestExtractTextBoundsSubstitutionsPerLine(t *testing.T) {
	line := `response = requests.get(` + strings.Repeat("endpoint+", maxTextVariableSubstitutionsPerLine) + `endpoint)`
	source := `import requests` + "\n" + `endpoint = "https://substitution-limit.example/payload"` + "\n" + line + "\n"

	var graph behavior.Graph
	ExtractText(&graph, textVariableTestContent("substitution-limit.py", source))

	assertTextVariableCoverage(t, graph, "variable substitution limit")
	if len(graph.Operations) != 0 || len(graph.Network) != 0 {
		t.Fatalf("semantic analysis continued after the substitution limit: operations=%#v network=%#v", graph.Operations, graph.Network)
	}
}

func TestExtractTextBoundsNestedStringExpressions(t *testing.T) {
	expr := strings.Repeat("os.path.expanduser(", maxTextStringExpressionDepth+1) + `"~"` + strings.Repeat(")", maxTextStringExpressionDepth+1)
	source := "target = " + expr + "\n" + `requests.get("https://must-not-be-analyzed.example/nesting")` + "\n"

	var graph behavior.Graph
	ExtractText(&graph, textVariableTestContent("nested-expression.py", source))

	assertTextVariableCoverage(t, graph, "string expression nesting limit")
	if len(graph.Operations) != 0 || len(graph.Network) != 0 {
		t.Fatalf("semantic analysis continued after the nesting limit: operations=%#v network=%#v", graph.Operations, graph.Network)
	}
}

func TestExtractTextManyGlobalsAndFunctionLinesStayLinear(t *testing.T) {
	const count = 2000
	var source strings.Builder
	for i := 0; i < count; i++ {
		source.WriteString("global_")
		source.WriteString(strconv.Itoa(i))
		source.WriteString(` = "value"`)
		source.WriteByte('\n')
	}
	source.WriteString("def quiet():\n")
	for i := 0; i < count; i++ {
		source.WriteString("    pass\n")
	}

	var graph behavior.Graph
	started := time.Now()
	ExtractText(&graph, textVariableTestContent("many-globals.py", source.String()))
	elapsed := time.Since(started)

	if elapsed > 5*time.Second {
		t.Fatalf("text extraction took %s for %d globals and %d inert function lines; variable lookup appears superlinear", elapsed, count, count)
	}
	if len(graph.Coverage) != 0 || len(graph.Operations) != 0 || len(graph.Network) != 0 {
		t.Fatalf("inert scale fixture produced analysis output: coverage=%#v operations=%#v network=%#v", graph.Coverage, graph.Operations, graph.Network)
	}
}

func textVariableTestContent(path, source string) artifact.Content {
	return artifact.Content{
		NodeID:      "node-0001",
		LogicalPath: path,
		Kind:        "script",
		MediaType:   "text/plain",
		Data:        []byte(source),
	}
}

func assertTextVariableCoverage(t *testing.T, graph behavior.Graph, detail string) {
	t.Helper()
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "text-variable-analysis" && coverage.Status == "partial" && strings.Contains(coverage.Detail, detail) {
			return
		}
	}
	t.Fatalf("missing partial text-variable-analysis coverage containing %q: %#v", detail, graph.Coverage)
}

func assertTextDownloadDestination(t *testing.T, graph behavior.Graph, target, destination string) {
	t.Helper()
	for _, operation := range graph.Operations {
		localOutput, ok := testOperationBinding(operation, behavior.ResourceRoleLocalOutput)
		if operation.Kind != "network.download" || !ok || localOutput.Value != target {
			continue
		}
		remoteSource, ok := testOperationBinding(operation, behavior.ResourceRoleRemoteSource)
		if ok && remoteSource.Value == destination {
			return
		}
	}
	t.Fatalf("missing download target %q associated with destination %q: operations=%#v network=%#v", target, destination, graph.Operations, graph.Network)
}

func TestRequestEvidenceBudgetDropsStaleProof(t *testing.T) {
	state := newTextVariableState()
	proof := make([]string, maxTextRequestEvidencePerVar)
	for i := range proof {
		proof[i] = "evidence-" + strconv.Itoa(i)
	}
	if !state.setRequestVariable("scope", "response", []string{"https://unit.invalid/p"}, proof...) {
		t.Fatal("exact evidence limit rejected")
	}
	if got := lookupTextRequestEvidence(state.requestVariables("scope"), "response"); len(got) != len(proof) {
		t.Fatalf("retained proof length = %d", len(got))
	}
	if state.setRequestVariable("scope", "response", []string{"https://new.invalid/p"}, append(proof, "extra")...) {
		t.Fatal("over-limit request proof accepted")
	}
	if _, found := lookupTextRequestVariable(state.requestVariables("scope"), "response"); found || len(state.requestEvidence) != 0 || state.omittedCoverageDetail() == "" {
		t.Fatal("over-limit reassignment retained stale destinations or evidence, or omitted coverage")
	}
}
