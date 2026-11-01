package extract

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestRunModelsCodexProjectHookWithoutClaimingOccurrence(t *testing.T) {
	artifacts, contents, configID, _ := projectConfigFixture(
		"checkout.tar.gz!repo/.codex/hooks.json",
		`{"description":"workspace checks","hooks":{"SessionStart":[{"matcher":"startup|resume","hooks":[{"type":"command","command":"node .codex/hooks/start.mjs","async":true}]}]}}`,
		"checkout.tar.gz!repo/.codex/hooks/start.mjs",
		"fetch('https://should-not-promote.invalid/stage');\n",
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("execution roots = %#v, want one conditional Codex hook", graph.ExecutionRoots)
	}
	root := graph.ExecutionRoots[0]
	if root.Kind != codexHooksRootKind || root.DeclarationNodeID != configID || root.StartNodeID != "" || root.StartScopeID == "" || root.Interpreter != "" {
		t.Fatalf("Codex hook root = %#v", root)
	}
	if len(root.EvidenceIDs) != 1 ||
		!evidenceHasValue(graph.Evidence, root.EvidenceIDs[0], "event=SessionStart") ||
		!evidenceHasValue(graph.Evidence, root.EvidenceIDs[0], "bounded-alternatives=startup|resume") {
		t.Fatalf("root lost exact hook declaration evidence: root=%#v evidence=%#v", root, graph.Evidence)
	}
	for _, gate := range []string{
		"compatible Codex frontend/version",
		"trusted project .codex layer",
		"effective per-hook enablement",
		"hash-bound trust",
		"explicit hook-trust bypass",
		"managed-policy",
		"lifecycle event and matcher",
		"session working directory",
		"effective shell selected from the Codex session environment",
		"event occurrence",
	} {
		if !coverageContains(graph.Coverage, configID, codexHooksAnalysisArea, gate) {
			t.Fatalf("Codex hook gate %q is not explicit in coverage: %#v", gate, graph.Coverage)
		}
	}
	if !hasConnectedOperationForNode(graph.Operations, configID, root.ID, behavior.OperationInterpreterInvoke) {
		t.Fatalf("hook command was not modeled in its conditional root scope: %#v", graph.Operations)
	}
	if len(graph.InvokedTargets) != 0 {
		t.Fatalf("session cwd is unknown, so relative operands must not become exact targets: %#v", graph.InvokedTargets)
	}
	if err := graph.Sort(); err != nil {
		t.Fatalf("Codex hook graph has invalid references: %v", err)
	}
}

func TestRunModelsCodexDocumentedEventsAndIgnoredMatcher(t *testing.T) {
	artifacts, contents, configID, _ := projectConfigFixture(
		"repo/.codex/hooks.json",
		`{"hooks":{
			"PreToolUse":[{"matcher":"^Bash$","hooks":[{"type":"command","command":"python3 policy.py"}]}],
			"PreCompact":[{"matcher":"manual|auto","hooks":[{"type":"command","command":"./compact.sh"}]}],
			"UserPromptSubmit":[{"matcher":"[ignored-regex","hooks":[{"type":"command","command":"./prompt.sh"}]}]
		}}`,
		"repo/policy.py",
		"",
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if got := countExecutionRootsByKind(graph.ExecutionRoots, codexHooksRootKind); got != 3 {
		t.Fatalf("Codex hook roots = %d, want 3: %#v", got, graph.ExecutionRoots)
	}
	var sawTool, sawCompact, sawIgnored bool
	for _, root := range graph.ExecutionRoots {
		if len(root.EvidenceIDs) != 1 {
			continue
		}
		sawTool = sawTool || evidenceHasValue(graph.Evidence, root.EvidenceIDs[0], "event=PreToolUse; matcher=^Bash$; bounded-alternatives=Bash")
		sawCompact = sawCompact || evidenceHasValue(graph.Evidence, root.EvidenceIDs[0], "event=PreCompact; matcher=manual|auto; bounded-alternatives=manual|auto")
		sawIgnored = sawIgnored || evidenceHasValue(graph.Evidence, root.EvidenceIDs[0], "event=UserPromptSubmit; matcher=<present; bytes=14; sha256=")
		if evidenceHasValue(graph.Evidence, root.EvidenceIDs[0], "[ignored-regex") {
			t.Fatalf("ignored matcher contents leaked into evidence: %#v", graph.Evidence)
		}
	}
	if !sawTool || !sawCompact || !sawIgnored {
		t.Fatalf("documented matcher semantics were not retained: evidence=%#v", graph.Evidence)
	}
	if !coverageContains(graph.Coverage, configID, codexHooksAnalysisArea, "hash-bound trust") {
		t.Fatalf("host gate is missing: %#v", graph.Coverage)
	}
	if len(graph.InvokedTargets) != 0 {
		t.Fatalf("Codex session-cwd commands gained exact targets: %#v", graph.InvokedTargets)
	}
	if err := graph.Sort(); err != nil {
		t.Fatalf("multi-event Codex hook graph has invalid references: %v", err)
	}
}

func TestRunCodexHookCloseNegativesFailClosed(t *testing.T) {
	tests := []struct {
		name        string
		logical     string
		hooks       string
		wantPartial string
	}{
		{
			name:    "same JSON outside project config path",
			logical: "repo/hooks.json",
			hooks:   `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node start.mjs"}]}]}}`,
		},
		{
			name:        "unsupported regular expression",
			logical:     "repo/.codex/hooks.json",
			hooks:       `{"hooks":{"SessionStart":[{"matcher":"^start.*$","hooks":[{"type":"command","command":"node start.mjs"}]}]}}`,
			wantPartial: "outside the bounded exact-alternative profile",
		},
		{
			name:        "unknown documented source",
			logical:     "repo/.codex/hooks.json",
			hooks:       `{"hooks":{"SessionStart":[{"matcher":"fork","hooks":[{"type":"command","command":"node start.mjs"}]}]}}`,
			wantPartial: "matcher has no documented exact alternative",
		},
		{
			name:        "parsed but nonexecuting handler",
			logical:     "repo/.codex/hooks.json",
			hooks:       `{"hooks":{"SessionStart":[{"hooks":[{"type":"prompt","command":"ignored"}]}]}}`,
			wantPartial: `handler type "prompt" is valid but outside Maratus's bounded command-handler adapter`,
		},
		{
			name:        "unknown event",
			logical:     "repo/.codex/hooks.json",
			hooks:       `{"hooks":{"BeforeEverything":{"malformed":"but ignored by the host"}}}`,
			wantPartial: `hook event "BeforeEverything" is not in the documented Codex event vocabulary`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts, contents, configID, _ := projectConfigFixture(test.logical, test.hooks, "repo/start.mjs", "")
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			if got := countExecutionRootsByKind(graph.ExecutionRoots, codexHooksRootKind); got != 0 || hasAnyConnectedOperation(graph.Operations) {
				t.Fatalf("close-negative configuration produced behavior: roots=%#v operations=%#v", graph.ExecutionRoots, graph.Operations)
			}
			if test.wantPartial != "" && !coverageContains(graph.Coverage, configID, codexHooksAnalysisArea, test.wantPartial) {
				t.Fatalf("missing partial coverage %q: %#v", test.wantPartial, graph.Coverage)
			}
		})
	}
}

func TestRunCodexHookWholeDocumentValidationIsAtomic(t *testing.T) {
	valid := `{"type":"command","command":"node start.mjs"}`
	tests := []struct {
		name   string
		data   []byte
		detail string
	}{
		{
			name:   "unknown top-level field",
			data:   []byte(`{"unknown":true,"hooks":{"SessionStart":[{"hooks":[` + valid + `]}]}}`),
			detail: "schema validation failed: unknown top-level field",
		},
		{
			name:   "bad description",
			data:   []byte(`{"description":1,"hooks":{"SessionStart":[{"hooks":[` + valid + `]}]}}`),
			detail: "schema validation failed: description is not a string",
		},
		{
			name:   "bad optional command field",
			data:   []byte(`{"hooks":{"SessionStart":[{"hooks":[` + valid + `,{"type":"command","command":"false","timeout":"3"}]}]}}`),
			detail: "handler.timeout is not an unsigned integer",
		},
		{
			name:   "unknown handler type",
			data:   []byte(`{"hooks":{"SessionStart":[{"hooks":[` + valid + `,{"type":"future","command":"false"}]}]}}`),
			detail: "handler type is outside the documented Codex hook profile",
		},
		{
			name:   "duplicate command field",
			data:   []byte(`{"hooks":{"SessionStart":[{"hooks":[` + valid + `,{"type":"command","command":"false","command":"true"}]}]}}`),
			detail: "duplicate JSON object key",
		},
		{
			name:   "malformed sibling event",
			data:   []byte(`{"hooks":{"SessionStart":[{"hooks":[` + valid + `]}],"PreToolUse":{}}}`),
			detail: "hooks.PreToolUse is not an array",
		},
		{
			name: "invalid utf8 in command",
			data: append(
				append([]byte(`{"hooks":{"SessionStart":[{"hooks":[`+valid+`,{"type":"command","command":"`), 0xff),
				[]byte(`"}]}]}}`)...,
			),
			detail: "input is not valid UTF-8",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts, contents, configID, _ := projectConfigFixture("repo/.codex/hooks.json", "", "repo/start.mjs", "")
			contents[0].Data = test.data
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			if got := countExecutionRootsByKind(graph.ExecutionRoots, codexHooksRootKind); got != 0 || len(graph.InvokedTargets) != 0 || hasAnyConnectedOperation(graph.Operations) {
				t.Fatalf("invalid sibling allowed partial model emission: roots=%#v targets=%#v operations=%#v", graph.ExecutionRoots, graph.InvokedTargets, graph.Operations)
			}
			if !coverageContains(graph.Coverage, configID, codexHooksAnalysisArea, test.detail) {
				t.Fatalf("missing atomic validation diagnostic %q: %#v", test.detail, graph.Coverage)
			}
		})
	}
}

func TestRunCodexMCPToolHandlerIsValidButUnsupported(t *testing.T) {
	artifacts, contents, configID, _ := projectConfigFixture(
		"repo/.codex/hooks.json",
		`{"hooks":{"SessionStart":[{"futureGroup":{"ignored":null},"hooks":[
			{"type":"mcp_tool","server":"local","tool":"inspect","input":{"path":"sample","count":2,"ratio":0.5,"flags":[true,"x"],"nested":{"key":"value"}},"timeout":5,"statusMessage":"Inspecting","futureHandler":null},
			{"type":"command","command":"node start.mjs","futureHandler":null}
		]}]}}`,
		"repo/start.mjs",
		"",
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if got := countExecutionRootsByKind(graph.ExecutionRoots, codexHooksRootKind); got != 1 {
		t.Fatalf("valid unsupported sibling invalidated the command hook: roots=%#v coverage=%#v", graph.ExecutionRoots, graph.Coverage)
	}
	if !coverageContains(graph.Coverage, configID, codexHooksAnalysisArea, `handler type "mcp_tool" is valid but outside Maratus's bounded command-handler adapter`) {
		t.Fatalf("unsupported MCP handler is not explicit: %#v", graph.Coverage)
	}
	root := graph.ExecutionRoots[0]
	if !hasConnectedOperationForNode(graph.Operations, configID, root.ID, behavior.OperationInterpreterInvoke) {
		t.Fatalf("valid command sibling lost its connected operation: %#v", graph.Operations)
	}
}

func TestRunCodexMalformedMCPToolHandlerInvalidatesWholeDocument(t *testing.T) {
	tests := []struct {
		name    string
		handler string
		detail  string
	}{
		{name: "missing server", handler: `{"type":"mcp_tool","tool":"inspect"}`, detail: "MCP tool handler server is absent"},
		{name: "server nonstring", handler: `{"type":"mcp_tool","server":1,"tool":"inspect"}`, detail: "handler.server is not a string"},
		{name: "input null", handler: `{"type":"mcp_tool","server":"local","tool":"inspect","input":null}`, detail: "handler.input is not an object"},
		{name: "input array", handler: `{"type":"mcp_tool","server":"local","tool":"inspect","input":[]}`, detail: "handler.input is not an object"},
		{name: "nested null", handler: `{"type":"mcp_tool","server":"local","tool":"inspect","input":{"value":null}}`, detail: "null is not representable in TOML"},
		{name: "large integer", handler: `{"type":"mcp_tool","server":"local","tool":"inspect","input":{"value":9223372036854775808}}`, detail: "integer is outside signed 64-bit TOML range"},
		{name: "multiple invalid values", handler: `{"type":"mcp_tool","server":"local","tool":"inspect","input":{"z":null,"a":9223372036854775808}}`, detail: "integer is outside signed 64-bit TOML range"},
		{name: "timeout string", handler: `{"type":"mcp_tool","server":"local","tool":"inspect","timeout":"5"}`, detail: "handler.timeout is not an unsigned integer"},
		{name: "status nonstring", handler: `{"type":"mcp_tool","server":"local","tool":"inspect","statusMessage":5}`, detail: "handler.statusMessage is not a string"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hooks := `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node start.mjs"},` + test.handler + `]}]}}`
			artifacts, contents, configID, _ := projectConfigFixture("repo/.codex/hooks.json", hooks, "repo/start.mjs", "")
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			second := Run(Context{Artifacts: &artifacts, Contents: contents})
			if !reflect.DeepEqual(graph, second) {
				t.Fatal("MCP schema rejection is nondeterministic")
			}
			if countExecutionRootsByKind(graph.ExecutionRoots, codexHooksRootKind) != 0 || hasAnyConnectedOperation(graph.Operations) {
				t.Fatalf("malformed MCP sibling allowed command behavior: roots=%#v operations=%#v", graph.ExecutionRoots, graph.Operations)
			}
			if !coverageContains(graph.Coverage, configID, codexHooksAnalysisArea, test.detail) {
				t.Fatalf("missing MCP schema diagnostic %q: %#v", test.detail, graph.Coverage)
			}
		})
	}
}

func TestRunCodexHookMalformedFormsEmitNoBehavior(t *testing.T) {
	tests := []struct {
		name   string
		hooks  string
		detail string
	}{
		{name: "malformed json", hooks: `{"hooks":`, detail: "hooks.json decode failed"},
		{name: "hooks array", hooks: `{"hooks":[]}`, detail: "hooks.json schema validation failed: hooks is malformed"},
		{name: "event object", hooks: `{"hooks":{"SessionStart":{}}}`, detail: "hooks.SessionStart is not an array"},
		{name: "matcher nonstring", hooks: `{"hooks":{"SessionStart":[{"matcher":true,"hooks":[]}]}}`, detail: "SessionStart matcher is not a string"},
		{name: "command absent", hooks: `{"hooks":{"SessionStart":[{"hooks":[{"type":"command"}]}]}}`, detail: "command handler command is absent"},
		{name: "command empty", hooks: `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"  "}]}]}}`, detail: "command handler command is empty"},
		{name: "async null", hooks: `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"true","async":null}]}]}}`, detail: "handler.async is not a boolean"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts, contents, configID, _ := projectConfigFixture("repo/.codex/hooks.json", test.hooks, "repo/start.mjs", "")
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			if countExecutionRootsByKind(graph.ExecutionRoots, codexHooksRootKind) != 0 || len(graph.InvokedTargets) != 0 || hasAnyConnectedOperation(graph.Operations) {
				t.Fatalf("malformed configuration produced behavior: roots=%#v targets=%#v operations=%#v", graph.ExecutionRoots, graph.InvokedTargets, graph.Operations)
			}
			if !coverageContains(graph.Coverage, configID, codexHooksAnalysisArea, test.detail) {
				t.Fatalf("malformed configuration lacks stable coverage %q: %#v", test.detail, graph.Coverage)
			}
		})
	}
}

func TestRunCodexHookEmptyGroupIsValidAndInert(t *testing.T) {
	artifacts, contents, configID, _ := projectConfigFixture(
		"repo/.codex/hooks.json",
		`{"hooks":{"SessionStart":[{}]}}`,
		"repo/start.mjs",
		"",
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if countExecutionRootsByKind(graph.ExecutionRoots, codexHooksRootKind) != 0 || hasAnyConnectedOperation(graph.Operations) {
		t.Fatalf("empty matcher group produced behavior: roots=%#v operations=%#v", graph.ExecutionRoots, graph.Operations)
	}
	if coverageContains(graph.Coverage, configID, codexHooksAnalysisArea, "") {
		t.Fatalf("host-valid empty matcher group was mislabeled partial: %#v", graph.Coverage)
	}
}

func TestRunDoesNotRecognizeCodexConfigTOMLByPathAlone(t *testing.T) {
	artifacts, contents, configID, _ := projectConfigFixture(
		"repo/.codex/config.toml",
		"[features]\nhooks = false\n",
		"repo/start.mjs",
		"",
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if countExecutionRootsByKind(graph.ExecutionRoots, codexHooksRootKind) != 0 || hasAnyConnectedOperation(graph.Operations) {
		t.Fatalf("unsupported TOML configuration produced behavior: roots=%#v operations=%#v", graph.ExecutionRoots, graph.Operations)
	}
	if coverageContains(graph.Coverage, configID, codexHooksAnalysisArea, "") {
		t.Fatalf("path-only TOML recognition produced false partial coverage: %#v", graph.Coverage)
	}
}

func TestRunCodexHookRetainsKnownMatcherAlternatives(t *testing.T) {
	artifacts, contents, configID, _ := projectConfigFixture(
		"repo/.codex/hooks.json",
		`{"hooks":{"SessionEnd":[{"matcher":"clear|other","hooks":[{"type":"command","command":"./finish.sh"}]}]}}`,
		"repo/finish.sh",
		"",
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if got := countExecutionRootsByKind(graph.ExecutionRoots, codexHooksRootKind); got != 1 {
		t.Fatalf("known matcher alternative was lost: roots=%#v", graph.ExecutionRoots)
	}
	root := graph.ExecutionRoots[0]
	if len(root.EvidenceIDs) != 1 || !evidenceHasValue(graph.Evidence, root.EvidenceIDs[0], "bounded-alternatives=other") {
		t.Fatalf("retained matcher alternative is not evidenced: root=%#v evidence=%#v", root, graph.Evidence)
	}
	if !coverageContains(graph.Coverage, configID, codexHooksAnalysisArea, "1 exact alternative(s) outside the documented SessionEnd values") {
		t.Fatalf("unsupported matcher alternative is not explicit: %#v", graph.Coverage)
	}
}

func TestRunCodexHookIgnoredMatcherIsBoundedBeforeInterpretation(t *testing.T) {
	matcher := strings.Repeat("x", maxCodexHookMatcherBytes+1)
	hooks := fmt.Sprintf(`{"hooks":{"Stop":[{"matcher":%q,"hooks":[{"type":"command","command":"./stop.sh"}]}]}}`, matcher)
	artifacts, contents, _, _ := projectConfigFixture("repo/.codex/hooks.json", hooks, "repo/stop.sh", "")
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if got := countExecutionRootsByKind(graph.ExecutionRoots, codexHooksRootKind); got != 1 {
		t.Fatalf("ignored oversized matcher suppressed a valid hook: roots=%#v coverage=%#v", graph.ExecutionRoots, graph.Coverage)
	}
	root := graph.ExecutionRoots[0]
	if len(root.Name) > 256 || strings.Contains(root.Name, strings.Repeat("x", 32)) {
		t.Fatalf("ignored matcher was not represented by a bounded marker: %#v", root)
	}
	if len(root.EvidenceIDs) != 1 || !evidenceHasValue(graph.Evidence, root.EvidenceIDs[0], fmt.Sprintf("bytes=%d; sha256=", len(matcher))) || !evidenceHasValue(graph.Evidence, root.EvidenceIDs[0], "matcher field ignored by host") {
		t.Fatalf("ignored matcher marker is missing: root=%#v evidence=%#v", root, graph.Evidence)
	}
}

func TestRunCodexHookUnknownEventDiagnosticIsBounded(t *testing.T) {
	event := strings.Repeat("E", maxCodexHookLabelBytes+1)
	hooks := fmt.Sprintf(`{"hooks":{%q:{"ignored":"by host"}}}`, event)
	artifacts, contents, configID, _ := projectConfigFixture("repo/.codex/hooks.json", hooks, "repo/unused.sh", "")
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if countExecutionRootsByKind(graph.ExecutionRoots, codexHooksRootKind) != 0 {
		t.Fatalf("unknown event produced a root: %#v", graph.ExecutionRoots)
	}
	if !coverageContains(graph.Coverage, configID, codexHooksAnalysisArea, fmt.Sprintf("<bytes=%d; sha256=", len(event))) {
		t.Fatalf("bounded unknown-event diagnostic is missing: %#v", graph.Coverage)
	}
	if coverageContains(graph.Coverage, configID, codexHooksAnalysisArea, strings.Repeat("E", 32)) {
		t.Fatalf("unknown event contents leaked into coverage: %#v", graph.Coverage)
	}
}

func TestRunCodexHookPreservesExactCommandBytes(t *testing.T) {
	const command = "printf x\\ "
	artifacts, contents, _, _ := projectConfigFixture(
		"repo/.codex/hooks.json",
		`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"printf x\\ "}]}]}}`,
		"repo/unused.sh",
		"",
	)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if got := countExecutionRootsByKind(graph.ExecutionRoots, codexHooksRootKind); got != 1 {
		t.Fatalf("exact command hook was not modeled: roots=%#v coverage=%#v", graph.ExecutionRoots, graph.Coverage)
	}
	root := graph.ExecutionRoots[0]
	if len(root.Arguments) != 1 || root.Arguments[0] != command {
		t.Fatalf("command bytes changed: arguments=%q, want %q", root.Arguments, command)
	}
	if len(root.EvidenceIDs) != 1 || !evidenceHasValue(graph.Evidence, root.EvidenceIDs[0], "command="+command) {
		t.Fatalf("evidence lost exact command: %#v", graph.Evidence)
	}
}

func TestRunCodexHooksAreBoundedAndDeterministic(t *testing.T) {
	var hooks strings.Builder
	hooks.WriteString(`{"hooks":{"SessionStart":[`)
	for index := 0; index < maxProjectConfigCommands+1; index++ {
		if index > 0 {
			hooks.WriteByte(',')
		}
		fmt.Fprintf(&hooks, `{"matcher":"startup","hooks":[{"type":"command","command":"./task-%03d.sh"}]}`, index)
	}
	hooks.WriteString(`]}}`)

	artifacts, contents, configID, _ := projectConfigFixture("repo/.codex/hooks.json", hooks.String(), "repo/unused.sh", "")
	first := Run(Context{Artifacts: &artifacts, Contents: contents})
	second := Run(Context{Artifacts: &artifacts, Contents: contents})
	if !reflect.DeepEqual(first, second) {
		t.Fatal("bounded Codex hook analysis is nondeterministic")
	}
	if roots := countExecutionRootsByKind(first.ExecutionRoots, codexHooksRootKind); roots != maxProjectConfigCommands {
		t.Fatalf("Codex hook roots = %d, want bounded prefix %d", roots, maxProjectConfigCommands)
	}
	if !coverageContains(first.Coverage, configID, codexHooksAnalysisArea, fmt.Sprintf("matcher-group limit %d reached", maxProjectConfigCommands)) {
		t.Fatalf("cardinality limit is not explicit: %#v", first.Coverage)
	}
	if err := first.Sort(); err != nil {
		t.Fatalf("bounded Codex hook graph has invalid references: %v", err)
	}
}

func TestPlanCodexHooksBoundsHandlersAndTotalTraversal(t *testing.T) {
	t.Run("handler cardinality", func(t *testing.T) {
		var handlers strings.Builder
		for index := 0; index < maxProjectConfigCommands+1; index++ {
			if index > 0 {
				handlers.WriteByte(',')
			}
			fmt.Fprintf(&handlers, `{"type":"command","command":"./task-%03d.sh"}`, index)
		}
		content := artifact.Content{
			NodeID:      "node-hooks",
			LogicalPath: "repo/.codex/hooks.json",
			Data:        []byte(`{"hooks":{"SessionStart":[{"hooks":[` + handlers.String() + `]}]}}`),
		}
		work := 0
		plans, issues := planCodexProjectHooks(content, &work)
		if len(plans) != maxProjectConfigCommands {
			t.Fatalf("plans = %d, want bounded prefix %d", len(plans), maxProjectConfigCommands)
		}
		if !projectConfigIssuesContain(issues, fmt.Sprintf("handler limit %d reached", maxProjectConfigCommands)) {
			t.Fatalf("handler limit is not explicit: %#v", issues)
		}
	})

	t.Run("shared traversal budget", func(t *testing.T) {
		var groups strings.Builder
		for group := 0; group < maxProjectConfigCommands; group++ {
			if group > 0 {
				groups.WriteByte(',')
			}
			groups.WriteString(`{"hooks":[`)
			for handler := 0; handler < 16; handler++ {
				if handler > 0 {
					groups.WriteByte(',')
				}
				groups.WriteString(`{"type":"command","command":"true"}`)
			}
			groups.WriteString(`]}`)
		}
		content := artifact.Content{
			NodeID:      "node-hooks",
			LogicalPath: "repo/.codex/hooks.json",
			Data:        []byte(`{"hooks":{"PreToolUse":[` + groups.String() + `]}}`),
		}
		work := 0
		firstPlans, firstIssues := planCodexProjectHooks(content, &work)
		if work != maxProjectConfigResolutionWork || len(firstPlans) == 0 || len(firstPlans) >= maxProjectConfigResolutionWork {
			t.Fatalf("traversal budget was not charged across groups and handlers: work=%d plans=%d", work, len(firstPlans))
		}
		if !projectConfigIssuesContain(firstIssues, fmt.Sprintf("traversal work limit %d reached", maxProjectConfigResolutionWork)) {
			t.Fatalf("traversal limit is not explicit: %#v", firstIssues)
		}

		secondWork := 0
		secondPlans, secondIssues := planCodexProjectHooks(content, &secondWork)
		if !reflect.DeepEqual(firstPlans, secondPlans) || !reflect.DeepEqual(firstIssues, secondIssues) {
			t.Fatal("bounded traversal result is nondeterministic")
		}

		small := artifact.Content{
			NodeID:      "node-second-hooks",
			LogicalPath: "other/.codex/hooks.json",
			Data:        []byte(`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"false"}]}]}}`),
		}
		laterPlans, laterIssues := planCodexProjectHooks(small, &work)
		if len(laterPlans) != 0 || !projectConfigIssuesContain(laterIssues, fmt.Sprintf("traversal work limit %d reached", maxProjectConfigResolutionWork)) {
			t.Fatalf("shared traversal budget was reset between documents: plans=%#v issues=%#v", laterPlans, laterIssues)
		}
	})
}

func projectConfigIssuesContain(issues []projectConfigIssue, fragment string) bool {
	for _, issue := range issues {
		if strings.Contains(issue.detail, fragment) {
			return true
		}
	}
	return false
}
