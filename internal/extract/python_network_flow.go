package extract

import "strings"

// Only requests/httpx responses expose the supported content attribute.
// Wrappers and trailing expressions do not preserve the returned object.
func pythonResponseCall(expression string) bool {
	expression = strings.TrimSpace(expression)
	marker, open, found := pythonNetworkCallLocation(expression)
	if !found || open != len(marker)-1 || !(strings.HasPrefix(marker, "requests.") || strings.HasPrefix(marker, "httpx.")) {
		return false
	}
	_, close, exact, _ := exactPythonCallContent(expression, open, maxPythonAPICallBytes)
	return exact && pythonCallTailEmpty(expression[close+1:])
}

func pythonNetworkArgument(line, parameter string, budget *textLineBudget) string {
	marker, open, found := pythonNetworkCallLocation(line)
	if !found {
		return ""
	}
	arguments := boundedTextCallArguments(callTextAtOpen(line, open), "network-call arguments", budget)
	positional, keywords, stable := pythonStableArgumentShape(arguments)
	if !stable {
		return ""
	}
	parameters := []string{"url", "filename"}
	if marker == "requests.request(" || marker == "httpx.request(" {
		parameters = []string{"method", "url"}
	}
	return pythonParameterExpression(positional, keywords, parameters, parameter)
}

// Accept a complete open(...).write(...) statement or its one-line with form.
// The body is returned intact so the caller must prove what is being written.
func pythonResponseWrite(line string, vars any) (path, body string, ok bool) {
	line = strings.TrimSpace(line)
	with := strings.HasPrefix(line, "with ")
	if with {
		line = strings.TrimSpace(strings.TrimPrefix(line, "with "))
	}
	if !strings.HasPrefix(line, "open(") {
		return "", "", false
	}
	content, close, exact, _ := exactPythonCallContent(line, len("open"), maxPythonAPICallBytes)
	if !exact {
		return "", "", false
	}
	arguments, limited, malformed := exactPythonArguments(content, maxTextStringExpressionArguments)
	if limited || malformed || !pythonSignature(1, 2, 0, "file", "mode").accepts(arguments) {
		return "", "", false
	}
	positional, keywords, _ := pythonStableArgumentShape(arguments)
	parameters := []string{"file", "mode"}
	path = resolveStringExpression("python", pythonParameterExpression(positional, keywords, parameters, "file"), vars)
	if path == "" || strings.ContainsRune(path, 0) {
		return "", "", false
	}
	mode, exact := exactPythonStringLiteral(pythonParameterExpression(positional, keywords, parameters, "mode"))
	if !exact || mode != "wb" && mode != "ab" && mode != "xb" {
		return "", "", false
	}
	tail := strings.TrimSpace(line[close+1:])
	if with {
		if !strings.HasPrefix(tail, "as ") {
			return "", "", false
		}
		parts := strings.SplitN(strings.TrimSpace(tail[3:]), ":", 2)
		if len(parts) != 2 || !identifierName(strings.TrimSpace(parts[0])) {
			return "", "", false
		}
		name := strings.TrimSpace(parts[0])
		tail = strings.TrimSpace(parts[1])
		if !strings.HasPrefix(tail, name+".") {
			return "", "", false
		}
		tail = tail[len(name):]
	}
	if !strings.HasPrefix(tail, ".write(") {
		return "", "", false
	}
	body, close, exact, _ = exactPythonCallContent(tail, len(".write"), maxPythonAPICallBytes)
	if !exact || !pythonCallTailEmpty(tail[close+1:]) {
		return "", "", false
	}
	return path, strings.TrimSpace(body), true
}

func pythonCallTailEmpty(tail string) bool {
	tail = strings.TrimSpace(tail)
	return tail == "" || strings.HasPrefix(tail, "#")
}

func invalidatePythonResponseUses(line string, state *textVariableState, scope string) {
	code := pythonCodeContext(line)
	requests := state.requestVariables(scope)
	for index := 0; index < len(code); {
		if !identifierStartByte(code[index]) {
			index++
			continue
		}
		end := index + 1
		for end < len(code) && isIdentifierByte(code[end]) {
			end++
		}
		name := code[index:end]
		if _, found := lookupTextRequestVariable(requests, name); found && !pythonIdentifierHasMemberPrefix(code, index) {
			// Passing the response itself or accessing another member may mutate
			// its content. Only an unchanged content read preserves this proof.
			suffix := code[end:]
			contentEnd := end + len(".content")
			if !strings.HasPrefix(suffix, ".content") || contentEnd < len(code) && (isIdentifierByte(code[contentEnd]) || code[contentEnd] == '(') || pythonRootedMemberMutation(code, index, end) {
				state.clearRequestVariable(scope, name)
			}
		}
		index = end
	}
}
