package extract

import "github.com/0x4D31/maratus/internal/behavior"

func testResourceCategory(resource behavior.Resource) string {
	for _, classification := range resource.Classifications {
		switch classification {
		case behavior.ResourceClassArchive:
			return "archive"
		case behavior.ResourceClassBrowserCookieStore:
			return "browser.cookies"
		case behavior.ResourceClassBrowserPasswordStore:
			return "browser.password-store"
		case behavior.ResourceClassBundleIdentifier:
			return "bundle-id"
		case behavior.ResourceClassCloudCredentialStore:
			return "cloud-credentials"
		case behavior.ResourceClassCryptoWalletStore:
			return "crypto-wallet"
		case behavior.ResourceClassDeveloperTokenStore:
			return "developer-token"
		case behavior.ResourceClassInterpreter:
			return "interpreter"
		case behavior.ResourceClassKeychain:
			return "keychain"
		case behavior.ResourceClassLaunchAgent:
			return "launch-agent"
		case behavior.ResourceClassLaunchDaemon:
			return "launch-daemon"
		case behavior.ResourceClassPackage:
			return "package"
		case behavior.ResourceClassPlistName:
			return "plist-name"
		case behavior.ResourceClassShellProfile:
			return "shell-profile"
		case behavior.ResourceClassSSHPrivateKey:
			return "ssh-private-key"
		}
	}
	switch resource.Kind {
	case behavior.ResourceURL, behavior.ResourceNetworkEndpoint:
		return "network-destination"
	case behavior.ResourceProcess, behavior.ResourceProcessMemory:
		return "process-memory"
	case behavior.ResourceCredential:
		return "user-password"
	case behavior.ResourceCredentialStore:
		return "credential-store"
	case behavior.ResourceLaunchdJob:
		return "launchd-service"
	case behavior.ResourceScreen:
		return "screenshot"
	}
	return string(resource.Kind)
}

func testOperationHasResource(operation behavior.ModeledOperation, category, value string) bool {
	for _, binding := range operation.ResourceBindings {
		if category == "process" && binding.Role == behavior.ResourceRoleExecutable && binding.Resource.Kind == behavior.ResourceFile && binding.Resource.Value == value {
			return true
		}
		if testResourceCategory(binding.Resource) == category && binding.Resource.Value == value {
			return true
		}
	}
	return false
}

func testOperationBinding(operation behavior.ModeledOperation, role behavior.ResourceRole) (behavior.Resource, bool) {
	binding, ok := operation.FirstBinding(role)
	return binding.Resource, ok
}
