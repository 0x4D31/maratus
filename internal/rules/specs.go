package rules

import "github.com/0x4D31/maratus/internal/behavior"

var MacOSDownloadExecute = Spec{
	Metadata: Metadata{ID: "macos.download-execute", Title: "Downloads and executes a payload", Namespace: "macos.execution", Description: "A statically modeled sequence downloads content to a file and later invokes that file.", Attack: []string{"T1105"}, MBC: []string{"E1105"}},
	Kind:     CapabilityRule,
	Match: Any(
		ResourceFlow(
			FlowStep(Operation(behavior.OperationNetworkDownload, ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)), behavior.ResourceRoleLocalOutput),
			FlowStep(Operation(behavior.OperationProcessExecute, ResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)), behavior.ResourceRoleExecutable),
		),
		ResourceFlow(
			FlowStep(Operation(behavior.OperationNetworkDownload, ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)), behavior.ResourceRoleLocalOutput),
			FlowStep(Operation(behavior.OperationFileMakeExecutable, ResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceFile)), behavior.ResourceRoleTarget),
			FlowStep(Operation(behavior.OperationProcessExecute, ResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)), behavior.ResourceRoleExecutable),
		),
		ResourceFlow(
			FlowStep(Operation(behavior.OperationNetworkDownload, ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)), behavior.ResourceRoleLocalOutput),
			FlowStep(Operation(behavior.OperationInterpreterInvoke, ResourceBinding(behavior.ResourceRoleLocalInput, behavior.ResourceFile)), behavior.ResourceRoleLocalInput),
		),
		ResourceFlow(
			FlowStep(Operation(behavior.OperationNetworkDownload, ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)), behavior.ResourceRoleLocalOutput),
			FlowStep(Operation(behavior.OperationFileMakeExecutable, ResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceFile)), behavior.ResourceRoleTarget),
			FlowStep(Operation(behavior.OperationInterpreterInvoke, ResourceBinding(behavior.ResourceRoleLocalInput, behavior.ResourceFile)), behavior.ResourceRoleLocalInput),
		),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSDownloadPipeInterpreter = Spec{
	Metadata: Metadata{ID: "macos.download-pipe-interpreter", Title: "Pipes downloaded content into an interpreter", Namespace: "macos.execution", Description: "Downloaded content is piped directly into a shell or interpreter.", Attack: []string{"T1105", "T1059"}, MBC: []string{"E1105", "E1059"}},
	Kind:     CapabilityRule,
	Match: Relate(
		Operation(behavior.OperationNetworkDownload),
		Operation(behavior.OperationInterpreterInvoke),
		RelatedBy(behavior.RelationPipesTo),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSNetworkCommunication = Spec{
	Metadata: Metadata{ID: "macos.network-communication", Title: "Communicates over a network", Namespace: "macos.communication", Description: "A reportable modeled operation initiates a connection or transfers data. This does not by itself establish command-and-control, exfiltration, or malicious infrastructure."},
	Kind:     CapabilityRule,
	Match: Any(
		Operation(behavior.OperationNetworkConnect, ResourceBinding(behavior.ResourceRoleRemoteDestination, behavior.ResourceNetworkEndpoint)),
		Operation(behavior.OperationNetworkConnect, ResourceBinding(behavior.ResourceRoleRemoteDestination, behavior.ResourceURL)),
		Operation(behavior.OperationNetworkDownload, ResourceBinding(behavior.ResourceRoleRemoteSource, behavior.ResourceNetworkEndpoint)),
		Operation(behavior.OperationNetworkDownload, ResourceBinding(behavior.ResourceRoleRemoteSource, behavior.ResourceURL)),
		Operation(behavior.OperationNetworkUpload, ResourceBinding(behavior.ResourceRoleRemoteDestination, behavior.ResourceNetworkEndpoint)),
		Operation(behavior.OperationNetworkUpload, ResourceBinding(behavior.ResourceRoleRemoteDestination, behavior.ResourceURL)),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSNativeProcessExecution = Spec{
	Metadata: Metadata{ID: "macos.native-process-execution", Title: "Calls native process-execution APIs", Namespace: "macos.execution", Description: "A function-scoped process operation shares exact located call evidence with a Mach-O imported call or Objective-C message call. This establishes statically present native API use without treating function scope alone as proof; the executable path, command, and runtime success may remain unresolved.", Attack: []string{"T1106"}},
	Kind:     CapabilityRule,
	Match: Any(
		Each(
			Operation(behavior.OperationProcessExecute, ResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)),
			Feature("macho.import_call"),
			SameContext(),
			SharedEvidence(),
		),
		Each(
			Operation(behavior.OperationProcessExecute, ResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)),
			Feature("objc.message_call"),
			SameContext(),
			SharedEvidence(),
		),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSFileExecution = Spec{
	Metadata:       Metadata{ID: "macos.file-execution", Title: "Executes a concrete file", Namespace: "macos.execution", Description: "A reportable modeled process operation invokes a concrete file. This does not by itself establish user execution, a command interpreter, or malicious intent."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationProcessExecute, ConcreteResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSLocalAgentInvocation = Spec{
	Metadata: Metadata{
		ID:          "macos.local-agent-invocation",
		Title:       "Invokes a local AI coding agent",
		Namespace:   "macos.execution",
		Description: "A statically modeled process operation invokes a recognized local coding-agent CLI command profile. This establishes the selected command name and retained arguments, not the bytes selected by runtime PATH lookup, prompt acceptance, tool invocation, or completed work.",
	},
	Kind: CapabilityRule,
	Match: Operation(
		behavior.OperationProcessExecute,
		ClassifiedResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile, behavior.ResourceClassAgentRuntime),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSLocalAgentReducedSafeguards = Spec{
	Metadata: Metadata{
		ID:          "macos.local-agent-reduced-safeguards",
		Title:       "Invokes a local AI coding agent with reduced safeguards",
		Namespace:   "macos.execution",
		Description: "A statically modeled coding-agent invocation includes an exact documented option that selects reduced approval or sandbox safeguards. Static analysis does not establish that the option was accepted, that host policy permitted it, or that any downstream action succeeded.",
	},
	Kind: CapabilityRule,
	Match: Operation(
		behavior.OperationProcessExecute,
		ClassifiedResourceBinding(behavior.ResourceRoleExecutable, behavior.ResourceFile, behavior.ResourceClassAgentRuntime),
		ConcreteClassifiedResourceBinding(behavior.ResourceRoleArguments, behavior.ResourceCommand, behavior.ResourceClassAgentReducedSafeguards),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSLocalAgentStateAccess = Spec{
	Metadata: Metadata{
		ID:          "macos.local-agent-state-access",
		Title:       "Reads or copies local AI agent state",
		Namespace:   "macos.collection",
		Description: "A statically modeled file operation reads or copies a concrete recognized coding-agent transcript or history path. It does not establish the contents present at runtime or successful collection.",
	},
	Kind: CapabilityRule,
	Match: Any(
		Operation(behavior.OperationFileRead, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassAgentState)),
		Operation(behavior.OperationFileCopy, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassAgentState)),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSLocalAgentStateModification = Spec{
	Metadata: Metadata{
		ID:          "macos.local-agent-state-modification",
		Title:       "Modifies local AI agent history or transcripts",
		Namespace:   "macos.configuration",
		Description: "A statically modeled file operation writes, copies, moves, or deletes a concrete recognized coding-agent transcript or history path. This neutral result does not independently establish evidence tampering, intent, or runtime success.",
	},
	Kind:           CapabilityRule,
	Match:          localAgentFileModification(behavior.ResourceClassAgentState),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSLocalAgentConfigurationModification = Spec{
	Metadata: Metadata{
		ID:          "macos.local-agent-configuration-modification",
		Title:       "Modifies local AI agent configuration or instructions",
		Namespace:   "macos.configuration",
		Description: "A statically modeled file operation writes, copies, moves, or deletes a concrete recognized coding-agent configuration, hook, MCP, or persistent-instruction path. Path modification alone does not establish effective host selection, an MCP connection, instruction ingestion, or malicious intent.",
	},
	Kind: CapabilityRule,
	Match: Any(
		localAgentFileModification(behavior.ResourceClassAgentConfiguration),
		localAgentFileModification(behavior.ResourceClassAgentHookConfig),
		localAgentFileModification(behavior.ResourceClassAgentInstruction),
		localAgentFileModification(behavior.ResourceClassAgentMCPConfig),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

func localAgentFileModification(classification behavior.ResourceClassification) Pattern {
	return Any(
		Operation(behavior.OperationFileWrite, ConcreteClassifiedResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile, classification)),
		Operation(behavior.OperationFileCopy, ConcreteClassifiedResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile, classification)),
		Operation(behavior.OperationFileMove, ConcreteClassifiedResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceFile, classification)),
		Operation(behavior.OperationFileDelete, ConcreteClassifiedResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceFile, classification)),
	)
}

var MacOSFileMakeExecutable = Spec{
	Metadata:       Metadata{ID: "macos.file-make-executable", Title: "Makes a file executable", Namespace: "macos.execution", Description: "A statically modeled file-mode change makes a file executable. This is common in installers and build tooling and does not by itself establish malicious intent.", Attack: []string{"T1222.002"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationFileMakeExecutable, ResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceFile)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSPackageInstall = Spec{
	Metadata:       Metadata{ID: "macos.package-install", Title: "Invokes macOS package installation", Namespace: "macos.execution", Description: "A statically visible macOS installer invocation requests package installation; the package resource is concrete only when its operand is statically known. This does not establish that installation succeeded or that the package is malicious."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationPackageInstall, ClassifiedResourceBinding(behavior.ResourceRoleLocalInput, behavior.ResourceFile, behavior.ResourceClassPackage)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSCredentialPrompt = Spec{
	Metadata:       Metadata{ID: "macos.credential-prompt", Title: "Prompts for credential input", Namespace: "macos.credentials", Description: "A statically modeled prompt requests credential input. The normalized operation does not establish the prompt mechanism, whether a user saw it, or whether input was supplied."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationCredentialPrompt, ResourceBinding(behavior.ResourceRoleCredential, behavior.ResourceCredential)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSCredentialValidation = Spec{
	Metadata:       Metadata{ID: "macos.credential-validation", Title: "Requests credential validation", Namespace: "macos.credentials", Description: "A statically modeled operation requests credential validation. Static invocation does not prove that credentials were supplied or accepted, or that validation succeeded. This remains independent from any prompt unless a typed credential identity relates them."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationCredentialValidate, ResourceBinding(behavior.ResourceRoleCredential, behavior.ResourceCredential)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSKeychainAccess = Spec{
	Metadata: Metadata{ID: "macos.keychain-access", Title: "Accesses macOS Keychain credentials", Namespace: "macos.credentials", Description: "Static evidence models a credential-specific Keychain operation or an exact read of a known Keychain storage path. A generic Keychain item query does not satisfy this rule.", Attack: []string{"T1555.001"}},
	Kind:     CapabilityRule,
	Match: Any(
		Operation(behavior.OperationCredentialStoreRead, ClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceCredentialStore, behavior.ResourceClassKeychain)),
		Operation(behavior.OperationFileRead, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassKeychain)),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSKeychainItemQuery = Spec{
	Metadata:       Metadata{ID: "macos.keychain-item-query", Title: "Queries macOS Keychain items", Namespace: "macos.technical.credentials", Description: "An exact called Keychain API queries items whose class is unresolved. The query may concern passwords, keys, identities, or certificates; this does not independently establish credential access or successful retrieval."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationKeychainItemQuery, ClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceCredentialStore, behavior.ResourceClassKeychain)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSBrowserCredentialCollection = Spec{
	Metadata: Metadata{ID: "macos.browser-credential-collection", Title: "Collects browser cookies or credential stores", Namespace: "macos.credentials", Description: "Static evidence models reads of browser cookie or credential-store paths.", Attack: []string{"T1555.003"}},
	Kind:     CapabilityRule,
	Match: Any(
		Operation(behavior.OperationFileRead, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassBrowserCookieStore)),
		Operation(behavior.OperationFileRead, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassBrowserPasswordStore)),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSCredentialMaterialCollection = Spec{
	Metadata: Metadata{ID: "macos.credential-material-collection", Title: "Collects wallet, SSH, cloud, package-manager, or developer credential material", Namespace: "macos.credentials", Description: "Static evidence models reads of wallet, SSH, cloud, package-manager, or developer credential material.", Attack: []string{"T1552"}},
	Kind:     CapabilityRule,
	Match: Any(
		Operation(behavior.OperationFileRead, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassSSHPrivateKey)),
		Operation(behavior.OperationFileRead, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassCloudCredentialStore)),
		Operation(behavior.OperationFileRead, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassDeveloperTokenStore)),
		Operation(behavior.OperationFileRead, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassCryptoWalletStore)),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSLaunchPersistence = Spec{
	Metadata: Metadata{ID: "macos.launch-persistence", Title: "Declares or configures LaunchAgent/LaunchDaemon persistence", Namespace: "macos.persistence", Description: "Static evidence models a LaunchAgent, LaunchDaemon, or other launchd persistence declaration or configuration.", Attack: []string{"T1543"}},
	Kind:     CapabilityRule,
	Match: Any(
		Operation(behavior.OperationLaunchdJobDeclare, ResourceBinding(behavior.ResourceRoleJob, behavior.ResourceLaunchdJob)),
		Operation(behavior.OperationLaunchdJobInstall, ResourceBinding(behavior.ResourceRoleJob, behavior.ResourceLaunchdJob)),
		Operation(behavior.OperationLaunchdJobLoad, ResourceBinding(behavior.ResourceRoleJob, behavior.ResourceLaunchdJob)),
		Operation(behavior.OperationLaunchdJobRegister, ResourceBinding(behavior.ResourceRoleJob, behavior.ResourceLaunchdJob)),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSShellProfilePersistence = Spec{
	Metadata:       Metadata{ID: "macos.shell-profile-persistence", Title: "Modifies shell startup files for persistence", Namespace: "macos.persistence", Description: "Static evidence models modification of shell startup files.", Attack: []string{"T1546.004"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationShellProfileModify, ConcreteClassifiedResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceFile, behavior.ResourceClassShellProfile)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSLoginItem = Spec{
	Metadata: Metadata{ID: "macos.login-item", Title: "Configures a login item", Namespace: "macos.persistence", Description: "Static evidence models configuration of a macOS login item.", Attack: []string{"T1547.015"}},
	Kind:     CapabilityRule,
	Match: Any(
		Operation(behavior.OperationLoginItemEnable, ResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceLoginItem)),
		Operation(behavior.OperationLoginItemRegister, ResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceLoginItem)),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSRemoveQuarantine = Spec{
	Metadata:       Metadata{ID: "macos.remove-quarantine", Title: "Modifies or removes quarantine metadata", Namespace: "macos.defense-evasion", Description: "Static evidence models removal or modification of quarantine metadata.", Attack: []string{"T1553.001"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationQuarantineAttributeRemove, ResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceFile)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSModifyGatekeeper = Spec{
	Metadata:       Metadata{ID: "macos.modify-gatekeeper", Title: "Weakens Gatekeeper or related macOS security policy", Namespace: "macos.defense-evasion", Description: "Static evidence models weakening of Gatekeeper or related macOS security policy.", Attack: []string{"T1553.001"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationGatekeeperConfigurationModify, ResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceConfiguration)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSClipboardRead = Spec{
	Metadata:       Metadata{ID: "macos.clipboard-read", Title: "Reads clipboard contents", Namespace: "macos.collection", Description: "Static evidence models reading clipboard contents.", Attack: []string{"T1115"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationClipboardRead),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSClipboardWrite = Spec{
	Metadata:       Metadata{ID: "macos.clipboard-write", Title: "Writes clipboard contents", Namespace: "macos.configuration", Description: "Static evidence models writing content to the system clipboard. This does not establish clipboard theft, replacement intent, or a successful write."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationClipboardWrite, ResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceClipboard)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSInputEventTap = Spec{
	Metadata:       Metadata{ID: "macos.input-event-tap", Title: "Creates a system input event tap", Namespace: "macos.collection", Description: "Static evidence models a call that creates a Quartz input event tap. Without a resolved event mask and callback behavior, this is not labeled keylogging or input capture."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationInputEventTapCreate, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceInputEventStream)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSAudioRecordingQueue = Spec{
	Metadata:       Metadata{ID: "macos.audio-recording-queue", Title: "Creates an audio recording queue", Namespace: "macos.technical.media", Description: "Static evidence models creation of an Audio Toolbox recording queue. It does not establish microphone permission, queue startup, captured audio, or a written recording, so it is not mapped to ATT&CK Audio Capture."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationAudioRecordingQueueCreate, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceAudioInput)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSCameraCapture = Spec{
	Metadata:       Metadata{ID: "macos.camera-capture", Title: "Initiates camera photo capture", Namespace: "macos.collection", Description: "Static evidence models a called AVFoundation photo-capture method. It does not establish camera permission, successful capture, storage, or exfiltration.", Attack: []string{"T1125"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationCameraCapture, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceCamera)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSScreenCapture = Spec{
	Metadata:       Metadata{ID: "macos.screen-capture", Title: "Captures screen content", Namespace: "macos.collection", Description: "Static evidence models screen image or recording capture; exact command output files are retained when available.", Attack: []string{"T1113"}, MBC: []string{"E1113"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationScreenCapture, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceScreen)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSFileVisibilityModification = Spec{
	Metadata:       Metadata{ID: "macos.file-visibility-modification", Title: "Marks a file or directory as hidden", Namespace: "macos.defense-evasion", Description: "Static evidence models an exact macOS command that sets a hidden or invisible filesystem attribute. Legitimate installers and applications may do this as well; runtime success is not established.", Attack: []string{"T1564.001"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationFileVisibilityModify, ResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceFile)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSScheduledJobPersistence = Spec{
	Metadata:       Metadata{ID: "macos.scheduled-job-persistence", Title: "Registers a recurring cron job", Namespace: "macos.persistence", Description: "Static evidence models registration of a cron job. This does not establish that cron accepted or later executed the job.", Attack: []string{"T1053.003"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationScheduledJobRegister, ClassifiedResourceBinding(behavior.ResourceRoleJob, behavior.ResourceScheduledJob, behavior.ResourceClassCronJob)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSPlistModification = Spec{
	Metadata: Metadata{ID: "macos.plist-modification", Title: "Modifies a macOS property list", Namespace: "macos.configuration", Description: "Static evidence models an exact property-list modification. This does not establish that a host consumes the changed key, that code is selected, or that persistence results."},
	Kind:     CapabilityRule,
	Match: Any(
		Operation(behavior.OperationPlistModify, ClassifiedResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceFile, behavior.ResourceClassPropertyList)),
		Operation(behavior.OperationPlistModify, ClassifiedResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceConfiguration, behavior.ResourceClassPropertyList)),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSPrivacyAuthorizationReset = Spec{
	Metadata:       Metadata{ID: "macos.privacy-authorization-reset", Title: "Resets macOS privacy authorization decisions", Namespace: "macos.configuration", Description: "Static evidence models an exact tccutil reset command for a protected service. This removes remembered authorization decisions and may cause future prompts; it does not grant access, bypass TCC, or establish command success."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationPrivacyAuthorizationReset, ResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceConfiguration)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSSystemInformationDiscovery = Spec{
	Metadata:       Metadata{ID: "macos.system-information-discovery", Title: "Queries system information", Namespace: "macos.discovery", Description: "Static evidence models a query for operating-system or hardware information.", Attack: []string{"T1082"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationSystemInfoQuery, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceSystem)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSNetworkConfigurationDiscovery = Spec{
	Metadata:       Metadata{ID: "macos.network-configuration-discovery", Title: "Queries local network configuration", Namespace: "macos.discovery", Description: "Static evidence models a read-only query for local interfaces, addresses, DNS, proxy, or network-service configuration. It does not establish external communication or successful execution.", Attack: []string{"T1016"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationNetworkConfigurationQuery, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceConfiguration)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSUserDiscovery = Spec{
	Metadata:       Metadata{ID: "macos.user-discovery", Title: "Queries local user identity", Namespace: "macos.discovery", Description: "Static evidence models a query for the current or local user identity.", Attack: []string{"T1033"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationUserInfoQuery, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceUserAccount)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSProcessDiscovery = Spec{
	Metadata:       Metadata{ID: "macos.process-discovery", Title: "Enumerates processes", Namespace: "macos.discovery", Description: "Static evidence models enumeration of local processes.", Attack: []string{"T1057"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationProcessEnumerate, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceProcess)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSSoftwareDiscovery = Spec{
	Metadata:       Metadata{ID: "macos.software-discovery", Title: "Enumerates installed software", Namespace: "macos.discovery", Description: "Static evidence models enumeration of installed applications or software.", Attack: []string{"T1518"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationSoftwareEnumerate, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceSoftware)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSFileDirectoryDiscovery = Spec{
	Metadata:       Metadata{ID: "macos.file-directory-discovery", Title: "Enumerates files or directories", Namespace: "macos.discovery", Description: "Static evidence models enumeration of a concrete or unresolved filesystem location.", Attack: []string{"T1083"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationFileEnumerate, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSApplicationDataCollection = Spec{
	Metadata: Metadata{ID: "macos.application-data-collection", Title: "Reads messaging, mail, Notes, or VPN application data", Namespace: "macos.collection", Description: "Static evidence models reads of common application data stores. It does not establish successful collection or exfiltration.", Attack: []string{"T1005"}},
	Kind:     CapabilityRule,
	Match: Any(
		Operation(behavior.OperationFileRead, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassMessagingDataStore)),
		Operation(behavior.OperationFileRead, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassMailDataStore)),
		Operation(behavior.OperationFileRead, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassNotesDataStore)),
		Operation(behavior.OperationFileRead, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassVPNProfileStore)),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSBrowserDataCollection = Spec{
	Metadata: Metadata{ID: "macos.browser-data-collection", Title: "Reads browser history or profile data", Namespace: "macos.collection", Description: "Static evidence models an exact read of a common browser data store. It does not establish successful collection or exfiltration.", Attack: []string{"T1005"}},
	Kind:     CapabilityRule,
	Match: Operation(
		behavior.OperationFileRead,
		ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassBrowserDataStore),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSArchiveLocalData = Spec{
	Metadata:       Metadata{ID: "macos.archive-local-data", Title: "Archives local data", Namespace: "macos.technical.data", Description: "Static evidence models creation of an archive from at least one exact local source. This does not establish collection, malicious staging, or later transfer, so a generic archive is not mapped to ATT&CK Archive Collected Data."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationArchiveCreate, ConcreteResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSArchiveExtract = Spec{
	Metadata:       Metadata{ID: "macos.archive-extract", Title: "Extracts a local archive", Namespace: "macos.technical.data", Description: "Static evidence models extraction from an exact local archive path. The destination may be the runtime working directory, an exact path, or unresolved. This does not establish that extraction succeeded, that any extracted entry was later selected, or that the archive was malicious."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationArchiveExtract, ConcreteResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSArchiveClassifiedData = Spec{
	Metadata: Metadata{ID: "macos.archive-classified-data", Title: "Archives classified local data", Namespace: "macos.collection", Description: "Static evidence models creation of an archive from at least one exact local source classified as a credential, browser, application, or wallet data store. Classification and archive flow are exact static facts; successful collection, adversary intent, and later transfer remain unproven.", Attack: []string{"T1560"}},
	Kind:     CapabilityRule,
	Match: Any(
		Operation(behavior.OperationArchiveCreate, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassKeychain), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
		Operation(behavior.OperationArchiveCreate, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassBrowserCookieStore), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
		Operation(behavior.OperationArchiveCreate, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassBrowserPasswordStore), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
		Operation(behavior.OperationArchiveCreate, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassBrowserDataStore), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
		Operation(behavior.OperationArchiveCreate, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassSSHPrivateKey), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
		Operation(behavior.OperationArchiveCreate, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassCloudCredentialStore), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
		Operation(behavior.OperationArchiveCreate, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassDeveloperTokenStore), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
		Operation(behavior.OperationArchiveCreate, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassCryptoWalletStore), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
		Operation(behavior.OperationArchiveCreate, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassMessagingDataStore), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
		Operation(behavior.OperationArchiveCreate, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassMailDataStore), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
		Operation(behavior.OperationArchiveCreate, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassNotesDataStore), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
		Operation(behavior.OperationArchiveCreate, ConcreteClassifiedResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile, behavior.ResourceClassVPNProfileStore), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSUploadStagedData = Spec{
	Metadata: Metadata{ID: "macos.upload-staged-data", Title: "Uploads a locally created archive", Namespace: "macos.transfer", Description: "An exact resource flow connects an archive created from at least one exact local source to a later network upload. Static analysis does not establish successful transfer, data sensitivity, adversary intent, or use of a command-and-control channel; the generic flow carries no exfiltration or collection ATT&CK mapping."},
	Kind:     CapabilityRule,
	Match: ResourceFlow(
		FlowStep(Operation(behavior.OperationArchiveCreate, ConcreteResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile), ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile)), behavior.ResourceRoleLocalOutput),
		FlowStep(Operation(behavior.OperationNetworkUpload, ResourceBinding(behavior.ResourceRoleLocalInput, behavior.ResourceFile)), behavior.ResourceRoleLocalInput),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSProcessMemory = Spec{
	Metadata: Metadata{ID: "macos.process-memory", Title: "Reads or writes process memory", Namespace: "macos.execution", Description: "Static evidence models a process-memory read or write. Target ownership may be unresolved, and this primitive does not independently prove access to another process or process injection."},
	Kind:     CapabilityRule,
	Match: Any(
		Operation(behavior.OperationProcessMemoryRead, ResourceBinding(behavior.ResourceRoleTargetProcess, behavior.ResourceProcess)),
		Operation(behavior.OperationProcessMemoryWrite, ResourceBinding(behavior.ResourceRoleTargetProcess, behavior.ResourceProcess)),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSProcessTaskAccess = Spec{
	Metadata:       Metadata{ID: "macos.process-task-access", Title: "Requests Mach task access", Namespace: "macos.execution", Description: "A statically modeled operation requests access to a Mach task. The target task's ownership and runtime success may be unresolved; this does not by itself establish access to another process or process injection."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationProcessTaskAccess, ResourceBinding(behavior.ResourceRoleTargetProcess, behavior.ResourceProcess)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSProcessThreadCreation = Spec{
	Metadata:       Metadata{ID: "macos.process-thread-creation", Title: "Requests Mach thread creation", Namespace: "macos.execution", Description: "A statically modeled operation requests creation of a Mach thread in a task. The target task's ownership and runtime success may be unresolved; this does not by itself establish remote-thread injection."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationProcessThreadCreate, ResourceBinding(behavior.ResourceRoleTargetProcess, behavior.ResourceProcess)),
	MinimumSupport: behavior.SupportCorroborated,
}

var PackageJSONInstallLifecycleRoot = Spec{
	Metadata:       Metadata{ID: "library.package-json-install-lifecycle-root", Title: "npm-compatible install lifecycle root", Namespace: "library.package", Description: "Selects npm-compatible package.json install and preparation hook execution roots for reuse by operation-backed capability rules."},
	Kind:           LibraryRule,
	Match:          ExecutionRoot("npm-script", "preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"),
	MinimumSupport: behavior.SupportCorroborated,
}

var PackageJSONLifecycle = Spec{
	Metadata: Metadata{ID: "package.package-json-lifecycle", Title: "Runs code from a package.json install hook", Namespace: "package.execution", Description: "An npm-compatible package.json preinstall, install, postinstall, prepublish, preprepare, prepare, or postprepare hook is statically associated with a network, process, or interpreter operation. This establishes a host-selected install-family execution path, not malicious intent, runtime success, or supply-chain compromise."},
	Kind:     CapabilityRule,
	Match: Any(
		Each(Operation(behavior.OperationNetworkConnect), LibraryRuleRef("library.package-json-install-lifecycle-root"), SameExecutionRoot()),
		Each(Operation(behavior.OperationNetworkDownload), LibraryRuleRef("library.package-json-install-lifecycle-root"), SameExecutionRoot()),
		Each(Operation(behavior.OperationNetworkUpload), LibraryRuleRef("library.package-json-install-lifecycle-root"), SameExecutionRoot()),
		Each(Operation(behavior.OperationProcessExecute), LibraryRuleRef("library.package-json-install-lifecycle-root"), SameExecutionRoot()),
		Each(Operation(behavior.OperationInterpreterInvoke), LibraryRuleRef("library.package-json-install-lifecycle-root"), SameExecutionRoot()),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var PackageNPMImplicitNodeGyp = Spec{
	Metadata: Metadata{ID: "package.npm-implicit-node-gyp", Title: "Runs code through npm's implicit node-gyp install path", Namespace: "package.execution", Description: "A package-root binding.gyp command expansion is statically associated with a network, process, or interpreter operation through npm's conditional implicit node-gyp install path. This does not establish compatible npm policy, install occurrence, command success, malicious intent, or supply-chain compromise."},
	Kind:     CapabilityRule,
	Match: Any(
		Each(Operation(behavior.OperationNetworkConnect), ExecutionRoot("npm-implicit-node-gyp-install"), SameExecutionRoot()),
		Each(Operation(behavior.OperationNetworkDownload), ExecutionRoot("npm-implicit-node-gyp-install"), SameExecutionRoot()),
		Each(Operation(behavior.OperationNetworkUpload), ExecutionRoot("npm-implicit-node-gyp-install"), SameExecutionRoot()),
		Each(Operation(behavior.OperationProcessExecute), ExecutionRoot("npm-implicit-node-gyp-install"), SameExecutionRoot()),
		Each(Operation(behavior.OperationInterpreterInvoke), ExecutionRoot("npm-implicit-node-gyp-install"), SameExecutionRoot()),
	),
	MinimumSupport: behavior.SupportCorroborated,
}
