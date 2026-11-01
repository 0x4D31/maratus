package behavior

// ResourceKind describes what a resource physically or structurally is.
// Analyst-facing semantic meaning belongs in ResourceClassification, never in
// this vocabulary. For example, a browser cookie database is still a file.
type ResourceKind string

const (
	ResourceAudioInput       ResourceKind = "audio-input"
	ResourceCamera           ResourceKind = "camera"
	ResourceClipboard        ResourceKind = "clipboard"
	ResourceCommand          ResourceKind = "command"
	ResourceConfiguration    ResourceKind = "configuration"
	ResourceCredential       ResourceKind = "credential"
	ResourceCredentialStore  ResourceKind = "credential-store"
	ResourceData             ResourceKind = "data"
	ResourceFile             ResourceKind = "file"
	ResourceIdentifier       ResourceKind = "identifier"
	ResourceInputEventStream ResourceKind = "input-event-stream"
	ResourceIOChannel        ResourceKind = "io-channel"
	ResourceLaunchdJob       ResourceKind = "launchd-job"
	ResourceLoginItem        ResourceKind = "login-item"
	ResourceNetworkEndpoint  ResourceKind = "network-endpoint"
	ResourcePasteboard       ResourceKind = "pasteboard"
	ResourcePipe             ResourceKind = "pipe"
	ResourceProcess          ResourceKind = "process"
	ResourceProcessMemory    ResourceKind = "process-memory"
	ResourceScheduledJob     ResourceKind = "scheduled-job"
	ResourceScreen           ResourceKind = "screen"
	ResourceSocket           ResourceKind = "socket"
	ResourceSoftware         ResourceKind = "software"
	ResourceSystem           ResourceKind = "system"
	ResourceURL              ResourceKind = "url"
	ResourceUserAccount      ResourceKind = "user-account"
)

var resourceKinds = [...]ResourceKind{
	ResourceAudioInput,
	ResourceCamera,
	ResourceClipboard,
	ResourceCommand,
	ResourceConfiguration,
	ResourceCredential,
	ResourceCredentialStore,
	ResourceData,
	ResourceFile,
	ResourceIdentifier,
	ResourceInputEventStream,
	ResourceIOChannel,
	ResourceLaunchdJob,
	ResourceLoginItem,
	ResourceNetworkEndpoint,
	ResourcePasteboard,
	ResourcePipe,
	ResourceProcess,
	ResourceProcessMemory,
	ResourceScheduledJob,
	ResourceScreen,
	ResourceSocket,
	ResourceSoftware,
	ResourceSystem,
	ResourceURL,
	ResourceUserAccount,
}

// ResourceClassification adds semantic meaning without changing a resource's
// physical kind.
type ResourceClassification string

const (
	ResourceClassAgentConfiguration     ResourceClassification = "agent-configuration"
	ResourceClassAgentHookConfig        ResourceClassification = "agent-hook-configuration"
	ResourceClassAgentInstruction       ResourceClassification = "agent-instruction"
	ResourceClassAgentMCPConfig         ResourceClassification = "agent-mcp-configuration"
	ResourceClassAgentReducedSafeguards ResourceClassification = "agent-reduced-safeguards"
	ResourceClassAgentState             ResourceClassification = "agent-state"
	ResourceClassAgentRuntime           ResourceClassification = "agent-runtime"
)

const (
	ResourceClassArchive              ResourceClassification = "archive"
	ResourceClassBrowserDataStore     ResourceClassification = "browser-data-store"
	ResourceClassBrowserCookieStore   ResourceClassification = "browser-cookie-store"
	ResourceClassBrowserPasswordStore ResourceClassification = "browser-password-store"
	ResourceClassBundleIdentifier     ResourceClassification = "bundle-identifier"
	ResourceClassCloudCredentialStore ResourceClassification = "cloud-credential-store"
	ResourceClassCronJob              ResourceClassification = "cron-job"
	ResourceClassCryptoWalletStore    ResourceClassification = "crypto-wallet-store"
	ResourceClassDeveloperTokenStore  ResourceClassification = "developer-token-store"
	ResourceClassInterpreter          ResourceClassification = "interpreter"
	ResourceClassKeychain             ResourceClassification = "keychain"
	ResourceClassLaunchAgent          ResourceClassification = "launch-agent"
	ResourceClassLaunchDaemon         ResourceClassification = "launch-daemon"
	ResourceClassMailDataStore        ResourceClassification = "mail-data-store"
	ResourceClassMessagingDataStore   ResourceClassification = "messaging-data-store"
	ResourceClassNotesDataStore       ResourceClassification = "notes-data-store"
	ResourceClassPackage              ResourceClassification = "package"
	ResourceClassPropertyList         ResourceClassification = "property-list"
	ResourceClassPlistName            ResourceClassification = "plist-name"
	ResourceClassScreenshot           ResourceClassification = "screenshot"
	ResourceClassShellProfile         ResourceClassification = "shell-profile"
	ResourceClassSSHPrivateKey        ResourceClassification = "ssh-private-key"
	ResourceClassVPNProfileStore      ResourceClassification = "vpn-profile-store"
)

var resourceClassifications = [...]ResourceClassification{
	ResourceClassAgentConfiguration,
	ResourceClassAgentHookConfig,
	ResourceClassAgentInstruction,
	ResourceClassAgentMCPConfig,
	ResourceClassAgentReducedSafeguards,
	ResourceClassAgentRuntime,
	ResourceClassAgentState,
	ResourceClassArchive,
	ResourceClassBrowserCookieStore,
	ResourceClassBrowserDataStore,
	ResourceClassBrowserPasswordStore,
	ResourceClassBundleIdentifier,
	ResourceClassCloudCredentialStore,
	ResourceClassCronJob,
	ResourceClassCryptoWalletStore,
	ResourceClassDeveloperTokenStore,
	ResourceClassInterpreter,
	ResourceClassKeychain,
	ResourceClassLaunchAgent,
	ResourceClassLaunchDaemon,
	ResourceClassMailDataStore,
	ResourceClassMessagingDataStore,
	ResourceClassNotesDataStore,
	ResourceClassPackage,
	ResourceClassPlistName,
	ResourceClassPropertyList,
	ResourceClassScreenshot,
	ResourceClassShellProfile,
	ResourceClassSSHPrivateKey,
	ResourceClassVPNProfileStore,
}

// ResourceRole describes how an operation uses a resource. Roles are stable
// join points for rules; they are not presentation labels inferred from order.
type ResourceRole string

const (
	ResourceRoleArguments         ResourceRole = "arguments"
	ResourceRoleCredential        ResourceRole = "credential"
	ResourceRoleExecutable        ResourceRole = "executable"
	ResourceRoleJob               ResourceRole = "job"
	ResourceRoleLocalInput        ResourceRole = "local_input"
	ResourceRoleLocalOutput       ResourceRole = "local_output"
	ResourceRoleRemoteDestination ResourceRole = "remote_destination"
	ResourceRoleRemoteSource      ResourceRole = "remote_source"
	ResourceRoleSource            ResourceRole = "source"
	ResourceRoleStandardInput     ResourceRole = "standard_input"
	ResourceRoleTarget            ResourceRole = "target"
	ResourceRoleTargetMemory      ResourceRole = "target_memory"
	ResourceRoleTargetProcess     ResourceRole = "target_process"
)

var resourceRoles = [...]ResourceRole{
	ResourceRoleArguments,
	ResourceRoleCredential,
	ResourceRoleExecutable,
	ResourceRoleJob,
	ResourceRoleLocalInput,
	ResourceRoleLocalOutput,
	ResourceRoleRemoteDestination,
	ResourceRoleRemoteSource,
	ResourceRoleSource,
	ResourceRoleStandardInput,
	ResourceRoleTarget,
	ResourceRoleTargetMemory,
	ResourceRoleTargetProcess,
}

// ResourceRolePolicy is the immutable public description of one role accepted
// by an operation kind. Kinds is copied before the policy leaves this package.
type ResourceRolePolicy struct {
	Role     ResourceRole   `json:"role"`
	Required bool           `json:"required"`
	Kinds    []ResourceKind `json:"physical_kinds"`
}

var operationResourcePolicies = map[OperationKind][]ResourceRolePolicy{
	OperationArchiveCreate: {
		{Role: ResourceRoleLocalOutput, Required: true, Kinds: []ResourceKind{ResourceFile}},
		{Role: ResourceRoleSource, Kinds: []ResourceKind{ResourceFile}},
	},
	OperationArchiveExtract: {
		{Role: ResourceRoleLocalOutput, Required: true, Kinds: []ResourceKind{ResourceFile}},
		{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceFile}},
	},
	OperationAudioRecordingQueueCreate: {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceAudioInput}}},
	OperationCameraCapture:             {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceCamera}}},
	OperationClipboardRead:             {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceClipboard}}},
	OperationClipboardWrite:            {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceClipboard}}},
	OperationCredentialPrompt:          {{Role: ResourceRoleCredential, Required: true, Kinds: []ResourceKind{ResourceCredential}}},
	OperationCredentialStoreRead:       {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceCredentialStore}}},
	OperationCredentialValidate:        {{Role: ResourceRoleCredential, Required: true, Kinds: []ResourceKind{ResourceCredential}}},
	OperationDataCompress:              {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceData}}},
	OperationDataCrypt:                 {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceData}}},
	OperationDataDecompress:            {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceData}}},
	OperationDataHash:                  {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceData}}},
	OperationDataRandomGenerate:        {{Role: ResourceRoleLocalOutput, Required: true, Kinds: []ResourceKind{ResourceData}}},
	OperationDirectoryCreate:           {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationEnvironmentRead:           {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceConfiguration}}},
	OperationFileCopy: {
		{Role: ResourceRoleLocalOutput, Required: true, Kinds: []ResourceKind{ResourceFile}},
		{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceFile}},
	},
	OperationFileDelete:         {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationFileEnumerate:      {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationFileMakeExecutable: {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationFileMetadataQuery:  {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationFileMove: {
		{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceFile}},
		{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceFile}},
	},
	OperationFileOpen:                      {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationFilePermissionModify:          {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationFileRead:                      {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationFileVisibilityModify:          {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationFileWrite:                     {{Role: ResourceRoleLocalOutput, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationGatekeeperConfigurationModify: {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceConfiguration}}},
	OperationInterpreterInvoke: {
		{Role: ResourceRoleArguments, Kinds: []ResourceKind{ResourceCommand}},
		{Role: ResourceRoleExecutable, Required: true, Kinds: []ResourceKind{ResourceFile}},
		{Role: ResourceRoleLocalInput, Kinds: []ResourceKind{ResourceFile}},
		{Role: ResourceRoleStandardInput, Kinds: []ResourceKind{ResourceCommand}},
	},
	OperationInputEventTapCreate: {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceInputEventStream}}},
	OperationIORead:              {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceIOChannel}}},
	OperationIOWrite:             {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceIOChannel}}},
	OperationKeychainItemQuery:   {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceCredentialStore}}},
	OperationLaunchdJobDeclare:   {{Role: ResourceRoleJob, Required: true, Kinds: []ResourceKind{ResourceLaunchdJob}}},
	OperationLaunchdJobInstall:   {{Role: ResourceRoleJob, Required: true, Kinds: []ResourceKind{ResourceLaunchdJob}}},
	OperationLaunchdJobLoad:      {{Role: ResourceRoleJob, Required: true, Kinds: []ResourceKind{ResourceLaunchdJob}}},
	OperationLaunchdJobRegister:  {{Role: ResourceRoleJob, Required: true, Kinds: []ResourceKind{ResourceLaunchdJob}}},
	OperationLoginItemEnable:     {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceLoginItem}}},
	OperationLoginItemRegister:   {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceLoginItem}}},
	OperationLibraryLoad:         {{Role: ResourceRoleLocalInput, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationNameResolve:         {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceIdentifier}}},
	OperationNetworkConnect: {
		{Role: ResourceRoleRemoteDestination, Required: true, Kinds: []ResourceKind{ResourceNetworkEndpoint, ResourceURL}},
	},
	OperationNetworkConfigurationQuery: {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceConfiguration}}},
	OperationNetworkDownload: {
		{Role: ResourceRoleLocalOutput, Kinds: []ResourceKind{ResourceFile}},
		{Role: ResourceRoleRemoteSource, Required: true, Kinds: []ResourceKind{ResourceNetworkEndpoint, ResourceURL}},
	},
	OperationNetworkUpload: {
		{Role: ResourceRoleLocalInput, Kinds: []ResourceKind{ResourceFile}},
		{Role: ResourceRoleRemoteDestination, Required: true, Kinds: []ResourceKind{ResourceNetworkEndpoint, ResourceURL}},
	},
	OperationPackageInstall:            {{Role: ResourceRoleLocalInput, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationPasteboardItemRead:        {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourcePasteboard}}},
	OperationPasteboardItemWrite:       {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourcePasteboard}}},
	OperationPlistModify:               {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceConfiguration, ResourceFile}}},
	OperationPrivacyAuthorizationReset: {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceConfiguration}}},
	OperationProcessEnumerate: {
		{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceProcess}},
	},
	OperationProcessExecute:         {{Role: ResourceRoleArguments, Kinds: []ResourceKind{ResourceCommand}}, {Role: ResourceRoleExecutable, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationProcessLaunchConfigure: {{Role: ResourceRoleArguments, Kinds: []ResourceKind{ResourceCommand}}, {Role: ResourceRoleExecutable, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationProcessMemoryRead: {
		{Role: ResourceRoleTargetMemory, Kinds: []ResourceKind{ResourceProcessMemory}},
		{Role: ResourceRoleTargetProcess, Required: true, Kinds: []ResourceKind{ResourceProcess}},
	},
	OperationProcessMemoryWrite: {
		{Role: ResourceRoleTargetMemory, Kinds: []ResourceKind{ResourceProcessMemory}},
		{Role: ResourceRoleTargetProcess, Required: true, Kinds: []ResourceKind{ResourceProcess}},
	},
	OperationProcessTaskAccess: {
		{Role: ResourceRoleTargetProcess, Required: true, Kinds: []ResourceKind{ResourceProcess}},
	},
	OperationProcessTraceControl: {
		{Role: ResourceRoleTargetProcess, Required: true, Kinds: []ResourceKind{ResourceProcess}},
	},
	OperationProcessThreadCreate: {
		{Role: ResourceRoleTargetProcess, Required: true, Kinds: []ResourceKind{ResourceProcess}},
	},
	OperationQuarantineAttributeRemove: {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationScreenCapture: {
		{Role: ResourceRoleLocalOutput, Kinds: []ResourceKind{ResourceFile}},
		{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceScreen}},
	},
	OperationScheduledJobRegister: {{Role: ResourceRoleJob, Required: true, Kinds: []ResourceKind{ResourceScheduledJob}}},
	OperationShellProfileModify:   {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceFile}}},
	OperationPipeCreate:           {{Role: ResourceRoleLocalOutput, Required: true, Kinds: []ResourceKind{ResourcePipe}}},
	OperationSocketBind:           {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceSocket}}},
	OperationSocketConnect:        {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceSocket}}},
	OperationSocketCreate:         {{Role: ResourceRoleLocalOutput, Required: true, Kinds: []ResourceKind{ResourceSocket}}},
	OperationSocketListen:         {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceSocket}}},
	OperationSocketReceive:        {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceSocket}}},
	OperationSocketSend:           {{Role: ResourceRoleTarget, Required: true, Kinds: []ResourceKind{ResourceSocket}}},
	OperationSoftwareEnumerate:    {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceSoftware}}},
	OperationSystemInfoQuery:      {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceSystem}}},
	OperationUserInfoQuery:        {{Role: ResourceRoleSource, Required: true, Kinds: []ResourceKind{ResourceUserAccount}}},
}

var classificationKinds = map[ResourceClassification][]ResourceKind{
	ResourceClassAgentConfiguration:     {ResourceFile},
	ResourceClassAgentHookConfig:        {ResourceFile},
	ResourceClassAgentInstruction:       {ResourceFile},
	ResourceClassAgentMCPConfig:         {ResourceFile},
	ResourceClassAgentRuntime:           {ResourceFile},
	ResourceClassAgentReducedSafeguards: {ResourceCommand},
	ResourceClassAgentState:             {ResourceFile},
	ResourceClassArchive:                {ResourceFile},
	ResourceClassBrowserDataStore:       {ResourceFile},
	ResourceClassBrowserCookieStore:     {ResourceFile},
	ResourceClassBrowserPasswordStore:   {ResourceFile},
	ResourceClassBundleIdentifier:       {ResourceIdentifier},
	ResourceClassCloudCredentialStore:   {ResourceFile},
	ResourceClassCronJob:                {ResourceScheduledJob},
	ResourceClassCryptoWalletStore:      {ResourceFile},
	ResourceClassDeveloperTokenStore:    {ResourceFile},
	ResourceClassInterpreter:            {ResourceFile},
	ResourceClassKeychain:               {ResourceCredentialStore, ResourceFile},
	ResourceClassLaunchAgent:            {ResourceLaunchdJob},
	ResourceClassLaunchDaemon:           {ResourceLaunchdJob},
	ResourceClassMailDataStore:          {ResourceFile},
	ResourceClassMessagingDataStore:     {ResourceFile},
	ResourceClassNotesDataStore:         {ResourceFile},
	ResourceClassPackage:                {ResourceFile},
	ResourceClassPropertyList:           {ResourceConfiguration, ResourceFile},
	ResourceClassPlistName:              {ResourceIdentifier},
	ResourceClassScreenshot:             {ResourceFile},
	ResourceClassShellProfile:           {ResourceFile},
	ResourceClassSSHPrivateKey:          {ResourceFile},
	ResourceClassVPNProfileStore:        {ResourceFile},
}

func ResourceKinds() []ResourceKind {
	return append([]ResourceKind(nil), resourceKinds[:]...)
}

func ResourceClassifications() []ResourceClassification {
	return append([]ResourceClassification(nil), resourceClassifications[:]...)
}

func ResourceRoles() []ResourceRole {
	return append([]ResourceRole(nil), resourceRoles[:]...)
}

// ResourceClassificationKinds returns a defensive copy of the physical
// resource kinds accepted by classification.
func ResourceClassificationKinds(classification ResourceClassification) []ResourceKind {
	return append([]ResourceKind(nil), classificationKinds[classification]...)
}

func ValidResourceKind(kind ResourceKind) bool {
	for _, candidate := range resourceKinds {
		if candidate == kind {
			return true
		}
	}
	return false
}

func ValidResourceClassification(classification ResourceClassification) bool {
	_, ok := classificationKinds[classification]
	return ok
}

func ValidResourceRole(role ResourceRole) bool {
	for _, candidate := range resourceRoles {
		if candidate == role {
			return true
		}
	}
	return false
}

// ValidResourceClassificationForKind prevents semantic classifications from
// silently changing a resource's physical kind.
func ValidResourceClassificationForKind(kind ResourceKind, classification ResourceClassification) bool {
	allowed, ok := classificationKinds[classification]
	if !ok {
		return false
	}
	for _, candidate := range allowed {
		if candidate == kind {
			return true
		}
	}
	return false
}

// OperationResourcePolicy returns a deterministic defensive copy of the role
// policy for kind.
func OperationResourcePolicy(kind OperationKind) []ResourceRolePolicy {
	policy := operationResourcePolicies[kind]
	out := make([]ResourceRolePolicy, len(policy))
	for index, item := range policy {
		out[index] = item
		out[index].Kinds = append([]ResourceKind(nil), item.Kinds...)
	}
	return out
}

// ValidOperationResourceRole reports whether an operation accepts the given
// role and physical resource kind.
func ValidOperationResourceRole(kind OperationKind, role ResourceRole, resourceKind ResourceKind) bool {
	for _, item := range operationResourcePolicies[kind] {
		if item.Role != role {
			continue
		}
		for _, allowed := range item.Kinds {
			if allowed == resourceKind {
				return true
			}
		}
		return false
	}
	return false
}
