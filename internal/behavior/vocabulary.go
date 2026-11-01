package behavior

// OperationKind is the closed vocabulary for primitive modeled operations.
// Names describe what the represented code or metadata does; ATT&CK/MBC
// objectives belong to capability rules rather than this semantic layer.
type OperationKind string

const (
	OperationArchiveCreate                 OperationKind = "archive.create"
	OperationArchiveExtract                OperationKind = "archive.extract"
	OperationAudioRecordingQueueCreate     OperationKind = "audio.recording-queue.create"
	OperationCameraCapture                 OperationKind = "camera.capture"
	OperationClipboardRead                 OperationKind = "clipboard.read"
	OperationClipboardWrite                OperationKind = "clipboard.write"
	OperationCredentialPrompt              OperationKind = "credential.prompt"
	OperationCredentialStoreRead           OperationKind = "credential.store.read"
	OperationCredentialValidate            OperationKind = "credential.validate"
	OperationDataCompress                  OperationKind = "data.compress"
	OperationDataCrypt                     OperationKind = "data.crypt"
	OperationDataDecompress                OperationKind = "data.decompress"
	OperationDataHash                      OperationKind = "data.hash"
	OperationDataRandomGenerate            OperationKind = "data.random.generate"
	OperationDirectoryCreate               OperationKind = "directory.create"
	OperationEnvironmentRead               OperationKind = "environment.read"
	OperationFileCopy                      OperationKind = "file.copy"
	OperationFileDelete                    OperationKind = "file.delete"
	OperationFileEnumerate                 OperationKind = "file.enumerate"
	OperationFileMakeExecutable            OperationKind = "file.make-executable"
	OperationFileMetadataQuery             OperationKind = "file.metadata.query"
	OperationFileMove                      OperationKind = "file.move"
	OperationFileOpen                      OperationKind = "file.open"
	OperationFilePermissionModify          OperationKind = "file.permission.modify"
	OperationFileRead                      OperationKind = "file.read"
	OperationFileVisibilityModify          OperationKind = "file.visibility.modify"
	OperationFileWrite                     OperationKind = "file.write"
	OperationGatekeeperConfigurationModify OperationKind = "gatekeeper.configuration.modify"
	OperationInterpreterInvoke             OperationKind = "interpreter.invoke"
	OperationInputEventTapCreate           OperationKind = "input-event.tap.create"
	OperationIORead                        OperationKind = "io.read"
	OperationIOWrite                       OperationKind = "io.write"
	OperationKeychainItemQuery             OperationKind = "keychain.item.query"
	OperationLaunchdJobDeclare             OperationKind = "launchd.job.declare"
	OperationLaunchdJobInstall             OperationKind = "launchd.job.install"
	OperationLaunchdJobLoad                OperationKind = "launchd.job.load"
	OperationLaunchdJobRegister            OperationKind = "launchd.job.register"
	OperationLoginItemEnable               OperationKind = "login-item.enable"
	OperationLoginItemRegister             OperationKind = "login-item.register"
	OperationLibraryLoad                   OperationKind = "library.load"
	OperationNameResolve                   OperationKind = "name.resolve"
	OperationNetworkConnect                OperationKind = "network.connect"
	OperationNetworkConfigurationQuery     OperationKind = "network.configuration.query"
	OperationNetworkDownload               OperationKind = "network.download"
	OperationNetworkUpload                 OperationKind = "network.upload"
	OperationPackageInstall                OperationKind = "package.install"
	OperationPasteboardItemRead            OperationKind = "pasteboard.item.read"
	OperationPasteboardItemWrite           OperationKind = "pasteboard.item.write"
	OperationPlistModify                   OperationKind = "plist.modify"
	OperationPrivacyAuthorizationReset     OperationKind = "privacy.authorization.reset"
	OperationProcessEnumerate              OperationKind = "process.enumerate"
	OperationProcessExecute                OperationKind = "process.execute"
	OperationProcessLaunchConfigure        OperationKind = "process.launch.configure"
	OperationProcessMemoryRead             OperationKind = "process.memory.read"
	OperationProcessMemoryWrite            OperationKind = "process.memory.write"
	OperationProcessTaskAccess             OperationKind = "process.task-access"
	OperationProcessTraceControl           OperationKind = "process.trace-control"
	OperationProcessThreadCreate           OperationKind = "process.thread.create"
	OperationQuarantineAttributeRemove     OperationKind = "quarantine.attribute.remove"
	OperationScreenCapture                 OperationKind = "screen.capture"
	OperationScheduledJobRegister          OperationKind = "scheduled-job.register"
	OperationShellProfileModify            OperationKind = "shell.profile.modify"
	OperationPipeCreate                    OperationKind = "pipe.create"
	OperationSocketBind                    OperationKind = "socket.bind"
	OperationSocketConnect                 OperationKind = "socket.connect"
	OperationSocketCreate                  OperationKind = "socket.create"
	OperationSocketListen                  OperationKind = "socket.listen"
	OperationSocketReceive                 OperationKind = "socket.receive"
	OperationSocketSend                    OperationKind = "socket.send"
	OperationSoftwareEnumerate             OperationKind = "software.enumerate"
	OperationSystemInfoQuery               OperationKind = "system.info.query"
	OperationUserInfoQuery                 OperationKind = "user.info.query"
)

var operationKinds = [...]OperationKind{
	OperationArchiveCreate,
	OperationArchiveExtract,
	OperationAudioRecordingQueueCreate,
	OperationCameraCapture,
	OperationClipboardRead,
	OperationClipboardWrite,
	OperationCredentialPrompt,
	OperationCredentialStoreRead,
	OperationCredentialValidate,
	OperationDataCompress,
	OperationDataCrypt,
	OperationDataDecompress,
	OperationDataHash,
	OperationDataRandomGenerate,
	OperationDirectoryCreate,
	OperationEnvironmentRead,
	OperationFileCopy,
	OperationFileDelete,
	OperationFileEnumerate,
	OperationFileMakeExecutable,
	OperationFileMetadataQuery,
	OperationFileMove,
	OperationFileOpen,
	OperationFilePermissionModify,
	OperationFileRead,
	OperationFileVisibilityModify,
	OperationFileWrite,
	OperationGatekeeperConfigurationModify,
	OperationInputEventTapCreate,
	OperationInterpreterInvoke,
	OperationIORead,
	OperationIOWrite,
	OperationKeychainItemQuery,
	OperationLaunchdJobDeclare,
	OperationLaunchdJobInstall,
	OperationLaunchdJobLoad,
	OperationLaunchdJobRegister,
	OperationLibraryLoad,
	OperationLoginItemEnable,
	OperationLoginItemRegister,
	OperationNameResolve,
	OperationNetworkConfigurationQuery,
	OperationNetworkConnect,
	OperationNetworkDownload,
	OperationNetworkUpload,
	OperationPackageInstall,
	OperationPasteboardItemRead,
	OperationPasteboardItemWrite,
	OperationPipeCreate,
	OperationPlistModify,
	OperationPrivacyAuthorizationReset,
	OperationProcessEnumerate,
	OperationProcessExecute,
	OperationProcessLaunchConfigure,
	OperationProcessMemoryRead,
	OperationProcessMemoryWrite,
	OperationProcessTaskAccess,
	OperationProcessThreadCreate,
	OperationProcessTraceControl,
	OperationQuarantineAttributeRemove,
	OperationScheduledJobRegister,
	OperationScreenCapture,
	OperationShellProfileModify,
	OperationSocketBind,
	OperationSocketConnect,
	OperationSocketCreate,
	OperationSocketListen,
	OperationSocketReceive,
	OperationSocketSend,
	OperationSoftwareEnumerate,
	OperationSystemInfoQuery,
	OperationUserInfoQuery,
}

// OperationKinds returns the deterministic closed semantic vocabulary. The
// returned slice is independent so callers cannot mutate the authority list.
func OperationKinds() []OperationKind {
	return append([]OperationKind(nil), operationKinds[:]...)
}

// ValidOperationKind reports whether kind belongs to the closed semantic
// vocabulary. New extractors may only emit a kind after it is defined here.
func ValidOperationKind(kind OperationKind) bool {
	for _, candidate := range operationKinds {
		if candidate == kind {
			return true
		}
	}
	return false
}
