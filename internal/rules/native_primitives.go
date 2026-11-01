package rules

import "github.com/0x4D31/maratus/internal/behavior"

// Native primitive rules deliberately describe the action established by an
// exact located API call and no more. They give analysts a useful capability
// inventory without assigning malicious intent, successful effect, concrete
// arguments, or ATT&CK objectives that require additional context.

var MacOSFileOpen = primitiveRule("macos.file-open", "Opens filesystem paths", "macos.technical.filesystem", behavior.OperationFileOpen, behavior.ResourceRoleSource, behavior.ResourceFile)

var MacOSFileDelete = primitiveRule("macos.file-delete", "Deletes filesystem entries", "macos.technical.filesystem", behavior.OperationFileDelete, behavior.ResourceRoleTarget, behavior.ResourceFile)

var MacOSFileCopy = Spec{
	Metadata: Metadata{ID: "macos.file-copy", Title: "Copies filesystem entries", Namespace: "macos.technical.filesystem", Description: "A modeled operation copies one filesystem entry to another. Exact paths are retained when statically known; this does not establish malicious staging or runtime success."},
	Kind:     CapabilityRule,
	Match: Operation(
		behavior.OperationFileCopy,
		ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile),
		ResourceBinding(behavior.ResourceRoleLocalOutput, behavior.ResourceFile),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSFileWrite = primitiveRule("macos.file-write", "Writes filesystem content", "macos.technical.filesystem", behavior.OperationFileWrite, behavior.ResourceRoleLocalOutput, behavior.ResourceFile)

var MacOSFileMove = Spec{
	Metadata: Metadata{ID: "macos.file-move", Title: "Moves or renames filesystem entries", Namespace: "macos.technical.filesystem", Description: "An exact called native API models a filesystem rename or move. Source and destination paths and runtime success may remain unresolved."},
	Kind:     CapabilityRule,
	Match: Operation(
		behavior.OperationFileMove,
		ResourceBinding(behavior.ResourceRoleSource, behavior.ResourceFile),
		ResourceBinding(behavior.ResourceRoleTarget, behavior.ResourceFile),
	),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSDirectoryCreate = primitiveRule("macos.directory-create", "Creates directories", "macos.technical.filesystem", behavior.OperationDirectoryCreate, behavior.ResourceRoleTarget, behavior.ResourceFile)

var MacOSFileMetadataQuery = primitiveRule("macos.file-metadata-query", "Queries filesystem metadata", "macos.technical.filesystem", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource, behavior.ResourceFile)

var MacOSFilePermissionModify = primitiveRule("macos.file-permission-modify", "Changes file permissions or ownership", "macos.technical.filesystem", behavior.OperationFilePermissionModify, behavior.ResourceRoleTarget, behavior.ResourceFile)

var MacOSDescriptorRead = primitiveRule("macos.descriptor-read", "Reads from descriptors or streams", "macos.technical.io", behavior.OperationIORead, behavior.ResourceRoleSource, behavior.ResourceIOChannel)

var MacOSDescriptorWrite = primitiveRule("macos.descriptor-write", "Writes to descriptors or streams", "macos.technical.io", behavior.OperationIOWrite, behavior.ResourceRoleTarget, behavior.ResourceIOChannel)

var MacOSEnvironmentRead = primitiveRule("macos.environment-read", "Reads the process environment", "macos.technical.runtime", behavior.OperationEnvironmentRead, behavior.ResourceRoleSource, behavior.ResourceConfiguration)

var MacOSDynamicLibraryLoad = Spec{
	Metadata:       Metadata{ID: "macos.dynamic-library-load", Title: "Loads a dynamic library", Namespace: "macos.technical.runtime", Description: "An exact called native API models loading a dynamic library. The library path and runtime success may remain unresolved.", Attack: []string{"T1129"}},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationLibraryLoad, ResourceBinding(behavior.ResourceRoleLocalInput, behavior.ResourceFile)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSPipeCreate = primitiveRule("macos.pipe-create", "Creates an anonymous pipe", "macos.technical.communication", behavior.OperationPipeCreate, behavior.ResourceRoleLocalOutput, behavior.ResourcePipe)

var MacOSPasteboardItemRead = Spec{
	Metadata:       Metadata{ID: "macos.pasteboard-item-read", Title: "Reads an item from a pasteboard", Namespace: "macos.technical.data", Description: "An exact called Carbon Pasteboard API reads item data from an unresolved pasteboard reference. The reference may identify the general clipboard, a named pasteboard, or drag-and-drop data; this does not independently establish clipboard collection."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationPasteboardItemRead, ResourceBinding(behavior.ResourceRoleSource, behavior.ResourcePasteboard)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSPasteboardItemWrite = Spec{
	Metadata:       Metadata{ID: "macos.pasteboard-item-write", Title: "Writes an item to a pasteboard", Namespace: "macos.technical.data", Description: "An exact called Carbon Pasteboard API writes item data to an unresolved pasteboard reference. The reference may identify the general clipboard, a named pasteboard, or drag-and-drop data; this does not independently establish clipboard replacement."},
	Kind:           CapabilityRule,
	Match:          Operation(behavior.OperationPasteboardItemWrite, ResourceBinding(behavior.ResourceRoleTarget, behavior.ResourcePasteboard)),
	MinimumSupport: behavior.SupportCorroborated,
}

var MacOSSocketCreate = primitiveRule("macos.socket-create", "Creates sockets", "macos.technical.communication", behavior.OperationSocketCreate, behavior.ResourceRoleLocalOutput, behavior.ResourceSocket)

var MacOSSocketConnect = primitiveRule("macos.socket-connect", "Connects sockets", "macos.technical.communication", behavior.OperationSocketConnect, behavior.ResourceRoleTarget, behavior.ResourceSocket)

var MacOSSocketBind = primitiveRule("macos.socket-bind", "Binds sockets", "macos.technical.communication", behavior.OperationSocketBind, behavior.ResourceRoleTarget, behavior.ResourceSocket)

var MacOSSocketListen = primitiveRule("macos.socket-listen", "Listens on sockets", "macos.technical.communication", behavior.OperationSocketListen, behavior.ResourceRoleTarget, behavior.ResourceSocket)

var MacOSSocketSend = primitiveRule("macos.socket-send", "Sends data through sockets", "macos.technical.communication", behavior.OperationSocketSend, behavior.ResourceRoleTarget, behavior.ResourceSocket)

var MacOSSocketReceive = primitiveRule("macos.socket-receive", "Receives data from sockets", "macos.technical.communication", behavior.OperationSocketReceive, behavior.ResourceRoleSource, behavior.ResourceSocket)

var MacOSNameResolve = primitiveRule("macos.name-resolve", "Resolves host or service addresses", "macos.technical.communication", behavior.OperationNameResolve, behavior.ResourceRoleSource, behavior.ResourceIdentifier)

var MacOSDataHash = primitiveRule("macos.data-hash", "Uses data hashing APIs", "macos.technical.data", behavior.OperationDataHash, behavior.ResourceRoleSource, behavior.ResourceData)

var MacOSDataCrypt = primitiveRule("macos.data-crypt", "Uses data encryption or decryption APIs", "macos.technical.data", behavior.OperationDataCrypt, behavior.ResourceRoleSource, behavior.ResourceData)

var MacOSDataCompress = primitiveRule("macos.data-compress", "Uses data compression APIs", "macos.technical.data", behavior.OperationDataCompress, behavior.ResourceRoleSource, behavior.ResourceData)

var MacOSDataDecompress = primitiveRule("macos.data-decompress", "Uses data decompression APIs", "macos.technical.data", behavior.OperationDataDecompress, behavior.ResourceRoleSource, behavior.ResourceData)

var MacOSDataRandomGenerate = primitiveRule("macos.data-random-generate", "Generates random bytes", "macos.technical.data", behavior.OperationDataRandomGenerate, behavior.ResourceRoleLocalOutput, behavior.ResourceData)

var MacOSProcessTraceControl = primitiveRule("macos.process-trace-control", "Controls process tracing", "macos.technical.execution", behavior.OperationProcessTraceControl, behavior.ResourceRoleTargetProcess, behavior.ResourceProcess)

func primitiveRule(id, title, namespace string, kind behavior.OperationKind, role behavior.ResourceRole, resource behavior.ResourceKind) Spec {
	return Spec{
		Metadata: Metadata{
			ID: id, Title: title, Namespace: namespace,
			Description: "An exact located native API call models this primitive. Arguments, affected object identity, intent, and runtime success may remain unresolved.",
		},
		Kind:           CapabilityRule,
		Match:          Operation(kind, ResourceBinding(role, resource)),
		MinimumSupport: behavior.SupportCorroborated,
	}
}
