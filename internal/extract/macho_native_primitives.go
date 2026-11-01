package extract

import (
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

// nativePrimitive describes a semantic action that follows from an exact,
// located call to a native API. The table deliberately stops at the primitive:
// arguments, affected objects, intent, and runtime success remain unresolved
// unless a separate bounded data-flow recognizer proves them.
type nativePrimitive struct {
	kind       behavior.OperationKind
	resource   behavior.Resource
	qualifiers map[string]string
	bindings   []behavior.ResourceBinding
}

func machoStringArgumentIndexesForSymbol(symbol string) []int {
	symbol = strings.TrimPrefix(symbol, "_")
	if isNativeProcessExecutionSymbol(symbol) {
		return []int{nativeProcessExecutableArgumentIndex(symbol)}
	}
	switch {
	case isFileOpenSymbol(symbol):
		if symbol == "openat" {
			return []int{1}
		}
		return []int{0}
	case isFilesystemDeleteSymbol(symbol):
		if symbol == "unlinkat" {
			return []int{1}
		}
		return []int{0}
	case isFilesystemMoveSymbol(symbol):
		if symbol == "renameat" {
			return []int{1, 3}
		}
		return []int{0, 1}
	case isDirectoryCreateSymbol(symbol):
		if symbol == "mkdirat" {
			return []int{1}
		}
		return []int{0}
	case isFileMetadataQuerySymbol(symbol):
		switch symbol {
		case "faccessat", "fstatat":
			return []int{1}
		case "fstat", "fstat$INODE64":
			return nil
		default:
			return []int{0}
		}
	case isFilePermissionModifySymbol(symbol):
		switch symbol {
		case "fchmodat", "fchownat":
			return []int{1}
		case "fchmod", "fchown":
			return nil
		default:
			return []int{0}
		}
	case symbol == "getenv" || symbol == "dlopen" || symbol == "getaddrinfo":
		return []int{0}
	default:
		return nil
	}
}

func nativePrimitiveForSymbol(symbol string) (nativePrimitive, bool) {
	symbol = strings.TrimPrefix(symbol, "_")
	unknown := func(kind behavior.OperationKind, resource behavior.Resource) (nativePrimitive, bool) {
		return nativePrimitive{
			kind:     kind,
			resource: resource,
			qualifiers: map[string]string{
				"resource_binding": "unresolved",
			},
		}, true
	}
	switch {
	case isFileOpenSymbol(symbol):
		return unknown(behavior.OperationFileOpen, behavior.NewResource(behavior.ResourceFile, ""))
	case isDescriptorReadSymbol(symbol):
		return unknown(behavior.OperationIORead, behavior.NewResource(behavior.ResourceIOChannel, ""))
	case isDescriptorWriteSymbol(symbol):
		return unknown(behavior.OperationIOWrite, behavior.NewResource(behavior.ResourceIOChannel, ""))
	case isFilesystemDeleteSymbol(symbol):
		return unknown(behavior.OperationFileDelete, behavior.NewResource(behavior.ResourceFile, ""))
	case isFilesystemMoveSymbol(symbol):
		primitive, _ := unknown(behavior.OperationFileMove, behavior.NewResource(behavior.ResourceFile, ""))
		primitive.bindings = behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, "")),
			behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, "")),
		)
		return primitive, true
	case isDirectoryCreateSymbol(symbol):
		return unknown(behavior.OperationDirectoryCreate, behavior.NewResource(behavior.ResourceFile, ""))
	case isFileMetadataQuerySymbol(symbol):
		return unknown(behavior.OperationFileMetadataQuery, behavior.NewResource(behavior.ResourceFile, ""))
	case isFilePermissionModifySymbol(symbol):
		return unknown(behavior.OperationFilePermissionModify, behavior.NewResource(behavior.ResourceFile, ""))
	case symbol == "getenv":
		return unknown(behavior.OperationEnvironmentRead, behavior.NewResource(behavior.ResourceConfiguration, ""))
	case symbol == "dlopen":
		return unknown(behavior.OperationLibraryLoad, behavior.NewResource(behavior.ResourceFile, ""))
	case symbol == "pipe" || symbol == "pipe2":
		return unknown(behavior.OperationPipeCreate, behavior.NewResource(behavior.ResourcePipe, ""))
	case isSocketCreateSymbol(symbol):
		return unknown(behavior.OperationSocketCreate, behavior.NewResource(behavior.ResourceSocket, ""))
	case isSocketConnectPrimitiveSymbol(symbol):
		return unknown(behavior.OperationSocketConnect, behavior.NewResource(behavior.ResourceSocket, ""))
	case symbol == "bind":
		return unknown(behavior.OperationSocketBind, behavior.NewResource(behavior.ResourceSocket, ""))
	case symbol == "listen":
		return unknown(behavior.OperationSocketListen, behavior.NewResource(behavior.ResourceSocket, ""))
	case isSocketSendSymbol(symbol):
		return unknown(behavior.OperationSocketSend, behavior.NewResource(behavior.ResourceSocket, ""))
	case isSocketReceiveSymbol(symbol):
		return unknown(behavior.OperationSocketReceive, behavior.NewResource(behavior.ResourceSocket, ""))
	case symbol == "getaddrinfo":
		return unknown(behavior.OperationNameResolve, behavior.NewResource(behavior.ResourceIdentifier, ""))
	case isDataHashSymbol(symbol):
		return unknown(behavior.OperationDataHash, behavior.NewResource(behavior.ResourceData, ""))
	case isDataCryptSymbol(symbol):
		return unknown(behavior.OperationDataCrypt, behavior.NewResource(behavior.ResourceData, ""))
	case isDataCompressSymbol(symbol):
		return unknown(behavior.OperationDataCompress, behavior.NewResource(behavior.ResourceData, ""))
	case isDataDecompressSymbol(symbol):
		return unknown(behavior.OperationDataDecompress, behavior.NewResource(behavior.ResourceData, ""))
	case isRandomGenerateSymbol(symbol):
		return unknown(behavior.OperationDataRandomGenerate, behavior.NewResource(behavior.ResourceData, ""))
	case symbol == "ptrace":
		return unknown(behavior.OperationProcessTraceControl, behavior.NewResource(behavior.ResourceProcess, ""))
	default:
		return nativePrimitive{}, false
	}
}

// nativePrimitiveArgumentBindings maps only ABI positions whose C signatures
// identify a string as the affected resource. Descriptor, handle, sockaddr,
// buffer, and callback arguments deliberately remain unresolved: a printable
// value in the same register is not proof of those typed objects.
func nativePrimitiveArgumentBindings(symbol string, context machoCallContext) []behavior.ResourceBinding {
	symbol = strings.TrimPrefix(symbol, "_")
	bind := func(role behavior.ResourceRole, kind behavior.ResourceKind, index int) (behavior.ResourceBinding, bool) {
		argument := context.stringArgument(index)
		if argument.Value == "" || len(argument.EvidenceIDs) == 0 {
			return behavior.ResourceBinding{}, false
		}
		return behavior.Bind(role, behavior.NewResource(kind, argument.Value), argument.EvidenceIDs...), true
	}
	one := func(role behavior.ResourceRole, kind behavior.ResourceKind, index int) []behavior.ResourceBinding {
		binding, ok := bind(role, kind, index)
		if !ok {
			return nil
		}
		return behavior.Bindings(binding)
	}

	switch {
	case isFileOpenSymbol(symbol):
		index := 0
		if symbol == "openat" {
			index = 1
		}
		return one(behavior.ResourceRoleSource, behavior.ResourceFile, index)
	case isFilesystemDeleteSymbol(symbol):
		index := 0
		if symbol == "unlinkat" {
			index = 1
		}
		return one(behavior.ResourceRoleTarget, behavior.ResourceFile, index)
	case isFilesystemMoveSymbol(symbol):
		sourceIndex, targetIndex := 0, 1
		if symbol == "renameat" {
			sourceIndex, targetIndex = 1, 3
		}
		source, sourceOK := bind(behavior.ResourceRoleSource, behavior.ResourceFile, sourceIndex)
		target, targetOK := bind(behavior.ResourceRoleTarget, behavior.ResourceFile, targetIndex)
		if !sourceOK || !targetOK {
			return nil
		}
		return behavior.Bindings(source, target)
	case isDirectoryCreateSymbol(symbol):
		index := 0
		if symbol == "mkdirat" {
			index = 1
		}
		return one(behavior.ResourceRoleTarget, behavior.ResourceFile, index)
	case isFileMetadataQuerySymbol(symbol):
		index := 0
		switch symbol {
		case "faccessat", "fstatat":
			index = 1
		case "fstat", "fstat$INODE64":
			return nil
		}
		return one(behavior.ResourceRoleSource, behavior.ResourceFile, index)
	case isFilePermissionModifySymbol(symbol):
		index := 0
		switch symbol {
		case "fchmodat", "fchownat":
			index = 1
		case "fchmod", "fchown":
			return nil
		}
		return one(behavior.ResourceRoleTarget, behavior.ResourceFile, index)
	case symbol == "getenv":
		return one(behavior.ResourceRoleSource, behavior.ResourceConfiguration, 0)
	case symbol == "dlopen":
		return one(behavior.ResourceRoleLocalInput, behavior.ResourceFile, 0)
	case symbol == "getaddrinfo":
		return one(behavior.ResourceRoleSource, behavior.ResourceIdentifier, 0)
	default:
		return nil
	}
}

func isDescriptorReadSymbol(symbol string) bool { return isFileReadSymbol(symbol) }

func isDescriptorWriteSymbol(symbol string) bool {
	switch symbol {
	case "write", "write$NOCANCEL", "pwrite", "pwrite$UNIX2003", "writev", "fwrite", "fwrite_unlocked":
		return true
	default:
		return false
	}
}

func isFilesystemDeleteSymbol(symbol string) bool {
	switch symbol {
	case "unlink", "unlinkat", "remove", "rmdir":
		return true
	default:
		return false
	}
}

func isFilesystemMoveSymbol(symbol string) bool { return symbol == "rename" || symbol == "renameat" }

func isDirectoryCreateSymbol(symbol string) bool { return symbol == "mkdir" || symbol == "mkdirat" }

func isFileMetadataQuerySymbol(symbol string) bool {
	switch symbol {
	case "access", "faccessat", "fstat", "fstat$INODE64", "fstatat", "lstat", "lstat$INODE64", "lstat64", "stat", "stat$INODE64", "stat64", "statfs", "statfs$INODE64", "statvfs":
		return true
	default:
		return false
	}
}

func isFilePermissionModifySymbol(symbol string) bool {
	switch symbol {
	case "chmod", "chmod$UNIX2003", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "lchown":
		return true
	default:
		return false
	}
}

func isSocketCreateSymbol(symbol string) bool { return symbol == "socket" || symbol == "socketpair" }

func isSocketConnectPrimitiveSymbol(symbol string) bool {
	return symbol == "connect" || symbol == "connect$NOCANCEL" || symbol == "connectx"
}

func isSocketSendSymbol(symbol string) bool {
	switch symbol {
	case "send", "send$NOCANCEL", "sendmsg", "sendmsg$NOCANCEL", "sendto":
		return true
	default:
		return false
	}
}

func isSocketReceiveSymbol(symbol string) bool {
	switch symbol {
	case "recv", "recv$NOCANCEL", "recvfrom", "recvmsg", "recvmsg$NOCANCEL":
		return true
	default:
		return false
	}
}

func isDataHashSymbol(symbol string) bool {
	for _, base := range []string{"CC_MD5", "CC_SHA1", "CC_SHA224", "CC_SHA256", "CC_SHA384", "CC_SHA512"} {
		if nativeAPIWithSuffix(symbol, base, "", "_Init", "_Update", "_Final", "_Transform") {
			return true
		}
	}
	return nativeAPIWithSuffix(symbol, "CCHmac", "", "Init", "Update", "Final", "OneShot") ||
		nativeAPIWithSuffix(symbol, "EVP_Digest", "", "Init", "Init_ex", "Init_ex2", "Update", "Final", "Final_ex")
}

func isDataCryptSymbol(symbol string) bool {
	return symbol == "CCCrypt" || nativeAPIWithSuffix(symbol, "CCCryptor", "Create", "CreateFromData", "Update", "Final", "Release", "Reset", "GetOutputLength", "GCMAddIV", "GCMAddAAD", "GCMEncrypt", "GCMDecrypt", "GCMFinal", "GCMReset") ||
		nativeAPIWithSuffix(symbol, "EVP_Encrypt", "Init", "Init_ex", "Init_ex2", "Update", "Final", "Final_ex") ||
		nativeAPIWithSuffix(symbol, "EVP_Decrypt", "Init", "Init_ex", "Init_ex2", "Update", "Final", "Final_ex") ||
		nativeAPIWithSuffix(symbol, "EVP_Cipher", "", "Init", "Init_ex", "Init_ex2", "Update", "Final", "Final_ex")
}

func nativeAPIWithSuffix(symbol, base string, suffixes ...string) bool {
	if !strings.HasPrefix(symbol, base) {
		return false
	}
	suffix := strings.TrimPrefix(symbol, base)
	for _, allowed := range suffixes {
		if suffix == allowed {
			return true
		}
	}
	return false
}

func isDataCompressSymbol(symbol string) bool {
	switch symbol {
	case "compress", "compress2", "BZ2_bzCompress", "BZ2_bzCompressInit", "BZ2_bzCompressEnd",
		"lzma_stream_encoder", "lzma_easy_encoder", "lzma_raw_encoder", "lzma_alone_encoder":
		return true
	default:
		return nativeAPIFamily(symbol, "deflate")
	}
}

func isDataDecompressSymbol(symbol string) bool {
	switch symbol {
	case "uncompress", "BZ2_bzDecompress", "BZ2_bzDecompressInit", "BZ2_bzDecompressEnd",
		"lzma_stream_decoder", "lzma_auto_decoder", "lzma_raw_decoder", "lzma_alone_decoder":
		return true
	default:
		return nativeAPIFamily(symbol, "inflate")
	}
}

func nativeAPIFamily(symbol, prefix string) bool {
	if symbol == prefix {
		return true
	}
	if !strings.HasPrefix(symbol, prefix) || len(symbol) == len(prefix) {
		return false
	}
	next := symbol[len(prefix)]
	return next == '_' || next == '$' || next >= 'A' && next <= 'Z' || next >= '0' && next <= '9'
}

func isRandomGenerateSymbol(symbol string) bool {
	return symbol == "SecRandomCopyBytes" || symbol == "CCRandomGenerateBytes" || symbol == "getentropy" ||
		nativeAPIWithSuffix(symbol, "arc4random", "", "_buf", "_uniform", "_stir", "_addrandom")
}
