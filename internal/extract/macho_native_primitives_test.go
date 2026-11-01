package extract

import (
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestNativePrimitiveTableUsesExactReusableAPISemantics(t *testing.T) {
	tests := map[string]behavior.OperationKind{
		"open":                behavior.OperationFileOpen,
		"fread":               behavior.OperationIORead,
		"writev":              behavior.OperationIOWrite,
		"unlinkat":            behavior.OperationFileDelete,
		"renameat":            behavior.OperationFileMove,
		"mkdir":               behavior.OperationDirectoryCreate,
		"lstat$INODE64":       behavior.OperationFileMetadataQuery,
		"chmod$UNIX2003":      behavior.OperationFilePermissionModify,
		"getenv":              behavior.OperationEnvironmentRead,
		"dlopen":              behavior.OperationLibraryLoad,
		"pipe":                behavior.OperationPipeCreate,
		"socket":              behavior.OperationSocketCreate,
		"connect$NOCANCEL":    behavior.OperationSocketConnect,
		"bind":                behavior.OperationSocketBind,
		"listen":              behavior.OperationSocketListen,
		"sendmsg$NOCANCEL":    behavior.OperationSocketSend,
		"recvfrom":            behavior.OperationSocketReceive,
		"getaddrinfo":         behavior.OperationNameResolve,
		"CC_SHA256_Update":    behavior.OperationDataHash,
		"CCCryptorGCMEncrypt": behavior.OperationDataCrypt,
		"deflateInit2_":       behavior.OperationDataCompress,
		"inflateInit2_":       behavior.OperationDataDecompress,
		"SecRandomCopyBytes":  behavior.OperationDataRandomGenerate,
		"ptrace":              behavior.OperationProcessTraceControl,
	}
	for symbol, want := range tests {
		t.Run(symbol, func(t *testing.T) {
			got, ok := nativePrimitiveForSymbol(symbol)
			if !ok || got.kind != want || got.qualifiers["resource_binding"] != "unresolved" {
				t.Fatalf("nativePrimitiveForSymbol(%q) = %#v, %v; want %s", symbol, got, ok, want)
			}
		})
	}
}

func TestNativePrimitiveTableRejectsNearNamesAndGenericRoutines(t *testing.T) {
	for _, symbol := range []string{
		"openHelper", "freadable", "writeValue", "unlinkIfPresent", "rename_item",
		"socketFactory", "connector", "sender", "receiver", "getaddrinfo_cached",
		"CCCryptic", "CC_SHA256Fake", "CCHmacWrapper", "EVP_DigestMystery", "SHA256Transform",
		"deflater", "inflater", "my_stream_encoder", "custom_raw_decoder", "arc4random_custom", "randomBytes",
	} {
		if got, ok := nativePrimitiveForSymbol(symbol); ok {
			t.Fatalf("near-name %q became native primitive %#v", symbol, got)
		}
	}
}
