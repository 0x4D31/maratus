package artifact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/0x4D31/maratus/internal/plistx"
)

const (
	hdiutilPath                = "/usr/bin/hdiutil"
	dmgAttachTimeout           = 60 * time.Second
	dmgDetachTimeout           = 20 * time.Second
	dmgDetachTotalTimeout      = 60 * time.Second
	maxDMGMountDirectories     = 64
	maxDMGAttachments          = 64
	maxDMGCleanupTargets       = 64
	maxHdiutilOutputBytes      = 4 << 20
	maxHdiutilStderrBytes      = 64 << 10
	zipPasswordEnvironmentName = "MARATUS_ZIP_PASSWORD"
)

// DMGTemporaryDirectoryEnvironment names the private scratch parent supplied
// by the supervised worker. It is separate from TMPDIR so the parent never
// recursively removes a directory that may still contain an uncertain mount.
const DMGTemporaryDirectoryEnvironment = "MARATUS_INTERNAL_DMG_TMPDIR"

func (s *scanner) scanDMG(parentID, logical string, data []byte, depth int) {
	if !s.options.AllowDMGMount {
		s.markNodePartial(parentID, "DMG contents not inspected by the portable core")
		s.addDMGDiagnostic(logical)
		return
	}
	if runtime.GOOS != "darwin" {
		s.markNodePartial(parentID, "system DMG extraction requires macOS; contents not inspected")
		s.addDiagnostic(fmt.Sprintf("%s: DMG detected; system DMG extraction requires macOS; contents not inspected", logical))
		return
	}
	if _, err := os.Stat(hdiutilPath); err != nil {
		s.markNodePartial(parentID, "system DMG extractor unavailable; contents not inspected")
		s.addDiagnostic(fmt.Sprintf("%s: DMG detected; %s unavailable; contents not inspected", logical, hdiutilPath))
		return
	}
	if len(data) == 0 {
		s.markNodePartial(parentID, "no retained DMG image bytes; contents not inspected")
		s.addDiagnostic(fmt.Sprintf("%s: DMG detected; no retained image bytes available for system extraction", logical))
		return
	}
	tmp, err := newDMGTemporaryDirectory()
	if err != nil {
		s.markNodePartial(parentID, "DMG system extraction failed; contents not inspected")
		s.addDiagnostic(fmt.Sprintf("%s: DMG system extraction tempdir failed: %v", logical, err))
		return
	}
	imagePath := filepath.Join(tmp, "image.dmg")
	safeToRemoveTemporary := true
	defer func() {
		s.cleanupDMGTemporary(logical, tmp, imagePath, safeToRemoveTemporary)
	}()
	if err := os.WriteFile(imagePath, data, 0o600); err != nil {
		s.markNodePartial(parentID, "DMG system extraction failed; contents not inspected")
		s.addDiagnostic(fmt.Sprintf("%s: DMG system extraction temp image failed: %v", logical, err))
		return
	}
	mountRoot := filepath.Join(tmp, "mount")
	if err := os.Mkdir(mountRoot, 0o700); err != nil {
		s.markNodePartial(parentID, "DMG system extraction failed; contents not inspected")
		s.addDiagnostic(fmt.Sprintf("%s: DMG system extraction mount root failed: %v", logical, err))
		return
	}
	transientRootCount := len(s.transientRoots)
	s.transientRoots = append(s.transientRoots, mountRoot)
	defer func() {
		s.transientRoots = s.transientRoots[:transientRootCount]
	}()
	var attachments []dmgAttachment
	defer func() {
		targets, discoveryErr := dmgCleanupTargets(attachments, mountRoot)
		if discoveryErr != nil {
			s.addDiagnostic(fmt.Sprintf("%s: DMG cleanup mount discovery failed: %v", logical, discoveryErr))
		}
		if len(targets) > 0 {
			s.detachDMGMounts(logical, targets)
		}
		clear, verificationErr := dmgMountRootSafeToRemove(mountRoot)
		if verificationErr != nil {
			safeToRemoveTemporary = false
			s.addDiagnostic(fmt.Sprintf("%s: DMG cleanup mount-state verification failed: %v", logical, verificationErr))
		} else if !clear {
			safeToRemoveTemporary = false
			s.addDiagnostic(fmt.Sprintf("%s: DMG cleanup could not confirm every private mount was detached", logical))
		}
	}()
	stdout, stderr, attachErr := hdiutil(dmgAttachTimeout, dmgAttachArguments(imagePath, mountRoot)...)
	parsedAttachments, parseErr := dmgAttachments(stdout)
	// Retain bounded partial results for deferred cleanup even when the plist
	// reports more attachments than Maratus will inspect.
	attachments = parsedAttachments
	if attachErr != nil {
		s.markNodePartial(parentID, "DMG system attach failed; contents not inspected")
		s.addDiagnostic(fmt.Sprintf("%s: DMG system attach failed: %s", logical, commandError(attachErr, hdiutilDiagnosticOutput(stdout, stderr))))
		return
	}
	if parseErr != nil {
		s.markNodePartial(parentID, "DMG system attach output was incomplete; contents not inspected")
		s.addDiagnostic(fmt.Sprintf("%s: DMG system attach output parse failed: %v", logical, parseErr))
		return
	}
	mounts, rejectedMounts := dmgMountPointsWithinRoot(attachments, mountRoot)
	for _, mount := range rejectedMounts {
		s.markNodePartial(parentID, "one or more DMG mount points were rejected; contents partially inspected")
		s.addDiagnostic(fmt.Sprintf("%s: DMG mount outside private mount root rejected: %s", logical, mount))
	}
	if len(mounts) == 0 {
		s.markNodePartial(parentID, "DMG attach produced no usable mount points; contents not inspected")
		s.addDiagnostic(fmt.Sprintf("%s: DMG system attach produced no usable mount points", logical))
		return
	}
	for _, mount := range mounts {
		info, err := os.Lstat(mount)
		if err != nil {
			s.markNodePartial(parentID, "one or more DMG volumes could not be inspected")
			s.addDiagnostic(fmt.Sprintf("%s: DMG mount stat failed: %v", logical, err))
			continue
		}
		if !info.IsDir() {
			s.markNodePartial(parentID, "one or more DMG volumes could not be inspected")
			s.addDiagnostic(fmt.Sprintf("%s: DMG mount is not a directory: %s", logical, mount))
			continue
		}
		volumeLogical := filepath.ToSlash(logical + "!" + filepath.Base(mount))
		volumeID := s.addDirectory(mount, volumeLogical, parentID, "dmg-volume")
		if volumeID == "" {
			s.markNodePartial(parentID, "one or more DMG volumes exceeded inspection limits")
			continue
		}
		s.scanDirectory(mount, volumeLogical, volumeID, depth, info)
	}
}

func newDMGTemporaryDirectory() (string, error) {
	parent := strings.TrimSpace(os.Getenv(DMGTemporaryDirectoryEnvironment))
	if parent == "" {
		return os.MkdirTemp("", "maratus-dmg-*")
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("DMG temporary parent is not a directory")
	}
	return os.MkdirTemp(parent, "maratus-dmg-*")
}

func (s *scanner) cleanupDMGTemporary(logical, temporaryRoot, imagePath string, safeToRemove bool) {
	if safeToRemove {
		if err := os.RemoveAll(temporaryRoot); err != nil {
			s.addDiagnostic(fmt.Sprintf("%s: DMG temporary-directory cleanup failed: %v", logical, err))
		}
		return
	}
	// Never recursively traverse a mount whose detach state is uncertain. The
	// retained image is a known regular sibling of the mount root and can be
	// removed directly; preserve the private 0700 directory for manual/OS
	// cleanup and report its exact location.
	if err := os.Remove(imagePath); err != nil && !os.IsNotExist(err) {
		s.addDiagnostic(fmt.Sprintf("%s: DMG temporary-image cleanup failed: %v", logical, err))
	}
	s.addDiagnostic(fmt.Sprintf("%s: private DMG temporary directory retained at %s because detach could not be confirmed; unmount it before removal", logical, temporaryRoot))
}

func dmgMountRootSafeToRemove(mountRoot string) (bool, error) {
	rootInfo, err := os.Lstat(mountRoot)
	if err != nil {
		return false, err
	}
	parentInfo, err := os.Lstat(filepath.Dir(mountRoot))
	if err != nil {
		return false, err
	}
	same, supported := sameFilesystemDevice(rootInfo, parentInfo)
	if !supported {
		return false, fmt.Errorf("filesystem mount identity is unavailable")
	}
	if !same {
		return false, nil
	}
	entries, limited, err := readDirectoryEntries(mountRoot, maxDMGMountDirectories)
	if err != nil {
		return false, err
	}
	if limited {
		return false, fmt.Errorf("DMG mount directory limit %d reached during cleanup verification", maxDMGMountDirectories)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := os.Lstat(filepath.Join(mountRoot, entry.Name()))
		if err != nil {
			return false, err
		}
		same, supported := sameFilesystemDevice(rootInfo, info)
		if !supported {
			return false, fmt.Errorf("filesystem mount identity is unavailable")
		}
		if !same {
			return false, nil
		}
	}
	return true, nil
}

func dmgAttachArguments(imagePath, mountRoot string) []string {
	return []string{
		"attach", imagePath,
		"-readonly",
		"-nobrowse",
		"-noautoopen",
		"-mountroot", mountRoot,
		"-plist",
	}
}

func (s *scanner) detachDMGMounts(logical string, targets []string) {
	if len(targets) > maxDMGCleanupTargets {
		s.addDiagnostic(fmt.Sprintf("%s: DMG cleanup target limit %d reached", logical, maxDMGCleanupTargets))
		targets = targets[:maxDMGCleanupTargets]
	}
	deadline := time.Now().Add(dmgDetachTotalTimeout)
	for i := len(targets) - 1; i >= 0; i-- {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			s.addDiagnostic(fmt.Sprintf("%s: DMG cleanup total timeout reached; %d detach targets omitted", logical, i+1))
			return
		}
		timeout := min(dmgDetachTimeout, remaining)
		stdout, stderr, err := hdiutil(timeout, "detach", targets[i], "-force")
		if err != nil {
			s.addDiagnostic(fmt.Sprintf("%s: DMG detach failed for %s: %s", logical, targets[i], commandError(err, hdiutilDiagnosticOutput(stdout, stderr))))
		}
	}
}

func hdiutil(timeout time.Duration, args ...string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, hdiutilPath, args...)
	cmd.Env = withoutEnvironmentVariable(os.Environ(), zipPasswordEnvironmentName)
	stdoutCapture := &boundedCommandOutput{maxBytes: maxHdiutilOutputBytes}
	stderrCapture := &boundedCommandOutput{maxBytes: maxHdiutilStderrBytes}
	cmd.Stdout = stdoutCapture
	cmd.Stderr = stderrCapture
	err := cmd.Run()
	stdout, stdoutExceeded := stdoutCapture.bytes()
	stderr, stderrExceeded := stderrCapture.bytes()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if stdoutExceeded {
		err = errors.Join(err, fmt.Errorf("hdiutil stdout exceeded %d bytes", maxHdiutilOutputBytes))
	}
	if stderrExceeded {
		err = errors.Join(err, fmt.Errorf("hdiutil stderr exceeded %d bytes", maxHdiutilStderrBytes))
	}
	return stdout, stderr, err
}

func hdiutilDiagnosticOutput(stdout, stderr []byte) []byte {
	if len(bytes.TrimSpace(stderr)) > 0 {
		return stderr
	}
	return stdout
}

type boundedCommandOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	maxBytes int
	exceeded bool
}

func (w *boundedCommandOutput) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	written := len(data)
	remaining := w.maxBytes - w.buffer.Len()
	if remaining < len(data) {
		w.exceeded = true
	}
	if remaining > 0 {
		if remaining < len(data) {
			data = data[:remaining]
		}
		_, _ = w.buffer.Write(data)
	}
	return written, nil
}

func (w *boundedCommandOutput) bytes() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.Bytes(), w.exceeded
}

func withoutEnvironmentVariable(environment []string, name string) []string {
	prefix := name + "="
	filtered := make([]string, 0, len(environment))
	for _, item := range environment {
		if item == name || strings.HasPrefix(item, prefix) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

type dmgAttachment struct {
	MountPoint string
	Device     string
}

func dmgAttachments(output []byte) ([]dmgAttachment, error) {
	if len(output) > maxHdiutilOutputBytes {
		return nil, fmt.Errorf("hdiutil plist exceeds %d bytes", maxHdiutilOutputBytes)
	}
	dict, err := plistx.Decode(output)
	if err != nil {
		return nil, err
	}
	var attachments []dmgAttachment
	seen := map[string]bool{}
	limited := false
	for _, entity := range plistx.Dicts(dict, "system-entities") {
		item := dmgAttachment{
			MountPoint: plistx.String(entity, "mount-point"),
			Device:     plistx.String(entity, "dev-entry"),
		}
		key := item.MountPoint + "\x00" + item.Device
		if (item.MountPoint != "" || item.Device != "") && !seen[key] {
			seen[key] = true
			if len(attachments) < maxDMGAttachments {
				attachments = append(attachments, item)
			} else {
				limited = true
			}
		}
	}
	sort.Slice(attachments, func(i, j int) bool {
		if attachments[i].MountPoint != attachments[j].MountPoint {
			return attachments[i].MountPoint < attachments[j].MountPoint
		}
		return attachments[i].Device < attachments[j].Device
	})
	if limited {
		return attachments, fmt.Errorf("hdiutil attachment limit %d reached", maxDMGAttachments)
	}
	return attachments, nil
}

func dmgMountPoints(attachments []dmgAttachment) []string {
	var mounts []string
	for _, item := range attachments {
		if item.MountPoint != "" {
			mounts = append(mounts, item.MountPoint)
		}
	}
	sort.Strings(mounts)
	return mounts
}

func dmgMountPointsWithinRoot(attachments []dmgAttachment, mountRoot string) (valid, rejected []string) {
	seenValid := map[string]bool{}
	seenRejected := map[string]bool{}
	for _, mount := range dmgMountPoints(attachments) {
		mount = filepath.Clean(mount)
		if dmgMountWithinRoot(mountRoot, mount) {
			if !seenValid[mount] {
				seenValid[mount] = true
				valid = append(valid, mount)
			}
			continue
		}
		if !seenRejected[mount] {
			seenRejected[mount] = true
			rejected = append(rejected, mount)
		}
	}
	sort.Strings(valid)
	sort.Strings(rejected)
	return valid, rejected
}

func dmgMountWithinRoot(mountRoot, mount string) bool {
	resolvedRoot, rootErr := filepath.EvalSymlinks(mountRoot)
	resolvedMount, mountErr := filepath.EvalSymlinks(mount)
	if rootErr == nil && mountErr == nil {
		return pathWithin(resolvedRoot, resolvedMount)
	}
	// Cleanup may need to reason about a mount path that disappeared between
	// attach and detach. Lexical containment is the only safe fallback when a
	// path cannot be resolved; existing paths are decided solely by their
	// resolved locations above.
	return pathWithin(mountRoot, mount)
}

func dmgCleanupTargets(attachments []dmgAttachment, mountRoot string) ([]string, error) {
	targetSet := map[string]bool{}
	for _, item := range attachments {
		mount := filepath.Clean(item.MountPoint)
		if item.MountPoint != "" && dmgMountWithinRoot(mountRoot, mount) {
			targetSet[mount] = true
			continue
		}
		if item.Device != "" {
			targetSet[item.Device] = true
		}
	}
	discovered, err := dmgMountDirectories(mountRoot)
	for _, mount := range discovered {
		targetSet[mount] = true
	}
	targets := make([]string, 0, len(targetSet))
	for target := range targetSet {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	if len(targets) > maxDMGCleanupTargets {
		targets = targets[:maxDMGCleanupTargets]
		err = errors.Join(err, fmt.Errorf("DMG cleanup target limit %d reached", maxDMGCleanupTargets))
	}
	return targets, err
}

func dmgMountDirectories(mountRoot string) ([]string, error) {
	entries, limited, err := readDirectoryEntries(mountRoot, maxDMGMountDirectories)
	if err != nil {
		return nil, err
	}
	var mounts []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		mount := filepath.Join(mountRoot, entry.Name())
		if pathWithin(mountRoot, mount) {
			mounts = append(mounts, mount)
		}
	}
	sort.Strings(mounts)
	if limited {
		return mounts, fmt.Errorf("DMG mount directory limit %d reached", maxDMGMountDirectories)
	}
	return mounts, nil
}

func dmgDetachTargets(attachments []dmgAttachment) []string {
	mounts := dmgMountPoints(attachments)
	if len(mounts) > 0 {
		return mounts
	}
	return dmgDeviceTargets(attachments)
}

func dmgDeviceTargets(attachments []dmgAttachment) []string {
	seen := map[string]bool{}
	var devices []string
	for _, item := range attachments {
		if item.Device != "" && !seen[item.Device] {
			seen[item.Device] = true
			devices = append(devices, item.Device)
		}
	}
	sort.Strings(devices)
	return devices
}

func commandError(err error, output []byte) string {
	text := strings.TrimSpace(string(output))
	if len(text) > 512 {
		text = text[:512] + "..."
	}
	if errors.Is(err, context.DeadlineExceeded) {
		if text == "" {
			return "timed out"
		}
		return "timed out: " + text
	}
	if text == "" {
		return err.Error()
	}
	return err.Error() + ": " + text
}
