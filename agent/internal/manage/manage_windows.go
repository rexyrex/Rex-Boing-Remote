//go:build windows

package manage

// Windows install, upgrade, uninstall and pairing code.
//
// The agent lives in %LOCALAPPDATA%\RexBoingRemote\rex-boing-agent.exe.
// OpenSSH for Windows reads an administrator's keys from
// %ProgramData%\ssh\administrators_authorized_keys (sshd_config "Match Group
// administrators") and everyone else's from %USERPROFILE%\.ssh\authorized_keys.
// A running .exe cannot be deleted or overwritten, but it can be renamed,
// which is how upgrade and uninstall replace or remove the running agent.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

const (
	winExeName      = "rex-boing-agent.exe"
	winNewName      = "rex-boing-agent.new.exe"
	winOldName      = "rex-boing-agent.old.exe"
	winInstallTmp   = "rex-boing-agent.install.tmp"
	winMaxAgentSize = 512 << 20
)

func executableName() string { return winExeName }

func installDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		if p, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0); err == nil {
			base = p
		}
	}
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, "AppData", "Local")
		}
	}
	return filepath.Join(base, "RexBoingRemote")
}

func winProgramData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0); err == nil {
		return p
	}
	return `C:\ProgramData`
}

func winSSHDir() string        { return filepath.Join(winProgramData(), "ssh") }
func winAdminKeysFile() string { return filepath.Join(winSSHDir(), "administrators_authorized_keys") }

func winUserKeysFile() (string, error) {
	home, err := os.UserHomeDir() // %USERPROFILE%
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "authorized_keys"), nil
}

func winFail(code, msg string) wire.Result { return wire.Result{OK: false, Error: code, Message: msg} }

// winIsAdministrator reports whether the user belongs to BUILTIN\
// Administrators, which is what decides the key file sshd reads, and
// whether this process is elevated. CheckTokenMembership (Token(0).IsMember)
// only sees an enabled group, so in a non-elevated UAC session, where the
// group is present but deny-only, the token's group list is checked too.
func winIsAdministrator() (member, elevated bool) {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, false
	}
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false, false
	}
	defer tok.Close()
	elevated = tok.IsElevated()
	if ok, err := windows.Token(0).IsMember(sid); err == nil && ok {
		return true, elevated
	}
	if groups, err := tok.GetTokenGroups(); err == nil {
		for _, g := range groups.AllGroups() {
			if g.Sid != nil && g.Sid.Equals(sid) {
				return true, elevated
			}
		}
	}
	return false, elevated
}

// winDefaultShell is OpenSSH's DefaultShell (HKLM\SOFTWARE\OpenSSH), or ""
// for the built-in default, cmd.exe.
func winDefaultShell() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\OpenSSH`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	s, _, err := k.GetStringValue("DefaultShell")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

func winExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// winRetry repeats f for about two seconds while it fails with a sharing
// or access error: antivirus scanners briefly lock freshly written
// executables. Other errors return at once.
func winRetry(f func() error) error {
	var err error
	for i := 0; i < 20; i++ {
		if err = f(); err == nil || !winIsAccessDenied(err) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

func winSamePath(a, b string) bool {
	if strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) {
		return true
	}
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

// winFreeOldName returns a name to move the current executable aside to.
// An older .old.exe may still be running (a session that has not ended
// since the last upgrade), so it falls back to a unique name; CleanupOld
// removes all of them later.
func winFreeOldName(dir string) string {
	old := filepath.Join(dir, winOldName)
	if err := os.Remove(old); err == nil || os.IsNotExist(err) {
		return old
	}
	return filepath.Join(dir, fmt.Sprintf("rex-boing-agent.%d.old.exe", time.Now().UnixNano()))
}

// winInstallExecutable copies the running executable into the install
// directory unless it already runs from there.
func winInstallExecutable() (string, bool, error) {
	src, err := os.Executable()
	if err != nil {
		return "", false, err
	}
	if p, err := filepath.EvalSymlinks(src); err == nil {
		src = p
	}
	dir := installDir()
	dst := filepath.Join(dir, winExeName)
	if winSamePath(src, dst) {
		return dst, false, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", false, err
	}
	tmp := filepath.Join(dir, winInstallTmp)
	if err := winCopyFile(src, tmp); err != nil {
		os.Remove(tmp)
		return "", false, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		// The installed copy is running (an open session), which blocks
		// overwriting it but not renaming it: move it aside.
		old := winFreeOldName(dir)
		if err2 := os.Rename(dst, old); err2 != nil {
			os.Remove(tmp)
			return "", false, fmt.Errorf("replace %s: %v", dst, err)
		}
		if err := winRetry(func() error { return os.Rename(tmp, dst) }); err != nil {
			os.Rename(old, dst)
			os.Remove(tmp)
			return "", false, err
		}
	}
	return dst, true, nil
}

func winCopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// winRestrictAdminKeyFile gives administrators_authorized_keys the ACL
// sshd requires: no inheritance, full control for Administrators and
// SYSTEM only. SIDs keep it working on localized Windows.
func winRestrictAdminKeyFile(path string) error {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		sys = `C:\Windows\System32`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(sys, "icacls.exe"), path,
		"/inheritance:r", "/grant", "*S-1-5-32-544:F", "/grant", "*S-1-5-18:F").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// winWriteKeyFile adds or replaces the key line in path. An existing file is
// rewritten in place, which keeps its owner and ACL (a temp-and-rename
// would replace them with the folder's inherited ones). A new admin key
// file gets the restricted ACL right after it is created.
func winWriteKeyFile(path, line, blob string, adminFile bool) (created, replaced bool, err error) {
	data, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return false, false, err
	}
	text, _ := winDecodeKeyFile(data)
	out, replaced := winUpsertKey(text, line, blob)
	if exists {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return false, false, err
		}
		if _, err := f.Write([]byte(out)); err != nil {
			f.Close()
			return false, false, err
		}
		return false, replaced, f.Close()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, false, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false, false, err
	}
	if _, err := f.Write([]byte(out)); err != nil {
		f.Close()
		return true, false, err
	}
	if err := f.Close(); err != nil {
		return true, false, err
	}
	if adminFile {
		if err := winRestrictAdminKeyFile(path); err != nil {
			return true, false, err
		}
	}
	return true, false, nil
}

func winIsAccessDenied(err error) bool {
	return os.IsPermission(err) || errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

func install(o InstallOptions) wire.Result {
	key, err := winParseKey(o.Key)
	if err != nil {
		return winFail("bad-key", err.Error())
	}
	label := o.Label
	if strings.TrimSpace(label) == "" {
		label = key.Comment
	}
	exe, copied, err := winInstallExecutable()
	if err != nil {
		return winFail("install-failed", "Could not copy the agent to "+installDir()+": "+err.Error())
	}
	shell := winDefaultShell()
	command := winForcedCommand(shell, exe)
	line := winKeyLine(command, key, label)
	member, elevated := winIsAdministrator()
	useAdminFile := member
	if member {
		if b, err := os.ReadFile(filepath.Join(winSSHDir(), "sshd_config")); err == nil {
			text, _ := winDecodeKeyFile(b)
			useAdminFile = winAdminKeyFileInUse(text) // a customised config may send admins to their own file
		}
	}

	var keyFile string
	var created, replaced bool
	if useAdminFile {
		keyFile = winAdminKeysFile()
		if !winExists(winSSHDir()) {
			return winFail("sshd-missing", "OpenSSH Server has not been set up on this PC yet ("+winSSHDir()+" does not exist). "+
				"Install it (Settings → System → Optional features → OpenSSH Server), start it once with Start-Service sshd, then run install again.")
		}
		created, replaced, err = winWriteKeyFile(keyFile, line, key.Blob, true)
		if err != nil {
			if winIsAccessDenied(err) || !elevated {
				return winFail("admin-key-file", "This account is an administrator, so OpenSSH reads its keys from "+keyFile+
					", which only an elevated process can change. Run the installer again in PowerShell opened with \"Run as administrator\".")
			}
			return winFail("install-failed", "Could not update "+keyFile+": "+err.Error())
		}
	} else {
		keyFile, err = winUserKeysFile()
		if err != nil {
			return winFail("no-home", "Could not find the user profile: "+err.Error())
		}
		created, replaced, err = winWriteKeyFile(keyFile, line, key.Blob, false)
		if err != nil {
			return winFail("install-failed", "Could not update "+keyFile+": "+err.Error())
		}
	}

	msg := "Installed. The key " + KeyCommentPrefix + winSanitizeLabel(label) + " can now run the agent, and nothing else."
	if replaced {
		msg = "Updated. The key " + KeyCommentPrefix + winSanitizeLabel(label) + " can now run the agent, and nothing else."
	}
	if copied {
		msg += " The agent was copied to " + exe + "."
	}
	shellName := "cmd"
	if winShellKind(shell) == "powershell" {
		shellName = "powershell"
	}
	details := map[string]string{
		"agentPath": exe,
		"keyFile":   keyFile,
		"shell":     shellName,
		"command":   command,
	}
	if created {
		details["keyFileCreated"] = "true"
	}
	if copied {
		details["agentCopied"] = "true"
	}
	return wire.Result{OK: true, Message: msg, Details: details}
}

// winRemoveKeysFrom drops this agent's lines from one key file.
func winRemoveKeysFrom(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	text, _ := winDecodeKeyFile(data)
	out, removed := winRemoveOurKeys(text)
	if removed == 0 {
		return 0, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return 0, err
	}
	if _, err := f.Write([]byte(out)); err != nil {
		f.Close()
		return 0, err
	}
	return removed, f.Close()
}

// winDeleteAtReboot asks Windows to delete path at the next restart. Only
// administrators may; for others it quietly does nothing.
func winDeleteAtReboot(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	return windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT) == nil
}

func winInside(path, dir string) bool {
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// winRemoveInstallDir deletes the install directory. The running agent is
// usually inside it; it is first moved to %TEMP% (a rename works on a
// running .exe), where CleanupOld or a restart removes it.
func winRemoveInstallDir() (string, error) {
	dir := installDir()
	if !winExists(dir) {
		return "There was no " + dir + " to remove.", nil
	}
	note := ""
	self, err := os.Executable()
	if err == nil && winInside(self, dir) {
		moved := filepath.Join(os.TempDir(), fmt.Sprintf("rex-boing-agent-%d.old.exe", os.Getpid()))
		if err := os.Rename(self, moved); err == nil {
			when := "the next time the agent runs"
			if winDeleteAtReboot(moved) {
				when = "when Windows restarts"
			}
			note = " The running agent moved itself to " + moved + " and is deleted " + when + "."
		} else {
			// %TEMP% on another volume: remove the rest, schedule the remainder.
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				if p := filepath.Join(dir, e.Name()); !winSamePath(p, self) {
					os.RemoveAll(p)
				}
			}
			if winDeleteAtReboot(self) && winDeleteAtReboot(dir) {
				return "Removed the agent's files; " + self + " is still running and is deleted when Windows restarts.", nil
			}
			return "Removed the agent's files except " + self + ", which is still running; delete " + dir + " by hand once this session has ended.", nil
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	return "Removed " + dir + "." + note, nil
}

func uninstall() wire.Result {
	member, _ := winIsAdministrator()
	details := map[string]string{}
	var problems []string
	total := 0

	if f, err := winUserKeysFile(); err == nil {
		n, err := winRemoveKeysFrom(f)
		switch {
		case err != nil && !os.IsNotExist(err):
			problems = append(problems, f+": "+err.Error())
		case n > 0:
			details["userKeyFile"] = f
		}
		total += n
	}
	adminFile := winAdminKeysFile()
	n, err := winRemoveKeysFrom(adminFile)
	switch {
	case err != nil && os.IsNotExist(err):
	case err != nil && winIsAccessDenied(err) && !member:
		// Not an administrator: install never wrote there, and it cannot be read.
	case err != nil && winIsAccessDenied(err):
		problems = append(problems, adminFile+" can only be changed from an elevated PowerShell (Run as administrator)")
	case err != nil:
		problems = append(problems, adminFile+": "+err.Error())
	case n > 0:
		details["adminKeyFile"] = adminFile
	}
	total += n

	dirMsg, err := winRemoveInstallDir()
	if err != nil {
		problems = append(problems, "could not remove "+installDir()+": "+err.Error())
	}
	details["removedKeys"] = fmt.Sprint(total)
	msg := fmt.Sprintf("Removed %d key line(s). %s", total, dirMsg)
	if len(problems) > 0 {
		r := winFail("uninstall-failed", strings.TrimSpace(msg+" Not done: "+strings.Join(problems, "; ")+"."))
		r.Details = details
		return r
	}
	return wire.Result{OK: true, Message: strings.TrimSpace(msg), Details: details}
}

func upgrade(r io.Reader, sha256Hex string, size int64) wire.Result {
	if !winValidSHA256(sha256Hex) {
		return winFail("usage", "--sha256 must be 64 hexadecimal characters.")
	}
	if size <= 0 || size > winMaxAgentSize {
		return winFail("usage", fmt.Sprintf("--size must be between 1 and %d bytes.", winMaxAgentSize))
	}
	dir := installDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return winFail("upgrade-failed", err.Error())
	}
	newPath := filepath.Join(dir, winNewName)
	f, err := os.OpenFile(newPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return winFail("upgrade-failed", "Could not create "+newPath+": "+err.Error())
	}
	h := sha256.New()
	n, err := io.CopyN(io.MultiWriter(f, h), r, size)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil || n != size {
		os.Remove(newPath)
		return winFail("short-read", fmt.Sprintf("Received %d of %d bytes: %v", n, size, err))
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, sha256Hex) {
		os.Remove(newPath)
		return winFail("hash-mismatch", "The upload's SHA-256 is "+got+", not the expected "+strings.ToLower(sha256Hex)+".")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var out []byte
	err = winRetry(func() error { // a virus scanner may hold the new file for a moment
		var e error
		out, e = exec.CommandContext(ctx, newPath, "version").Output()
		return e
	})
	info, verr := winCheckVersionOutput(out)
	if err != nil || verr != nil {
		os.Remove(newPath)
		reason := verr
		if reason == nil {
			reason = err
		}
		return winFail("verify-failed", "The new agent did not pass its self-check: "+reason.Error())
	}

	target := filepath.Join(dir, winExeName)
	hadTarget := winExists(target)
	old := ""
	if hadTarget {
		old = winFreeOldName(dir)
		if err := winRetry(func() error { return os.Rename(target, old) }); err != nil {
			os.Remove(newPath)
			return winFail("upgrade-failed", "Could not move "+target+" aside: "+err.Error())
		}
	}
	if err := winRetry(func() error { return os.Rename(newPath, target) }); err != nil {
		if hadTarget {
			os.Rename(old, target)
		}
		os.Remove(newPath)
		return winFail("upgrade-failed", "Could not put the new agent in place: "+err.Error())
	}
	return wire.Result{OK: true, Message: "Upgraded to " + info.Version + ".", Details: map[string]string{
		"version":   info.Version,
		"agentPath": target,
	}}
}

// CleanupOld deletes executables left behind by earlier upgrades and
// uninstalls. The agent calls it at the start of every run; files still in
// use by an older, still-running session are skipped and retried next time.
func CleanupOld() {
	clean := func(dir string, match func(name string) bool) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() && match(strings.ToLower(e.Name())) {
				os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	clean(installDir(), func(n string) bool {
		return strings.HasPrefix(n, "rex-boing-agent") && strings.HasSuffix(n, ".old.exe")
	})
	clean(os.TempDir(), func(n string) bool {
		return strings.HasPrefix(n, "rex-boing-agent-") && strings.HasSuffix(n, ".old.exe")
	})
}

// winPairAddresses lists the IPv4 addresses of the adapters that are up,
// best first (orderPairAddresses in paircode.go). Hyper-V's internal
// switches (WSL, Default Switch) and host-only adapters of VirtualBox and
// VMware are unreachable from a Mac; they are recognised by name and by
// having no default gateway, so an external Hyper-V switch (which carries
// the PC's real LAN address and a gateway) is kept.
func winPairAddresses() []net.IP {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(15000)
	var buf []byte
	for attempt := 0; ; attempt++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			if size == 0 {
				return nil
			}
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || size <= uint32(len(buf)) || attempt > 4 {
			return nil
		}
	}
	var out []net.IP
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp || aa.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		name := windows.UTF16PtrToString(aa.FriendlyName) + " " + windows.UTF16PtrToString(aa.Description)
		if aa.FirstGatewayAddress == nil && winVirtualAdapter(name) {
			continue
		}
		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			if ip := ua.Address.IP().To4(); ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				out = append(out, ip)
			}
		}
	}
	return out
}

func pairCode() (string, error) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = os.Getenv("COMPUTERNAME")
	}
	user := winSSHUser(os.Getenv("USERNAME"), os.Getenv("USERDOMAIN"), os.Getenv("COMPUTERNAME"))
	if user == "" {
		return "", errors.New("cannot tell the user name (USERNAME is not set)")
	}
	addrs := orderPairAddresses(winPairAddresses())
	if host != "" {
		addrs = append(addrs, strings.ToLower(host)+".local")
	}
	return encodePairCode(wire.PairCode{
		V:         1,
		Name:      host,
		User:      user,
		Port:      sshdPort(filepath.Join(winSSHDir(), "sshd_config")),
		OS:        "windows",
		Addresses: addrs,
		HostKeys:  readHostKeys(winSSHDir()),
	})
}
