package manage

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// testBlob builds a syntactically valid key blob for typ.
func testBlob(typ string, seed byte) string {
	b := make([]byte, 4+len(typ)+36)
	binary.BigEndian.PutUint32(b, uint32(len(typ)))
	copy(b[4:], typ)
	binary.BigEndian.PutUint32(b[4+len(typ):], 32)
	for i := 8 + len(typ); i < len(b); i++ {
		b[i] = seed
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestWinParseKey(t *testing.T) {
	blob := testBlob("ssh-ed25519", 1)
	k, err := winParseKey("  ssh-ed25519 " + blob + " alex@Alexs-MacBook \n")
	if err != nil || k.Type != "ssh-ed25519" || k.Blob != blob || k.Comment != "alex@Alexs-MacBook" {
		t.Fatalf("k=%+v err=%v", k, err)
	}
	bad := []string{
		"",
		"ssh-ed25519",
		"ssh-dss " + testBlob("ssh-dss", 1),
		"sk-ssh-ed25519@openssh.com " + testBlob("sk-ssh-ed25519@openssh.com", 1),
		"ssh-ed25519 !!!notbase64",
		"ssh-rsa " + blob, // blob says ed25519
		"ssh-ed25519 " + blob + " a\nssh-ed25519 " + blob,
		`command="x" ssh-ed25519 ` + blob,
	}
	for _, b := range bad {
		if _, err := winParseKey(b); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

func TestWinSanitizeLabel(t *testing.T) {
	cases := map[string]string{
		"Alex's MacBook Pro":      "Alex-s-MacBook-Pro",
		"rex-boing-remote:Studio": "Studio",
		"  ":                      "mac",
		"a\"b`c$d":                "a-b-c-d",
		strings.Repeat("x", 100):  strings.Repeat("x", 64),
		"alex@mac.local":          "alex-mac.local",
		"--Studio--.":             "Studio",
	}
	for in, want := range cases {
		if got := winSanitizeLabel(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestWinForcedCommandAndLine(t *testing.T) {
	exe := `C:\Users\O'Brien\AppData\Local\RexBoingRemote\rex-boing-agent.exe`
	if got := winForcedCommand(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, exe); got != `& 'C:\Users\O''Brien\AppData\Local\RexBoingRemote\rex-boing-agent.exe' ssh` {
		t.Errorf("powershell: %s", got)
	}
	if got := winForcedCommand(`"C:\Program Files\PowerShell\7\pwsh.exe"`, exe); !strings.HasPrefix(got, "& '") {
		t.Errorf("pwsh: %s", got)
	}
	cmd := winForcedCommand("", `C:\Users\alex\AppData\Local\RexBoingRemote\rex-boing-agent.exe`)
	if cmd != `"C:\Users\alex\AppData\Local\RexBoingRemote\rex-boing-agent.exe" ssh` {
		t.Errorf("cmd: %s", cmd)
	}
	if winShellKind(`C:\Windows\System32\cmd.exe`) != "cmd" {
		t.Error("cmd kind")
	}
	k := winParsedKey{Type: "ssh-ed25519", Blob: testBlob("ssh-ed25519", 2)}
	line := winKeyLine(cmd, k, "Alexs-MacBook")
	want := `restrict,command="\"C:\Users\alex\AppData\Local\RexBoingRemote\rex-boing-agent.exe\" ssh" ssh-ed25519 ` + k.Blob + " rex-boing-remote:Alexs-MacBook"
	if line != want {
		t.Errorf("line:\n%s\nwant:\n%s", line, want)
	}
	opts, typ, blob, comment, ok := winLineFields(line)
	if !ok || !strings.HasPrefix(opts, "restrict,") || typ != "ssh-ed25519" || blob != k.Blob || comment != "rex-boing-remote:Alexs-MacBook" {
		t.Errorf("fields: %q %q %q %q %v", opts, typ, blob, comment, ok)
	}
	if !winIsOurLine(line) || winIsOurLine("ssh-ed25519 "+k.Blob+" alex@laptop") || winIsOurLine("# rex-boing-remote: comment") {
		t.Error("ownership detection")
	}
	// A quoted option containing spaces and a fake comment marker.
	tricky := `command="echo rex-boing-remote:x y" ssh-rsa AAAA user@host`
	if _, typ, _, c, ok := winLineFields(tricky); !ok || typ != "ssh-rsa" || c != "user@host" {
		t.Errorf("tricky: %q %q", typ, c)
	}
}

func TestWinUpsertAndRemove(t *testing.T) {
	blobA := testBlob("ssh-ed25519", 3)
	blobB := testBlob("ssh-ed25519", 4)
	foreign := "ssh-rsa " + testBlob("ssh-rsa", 5) + " me@desktop"
	ours := `restrict,command="x" ssh-ed25519 ` + blobA + " rex-boing-remote:Old"
	content := "# my keys\r\n" + foreign + "\r\n" + ours + "\r\n" + ours + "\r\n"
	newLine := `restrict,command="y" ssh-ed25519 ` + blobA + " rex-boing-remote:New"
	out, replaced := winUpsertKey(content, newLine, blobA)
	want := "# my keys\r\n" + foreign + "\r\n" + newLine + "\r\n"
	if !replaced || out != want {
		t.Errorf("upsert replaced=%v:\n%q\nwant\n%q", replaced, out, want)
	}
	// Appending to an LF file without a trailing newline.
	out, replaced = winUpsertKey(foreign, newLine, blobB)
	if replaced || out != foreign+"\n"+newLine+"\n" {
		t.Errorf("append: %q", out)
	}
	if out, _ := winUpsertKey("", newLine, blobA); out != newLine+"\n" {
		t.Errorf("empty file: %q", out)
	}
	out, removed := winRemoveOurKeys(content)
	if removed != 2 || out != "# my keys\r\n"+foreign+"\r\n" {
		t.Errorf("remove %d: %q", removed, out)
	}
	if out, removed := winRemoveOurKeys(foreign); removed != 0 || out != foreign {
		t.Error("remove must leave foreign-only files byte for byte")
	}
}

func TestWinDecodeKeyFile(t *testing.T) {
	if s, changed := winDecodeKeyFile([]byte("abc\n")); s != "abc\n" || changed {
		t.Error("plain")
	}
	if s, changed := winDecodeKeyFile([]byte("\xEF\xBB\xBFabc")); s != "abc" || !changed {
		t.Error("utf-8 bom")
	}
	le := []byte{0xFF, 0xFE, 'h', 0, 'i', 0, '\r', 0, '\n', 0}
	if s, changed := winDecodeKeyFile(le); s != "hi\r\n" || !changed {
		t.Errorf("utf-16le: %q", s)
	}
	be := []byte{0xFE, 0xFF, 0, 'o', 0, 'k'}
	if s, _ := winDecodeKeyFile(be); s != "ok" {
		t.Errorf("utf-16be: %q", s)
	}
}

func TestWinAdminKeyFileInUse(t *testing.T) {
	stock := "Match Group administrators\r\n       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\r\n"
	if !winAdminKeyFileInUse(stock) || !winAdminKeyFileInUse("") {
		t.Error("stock config must use the admin file")
	}
	if winAdminKeyFileInUse("#Match Group administrators\n#  AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\nPort 22\n") {
		t.Error("commented-out block must not count")
	}
}

func TestWinMisc(t *testing.T) {
	if winSSHUser("alex", "DESKTOP-1", "DESKTOP-1") != "alex" || winSSHUser("alex", "CONTOSO", "PC1") != `CONTOSO\alex` {
		t.Error("ssh user")
	}
	if _, err := winCheckVersionOutput([]byte(`{"name":"rex-boing-agent","version":"0.2.0","protocol":1,"os":"windows","arch":"amd64"}` + "\r\n")); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "garbage", `{"name":"other","protocol":1}`, `{"name":"rex-boing-agent","protocol":2}`, `{"name":"rex-boing-agent","protocol":1,"os":"linux"}`} {
		if _, err := winCheckVersionOutput([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if !winValidSHA256(strings.Repeat("aB", 32)) || winValidSHA256("abc") || winValidSHA256(strings.Repeat("g", 64)) {
		t.Error("sha256 validation")
	}
}
