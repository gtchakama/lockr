// Error-path and edge-case tests for the CLI. Reuses the env helpers from
// cmd_test.go.
package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gtchakama/lockr/internal/model"
	"github.com/gtchakama/lockr/internal/session"
	"github.com/gtchakama/lockr/internal/vault"
	"github.com/zalando/go-keyring"
)

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// runIO is like env.run but with caller-supplied stdin and stdout.
func (e *env) runIO(in io.Reader, out io.Writer, args ...string) (int, string) {
	var er bytes.Buffer
	stdin, stdout, stderr = in, out, &er
	lineReader = bufio.NewReader(in)
	code := run(args)
	return code, er.String()
}

func (e *env) pwError(err error) {
	readPassword = func(string) ([]byte, error) { return nil, err }
}

func (e *env) expect(want int, in string, args ...string) (string, string) {
	e.t.Helper()
	code, out, errs := e.run(in, args...)
	if code != want {
		e.t.Fatalf("%v: exit %d, want %d (stderr %q)", args, code, want, errs)
	}
	return out, errs
}

func (e *env) vaultPath() string { return filepath.Join(e.dir, "vault.lockr") }

func (e *env) sealedID() vault.ID {
	e.t.Helper()
	s, err := vault.Read(e.vaultPath())
	if err != nil {
		e.t.Fatal(err)
	}
	return s.ID()
}

func (e *env) sessionActive() bool {
	_, _, err := session.Load(e.sealedID(), e.clock)
	return err == nil
}

// --- root / exit codes -------------------------------------------------------

func TestExitCodeMapping(t *testing.T) {
	wrap := func(err error) error { return errors.Join(errors.New("ctx"), err) }
	cases := []struct {
		err  error
		want int
	}{
		{nil, codeOK},
		{&exitError{code: 7}, 7},
		{wrap(session.ErrLocked), codeLocked},
		{errors.New("unknown command \"x\" for \"lockr\""), codeUsage},
		{errors.New("something else"), codeGeneric},
	}
	for _, c := range cases {
		if got := exitCode(c.err); got != c.want {
			t.Errorf("%v: got %d want %d", c.err, got, c.want)
		}
	}
	if got := (&exitError{code: 7}).Error(); got != "exit status 7" {
		t.Errorf("Error(): %q", got)
	}
	inner := errors.New("inner")
	if ee := (&exitError{code: 1, err: inner}); !errors.Is(ee, inner) || ee.Error() != "inner" {
		t.Error("exitError should unwrap to its cause")
	}
}

func TestUnknownCommandAndStderrFormat(t *testing.T) {
	e := setup(t)
	_, errs := e.expect(codeUsage, "", "frobnicate")
	if !strings.HasPrefix(errs, "lockr: unknown command") {
		t.Fatalf("stderr %q", errs)
	}
	_, errs = e.expect(codeNotFound, "", "status")
	if !strings.HasPrefix(errs, "lockr: no vault found") {
		t.Fatalf("stderr %q", errs)
	}
}

func TestSilentChildExitPrintsNothing(t *testing.T) {
	e := initVault(t)
	_, errs := e.expect(3, "", "run", "proj", "--", "sh", "-c", "exit 3")
	if errs != "" {
		t.Fatalf("child exit should not add a lockr message, got %q", errs)
	}
}

// --- io helpers --------------------------------------------------------------

func TestReadLine(t *testing.T) {
	setup(t)
	stdin, stderr = strings.NewReader("first\r\nsecond"), io.Discard
	lineReader = nil // forces lazy init from stdin
	if s, err := readLine("? "); err != nil || s != "first" {
		t.Fatalf("%q %v", s, err)
	}
	if s, err := readLine("? "); err != nil || s != "second" {
		t.Fatalf("unterminated last line: %q %v", s, err)
	}
	if _, err := readLine("? "); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestNewPassword(t *testing.T) {
	e := setup(t)
	boom := errors.New("tty gone")
	long := "a-long-enough-password"
	t.Run("first read fails", func(t *testing.T) {
		e.pwError(boom)
		if _, err := newPassword("x"); !errors.Is(err, boom) {
			t.Fatal(err)
		}
	})
	t.Run("empty rejected", func(t *testing.T) {
		setup(t).passwords = []string{""}
		if _, err := newPassword("x"); err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatal(err)
		}
	})
	t.Run("short allowed with warning", func(t *testing.T) {
		setup(t).passwords = []string{"short", "short"}
		var w bytes.Buffer
		stderr = &w
		pw, err := newPassword("x")
		if err != nil || string(pw) != "short" {
			t.Fatalf("pw=%q err=%v", pw, err)
		}
		if !strings.Contains(w.String(), "warning: 5-character") {
			t.Fatalf("no warning: %q", w.String())
		}
	})
	t.Run("short counts characters not bytes", func(t *testing.T) {
		setup(t).passwords = []string{"ééééééééééé", "ééééééééééé"} // 11 runes, 22 bytes
		var w bytes.Buffer
		stderr = &w
		if _, err := newPassword("x"); err != nil || !strings.Contains(w.String(), "11-character") {
			t.Fatalf("err=%v warn=%q", err, w.String())
		}
	})
	t.Run("long enough no warning", func(t *testing.T) {
		setup(t).passwords = []string{long, long}
		var w bytes.Buffer
		stderr = &w
		if _, err := newPassword("x"); err != nil || w.Len() != 0 {
			t.Fatalf("err=%v warn=%q", err, w.String())
		}
	})
	t.Run("repeat read fails", func(t *testing.T) {
		n := 0
		readPassword = func(string) ([]byte, error) {
			n++
			if n == 2 {
				return nil, boom
			}
			return []byte(long), nil
		}
		if _, err := newPassword("x"); !errors.Is(err, boom) {
			t.Fatal(err)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		setup(t).passwords = []string{long, long + "!"}
		if _, err := newPassword("x"); err == nil || !strings.Contains(err.Error(), "do not match") {
			t.Fatal(err)
		}
	})
	t.Run("ok", func(t *testing.T) {
		setup(t).passwords = []string{long, long}
		pw, err := newPassword("x")
		if err != nil || string(pw) != long {
			t.Fatalf("%q %v", pw, err)
		}
	})
}

func TestReadSecretValue(t *testing.T) {
	e := setup(t)
	cases := []struct{ in, want string }{
		{"v\n", "v"}, {"v\r\n", "v"}, {"v", "v"}, {"a\nb\n", "a\nb"}, {"\r\nx\n", "\r\nx"},
	}
	for _, c := range cases {
		stdin = strings.NewReader(c.in)
		if v, err := readSecretValue("p", true); err != nil || string(v) != c.want {
			t.Errorf("%q: got %q %v", c.in, v, err)
		}
	}
	for _, in := range []string{"", "\n", "\r\n"} {
		stdin = strings.NewReader(in)
		if _, err := readSecretValue("p", true); exitCode(err) != codeUsage {
			t.Errorf("%q: want usage error, got %v", in, err)
		}
	}
	stdin = failReader{}
	if _, err := readSecretValue("p", true); err == nil {
		t.Error("read error swallowed")
	}
	e.inTTY = false
	if _, err := readSecretValue("p", false); exitCode(err) != codeUsage {
		t.Errorf("no tty: %v", err)
	}
	e.inTTY = true
	e.pwError(errors.New("nope"))
	if _, err := readSecretValue("p", false); err == nil {
		t.Error("prompt error swallowed")
	}
	e.passwords = nil
	readPassword = func(string) ([]byte, error) { return []byte("typed"), nil }
	if v, err := readSecretValue("p", false); err != nil || string(v) != "typed" {
		t.Errorf("%q %v", v, err)
	}
	readPassword = func(string) ([]byte, error) { return nil, nil }
	if _, err := readSecretValue("p", false); exitCode(err) != codeUsage {
		t.Errorf("empty prompt: %v", err)
	}
}

func TestConfirm(t *testing.T) {
	e := setup(t)
	stderr = io.Discard
	if err := confirm("q", true); err != nil {
		t.Fatal(err)
	}
	e.inTTY = false
	if err := confirm("q", false); exitCode(err) != codeUsage {
		t.Fatalf("no tty without --yes: %v", err)
	}
	e.inTTY = true
	for in, ok := range map[string]bool{"y\n": true, "YES\n": true, " yes \n": true, "n\n": false, "\n": false, "yep\n": false} {
		lineReader = bufio.NewReader(strings.NewReader(in))
		err := confirm("q", false)
		if (err == nil) != ok {
			t.Errorf("%q: err=%v want ok=%v", in, err, ok)
		}
	}
	lineReader = bufio.NewReader(strings.NewReader(""))
	if err := confirm("q", false); err == nil {
		t.Fatal("EOF treated as confirmation")
	}
}

// --- init / unlock / lock / status ------------------------------------------

func TestInit(t *testing.T) {
	e := setup(t)
	_, errs := e.expect(codeGeneric, "", "init")
	if !strings.Contains(errs, "interactive terminal") {
		t.Fatal(errs)
	}
	e.inTTY = true
	e.expect(codeUsage, "", "init", "extra")
	e.passwords = []string{""}
	e.expect(codeGeneric, "", "init")
	e.passwords = []string{testPW, "different password!!"}
	e.expect(codeGeneric, "", "init")
	if _, err := os.Stat(e.vaultPath()); !os.IsNotExist(err) {
		t.Fatal("failed init left a vault behind")
	}
	e.passwords = []string{testPW, testPW}
	out, _ := e.expect(0, "", "init")
	if !strings.Contains(out, "Created vault at "+e.vaultPath()) || !e.sessionActive() {
		t.Fatalf("out %q active=%v", out, e.sessionActive())
	}
	_, errs = e.expect(codeGeneric, "", "init")
	if !strings.Contains(errs, "already exists") {
		t.Fatal(errs)
	}
}

func TestInitCreateFailureAndKeyringWarning(t *testing.T) {
	e := setup(t)
	e.inTTY = true
	e.passwords = []string{testPW, testPW}
	blocker := filepath.Join(e.dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCKR_VAULT", filepath.Join(blocker, "v.lockr")) // parent is a file
	e.expect(codeGeneric, "", "init")

	t.Setenv("LOCKR_VAULT", e.vaultPath())
	keyring.MockInitWithError(errors.New("keychain locked"))
	e.passwords = []string{testPW, testPW}
	_, errs := e.expect(0, "", "init")
	if !strings.Contains(errs, "could not cache session") {
		t.Fatalf("want warning, got %q", errs)
	}
}

func TestUnlockErrors(t *testing.T) {
	e := initVault(t)
	e.inTTY = true
	e.expect(codeUsage, "", "unlock", "--ttl", "0s")
	e.expect(codeUsage, "", "unlock", "--ttl", "-5m")
	e.expect(codeUsage, "", "unlock", "--ttl", "bogus")
	e.expect(codeUsage, "", "unlock", "extra")

	e.pwError(errors.New("tty gone"))
	e.expect(codeGeneric, "", "unlock")

	e.passwords = []string{testPW}
	setup2 := keyring.MockInitWithError
	setup2(errors.New("keychain locked"))
	e.pwError(nil)
	readPassword = func(string) ([]byte, error) { return []byte(testPW), nil }
	e.expect(codeGeneric, "", "unlock")
	keyring.MockInit()

	t.Setenv("LOCKR_VAULT", filepath.Join(e.dir, "absent"))
	e.expect(codeNotFound, "", "unlock")
}

func TestUnlockReportsExpiry(t *testing.T) {
	e := initVault(t)
	e.must("", "lock")
	e.inTTY = true
	e.passwords = []string{testPW}
	out := e.must("", "unlock", "--ttl", "30m")
	if want := "Unlocked until " + e.clock.Add(30*time.Minute).Format(time.RFC3339); !strings.Contains(out, want) {
		t.Fatalf("got %q want %q", out, want)
	}
}

func TestLockAndStatus(t *testing.T) {
	e := initVault(t)
	out := e.must("", "status")
	if !strings.HasPrefix(out, "unlocked (expires "+e.clock.Add(defaultTTL).Format(time.RFC3339)+")") ||
		!strings.Contains(out, "vault: "+e.vaultPath()) {
		t.Fatalf("status: %q", out)
	}
	if out := e.must("", "lock"); out != "Locked\n" {
		t.Fatal(out)
	}
	if e.sessionActive() {
		t.Fatal("session survived lock")
	}
	if out := e.must("", "status"); out != "locked\nvault: "+e.vaultPath()+"\n" {
		t.Fatalf("status: %q", out)
	}
	e.must("", "lock") // idempotent
	e.expect(codeUsage, "", "status", "x")
	e.expect(codeUsage, "", "lock", "x")

	keyring.MockInitWithError(errors.New("keychain broken"))
	e.expect(codeGeneric, "", "lock")
	keyring.MockInit()

	t.Setenv("LOCKR_VAULT", filepath.Join(e.dir, "absent"))
	e.expect(codeNotFound, "", "lock")
	e.expect(codeNotFound, "", "status")
}

// --- passwd / destroy --------------------------------------------------------

func TestPasswd(t *testing.T) {
	e := initVault(t)
	e.expect(codeGeneric, "", "passwd") // no tty
	e.inTTY = true
	e.expect(codeUsage, "", "passwd", "x")

	e.passwords = []string{"wrong current pw!"}
	e.expect(codeGeneric, "", "passwd")

	e.passwords = []string{testPW, ""}
	e.expect(codeGeneric, "", "passwd")

	queued := readPassword
	e.pwError(errors.New("tty gone"))
	e.expect(codeGeneric, "", "passwd")
	readPassword = queued

	e.passwords = []string{testPW, "brand new password 1", "brand new password 1"}
	out, _ := e.expect(0, "", "passwd")
	if out != "Password changed\n" {
		t.Fatal(out)
	}
	e.must("", "lock")
	e.passwords = []string{testPW}
	e.expect(codeGeneric, "", "unlock") // old password no longer works
	e.passwords = []string{"brand new password 1"}
	e.must("", "unlock")
	e.inTTY = false
	if got := e.must("", "get", "proj/api"); got != "s3cr3t-value" {
		t.Fatalf("data lost across passwd: %q", got)
	}
}

func TestPasswdNoVaultAndLockFailure(t *testing.T) {
	e := setup(t)
	e.inTTY = true
	e.expect(codeNotFound, "", "passwd")

	e = initVault(t)
	e.inTTY = true
	_ = os.Remove(e.vaultPath() + ".lock")
	if err := os.Mkdir(e.vaultPath()+".lock", 0o755); err != nil { // lock file path is a directory
		t.Fatal(err)
	}
	e.expect(codeGeneric, "", "passwd")
	e.expect(codeGeneric, "x\n", "add", "proj/y", "--stdin")
}

func TestDestroyVariants(t *testing.T) {
	e := initVault(t)
	e.inTTY = true
	e.expect(codeGeneric, "nope\n", "destroy")
	e.expect(codeGeneric, "", "destroy") // EOF on prompt
	if _, err := os.Stat(e.vaultPath()); err != nil {
		t.Fatalf("aborted destroy removed vault: %v", err)
	}
	e.expect(codeUsage, "", "destroy", "x")
	id := e.sealedID()
	e.inTTY = false
	if err := os.WriteFile(e.vaultPath()+".bak", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ := e.expect(0, "", "destroy", "--yes")
	if out != "Vault destroyed\n" {
		t.Fatal(out)
	}
	for _, p := range []string{e.vaultPath(), e.vaultPath() + ".bak"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s still exists", p)
		}
	}
	if _, _, err := session.Load(id, e.clock); !errors.Is(err, session.ErrLocked) {
		t.Fatal("session survived destroy")
	}
	e.expect(0, "", "destroy", "--yes") // nothing left: still succeeds
}

func TestDestroyWarnsWhenSessionCannotBeCleared(t *testing.T) {
	e := initVault(t)
	keyring.MockInitWithError(errors.New("keychain broken"))
	_, errs := e.expect(0, "", "destroy", "--yes")
	if !strings.Contains(errs, "could not clear session") {
		t.Fatal(errs)
	}
	if _, err := os.Stat(e.vaultPath()); !os.IsNotExist(err) {
		t.Fatal("vault should still be removed")
	}
}

func TestDestroyRemoveFailure(t *testing.T) {
	e := setup(t)
	dir := filepath.Join(e.dir, "vaultdir")
	if err := os.MkdirAll(filepath.Join(dir, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCKR_VAULT", dir)
	e.expect(codeGeneric, "", "destroy", "--yes")
}

// --- unlockSealed / openRead / withWrite ------------------------------------

func TestPromptUnlockOnReadCachesSession(t *testing.T) {
	e := initVault(t)
	e.must("", "lock")
	e.inTTY = true
	e.passwords = []string{testPW}
	e.must("", "project", "list")
	if !e.sessionActive() {
		t.Fatal("prompt unlock should cache a session")
	}
	e.inTTY = false
	e.must("", "project", "list") // no prompt needed now
}

func TestPromptUnlockFailures(t *testing.T) {
	e := initVault(t)
	e.must("", "lock")
	e.inTTY = true
	e.passwords = []string{"wrong password!!"}
	e.expect(codeGeneric, "", "list")
	if e.sessionActive() {
		t.Fatal("wrong password created a session")
	}
	e.pwError(errors.New("tty gone"))
	e.expect(codeGeneric, "", "list")
	e.expect(codeGeneric, "", "rm", "proj/api", "--yes")

	readPassword = func(string) ([]byte, error) { return []byte(testPW), nil }
	keyring.MockInitWithError(errors.New("keychain broken"))
	out, errs := e.expect(0, "", "project", "list")
	if !strings.Contains(errs, "could not cache session") || !strings.Contains(out, "proj\t1 items") {
		t.Fatalf("out %q errs %q", out, errs)
	}
}

func TestStaleSessionIsDiscarded(t *testing.T) {
	e := initVault(t)
	id := e.sealedID()
	if err := session.Save(id, bytes.Repeat([]byte{7}, 32), time.Hour, e.clock); err != nil {
		t.Fatal(err)
	}
	e.expect(codeLocked, "", "get", "proj/api")
	if e.sessionActive() {
		t.Fatal("stale session was not cleared")
	}
}

func TestWritesNeedUnlockedVaultWithoutTTY(t *testing.T) {
	e := initVault(t)
	e.must("", "lock")
	for _, args := range [][]string{
		{"project", "new", "p2"}, {"project", "rm", "proj", "--yes", "--force"},
		{"add", "proj/z", "--stdin"}, {"edit", "proj/api", "--url", "x"},
		{"mv", "proj/api", "proj/b"}, {"list"}, {"project", "list"}, {"run", "proj", "--", "true"},
	} {
		_, errs := e.expect(codeLocked, "v\n", args...)
		if !strings.Contains(errs, "lockr unlock") {
			t.Errorf("%v: stderr %q", args, errs)
		}
	}
}

func TestNoVaultMutations(t *testing.T) {
	e := setup(t)
	for _, args := range [][]string{
		{"project", "new", "p"}, {"add", "p/i", "--stdin"}, {"rm", "p/i", "--yes"},
		{"mv", "p/a", "p/b"}, {"edit", "p/i"}, {"list"}, {"project", "list"},
		{"project", "rm", "p", "--yes"}, {"run", "p", "--", "true"},
	} {
		e.expect(codeNotFound, "", args...)
	}
}

func TestNoHomeNoVaultPath(t *testing.T) {
	e := setup(t)
	t.Setenv("LOCKR_VAULT", "")
	t.Setenv("HOME", "")
	for _, args := range [][]string{{"status"}, {"get", "a/b"}, {"project", "new", "p"}, {"destroy", "--yes"}, {"lock"}} {
		e.expect(codeGeneric, "", args...)
	}
}

func TestAuditFailureOnlyWarns(t *testing.T) {
	e := initVault(t)
	if err := os.Mkdir(filepath.Join(e.dir, "audit.jsonl"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, errs := e.expect(0, "", "get", "proj/api")
	if out != "s3cr3t-value" || !strings.Contains(errs, "warning: audit log") {
		t.Fatalf("out %q errs %q", out, errs)
	}
}

// --- get ---------------------------------------------------------------------

func TestGetFields(t *testing.T) {
	e := initVault(t)
	e.must("pw\n", "add", "proj/site", "--kind", "login", "--username", "bob", "--url", "https://x.test", "--stdin")
	if got := e.must("", "get", "proj/site.url"); got != "https://x.test" {
		t.Fatal(got)
	}
	if got := e.must("", "get", "proj/site.password"); got != "pw" {
		t.Fatal(got)
	}
	e.expect(codeNotFound, "", "get", "proj/site.totp") // no seed stored
	e.expect(codeNotFound, "", "get", "proj/api.url")   // no url stored
}

func TestGetOutputFailure(t *testing.T) {
	e := initVault(t)
	code, errs := e.runIO(strings.NewReader(""), failWriter{}, "get", "proj/api")
	if code != codeGeneric || !strings.Contains(errs, "write failed") {
		t.Fatalf("code %d errs %q", code, errs)
	}
}

// --- add / edit / rm / mv ----------------------------------------------------

func TestAddValidation(t *testing.T) {
	e := initVault(t)
	e.expect(codeUsage, "v\n", "add", "bad", "--stdin")
	e.expect(codeUsage, "v\n", "add", "proj/x", "--stdin", "--kind", "weird")
	e.expect(codeUsage, "v\n", "add", "proj/x", "--stdin", "--env", "lower case")
	e.expect(codeUsage, "", "add")
	e.expect(codeUsage, "", "add", "proj/x", "--stdin") // empty stdin
	e.expect(codeUsage, "", "add", "proj/x")            // no tty, no --stdin
	e.expect(codeUsage, "v\n", "add", "proj/x", "--stdin", "--totp")
	_, errs := e.expect(codeGeneric, "v\n", "add", "proj/api", "--stdin")
	if !strings.Contains(errs, "--replace") {
		t.Fatal(errs)
	}
	if got := e.must("", "get", "proj/api"); got != "s3cr3t-value" {
		t.Fatalf("failed add changed the item: %q", got)
	}
	e.expect(codeNotFound, "", "get", "proj/x")
}

func TestAddReplaceKeepsCreatedAt(t *testing.T) {
	e := initVault(t)
	created := e.clock
	e.clock = e.clock.Add(time.Hour)
	e.must("new\n", "add", "proj/api", "--stdin", "--replace")
	if got := e.must("", "get", "proj/api"); got != "new" {
		t.Fatal(got)
	}
	it := openItemT(t, "proj", "api")
	if !it.CreatedAt.Equal(created) || !it.UpdatedAt.Equal(e.clock) {
		t.Fatalf("created %v updated %v", it.CreatedAt, it.UpdatedAt)
	}
}

func TestAddPromptsOnTTY(t *testing.T) {
	e := initVault(t)
	e.inTTY = true
	var prompts []string
	readPassword = func(p string) ([]byte, error) { prompts = append(prompts, p); return []byte("typed-value"), nil }
	e.must("", "add", "proj/tok")
	e.must("", "add", "proj/login", "--kind", "login")
	if len(prompts) != 2 || prompts[0] != "Secret value: " || prompts[1] != "Password: " {
		t.Fatalf("prompts %q", prompts)
	}
	e.pwError(errors.New("tty gone"))
	e.expect(codeGeneric, "", "add", "proj/n")
	readPassword = func(p string) ([]byte, error) { return []byte("typed-value"), nil }
	// TOTP seed prompt failure: first prompt ok, second errors
	n := 0
	readPassword = func(string) ([]byte, error) {
		n++
		if n == 2 {
			return nil, errors.New("tty gone")
		}
		return []byte("typed-value"), nil
	}
	e.expect(codeGeneric, "", "add", "proj/n2", "--totp")
	e.expect(codeNotFound, "", "get", "proj/n2")
}

func TestEdit(t *testing.T) {
	e := initVault(t)
	e.clock = e.clock.Add(time.Hour)
	e.must("", "edit", "proj/api", "--url", "https://u.test", "--username", "al", "--env", "OTHER")
	it := openItemT(t, "proj", "api")
	if it.URL != "https://u.test" || it.Username != "al" || string(it.Env) != "OTHER" || !it.UpdatedAt.Equal(e.clock) {
		t.Fatalf("%+v", it)
	}
	if string(it.Secret) != "s3cr3t-value" {
		t.Fatal("untouched secret changed")
	}
	e.must("", "edit", "proj/api", "--url", "", "--env", "") // explicit empty clears
	it = openItemT(t, "proj", "api")
	if it.URL != "" || it.Env != "" || it.Username != "al" {
		t.Fatalf("%+v", it)
	}
	e.must("rotated\r\n", "edit", "proj/api", "--secret", "--stdin")
	if got := e.must("", "get", "proj/api"); got != "rotated" {
		t.Fatal(got)
	}
	e.inTTY = true
	e.passwords = []string{"typed secret"}
	e.must("", "edit", "proj/api", "--secret")
	e.passwords = []string{"jbsw y3dp ehpk 3pxp"}
	e.must("", "edit", "proj/api", "--totp")
	if openItemT(t, "proj", "api").TOTPSeed != "JBSWY3DPEHPK3PXP" {
		t.Fatal("seed not normalised")
	}
}

func TestEditErrors(t *testing.T) {
	e := initVault(t)
	e.expect(codeUsage, "", "edit", "bad")
	e.expect(codeUsage, "", "edit", "proj/api", "--env", "no good")
	e.expect(codeNotFound, "", "edit", "proj/none", "--url", "x")
	e.expect(codeNotFound, "", "edit", "gone/none", "--url", "x")
	e.expect(codeUsage, "", "edit", "proj/api", "--secret") // no tty
	e.expect(codeUsage, "\n", "edit", "proj/api", "--secret", "--stdin")
	e.expect(codeUsage, "", "edit", "proj/api", "--totp") // no tty
	e.expect(codeUsage, "", "edit")
	e.inTTY = true
	e.pwError(errors.New("tty gone"))
	e.expect(codeGeneric, "", "edit", "proj/api", "--totp")
	// a failed edit must not persist partial changes
	e.expect(codeUsage, "\n", "edit", "proj/api", "--url", "https://partial", "--secret", "--stdin")
	if it := openItemT(t, "proj", "api"); it.URL != "" {
		t.Fatalf("partial edit persisted: %+v", it)
	}
}

func TestRm(t *testing.T) {
	e := initVault(t)
	e.expect(codeUsage, "", "rm", "bad", "--yes")
	e.expect(codeNotFound, "", "rm", "proj/none", "--yes")
	e.expect(codeNotFound, "", "rm", "gone/none", "--yes")
	e.expect(codeUsage, "", "rm", "proj/api") // no tty, no --yes
	e.inTTY = true
	e.expect(codeGeneric, "n\n", "rm", "proj/api")
	e.expect(codeGeneric, "", "rm", "proj/api") // EOF
	e.must("", "get", "proj/api")
	out, _ := e.expect(0, "y\n", "rm", "proj/api")
	if out != "Deleted proj/api\n" {
		t.Fatal(out)
	}
	e.expect(codeNotFound, "", "get", "proj/api")
}

func TestMvErrors(t *testing.T) {
	e := initVault(t)
	e.must("", "project", "new", "other")
	e.must("x\n", "add", "proj/b", "--stdin")
	e.expect(codeUsage, "", "mv", "bad", "proj/c")
	e.expect(codeUsage, "", "mv", "proj/api", "bad")
	e.expect(codeUsage, "", "mv", "proj/api")
	e.expect(codeNotFound, "", "mv", "proj/none", "proj/c")
	e.expect(codeNotFound, "", "mv", "proj/api", "nowhere/c")
	_, errs := e.expect(codeGeneric, "", "mv", "proj/api", "proj/b")
	if !strings.Contains(errs, "already exists") {
		t.Fatal(errs)
	}
	if got := e.must("", "get", "proj/b"); got != "x" {
		t.Fatalf("destination clobbered: %q", got)
	}
	e.clock = e.clock.Add(time.Hour)
	out := e.must("", "mv", "proj/api", "other/api")
	if out != "Moved proj/api to other/api\n" {
		t.Fatal(out)
	}
	e.expect(codeNotFound, "", "get", "proj/api")
	if it := openItemT(t, "other", "api"); !it.UpdatedAt.Equal(e.clock) || string(it.Secret) != "s3cr3t-value" {
		t.Fatalf("%+v", it)
	}
}

// --- list / project ----------------------------------------------------------

func TestListFilterAndErrors(t *testing.T) {
	e := initVault(t)
	e.must("", "project", "new", "empty")
	e.must("v\n", "add", "empty/one", "--stdin")
	e.must("", "project", "new", "zero")
	out := e.must("", "list", "proj")
	if !strings.Contains(out, "proj/api") || strings.Contains(out, "empty/one") {
		t.Fatalf("filter: %s", out)
	}
	all := e.must("", "list")
	if !(strings.Index(all, "empty/one") < strings.Index(all, "proj/api")) {
		t.Fatalf("not sorted:\n%s", all)
	}
	if zero := e.must("", "list", "zero"); strings.Count(zero, "\n") != 1 { // header only
		t.Fatalf("empty project: %q", zero)
	}
	e.expect(codeUsage, "", "list", "bad name!")
	e.expect(codeNotFound, "", "list", "nope")
	e.expect(codeUsage, "", "list", "a", "b")
}

func TestListMarksTOTPKind(t *testing.T) {
	e := initVault(t)
	e.inTTY = true
	e.passwords = []string{"pw-pw-pw-pw", "JBSWY3DPEHPK3PXP"}
	e.must("", "add", "proj/s", "--kind", "login", "--totp")
	e.inTTY = false
	if out := e.must("", "list"); !strings.Contains(out, "login+totp") {
		t.Fatal(out)
	}
}

func TestProjectCommands(t *testing.T) {
	e := initVault(t)
	e.expect(codeUsage, "", "project", "new", "Bad Name")
	_, errs := e.expect(codeGeneric, "", "project", "new", "proj")
	if !strings.Contains(errs, "already exists") {
		t.Fatal(errs)
	}
	e.must("", "project", "new", "alpha")
	if out := e.must("", "project", "list"); out != "alpha\t0 items\nproj\t1 items\n" {
		t.Fatalf("%q", out)
	}
	e.expect(codeUsage, "", "project", "list", "x")
	e.expect(codeUsage, "", "project", "rm", "Bad Name", "--yes")
	e.expect(codeNotFound, "", "project", "rm", "ghost", "--yes")
	e.expect(codeUsage, "", "project", "rm", "alpha") // no tty, no --yes
	e.inTTY = true
	e.expect(codeGeneric, "n\n", "project", "rm", "alpha")
	e.must("", "project", "list")
	if out, _ := e.expect(0, "y\n", "project", "rm", "alpha"); out != "Deleted project alpha\n" {
		t.Fatal(out)
	}
	e.expect(codeUsage, "y\n", "project", "rm", "proj") // non-empty needs --force even when confirmed
	if out := e.must("", "project", "list"); out != "proj\t1 items\n" {
		t.Fatalf("%q", out)
	}
}

// --- run ---------------------------------------------------------------------

func TestRunErrors(t *testing.T) {
	e := initVault(t)
	e.expect(codeUsage, "", "run")
	e.expect(codeUsage, "", "run", "--", "true")
	e.expect(codeUsage, "", "run", "proj", "--")
	e.expect(codeUsage, "", "run", "Bad Name", "--", "true")
	e.expect(codeNotFound, "", "run", "ghost", "--", "true")
	_, errs := e.expect(codeGeneric, "", "run", "proj", "--", "/definitely/not/a/binary")
	if errs == "" {
		t.Fatal("start failure should be reported")
	}
	// killed by a signal => no exit status => generic failure
	e.expect(codeGeneric, "", "run", "proj", "--", "sh", "-c", "kill -9 $$")
}

func TestRunInjectsOnlyEnvMappedItemsAndKeepsEnvironment(t *testing.T) {
	e := initVault(t)
	t.Setenv("KEEP_ME", "yes")
	e.must("hidden\n", "add", "proj/noenv", "--stdin")
	e.must("z\n", "add", "proj/zzz", "--stdin", "--env", "ZZZ")
	script := `printf '%s|%s|%s' "$KEEP_ME" "$API_KEY$ZZZ" "${noenv-unset}"`
	out, _ := e.expect(0, "", "run", "proj", "--", "sh", "-c", script)
	if out != "yes|s3cr3t-valuez|unset" {
		t.Fatalf("%q", out)
	}
	// a project with no env items still runs, with no extra variables
	e.must("", "project", "new", "bare")
	out, _ = e.expect(0, "", "run", "bare", "--", "sh", "-c", `printf %s "${API_KEY-unset}"`)
	if out != "unset" {
		t.Fatalf("%q", out)
	}
	audit, _ := os.ReadFile(filepath.Join(e.dir, "audit.jsonl"))
	if !strings.Contains(string(audit), `"cmd":"run","ref":"bare"`) {
		t.Fatalf("run not audited: %s", audit)
	}
}

func TestRunForwardsStdin(t *testing.T) {
	e := initVault(t)
	out, _ := e.expect(0, "piped-in", "run", "proj", "--", "cat")
	if out != "piped-in" {
		t.Fatalf("%q", out)
	}
}

func TestRunForwardsTermSignalToChild(t *testing.T) {
	e := initVault(t)
	// Make sure a SIGTERM that races ahead of lockr's own handler cannot kill
	// the test binary.
	guard := make(chan os.Signal, 4)
	signal.Notify(guard, syscall.SIGTERM)
	defer signal.Stop(guard)

	ready := filepath.Join(e.dir, "ready")
	script := `trap 'exit 9' TERM; : > ` + ready + `; i=0; while [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done; exit 0`
	go func() {
		for i := 0; i < 400; i++ {
			if _, err := os.Stat(ready); err == nil {
				time.Sleep(100 * time.Millisecond) // let lockr install its handler
				_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()
	e.expect(9, "", "run", "proj", "--", "sh", "-c", script)
}

// --- skill -------------------------------------------------------------------

func TestSkillInstall(t *testing.T) {
	e := setup(t)
	out := e.must("", "skill", "install", "--print")
	if !strings.Contains(out, "lockr") || len(out) < 50 {
		t.Fatalf("print: %q", out)
	}
	if _, err := os.Stat(filepath.Join(e.dir, ".claude")); err == nil {
		t.Fatal("--print must not write")
	}
	e.must("", "skill", "install") // default ~/.claude/skills/lockr under HOME
	b, err := os.ReadFile(filepath.Join(e.dir, ".claude", "skills", "lockr", "SKILL.md"))
	if err != nil || string(b) != out {
		t.Fatalf("installed content differs: %v", err)
	}
	e.must("", "skill", "install", "--dir", "~/custom")
	if _, err := os.Stat(filepath.Join(e.dir, "custom", "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	e.expect(codeUsage, "", "skill", "install", "extra")
}

func TestSkillInstallFailures(t *testing.T) {
	e := setup(t)
	blocker := filepath.Join(e.dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.expect(codeGeneric, "", "skill", "install", "--dir", filepath.Join(blocker, "sub"))
	d := filepath.Join(e.dir, "d")
	if err := os.MkdirAll(filepath.Join(d, "SKILL.md"), 0o755); err != nil { // target is a directory
		t.Fatal(err)
	}
	e.expect(codeGeneric, "", "skill", "install", "--dir", d)
	t.Setenv("HOME", "")
	e.expect(codeGeneric, "", "skill", "install")
	code, errs := e.runIO(strings.NewReader(""), failWriter{}, "skill", "install", "--print")
	if code != codeGeneric || !strings.Contains(errs, "write failed") {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestExpandHome(t *testing.T) {
	t.Setenv("HOME", "/h")
	for in, want := range map[string]string{
		"~": "/h", "~/a/b": "/h/a/b", "/abs": "/abs", "rel/x": "rel/x", "~user/x": "~user/x", "": "",
	} {
		got, err := expandHome(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q %v want %q", in, got, err, want)
		}
	}
	t.Setenv("HOME", "")
	if _, err := expandHome("~"); err == nil {
		t.Error("missing HOME should error")
	}
	if got, err := expandHome("/abs"); err != nil || got != "/abs" {
		t.Error("absolute paths must not need HOME")
	}
}

// --- import-v1 ---------------------------------------------------------------

func TestImportV1Errors(t *testing.T) {
	e := initVault(t)
	v1 := filepath.Join(e.dir, "v1.enc")
	e.inTTY = true
	e.expect(codeGeneric, "", "import-v1", filepath.Join(e.dir, "missing"))
	e.expect(codeUsage, "", "import-v1", "a", "b")

	writeV1(t, v1, "old-password-1", map[string]map[string]any{"g": {"k": "v"}})
	e.inTTY = false
	_, errs := e.expect(codeGeneric, "", "import-v1", v1)
	if !strings.Contains(errs, "interactive terminal") {
		t.Fatal(errs)
	}

	e.inTTY = true
	e.pwError(errors.New("tty gone"))
	e.expect(codeGeneric, "", "import-v1", v1)

	if err := os.WriteFile(v1, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	readPassword = func(string) ([]byte, error) { return []byte("x"), nil }
	_, errs = e.expect(codeGeneric, "", "import-v1", v1)
	if !strings.Contains(errs, "not a v1 vault") {
		t.Fatal(errs)
	}
	t.Setenv("HOME", "")
	e.expect(codeGeneric, "", "import-v1")
	e.expect(codeNotFound, "", "get", "g/k")
}

func TestImportV1DefaultPathPrefixAndSkips(t *testing.T) {
	e := initVault(t)
	if err := os.MkdirAll(filepath.Join(e.dir, ".lockr"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeV1(t, filepath.Join(e.dir, ".lockr", "vault.enc"), "old-password-1", map[string]map[string]any{
		"web":    {"api_token": map[string]any{"value": "t1", "updated_at": "2020-05-06T07:08:09Z"}, "Bad.Key": "x"},
		"Bad Gr": {"k": "v", "j": "w"},
	})
	e.inTTY = true
	e.passwords = []string{"old-password-1"}
	out, errs := e.expect(0, "", "import-v1", "--project-prefix", "legacy-")
	if !strings.Contains(out, "Imported 1 items into 1 new projects (3 skipped)") {
		t.Fatalf("out %q errs %q", out, errs)
	}
	if !strings.Contains(errs, `skipping group "Bad Gr"`) || !strings.Contains(errs, "Bad.Key") {
		t.Fatalf("errs %q", errs)
	}
	e.inTTY = false
	if got := e.must("", "get", "legacy-web/api_token"); got != "t1" {
		t.Fatal(got)
	}
	it := openItemT(t, "legacy-web", "api_token")
	if string(it.Env) != "API_TOKEN" || it.CreatedAt.Year() != 2020 || !it.UpdatedAt.Equal(it.CreatedAt) {
		t.Fatalf("%+v", it)
	}
}

func TestImportV1PlainValueGetsNowAndSecondRunSkips(t *testing.T) {
	e := initVault(t)
	v1 := filepath.Join(e.dir, "v1.enc")
	writeV1(t, v1, "old-password-1", map[string]map[string]any{"g": {"K": "plain"}})
	e.inTTY = true
	e.passwords = []string{"old-password-1", "old-password-1"}
	e.must("", "import-v1", v1)
	it := openItemT(t, "g", "K")
	if !it.CreatedAt.Equal(e.clock) || string(it.Env) != "K" {
		t.Fatalf("%+v", it)
	}
	out := e.must("", "import-v1", v1)
	if !strings.Contains(out, "Imported 0 items into 0 new projects (1 skipped)") {
		t.Fatal(out)
	}
}

// --- vault inspection helpers ------------------------------------------------

// getItem reads an item straight from the vault using the cached session; nil
// if absent.
func getItem(t *testing.T, project, item string) *model.Item {
	t.Helper()
	s, err := vault.Read(os.Getenv("LOCKR_VAULT"))
	if err != nil {
		t.Fatal(err)
	}
	dek, _, err := session.Load(s.ID(), now())
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.UnlockWithDEK(dek)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	p, _ := model.ParseName(project)
	i, _ := model.ParseName(item)
	if it, ok := u.Body.Projects[p][i]; ok {
		cp := *it
		cp.Secret = append([]byte(nil), it.Secret...)
		return &cp
	}
	return nil
}

func openItemT(t *testing.T, project, item string) *model.Item {
	t.Helper()
	it := getItem(t, project, item)
	if it == nil {
		t.Fatalf("%s/%s not found", project, item)
	}
	return it
}

func TestUnknownSubcommandExitsUsage(t *testing.T) {
	e := setup(t)
	for _, args := range [][]string{{"project", "bogus"}, {"skill", "nope"}} {
		if code, _, _ := e.run("", args...); code != 64 {
			t.Errorf("%v: exit %d, want 64", args, code)
		}
	}
}
