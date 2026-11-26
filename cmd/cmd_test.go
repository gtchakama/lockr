// End-to-end tests for the CLI: run commands in-process against a temp vault
// with a mock keyring, scripted passwords and fake TTY state.
package cmd

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gtchakama/lockr/internal/crypto"
	"github.com/gtchakama/lockr/internal/totp"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/argon2"
)

const testPW = "correct horse battery"

type env struct {
	t         *testing.T
	dir       string
	inTTY     bool
	outTTY    bool
	passwords []string
	clock     time.Time
}

func setup(t *testing.T) *env {
	t.Helper()
	keyring.MockInit()
	e := &env{t: t, dir: t.TempDir(), clock: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	t.Setenv("LOCKR_VAULT", filepath.Join(e.dir, "vault.lockr"))
	t.Setenv("HOME", e.dir)
	kdf = crypto.KDFParams{Memory: 8 * 1024, Time: 1, Threads: 1}
	stdinIsTTY = func() bool { return e.inTTY }
	stdoutIsTTY = func() bool { return e.outTTY }
	now = func() time.Time { return e.clock }
	readPassword = func(string) ([]byte, error) {
		if len(e.passwords) == 0 {
			t.Fatal("unexpected password prompt")
		}
		p := e.passwords[0]
		e.passwords = e.passwords[1:]
		return []byte(p), nil
	}
	return e
}

// run executes a command with the given stdin and returns code, stdout, stderr.
func (e *env) run(in string, args ...string) (int, string, string) {
	var o, er bytes.Buffer
	stdin, stdout, stderr = strings.NewReader(in), &o, &er
	lineReader = bufio.NewReader(stdin)
	code := run(args)
	return code, o.String(), er.String()
}

func (e *env) must(in string, args ...string) string {
	e.t.Helper()
	code, out, errs := e.run(in, args...)
	if code != 0 {
		e.t.Fatalf("%v: exit %d: %s", args, code, errs)
	}
	return out
}

// initVault creates a vault with project "proj" and secret proj/api (env API_KEY).
func initVault(t *testing.T) *env {
	e := setup(t)
	e.inTTY = true
	e.passwords = []string{testPW, testPW}
	e.must("", "init")
	e.must("", "project", "new", "proj")
	e.must("s3cr3t-value\n", "add", "proj/api", "--stdin", "--env", "API_KEY")
	e.inTTY = false
	return e
}

func TestRoundtrip(t *testing.T) {
	e := initVault(t)
	if out := e.must("", "get", "proj/api"); out != "s3cr3t-value" {
		t.Fatalf("got %q", out)
	}
	audit, err := os.ReadFile(filepath.Join(e.dir, "audit.jsonl"))
	if err != nil || !strings.Contains(string(audit), `"ref":"proj/api"`) || strings.Contains(string(audit), "s3cr3t") {
		t.Fatalf("audit: %v %s", err, audit)
	}
}

func TestAddRequiresProject(t *testing.T) {
	e := initVault(t)
	code, _, errs := e.run("x\n", "add", "nope/api", "--stdin")
	if code != codeNotFound || !strings.Contains(errs, "lockr project new nope") {
		t.Fatalf("code %d: %s", code, errs)
	}
}

func TestGetExitCodes(t *testing.T) {
	e := initVault(t)
	cases := []struct {
		name string
		args []string
		tty  bool
		want int
	}{
		{"bad ref", []string{"get", "noslash"}, false, codeUsage},
		{"bad field", []string{"get", "proj/api.nope"}, false, codeUsage},
		{"missing item", []string{"get", "proj/none"}, false, codeNotFound},
		{"missing project", []string{"get", "x/none"}, false, codeNotFound},
		{"empty field", []string{"get", "proj/api.username"}, false, codeNotFound},
		{"tty", []string{"get", "proj/api"}, true, codeTTY},
		{"no args", []string{"get"}, false, codeUsage},
		{"bad flag", []string{"get", "--nope", "proj/api"}, false, codeUsage},
	}
	for _, c := range cases {
		e.outTTY = c.tty
		code, out, _ := e.run("", c.args...)
		if code != c.want || out != "" {
			t.Errorf("%s: code %d out %q, want %d", c.name, code, out, c.want)
		}
	}
	e.outTTY = true
	if out := e.must("", "get", "proj/api", "--reveal"); out != "s3cr3t-value" {
		t.Fatalf("reveal got %q", out)
	}
	e.outTTY = false
	e.must("", "lock")
	code, _, errs := e.run("", "get", "proj/api")
	if code != codeLocked || !strings.Contains(errs, "lockr unlock") {
		t.Fatalf("locked: %d %s", code, errs)
	}
	code, _, _ = e.run("", "rm", "proj/api", "--yes")
	if code != codeLocked {
		t.Fatalf("mutation while locked on non-tty: %d", code)
	}
}

func TestNoVault(t *testing.T) {
	e := setup(t)
	if code, _, _ := e.run("", "get", "a/b"); code != codeNotFound {
		t.Fatalf("code %d", code)
	}
}

func TestUnlock(t *testing.T) {
	e := initVault(t)
	e.must("", "lock")
	code, _, errs := e.run("", "unlock")
	if code == 0 || !strings.Contains(errs, "interactive terminal") {
		t.Fatalf("non-tty unlock: %d %s", code, errs)
	}
	e.inTTY = true
	e.passwords = []string{"wrong password!!"}
	if code, _, _ := e.run("", "unlock"); code == 0 {
		t.Fatal("wrong password unlocked")
	}
	if out := e.must("", "status"); !strings.HasPrefix(out, "locked") {
		t.Fatalf("status after failed unlock: %s", out)
	}
	e.passwords = []string{testPW}
	e.must("", "unlock", "--ttl", "1h")
	if out := e.must("", "status"); !strings.HasPrefix(out, "unlocked") {
		t.Fatalf("status: %s", out)
	}
	e.clock = e.clock.Add(2 * time.Hour)
	e.inTTY = false
	if code, _, _ := e.run("", "get", "proj/api"); code != codeLocked {
		t.Fatalf("expired session: %d", code)
	}
}

func TestTOTP(t *testing.T) {
	e := initVault(t)
	e.inTTY = true
	e.passwords = []string{"hunter2hunter2", "jbsw y3dp ehpk 3pxp"}
	e.must("", "add", "proj/site", "--kind", "login", "--username", "bob", "--url", "https://x.test", "--totp")
	e.inTTY = false
	want, err := totp.Code("JBSWY3DPEHPK3PXP", e.clock)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.must("", "get", "proj/site.totp"); got != want {
		t.Fatalf("totp %q want %q", got, want)
	}
	if got := e.must("", "get", "proj/site.username"); got != "bob" {
		t.Fatalf("username %q", got)
	}
	if got := e.must("", "get", "proj/site"); got != "hunter2hunter2" {
		t.Fatalf("password %q", got)
	}
	e.inTTY = true
	e.passwords = []string{"not base32 !!"}
	if code, _, _ := e.run("", "edit", "proj/site", "--totp"); code != codeUsage {
		t.Fatalf("bad seed code %d", code)
	}
}

func TestRun(t *testing.T) {
	e := initVault(t)
	code, out, _ := e.run("", "run", "proj", "--", "sh", "-c", `printf %s "$API_KEY"; exit 7`)
	if code != 7 || out != "s3cr3t-value" {
		t.Fatalf("code %d out %q", code, out)
	}
	if code, _, _ := e.run("", "run", "proj", "sh"); code != codeUsage {
		t.Fatalf("missing -- : %d", code)
	}
	e.must("", "lock")
	if code, _, _ := e.run("", "run", "proj", "--", "true"); code != codeLocked {
		t.Fatalf("locked run: %d", code)
	}
}

func TestListNeverPrintsValues(t *testing.T) {
	e := initVault(t)
	e.must("pw-value-xyz\n", "add", "proj/old", "--kind", "login", "--username", "alice", "--stdin")
	e.clock = e.clock.Add(100 * 24 * time.Hour)
	e.inTTY = true
	e.passwords = []string{testPW}
	e.must("", "unlock")
	e.inTTY = false
	e.must("new-value\n", "add", "proj/fresh", "--stdin")
	out := e.must("", "list")
	if strings.Contains(out, "s3cr3t") || strings.Contains(out, "pw-value") || strings.Contains(out, "new-value") {
		t.Fatalf("list leaked a value:\n%s", out)
	}
	for _, want := range []string{"REF", "proj/api", "alice", "API_KEY", "⚠ rotate"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list missing %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "proj/fresh") && strings.Contains(line, "rotate") {
			t.Fatalf("fresh item flagged: %s", line)
		}
	}
}

func TestMvRmProject(t *testing.T) {
	e := initVault(t)
	e.must("", "mv", "proj/api", "proj/api2")
	if got := e.must("", "get", "proj/api2"); got != "s3cr3t-value" {
		t.Fatal(got)
	}
	if code, _, _ := e.run("", "project", "rm", "proj", "--yes"); code != codeUsage {
		t.Fatalf("non-empty rm without --force: %d", code)
	}
	e.must("", "project", "rm", "proj", "--yes", "--force")
	if code, _, _ := e.run("", "get", "proj/api2"); code != codeNotFound {
		t.Fatalf("after rm: %d", code)
	}
}

func TestSkillPrint(t *testing.T) {
	e := setup(t)
	dir := filepath.Join(e.dir, "sk")
	e.must("", "skill", "install", "--dir", dir)
	if _, err := os.Stat(filepath.Join(dir, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
}

func writeV1(t *testing.T, path, pw string, data map[string]map[string]any) {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	key := argon2.IDKey([]byte(pw), salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	pt, err := json.Marshal(map[string]any{"version": 2, "data": data})
	if err != nil {
		t.Fatal(err)
	}
	f, err := json.Marshal(map[string]string{
		"salt":       base64.StdEncoding.EncodeToString(salt),
		"nonce":      base64.StdEncoding.EncodeToString(nonce),
		"ciphertext": base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, pt, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, f, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestImportV1(t *testing.T) {
	e := initVault(t)
	v1 := filepath.Join(e.dir, "vault.enc")
	writeV1(t, v1, "old-password", map[string]map[string]any{
		"proj":   {"api": "conflict", "db_url": map[string]any{"value": "postgres://x", "updated_at": "2025-01-01T00:00:00Z"}},
		"other":  {"TOKEN": "tok-123", "bad key": "x"},
		"bad/gp": {"K": "v"},
	})
	e.inTTY = true
	e.passwords = []string{"old-password"}
	code, out, errs := e.run("", "import-v1", v1)
	if code != 0 {
		t.Fatalf("import: %d %s", code, errs)
	}
	if !strings.Contains(out, "Imported 2 items into 1 new projects (3 skipped)") {
		t.Fatalf("out %q", out)
	}
	for _, v := range []string{"postgres", "tok-123", "conflict"} {
		if strings.Contains(out+errs, v) {
			t.Fatalf("import leaked %q", v)
		}
	}
	e.inTTY = false
	if got := e.must("", "get", "proj/api"); got != "s3cr3t-value" {
		t.Fatalf("overwritten: %q", got)
	}
	if got := e.must("", "get", "other/TOKEN"); got != "tok-123" {
		t.Fatalf("token %q", got)
	}
	code, out, _ = e.run("", "run", "proj", "--", "sh", "-c", `printf %s "$DB_URL"`)
	if code != 0 || out != "postgres://x" {
		t.Fatalf("env from import: %d %q", code, out)
	}
	e.inTTY = true
	e.passwords = []string{"wrong"}
	writeV1(t, v1, "old-password", map[string]map[string]any{"z": {"a": "b"}})
	if code, _, _ := e.run("", "import-v1", v1); code == 0 {
		t.Fatal("wrong v1 password accepted")
	}
}

func TestDestroy(t *testing.T) {
	e := initVault(t)
	if code, _, _ := e.run("", "destroy"); code == 0 {
		t.Fatal("destroy without tty or --yes succeeded")
	}
	e.inTTY = true
	e.must("destroy\n", "destroy")
	if _, err := os.Stat(filepath.Join(e.dir, "vault.lockr")); !os.IsNotExist(err) {
		t.Fatalf("vault still exists: %v", err)
	}
}
