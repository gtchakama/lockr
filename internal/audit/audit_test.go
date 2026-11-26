package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppend(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, c := range []string{"get", "list"} {
		if err := Append(p, Entry{Time: time.Now(), Cmd: c, Ref: "p/i"}); err != nil {
			t.Fatal(err)
		}
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	f, _ := os.Open(p)
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil || e.Ref != "p/i" {
			t.Fatalf("bad line %q: %v", sc.Text(), err)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("lines %d", n)
	}
}

func TestParsePS(t *testing.T) {
	ppid, name, ok := parsePS("  123 -/bin/zsh\n")
	if !ok || ppid != 123 || name != "zsh" {
		t.Fatalf("%d %q %v", ppid, name, ok)
	}
	if _, _, ok := parsePS(""); ok {
		t.Fatal("empty should fail")
	}
}

func TestParentChainNoPanic(t *testing.T) {
	_ = ParentChain()
}

func TestAppendErrors(t *testing.T) {
	dir := t.TempDir()
	// path is a directory: open fails
	if err := Append(dir, Entry{Cmd: "get"}); err == nil {
		t.Fatal("expected open error for directory path")
	}
	// parent does not exist
	if err := Append(filepath.Join(dir, "missing", "a.jsonl"), Entry{Cmd: "get"}); err == nil {
		t.Fatal("expected open error for missing parent")
	}
	// unmarshalable timestamp (year > 9999): nothing may be written
	p := filepath.Join(dir, "a.jsonl")
	bad := Entry{Time: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), Cmd: "get"}
	if err := Append(p, bad); err == nil {
		t.Fatal("expected marshal error")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("file created despite marshal error: %v", err)
	}
}

func TestAppendAppendsAndOmitsEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	if err := os.WriteFile(p, []byte("{\"existing\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Append(p, Entry{Time: time.Unix(0, 0).UTC(), Cmd: "lock"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	want := "{\"existing\":true}\n{\"ts\":\"1970-01-01T00:00:00Z\",\"cmd\":\"lock\"}\n"
	if string(b) != want {
		t.Fatalf("got %q", b)
	}
}

// fakePS installs a `ps` script on PATH. The script receives the pid after -p.
func fakePS(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\npid=\"$4\"\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "ps"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestParentChainWalksAncestors(t *testing.T) {
	// First lookup is for our real parent pid; chain: zsh -> claude -> node.
	fakePS(t, fmt.Sprintf(`case "$pid" in
%d) echo "500 -/bin/zsh" ;;
500) echo "600 /usr/local/bin/claude" ;;
600) echo "700 node" ;;
*) echo "1 launchd" ;;
esac`, os.Getppid()))
	if got, want := ParentChain(), "zsh ← claude ← node"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParentChainStopsAtInit(t *testing.T) {
	fakePS(t, fmt.Sprintf(`case "$pid" in
%d) echo "1 bash" ;;
esac`, os.Getppid()))
	if got := ParentChain(); got != "bash" {
		t.Fatalf("got %q", got)
	}
}

func TestParentChainBestEffort(t *testing.T) {
	fakePS(t, "exit 1")
	if got := ParentChain(); got != "" {
		t.Fatalf("ps failure: got %q", got)
	}
	fakePS(t, `echo "garbage"`)
	if got := ParentChain(); got != "" {
		t.Fatalf("unparseable ps output: got %q", got)
	}
	t.Setenv("PATH", t.TempDir()) // no ps at all
	if got := ParentChain(); got != "" {
		t.Fatalf("missing ps: got %q", got)
	}
}

func TestParsePSCases(t *testing.T) {
	cases := []struct {
		in   string
		ppid int
		name string
		ok   bool
	}{
		{"1 launchd", 1, "launchd", true},
		{"  42 /Applications/My App.app/Contents/MacOS/app\n", 42, "app", true},
		{"7 -zsh", 7, "zsh", true},
		{"7 two words", 7, "two words", true},
		{"only", 0, "", false},
		{"abc zsh", 0, "", false},
		{"   \n", 0, "", false},
	}
	for _, c := range cases {
		ppid, name, ok := parsePS(c.in)
		if ppid != c.ppid || name != c.name || ok != c.ok {
			t.Errorf("%q: got (%d,%q,%v) want (%d,%q,%v)", c.in, ppid, name, ok, c.ppid, c.name, c.ok)
		}
	}
}

func TestParentChainSkippedOnWindows(t *testing.T) {
	old := goos
	goos = "windows"
	t.Cleanup(func() { goos = old })
	fakePS(t, `echo "5 shouldnotrun"`)
	if got := ParentChain(); got != "" {
		t.Fatalf("got %q", got)
	}
}
