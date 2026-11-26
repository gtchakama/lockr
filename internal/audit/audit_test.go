package audit

import (
	"bufio"
	"encoding/json"
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
