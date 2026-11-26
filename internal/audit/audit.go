// Package audit appends one JSON line per lockr invocation to an audit log.
// Boundary: entries carry command and ref names only, never secret values.
// Everything here is best effort and must not break the calling command.
package audit

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Entry is one audit record.
type Entry struct {
	Time   time.Time `json:"ts"`
	Cmd    string    `json:"cmd"`
	Ref    string    `json:"ref,omitempty"`
	Parent string    `json:"parent,omitempty"`
	CWD    string    `json:"cwd,omitempty"`
}

// Append writes e as a single JSON line (O_APPEND, mode 0600).
func Append(path string, e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// goos is a seam so the non-Windows-only path can be tested on any platform.
var goos = runtime.GOOS

// ParentChain returns up to 3 ancestor process names, e.g. "zsh ← claude".
// Best effort: returns "" on any error or on Windows.
func ParentChain() (out string) {
	defer func() {
		if recover() != nil {
			out = ""
		}
	}()
	if goos == "windows" {
		return ""
	}
	pid := os.Getppid()
	var names []string
	for i := 0; i < 3 && pid > 1; i++ {
		b, err := exec.Command("ps", "-o", "ppid=,comm=", "-p", strconv.Itoa(pid)).Output()
		if err != nil {
			break
		}
		ppid, name, ok := parsePS(string(b))
		if !ok {
			break
		}
		names = append(names, name)
		pid = ppid
	}
	return strings.Join(names, " ← ")
}

func parsePS(s string) (int, string, bool) {
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) < 2 {
		return 0, "", false
	}
	ppid, err := strconv.Atoi(f[0])
	if err != nil {
		return 0, "", false
	}
	name := strings.Join(f[1:], " ")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return ppid, strings.TrimPrefix(name, "-"), true
}
