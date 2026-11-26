// Injectable terminal and clock seams (tests replace these) plus prompting
// helpers. Boundary: all interactive input flows through here; nothing else
// reads the terminal directly.
package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gtchakama/lockr/internal/crypto"
	"golang.org/x/term"
)

var (
	stdin  io.Reader = os.Stdin
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr

	stdinIsTTY  = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	stdoutIsTTY = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }

	// readPassword prompts on stderr and reads a hidden line from the terminal.
	readPassword = func(prompt string) ([]byte, error) {
		fmt.Fprint(os.Stderr, prompt)
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return pw, err
	}

	now = time.Now
	kdf = crypto.DefaultKDF
)

const (
	defaultTTL     = 8 * time.Hour
	minPasswordLen = 12
)

var lineReader *bufio.Reader

// readLine reads one visible line from stdin (confirmations, names).
func readLine(prompt string) (string, error) {
	fmt.Fprint(stderr, prompt)
	if lineReader == nil {
		lineReader = bufio.NewReader(stdin)
	}
	s, err := lineReader.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && s != "") {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func requireTTY(what string) error {
	if !stdinIsTTY() {
		return fmt.Errorf("%s needs an interactive terminal; ask the user to run it themselves", what)
	}
	return nil
}

// newPassword prompts twice and enforces the minimum length.
func newPassword(label string) ([]byte, error) {
	pw, err := readPassword(label + ": ")
	if err != nil {
		return nil, err
	}
	if len([]rune(string(pw))) < minPasswordLen {
		crypto.Zero(pw)
		return nil, fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	again, err := readPassword("Repeat " + strings.ToLower(label) + ": ")
	if err != nil {
		crypto.Zero(pw)
		return nil, err
	}
	defer crypto.Zero(again)
	if string(pw) != string(again) {
		crypto.Zero(pw)
		return nil, errors.New("passwords do not match")
	}
	return pw, nil
}

// readSecretValue reads a value from stdin (--stdin, one trailing newline
// trimmed) or a hidden prompt. Values are never accepted as argv.
func readSecretValue(prompt string, fromStdin bool) ([]byte, error) {
	var v []byte
	if fromStdin {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return nil, err
		}
		if n := len(b); n > 0 && b[n-1] == '\n' {
			b = b[:n-1]
			if n := len(b); n > 0 && b[n-1] == '\r' {
				b = b[:n-1]
			}
		}
		v = b
	} else {
		if !stdinIsTTY() {
			return nil, usageErr("no terminal to prompt on: pipe the value with --stdin")
		}
		b, err := readPassword(prompt)
		if err != nil {
			return nil, err
		}
		v = b
	}
	if len(v) == 0 {
		return nil, usageErr("empty value")
	}
	return v, nil
}

// confirm asks a y/N question on a TTY; without one it requires --yes.
func confirm(question string, yes bool) error {
	if yes {
		return nil
	}
	if !stdinIsTTY() {
		return usageErr("refusing without confirmation: pass --yes")
	}
	ans, err := readLine(question + " [y/N] ")
	if err != nil {
		return err
	}
	if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
		return errors.New("aborted")
	}
	return nil
}
