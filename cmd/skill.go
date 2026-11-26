// `lockr skill`: install the bundled agent skill (SKILL.md) for every coding
// agent on this machine. One canonical copy lives in ~/.agents/skills/lockr
// (the shared Agent Skills directory); each selected agent gets a symlink to
// it, or a copy where symlinks are unavailable, so one update reaches all.
package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/gtchakama/lockr/skill"
	"github.com/spf13/cobra"
)

const skillName = "lockr"

// agent is a coding agent that loads skills from <home>/<skills>/<name>/SKILL.md.
// It counts as installed on this machine when <home>/<root> exists.
type agent struct {
	id, name, root, skills string
}

// agents lists known skill-capable agents. The shared ~/.agents directory is
// handled separately as the canonical location.
var agents = []agent{
	{"claude", "Claude Code", ".claude", ".claude/skills"},
	{"codex", "Codex", ".codex", ".codex/skills"},
	{"gemini", "Gemini CLI", ".gemini", ".gemini/skills"},
	{"antigravity", "Antigravity", ".gemini/antigravity", ".gemini/antigravity/skills"},
	{"cursor", "Cursor", ".cursor", ".cursor/skills"},
	{"opencode", "OpenCode", ".config/opencode", ".config/opencode/skills"},
	{"copilot", "GitHub Copilot", ".copilot", ".copilot/skills"},
	{"windsurf", "Windsurf", ".codeium/windsurf", ".codeium/windsurf/skills"},
	{"kiro", "Kiro", ".kiro", ".kiro/skills"},
	{"factory", "Factory Droid", ".factory", ".factory/skills"},
	{"goose", "Goose", ".config/goose", ".config/goose/skills"},
	{"pi", "Pi", ".pi/agent", ".pi/agent/skills"},
	{"grok", "Grok", ".grok", ".grok/skills"},
}

const canonicalSkills = ".agents/skills"

func detectAgents(home string) []agent {
	var found []agent
	for _, a := range agents {
		if info, err := os.Stat(filepath.Join(home, a.root)); err == nil && info.IsDir() {
			found = append(found, a)
		}
	}
	return found
}

func (a agent) target(home string) string { return filepath.Join(home, a.skills, skillName) }

func newSkillCmd() *cobra.Command {
	c := &cobra.Command{Use: "skill", Short: "Manage the agent skill", Args: usageArgs(cobra.NoArgs), RunE: helpOnly}
	var (
		dir     string
		print   bool
		all     bool
		only    []string
		copyAll bool
	)
	install := &cobra.Command{
		Use:   "install",
		Short: "Install SKILL.md for the coding agents on this machine",
		Long: "Detects installed coding agents and lets you pick which get the lockr skill.\n" +
			"Without a terminal, pass --all or --agent. --dir writes to one directory only.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			if print {
				_, err := fmt.Fprint(stdout, skill.Content)
				return err
			}
			if dir != "" {
				d, err := expandHome(dir)
				if err != nil {
					return err
				}
				p, err := writeSkill(d)
				if err == nil {
					fmt.Fprintf(stdout, "Installed %s\n", p)
				}
				return err
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			chosen, err := chooseAgents(home, all, only)
			if err != nil || len(chosen) == 0 {
				return err
			}
			return installFor(home, chosen, copyAll)
		},
	}
	install.Flags().StringVar(&dir, "dir", "", "write SKILL.md into this one directory instead")
	install.Flags().BoolVar(&print, "print", false, "print SKILL.md instead of writing it")
	install.Flags().BoolVar(&all, "all", false, "install for every detected agent without asking")
	install.Flags().StringSliceVar(&only, "agent", nil, "install for these agents (comma-separated ids, see `lockr skill list`)")
	install.Flags().BoolVar(&copyAll, "copy", false, "copy the file into each agent instead of symlinking")

	list := &cobra.Command{
		Use:   "list",
		Short: "Show known agents and where the skill is installed",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			for _, a := range agents {
				state := "not detected"
				if _, err := os.Stat(filepath.Join(home, a.root)); err == nil {
					state = "detected"
					if _, err := os.Stat(filepath.Join(a.target(home), "SKILL.md")); err == nil {
						state = "installed"
					}
				}
				fmt.Fprintf(stdout, "%-12s %-15s %-13s ~/%s/%s\n", a.id, a.name, state, a.skills, skillName)
			}
			return nil
		},
	}

	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the skill from every agent and the shared directory",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			targets := []string{filepath.Join(home, canonicalSkills, skillName)}
			for _, a := range agents {
				targets = append(targets, a.target(home))
			}
			for _, t := range targets {
				if _, err := os.Lstat(t); err != nil {
					continue
				}
				if err := os.RemoveAll(t); err != nil {
					return err
				}
				fmt.Fprintf(stdout, "Removed %s\n", t)
			}
			return nil
		},
	}
	c.AddCommand(install, list, uninstall)
	return c
}

// chooseAgents resolves --agent, --all, or an interactive checklist.
func chooseAgents(home string, all bool, only []string) ([]agent, error) {
	if len(only) > 0 {
		var out []agent
		for _, id := range only {
			i := slices.IndexFunc(agents, func(a agent) bool { return a.id == strings.TrimSpace(id) })
			if i < 0 {
				return nil, usageErr("unknown agent %q: see `lockr skill list`", id)
			}
			out = append(out, agents[i])
		}
		return out, nil
	}
	found := detectAgents(home)
	if len(found) == 0 {
		fmt.Fprintf(stdout, "No coding agents detected. Use --agent <id> or --dir <path>.\n")
		return nil, nil
	}
	if all {
		return found, nil
	}
	if !stdinIsTTY() {
		return nil, usageErr("not a terminal: pass --all or --agent <ids> to choose agents")
	}
	return pickAgents(home, found)
}

// pickAgents shows a checklist (everything selected) and reads toggles from stdin.
func pickAgents(home string, found []agent) ([]agent, error) {
	sel := make([]bool, len(found))
	for i := range sel {
		sel[i] = true
	}
	in := bufio.NewScanner(stdin)
	for {
		fmt.Fprintln(stdout, "Install the lockr skill for:")
		for i, a := range found {
			mark := " "
			if sel[i] {
				mark = "x"
			}
			fmt.Fprintf(stdout, "  [%s] %2d  %-15s ~/%s/%s\n", mark, i+1, a.name, a.skills, skillName)
		}
		fmt.Fprint(stdout, "Toggle numbers (e.g. \"2 5\"), a = all, n = none, q = cancel, Enter = install: ")
		if !in.Scan() {
			return nil, errors.New("cancelled")
		}
		line := strings.TrimSpace(strings.ToLower(in.Text()))
		switch line {
		case "":
			var out []agent
			for i, a := range found {
				if sel[i] {
					out = append(out, a)
				}
			}
			if len(out) == 0 {
				fmt.Fprintln(stdout, "Nothing selected.")
			}
			return out, nil
		case "q":
			return nil, errors.New("cancelled")
		case "a", "n":
			for i := range sel {
				sel[i] = line == "a"
			}
			continue
		}
		for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == ',' }) {
			n, err := strconv.Atoi(f)
			if err != nil || n < 1 || n > len(found) {
				fmt.Fprintf(stdout, "Ignoring %q\n", f)
				continue
			}
			sel[n-1] = !sel[n-1]
		}
	}
}

// installFor writes the canonical copy and links each agent to it. Agents
// whose skills directory already resolves to the canonical one are skipped.
func installFor(home string, chosen []agent, copyAll bool) error {
	canon := filepath.Join(home, canonicalSkills, skillName)
	if _, err := writeSkill(canon); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Installed %s\n", filepath.Join(canon, "SKILL.md"))
	canonReal, _ := filepath.EvalSymlinks(canon)
	var failed []string
	for _, a := range chosen {
		t := a.target(home)
		if r, err := filepath.EvalSymlinks(t); err == nil && r == canonReal {
			fmt.Fprintf(stdout, "  %-15s already linked\n", a.name)
			continue
		}
		how, err := linkOrCopy(canon, t, copyAll)
		if err != nil {
			fmt.Fprintf(stderr, "  %-15s failed: %v\n", a.name, err)
			failed = append(failed, a.id)
			continue
		}
		fmt.Fprintf(stdout, "  %-15s %s %s\n", a.name, how, t)
	}
	if len(failed) > 0 {
		return fmt.Errorf("could not install for: %s", strings.Join(failed, ", "))
	}
	return nil
}

// linkOrCopy replaces t with a symlink to canon, falling back to a copy.
func linkOrCopy(canon, t string, copyOnly bool) (string, error) {
	if err := os.MkdirAll(filepath.Dir(t), 0o755); err != nil {
		return "", err
	}
	if err := os.RemoveAll(t); err != nil {
		return "", err
	}
	if !copyOnly {
		if rel, err := filepath.Rel(filepath.Dir(t), canon); err == nil && os.Symlink(rel, t) == nil {
			return "linked", nil
		}
	}
	if _, err := writeSkill(t); err != nil {
		return "", err
	}
	return "copied", nil
}

func writeSkill(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "SKILL.md")
	return p, os.WriteFile(p, []byte(skill.Content), 0o644)
}

func expandHome(p string) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~")), nil
}
