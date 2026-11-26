// `lockr skill install`: write the bundled agent skill (SKILL.md) to disk.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gtchakama/lockr/skill"
	"github.com/spf13/cobra"
)

func newSkillCmd() *cobra.Command {
	c := &cobra.Command{Use: "skill", Short: "Manage the agent skill", Args: usageArgs(cobra.NoArgs), RunE: helpOnly}
	var dir string
	var print bool
	install := &cobra.Command{
		Use:   "install",
		Short: "Install SKILL.md for coding agents",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			if print {
				_, err := fmt.Fprint(stdout, skill.Content)
				return err
			}
			d, err := expandHome(dir)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(d, 0o755); err != nil {
				return err
			}
			p := filepath.Join(d, "SKILL.md")
			if err := os.WriteFile(p, []byte(skill.Content), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Installed %s\n", p)
			return nil
		},
	}
	install.Flags().StringVar(&dir, "dir", "~/.claude/skills/lockr", "target directory")
	install.Flags().BoolVar(&print, "print", false, "print SKILL.md instead of writing it")
	c.AddCommand(install)
	return c
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
