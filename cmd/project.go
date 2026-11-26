// `lockr project new|list|rm`: manage the top-level grouping of items.
package cmd

import (
	"fmt"
	"slices"

	"github.com/gtchakama/lockr/internal/model"
	"github.com/gtchakama/lockr/internal/vault"
	"github.com/spf13/cobra"
)

func newProjectCmd() *cobra.Command {
	c := &cobra.Command{Use: "project", Short: "Manage projects", Args: usageArgs(cobra.NoArgs)}
	c.AddCommand(newProjectNewCmd(), newProjectListCmd(), newProjectRmCmd())
	return c
}

func newProjectNewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "new <name>",
		Short: "Create a project",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			name, err := model.ParseName(args[0])
			if err != nil {
				return usageWrap(err)
			}
			return withWrite(func(u *vault.Unlocked) error {
				if _, ok := u.Body.Projects[name]; ok {
					return fmt.Errorf("project %q already exists", name)
				}
				u.Body.Projects[name] = map[model.Name]*model.Item{}
				fmt.Fprintf(stdout, "Created project %s\n", name)
				return nil
			})
		},
	}
}

func sortedNames[V any](m map[model.Name]V) []model.Name {
	out := make([]model.Name, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func newProjectListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List projects",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			u, _, err := openRead(true)
			if err != nil {
				return err
			}
			defer u.Close()
			for _, p := range sortedNames(u.Body.Projects) {
				fmt.Fprintf(stdout, "%s\t%d items\n", p, len(u.Body.Projects[p]))
			}
			return nil
		},
	}
}

func newProjectRmCmd() *cobra.Command {
	var force, yes bool
	c := &cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a project",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			name, err := model.ParseName(args[0])
			if err != nil {
				return usageWrap(err)
			}
			return withWrite(func(u *vault.Unlocked) error {
				items, ok := u.Body.Projects[name]
				if !ok {
					return fmt.Errorf("project %q %w", name, model.ErrNotFound)
				}
				if len(items) > 0 && !force {
					return usageErr("project %q has %d items: pass --force to delete them too", name, len(items))
				}
				if err := confirm(fmt.Sprintf("Delete project %s (%d items)?", name, len(items)), yes); err != nil {
					return err
				}
				delete(u.Body.Projects, name)
				fmt.Fprintf(stdout, "Deleted project %s\n", name)
				return nil
			})
		},
	}
	c.Flags().BoolVar(&force, "force", false, "delete a non-empty project")
	c.Flags().BoolVar(&yes, "yes", false, "skip the confirmation")
	return c
}
